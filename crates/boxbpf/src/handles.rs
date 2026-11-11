//! The maps of an attached engine, with the writes a daemon makes.
//!
//! Nothing here needs privilege. A process that was handed these maps by
//! the loader uses them exactly like one that loaded the programs itself.

use std::{
    collections::HashMap as StdHashMap,
    io,
    net::{IpAddr, SocketAddr},
    os::fd::{BorrowedFd, OwnedFd},
    sync::Arc,
    time::Duration,
};

use aya::maps::{HashMap, Map, MapData, MapError, PerCpuHashMap, PerCpuValues, RingBuf, lpm_trie};
use netpol::{
    Compiled, EndpointIndex, Protocol, SetId, Spec,
    abi::{self, Plain},
    base::PortOf,
    pins::{self, PinTable},
};

use crate::{Error, engine::MAPS, events, sys};

/// Lets a `netpol::abi` struct be a map key or value.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Raw<T>(T);

// SAFETY: `Plain` promises repr(C) without padding and that every bit
// pattern is valid, which is what aya asks of a `Pod`.
unsafe impl<T: Plain> aya::Pod for Raw<T> {}

/// The cgroup id of a box cgroup: the key of everything the engine holds
/// for the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoxId(pub u64);

impl BoxId {
    /// The id of the box whose cgroup directory is open as `dir`.
    pub fn of(dir: BorrowedFd<'_>) -> io::Result<Self> {
        sys::cgroup_id(dir).map(Self)
    }
}

/// What one box may take of the maps all boxes share. Without a limit one
/// box could fill a map and every other box's install, reconfigure or pin
/// would fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Rule entries of one policy: its prefixes and name sets. While a
    /// policy is being replaced the box holds the old entries too.
    pub rule_entries: usize,
    /// Addresses pinned at one time.
    pub pins: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rule_entries: 1024,
            pins: 1024,
        }
    }
}

/// What a box holds of the shared maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub rule_entries: usize,
    pub pins: usize,
    /// Pins refused so far because the box was at its limit.
    pub pins_refused: u64,
}

/// What this process wrote for one box.
struct Held {
    /// The generation the box's config entry names.
    generation: u32,
    compiled: Arc<Compiled>,
    /// The entries of that generation.
    keys: abi::BoxKeys,
    /// The kernel map is the truth for the programs. This copy says which
    /// set an address is pinned to, what to delete, and when.
    pins: PinTable,
    pins_refused: u64,
}

/// A box whose policy is in the maps, with what is needed to change it.
#[derive(Debug, Clone)]
pub struct LiveBox {
    id: BoxId,
    spec: Spec,
    compiled: Arc<Compiled>,
}

impl LiveBox {
    #[must_use]
    pub const fn id(&self) -> BoxId {
        self.id
    }

    #[must_use]
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// The policy as the kernel has it: what the evaluator judges and what
    /// an event's rule number indexes. Shared, so a reader keeps a
    /// snapshot while the box is reconfigured.
    #[must_use]
    pub const fn compiled(&self) -> &Arc<Compiled> {
        &self.compiled
    }
}

/// A flow of a box to one of its endpoints, as the engine recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalDestination {
    pub box_id: BoxId,
    /// Where the box sent the flow: the address a redirect rule took it
    /// from, or the endpoint's own when the box dialled that.
    pub destination: SocketAddr,
    /// The endpoint the flow arrived at.
    pub endpoint: EndpointIndex,
}

/// The flows map alone: who is behind the peer of an endpoint. An endpoint
/// task holds its own copy and asks without the lock the writers share.
pub struct Flows {
    map: HashMap<MapData, Raw<abi::FlowKey>, Raw<abi::FlowVal>>,
    /// A second descriptor of the map, to make further handles from.
    fd: OwnedFd,
}

impl Flows {
    fn from_fd(fd: OwnedFd) -> Result<Self, Error> {
        let kept = fd.try_clone().map_err(|source| Error::Sys {
            what: "duplicate the flows map",
            source,
        })?;
        let data = MapData::from_fd(fd).map_err(Error::map("flows"))?;
        Ok(Self {
            map: HashMap::try_from(Map::LruHashMap(data)).map_err(Error::map("flows"))?,
            fd: kept,
        })
    }

    /// Another handle on the same map.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let fd = self.fd.try_clone().map_err(|source| Error::Sys {
            what: "duplicate the flows map",
            source,
        })?;
        Self::from_fd(fd)
    }

    /// Which box is behind `peer`, the remote end of a flow that reached
    /// an endpoint, and where that flow was first headed. The egress hook
    /// records every flow of a box to one of its own endpoints with the
    /// first packet, so the entry is there by the time the endpoint sees
    /// that packet, and removes it with the box's socket. `None` means the
    /// peer is no box socket: a process outside every box.
    pub fn original_destination(
        &self,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Result<Option<OriginalDestination>, Error> {
        // A v4-mapped peer is an IPv4 flow, and recorded as one.
        let peer = SocketAddr::new(netpol::eval::canonical(peer.ip()), peer.port());
        let key = Raw(abi::flow_key(peer, protocol));
        let found = absent_ok(self.map.get(&key, 0)).map_err(Error::map("flows"))?;
        Ok(found.map(|Raw(v)| OriginalDestination {
            box_id: BoxId(v.box_id),
            destination: SocketAddr::new(abi::addr_of(&v.orig_addr, v.orig_family), v.orig_port),
            endpoint: EndpointIndex(v.endpoint),
        }))
    }
}

pub struct Handles {
    box_cfg: HashMap<MapData, u64, Raw<abi::BoxCfg>>,
    rules4: lpm_trie::LpmTrie<MapData, [u8; 20], Raw<abi::Rules>>,
    rules6: lpm_trie::LpmTrie<MapData, [u8; 32], Raw<abi::Rules>>,
    pins: HashMap<MapData, Raw<abi::PinKey>, Raw<abi::PinVal>>,
    set_rules: HashMap<MapData, Raw<abi::SetKey>, Raw<abi::Rules>>,
    endpoints: HashMap<MapData, Raw<abi::EndpointKey>, Raw<abi::Endpoint>>,
    stats: PerCpuHashMap<MapData, u64, Raw<abi::Stats>>,
    flows: Flows,
    events: Option<RingBuf<MapData>>,
    boxes: StdHashMap<u64, Held>,
    /// Entries of replaced or abandoned generations that a delete failed
    /// on. No config entry names them, so they judge nothing. They are
    /// tried again with the next write.
    stale: Vec<abi::BoxKeys>,
    limits: Limits,
}

/// A lookup or delete that found nothing is not an error for a caller that
/// only wants the entry gone or wants to know whether it exists.
fn absent_ok<T>(result: Result<T, MapError>) -> Result<Option<T>, MapError> {
    match result {
        Ok(v) => Ok(Some(v)),
        Err(MapError::KeyNotFound) => Ok(None),
        Err(MapError::SyscallError(e)) if e.io_error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl Handles {
    /// Wraps map descriptors in hand-over order: the order the loader
    /// sends them in.
    pub fn from_fds(fds: Vec<OwnedFd>) -> Result<Self, Error> {
        let count = fds.len();
        let fds = fds.into_iter();
        let fds = std::cell::RefCell::new(fds);
        let next_fd = |count: usize| -> Result<OwnedFd, Error> {
            fds.borrow_mut()
                .next()
                .ok_or(Error::HandleCount(count, MAPS.len()))
        };
        let next = |name: &'static str| -> Result<MapData, Error> {
            MapData::from_fd(next_fd(count)?).map_err(Error::map(name))
        };
        let this = Self {
            box_cfg: HashMap::try_from(Map::HashMap(next("box_cfg")?))
                .map_err(Error::map("box_cfg"))?,
            rules4: lpm_trie::LpmTrie::try_from(Map::LpmTrie(next("rules4")?))
                .map_err(Error::map("rules4"))?,
            rules6: lpm_trie::LpmTrie::try_from(Map::LpmTrie(next("rules6")?))
                .map_err(Error::map("rules6"))?,
            pins: HashMap::try_from(Map::HashMap(next("pins")?)).map_err(Error::map("pins"))?,
            set_rules: HashMap::try_from(Map::HashMap(next("set_rules")?))
                .map_err(Error::map("set_rules"))?,
            endpoints: HashMap::try_from(Map::HashMap(next("endpoints")?))
                .map_err(Error::map("endpoints"))?,
            stats: PerCpuHashMap::try_from(Map::PerCpuHashMap(next("stats")?))
                .map_err(Error::map("stats"))?,
            flows: Flows::from_fd(next_fd(count)?)?,
            events: Some(
                RingBuf::try_from(Map::RingBuf(next("events")?)).map_err(Error::map("events"))?,
            ),
            boxes: StdHashMap::new(),
            stale: Vec::new(),
            limits: Limits::default(),
        };
        if fds.borrow_mut().next().is_some() {
            return Err(Error::HandleCount(count, MAPS.len()));
        }
        Ok(this)
    }

    /// The event ring buffer. There is one reader per engine, so this
    /// returns it once.
    pub fn take_events(&mut self) -> Option<events::Source> {
        self.events.take().map(events::Source::new)
    }

    /// Replaces the per-box limits. Boxes already in the maps keep what
    /// they have.
    pub const fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Writes every entry of one generation.
    fn write(&mut self, entries: &abi::BoxEntries) -> Result<(), Error> {
        for (key, value) in &entries.rules4 {
            let key = lpm_trie::Key::new(key.prefixlen, key.data());
            self.rules4
                .insert(&key, &Raw(*value), 0)
                .map_err(Error::map("rules4"))?;
        }
        for (key, value) in &entries.rules6 {
            let key = lpm_trie::Key::new(key.prefixlen, key.data());
            self.rules6
                .insert(&key, &Raw(*value), 0)
                .map_err(Error::map("rules6"))?;
        }
        for (key, value) in &entries.sets {
            self.set_rules
                .insert(&Raw(*key), &Raw(*value), 0)
                .map_err(Error::map("set_rules"))?;
        }
        for (key, value) in &entries.endpoints {
            self.endpoints
                .insert(&Raw(*key), &Raw(*value), 0)
                .map_err(Error::map("endpoints"))?;
        }
        Ok(())
    }

    /// Deletes the entries of a generation no config entry names. What a
    /// delete fails on is kept for [`Self::collect`].
    fn discard(&mut self, keys: abi::BoxKeys) {
        let mut left = abi::BoxKeys::default();
        for key in keys.rules4 {
            let lpm = lpm_trie::Key::new(key.prefixlen, key.data());
            if absent_ok(self.rules4.remove(&lpm)).is_err() {
                left.rules4.push(key);
            }
        }
        for key in keys.rules6 {
            let lpm = lpm_trie::Key::new(key.prefixlen, key.data());
            if absent_ok(self.rules6.remove(&lpm)).is_err() {
                left.rules6.push(key);
            }
        }
        for key in keys.sets {
            if absent_ok(self.set_rules.remove(&Raw(key))).is_err() {
                left.sets.push(key);
            }
        }
        for key in keys.endpoints {
            if absent_ok(self.endpoints.remove(&Raw(key))).is_err() {
                left.endpoints.push(key);
            }
        }
        if !left.is_empty() {
            self.stale.push(left);
        }
    }

    /// Tries again to delete what earlier deletes failed on.
    fn collect(&mut self) {
        for keys in std::mem::take(&mut self.stale) {
            self.discard(keys);
        }
    }

    fn zero_stats(&mut self, id: BoxId) -> Result<(), Error> {
        let cpus = aya::util::nr_cpus().map_err(|(_, e)| Error::Sys {
            what: "count CPUs",
            source: e,
        })?;
        let zero = vec![Raw(abi::Stats::default()); cpus.get() as usize];
        let zero = PerCpuValues::try_from(zero).map_err(|e| Error::Sys {
            what: "size per-CPU counters",
            source: e,
        })?;
        self.stats
            .insert(&id.0, zero, 0)
            .map_err(Error::map("stats"))
    }

    /// Makes the box's pins fit `compiled`: a pin of a name the policy has
    /// no rule for goes, and a pin whose name a more specific pattern now
    /// covers moves to that pattern's set.
    fn rebind_pins(&mut self, id: BoxId, compiled: &Compiled) -> Result<(), Error> {
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Ok(());
        };
        let rebound = held.pins.rebind(|name| compiled.set_for_name(name));
        for addr in rebound.dropped {
            absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr))))
                .map_err(Error::map("pins"))?;
        }
        for (addr, set, expiry) in rebound.moved {
            self.pins
                .insert(
                    &Raw(abi::pin_key(id.0, addr)),
                    &Raw(abi::pin_val(set, expiry)),
                    0,
                )
                .map_err(Error::map("pins"))?;
        }
        Ok(())
    }

    /// Everything of [`Self::apply`] up to and including the switch.
    fn switch_to(
        &mut self,
        id: BoxId,
        first: bool,
        compiled: &Compiled,
        entries: &abi::BoxEntries,
    ) -> Result<(), Error> {
        self.write(entries)?;
        if first {
            self.zero_stats(id)?;
        }
        // Before the switch: a pin of a name the new policy dropped must
        // not live into it. Until the switch such a pin admits nothing
        // more than the old policy did.
        self.rebind_pins(id, compiled)?;
        self.box_cfg
            .insert(&id.0, &Raw(entries.cfg), 0)
            .map_err(Error::map("box_cfg"))
    }

    /// Puts a policy in force for a box: its first, or one that replaces
    /// the policy the box has.
    ///
    /// The new entries are written under a new generation, beside those in
    /// force. The write of the config entry then switches the programs
    /// from one generation to the other, so no flow is ever judged by a
    /// mix of two policies. If anything fails before that write, the new
    /// entries are deleted and the box keeps what it had: its old policy,
    /// or for a new box no network.
    pub fn apply(&mut self, id: BoxId, compiled: Arc<Compiled>) -> Result<(), Error> {
        if id.0 == 0 {
            return Err(Error::BoxIdZero);
        }
        let needed = abi::rule_entries(&compiled);
        if needed > self.limits.rule_entries {
            return Err(Error::RuleEntryLimit {
                needed,
                limit: self.limits.rule_entries,
            });
        }
        self.collect();
        let current = self.boxes.get(&id.0).map(|held| held.generation);
        let generation = current.map_or(1, |g| g.wrapping_add(1));
        let entries = abi::entries(&compiled, id.0, generation);
        let keys = entries.keys();
        if let Err(error) = self.switch_to(id, current.is_none(), &compiled, &entries) {
            self.discard(keys);
            if current.is_none() {
                // Nothing reads the counters of a box that never started.
                let _absent = self.stats.remove(&id.0);
            }
            return Err(error);
        }
        match self.boxes.get_mut(&id.0) {
            Some(held) => {
                held.generation = generation;
                held.compiled = compiled;
                let replaced = std::mem::replace(&mut held.keys, keys);
                self.discard(replaced);
            }
            None => {
                self.boxes.insert(
                    id.0,
                    Held {
                        generation,
                        compiled,
                        keys,
                        pins: PinTable::new(),
                        pins_refused: 0,
                    },
                );
            }
        }
        Ok(())
    }

    /// Takes a box out of the maps. The config entry goes first, so the
    /// box has no network from the first write on.
    pub fn remove(&mut self, id: BoxId) -> Result<(), Error> {
        absent_ok(self.box_cfg.remove(&id.0)).map_err(Error::map("box_cfg"))?;
        if let Some(held) = self.boxes.remove(&id.0) {
            self.discard(held.keys);
            for addr in held.pins.addresses() {
                absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr))))
                    .map_err(Error::map("pins"))?;
            }
        }
        absent_ok(self.stats.remove(&id.0)).map_err(Error::map("stats"))?;
        Ok(())
    }

    /// Compiles a spec and puts it into the maps.
    pub fn install(&mut self, id: BoxId, spec: Spec) -> Result<LiveBox, Error> {
        let compiled = Arc::new(spec.compile()?);
        self.apply(id, Arc::clone(&compiled))?;
        Ok(LiveBox { id, spec, compiled })
    }

    /// Gives a live box a new spec. On any error the box keeps the policy
    /// it had.
    pub fn reconfigure(&mut self, live: &mut LiveBox, spec: Spec) -> Result<(), Error> {
        let compiled = Arc::new(spec.compile()?);
        self.apply(live.id, Arc::clone(&compiled))?;
        live.spec = spec;
        live.compiled = compiled;
        Ok(())
    }

    /// Admits new inbound flows on a port of the box.
    pub fn publish(&mut self, live: &mut LiveBox, port: PortOf) -> Result<(), Error> {
        if live.spec.deployment.published.contains(&port) {
            return Ok(());
        }
        let mut spec = live.spec.clone();
        spec.deployment.published.push(port);
        self.reconfigure(live, spec)
    }

    pub fn unpublish(&mut self, live: &mut LiveBox, port: PortOf) -> Result<(), Error> {
        if !live.spec.deployment.published.contains(&port) {
            return Ok(());
        }
        let mut spec = live.spec.clone();
        spec.deployment.published.retain(|p| *p != port);
        self.reconfigure(live, spec)
    }

    /// Replaces the host ports the box may reach on the host alias.
    pub fn set_host_exposures(
        &mut self,
        live: &mut LiveBox,
        ports: Vec<PortOf>,
    ) -> Result<(), Error> {
        if live.spec.deployment.host_exposures == ports {
            return Ok(());
        }
        let mut spec = live.spec.clone();
        spec.deployment.host_exposures = ports;
        self.reconfigure(live, spec)
    }

    pub fn uninstall(&mut self, live: &LiveBox) -> Result<(), Error> {
        self.remove(live.id)
    }

    /// Pins an address the resolver answered for `name` to the set of that
    /// name in the box's policy, for `ttl` from now. A pin of the same
    /// address replaces the earlier one.
    ///
    /// The name is kept with the pin: when the box's policy changes, the
    /// pin follows the name to its new set or goes with it.
    ///
    /// A box at its pin limit gets [`Error::PinLimit`], and the refusal is
    /// counted in [`Self::usage`].
    pub fn pin(&mut self, id: BoxId, addr: IpAddr, name: &str, ttl: Duration) -> Result<(), Error> {
        let limit = self.limits.pins;
        let now = sys::boot_time_ns();
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Err(Error::UnknownBox);
        };
        let Some(set) = held.compiled.set_for_name(name) else {
            return Err(Error::NameWithoutRule(name.to_owned()));
        };
        if held.pins.len() >= limit && !held.pins.contains(addr) {
            // Pins that have run out give their room back first.
            for dead in held.pins.take_expired(now) {
                absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, dead))))
                    .map_err(Error::map("pins"))?;
            }
            if held.pins.len() >= limit {
                held.pins_refused += 1;
                return Err(Error::PinLimit { limit });
            }
        }
        let expiry = pins::expiry(now, ttl);
        self.pins
            .insert(
                &Raw(abi::pin_key(id.0, addr)),
                &Raw(abi::pin_val(set, expiry)),
                0,
            )
            .map_err(Error::map("pins"))?;
        held.pins.insert(addr, name, set, expiry);
        Ok(())
    }

    pub fn unpin(&mut self, id: BoxId, addr: IpAddr) -> Result<(), Error> {
        absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr)))).map_err(Error::map("pins"))?;
        if let Some(held) = self.boxes.get_mut(&id.0) {
            held.pins.remove(addr);
        }
        Ok(())
    }

    /// The set an address is pinned to right now, for the evaluator.
    #[must_use]
    pub fn pinned_set(&self, id: BoxId, addr: IpAddr) -> Option<SetId> {
        self.boxes
            .get(&id.0)
            .and_then(|held| held.pins.live(addr, sys::boot_time_ns()))
    }

    /// Deletes pins whose time has passed. The programs already ignore
    /// them. This gives the space back. Returns how many were deleted.
    pub fn sweep_pins(&mut self) -> Result<usize, Error> {
        self.collect();
        let now = sys::boot_time_ns();
        let mut swept = 0;
        for (box_id, held) in &mut self.boxes {
            for addr in held.pins.take_expired(now) {
                absent_ok(self.pins.remove(&Raw(abi::pin_key(*box_id, addr))))
                    .map_err(Error::map("pins"))?;
                swept += 1;
            }
        }
        Ok(swept)
    }

    /// What the box holds of the shared maps. `None` for an unknown box.
    #[must_use]
    pub fn usage(&self, id: BoxId) -> Option<Usage> {
        self.boxes.get(&id.0).map(|held| Usage {
            rule_entries: held.keys.rules4.len() + held.keys.rules6.len() + held.keys.sets.len(),
            pins: held.pins.len(),
            pins_refused: held.pins_refused,
        })
    }

    /// The counters of a box, summed over CPUs. `None` for an unknown box.
    pub fn stats(&self, id: BoxId) -> Result<Option<abi::Stats>, Error> {
        let Some(per_cpu) = absent_ok(self.stats.get(&id.0, 0)).map_err(Error::map("stats"))?
        else {
            return Ok(None);
        };
        let mut total = abi::Stats::default();
        for Raw(cpu) in per_cpu.iter() {
            total.add(cpu);
        }
        Ok(Some(total))
    }

    /// See [`Flows::original_destination`].
    pub fn original_destination(
        &self,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Result<Option<OriginalDestination>, Error> {
        self.flows.original_destination(peer, protocol)
    }

    /// A handle on the flows map for an endpoint task.
    pub fn flows(&self) -> Result<Flows, Error> {
        self.flows.try_clone()
    }
}
