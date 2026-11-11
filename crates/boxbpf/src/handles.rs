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
    rules4: lpm_trie::LpmTrie<MapData, [u8; 16], Raw<abi::Rules>>,
    rules6: lpm_trie::LpmTrie<MapData, [u8; 28], Raw<abi::Rules>>,
    pins: HashMap<MapData, Raw<abi::PinKey>, Raw<abi::PinVal>>,
    set_rules: HashMap<MapData, Raw<abi::SetKey>, Raw<abi::Rules>>,
    endpoints: HashMap<MapData, Raw<abi::EndpointKey>, Raw<abi::Endpoint>>,
    stats: PerCpuHashMap<MapData, u64, Raw<abi::Stats>>,
    flows: Flows,
    events: Option<RingBuf<MapData>>,
    /// The pins this process wrote, per box. The kernel map is the truth
    /// for the programs. This copy says what to delete and when.
    pinned: StdHashMap<u64, PinTable>,
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
            pinned: StdHashMap::new(),
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

    fn next_generation(&self, id: BoxId) -> Result<u32, Error> {
        let current = absent_ok(self.box_cfg.get(&id.0, 0)).map_err(Error::map("box_cfg"))?;
        Ok(current.map_or(1, |Raw(cfg)| cfg.generation.wrapping_add(1)))
    }

    /// Writes `new` and removes what only `old` has. The config entry is
    /// not touched.
    fn write_entries(&mut self, old: &abi::BoxEntries, new: &abi::BoxEntries) -> Result<(), Error> {
        for (key, value) in new.rules4.iter().filter(|e| !old.rules4.contains(e)) {
            let key = lpm_trie::Key::new(key.prefixlen, key.data());
            self.rules4
                .insert(&key, &Raw(*value), 0)
                .map_err(Error::map("rules4"))?;
        }
        for (key, value) in new.rules6.iter().filter(|e| !old.rules6.contains(e)) {
            let key = lpm_trie::Key::new(key.prefixlen, key.data());
            self.rules6
                .insert(&key, &Raw(*value), 0)
                .map_err(Error::map("rules6"))?;
        }
        for (key, value) in new.sets.iter().filter(|e| !old.sets.contains(e)) {
            self.set_rules
                .insert(&Raw(*key), &Raw(*value), 0)
                .map_err(Error::map("set_rules"))?;
        }
        for (key, value) in new.endpoints.iter().filter(|e| !old.endpoints.contains(e)) {
            self.endpoints
                .insert(&Raw(*key), &Raw(*value), 0)
                .map_err(Error::map("endpoints"))?;
        }

        for (key, _) in old
            .rules4
            .iter()
            .filter(|(k, _)| !new.rules4.iter().any(|(n, _)| n == k))
        {
            let key = lpm_trie::Key::new(key.prefixlen, key.data());
            absent_ok(self.rules4.remove(&key)).map_err(Error::map("rules4"))?;
        }
        for (key, _) in old
            .rules6
            .iter()
            .filter(|(k, _)| !new.rules6.iter().any(|(n, _)| n == k))
        {
            let key = lpm_trie::Key::new(key.prefixlen, key.data());
            absent_ok(self.rules6.remove(&key)).map_err(Error::map("rules6"))?;
        }
        for (key, _) in old
            .sets
            .iter()
            .filter(|(k, _)| !new.sets.iter().any(|(n, _)| n == k))
        {
            absent_ok(self.set_rules.remove(&Raw(*key))).map_err(Error::map("set_rules"))?;
        }
        for (key, _) in old
            .endpoints
            .iter()
            .filter(|(k, _)| !new.endpoints.iter().any(|(n, _)| n == k))
        {
            absent_ok(self.endpoints.remove(&Raw(*key))).map_err(Error::map("endpoints"))?;
        }
        Ok(())
    }

    /// Puts a box's policy into the maps.
    ///
    /// Rules, sets and endpoints go first and the config entry last: a
    /// cgroup without a config entry has no network, so a half-written box
    /// is never live.
    pub fn apply(&mut self, id: BoxId, compiled: &Compiled) -> Result<(), Error> {
        self.update(id, None, compiled)
    }

    /// Replaces the policy of a box. Only entries that differ are written.
    /// The config entry goes last with a new generation, which ends the
    /// verdicts sockets have cached under the old policy.
    pub fn update(
        &mut self,
        id: BoxId,
        old: Option<&Compiled>,
        new: &Compiled,
    ) -> Result<(), Error> {
        if id.0 == 0 {
            return Err(Error::BoxIdZero);
        }
        let generation = self.next_generation(id)?;
        let old = old.map(|c| abi::entries(c, id.0, 0)).unwrap_or_default();
        let new = abi::entries(new, id.0, generation);
        self.write_entries(&old, &new)?;
        if absent_ok(self.stats.get(&id.0, 0))
            .map_err(Error::map("stats"))?
            .is_none()
        {
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
                .map_err(Error::map("stats"))?;
        }
        self.box_cfg
            .insert(&id.0, &Raw(new.cfg), 0)
            .map_err(Error::map("box_cfg"))
    }

    /// Takes a box out of the maps. The config entry goes first, so the
    /// box has no network from the first write on.
    pub fn remove(&mut self, id: BoxId, compiled: &Compiled) -> Result<(), Error> {
        absent_ok(self.box_cfg.remove(&id.0)).map_err(Error::map("box_cfg"))?;
        let old = abi::entries(compiled, id.0, 0);
        self.write_entries(&old, &abi::BoxEntries::default())?;
        if let Some(table) = self.pinned.remove(&id.0) {
            for addr in table.addresses() {
                absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr))))
                    .map_err(Error::map("pins"))?;
            }
        }
        absent_ok(self.stats.remove(&id.0)).map_err(Error::map("stats"))?;
        Ok(())
    }

    /// Makes the egress hook forget its cached verdicts for the box.
    pub fn bump_generation(&mut self, id: BoxId) -> Result<(), Error> {
        let Some(Raw(mut cfg)) =
            absent_ok(self.box_cfg.get(&id.0, 0)).map_err(Error::map("box_cfg"))?
        else {
            return Ok(());
        };
        cfg.generation = cfg.generation.wrapping_add(1);
        self.box_cfg
            .insert(&id.0, &Raw(cfg), 0)
            .map_err(Error::map("box_cfg"))
    }

    /// Compiles a spec and puts it into the maps.
    pub fn install(&mut self, id: BoxId, spec: Spec) -> Result<LiveBox, Error> {
        let compiled = Arc::new(spec.compile()?);
        self.apply(id, &compiled)?;
        Ok(LiveBox { id, spec, compiled })
    }

    /// Gives a live box a new spec. On a compile error nothing changes.
    pub fn reconfigure(&mut self, live: &mut LiveBox, spec: Spec) -> Result<(), Error> {
        let compiled = Arc::new(spec.compile()?);
        self.update(live.id, Some(&live.compiled), &compiled)?;
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
        self.remove(live.id, &live.compiled)
    }

    /// Pins an address the resolver answered to the set of its name, for
    /// `ttl` from now. A pin of the same address replaces the earlier one.
    pub fn pin(&mut self, id: BoxId, addr: IpAddr, set: SetId, ttl: Duration) -> Result<(), Error> {
        let expiry = pins::expiry(sys::boot_time_ns(), ttl);
        self.pins
            .insert(
                &Raw(abi::pin_key(id.0, addr)),
                &Raw(abi::pin_val(set, expiry)),
                0,
            )
            .map_err(Error::map("pins"))?;
        self.pinned
            .entry(id.0)
            .or_default()
            .insert(addr, set, expiry);
        Ok(())
    }

    pub fn unpin(&mut self, id: BoxId, addr: IpAddr) -> Result<(), Error> {
        absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr)))).map_err(Error::map("pins"))?;
        if let Some(table) = self.pinned.get_mut(&id.0) {
            table.remove(addr);
        }
        Ok(())
    }

    /// The set an address is pinned to right now, for the evaluator.
    #[must_use]
    pub fn pinned_set(&self, id: BoxId, addr: IpAddr) -> Option<SetId> {
        self.pinned
            .get(&id.0)
            .and_then(|t| t.live(addr, sys::boot_time_ns()))
    }

    /// Deletes pins whose time has passed. The programs already ignore
    /// them. This gives the space back. Returns how many were deleted.
    pub fn sweep_pins(&mut self) -> Result<usize, Error> {
        let now = sys::boot_time_ns();
        let mut swept = 0;
        for (box_id, table) in &mut self.pinned {
            for addr in table.take_expired(now) {
                absent_ok(self.pins.remove(&Raw(abi::pin_key(*box_id, addr))))
                    .map_err(Error::map("pins"))?;
                swept += 1;
            }
        }
        Ok(swept)
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
