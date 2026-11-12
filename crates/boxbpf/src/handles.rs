//! The maps of an attached engine, with the writes a daemon makes.
//!
//! Nothing here needs privilege. A process that was handed these maps by
//! the loader uses them exactly like one that loaded the programs itself.
//!
//! An engine has one set of handles, and nothing else writes its maps. So
//! what the handles wrote is their record of what the maps hold: they keep
//! it per box and never read a policy back from the kernel.

use std::{
    collections::{BTreeSet, HashMap as StdHashMap},
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
#[derive(Clone, Copy, Default)]
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
    /// Rule entries of one policy: its prefixes, its name sets, and the
    /// merged sets made for addresses that names of several sets resolve
    /// to. While a policy is being replaced the box holds the old entries
    /// too.
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
    /// Sets made for addresses that names of several sets resolve to.
    /// Their entries are part of `rule_entries`.
    pub merged_sets: usize,
    pub pins: usize,
    /// Pins refused so far because the box was at a limit.
    pub pins_refused: u64,
    /// Sockets of the box with a flow to one of its endpoints, as the
    /// programs count them.
    pub flows: u32,
    /// Listening sockets of the box the programs know.
    pub listens: u32,
}

/// A merged list that did not fit: the address it was made for and the
/// names that resolve to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetOverflow {
    pub address: IpAddr,
    pub names: Vec<String>,
    pub overflow: netpol::compile::Overflow,
}

/// A set made for the addresses that names of the same several sets
/// resolve to.
#[derive(Debug)]
struct Merged {
    members: Vec<SetId>,
    /// Its entries in the generation in force.
    keys: Vec<abi::SetKey>,
    /// How many pins name it. With the last one it goes.
    addresses: usize,
    /// Where its lists that did not fit refuse.
    overflow: Vec<netpol::compile::Overflow>,
}

type MergedSets = StdHashMap<SetId, Merged>;

/// What this process wrote for one box.
struct Held {
    /// The generation the box's config entry names.
    generation: u32,
    compiled: Arc<Compiled>,
    /// The entries of that generation.
    keys: abi::BoxKeys,
    /// The kernel map is the truth for the programs. This copy says which
    /// sets an address is pinned to, what to delete, and when.
    pins: PinTable,
    pins_refused: u64,
    /// The box's own addresses. They are in the kernel's pin map too, in
    /// the set [`SetId::OWN`].
    own: BTreeSet<IpAddr>,
    merged: MergedSets,
    /// The first merged list of the box that did not fit, until
    /// [`Handles::take_set_overflow`] hands it out. A box is told once.
    overflow: Option<SetOverflow>,
    overflow_told: bool,
}

impl Held {
    fn rule_entries(&self) -> usize {
        abi::rule_entries(&self.compiled) + merged_entries(&self.merged)
    }

    /// Keeps the first merged list that did not fit, for the daemon to
    /// report.
    fn note_overflow(&mut self, addr: IpAddr, overflow: Option<netpol::compile::Overflow>) {
        let Some(overflow) = overflow else { return };
        if self.overflow.is_none() && !self.overflow_told {
            self.overflow = Some(SetOverflow {
                address: addr,
                names: self
                    .pins
                    .names(addr)
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                overflow,
            });
        }
    }
}

fn merged_entries(merged: &MergedSets) -> usize {
    merged.values().map(|set| set.keys.len()).sum()
}

type PinMap = HashMap<MapData, Raw<abi::PinKey>, Raw<abi::PinVal>>;
type SetMap = HashMap<MapData, Raw<abi::SetKey>, Raw<abi::Rules>>;

/// Where the entries of merged sets are written for one policy of a box.
struct Merging<'a> {
    set_rules: &'a mut SetMap,
    compiled: &'a Compiled,
    box_id: u64,
    generation: u32,
    /// The most rule entries the box may have under this policy.
    limit: usize,
}

impl Merging<'_> {
    /// Makes sure `merged` has the set for `members`, with its entries in
    /// the map. Returns the overflow of a set made now.
    ///
    /// # Errors
    ///
    /// [`Error::RuleEntryLimit`] when the set would take the box past its
    /// limit, [`Error::MergedSetClash`] when its id is taken, and the map's
    /// error. The set is then not in `merged`, and its address must have
    /// no pin.
    fn ensure(
        &mut self,
        merged: &mut MergedSets,
        members: &[SetId],
    ) -> Result<Option<netpol::compile::Overflow>, Error> {
        let made = self.compiled.merged(members);
        if let Some(known) = merged.get(&made.id) {
            return if known.members == members {
                Ok(None)
            } else {
                Err(Error::MergedSetClash)
            };
        }
        if self.compiled.sets.iter().any(|set| set.id == made.id) {
            return Err(Error::MergedSetClash);
        }
        let needed = abi::rule_entries(self.compiled) + merged_entries(merged) + made.entries.len();
        if needed > self.limit {
            return Err(Error::RuleEntryLimit {
                needed,
                limit: self.limit,
            });
        }
        let mut keys = Vec::with_capacity(made.entries.len());
        for entry in &made.entries {
            let (key, value) = abi::set_entry(entry, self.box_id, self.generation);
            if let Err(error) = self.set_rules.insert(&Raw(key), &Raw(value), 0) {
                for key in keys {
                    let _gone = self.set_rules.remove(&Raw(key));
                }
                return Err(Error::map("set_rules")(error));
            }
            keys.push(key);
        }
        merged.insert(
            made.id,
            Merged {
                members: members.to_vec(),
                keys,
                addresses: 0,
                overflow: made.overflow.clone(),
            },
        );
        Ok(made.overflow.first().copied())
    }
}

/// Takes one pin away from a merged set, and the set with its last pin.
fn release(merged: &mut MergedSets, set_rules: &mut SetMap, set: SetId) {
    let Some(held) = merged.get_mut(&set) else {
        return;
    };
    held.addresses = held.addresses.saturating_sub(1);
    if held.addresses == 0
        && let Some(gone) = merged.remove(&set)
    {
        // Nothing names the set any more, so an entry a delete fails on
        // judges nothing. The box's removal takes its generation's keys.
        for key in gone.keys {
            let _gone = set_rules.remove(&Raw(key));
        }
    }
}

/// Writes or deletes the pin of one address.
fn write_pin(
    pins: &mut PinMap,
    id: BoxId,
    addr: IpAddr,
    placement: Option<&pins::Placement>,
) -> Result<(), Error> {
    let key = Raw(abi::pin_key(id.0, addr));
    match placement {
        Some(p) => pins
            .insert(&key, &Raw(abi::pin_val(p.set(), p.expiry_ns)), 0)
            .map_err(Error::map("pins")),
        None => absent_ok(pins.remove(&key))
            .map(drop)
            .map_err(Error::map("pins")),
    }
}

/// Makes the engine's entry for `addr` what the box's pin table wants at
/// `now`: the set of its one live name, the merged set of several, or no
/// entry.
///
/// # Errors
///
/// What kept the entry from being written. The address then has no pin:
/// nothing judges it by name until it is placed again.
fn place(
    held: &mut Held,
    pins: &mut PinMap,
    set_rules: &mut SetMap,
    limit: usize,
    id: BoxId,
    addr: IpAddr,
    now: u64,
) -> Result<(), Error> {
    let wanted = held.pins.wanted(addr, now);
    let placed = held.pins.placed(addr).cloned();
    if wanted == placed {
        return Ok(());
    }
    let mut merging = Merging {
        set_rules,
        compiled: &held.compiled,
        box_id: id.0,
        generation: held.generation,
        limit,
    };
    let merged = match wanted.as_ref().filter(|w| w.is_merged()) {
        Some(w) => merging.ensure(&mut held.merged, &w.members).map(Some),
        None => Ok(None),
    };
    let written = merged.and_then(|overflow| {
        write_pin(pins, id, addr, wanted.as_ref())?;
        Ok(overflow)
    });
    let (now_placed, result) = match written {
        Ok(overflow) => {
            held.note_overflow(addr, overflow.flatten());
            (wanted, Ok(()))
        }
        Err(error) => {
            // Without its set the address must not keep the pin it had.
            let _gone = write_pin(pins, id, addr, None);
            (None, Err(error))
        }
    };
    // The new set gets its pin before the old one loses it, so a set both
    // name is never taken away in between.
    if let Some(p) = now_placed.as_ref().filter(|p| p.is_merged())
        && let Some(set) = held.merged.get_mut(&p.set())
    {
        set.addresses += 1;
    }
    if let Some(p) = placed.filter(pins::Placement::is_merged) {
        release(&mut held.merged, set_rules, p.set());
    }
    // A set made for a pin that was then not written has no pin.
    held.merged.retain(|_, set| {
        if set.addresses > 0 {
            return true;
        }
        for key in set.keys.drain(..) {
            let _gone = set_rules.remove(&Raw(key));
        }
        false
    });
    held.pins.set_placed(addr, now_placed);
    result
}

/// Places every address of a box anew for `compiled` at `generation`: the
/// merged sets are written under that generation into `merged`, and each
/// pin that changes is rewritten. An address whose merged set does not fit
/// the box's limit loses its pin and is counted as refused.
///
/// # Errors
///
/// A map's error. What was written so far is in `merged`.
#[allow(clippy::too_many_arguments)]
fn place_all(
    held: &mut Held,
    pins: &mut PinMap,
    set_rules: &mut SetMap,
    limit: usize,
    id: BoxId,
    compiled: &Compiled,
    generation: u32,
    merged: &mut MergedSets,
) -> Result<(), Error> {
    let now = sys::boot_time_ns();
    let mut merging = Merging {
        set_rules,
        compiled,
        box_id: id.0,
        generation,
        limit,
    };
    let mut addrs: Vec<IpAddr> = held.pins.addresses().collect();
    addrs.sort_unstable();
    for addr in addrs {
        let mut wanted = held.pins.wanted(addr, now);
        if let Some(w) = wanted.as_ref().filter(|w| w.is_merged()) {
            match merging.ensure(merged, &w.members) {
                Ok(overflow) => {
                    if let Some(set) = merged.get_mut(&w.set()) {
                        set.addresses += 1;
                    }
                    held.note_overflow(addr, overflow);
                }
                Err(Error::RuleEntryLimit { .. } | Error::MergedSetClash) => {
                    held.pins_refused += 1;
                    wanted = None;
                }
                Err(error) => return Err(error),
            }
        }
        if wanted.as_ref() != held.pins.placed(addr) {
            write_pin(pins, id, addr, wanted.as_ref())?;
        }
        held.pins.set_placed(addr, wanted);
    }
    Ok(())
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
            map: HashMap::try_from(Map::HashMap(data)).map_err(Error::map("flows"))?,
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
    /// an endpoint in the network namespace `netns`, and where that flow
    /// was first headed. `netns` is the endpoint's own namespace cookie
    /// ([`crate::netns_cookie`] of its socket): a peer address means
    /// nothing without it, since every namespace has the same loopback.
    ///
    /// The egress hook records every flow of a box to one of its own
    /// endpoints with the first packet, so the entry is there by the time
    /// the endpoint sees that packet, and removes it with the box's
    /// socket. `None` means the peer is no box socket: a process outside
    /// every box.
    pub fn original_destination(
        &self,
        netns: u64,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Result<Option<OriginalDestination>, Error> {
        // A v4-mapped peer is an IPv4 flow, and recorded as one.
        let peer = SocketAddr::new(netpol::eval::canonical(peer.ip()), peer.port());
        let key = Raw(abi::flow_key(netns, peer, protocol));
        let found = absent_ok(self.map.get(&key, 0)).map_err(Error::map("flows"))?;
        Ok(found.map(|Raw(v)| OriginalDestination {
            box_id: BoxId(v.box_id),
            destination: SocketAddr::new(abi::addr_of(&v.orig_addr, v.orig_family), v.orig_port),
            endpoint: EndpointIndex(v.endpoint),
        }))
    }
}

/// A TCP socket of a box that listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Listening {
    /// The address the socket is bound to. Unspecified: every address of
    /// the family, and for an IPv6 socket usually IPv4 as well.
    pub address: IpAddr,
    pub port: u16,
}

/// The table of listening sockets alone, for a task that watches a box's
/// ports and must not wait for the writers' lock.
pub struct Listens {
    map: HashMap<MapData, Raw<abi::ListenKey>, Raw<abi::Listen>>,
    /// A second descriptor of the map, to make further handles from.
    fd: OwnedFd,
}

impl Listens {
    fn from_fd(fd: OwnedFd) -> Result<Self, Error> {
        let kept = fd.try_clone().map_err(|source| Error::Sys {
            what: "duplicate the listens map",
            source,
        })?;
        let data = MapData::from_fd(fd).map_err(Error::map("listens"))?;
        Ok(Self {
            map: HashMap::try_from(Map::HashMap(data)).map_err(Error::map("listens"))?,
            fd: kept,
        })
    }

    /// Another handle on the same map.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let fd = self.fd.try_clone().map_err(|source| Error::Sys {
            what: "duplicate the listens map",
            source,
        })?;
        Self::from_fd(fd)
    }

    /// The TCP sockets of the box that listen now in the network namespace
    /// `netns`, sorted. The programs add a socket when it starts to listen
    /// and take it out when it is released. A [`netpol::event::ListenEvent`]
    /// says when this changed. The table is what counts: read it after an
    /// event, and now and then without one.
    ///
    /// This walks the table of all boxes.
    pub fn listening(&self, id: BoxId, netns: u64) -> Result<Vec<Listening>, Error> {
        let mut out = Vec::new();
        for entry in self.map.iter() {
            let (Raw(key), Raw(listen)) = match entry {
                Ok(entry) => entry,
                // An entry that went while we walked.
                Err(MapError::KeyNotFound) => continue,
                Err(error) => return Err(Error::map("listens")(error)),
            };
            if key.box_id == id.0 && key.netns == netns {
                out.push(Listening {
                    address: abi::addr_of(&listen.addr, listen.family),
                    port: listen.port,
                });
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
}

pub struct Handles {
    box_cfg: HashMap<MapData, u64, Raw<abi::BoxCfg>>,
    rules4: lpm_trie::LpmTrie<MapData, [u8; 20], Raw<abi::Rules>>,
    rules6: lpm_trie::LpmTrie<MapData, [u8; 32], Raw<abi::Rules>>,
    pins: PinMap,
    set_rules: SetMap,
    endpoints: HashMap<MapData, Raw<abi::EndpointKey>, Raw<abi::Endpoint>>,
    stats: PerCpuHashMap<MapData, u64, Raw<abi::Stats>>,
    box_use: HashMap<MapData, u64, Raw<abi::Usage>>,
    flows: Flows,
    listens: Listens,
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
            box_use: HashMap::try_from(Map::HashMap(next("box_use")?))
                .map_err(Error::map("box_use"))?,
            flows: Flows::from_fd(next_fd(count)?)?,
            listens: Listens::from_fd(next_fd(count)?)?,
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

    /// The entries a box has from its first policy to its removal: its
    /// counters, and the count of what the programs record for it.
    fn zero_stats(&mut self, id: BoxId) -> Result<(), Error> {
        self.box_use
            .insert(&id.0, &Raw(abi::Usage::default()), 0)
            .map_err(Error::map("box_use"))?;
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

    /// Deletes the entries of merged sets no pin names.
    fn discard_merged(&mut self, merged: MergedSets) {
        let keys = merged.into_values().flat_map(|set| set.keys).collect();
        self.discard(abi::BoxKeys {
            sets: keys,
            ..abi::BoxKeys::default()
        });
    }

    /// Makes the box's pins fit `compiled` at `generation`. A name the
    /// policy has no rule for goes, and one a more specific pattern now
    /// covers moves to that pattern's set. Then every address is placed
    /// again: the rules of a set, and so of a merged set, differ from one
    /// policy to the next. The merged sets of the generation come back.
    fn rebind_pins(
        &mut self,
        id: BoxId,
        compiled: &Compiled,
        generation: u32,
    ) -> Result<MergedSets, Error> {
        let mut merged = MergedSets::new();
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Ok(merged);
        };
        held.pins.rebind(|name| compiled.set_for_name(name));
        let placed = place_all(
            held,
            &mut self.pins,
            &mut self.set_rules,
            self.limits.rule_entries,
            id,
            compiled,
            generation,
            &mut merged,
        );
        match placed {
            Ok(()) => Ok(merged),
            Err(error) => {
                self.discard_merged(merged);
                Err(error)
            }
        }
    }

    /// Everything of [`Self::apply`] up to and including the switch.
    fn switch_to(
        &mut self,
        id: BoxId,
        first: bool,
        compiled: &Compiled,
        entries: &abi::BoxEntries,
    ) -> Result<MergedSets, Error> {
        self.write(entries)?;
        if first {
            self.zero_stats(id)?;
        }
        // Before the switch: a pin of a name the new policy dropped must
        // not live into it. Until the switch such a pin admits nothing
        // more than the old policy did, and a pin moved to a set only the
        // new policy has admits nothing.
        let merged = self.rebind_pins(id, compiled, entries.cfg.generation)?;
        match self.box_cfg.insert(&id.0, &Raw(entries.cfg), 0) {
            Ok(()) => Ok(merged),
            Err(error) => {
                self.discard_merged(merged);
                Err(Error::map("box_cfg")(error))
            }
        }
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
        let merged = match self.switch_to(id, current.is_none(), &compiled, &entries) {
            Ok(merged) => merged,
            Err(error) => {
                self.discard(keys);
                if current.is_none() {
                    // Nothing reads the counters of a box that never started.
                    let _absent = self.stats.remove(&id.0);
                    let _absent = self.box_use.remove(&id.0);
                }
                self.keep_policy(id);
                return Err(error);
            }
        };
        match self.boxes.get_mut(&id.0) {
            Some(held) => {
                held.generation = generation;
                held.compiled = compiled;
                let replaced = std::mem::replace(&mut held.keys, keys);
                let replaced_merged = std::mem::replace(&mut held.merged, merged);
                self.discard(replaced);
                self.discard_merged(replaced_merged);
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
                        own: BTreeSet::new(),
                        merged,
                        overflow: None,
                        overflow_told: false,
                    },
                );
            }
        }
        Ok(())
    }

    /// After a policy change that failed: the pins were made to fit the
    /// policy that did not come, so they are made to fit the one the box
    /// keeps. A name the other policy dropped stays dropped.
    fn keep_policy(&mut self, id: BoxId) {
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return;
        };
        let compiled = Arc::clone(&held.compiled);
        let generation = held.generation;
        held.pins.rebind(|name| compiled.set_for_name(name));
        let mut merged = MergedSets::new();
        // What this cannot place has no pin, which admits nothing.
        let _placed = place_all(
            held,
            &mut self.pins,
            &mut self.set_rules,
            self.limits.rule_entries,
            id,
            &compiled,
            generation,
            &mut merged,
        );
        // The sets were written under the same keys again. Those the pins
        // no longer name go.
        let mut old = std::mem::replace(&mut held.merged, merged);
        old.retain(|set, _| !held.merged.contains_key(set));
        self.discard_merged(old);
    }

    /// Takes a box out of the maps. The config entry goes first, so the
    /// box has no network from the first write on.
    pub fn remove(&mut self, id: BoxId) -> Result<(), Error> {
        absent_ok(self.box_cfg.remove(&id.0)).map_err(Error::map("box_cfg"))?;
        if let Some(held) = self.boxes.remove(&id.0) {
            self.discard(held.keys);
            self.discard_merged(held.merged);
            for addr in held.pins.addresses().chain(held.own.iter().copied()) {
                absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr))))
                    .map_err(Error::map("pins"))?;
            }
        }
        absent_ok(self.stats.remove(&id.0)).map_err(Error::map("stats"))?;
        absent_ok(self.box_use.remove(&id.0)).map_err(Error::map("box_use"))?;
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

    pub fn uninstall(&mut self, live: &LiveBox) -> Result<(), Error> {
        self.remove(live.id)
    }

    /// Makes `addr` one of the box's own addresses: a source its packets
    /// may have, and an address the rules for [`netpol::Target::OwnAddresses`]
    /// apply to. It takes effect with the one map write, with no change of
    /// the box's policy. A box has one for each of its network namespaces:
    /// call this when a namespace gets its address, before anything runs
    /// in it, and [`Self::remove_own_address`] when the namespace is gone.
    ///
    /// An address has one place in the engine's table. If it was pinned
    /// for a name, it is the box's own from now on.
    pub fn add_own_address(&mut self, id: BoxId, addr: IpAddr) -> Result<(), Error> {
        let addr = netpol::eval::canonical(addr);
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Err(Error::UnknownBox);
        };
        self.pins
            .insert(
                &Raw(abi::pin_key(id.0, addr)),
                &Raw(abi::own_address_val()),
                0,
            )
            .map_err(Error::map("pins"))?;
        if let Some(placed) = held.pins.placed(addr).filter(|p| p.is_merged()) {
            release(&mut held.merged, &mut self.set_rules, placed.set());
        }
        held.pins.remove(addr);
        held.own.insert(addr);
        Ok(())
    }

    pub fn remove_own_address(&mut self, id: BoxId, addr: IpAddr) -> Result<(), Error> {
        let addr = netpol::eval::canonical(addr);
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Ok(());
        };
        if held.own.remove(&addr) {
            absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr))))
                .map_err(Error::map("pins"))?;
        }
        Ok(())
    }

    /// Pins an address the resolver answered for `name`, for `ttl` from
    /// now. The address is then judged by the rules of that name's set in
    /// the box's policy. When names of other sets are live for the address
    /// too, it is judged by the rules of all of them in the order of the
    /// policy's list, through a merged set this makes for it.
    ///
    /// The name is kept with the pin: when the box's policy changes, the
    /// pin follows the name to its new set or goes with it.
    ///
    /// One of the box's own addresses stays its own: a name that resolves
    /// to the box itself needs no pin, since a box may always reach itself.
    ///
    /// # Errors
    ///
    /// Each of these is counted in [`Self::usage`], and each leaves the
    /// address without what the name would have added:
    ///
    /// - [`Error::PinLimit`] for a box at its pin limit. The address is
    ///   not pinned.
    /// - [`Error::NamesPerAddress`], [`Error::RuleEntryLimit`] and
    ///   [`Error::MergedSetClash`] when the address cannot be judged by the
    ///   rules of all its names. It then has no pin at all, since the rules
    ///   left out could be the ones that refuse.
    pub fn pin(&mut self, id: BoxId, addr: IpAddr, name: &str, ttl: Duration) -> Result<(), Error> {
        let limit = self.limits.pins;
        let rule_entries = self.limits.rule_entries;
        let now = sys::boot_time_ns();
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Err(Error::UnknownBox);
        };
        let Some(set) = held.compiled.set_for_name(name) else {
            return Err(Error::NameWithoutRule(name.to_owned()));
        };
        if held.own.contains(&netpol::eval::canonical(addr)) {
            return Ok(());
        }
        if held.pins.len() >= limit && !held.pins.contains(addr) {
            // Pins that have run out give their room back first.
            for lost in held.pins.expire(now) {
                let _placed = place(
                    held,
                    &mut self.pins,
                    &mut self.set_rules,
                    rule_entries,
                    id,
                    lost,
                    now,
                );
            }
            if held.pins.len() >= limit {
                held.pins_refused += 1;
                return Err(Error::PinLimit { limit });
            }
        }
        let recorded = held
            .pins
            .insert(addr, name, set, pins::expiry(now, ttl), now)
            .map_err(|_| Error::NamesPerAddress {
                limit: pins::NAMES_PER_ADDRESS,
            });
        let placed = place(
            held,
            &mut self.pins,
            &mut self.set_rules,
            rule_entries,
            id,
            addr,
            now,
        );
        let result = recorded.and(placed);
        if result.is_err() {
            held.pins_refused += 1;
        }
        result
    }

    /// Takes every pin of `addr` away, whatever names it was for.
    pub fn unpin(&mut self, id: BoxId, addr: IpAddr) -> Result<(), Error> {
        let Some(held) = self.boxes.get_mut(&id.0) else {
            return Ok(());
        };
        if held.own.contains(&netpol::eval::canonical(addr)) {
            return Ok(());
        }
        absent_ok(self.pins.remove(&Raw(abi::pin_key(id.0, addr)))).map_err(Error::map("pins"))?;
        if let Some(placed) = held.pins.placed(addr).filter(|p| p.is_merged()) {
            release(&mut held.merged, &mut self.set_rules, placed.set());
        }
        held.pins.remove(addr);
        Ok(())
    }

    /// The sets an address is in right now: those of the names it is
    /// pinned for, or [`SetId::OWN`] for one of the box's own addresses.
    /// This is the table the evaluator asks.
    #[must_use]
    pub fn pinned_sets(&self, id: BoxId, addr: IpAddr) -> Vec<SetId> {
        let Some(held) = self.boxes.get(&id.0) else {
            return Vec::new();
        };
        if held.own.contains(&netpol::eval::canonical(addr)) {
            return vec![SetId::OWN];
        }
        held.pins.live(addr, sys::boot_time_ns())
    }

    /// Drops the names whose time has passed and places their addresses
    /// again: an address with no live name loses its pin, and one that
    /// names of fewer sets are live for is judged by those. The programs
    /// already ignore a pin from the moment its first set runs out.
    /// Returns how many addresses were placed again.
    pub fn sweep_pins(&mut self) -> Result<usize, Error> {
        self.collect();
        let now = sys::boot_time_ns();
        let rule_entries = self.limits.rule_entries;
        let mut swept = 0;
        for (box_id, held) in &mut self.boxes {
            for addr in held.pins.expire(now) {
                let placed = place(
                    held,
                    &mut self.pins,
                    &mut self.set_rules,
                    rule_entries,
                    BoxId(*box_id),
                    addr,
                    now,
                );
                match placed {
                    Ok(()) => {}
                    // The address has no pin now, which is what a limit
                    // asks for.
                    Err(Error::RuleEntryLimit { .. } | Error::MergedSetClash) => {
                        held.pins_refused += 1;
                    }
                    Err(error) => return Err(error),
                }
                swept += 1;
            }
        }
        Ok(swept)
    }

    /// How long until a pin runs out for an address that another name is
    /// still live for. Nothing judges that address from then until
    /// [`Self::sweep_pins`] has placed it again, so a daemon sweeps then.
    #[must_use]
    pub fn next_pin_change(&self) -> Option<Duration> {
        let next = self
            .boxes
            .values()
            .filter_map(|held| held.pins.next_change())
            .min()?;
        Some(Duration::from_nanos(
            next.saturating_sub(sys::boot_time_ns()),
        ))
    }

    /// Whether a refusal of a flow to `addr` at rule number `rule` came
    /// from a merged list that did not fit: such a list refuses in the
    /// place of the first rule left out of it, and that rule refused
    /// nothing.
    #[must_use]
    pub fn refused_at_overflow(
        &self,
        id: BoxId,
        addr: IpAddr,
        direction: netpol::Direction,
        rule: u16,
    ) -> bool {
        let Some(held) = self.boxes.get(&id.0) else {
            return false;
        };
        held.pins
            .placed(addr)
            .filter(|placed| placed.is_merged())
            .and_then(|placed| held.merged.get(&placed.set()))
            .is_some_and(|set| {
                set.overflow
                    .iter()
                    .any(|o| o.direction == direction && o.cut == rule)
            })
    }

    /// The first merged list of the box that did not fit one set, once.
    /// Such a list keeps its first rules and refuses every flow the rest
    /// would have judged. `None` when there was none, or the box was told.
    pub fn take_set_overflow(&mut self, id: BoxId) -> Option<SetOverflow> {
        let held = self.boxes.get_mut(&id.0)?;
        let overflow = held.overflow.take()?;
        held.overflow_told = true;
        Some(overflow)
    }

    /// What the box holds of the shared maps. `None` for an unknown box.
    #[must_use]
    pub fn usage(&self, id: BoxId) -> Option<Usage> {
        let Raw(counted) = self.box_use.get(&id.0, 0).unwrap_or_default();
        self.boxes.get(&id.0).map(|held| Usage {
            rule_entries: held.rule_entries(),
            merged_sets: held.merged.len(),
            pins: held.pins.len(),
            pins_refused: held.pins_refused,
            flows: counted.flows,
            listens: counted.listens,
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
        netns: u64,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Result<Option<OriginalDestination>, Error> {
        self.flows.original_destination(netns, peer, protocol)
    }

    /// A handle on the flows map for an endpoint task.
    pub fn flows(&self) -> Result<Flows, Error> {
        self.flows.try_clone()
    }

    /// See [`Listens::listening`].
    pub fn listening(&self, id: BoxId, netns: u64) -> Result<Vec<Listening>, Error> {
        self.listens.listening(id, netns)
    }

    /// A handle on the table of listening sockets for a watcher task.
    pub fn listens(&self) -> Result<Listens, Error> {
        self.listens.try_clone()
    }
}
