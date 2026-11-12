//! Bookkeeping for pins: addresses the resolver answered for a name the
//! box may reach.
//!
//! Time is the boot-time clock in nanoseconds, passed in by the caller. The
//! kernel programs compare a pin's expiry against the same clock.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use crate::{
    base::{prefix4, prefix6},
    eval::canonical,
    model::{Prefix, SetId},
};

/// How long an answered address stays reachable for new flows.
pub const PIN_TTL: Duration = Duration::from_secs(300);

/// When a pin made at `now_ns` stops admitting new flows.
#[must_use]
pub fn expiry(now_ns: u64, ttl: Duration) -> u64 {
    now_ns.saturating_add(u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX))
}

/// The programs admit a pin while its expiry is still ahead.
#[must_use]
pub const fn is_live(expiry_ns: u64, now_ns: u64) -> bool {
    expiry_ns > now_ns
}

/// IPv4 ranges a public name has no business resolving to: this network,
/// private, carrier-grade NAT, loopback, link-local, multicast, and the
/// reserved top that ends in the broadcast address.
const INTERNAL4: [Prefix; 9] = [
    prefix4(Ipv4Addr::new(0, 0, 0, 0), 8),
    prefix4(Ipv4Addr::new(10, 0, 0, 0), 8),
    prefix4(Ipv4Addr::new(100, 64, 0, 0), 10),
    prefix4(Ipv4Addr::new(127, 0, 0, 0), 8),
    prefix4(Ipv4Addr::new(169, 254, 0, 0), 16),
    prefix4(Ipv4Addr::new(172, 16, 0, 0), 12),
    prefix4(Ipv4Addr::new(192, 168, 0, 0), 16),
    prefix4(Ipv4Addr::new(224, 0, 0, 0), 4),
    prefix4(Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// The same for IPv6: unspecified, loopback, unique local, link-local and
/// multicast.
const INTERNAL6: [Prefix; 5] = [
    Prefix::host(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    Prefix::host(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    prefix6(0xfc00, 7),
    prefix6(0xfe80, 10),
    prefix6(0xff00, 8),
];

/// The internal ranges `addr` lies in. A NAT64 address is in the range of
/// the IPv4 address it carries, as an IPv6 prefix.
fn internal_ranges(addr: IpAddr) -> Vec<Prefix> {
    let within = |table: &[Prefix], a: IpAddr| -> Vec<Prefix> {
        table.iter().filter(|r| r.contains(a)).copied().collect()
    };
    match addr {
        IpAddr::V4(_) => within(&INTERNAL4, addr),
        IpAddr::V6(a) => {
            if let [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] = a.segments() {
                let v4 = Ipv4Addr::from_bits((u32::from(hi) << 16) | u32::from(lo));
                return within(&INTERNAL4, IpAddr::V4(v4))
                    .into_iter()
                    .map(|range| Prefix::host(addr).truncated(96 + range.len()))
                    .collect();
            }
            within(&INTERNAL6, addr)
        }
    }
}

/// True for an address a public name has no business resolving to: private
/// and unique-local ranges, loopback, link-local, carrier-grade NAT,
/// multicast, broadcast and unspecified. A v4-mapped or NAT64 address is
/// judged by the IPv4 address it carries.
#[must_use]
pub fn is_internal(addr: IpAddr) -> bool {
    !internal_ranges(canonical(addr)).is_empty()
}

/// The rebinding filter: whether the resolver may pin `addr` for a name.
///
/// An address in an internal range, or in one of the box's `protected`
/// ranges, is refused unless the box allows a prefix that holds the address
/// and itself lies inside every such range the address is in. That is the
/// test [`crate::Rule::reaches_into`] makes for the box's rules, so a wide
/// allow such as `0.0.0.0/0` neither opens a protected range nor switches
/// this filter off. It keeps a public name from being pointed at something
/// the box was never meant to reach.
#[must_use]
pub fn may_pin(addr: IpAddr, allowed: &[Prefix], protected: &[Prefix]) -> bool {
    let addr = canonical(addr);
    let mut around = internal_ranges(addr);
    around.extend(
        protected
            .iter()
            .map(Prefix::canonical)
            .filter(|range| range.contains(addr)),
    );
    around.is_empty()
        || allowed
            .iter()
            .map(Prefix::canonical)
            .any(|p| p.contains(addr) && around.iter().all(|range| range.covers(&p)))
}

/// The names remembered for one address at a time. A name of a set the
/// address already has takes the place of that set's oldest name, so only
/// an address that names of more sets than this resolve to is refused.
pub const NAMES_PER_ADDRESS: usize = 8;

/// One name an address was answered for, the set of that name in the
/// policy the pin was last checked against, and when it runs out.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    name: Box<str>,
    set: SetId,
    expiry_ns: u64,
}

/// What the engine's entry for an address says: the sets whose rules judge
/// the address, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The sets of the names that are live for the address, sorted, each
    /// once.
    pub members: Vec<SetId>,
    /// When the first of those sets loses its last live name. The entry
    /// admits nothing from then on, and the sets are worked out again.
    pub expiry_ns: u64,
}

impl Placement {
    /// The set the address is pinned to: its one set, or the merged set of
    /// several ([`merged_id`]).
    #[must_use]
    pub fn set(&self) -> SetId {
        match self.members.as_slice() {
            [one] => *one,
            many => merged_id(many),
        }
    }

    #[must_use]
    pub const fn is_merged(&self) -> bool {
        self.members.len() > 1
    }
}

/// The id of the set that stands for several sets at once. The same members
/// give the same id under every policy of a box.
#[must_use]
pub fn merged_id(members: &[SetId]) -> SetId {
    // FNV-1a, 64 bits, over a tag no name pattern starts with.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let ids = members.iter().flat_map(|id| id.0.to_le_bytes());
    for byte in b"+".iter().copied().chain(ids) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Not the id of the box's own addresses.
    SetId(hash.max(1))
}

/// An address is pinned for names of more sets than a table remembers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("names of more than {NAMES_PER_ADDRESS} rules resolve to the address")]
pub struct TooManyNames;

#[derive(Debug, Clone, Default)]
struct Address {
    names: Vec<Pin>,
    /// What the engine's entry holds, as the caller last recorded it.
    placed: Option<Placement>,
    /// Set when a name did not fit. Until then nothing judges the address:
    /// the rules of the name left out could have been the ones that refuse.
    closed_until_ns: u64,
}

impl Address {
    fn wanted(&self, now_ns: u64) -> Option<Placement> {
        if is_live(self.closed_until_ns, now_ns) {
            return None;
        }
        // A set stays for as long as any of its names is live.
        let mut sets: Vec<(SetId, u64)> = Vec::new();
        for pin in self.names.iter().filter(|p| is_live(p.expiry_ns, now_ns)) {
            match sets.iter_mut().find(|(set, _)| *set == pin.set) {
                Some((_, expiry)) => *expiry = (*expiry).max(pin.expiry_ns),
                None => sets.push((pin.set, pin.expiry_ns)),
            }
        }
        let expiry_ns = sets.iter().map(|(_, expiry)| *expiry).min()?;
        let mut members: Vec<SetId> = sets.into_iter().map(|(set, _)| set).collect();
        members.sort_unstable();
        Some(Placement { members, expiry_ns })
    }
}

/// The daemon's view of one box's pins: every name an address was answered
/// for, and what the engine's entry for the address holds. Names of several
/// rules can resolve to one address, and the address is then judged by the
/// rules of all of them.
///
/// The table decides what an entry should hold ([`Self::wanted`]). The
/// caller writes the entry and records it ([`Self::set_placed`]). What is
/// recorded answers "which sets is this address in" for the evaluator.
#[derive(Debug, Clone, Default)]
pub struct PinTable {
    pins: HashMap<IpAddr, Address>,
}

impl PinTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `addr` was answered for `name`, which is in `set`,
    /// until `expiry_ns`. Other names of the address stay.
    ///
    /// # Errors
    ///
    /// [`TooManyNames`] when the address has [`NAMES_PER_ADDRESS`] live
    /// names, each of another set than `set`. The name is not recorded,
    /// and the address wants no entry until every name it has, and this
    /// one, would have run out.
    pub fn insert(
        &mut self,
        addr: IpAddr,
        name: &str,
        set: SetId,
        expiry_ns: u64,
        now_ns: u64,
    ) -> Result<(), TooManyNames> {
        let address = self.pins.entry(canonical(addr)).or_default();
        if let Some(pin) = address.names.iter_mut().find(|p| &*p.name == name) {
            pin.set = set;
            pin.expiry_ns = expiry_ns;
            return Ok(());
        }
        let pin = Pin {
            name: name.into(),
            set,
            expiry_ns,
        };
        address.names.retain(|p| is_live(p.expiry_ns, now_ns));
        if address.names.len() < NAMES_PER_ADDRESS {
            address.names.push(pin);
            return Ok(());
        }
        // Names of one set have the same rules: the one that runs out
        // first gives its place to the new one.
        let oldest = address
            .names
            .iter_mut()
            .filter(|p| p.set == set)
            .min_by_key(|p| p.expiry_ns);
        if let Some(place) = oldest {
            *place = pin;
            return Ok(());
        }
        let last = address.names.iter().map(|p| p.expiry_ns).max();
        address.closed_until_ns = last.map_or(expiry_ns, |last| last.max(expiry_ns));
        Err(TooManyNames)
    }

    /// The names `addr` was answered for, live or not.
    #[must_use]
    pub fn names(&self, addr: IpAddr) -> Vec<&str> {
        self.pins
            .get(&canonical(addr))
            .map(|address| address.names.iter().map(|p| &*p.name).collect())
            .unwrap_or_default()
    }

    /// Forgets the address and every name it was answered for.
    pub fn remove(&mut self, addr: IpAddr) {
        self.pins.remove(&canonical(addr));
    }

    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.pins.contains_key(&canonical(addr))
    }

    /// What the engine's entry for `addr` should hold at `now_ns`. `None`
    /// when no name of the address is live.
    #[must_use]
    pub fn wanted(&self, addr: IpAddr, now_ns: u64) -> Option<Placement> {
        self.pins.get(&canonical(addr))?.wanted(now_ns)
    }

    /// What the engine's entry for `addr` holds, live or not.
    #[must_use]
    pub fn placed(&self, addr: IpAddr) -> Option<&Placement> {
        self.pins.get(&canonical(addr))?.placed.as_ref()
    }

    /// Records what the engine's entry for `addr` holds now. An address
    /// with no entry and no name is forgotten.
    pub fn set_placed(&mut self, addr: IpAddr, placed: Option<Placement>) {
        let addr = canonical(addr);
        let Some(address) = self.pins.get_mut(&addr) else {
            return;
        };
        address.placed = placed;
        if address.placed.is_none() && address.names.is_empty() {
            self.pins.remove(&addr);
        }
    }

    /// The sets whose rules judge `addr` at `now_ns`, as the engine's entry
    /// has them. Empty for an address with no live entry.
    #[must_use]
    pub fn live(&self, addr: IpAddr, now_ns: u64) -> Vec<SetId> {
        self.placed(addr)
            .filter(|placed| is_live(placed.expiry_ns, now_ns))
            .map(|placed| placed.members.clone())
            .unwrap_or_default()
    }

    /// Drops the names that have run out and returns the addresses that
    /// lost one. The caller works out each one's entry again.
    pub fn expire(&mut self, now_ns: u64) -> Vec<IpAddr> {
        let mut changed = Vec::new();
        self.pins.retain(|addr, address| {
            let before = address.names.len();
            address.names.retain(|p| is_live(p.expiry_ns, now_ns));
            if address.names.is_empty() && address.placed.is_none() {
                return false;
            }
            if address.names.len() != before {
                changed.push(*addr);
            }
            true
        });
        changed
    }

    /// Checks every name against a new policy. `set_for` is the policy's
    /// [`crate::Compiled::set_for_name`]. A name the policy no longer has a
    /// rule for is dropped, and one a more specific pattern now covers
    /// moves to that pattern's set. The caller then works out the entry of
    /// every address again: the rules of a set differ from one policy to
    /// the next.
    pub fn rebind(&mut self, set_for: impl Fn(&str) -> Option<SetId>) {
        for address in self.pins.values_mut() {
            address.names.retain_mut(|pin| match set_for(&pin.name) {
                Some(set) => {
                    pin.set = set;
                    true
                }
                None => false,
            });
        }
    }

    /// When the first entry runs out while a name of its address is still
    /// live: that address is judged by nothing until its entry is worked
    /// out again.
    #[must_use]
    pub fn next_change(&self) -> Option<u64> {
        self.pins
            .values()
            .filter_map(|address| {
                let placed = address.placed.as_ref()?;
                address
                    .names
                    .iter()
                    .any(|p| p.expiry_ns > placed.expiry_ns)
                    .then_some(placed.expiry_ns)
            })
            .min()
    }

    /// Every address the table knows, with or without a live name.
    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.pins.keys().copied()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn expiry_arithmetic() {
        assert_eq!(expiry(1_000, Duration::from_secs(1)), 1_000_001_000);
        assert_eq!(expiry(u64::MAX - 5, PIN_TTL), u64::MAX);
        assert!(is_live(10, 9));
        assert!(!is_live(10, 10));
    }

    #[test]
    fn internal_addresses() {
        for a in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(is_internal(ip(a)), "{a}");
        }
        for a in [
            "8.8.8.8",
            "100.63.0.1",
            "172.32.0.1",
            "2001:4860::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(!is_internal(ip(a)), "{a}");
        }
    }

    #[test]
    fn the_filter_passes_what_the_box_allows_inside_the_range() {
        let allowed = ["10.20.0.0/16".parse().unwrap()];
        let protected = ["192.0.2.1/32".parse().unwrap()];
        assert!(may_pin(ip("93.184.216.34"), &allowed, &protected));
        assert!(!may_pin(ip("10.1.1.1"), &allowed, &protected));
        assert!(may_pin(ip("10.20.3.4"), &allowed, &protected));
        assert!(may_pin(ip("::ffff:10.20.3.4"), &allowed, &protected));
        // A public address that is the box's gateway.
        assert!(!may_pin(ip("192.0.2.1"), &allowed, &protected));
        assert!(!may_pin(
            ip("192.0.2.1"),
            &["192.0.2.0/24".parse().unwrap()],
            &protected
        ));
        assert!(may_pin(
            ip("192.0.2.1"),
            &["192.0.2.1/32".parse().unwrap()],
            &protected
        ));
    }

    #[test]
    fn a_wide_allow_does_not_switch_the_filter_off() {
        let everything: [Prefix; 2] = ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        let subnet = ["100.64.0.0/24".parse().unwrap()];
        for a in [
            "10.1.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.7",
            "fe80::1",
            "fd00::1",
            "64:ff9b::a00:1",
        ] {
            assert!(!may_pin(ip(a), &everything, &subnet), "{a}");
        }
        assert!(may_pin(ip("8.8.8.8"), &everything, &subnet));
        assert!(may_pin(ip("2001:4860::1"), &everything, &subnet));
        // The carrier-grade NAT range is allowed, the virtual network in
        // it is still closed. Its own prefix opens it.
        let tailnet = ["100.64.0.0/10".parse().unwrap()];
        assert!(may_pin(ip("100.100.1.1"), &tailnet, &subnet));
        assert!(!may_pin(ip("100.64.0.7"), &tailnet, &subnet));
        assert!(may_pin(ip("100.64.0.7"), &subnet, &subnet));
        // A NAT64 address is allowed by a prefix inside the mapped range.
        let nat64 = ["64:ff9b::a14:0/112".parse().unwrap()];
        assert!(may_pin(ip("64:ff9b::a14:304"), &nat64, &subnet));
        assert!(!may_pin(ip("64:ff9b::a15:304"), &nat64, &subnet));
    }

    /// Places every address as the table wants it, as a caller with no
    /// limits would.
    fn place_all(t: &mut PinTable, now: u64) {
        for addr in t.addresses().collect::<Vec<_>>() {
            let wanted = t.wanted(addr, now);
            t.set_placed(addr, wanted);
        }
    }

    #[test]
    fn the_table_tracks_live_pins() {
        let mut t = PinTable::new();
        t.insert(ip("198.51.100.1"), "a.test", SetId(1), 100, 0)
            .unwrap();
        t.insert(ip("::ffff:198.51.100.2"), "b.test", SetId(2), 200, 0)
            .unwrap();
        place_all(&mut t, 0);
        assert_eq!(t.live(ip("198.51.100.1"), 50), [SetId(1)]);
        assert_eq!(t.live(ip("198.51.100.1"), 100), []);
        assert_eq!(t.live(ip("198.51.100.2"), 150), [SetId(2)]);
        assert_eq!(t.expire(150), [ip("198.51.100.1")]);
        assert_eq!(t.wanted(ip("198.51.100.1"), 150), None);
        t.set_placed(ip("198.51.100.1"), None);
        assert_eq!(t.len(), 1);
        t.remove(ip("198.51.100.2"));
        assert!(t.is_empty());
    }

    #[test]
    fn an_address_of_several_names_is_in_the_sets_of_all_of_them() {
        let mut t = PinTable::new();
        let shared = ip("198.51.100.2");
        t.insert(shared, "b.test", SetId(7), 200, 0).unwrap();
        t.insert(shared, "c.test", SetId(3), 300, 0).unwrap();
        let wanted = t.wanted(shared, 0).expect("two live names");
        assert_eq!(wanted.members, [SetId(3), SetId(7)]);
        // The entry runs out with the first set that does.
        assert_eq!(wanted.expiry_ns, 200);
        assert!(wanted.is_merged());
        assert_eq!(wanted.set(), merged_id(&[SetId(3), SetId(7)]));
        assert_ne!(wanted.set(), merged_id(&[SetId(3)]));
        assert_ne!(wanted.set(), merged_id(&[SetId(7), SetId(3)]));
        t.set_placed(shared, Some(wanted));
        assert_eq!(t.live(shared, 199), [SetId(3), SetId(7)]);
        // Between the entry's end and its rewrite nothing judges the
        // address, and the table says when that is.
        assert_eq!(t.live(shared, 200), []);
        assert_eq!(t.next_change(), Some(200));
        assert_eq!(t.expire(200), [shared]);
        let left = t.wanted(shared, 200).expect("one live name");
        assert_eq!(
            (left.members.as_slice(), left.expiry_ns),
            (&[SetId(3)][..], 300)
        );
        assert_eq!(left.set(), SetId(3));
        t.set_placed(shared, Some(left));
        assert_eq!(t.next_change(), None);
    }

    #[test]
    fn a_set_stays_for_as_long_as_one_of_its_names_is_live() {
        let mut t = PinTable::new();
        let addr = ip("198.51.100.3");
        t.insert(addr, "a.wild.test", SetId(5), 100, 0).unwrap();
        t.insert(addr, "b.wild.test", SetId(5), 400, 0).unwrap();
        t.insert(addr, "other.test", SetId(6), 300, 0).unwrap();
        let wanted = t.wanted(addr, 0).unwrap();
        assert_eq!(wanted.members, [SetId(5), SetId(6)]);
        assert_eq!(wanted.expiry_ns, 300);
        // The same name again moves its own end and adds nothing.
        t.insert(addr, "other.test", SetId(6), 500, 0).unwrap();
        assert_eq!(t.wanted(addr, 0).unwrap().expiry_ns, 400);
    }

    #[test]
    fn an_address_remembers_a_bounded_number_of_names() {
        let mut t = PinTable::new();
        let addr = ip("198.51.100.4");
        for i in 0..NAMES_PER_ADDRESS {
            let i = u64::try_from(i).unwrap();
            t.insert(addr, &format!("n{i}.test"), SetId(10 + i), 100 + i, 0)
                .unwrap();
        }
        // A name of a set the address has takes the place of that set's
        // oldest name. A name of one more set does not fit.
        t.insert(addr, "again.test", SetId(10), 900, 0).unwrap();
        assert_eq!(t.wanted(addr, 0).unwrap().members.len(), NAMES_PER_ADDRESS);
        assert_eq!(
            t.insert(addr, "more.test", SetId(99), 950, 0),
            Err(TooManyNames)
        );
        // The rules of the name left out judge nothing, so nothing may:
        // the address has no entry until all of these names have run out.
        assert_eq!(t.wanted(addr, 0), None);
        assert_eq!(t.wanted(addr, 949), None);
        assert_eq!(t.names(addr).len(), NAMES_PER_ADDRESS);
        // After that a name fits again.
        t.insert(addr, "more.test", SetId(99), 2000, 950).unwrap();
        assert_eq!(t.wanted(addr, 950).unwrap().members, [SetId(99)]);
    }

    #[test]
    fn a_new_policy_drops_and_moves_names() {
        let mut t = PinTable::new();
        t.insert(ip("198.51.100.1"), "gone.test", SetId(1), 100, 0)
            .unwrap();
        t.insert(ip("198.51.100.2"), "kept.test", SetId(2), 200, 0)
            .unwrap();
        t.insert(ip("198.51.100.2"), "gone.test", SetId(1), 200, 0)
            .unwrap();
        t.insert(ip("198.51.100.3"), "api.wild.test", SetId(3), 300, 0)
            .unwrap();
        place_all(&mut t, 0);
        t.rebind(|name| match name {
            "kept.test" => Some(SetId(2)),
            // A more specific pattern now covers the name.
            "api.wild.test" => Some(SetId(9)),
            _ => None,
        });
        // The entries are the caller's to rewrite.
        assert_eq!(t.wanted(ip("198.51.100.1"), 0), None);
        assert_eq!(t.wanted(ip("198.51.100.2"), 0).unwrap().members, [SetId(2)]);
        assert_eq!(t.wanted(ip("198.51.100.3"), 0).unwrap().members, [SetId(9)]);
        assert_eq!(t.live(ip("198.51.100.3"), 0), [SetId(3)]);
        place_all(&mut t, 0);
        assert!(!t.contains(ip("198.51.100.1")));
        assert_eq!(t.live(ip("198.51.100.3"), 0), [SetId(9)]);
    }
}
