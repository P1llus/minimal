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

/// One pin: the name the address was answered for, the set of that name
/// in the policy the pin was last checked against, and when it runs out.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    name: Box<str>,
    set: SetId,
    expiry_ns: u64,
}

/// What a change of policy does to the pins of a box.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rebound {
    /// Pins of names the new policy has no rule for. They are out of the
    /// table. The caller deletes them from the kernel map.
    pub dropped: Vec<IpAddr>,
    /// Pins whose name now belongs to another set, with the new set and
    /// the unchanged expiry. The table has them already. The caller
    /// rewrites them in the kernel map.
    pub moved: Vec<(IpAddr, SetId, u64)>,
}

/// The daemon's view of one box's pins. The kernel holds the same entries.
/// This copy answers "which set is this address pinned to" for the
/// evaluator, "which entries can be deleted" for the sweep, and "which
/// name was this for" when the policy changes.
#[derive(Debug, Clone, Default)]
pub struct PinTable {
    pins: HashMap<IpAddr, Pin>,
}

impl PinTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a pin of `addr` for `name`. A later pin of the same address
    /// replaces the earlier one: an address belongs to one set at a time.
    pub fn insert(&mut self, addr: IpAddr, name: &str, set: SetId, expiry_ns: u64) {
        self.pins.insert(
            canonical(addr),
            Pin {
                name: name.into(),
                set,
                expiry_ns,
            },
        );
    }

    pub fn remove(&mut self, addr: IpAddr) {
        self.pins.remove(&canonical(addr));
    }

    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.pins.contains_key(&canonical(addr))
    }

    /// The set `addr` is pinned to, if the pin is still live.
    #[must_use]
    pub fn live(&self, addr: IpAddr, now_ns: u64) -> Option<SetId> {
        self.pins
            .get(&canonical(addr))
            .filter(|pin| is_live(pin.expiry_ns, now_ns))
            .map(|pin| pin.set)
    }

    /// Removes and returns the addresses whose pins have run out, for the
    /// caller to delete from the kernel map too.
    pub fn take_expired(&mut self, now_ns: u64) -> Vec<IpAddr> {
        let dead: Vec<IpAddr> = self
            .pins
            .iter()
            .filter(|(_, pin)| !is_live(pin.expiry_ns, now_ns))
            .map(|(a, _)| *a)
            .collect();
        for addr in &dead {
            self.pins.remove(addr);
        }
        dead
    }

    /// Checks every pin against a new policy. `set_for` is the policy's
    /// [`crate::Compiled::set_for_name`]. A pin whose name the policy no
    /// longer has a rule for is dropped, and one whose name a more specific
    /// pattern now covers moves to that pattern's set.
    pub fn rebind(&mut self, set_for: impl Fn(&str) -> Option<SetId>) -> Rebound {
        let mut out = Rebound::default();
        self.pins.retain(|addr, pin| match set_for(&pin.name) {
            None => {
                out.dropped.push(*addr);
                false
            }
            Some(set) => {
                if set != pin.set {
                    pin.set = set;
                    out.moved.push((*addr, set, pin.expiry_ns));
                }
                true
            }
        });
        out
    }

    /// Every address with a pin, live or not.
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

    #[test]
    fn the_table_tracks_live_pins() {
        let mut t = PinTable::new();
        t.insert(ip("198.51.100.1"), "a.test", SetId(1), 100);
        t.insert(ip("::ffff:198.51.100.2"), "b.test", SetId(2), 200);
        assert_eq!(t.live(ip("198.51.100.1"), 50), Some(SetId(1)));
        assert_eq!(t.live(ip("198.51.100.1"), 100), None);
        assert_eq!(t.live(ip("198.51.100.2"), 150), Some(SetId(2)));
        t.insert(ip("198.51.100.2"), "c.test", SetId(3), 300);
        assert_eq!(t.live(ip("198.51.100.2"), 250), Some(SetId(3)));
        assert_eq!(t.take_expired(150), [ip("198.51.100.1")]);
        assert_eq!(t.len(), 1);
        t.remove(ip("198.51.100.2"));
        assert!(t.is_empty());
    }

    #[test]
    fn a_new_policy_drops_and_moves_pins_by_their_names() {
        let mut t = PinTable::new();
        t.insert(ip("198.51.100.1"), "gone.test", SetId(1), 100);
        t.insert(ip("198.51.100.2"), "kept.test", SetId(2), 200);
        t.insert(ip("198.51.100.3"), "api.wild.test", SetId(3), 300);
        let rebound = t.rebind(|name| match name {
            "kept.test" => Some(SetId(2)),
            // A more specific pattern now covers the name.
            "api.wild.test" => Some(SetId(9)),
            _ => None,
        });
        assert_eq!(rebound.dropped, [ip("198.51.100.1")]);
        assert_eq!(rebound.moved, [(ip("198.51.100.3"), SetId(9), 300)]);
        assert!(!t.contains(ip("198.51.100.1")));
        assert_eq!(t.live(ip("198.51.100.2"), 0), Some(SetId(2)));
        assert_eq!(t.live(ip("198.51.100.3"), 0), Some(SetId(9)));
    }
}
