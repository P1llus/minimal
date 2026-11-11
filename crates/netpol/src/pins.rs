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

const fn in4(a: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    a.to_bits() & mask == u32::from_be_bytes(net)
}

const fn in6(a: Ipv6Addr, first: u16, len: u32) -> bool {
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    a.to_bits() & mask == (first as u128) << 112
}

/// True for an address a public name has no business resolving to: private
/// and unique-local ranges, loopback, link-local, carrier-grade NAT,
/// multicast, broadcast and unspecified. A v4-mapped or NAT64 address is
/// judged by the IPv4 address it carries.
#[must_use]
pub fn is_internal(addr: IpAddr) -> bool {
    match canonical(addr) {
        IpAddr::V4(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || in4(a, [100, 64, 0, 0], 10)
                || in4(a, [0, 0, 0, 0], 8)
                || in4(a, [240, 0, 0, 0], 4)
        }
        IpAddr::V6(a) => {
            // NAT64 carries an IPv4 address in its last 32 bits.
            if let [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] = a.segments() {
                let v4 = Ipv4Addr::from_bits((u32::from(hi) << 16) | u32::from(lo));
                return is_internal(IpAddr::V4(v4));
            }
            a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || in6(a, 0xfc00, 7)
                || in6(a, 0xfe80, 10)
        }
    }
}

/// The rebinding filter: whether the resolver may pin `addr` for a name.
///
/// An internal address or one of the box's infrastructure addresses is
/// refused unless a prefix the box allows covers it. That keeps a public
/// name from being pointed at something the box was never meant to reach.
#[must_use]
pub fn may_pin(addr: IpAddr, allowed: &[Prefix], infrastructure: &[Prefix]) -> bool {
    let addr = canonical(addr);
    let suspicious = is_internal(addr) || infrastructure.iter().any(|p| p.contains(addr));
    !suspicious || allowed.iter().any(|p| p.contains(addr))
}

/// The daemon's view of one box's pins. The kernel holds the same entries.
/// This copy answers "which set is this address pinned to" for the
/// evaluator and "which entries can be deleted" for the sweep.
#[derive(Debug, Clone, Default)]
pub struct PinTable {
    pins: HashMap<IpAddr, (SetId, u64)>,
}

impl PinTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a pin. A later pin of the same address replaces the earlier
    /// one: an address belongs to one set at a time.
    pub fn insert(&mut self, addr: IpAddr, set: SetId, expiry_ns: u64) {
        self.pins.insert(canonical(addr), (set, expiry_ns));
    }

    pub fn remove(&mut self, addr: IpAddr) {
        self.pins.remove(&canonical(addr));
    }

    /// The set `addr` is pinned to, if the pin is still live.
    #[must_use]
    pub fn live(&self, addr: IpAddr, now_ns: u64) -> Option<SetId> {
        self.pins
            .get(&canonical(addr))
            .filter(|(_, expiry)| is_live(*expiry, now_ns))
            .map(|(set, _)| *set)
    }

    /// Removes and returns the addresses whose pins have run out, for the
    /// caller to delete from the kernel map too.
    pub fn take_expired(&mut self, now_ns: u64) -> Vec<IpAddr> {
        let dead: Vec<IpAddr> = self
            .pins
            .iter()
            .filter(|(_, (_, expiry))| !is_live(*expiry, now_ns))
            .map(|(a, _)| *a)
            .collect();
        for addr in &dead {
            self.pins.remove(addr);
        }
        dead
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
    fn the_filter_lets_allowed_prefixes_through() {
        let allowed = ["10.20.0.0/16".parse().unwrap()];
        let infra = ["192.0.2.1/32".parse().unwrap()];
        assert!(may_pin(ip("93.184.216.34"), &allowed, &infra));
        assert!(!may_pin(ip("10.1.1.1"), &allowed, &infra));
        assert!(may_pin(ip("10.20.3.4"), &allowed, &infra));
        // A public address that is the box's gateway.
        assert!(!may_pin(ip("192.0.2.1"), &allowed, &infra));
        assert!(may_pin(
            ip("192.0.2.1"),
            &["192.0.2.0/24".parse().unwrap()],
            &infra
        ));
    }

    #[test]
    fn the_table_tracks_live_pins() {
        let mut t = PinTable::new();
        t.insert(ip("198.51.100.1"), SetId(1), 100);
        t.insert(ip("::ffff:198.51.100.2"), SetId(2), 200);
        assert_eq!(t.live(ip("198.51.100.1"), 50), Some(SetId(1)));
        assert_eq!(t.live(ip("198.51.100.1"), 100), None);
        assert_eq!(t.live(ip("198.51.100.2"), 150), Some(SetId(2)));
        t.insert(ip("198.51.100.2"), SetId(3), 300);
        assert_eq!(t.live(ip("198.51.100.2"), 250), Some(SetId(3)));
        assert_eq!(t.take_expired(150), [ip("198.51.100.1")]);
        assert_eq!(t.len(), 1);
        t.remove(ip("198.51.100.2"));
        assert!(t.is_empty());
    }
}
