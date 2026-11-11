//! Records of the engine's event ring buffer, decoded.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::abi::{self, EVENT_NET, Hook, NO_RULE, Reason};

/// What the engine did with the flow an event reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Denied,
    Allowed,
    Redirected,
}

/// A flow the engine refused, or with flow logging on, admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEvent {
    /// Cgroup id of the box.
    pub box_id: u64,
    /// Boot-time clock, nanoseconds.
    pub time_ns: u64,
    pub hook: Hook,
    pub outcome: Outcome,
    pub reason: Reason,
    /// Position of the deciding rule in the box's compiled rule list.
    pub rule: Option<u16>,
    /// IP protocol number. For a refused socket, the one asked for.
    pub protocol: u16,
    /// Socket type, 0 in the packet hooks.
    pub sock_type: u16,
    /// Unspecified in the system-call hooks, which do not know it yet.
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    /// For ICMP the message type.
    pub dst_port: u16,
    /// 0 in the packet hooks.
    pub pid: u32,
    pub cookie: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Net(NetEvent),
    /// A kind this reader does not know, or a network record with a code it
    /// does not know. The header is still usable.
    Unknown {
        kind: u16,
        box_id: u64,
        time_ns: u64,
    },
}

/// Reads fields off the front of a record.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_ne_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_ne_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_ne_bytes)
    }
}

/// Decodes one record. `None` when it is shorter than its own header says
/// or than the fields this reader knows.
#[must_use]
pub fn decode(record: &[u8]) -> Option<Event> {
    let mut c = Cursor(record);
    let kind = c.u16()?;
    let size = usize::from(c.u16()?);
    let _cpu = c.u32()?;
    let time_ns = c.u64()?;
    let box_id = c.u64()?;
    if size > record.len() || size < size_of::<abi::EvHdr>() {
        return None;
    }
    let unknown = Event::Unknown {
        kind,
        box_id,
        time_ns,
    };
    if kind != EVENT_NET {
        return Some(unknown);
    }
    let hook = c.u8()?;
    let verdict = c.u8()?;
    let reason = c.u8()?;
    let family = c.u8()?;
    let protocol = c.u16()?;
    let sock_type = c.u16()?;
    let src_port = c.u16()?;
    let dst_port = c.u16()?;
    let pid = c.u32()?;
    let rule = c.u32()?;
    let src = c.take::<16>()?;
    let dst = c.take::<16>()?;
    let _pad = c.u32()?;
    let cookie = c.u64()?;

    let outcome = match verdict {
        abi::ACTION_DENY => Outcome::Denied,
        abi::ACTION_ALLOW => Outcome::Allowed,
        abi::ACTION_REDIRECT => Outcome::Redirected,
        _ => return Some(unknown),
    };
    let (Some(hook), Some(reason)) = (Hook::from_code(hook), Reason::from_code(reason)) else {
        return Some(unknown);
    };
    Some(Event::Net(NetEvent {
        box_id,
        time_ns,
        hook,
        outcome,
        reason,
        rule: u16::try_from(rule).ok().filter(|r| *r != NO_RULE),
        protocol,
        sock_type,
        src: abi::addr_of(&src, family),
        src_port,
        dst: abi::addr_of(&dst, family),
        dst_port,
        pid,
        cookie,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u16, size: u16, verdict: u8) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend(kind.to_ne_bytes());
        r.extend(size.to_ne_bytes());
        r.extend(3u32.to_ne_bytes());
        r.extend(1_000u64.to_ne_bytes());
        r.extend(42u64.to_ne_bytes());
        r.extend([Hook::Connect6.code(), verdict, Reason::Rule.code(), 6]);
        r.extend(6u16.to_ne_bytes());
        r.extend(1u16.to_ne_bytes());
        r.extend(0u16.to_ne_bytes());
        r.extend(443u16.to_ne_bytes());
        r.extend(77u32.to_ne_bytes());
        r.extend(5u32.to_ne_bytes());
        r.extend([0u8; 16]);
        r.extend(
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        r.extend(0u32.to_ne_bytes());
        r.extend(9u64.to_ne_bytes());
        r
    }

    #[test]
    fn a_network_record_decodes() {
        let r = record(EVENT_NET, 88, abi::ACTION_DENY);
        assert_eq!(r.len(), size_of::<abi::EvNet>());
        let Some(Event::Net(e)) = decode(&r) else {
            panic!("not a net event")
        };
        assert_eq!(
            (e.box_id, e.time_ns, e.hook, e.outcome),
            (42, 1_000, Hook::Connect6, Outcome::Denied)
        );
        assert_eq!(
            (e.reason, e.rule, e.protocol, e.pid, e.cookie),
            (Reason::Rule, Some(5), 6, 77, 9)
        );
        assert_eq!(
            (e.dst.to_string().as_str(), e.dst_port),
            ("2001:db8::1", 443)
        );
    }

    #[test]
    fn a_longer_record_of_a_known_kind_still_decodes() {
        let mut r = record(EVENT_NET, 96, abi::ACTION_ALLOW);
        r.extend([0xaa; 8]);
        assert!(matches!(decode(&r), Some(Event::Net(e)) if e.outcome == Outcome::Allowed));
    }

    #[test]
    fn unknown_kinds_and_codes_keep_the_header() {
        let r = record(7, 88, 0);
        assert_eq!(
            decode(&r),
            Some(Event::Unknown {
                kind: 7,
                box_id: 42,
                time_ns: 1_000
            })
        );
        let r = record(EVENT_NET, 88, 9);
        assert_eq!(
            decode(&r),
            Some(Event::Unknown {
                kind: EVENT_NET,
                box_id: 42,
                time_ns: 1_000
            })
        );
    }

    #[test]
    fn short_records_are_rejected() {
        let r = record(EVENT_NET, 88, 0);
        assert_eq!(decode(&r[..87]), None);
        assert_eq!(decode(&r[..10]), None);
        // A header that claims more than there is.
        assert_eq!(decode(&record(7, 200, 0)), None);
    }
}
