//! Judging a flow in Rust, the way the kernel programs judge it.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::{
    compile::{Compiled, Slot},
    model::{
        Action, Defaults, Direction, Family, NamePattern, Prefix, Protocol, Rule, SetId, Target,
        Verdict,
    },
};

pub use crate::abi::Reason;

/// A new flow of a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub direction: Direction,
    pub protocol: Protocol,
    /// The other end. For a bind, the local address being bound.
    pub remote: IpAddr,
    /// Egress: destination port. Ingress and bind: local port. ICMP: the
    /// message type.
    pub port: u16,
    /// The box's own address of the flow, when known. Only the source
    /// check looks at it.
    pub local: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowVerdict {
    Allow,
    Deny,
    /// The flow goes to this endpoint address instead.
    Redirect(SocketAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: FlowVerdict,
    /// Position of the deciding rule in [`Compiled::rules`].
    pub rule: Option<u16>,
    pub reason: Reason,
}

/// An address the way the programs see it: a v4-mapped IPv6 address is
/// IPv4, because that is what goes on the wire.
#[must_use]
pub fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

const fn is_link_local6(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

fn first_match(slots: &[Slot], flow: &Flow, below: Option<u16>) -> Option<Slot> {
    slots
        .iter()
        .take_while(|s| below.is_none_or(|limit| s.prio < limit))
        .find(|s| s.protocols.contains(flow.protocol) && s.ports.contains(flow.port))
        .copied()
}

impl Compiled {
    /// Whether a packet from `local` passes the source check.
    fn source_ok(&self, local: IpAddr) -> bool {
        match local {
            IpAddr::V4(a) => self.config.addrs.v4 == Some(a) || a.is_loopback(),
            IpAddr::V6(a) => {
                self.config.addrs.v6 == Some(a)
                    || a.is_loopback()
                    || a.is_unspecified()
                    || is_link_local6(a)
            }
        }
    }

    /// Judges a new flow. `pinned` is the set the remote address is
    /// currently pinned to, if any: the caller looks it up and checks that
    /// the pin has not expired.
    ///
    /// The kernel judges new flows only: a TCP segment after the SYN, a UDP
    /// packet to a peer the other direction admitted, and an ICMP echo reply
    /// pass without a verdict.
    #[must_use]
    pub fn evaluate(&self, flow: &Flow, pinned: Option<SetId>) -> Decision {
        let remote = canonical(flow.remote);
        if flow.direction == Direction::Egress
            && self.config.source_check
            && let Some(local) = flow.local
            && !self.source_ok(canonical(local))
        {
            return Decision {
                verdict: FlowVerdict::Deny,
                rule: None,
                reason: Reason::SourceAddress,
            };
        }

        let by_prefix = self
            .nets
            .iter()
            .filter(|e| e.direction == flow.direction && e.prefix.contains(remote))
            .max_by_key(|e| e.prefix.len())
            .and_then(|e| first_match(&e.rules, flow, None))
            .map(|slot| (slot, Reason::Rule));
        let by_set = pinned
            .and_then(|id| self.set_rules(id, flow.direction))
            .and_then(|rules| first_match(rules, flow, by_prefix.map(|(slot, _)| slot.prio)))
            .map(|slot| (slot, Reason::SetRule));

        let Some((slot, reason)) = by_set.or(by_prefix) else {
            let verdict = match self.config.defaults.of(flow.direction) {
                Verdict::Allow => FlowVerdict::Allow,
                Verdict::Deny => FlowVerdict::Deny,
            };
            return Decision {
                verdict,
                rule: None,
                reason: Reason::Default,
            };
        };
        let rule = Some(slot.prio);
        match slot.action {
            Action::Allow => Decision {
                verdict: FlowVerdict::Allow,
                rule,
                reason,
            },
            Action::Deny => Decision {
                verdict: FlowVerdict::Deny,
                rule,
                reason,
            },
            Action::Redirect(index) => {
                let to = self
                    .endpoint(index)
                    .and_then(|e| match Family::of(&remote) {
                        Family::V4 => e.v4.map(SocketAddr::V4),
                        Family::V6 => e.v6.map(SocketAddr::V6),
                    });
                match to {
                    Some(addr) => Decision {
                        verdict: FlowVerdict::Redirect(addr),
                        rule,
                        reason,
                    },
                    None => Decision {
                        verdict: FlowVerdict::Deny,
                        rule,
                        reason: Reason::NoEndpoint,
                    },
                }
            }
        }
    }
}

/// Judges a flow against the ordered rule list itself, with no compiled
/// form in between. `protected` are the base policy's protected ranges and
/// `name` is the name the remote address is pinned for.
///
/// Returns the position and action of the first matching rule, or `None`
/// and the default. This is the reference [`Compiled::evaluate`] is tested
/// against.
#[must_use]
pub fn evaluate_ordered(
    rules: &[Rule],
    protected: &[Prefix],
    defaults: &Defaults,
    flow: &Flow,
    name: Option<&str>,
) -> (Option<usize>, Action) {
    let remote = canonical(flow.remote);
    let around: Vec<&Prefix> = protected
        .iter()
        .filter(|range| flow.direction == Direction::Egress && range.contains(remote))
        .collect();
    let hit = rules.iter().enumerate().find(|(_, r)| {
        r.direction == flow.direction
            && r.matches_l4(flow.protocol, flow.port)
            && around.iter().all(|range| r.reaches_into(range))
            && match &r.target {
                Target::Any => true,
                Target::Net(p) => p.contains(remote),
                Target::Names(pattern) => name.is_some_and(|n| pattern.matches(n)),
            }
    });
    match hit {
        Some((i, r)) => (Some(i), r.action),
        None => {
            let action = match defaults.of(flow.direction) {
                Verdict::Allow => Action::Allow,
                Verdict::Deny => Action::Deny,
            };
            (None, action)
        }
    }
}

/// The pattern a set stands for. Lets a caller that only has a pin's set
/// find the names it covers.
#[must_use]
pub fn pattern_of(compiled: &Compiled, id: SetId) -> Option<&NamePattern> {
    compiled
        .names
        .iter()
        .find(|(_, set)| *set == id)
        .map(|(pattern, _)| pattern)
}

/// The echo request type of a family. A ping socket can send nothing else,
/// so this is the "port" of an ICMP flow judged at `connect`.
#[must_use]
pub const fn echo_request(family: Family) -> u16 {
    match family {
        Family::V4 => 8,
        Family::V6 => 128,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use crate::{
        base::{BasePolicy, BoxAddrs, RESOLVER},
        compile::{Options, compile},
        model::{Endpoint, Origin, PortRange, Protocols},
        policy::BoxPolicy,
    };

    fn base() -> BasePolicy {
        BasePolicy {
            before: Vec::new(),
            protected: Vec::new(),
            defaults: Defaults {
                egress: Verdict::Deny,
                ingress: Verdict::Deny,
                bind: Verdict::Allow,
            },
            endpoints: Vec::new(),
            source_check: false,
            addrs: BoxAddrs::default(),
        }
    }

    fn egress(protocol: Protocol, remote: &str, port: u16) -> Flow {
        Flow {
            direction: Direction::Egress,
            protocol,
            remote: remote.parse().unwrap(),
            port,
            local: None,
        }
    }

    #[test]
    fn longest_prefix_then_first_rule() {
        let policy = BoxPolicy {
            deny: vec!["10.1.2.0/24".parse().unwrap()],
            allow: vec![
                "10.1.0.0/16".parse().unwrap(),
                "fd00:1::/32".parse().unwrap(),
            ],
            ..BoxPolicy::default()
        };
        let c = compile(&base(), &policy, Options::default()).unwrap();
        let d = c.evaluate(&egress(Protocol::Tcp, "10.1.1.1", 80), None);
        assert_eq!(
            (d.verdict, d.rule, d.reason),
            (FlowVerdict::Allow, Some(1), Reason::Rule)
        );
        let d = c.evaluate(&egress(Protocol::Tcp, "10.1.2.1", 80), None);
        assert_eq!((d.verdict, d.rule), (FlowVerdict::Deny, Some(0)));
        let d = c.evaluate(&egress(Protocol::Tcp, "10.2.0.1", 80), None);
        assert_eq!(
            (d.verdict, d.rule, d.reason),
            (FlowVerdict::Deny, None, Reason::Default)
        );
        assert_eq!(
            c.evaluate(&egress(Protocol::Udp, "fd00:1::9", 53), None)
                .verdict,
            FlowVerdict::Allow
        );
        // A v4-mapped address is judged as IPv4.
        assert_eq!(
            c.evaluate(&egress(Protocol::Tcp, "::ffff:10.1.1.1", 80), None)
                .verdict,
            FlowVerdict::Allow
        );
        assert_eq!(
            c.evaluate(&egress(Protocol::Tcp, "::ffff:10.1.2.1", 80), None)
                .verdict,
            FlowVerdict::Deny
        );
    }

    #[test]
    fn a_pin_admits_what_the_default_refuses_and_an_earlier_prefix_rule_still_wins() {
        let policy = BoxPolicy {
            deny: vec!["203.0.113.0/24".parse().unwrap()],
            names: vec!["example.com".parse().unwrap()],
            ..BoxPolicy::default()
        };
        let c = compile(&base(), &policy, Options::default()).unwrap();
        let set = c.set_for_name("example.com");
        let d = c.evaluate(&egress(Protocol::Tcp, "198.51.100.7", 443), set);
        assert_eq!((d.verdict, d.reason), (FlowVerdict::Allow, Reason::SetRule));
        assert_eq!(
            c.evaluate(&egress(Protocol::Tcp, "198.51.100.7", 443), None)
                .verdict,
            FlowVerdict::Deny
        );
        // The deny prefix is earlier in the list than the name.
        let d = c.evaluate(&egress(Protocol::Tcp, "203.0.113.7", 443), set);
        assert_eq!((d.verdict, d.reason), (FlowVerdict::Deny, Reason::Rule));
    }

    #[test]
    fn redirect_goes_to_the_endpoint_of_the_flows_family() {
        let mut b = base();
        let v4 = SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 1), 5353);
        b.endpoints.push((
            RESOLVER,
            Endpoint {
                v4: Some(v4),
                v6: None,
            },
        ));
        b.before.push(
            Rule::new(
                Direction::Egress,
                Target::Net(Prefix::V4_ALL),
                Action::Redirect(RESOLVER),
                Origin::Resolver,
            )
            .protocols(Protocols::TCP_UDP)
            .ports(PortRange::one(53)),
        );
        b.before.push(
            Rule::new(
                Direction::Egress,
                Target::Names("steered.example".parse().unwrap()),
                Action::Redirect(RESOLVER),
                Origin::Steering,
            )
            .protocols(Protocols::TCP),
        );
        let c = compile(&b, &BoxPolicy::default(), Options::default()).unwrap();
        let d = c.evaluate(&egress(Protocol::Udp, "8.8.8.8", 53), None);
        assert_eq!(d.verdict, FlowVerdict::Redirect(SocketAddr::V4(v4)));
        // A pinned IPv6 address of a steered name, and no IPv6 endpoint.
        let set = c.set_for_name("steered.example");
        let d = c.evaluate(&egress(Protocol::Tcp, "2001:db8::1", 443), set);
        assert_eq!(
            (d.verdict, d.reason),
            (FlowVerdict::Deny, Reason::NoEndpoint)
        );
    }

    #[test]
    fn source_check_only_judges_egress_with_a_known_local_address() {
        let mut b = base();
        b.source_check = true;
        b.addrs.v4 = Some(Ipv4Addr::new(10, 99, 0, 2));
        b.defaults.egress = Verdict::Allow;
        let c = compile(&b, &BoxPolicy::default(), Options::default()).unwrap();
        let mut flow = egress(Protocol::Udp, "10.99.0.1", 53);
        assert_eq!(c.evaluate(&flow, None).verdict, FlowVerdict::Allow);
        flow.local = Some("10.99.0.2".parse().unwrap());
        assert_eq!(c.evaluate(&flow, None).verdict, FlowVerdict::Allow);
        flow.local = Some("10.99.0.3".parse().unwrap());
        assert_eq!(c.evaluate(&flow, None).reason, Reason::SourceAddress);
        flow.local = Some("127.0.0.1".parse().unwrap());
        assert_eq!(c.evaluate(&flow, None).verdict, FlowVerdict::Allow);
        flow.local = Some("fe80::1".parse().unwrap());
        assert_eq!(c.evaluate(&flow, None).verdict, FlowVerdict::Allow);
    }
}
