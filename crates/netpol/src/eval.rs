//! Judging a flow in Rust, the way the kernel programs judge it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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

/// ICMPv6 types a host sends before it has an address to send from:
/// multicast listener reports and done, router solicitation, and the
/// neighbour solicitation of duplicate address detection.
const fn sent_unaddressed(icmp_type: u16) -> bool {
    matches!(icmp_type, 131..=133 | 135 | 143)
}

/// Where the kernel sends a flow to the unspecified address: this host. An
/// IPv4 socket bound to an address dials that address, anything else
/// dials loopback.
fn dialled(remote: IpAddr, local: Option<IpAddr>) -> IpAddr {
    match (remote, local.map(canonical)) {
        (IpAddr::V4(a), Some(IpAddr::V4(bound)))
            if a.is_unspecified() && !bound.is_unspecified() =>
        {
            IpAddr::V4(bound)
        }
        (IpAddr::V4(a), _) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (IpAddr::V6(a), _) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => remote,
    }
}

fn first_match(slots: &[Slot], flow: &Flow, below: Option<u16>) -> Option<Slot> {
    slots
        .iter()
        .take_while(|s| below.is_none_or(|limit| s.prio < limit))
        .find(|s| s.protocols.contains(flow.protocol) && s.ports.contains(flow.port))
        .copied()
}

impl Compiled {
    /// Whether a packet of `flow` from `local` passes the source check:
    /// from one of the box's own addresses or loopback. The unspecified
    /// IPv6 address passes for what a host sends before it has an address.
    fn source_ok(local: IpAddr, own: bool, flow: &Flow) -> bool {
        match local {
            IpAddr::V4(a) => own || a.is_loopback(),
            IpAddr::V6(a) if a.is_unspecified() => {
                flow.protocol == Protocol::Icmp && sent_unaddressed(flow.port)
            }
            IpAddr::V6(a) => own || a.is_loopback(),
        }
    }

    /// Judges a new flow. `pinned` is the engine's table of pinned
    /// addresses for the box: the sets an address is in right now, those of
    /// the names it was answered for or [`SetId::OWN`], and none for an
    /// address with no pin or one that has run out. `Handles::pinned_sets`
    /// in `boxbpf` is that table. An address in several sets is judged by
    /// their merged set ([`Compiled::merged`]).
    ///
    /// The kernel judges new flows only: a TCP segment after the SYN, a UDP
    /// packet to a peer the other direction admitted, and an ICMP echo reply
    /// pass without a verdict.
    ///
    /// Two cases are judged as the kernel acts on them. An egress flow to
    /// `0.0.0.0` or `::` is judged as the address the kernel dials for it.
    /// A bind to port 0 asks for an ephemeral port and is not judged.
    #[must_use]
    pub fn evaluate(&self, flow: &Flow, pinned: impl Fn(IpAddr) -> Vec<SetId>) -> Decision {
        let Some(remote) = self.judged_remote(flow, &pinned) else {
            return Decision {
                verdict: FlowVerdict::Deny,
                rule: None,
                reason: Reason::SourceAddress,
            };
        };
        if flow.direction == Direction::Bind && flow.port == 0 {
            return Decision {
                verdict: FlowVerdict::Allow,
                rule: None,
                reason: Reason::EphemeralPort,
            };
        }

        let by_prefix = self
            .nets
            .iter()
            .filter(|e| e.direction == flow.direction && e.prefix.contains(remote))
            .max_by_key(|e| e.prefix.len())
            .and_then(|e| first_match(&e.rules, flow, None))
            .map(|slot| (slot, Reason::Rule));
        let below = by_prefix.map(|(slot, _)| slot.prio);
        let sets = pinned(remote);
        let by_set = match sets.as_slice() {
            [] => None,
            [one] => self
                .set_rules(*one, flow.direction)
                .and_then(|rules| first_match(rules, flow, below)),
            many => self
                .merged(many)
                .entries
                .iter()
                .find(|entry| entry.direction == flow.direction)
                .and_then(|entry| first_match(&entry.rules, flow, below)),
        }
        .map(|slot| (slot, Reason::SetRule));

        match by_set.or(by_prefix) {
            Some((slot, reason)) => self.decided(remote, slot.prio, slot.action, reason),
            None => self.by_default(flow.direction),
        }
    }

    /// The address a flow is judged by, or `None` for an egress flow from
    /// an address that is not the box's.
    fn judged_remote(&self, flow: &Flow, pinned: &impl Fn(IpAddr) -> Vec<SetId>) -> Option<IpAddr> {
        let mut remote = canonical(flow.remote);
        if flow.direction == Direction::Egress {
            remote = dialled(remote, flow.local);
        }
        if flow.direction == Direction::Egress
            && self.config.source_check
            && let Some(local) = flow.local.map(canonical)
            && !Self::source_ok(local, pinned(local).contains(&SetId::OWN), flow)
        {
            return None;
        }
        Some(remote)
    }

    fn by_default(&self, direction: Direction) -> Decision {
        let verdict = match self.config.defaults.of(direction) {
            Verdict::Allow => FlowVerdict::Allow,
            Verdict::Deny => FlowVerdict::Deny,
        };
        Decision {
            verdict,
            rule: None,
            reason: Reason::Default,
        }
    }

    /// The decision of the rule at `prio` for a flow to `remote`.
    fn decided(&self, remote: IpAddr, prio: u16, action: Action, reason: Reason) -> Decision {
        let rule = Some(prio);
        match action {
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

    /// Judges a flow by the policy's list with some of its rules left out:
    /// what the rest of the list says about a flow that one of the rules
    /// in `skip` took. A service behind a redirect asks this to learn
    /// whether the box's other rules let the flow exist at all.
    ///
    /// This reads the ordered list and not the compiled entries, which
    /// leave out a rule that an earlier one always beats.
    #[must_use]
    pub fn evaluate_skipping(
        &self,
        flow: &Flow,
        pinned: impl Fn(IpAddr) -> Vec<SetId>,
        skip: impl Fn(&Rule) -> bool,
    ) -> Decision {
        let Some(remote) = self.judged_remote(flow, &pinned) else {
            return Decision {
                verdict: FlowVerdict::Deny,
                rule: None,
                reason: Reason::SourceAddress,
            };
        };
        if flow.direction == Direction::Bind && flow.port == 0 {
            return Decision {
                verdict: FlowVerdict::Allow,
                rule: None,
                reason: Reason::EphemeralPort,
            };
        }
        let sets = pinned(remote);
        // A rule by name judges an address in a set whose pattern the
        // rule's pattern covers, as the compiler lays the sets out.
        let patterns: Vec<&NamePattern> =
            sets.iter().filter_map(|id| pattern_of(self, *id)).collect();
        let around: Vec<&Prefix> = self
            .protected
            .iter()
            .filter(|range| flow.direction == Direction::Egress && range.contains(remote))
            .collect();
        let hit = self.rules.iter().zip(0u16..).find(|(r, _)| {
            r.direction == flow.direction
                && !skip(r)
                && r.matches_l4(flow.protocol, flow.port)
                && around.iter().all(|range| r.reaches_into(range))
                && match &r.target {
                    Target::Any => true,
                    Target::Net(p) => p.contains(remote),
                    Target::Names(pattern) => patterns.iter().any(|set| pattern.covers(set)),
                    Target::OwnAddresses => sets.contains(&SetId::OWN),
                }
        });
        match hit {
            Some((r, prio)) => {
                let reason = match r.target {
                    Target::Names(_) | Target::OwnAddresses => Reason::SetRule,
                    Target::Any | Target::Net(_) => Reason::Rule,
                };
                self.decided(remote, prio, r.action, reason)
            }
            None => self.by_default(flow.direction),
        }
    }
}

/// What the engine's table of pinned addresses says about the remote
/// address of a flow, for [`evaluate_ordered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pinned<'a> {
    No,
    /// Pinned for these names: one, or several that resolve to the address.
    Names(&'a [&'a str]),
    /// One of the box's own addresses.
    Own,
}

/// Judges a flow against the ordered rule list itself, with no compiled
/// form in between. `protected` are the base policy's protected ranges and
/// `pinned` says what the remote address is pinned as.
///
/// Returns the position and action of the first matching rule, or `None`
/// and the default. This is the reference [`Compiled::evaluate`] is tested
/// against. It reads a flow the same way: the unspecified destination is
/// the address the kernel dials, and a bind to port 0 is not judged.
#[must_use]
pub fn evaluate_ordered(
    rules: &[Rule],
    protected: &[Prefix],
    defaults: &Defaults,
    flow: &Flow,
    pinned: Pinned<'_>,
) -> (Option<usize>, Action) {
    if flow.direction == Direction::Bind && flow.port == 0 {
        return (None, Action::Allow);
    }
    let mut remote = canonical(flow.remote);
    if flow.direction == Direction::Egress {
        remote = dialled(remote, flow.local);
    }
    let around: Vec<&Prefix> = protected
        .iter()
        .filter(|range| flow.direction == Direction::Egress && range.contains(remote))
        .collect();
    let hit = rules.iter().enumerate().find(|(_, r)| {
        r.direction == flow.direction
            && r.matches_l4(flow.protocol, flow.port)
            && around.iter().all(|range| r.reaches_into(range))
            && match (&r.target, pinned) {
                (Target::Any, _) => true,
                (Target::Net(p), _) => p.contains(remote),
                (Target::Names(pattern), Pinned::Names(names)) => {
                    names.iter().any(|name| pattern.matches(name))
                }
                (Target::OwnAddresses, Pinned::Own) => true,
                (Target::Names(_) | Target::OwnAddresses, _) => false,
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
        base::{BasePolicy, RESOLVER},
        compile::{Options, compile},
        model::{Endpoint, EndpointIndex, Origin, PortRange, Protocols},
        policy::{BoxAction, BoxPolicy, BoxRule},
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
        let d = c.evaluate(&egress(Protocol::Tcp, "10.1.1.1", 80), |_| Vec::new());
        assert_eq!(
            (d.verdict, d.rule, d.reason),
            (FlowVerdict::Allow, Some(1), Reason::Rule)
        );
        let d = c.evaluate(&egress(Protocol::Tcp, "10.1.2.1", 80), |_| Vec::new());
        assert_eq!((d.verdict, d.rule), (FlowVerdict::Deny, Some(0)));
        let d = c.evaluate(&egress(Protocol::Tcp, "10.2.0.1", 80), |_| Vec::new());
        assert_eq!(
            (d.verdict, d.rule, d.reason),
            (FlowVerdict::Deny, None, Reason::Default)
        );
        assert_eq!(
            c.evaluate(&egress(Protocol::Udp, "fd00:1::9", 53), |_| Vec::new())
                .verdict,
            FlowVerdict::Allow
        );
        // A v4-mapped address is judged as IPv4.
        assert_eq!(
            c.evaluate(&egress(Protocol::Tcp, "::ffff:10.1.1.1", 80), |_| Vec::new(
            ))
            .verdict,
            FlowVerdict::Allow
        );
        assert_eq!(
            c.evaluate(&egress(Protocol::Tcp, "::ffff:10.1.2.1", 80), |_| Vec::new(
            ))
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
        let set = || c.set_for_name("example.com").into_iter().collect();
        let d = c.evaluate(&egress(Protocol::Tcp, "198.51.100.7", 443), |_| set());
        assert_eq!((d.verdict, d.reason), (FlowVerdict::Allow, Reason::SetRule));
        assert_eq!(
            c.evaluate(&egress(Protocol::Tcp, "198.51.100.7", 443), |_| Vec::new())
                .verdict,
            FlowVerdict::Deny
        );
        // The deny prefix is earlier in the list than the name.
        let d = c.evaluate(&egress(Protocol::Tcp, "203.0.113.7", 443), |_| set());
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
        let d = c.evaluate(&egress(Protocol::Udp, "8.8.8.8", 53), |_| Vec::new());
        assert_eq!(d.verdict, FlowVerdict::Redirect(SocketAddr::V4(v4)));
        // A pinned IPv6 address of a steered name, and no IPv6 endpoint.
        let set = c.set_for_name("steered.example");
        let d = c.evaluate(&egress(Protocol::Tcp, "2001:db8::1", 443), |_| {
            set.into_iter().collect()
        });
        assert_eq!(
            (d.verdict, d.reason),
            (FlowVerdict::Deny, Reason::NoEndpoint)
        );
    }

    fn name_rule(action: BoxAction, port: u16, name: &str) -> BoxRule {
        BoxRule {
            action,
            protocols: Protocols::TCP,
            ports: PortRange::one(port),
            to: Target::Names(name.parse().unwrap()),
        }
    }

    #[test]
    fn an_address_of_two_names_is_judged_by_the_rules_of_both_in_list_order() {
        let policy = BoxPolicy {
            rules: vec![name_rule(BoxAction::Deny, 22, "a.test")],
            names: vec!["a.test".parse().unwrap(), "b.test".parse().unwrap()],
            ..BoxPolicy::default()
        };
        let c = compile(&base(), &policy, Options::default()).unwrap();
        let a = c.set_for_name("a.test").unwrap();
        let b = c.set_for_name("b.test").unwrap();
        let mut both = vec![a, b];
        both.sort_unstable();
        let to = |port: u16, sets: &[SetId]| {
            let d = c.evaluate(&egress(Protocol::Tcp, "198.51.100.7", port), |_| {
                sets.to_vec()
            });
            (d.verdict, d.rule)
        };
        // The deny for one name comes before the allow for the other.
        assert_eq!(to(22, &both), (FlowVerdict::Deny, Some(0)));
        assert_eq!(to(22, &[b]), (FlowVerdict::Allow, Some(2)));
        assert_eq!(to(443, &both), (FlowVerdict::Allow, Some(1)));
        // The list read rule by rule gives the same for both names.
        for port in [22, 443] {
            let flow = egress(Protocol::Tcp, "198.51.100.7", port);
            let (index, _) = evaluate_ordered(
                &c.rules,
                &c.protected,
                &c.config.defaults,
                &flow,
                Pinned::Names(&["a.test", "b.test"]),
            );
            assert_eq!(to(port, &both).1.map(usize::from), index, "port {port}");
        }
        let merged = c.merged(&both);
        assert_eq!(merged.id, crate::pins::merged_id(&both));
        assert_eq!(merged.overflow, None);
        assert!(c.sets.iter().all(|set| set.id != merged.id));
    }

    #[test]
    fn a_merged_list_that_does_not_fit_keeps_its_first_rules_and_refuses_the_rest() {
        // Twenty rules for each of two names, and one for every address.
        let mut rules = vec![BoxRule {
            action: BoxAction::Allow,
            protocols: Protocols::TCP,
            ports: PortRange::one(9000),
            to: Target::Any,
        }];
        for i in 0..20 {
            rules.push(name_rule(BoxAction::Allow, 100 + i, "a.test"));
            rules.push(name_rule(BoxAction::Allow, 200 + i, "b.test"));
        }
        let policy = BoxPolicy {
            rules,
            default: Some(Verdict::Allow),
            ..BoxPolicy::default()
        };
        let c = compile(&base(), &policy, Options::default()).unwrap();
        let mut both = vec![
            c.set_for_name("a.test").unwrap(),
            c.set_for_name("b.test").unwrap(),
        ];
        both.sort_unstable();
        let merged = c.merged(&both);
        assert_eq!(
            merged.overflow,
            Some(crate::compile::Overflow {
                direction: Direction::Egress,
                rules: 40
            })
        );
        let [entry] = merged.entries.as_slice() else {
            panic!("one direction has rules: {merged:?}");
        };
        assert_eq!(entry.rules.len(), crate::abi::RULES_MAX);
        assert!(entry.rules.windows(2).all(|w| w[0].prio < w[1].prio));
        // The first rule left out is rule 32 of the list: the one for
        // every address, then 31 of the names' rules.
        let last = entry.rules.last().unwrap();
        assert_eq!((last.prio, last.action), (32, Action::Deny));

        let names = Pinned::Names(&["a.test", "b.test"]);
        let mut refused_where_the_list_allows = 0;
        for port in (90..230).chain([9000, 9001]) {
            let flow = egress(Protocol::Tcp, "198.51.100.7", port);
            let got = c.evaluate(&flow, |_| both.clone());
            let (index, action) =
                evaluate_ordered(&c.rules, &c.protected, &c.config.defaults, &flow, names);
            match index {
                // A rule before the cut decides as the list says.
                Some(index) if index < 32 => {
                    assert_eq!(got.rule.map(usize::from), Some(index), "port {port}");
                    assert_eq!(got.verdict, FlowVerdict::Allow, "port {port}");
                }
                // Everything else is refused at the cut, also what a rule
                // left out or the default would allow.
                _ => {
                    assert_eq!(action, Action::Allow, "port {port}");
                    assert_eq!(
                        (got.verdict, got.rule, got.reason),
                        (FlowVerdict::Deny, Some(32), Reason::SetRule),
                        "port {port}"
                    );
                    refused_where_the_list_allows += 1;
                }
            }
        }
        assert!(refused_where_the_list_allows > 100);
        // One name alone is judged by its own list, which fits.
        let alone = c.evaluate(&egress(Protocol::Tcp, "198.51.100.7", 119), |_| {
            vec![c.set_for_name("a.test").unwrap()]
        });
        assert_eq!(alone.verdict, FlowVerdict::Allow);
    }

    #[test]
    fn a_rule_an_earlier_one_always_beats_still_judges_when_that_one_is_left_out() {
        let steered: NamePattern = "steered.test".parse().unwrap();
        let v4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 80, 1), 20481);
        let mut b = base();
        b.endpoints.push((
            EndpointIndex(1),
            Endpoint {
                v4: Some(v4),
                v6: None,
            },
        ));
        b.before.push(
            Rule::new(
                Direction::Egress,
                Target::Names(steered.clone()),
                Action::Redirect(EndpointIndex(1)),
                Origin::Steering,
            )
            .protocols(Protocols::TCP)
            .ports(PortRange::one(8443)),
        );
        let listed = BoxPolicy {
            names: vec![steered],
            ..BoxPolicy::default()
        };
        let refusing = BoxPolicy {
            rules: vec![name_rule(BoxAction::Deny, 8443, "steered.test")],
            ..listed.clone()
        };
        let flow = egress(Protocol::Tcp, "198.51.100.7", 8443);
        let steering = |r: &Rule| r.origin == Origin::Steering;
        for (policy, rest, rule) in [
            (&listed, FlowVerdict::Allow, Some(1)),
            (&refusing, FlowVerdict::Deny, Some(1)),
        ] {
            let c = compile(&b, policy, Options::default()).unwrap();
            let set = || vec![c.set_for_name("steered.test").unwrap()];
            assert_eq!(
                c.evaluate(&flow, |_| set()).verdict,
                FlowVerdict::Redirect(SocketAddr::V4(v4))
            );
            let d = c.evaluate_skipping(&flow, |_| set(), steering);
            assert_eq!((d.verdict, d.rule, d.reason), (rest, rule, Reason::SetRule));
            // An address the name was never answered for has no rule.
            let unpinned = c.evaluate_skipping(&flow, |_| Vec::new(), steering);
            assert_eq!(unpinned.verdict, FlowVerdict::Deny);
        }
    }

    /// A table of pinned addresses that holds these as the box's own.
    fn own(list: &'static [&'static str]) -> impl Fn(IpAddr) -> Vec<SetId> {
        move |addr| {
            list.iter()
                .any(|a| a.parse::<IpAddr>().unwrap() == addr)
                .then_some(SetId::OWN)
                .into_iter()
                .collect()
        }
    }

    #[test]
    fn source_check_only_judges_egress_with_a_known_local_address() {
        let mut b = base();
        b.source_check = true;
        b.defaults.egress = Verdict::Allow;
        let c = compile(&b, &BoxPolicy::default(), Options::default()).unwrap();
        let addrs = own(&["10.99.0.2", "10.99.0.7"]);
        let mut flow = egress(Protocol::Udp, "10.99.0.1", 53);
        assert_eq!(c.evaluate(&flow, &addrs).verdict, FlowVerdict::Allow);
        // A box has an address per network namespace, and each is a source.
        for local in ["10.99.0.2", "10.99.0.7", "::ffff:10.99.0.2", "127.0.0.1"] {
            flow.local = Some(local.parse().unwrap());
            assert_eq!(
                c.evaluate(&flow, &addrs).verdict,
                FlowVerdict::Allow,
                "{local}"
            );
        }
        flow.local = Some("10.99.0.3".parse().unwrap());
        assert_eq!(c.evaluate(&flow, &addrs).reason, Reason::SourceAddress);
        // An address pinned for a name is not the box's own.
        let name = SetId(77);
        assert_eq!(
            c.evaluate(&flow, |_| vec![name]).reason,
            Reason::SourceAddress
        );
    }

    #[test]
    fn a_link_local_source_must_be_the_box_s_own() {
        let mut b = base();
        b.source_check = true;
        b.defaults.egress = Verdict::Allow;
        let c = compile(&b, &BoxPolicy::default(), Options::default()).unwrap();
        let from = |local: &str, protocol, port| {
            let mut flow = egress(protocol, "fd00:99::9", port);
            flow.local = Some(local.parse().unwrap());
            c.evaluate(&flow, own(&["fd00:99::2", "fe80::99:2"])).reason
        };
        assert_eq!(from("fe80::99:2", Protocol::Udp, 53), Reason::Default);
        assert_eq!(from("fd00:99::2", Protocol::Udp, 53), Reason::Default);
        assert_eq!(from("::1", Protocol::Udp, 53), Reason::Default);
        // Another host's link-local address, which a box can bind.
        assert_eq!(from("fe80::99:3", Protocol::Udp, 53), Reason::SourceAddress);
        assert_eq!(
            from("fe80::99:3", Protocol::Icmp, 135),
            Reason::SourceAddress
        );
        // The unspecified address: duplicate address detection and the
        // multicast reports before it, nothing else.
        for icmp_type in [131, 132, 133, 135, 143] {
            assert_eq!(from("::", Protocol::Icmp, icmp_type), Reason::Default);
        }
        assert_eq!(from("::", Protocol::Icmp, 128), Reason::SourceAddress);
        assert_eq!(from("::", Protocol::Icmp, 136), Reason::SourceAddress);
        assert_eq!(from("::", Protocol::Udp, 53), Reason::SourceAddress);
    }

    #[test]
    fn a_box_without_an_ipv4_address_sends_nothing_from_the_unspecified_one() {
        let mut b = base();
        b.source_check = true;
        b.defaults.egress = Verdict::Allow;
        let c = compile(&b, &BoxPolicy::default(), Options::default()).unwrap();
        let mut flow = egress(Protocol::Udp, "10.99.0.1", 67);
        flow.local = Some("0.0.0.0".parse().unwrap());
        assert_eq!(
            c.evaluate(&flow, own(&["fd00:99::2"])).reason,
            Reason::SourceAddress
        );
    }

    #[test]
    fn a_box_talks_to_its_own_addresses_whichever_they_are() {
        let d =
            crate::base::Deployment::new(crate::base::NodeKind::Native, crate::base::Mode::OwnIp);
        let c = compile(
            &crate::base::base_policy(&d),
            &BoxPolicy::default(),
            Options::default(),
        )
        .unwrap();
        let addrs = own(&["10.99.0.2", "10.99.0.7", "fd00:99::2"]);
        for direction in [Direction::Egress, Direction::Ingress] {
            for to in ["10.99.0.2", "10.99.0.7", "fd00:99::2", "127.0.0.1", "::1"] {
                let flow = Flow {
                    direction,
                    ..egress(Protocol::Tcp, to, 8080)
                };
                let d = c.evaluate(&flow, &addrs);
                assert_eq!(d.verdict, FlowVerdict::Allow, "{direction} {to}");
                assert_eq!(
                    c.rules[usize::from(d.rule.unwrap())].origin,
                    Origin::OwnAddresses
                );
            }
            // Its neighbour on the virtual network is not itself.
            let flow = Flow {
                direction,
                ..egress(Protocol::Tcp, "10.99.0.3", 8080)
            };
            assert_eq!(c.evaluate(&flow, &addrs).verdict, FlowVerdict::Deny);
        }
        // The rules are in the policy once, for whatever the set holds.
        assert!(
            c.sets
                .iter()
                .any(|s| s.id == SetId::OWN && s.direction == Direction::Ingress)
        );
        assert!(
            c.nets
                .iter()
                .all(|e| !e.prefix.contains("10.99.0.2".parse().unwrap()) || e.prefix.len() < 32)
        );
    }

    #[test]
    fn the_unspecified_destination_is_judged_as_what_the_kernel_dials() {
        let policy = BoxPolicy {
            deny: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
            allow: vec!["10.1.0.0/16".parse().unwrap()],
            default: Some(Verdict::Allow),
            ..BoxPolicy::default()
        };
        let c = compile(&base(), &policy, Options::default()).unwrap();
        for to in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let d = c.evaluate(&egress(Protocol::Tcp, to, 80), |_| Vec::new());
            assert_eq!(
                (d.verdict, d.reason),
                (FlowVerdict::Deny, Reason::Rule),
                "{to}"
            );
        }
        // An IPv4 socket bound to an address dials that address.
        let mut bound = egress(Protocol::Tcp, "0.0.0.0", 80);
        bound.local = Some("10.1.2.3".parse().unwrap());
        let d = c.evaluate(&bound, |_| Vec::new());
        assert_eq!((d.verdict, d.rule), (FlowVerdict::Allow, Some(2)));
        // A bind to the unspecified address is a wildcard bind, not a flow
        // to loopback.
        let wildcard = Flow {
            direction: Direction::Bind,
            ..egress(Protocol::Tcp, "0.0.0.0", 8080)
        };
        assert_eq!(
            c.evaluate(&wildcard, |_| Vec::new()).reason,
            Reason::Default
        );
    }

    #[test]
    fn a_bind_to_port_zero_is_not_judged() {
        let mut b = base();
        b.defaults.bind = Verdict::Deny;
        b.before.push(Rule::new(
            Direction::Bind,
            Target::Any,
            Action::Deny,
            Origin::OtherEndpoints,
        ));
        let c = compile(&b, &BoxPolicy::default(), Options::default()).unwrap();
        let bind = |port| Flow {
            direction: Direction::Bind,
            ..egress(Protocol::Tcp, "127.0.0.1", port)
        };
        let d = c.evaluate(&bind(0), |_| Vec::new());
        assert_eq!(
            (d.verdict, d.rule, d.reason),
            (FlowVerdict::Allow, None, Reason::EphemeralPort)
        );
        assert_eq!(
            c.evaluate(&bind(8080), |_| Vec::new()).verdict,
            FlowVerdict::Deny
        );
    }
}
