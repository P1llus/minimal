//! The compiled form must judge every flow exactly as the ordered rule
//! list does. That is the whole contract of the compiler: copying covering
//! rules into longer prefixes, pruning, and name sets may change the shape
//! of the data and never a verdict.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use netpol::{
    Action, Compiled, Defaults, Direction, Endpoint, EndpointIndex, Flow, FlowVerdict, NamePattern,
    Origin, Pinned, PortRange, Prefix, Protocol, Protocols, Rule, SetId, Target, Verdict,
    abi::RULES_MAX,
    base::{BasePolicy, Deployment, Mode, NodeKind, PortOf, Services, VirtualNetwork, base_policy},
    compile::{CompileError, Options, compile},
    evaluate_ordered,
    policy::{BoxAction, BoxPolicy, BoxRule},
};
use proptest::prelude::*;

const PREFIXES: [&str; 11] = [
    "::ffff:10.1.2.0/121",
    "0.0.0.0/0",
    "10.0.0.0/8",
    "10.1.0.0/16",
    "10.1.2.0/24",
    "10.1.2.3/32",
    "192.0.2.0/24",
    "::/0",
    "fd00::/8",
    "fd00:1::/32",
    "fd00:1:2::/48",
];
const PATTERNS: [&str; 5] = [
    "example.com",
    "*.example.com",
    "*.a.example.com",
    "x.a.example.com",
    "other.org",
];
const ADDRS: [&str; 16] = [
    "0.0.0.0",
    "::",
    "169.254.169.254",
    "fe80::1",
    "10.1.2.3",
    "10.1.2.9",
    "10.1.9.9",
    "10.9.9.9",
    "192.0.2.1",
    "8.8.8.8",
    "::ffff:10.1.2.3",
    "fd00:1:2::1",
    "fd00:1:9::1",
    "fd00:9::1",
    "2001:db8::1",
    "::1",
];
const NAMES: [&str; 6] = [
    "example.com",
    "www.example.com",
    "x.a.example.com",
    "y.a.example.com",
    "other.org",
    "nomatch.net",
];
const PORTS: [u16; 6] = [0, 53, 443, 450, 1023, 8080];

const ENDPOINT4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 1), 5353);
const ENDPOINT6: SocketAddrV6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);

fn direction() -> impl Strategy<Value = Direction> {
    prop::sample::select(Direction::ALL.to_vec())
}

fn protocols() -> impl Strategy<Value = Protocols> {
    (1u8..=7).prop_map(Protocols::from_bits)
}

fn ports() -> impl Strategy<Value = PortRange> {
    prop::sample::select(vec![
        PortRange::ALL,
        PortRange::one(53),
        PortRange::one(443),
        PortRange::new(400, 500).expect("ordered"),
        PortRange::new(0, 1023).expect("ordered"),
    ])
}

fn target() -> impl Strategy<Value = Target> {
    prop_oneof![
        1 => Just(Target::Any),
        5 => prop::sample::select(PREFIXES.to_vec()).prop_map(|p| Target::Net(p.parse().expect("prefix"))),
        3 => prop::sample::select(PATTERNS.to_vec()).prop_map(|p| Target::Names(p.parse().expect("pattern"))),
        1 => Just(Target::OwnAddresses),
    ]
}

/// Ranges a base policy might protect, among and around [`PREFIXES`].
const PROTECTED: [&str; 5] = [
    "10.1.0.0/16",
    "10.1.2.0/24",
    "192.0.2.0/24",
    "fd00:1::/32",
    "::ffff:10.9.0.0/112",
];

fn protected() -> impl Strategy<Value = Vec<Prefix>> {
    prop::sample::subsequence(PROTECTED.to_vec(), 0..4)
        .prop_map(|list| list.iter().map(|p| p.parse().expect("prefix")).collect())
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        direction(),
        protocols(),
        ports(),
        target(),
        0u8..5,
        any::<bool>(),
    )
        .prop_map(|(direction, protocols, ports, target, a, from_box)| {
            let action = match a {
                0 | 1 => Action::Allow,
                2 | 3 => Action::Deny,
                // Only egress can be redirected.
                _ if direction == Direction::Egress => Action::Redirect(EndpointIndex(0)),
                _ => Action::Deny,
            };
            Rule {
                direction,
                protocols,
                ports,
                target,
                action,
                // Only a rule the box wrote stops at a protected range.
                origin: if from_box {
                    Origin::BoxRule(0)
                } else {
                    Origin::Published
                },
            }
        })
}

fn verdict() -> impl Strategy<Value = Verdict> {
    prop::sample::select(vec![Verdict::Allow, Verdict::Deny])
}

/// What the remote address of a flow is pinned as: nothing, a name, or one
/// of the box's own addresses.
fn pinned() -> impl Strategy<Value = Pinned<'static>> {
    prop_oneof![
        3 => Just(Pinned::No),
        4 => prop::sample::select(NAMES.to_vec()).prop_map(Pinned::Name),
        2 => Just(Pinned::Own),
    ]
}

fn flow() -> impl Strategy<Value = (Flow, Pinned<'static>)> {
    (
        direction(),
        prop::sample::select(Protocol::ALL.to_vec()),
        prop::sample::select(ADDRS.to_vec()),
        prop::sample::select(PORTS.to_vec()),
        pinned(),
    )
        .prop_map(|(direction, protocol, remote, port, name)| {
            (
                Flow {
                    direction,
                    protocol,
                    remote: remote.parse().expect("address"),
                    port,
                    local: None,
                },
                name,
            )
        })
}

/// Checks one flow against both evaluators.
fn agree(c: &Compiled, flow: &Flow, name: Pinned<'_>) -> Result<(), TestCaseError> {
    let set = match name {
        Pinned::No => None,
        Pinned::Name(n) => c.set_for_name(n),
        Pinned::Own => Some(SetId::OWN),
    };
    let got = c.evaluate(flow, |_| set);
    let (index, action) = evaluate_ordered(&c.rules, &c.protected, &c.config.defaults, flow, name);
    let want = match action {
        Action::Allow => FlowVerdict::Allow,
        Action::Deny => FlowVerdict::Deny,
        Action::Redirect(_) => FlowVerdict::Redirect(match netpol::eval::canonical(flow.remote) {
            IpAddr::V4(_) => SocketAddr::V4(ENDPOINT4),
            IpAddr::V6(_) => SocketAddr::V6(ENDPOINT6),
        }),
    };
    prop_assert_eq!(got.verdict, want, "flow {:?} name {:?}\n{}", flow, name, c);
    prop_assert_eq!(
        got.rule.map(usize::from),
        index,
        "flow {:?} name {:?}\n{}",
        flow,
        name,
        c
    );
    Ok(())
}

fn bare(
    rules: Vec<Rule>,
    protected: Vec<Prefix>,
    egress: Verdict,
    ingress: Verdict,
    bind: Verdict,
) -> BasePolicy {
    BasePolicy {
        before: rules,
        protected,
        defaults: Defaults {
            egress,
            ingress,
            bind,
        },
        endpoints: vec![(
            EndpointIndex(0),
            Endpoint {
                v4: Some(ENDPOINT4),
                v6: Some(ENDPOINT6),
            },
        )],
        source_check: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]

    #[test]
    fn compiled_agrees_with_the_ordered_list(
        rules in prop::collection::vec(rule(), 0..10),
        protected in protected(),
        (egress, ingress, bind) in (verdict(), verdict(), verdict()),
        flows in prop::collection::vec(flow(), 1..40),
    ) {
        let base = bare(rules, protected, egress, ingress, bind);
        match compile(&base, &BoxPolicy::default(), Options::default()) {
            Ok(c) => {
                for (flow, name) in &flows {
                    agree(&c, flow, *name)?;
                }
            }
            // A list that does not fit is refused, never truncated.
            Err(CompileError::TooManyRules { needed, max, .. }) => {
                prop_assert!(needed > max && max == RULES_MAX);
            }
            Err(other) => prop_assert!(false, "unexpected error {other}"),
        }
    }

    #[test]
    fn rule_lists_are_sorted_bounded_and_complete(
        rules in prop::collection::vec(rule(), 0..10),
        protected in protected(),
    ) {
        let base = bare(rules, protected, Verdict::Deny, Verdict::Deny, Verdict::Deny);
        let Ok(c) = compile(&base, &BoxPolicy::default(), Options::default()) else { return Ok(()) };
        for entry in &c.nets {
            prop_assert!(!entry.rules.is_empty() && entry.rules.len() <= RULES_MAX);
            prop_assert!(entry.rules.windows(2).all(|w| w[0].prio < w[1].prio));
            // Every slot is a rule of this direction whose target covers the entry.
            for slot in &entry.rules {
                let rule = &c.rules[usize::from(slot.prio)];
                prop_assert_eq!(rule.direction, entry.direction);
                let covers = match &rule.target {
                    Target::Any => true,
                    Target::Net(p) => p.covers(&entry.prefix),
                    Target::Names(_) | Target::OwnAddresses => false,
                };
                prop_assert!(covers, "{:?} does not cover {}", rule.target, entry.prefix);
            }
        }
        // Every prefix a rule names has an entry in its direction, and so
        // has every protected range.
        for rule in &c.rules {
            if let Target::Net(p) = &rule.target {
                prop_assert!(c.nets.iter().any(|e| e.direction == rule.direction && e.prefix == *p));
            }
        }
        for range in &c.protected {
            prop_assert!(c.nets.iter().any(|e| e.direction == Direction::Egress && e.prefix == *range));
        }
        // No allow the box wrote for a wider prefix is in an entry inside
        // a protected range.
        for entry in c.nets.iter().filter(|e| e.direction == Direction::Egress) {
            for range in c.protected.iter().filter(|r| r.covers(&entry.prefix)) {
                for slot in &entry.rules {
                    let rule = &c.rules[usize::from(slot.prio)];
                    prop_assert!(rule.reaches_into(range), "{} in {} inside {}", rule, entry.prefix, range);
                }
            }
        }
        for set in &c.sets {
            prop_assert!(set.rules.len() <= RULES_MAX);
            prop_assert!(set.rules.windows(2).all(|w| w[0].prio < w[1].prio));
        }
    }

    #[test]
    fn base_and_box_policy_compile_to_what_their_order_says(
        mode in prop::sample::select(vec![Mode::None, Mode::HostIp, Mode::OwnIp]),
        transport_ipv6 in any::<bool>(),
        with_services in any::<bool>(),
        allow in prop::sample::subsequence(PREFIXES.to_vec(), 0..4),
        deny in prop::sample::subsequence(PREFIXES.to_vec(), 0..3),
        names in prop::sample::subsequence(PATTERNS.to_vec(), 0..3),
        limit in prop::option::of(protocols()),
        explicit in prop::collection::vec((any::<bool>(), protocols(), ports(), target()), 0..3),
        default in prop::option::of(verdict()),
        flows in prop::collection::vec(flow(), 1..40),
    ) {
        let mut d = Deployment::new(NodeKind::Guest, mode);
        d.transport_ipv6 = transport_ipv6;
        if mode == Mode::OwnIp {
            d.network = Some(VirtualNetwork {
                subnet: "10.1.0.0/16".parse().unwrap(),
                gateway: "10.1.0.1".parse().unwrap(),
                host_alias: Some("10.1.0.254".parse().unwrap()),
            });
            d.host_exposures = vec![PortOf { protocols: Protocols::TCP, port: 443 }];
            d.published = vec![PortOf { protocols: Protocols::TCP, port: 8080 }];
        }
        if with_services {
            let e = Endpoint { v4: Some(ENDPOINT4), v6: Some(ENDPOINT6) };
            d.services = Services { resolver: Some(e), credential_proxy: None, hostname_proxy: None };
        }
        let policy = BoxPolicy {
            rules: explicit
                .into_iter()
                .map(|(allow, protocols, ports, to)| BoxRule {
                    action: if allow { BoxAction::Allow } else { BoxAction::Deny },
                    protocols,
                    ports,
                    to,
                })
                .collect(),
            protocols: limit,
            deny: deny.iter().map(|p| p.parse::<Prefix>().unwrap()).collect(),
            allow: allow.iter().map(|p| p.parse::<Prefix>().unwrap()).collect(),
            names: names.iter().map(|n| n.parse::<NamePattern>().unwrap()).collect(),
            default,
        };
        let base = base_policy(&d);
        let Ok(c) = compile(&base, &policy, Options::default()) else { return Ok(()) };

        // The list is base-before, box, then a deny per protected range.
        let box_rules = policy.rules();
        prop_assert_eq!(c.rules.len(), base.before.len() + box_rules.len() + base.protected.len());
        prop_assert!(c.rules.iter().rev().take(base.protected.len()).all(|r| r.origin == Origin::Protected));
        prop_assert!(c.rules.iter().take(base.before.len()).all(|r| r.origin.is_base()));
        prop_assert!(c.rules.iter().skip(base.before.len()).take(box_rules.len()).all(|r| !r.origin.is_base()));
        prop_assert_eq!(c.config.defaults.egress, policy.egress_default(base.defaults.egress));

        for (flow, name) in &flows {
            agree(&c, flow, *name)?;
        }
    }
}
