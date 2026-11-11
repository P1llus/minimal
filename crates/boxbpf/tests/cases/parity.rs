//! The kernel programs and the Rust evaluator must give the same verdict
//! for the same flow. One table of flows, judged by both.

use std::{net::IpAddr, time::Duration};

use boxbpf::BoxId;
use netpol::{
    Action, Compiled, Defaults, Direction, Flow, FlowVerdict, Origin, PortRange, Prefix, Protocol,
    Protocols, Rule, Target, Verdict,
    base::{BasePolicy, BoxAddrs},
    compile::{Options, compile},
    policy::{BoxAction, BoxPolicy, BoxRule},
};

use crate::support::{Harness, REFUSED};

fn kernel_denies(result: &str) -> bool {
    result == format!("err {REFUSED}")
}

fn evaluator_denies(h: &Harness, id: BoxId, compiled: &Compiled, flow: &Flow) -> bool {
    let pinned = h.handles.pinned_set(id, flow.remote);
    compiled.evaluate(flow, pinned).verdict == FlowVerdict::Deny
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn kernel_and_evaluator_agree_on_a_table_of_flows() {
    let Some(mut h) = Harness::start_with(
        "cases::parity::kernel_and_evaluator_agree_on_a_table_of_flows",
        &[0x0101],
    ) else {
        return;
    };
    let prefix = |s: String| s.parse::<Prefix>().expect("prefix");
    let net = |s: String| Target::Net(prefix(s));

    // Bind rules have no form in a box's own policy, so they come in as
    // base rules: TCP 18200-18210 on the test's addresses, nothing else
    // there, and everything on the rest of the host.
    let bind = |target: Target, action: Action| {
        Rule::new(Direction::Bind, target, action, Origin::Published)
    };
    let base = BasePolicy {
        before: vec![
            bind(net(h.v4_net()), Action::Allow)
                .protocols(Protocols::TCP)
                .ports(PortRange::new(18200, 18210).expect("range")),
            bind(net(h.v4_net()), Action::Deny),
            bind(net(h.v6_net()), Action::Deny).protocols(Protocols::UDP),
        ],
        after: Vec::new(),
        defaults: Defaults {
            egress: Verdict::Allow,
            ingress: Verdict::Allow,
            bind: Verdict::Allow,
        },
        endpoints: Vec::new(),
        source_check: false,
        addrs: BoxAddrs::default(),
    };
    let policy = BoxPolicy {
        rules: vec![
            BoxRule {
                action: BoxAction::Deny,
                protocols: Protocols::UDP,
                ports: PortRange::one(443),
                to: Target::Any,
            },
            BoxRule {
                action: BoxAction::Allow,
                protocols: Protocols::TCP,
                ports: PortRange::new(1000, 2000).expect("range"),
                to: net(h.v4_group(3)),
            },
        ],
        protocols: None,
        deny: vec![prefix(h.v4(1, 9).to_string()), prefix(h.v6_group(2))],
        allow: vec![
            prefix(h.v4_group(1)),
            prefix(h.v6_net()),
            prefix("::1/128".to_owned()),
        ],
        names: vec!["pinned.test".parse().expect("name")],
        default: None,
    };
    let options = Options {
        refuse_errno: u16::try_from(REFUSED).expect("errno"),
        log_flows: false,
    };
    let compiled = compile(&base, &policy, options).expect("compile");
    let id = h.new_box("p");
    let compiled = std::sync::Arc::new(compiled);
    h.handles
        .apply(id, std::sync::Arc::clone(&compiled))
        .expect("apply");
    // One address the default would refuse is pinned for an allowed name.
    h.handles
        .pin(
            id,
            IpAddr::V4(h.v4(5, 2)),
            "pinned.test",
            Duration::from_secs(60),
        )
        .expect("pin");

    let v4 = |g, n| IpAddr::V4(h.v4(g, n));
    let mapped = |g, n| IpAddr::V6(h.v4(g, n).to_ipv6_mapped());
    let remotes = [
        v4(1, 1),
        v4(1, 9),
        v4(3, 1),
        v4(5, 1),
        v4(5, 2),
        mapped(1, 1),
        mapped(1, 9),
        mapped(5, 2),
        IpAddr::V6(h.v6(0x0101)),
        IpAddr::V6(h.v6(0x0201)),
        "::1".parse().expect("address"),
        "fd77::1".parse().expect("address"),
    ];
    let mut flows = Vec::new();
    for remote in remotes {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for port in [9, 443, 1500, 2001] {
                flows.push(Flow {
                    direction: Direction::Egress,
                    protocol,
                    remote,
                    port,
                    local: None,
                });
            }
        }
    }
    for local in [
        v4(1, 1),
        "127.0.0.1".parse().expect("address"),
        IpAddr::V6(h.v6(0x0101)),
        "::1".parse().expect("address"),
    ] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for port in [18200, 18210, 18211] {
                flows.push(Flow {
                    direction: Direction::Bind,
                    protocol,
                    remote: local,
                    port,
                    local: None,
                });
            }
        }
    }

    // Bind rules by protocol, port and local address, stated outright.
    let own = h.v4(1, 1).to_string();
    assert_eq!(
        h.probe("p", &["bind", "tcp", &own, "18200"]),
        "ok port=18200"
    );
    assert!(
        kernel_denies(&h.probe("p", &["bind", "tcp", &own, "18211"])),
        "a port outside the bind rule"
    );
    assert!(
        kernel_denies(&h.probe("p", &["bind", "udp", &own, "18200"])),
        "the bind rule is TCP only"
    );
    assert!(
        h.probe("p", &["bind", "tcp", &own, "0"])
            .starts_with("ok port="),
        "an ephemeral port is not judged"
    );

    let mut disagreements = Vec::new();
    let (mut denied, mut allowed) = (0, 0);
    for flow in &flows {
        let (ip, port) = (flow.remote.to_string(), flow.port.to_string());
        let result = match (flow.direction, flow.protocol) {
            (Direction::Bind, Protocol::Tcp) => h.probe("p", &["bind", "tcp", &ip, &port]),
            (Direction::Bind, _) => h.probe("p", &["bind", "udp", &ip, &port]),
            (_, Protocol::Tcp) => h.probe("p", &["tcp", &ip, &port, "300"]),
            (_, _) => h.probe("p", &["udp", &ip, &port]),
        };
        let kernel = kernel_denies(&result);
        if kernel {
            denied += 1;
        } else {
            allowed += 1;
        }
        if kernel != evaluator_denies(&h, id, &compiled, flow) {
            disagreements.push(format!("{flow:?}: kernel said `{result}`"));
        }
    }
    assert!(
        disagreements.is_empty(),
        "kernel and evaluator disagree:\n{}",
        disagreements.join("\n")
    );
    // The table must exercise both verdicts, or agreement means nothing.
    assert!(
        denied >= 20 && allowed >= 20,
        "{denied} denied, {allowed} allowed of {}",
        flows.len()
    );
    println!(
        "parity: {} flows, {denied} denied, {allowed} allowed",
        flows.len()
    );
}
