//! Default deny, rules by prefix, port and protocol for both families,
//! v4-mapped destinations, events and counters.

use std::net::IpAddr;

use netpol::{
    PortRange, Protocols, Target,
    abi::{Hook, Reason},
    event::Outcome,
    policy::{BoxAction, BoxPolicy, BoxRule},
};

use crate::support::{Harness, REFUSED, host_ip, servers};

fn refused() -> String {
    format!("err {REFUSED}")
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn an_unconfigured_box_has_no_network() {
    let Some(mut h) = Harness::start("cases::rules::an_unconfigured_box_has_no_network") else {
        return;
    };
    // The daemon's side of the engine works without privilege.
    assert!(!nix::unistd::geteuid().is_root());
    let mut events = h.handles.take_events().expect("event source");

    let bare = h.new_box("bare");
    let stream = libc::SOCK_STREAM.to_string();
    let dgram = libc::SOCK_DGRAM.to_string();
    assert_eq!(
        h.probe("bare", &["sock", &libc::AF_INET.to_string(), &stream, "0"]),
        "err 1"
    );
    assert_eq!(
        h.probe("bare", &["sock", &libc::AF_INET6.to_string(), &dgram, "0"]),
        "err 1"
    );
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().any(|e| e.box_id == bare.0
            && e.hook == Hook::SockCreate
            && e.reason == Reason::NoConfig
            && e.outcome == Outcome::Denied),
        "{seen:?}"
    );

    // A socket that exists when the box loses its policy shows the other
    // layers on their own.
    let echo = servers::udp_echo(IpAddr::V4(h.v4(1, 1)));
    let live = h.install("gone", host_ip(), BoxPolicy::default());
    let target = h.v4(1, 1).to_string();
    let mut held = h.hold_probe("gone", &["hold-udp", &target, &echo.to_string()]);
    assert_eq!(held.step(), "ok");
    h.handles.uninstall(&live).expect("remove the box");
    assert_eq!(
        held.step(),
        "err 1",
        "the packet hook refuses a box without a config entry"
    );
    assert_eq!(
        h.probe("gone", &["udp", &target, &echo.to_string()]),
        "err 1"
    );
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter()
            .any(|e| e.hook == Hook::Egress && e.reason == Reason::NoConfig),
        "{seen:?}"
    );
    assert_eq!(h.handles.stats(live.id()).expect("stats"), None);
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn rules_by_prefix_port_and_protocol_for_both_families() {
    // Group 1 is allowed, one host in it denied. Group 3 is open on one
    // TCP port only. Group 5 is outside every rule.
    let v6 = [0x0101, 0x0109, 0x0301, 0x0501];
    let Some(mut h) = Harness::start_with(
        "cases::rules::rules_by_prefix_port_and_protocol_for_both_families",
        &v6,
    ) else {
        return;
    };
    let mut events = h.handles.take_events().expect("event source");
    let port = servers::banner();
    let echo = servers::udp_echo("::".parse().expect("address"));
    let (port_s, echo_s) = (port.to_string(), echo.to_string());

    let rule = |to: String| BoxRule {
        action: BoxAction::Allow,
        protocols: Protocols::TCP,
        ports: PortRange::one(port),
        to: Target::Net(to.parse().expect("prefix")),
    };
    let policy = BoxPolicy {
        rules: vec![rule(h.v4_group(3)), rule(h.v6_group(3))],
        deny: vec![
            h.v4(1, 9).to_string().parse().expect("prefix"),
            h.v6(0x0109).to_string().parse().expect("prefix"),
        ],
        allow: vec![
            h.v4_group(1).parse().expect("prefix"),
            h.v6_group(1).parse().expect("prefix"),
        ],
        ..BoxPolicy::default()
    };
    let live = h.install("r", host_ip(), policy);

    for (allowed, denied, port_only, outside) in [
        (
            IpAddr::V4(h.v4(1, 1)),
            IpAddr::V4(h.v4(1, 9)),
            IpAddr::V4(h.v4(3, 1)),
            IpAddr::V4(h.v4(5, 1)),
        ),
        (
            IpAddr::V6(h.v6(0x0101)),
            IpAddr::V6(h.v6(0x0109)),
            IpAddr::V6(h.v6(0x0301)),
            IpAddr::V6(h.v6(0x0501)),
        ),
    ] {
        let tcp = |ip: IpAddr, port: &str| h.probe("r", &["tcp", &ip.to_string(), port, "500"]);
        let udp = |ip: IpAddr, port: &str| h.probe("r", &["udp", &ip.to_string(), port, "500"]);
        assert!(
            tcp(allowed, &port_s).ends_with("data=hello"),
            "allowed prefix: {}",
            tcp(allowed, &port_s)
        );
        assert!(
            udp(allowed, &echo_s).starts_with("ok from="),
            "allowed prefix, UDP: {}",
            udp(allowed, &echo_s)
        );
        assert_eq!(
            tcp(denied, &port_s),
            refused(),
            "a denied host inside the allowed prefix"
        );
        assert_eq!(
            tcp(outside, &port_s),
            refused(),
            "outside every rule: the implied default is deny"
        );
        assert!(
            tcp(port_only, &port_s).ends_with("data=hello"),
            "the port rule's port"
        );
        assert_eq!(tcp(port_only, &echo_s), refused(), "another port");
        assert_eq!(
            udp(port_only, &port_s),
            refused(),
            "the port rule is TCP only"
        );
    }

    // An AF_INET6 socket with a v4-mapped destination speaks IPv4 and
    // gets the IPv4 rules.
    let mapped = |v4: std::net::Ipv4Addr| v4.to_ipv6_mapped().to_string();
    let out = h.probe("r", &["tcp", &mapped(h.v4(1, 1)), &port_s, "500"]);
    assert!(
        out.starts_with("ok peer=[::ffff:") && out.ends_with("data=hello"),
        "{out}"
    );
    assert_eq!(
        h.probe("r", &["tcp", &mapped(h.v4(1, 9)), &port_s, "500"]),
        refused()
    );
    assert_eq!(
        h.probe("r", &["udp", &mapped(h.v4(5, 1)), &echo_s]),
        refused()
    );

    let seen = Harness::drain(&mut events);
    let denied4 = IpAddr::V4(h.v4(1, 9));
    let by_rule = seen
        .iter()
        .find(|e| e.hook == Hook::Connect4 && e.dst == denied4 && e.reason == Reason::Rule)
        .unwrap_or_else(|| panic!("no event for the denied host: {seen:?}"));
    assert_eq!(
        (by_rule.box_id, by_rule.dst_port, by_rule.protocol),
        (live.id().0, port, 6)
    );
    assert_ne!(by_rule.pid, 0);
    // The rule number is the position in the compiled list.
    let rule = &live.compiled().rules[usize::from(by_rule.rule.expect("rule number"))];
    assert_eq!(rule.target, Target::Net(netpol::Prefix::host(denied4)));
    assert!(
        seen.iter()
            .any(|e| e.hook == Hook::Connect6 && e.reason == Reason::Default && e.rule.is_none()),
        "{seen:?}"
    );
    // The mapped destination arrived at the IPv6 hook as an IPv4 flow.
    assert!(
        seen.iter()
            .any(|e| e.hook == Hook::Connect6 && e.dst == denied4),
        "{seen:?}"
    );

    let stats = h
        .handles
        .stats(live.id())
        .expect("stats")
        .expect("the box has counters");
    assert!(stats.refused >= 9, "{stats:?}");
    assert!(
        stats.tx_pkts > 0 && stats.tx_bytes > 0 && stats.rx_pkts > 0,
        "{stats:?}"
    );
    assert_eq!(stats.ev_lost, 0);
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn the_unspecified_destination_is_judged_as_the_address_the_kernel_dials() {
    let Some(mut h) = Harness::start(
        "cases::rules::the_unspecified_destination_is_judged_as_the_address_the_kernel_dials",
    ) else {
        return;
    };
    let mut events = h.handles.take_events().expect("event source");
    let port = servers::banner().to_string();

    // Everything but loopback.
    let no_loopback = BoxPolicy {
        deny: vec![
            "127.0.0.0/8".parse().expect("prefix"),
            "::1/128".parse().expect("prefix"),
        ],
        ..BoxPolicy::default()
    };
    let live = h.install("d", host_ip(), no_loopback);
    // The kernel dials loopback for these. The system call says no at
    // once. Judged as written they would pass it and time out on the wire.
    for to in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
        assert_eq!(h.probe("d", &["tcp", to, &port, "700"]), refused(), "{to}");
        assert_eq!(h.probe("d", &["udp", to, &port]), refused(), "{to}");
    }
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().any(|e| e.box_id == live.id().0
            && e.hook == Hook::Connect4
            && e.reason == Reason::Rule
            && e.dst == IpAddr::from([127, 0, 0, 1])),
        "{seen:?}"
    );
    assert!(seen.iter().all(|e| e.hook != Hook::Egress), "{seen:?}");

    // A socket bound to an address dials that address, and is judged so.
    let only_group_1 = BoxPolicy {
        allow: vec![h.v4_group(1).parse().expect("prefix")],
        ..BoxPolicy::default()
    };
    h.install("b", host_ip(), only_group_1);
    let own = h.v4(1, 1).to_string();
    assert_eq!(
        h.probe("b", &["tcp-from", &own, "0.0.0.0", &port]),
        "ok connected"
    );
    assert_eq!(h.probe("b", &["tcp", "0.0.0.0", &port, "700"]), refused());
}
