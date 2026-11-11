//! A box with a network namespace of its own, built without privilege: a
//! user namespace, a veth pair to a peer namespace. Ingress rules, the
//! source address check, ICMP and ICMPv6 type rules, neighbour discovery.

use std::process::Command;

use netpol::{
    Direction, Flow, FlowVerdict, PortRange, Protocol, Protocols, Target,
    abi::{Hook, Reason},
    base::{Deployment, Mode, NodeKind, PortOf, VirtualNetwork},
    policy::{BoxAction, BoxPolicy, BoxRule},
};

use crate::support::{Cgroups, Harness, REFUSED, ip, wait_for};

const BOX4: &str = "10.99.0.2";
const BOX4_OTHER: &str = "10.99.0.3";
const GATEWAY4: &str = "10.99.0.1";
const PEER4: &str = "10.99.0.9";
const BOX6: &str = "fd00:99::2";
const BOX_LL6: &str = "fe80::99:2";
const ENDPOINT: &str = "127.0.80.1:20480";
/// A link-local address on the box's interface that is not the one the
/// engine was told.
const OTHER_LL6: &str = "fe80::99:3";
const PEER6: &str = "fd00:99::9";

fn refused() -> String {
    format!("err {REFUSED}")
}

/// Runs a command inside the user and network namespace of `pid`.
fn in_ns(pid: u32, args: &[&str]) {
    let status = Command::new("nsenter")
        .args([
            "-t",
            &pid.to_string(),
            "-U",
            "-n",
            "--preserve-credentials",
            "--",
        ])
        .args(args)
        .status()
        .expect("run nsenter");
    assert!(
        status.success(),
        "{args:?} failed in the namespace of {pid}"
    );
}

fn allow(protocols: Protocols, ports: PortRange, to: &str) -> BoxRule {
    BoxRule {
        action: BoxAction::Allow,
        protocols,
        ports,
        to: Target::Net(to.parse().expect("prefix")),
    }
}

fn policy(icmp4: u16, icmp6: u16) -> BoxPolicy {
    BoxPolicy {
        rules: vec![
            allow(Protocols::TCP, PortRange::one(18080), PEER4),
            allow(Protocols::TCP, PortRange::one(18080), PEER6),
            allow(Protocols::UDP, PortRange::one(18090), PEER4),
            allow(Protocols::ICMP, PortRange::one(icmp4), PEER4),
            allow(Protocols::ICMP, PortRange::one(icmp6), PEER6),
        ],
        ..BoxPolicy::default()
    }
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_box_in_its_own_network_namespace() {
    let Some(mut h) = Harness::start("cases::netns::a_box_in_its_own_network_namespace") else {
        return;
    };
    let mut events = h.handles.take_events().expect("event source");

    let mut deployment = Deployment::new(NodeKind::Guest, Mode::OwnIp);
    deployment.network = Some(VirtualNetwork {
        subnet: "10.99.0.0/24".parse().expect("prefix"),
        gateway: ip(GATEWAY4),
        host_alias: None,
    });
    deployment.transport_ipv6 = true;
    // The box's resolver endpoint is inside its own namespace, at the
    // address every namespace has.
    let endpoint: std::net::SocketAddrV4 = ENDPOINT.parse().expect("address");
    deployment.services.resolver = Some(netpol::Endpoint {
        v4: Some(endpoint),
        v6: None,
    });
    let mut live = h.install("own", deployment, policy(8, 128));
    // The addresses of the box's namespace, as the daemon adds them when
    // it gives the namespace its interface.
    for own in [BOX4, BOX6, BOX_LL6] {
        h.handles
            .add_own_address(live.id(), ip(own))
            .expect("own address");
    }

    // The peer's namespaces belong to a process outside any box. The box's
    // network namespace is created by a process inside the box cgroup, as
    // the sandbox does it: that is what puts the kernel's own neighbour
    // discovery for that namespace under the box's rules.
    let mut peer_cmd = Command::new("unshare");
    peer_cmd.args(["-Urn", "sleep", "600"]);
    let peer =
        crate::support::Background::from(peer_cmd.spawn().expect("start the peer namespace"));
    // Ready once it has left our user namespace and its id map is written.
    wait_for("the peer's user namespace", || {
        let userns = |pid: u32| std::fs::read_link(format!("/proc/{pid}/ns/user")).ok();
        userns(peer.pid()).is_some()
            && userns(peer.pid()) != userns(std::process::id())
            && std::fs::read_to_string(format!("/proc/{}/uid_map", peer.pid()))
                .is_ok_and(|m| !m.trim().is_empty())
    });
    let mut box_cmd = Command::new("nsenter");
    box_cmd.args([
        "-t",
        &peer.pid().to_string(),
        "-U",
        "--preserve-credentials",
        "--",
        "unshare",
        "-n",
        "sleep",
        "600",
    ]);
    let cg = h.cgroups();
    let holder = cg.spawn_in_box("own", box_cmd);
    let (peer_ns, box_ns) = (peer.pid(), holder.pid());
    let own_netns = || {
        let of = |pid: u32| std::fs::read_link(format!("/proc/{pid}/ns/net")).ok();
        of(box_ns).is_some() && of(box_ns) != of(peer_ns) && of(box_ns) != of(std::process::id())
    };
    wait_for("the box's network namespace", own_netns);

    in_ns(
        peer_ns,
        &[
            "ip", "link", "add", "vb", "type", "veth", "peer", "name", "va",
        ],
    );
    in_ns(
        peer_ns,
        &["ip", "link", "set", "va", "netns", &box_ns.to_string()],
    );
    for addr in [GATEWAY4, PEER4] {
        in_ns(
            peer_ns,
            &["ip", "addr", "add", &format!("{addr}/24"), "dev", "vb"],
        );
    }
    in_ns(
        peer_ns,
        &[
            "ip",
            "-6",
            "addr",
            "add",
            &format!("{PEER6}/64"),
            "dev",
            "vb",
            "nodad",
        ],
    );
    for addr in [BOX4, BOX4_OTHER] {
        in_ns(
            box_ns,
            &["ip", "addr", "add", &format!("{addr}/24"), "dev", "va"],
        );
    }
    in_ns(
        box_ns,
        &[
            "ip",
            "-6",
            "addr",
            "add",
            &format!("{BOX6}/64"),
            "dev",
            "va",
            "nodad",
        ],
    );
    // The box's link-local address is the one its deployment names, as
    // when the daemon sets the interface up.
    in_ns(box_ns, &["ip", "link", "set", "va", "addrgenmode", "none"]);
    for addr in [BOX_LL6, OTHER_LL6] {
        in_ns(
            box_ns,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                &format!("{addr}/64"),
                "dev",
                "va",
                "nodad",
            ],
        );
    }
    for (ns, dev) in [
        (peer_ns, "vb"),
        (peer_ns, "lo"),
        (box_ns, "va"),
        (box_ns, "lo"),
    ] {
        in_ns(ns, &["ip", "link", "set", dev, "up"]);
    }
    // Ping sockets are off in a new namespace.
    in_ns(box_ns, &["sysctl", "-qw", "net.ipv4.ping_group_range=0 0"]);
    let _peer_banner = Cgroups::hold_peer_probe(peer_ns, &["serve-tcp", "::", "18080"]);
    let probe = |args: &[&str]| cg.probe_in("own", box_ns, args);

    // ---- egress: rules reach a socket in the box's own namespace
    assert!(
        probe(&["tcp", PEER4, "18080"]).ends_with("data=hello"),
        "{}",
        probe(&["tcp", PEER4, "18080"])
    );
    assert_eq!(
        probe(&["tcp", PEER4, "18081", "500"]),
        refused(),
        "another port of the peer"
    );
    assert_eq!(
        probe(&["tcp", GATEWAY4, "80", "500"]),
        refused(),
        "the gateway is infrastructure"
    );
    assert_eq!(
        probe(&["tcp", "10.99.0.77", "80", "500"]),
        refused(),
        "other addresses of the virtual network"
    );
    assert_eq!(
        probe(&["tcp", "127.0.0.1", "9", "500"]),
        format!("err {}", libc::ECONNREFUSED),
        "its own loopback"
    );
    // IPv6 needs the kernel's neighbour discovery from this namespace to
    // pass the box's egress hook, which the base policy admits.
    assert!(
        probe(&["tcp", PEER6, "18080", "4000"]).ends_with("data=hello"),
        "{}",
        probe(&["tcp", PEER6, "18080"])
    );
    assert_eq!(probe(&["tcp", PEER6, "18081", "500"]), refused());

    // ---- an endpoint in the box's namespace knows its peers by namespace
    let mut inside = Cgroups::hold_peer_probe(box_ns, &["endpoint-udp", "127.0.80.1", "20480"]);
    let inside_ns: u64 = inside
        .ready
        .strip_prefix("netns=")
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no namespace cookie: {}", inside.ready));
    let here = boxbpf::current_netns_cookie().expect("namespace cookie");
    assert_ne!(inside_ns, here);
    let _client = cg.hold_probe_in("own", box_ns, &["hold-udp", "127.0.80.1", "20480", "40123"]);
    let peer: std::net::SocketAddr = inside
        .step()
        .strip_prefix("ok peer=")
        .and_then(|p| p.parse().ok())
        .expect("the endpoint got the box's datagram");
    assert_eq!(peer, "127.0.0.1:40123".parse().expect("address"));
    let recorded = |h: &Harness, netns| {
        h.handles
            .original_destination(netns, peer, Protocol::Udp)
            .expect("lookup")
            .map(|flow| (flow.box_id, flow.destination, flow.endpoint))
    };
    assert_eq!(
        recorded(&h, inside_ns),
        Some((
            live.id(),
            ENDPOINT.parse().expect("address"),
            netpol::base::RESOLVER
        ))
    );
    assert_eq!(
        recorded(&h, here),
        None,
        "the same peer address in another namespace"
    );
    // A box on the node's network with the same client address and port.
    // Each endpoint finds its own box behind `127.0.0.1:40123`.
    let outside = std::net::UdpSocket::bind((h.v4(6, 1), 0)).expect("bind an endpoint");
    let std::net::SocketAddr::V4(outside_at) = outside.local_addr().expect("address") else {
        panic!("an IPv4 socket");
    };
    let mut twin = crate::support::host_ip();
    twin.services.resolver = Some(netpol::Endpoint {
        v4: Some(outside_at),
        v6: None,
    });
    let twin = h.install("twin", twin, BoxPolicy::default());
    let _twin_client = h.hold_probe(
        "twin",
        &[
            "hold-udp",
            &outside_at.ip().to_string(),
            &outside_at.port().to_string(),
            "40123",
        ],
    );
    let mut buf = [0u8; 8];
    let (_, twin_peer) = outside.recv_from(&mut buf).expect("the twin's datagram");
    assert_eq!(twin_peer, peer);
    assert_eq!(recorded(&h, here).map(|(id, ..)| id), Some(twin.id()));
    assert_eq!(recorded(&h, inside_ns).map(|(id, ..)| id), Some(live.id()));

    // ---- UDP: a socket's replies come back, and nothing else comes in
    let _peer_echo = Cgroups::hold_peer_probe(peer_ns, &["serve-udp", PEER4, "18090"]);
    assert_eq!(
        probe(&["udp", PEER4, "18090", "1000"]),
        format!("ok from={PEER4}:18090"),
        "the reply of a peer the box wrote to passes the ingress default"
    );
    let _box_echo = cg.hold_probe_in("own", box_ns, &["serve-udp", "::", "18091"]);
    let knock = |port: &str| Cgroups::peer_probe(peer_ns, &["udp", BOX4, port, "500"]);
    assert_eq!(
        knock("18091"),
        "err timeout",
        "a datagram nobody asked for is dropped"
    );
    let udp_port = PortOf {
        protocols: Protocols::UDP,
        port: 18091,
    };
    h.handles.publish(&mut live, udp_port).expect("publish");
    // The peer sends from the gateway address, which no egress rule lets
    // the box write to. The answer passes because the datagram came in.
    assert_eq!(knock("18091"), format!("ok from={BOX4}:18091"));
    h.handles.unpublish(&mut live, udp_port).expect("unpublish");
    assert_eq!(knock("18091"), "err timeout");

    // ---- ICMP and ICMPv6 by message type
    assert_eq!(probe(&["ping", PEER4]), "ok type=0");
    assert_eq!(probe(&["ping", PEER6]), "ok type=129");
    let spec = netpol::Spec {
        policy: policy(0, 129),
        ..live.spec().clone()
    };
    h.handles.reconfigure(&mut live, spec).expect("reconfigure");
    // The rules now name the reply types only. An echo request is another
    // type. IPv4 reports the drop, the IPv6 ping socket does not.
    assert_eq!(probe(&["ping", PEER4, "500"]), "err 1");
    assert_eq!(probe(&["ping", PEER6, "500"]), "err timeout");
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().any(|e| e.hook == Hook::Egress
            && e.protocol == 58
            && e.dst == ip(PEER6)
            && e.dst_port == 128),
        "no event for the refused ICMPv6 echo: {seen:?}"
    );

    // ---- source address check
    assert_eq!(
        probe(&["tcp-from", BOX4_OTHER, PEER4, "18080", "700"]),
        "err timeout"
    );
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().any(|e| e.hook == Hook::Egress
            && e.reason == Reason::SourceAddress
            && e.src == ip(BOX4_OTHER)),
        "{seen:?}"
    );
    // The box talks to its own address and not to the other one on its
    // interface, which is just an address of the virtual network.
    let refused_by_peer = format!("err {}", libc::ECONNREFUSED);
    assert_eq!(probe(&["tcp", BOX4, "9", "500"]), refused_by_peer);
    assert_eq!(probe(&["tcp", BOX4_OTHER, "9", "500"]), refused());
    // A second address of the box, as a task run in a namespace of its
    // own gets one: a source and "itself" from the one write on, and
    // neither once it is taken away. The policy is not compiled again.
    let generation = live.compiled().clone();
    h.handles
        .add_own_address(live.id(), ip(BOX4_OTHER))
        .expect("a second address");
    assert_eq!(
        probe(&["tcp-from", BOX4_OTHER, PEER4, "18080", "700"]),
        "ok connected"
    );
    assert_eq!(probe(&["tcp", BOX4_OTHER, "9", "500"]), refused_by_peer);
    h.handles
        .remove_own_address(live.id(), ip(BOX4_OTHER))
        .expect("remove the address");
    assert_eq!(
        probe(&["tcp-from", BOX4_OTHER, PEER4, "18080", "700"]),
        "err timeout"
    );
    assert_eq!(probe(&["tcp", BOX4_OTHER, "9", "500"]), refused());
    assert!(std::sync::Arc::ptr_eq(&generation, live.compiled()));
    let _drops = Harness::drain(&mut events);

    // A box can give itself any link-local address. Only the one the
    // engine knows as the box's is a source.
    let from = |source: &str| probe(&["tcp-from", &format!("{source}%va"), PEER6, "18080", "700"]);
    assert_eq!(from(BOX_LL6), "ok connected");
    assert_eq!(from(OTHER_LL6), "err timeout");
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().any(|e| e.hook == Hook::Egress
            && e.reason == Reason::SourceAddress
            && e.src == ip(OTHER_LL6)),
        "{seen:?}"
    );
    assert!(
        seen.iter().all(|e| e.src != ip(BOX_LL6)),
        "the box's own link-local address is refused: {seen:?}"
    );
    // Duplicate address detection sends from the unspecified address, and
    // the source check lets that through.
    in_ns(
        box_ns,
        &["ip", "-6", "addr", "add", "fd00:99::7/64", "dev", "va"],
    );
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().all(|e| e.reason != Reason::SourceAddress),
        "{seen:?}"
    );

    // ---- ingress: new inbound flows only on published ports
    let _box_server = cg.hold_probe_in("own", box_ns, &["serve-tcp", "::", "18300"]);
    // The listener is known by the namespace it is in.
    let listeners = |netns| h.handles.listening(live.id(), netns).expect("listeners");
    assert_eq!(
        listeners(inside_ns),
        [boxbpf::Listening {
            address: ip("::"),
            port: 18300
        }]
    );
    assert!(listeners(here).is_empty());
    let inbound = |addr: &str| Cgroups::peer_probe(peer_ns, &["tcp", addr, "18300", "700"]);
    let published = PortOf {
        protocols: Protocols::TCP,
        port: 18300,
    };
    let ingress = Flow {
        direction: Direction::Ingress,
        protocol: Protocol::Tcp,
        remote: ip(PEER4),
        port: 18300,
        local: None,
    };
    assert_eq!(inbound(BOX4), "err timeout");
    assert_eq!(
        live.compiled().evaluate(&ingress, |_| None).verdict,
        FlowVerdict::Deny
    );
    let seen = Harness::drain(&mut events);
    // The peer connects from the first address of its interface.
    assert!(
        seen.iter().any(|e| e.hook == Hook::Ingress
            && e.dst == ip(BOX4)
            && e.dst_port == 18300
            && e.src == ip(GATEWAY4)),
        "{seen:?}"
    );

    h.handles.publish(&mut live, published).expect("publish");
    assert!(
        inbound(BOX4).ends_with("data=hello"),
        "published, IPv4: {}",
        inbound(BOX4)
    );
    assert!(
        inbound(BOX6).ends_with("data=hello"),
        "published, IPv6: {}",
        inbound(BOX6)
    );
    assert_eq!(
        live.compiled().evaluate(&ingress, |_| None).verdict,
        FlowVerdict::Allow
    );

    h.handles
        .unpublish(&mut live, published)
        .expect("unpublish");
    assert_eq!(inbound(BOX4), "err timeout");
    assert_eq!(inbound(BOX6), "err timeout");

    let stats = h
        .handles
        .stats(live.id())
        .expect("stats")
        .expect("counters");
    assert!(
        stats.tx_pkts > 0 && stats.rx_pkts > 0 && stats.tx_drop > 0 && stats.rx_drop > 0,
        "{stats:?}"
    );
}
