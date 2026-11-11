//! Redirects to per-box endpoints: DNS over UDP and TCP with the address
//! restored for the application, TCP to a proxy endpoint with lookup of the
//! original destination, isolation between boxes, and name-set pins.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use netpol::{
    Endpoint, FlowVerdict, PortRange, Prefix, Protocol,
    base::{CREDENTIAL_PROXY, Deployment, EndpointRange, RESOLVER},
    policy::BoxPolicy,
};

use crate::support::{Harness, REFUSED, host_ip, servers};

fn refused() -> String {
    format!("err {REFUSED}")
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn dns_is_redirected_to_the_box_endpoint_and_boxes_are_isolated() {
    let Some(mut h) = Harness::start(
        "cases::redirect::dns_is_redirected_to_the_box_endpoint_and_boxes_are_isolated",
    ) else {
        return;
    };
    let here = boxbpf::current_netns_cookie().expect("namespace cookie");
    let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    // IPv4 endpoints get an address each in group 6. On IPv6 the host has
    // one loopback address, so endpoints differ by port.
    let endpoint = |host: u8| {
        let v4 = SocketAddrV4::new(h.v4(6, host), servers::free_port(IpAddr::V4(h.v4(6, host))));
        let v6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, servers::free_port(lo6), 0, 0);
        Endpoint {
            v4: Some(v4),
            v6: Some(v6),
        }
    };
    let (ep_a, ep_b) = (endpoint(1), endpoint(2));
    let ports6 = [ep_a, ep_b].map(|e| e.v6.expect("v6").port());
    let ranges = vec![
        EndpointRange {
            prefix: h.v4_group(6).parse().expect("prefix"),
            ports: PortRange::ALL,
        },
        EndpointRange {
            prefix: Prefix::host(lo6),
            ports: PortRange::new(ports6[0].min(ports6[1]), ports6[0].max(ports6[1]))
                .expect("range"),
        },
    ];
    let flows = h.handles.flows().expect("flows");
    let serve = |e: Endpoint, answer: Ipv4Addr| {
        (
            servers::dns_endpoint(SocketAddr::V4(e.v4.expect("v4")), answer, &flows),
            servers::dns_endpoint(SocketAddr::V6(e.v6.expect("v6")), answer, &flows),
        )
    };
    let (a4, a6) = serve(ep_a, Ipv4Addr::new(198, 51, 100, 1));
    let (b4, _b6) = serve(ep_b, Ipv4Addr::new(198, 51, 100, 2));

    let deployment = |e: Endpoint| -> Deployment {
        let mut d = host_ip();
        d.services.resolver = Some(e);
        d.endpoint_ranges.clone_from(&ranges);
        d
    };
    let box_a = h.install("a", deployment(ep_a), BoxPolicy::default());
    let box_b = h.install("b", deployment(ep_b), BoxPolicy::default());

    // Whatever server the box asks, its own endpoint answers, and the
    // application sees the server it asked.
    let wait = Duration::from_secs(2);
    for (server, shown) in [
        ("127.0.0.53", "127.0.0.53:53"),
        ("8.8.8.8", "8.8.8.8:53"),
        ("::1", "[::1]:53"),
    ] {
        let endpoint_rx = if server.contains(':') { &a6 } else { &a4 };
        for over in ["udp", "tcp"] {
            let args: &[&str] = if over == "tcp" {
                &["dns", server, "tcp"]
            } else {
                &["dns", server]
            };
            assert_eq!(
                h.probe("a", args),
                format!("ok from={shown} answer=198.51.100.1"),
                "{server} over {over}"
            );
            // The endpoint learns the box and the original server from
            // the peer address it saw.
            let seen = endpoint_rx
                .recv_timeout(wait)
                .expect("the endpoint saw the query");
            let origin = seen.origin.expect("a recorded flow");
            assert_eq!(origin.box_id, box_a.id());
            assert_eq!(origin.destination, shown.parse().expect("address"));
            assert_eq!(origin.endpoint, RESOLVER);
            // The entry went with the box's socket: whoever gets that
            // address and port next is not taken for the box.
            assert_eq!(
                h.handles
                    .original_destination(here, seen.peer, seen.protocol)
                    .expect("lookup"),
                None,
                "{server} over {over}"
            );
        }
    }
    // A v4-mapped server on an AF_INET6 socket is an IPv4 flow.
    assert_eq!(
        h.probe("a", &["dns", "::ffff:127.0.0.53"]),
        "ok from=[::ffff:127.0.0.53]:53 answer=198.51.100.1"
    );

    // The other box gets its own endpoint.
    assert_eq!(
        h.probe("b", &["dns", "127.0.0.53"]),
        "ok from=127.0.0.53:53 answer=198.51.100.2"
    );
    let seen = b4.recv_timeout(wait).expect("endpoint b saw the query");
    assert_eq!(seen.origin.expect("a recorded flow").box_id, box_b.id());

    // A process outside every box reaches the endpoint too, since nothing
    // judges its sockets. The engine has no entry for it, which is how an
    // endpoint knows not to serve it.
    while a4.try_recv().is_ok() {}
    let outside = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    outside
        .send_to(b"not a box", SocketAddr::V4(ep_a.v4.expect("v4")))
        .expect("send");
    let seen = a4.recv_timeout(wait).expect("endpoint a saw the datagram");
    assert_eq!(seen.peer, outside.local_addr().expect("address"));
    assert_eq!(seen.origin, None);

    // A box reaches its own endpoint directly and not the other box's.
    let sock = |e: Endpoint, v6: bool| -> (String, String) {
        if v6 {
            let s = e.v6.expect("v6");
            (s.ip().to_string(), s.port().to_string())
        } else {
            let s = e.v4.expect("v4");
            (s.ip().to_string(), s.port().to_string())
        }
    };
    for v6 in [false, true] {
        let (own_ip, own_port) = sock(ep_a, v6);
        let (other_ip, other_port) = sock(ep_b, v6);
        assert!(
            h.probe("a", &["tcp", &own_ip, &own_port, "500"])
                .starts_with("ok "),
            "own endpoint, v6={v6}"
        );
        assert_eq!(
            h.probe("a", &["tcp", &other_ip, &other_port, "500"]),
            refused(),
            "other endpoint, v6={v6}"
        );
        assert_eq!(
            h.probe("a", &["udp", &other_ip, &other_port]),
            refused(),
            "other endpoint UDP, v6={v6}"
        );
    }
    // The evaluator sends the same flow to the same place.
    let flow = netpol::Flow {
        direction: netpol::Direction::Egress,
        protocol: Protocol::Udp,
        remote: "9.9.9.9".parse().expect("address"),
        port: 53,
        local: None,
    };
    assert_eq!(
        box_a.compiled().evaluate(&flow, |_| None).verdict,
        FlowVerdict::Redirect(SocketAddr::V4(ep_a.v4.expect("v4")))
    );
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn steered_names_go_to_the_proxy_and_pins_expire() {
    let Some(mut h) =
        Harness::start("cases::redirect::steered_names_go_to_the_proxy_and_pins_expire")
    else {
        return;
    };
    let here = boxbpf::current_netns_cookie().expect("namespace cookie");
    let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let proxy = Endpoint {
        v4: Some(SocketAddrV4::new(
            h.v4(6, 3),
            servers::free_port(IpAddr::V4(h.v4(6, 3))),
        )),
        v6: Some(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            servers::free_port(lo6),
            0,
            0,
        )),
    };
    let flows = h.handles.flows().expect("flows");
    let seen4 = servers::proxy_endpoint(SocketAddr::V4(proxy.v4.expect("v4")), &flows);
    let seen6 = servers::proxy_endpoint(SocketAddr::V6(proxy.v6.expect("v6")), &flows);
    let banner = servers::banner().to_string();
    let echo = servers::udp_echo(IpAddr::V4(h.v4(5, 8))).to_string();

    let mut deployment = host_ip();
    deployment.services.credential_proxy = Some(proxy);
    deployment.steered = vec!["steered.test".parse().expect("name")];
    let policy = BoxPolicy {
        names: vec!["allowed.test".parse().expect("name")],
        ..BoxPolicy::default()
    };
    let mut live = h.install("c", deployment, policy);
    let id = live.id();
    let allowed = live
        .compiled()
        .set_for_name("allowed.test")
        .expect("set of the allowed name");
    assert!(
        live.compiled().resolvable("allowed.test") && !live.compiled().resolvable("other.test")
    );

    // TCP 443 to an address pinned for a steered name lands on the proxy
    // endpoint, which learns where it was going. Nothing listens at the
    // pinned addresses themselves.
    let wait = Duration::from_secs(2);
    for (target, seen) in [
        (IpAddr::V4(h.v4(5, 7)), &seen4),
        (IpAddr::V6(h.v6(0x0507)), &seen6),
    ] {
        h.handles
            .pin(id, target, "steered.test", Duration::from_secs(60))
            .expect("pin");
        let shown = SocketAddr::new(target, 443);
        assert_eq!(
            h.probe("c", &["tcp", &target.to_string(), "443"]),
            format!("ok peer={shown} data=proxied")
        );
        let origin = seen
            .recv_timeout(wait)
            .expect("the proxy endpoint accepted")
            .origin
            .expect("a recorded flow");
        assert_eq!(
            (origin.box_id, origin.destination, origin.endpoint),
            (id, shown, CREDENTIAL_PROXY)
        );
        // QUIC to the same address is refused at once, so the client falls back.
        assert_eq!(
            h.probe("c", &["udp", &target.to_string(), "443"]),
            refused()
        );
        // Steering admits nothing else: the name is not on the allow list.
        assert_eq!(
            h.probe("c", &["tcp", &target.to_string(), &banner, "300"]),
            refused()
        );
    }
    // The box may dial its endpoint itself. That flow is recorded too,
    // with the endpoint as where it was headed. A process outside every
    // box connects as well and has no entry.
    for (endpoint, seen) in [
        (SocketAddr::V4(proxy.v4.expect("v4")), &seen4),
        (SocketAddr::V6(proxy.v6.expect("v6")), &seen6),
    ] {
        assert_eq!(
            h.probe(
                "c",
                &[
                    "tcp",
                    &endpoint.ip().to_string(),
                    &endpoint.port().to_string()
                ]
            ),
            format!("ok peer={endpoint} data=proxied")
        );
        let direct = seen
            .recv_timeout(wait)
            .expect("the proxy endpoint accepted");
        let origin = direct.origin.expect("a recorded flow");
        assert_eq!(
            (origin.box_id, origin.destination, origin.endpoint),
            (id, endpoint, CREDENTIAL_PROXY)
        );
        assert_eq!(
            h.handles
                .original_destination(here, direct.peer, Protocol::Tcp)
                .expect("lookup"),
            None,
            "the entry goes with the socket"
        );

        let outside = std::net::TcpStream::connect(endpoint).expect("connect from outside");
        let from_outside = seen
            .recv_timeout(wait)
            .expect("the proxy endpoint accepted");
        assert_eq!(from_outside.peer, outside.local_addr().expect("address"));
        assert_eq!(from_outside.origin, None);
    }

    // A v4-mapped destination is redirected as IPv4.
    let mapped = h.v4(5, 7).to_ipv6_mapped().to_string();
    assert_eq!(
        h.probe("c", &["tcp", &mapped, "443"]),
        format!("ok peer=[{mapped}]:443 data=proxied")
    );

    // A pin for an allowed name admits the address while it lives.
    let target = IpAddr::V4(h.v4(5, 8));
    let target_s = target.to_string();
    assert_eq!(
        h.probe("c", &["tcp", &target_s, &banner, "300"]),
        refused(),
        "not pinned yet"
    );
    h.handles
        .pin(id, target, "allowed.test", Duration::from_millis(900))
        .expect("pin");
    assert_eq!(h.handles.pinned_set(id, target), Some(allowed));
    assert!(
        h.probe("c", &["tcp", &target_s, &banner, "300"])
            .ends_with("data=hello")
    );
    let mut open_flow = h.hold_probe("c", &["hold-udp", &target_s, &echo]);
    std::thread::sleep(Duration::from_millis(1100));

    assert_eq!(h.handles.pinned_set(id, target), None);
    assert_eq!(
        h.probe("c", &["tcp", &target_s, &banner, "300"]),
        refused(),
        "a new connection needs a live pin"
    );
    assert_eq!(
        open_flow.step(),
        "ok",
        "a flow opened while the pin lived continues"
    );
    assert_eq!(h.handles.sweep_pins().expect("sweep"), 1);
    // A change of policy ends what sockets have cached: the open flow is
    // judged again, and the pin is gone.
    let port = netpol::base::PortOf {
        protocols: netpol::Protocols::TCP,
        port: 18400,
    };
    h.handles.publish(&mut live, port).expect("publish");
    assert_eq!(open_flow.step(), "err 1");
}
