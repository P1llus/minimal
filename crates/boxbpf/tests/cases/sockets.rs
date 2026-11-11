//! A socket belongs to the box it was created in: every hook judges it as
//! that box, whichever process makes the call.

use std::{
    net::{IpAddr, SocketAddr},
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::Duration,
};

use netpol::{
    abi::{Hook, Reason},
    policy::BoxPolicy,
};

use crate::support::{Harness, REFUSED, host_ip, probe, servers};

fn refused() -> String {
    format!("err {REFUSED}")
}

/// Sockets a process of `box_name` creates and hands out.
fn made_in(h: &Harness, box_name: &str, kind: &str, count: usize) -> Vec<OwnedFd> {
    let (ours, theirs) = UnixStream::pair().expect("socket pair");
    assert_eq!(
        h.cgroups().probe_over(
            box_name,
            &["make-sockets", kind, &count.to_string()],
            theirs.into()
        ),
        "ok"
    );
    let socks = probe::recv_sockets(ours.as_fd()).expect("receive the sockets");
    assert_eq!(socks.len(), count);
    socks
}

/// What a process of `box_name` gets when it uses `sock`.
fn used_in(h: &Harness, box_name: &str, sock: OwnedFd, kind: &str, to: SocketAddr) -> String {
    let (ours, theirs) = UnixStream::pair().expect("socket pair");
    probe::send_sockets(ours.as_fd(), &[sock]).expect("pass the socket on");
    h.cgroups().probe_over(
        box_name,
        &[
            "use-socket",
            kind,
            &to.ip().to_string(),
            &to.port().to_string(),
        ],
        theirs.into(),
    )
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_socket_is_judged_as_the_box_that_created_it() {
    let Some(mut h) =
        Harness::start("cases::sockets::a_socket_is_judged_as_the_box_that_created_it")
    else {
        return;
    };
    let mut events = h.handles.take_events().expect("event source");
    let port = servers::banner();
    let allow = |group: u8| BoxPolicy {
        allow: vec![h.v4_group(group).parse().expect("prefix")],
        ..BoxPolicy::default()
    };
    // Box a may reach group 1 only, box b group 5 only.
    let (policy_a, policy_b) = (allow(1), allow(5));
    let a = h.install("a", host_ip(), policy_a);
    let b = h.install("b", host_ip(), policy_b);
    let in_a = SocketAddr::new(IpAddr::V4(h.v4(1, 1)), port);
    let in_b = SocketAddr::new(IpAddr::V4(h.v4(5, 1)), port);
    let wait = Duration::from_millis(1500);
    let errno = |result: std::io::Result<String>| result.err().and_then(|e| e.raw_os_error());

    // This process is in no box. With a's sockets it is judged as a, at
    // the system call and on the wire: the connection completes.
    let mut socks = made_in(&h, "a", "tcp", 4);
    let mut next = || socks.pop().expect("a socket of box a");
    assert_eq!(
        probe::connect_fd(&next(), in_a, wait).expect("a's rules admit group 1"),
        "connected"
    );
    assert_eq!(errno(probe::connect_fd(&next(), in_b, wait)), Some(REFUSED));
    let seen = Harness::drain(&mut events);
    assert!(
        seen.iter().any(|e| e.box_id == a.id().0
            && e.hook == Hook::Connect4
            && e.reason == Reason::Default
            && e.dst == in_b.ip()),
        "the refusal is reported for box a: {seen:?}"
    );
    assert!(
        seen.iter().all(|e| e.reason != Reason::NoConfig),
        "{seen:?}"
    );
    let refusals = |h: &Harness, id| {
        h.handles
            .stats(id)
            .expect("stats")
            .expect("counters")
            .refused
    };
    assert_eq!((refusals(&h, a.id()), refusals(&h, b.id())), (1, 0));

    // A process of box b that holds a socket of box a: still a's rules.
    assert_eq!(used_in(&h, "b", next(), "tcp", in_a), "ok connected");
    assert_eq!(used_in(&h, "b", next(), "tcp", in_b), refused());
    // Its own sockets follow b's rules.
    let tcp = |to: SocketAddr| {
        h.probe(
            "b",
            &["tcp", &to.ip().to_string(), &to.port().to_string(), "500"],
        )
    };
    assert_eq!(tcp(in_a), refused());
    assert!(tcp(in_b).ends_with("data=hello"), "{}", tcp(in_b));
    assert_eq!((refusals(&h, a.id()), refusals(&h, b.id())), (2, 1));

    // The same for a datagram socket, which the sendmsg hook judges.
    let echo = servers::udp_echo("0.0.0.0".parse().expect("address"));
    let (to_a, to_b) = (
        SocketAddr::new(in_a.ip(), echo),
        SocketAddr::new(in_b.ip(), echo),
    );
    let mut socks = made_in(&h, "a", "udp", 3);
    let mut next = || socks.pop().expect("a socket of box a");
    assert_eq!(probe::sendto_fd(&next(), to_a).expect("group 1"), "sent");
    assert_eq!(errno(probe::sendto_fd(&next(), to_b)), Some(REFUSED));
    assert_eq!(used_in(&h, "b", next(), "udp", to_b), refused());

    // A socket that accept() returned is its listener's box's. The bind
    // hook lets the call through to the kernel, which says the socket is
    // bound already.
    assert_eq!(
        h.probe("a", &["accept-bind", &in_a.ip().to_string()]),
        format!("err {}", libc::EINVAL)
    );
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_udp_socket_gets_the_answers_of_many_peers() {
    use netpol::{
        Defaults, Verdict,
        base::{BasePolicy, BoxAddrs},
        compile::{Options, compile},
    };

    let Some(mut h) = Harness::start("cases::sockets::a_udp_socket_gets_the_answers_of_many_peers")
    else {
        return;
    };
    // Nothing may come in but an answer: every datagram the box gets
    // back passes because its socket remembers the peer.
    let base = BasePolicy {
        before: Vec::new(),
        protected: Vec::new(),
        defaults: Defaults {
            egress: Verdict::Allow,
            ingress: Verdict::Deny,
            bind: Verdict::Allow,
        },
        endpoints: Vec::new(),
        source_check: false,
        addrs: BoxAddrs::default(),
    };
    let compiled = compile(&base, &BoxPolicy::default(), Options::default()).expect("compile");
    let id = h.new_box("u");
    h.handles
        .apply(id, std::sync::Arc::new(compiled))
        .expect("apply");

    // Forty peers on consecutive ports, as a resolver or a peer-to-peer
    // client has them.
    let at = IpAddr::V4(h.v4(1, 1));
    let count = 40u16;
    let first = (20_000..40_000u16)
        .step_by(100)
        .find(|first| {
            (*first..*first + count)
                .all(|port| std::net::UdpSocket::bind(SocketAddr::new(at, port)).is_ok())
        })
        .expect("forty free ports in a row");
    for port in first..first + count {
        servers::udp_echo_at(SocketAddr::new(at, port));
    }
    assert_eq!(
        h.probe(
            "u",
            &[
                "udp-many",
                &at.to_string(),
                &first.to_string(),
                &count.to_string()
            ]
        ),
        format!("ok answers={count}")
    );
    let stats = h.handles.stats(id).expect("stats").expect("counters");
    assert_eq!(stats.rx_drop, 0, "{stats:?}");
}

fn listening(h: &Harness, id: boxbpf::BoxId, netns: u64) -> Vec<(IpAddr, u16)> {
    h.handles
        .listening(id, netns)
        .expect("read the listeners")
        .into_iter()
        .map(|l| (l.address, l.port))
        .collect()
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_listening_socket_is_in_the_table_until_it_is_released() {
    use netpol::event::{Event, ListenEvent};

    let Some(mut h) =
        Harness::start("cases::sockets::a_listening_socket_is_in_the_table_until_it_is_released")
    else {
        return;
    };
    let mut events = h.handles.take_events().expect("event source");
    let here = boxbpf::current_netns_cookie().expect("namespace cookie");
    let live = h.install("l", host_ip(), BoxPolicy::default());
    let other = h.install("m", host_ip(), BoxPolicy::default());
    let id = live.id();
    assert!(listening(&h, id, here).is_empty());

    let at4 = IpAddr::V4(h.v4(1, 1));
    let any6: IpAddr = "::".parse().expect("address");
    let (on4, port4) = h.listen_in("l", at4);
    let (_on6, port6) = h.listen_in("l", any6);
    let mut expected = vec![(at4, port4), (any6, port6)];
    expected.sort_unstable();
    assert_eq!(listening(&h, id, here), expected);
    assert!(listening(&h, other.id(), here).is_empty(), "another box");
    assert!(listening(&h, id, here + 1).is_empty(), "another namespace");
    assert_eq!(h.handles.usage(id).expect("usage").listens, 2);

    // The record that says "read the table now".
    let heard = |events: &mut boxbpf::events::Source| -> Vec<ListenEvent> {
        Harness::drain_all(events)
            .into_iter()
            .filter_map(|event| match event {
                Event::Listen(e) => Some(e),
                _ => None,
            })
            .collect()
    };
    let opened = heard(&mut events);
    assert_eq!(opened.len(), 2, "{opened:?}");
    assert!(
        opened.iter().any(|e| e.box_id == id.0
            && e.netns == here
            && e.port == port4
            && e.family == netpol::Family::V4
            && e.open),
        "{opened:?}"
    );

    // A bound datagram socket and a TCP socket that only connects are no
    // listeners, and neither is a listener outside every box.
    let outside = std::net::TcpListener::bind((h.v4(1, 2), 0)).expect("listen");
    let port = outside.local_addr().expect("address").port();
    assert!(
        h.probe(
            "l",
            &["tcp", &h.v4(1, 2).to_string(), &port.to_string(), "300"]
        )
        .starts_with("ok ")
    );
    assert!(
        h.probe("l", &["bind", "udp", &at4.to_string(), "0"])
            .starts_with("ok ")
    );
    assert_eq!(listening(&h, id, here), expected);

    // The entry goes with the socket.
    drop(on4);
    crate::support::wait_for("the closed listener to leave the table", || {
        listening(&h, id, here) == [(any6, port6)]
    });
    let closed = heard(&mut events);
    assert!(
        closed.iter().any(|e| e.port == port4 && !e.open),
        "{closed:?}"
    );
    assert_eq!(h.handles.usage(id).expect("usage").listens, 1);
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_box_has_room_for_so_many_listeners() {
    let Some(mut h) = Harness::start_sized(
        "cases::sockets::a_box_has_room_for_so_many_listeners",
        "listens_per_box",
        2,
    ) else {
        return;
    };
    let here = boxbpf::current_netns_cookie().expect("namespace cookie");
    let full = h.install("full", host_ip(), BoxPolicy::default());
    let free = h.install("free", host_ip(), BoxPolicy::default());
    let at = IpAddr::V4(h.v4(1, 1));
    let held: Vec<_> = (0..3).map(|_| h.listen_in("full", at)).collect();
    // The third listens, as far as the box can tell. It is not recorded.
    assert_eq!(listening(&h, full.id(), here).len(), 2);
    assert_eq!(h.handles.usage(full.id()).expect("usage").listens, 2);
    let (_other, port) = h.listen_in("free", at);
    assert_eq!(listening(&h, free.id(), here), [(at, port)]);
    drop(held);
    crate::support::wait_for("the listeners to leave the table", || {
        listening(&h, full.id(), here).is_empty()
    });
    assert_eq!(h.handles.usage(full.id()).expect("usage").listens, 0);
}
