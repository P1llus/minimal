//! Listeners the test process runs itself, as the daemon would: plain
//! targets for allowed flows, and the per-box service endpoints.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    sync::mpsc::{Receiver, channel},
    thread,
    time::Duration,
};

use boxbpf::{Flows, OriginalDestination};
use netpol::Protocol;

/// A TCP listener on every address of the host that greets with `hello`.
/// Returns its port.
pub fn banner() -> u16 {
    let listener = TcpListener::bind("[::]:0").expect("bind a banner listener");
    let port = listener.local_addr().expect("local address").port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            // The client may have gone away.
            let _sent = stream.write_all(b"hello\n");
        }
    });
    port
}

/// A TCP listener on every address of the host that greets with `hello`
/// and then sends back what it reads, for as long as the client stays.
/// Returns its port.
pub fn greeting_echo() -> u16 {
    let listener = TcpListener::bind("[::]:0").expect("bind an echo listener");
    let port = listener.local_addr().expect("local address").port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                let mut next: &[u8] = b"hello\n";
                // Either end may have gone away.
                while stream.write_all(next).is_ok() {
                    match stream.read(&mut buf) {
                        Ok(n) if n > 0 => next = buf.get(..n).unwrap_or_default(),
                        _ => break,
                    }
                }
            });
        }
    });
    port
}

/// A UDP socket at `at` that answers every datagram. Returns its port.
pub fn udp_echo(at: IpAddr) -> u16 {
    let sock = UdpSocket::bind(SocketAddr::new(at, 0)).expect("bind a UDP echo socket");
    let port = sock.local_addr().expect("local address").port();
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        while let Ok((_, peer)) = sock.recv_from(&mut buf) {
            let _sent = sock.send_to(b"pong", peer);
        }
    });
    port
}

/// A UDP socket at `at` that takes datagrams and never answers, with its
/// port. It is bound for as long as the caller keeps it.
pub fn udp_silent(at: IpAddr) -> (UdpSocket, u16) {
    let sock = UdpSocket::bind(SocketAddr::new(at, 0)).expect("bind a silent UDP socket");
    let port = sock.local_addr().expect("local address").port();
    (sock, port)
}

/// A UDP socket at exactly `at` that answers every datagram.
pub fn udp_echo_at(at: SocketAddr) {
    let sock = UdpSocket::bind(at).expect("bind a UDP echo socket");
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        while let Ok((_, peer)) = sock.recv_from(&mut buf) {
            let _sent = sock.send_to(b"pong", peer);
        }
    });
}

fn dns_answer(query: &[u8], answer: Ipv4Addr) -> Vec<u8> {
    let mut reply = query.to_vec();
    if let Some(flags) = reply.get_mut(2..4) {
        flags.copy_from_slice(&[0x81, 0x80]);
    }
    if let Some(count) = reply.get_mut(6..8) {
        count.copy_from_slice(&[0, 1]);
    }
    reply.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    reply.extend(answer.octets());
    reply
}

/// A peer of an endpoint, with what the engine recorded for it at the time
/// the endpoint saw it. The entry goes with the peer's socket, so the
/// endpoint asks before it answers, as the daemon's endpoints do.
pub struct Seen {
    pub peer: SocketAddr,
    pub protocol: Protocol,
    pub origin: Option<OriginalDestination>,
}

fn seen(flows: &Flows, peer: SocketAddr, protocol: Protocol) -> Seen {
    // These endpoints are in the test's own network namespace.
    let netns = boxbpf::current_netns_cookie().expect("namespace cookie");
    Seen {
        peer,
        protocol,
        origin: flows
            .original_destination(netns, peer, protocol)
            .expect("lookup"),
    }
}

/// A resolver endpoint: answers every query over UDP and TCP at `at` with
/// one A record and reports the peer of each query.
pub fn dns_endpoint(at: SocketAddr, answer: Ipv4Addr, flows: &Flows) -> Receiver<Seen> {
    let (tx, rx) = channel();
    let (udp_flows, tcp_flows) = (
        flows.try_clone().expect("flows"),
        flows.try_clone().expect("flows"),
    );
    let udp = UdpSocket::bind(at).expect("bind a resolver endpoint (UDP)");
    let tcp = TcpListener::bind(at).expect("bind a resolver endpoint (TCP)");
    let udp_tx = tx.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = udp.recv_from(&mut buf) {
            let _told = udp_tx.send(seen(&udp_flows, peer, Protocol::Udp));
            let _sent = udp.send_to(&dns_answer(buf.get(..n).unwrap_or_default(), answer), peer);
        }
    });
    thread::spawn(move || {
        for mut stream in tcp.incoming().flatten() {
            let Ok(peer) = stream.peer_addr() else {
                continue;
            };
            let _timeout = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut len = [0u8; 2];
            if stream.read_exact(&mut len).is_err() {
                // A plain connect with no query, as the isolation checks do.
                continue;
            }
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if stream.read_exact(&mut query).is_err() {
                continue;
            }
            let _told = tx.send(seen(&tcp_flows, peer, Protocol::Tcp));
            let reply = dns_answer(&query, answer);
            let _sent = stream
                .write_all(&u16::try_from(reply.len()).expect("length").to_be_bytes())
                .and_then(|()| stream.write_all(&reply));
        }
    });
    rx
}

/// A proxy endpoint: accepts at `at`, says `proxied`, reports each peer.
pub fn proxy_endpoint(at: SocketAddr, flows: &Flows) -> Receiver<Seen> {
    let (tx, rx) = channel();
    let flows = flows.try_clone().expect("flows");
    let listener = TcpListener::bind(at).expect("bind a proxy endpoint");
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let Ok(peer) = stream.peer_addr() else {
                continue;
            };
            let _told = tx.send(seen(&flows, peer, Protocol::Tcp));
            let _sent = stream.write_all(b"proxied\n");
        }
    });
    rx
}

/// A free port on an address, for an endpoint the test binds next.
pub fn free_port(at: IpAddr) -> u16 {
    TcpListener::bind(SocketAddr::new(at, 0))
        .expect("bind")
        .local_addr()
        .expect("local address")
        .port()
}
