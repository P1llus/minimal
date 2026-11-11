//! Socket actions a test runs as a process of a box. The action is in
//! `BOXBPF_TEST_PROBE`. The result is one line, `probe: ok ...` or
//! `probe: err <errno>`.

use std::{
    io::{BufRead, Read, Write},
    mem::size_of,
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    time::Duration,
};

fn errno(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "err timeout".to_owned(),
        _ => format!("err {}", e.raw_os_error().unwrap_or(0)),
    }
}

fn report(result: std::io::Result<String>) -> String {
    match result {
        Ok(text) => format!("ok {text}"),
        Err(e) => errno(&e),
    }
}

fn say(line: &str) {
    println!("probe: {}", line.trim_end());
    std::io::stdout().flush().expect("flush");
}

fn wait_step() -> bool {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .is_ok_and(|n| n > 0)
}

fn addr(ip: &str, port: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().expect("address"), port.parse().expect("port"))
}

fn unspecified(peer: &SocketAddr) -> SocketAddr {
    match peer.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().expect("address"),
        IpAddr::V6(_) => "[::]:0".parse().expect("address"),
    }
}

fn millis(arg: Option<&&str>, default: u64) -> Duration {
    Duration::from_millis(arg.and_then(|v| v.parse().ok()).unwrap_or(default))
}

fn tcp(to: SocketAddr, timeout: Duration) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&to, timeout)?;
    let peer = stream.peer_addr()?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).unwrap_or(0);
    let data = String::from_utf8_lossy(buf.get(..n).unwrap_or_default())
        .trim()
        .to_owned();
    Ok(format!("peer={peer} data={data}"))
}

/// A raw socket of our own, so the bind address and the errno of each step
/// are ours to choose and see.
fn raw_socket(family: i32, kind: i32, protocol: i32) -> std::io::Result<OwnedFd> {
    // SAFETY: socket takes no pointers.
    let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: socket just returned this descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sockaddr(to: SocketAddr) -> socket2_lite::Addr {
    socket2_lite::Addr::from(to)
}

/// The two sockaddr layouts, without another dependency.
mod socket2_lite {
    use std::net::SocketAddr;

    pub union Addr {
        pub v4: libc::sockaddr_in,
        pub v6: libc::sockaddr_in6,
    }

    impl Addr {
        pub fn from(a: SocketAddr) -> Self {
            match a {
                SocketAddr::V4(a) => Self {
                    v4: libc::sockaddr_in {
                        sin_family: libc::sa_family_t::try_from(libc::AF_INET).expect("family"),
                        sin_port: a.port().to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(a.ip().octets()),
                        },
                        sin_zero: [0; 8],
                    },
                },
                SocketAddr::V6(a) => Self {
                    v6: libc::sockaddr_in6 {
                        sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).expect("family"),
                        sin6_port: a.port().to_be(),
                        sin6_flowinfo: 0,
                        sin6_addr: libc::in6_addr {
                            s6_addr: a.ip().octets(),
                        },
                        sin6_scope_id: a.scope_id(),
                    },
                },
            }
        }

        pub fn len(a: &SocketAddr) -> libc::socklen_t {
            let size = match a {
                SocketAddr::V4(_) => size_of::<libc::sockaddr_in>(),
                SocketAddr::V6(_) => size_of::<libc::sockaddr_in6>(),
            };
            libc::socklen_t::try_from(size).expect("sockaddr size")
        }

        pub const fn as_ptr(&self) -> *const libc::sockaddr {
            std::ptr::from_ref(self).cast()
        }
    }
}

fn family_of(a: &SocketAddr) -> i32 {
    if a.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    }
}

fn check(ret: isize) -> std::io::Result<usize> {
    usize::try_from(ret).map_err(|_e| std::io::Error::last_os_error())
}

fn check_int(ret: libc::c_int) -> std::io::Result<()> {
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn timeval(d: Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: libc::time_t::try_from(d.as_secs()).expect("seconds"),
        tv_usec: libc::suseconds_t::from(d.subsec_micros()),
    }
}

fn timeval_len() -> libc::socklen_t {
    libc::socklen_t::try_from(size_of::<libc::timeval>()).expect("size of timeval")
}

/// Sets a send or receive timeout on a socket.
fn set_timeout(sock: &OwnedFd, option: libc::c_int, d: Duration) -> std::io::Result<()> {
    let tv = timeval(d);
    // SAFETY: tv is a valid timeval of the length passed.
    let set = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&raw const tv).cast(),
            timeval_len(),
        )
    };
    check_int(set)
}

/// An ICMP echo through an unprivileged ping socket.
fn ping(to: IpAddr, wait: Duration) -> std::io::Result<String> {
    let dest = SocketAddr::new(to, 0);
    let (protocol, echo) = if to.is_ipv4() {
        (libc::IPPROTO_ICMP, 8u8)
    } else {
        (libc::IPPROTO_ICMPV6, 128u8)
    };
    let sock = raw_socket(family_of(&dest), libc::SOCK_DGRAM, protocol)?;
    let packet = [echo, 0, 0, 0, 0, 0, 0, 1, b'b', b'o', b'x'];
    let sa = sockaddr(dest);
    // SAFETY: packet and sa are valid for the lengths passed.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            sa.as_ptr(),
            socket2_lite::Addr::len(&dest),
        )
    };
    check(sent)?;
    set_timeout(&sock, libc::SO_RCVTIMEO, wait)?;
    let mut buf = [0u8; 64];
    // SAFETY: buf is writable for its length.
    let got = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    check(got)?;
    Ok(format!("type={}", buf.first().copied().unwrap_or(255)))
}

fn bind(kind: &str, at: SocketAddr) -> std::io::Result<String> {
    let port = if kind == "tcp" {
        TcpListener::bind(at)?.local_addr()?.port()
    } else {
        UdpSocket::bind(at)?.local_addr()?.port()
    };
    Ok(format!("port={port}"))
}

/// TCP connect from a chosen local address.
fn tcp_from(src: IpAddr, to: SocketAddr, timeout: Duration) -> std::io::Result<String> {
    let sock = raw_socket(family_of(&to), libc::SOCK_STREAM, 0)?;
    let local = SocketAddr::new(src, 0);
    let sa = sockaddr(local);
    // SAFETY: sa is valid for the length passed.
    let bound = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            sa.as_ptr(),
            socket2_lite::Addr::len(&local),
        )
    };
    check_int(bound)?;
    // A send timeout bounds a blocking connect.
    set_timeout(&sock, libc::SO_SNDTIMEO, timeout)?;
    let sa = sockaddr(to);
    // SAFETY: sa is valid for the length passed.
    let connected =
        unsafe { libc::connect(sock.as_raw_fd(), sa.as_ptr(), socket2_lite::Addr::len(&to)) };
    if connected < 0 {
        let e = std::io::Error::last_os_error();
        // A connect that ran into its send timeout reports EINPROGRESS.
        if e.raw_os_error() == Some(libc::EINPROGRESS) {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        return Err(e);
    }
    Ok("connected".to_owned())
}

/// The query of `dns`: one A question for `box.test`.
const QUERY: [u8; 26] =
    *b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03box\x04test\x00\x00\x01\x00\x01";

/// One DNS query over UDP on an unconnected socket, or over TCP. Reports
/// who the answer came from and the address in it.
fn dns(server: SocketAddr, over_tcp: bool) -> std::io::Result<String> {
    let mut buf = [0u8; 512];
    let (n, from) = if over_tcp {
        let mut stream = TcpStream::connect_timeout(&server, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(&[0, 26])?;
        stream.write_all(&QUERY)?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?;
        let n = usize::from(u16::from_be_bytes(len));
        stream.read_exact(buf.get_mut(..n).ok_or(std::io::ErrorKind::InvalidData)?)?;
        (n, stream.peer_addr()?)
    } else {
        let sock = UdpSocket::bind(unspecified(&server))?;
        sock.set_read_timeout(Some(Duration::from_secs(2)))?;
        sock.send_to(&QUERY, server)?;
        sock.recv_from(&mut buf)?
    };
    let answer = buf
        .get(..n)
        .and_then(|r| r.last_chunk::<4>())
        .map(|a| IpAddr::from(*a));
    Ok(format!(
        "from={from} answer={}",
        answer.map_or_else(|| "-".to_owned(), |a| a.to_string())
    ))
}

fn hold_udp(to: SocketAddr) {
    let sock = UdpSocket::bind(unspecified(&to)).and_then(|s| s.connect(to).map(|()| s));
    let Ok(sock) = sock else {
        say("ready err setup");
        return;
    };
    say(&format!(
        "ready {}",
        report(sock.send(b"x").map(|_| String::new()))
    ));
    while wait_step() {
        say(&report(sock.send(b"x").map(|_| String::new())));
    }
}

fn serve_tcp(at: SocketAddr) {
    let listener = TcpListener::bind(at).expect("bind");
    say("ready");
    for mut stream in listener.incoming().flatten() {
        // The client may have given up already.
        let _sent = stream.write_all(b"hello\n");
    }
}

fn serve_udp(at: SocketAddr) {
    let sock = UdpSocket::bind(at).expect("bind");
    say("ready");
    let mut buf = [0u8; 64];
    while let Ok((_, peer)) = sock.recv_from(&mut buf) {
        let _sent = sock.send_to(b"pong", peer);
    }
}

fn loader_request(socket: &str, boxes: &str) -> String {
    let dir: OwnedFd = std::fs::File::open(boxes).expect("open boxes").into();
    match boxbpf::loader::request(Path::new(socket), dir.as_fd()) {
        Ok(_) => "ok handles".to_owned(),
        Err(e) => format!("err {e}"),
    }
}

pub fn run() {
    let spec = std::env::var("BOXBPF_TEST_PROBE").expect("probe action");
    let args: Vec<&str> = spec.split(' ').collect();
    let result = match args.as_slice() {
        ["tcp", ip, port, rest @ ..] => report(tcp(addr(ip, port), millis(rest.first(), 2000))),
        ["tcp-from", src, ip, port, rest @ ..] => report(tcp_from(
            src.parse().expect("address"),
            addr(ip, port),
            millis(rest.first(), 1500),
        )),
        ["udp", ip, port, rest @ ..] => {
            let to = addr(ip, port);
            let wait = millis(rest.first(), 0);
            report(UdpSocket::bind(unspecified(&to)).and_then(|sock| {
                sock.send_to(b"ping", to)?;
                if wait.is_zero() {
                    return Ok(String::new());
                }
                sock.set_read_timeout(Some(wait))?;
                let mut buf = [0u8; 64];
                let (_, from) = sock.recv_from(&mut buf)?;
                Ok(format!("from={from}"))
            }))
        }
        ["udp-connect", ip, port] => {
            let to = addr(ip, port);
            report(UdpSocket::bind(unspecified(&to)).and_then(|sock| {
                sock.connect(to)?;
                sock.send(b"x")?;
                Ok(format!("peer={}", sock.peer_addr()?))
            }))
        }
        ["ping", ip, rest @ ..] => report(ping(
            ip.parse().expect("address"),
            millis(rest.first(), 1000),
        )),
        ["sock", family, kind, protocol] => {
            let n = |s: &str| s.parse::<i32>().expect("number");
            report(raw_socket(n(family), n(kind), n(protocol)).map(|_| String::new()))
        }
        ["bind", kind, ip, port] => report(bind(kind, addr(ip, port))),
        ["dns", ip, rest @ ..] => report(dns(addr(ip, "53"), rest.first() == Some(&"tcp"))),
        ["hold-udp", ip, port] => return hold_udp(addr(ip, port)),
        ["serve-tcp", ip, port] => return serve_tcp(addr(ip, port)),
        ["serve-udp", ip, port] => return serve_udp(addr(ip, port)),
        ["loader-request", socket, boxes] => loader_request(socket, boxes),
        _ => format!("err unknown-probe {spec}"),
    };
    say(&result);
}
