//! The policy engine under the real daemon: boxes started through the CLI,
//! probed from inside.
//!
//! These tests run as the invoking user, like the daemon does. They start
//! the daemon binary, which puts itself in a delegated scope, and a root
//! loader through `sudo -n`. They need: `MINIMALD_NETNS_TEST=1`,
//! passwordless sudo, a systemd user session, the `min` binary beside the
//! `minimald` binary (`cargo build -p minimal`), and packages for a box,
//! from the cache in `MINIMALD_TEST_CACHE_DIR` or from the network.
//! `just test-root-integration` sets all of that up.

use std::{
    io::{Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Metadata, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};

const GATE: &str = "MINIMALD_NETNS_TEST";
/// Addresses the tests put on loopback: public-looking ones, which the
/// resolver's rebinding filter lets a name resolve to.
const PUBLIC4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const WILD4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
const PUBLIC6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
/// The addresses of the test of a box with its own address. Tests run at
/// the same time and each removes its addresses when it ends.
const OWN_OPEN4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 17);
const OWN_NAMED4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 18);
const REFUSED: &str = "Operation not permitted";

fn gated(test: &str) -> bool {
    if std::env::var_os(GATE).is_some() {
        return true;
    }
    eprintln!("skipping {test}: {GATE} is not set (it needs sudo -n, systemd and the min binary)");
    false
}

fn minimald() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_minimald"))
}

fn min_binary() -> PathBuf {
    let min = minimald().with_file_name("min");
    assert!(
        min.exists(),
        "{} is missing: build it with `cargo build -p minimal`",
        min.display()
    );
    min
}

fn sudo(args: &[&str]) -> bool {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for(what: &str, limit: Duration, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Loopback addresses for the test, removed again when it ends.
struct LoopbackAddrs(Vec<String>);

impl LoopbackAddrs {
    fn add(addrs: &[IpAddr]) -> Self {
        let addrs: Vec<String> = addrs
            .iter()
            .map(|addr| format!("{addr}/{}", if addr.is_ipv4() { 32 } else { 128 }))
            .collect();
        for addr in &addrs {
            // Left over from a run that was killed: fine.
            let _exists = sudo(&["ip", "addr", "add", addr, "dev", "lo", "nodad"]);
        }
        Self(addrs)
    }
}

impl Drop for LoopbackAddrs {
    fn drop(&mut self) {
        for addr in &self.0 {
            let _gone = sudo(&["ip", "addr", "del", addr, "dev", "lo"]);
        }
    }
}

/// A TCP listener that says `hello` and a UDP socket that takes anything,
/// on one port of `addr`.
fn target(addr: IpAddr) -> u16 {
    let listener = TcpListener::bind(SocketAddr::new(addr, 0)).expect("bind a target");
    let port = listener.local_addr().expect("address").port();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _sent = stream.write_all(b"hello\n");
        }
    });
    port
}

fn targets(addrs: &[IpAddr], port_of: IpAddr) -> u16 {
    // One port number on every address keeps the probes simple.
    loop {
        let port = target(port_of);
        let rest: Vec<_> = addrs
            .iter()
            .filter(|a| **a != port_of)
            .map(|a| TcpListener::bind(SocketAddr::new(*a, port)))
            .collect();
        if rest.iter().all(Result::is_ok) {
            for listener in rest.into_iter().flatten() {
                std::thread::spawn(move || {
                    for mut stream in listener.incoming().flatten() {
                        let _sent = stream.write_all(b"hello\n");
                    }
                });
            }
            return port;
        }
    }
}

/// The resolver the daemon forwards to, with the names the tests use.
/// Records every name it was asked for.
struct Upstream {
    at: SocketAddr,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn answer(query: &[u8], asked: &Mutex<Vec<String>>) -> Option<Vec<u8>> {
        let message = Message::from_vec(query).ok()?;
        let question = message.queries.first()?.clone();
        let name = question.name().to_lowercase().to_string();
        let name = name.trim_end_matches('.').to_owned();
        asked.lock().expect("lock").push(name.clone());
        let records: Vec<RData> = match (name.as_str(), question.query_type()) {
            ("allowed.test", RecordType::A) => vec![RData::A(A(PUBLIC4))],
            ("allowed.test", RecordType::AAAA) => vec![RData::AAAA(AAAA(PUBLIC6))],
            ("a.wild.test", RecordType::A) => vec![RData::A(A(WILD4))],
            ("own.open.test", RecordType::A) => vec![RData::A(A(OWN_OPEN4))],
            ("own.named.test", RecordType::A) => vec![RData::A(A(OWN_NAMED4))],
            // A listed name that points at a private address.
            ("rebind.test", RecordType::A) => vec![RData::A(A(Ipv4Addr::new(127, 0, 0, 2)))],
            _ => Vec::new(),
        };
        let known = matches!(
            name.as_str(),
            "allowed.test" | "a.wild.test" | "rebind.test" | "own.open.test" | "own.named.test"
        );
        let mut reply = Message::response(message.metadata.id, message.metadata.op_code);
        reply.metadata = Metadata::response_from_request(&message.metadata);
        reply.metadata.recursion_available = true;
        reply.metadata.response_code = if known {
            ResponseCode::NoError
        } else {
            ResponseCode::NXDomain
        };
        reply.add_query(question.clone());
        for data in records {
            reply.add_answer(Record::from_rdata(question.name().clone(), 60, data));
        }
        reply.to_vec().ok()
    }

    fn start() -> Self {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind the upstream resolver");
        let at = udp.local_addr().expect("address");
        let tcp = TcpListener::bind(at).expect("bind the upstream resolver (TCP)");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&asked);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = udp.recv_from(&mut buf) {
                if let Some(reply) = Self::answer(buf.get(..n).unwrap_or_default(), &seen) {
                    let _sent = udp.send_to(&reply, peer);
                }
            }
        });
        let seen = Arc::clone(&asked);
        std::thread::spawn(move || {
            for mut stream in tcp.incoming().flatten() {
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
                if stream.read_exact(&mut query).is_err() {
                    continue;
                }
                if let Some(reply) = Self::answer(&query, &seen) {
                    let len = u16::try_from(reply.len()).expect("length").to_be_bytes();
                    let _sent = stream
                        .write_all(&len)
                        .and_then(|()| stream.write_all(&reply));
                }
            }
        });
        Self { at, asked }
    }

    fn asked(&self, name: &str) -> bool {
        self.asked.lock().expect("lock").iter().any(|n| n == name)
    }
}

/// The root loader, started through sudo for this test.
struct Loader {
    socket: PathBuf,
    _child: Child,
}

impl Loader {
    fn start(dir: &Path) -> Self {
        let socket = dir.join("loader.sock");
        let uid = nix::unistd::getuid().as_raw().to_string();
        let child = Command::new("sudo")
            .arg("-n")
            .arg(minimald())
            .args(["__policy-loader", "--listen"])
            .arg(&socket)
            .args(["--owner", &uid])
            .stdin(Stdio::null())
            .spawn()
            .expect("start the loader through sudo -n: these tests need passwordless sudo");
        wait_for("the loader socket", Duration::from_secs(10), || {
            socket.exists()
        });
        Self {
            socket,
            _child: child,
        }
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        // The loader runs as root, so only root can end it.
        let pattern = format!("__policy-loader --listen {}", self.socket.display());
        let _ended = sudo(&["pkill", "-f", &pattern]);
    }
}

/// A daemon with its own state directory, and the CLI pointed at it.
struct Daemon {
    state: PathBuf,
    project: PathBuf,
    child: Child,
}

impl Daemon {
    fn start(dir: &Path, loader_socket: &Path, upstream: Option<SocketAddr>) -> Self {
        let state = dir.join("state");
        let project = dir.join("project");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::create_dir_all(&project).expect("project dir");
        std::fs::write(
            project.join("minimal.toml"),
            "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\nbranch = \"main\"\n\
             locked_commit = \"1419729941fd3b67cec371b4064daafff0e69c7a\"\n\n\
             [defaults]\nstate_key = \"dev\"\n\n[session]\npackages = [\"base\", \"vim\", \"git\"]\n",
        )
        .expect("project file");
        let cache = std::env::var_os("MINIMALD_TEST_CACHE_DIR")
            .map_or_else(|| dir.join("cache"), PathBuf::from);
        let log = std::fs::File::create(dir.join("minimald.log")).expect("log file");
        let mut command = Command::new(minimald());
        command
            .arg("--minimal-state-dir")
            .arg(&state)
            .arg("--minimal-cache-dir")
            .arg(&cache)
            .args(["run", "--instance-num", "0"])
            .env("MINIMALD_POLICY_LOADER_SOCKET", loader_socket)
            // The user's own host exposures are not the test's.
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("log file"))
            .stderr(log);
        if let Some(gvproxy) = std::env::var_os("GVPROXY_BIN") {
            command.arg("--gvproxy-bin").arg(gvproxy);
        }
        if let Some(upstream) = upstream {
            command.env("MINIMALD_UPSTREAM_DNS", upstream.to_string());
        }
        let child = command.spawn().expect("start minimald");
        let socket = state.join("providers/local-minimald0/ssh.sock");
        wait_for("the daemon's socket", Duration::from_secs(30), || {
            socket.exists()
        });
        Self {
            state,
            project,
            child,
        }
    }

    fn min(&self, args: &[&str]) -> String {
        let out = Command::new(min_binary())
            .arg("--minimal-dir")
            .arg(&self.state)
            .arg("--no-input")
            .args(args)
            .current_dir(&self.project)
            .stdin(Stdio::null())
            .output()
            .expect("run min");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Activates a session box with the given network flags.
    fn activate(&self, name: &str, flags: &[&str]) -> String {
        let mut args = vec!["session", "activate", "--name", name];
        args.extend_from_slice(flags);
        args.push(".");
        self.min(&args)
    }

    /// Runs a bash script in the box and returns what it printed.
    fn exec(&self, name: &str, script: &str) -> String {
        self.min(&["box", "exec", name, "--", "bash", "-c", script])
    }

    /// Opens a TCP connection from the box. The result names the outcome
    /// the way bash does: `ok`, or the error text.
    fn connect(&self, name: &str, host: &str, port: u16) -> String {
        self.exec(
            name,
            &format!("exec 3<>/dev/tcp/{host}/{port} && echo ok; true"),
        )
    }

    /// Opens a TCP connection from the box and returns the line the other
    /// side greets with, or nothing.
    fn greeting(&self, name: &str, host: &str, port: u16) -> String {
        self.exec(
            name,
            &format!(
                "exec 3<>/dev/tcp/{host}/{port} && read -t 5 line <&3 && echo \"$line\"; true"
            ),
        )
    }

    /// Writes the user's host exposures table with this one port in it.
    fn expose_host_port(&self, port: u16) {
        let dir = self.state.with_file_name("config").join("minimal");
        std::fs::create_dir_all(&dir).expect("config dir");
        std::fs::write(
            dir.join("config.toml"),
            format!("[host-exposures]\ntarget = {{ port = {port} }}\n"),
        )
        .expect("config file");
    }

    /// Starts a command in the box that runs until its client is ended.
    fn run_in(&self, name: &str, argv: &[&str]) -> Running {
        let child = Command::new(min_binary())
            .arg("--minimal-dir")
            .arg(&self.state)
            .args(["--no-input", "box", "exec", name, "--"])
            .args(argv)
            .current_dir(&self.project)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("run min");
        Running(child)
    }

    /// The loopback address the host reaches the box's published ports at.
    fn published_address(&self, name: &str) -> Ipv4Addr {
        let listing = self.min(&["ls"]);
        listing
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace().skip(1);
                (words.next() == Some(name)).then(|| words.next())?
            })
            .find_map(|word| word.parse().ok())
            .unwrap_or_else(|| panic!("no published address for {name} in:\n{listing}"))
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.state.with_file_name("minimald.log")).unwrap_or_default()
    }

    /// The port the daemon's hostname proxy listens on: its default, or
    /// another when a second daemon on this host holds that.
    fn proxy_port(&self) -> u16 {
        let log = self.log();
        let line = log
            .lines()
            .find(|l| l.contains("hostname proxy is serving"))
            .expect("the proxy's serving line");
        // The log colours its fields: drop the escape sequences first.
        let mut plain = String::new();
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for skipped in chars.by_ref() {
                    if skipped.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain
            .split_whitespace()
            .find_map(|word| word.strip_prefix("port="))
            .and_then(|port| port.parse().ok())
            .unwrap_or_else(|| panic!("no port in {plain}"))
    }

    /// The daemon's cgroup root on disk.
    fn cgroup_root(&self) -> PathBuf {
        let text = std::fs::read_to_string(format!("/proc/{}/cgroup", self.child.id()))
            .expect("the daemon's cgroup");
        let own = text
            .lines()
            .find_map(|l| l.strip_prefix("0::/"))
            .expect("cgroup v2 membership");
        Path::new("/sys/fs/cgroup")
            .join(own.trim_end_matches("/supervisor"))
            .clone()
    }
}

/// A command running in a box. Ending its client ends it.
struct Running(Child);

impl Running {
    fn end(mut self) {
        self.signal();
        let _reaped = self.0.wait();
    }

    fn signal(&self) {
        let _signalled = Command::new("kill").arg(self.0.id().to_string()).status();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.signal();
    }
}

/// Whether a connection to `at` is accepted and then kept. A forward whose
/// box end refuses is accepted too, and closed at once.
fn stays_open(at: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&at, Duration::from_secs(2)) else {
        return false;
    };
    let _set = stream.set_read_timeout(Some(Duration::from_millis(500)));
    matches!(
        stream.read(&mut [0u8; 1]),
        Err(error) if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    )
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _signalled = Command::new("kill")
            .arg(self.child.id().to_string())
            .status();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

#[test]
#[ignore = "needs MINIMALD_NETNS_TEST=1, sudo -n and systemd (just test-root-integration)"]
fn a_box_s_policy_decides_what_it_reaches_for_both_families() {
    if !gated("a_box_s_policy_decides_what_it_reaches_for_both_families") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let v4 = |a: Ipv4Addr| IpAddr::V4(a);
    let _addrs = LoopbackAddrs::add(&[v4(PUBLIC4), v4(WILD4), IpAddr::V6(PUBLIC6)]);
    let loader = Loader::start(dir.path());
    let upstream = Upstream::start();
    let port = targets(
        &[
            v4(Ipv4Addr::LOCALHOST),
            v4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            v4(PUBLIC4),
            v4(WILD4),
            IpAddr::V6(PUBLIC6),
        ],
        v4(Ipv4Addr::LOCALHOST),
    );
    let daemon = Daemon::start(dir.path(), &loader.socket, Some(upstream.at));
    assert!(
        daemon
            .log()
            .contains("the network policy engine is attached"),
        "{}",
        daemon.log()
    );

    // A box that allows everything, first: it also fills the package
    // cache the restricted boxes cannot fill themselves.
    let out = daemon.activate("open", &["--network", "host_ip"]);
    for host in ["127.0.0.1", "127.0.0.2", "::1"] {
        assert_eq!(daemon.connect("open", host, port).trim(), "ok", "{out}");
    }

    // Subnets, both families.
    daemon.activate(
        "sub",
        &[
            "--network",
            "host_ip",
            "--allow-subnets",
            "127.0.0.1/32",
            "--allow-subnets",
            "::1/128",
        ],
    );
    assert_eq!(daemon.connect("sub", "127.0.0.1", port).trim(), "ok");
    assert_eq!(daemon.connect("sub", "::1", port).trim(), "ok");
    assert!(daemon.connect("sub", "127.0.0.2", port).contains(REFUSED));
    let udp = daemon.exec("sub", "echo x > /dev/udp/127.0.0.2/9; true");
    assert!(udp.contains(REFUSED), "{udp}");

    daemon.activate(
        "other",
        &["--network", "host_ip", "--allow-subnets", "127.0.0.2/32"],
    );
    assert_eq!(daemon.connect("other", "127.0.0.2", port).trim(), "ok");
    assert!(daemon.connect("other", "127.0.0.1", port).contains(REFUSED));
    assert!(daemon.connect("other", "::1", port).contains(REFUSED));

    // Names: refused before a lookup, admitted after, for both families.
    daemon.activate(
        "names",
        &[
            "--network",
            "host_ip",
            "--allow-dns-hosts",
            "allowed.test",
            "--allow-dns-hosts",
            "a.wild.test",
            "--allow-dns-hosts",
            "rebind.test",
            "--allow-dns-hosts",
            "host.min.internal",
        ],
    );
    let (public4, public6) = (PUBLIC4.to_string(), PUBLIC6.to_string());
    let before = daemon.connect("names", &public4, port);
    assert!(before.contains(REFUSED), "{before}");
    assert!(daemon.connect("names", &public6, port).contains(REFUSED));
    assert_eq!(daemon.connect("names", "allowed.test", port).trim(), "ok");
    assert_eq!(daemon.connect("names", &public4, port).trim(), "ok");
    assert_eq!(daemon.connect("names", &public6, port).trim(), "ok");
    // The box's resolver file names its own endpoint, and the query went
    // through the daemon to the resolver the daemon was given.
    let resolv = daemon.exec("names", "cat /etc/resolv.conf");
    assert!(resolv.contains("nameserver 127.0.80.1"), "{resolv}");
    assert!(upstream.asked("allowed.test"));
    // A name the box does not list never leaves the daemon.
    let other = daemon.exec("names", "getent hosts other.test; echo rc=$?");
    assert!(other.contains("rc=2"), "{other}");
    assert!(!upstream.asked("other.test"));
    // A second listed name has its own addresses admitted.
    assert_eq!(daemon.connect("names", "a.wild.test", port).trim(), "ok");
    let apex = daemon.exec("names", "getent hosts wild.test; echo rc=$?");
    assert!(apex.contains("rc=2"), "{apex}");
    // A listed name that resolves to a private address is not admitted.
    let rebind = daemon.connect("names", "rebind.test", port);
    assert_ne!(rebind.trim(), "ok", "{rebind}");
    assert!(daemon.connect("names", "127.0.0.2", port).contains(REFUSED));
    // The host's name is the alias, in the hosts file and from the
    // resolver. Listing it does not open the host's loopback. The alias
    // leads to the host relay, which dials a port only once the user has
    // exposed it.
    let named = daemon.exec("names", "getent hosts host.min.internal");
    assert!(named.contains("100.64.255.254"), "{named}");
    assert!(daemon.connect("names", "127.0.0.1", port).contains(REFUSED));
    let closed = daemon.greeting("names", "host.min.internal", port);
    assert!(!closed.contains("hello"), "{closed}");
    daemon.expose_host_port(port);
    let exposed = daemon.greeting("names", "host.min.internal", port);
    assert_eq!(exposed.trim(), "hello");
    let other = daemon.greeting("names", "host.min.internal", port.wrapping_add(1));
    assert!(!other.contains("hello"), "{other}");

    // Refusals are box events, each with its source.
    wait_for("the refusal events", Duration::from_secs(10), || {
        let events = daemon.min(&["box", "events", "names"]);
        events.contains("name_not_allowed") && events.contains("rebinding")
    });
    let events = daemon.min(&["box", "events", "names"]);
    let refused: Vec<&str> = events
        .lines()
        .filter(|l| l.contains("net_refused"))
        .collect();
    assert!(
        refused
            .iter()
            .any(|l| l.contains("\"source\":\"kernel\"") && l.contains(&public4)),
        "{events}"
    );
    assert!(
        refused
            .iter()
            .any(|l| l.contains("\"source\":\"resolver\"") && l.contains("other.test")),
        "{events}"
    );

    // A burst of refusals stays a bounded number of events.
    daemon.exec(
        "sub",
        "for p in $(seq 1000 1200); do exec 3<>/dev/tcp/127.0.0.2/$p; done 2>/dev/null; true",
    );
    std::thread::sleep(Duration::from_secs(1));
    let burst = daemon.min(&["box", "events", "sub"]);
    let count = burst.lines().filter(|l| l.contains("net_refused")).count();
    assert!(count > 0 && count <= 45, "{count} events:\n{burst}");

    // An endpoint serves its box only: a process outside every box gets
    // no answer from any resolver endpoint, and no proxy endpoint talks
    // to it.
    let outside = UdpSocket::bind("127.0.0.1:0").expect("bind");
    outside
        .set_read_timeout(Some(Duration::from_millis(150)))
        .expect("timeout");
    let mut query = Message::query();
    query.add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_utf8("allowed.test.").expect("name"),
        RecordType::A,
    ));
    let query = query.to_vec().expect("encode");
    let mut bound = 0;
    for block in 0..32_u16 {
        let resolver = SocketAddr::from(([127, 0, 80, 1], 20480 + block * 4));
        if UdpSocket::bind(resolver).is_ok() {
            continue;
        }
        bound += 1;
        outside.send_to(&query, resolver).expect("send");
        let mut buf = [0u8; 512];
        assert!(
            outside.recv_from(&mut buf).is_err(),
            "the resolver endpoint at {resolver} answered a process outside its box"
        );
        let proxy = SocketAddr::from(([127, 0, 80, 1], 20481 + block * 4));
        if let Ok(mut stream) = std::net::TcpStream::connect(proxy) {
            let _sent = stream.write_all(b"GET / HTTP/1.1\r\nHost: open.min.internal\r\n\r\n");
            let mut reply = Vec::new();
            let _closed = stream.read_to_end(&mut reply);
            assert!(reply.is_empty(), "the proxy endpoint at {proxy} answered");
        }
    }
    assert!(bound >= 3, "found {bound} resolver endpoints");
    // And a box reaches its own endpoints and no other box's.
    let reach = daemon.exec(
        "sub",
        "n=0; for b in $(seq 0 31); do p=$((20480 + b * 4)); \
         (echo x > /dev/udp/127.0.80.1/$p) 2>/dev/null && n=$((n + 1)); done; echo reached=$n",
    );
    assert!(reach.contains("reached=1"), "{reach}");

    // The hostname proxy judges a box's request by the box's policy,
    // also when the box dials the node's shared listener.
    let proxy = daemon.proxy_port();
    let request = |name: &str, host: &str| {
        daemon.exec(
            name,
            &format!(
                "exec 3<>/dev/tcp/127.0.0.1/{proxy} && printf 'GET / HTTP/1.1\\r\\nHost: {host}\\r\\n\
                 Connection: close\\r\\n\\r\\n' >&3 && head -c 64 <&3 | head -1; true"
            ),
        )
    };
    let denied = request("names", "open.min.internal:8099");
    assert!(denied.contains("403"), "{denied}");
    wait_for("the proxy's refusal event", Duration::from_secs(10), || {
        daemon
            .min(&["box", "events", "names"])
            .contains("hostname_proxy")
    });

    // A box with no network runs, and has none.
    daemon.activate("alone", &["--network", "none"]);
    assert_ne!(daemon.connect("alone", "127.0.0.1", port).trim(), "ok");
    // Its namespace lets the box's own group open ping sockets.
    let ping = daemon.exec("alone", "cat /proc/sys/net/ipv4/ping_group_range");
    assert_eq!(
        ping.split_whitespace().collect::<Vec<_>>(),
        ["1000", "1000"]
    );

    // Stopping a box removes its cgroup and its entry: a box of the same
    // name starts clean afterwards.
    let boxes = daemon.cgroup_root().join("boxes");
    let before = std::fs::read_dir(&boxes).expect("boxes").count();
    daemon.min(&["box", "stop", "--force", "other"]);
    wait_for("the box's cgroup to go", Duration::from_secs(15), || {
        std::fs::read_dir(&boxes).is_ok_and(|d| d.count() < before)
    });
}

#[test]
#[ignore = "needs MINIMALD_NETNS_TEST=1, sudo -n and systemd (just test-root-integration)"]
fn a_box_with_its_own_address_is_judged_published_and_named() {
    if !gated("a_box_with_its_own_address_is_judged_published_and_named") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let v4 = |a: Ipv4Addr| IpAddr::V4(a);
    let _addrs = LoopbackAddrs::add(&[v4(OWN_OPEN4), v4(OWN_NAMED4)]);
    let loader = Loader::start(dir.path());
    let upstream = Upstream::start();
    // The virtual network dials these from the host, where they are local.
    let port = targets(&[v4(OWN_OPEN4), v4(OWN_NAMED4)], v4(OWN_OPEN4));
    let daemon = Daemon::start(dir.path(), &loader.socket, Some(upstream.at));

    // Fills the package cache, which a restricted box cannot.
    daemon.activate("open", &["--network", "host_ip"]);

    let subnet = format!("{OWN_OPEN4}/32");
    let out = daemon.activate(
        "web",
        &[
            "--network",
            "own_ip",
            "--allow-subnets",
            &subnet,
            "--allow-dns-hosts",
            "own.named.test",
            "--ingress",
            "18080:8080",
            "--dynamic-ingress",
            "allow",
            "--dynamic-range",
            "3000-3010",
        ],
    );

    // Egress: the listed subnet, then the listed name, and nothing else.
    let public = OWN_OPEN4.to_string();
    let named = OWN_NAMED4.to_string();
    assert_eq!(daemon.connect("web", &public, port).trim(), "ok", "{out}");
    let refused = daemon.connect("web", &named, port);
    assert!(refused.contains(REFUSED), "{refused}");
    assert_eq!(daemon.connect("web", "own.named.test", port).trim(), "ok");
    let unlisted = daemon.connect("web", "own.open.test", port);
    assert_ne!(unlisted.trim(), "ok", "{unlisted}");
    let events = daemon.min(&["box", "events", "web"]);
    assert!(events.contains("net_refused"), "{events}");
    assert!(events.contains("name_not_allowed"), "{events}");

    // Ingress: the declared port, a port the box listens on inside the
    // range, and not a loopback listener or a port nobody published.
    let declared = daemon.run_in(
        "web",
        &[
            "git",
            "daemon",
            "--listen=0.0.0.0",
            "--port=8080",
            "--base-path=/tmp",
        ],
    );
    let listening = daemon.run_in(
        "web",
        &[
            "git",
            "daemon",
            "--listen=0.0.0.0",
            "--port=3005",
            "--base-path=/tmp",
        ],
    );
    let _loopback_only = daemon.run_in(
        "web",
        &[
            "git",
            "daemon",
            "--listen=127.0.0.1",
            "--port=3006",
            "--base-path=/tmp",
        ],
    );
    let published = daemon.published_address("web");
    let at = |port: u16| SocketAddr::new(IpAddr::V4(published), port);
    wait_for("the declared port", Duration::from_secs(20), || {
        stays_open(at(18080))
    });
    wait_for("the listening port", Duration::from_secs(20), || {
        stays_open(at(3005))
    });
    assert!(
        !stays_open(at(3006)),
        "a loopback listener is not published"
    );
    assert!(!stays_open(at(3999)), "nothing published this port");
    listening.end();
    wait_for("the withdrawal", Duration::from_secs(20), || {
        TcpStream::connect_timeout(&at(3005), Duration::from_secs(2)).is_err()
    });

    // A peer that lists the box by name is told its address on the
    // virtual network and reaches the port it declared. It has no other
    // egress.
    daemon.activate(
        "peer",
        &[
            "--network",
            "own_ip",
            "--allow-dns-hosts",
            "web.min.internal",
        ],
    );
    let told = daemon.exec("peer", "getent hosts web.min.internal; true");
    assert!(told.contains("100.64."), "{told}");
    assert_eq!(
        daemon.connect("peer", "web.min.internal", 8080).trim(),
        "ok"
    );
    let refused = daemon.connect("peer", &public, port);
    assert!(refused.contains(REFUSED), "{refused}");
    drop(declared);
}

#[test]
#[ignore = "needs MINIMALD_NETNS_TEST=1, sudo -n and systemd (just test-root-integration)"]
fn without_a_loader_only_boxes_that_need_no_enforcement_start() {
    if !gated("without_a_loader_only_boxes_that_need_no_enforcement_start") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let port = target(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let daemon = Daemon::start(dir.path(), &dir.path().join("no-loader.sock"), None);
    let log = daemon.log();
    assert!(log.contains("no network policy engine"), "{log}");
    assert!(log.contains("min finalize-install"), "{log}");

    daemon.activate("open", &["--network", "host_ip"]);
    assert_eq!(daemon.connect("open", "127.0.0.1", port).trim(), "ok");

    let activation = daemon.activate(
        "sub",
        &["--network", "host_ip", "--allow-subnets", "127.0.0.1/32"],
    );
    let exec = daemon.connect("sub", "127.0.0.1", port);
    let said = format!("{activation}{exec}");
    assert_ne!(exec.trim(), "ok", "{said}");
    assert!(said.contains("min finalize-install"), "{said}");
}

#[test]
#[ignore = "needs MINIMALD_NETNS_TEST=1, sudo -n and systemd (just test-root-integration)"]
fn a_loader_of_another_version_is_not_used() {
    use nix::sys::socket::{
        AddressFamily, Backlog, MsgFlags, SockFlag, SockType, UnixAddr, accept, bind, listen, recv,
        send, socket,
    };
    use std::os::fd::AsRawFd as _;

    if !gated("a_loader_of_another_version_is_not_used") {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    // A loader that claims other programs than this daemon carries.
    let path = dir.path().join("loader.sock");
    let listener = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("socket");
    bind(
        listener.as_raw_fd(),
        &UnixAddr::new(&path).expect("address"),
    )
    .expect("bind");
    listen(&listener, Backlog::new(1).expect("backlog")).expect("listen");
    std::thread::spawn(move || {
        while let Ok(conn) = accept(listener.as_raw_fd()) {
            let mut request = [0u8; 256];
            let _read = recv(conn, &mut request, MsgFlags::empty());
            let reply = format!(
                "err object mismatch: loader={} daemon=unread",
                "0".repeat(64)
            );
            let _sent = send(conn, reply.as_bytes(), MsgFlags::empty());
        }
    });
    let port = target(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let daemon = Daemon::start(dir.path(), &path, None);
    let log = daemon.log();
    assert!(log.contains("from another version"), "{log}");
    // The loader refuses another build before it loads anything, so the
    // daemon runs as one with no loader does: a box that allows everything
    // has its network, and one that needs enforcement is refused.
    daemon.activate("open", &["--network", "host_ip"]);
    assert_eq!(daemon.connect("open", "127.0.0.1", port).trim(), "ok");

    let activation = daemon.activate(
        "sub",
        &["--network", "host_ip", "--allow-subnets", "127.0.0.1/32"],
    );
    let exec = daemon.connect("sub", "127.0.0.1", port);
    let said = format!("{activation}{exec}");
    assert_ne!(exec.trim(), "ok", "{said}");
    assert!(said.contains("min finalize-install"), "{said}");
}
