//! Checks the engine against a guest kernel.
//!
//! This program is the `/init` of a bare initramfs. As PID 1 it does what
//! the guest daemon does: it loads and attaches the programs itself at the
//! real cgroup root's `boxes/`, installs box policies, and then compares
//! what the kernel does with what the evaluator says, flow by flow.
//!
//! It prints `PASS`/`FAIL` lines and a final `RESULT`, then powers the
//! machine off. `scripts/boxbpf-guest-kernel.sh` builds the initramfs and
//! boots it in QEMU.

#[cfg(target_os = "linux")]
mod guest {
    use std::{
        ffi::CString,
        fs,
        io::{Read, Write},
        net::{
            IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener,
            TcpStream, UdpSocket,
        },
        os::fd::AsFd,
        path::Path,
        time::Duration,
    };

    use boxbpf::{BoxId, Engine, Error, Handles, MapSizes};
    use netpol::{
        Direction, Endpoint, Flow, FlowVerdict, PortRange, Protocol, Protocols, Spec, Target,
        base::{Deployment, Mode, NodeKind, RESOLVER},
        compile::Options,
        policy::{BoxAction, BoxPolicy, BoxRule},
    };

    const CGROUP: &str = "/sys/fs/cgroup";
    /// What a refused system call returns: `EPERM`.
    const REFUSED: i32 = 1;
    const RESOLVER4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 77, 0, 1), 15353);
    const RESOLVER6: SocketAddrV6 = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 15353, 0, 0);

    fn mount(source: &str, target: &str, fstype: &str) {
        if fs::create_dir_all(target).is_err() {
            return;
        }
        let (Ok(s), Ok(t), Ok(f)) = (
            CString::new(source),
            CString::new(target),
            CString::new(fstype),
        ) else {
            return;
        };
        // SAFETY: three valid C strings and no data argument.
        let _mounted =
            unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), 0, std::ptr::null()) };
    }

    fn loopback_up() {
        // SAFETY: socket takes no pointers.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        // SAFETY: an all-zero ifreq is valid, and the name is filled in below.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in request.ifr_name.iter_mut().zip(c"lo".to_bytes_with_nul()) {
            *dst = libc::c_char::from_ne_bytes([*src]);
        }
        // SAFETY: request is a valid ifreq naming an interface.
        let _got =
            unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as libc::Ioctl, &raw mut request) };
        // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
        let flags = unsafe { request.ifr_ifru.ifru_flags };
        request.ifr_ifru.ifru_flags = flags | libc::c_short::try_from(libc::IFF_UP).unwrap_or(1);
        // SAFETY: request is a valid ifreq with the new flags.
        let _set =
            unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::Ioctl, &raw mut request) };
        // SAFETY: sock is ours and not used again.
        let _closed = unsafe { libc::close(sock) };
    }

    /// Gives the loopback interface a second address, outside 127.0.0.0/8:
    /// a source the engine does not let pass for being loopback.
    fn loopback_alias(addr: Ipv4Addr) {
        // SAFETY: socket takes no pointers.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        // SAFETY: an all-zero ifreq is valid, and name and address are
        // filled in below.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in request.ifr_name.iter_mut().zip(c"lo:1".to_bytes_with_nul()) {
            *dst = libc::c_char::from_ne_bytes([*src]);
        }
        let sin = libc::sockaddr_in {
            sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap_or(2),
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.octets()),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: sockaddr_in and sockaddr have the same size, and every
        // bit pattern is a valid sockaddr.
        request.ifr_ifru.ifru_addr =
            unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) };
        // SAFETY: request is a valid ifreq naming an interface and an address.
        let _set = unsafe { libc::ioctl(sock, libc::SIOCSIFADDR as libc::Ioctl, &raw mut request) };
        // SAFETY: sock is ours and not used again.
        let _closed = unsafe { libc::close(sock) };
    }

    /// One datagram from `from` to port 9 of the same address.
    fn udp_from(from: Ipv4Addr) -> String {
        match UdpSocket::bind((from, 0)).and_then(|s| s.send_to(b"x", (from, 9))) {
            Ok(_) => "ok".to_owned(),
            Err(e) => errno(&e),
        }
    }

    /// Runs `action` in a child that first joins the box cgroup, and returns
    /// the line it reports.
    fn in_box(name: &str, action: impl FnOnce() -> String) -> String {
        let Ok((read, write)) = nix::unistd::pipe() else {
            return "err pipe".to_owned();
        };
        // SAFETY: this process has one thread, and the child only uses
        // files and sockets before it exits.
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Child) => {
                drop(read);
                let joined = fs::write(format!("{CGROUP}/boxes/{name}/cgroup.procs"), "0");
                let line = if joined.is_ok() {
                    action()
                } else {
                    "err join".to_owned()
                };
                let _sent = fs::File::from(write).write_all(line.as_bytes());
                std::process::exit(0);
            }
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                drop(write);
                let mut line = String::new();
                let _read = fs::File::from(read).read_to_string(&mut line);
                let _reaped = nix::sys::wait::waitpid(child, None);
                line
            }
            Err(_) => "err fork".to_owned(),
        }
    }

    fn errno(e: &std::io::Error) -> String {
        format!("err {}", e.raw_os_error().unwrap_or(0))
    }

    fn tcp(to: SocketAddr) -> String {
        match TcpStream::connect_timeout(&to, Duration::from_millis(500)) {
            Ok(_) => "ok".to_owned(),
            Err(e) => errno(&e),
        }
    }

    fn udp(to: SocketAddr) -> String {
        let any: SocketAddr = if to.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        match UdpSocket::bind(any).and_then(|s| s.send_to(b"x", to)) {
            Ok(_) => "ok".to_owned(),
            Err(e) => errno(&e),
        }
    }

    struct Report {
        failed: bool,
    }

    impl Report {
        fn check(&mut self, name: &str, ok: bool, detail: &str) {
            println!(
                "{} guest.{name} | {detail}",
                if ok { "PASS" } else { "FAIL" }
            );
            self.failed |= !ok;
        }
    }

    fn box_id(name: &str) -> Result<BoxId, Error> {
        let dir =
            fs::File::open(format!("{CGROUP}/boxes/{name}")).map_err(|source| Error::Sys {
                what: "open a box cgroup",
                source,
            })?;
        BoxId::of(dir.as_fd()).map_err(|source| Error::Sys {
            what: "read a box id",
            source,
        })
    }

    fn start() -> Result<Handles, Error> {
        let step = |what: &'static str| move |source: std::io::Error| Error::Sys { what, source };
        for dir in ["supervisor", "boxes", "boxes/bare", "boxes/b", "boxes/own"] {
            fs::create_dir_all(format!("{CGROUP}/{dir}"))
                .map_err(step("create the cgroup layout"))?;
        }
        fs::write(format!("{CGROUP}/supervisor/cgroup.procs"), "0")
            .map_err(step("move into supervisor/"))?;
        let boxes = fs::File::open(format!("{CGROUP}/boxes")).map_err(step("open boxes/"))?;
        Engine::start(boxes.as_fd(), &MapSizes::default())
    }

    fn spec(port: u16) -> Spec {
        let mut deployment = Deployment::new(NodeKind::Guest, Mode::HostIp);
        deployment.transport_ipv6 = true;
        deployment.services.resolver = Some(Endpoint {
            v4: Some(RESOLVER4),
            v6: Some(RESOLVER6),
        });
        let allow = |to: &str, ports: PortRange| BoxRule {
            action: BoxAction::Allow,
            protocols: Protocols::TCP,
            ports,
            to: to.parse().map_or(Target::Any, Target::Net),
        };
        let prefixes = |list: &[&str]| list.iter().filter_map(|p| p.parse().ok()).collect();
        Spec {
            deployment,
            policy: BoxPolicy {
                rules: vec![
                    allow("127.2.0.0/16", PortRange::one(port)),
                    allow("::1/128", PortRange::one(port)),
                ],
                deny: prefixes(&["127.1.2.0/24"]),
                allow: prefixes(&["127.1.0.0/16"]),
                ..BoxPolicy::default()
            },
            options: Options { log_flows: false },
        }
    }

    fn run(report: &mut Report) -> Result<(), Error> {
        mount("proc", "/proc", "proc");
        mount("sysfs", "/sys", "sysfs");
        mount("cgroup2", CGROUP, "cgroup2");
        loopback_up();
        let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        println!(
            "INFO guest.kernel | {} btf={}",
            release.trim(),
            Path::new("/sys/kernel/btf/vmlinux").exists()
        );

        let mut handles = start()?;
        report.check(
            "load",
            true,
            "every program passed the verifier and attached at boxes/",
        );
        // A second engine at the same cgroup would judge every flow too,
        // from maps nobody writes.
        let again = fs::File::open(format!("{CGROUP}/boxes"))
            .map_err(|source| Error::Sys {
                what: "open boxes/",
                source,
            })
            .and_then(|boxes| Engine::start(boxes.as_fd(), &MapSizes::default()));
        report.check(
            "in_use",
            matches!(again, Err(Error::InUse)),
            &format!(
                "a cgroup with an engine gets no second one: {}",
                again
                    .err()
                    .map_or_else(|| "it did".to_owned(), |e| e.to_string())
            ),
        );
        let mut events = handles.take_events();

        let listener = TcpListener::bind("[::]:0").map_err(|source| Error::Sys {
            what: "listen",
            source,
        })?;
        let port = listener.local_addr().map_or(0, |a| a.port());
        let resolver = UdpSocket::bind(RESOLVER4).map_err(|source| Error::Sys {
            what: "bind the resolver",
            source,
        })?;
        let _timeout = resolver.set_read_timeout(Some(Duration::from_secs(2)));
        let netns = boxbpf::netns_cookie(resolver.as_fd()).map_err(|source| Error::Sys {
            what: "read the namespace cookie",
            source,
        })?;

        let out = in_box("bare", || tcp((Ipv4Addr::LOCALHOST, port).into()));
        report.check(
            "no_config",
            out == "err 1",
            &format!("a cgroup without policy cannot create a socket: {out}"),
        );

        let live = handles.install(box_id("b")?, spec(port))?;
        let refused = format!("err {REFUSED}");

        // One table, judged by the kernel and by the evaluator.
        let remotes = [
            "127.1.1.1",
            "127.1.2.1",
            "127.2.0.1",
            "127.3.0.1",
            "::1",
            "::ffff:127.1.1.1",
            "::ffff:127.1.2.1",
        ];
        let (mut total, mut denied, mut wrong) = (0, 0, Vec::new());
        for remote in remotes.iter().filter_map(|r| r.parse::<IpAddr>().ok()) {
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                for flow_port in [port, 9] {
                    let to = SocketAddr::new(remote, flow_port);
                    let out = in_box("b", || {
                        if protocol == Protocol::Tcp {
                            tcp(to)
                        } else {
                            udp(to)
                        }
                    });
                    let flow = Flow {
                        direction: Direction::Egress,
                        protocol,
                        remote,
                        port: flow_port,
                        local: None,
                    };
                    let expect_deny = live.compiled().evaluate(&flow, |_| Vec::new()).verdict
                        == FlowVerdict::Deny;
                    total += 1;
                    denied += usize::from(out == refused);
                    if (out == refused) != expect_deny {
                        wrong.push(format!(
                            "{protocol} {to}: kernel `{out}`, evaluator deny={expect_deny}"
                        ));
                    }
                }
            }
        }
        report.check(
            "parity",
            wrong.is_empty() && denied > 5 && denied < total,
            &format!(
                "{total} flows, {denied} denied, {} disagreements {}",
                wrong.len(),
                wrong.join("; ")
            ),
        );

        // DNS goes to the resolver endpoint and the box sees the server it asked.
        let Ok((read, write)) = nix::unistd::pipe() else {
            return Ok(());
        };
        // SAFETY: one thread, and the child only uses sockets and the pipe.
        if let Ok(nix::unistd::ForkResult::Child) = unsafe { nix::unistd::fork() } {
            drop(read);
            let joined = fs::write(format!("{CGROUP}/boxes/b/cgroup.procs"), "0");
            let line = joined
                .and_then(|()| UdpSocket::bind("0.0.0.0:0"))
                .and_then(|s| {
                    s.set_read_timeout(Some(Duration::from_secs(2)))?;
                    s.send_to(b"query", "127.0.0.53:53")?;
                    let mut buf = [0u8; 16];
                    s.recv_from(&mut buf).map(|(_, from)| from.to_string())
                });
            let line = line.unwrap_or_else(|e| errno(&e));
            let _sent = fs::File::from(write).write_all(line.as_bytes());
            std::process::exit(0);
        }
        drop(write);
        let mut buf = [0u8; 16];
        let origin = match resolver.recv_from(&mut buf) {
            Ok((n, peer)) => {
                // The entry goes with the box's socket, which closes once
                // the reply is in: ask first.
                let origin = handles.original_destination(netns, peer, Protocol::Udp)?;
                let _sent = resolver.send_to(buf.get(..n).unwrap_or_default(), peer);
                origin
            }
            Err(_) => None,
        };
        let mut seen = String::new();
        let _read = fs::File::from(read).read_to_string(&mut seen);
        let origin_ok = origin.is_some_and(|o| {
            o.box_id == live.id()
                && o.endpoint == RESOLVER
                && o.destination == SocketAddr::from(([127, 0, 0, 53], 53))
        });
        report.check(
            "redirect",
            seen == "127.0.0.53:53" && origin_ok,
            &format!("reply seen from {seen}, original destination recorded: {origin_ok}"),
        );

        let mut refusals = 0;
        if let Some(source) = events.as_mut() {
            while let Some(event) = source.try_next() {
                refusals += usize::from(matches!(event, netpol::event::Event::Net(_)));
            }
        }
        report.check(
            "events",
            refusals > denied,
            &format!("{refusals} refusal events for {denied} refused flows and one socket"),
        );
        // A box socket that listens is in the table until it is released,
        // and a record says when to read the table.
        let (Ok((port_read, port_write)), Ok((stop_read, stop_write))) =
            (nix::unistd::pipe(), nix::unistd::pipe())
        else {
            return Ok(());
        };
        // SAFETY: one thread, and the child only uses sockets and the pipes.
        let listener = unsafe { nix::unistd::fork() };
        if let Ok(nix::unistd::ForkResult::Child) = listener {
            drop((port_read, stop_write));
            let joined = fs::write(format!("{CGROUP}/boxes/b/cgroup.procs"), "0");
            let bound = joined.and_then(|()| TcpListener::bind("[::]:0"));
            let said = bound
                .as_ref()
                .map_or(0, |l| l.local_addr().map_or(0, |a| a.port()));
            let _sent = fs::File::from(port_write).write_all(said.to_string().as_bytes());
            let mut wait = String::new();
            let _closed = fs::File::from(stop_read).read_to_string(&mut wait);
            std::process::exit(0);
        }
        drop((port_write, stop_read));
        let mut said = String::new();
        let _read = fs::File::from(port_read).read_to_string(&mut said);
        let listen_port: u16 = said.parse().unwrap_or(0);
        let listed = handles.listening(live.id(), netns)?;
        let mut heard = false;
        if let Some(source) = events.as_mut() {
            while let Some(event) = source.try_next() {
                if let netpol::event::Event::Listen(e) = event {
                    heard |= e.box_id == live.id().0 && e.port == listen_port && e.open;
                }
            }
        }
        drop(stop_write);
        if let Ok(nix::unistd::ForkResult::Parent { child }) = listener {
            let _reaped = nix::sys::wait::waitpid(child, None);
        }
        let after = handles.listening(live.id(), netns)?;
        report.check(
            "listen",
            listen_port != 0
                && listed.len() == 1
                && listed.iter().all(|l| l.port == listen_port)
                && heard
                && after.is_empty(),
            &format!(
                "port {listen_port}: in the table {listed:?}, record seen: {heard}, after release {after:?}"
            ),
        );

        // A box with a source check sends from its own addresses only,
        // and those are a set the daemon adds to while the box runs.
        let address = Ipv4Addr::new(10, 9, 0, 1);
        loopback_alias(address);
        let own_ip = Spec {
            deployment: Deployment::new(NodeKind::Guest, Mode::OwnIp),
            policy: BoxPolicy {
                default: Some(netpol::Verdict::Allow),
                ..BoxPolicy::default()
            },
            options: Options { log_flows: false },
        };
        let own = handles.install(box_id("own")?, own_ip)?;
        let before = in_box("own", || udp_from(address));
        handles.add_own_address(own.id(), IpAddr::V4(address))?;
        let with = in_box("own", || udp_from(address));
        handles.remove_own_address(own.id(), IpAddr::V4(address))?;
        let after = in_box("own", || udp_from(address));
        report.check(
            "own_address",
            (before.as_str(), with.as_str(), after.as_str()) == ("err 1", "ok", "err 1"),
            &format!("a send from {address}: {before} before it is the box's, {with} while, {after} after"),
        );
        handles.uninstall(&own)?;

        let stats = handles.stats(live.id())?.unwrap_or_default();
        report.check(
            "stats",
            stats.tx_pkts > 0 && usize::try_from(stats.refused).is_ok_and(|r| r == denied),
            &format!("{stats:?}"),
        );

        handles.uninstall(&live)?;
        let out = in_box("b", || tcp((Ipv4Addr::LOCALHOST, port).into()));
        report.check(
            "uninstall",
            out == "err 1",
            &format!("after removing the box: {out}"),
        );
        Ok(())
    }

    pub fn main() {
        if std::process::id() != 1 {
            eprintln!(
                "guest_selftest runs as /init of a test initramfs: see scripts/boxbpf-guest-kernel.sh"
            );
            std::process::exit(2);
        }
        let mut report = Report { failed: false };
        if let Err(e) = run(&mut report) {
            report.check("run", false, &e.to_string());
        }
        println!(
            "RESULT guest {}",
            if report.failed { "fail" } else { "pass" }
        );
        let _flushed = std::io::stdout().flush();
        // SAFETY: sync takes no arguments.
        unsafe { libc::sync() };
        // SAFETY: as PID 1 with nothing else running, powering off is the way out.
        let _off = unsafe { libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF) };
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    guest::main();
}
