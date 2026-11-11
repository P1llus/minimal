//! Shared by the root integration tests.
//!
//! A test runs as the unprivileged user, like the daemon does. It gets a
//! delegated cgroup from systemd, starts a loader as root through `sudo -n`,
//! asks it for an engine, and judges what processes placed in box cgroups
//! can do. The helper roles (loader, probe) are this same test binary run
//! again with `BOXBPF_TEST_ROLE` set.

pub mod probe;
pub mod roles;
pub mod servers;

use std::{
    ffi::CString,
    fs,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsFd, OwnedFd},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

use boxbpf::{BoxId, Handles, LiveBox};
use netpol::{
    Spec,
    base::{Deployment, Mode, NodeKind},
    compile::Options,
    policy::BoxPolicy,
};

/// Set to run these tests. Unset, they skip: the default suite must not
/// need root, systemd or a network.
pub const GATE: &str = "BOXBPF_ROOT_TEST";
const IN_UNIT: &str = "BOXBPF_TEST_IN_UNIT";
pub const ROLE: &str = "BOXBPF_TEST_ROLE";
pub const SOCKET: &str = "BOXBPF_TEST_SOCKET";
pub const LO_ADDRS: &str = "BOXBPF_TEST_LO_ADDRS";
/// Sizes the loader loads the engine with where a test wants small ones to
/// fill: `name=value` pairs, comma separated. See the loader role.
pub const SIZES: &str = "BOXBPF_TEST_SIZES";

/// The errno of a call the engine refused. The kernel returns it for a
/// cgroup program that says no, at the system call and for a datagram
/// dropped on the way out.
pub const REFUSED: i32 = libc::EPERM;

fn exe() -> PathBuf {
    std::env::current_exe().expect("path of the test binary")
}

fn own_cgroup() -> PathBuf {
    let text = fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let rel = text
        .lines()
        .find_map(|l| l.strip_prefix("0::/"))
        .expect("cgroup v2 membership");
    Path::new("/sys/fs/cgroup").join(rel)
}

/// Runs this test again inside a delegated systemd unit and reports its
/// result. Returns true when the caller is the outer process and is done.
fn rerun_delegated(test: &str) -> bool {
    if std::env::var_os(IN_UNIT).is_some() {
        return false;
    }
    let user_bus =
        std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|d| Path::new(&d).join("bus").exists());
    let mut cmd = if user_bus {
        // What the daemon does when it is started by hand.
        let mut c = Command::new("systemd-run");
        c.args([
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            "-p",
            "Delegate=yes",
            "--",
        ]);
        c
    } else {
        // No user manager: a system service of this user, delegated, with
        // the process started in the supervisor sub-cgroup.
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .expect("the current user has a passwd entry")
            .name;
        let mut c = Command::new("sudo");
        c.args([
            "-n",
            "systemd-run",
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
        ]);
        c.args([
            "-p",
            &format!("User={user}"),
            "-p",
            "Delegate=yes",
            "-p",
            "DelegateSubgroup=supervisor",
        ]);
        c.arg(format!("--setenv={GATE}=1"))
            .arg(format!("--setenv={IN_UNIT}=1"));
        if let Some(path) = std::env::var_os("PATH") {
            c.arg(format!("--setenv=PATH={}", path.to_string_lossy()));
        }
        c.arg("--");
        c
    };
    let status = cmd
        .arg(exe())
        .args(["--exact", test, "--ignored", "--nocapture"])
        .env(IN_UNIT, "1")
        .status()
        .expect("run systemd-run: these tests need a systemd host");
    assert!(
        status.success(),
        "{test} failed inside its delegated unit ({status})"
    );
    true
}

/// A process that runs until the handle is dropped.
pub struct Background(Child);

impl Drop for Background {
    fn drop(&mut self) {
        // Either may fail because the process is already gone.
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

impl Background {
    pub fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl From<Child> for Background {
    fn from(child: Child) -> Self {
        Self(child)
    }
}

/// The root loader helper. It cleans up after itself when its stdin
/// closes, so it is asked to stop that way and given time to finish.
/// Killing sudo would take the helper down in the middle of its cleanup.
struct LoaderProcess(Child);

impl Drop for LoaderProcess {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let end = Instant::now() + Duration::from_secs(15);
        while Instant::now() < end {
            if !matches!(self.0.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

/// A probe that stays alive between two steps of a test.
pub struct Held {
    /// What the probe said when it was ready, after the word `ready`.
    pub ready: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Held {
    fn read_line(&mut self) -> String {
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .expect("read from a held probe");
        line.trim().to_owned()
    }

    /// Lets the probe take its next step and returns what it reports.
    pub fn step(&mut self) -> String {
        self.stdin.write_all(b"\n").expect("signal a held probe");
        loop {
            // libtest may print lines of its own in between.
            let line = self.read_line();
            if let Some(result) = line.strip_prefix("probe: ") {
                return result.trim().to_owned();
            }
            assert!(
                !line.is_empty() || self.child.try_wait().expect("wait").is_none(),
                "held probe ended early"
            );
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

/// The box cgroups of one test: where probes are placed. A cheap copy of
/// the root path, so a test can keep probing while it changes the maps.
#[derive(Clone)]
pub struct Cgroups {
    root: PathBuf,
}

/// One test's delegated root and loader, with no engine asked for yet.
pub struct Bare {
    pub root: PathBuf,
    pub boxes: OwnedFd,
    pub socket: PathBuf,
    net: (u8, u8),
    tmp: tempfile::TempDir,
    loader: LoaderProcess,
}

/// One test's delegated root, engine and addresses.
pub struct Harness {
    pub root: PathBuf,
    pub boxes: OwnedFd,
    pub handles: Handles,
    pub socket: PathBuf,
    /// Distinguishes the addresses of tests that run at the same time.
    net: (u8, u8),
    _tmp: tempfile::TempDir,
    _loader: LoaderProcess,
}

impl Harness {
    /// Sets a test up. `None` means the test is over for this process:
    /// skipped because the gate is not set, or run in a child.
    pub fn start(test: &str) -> Option<Self> {
        Self::start_with(test, &[])
    }

    /// Like [`Self::start`], with extra IPv6 addresses on the host's
    /// loopback for the duration of the test. `suffixes` are the low 16
    /// bits; see [`Self::v6`].
    pub fn start_with(test: &str, v6_suffixes: &[u16]) -> Option<Self> {
        Self::start_as(test, v6_suffixes, None)
    }

    /// Like [`Self::start`], with an engine of other sizes, small enough
    /// for a test to fill: `rule_entries` or `flows_per_box`.
    pub fn start_sized(test: &str, size: &str, value: u32) -> Option<Self> {
        Self::start_as(test, &[], Some((size, value)))
    }

    fn start_as(test: &str, v6_suffixes: &[u16], size: Option<(&str, u32)>) -> Option<Self> {
        if std::env::var_os(GATE).is_none() {
            eprintln!("skipping {test}: {GATE} is not set (it needs sudo -n, systemd and clang)");
            return None;
        }
        if rerun_delegated(test) {
            return None;
        }
        let bare = Self::ground(v6_suffixes, size);
        let handles = boxbpf::loader::request(&bare.socket, bare.boxes.as_fd())
            .expect("get handles from the loader");
        Some(Self {
            root: bare.root,
            boxes: bare.boxes,
            handles,
            socket: bare.socket,
            net: bare.net,
            _tmp: bare.tmp,
            _loader: bare.loader,
        })
    }

    /// Sets a test up without asking the loader for an engine: for tests
    /// of the request itself.
    pub fn bare(test: &str) -> Option<Bare> {
        if std::env::var_os(GATE).is_none() {
            eprintln!("skipping {test}: {GATE} is not set (it needs sudo -n, systemd and clang)");
            return None;
        }
        if rerun_delegated(test) {
            return None;
        }
        Some(Self::ground(&[], None))
    }

    fn ground(v6_suffixes: &[u16], size: Option<(&str, u32)>) -> Bare {
        // In a scope we start in the unit's own cgroup, in a service with
        // DelegateSubgroup already in supervisor/.
        let here = own_cgroup();
        let root = if here.ends_with("supervisor") {
            here.parent().expect("unit cgroup").to_owned()
        } else {
            here
        };
        let supervisor = root.join("supervisor");
        fs::create_dir_all(&supervisor).expect("create supervisor/");
        fs::write(supervisor.join("cgroup.procs"), "0").expect("move into supervisor/");
        let boxes_dir = root.join("boxes");
        fs::create_dir_all(&boxes_dir).expect("create boxes/");
        let boxes: OwnedFd = fs::File::open(&boxes_dir).expect("open boxes/").into();

        let pid = std::process::id();
        let net = (
            u8::try_from(100 + (pid / 250) % 100).expect("fits"),
            u8::try_from(1 + pid % 250).expect("fits"),
        );
        let tmp = tempfile::Builder::new()
            .prefix("boxbpf-test-")
            .tempdir()
            .expect("temp dir");
        let socket = tmp.path().join("loader.sock");
        let lo_addrs: Vec<String> = v6_suffixes
            .iter()
            .map(|s| v6_addr(net, *s).to_string())
            .collect();

        // The loader. sudo passes stdin through, and the helper exits when
        // it closes, so it cannot outlive this process.
        let loader = Command::new("sudo")
            .args(["-n", "env"])
            .arg(format!("{GATE}=1"))
            .arg(format!("{ROLE}=loader"))
            .arg(format!("{SOCKET}={}", socket.display()))
            .arg(format!("{LO_ADDRS}={}", lo_addrs.join(",")))
            .arg(format!(
                "{SIZES}={}",
                size.map(|(name, value)| format!("{name}={value}"))
                    .unwrap_or_default()
            ))
            .arg(exe())
            .args(["--exact", "helper", "--ignored", "--nocapture"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("start the loader through sudo -n: these tests need passwordless sudo");
        let loader = LoaderProcess(loader);
        wait_for("the loader socket", || socket.exists());
        Bare {
            root,
            boxes,
            socket,
            net,
            tmp,
            loader,
        }
    }

    /// An IPv4 loopback address of this test. `group` and `host` pick one
    /// of many, so prefixes of different lengths can be told apart.
    pub fn v4(&self, group: u8, host: u8) -> Ipv4Addr {
        // 127.<100-199>.<1-250>.x belongs to one test. The last octet
        // holds a 3-bit group and a 5-bit host.
        Ipv4Addr::new(127, self.net.0, self.net.1, (group << 5) | (host & 31))
    }

    /// The /24 all of this test's IPv4 addresses are in.
    pub fn v4_net(&self) -> String {
        format!("127.{}.{}.0/24", self.net.0, self.net.1)
    }

    /// The /27 of one group.
    pub fn v4_group(&self, group: u8) -> String {
        format!("{}/27", self.v4(group, 0))
    }

    /// An IPv6 address of this test: `fd00:<test>:<group>::<host>` from a
    /// 16-bit suffix `group << 8 | host`.
    pub fn v6(&self, suffix: u16) -> Ipv6Addr {
        v6_addr(self.net, suffix)
    }

    /// The /32 all of this test's IPv6 addresses are in.
    pub fn v6_net(&self) -> String {
        format!("{}/32", self.v6(0))
    }

    /// The /48 of one group.
    pub fn v6_group(&self, group: u8) -> String {
        format!("{}/48", self.v6(u16::from(group) << 8))
    }

    pub fn cgroups(&self) -> Cgroups {
        Cgroups {
            root: self.root.clone(),
        }
    }

    /// Creates a box cgroup and returns its id. No policy yet.
    pub fn new_box(&self, name: &str) -> BoxId {
        self.cgroups().new_box(name)
    }

    /// Creates a box cgroup and installs a policy for it.
    pub fn install(&mut self, name: &str, deployment: Deployment, policy: BoxPolicy) -> LiveBox {
        let id = self.new_box(name);
        let spec = Spec {
            deployment,
            policy,
            options: Options { log_flows: false },
        };
        self.handles
            .install(id, spec)
            .expect("install a box policy")
    }

    pub fn probe(&self, box_name: &str, args: &[&str]) -> String {
        self.cgroups().probe(box_name, args)
    }

    pub fn hold_probe(&self, box_name: &str, args: &[&str]) -> Held {
        self.cgroups().hold_probe(box_name, args)
    }

    /// The next events, waiting a little for stragglers.
    pub fn drain(source: &mut boxbpf::events::Source) -> Vec<netpol::event::NetEvent> {
        let mut out = Vec::new();
        let end = Instant::now() + Duration::from_millis(200);
        while Instant::now() < end {
            match source.try_next() {
                Some(e) => out.push(e),
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        out
    }
}

impl Cgroups {
    /// Creates a box cgroup and returns its id. No policy yet.
    pub fn new_box(&self, name: &str) -> BoxId {
        let dir = self.root.join("boxes").join(name);
        fs::create_dir(&dir).expect("create a box cgroup");
        BoxId::of(fs::File::open(&dir).expect("open a box cgroup").as_fd()).expect("box id")
    }

    fn in_box(&self, name: &str, cmd: Command) -> Command {
        self.in_cgroup(&format!("boxes/{name}"), cmd)
    }

    /// Makes `cmd` start in the cgroup `rel` below the test's root.
    fn in_cgroup(&self, rel: &str, mut cmd: Command) -> Command {
        let procs = CString::new(
            self.root
                .join(rel)
                .join("cgroup.procs")
                .to_string_lossy()
                .as_bytes(),
        )
        .expect("cgroup path");
        let join = move || {
            // SAFETY: procs is a C string made before the fork, and open is
            // async-signal-safe.
            let fd = unsafe { libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: fd is open and the buffer is one valid byte. write is
            // async-signal-safe.
            let wrote = unsafe { libc::write(fd, c"0".as_ptr().cast(), 1) };
            let result = if wrote == 1 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            };
            // SAFETY: fd is ours and not used again.
            let _closed = unsafe { libc::close(fd) };
            result
        };
        // SAFETY: the closure runs between fork and exec and only makes the
        // async-signal-safe calls above, on memory prepared before the fork.
        unsafe { cmd.pre_exec(join) };
        cmd
    }

    fn probe_command(args: &[&str], netns_of: Option<u32>) -> Command {
        let mut cmd = match netns_of {
            Some(pid) => {
                let mut c = Command::new("nsenter");
                c.args([
                    "-t",
                    &pid.to_string(),
                    "-U",
                    "-n",
                    "--preserve-credentials",
                    "--",
                ]);
                c.arg(exe());
                c
            }
            None => Command::new(exe()),
        };
        cmd.args(["--exact", "helper", "--ignored", "--nocapture"]);
        cmd.env(ROLE, "probe")
            .env("BOXBPF_TEST_PROBE", args.join(" "));
        cmd
    }

    fn run(mut cmd: Command) -> String {
        let out = cmd.stderr(Stdio::inherit()).output().expect("run a probe");
        // libtest prints its own lines around ours.
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("probe: "))
            .unwrap_or("err no-result")
            .to_owned()
    }

    /// Runs a probe as this user in a cgroup nobody delegated: a transient
    /// system service. Returns its result line.
    pub fn outside_probe(args: &[&str]) -> String {
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .expect("the current user has a passwd entry")
            .name;
        let mut cmd = Command::new("sudo");
        cmd.args([
            "-n",
            "systemd-run",
            "--wait",
            "--pipe",
            "--quiet",
            "--collect",
        ])
        .args(["-p", &format!("User={user}")])
        .arg(format!("--setenv={GATE}=1"))
        .arg(format!("--setenv={ROLE}=probe"))
        .arg(format!("--setenv=BOXBPF_TEST_PROBE={}", args.join(" ")))
        .arg("--")
        .arg(exe())
        .args(["--exact", "helper", "--ignored", "--nocapture"]);
        Self::run(cmd)
    }

    /// Runs a socket action as a process of the box and returns its result
    /// line: `ok ...` or `err <errno>`.
    pub fn probe(&self, box_name: &str, args: &[&str]) -> String {
        Self::run(self.in_box(box_name, Self::probe_command(args, None)))
    }

    /// Runs a probe in the cgroup `rel` below the test's root, which need
    /// not be a box.
    pub fn probe_at(&self, rel: &str, args: &[&str]) -> String {
        Self::run(self.in_cgroup(rel, Self::probe_command(args, None)))
    }

    /// Like [`Self::probe`], with `channel` as the probe's standard input:
    /// a unix socket it passes sockets over.
    pub fn probe_over(&self, box_name: &str, args: &[&str], channel: OwnedFd) -> String {
        let mut cmd = self.in_box(box_name, Self::probe_command(args, None));
        cmd.stdin(Stdio::from(channel));
        Self::run(cmd)
    }

    /// The same for a box whose sockets live in the netns of `pid`.
    pub fn probe_in(&self, box_name: &str, netns_of: u32, args: &[&str]) -> String {
        Self::run(self.in_box(box_name, Self::probe_command(args, Some(netns_of))))
    }

    /// A socket action outside any box, in the netns of `pid`.
    pub fn peer_probe(netns_of: u32, args: &[&str]) -> String {
        Self::run(Self::probe_command(args, Some(netns_of)))
    }

    fn hold(mut cmd: Command) -> Held {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start a held probe");
        let stdin = child.stdin.take().expect("stdin");
        let mut held = Held {
            ready: String::new(),
            stdout: BufReader::new(child.stdout.take().expect("stdout")),
            stdin,
            child,
        };
        loop {
            let line = held.read_line();
            if let Some(said) = line.strip_prefix("probe: ready") {
                held.ready = said.trim().to_owned();
                return held;
            }
            assert!(
                !line.is_empty() || held.child.try_wait().expect("wait").is_none(),
                "held probe ended early"
            );
        }
    }

    /// Starts a probe in a box that does its first step, reports `ready`,
    /// and waits for [`Held::step`].
    pub fn hold_probe(&self, box_name: &str, args: &[&str]) -> Held {
        Self::hold(self.in_box(box_name, Self::probe_command(args, None)))
    }

    pub fn hold_probe_in(&self, box_name: &str, netns_of: u32, args: &[&str]) -> Held {
        Self::hold(self.in_box(box_name, Self::probe_command(args, Some(netns_of))))
    }

    pub fn hold_peer_probe(netns_of: u32, args: &[&str]) -> Held {
        Self::hold(Self::probe_command(args, Some(netns_of)))
    }

    /// Starts a long-running command as a process of a box.
    pub fn spawn_in_box(&self, box_name: &str, cmd: Command) -> Background {
        Background(self.in_box(box_name, cmd).spawn().expect("spawn in a box"))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Kill what is left in the boxes and remove their cgroups, so the
        // unit ends clean. Failures only leave it to systemd.
        let Ok(entries) = fs::read_dir(self.root.join("boxes")) else {
            return;
        };
        for dir in entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
            let _killed = fs::write(dir.join("cgroup.kill"), "1");
            for _ in 0..50 {
                if fs::read_to_string(dir.join("cgroup.events"))
                    .is_ok_and(|e| e.contains("populated 0"))
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _removed = fs::remove_dir(&dir);
        }
    }
}

fn v6_addr(net: (u8, u8), suffix: u16) -> Ipv6Addr {
    let test = (u16::from(net.0) << 8) | u16::from(net.1);
    Ipv6Addr::new(0xfd00, test, suffix >> 8, 0, 0, 0, 0, suffix & 0xff)
}

pub fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A `host_ip` deployment on a native node with IPv6: no base rules, every
/// default is allow.
pub fn host_ip() -> Deployment {
    let mut d = Deployment::new(NodeKind::Native, Mode::HostIp);
    d.transport_ipv6 = true;
    d
}

pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("address")
}
