//! The spawner, on real boxes: this test binary plays the daemon, and the
//! `minimald` binary is its spawner process and its enter shim.
//!
//! The boxes run a probe, compiled here with `gcc -static`, in a rootfs that
//! holds nothing else. A test that needs box cgroups runs itself again in a
//! delegated systemd scope (`sandbox::cgroup::testing::delegated_root`). A
//! host that gives no such scope, or no unprivileged user namespace, skips
//! with the reason on stderr.
#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox::cgroup::{BoxCgroup, Root};
use sandbox::config::{Config, SandboxMapped};
use sandbox::spawner::enter::{SHIM_ESCALATION, init_of};
use sandbox::{Child, NetPlan, SignalTarget, Spawner, Stdio, Terminal};

/// The probe a test box runs. Its source lists what its arguments ask for.
const PROBE_C: &str = include_str!("../../sandbox/src/testdata/box_probe.c");

/// What a test of the spawner works with.
struct Fixture {
    spawner: Spawner,
    /// The cgroup root, for a test that asked for one.
    root: Option<Root>,
    /// Holds the probe and every box.
    dir: tempfile::TempDir,
    probe: PathBuf,
}

impl Fixture {
    /// The fixture of the test named `test`, or `None` when the host cannot
    /// run it. With `cgroups`, this process is first run again in a
    /// delegated scope, and `None` is also what the first run gets.
    fn new(test: &str, cgroups: bool) -> Option<Self> {
        if let Some(reason) = sandbox::user_namespaces_restriction() {
            eprintln!("skipping {test}: no unprivileged user namespace: {reason}");
            return None;
        }
        let root = if cgroups {
            Some(sandbox::cgroup::testing::delegated_root(test)?)
        } else {
            None
        };
        // After the root is open, so the spawner starts in `supervisor`.
        let spawner = Spawner::process(
            env!("CARGO_BIN_EXE_minimald"),
            Terminal::Detached,
            root.clone(),
        );
        spawner.start().expect("starting the spawner process");
        spawner
            .clone()
            .install()
            .expect("this test process has no spawner yet");

        let dir = tempfile::tempdir().expect("a directory for the boxes");
        let source = dir.path().join("probe.c");
        let probe = dir.path().join("probe");
        std::fs::write(&source, PROBE_C).expect("writing the probe's source");
        let compiled = std::process::Command::new("gcc")
            .args(["-static", "-o"])
            .arg(&probe)
            .arg(&source)
            .status()
            .expect("running gcc");
        assert!(compiled.success(), "gcc could not compile the probe");
        Some(Self {
            spawner,
            root,
            dir,
            probe,
        })
    }

    fn root(&self) -> &Root {
        self.root.as_ref().expect("the test asked for cgroups")
    }

    /// Starts a box named `name` that runs the probe with `args`. `extra`
    /// are more programs for its `/usr/bin`: a name and the file to copy.
    async fn launch(
        &self,
        name: &str,
        cgroup: Option<&BoxCgroup>,
        plan: Option<NetPlan>,
        extra: &[(&str, &Path)],
        args: &[&str],
    ) -> TestBox {
        self.launch_weighted(name, cgroup, plan, extra, args, None)
            .await
    }

    /// [`Self::launch`], with a CPU weight for the box's sandbox.
    async fn launch_weighted(
        &self,
        name: &str,
        cgroup: Option<&BoxCgroup>,
        plan: Option<NetPlan>,
        extra: &[(&str, &Path)],
        args: &[&str],
        cpu_weight: Option<u64>,
    ) -> TestBox {
        let source = self.dir.path().join(format!("{name}-rootfs"));
        let bin = source.join("usr/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(source.join("usr/lib")).unwrap();
        std::fs::create_dir_all(source.join("etc")).unwrap();
        std::fs::copy(&self.probe, bin.join("probe")).unwrap();
        for (program, file) in extra {
            std::fs::copy(file, bin.join(program)).unwrap();
        }
        let mut config = Config::new(name)
            .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
            .with_dns(false)
            .with_box_cgroup(cgroup.cloned());
        if let Some(weight) = cpu_weight {
            config = config.with_cpu_weight(weight);
        }
        let mut sandbox = config
            .build(self.dir.path().join(name), ())
            .await
            .expect("building the box");
        let plan = plan.unwrap_or_else(|| sandbox.built_in_plan());
        let container = sandbox.new_container(&plan).expect("the box's container");
        let mut command = sandbox
            .command(&container, "/usr/bin/probe", args, [("", ""); 0])
            .expect("the probe's command");
        command.stdin(Stdio::Null).stdout(Stdio::MakePipe);
        let mut child = command.spawn().expect("starting the box");
        let report = Report::read(child.stdout.take().expect("the probe's stdout"));
        let run = sandbox
            .rootfs()
            .parent()
            .expect("a rootfs has a parent")
            .join("run");
        TestBox {
            child,
            report,
            run,
            _sandbox: sandbox,
        }
    }
}

/// A box that runs the probe.
struct TestBox {
    child: Child,
    report: Report,
    /// The box's `/run`, as this host names it.
    run: PathBuf,
    _sandbox: sandbox::Sandbox,
}

impl TestBox {
    /// Ends the hold of a probe that holds at `/run/<name>`.
    fn release(&self, name: &str) {
        std::fs::write(self.run.join(name), "").expect("releasing a held probe");
    }
}

/// What a probe printed so far, read as it comes.
struct Report {
    text: Arc<Mutex<String>>,
    reader: std::thread::JoinHandle<()>,
}

impl Report {
    fn read(mut pipe: impl std::io::Read + Send + 'static) -> Self {
        let text = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&text);
        let reader = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            // A terminal's master ends with an error, a pipe with zero.
            while let Ok(n @ 1..) = pipe.read(&mut chunk) {
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        });
        Self { text, reader }
    }

    /// Waits until the probe has printed a line that starts with `key`.
    fn wait_for(&self, key: &str) {
        eventually(&format!("the probe prints `{key}`"), || {
            self.text
                .lock()
                .unwrap()
                .lines()
                .any(|line| line.starts_with(key))
                .then_some(())
        });
    }

    /// Everything the probe printed, as `key: value` lines, once it is done.
    fn finish(self) -> BTreeMap<String, String> {
        self.reader.join().expect("the report's reader");
        let text = self.text.lock().unwrap();
        text.lines()
            .filter_map(|line| line.split_once(": "))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }
}

/// Polls `check` until it gives a value, for at most ten seconds.
fn eventually<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The fields of `/proc/<pid>/stat` after the command name, or `None` for a
/// process that is gone.
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    Some(rest.split_whitespace().map(str::to_string).collect())
}

/// Whether `pid` exists and is not a zombie.
fn running(pid: u32) -> bool {
    stat_fields(pid).is_some_and(|fields| fields[0] != "Z")
}

fn parent_of(pid: u32) -> u32 {
    stat_fields(pid).expect("the process runs")[1]
        .parse()
        .unwrap()
}

fn comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .expect("the process runs")
        .trim()
        .to_string()
}

/// The line of `/proc/<pid>/cgroup`, as the host sees it.
fn cgroup_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .expect("the process runs")
        .trim()
        .to_string()
}

fn ns_of(pid: u32, kind: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/{kind}"))
        .unwrap_or_else(|e| panic!("reading /proc/{pid}/ns/{kind}: {e}"))
        .to_string_lossy()
        .into_owned()
}

fn procs_in(cgroup: &Path) -> BTreeSet<u32> {
    std::fs::read_to_string(cgroup.join("cgroup.procs"))
        .expect("reading cgroup.procs")
        .lines()
        .map(|pid| pid.parse().unwrap())
        .collect()
}

const BOX_ID: &str = "0191e0c8-0000-7000-8000-000000000001";
const SIBLING_ID: &str = "0191e0c8-0000-7000-8000-000000000002";
const DESTROY_LIMIT: Duration = Duration::from_secs(10);

/// A box's supervisor and program, a program that enters the box and the
/// shim that starts it are all in the box's cgroup from the start, and see
/// it as the root. The box has no cgroup below its own and can reach no
/// other box's. The daemon's own cgroup holds the daemon and the spawner
/// only. A socket made for a box is made by a process in the box's cgroup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn everything_of_a_box_starts_in_its_cgroup() {
    let Some(fixture) = Fixture::new("everything_of_a_box_starts_in_its_cgroup", true) else {
        return;
    };
    let root = fixture.root();
    let cgroup = root.create_box(BOX_ID).expect("the box's cgroup");
    let sibling = root.create_box(SIBLING_ID).expect("the sibling's cgroup");
    let in_box = format!("0::{}/boxes/{BOX_ID}", root.name());
    let in_supervisor = format!("0::{}/supervisor", root.name());

    let boxed = fixture
        .launch("placed", Some(&cgroup), None, &[], &["HOLD:/run/release"])
        .await;
    let supervisor = boxed.child.id();
    let program = eventually("the box has its program", || init_of(supervisor).ok());
    assert_eq!(cgroup_of(supervisor), in_box);
    assert_eq!(cgroup_of(program), in_box);

    // A stop leaves the supervisor out of what it signals, and nothing else.
    assert!(fixture.spawner.supervises(supervisor));
    assert!(!fixture.spawner.supervises(program));

    // What `ps` shows: one spawner, and a supervisor per box.
    let spawner = parent_of(supervisor);
    assert_eq!(comm(spawner), "minimal-spawner");
    assert_eq!(parent_of(spawner), std::process::id());
    assert_eq!(cgroup_of(spawner), in_supervisor);
    assert_eq!(comm(supervisor), "minimal-box");
    let cmdline = std::fs::read(format!("/proc/{supervisor}/cmdline")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&cmdline).trim_end_matches('\0'),
        "minimal-box"
    );

    // The entered program tries to reach the sibling box: by the names the
    // sibling could have from inside this box, by the sibling's path on
    // the host, and from a user namespace of its own where it is root.
    let nested = format!("NESTED:{SIBLING_ID}");
    let spellings = [
        format!("/sys/fs/cgroup/{SIBLING_ID}/cgroup.procs"),
        format!("/sys/fs/cgroup/../{SIBLING_ID}/cgroup.procs"),
        sibling.path().join("cgroup.procs").display().to_string(),
    ];
    let mut probe_args = vec!["MKDIR:/sys/fs/cgroup/sub".to_string()];
    probe_args.extend(spellings.iter().map(|path| format!("WRITE:{path}")));
    probe_args.extend([nested, "HOLD:/run/release-entered".to_string()]);
    let mut enter = boxed
        .child
        .entrance()
        .command("/usr/bin/probe", &probe_args);
    enter.stdin(Stdio::Null).stdout(Stdio::MakePipe);
    let mut entered = enter.spawn().expect("entering the box");
    let entered_report = Report::read(entered.stdout.take().unwrap());
    let shim = entered.id();
    let entered_program = eventually("the shim has its program", || init_of(shim).ok());
    assert_eq!(comm(shim), "minimal-enter");
    assert_eq!(parent_of(shim), spawner);
    assert_eq!(cgroup_of(shim), in_box);
    assert_eq!(cgroup_of(entered_program), in_box);

    // Past its nested attempt, the entered probe only holds.
    entered_report.wait_for("nested sibling reached");
    assert_eq!(
        procs_in(cgroup.path()),
        BTreeSet::from([supervisor, program, shim, entered_program]),
        "the box's cgroup holds the box's processes and nothing else"
    );
    assert_eq!(
        procs_in(&root.dir().join("supervisor")),
        BTreeSet::from([std::process::id(), spawner]),
        "the daemon's cgroup holds the daemon and the spawner only"
    );
    let below: Vec<_> = std::fs::read_dir(cgroup.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();
    assert!(below.is_empty(), "the box made a cgroup: {below:?}");

    // A socket for a box that runs nothing: a process is created in the
    // box's cgroup to make it, which the cgroup's counter of processes
    // records, and no process stays behind.
    let socket = fixture
        .spawner
        .socket(Some(&sibling), false, false)
        .expect("a socket for the sibling box");
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes one `c_int` through live pointers.
    let got = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut kind).cast(),
            &raw mut len,
        )
    };
    assert_eq!((got, kind), (0, libc::SOCK_STREAM));
    if root.controllers().pids {
        let peak = std::fs::read_to_string(sibling.path().join("pids.peak"))
            .expect("the kernel counts a cgroup's processes");
        assert_eq!(peak.trim(), "1", "one process made the socket");
    }
    assert!(!sibling.populated().unwrap());
    assert_eq!(
        procs_in(&root.dir().join("supervisor")),
        BTreeSet::from([std::process::id(), spawner])
    );

    boxed.release("release-entered");
    let status = entered.exited().await;
    assert!(status.success(), "{status:?}");
    let seen = entered_report.finish();
    assert_eq!(seen["self_cgroup"], "0::/", "{seen:?}");
    assert_ne!(seen["mkdir /sys/fs/cgroup/sub"], "errno 0", "{seen:?}");
    for path in &spellings {
        assert_ne!(seen[&format!("open {path}")], "errno 0", "{seen:?}");
    }
    assert_eq!(seen["nested self_cgroup"], "0::/", "{seen:?}");
    assert_ne!(seen["nested mkdir"], "errno 0", "{seen:?}");
    assert_eq!(seen["nested sibling reached"], "0", "{seen:?}");

    boxed.release("release");
    let status = boxed.child.exited().await;
    assert!(status.success(), "{status:?}");
    assert_eq!(boxed.report.finish()["self_cgroup"], "0::/");

    cgroup
        .destroy(DESTROY_LIMIT)
        .await
        .expect("the box's cgroup goes");
    sibling
        .destroy(DESTROY_LIMIT)
        .await
        .expect("the sibling's cgroup goes");
}

/// A daemon with a cgroup root runs no container in its own cgroup: a
/// container that belongs to no box gets a cgroup of its own, with the CPU
/// weight its sandbox asked for, and the cgroup goes when the container
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_container_of_no_box_gets_a_cgroup_of_its_own() {
    let Some(fixture) = Fixture::new("a_container_of_no_box_gets_a_cgroup_of_its_own", true) else {
        return;
    };
    let root = fixture.root();
    let build = fixture
        .launch_weighted(
            "unboxed",
            None,
            None,
            &[],
            &["HOLD:/run/release"],
            Some(300),
        )
        .await;
    let supervisor = build.child.id();
    let program = eventually("the container has its program", || init_of(supervisor).ok());
    let own = root.dir().join("boxes/build-0");
    let in_own = format!("0::{}/boxes/build-0", root.name());
    assert_eq!(cgroup_of(supervisor), in_own);
    assert_eq!(cgroup_of(program), in_own);
    if root.controllers().cpu {
        assert_eq!(
            std::fs::read_to_string(own.join("cpu.weight"))
                .unwrap()
                .trim(),
            "300"
        );
    }
    assert_eq!(
        procs_in(&root.dir().join("supervisor")).len(),
        2,
        "the daemon's cgroup holds the daemon and the spawner only"
    );

    build.release("release");
    assert!(build.child.exited().await.success());
    assert_eq!(build.report.finish()["self_cgroup"], "0::/");
    eventually("the container's cgroup is removed", || {
        (!own.exists()).then_some(())
    });
}

/// A program that enters a box is in every namespace of the box's program,
/// the PID namespace included, which the box's supervisor is not in. Its
/// exit status reaches the requester. A socket made in the box's network
/// namespace is in that namespace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entered_program_is_in_every_namespace_of_the_box() {
    let Some(fixture) = Fixture::new("an_entered_program_is_in_every_namespace_of_the_box", false)
    else {
        return;
    };
    let boxed = fixture
        .launch(
            "joined",
            None,
            Some(NetPlan::isolated()),
            &[],
            &["HOLD:/run/release"],
        )
        .await;
    let supervisor = boxed.child.id();
    let program = eventually("the box has its program", || init_of(supervisor).ok());
    let kinds = ["user", "mnt", "pid", "net", "ipc", "cgroup", "uts"];

    let mut args: Vec<String> = kinds.iter().map(|kind| format!("NS:{kind}")).collect();
    args.push("EXIT:42".to_string());
    let mut enter = boxed.child.entrance().command("/usr/bin/probe", &args);
    enter.stdin(Stdio::Null);
    let output = tokio::task::block_in_place(|| enter.output()).expect("entering the box");
    assert_eq!(output.status.exit_code, Some(42), "{:?}", output.status);
    let seen = String::from_utf8_lossy(&output.stdout);
    for kind in kinds {
        let line = format!("ns {kind}: {}", ns_of(program, kind));
        assert!(seen.lines().any(|l| l == line), "no `{line}` in:\n{seen}");
    }
    assert_ne!(
        ns_of(program, "pid"),
        ns_of(supervisor, "pid"),
        "the supervisor stays outside the PID namespace it made"
    );
    for kind in ["user", "mnt", "pid", "net", "ipc", "cgroup"] {
        assert_ne!(
            ns_of(program, kind),
            ns_of(std::process::id(), kind),
            "the box has its own {kind} namespace"
        );
    }

    let socket = boxed
        .child
        .entrance()
        .socket(false, true)
        .expect("a socket in the box's network namespace");
    // SAFETY: `SIOCGSKNS` takes no argument and returns a descriptor of the
    // socket's network namespace.
    let netns = unsafe { libc::ioctl(socket.as_raw_fd(), 0x894C) };
    assert!(netns >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: a fresh descriptor that nothing else owns.
    let netns = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(netns) });
    assert_eq!(
        netns.metadata().unwrap().ino(),
        std::fs::metadata(format!("/proc/{supervisor}/ns/net"))
            .unwrap()
            .ino()
    );

    boxed.release("release");
    assert!(boxed.child.exited().await.success());
}

/// Nothing outlives what asked for it. Killing an entered program's shim
/// ends the program, and so does dropping its handle. When the spawner
/// dies, every box dies with it and its handle says why, and the next
/// request starts a new spawner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_dies_with_its_handle_and_a_box_with_its_spawner() {
    let Some(fixture) = Fixture::new(
        "a_job_dies_with_its_handle_and_a_box_with_its_spawner",
        false,
    ) else {
        return;
    };
    let boxed = fixture
        .launch("mortal", None, None, &[], &["HOLD:/run/release"])
        .await;
    let supervisor = boxed.child.id();
    let program = eventually("the box has its program", || init_of(supervisor).ok());
    let spawner = parent_of(supervisor);

    let enter = |hold: &str| {
        let mut command = boxed
            .child
            .entrance()
            .command("/usr/bin/probe", [format!("HOLD:/run/{hold}")]);
        command
            .stdin(Stdio::Null)
            .stdout(Stdio::Null)
            .stderr(Stdio::Null);
        let entered = command.spawn().expect("entering the box");
        let inside = eventually("the shim has its program", || init_of(entered.id()).ok());
        (entered, inside)
    };

    let (killed, inside) = enter("never-a");
    killed.kill();
    let status = killed.exited().await;
    assert_eq!(status.code, 128 + libc::SIGKILL, "{status:?}");
    eventually("the killed shim's program is gone", || {
        (!running(inside)).then_some(())
    });

    let (dropped, inside) = enter("never-b");
    let shim = dropped.id();
    drop(dropped);
    eventually("the dropped handle's shim is gone", || {
        (!running(shim)).then_some(())
    });
    eventually("the dropped handle's program is gone", || {
        (!running(inside)).then_some(())
    });
    assert!(running(program), "the box itself runs on");

    // SAFETY: `kill` of the spawner process, which this process started.
    assert_eq!(
        unsafe { libc::kill(spawner as libc::pid_t, libc::SIGKILL) },
        0
    );
    let status = boxed.child.exited().await;
    assert_eq!(status.code, sandbox::ExitStatus::FAILURE, "{status:?}");
    assert_eq!(status.reason, "the spawner exited");
    eventually("the box's supervisor is gone", || {
        (!running(supervisor)).then_some(())
    });
    eventually("the box's program is gone", || {
        (!running(program)).then_some(())
    });

    let again = fixture.launch("after", None, None, &[], &["EXIT:7"]).await;
    let status = again.child.exited().await;
    assert_eq!(status.exit_code, Some(7), "{status:?}");
}

/// A program entered on a terminal leads a session with that terminal as
/// its controlling terminal. A shell with job control then puts a
/// background job in a process group of its own, and a SIGTERM to the
/// program's handle still ends that job, through the shim.
///
/// Needs a static busybox on the host, for a shell in the box's rootfs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_ends_the_jobs_of_a_program_entered_on_a_terminal() {
    let busybox = Path::new("/usr/bin/busybox");
    let is_static = std::process::Command::new("file")
        .arg(busybox)
        .output()
        .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("statically linked"));
    if !is_static {
        eprintln!("skipping: no static busybox at {}", busybox.display());
        return;
    }
    let Some(fixture) = Fixture::new(
        "a_stop_ends_the_jobs_of_a_program_entered_on_a_terminal",
        false,
    ) else {
        return;
    };
    let boxed = fixture
        .launch(
            "terminal",
            None,
            None,
            &[("sh", busybox), ("sleep", busybox)],
            &["HOLD:/run/release"],
        )
        .await;

    let (mut master, mut slave) = (-1, -1);
    // SAFETY: `openpty` writes two descriptors through live pointers. The
    // name, termios and size pointers may be null.
    let opened = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(opened, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: `openpty` succeeded, so both descriptors are open and ours.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    let terminal = std::fs::File::from(slave.try_clone().unwrap())
        .metadata()
        .unwrap()
        .rdev();

    // The job ignores SIGTERM and SIGHUP, so only the shim's kill of the
    // session ends it. The master stays open, so no hangup does.
    let mut enter = boxed.child.entrance().command(
        "/usr/bin/sh",
        ["-c", "set -m; trap '' TERM HUP; /usr/bin/sleep 600 & wait"],
    );
    enter
        .env("PATH", "/usr/bin")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    let entered = enter.spawn().expect("entering the box on a terminal");
    let children_of = |pid: u32| -> Vec<u32> {
        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
            .unwrap_or_default()
            .split_whitespace()
            .map(|child| child.parse().unwrap())
            .collect()
    };
    let (shell, job) = eventually("the shell runs its job", || {
        let shell = init_of(entered.id()).ok()?;
        Some((shell, *children_of(shell).first()?))
    });
    let shell_stat = stat_fields(shell).expect("the shell runs");
    let job_stat = eventually("the job is in its own group", || {
        stat_fields(job).filter(|job| job[2] != shell_stat[2])
    });
    assert_eq!(
        shell_stat[3],
        shell.to_string(),
        "the shell leads a session"
    );
    assert_eq!(
        job_stat[3], shell_stat[3],
        "the job is in the shell's session"
    );
    assert_eq!(
        shell_stat[4],
        terminal.to_string(),
        "the terminal is the session's controlling terminal"
    );

    entered.signal(libc::SIGTERM, SignalTarget::Job);
    entered.exited().await;
    let deadline = Instant::now() + SHIM_ESCALATION + Duration::from_secs(10);
    while running(job) {
        assert!(Instant::now() < deadline, "the job outlived the stop");
        std::thread::sleep(Duration::from_millis(50));
    }

    drop(master);
    boxed.release("release");
    assert!(boxed.child.exited().await.success());
}
