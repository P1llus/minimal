//! The jobs of a spawner, done by the calling process.
//!
//! A spawner process calls these for the daemon. A process with no spawner
//! of its own calls them directly. Either way the caller is the parent of
//! what a job creates.
//!
//! A child that execs at once, or makes raw syscalls only, is created with
//! `clone3(CLONE_INTO_CGROUP)` and is in the box's cgroup from its first
//! instruction. A container's supervisor keeps running library code, which a
//! raw `clone3` child cannot do safely on every libc, so hakoniwa forks it
//! and it joins the cgroup as its first step, before it creates a namespace.
//! In both cases no code of the box runs outside the box's cgroup.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use super::enter::{self, ShimArgs};
use super::wire::{ContainerSpec, Enter, Run, Session};
use super::{ENTER_MODE, ExitStatus, title::Title};

/// How long a container's setup may take: its namespaces, its ID maps, its
/// network and its mounts. Far more than a healthy host needs.
const SETUP_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// A container this process started.
pub(crate) struct Container {
    /// hakoniwa's handle on the supervisor.
    pub(crate) child: hakoniwa::Child,
    /// The supervisor, pinned.
    pub(crate) supervisor: OwnedFd,
    /// The container's network namespace, when it has one of its own.
    pub(crate) netns: Option<OwnedFd>,
}

/// A shim this process started to run a program in a running container.
pub(crate) struct Shim {
    pub(crate) pid: u32,
    pub(crate) pidfd: OwnedFd,
}

fn hakoniwa_container(
    spec: &ContainerSpec,
    cgroup: Option<OwnedFd>,
) -> io::Result<hakoniwa::Container> {
    use hakoniwa::MountOptions as Options;

    let mut container = hakoniwa::Container::new();
    container
        .rootfs(&spec.rootfs)
        .map_err(io::Error::other)?
        // The one entry of the id map: the box's processes hold no other id,
        // and with `no_new_privs` an exec as this uid leaves every
        // capability set empty.
        .uidmap(spec.uid)
        .gidmap(spec.gid)
        .devfsmount("/dev")
        .tmpfsmount("/tmp");
    // The box's own devpts instance, with a limit on its PTY count: PTYs
    // are one pool for the machine, and without a per-instance limit one
    // box can take them all.
    container.mount(
        "devpts",
        "/dev/pts",
        "devpts",
        Options::NOSUID | Options::NOEXEC,
        Some(crate::config::BOX_DEVPTS_OPTIONS.to_string()),
    );
    // Every box maps onto the daemon's one kernel uid, so IPC permission
    // bits cannot keep boxes apart. Only the namespace does.
    container.unshare(hakoniwa::Namespace::Ipc);
    // Rooted at the cgroup the supervisor is in when it unshares: the box
    // cgroup, which it joins first. With that root a process of the box can
    // name no other cgroup, another box's included.
    container.unshare(hakoniwa::Namespace::Cgroup);
    if let Some(dir) = cgroup {
        container.cgroup(dir);
        // The box's view of its own cgroup, where a runtime looks for its
        // limits. Read-only, and the namespace root is all it shows.
        container.mount(
            "cgroup2",
            "/sys/fs/cgroup",
            "cgroup2",
            Options::RDONLY | Options::NOSUID | Options::NODEV | Options::NOEXEC,
            None,
        );
    }
    if spec.netns {
        container.unshare(hakoniwa::Namespace::Network);
    }
    for mount in &spec.mounts {
        container.mount(
            &mount.source,
            &mount.target,
            &mount.fstype,
            Options::from_bits_truncate(mount.options),
            mount.data.clone(),
        );
    }
    if spec.mount_fallback {
        container.bindmount_rw("/proc", "/proc");
        container.runctl(hakoniwa::Runctl::MountFallback);
    }
    for (original, link) in &spec.symlinks {
        container.symlink(original, link);
    }
    if let Some(hostname) = &spec.hostname {
        container.unshare(hakoniwa::Namespace::Uts);
        container.hostname(hostname);
    }
    Ok(container)
}

/// Starts a container and its program. `titled` shows the supervisor as
/// `minimal-box` in `ps`, for a caller that is a spawner process.
pub(crate) fn run(
    run: &Run,
    stdio: [OwnedFd; 3],
    cgroup: Option<OwnedFd>,
    titled: bool,
) -> io::Result<Container> {
    let mut container = hakoniwa_container(&run.container, cgroup)?;
    match run.session {
        Session::New => {
            container.runctl(hakoniwa::Runctl::SupervisorNewSession);
        }
        Session::NewWithTerminal => {
            container.runctl(hakoniwa::Runctl::SupervisorNewSession);
            container.runctl(hakoniwa::Runctl::NewSession);
        }
        // The supervisor stays in the session whose terminal the program
        // takes the foreground of.
        Session::Foreground => {}
    }
    let mut command = container.command(&run.program);
    command.args(&run.args);
    if let Some(dir) = &run.cwd {
        command.current_dir(dir);
    }
    command.envs(
        run.env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    crate::with_box_closure(
        &container,
        &mut command,
        run.lo_up,
        run.ping_gid,
        run.gate.clone(),
        run.session,
    );
    let [stdin, stdout, stderr] = stdio;
    command
        .stdin(hakoniwa::Stdio::from(stdin))
        .stdout(hakoniwa::Stdio::from(stdout))
        .stderr(hakoniwa::Stdio::from(stderr));
    // The spawner serves every box from one thread, and it waits here for
    // the container's setup. A mount whose source does not answer must not
    // hold every other box.
    command.setup_timeout(SETUP_LIMIT);
    let spawned = {
        // The supervisor is a fork of this process and keeps the title.
        let _title = titled.then(|| Title::set(c"minimal-box"));
        command.spawn()
    };
    let child = spawned.map_err(io::Error::other)?;
    let supervisor = enter::pidfd_open(child.id()).map_err(io::Error::other)?;
    // The supervisor made its namespaces before the spawn returned, and it
    // is this process's child, so its pid is its own until it is reaped.
    let netns = if run.container.netns {
        Some(std::fs::File::open(format!("/proc/{}/ns/net", child.id()))?.into())
    } else {
        None
    };
    Ok(Container {
        child,
        supervisor,
        netns,
    })
}

/// The first process of the container whose supervisor is `supervisor`, with
/// a pidfd that is certainly its own: the supervisor still lists the pid as
/// its child after the pin, so the pid was not reused in between. `None`
/// until the supervisor has forked it, and once it has exited.
pub(crate) fn pinned_init(supervisor: u32) -> Option<(u32, OwnedFd)> {
    let pid = enter::init_of(supervisor).ok()?;
    let pinned = enter::pidfd_open(pid).ok()?;
    (enter::init_of(supervisor).ok()? == pid).then_some((pid, pinned))
}

/// The terminal of this process's session, if it has one.
fn terminal() -> Option<std::fs::File> {
    std::fs::File::options()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/tty")
        .ok()
}

/// Makes `group` the foreground process group of `terminal`.
fn set_foreground(terminal: &std::fs::File, group: libc::pid_t) {
    // SAFETY: plain syscalls on this thread's signal mask and the terminal.
    unsafe {
        // A background group that changes the foreground group is stopped
        // with SIGTTOU unless it blocks the signal.
        let mut ttou: libc::sigset_t = std::mem::zeroed();
        let mut before: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut ttou);
        libc::sigaddset(&raw mut ttou, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const ttou, &raw mut before);
        libc::tcsetpgrp(terminal.as_raw_fd(), group);
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const before, std::ptr::null_mut());
    }
}

/// Makes this process's group the foreground group of its terminal again,
/// once a job that had taken the foreground is gone. Does nothing for a
/// process with no terminal, and nothing while another group, such as the
/// user's shell, has the foreground.
pub(crate) fn retake_foreground(job_group: u32) {
    let Some(terminal) = terminal() else {
        return;
    };
    // SAFETY: `tcgetpgrp` and `getpgrp` only read.
    if unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) } == job_group as libc::pid_t {
        set_foreground(&terminal, unsafe { libc::getpgrp() });
    }
}

/// The program a foreground job's first process runs: its one long-lived
/// child. `None` before it is started and once it is gone.
pub(crate) fn foreground_program(init: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{init}/task/{init}/children"))
        .ok()?
        .split_ascii_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Whether `pid` is stopped by a job control signal.
pub(crate) fn stopped(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('T'))
    })
}

/// Does for a stopped foreground job what a shell's job expects of the
/// command in front of it, as `sudo` does for the command it runs.
///
/// The job's process group `job_group` holds the terminal and has stopped,
/// which the user's shell cannot see: the shell waits for the process that
/// asked for the job. So this process takes the terminal back and stops
/// its own process group, the requester included. The shell then sees its
/// job stopped and takes the terminal. When the shell continues the job,
/// this process runs on from here: it hands the terminal back to the job's
/// group, if the shell continued it in the foreground, and continues it.
///
/// Does nothing unless the job's group is the terminal's foreground group.
pub(crate) fn suspend_with(job_group: u32) {
    let job_group = job_group as libc::pid_t;
    let Some(terminal) = terminal() else {
        return;
    };
    // SAFETY: plain syscalls on the terminal and on process groups this
    // process started or belongs to.
    unsafe {
        if libc::tcgetpgrp(terminal.as_raw_fd()) != job_group {
            return;
        }
        let own = libc::getpgrp();
        set_foreground(&terminal, own);
        libc::kill(0, libc::SIGTSTP);
        // A process with one thread has stopped inside the call above. One
        // with more stops a moment after it. Both run on from here only
        // once they are continued.
        std::thread::sleep(std::time::Duration::from_millis(20));
        if libc::tcgetpgrp(terminal.as_raw_fd()) == own {
            set_foreground(&terminal, job_group);
        }
        libc::kill(-job_group, libc::SIGCONT);
    }
}

/// Whether the process a pidfd names has exited.
pub(crate) fn exited(pidfd: BorrowedFd<'_>) -> bool {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` reads and writes the one `pollfd` it is given.
    unsafe { libc::poll(&raw mut poll, 1, 0) > 0 }
}

/// Sends `signal` to the process a pidfd names. A process that has exited
/// takes no signal, and that is no error.
pub(crate) fn signal(pidfd: BorrowedFd<'_>, signal: libc::c_int) {
    // SAFETY: `pidfd_send_signal` with no `siginfo` reads no memory.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}

/// What a hakoniwa status says, in this crate's words.
pub(crate) fn exit_status(status: hakoniwa::ExitStatus) -> ExitStatus {
    ExitStatus {
        code: status.code,
        exit_code: status.exit_code,
        reason: status.reason,
    }
}

/// How a reaped shim ended, in the shape a container's status has.
pub(crate) fn shim_status(status: libc::c_int) -> ExitStatus {
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        ExitStatus {
            code,
            exit_code: Some(code),
            reason: format!("the program exited with code {code}"),
        }
    } else {
        let signal = libc::WTERMSIG(status);
        ExitStatus {
            code: 128 + signal,
            exit_code: None,
            reason: format!("the enter shim received signal {signal}"),
        }
    }
}

/// Reaps `pid`, a child of this process. `None` while it still runs and
/// `block` is false.
pub(crate) fn reap(pid: u32, block: bool) -> io::Result<Option<libc::c_int>> {
    let mut status = 0;
    loop {
        // SAFETY: `waitpid` writes the status through a live pointer.
        let reaped = unsafe {
            libc::waitpid(
                pid as libc::pid_t,
                &raw mut status,
                if block { 0 } else { libc::WNOHANG },
            )
        };
        if reaped == 0 {
            return Ok(None);
        }
        if reaped > 0 {
            return Ok(Some(status));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// `struct clone_args` up to the cgroup field.
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const CLONE_PIDFD: u64 = 0x1000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Creates a child of this process that starts in `cgroup` when one is
/// given. Returns `0` in the child, and the child's pid and pidfd in the
/// parent.
///
/// # Safety
///
/// The child is a copy made by the raw syscall, so the C library's own
/// record of the thread is stale in it. It may only make direct syscalls
/// until it execs or exits.
pub(super) unsafe fn clone_into(
    cgroup: Option<BorrowedFd<'_>>,
) -> io::Result<(libc::pid_t, Option<OwnedFd>)> {
    let mut pidfd: libc::c_int = -1;
    let mut args = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&raw mut pidfd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    if let Some(cgroup) = cgroup {
        args.flags |= CLONE_INTO_CGROUP;
        args.cgroup = cgroup.as_raw_fd() as u64;
    }
    // SAFETY: `args` is a valid `clone_args` of the size passed, and `pidfd`
    // outlives the call.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &raw mut args,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    match pid {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok((0, None)),
        // SAFETY: the kernel returned a fresh pidfd that nothing else owns.
        pid => Ok((
            pid as libc::pid_t,
            Some(unsafe { OwnedFd::from_raw_fd(pidfd) }),
        )),
    }
}

/// A copy of `fd` numbered 10 or above, clear of the numbers a child puts
/// its descriptors on.
fn lifted(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: `fcntl` on a live descriptor.
    let copy = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

fn c_string(bytes: &[u8], what: &str) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} holds a NUL byte"),
        )
    })
}

/// Starts a program in the running container whose first process is
/// `init_pid`, pinned as `init`: `exe`, this same binary, runs as the enter
/// shim in `cgroup` and forks the program into the container.
pub(crate) fn enter(
    exe: &Path,
    init_pid: u32,
    init: BorrowedFd<'_>,
    enter: &Enter,
    stdio: [OwnedFd; 3],
    cgroup: Option<BorrowedFd<'_>>,
) -> io::Result<Shim> {
    use std::os::fd::AsFd as _;

    let join = enter::namespaces_to_join(init_pid).map_err(io::Error::other)?;
    // The namespaces were read by pid. The pid named the box's first process
    // for as long as that process has not exited.
    if exited(init) {
        return Err(io::Error::other("the box's first process has exited"));
    }
    let shim = ShimArgs {
        join,
        chdir: enter.cwd.clone(),
        argv: std::iter::once(&enter.program)
            .chain(&enter.args)
            .map(Into::into)
            .collect(),
    };
    let exe_c = c_string(exe.as_os_str().as_bytes(), "the executable's path")?;
    let mut argv = vec![
        c"minimal-enter".to_owned(),
        c_string(ENTER_MODE.as_bytes(), "the mode")?,
    ];
    for word in shim.to_command_line() {
        argv.push(c_string(word.as_bytes(), "an argument")?);
    }
    let envp = enter
        .env
        .iter()
        .map(|(key, value)| c_string(format!("{key}={value}").as_bytes(), "a variable"))
        .collect::<io::Result<Vec<_>>>()?;
    let pointers = |strings: &[CString]| -> Vec<*const libc::c_char> {
        strings
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    };
    let (argv_p, envp_p) = (pointers(&argv), pointers(&envp));

    // Where the child puts them: stdin, stdout, stderr, then the pidfd.
    let placed = [
        lifted(stdio[0].as_fd())?,
        lifted(stdio[1].as_fd())?,
        lifted(stdio[2].as_fd())?,
        lifted(init)?,
    ];
    drop(stdio);
    // Close-on-exec: an exec that works closes it, and one that fails
    // writes its errno first.
    let (mut failed, failure) = io::pipe()?;
    // SAFETY: `getpid` reads this process's id.
    let parent = unsafe { libc::getpid() };

    // SAFETY: the child calls `dup2`, `prctl`, `getppid`, `execve`, `write`
    // and `_exit` on memory prepared above, and nothing else.
    let (pid, pidfd) = unsafe { clone_into(cgroup)? };
    if pid == 0 {
        // SAFETY: see above. The child never returns.
        unsafe {
            for (number, fd) in placed.iter().enumerate() {
                if libc::dup2(fd.as_raw_fd(), number as libc::c_int) < 0 {
                    report_and_exit(failure.as_raw_fd());
                }
            }
            // The shim dies with whoever started it, and its program with it.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            libc::execve(exe_c.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
            report_and_exit(failure.as_raw_fd());
        }
    }
    drop(failure);
    drop(placed);
    let mut errno = [0u8; 4];
    if io::Read::read_exact(&mut failed, &mut errno).is_ok() {
        let _ = reap(pid as u32, true);
        let error = io::Error::from_raw_os_error(i32::from_le_bytes(errno));
        return Err(io::Error::new(
            error.kind(),
            format!("running {} as the enter shim: {error}", exe.display()),
        ));
    }
    Ok(Shim {
        pid: pid as u32,
        pidfd: pidfd.expect("the parent gets the child's pidfd"),
    })
}

/// Writes `errno` to `to` and exits. For a child between `clone3` and `exec`.
unsafe fn report_and_exit(to: libc::c_int) -> ! {
    // SAFETY: plain syscalls on stack memory.
    unsafe {
        let errno = (*libc::__errno_location()).to_le_bytes();
        libc::write(to, errno.as_ptr().cast(), errno.len());
        libc::_exit(127)
    }
}

/// The report of a job's child: the step it failed at, 0 for none, and the
/// errno of the failure.
const REPORT_LEN: usize = 5;

/// The step a socket's child fails at when it cannot join the namespaces.
const SOCKET_JOIN: u8 = 1;

/// Creates a socket in `cgroup`, and in the user and network namespaces of
/// the process `netns_of` when one is given, and returns it. A child of this
/// process creates it and passes it back.
pub(crate) fn socket(
    netns_of: Option<u32>,
    v6: bool,
    datagram: bool,
    cgroup: Option<BorrowedFd<'_>>,
) -> io::Result<OwnedFd> {
    let namespaces = netns_of.map(Namespaces::of).transpose()?;
    let join = namespaces.as_ref().map(Namespaces::raw);
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let kind = if datagram {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    // SAFETY: the child calls `setns`, `socket`, `sendmsg` and `_exit` on
    // descriptors opened above and on stack memory, and nothing else.
    let (pid, _pidfd) = unsafe { clone_into(cgroup)? };
    if pid == 0 {
        // SAFETY: see above. The child never returns.
        unsafe { socket_child(join, theirs.as_raw_fd(), domain, kind) }
    }
    drop(theirs);
    let received = receive_report(&ours);
    let _ = reap(pid as u32, true);
    match received? {
        Some((0, _, Some(socket))) => Ok(socket),
        Some((SOCKET_JOIN, error, _)) => Err(io::Error::new(
            error.kind(),
            format!("joining the box's network namespace: {error}"),
        )),
        Some((step, error, _)) if step != 0 => Err(error),
        _ => Err(io::Error::other(
            "the process that creates a box's socket exited without its result",
        )),
    }
}

/// The user and network namespaces of a container's supervisor, which a
/// job's child joins.
pub(super) struct Namespaces {
    user: std::fs::File,
    net: std::fs::File,
}

impl Namespaces {
    /// Those of `pid`, which the caller knows to be the supervisor: it is
    /// the caller's child and not reaped.
    pub(super) fn of(pid: u32) -> io::Result<Self> {
        let open = |kind: &str| std::fs::File::open(format!("/proc/{pid}/ns/{kind}"));
        Ok(Self {
            user: open("user")?,
            net: open("net")?,
        })
    }

    pub(super) fn raw(&self) -> (libc::c_int, libc::c_int) {
        (self.user.as_raw_fd(), self.net.as_raw_fd())
    }
}

/// Joins a user namespace and then a network namespace. The user namespace
/// comes first: the caller holds the capability to join the network
/// namespace only inside it.
///
/// # Safety
///
/// Direct syscalls only, so a `clone3` child may call it.
pub(super) unsafe fn join((user, net): (libc::c_int, libc::c_int)) -> bool {
    // SAFETY: `setns` reads two integers.
    unsafe {
        libc::setns(user, libc::CLONE_NEWUSER) == 0 && libc::setns(net, libc::CLONE_NEWNET) == 0
    }
}

/// The errno of the calling thread.
///
/// # Safety
///
/// Reads thread-local memory, which a `clone3` child has a copy of.
pub(super) unsafe fn errno() -> libc::c_int {
    // SAFETY: the C library's errno of this thread is always readable.
    unsafe { *libc::__errno_location() }
}

/// The child of [`socket`]: joins, creates, reports, exits.
///
/// # Safety
///
/// Only for the child of a `clone3`. It never returns.
unsafe fn socket_child(
    namespaces: Option<(libc::c_int, libc::c_int)>,
    out: libc::c_int,
    domain: libc::c_int,
    kind: libc::c_int,
) -> ! {
    // SAFETY: direct syscalls on the parent's descriptors and stack memory.
    unsafe {
        if namespaces.is_some_and(|namespaces| !join(namespaces)) {
            send_report(out, SOCKET_JOIN, errno(), -1);
        }
        let fd = libc::socket(domain, kind | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            send_report(out, 2, errno(), -1);
        }
        send_report(out, 0, 0, fd)
    }
}

/// Sends the report of a job's child, with the descriptor it made when it
/// made one, and ends the child.
///
/// # Safety
///
/// Only for the child of a `clone3`. It never returns.
pub(super) unsafe fn send_report(
    out: libc::c_int,
    step: u8,
    errno: libc::c_int,
    fd: libc::c_int,
) -> ! {
    // SAFETY: direct syscalls on the parent's descriptors and stack memory.
    unsafe {
        let mut report = [0u8; REPORT_LEN];
        report[0] = step;
        report[1..].copy_from_slice(&errno.to_le_bytes());
        let mut iov = libc::iovec {
            iov_base: report.as_mut_ptr().cast(),
            iov_len: report.len(),
        };
        let mut control = [0u64; 4];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        if fd >= 0 {
            let bytes = std::mem::size_of::<libc::c_int>() as u32;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(bytes) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(bytes) as _;
            libc::CMSG_DATA(cmsg)
                .cast::<libc::c_int>()
                .write_unaligned(fd);
        }
        libc::sendmsg(out, &raw const msg, 0);
        libc::_exit(0)
    }
}

/// Reads the report of a job's child: the step it failed at, the error of
/// that step, and the descriptor it sent. `None` when it sent no report.
pub(super) fn receive_report(
    sock: &std::os::unix::net::UnixStream,
) -> io::Result<Option<(u8, io::Error, Option<OwnedFd>)>> {
    let mut report = [0u8; REPORT_LEN];
    let mut iov = libc::iovec {
        iov_base: report.as_mut_ptr().cast(),
        iov_len: report.len(),
    };
    let mut control = [0u64; 4];
    // SAFETY: a zeroed `msghdr` is a valid empty one.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    let got = loop {
        // SAFETY: `msg` points at buffers that outlive the call.
        let got = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if got < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break got;
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sent = None;
    // SAFETY: the kernel filled the control buffer, and it is read inside
    // the length the kernel set.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fd = libc::CMSG_DATA(cmsg).cast::<libc::c_int>().read_unaligned();
                sent = Some(OwnedFd::from_raw_fd(fd));
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }
    if got as usize != REPORT_LEN {
        return Ok(None);
    }
    let errno = i32::from_le_bytes([report[1], report[2], report[3], report[4]]);
    Ok(Some((report[0], io::Error::from_raw_os_error(errno), sent)))
}
