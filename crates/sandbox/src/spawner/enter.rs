//! Entering a running box.
//!
//! A program that joins a box later than its first process is started by a
//! shim: this binary, re-executed in the box's cgroup with the box init's
//! pidfd on a fixed descriptor. The shim joins the box's namespaces with one
//! `setns`, forks the program into them, and stays outside the box's PID
//! namespace as the program's parent, so it can report the program's status
//! and end the program's process group when it is told to stop.

use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use nix::sched::CloneFlags;

/// How long the shim gives the injected process group between the SIGTERM it
/// forwards and the SIGKILL that ends the group. Ending an exec is SIGTERM, a
/// grace period, then SIGKILL, so a member that traps SIGTERM can clean up.
///
/// This and [`SHIM_ESCALATION`] are two halves of one timeline and are defined
/// together on purpose: the daemon's SIGKILL of the shim must come after the
/// shim's own group SIGKILL plus [`ESCALATION_MARGIN`]. A shim SIGKILLed first
/// cannot kill the group (`PR_SET_PDEATHSIG` takes the group leader only), so
/// the daemon's SIGKILL is a fallback for a wedged shim, never the normal way
/// an exec ends. Whole seconds, because `alarm(2)` arms whole seconds.
pub const GROUP_GRACE: Duration = Duration::from_secs(2);

/// How long the daemon waits for a SIGTERMed shim to exit before it SIGKILLs
/// it. Longer than [`GROUP_GRACE`] plus [`ESCALATION_MARGIN`], which the const
/// assertion below enforces; [`GROUP_GRACE`] says why.
pub const SHIM_ESCALATION: Duration = Duration::from_secs(5);

/// The slack between the shim's group SIGKILL and the daemon's SIGKILL of the
/// shim: time for the shim to finish its last group scan, reap, and exit.
const ESCALATION_MARGIN: Duration = Duration::from_secs(2);

const _: () = {
    assert!(
        SHIM_ESCALATION.as_secs() > GROUP_GRACE.as_secs() + ESCALATION_MARGIN.as_secs(),
        "the daemon must SIGKILL the shim only after the shim's own group SIGKILL"
    );
    assert!(
        GROUP_GRACE.subsec_nanos() == 0 && GROUP_GRACE.as_secs() > 0,
        "alarm(2) arms whole seconds"
    );
};

/// [`GROUP_GRACE`] as the `alarm(2)` argument the SIGTERM handler arms.
#[allow(clippy::cast_possible_truncation)]
const GROUP_GRACE_ALARM: libc::c_uint = GROUP_GRACE.as_secs() as libc::c_uint;

/// How often the shim's main flow checks, during the grace period, whether the
/// group still has a live member.
const GROUP_POLL: Duration = Duration::from_millis(25);

/// The process-group id (== pid, see `setpgid(0, 0)` in [`shim_main`]) of the
/// process this shim injected into the session, published after spawn so the
/// signal handlers can reach the whole group — the injected program and every
/// descendant it forked — rather than leaving grandchildren reparented to
/// PID 1. `0` before the spawn and again just before the leader is reaped, so
/// a handler can never target a recycled pid.
static CHILD_PGID: AtomicI32 = AtomicI32::new(0);

/// The first SIGTERM or SIGHUP the shim received, `0` until one arrives. The
/// handler claims it with a compare-exchange, so a second signal neither
/// re-sends the group SIGTERM nor re-arms or extends the grace period.
static TERM_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Whether the group has been sent its SIGTERM. Claimed with a swap by
/// whichever of the handler and the main flow first sees both a termination
/// request and a published [`CHILD_PGID`], so the group gets exactly one.
static GROUP_TERMED: AtomicBool = AtomicBool::new(false);

/// Set by the SIGALRM handler once [`GROUP_GRACE`] has run out.
static GRACE_EXPIRED: AtomicBool = AtomicBool::new(false);

/// The descriptor the box init's pidfd is on when the shim starts.
pub(crate) const PIDFD_FD: RawFd = 3;

/// A namespace an injected process can join.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Namespace {
    /// Must be joined in the same `setns` call as any other namespace it owns.
    User,
    Mnt,
    Pid,
    Uts,
    Ipc,
    Cgroup,
    Net,
}

impl Namespace {
    /// Every namespace, in no significant order — a single `setns` call takes
    /// the whole set at once and the kernel sequences it internally.
    const ALL: [Self; 7] = [
        Self::User,
        Self::Mnt,
        Self::Pid,
        Self::Uts,
        Self::Ipc,
        Self::Cgroup,
        Self::Net,
    ];

    /// The namespace an entry name under `/proc/<pid>/ns/` stands for.
    fn from_proc_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|ns| ns.proc_name() == name)
    }

    /// The entry name under `/proc/<pid>/ns/`.
    pub(crate) fn proc_name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mnt => "mnt",
            Self::Pid => "pid",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Cgroup => "cgroup",
            Self::Net => "net",
        }
    }

    /// The `clone(2)` flag `setns` selects this namespace with.
    fn clone_flag(self) -> CloneFlags {
        match self {
            Self::User => CloneFlags::CLONE_NEWUSER,
            Self::Mnt => CloneFlags::CLONE_NEWNS,
            Self::Pid => CloneFlags::CLONE_NEWPID,
            Self::Uts => CloneFlags::CLONE_NEWUTS,
            Self::Ipc => CloneFlags::CLONE_NEWIPC,
            Self::Cgroup => CloneFlags::CLONE_NEWCGROUP,
            Self::Net => CloneFlags::CLONE_NEWNET,
        }
    }

    /// The namespace `pid` is in, as the kernel's `ns:[inode]` identity, or
    /// `None` if this kernel has no such namespace type.
    fn identity(self, pid: Option<u32>) -> Result<Option<String>, EnterError> {
        let who = pid.map_or_else(|| "self".to_string(), |p| p.to_string());
        let path = format!("/proc/{who}/ns/{}", self.proc_name());
        match std::fs::read_link(&path) {
            Ok(target) => Ok(Some(target.to_string_lossy().into_owned())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(EnterError::ReadNamespace { path, source }),
        }
    }
}

/// The namespaces of `leader_pid` that the caller is not already in.
///
/// The set has to be computed, not hardcoded, and asking for one namespace too
/// many is not free. Once `setns` switches our credentials into the sandbox's
/// user namespace, we hold capabilities *there* and nowhere else — so asking in
/// the same call for a namespace the sandbox never unshared, which is therefore
/// still the host's, is refused with `EPERM` rather than quietly ignored.
/// Measured, joining a sandbox that unshared user/mount/PID/UTS/cgroup but left
/// IPC and (for a `HostNet` session) the network alone:
///
/// ```text
///  setns(pidfd, user|mnt)    = ok        setns(pidfd, user|ipc) = EPERM
///  setns(pidfd, user|pid)    = ok        setns(pidfd, user|net) = EPERM
///  setns(pidfd, user|uts)    = ok
///  setns(pidfd, user|cgroup) = ok
/// ```
///
/// Diffing namespace identities against our own yields exactly the set the
/// sandbox created, which is what makes this work across a `HostNet` session
/// (network shared with the daemon, so not joined) and a `NoNet`/`OwnIp` one
/// (network unshared, so joined) without either being a special case.
///
/// # Errors
///
/// [`EnterError::ReadNamespace`] if `/proc` cannot be read for either process;
/// a namespace type this kernel does not implement is skipped, not an error.
pub fn namespaces_to_join(leader_pid: u32) -> Result<Vec<Namespace>, EnterError> {
    Namespace::ALL
        .into_iter()
        .filter_map(|ns| {
            let differs = || {
                Ok(match (ns.identity(Some(leader_pid))?, ns.identity(None)?) {
                    (Some(theirs), Some(ours)) => theirs != ours,
                    // A namespace type the kernel lacks entirely: nothing to join.
                    _ => false,
                })
            };
            match differs() {
                Ok(true) => Some(Ok(ns)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            }
        })
        .collect()
}

/// A failure injecting a process into a session's namespaces.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnterError {
    /// The supervisor's `children` file could not be read. Absent on a kernel
    /// built without `CONFIG_PROC_CHILDREN`; `ENOENT` also means the supervisor
    /// itself is gone, i.e. the session has ended.
    #[error("reading /proc/{pid}/task/{pid}/children (is CONFIG_PROC_CHILDREN enabled?)")]
    ReadChildren {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    /// The supervisor has no children: the session program has exited, and its
    /// namespaces are on their way out with it.
    #[error("sandbox supervisor {pid} has no child process; the session program has exited")]
    NoSessionLeader { pid: u32 },

    /// The supervisor has more than one child, so "the session program" is
    /// ambiguous. hakoniwa forks exactly once, so this means the process
    /// structure this module is written against has changed.
    #[error("sandbox supervisor {pid} has {count} children, expected exactly 1: {children}")]
    AmbiguousSessionLeader {
        pid: u32,
        count: usize,
        children: String,
    },

    /// The `children` file held something that is not a PID.
    #[error("sandbox supervisor {pid} reported an unparseable child pid: {child:?}")]
    MalformedChild { pid: u32, child: String },

    /// A `/proc/<pid>/ns/*` link could not be read while working out which
    /// namespaces the session actually has.
    #[error("reading the namespace link {path}")]
    ReadNamespace {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `pidfd_open(2)` failed. `ESRCH` means the session program exited between
    /// resolving its PID and pinning it.
    #[error("pidfd_open({pid})")]
    PidfdOpen {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    /// `setns(2)` failed. `EPERM` on an otherwise sound setup means one of: the
    /// caller is multi-threaded (which the user namespace forbids), the set
    /// includes a namespace the sandbox never unshared (see
    /// [`namespaces_to_join`]), or the sandbox's user namespace is not owned by
    /// this user — a daemon can only join sandboxes it owns.
    #[error("setns(2) onto the session's namespaces ({namespaces})")]
    Setns {
        namespaces: String,
        #[source]
        source: nix::Error,
    },

    /// The shim was started with arguments it does not read.
    #[error("the enter shim was started with bad arguments: {0}")]
    Usage(String),

    /// The injected program could not be started for a reason a shell would
    /// not report as its own (those are exit codes 127/126). `ENOMEM` from the
    /// fork means the sandbox's PID namespace has no live init left to
    /// reparent to — the session shell exited while we were joining.
    #[error("spawning {program:?} inside the session")]
    Spawn {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The shim could not reap the process it started.
    #[error("waiting for {program:?} inside the session")]
    Wait {
        program: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Resolves the PID of the process hakoniwa exec'd, given the PID of its
/// container supervisor — that is, [`hakoniwa::Child::id()`].
///
/// The supervisor's sole child is the exec'd program (see the module docs), and
/// `/proc/<pid>/task/<pid>/children` names it. The read is race-free against a
/// just-returned `spawn()`: hakoniwa's parent only reports setup-success to the
/// caller *after* the second fork, so by the time a `hakoniwa::Child` exists the
/// child entry does too. It is not race-free against the `execve` that follows,
/// which matters only for reads that depend on it — `/proc/<pid>/environ` in
/// that window still holds the daemon's environment, not the session's.
///
/// # Errors
///
/// [`EnterError::NoSessionLeader`] once the session program has exited, and
/// [`EnterError::ReadChildren`] if `/proc` cannot answer — including on a
/// kernel without `CONFIG_PROC_CHILDREN`.
pub fn init_of(container_pid: u32) -> Result<u32, EnterError> {
    let path = format!("/proc/{container_pid}/task/{container_pid}/children");
    let raw = std::fs::read_to_string(&path).map_err(|source| EnterError::ReadChildren {
        pid: container_pid,
        source,
    })?;

    let children: Vec<&str> = raw.split_ascii_whitespace().collect();
    match children.as_slice() {
        [] => Err(EnterError::NoSessionLeader { pid: container_pid }),
        [child] => child.parse().map_err(|_| EnterError::MalformedChild {
            pid: container_pid,
            child: (*child).to_string(),
        }),
        many => Err(EnterError::AmbiguousSessionLeader {
            pid: container_pid,
            count: many.len(),
            children: many.join(" "),
        }),
    }
}

/// Pins `pid` as a pidfd, so later use cannot be misdirected by PID reuse.
pub(crate) fn pidfd_open(pid: u32) -> Result<OwnedFd, EnterError> {
    // SAFETY: `pidfd_open` takes a pid and a flags word and returns a fresh
    // descriptor or -1; it reads no user memory. On success we own the
    // descriptor and hand it straight to `OwnedFd`, which closes it exactly
    // once.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(EnterError::PidfdOpen {
            pid,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `fd` is a positive, freshly-opened descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// What a shim is asked to do, as its command line carries it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShimArgs {
    /// The namespaces of the box init to join. Naming one the box does not
    /// have of its own is refused by the kernel, so the set is computed by
    /// [`namespaces_to_join`], never assumed.
    pub(crate) join: Vec<Namespace>,
    /// The directory to start in, as the box names it.
    pub(crate) chdir: Option<PathBuf>,
    /// The program and its arguments.
    pub(crate) argv: Vec<OsString>,
}

impl ShimArgs {
    /// The command line that carries these arguments, after the mode word:
    /// `[--join a,b] [--chdir dir] -- program args...`. The names of the
    /// joined namespaces are in it so `ps` shows what a shim joined.
    pub(crate) fn to_command_line(&self) -> Vec<OsString> {
        let mut line = Vec::new();
        if !self.join.is_empty() {
            let names: Vec<&str> = self.join.iter().map(|ns| ns.proc_name()).collect();
            line.push("--join".into());
            line.push(names.join(",").into());
        }
        if let Some(dir) = &self.chdir {
            line.push("--chdir".into());
            line.push(dir.clone().into_os_string());
        }
        line.push("--".into());
        line.extend(self.argv.iter().cloned());
        line
    }

    /// Reads a command line [`Self::to_command_line`] wrote.
    pub(crate) fn parse(line: impl IntoIterator<Item = OsString>) -> Result<Self, EnterError> {
        let mut line = line.into_iter();
        let mut join = Vec::new();
        let mut chdir = None;
        loop {
            let word = line
                .next()
                .ok_or_else(|| EnterError::Usage("no `--` before the program".into()))?;
            match word.to_str() {
                Some("--") => break,
                Some("--join") => {
                    let names = line.next().and_then(|names| names.into_string().ok());
                    let names =
                        names.ok_or_else(|| EnterError::Usage("--join takes names".into()))?;
                    for name in names.split(',') {
                        join.push(Namespace::from_proc_name(name).ok_or_else(|| {
                            EnterError::Usage(format!("`{name}` is not a namespace"))
                        })?);
                    }
                }
                Some("--chdir") => {
                    chdir = Some(PathBuf::from(line.next().ok_or_else(|| {
                        EnterError::Usage("--chdir takes a directory".into())
                    })?));
                }
                _ => {
                    return Err(EnterError::Usage(format!(
                        "unexpected `{}`",
                        word.to_string_lossy()
                    )));
                }
            }
        }
        let argv: Vec<OsString> = line.collect();
        if argv.is_empty() {
            return Err(EnterError::Usage("no program".into()));
        }
        Ok(Self { join, chdir, argv })
    }
}

/// Runs the shim for the command line `line` and exits with the program's
/// status. An error of the shim's own is one line on stderr and status 125.
pub(crate) fn main(line: impl IntoIterator<Item = OsString>) -> ! {
    super::title::set_comm(c"minimal-enter");
    let code = match ShimArgs::parse(line).and_then(shim_main) {
        Ok(code) => code,
        Err(error) => {
            let mut text = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                text.push_str(": ");
                text.push_str(&cause.to_string());
                source = cause.source();
            }
            eprintln!("minimal: entering the box failed: {text}");
            125
        }
    };
    std::process::exit(code)
}

/// Point this process's fd 0 at `/dev/null`, closing its copy of whatever
/// stdin it inherited. Best effort: if `/dev/null` cannot be opened the copy
/// stays, as it always did.
fn release_stdin() {
    // SAFETY: opens a new descriptor this process then owns.
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if null < 0 {
        return;
    }
    // SAFETY: both descriptors are this process's own; the shim is
    // single-threaded here (see `shim_main`), so nothing races on fd 0.
    unsafe { libc::dup2(null, libc::STDIN_FILENO) };
    // SAFETY: `null` was opened above and is closed once.
    unsafe { libc::close(null) };
}

/// Joins the session's namespaces and runs the requested program there,
/// returning the exit code to leave with.
///
/// **Must be called before the tokio runtime is built.** `setns(CLONE_NEWUSER)`
/// refuses a multi-threaded caller, and the `fork` this performs is only safe
/// because the process is single-threaded.
///
/// The spawn here is the fork that matters: `setns(CLONE_NEWPID)` placed *this*
/// process's future children in the session's PID namespace without moving this
/// process, so the program lands in the namespace and the shim stays outside it
/// as its parent, able to reap it and report its status.
///
/// # Errors
///
/// [`EnterError::JoinDenyLeaf`] if the box is deny-all and its classifier
/// leaf cannot be joined, [`EnterError::Setns`] if the namespaces cannot be
/// joined, [`EnterError::Spawn`] if the program cannot be started for a
/// reason a shell would not report, and [`EnterError::Wait`] if the started
/// program cannot be reaped. A program that is missing, not executable, or not
/// an executable format is reported on stderr and returned as the shell's exit
/// code (127/126) rather than as an error.
fn shim_main(args: ShimArgs) -> Result<i32, EnterError> {
    // SAFETY: whoever started this shim placed the box init's pidfd on this
    // descriptor, and nothing else in this freshly exec'd process owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(PIDFD_FD) };

    // The daemon's procfs, opened before the join: the grace period below scans
    // it for live members of the injected group, by the pids and group ids this
    // shim sees. After `setns(CLONE_NEWNS)` the path `/proc` names the box's
    // procfs, whose pids belong to the box's PID namespace rather than this
    // shim's. `None` (no procfs) only costs the early exit: the grace period
    // then always runs to its end.
    let proc_dir = std::fs::File::open("/proc").ok();

    if !args.join.is_empty() {
        // One call for the whole set: the kernel installs the user namespace
        // first and validates the rest against the credentials that gives us,
        // which is what makes the rest permitted. Joining them one at a time
        // fails — and joining the mount namespace first would repoint `/proc`
        // at the sandbox's procfs, where the remaining `/proc/<host pid>/ns`
        // paths do not exist.
        let flags = args
            .join
            .iter()
            .fold(CloneFlags::empty(), |acc, ns| acc | ns.clone_flag());
        nix::sched::setns(&pidfd, flags).map_err(|source| EnterError::Setns {
            namespaces: args
                .join
                .iter()
                .map(|ns| ns.proc_name())
                .collect::<Vec<_>>()
                .join(","),
            source,
        })?;
    }
    drop(pidfd);

    let (program, rest) = args
        .argv
        .split_first()
        .expect("the parser requires a program");

    let mut cmd = Command::new(program);
    cmd.args(rest);
    if let Some(dir) = &args.chdir {
        cmd.current_dir(dir);
    }

    // Compiled before the fork, so the child only loads it.
    let seccomp_program = crate::seccomp::box_program();

    // A tty exec hands the shim the slave side of its PTY as stdin. The
    // injected process then makes that PTY its controlling terminal, so job
    // control, `/dev/tty` and a hangup at the PTY's close reach it
    // (BOX-149). Read here, before the fork, and copied into the child.
    // SAFETY: `isatty` only queries the descriptor.
    let take_terminal = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

    // SAFETY: the closures run in the forked child between `fork` and `exec`,
    // where only async-signal-safe calls are legal. `signal`, `alarm`,
    // `setpgid`, `setsid`, `ioctl`, `prctl` and the raw `seccomp` syscall are
    // on that list, and the closures allocate nothing
    // and capture only a static reference and a `bool`.
    unsafe {
        cmd.pre_exec(move || {
            // Undo what the shim's own termination handling (installed before
            // the spawn) left in this forked copy: the handlers, and an alarm
            // a handler running here before this point could have armed, which
            // `exec` would otherwise carry into the program. Dispositions first,
            // so a signal from here on takes its default action.
            for signum in [libc::SIGTERM, libc::SIGHUP, libc::SIGALRM] {
                if libc::signal(signum, libc::SIG_DFL) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
            }
            libc::alarm(0);
            // Make the injected process the leader of a new process group
            // (pid == pgid). Nothing else does: the shim sits outside the
            // session's PID namespace, so the group ids the session's shell
            // already assigned do not help it name "the shim's child and its
            // descendants" for a later group kill.
            //
            // A tty exec leads a new session instead, which also makes it the
            // leader of a new process group, and takes its PTY as the
            // session's controlling terminal.
            if take_terminal {
                lead_session_on_terminal()?;
            } else if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Tie the injected process's lifetime to this shim's. Nothing else
            // does: the shim is its parent but sits outside the session's PID
            // namespace, and killing the shim is exactly how the daemon cancels
            // an exec whose client has gone away. Without this the command
            // keeps running in the session, holding stdio pipes nobody reads.
            //
            // The usual `getppid()` race check — did the parent die before this
            // ran? — is not available here: the parent is outside the PID
            // namespace this process was just placed in, so `getppid` reports 0
            // whether or not it is still alive. The window is a few
            // instructions wide, and what escapes through it is bounded by the
            // session: the sandbox's PID namespace dies with its shell, taking
            // anything left in it.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });

        // The profile the box's own processes run under. A process that joins
        // the box later does not inherit it.
        cmd.pre_exec(move || crate::seccomp::install(seccomp_program));
    }

    // The handlers go in before the spawn, so a SIGTERM or SIGHUP that arrives
    // before the child exists is recorded (and its grace period armed) rather
    // than taking the default action, which would leave the child to
    // `PR_SET_PDEATHSIG` and its descendants to run on. The forked copy resets
    // them in its first pre-exec closure.
    // SAFETY: shim_main runs before any runtime is built (see its doc), so this
    // process is single-threaded and no handler can interrupt half-initialised
    // state.
    unsafe {
        install_termination_handlers();
    }

    let program = PathBuf::from(program);
    let spawned = cmd.spawn();
    // The child has its own copy of stdin and this process never reads it, so
    // the shim lets go of its copy whatever the spawn did: holding the read end
    // kept the exec's stdin pipe open after the command closed its stdin, and
    // the daemon then took a command that had closed its input for one that
    // had stopped reading it (inbox#1089, lab 789z).
    release_stdin();
    let mut child = match spawned {
        Ok(child) => child,
        Err(source) => {
            // The child's `chdir` fails with the same `ENOENT` as a missing
            // program; a missing working directory is not "command not found".
            let chdir_missing = spawn_failed_on_missing_chdir(&source, args.chdir.as_deref());
            let mapped = if chdir_missing {
                None
            } else {
                spawn_failure_code_and_message(&source)
            };
            let Some((code, msg)) = mapped else {
                return Err(EnterError::Spawn { program, source });
            };
            eprintln!("{program}: {msg}", program = program.display());
            return Ok(code);
        }
    };

    // Publish the child's group lead (its own pid, from `setpgid(0, 0)` above)
    // for the handlers. A termination that arrived before this store found no
    // group to signal, so it is forwarded here; `GROUP_TERMED` makes sure the
    // group gets one SIGTERM whichever side gets there first.
    let pgid = libc::pid_t::try_from(child.id()).expect("a pid fits a pid_t");
    CHILD_PGID.store(pgid, Ordering::SeqCst);
    if TERM_SIGNAL.load(Ordering::SeqCst) != 0 {
        term_group_once();
    }

    // Wait for the leader to exit without reaping it: until it is reaped its
    // pid stays allocated and still names the group, so neither a handler nor
    // the grace period below can target a recycled group. The handlers return
    // (they only record and signal), so an interrupted wait is resumed.
    //
    // A tty exec leads its own session, and a shell on its PTY puts each job
    // in a process group of its own. The handler's SIGTERM reaches only the
    // leader's group, so this flow sends the session's other groups theirs
    // as soon as it sees the termination (BOX-151).
    let mut session_termed = false;
    loop {
        if take_terminal && !session_termed && TERM_SIGNAL.load(Ordering::SeqCst) != 0 {
            session_termed = true;
            if let Some(proc_dir) = &proc_dir {
                signal_session(proc_dir, pgid, libc::SIGTERM, Some(pgid));
            }
        }
        // SAFETY: `waitid` writes only into `info`, a zeroed `siginfo_t` we own.
        let observed = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                child.id(),
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if observed == 0 {
            break;
        }
        let source = std::io::Error::last_os_error();
        if source.kind() != std::io::ErrorKind::Interrupted {
            return Err(EnterError::Wait { program, source });
        }
    }

    // The leader has exited. Decide once whether the exec was ended or ended
    // by itself, after blocking SIGTERM and SIGHUP so the answer cannot change
    // once read. One that arrived before the block started the grace period;
    // one that arrives after it is never delivered, and the exec ends as the
    // leader did, killing nothing: a normal exit leaves the group's other
    // members (a `nohup`'d job) alone.
    block_termination_signals();
    let terminated_by = TERM_SIGNAL.load(Ordering::SeqCst);
    if terminated_by != 0 {
        if take_terminal
            && !session_termed
            && !GRACE_EXPIRED.load(Ordering::SeqCst)
            && let Some(proc_dir) = &proc_dir
        {
            signal_session(proc_dir, pgid, libc::SIGTERM, Some(pgid));
        }
        // The usual shape: the leader died of the SIGTERM while a member it
        // forked traps or ignores it. Hold the leader as a zombie, so the pgid
        // stays allocated, until the grace period runs out (the SIGALRM
        // handler sets the flag and has already SIGKILLed the group) or the
        // group has no live member left. Then SIGKILL whatever remains.
        while !GRACE_EXPIRED.load(Ordering::SeqCst)
            && proc_dir.as_ref().is_none_or(|proc_dir| {
                group_has_live_member(proc_dir, pgid)
                    || (take_terminal && session_has_live_member(proc_dir, pgid))
            })
        {
            std::thread::sleep(GROUP_POLL);
        }
        // SAFETY: `pgid` names the group this shim spawned, which its unreaped
        // leader keeps from being recycled.
        unsafe { kill_group(pgid) };
        // A tty exec: every job of its session, in whatever group, ends too.
        // The unreaped leader keeps the session id from being recycled.
        if take_terminal && let Some(proc_dir) = &proc_dir {
            signal_session(proc_dir, pgid, libc::SIGKILL, None);
        }
    }

    // Disarm: no alarm left to fire, and from here the handlers are no-ops so
    // a straggler signal cannot target the pid the reap below frees for reuse.
    // SAFETY: `alarm(0)` only cancels this process's pending alarm.
    unsafe { libc::alarm(0) };
    CHILD_PGID.store(0, Ordering::SeqCst);

    let status = child.wait().map_err(|source| EnterError::Wait {
        program: program.clone(),
        source,
    })?;

    // An exec that was ended reports the signal that ended it, the way the
    // shell reports a command it killed, whatever the leader's own status.
    if terminated_by != 0 {
        return Ok(128 + terminated_by);
    }
    // Mirror the shell's convention for a signalled child so the daemon sees
    // the same code it would from a direct spawn.
    Ok(status
        .code()
        .or_else(|| status.signal().map(|sig| 128 + sig))
        .unwrap_or(1))
}

/// Kill every process in the process group led by `pgid` — the injected program
/// and every descendant that has not left the group.
///
/// The daemon cancels a `min session exec` by signalling the shim, which
/// SIGTERMs this group and, once [`GROUP_GRACE`] is over, calls this with the
/// group lead captured at spawn. Without the group kill, only the shim's direct
/// child dies and its grandchildren are reparented to PID 1 to run on
/// indefinitely (#948).
///
/// A descendant that calls `setsid(2)` leaves the group and escapes this kill
/// (and the shim's `wait`); it is bounded by the sandbox's PID namespace dying
/// with its session shell, the same bound the pre-fix race already relied on.
///
/// # Safety
///
/// The caller must pass the group-lead of a live group it is entitled to
/// signal, or `0` (a no-op, so a handler that fires after the child was reaped
/// cannot hit a recycled pid). Any `pgid <= 1` is a no-op: `kill(0, …)` would
/// signal the shim's own group and `kill(-1, …)` every process it may signal,
/// so neither can ever be the target.
unsafe fn kill_group(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    // SAFETY: only async-signal-safe calls follow, so this is legal from a
    // signal handler. SIGKILL is uncatchable, so nothing in the group can
    // survive it; ESRCH means the group is already gone.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

/// Makes the calling process the leader of a new session, and so of a new
/// process group (pid == pgid == sid), and makes the terminal on its stdin
/// the session's controlling terminal. A tty exec runs on its PTY as a
/// login shell runs on its terminal.
///
/// # Safety
///
/// Call it in a forked child before `exec`: it makes only the
/// async-signal-safe calls `setsid(2)` and `ioctl(2)`.
pub(crate) unsafe fn lead_session_on_terminal() -> std::io::Result<()> {
    // SAFETY: `setsid` takes no arguments. It fails only for a process that
    // already leads a group, which a freshly forked child never does.
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `TIOCSCTTY` with `0` takes the terminal only if no other
    // session holds it, and writes through no pointer.
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Send the injected group its one SIGTERM, if the group is published and no
/// one has sent it yet. Async-signal-safe (atomics and `kill` only), so both
/// the SIGTERM/SIGHUP handler and the main flow call it.
fn term_group_once() {
    let pgid = CHILD_PGID.load(Ordering::SeqCst);
    // The same guard as `kill_group`: `0` is "no group yet" (or "already
    // reaped"), and nothing at or below 1 names a child group.
    if pgid > 1 && !GROUP_TERMED.swap(true, Ordering::SeqCst) {
        // SAFETY: `pgid` is the group lead this shim spawned, unreaped while
        // published; `kill(2)` is async-signal-safe.
        unsafe { libc::kill(-pgid, libc::SIGTERM) };
    }
}

/// SIGTERM and SIGHUP: the daemon ending an exec whose client went away. The
/// first one records itself, arms [`GROUP_GRACE`] and forwards SIGTERM to the
/// group; any later one does nothing, so the grace period is never re-armed or
/// extended. The waiting happens in [`shim_main`]'s main flow, not here.
extern "C" fn on_term_or_hup(signum: libc::c_int) {
    // The main flow reads errno after the `waitid` this may have interrupted.
    // SAFETY: `__errno_location` is this thread's errno slot, live for the call.
    let saved = unsafe { *libc::__errno_location() };
    if TERM_SIGNAL
        .compare_exchange(0, signum, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // SAFETY: `alarm(2)` is async-signal-safe and arms only this process's
        // timer.
        unsafe { libc::alarm(GROUP_GRACE_ALARM) };
        term_group_once();
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = saved };
}

/// SIGALRM: [`GROUP_GRACE`] has run out. SIGKILL the group and tell the main
/// flow. Once the shim is about to reap its child, [`CHILD_PGID`] is `0` and the
/// kill is a no-op, so an alarm that fires late does nothing.
extern "C" fn on_grace_expired(_signum: libc::c_int) {
    // SAFETY: `__errno_location` is this thread's errno slot, live for the call.
    let saved = unsafe { *libc::__errno_location() };
    GRACE_EXPIRED.store(true, Ordering::SeqCst);
    // SAFETY: the published pgid is the group this shim spawned, or `0`.
    unsafe { kill_group(CHILD_PGID.load(Ordering::SeqCst)) };
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = saved };
}

/// Install [`on_term_or_hup`] for SIGTERM and SIGHUP — the two the daemon uses
/// to cancel a shim whose client died — and [`on_grace_expired`] for SIGALRM.
///
/// # Safety
///
/// Must run while the process is single-threaded (before the tokio runtime is
/// built, which [`shim_main`] guarantees) so a handler cannot interrupt a
/// half-initialised data structure.
unsafe fn install_termination_handlers() {
    let handlers: [(libc::c_int, extern "C" fn(libc::c_int)); 3] = [
        (libc::SIGTERM, on_term_or_hup),
        (libc::SIGHUP, on_term_or_hup),
        (libc::SIGALRM, on_grace_expired),
    ];
    for (signum, handler) in handlers {
        // SAFETY: an all-zero `sigaction` is a valid disposition (empty mask,
        // SIG_DFL); `sigemptyset` writes only the mask; `sigaction` installs a
        // handler whose body is limited to atomics, `kill`, `alarm` and errno.
        // No SA_RESTART: the main flow's waits retry on EINTR themselves.
        let installed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            libc::sigaction(signum, &raw const action, std::ptr::null_mut())
        };
        debug_assert_eq!(
            installed, 0,
            "installing the termination handler for signal {signum}"
        );
    }
}

/// Block SIGTERM and SIGHUP for the rest of the shim's life: once the shim has
/// decided whether the exec was ended, a later request must not change that.
fn block_termination_signals() {
    // SAFETY: an all-zero `sigset_t` is valid storage for `sigemptyset` to
    // initialise; `sigprocmask` only changes this single-threaded process's
    // mask.
    let blocked = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGTERM);
        libc::sigaddset(&raw mut set, libc::SIGHUP);
        libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut())
    };
    debug_assert_eq!(blocked, 0, "blocking SIGTERM and SIGHUP");
}

/// Whether the process group `pgid` has a member that is still running: any
/// member that is not a zombie (the shim's own unreaped leader is one). Read
/// from the `pgrp` and state fields of every `<pid>/stat` under `proc_dir`,
/// the shim's own procfs. `kill(-pgid, 0)` cannot answer this: the zombie
/// leader the shim holds is still a member, so it never reports `ESRCH`. A
/// scan that cannot be made answers `true`, which only costs the early exit:
/// the grace period then runs to its end.
fn group_has_live_member(proc_dir: &std::fs::File, pgid: libc::pid_t) -> bool {
    let mut live = false;
    let scanned = scan_live_processes(proc_dir, |_, member| {
        live = member.pgrp == pgid;
        live
    });
    live || !scanned
}

/// Whether the session `sid` has a member that is still running, read as
/// [`group_has_live_member`] reads a group. A scan that cannot be made
/// answers `true`.
pub(crate) fn session_has_live_member(proc_dir: &std::fs::File, sid: libc::pid_t) -> bool {
    if sid <= 1 {
        return false;
    }
    let mut live = false;
    let scanned = scan_live_processes(proc_dir, |_, member| {
        live = member.session == sid;
        live
    });
    live || !scanned
}

/// Sends `signal` to every live process of the session `sid` under
/// `proc_dir`, in every process group of it, except the members of
/// `skip_group`. A tty exec leads its own session, and a shell with job
/// control puts each job in a group of its own, so a group kill does not
/// reach them (BOX-151). A process that calls `setsid(2)` leaves the
/// session and is not signalled. Any `sid <= 1` is a no-op.
///
/// The caller must keep the session leader unreaped, so the session id
/// cannot be recycled while the scan runs.
pub(crate) fn signal_session(
    proc_dir: &std::fs::File,
    sid: libc::pid_t,
    signal: libc::c_int,
    skip_group: Option<libc::pid_t>,
) {
    if sid <= 1 {
        return;
    }
    scan_live_processes(proc_dir, |pid, member| {
        if member.session == sid
            && Some(member.pgrp) != skip_group
            && let Ok(pid) = libc::pid_t::try_from(pid)
        {
            // SAFETY: `kill(2)` has no Rust-side invariants. ESRCH means the
            // process ended since the scan read it.
            unsafe { libc::kill(pid, signal) };
        }
        false
    });
}

/// The fields of a `/proc/<pid>/stat` line that the group and session
/// scans read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcMember {
    pgrp: libc::pid_t,
    session: libc::pid_t,
}

/// Calls `visit` with every process under `proc_dir` that is not a zombie,
/// until `visit` answers `true`. False when the scan cannot be made.
fn scan_live_processes(
    proc_dir: &std::fs::File,
    mut visit: impl FnMut(u32, ProcMember) -> bool,
) -> bool {
    // A fresh open file description for every scan: a `dup` would share the
    // directory offset the previous scan left at the end.
    // SAFETY: `openat` on a directory fd this function borrows, with a static
    // NUL-terminated path; the result is checked before use.
    let fd = unsafe {
        libc::openat(
            proc_dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` is an open directory this function owns; on success
    // `fdopendir` takes it over and `closedir` below closes it.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        // SAFETY: `fdopendir` failed, so `fd` is still ours to close.
        unsafe { libc::close(fd) };
        return false;
    }
    loop {
        // SAFETY: `dir` is the open stream above, used by this thread only.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `readdir` returned a valid entry whose `d_name` is
        // NUL-terminated and live until the next `readdir` on `dir`.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Some(pid) = name.to_str().ok().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if let Some(member) = live_member(proc_dir, pid)
            && visit(pid, member)
        {
            break;
        }
    }
    // SAFETY: `dir` came from `fdopendir` above and is closed exactly once.
    unsafe { libc::closedir(dir) };
    true
}

/// The group and session of `pid` (under `proc_dir`), if it is not a
/// zombie. A process that is gone, or whose `stat` cannot be read, is none.
fn live_member(proc_dir: &std::fs::File, pid: u32) -> Option<ProcMember> {
    let path = std::ffi::CString::new(format!("{pid}/stat")).ok()?;
    // SAFETY: `openat` on a directory fd this function borrows and a
    // NUL-terminated path it owns; the result is checked before use.
    let fd = unsafe {
        libc::openat(
            proc_dir.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` was just opened and nothing else owns it.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut stat = String::new();
    std::io::Read::read_to_string(&mut file, &mut stat).ok()?;
    stat_live_member(&stat)
}

/// Whether a `/proc/<pid>/stat` line names a process in group `pgid` that is
/// not a zombie.
#[cfg(test)]
fn stat_is_live_member(stat: &str, pgid: libc::pid_t) -> bool {
    stat_live_member(stat).is_some_and(|member| member.pgrp == pgid)
}

/// The group and session a `/proc/<pid>/stat` line names, if the process is
/// not a zombie. The fields after the parenthesised comm, which may itself
/// contain `)`, start: state ppid pgrp session.
fn stat_live_member(stat: &str) -> Option<ProcMember> {
    let (_, after_comm) = stat.rsplit_once(')')?;
    let mut fields = after_comm.split_whitespace();
    let (Some(state), Some(_ppid), Some(pgrp), Some(session)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return None;
    };
    if matches!(state, "Z" | "X") {
        return None;
    }
    Some(ProcMember {
        pgrp: pgrp.parse().ok()?,
        session: session.parse().ok()?,
    })
}

/// Maps a failed `spawn` to the shell's exit-code and message conventions:
/// `ENOENT` is "command not found" (127), `EACCES` is "permission denied"
/// (126), and `ENOEXEC` is "cannot execute" (126). Any other failure — a
/// fork's `ENOMEM`, or an `EPERM` from a `pre_exec` hook, included — is not the
/// program's to report, so it is `None` and stays a [`EnterError::Spawn`].
/// `EACCES` is matched by errno rather than [`std::io::ErrorKind::PermissionDenied`],
/// which also covers `EPERM`.
///
/// The message is the plain text a shell would print, without the debug
/// wrapper `main` adds to [`EnterError`] — a script must be able to tell
/// "not found" from the command's own failure.
fn spawn_failure_code_and_message(source: &std::io::Error) -> Option<(i32, String)> {
    match source.raw_os_error()? {
        libc::ENOENT => Some((127, "command not found".to_string())),
        libc::EACCES => Some((126, "permission denied".to_string())),
        libc::ENOEXEC => Some((126, format!("cannot execute: {source}"))),
        _ => None,
    }
}

/// Whether a failed `spawn` is the child's `chdir` failing on a missing
/// working directory rather than the program itself being missing. Only
/// `ENOENT` is ambiguous between the two — `EACCES` and `ENOEXEC` are the
/// program's own failure whichever syscall raised them, so they map
/// unconditionally and never route through this discriminator.
fn spawn_failed_on_missing_chdir(source: &std::io::Error, chdir: Option<&Path>) -> bool {
    source.raw_os_error() == Some(libc::ENOENT) && chdir.is_some_and(|dir| !dir.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A failed spawn maps to the shell's exit-code and message conventions:
    /// `ENOENT` is "command not found" (127), `EACCES` is "permission denied"
    /// (126), and `ENOEXEC` is "cannot execute" (126). Anything else, such as
    /// the fork's `ENOMEM` or a `pre_exec` hook's `EPERM`, is left to
    /// [`EnterError::Spawn`].
    #[test]
    fn spawn_failures_map_to_shell_exit_codes_and_messages() {
        let not_found = std::io::Error::from_raw_os_error(libc::ENOENT);
        let (code, msg) = spawn_failure_code_and_message(&not_found).unwrap();
        assert_eq!(code, 127);
        assert_eq!(msg, "command not found");

        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        let (code, msg) = spawn_failure_code_and_message(&denied).unwrap();
        assert_eq!(code, 126);
        assert_eq!(msg, "permission denied");

        let no_exec = std::io::Error::from_raw_os_error(libc::ENOEXEC);
        let (code, msg) = spawn_failure_code_and_message(&no_exec).unwrap();
        assert_eq!(code, 126);
        assert!(msg.starts_with("cannot execute: "), "got {msg:?}");

        let fork_failed = std::io::Error::from_raw_os_error(libc::ENOMEM);
        assert_eq!(spawn_failure_code_and_message(&fork_failed), None);

        let hook_refused = std::io::Error::from_raw_os_error(libc::EPERM);
        assert_eq!(spawn_failure_code_and_message(&hook_refused), None);
    }

    /// Only `ENOENT` is ambiguous between a missing program and a missing
    /// working directory. An `EACCES` from `chdir` (an inaccessible cwd) is
    /// the program's own failure and must not be swallowed by the
    /// missing-chdir discriminator, so it still maps to 126.
    #[test]
    fn missing_chdir_discriminator_only_swallows_enoent() {
        let missing = std::io::Error::from_raw_os_error(libc::ENOENT);
        let denied = std::io::Error::from_raw_os_error(libc::EACCES);
        let no_exec = std::io::Error::from_raw_os_error(libc::ENOEXEC);
        let chdir = Some(Path::new("/definitely/not/here"));

        assert!(spawn_failed_on_missing_chdir(&missing, chdir));
        assert!(!spawn_failed_on_missing_chdir(&missing, None));
        assert!(!spawn_failed_on_missing_chdir(&denied, chdir));
        assert!(!spawn_failed_on_missing_chdir(&no_exec, chdir));
    }

    /// A process whose only child is known: `sh` prints the PID of the
    /// background `sleep` it forked, so the expected answer arrives on stdout
    /// after the fork rather than being guessed at.
    fn shell_with_one_child() -> (std::process::Child, u32) {
        use std::io::BufRead as _;

        let mut sh = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 & echo $!; wait")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawning /bin/sh");
        // One line, not to EOF: `sh` holds the pipe open until the background
        // `sleep` it just forked has finished, which is the state under test.
        let mut out = String::new();
        std::io::BufReader::new(sh.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut out)
            .expect("reading the child pid");
        let child_pid = out.trim().parse().expect("sh printed a pid");
        (sh, child_pid)
    }

    /// Every box unshares its own IPC namespace, so a process injected into a
    /// box has to be able to join it: the joinable set includes IPC, and
    /// [`namespaces_to_join`] picks it up wherever the box's differs from ours.
    #[test]
    fn the_ipc_namespace_is_one_an_injected_process_joins() {
        assert!(
            Namespace::ALL.contains(&Namespace::Ipc),
            "an injected process must join its box's IPC namespace"
        );
        assert_eq!(Namespace::Ipc.proc_name(), "ipc");
        assert_eq!(Namespace::Ipc.clone_flag(), CloneFlags::CLONE_NEWIPC);
    }

    #[test]
    fn resolves_the_grandchild_not_the_forking_process() {
        let (mut sh, expected) = shell_with_one_child();

        let resolved = init_of(sh.id());

        let _ = sh.kill();
        let _ = sh.wait();
        assert_eq!(resolved.expect("resolving the sole child"), expected);
    }

    /// The group kill reaches a descendant, not just the direct child: `sh`
    /// puts its background `sleep` in the group, and after [`kill_group`] on the
    /// group lead, `kill(grandchild, 0)` reports `ESRCH` — the descendant is
    /// gone, not reparented and left running.
    #[test]
    fn kill_group_reaches_the_grandchild() {
        use std::io::BufRead as _;
        use std::os::unix::process::CommandExt as _;
        use std::time::Instant;

        let mut sh = Command::new("/bin/sh");
        sh.arg("-c")
            .arg("sleep 600 & echo $!; wait")
            .stdout(std::process::Stdio::piped());
        // SAFETY: the closure only calls `setpgid(2)`, which is
        // async-signal-safe, in the forked pre-exec child.
        unsafe {
            sh.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut sh = sh.spawn().expect("spawning /bin/sh");

        let mut out = String::new();
        std::io::BufReader::new(sh.stdout.as_mut().expect("piped stdout"))
            .read_line(&mut out)
            .expect("reading the grandchild pid");
        let grandchild: i32 = out.trim().parse().expect("sh printed a pid");

        // SAFETY: `sh.id()` is the group lead the pre_exec created; it is the
        // group this test spawned and owns.
        unsafe { kill_group(sh.id() as i32) };
        let _ = sh.wait();

        // The descendant must disappear quickly rather than linger under PID 1.
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        loop {
            // SAFETY: `kill(pid, 0)` only probes existence; `grandchild` names a
            // process this test forked.
            let exists = unsafe { libc::kill(grandchild, 0) } == 0;
            if !exists {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH),
                    "the grandchild must be gone, not just invisible"
                );
                break;
            }
            // Killed but not yet reaped: a container's PID 1 need not reap
            // the orphans reparented to it, so a zombie counts as dead.
            if is_zombie(grandchild) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "grandchild {grandchild} survived the group kill"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Whether `pid` is a zombie, per the state field of `/proc/<pid>/stat`
    /// (the first field after the parenthesised comm).
    fn is_zombie(pid: i32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let (_, after_comm) = stat.rsplit_once(')')?;
                after_comm
                    .split_whitespace()
                    .next()
                    .map(|state| state == "Z")
            })
            .unwrap_or(false)
    }

    /// The handler's guard: `kill_group` never signals the shim's own group
    /// (`0`) or every process it may signal (`-1`, from a `pgid` of `1`), nor
    /// a negative id. Reaching any `kill` here would take the test runner down.
    #[test]
    fn kill_group_ignores_pgids_that_name_no_child_group() {
        for pgid in [i32::MIN, -1, 0, 1] {
            // SAFETY: every value is below the guard, so no signal is sent.
            unsafe { kill_group(pgid) };
        }
    }

    /// The grace period's group probe reads state and pgrp past the last `)`,
    /// so a comm holding `) ` cannot shift the fields, and a zombie member is
    /// not a live one.
    #[test]
    fn stat_is_live_member_reads_state_and_pgrp() {
        assert!(stat_is_live_member("42 (sh) S 1 42 42 0 -1", 42));
        assert!(stat_is_live_member("43 (a) b) R 42 42 42 0 -1", 42));
        assert!(!stat_is_live_member("42 (sh) Z 1 42 42 0 -1", 42));
        assert!(!stat_is_live_member("44 (sh) S 1 44 44 0 -1", 42));
        assert!(!stat_is_live_member("garbage", 42));
    }

    /// The probe the grace period polls: a running group has a live member,
    /// and a group whose only member is its unreaped zombie leader — the
    /// state the shim holds the group in — has none, so the shim stops
    /// waiting as soon as the last real member is gone.
    #[test]
    fn group_has_live_member_ignores_the_zombie_leader() {
        use std::os::unix::process::CommandExt as _;

        let proc_dir = std::fs::File::open("/proc").expect("opening /proc");
        let mut sleep = Command::new("sleep");
        sleep.arg("600");
        // SAFETY: the closure only calls `setpgid(2)`, which is
        // async-signal-safe, in the forked pre-exec child.
        unsafe {
            sleep.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut sleep = sleep.spawn().expect("spawning sleep");
        let pgid = libc::pid_t::try_from(sleep.id()).expect("a pid fits a pid_t");
        assert!(
            group_has_live_member(&proc_dir, pgid),
            "the running leader is a live member"
        );

        // SAFETY: `pgid` is the group this test spawned and owns.
        unsafe { kill_group(pgid) };
        // SAFETY: `waitid` writes only into `info`, a zeroed `siginfo_t`.
        let observed = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                sleep.id(),
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(observed, 0, "waiting for the leader to die");
        assert!(
            !group_has_live_member(&proc_dir, pgid),
            "a zombie leader alone is not a live member"
        );
        let _ = sleep.wait();
    }

    #[test]
    fn a_process_without_children_is_not_a_container_supervisor() {
        let mut sleep = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawning /bin/sleep");

        let resolved = init_of(sleep.id());

        let _ = sleep.kill();
        let _ = sleep.wait();
        assert!(
            matches!(resolved, Err(EnterError::NoSessionLeader { .. })),
            "expected NoSessionLeader, got {resolved:?}"
        );
    }

    /// A PTY: its master side and its slave side.
    fn open_terminal() -> (std::fs::File, std::fs::File) {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: valid out-pointers for both descriptors, and NULL for the
        // optional name, termios and size.
        let opened = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `openpty` succeeded, so both descriptors are open and ours.
        unsafe {
            (
                std::fs::File::from(OwnedFd::from_raw_fd(master)),
                std::fs::File::from(OwnedFd::from_raw_fd(slave)),
            )
        }
    }

    /// Whether `pid` is gone or a zombie.
    fn process_gone(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => true,
            Ok(stat) => stat
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
        }
    }

    /// A program on a terminal leads its own session, and a shell with job
    /// control puts a background job in a process group of its own. The
    /// shim's stop reaches that job through the session: SIGTERM to the
    /// leader's group and to every other group of the session, then SIGKILL
    /// to what is left. The job here ignores SIGTERM, so only the SIGKILL
    /// ends it. This drives the session calls the shim makes.
    #[test]
    fn a_stop_ends_every_process_group_of_the_session() {
        use std::os::unix::process::CommandExt as _;

        let dir = tempfile::tempdir().unwrap();
        let member = dir.path().join("member");
        let (master, slave) = open_terminal();
        let script =
            r#"set -m; sh -c 'trap "" TERM; echo $$ > "$1"; exec sleep 600' sh "$1" & wait"#;
        let mut shell = std::process::Command::new("sh");
        shell
            .args(["-c", script, "sh"])
            .arg(&member)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        // SAFETY: the step makes only async-signal-safe calls.
        unsafe {
            shell.pre_exec(|| lead_session_on_terminal());
        }
        let mut shell = shell.spawn().expect("the shell starts");
        let sid = libc::pid_t::try_from(shell.id()).unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        let job: libc::pid_t = loop {
            if let Some(pid) = std::fs::read_to_string(&member)
                .ok()
                .and_then(|text| text.trim().parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "the job never started");
            std::thread::sleep(Duration::from_millis(20));
        };
        // SAFETY: both calls only query the kernel.
        let (job_group, job_session) = unsafe { (libc::getpgid(job), libc::getsid(job)) };
        assert_eq!(job_session, sid, "the job is in the exec's session");
        assert_ne!(job_group, sid, "the job has a process group of its own");

        let proc_dir = std::fs::File::open("/proc").unwrap();
        // The shim's handler: SIGTERM to the leader's group. Its main flow:
        // SIGTERM to the session's other groups.
        // SAFETY: `sid` is the group this test spawned.
        unsafe { libc::kill(-sid, libc::SIGTERM) };
        signal_session(&proc_dir, sid, libc::SIGTERM, Some(sid));
        let deadline = Instant::now() + Duration::from_secs(10);
        while !process_gone(shell.id()) {
            assert!(Instant::now() < deadline, "the shell outlived its SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(200));
        let job_pid = u32::try_from(job).unwrap();
        assert!(!process_gone(job_pid), "the job ignores SIGTERM");
        assert!(
            session_has_live_member(&proc_dir, sid),
            "the session still has the job"
        );

        // The grace period ends: SIGKILL to the whole session. The shell is
        // still unreaped, so its session id is not recycled.
        signal_session(&proc_dir, sid, libc::SIGKILL, None);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !process_gone(job_pid) {
            assert!(Instant::now() < deadline, "the job outlived the stop");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!session_has_live_member(&proc_dir, sid));
        let _ = shell.wait();
        drop(master);
    }

    /// The PTY a program is started on is its controlling terminal. The
    /// shim's pre-exec step makes the program lead a new session, and the
    /// PTY's foreground process group is then that program. A program
    /// started without the step has no controlling terminal on the PTY.
    #[test]
    fn a_program_on_a_pty_has_it_as_its_controlling_terminal() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;

        let spawn_on_pty = |lead: bool| {
            let (master, slave) = open_terminal();
            let mut command = std::process::Command::new("sleep");
            command
                .arg("30")
                .stdin(slave.try_clone().unwrap())
                .stdout(slave.try_clone().unwrap())
                .stderr(slave);
            if lead {
                // SAFETY: the step makes only async-signal-safe calls.
                unsafe {
                    command.pre_exec(|| lead_session_on_terminal());
                }
            }
            let child = command.spawn().expect("the process starts");
            (master, child)
        };

        let (master, mut child) = spawn_on_pty(true);
        let pid = i32::try_from(child.id()).unwrap();
        // SAFETY: both calls only query the kernel.
        let (foreground, sid) = unsafe { (libc::tcgetpgrp(master.as_raw_fd()), libc::getsid(pid)) };
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(sid, pid, "the process leads its own session");
        assert_eq!(
            foreground, pid,
            "the PTY is the controlling terminal of the process"
        );

        let (master, mut child) = spawn_on_pty(false);
        let pid = i32::try_from(child.id()).unwrap();
        // SAFETY: only queries the kernel.
        let foreground = unsafe { libc::tcgetpgrp(master.as_raw_fd()) };
        let _ = child.kill();
        let _ = child.wait();
        assert_ne!(
            foreground, pid,
            "without the step the PTY is no one's terminal"
        );
    }
}
