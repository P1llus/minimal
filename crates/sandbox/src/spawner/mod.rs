//! The one way a process of a box is started.
//!
//! A spawner does three jobs: it runs a program in a new container, it runs
//! a program in a running container, and it creates a socket for a box.
//! Whatever it creates starts in the box's cgroup, and the spawner is its
//! parent and reaps it.
//!
//! A daemon has its spawner as a process of its own, [`Spawner::process`],
//! so the daemon itself never forks. That process is the daemon's binary in
//! an internal mode, which [`run_internal_mode`] serves. A program with no
//! such binary runs the same loop on a thread, [`Spawner::in_process`].
//! Both are reached over a socket with the same messages.

mod client;
mod core;
pub mod enter;
mod server;
mod title;
mod wire;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::cgroup::{BoxCgroup, CpuWeight, LimitError, Root};
use client::Connection;
pub(crate) use wire::{ContainerSpec, Mount, Session, Tap};

/// The first argument of this binary when it runs as a spawner process.
const SPAWNER_MODE: &str = "__spawner";

/// The first argument of this binary when it runs as an enter shim.
const ENTER_MODE: &str = "__enter";

/// Runs this process as a spawner or as an enter shim when its command line
/// asks for one, and returns otherwise. A binary that starts a spawner
/// process calls this first in `main`, before it starts a thread.
pub fn run_internal_mode() {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(OsStr::to_str) {
        Some(SPAWNER_MODE) => server::main(args),
        Some(ENTER_MODE) => enter::main(args),
        _ => {}
    }
}

/// How a job ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    /// The program's exit code, 128 plus the signal that ended it, or 125
    /// when the job failed before its program ran.
    pub code: i32,
    /// The program's exit code, when it exited by itself.
    pub exit_code: Option<i32>,
    /// What happened, in words.
    pub reason: String,
}

impl ExitStatus {
    /// The code of a job that failed outside its program.
    pub const FAILURE: i32 = 125;

    /// A job that failed outside its program.
    pub(crate) fn failure(reason: impl Into<String>) -> Self {
        Self {
            code: Self::FAILURE,
            exit_code: None,
            reason: reason.into(),
        }
    }

    /// Whether the program ran and exited with code 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

/// Where a standard stream of a job comes from.
#[derive(Debug)]
pub enum Stdio {
    /// The requesting process's own stream.
    Inherit,
    /// A new pipe, whose other end the [`Child`] holds.
    MakePipe,
    /// `/dev/null`.
    Null,
    /// This descriptor.
    Fd(OwnedFd),
}

impl Stdio {
    /// [`Stdio::MakePipe`].
    #[must_use]
    pub fn piped() -> Self {
        Self::MakePipe
    }

    /// [`Stdio::Null`].
    #[must_use]
    pub fn null() -> Self {
        Self::Null
    }

    /// The descriptor the job gets, and the end the requester keeps when the
    /// stream is a new pipe. `number` is the stream's descriptor number.
    fn ends(self, number: libc::c_int) -> io::Result<(OwnedFd, Option<OwnedFd>)> {
        let null = || {
            std::fs::File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .map(OwnedFd::from)
        };
        match self {
            Self::Inherit => {
                // SAFETY: the descriptor is only duplicated, and a closed
                // one fails the duplication.
                let own = unsafe { BorrowedFd::borrow_raw(number) };
                match own.try_clone_to_owned() {
                    Ok(fd) => Ok((fd, None)),
                    // A requester with the stream closed has none to share.
                    Err(_) => Ok((null()?, None)),
                }
            }
            Self::MakePipe => {
                let (reader, writer) = io::pipe()?;
                if number == 0 {
                    Ok((reader.into(), Some(writer.into())))
                } else {
                    Ok((writer.into(), Some(reader.into())))
                }
            }
            Self::Null => Ok((null()?, None)),
            Self::Fd(fd) => Ok((fd, None)),
        }
    }
}

impl From<std::fs::File> for Stdio {
    fn from(file: std::fs::File) -> Self {
        Self::Fd(file.into())
    }
}

impl From<OwnedFd> for Stdio {
    fn from(fd: OwnedFd) -> Self {
        Self::Fd(fd)
    }
}

impl From<PipeReader> for Stdio {
    fn from(pipe: PipeReader) -> Self {
        Self::Fd(pipe.into())
    }
}

impl From<PipeWriter> for Stdio {
    fn from(pipe: PipeWriter) -> Self {
        Self::Fd(pipe.into())
    }
}

/// How a spawner process relates to the terminal of the process that
/// starts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// The spawner and its jobs stay in the caller's session and process
    /// group. A job can be the terminal's foreground program, and an
    /// interrupt from the terminal reaches the job, the spawner and the
    /// caller alike. For a tool that runs one program for its user.
    Shared,
    /// The spawner starts a session of its own. An interrupt from the
    /// caller's terminal reaches the caller only, which can then stop its
    /// boxes in order. For a daemon.
    Detached,
}

/// How a [`Spawner`] reaches the loop that does its jobs.
enum Backend {
    /// A process: this binary, run again in its spawner mode.
    Process { exe: PathBuf, terminal: Terminal },
    /// A thread of this process.
    Thread,
}

struct Inner {
    backend: Backend,
    connection: Mutex<Option<Arc<Connection>>>,
    /// Where a container with no box cgroup gets a cgroup of its own.
    root: Option<Root>,
}

/// A handle on a spawner. Clones share the one spawner.
#[derive(Clone)]
pub struct Spawner {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Spawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner.backend {
            Backend::Process { exe, .. } => f.debug_struct("Spawner").field("exe", exe).finish(),
            Backend::Thread => f.write_str("Spawner(in process)"),
        }
    }
}

/// The spawner of this process, once one is installed.
static INSTALLED: OnceLock<Spawner> = OnceLock::new();

impl Spawner {
    /// A spawner that is a process: `exe`, the calling binary, whose `main`
    /// calls [`run_internal_mode`]. The process is started by the first
    /// request, or by [`Spawner::start`], in the cgroup the caller is in
    /// then. It is started again on the next request if it has died, and
    /// everything it had started has died with it.
    ///
    /// `root` is the caller's cgroup root, if it has one. A container that
    /// is started with no box cgroup then gets a cgroup of its own below
    /// the root's `boxes`, removed when the container ends, so no container
    /// shares the cgroup the caller and the spawner are in.
    pub fn process(exe: impl Into<PathBuf>, terminal: Terminal, root: Option<Root>) -> Self {
        Self {
            inner: Arc::new(Inner {
                backend: Backend::Process {
                    exe: exe.into(),
                    terminal,
                },
                connection: Mutex::new(None),
                root,
            }),
        }
    }

    /// Starts the spawner now, if it is not running.
    ///
    /// # Errors
    ///
    /// Fails if the spawner cannot be started.
    pub fn start(&self) -> io::Result<()> {
        self.connection().map(drop)
    }

    /// A spawner that works on a thread of this process, for a program whose
    /// binary has no spawner mode. It cannot enter a running container,
    /// because that takes a binary with an enter mode.
    #[must_use]
    pub fn in_process() -> Self {
        Self {
            inner: Arc::new(Inner {
                backend: Backend::Thread,
                connection: Mutex::new(None),
                root: None,
            }),
        }
    }

    /// Makes this the spawner [`Spawner::current`] returns. The first call
    /// in a process decides, and a later one gets its spawner back.
    ///
    /// # Errors
    ///
    /// Returns `self` when a spawner is installed already.
    pub fn install(self) -> Result<(), Self> {
        INSTALLED.set(self)
    }

    /// The spawner of this process: the installed one, or one that works in
    /// process when none was installed.
    ///
    /// Read where a container's command is built ([`crate::Sandbox::command`]),
    /// where a build asks for a socket of a box with no held network, and
    /// where a stop asks which processes of a box are supervisors.
    /// Everything else takes its spawner from the job it works on.
    #[must_use]
    pub fn current() -> Self {
        INSTALLED.get_or_init(Self::in_process).clone()
    }

    /// The connection to the running spawner, started first if there is none.
    fn connection(&self) -> io::Result<Arc<Connection>> {
        let mut connection = self.inner.connection.lock().expect("spawner lock");
        if let Some(live) = connection.as_ref().filter(|c| !c.closed()) {
            return Ok(Arc::clone(live));
        }
        let (ours, theirs) = UnixStream::pair()?;
        let fresh = match &self.inner.backend {
            Backend::Process { exe, terminal } => {
                let process = spawner_process(exe, *terminal, &theirs)?;
                Connection::open(ours, Some(process))?
            }
            Backend::Thread => {
                std::thread::Builder::new()
                    .name("spawner".into())
                    .spawn(move || server::serve(theirs, None, false))?;
                Connection::open(ours, None)?
            }
        };
        *connection = Some(Arc::clone(&fresh));
        Ok(fresh)
    }

    /// Creates a socket in `cgroup`, in the requester's network namespace.
    /// The socket belongs to the box from its creation, which is what a
    /// per-cgroup network rule goes by.
    ///
    /// # Errors
    ///
    /// Fails if the spawner is gone or the socket cannot be created.
    pub fn socket(
        &self,
        cgroup: Option<&BoxCgroup>,
        v6: bool,
        datagram: bool,
    ) -> io::Result<OwnedFd> {
        self.connection()?
            .socket(None, v6, datagram, cgroup.map(BoxCgroup::dir_fd))
    }

    /// Closes the socket to the running spawner, as the end of the
    /// requesting process does.
    #[cfg(test)]
    pub(crate) fn hang_up(&self) {
        if let Some(connection) = self.inner.connection.lock().expect("spawner lock").as_ref() {
            connection.hang_up();
        }
    }

    /// Whether `pid` is the supervisor of a container this spawner runs. A
    /// stop that signals the processes of a box leaves the supervisor out:
    /// it ends when the box's program does, and the program is killed
    /// outright when its supervisor dies first.
    #[must_use]
    pub fn supervises(&self, pid: u32) -> bool {
        self.inner
            .connection
            .lock()
            .expect("spawner lock")
            .as_ref()
            .is_some_and(|connection| connection.supervises(pid))
    }

    /// A cgroup for one container that has no box cgroup, below `root`.
    fn own_cgroup(root: &Root, cpu_weight: Option<u64>) -> io::Result<BoxCgroup> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let name = format!(
            "build-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let cgroup = root.create_box(&name).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("creating the cgroup `{name}` for a container: {error}"),
            )
        })?;
        if let Some(weight) = cpu_weight {
            match cgroup.set_cpu_weight(CpuWeight::clamped(weight)) {
                Ok(()) => {}
                // A weight is a share of what is there to share. Without
                // the controller the container runs unweighted.
                Err(LimitError::ControllerNotDelegated(_) | LimitError::NoCgroup) => {
                    tracing::debug!(cgroup = %name, weight, "no cpu controller for a CPU weight");
                }
                Err(LimitError::Io(error)) => {
                    tracing::warn!(cgroup = %name, weight, %error, "setting a CPU weight");
                }
            }
        }
        Ok(cgroup)
    }

    /// A command that runs `program` in a new container.
    pub(crate) fn run(&self, launch: Launch, program: &str) -> Command {
        Command {
            target: Target::Container {
                spawner: self.clone(),
                launch: Box::new(launch),
            },
            program: program.to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
        }
    }
}

/// Starts `exe` as a spawner process that serves `socket`.
fn spawner_process(
    exe: &Path,
    terminal: Terminal,
    socket: &UnixStream,
) -> io::Result<std::process::Child> {
    let fd = socket.as_raw_fd();
    let mut command = std::process::Command::new(exe);
    command
        .arg0("minimal-spawner")
        .arg(SPAWNER_MODE)
        .arg(exe)
        .stdin(std::process::Stdio::null());
    // SAFETY: the closure makes direct syscalls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if terminal == Terminal::Detached && libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if fd == server::SOCKET_FD {
                // Already in place: keep it across the exec.
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(fd, server::SOCKET_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            // The spawner gets its stdio and its socket. Anything else the
            // caller has open without close-on-exec, say another box's
            // terminal caught between its open and its flag, stops at the
            // exec.
            if libc::syscall(
                libc::SYS_close_range,
                server::SOCKET_FD + 1,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// What a container's command needs beyond its program.
#[derive(Clone)]
pub(crate) struct Launch {
    pub(crate) container: ContainerSpec,
    pub(crate) gate: Option<PathBuf>,
    pub(crate) session: Session,
    pub(crate) lo_up: bool,
    /// The cgroup of the box the container belongs to.
    pub(crate) cgroup: Option<BoxCgroup>,
    /// The CPU weight of a container that gets a cgroup of its own. A
    /// container in a box's cgroup shares the box's CPU time unweighted.
    pub(crate) cpu_weight: Option<u64>,
}

enum Target {
    Container {
        spawner: Spawner,
        launch: Box<Launch>,
    },
    Running(Entrance),
}

/// A program to start through a spawner, built like a
/// [`std::process::Command`].
///
/// The program gets the environment set here and nothing else.
pub struct Command {
    target: Target,
    program: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Command")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

impl Command {
    /// Adds arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args
            .extend(args.into_iter().map(|arg| arg.as_ref().to_string()));
        self
    }

    /// Sets a variable of the program's environment.
    pub fn env(&mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> &mut Self {
        self.env
            .insert(key.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Sets variables of the program's environment.
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, value) in vars {
            self.env(key, value);
        }
        self
    }

    /// Sets the program's working directory, as the box names it.
    pub fn current_dir(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Sets the program's standard input.
    pub fn stdin(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        self.stdin = stdio.into();
        self
    }

    /// Sets the program's standard output.
    pub fn stdout(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        self.stdout = stdio.into();
        self
    }

    /// Sets the program's standard error.
    pub fn stderr(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        self.stderr = stdio.into();
        self
    }

    /// Runs the program to its end with its output captured.
    ///
    /// # Errors
    ///
    /// Fails as [`Self::spawn`] does, or if the output cannot be read.
    pub fn output(&mut self) -> io::Result<Output> {
        use std::io::Read as _;

        self.stdout(Stdio::MakePipe).stderr(Stdio::MakePipe);
        let mut child = self.spawn()?;
        let mut out = child.stdout.take().expect("stdout is a pipe");
        let mut err = child.stderr.take().expect("stderr is a pipe");
        // Read side by side, so a program that fills one pipe is not stuck
        // behind the other.
        let (stdout, stderr) = std::thread::scope(|scope| {
            let stderr = scope.spawn(move || {
                let mut bytes = Vec::new();
                err.read_to_end(&mut bytes).map(|_| bytes)
            });
            let mut bytes = Vec::new();
            let stdout = out.read_to_end(&mut bytes).map(|_| bytes);
            (stdout, stderr.join().expect("the stderr reader panicked"))
        });
        Ok(Output {
            stdout: stdout?,
            stderr: stderr?,
            status: child.wait(),
        })
    }

    /// Starts the program. The call returns once the program's process
    /// exists, and blocks until then.
    ///
    /// The standard streams set on the command go to this one program, and
    /// a second `spawn` inherits the requester's.
    ///
    /// # Errors
    ///
    /// Fails if the spawner is gone, or if it could not create the process.
    pub fn spawn(&mut self) -> io::Result<Child> {
        let take = |stdio: &mut Stdio| std::mem::replace(stdio, Stdio::Inherit);
        let (stdin, stdin_ours) = take(&mut self.stdin).ends(0)?;
        let (stdout, stdout_ours) = take(&mut self.stdout).ends(1)?;
        let (stderr, stderr_ours) = take(&mut self.stderr).ends(2)?;
        let env: Vec<(String, String)> = self
            .env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        let (connection, cgroup, own_cgroup) = match &self.target {
            Target::Container { spawner, launch } => {
                let connection = spawner.connection()?;
                match (&launch.cgroup, &spawner.inner.root) {
                    (Some(cgroup), _) => (connection, Some(cgroup.clone()), None),
                    (None, Some(root)) => {
                        let own = Spawner::own_cgroup(root, launch.cpu_weight)?;
                        (connection, Some(own.clone()), Some(own))
                    }
                    (None, None) => (connection, None, None),
                }
            }
            Target::Running(entrance) => (
                Arc::clone(&entrance.connection),
                entrance.cgroup.clone(),
                None,
            ),
        };
        let mut fds = vec![stdin.as_fd(), stdout.as_fd(), stderr.as_fd()];
        fds.extend(cgroup.as_ref().map(BoxCgroup::dir_fd));
        let has_cgroup = cgroup.is_some();
        let started = match &self.target {
            Target::Container { launch, .. } => {
                let run = wire::Run {
                    container: launch.container.clone(),
                    program: self.program.clone(),
                    args: self.args.clone(),
                    env,
                    cwd: self.cwd.clone(),
                    gate: launch.gate.clone(),
                    session: launch.session,
                    lo_up: launch.lo_up,
                };
                connection.start(
                    |id| wire::Request::Run {
                        id,
                        run,
                        cgroup: has_cgroup,
                    },
                    &fds,
                    true,
                    own_cgroup,
                )?
            }
            Target::Running(entrance) => {
                let enter = wire::Enter {
                    program: self.program.clone(),
                    args: self.args.clone(),
                    env,
                    cwd: self.cwd.clone(),
                };
                let into = entrance.job;
                connection.start(
                    |id| wire::Request::Enter {
                        id,
                        into,
                        enter,
                        cgroup: has_cgroup,
                    },
                    &fds,
                    false,
                    None,
                )?
            }
        };
        Ok(Child {
            stdin: stdin_ours.map(PipeWriter::from),
            stdout: stdout_ours.map(PipeReader::from),
            stderr: stderr_ours.map(PipeReader::from),
            pid: started.pid,
            tap: started.tap,
            job: started.id,
            outcome: started.outcome,
            connection,
            cgroup,
        })
    }
}

/// What a program that ran to its end left.
#[derive(Debug, Clone)]
pub struct Output {
    /// How it ended.
    pub status: ExitStatus,
    /// What it wrote to its standard output.
    pub stdout: Vec<u8>,
    /// What it wrote to its standard error.
    pub stderr: Vec<u8>,
}

/// Which process of a job a signal goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalTarget {
    /// The job's own process: a container's supervisor, which takes the
    /// container with it, or an entered program's shim, which forwards a
    /// termination signal to the program's process group.
    Job,
    /// A container's first process, the program the container was started
    /// for.
    Program,
}

/// A started job. Dropping it kills the job.
pub struct Child {
    /// The program's standard input, when it is a pipe.
    pub stdin: Option<PipeWriter>,
    /// The program's standard output, when it is a pipe.
    pub stdout: Option<PipeReader>,
    /// The program's standard error, when it is a pipe.
    pub stderr: Option<PipeReader>,
    pid: u32,
    tap: Option<OwnedFd>,
    job: u64,
    outcome: Arc<client::Outcome>,
    connection: Arc<Connection>,
    cgroup: Option<BoxCgroup>,
}

impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Child")
            .field("pid", &self.pid)
            .field("job", &self.job)
            .finish_non_exhaustive()
    }
}

impl Child {
    /// The pid of the job's own process: a container's supervisor, which
    /// holds the container's user and network namespaces, or an entered
    /// program's shim. The spawner reaps it when it exits, so the pid names
    /// it only while the job runs.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// The tap the container was started with. Yields it once.
    pub fn take_tap_fd(&mut self) -> Option<OwnedFd> {
        self.tap.take()
    }

    /// How the job ended, if it has.
    #[must_use]
    pub fn try_wait(&self) -> Option<ExitStatus> {
        self.outcome.get()
    }

    /// Closes the program's standard input and blocks until the job has
    /// ended.
    pub fn wait(&mut self) -> ExitStatus {
        drop(self.stdin.take());
        self.outcome.wait()
    }

    /// Resolves once the job has ended.
    pub async fn exited(&self) -> ExitStatus {
        self.outcome.ended().await
    }

    /// Kills the job.
    pub fn kill(&self) {
        self.signal(libc::SIGKILL, SignalTarget::Job);
    }

    /// Sends `signal` to a process of the job.
    pub fn signal(&self, signal: i32, target: SignalTarget) {
        if self.outcome.get().is_none() {
            self.connection
                .signal(self.job, signal, target == SignalTarget::Program);
        }
    }

    /// The way into this container for more programs and sockets.
    #[must_use]
    pub fn entrance(&self) -> Entrance {
        Entrance {
            connection: Arc::clone(&self.connection),
            job: self.job,
            cgroup: self.cgroup.clone(),
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.outcome.get().is_none() {
            self.connection.forget(self.job);
        }
    }
}

/// The way into a running container: what starts more programs in it and
/// creates sockets in its network namespace. It holds no claim on the
/// container, and fails once the container has ended.
#[derive(Clone)]
pub struct Entrance {
    connection: Arc<Connection>,
    job: u64,
    cgroup: Option<BoxCgroup>,
}

impl std::fmt::Debug for Entrance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entrance")
            .field("job", &self.job)
            .finish_non_exhaustive()
    }
}

impl Entrance {
    /// A command that runs `program` in the container: in its namespaces
    /// and in its cgroup, with the box's seccomp profile.
    pub fn command<I, S>(&self, program: impl AsRef<str>, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut command = Command {
            target: Target::Running(self.clone()),
            program: program.as_ref().to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
        };
        command.args(args);
        command
    }

    /// Creates a socket in the container's network namespace and cgroup.
    ///
    /// # Errors
    ///
    /// Fails if the container has ended or the socket cannot be created.
    pub fn socket(&self, v6: bool, datagram: bool) -> io::Result<OwnedFd> {
        self.connection.socket(
            Some(self.job),
            v6,
            datagram,
            self.cgroup.as_ref().map(BoxCgroup::dir_fd),
        )
    }
}
