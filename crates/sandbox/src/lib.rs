//! The low-level sandbox implementation.
//!
//! Build a [`Config`] and use it to construct a [`Sandbox`].
//!
//! There are two main variants of sandboxes:
//!
//!  * those configured with [`WdSetup::Isolated`], which have no state directory, file mappings to the host system,
//!    or mapped cwd. These are 'cleanroom' sandboxes, for hermetic builds.
//!  * those configured with [`WdSetup::BoundDir`], which map a directory from the host for the cwd, allow additional
//!    filesystem mappings into the sandbox, allows wiring a `/state` directory, and brings across a host of default
//!    environment variables (like TERM) from the host. These are for task sandboxes.

pub mod config;
use config::Config;
pub mod network;
pub use network::{
    AbandonFuture, AttachFuture, HOST_MIN_INTERNAL, HostEntry, HostNet, NetGuard, NetPlan, Network,
    NetworkError, NoNet, PlanFuture, Resolver, Spawned, TapSpec,
};
use std::fs::{self, Permissions};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
#[cfg(target_os = "linux")]
pub mod cgroup;
/// Box cgroups exist on Linux only. The handle has no value elsewhere, so a
/// sandbox configuration there never carries one.
#[cfg(not(target_os = "linux"))]
pub mod cgroup {
    /// The cgroup of one box.
    #[derive(Debug, Clone)]
    pub enum BoxCgroup {}

    impl BoxCgroup {
        /// The cgroup's name, the id of its box.
        #[must_use]
        pub fn name(&self) -> &str {
            match *self {}
        }
    }
}
pub mod error;
#[cfg(target_os = "linux")]
pub mod seccomp;
#[cfg(target_os = "linux")]
pub mod spawner;
#[cfg(target_os = "linux")]
use crate::config::Invocation;
use crate::config::WdSetup;
#[cfg(target_os = "linux")]
use crate::error::ExecutionError;
pub use error::Error;
#[cfg(target_os = "linux")]
pub use spawner::{
    Child, Command, Entrance, ExitStatus, Output, SignalTarget, Spawner, Stdio, Terminal,
};

mod listener;

/// Something that handles line-oriented RPCs from within the sandbox.
pub trait Channel: Send {
    // Return true to close the connection.
    fn handle(&mut self, stream: &mut UnixStream, line: &str, rootfs: &Path);

    /// Handles a request line that was not valid UTF-8. `line` is its lossy
    /// decode, with each invalid byte replaced by U+FFFD, and `raw` is the
    /// line as the box sent it, so a channel can tell which values held an
    /// invalid byte. The default handles `line` as [`Channel::handle`] does.
    fn handle_lossy(&mut self, stream: &mut UnixStream, line: &str, raw: &[u8], rootfs: &Path) {
        let _ = raw;
        self.handle(stream, line, rootfs);
    }
}

impl Channel for () {
    fn handle(&mut self, stream: &mut UnixStream, _line: &str, _rootfs: &Path) {
        writeln!(stream, "error: no handler!").ok();
    }
}

/// The name of the working directory inside a session sandbox: the host
/// directory given to [`Config::with_session_dirs`] is bind-mounted at
/// `/{SESSION_DEFAULT_WD}` unless the config overrides the name.
///
/// Exported so callers that have to translate between a path typed inside the
/// sandbox and the host directory backing it agree with the mount on where it
/// lives.
///
/// [`Config::with_session_dirs`]: config::Config::with_session_dirs
pub const SESSION_DEFAULT_WD: &str = "workbench";

/// The name of the home directory inside a session sandbox: the host directory
/// given to [`Config::with_session_dirs`] is bind-mounted at `/{SESSION_HOME}`.
///
/// Exported for the same reason as [`SESSION_DEFAULT_WD`].
///
/// [`Config::with_session_dirs`]: config::Config::with_session_dirs
pub const SESSION_HOME: &str = "home";

/// An initialized sandbox.
///
/// Sandboxes can have a [`Channel`] wired to the outside world for interactive operations and mutations
/// to the sandbox itself that originate from inside the sandbox. Pass `()` as the channel to have this
/// be effectively disabled.
#[derive(Debug)]
pub struct Sandbox<C: Channel = ()> {
    pub(crate) base_dir: PathBuf,
    #[cfg(target_os = "linux")]
    pub(crate) state_dir: PathBuf,
    pub(crate) config: Config,

    keep_dir: bool,
    stdout: Option<fs::File>,
    stderr: Option<fs::File>,

    listener: Option<listener::Listener<C>>,
}

impl<C: Channel> Drop for Sandbox<C> {
    fn drop(&mut self) {
        drop(self.listener.take()); // drop the listener first to clean up the listening thread

        if let Some(stdout) = self.stdout.take() {
            if let Err(e) = stdout.sync_all() {
                tracing::warn!("Failed fsync of stdout file: {}", e,);
            }
            drop(stdout);
        }
        if let Some(stderr) = self.stderr.take() {
            if let Err(e) = stderr.sync_all() {
                tracing::warn!("Failed fsync of stderr file: {}", e,);
            }
            drop(stderr);
        }

        if !self.keep_dir
            && let Err(e) = common::remove_dir_all(&self.base_dir)
        {
            tracing::warn!(
                "Failed cleanup for sandbox at path {}: {}",
                self.base_dir.display(),
                e,
            );
        }
    }
}

// Sandbox initialization
impl<C: Channel> Sandbox<C> {
    /// The working directory a command in this sandbox starts in, as an
    /// absolute path inside the sandbox.
    ///
    /// Exposed so a caller that runs a process in this sandbox by some route
    /// other than [`Self::command`] — minimald joining a live session's
    /// namespaces — starts it where the sandbox's own process started.
    pub fn command_cwd(&self) -> Result<String, Error> {
        self.config.command_cwd()
    }

    /// The environment a command in this sandbox is launched with, before any
    /// per-invocation additions. Companion to [`Self::command_cwd`].
    #[must_use]
    pub fn command_env(&self) -> std::collections::BTreeMap<String, String> {
        self.config.command_env()
    }

    /// Holds the program of every command `container` spawns at a start gate:
    /// the command's pre-exec closure waits, just before it execs the
    /// program, until the returned [`StartGate`] is released or dropped.
    ///
    /// For a launch whose box must exist before its program may run: a
    /// session's activate hooks run in the box, and the box's program is the
    /// session's interactive shell, whose startup files must not run before
    /// those hooks have.
    ///
    /// The gate is a FIFO in the box's `/run`, which the daemon creates and
    /// holds open for writing. The box opens it, removes its name, and waits
    /// for end-of-file, which the kernel delivers when the last writer
    /// closes. Each call makes a FIFO of its own, so releasing one gate
    /// starts no other container's program. The gate only delays the
    /// program. Nothing about the box's confinement depends on it.
    #[cfg(target_os = "linux")]
    #[tracing::instrument(level = "info", skip_all, err)]
    pub fn hold_start(&self, container: &mut Container) -> Result<StartGate, Error> {
        use std::os::fd::FromRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;

        static NEXT_GATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let name = format!(
            "{START_GATE_NAME}-{}",
            NEXT_GATE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let path = self.base_dir.join("run").join(&name);
        // A FIFO left at this name by an earlier daemon process has no
        // writer; replace it rather than share it.
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::IO("removing a stale start gate", path, e)),
        }
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| {
            Error::IO(
                "naming the start gate",
                path.clone(),
                std::io::Error::other(e),
            )
        })?;
        // SAFETY: `mkfifo(3)` with a NUL-terminated path and a mode.
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            return Err(Error::IO(
                "creating the start gate",
                path,
                std::io::Error::last_os_error(),
            ));
        }
        // `O_RDWR` on a FIFO opens without waiting for a reader (Linux
        // `fifo(7)`), and makes this the writer whose close releases the box.
        // SAFETY: `open(2)` with a NUL-terminated path.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Error::IO(
                "opening the start gate",
                path,
                std::io::Error::last_os_error(),
            ));
        }
        container.launch.gate = Some(Path::new("/run").join(&name));
        Ok(StartGate {
            // SAFETY: `fd` is a fresh descriptor nothing else owns.
            _writer: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            path,
        })
    }

    /// Creates a new sandbox, containing all filesystem state within `base_dir`.
    #[tracing::instrument(level = "info", skip_all, err)]
    pub(crate) fn new(base_dir: PathBuf, config: Config, channel: C) -> Result<Self, Error> {
        // Setup the rootfs
        let rootfs = base_dir.join("rootfs");
        fs::create_dir_all(&rootfs)
            .map_err(|e| Error::IO("create rootfs dir", rootfs.clone(), e))?;
        let hardlinking_start = SystemTime::now();
        let mut collisions = common::LinkCollisions::default();
        for i in config.rootfs.iter() {
            match i {
                config::SandboxMapped::Dir(p) => {
                    hardlink_dir_contents_counted(p, &rootfs, &mut collisions)?;
                }
                config::SandboxMapped::TempDir(td) => {
                    hardlink_dir_contents_counted(td.path(), &rootfs, &mut collisions)?;
                }
                config::SandboxMapped::File(p) | config::SandboxMapped::FileCopy(p) => {
                    return Err(Error::MappedFile(p.clone()));
                }
            }
        }
        hardlink_dir_contents_counted(&base_dir.join("synth"), &rootfs, &mut collisions)?;

        // MINIMAL_INTERNAL_CS_BUILD bundle: when the env var is "1"
        // AND the convention path exists on host, hardlink that
        // directory's contents into the sandbox rootfs root. This is
        // the same mechanism the public `extra_rootfs` field used to
        // provide; it now happens behind the (undocumented) CS flag
        // with a hardcoded convention path, so there's no new public
        // API surface.
        //
        // Convention: minimalmertic's hermetic-builder-rs stages its
        // CS-only cache bundle (cargo-vendor, npm-cache, pnpm-store,
        // bun-cache, pip-wheels, rust-stage0, goproxy) at
        // /root/.cache/minimal/cs-mirror/. Inside the sandbox these
        // appear at /cargo-vendor, /goproxy, etc. — top-level paths
        // matching the existing pkg-build.sh offline-cache idiom.
        //
        // Inert when env var unset or the convention path doesn't
        // exist (tests, dev environments, non-CS callers).
        if std::env::var("MINIMAL_INTERNAL_CS_BUILD").as_deref() == Ok("1") {
            let cs_mirror = Path::new("/root/.cache/minimal/cs-mirror");
            if cs_mirror.exists() {
                hardlink_dir_contents_counted(cs_mirror, &rootfs, &mut collisions)?;
            }
        }
        log_rootfs_collisions(&collisions);
        tracing::trace!("rootfs hardlinking took {:?}", hardlinking_start.elapsed());

        // On aarch64, autotools/libtool defaults to installing libraries
        // into lib64/. Create a usr/lib64 → lib symlink in the rootfs so
        // configure scripts detect it and use usr/lib/ instead. Also create
        // the same symlink in the output directory so DESTDIR installs that
        // still target lib64/ land in lib/ transparently.
        let usr_lib64 = rootfs.join("usr").join("lib64");
        if !fs::exists(&usr_lib64).unwrap_or(true) {
            std::os::unix::fs::symlink("lib", &usr_lib64)
                .map_err(|e| Error::IO("create usr/lib64 symlink", usr_lib64, e))?;
        }

        // Setup the working directory
        match &config.wd {
            WdSetup::Isolated { working_inputs } => {
                let b = base_dir.join("build");
                fs::create_dir_all(&b).map_err(|e| Error::IO("create build dir", b.clone(), e))?;

                let hardlinking_start = SystemTime::now();
                for i in working_inputs {
                    match i {
                        config::SandboxMapped::File(p) => {
                            let dest = &b.join(p.file_name().unwrap());
                            match fs::hard_link(p, dest) {
                                Ok(()) => Ok(()),
                                Err(e) => {
                                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                                        log_input_collision("linking", p, dest);
                                        Ok(())
                                    } else {
                                        Err(e)
                                    }
                                }
                            }
                            .map_err(|e| Error::IO("hardlinking input file", dest.clone(), e))?;
                        }
                        config::SandboxMapped::FileCopy(p) => {
                            let dest = b.join(p.file_name().unwrap());
                            if !copy_input_file(p, &dest)
                                .map_err(|e| Error::IO("copying input file", dest.clone(), e))?
                            {
                                log_input_collision("copying", p, &dest);
                            }
                        }
                        config::SandboxMapped::Dir(p) => hardlink_dir_contents(p, &b)?,
                        config::SandboxMapped::TempDir(td) => hardlink_dir_contents(td.path(), &b)?,
                    }
                }
                tracing::trace!("input hardlinking took {:?}", hardlinking_start.elapsed());

                let output = b.join("output");
                fs::create_dir_all(&output)
                    .map_err(|e| Error::IO("create output dir", b.clone(), e))?;

                // Mirror the usr/lib64 → lib symlink into the output dir so
                // that DESTDIR installs targeting lib64/ land in lib/.
                let out_usr_lib = output.join("usr").join("lib");
                fs::create_dir_all(&out_usr_lib)
                    .map_err(|e| Error::IO("create output usr/lib", out_usr_lib.clone(), e))?;
                let out_usr_lib64 = output.join("usr").join("lib64");
                std::os::unix::fs::symlink("lib", &out_usr_lib64)
                    .map_err(|e| Error::IO("create output usr/lib64 symlink", out_usr_lib64, e))?;
            }
            WdSetup::BoundDir { .. } => {
                let rootfs_cwd = rootfs.join(config.wd.bound_dir_sandbox_cwd());
                fs::create_dir_all(&rootfs_cwd)
                    .map_err(|e| Error::IO("create shadow cwd tree", rootfs_cwd, e))?;
            }
            WdSetup::Session {
                working_name_override,
                ..
            } => {
                let rootfs_cwd = rootfs.join(
                    working_name_override
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(|| SESSION_DEFAULT_WD.to_string()),
                );
                fs::create_dir_all(&rootfs_cwd)
                    .map_err(|e| Error::IO("create cwd", rootfs_cwd, e))?;
                let rootfs_home = rootfs.join(SESSION_HOME);
                fs::create_dir_all(&rootfs_home)
                    .map_err(|e| Error::IO("create home", rootfs_home.clone(), e))?;
            }
        }

        // Create bind-mount targets for the file mappings (none for an
        // isolated working directory).
        for m in config.wd.fs_mappings() {
            let sp = m.path_in_sandbox();
            let sp = match sp.strip_prefix("/") {
                Some(stripped) => stripped,
                None => &sp,
            };
            let p = rootfs.join(sp);

            if m.is_file {
                fs::create_dir_all(p.parent().unwrap())
                    .map_err(|e| Error::IO("create mapping parent", p, e))?;
            } else {
                fs::create_dir_all(&p).map_err(|e| Error::IO("create mapping target", p, e))?;
            }
        }

        // Setup /state
        let state_dir = match &config.state_dir {
            None => base_dir.join("state"),
            Some(s) => s.to_path_buf(),
        };

        if !matches!(&config.wd, WdSetup::Session { .. }) {
            fs::create_dir_all(state_dir.join("home"))
                .map_err(|e| Error::IO("mkdir /state/home", state_dir.join("home"), e))?;
            fs::create_dir_all(state_dir.join("data"))
                .map_err(|e| Error::IO("mkdir /state/data", state_dir.join("data"), e))?;
            fs::create_dir_all(state_dir.join("state"))
                .map_err(|e| Error::IO("mkdir /state/state", state_dir.join("state"), e))?;
        }
        fs::create_dir_all(state_dir.join("cache"))
            .map_err(|e| Error::IO("mkdir /state/cache", state_dir.join("cache"), e))?;

        // Create /run/minenv_sock as the pipe to higher-level functions.
        let run_dir = base_dir.join("run");
        fs::create_dir_all(&run_dir).map_err(|e| Error::IO("mkdir /run", run_dir.clone(), e))?;
        fs::set_permissions(&run_dir, Permissions::from_mode(0o700))
            .map_err(|e| Error::IO("set perms /run", run_dir.clone(), e))?;
        let sock_path = run_dir.join("minenv_sock");
        let listener = listener::Listener::new(&sock_path, &rootfs, channel)
            .map_err(|e| Error::IO("creating env socket", sock_path, e))?;

        let stdout = fs::File::create(base_dir.join("stdout"))
            .map_err(|e| Error::IO("creating stdout", base_dir.join("stdout"), e))?;
        let stderr = fs::File::create(base_dir.join("stderr"))
            .map_err(|e| Error::IO("creating stderr", base_dir.join("stderr"), e))?;

        Ok(Self {
            base_dir,
            #[cfg(target_os = "linux")]
            state_dir,
            config,
            keep_dir: false,
            stdout: Some(stdout),
            stderr: Some(stderr),
            listener: Some(listener),
        })
    }

    #[cfg(target_os = "linux")]
    fn needs_lib64_symlink(&self) -> Result<bool, Error> {
        let lib64_p = self.rootfs().join("lib64");
        Ok(!fs::exists(&lib64_p)
            .map_err(|e| Error::IO("checking for lib64 directory", lib64_p, e))?)
    }
    #[cfg(target_os = "linux")]
    fn needs_lib_symlink(&self) -> Result<bool, Error> {
        let lib_p = self.rootfs().join("lib");
        Ok(!fs::exists(&lib_p).map_err(|e| Error::IO("checking for lib directory", lib_p, e))?)
    }
    #[cfg(target_os = "linux")]
    fn needs_bin_symlink(&self) -> Result<bool, Error> {
        let bin_p = self.rootfs().join("bin");
        Ok(!fs::exists(&bin_p).map_err(|e| Error::IO("checking for bin directory", bin_p, e))?)
    }

    /// Configures the sandbox to not delete itself when dropped.
    pub fn keep_dir(&mut self, keep_dir: bool) {
        self.keep_dir = keep_dir;
    }

    /// Path to the rootfs of the sandbox.
    pub fn rootfs(&self) -> PathBuf {
        self.base_dir.join("rootfs")
    }
}

/// A container of this sandbox, ready to run commands: what
/// [`Sandbox::new_container`] decided, as the spawner takes it.
#[cfg(target_os = "linux")]
pub struct Container {
    launch: spawner::Launch,
}

/// The prefix of a start gate's FIFO name in the box's `/run`; each gate adds
/// its own number. See [`Sandbox::hold_start`].
pub const START_GATE_NAME: &str = "minimal-start-gate";

/// The daemon's half of a box's start gate: the one writer of the FIFO the
/// box's first process waits on, just before it execs its program. The
/// program runs once every writer has closed, so dropping this — or calling
/// [`Self::release`], which says so at the call site — lets it start. A
/// daemon that loses the gate any other way (its host dropped, the daemon
/// gone) releases it too: the gate can delay the program, never wedge it.
#[derive(Debug)]
pub struct StartGate {
    _writer: std::os::fd::OwnedFd,
    /// The FIFO, host-side, removed when the gate goes. A box that has not
    /// opened it by then finds no gate and runs at once, which is what a
    /// released gate means anyway.
    path: PathBuf,
}

impl StartGate {
    /// Lets the gated program exec.
    pub fn release(self) {}
}

impl Drop for StartGate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "linux")]
impl Container {
    /// Makes each command from this container the leader of a new session
    /// whose controlling terminal is the command's stdin.
    pub fn set_session_leader(&mut self) {
        self.launch.session = spawner::Session::NewWithTerminal;
    }

    /// Makes each command from this container the leader of a new session
    /// and process group, without a controlling terminal. For a program
    /// whose stdin is not a terminal, where taking one fails.
    pub fn set_session_leader_without_terminal(&mut self) {
        self.launch.session = spawner::Session::New;
    }
}

/// Replaces `command` with one that runs the box's pre-exec steps in the
/// forked child and then execs the program `command` named.
///
/// hakoniwa builds the namespaces, the mounts and the id map. These are the
/// steps it has no option for: bringing `lo` up in a fresh network namespace
/// that gets no tap, loading the seccomp profile, and waiting at the start
/// gate.
///
/// `command_from_closure` starts a fresh `Command`, so the working directory
/// and environment already set on `command` are carried over to it: hakoniwa
/// `chdir`s and rebuilds the child's `environ` from the command it spawns,
/// and the exec in the closure inherits both. Whatever a caller sets on the
/// returned command afterwards (`SHELL`, `PS1`, stdio) lands on the closure
/// command and reaches the program the same way.
#[cfg(target_os = "linux")]
pub(crate) fn with_box_closure(
    container: &hakoniwa::Container,
    command: &mut hakoniwa::Command,
    lo_up: bool,
    start_gate: Option<PathBuf>,
    new_session: bool,
) {
    let program = command.get_program().to_string();
    let args = command.get_args();
    let current_dir = command.get_current_dir().map(Path::to_path_buf);
    let envs = command.get_envs();
    // Compiled here, before any fork, so the closure only loads it.
    let seccomp_program = seccomp::box_program();
    // SAFETY: the closure runs in a forked child of a process whose other
    // threads, if any, are not copied. It allocates (the argv `CString`s, a
    // failure message), as hakoniwa's own closure path does, and never
    // returns: it execs or `_exit`s.
    let mut closure = unsafe {
        container.command_from_closure(move || {
            exec_box_program(
                &program,
                &args,
                seccomp_program,
                lo_up,
                start_gate.as_deref(),
                new_session,
            )
        })
    };
    if let Some(dir) = current_dir {
        closure.current_dir(dir);
    }
    closure.envs(envs);
    *command = closure;
}

/// Brings the loopback interface up in the current network namespace.
///
/// A fresh network namespace starts with `lo` down, and hakoniwa brings it
/// up only where it builds a tap.
#[cfg(target_os = "linux")]
fn bring_lo_up() -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: socket(2) with valid arguments; async-signal-safe.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid, owned socket fd.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = sock.as_raw_fd();

    #[repr(C)]
    struct IfReqFlags {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    let mut name_buf = [0 as libc::c_char; libc::IFNAMSIZ];
    for (dst, b) in name_buf.iter_mut().zip(b"lo".iter()) {
        *dst = *b as libc::c_char;
    }

    let mut flags = IfReqFlags {
        name: name_buf,
        flags: 0,
        _pad: [0; 22],
    };

    // SAFETY: fd open; ifreq sized for the flags ioctls.
    if unsafe {
        libc::ioctl(
            fd,
            libc::SIOCGIFFLAGS as _,
            std::ptr::from_mut(&mut flags).cast::<libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    flags.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    // SAFETY: fd open; ifreq sized for the flags ioctls.
    if unsafe {
        libc::ioctl(
            fd,
            libc::SIOCSIFFLAGS as _,
            std::ptr::from_mut(&mut flags).cast::<libc::c_void>(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The box's pre-exec steps, then the exec of its program. Never returns: a
/// failure is reported on the child's stderr and exits the child with the
/// shell's "cannot run" status.
#[cfg(target_os = "linux")]
fn exec_box_program(
    program: &str,
    args: &[String],
    seccomp_program: &'static seccomp::Program,
    lo_up: bool,
    start_gate: Option<&Path>,
    new_session: bool,
) -> ! {
    // A new session and process group for the program, with no controlling
    // terminal: the box's processes then share neither with the daemon.
    // SAFETY: `setsid(2)` takes no arguments. It fails only for a process
    // group leader, which this forked child is not.
    if new_session && unsafe { libc::setsid() } == -1 {
        exit_child(
            "starting the box's own session",
            &std::io::Error::last_os_error(),
        );
    }
    // A box whose `lo` stays down still runs, without loopback.
    if lo_up && let Err(e) = bring_lo_up() {
        report_from_child("bringing up the loopback interface", &e);
    }
    let start_gate = start_gate.and_then(open_start_gate);
    if let Err(e) = seccomp::install(seccomp_program) {
        exit_child("installing the seccomp profile", &e);
    }
    if let Some(gate) = start_gate {
        wait_at_start_gate(&gate);
    }
    let e = execv_in_child(program, args);
    exit_child(&format!("exec {program}"), &e)
}

/// Exec into `program` with `args` from the forked child of a hakoniwa
/// `command_from_closure` closure; returns only when the exec failed.  The
/// environment is not passed explicitly: `execv` hands the program the
/// `environ` hakoniwa rebuilt from the command's final `envs` just before
/// running the closure.
#[cfg(target_os = "linux")]
fn execv_in_child(program: &str, args: &[String]) -> std::io::Error {
    let argv_c: Result<Vec<std::ffi::CString>, _> = std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(std::ffi::CString::new)
        .collect();
    let argv_c = match argv_c {
        Ok(argv) => argv,
        Err(_) => return std::io::Error::from_raw_os_error(libc::EINVAL),
    };
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // SAFETY: execv only touches the C strings we just built, which `argv_c`
    // keeps alive for the call.
    unsafe { libc::execv(argv_c[0].as_ptr(), argv_ptrs.as_ptr()) };
    // execv returns only on failure.
    std::io::Error::last_os_error()
}

/// Opens the box's end of its start gate and removes the gate's name, so no
/// path to it is left once the program runs. Non-blocking for the open, so a
/// gate with no writer left cannot park the child in `open(2)`; blocking
/// again for the read. A gate that cannot be opened is one the daemon
/// already released, and is not waited on.
#[cfg(target_os = "linux")]
fn open_start_gate(path: &Path) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `open(2)` with a NUL-terminated path.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a fresh descriptor this child owns.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    // SAFETY: `unlink(2)` with the same NUL-terminated path, and `fcntl(2)`
    // on the descriptor just opened.
    let cleared = unsafe {
        libc::unlink(path.as_ptr());
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        flags >= 0 && libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) == 0
    };
    cleared.then_some(fd)
}

/// Waits until the daemon releases the start gate: a read on the FIFO
/// returns end-of-file once its last writer closes. Bytes are read and
/// dropped, so nothing written into the gate releases it.
#[cfg(target_os = "linux")]
fn wait_at_start_gate(gate: &std::os::fd::OwnedFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `read(2)` into a buffer that outlives the call.
        let n = unsafe {
            libc::read(
                std::os::fd::AsRawFd::as_raw_fd(gate),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        match n {
            0 => return,
            n if n > 0 => {}
            _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
            // A gate that cannot be read cannot be waited on.
            _ => return,
        }
    }
}

/// Writes a failure of the forked child to its stderr. Called after the
/// fork, so it uses `write(2)` and not the Rust stdio machinery.
#[cfg(target_os = "linux")]
fn report_from_child(what: &str, err: &std::io::Error) {
    let msg = format!("minimal: sandbox: {what} failed: {err}\n");
    // SAFETY: `write(2)` from a buffer that outlives the call.
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
    }
}

/// Reports a failure of the forked child and exits it with 127, the shell's
/// "cannot run" status, so a spawn that never reached the program is
/// distinguishable from the program's own exit codes.
#[cfg(target_os = "linux")]
fn exit_child(what: &str, err: &std::io::Error) -> ! {
    report_from_child(what, err);
    // SAFETY: `_exit(2)` does not return.
    unsafe { libc::_exit(127) }
}

/// Options for [`Sandbox::bind_mount`].
#[derive(Debug, Default, Clone, Copy)]
#[cfg(target_os = "linux")]
struct BindOpts {
    read_only: bool,
    recursive: bool,
}

// Sandbox usage
#[cfg(target_os = "linux")]
impl<C: Channel> Sandbox<C> {
    fn bind_mount(
        path: &Path,
        container_path: &str,
        opts: BindOpts,
        mounts: &mut Vec<spawner::Mount>,
    ) -> Result<(), Error> {
        let mut flags = hakoniwa::MountOptions::BIND
            | hakoniwa::MountOptions::NOSUID
            | locked_mount_flags(path);
        if opts.recursive {
            flags |= hakoniwa::MountOptions::REC;
        }
        if opts.read_only {
            flags |= hakoniwa::MountOptions::RDONLY;
        }
        let source = path.to_str().ok_or_else(|| {
            Error::Execution(ExecutionError::MountError {
                msg: "Unable to convert path to unicode string",
                path: path.to_path_buf(),
            })
        })?;
        mounts.push(spawner::Mount {
            source: source.to_string(),
            target: container_path.to_string(),
            fstype: String::new(),
            options: flags.bits(),
            data: None,
        });
        Ok(())
    }

    /// The network plan this sandbox's own configuration implies: its
    /// [`plan`](config::Config::plan), carrying the host resolver when
    /// [`setup_dns_config`](config::Config::setup_dns_config) asks for one.
    #[must_use]
    pub fn built_in_plan(&self) -> network::NetPlan {
        plan_from_config(&self.config)
    }

    /// Step 1 of a launch: ask the provider what this sandbox needs. A sandbox
    /// with no provider is planned by its own configuration, through the same
    /// sequence. From here the plan's release is owed; see [`PlannedLaunch`].
    ///
    /// Not an `async fn`: that would hold `&Sandbox<C>` across the await and
    /// impose `C: Sync` on every caller's future, which the build path does
    /// not satisfy.
    ///
    /// # Errors
    ///
    /// Propagates the provider's planning failure.
    pub fn plan_launch(
        &self,
    ) -> impl Future<Output = Result<PlannedLaunch, Error>> + Send + 'static {
        let network = self
            .config
            .network
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(self.built_in_plan()));
        PlannedLaunch::begin(network)
    }

    /// Decides the container for this sandbox under `plan`: its mounts, its
    /// namespaces and its network. A command of the container starts it,
    /// through the spawner, in the sandbox's box cgroup when it has one.
    #[cfg(target_os = "linux")]
    pub fn new_container(&self, plan: &network::NetPlan) -> Result<Container, Error> {
        // An isolating plan gets a network namespace with only `lo`, which
        // the provider wires once the process exists. A host that cannot
        // make the namespace fails the launch.
        let isolate = isolation_decision(plan, network_namespaces_available())?;
        // A plan cannot describe a tap without isolation.
        let tap = plan.tap().map(|tap| spawner::Tap {
            address: tap.address,
            netmask: tap.netmask,
            gateway: tap.gateway,
            mtu: tap.mtu,
        });
        let mut mounts = Vec::new();
        let mut symlinks = Vec::new();

        let rec = BindOpts {
            recursive: true,
            read_only: false,
        };
        Self::bind_mount(&self.state_dir, "/state", rec, &mut mounts)?;
        Self::bind_mount(&self.base_dir.join("run"), "/run", rec, &mut mounts)?;

        // A build inside a container that masks parts of `/proc`: the
        // kernel refuses a fresh procfs over a masked one, so the outer
        // `/proc` is bound in, and each mount may keep the flags of its
        // source where the kernel refuses to change them.
        let mount_fallback = std::env::var("MINIMAL_INTERNAL_CS_BUILD").as_deref() == Ok("1");

        if self.needs_bin_symlink()? {
            symlinks.push(("/usr/bin".to_string(), "/bin".to_string()));
        }
        if self.needs_lib64_symlink()? {
            symlinks.push(("/usr/lib".to_string(), "/lib64".to_string()));
        }
        if self.needs_lib_symlink()? {
            symlinks.push(("/usr/lib".to_string(), "/lib".to_string()));
        }

        // Mount in the working directory
        match &self.config.wd {
            WdSetup::Isolated { .. } => {
                Self::bind_mount(&self.base_dir.join("build"), "/build", rec, &mut mounts)?;
            }
            WdSetup::BoundDir {
                path, read_only, ..
            } => {
                let sandbox_cwd = self.config.wd.bound_dir_sandbox_cwd();
                let sandbox_cwd = sandbox_cwd.to_str().ok_or_else(|| {
                    Error::IO(
                        "bound-dir cwd is not valid UTF-8",
                        sandbox_cwd.to_path_buf(),
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 path"),
                    )
                })?;
                let container_path = format!("/{sandbox_cwd}");
                let opts = BindOpts {
                    recursive: true,
                    read_only: *read_only,
                };
                Self::bind_mount(path, &container_path, opts, &mut mounts)?;
            }
            WdSetup::Session {
                home,
                working,
                working_name_override,
                ..
            } => {
                // mount the given home path to /{SESSION_HOME}
                Self::bind_mount(
                    home,
                    &format!("/{SESSION_HOME}"),
                    BindOpts {
                        recursive: true,
                        read_only: false,
                    },
                    &mut mounts,
                )?;
                // mount the given working directory to /{SESSION_DEFAULT_WD} (unless overridden)
                Self::bind_mount(
                    working,
                    &format!(
                        "/{}",
                        working_name_override
                            .as_ref()
                            .cloned()
                            .unwrap_or_else(|| SESSION_DEFAULT_WD.to_string())
                    ),
                    BindOpts {
                        recursive: true,
                        read_only: false,
                    },
                    &mut mounts,
                )?;
            }
        }
        // Mount in any file mappings. hakoniwa applies mounts sorted by
        // target, so a mapping inside a session's `/home` or `/workbench`
        // lands on top of that directory's own mount.
        for m in self.config.wd.fs_mappings() {
            let opts = BindOpts {
                recursive: !m.is_file,
                read_only: m.read_only,
            };
            Self::bind_mount(
                Path::new(&m.host_path),
                &m.path_in_sandbox(),
                opts,
                &mut mounts,
            )?;
        }

        if let Some(hn) = &self.config.hostname {
            let etc_hostname = self.rootfs().join("etc").join("hostname");
            if !std::fs::exists(&etc_hostname)
                .map_err(|e| Error::IO("checking for /etc/hostname", etc_hostname.clone(), e))?
            {
                std::fs::write(&etc_hostname, format!("{}\n", hn))
                    .map_err(|e| Error::IO("writing /etc/hostname", etc_hostname.clone(), e))?;
            }
        }

        // The resolver the plan names, written to the rootfs before spawn like
        // `/etc/hostname` above: hakoniwa binds `/etc` read-only from
        // `<rootfs>/etc`, so an in-sandbox write would hit a read-only fs.
        write_resolv_conf(&self.rootfs(), plan.resolver())?;
        // The plan's static hosts entries, written the same way — a name the
        // box's resolver does not know still answers from `/etc/hosts`.
        write_hosts(&self.rootfs(), plan.hosts(), ipv6_disabled())?;

        Ok(Container {
            launch: spawner::Launch {
                container: spawner::ContainerSpec {
                    rootfs: self.rootfs(),
                    uid: config::BOX_UID,
                    gid: config::BOX_GID,
                    mounts,
                    symlinks,
                    hostname: self.config.hostname.clone(),
                    netns: isolate,
                    tap,
                    mount_fallback,
                },
                gate: None,
                session: spawner::Session::Inherit,
                // hakoniwa brings `lo` up only where it builds a tap.
                lo_up: isolate && plan.tap().is_none(),
                cgroup: self.config.box_cgroup.clone(),
            },
        })
    }

    /// A command that runs `program` in a new instance of `container`, with
    /// this sandbox's working directory and environment and `env_vars` on
    /// top. The process's spawner starts it ([`Spawner::current`]).
    #[cfg(target_os = "linux")]
    pub fn command<I, ArgS, IE, EnvK, EnvV>(
        &mut self,
        container: &Container,
        program: &str,
        args: I,
        env_vars: IE,
    ) -> Result<Command, Error>
    where
        I: IntoIterator<Item = ArgS>,
        ArgS: AsRef<str>,
        IE: IntoIterator<Item = (EnvK, EnvV)>,
        EnvK: AsRef<str>,
        EnvV: AsRef<str>,
    {
        let rootfs = self.rootfs();
        let mut program = program.to_string();

        // Add /usr/bin/ for commands that are not absolute, and don't shadow anything in cwd
        if !program.starts_with("/") {
            let cwd = match &self.config.wd {
                WdSetup::Isolated { .. } => self.base_dir.join("build"),
                WdSetup::BoundDir { path, .. } => path.clone(),
                WdSetup::Session { working, .. } => working.clone(),
            };
            let in_cwd = cwd.join(&program);
            let in_usr_bin = rootfs.join("usr/bin").join(&program);
            if !fs::exists(&in_cwd)
                .map_err(|e| Error::IO("checking program in cwd", in_cwd.clone(), e))?
                && fs::exists(&in_usr_bin)
                    .map_err(|e| Error::IO("checking program in usr/bin", in_usr_bin.clone(), e))?
            {
                program = format!("/usr/bin/{program}");
            }
        }

        let mut command = Spawner::current().run(container.launch.clone(), &program);
        command.args(args);
        // Both come from the config, so a program that enters the running
        // container later can be given the same ones.
        command.current_dir(self.config.command_cwd()?);
        command.envs(self.config.command_env());
        command.envs(env_vars);
        Ok(command)
    }

    /// Runs the invocations in the sandbox to completion.
    #[cfg(target_os = "linux")]
    pub async fn run<W1, W2>(
        &mut self,
        invocations: Vec<Invocation>,
        stdout_writer: Option<W1>,
        stderr_writer: Option<W2>,
    ) -> Result<(), Error>
    where
        W1: tokio::io::AsyncWrite + Unpin + Send,
        W2: tokio::io::AsyncWrite + Unpin + Send,
    {
        self.run_with_cancel(
            invocations,
            stdout_writer,
            stderr_writer,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
    }

    /// Runs the invocations in the sandbox, killing the container if `cancel`
    /// fires.
    #[cfg(target_os = "linux")]
    pub async fn run_with_cancel<W1, W2>(
        &mut self,
        invocations: Vec<Invocation>,
        mut stdout_writer: Option<W1>,
        mut stderr_writer: Option<W2>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), Error>
    where
        W1: tokio::io::AsyncWrite + Unpin + Send,
        W2: tokio::io::AsyncWrite + Unpin + Send,
    {
        for (i, exec) in invocations.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(Error::Execution(ExecutionError::Cancelled));
            }

            // One launch per invocation: each spawn makes a container of its
            // own, with its own network namespace, so each needs its own plan.
            let planned = self.plan_launch().await?;
            let container = self.new_container(planned.plan())?;

            let mut cmd = self.command(&container, &exec.executable, &exec.args, &exec.envs)?;
            cmd.stderr(Stdio::MakePipe);
            cmd.stdout(Stdio::MakePipe);
            tracing::debug!("Executing: {} {}", &exec.executable, exec.args.join(" "));

            let mut child = cmd
                .spawn()
                .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;

            // Step 3: wire this invocation's netns. Torn down explicitly once
            // the invocation completes (both arms). A failed attach drops
            // the child, which kills it.
            let net_guard = planned.attach_child(&mut child).await?;

            // Take pipes from the child so threads can stream them into the stdout/stderr
            // files, as well as to the caller-provided writers if applicable.
            let child_stdout = child.stdout.take();
            let child_stderr = child.stderr.take();

            // Stdout thread — like stderr, capture a rolling tail of the
            // last ~4 KiB so the caller can include it in InvocationFailed
            // when a build script swallows its stderr (mesa's pip install
            // 2>/dev/null pattern) but emits the real diagnostic to stdout.
            let stdout_file = self.stdout.take();
            let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
            let stdout_thread =
                std::thread::spawn(move || -> Result<(Option<fs::File>, Vec<u8>), Error> {
                    let mut file = stdout_file;
                    let mut tail = Vec::new();
                    if let Some(mut pipe) = child_stdout {
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = pipe.read(&mut buf).map_err(|e| {
                                Error::IO("reading stdout pipe", Default::default(), e)
                            })?;
                            if n == 0 {
                                break;
                            }
                            if let Some(f) = file.as_mut() {
                                f.write_all(&buf[..n]).map_err(|e| {
                                    Error::IO("writing stdout", Default::default(), e)
                                })?;
                            }
                            tail.extend_from_slice(&buf[..n]);
                            if tail.len() > 8192 {
                                let start = tail.len() - 4096;
                                tail = tail[start..].to_vec();
                            }
                            // Ignore send errors: the receiver may have been dropped
                            // if the async writer errored, but we still drain the pipe.
                            let _ = stdout_tx.blocking_send(buf[..n].to_vec());
                        }
                        if let Some(f) = file.as_mut() {
                            f.flush()
                                .map_err(|e| Error::IO("flushing stdout", Default::default(), e))?;
                        }
                    }
                    if tail.len() > 4096 {
                        let start = tail.len() - 4096;
                        tail = tail[start..].to_vec();
                    }
                    Ok((file, tail))
                });

            // Stderr thread
            let stderr_file = self.stderr.take();
            let (stderr_tx, mut stderr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
            let stderr_thread =
                std::thread::spawn(move || -> Result<(Option<fs::File>, Vec<u8>), Error> {
                    let mut file = stderr_file;
                    let mut tail = Vec::new();
                    if let Some(mut pipe) = child_stderr {
                        let mut buf = [0u8; 8192];
                        loop {
                            let n = pipe.read(&mut buf).map_err(|e| {
                                Error::IO("reading stderr pipe", Default::default(), e)
                            })?;
                            if n == 0 {
                                break;
                            }
                            if let Some(f) = file.as_mut() {
                                f.write_all(&buf[..n]).map_err(|e| {
                                    Error::IO("writing stderr", Default::default(), e)
                                })?;
                            }
                            tail.extend_from_slice(&buf[..n]);
                            if tail.len() > 8192 {
                                let start = tail.len() - 4096;
                                tail = tail[start..].to_vec();
                            }
                            let _ = stderr_tx.blocking_send(buf[..n].to_vec());
                        }
                        if let Some(f) = file.as_mut() {
                            f.flush()
                                .map_err(|e| Error::IO("flushing stderr", Default::default(), e))?;
                        }
                    }
                    if tail.len() > 4096 {
                        let start = tail.len() - 4096;
                        tail = tail[start..].to_vec();
                    }
                    Ok((file, tail))
                });

            // Forward chunks from the channels to the optional async writers.
            use tokio::io::AsyncWriteExt;
            let stdout_fwd = async {
                while let Some(chunk) = stdout_rx.recv().await {
                    if let Some(w) = stdout_writer.as_mut() {
                        w.write_all(&chunk).await.map_err(|e| {
                            Error::IO("writing to stdout writer", Default::default(), e)
                        })?;
                    }
                }
                Ok::<(), Error>(())
            };
            let stderr_fwd = async {
                while let Some(chunk) = stderr_rx.recv().await {
                    if let Some(w) = stderr_writer.as_mut() {
                        w.write_all(&chunk).await.map_err(|e| {
                            Error::IO("writing to stderr writer", Default::default(), e)
                        })?;
                    }
                }
                Ok::<(), Error>(())
            };

            // Race the forwarding against cancellation. When cancelled, kill the
            // child process — this closes its pipes, which unblocks the reader
            // threads, which drop the senders, which completes the fwd futures.
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    child.kill();

                    // Recover stdout/stderr files from the reader threads.
                    // The threads will finish promptly now that pipes are closed.
                    if let Ok(Ok((f, _tail))) = stdout_thread.join() {
                        self.stdout = f;
                    }
                    if let Ok(Ok((f, _tail))) = stderr_thread.join() {
                        self.stderr = f;
                    }

                    // Wait for the child to be gone, then tear down its network.
                    child.exited().await;
                    if let Some(net_guard) = net_guard {
                        net_guard.teardown().await;
                    }
                    return Err(Error::Execution(ExecutionError::Cancelled));
                }
                (stdout_fwd_res, stderr_fwd_res) = async { tokio::join!(stdout_fwd, stderr_fwd) } => {
                    // The pipes are drained, so the child is exiting.
                    let status = child.exited().await;
                    // Compute the invocation outcome with a closure so every
                    // failure path (reader-thread error, async writer error, wait
                    // error, non-zero exit) funnels through one point; then tear
                    // the network down unconditionally *before* propagating, so a
                    // switch attachment is never leaked on an error return.
                    let outcome: Result<(), Error> = (|| {
                        let (stdout_file, stdout_tail) = stdout_thread
                            .join()
                            .expect("stdout reader thread panicked")?;
                        let (stderr_file, stderr_tail) = stderr_thread
                            .join()
                            .expect("stderr reader thread panicked")?;

                        self.stdout = stdout_file;
                        self.stderr = stderr_file;

                        // Propagate any async writer errors.
                        stdout_fwd_res?;
                        stderr_fwd_res?;

                        if !status.success() {
                            let stderr_str = String::from_utf8_lossy(&stderr_tail).into_owned();
                            let stdout_str = String::from_utf8_lossy(&stdout_tail).into_owned();
                            return Err(Error::Execution(ExecutionError::InvocationFailed {
                                idx: i,
                                code: status.code,
                                reason: status.reason,
                                stderr: stderr_str,
                                stdout: stdout_str,
                            }));
                        }
                        Ok(())
                    })();

                    // The invocation's process has exited; tear down its network
                    // before propagating any error.
                    if let Some(net_guard) = net_guard {
                        net_guard.teardown().await;
                    }
                    outcome?;
                }
            }
        }
        Ok(())
    }
}

// Output collection
impl Sandbox {
    /// Copies all output files into the given destination directory that match the globset.
    ///
    /// Symlinks are copied if they point to a file within the output, otherwise an error is returned.
    pub fn match_outputs_into<P: AsRef<Path>>(
        &self,
        matcher: globset::GlobSet,
        dest_dir: P,
    ) -> Result<(), Error> {
        use error::OutputError;

        let output_dir = self.base_dir.join("build").join("output");
        let dest_dir = dest_dir.as_ref();

        for entry in walkdir::WalkDir::new(&output_dir) {
            let entry =
                entry.map_err(|e| Error::IO("walking outputs", output_dir.clone(), e.into()))?;
            let path = entry.path();
            let file_type = entry.file_type();

            // Skip directories
            if file_type.is_dir() {
                continue;
            }

            // Get relative path from output_dir for glob matching
            let rel_path = path
                .strip_prefix(&output_dir)
                .expect("path should be under output_dir");

            // Check if this entry matches the glob
            if !matcher.is_match(rel_path) {
                continue;
            }

            // Create destination directory structure
            let dest_path = dest_dir.join(rel_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| Error::IO("creating dest directory", parent.to_path_buf(), e))?;
            }

            if file_type.is_symlink() {
                // Read the symlink target
                let target = fs::read_link(path)
                    .map_err(|e| Error::IO("reading symlink", path.to_path_buf(), e))?;

                let resolved_target = path.parent().unwrap().join(&target);
                let is_internal = if let Ok(canonical_target) = resolved_target.canonicalize() {
                    canonical_target.starts_with(&output_dir)
                } else {
                    false
                };
                if !is_internal {
                    return Err(Error::Output(OutputError::ExternalSymlink {
                        symlink: path.to_path_buf(),
                        target,
                    }));
                }

                // Recreate the symlink with the same target
                std::os::unix::fs::symlink(&target, &dest_path)
                    .map_err(|e| Error::IO("creating symlink", dest_path.clone(), e))?;
            } else if file_type.is_file() {
                // Copy the file
                fs::copy(path, &dest_path)
                    .map_err(|e| Error::IO("copying file", dest_path.clone(), e))?;
            }
        }

        Ok(())
    }
}

fn copy_input_file(src: &Path, dest: &Path) -> std::io::Result<bool> {
    let mut out = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut input = fs::File::open(src)?;
    std::io::copy(&mut input, &mut out)?;
    out.set_permissions(input.metadata()?.permissions())?;
    Ok(true)
}

fn hardlink_dir_contents(src_dir: &Path, dst_parent_dir: &Path) -> Result<(), Error> {
    common::hardlink_dir_contents(src_dir, dst_parent_dir).map_err(Error::HardlinkFailed)
}

fn hardlink_dir_contents_counted(
    src_dir: &Path,
    dst_parent_dir: &Path,
    counts: &mut common::LinkCollisions,
) -> Result<(), Error> {
    common::hardlink_dir_contents_counted(src_dir, dst_parent_dir, counts)
        .map_err(Error::HardlinkFailed)
}

/// One line for the paths that more than one rootfs layer shipped. It is
/// INFO only when some of them differ (each of those also has its own
/// WARN); an overlap where every path matches is the usual case, at debug.
fn log_rootfs_collisions(c: &common::LinkCollisions) {
    if c.differ > 0 {
        tracing::info!(
            same = c.same,
            unchecked = c.unchecked,
            differ = c.differ,
            "rootfs: paths shipped by more than one layer; the first-linked file stays"
        );
    } else if c.total() > 0 {
        tracing::debug!(
            same = c.same,
            unchecked = c.unchecked,
            differ = c.differ,
            "rootfs: paths shipped by more than one layer; the first-linked file stays"
        );
    }
}

/// Logs a working input that was not placed at `dest` because something is
/// already there, by the rootfs rule: debug when the two match or are too
/// large to compare, a WARN when they differ. `verb` is "linking" or
/// "copying".
fn log_input_collision(verb: &str, src: &Path, dest: &Path) {
    match common::link_collision(src, dest) {
        common::LinkCollision::Differs(why) => tracing::warn!(
            "Not {verb} {} => {}, already exists ({why}; the first one stays)",
            src.display(),
            dest.display()
        ),
        same_or_unchecked => tracing::debug!(
            "Not {verb} {} => {}, already exists ({})",
            src.display(),
            dest.display(),
            same_or_unchecked.note()
        ),
    }
}

/// Returns the kernel-locked mount flags for the mount containing `path`.
///
/// In a user namespace, remounting a bind mount requires preserving all
/// flags that the kernel has locked (CL_UNPRIVILEGED). If the remount
/// omits a locked flag the kernel returns EPERM. By proactively reading
/// these flags and including them in the mount options we hand to
/// hakoniwa, the remount succeeds even in nested sandboxes—without
/// resorting to MountFallback (which can silently drop requested
/// restrictions like RDONLY).
#[cfg(target_os = "linux")]
fn locked_mount_flags(path: &Path) -> hakoniwa::MountOptions {
    use nix::sys::statfs::statfs;
    use nix::sys::statvfs::FsFlags;

    let stat = match statfs(path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "statfs({}) failed: {e}, not adding locked mount flags",
                path.to_string_lossy()
            );
            return hakoniwa::MountOptions::empty();
        }
    };

    let flags = stat.flags();
    let mut opts = hakoniwa::MountOptions::empty();
    if flags.contains(FsFlags::ST_RDONLY) {
        opts |= hakoniwa::MountOptions::RDONLY;
    }
    if flags.contains(FsFlags::ST_NOSUID) {
        opts |= hakoniwa::MountOptions::NOSUID;
    }
    if flags.contains(FsFlags::ST_NODEV) {
        opts |= hakoniwa::MountOptions::NODEV;
    }
    if flags.contains(FsFlags::ST_NOEXEC) {
        opts |= hakoniwa::MountOptions::NOEXEC;
    }
    opts
}

/// Best-effort probe for whether this host can create network namespaces.
///
/// Reads `/proc/sys/user/max_net_namespaces`: a missing file or a zero limit
/// means network namespaces are unavailable, so [`new_container`](Sandbox::new_container)
/// fails closed for [`NetworkMode::NoNet`] and [`NetworkMode::OwnIp`] rather
/// than silently sharing the host network. The quota is a necessary, not
/// sufficient, signal — a positive quota can still be denied at `unshare` time
/// by capability or seccomp policy — but with the fail-closed contract above a
/// false positive surfaces as a spawn error, never as a silent loss of
/// isolation.
#[cfg(target_os = "linux")]
fn network_namespaces_available() -> bool {
    std::fs::read_to_string("/proc/sys/user/max_net_namespaces")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

/// A host-level obstruction to creating the unprivileged user namespace every
/// sandbox needs, as diagnosed by [`user_namespaces_restriction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UsernsRestriction {
    /// User namespaces are unavailable outright: `/proc/sys/user/
    /// max_user_namespaces` is missing (kernel built without
    /// `CONFIG_USER_NS`) or zero (administratively disabled).
    Disabled,
    /// `kernel.apparmor_restrict_unprivileged_userns=1` (stock Ubuntu 24.04+)
    /// and this process is unconfined, so the kernel will deny the unshare.
    /// Loading an AppArmor profile that grants this process `userns` lifts
    /// the restriction for it alone (`packaging/apparmor/minimald`).
    ApparmorUnconfined,
}

impl std::fmt::Display for UsernsRestriction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => {
                write!(
                    f,
                    "user namespaces are unavailable (user.max_user_namespaces is 0 or missing)"
                )
            }
            Self::ApparmorUnconfined => {
                write!(
                    f,
                    "kernel.apparmor_restrict_unprivileged_userns=1 and this process is unconfined"
                )
            }
        }
    }
}

/// The binary a [`UsernsRestriction::remedy`] is written for. The AppArmor
/// profile attaches by binary path, so the step that lifts that restriction
/// differs per binary; the sysctl remedy does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemedyTarget<'a> {
    /// `minimald`. `min finalize-install` loads the profile for the daemon
    /// at the path the installer wrote; a daemon built from source runs
    /// elsewhere, so the remedy also names the loader with `--path` for
    /// `bin`, this daemon's own path. No cheap check tells the two apart
    /// here, so both forms are always printed. A profile attaches at exec,
    /// so the daemon that is running stays unconfined until it is
    /// restarted.
    Daemon { bin: &'a str },
    /// A `mip` binary, which the installer's profile does not cover: the
    /// loader script is run with `--path` for it. `bin` is the binary's
    /// path; `data_dir` is the installer's data prefix, where the loader
    /// lands (`<data_dir>/apparmor/install-apparmor-profile.sh`).
    Mip { bin: &'a str, data_dir: &'a str },
}

impl UsernsRestriction {
    /// The cause in the words a person reads inside a refusal — never the
    /// sysctl key alone, which names the mechanism rather than the fact.
    #[must_use]
    pub fn cause(self) -> &'static str {
        match self {
            Self::Disabled => {
                "user namespaces are switched off (user.max_user_namespaces=0 or no kernel support)"
            }
            Self::ApparmorUnconfined => "Ubuntu restricts unprivileged user namespaces",
        }
    }

    /// The remedy this restriction takes for `target`, one sentence a person
    /// can act on. The AppArmor restriction is lifted by the profile — the
    /// install step for the daemon, the loader with `--path` for `mip` —
    /// never by `sudo sysctl`, which switches the protection off for every
    /// program, is lost at boot, and leaves the install's record unchanged.
    /// Switched-off namespaces no profile can lift: the sysctl set now (the
    /// gate re-reads it on the next create) and made persistent, or a kernel
    /// built with them.
    #[must_use]
    pub fn remedy(self, target: RemedyTarget<'_>) -> String {
        match (self, target) {
            (Self::Disabled, _) => "Set user.max_user_namespaces above 0: sudo sysctl -w \
                                    user.max_user_namespaces=15000 takes effect now, a \
                                    /etc/sysctl.d drop-in keeps it across reboots; or use a \
                                    kernel with CONFIG_USER_NS."
                .to_string(),
            (Self::ApparmorUnconfined, RemedyTarget::Daemon { bin }) => {
                let bin = shell_word(bin);
                format!(
                    "Finish the install to allow it for Minimal only: min finalize-install   (see \
                     what it changes first: min finalize-install --show). The profile takes effect \
                     when the daemon next starts: run min stop, then your command again.\n\
                     A daemon built from source is not covered: attach the profile to this \
                     binary instead, from a checkout: sudo scripts/install-apparmor-profile.sh \
                     --path {bin}, then the same restart."
                )
            }
            (Self::ApparmorUnconfined, RemedyTarget::Mip { bin, data_dir }) => {
                let loader =
                    shell_word(&format!("{data_dir}/apparmor/install-apparmor-profile.sh"));
                let bin = shell_word(bin);
                format!(
                    "Attach the AppArmor profile to mip (one-time, needs root): sudo bash \
                     {loader} --path {bin} (from a checkout: \
                     sudo scripts/install-apparmor-profile.sh --path {bin})."
                )
            }
        }
    }
}

/// A path as one shell word for a remedy the operator pastes, so a space in
/// it does not split the command. A path with a NUL cannot be quoted for a
/// shell at all; it is shown bare.
fn shell_word(path: &str) -> String {
    shlex::try_quote(path).map_or_else(|_| path.to_string(), |q| q.into_owned())
}

/// Probe for whether this host will refuse the unprivileged user namespace
/// every sandbox starts by unsharing — the counterpart of the network probe
/// above, for the namespace that has no fallback.
///
/// Returns the obstruction it finds, or `None` when none is visible. The
/// sandbox child is forked from the calling process with no exec in between,
/// so the caller's own privileges and AppArmor label are exactly what the
/// kernel will check at `unshare`/`uid_map` time — probe from the daemon,
/// not from a helper. Like the network probe this is a necessary-not-
/// sufficient signal (seccomp or LSM policy can still deny at spawn time):
/// a false `None` surfaces later as the spawn error it always was, never as
/// a loss of isolation.
///
/// A `Some` is not advisory: `minimald` gates every session create on it
/// (NET-143), refusing the create with this cause and its remedy, so a false
/// `Some` — a host whose kernel would in fact allow the unshare — refuses
/// every session on that host. Three facts are read, each live from `/proc`
/// on every call, so a remedy applied to a running host takes effect at the
/// next create without a restart; a daemon that must run anyway sets
/// `MINIMALD_USERNS_GATE=off` to skip the gate.
#[cfg(target_os = "linux")]
#[must_use]
pub fn user_namespaces_restriction() -> Option<UsernsRestriction> {
    userns_restriction_from(
        std::fs::read_to_string("/proc/sys/user/max_user_namespaces").ok(),
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok(),
        nix::unistd::geteuid().is_root(),
        apparmor_label().as_deref(),
    )
}

/// This process's AppArmor label, e.g. `unconfined` or `minimald (unconfined)`.
///
/// The `apparmor/` subdir is the modern location; older kernels expose only
/// the shared `attr/current`. Unreadable (AppArmor absent) is `None`.
#[cfg(target_os = "linux")]
fn apparmor_label() -> Option<String> {
    [
        "/proc/self/attr/apparmor/current",
        "/proc/self/attr/current",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
}

/// Decision core of [`user_namespaces_restriction`], on pre-read inputs.
#[cfg(target_os = "linux")]
fn userns_restriction_from(
    max_user_namespaces: Option<String>,
    apparmor_restrict: Option<String>,
    euid_is_root: bool,
    apparmor_label: Option<&str>,
) -> Option<UsernsRestriction> {
    if max_user_namespaces
        .and_then(|s| s.trim().parse::<u64>().ok())
        .is_none_or(|n| n == 0)
    {
        return Some(UsernsRestriction::Disabled);
    }
    // The AppArmor restriction below only binds unprivileged processes; a
    // root daemon (e.g. the in-guest microVM pid-1) is exempt from it.
    if euid_is_root {
        return None;
    }
    let restricted = apparmor_restrict
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|v| v != 0);
    // The label reads `unconfined` or `<profile> (<mode>)`, possibly
    // NUL/newline-terminated. An unreadable label on a kernel that has the
    // restriction sysctl means no profile is attached — which the kernel
    // treats as unconfined, so we do too.
    let unconfined =
        apparmor_label.is_none_or(|l| l.trim_end_matches(['\n', '\0']).trim() == "unconfined");
    (restricted && unconfined).then_some(UsernsRestriction::ApparmorUnconfined)
}

/// A launch between its plan and its attach, owing the plan's release.
///
/// A value rather than a closure, because the session path builds its
/// environment asynchronously between the two steps. Every way out releases
/// the plan exactly once: [`attach`](Self::attach) hands the obligation to the
/// returned [`NetGuard`], [`abandon`](Self::abandon) releases it, and `Drop`
/// releases it — which is what catches a cancelled launch.
pub struct PlannedLaunch {
    network: std::sync::Arc<dyn network::Network>,
    plan: network::NetPlan,
    /// Whether the release is still owed. Cleared by `attach` and `abandon`.
    owed: bool,
}

impl std::fmt::Debug for PlannedLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlannedLaunch")
            .field("plan", &self.plan)
            .field("owed", &self.owed)
            .finish_non_exhaustive()
    }
}

impl PlannedLaunch {
    /// Step 1: ask the provider for its plan, and take on its release. Split
    /// from [`Sandbox::plan_launch`] so the sequence is reachable without a
    /// `Sandbox`.
    ///
    /// # Errors
    ///
    /// Propagates the provider's planning failure; a plan that failed reserved
    /// nothing.
    pub async fn begin(network: std::sync::Arc<dyn network::Network>) -> Result<Self, Error> {
        let plan = network.plan().await.map_err(Error::Network)?;
        Ok(Self {
            network,
            plan,
            owed: true,
        })
    }

    /// What the sandbox needs; the container is built from it.
    #[must_use]
    pub fn plan(&self) -> &network::NetPlan {
        &self.plan
    }

    /// The process exists: wire its namespace. The returned guard owns the
    /// release from here, so no abandon follows.
    ///
    /// # Errors
    ///
    /// Propagates the provider's attach failure; the plan's release stays owed
    /// and the drop of `self` runs it.
    pub async fn attach(mut self, spawned: network::Spawned) -> Result<Box<dyn NetGuard>, Error> {
        let guard = self.network.attach(spawned).await.map_err(Error::Network)?;
        self.owed = false;
        Ok(guard)
    }

    /// [`attach`](Self::attach) for a process that runs while its namespace
    /// is wired, as a short build step does: the process can end before the
    /// wiring does, and its namespace goes with it. Nothing is left to wire
    /// then, and the process's own exit status is the result, so `None`
    /// stands for that outcome. The plan's release has run by then, because
    /// a next step's plan can replace what the release gives back.
    ///
    /// # Errors
    ///
    /// Propagates the provider's attach failure while the process still runs.
    #[cfg(target_os = "linux")]
    pub async fn attach_child(self, child: &mut Child) -> Result<Option<Box<dyn NetGuard>>, Error> {
        let spawned = network::Spawned::from_child(child);
        self.attach_unless_ended(spawned, || child.try_wait().is_some())
            .await
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    async fn attach_unless_ended(
        mut self,
        spawned: network::Spawned,
        ended: impl FnOnce() -> bool,
    ) -> Result<Option<Box<dyn NetGuard>>, Error> {
        match self.network.attach(spawned).await {
            Ok(guard) => {
                self.owed = false;
                Ok(Some(guard))
            }
            Err(error) => {
                let error = Error::Network(error);
                if !ended() {
                    return Err(error);
                }
                tracing::debug!(%error, "the process ended before its network attach did");
                self.abandon().await;
                Ok(None)
            }
        }
    }

    /// Give up before the process exists, releasing the plan.
    pub async fn abandon(mut self) {
        self.owed = false;
        self.network.abandon().await;
    }
}

impl Drop for PlannedLaunch {
    fn drop(&mut self) {
        if !self.owed {
            return;
        }
        let network = std::sync::Arc::clone(&self.network);
        // `Drop` cannot `await`; with no runtime there is nothing to release to.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { network.abandon().await });
        }
    }
}

/// A network namespace on a [`Network`](network::Network), held open with no
/// program in it. A process of this daemon can create sockets in the
/// namespace, so they leave on that network and under its rules. Dropping it
/// ends the namespace and releases the network.
pub struct HeldNetwork {
    pid: u32,
    nameservers: Vec<std::net::Ipv4Addr>,
    #[cfg(target_os = "linux")]
    entrance: Entrance,
    #[cfg(target_os = "linux")]
    _held: std::sync::Mutex<Held>,
}

impl std::fmt::Debug for HeldNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldNetwork")
            .field("pid", &self.pid)
            .field("nameservers", &self.nameservers)
            .finish_non_exhaustive()
    }
}

impl HeldNetwork {
    /// The process whose `/proc/<pid>/ns` holds the namespace.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Creates a socket in the namespace, and in the cgroup the network is
    /// held in.
    ///
    /// # Errors
    ///
    /// Fails if the held process has ended or the socket cannot be created.
    pub fn socket(&self, v6: bool, datagram: bool) -> std::io::Result<std::os::fd::OwnedFd> {
        #[cfg(target_os = "linux")]
        {
            self.entrance.socket(v6, datagram)
        }
        // No network is held anywhere else, so there is no value to call
        // this on.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (v6, datagram);
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }

    /// The name servers the network's plan names, which answer inside the
    /// namespace.
    #[must_use]
    pub fn nameservers(&self) -> &[std::net::Ipv4Addr] {
        &self.nameservers
    }
}

/// What keeps a [`HeldNetwork`] up. The sandbox's process waits at the start
/// gate and never runs a program, so its rootfs holds nothing to run.
#[cfg(target_os = "linux")]
struct Held {
    child: Child,
    guard: Option<Box<dyn NetGuard>>,
    _gate: StartGate,
    _sandbox: Sandbox<()>,
}

#[cfg(target_os = "linux")]
impl Drop for Held {
    fn drop(&mut self) {
        // Killed before the gate goes, so no program ever starts.
        end_held(&mut self.child);
        // `Drop` cannot `await`; with no runtime there is nothing to release to.
        if let (Some(guard), Ok(handle)) =
            (self.guard.take(), tokio::runtime::Handle::try_current())
        {
            handle.spawn(guard.teardown());
        }
    }
}

/// Ends a held process and waits until it is gone.
#[cfg(target_os = "linux")]
fn end_held(child: &mut Child) {
    child.kill();
    child.wait();
}

/// The error for a held process that ended before its network was attached.
#[cfg(target_os = "linux")]
fn held_process_ended(status: &ExitStatus) -> Error {
    Error::Execution(ExecutionError::InvocationFailed {
        idx: 0,
        code: status.code,
        reason: format!(
            "the held network's process ended before its attach: {}",
            status.reason
        ),
        stderr: String::new(),
        stdout: String::new(),
    })
}

/// The sandbox a [`HeldNetwork`] runs in. Its rootfs is the bare `usr/` that
/// [`Sandbox::new`] links `usr/lib64` in.
#[cfg(target_os = "linux")]
async fn held_sandbox(
    base_dir: &Path,
    network: std::sync::Arc<dyn network::Network>,
    cgroup: Option<cgroup::BoxCgroup>,
) -> Result<Sandbox<()>, Error> {
    let rootfs = tempfile::tempdir()
        .map_err(|e| Error::IO("create held rootfs", base_dir.to_path_buf(), e))?;
    let usr = rootfs.path().join("usr");
    fs::create_dir(&usr).map_err(|e| Error::IO("create held rootfs usr", usr, e))?;
    Config::new("held-network")
        .with_add_rootfs(config::SandboxMapped::TempDir(rootfs))
        .with_network(network)
        .with_box_cgroup(cgroup)
        .build(base_dir, ())
        .await
}

/// Starts a sandbox under `base_dir` that holds `network` up with no program
/// in it. The held process, and every socket made in the namespace, is in
/// `cgroup` when one is given.
///
/// # Errors
///
/// Propagates a failure to plan, spawn or attach. Nothing stays held.
#[cfg(target_os = "linux")]
pub async fn hold_network(
    base_dir: &Path,
    network: std::sync::Arc<dyn network::Network>,
    cgroup: Option<cgroup::BoxCgroup>,
) -> Result<HeldNetwork, Error> {
    let mut sandbox = held_sandbox(base_dir, network, cgroup).await?;
    let planned = sandbox.plan_launch().await?;
    let nameservers = match planned.plan().resolver() {
        network::Resolver::Nameservers(nameservers) => nameservers.clone(),
        _ => Vec::new(),
    };
    let mut container = sandbox.new_container(planned.plan())?;
    let gate = sandbox.hold_start(&mut container)?;
    let mut cmd = sandbox.command(&container, "/held-network", [""; 0], [("", ""); 0])?;
    // A held process reads and writes nothing. It must not take the
    // requester's terminal: hakoniwa binds a terminal stdout as the box's
    // console, and a daemon whose stdout is a microVM guest's console has
    // none it can bind there.
    cmd.stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null);
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Execution(ExecutionError::SpawnFailed(e)))?;
    let pid = child.id();
    let spawned = network::Spawned::from_child(&mut child);
    // A held process waits at its start gate, so one that has ended failed
    // its own setup. Its exit status says why, and neither the attach's
    // error nor a later read of its namespace carries that.
    let guard = match planned.attach(spawned).await {
        Ok(guard) => {
            // An attach that touches no namespace succeeds over an ended
            // process too.
            if let Some(status) = child.try_wait() {
                return Err(held_process_ended(&status));
            }
            guard
        }
        Err(e) => {
            let ended = child.try_wait();
            end_held(&mut child);
            return Err(match ended {
                Some(status) => held_process_ended(&status),
                None => e,
            });
        }
    };
    Ok(HeldNetwork {
        pid,
        nameservers,
        entrance: child.entrance(),
        _held: std::sync::Mutex::new(Held {
            child,
            guard: Some(guard),
            _gate: gate,
            _sandbox: sandbox,
        }),
    })
}

/// Sandboxes run only on Linux, so no network is held anywhere else.
///
/// # Errors
///
/// Always.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unused_async)]
pub async fn hold_network(
    base_dir: &Path,
    _network: std::sync::Arc<dyn network::Network>,
    _cgroup: Option<cgroup::BoxCgroup>,
) -> Result<HeldNetwork, Error> {
    Err(Error::IO(
        "holding a network",
        base_dir.to_path_buf(),
        std::io::Error::from(std::io::ErrorKind::Unsupported),
    ))
}

/// The network plan a sandbox's built-in configuration implies. See
/// [`Sandbox::built_in_plan`].
fn plan_from_config(config: &config::Config) -> network::NetPlan {
    // A resolver the plan names wins; `setup_dns_config` fills in the host's
    // only where the plan is silent.
    if config.setup_dns_config && *config.plan.resolver() == network::Resolver::None {
        return config.plan.clone().with_resolver(network::Resolver::Host);
    }
    config.plan.clone()
}

/// Whether to unshare the network namespace, or the error that says we will not
/// hand back host networking instead. Takes what the probe found so 017-011 is
/// provable on any host.
#[cfg(target_os = "linux")]
fn isolation_decision(plan: &network::NetPlan, netns_available: bool) -> Result<bool, Error> {
    if plan.isolates_netns() && !netns_available {
        return Err(Error::Execution(
            ExecutionError::NetworkIsolationUnavailable,
        ));
    }
    Ok(plan.isolates_netns())
}

/// Puts the plan's resolver into `<rootfs>/etc/resolv.conf`. The host's is
/// synthesized only if the rootfs has none; named servers replace whatever is
/// there, unlinking first because the rootfs is a hardlink farm over the
/// package cache.
fn write_resolv_conf(rootfs: &Path, resolver: &network::Resolver) -> Result<(), Error> {
    let etc_resolv = rootfs.join("etc").join("resolv.conf");
    match resolver {
        network::Resolver::None => Ok(()),
        network::Resolver::Host => {
            if fs::exists(&etc_resolv)
                .map_err(|e| Error::IO("checking for /etc/resolv.conf", etc_resolv.clone(), e))?
            {
                return Ok(());
            }
            common::synth_dns_config(rootfs)
                .map_err(|e| Error::IO("synthesizing /etc/resolv.conf", etc_resolv, e))
        }
        network::Resolver::Nameservers(servers) => {
            fs::create_dir_all(rootfs.join("etc"))
                .map_err(|e| Error::IO("creating /etc", rootfs.join("etc"), e))?;
            match fs::remove_file(&etc_resolv) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::IO("replacing /etc/resolv.conf", etc_resolv, e)),
            }
            let body: String = servers
                .iter()
                .map(|s| format!("nameserver {s}\n"))
                .collect();
            fs::write(&etc_resolv, body)
                .map_err(|e| Error::IO("writing /etc/resolv.conf", etc_resolv, e))
        }
    }
}

/// Appends the plan's static entries to `<rootfs>/etc/hosts`, preserving
/// whatever the rootfs ships. The file is replaced rather than appended in
/// place, unlinking first for the same reason [`write_resolv_conf`] does: the
/// rootfs is a hardlink farm over the package cache, and an in-place append
/// would write through the link into the cached package.
///
/// With `strip_ipv6` set (no IPv6 address in the daemon's namespace, see
/// [`ipv6_disabled`]), the shipped IPv6 entries are dropped first, even when
/// the plan carries no entries of its own: a VM guest boots with
/// `ipv6.disable=1`, but its base image's `/etc/hosts` still maps `localhost`
/// to `::1`, and a program that binds what the resolver hands back then fails
/// with `EAFNOSUPPORT`.
///
/// Idempotent: `new_container` runs once per task invocation over the same
/// rootfs, so an entry a previous invocation already wrote is skipped instead
/// of growing the file a line per exec, and a file that needs no change is
/// left alone.
///
/// The rewrite is atomic: the body is written to a temp file in the same
/// directory and renamed over the target, so a concurrent writer or reader
/// never sees a truncated or missing file. Writers within this process are
/// serialized across the whole read-merge-rename, and each call stages under
/// its own temp name, so concurrent calls neither collide on the temp nor
/// drop an entry another call merged in.
fn write_hosts(rootfs: &Path, hosts: &[network::HostEntry], strip_ipv6: bool) -> Result<(), Error> {
    static WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    if hosts.is_empty() && !strip_ipv6 {
        return Ok(());
    }
    // A poisoned lock only means another writer panicked mid-call; the file
    // on disk is still whole (the rename is atomic), so carry on.
    let _guard = WRITE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let etc_hosts = rootfs.join("etc").join("hosts");
    let shipped = match fs::read(&etc_hosts) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::IO("reading /etc/hosts", etc_hosts.clone(), e)),
    };
    let mut body = String::from_utf8_lossy(&shipped).into_owned();
    if strip_ipv6 {
        body = strip_ipv6_hosts_entries(&body);
    }
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    for entry in hosts {
        if hosts_entry_present(&body, entry) {
            continue;
        }
        body.push_str(&format!("{}\t{}\n", entry.address, entry.name));
    }
    if body.as_bytes() == shipped.as_slice() {
        return Ok(());
    }
    fs::create_dir_all(rootfs.join("etc"))
        .map_err(|e| Error::IO("creating /etc", rootfs.join("etc"), e))?;
    let seq = TEMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp = etc_hosts.with_file_name(format!("hosts.tmp{}.{seq}", std::process::id()));
    let written = fs::write(&temp, &body)
        .map_err(|e| Error::IO("writing /etc/hosts temp", temp.clone(), e))
        .and_then(|()| {
            fs::rename(&temp, &etc_hosts)
                .map_err(|e| Error::IO("renaming /etc/hosts into place", etc_hosts, e))
        });
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

/// Whether the daemon's own network namespace has no IPv6 address configured.
/// On Linux this is read from `/proc/net/if_inet6`: the file is absent when the
/// kernel booted with `ipv6.disable=1`, and empty when IPv6 is compiled in but
/// turned off by sysctl (`net.ipv6.conf.all.disable_ipv6=1`). An unreadable
/// `/proc` also counts as disabled on purpose, since stripping only drops the
/// `::1` lines and keeps the IPv4 `localhost` mapping. On other platforms IPv6
/// is always assumed available (the caller is Linux-only in practice).
fn ipv6_disabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        match fs::read("/proc/net/if_inet6") {
            Ok(data) => data.is_empty(),
            Err(_) => true,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Strips the IPv6 entries from a hosts file `body`: a line whose address
/// parses as IPv6 (`::1`, `ff02::1`, a zoned `fe80::1%eth0`) is dropped, and
/// an `ip6-*` alias on an IPv4 line is removed while the line's other names
/// are kept. Comments, blank lines, and every other IPv4 entry survive.
fn strip_ipv6_hosts_entries(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let (data, comment) = match line.find('#') {
            Some(i) => (&line[..i], Some(&line[i..])),
            None => (line, None),
        };
        let mut fields = data.split_whitespace();
        let Some(address) = fields.next() else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let bare = address.split_once('%').map_or(address, |(a, _)| a);
        if bare.parse::<std::net::Ipv6Addr>().is_ok() {
            continue;
        }
        let names: Vec<&str> = fields.collect();
        let kept: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| !name.to_ascii_lowercase().starts_with("ip6-"))
            .collect();
        if kept.len() == names.len() {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if kept.is_empty() {
            continue;
        }
        out.push_str(address);
        out.push('\t');
        out.push_str(&kept.join(" "));
        if let Some(comment) = comment {
            out.push(' ');
            out.push_str(comment);
        }
        out.push('\n');
    }
    out
}

/// Whether `body` already answers `entry` — a line whose whitespace-separated
/// fields carry both the address and the name, in tab- or space-separated
/// form, and whether it was written by this function or shipped by the rootfs.
fn hosts_entry_present(body: &str, entry: &network::HostEntry) -> bool {
    let address = entry.address.to_string();
    body.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.contains(&address.as_str()) && fields.contains(&entry.name.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A copied input is a new file with the source's bytes and mode.
    #[test]
    fn copy_input_file_copies_bytes_and_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.tar.gz");
        fs::write(&src, b"payload").unwrap();
        fs::set_permissions(&src, Permissions::from_mode(0o640)).unwrap();
        let dest = tmp.path().join("dest.tar.gz");
        assert!(copy_input_file(&src, &dest).unwrap());
        assert_eq!(fs::read(&dest).unwrap(), b"payload");
        assert_eq!(
            fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    /// An existing destination is left alone, even one that is a hardlink to
    /// another file: `fs::copy` would truncate it and so rewrite that file.
    #[test]
    fn copy_input_file_never_writes_through_an_existing_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("cached-from-a-dep");
        fs::write(&shared, b"shared bytes").unwrap();
        let dest = tmp.path().join("build-dest");
        fs::hard_link(&shared, &dest).unwrap();
        let src = tmp.path().join("other-source");
        fs::write(&src, b"other").unwrap();
        assert!(!copy_input_file(&src, &dest).unwrap());
        assert_eq!(fs::read(&shared).unwrap(), b"shared bytes");
        assert_eq!(fs::read(&dest).unwrap(), b"shared bytes");
    }
    use config::{Config, SandboxMapped};

    /// The daemon's AppArmor remedy names the install step for the
    /// installed daemon and, on its own line, the loader with `--path` for
    /// this daemon's own path, so a source-built daemon is covered too
    /// (NET-143).
    #[test]
    fn daemon_apparmor_remedy_names_finalize_install_and_this_binary() {
        let remedy = UsernsRestriction::ApparmorUnconfined.remedy(RemedyTarget::Daemon {
            bin: "/home/me/src/minimal/target/debug/minimald",
        });
        assert_eq!(
            remedy,
            "Finish the install to allow it for Minimal only: min finalize-install   (see what \
             it changes first: min finalize-install --show). The profile takes effect when the \
             daemon next starts: run min stop, then your command again.\n\
             A daemon built from source is not covered: attach the profile to this binary \
             instead, from a checkout: sudo scripts/install-apparmor-profile.sh --path \
             /home/me/src/minimal/target/debug/minimald, then the same restart."
        );
        let spaced = UsernsRestriction::ApparmorUnconfined.remedy(RemedyTarget::Daemon {
            bin: "/opt/my tools/minimald",
        });
        assert!(
            spaced.contains("--path '/opt/my tools/minimald', then"),
            "a path with a space is one shell word: {spaced}"
        );
    }

    /// The mip AppArmor remedy is a command the operator pastes, so a data
    /// dir or binary path with a space stays one shell word, while a plain
    /// path is shown bare (NET-143).
    #[test]
    fn mip_apparmor_remedy_quotes_paths_with_spaces() {
        let remedy = UsernsRestriction::ApparmorUnconfined.remedy(RemedyTarget::Mip {
            bin: "/opt/my tools/mip",
            data_dir: "/home/me/.local/share/minimal",
        });
        assert!(
            remedy.contains(
                "sudo bash /home/me/.local/share/minimal/apparmor/install-apparmor-profile.sh \
                 --path '/opt/my tools/mip' (from a checkout: \
                 sudo scripts/install-apparmor-profile.sh --path '/opt/my tools/mip')."
            ),
            "paths with spaces are single-quoted, plain ones bare: {remedy}"
        );

        let plain = UsernsRestriction::ApparmorUnconfined.remedy(RemedyTarget::Mip {
            bin: "/usr/local/bin/mip",
            data_dir: "/usr/local/share/minimal",
        });
        assert!(
            plain.contains("--path /usr/local/bin/mip (from a checkout"),
            "a plain path is not quoted: {plain}"
        );

        // The loader's path is built from the data dir, so a space there
        // (a custom XDG_DATA_HOME) is quoted the same way.
        let spaced_dir = UsernsRestriction::ApparmorUnconfined.remedy(RemedyTarget::Mip {
            bin: "/usr/local/bin/mip",
            data_dir: "/home/me/My Data/minimal",
        });
        assert!(
            spaced_dir.contains(
                "sudo bash '/home/me/My Data/minimal/apparmor/install-apparmor-profile.sh' \
                 --path /usr/local/bin/mip (from a checkout"
            ),
            "a data dir with a space is one shell word: {spaced_dir}"
        );
    }

    // /proc is mounted with nosuid,nodev on essentially every Linux distro;
    // if either stops showing up we've broken the FsFlags → MountOptions
    // mapping and a nested sandbox would silently lose those locked flags
    // again. NOEXEC is also common but skipped here since it's not
    // universal.
    #[cfg(target_os = "linux")]
    #[test]
    fn locked_mount_flags_reads_proc_flags() {
        let opts = locked_mount_flags(Path::new("/proc"));
        assert!(opts.contains(hakoniwa::MountOptions::NOSUID));
        assert!(opts.contains(hakoniwa::MountOptions::NODEV));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_mount_flags_empty_on_statfs_failure() {
        let opts = locked_mount_flags(Path::new("/nonexistent-path-for-statfs-test"));
        assert!(opts.is_empty());
    }

    /// A provider that records which operations ran, in order, so the sequence
    /// itself can be asserted rather than its effects.
    #[derive(Debug, Default)]
    struct Recorder {
        events: std::sync::Mutex<Vec<&'static str>>,
        /// When set, `attach` fails — the path that must still leave the plan's
        /// release owed.
        attach_fails: bool,
    }

    impl Recorder {
        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
        fn push(&self, e: &'static str) {
            self.events.lock().unwrap().push(e);
        }
    }

    impl network::Network for Recorder {
        fn plan(&self) -> network::PlanFuture<'_> {
            self.push("plan");
            Box::pin(std::future::ready(Ok(network::NetPlan::isolated())))
        }
        fn attach(&self, spawned: network::Spawned) -> network::AttachFuture<'_> {
            self.push("attach");
            if self.attach_fails {
                return Box::pin(std::future::ready(Err(network::NetworkError::new(
                    std::io::Error::other("attach refused"),
                ))));
            }
            drop(spawned);
            Box::pin(std::future::ready(Ok(network::noop_guard())))
        }
        fn abandon(&self) -> network::AbandonFuture<'_> {
            self.push("abandon");
            Box::pin(std::future::ready(()))
        }
    }

    fn planned_with(rec: &std::sync::Arc<Recorder>) -> PlannedLaunch {
        PlannedLaunch {
            network: rec.clone(),
            plan: network::NetPlan::isolated(),
            owed: true,
        }
    }

    /// 017-001. A full launch records `plan` then `attach`, nothing between.
    /// The order is structural: `new_container` takes a `&NetPlan` and `attach`
    /// takes a [`network::Spawned`], which only a spawned process yields.
    #[tokio::test]
    async fn network_phases_run_in_order() {
        let rec = std::sync::Arc::new(Recorder::default());
        let planned = PlannedLaunch::begin(rec.clone()).await.expect("planning");
        assert_eq!(rec.events(), vec!["plan"]);
        assert!(
            planned.plan().isolates_netns(),
            "the provider's plan is carried forward"
        );

        let guard = planned.attach(network::Spawned::new(4242)).await.unwrap();
        assert_eq!(rec.events(), vec!["plan", "attach"]);
        guard.teardown().await;
    }

    /// 017-002. A launch that gives up between plan and attach releases the
    /// plan exactly once, and a failed attach still leaves the release owed.
    #[tokio::test]
    async fn abandoned_launch_releases_the_plan() {
        let rec = std::sync::Arc::new(Recorder::default());
        rec.push("plan");
        planned_with(&rec).abandon().await;
        // The explicit abandon consumes the launch; its drop must not release again.
        assert_eq!(rec.events(), vec!["plan", "abandon"]);

        let rec = std::sync::Arc::new(Recorder {
            events: std::sync::Mutex::new(vec!["plan"]),
            attach_fails: true,
        });
        assert!(
            planned_with(&rec)
                .attach(network::Spawned::new(1))
                .await
                .is_err()
        );
        tokio::task::yield_now().await;
        assert_eq!(
            rec.events(),
            vec!["plan", "attach", "abandon"],
            "a failed attach must still release the plan"
        );
    }

    /// A process that ended while its namespace was being wired leaves its
    /// own exit status as the result, and the plan's release has run when the
    /// attach returns, so the next step's plan cannot overtake it. A failed
    /// attach of a process that still runs stays a failure.
    #[tokio::test]
    async fn a_process_that_ended_during_attach_is_no_attach_failure() {
        let failing = || {
            std::sync::Arc::new(Recorder {
                events: std::sync::Mutex::new(vec!["plan"]),
                attach_fails: true,
            })
        };
        let rec = failing();
        let attached = planned_with(&rec)
            .attach_unless_ended(network::Spawned::new(1), || true)
            .await;
        assert!(matches!(attached, Ok(None)));
        assert_eq!(rec.events(), vec!["plan", "attach", "abandon"]);

        let rec = failing();
        let attached = planned_with(&rec)
            .attach_unless_ended(network::Spawned::new(1), || false)
            .await;
        assert!(attached.is_err(), "the process still runs");

        let rec = std::sync::Arc::new(Recorder::default());
        let attached = planned_with(&rec)
            .attach_unless_ended(network::Spawned::new(1), || {
                panic!("a good attach never asks")
            })
            .await;
        assert!(matches!(attached, Ok(Some(_))));
    }

    /// 017-002 sub-requirement: the launch future going away is the one exit a
    /// caller cannot handle, so the release rides on `Drop`.
    #[tokio::test]
    async fn cancelled_launch_releases_the_plan() {
        let rec = std::sync::Arc::new(Recorder::default());
        rec.push("plan");
        drop(planned_with(&rec));
        tokio::task::yield_now().await;
        assert_eq!(rec.events(), vec!["plan", "abandon"]);
    }

    /// 017-010. The descriptor reaches the provider once: a second take yields
    /// nothing rather than a second owner of the same fd.
    #[test]
    fn the_tap_descriptor_goes_to_the_provider_once() {
        use std::os::fd::AsRawFd as _;
        // A pipe end stands in for the tap; any real fd proves ownership moved.
        let (read_end, _write_end) = std::io::pipe().expect("pipe");
        let fd = std::os::fd::OwnedFd::from(read_end);
        let raw = fd.as_raw_fd();

        let mut spawned = network::Spawned::new(7).with_tap_fd(fd);
        assert_eq!(spawned.take_tap_fd().expect("first take").as_raw_fd(), raw);
        assert!(
            spawned.take_tap_fd().is_none(),
            "a second take gets nothing"
        );
        assert!(network::Spawned::new(7).take_tap_fd().is_none());
    }

    /// 017-004. Both ways a sandbox process starts — the invocation path
    /// ([`Sandbox::plan_launch`]) and the caller-spawn path `minimald` uses
    /// ([`PlannedLaunch::begin`]) — reach the same provider through one
    /// sequence; with no provider, both plan from the sandbox's own config.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn both_spawn_paths_apply_the_network() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-both-paths")
            .with_network(recorder.clone() as std::sync::Arc<dyn network::Network>);
        let sandbox = Sandbox::new(base, config, ()).unwrap();

        let from_invocation = sandbox.plan_launch().await.expect("plan");
        let from_caller = PlannedLaunch::begin(recorder.clone()).await.expect("plan");
        assert_eq!(
            recorder.events(),
            vec!["plan", "plan"],
            "each path asks once"
        );
        assert_eq!(from_invocation.plan(), from_caller.plan());
        from_invocation.abandon().await;
        from_caller.abandon().await;
        assert_eq!(
            recorder.events(),
            vec!["plan", "plan", "abandon", "abandon"]
        );

        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-both-paths-bare").with_plan(network::NetPlan::isolated());
        let sandbox = Sandbox::new(base, config, ()).unwrap();
        let from_invocation = sandbox.plan_launch().await.expect("plan");
        let from_caller = PlannedLaunch::begin(std::sync::Arc::new(sandbox.built_in_plan()))
            .await
            .expect("plan");
        assert!(from_invocation.plan().isolates_netns());
        assert_eq!(from_invocation.plan(), from_caller.plan());
    }

    fn tap_spec() -> network::TapSpec {
        network::TapSpec {
            address: std::net::Ipv4Addr::new(100, 64, 0, 2),
            netmask: std::net::Ipv4Addr::new(255, 255, 0, 0),
            gateway: std::net::Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1500,
        }
    }

    /// 017-007. A plan with tap parameters isolates, however it was built:
    /// `NetPlan` has no constructor that pairs a tap with a shared namespace.
    #[test]
    fn a_tap_plan_always_isolates() {
        assert!(network::NetPlan::isolated_with_tap(tap_spec()).isolates_netns());
        assert!(
            network::NetPlan::isolated_with_tap(tap_spec())
                .with_resolver(network::Resolver::Host)
                .isolates_netns()
        );
        assert!(network::NetPlan::host().tap().is_none());
    }

    /// 017-006, for the plans the sandbox layer handles by itself: a shared
    /// namespace gets no tap and the host's resolver only when asked; an
    /// isolated one gets no tap and no resolver; a resolver the plan names is
    /// kept. The mode half is `minimald::net::provider`.
    #[test]
    fn the_mode_bounds_the_network_access() {
        let plan_for = |plan, dns| {
            let mut cfg = Config::new("t").with_plan(plan);
            cfg.setup_dns_config = dns;
            plan_from_config(&cfg)
        };

        let host = plan_for(network::NetPlan::host(), true);
        assert!(!host.isolates_netns() && host.tap().is_none());
        assert_eq!(host.resolver(), &network::Resolver::Host);
        assert_eq!(
            plan_for(network::NetPlan::host(), false).resolver(),
            &network::Resolver::None
        );

        let isolated = plan_for(network::NetPlan::isolated(), false);
        assert!(isolated.isolates_netns() && isolated.tap().is_none());
        assert_eq!(isolated.resolver(), &network::Resolver::None);

        let named = network::Resolver::Nameservers(vec![std::net::Ipv4Addr::new(100, 64, 0, 1)]);
        let own_ip = network::NetPlan::isolated_with_tap(tap_spec()).with_resolver(named.clone());
        assert_eq!(plan_for(own_ip, true).resolver(), &named);
    }

    /// The plan's resolver is what reaches `/etc/resolv.conf`.
    #[test]
    fn the_plan_names_the_resolver_the_rootfs_gets() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rootfs = tmp.path();
        let resolv = rootfs.join("etc").join("resolv.conf");
        fs::create_dir_all(rootfs.join("etc")).unwrap();

        write_resolv_conf(rootfs, &network::Resolver::None).unwrap();
        assert!(!resolv.exists(), "None must write nothing");

        write_resolv_conf(rootfs, &network::Resolver::Host).unwrap();
        assert!(resolv.exists(), "Host must synthesize a resolver");

        fs::write(&resolv, "nameserver 192.0.2.1\n").unwrap();
        write_resolv_conf(rootfs, &network::Resolver::Host).unwrap();
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 192.0.2.1\n",
            "Host must not replace a resolver the rootfs already has"
        );

        let switch = std::net::Ipv4Addr::new(100, 64, 0, 1);
        write_resolv_conf(rootfs, &network::Resolver::Nameservers(vec![switch])).unwrap();
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "nameserver 100.64.0.1\n",
            "named servers must replace what is there"
        );
    }

    /// NET-003: a host-address box resolves `host.min.internal` through a
    /// static `/etc/hosts` entry — the plan carries it and the container build
    /// writes it, keeping whatever the rootfs ships and leaving the hardlinked
    /// package cache untouched.
    #[test]
    fn hosts_entry_names_host_min_internal() {
        let plan = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(network::HostNet.plan())
            .expect("HostNet plans do not fail");
        let hosts = plan.hosts();
        assert_eq!(
            hosts.len(),
            1,
            "the native host-address plan carries one entry"
        );
        assert_eq!(hosts[0].name, network::HOST_MIN_INTERNAL);
        assert_eq!(hosts[0].address, std::net::Ipv4Addr::LOCALHOST);

        let tmp = tempfile::TempDir::new().unwrap();
        let rootfs = tmp.path();
        let etc_hosts = rootfs.join("etc").join("hosts");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        // The rootfs's hosts file is hardlinked from the package cache.
        let cache = tmp.path().join("package-etc-hosts");
        fs::write(&cache, "127.0.0.1\tlocalhost\n").unwrap();
        fs::hard_link(&cache, &etc_hosts).unwrap();

        write_hosts(rootfs, hosts, false).unwrap();
        assert_eq!(
            fs::read_to_string(&etc_hosts).unwrap(),
            "127.0.0.1\tlocalhost\n127.0.0.1\thost.min.internal\n",
            "shipped content kept, entry appended"
        );
        // `new_container` runs once per task invocation on the same rootfs, so
        // a second write over an already-present entry must not duplicate it.
        write_hosts(rootfs, hosts, false).unwrap();
        assert_eq!(
            fs::read_to_string(&etc_hosts).unwrap(),
            "127.0.0.1\tlocalhost\n127.0.0.1\thost.min.internal\n",
            "a repeat write does not grow the file a line per invocation"
        );
        assert_eq!(
            fs::read_to_string(&cache).unwrap(),
            "127.0.0.1\tlocalhost\n",
            "the package cache file must be untouched"
        );
    }

    /// A VM guest boots with `ipv6.disable=1`, but its base image's
    /// `/etc/hosts` still ships IPv6 entries. Stripping them keeps resolvers
    /// from handing out `::1` for `localhost`, which makes programs fail with
    /// `EAFNOSUPPORT`. IPv4 entries, comments, and blank lines survive.
    #[test]
    fn strip_ipv6_hosts_entries_drops_only_ipv6() {
        let shipped = "\
127.0.0.1\tlocalhost
::1\tlocalhost ip6-localhost ip6-loopback
ff02::1\tip6-allnodes
ff02::2\tip6-allrouters
# a comment

127.0.1.1\thostname
";
        let stripped = strip_ipv6_hosts_entries(shipped);
        assert_eq!(
            stripped, "127.0.0.1\tlocalhost\n# a comment\n\n127.0.1.1\thostname\n",
            "IPv6 entries removed, IPv4 entries, blank lines and comments kept"
        );
    }

    /// A bare `::1 localhost` line carries no `ip6-*` alias, so only parsing
    /// the address as IPv6 catches it; zoned link-local addresses go too.
    #[test]
    fn strip_ipv6_hosts_entries_drops_bare_v6_addresses() {
        let shipped = "127.0.0.1 localhost\n::1 localhost\nfe80::1%eth0 link\n";
        assert_eq!(
            strip_ipv6_hosts_entries(shipped),
            "127.0.0.1 localhost\n",
            "every IPv6-addressed line is dropped"
        );
    }

    /// An `ip6-*` alias on an IPv4 line goes, but the line's other names stay:
    /// dropping the whole line would lose the IPv4 `localhost` mapping.
    #[test]
    fn strip_ipv6_hosts_entries_keeps_ipv4_names_beside_ip6_aliases() {
        let shipped = "127.0.0.1 localhost ip6-localhost # loopback\n127.0.0.2 ip6-only\n";
        assert_eq!(
            strip_ipv6_hosts_entries(shipped),
            "127.0.0.1\tlocalhost # loopback\n",
            "only the ip6-* alias is removed; a line left without names goes"
        );
    }

    /// A plan with no entries of its own still has the shipped IPv6 entries
    /// stripped, and an unchanged file is not rewritten.
    #[test]
    fn write_hosts_strips_ipv6_without_plan_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rootfs = tmp.path();
        let etc_hosts = rootfs.join("etc").join("hosts");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        let cache = tmp.path().join("package-etc-hosts");
        fs::write(&cache, "127.0.0.1\tlocalhost\n::1\tlocalhost\n").unwrap();
        fs::hard_link(&cache, &etc_hosts).unwrap();

        write_hosts(rootfs, &[], false).unwrap();
        assert_eq!(
            fs::read_to_string(&etc_hosts).unwrap(),
            "127.0.0.1\tlocalhost\n::1\tlocalhost\n",
            "with IPv6 available, an empty plan leaves the file alone"
        );

        write_hosts(rootfs, &[], true).unwrap();
        assert_eq!(
            fs::read_to_string(&etc_hosts).unwrap(),
            "127.0.0.1\tlocalhost\n",
            "with no IPv6 stack, the shipped ::1 entry is stripped"
        );
        assert_eq!(
            fs::read_to_string(&cache).unwrap(),
            "127.0.0.1\tlocalhost\n::1\tlocalhost\n",
            "the package cache file must be untouched"
        );

        let empty = tempfile::TempDir::new().unwrap();
        write_hosts(empty.path(), &[], true).unwrap();
        assert!(
            !empty.path().join("etc").join("hosts").exists(),
            "an absent file with nothing to write stays absent"
        );
    }

    /// Concurrent `write_hosts` calls over one rootfs keep the shipped lines
    /// and every call's entry, and none fails on a shared temp file.
    #[test]
    fn write_hosts_concurrent_writers_lose_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rootfs = tmp.path().to_path_buf();
        let etc_hosts = rootfs.join("etc").join("hosts");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(&etc_hosts, "127.0.0.1\tlocalhost\n").unwrap();

        let writers: Vec<_> = (0..16u8)
            .map(|i| {
                let rootfs = rootfs.clone();
                std::thread::spawn(move || {
                    let entry = network::HostEntry {
                        name: format!("box{i}.min.internal"),
                        address: std::net::Ipv4Addr::new(10, 0, 0, i),
                    };
                    write_hosts(&rootfs, &[entry], false)
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap().expect("no writer fails");
        }

        let body = fs::read_to_string(&etc_hosts).unwrap();
        assert!(body.starts_with("127.0.0.1\tlocalhost\n"), "{body}");
        for i in 0..16u8 {
            assert!(
                body.contains(&format!("10.0.0.{i}\tbox{i}.min.internal\n")),
                "entry {i} missing: {body}"
            );
        }
        let leftovers: Vec<_> = fs::read_dir(rootfs.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "hosts")
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    /// 017-011. A host that cannot make the namespace the plan needs fails the
    /// launch rather than handing back the host's network.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_namespace_support_fails_closed() {
        let err = isolation_decision(&network::NetPlan::isolated(), false)
            .expect_err("an isolating plan on a host without namespaces must fail");
        assert!(
            matches!(
                err,
                Error::Execution(ExecutionError::NetworkIsolationUnavailable)
            ),
            "expected NetworkIsolationUnavailable, got {err:?}"
        );
        assert!(
            isolation_decision(&network::NetPlan::isolated_with_tap(tap_spec()), false,).is_err()
        );
        assert!(!isolation_decision(&network::NetPlan::host(), false).unwrap());
    }

    /// The Ubuntu 24.04+ default: restriction sysctl on, daemon unconfined —
    /// the one case the AppArmor profile exists to fix.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_and_unconfined_is_diagnosed() {
        let got = userns_restriction_from(
            Some("15000\n".into()),
            Some("1\n".into()),
            false,
            Some("unconfined\n"),
        );
        assert_eq!(got, Some(UsernsRestriction::ApparmorUnconfined));
    }

    /// With the minimald profile attached the label is no longer bare
    /// `unconfined`, so the restriction does not bind — no warning.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_but_confined_is_clear() {
        let got = userns_restriction_from(
            Some("15000\n".into()),
            Some("1\n".into()),
            false,
            Some("minimald (unconfined)\n"),
        );
        assert_eq!(got, None);
    }

    /// Root is exempt from the AppArmor restriction (the in-guest microVM
    /// daemon runs as root and must stay silent).
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_but_root_is_clear() {
        let got = userns_restriction_from(
            Some("15000\n".into()),
            Some("1\n".into()),
            true,
            Some("unconfined\n"),
        );
        assert_eq!(got, None);
    }

    /// Most distros: the restriction sysctl reads 0 (or does not exist on
    /// non-AppArmor kernels) — unconfined is fine.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_unrestricted_is_clear() {
        for sysctl in [Some("0\n".to_string()), None] {
            let got = userns_restriction_from(
                Some("15000\n".into()),
                sysctl,
                false,
                Some("unconfined\n"),
            );
            assert_eq!(got, None);
        }
    }

    /// A zero or missing user-namespace quota means no sandbox can start at
    /// all, root or not, regardless of AppArmor.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_zero_or_missing_quota_is_disabled() {
        for quota in [Some("0\n".to_string()), None] {
            let got = userns_restriction_from(quota, Some("0\n".into()), true, None);
            assert_eq!(got, Some(UsernsRestriction::Disabled));
        }
    }

    /// An unreadable label on a kernel that enforces the restriction means no
    /// profile is attached: the kernel treats that as unconfined, so the probe
    /// must as well.
    #[cfg(target_os = "linux")]
    #[test]
    fn userns_restricted_with_unreadable_label_is_diagnosed() {
        let got = userns_restriction_from(Some("15000\n".into()), Some("1\n".into()), false, None);
        assert_eq!(got, Some(UsernsRestriction::ApparmorUnconfined));
    }

    /// Creates a tempdir with the `synth/usr/` structure required by
    /// `Sandbox::new`. The `synth/` dir is hardlinked into the rootfs;
    /// `usr/` must be present so the subsequent `usr/lib64 → lib` symlink
    /// step can succeed.
    fn make_base_with_synth() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        fs::create_dir_all(base.join("synth").join("usr")).unwrap();
        (tmp, base)
    }

    /// `Sandbox::new` must reject a `SandboxMapped::File` entry in `config.rootfs`
    /// with `Error::MappedFile`. Files cannot be hardlinked at the rootfs level —
    /// only directories are valid rootfs entries.
    #[test]
    fn sandbox_new_rejects_mapped_file_in_rootfs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().to_path_buf();
        // A file path that need not exist — the error is returned before it is accessed.
        let phantom = base.join("phantom.txt");
        let config = Config::new("test-reject-file").with_add_rootfs(SandboxMapped::File(phantom));
        let result = Sandbox::new(base, config, ());
        assert!(
            matches!(result, Err(Error::MappedFile(_))),
            "expected MappedFile error, got {result:?}"
        );
    }

    /// A build that fails after its directory was created leaves nothing
    /// behind: `Sandbox::new` rejecting a file in the rootfs comes after
    /// `Config::build` made the directory and its synth config.
    #[tokio::test]
    async fn a_failed_build_removes_its_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path().join("sandboxes");
        std::fs::create_dir(&base).unwrap();
        let result = Config::new("test-cleanup")
            .with_add_rootfs(SandboxMapped::File(tmp.path().join("phantom.txt")))
            .build(&base, ())
            .await;
        assert!(matches!(result, Err(Error::MappedFile(_))), "{result:?}");
        let left: Vec<_> = std::fs::read_dir(&base).unwrap().collect();
        assert!(left.is_empty(), "left behind: {left:?}");
    }

    /// When no explicit `state_dir` is configured, `Sandbox::new` derives it
    /// as `base_dir/state`. The caller relies on this to bind-mount `/state`
    /// into the container at the correct host path.
    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_new_derives_state_dir_from_base() {
        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-state-default");
        let sandbox = Sandbox::new(base.clone(), config, ()).unwrap();
        assert_eq!(
            sandbox.state_dir,
            base.join("state"),
            "state_dir should default to base_dir/state"
        );
    }

    /// When an explicit `state_dir` is supplied via `Config::with_state_dir`,
    /// `Sandbox::new` must store that path verbatim so the container bind-mounts
    /// the caller's chosen directory rather than an auto-generated one.
    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_new_honours_explicit_state_dir() {
        let (_tmp, base) = make_base_with_synth();
        let state_tmp = tempfile::TempDir::new().unwrap();
        let state_path = state_tmp.path().to_path_buf();
        let config = Config::new("test-state-explicit").with_state_dir(state_path.clone());
        let sandbox = Sandbox::new(base, config, ()).unwrap();
        assert_eq!(
            sandbox.state_dir, state_path,
            "state_dir should match the path supplied via with_state_dir"
        );
    }

    /// After a successful `Sandbox::new`, the minenv Unix socket must be connectable.
    /// This exercises the channel listener thread: if the thread failed to bind or
    /// is not running, the connect call would fail.
    #[test]
    fn sandbox_new_minenv_socket_is_connectable() {
        use std::os::unix::net::UnixStream;
        let (_tmp, base) = make_base_with_synth();
        let config = Config::new("test-socket");
        let sandbox = Sandbox::new(base, config, ()).unwrap();
        let sock = sandbox.base_dir.join("run").join("minenv_sock");
        UnixStream::connect(&sock).expect("minenv_sock should be connectable after Sandbox::new");
    }

    /// A `BoundDir` (task) sandbox configured with a nested working directory
    /// and a mix of file and directory mappings must construct successfully and
    /// come up fully operational. This drives the `WdSetup::BoundDir` arm of
    /// `Sandbox::new` — shadow-cwd creation and the fs-mapping target loop —
    /// which every other constructor test (all `Isolated`) leaves unexercised.
    /// The asserted contract mirrors the `Isolated` socket test: `new` returns
    /// `Ok` and the minenv socket is connectable, proving the constructor ran to
    /// completion for a bound-dir config rather than panicking or erroring in
    /// the bound-dir branch.
    #[test]
    fn sandbox_new_accepts_bound_dir_with_file_and_dir_mappings() {
        use std::os::unix::net::UnixStream;
        let (_tmp, base) = make_base_with_synth();
        let file_mapping = common::FsMapping {
            host_path: "/host/etc/app.conf".to_string(),
            sandbox_path: Some("/etc/app.conf".to_string()),
            is_file: true,
            ..Default::default()
        };
        let dir_mapping = common::FsMapping {
            host_path: "/host/opt/data".to_string(),
            sandbox_path: Some("/opt/data".to_string()),
            is_file: false,
            ..Default::default()
        };
        let config = Config::new("test-bound-dir").with_wd(
            "/work/project",
            false,
            vec![file_mapping, dir_mapping],
        );
        let sandbox = Sandbox::new(base, config, ())
            .expect("bound-dir sandbox with file and dir mappings should construct");
        let sock = sandbox.base_dir.join("run").join("minenv_sock");
        UnixStream::connect(&sock)
            .expect("minenv_sock should be connectable after a bound-dir Sandbox::new");
    }

    // ---------------------------------------------------------------------
    // Boxes that run a probe: cgroups, namespaces, the start gate.
    // ---------------------------------------------------------------------

    /// The program a test box runs: `/usr/bin/probe` of its rootfs. It
    /// prints its own cgroup as the kernel names it and its pid, then does
    /// what its arguments ask and prints one `key: value` line per result.
    /// The source lists the operations.
    #[cfg(target_os = "linux")]
    const CGROUP_PROBE_C: &str = include_str!("testdata/box_probe.c");

    /// What `statfs` reports for a cgroup2 mount.
    #[cfg(target_os = "linux")]
    const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

    /// The longest path an `AF_UNIX` socket may take: `sockaddr_un::sun_path`
    /// holds 108 bytes including the terminating NUL.
    #[cfg(target_os = "linux")]
    const SUN_PATH_MAX: usize = 107;

    /// Whether a box can be built under `candidate`, for a box named `name`.
    ///
    /// The box's environment socket lives at
    /// `<candidate>/sandbox/<name>-<timestamp>-<attempt>-<pid>/run/minenv_sock`,
    /// and the bind is refused with `EINVAL` when that path does not fit the
    /// 108 bytes `sun_path` holds. Hakoniwa also re-issues its read-only bind
    /// flags with `MS_REMOUNT` inside the user namespace, which may not
    /// *clear* a flag the underlying mount holds — so a `nodev` tmpfs (an
    /// ordinary `/tmp`) refuses with `EPERM`, and a `noexec` filesystem could
    /// not run the probe either.
    #[cfg(target_os = "linux")]
    fn hosts_a_box(candidate: &Path, name: &str) -> Result<(), String> {
        use nix::sys::statfs::statfs;
        use nix::sys::statvfs::FsFlags;

        let probe = tempfile::tempdir_in(candidate)
            .map_err(|e| format!("cannot create a temp dir here: {e}"))?;
        let flags = statfs(probe.path())
            .map_err(|e| format!("statfs failed: {e}"))?
            .flags();
        if flags.contains(FsFlags::ST_NODEV) {
            return Err("the filesystem is mounted nodev".to_string());
        }
        if flags.contains(FsFlags::ST_NOEXEC) {
            return Err("the filesystem is mounted noexec".to_string());
        }
        // The real name shape: `<name>-<timestamp>-<attempt>-<pid>`, with the
        // timestamp and pid at the sizes they actually reach.
        let below = format!("/sandbox/{name}-1790441721-0-1048576/run/minenv_sock");
        let socket_len = probe.path().as_os_str().len() + below.len();
        if socket_len > SUN_PATH_MAX {
            return Err(format!(
                "the box's socket path under it would be {socket_len} bytes, \
                 past the {SUN_PATH_MAX} an AF_UNIX path may be"
            ));
        }
        Ok(())
    }

    /// The first directory on this host that can host a box: the host's tmp
    /// first, then the conventional scratch and runtime directories, then the
    /// cargo target directory's tmp. A host with nowhere is told what every
    /// candidate was refused for.
    #[cfg(target_os = "linux")]
    fn box_base_dir(name: &str) -> PathBuf {
        let candidates = vec![
            std::env::temp_dir(),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/run"),
            PathBuf::from("/state"),
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|dir| PathBuf::from(dir).join("tmp"))
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp")),
        ];
        let mut refusals = Vec::new();
        let chosen = candidates
            .into_iter()
            .find(|candidate| match hosts_a_box(candidate, name) {
                Ok(()) => true,
                Err(reason) => {
                    refusals.push(format!("{}: {}", candidate.display(), reason));
                    false
                }
            })
            .unwrap_or_else(|| {
                panic!(
                    "no directory on this host can host the box this proof needs: {}",
                    refusals.join("; ")
                )
            });
        if refusals.is_empty() {
            eprintln!("box base: {}", chosen.display());
        } else {
            eprintln!(
                "box base: {} (refused: {})",
                chosen.display(),
                refusals.join("; ")
            );
        }
        chosen
    }

    /// Compiles the cgroup probe statically, so it runs in the minimal rootfs
    /// this proof builds for the box. Panics when no C compiler is on `PATH`
    /// rather than skipping: the proof only reaches this on a host whose
    /// user-namespace gate passed, so a missing compiler is a host that
    /// promised to run it and cannot.
    #[cfg(target_os = "linux")]
    fn compile_cgroup_probe(base: &Path) -> PathBuf {
        let src = base.join("cgroup_probe.c");
        let bin = base.join("cgroup_probe");
        std::fs::write(&src, CGROUP_PROBE_C).expect("writing the cgroup probe source");
        let status = std::process::Command::new("gcc")
            .args(["-static", "-o"])
            .arg(&bin)
            .arg(&src)
            .status()
            .expect("spawning gcc to compile the cgroup probe");
        assert!(
            status.success(),
            "gcc failed to compile the cgroup probe: {status:?}"
        );
        bin
    }

    /// A minimal rootfs holding the probe at `/usr/bin/probe`, with the
    /// directories the sandbox layer needs (`usr/lib` for its symlink, `etc`
    /// for hakoniwa's rootfs setup).
    #[cfg(target_os = "linux")]
    fn probe_rootfs(dir: &Path, probe: &Path) {
        std::fs::create_dir_all(dir.join("usr").join("bin"))
            .expect("creating the probe rootfs usr/bin");
        std::fs::copy(probe, dir.join("usr").join("bin").join("probe"))
            .expect("copying the probe into the rootfs");
        std::fs::create_dir_all(dir.join("usr").join("lib"))
            .expect("creating the probe rootfs usr/lib");
        std::fs::create_dir_all(dir.join("etc")).expect("creating the probe rootfs etc");
    }

    /// A probe box a test launched and is holding. The probe's `HOLD:`
    /// argument keeps the box running until the release file appears, so the
    /// test can read the host's side of the box's cgroup while the box is
    /// still in it. The report is read afterwards.
    ///
    /// The release handshake runs through the sandbox's `/run`. It is the
    /// one live directory the host and the box share: the bind is of the
    /// same directory, not a copy. The rootfs is assembled by hardlink, so
    /// a file created in its source
    /// directory after the build never appears inside the box at all.
    #[cfg(target_os = "linux")]
    struct HeldProbe {
        /// The probe's `key: value` report, read to EOF in the background:
        /// the read finishes when the box exits, which the hold delays, and
        /// the probe's stdout is unbuffered, so every line it prints is
        /// already through the pipe while the box is held.
        report: tokio::task::JoinHandle<Result<std::collections::BTreeMap<String, String>, String>>,
        /// Creating this file releases the box's hold: the host-side twin of
        /// the `HOLD:/run/<name>` path the probe polls.
        release: PathBuf,
        /// The box's sandbox base directory, whose `run` is the box's `/run`
        base: PathBuf,
        /// Keeps the box's sandbox — and with it that base directory —
        /// alive: the sandbox's own `Drop` removes the directory, and a held
        /// probe reads the release and report files out of it. Dropped when
        /// the probe's report is read.
        keep_alive: Box<dyn Send>,
    }

    #[cfg(target_os = "linux")]
    impl HeldProbe {
        /// Ends the box's hold: creates the file the box is polling for.
        fn release_hold(&self) {
            std::fs::write(&self.release, b"released\n")
                .unwrap_or_else(|e| panic!("releasing the held box: {e}"));
        }

        /// The probe's report, once the box has run to its end.
        async fn report(self) -> std::collections::BTreeMap<String, String> {
            // The box's sandbox stays alive until the report is in: the
            // report is read from the child's stdout, and the tests read the
            // base directory's other files — the closure's report, the
            // hold's release — while the box is still held, which is this
            // value's whole purpose.
            let keep_alive = self.keep_alive;
            let report = self.report;
            let placed = report
                .await
                .expect("reading the held probe's report")
                .expect("the probe in the box reported");
            drop(keep_alive);
            placed
        }

        /// Releases the box and reads what it printed, in one step — for the
        /// boxes held only to keep their launch alive for the assertions.
        async fn release_and_report(self) -> std::collections::BTreeMap<String, String> {
            self.release_hold();
            self.report().await
        }
    }

    /// Launches a box through the production launch path, named `name`, in
    /// `cgroup` when there is one, running the probe with `probe_args`, and
    /// hands the box back held: the probe holds (`HOLD:/run/<name>` among
    /// its args) until [`HeldProbe::release_hold`] creates that file, and
    /// [`HeldProbe::report`] reads what the probe printed.
    #[cfg(target_os = "linux")]
    async fn launch_box_probe(
        name: &str,
        cgroup: Option<cgroup::BoxCgroup>,
        probe_args: &[String],
    ) -> HeldProbe {
        launch_box_probe_under(name, cgroup, probe_args, None).await
    }

    /// [`launch_box_probe`], with the box launched under `plan` in place of
    /// the sandbox's own built-in plan when one is given.
    #[cfg(target_os = "linux")]
    async fn launch_box_probe_under(
        name: &str,
        cgroup: Option<cgroup::BoxCgroup>,
        probe_args: &[String],
        plan: Option<network::NetPlan>,
    ) -> HeldProbe {
        use std::io::Read as _;

        let base_dir = box_base_dir(name);
        let build = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let probe = compile_cgroup_probe(build.path());
        let source = build.path().join("rootfs-src");
        probe_rootfs(&source, &probe);

        let config = Config::new(name)
            .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
            .with_dns(false)
            .with_box_cgroup(cgroup);
        let sandbox_home = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let mut sandbox = config
            .build(sandbox_home.path().join("sandbox"), ())
            .await
            .expect("building the box");

        let plan = plan.unwrap_or_else(|| sandbox.built_in_plan());
        let container = sandbox
            .new_container(&plan)
            .expect("building the box's container");
        let mut command = sandbox
            .command(
                &container,
                "/usr/bin/probe",
                probe_args.iter().cloned(),
                std::iter::empty::<(&str, &str)>(),
            )
            .expect("building the probe command");
        command.stdout(Stdio::MakePipe);
        let mut child = command.spawn().expect("spawning the probe in the box");

        // The box's own `/run`, host-side: the hold's release file lands
        // here, and so does the report the box's pre-exec closure wrote.
        let run = sandbox.base_dir.join("run");
        let release = probe_args
            .iter()
            .find_map(|arg| arg.strip_prefix("HOLD:/run/"))
            .map_or_else(|| run.join("probe-not-held"), |file| run.join(file));

        let stdout = child.stdout.take().expect("the probe's stdout pipe");
        // The reader runs in the background: its EOF is the box's exit, which
        // the hold delays — this is the handshake's point — and its deadline
        // counts from the spawn. The box's 10s hold is the shorter of the
        // two, so a lost release file is a box that leaves on its own, never
        // a report that times out.
        let report = tokio::task::spawn(async move {
            let report = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || {
                    let mut buf = Vec::new();
                    std::io::BufReader::new(stdout)
                        .read_to_end(&mut buf)
                        .expect("reading the probe's report");
                    buf
                }),
            )
            .await
            .map_err(|_| "the probe in the box did not report in time".to_string())?
            .expect("spawn_blocking join");
            let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.exited())
                .await
                .map_err(|_| "waiting for the probe in the box timed out".to_string())?;
            if !status.success() {
                return Err(format!(
                    "the probe in the box failed: {status:?}\nreport: {}",
                    String::from_utf8_lossy(&report)
                ));
            }
            Ok(String::from_utf8_lossy(&report)
                .lines()
                .filter_map(|line| {
                    line.split_once(": ")
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect())
        });

        HeldProbe {
            report,
            release,
            base: sandbox.base_dir.clone(),
            // The box's sandbox stays alive for as long as the probe holds
            // the box: its own `Drop` removes the base directory, and the
            // two files this harness reads out of it — the closure's report
            // and the hold's release — live in that directory's `/run`.
            keep_alive: Box::new((sandbox, sandbox_home)),
        }
    }

    /// [`launch_box_probe`], released at once: the probe's report.
    #[cfg(target_os = "linux")]
    async fn box_probe_report(
        name: &str,
        cgroup: Option<cgroup::BoxCgroup>,
        probe_args: &[String],
    ) -> std::collections::BTreeMap<String, String> {
        let held = launch_box_probe(name, cgroup, probe_args).await;
        held.release_hold();
        held.report().await
    }

    /// The start gate (#2118): a command whose container holds its start
    /// builds its box and then waits, before it execs its program, until the
    /// gate is released. While the gate is held the box's process is alive
    /// and the program has done nothing; released, the program runs to
    /// completion. Two gates on one sandbox are independent: releasing the
    /// second starts only its own box, and the first waits for its own.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_start_runs_the_program_only_once_released() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "skipping a_held_start_runs_the_program_only_once_released: \
                 this host denies the unprivileged user namespace every \
                 sandbox starts by unsharing: {reason}"
            );
            return;
        }

        let name = "start-gate";
        let base_dir = box_base_dir(name);
        let build = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let probe = compile_cgroup_probe(build.path());
        let source = build.path().join("rootfs-src");
        probe_rootfs(&source, &probe);
        let sandbox_home = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let mut sandbox = Config::new(name)
            .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
            .with_dns(false)
            .build(sandbox_home.path().join("sandbox"), ())
            .await
            .expect("building the box");

        let plan = sandbox.built_in_plan();
        let run = sandbox.base_dir.join("run");
        // Both gates are armed before either box spawns: the order in which a
        // shared FIFO would hand the first box the second gate.
        let mut armed = Vec::new();
        for mark in ["first", "second"] {
            let mut container = sandbox
                .new_container(&plan)
                .expect("building the box's container");
            let gate = sandbox
                .hold_start(&mut container)
                .expect("holding the box's start");
            armed.push((mark, gate, container));
        }
        let mut held = Vec::new();
        for (mark, gate, container) in armed {
            let mut command = sandbox
                .command(
                    &container,
                    "/usr/bin/probe",
                    [format!("MARK:/run/{mark}")],
                    std::iter::empty::<(&str, &str)>(),
                )
                .expect("building the probe command");
            let child = command.spawn().expect("spawning the probe in the box");
            held.push((run.join(mark), gate, child, container));
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        for (mark, _, child, _) in &mut held {
            assert!(
                !mark.exists(),
                "a program ran while its start was held: {}",
                mark.display()
            );
            assert!(
                child.try_wait().is_none(),
                "a held box exited before its start was released"
            );
        }

        // Released in reverse: the second gate starts only the second box.
        let (first_mark, first_gate, first_child, _first_container) = held.remove(0);
        let (second_mark, second_gate, second_child, _second_container) = held.remove(0);
        second_gate.release();
        let status =
            tokio::time::timeout(std::time::Duration::from_secs(30), second_child.exited())
                .await
                .expect("the released box ran to completion in time");
        assert!(status.success(), "the released probe failed: {status:?}");
        assert!(
            second_mark.exists(),
            "the released program never ran: no mark at {}",
            second_mark.display()
        );
        assert!(
            !first_mark.exists(),
            "releasing the second gate started the first box's program"
        );
        assert!(
            first_child.try_wait().is_none(),
            "the first box exited while its own gate was still held"
        );

        first_gate.release();
        let status = tokio::time::timeout(std::time::Duration::from_secs(30), first_child.exited())
            .await
            .expect("the released box ran to completion in time");
        assert!(status.success(), "the released probe failed: {status:?}");
        assert!(
            first_mark.exists(),
            "the released program never ran: no mark at {}",
            first_mark.display()
        );
    }

    /// A spawner whose requester is gone reads the end of its socket and
    /// kills every box it started. The box's handle says why it ended.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spawner_kills_its_boxes_when_its_requester_is_gone() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "skipping a_spawner_kills_its_boxes_when_its_requester_is_gone: this host \
                 denies the unprivileged user namespace every sandbox starts by \
                 unsharing: {reason}"
            );
            return;
        }

        let name = "orphaned";
        let base_dir = box_base_dir(name);
        let build = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let probe = compile_cgroup_probe(build.path());
        let source = build.path().join("rootfs-src");
        probe_rootfs(&source, &probe);
        let mut sandbox = Config::new(name)
            .with_rootfs(std::iter::once(SandboxMapped::Dir(source)))
            .with_dns(false)
            .build(build.path().join("sandbox"), ())
            .await
            .expect("building the box");
        let plan = sandbox.built_in_plan();
        let container = sandbox
            .new_container(&plan)
            .expect("building the box's container");
        let mut command = sandbox
            .command(
                &container,
                "/usr/bin/probe",
                ["HOLD:/run/never"],
                std::iter::empty::<(&str, &str)>(),
            )
            .expect("building the probe command");
        command.stdout(Stdio::Null);
        let child = command.spawn().expect("spawning the probe in the box");
        let supervisor = child.id();
        let alive = |pid: u32| {
            fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let program = loop {
            if let Ok(program) = spawner::enter::init_of(supervisor) {
                break program;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the box never had a program"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };

        Spawner::current().hang_up();
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.exited())
            .await
            .expect("the box's handle learns of the end");
        assert_eq!(status.code, ExitStatus::FAILURE, "{status:?}");
        assert_eq!(status.reason, "the spawner exited");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while alive(supervisor) || alive(program) {
            assert!(
                std::time::Instant::now() < deadline,
                "the box outlived the requester of its spawner"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// A held network builds with no package in its rootfs, holds a namespace
    /// of its own while it lives, and takes its process with it when dropped.
    /// Building needs no user namespace, so that part holds on every host.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_network_holds_its_namespace_until_dropped() {
        let name = "held-network";
        let base_dir = box_base_dir(name);
        let home = tempfile::tempdir_in(&base_dir)
            .unwrap_or_else(|e| panic!("a temp dir under {}: {e}", base_dir.display()));
        let rec = std::sync::Arc::new(Recorder::default());
        held_sandbox(home.path(), rec.clone(), None)
            .await
            .expect("building the held sandbox");

        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "skipping the rest of a_held_network_holds_its_namespace_until_dropped: \
                 this host denies the unprivileged user namespace every \
                 sandbox starts by unsharing: {reason}"
            );
            return;
        }

        let held = hold_network(home.path(), rec.clone(), None)
            .await
            .expect("holding the network");
        let proc_dir = PathBuf::from(format!("/proc/{}", held.pid()));
        assert_ne!(
            fs::read_link(proc_dir.join("ns/net")).expect("reading the held namespace"),
            fs::read_link("/proc/self/ns/net").expect("reading this process's namespace"),
            "the held process shares this process's network namespace"
        );

        drop(held);
        assert!(
            !proc_dir.exists(),
            "the held process outlived its handle: {}",
            proc_dir.display()
        );
    }

    /// The devpts remount, in a real box launched from the production path:
    /// the box's `/dev/pts` carries the per-instance `max=` cap, keeps the
    /// `nosuid,noexec` it was mounted with, and keeps `ptmxmode=0666`, so the
    /// box's own unprivileged user can still open a PTY pair. A remount that
    /// restated only `max=` would reset `ptmxmode` to 0000 and break every
    /// PTY in every box; this is the test that catches it.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn box_devpts_is_capped_and_still_opens_a_pty() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "skipping box_devpts_is_capped_and_still_opens_a_pty: this \
                 host denies the unprivileged user namespace every sandbox \
                 starts by unsharing: {reason}"
            );
            return;
        }
        let probe_args = vec!["MOUNTINFO:/dev/pts".to_string(), "OPENPTY".to_string()];
        let report = box_probe_report("pty-probe", None, &probe_args).await;

        let mount = report
            .get("mountinfo /dev/pts")
            .cloned()
            .unwrap_or_else(|| "no report".to_string());
        eprintln!("the box's /dev/pts: {mount}");
        let (per_mount, superblock) = mount
            .split_once(" - ")
            .unwrap_or_else(|| panic!("the box's /dev/pts is not a mountinfo line: {mount:?}"));
        let mount_flags: Vec<&str> = per_mount
            .split_whitespace()
            .nth(5)
            .unwrap_or_default()
            .split(',')
            .collect();
        for flag in ["nosuid", "noexec"] {
            assert!(
                mount_flags.contains(&flag),
                "the box's /dev/pts keeps {flag} across the remount: {mount:?}"
            );
        }
        let super_opts: Vec<&str> = superblock
            .split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .split(',')
            .collect();
        let max = format!("max={}", config::BOX_PTY_MAX);
        assert!(
            super_opts.contains(&max.as_str()),
            "the box's devpts instance is capped at BOX_PTY_MAX: {mount:?}"
        );
        assert!(
            super_opts.contains(&"ptmxmode=666"),
            "the box's ptmx stays openable by its user: {mount:?}"
        );

        assert_eq!(
            report.get("openpty uid").map(String::as_str),
            Some(config::BOX_UID.to_string().as_str()),
            "the PTY is opened as the box's own unprivileged user"
        );
        assert_eq!(
            report.get("openpty").map(String::as_str),
            Some("errno 0"),
            "the box's user opens a PTY pair after the remount"
        );
    }

    /// Every box has its own IPC namespace, whatever its network plan: a
    /// `host_ip` box, which shares the network namespace, and a `none` box
    /// each sit in a namespace of their own, distinct from each other and
    /// from this process's. Box A creates a System V message queue,
    /// semaphore set and shared memory segment under one key, and a POSIX
    /// message queue under one name, and finds all four again from inside;
    /// box B, launched while A still holds them, finds none of them. Run in
    /// both directions, so neither plan can reach the other's objects.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_box_has_its_own_ipc_namespace() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!(
                "skipping every_box_has_its_own_ipc_namespace: this host \
                 denies the unprivileged user namespace every sandbox starts \
                 by unsharing: {reason}"
            );
            return;
        }

        let own_ipc = std::fs::read_link("/proc/self/ns/ipc")
            .expect("reading this process's IPC namespace")
            .to_string_lossy()
            .into_owned();
        let enoent = format!("errno {}", libc::ENOENT);
        let pairs = [
            (
                "host_ip",
                network::NetPlan::host(),
                "none",
                network::NetPlan::isolated(),
            ),
            (
                "none",
                network::NetPlan::isolated(),
                "host_ip",
                network::NetPlan::host(),
            ),
        ];
        for (round, (a_name, a_plan, b_name, b_plan)) in pairs.into_iter().enumerate() {
            // Unique per run, so a stale object from an earlier run cannot
            // stand in for the one this run creates.
            let key = 0x4d49_0000 + (std::process::id() & 0x0fff) * 4 + round as u32;
            let mq = format!("minimal-ipc-{}-{round}", std::process::id());
            let a_args = vec![
                "NS:ipc".to_string(),
                format!("SYSV:{key}"),
                format!("SYSVGET:{key}"),
                format!("MQ:{mq}"),
                format!("MQOPEN:{mq}"),
                "MARK:/run/ipc-ready".to_string(),
                "HOLD:/run/ipc-release".to_string(),
            ];
            let a =
                launch_box_probe_under(&format!("ipc-a{round}"), None, &a_args, Some(a_plan)).await;
            // Box B starts only once A's objects exist, so B finding none of
            // them is the namespace's doing, never a race with A's creation.
            let ready = a.base.join("run").join("ipc-ready");
            for _ in 0..200 {
                if ready.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let b_args = vec![
                "NS:ipc".to_string(),
                format!("SYSVGET:{key}"),
                format!("MQOPEN:{mq}"),
            ];
            let b = launch_box_probe_under(&format!("ipc-b{round}"), None, &b_args, Some(b_plan))
                .await
                .release_and_report()
                .await;
            let a = a.release_and_report().await;

            let a_ipc = a.get("ns ipc").expect("box A reports its IPC namespace");
            let b_ipc = b.get("ns ipc").expect("box B reports its IPC namespace");
            assert_ne!(
                a_ipc, &own_ipc,
                "the {a_name} box must not share this process's IPC namespace"
            );
            assert_ne!(
                b_ipc, &own_ipc,
                "the {b_name} box must not share this process's IPC namespace"
            );
            assert_ne!(
                a_ipc, b_ipc,
                "the {a_name} and {b_name} boxes must not share an IPC namespace"
            );
            for kind in ["msg", "sem", "shm"] {
                assert_eq!(
                    a.get(&format!("sysv create {kind}")).map(String::as_str),
                    Some("errno 0"),
                    "the {a_name} box creates a System V {kind} object: {a:?}"
                );
                assert_eq!(
                    a.get(&format!("sysv get {kind}")).map(String::as_str),
                    Some("errno 0"),
                    "the {a_name} box finds its own System V {kind} object: {a:?}"
                );
                assert_eq!(
                    b.get(&format!("sysv get {kind}")),
                    Some(&enoent),
                    "the {b_name} box must not find the {a_name} box's System \
                     V {kind} object: {b:?}"
                );
            }
            assert_eq!(
                a.get("mq create").map(String::as_str),
                Some("errno 0"),
                "the {a_name} box creates a POSIX message queue: {a:?}"
            );
            assert_eq!(
                a.get("mq open").map(String::as_str),
                Some("errno 0"),
                "the {a_name} box opens its own POSIX message queue: {a:?}"
            );
            assert_eq!(
                b.get("mq open"),
                Some(&enoent),
                "the {b_name} box must not open the {a_name} box's POSIX \
                 message queue: {b:?}"
            );
        }
    }

    /// The lines of a probe report that start with `prefix`, by what follows.
    #[cfg(target_os = "linux")]
    fn errno_of(report: &std::collections::BTreeMap<String, String>, key: &str) -> i32 {
        report
            .get(key)
            .unwrap_or_else(|| panic!("the probe reported no `{key}`: {report:?}"))
            .strip_prefix("errno ")
            .and_then(|errno| errno.parse().ok())
            .unwrap_or_else(|| panic!("`{key}` is not an errno: {report:?}"))
    }

    /// A box launched with a cgroup: every one of its processes is in that
    /// cgroup on the host, the box sees it as the root of the hierarchy, and
    /// the view it gets is read-only with no room for a cgroup below.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_box_runs_in_its_cgroup_and_sees_it_as_the_root() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!("skipping: this host denies unprivileged user namespaces: {reason}");
            return;
        }
        let Some(root) = cgroup::testing::delegated_root(
            "tests::a_box_runs_in_its_cgroup_and_sees_it_as_the_root",
        ) else {
            return;
        };
        let cgroup = root.create_box("placed").unwrap();
        let args: Vec<String> = [
            "STATFS:/sys/fs/cgroup",
            "READ:/sys/fs/cgroup/cgroup.procs",
            "WRITE:/sys/fs/cgroup/cgroup.procs",
            "MKDIR:/sys/fs/cgroup/sub",
            "HOLD:/run/placed-release",
        ]
        .map(String::from)
        .to_vec();
        let held = launch_box_probe("placed", Some(cgroup.clone()), &args).await;

        // While the box is held: the host's side.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut pids = Vec::new();
        while std::time::Instant::now() < deadline {
            pids = cgroup.procs().unwrap();
            // The supervisor and the program.
            if pids.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            pids.len() >= 2,
            "the box's supervisor and its program are in the box cgroup: {pids:?}"
        );
        for pid in &pids {
            assert_eq!(
                root.box_of_pid(*pid).as_deref(),
                Some("placed"),
                "/proc/{pid}/cgroup names the box cgroup"
            );
        }
        // Nothing of the box is in the supervisor cgroup.
        let supervisor =
            std::fs::read_to_string(root.dir().join(cgroup::SUPERVISOR).join("cgroup.procs"))
                .unwrap();
        for pid in &pids {
            assert!(
                !supervisor
                    .lines()
                    .any(|line| line.trim() == pid.to_string()),
                "pid {pid} of the box is in the supervisor cgroup"
            );
        }

        let report = held.release_and_report().await;
        assert_eq!(report.get("self_cgroup").map(String::as_str), Some("0::/"));
        assert_eq!(
            report.get("pid").map(String::as_str),
            Some("1"),
            "the program is the first process of the box's PID namespace"
        );
        assert_eq!(
            report.get("fstype /sys/fs/cgroup").map(String::as_str),
            Some(format!("magic {CGROUP2_SUPER_MAGIC}").as_str())
        );
        assert_eq!(errno_of(&report, "read /sys/fs/cgroup/cgroup.procs"), 0);
        assert_eq!(
            errno_of(&report, "open /sys/fs/cgroup/cgroup.procs"),
            libc::EROFS
        );
        assert_eq!(errno_of(&report, "mkdir /sys/fs/cgroup/sub"), libc::EROFS);

        cgroup
            .destroy(std::time::Duration::from_secs(10))
            .await
            .unwrap();
    }

    /// A process of one box cannot move itself into another box's cgroup, as
    /// itself or from a user namespace of its own where it is root and mounts
    /// cgroup2 itself. Its cgroup namespace is rooted at its box, so no path
    /// names the sibling, and no cgroup can be made below its own.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_box_process_cannot_move_into_a_sibling_box() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!("skipping: this host denies unprivileged user namespaces: {reason}");
            return;
        }
        let Some(root) =
            cgroup::testing::delegated_root("tests::a_box_process_cannot_move_into_a_sibling_box")
        else {
            return;
        };
        let own = root.create_box("mover").unwrap();
        let sibling = root.create_box("sibling").unwrap();
        // The sibling's cgroup as every path a process could try spells it:
        // beside its own root, and by the host's full path.
        let host_path = sibling.path().join("cgroup.procs");
        let args: Vec<String> = vec![
            "WRITE:/sys/fs/cgroup/sibling/cgroup.procs".to_string(),
            "WRITE:/sys/fs/cgroup/../sibling/cgroup.procs".to_string(),
            format!("WRITE:{}", host_path.display()),
            "NESTED:sibling".to_string(),
            "HOLD:/run/mover-release".to_string(),
        ];
        let held = launch_box_probe("mover", Some(own.clone()), &args).await;
        let report = held.release_and_report().await;

        for spelling in [
            "/sys/fs/cgroup/sibling/cgroup.procs".to_string(),
            "/sys/fs/cgroup/../sibling/cgroup.procs".to_string(),
            host_path.display().to_string(),
        ] {
            assert_eq!(
                errno_of(&report, &format!("open {spelling}")),
                libc::ENOENT,
                "no path in the box names the sibling's cgroup"
            );
        }
        // From a nested user namespace with its own cgroup2 mount.
        assert_eq!(errno_of(&report, "nested unshare"), 0, "{report:?}");
        assert_eq!(errno_of(&report, "nested mount"), 0, "{report:?}");
        assert_eq!(
            report.get("nested self_cgroup").map(String::as_str),
            Some("0::/")
        );
        assert_eq!(
            errno_of(&report, "nested mkdir"),
            libc::EAGAIN,
            "no cgroup can be made below the box's: {report:?}"
        );
        assert_ne!(
            errno_of(&report, "nested raise descendants"),
            0,
            "the box cannot lift the limit on its own subtree: {report:?}"
        );
        assert_eq!(
            report.get("nested sibling reached").map(String::as_str),
            Some("0")
        );
        assert!(
            sibling.procs().unwrap().is_empty(),
            "nothing moved into the sibling box"
        );

        for cgroup in [own, sibling] {
            cgroup
                .destroy(std::time::Duration::from_secs(10))
                .await
                .unwrap();
        }
    }

    /// A box launched with no cgroup still has a cgroup namespace of its own,
    /// and no cgroup mount.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_box_without_a_cgroup_has_its_own_cgroup_namespace_and_no_mount() {
        if let Some(reason) = user_namespaces_restriction() {
            eprintln!("skipping: this host denies unprivileged user namespaces: {reason}");
            return;
        }
        let args = vec!["STATFS:/sys/fs/cgroup".to_string()];
        let report = box_probe_report("unplaced", None, &args).await;
        assert_eq!(report.get("self_cgroup").map(String::as_str), Some("0::/"));
        assert_eq!(
            errno_of(&report, "fstype /sys/fs/cgroup"),
            libc::ENOENT,
            "{report:?}"
        );
    }

    /// The start gate releases on end-of-file only. A byte written into it
    /// does not release it, and its name is gone once the box has opened it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_start_gate_releases_on_end_of_file_and_not_on_bytes() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gate");
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `mkfifo` and `open` with a NUL-terminated path.
        let writer = unsafe {
            assert_eq!(libc::mkfifo(c_path.as_ptr(), 0o600), 0);
            let fd = libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            assert!(fd >= 0);
            std::os::fd::OwnedFd::from_raw_fd(fd)
        };
        let mut done = [0; 2];
        // SAFETY: `pipe` fills the two descriptors.
        assert_eq!(unsafe { libc::pipe(done.as_mut_ptr()) }, 0);
        // SAFETY: the child calls only what the launch closure calls.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: plain syscalls on this child's own descriptors.
            unsafe {
                libc::close(done[0]);
                libc::close(writer.as_raw_fd());
                let Some(gate) = open_start_gate(&path) else {
                    libc::_exit(3);
                };
                libc::write(done[1], b"o".as_ptr().cast(), 1);
                wait_at_start_gate(&gate);
                libc::write(done[1], b"r".as_ptr().cast(), 1);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent owns the pipe's ends and the child's pid.
        unsafe { libc::close(done[1]) };
        let read_byte = |wait_ms: i32| -> Option<u8> {
            let mut poll = libc::pollfd {
                fd: done[0],
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd, then a read of one byte.
            unsafe {
                if libc::poll(&raw mut poll, 1, wait_ms) <= 0 {
                    return None;
                }
                let mut byte = 0u8;
                (libc::read(done[0], (&raw mut byte).cast(), 1) == 1).then_some(byte)
            }
        };
        assert_eq!(read_byte(10_000), Some(b'o'), "the child opened the gate");
        assert!(!path.exists(), "the gate's name is gone once it is open");
        // Bytes do not release it.
        // SAFETY: a write from a buffer that outlives the call.
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), b"release?".as_ptr().cast(), 8) },
            8
        );
        assert_eq!(
            read_byte(300),
            None,
            "bytes in the gate must not release it"
        );
        // End-of-file does.
        drop(writer);
        assert_eq!(
            read_byte(10_000),
            Some(b'r'),
            "the gate releases at end-of-file"
        );
        let mut status = 0;
        // SAFETY: reaps the child this test forked.
        unsafe {
            libc::waitpid(pid, &raw mut status, 0);
            libc::close(done[0]);
        }
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }
}
