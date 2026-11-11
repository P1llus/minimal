use crate::network::{NetPlan, Network};
use crate::{Error, Sandbox};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};

/// The uid every box execs as inside its user namespace.
///
/// `Sandbox::new_container` maps exactly this uid (and [`BOX_GID`]) onto the
/// daemon's own uid and gid, so the process a box execs is not root inside its
/// user namespace and the kernel therefore clears its effective and permitted
/// capability sets at exec. The same uid is the one
/// `common::synth_user_group_config` writes the box's `/etc/passwd` entry for,
/// so the name the box reports and the uid it holds agree. `common` cannot
/// depend on this crate, so no type can hold that agreement;
/// `the_synth_passwd_entry_names_the_box_uid_and_gid` does, reading the entries
/// the function writes and failing when they name another uid.
pub const BOX_UID: u32 = 1000;

/// The gid every box execs as inside its user namespace, mapped onto the
/// daemon's own gid the same way [`BOX_UID`] is mapped onto its uid. The
/// synthesized `group` entry is held to it by the same test.
pub const BOX_GID: u32 = 1000;

/// The most PTYs one box may hold at once. PTYs are one pool for the machine
/// (`kernel.pty.max` minus `kernel.pty.reserve`), so the box's devpts
/// instance carries its own limit and one box cannot take them all. 1024
/// leaves room for a real session. Only the guest VM raises `kernel.pty.max`;
/// on a native host a few boxes at this limit can still exhaust the pool.
pub const BOX_PTY_MAX: u32 = 1024;

/// The mount options of the box's devpts instance: a fresh instance with the
/// usual modes, and the limit on how many PTYs the box may hold.
pub const BOX_DEVPTS_OPTIONS: &str = "newinstance,ptmxmode=0666,mode=620,max=1024";

const _: () = assert!(
    BOX_PTY_MAX == 1024,
    "BOX_DEVPTS_OPTIONS spells the limit out"
);

/// Something in the FS that needs to be mapped into the sandbox.
#[derive(Debug)]
pub enum SandboxMapped {
    File(PathBuf),
    Dir(PathBuf),
    TempDir(tempfile::TempDir),
    /// Special case of [`SandboxMapped::File`] where the path is
    /// copied-in + permissions applied, rather than hardlinked.
    FileCopy(PathBuf),
}

impl PartialEq for SandboxMapped {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(f1), Self::File(f2)) => f1.eq(f2),
            (Self::Dir(d1), Self::Dir(d2)) => d1.eq(d2),
            (Self::TempDir(d1), Self::TempDir(d2)) => d1.path().eq(d2.path()),
            (Self::FileCopy(f1), Self::FileCopy(f2)) => f1.eq(f2),
            _ => false,
        }
    }
}
impl Eq for SandboxMapped {}

// Ordered on (variant tag, path), mirroring the `PartialEq`/`Hash` key above,
// so `BTreeSet<SandboxMapped>` iterates — and the rootfs therefore assembles —
// in the same order in every process. Assembly is first-writer-wins
// hardlinking, so an unordered collection let a per-process hash seed decide
// which entry provided a path that two entries both contain.
impl PartialOrd for SandboxMapped {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SandboxMapped {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn key(m: &SandboxMapped) -> (u8, &Path) {
            match m {
                SandboxMapped::File(p) => (0, p),
                SandboxMapped::Dir(p) => (1, p),
                SandboxMapped::TempDir(t) => (2, t.path()),
                SandboxMapped::FileCopy(p) => (3, p),
            }
        }
        key(self).cmp(&key(other))
    }
}

impl Hash for SandboxMapped {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::File(p) => {
                "f".hash(state);
                p.hash(state);
            }
            Self::Dir(p) => {
                "d".hash(state);
                p.hash(state);
            }
            Self::TempDir(p) => {
                "t".hash(state);
                p.path().hash(state);
            }
            Self::FileCopy(p) => {
                "fc".hash(state);
                p.hash(state);
            }
        }
    }
}

/// The different ways the working directory in the sandbox is to be setup.
#[derive(Debug)]
pub enum WdSetup {
    /// An empty directory `/build` is created, which is setup according to `working_inputs`.
    Isolated {
        /// The set of files that should be mapped into the working directory of the sandbox.
        working_inputs: Vec<SandboxMapped>,
    },
    /// The host filesystem up to the given path is recreated with empty directories, and
    /// the given path is bind-mounted into the sandbox.
    BoundDir {
        path: PathBuf,
        read_only: bool,
        fs_mappings: Vec<common::FsMapping>,
    },
    /// The layout used for a minimal session.
    ///
    /// The homedir is at /home, and the working directory is at /workbench (unless overridden).
    /// `fs_mappings` are bind-mounted on top of those two mounts, so a
    /// read-only mapping inside the home stays read-only.
    Session {
        home: PathBuf,
        working: PathBuf,
        working_name_override: Option<String>,
        fs_mappings: Vec<common::FsMapping>,
    },
}

impl WdSetup {
    /// The file mappings bind-mounted into the sandbox: those of a
    /// [`Self::BoundDir`] or [`Self::Session`] layout, none for
    /// [`Self::Isolated`].
    pub(crate) fn fs_mappings(&self) -> &[common::FsMapping] {
        match self {
            Self::BoundDir { fs_mappings, .. } | Self::Session { fs_mappings, .. } => fs_mappings,
            Self::Isolated { .. } => &[],
        }
    }

    /// Returns the path within the sandbox of the cwd. The returned path
    /// is always relative.
    ///
    /// SAFETY:
    ///  * This function will panic if the variant is not `BoundDir`.
    pub(crate) fn bound_dir_sandbox_cwd(&self) -> &Path {
        let p = match self {
            Self::BoundDir { path, .. } => match std::env::var("MINIMAL_INTERNAL_PATCH_STRIP") {
                Err(_) => path,
                Ok(prefix) => match path.strip_prefix(&prefix) {
                    Err(_) => path,
                    Ok(stripped) => stripped,
                },
            },
            _ => panic!("sandbox_cwd called for non bound-dir variant {:?}", self),
        };
        if p.is_absolute() {
            return p.strip_prefix("/").unwrap();
        }
        p
    }
}

/// Describes the setup of a sandbox.
#[derive(Debug)]
pub struct Config {
    /// A human-readable name for this sandbox, such as the package being built.
    pub name: String,
    /// Whether to delete the sandbox files when dropped.
    pub keep_dirs: bool,

    /// The state directory, if any. An empty one will be created otherwise.
    pub state_dir: Option<PathBuf>,
    /// How the working directory is configured.
    ///
    /// The two main options are:
    ///  * Isolated: cwd is an empty `/build` directory.
    ///  * BoundDir: cwd is a path on the host system. Directories between `/` and the
    ///    given path are created but empty, and the given path is bind-mounted
    ///    into the sandbox.
    pub wd: WdSetup,
    /// The set of files that should be mapped into the root filesystem of the sandbox.
    ///
    /// `BTreeSet`: iteration order is assembly order (entries are hardlinked
    /// first-writer-wins), so it must be deterministic across processes.
    pub rootfs: BTreeSet<SandboxMapped>,

    /// Synthesize the host's resolver into the sandbox, when no provider
    /// decides the network; a provider's plan names its own.
    pub setup_dns_config: bool,
    /// What this sandbox's network looks like when no provider decides it.
    ///
    /// Used only when [`network`](Self::network) is `None`. A caller that has a
    /// network *mode* turns it into a plan; the sandbox layer does not know what
    /// a mode is.
    pub plan: NetPlan,
    /// A custom per-sandbox [`Network`], if injected via
    /// [`with_network`](Self::with_network). When set its plan overrides
    /// [`plan`](Self::plan), and it decides both netns isolation and any
    /// post-spawn wiring (e.g. an own-IP gvproxy switch attach). Keeping the
    /// wiring behind this trait is what lets tasks and sessions share one
    /// networking path instead of it living only in the minimald session host.
    pub network: Option<std::sync::Arc<dyn Network>>,

    /// The hostname to set in the environment, if any.
    pub hostname: Option<String>,
    /// The username to set in the environment, if any. Defaults to `build`.
    pub username: Option<String>,
    /// The home directory to give the sandboxed process — both `$HOME` and
    /// the synthesized passwd entry — under the [`WdSetup::BoundDir`] layout.
    /// The other two layouts own their home outright (`/state/home` for
    /// `Isolated`, `/home` for `Session`) and ignore this.
    ///
    /// `None` falls back to the ambient `$HOME` of the process building the
    /// sandbox, which is the right answer for `mip` on a developer's host and
    /// the wrong one under `minimald`, where the daemon is pid 1 in the guest
    /// with `HOME=/` and has a real session home to offer instead (#1204).
    pub home: Option<PathBuf>,

    /// Globally/initially-set environment variables.
    pub env_vars: HashMap<String, String>,

    /// Suffix marker to identify the process in the names of temp files/directories. Defaults
    /// to the PID when not set.
    pub daemon_id: Option<String>,

    /// The cgroup of the box this sandbox runs in or for. Every process of
    /// the sandbox starts in it, and the box's cgroup namespace is rooted
    /// there. `None` runs the sandbox in the cgroup of the process that
    /// starts it.
    pub box_cgroup: Option<crate::cgroup::BoxCgroup>,
}

/// A command to be run in the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The program to exec.
    ///
    /// If executable is not an absolute path, it will be
    /// mutated to `/usr/bin/{executable}` if:
    ///  * `{executable}` is not a file in the cwd
    ///  * `/usr/bin/{executable}` exists
    pub executable: String,
    /// Argv given to the invoked program.
    pub args: Vec<String>,
    /// Environment variables set on this invocation only. This
    /// takes precedence over any env vars set on [Config].
    pub envs: HashMap<String, String>,
}

impl Config {
    /// The home directory a command in this sandbox sees, as an absolute path
    /// inside the sandbox. One definition, used for both `$HOME` and the
    /// synthesized passwd entry so the two can never disagree.
    ///
    /// `Isolated` and `Session` own their home outright. `BoundDir` mirrors
    /// host paths one-for-one, so its home is a host path too: the
    /// caller-supplied [`Config::home`] when there is one, else the ambient
    /// `$HOME`. `/state/home` is the last resort for a process with no `$HOME`
    /// at all.
    #[must_use]
    pub fn sandbox_home(&self) -> String {
        match &self.wd {
            WdSetup::Isolated { .. } => "/state/home".to_string(),
            WdSetup::Session { .. } => format!("/{}", crate::SESSION_HOME),
            WdSetup::BoundDir { .. } => self
                .home
                .as_deref()
                .and_then(Path::to_str)
                .map(String::from)
                .or_else(|| std::env::var("HOME").ok())
                .unwrap_or_else(|| "/state/home".to_string()),
        }
    }

    /// The working directory a command in this sandbox starts in, as an
    /// absolute path inside the sandbox — `/workbench` for a session (unless
    /// the name is overridden), `/build` for a task.
    ///
    /// Fails only for a [`WdSetup::BoundDir`] sandbox whose host path is not
    /// valid UTF-8: the sandbox-side cwd is that path with the host prefix
    /// stripped, so it cannot be rendered as a string.
    pub fn command_cwd(&self) -> Result<String, Error> {
        match &self.wd {
            WdSetup::BoundDir { .. } => {
                let cwd = self.wd.bound_dir_sandbox_cwd();
                let cwd = cwd.to_str().ok_or_else(|| {
                    Error::IO(
                        "sandbox cwd is not valid UTF-8",
                        cwd.to_path_buf(),
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-UTF-8 path"),
                    )
                })?;
                Ok(format!("/{cwd}"))
            }
            WdSetup::Isolated { .. } => Ok("/build".to_string()),
            WdSetup::Session {
                working_name_override,
                ..
            } => Ok(format!(
                "/{}",
                working_name_override
                    .clone()
                    .unwrap_or_else(|| crate::SESSION_DEFAULT_WD.to_string())
            )),
        }
    }

    /// The environment a command in this sandbox is launched with, before any
    /// per-invocation additions.
    ///
    /// The layout defaults come first and the configured
    /// [`env_vars`](Self::env_vars) last, so a composition's variables win on a
    /// key collision — `PS1`, `LANG` and the login-shell identity are floors,
    /// not policy.
    #[must_use]
    pub fn command_env(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        // The layout default `PATH`; a composed `PATH` expands `$PATH`/`${PATH}`
        // against it.
        let default_path = if let WdSetup::Session { .. } = &self.wd {
            "/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin" // adds /home/.local/bin
        } else {
            "/usr/bin:/bin:/usr/sbin:/sbin"
        };
        let mut set = |k: &str, v: &str| {
            env.insert(k.to_string(), v.to_string());
        };

        // XDG vars
        if let WdSetup::Session { .. } = &self.wd {
            set("XDG_STATE_HOME", "/home/.local/state");
            set("XDG_CONFIG_HOME", "/home/.config");
            set("XDG_DATA_HOME", "/home/.local/share");
            set("PATH", default_path);
            // A styled default shell prompt for interactive sessions. Set as a
            // plain default here (not forced) so a user's composition var can
            // override it: the composed `env_vars` are applied further down and
            // win on key collision.
            set(
                "PS1",
                r"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ",
            );
            // Login-shell identity, mirroring what sshd/pam would set from
            // `/etc/passwd`. `USER`/`LOGNAME` track the configured username;
            // `SHELL` points at the session shell (the `bash` package installs
            // to `/usr/bin/bash`). All plain defaults, so composition vars win.
            if let Some(user) = &self.username {
                set("USER", user);
                set("LOGNAME", user);
            }
            set("SHELL", "/usr/bin/bash");
        } else {
            // Both build and BoundWd layouts
            set("XDG_STATE_HOME", "/state/state");
            set("XDG_CONFIG_HOME", "/state/home");
            set("XDG_DATA_HOME", "/state/data");
            set("PATH", default_path);
        }
        set("XDG_CACHE_HOME", "/state/cache");
        set("XDG_RUNTIME_DIR", "/run");

        set("HOME", &self.sandbox_home());

        if let WdSetup::Isolated { .. } = self.wd {
            set("OUTPUT_DIR", "/build/output");
            set("GIT_TERMINAL_PROMPT", "0");
            set("SOURCE_DATE_EPOCH", "0");
            set("PYTHONHASHSEED", "0");
        }

        // Locale. Sessions get an `en_US.UTF-8` floor: it is the locale the
        // session rootfs actually ships (`locale -a` lists `en_US.utf8`, not
        // `C.UTF-8`), so it never triggers "cannot set locale" warnings the
        // way `C.UTF-8` does. Setting only `LANG` (the lowest-precedence
        // locale knob, no `LC_ALL`) lets a session's composed `env_vars` or a
        // client's forwarded `LANG`/`LC_*` override it. Build/task sandboxes
        // keep the fixed `en_US.utf8` + `LC_ALL` they always had, for output
        // stability. glibc normalizes the `UTF-8` codeset to `utf8`, so both
        // spellings resolve to the same shipped locale.
        if let WdSetup::Session { .. } = &self.wd {
            set("LANG", "en_US.UTF-8");
        } else {
            set("LANG", "en_US.utf8");
            set("LC_ALL", "en_US.utf8");
        }
        set("IS_SANDBOX", "1");
        if let WdSetup::BoundDir { .. } = self.wd {
            //  Quality-of-life wiring for task sandboxes
            for var in ["TERM", "COLORTERM", "LS_COLORS"] {
                if let Ok(value) = std::env::var(var) {
                    set(var, &value);
                }
            }
        }

        // A composed `PATH` may extend the layout default by referring to it
        // as `$PATH` or `${PATH}`; expand that reference so the default
        // directories are not lost. Every other variable stays literal.
        self.env_vars.iter().for_each(|(var, val)| {
            if var == "PATH" {
                set(var, &expand_path_reference(val, default_path));
            } else {
                set(var, val);
            }
        });
        env
    }

    /// Initializes an empty config with the given name.
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            setup_dns_config: true,
            plan: NetPlan::host(),
            network: None,
            env_vars: HashMap::with_capacity(12),
            hostname: None,
            username: None,
            home: None,
            keep_dirs: false,
            rootfs: BTreeSet::new(),
            state_dir: None,
            wd: WdSetup::Isolated {
                working_inputs: Vec::with_capacity(6),
            },
            daemon_id: None,
            box_cgroup: None,
        }
    }

    /// Configures the sandbox to use the given directory for `/state`.
    pub fn with_state_dir<P: Into<PathBuf>>(mut self, state_dir: P) -> Self {
        self.state_dir = Some(state_dir.into());
        self
    }
    /// Configures the sandbox to map the given directory as the working directory.
    pub fn with_wd<P: Into<PathBuf>>(
        mut self,
        wd: P,
        read_only: bool,
        fs_mappings: Vec<common::FsMapping>,
    ) -> Self {
        self.wd = WdSetup::BoundDir {
            path: wd.into(),
            read_only,
            fs_mappings,
        };
        self
    }
    /// Configures the sandbox to isolate itself from the host, configuring only
    /// the given files as contents of the isolated working directory.
    pub fn with_isolated_wd<I: Iterator<Item = SandboxMapped>>(mut self, inputs: I) -> Self {
        match &mut self.wd {
            WdSetup::BoundDir { .. } | WdSetup::Session { .. } => {
                self.wd = WdSetup::Isolated {
                    working_inputs: inputs.into_iter().collect(),
                };
            }
            WdSetup::Isolated { working_inputs } => working_inputs.extend(inputs),
        };
        self
    }
    /// Configures the sandbox following the layout for a session.
    pub fn with_session_dirs(self, home: PathBuf, working: PathBuf) -> Self {
        self.with_session_dirs_mapped(home, working, Vec::new())
    }
    /// Configures the sandbox following the layout for a session, with
    /// `fs_mappings` bind-mounted over the session's home and working
    /// directory. Each mapping's [`path_in_sandbox`] is where it lands, so a
    /// mapping meant to sit inside the home names its `/home/...` path.
    ///
    /// [`path_in_sandbox`]: common::FsMapping::path_in_sandbox
    pub fn with_session_dirs_mapped(
        mut self,
        home: PathBuf,
        working: PathBuf,
        fs_mappings: Vec<common::FsMapping>,
    ) -> Self {
        self.wd = WdSetup::Session {
            home,
            working,
            working_name_override: None,
            fs_mappings,
        };
        self
    }

    /// Configures the hostname to use in the sandbox.
    pub fn with_hostname<S: Into<String>>(mut self, hostname: S) -> Self {
        self.hostname = Some(hostname.into());
        self
    }
    /// Adds to the set of environment variables all invocations will see.
    pub fn with_env_vars<I: Iterator<Item = (String, String)>>(
        mut self,
        extra_env_vars: I,
    ) -> Self {
        self.env_vars.extend(extra_env_vars);
        self
    }
    /// Sets the given environment variable, all invocations will see it unless overridden.
    pub fn with_env_var<S1: Into<String>, S2: Into<String>>(mut self, key: S1, val: S2) -> Self {
        self.env_vars.insert(key.into(), val.into());
        self
    }

    /// Adds the set of [SandboxMapped] objects to the root fs.
    pub fn with_rootfs<I: Iterator<Item = SandboxMapped>>(mut self, rootfs: I) -> Self {
        self.rootfs.extend(rootfs);
        self
    }
    /// Adds the given [SandboxMapped] object to the root fs.
    pub fn with_add_rootfs(mut self, file: SandboxMapped) -> Self {
        self.rootfs.insert(file);
        self
    }
    /// Sets what this sandbox's network looks like when no provider decides it.
    /// Ignored if a custom [`Network`] is set via
    /// [`with_network`](Self::with_network), whose own plan wins.
    #[must_use]
    pub fn with_plan(mut self, plan: NetPlan) -> Self {
        self.plan = plan;
        self
    }
    /// Sets a custom per-sandbox [`Network`], overriding
    /// [`with_plan`](Self::with_plan). Use this for modes that
    /// need post-spawn wiring (e.g. own-IP gvproxy switch attach), supplied by
    /// the consumer so the wiring lives behind one abstraction for every sandbox.
    pub fn with_network(mut self, network: std::sync::Arc<dyn Network>) -> Self {
        self.network = Some(network);
        self
    }
    /// Sets whether the host's resolver is synthesized into the sandbox.
    /// Ignored when a [`Network`] is set: its plan names the resolver.
    pub fn with_dns(mut self, dns: bool) -> Self {
        self.setup_dns_config = dns;
        self
    }
    /// Configures the username to use in the sandbox.
    pub fn with_username<S: Into<String>>(mut self, username: S) -> Self {
        self.username = Some(username.into());
        self
    }
    /// Configures the home directory to give the sandboxed process under the
    /// [`WdSetup::BoundDir`] layout, in place of the ambient `$HOME`. See
    /// [`Config::home`]; `None` restores the ambient fallback.
    pub fn with_home<P: Into<PathBuf>>(mut self, home: Option<P>) -> Self {
        self.home = home.map(Into::into);
        self
    }

    /// Extends the list of environment variables with the set generated from given build args.
    pub fn with_build_args<K: AsRef<str>, V: Into<String>, I: Iterator<Item = (K, V)>>(
        mut self,
        build_args: I,
    ) -> Self {
        self.env_vars.extend(build_args.map(|(k, v)| {
            (
                "MINIMAL_ARG_".to_owned()
                    + &k.as_ref()
                        .trim()
                        .replace("=", "")
                        .replace(":", "")
                        .replace("/", "")
                        .replace("\"", "")
                        .replace("'", "")
                        .to_uppercase(),
                v.into(),
            )
        }));
        self
    }

    /// Sets the identifier for the process/daemon doing the build.
    pub fn with_daemon_id(mut self, id: String) -> Self {
        self.daemon_id = Some(id);
        self
    }

    /// Runs the sandbox in `cgroup`, the cgroup of the box it belongs to,
    /// when the box has one.
    #[must_use]
    pub fn with_box_cgroup(mut self, cgroup: Option<crate::cgroup::BoxCgroup>) -> Self {
        self.box_cgroup = cgroup;
        self
    }

    /// Builds the sandbox using the given configuration, with temporary files and the rootfs
    /// contained within the given directory.
    pub async fn build<P: AsRef<Path>, C: super::Channel>(
        self,
        base_dir: P,
        channel: C,
    ) -> Result<Sandbox<C>, Error> {
        // Make sure the parent directory exists
        fs::create_dir_all(base_dir.as_ref()).map_err(|e| {
            Error::IO(
                "create sandbox base directory",
                base_dir.as_ref().to_path_buf(),
                e,
            )
        })?;

        // Create a unique directory name using sandbox name, timestamp, and daemon ID.
        // At this layer its plausible that there might be two packages of the same name
        // built at the same time, so we do an atomic directory creation dance /w an attempt
        // counter to make sure each sandbox gets its own folder.
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                Error::IO(
                    "get timestamp",
                    Default::default(),
                    std::io::Error::other(e),
                )
            })?
            .as_secs();
        let id = self
            .daemon_id
            .clone()
            .unwrap_or_else(|| std::process::id().to_string());

        // The box's env socket lives at
        // <base_dir>/<name>-<timestamp>-<attempt>-<id>/run/minenv_sock.
        // `sockaddr_un::sun_path` holds 107 usable bytes; a long session
        // or task name can push the path past that and the bind fails with
        // EINVAL. Truncate the name to fit, appending a short hash of the
        // full name so two long names that share a prefix still get
        // distinct directories.
        const SUN_PATH_MAX: usize = 107;
        // The attempt counter runs 0..=20, so reserve its widest spelling.
        let suffix = format!("-{timestamp}-20-{id}/run/minenv_sock");
        let base_len = base_dir.as_ref().as_os_str().len();
        let overhead = 1 + suffix.len(); // '/' separator + suffix
        let name_budget = SUN_PATH_MAX.saturating_sub(base_len + overhead);
        let name = fit_box_name(&self.name, name_budget).ok_or_else(|| {
            Error::IO(
                "create sandbox directory",
                base_dir.as_ref().to_path_buf(),
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "base directory path is {base_len} bytes, leaving no \
                         room for a box name under the {SUN_PATH_MAX}-byte \
                         AF_UNIX path limit"
                    ),
                ),
            )
        })?;

        let build_base_dir = {
            let mut attempt = 0u32;
            loop {
                let dir_name = format!("{}-{}-{}-{}", name, timestamp, attempt, id);

                let candidate_dir = base_dir.as_ref().join(dir_name);
                match fs::create_dir(&candidate_dir) {
                    Ok(()) => break candidate_dir,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        attempt += 1;
                        if attempt > 20 {
                            return Err(Error::IO(
                                "create sandbox directory",
                                candidate_dir,
                                std::io::Error::new(
                                    std::io::ErrorKind::AlreadyExists,
                                    "too many directory creation attempts",
                                ),
                            ));
                        }
                        continue;
                    }
                    Err(e) => {
                        return Err(Error::IO("create sandbox directory", candidate_dir, e));
                    }
                }
            }
        };

        // Until the `Sandbox` exists (its `Drop` removes the directory from
        // then on), a failure below would leave the directory behind.
        let cleanup = RemoveUnlessKept((!self.keep_dirs).then(|| build_base_dir.clone()));

        // Validate FS mappings, creating any non-existent files as we go.
        for m in self.wd.fs_mappings() {
            match fs::metadata(&m.host_path) {
                Ok(stat) => {
                    if stat.is_dir() && m.is_file {
                        return Err(Error::IO(
                            "stat fs mapping",
                            m.host_path.clone().into(),
                            std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "directory mapped as a file",
                            ),
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !m.create_if_missing {
                        return Err(Error::IO("fs mapping", m.host_path.clone().into(), e));
                    }

                    // Missing and needs to be created.
                    if m.is_file {
                        fs::write(
                            &m.host_path,
                            if m.host_path.ends_with(".json") {
                                "{}"
                            } else {
                                ""
                            },
                        )
                        .map_err(|e| {
                            Error::IO("create mapped file", m.host_path.clone().into(), e)
                        })?;
                    } else {
                        fs::create_dir_all(&m.host_path).map_err(|e| {
                            Error::IO("create mapped dir", m.host_path.clone().into(), e)
                        })?;
                    }
                }
                Err(e) => {
                    return Err(Error::IO("stat fs mapping", m.host_path.clone().into(), e));
                }
            };
        }

        // Make synthetic configuration. The resolver is the plan's to say, and
        // is written when the container is built.
        let sd = build_base_dir.join("synth");
        fs::create_dir_all(&sd)
            .map_err(|e| Error::IO("create synth config directory", sd.clone(), e))?;
        let home = self.sandbox_home();
        match &self.username {
            Some(n) => common::synth_user_group_config(&sd, n, &home),
            None => common::synth_user_group_config(&sd, "build", &home),
        }
        .map_err(|e| Error::IO("synthesizing user/group configuration", sd, e))?;

        let sandbox = Sandbox::new(build_base_dir, self, channel)?;
        cleanup.keep();
        Ok(sandbox)
    }
}

/// Removes a sandbox directory on drop unless [`Self::keep`] is called: the
/// cleanup for a directory that never became a [`Sandbox`].
struct RemoveUnlessKept(Option<PathBuf>);

impl RemoveUnlessKept {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for RemoveUnlessKept {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take()
            && let Err(e) = common::remove_dir_all(&dir)
        {
            tracing::warn!(
                "failed to remove sandbox directory {} after a failed build: {e}",
                dir.display()
            );
        }
    }
}

/// Replaces each `${PATH}` and `$PATH` reference in `value` with `default`.
/// A `$PATH` followed by a character that continues a variable name (such as
/// `$PATH_SUFFIX`) is a different variable and stays literal.
fn expand_path_reference(value: &str, default: &str) -> String {
    let expanded = value.replace("${PATH}", default);
    let mut expanded_path = String::with_capacity(expanded.len());
    let mut remaining = expanded.as_str();
    while let Some(index) = remaining.find("$PATH") {
        expanded_path.push_str(&remaining[..index]);
        let after_reference = &remaining[index + "$PATH".len()..];
        let continues_variable = after_reference
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if continues_variable {
            expanded_path.push_str("$PATH");
        } else {
            expanded_path.push_str(default);
        }
        remaining = after_reference;
    }
    expanded_path.push_str(remaining);
    expanded_path
}

/// Fits a box name into `budget` bytes. A name that fits is kept as is; a
/// longer one is cut at a char boundary and suffixed with `-` and the first 8
/// hex digits of the full name's SHA-256, so two long names sharing a prefix
/// still differ and the same name always maps to the same result. `None` when
/// the budget leaves no room for any name.
fn fit_box_name(name: &str, budget: usize) -> Option<String> {
    if budget == 0 {
        return None;
    }
    if name.len() <= budget {
        return Some(name.to_string());
    }
    let hash = hex::encode(Sha256::digest(name.as_bytes()));
    let hash_suffix = &hash[..8];
    // Reserve room for the hash suffix plus a '-' separator.
    let keep = budget
        .checked_sub(1 + hash_suffix.len())
        .filter(|&k| k > 0)?;
    let mut end = keep;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    Some(format!("{}-{}", &name[..end], hash_suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_box_name_within_budget_is_kept() {
        assert_eq!(fit_box_name("short", 5).as_deref(), Some("short"));
    }

    #[test]
    fn a_long_box_name_is_cut_to_the_budget_with_a_hash_suffix() {
        let name = "a".repeat(200);
        let fitted = fit_box_name(&name, 40).unwrap();
        assert_eq!(fitted.len(), 40);
        assert!(fitted.starts_with(&"a".repeat(31)), "{fitted}");
        // Deterministic: the same name always lands on the same directory name.
        assert_eq!(fit_box_name(&name, 40).unwrap(), fitted);
    }

    #[test]
    fn long_box_names_sharing_a_prefix_stay_distinct() {
        let prefix = "a".repeat(100);
        let a = fit_box_name(&format!("{prefix}-alpha"), 40).unwrap();
        let b = fit_box_name(&format!("{prefix}-beta"), 40).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_long_box_name_is_cut_on_a_char_boundary() {
        // 'é' is two bytes; a cut landing mid-char backs off to the boundary.
        let fitted = fit_box_name(&"é".repeat(50), 20).unwrap();
        assert!(fitted.len() <= 20, "{fitted}");
        assert!(fitted.starts_with("éééé"), "{fitted}");
    }

    #[test]
    fn a_budget_with_no_room_refuses_the_name() {
        assert_eq!(fit_box_name("anything", 0), None);
        assert_eq!(fit_box_name(&"a".repeat(20), 9), None);
    }

    fn session_config() -> Config {
        let mut config = Config::new("test");
        config.wd = WdSetup::Session {
            home: PathBuf::from("/tmp/home"),
            working: PathBuf::from("/tmp/working"),
            working_name_override: None,
            fs_mappings: Vec::new(),
        };
        config.username = Some("dev".to_string());
        config
    }

    /// The pair a session's shell is launched with is the pair anything
    /// injected into that session later has to be given, so both come from
    /// here. `/workbench` is the contract the session layout promises.
    #[test]
    fn a_session_starts_in_workbench_with_its_login_identity() {
        let config = session_config();

        assert_eq!(config.command_cwd().unwrap(), "/workbench");
        let env = config.command_env();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home"));
        assert_eq!(env.get("USER").map(String::as_str), Some("dev"));
        assert_eq!(env.get("LANG").map(String::as_str), Some("en_US.UTF-8"));
    }

    /// Composed variables are policy; the layout defaults are only a floor.
    #[test]
    fn configured_vars_override_the_layout_defaults() {
        let mut config = session_config();
        config
            .env_vars
            .insert("LANG".to_string(), "en_GB.UTF-8".to_string());
        config
            .env_vars
            .insert("EDITOR".to_string(), "hx".to_string());

        let env = config.command_env();

        assert_eq!(env.get("LANG").map(String::as_str), Some("en_GB.UTF-8"));
        assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx"));
    }

    /// A composed `PATH` that refers to `$PATH` (or `${PATH}`) extends the
    /// layout default instead of replacing it verbatim; a `PATH` without a
    /// reference, and any other variable, stay literal.
    #[test]
    fn a_composed_path_expands_its_self_reference() {
        let mut config = session_config();
        config
            .env_vars
            .insert("PATH".to_string(), "/opt/bin:$PATH".to_string());
        config
            .env_vars
            .insert("EDITOR".to_string(), "hx:$PATH".to_string());

        let env = config.command_env();

        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/opt/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin"),
        );
        // A non-PATH variable containing `$PATH` stays literal.
        assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx:$PATH"));

        let mut braced = session_config();
        braced
            .env_vars
            .insert("PATH".to_string(), "/opt/bin:${PATH}".to_string());
        assert_eq!(
            braced.command_env().get("PATH").map(String::as_str),
            Some("/opt/bin:/usr/bin:/bin:/usr/sbin:/sbin:/home/.local/bin"),
        );

        let mut literal = session_config();
        literal
            .env_vars
            .insert("PATH".to_string(), "/opt/bin".to_string());
        assert_eq!(
            literal.command_env().get("PATH").map(String::as_str),
            Some("/opt/bin"),
        );
    }

    /// A non-session sandbox expands a composed `PATH` against its own layout
    /// default, which has no `/home/.local/bin`.
    #[test]
    fn a_build_sandbox_expands_a_composed_path_against_its_default() {
        let mut config = Config::new("test");
        config
            .env_vars
            .insert("PATH".to_string(), "/opt/bin:$PATH".to_string());

        assert_eq!(
            config.command_env().get("PATH").map(String::as_str),
            Some("/opt/bin:/usr/bin:/bin:/usr/sbin:/sbin"),
        );
    }

    /// A `$PATH` reference is expanded only when the following character cannot
    /// continue a variable name, so a longer reference such as `$PATH_SUFFIX`
    /// stays literal instead of being corrupted into the default path.
    #[test]
    fn a_composed_path_keeps_longer_variable_references_literal() {
        let mut config = session_config();
        config
            .env_vars
            .insert("PATH".to_string(), "/opt/bin:$PATH_SUFFIX".to_string());

        let env = config.command_env();

        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/opt/bin:$PATH_SUFFIX"),
        );
    }

    /// A build sandbox keeps the layout it always had — the extraction of this
    /// logic out of `command_inner` must not have moved the task plane.
    #[test]
    fn a_build_sandbox_keeps_its_own_layout() {
        let config = Config::new("test");

        assert_eq!(config.command_cwd().unwrap(), "/build");
        let env = config.command_env();
        assert_eq!(env.get("HOME").map(String::as_str), Some("/state/home"));
        assert_eq!(env.get("SOURCE_DATE_EPOCH").map(String::as_str), Some("0"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("en_US.utf8"));
        assert_eq!(env.get("PS1"), None);
    }

    /// A bound-dir sandbox mirrors host paths, so its home is a host path —
    /// the caller's when one is given. `minimald` gives the session's home
    /// here because its own ambient `$HOME` is `/` in the guest, which is not
    /// a directory anything can be patched into (#1204).
    #[test]
    fn a_bound_dir_sandbox_takes_the_home_it_is_given() {
        let config = Config::new("test")
            .with_wd("/workbench", false, Vec::new())
            .with_home(Some("/var/lib/minimal/sessions/s1/home"));

        assert_eq!(config.sandbox_home(), "/var/lib/minimal/sessions/s1/home");
        assert_eq!(
            config.command_env().get("HOME").map(String::as_str),
            Some("/var/lib/minimal/sessions/s1/home"),
        );
    }

    /// The other two layouts own their home outright, so an override is
    /// ignored rather than silently relocating a session's `/home`.
    #[test]
    fn only_the_bound_dir_layout_takes_a_home_override() {
        let session = session_config().with_home(Some("/elsewhere"));
        assert_eq!(session.sandbox_home(), "/home");

        let build = Config::new("test").with_home(Some("/elsewhere"));
        assert_eq!(build.sandbox_home(), "/state/home");
    }

    /// One file of a synthesized `etc`, read back from disk: what these tests
    /// check is what `common::synth_user_group_config` wrote, not what it was
    /// asked to write.
    fn synth_file(dir: &tempfile::TempDir, file: &str) -> String {
        std::fs::read_to_string(dir.path().join("etc").join(file))
            .unwrap_or_else(|e| panic!("reading the synthesized {file}: {e}"))
    }

    /// The `name` entry of a synthesized passwd or group `content`, so a test
    /// can read the entry the box's reported identity comes from.
    fn synth_entry<'a>(content: &'a str, name: &str, file: &str) -> &'a str {
        let not_there = format!("no {name} entry in the synthesized {file}: {content}");
        content
            .lines()
            .find(|line| line.split(':').next() == Some(name))
            .unwrap_or_else(|| panic!("{not_there}"))
    }

    /// The numeric field at `index` of a colon-separated passwd or group
    /// `entry`, named by `what` in the panics a malformed entry raises.
    fn synth_number(entry: &str, index: usize, what: &str) -> u32 {
        let missing = format!("{what} is missing from the entry: {entry}");
        let field = entry
            .split(':')
            .nth(index)
            .unwrap_or_else(|| panic!("{missing}"));
        let not_a_number = format!("{what} is not a number in the entry: {entry}");
        field.parse().unwrap_or_else(|_| panic!("{not_a_number}"))
    }

    /// The agreement `BOX_UID`'s documentation promises: the uid every box
    /// execs as and the uid `common::synth_user_group_config` writes the box's
    /// `/etc/passwd` entry for are the same, and likewise the gids — so the
    /// name a box reports and the id it holds agree.
    ///
    /// `common` cannot depend on this crate, so no type holds the two
    /// constants together; this test does, by reading the files the function
    /// writes. A change to either side fails here, rather than leaving a box
    /// reporting a name that maps to a uid it does not hold.
    #[test]
    fn the_synth_passwd_entry_names_the_box_uid_and_gid() {
        let synth = tempfile::tempdir().expect("a temp dir for the synthesized config");
        common::synth_user_group_config(synth.path(), "dev", "/home")
            .expect("synthesizing the box's user and group configuration");

        let passwd = synth_file(&synth, "passwd");
        let group = synth_file(&synth, "group");

        let user = synth_entry(&passwd, "dev", "passwd");
        assert_eq!(
            synth_number(user, 2, "the passwd entry's uid"),
            BOX_UID,
            "the synthesized passwd entry must name the uid every box execs as, \
             or the box reports a name that maps to a uid it does not hold"
        );
        assert_eq!(
            synth_number(user, 3, "the passwd entry's gid"),
            BOX_GID,
            "the synthesized passwd entry must name the gid every box execs as"
        );

        let own_group = synth_entry(&group, "dev", "group");
        assert_eq!(
            synth_number(own_group, 2, "the group entry's gid"),
            BOX_GID,
            "the synthesized group entry must name the gid every box execs as"
        );
    }
}
