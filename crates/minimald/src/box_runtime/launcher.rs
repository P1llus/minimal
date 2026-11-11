//! The launchers: what starts a box's process, and the environment it
//! starts in.

use super::*;

/// Emit one `tracing::info!` per item the launcher folds into the
/// session — packages, vars, and patches — tagging each with its
/// provenance so an operator can trace "where did `EDITOR=hx` come
/// from?" back to the loadout / project / package that contributed
/// it.
///
/// Baseline packages (the launcher-defaults `base`, `coreutils`,
/// `socat`) log with `source = "launcher-baseline"` so they can be
/// distinguished from composition contributions. Patches and hooks
/// still log even though the launcher can't act on them yet — an
/// operator inspecting a session should see the intent even when
/// the plumbing is deferred.
///
/// Var values are logged at `debug` (separate call) rather than
/// `info` so an accidentally-inherited secret doesn't sit in the
/// default log stream.
#[cfg_attr(test, allow(dead_code))]
pub(super) fn log_session_contents(
    session_name: &str,
    baseline_packages: &[&str],
    composition: Option<&boxes::core::compose::Composition>,
) {
    for p in baseline_packages {
        tracing::info!(
            session = session_name,
            domain = "package",
            name = p,
            source = "launcher-baseline",
            "session content",
        );
    }
    let Some(comp) = composition else {
        return;
    };
    for p in comp.packages() {
        tracing::info!(
            session = session_name,
            domain = "package",
            name = %p.package(),
            source = ?boxes::core::source::Provenanced::source(p),
            "session content",
        );
    }
    for v in comp.vars() {
        let var = v.var();
        tracing::info!(
            session = session_name,
            domain = "var",
            name = %var.name(),
            source = ?boxes::core::source::Provenanced::source(v),
            "session content",
        );
        tracing::debug!(
            session = session_name,
            name = %var.name(),
            value = %var.value(),
            "session var value",
        );
    }
    for sp in comp.patches() {
        let patch = sp.patch();
        tracing::info!(
            session = session_name,
            domain = "patch",
            host_source = %patch.host_path(),
            sandbox_dest = %patch.destination(),
            source = ?boxes::core::source::Provenanced::source(sp),
            "session content (patch: materialized into session home at FinalizeSession)",
        );
    }
    // Hooks are logged in setup order (project first, then loadouts —
    // see `Composition::lifecycle_hooks`), so the log reads in the
    // order the transitions will fire. Execution is still deferred, so
    // this records intent rather than an outcome; an operator
    // inspecting a session should be able to see which scripts it
    // carries and where each came from before any of them runs.
    for h in comp.lifecycle_hooks() {
        let src = boxes::core::source::Provenanced::source(h);
        let hook = h.hook();
        [
            ("on_activate", hook.on_activate()),
            ("on_destroy", hook.on_destroy()),
            ("on_attach", hook.on_attach()),
            ("on_detach", hook.on_detach()),
        ]
        .into_iter()
        .filter_map(|(event, script)| script.map(|s| (event, s)))
        .for_each(|(event, script)| {
            let kind = match script.body() {
                boxes::core::lifecyclehook::HookScriptBody::Inline(_) => "inline",
                boxes::core::lifecyclehook::HookScriptBody::External(_) => "external",
            };
            tracing::info!(
                session = session_name,
                domain = "lifecycle_hook",
                event,
                kind,
                timeout_secs = script.timeout().as_secs(),
                description = hook.description().unwrap_or_default(),
                source = ?src,
                "session content (lifecycle hook: composed, not yet executed)",
            );
        });
    }
}

/// Opens a PTY of the requested size, launches the session process
/// wired to the slave side, and yields the master side plus a
/// handle to the process. The seam between the generic [`Host`]
/// runtime and the process-creation backend.
pub(crate) trait BoxLauncher {
    /// The running-process handle this launcher produces.
    type Process: BoxProcess;
    /// A value held for the session's lifetime, for its `Drop` (it owns the
    /// sandbox files backing the running process's rootfs) and as the live view
    /// of the session's environment. Dropped after [`Self::Process`].
    type Guard: BoxGuard;

    /// Launches the box's entrypoint.
    fn launch(
        self,
        session_id: boxes::SessionId,
        name: String,
        username: String,
        paths: BoxPaths,
        sz: WinSize,
    ) -> impl Future<Output = io::Result<Launched<Self::Process, Self::Guard>>> + Send;

    /// What [`Self::launch`] starts as the box's first process, read from
    /// the spec the box's actor handed this launcher.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when the spec names an entrypoint no launch can start.
    fn entrypoint(&self) -> io::Result<LaunchEntrypoint>;
}

/// The spec a launch starts its box from, as the box's actor hands it over.
/// The actor keeps its own hold on the spec, so every later launch of the
/// box reads the same one.
#[derive(Debug, Clone, Default)]
pub(crate) struct LaunchSpec {
    /// The spec stored beside the box's record (BOX-068). `None` for a box
    /// filed with no spec: a client that predates it, or the dashboard.
    pub(crate) spec: Option<std::sync::Arc<mfile::spec::BoxSpec>>,
    /// Whether the launch is minted only for lifecycle hooks. A hook
    /// launch starts the shell, whatever entrypoint the spec names: the
    /// hooks need the box, and a task's argv must not run before its
    /// activate hooks end. Every other launch starts the spec's
    /// entrypoint, so a task box runs its task as its first process (T43).
    pub(crate) for_hooks: bool,
}

/// The first process a launch starts, as [`LaunchSpec::entrypoint`]
/// decides it. Every launcher starts what this says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LaunchEntrypoint {
    /// The box's login shell, which the launch resolves from the composed
    /// `SHELL` (see `crate::attach_shell`).
    Shell,
    /// A program, by its absolute path in the box, and its arguments.
    Argv { program: String, args: Vec<String> },
}

impl LaunchEntrypoint {
    /// What a log line names for this entrypoint: `login shell`, or the
    /// program's path without its arguments. An argument can carry a
    /// secret, so no log line prints one. [`Self::arg_count`] says how many.
    pub(crate) fn log_name(&self) -> &str {
        match self {
            Self::Shell => "login shell",
            Self::Argv { program, .. } => program,
        }
    }

    /// How many arguments the entrypoint passes to its program: 0 for the
    /// shell.
    pub(crate) fn arg_count(&self) -> usize {
        match self {
            Self::Shell => 0,
            Self::Argv { args, .. } => args.len(),
        }
    }
}

impl LaunchSpec {
    /// The one place a launch decides its box's first process (T42):
    ///
    /// - a box with no spec, and a launch minted only for hooks, start the
    ///   shell;
    /// - otherwise the spec's entrypoint: the shell, or its argv.
    ///
    /// A program word with no `/` names a program under `/usr/bin`, where
    /// packages install: the box's rootfs has no `/bin` and no `PATH`
    /// lookup happens before the exec.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for an argv entrypoint with no program.
    pub(crate) fn entrypoint(&self) -> io::Result<LaunchEntrypoint> {
        let Some(spec) = self.spec.as_deref() else {
            return Ok(LaunchEntrypoint::Shell);
        };
        match &spec.entrypoint {
            mfile::spec::Entrypoint::Shell => Ok(LaunchEntrypoint::Shell),
            mfile::spec::Entrypoint::Exec(_) if self.for_hooks => Ok(LaunchEntrypoint::Shell),
            mfile::spec::Entrypoint::Exec(argv) => {
                let Some((program, args)) = argv.split_first() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the box's settings name an entrypoint with no program",
                    ));
                };
                let program = if program.contains('/') {
                    program.clone()
                } else {
                    format!("/usr/bin/{program}")
                };
                Ok(LaunchEntrypoint::Argv {
                    program,
                    args: args.to_vec(),
                })
            }
        }
    }
}

impl LaunchSpec {
    /// Whether `entrypoint` runs on three pipes, not on the box's terminal:
    /// an argv entrypoint of a box whose spec does not set
    /// `io.pty_enabled`. Such a box speaks the pipeline contract, so a task
    /// run relays its stdin, stdout and stderr as three streams (T43).
    pub(crate) fn runs_on_pipes(&self, entrypoint: &LaunchEntrypoint) -> bool {
        matches!(entrypoint, LaunchEntrypoint::Argv { .. })
            && self.spec.as_deref().is_some_and(|spec| !spec.pty_enabled)
    }
}

/// The daemon's ends of the three pipes an entrypoint runs on when
/// [`LaunchSpec::runs_on_pipes`] says so. The launch's
/// [`Launched::master`] is then the read end of the entrypoint's stdout.
pub(crate) struct EntrypointPipes {
    /// The write end of the entrypoint's stdin.
    pub(super) stdin: OwnedFd,
    /// The read end of the entrypoint's stderr.
    pub(super) stderr: OwnedFd,
}

/// The three pipes of an entrypoint that runs on pipes: what the child
/// gets as its stdin, stdout and stderr, and the daemon's ends. Every end
/// is close-on-exec, so no other process inherits one. The child's ends
/// become its fds 0, 1 and 2 through `dup2`, which clears the flag there.
pub(crate) struct ChildPipes {
    pub(crate) stdin: OwnedFd,
    pub(crate) stdout: OwnedFd,
    pub(crate) stderr: OwnedFd,
    /// The read end of the child's stdout: the launch's master.
    pub(crate) stdout_reader: OwnedFd,
    pub(crate) parent: EntrypointPipes,
}

impl ChildPipes {
    /// Opens the three pipes.
    ///
    /// # Errors
    ///
    /// The error of `pipe2(2)`.
    pub(crate) fn open() -> io::Result<Self> {
        let pipe = || nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from);
        let (stdin, stdin_writer) = pipe()?;
        let (stdout_reader, stdout) = pipe()?;
        let (stderr_reader, stderr) = pipe()?;
        Ok(Self {
            stdin,
            stdout,
            stderr,
            stdout_reader,
            parent: EntrypointPipes {
                stdin: stdin_writer,
                stderr: stderr_reader,
            },
        })
    }
}

/// The name among a task run's entrypoint variables
/// ([`AttachEnv::entrypoint`]) under which the run stages the directory its
/// box's entrypoint starts in (`inherit_cwd`). A launch takes it out before
/// the environment is built, so it never reaches the box.
/// The `:` keeps it apart from any variable name a task can declare.
pub(crate) const START_DIR_KEY: &str = "minimal:start-dir";

/// Where a command should start in a session, and with what environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BoxEnvironment {
    /// Absolute path inside the sandbox: `/workbench` for a session.
    pub(crate) cwd: String,
    /// The composed session variables, layout defaults included, plus anything
    /// installed into the session since it launched.
    pub(crate) vars: BTreeMap<String, String>,
}

/// The launcher-owned value a [`Host`] holds for its session's lifetime.
///
/// Primarily a `Drop` guard — it owns the sandbox files backing the running
/// process's rootfs — but it is also the live handle to the session's
/// environment.
pub(crate) trait BoxGuard: Send + 'static {
    /// The working directory and environment a command should run with in this
    /// session, as of now.
    fn command_environment(&self) -> BoxEnvironment;
}

/// The mock launcher has no sandbox, so there is nothing to describe.
#[cfg(test)]
impl BoxGuard for () {
    fn command_environment(&self) -> BoxEnvironment {
        BoxEnvironment::default()
    }
}

impl BoxGuard for crate::env::Env {
    fn command_environment(&self) -> BoxEnvironment {
        crate::env::Env::command_environment(self)
    }
}

/// The product of [`BoxLauncher::launch`].
pub(crate) struct Launched<P, G> {
    /// Master side of the launched process's PTY; the slave is wired to the
    /// process. The [`Host`] reads its stdout and writes its stdin here.
    pub(super) master: OwnedFd,
    /// Handle used to wait on / signal the launched process.
    pub(super) process: P,
    /// Kept alive for the session; see [`BoxLauncher::Guard`].
    pub(super) guard: G,
    /// The per-sandbox network attachment (own-IP switch wiring), if any. Torn
    /// down explicitly via [`sandbox::NetGuard::teardown`] at session end.
    /// `None` for `HostNet`/`NoNet` and for the plain mock.
    pub(super) net_guard: Option<Box<dyn sandbox::NetGuard>>,
    /// Path of the session PTY's slave side, so hooks can open the
    /// terminal briefly rather than the host retaining a descriptor.
    pub(super) tty_path: std::path::PathBuf,
    /// The listen plan the launch gathered for the box it launched: the
    /// lease, the published address, the switch control channel, the gate
    /// and the publication set its watcher publishes through. `None` when
    /// the launch could build no plan — no lease, no published address or no
    /// live gate — and a mock launch that builds none starts no watcher at
    /// all. The plan rides here rather than a table between the two, so it
    /// is this launch's own from the moment it is built: it never survives
    /// to a spawn that did not gather it.
    pub(super) listen_plan: Option<crate::net::listeners::ListenPlan>,
    /// The gate holding the launched shell before it execs, on a launch
    /// minted only for lifecycle hooks (see [`SandboxLauncher::for_hooks`]):
    /// the box exists for the hooks to run in, while the shell — whose
    /// startup files are the user's — waits for the first attach. `None` on
    /// every other launch, whose shell starts at once.
    pub(super) start_gate: Option<sandbox::StartGate>,
    /// The daemon's ends of the entrypoint's stdin and stderr, on a launch
    /// whose entrypoint runs on pipes ([`LaunchSpec::runs_on_pipes`]).
    /// `None` on a launch that gives its process the terminal.
    pub(super) pipes: Option<EntrypointPipes>,
}

/// The box's output log as its host writes it (BOX-155): every byte the
/// box's entrypoint writes to its terminal, appended from the start of the
/// launch. The host writes the log before it hands the same bytes to an
/// attached client, so a client is a second reader. When a client leaves,
/// the log already has everything it saw and everything after it.
///
/// The file is [`boxes::store::LOG_FILE`] beside the box's record. No path
/// mounted into the box reaches it, and only the daemon's user can open it
/// (BOX-164). The open does not follow a symlink, so a link planted where
/// the log goes is refused and is not written through.
///
/// The log holds at most [`boxes::store::LOG_CAP`] bytes. Past the cap it
/// keeps [`boxes::store::LOG_DROPPED`] and the newest output, and the box
/// runs on (see [`boxes::store::LogWriter`]).
pub(crate) struct BoxOutputLog {
    /// `None` when the box has no log: its workspace is not in the store
    /// (a test host), or a write failed.
    writer: Option<boxes::store::LogWriter>,
    path: Option<paths::DaemonAbsPath>,
    session_id: boxes::SessionId,
}

impl BoxOutputLog {
    /// Opens the log of the box whose workspace is `paths.working`, for
    /// appends, before the launch starts the entrypoint. A box whose
    /// workspace is not in the store has no log.
    ///
    /// # Errors
    ///
    /// The open's error for a box in the store, after the daemon log names
    /// the path and the error. The box does not start without its log.
    pub(crate) fn open(session_id: boxes::SessionId, paths: &BoxPaths) -> io::Result<Self> {
        let Some(dir) = boxes::store::BoxDir::for_tree(&paths.working) else {
            tracing::debug!(
                box_id = %session_id,
                workspace = %paths.working.as_str(),
                "no output log: the box's workspace is not in the box store"
            );
            return Ok(Self {
                writer: None,
                path: None,
                session_id,
            });
        };
        let path = dir.log_path();
        let writer = Self::open_path(&path)
            .and_then(|file| boxes::store::LogWriter::new(path.clone(), file));
        match writer {
            Ok(writer) => {
                tracing::info!(
                    box_id = %session_id,
                    log_path = %path.as_str(),
                    cap_bytes = boxes::store::LOG_CAP,
                    "logging the box's output from its start"
                );
                Ok(Self {
                    writer: Some(writer),
                    path: Some(path),
                    session_id,
                })
            }
            Err(e) => {
                tracing::warn!(
                    box_id = %session_id,
                    log_path = %path.as_str(),
                    error = %e,
                    "refused to open the box's output log"
                );
                Err(e)
            }
        }
    }

    /// Opens `path` owner-only, for reads and appends, without following a
    /// symlink. Anything there that is not a regular file is refused. The
    /// reads are the cap's: it copies the newest bytes out of this file.
    fn open_path(path: &paths::DaemonAbsPath) -> io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.as_utf8_path())?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the log path is not a regular file",
            ));
        }
        Ok(file)
    }

    /// Appends `bytes` to the log. A write that fails goes to the daemon
    /// log with the path and the error, and the log stops there: a log
    /// with a hole in it is not complete, so nothing more is written.
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        let Some(writer) = self.writer.as_mut() else {
            return;
        };
        if let Err(e) = writer.write(bytes) {
            tracing::warn!(
                box_id = %self.session_id,
                log_path = %self.path.as_ref().map_or("", |p| p.as_str()),
                error = %e,
                dropped_bytes = bytes.len(),
                "refused a write to the box's output log; the log stops here"
            );
            self.writer = None;
        }
    }
}

/// Packages every session sandbox gets unconditionally, regardless of
/// the client's contribution: `base` for the shell, `coreutils` for
/// `ls`/`cat`/etc, and `socat` for the `min` command bridge (the
/// helper installed at `/usr/bin/min` speaks to `/run/minenv_sock`
/// via `socat`).
#[cfg_attr(test, allow(dead_code))]
pub(super) const BASELINE_PACKAGES: &[&str] = &["base", "coreutils", "socat"];

/// Environment folded into a session shell at the launching attach, over and
/// above the composition. Both halves are captured from the SSH channel the
/// attach arrives on (see [`crate::box_actor::Session::attach`]).
///
/// The two halves sit on opposite sides of the composition in precedence:
/// `inherited` are defaults the composition may override, `connection` are
/// authoritative facts that override the composition.
///
/// `inherited` is a launch-time fact: it describes the client that *created*
/// the shell and cannot be revised without respawning it. `connection` is a
/// per-attach fact — see [`ConnectionEnv`] — carried on every attach, not just
/// the one that mints the host.
///
/// The fields are read only by the real [`SandboxLauncher`]; the mock launcher
/// ignores them, so tolerate them being unread under `test`.
#[derive(Debug, Default, Clone)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct AttachEnv {
    /// Locale/timezone vars the client forwarded from its shell (`LANG`,
    /// `LC_*`, `TZ`) — OpenSSH's `AcceptEnv` set. Applied as defaults *below*
    /// the composition, so a loadout's explicit locale still wins.
    pub(crate) inherited: Vec<(String, String)>,
    /// Per-connection facts — `TERM` from the PTY request, plus the banner's
    /// detach hint the daemon derives from the channel's session keys. Applied
    /// *above* the composition, the way sshd sets `TERM`
    /// authoritatively regardless of shell dotfiles. (`SSH_TTY` and
    /// `SSH_CONNECTION`/`SSH_CLIENT` are deliberately not set: the session
    /// sandbox has no host `/dev/pts` and the Unix-socket transport has no peer
    /// address, so any value would name something that doesn't exist in-session.)
    pub(crate) connection: Vec<(String, String)>,
    /// A task run's resolved variables (T43), and the directory it starts
    /// in under [`START_DIR_KEY`]: for the argv entrypoint's process alone,
    /// layered above everything else in its environment. They can hold
    /// values the caller's shell gave, secrets among them. So neither the
    /// box's environment nor the host's connection layer keeps them, and no
    /// later exec, attach or hook in the box sees them.
    pub(crate) entrypoint: Vec<(String, String)>,
}

impl AttachEnv {
    /// The connection half as a map, for merging into a session environment.
    pub(crate) fn connection_env(&self) -> ConnectionEnv {
        self.connection.iter().cloned().collect()
    }

    /// Whether this attach declares a terminal (`TERM` from the PTY
    /// request). The detach hint the daemon seeds every attach with is not a
    /// terminal fact, so an empty-vs-non-empty map no longer answers this.
    pub(crate) fn declares_terminal(&self) -> bool {
        self.connection.iter().any(|(k, _)| k == "TERM")
    }
}

/// The facts that describe *the terminal currently attached*, as opposed to
/// the session's own composed environment: `TERM` from the PTY request, plus
/// the banner's detach hint derived from the channel's session keys, and
/// `MINIMAL_SESSION_NAME` when the session is renamed — republished so the
/// already-running shell picks up the new name at its next prompt.
///
/// Kept apart from [`AttachEnv`] because its lifetime is different. A session
/// shell is spawned once and lives across many attaches, so its `environ` is
/// frozen at launch — but `TERM` describes whichever terminal is on the other
/// end *now*, and a client attaching from a different terminal than the one
/// that minted the shell brings a different one. The host therefore keeps the
/// latest and republishes it on every attach ([`Host::publish_connection_env`])
/// rather than treating it as a launch-time constant.
pub(crate) type ConnectionEnv = std::collections::BTreeMap<String, String>;

/// Where the session home lives inside the sandbox.
///
/// Derived from the same `sandbox` constant the sandbox mounts it from
/// (`crate::env::HOME_ROOT` is the same value; this module cannot use that one
/// because `env` is `cfg(not(test))` and these paths are asserted under test).
pub(super) const SESSION_HOME_ROOT: &str = constcat::concat!("/", sandbox::SESSION_HOME);

/// Session-home-relative directory holding the per-attach environment files.
pub(super) const ATTACH_ENV_DIR_REL: &str = ".local/state/minimal";

/// POSIX-shell form of the per-attach environment, sourced by the baseline
/// [`BASELINE_PROMPT_COMMAND`] at every prompt.
pub(super) const ATTACH_ENV_SH_REL: &str = constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.sh");

/// fish form of the same file, read by the fish hook the daemon installs into
/// the rootfs (`crate::env`). Written alongside the POSIX form because a
/// session's shell is whatever the user runs, not only the bash the daemon
/// spawns.
pub(super) const ATTACH_ENV_FISH_REL: &str =
    constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.fish");

/// The same facts as data rather than as a script, for a shell that would
/// rather read them than evaluate them — nushell, today.
///
/// Nu cannot use either script form. `source` takes a *parse-time constant*
/// path, so it can't be pointed at `$env.MINIMAL_ATTACH_ENV_JSON`; and a
/// literal path that doesn't exist yet is a hard parse error, which would
/// break the shell outright on a session that has published nothing. Its
/// `load-env (open …)` reads this file instead, under a `path exists` guard.
/// JSON also sidesteps a third set of quoting rules — the escaping is the
/// serializer's problem, not this module's.
///
/// Every key here becomes an environment variable, so the file carries no
/// metadata (not even the "generated" banner the script forms have).
pub(super) const ATTACH_ENV_JSON_REL: &str =
    constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.json");

/// In-sandbox absolute path of the POSIX per-attach environment file.
pub(crate) const ATTACH_ENV_SH: &str = constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_SH_REL);

/// In-sandbox absolute path of the fish per-attach environment file.
pub(crate) const ATTACH_ENV_FISH: &str =
    constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_FISH_REL);

/// In-sandbox absolute path of the JSON per-attach environment file.
pub(crate) const ATTACH_ENV_JSON: &str =
    constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_JSON_REL);

/// The baseline shell's per-prompt wiring, in two halves.
///
/// Trigger half of the launcher-baseline orientation banner: evaluates the
/// [`BASELINE_MOTD`] payload at the first interactive prompt, then unsets
/// both vars so the banner prints exactly once and never for
/// non-interactive commands. Identical to the MOTD recipe the built-in
/// `default` loadout ships and `docs/reference/loadouts.md` ("Vars in the
/// attach shell") documents.
///
/// It carries nothing but the banner. The per-attach environment is refreshed
/// by the shell hooks the daemon installs into the rootfs (`crate::env`),
/// deliberately not from here: this variable is composed, so a loadout
/// setting its own `PROMPT_COMMAND` would replace the refresh, and the MOTD
/// recipe above would `unset` it — neither of which a session's `TERM` may
/// depend on.
pub(super) const BASELINE_PROMPT_COMMAND: &str =
    r#"eval "$MINIMAL_MOTD"; unset PROMPT_COMMAND MINIMAL_MOTD"#;

/// Absolute workspace root inside a session sandbox, `/workbench` by
/// convention. Derived from the same [`sandbox::SESSION_DEFAULT_WD`] the
/// sandbox uses as the shell's initial cwd (sessions never set a
/// `working_name_override`), so [`BASELINE_MOTD`]'s blueprint test cannot
/// drift from where the workspace actually lives.
pub(super) const SESSION_WORKSPACE_ROOT: &str = constcat::concat!("/", sandbox::SESSION_DEFAULT_WD);

/// Payload half of the launcher-baseline orientation banner: a STATIC
/// template. The dynamic parts resolve in-shell at print time: the
/// template interpolates `$MINIMAL_SESSION_NAME` and `$MINIMAL_LOADOUTS`
/// (both seeded by [`session_baseline_env`] — the loadout list arrives
/// from the client as the composition's first-class orientation field,
/// never as a user var); each carries a `${VAR:-fallback}` so a missing
/// var still renders sanely. Whether the workspace holds a blueprint is a
/// SESSION-filesystem fact, so it is not interpolated from anywhere — the
/// template tests [`SESSION_WORKSPACE_ROOT`] directly (both mfile
/// layouts, `minimal.toml` and `.minimal/minimal.toml`) when it prints,
/// which stays correct across skipped uploads, an in-session `min init`,
/// and attaches from unrelated host directories. TTY-gated, plain text —
/// `NO_COLOR`-safe, no box drawing.
pub(super) const BASELINE_MOTD: &str = constcat::concat!(
    r#"[ -t 1 ] && { printf 'minimal · session %s · loadout %s\ndetach: %s' "${MINIMAL_SESSION_NAME:-unnamed}" "${MINIMAL_LOADOUTS:-none}" "${MINIMAL_DETACH_HINT:-ctrl-] then d}"; [ -f "#,
    SESSION_WORKSPACE_ROOT,
    r#"/minimal.toml ] || [ -f "#,
    SESSION_WORKSPACE_ROOT,
    r#"/.minimal/minimal.toml ] || printf ' · no minimal.toml here — min init to add one'; printf '\n'; }"#,
);

/// The launcher-baseline environment seeded beneath every other layer of
/// [`layer_session_env`]: the session's identity (`MINIMAL_SESSION_NAME`,
/// plus `MINIMAL_LOADOUTS` when the composition's first-class orientation
/// field carries a display list) and the once-only orientation banner
/// pair. ALL orientation env is seeded here, daemon-side, from typed
/// data — none of it rides the user var lane, so user vars and policy
/// can never collide with it. Sitting on the lowest layer means any
/// composed `PROMPT_COMMAND` — a user loadout's, or the built-in
/// default's — overrides the baseline banner cleanly, while the identity
/// vars stay available for that override to interpolate.
///
/// `loadouts_display` is `None` when the composition carries no display
/// list (a client that predates the orientation field, or no
/// composition at all): the var is then left unset so each template's
/// own `${MINIMAL_LOADOUTS:-…}` fallback renders — the baseline banner
/// falls back to `none`, the built-in default loadout's MOTD to
/// `default (built-in)`, each correct for the context it prints in.
pub(super) fn session_baseline_env(
    session_name: &str,
    loadouts_display: Option<&str>,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("MINIMAL_SESSION_NAME".to_string(), session_name.to_string()),
        (
            "PROMPT_COMMAND".to_string(),
            BASELINE_PROMPT_COMMAND.to_string(),
        ),
        ("MINIMAL_MOTD".to_string(), BASELINE_MOTD.to_string()),
        // Where the host republishes the attached terminal's facts. Named
        // rather than hard-coded into the prompt command so a loadout that
        // replaces `PROMPT_COMMAND` (or starts another shell) can still find
        // the file; the fish form is offered for the same reason.
        ("MINIMAL_ATTACH_ENV".to_string(), ATTACH_ENV_SH.to_string()),
        (
            "MINIMAL_ATTACH_ENV_FISH".to_string(),
            ATTACH_ENV_FISH.to_string(),
        ),
        (
            "MINIMAL_ATTACH_ENV_JSON".to_string(),
            ATTACH_ENV_JSON.to_string(),
        ),
        // The POSIX fallback tier. `$ENV` is the only startup hook a plain
        // `sh`, dash, ash, or ksh offers, and unlike the other four shells
        // there is nothing in the rootfs they read on their own — so this one
        // has to travel as a variable. It names a daemon-owned file; the file
        // is what does the work.
        ("ENV".to_string(), crate::env::ATTACH_ENV_POSIX.to_string()),
    ];
    if let Some(display) = loadouts_display {
        env.push(("MINIMAL_LOADOUTS".to_string(), display.to_string()));
    }
    env
}

/// Layers a session shell's environment by precedence, lowest first: the
/// launcher `baseline` (session identity + orientation banner), the
/// client-forwarded `inherited` locale/timezone, then the `composition` vars
/// (which may override both lower layers), then the `connection` facts
/// (which override everything — sshd-style). Later inserts win on a shared key.
pub(super) fn layer_session_env(
    baseline: Vec<(String, String)>,
    inherited: Vec<(String, String)>,
    composition: Vec<(String, String)>,
    connection: Vec<(String, String)>,
) -> std::collections::HashMap<String, String> {
    let mut env = std::collections::HashMap::new();
    for (k, v) in baseline
        .into_iter()
        .chain(inherited)
        .chain(composition)
        .chain(connection)
    {
        env.insert(k, v);
    }
    env
}

/// The real [`BoxLauncher`]: evaluates a minimal context into a graph,
/// builds a sandboxed `/bin/bash`, and wires it to a freshly opened PTY.
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct SandboxLauncher {
    pub(crate) ctx: mctx::Context,
    /// Env captured from the SSH channel that mints this shell; see
    /// [`AttachEnv`].
    pub(crate) attach_env: AttachEnv,
    pub(crate) network_mode: NetworkMode,
    /// Shared per-host gvproxy switch. Used only for
    /// [`NetworkMode::OwnIp`] launches.
    pub(crate) net_switch: std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>>,
    /// The session's whole network policy — declared egress enforced by the
    /// switch relay's outbound leg (NET-062/063/064), static ingress port
    /// mappings applied on the switch once this `OwnIp` PTask attaches and
    /// inbound ports gated on its other leg, removed on exit. Unused by other
    /// network modes.
    pub(crate) policy: boxes::BoxPolicy,
    /// The proxy-routing-table handle the `OwnIp` lease is reported through
    /// on attach, so the box's `<name>.min.internal` route exists exactly
    /// while the box does (NET-001). Ignored by every other network mode.
    pub(crate) own_address: Option<crate::net::provider::OwnAddressReporter>,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when it was registered: the switch address this `OwnIp` PTask
    /// attaches with instead of drawing one, and the published loopback
    /// address the host side names the box by. Ignored by every other
    /// network mode; `None` for a session the activating client did not
    /// register, which self-allocates on a native host and is refused on a
    /// VM host, where the in-VM daemon draws nothing (NET-138).
    pub(crate) box_addresses: Option<boxes::BoxAddresses>,
    /// Composition to merge into the launcher's baseline packages and
    /// vars. Patches and lifecycle hooks are ignored today.
    pub(crate) composition: Option<std::sync::Arc<boxes::core::compose::Composition>>,
    /// Weak handle back to the owning session actor, for  `min` commands
    /// (e.g. `min build`) to drive session side-ops.
    pub(crate) session: crate::box_actor::WeakBoxHandle,
    /// Whether this launch exists to run lifecycle hooks rather than to serve
    /// a person: minted by the session's hook path — activation at finalize,
    /// teardown at detach or destroy — headless, its pty read by nobody.
    ///
    /// The unenforced-placement advisory is a session surface, and a hook run
    /// is not a session start: its daemon-log record would count one hook run
    /// as one session start, and its banner would be written into a hook pty
    /// no one reads. So a hook launch emits neither form. This is *not* the
    /// launch phase (`LaunchPhase`): the destroy path's hook launch is
    /// `Attached` exactly like an attach's, and finalize's activation launch
    /// is `Activating` — only the caller that mints the launch knows what it
    /// is for, which is why it travels on the launcher.
    pub(crate) for_hooks: bool,
    /// The box's runtime publications, built fresh for the spawn this
    /// launcher is about to run: the one set this launch's listen plan and
    /// the session actor's runtime expose path both read, so a port the
    /// one published is never bound by the other (NET-047's never-contend
    /// half, and the answer `min net expose` gets when the listener
    /// watcher published its port first).
    pub(crate) publications: crate::net::listeners::BoxPublications,
    /// The daemon's state directory, handed to this launch's listen plan:
    /// its watcher appends each listen it publishes to the audit log under
    /// it, the one the session's runtime expose path audits in (NET-046).
    pub(crate) state_dir: std::path::PathBuf,
    /// The proxy's root certificate, PEM-encoded, that this launch adds to
    /// the box's own trust store (BEP-011), as
    /// [`super::launch_root_certificate`] reads it from the box's record.
    /// `None` for a box that gets no root.
    pub(crate) root_certificate: Option<String>,
    /// The spec this launch starts the box from: its first process comes
    /// from here, through [`LaunchSpec::entrypoint`].
    pub(crate) spec: LaunchSpec,
}

/// Reaps a freshly-spawned sandbox process if the launch is abandoned
/// before the process is handed off to a [`Launched`].
///
/// A [`hakoniwa::Child`] does not terminate when dropped, so anything
/// that lets one go without killing it orphans the sandbox — a process
/// still holding the session's rootfs after the session it belonged to
/// is gone. The `Err` arms between the spawn and the handoff reap
/// explicitly; this is what catches the third way out, a **cancelled**
/// launch future. There is a real caller: a teardown transition bounds
/// its launch with a timeout (`box_actor::HOOK_LAUNCH_TIMEOUT`) and drops
/// this future when it expires, which without the guard would strand a
/// sandbox the destroy then tries to delete out from under.
///
/// Reaping is synchronous (`kill` + `wait` are not async), so unlike
/// [`sandbox::PlannedLaunch`] — which has to give a lease back, and spawns
/// that release — this needs no runtime to do its work in `Drop`.
#[cfg_attr(test, allow(dead_code))]
pub(super) struct SpawnedProcessGuard {
    /// `None` once the process has been handed off — see
    /// [`Self::release`].
    process: Option<sandbox::Child>,
}

#[cfg_attr(test, allow(dead_code))]
impl SpawnedProcessGuard {
    fn new(process: sandbox::Child) -> Self {
        Self {
            process: Some(process),
        }
    }

    /// Borrow the guarded process, for the post-spawn wiring that still
    /// needs it while the guard stays responsible for it.
    fn get_mut(&mut self) -> &mut sandbox::Child {
        self.process
            .as_mut()
            .expect("the process is taken only by `release`, which consumes the guard")
    }

    /// Hand the process off, disarming the guard.
    fn release(mut self) -> sandbox::Child {
        self.process
            .take()
            .expect("the process is taken only here, and this consumes the guard")
    }
}

impl Drop for SpawnedProcessGuard {
    fn drop(&mut self) {
        let Some(mut process) = self.process.take() else {
            return;
        };
        // Waited for, so the sandbox's directories are free of it when
        // this returns.
        process.kill();
        process.wait();
    }
}

impl BoxLauncher for SandboxLauncher {
    type Process = SandboxProcess;

    fn entrypoint(&self) -> io::Result<LaunchEntrypoint> {
        self.spec.entrypoint()
    }

    // The session env, kept alive for the session's lifetime (it owns the
    // sandbox files backing the running process's rootfs). The own-IP switch
    // attachment, when present, travels separately as `Launched::net_guard` and
    // is torn down explicitly at session end.
    type Guard = crate::env::Env;

    async fn launch(
        self,
        session_id: boxes::SessionId,
        name: String,
        username: String,
        paths: BoxPaths,
        sz: WinSize,
    ) -> io::Result<Launched<SandboxProcess, Self::Guard>> {
        // Decided before anything is built, so a spec no launch can start
        // reserves nothing.
        let entrypoint = self.entrypoint()?;
        let on_pipes = self.spec.runs_on_pipes(&entrypoint);
        let ctx = self.ctx;
        // Move the session policy out of `self` up front so it can be applied
        // after the switch attach below (the rest of `self` is consumed first).
        let policy = self.policy;
        // Whether the declaration lets a listen publish at all (NET-016):
        // `allow` with a range. Read now, before the policy moves into the
        // network plan, for the missing-listen-plan line below.
        let listens_can_publish = policy.ingress.as_ref().is_some_and(|ingress| {
            ingress.dynamic_ingress == Some(boxes::DynamicIngress::Allow)
                && ingress.dynamic_allowed_range.is_some()
        });
        let network_mode = self.network_mode;
        // BEP-011: the root this launch adds to the box's trust store, moved
        // out with them for the env build below.
        let root_certificate = self.root_certificate;
        let net_switch = self.net_switch;
        let own_address = self.own_address;
        let box_addresses = self.box_addresses;
        // The session name, registered as this PTask's `*.min.internal` hostname on
        // an own-IP attach (finding #3 / UC6); cloned because `name` is consumed by
        // the sandbox env below.
        let session_name = name.clone();
        let composition = self.composition;
        let attach_env = self.attach_env;
        let session = self.session;
        // What this launch is for, decided by the caller that minted it (see
        // [`SandboxLauncher::for_hooks`]): it gates the advisory below, never
        // the placement itself — a hook launch's box is placed like any
        // other's, or runs unenforced like any other's; only the advice is
        // for the session's audience.
        let for_hooks = self.for_hooks;
        // `graph_from_all_packages` is CPU-heavy (nickel evaluation,
        // graph construction) — run it on the blocking pool so it
        // doesn't stall the async executor.
        let (ctx, graph_result) = crate::traced::spawn_blocking(move || {
            let mut ctx = ctx;
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());
            (ctx, r)
        })
        .await
        .map_err(io::Error::other)?;
        let graph = graph_result.map_err(io::Error::other)?;

        // Step 1 (pre-spawn): the provider for this PTask's mode reserves what
        // the sandbox needs — for own-IP, a lease and a running gvproxy — and
        // says what it is. The decision this launch itself read above goes in
        // with them, carried rather than memoized, so the plan below follows
        // this launch's verdict fact and never a concurrent launch's.
        // `PlannedLaunch` owns the release from here: an early `Err` return
        // or a cancelled launch gives the lease back.
        let planned = sandbox::PlannedLaunch::begin(crate::net::provider::network_for(
            network_mode,
            &net_switch,
            &session_name,
            Some(policy),
            own_address.clone(),
            box_addresses,
        ))
        .await
        .map_err(|e| io::Error::other(format!("planning the session network: {e}")))?;

        // Package + env-var union of the launcher baseline and every
        // contribution the composer collected. Packages: baseline set
        // (required for a usable interactive shell) unioned with
        // everything the composition asks for, dedup-preserving-order
        // so the base packages install first. Env vars: the
        // composition's over a small launcher baseline — the session's
        // identity (`MINIMAL_SESSION_NAME`) and the once-only
        // orientation banner pair (see [`session_baseline_env`]) —
        // while `sandbox` sets the session defaults (`PS1`, `PATH`,
        // `HOME`, `LANG`, …) which these vars then override on a
        // shared key.
        //
        // Baseline is intentionally minimal: `base` for the shell,
        // `coreutils` for `ls`/`cat`/etc, and `socat` for the
        // in-sandbox `min` helper's UDS relay to the daemon. `bash`
        // is unconditionally added as a helper dep by
        // `crate::env::Env::build`, so listing it here would just
        // duplicate the entry — `socat` is added there too but is
        // named explicitly so the baseline reads as self-contained.
        //
        // Both maps carry only resolved values, so the composition-
        // vars merge doesn't need `EnvVarValue::Value(...)` at
        // each insert: `EnvArgs::with_resolved_env_vars` wraps once
        // at the boundary. Composition patches and lifecycle hooks
        // are not applied yet (the file-upload path and in-sandbox
        // exec plumbing that they need aren't wired), so they pass
        // through this stage untouched.
        // A shadow set tracks membership so the composition-union
        // pass below stays O(n) instead of the naive
        // `Vec::contains` per iteration (see clippy's O(n²) hint).
        // Two `String` allocs per baseline entry (one for the vec,
        // one for the set) — intrinsic given both need owned
        // strings and `String::clone` is a deep copy. Trivial cost
        // for a three-element baseline.
        let mut packages: Vec<String> =
            BASELINE_PACKAGES.iter().map(|s| (*s).to_string()).collect();
        let mut package_set: std::collections::HashSet<String> =
            BASELINE_PACKAGES.iter().map(|s| (*s).to_string()).collect();
        if let Some(comp) = &composition {
            for p in comp.packages() {
                let name = p.package();
                if package_set.insert(name.to_string()) {
                    packages.push(name.to_string());
                }
            }
        }
        // Env vars, layered by precedence (see [`layer_session_env`]): the
        // launcher baseline and the client-forwarded locale/timezone sit
        // below the composition, and the per-connection facts (`TERM`) sit
        // above it.
        let composition_vars: Vec<(String, String)> = composition
            .as_ref()
            .map(|c| {
                c.vars()
                    .iter()
                    .map(|v| (v.var().name().to_string(), v.var().value().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        // The banner's loadout list arrives as the composition's
        // first-class orientation field; empty means "unknown" (an old
        // client) and seeds nothing — the template's `${…:-}` fallback
        // renders instead.
        let loadouts_display = composition
            .as_ref()
            .map(|c| c.orientation().loadouts_display.as_str())
            .filter(|d| !d.is_empty());
        // BEP-011: the env build adds the trust variables below these, once
        // it knows whether the box's packages ship a CA bundle.
        //
        // BEP-015: a box whose grant gave it the git credential helper gets
        // the helper as git's sole helper for the grant hosts, at command
        // scope, which git reads after every configuration file. The pairs
        // follow any that the composition sets. A count that is not a
        // number adds no pairs, so the pairs the box set stay as they are.
        let mut connection = attach_env.connection;
        // A task run's start directory rides its entrypoint variables (see
        // [`START_DIR_KEY`]). Only an argv entrypoint starts there, and only
        // an argv entrypoint gets the variables.
        let mut entrypoint_vars = attach_env.entrypoint;
        let start_dir = entrypoint_vars
            .iter()
            .rposition(|(key, _)| key == START_DIR_KEY)
            .map(|at| entrypoint_vars.remove(at).1);
        entrypoint_vars.retain(|(key, _)| key != START_DIR_KEY);
        let git_config_count = composition_vars
            .iter()
            .chain(&connection)
            .rev()
            .find(|(key, _)| key == "GIT_CONFIG_COUNT")
            .map(|(_, value)| value.parse::<usize>());
        match git_config_count.unwrap_or(Ok(0)) {
            Ok(first) => {
                let sealed = connection
                    .iter()
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>();
                let git_env = crate::box_actor::bep_git_helper::launch_git_config_env(
                    paths.home.as_utf8_path().as_std_path(),
                    first,
                    sealed,
                );
                connection.extend(git_env);
            }
            Err(_) => tracing::warn!(
                "GIT_CONFIG_COUNT in the box environment is not a number; \
                 the git credential helper is not set for the grant hosts"
            ),
        }
        let env_vars = layer_session_env(
            session_baseline_env(&name, loadouts_display),
            attach_env.inherited,
            composition_vars,
            connection,
        );
        // Which shell this attach starts is decided from the composed
        // `SHELL` (see `crate::attach_shell`). Read before `env_vars`
        // moves into the env build; the rootfs it has to be checked
        // against doesn't exist until that build has run.
        let requested_shell = env_vars.get("SHELL").cloned();
        // Whether anything composed a prompt. `sandbox` sets a
        // bash-syntax `PS1` as the session default, which a shell that
        // doesn't speak those escapes prints literally — so a non-bash
        // shell gets its own (see `ShellChoice::prompt`), but only when
        // the user hasn't asked for a specific prompt themselves.
        let composed_prompt = env_vars.contains_key("PS1");
        // For the log line on the fallback path, which fires after
        // `name` has moved into `EnvArgs`.
        let session_label = name.clone();
        // Log every item that will (or would) end up in the session,
        // tagged with its provenance. Patches and lifecycle hooks are
        // included even though the launcher can't act on them yet —
        // an operator inspecting logs should see the intent.
        log_session_contents(&name, BASELINE_PACKAGES, composition.as_deref());

        // Build the env + container and spawn the process. Any failure here
        // leaves no process to reap; `planned` releases its lease on the `Err`
        // return. `planned` outlives the block, so the plan is cloned out.
        let plan = planned.plan().clone();
        let build_and_spawn = async {
            // The env owns the context, graph and the sandbox files backing the
            // running process's rootfs, so it is `Send + 'static` and can be moved
            // into the host as the guard that keeps those files alive.
            // Boxed: inlined, this reaches the cache fetchers' client stack and
            // the launch future's layout overruns rustc's query depth (128).
            let mut env_args =
                crate::env::EnvArgs::new(name, paths.working, paths.home, paths.cache, session)
                    .with_session_id(session_id)
                    .with_packages(packages)
                    .with_resolved_env_vars(env_vars)
                    // Session envs source package attrs (env_state_wiring,
                    // env_dir/file_mappings) exclusively through the
                    // composer so they're subject to user policy. Task-run
                    // uses a different `Env::build` (mctx::env::Env) and
                    // keeps the legacy un-gated wiring for now.
                    .without_package_attr_wiring()
                    .with_network(plan.clone())
                    .with_username(username);
            // BEP-011: the build writes the root into the box's own bundle
            // copy and hashed directory, and sets the trust variables.
            if let Some(pem) = root_certificate {
                env_args = env_args.with_root_certificate(pem);
            }
            let mut env = Box::pin(crate::env::Env::build(ctx, graph, env_args)).await?;

            let mut container = env
                .container(&plan)
                .map_err(|e| io::Error::other(format!("container build: {e}")))?;
            // The entrypoint leads a session of its own either way. Only a
            // terminal can be its controlling terminal: on pipes, taking one
            // fails with ENOTTY and the entrypoint never runs.
            if on_pipes {
                container.set_session_leader_without_terminal();
            } else {
                container.set_session_leader();
            }
            // A launch minted only for hooks holds its shell at the gate: the
            // hooks need the box, not the shell, and the shell's startup —
            // the user's rc files and prompt commands — must not run ahead of
            // the activate hooks it may depend on. The first attach releases
            // it (see [`Host::attach`]).
            let start_gate = if for_hooks {
                Some(
                    env.hold_start(&mut container)
                        .map_err(|e| io::Error::other(format!("start gate: {e}")))?,
                )
            } else {
                None
            };

            let pty = Pty::open(sz).map_err(|e| io::Error::other(format!("pty open: {e}")))?;

            // What the box runs first, from its spec (T42): the login shell,
            // or the spec's argv.
            let mut command = match &entrypoint {
                LaunchEntrypoint::Shell => {
                // The shell, and the argv it needs to reach the daemon's
                // per-attach environment hook. Every program path here is
                // absolute (`/usr/bin/<shell>`): packages install with
                // `--prefix=/usr` and the generic rootfs has no `/bin`, so a
                // bare name or a `/bin/…` path would fail with ENOENT.
                let shell = crate::attach_shell::resolve(requested_shell.as_deref(), &env.rootfs());
                if let Some(notice) = &shell.fallback {
                    tracing::warn!(
                        session = %session_label,
                        requested = requested_shell.as_deref().unwrap_or_default(),
                        "{notice}",
                    );
                    // Onto the pty's *slave* — that is the shell's stdout, so
                    // the line reaches the attached terminal ahead of the
                    // first prompt. Writing to the master would feed it to
                    // the shell as input instead. Best-effort: a session that
                    // comes up must not fail over a notice, and the log above
                    // has already recorded it. CRLF because this is a raw
                    // terminal write, not a line through the shell.
                    let written = pty.dup_slave_fd().and_then(|fd| {
                        use std::io::Write as _;
                        std::fs::File::from(fd).write_all(format!("minimal: {notice}\r\n").as_bytes())
                    });
                    if let Err(e) = written {
                        tracing::debug!(error = %e, "could not print the shell notice to the terminal");
                    }
                }
                let mut command = env
                    .command(&container, &shell.program, shell.args.iter().copied())
                    .map_err(|e| io::Error::other(format!("build command: {e}")))?;
                // Name the shell that is actually running. The composed
                // value is a path on the machine the loadout was authored on
                // (`/opt/homebrew/bin/fish`), which resolves to nothing
                // in-session, and on the fallback path it names a shell that
                // isn't the one at this prompt.
                command.env("SHELL", &shell.program);
                // The session default `PS1` is bash's, so a shell with its
                // own prompt grammar needs the equivalent in that grammar —
                // handed the bash one, zsh renders `\[\033[…\]\u@\h` as
                // literal text. Skipped when the composition set `PS1`: that
                // is the user's own prompt, in whatever syntax they meant.
                if let Some(prompt) = shell.prompt
                    && !composed_prompt
                {
                    command.env("PS1", prompt);
                }
                    command
                }
                // The argv runs in the same environment the shell gets.
                // `SHELL` and `PS1` stay as composed: no shell of the
                // daemon's choosing runs here for them to describe.
                LaunchEntrypoint::Argv { program, args } => {
                    let mut command = env
                        .command(&container, program, args.iter().map(String::as_str))
                        .map_err(|e| io::Error::other(format!("build command: {e}")))?;
                    // The task run's variables reach this process, and the
                    // processes it starts, and nothing else in the box.
                    for (key, value) in &entrypoint_vars {
                        command.env(key, value);
                    }
                    // `inherit_cwd`: the in-box `min task run` reads its
                    // `$PWD`, so the argv starts where the client ran.
                    if let Some(dir) = &start_dir {
                        command.current_dir(dir);
                        command.env("PWD", dir);
                    }
                    command
                }
            };
            // A box without a terminal runs its argv on three pipes, so
            // a task run relays its stdin, stdout and stderr (T43). The
            // host reads the stdout pipe where it reads a terminal's
            // master, and nothing holds the terminal opened above.
            let (master, tty_path, late_notice_fd, pipes) = if on_pipes {
                let child = ChildPipes::open()?;
                command.stdin(sandbox::Stdio::from(child.stdin));
                command.stdout(sandbox::Stdio::from(child.stdout));
                command.stderr(sandbox::Stdio::from(child.stderr));
                drop(pty);
                (
                    child.stdout_reader,
                    std::path::PathBuf::from("/dev/null"),
                    None,
                    Some(child.parent),
                )
            } else {
                command.stdin(sandbox::Stdio::from(pty.dup_slave_fd()?));
                command.stdout(sandbox::Stdio::from(pty.dup_slave_fd()?));
                let tty_path = pty.slave_path().to_path_buf();
                // Kept for one notice written after the switch attach below
                // (an own-address box the hostname proxy stranded), so it is
                // said in the terminal, not only in the daemon's log. Never
                // for a hook launch: its pty is read by nobody. Dropped
                // before the launch returns, so it never outlives the
                // shell's own slave fds.
                let late_notice_fd = (matches!(network_mode, NetworkMode::OwnIp) && !for_hooks)
                    .then(|| pty.dup_slave_fd().ok())
                    .flatten();
                let (master, slave) = pty.into_fds();
                command.stderr(sandbox::Stdio::from(slave));
                (master, tty_path, late_notice_fd, None)
            };

            let process = command
                .spawn()
                .map_err(|e| io::Error::other(format!("exec failed: {e}")))?;
            // `command`/`container` no longer borrow `env`, so it can be moved
            // into the host to keep its backing files alive.
            drop(container);
            Ok::<_, io::Error>((
                env,
                master,
                process,
                tty_path,
                late_notice_fd,
                start_gate,
                pipes,
            ))
        }
        .await;

        let (env, master, process, tty_path, late_notice_fd, start_gate, pipes) = build_and_spawn?;

        // From here the process exists, so every way out of this function
        // has to account for it — including the one no `return` covers, a
        // cancelled future. `SpawnedProcessGuard` owns it until the
        // handoff at the bottom; an `Err` return or a drop reaps it.
        let mut process = SpawnedProcessGuard::new(process);

        // Step 3 (post-spawn): hand the process to the provider, which wires its
        // namespace onto the switch; a tap the sandbox layer built travels here
        // inside `Spawned`.
        //
        // Until this returns, an own-IP PTask's egress isn't up yet, but a shell
        // PTask never probes the network in this window (the SSH layer dispatches
        // commands only after `Launched` is returned).
        let net_guard: Option<Box<dyn sandbox::NetGuard>> = {
            let spawned = sandbox::Spawned::from_child(process.get_mut());
            match planned.attach(spawned).await {
                // The guard owns the release now; it detaches at session end.
                Ok(guard) => Some(guard),
                // The release stays with `planned`, which drops on this return.
                Err(e) => return Err(io::Error::other(e)),
            }
        };

        // Step 4 (post-attach): gather the listen-publication plan (NET-016,
        // NET-017) — everything the box's listener watcher needs, from what
        // this launch alone holds: the box's lease on the switch, the gvproxy
        // control channel its forwarder verbs ride (built the way the
        // provider's own-IP plan builds it), the published address the
        // switch granted this session (NET-010), the ingress gate the
        // attach just registered for the relay, and the box's publication
        // set, shared with the runtime expose surface so neither binds a
        // port the other already holds. The plan rides [`Launched`] to the
        // host that runs the box, which starts the watcher when it builds
        // and stops it with the session — so a box with no lease, no
        // published address or no live gate carries no plan, and its ports
        // stay unpublishable by listening.
        //
        // Read here, after `planned.attach` above returned: a successful
        // attach has already reported this spawn's lease
        // (`complete_own_ip_attach` reports it before it returns `Ok`), and
        // every launch — a respawn included — runs this step afresh, so the
        // lease the plan carries is always this spawn's own.
        let lease = crate::net::provider::attached_lease(&plan, own_address.as_ref());
        let published = own_address
            .as_ref()
            .and_then(|reporter| reporter.published_address());
        let gate = lease.and_then(crate::net::switch::live_gate);
        // Design §7.1: a box that attached while the hostname proxy was not
        // serving past the settle was compiled with no node-address opening
        // (fail closed rather than at a port the proxy may not hold), so it
        // cannot reach the hostname proxy until it restarts. Said in the
        // session's own terminal — the person whose `HTTP(S)_PROXY` requests
        // will not route is told why and what clears it — beside the
        // daemon's warning. Best-effort, like the banner notices above.
        if let (Some(fd), Some(lease)) = (late_notice_fd, lease)
            && net_switch.lock().await.hostname_proxy_stranded(lease)
        {
            use std::io::Write as _;
            let written = std::fs::File::from(fd).write_all(
                b"minimal: the hostname proxy was not serving yet when this session's \
                  box attached, so the box cannot reach it (*.min.internal requests \
                  through HTTP(S)_PROXY will not route); restart the session once the \
                  daemon's hostname proxy serves\r\n",
            );
            if let Err(e) = written {
                tracing::debug!(
                    error = %e,
                    "could not print the hostname-proxy notice to the terminal"
                );
            }
        }
        if matches!(network_mode, NetworkMode::OwnIp)
            && (lease.is_none() || published.is_none() || gate.is_none())
        {
            // An own-address box whose listens will never publish: said once
            // per launch, naming the fact that is missing, so a listen that
            // never publishes is not silent (NET-016) — a warning where the
            // declaration allows listens to publish, since one it allows will
            // not.
            if listens_can_publish {
                tracing::warn!(
                    session = %session_label,
                    lease = ?lease,
                    published = ?published,
                    gate = gate.is_some(),
                    "the box carries no listen plan; its listens are not published"
                );
            } else {
                tracing::info!(
                    session = %session_label,
                    lease = ?lease,
                    published = ?published,
                    gate = gate.is_some(),
                    "the box carries no listen plan; its listens are not published"
                );
            }
        }
        let listen_plan = match (lease, published, gate) {
            (Some(lease), Some(published), Some(gate)) => {
                tracing::debug!(
                    session = %session_label,
                    %lease,
                    %published,
                    "built the box's listen plan"
                );
                let switch = net_switch.lock().await;
                let control = match switch.transport() {
                    crate::net::SwitchTransport::LocalSpawn => {
                        crate::net::policy::ControlChannel::Unix(switch.control_socket())
                    }
                    crate::net::SwitchTransport::HostShuttle { cid, port } => {
                        crate::net::policy::ControlChannel::Vsock { cid, port }
                    }
                };
                Some(crate::net::listeners::ListenPlan::new(
                    session_label,
                    lease,
                    published,
                    control,
                    gate,
                    self.publications,
                    self.state_dir,
                    own_address
                        .as_ref()
                        .map(crate::net::provider::OwnAddressReporter::registry),
                    session_id,
                ))
            }
            _ => None,
        };

        Ok(Launched {
            master,
            process: SandboxProcess::new(SandboxBackend {
                child: process.release(),
            }),
            guard: env,
            net_guard,
            tty_path,
            // The box's listen plan, and with it the one handoff to the
            // host that runs the box: taken when the host builds, so a
            // cancelled launch's plan never reaches any host at all.
            listen_plan,
            start_gate,
            pipes,
        })
    }
}

/// Whether the spec stored beside a box's record sets `io.pty_enabled`
/// (BOX-030). It reads only that key, so the PTY check of a resume runs
/// before the spec is parsed whole: a spec this daemon cannot start from is
/// a later refusal (BOX-025). Bytes that are not a JSON object read as no
/// PTY.
pub(crate) fn stored_spec_sets_pty(bytes: &[u8]) -> bool {
    serde_json_lenient::from_slice::<serde_json_lenient::Value>(bytes)
        .ok()
        .and_then(|spec| spec.get("io")?.get("pty_enabled")?.as_bool())
        .unwrap_or(false)
}

/// The spec stored beside a box's record at its creation (BOX-068), parsed
/// for a resume to restart the box from (BOX-025).
///
/// # Errors
///
/// `InvalidInput`, as a create gives for a spec it refuses, when the bytes
/// are not a spec of the version this daemon reads,
/// [`mfile::spec::BOX_SPEC_VERSION`].
pub(crate) fn stored_spec(bytes: &[u8]) -> io::Result<mfile::spec::BoxSpec> {
    let refused = |why: String| io::Error::new(io::ErrorKind::InvalidInput, why);
    let spec: mfile::spec::BoxSpec = serde_json_lenient::from_slice(bytes).map_err(|e| {
        refused(format!(
            "The settings it was created with cannot be read: {e}."
        ))
    })?;
    if spec.v != mfile::spec::BOX_SPEC_VERSION {
        return Err(refused(format!(
            "The settings it was created with are version {}, and this daemon reads only version {}.",
            spec.v,
            mfile::spec::BOX_SPEC_VERSION
        )));
    }
    Ok(spec)
}

/// Restarts `record` from `spec` (BOX-025): the network mode, the policy
/// and the hooks switch the box was created with. A change made to them
/// while the box ran does not carry into the restart. Every launch reads
/// these settings from the record, so the restart writes them there.
pub(crate) fn restart_from_stored_spec(record: &mut boxes::Record, spec: &mfile::spec::BoxSpec) {
    record.network = spec.network.mode;
    record.policy = spec.network.policy.clone();
    record.hooks_enabled = spec.hooks_enabled;
}
