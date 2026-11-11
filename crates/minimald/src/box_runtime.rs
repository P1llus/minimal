//! The running state of an active session.
//!
//! The [`Pty`] struct owns a master/slave pseudo-terminal pair created via
//! `openpty(3)`, exposing its file descriptors and window-size controls.
//!
//! The [`Host`] struct holds the running state of an active session.

use async_dialog::Selection;
use russh::Channel;
use russh::server::Msg;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::error::{SendError, SendTimeoutError};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::RequestedPty;
use crate::box_actor::BoxPaths;
use crate::box_manager::BoxControl;
use crate::workspace_delta::DeltaSource;
use boxes::NetworkMode;
use boxes::keys::{ChordMatcher, FeedOutcome, KeyAction, SessionKeys};
use std::sync::Arc;

mod pty;

pub use pty::*;

mod backend;
mod binding;
mod handle;
mod hooks;
mod launcher;
#[cfg(test)]
mod mock;
mod pipes;
mod processes;

pub(crate) use backend::*;
pub(crate) use binding::*;
pub use handle::*;
use hooks::*;
pub(crate) use launcher::*;
#[cfg(test)]
pub(crate) use mock::*;
pub(crate) use pipes::EntrypointIoTake;
use pipes::{HostPipes, PIPE_EXIT_POLL, PipeStream, read_ready};
pub(crate) use processes::*;

/// What a host loop returns when it ends: the portable exit code, and the
/// reaped [`ExitReason`] when the backend accounted for the end.
#[derive(Debug, Clone)]
pub(crate) struct HostExit {
    /// The portable exit code, as [`BoxProcess::try_wait`] reports it.
    pub(crate) code: i32,
    /// How the process ended. `None` when the backend gave no account.
    pub(crate) reason: Option<ExitReason>,
    /// Whether a kill from the daemon ended the host. `false` when the
    /// entrypoint returned, or ended, with no kill asked for: only that end
    /// ends the box (BOX-038).
    pub(crate) requested: bool,
}

/// The state of the session process.
///
/// Generic over the [`BoxProcess`] it supervises and the [`BoxLauncher`]
/// guard kept alive for the session, so the runtime loop can be driven against a
/// real sandboxed process or a test double.
pub(crate) struct Host<P: BoxProcess, G: BoxGuard> {
    /// Channel for actor messages via [`HostHandle`].
    receiver: mpsc::Receiver<Message>,

    /// The async task and its channel that wires the session
    /// to the ssh channel, if currently attached.
    remote: Option<BindingSlot>,

    /// See [`OUTPUT_STALL_TIMEOUT`]; a field only so a test can shorten it.
    output_stall_timeout: std::time::Duration,
    /// When the attached binding, whose mailbox is full, gets shed. Armed when
    /// the host first finds the mailbox full, and cleared as soon as a slot
    /// frees up.
    output_stall_deadline: Option<tokio::time::Instant>,

    /// The last-set pty terminal size.
    sz: WinSize,
    /// In-memory representation of the terminal state.
    parser: vt100::Parser<ParserEventHandler>,
    /// The session process.
    process: P,
    /// The pty-master failure that unwound the host, held from the moment
    /// [`Host::step`] hit it until [`Host::mainloop`] has reaped the process.
    ///
    /// The binding cannot be told why it is going away until both are known —
    /// the error says how the host noticed, the reap says what became of the
    /// shell — and the reap is the slower of the two. Set only by a pty
    /// failure, never by a deliberate kill, which is what keeps a destroy from
    /// raising a shell-exit prompt.
    pending_pty_err: Option<std::io::Error>,
    /// Set when [`Host::step`] takes a `Message::Kill`. The step-error branch
    /// of [`Host::mainloop`] reads it to tell a requested end from a pty
    /// failure. A pty error stashed before the kill does not hide the kill.
    kill_requested: bool,
    /// The master-side fd of the Pty. On a host whose entrypoint runs on
    /// pipes, the read end of its stdout pipe (see [`Self::pipes`]).
    master: AsyncFd<std::fs::File>,
    /// The entrypoint's stdin and stderr pipes, on a host whose launch ran
    /// its entrypoint on pipes, not on a terminal (T43). `None` otherwise.
    pipes: Option<HostPipes>,
    /// The box's output log (BOX-155). Every read from the master lands
    /// here first, whether or not a binding is attached, so the attached
    /// client is a second reader and the log is complete after it leaves.
    output_log: BoxOutputLog,
    /// The box's directory beside its mounts, handed to each binding so it
    /// can record `detached` when its client leaves (BOX-016). `None` for a
    /// host whose workspace is not in the box store (tests).
    box_dir: Option<boxes::store::BoxDir>,
    /// Various attributes about the running terminal.
    attrs: HostAttrs,

    // Writer for bytes coming from the remote - i.e. 'stdin' keystrokes
    // that need to get written to the pty. Clones of this sender are
    // given to [`Binding::spawn`].
    remote_tx: mpsc::Sender<StdinMsg>,
    // Recieve-end for bytes coming from the remote - i.e. 'stdin' keystrokes.
    // We process this end.
    remote_rx: mpsc::Receiver<StdinMsg>,

    // Monotonic identity of the currently active binding. Bumped by
    // `attach()` before the new binding is spawned, so an [`StdinMsg`] whose
    // generation lags this was queued by a superseded binding and gets
    // discarded rather than interpreted under the new channel's session keys.
    binding_generation: u64,

    // Temporary buffer for reading from the pty master (i.e. 'stdout').
    stdout_buf: Vec<u8>,
    // Bytes that need to be written to the pty master (i.e. 'stdin').
    //
    // (<buffer>, <number of bytes from buffer already written>)
    stdin_buf: Option<(bytes::Bytes, usize)>,

    // The per-sandbox network attachment (own-IP switch wiring), if any. Torn
    // down explicitly in `mainloop` when the session ends, before `_guard` (and
    // thus the sandbox files) is dropped. `None` for `HostNet`/`NoNet` and
    // net-guard-less tests.
    net_guard: Option<Box<dyn sandbox::NetGuard>>,

    /// The box's listen-publication watcher (NET-016, NET-017): publishes
    /// the ports its processes listen on when the box's ingress rules
    /// permit them, and withdraws each one whose listener closed. Started
    /// in `build` from the plan the launch staged, stopped in `mainloop`
    /// before the network attachment tears down — so every
    /// runtime-published forward is gone before the switch's tap does.
    /// `None` for boxes with nothing to publish on (tests, `HostNet`/`NoNet`,
    /// and any launch that staged no plan).
    listen_watcher: Option<crate::net::listeners::ListenWatcher>,

    /// The session's hostname-registry marker (NET-128): marked running when
    /// this host's `mainloop` starts and stopped when it returns, so a name
    /// the box shares with its node answers NODATA while no host is running.
    /// `None` for hosts built without one (tests, and a task's host).
    #[cfg(target_os = "linux")]
    name_marker: Option<NameMarker>,

    /// Path of the session PTY's slave side. Attach and detach hooks
    /// open it briefly so their stdout is a real terminal; the host
    /// never holds a descriptor on it, because one open slave fd stops
    /// the master from ever seeing EOF.
    tty_path: std::path::PathBuf,
    /// The composed hooks, so the attach and detach transitions can run
    /// them. `None` for a host spawned without one (tests, and a
    /// restart-orphaned actor).
    composition: Option<Arc<boxes::core::compose::Composition>>,
    /// Identity and paths a hook run needs.
    session_id: boxes::SessionId,
    hooks_dir: paths::DaemonAbsPath,
    workspace_dir: paths::DaemonAbsPath,

    // Destroy capability handed to each binding this host spawns, so a
    // shell-exit "delete" can tear the whole session down. `None` for hosts
    // built without a manager (the test harness).
    control: Option<BoxControl>,

    // Workspace baseline taken before the process launched, handed to each
    // binding so the shell-exit prompt can list the files changed during the
    // session. `None` when the workspace could not be walked at build time;
    // the prompt then renders without a delta.
    delta: Option<Arc<DeltaSource>>,

    // The session's workspace root, kept for the at-risk assessment
    // (`Message::GetAtRisk`): the VCS mode needs the tree path even when
    // the baseline snapshot could not be armed.
    workspace_root: std::path::PathBuf,

    /// The launch's start gate, held until the first attach; see
    /// [`Launched::start_gate`] and [`Self::attach`].
    start_gate: Option<sandbox::StartGate>,

    // The session's display name, handed to each binding so the shell-exit
    // prompt's save-then-delete lane can name its archive.
    session_name: String,

    /// The attached terminal's facts as of the latest attach, layered over the
    /// session's own environment for everything this host runs in the sandbox
    /// (`command_in_session`) and republished into the session's home so the
    /// already-running shell can pick them up at its next prompt.
    connection_env: ConnectionEnv,

    /// Daemon-side path of the session's home directory — the same directory
    /// the sandbox mounts at [`SESSION_HOME_ROOT`]. Held so the per-attach
    /// environment files can be written without entering the sandbox.
    home_dir: paths::DaemonAbsPath,

    // Daemon-side directory the save-then-delete lane archives into, handed
    // to each binding alongside `delta`.
    archives_dir: std::path::PathBuf,

    // Whether the box is registered (see [`HostParams::holds_host_row`]),
    // handed to each binding for its shell-exit prompt.
    holds_host_row: bool,

    // Whether the box ends when its entrypoint returns (see
    // [`HostParams::ends_with_entrypoint`]), handed to each binding so a
    // shell exit there raises no prompt.
    ends_with_entrypoint: bool,

    // The per-channel session-key chord matcher: the negotiated leader chord
    // that enters command mode, the detach/forward subcommand keys, the bell
    // flag, plus the command-mode state and the pending split-candidate
    // buffer. Refreshed from the channel's env vars on every attach (so two
    // clients with different configs on the same session each get their own
    // chord, and a reattach never inherits a stale awaiting-subcommand state
    // or half a split candidate); defaults to `ctrl-]` / `d` when a client
    // sends no keys.
    chord_matcher: ChordMatcher,

    // Deadline for flushing a held chord-matcher split candidate: armed when a
    // stdin chunk leaves the matcher holding a partial form (e.g. a lone `ESC`,
    // a prefix of every kitty form), cleared when the next chunk resolves it or
    // the idle gap elapses and the candidate is flushed to the PTY as data.
    chord_flush_deadline: Option<tokio::time::Instant>,

    // Keeps launcher-owned resources (the session's `Env`, which owns the
    // sandbox files backing the running process's rootfs along with the context
    // and graph) alive for as long as this host (and thus the session process)
    // lives. Declared last so it is dropped after `process`: the process is torn
    // down before the sandbox files backing its rootfs are removed. Also read,
    // via `BoxGuard`, for the session's current environment.
    guard: G,
}

/// The non-launcher inputs to [`Host::spawn`] and [`Host::build`].
///
/// Both entry points take the same set, and `spawn` forwards them verbatim to
/// `build`, so the parameters travel as one named bundle rather than a long
/// positional pass-through. `launcher` stays a separate generic argument.
pub(crate) struct HostParams {
    pub name: String,
    pub username: String,
    pub paths: BoxPaths,
    pub sz: WinSize,
    pub channel: Option<Channel<Msg>>,
    pub control: Option<BoxControl>,
    pub delta: Option<Arc<DeltaSource>>,
    pub archives_dir: std::path::PathBuf,
    /// Whether the session's record carries host-handed addresses (T66): the
    /// box is registered, so its host-side row ends with this host's shell
    /// (NET-138). The shell-exit prompt words its Keep item for that.
    pub holds_host_row: bool,
    /// Whether the box ends when its entrypoint returns: its spec sets
    /// `lifetime = "until_complete"` (BOX-038). The daemon ends such a box
    /// whether or not a client is attached, so a shell exit raises no
    /// shell-exit prompt. A box that runs until it is stopped keeps the
    /// prompt, because the box outlives its shell.
    pub ends_with_entrypoint: bool,
    pub session_id: boxes::SessionId,
    pub composition: Option<Arc<boxes::core::compose::Composition>>,
    pub connection_env: ConnectionEnv,
    /// The session's hostname-registry marker (NET-128): the host marks the
    /// box's name running when it takes over and stopped when it exits, so a
    /// name the box shares with its node answers NODATA while a dead box's
    /// listeners would otherwise be spoken for by the node's own. `None` for
    /// a host this daemon gave no name route to.
    #[cfg(target_os = "linux")]
    pub name_marker: Option<NameMarker>,
}

/// The sealed values a host launch of the box places in its environment
/// (BEP-007): the ones its record holds, which the create copied from the
/// request. [`place_launch_deliveries`] places them.
pub(crate) fn launch_deliveries(record: &boxes::Record) -> Vec<boxes::SealedDelivery> {
    record.sealed_deliveries.clone()
}

/// Opens the one `box.launch` span of a launch and logs the launch at info
/// level inside it. Both name the entrypoint by [`LaunchEntrypoint::log_name`]
/// and its argument count, never by its arguments: an argument can carry a
/// secret, and the daemon log keeps no secret.
pub(crate) fn launch_span(
    session_id: boxes::SessionId,
    session_name: &str,
    entrypoint: &LaunchEntrypoint,
) -> tracing::Span {
    let span = tracing::info_span!(
        "box.launch",
        session_id = %session_id,
        session = %session_name,
        entrypoint = entrypoint.log_name(),
        args = entrypoint.arg_count(),
    );
    tracing::info!(
        parent: &span,
        entrypoint = entrypoint.log_name(),
        args = entrypoint.arg_count(),
        "launching the box's entrypoint from its spec"
    );
    span
}

/// Places the grants' sealed values in a launch's connection layer
/// (BEP-007), before the launcher builds the shell from `attach_env`, so the
/// values exist before the shell's entrypoint runs. Returns the placed
/// connection layer for the host to keep, layer onto what it runs in the box
/// and republish for the shell to re-read. Logs once per variable, through
/// [`place_sealed_deliveries`].
pub(crate) fn place_launch_deliveries(
    attach_env: &mut AttachEnv,
    session_id: boxes::SessionId,
    deliveries: &[boxes::SealedDelivery],
) -> ConnectionEnv {
    let mut connection_env = attach_env.connection_env();
    place_sealed_deliveries(&mut connection_env, session_id, deliveries);
    attach_env.connection = connection_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    connection_env
}

/// Places each grant's sealed value in the grant's environment variable
/// (BEP-007), over any value `env` held there, so the variable holds the
/// sealed value and nothing else. The daemon never holds a plaintext token:
/// a sealed value is all a create request carries. Logs one debug line per
/// variable, naming the box and the variable, never the value.
pub(crate) fn place_sealed_deliveries(
    env: &mut ConnectionEnv,
    session_id: boxes::SessionId,
    deliveries: &[boxes::SealedDelivery],
) {
    for delivery in deliveries {
        // The create refuses such a name. A record that holds one anyway
        // places nothing, because the name is written unquoted into the
        // file the box's shell sources.
        if boxes::core::primitives::StrictVarName::try_new(delivery.variable.as_str()).is_err() {
            tracing::warn!(
                session_id = %session_id,
                variable = ?delivery.variable,
                "skipped a grant's sealed value: its name is not a variable name"
            );
            continue;
        }
        env.insert(delivery.variable.clone(), delivery.sealed.clone());
        tracing::debug!(
            session_id = %session_id,
            variable = %delivery.variable,
            "placed a grant's sealed value in the box environment"
        );
    }
}

/// Where a box with the proxy's root (BEP-011) finds its CA bundle: the
/// box's own copy of the system roots with the root appended. The bundle a
/// package ships can be the package store's own file, so the launch writes
/// a new file here and never writes into the one it replaces.
pub(crate) const BOX_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// The hashed certificate directory the root is linked in under its
/// subject hash (BEP-011), beside the system roots.
pub(crate) const BOX_CA_DIR: &str = "/etc/ssl/certs";

/// Where a box with the proxy's root (BEP-011) finds the root alone, for
/// `NODE_EXTRA_CA_CERTS` and as the target of its hashed-directory link.
pub(crate) const BOX_ROOT_CERTIFICATE: &str = "/etc/ssl/certs/minimal-box-egress-proxy-root.pem";

/// The root certificate a host launch of the box adds to the box's trust
/// store (BEP-011): the one its record holds, when the box declares a
/// credentialed upstream and its steering is not `off`. `None` for every
/// other box, so a box with no grant gets no root, whichever packages it
/// shares with a box that has one.
pub(crate) fn launch_root_certificate(record: &boxes::Record) -> Option<String> {
    use boxes::core::bep::Steering;
    let upstream = record.policy.credentialed_upstream.as_ref()?;
    if upstream.bep.resolved_steering() == Steering::Off {
        return None;
    }
    record.root_certificate.clone()
}

/// The trust variables a launch sets for a box whose trust store has the
/// root (BEP-011): `NODE_EXTRA_CA_CERTS` at the root, and, when the box has
/// its own CA bundle, `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` at it. A box
/// whose packages ship no bundle gets no bundle, so those two stay unset and
/// a tool that reads them keeps its own public roots. Empty when the root is
/// not injected.
pub(crate) fn launch_trust_env(root_injected: bool, bundle: bool) -> Vec<(String, String)> {
    if !root_injected {
        return Vec::new();
    }
    let mut vars = Vec::new();
    if bundle {
        vars.push(("SSL_CERT_FILE".to_string(), BOX_CA_BUNDLE.to_string()));
        vars.push(("REQUESTS_CA_BUNDLE".to_string(), BOX_CA_BUNDLE.to_string()));
    }
    vars.push((
        "NODE_EXTRA_CA_CERTS".to_string(),
        BOX_ROOT_CERTIFICATE.to_string(),
    ));
    vars
}

/// Adds the [`launch_trust_env`] variables to `vars`, the box's composed
/// environment, below every variable it already holds: a box spec that
/// sets one of them keeps its own value.
pub(crate) fn layer_trust_env(
    vars: &mut std::collections::BTreeMap<String, String>,
    root_injected: bool,
    bundle: bool,
) {
    for (name, value) in launch_trust_env(root_injected, bundle) {
        vars.entry(name).or_insert(value);
    }
}

/// The `NO_PROXY` entries every box whose environment points at the proxy
/// carries (BEP-012), ahead of the box's own `[network.bep] no_proxy`
/// entries: the local zone and loopback, so in-box and peer traffic never
/// goes through the proxy.
const NO_PROXY_DEFAULTS: [&str; 4] = [
    ".min.internal",
    "host.min.internal",
    "localhost",
    "127.0.0.1",
];

/// The proxy variables a launch of the box sets (BEP-012), in a fixed order:
/// `HTTPS_PROXY` and `HTTP_PROXY` at the Box Egress Proxy's listener on
/// `subnet`, `NO_PROXY`, and `NODE_USE_ENV_PROXY=1`, which Node's built-in
/// `fetch` needs before it reads the other three.
///
/// Empty unless the box's steering is `proxy_env` or `both`, or its
/// `[network.bep] proxy_env` is true. Also empty when the box declares no
/// credentialed upstream, or its network mode on a host of kind `host` puts
/// the lane out of effect (BEP-085): such a box cannot reach the proxy's
/// address, so the variables would send all of its HTTP traffic to an
/// address that drops it. A `host_ip` box on a VM host gets them.
pub(crate) fn launch_proxy_env(
    record: &boxes::Record,
    subnet: switch::SwitchSubnet,
    host: paths::HostKind,
) -> Vec<(String, String)> {
    use boxes::core::bep::Steering;
    let Some(upstream) = record.policy.credentialed_upstream.as_ref() else {
        return Vec::new();
    };
    let bep = &upstream.bep;
    let steered =
        matches!(bep.resolved_steering(), Steering::ProxyEnv | Steering::Both) || bep.proxy_env;
    if !steered || !boxes::CredentialedUpstream::in_effect(record.network, host) {
        return Vec::new();
    }
    let proxy = format!(
        "http://{}:{}",
        subnet.box_egress_proxy_address(),
        boxes::core::egress::PROXY_LISTENER_PORT
    );
    let no_proxy = NO_PROXY_DEFAULTS
        .iter()
        .map(|entry| (*entry).to_string())
        .chain(bep.no_proxy.iter().cloned())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        ("HTTPS_PROXY".to_string(), proxy.clone()),
        ("HTTP_PROXY".to_string(), proxy),
        ("NO_PROXY".to_string(), no_proxy),
        ("NODE_USE_ENV_PROXY".to_string(), "1".to_string()),
    ]
}

/// Places the proxy variables (BEP-012) in a launch's connection layer, over
/// any value the layer held there, so the shell's launch environment and
/// everything the host runs in the box carry them. Call it before
/// [`place_launch_deliveries`], which keeps the layer it reads.
///
/// Logs one debug line for a box that declares a credentialed upstream. The
/// line names the variables set, the box's network mode, the host kind and
/// whether the lane is in effect, so a box that got no variables shows why.
pub(crate) fn place_launch_proxy_env(
    attach_env: &mut AttachEnv,
    record: &boxes::Record,
    host: paths::HostKind,
    vars: &[(String, String)],
) {
    for (name, value) in vars {
        attach_env.connection.retain(|(k, _)| k != name);
        attach_env.connection.push((name.clone(), value.clone()));
    }
    if record.policy.credentialed_upstream.is_none() {
        return;
    }
    let names: Vec<&str> = vars.iter().map(|(name, _)| name.as_str()).collect();
    tracing::debug!(
        session_id = %record.id,
        network = record.network.word(),
        host_kind = host.tag(),
        lane_in_effect = boxes::CredentialedUpstream::in_effect(record.network, host),
        variables = %names.join(","),
        "proxy variables for the box environment"
    );
}

/// The host kind a launch reads from this daemon's switch transport: a
/// switch reached over the VM's host shuttle means this daemon runs inside
/// a VM, and every other transport is a native host.
pub(crate) fn host_kind_of(transport: crate::net::SwitchTransport) -> paths::HostKind {
    match transport {
        crate::net::SwitchTransport::HostShuttle { .. } => paths::HostKind::Minvmd,
        crate::net::SwitchTransport::LocalSpawn => paths::HostKind::Minimald,
    }
}

/// The host's half of the name lifecycle (NET-128): the registry and the
/// stable session id, so the host can mark its box's name running when it
/// starts and stopped when it exits. Held by [`HostParams`] and copied into
/// the [`Host`], because the mark belongs to the *host's* lifetime, not the
/// session's — a session whose host has exited keeps its name *held* (never
/// NXDOMAIN, so the box's name is not negatively cached), answering NODATA
/// at a shared address until a host runs again.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) struct NameMarker {
    /// The daemon's registry the marks land in.
    registry: std::sync::Arc<std::sync::RwLock<crate::net::dns::HostnameRegistry>>,
    /// The stable id of the session whose box's name is marked.
    session_id: boxes::SessionId,
    /// The host launch this marker's host belongs to
    /// ([`crate::net::dns::HostnameRegistry::begin_host_launch`]). The stop
    /// mark carries it, so a replaced host cannot mark a newer host's box
    /// stopped (NET-070).
    launch: u64,
}

#[cfg(target_os = "linux")]
impl NameMarker {
    /// Marks one session's box name, in one registry, for one host launch.
    pub(crate) fn new(
        registry: std::sync::Arc<std::sync::RwLock<crate::net::dns::HostnameRegistry>>,
        session_id: boxes::SessionId,
        launch: u64,
    ) -> Self {
        Self {
            registry,
            session_id,
            launch,
        }
    }

    /// The box's host is running: its name answers at its address (NET-128) —
    /// the state every box is in from finalize (NET-011), so a mark that finds
    /// nothing stopped changes nothing.
    pub(crate) fn mark_running(&self) {
        self.registry
            .write()
            .expect("hostname registry lock poisoned")
            .mark_running(self.session_id);
    }

    /// The box's host has exited (NET-128): its name stays held — a stopped
    /// box is never mistaken for one that never existed — but a name it
    /// shares with the node answers NODATA until a host runs again, so the
    /// node's own listener at that port is not spoken for by a dead box.
    /// A host that a newer launch replaced changes nothing here.
    pub(crate) fn mark_stopped(&self) {
        self.registry
            .write()
            .expect("hostname registry lock poisoned")
            .mark_host_stopped(self.session_id, self.launch);
    }
}

impl<P: BoxProcess, G: BoxGuard> Host<P, G> {
    /// Builds a command that runs `program` inside this session's box, with
    /// the session's variables, then the attached terminal's facts, then
    /// `extra_env`. The terminal's facts sit above the session's own for the
    /// same reason they do at launch: `TERM` describes the terminal, and the
    /// session's copy of it is only as fresh as the attach that started the
    /// shell.
    pub(crate) fn command_in_session<I, S>(
        &self,
        program: &str,
        args: I,
        extra_env: std::collections::BTreeMap<String, String>,
    ) -> crate::box_command::BoxCommand
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let environment = self.guard.command_environment();
        let mut vars = environment.vars;
        vars.extend(self.connection_env.clone());
        vars.extend(extra_env);
        self.process
            .entrance()
            .command(program, args, vars, &environment.cwd)
    }

    /// Snapshot what a hook run needs, or `None` when there is nothing
    /// to run or nothing to run it in.
    fn hook_plan(&self, event: crate::hooks::HookEvent) -> Option<HookPlan> {
        let composition = self.composition.clone()?;
        if !self.process.has_init() {
            tracing::debug!(
                event = event.as_str(),
                "the box has no first process; skipping lifecycle hooks",
            );
            return None;
        }
        let environment = self.guard.command_environment();
        Some(HookPlan {
            event,
            commands: crate::hooks::InjectedCommands {
                entrance: self.process.entrance(),
                cwd: environment.cwd,
                vars: environment.vars,
            },
            composition,
            session_id: self.session_id,
            session_name: self.session_name.clone(),
            hooks_dir: self.hooks_dir.clone(),
            workspace: self.workspace_dir.clone(),
            output: crate::hooks::HookOutput::Tty(self.tty_path.clone()),
        })
    }

    /// Snapshot a plan and run it, if there is anything to run.
    async fn run_hooks_for(&mut self, event: crate::hooks::HookEvent) {
        if let Some(plan) = self.hook_plan(event) {
            run_hook_plan(plan).await;
        }
    }

    /// Spawns a session host from the given launcher, wiring it to `channel` if
    /// one is supplied, and drives its runtime loop on a background task.
    ///
    /// Returns the [`HostHandle`] alongside the [`JoinHandle`] of the runtime
    /// loop, so the owner can await full teardown (process reaped, sandbox guard
    /// dropped) after issuing a [`HostHandle::kill`].
    pub async fn spawn<L>(
        launcher: L,
        params: HostParams,
    ) -> Result<(HostHandle, JoinHandle<Result<HostExit, std::io::Error>>), std::io::Error>
    where
        L: BoxLauncher<Process = P, Guard = G>,
    {
        let (host, handle) = Self::build(launcher, params).await?;
        // The host loop outlives the exec or attach that launched it: its own
        // root, linked to that request. Without it, `session host killed on
        // request` minutes later still named the first exec's command.
        let root = tracing::info_span!(
            parent: None,
            "session.host",
            session_id = %host.session_id,
            session = %host.session_name,
        );
        let task = crate::traced::spawn_detached(root, host.run());
        Ok((handle, task))
    }

    /// Builds the host and its handle from a launcher without spawning the
    /// runtime loop, so callers (notably tests) can drive [`Self::step`]
    /// directly and observe the host's state.
    async fn build<L>(launcher: L, params: HostParams) -> Result<(Self, HostHandle), std::io::Error>
    where
        L: BoxLauncher<Process = P, Guard = G>,
    {
        let HostParams {
            name,
            username,
            paths,
            sz,
            channel,
            control,
            delta,
            archives_dir,
            holds_host_row,
            ends_with_entrypoint,
            session_id,
            composition,
            connection_env,
            #[cfg(target_os = "linux")]
            name_marker,
        } = params;
        // The change-detection baseline (`delta`) is armed once per session and
        // handed in, so a host rebuilt on reattach keeps the activation-time
        // reference point rather than re-snapshotting an already-modified
        // workspace. The root is still kept for the at-risk assessment, whose
        // VCS mode needs the tree path even when no baseline could be armed.
        let workspace_root = paths.working.as_utf8_path().as_std_path().to_path_buf();
        // Kept before `launch` consumes `paths`.
        let hooks_dir = paths.hooks.clone();
        let workspace_dir = paths.working.clone();
        // Opened before the launch, so the first byte the entrypoint writes
        // has a log to land in (BOX-155). A box in the store whose log
        // cannot be opened does not start: its log would not be complete.
        let output_log = BoxOutputLog::open(session_id, &paths)?;
        let box_dir = boxes::store::BoxDir::for_tree(&paths.working);
        // Kept for `write_connection_env`, which rewrites the per-attach env
        // (TERM included) into the session's home on every reattach.
        let home_dir = paths.home.clone();

        // The launcher consumes `name`; the bindings need it too, to name the
        // archives the shell-exit prompt's save-then-delete lane writes.
        let session_name = name.clone();
        // One span per launch, naming the entrypoint the launcher read from
        // the box's spec, so the daemon log says what each launch started.
        let entrypoint = launcher.entrypoint()?;
        let launch_span = launch_span(session_id, &session_name, &entrypoint);
        let Launched {
            master,
            process,
            guard,
            net_guard,
            tty_path,
            listen_plan,
            start_gate,
            pipes,
        } = tracing::Instrument::instrument(
            launcher.launch(session_id, name, username, paths, sz),
            launch_span,
        )
        .await?;

        // The listen-publication watcher (NET-016, NET-017): the plan this
        // launch gathered is the box's whole publication surface — its
        // lease, the switch's published address, the gvproxy control
        // channel, the ingress gate the attach registered, and the
        // publication set it shares with the runtime expose path. It polls
        // the listening sockets of the process the launch names the box's
        // leader (whose `/proc` entry reads the whole box's network
        // namespace) and keeps the box's published ports in step with them
        // until the session ends. A launch that carried no plan — no
        // lease, no published address — starts no watcher, and none of its
        // ports is published by listening.
        //
        // The leader itself is the watcher's to resolve, not this build's to
        // have resolved: a resolution that fails here — a shell that is
        // mid-spawn, a `/proc` that cannot answer for the moment — would
        // otherwise drop the plan with it and silently cost the box its
        // whole listen-published surface, so the build hands the container
        // PID it holds and the watcher asks on every poll until the box's
        // program is there to be found (the module's nothing-is-one-shot
        // contract, held of its start).
        // The engine records the box's listening sockets. A box nothing
        // judges has no such record, and publishes none by listening.
        let listen_watcher = listen_plan.and_then(|plan| {
            let source = plan.listeners()?;
            Some(crate::net::listeners::ListenWatcher::start(plan, source))
        });

        let (sender, receiver) = mpsc::channel(HOST_MAILBOX_CAPACITY);
        let handle = HostHandle { sender };

        let parser = vt100::Parser::new_with_callbacks(
            sz.rows,
            sz.cols,
            0,
            ParserEventHandler(handle.make_weak()),
        );

        let (remote_tx, remote_rx) = mpsc::channel(4);
        let master = {
            set_nonblocking(master.as_raw_fd())?;
            let file = unsafe { std::fs::File::from_raw_fd(master.into_raw_fd()) };
            // SAFETY: the `AsyncFd` owns `file` for its whole life, and nothing
            // reaches the `File` through it to close or replace its fd, so the
            // fd stays open and names the same PTY master until it is dropped.
            unsafe { AsyncFd::register(file) }?
        };
        let pipes = pipes.map(HostPipes::new).transpose()?;

        let mut host = Host {
            receiver,
            remote: None,
            output_stall_timeout: OUTPUT_STALL_TIMEOUT,
            output_stall_deadline: None,
            sz,
            parser,
            process,
            pending_pty_err: None,
            kill_requested: false,
            master,
            pipes,
            output_log,
            box_dir,
            attrs: HostAttrs {
                ..HostAttrs::default()
            },

            remote_tx,
            remote_rx,
            binding_generation: 0,
            stdout_buf: vec![0u8; 8 * 1024],
            stdin_buf: None,
            net_guard,
            listen_watcher,
            #[cfg(target_os = "linux")]
            name_marker,
            tty_path,
            composition,
            session_id,
            hooks_dir,
            workspace_dir,
            control,
            delta,
            workspace_root,
            session_name,
            archives_dir,
            holds_host_row,
            ends_with_entrypoint,
            connection_env,
            home_dir,
            start_gate,
            chord_matcher: ChordMatcher::new(SessionKeys::default()),
            chord_flush_deadline: None,
            guard,
        };

        if let Some(channel) = channel {
            // The launch already folded these facts into the shell's
            // environment, so pass an empty map rather than re-applying them:
            // `attach` treats empty as "nothing new to say" and publishes what
            // the host already holds.
            host.attach(
                channel,
                sz,
                true,
                ConnectionEnv::new(),
                SessionKeys::default(),
            )
            .await;
        } else {
            // No client to bind, so nothing calls `attach` — publish anyway,
            // so a host minted headlessly still has the files in place before
            // anything in the session looks for them.
            host.publish_connection_env().await;
        }

        Ok((host, handle))
    }

    /// Runs [`Self::run`] and returns only the exit code.
    #[cfg(test)]
    pub async fn mainloop(self) -> Result<i32, std::io::Error> {
        self.run().await.map(|exit| exit.code)
    }

    /// Runs the host loop until the process ends, and returns the reaped
    /// [`ExitReason`] beside the exit code. Only the reason can tell an
    /// entrypoint that exited 125 from a container that a signal ended,
    /// because `hakoniwa` reports 125 for both.
    pub(crate) async fn run(mut self) -> Result<HostExit, std::io::Error> {
        // The box's host is running from here: its name answers at its
        // address (NET-128) — the state it was in from finalize (NET-011), so
        // this mark only speaks where a previous host's exit had stopped it.
        #[cfg(target_os = "linux")]
        if let Some(marker) = &self.name_marker {
            marker.mark_running();
        }
        let result = loop {
            match self.process.try_wait() {
                Ok(Some(exit_code)) => {
                    // This is the host's own account, at info because it is the
                    // moment a live session stops being one. `try_wait` logged
                    // the same hakoniwa reason already, but from the process
                    // handle, which has no span and so names no session —
                    // repeat it here, where it is attributable, for the same
                    // reason the pty/step path does.
                    let exit = self.process.exit_reason();
                    // A kill from the daemon can lose the race to this reap:
                    // it is queued, but the process is reaped here before
                    // `step` takes it. The daemon asked for the end, so the
                    // entrypoint's own return does not end the box (BOX-038).
                    let requested = self.kill_queued();
                    tracing::info!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        exit_code,
                        requested,
                        abnormal = exit.as_ref().is_some_and(ExitReason::is_abnormal),
                        exit_reason = exit.as_ref().map_or("", |r| r.reason.as_str()),
                        "session process exited; reaped by the host loop",
                    );
                    // The process was reaped here before the pty surfaced its
                    // death as an `EIO`. Still notify the attached binding, so
                    // it tells the client the box ended rather than reporting
                    // a lost host. The box itself ends from the daemon, with
                    // or without a client (BOX-038): the actor reads this
                    // loop's `HostExit`.
                    //
                    // The race is structurally one-sided: `step` parks in a
                    // `select!` on the master read, and a dying process closes
                    // every slave fd, so the `EIO` normally lands before this
                    // poll comes round again — which makes this the safety net
                    // rather than the common path.
                    self.notify_remote_teardown(TeardownCause {
                        pty_err: None,
                        exit: exit.clone(),
                    });
                    break Ok(HostExit {
                        code: exit_code,
                        reason: exit,
                        requested,
                    });
                }
                Ok(None) => {}
                // Previously silent: a `wait` that fails ends the session
                // exactly like an exit does, and left no trace at all.
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        errno = ?e.raw_os_error(),
                        error = %e,
                        "could not wait on the session process; ending the host",
                    );
                    break Err(e);
                }
            }

            if self.step().await.is_err() {
                // Everything here is gated on a stashed pty error, so a
                // deliberate kill stays silent: `Message::Kill` also returns
                // `Err` from `step`, but a destroy or a daemon shutdown either
                // wants no farewell at all or has already sent its own teardown.
                let mut pending = self.pending_pty_err.take();
                // Read from the kill itself, not from `pending`: a kill can
                // arrive after a pty error was stashed, and that end is still
                // the daemon's, not the entrypoint's own return (BOX-038).
                let requested = self.kill_requested;

                // Notify *before* the reap when the process may still be
                // running, because `wait` below is unbounded — see
                // `shell_is_already_gone`. Nothing is lost by going early: a
                // live process has no exit reason to report yet.
                if let Some(e) = pending.take_if(|e| !shell_is_already_gone(e)) {
                    self.notify_remote_teardown(TeardownCause {
                        pty_err: Some(e),
                        exit: None,
                    });
                }

                let code = self.process.wait();
                let exit = self.process.exit_reason();
                // The pty/step arm that got here already logged the errno; this
                // records what reaping the process then yielded.
                //
                // Carries the reason as well as the code because this is the
                // only session-attributed line a *detached* death produces:
                // hakoniwa's own account is logged from the process handle,
                // which has no span and so names no session, and the binding's
                // farewell line never happens with nothing attached.
                //
                // A requested teardown is logged at info: its SIGKILL reaps
                // with the same abnormal reason an OOM kill does, and a warn
                // for every destroy would bury the deaths nobody asked for.
                if requested {
                    tracing::info!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        ?code,
                        abnormal = exit.as_ref().is_some_and(ExitReason::is_abnormal),
                        exit_reason = exit.as_ref().map_or("", |r| r.reason.as_str()),
                        "session process reaped after requested teardown",
                    );
                } else {
                    tracing::warn!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        ?code,
                        abnormal = exit.as_ref().is_some_and(ExitReason::is_abnormal),
                        exit_reason = exit.as_ref().map_or("", |r| r.reason.as_str()),
                        "session process reaped after pty/step error",
                    );
                }

                // Otherwise notify *after* it, which is the whole point: only
                // the reap can say whether that shell exited or was killed, and
                // on the `EIO` path it costs a few milliseconds.
                if let Some(e) = pending {
                    self.notify_remote_teardown(TeardownCause {
                        pty_err: Some(e),
                        exit: exit.clone(),
                    });
                }
                break code.map(|code| HostExit {
                    code,
                    reason: exit,
                    requested,
                });
            }
        };

        // An entrypoint that ended before its run took the streams, as a
        // fast one can, still has its output held in the pipes. The run can
        // take it until the hold ends. A kill asked for the end, so no run
        // waits on it.
        if matches!(&result, Ok(exit) if !exit.requested) {
            self.hold_output_after_exit().await;
        }

        // What the entrypoint wrote before it ended and the host did not
        // read yet, to the log and to the run. Then the run's streams end.
        if let Some(pipes) = self.pipes.as_mut() {
            pipes.drain(&self.master, &mut self.output_log).await;
        }

        // The box's host has exited (NET-128): mark the name stopped *before*
        // the forwards come down, so there is no window in which a lookup is
        // answered at a forward whose process is already dead. The name stays
        // held — answered, never NXDOMAIN — and answers NODATA while it
        // shares an address with the node.
        #[cfg(target_os = "linux")]
        if let Some(marker) = self.name_marker.take() {
            marker.mark_stopped();
        }

        // Stop the listen-publication watcher (NET-017's last half) before
        // the network attachment tears down: the stop withdraws every port
        // the box's processes published by listening — the gate refusing
        // each first, the forward after — so no runtime-published forward
        // outlives the tap it delivers through, and no session ends with a
        // port published on its address. Declared forwards are not this
        // call's: they come down with the attachment below (NET-121).
        if let Some(watcher) = self.listen_watcher.take() {
            watcher.stop().await;
        }

        // Tear down the per-sandbox network attachment explicitly (own-IP switch
        // detach + ingress removal) on this live runtime, before `_guard` drops
        // the sandbox files. No-op for `HostNet`/`NoNet` and net-guard-less mocks.
        if let Some(net_guard) = self.net_guard.take() {
            net_guard.teardown().await;
        }

        result
    }

    /// Whether a kill from the daemon waits in the mailbox. Called once the
    /// process is reaped and the loop ends, so it drains the mailbox: the
    /// loop takes no message after this. A run that asked for the
    /// entrypoint's streams gets them, and the other messages drop as they
    /// do when the host ends.
    fn kill_queued(&mut self) -> bool {
        let mut killed = false;
        while let Ok(msg) = self.receiver.try_recv() {
            match msg {
                Message::Kill(for_shutdown) => {
                    tracing::info!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        for_shutdown,
                        "session host killed on request; the process was already reaped",
                    );
                    killed = true;
                }
                Message::TakeEntrypointIo(reply) => self.answer_take_entrypoint_io(reply),
                _ => {}
            }
        }
        killed
    }

    /// Hands the entrypoint's streams to the run that asked for them, or
    /// says why it gets none: the entrypoint has a terminal, or another run
    /// relays it.
    fn answer_take_entrypoint_io(&mut self, reply: oneshot::Sender<EntrypointIoTake>) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the run may already be gone; the output then goes to the log only"
        )]
        let _ = reply.send(
            self.pipes
                .as_mut()
                .map_or(EntrypointIoTake::OnTerminal, HostPipes::take_io),
        );
    }

    /// Holds an ended entrypoint's output for the run that started it, when
    /// the entrypoint ended before the run took its streams. The pipes keep
    /// what it wrote. The hold ends when the run takes the streams, when a
    /// kill arrives, or at the hold's deadline ([`pipes::FIRST_RELAY_WAIT`]
    /// from the launch). The process is reaped already, so every other
    /// message drops as it does when the host ends.
    async fn hold_output_after_exit(&mut self) {
        let Some(deadline) = self.pipes.as_ref().and_then(|p| p.first_relay_deadline) else {
            return;
        };
        loop {
            tokio::select! {
                msg = self.receiver.recv() => match msg {
                    Some(Message::TakeEntrypointIo(reply)) => {
                        self.answer_take_entrypoint_io(reply);
                        return;
                    }
                    Some(Message::Kill(_)) | None => return,
                    Some(_) => {}
                },
                () = tokio::time::sleep_until(deadline) => {
                    let session = self.session_name.clone();
                    if let Some(pipes) = self.pipes.as_mut() {
                        pipes.first_relay_missed(&session);
                    }
                    return;
                }
            }
        }
    }

    /// Logs a pty-master failure and stashes it for [`Self::mainloop`] to hand
    /// to the binding once the process has been reaped.
    ///
    /// Used on any pty read/write failure — in practice the process dying closes
    /// every slave fd, so the master reports `EIO`; this is the signal to unwind
    /// the host.
    ///
    /// Deliberately does *not* notify the binding itself. The error alone
    /// cannot say whether the shell exited or was killed — both arrive as the
    /// same `EIO` — so the notice waits for the reap, which is the only thing
    /// that can tell them apart.
    fn record_pty_err(&mut self, op: PtyOp, e: std::io::Error) {
        // `errno` and `kind` are logged as their own fields, not left inside the
        // rendered message: this is the one line that says whether a session
        // died of the expected EIO-on-exit (5), of an `EINTR` (4) that the read
        // loop treated as fatal rather than retrying, or of something else
        // entirely.
        tracing::warn!(
            session_id = %self.session_id,
            session = %self.session_name,
            op = op.as_str(),
            errno = ?e.raw_os_error(),
            kind = ?e.kind(),
            error = %e,
            attached = self.remote.is_some(),
            "pty master error; tearing down host",
        );
        self.pending_pty_err = Some(e);
    }

    /// Notifies the attached binding that the session is going away, so it
    /// tears down and closes the client's channel. No prompt follows: the box
    /// ends from the daemon whether or not a client is attached (BOX-038).
    ///
    /// Called once the process has been reaped, from either route into
    /// teardown: the loop's own `try_wait` (no pty error) or a pty failure
    /// stashed by [`Self::record_pty_err`].
    ///
    /// The notice is sent best-effort with `try_send`, never awaited: the
    /// binding drains this queue in the same `select!` as its (potentially
    /// blocking) write to the ssh remote, so awaiting a full queue could wedge
    /// teardown behind a stuck remote. If the queue is full the notice is
    /// dropped — the host returns regardless, and dropping its sender closes the
    /// binding on its next turn. The message stays buffered even as this host
    /// drops, and an mpsc receiver drains its buffer before observing the closed
    /// sender, so the binding sees the teardown before falling through to
    /// `HostGone`.
    fn notify_remote_teardown(&mut self, cause: TeardownCause) {
        // Read off the screen before the binding slot is borrowed: the binding
        // has no view of this host's parser, so the codes that undo whatever
        // input modes the process left behind have to travel with the message.
        let unwind_codes = self.unwind_codes();
        match self.remote.as_mut() {
            Some((tx, ..)) => match tx.try_send(BindingMsg::TeardownDueToProcessExit {
                cause,
                unwind_codes,
            }) {
                Ok(()) => tracing::debug!(
                    session_id = %self.session_id,
                    "handed the teardown cause to the attached binding",
                ),
                // The documented best-effort drop, made visible: the binding
                // never learns why it is going away, so it falls through to
                // `HostGone`. The box still ends from the daemon.
                Err(e) => tracing::warn!(
                    session_id = %self.session_id,
                    error = %e,
                    "could not hand the teardown to the binding; \
                     the client is told the host is gone",
                ),
            },
            None => tracing::debug!(
                session_id = %self.session_id,
                "session process exited with no binding attached",
            ),
        }
    }

    /// Snapshots the visible terminal screen into the structured
    /// [`minimald_rpc::ScreenSnapshot`] wire type: dimensions, the cursor
    /// position (omitted when the session hid its cursor), and every cell
    /// of the grid. Read-only — no PTY resize and no I/O relay, unlike
    /// `attach`.
    fn screen_snapshot(&self) -> minimald_rpc::ScreenSnapshot {
        screen_to_snapshot(self.parser.screen())
    }

    pub async fn step(&mut self) -> Result<(), ()> {
        // Snapshot the chord-flush deadline for the select below: the arm
        // sleeps until this absolute instant, so the timer survives the select
        // being rebuilt on every `step()` call (a bare `sleep` would restart
        // each iteration and never fire while other events keep waking the
        // loop).
        let chord_flush_deadline = self.chord_flush_deadline;
        // Output backpressure. While the attached binding's mailbox is full,
        // the pty is not read: the shell waits on the terminal instead of
        // this loop parking in a send, so the loop keeps answering its
        // mailbox. A binding that frees no slot within the stall bound is
        // shed. Snapshotted like the chord deadline, so the timer survives
        // the select being rebuilt on every call.
        let stalled_binding = self
            .remote
            .as_ref()
            .filter(|(tx, ..)| tx.capacity() == 0)
            .map(|(tx, ..)| tx.clone());
        self.output_stall_deadline = stalled_binding.as_ref().map(|_| {
            self.output_stall_deadline
                .unwrap_or_else(|| tokio::time::Instant::now() + self.output_stall_timeout)
        });
        let output_stall_deadline = self.output_stall_deadline;
        // An entrypoint on pipes (T43): the host reads them only while it
        // does not hold the output for the first run and the run's relay
        // has room. Snapshotted, so no arm below borrows `self`.
        let on_pipes = self.pipes.is_some();
        let reads_pipes = self.pipes.as_ref().is_none_or(HostPipes::reads);
        let stdout_open = self.pipes.as_ref().is_none_or(|p| !p.stdout_eof);
        let stderr_fd = self.pipes.as_ref().and_then(HostPipes::stderr_to_read);
        let full_relay = self.pipes.as_ref().and_then(HostPipes::full_relay);
        let first_relay_deadline = self.pipes.as_ref().and_then(|p| p.first_relay_deadline);
        tokio::select! {
            // Read actor messages.
            Some(msg) = self.receiver.recv() => {
                match msg {
                    Message::SignalEntrypoint(signal) => {
                        self.process.signal_entrypoint(signal);
                    }
                    Message::Kill(for_shutdown) => {
                        // The other way a session ends: someone asked it to.
                        // Without this line a destroy, a daemon shutdown and a
                        // shell that died on its own are indistinguishable in
                        // the log — they all end with the host loop returning.
                        tracing::info!(
                            session_id = %self.session_id,
                            session = %self.session_name,
                            for_shutdown,
                            "session host killed on request",
                        );
                        self.kill_requested = true;
                        if for_shutdown
                            && let Some(binding) = self.remote.take() {
                                // If there was a binding we just swapped out, tell it to
                                // shut down and wait for it to finish.
                                let unwind_codes = self.unwind_codes();
                                retire_binding(
                                    binding,
                                    BindingMsg::TeardownDueToDaemonShutdown(unwind_codes),
                                )
                                .await;
                            }

                        if let Err(e) = self.process.kill() {
                            tracing::warn!(error = %e, "killing session process");
                        }
                        // Drive teardown directly rather than waiting for the
                        // pty to report the death: a hangup on the master does
                        // not reliably wake `readable()`, so a killed process
                        // that produced no draining output would otherwise leave
                        // the loop parked forever. Returning `Err` makes
                        // `mainloop` reap via `wait()` and return.
                        return Err(());
                    }
                    Message::Attach(channel, sz, connection, keys) => {
                        self.attach(channel, sz, false, connection, keys).await;
                    }
                    // Unchanged name: nothing to republish.
                    Message::Rename(new_name) if new_name == self.session_name => {}
                    Message::Rename(new_name) => {
                        self.session_name = new_name.clone();
                        // The attached binding cloned the old name at spawn
                        // for its save-then-delete archive; best-effort, since
                        // the next attach clones the new one anyway.
                        if let Some((tx, ..)) = self.remote.as_ref() {
                            let _ = tx.try_send(BindingMsg::Rename(new_name.clone()));
                        }
                        // The shell's `environ` is frozen at launch, so the
                        // new name reaches it the same way `TERM` does: by
                        // republishing through the per-attach environment
                        // files the shell re-sources at every prompt.
                        self.connection_env
                            .insert("MINIMAL_SESSION_NAME".to_string(), new_name);
                        self.publish_connection_env().await;
                    }
                    Message::SetTitleCallback(title) => {
                        self.attrs.title = Some((title, SystemTime::now()));
                    }
                    Message::AudibleBellCallback => {
                        let (count, last) = &mut self.attrs.audible_bell;
                        *count += 1;
                        *last = Some(SystemTime::now());
                    }
                    Message::VisualBellCallback => {
                        let (count, last) = &mut self.attrs.visual_bell;
                        *count += 1;
                        *last = Some(SystemTime::now());
                    }
                    Message::GetAttrs(s) => {
                        let _ = s.send(self.attrs.clone());
                    }
                    Message::GetScreen(s) => {
                        let _ = s.send(self.screen_snapshot());
                    }
                    Message::TakeEntrypointIo(reply) => self.answer_take_entrypoint_io(reply),
                    // NET-045: forward the ask to the attached client, whose
                    // binding renders the exit prompt's own dialog. Nobody
                    // attached — no binding, or one whose mailbox is wedged —
                    // answers `None` so the session refuses with the typed
                    // nobody-is-attached error rather than hanging on a
                    // dialog nobody can see.
                    Message::AskExpose { port, reply } => match self.remote.as_ref() {
                        None => {
                            // The plan's observability line: one info line per
                            // refusal for want of a client, naming the box and
                            // the port — and the one line the session-level
                            // no-host shortcut never says, so a refusal read
                            // off the log can be told to have come from a
                            // live host that found nobody on it.
                            tracing::info!(
                                session = %self.session_name,
                                port,
                                "refusing the runtime port publish ask for want of a client to answer it"
                            );
                            #[expect(
                                clippy::let_underscore_must_use,
                                reason = "the asker may already be gone; there is nothing to answer then"
                            )]
                            let _ = reply.send(None);
                        }
                        Some((tx, ..)) => {
                            let (binding_reply, binding_recv) = oneshot::channel();
                            match tx
                                .send_timeout(
                                    BindingMsg::AskExpose {
                                        port,
                                        reply: binding_reply,
                                    },
                                    crate::box_actor::HOST_PROBE_TIMEOUT,
                                )
                                .await
                            {
                                // The human may sit at the dialog for as long
                                // as they like, so only the hand-off is
                                // bounded. The answer is awaited on a spawned
                                // task, never inside this loop: a host parked
                                // on a human stops pumping the pty and stops
                                // answering probes, and the probes that
                                // decide `is_alive` would report a live host
                                // dead.
                                Ok(()) => {
                                    crate::traced::spawn(async move {
                                        // The binding dropping mid-prompt — a
                                        // detach, a shed, a daemon shutdown —
                                        // is the nobody-attached case again.
                                        let answer = binding_recv.await.ok();
                                        tracing::info!(port, answer = ?answer, "the attached client answered the runtime port publish ask");
                                        #[expect(
                                            clippy::let_underscore_must_use,
                                            reason = "the asker may already be gone; there is nothing to answer then"
                                        )]
                                        let _ = reply.send(answer);
                                    });
                                }
                                Err(send_error) => {
                                    // The ask never reached a human. On a
                                    // timeout the message comes back here
                                    // (binding-level reply and all) and drops
                                    // with this arm; on a closed mailbox the
                                    // binding is already gone. Either way the
                                    // host-level answer below is what the
                                    // asker sees: nobody is attached.
                                    tracing::warn!(port, error = %send_error, "the ask could not reach the attached client");
                                    #[expect(
                                        clippy::let_underscore_must_use,
                                        reason = "the asker may already be gone; there is nothing to answer then"
                                    )]
                                    let _ = reply.send(None);
                                }
                            }
                        }
                    },
                    Message::CommandInSession {
                        program,
                        args,
                        extra_env,
                        reply,
                    } => {
                        let _ = reply.send(self.command_in_session(&program, args, extra_env));
                    }
                    Message::GetAtRisk(s) => {
                        // Computed on a spawned task: the git commands and
                        // the re-walk are each bounded but can take seconds,
                        // and this loop must keep pumping the pty while
                        // they run.
                        let root = self.workspace_root.clone();
                        let delta = self.delta.clone();
                        crate::traced::spawn(async move {
                            let _ = s.send(crate::workspace_delta::assess(root, delta).await);
                        });
                    }
                    #[cfg(test)]
                    Message::SetOutputStallTimeout(timeout) => {
                        self.output_stall_timeout = timeout;
                    }
                    #[cfg(test)]
                    Message::FeedStdin(bytes) => {
                        // Queued, not awaited: a pty whose input side is
                        // wedged (the shell is blocked on an output side that
                        // nobody is draining) must not park this loop, which
                        // a test may be relying on to shed a binding on time.
                        queue_stdin(&mut self.stdin_buf, bytes);
                    }
                }
            },
            // Read from master - stdout of session process => ssh channel (if any).
            // Not while the binding's mailbox is full; see `stalled_binding`.
            // On pipes, not while the host holds or cannot relay the output,
            // and not after EOF.
            r = self.master.readable(), if stalled_binding.is_none() && reads_pipes && stdout_open => {
                let mut guard = match r {
                    Ok(g) => g,
                    Err(e) => {
                        // The io reactor failed to report readiness; the master
                        // is unusable, so unwind rather than panic.
                        self.record_pty_err(PtyOp::Readable, e);
                        return Err(());
                    }
                };
                match guard.try_io(|fd| fd.get_ref().read(&mut self.stdout_buf)) {
                    // A stdout pipe at EOF stays readable, so the host stops
                    // reading it. The exit poll below sees the end.
                    Ok(Ok(0)) => {
                        if let Some(pipes) = self.pipes.as_mut() {
                            pipes.stdout_eof = true;
                        }
                    },
                    Ok(Ok(n)) => {
                        let b = &self.stdout_buf[..n];
                        self.attrs.stdout_last = Some(SystemTime::now());
                        // The log first: a client is a second reader, and
                        // the log has these bytes whatever the client does.
                        self.output_log.write(b);
                        // A pipe is no terminal: its output goes to the run,
                        // and no screen models it.
                        match self.pipes.as_mut() {
                            Some(pipes) => pipes.relay(PipeStream::Stdout, b),
                            None => self.parser.process(b),
                        }
                        // Never an awaited send: this arm runs only while the
                        // mailbox has a free slot, and nothing else fills it
                        // in between. What can fail is a binding whose task
                        // has already ended.
                        if let Some((tx, ..)) = self.remote.as_ref()
                            && let Err(e) = tx.try_send(BindingMsg::Stdin(b.to_vec()))
                        {
                            tracing::warn!("shedding binding on stdout=>remote send: {e}");
                            self.shed_binding();
                        }
                    }
                    // Every errno except `WouldBlock` (which `try_io` routes to
                    // the arm below) lands here and is fatal to the host —
                    // `EINTR` included, which is retryable and is not retried.
                    // The errno is on the log line so a spurious teardown can
                    // be told apart from the genuine EIO-on-exit.
                    Ok(Err(e)) => {
                        self.record_pty_err(PtyOp::Read, e);
                        return Err(());
                    },
                    Err(_would_block) => {},
                }
            },
            // The entrypoint's stderr, on pipes: to the log and to the run,
            // as a stream of its own.
            r = async {
                match stderr_fd {
                    Some(fd) => read_ready(fd).await,
                    None => std::future::pending().await,
                }
            } => {
                match r {
                    Ok(b) if !b.is_empty() => {
                        self.attrs.stdout_last = Some(SystemTime::now());
                        self.output_log.write(&b);
                        if let Some(pipes) = self.pipes.as_mut() {
                            pipes.relay(PipeStream::Stderr, &b);
                        }
                    }
                    Ok(_) => {
                        if let Some(pipes) = self.pipes.as_mut() {
                            pipes.stderr_ended();
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            session_id = %self.session_id,
                            error = %e,
                            "the entrypoint's stderr could not be read; it is no longer read",
                        );
                        if let Some(pipes) = self.pipes.as_mut() {
                            pipes.stderr_ended();
                        }
                    }
                }
            }
            // A slot freed up in the run's full relay: wake the loop so the
            // pipe reads re-arm. A run that went away is dropped.
            reserved = async {
                match full_relay.as_ref() {
                    Some(tx) => tx.reserve().await.map(drop),
                    None => std::future::pending().await,
                }
            } => {
                if reserved.is_err()
                    && let Some(pipes) = self.pipes.as_mut()
                {
                    pipes.relay_gone();
                }
            }
            // No run took the entrypoint's streams in time.
            _ = async {
                match first_relay_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                let session = self.session_name.clone();
                if let Some(pipes) = self.pipes.as_mut() {
                    pipes.first_relay_missed(&session);
                }
            }
            // On pipes, nothing like a terminal's hangup reports the exit,
            // so the loop wakes to let `run` check for it.
            _ = tokio::time::sleep(PIPE_EXIT_POLL), if on_pipes => {}
            // Input typed into a box that runs on pipes has no terminal to
            // go to. Only a task run writes the entrypoint's stdin.
            _ = std::future::ready(()), if on_pipes && self.stdin_buf.is_some() => {
                tracing::debug!(
                    session_id = %self.session_id,
                    "dropped input for an entrypoint that runs without a terminal",
                );
                self.stdin_buf = None;
            }
            // A slot freed up in the stalled binding's mailbox. The permit is
            // dropped at once; the point is to wake the loop so the pty read
            // arm re-arms.
            reserved = async {
                match stalled_binding.as_ref() {
                    Some(tx) => tx.reserve().await.map(drop),
                    None => std::future::pending().await,
                }
            } => {
                if reserved.is_err() {
                    tracing::warn!("shedding binding whose task has ended");
                    self.shed_binding();
                }
            }
            // The stalled binding took no output within the stall bound: its
            // client has stopped reading.
            _ = async {
                match output_stall_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                tracing::warn!(
                    session_id = %self.session_id,
                    session = %self.session_name,
                    stall = ?self.output_stall_timeout,
                    "shedding binding that took no session output within the stall bound",
                );
                self.shed_binding();
            }
            // Read from remote (ssh channel) - these keystrokes need writing to the pty.
            //
            // To ensure we never block service of reads from the master side of the pty ('stdout'),
            // we only consume new keystrokes if we have none waiting to be written to the pty, and
            // pending writes to the pty are serviced async by their own select arm (below).
            Some(msg) = self.remote_rx.recv(), if self.stdin_buf.is_none() => {
                // Discard input queued by the superseded binding: its bytes
                // predate the attach that installed the current session keys,
                // and matching them now would hand the old channel's
                // keystrokes to the new channel's chord (or its size).
                if msg.generation != self.binding_generation {
                    return Ok(());
                }
                match msg.kind {
                    StdinMsgKind::Bytes(b) => {
                        self.attrs.stdin_last = Some(SystemTime::now());

                        // Session-key chord matching over the stdin byte
                        // stream: the leader chord is swallowed and enters
                        // command mode; the next keystroke is the subcommand —
                        // detach, forward, or an unbound key that cancels. The
                        // leader is never forwarded except via the explicit
                        // forward subcommand. Coalesced and split chunks are
                        // handled by the matcher; the decisions below only map
                        // outcomes to I/O, with every PTY-bound byte (data
                        // runs and verbatim leaders) collected in stream order.
                        let mut forward: Vec<u8> = Vec::new();
                        for outcome in self.chord_matcher.feed(&b) {
                            match outcome {
                                FeedOutcome::Forward(bytes) => {
                                    forward.extend_from_slice(&bytes);
                                }
                                FeedOutcome::Action(KeyAction::Swallow) => {}
                                FeedOutcome::Action(KeyAction::EnterCommandMode) => {
                                    // Ring the terminal bell on the channel back
                                    // to the user (never the PTY, so the app
                                    // never sees it) when the client opted in.
                                    // `try_send`: a bell is worth dropping,
                                    // and an awaited send would park this loop
                                    // behind a stalled binding.
                                    if self.chord_matcher.keys().bell_on_leader
                                        && let Some((tx, ..)) = self.remote.as_ref()
                                    {
                                        let _ = tx.try_send(BindingMsg::Stdin(vec![0x07]));
                                    }
                                }
                                FeedOutcome::Action(KeyAction::Detach) => {
                                    // Bounded, because the detach chord is also
                                    // how a user gets out of an attach whose
                                    // output has stalled, and then the mailbox
                                    // is full. A binding that cannot take the
                                    // detach in time is shed, which closes its
                                    // channel all the same.
                                    let uc = self.unwind_codes();
                                    if let Some((tx, ..)) = self.remote.as_ref() {
                                        match tx
                                            .send_timeout(
                                                BindingMsg::TeardownDueToDetach(uc),
                                                crate::box_actor::HOST_PROBE_TIMEOUT,
                                            )
                                            .await
                                        {
                                            Ok(()) => self.remote = None,
                                            Err(e) => {
                                                tracing::warn!("shedding binding that could not take the detach: {e}");
                                                self.shed_binding();
                                            }
                                        };
                                    }
                                }
                                FeedOutcome::Action(KeyAction::ForwardLeader) => {
                                    // Queue a verbatim leader byte in the PTY
                                    // stream, handing the next keystroke to the
                                    // layer below (a nested daemon *that
                                    // negotiated the same leader*, if any).
                                    // Safe to over-send: a stray leader past the
                                    // deepest layer hits the app's own
                                    // non-destructive leader binding.
                                    forward.push(self.chord_matcher.keys().leader.plain_byte());
                                }
                            }
                        }
                        if !forward.is_empty() {
                            queue_stdin(&mut self.stdin_buf, forward);
                        }

                        // Arm (or clear) the idle-flush timer: a chunk that
                        // leaves the matcher holding a split candidate (a lone
                        // `ESC`, a prefix of every kitty form) must not wedge
                        // that candidate forever — flush it to the PTY as data
                        // once the stream goes quiet.
                        self.chord_flush_deadline = self
                            .chord_matcher
                            .has_pending()
                            .then(|| tokio::time::Instant::now() + CHORD_FLUSH_IDLE);
                    }
                    StdinMsgKind::TerminalUpdate(sz) => {
                        self.set_size(WinSize::from(&sz));
                    },
                    StdinMsgKind::WindowChange{ col_width, row_height, pix_height, pix_width } => {
                        self.set_size(WinSize {
                            rows: row_height as u16,
                            cols: col_width as u16,
                            xpixel: pix_width as u16,
                            ypixel: pix_height as u16,
                        });
                    },
                }
            },
            // Write buffered keystrokes into the pty, if any,
            w = self.master.writable(), if self.stdin_buf.is_some() && !on_pipes => {
                let mut guard = match w {
                    Ok(g) => g,
                    Err(e) => {
                        // The io reactor failed to report writability; the master
                        // is unusable, so unwind rather than panic.
                        self.record_pty_err(PtyOp::Writable, e);
                        return Err(());
                    }
                };
                let (buff, n) = self.stdin_buf.as_mut().unwrap();
                let res = guard.try_io(|fd| fd.get_ref().write(&buff[*n..]));
                match res {
                    Ok(Ok(extra)) => {
                        if (*n+extra) == buff.len() {
                            self.stdin_buf = None;
                        } else {
                            *n += extra;
                        }
                    }
                    // A write failure means the slave side is gone (the process
                    // died, e.g. on kill): EIO closes every slave fd. Tear the
                    // host down so it gets reaped, instead of panicking and
                    // leaking the process as a zombie.
                    Ok(Err(e)) => {
                        self.record_pty_err(PtyOp::Write, e);
                        return Err(());
                    }
                    Err(_would_block) => {},
                }
            }
            // Flush a held chord-matcher split candidate once the stream goes
            // quiet. A lone `ESC` is a strict prefix of every kitty form, so
            // the matcher holds it for the next chunk; without this, a bare
            // `ESC` (e.g. leaving vim insert mode) would be held until the
            // user's next keystroke. `pending()` keeps the arm inert while no
            // candidate is held.
            _ = async {
                match chord_flush_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                self.chord_flush_deadline = None;
                // Appended after anything already queued: forwarded input
                // still waiting on an unwritable pty predates the candidate
                // the flush releases, and replacing the buffer would drop it
                // (see `queue_stdin`).
                let flushed = self.chord_matcher.flush();
                if !flushed.is_empty() {
                    queue_stdin(&mut self.stdin_buf, flushed);
                }
            }

        }

        Ok(())
    }

    async fn attach(
        &mut self,
        channel: Channel<Msg>,
        sz: WinSize,
        skip_flush: bool,
        connection: ConnectionEnv,
        keys: SessionKeys,
    ) {
        // Merge the connection facts rather than replacing the stored map.
        // Every attach carries the banner's detach hint (derived from this
        // channel's keys), but only some carry a terminal — replacing
        // wholesale would let a terminal-less attach drop the last published
        // `TERM` (see the attach-side log about keeping it). Merging updates
        // whatever this attach declares and leaves the rest standing.
        self.connection_env.extend(connection);
        self.publish_connection_env().await;

        // A new channel means a fresh matcher: fresh key negotiation, idle
        // command-mode state, and no pending split candidate — two clients
        // with different configs on the same session each get their own
        // chord, and a reattach never inherits a stale awaiting-subcommand
        // state.
        self.chord_matcher = ChordMatcher::new(keys);
        // A fresh matcher holds no candidate, so any pending idle-flush
        // deadline from the previous channel is stale.
        self.chord_flush_deadline = None;

        // Bump before spawning the new binding: anything the superseded
        // binding already queued into the shared stdin channel carries the
        // old generation from here on, so the stdin arm drops it instead of
        // interpreting those keystrokes under this channel's fresh keys.
        self.binding_generation += 1;

        // The redraw is rendered here but not written here: a redraw can be
        // megabytes (a large terminal with per-cell colour), and russh parks
        // a write while the client's ssh window is exhausted, so writing it
        // on the host loop let one client that stopped reading before its
        // redraw was written stall the host loop, and every other client of
        // the session with it.
        let redraw = (!skip_flush).then(|| {
            self.parser.screen_mut().set_size(sz.rows, sz.cols);
            self.parser.screen().state_formatted()
        });
        let new_binding = Binding::spawn(
            channel,
            self.remote_tx.clone(),
            self.binding_generation,
            self.control.clone(),
            self.delta.clone(),
            self.session_name.clone(),
            self.archives_dir.clone(),
            self.holds_host_row,
            self.ends_with_entrypoint,
            self.box_dir.clone(),
        )
        .await;

        // The redraw is the new binding's first output, written by the
        // binding's own task and raced against the shed like any other
        // stdout, so a client that never reads stalls only its binding. The
        // mailbox is fresh, so the first message always fits.
        if let Some(redraw) = redraw
            && let Err(e) = new_binding.0.try_send(BindingMsg::Stdin(redraw))
        {
            tracing::warn!(session = %self.session_name, "could not queue the attach redraw: {e}");
        }

        if let Some(old_binding) = self.remote.replace(new_binding) {
            // If there was a binding we just swapped out, tell it to
            // shut down and wait for it to finish.
            let unwind_codes = self.unwind_codes();
            retire_binding(
                old_binding,
                BindingMsg::TeardownDueToSuperceded(unwind_codes),
            )
            .await;
        }

        self.set_size(sz);

        // A host minted for hooks holds its shell at the start gate until a
        // client is here for it: released now, with the binding installed and
        // the pty sized, so the shell's startup runs after the activate hooks
        // and on the terminal that attached — the order a shell minted by an
        // attach has always had.
        if let Some(gate) = self.start_gate.take() {
            tracing::info!(
                session = %self.session_name,
                "released the hook-launched session shell to start for the attaching client"
            );
            gate.release();
        }

        // After the binding is installed and sized, so a hook writing to
        // the terminal reaches the client that just attached.
        self.run_hooks_for(crate::hooks::HookEvent::Attach).await;
    }
    /// Rewrites the session's per-attach environment files from
    /// [`Self::connection_env`].
    ///
    /// Takes `&mut self` rather than `&self` deliberately: a `Host` holds a
    /// non-`Sync` `dyn NetGuard`, so a `&Host` held across the write's await
    /// would make the whole session future non-`Send` (the same constraint
    /// [`HookPlan`] snapshots around).
    async fn publish_connection_env(&mut self) {
        write_connection_env(self.home_dir.clone(), self.connection_env.clone()).await;
    }

    /// Drops the attached binding without waiting for it, for when it has
    /// stopped taking what the host hands it.
    ///
    /// Cancels the binding's shed token rather than aborting its task: an
    /// aborted task drops its channel halves, and russh sends no close for a
    /// dropped channel, so the client would stay connected with nothing
    /// behind it. A shed binding instead leaves through its own exit path,
    /// which sends EOF, an exit status and a close.
    ///
    /// Bumps the generation first. Stdin that the shed binding already queued
    /// into the shared stdin channel still carries the old generation, so the
    /// stdin arm drops it instead of handing a dead channel's keystrokes to
    /// the shell (or to a later re-attach's fresh chord).
    fn shed_binding(&mut self) {
        self.binding_generation += 1;
        self.output_stall_deadline = None;
        if let Some((_tx, _task, shed)) = self.remote.take() {
            shed.cancel();
        }
    }

    fn set_size(&mut self, sz: WinSize) {
        // If the terminal size changed, reconfigure the pty.
        if sz != self.sz {
            if let Err(e) = set_winsize(self.master.as_raw_fd(), sz) {
                tracing::warn!(error = %e, "set_winsize failed, ignoring");
            }
            self.parser.screen_mut().set_size(sz.rows, sz.cols);
            self.sz = sz;
        }
    }

    /// Computes terminal escape sequences to return the outer terminal
    /// to a normal state on detach.
    ///
    /// Deliberately *narrow*: the host has a screen model, so it emits only
    /// what this session actually turned on. That matters most for
    /// [`LEAVE_ALT_SCREEN`](boxes::terminal::LEAVE_ALT_SCREEN), which is
    /// not inert against a terminal that never left the normal buffer — see
    /// its docs. The `min` client's blind fallback exists only for the case
    /// where these bytes cannot reach the tty at all.
    fn unwind_codes(&self) -> Vec<u8> {
        use boxes::terminal as term;

        let live = self.parser.screen();
        let clean = vt100::Parser::new(live.size().0, live.size().1, 0)
            .screen()
            .clone();

        // app keypad/cursor, paste, mouse
        let mut out = clean.input_mode_diff(live);
        // disable alternate screen
        if live.alternate_screen() {
            out.extend_from_slice(term::LEAVE_ALT_SCREEN.as_bytes());
        }
        // disable hidden cursor
        if live.hide_cursor() {
            out.extend_from_slice(term::SHOW_CURSOR.as_bytes());
        }

        // blind: reset text colors etc ('SGR')
        out.extend_from_slice(term::SGR_RESET.as_bytes());
        // blind: disable focus reporting
        out.extend_from_slice(term::FOCUS_REPORTING_OFF.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests;

// BEP-012: which boxes get the proxy variables, and what each one holds.
#[cfg(test)]
mod proxy_env_tests {
    use super::*;
    use boxes::core::bep::{BepSettings, Steering};

    pub(super) fn record(network: NetworkMode, bep: Option<BepSettings>) -> boxes::Record {
        boxes::Record {
            id: boxes::SessionId::nil(),
            name: None,
            username: None,
            project_path: paths::HostAbsPath::try_new("/p").unwrap(),
            network,
            policy: boxes::BoxPolicy {
                credentialed_upstream: bep.map(|bep| boxes::CredentialedUpstream {
                    bep,
                    ..Default::default()
                }),
                ..Default::default()
            },
            status: boxes::BoxState::default(),
            reason: None,
            exit_code: None,
            signal: None,
            hooks_enabled: true,
            task_addresses: Vec::new(),
            box_addresses: None,
            host_ip_enforcement: None,
            box_id: None,
            host_row_bound: false,
            bound_ports: std::collections::BTreeSet::new(),
            sealed_deliveries: Vec::new(),
            root_certificate: None,
            ends_with_run: false,
            box_type: None,
            parent: None,
            project_root: None,
            attrs: BTreeMap::new(),
        }
    }

    pub(super) fn steering(steering: Steering) -> BepSettings {
        BepSettings {
            steering: Some(steering),
            ..BepSettings::default()
        }
    }

    fn get<'a>(vars: &'a [(String, String)], name: &str) -> Option<&'a str> {
        vars.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn proxy_env_and_no_proxy_are_set() {
        let bep = BepSettings {
            no_proxy: vec!["example.internal".to_string(), "10.0.0.0/8".to_string()],
            ..steering(Steering::ProxyEnv)
        };
        let vars = launch_proxy_env(
            &record(NetworkMode::OwnIp, Some(bep)),
            switch::DEFAULT_SUBNET,
            paths::HostKind::Minimald,
        );
        assert_eq!(
            get(&vars, "HTTPS_PROXY"),
            Some("http://100.64.255.252:8118")
        );
        assert_eq!(get(&vars, "HTTP_PROXY"), Some("http://100.64.255.252:8118"));
        assert_eq!(
            get(&vars, "NO_PROXY"),
            Some(".min.internal,host.min.internal,localhost,127.0.0.1,example.internal,10.0.0.0/8")
        );
        assert_eq!(get(&vars, "NODE_USE_ENV_PROXY"), Some("1"));
        assert_eq!(vars.len(), 4, "{vars:?}");
    }

    #[test]
    fn proxy_env_follows_steering_and_the_proxy_env_setting() {
        for bep in [
            steering(Steering::ProxyEnv),
            steering(Steering::Both),
            BepSettings {
                proxy_env: true,
                ..steering(Steering::Dns)
            },
        ] {
            let vars = launch_proxy_env(
                &record(NetworkMode::OwnIp, Some(bep.clone())),
                switch::DEFAULT_SUBNET,
                paths::HostKind::Minimald,
            );
            assert_eq!(get(&vars, "NODE_USE_ENV_PROXY"), Some("1"), "{bep:?}");
        }
        for bep in [
            BepSettings::default(),
            steering(Steering::Dns),
            steering(Steering::Off),
        ] {
            let vars = launch_proxy_env(
                &record(NetworkMode::OwnIp, Some(bep.clone())),
                switch::DEFAULT_SUBNET,
                paths::HostKind::Minimald,
            );
            assert!(vars.is_empty(), "{bep:?}: {vars:?}");
        }
        // No credentialed upstream, or a network mode with no lane.
        assert!(
            launch_proxy_env(
                &record(NetworkMode::OwnIp, None),
                switch::DEFAULT_SUBNET,
                paths::HostKind::Minimald,
            )
            .is_empty()
        );
        assert!(
            launch_proxy_env(
                &record(NetworkMode::HostNet, Some(steering(Steering::ProxyEnv))),
                switch::DEFAULT_SUBNET,
                paths::HostKind::Minimald,
            )
            .is_empty()
        );
    }

    #[test]
    fn proxy_env_reaches_the_connection_layer_over_an_old_value() {
        let mut attach_env = AttachEnv {
            inherited: vec![],
            connection: vec![
                ("TERM".to_string(), "xterm-256color".to_string()),
                (
                    "HTTPS_PROXY".to_string(),
                    "http://elsewhere:3128".to_string(),
                ),
            ],
            entrypoint: vec![],
        };
        let laned = record(NetworkMode::OwnIp, Some(steering(Steering::ProxyEnv)));
        let vars = launch_proxy_env(&laned, switch::DEFAULT_SUBNET, paths::HostKind::Minimald);
        place_launch_proxy_env(&mut attach_env, &laned, paths::HostKind::Minimald, &vars);
        let kept = place_launch_deliveries(&mut attach_env, boxes::SessionId::nil(), &[]);
        assert_eq!(
            kept.get("HTTPS_PROXY").map(String::as_str),
            Some("http://100.64.255.252:8118")
        );
        assert_eq!(
            kept.get("NODE_USE_ENV_PROXY").map(String::as_str),
            Some("1")
        );
        assert_eq!(kept.get("TERM").map(String::as_str), Some("xterm-256color"));
        assert_eq!(kept.len(), 5, "{kept:?}");
    }
}
