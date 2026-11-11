//! The network policy engine of this daemon.
//!
//! The engine is a set of programs attached at the daemon's `boxes` cgroup,
//! with maps the daemon writes each box's policy into. A daemon gets it at
//! start: as root it loads the programs itself, otherwise it asks the root
//! loader. A daemon that got none says so once, runs the boxes that need no
//! enforcement, and refuses the rest.
//!
//! Every box cgroup needs an entry here before its first process starts:
//! with the programs attached, a cgroup the maps do not know has no network.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock},
    time::{Duration, Instant},
};

use boxbpf::{BoxId, Flows, Handles, LiveBox, OriginalDestination};
use boxes::{BoxPolicy, NetworkMode, SessionId};
use netpol::{Compiled, Protocol, Verdict, base::Services, compile::Spec};
use sandbox::cgroup::{BoxCgroup, Root};
use tokio::sync::mpsc;

use super::{
    endpoints::{self, Allocator, Block, Service, Sockets, Wants},
    spec::{self, Node, SpecError},
};
use crate::events::{self, Limiter, Log, Observation};

/// Overrides where the daemon looks for the root loader's socket.
pub const LOADER_SOCKET_ENV: &str = "MINIMALD_POLICY_LOADER_SOCKET";

const FIX_LOADER: &str = "Run `min finalize-install`.";
const FIX_CGROUP: &str = "Start the daemon in a systemd user session, or in a unit with \
                          `Delegate=yes`.";

/// Why this daemon has no engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Absent {
    /// The daemon has not looked for one: a test, or a tool that links the
    /// daemon's code.
    NotStarted,
    NoCgroupRoot,
    NoLoader {
        socket: PathBuf,
    },
    LoaderOutOfDate,
    LoaderRefused(String),
    Failed(String),
}

impl Absent {
    /// What a user can do about it.
    const fn fix(&self) -> &'static str {
        match self {
            Self::NoCgroupRoot => FIX_CGROUP,
            Self::NoLoader { .. } | Self::LoaderOutOfDate => FIX_LOADER,
            Self::NotStarted | Self::LoaderRefused(_) | Self::Failed(_) => "",
        }
    }
}

impl std::fmt::Display for Absent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => f.write_str("it was not started"),
            Self::NoCgroupRoot => f.write_str("the daemon has no cgroup of its own for boxes"),
            Self::NoLoader { socket } => write!(
                f,
                "the policy loader is not installed (nothing listens at {})",
                socket.display()
            ),
            Self::LoaderOutOfDate => {
                f.write_str("the installed policy loader is from another version of Minimal")
            }
            Self::LoaderRefused(reason) => write!(f, "the policy loader refused: {reason}"),
            Self::Failed(error) => f.write_str(error),
        }
    }
}

/// Why a box cannot run here with its network policy applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unenforceable {
    /// A setting nothing applies yet to a box that shares the node's
    /// address.
    Setting(&'static str),
    NoEngine(Absent),
    Spec(SpecError),
    Compile(netpol::CompileError),
}

impl std::fmt::Display for Unenforceable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the box did not start: ")?;
        match self {
            Self::Setting(setting) => write!(
                f,
                "its network policy sets `{setting}`, which this version of Minimal cannot \
                 apply to a box that shares the host's address (`host_ip`). Give the box its \
                 own address (`own_ip`), or remove the setting."
            ),
            Self::NoEngine(why) => {
                write!(
                    f,
                    "its network policy needs enforcement, and this daemon has no network \
                     policy engine: {why}."
                )?;
                match why.fix() {
                    "" => Ok(()),
                    fix => write!(f, " {fix}"),
                }
            }
            Self::Spec(error) => write!(f, "its network policy is not valid: {error}."),
            Self::Compile(error) => write!(f, "its network policy cannot be applied: {error}."),
        }
    }
}

impl std::error::Error for Unenforceable {}

/// Why a box's policy could not be put in place.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InstallError {
    #[error("{0}")]
    Unenforceable(#[from] Unenforceable),
    #[error("the box's service endpoints could not be bound: {0}")]
    Endpoints(std::io::Error),
    #[error("writing the box's network policy failed: {0}")]
    Engine(#[from] boxbpf::Error),
}

/// What the engine needs to know about a box.
#[derive(Debug, Clone)]
pub(crate) struct BoxFacts {
    pub(crate) session: SessionId,
    pub(crate) mode: NetworkMode,
    /// The policy as the box declares it.
    pub(crate) policy: BoxPolicy,
    pub(crate) deny_all_opt_out: bool,
}

/// One box in the engine's maps.
pub(crate) struct Installed {
    session: SessionId,
    id: BoxId,
    facts: BoxFacts,
    block: Option<Block>,
    wants: Wants,
    live: Mutex<LiveBox>,
    /// The policy as the kernel has it, for readers that must not wait for
    /// a writer.
    compiled: RwLock<Arc<Compiled>>,
    limiter: Mutex<Limiter>,
    log: Arc<dyn Log>,
    /// The tasks serving the box's endpoints. Aborting one closes its socket.
    serving: Mutex<Vec<tokio::task::AbortHandle>>,
}

impl std::fmt::Debug for Installed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installed")
            .field("session", &self.session)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Installed {
    pub(crate) const fn session(&self) -> SessionId {
        self.session
    }

    /// A snapshot of the box's compiled policy.
    pub(crate) fn compiled(&self) -> Arc<Compiled> {
        Arc::clone(&self.compiled.read().expect("compiled policy lock"))
    }

    /// The prefixes the box allows, for the resolver's rebinding filter.
    pub(crate) fn allowed_prefixes(&self) -> Vec<netpol::Prefix> {
        self.live
            .lock()
            .expect("live box lock")
            .spec()
            .policy
            .allow
            .clone()
    }

    /// Addresses of the node's infrastructure, which a public name has no
    /// business resolving to.
    pub(crate) fn infrastructure(&self) -> Vec<netpol::Prefix> {
        let live = self.live.lock().expect("live box lock");
        let deployment = &live.spec().deployment;
        let mut out: Vec<netpol::Prefix> = deployment
            .endpoint_ranges
            .iter()
            .map(|r| r.prefix)
            .collect();
        if let Some(net) = &deployment.network {
            out.push(net.subnet);
        }
        out
    }

    /// Whether the transport under the box carries IPv6.
    pub(crate) fn has_ipv6(&self) -> bool {
        self.live
            .lock()
            .expect("live box lock")
            .spec()
            .deployment
            .transport_ipv6
    }

    pub(crate) fn limiter(&self) -> MutexGuard<'_, Limiter> {
        self.limiter.lock().expect("event limiter lock")
    }

    pub(crate) fn log(&self) -> &dyn Log {
        self.log.as_ref()
    }
}

/// What serves a box's endpoints. Set once the daemon's server state
/// exists, before any box starts.
pub(crate) struct Serving {
    pub(crate) runtime: tokio::runtime::Handle,
    pub(crate) resolver: Arc<super::resolver::Resolver>,
    /// Serves one hostname proxy listener of one box.
    pub(crate) hostname_proxy: Arc<dyn BoxProxy>,
}

/// The hostname proxy, as the engine starts it for a box.
pub(crate) trait BoxProxy: Send + Sync {
    fn serve(
        &self,
        listener: tokio::net::TcpListener,
        of: Arc<Installed>,
        peers: Peers,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// Tells an endpoint whether a peer is its box. An endpoint task holds its
/// own.
pub(crate) struct Peers {
    flows: Flows,
    /// The network namespace the endpoint is in: the daemon's own.
    netns: u64,
}

impl Peers {
    /// The flow behind `peer` when the engine recorded it as a socket of
    /// `of` talking to `service`. `None` for every other peer: a process
    /// outside the box, which the endpoint must not serve.
    pub(crate) fn of_box(
        &self,
        of: &Installed,
        service: Service,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Option<OriginalDestination> {
        match self.flows.original_destination(self.netns, peer, protocol) {
            Ok(Some(flow)) if flow.box_id == of.id && flow.endpoint == service.index() => {
                Some(flow)
            }
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, %peer, "looking up the peer of a box endpoint");
                None
            }
        }
    }
}

struct Attached {
    handles: Mutex<Handles>,
    flows: Flows,
    node: RwLock<Node>,
    boxes: RwLock<HashMap<BoxId, Arc<Installed>>>,
    by_session: RwLock<HashMap<SessionId, BoxId>>,
    allocator: Allocator,
    observations: mpsc::Sender<Observation>,
    /// Taken by [`Engine::start_tasks`].
    pending: Mutex<Option<(boxbpf::events::Source, mpsc::Receiver<Observation>)>>,
    serving: OnceLock<Serving>,
}

enum State {
    Attached(Box<Attached>),
    Absent(Absent),
}

/// The engine, or the reason there is none.
pub(crate) struct Engine {
    state: State,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();
static NOT_STARTED: Engine = Engine {
    state: State::Absent(Absent::NotStarted),
};

/// How often expired name pins are deleted from the maps.
const PIN_SWEEP: Duration = Duration::from_secs(30);
/// Observations waiting for the event task. More than this are dropped
/// and counted: a box cannot make the daemon hold its refusals in memory.
const OBSERVATION_QUEUE: usize = 4096;

pub(crate) fn loader_socket() -> PathBuf {
    std::env::var_os(LOADER_SOCKET_ENV)
        .map_or_else(|| PathBuf::from(paths::POLICY_LOADER_SOCKET), PathBuf::from)
}

fn from_loader(boxes: std::os::fd::BorrowedFd<'_>, socket: &Path) -> Result<Handles, Absent> {
    use boxbpf::Error;

    if !socket.exists() {
        return Err(Absent::NoLoader {
            socket: socket.to_owned(),
        });
    }
    boxbpf::loader::request(socket, boxes).map_err(|error| match error {
        Error::AbiMismatch { .. } | Error::ObjectMismatch { .. } => Absent::LoaderOutOfDate,
        Error::Refused(reason) => Absent::LoaderRefused(reason),
        Error::Sys { source, .. }
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Absent::NoLoader {
                socket: socket.to_owned(),
            }
        }
        other => Absent::Failed(other.to_string()),
    })
}

impl Engine {
    /// Gets the engine for the box cgroups below `root` and makes it the
    /// one [`Engine::current`] returns. Says once what it got.
    pub(crate) fn boot(root: Option<&Root>, node: Node) {
        let engine = Self::acquire(root, node, &loader_socket());
        match &engine.state {
            State::Attached(_) => tracing::info!(
                loaded_by = if nix::unistd::geteuid().is_root() {
                    "this daemon"
                } else {
                    "the policy loader"
                },
                "the network policy engine is attached to the daemon's box cgroups"
            ),
            State::Absent(why) => tracing::warn!(
                "no network policy engine: {why}. Boxes whose network policy needs \
                 enforcement are refused. {}",
                why.fix()
            ),
        }
        if ENGINE.set(engine).is_err() {
            tracing::warn!("a network policy engine was set before the daemon's own");
        }
    }

    fn acquire(root: Option<&Root>, node: Node, socket: &Path) -> Self {
        let Some(root) = root else {
            return Self::absent(Absent::NoCgroupRoot);
        };
        let boxes = match std::fs::File::open(root.dir().join(sandbox::cgroup::BOXES)) {
            Ok(dir) => std::os::fd::OwnedFd::from(dir),
            Err(error) => {
                return Self::absent(Absent::Failed(format!("opening the boxes cgroup: {error}")));
            }
        };
        let handles = if nix::unistd::geteuid().is_root() {
            use std::os::fd::AsFd as _;
            boxbpf::Engine::start(boxes.as_fd(), &boxbpf::MapSizes::default())
                .map_err(|error| Absent::Failed(error.to_string()))
        } else {
            use std::os::fd::AsFd as _;
            from_loader(boxes.as_fd(), socket)
        };
        match handles.and_then(|handles| Self::attached(handles, node)) {
            Ok(engine) => engine,
            Err(why) => Self::absent(why),
        }
    }

    fn attached(mut handles: Handles, node: Node) -> Result<Self, Absent> {
        let failed = |error: boxbpf::Error| Absent::Failed(error.to_string());
        let flows = handles.flows().map_err(failed)?;
        let source = handles
            .take_events()
            .ok_or_else(|| Absent::Failed("the engine has no event buffer".to_owned()))?;
        let (observations, receiver) = mpsc::channel(OBSERVATION_QUEUE);
        Ok(Self {
            state: State::Attached(Box::new(Attached {
                handles: Mutex::new(handles),
                flows,
                node: RwLock::new(node),
                boxes: RwLock::default(),
                by_session: RwLock::default(),
                allocator: Allocator::new(),
                observations,
                pending: Mutex::new(Some((source, receiver))),
                serving: OnceLock::new(),
            })),
        })
    }

    const fn absent(why: Absent) -> Self {
        Self {
            state: State::Absent(why),
        }
    }

    /// The daemon's engine. Read where a box's lifecycle starts and passed
    /// down from there.
    pub(crate) fn current() -> &'static Self {
        ENGINE.get().unwrap_or(&NOT_STARTED)
    }

    const fn attached_state(&self) -> Option<&Attached> {
        match &self.state {
            State::Attached(attached) => Some(attached),
            State::Absent(_) => None,
        }
    }

    /// Starts what runs beside the boxes: the event reader, the event
    /// writer and the pin sweep. `serving` is what answers at a box's
    /// endpoints. Call once, on the runtime, before the first box starts.
    pub(crate) fn start_tasks(&'static self, serving: Serving) {
        let Some(attached) = self.attached_state() else {
            return;
        };
        let runtime = serving.runtime.clone();
        if attached.serving.set(serving).is_err() {
            return;
        }
        let Some((source, receiver)) = attached.pending.lock().expect("engine lock").take() else {
            return;
        };
        let _in_runtime = runtime.enter();
        match boxbpf::events::Reader::new(source) {
            Ok(reader) => {
                runtime.spawn(self.read_kernel_events(reader));
            }
            Err(error) => tracing::warn!(
                %error,
                "the policy engine's events cannot be read; refusals are not reported"
            ),
        }
        runtime.spawn(events::sink(receiver, move || {
            self.attached_state().map_or_else(Vec::new, |attached| {
                attached
                    .boxes
                    .read()
                    .expect("engine lock")
                    .values()
                    .cloned()
                    .collect()
            })
        }));
        runtime.spawn(async move {
            let mut tick = tokio::time::interval(PIN_SWEEP);
            loop {
                tick.tick().await;
                let Some(attached) = self.attached_state() else {
                    return;
                };
                let swept = attached.handles.lock().expect("engine lock").sweep_pins();
                if let Err(error) = swept {
                    tracing::warn!(%error, "deleting expired name pins");
                }
            }
        });
    }

    async fn read_kernel_events(&'static self, mut reader: boxbpf::events::Reader) {
        let mut unknown_box: u64 = 0;
        loop {
            let event = match reader.next().await {
                Ok(event) => event,
                Err(error) => {
                    tracing::warn!(%error, "reading the policy engine's events stopped");
                    return;
                }
            };
            if event.outcome != netpol::event::Outcome::Denied {
                continue;
            }
            let Some(of) = self.by_cgroup(BoxId(event.box_id)) else {
                // A box torn down a moment ago, or a cgroup the daemon
                // gave no entry.
                unknown_box += 1;
                if unknown_box.is_power_of_two() {
                    tracing::debug!(
                        cgroup_id = event.box_id,
                        count = unknown_box,
                        "a refusal in a cgroup the engine has no box for"
                    );
                }
                continue;
            };
            let refusal = events::NetRefusal::from_kernel(&event, &of.compiled());
            self.observe(of, refusal);
        }
    }

    /// Reports a refusal. Never waits: a full queue drops it.
    pub(crate) fn observe(&self, of: Arc<Installed>, refusal: events::NetRefusal) {
        if let Some(attached) = self.attached_state() {
            let _full = attached.observations.try_send(Observation {
                of,
                body: events::Body::Net(refusal),
            });
        }
    }

    /// The first setting of `policy` that nothing applies to a box sharing
    /// the node's address.
    fn unapplied_setting(mode: NetworkMode, policy: &BoxPolicy) -> Option<&'static str> {
        if mode != NetworkMode::HostNet {
            return None;
        }
        if policy.credentialed_upstream.is_some() {
            return Some("secrets");
        }
        if policy.quic443 == Some(boxes::core::bep::Quic443::Block) {
            return Some("quic443");
        }
        None
    }

    /// Whether a box in `mode` with `policy` can run here with every rule
    /// of the policy applied.
    pub(crate) fn can_enforce(
        &self,
        mode: NetworkMode,
        policy: &BoxPolicy,
        deny_all_opt_out: bool,
    ) -> Result<(), Unenforceable> {
        if let Some(setting) = Self::unapplied_setting(mode, policy) {
            return Err(Unenforceable::Setting(setting));
        }
        let own = spec::box_policy(policy.egress.as_ref(), mode, deny_all_opt_out)
            .map_err(Unenforceable::Spec)?;
        match &self.state {
            State::Attached(attached) => {
                let node = attached.node.read().expect("engine lock").clone();
                // Endpoint addresses do not change whether a policy
                // compiles, so any block stands in for the box's own.
                let block = Block::sample();
                Self::spec_of(&node, mode, own, Some(block))
                    .compile()
                    .map(drop)
                    .map_err(Unenforceable::Compile)
            }
            State::Absent(why) => {
                // Without the programs a box runs unjudged. That is what a
                // box with no network or with nothing to enforce asks for,
                // and a box with its own address is judged by its relay.
                let nothing_to_enforce =
                    own.rules().is_empty() && own.egress_default(Verdict::Allow) == Verdict::Allow;
                match mode {
                    NetworkMode::NoNet | NetworkMode::OwnIp => Ok(()),
                    _ if nothing_to_enforce => Ok(()),
                    _ => Err(Unenforceable::NoEngine(why.clone())),
                }
            }
        }
    }

    fn wants(node: &Node, mode: NetworkMode, own: &netpol::BoxPolicy) -> Wants {
        Wants {
            resolver: spec::needs_resolver(node, mode, own),
            hostname_proxy: mode == NetworkMode::HostNet,
        }
    }

    fn spec_of(
        node: &Node,
        mode: NetworkMode,
        own: netpol::BoxPolicy,
        block: Option<Block>,
    ) -> Spec {
        let wants = Self::wants(node, mode, &own);
        let services = block.map_or_else(Services::default, |block| Services {
            resolver: wants.resolver.then(|| block.endpoint(Service::Resolver)),
            credential_proxy: None,
            hostname_proxy: wants
                .hostname_proxy
                .then(|| block.endpoint(Service::HostnameProxy)),
        });
        let ranges = spec::endpoint_ranges(&endpoints::addresses(), endpoints::port_range());
        Spec {
            deployment: spec::deployment(node, mode, services, ranges),
            policy: own,
            options: spec::OPTIONS,
        }
    }

    /// Puts the box's policy into the maps and starts its endpoints. The
    /// cgroup must be empty: nothing of the box runs before this returns.
    ///
    /// A daemon without an engine installs nothing, and refuses here the
    /// box it cannot enforce.
    pub(crate) fn install(
        &self,
        cgroup: &BoxCgroup,
        facts: BoxFacts,
        log: Arc<dyn Log>,
    ) -> Result<Option<Arc<Installed>>, InstallError> {
        self.can_enforce(facts.mode, &facts.policy, facts.deny_all_opt_out)?;
        let Some(attached) = self.attached_state() else {
            return Ok(None);
        };
        let own = spec::box_policy(
            facts.policy.egress.as_ref(),
            facts.mode,
            facts.deny_all_opt_out,
        )
        .map_err(Unenforceable::Spec)?;
        let node = attached.node.read().expect("engine lock").clone();
        let wants = Self::wants(&node, facts.mode, &own);
        let (block, sockets) = if wants.any() {
            let (block, sockets) = attached
                .allocator
                .take(wants)
                .map_err(InstallError::Endpoints)?;
            (Some(block), sockets)
        } else {
            (None, Sockets::default())
        };
        let id = BoxId(cgroup.id());
        let spec = Self::spec_of(&node, facts.mode, own, block);
        let live = attached
            .handles
            .lock()
            .expect("engine lock")
            .install(id, spec);
        let live = match live {
            Ok(live) => live,
            Err(error) => {
                if let Some(block) = block {
                    drop(sockets);
                    attached.allocator.release(block);
                }
                return Err(match error {
                    boxbpf::Error::Compile(error) => Unenforceable::Compile(error).into(),
                    other => other.into(),
                });
            }
        };
        let installed = Arc::new(Installed {
            session: facts.session,
            id,
            facts,
            block,
            wants,
            compiled: RwLock::new(Arc::clone(live.compiled())),
            live: Mutex::new(live),
            limiter: Mutex::new(Limiter::new(Instant::now())),
            log,
            serving: Mutex::default(),
        });
        attached
            .boxes
            .write()
            .expect("engine lock")
            .insert(id, Arc::clone(&installed));
        attached
            .by_session
            .write()
            .expect("engine lock")
            .insert(installed.session, id);
        self.serve(attached, &installed, sockets);
        tracing::debug!(
            box_id = %installed.session,
            cgroup_id = id.0,
            resolver = wants.resolver,
            "installed the box's network policy"
        );
        Ok(Some(installed))
    }

    fn serve(&self, attached: &Attached, of: &Arc<Installed>, sockets: Sockets) {
        let Some(serving) = attached.serving.get() else {
            if of.wants.any() {
                tracing::error!(
                    box_id = %of.session,
                    "the box's endpoints have nothing to serve them; its DNS will not answer"
                );
            }
            return;
        };
        let _in_runtime = serving.runtime.enter();
        let mut tasks = Vec::new();
        let peers = || -> Option<Peers> {
            let made = attached.flows.try_clone().and_then(|flows| {
                let netns =
                    boxbpf::current_netns_cookie().map_err(|source| boxbpf::Error::Sys {
                        what: "read the network namespace cookie",
                        source,
                    })?;
                Ok(Peers { flows, netns })
            });
            match made {
                Ok(peers) => Some(peers),
                Err(error) => {
                    tracing::error!(%error, "an endpoint cannot ask the engine for its peers");
                    None
                }
            }
        };
        for socket in sockets.resolver_udp {
            let Some(peers) = peers() else { continue };
            let made = socket
                .set_nonblocking(true)
                .and_then(|()| tokio::net::UdpSocket::from_std(socket));
            match made {
                Ok(socket) => tasks.push(
                    serving
                        .runtime
                        .spawn(super::resolver::serve_udp(
                            Arc::clone(&serving.resolver),
                            Arc::clone(of),
                            peers,
                            socket,
                        ))
                        .abort_handle(),
                ),
                Err(error) => tracing::error!(%error, "a resolver endpoint cannot be served"),
            }
        }
        let listen = |listener: std::net::TcpListener| {
            listener
                .set_nonblocking(true)
                .and_then(|()| tokio::net::TcpListener::from_std(listener))
        };
        for listener in sockets.resolver_tcp {
            let Some(peers) = peers() else { continue };
            match listen(listener) {
                Ok(listener) => tasks.push(
                    serving
                        .runtime
                        .spawn(super::resolver::serve_tcp(
                            Arc::clone(&serving.resolver),
                            Arc::clone(of),
                            peers,
                            listener,
                        ))
                        .abort_handle(),
                ),
                Err(error) => tracing::error!(%error, "a resolver endpoint cannot be served"),
            }
        }
        for listener in sockets.hostname_proxy {
            let Some(peers) = peers() else { continue };
            match listen(listener) {
                Ok(listener) => tasks.push(
                    serving
                        .runtime
                        .spawn(
                            serving
                                .hostname_proxy
                                .serve(listener, Arc::clone(of), peers),
                        )
                        .abort_handle(),
                ),
                Err(error) => tracing::error!(%error, "a proxy endpoint cannot be served"),
            }
        }
        *of.serving.lock().expect("endpoint task lock") = tasks;
    }

    /// Compiles the box's policy again and writes what changed: after its
    /// facts changed, or the node's.
    fn recompile(
        attached: &Attached,
        of: &Installed,
        facts: &BoxFacts,
    ) -> Result<(), InstallError> {
        let own = spec::box_policy(
            facts.policy.egress.as_ref(),
            facts.mode,
            facts.deny_all_opt_out,
        )
        .map_err(Unenforceable::Spec)?;
        let node = attached.node.read().expect("engine lock").clone();
        let spec = Self::spec_of(&node, facts.mode, own, of.block);
        let mut live = of.live.lock().expect("live box lock");
        if *live.spec() == spec {
            return Ok(());
        }
        attached
            .handles
            .lock()
            .expect("engine lock")
            .reconfigure(&mut live, spec)?;
        *of.compiled.write().expect("compiled policy lock") = Arc::clone(live.compiled());
        Ok(())
    }

    /// Whether the box's entry was written for these facts.
    pub(crate) fn matches(of: &Installed, facts: &BoxFacts) -> bool {
        of.facts.mode == facts.mode
            && of.facts.policy.egress == facts.policy.egress
            && of.facts.deny_all_opt_out == facts.deny_all_opt_out
    }

    /// Tells the engine where the node's hostname proxy listens, once it
    /// is bound. Boxes that are running get the redirect now.
    pub(crate) fn set_node_hostname_proxy(&self, listeners: Vec<SocketAddr>) {
        let Some(attached) = self.attached_state() else {
            return;
        };
        {
            let mut node = attached.node.write().expect("engine lock");
            if node.hostname_proxy == listeners {
                return;
            }
            node.hostname_proxy = listeners;
        }
        let boxes: Vec<Arc<Installed>> = attached
            .boxes
            .read()
            .expect("engine lock")
            .values()
            .cloned()
            .collect();
        for of in boxes {
            if let Err(error) = Self::recompile(attached, &of, &of.facts) {
                tracing::error!(
                    box_id = %of.session,
                    %error,
                    "the box's network policy could not be updated for the hostname proxy"
                );
            }
        }
    }

    /// Takes the box out of the maps and closes its endpoints. Call after
    /// the box's cgroup was killed.
    pub(crate) fn uninstall(&self, session: SessionId) {
        let Some(attached) = self.attached_state() else {
            return;
        };
        let Some(id) = attached
            .by_session
            .write()
            .expect("engine lock")
            .remove(&session)
        else {
            return;
        };
        let Some(of) = attached.boxes.write().expect("engine lock").remove(&id) else {
            return;
        };
        for task in of.serving.lock().expect("endpoint task lock").drain(..) {
            task.abort();
        }
        let mut handles = attached.handles.lock().expect("engine lock");
        let counters = handles.stats(id).ok().flatten();
        let removed = handles.uninstall(&of.live.lock().expect("live box lock"));
        drop(handles);
        if let Err(error) = removed {
            tracing::warn!(box_id = %session, %error, "removing the box's network policy");
        }
        if let Some(block) = of.block {
            attached.allocator.release(block);
        }
        if let Some(c) = counters {
            tracing::info!(
                box_id = %session,
                tx_packets = c.tx_pkts,
                tx_bytes = c.tx_bytes,
                rx_packets = c.rx_pkts,
                rx_bytes = c.rx_bytes,
                tx_dropped = c.tx_drop,
                rx_dropped = c.rx_drop,
                refused = c.refused,
                events_lost = c.ev_lost,
                events_limited = c.ev_limited,
                "removed the box's network policy"
            );
        }
    }

    /// The address to write into the box's resolver file, when the box's
    /// DNS goes to an endpoint of its own.
    // Only the real launcher asks, which the unit tests replace.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn resolver_address(&self, cgroup: &BoxCgroup) -> Option<std::net::Ipv4Addr> {
        self.by_cgroup(BoxId(cgroup.id()))
            .filter(|of| of.wants.resolver)
            .map(|_| endpoints::V4)
    }

    pub(crate) fn installed(&self, session: SessionId) -> Option<Arc<Installed>> {
        let attached = self.attached_state()?;
        let id = *attached
            .by_session
            .read()
            .expect("engine lock")
            .get(&session)?;
        self.by_cgroup(id)
    }

    fn by_cgroup(&self, id: BoxId) -> Option<Arc<Installed>> {
        self.attached_state()?
            .boxes
            .read()
            .expect("engine lock")
            .get(&id)
            .cloned()
    }

    /// Admits `addr` for the box as an address of `name`, for the pin
    /// lifetime.
    pub(crate) fn pin(
        &self,
        of: &Installed,
        addr: IpAddr,
        name: &str,
    ) -> Result<(), boxbpf::Error> {
        let Some(attached) = self.attached_state() else {
            return Ok(());
        };
        attached
            .handles
            .lock()
            .expect("engine lock")
            .pin(of.id, addr, name, netpol::pins::PIN_TTL)
    }

    /// Judges a flow of the box as the kernel programs would. `name` is
    /// the host name the flow is for, when the caller knows it: it stands
    /// for a pin of the destination.
    pub(crate) fn evaluate(
        &self,
        of: &Installed,
        flow: &netpol::Flow,
        name: Option<&str>,
    ) -> netpol::Decision {
        let compiled = of.compiled();
        let pinned = name
            .and_then(|name| compiled.set_for_name(name))
            .or_else(|| {
                self.attached_state()?
                    .handles
                    .lock()
                    .expect("engine lock")
                    .pinned_set(of.id, flow.remote)
            });
        compiled.evaluate(flow, pinned)
    }

    /// Makes the box's entry match `facts`, when a launch finds the entry
    /// a different launch wrote.
    pub(crate) fn reconfigure(&self, of: &Installed, facts: &BoxFacts) -> Result<(), InstallError> {
        let Some(attached) = self.attached_state() else {
            return Ok(());
        };
        Self::recompile(attached, of, facts)
    }
}

#[cfg(test)]
mod tests {
    use boxes::EgressPolicy;

    use super::*;

    fn egress(edit: impl FnOnce(&mut EgressPolicy)) -> BoxPolicy {
        let mut section = EgressPolicy {
            allow_subnets: None,
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: None,
        };
        edit(&mut section);
        BoxPolicy::new(Some(section), None)
    }

    fn list(entries: &[&str]) -> Option<Vec<String>> {
        Some(entries.iter().map(|e| (*e).to_owned()).collect())
    }

    #[test]
    fn without_an_engine_only_boxes_with_nothing_to_enforce_run() {
        let socket = PathBuf::from("/run/minimal/policy-loader.sock");
        let engine = Engine::absent(Absent::NoLoader {
            socket: socket.clone(),
        });
        let host = NetworkMode::HostNet;
        for policy in [BoxPolicy::new(None, None), egress(|_| {})] {
            assert_eq!(
                engine.can_enforce(host, &policy, false),
                Ok(()),
                "{policy:?}"
            );
        }
        let restricted = [
            BoxPolicy::new(Some(EgressPolicy::deny_all()), None),
            egress(|e| e.allow_subnets = list(&["10.0.0.0/8"])),
            egress(|e| e.allow_subnets = list(&[])),
            egress(|e| e.allow_dns_hosts = list(&["example.com"])),
            egress(|e| e.deny_subnets = list(&["10.0.0.0/8"])),
            egress(|e| e.allow_protocols = Some(Vec::new())),
        ];
        for policy in &restricted {
            let refusal = engine
                .can_enforce(host, policy, false)
                .expect_err("needs the engine");
            assert_eq!(
                refusal,
                Unenforceable::NoEngine(Absent::NoLoader {
                    socket: socket.clone()
                }),
                "{policy:?}"
            );
            let text = refusal.to_string();
            assert!(text.contains("min finalize-install"), "{text}");
            // A box with no network has nothing to enforce, and one with
            // its own address is judged by its relay.
            assert_eq!(
                engine.can_enforce(NetworkMode::NoNet, policy, false),
                Ok(())
            );
            assert_eq!(
                engine.can_enforce(NetworkMode::OwnIp, policy, false),
                Ok(())
            );
        }
    }

    #[test]
    fn each_reason_for_no_engine_names_its_fix() {
        let text = |why: Absent| Unenforceable::NoEngine(why).to_string();
        assert!(text(Absent::LoaderOutOfDate).contains("min finalize-install"));
        assert!(text(Absent::NoCgroupRoot).contains("Delegate=yes"));
        let refused = text(Absent::LoaderRefused("the peer runs in /x".to_owned()));
        assert!(refused.contains("the peer runs in /x") && !refused.ends_with(' '));
    }

    #[test]
    fn settings_nothing_applies_to_a_host_address_box_are_refused_by_name() {
        let engine = Engine::absent(Absent::NotStarted);
        let mut blocked = BoxPolicy::new(None, None);
        blocked.quic443 = Some(boxes::core::bep::Quic443::Block);
        assert_eq!(
            engine.can_enforce(NetworkMode::HostNet, &blocked, false),
            Err(Unenforceable::Setting("quic443"))
        );
        assert_eq!(
            engine.can_enforce(NetworkMode::OwnIp, &blocked, false),
            Ok(())
        );
    }

    #[test]
    fn a_policy_entry_that_does_not_parse_is_refused_with_the_entry() {
        let engine = Engine::absent(Absent::NotStarted);
        let policy = egress(|e| e.allow_subnets = list(&["not-a-subnet"]));
        let refusal = engine
            .can_enforce(NetworkMode::HostNet, &policy, false)
            .expect_err("a bad subnet");
        assert!(refusal.to_string().contains("not-a-subnet"), "{refusal}");
    }
}
