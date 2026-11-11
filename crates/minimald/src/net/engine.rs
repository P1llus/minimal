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
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock},
    time::{Duration, Instant},
};

use boxbpf::{BoxId, Flows, Handles, LiveBox, OriginalDestination};
use boxes::{BoxPolicy, NetworkMode, SessionId};
use netpol::{
    Compiled, Protocol, Verdict,
    base::{PortOf, Services},
    compile::Spec,
};
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
    /// The node has no network to give the box.
    NoNetwork(&'static str),
    /// A setting nothing applies yet.
    Setting(&'static str),
    NoEngine(Absent),
    Spec(SpecError),
    Compile(netpol::CompileError),
}

impl std::fmt::Display for Unenforceable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the box did not start: ")?;
        match self {
            Self::NoNetwork(why) => write!(
                f,
                "it asks for a network, and this VM has none: {why}. A box with \
                 `--network none` starts."
            ),
            Self::Setting(setting) => write!(
                f,
                "its network policy sets `{setting}`, which this version of Minimal cannot \
                 apply. Remove the setting."
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
    #[error("the box's network policy was removed")]
    Removed,
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
    block: Option<Block>,
    /// Whether the box's processes have a network namespace of their own,
    /// where its endpoints are bound when it has one.
    own_namespace: bool,
    /// Whether the box sits on the virtual network: alone in a namespace of
    /// its own, or with a guest node whose address is on it.
    on_virtual_network: bool,
    /// The address the box is told for the host's name.
    host_alias: Option<Ipv4Addr>,
    wants: Wants,
    /// The box's entry and what it was written for. Every writer takes
    /// this lock first and the engine's handles second.
    entry: Mutex<Entry>,
    /// The policy as the kernel has it, for readers that must not wait for
    /// a writer.
    compiled: RwLock<Arc<Compiled>>,
    limiter: Mutex<Limiter>,
    log: Arc<dyn Log>,
    /// The tasks serving the box's endpoints. Aborting one closes its socket.
    serving: Mutex<Vec<tokio::task::AbortHandle>>,
    /// Notified when a socket of the box starts or stops listening.
    listen_wake: Arc<tokio::sync::Notify>,
}

struct Entry {
    live: LiveBox,
    facts: BoxFacts,
    /// Set when the box was taken out of the maps. A writer that comes
    /// late must not put it back: its processes may have outlived the kill.
    removed: bool,
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

    /// Whether the box reaches a peer at the peer's address on the virtual
    /// network. A box that shares a native node's address reaches it at
    /// the node's loopback, where the peer's ports are published.
    pub(crate) const fn on_virtual_network(&self) -> bool {
        self.on_virtual_network
    }

    /// The address that stands for the host's loopback for this box.
    pub(crate) const fn host_alias(&self) -> Option<Ipv4Addr> {
        self.host_alias
    }

    /// A snapshot of the box's compiled policy.
    pub(crate) fn compiled(&self) -> Arc<Compiled> {
        Arc::clone(&self.compiled.read().expect("compiled policy lock"))
    }

    /// The prefixes the box allows, for the resolver's rebinding filter.
    pub(crate) fn allowed_prefixes(&self) -> Vec<netpol::Prefix> {
        self.entry
            .lock()
            .expect("box entry lock")
            .live
            .spec()
            .policy
            .allow
            .clone()
    }

    /// Addresses of the node's infrastructure, which a public name has no
    /// business resolving to.
    pub(crate) fn infrastructure(&self) -> Vec<netpol::Prefix> {
        let entry = self.entry.lock().expect("box entry lock");
        let deployment = &entry.live.spec().deployment;
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
        self.entry
            .lock()
            .expect("box entry lock")
            .live
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
    /// Opens the host's end of a connection a box made to the host alias.
    pub(crate) host_relay: Arc<dyn super::relay::Dial>,
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
    /// The network namespace the endpoint is in.
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

/// One network namespace of a box's own, with the box's address in it
/// known to the engine and the daemon's endpoints served inside.
pub(crate) struct Namespace {
    engine: &'static Engine,
    of: Arc<Installed>,
    address: std::net::Ipv4Addr,
    /// The namespace's cookie, when endpoints are served in it.
    netns: Option<u64>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Namespace {
    /// The listening sockets of the box in this namespace, as the engine
    /// records them. `None` without an engine.
    pub(crate) fn listeners(&self) -> Option<Arc<dyn super::listens::Listeners>> {
        let attached = self.engine.attached_state()?;
        let netns = self.netns?;
        let table = match attached.handles.lock().expect("engine lock").listens() {
            Ok(table) => table,
            Err(error) => {
                tracing::warn!(%error, "the engine's table of listening sockets cannot be read");
                return None;
            }
        };
        Some(Arc::new(super::listens::EngineListeners {
            table,
            of: self.of.id,
            netns,
            wake: Arc::clone(&self.of.listen_wake),
        }))
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        let Some(attached) = self.engine.attached_state() else {
            return;
        };
        let removed = attached
            .handles
            .lock()
            .expect("engine lock")
            .remove_own_address(self.of.id, self.address.into());
        if let Err(error) = removed {
            tracing::warn!(
                box_id = %self.of.session,
                address = %self.address,
                %error,
                "a box's address stays in its policy"
            );
        }
    }
}

/// The listening sockets of every box in the node's own namespace.
struct NodeListeners {
    engine: &'static Engine,
    table: boxbpf::Listens,
    netns: u64,
}

impl super::listens::Listeners for NodeListeners {
    fn listening(&self) -> std::io::Result<Vec<super::listens::Listener>> {
        let Some(attached) = self.engine.attached_state() else {
            return Ok(Vec::new());
        };
        let sharing: Vec<BoxId> = attached
            .boxes
            .read()
            .expect("engine lock")
            .values()
            .filter(|of| !of.own_namespace)
            .map(|of| of.id)
            .collect();
        let mut all = Vec::new();
        for id in sharing {
            let listening = self
                .table
                .listening(id, self.netns)
                .map_err(std::io::Error::other)?;
            all.extend(
                listening
                    .into_iter()
                    .map(|socket| super::listens::Listener {
                        address: socket.address,
                        port: socket.port,
                    }),
            );
        }
        Ok(all)
    }

    fn changed(&self) -> futures::future::BoxFuture<'_, ()> {
        match self.engine.attached_state() {
            Some(attached) => Box::pin(async move { attached.listen_wake.notified().await }),
            None => Box::pin(std::future::pending()),
        }
    }
}

struct Attached {
    handles: Mutex<Handles>,
    flows: Flows,
    node: RwLock<Node>,
    boxes: RwLock<HashMap<BoxId, Arc<Installed>>>,
    by_session: RwLock<HashMap<SessionId, BoxId>>,
    /// Notified when a socket of any box starts or stops listening.
    listen_wake: Arc<tokio::sync::Notify>,
    allocator: Allocator,
    events: mpsc::Sender<events::Write>,
    /// Taken by [`Engine::start_tasks`].
    pending: Mutex<Option<(boxbpf::events::Source, mpsc::Receiver<events::Write>)>>,
    serving: OnceLock<Serving>,
}

impl Attached {
    /// Takes the handles as this daemon's engine.
    fn new(mut handles: Handles, node: Node) -> Result<Self, Absent> {
        let failed = |error: boxbpf::Error| Absent::Failed(error.to_string());
        let flows = handles.flows().map_err(failed)?;
        let source = handles
            .take_events()
            .ok_or_else(|| Absent::Failed("the engine has no event buffer".to_owned()))?;
        let (events, receiver) = mpsc::channel(EVENT_QUEUE);
        Ok(Self {
            handles: Mutex::new(handles),
            flows,
            node: RwLock::new(node),
            boxes: RwLock::default(),
            by_session: RwLock::default(),
            listen_wake: Arc::default(),
            allocator: Allocator::new(),
            events,
            pending: Mutex::new(Some((source, receiver))),
            serving: OnceLock::new(),
        })
    }
}

enum State {
    Attached(Box<Attached>),
    /// No programs are attached: boxes run unjudged, so only those that
    /// need no enforcement run.
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
/// Events waiting to be written. Each box's limiter runs before this
/// queue, so one box cannot fill it. What does not fit is counted for its
/// box and reported in the box's next summary.
const EVENT_QUEUE: usize = 4096;

pub(crate) fn loader_socket() -> PathBuf {
    std::env::var_os(LOADER_SOCKET_ENV)
        .map_or_else(|| PathBuf::from(paths::POLICY_LOADER_SOCKET), PathBuf::from)
}

/// Why the engine was not taken, and whether its programs may be attached
/// to the `boxes` cgroup all the same.
struct NotTaken {
    why: Absent,
    /// False when nothing was loaded: no loader was reached, or it refused
    /// the request. In every other case the programs come off again unless
    /// the side that attached them died first, which this side cannot see.
    may_be_attached: bool,
}

impl NotTaken {
    const fn clean(why: Absent) -> Self {
        Self {
            why,
            may_be_attached: false,
        }
    }

    const fn unclear(why: Absent) -> Self {
        Self {
            why,
            may_be_attached: true,
        }
    }
}

/// What went wrong between the request to the loader and its last word.
enum Failure {
    Loader(boxbpf::Error),
    /// The loader attached the engine, and this daemon could not take it.
    Setup(Absent),
}

impl From<boxbpf::Error> for Failure {
    fn from(error: boxbpf::Error) -> Self {
        Self::Loader(error)
    }
}

/// Asks the loader for the engine and takes it as this daemon's. The
/// loader learns that the engine is in use only after that, so a daemon
/// that cannot take it leaves the loader to detach the programs.
fn from_loader(
    boxes: std::os::fd::BorrowedFd<'_>,
    socket: &Path,
    node: Node,
) -> Result<Attached, NotTaken> {
    use boxbpf::Error;

    let no_loader = || {
        NotTaken::clean(Absent::NoLoader {
            socket: socket.to_owned(),
        })
    };
    if !socket.exists() {
        return Err(no_loader());
    }
    let taken = boxbpf::loader::request_then(socket, boxes, |handles| {
        Attached::new(handles, node).map_err(Failure::Setup)
    });
    taken.map_err(|failure| match failure {
        // The loader compares the two builds before it loads.
        Failure::Loader(Error::AbiMismatch { .. } | Error::ObjectMismatch { .. }) => {
            NotTaken::clean(Absent::LoaderOutOfDate)
        }
        Failure::Loader(Error::Refused(reason)) => NotTaken::clean(Absent::LoaderRefused(reason)),
        // Nothing listens at the socket: the connection was never made.
        Failure::Loader(Error::Sys { source, .. })
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            no_loader()
        }
        Failure::Loader(other) => NotTaken::unclear(Absent::Failed(other.to_string())),
        Failure::Setup(why) => NotTaken::unclear(why),
    })
}

impl Engine {
    /// Gets the engine for the box cgroups below `root` and makes it the
    /// one [`Engine::current`] returns. Says once what it got. Returns the
    /// root to run boxes in, which is another one than it was given when
    /// the `boxes` cgroup had to be replaced.
    pub(crate) fn boot(root: Option<Root>, node: Node) -> Option<Root> {
        let (engine, root) = Self::acquire(root, node, &loader_socket());
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
        root
    }

    fn acquire(root: Option<Root>, node: Node, socket: &Path) -> (Self, Option<Root>) {
        use std::os::fd::AsFd as _;

        let Some(root) = root else {
            return (Self::absent(Absent::NoCgroupRoot), None);
        };
        let boxes = match std::fs::File::open(root.dir().join(sandbox::cgroup::BOXES)) {
            Ok(dir) => std::os::fd::OwnedFd::from(dir),
            Err(error) => {
                let why = Absent::Failed(format!("opening the boxes cgroup: {error}"));
                return (Self::absent(why), Some(root));
            }
        };
        let taken = if nix::unistd::geteuid().is_root() {
            // A start that fails leaves nothing attached. One that works
            // leaves the programs attached whatever comes after it.
            boxbpf::Engine::start(boxes.as_fd(), &boxbpf::MapSizes::default())
                .map_err(|error| NotTaken::clean(Absent::Failed(error.to_string())))
                .and_then(|handles| Attached::new(handles, node).map_err(NotTaken::unclear))
        } else {
            from_loader(boxes.as_fd(), socket, node)
        };
        drop(boxes);
        match taken {
            Ok(attached) => (
                Self {
                    state: State::Attached(Box::new(attached)),
                },
                Some(root),
            ),
            Err(NotTaken {
                why,
                may_be_attached: false,
            }) => (Self::absent(why), Some(root)),
            Err(NotTaken { why, .. }) => {
                // Below programs whose maps nobody writes a box has no
                // network at all. A new `boxes` cgroup has no programs.
                let dir = root.dir().to_owned();
                drop(root);
                match Root::open(&dir) {
                    Ok(root) => (Self::absent(why), Some(root)),
                    Err(error) => {
                        tracing::error!(
                            root = %dir.display(),
                            %error,
                            "the boxes cgroup could not be replaced after the network policy \
                             engine failed to start; boxes run without a cgroup, and a box \
                             that needs one is refused"
                        );
                        (Self::absent(why), None)
                    }
                }
            }
        }
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
                Ok(netpol::event::Event::Net(event)) => event,
                Ok(netpol::event::Event::Listen(event)) => {
                    // The table is what counts. This only says to read it.
                    if let Some(of) = self.by_cgroup(BoxId(event.box_id)) {
                        of.listen_wake.notify_one();
                    }
                    if let Some(attached) = self.attached_state() {
                        attached.listen_wake.notify_one();
                    }
                    continue;
                }
                Ok(_) => continue,
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

    /// Reports a refusal. The box's limiter decides here, before the
    /// queue all boxes share, what becomes an event. Never waits: an event
    /// the queue has no room for is counted for the box.
    pub(crate) fn observe(&self, of: Arc<Installed>, refusal: events::NetRefusal) {
        let Some(attached) = self.attached_state() else {
            return;
        };
        let observation = Observation {
            of,
            body: events::Body::Net(refusal),
        };
        for (kind, data) in events::limited(&observation, Instant::now()) {
            let write = events::Write {
                of: Arc::clone(&observation.of),
                kind,
                data,
            };
            if attached.events.try_send(write).is_err() {
                observation.of.limiter().lost();
            }
        }
    }

    /// The first setting of `policy` that nothing applies to a box with a
    /// network.
    fn unapplied_setting(mode: NetworkMode, policy: &BoxPolicy) -> Option<&'static str> {
        if mode == NetworkMode::NoNet {
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
        if mode != NetworkMode::NoNet
            && let Some(why) = crate::guest_net::missing()
        {
            return Err(Unenforceable::NoNetwork(why));
        }
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
                // box with no network or with nothing to enforce asks for.
                // A box with its own address is closed unless it says
                // otherwise, so only one that opens everything runs.
                let unjudged = match mode {
                    NetworkMode::OwnIp => Verdict::Deny,
                    _ => Verdict::Allow,
                };
                let nothing_to_enforce =
                    own.rules().is_empty() && own.egress_default(unjudged) == Verdict::Allow;
                match mode {
                    NetworkMode::NoNet => Ok(()),
                    _ if nothing_to_enforce => Ok(()),
                    _ => Err(Unenforceable::NoEngine(why.clone())),
                }
            }
        }
    }

    fn wants(node: &Node, mode: NetworkMode, own: &netpol::BoxPolicy) -> Wants {
        Wants {
            resolver: spec::needs_resolver(node, mode, own),
            hostname_proxy: mode != NetworkMode::NoNet,
            host_relay: mode != NetworkMode::NoNet,
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
            host_relay: wants.host_relay.then(|| block.endpoint(Service::HostRelay)),
        });
        // In a namespace of its own a box has one block, and the rest of
        // the range is its own to bind.
        let ports = if mode == NetworkMode::OwnIp {
            endpoints::own_namespace_ports()
        } else {
            endpoints::port_range()
        };
        let ranges = spec::endpoint_ranges(&endpoints::addresses(), ports);
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
        &'static self,
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
        let own_namespace = facts.mode == NetworkMode::OwnIp;
        let (block, sockets) = if own_namespace {
            // Bound inside the namespace, once it exists.
            let block = Block::own_namespace(attached.allocator.v6());
            (Some(block), Sockets::default())
        } else if wants.any() {
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
        let on_virtual_network = spec.deployment.network.is_some();
        let host_alias = match spec.deployment.host_alias {
            Some(IpAddr::V4(alias)) => Some(alias),
            _ => None,
        };
        let live = attached
            .handles
            .lock()
            .expect("engine lock")
            .install(id, spec);
        let live = match live {
            Ok(live) => live,
            Err(error) => {
                if let Some(block) = block.filter(|_| !own_namespace) {
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
            block,
            own_namespace,
            on_virtual_network,
            host_alias,
            wants,
            compiled: RwLock::new(Arc::clone(live.compiled())),
            entry: Mutex::new(Entry {
                live,
                facts,
                removed: false,
            }),
            limiter: Mutex::new(Limiter::new(Instant::now())),
            log,
            serving: Mutex::default(),
            listen_wake: Arc::default(),
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
        if !own_namespace {
            let tasks = match boxbpf::current_netns_cookie() {
                Ok(netns) => self.serve(attached, &installed, sockets, netns),
                Err(error) => {
                    tracing::error!(%error, "the daemon's network namespace cannot be named");
                    Vec::new()
                }
            };
            *installed.serving.lock().expect("endpoint task lock") = tasks;
        }
        tracing::debug!(
            box_id = %installed.session,
            cgroup_id = id.0,
            resolver = wants.resolver,
            "installed the box's network policy"
        );
        Ok(Some(installed))
    }

    /// Serves `sockets`, the endpoints of `of` in the network namespace
    /// `netns`, and returns the tasks that do.
    fn serve(
        &'static self,
        attached: &Attached,
        of: &Arc<Installed>,
        sockets: Sockets,
        netns: u64,
    ) -> Vec<tokio::task::AbortHandle> {
        let Some(serving) = attached.serving.get() else {
            if of.wants.any() {
                tracing::error!(
                    box_id = %of.session,
                    "the box's endpoints have nothing to serve them; its DNS will not answer"
                );
            }
            return Vec::new();
        };
        let _in_runtime = serving.runtime.enter();
        let mut tasks = Vec::new();
        let peers = || -> Option<Peers> {
            match attached
                .flows
                .try_clone()
                .map(|flows| Peers { flows, netns })
            {
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
        for listener in sockets.host_relay {
            let Some(peers) = peers() else { continue };
            match listen(listener) {
                Ok(listener) => tasks.push(
                    serving
                        .runtime
                        .spawn(super::relay::serve(
                            listener,
                            self,
                            Arc::clone(of),
                            peers,
                            Service::HostRelay,
                            Arc::clone(&serving.host_relay),
                        ))
                        .abort_handle(),
                ),
                Err(error) => tracing::error!(%error, "a host relay endpoint cannot be served"),
            }
        }
        tasks
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
        let mut spec = Self::spec_of(&node, facts.mode, own, of.block);
        let mut entry = of.entry.lock().expect("box entry lock");
        if entry.removed {
            return Ok(());
        }
        // Published ports come and go while the box runs. No fact of the
        // box names them, so the entry itself is their record.
        spec.deployment
            .published
            .clone_from(&entry.live.spec().deployment.published);
        if *entry.live.spec() != spec {
            attached
                .handles
                .lock()
                .expect("engine lock")
                .reconfigure(&mut entry.live, spec)?;
            *of.compiled.write().expect("compiled policy lock") = Arc::clone(entry.live.compiled());
        }
        entry.facts = facts.clone();
        Ok(())
    }

    /// Admits new inbound flows to a port of the box. Without an engine
    /// nothing judges the box's flows, and there is nothing to write.
    pub(crate) fn publish(&self, of: &Installed, port: PortOf) -> Result<(), InstallError> {
        let Some(attached) = self.attached_state() else {
            return Ok(());
        };
        let mut entry = of.entry.lock().expect("box entry lock");
        if entry.removed {
            return Err(InstallError::Removed);
        }
        attached
            .handles
            .lock()
            .expect("engine lock")
            .publish(&mut entry.live, port)?;
        *of.compiled.write().expect("compiled policy lock") = Arc::clone(entry.live.compiled());
        Ok(())
    }

    /// Stops admitting new inbound flows to a port of the box.
    pub(crate) fn unpublish(&self, of: &Installed, port: PortOf) -> Result<(), InstallError> {
        let Some(attached) = self.attached_state() else {
            return Ok(());
        };
        let mut entry = of.entry.lock().expect("box entry lock");
        if entry.removed {
            return Ok(());
        }
        attached
            .handles
            .lock()
            .expect("engine lock")
            .unpublish(&mut entry.live, port)?;
        *of.compiled.write().expect("compiled policy lock") = Arc::clone(entry.live.compiled());
        Ok(())
    }

    /// Makes a network namespace of the box's own usable: `address` becomes
    /// an address the box may send from, and the daemon's endpoints for the
    /// box are bound and served inside, on sockets `spawned` makes there.
    /// Dropping the result takes both back.
    ///
    /// A box has one such namespace for its session and one for each task
    /// that runs beside it.
    pub(crate) fn serve_namespace(
        &'static self,
        of: &Arc<Installed>,
        spawned: &sandbox::Spawned,
        address: std::net::Ipv4Addr,
    ) -> Result<Namespace, InstallError> {
        let Some(attached) = self.attached_state() else {
            return Ok(Namespace {
                engine: self,
                of: Arc::clone(of),
                address,
                netns: None,
                tasks: Vec::new(),
            });
        };
        attached
            .handles
            .lock()
            .expect("engine lock")
            .add_own_address(of.id, address.into())?;
        // From here the address is taken back when this returns early.
        let mut namespace = Namespace {
            engine: self,
            of: Arc::clone(of),
            address,
            netns: None,
            tasks: Vec::new(),
        };
        let Some(block) = of.block.filter(|_| of.own_namespace) else {
            return Ok(namespace);
        };
        let sockets = endpoints::bind_with(block, of.wants, &|v6, datagram| {
            spawned.socket_for_daemon(v6, datagram)
        })
        .map_err(InstallError::Endpoints)?;
        let netns = sockets
            .resolver_udp
            .first()
            .map(|socket| std::os::fd::AsFd::as_fd(socket))
            .or_else(|| {
                sockets
                    .hostname_proxy
                    .first()
                    .map(|socket| std::os::fd::AsFd::as_fd(socket))
            })
            .map(boxbpf::netns_cookie)
            .transpose()
            .map_err(InstallError::Endpoints)?;
        if let Some(netns) = netns {
            namespace.netns = Some(netns);
            namespace.tasks = self.serve(attached, of, sockets, netns);
        }
        Ok(namespace)
    }

    /// Tells the engine which virtual network boxes with an address of
    /// their own sit on, once the node's switch is made.
    pub(crate) fn set_node_switch(&self, subnet: switch::SwitchSubnet) {
        if let Some(attached) = self.attached_state() {
            attached.node.write().expect("engine lock").switch = Some(subnet);
        }
    }

    /// The listening sockets of the boxes that share the node's network
    /// namespace, as the engine records them. `None` without an engine.
    pub(crate) fn node_listeners(&'static self) -> Option<Arc<dyn super::listens::Listeners>> {
        let attached = self.attached_state()?;
        let table = attached
            .handles
            .lock()
            .expect("engine lock")
            .listens()
            .map_err(std::io::Error::other);
        match table.and_then(|table| Ok((table, boxbpf::current_netns_cookie()?))) {
            Ok((table, netns)) => Some(Arc::new(NodeListeners {
                engine: self,
                table,
                netns,
            })),
            Err(error) => {
                tracing::warn!(%error, "the engine's table of listening sockets cannot be read");
                None
            }
        }
    }

    /// Whether the box's entry was written for these facts.
    pub(crate) fn matches(of: &Installed, facts: &BoxFacts) -> bool {
        let entry = of.entry.lock().expect("box entry lock");
        entry.facts.mode == facts.mode
            && entry.facts.policy.egress == facts.policy.egress
            && entry.facts.deny_all_opt_out == facts.deny_all_opt_out
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
            let facts = of.entry.lock().expect("box entry lock").facts.clone();
            if let Err(error) = Self::recompile(attached, &of, &facts) {
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
        // The box's lock first, as every writer does, and the mark under
        // it: a recompile that waited for this lock finds the box removed.
        let mut entry = of.entry.lock().expect("box entry lock");
        entry.removed = true;
        let mut handles = attached.handles.lock().expect("engine lock");
        let counters = handles.stats(id).ok().flatten();
        let removed = handles.uninstall(&entry.live);
        drop(handles);
        drop(entry);
        if let Err(error) = removed {
            tracing::warn!(box_id = %session, %error, "removing the box's network policy");
        }
        if let Some(block) = of.block.filter(|_| !of.own_namespace) {
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

    /// The box whose cgroup is `cgroup`, when the engine judges it.
    // Only the real launches ask, which the unit tests replace.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn of_cgroup(&self, cgroup: &BoxCgroup) -> Option<Arc<Installed>> {
        self.by_cgroup(BoxId(cgroup.id()))
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
        compiled.evaluate(flow, |_| pinned)
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
            // A box with no network has nothing to enforce. One with its
            // own address has, as much as one that shares the node's.
            assert_eq!(
                engine.can_enforce(NetworkMode::NoNet, policy, false),
                Ok(())
            );
            assert_eq!(
                engine.can_enforce(NetworkMode::OwnIp, policy, false),
                Err(Unenforceable::NoEngine(Absent::NoLoader {
                    socket: socket.clone()
                }))
            );
        }
    }

    /// A loader that answers one request with `reply` and no descriptors.
    fn fake_loader(socket: &Path, reply: String) -> std::thread::JoinHandle<()> {
        use nix::sys::socket::{
            AddressFamily, Backlog, MsgFlags, SockFlag, SockType, UnixAddr, accept, bind, listen,
            recv, send, socket as new_socket,
        };
        use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

        let listener = new_socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .expect("socket");
        bind(
            listener.as_raw_fd(),
            &UnixAddr::new(socket).expect("address"),
        )
        .expect("bind");
        listen(&listener, Backlog::new(1).expect("backlog")).expect("listen");
        std::thread::spawn(move || {
            let conn = accept(listener.as_raw_fd()).expect("accept");
            // SAFETY: `accept` returned a descriptor nothing else owns.
            let conn = unsafe { OwnedFd::from_raw_fd(conn) };
            let mut request = [0u8; 256];
            recv(conn.as_raw_fd(), &mut request, MsgFlags::empty()).expect("the request");
            send(conn.as_raw_fd(), reply.as_bytes(), MsgFlags::empty()).expect("the reply");
        })
    }

    #[test]
    fn an_engine_that_was_not_taken_leaves_no_program_over_the_boxes() {
        use std::os::unix::fs::MetadataExt as _;

        let test =
            "net::engine::tests::an_engine_that_was_not_taken_leaves_no_program_over_the_boxes";
        let Some(root) = sandbox::cgroup::testing::delegated_root(test) else {
            return;
        };
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipped: root loads the engine itself and asks no loader");
            return;
        }
        let dir = tempfile::tempdir().expect("a directory for the sockets");
        let boxes_of = |root: &Root| {
            std::fs::metadata(root.dir().join(sandbox::cgroup::BOXES))
                .expect("the boxes cgroup")
                .ino()
        };
        let open = BoxPolicy::new(None, None);

        // The loader says it attached and sends no maps. Whether its
        // programs are off again is its word alone, so the boxes get a
        // cgroup nothing was ever attached to.
        let before = boxes_of(&root);
        let socket = dir.path().join("attached.sock");
        let loader = fake_loader(&socket, format!("ok abi={} cgroup=7", netpol::abi::VERSION));
        let (engine, root) = Engine::acquire(Some(root), Node::native(), &socket);
        loader.join().expect("the loader");
        assert!(
            matches!(engine.state, State::Absent(Absent::Failed(_))),
            "the engine was taken"
        );
        let root = root.expect("the root stays usable");
        assert_ne!(boxes_of(&root), before, "the boxes cgroup was kept");
        assert_eq!(
            engine.can_enforce(NetworkMode::HostNet, &open, false),
            Ok(())
        );
        let id = "0191e0c8-0000-7000-8000-00000000000a";
        root.create_box(id)
            .expect("a box cgroup in the new boxes cgroup")
            .destroy_blocking(Duration::from_secs(5))
            .expect("removing it");

        // A loader of another build refuses before it loads anything, so
        // the cgroup stays as it is.
        let before = boxes_of(&root);
        let socket = dir.path().join("refusing.sock");
        let loader = fake_loader(&socket, "err object mismatch loader=abc".to_owned());
        let (engine, root) = Engine::acquire(Some(root), Node::native(), &socket);
        loader.join().expect("the loader");
        assert!(matches!(
            engine.state,
            State::Absent(Absent::LoaderOutOfDate)
        ));
        let root = root.expect("the root");
        assert_eq!(boxes_of(&root), before);
        assert_eq!(
            engine.can_enforce(NetworkMode::HostNet, &open, false),
            Ok(())
        );
        let restricted = egress(|e| e.allow_subnets = list(&["10.0.0.0/8"]));
        let refusal = engine
            .can_enforce(NetworkMode::HostNet, &restricted, false)
            .expect_err("needs the engine");
        assert!(
            refusal.to_string().contains("min finalize-install"),
            "{refusal}"
        );
    }

    #[test]
    fn a_daemon_with_no_cgroup_root_runs_a_host_address_box_that_allows_everything() {
        let engine = Engine::absent(Absent::NoCgroupRoot);
        let open = BoxPolicy::new(None, None);
        assert_eq!(
            engine.can_enforce(NetworkMode::HostNet, &open, false),
            Ok(())
        );
        let restricted = egress(|e| e.allow_subnets = list(&["10.0.0.0/8"]));
        let refusal = engine
            .can_enforce(NetworkMode::HostNet, &restricted, false)
            .expect_err("needs the engine");
        assert!(refusal.to_string().contains("Delegate=yes"), "{refusal}");
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
            Err(Unenforceable::Setting("quic443"))
        );
        assert_eq!(
            engine.can_enforce(NetworkMode::NoNet, &blocked, false),
            Ok(())
        );
    }

    #[test]
    fn a_box_with_its_own_address_is_closed_unless_it_says_otherwise() {
        let engine = Engine::absent(Absent::NoCgroupRoot);
        let silent = BoxPolicy::new(None, None);
        // No egress section means nothing leaves, which only an engine
        // can hold the box to.
        assert!(
            engine
                .can_enforce(NetworkMode::OwnIp, &silent, false)
                .is_err()
        );
        // Under the daemon's opt-out the same box allows everything.
        assert_eq!(
            engine.can_enforce(NetworkMode::OwnIp, &silent, true),
            Ok(())
        );
        assert_eq!(
            engine.can_enforce(NetworkMode::HostNet, &silent, false),
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
