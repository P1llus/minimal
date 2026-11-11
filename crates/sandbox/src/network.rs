//! Per-sandbox network configuration.
//!
//! [`Network`] decouples network setup from sandbox consumers: any sandbox —
//! build, task, or session — configures networking the same way, via
//! [`Config::with_network`](crate::Config::with_network). The built-in
//! [`HostNet`]/[`NoNet`] cover the consumer-agnostic modes; richer modes (e.g.
//! an own-IP gvproxy switch attach) are supplied by consumers as out-of-crate
//! `impl Network`, keeping switch/tap/relay logic out of `sandbox`.
//!
//! This respects the deployment-model ownership rule (spec R1.4): the gvproxy
//! **process** is owned by `minimald` (DM2) or `minvmd` (DM1/3/4), never by
//! `sandbox`. `sandbox` only decides netns isolation (pre-spawn) and invokes
//! the consumer-provided wiring against an already-running switch (post-spawn).

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;

/// The future returned by [`Network::plan`].
pub type PlanFuture<'a> = Pin<Box<dyn Future<Output = Result<NetPlan, NetworkError>> + Send + 'a>>;

/// The future returned by [`Network::attach`].
pub type AttachFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn NetGuard>, NetworkError>> + Send + 'a>>;

/// The future returned by [`Network::abandon`].
pub type AbandonFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// What `/etc/resolv.conf` should say inside the sandbox. The container build
/// is the one place that acts on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Resolver {
    /// Leave the rootfs's `/etc/resolv.conf` alone.
    #[default]
    None,
    /// Synthesise one from the host's resolver, unless the rootfs already has
    /// one. Correct only in a namespace that can reach it.
    Host,
    /// Write these nameservers. An isolated sandbox needs this: the host's stub
    /// resolver (`127.0.0.53`) is unreachable from a fresh netns.
    Nameservers(Vec<Ipv4Addr>),
}

/// What a sandbox needs from its network, decided before the process starts.
///
/// Data, not behaviour: it says what the sandbox needs and not how a
/// provider obtains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPlan {
    isolate_netns: bool,
    /// Whether the provider gives the namespace its interface once the
    /// container exists. The sandbox's program waits until it has.
    wired: bool,
    resolver: Resolver,
    hosts: Vec<HostEntry>,
}

/// A static `name → address` line the container build writes into the
/// sandbox's `/etc/hosts`, so a name the box's resolver does not know still
/// answers (NSS consults `/etc/hosts` before DNS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    /// The name to answer, as written — `/etc/hosts` needs no zone suffix.
    pub name: String,
    /// The address the name answers with.
    pub address: Ipv4Addr,
}

impl std::fmt::Display for NetPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.isolate_netns {
            write!(f, "host_ip")
        } else if self.wired {
            write!(f, "own_ip")
        } else {
            write!(f, "isolated")
        }
    }
}

impl NetPlan {
    /// Share the host's (or VM's) network namespace.
    #[must_use]
    pub fn host() -> Self {
        Self {
            isolate_netns: false,
            wired: false,
            resolver: Resolver::None,
            hosts: Vec::new(),
        }
    }

    /// A fresh, empty network namespace: only a down `lo`, so every egress
    /// attempt fails.
    #[must_use]
    pub fn isolated() -> Self {
        Self {
            isolate_netns: true,
            wired: false,
            resolver: Resolver::None,
            hosts: Vec::new(),
        }
    }

    /// A fresh network namespace that the provider wires once the container
    /// exists: its `attach` sets the interface up through [`Spawned::link`].
    #[must_use]
    pub fn isolated_wired() -> Self {
        Self {
            isolate_netns: true,
            wired: true,
            resolver: Resolver::None,
            hosts: Vec::new(),
        }
    }

    /// Sets what `/etc/resolv.conf` should say.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// Adds a static `/etc/hosts` entry for the sandbox.
    #[must_use]
    pub fn with_hosts_entry(mut self, name: impl Into<String>, address: Ipv4Addr) -> Self {
        self.hosts.push(HostEntry {
            name: name.into(),
            address,
        });
        self
    }

    /// Whether the sandbox runs in its own unshared network namespace.
    #[must_use]
    pub fn isolates_netns(&self) -> bool {
        self.isolate_netns
    }

    /// Whether the provider sets the namespace's interface up after the
    /// container exists.
    #[must_use]
    pub fn wired(&self) -> bool {
        self.wired
    }

    /// What to write to `/etc/resolv.conf`.
    #[must_use]
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// The static `/etc/hosts` entries to write.
    #[must_use]
    pub fn hosts(&self) -> &[HostEntry] {
        &self.hosts
    }
}

/// A plan is its own provider, reserving nothing: what a sandbox with no
/// provider of its own launches through, so there is one launch sequence.
impl Network for NetPlan {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(self.clone())))
    }
}

/// An error from [`Network::attach`]. Wraps a consumer error so `sandbox` need
/// not know the concrete failure type.
#[derive(Debug)]
pub struct NetworkError(pub Box<dyn std::error::Error + Send + Sync>);

impl NetworkError {
    /// Wraps any error as a [`NetworkError`].
    #[must_use]
    pub fn new<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self(Box::new(err))
    }
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network attach failed: {}", self.0)
    }
}

impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Per-sandbox network configuration, in three operations around the spawn.
///
/// `plan` runs before the container is built, `attach` after the process
/// starts, and `abandon` releases what `plan` reserved when no `attach`
/// follows. The sandbox layer runs `abandon` on every path out of a launch
/// that does not reach `attach`, including a cancelled one.
pub trait Network: Send + Sync + std::fmt::Debug {
    /// Before the process starts: reserve what the sandbox needs (a lease, a
    /// switch), and describe it.
    fn plan(&self) -> PlanFuture<'_>;

    /// After the process starts: wire its network namespace. Returns a
    /// [`NetGuard`] whose [`teardown`](NetGuard::teardown) reverses the wiring.
    ///
    /// The default is a no-op, for modes that need no post-spawn work
    /// ([`HostNet`], [`NoNet`]).
    fn attach(&self, spawned: Spawned) -> AttachFuture<'_> {
        drop(spawned);
        Box::pin(std::future::ready(Ok(noop_guard())))
    }

    /// Release whatever [`plan`](Self::plan) reserved, when no
    /// [`attach`](Self::attach) will follow. Runs at most once per `plan`, and
    /// never after a successful `attach`. The default is a no-op.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

/// What a launched sandbox process hands to [`Network::attach`].
#[derive(Debug, Default)]
pub struct Spawned {
    netns: Option<std::os::fd::OwnedFd>,
    /// The way to the container's spawner jobs.
    #[cfg(target_os = "linux")]
    job: Option<crate::Entrance>,
}

impl Spawned {
    /// A launched process with no network namespace of its own.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the sandbox's own network namespace.
    #[must_use]
    pub fn with_netns(mut self, netns: std::os::fd::OwnedFd) -> Self {
        self.netns = Some(netns);
        self
    }

    /// The sandbox's network namespace, when it has one of its own. A
    /// descriptor, not a pid: the spawner reaps the sandbox's processes, so
    /// a pid the provider held could come to name another process.
    #[must_use]
    pub fn netns(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd as _;
        self.netns.as_ref().map(|fd| fd.as_fd())
    }

    /// Reads a just-started container: its network namespace and the way
    /// to its spawner jobs.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn from_child(child: &crate::Child) -> Self {
        Self {
            // A copy that cannot be made leaves the provider without the
            // namespace, and an attach that needs it fails.
            netns: child.netns().and_then(|fd| fd.try_clone_to_owned().ok()),
            job: Some(child.entrance()),
        }
    }

    #[cfg(target_os = "linux")]
    fn job(&self) -> std::io::Result<&crate::Entrance> {
        self.job
            .as_ref()
            .ok_or_else(|| std::io::Error::other("the sandbox was not started by a spawner"))
    }

    /// Sets up the one interface of the sandbox's network namespace. See
    /// [`crate::Entrance::link`].
    ///
    /// # Errors
    ///
    /// As [`crate::Entrance::link`].
    #[cfg(target_os = "linux")]
    pub fn link(&self, spec: crate::LinkSpec) -> std::io::Result<Option<std::os::fd::OwnedFd>> {
        self.job()?.link(spec)
    }

    /// Creates a socket in the sandbox's network namespace that belongs to
    /// the caller. See [`crate::Entrance::socket_for_daemon`].
    ///
    /// # Errors
    ///
    /// As [`crate::Entrance::socket_for_daemon`].
    #[cfg(target_os = "linux")]
    pub fn socket_for_daemon(
        &self,
        v6: bool,
        datagram: bool,
    ) -> std::io::Result<std::os::fd::OwnedFd> {
        self.job()?.socket_for_daemon(v6, datagram)
    }
}

/// Reverses per-sandbox network wiring. Teardown is **explicit** — call
/// [`teardown`](NetGuard::teardown) on a live async runtime — rather than on
/// `Drop`, which cannot await and may run after the runtime has stopped.
pub trait NetGuard: Send {
    /// Reverses the wiring set up by [`Network::attach`]. Consumes the guard.
    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The static name the host answers by, for boxes that share its network
/// namespace (NET-003). The host's own resolver has no `min.internal.` zone, so
/// a native host-address box resolves the host by name through this
/// `/etc/hosts` entry at the host's loopback.
pub const HOST_MIN_INTERNAL: &str = "host.min.internal";

/// Shares the host/VM network namespace (the default), and the host's
/// resolver with it. No isolation, no wiring.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostNet;

impl Network for HostNet {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(NetPlan::host()
            .with_resolver(Resolver::Host)
            .with_hosts_entry(HOST_MIN_INTERNAL, Ipv4Addr::LOCALHOST))))
    }
}

/// A fresh, empty network namespace: only `lo`, which the box's pre-exec
/// closure brings up, so every egress attempt past loopback fails (UC1). No
/// post-spawn wiring.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNet;

impl Network for NoNet {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(NetPlan::isolated())))
    }
}

/// The no-op guard returned by the default [`Network::attach`] and by sandboxes
/// with no custom network.
pub(crate) fn noop_guard() -> Box<dyn NetGuard> {
    struct NoopGuard;
    impl NetGuard for NoopGuard {
        fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(std::future::ready(()))
        }
    }
    Box::new(NoopGuard)
}
