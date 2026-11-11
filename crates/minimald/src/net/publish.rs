//! Publishing a port of a box.
//!
//! A published port has two parts. A forward carries connections from
//! outside the virtual network to the box's port: the daemon's own gvproxy
//! on a native node, the VM host in a VM, where the VM host also decides
//! once more whether the box may publish the port. The engine's ingress
//! entry admits those connections at the box. The forward goes up first, so
//! the box never admits a port that nothing forwards to. It comes down
//! last, so nothing new arrives while it closes.
//!
//! A declared port, `min net expose` and the listen watcher all publish
//! through [`publish`]. It holds each external port for one of them at a
//! time, so a port is forwarded once.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boxes::{BoxId, DynamicIngress, IpProto, PortMapping};
use futures::future::BoxFuture;
use minimald_rpc::{ForwardState, PublishOrigin, PublishPortRequest, UnpublishPortRequest};
use netpol::{Protocols, base::PortOf};

use super::door::{Connect, DoorError, GuestDoor};
use super::engine::{Engine, Installed};
use super::policy::{self, ControlChannel};
use crate::audit::{self, DecidedBy, DecisionOutcome, DecisionRecord};

/// The waits before the second and the third try to close a forward.
const CLOSE_RETRY_WAITS: [Duration; 2] = [Duration::from_millis(200), Duration::from_secs(1)];

/// Who asked for a port to be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The box declares the port. It is published while the box runs.
    Declared,
    /// `min net expose` in the box, with the setting that allowed it and
    /// who decided.
    Expose {
        decision: DynamicIngress,
        decided_by: DecidedBy,
    },
    /// A process of the box listens on the port, and the box's setting is
    /// `allow`.
    Listen,
}

impl Origin {
    /// The origin as the VM host and the log name it.
    pub(crate) const fn kind(self) -> PublishOrigin {
        match self {
            Self::Declared => PublishOrigin::Declared,
            Self::Expose { .. } => PublishOrigin::Expose,
            Self::Listen => PublishOrigin::Listen,
        }
    }

    /// The decision behind a port published at run time. A declared port
    /// has none: the box's creator wrote it down.
    const fn decision(self) -> Option<(DynamicIngress, DecidedBy)> {
        match self {
            Self::Declared => None,
            Self::Expose {
                decision,
                decided_by,
            } => Some((decision, decided_by)),
            Self::Listen => Some((DynamicIngress::Allow, DecidedBy::BoxPolicy)),
        }
    }
}

/// Why a port was not published, or not unpublished.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PublishError {
    #[error("{0:?} ports cannot be published")]
    Protocol(IpProto),
    /// The port is published already, or is being published.
    #[error("the port is held by a {by:?} publish")]
    Held {
        by: PublishOrigin,
        /// Where it answers, once it is published.
        listener: Option<SocketAddr>,
    },
    #[error("{0}")]
    Refused(minimald_rpc::PublishRefusal),
    #[error("the forward could not be set: {0}")]
    Forward(io::Error),
    #[error("the box's ingress entry could not be written: {0}")]
    Engine(String),
    #[error("the publish could not be recorded: {0}")]
    Audit(io::Error),
}

impl From<DoorError> for PublishError {
    fn from(error: DoorError) -> Self {
        match error {
            DoorError::Refused(refusal) => Self::Refused(refusal),
            DoorError::Unreachable(error) => Self::Forward(error),
            DoorError::Failed(error) => Self::Forward(io::Error::other(error)),
        }
    }
}

/// A forward to a box's port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Forward {
    /// Where connections for the port are accepted.
    pub(crate) listener: SocketAddr,
    /// False while the listener waits for another box to give the port up.
    pub(crate) bound: bool,
}

/// What carries connections from outside the virtual network to one box.
pub(crate) trait Forwarder: Send + Sync {
    fn open(
        &self,
        port: PortMapping,
        origin: PublishOrigin,
    ) -> BoxFuture<'_, Result<Forward, PublishError>>;

    /// Ends a forward and returns how many of its connections were closed,
    /// when the forwarder says. Closing a forward that is not there is no
    /// error.
    fn close(
        &self,
        port: PortMapping,
        origin: PublishOrigin,
    ) -> BoxFuture<'_, Result<Option<u64>, PublishError>>;
}

/// The engine's part of a published port.
pub(crate) trait Admission: Send + Sync {
    fn admit(&self, port: PortOf) -> Result<(), String>;
    fn refuse(&self, port: PortOf) -> Result<(), String>;
}

/// The ingress entries of one box in the engine.
pub(crate) struct EngineAdmission {
    pub(crate) engine: &'static Engine,
    pub(crate) of: Arc<Installed>,
}

impl Admission for EngineAdmission {
    fn admit(&self, port: PortOf) -> Result<(), String> {
        self.engine
            .publish(&self.of, port)
            .map_err(|error| error.to_string())
    }

    fn refuse(&self, port: PortOf) -> Result<(), String> {
        self.engine
            .unpublish(&self.of, port)
            .map_err(|error| error.to_string())
    }
}

/// The daemon's own gvproxy, forwarding from an address of the node to the
/// box's address on the virtual network.
pub(crate) struct GvproxyForwarder {
    control: ControlChannel,
    /// The node's address the box's ports answer at.
    listen: Ipv4Addr,
    /// The box's address on the virtual network.
    lease: Ipv4Addr,
}

impl GvproxyForwarder {
    pub(crate) fn new(control: PathBuf, listen: Ipv4Addr, lease: Ipv4Addr) -> Self {
        Self {
            control: ControlChannel::Unix(control),
            listen,
            lease,
        }
    }

    async fn unexpose(&self, port: PortMapping) -> io::Result<Option<u64>> {
        let request = policy::expose_request(&port, self.listen, self.lease);
        let request = policy::UnexposeRequest {
            local: request.local,
            protocol: request.protocol,
        };
        let reply = policy::post_json_reply_within(
            &self.control,
            "/services/forwarder/unexpose",
            &request,
            policy::GVPROXY_CONTROL_TIMEOUT,
        )
        .await?;
        Ok(policy::ClosedConnections::from_reply(&reply).0)
    }
}

impl Forwarder for GvproxyForwarder {
    fn open(
        &self,
        port: PortMapping,
        _origin: PublishOrigin,
    ) -> BoxFuture<'_, Result<Forward, PublishError>> {
        Box::pin(async move {
            let request = policy::expose_request(&port, self.listen, self.lease);
            let expose =
                || policy::post_json(&self.control, "/services/forwarder/expose", &request);
            if let Err(error) = expose().await {
                if !policy::is_already_running(&error) {
                    return Err(PublishError::Forward(error));
                }
                // gvproxy has a forward at this listener, and the box holds
                // none there: one whose close failed earlier. It goes
                // first.
                self.unexpose(port).await.map_err(PublishError::Forward)?;
                expose().await.map_err(PublishError::Forward)?;
            }
            Ok(Forward {
                listener: SocketAddr::new(self.listen.into(), port.external_port),
                bound: true,
            })
        })
    }

    fn close(
        &self,
        port: PortMapping,
        _origin: PublishOrigin,
    ) -> BoxFuture<'_, Result<Option<u64>, PublishError>> {
        Box::pin(async move { self.unexpose(port).await.map_err(PublishError::Forward) })
    }
}

/// The VM host, forwarding from the host machine to a box in this VM.
pub(crate) struct DoorForwarder<C> {
    door: GuestDoor<C>,
    box_id: BoxId,
}

impl<C: Connect> DoorForwarder<C> {
    pub(crate) const fn new(door: GuestDoor<C>, box_id: BoxId) -> Self {
        Self { door, box_id }
    }
}

impl<C: Connect> Forwarder for DoorForwarder<C> {
    fn open(
        &self,
        port: PortMapping,
        origin: PublishOrigin,
    ) -> BoxFuture<'_, Result<Forward, PublishError>> {
        Box::pin(async move {
            let forwarded = self
                .door
                .publish(PublishPortRequest {
                    box_id: self.box_id,
                    external: port.external_port,
                    internal: port.internal_port,
                    proto: port.proto,
                    origin,
                })
                .await?;
            Ok(Forward {
                listener: forwarded.listener.into(),
                bound: forwarded.state == ForwardState::Bound,
            })
        })
    }

    fn close(
        &self,
        port: PortMapping,
        origin: PublishOrigin,
    ) -> BoxFuture<'_, Result<Option<u64>, PublishError>> {
        Box::pin(async move {
            // The VM host ends a declared port's forward when the box ends,
            // and refuses to end it earlier.
            if origin == PublishOrigin::Declared {
                return Ok(None);
            }
            let request = UnpublishPortRequest {
                box_id: self.box_id,
                external: port.external_port,
                proto: port.proto,
            };
            match self.door.unpublish(request).await {
                Ok(closed) => Ok(Some(u64::from(closed))),
                Err(DoorError::Refused(minimald_rpc::PublishRefusal::NotPublished)) => Ok(None),
                Err(error) => Err(error.into()),
            }
        })
    }
}

/// A published port of the box, as a listing shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) port: PortMapping,
    pub(crate) origin: PublishOrigin,
    pub(crate) forward: Forward,
}

#[derive(Debug, Clone, Copy)]
struct Hold {
    by: PublishOrigin,
    internal: u16,
    /// Set once the port is published.
    forward: Option<Forward>,
}

#[derive(Default)]
struct Ports {
    /// Every external port of the box that is published or being
    /// published or unpublished.
    held: HashMap<(IpProto, u16), Hold>,
    /// How many forwards lead to each internal port. The engine's entry
    /// stays for as long as one does.
    admitted: HashMap<(IpProto, u16), usize>,
}

/// What publishing a port of one box needs.
pub(crate) struct PublishCtx {
    /// The box's name in the decision log.
    box_name: String,
    forwarder: Arc<dyn Forwarder>,
    admission: Arc<dyn Admission>,
    /// The daemon's state directory, which holds the decision log.
    state_dir: PathBuf,
    ports: Mutex<Ports>,
}

fn port_of(proto: IpProto, port: u16) -> Result<PortOf, PublishError> {
    let protocols = match proto {
        IpProto::Tcp => Protocols::TCP,
        IpProto::Udp => Protocols::UDP,
        other => return Err(PublishError::Protocol(other)),
    };
    Ok(PortOf { protocols, port })
}

impl PublishCtx {
    pub(crate) fn new(
        box_name: String,
        forwarder: Arc<dyn Forwarder>,
        admission: Arc<dyn Admission>,
        state_dir: PathBuf,
    ) -> Arc<Self> {
        Arc::new(Self {
            box_name,
            forwarder,
            admission,
            state_dir,
            ports: Mutex::default(),
        })
    }

    fn ports(&self) -> std::sync::MutexGuard<'_, Ports> {
        self.ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The box's published ports, by external port.
    pub(crate) fn rows(&self) -> Vec<Row> {
        let mut rows: Vec<Row> = self
            .ports()
            .held
            .iter()
            .filter_map(|((proto, external), hold)| {
                Some(Row {
                    port: PortMapping {
                        external_port: *external,
                        internal_port: hold.internal,
                        proto: *proto,
                    },
                    origin: hold.by,
                    forward: hold.forward?,
                })
            })
            .collect();
        rows.sort_by_key(|row| (row.port.external_port, row.port.proto == IpProto::Udp));
        rows
    }

    fn release(&self, port: PortMapping) {
        self.ports().held.remove(&(port.proto, port.external_port));
    }

    /// Writes the engine's entry for the port unless another forward to the
    /// same internal port already has.
    fn admit(&self, port: PortMapping) -> Result<(), PublishError> {
        let entry = port_of(port.proto, port.internal_port)?;
        let key = (port.proto, port.internal_port);
        let mut ports = self.ports();
        let forwards = ports.admitted.get(&key).copied().unwrap_or(0);
        if forwards == 0 {
            self.admission.admit(entry).map_err(PublishError::Engine)?;
        }
        ports.admitted.insert(key, forwards + 1);
        Ok(())
    }

    /// Takes the engine's entry for the port away with its last forward.
    fn refuse(&self, port: PortMapping) {
        let Ok(entry) = port_of(port.proto, port.internal_port) else {
            return;
        };
        let mut ports = self.ports();
        let key = (port.proto, port.internal_port);
        match ports.admitted.get_mut(&key) {
            Some(forwards) if *forwards > 1 => *forwards -= 1,
            Some(_) => {
                ports.admitted.remove(&key);
                if let Err(error) = self.admission.refuse(entry) {
                    tracing::error!(
                        box = %self.box_name,
                        port = port.internal_port,
                        %error,
                        "a published port's ingress entry could not be removed"
                    );
                }
            }
            None => {}
        }
    }

    /// Closes the forward, trying again when the forwarder does not answer.
    async fn close(
        &self,
        port: PortMapping,
        origin: PublishOrigin,
    ) -> Result<Option<u64>, PublishError> {
        let mut waits = CLOSE_RETRY_WAITS.into_iter();
        loop {
            match self.forwarder.close(port, origin).await {
                Ok(closed) => return Ok(closed),
                Err(error) => match waits.next() {
                    Some(wait) => tokio::time::sleep(wait).await,
                    None => return Err(error),
                },
            }
        }
    }
}

/// A forward that is being opened, or is open with no [`Published`] to own
/// it yet. Dropped that way, by a failure or by its future being dropped,
/// it closes what the forwarder may have opened.
struct Opening {
    ctx: Arc<PublishCtx>,
    port: PortMapping,
    origin: PublishOrigin,
    admitted: bool,
    done: bool,
}

impl Drop for Opening {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        if self.admitted {
            self.ctx.refuse(self.port);
        }
        close_in_background(Arc::clone(&self.ctx), self.port, self.origin);
    }
}

/// Closes a forward and gives its external port up, on the runtime. The
/// port stays held until then: a new publish of it must not meet the old
/// forward, and must not be closed by the old forward's close.
fn close_in_background(ctx: Arc<PublishCtx>, port: PortMapping, origin: PublishOrigin) {
    let close = async move {
        if let Err(error) = ctx.close(port, origin).await {
            tracing::warn!(
                box = %ctx.box_name,
                port = port.external_port,
                %error,
                "a port's forward could not be closed"
            );
        }
        ctx.release(port);
    };
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            runtime.spawn(close);
        }
        // No runtime, so the daemon is ending, and its forwarder with it.
        Err(_) => drop(close),
    }
}

/// Publishes one port of the box.
///
/// Dropping the future before it ends withdraws the publish, an ask of the
/// VM host included.
pub(crate) async fn publish(
    ctx: &Arc<PublishCtx>,
    port: PortMapping,
    origin: Origin,
) -> Result<Published, PublishError> {
    port_of(port.proto, port.internal_port)?;
    let key = (port.proto, port.external_port);
    {
        let mut ports = ctx.ports();
        if let Some(hold) = ports.held.get(&key) {
            return Err(PublishError::Held {
                by: hold.by,
                listener: hold.forward.map(|forward| forward.listener),
            });
        }
        ports.held.insert(
            key,
            Hold {
                by: origin.kind(),
                internal: port.internal_port,
                forward: None,
            },
        );
    }
    let mut opening = Opening {
        ctx: Arc::clone(ctx),
        port,
        origin: origin.kind(),
        admitted: false,
        done: false,
    };
    let forward = match ctx.forwarder.open(port, origin.kind()).await {
        Ok(forward) => forward,
        Err(error) => {
            // The forwarder said no, so there is nothing to close.
            opening.done = true;
            ctx.release(port);
            return Err(error);
        }
    };
    ctx.admit(port)?;
    opening.admitted = true;
    if let Some((decision, decided_by)) = origin.decision() {
        let record = DecisionRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            box_name: ctx.box_name.clone(),
            port: port.external_port,
            decision,
            decided_by,
            outcome: DecisionOutcome::Published,
            reason: None,
        };
        // A port opened at run time stays open only with its record.
        audit::try_append_capped(&ctx.state_dir, &record, audit::MAX_LOG_BYTES)
            .await
            .map_err(PublishError::Audit)?;
    }
    opening.done = true;
    if let Some(hold) = ctx.ports().held.get_mut(&key) {
        hold.forward = Some(forward);
    }
    Ok(Published {
        ctx: Arc::clone(ctx),
        port,
        origin: origin.kind(),
        forward,
        live: true,
    })
}

/// Records that a port's publish failed after the box's setting allowed
/// it. The log keeps the record whether or not it can be written.
pub(crate) async fn record_failure(ctx: &PublishCtx, port: u16, origin: Origin, reason: String) {
    let Some((decision, decided_by)) = origin.decision() else {
        return;
    };
    let record = DecisionRecord {
        ts: chrono::Utc::now().to_rfc3339(),
        box_name: ctx.box_name.clone(),
        port,
        decision,
        decided_by,
        outcome: DecisionOutcome::PublishFailed,
        reason: Some(reason),
    };
    if let Err(error) =
        audit::try_append_capped(&ctx.state_dir, &record, audit::MAX_LOG_BYTES).await
    {
        tracing::warn!(box = %ctx.box_name, port, %error, "a failed publish could not be recorded");
    }
}

/// A published port. Dropping it unpublishes the port.
pub(crate) struct Published {
    ctx: Arc<PublishCtx>,
    port: PortMapping,
    origin: PublishOrigin,
    forward: Forward,
    live: bool,
}

impl std::fmt::Debug for Published {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Published")
            .field("port", &self.port)
            .field("origin", &self.origin)
            .field("forward", &self.forward)
            .finish_non_exhaustive()
    }
}

impl Published {
    pub(crate) const fn port(&self) -> PortMapping {
        self.port
    }

    pub(crate) const fn forward(&self) -> Forward {
        self.forward
    }

    /// Unpublishes the port and waits for it. Returns how many connections
    /// the forward closed, when the forwarder says.
    ///
    /// The engine's entry is gone when this returns, whatever it returns.
    /// On an error the forward may still stand. It admits nothing then,
    /// and the next publish of the port replaces it.
    pub(crate) async fn withdraw(mut self) -> Result<Option<u64>, PublishError> {
        self.live = false;
        self.ctx.refuse(self.port);
        let closed = self.ctx.close(self.port, self.origin).await;
        self.ctx.release(self.port);
        closed
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        self.ctx.refuse(self.port);
        close_in_background(Arc::clone(&self.ctx), self.port, self.origin);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::door::testing::{FakeHost, box_id};
    use minimald_rpc::{GuestDoorReply, GuestDoorRequest, PublishRefusal};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// What happened at the forwarder and the engine, in order.
    #[derive(Default)]
    struct Journal(Mutex<Vec<String>>);

    impl Journal {
        fn note(&self, line: String) {
            self.0.lock().unwrap().push(line);
        }

        fn take(&self) -> Vec<String> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    #[derive(Default)]
    struct Fake {
        journal: Arc<Journal>,
        fail_open: AtomicBool,
        fail_close: AtomicBool,
        fail_admit: AtomicBool,
        /// Opens wait here when set, as an ask of the VM host does.
        hold_open: Option<Arc<tokio::sync::Notify>>,
    }

    impl Forwarder for Fake {
        fn open(
            &self,
            port: PortMapping,
            origin: PublishOrigin,
        ) -> BoxFuture<'_, Result<Forward, PublishError>> {
            Box::pin(async move {
                if let Some(held) = &self.hold_open {
                    held.notified().await;
                }
                if self.fail_open.load(Ordering::SeqCst) {
                    return Err(PublishError::Refused(PublishRefusal::PortInUse));
                }
                self.journal
                    .note(format!("open {} {origin:?}", port.external_port));
                Ok(Forward {
                    listener: SocketAddr::from(([127, 0, 64, 9], port.external_port)),
                    bound: true,
                })
            })
        }

        fn close(
            &self,
            port: PortMapping,
            _origin: PublishOrigin,
        ) -> BoxFuture<'_, Result<Option<u64>, PublishError>> {
            Box::pin(async move {
                if self.fail_close.load(Ordering::SeqCst) {
                    self.journal
                        .note(format!("close {} failed", port.external_port));
                    return Err(PublishError::Forward(io::ErrorKind::TimedOut.into()));
                }
                self.journal.note(format!("close {}", port.external_port));
                Ok(Some(2))
            })
        }
    }

    impl Admission for Fake {
        fn admit(&self, port: PortOf) -> Result<(), String> {
            if self.fail_admit.load(Ordering::SeqCst) {
                return Err("no room".into());
            }
            self.journal.note(format!("admit {}", port.port));
            Ok(())
        }

        fn refuse(&self, port: PortOf) -> Result<(), String> {
            self.journal.note(format!("refuse {}", port.port));
            Ok(())
        }
    }

    struct Bench {
        fake: Arc<Fake>,
        ctx: Arc<PublishCtx>,
        dir: tempfile::TempDir,
    }

    fn bench_with(fake: Fake) -> Bench {
        let fake = Arc::new(fake);
        let dir = tempfile::tempdir().unwrap();
        let ctx = PublishCtx::new(
            "web".into(),
            Arc::clone(&fake) as Arc<dyn Forwarder>,
            Arc::clone(&fake) as Arc<dyn Admission>,
            dir.path().to_path_buf(),
        );
        Bench { fake, ctx, dir }
    }

    fn bench() -> Bench {
        bench_with(Fake::default())
    }

    impl Bench {
        fn journal(&self) -> Vec<String> {
            self.fake.journal.take()
        }

        fn records(&self) -> Vec<serde_json_lenient::Value> {
            std::fs::read_to_string(audit::log_path(self.dir.path()))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json_lenient::from_str(line).unwrap())
                .collect()
        }

        /// Waits until the background close of `external` has given the
        /// port up.
        async fn released(&self, external: u16) {
            for _ in 0..500 {
                if !self
                    .ctx
                    .ports()
                    .held
                    .contains_key(&(IpProto::Tcp, external))
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("port {external} stayed held");
        }
    }

    const fn tcp(external: u16, internal: u16) -> PortMapping {
        PortMapping {
            external_port: external,
            internal_port: internal,
            proto: IpProto::Tcp,
        }
    }

    const EXPOSE: Origin = Origin::Expose {
        decision: DynamicIngress::Ask,
        decided_by: DecidedBy::AttachedHuman,
    };

    #[tokio::test]
    async fn the_forward_goes_up_before_the_entry_and_comes_down_after_it() {
        let bench = bench();
        let published = publish(&bench.ctx, tcp(18080, 8080), Origin::Declared)
            .await
            .unwrap();
        assert_eq!(bench.journal(), ["open 18080 Declared", "admit 8080"]);
        assert_eq!(
            bench.ctx.rows(),
            [Row {
                port: tcp(18080, 8080),
                origin: PublishOrigin::Declared,
                forward: published.forward(),
            }]
        );
        assert_eq!(published.withdraw().await.unwrap(), Some(2));
        assert_eq!(bench.journal(), ["refuse 8080", "close 18080"]);
        assert!(bench.ctx.rows().is_empty());
        // A declared port is no decision of the running box.
        assert!(bench.records().is_empty());
    }

    #[tokio::test]
    async fn a_port_published_at_run_time_is_recorded_with_who_decided() {
        let bench = bench();
        let _expose = publish(&bench.ctx, tcp(3005, 3005), EXPOSE).await.unwrap();
        let _listen = publish(&bench.ctx, tcp(3006, 3006), Origin::Listen)
            .await
            .unwrap();
        let records = bench.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["box"], "web");
        assert_eq!(records[0]["port"], 3005);
        assert_eq!(records[0]["decision"], "ask");
        assert_eq!(records[0]["decided_by"], "attached-human");
        assert_eq!(records[0]["outcome"], "published");
        assert_eq!(records[1]["port"], 3006);
        assert_eq!(records[1]["decision"], "allow");
        assert_eq!(records[1]["decided_by"], "box-policy");
    }

    #[tokio::test]
    async fn a_publish_that_cannot_be_recorded_is_taken_back() {
        let bench = bench();
        // A file where the log's directory would be.
        std::fs::write(bench.dir.path().join("audit"), "").unwrap();
        let refused = publish(&bench.ctx, tcp(3005, 3005), Origin::Listen).await;
        assert!(
            matches!(refused, Err(PublishError::Audit(_))),
            "{refused:?}"
        );
        bench.released(3005).await;
        assert_eq!(
            bench.journal(),
            [
                "open 3005 Listen",
                "admit 3005",
                "refuse 3005",
                "close 3005"
            ]
        );
        // A declared port needs no record and stands.
        publish(&bench.ctx, tcp(18080, 8080), Origin::Declared)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_refused_forward_leaves_nothing_behind() {
        let bench = bench();
        bench.fake.fail_open.store(true, Ordering::SeqCst);
        let refused = publish(&bench.ctx, tcp(3005, 3005), Origin::Listen).await;
        assert!(
            matches!(
                refused,
                Err(PublishError::Refused(PublishRefusal::PortInUse))
            ),
            "{refused:?}"
        );
        assert!(bench.journal().is_empty());
        bench.fake.fail_open.store(false, Ordering::SeqCst);
        // The port is free for the next try at once.
        publish(&bench.ctx, tcp(3005, 3005), Origin::Listen)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_entry_that_cannot_be_written_closes_the_forward() {
        let bench = bench();
        bench.fake.fail_admit.store(true, Ordering::SeqCst);
        let refused = publish(&bench.ctx, tcp(3005, 3005), Origin::Listen).await;
        assert!(
            matches!(refused, Err(PublishError::Engine(_))),
            "{refused:?}"
        );
        bench.released(3005).await;
        assert_eq!(bench.journal(), ["open 3005 Listen", "close 3005"]);
        assert!(bench.records().is_empty());
    }

    #[tokio::test]
    async fn an_external_port_is_held_for_one_publish_at_a_time() {
        let bench = bench();
        let listening = publish(&bench.ctx, tcp(3005, 3005), Origin::Listen)
            .await
            .unwrap();
        let second = publish(&bench.ctx, tcp(3005, 3005), EXPOSE).await;
        match second {
            Err(PublishError::Held { by, listener }) => {
                assert_eq!(by, PublishOrigin::Listen);
                assert_eq!(listener, Some(listening.forward().listener));
            }
            other => panic!("{other:?}"),
        }
        // UDP on the same number is another port.
        let udp = PortMapping {
            proto: IpProto::Udp,
            ..tcp(3005, 3005)
        };
        publish(&bench.ctx, udp, EXPOSE).await.unwrap();
        bench.journal();

        // The port stays held until the old forward is closed.
        drop(listening);
        let early = publish(&bench.ctx, tcp(3005, 3005), EXPOSE).await;
        assert!(
            matches!(
                early,
                Err(PublishError::Held {
                    by: PublishOrigin::Listen,
                    listener: Some(_)
                })
            ),
            "{early:?}"
        );
        bench.released(3005).await;
        publish(&bench.ctx, tcp(3005, 3005), EXPOSE).await.unwrap();
    }

    #[tokio::test]
    async fn the_entry_of_an_internal_port_stays_for_as_long_as_one_forward_leads_to_it() {
        let bench = bench();
        let first = publish(&bench.ctx, tcp(18080, 8080), Origin::Declared)
            .await
            .unwrap();
        let second = publish(&bench.ctx, tcp(18081, 8080), Origin::Declared)
            .await
            .unwrap();
        assert_eq!(
            bench.journal(),
            ["open 18080 Declared", "admit 8080", "open 18081 Declared"]
        );
        first.withdraw().await.unwrap();
        assert_eq!(bench.journal(), ["close 18080"]);
        second.withdraw().await.unwrap();
        assert_eq!(bench.journal(), ["refuse 8080", "close 18081"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_forward_that_does_not_close_is_tried_three_times_and_then_given_up() {
        let bench = bench();
        let published = publish(&bench.ctx, tcp(3005, 3005), Origin::Listen)
            .await
            .unwrap();
        bench.journal();
        bench.fake.fail_close.store(true, Ordering::SeqCst);
        let failed = published.withdraw().await;
        assert!(
            matches!(failed, Err(PublishError::Forward(_))),
            "{failed:?}"
        );
        // The entry went first, so the forward that stands admits nothing.
        assert_eq!(
            bench.journal(),
            [
                "refuse 3005",
                "close 3005 failed",
                "close 3005 failed",
                "close 3005 failed"
            ]
        );
        assert!(bench.ctx.rows().is_empty());
    }

    #[tokio::test]
    async fn dropping_a_publish_that_waits_withdraws_it() {
        let held = Arc::new(tokio::sync::Notify::new());
        let bench = bench_with(Fake {
            hold_open: Some(Arc::clone(&held)),
            ..Fake::default()
        });
        let ctx = Arc::clone(&bench.ctx);
        let asking =
            crate::traced::spawn(async move { publish(&ctx, tcp(3005, 3005), EXPOSE).await });
        tokio::task::yield_now().await;
        assert!(bench.ctx.ports().held.contains_key(&(IpProto::Tcp, 3005)));
        asking.abort();
        let _ = asking.await;
        bench.released(3005).await;
        // The forwarder may have opened it, so it is told to close.
        assert_eq!(bench.journal(), ["close 3005"]);
        assert!(bench.records().is_empty());
    }

    #[tokio::test]
    async fn a_failed_publish_is_recorded_for_a_run_time_port_only() {
        let bench = bench();
        record_failure(&bench.ctx, 3005, Origin::Listen, "port in use".into()).await;
        record_failure(&bench.ctx, 8080, Origin::Declared, "port in use".into()).await;
        let records = bench.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["outcome"], "publish-failed");
        assert_eq!(records[0]["reason"], "port in use");
    }

    #[tokio::test]
    async fn only_tcp_and_udp_ports_are_published() {
        let bench = bench();
        let icmp = PortMapping {
            proto: IpProto::Icmp,
            ..tcp(1, 1)
        };
        let refused = publish(&bench.ctx, icmp, Origin::Declared).await;
        assert!(
            matches!(refused, Err(PublishError::Protocol(_))),
            "{refused:?}"
        );
        assert!(bench.journal().is_empty());
    }

    /// A gvproxy for tests: answers each control request with what `answer`
    /// gives for its path and body.
    fn fake_gvproxy(
        dir: &std::path::Path,
        answer: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
    ) -> PathBuf {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let path = dir.join("gvproxy.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let answer = Arc::new(answer);
        crate::traced::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let answer = Arc::clone(&answer);
                crate::traced::spawn(async move {
                    let mut request = Vec::new();
                    let (head, body) = loop {
                        let mut chunk = [0u8; 1024];
                        let got = stream.read(&mut chunk).await.unwrap();
                        request.extend_from_slice(&chunk[..got]);
                        let text = String::from_utf8_lossy(&request).into_owned();
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let length: usize = head
                                .lines()
                                .find_map(|line| line.strip_prefix("Content-Length: "))
                                .unwrap()
                                .parse()
                                .unwrap();
                            if body.len() >= length {
                                break (head.to_string(), body.to_string());
                            }
                        }
                    };
                    let path = head.split_whitespace().nth(1).unwrap();
                    let (status, said) = answer(path, &body);
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{said}",
                        said.len()
                    );
                    stream.write_all(reply.as_bytes()).await.unwrap();
                });
            }
        });
        path
    }

    #[tokio::test]
    async fn gvproxy_forwards_from_the_nodes_address_to_the_boxs_lease() {
        let dir = tempfile::tempdir().unwrap();
        let asked = Arc::new(Journal::default());
        let seen = Arc::clone(&asked);
        let control = fake_gvproxy(dir.path(), move |path, body| {
            seen.note(format!("{path} {body}"));
            (200, r#"{"closed":4}"#.to_string())
        });
        let forwarder = GvproxyForwarder::new(
            control,
            Ipv4Addr::new(127, 0, 64, 9),
            Ipv4Addr::new(100, 64, 1, 7),
        );
        let forward = forwarder
            .open(tcp(18080, 8080), PublishOrigin::Declared)
            .await
            .unwrap();
        assert_eq!(
            forward,
            Forward {
                listener: "127.0.64.9:18080".parse().unwrap(),
                bound: true
            }
        );
        let closed = forwarder
            .close(tcp(18080, 8080), PublishOrigin::Declared)
            .await
            .unwrap();
        assert_eq!(closed, Some(4));
        assert_eq!(
            asked.take(),
            [
                r#"/services/forwarder/expose {"local":"127.0.64.9:18080","remote":"100.64.1.7:8080","protocol":"tcp"}"#,
                r#"/services/forwarder/unexpose {"local":"127.0.64.9:18080","protocol":"tcp"}"#,
            ]
        );
    }

    #[tokio::test]
    async fn a_forward_gvproxy_still_has_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let asked = Arc::new(Journal::default());
        let seen = Arc::clone(&asked);
        let stale = Arc::new(AtomicBool::new(true));
        let control = fake_gvproxy(dir.path(), move |path, _| {
            seen.note(path.to_string());
            let expose = path.ends_with("/expose");
            if expose && stale.load(Ordering::SeqCst) {
                return (500, "proxy already running".to_string());
            }
            stale.store(false, Ordering::SeqCst);
            (200, String::new())
        });
        let forwarder = GvproxyForwarder::new(
            control,
            Ipv4Addr::new(127, 0, 64, 9),
            Ipv4Addr::new(100, 64, 1, 7),
        );
        forwarder
            .open(tcp(3005, 3005), PublishOrigin::Listen)
            .await
            .unwrap();
        assert_eq!(
            asked.take(),
            [
                "/services/forwarder/expose",
                "/services/forwarder/unexpose",
                "/services/forwarder/expose"
            ]
        );
    }

    #[tokio::test]
    async fn a_port_another_program_holds_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let control = fake_gvproxy(dir.path(), |_, _| {
            (
                500,
                "listen tcp 127.0.64.9:3005: bind: address already in use".to_string(),
            )
        });
        let forwarder = GvproxyForwarder::new(
            control,
            Ipv4Addr::new(127, 0, 64, 9),
            Ipv4Addr::new(100, 64, 1, 7),
        );
        let refused = forwarder.open(tcp(3005, 3005), PublishOrigin::Listen).await;
        assert!(
            matches!(&refused, Err(PublishError::Forward(error)) if error.kind() == io::ErrorKind::AddrInUse),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn the_vm_host_forwards_and_keeps_a_declared_port_until_the_box_ends() {
        let asked = Arc::new(Journal::default());
        let seen = Arc::clone(&asked);
        let host = FakeHost::answering(move |request| match request {
            GuestDoorRequest::PublishPort(request) => {
                seen.note(format!("publish {} {:?}", request.external, request.origin));
                Some(GuestDoorReply::Published {
                    listener: std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, request.external),
                    box_id: request.box_id,
                    internal: request.internal,
                    proto: request.proto,
                    state: if request.external == 18080 {
                        ForwardState::Waiting
                    } else {
                        ForwardState::Bound
                    },
                })
            }
            GuestDoorRequest::UnpublishPort(request) => {
                seen.note(format!("unpublish {}", request.external));
                Some(if request.external == 3005 {
                    GuestDoorReply::Unpublished {
                        listener: "127.0.0.1:3005".parse().unwrap(),
                        closed: 1,
                    }
                } else {
                    GuestDoorReply::PublishRefused {
                        refusal: PublishRefusal::NotPublished,
                        box_id: request.box_id,
                        external: request.external,
                        proto: request.proto,
                    }
                })
            }
            other => panic!("{other:?}"),
        });
        let forwarder = DoorForwarder::new(GuestDoor::new(host), box_id(1));
        let declared = forwarder
            .open(tcp(18080, 8080), PublishOrigin::Declared)
            .await
            .unwrap();
        // The host listens later, when another box gives the port up.
        assert!(!declared.bound);
        assert_eq!(
            forwarder
                .close(tcp(18080, 8080), PublishOrigin::Declared)
                .await
                .unwrap(),
            None
        );
        let listened = forwarder
            .open(tcp(3005, 3005), PublishOrigin::Listen)
            .await
            .unwrap();
        assert!(listened.bound);
        assert_eq!(
            forwarder
                .close(tcp(3005, 3005), PublishOrigin::Listen)
                .await
                .unwrap(),
            Some(1)
        );
        // A forward the host no longer has is closed.
        assert_eq!(
            forwarder
                .close(tcp(3006, 3006), PublishOrigin::Listen)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            asked.take(),
            [
                "publish 18080 Declared",
                "publish 3005 Listen",
                "unpublish 3005",
                "unpublish 3006"
            ]
        );
    }
}
