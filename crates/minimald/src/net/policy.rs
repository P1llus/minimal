//! Forwards for a box's published ports, and rate-limited policy-violation
//! warning plumbing.
//!
//! A forward listens on the host and carries connections to a box's address
//! on the virtual network. A native node asks its own gvproxy at the control
//! socket, with `POST /services/forwarder/expose` and
//! `POST /services/forwarder/unexpose`. In a VM the VM host holds every
//! forward, and the daemon asks it through the guest door
//! ([`ControlChannel`]).

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

use boxes::core::ingress::{DynamicPortVerdict, IngressRules};
use boxes::{IngressPolicy, IpProto, PortMapping};

/// The forwarder-expose request body gvproxy's `POST /services/forwarder/expose`
/// expects: a host-side `local` listen address and the PTask-side `remote` it
/// forwards to, plus the transport `protocol`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExposeRequest {
    /// Host-side listen address, `host:port` (e.g. `127.0.0.1:8080`).
    pub local: String,
    /// PTask-side destination, `ip:port`.
    pub remote: String,
    /// Transport protocol (`tcp` / `udp`).
    pub protocol: String,
}

/// The `POST /services/forwarder/unexpose` body: the `local` address (and its
/// `protocol`) a prior [`ExposeRequest`] bound, identifying the forward to drop.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnexposeRequest {
    /// The host-side listen address the forward was exposed on.
    pub local: String,
    /// The transport protocol the forward was exposed with.
    pub protocol: String,
}

/// The forwards the node's own gvproxy holds for boxes. gvproxy keeps
/// them in memory only, so one that is started again gets them from here.
#[derive(Debug, Default)]
pub struct Forwards(tokio::sync::Mutex<Vec<ExposeRequest>>);

impl Forwards {
    /// Opens a forward and records it. The lock is held across the request,
    /// so a replay either sees the forward or runs before it.
    async fn open(&self, sock: &std::path::Path, req: &ExposeRequest) -> io::Result<()> {
        let mut held = self.0.lock().await;
        post_json(sock, "/services/forwarder/expose", req).await?;
        held.push(req.clone());
        Ok(())
    }

    /// Ends a forward. It leaves the record first: a forward its box gave
    /// up must not come back with the next gvproxy, whatever this one says.
    async fn close(
        &self,
        sock: &std::path::Path,
        mapping: &ExposedMapping,
    ) -> io::Result<ClosedConnections> {
        let mut held = self.0.lock().await;
        held.retain(|open| open.local != mapping.local || open.protocol != mapping.protocol);
        let req = UnexposeRequest {
            local: mapping.local.clone(),
            protocol: mapping.protocol.clone(),
        };
        post_json_reply_within(
            sock,
            "/services/forwarder/unexpose",
            &req,
            GVPROXY_CONTROL_TIMEOUT,
        )
        .await
        .map(|body| ClosedConnections::from_reply(&body))
    }

    /// Gives a gvproxy that was just started the forwards the last one
    /// held. Returns how many it took and how many it refused.
    pub(crate) async fn replay(&self, sock: &std::path::Path) -> (usize, usize) {
        let held = self.0.lock().await;
        let (mut taken, mut refused) = (0, 0);
        for forward in held.iter() {
            match post_json(sock, "/services/forwarder/expose", forward).await {
                Ok(()) => taken += 1,
                Err(error) => {
                    refused += 1;
                    tracing::warn!(
                        local = %forward.local,
                        remote = %forward.remote,
                        protocol = %forward.protocol,
                        %error,
                        "the restarted gvproxy did not take a forward"
                    );
                }
            }
        }
        (taken, refused)
    }

    #[cfg(test)]
    pub(crate) async fn held(&self) -> Vec<ExposeRequest> {
        self.0.lock().await.clone()
    }
}

/// The node's own gvproxy as the holder of forwards.
#[derive(Debug, Clone)]
pub struct OwnSwitch {
    /// gvproxy's control socket.
    pub socket: std::path::PathBuf,
    /// What it holds, for the gvproxy that follows it.
    pub forwards: Arc<Forwards>,
}

/// What holds the forwards that carry connections from outside the virtual
/// network to a box.
#[derive(Debug, Clone)]
pub enum ControlChannel {
    /// The node's own gvproxy.
    Unix(OwnSwitch),
    /// The VM host, asked through the guest door. It knows a box by the id
    /// it minted, and a box it did not register has none.
    VmHost {
        door: Arc<dyn super::door::HostDoor>,
        box_id: Option<boxes::BoxId>,
    },
}

impl ControlChannel {
    /// The channel of the node a switch client describes, for one box.
    #[must_use]
    pub fn of(switch: &crate::net::SwitchClient, box_id: Option<boxes::BoxId>) -> Self {
        match switch.transport() {
            crate::net::SwitchTransport::LocalSpawn => Self::Unix(OwnSwitch {
                socket: switch.control_socket(),
                forwards: switch.forwards(),
            }),
            crate::net::SwitchTransport::VmHost => Self::VmHost {
                door: super::door::of_this_guest(),
                box_id,
            },
        }
    }

    /// A gvproxy at `socket` that no switch client runs, with a record of
    /// its forwards that nothing replays.
    #[cfg(test)]
    pub(crate) fn unix(socket: impl Into<std::path::PathBuf>) -> Self {
        Self::Unix(OwnSwitch {
            socket: socket.into(),
            forwards: Arc::default(),
        })
    }

    /// Whether the VM host holds a row for the box. `None` on a node that
    /// has no VM host, for a box the VM host did not register, and when
    /// the VM host does not answer.
    pub async fn box_standing(&self) -> Option<bool> {
        let Self::VmHost {
            door,
            box_id: Some(box_id),
        } = self
        else {
            return None;
        };
        for attempt in 1..=3 {
            match door.box_standing(*box_id).await {
                Ok(standing) => return Some(standing),
                Err(error) => {
                    tracing::debug!(%box_id, attempt, %error, "the VM host did not say whether the box stands");
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    /// Asks the VM host for the id of a box about to be created. `None`
    /// on a node that has no VM host, where the store mints the id. Every
    /// try carries one token, so the VM host mints one id for them all.
    pub async fn mint_box_id(
        &self,
        switch_address: Option<Ipv4Addr>,
        host_ip_name: Option<String>,
    ) -> Option<io::Result<boxes::BoxId>> {
        let Self::VmHost { door, .. } = self else {
            return None;
        };
        let request = minimald_rpc::MintBoxIdRequest {
            switch_address,
            create_token: Some(uuid::Uuid::new_v4().simple().to_string()),
            host_ip_name,
        };
        let mut last = io::Error::from(io::ErrorKind::TimedOut);
        for attempt in 1..=3 {
            match door.mint_box_id(request.clone()).await {
                Ok(minted) => return Some(Ok(minted)),
                // The VM host refused. Asking again changes nothing.
                Err(super::door::DoorError::Failed(error)) => {
                    return Some(Err(io::Error::other(error)));
                }
                Err(error) => {
                    tracing::debug!(?switch_address, attempt, %error, "the box id mint was not answered");
                    last = door_error(error);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Some(Err(last))
    }

    /// Tells the VM host that the box has ended, and asks until the VM host
    /// answers. The VM host then drops what it holds for the box: the row
    /// and the forwards of a box with its own address, the residency of a
    /// box that shares the node's. `None` at once on a node that has no VM
    /// host.
    pub async fn report_box_end(&self) -> Option<super::door::BoxEnded> {
        let Self::VmHost {
            door,
            box_id: Some(box_id),
        } = self
        else {
            return None;
        };
        let ended = door.end_box(*box_id).await;
        tracing::info!(
            %box_id,
            ended = ended.ended,
            forwards_unbound = ended.forwards_unbound,
            still_bound = ended.still_bound,
            "told the VM host that the box has ended"
        );
        Some(ended)
    }

    /// Whether the forwards are the VM host's. It ends a declared port's
    /// forward when the box ends, and refuses to end it earlier.
    #[must_use]
    pub fn host_unbinds_declared_forwards(&self) -> bool {
        matches!(self, Self::VmHost { .. })
    }
}

/// A refusal of the VM host, carried in an [`io::Error`].
#[derive(Debug)]
struct HostRefusal(minimald_rpc::PublishRefusal);

impl fmt::Display for HostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the VM host refused: {:?}", self.0)
    }
}

impl std::error::Error for HostRefusal {}

/// The VM host's refusal in `error`, when that is what it is.
#[must_use]
pub fn host_refusal(error: &io::Error) -> Option<minimald_rpc::PublishRefusal> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<HostRefusal>())
        .map(|refusal| refusal.0.clone())
}

fn door_error(error: super::door::DoorError) -> io::Error {
    use super::door::DoorError;
    use minimald_rpc::PublishRefusal;
    match error {
        DoorError::Refused(refusal) => {
            let kind = match refusal {
                PublishRefusal::PortInUse | PublishRefusal::ListenerHeld => {
                    io::ErrorKind::AddrInUse
                }
                _ => io::ErrorKind::PermissionDenied,
            };
            io::Error::new(kind, HostRefusal(refusal))
        }
        DoorError::Unreachable(error) => error,
        DoorError::Failed(error) => io::Error::other(error),
    }
}

fn proto_of(protocol: &str) -> IpProto {
    if protocol == "udp" {
        IpProto::Udp
    } else {
        IpProto::Tcp
    }
}

/// Opens the forward for `mapping` and returns where it listens: at
/// `published` on the node's own gvproxy, and where the VM host says in a
/// VM.
async fn open_forward(
    control: &ControlChannel,
    mapping: &PortMapping,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    origin: minimald_rpc::PublishOrigin,
) -> io::Result<ExposedMapping> {
    let req = expose_request(mapping, published, ptask_ip);
    match control {
        ControlChannel::Unix(own) => {
            own.forwards.open(&own.socket, &req).await?;
            Ok(ExposedMapping {
                local: req.local,
                protocol: req.protocol,
            })
        }
        ControlChannel::VmHost { door, box_id } => {
            let box_id = box_id.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    HostRefusal(minimald_rpc::PublishRefusal::UnknownBox),
                )
            })?;
            let forwarded = door
                .publish(minimald_rpc::PublishPortRequest {
                    box_id,
                    external: mapping.external_port,
                    internal: mapping.internal_port,
                    proto: mapping.proto,
                    origin,
                })
                .await
                .map_err(door_error)?;
            Ok(ExposedMapping {
                local: forwarded.listener.to_string(),
                protocol: req.protocol,
            })
        }
    }
}

/// Ends the forward at `mapping` and returns how many connections went
/// with it, when the holder says.
async fn close_forward(
    control: &ControlChannel,
    mapping: &ExposedMapping,
) -> io::Result<ClosedConnections> {
    match control {
        ControlChannel::Unix(own) => own.forwards.close(&own.socket, mapping).await,
        ControlChannel::VmHost { door, box_id } => {
            let (Some(box_id), Some((_, external))) = (*box_id, mapping.host_port()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("no forward of the VM host is named by {}", mapping.local),
                ));
            };
            let request = minimald_rpc::UnpublishPortRequest {
                box_id,
                external,
                proto: proto_of(&mapping.protocol),
            };
            match door.unpublish(request).await {
                Ok(closed) => Ok(ClosedConnections(Some(u64::from(closed)))),
                // Nothing is left to end.
                Err(super::door::DoorError::Refused(
                    minimald_rpc::PublishRefusal::NotPublished
                    | minimald_rpc::PublishRefusal::UnknownBox,
                )) => Ok(ClosedConnections(None)),
                Err(error) => Err(door_error(error)),
            }
        }
    }
}

/// gvproxy's wire spelling of an [`IpProto`] in a forwarder request.
fn protocol_str(proto: IpProto) -> &'static str {
    match proto {
        IpProto::Tcp => "tcp",
        IpProto::Udp => "udp",
        // gvproxy's forwarder only exposes TCP/UDP, and `Record::validate_policy`
        // rejects any other protocol before it reaches here. `IpProto` is also
        // `#[non_exhaustive]`, so the `_` arm cannot be eliminated; a
        // `debug_assert!` surfaces any future caller that bypasses validation in
        // test runs, while TCP — the forwarder's default transport — stays the
        // production fallback rather than a silently misrouted request.
        _ => {
            debug_assert!(
                false,
                "protocol_str reached its fallback with {proto:?}; validate_policy \
                 must reject every non-TCP/UDP ingress protocol before apply_ingress"
            );
            "tcp"
        }
    }
}

/// Builds the [`ExposeRequest`] that forwards `mapping`'s host-side
/// `external_port` — published at `published`, the host loopback address the
/// box's declaration is published on (NET-010) — to `ptask_ip:internal_port`
/// on the switch.
///
/// The `local` host is a loopback address so the forward binds host loopback
/// only: a process *on the host* reaches the port (R2.3), while the spec's "no
/// external exposure by default" keeps it off the LAN. It is the box's **own**
/// address, not `127.0.0.1`, wherever the reserved local range gave it one, so
/// two boxes naming the same port both publish — on their own addresses, at
/// their own port numbers (NET-010). A box that shares an address with another
/// and names a port it names too collides there; the collision is intrinsic to
/// the mode, so it is *reported* by the registry's publish — never translated
/// away here: neither port number is remapped (NET-129).
///
/// The `remote` targets the PTask's allocated switch address.
#[must_use]
pub fn expose_request(
    mapping: &PortMapping,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
) -> ExposeRequest {
    ExposeRequest {
        local: format!("{published}:{}", mapping.external_port),
        remote: format!("{ptask_ip}:{}", mapping.internal_port),
        protocol: protocol_str(mapping.proto).to_string(),
    }
}

/// A forward currently exposed on the switch, retained so it can be torn down
/// on PTask exit ([`remove_ingress`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedMapping {
    local: String,
    protocol: String,
}

impl ExposedMapping {
    /// The `host:port` the forward is bound on — the address the switch is
    /// actually holding, spelled exactly as its expose request named it. A
    /// caller reporting a publish (the per-mapping info line in
    /// `finish_own_ip_attach`) reads this instead of re-deriving the address
    /// from the request, so the report cannot claim a host a forward is not
    /// published on.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// [`Self::local`] split into the host address and port to report. `None`
    /// when `local` is not a `host:port` pair with a numeric port — a shape
    /// [`expose_request`], its only builder, never produces.
    #[must_use]
    pub fn host_port(&self) -> Option<(&str, u16)> {
        let (host, port) = self.local.rsplit_once(':')?;
        Some((host, port.parse().ok()?))
    }
}

/// A port's forward, owned by the daemon: the mapping the switch bound for
/// it and the internal port it forwards to.
#[derive(Clone)]
pub struct PortForwarder {
    mapping: ExposedMapping,
    internal_port: u16,
}

impl fmt::Debug for PortForwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortForwarder")
            .field("local", &self.mapping.local)
            .field("internal_port", &self.internal_port)
            .finish_non_exhaustive()
    }
}

impl PortForwarder {
    /// The forwarder of a forward the switch bound at `mapping`.
    fn bound(mapping: ExposedMapping, internal_port: u16) -> Self {
        Self {
            mapping,
            internal_port,
        }
    }

    /// The `host:port` the forward is bound on, as [`ExposedMapping`] reads
    /// it.
    #[must_use]
    pub fn local(&self) -> &str {
        self.mapping.local()
    }

    /// [`Self::local`] split into the host address and port.
    #[must_use]
    pub fn host_port(&self) -> Option<(&str, u16)> {
        self.mapping.host_port()
    }

    /// Whether this is the forward `mapping` declares at `published`: the
    /// same listener and the same protocol. TCP and UDP on one port are two
    /// forwards.
    #[must_use]
    pub fn is_forward_of(&self, published: Ipv4Addr, mapping: &PortMapping) -> bool {
        self.mapping.protocol == protocol_str(mapping.proto)
            && self.mapping.local == format!("{published}:{}", mapping.external_port)
    }

    /// The internal port the forward delivers to.
    #[must_use]
    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }
}

/// Exposes every static port mapping in `ingress` on the switch's `control_sock`
/// at `published` — the box's own host loopback address (NET-010) — forwarding
/// to `ptask_ip`, returning one daemon-owned [`PortForwarder`] per bound
/// forward (R2.3, R2.4-static, NET-121). The dynamic range, if any, is not
/// applied here — dynamic port-mapping is split to #553.
///
/// `yielded` is the ports the box yields at a shared address (NET-129,
/// first-come): another box holds each one, so its forward is known state,
/// not a failure. It is skipped, with one warn line naming the port and the
/// box that holds it, and the box's other forwards bind as usual.
///
/// A host port another process already holds is a failure like any other
/// refused bind (NET-121): the rollback below runs and the caller withdraws
/// the name. Only the returned error differs. It carries a
/// [`minimald_rpc::PortInUseRefusal`] in place of the forwarder's raw
/// refusal, and its kind is [`io::ErrorKind::AddrInUse`]. The refusal names
/// the port and its holder. `holder_of` says what holds a taken port. The
/// attach path passes [`port_holder`] over the hostname registry,
/// so the refusal names the box whose publish stands at that address and
/// port, or the host when none does.
///
/// On the first failure the already-bound forwards are rolled back so a
/// partial apply does not leak forwards onto the switch, and the original
/// error is returned. The failure says its own line first (NET-121's sub 2):
/// one warn per failed bind, naming the declared port and the reason, so the
/// daemon log's tail shows which port of which address could not bind.
///
/// # Errors
///
/// Returns the I/O error from the first failing `expose` call (after rollback).
pub async fn apply_ingress(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
    yielded: &[super::dns::SharedPortCollision],
    holder_of: &(dyn Fn(u16) -> minimald_rpc::PortHolder + Sync),
) -> io::Result<Vec<PortForwarder>> {
    apply_declared(control, published, ptask_ip, ingress, yielded, holder_of).await
}

/// Binds the declared forwards of a box on a VM-backed host when finalize
/// publishes it, before the record goes `Active` (NET-121, NET-144, design
/// §7.1: the bind succeeds before the name is published). On a VM-backed
/// host the forwarder binds on the host OS, so the daemon cannot probe the
/// ports itself ([`host_ports_in_use`]). It binds them, toward the
/// `switch_address` the VM host handed the box, and a held port fails with
/// the same typed refusal the native probe gives. A failure rolls back as
/// [`apply_ingress`] does.
///
/// The bound forwards stay on the host. The box's first attach asks for the
/// same forwards again, which the host already holds for it. The host
/// unbinds the forwards when it withdraws the box's row, as it does for
/// every declared forward ([`release_declared_ingress`]).
///
/// # Errors
///
/// As [`apply_ingress`].
pub async fn bind_declared_at_publish(
    control: &ControlChannel,
    published: Ipv4Addr,
    switch_address: Ipv4Addr,
    ingress: &IngressPolicy,
    yielded: &[super::dns::SharedPortCollision],
    holder_of: &(dyn Fn(u16) -> minimald_rpc::PortHolder + Sync),
) -> io::Result<Vec<PortForwarder>> {
    apply_declared(
        control,
        published,
        switch_address,
        ingress,
        yielded,
        holder_of,
    )
    .await
}

/// Binds each declared port's forward. A failure takes down what it bound.
async fn apply_declared(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
    yielded: &[super::dns::SharedPortCollision],
    holder_of: &(dyn Fn(u16) -> minimald_rpc::PortHolder + Sync),
) -> io::Result<Vec<PortForwarder>> {
    let mut bound: Vec<PortForwarder> = Vec::with_capacity(ingress.port_mappings.len());
    for mapping in &ingress.port_mappings {
        if let Some(collision) = yielded
            .iter()
            .find(|collision| collision.port == mapping.external_port)
        {
            tracing::warn!(
                port = mapping.external_port,
                address = %published,
                other = %collision.other,
                action = "shared-address-port-collision",
                "declared ingress port not bound: another box at the shared \
                 address holds it"
            );
            continue;
        }
        let opened = open_forward(
            control,
            mapping,
            published,
            ptask_ip,
            minimald_rpc::PublishOrigin::Declared,
        )
        .await;
        match opened {
            Ok(exposed) => bound.push(PortForwarder::bound(exposed, mapping.internal_port)),
            Err(e) => {
                // The failed bind is the failure's own fact, said where it
                // happened: the declared port, the address it tried to bind
                // on, and the reason the switch gave. What follows — the
                // rollback and the caller's refusal to publish — reads it in
                // the log beside the name that was never registered.
                tracing::warn!(
                    port = mapping.external_port,
                    %published,
                    error = %e,
                    "binding declared ingress port failed"
                );
                // Roll back what we managed to expose so a half-applied policy
                // does not leave dangling forwards on the shared switch.
                release_declared_ingress(control, &bound).await;
                // A taken host port fails the apply like any other refusal:
                // NET-121 (docs/specs/18-spec-box-networking, design §7.1)
                // makes a failed bind a surfaced error, never a silent
                // fallback, so the box never publishes a name while one of
                // its declared ports is missing. Only the error's words
                // differ: they name the port and the way out.
                if is_address_in_use(&e) {
                    return Err(address_in_use_error(minimald_rpc::PortInUseRefusal {
                        port: mapping.external_port,
                        box_port: mapping.internal_port,
                        holder: holder_of(mapping.external_port),
                    }));
                }
                return Err(e);
            }
        }
    }
    Ok(bound)
}

/// The OS's own text for a bind onto a port another process already holds,
/// as it reaches [`apply_ingress`] inside the forwarder's refusal.
const ADDRESS_IN_USE_BODY: &str = "address already in use";

/// Whether `error` is the forwarder refusing an `expose` because the host
/// port it binds is already in use — the OS's `EADDRINUSE` text, matched on
/// the message's own words rather than the forwarder's surrounding wording,
/// so a differently-phrased listener on the same bind is still read as the
/// same fact.
fn is_address_in_use(error: &io::Error) -> bool {
    if host_refusal(error) == Some(minimald_rpc::PublishRefusal::PortInUse) {
        return true;
    }
    let said = error.to_string();
    said.contains("returned HTTP 500") && said.contains(ADDRESS_IN_USE_BODY)
}

/// The declared TCP host ports of `ingress` that another process already
/// holds at `published`, found by a short-lived bind of each one in this
/// daemon's network namespace — the same bind the forwarder makes at the
/// box's first spawn when `control` reaches a switch this daemon spawned.
/// When the host unbinds the declared forwards
/// ([`ControlChannel::host_unbinds_declared_forwards`]), the forwarder
/// binds on the host OS, not where this daemon runs, so a bind here would
/// test the wrong ports: the probe reports nothing and the spawn's own
/// apply says a taken port. A port in `yielded` is skipped, because another
/// box at the shared address holds it and the collision report already
/// names it. A bind that fails for any reason other than `EADDRINUSE`
/// reports nothing: the spawn's own apply says that failure. Call this only
/// when the box's forwards are not bound, or it finds the box's own
/// forwards.
#[must_use]
pub fn host_ports_in_use(
    control: &ControlChannel,
    published: Ipv4Addr,
    ingress: &IngressPolicy,
    yielded: &[u16],
) -> Vec<u16> {
    if control.host_unbinds_declared_forwards() {
        return Vec::new();
    }
    ingress
        .port_mappings
        .iter()
        .filter(|mapping| mapping.proto == boxes::IpProto::Tcp)
        .map(|mapping| mapping.external_port)
        .filter(|port| !yielded.contains(port))
        .filter(|&port| port_held_at(published, port))
        .collect()
}

/// How many times [`port_held_at`] binds a port before it reports the port
/// held.
const PORT_HELD_BINDS: u32 = 3;
const _: () = assert!(PORT_HELD_BINDS > 1, "one failed bind is not enough");

/// The pause between two binds of [`port_held_at`].
const PORT_HELD_RETRY: Duration = Duration::from_millis(20);

/// Whether another process holds `port` at `address`: every one of
/// [`PORT_HELD_BINDS`] binds, [`PORT_HELD_RETRY`] apart, fails with
/// `EADDRINUSE`. A single failed bind is not enough, because a parallel
/// probe of the same port holds it for the moment of its own bind. A real
/// holder fails every bind. The first bind that succeeds, or fails for any
/// other reason, ends the probe at once, so a free port costs no pause.
fn port_held_at(address: Ipv4Addr, port: u16) -> bool {
    port_held_by(|| std::net::TcpListener::bind((address, port)).map(drop))
}

/// [`port_held_at`]'s rule over any `bind`, so a test can fail chosen
/// binds in turn without racing a listener's release.
fn port_held_by(mut bind: impl FnMut() -> io::Result<()>) -> bool {
    for attempt in 1..=PORT_HELD_BINDS {
        match bind() {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                if attempt < PORT_HELD_BINDS {
                    std::thread::sleep(PORT_HELD_RETRY);
                }
            }
            _ => return false,
        }
    }
    true
}

/// The error [`apply_ingress`] returns for a declared port that something
/// else already holds on the host, and the error a finalize returns when it
/// finds one before the box is active. A person reads it at the failed
/// activation or command, so it names the port, its holder and the next step
/// (NET-144). The forwarder's own refusal is in the warn line
/// [`apply_ingress`] logs, not here. The kind is
/// [`io::ErrorKind::AddrInUse`], and the payload is the typed refusal, which
/// [`port_in_use_refusal`] reads back.
pub fn address_in_use_error(refusal: minimald_rpc::PortInUseRefusal) -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, refusal)
}

/// The typed refusal inside `error`, when it is one [`address_in_use_error`]
/// built or when its text carries one, as an error wrapped on its way up
/// does.
#[must_use]
pub fn port_in_use_refusal(error: &io::Error) -> Option<minimald_rpc::PortInUseRefusal> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<minimald_rpc::PortInUseRefusal>())
        .cloned()
        .or_else(|| minimald_rpc::PortInUseRefusal::find_in(&error.to_string()))
}

/// What holds `port` at `address` (NET-144): the box whose publish stands
/// there in the hostname registry, or the host when no box does. A holder
/// named `own_name` is the box that asks, so it does not count: then the
/// host holds the port.
#[must_use]
pub fn port_holder(
    registry: &std::sync::RwLock<super::dns::HostnameRegistry>,
    own_name: &str,
    address: Ipv4Addr,
    port: u16,
) -> minimald_rpc::PortHolder {
    registry
        .read()
        .expect("hostname registry lock poisoned")
        .own_port_holder(address, port)
        .map(|(_, name)| name)
        .filter(|name| name != own_name)
        .map_or(
            minimald_rpc::PortHolder::Host,
            minimald_rpc::PortHolder::Box,
        )
}

/// The body the forwarder answers an expose with when a forward is already
/// bound at the listener, as an HTTP 500.
const ALREADY_RUNNING_BODY: &str = "proxy already running";

/// Binds the forward of a declared port this box took over at a shared
/// address.
///
/// # Errors
///
/// What the forward's holder refused with.
pub async fn bind_handed_port(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    mapping: &PortMapping,
) -> io::Result<PortForwarder> {
    let exposed = open_forward(
        control,
        mapping,
        published,
        ptask_ip,
        minimald_rpc::PublishOrigin::Declared,
    )
    .await?;
    Ok(PortForwarder::bound(exposed, mapping.internal_port))
}

/// Removes every forward in `bound` from the switch's `control_sock` (R2.3
/// teardown on PTask exit). Best-effort: a failed unexpose is logged and the
/// rest still attempted, since teardown runs on the session-end path where there
/// is no caller left to propagate to. A bound forward that comes down says one
/// info line (NET-121), naming the port it unbound — the unbind half of the
/// per-forwarder bind/unbind pair the daemon log carries.
pub async fn remove_ingress(control: &ControlChannel, bound: &[PortForwarder]) {
    for forwarder in bound {
        let (host, external_port) = forwarder.host_port().unwrap_or(("", 0));
        match close_forward(control, &forwarder.mapping).await {
            Ok(closed) => {
                tracing::info!(
                    host,
                    port = external_port,
                    closed_connections = %closed,
                    reason = "box stopped",
                    "unbound ingress forwarder"
                );
            }
            Err(e) => {
                tracing::warn!(
                    local = %forwarder.local(),
                    error = %e,
                    "removing ingress port mapping from switch on PTask exit"
                );
            }
        }
    }
}

/// Unbinds one forward and says whether the switch let it go: the fallible
/// twin of [`remove_ingress`], for a caller that keeps tracking a forward the
/// switch still holds so a later teardown can retry it.
pub async fn unexpose_forwarder(
    control: &ControlChannel,
    forwarder: &PortForwarder,
) -> io::Result<()> {
    let closed = unexpose_mapping(control, &forwarder.mapping).await?;
    // The caller says why in its own line. This line carries the switch's
    // count, and claims no withdrawal.
    let (host, port) = forwarder.mapping.host_port().unwrap_or(("", 0));
    tracing::info!(
        host,
        port,
        protocol = %forwarder.mapping.protocol,
        closed_connections = %closed,
        "unbound a port's forward on the switch"
    );
    Ok(())
}

/// Takes down the forwards of declared ports at the end of a box. The VM
/// host ends the ones it holds itself, when it is told that the box ended.
pub async fn release_declared_ingress(control: &ControlChannel, bound: &[PortForwarder]) {
    if !control.host_unbinds_declared_forwards() {
        remove_ingress(control, bound).await;
        return;
    }
    for forwarder in bound {
        let (host, external_port) = forwarder.host_port().unwrap_or(("", 0));
        tracing::info!(
            host,
            port = external_port,
            reason = "box stopped",
            "left the declared ingress forwarder for the host to unbind"
        );
    }
}

/// Opens the forward for a port the box listens on.
///
/// # Errors
///
/// What the forward's holder refused with.
pub async fn expose_mapping(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    port: u16,
) -> io::Result<ExposedMapping> {
    let mapping = PortMapping {
        external_port: port,
        internal_port: port,
        proto: IpProto::Tcp,
    };
    open_forward(
        control,
        &mapping,
        published,
        ptask_ip,
        minimald_rpc::PublishOrigin::Listen,
    )
    .await
}

/// How many accepted connections the switch closed when it unexposed a
/// forward: the `closed` field of the patched switch's `/unexpose` reply
/// (`vendor/gvproxy/patches/`). `None` when the reply carries no count, so
/// the log says unknown rather than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedConnections(pub Option<u64>);

impl ClosedConnections {
    /// The count in an `/unexpose` reply body, `{"closed":<n>}`.
    pub(crate) fn from_reply(body: &[u8]) -> Self {
        #[derive(serde::Deserialize)]
        struct Reply {
            closed: Option<u64>,
        }
        let text = String::from_utf8_lossy(body);
        let text = text.trim();
        if text.is_empty() {
            return Self(None);
        }
        Self(
            serde_json_lenient::from_str::<Reply>(text)
                .ok()
                .and_then(|reply| reply.closed),
        )
    }
}

impl fmt::Display for ClosedConnections {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(n) => write!(f, "{n}"),
            None => f.write_str("unknown"),
        }
    }
}

/// Ends the forward at `mapping`.
///
/// # Errors
///
/// What the forward's holder refused with.
pub async fn unexpose_mapping(
    control: &ControlChannel,
    mapping: &ExposedMapping,
) -> io::Result<ClosedConnections> {
    close_forward(control, mapping).await
}

/// NET-017's one line per withdrawal: a published port's listener closed and
/// its forward came down. The box is the caller's span: the listen watcher
/// runs inside one that names it. The line claims closed connections only
/// when the switch reported a count. An unpatched switch reports none, so
/// the line then says the count is not known.
pub fn log_withdrawal(mapping: &ExposedMapping, closed: ClosedConnections) {
    let (host, port) = mapping.host_port().unwrap_or(("", 0));
    if closed.0.is_some() {
        tracing::info!(
            host,
            port,
            protocol = %mapping.protocol,
            closed_connections = %closed,
            "withdrew a published port, and the switch closed the connections it accepted"
        );
    } else {
        tracing::info!(
            host,
            port,
            protocol = %mapping.protocol,
            closed_connections = %closed,
            "withdrew a published port, and the switch did not report how many \
             accepted connections it closed"
        );
    }
}

/// Why a runtime port-publish request was refused **before** the switch was
/// asked anything: the typed error NET-044's deny arm answers with, rather
/// than a bare message, so a caller can tell "this box denies dynamic
/// ingress" from "that port is out of range" without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposeRefusal {
    /// The box's `dynamic_ingress` is unset or `deny` — the deny-all default
    /// an absent declaration means.
    DeniedByPolicy,
    /// `dynamic_ingress` is `ask`: the attached human decides (NET-045), and
    /// with nobody attached — or until that prompt path exists — the request
    /// fails closed rather than publishing unasked.
    AskNeedsAnswer,
    /// `dynamic_ingress` is `ask` and the attached human answered no — or
    /// keyed a cancel, which means the same (NET-045): the box's own deny
    /// answer, now in the human's hand. The log and the audit record say it
    /// with the deny's words; the caller's line says who declined.
    DeniedByHuman,
    /// `dynamic_ingress` is `ask` and the VM host's attached client could
    /// not show the dialog — no terminal to draw it on — so the ask ended
    /// in the deny an unanswerable dialog defaults to.
    AskNoTerminal,
    /// `dynamic_ingress` allows, but the box declares no
    /// `dynamic_allowed_range`: no port was opted in.
    NoDynamicRange,
    /// The requested port lies outside the declared `dynamic_allowed_range`.
    OutOfRange { requested: u16, range: (u16, u16) },
    /// The box holds no address the hostname registry published for it, so
    /// there is nowhere to bind. A capability gap: waiting does not fix it.
    NoPublishedAddress,
    /// The box has a published address but no running PTask attached to the
    /// switch — no lease reported yet, or the spawn that held one has ended —
    /// so there is nothing to forward to until the box is started.
    NotAttached,
    /// No box is running behind the session: it was stopped, and its record
    /// still reads `active` — but the publish has nothing to deliver to, and a
    /// forward bound for the lease it would name would answer for nothing.
    /// Starting the box again is what fixes it.
    NotRunning,
    /// The port is held already by this box's other runtime surface — the
    /// reservation or publication that holds it, whichever surface that
    /// is, named by the owner the loser is refused with. While `pending`
    /// is true the hold is a reservation whose publish has not landed
    /// yet: the port is on its way to being published, not there yet.
    AlreadyPublished {
        port: u16,
        owner: super::listeners::PublicationOwner,
        pending: bool,
    },
    /// The port is published already for this box by its own listening
    /// process (NET-016): the publication stands, its gate admits the port,
    /// and it is listed at `local`. The request's goal is met, not refused,
    /// so the in-box caller hears this as a plain message and exits 0. The
    /// request publishes nothing of its own: the publication stays the
    /// listener's, and it is withdrawn when the listener closes (NET-017).
    ListenPublished { port: u16, local: SocketAddr },
    /// The box shares the host's network (`host_ip`), so the port already
    /// answers on the host and there is nothing to publish. The request's
    /// goal is met, not refused, so the in-box caller hears this as a plain
    /// message and exits 0. `host_loopback` says whether the host's own
    /// loopback is one of the places it answers: true on a native host, and
    /// false on a VM-backed one, where the loopback the box shares is the
    /// guest's and the name is the only host-reachable answer (NET-129).
    NeedsNoExposing { port: u16, host_loopback: bool },
}

impl ExposeRefusal {
    /// The line the in-box `min net expose` prints for this refusal: the
    /// verdict and, where a way forward exists, the way forward, named with
    /// the box's current host-side name and the port the request asked for,
    /// so a detached agent reading it has its next command. `network` is the
    /// box's mode: a `--network none` box carries no dynamic ingress at all,
    /// so re-activating with it is no way forward there, and the host-side
    /// forward — which dials inside the box's own namespace — is the one
    /// offered. The verdict alone (`Display`) is what the log line and the
    /// audit record carry.
    #[must_use]
    pub fn for_caller(&self, box_name: &str, network: boxes::NetworkMode, port: u16) -> String {
        let forward = format!("min net forward {box_name} <local>:{port}");
        match self {
            Self::DeniedByPolicy => match network {
                boxes::NetworkMode::NoNet => format!(
                    "{self}: a --network none box has no address to publish at. Forward it \
                     from the host instead: {forward}"
                ),
                // `NetworkMode` is non-exhaustive; every other mode gets the
                // own-address advice.
                _ => format!(
                    "{self}. Re-activate with --network own_ip and --dynamic-ingress allow \
                     --dynamic-range <lo>-<hi> (or --dynamic-ingress ask) to allow it, or \
                     forward it from the host now: {forward}"
                ),
            },
            Self::DeniedByHuman => format!(
                "{self}: the person attached to this session answered no. Ask again, or \
                 forward it from the host: {forward}"
            ),
            Self::AskNoTerminal => format!(
                "{self}: no terminal was attached to answer. Attach one and retry, or \
                 forward it from the host: {forward}"
            ),
            Self::AskNeedsAnswer => format!(
                "{self}: attach a terminal (min session attach {box_name}) and retry, or \
                 have the host forward it ({forward})"
            ),
            Self::NeedsNoExposing {
                host_loopback: true,
                ..
            } => format!(
                "{self}, so it already answers at {box_name}.min.internal:{port} \
                 (and localhost:{port})"
            ),
            Self::NeedsNoExposing {
                host_loopback: false,
                ..
            } => format!("{self}, so it already answers at {box_name}.min.internal:{port}"),
            // The same words for an allow-stance and an ask-stance box: the
            // range refused the port before any prompt (NET-047).
            Self::OutOfRange { .. } => format!("{self}. Nothing was published."),
            // The listener's publication is the one standing, so the
            // caller hears how long it lasts: it is not the request's own.
            Self::ListenPublished { .. } => {
                format!("{self}. It is unpublished when that process stops listening on it.")
            }
            _ => self.to_string(),
        }
    }
}

impl fmt::Display for ExposeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // One verdict for the three denies: the policy's, the human's
            // and the one an unshowable dialog defaults to. The log and the
            // audit record pin these words; the caller's line tells them
            // apart.
            Self::DeniedByPolicy | Self::DeniedByHuman | Self::AskNoTerminal => {
                write!(f, "dynamic ingress is denied for this box")
            }
            Self::AskNeedsAnswer => write!(
                f,
                "dynamic ingress is set to ask and nobody is attached to answer"
            ),
            Self::NoDynamicRange => write!(
                f,
                "this box has no --dynamic-range, so no port can be opened at runtime"
            ),
            Self::OutOfRange { requested, range } => write!(
                f,
                "port {requested} is outside this box's --dynamic-range {}-{}",
                range.0, range.1
            ),
            Self::NoPublishedAddress => write!(
                f,
                "this box was given no address on the host to open a port at"
            ),
            Self::NotAttached => write!(
                f,
                "this box's network is not connected, so no port can be opened on it; \
                 start the box and try again"
            ),
            Self::NotRunning => {
                write!(
                    f,
                    "this box is not running, so there is nothing to open a port on; \
                     start the box and try again"
                )
            }
            Self::AlreadyPublished {
                port,
                owner,
                pending,
            } => {
                let state = if *pending {
                    "is being published"
                } else {
                    "is published already"
                };
                write!(f, "port {port} {state} by this box ({})", owner.as_str())
            }
            Self::ListenPublished { port, local } => write!(
                f,
                "port {port} is published already at {local}, because a process in this box \
                 is listening on it"
            ),
            Self::NeedsNoExposing { port, .. } => write!(
                f,
                "port {port} needs no exposing: this box shares the host's network"
            ),
        }
    }
}

/// Why one runtime port-publish request ended without a publish — the answer
/// the session actor hands its caller, which is what the box's own
/// `min net expose` prints.
#[derive(Debug)]
pub enum ExposeFailure {
    /// The box's `dynamic_ingress` decision refused the port: the switch was
    /// asked nothing, so nothing partial is left behind (NET-047).
    Refused(ExposeRefusal),
    /// The publish could not be made — the switch refused the bind or never
    /// answered. One mapping is one request, so a bind that failed bound
    /// nothing and asked nothing further (NET-047).
    Publish { port: u16, source: io::Error },
    /// The box's own record could not be read to decide the request, so its
    /// name, its policy and its addresses are all unknown. Refused rather
    /// than guessed at: the switch was asked nothing, and nothing was bound
    /// (NET-047). Its own arm — not `Publish` — because a caller that knows
    /// the box's name without the record (the env channel, from the
    /// environment's own name) is the one that can still say whose request
    /// this was in the one line the request owes the log.
    RecordUnreadable { port: u16, source: io::Error },
    /// The session actor dropped the request's reply channel before
    /// answering — the box is stopping or stopped, so nobody is home to
    /// decide it. The switch was asked nothing and nothing was bound. Its
    /// own arm — not `Publish` — because the actor never reached the bind:
    /// a real `ENOTCONN` out of a bind the actor *did* attempt stays a
    /// `Publish`, and conflating the two would log one request twice.
    ActorGone { port: u16 },
}

impl fmt::Display for ExposeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::Publish { port, source } => {
                write!(f, "publishing port {port} failed: {source}")
            }
            Self::RecordUnreadable { port, source } => {
                write!(
                    f,
                    "port {port} was not opened: the session's saved state could \
                     not be read: {source}"
                )
            }
            Self::ActorGone { port } => {
                write!(
                    f,
                    "port {port} was not opened: the box is stopping or stopped"
                )
            }
        }
    }
}

/// Decides one runtime port-publish request against the box's
/// `dynamic_ingress` setting (NET-043): `ingress` is the box's declared
/// ingress half, `None` the deny-all default an absent declaration means.
/// `Ok(DynamicIngress::Allow)` when the box allows the port; the typed
/// refusal saying why not otherwise.
///
/// The stance and the range are [`IngressRules::dynamic_verdict`]'s to
/// derive — the one derivation this decision and the listen watcher's
/// verdict share, so the two runtime ingress surfaces cannot part ways on a
/// port — and this is the half that renders each fact as the refusal the
/// box's `min net expose` prints. An `ask` box's range is checked here too,
/// so a port outside it is refused without a prompt.
pub fn dynamic_ingress_decision(
    ingress: Option<&IngressPolicy>,
    port: u16,
) -> Result<boxes::DynamicIngress, ExposeRefusal> {
    match IngressRules::from_policy(ingress).dynamic_verdict(port) {
        DynamicPortVerdict::Allow => Ok(boxes::DynamicIngress::Allow),
        DynamicPortVerdict::Deny => Err(ExposeRefusal::DeniedByPolicy),
        // An `ask` box with a range refuses a port outside it here, before
        // any prompt is routed: no answer could publish it (NET-047).
        DynamicPortVerdict::Ask => match ingress.and_then(|i| i.dynamic_allowed_range) {
            Some(range) if port < range.0 || port > range.1 => Err(ExposeRefusal::OutOfRange {
                requested: port,
                range,
            }),
            _ => Err(ExposeRefusal::AskNeedsAnswer),
        },
        DynamicPortVerdict::NoRange => Err(ExposeRefusal::NoDynamicRange),
        DynamicPortVerdict::OutOfRange { range } => Err(ExposeRefusal::OutOfRange {
            requested: port,
            range,
        }),
    }
}

/// Publishes one port a process inside the box asked for at runtime
/// (NET-043/NET-044): the box's own port number, at the address its
/// registration handed it, forwarded to its own switch address — the same
/// request shape a declared mapping takes ([`expose_request`]). The caller
/// decides the request with [`dynamic_ingress_decision`] first; this is the
/// publish half only.
///
/// One mapping is one expose request, so the guarantee [`apply_ingress`]
/// buys with a rollback is structural here: a request that fails binds
/// nothing, and there is no earlier forward to roll back — the rejected
/// request leaves no partial mapping (NET-047). The bind's failure says its
/// own line, naming the port and the `local` it tried, the way the declared
/// binds' failures do.
///
/// # Errors
///
/// Returns the I/O error from the failing `expose` call.
pub async fn expose_dynamic(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    port: u16,
    proto: IpProto,
) -> io::Result<PortForwarder> {
    let mapping = PortMapping {
        external_port: port,
        internal_port: port,
        proto,
    };
    let opened = open_forward(
        control,
        &mapping,
        published,
        ptask_ip,
        minimald_rpc::PublishOrigin::Expose,
    )
    .await;
    match opened {
        Ok(exposed) => Ok(PortForwarder::bound(exposed, port)),
        Err(e) => {
            tracing::warn!(
                port,
                %published,
                error = %e,
                "binding dynamic ingress port failed"
            );
            Err(e)
        }
    }
}

/// `POST`s `body` as JSON to `path` on gvproxy's control socket over a fresh
/// HTTP/1.1 keep-alive connection, succeeding on a 2xx status.
///
/// The forwarder verbs are ordinary request/response. The exchange is framed
/// by `Content-Length` (not read-to-EOF) with **no** `Connection: close` (see
/// [`exchange`]).
pub(crate) async fn post_json<T: Serialize>(
    control: &std::path::Path,
    path: &str,
    body: &T,
) -> io::Result<()> {
    post_json_within(control, path, body, GVPROXY_CONTROL_TIMEOUT).await
}

/// [`post_json`] with the exchange's bound injected: the publish verbs run at
/// [`GVPROXY_CONTROL_TIMEOUT`].
pub(crate) async fn post_json_within<T: Serialize>(
    control: &std::path::Path,
    path: &str,
    body: &T,
    timeout: Duration,
) -> io::Result<()> {
    post_json_reply_within(control, path, body, timeout)
        .await
        .map(drop)
}

/// [`post_json_within`] that hands back the body of a 2xx reply, for a verb
/// whose answer carries data: the patched switch's `/unexpose` says how many
/// accepted connections it closed.
pub(crate) async fn post_json_reply_within<T: Serialize>(
    control: &std::path::Path,
    path: &str,
    body: &T,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let body = serde_json_lenient::to_vec(body).map_err(io::Error::other)?;
    let mut request = Vec::with_capacity(128 + body.len());
    // HTTP/1.1 keep-alive (no `Connection: close`): `exchange` reads exactly
    // `Content-Length` bytes and this side closes the connection.
    request.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    request.extend_from_slice(b"Host: localhost\r\n");
    request.extend_from_slice(b"Content-Type: application/json\r\n");
    request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&body);

    // Bound the whole exchange: a gvproxy that accepts the socket and then
    // stalls must not hang the launch or teardown path indefinitely.
    let response = tokio::time::timeout(timeout, async {
        exchange(UnixStream::connect(control).await?, &request).await
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("gvproxy {path} control request timed out after {timeout:?}"),
        )
    })??;

    let status = parse_status_code(&response)?;
    if (200..300).contains(&status) {
        Ok(body_after_headers(&response).to_vec())
    } else {
        let said = String::from_utf8_lossy(body_after_headers(&response));
        // A refusal that says the listener is already held, by another host
        // process (the OS's bind text) or by a forward this forwarder already
        // runs, carries `AddrInUse`: the address exists, and a caller that
        // reads the kind can tell it from a missing one.
        let kind = if status == 500
            && (said.contains(ADDRESS_IN_USE_BODY) || said.contains(ALREADY_RUNNING_BODY))
        {
            io::ErrorKind::AddrInUse
        } else {
            io::ErrorKind::Other
        };
        Err(io::Error::new(
            kind,
            format!("gvproxy {path} returned HTTP {status}: {said}"),
        ))
    }
}

/// Writes `request` to a freshly-connected control stream and reads the response
/// framed by its `Content-Length`.
///
/// We must **not** read to EOF: the request is HTTP/1.1 keep-alive (see
/// [`post_json`]), so gvproxy holds the connection open after responding and an
/// EOF-terminated read would block until the [`GVPROXY_CONTROL_TIMEOUT`]. Instead
/// we read the status line + headers, take `Content-Length` body bytes, and let
/// the caller drop the stream.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    stream.write_all(request).await?;

    // Read incrementally until the header terminator is in hand, capping total
    // buffered bytes: gvproxy's forwarder replies are tiny, so a stream that never
    // completes its headers within the bound is misbehaving.
    let mut response = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    let header_end = loop {
        if let Some(i) = find_header_end(&response) {
            break i;
        }
        if response.len() as u64 >= MAX_CONTROL_RESPONSE {
            return Err(io::Error::other(
                "gvproxy control response exceeded the size cap before its headers ended",
            ));
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            // EOF before headers completed — the empty-reply symptom the
            // keep-alive framing is meant to avoid; surface it as-is.
            return Ok(response);
        }
        response.extend_from_slice(&buf[..n]);
    };

    // Body length from `Content-Length` (0 if absent). Read until the body is
    // fully buffered, so we never depend on a server close to signal completion.
    let want = content_length(&response[..header_end]).unwrap_or(0);
    let body_have = response.len() - header_end;
    let mut remaining = want.saturating_sub(body_have);
    while remaining > 0 {
        if response.len() as u64 >= MAX_CONTROL_RESPONSE {
            break;
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        remaining = remaining.saturating_sub(n);
    }
    Ok(response)
}

/// Parses the numeric status code from an HTTP response's status line
/// (`HTTP/1.x <code> <reason>`).
fn parse_status_code(response: &[u8]) -> io::Result<u16> {
    let line_end = response
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(response.len());
    let line = std::str::from_utf8(&response[..line_end])
        .map_err(|_| io::Error::other("gvproxy response status line was not UTF-8"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed gvproxy status line: {line:?}")))
}

/// Index just past the `\r\n\r\n` header terminator, or `None` if the headers are
/// not yet fully buffered.
fn find_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// The `Content-Length` header value parsed from a response's header block, or
/// `None` if the header is absent or unparseable (treated as a zero-length body).
fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

/// Returns the body bytes following the blank line that ends the headers, or the
/// whole buffer if no header terminator is found (best-effort, for diagnostics).
fn body_after_headers(response: &[u8]) -> &[u8] {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(response, |i| &response[i + 4..])
}

/// Upper bound on a single gvproxy control request (expose/unexpose). The
/// control socket can accept the connection and then stall or never close;
/// without a bound, teardown's `remove_ingress` would block forever before the
/// switch `detach`, leaving the PTask attached and its forwards present.
pub(crate) const GVPROXY_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on bytes buffered from a single gvproxy control response. The
/// forwarder's replies are a status line plus a tiny body, so 64 KiB is far
/// above any legitimate response while capping memory if a misbehaving socket
/// streams without closing inside the [`GVPROXY_CONTROL_TIMEOUT`] window.
const MAX_CONTROL_RESPONSE: u64 = 64 * 1024;

/// Which direction a policy violation occurred in, for R2.7's `direction`
/// structured field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound traffic from the PTask (an egress-policy violation).
    Egress,
    /// Inbound traffic to the PTask (an ingress-policy violation).
    Ingress,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Egress => "egress",
            Self::Ingress => "ingress",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The end of a box reaches the VM host under the box's id. A node
    /// with its own gvproxy has nobody to tell.
    #[tokio::test]
    async fn the_end_of_a_box_is_reported_to_the_vm_host_alone() {
        use crate::net::door::testing::{FakeHost, box_id};
        use minimald_rpc::{GuestDoorReply, GuestDoorRequest};

        let (told, mut ended) = tokio::sync::mpsc::unbounded_channel();
        let host = FakeHost::answering(move |request| {
            let GuestDoorRequest::EndBox(end) = request else {
                panic!("{request:?}")
            };
            told.send(end.box_id).expect("the test listens");
            Some(GuestDoorReply::BoxEnded {
                ended: true,
                box_id: end.box_id,
                forwards_unbound: 0,
                still_bound: 0,
            })
        });
        let in_a_vm = ControlChannel::VmHost {
            door: Arc::new(crate::net::door::GuestDoor::new(host)),
            box_id: Some(box_id(3)),
        };
        let answered = in_a_vm.report_box_end().await;
        assert!(answered.is_some_and(|answered| answered.ended));
        assert_eq!(ended.recv().await, Some(box_id(3)));

        let native = ControlChannel::unix("/nonexistent/gvproxy.sock");
        assert_eq!(native.report_box_end().await, None);
    }

    #[test]
    fn expose_request_maps_host_port_to_ptask_ip() {
        // R2.3/R2.4-static: external_port forwards to the PTask's switch IP on
        // internal_port; the local host is the box's own loopback address
        // (NET-010) so only the host can connect.
        let mapping = PortMapping {
            external_port: 18080,
            internal_port: 80,
            proto: IpProto::Tcp,
        };
        let published = Ipv4Addr::new(127, 0, 64, 9);
        let req = expose_request(&mapping, published, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(req.local, "127.0.64.9:18080");
        assert_eq!(req.remote, "100.64.0.2:80");
        assert_eq!(req.protocol, "tcp");
    }

    #[test]
    fn expose_request_serializes_to_gvproxy_fields() {
        let mapping = PortMapping {
            external_port: 5353,
            internal_port: 53,
            proto: IpProto::Udp,
        };
        // A box with no address of its own publishes on the node's shared
        // one, still at its own port numbers (NET-123's interim, NET-129).
        let req = expose_request(&mapping, Ipv4Addr::LOCALHOST, Ipv4Addr::new(100, 64, 0, 7));
        let json = serde_json_lenient::to_string(&req).unwrap();
        assert!(json.contains("\"local\":\"127.0.0.1:5353\""), "got: {json}");
        assert!(json.contains("\"remote\":\"100.64.0.7:53\""), "got: {json}");
        assert!(json.contains("\"protocol\":\"udp\""), "got: {json}");
    }

    #[test]
    fn refusals_name_the_way_forward_for_the_caller() {
        use boxes::NetworkMode;

        // The in-box line carries the verdict and the next command, named
        // with the host-side box name and the port asked for; the verdict
        // alone is what the log and the audit record keep.
        assert_eq!(
            ExposeRefusal::DeniedByPolicy.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is denied for this box. Re-activate with --network own_ip and \
             --dynamic-ingress allow --dynamic-range <lo>-<hi> (or --dynamic-ingress ask) \
             to allow it, or forward it from the host now: min net forward web <local>:3001"
        );
        // A `--network none` box cannot carry dynamic ingress, so the only
        // way forward is the host's forward, which dials inside the box.
        assert_eq!(
            ExposeRefusal::DeniedByPolicy.for_caller("web", NetworkMode::NoNet, 3001),
            "dynamic ingress is denied for this box: a --network none box has no address \
             to publish at. Forward it from the host instead: min net forward web \
             <local>:3001"
        );
        // The three denies share the verdict and differ in the way forward.
        assert_eq!(
            ExposeRefusal::DeniedByHuman.to_string(),
            ExposeRefusal::DeniedByPolicy.to_string()
        );
        assert_eq!(
            ExposeRefusal::AskNoTerminal.to_string(),
            ExposeRefusal::DeniedByPolicy.to_string()
        );
        assert_eq!(
            ExposeRefusal::DeniedByHuman.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is denied for this box: the person attached to this session \
             answered no. Ask again, or forward it from the host: min net forward web \
             <local>:3001"
        );
        assert_eq!(
            ExposeRefusal::AskNoTerminal.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is denied for this box: no terminal was attached to answer. \
             Attach one and retry, or forward it from the host: min net forward web \
             <local>:3001"
        );
        assert_eq!(
            ExposeRefusal::AskNeedsAnswer.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is set to ask and nobody is attached to answer: attach a \
             terminal (min session attach web) and retry, or have the host forward it \
             (min net forward web <local>:3001)"
        );
        // Natively the host's loopback answers too; on a VM-backed host the
        // loopback the box shares is the guest's, so only the name is named.
        assert_eq!(
            ExposeRefusal::NeedsNoExposing {
                port: 3001,
                host_loopback: true
            }
            .for_caller("web", NetworkMode::HostNet, 3001),
            "port 3001 needs no exposing: this box shares the host's network, so it \
             already answers at web.min.internal:3001 (and localhost:3001)"
        );
        assert_eq!(
            ExposeRefusal::NeedsNoExposing {
                port: 3001,
                host_loopback: false
            }
            .for_caller("web", NetworkMode::HostNet, 3001),
            "port 3001 needs no exposing: this box shares the host's network, so it \
             already answers at web.min.internal:3001"
        );
        // The hold a port loses to is one watch in either of its two
        // states: the publication it stands on, or the reservation still
        // on its way there. Each state is its own verdict, and the in-box
        // line names it the same way the log does.
        assert_eq!(
            ExposeRefusal::AlreadyPublished {
                port: 3001,
                owner: crate::net::listeners::PublicationOwner::Listen,
                pending: false
            }
            .for_caller("web", NetworkMode::OwnIp, 3001),
            "port 3001 is published already by this box (listen)"
        );
        assert_eq!(
            ExposeRefusal::AlreadyPublished {
                port: 3001,
                owner: crate::net::listeners::PublicationOwner::Listen,
                pending: true
            }
            .for_caller("web", NetworkMode::OwnIp, 3001),
            "port 3001 is being published by this box (listen)"
        );
        // A port the box's own listener published is the goal met: the
        // line says where it answers, and that the publication is the
        // listener's, which goes when the listener does.
        assert_eq!(
            ExposeRefusal::ListenPublished {
                port: 3001,
                local: SocketAddr::from(([127, 0, 64, 9], 3001)),
            }
            .for_caller("web", NetworkMode::OwnIp, 3001),
            "port 3001 is published already at 127.0.64.9:3001, because a process in this \
             box is listening on it. It is unpublished when that process stops listening on it."
        );
        // A refusal with no way forward beyond its own words is its verdict.
        assert_eq!(
            ExposeRefusal::NoDynamicRange.for_caller("web", NetworkMode::OwnIp, 3001),
            ExposeRefusal::NoDynamicRange.to_string()
        );
    }

    #[test]
    fn dynamic_ingress_decision_denies_the_absent_and_explicit_deny() {
        // NET-043: the setting decides, and an absent declaration is the
        // deny-all default — the two shapes a request from inside a bare box
        // meets.
        let allow = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(None, 3000),
            Err(ExposeRefusal::DeniedByPolicy),
            "a box that declared no ingress denies every runtime publish"
        );
        let deny = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Deny),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(Some(&deny), 3000),
            Err(ExposeRefusal::DeniedByPolicy),
        );
        assert_eq!(
            dynamic_ingress_decision(Some(&allow), 3000),
            Ok(boxes::DynamicIngress::Allow),
        );
    }

    #[test]
    fn absent_dynamic_ingress_is_deny() {
        // NET-043: an absent stance is not a permission waiting to be read.
        // A declaration can carry a range — or even a mode-allow's range
        // with the mode itself never spelled — and still deny every runtime
        // publish, exactly as an explicit deny does: the stance is the fact
        // the decision turns on, and only a spelled `allow` is an allow.
        let absent = IngressPolicy {
            dynamic_ingress: None,
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        let explicit = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Deny),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        for port in [2999, 3000, 3500, 3999, 4000] {
            assert_eq!(
                dynamic_ingress_decision(Some(&absent), port),
                dynamic_ingress_decision(Some(&explicit), port),
                "an absent stance must decide exactly as the explicit deny at port {port}"
            );
            assert_eq!(
                dynamic_ingress_decision(Some(&absent), port),
                Err(ExposeRefusal::DeniedByPolicy),
                "an absent stance denies the runtime publish at port {port}"
            );
        }
        // The whole-declaration absence — the bare box's shape — denies the
        // same way, so the deny is a property of the stance, not of the
        // declaration around it.
        assert_eq!(
            dynamic_ingress_decision(None, 3000),
            Err(ExposeRefusal::DeniedByPolicy),
            "a box with no ingress declaration denies the runtime publish"
        );
    }

    #[test]
    fn dynamic_ingress_decision_gates_on_the_declared_range() {
        // NET-047: an allowed request still has to be in the range the box
        // opted in — the bounds are inclusive, unset means nothing was opted
        // in, and `ask` fails closed with nobody to answer it.
        let allow = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        for port in [2999, 4000] {
            assert_eq!(
                dynamic_ingress_decision(Some(&allow), port),
                Err(ExposeRefusal::OutOfRange {
                    requested: port,
                    range: (3000, 3999),
                }),
                "port {port} is outside the range and must be refused by name"
            );
        }
        for port in [3000, 3999] {
            assert_eq!(
                dynamic_ingress_decision(Some(&allow), port),
                Ok(boxes::DynamicIngress::Allow),
                "the range's own bounds are inside it"
            );
        }
        let no_range = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            dynamic_allowed_range: None,
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(Some(&no_range), 3000),
            Err(ExposeRefusal::NoDynamicRange),
        );
        let ask = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Ask),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(Some(&ask), 3000),
            Err(ExposeRefusal::AskNeedsAnswer),
        );
    }

    #[test]
    fn expose_and_listen_share_one_verdict() {
        // `min net expose` and the listen watcher are two runtime ingress
        // surfaces over one box, so the stance and the range they read are
        // one derivation ([`IngressRules::dynamic_verdict`]), and this pins
        // the two surfaces to it over every shape the box's declaration can
        // take: absent stance, deny, ask, allow; absent range and one opted
        // in; in-range at both bounds and out-of-range at either edge.
        //
        // The declaration is the listen verdict's own half (NET-121), so
        // every policy below declares nothing: on these rows the verdict is
        // `Publish` or `Deny`, and `Publish` holds exactly where the expose
        // decision allows.
        use boxes::DynamicIngress;
        use boxes::core::ingress::ListenVerdict;

        const LOW: u16 = 3000;
        const HIGH: u16 = 3010;
        let stances = [
            (None, "absent"),
            (Some(DynamicIngress::Deny), "deny"),
            (Some(DynamicIngress::Ask), "ask"),
            (Some(DynamicIngress::Allow), "allow"),
        ];
        let ranges = [(None, "no range"), (Some((LOW, HIGH)), "3000-3010")];
        for port in [LOW - 1, LOW, HIGH, HIGH + 1] {
            for (stance, stance_name) in stances {
                for (range, range_name) in ranges {
                    let ingress = IngressPolicy {
                        dynamic_ingress: stance,
                        dynamic_allowed_range: range,
                        ..Default::default()
                    };
                    let decision = dynamic_ingress_decision(Some(&ingress), port);
                    let listen = IngressRules::from_policy(Some(&ingress))
                        .listen_verdict(IpProto::Tcp, port);
                    // The agreement the shared derivation buys: the watcher
                    // publishes exactly the ports the expose decision allows.
                    let allowed = decision == Ok(DynamicIngress::Allow);
                    let expected_listen = if allowed {
                        ListenVerdict::Publish
                    } else {
                        ListenVerdict::Deny
                    };
                    assert_eq!(
                        listen, expected_listen,
                        "stance {stance_name}, range {range_name}, port {port}"
                    );
                    // And the refusal names its own fact, stance before
                    // range, in the words `min net expose` prints.
                    let expected_decision = match stance {
                        None | Some(DynamicIngress::Deny) => Err(ExposeRefusal::DeniedByPolicy),
                        Some(DynamicIngress::Ask) => match range {
                            Some((low, high)) if port < low || port > high => {
                                Err(ExposeRefusal::OutOfRange {
                                    requested: port,
                                    range: (low, high),
                                })
                            }
                            _ => Err(ExposeRefusal::AskNeedsAnswer),
                        },
                        Some(DynamicIngress::Allow) => match range {
                            None => Err(ExposeRefusal::NoDynamicRange),
                            Some((low, high)) if low <= port && port <= high => {
                                Ok(DynamicIngress::Allow)
                            }
                            Some(range) => Err(ExposeRefusal::OutOfRange {
                                requested: port,
                                range,
                            }),
                        },
                    };
                    assert_eq!(
                        decision, expected_decision,
                        "stance {stance_name}, range {range_name}, port {port}"
                    );
                }
            }
        }
    }

    #[test]
    fn expose_refusals_render_their_own_reasons() {
        // The typed refusal is what the box's `min net expose` prints, so
        // each message must name the fact that decided it — not a generic
        // "refused".
        let refusal = ExposeRefusal::OutOfRange {
            requested: 80,
            range: (3000, 3999),
        };
        let rendered = refusal.to_string();
        assert!(rendered.contains("80"), "{rendered}");
        assert!(rendered.contains("3000-3999"), "{rendered}");
        assert!(
            ExposeRefusal::DeniedByPolicy
                .to_string()
                .contains("denied for this box")
        );
        // The two missing-address halves say which half is missing: no
        // published address is a capability gap, no switch address is a box
        // that is not attached yet — and neither reads as a policy deny.
        let unpublished = ExposeRefusal::NoPublishedAddress.to_string();
        let unattached = ExposeRefusal::NotAttached.to_string();
        assert!(
            unpublished.contains("no address on the host to open a port at"),
            "{unpublished}"
        );
        assert!(
            unattached.contains("not connected") && unattached.contains("start the box"),
            "{unattached}"
        );
        assert_ne!(unpublished, unattached);
        assert!(!unattached.contains("denied") && !unpublished.contains("denied"));
        assert!(
            ExposeFailure::Refused(refusal)
                .to_string()
                .starts_with(&rendered),
            "the failure wraps the refusal's own words"
        );
        let failed = ExposeFailure::Publish {
            port: 3000,
            source: io::Error::other("gvproxy refused"),
        };
        assert!(
            failed.to_string().contains("3000"),
            "the publish failure names the port it could not bind: {failed}"
        );
    }

    #[test]
    fn parse_status_code_reads_the_code() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(), 200);
        assert_eq!(
            parse_status_code(b"HTTP/1.0 500 Internal Server Error\r\n").unwrap(),
            500
        );
    }

    #[test]
    fn parse_status_code_rejects_a_malformed_line() {
        assert!(parse_status_code(b"not http\r\n").is_err());
    }

    #[test]
    fn direction_renders_the_r2_7_field_values() {
        // R2.7 spells the `direction` structured field `egress`/`ingress`.
        assert_eq!(Direction::Egress.to_string(), "egress");
        assert_eq!(Direction::Ingress.to_string(), "ingress");
    }

    #[test]
    fn content_length_parses_case_insensitively_or_absent() {
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"),
            Some(6)
        );
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\ncontent-length:  0\r\n\r\n"),
            Some(0)
        );
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn exchange_frames_by_content_length_without_a_server_close() {
        // The response is framed by `Content-Length`, never by the server
        // closing the socket, so `exchange` must return the full reply from a
        // peer that stays open. If it ever reverts to read-to-EOF, this test
        // hangs (the peer never closes).
        let (client, mut server) = tokio::io::duplex(1024);
        let server = crate::traced::spawn(async move {
            let mut buf = [0u8; 256];
            // Drain the request (headers + empty body arrive together here).
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nWEB_OK")
                .await
                .unwrap();
            // Hold the connection open — do NOT close — until the caller is done.
            server
        });

        let resp = exchange(
            client,
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .expect("exchange returns the framed response without waiting for EOF");

        assert_eq!(parse_status_code(&resp).unwrap(), 200);
        assert_eq!(body_after_headers(&resp), b"WEB_OK");
        drop(server.await.unwrap());
    }

    /// NET-017: a withdrawn publish's unexpose reads how many accepted
    /// connections the switch closed and logs it, and the sibling publish
    /// of the same in-box port is never asked to come down.
    mod closed_on_retract {
        use super::forwarder_probe::read_request;
        use super::*;
        use std::sync::Mutex;
        use tokio::net::UnixListener;
        use tokio::sync::mpsc;
        use tracing::Instrument as _;

        #[derive(Clone, Default)]
        struct LogCapture(Arc<Mutex<Vec<u8>>>);

        impl LogCapture {
            fn contents(&self) -> String {
                String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
            }
        }

        impl std::io::Write for LogCapture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
            type Writer = LogCapture;
            fn make_writer(&self) -> Self::Writer {
                self.clone()
            }
        }

        /// A switch whose `/unexpose` answers each `local` with the body
        /// `reply` picks, and reports every request's body.
        fn spawn_switch(
            path: std::path::PathBuf,
            reply: impl Fn(&str) -> String + Send + Sync + 'static,
        ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<String>) {
            let listener = UnixListener::bind(&path).unwrap();
            let (tx, rx) = mpsc::channel(16);
            let handle = crate::traced::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let body = String::from_utf8(read_request(&mut sock).await).unwrap();
                    let answer = reply(&body);
                    sock.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{answer}",
                            answer.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("the fake switch must answer");
                    if tx.send(body).await.is_err() {
                        return;
                    }
                }
            });
            (handle, rx)
        }

        /// gvproxy holds forwards in memory. One that is started again
        /// gets the forwards that are open, and none that was ended.
        #[tokio::test]
        async fn a_gvproxy_that_is_started_again_gets_the_open_forwards() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (first, mut asked) = spawn_switch(sock.clone(), |_| String::new());
            let control = ControlChannel::unix(sock.clone());
            let ControlChannel::Unix(own) = &control else {
                unreachable!("the node's own gvproxy")
            };
            let published = Ipv4Addr::new(127, 0, 0, 5);
            let lease = Ipv4Addr::new(100, 64, 0, 2);
            let kept = expose_mapping(&control, published, lease, 8080)
                .await
                .expect("the first forward opens");
            let ended = expose_mapping(&control, published, lease, 9090)
                .await
                .expect("the second forward opens");
            unexpose_mapping(&control, &ended)
                .await
                .expect("the second forward ends");
            for _ in 0..3 {
                asked.recv().await.expect("a request of the first gvproxy");
            }
            assert_eq!(
                own.forwards.held().await,
                [ExposeRequest {
                    local: kept.local().to_owned(),
                    remote: "100.64.0.2:8080".to_owned(),
                    protocol: "tcp".to_owned(),
                }]
            );

            // gvproxy dies and another one listens on the same socket.
            first.abort();
            let _gone = first.await;
            std::fs::remove_file(&sock).unwrap();
            let (_second, mut asked) = spawn_switch(sock.clone(), |_| String::new());
            assert_eq!(own.forwards.replay(&sock).await, (1, 0));
            let replayed = asked.recv().await.expect("the replayed forward");
            assert!(
                replayed.contains("127.0.0.5:8080") && replayed.contains("100.64.0.2:8080"),
                "{replayed}"
            );
            assert!(asked.try_recv().is_err(), "one forward, once");

            // A forward that could not be opened is not on record.
            std::fs::remove_file(&sock).unwrap();
            expose_mapping(&control, published, lease, 7070)
                .await
                .expect_err("nothing listens");
            assert_eq!(own.forwards.held().await.len(), 1);
        }

        #[tokio::test]
        async fn retracting_one_publish_closes_only_its_accepted_connections() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let retracted = ExposedMapping {
                local: "127.0.0.5:8080".to_string(),
                protocol: "tcp".to_string(),
            };
            let sibling = ExposedMapping {
                local: "127.0.0.6:9090".to_string(),
                protocol: "tcp".to_string(),
            };
            // The retracted publish held two connections. A switch that
            // reports no count stands in for an unpatched one.
            let (server, mut asked) = spawn_switch(sock.clone(), |body| {
                if body.contains("127.0.0.5:8080") {
                    r#"{"closed":2}"#.to_string()
                } else {
                    String::new()
                }
            });
            let control = ControlChannel::unix(sock);

            let log = LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(log.clone())
                .with_ansi(false)
                .finish();
            let guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!("listen", session = "web-box");
            let closed = unexpose_mapping(&control, &retracted)
                .instrument(span.clone())
                .await
                .expect("the retracted publish comes down");
            assert_eq!(closed, ClosedConnections(Some(2)));
            assert!(
                log.contents().is_empty(),
                "the shared unexpose logs nothing, so a move or a revoke never claims a withdrawal: {}",
                log.contents()
            );
            span.in_scope(|| log_withdrawal(&retracted, closed));

            let first = asked.recv().await.expect("the switch was asked");
            assert!(
                first.contains("127.0.0.5:8080"),
                "the unexpose names the retracted publish: {first}"
            );
            assert!(
                asked.try_recv().is_err(),
                "the sibling publish of the same in-box port is not asked to come down"
            );
            let text = log.contents();
            let line = text
                .lines()
                .find(|l| l.contains("withdrew a published port"))
                .unwrap_or_else(|| panic!("no retraction line in the log: {text}"));
            assert!(
                line.contains("the switch closed the connections it accepted"),
                "a reported count is said as closed connections: {line}"
            );
            assert!(line.contains("web-box"), "the line names the box: {line}");
            assert!(
                line.contains("port=8080"),
                "the line names the port: {line}"
            );
            assert!(
                line.contains("closed_connections=2"),
                "the line carries the switch's count: {line}"
            );

            // A reply with no count is logged as unknown, never as zero.
            let closed = unexpose_mapping(&control, &sibling)
                .await
                .expect("the sibling publish comes down when it is retracted");
            assert_eq!(closed, ClosedConnections(None));
            log_withdrawal(&sibling, closed);
            drop(guard);
            let text = log.contents();
            let line = text
                .lines()
                .filter(|l| l.contains("withdrew a published port"))
                .nth(1)
                .unwrap_or_else(|| panic!("no second retraction line: {text}"));
            assert!(line.contains("port=9090"), "{line}");
            assert!(line.contains("closed_connections=unknown"), "{line}");
            assert!(
                line.contains("did not report how many accepted connections it closed"),
                "an unknown count says what is known: {line}"
            );
            assert!(
                !line.contains("the switch closed the connections"),
                "an unknown count claims no closed connection: {line}"
            );
            server.abort();
        }

        #[test]
        fn the_closed_count_reads_from_the_unexpose_reply() {
            assert_eq!(
                ClosedConnections::from_reply(br#"{"closed":3}"#),
                ClosedConnections(Some(3))
            );
            assert_eq!(
                ClosedConnections::from_reply(b"{\"closed\":0}\n"),
                ClosedConnections(Some(0))
            );
            assert_eq!(ClosedConnections::from_reply(b""), ClosedConnections(None));
            assert_eq!(
                ClosedConnections::from_reply(b"{}"),
                ClosedConnections(None)
            );
            assert_eq!(
                ClosedConnections::from_reply(b"not json"),
                ClosedConnections(None)
            );
            assert_eq!(ClosedConnections(None).to_string(), "unknown");
            assert_eq!(ClosedConnections(Some(4)).to_string(), "4");
        }
    }

    mod forwarder_probe {
        use std::path::PathBuf;
        use std::time::Duration;

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{UnixListener, UnixStream};
        use tokio::sync::mpsc;

        /// Reads one control request off `sock`: its head up to the
        /// end-of-head marker, then exactly its `Content-Length` body — the
        /// mirror of `post_json`'s keep-alive framing, so the fake forwarder
        /// never blocks reading past what the client sent.
        pub(super) async fn read_request(sock: &mut UnixStream) -> Vec<u8> {
            let mut buf = Vec::with_capacity(256);
            let mut scratch = [0u8; 512];
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                    break i;
                }
                let n = sock
                    .read(&mut scratch)
                    .await
                    .expect("the fake forwarder must receive the request head");
                assert!(n > 0, "the probe closed before sending its head");
                buf.extend_from_slice(&scratch[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let len: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < head_end + len {
                let n = sock
                    .read(&mut scratch)
                    .await
                    .expect("the fake forwarder must receive the request body");
                assert!(n > 0, "the probe closed mid-body");
                buf.extend_from_slice(&scratch[..n]);
            }
            buf[head_end..head_end + len].to_vec()
        }

        /// The `local` address a request body names, for the decide closure.
        fn local_of(body: &[u8]) -> String {
            let text = String::from_utf8_lossy(body);
            text.split("\"local\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default()
                .to_string()
        }

        /// Serves a gvproxy-shaped control channel at `path`: every request
        /// is read in full, then answered with the status `decide` picks for
        /// the `local` address its body names. `delay` parks each answer.
        /// Every round's `local` is handed to the returned receiver; the
        /// returned handle aborts the server when the test is done with it.
        pub(super) fn spawn_forwarder_answering(
            path: PathBuf,
            delay: Duration,
            decide: impl Fn(&str) -> u16 + Send + Sync + 'static,
        ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<String>) {
            let listener = UnixListener::bind(&path).unwrap();
            let (tx, rx) = mpsc::channel(512);
            let decide = std::sync::Arc::new(decide);
            let handle = crate::traced::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let body = read_request(&mut sock).await;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let local = local_of(&body);
                    let status = decide(&local);
                    let reason = if status == 200 {
                        "OK"
                    } else {
                        "Internal Server Error"
                    };
                    sock.write_all(
                        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .expect("the fake forwarder must answer");
                    if tx.send(local).await.is_err() {
                        return;
                    }
                }
            });
            (handle, rx)
        }
    }

    // ---- a shared-address port's forward bound at its hand-over (NET-129) --
    mod handed_port {
        use std::net::Ipv4Addr;

        use tokio::io::AsyncWriteExt as _;
        use tokio::net::UnixListener;

        use super::super::{ControlChannel, PortMapping, bind_handed_port};
        use super::forwarder_probe::read_request;

        const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 128, 10);

        fn mapping() -> PortMapping {
            PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: boxes::IpProto::Tcp,
            }
        }

        /// A forwarder that answers one expose with `status` and `body`,
        /// framed as the real one frames its answers, and hands back the
        /// request body it read.
        fn forwarder_answering_once(
            path: std::path::PathBuf,
            status: u16,
            body: &'static str,
        ) -> tokio::task::JoinHandle<String> {
            let listener = UnixListener::bind(&path).unwrap();
            crate::traced::spawn(async move {
                let (mut sock, _) = listener.accept().await.expect("the bind is asked");
                let request = String::from_utf8_lossy(&read_request(&mut sock).await).into_owned();
                sock.write_all(
                    format!(
                        "HTTP/1.1 {status} Whatever\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("the fake forwarder must answer");
                request
            })
        }

        /// The switch binds the forward: the bind posts the expose the
        /// box's own attach posts for the mapping, and hands back the
        /// forwarder to track, naming the listener and the inside port.
        #[tokio::test]
        async fn a_bound_hand_over_hands_back_the_forwarder_to_track() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let forwarder = forwarder_answering_once(sock.clone(), 200, "");

            let tracked =
                bind_handed_port(&ControlChannel::unix(sock), PUBLISHED, LEASE, &mapping())
                    .await
                    .expect("the switch bound the forward");

            let request = forwarder.await.expect("the fake forwarder ran");
            assert!(
                request.contains("\"local\":\"127.0.64.9:18080\""),
                "{request}"
            );
            assert!(
                request.contains("\"remote\":\"100.64.128.10:80\""),
                "{request}"
            );
            assert_eq!(tracked.local(), "127.0.64.9:18080");
            assert_eq!(tracked.internal_port(), 80);
            // TCP and UDP on one port are two forwards: the tracked TCP
            // one is not the UDP mapping's.
            assert!(tracked.is_forward_of(PUBLISHED, &mapping()));
            let udp = PortMapping {
                proto: boxes::IpProto::Udp,
                ..mapping()
            };
            assert!(!tracked.is_forward_of(PUBLISHED, &udp));
        }
    }

    // ---- who unbinds a declared forward when its box stops (NET-121) ------
    mod declared_release {
        use std::time::Duration;

        use super::super::{
            ControlChannel, ExposedMapping, PortForwarder, release_declared_ingress,
        };
        use super::forwarder_probe::spawn_forwarder_answering;

        /// A declared forwarder bound at `local`, as `apply_ingress` builds
        /// one, with no ingress gate behind it.
        pub(super) fn declared_at(local: &str) -> PortForwarder {
            PortForwarder {
                mapping: ExposedMapping {
                    local: local.to_string(),
                    protocol: "tcp".to_string(),
                },
                internal_port: 80,
            }
        }

        /// On a native host the daemon drives the switch directly, so it
        /// still unbinds a declared forward itself when the box stops.
        #[tokio::test]
        async fn declared_forwards_unbound_by_the_daemon_on_a_native_host() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, mut asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 200);
            let control = ControlChannel::unix(sock);
            assert!(!control.host_unbinds_declared_forwards());

            release_declared_ingress(&control, &[declared_at("127.0.64.202:18202")]).await;
            forwarder.abort();

            assert_eq!(
                asked.recv().await.as_deref(),
                Some("127.0.64.202:18202"),
                "the daemon asked the switch to unbind the declared forward"
            );
        }
    }

    // ---- a host port another process already holds (reported as EADDRINUSE) --
    mod host_port_in_use {
        use std::io;
        use std::net::Ipv4Addr;

        use tokio::io::AsyncWriteExt as _;
        use tokio::net::UnixListener;

        use super::super::{
            ControlChannel, IngressPolicy, PORT_HELD_BINDS, PORT_HELD_RETRY, PortMapping,
            apply_ingress, host_ports_in_use, is_address_in_use, port_held_by, port_in_use_refusal,
        };
        use super::forwarder_probe::read_request;

        const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 128, 10);

        fn mapping(external_port: u16) -> PortMapping {
            PortMapping {
                external_port,
                internal_port: 80,
                proto: boxes::IpProto::Tcp,
            }
        }

        fn ingress(ports: &[u16]) -> IngressPolicy {
            IngressPolicy {
                port_mappings: ports.iter().map(|&port| mapping(port)).collect(),
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }
        }

        /// Serves a gvproxy-shaped control channel at `path`: one request per
        /// entry of `answers`, each answered with its status and body — the
        /// stand-in for the host forwarder whose `expose` of a taken port
        /// answers `500` with the OS's bind text in its body. The OS's own
        /// words arrive as an HTTP body, so the answers here carry them.
        fn forwarder_answering_in_turn(
            path: std::path::PathBuf,
            answers: Vec<(u16, &'static str)>,
        ) -> tokio::task::JoinHandle<Vec<String>> {
            let listener = UnixListener::bind(&path).unwrap();
            crate::traced::spawn(async move {
                let mut asked = Vec::new();
                for (status, body) in answers {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return asked;
                    };
                    asked
                        .push(String::from_utf8_lossy(&read_request(&mut sock).await).into_owned());
                    sock.write_all(
                        format!(
                            "HTTP/1.1 {status} Internal Server Error\r\n\
                             Content-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("the fake forwarder must answer");
                }
                asked
            })
        }

        /// The OS's bind text as the forwarder returns it to the caller of
        /// `expose`: the status line in the wrapper's own words, the OS's
        /// message in the body.
        const IN_USE: (u16, &str) = (
            500,
            "listen tcp 127.0.0.1:18999: bind: address already in use",
        );

        /// One declared port taken by another process fails the apply
        /// (NET-121): the forward already bound is rolled back with an
        /// unexpose, and the error names the taken port in place of the
        /// forwarder's raw refusal. The caller then withdraws the name, as
        /// it does for every failed apply.
        #[tokio::test]
        async fn a_taken_host_port_fails_the_apply_and_rolls_back() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            // Two declared ports: the first binds, the second is taken, and
            // the third request is the rollback of the first.
            let forwarder =
                forwarder_answering_in_turn(sock.clone(), vec![(200, ""), IN_USE, (200, "")]);
            let err = match apply_ingress(
                &ControlChannel::unix(sock),
                PUBLISHED,
                LEASE,
                &ingress(&[18080, 18999]),
                &[],
                &|_| minimald_rpc::PortHolder::Host,
            )
            .await
            {
                Err(e) => e,
                Ok(_) => panic!("a taken host port must fail the apply"),
            };

            assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
            assert_eq!(
                port_in_use_refusal(&err),
                Some(minimald_rpc::PortInUseRefusal {
                    port: 18999,
                    box_port: 80,
                    holder: minimald_rpc::PortHolder::Host,
                }),
                "the error carries the typed refusal for the finalize to read"
            );
            assert_eq!(
                err.to_string(),
                "Port 18999 is already in use on this machine by another \
                 program on this machine.\nChoose another host port in --ingress (for \
                 example --ingress 19000:80) or in [network] ingress in \
                 minimal.toml.",
                "the error names the taken port and the next step, and no \
                 forwarder internals"
            );
            let asked = forwarder
                .await
                .expect("the fake forwarder served every round");
            assert_eq!(asked.len(), 3, "expose, expose, rollback: {asked:?}");
            assert!(
                asked[2].contains("127.0.64.9:18080"),
                "the rollback releases the forward that bound: {asked:?}"
            );
        }

        /// A port held only for a moment, as a parallel probe of the same
        /// port holds it, is not reported: the probe binds again before it
        /// names the port. A port held across every bind still is.
        #[test]
        fn a_port_held_only_for_a_moment_is_not_reported() {
            let native = ControlChannel::unix("/nonexistent/gvproxy.sock");
            let in_use = || Err(io::Error::from(io::ErrorKind::AddrInUse));
            for free_at in 2..=PORT_HELD_BINDS {
                let mut binds = 0;
                assert!(
                    !port_held_by(|| {
                        binds += 1;
                        if binds < free_at { in_use() } else { Ok(()) }
                    }),
                    "a port freed by bind {free_at} is not held by another program"
                );
                assert_eq!(
                    binds, free_at,
                    "the probe stops at the first bind that succeeds"
                );
            }
            let mut binds = 0;
            assert!(
                port_held_by(|| {
                    binds += 1;
                    in_use()
                }),
                "a port that refuses every bind is held"
            );
            assert_eq!(
                binds, PORT_HELD_BINDS,
                "the probe binds before it names a held port"
            );

            let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = held.local_addr().unwrap().port();
            let declared = ingress(&[port]);
            let started = std::time::Instant::now();
            assert_eq!(
                host_ports_in_use(&native, Ipv4Addr::LOCALHOST, &declared, &[]),
                [port],
                "a port held across every bind is still reported"
            );
            assert!(
                started.elapsed() >= PORT_HELD_RETRY * (PORT_HELD_BINDS - 1),
                "the probe binds again before it names a held port"
            );
            drop(held);
        }

        /// Only the OS's own words get the taken-port error: any other
        /// refusal of the bind — a permission denied, a missing address, a
        /// crashed forwarder — rolls back and fails with the forwarder's
        /// refusal as it came.
        #[tokio::test]
        async fn any_other_refusal_still_rolls_back_and_fails() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let forwarder = forwarder_answering_in_turn(
                sock.clone(),
                vec![(200, ""), (500, "listen tcp: permission denied")],
            );
            let err = match apply_ingress(
                &ControlChannel::unix(sock),
                PUBLISHED,
                LEASE,
                &ingress(&[18080, 18181]),
                &[],
                &|_| minimald_rpc::PortHolder::Host,
            )
            .await
            {
                Err(e) => e,
                Ok(_) => panic!("a refusal that is not the OS's bind text still fails"),
            };

            assert!(
                !is_address_in_use(&err),
                "a permission-denied refusal is not the bind text: {err}"
            );
            forwarder
                .await
                .expect("the fake forwarder served both rounds");
        }

        /// The classifier's own words: the status line the wrapper writes,
        /// the OS's phrase the body carries. A refusal that says either half
        /// alone — a 200 that carries the phrase, a 500 that does not — is
        /// not the bind text.
        #[test]
        fn the_classifier_reads_the_wrappers_own_words() {
            let said = |body: &str| {
                std::io::Error::other(format!(
                    "gvproxy /services/forwarder/expose returned HTTP 500: {body}"
                ))
            };
            assert!(is_address_in_use(&said(
                "listen tcp 127.0.0.1:18999: bind: address already in use"
            )));
            assert!(!is_address_in_use(&said(
                "listen tcp 127.0.0.1:18999: bind: permission denied"
            )));
            assert!(!is_address_in_use(&said("proxy already running")));
            assert!(!is_address_in_use(&std::io::Error::other(
                "connection closed before the answer"
            )));
        }
    }
}
