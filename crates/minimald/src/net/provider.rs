//! One function that reads a PTask's network mode, and the own-IP provider it
//! returns. Every sandbox consumer in the daemon calls [`network_for`], and
//! nothing else reads the mode. The gvproxy **process** belongs to the
//! daemon-scoped [`SwitchClient`] (DM2) or to `minvmd` (DM1/3/4); this only
//! leases from it and wires a running switch into a sandbox's namespace.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use boxes::{NetworkMode, SessionId};
use sandbox::{
    AbandonFuture, AttachFuture, NetGuard, NetPlan, Network, NetworkError, PlanFuture, Resolver,
    Spawned,
};
use tokio::sync::Mutex;

use crate::net::SwitchClient;
use crate::net::policy::ControlChannel;

/// Reports an own-address box's lease to the proxy's routing table (NET-001).
/// The session launcher mints one per launch carrying the stable `SessionId`,
/// so the lease the attach path reports stays with the session across a
/// rename — the registry keys the fact by the id, not the mutable name.
///
/// A task launch carries none: a task is a second PTask beside its session's
/// and owns no proxy route of its own.
#[derive(Debug, Clone)]
pub(crate) struct OwnAddressReporter {
    registry: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
    session_id: SessionId,
    /// The box's runtime publishes (NET-044), shared with its session actor:
    /// the attach this reporter rides hands it to the spawn's guard, so the
    /// runtime forwards come down with the spawn exactly as the declared
    /// ones do.
    runtime_ingress: RuntimeIngress,
}

/// One live runtime publish (NET-044): the forwarder the switch accepted,
/// paired with the mapping it published — held together, so the list the
/// policy surfaces read is exactly what the switch holds.
pub(crate) struct LiveIngressForward {
    /// The daemon-owned forward: its unexpose releases the port.
    pub(crate) forwarder: crate::net::policy::PortForwarder,
    /// The mapping as the policy surfaces read it.
    pub(crate) mapping: minimald_rpc::LiveMapping,
}

/// The row the policy surfaces read, not the forwarder's own internals —
/// `PortForwarder` is a handle, and the mapping is the fact it published.
impl std::fmt::Debug for LiveIngressForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveIngressForward")
            .field("mapping", &self.mapping)
            .finish()
    }
}

#[derive(Default)]
struct RuntimeIngressState {
    /// The spawn that held the box's switch address has ended and no new one
    /// has attached: a forward published now would deliver to a lease the
    /// switch may already have handed to another box.
    detached: bool,
    forwards: Vec<LiveIngressForward>,
    /// The declared ports' forwards bound for this spawn after its attach
    /// (NET-129): a shared-address port the box took over while it ran.
    /// They deliver to the spawn's lease as its attach's own forwards do,
    /// and come down with it the same way.
    handed: Vec<crate::net::policy::PortForwarder>,
}

/// The ports a box published at runtime with its own `min net expose`
/// (NET-044), shared between its session actor — which publishes, lists and
/// unbinds them at stop — and the guard of the spawn they deliver to. A
/// runtime forward delivers to that spawn's lease, and leases are per-spawn,
/// so the forwards follow the declared ones: the spawn's teardown unbinds
/// them beside its declared forwards, and the next spawn starts with none
/// rather than inheriting a forward aimed at a stale address.
#[derive(Clone, Default)]
pub(crate) struct RuntimeIngress(Arc<std::sync::Mutex<RuntimeIngressState>>);

impl std::fmt::Debug for RuntimeIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeIngress")
            .field("mappings", &self.snapshot())
            .finish()
    }
}

impl RuntimeIngress {
    fn state(&self) -> std::sync::MutexGuard<'_, RuntimeIngressState> {
        self.0.lock().expect("runtime ingress lock poisoned")
    }

    /// The live mappings, in publish order — the rows `min session policy`
    /// lists beside the declaration.
    pub(crate) fn snapshot(&self) -> Vec<minimald_rpc::LiveMapping> {
        self.state()
            .forwards
            .iter()
            .map(|live| live.mapping.clone())
            .collect()
    }

    /// Whether the spawn the box's forwards deliver to has ended with no new
    /// one attached.
    pub(crate) fn is_detached(&self) -> bool {
        self.state().detached
    }

    /// Records a publish the switch accepted. Refused — handing the forward
    /// back for the caller to unbind — when the spawn it delivers to ended
    /// while the publish was in flight, so a forward aimed at a dead lease is
    /// never recorded as live.
    pub(crate) fn record(&self, live: LiveIngressForward) -> Result<(), LiveIngressForward> {
        let mut state = self.state();
        if state.detached {
            return Err(live);
        }
        state.forwards.push(live);
        Ok(())
    }

    /// Records a declared port's forward bound after the attach, at a
    /// shared-address port's hand-over (NET-129). Refused, handing the
    /// forward back for the caller to release, when the spawn it delivers
    /// to has ended.
    pub(crate) fn record_handed(
        &self,
        forwarder: crate::net::policy::PortForwarder,
    ) -> Result<(), crate::net::policy::PortForwarder> {
        let mut state = self.state();
        if state.detached {
            return Err(forwarder);
        }
        state.handed.push(forwarder);
        Ok(())
    }

    /// Whether the forward `mapping` declares at `published` is held as one
    /// bound at a hand-over.
    pub(crate) fn holds_handed(
        &self,
        published: std::net::Ipv4Addr,
        mapping: &boxes::PortMapping,
    ) -> bool {
        self.state()
            .handed
            .iter()
            .any(|forwarder| forwarder.is_forward_of(published, mapping))
    }

    /// The box stopped: takes the forwards bound at a hand-over, for the
    /// session actor to release as declared forwards are.
    pub(crate) fn take_handed(&self) -> Vec<crate::net::policy::PortForwarder> {
        std::mem::take(&mut self.state().handed)
    }

    /// The spawn ended: takes the forwards bound at a hand-over, for the
    /// guard to release beside the ones its attach bound, and refuses new
    /// ones until the next attach.
    pub(crate) fn detach_handed(&self) -> Vec<crate::net::policy::PortForwarder> {
        let mut state = self.state();
        state.detached = true;
        std::mem::take(&mut state.handed)
    }

    /// A spawn attached: its lease is the box's switch address from here on.
    fn attached(&self) {
        self.state().detached = false;
    }

    /// The spawn ended: takes every runtime forward for the guard to unbind
    /// beside the declared ones, and refuses publishes until the next attach.
    pub(crate) fn detach(&self) -> Vec<crate::net::policy::PortForwarder> {
        let mut state = self.state();
        state.detached = true;
        std::mem::take(&mut state.forwards)
            .into_iter()
            .map(|live| live.forwarder)
            .collect()
    }

    /// Takes the one runtime forward published for `port`, for the session
    /// actor to unbind: the publish it recorded is being withdrawn because
    /// its allow could not be audited (NET-046). `None` when no forward for
    /// the port is recorded — a spawn's end took it first.
    ///
    /// Whole, mapping and all, so an unbind the switch refuses can
    /// [`Self::record`] it back exactly as it was published.
    pub(crate) fn take(&self, port: u16) -> Option<LiveIngressForward> {
        let mut state = self.state();
        let position = state
            .forwards
            .iter()
            .position(|live| live.mapping.internal_port == port)?;
        Some(state.forwards.remove(position))
    }

    /// The box stopped: takes every runtime forward for the session actor to
    /// unbind.
    pub(crate) fn take_all(&self) -> Vec<crate::net::policy::PortForwarder> {
        std::mem::take(&mut self.state().forwards)
            .into_iter()
            .map(|live| live.forwarder)
            .collect()
    }
}

impl OwnAddressReporter {
    /// Builds the reporter for one session's launches.
    #[must_use]
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn new(
        registry: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
        session_id: SessionId,
    ) -> Self {
        Self {
            registry,
            session_id,
            runtime_ingress: RuntimeIngress::default(),
        }
    }

    /// The same reporter, sharing `runtime_ingress` with the session actor
    /// that publishes into it.
    #[must_use]
    pub(crate) fn with_runtime_ingress(mut self, runtime_ingress: RuntimeIngress) -> Self {
        self.runtime_ingress = runtime_ingress;
        self
    }

    /// The box's runtime publishes, for the spawn's guard to unbind at its
    /// teardown.
    pub(crate) fn runtime_ingress(&self) -> RuntimeIngress {
        self.runtime_ingress.clone()
    }

    /// The registry this reporter reports to, for the listen watcher's
    /// dynamic-port records and releases (NET-129): a watcher holding this
    /// handle needs no other path to the registry.
    /// The box this reporter speaks for.
    pub(crate) const fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub(crate) fn registry(&self) -> Arc<RwLock<crate::net::dns::HostnameRegistry>> {
        Arc::clone(&self.registry)
    }

    /// Reports `lease` — with the box's ingress declaration as an
    /// external→internal port map — and registers `session_name`'s box name
    /// against it, so the name routes exactly when the box is reachable. The
    /// lease is always recorded; on a native host the registration follows it
    /// only where the box has a published address to route at (NET-010).
    pub(crate) fn report(&self, session_name: &str, lease: Ipv4Addr, ports: BTreeMap<u16, u16>) {
        let mut registry = self
            .registry
            .write()
            .expect("hostname registry lock poisoned");
        registry.report_own_address(self.session_id, session_name, lease, ports);
        drop(registry);
        self.runtime_ingress.attached();
    }

    /// The switch lease the attach reported for this box ([`Self::report`]),
    /// or `None` before an attach reported one. On a VM host the daemon
    /// builds the box's tap itself after the spawn
    /// ([`TapMechanism::Privileged`]), so the launch's plan carries no tap to
    /// read the lease from: this is where the lease is read there.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn lease(&self) -> Option<Ipv4Addr> {
        self.registry
            .read()
            .expect("hostname registry lock poisoned")
            .own_lease(self.session_id)
    }

    /// The host loopback address this box's declaration publishes on (NET-010):
    /// the address a creator handed the box and its record published — `None`
    /// when nobody handed one, because the daemon has no address of its own to
    /// stand in with. The attach path reads it here — rather than re-deriving
    /// one — so the forwards it binds and the name the registry answers stay at
    /// the one address the box owns, and a box nobody handed an address fails
    /// its attach rather than publishing at a default.
    pub(crate) fn published_address(&self) -> Option<Ipv4Addr> {
        self.registry
            .read()
            .expect("hostname registry lock poisoned")
            .published_own_address(self.session_id)
    }

    /// The ports this box yields at a shared address, each with the box that
    /// holds it (NET-129, first-come): recorded when the box published, read
    /// here so the attach skips those forwards rather than failing on them.
    pub(crate) fn shared_port_collisions(&self) -> Vec<crate::net::dns::SharedPortCollision> {
        self.registry
            .read()
            .expect("hostname registry lock poisoned")
            .shared_port_collisions(self.session_id)
    }

    /// Withdraws `session_name`'s box name if this session still owns it —
    /// the failed attach's other half (NET-121): a bind that failed, or an
    /// address nobody handed, leaves no name standing that says "reachable
    /// here" over ports that are not.
    pub(crate) fn withdraw(&self, session_name: &str) {
        let mut registry = self
            .registry
            .write()
            .expect("hostname registry lock poisoned");
        registry.withdraw_own_name(self.session_id, session_name);
    }
}

/// The network provider for `mode`. `NoNet` is the sandbox layer's own; `HostNet`
/// is the sandbox layer's plan, decided here against the switch (on a VM host
/// the resolver must be the node's DNS layer, not the host's) and against the
/// box's own declaration — a native deny-all box resolves through the box
/// zone's answerer, from the policy below; `OwnIp` needs a
/// lease, a tap and a switch attach. An unrecognised mode (`NetworkMode` is
/// `#[non_exhaustive]`) gets the empty namespace, the safe direction.
///
/// `policy` is the launch's whole session policy — the own-IP relay gate carries
/// it in both directions (egress verdict per NET-062/063/064, inbound
/// default-block per finding #2), while other modes have no relay to gate;
/// `None` attaches ungated. The session launcher passes the box's *effective*
/// policy (NET-074), and a task launch passes its session's effective egress
/// alone when the rollout leaves one in force, `None` when the daemon opted
/// out (or under the announced phase) — an ungated task keeps the open
/// inbound it always had — because a task carries none of its session's
/// ingress, the session's own PTask being attached at the same time.
/// `own_address` carries the registry handle an own-address launch reports its
/// lease through once the box attaches (NET-001); a task launch passes `None`
/// for that too. `box_addresses` carries the switch and loopback addresses
/// the VM host daemon handed the box's registration (T66): its switch
/// address is what this `OwnIp` PTask attaches with instead of drawing one,
/// because the host-side table's row is keyed by it. A task launch goes
/// through [`task_network_for`] instead — the task's sandbox is not the box
/// the registration named, and attaching it at the box's address would key
/// its frames to the session's row.
pub(crate) fn network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: &str,
    policy: Option<boxes::BoxPolicy>,
    own_address: Option<OwnAddressReporter>,
    box_addresses: Option<boxes::BoxAddresses>,
    engine_box: Option<crate::net::gvproxy_network::EngineBox>,
) -> Arc<dyn Network> {
    match mode {
        NetworkMode::HostNet => Arc::new(HostIpAddressNetwork {
            switch: Arc::clone(switch),
            host_alias: engine_box.and_then(|judged| judged.of.host_alias()),
        }),
        NetworkMode::OwnIp => Arc::new(OwnIpNetwork {
            switch: Arc::clone(switch),
            identity: identity.to_string(),
            policy,
            own_address,
            box_addresses,
            task_slots: None,
            engine_box,
            reserved: std::sync::Mutex::new(None),
        }),
        _ => Arc::new(sandbox::NoNet),
    }
}

/// `network`, with the box's resolver file naming `resolver`: the address
/// of the box's own resolver endpoint. The policy engine sends the box's
/// DNS there whatever server it asks, so the file only has to name a server
/// that can be redirected. A copy of the host's file may name one that
/// cannot: an IPv6 link-local server with a scope.
pub(crate) fn with_box_resolver(
    network: Arc<dyn Network>,
    resolver: std::net::Ipv4Addr,
) -> Arc<dyn Network> {
    Arc::new(BoxResolver {
        inner: network,
        resolver,
    })
}

#[derive(Debug)]
struct BoxResolver {
    inner: Arc<dyn Network>,
    resolver: std::net::Ipv4Addr,
}

impl Network for BoxResolver {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(async move {
            let plan = self.inner.plan().await?;
            Ok(plan.with_resolver(Resolver::Nameservers(vec![self.resolver])))
        })
    }

    fn attach(&self, spawned: sandbox::Spawned) -> sandbox::AttachFuture<'_> {
        self.inner.attach(spawned)
    }

    fn abandon(&self) -> sandbox::AbandonFuture<'_> {
        self.inner.abandon()
    }
}

/// [`network_for`] for a task run (NET-138): an `OwnIp` task attaches at
/// one of the task addresses the VM host registered with its session's box
/// (`task_addresses`, off the session record) — each a host-side row
/// carrying the box's id and egress — never at the box's own address and
/// never at one it draws. No task addresses is the plain draw, which only a
/// native switch makes ([`SwitchClient::attach_task_slot`]). Every other
/// mode is [`network_for`]'s, with no reporter and no handed box addresses:
/// a task owns no proxy route.
pub(crate) fn task_network_for(
    mode: NetworkMode,
    switch: &Arc<Mutex<SwitchClient>>,
    identity: &str,
    policy: Option<boxes::BoxPolicy>,
    task_addresses: Vec<std::net::Ipv4Addr>,
    engine_box: Option<crate::net::gvproxy_network::EngineBox>,
) -> Arc<dyn Network> {
    match mode {
        NetworkMode::OwnIp => Arc::new(OwnIpNetwork {
            switch: Arc::clone(switch),
            identity: identity.to_string(),
            policy,
            own_address: None,
            box_addresses: None,
            task_slots: Some(task_addresses),
            engine_box,
            reserved: std::sync::Mutex::new(None),
        }),
        _ => network_for(mode, switch, identity, policy, None, None, None),
    }
}

/// A host-address box: it shares the daemon host's network namespace, so its
/// plan is the sandbox layer's [`sandbox::HostNet`]. On a VM host the
/// namespace it shares is the guest's, where the host's own resolver is
/// unreachable, so there the plan names the node's DNS layer at the switch
/// gateway, whose `min.internal.` zone carries the `host` record.
#[derive(Debug)]
struct HostIpAddressNetwork {
    switch: Arc<Mutex<SwitchClient>>,
    /// The address the engine redirects to the box's host relay. A box no
    /// engine judges has none.
    host_alias: Option<Ipv4Addr>,
}

impl Network for HostIpAddressNetwork {
    /// Reads the switch's transport once, before the process starts. Nothing is
    /// attached, so this never starts or stops a gvproxy process.
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(async move {
            let (vm_host, subnet) = {
                let s = self.switch.lock().await;
                (
                    matches!(
                        s.transport(),
                        crate::net::SwitchTransport::HostShuttle { .. }
                    ),
                    s.subnet(),
                )
            };
            if !vm_host {
                // The box may ask the host's own resolver, which has no
                // `min.internal.` zone, so `/etc/hosts` names the host: at
                // the alias the engine leads to the host relay, or at the
                // loopback the box shares when no engine judges it.
                return Ok(NetPlan::host()
                    .with_resolver(Resolver::Host)
                    .with_hosts_entry(
                        sandbox::HOST_MIN_INTERNAL,
                        self.host_alias.unwrap_or(Ipv4Addr::LOCALHOST),
                    ));
            }
            // In a guest, 127.0.0.1 is the guest's loopback and the host's
            // resolver is unreachable. The node's DNS layer answers at the
            // gateway, and named servers replace whatever the rootfs ships.
            Ok(NetPlan::host().with_resolver(Resolver::Nameservers(vec![subnet.dns_server()])))
        })
    }
}

/// The plan of a box with an address of its own: a namespace the attach
/// wires, resolving at the virtual network's resolver.
fn own_ip_plan(subnet: crate::net::SwitchSubnet) -> NetPlan {
    NetPlan::isolated_wired().with_resolver(Resolver::Nameservers(vec![subnet.dns_server()]))
}

/// What [`OwnIpNetwork::plan`] reserved, waiting for an attach or an abandon.
#[derive(Debug, Clone)]
struct Reserved {
    lease: crate::net::PtaskLease,
    subnet: crate::net::SwitchSubnet,
    /// gvproxy's control channel: a local socket on DM2, host vsock on DM1/3/4.
    control: ControlChannel,
}

/// An own-IP network: leases an address from the per-host gvproxy switch before
/// the sandbox starts, then relays the sandbox's own tap onto that switch,
/// gated by the session's policy — its declared egress enforced on the
/// relay's outbound leg, its static ingress forwards applied and inbound
/// ports gated on the other (R1.5/R2.3, NET-062).
struct OwnIpNetwork {
    switch: Arc<Mutex<SwitchClient>>,
    /// Registered as the PTask's `*.min.internal` hostname on attach (R3.1).
    identity: String,
    /// The launch's whole session policy, carried into the relay gate.
    policy: Option<boxes::BoxPolicy>,
    /// The registry handle the lease is reported through on attach, so the
    /// box's proxy route exists exactly while the lease does (NET-001). `None`
    /// for a task launch, which owns no proxy route.
    own_address: Option<OwnAddressReporter>,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when it was registered: the switch address this PTask attaches
    /// with instead of drawing one — the host-side table's row is keyed by
    /// it, so a self-allocated lease would never match — and the published
    /// loopback address the host side names the box by. `None` for a launch
    /// the activating client did not register, which draws on a native
    /// switch and is refused on one the VM host owns (NET-138).
    box_addresses: Option<boxes::BoxAddresses>,
    /// For a task launch ([`task_network_for`]), the task addresses the VM
    /// host registered with the session's box (NET-138): the PTask attaches
    /// at the first one no task run holds. `None` for a box's own launch.
    task_slots: Option<Vec<std::net::Ipv4Addr>>,
    /// The box's entry in the engine, which judges what the box sends and
    /// takes. `None` for a box that runs unjudged.
    engine_box: Option<crate::net::gvproxy_network::EngineBox>,
    /// Taken by `plan`, taken back out by `attach` or `abandon`. A `std` mutex,
    /// never held across an await, so a cancelled launch cannot leak it.
    reserved: std::sync::Mutex<Option<Reserved>>,
}

impl std::fmt::Debug for OwnIpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnIpNetwork")
            .field("identity", &self.identity)
            .field("has_policy", &self.policy.is_some())
            .field("handed_addresses", &self.box_addresses.is_some())
            .field("task_slots", &self.task_slots)
            .finish_non_exhaustive()
    }
}

impl Network for OwnIpNetwork {
    /// Lease an address and make sure the switch is up, then describe the tap
    /// the sandbox layer should build. Before the process starts, because the
    /// sandbox layer assigns the address as it creates the tap.
    ///
    /// The lease is the host's handed address when the box was registered
    /// (T66) — the address the host-side table's row is keyed by — a free
    /// one of the session's task addresses for a task launch (NET-138), and
    /// a self-allocated one otherwise, which only a native switch draws.
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(self.reserve())
    }

    /// Relay the sandbox's tap onto the switch and apply its ingress. The
    /// reservation is read, not taken, until the attach has succeeded: a
    /// failed attach hands the release to [`abandon`](Self::abandon) (017-008).
    fn attach(&self, spawned: Spawned) -> AttachFuture<'_> {
        Box::pin(self.attach_reserved(spawned))
    }

    /// Give the lease back; the sandbox layer runs this on every path out of a
    /// launch that does not reach `attach`. The detach releases the lease
    /// with the count (T66), so an abandoned launch leaves no lease in the
    /// static-lease table for a tap nothing holds — the handed one included,
    /// which is what lets the same box's re-attach re-hand its address.
    fn abandon(&self) -> AbandonFuture<'_> {
        Box::pin(async move {
            let Some(reserved) = self
                .reserved
                .lock()
                .expect("reserved mutex poisoned")
                .take()
            else {
                // The plan failed or an attach took it; detaching anyway would
                // decrement the switch's count below the truth.
                return;
            };
            if let Err(e) = self.switch.lock().await.detach(reserved.lease).await {
                tracing::warn!(error = %e, "detaching OwnIp PTask after an abandoned launch");
            }
        })
    }
}

impl OwnIpNetwork {
    /// The body of [`Network::plan`]: leases the address and records the
    /// reservation.
    async fn reserve(&self) -> Result<NetPlan, NetworkError> {
        let (lease, control, subnet) = {
            let mut s = self.switch.lock().await;
            let subnet = s.subnet();
            let attach = match (self.box_addresses.as_ref(), self.task_slots.as_deref()) {
                (Some(handed), _) => s
                    .attach_handed(handed.switch_address)
                    .await
                    .map_err(NetworkError::new)?,
                (None, Some(slots)) => {
                    s.attach_task_slot(slots).await.map_err(NetworkError::new)?
                }
                (None, None) => s.attach().await.map_err(NetworkError::new)?,
            };
            // A box's id is its session's, and a task's box is its
            // session's box.
            let box_id = self
                .own_address
                .as_ref()
                .map(OwnAddressReporter::session_id)
                .or_else(|| self.engine_box.as_ref().map(|judged| judged.of.session()));
            (attach.lease, ControlChannel::of(&s, box_id), subnet)
        };

        *self.reserved.lock().unwrap() = Some(Reserved {
            lease,
            subnet,
            control,
        });
        Ok(own_ip_plan(subnet))
    }

    /// The body of [`Network::attach`]: relays the tap and applies the
    /// ingress from the reservation `plan` made.
    async fn attach_reserved(&self, spawned: Spawned) -> Result<Box<dyn NetGuard>, NetworkError> {
        let Some(reserved) = self.reserved.lock().unwrap().clone() else {
            return Err(NetworkError::new(std::io::Error::other(
                "own-IP attach without a plan: nothing was leased",
            )));
        };

        // A native node carries the box's frames to its own gvproxy. A
        // guest has the node's bridge to hang the namespace off. Either
        // way the box's program waits until the launch lets it start.
        let place = crate::net::attach::Place {
            address: reserved.lease.ip,
            subnet: reserved.subnet,
        };
        let uplink: Box<dyn crate::net::attach::Uplink> = match &reserved.control {
            ControlChannel::Unix(gvproxy) => {
                Box::new(crate::net::attach::tap::TapUplink::new(gvproxy.clone()))
            }
            ControlChannel::VmHost { .. } => Box::new(crate::net::attach::veth::VethUplink),
        };
        let link = uplink
            .connect(&spawned, place)
            .await
            .map_err(NetworkError::new)?;

        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &self.switch,
            link,
            reserved.control,
            reserved.lease,
            crate::net::gvproxy_network::AttachInputs {
                session_name: &self.identity,
                policy: self.policy.as_ref(),
                own_address: self.own_address.as_ref(),
                engine_box: self.engine_box.as_ref(),
                spawned: &spawned,
            },
        )
        .await
        .map_err(NetworkError::new)?;
        // Committed: the guard owns the release from here.
        self.reserved.lock().unwrap().take();
        Ok(Box::new(guard) as Box<dyn NetGuard>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A switch whose attach/detach are pure bookkeeping: `HostShuttle` leaves
    /// the gvproxy process to `minvmd`, so only the count moves.
    ///
    /// It lets the daemon draw, which a VM host's switch never does in
    /// production (NET-138): these tests drive the draw path itself, with
    /// no host to hand them addresses.
    fn counting_switch() -> Arc<Mutex<SwitchClient>> {
        Arc::new(Mutex::new(
            SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy")
                .with_transport(crate::net::SwitchTransport::HostShuttle {
                    cid: crate::net::VSOCK_HOST_CID,
                    port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
                })
                .allowing_self_allocation(),
        ))
    }

    #[tokio::test]
    async fn a_box_with_a_resolver_endpoint_has_it_in_its_resolver_file() {
        let switch = counting_switch();
        let endpoint = crate::net::endpoints::V4;
        let plan = with_box_resolver(
            network_for(NetworkMode::HostNet, &switch, "s", None, None, None, None),
            endpoint,
        )
        .plan()
        .await
        .unwrap();
        assert_eq!(plan.resolver(), &Resolver::Nameservers(vec![endpoint]));
        // Nothing else about the plan changes.
        assert!(!plan.isolates_netns());
    }

    /// 017-005's precondition: the mode decides the provider, in one place,
    /// and each provider plans what its mode states.
    #[tokio::test]
    async fn every_mode_gets_its_provider() {
        let switch = counting_switch();

        let host = network_for(NetworkMode::HostNet, &switch, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert!(!host.isolates_netns());
        // The fixture's switch is a `HostShuttle` — a VM host — so the
        // host-address box resolves through the node's DNS layer, not the
        // host's own resolver (NET-003; the native case is
        // `host_min_internal_resolves_to_host_reach_address_per_mode`).
        assert_eq!(
            host.resolver(),
            &Resolver::Nameservers(vec![crate::net::SwitchSubnet::default().dns_server()])
        );

        let no_net = network_for(NetworkMode::NoNet, &switch, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert!(no_net.isolates_netns() && !no_net.wired());
        assert_eq!(no_net.resolver(), &Resolver::None);

        let own_ip = network_for(NetworkMode::OwnIp, &switch, "s", None, None, None, None);
        assert!(own_ip.plan().await.unwrap().isolates_netns());
        assert_eq!(switch.lock().await.attached(), 1, "own-IP takes a lease");
        own_ip.abandon().await;
        assert_eq!(switch.lock().await.attached(), 0);
    }

    /// A box with an address of its own gets a namespace the attach wires,
    /// and resolves at the virtual network's resolver.
    #[test]
    fn an_own_ip_plan_is_wired_after_the_spawn_and_resolves_at_the_switch() {
        let subnet = crate::net::SwitchSubnet::default();
        let plan = own_ip_plan(subnet);
        assert!(plan.isolates_netns() && plan.wired());
        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.dns_server()])
        );
    }

    /// 017-008. A launch whose attach fails leaves the switch's attachment
    /// count where it was: decremented once, not zero times and not twice.
    #[tokio::test]
    async fn failed_attach_releases_the_switch_once() {
        let switch = counting_switch();
        let before = switch.lock().await.attached();

        let net = network_for(NetworkMode::OwnIp, &switch, "s", None, None, None, None);
        net.plan().await.expect("planning leases an address");
        assert_eq!(switch.lock().await.attached(), before + 1);

        // Nothing was spawned, so there is no namespace to set up.
        assert!(net.attach(Spawned::new()).await.is_err());

        // The sandbox layer runs `abandon` on exactly this path.
        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            before,
            "a failed attach must give the lease back"
        );
        net.abandon().await;
        assert_eq!(
            switch.lock().await.attached(),
            before,
            "an abandon with nothing reserved is a no-op"
        );
    }

    /// 017-N01, stated structurally: the switch is free once a plan returns,
    /// and four launches hold four leases at once. Whether the 2x bound holds
    /// in time is the measurement spec 017 still asks for.
    #[tokio::test]
    async fn concurrent_own_ip_launches_do_not_serialize() {
        let switch = counting_switch();
        let launches: Vec<_> = (0..4)
            .map(|i| {
                network_for(
                    NetworkMode::OwnIp,
                    &switch,
                    &format!("p{i}"),
                    None,
                    None,
                    None,
                    None,
                )
            })
            .collect();
        for net in &launches {
            net.plan().await.expect("planning leases an address");
            assert!(
                switch.try_lock().is_ok(),
                "the switch must be free between a plan and its attach"
            );
        }
        assert_eq!(switch.lock().await.attached(), 4);
        for net in &launches {
            net.abandon().await;
        }
        assert_eq!(switch.lock().await.attached(), 0);
    }

    /// NET-003 for every box kind: `host.min.internal` answers with the address
    /// that reaches the host's loopback — `127.0.0.1` from `/etc/hosts` for a
    /// box sharing the native host's namespace, the switch gateway's DNS zone
    /// for own-address boxes and for host-address boxes on a VM host.
    #[tokio::test]
    async fn host_min_internal_resolves_to_host_reach_address_per_mode() {
        let subnet = crate::net::SwitchSubnet::default();

        // Native host-address: `/etc/hosts` at the host's loopback, because the
        // host's own resolver has no `min.internal.` zone to answer from.
        let native = Arc::new(Mutex::new(SwitchClient::new(
            "/usr/bin/gvproxy",
            "/run/minimal/gvproxy",
        )));
        let plan = network_for(NetworkMode::HostNet, &native, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert_eq!(plan.resolver(), &Resolver::Host);
        assert_eq!(plan.hosts().len(), 1, "one static entry for the host");
        let entry = &plan.hosts()[0];
        assert_eq!(entry.name, sandbox::HOST_MIN_INTERNAL);
        assert_eq!(
            entry.address,
            std::net::Ipv4Addr::LOCALHOST,
            "the name answers at the host's loopback"
        );

        // VM-host host-address: the node's DNS layer answers the same name.
        let vm = counting_switch();
        let plan = network_for(NetworkMode::HostNet, &vm, "s", None, None, None, None)
            .plan()
            .await
            .unwrap();
        assert_eq!(
            plan.resolver(),
            &Resolver::Nameservers(vec![subnet.gateway()])
        );

        // Own-address (the plan is transport-independent): the same gateway,
        // whose static zone answers the name with the NAT'd host-alias address.
        let own = own_ip_plan(subnet);
        assert_eq!(
            own.resolver(),
            &Resolver::Nameservers(vec![subnet.gateway()])
        );
        assert!(
            own.hosts().is_empty(),
            "own-address boxes resolve the host through the zone, not /etc/hosts"
        );
    }
}
