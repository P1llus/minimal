//! The attach of a box with an address of its own: its namespace's TAP is
//! connected to the node's switch, the engine learns the box's address and
//! serves its endpoints inside the namespace, and the box's declared ports
//! are opened.
//!
//! Who made the TAP is `net::provider`'s business. The gvproxy process
//! belongs to the daemon's [`SwitchClient`].

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use sandbox::NetGuard;
use tokio::sync::Mutex;

use crate::net::attach::Link;
use crate::net::engine::{Engine, Installed, Namespace};
use crate::net::ingress_gate::{self, IngressGate};
use crate::net::ingress_gate::{Admission, EngineAdmission};
use crate::net::policy::{ControlChannel, PortForwarder};
use crate::net::{PtaskLease, SwitchClient};

/// The box a namespace belongs to, as the engine knows it.
#[derive(Clone)]
pub(crate) struct EngineBox {
    pub(crate) engine: &'static Engine,
    pub(crate) of: Arc<Installed>,
}

/// An ingress side with no engine under it: every port is open, as it is
/// for a box nothing judges.
struct Unjudged;

impl Admission for Unjudged {
    fn admit(&self, _: netpol::base::PortOf) -> Result<(), String> {
        Ok(())
    }

    fn refuse(&self, _: netpol::base::PortOf) -> Result<(), String> {
        Ok(())
    }
}

/// What stands once a namespace is connected, before its ports are open.
struct Wired {
    /// The namespace's connection to the virtual network.
    _link: Link,
    /// The box's address in the engine and the daemon's endpoints inside
    /// the namespace.
    namespace: Option<Namespace>,
    /// Kept for the attach's life: the publication code finds it by lease.
    gate: Option<Arc<IngressGate>>,
}

/// The own-IP attachment guard. Returned by [`complete_own_ip_attach`] and torn
/// down explicitly via [`NetGuard::teardown`] at the end of the sandbox's life.
///
/// Teardown removes this PTask's ingress forwards then detaches it from the
/// switch (decrementing the switch refcount — which stops gvproxy once the last
/// `OwnIp` PTask leaves — and releasing the lease with the count, handed or
/// drawn alike; a handed lease released with it is what lets the same box's
/// re-attach re-hand its address, T66). It is **explicit** — driven on a
/// live runtime by the owner — so the normal path cannot be lost to a stopped
/// runtime. A guard dropped without it — a task run whose future was aborted
/// mid-await, say — schedules the same release on the runtime it drops on,
/// so the lease never outlives the attach: a task slot held by a leaked lease
/// would read as busy until the daemon restarts.
pub(crate) struct OwnIpGuard {
    /// The attach this guard holds until its release; `None` once
    /// [`NetGuard::teardown`] has taken it, so the drop owes nothing.
    attach: Option<OwnIpAttach>,
}

/// What an own-IP attach holds until its release ([`OwnIpGuard`]).
struct OwnIpAttach {
    wired: Wired,
    /// The shared switch, locked on teardown to detach this PTask.
    switch: Arc<Mutex<SwitchClient>>,
    /// gvproxy's control channel (local socket on DM2, host vsock on DM1/3/4),
    /// used on teardown to remove this PTask's ingress forwards before detaching.
    control: ControlChannel,
    /// The declared ports' forwarders (NET-121) this attach bound — the
    /// forwards the box's name is published beside, held until the box
    /// stops, each able to unbind its port and end its connections. Removed
    /// on teardown. Empty when no ingress was configured.
    exposed: Vec<PortForwarder>,
    /// The lease this guard's attach holds — its address at its epoch —
    /// passed to `detach` so the lease is released with the count (T66),
    /// handed or drawn alike: a lease's life is its attachment's.
    lease: PtaskLease,
    /// The box's runtime publishes (NET-044), shared with its session actor.
    /// They deliver to this spawn's lease, so they come down with it, beside
    /// `exposed`: the next spawn takes a new lease and starts with none,
    /// never with a forward aimed at the stale one. `None` for a task, which
    /// publishes nothing at runtime.
    runtime_ingress: Option<crate::net::provider::RuntimeIngress>,
}

impl OwnIpAttach {
    /// The release [`NetGuard::teardown`] drives, and a dropped guard
    /// schedules: forwards down, then the lease back with the count.
    async fn release(self) {
        // Remove ingress forwards (R2.3 teardown) before detaching: detach
        // may stop gvproxy once the last PTask leaves, so the unexpose must
        // reach a still-running switch first. On a VM-backed host the
        // declared forwards are the host's to unbind at box end, so this
        // asks the switch for nothing there.
        let Self {
            wired,
            switch,
            control,
            mut exposed,
            runtime_ingress,
            lease,
        } = self;
        // A declared port bound for this spawn after its attach, at a
        // shared-address port's hand-over (NET-129), is released with the
        // ones the attach bound.
        let ends_box = runtime_ingress.is_some();
        if let Some(runtime_ingress) = &runtime_ingress {
            exposed.extend(runtime_ingress.detach_handed());
        }
        if !exposed.is_empty() {
            crate::net::policy::release_declared_ingress(&control, &exposed).await;
        }
        // The runtime publishes deliver to the same lease, so they take
        // the same path down — and the box refuses new ones until its
        // next spawn attaches.
        if let Some(runtime_ingress) = &runtime_ingress {
            let runtime = runtime_ingress.detach();
            if !runtime.is_empty() {
                crate::net::policy::remove_ingress(&control, &runtime).await;
            }
        }
        // The ports close before the box loses its address, and the
        // frames stop last. All of it is gone before the lease goes back.
        drop(exposed);
        let Wired {
            _link: link,
            namespace,
            gate,
        } = wired;
        drop(gate);
        drop(namespace);
        drop(link);
        if let Err(e) = switch.lock().await.detach(lease).await {
            tracing::warn!(error = %e, "detaching OwnIp PTask from switch on session end");
        }
        // A task's namespace is not its box's: the box's own launch ends it.
        if ends_box
            && let ControlChannel::VmHost {
                door,
                box_id: Some(box_id),
            } = control
        {
            // The VM host unbinds the box's forwards on this message only,
            // so it is told until it answers, whatever becomes of this
            // launch.
            crate::traced::spawn_detached(
                tracing::info_span!(parent: None, "net.end_box", %box_id),
                async move {
                    let ended = door.end_box(box_id).await;
                    tracing::info!(
                        %box_id,
                        ended = ended.ended,
                        forwards_unbound = ended.forwards_unbound,
                        still_bound = ended.still_bound,
                        "told the VM host that the box's network is gone"
                    );
                },
            );
        }
    }
}

impl Drop for OwnIpGuard {
    fn drop(&mut self) {
        let Some(attach) = self.attach.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                tracing::debug!(
                    ip = %attach.lease.ip,
                    "own-IP attach dropped without its teardown; releasing it"
                );
                runtime.spawn(attach.release());
            }
            Err(_) => tracing::warn!(
                ip = %attach.lease.ip,
                "own-IP attach dropped off any runtime; its lease stays held \
                 until the daemon restarts"
            ),
        }
    }
}

impl NetGuard for OwnIpGuard {
    fn teardown(mut self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let attach = self.attach.take();
        Box::pin(async move {
            if let Some(attach) = attach {
                attach.release().await;
            }
        })
    }
}

/// What an attach is given beside the box's lease.
pub(crate) struct AttachInputs<'a> {
    pub(crate) session_name: &'a str,
    pub(crate) policy: Option<&'a boxes::BoxPolicy>,
    pub(crate) own_address: Option<&'a crate::net::provider::OwnAddressReporter>,
    /// The box's entry in the engine. `None` for a box nothing judges.
    pub(crate) engine_box: Option<&'a EngineBox>,
    /// The container whose namespace is attached.
    pub(crate) spawned: &'a sandbox::Spawned,
}

/// Finishes the attach of a box's namespace that `link` connects to the
/// virtual network: the engine's side of it and its declared ports. The
/// box's program does not run yet.
///
/// # Errors
///
/// Whatever step failed. Everything made before it is taken back, and the
/// lease stays with the launch to give back.
pub(crate) async fn complete_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    link: Link,
    control: ControlChannel,
    lease: PtaskLease,
    inputs: AttachInputs<'_>,
) -> io::Result<OwnIpGuard> {
    let AttachInputs {
        session_name,
        policy,
        own_address,
        engine_box,
        spawned,
    } = inputs;
    let lease_ip = lease.ip;
    let namespace = engine_box
        .map(|of| of.engine.serve_namespace(&of.of, spawned, lease_ip))
        .transpose()
        .map_err(io::Error::other)?;
    let gate = policy
        .map(|policy| {
            let admission: Arc<dyn Admission> = match engine_box {
                Some(of) => Arc::new(EngineAdmission {
                    engine: of.engine,
                    of: Arc::clone(&of.of),
                }),
                None => Arc::new(Unjudged),
            };
            let listeners = namespace.as_ref().and_then(Namespace::listeners);
            IngressGate::new(policy.ingress.as_ref(), admission, listeners)
                .map_err(io::Error::other)
        })
        .transpose()?;
    if let Some(gate) = &gate {
        ingress_gate::register(lease_ip, gate);
    }
    tracing::debug!(
        session = session_name,
        switch_address = %lease_ip,
        judged = engine_box.is_some(),
        "own-address box attached to the switch"
    );
    finish_own_ip_attach(
        switch,
        Wired {
            _link: link,
            namespace,
            gate,
        },
        control,
        lease,
        session_name,
        policy.and_then(|p| p.ingress.as_ref()),
        own_address,
    )
    .await
}

/// The rest of the attach: binds the declared ports' forwards and reports
/// the box's address to the name registry. A forward that does not bind
/// takes the wiring down again.
async fn finish_own_ip_attach(
    switch: &Arc<Mutex<SwitchClient>>,
    wired: Wired,
    control: ControlChannel,
    lease: PtaskLease,
    session_name: &str,
    ingress: Option<&boxes::IngressPolicy>,
    own_address: Option<&crate::net::provider::OwnAddressReporter>,
) -> io::Result<OwnIpGuard> {
    let gate = wired.gate.as_ref();
    let lease_ip = lease.ip;
    // The host loopback address this box's declaration publishes on (NET-010):
    // the address a creator handed it, read back from the registry rather than
    // re-derived, so the forwards bind where the box's name answers. The
    // daemon has no default of its own to stand in with — a box nobody handed
    // an address publishes nowhere, and a launch that declared ingress fails
    // rather than binding forwards at an address nobody chose for it. A launch
    // without a reporter — a task, which owns no proxy route of its own — is
    // not this box's publish: tasks declare no ingress, so they never reach
    // for a published address at all.
    let published = own_address.and_then(|reporter| reporter.published_address());
    let exposed = match (ingress, published) {
        (Some(ingress), _) if ingress.port_mappings.is_empty() => Vec::new(),
        (Some(ingress), Some(published)) => {
            // The ports this box yields at a shared address (NET-129,
            // first-come) are known state from its publish, not a failed
            // bind: their forwards are skipped and the box stays usable.
            let yielded = own_address
                .map(crate::net::provider::OwnAddressReporter::shared_port_collisions)
                .unwrap_or_default();
            // A taken port's refusal names its holder (NET-144): the box
            // whose publish stands at that address and port, or the host.
            let registry = own_address.map(crate::net::provider::OwnAddressReporter::registry);
            let holder_of = |port: u16| match &registry {
                Some(registry) => {
                    crate::net::policy::port_holder(registry, session_name, published, port)
                }
                None => minimald_rpc::PortHolder::Host,
            };
            match crate::net::policy::apply_ingress_naming_holders(
                &control, published, lease_ip, ingress, gate, &yielded, &holder_of,
            )
            .await
            {
                Ok(exposed) => exposed,
                // The failure is already said — one warn per failed bind,
                // with the port and the reason, where the bind happened — so
                // no aggregate line re-tells it here. The attach fails: no
                // route reported, and the name finalize registered is
                // withdrawn — a bind that failed never leaves a name standing
                // for a port that refused (NET-121) — and no substitute
                // address stands in for the port that could not bind. A taken
                // port comes back as the typed refusal, with the port and its
                // holder, so the finalize that launched this attach can name
                // both (NET-144).
                Err(e) => {
                    drop(wired);
                    if let Some(own_address) = own_address {
                        own_address.withdraw(session_name);
                    }
                    return Err(e);
                }
            }
        }
        (Some(_), None) => {
            // A declared ingress with no address handed: fail the attach with
            // the same rollback as a failed bind — the relay is dropped, the
            // route never reported, and the name finalize registered is
            // withdrawn, so the box never publishes at an address nobody
            // chose for it and its name never answers for ports that are
            // not bound (NET-010, NET-121).
            drop(wired);
            if let Some(own_address) = own_address {
                own_address.withdraw(session_name);
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no published address handed for box {session_name}"),
            ));
        }
        (None, _) => Vec::new(),
    };

    // One info line per bound forwarder (NET-040, NET-121): the host address
    // it is reachable at, the port, and the session it belongs to — so the
    // daemon log tail (and the `min bug` bundle carrying it) shows each
    // forwarder bind and its result when a publish goes wrong. Reported from
    // `exposed` — the forwards the switch actually accepted, 1:1 with the
    // request since a failed apply rolls back and errors above — and from
    // each forward's own `local` bind, never from the request: the record
    // stays true to what the forwarder holds if the address `expose_request`
    // binds ever moves off the loopback.
    //
    // The message text is a contract beside the fields: `session-e2e.sh`'s
    // `published_loopback_host` reads the publish record — the address the
    // forwarder actually bound — out of the daemon log by exactly this
    // phrase, so it is not reworded without that reader moving too.
    for forwarder in &exposed {
        match forwarder.host_port() {
            Some((host, port)) => tracing::info!(
                host,
                port,
                session = session_name,
                "exposed ingress port on the host loopback"
            ),
            // `expose_request` cannot build a `local` that splits into no
            // host and port; if one ever appears, name what the forwarder
            // holds rather than invent a port for it.
            None => tracing::info!(
                local = %forwarder.local(),
                session = session_name,
                "exposed ingress port on the host loopback"
            ),
        }
    }

    if let Some(own_address) = own_address {
        let ports = ingress.map_or_else(BTreeMap::new, |ingress| {
            ingress
                .port_mappings
                .iter()
                .map(|mapping| (mapping.external_port, mapping.internal_port))
                .collect()
        });
        own_address.report(session_name, lease_ip, ports);
    }

    let runtime_ingress =
        own_address.map(crate::net::provider::OwnAddressReporter::runtime_ingress);
    // The box's actor unbinds a declared forward a move of its publish left
    // at the old address (#2748), so it holds clones of the attach's.
    if let Some(runtime_ingress) = &runtime_ingress {
        runtime_ingress.record_attached(&exposed);
    }
    Ok(OwnIpGuard {
        attach: Some(OwnIpAttach {
            wired,
            switch: Arc::clone(switch),
            control,
            exposed,
            lease,
            runtime_ingress,
        }),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use sandbox::NetGuard as _;
    use switch::MacAddr;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::{Mutex, mpsc};

    use crate::net::PtaskLease;
    use crate::net::SwitchClient;
    use crate::net::SwitchTransport;
    use crate::net::attach::Link;
    use crate::net::dns;
    use crate::net::policy::ControlChannel;

    /// A lease at `ip` for an attach whose switch never handed it: epoch 0,
    /// which no allocator hands, so its teardown releases nothing.
    fn lease_at(ip: Ipv4Addr) -> PtaskLease {
        PtaskLease {
            ip,
            mac: MacAddr::for_switch_ip(ip),
            epoch: 0,
        }
    }

    /// The fake gvproxy's answer for a request it serves happily.
    fn ok() -> (u16, String) {
        (200, String::new())
    }

    /// A switch whose attach/detach are pure bookkeeping: `HostShuttle`
    /// leaves the gvproxy process to `minvmd`, so only the count moves —
    /// the shape a VM-backed host's daemon carries. Carries the same
    /// instance host id the NET-121 proofs build their registry with
    /// (`aaaa1`), the pairing the daemon itself makes
    /// (`box_manager.rs` builds its registry from this switch's `host_id`),
    /// so the attach's per-id `/services/dns/add` publishes — its own id
    /// beside the deprecated `local` one — are the two the proofs count.
    fn vm_host_switch() -> Arc<Mutex<SwitchClient>> {
        Arc::new(Mutex::new(
            SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy")
                .with_host_id("aaaa1")
                .with_transport(SwitchTransport::HostShuttle {
                    cid: crate::net::VSOCK_HOST_CID,
                    port: crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
                }),
        ))
    }

    // ---- NET-121: bind before the name; failed bind, no substitute; revocation
    // -----------------------------------------------------------------------

    /// Reads one control request off `sock` — its head, then exactly its
    /// `Content-Length` body — and returns both. The mirror of
    /// `policy::post_json`'s keep-alive framing; the `/connect` upgrade
    /// carries no body, and the head is what tells it apart.
    async fn read_request_head_and_body(
        sock: &mut UnixStream,
    ) -> std::io::Result<(String, Vec<u8>)> {
        let mut buf = Vec::with_capacity(512);
        let mut scratch = [0u8; 512];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                break i;
            }
            let n = sock
                .read(&mut scratch)
                .await
                .expect("the fake gvproxy must receive the control request");
            assert!(n > 0, "the control client closed before sending its head");
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
                .expect("the fake gvproxy must receive the request body");
            assert!(n > 0, "the control client closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        Ok((head, buf[head_end..head_end + len].to_vec()))
    }

    /// The gvproxy stand-in the NET-121 proofs drive `complete_own_ip_attach`
    /// against: every control request is read in full, answered with the
    /// status and reason body `decide` picks for `(path, body)`, and recorded
    /// as `(path, body)` on `events` in arrival order — the order the
    /// attach's binds and registrations happened in. The `/connect` upgrade
    /// is hijacked the way the real switch hijacks it: no response is
    /// written, and the upgraded stream is handed to the test, which becomes
    /// the switch side of the box's relay for as long as it holds it.
    ///
    /// Abort the returned handle when the test is done; the fake accepts
    /// until then.
    fn spawn_control_channel_deciding(
        path: PathBuf,
        decide: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
        events: mpsc::Sender<(String, String)>,
        handed: mpsc::Sender<UnixStream>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        crate::traced::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let Ok((head, body)) = read_request_head_and_body(&mut sock).await else {
                    return;
                };
                if head.starts_with("POST /connect") {
                    // The real switch hijacks the connection and writes no
                    // response; the relay legs take it from here.
                    handed
                        .send(sock)
                        .await
                        .expect("the test still holds the handed stream");
                    continue;
                }
                let request_path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let body = String::from_utf8_lossy(&body).into_owned();
                let (status, reason_body) = decide(&request_path, &body);
                let reason = match status {
                    200..=299 => "OK",
                    403 => "Forbidden",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Answered",
                };
                let mut response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n\r\n",
                    reason_body.len()
                )
                .into_bytes();
                response.extend_from_slice(reason_body.as_bytes());
                sock.write_all(&response)
                    .await
                    .expect("the fake gvproxy must answer");
                events
                    .send((request_path, body))
                    .await
                    .expect("the test is still collecting the control requests");
            }
        })
    }

    /// The two declared ports the NET-121 proofs publish: host `:8080` and
    /// `:9090`, each forwarding to its own number on the box.
    fn declared_two_ports() -> boxes::BoxPolicy {
        boxes::BoxPolicy {
            ingress: Some(boxes::IngressPolicy {
                port_mappings: vec![
                    boxes::PortMapping {
                        external_port: 8080,
                        internal_port: 80,
                        proto: boxes::IpProto::Tcp,
                    },
                    boxes::PortMapping {
                        external_port: 9090,
                        internal_port: 90,
                        proto: boxes::IpProto::Tcp,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
            credentialed_upstream: None,
            quic443: None,
        }
    }

    /// Three declared ports — one more than any one attach can bind before a
    /// refusal — so a proof can show the rollback of a half-bound box: two
    /// bound, the third refused, and the two unbound with it.
    fn declared_three_ports() -> boxes::BoxPolicy {
        boxes::BoxPolicy {
            ingress: Some(boxes::IngressPolicy {
                port_mappings: vec![
                    boxes::PortMapping {
                        external_port: 8080,
                        internal_port: 80,
                        proto: boxes::IpProto::Tcp,
                    },
                    boxes::PortMapping {
                        external_port: 9090,
                        internal_port: 90,
                        proto: boxes::IpProto::Tcp,
                    },
                    boxes::PortMapping {
                        external_port: 7070,
                        internal_port: 70,
                        proto: boxes::IpProto::Tcp,
                    },
                ],
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }),
            egress: None,
            credentialed_upstream: None,
            quic443: None,
        }
    }

    /// One failed-bind scenario's pieces: the control path its stand-in
    /// listens on, the registry the box's name would publish in, the
    /// reporter that would report it, and the relay's own two ends — the
    /// box's half held for its life, never read, so the box stays reachable
    /// for as long as the scenario runs — everything but the fake that
    /// answers and the attach itself.
    struct AttachScenario {
        control_path: PathBuf,
        registry: Arc<std::sync::RwLock<dns::HostnameRegistry>>,
        reporter: crate::net::provider::OwnAddressReporter,
    }

    /// Builds one scenario inside `dir`, on its own `socket`, so a test can
    /// drive two attaches without one's traffic landing on the other's
    /// stand-in or registry.
    fn attach_scenario(dir: &tempfile::TempDir, socket: &str) -> AttachScenario {
        let control_path = dir.path().join(socket);
        let registry = Arc::new(std::sync::RwLock::new(dns::HostnameRegistry::new(
            "aaaa1", true,
        )));
        let reporter = crate::net::provider::OwnAddressReporter::new(
            Arc::clone(&registry),
            boxes::SessionId::nil(),
        );
        AttachScenario {
            control_path,
            registry,
            reporter,
        }
    }

    /// A connection of a namespace that nothing carries.
    fn no_link() -> Link {
        Link::new(|| {})
    }

    /// The control requests that have arrived. An attach that has returned
    /// has made all of its own.
    fn seen_so_far(events: &mut mpsc::Receiver<(String, String)>) -> Vec<(String, String)> {
        let mut seen = Vec::new();
        while let Ok(event) = events.try_recv() {
            seen.push(event);
        }
        seen
    }

    /// Reads control events until `want` requests on `path` have arrived.
    async fn collect_until(
        events: &mut mpsc::Receiver<(String, String)>,
        path: &str,
        want: usize,
    ) -> Vec<(String, String)> {
        let mut seen = Vec::new();
        loop {
            let event = match tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
                .await
            {
                Ok(Some(event)) => event,
                Ok(None) => {
                    panic!("the fake gvproxy stopped before {want} {path} requests arrived")
                }
                Err(_) => panic!("no {path} request arrived within 5s; seen so far: {seen:?}"),
            };
            let hit = event.0 == path;
            seen.push(event);
            if hit && seen.iter().filter(|(p, _)| p == path).count() >= want {
                return seen;
            }
        }
    }

    /// The `local` fields of every request on `path`, in order.
    fn locals_of(events: &[(String, String)], path: &str) -> Vec<String> {
        events
            .iter()
            .filter(|(p, _)| p == path)
            .filter_map(|(_, body)| {
                body.split("\"local\":\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .map(str::to_string)
            })
            .collect()
    }

    /// NET-121's sub 2, both shapes of a bind that did not land:
    ///
    /// A *gate refusal* — the switch answering an expose with a refusal, the
    /// way the session gate answers a port the box's row does not declare —
    /// is a failed bind exactly like a bind that errored: the attach fails,
    /// neither the name nor any substitute address is published for the
    /// refused port, and the refusal's own reason reaches the caller beside
    /// the port, in the returned error and in the warn line.
    ///
    /// The registry this drives is one finalize has already run on (NET-011):
    /// the creator's hand published the box's address and the registration
    /// held the name at it *before* the binds — the finding's own premise —
    /// so the rollback's other half is the one thing that makes the end
    /// state honest: the failed bind withdraws that name, and no name is
    /// left standing for a port that refused.
    ///
    /// And either shape rolls the whole half back: the ports that *did* bind
    /// are unexposed before the attach gives up, so a half-bound box holds
    /// nothing — the rollback is asserted per shape, not by extrapolating
    /// from one port's.
    #[tokio::test]
    async fn failed_forwarder_bind_is_reported_not_substituted() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        const HANDED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 10);
        let capture = crate::test_harness::captured_log();
        let dir = tempfile::TempDir::new().unwrap();

        // Shape one: the gate refuses the third of three declared ports,
        // with the reason a real gate refusal carries.
        let refused = attach_scenario(&dir, "gvproxy.sock");
        let (refused_events_tx, mut refused_events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let refused_fake = spawn_control_channel_deciding(
            refused.control_path.clone(),
            |path, body| {
                if path == "/services/forwarder/expose" && body.contains(&format!("{HANDED}:7070"))
                {
                    (403, "port 7070 is not declared on this row".to_string())
                } else {
                    ok()
                }
            },
            refused_events_tx,
            handed_tx,
        );
        let refused_switch = vm_host_switch();
        let refused_policy = declared_three_ports();
        // Finalize has already run: the hand published the box's address,
        // the registration held the name at it, and the attach's binds are
        // what must undo that if they fail.
        {
            let mut reg = refused.registry.write().expect("registry lock");
            reg.publish_own_address(
                boxes::SessionId::nil(),
                "web",
                HANDED,
                BTreeSet::from([8080, 9090, 7070]),
            );
            reg.register_own_ip(
                boxes::SessionId::nil(),
                "web",
                BTreeSet::from([8080, 9090, 7070]),
            );
        }
        let held_before = refused
            .registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held_before,
            dns::ZoneEntry::Held {
                owner: "web".to_string(),
                address: Some(HANDED),
            },
            "finalize held the name before the binds: {held_before:?}"
        );
        let err = match crate::net::gvproxy_network::complete_own_ip_attach(
            &refused_switch,
            no_link(),
            ControlChannel::Unix(refused.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&refused_policy),
                own_address: Some(&refused.reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        {
            Ok(_) => panic!("a refused bind must fail the attach like a failed one"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("7070")
                && err.to_string().contains("not declared on this row"),
            "the refusal names its port and carries the reason the gate gave: {err}"
        );

        // Every declared port was attempted — the refusal is answered, not
        // anticipated — and both binds that landed are rolled back with it:
        // a half-bound box holds nothing.
        let events = collect_until(&mut refused_events_rx, "/services/forwarder/unexpose", 2).await;
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec![
                format!("{HANDED}:8080"),
                format!("{HANDED}:9090"),
                format!("{HANDED}:7070")
            ],
            "all three binds were attempted: {events:?}"
        );
        assert_eq!(
            locals_of(&events, "/services/forwarder/unexpose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "the binds that succeeded are rolled back with the refused one: {events:?}"
        );
        assert!(
            !events.iter().any(|(p, _)| p == "/services/dns/add"),
            "a refused bind publishes no name: {events:?}"
        );
        let held = refused
            .registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held,
            dns::ZoneEntry::Absent,
            "the failed bind withdrew the name finalize registered; no \
             substitute address stands in for the refused bind: {held:?}"
        );
        // The refusal is the log's own fact, said per port: the declared
        // number, and the reason the gate gave, in the same warn line.
        let log = capture.contents();
        assert!(
            log.contains("binding declared ingress port failed")
                && log.contains("port=7070")
                && log.contains("port 7070 is not declared on this row"),
            "the refused bind says its line with the port and the reason: {log}"
        );
        refused_fake.abort();

        // Shape two: a bind that errors — the real forwarder answering a
        // bind failure — fails the attach the same way, on its own ports.
        let failed = attach_scenario(&dir, "gvproxy-2.sock");
        let (failed_events_tx, mut failed_events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let failed_fake = spawn_control_channel_deciding(
            failed.control_path.clone(),
            |path, body| {
                if path == "/services/forwarder/expose" && body.contains(&format!("{HANDED}:9090"))
                {
                    (500, String::new())
                } else {
                    ok()
                }
            },
            failed_events_tx,
            handed_tx,
        );
        let failed_switch = vm_host_switch();
        let failed_policy = declared_two_ports();
        // Finalize has already run here too — the same held-from-finalize
        // name for the failed bind to withdraw.
        {
            let mut reg = failed.registry.write().expect("registry lock");
            reg.publish_own_address(
                boxes::SessionId::nil(),
                "web",
                HANDED,
                BTreeSet::from([8080, 9090]),
            );
            reg.register_own_ip(boxes::SessionId::nil(), "web", BTreeSet::from([8080, 9090]));
        }
        let held_before = failed
            .registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held_before,
            dns::ZoneEntry::Held {
                owner: "web".to_string(),
                address: Some(HANDED),
            },
            "finalize held the name before the binds: {held_before:?}"
        );
        let err = match crate::net::gvproxy_network::complete_own_ip_attach(
            &failed_switch,
            no_link(),
            ControlChannel::Unix(failed.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&failed_policy),
                own_address: Some(&failed.reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        {
            Ok(_) => panic!("a failed bind must fail the attach"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("9090") || err.to_string().contains("500"),
            "the failure names the bind that failed: {err}"
        );

        // Both binds attempted, the one that landed rolled back, and no
        // registration — the same shape the refusal proved, on its own ports.
        let events = collect_until(&mut failed_events_rx, "/services/forwarder/unexpose", 1).await;
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "both binds were attempted: {events:?}"
        );
        assert_eq!(
            locals_of(&events, "/services/forwarder/unexpose"),
            vec![format!("{HANDED}:8080")],
            "the bind that succeeded is rolled back with the failed one: {events:?}"
        );
        assert!(
            !events.iter().any(|(p, _)| p == "/services/dns/add"),
            "a failed bind publishes no name: {events:?}"
        );
        let held = failed
            .registry
            .read()
            .expect("registry lock")
            .zone_entry("web.min.internal", &[]);
        assert_eq!(
            held,
            dns::ZoneEntry::Absent,
            "the failed bind withdrew the name finalize registered; no \
             substitute address stands in for the failed bind: {held:?}"
        );
        let log = capture.contents();
        assert!(
            log.contains("binding declared ingress port failed") && log.contains("port=9090"),
            "the failed bind says its line with the port: {log}"
        );
        failed_fake.abort();
    }

    /// NET-121/NET-010's no-address half: a launch that declared ingress but
    /// was handed no address fails its attach — with the same rollback as a
    /// failed bind — rather than publishing at a default. The daemon has no
    /// address of its own to stand in with: zero forwarders bound, zero
    /// names published, the registry's name absent before and after.
    #[tokio::test]
    async fn attach_without_a_handed_address_fails_rather_than_publishing_a_default() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        let dir = tempfile::TempDir::new().unwrap();

        // A launch with no reporter at all: whatever it declared, nothing
        // hands it an address to publish at.
        let bare = attach_scenario(&dir, "gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake = spawn_control_channel_deciding(
            bare.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let policy = declared_two_ports();
        let err = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            ControlChannel::Unix(bare.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: None,
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .err()
        .expect("no address handed, no publish");
        assert_eq!(
            err.to_string(),
            "no published address handed for box web",
            "the failure says what was missing, not a default it invented: {err}"
        );
        // Zero forwarders, zero names: the failure is decided before any
        // bind, so no expose and no name registration ever reached the
        // control channel — only the connect upgrade did.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let mut seen = Vec::new();
        while let Ok(event) = events_rx.try_recv() {
            seen.push(event);
        }
        assert!(
            seen.iter().all(|(path, _)| path == "/connect"),
            "nothing but the connect: no bind, no name: {seen:?}"
        );
        assert_eq!(
            bare.registry
                .read()
                .expect("registry lock")
                .zone_entry("web.min.internal", &[]),
            dns::ZoneEntry::Absent,
            "a box nobody handed an address holds no name"
        );
        fake.abort();

        // The same launch with a reporter whose registry holds no hand —
        // the real shape of a creator that has not handed one: finalize
        // registered nothing (there was no published address to register
        // at), and the attach refuses to invent one the registry never
        // recorded.
        let unhand = attach_scenario(&dir, "gvproxy-2.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let unhand_fake = spawn_control_channel_deciding(
            unhand.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        assert!(
            unhand
                .registry
                .write()
                .expect("registry lock")
                .register_own_ip(boxes::SessionId::nil(), "web", BTreeSet::from([8080, 9090]))
                .is_none(),
            "finalize with no hand registers no name"
        );
        let err = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            ControlChannel::Unix(unhand.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: Some(&unhand.reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .err()
        .expect("a reporter with no hand publishes nothing either");
        assert_eq!(
            err.to_string(),
            "no published address handed for box web",
            "the same missing fact, the same failure: {err}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let mut seen = Vec::new();
        while let Ok(event) = events_rx.try_recv() {
            seen.push(event);
        }
        assert!(
            seen.iter().all(|(path, _)| path == "/connect"),
            "nothing but the connect: no bind, no name: {seen:?}"
        );
        assert_eq!(
            unhand
                .registry
                .read()
                .expect("registry lock")
                .zone_entry("web.min.internal", &[]),
            dns::ZoneEntry::Absent,
            "the attach left the name as finalize left it: absent"
        );
        unhand_fake.abort();
    }

    /// The other side of the same contract: a reporter whose registry holds
    /// a handed address publishes at exactly it — `127.0.0.1`, the address
    /// the old default published at, now sourced from the hand that named
    /// it — and the failure above is the only alternative: the address the
    /// forwards bind and the name answers is the one the creator handed, or
    /// there is no publish at all.
    #[tokio::test]
    async fn attach_publishes_at_the_address_the_reporter_handed() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        const HANDED: Ipv4Addr = Ipv4Addr::LOCALHOST;
        let dir = tempfile::TempDir::new().unwrap();
        let scenario = attach_scenario(&dir, "gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake = spawn_control_channel_deciding(
            scenario.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let policy = declared_two_ports();

        // The creator's hand: the host loopback itself, published into the
        // registry before the attach — the shape the round's finding asked
        // for, that `127.0.0.1` is an address someone handed, never a
        // default the daemon reached for.
        scenario
            .registry
            .write()
            .expect("registry lock")
            .publish_own_address(
                boxes::SessionId::nil(),
                "web",
                HANDED,
                BTreeSet::from([8080, 9090]),
            );

        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            ControlChannel::Unix(scenario.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: Some(&scenario.reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .expect("the attach completes at the handed address");
        let events = seen_so_far(&mut events_rx);
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "the forwards bind at the handed address, exactly as handed: {events:?}"
        );
        assert_eq!(
            scenario
                .registry
                .read()
                .expect("registry lock")
                .zone_entry("web.min.internal", &[]),
            dns::ZoneEntry::Held {
                owner: "web".to_string(),
                address: Some(HANDED),
            },
            "the name answers at the same handed address"
        );
        Box::new(guard).teardown().await;
        let unbound = collect_until(&mut events_rx, "/services/forwarder/unexpose", 2).await;
        assert_eq!(
            locals_of(&unbound, "/services/forwarder/unexpose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "teardown unbinds what the hand addressed: {unbound:?}"
        );
        fake.abort();
    }

    /// NET-138: a task run's guard dropped without its teardown — the Env
    /// actor's abort cancelling an in-box `min run` mid-await — still
    /// releases its task slot, so the session's next run finds the slot free
    /// rather than refused as busy until the daemon restarts.
    #[tokio::test]
    async fn a_dropped_guard_releases_its_task_slot() {
        let dir = tempfile::TempDir::new().unwrap();
        let scenario = attach_scenario(&dir, "gvproxy.sock");
        let (events_tx, _events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake = spawn_control_channel_deciding(
            scenario.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let slots = [Ipv4Addr::new(100, 64, 128, 20)];
        let attached = switch
            .lock()
            .await
            .attach_task_slot(&slots)
            .await
            .expect("the slot is free");
        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            ControlChannel::Unix(scenario.control_path.clone()),
            attached.lease,
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: None,
                own_address: None,
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .expect("the task's attach completes");
        assert!(
            matches!(
                switch.lock().await.attach_task_slot(&slots).await,
                Err(crate::net::NetError::TaskSlotsBusy { slots: 1 })
            ),
            "the run holds its slot"
        );

        drop(guard);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while switch.lock().await.attached() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the dropped guard's release never ran"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let again = switch
            .lock()
            .await
            .attach_task_slot(&slots)
            .await
            .expect("the dropped run's slot is free again");
        assert_eq!(again.lease.ip, slots[0]);
        fake.abort();
    }

    /// NET-129, first-come at a shared address: a box whose declared port
    /// another box at the same address already holds yields that port. Its
    /// attach reads the collision its publish recorded and skips that
    /// forward, so it never asks the forwarder for a bind the forwarder would
    /// refuse ("proxy already running"). The attach succeeds, the box's
    /// other forwards bind, its name registers, and the skipped port is said
    /// in one warn line naming the port and the box that holds it.
    #[tokio::test]
    async fn a_yielded_shared_address_port_is_skipped_and_the_attach_succeeds() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 10);
        const SHARED: Ipv4Addr = Ipv4Addr::LOCALHOST;
        let capture = crate::test_harness::captured_log();
        let dir = tempfile::TempDir::new().unwrap();
        let scenario = attach_scenario(&dir, "gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        // The forwarder refuses the held port exactly as the real one does,
        // so an attach that asked for it would fail.
        let fake = spawn_control_channel_deciding(
            scenario.control_path.clone(),
            |path, body| {
                if path == "/services/forwarder/expose" && body.contains(&format!("{SHARED}:8080"))
                {
                    (500, "proxy already running".to_string())
                } else {
                    ok()
                }
            },
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let policy = declared_two_ports();

        // Finalize has run for both boxes: the holder published 8080 first,
        // and this box (the nil id) yields it.
        let holder = boxes::SessionId::parse_str("00000000-0000-0000-0000-0000000000a1")
            .expect("a valid id");
        {
            let mut reg = scenario.registry.write().expect("registry lock");
            reg.publish_own_address(holder, "holder", SHARED, BTreeSet::from([8080]));
            reg.register_own_ip(holder, "holder", BTreeSet::from([8080]));
            let collisions = reg.publish_own_address(
                boxes::SessionId::nil(),
                "web",
                SHARED,
                BTreeSet::from([8080, 9090]),
            );
            assert_eq!(
                collisions.iter().map(|c| c.port).collect::<Vec<_>>(),
                vec![8080],
                "the later box yields the held port"
            );
            reg.register_own_ip(boxes::SessionId::nil(), "web", BTreeSet::from([8080, 9090]));
        }

        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            ControlChannel::Unix(scenario.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: Some(&scenario.reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .expect("a yielded port does not fail the attach");
        let events = seen_so_far(&mut events_rx);
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec![format!("{SHARED}:9090")],
            "the yielded port is never asked for; the other forward binds: {events:?}"
        );
        assert_eq!(
            scenario
                .registry
                .read()
                .expect("registry lock")
                .zone_entry("web.min.internal", &[]),
            dns::ZoneEntry::Held {
                owner: "web".to_string(),
                address: Some(SHARED),
            },
            "the yielding box's name stays registered"
        );
        let log = capture.contents();
        assert!(
            log.lines().any(|line| {
                line.contains("declared ingress port not bound")
                    && line.contains("port=8080")
                    && line.contains("other=holder")
            }),
            "the skipped port is said with the box that holds it: {log}"
        );
        Box::new(guard).teardown().await;
        let unbound = collect_until(&mut events_rx, "/services/forwarder/unexpose", 1).await;
        assert_eq!(
            locals_of(&unbound, "/services/forwarder/unexpose"),
            vec![format!("{SHARED}:9090")],
            "teardown unbinds only what the attach bound: {unbound:?}"
        );
        fake.abort();
    }

    /// NET-044 across a respawn: a runtime publish delivers to the lease of
    /// the spawn that was running when it was made, and leases are per-spawn,
    /// so it follows the declared forwards — the spawn's teardown unbinds it
    /// beside them, and the box refuses new publishes until a spawn attaches
    /// again. The next spawn, on a new lease, starts with no runtime forward
    /// at all: nothing is left delivering to the stale address.
    #[tokio::test]
    async fn runtime_forwards_come_down_with_the_spawn_they_deliver_to() {
        const FIRST_LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        const SECOND_LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 10);
        const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);
        let dir = tempfile::TempDir::new().unwrap();
        let scenario = attach_scenario(&dir, "gvproxy.sock");
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake = spawn_control_channel_deciding(
            scenario.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let policy = declared_two_ports();
        let control = ControlChannel::Unix(scenario.control_path.clone());
        scenario
            .registry
            .write()
            .expect("registry lock")
            .publish_own_address(
                boxes::SessionId::nil(),
                "web",
                PUBLISHED,
                BTreeSet::from([8080, 9090]),
            );
        // The session actor's cell, shared with every spawn's guard through
        // the reporter, as the launcher wires it.
        let runtime = crate::net::provider::RuntimeIngress::default();
        let reporter = scenario
            .reporter
            .clone()
            .with_runtime_ingress(runtime.clone());

        // First spawn: attach, then a runtime publish delivering to its lease.
        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            control.clone(),
            lease_at(FIRST_LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: Some(&reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .expect("the first spawn attaches");
        seen_so_far(&mut events_rx);
        let forwarder = crate::net::policy::expose_dynamic(
            &control,
            PUBLISHED,
            FIRST_LEASE,
            3000,
            boxes::IpProto::Tcp,
            None,
        )
        .await
        .expect("the runtime publish binds");
        let exposed = collect_until(&mut events_rx, "/services/forwarder/expose", 1).await;
        assert!(
            exposed
                .iter()
                .any(|(_, body)| body.contains(&format!("\"remote\":\"{FIRST_LEASE}:3000\""))),
            "the runtime publish delivers to the first spawn's lease: {exposed:?}"
        );
        runtime
            .record(crate::net::provider::LiveIngressForward {
                mapping: minimald_rpc::LiveMapping {
                    local: forwarder.local().to_string(),
                    internal_port: forwarder.internal_port(),
                    proto: boxes::IpProto::Tcp,
                    // The gate-less runtime publish this test drives reads
                    // as reachable — there is no relay gate to have
                    // admitted the port — so the field says so outright
                    // rather than defaulting to the unknown.
                    pending: Some(false),
                },
                forwarder,
            })
            .expect("a running spawn records the publish");

        // The spawn ends: its teardown unbinds the runtime forward with the
        // declared ones, and the box is detached until the next spawn.
        Box::new(guard).teardown().await;
        let unbound = collect_until(&mut events_rx, "/services/forwarder/unexpose", 3).await;
        assert!(
            locals_of(&unbound, "/services/forwarder/unexpose")
                .contains(&format!("{PUBLISHED}:3000")),
            "the spawn's teardown unbinds the runtime forward: {unbound:?}"
        );
        assert!(runtime.snapshot().is_empty(), "nothing is listed as live");
        assert!(
            runtime.is_detached(),
            "the box refuses publishes while no spawn is attached"
        );

        // Second spawn, on a new lease: it starts with no runtime forward,
        // and publishes are accepted again.
        let second_tap = no_link();
        let guard = crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            second_tap,
            control.clone(),
            lease_at(SECOND_LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: Some(&reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        .expect("the second spawn attaches");
        let reattached = seen_so_far(&mut events_rx);
        assert!(
            !reattached
                .iter()
                .any(|(_, body)| body.contains(&format!("\"remote\":\"{FIRST_LEASE}:"))),
            "nothing delivers to the stale lease after the respawn: {reattached:?}"
        );
        assert!(
            runtime.snapshot().is_empty(),
            "the new spawn inherits no runtime forward"
        );
        assert!(
            !runtime.is_detached(),
            "the new spawn's attach accepts publishes again"
        );
        assert_eq!(
            scenario
                .registry
                .read()
                .expect("registry lock")
                .own_lease(boxes::SessionId::nil()),
            Some(SECOND_LEASE),
            "the registry's lease, which the next publish delivers to, is the new spawn's"
        );
        Box::new(guard).teardown().await;
        fake.abort();
    }

    /// NET-121's `local` is the box's handed host loopback address (T66):
    /// a box whose registration the VM host daemon completed hands its
    /// host loopback address in with the launch, and the attach's exposes
    /// name exactly that address and the declared port — never `127.0.0.1`,
    /// the node's shared interim a box without a handed address falls back
    /// to (NET-123), and never an address the daemon picked for itself.
    /// The same address comes off again at teardown: what was bound where
    /// it was named is unbound there too.
    ///
    /// The daemon's own registration is the in-guest zone only; host-OS
    /// name publication belongs to the host-side creator whose row handed
    /// the address in — and this proof's registry row stands for that row.
    #[tokio::test]
    async fn local_is_the_handed_loopback_address() {
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
        // The host loopback address the box's registration handed it — the
        // row's own slice of the reserved local range (T66).
        const HANDED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);

        let dir = tempfile::TempDir::new().unwrap();
        let scenario = attach_scenario(&dir, "gvproxy.sock");
        // The host-side registration's row: the box's own address, published
        // by the same stable id the reporter reads back — what `box_actor`'s
        // finalize does for a handed box, standing in for the host-side
        // creator that owns the row.
        scenario
            .registry
            .write()
            .expect("registry lock")
            .publish_own_address(
                boxes::SessionId::nil(),
                "web",
                HANDED,
                BTreeSet::from([8080u16, 9090]),
            );
        let (events_tx, mut events_rx) = mpsc::channel(64);
        let (handed_tx, _handed_rx) = mpsc::channel(4);
        let fake = spawn_control_channel_deciding(
            scenario.control_path.clone(),
            |_, _| ok(),
            events_tx,
            handed_tx,
        );
        let switch = vm_host_switch();
        let policy = declared_two_ports();

        let guard = match crate::net::gvproxy_network::complete_own_ip_attach(
            &switch,
            no_link(),
            ControlChannel::Unix(scenario.control_path.clone()),
            lease_at(LEASE),
            crate::net::gvproxy_network::AttachInputs {
                session_name: "web",
                policy: Some(&policy),
                own_address: Some(&scenario.reporter),
                engine_box: None,
                spawned: &sandbox::Spawned::new(),
            },
        )
        .await
        {
            Ok(guard) => guard,
            Err(e) => panic!("the attach completes at the handed address: {e}"),
        };
        let events = seen_so_far(&mut events_rx);

        // The binds name the handed address and the declared ports — never
        // `127.0.0.1`, and never a port number the daemon substituted.
        assert_eq!(
            locals_of(&events, "/services/forwarder/expose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "every bind names the handed loopback address: {events:?}"
        );

        // Teardown unbinds at the same address it bound: the handed
        // address is the forward's for its whole life, not just its bind.
        Box::new(guard).teardown().await;
        let unbound = collect_until(&mut events_rx, "/services/forwarder/unexpose", 2).await;
        assert_eq!(
            locals_of(&unbound, "/services/forwarder/unexpose"),
            vec![format!("{HANDED}:8080"), format!("{HANDED}:9090")],
            "teardown unbinds every forwarder at the handed address: {unbound:?}"
        );
        fake.abort();
    }
}
