//! The host-side table of every published namespace (NET-138) — the rows the
//! VM host daemon's egress gate decides by (NET-081).
//!
//! On a VM-backed host the guest cannot be trusted to say what its boxes may
//! reach: the in-VM daemon is *inside* the escape boundary, and a process
//! that breaks out of a box into the VM controls it. The per-box,
//! source-addressed egress rules NET-081 asks for therefore live **outside**
//! the VM, in `minvmd`, applied by [`crate::net::egress_gate`] between the
//! guest's shuttle and the switch socket. This module is the table that gate
//! reads: one row per published namespace, holding its name, its addresses on
//! the switch and on the loopback, the ports it admitted, the names it
//! declared, and its compiled [`EgressRules`] — the rules the gate decides
//! every frame by, the same set the in-guest relay applies, now held where
//! nothing inside the VM can change it. The publish half of the gate
//! (NET-081's control verbs) reads the row's ports and names as the records
//! it will admit a switch publish for; the frame half reads the rules alone.
//!
//! The trust boundary is the type boundary. Rows are filled **in this
//! process**, from the host side — the host's own derivation of the guest
//! node's namespace ([`BoxRegistry::register_node_namespace`]), and the
//! client's box declarations carried over the host's control path — and never
//! from anything the guest says. The gate is handed a [`BoxTable`], the
//! read-only view whose only row operations are lookups, so the one component
//! that reads guest frames cannot add, replace, or withdraw a row. The
//! registration path that carries a client's box declarations into this
//! registry is [`crate::control`] — the host daemon's control socket, over
//! which the activating client registers a box and reads the addresses the
//! allocation hands back.
//!
//! This registry is also the proxy's attachment source (NET-133): when the
//! host hands it the attachment table
//! ([`BoxRegistry::feeding_proxy_attachments`]), every box row it publishes
//! is an attachment issued ahead of the row and every retirement takes the
//! attachment with it — the same host-side facts, the same trust boundary,
//! the one writer.
//!
//! One dimension of a row is filled from the in-VM daemon's own reports —
//! the **runtime-admitted ports** (NET-138's sanctioned exception, NET-045's
//! decisions), reported over the daemon's control channel and recorded only
//! inside the grant the row's host-side registration holds: the box's
//! dynamic-ingress stance, its allowed range, the per-row cap, and the
//! per-row admit rate ([`BoxRegistry::admit_runtime_port`]). Everything the
//! guest says still passes that check; a row's other facts stay host-sourced
//! alone.
//!
//! A row's liveness is read at the host's end of the box's attachment
//! (NET-138): a relay that carries a box's frames holds its row attached,
//! and the end of the last such relay marks the row **detached** rather than
//! withdrawing it at once. A detached row decides frames exactly as before;
//! it is withdrawn once [`DETACH_GRACE`] passes with no relay carrying it
//! again, so a box whose shuttle reconnects keeps its row. The client boxes'
//! registrations — the creator's declarations, never anything the guest said
//! — are persisted in this daemon's state dir ([`BoxRegistry::persisting_to`])
//! and reloaded under the resume bound at start — a VM's cold boot
//! outlasts the detach grace — and a creator whose box outlived its row
//! asks for the row back from that persisted record
//! ([`BoxRegistry::resume_client_box`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::Ipv4Addr;
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use boxes::core::zone_answer;
use boxes::{DynamicIngress, IpProto};
use switch::SwitchSubnet;

use crate::bep_attach::BoxId;

/// The per-row cap on runtime-admitted ports (NET-138): the row's
/// runtime-published set answers to this bound, so a report storm cannot
/// grow a row without limit — the cap is the row-state half of the grant,
/// beside the stance and range the declaration carries. An admit report a
/// row at its cap receives is refused when it names a new port; a re-admit
/// of a port the row already holds is answered as recorded and changes
/// nothing, so a client that retries a lost reply never draws a refusal for
/// a port the host holds.
pub(crate) const RUNTIME_PORT_CAP: usize = 256;

/// The per-row admit rate (NET-138): at most this many admit reports are
/// recorded per trailing second. The rate bounds the *reports*, not the
/// ports (the cap bounds the ports): a box that churns its mappings faster
/// than this is a loop, and a loop must not hold the serving thread. Only
/// reports that pass every grant check and record a new port count toward
/// it — a refusal records nothing and paces nothing, a re-admit of a held
/// port changes nothing and is not counted, and a withdrawal never counts.
pub(crate) const ROW_ADMIT_RATE_PER_SECOND: usize = 10;

/// The window the admit rate is measured over, matching
/// [`ROW_ADMIT_RATE_PER_SECOND`] one trailing second.
const ADMIT_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// The file the registry persists its client boxes' registrations to, in
/// the VM host daemon's state dir ([`BoxRegistry::persisting_to`]).
pub const REGISTRY_FILE: &str = "box-registry.json";

/// The persisted registry's format version. A file of any other version is
/// not read: its rows are not reloaded, which leaves those boxes rowless —
/// the fail-closed reading of a file this build cannot vouch for.
const REGISTRY_FILE_VERSION: u32 = 2;

/// The file the registry persists its held box names to
/// ([`BoxRegistry::hold_box_name`]), beside [`REGISTRY_FILE`]. A file of
/// its own, so the registry file stays the format a daemon that predates
/// held-name persistence reads ([`RegistryFile`] denies unknown fields),
/// and a held-names file this build cannot use costs the holds alone,
/// never a creation.
pub const HELD_NAMES_FILE: &str = "box-held-names.json";

/// The persisted held names' format version. A file of any other version
/// is set aside and reloads no hold, like one that does not parse.
const HELD_NAMES_FILE_VERSION: u32 = 1;

/// The file the registry persists its minted `host_ip` box ids to, beside
/// [`REGISTRY_FILE`]: every id it minted, and the ones admitted with a
/// credentialed lane ([`HostIpIds`]). A file of its own, for the same
/// reason as [`HELD_NAMES_FILE`]. A restart then still holds each id for
/// the collision check, and still revokes a grant box's id at its destroy
/// (BEP-043).
pub const HOST_IP_IDS_FILE: &str = "box-host-ip-ids.json";

/// The persisted `host_ip` ids' format version. A file of any other
/// version is set aside and reloads no id, like one that does not parse.
const HOST_IP_IDS_FILE_VERSION: u32 = 1;

/// How long a hold reloaded from [`HELD_NAMES_FILE`] stands unconfirmed
/// before it is dropped ([`BoxRegistry::expire_unconfirmed_holds`]). Only
/// a host client re-makes a hold, over the host's control socket: the
/// creating client's attach or exec re-sends its session's own. The
/// in-VM daemon cannot, because the hold verbs are not served on its
/// door, so the expiry is the one thing that clears a hold whose session
/// ended with no release from the host, and dropping it gives the name
/// back to NXDOMAIN (NET-012). It also drops the hold of a live session
/// that nobody attaches to or execs into within the bound; that
/// session's next attach or exec makes the hold again. The bound is
/// long enough for a client that follows a restart with an attach to get
/// there through a slow boot.
pub const HELD_NAME_RECONFIRM_BOUND: Duration = Duration::from_secs(300);

/// How long a `host_ip` registration name stands while no box is admitted
/// under its id ([`BoxRegistry::register_host_ip_box`]). A `host_ip`
/// registration holds no connection, so a creator that dies between its
/// register and its box's admission leaves the name with nothing to
/// withdraw it. Past this bound a new registration under the name takes it.
/// The in-VM create and the admission that follows it come inside one slow
/// boot, which this bound covers.
pub const HOST_IP_UNADMITTED_NAME_BOUND: Duration = Duration::from_secs(300);

/// The subscribers to row withdrawals: one sender per subscriber, each told
/// of every row the registry removes ([`RowWithdrawal`]). Shared by the
/// registry and every [`BoxTable`] it hands out.
type RowWithdrawals = Arc<Mutex<Vec<std::sync::mpsc::Sender<RowWithdrawal>>>>;

/// How long a client-driven registration waits for a withdrawn box's
/// revocation to release the addresses it asks for, before it is refused
/// with [`AllocationError::RevocationPending`]. A revocation that goes well
/// holds an address for one unexpose per forward, which takes milliseconds.
/// The bound is for a switch that is slow to answer, and it keeps a control
/// connection's thread from waiting on a switch that never answers.
pub const REVOCATION_WAIT: Duration = Duration::from_secs(5);

/// The addresses a withdrawn box's revocation still holds against reuse
/// (design §7.1): the switch address its forwards dial and the published
/// loopback address they listen on. Each is held from the row's withdrawal
/// until every subscriber is done with it. No row is registered at a held
/// address ([`BoxRegistry::try_register`]), so the forwards a revocation
/// unbinds, and the connections it ends, are always the withdrawn box's. A
/// new box at the same address can neither receive the old box's forwarded
/// connections nor have its own forwards unbound by the old box's end.
///
/// The holds are counted, because two of them may name one address.
#[derive(Debug, Default)]
struct Revoking {
    held: Mutex<BTreeMap<[u8; 4], usize>>,
    /// Signalled whenever a hold is released, for the registrations that
    /// wait on one ([`Revoking::wait_released`]).
    released: Condvar,
}

impl Revoking {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<[u8; 4], usize>> {
        self.held
            .lock()
            .expect("the revocation holds' lock is held only across a map update")
    }

    /// The first of `addrs` a revocation still holds, when one does.
    fn first_held(&self, addrs: &[[u8; 4]]) -> Option<[u8; 4]> {
        let held = self.lock();
        addrs.iter().find(|addr| held.contains_key(*addr)).copied()
    }

    fn hold(&self, addrs: &[[u8; 4]]) {
        let mut held = self.lock();
        for addr in addrs {
            *held.entry(*addr).or_default() += 1;
        }
    }

    fn release(&self, addrs: &[[u8; 4]]) {
        let mut held = self.lock();
        for addr in addrs {
            if let Some(count) = held.get_mut(addr) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(addr);
                }
            }
        }
        drop(held);
        self.released.notify_all();
    }

    /// Waits up to `bound` for every one of `addrs` to be released. Returns
    /// the first address still held at the bound, or `None` once none is.
    fn wait_released(&self, addrs: &[[u8; 4]], bound: Duration) -> Option<[u8; 4]> {
        let deadline = Instant::now() + bound;
        let mut held = self.lock();
        loop {
            let still = addrs
                .iter()
                .find(|addr| held.contains_key(*addr))
                .copied()?;
            let now = Instant::now();
            if now >= deadline {
                return Some(still);
            }
            held = self
                .released
                .wait_timeout(held, deadline - now)
                .expect("the revocation holds' lock is held only across a map update")
                .0;
        }
    }
}

/// The addresses a row's revocation holds: its switch address, and its
/// published loopback address when that is one of the reserved range's
/// per-box addresses. The shared `127.0.0.1` is never held: every
/// host-address namespace publishes there, so it is no one box's to hold.
fn revocation_addrs(switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> Vec<[u8; 4]> {
    let mut addrs = vec![switch_addr.octets()];
    if in_reserved_local_range(loopback_addr) {
        addrs.push(loopback_addr.octets());
    }
    addrs
}

/// One withdrawn row, as a row-withdrawal subscriber receives it
/// ([`BoxTable::subscribe_row_withdrawals`]). It holds the row's addresses
/// against reuse for as long as any subscriber keeps a copy: a registration
/// at one of them is refused until every copy is dropped. The egress gate
/// keeps its copy until it has unbound the box's forwards, so no new box is
/// registered at an address an old box's forward still dials or listens on.
#[derive(Debug, Clone)]
pub struct RowWithdrawal {
    switch_addr: Ipv4Addr,
    box_id: BoxId,
    hold: Arc<RevocationHold>,
}

impl RowWithdrawal {
    /// The withdrawn row's switch address: the address its forwards dial.
    #[must_use]
    pub fn switch_addr(&self) -> Ipv4Addr {
        self.switch_addr
    }

    /// The addresses this withdrawal holds against reuse.
    /// The id of the box whose row was withdrawn.
    #[must_use]
    pub fn box_id(&self) -> BoxId {
        self.box_id
    }

    #[must_use]
    pub fn held_addrs(&self) -> &[[u8; 4]] {
        &self.hold.addrs
    }
}

/// The hold a [`RowWithdrawal`]'s copies share, released when the last copy
/// drops.
#[derive(Debug)]
struct RevocationHold {
    addrs: Vec<[u8; 4]>,
    revoking: Arc<Revoking>,
}

impl Drop for RevocationHold {
    fn drop(&mut self) {
        self.revoking.release(&self.addrs);
    }
}

/// The guest node namespace's name in the table: the in-VM daemon, whose own
/// root-netns tap [`BoxRegistry::register_node_namespace`] publishes. Read
/// from the sessions zone so the registry and the store's reserved names
/// spell the one label the zone defines.
const NODE_NAMESPACE: &str = zone_answer::NODE_ROW_LABEL;

/// The node namespace's row's name under the zone, as
/// [`BoxRegistry::zone_view`] holds it: `minimald.min.internal`, the same
/// name every VM host daemon's table holds its own node's row under. The
/// row never travels the answerer channel (`net::answerer::zone_rows`
/// excludes it): one name for every VM means a second VM's registration of
/// it is refused by the holder's first-writer rule by construction — a
/// standing clash-warn for the normal multi-VM case — so the holder's own
/// node row is the one the zone answers host-side, and inside the guest
/// the node's DNS layer keeps answering the name for its own VM.
#[must_use]
pub fn node_zone_name() -> String {
    zone_name(NODE_NAMESPACE)
}

/// The published rows, keyed by switch address in wire octets — the key the
/// gate's per-frame lookup uses, straight off the frame summary. A `BTreeMap`
/// because the row set's order escapes to diagnostics and to
/// [`BoxTable::rows`], and the same declarations must produce the same order
/// every time (a hash map's would vary run to run).
type Rows = BTreeMap<[u8; 4], Arc<BoxRecord>>;

/// One published namespace: a box the host knows, with the addresses the
/// host handed it and what its creator registered for it.
///
/// A row holds what the host decides by: which host ports may be forwarded
/// to the box, and whether the box may use the credential proxy. It holds no
/// egress rules. What a box may reach is decided in the VM.
#[derive(Debug)]
pub struct BoxRecord {
    /// The box's name. A rename changes it in place.
    name: RwLock<Arc<str>>,
    /// The box's id, minted on the host at registration.
    box_id: BoxId,
    /// The box's address on the virtual network.
    switch_addr: Ipv4Addr,
    /// The box's published address on the host's loopback.
    loopback_addr: Ipv4Addr,
    /// The external ports the box declared.
    admitted_ports: Vec<u16>,
    /// Further names the row may answer under.
    declared_names: Vec<String>,
    /// Whether the box was created with a credentialed upstream.
    credentialed_upstream: bool,
    /// The box's dynamic ingress stance and range.
    dynamic_ingress: DynamicIngress,
    dynamic_range: Option<(u16, u16)>,
    /// The ports published at run time under that grant.
    runtime_ports: Mutex<RowRuntime>,
    /// Whether the in-VM daemon referred to this box. From then on the box
    /// may have run at its addresses, so they are quarantined when they are
    /// returned. A row whose box never started returns them at once.
    used: std::sync::atomic::AtomicBool,
    /// The box row a task row belongs to. A task row is one of its box's
    /// task addresses, kept out of the hand-out book while the box stands.
    /// `None` for a box's own row.
    task_row_of: Option<Ipv4Addr>,
    /// The task addresses filed with this box. Empty for a task row.
    task_addrs: Vec<Ipv4Addr>,
}

impl PartialEq for BoxRecord {
    fn eq(&self, other: &Self) -> bool {
        if !(self.name() == other.name()
            && self.box_id == other.box_id
            && self.switch_addr == other.switch_addr
            && self.loopback_addr == other.loopback_addr
            && self.admitted_ports == other.admitted_ports
            && self.declared_names == other.declared_names
            && self.credentialed_upstream == other.credentialed_upstream
            && self.dynamic_ingress == other.dynamic_ingress
            && self.dynamic_range == other.dynamic_range
            && self.task_row_of == other.task_row_of
            && self.task_addrs == other.task_addrs)
        {
            return false;
        }
        let own_ports = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ports
            .clone();
        let other_ports = other
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ports
            .clone();
        own_ports == other_ports
    }
}

impl Eq for BoxRecord {}

/// A row's mutable runtime half: the ports the in-VM daemon's admit reports
/// recorded — each the port and protocol pair the report named, so one port
/// number published under two protocols is two admissions, not one — and
/// the timestamps of the admits the trailing-second rate is measured by.
/// Guarded by its own mutex, never the row lock: the ports change with the
/// box's runtime publications, while every other row dimension is
/// registration-frozen.
#[derive(Debug, Default, PartialEq, Eq)]
struct RowRuntime {
    ports: Vec<RuntimePort>,
    admits: VecDeque<Instant>,
}

/// One runtime-admitted port: the port number and the protocol it was
/// published under — the pair a report names and a withdrawal removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimePort {
    port: u16,
    proto: IpProto,
}

impl BoxRecord {
    /// The namespace's name — what a diagnostic names a row by. The name
    /// as it is now: a rename re-keys it in place ([`Self::rename`]).
    #[must_use]
    pub fn name(&self) -> Arc<str> {
        Arc::clone(
            &self
                .name
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Re-keys the row to `name` (#1116). Only the registry's rename
    /// calls this, under the write of the row lock that checked the name
    /// is free.
    fn rename(&self, name: &str) {
        *self
            .name
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::from(name);
    }

    /// The switch address of the box row this is a task row of, or `None`
    /// for a box's own row ([`BoxRecord`]'s task rows, NET-138).
    /// Whether the in-VM daemon referred to this box ([`Self::mark_used`]).
    #[must_use]
    pub fn was_used(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    /// Records that the in-VM daemon referred to this box: it asked whether
    /// the row stands, published for it, or opened a stream for it.
    pub fn mark_used(&self) {
        self.used.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn task_row_of(&self) -> Option<Ipv4Addr> {
        self.task_row_of
    }

    /// Whether this is a task row: one filed with a box at one of its task
    /// addresses, rather than the box's own row.
    #[must_use]
    pub fn is_task_row(&self) -> bool {
        self.task_row_of.is_some()
    }

    /// The task addresses filed with this box, in the order they were
    /// drawn: each the key of a task row of this box's.
    #[must_use]
    pub fn task_addrs(&self) -> &[Ipv4Addr] {
        &self.task_addrs
    }

    /// The addresses this row's withdrawal holds against reuse: its switch
    /// address, and its box's published loopback address for a box's own
    /// row. A task row publishes nothing at the loopback, which its box's
    /// row holds.
    fn revocation_addrs(&self) -> Vec<[u8; 4]> {
        if self.is_task_row() {
            vec![self.switch_addr.octets()]
        } else {
            revocation_addrs(self.switch_addr, self.loopback_addr)
        }
    }

    /// The box's own id (BEP-070): minted once for this creation — by
    /// the registration that published the row, or taken from the id a
    /// re-registration presented — with its random bytes from the host's
    /// OS CSPRNG. Unique per creation, so a box recreated with the same
    /// name and addresses carries a different id, and the id never
    /// returns to use: a revocation scoped to it stays scoped forever.
    /// This is what the proxy's attachment names the box by and a
    /// delivered connection's header carries (NET-133).
    #[must_use]
    pub fn box_id(&self) -> BoxId {
        self.box_id
    }

    /// The namespace's address on the switch: the lease its frames must carry
    /// (NET-084) and the key the gate resolves a frame's source through.
    #[must_use]
    pub fn switch_addr(&self) -> Ipv4Addr {
        self.switch_addr
    }

    /// The namespace's address on the guest's loopback.
    #[must_use]
    pub fn loopback_addr(&self) -> Ipv4Addr {
        self.loopback_addr
    }

    /// The ports this namespace admitted, in the order the declaration
    /// carried them.
    ///
    /// Two readings, both of them the declaration's own and neither one the
    /// frame verdict's:
    ///
    /// * An **ingress** dimension — what may be sent *to* this namespace,
    ///   which the host attaches it by on the registration path (T66's
    ///   client-driven one, the same path that fills this table). The frame
    ///   verdict reads [`Self::egress`] alone and never this.
    /// * The **publish** dimension — the ports a switch publish at this
    ///   namespace's address may name: the host-side listener a forwarder
    ///   binds, the end the registration wire carries. A mapping's inside
    ///   end is not a record of the publish — it is the port the forwarder
    ///   dials on the target, governed by the target's own ingress
    ///   declaration inside the VM, which no row here is compiled from. The
    ///   gate's publish decision (NET-081's control verbs) reads this and
    ///   [`Self::declared_names`] as the records it admits a publish by;
    ///   nothing outside the declaration is publishable, so a row that names
    ///   no ports publishes none.
    ///
    /// It is carried in the row because NET-138's row holds a namespace's
    /// whole declaration, where both the attaching side and the publish
    /// decision reach it without a second table.
    #[must_use]
    pub fn admitted_ports(&self) -> &[u16] {
        &self.admitted_ports
    }

    /// The zone names this namespace declared, in the order the declaration
    /// carried them — the publish dimension's name half: the records a
    /// `dns/add` at this namespace's address may carry. A row that names none
    /// publishes none.
    #[must_use]
    pub fn declared_names(&self) -> &[String] {
        &self.declared_names
    }

    /// Whether this box's declaration named a credentialed upstream
    /// (NET-134): `true` marks the Box Egress Proxy's listener as this
    /// box's infrastructure — the one destination its compiled frame rules
    /// never decide, because the credentials the proxy redeems are the
    /// lane's own and no egress rule of the box's says anything about them.
    /// `false`, the absent declaration, is no lane: the proxy's address
    /// stays under the box-to-host default-deny like any other host-side
    /// destination, whatever the box's rules would allow.
    ///
    /// The gate reads this beside the row's rules ([`crate::net::egress_gate`]),
    /// never through them: the declaration is a fact about the box, reduced
    /// from the session policy's own field at registration — nothing the
    /// guest says can add a lane to a row behind the gate's back.
    #[must_use]
    pub fn declares_credentialed_upstream(&self) -> bool {
        self.credentialed_upstream
    }

    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant a runtime port report is checked against ([`Self::admit` is
    /// not this — that is the registry's]). `allow` and `ask` are the two
    /// stances that can record a report in range; `deny`, the default,
    /// admits none.
    #[must_use]
    pub fn dynamic_ingress(&self) -> DynamicIngress {
        self.dynamic_ingress
    }

    /// The range the stance admits runtime ports in, inclusive at both
    /// ends — the grant's range half. `None` permits nothing even under an
    /// `allow` stance.
    #[must_use]
    pub fn dynamic_range(&self) -> Option<(u16, u16)> {
        self.dynamic_range
    }

    /// The row's runtime-admitted port numbers recorded under `proto`, in
    /// report order: the runtime half of the set the gate admits the box's
    /// publications in that protocol by — the declared half is
    /// [`Self::admitted_ports`]. Keyed on the (port, protocol) pair the
    /// report named, so a port admitted for udp never admits its tcp twin.
    #[must_use]
    pub fn runtime_port_numbers_in(&self, proto: IpProto) -> Vec<u16> {
        let runtime = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime
            .ports
            .iter()
            .filter(|reported| reported.proto == proto)
            .map(|reported| reported.port)
            .collect()
    }

    /// The row's runtime-admitted ports, distinct port numbers in report
    /// order, across both protocols: the read-only row verb's answer's
    /// runtime dimension. The gate decides by the protocol-keyed half
    /// ([`Self::runtime_port_numbers_in`]). Reported by the in-VM daemon
    /// within the grant the registration holds
    /// ([`BoxRegistry::admit_runtime_port`]), removed by its withdrawal
    /// reports, and gone with the row itself when the row is withdrawn.
    #[must_use]
    pub fn runtime_port_numbers(&self) -> Vec<u16> {
        let runtime = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen = Vec::new();
        for port in runtime.ports.iter().map(|reported| reported.port) {
            if !seen.contains(&port) {
                seen.push(port);
            }
        }
        seen
    }
}

/// A namespace's declaration as it arrives on the host, before any frame
/// exists: the facts a row is compiled from. Builder-shaped (the crate's
/// `VmEgressPolicy` style) because the addresses alone make a namespace and
/// everything else is optional.
#[derive(Debug, Clone)]
pub struct BoxRegistration {
    name: String,
    box_id: Option<BoxId>,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    credentialed_upstream: Option<boxes::CredentialedUpstream>,
    dynamic_ingress: Option<DynamicIngress>,
    dynamic_allowed_range: Option<(u16, u16)>,
    task_addrs: Vec<Ipv4Addr>,
}

impl BoxRegistration {
    /// A declaration for the namespace `name`, addressed at `switch_addr` on
    /// the switch and `loopback_addr` on the guest's loopback. The egress
    /// policy is absent (allow-all, the shipped default) until
    /// [`with_egress_policy`](Self::with_egress_policy) declares one, and
    /// the box's id is minted at registration
    /// ([`crate::bep_attach::mint_box_id`]).
    #[must_use]
    pub fn new(name: impl Into<String>, switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> Self {
        Self {
            name: name.into(),
            box_id: None,
            switch_addr,
            loopback_addr,
            admitted_ports: Vec::new(),
            declared_names: Vec::new(),
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
            task_addrs: Vec::new(),
        }
    }

    /// The task addresses filed with the box (NET-138): one task row each,
    /// published and withdrawn with the box's own row.
    #[must_use]
    pub fn with_task_addresses(mut self, addrs: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        self.task_addrs = addrs.into_iter().collect();
        self
    }

    /// The ports this namespace admitted — the ingress **and** publish
    /// dimensions [`BoxRecord::admitted_ports`] documents, not a dimension
    /// the gate's frame verdict reads.
    #[must_use]
    pub fn with_admitted_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.admitted_ports = ports.into_iter().collect();
        self
    }

    /// The zone names this namespace declared — the name half of the publish
    /// dimension [`BoxRecord::declared_names`] documents. Names are matched
    /// exactly, as the client's own client spells them.
    #[must_use]
    pub fn with_declared_names(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.declared_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// The namespace's declaration of a credentialed upstream (NET-134):
    /// `Some` marks the Box Egress Proxy's listener as this box's
    /// infrastructure, so the gate admits its address beside — never
    /// through — whatever egress rules the declaration also carries. The
    /// declaration is reduced to a lane in the row; its own content is the
    /// proxy document's to extend, so nothing of it is retained here.
    #[must_use]
    pub fn with_credentialed_upstream(mut self, declaration: boxes::CredentialedUpstream) -> Self {
        self.credentialed_upstream = Some(declaration);
        self
    }

    /// The box's dynamic-ingress grant (NET-045, NET-138): the stance and
    /// the range a runtime port report is checked against — the row's own
    /// copy of the same create inputs the session record holds, carried at
    /// registration so the host decides every report against a fact the
    /// guest cannot change. `None` for the stance is the declaration's
    /// `deny` default; `None` for the range permits nothing under any
    /// stance.
    #[must_use]
    pub fn with_dynamic_ingress(
        mut self,
        stance: DynamicIngress,
        range: Option<(u16, u16)>,
    ) -> Self {
        self.dynamic_ingress = Some(stance);
        self.dynamic_allowed_range = range;
        self
    }
}

/// A box declaration as the activating client carries it over the host's
/// control socket: the facts a row is compiled from, without the addresses —
/// a client-driven registration allocates those on the host, from the
/// address plan this registry's switch serves, and hands them back with the
/// row ([`BoxRegistry::register_client_box`]).
#[derive(Debug, Clone)]
pub struct ClientBoxSpec {
    /// The box's name: what the row is named by, and the name the create
    /// request will carry — a box's id on the host is its name.
    pub name: String,
    /// The external ports the box's ingress rules admit, as the client
    /// expanded them.
    pub ingress_ports: Vec<u16>,
    /// The box's declaration of a credentialed upstream (NET-134), carried
    /// from the session's policy: `Some` makes the Box Egress Proxy's
    /// listener this box's infrastructure — reachable whatever the egress
    /// rules say — while `None` is no lane, and the proxy's address stays
    /// refused under the box-to-host default-deny. The one field a client
    /// that predates NET-134 sends absent, every time.
    pub credentialed_upstream: Option<boxes::CredentialedUpstream>,
    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant the row holds a runtime port report against. `None` is the
    /// declaration's `deny` default — a client that predates the grant
    /// fields registers a row that admits no runtime port, exactly as one
    /// whose declaration said `deny` does.
    pub dynamic_ingress: Option<DynamicIngress>,
    /// The range the stance admits runtime ports in, inclusive at both
    /// ends. `None` permits nothing even under an `allow` stance.
    pub dynamic_allowed_range: Option<(u16, u16)>,
}

/// One client box's creation as the registry keeps it past its row and
/// persists it ([`BoxRegistry::persisting_to`]): the declaration its
/// creator registered — never a fact the guest reported (NET-138) — with
/// the addresses and the box id the registration handed back, and whether
/// a row stands for it. A creation lives from its registration until its
/// creator withdraws the box ([`BoxRegistry::withdraw_client_box`]) or a
/// new registration takes its name; a row withdrawn at the end of its
/// detach grace or its resume bound leaves the creation **dormant**
/// (`standing: false`) for its creator to resume
/// ([`BoxRegistry::resume_client_box`]). A new registration under a
/// dormant creation's name takes the name (BOX-004) and leaves the dormant
/// creation **superseded** ([`Creations`]): still kept, still resumable by
/// its box id once no live row holds the name. A creation, standing or dormant,
/// keeps its addresses reserved: its switch and task addresses stay out of
/// the hand-out book — taken again from a fresh book at reload — and its
/// published loopback address stays the answerer's
/// link for its name, so a resume finds every address its box was created
/// with. Its creator's withdrawal releases them all. At most one creation
/// per box name is the name's own; the others under it are superseded.
///
/// The file format: one JSON object per creation in
/// [`RegistryFile::boxes`], its fields named as here.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    name: String,
    box_id: minimald_rpc::BoxId,
    switch_address: Ipv4Addr,
    loopback_address: Ipv4Addr,
    ingress_ports: Vec<u16>,
    credentialed_upstream: Option<boxes::CredentialedUpstream>,
    dynamic_ingress: Option<DynamicIngress>,
    dynamic_allowed_range: Option<(u16, u16)>,
    /// The task addresses filed with the box (NET-138), persisted with it
    /// so a reload and a resume restore its task rows with its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    task_addresses: Vec<Ipv4Addr>,
    /// Whether a row stands for the creation. Not persisted: every creation
    /// loads dormant.
    #[serde(skip)]
    standing: bool,
}

impl Creation {
    fn new(
        spec: &ClientBoxSpec,
        switch_address: Ipv4Addr,
        loopback_address: Ipv4Addr,
        task_addresses: Vec<Ipv4Addr>,
        id: BoxId,
    ) -> Self {
        Self {
            name: spec.name.clone(),
            box_id: minimald_rpc::BoxId::from_bytes(id),
            switch_address,
            loopback_address,
            ingress_ports: spec.ingress_ports.clone(),
            credentialed_upstream: spec.credentialed_upstream.clone(),
            dynamic_ingress: spec.dynamic_ingress,
            dynamic_allowed_range: spec.dynamic_allowed_range,
            task_addresses,
            standing: true,
        }
    }

    fn id(&self) -> BoxId {
        self.box_id.to_bytes()
    }

    /// The declaration the creation was registered from, for the same
    /// compile a registration runs ([`BoxRegistry::client_registration`]).
    fn spec(&self) -> ClientBoxSpec {
        ClientBoxSpec {
            name: self.name.clone(),
            ingress_ports: self.ingress_ports.clone(),
            credentialed_upstream: self.credentialed_upstream.clone(),
            dynamic_ingress: self.dynamic_ingress,
            dynamic_allowed_range: self.dynamic_allowed_range,
        }
    }
}

/// The client boxes' creations ([`Creation`]) a registry keeps. Each name
/// has at most one creation of its own, keyed by the name's
/// [`canonical_box_name`] form: the map this derefs to. `superseded`
/// holds the dormant creations whose name a newer registration took
/// (BOX-004). Each keeps its addresses and its box id, so its creator can
/// resume it by that id once no live row holds the name, or withdraw it.
#[derive(Debug, Default)]
struct Creations {
    by_name: BTreeMap<String, Creation>,
    superseded: Vec<Creation>,
}

impl Creations {
    /// Every kept creation: each name's own, then the superseded ones.
    fn all(&self) -> impl Iterator<Item = &Creation> {
        self.by_name.values().chain(self.superseded.iter())
    }

    /// Whether any kept creation, superseded ones included, is under the
    /// name whose canonical form is `key`.
    fn holds_name(&self, key: &str) -> bool {
        self.by_name.contains_key(key)
            || self
                .superseded
                .iter()
                .any(|creation| canonical_box_name(&creation.name) == key)
    }
}

impl std::ops::Deref for Creations {
    type Target = BTreeMap<String, Creation>;

    fn deref(&self) -> &Self::Target {
        &self.by_name
    }
}

impl std::ops::DerefMut for Creations {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.by_name
    }
}

/// The persisted registry ([`REGISTRY_FILE`]): its format version, then
/// every creation the registry keeps, superseded ones included.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u32,
    boxes: Vec<Creation>,
}

/// The persisted held box names ([`HELD_NAMES_FILE`]): its format
/// version, then every held name mapped to the session that holds it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldNamesFile {
    version: u32,
    held_names: BTreeMap<String, Option<boxes::SessionId>>,
}

/// The persisted `host_ip` box ids ([`HOST_IP_IDS_FILE`]): its format
/// version, every id the registry minted, and the minted ids admitted with
/// a credentialed lane.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostIpIdsFile {
    version: u32,
    ids: Vec<boxes::BoxId>,
    credentialed: Vec<boxes::BoxId>,
}

/// Writes `file` to `path` the one way any of the registry's persisted
/// files — the box registry ([`REGISTRY_FILE`]), its held names
/// ([`HELD_NAMES_FILE`]) and its `host_ip` ids ([`HOST_IP_IDS_FILE`]) — is
/// ever written: to a sibling temporary file
/// created afresh with mode 0600 — what they hold names this user's boxes
/// and sessions, which is no other user's to read — synced, then renamed
/// over `path`, and the directory synced, so a crash at any point leaves
/// either the old file or the new one, whole, and never a partial one.
fn write_registry_file(
    path: &std::path::Path,
    file: &impl serde::Serialize,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes = serde_json_lenient::to_vec_pretty(file).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    {
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        out.write_all(&bytes)?;
        out.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Reads the creations persisted at `path`: none when there is no file
/// yet. A file that cannot be read, does not parse, or is of another
/// version than [`REGISTRY_FILE_VERSION`] reloads no row — its boxes are
/// unregistered sources the gate drops (NET-085): fail-closed — and is set
/// aside ([`set_aside_registry_file`]) rather than written over, said as an
/// error line, so the creations it may still hold are there to recover.
/// `None` when it could not be set aside: the caller then persists
/// nothing, since the first write would replace it.
fn read_registry_file(path: &std::path::Path) -> Option<Vec<Creation>> {
    #[derive(serde::Deserialize)]
    struct Version {
        version: u32,
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(error) => return set_aside_registry_file(path, &error.to_string()),
    };
    match serde_json_lenient::from_slice::<Version>(&bytes) {
        Ok(Version { version }) if version == REGISTRY_FILE_VERSION => {}
        Ok(Version { version }) => {
            return set_aside_registry_file(
                path,
                &format!("version {version}, this build reads {REGISTRY_FILE_VERSION}"),
            );
        }
        Err(error) => return set_aside_registry_file(path, &error.to_string()),
    }
    match serde_json_lenient::from_slice::<RegistryFile>(&bytes) {
        Ok(file) => Some(file.boxes),
        Err(error) => set_aside_registry_file(path, &error.to_string()),
    }
}

/// One box a VM's persisted registry ([`REGISTRY_FILE`]) holds: its name
/// and its box id, as [`persisted_box_names`] reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedBox {
    /// The box's name, as its creator registered it.
    pub name: String,
    /// The box's id.
    pub id: minimald_rpc::BoxId,
}

/// Reads the boxes a VM's state dir `state_dir` holds in its persisted
/// registry ([`REGISTRY_FILE`]), each one's name and id, with no daemon
/// running: what the CLI reads for a stopped VM (NET-148, NET-152).
///
/// Read-only, unlike [`read_registry_file`]: a file that is missing, that
/// cannot be read, that does not parse, or that is of another version than
/// [`REGISTRY_FILE_VERSION`] reads as no boxes, and it is never written,
/// renamed or set aside. The daemon that owns the file decides what to do
/// with it on its next start. Each box id is listed once, in file order.
#[must_use]
pub fn persisted_box_names(state_dir: &std::path::Path) -> Vec<PersistedBox> {
    #[derive(serde::Deserialize)]
    struct Version {
        version: u32,
    }
    let path = state_dir.join(REGISTRY_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    match serde_json_lenient::from_slice::<Version>(&bytes) {
        Ok(Version { version }) if version == REGISTRY_FILE_VERSION => {}
        _ => return Vec::new(),
    }
    let Ok(file) = serde_json_lenient::from_slice::<RegistryFile>(&bytes) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    file.boxes
        .into_iter()
        .filter(|creation| seen.insert(creation.box_id))
        .map(|creation| PersistedBox {
            name: creation.name,
            id: creation.box_id,
        })
        .collect()
}

/// Renames the unusable registry file at `path` aside, to the same name
/// with an `.unusable-<unix seconds>` suffix, and says so as an error line
/// naming `why`. Returns no creations when it is set aside, and `None` —
/// persistence off for this process, said as a second error line — when
/// the rename fails.
fn set_aside_registry_file(path: &std::path::Path, why: &str) -> Option<Vec<Creation>> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unusable-{stamp}"));
    let aside = std::path::PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => {
            tracing::error!(
                path = %path.display(),
                aside = %aside.display(),
                why,
                "the persisted box registry is unusable; it is set aside and no rows are reloaded"
            );
            Some(Vec::new())
        }
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                why,
                %error,
                "the persisted box registry is unusable and could not be set aside; \
                 no rows are reloaded and none are persisted by this process"
            );
            None
        }
    }
}

/// Reads the held box names persisted at `path`, each keyed by its
/// [`canonical_box_name`] form whatever spelling the file holds it under:
/// none when there is no file yet. Two spellings that fold to one name
/// reload as one hold: the spelling that sorts first by its bytes
/// (`WEB` before `web`), because the file's names parse into a sorted
/// map and the file's own order is lost. The other is said as a warn
/// line and dropped. A file that cannot be read, does not
/// parse, or is of another version than [`HELD_NAMES_FILE_VERSION`]
/// reloads no hold and is renamed aside under the same `.unusable-<unix
/// seconds>` suffix as an unusable registry file, said as an error line;
/// a rename that fails is a second error line, and the next hold writes
/// over it — the holds are an interim every session's attach re-makes,
/// never a record a resume is checked against.
fn read_held_names_file(path: &std::path::Path) -> BTreeMap<String, Option<boxes::SessionId>> {
    let why = match std::fs::read(path) {
        Ok(bytes) => match serde_json_lenient::from_slice::<HeldNamesFile>(&bytes) {
            Ok(file) if file.version == HELD_NAMES_FILE_VERSION => {
                let mut held = BTreeMap::new();
                for (name, owner) in file.held_names {
                    match held.entry(canonical_box_name(&name)) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(owner);
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => {
                            tracing::warn!(
                                box = %name,
                                canonical = %entry.key(),
                                "the persisted held box names hold one name under two \
                                 spellings; reloading the one that sorts first only"
                            );
                        }
                    }
                }
                return held;
            }
            Ok(file) => format!(
                "version {}, this build reads {HELD_NAMES_FILE_VERSION}",
                file.version
            ),
            Err(error) => error.to_string(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return BTreeMap::new(),
        Err(error) => error.to_string(),
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unusable-{stamp}"));
    let aside = std::path::PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => tracing::error!(
            path = %path.display(),
            aside = %aside.display(),
            why,
            "the persisted held box names are unusable; they are set aside and no hold is reloaded"
        ),
        Err(error) => tracing::error!(
            path = %path.display(),
            why,
            %error,
            "the persisted held box names are unusable and could not be set aside; \
             no hold is reloaded and the next hold writes over them"
        ),
    }
    BTreeMap::new()
}

/// Reads the `host_ip` box ids persisted at `path`: none when there is no
/// file yet. A credentialed id the file does not also list as minted is
/// minted all the same: the file is only ever written by this registry. A
/// file that cannot be read, does not parse, or is of another version than
/// [`HOST_IP_IDS_FILE_VERSION`] reloads no id and is renamed aside under
/// the same `.unusable-<unix seconds>` suffix, said as an error line.
fn read_host_ip_ids_file(path: &std::path::Path) -> HostIpIds {
    let why = match std::fs::read(path) {
        Ok(bytes) => match serde_json_lenient::from_slice::<HostIpIdsFile>(&bytes) {
            Ok(file) if file.version == HOST_IP_IDS_FILE_VERSION => {
                let credentialed: BTreeSet<BoxId> =
                    file.credentialed.iter().map(|id| id.to_bytes()).collect();
                let mut ids: BTreeSet<BoxId> = file.ids.iter().map(|id| id.to_bytes()).collect();
                ids.extend(credentialed.iter().copied());
                return HostIpIds {
                    ids,
                    credentialed,
                    ..HostIpIds::default()
                };
            }
            Ok(file) => format!(
                "version {}, this build reads {HOST_IP_IDS_FILE_VERSION}",
                file.version
            ),
            Err(error) => error.to_string(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return HostIpIds::default(),
        Err(error) => error.to_string(),
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".unusable-{stamp}"));
    let aside = std::path::PathBuf::from(aside);
    match std::fs::rename(path, &aside) {
        Ok(()) => tracing::error!(
            path = %path.display(),
            aside = %aside.display(),
            why,
            "the persisted host_ip box ids are unusable; they are set aside and no id is reloaded"
        ),
        Err(error) => tracing::error!(
            path = %path.display(),
            why,
            %error,
            "the persisted host_ip box ids are unusable and could not be set aside; \
             no id is reloaded and the next change writes over them"
        ),
    }
    HostIpIds::default()
}

/// The run of `subnet`'s address plan the host hands registered boxes from:
/// the PTask run's upper half, `[midpoint + 1, last_ptask]`, as an inclusive
/// `(first, last)` pair — one address more than the daemon's reserve below
/// it, a PTask run holding an odd number of addresses.
///
/// The plan's PTask run is split into two disjoint sub-runs so the two
/// allocators that draw on it cannot meet: this host hands a registered box
/// and its task addresses only from the upper half, and the lower half — the
/// run below this hand-out run — is the self-allocation reserve a native
/// daemon draws from. The daemon's half is the same midpoint rule mirrored
/// in `minimald::net::self_allocation_run`; one rule, two statements, so
/// change both together — each side's tests pin the default plan's split
/// literally.
///
/// An in-VM daemon draws nothing (NET-138): every own-address box arrives
/// handed, and so does every task run, at a task address filed with its box
/// here. The reserve stays unused under a host that registers boxes.
#[must_use]
fn hand_out_run(subnet: SwitchSubnet) -> (u32, u32) {
    let first = subnet.first_ptask();
    let last = subnet.last_ptask();
    let reserve_len = (last - first).div_ceil(2);
    (first + reserve_len, last)
}

/// How long a released hand-out address waits before it is handed again:
/// the switch crate's one quarantine, shared with the daemon's
/// self-allocation reserve ([`switch::SWITCH_ADDRESS_REUSE_QUARANTINE`]).
const SWITCH_REUSE_QUARANTINE: Duration = switch::SWITCH_ADDRESS_REUSE_QUARANTINE;

/// How many hand-out addresses a task-slot draw always leaves for a new
/// box's own address (NET-138): task slots are best-effort, so the
/// registry stops drawing them once the book could hand fewer than this,
/// and a box is never refused because task slots took its address. Sixteen
/// keeps room for sixteen new boxes once task slots stop being handed:
/// about an eighth of a carved /24's hand-out run of 125, so the first
/// twenty-odd boxes there still get their full
/// [`minimald_rpc::TASK_SLOTS_PER_BOX`] slots each, and a rounding error
/// against the default plan's run of thousands.
pub const TASK_SLOT_FLOOR: usize = 16;

/// The hand-out run's book (NET-138, design §7.1): which of the run's
/// switch addresses are out — drawn for a row that stands or a
/// registration in flight — and which came back, when. Modeled on the
/// daemon's own self-allocation book (`minimald::net::IpAllocator`): an
/// address is reused, never shared, and never wraps.
///
/// Addresses are handed longest-free first: the run's never-drawn
/// addresses in plan order, then returned ones in return order, so the
/// quarantine is the normal case rather than the edge. A returned address
/// is handed again only once its quarantine ([`SWITCH_REUSE_QUARANTINE`])
/// has passed **and** no row and no withdrawn box's revocation still holds
/// it — the registry checks both at the draw. A row withdrawn before it
/// was ever attributed — no frame of its box ever crossed the gate — comes
/// back with no quarantine: nothing on the host keyed state by it, so an
/// activation that withdraws and re-registers (an autogen name's retry)
/// spends nothing.
///
/// A row's box id is the epoch its address carries between two hands: a
/// re-handed address is a new box with a new id (BEP-070), and a
/// withdrawal that names the old id removes nothing of the new row
/// ([`BoxRegistry::withdraw_client_box`]).
#[derive(Debug)]
struct SwitchAddressBook {
    /// The hand-out run, inclusive at both ends (`hand_out_run`).
    first: u32,
    last: u32,
    /// The next never-drawn address; `None` once the run is drawn through.
    /// Only ever advances, by a checked add, so it can never wrap.
    next: Option<u32>,
    /// The addresses drawn and not yet returned.
    out: BTreeSet<u32>,
    /// Returned addresses, oldest return first, each with the instant it
    /// becomes eligible again — its return plus the quarantine, or its
    /// return alone for a row that was never attributed — and the id of
    /// the box that returned it, the one box that may take it back inside
    /// its quarantine ([`Self::take`]).
    ///
    /// Not persisted: a minvmd restart is a VM restart, and every
    /// switch-keyed host-side state the quarantine outlasts — the gate's
    /// reply flows and DNS pins, the proxy's attachments, gvproxy's
    /// neighbour entries — lives in this process and the VM it supervises,
    /// and ends with them, so a book reloaded at start
    /// ([`BoxRegistry::persisting_to`]) holds only what reloaded rows hold.
    free: VecDeque<(u32, Instant, BoxId)>,
}

/// Where the hand-out run stands when a draw hands nothing: the counts an
/// [`AllocationError::SwitchExhausted`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandOutCounts {
    /// Addresses out: drawn for a row that stands or a registration in
    /// flight.
    pub live: usize,
    /// Addresses returned but not yet eligible — inside their quarantine,
    /// or still held by a row or a withdrawn box's revocation.
    pub quarantined: usize,
    /// Every address the hand-out run holds.
    pub capacity: u64,
    /// How long until the soonest returned address's quarantine passes,
    /// when one was returned at all.
    pub next_free_in: Option<Duration>,
}

impl std::fmt::Display for HandOutCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} of {} box addresses are in use",
            self.live, self.capacity
        )?;
        // The resting rule is named only when an address is resting.
        if self.quarantined > 0 {
            write!(
                f,
                " and {} {} released but cannot be reused yet (an address rests {} s after its \
                 release)",
                self.quarantined,
                if self.quarantined == 1 { "was" } else { "were" },
                SWITCH_REUSE_QUARANTINE.as_secs()
            )?;
        }
        if let Some(wait) = self.next_free_in {
            // Rounded up: an address that frees in 0.4 s is not free now.
            let secs = wait
                .as_secs()
                .saturating_add(u64::from(wait.subsec_nanos() > 0));
            write!(f, "; the next one frees in {} s", secs.max(1))?;
        }
        Ok(())
    }
}

impl SwitchAddressBook {
    fn new(subnet: SwitchSubnet) -> Self {
        let (first, last) = hand_out_run(subnet);
        Self {
            first,
            last,
            next: (first <= last).then_some(first),
            out: BTreeSet::new(),
            free: VecDeque::new(),
        }
    }

    /// Draws an address at `now`: a never-drawn one first, then the
    /// returned address free longest whose eligibility has passed and that
    /// `held` does not name. Hands nothing, and says where the run stands,
    /// when no address qualifies.
    fn draw(
        &mut self,
        now: Instant,
        held: impl Fn(Ipv4Addr) -> bool,
    ) -> Result<Ipv4Addr, HandOutCounts> {
        // A never-drawn address a row took by name ([`Self::take`]) is out
        // or returned already, never the cursor's to hand.
        while let Some(next) = self.next {
            self.next = next.checked_add(1).filter(|after| *after <= self.last);
            if !self.free.iter().any(|&(addr, ..)| addr == next) && self.out.insert(next) {
                return Ok(Ipv4Addr::from(next));
            }
        }
        let reusable = self
            .free
            .iter()
            .position(|&(addr, eligible, _)| now >= eligible && !held(Ipv4Addr::from(addr)));
        if let Some((addr, ..)) = reusable.and_then(|at| self.free.remove(at)) {
            self.out.insert(addr);
            return Ok(Ipv4Addr::from(addr));
        }
        Err(HandOutCounts {
            live: self.out.len(),
            quarantined: self.free.len(),
            capacity: u64::from(self.last)
                .saturating_sub(u64::from(self.first))
                .saturating_add(1),
            next_free_in: self
                .free
                .iter()
                .map(|&(_, eligible, _)| eligible.saturating_duration_since(now))
                .filter(|wait| !wait.is_zero())
                .min(),
        })
    }

    /// How many addresses draws at `now` could still hand, by the rules
    /// [`Self::draw`] keeps: the run's never-drawn addresses, and the
    /// returned ones whose eligibility has passed that `held` does not
    /// hold. The task-slot floor ([`TASK_SLOT_FLOOR`]) is measured on it.
    fn spare(&self, now: Instant, held: impl Fn(Ipv4Addr) -> bool) -> usize {
        let never_drawn = self.next.map_or(0, |next| {
            let ahead = usize::try_from(self.last - next).map_or(usize::MAX, |n| n + 1);
            let taken = self.out.range(next..).count()
                + self.free.iter().filter(|&&(addr, ..)| addr >= next).count();
            ahead.saturating_sub(taken)
        });
        let reusable = self
            .free
            .iter()
            .filter(|&&(addr, eligible, _)| now >= eligible && !held(Ipv4Addr::from(addr)))
            .count();
        never_drawn + reusable
    }

    /// Returns `addr` at `now` from the box `returned_by`, quarantined
    /// unless `quarantine` is false. Only an address this book drew and has
    /// not had back is returned: one an explicit registration brought
    /// ([`BoxRegistry::try_register`]) is not the run's to hand, and a
    /// second return is a no-op. An eligibility past the clock's range
    /// keeps the address out for good — the fail-closed reading of an
    /// overflow, never a wrap to an early one. Returns whether the address
    /// came back.
    fn give_back(
        &mut self,
        addr: Ipv4Addr,
        now: Instant,
        quarantine: bool,
        returned_by: BoxId,
    ) -> bool {
        let addr = u32::from(addr);
        let eligible = if quarantine {
            now.checked_add(SWITCH_REUSE_QUARANTINE)
        } else {
            Some(now)
        };
        let Some(eligible) = eligible else {
            return false;
        };
        if !self.out.remove(&addr) {
            return false;
        }
        self.free.push_back((addr, eligible, returned_by));
        true
    }

    /// Takes `addr` itself out for the box `taker`, at `now`: the draw a
    /// creation reloaded at start makes for its own addresses
    /// ([`BoxRegistry::persisting_to`]). An
    /// address inside the run that is not out is taken: a never-drawn one,
    /// a returned one whose eligibility has passed, or a returned one
    /// inside its quarantine when `taker` is the box that returned it —
    /// the state the quarantine guards is that box's own. Refused for an
    /// address outside the run, one already out, and one another box
    /// returned inside its quarantine. Returns whether it was taken.
    fn take(&mut self, addr: Ipv4Addr, now: Instant, taker: BoxId) -> bool {
        let addr = u32::from(addr);
        if addr < self.first || addr > self.last || self.out.contains(&addr) {
            return false;
        }
        if let Some(at) = self.free.iter().position(|&(free, ..)| free == addr) {
            let (_, eligible, returned_by) = self.free[at];
            if now < eligible && returned_by != taker {
                return false;
            }
            self.free.remove(at);
        }
        self.out.insert(addr);
        true
    }
}

/// Why a client-driven registration could not be allocated. Both runs a
/// box address comes from — the plan's switch lease run and the published
/// loopback slice — are finite; exhausting one is an answer to hand back
/// over the control socket, not a panic.
///
/// Not `Copy`: every variant that names a box carries its [`String`] name,
/// and the refusal is built once, answered with, and dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocationError {
    /// Every switch address in the hand-out run is out or not yet eligible
    /// again: held by a live row or a registration in flight, or returned
    /// and still inside its reuse quarantine ([`SwitchAddressBook`]). The
    /// counts say which, so the refusal tells an exhausted plan from one
    /// that frees an address shortly.
    #[error("{}: {}", minimald_rpc::SWITCH_PLAN_EXHAUSTED, .0)]
    SwitchExhausted(HandOutCounts),
    /// Every address in the loopback slice this subnet's switch publishes
    /// at is handed out.
    #[error(
        "{}; no published address remains",
        minimald_rpc::LOOPBACK_SLICE_EXHAUSTED
    )]
    LoopbackExhausted,
    /// The address plan does not serve this registry's subnet, so no box
    /// address can be allocated against it. An explicit registration
    /// ([`BoxRegistry::try_register`]) still works: it brings its own
    /// addresses.
    #[error("the address plan does not serve subnet {0}; no box address can be allocated")]
    UnplannedSubnet(SwitchSubnet),
    /// The id minted for the registration is already held by a live row, a
    /// kept creation, an attachment or a revocation record the Box Egress
    /// Proxy retains: one id names one box (BEP-070), so the registration
    /// is refused — never re-minted — before any address is spent, so the
    /// refusal leaves no new fact on the host.
    #[error(
        "box id {} is already in use. A running box, a stopped box that can resume, a Box \
         Egress Proxy attachment, or a revocation record of the Box Egress Proxy holds it",
        crate::bep_attach::BoxIdText(id)
    )]
    CollidingBoxId {
        /// The id a live row, a kept creation, an attachment or a retained
        /// revocation record already holds.
        id: BoxId,
    },
    /// The Box Egress Proxy answers its control socket but did not list the
    /// box ids its revocation records hold: a timeout, a refusal or a
    /// malformed reply. The check cannot show that no record holds the
    /// minted id, so the registration is refused before any address is
    /// spent (BEP-070).
    #[error(
        "the box was not created. The Box Egress Proxy did not list its revocation records, so \
         box id {} was not checked against them: {why}",
        crate::bep_attach::BoxIdText(id)
    )]
    RevocationsUnread {
        /// The minted id the check did not finish on.
        id: BoxId,
        /// Why the proxy's list was not read.
        why: String,
    },
    /// No Box Egress Proxy runs, and its audit log was not read whole: an
    /// I/O error, or a complete line that does not parse. The check cannot
    /// show that no revocation record holds the minted id, so the
    /// registration is refused before any address is spent (BEP-070).
    #[error(
        "the box was not created. Box id {} was not checked against the revocation records in \
         the Box Egress Proxy audit log in {audit}: {why}",
        crate::bep_attach::BoxIdText(id)
    )]
    AuditUnread {
        /// The minted id the check did not finish on.
        id: BoxId,
        /// The audit log's directory.
        audit: String,
        /// Why the log was not read whole.
        why: String,
    },
    /// The address is still held by a withdrawn box's revocation: the host
    /// has not finished unbinding the forwards that box published there
    /// (design §7.1). A row at the address now would receive the old box's
    /// forwarded connections, or have its own forwards unbound at the old
    /// box's end, so the registration is refused instead.
    #[error(
        "address {addr} still belongs to a box that is shutting down (its port forwards are not \
         removed yet); try again shortly"
    )]
    RevocationPending {
        /// The held address: a switch address or a published loopback one.
        addr: Ipv4Addr,
    },
    /// A withdrawal under the box's name landed while the answerer was
    /// allocating its published address: the withdrawal is ordered after
    /// the registration was read, so the registration writes no row.
    #[error("the box's registration was cancelled while its address was being assigned")]
    WithdrawnWhileAllocating,
    /// The name folds to one a live row already holds: the answerer keys
    /// an address by the name's canonical form
    /// ([`canonical_box_name`]), so two rows under
    /// folded-equal names would share one published address — one box, one
    /// address, one row. The registration is refused before any address is
    /// spent, and names the spelling the live row holds.
    ///
    /// Box names are DNS labels under `min.internal`, and DNS compares
    /// names case-insensitively (RFC 4343); the answerer already keys this
    /// way and session names are unique under the same fold, so one row per
    /// name (NET-138) means one row per folded name.
    #[error("a box named {held} already exists")]
    NameAlreadyHeld {
        /// The name the live row holds, in its registered spelling: the
        /// one the refusal reports back to the asking client.
        held: String,
    },
}

/// One box name's registration bookkeeping: how many registrations of it
/// are in flight — between reading the generation and the end of their
/// turn — and how many withdrawals under the name landed while they were.
/// A registration is refused when the generation moved past the one it
/// read ([`BoxRegistry::register_client_box_since`]).
#[derive(Debug, Default)]
pub struct NameRegistrations {
    generation: u64,
    in_flight: u32,
}

fn lock_generations(
    generations: &Mutex<HashMap<String, NameRegistrations>>,
) -> MutexGuard<'_, HashMap<String, NameRegistrations>> {
    generations
        .lock()
        .expect("the withdrawal generations' lock is held only across a map read or update")
}

/// One registration of a box name in flight
/// ([`BoxRegistry::begin_registration`]). Dropping it ends the count, and
/// the name's entry goes with its last registration, so the map holds only
/// names with a registration in flight.
#[derive(Debug)]
pub struct RegistrationClaim {
    generations: Arc<Mutex<HashMap<String, NameRegistrations>>>,
    /// The box's name in [`canonical_box_name`] form: the map's key.
    key: String,
    generation: u64,
}

impl RegistrationClaim {
    /// The name's withdrawal generation when the registration began.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for RegistrationClaim {
    fn drop(&mut self) {
        let mut generations = lock_generations(&self.generations);
        if let Some(entry) = generations.get_mut(&self.key) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            if entry.in_flight == 0 {
                generations.remove(&self.key);
            }
        }
    }
}

/// Why a creator's resume of its box's row was refused
/// ([`BoxRegistry::resume_client_box`]). Every refusal leaves the table as
/// it was: no row, no spent address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResumeError {
    /// The registry keeps no creation under the name: the box was never
    /// registered on this host, or its creator withdrew it.
    #[error("no box {name:?} is registered on this host to resume")]
    NoCreation {
        /// The name the resume presented.
        name: String,
    },
    /// The creation under the name was handed another pair than the one
    /// presented: not the resuming client's box.
    #[error(
        "box {name:?} was handed switch address {held_switch} and loopback address \
         {held_loopback}, not the pair the resume presented"
    )]
    NotTheHandedPair {
        /// The name the resume presented.
        name: String,
        /// The switch address the creation holds.
        held_switch: Ipv4Addr,
        /// The loopback address the creation holds.
        held_loopback: Ipv4Addr,
    },
    /// The creation under the name is another box than the id the resume
    /// named: a newer creation took the name and its addresses.
    #[error(
        "box {name:?} is box id {}, not the {} the resume named",
        crate::bep_attach::BoxIdText(held_box_id),
        crate::bep_attach::BoxIdText(asked_box_id)
    )]
    NotTheBoxId {
        /// The name the resume presented.
        name: String,
        /// The id the creation holds.
        held_box_id: BoxId,
        /// The id the resume named.
        asked_box_id: BoxId,
    },
    /// The answerer handed the name another published address than the
    /// one the box was created with: the box's address moved while it had
    /// no row, and a row at the old one would answer for an address the
    /// box no longer holds. The address is never moved on a resume: the
    /// creator proves itself with the pair it was handed.
    #[error(
        "box {name:?} was created at loopback address {held}, but the answerer now holds \
         {allocated} for it"
    )]
    LoopbackMoved {
        /// The name the resume presented.
        name: String,
        /// The loopback address the creation holds.
        held: Ipv4Addr,
        /// The address the answerer allocated for the name now.
        allocated: Ipv4Addr,
    },
    /// The row could not be published at the box's addresses.
    #[error(transparent)]
    Allocation(#[from] AllocationError),
}

/// What a resume finds before anything is allocated for it
/// ([`BoxRegistry::resumable`]).
#[derive(Debug)]
pub enum Resumable {
    /// The creation's row stands: the resume's answer, as it stands.
    Standing(Arc<BoxRecord>),
    /// The creation is dormant: its row is reinstated under `name`, the
    /// name it was registered under, which the answerer holds its
    /// published address by.
    Dormant {
        /// The creation's own name.
        name: String,
    },
}

/// The row that stands for `creation`, when one does: the row at its
/// switch address, of its box id.
fn standing_row_of<'rows>(rows: &'rows Rows, creation: &Creation) -> Option<&'rows Arc<BoxRecord>> {
    rows.get(&creation.switch_address.octets())
        .filter(|record| record.box_id == creation.id() && !record.is_task_row())
}

/// Why a client-driven withdrawal was refused. The pair a withdrawal
/// presents is the proof that its client is the row's creator (T66), so a
/// refusal is the daemon saying the proof does not match the row the
/// switch address publishes — never a failure of the goal state, which
/// [`BoxRegistry::withdraw_client_box`] reports as `Ok(None)`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WithdrawError {
    /// A row is published at the switch address under another box's name:
    /// the requesting client is not its creator.
    #[error(
        "the row at switch address {switch_addr} is held by box {held_name:?}, \
         not by the withdrawing {asked_name:?}"
    )]
    NotTheCreatorsRow {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The name the published row carries.
        held_name: String,
        /// The name the withdrawal presented.
        asked_name: String,
    },
    /// The row at the switch address carries the requested name but another
    /// loopback address than the pair presented: not the pair the
    /// registration handed back.
    #[error(
        "the row at switch address {switch_addr} carries loopback address \
         {held_loopback}, not the {asked_loopback} the withdrawal presented"
    )]
    NotTheHandedPair {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The loopback address the published row carries.
        held_loopback: Ipv4Addr,
        /// The loopback address the withdrawal presented.
        asked_loopback: Ipv4Addr,
    },
    /// The row at the switch address carries the requested name and pair
    /// but another box id than the withdrawal named: a newer creation was
    /// handed the same name and addresses since, and the withdrawing client
    /// is the creator of the row before it, not of this one.
    #[error(
        "the row at switch address {switch_addr} is box id {}, not the {} the withdrawal \
         named; it is a newer box under the same name and addresses",
        crate::bep_attach::BoxIdText(held_box_id),
        crate::bep_attach::BoxIdText(asked_box_id)
    )]
    NotTheBoxId {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The id the published row holds.
        held_box_id: BoxId,
        /// The id the withdrawal named.
        asked_box_id: BoxId,
    },
}

/// Why a renamed session's re-key of its box was refused
/// ([`BoxRegistry::rename_client_box`], #1116). A refused rename changes
/// nothing: the box stays under the name the host held it by.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenameError {
    /// The row at the switch address is another box's: the renaming
    /// client is not its creator.
    #[error(
        "the row at switch address {switch_addr} is box id {}, not the {} the rename named",
        crate::bep_attach::BoxIdText(held_box_id),
        crate::bep_attach::BoxIdText(asked_box_id)
    )]
    NotTheBoxId {
        /// The switch address the rename named.
        switch_addr: Ipv4Addr,
        /// The id the published row holds.
        held_box_id: BoxId,
        /// The id the rename named.
        asked_box_id: BoxId,
    },
    /// The box the id names was handed another pair than the one the
    /// rename presented.
    #[error(
        "box id {} was handed switch address {held_switch} and loopback address \
         {held_loopback}, not the {asked_switch} and {asked_loopback} the rename presented",
        crate::bep_attach::BoxIdText(box_id)
    )]
    NotTheHandedPair {
        /// The id the rename named.
        box_id: BoxId,
        /// The switch address the box holds.
        held_switch: Ipv4Addr,
        /// The loopback address the box holds.
        held_loopback: Ipv4Addr,
        /// The switch address the rename presented.
        asked_switch: Ipv4Addr,
        /// The loopback address the rename presented.
        asked_loopback: Ipv4Addr,
    },
    /// Another box's row holds the new name on this host.
    #[error("box {holder:?} holds the name {name:?} on the VM host")]
    NameHeld {
        /// The name the rename asked for.
        name: String,
        /// The name of the row that holds it, in its own spelling.
        holder: String,
    },
}

/// Why an admit report was refused against the host-held grant (NET-138):
/// the one refusal the in-VM daemon's publish unwinds by. Every variant
/// names the box whose row was asked about — except the first, which names
/// the address no row answered at, because the box is exactly what the
/// report could not prove — and the port and protocol the report carried,
/// so the refusal the guest unwinds its publish on says what was refused
/// and which check refused it, in one sentence the wire carries verbatim.
///
/// Refused reports record nothing: not the port, not a rate timestamp, not
/// a fact the host did not already hold. Not `Copy`: every variant that
/// names a box carries its [`String`] name, and the refusal is built once,
/// answered with, and dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortReportRefusal {
    /// No row is held at the switch address the report named — the box was
    /// never registered, its row was withdrawn, or the daemon restarted
    /// since: the guest cannot invent a row by reporting at an address.
    #[error(
        "no box row is held at switch address {switch_addr}; the reported port {port} \
         records nowhere"
    )]
    NoRow {
        /// The switch address the report named.
        switch_addr: Ipv4Addr,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's dynamic-ingress stance is `deny` — or the declaration
    /// carried no stance, its default — which admits no runtime port.
    #[error("box {name} declared dynamic ingress deny; its runtime port reports record nothing")]
    DenyStance {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's stance is `ask`, and a guest's admit report is not the
    /// attached human's yes: an `ask` admission records only from the host
    /// side, where the answer is seen, so the guest's report records
    /// nothing under it.
    #[error(
        "box {name} declared dynamic ingress ask; ask-yes must be host-recorded, so the \
         guest's report of port {port} records nothing"
    )]
    AskNotHostRecorded {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's stance is `allow` but its declaration named no allowed
    /// range, and an absent range permits nothing.
    #[error("box {name} declared no dynamic allowed range; no runtime port is permitted")]
    NoAllowedRange {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The reported port is outside the row's allowed range, inclusive at
    /// both ends.
    #[error(
        "runtime port {port} is outside box {name}'s allowed range \
         {}-{}",
        range.0,
        range.1
    )]
    OutsideAllowedRange {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The row's allowed range, inclusive at both ends.
        range: (u16, u16),
    },
    /// The row already holds the per-row cap of runtime-admitted ports
    /// ([`RUNTIME_PORT_CAP`]).
    #[error(
        "box {name} already holds {cap} runtime-admitted ports, its per-row cap; \
         the reported port {port} records nothing"
    )]
    RowCapReached {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The cap the row reached.
        cap: usize,
    },
    /// The row is over its per-row admit rate
    /// ([`ROW_ADMIT_RATE_PER_SECOND`] per trailing second).
    #[error(
        "box {name} is over its per-row admit rate ({rate} per second); the reported \
         port {port} records nothing"
    )]
    RateExceeded {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The rate the row is over.
        rate: usize,
    },
}

/// The per-row bound on pending asks (NET-045): a row's ask queue holds at
/// most this many asks — the offered one and those waiting behind it — so a
/// guest that asks in a loop cannot grow a row's ask state without limit.
/// The honest reporter asks at most once per exposure, and the queue exists
/// for the exposures that overlap the dialog a row already holds open; past
/// the bound the guest's ask is refused at once, so the exposure answers
/// its own refusal rather than waiting behind a wall of asks.
pub(crate) const PENDING_ASKS_PER_ROW: usize = 8;

/// Mints the id one pending ask is named by (NET-045): one UUIDv4 — all
/// random, no timestamp, because an ask is an event, not an entity with a
/// creation order to keep — with its bytes from the host's OS CSPRNG and
/// from nothing the guest could observe, predict or arrange. The offer
/// hands the id to the attached host client and the recorded answer
/// carries it back; an answer for an id the book does not hold pending is
/// refused, and a resolved id leaves the book for good, so no id is ever
/// answered twice.
fn mint_ask_id() -> minimald_rpc::AskId {
    minimald_rpc::AskId::from_bytes(uuid::Uuid::new_v4().into_bytes())
}

/// One pending ask's host-sourced facts (NET-045): what a dialog, a log
/// line and an audit line name the ask by. The name, the box id and the
/// switch address are copied from the host row at record time; the port
/// and the protocol are the two fields the guest's ask carries. Nothing
/// else the guest could say reaches them, so the offer's dialog text is
/// built from the host row alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AskFacts {
    /// The box's name, from the host's own row.
    pub(crate) name: String,
    /// The row's box id: the host-minted identity clients subscribe by.
    pub(crate) box_id: BoxId,
    /// The row's switch address: the ask's own row key.
    pub(crate) switch_address: Ipv4Addr,
    /// The port the exposure asks to publish.
    pub(crate) port: u16,
    /// The protocol the port would publish under.
    pub(crate) proto: IpProto,
}

impl AskFacts {
    /// The offer an attached client renders its dialog from.
    fn offer(&self, ask_id: minimald_rpc::AskId) -> minimald_rpc::BoxControlReply {
        minimald_rpc::BoxControlReply::PendingAskOffer(minimald_rpc::PendingAskOffer {
            ask_id,
            box_id: minimald_rpc::BoxId::from_bytes(self.box_id),
            name: self.name.clone(),
            port: self.port,
            proto: self.proto,
        })
    }
}

/// One pending ask as the book holds it: its facts and the sending end of
/// the guest's outcome channel. The end is sent once, by whichever of an
/// answer or a cancellation removes the ask from the book first. No timer
/// ever touches it.
struct PendingAsk {
    facts: AskFacts,
    reply: std::sync::mpsc::Sender<minimald_rpc::AskAdmitOutcome>,
}

/// One attached host client's subscription: the push channel its serving
/// thread writes to the client, keyed by an id so the client's own detach
/// removes exactly its own entry. Only the detach removes an entry; a push
/// that fails is not counted as delivered, and the client's serving thread
/// unsubscribes it on its way out.
struct AskSubscriber {
    id: u64,
    pushes: std::sync::mpsc::Sender<minimald_rpc::BoxControlReply>,
}

/// The host's record of pending asks (NET-045), held by the registry beside
/// the rows it asks about:
///
/// * the pending asks by their host-minted id; resolving an ask removes it,
///   so the first recorded answer is the only one an id ever takes;
/// * each row's queue of them in arrival order, keyed by switch address.
///   The front is the one offered: one dialog at a time per row, the rest
///   waiting behind it within [`PENDING_ASKS_PER_ROW`];
/// * the attached host clients by the box id of the row each subscribed
///   to, never a name.
///
/// Lock order: a path that reads the rows takes the row lock first and the
/// book second, and no path takes them the other way round; a recorded
/// yes takes the row's runtime lock innermost.
#[derive(Default)]
struct AskBook {
    pending: std::collections::HashMap<minimald_rpc::AskId, PendingAsk>,
    queues: std::collections::HashMap<[u8; 4], VecDeque<minimald_rpc::AskId>>,
    subscribers: std::collections::HashMap<BoxId, Vec<AskSubscriber>>,
    next_subscriber: u64,
    /// The most recent ends, oldest first, bounded at
    /// [`ENDED_ASKS_REMEMBERED`]: what a late answer for an ended ask is
    /// told instead of a bare refusal. Never consulted to admit anything.
    ended: VecDeque<EndedAsk>,
}

/// How many ended asks the book remembers for late answers (NET-045). An
/// answer that arrives after its ask's end was evicted is refused as an
/// unknown id, which admits nothing either.
pub(crate) const ENDED_ASKS_REMEMBERED: usize = 256;

/// One ended ask as the book remembers it for a late answer.
#[derive(Debug, Clone, Copy)]
struct EndedAsk {
    ask_id: minimald_rpc::AskId,
    port: u16,
    proto: IpProto,
    end: minimald_rpc::AskLateEnd,
}

/// Why a recorded answer was refused (NET-045). Neither records anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerRefusal {
    /// The book never minted the id, or its end has been forgotten.
    UnknownId,
    /// The ask already ended: how, and what it was about.
    AlreadyEnded {
        port: u16,
        proto: IpProto,
        end: minimald_rpc::AskLateEnd,
    },
}

/// How an outcome reads to a late answer: allowed only when admitted,
/// denied for a no or a no-tty, and every other end as the cancellation it
/// is — a yes the row could no longer take included, since its row went.
fn late_end(outcome: &minimald_rpc::AskAdmitOutcome) -> minimald_rpc::AskLateEnd {
    use minimald_rpc::{AskCancelCause, AskLateEnd, AskRefused};
    match outcome {
        minimald_rpc::AskAdmitOutcome::Admitted { .. } => AskLateEnd::Allowed,
        minimald_rpc::AskAdmitOutcome::Refused {
            reason: AskRefused::Denied | AskRefused::NoTty,
            ..
        } => AskLateEnd::Denied,
        minimald_rpc::AskAdmitOutcome::Refused { cause, .. } => AskLateEnd::Cancelled {
            cause: cause.unwrap_or(AskCancelCause::RowWithdrawn),
        },
    }
}

/// A count of live connections of one kind, with an optional cap: the ask
/// verbs' threads (NET-045) are bounded by it, and a graceful stop waits on
/// one to reach zero.
#[derive(Debug, Default)]
pub(crate) struct ConnectionGauge {
    count: Mutex<usize>,
    idle: std::sync::Condvar,
}

/// One counted connection; the count drops with the guard.
#[derive(Debug)]
pub(crate) struct GaugeGuard(Arc<ConnectionGauge>);

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        let mut count = self
            .0
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.0.idle.notify_all();
        }
    }
}

impl ConnectionGauge {
    /// Count one more connection, unless `cap` are already counted.
    pub(crate) fn try_acquire(self: &Arc<Self>, cap: usize) -> Option<GaugeGuard> {
        let mut count = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *count >= cap {
            return None;
        }
        *count += 1;
        Some(GaugeGuard(Arc::clone(self)))
    }

    /// Wait until nothing is counted, at most `bound`; whether it emptied.
    pub(crate) fn wait_idle(&self, bound: std::time::Duration) -> bool {
        let count = self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (count, _) = self
            .idle
            .wait_timeout_while(count, bound, |count| *count > 0)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *count == 0
    }
}

/// The held connections' gauges, shared by every clone of a registry: the
/// ask verbs' (NET-045) guest-door ask connections and host subscriptions,
/// and the held registrations' lease connections
/// ([`minimald_rpc::RegisterBoxRequest::hold`]), each capped by the door,
/// and the asks whose end is not yet audited, which a graceful stop waits
/// on.
#[derive(Debug)]
pub(crate) struct AskGauges {
    pub(crate) guest_asks: Arc<ConnectionGauge>,
    pub(crate) subscriptions: Arc<ConnectionGauge>,
    pub(crate) leases: Arc<ConnectionGauge>,
    pub(crate) unaudited: Arc<ConnectionGauge>,
    guest_ask_cap: std::sync::atomic::AtomicUsize,
    subscription_cap: std::sync::atomic::AtomicUsize,
    lease_cap: std::sync::atomic::AtomicUsize,
}

impl Default for AskGauges {
    fn default() -> Self {
        Self {
            guest_asks: Arc::default(),
            subscriptions: Arc::default(),
            leases: Arc::default(),
            unaudited: Arc::default(),
            guest_ask_cap: crate::control::MAX_GUEST_ASK_CONNECTIONS.into(),
            subscription_cap: crate::control::MAX_ASK_SUBSCRIPTIONS.into(),
            lease_cap: crate::control::MAX_REGISTRATION_LEASES.into(),
        }
    }
}

impl AskGauges {
    /// The guest-door ask connection cap.
    pub(crate) fn guest_ask_cap(&self) -> usize {
        self.guest_ask_cap.load(Ordering::Relaxed)
    }

    /// The host subscription cap.
    pub(crate) fn subscription_cap(&self) -> usize {
        self.subscription_cap.load(Ordering::Relaxed)
    }

    /// Lower both caps, so a test can fill them.
    #[cfg(test)]
    pub(crate) fn set_caps(&self, guest_asks: usize, subscriptions: usize) {
        self.guest_ask_cap.store(guest_asks, Ordering::Relaxed);
        self.subscription_cap
            .store(subscriptions, Ordering::Relaxed);
    }

    /// The held registrations' lease connection cap.
    pub(crate) fn lease_cap(&self) -> usize {
        self.lease_cap.load(Ordering::Relaxed)
    }

    /// Lower the lease cap, so a test can fill it.
    #[cfg(test)]
    pub(crate) fn set_lease_cap(&self, leases: usize) {
        self.lease_cap.store(leases, Ordering::Relaxed);
    }
}

/// Counts, not contents: the reply and push channels have no useful debug
/// form, and the ids and facts are what the log lines carry.
impl std::fmt::Debug for AskBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskBook")
            .field("pending", &self.pending.len())
            .field("rows", &self.queues.len())
            .field("subscribed_boxes", &self.subscribers.len())
            .finish()
    }
}

impl AskBook {
    /// Push `message` to the clients attached to `box_id` — every one, or
    /// only the subscriber `only` names — and answer how many took it.
    fn push(
        &self,
        box_id: &BoxId,
        message: &minimald_rpc::BoxControlReply,
        only: Option<u64>,
    ) -> usize {
        self.subscribers.get(box_id).map_or(0, |clients| {
            clients
                .iter()
                .filter(|client| only.is_none_or(|id| client.id == id))
                .filter(|client| client.pushes.send(message.clone()).is_ok())
                .count()
        })
    }

    /// Whether any client is attached to `box_id`.
    fn has_client(&self, box_id: &BoxId) -> bool {
        self.subscribers
            .get(box_id)
            .is_some_and(|clients| !clients.is_empty())
    }

    /// Offer the ask at the front of the row's queue to every attached
    /// client, when the queue holds one.
    fn offer_front(&self, switch_address: Ipv4Addr) -> Option<AskOffered> {
        let ask_id = *self.queues.get(&switch_address.octets())?.front()?;
        let facts = &self.pending.get(&ask_id)?.facts;
        let offered_to = self.push(&facts.box_id, &facts.offer(ask_id), None);
        Some(AskOffered {
            ask_id,
            facts: facts.clone(),
            offered_to,
        })
    }

    /// End one pending ask with `outcome`: remove it from the book and its
    /// row's queue, answer the guest's held reply, dismiss the dialogs still
    /// showing it, and offer the row's next queued ask when the ended one
    /// was the row's offered dialog. `None` when the book does not hold the
    /// ask: it was already answered, cancelled, or never minted.
    fn end(
        &mut self,
        ask_id: minimald_rpc::AskId,
        outcome: impl FnOnce(&AskFacts) -> minimald_rpc::AskAdmitOutcome,
    ) -> Option<AskEnded> {
        let pending = self.pending.remove(&ask_id)?;
        let key = pending.facts.switch_address.octets();
        let mut was_front = false;
        if let Some(queue) = self.queues.get_mut(&key) {
            was_front = queue.front() == Some(&ask_id);
            queue.retain(|queued| *queued != ask_id);
            if queue.is_empty() {
                self.queues.remove(&key);
            }
        }
        let outcome = outcome(&pending.facts);
        if self.ended.len() >= ENDED_ASKS_REMEMBERED {
            self.ended.pop_front();
        }
        self.ended.push_back(EndedAsk {
            ask_id,
            port: pending.facts.port,
            proto: pending.facts.proto,
            end: late_end(&outcome),
        });
        // The guest may already be gone; its connection's end is its own
        // cancellation, and there is nothing left to tell it.
        let _ = pending.reply.send(outcome);
        let dismissed = if was_front {
            self.push(
                &pending.facts.box_id,
                &minimald_rpc::BoxControlReply::PendingAskDismissed {
                    ask_id,
                    dismissed: true,
                },
                None,
            )
        } else {
            0
        };
        let offered_next = if was_front {
            self.offer_front(pending.facts.switch_address)
        } else {
            None
        };
        Some(AskEnded {
            ask_id,
            facts: pending.facts,
            outcome,
            dismissed,
            offered_next,
        })
    }

    /// How a recorded answer for an ask the book no longer holds is
    /// refused: with the ask's remembered end, or as an unknown id.
    fn late_refusal(&self, ask_id: minimald_rpc::AskId) -> AnswerRefusal {
        self.ended
            .iter()
            .rev()
            .find(|ended| ended.ask_id == ask_id)
            .map_or(AnswerRefusal::UnknownId, |ended| {
                AnswerRefusal::AlreadyEnded {
                    port: ended.port,
                    proto: ended.proto,
                    end: ended.end,
                }
            })
    }

    /// End every pending ask the predicate selects as cancelled by `cause`.
    fn cancel_where(
        &mut self,
        select: impl Fn(&AskFacts) -> bool,
        cause: minimald_rpc::AskCancelCause,
    ) -> Vec<AskEnded> {
        let ids: Vec<minimald_rpc::AskId> = self
            .pending
            .iter()
            .filter(|(_, pending)| select(&pending.facts))
            .map(|(ask_id, _)| *ask_id)
            .collect();
        ids.into_iter()
            .filter_map(|ask_id| self.end(ask_id, |_| cancelled(ask_id, cause)))
            .collect()
    }
}

/// The cancelled end of `ask_id`, by `cause`.
fn cancelled(
    ask_id: minimald_rpc::AskId,
    cause: minimald_rpc::AskCancelCause,
) -> minimald_rpc::AskAdmitOutcome {
    minimald_rpc::AskAdmitOutcome::Refused {
        ask_id,
        reason: minimald_rpc::AskRefused::Cancelled,
        cause: Some(cause),
    }
}

/// An ask offered to the clients attached to its row (NET-045): what the
/// door's log and audit lines record the offer by.
#[derive(Debug, Clone)]
pub(crate) struct AskOffered {
    /// The ask's own id.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The host-sourced facts the dialog is built from.
    pub(crate) facts: AskFacts,
    /// How many attached clients the offer reached.
    pub(crate) offered_to: usize,
}

/// An ask the book recorded pending (NET-045). `offered` is the offer when
/// the ask became the row's offered dialog at once, and `None` when it
/// waits behind the one the row already holds open; it is offered when it
/// reaches the front, by whichever path ends the ask ahead of it.
#[derive(Debug)]
pub(crate) struct AskRecorded {
    /// The ask's host-minted id.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The ask's host-sourced facts.
    pub(crate) facts: AskFacts,
    /// The offer, when the ask is the row's offered dialog.
    pub(crate) offered: Option<AskOffered>,
}

/// Why the book refused to record an ask (NET-045): the minted id the
/// refusal is audited under, the host row's facts where a row exists at the
/// named address, and the typed reason the guest's exposure is refused
/// with.
#[derive(Debug)]
pub(crate) struct AskRecordRefusal {
    /// The id minted for the refused ask; never offered, never answerable.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The host row's facts; `None` when no row is held at the address.
    pub(crate) facts: Option<AskFacts>,
    /// Why the ask was refused.
    pub(crate) reason: minimald_rpc::AskRefused,
}

/// A pending ask's end (NET-045), by a recorded answer or a cancellation:
/// the outcome the guest's held reply was answered with, how many dialogs
/// were dismissed, and the row's next ask when one was offered in its
/// place.
#[derive(Debug)]
pub(crate) struct AskEnded {
    /// The ended ask's id.
    pub(crate) ask_id: minimald_rpc::AskId,
    /// The ended ask's host-sourced facts.
    pub(crate) facts: AskFacts,
    /// The outcome the guest's held reply was answered with.
    pub(crate) outcome: minimald_rpc::AskAdmitOutcome,
    /// How many attached clients the ended dialog was dismissed from.
    pub(crate) dismissed: usize,
    /// The row's next queued ask, offered now that this one ended.
    pub(crate) offered_next: Option<AskOffered>,
}

impl BoxRegistry {
    /// Record the in-VM daemon's ask (NET-045): mint the ask's id, check the
    /// ask against the host row, queue it on the row, and offer it to every
    /// client attached to the row's box id when it is the row's front.
    /// `reply` is the sending end of the guest's outcome channel; the book
    /// sends the ask's end on it once, on the first answer or cancellation,
    /// and never on a timer.
    ///
    /// The checks, in order: a row is held at the address
    /// ([`minimald_rpc::AskRefused::NoRow`]); its stance is `ask`
    /// ([`minimald_rpc::AskRefused::StanceNotAsk`]); its range admits the
    /// port ([`minimald_rpc::AskRefused::OutsideGrant`]), so no client is
    /// asked about a publish the grant would refuse anyway; a client is
    /// attached to answer ([`minimald_rpc::AskRefused::NoClient`]); and the
    /// row's queue is inside its bound
    /// ([`minimald_rpc::AskRefused::QueueFull`]). A refusal records nothing
    /// and drops `reply` unsent: the refusal is the caller's answer.
    pub(crate) fn record_ask(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
        reply: std::sync::mpsc::Sender<minimald_rpc::AskAdmitOutcome>,
    ) -> Result<AskRecorded, AskRecordRefusal> {
        let ask_id = mint_ask_id();
        let refuse = |facts: Option<AskFacts>, reason| AskRecordRefusal {
            ask_id,
            facts,
            reason,
        };
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let Some(record) = rows.get(&switch_addr.octets()) else {
            return Err(refuse(None, minimald_rpc::AskRefused::NoRow));
        };
        let facts = AskFacts {
            name: record.name().to_string(),
            box_id: record.box_id(),
            switch_address: record.switch_addr(),
            port,
            proto,
        };
        if record.dynamic_ingress() != DynamicIngress::Ask {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::StanceNotAsk));
        }
        if !in_range(record.dynamic_range(), port) {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::OutsideGrant));
        }
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        drop(rows);
        if !book.has_client(&facts.box_id) {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::NoClient));
        }
        let queue = book.queues.entry(switch_addr.octets()).or_default();
        if queue.len() >= PENDING_ASKS_PER_ROW {
            return Err(refuse(Some(facts), minimald_rpc::AskRefused::QueueFull));
        }
        let is_front = queue.is_empty();
        queue.push_back(ask_id);
        book.pending.insert(
            ask_id,
            PendingAsk {
                facts: facts.clone(),
                reply,
            },
        );
        let offered = if is_front {
            book.offer_front(switch_addr)
        } else {
            None
        };
        Ok(AskRecorded {
            ask_id,
            facts,
            offered,
        })
    }

    /// Record a host client's answer for one pending ask (NET-045). The ask
    /// is removed from the book before its outcome is decided, so the first
    /// answer is the only one it takes and a second finds nothing.
    ///
    /// A yes records the ask's port in the row the table holds now, inside
    /// the grant ([`record_ask_yes`]), and answers the guest's held reply
    /// [`minimald_rpc::AskAdmitOutcome::Admitted`]: that reply is the one
    /// admit the yes is consumed by. A no and a no-tty record nothing: the
    /// ask leaves the book, and nothing is stored that could later count as
    /// a yes.
    ///
    /// # Errors
    ///
    /// [`AnswerRefusal`] when the book holds no pending ask under `ask_id`:
    /// how it ended, when the book still remembers, or an unknown id.
    /// Nothing is recorded either way: a late yes never admits.
    pub(crate) fn record_ask_answer(
        &self,
        ask_id: minimald_rpc::AskId,
        answer: minimald_rpc::AskAnswer,
    ) -> Result<AskEnded, AnswerRefusal> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        if !book.pending.contains_key(&ask_id) {
            return Err(book.late_refusal(ask_id));
        }
        book.end(ask_id, |facts| match answer {
            minimald_rpc::AskAnswer::Yes => match record_ask_yes(&rows, facts) {
                Ok(()) => minimald_rpc::AskAdmitOutcome::Admitted {
                    ask_id,
                    port: facts.port,
                    proto: facts.proto,
                },
                Err(reason) => minimald_rpc::AskAdmitOutcome::Refused {
                    ask_id,
                    reason,
                    cause: None,
                },
            },
            minimald_rpc::AskAnswer::No => minimald_rpc::AskAdmitOutcome::Refused {
                ask_id,
                reason: minimald_rpc::AskRefused::Denied,
                cause: None,
            },
            minimald_rpc::AskAnswer::NoTty => minimald_rpc::AskAdmitOutcome::Refused {
                ask_id,
                reason: minimald_rpc::AskRefused::NoTty,
                cause: None,
            },
        })
        .ok_or(AnswerRefusal::UnknownId)
    }

    /// Cancel one pending ask (NET-045): the guest withdrew it — its
    /// connection ended — so the ask leaves the book unanswered and its
    /// dialogs are dismissed. `None` when the ask already ended: a
    /// cancellation never undoes an answer.
    pub(crate) fn cancel_ask(&self, ask_id: minimald_rpc::AskId) -> Option<AskEnded> {
        self.asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .end(ask_id, |_| {
                cancelled(ask_id, minimald_rpc::AskCancelCause::GuestClosed)
            })
    }

    /// Cancel every pending ask the row at `switch_addr` holds (NET-045):
    /// the row's withdrawal takes the grant the asks would publish under,
    /// so each ends cancelled and the guest's exposure is refused.
    fn cancel_asks_for_row(&self, switch_addr: Ipv4Addr) -> Vec<AskEnded> {
        self.asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .cancel_where(
                |facts| facts.switch_address == switch_addr,
                minimald_rpc::AskCancelCause::RowWithdrawn,
            )
    }

    /// Subscribe an attached host client to the pending asks of the row
    /// holding `box_id` (NET-045): keyed by the host-minted box id, never a
    /// name. Answers the subscription's id, for the detach to end exactly
    /// this subscription, and the row's standing offered ask, pushed to this
    /// client alone so a client attaching mid-ask sees the open dialog.
    /// `None` when no live row holds `box_id`: there is nothing to subscribe
    /// to.
    pub(crate) fn subscribe_asks(
        &self,
        box_id: BoxId,
        pushes: std::sync::mpsc::Sender<minimald_rpc::BoxControlReply>,
    ) -> Option<(u64, Option<AskOffered>)> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let switch_address = rows
            .values()
            .find(|record| record.box_id == box_id && !record.is_task_row())?
            .switch_addr();
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        drop(rows);
        let id = book.next_subscriber;
        book.next_subscriber += 1;
        book.subscribers
            .entry(box_id)
            .or_default()
            .push(AskSubscriber { id, pushes });
        let standing = book
            .queues
            .get(&switch_address.octets())
            .and_then(|queue| queue.front().copied())
            .and_then(|ask_id| {
                let facts = book.pending.get(&ask_id)?.facts.clone();
                let offered_to = book.push(&box_id, &facts.offer(ask_id), Some(id));
                Some(AskOffered {
                    ask_id,
                    facts,
                    offered_to,
                })
            });
        Some((id, standing))
    }

    /// End one client's subscription (NET-045). When it was the last client
    /// attached to the box, every pending ask the box holds is cancelled:
    /// nobody is left to answer, and an ask must not hold the exposure
    /// behind a dialog nobody can see. The cancelled asks come back for the
    /// caller's log lines; their audit lines are the guests' own serving
    /// threads', which receive the cancellation.
    pub(crate) fn unsubscribe_asks(&self, box_id: BoxId, subscriber: u64) -> Vec<AskEnded> {
        let mut book = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic");
        if let Some(clients) = book.subscribers.get_mut(&box_id) {
            clients.retain(|client| client.id != subscriber);
            if clients.is_empty() {
                book.subscribers.remove(&box_id);
            }
        }
        if book.has_client(&box_id) {
            return Vec::new();
        }
        book.cancel_where(
            |facts| facts.box_id == box_id,
            minimald_rpc::AskCancelCause::LastDetach,
        )
    }

    /// Cancel every pending ask for a graceful stop (NET-045): each ends
    /// through the same path as any cancellation, by
    /// [`minimald_rpc::AskCancelCause::MinvmdStopping`], so its guest's
    /// serving thread audits it; then wait, at most `bound`, for every
    /// ended ask's audit line to be written. Answers the ended asks.
    pub(crate) fn stop_asks(&self, bound: std::time::Duration) -> Vec<AskEnded> {
        let ended = self
            .asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .cancel_where(|_| true, minimald_rpc::AskCancelCause::MinvmdStopping);
        if !self.ask_gauges.unaudited.wait_idle(bound) {
            tracing::warn!(
                "some cancelled asks' audit lines were not written before the stop's bound"
            );
        }
        ended
    }

    /// The ask verbs' connection gauges (NET-045).
    pub(crate) fn ask_gauges(&self) -> &AskGauges {
        &self.ask_gauges
    }

    /// How many asks the book holds pending: the tests' view that an ask
    /// ended and left nothing behind.
    #[cfg(test)]
    pub(crate) fn pending_ask_count(&self) -> usize {
        self.asks
            .lock()
            .expect("the ask book's lock is never held across a panic")
            .pending
            .len()
    }
}

/// Whether `range`, inclusive at both ends, admits `port`; an absent range
/// admits nothing.
fn in_range(range: Option<(u16, u16)>, port: u16) -> bool {
    range.is_some_and(|(low, high)| (low..=high).contains(&port))
}

/// Record an answered yes's port in the row the table holds now (NET-045):
/// the port joins the row's runtime-admitted set, the same set the in-VM
/// daemon's reports fill under `allow`, and a port the row already holds
/// is recorded already.
///
/// The row is looked up again at answer time and checked again: a row
/// withdrawn and registered anew at the address is another box the human
/// was not asked about. The report path's cap and rate bound a guest's
/// report storm (NET-138); a yes is the host's own decision at human pace,
/// bounded by the ask queue and the dialog, so neither applies.
///
/// # Errors
///
/// The row is gone or is another box ([`minimald_rpc::AskRefused::NoRow`]),
/// its stance is no longer `ask` ([`minimald_rpc::AskRefused::StanceNotAsk`]),
/// or its range no longer admits the port
/// ([`minimald_rpc::AskRefused::OutsideGrant`]). Nothing is recorded.
fn record_ask_yes(
    rows: &std::sync::RwLockReadGuard<'_, Rows>,
    facts: &AskFacts,
) -> Result<(), minimald_rpc::AskRefused> {
    let record = rows
        .get(&facts.switch_address.octets())
        .filter(|record| record.box_id == facts.box_id)
        .ok_or(minimald_rpc::AskRefused::NoRow)?;
    if record.dynamic_ingress() != DynamicIngress::Ask {
        return Err(minimald_rpc::AskRefused::StanceNotAsk);
    }
    if !in_range(record.dynamic_range(), facts.port) {
        return Err(minimald_rpc::AskRefused::OutsideGrant);
    }
    let reported = RuntimePort {
        port: facts.port,
        proto: facts.proto,
    };
    let mut runtime = record
        .runtime_ports
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !runtime.ports.contains(&reported) {
        runtime.ports.push(reported);
    }
    Ok(())
}

/// The writable half of the host-side table, held by the host process: the
/// registration surface — the host's own node-namespace row, and T66's
/// client-driven path — and the source of the read-only [`BoxTable`] the
/// gate reads.
///
/// Cheap to clone, and every clone shares the rows, the hand-out book,
/// and the withdrawal channel: the table the gate holds is the same one every
/// later registration lands in, which is how a box published after the gate
/// started is decided by its rules from that moment on, an address a
/// registration takes on one clone is never handed twice, and a report any
/// handle files reaches the one drainer. The subnet a registry is built with
/// fixes the address plan its rows compile against — the resolver the
/// carve-out is keyed to, the node address, and the runs the client-driven
/// allocation draws from — so it must be the same subnet the gate's switch
/// serves.
#[derive(Debug)]
pub struct BoxRegistry {
    subnet: SwitchSubnet,
    rows: Arc<RwLock<Rows>>,
    /// The switch addresses whose rows this daemon has marked stopped —
    /// namespaces whose declarations stay published while they are not
    /// running, keyed by the row's own key and shared by every clone.
    stopped: Arc<RwLock<BTreeSet<[u8; 4]>>>,
    /// The box names this daemon holds in the zone with no row behind them
    /// (the `host_ip` interim): a name held here answers NODATA under the
    /// zone apex where an unheld name answers NXDOMAIN. Keyed by the
    /// name's [`canonical_box_name`] form and shared by every clone; the
    /// [`Self::zone_view`] fold keeps a row's entry for a name a row
    /// publishes, so a hold never shadows a row. Each hold carries the
    /// session that made it, when its client named one, so a release
    /// frees only that session's hold, never a newer session's under the
    /// same name.
    held_names: Arc<RwLock<BTreeMap<String, Option<boxes::SessionId>>>>,
    /// The resident `host_ip` boxes' compiled egress, by session
    /// ([`Self::admit_host_ip_box`], NET-085), shared by every clone and
    /// every [`BoxTable`]: the union the gate decides a box-marked frame
    /// from the node address by.
    host_ip_boxes: Arc<RwLock<HostIpBoxes>>,
    /// The ids minted for `host_ip` boxes ([`Self::register_host_ip_box`],
    /// BEP-082), shared by every clone. A `host_ip` box has no row in the
    /// address table, so this map is the record of its id, each with the
    /// name it registered under: the collision check
    /// ([`Self::holds_box_id`]) reads it beside the rows, and the in-VM
    /// daemon's mint ask finds the id by that name
    /// ([`Self::host_ip_id_for`]). The name goes when the box retires or
    /// when a later registration takes the name, so an ended box's id never
    /// answers a new box's ask. The id itself stays until the VM host
    /// daemon restarts, for the collision check. The mint never draws the
    /// same UUIDv7 twice, so a kept id never refuses a new box.
    host_ip_ids: Arc<Mutex<HostIpIds>>,
    /// The held names reloaded from [`HELD_NAMES_FILE`] that no hold has
    /// re-made since, each with when it was reloaded: dropped once
    /// [`HELD_NAME_RECONFIRM_BOUND`] has passed
    /// ([`Self::expire_unconfirmed_holds`]). Changed only under the write
    /// of [`Self::held_names`], so a hold that re-confirms a name and the
    /// expiry that would drop it never interleave.
    unconfirmed_holds: Arc<Mutex<BTreeMap<String, Instant>>>,
    /// The table's change pings: one `()` to every live subscriber whenever
    /// a row lands, goes, or is marked stopped. The host answerer
    /// ([`crate::net::answerer`]) subscribes — a daemon that does not hold
    /// the answerer port re-registers its zone rows with the one that does
    /// on every change — and the zone-table dump does
    /// ([`crate::diag`]). Senders whose subscriber is gone are pruned on
    /// the next ping, so a dead subscriber is never held past one change.
    table_pings: Arc<Mutex<Vec<std::sync::mpsc::Sender<()>>>>,
    /// The row-withdrawal subscribers ([`BoxTable::subscribe_row_withdrawals`]):
    /// told the switch address of every row removed, whichever path removed
    /// it. The egress gate subscribes, to unbind a withdrawn box's forwards.
    row_withdrawals: RowWithdrawals,
    /// The addresses withdrawn boxes' revocations still hold against reuse
    /// ([`Revoking`]), shared by every clone and every [`BoxTable`].
    revoking: Arc<Revoking>,
    /// The book the client-driven allocation hands switch addresses from
    /// and returns them to ([`SwitchAddressBook`]), shared by every clone of
    /// this registry. Draws from the hand-out run — the plan run's upper
    /// half, above the daemon's self-allocation reserve (`hand_out_run`) —
    /// never from the reserve itself. A draw reads the rows while it holds
    /// the book, so the book is never taken while a row lock is held: every
    /// return lands after the row lock that removed the row is dropped.
    switch_book: Arc<Mutex<SwitchAddressBook>>,
    /// How far the tests have moved this registry's clock past the real
    /// one ([`Self::now`]), shared by every clone, so a quarantine is
    /// driven without waiting it out.
    #[cfg(test)]
    clock_skew: Arc<Mutex<Duration>>,
    /// The next published loopback address the tests' single-node
    /// allocation hands out, shared the same way. The daemon's addresses
    /// are the answerer's ([`Self::register_client_box_at`]).
    #[cfg(test)]
    next_loopback_addr: Arc<AtomicU32>,
    /// The loopback slice this subnet's switch publishes at, when the
    /// address plan serves it. A registry the plan does not serve cannot
    /// register a client box. `None` for a subnet the plan
    /// does not serve — such a registry still holds explicit registrations
    /// (the node's own row among them), it just cannot allocate for a
    /// client box.
    loopback_slice: Option<switch::LoopbackSlice>,
    /// The proxy's attachment table this registry feeds (NET-133), when the
    /// host handed one over: every box row published here is an attachment
    /// first and every row retired here retires its attachment with it.
    /// `None` for a registry that feeds no proxy — a table-less registry
    /// still publishes rows, it just gives no attachments.
    attachments: Option<crate::bep_attach::Attachments>,
    /// The record of pending asks (NET-045): the unresolved asks by their
    /// host-minted ids, each row's queue of them, and the attached host
    /// clients by the box id each subscribed to — shared by every clone,
    /// because the clients the doors register are the same clients every
    /// clone's offers must reach.
    asks: Arc<Mutex<AskBook>>,
    /// The ask verbs' connection gauges (NET-045), shared by every clone.
    ask_gauges: Arc<AskGauges>,
    /// The registrations in flight per box name, with the name's withdrawal
    /// generation ([`NameRegistrations`]), keyed by the name in
    /// [`canonical_box_name`] form: the answerer allocates per canonical
    /// name, so "Web" and "web" are one box here too. Shared by every clone, and
    /// bounded by the registrations in flight: an entry goes once its last
    /// registration ends.
    withdrawal_generations: Arc<Mutex<HashMap<String, NameRegistrations>>>,
    /// The client boxes' creations ([`Creation`]), keyed by the name's
    /// [`canonical_box_name`] form and shared by every clone: what a row
    /// is reinstated from at start and at its creator's resume. Taken
    /// inside the row lock when both are held — a creation is inserted,
    /// ended, and marked dormant under the same write of the row lock
    /// that publishes or removes its row — and never the other way round.
    creations: Arc<Mutex<Creations>>,
    /// Where the creations are persisted ([`Self::persisting_to`]), when
    /// this registry persists at all: the supervisor's does, in its VM's
    /// state dir; a test's need not.
    persisted_at: Option<Arc<std::path::PathBuf>>,
    /// Serializes the persisted file's writes, so the last write to land
    /// is of the newest creations, whichever handle wrote it.
    persist_turn: Arc<Mutex<()>>,
    /// The Box Egress Proxy's control socket, where the destroy of a live
    /// box with a credentialed lane records its revocation
    /// ([`submit_revocation`], BEP-043). `None` sends nothing. [`Self::new`]
    /// sets `None`, and only the daemon's start path sets the socket
    /// ([`Self::with_proxy_control`]).
    proxy_control: Option<Arc<std::path::PathBuf>>,
    /// The node row's mirrored binds for the host-address boxes
    /// ([`NodeMirror`], NET-138), shared by every clone.
    node_mirror: Arc<NodeMirror>,
}

/// The Box Egress Proxy's control socket, under the home directory.
const PROXY_CONTROL_SOCKET: &str = ".minimal/bep/control.sock";

/// The Box Egress Proxy control socket under the home directory, the one the
/// daemon's registry sends revocations to ([`BoxRegistry::with_proxy_control`]).
/// `None` on a host with no home directory.
pub fn home_proxy_control() -> Option<std::path::PathBuf> {
    std::env::home_dir().map(|home| home.join(PROXY_CONTROL_SOCKET))
}

/// How long a revocation waits for the proxy, for the connect and for each
/// reply.
const PROXY_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

/// How the box whose id [`spawn_revocation`] revokes came to its end. The
/// revocation thread's warnings name it, so a log reader sees which step
/// completed without the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoxEnd {
    /// The destroy of an own-address box.
    Destroy,
    /// The retire of a destroyed host_ip box. Only a destroy revokes: the
    /// retire of a stopped box sends no revocation (BEP-043).
    HostIpRetire,
}

impl BoxEnd {
    /// The words that open the revocation thread's warnings. The destroy
    /// keeps its text, which `scripts/session-e2e.sh` matches.
    fn completed(self) -> &'static str {
        match self {
            Self::Destroy => "the destroy completed",
            Self::HostIpRetire => "the box was destroyed",
        }
    }
}

/// Every id [`spawn_revocation`] was called for, in order. A test reads it
/// to know, with no wait, that a retire decided not to revoke.
#[cfg(test)]
static REVOCATIONS_SPAWNED: Mutex<Vec<BoxId>> = Mutex::new(Vec::new());

/// Whether [`spawn_revocation`] was called for `box_id`.
#[cfg(test)]
fn revocation_spawned(box_id: BoxId) -> bool {
    REVOCATIONS_SPAWNED
        .lock()
        .expect("the spawned revocations' lock is never held across a panic")
        .contains(&box_id)
}

/// Sends the revocation of `box_id` to the proxy at `path` on a thread of its
/// own, so the end of the box does not wait for it. A failure is one warning
/// that names the step that failed.
fn spawn_revocation(path: std::path::PathBuf, box_id: BoxId, end: BoxEnd) {
    #[cfg(test)]
    REVOCATIONS_SPAWNED
        .lock()
        .expect("the spawned revocations' lock is never held across a panic")
        .push(box_id);
    let spawned = std::thread::Builder::new()
        .name("bep-revocation".into())
        .spawn(move || {
            let submitted = submit_revocation(&path, box_id);
            let id = box_id_hex(box_id);
            let completed = end.completed();
            match (submitted.revoke, submitted.forget) {
                (Ok(()), Ok(())) => {}
                (Err(revoke), Ok(())) => tracing::warn!(
                    box_id = %id,
                    error = %revoke,
                    "{completed} without a revocation from the Box Egress Proxy: \
                     the proxy forgot the box, and the withdrawn attachment refuses its values"
                ),
                (Err(revoke), Err(forget)) => tracing::warn!(
                    box_id = %id,
                    revoke_error = %revoke,
                    forget_error = %forget,
                    "{completed} without a revocation from the Box Egress Proxy \
                     and without the proxy forgetting the box: the withdrawn attachment \
                     refuses its values"
                ),
                (Ok(()), Err(forget)) => tracing::warn!(
                    box_id = %id,
                    error = %forget,
                    "the Box Egress Proxy recorded the ended box's revocation but did not \
                     forget the box"
                ),
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(
            box_id = %box_id_hex(box_id),
            %error,
            "{} without a revocation: the revocation thread did not start",
            end.completed()
        );
    }
}

/// The box id as the proxy's control socket takes it: 32 lowercase hex
/// digits.
fn box_id_hex(box_id: BoxId) -> String {
    box_id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The outcome of each of the two requests of [`submit_revocation`].
struct Submitted {
    /// The `revoke_box` request's outcome.
    revoke: std::io::Result<()>,
    /// The `forget_box` request's outcome.
    forget: std::io::Result<()>,
}

/// Records the revocation of the live box `box_id` with the proxy's control
/// socket at `path`, then forgets the box there (BEP-043, BEP-067, T41).
/// Each request has a connection of its own, so `forget_box` is sent even
/// when `revoke_box` fails: the proxy then attributes the id to no live box.
fn submit_revocation(path: &std::path::Path, box_id: BoxId) -> Submitted {
    let id = box_id_hex(box_id);
    let revoke = send_control(path, "revoke_box", &id);
    if revoke.is_ok() {
        tracing::info!(
            box_id = %id,
            "recorded the ended box's revocation with the Box Egress Proxy"
        );
    }
    let forget = send_control(path, "forget_box", &id);
    Submitted { revoke, forget }
}

/// The source that already holds a minted box id ([`BoxRegistry::holds_box_id`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum IdHolder {
    /// A published row.
    LiveRow,
    /// A kept creation, live or dormant.
    KeptCreation,
    /// The proxy's attachment table.
    Attachment,
    /// A `host_ip` box's minted id ([`BoxRegistry::register_host_ip_box`]).
    HostIpBox,
    /// A revocation record the proxy retains.
    RevocationRecord,
    /// A revocation record in the proxy's audit log, read with no proxy
    /// running: the record's line, and the log's directory.
    AuditedRevocation {
        /// The record's line, as the log holds it.
        record: String,
        /// The directory of the log that holds the record.
        audit: std::path::PathBuf,
    },
}

impl IdHolder {
    /// The source's name in a log line.
    fn as_str(&self) -> &'static str {
        match self {
            IdHolder::LiveRow => "live row",
            IdHolder::KeptCreation => "kept creation",
            IdHolder::Attachment => "attachment",
            IdHolder::HostIpBox => "host_ip box",
            IdHolder::RevocationRecord => "revocation record",
            IdHolder::AuditedRevocation { .. } => "revocation record in the audit log",
        }
    }
}

/// The directory of the audit log that the proxy serving the control
/// socket at `control` writes: `audit` beside the socket. For the home
/// socket ([`home_proxy_control`]) that is `~/.minimal/bep/audit`, the
/// directory `bep serve` writes (`bep::audit::default_dir`).
fn proxy_audit_dir(control: &std::path::Path) -> std::path::PathBuf {
    control
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""))
        .join("audit")
}

/// The revocation record of `id` in the proxy's audit log in `audit`, when
/// one is there (BEP-070). These are the records a `bep serve` start puts
/// back in force ([`bep::revoke::restore`]), read here when no proxy runs.
/// A missing directory holds none.
///
/// # Errors
///
/// [`AllocationError::AuditUnread`] when the log is not read, or when a
/// complete line in it does not parse. That line can be the revocation of
/// `id`, so the check fails closed, as a `bep serve` start does.
fn audit_revocation_holding(
    audit: &std::path::Path,
    id: BoxId,
) -> Result<Option<IdHolder>, AllocationError> {
    let unread = |why: String| {
        tracing::warn!(
            box_id = %crate::bep_attach::BoxIdText(&id),
            audit = %audit.display(),
            why = %why,
            "refused a box registration: the Box Egress Proxy's audit log was not read whole, \
             so the box id check did not finish"
        );
        AllocationError::AuditUnread {
            id,
            audit: audit.display().to_string(),
            why,
        }
    };
    let batch = bep::audit::LogReader::new(audit)
        .read_new()
        .map_err(|error| unread(error.to_string()))?;
    let hex = box_id_hex(id);
    if let Some(entry) = batch.entries.into_iter().find(|entry| {
        entry.record.kind == bep::audit::Kind::Revocation
            && entry.record.subject.eq_ignore_ascii_case(&hex)
    }) {
        return Ok(Some(IdHolder::AuditedRevocation {
            record: entry.line,
            audit: audit.to_path_buf(),
        }));
    }
    if batch.skipped > 0 {
        let segments: Vec<String> = batch
            .skipped_in
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        let lines = if batch.skipped == 1 {
            "1 line".to_owned()
        } else {
            format!("{} lines", batch.skipped)
        };
        // `bep serve --quarantine-unreadable` moves those segments aside and
        // records again the revocations it reads there (BEP-068), so the
        // refusal names it as the way out.
        return Err(unread(format!(
            "{lines} in {} did not parse, and a line that does not parse can record a destroyed \
             box. To move those segments into {} and start the proxy, run `bep serve` with \
             `--quarantine-unreadable`",
            segments.join(", "),
            audit.join(bep::audit::QUARANTINE_DIR).display()
        )));
    }
    Ok(None)
}

/// The box ids the revocations in force at the proxy's control socket at
/// `path` name, as 32 lowercase hex digits: the ones the proxy restored
/// from its audit log at start and the ones recorded since (BEP-070).
///
/// # Errors
///
/// The I/O error of the connect, the write or the read, or a refusal the
/// proxy replied with.
fn proxy_revoked_box_ids(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    let reply = exchange_control(
        path,
        "revoked_box_ids",
        &serde_json::json!({ "op": "revoked_box_ids" }),
    )?;
    let reply: bep::control::RevokedBoxIdsReply =
        serde_json::from_value(reply).map_err(std::io::Error::other)?;
    Ok(reply
        .box_ids
        .into_iter()
        .map(|id| id.to_ascii_lowercase())
        .collect())
}

/// How long [`BoxRegistry::send_live_boxes`] waits for the proxy's control
/// socket to take connections. `bep serve` binds it just after its
/// listener, the socket whose appearance starts the send.
const LIVE_BOXES_WAIT: Duration = Duration::from_secs(10);

impl BoxRegistry {
    /// The id of every box this registry holds, a live row or a kept
    /// creation, as 32 lowercase hex digits, each once.
    pub fn live_box_ids(&self) -> Vec<String> {
        let mut ids: BTreeSet<String> = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .map(|record| box_id_hex(record.box_id))
            .collect();
        ids.extend(
            self.creations()
                .all()
                .map(|creation| box_id_hex(creation.id())),
        );
        ids.into_iter().collect()
    }

    /// Names every box this registry holds to the proxy's control socket,
    /// in one `live_boxes` request (BEP-063, #2617). The proxy then frees
    /// the client key of each box it kept from before its start that is not
    /// in the list: a box that ended with no `forget_box`. It retries the
    /// connect for [`LIVE_BOXES_WAIT`] while no proxy takes it. With no
    /// control socket set, it sends nothing.
    pub fn send_live_boxes(&self) {
        let Some(path) = self.proxy_control.as_deref() else {
            return;
        };
        let ids = self.live_box_ids();
        let count = ids.len();
        let request = serde_json::json!({ "op": "live_boxes", "box_ids": ids });
        let deadline = Instant::now() + LIVE_BOXES_WAIT;
        loop {
            match exchange_control(path, "live_boxes", &request) {
                Ok(_) => {
                    tracing::info!(
                        boxes = count,
                        "named the live boxes to the Box Egress Proxy"
                    );
                    return;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "the Box Egress Proxy did not take the live box list: a client key of \
                         a box that ended with no forget stays in use until the next start"
                    );
                    return;
                }
            }
        }
    }
}

/// Sends one `op` request for the box id `id` to the proxy's control socket
/// at `path`, and reads its reply. The protocol is one JSON object per line
/// each way.
///
/// # Errors
///
/// The I/O error of the connect, the write or the read, or a refusal the
/// proxy replied with.
fn send_control(path: &std::path::Path, op: &str, id: &str) -> std::io::Result<()> {
    exchange_control(path, op, &serde_json::json!({ "op": op, "box_id": id })).map(|_| ())
}

/// Sends the `op` request line `request` to the proxy's control socket at
/// `path`, and reads its reply.
///
/// # Errors
///
/// The I/O error of the connect, the write or the read, or a refusal the
/// proxy replied with.
fn exchange_control(
    path: &std::path::Path,
    op: &str,
    request: &serde_json::Value,
) -> std::io::Result<serde_json::Value> {
    use std::io::{BufRead as _, Write as _};

    let stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_read_timeout(Some(PROXY_CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(PROXY_CONTROL_TIMEOUT))?;
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = request.to_string();
    line.push('\n');
    writer.write_all(line.as_bytes())?;
    let mut reply = String::new();
    if reader.read_line(&mut reply)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the proxy closed the control connection",
        ));
    }
    let reply: serde_json::Value = serde_json::from_str(&reply).map_err(std::io::Error::other)?;
    if reply.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let why = reply
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no reason given");
        return Err(std::io::Error::other(format!(
            "the proxy refused {op}: {why}"
        )));
    }
    Ok(reply)
}

/// A clone shares the live rows, the hand-out book, and the withdrawal
/// channel but not the receiver: only the registry that created the channel —
/// the one [`Self::spawn_withdrawal_drainer`] (or a test) drains — holds the
/// receiving end, so a clone can register, allocate, and file reports like
/// the original but has nothing to take.
impl Clone for BoxRegistry {
    fn clone(&self) -> Self {
        BoxRegistry {
            subnet: self.subnet,
            rows: self.rows.clone(),
            stopped: Arc::clone(&self.stopped),
            held_names: Arc::clone(&self.held_names),
            host_ip_boxes: Arc::clone(&self.host_ip_boxes),
            host_ip_ids: Arc::clone(&self.host_ip_ids),
            unconfirmed_holds: Arc::clone(&self.unconfirmed_holds),
            table_pings: Arc::clone(&self.table_pings),
            row_withdrawals: Arc::clone(&self.row_withdrawals),
            revoking: Arc::clone(&self.revoking),
            switch_book: Arc::clone(&self.switch_book),
            #[cfg(test)]
            clock_skew: Arc::clone(&self.clock_skew),
            #[cfg(test)]
            next_loopback_addr: Arc::clone(&self.next_loopback_addr),
            loopback_slice: self.loopback_slice,
            attachments: self.attachments.clone(),
            asks: Arc::clone(&self.asks),
            ask_gauges: Arc::clone(&self.ask_gauges),
            withdrawal_generations: Arc::clone(&self.withdrawal_generations),
            creations: Arc::clone(&self.creations),
            persisted_at: self.persisted_at.clone(),
            persist_turn: Arc::clone(&self.persist_turn),
            proxy_control: self.proxy_control.clone(),
            node_mirror: Arc::clone(&self.node_mirror),
        }
    }
}

impl BoxRegistry {
    /// An empty registry for a switch serving `subnet`. Every row registered
    /// here compiles its lease from its own switch address and the resolver
    /// carve-out from this subnet, so `subnet` must be the one the switch was
    /// configured with.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        let loopback_slice = switch::AddressPlan::default().loopback_slice_for_switch(subnet);
        Self {
            subnet,
            rows: Arc::new(RwLock::new(BTreeMap::new())),
            stopped: Arc::new(RwLock::new(BTreeSet::new())),
            held_names: Arc::new(RwLock::new(BTreeMap::new())),
            host_ip_boxes: Arc::new(RwLock::new(HostIpBoxes::default())),
            host_ip_ids: Arc::new(Mutex::new(HostIpIds::default())),
            unconfirmed_holds: Arc::new(Mutex::new(BTreeMap::new())),
            table_pings: Arc::new(Mutex::new(Vec::new())),
            row_withdrawals: Arc::new(Mutex::new(Vec::new())),
            revoking: Arc::new(Revoking::default()),
            switch_book: Arc::new(Mutex::new(SwitchAddressBook::new(subnet))),
            #[cfg(test)]
            clock_skew: Arc::new(Mutex::new(Duration::ZERO)),
            #[cfg(test)]
            next_loopback_addr: Arc::new(AtomicU32::new(
                loopback_slice.map_or(0, |slice| box_loopback_run(slice).0),
            )),
            loopback_slice,
            attachments: None,
            asks: Arc::new(Mutex::new(AskBook::default())),
            ask_gauges: Arc::new(AskGauges::default()),
            withdrawal_generations: Arc::new(Mutex::new(HashMap::new())),
            creations: Arc::new(Mutex::new(Creations::default())),
            persisted_at: None,
            persist_turn: Arc::new(Mutex::new(())),
            proxy_control: None,
            node_mirror: Arc::new(NodeMirror::new(subnet.daemon_ip())),
        }
    }

    /// Sets the Box Egress Proxy control socket that a live box's destroy
    /// sends its revocation to. `None` sends none. Returns `self`, for the
    /// caller's chain.
    #[must_use]
    pub fn with_proxy_control(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.proxy_control = path.map(Arc::new);
        self
    }

    /// The Box Egress Proxy control socket this registry sends a live box's
    /// revocation to, if any ([`Self::with_proxy_control`]).
    pub fn proxy_control(&self) -> Option<&std::path::Path> {
        self.proxy_control
            .as_deref()
            .map(std::path::PathBuf::as_path)
    }

    /// Start a registration of box `name`: count it in flight and read the
    /// name's withdrawal generation, before the answerer allocates its
    /// address. The claim is held until the registration's turn ends, and
    /// its drop ends the count — on success, refusal and panic alike.
    #[must_use]
    pub fn begin_registration(&self, name: &str) -> RegistrationClaim {
        let key = canonical_box_name(name);
        let mut generations = self.generations();
        let entry = generations.entry(key.clone()).or_default();
        entry.in_flight = entry.in_flight.saturating_add(1);
        let generation = entry.generation;
        RegistrationClaim {
            generations: Arc::clone(&self.withdrawal_generations),
            key,
            generation,
        }
    }

    /// Box `name`'s withdrawal generation, as an in-flight registration
    /// compares it to the one its claim read. A name with no registration
    /// in flight reads 0.
    fn withdrawal_generation(&self, name: &str) -> u64 {
        self.generations()
            .get(&canonical_box_name(name))
            .map_or(0, |entry| entry.generation)
    }

    /// Bump box `name`'s withdrawal generation. Every withdrawal path calls
    /// it under the row lock it withdraws under, so a registration's check
    /// under the same lock sees every withdrawal ordered before it. A name
    /// with no registration in flight has nobody to tell, so nothing is
    /// kept for it.
    fn bump_withdrawal_generation(&self, name: &str) {
        if let Some(entry) = self.generations().get_mut(&canonical_box_name(name)) {
            entry.generation = entry.generation.wrapping_add(1);
        }
    }

    /// Hand a refused registration's address back to the answerer, by
    /// running `release`, unless something else owns it: a live row under
    /// the claim's name, or another registration of the name still in
    /// flight — names compared in [`canonical_box_name`] form, the form the
    /// answerer holds the address under. The answerer allocates per name, so either one holds the
    /// very address a release by name would free. Decided under the row
    /// lock and the generations' lock, and `release` runs under both, so no
    /// registration of the name can start between the decision and the
    /// release. Returns whether `release` ran.
    pub fn release_unless_owned(&self, claim: &RegistrationClaim, release: impl FnOnce()) -> bool {
        self.release_unless_owned_past(&claim.key, 1, release)
    }

    /// Hand a withdrawn box's address back to the answerer, by running
    /// `release`, unless something else owns it: [`Self::release_unless_owned`]
    /// for a withdrawal, which holds no registration of its own, so every
    /// registration of the name in flight counts as another owner. Returns
    /// whether `release` ran.
    pub fn release_withdrawn_unless_owned(&self, name: &str, release: impl FnOnce()) -> bool {
        self.release_unless_owned_past(&canonical_box_name(name), 0, release)
    }

    /// The one locked decision both releases take: under the row lock and
    /// then the generations' lock, `release` runs unless a live row or a
    /// kept creation holds `key` — a dormant creation's published address
    /// stays reserved for its resume ([`Creation`]) — or more than `own`
    /// registrations of it are in flight.
    fn release_unless_owned_past(&self, key: &str, own: u32, release: impl FnOnce()) -> bool {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let generations = self.generations();
        let row_holds = rows
            .values()
            .any(|record| canonical_box_name(&record.name()) == key);
        let others_in_flight = generations
            .get(key)
            .map_or(0, |entry| entry.in_flight.saturating_sub(own));
        if row_holds || others_in_flight > 0 || self.creations().holds_name(key) {
            return false;
        }
        release();
        true
    }

    /// Whether the registry keeps an entry for box `name`: only while a
    /// registration of it is in flight.
    #[cfg(test)]
    pub(crate) fn tracks_registrations_of(&self, name: &str) -> bool {
        self.generations().contains_key(&canonical_box_name(name))
    }

    fn generations(&self) -> MutexGuard<'_, HashMap<String, NameRegistrations>> {
        lock_generations(&self.withdrawal_generations)
    }

    /// Hands this registry the proxy's attachment table to feed
    /// (NET-133): from here on every box row it publishes is an attachment
    /// issued ahead of the row — the proxy holds the box before its first
    /// connection could arrive — and every row it retires takes the
    /// attachment with it, ahead of the row's own removal. Returns `self`,
    /// for the supervisor's call chain.
    ///
    /// The table is the host's own; feeding it is the registry's one write
    /// path, so the attachments stay sourced from the host-side creator
    /// alone: nothing the guest says reaches either table (NET-138's
    /// boundary, which NET-133 borrows for the proxy).
    #[must_use]
    pub fn feeding_proxy_attachments(
        mut self,
        attachments: crate::bep_attach::Attachments,
    ) -> Self {
        self.attachments = Some(attachments);
        self
    }

    /// Persists this registry's client-box creations at `path` — the
    /// supervisor passes [`REGISTRY_FILE`] in its VM's state dir — and
    /// reloads what a previous run persisted there first. Returns `self`,
    /// for the supervisor's call chain, and is the chain's last link: a
    /// reloaded row is compiled under the egress default and issues its
    /// proxy attachment exactly as a registration does, so both must be
    /// set before.
    ///
    /// Every creation whose row stood at the last write is reinstated at
    /// its own addresses with its own box id, compiled from its creator's
    /// declaration as a registration is, and awaits its box's first frame
    /// under [`RESUME_ATTACH_BOUND`] from this instant ([`RowLiveness`]):
    /// the VM the row's box ran in ended with the previous run, so the
    /// box's host is not launched in the new VM until the guest daemon
    /// starts, and the row is withdrawn once the bound passes unless the
    /// box's shuttle carries a frame from its address again. A resume
    /// does not extend that bound; once the row has gone, its creator's
    /// resume reinstates it ([`Self::resume_client_box`]). A
    /// dormant creation stays dormant. The hand-out book takes every
    /// creation's switch and task addresses, dormant ones' included, so a
    /// fresh book hands none of them to a new box; their quarantine is not
    /// persisted ([`SwitchAddressBook`]). A creation whose addresses the
    /// book will not give — an address outside the run, or one an earlier
    /// entry took — is dropped and said as a warn line; one whose row
    /// cannot be published is kept dormant, its addresses reserved. A
    /// creation at a loopback address an earlier entry already holds is
    /// dropped the same way, named with the box that holds it: two creations
    /// at one address would each answer for it when they resume.
    ///
    /// The file is written after every change to the creations: mode 0600,
    /// written to a temporary file and renamed over the last
    /// ([`write_registry_file`]), versioned ([`REGISTRY_FILE_VERSION`]).
    /// A write that fails is a warn line, and the creations stay held in
    /// this process: the rows decide frames from memory, and the file only
    /// outlives the process. A file found unusable is set aside, never
    /// written over ([`read_registry_file`]); when it cannot be, this
    /// registry persists nothing.
    ///
    /// The held box names ([`Self::hold_box_name`]) persist the same way
    /// to [`HELD_NAMES_FILE`] beside `path`, written after every change to
    /// them, and are reloaded from it here ([`read_held_names_file`]), so
    /// a restarted daemon still knows which session holds which name. A
    /// reloaded hold stands unconfirmed until a hold re-makes it, and one
    /// nothing re-makes within [`HELD_NAME_RECONFIRM_BOUND`] is dropped
    /// ([`Self::expire_unconfirmed_holds`]): a session that ended without
    /// its release does not keep its name answering NODATA for good.
    #[must_use]
    pub fn persisting_to(mut self, path: std::path::PathBuf) -> Self {
        let Some(loaded) = read_registry_file(&path) else {
            return self;
        };
        let now = self.now();
        {
            let mut held = self.held_names.write().expect(
                "the held names' lock is never held across a panic, so it cannot be poisoned",
            );
            *held = read_held_names_file(&path.with_file_name(HELD_NAMES_FILE));
            *self.unconfirmed_holds() = held.keys().map(|name| (name.clone(), now)).collect();
        }
        {
            // BEP-043: a reloaded id is held for the collision check, and a
            // reloaded credentialed id is revoked at its box's destroy.
            let reloaded = read_host_ip_ids_file(&path.with_file_name(HOST_IP_IDS_FILE));
            tracing::info!(
                minted = reloaded.ids.len(),
                credentialed = reloaded.credentialed.len(),
                "reloaded the persisted host_ip box ids"
            );
            *self.host_ip_id_set() = reloaded;
        }
        self.persisted_at = Some(Arc::new(path));
        let mut held_loopbacks = std::collections::BTreeMap::new();
        // Every creation loads dormant. A start of this process is a boot
        // of the VM, so no box of an earlier run is running, and a row
        // comes back when its creator resumes the box.
        for creation in loaded {
            let key = canonical_box_name(&creation.name);
            // A second creation under a name is a superseded one: it is
            // kept, resumable by its box id.
            let superseded = self.creations().contains_key(&key);
            // A loopback address is one creation's while its creation is
            // kept: the file is only ever written by this registry, but a
            // second creation at the same address — from an interrupted
            // moment or an older run — would put two boxes at it, and the
            // one that resumes second would find its address held by the
            // first, as a duplicate switch address would.
            // A superseded creation can share its loopback address with the
            // creation that took its name: the answerer keys that address by
            // the name, and only one of them can have a row at a time.
            if let Some(holder) = held_loopbacks
                .get(&creation.loopback_address)
                .filter(|holder: &&String| canonical_box_name(holder) != key)
            {
                tracing::warn!(
                    box = %creation.name,
                    held = %holder,
                    held_loopback = %creation.loopback_address,
                    "the persisted box registry holds a loopback address twice; \
                     reloading the first only"
                );
                continue;
            }
            // Every creation, dormant ones included, holds its switch and
            // task addresses: a fresh book hands none of them to a new box.
            if let Err(addr) = self.take_creation_addrs(&creation, now) {
                tracing::warn!(
                    box = %creation.name,
                    %addr,
                    "could not reload a persisted box: one of its switch addresses is not the \
                     hand-out run's to give it; its creation is dropped"
                );
                continue;
            }
            held_loopbacks
                .entry(creation.loopback_address)
                .or_insert_with(|| creation.name.clone());
            if superseded {
                self.creations().superseded.push(creation);
                continue;
            }
            self.creations().insert(key, creation);
        }
        self.persist();
        self
    }

    /// Takes every switch address `creation` holds — its box's and each of
    /// its task addresses — from the hand-out book, all or none: on the
    /// first one the book will not give, the ones taken go back, and that
    /// address is the error.
    fn take_creation_addrs(&self, creation: &Creation, now: Instant) -> Result<(), Ipv4Addr> {
        let mut book = self.switch_book();
        let addrs =
            std::iter::once(creation.switch_address).chain(creation.task_addresses.iter().copied());
        let mut taken = Vec::new();
        for addr in addrs {
            if !book.take(addr, now, creation.id()) {
                for addr in taken {
                    book.give_back(addr, now, false, creation.id());
                }
                return Err(addr);
            }
            taken.push(addr);
        }
        Ok(())
    }

    /// Returns every switch address `creation` holds to the hand-out book:
    /// its creator withdrew a dormant box. Quarantined, as a row that was
    /// attributed returns its address: a dormant creation's row stood once.
    fn give_back_creation_addrs(&self, creation: &Creation) {
        for addr in
            std::iter::once(creation.switch_address).chain(creation.task_addresses.iter().copied())
        {
            self.give_back_switch_addr(addr, true, creation.id());
        }
    }

    fn creations(&self) -> MutexGuard<'_, Creations> {
        self.creations
            .lock()
            .expect("the creations' lock is never held across a panic")
    }

    /// The zone rows of every dormant creation — its name under the zone,
    /// and the loopback address it was created with, unanswerable until its
    /// box resumes ([`Self::resume_client_box`]). The rows the table itself
    /// publishes ([`Self::zone_view`]) hold only what stands: a creation
    /// whose row was withdrawn is invisible to them, so a restarted
    /// answerer's book would not know its address is taken and could hand
    /// it to a new box — the address this fold keeps claimed.
    #[must_use]
    pub fn dormant_creation_rows(&self) -> Vec<(String, Ipv4Addr)> {
        self.creations()
            .all()
            .filter(|creation| !creation.standing)
            .map(|creation| (zone_name(&creation.name), creation.loopback_address))
            .collect()
    }

    /// Writes the creations to the persisted file, when this registry
    /// persists ([`Self::persisting_to`]). Called after every change to
    /// them, with no row lock held; the snapshot is taken inside the
    /// write's turn, so the last write to land holds the newest creations.
    fn persist(&self) {
        let Some(path) = &self.persisted_at else {
            return;
        };
        let _turn = self
            .persist_turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file = RegistryFile {
            version: REGISTRY_FILE_VERSION,
            boxes: self.creations().all().cloned().collect(),
        };
        if let Err(error) = write_registry_file(path, &file) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not persist the box registry; its rows will not survive this process"
            );
        }
    }

    /// Writes the held box names to [`HELD_NAMES_FILE`] beside the
    /// persisted registry, when this registry persists
    /// ([`Self::persisting_to`]). Called after every change to them, with
    /// the held names' lock released; the snapshot is taken inside the
    /// write's turn, so the last write to land holds the newest holds. A
    /// write that fails is a warn line, and the holds stay in this
    /// process.
    fn persist_held_names(&self) {
        let Some(path) = &self.persisted_at else {
            return;
        };
        let path = path.with_file_name(HELD_NAMES_FILE);
        let _turn = self
            .persist_turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file = HeldNamesFile {
            version: HELD_NAMES_FILE_VERSION,
            held_names: self
                .held_names
                .read()
                .expect(
                    "the held names' lock is never held across a panic, so it cannot be poisoned",
                )
                .clone(),
        };
        if let Err(error) = write_registry_file(&path, &file) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not persist the held box names; they will not survive this process"
            );
        }
    }

    /// Writes the minted `host_ip` box ids and the credentialed ones to
    /// [`HOST_IP_IDS_FILE`]. Call it with no lock on the id set held.
    fn persist_host_ip_ids(&self) {
        let Some(path) = &self.persisted_at else {
            return;
        };
        let path = path.with_file_name(HOST_IP_IDS_FILE);
        let _turn = self
            .persist_turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file = {
            let ids = self.host_ip_id_set();
            HostIpIdsFile {
                version: HOST_IP_IDS_FILE_VERSION,
                ids: ids
                    .ids
                    .iter()
                    .copied()
                    .map(boxes::BoxId::from_bytes)
                    .collect(),
                credentialed: ids
                    .credentialed
                    .iter()
                    .copied()
                    .map(boxes::BoxId::from_bytes)
                    .collect(),
            }
        };
        if let Err(error) = write_registry_file(&path, &file) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not persist the host_ip box ids; they will not survive this process"
            );
        }
    }

    /// Marks `record`'s creation dormant, when the record is the
    /// creation's row: its row is gone, and its addresses stay reserved
    /// for it ([`Creation`]). Called
    /// under the row lock that removed the row. Returns whether a creation
    /// changed.
    fn creation_rowless(&self, record: &BoxRecord) -> bool {
        let mut creations = self.creations();
        match creations.get_mut(&canonical_box_name(&record.name())) {
            Some(creation) if creation.id() == record.box_id && creation.standing => {
                creation.standing = false;
                true
            }
            _ => false,
        }
    }

    /// The subnet this registry's rows are addressed on.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// The instant the hand-out book draws and returns at: the real clock,
    /// moved by [`Self::advance_clock`] in tests.
    fn now(&self) -> Instant {
        #[cfg(test)]
        {
            let skew = *self
                .clock_skew
                .lock()
                .expect("the test clock's lock is held only across a read or an add");
            Instant::now()
                .checked_add(skew)
                .expect("a test moves the clock by minutes, never past the clock's range")
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    /// Moves this registry's clock, and every clone's, `by` past the real
    /// one: the seam that drives the hand-out quarantine in tests.
    #[cfg(test)]
    pub(crate) fn advance_clock(&self, by: Duration) {
        let mut skew = self
            .clock_skew
            .lock()
            .expect("the test clock's lock is held only across a read or an add");
        *skew = skew.saturating_add(by);
    }

    fn switch_book(&self) -> MutexGuard<'_, SwitchAddressBook> {
        self.switch_book
            .lock()
            .expect("the hand-out book's lock is never held across a panic")
    }

    /// Draws a switch address from the hand-out book ([`SwitchAddressBook`]):
    /// a returned address only once it is eligible and no row and no
    /// withdrawn box's revocation holds it.
    fn draw_switch_addr(&self) -> Result<Ipv4Addr, AllocationError> {
        let now = self.now();
        let mut book = self.switch_book();
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        book.draw(now, |addr| {
            rows.contains_key(&addr.octets())
                || self.revoking.first_held(&[addr.octets()]).is_some()
        })
        .map_err(AllocationError::SwitchExhausted)
    }

    /// Draws a task address from the hand-out book, as [`Self::draw_switch_addr`]
    /// draws a box's, but only while the book could still hand more than
    /// [`TASK_SLOT_FLOOR`] addresses: `None` once a task slot would eat into
    /// what new boxes need, or the book hands nothing.
    fn draw_task_addr(&self) -> Option<Ipv4Addr> {
        let now = self.now();
        let mut book = self.switch_book();
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let held = |addr: Ipv4Addr| {
            rows.contains_key(&addr.octets())
                || self.revoking.first_held(&[addr.octets()]).is_some()
        };
        if book.spare(now, held) <= TASK_SLOT_FLOOR {
            return None;
        }
        book.draw(now, held).ok()
    }

    /// Returns a removed row's switch address to the hand-out book:
    /// quarantined when the row was ever attributed
    /// ([`BoxRecord::was_attributed`]), at once when no frame of its box
    /// ever crossed the gate. Called after the row lock that removed it is
    /// dropped. An address the book did not draw is not returned.
    fn give_back_switch_addr(&self, addr: Ipv4Addr, quarantine: bool, returned_by: BoxId) {
        let now = self.now();
        self.switch_book()
            .give_back(addr, now, quarantine, returned_by);
    }

    /// How many hand-out addresses are out: drawn for a row that stands or
    /// a registration in flight.
    #[cfg(test)]
    pub(crate) fn live_switch_addrs(&self) -> usize {
        self.switch_book().out.len()
    }

    /// The returned hand-out addresses, oldest return first, each with
    /// whether it is eligible to be handed again now.
    #[cfg(test)]
    pub(crate) fn returned_switch_addrs(&self) -> Vec<(Ipv4Addr, bool)> {
        let now = self.now();
        self.switch_book()
            .free
            .iter()
            .map(|&(addr, eligible, _)| (Ipv4Addr::from(addr), now >= eligible))
            .collect()
    }

    /// Publishes one namespace: compiles the declaration into a row keyed by
    /// its switch address — the lease the shared verdict checks every
    /// frame's source against (NET-084) — and returns it. Registering an
    /// address that is already published replaces that row with the newest
    /// declaration, whatever it holds: the table compares no policy against
    /// the row it holds — a rule set's absent dimensions are allow-all, so
    /// there is not even a widest one to rank against — and a re-registration
    /// can widen a namespace's reach as readily as narrow it. Whether a
    /// re-declaration may widen is the registering side's contract to enforce
    /// (T66's client-driven path, which decides whether re-declaring a live
    /// namespace is even possible); what this table enforces is NET-138's
    /// boundary — only the host process holding this registry can publish at
    /// all, so nothing inside the VM can change a row behind the gate's back.
    ///
    /// A row that declared DNS hosts carries those names in the row itself
    /// ([`BoxRecord::allow_dns_hosts`]), beside the rules: the name-based
    /// admission is decided against them, on the host, by the gate's DNS
    /// admission table ([`crate::net::dns_pins`]).
    ///
    /// # Errors
    ///
    /// [`AllocationError::RevocationPending`] when the registration's switch
    /// address, or its per-box published loopback address, is still held by
    /// a withdrawn box's revocation ([`RowWithdrawal`], design §7.1). The
    /// check and the insert happen under one write of the row lock, and a
    /// withdrawal takes its hold under the same lock, so no row can land at
    /// an address between its withdrawal and the end of its revocation. A
    /// refused registration leaves nothing behind: no row and no attachment.
    ///
    /// # Panics
    ///
    /// Never: the row lock is only ever held across this map update, never
    /// across a panic.
    pub fn try_register(
        &self,
        registration: BoxRegistration,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.try_register_since(registration, None, None)
    }

    /// [`Self::try_register`], refused with
    /// [`AllocationError::WithdrawnWhileAllocating`] when `generation` is
    /// given and the box name's withdrawal generation is no longer it. The
    /// check runs under the row lock every withdrawal bumps the generation
    /// under, before anything is published. `creation`, for a client box,
    /// is kept — replacing any creation under the name — under the same
    /// write of the row lock that publishes the row, and persisted after.
    fn try_register_since(
        &self,
        registration: BoxRegistration,
        generation: Option<u64>,
        creation: Option<Creation>,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        // The box's own id (BEP-070): the one a client-driven registration
        // minted and checked ([`Self::register_client_box_at`]), or a fresh
        // UUIDv7 minted here for this creation — never a counter, never a
        // digest of the declaration below, never one a client presented.
        // Minted once, before anything else, so the row and the attachment
        // it issues hold the one identity this registration created the
        // box with.
        let box_id = registration
            .box_id
            .unwrap_or_else(crate::bep_attach::mint_box_id);
        // The dynamic-ingress grant (NET-045, NET-138): the stance and range
        // the host holds every runtime port report against, from the same
        // create inputs the session record holds. Absent is deny with no
        // range — the row a pre-grant client registers admits no runtime
        // port.
        let dynamic_ingress = registration.dynamic_ingress.unwrap_or(DynamicIngress::Deny);
        let dynamic_range = registration.dynamic_allowed_range;
        // The box's task rows: its task addresses, each under the box's id.
        // A task run publishes nothing and has no grant of its own.
        let task_rows: Vec<Arc<BoxRecord>> = registration
            .task_addrs
            .iter()
            .map(|&task_addr| {
                Arc::new(BoxRecord {
                    name: RwLock::new(Arc::from(registration.name.as_str())),
                    box_id,
                    switch_addr: task_addr,
                    loopback_addr: registration.loopback_addr,
                    admitted_ports: Vec::new(),
                    declared_names: Vec::new(),
                    credentialed_upstream: false,
                    dynamic_ingress: DynamicIngress::Deny,
                    dynamic_range: None,
                    runtime_ports: Mutex::new(RowRuntime::default()),
                    used: std::sync::atomic::AtomicBool::new(false),
                    task_row_of: Some(registration.switch_addr),
                    task_addrs: Vec::new(),
                })
            })
            .collect();
        let record = Arc::new(BoxRecord {
            name: RwLock::new(Arc::from(registration.name)),
            box_id,
            credentialed_upstream: registration.credentialed_upstream.is_some(),
            dynamic_ingress,
            dynamic_range,
            // A row starts with no run-time ports. A registration at the
            // same address starts the set empty again.
            runtime_ports: Mutex::new(RowRuntime::default()),
            used: std::sync::atomic::AtomicBool::new(false),
            switch_addr: registration.switch_addr,
            loopback_addr: registration.loopback_addr,
            admitted_ports: registration.admitted_ports,
            declared_names: registration.declared_names,
            task_row_of: None,
            task_addrs: registration.task_addrs,
        });
        // NET-133: the box's proxy attachment is issued from the row's own
        // host facts — the name, both addresses, and the box's own id
        // minted above — and issued **before** the row is visible, so the
        // proxy holds the box ahead of its first connection: the box-egress
        // pool's listeners are partitioned by rows, a delivered connection
        // can only exist once the row made the box a share, and the share
        // comes a pool turn after the row. The guest node's own namespace
        // is not a box: its row buys no share in the pool (the same one
        // address `RegisteredBoxes` excludes) and no attachment either —
        // the plan keeps that address outside the run every client box is
        // handed from, so excluding it names exactly the node row.
        //
        // Both happen under the row lock, after the revocation check: a
        // withdrawal takes its hold under the same lock, so an address is
        // either still a live row's or held until its revocation ends.
        #[expect(
            clippy::unwrap_in_result,
            reason = "the expect is the lock's poison guard, not this function's error \
                      handling: the row lock is never held across a panic, so it cannot be \
                      poisoned"
        )]
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let held_against = std::iter::once(&record)
            .chain(&task_rows)
            .flat_map(|row| row.revocation_addrs())
            .collect::<Vec<_>>();
        if let Some(held) = self.revoking.first_held(&held_against) {
            drop(rows);
            let addr = Ipv4Addr::from(held);
            tracing::warn!(
                box = %record.name(),
                %addr,
                "refused a box registration at an address a withdrawn box's revocation still holds"
            );
            return Err(AllocationError::RevocationPending { addr });
        }
        if generation.is_some_and(|read| read != self.withdrawal_generation(&record.name())) {
            drop(rows);
            return Err(AllocationError::WithdrawnWhileAllocating);
        }
        if let Some(attachments) = &self.attachments
            && record.switch_addr != self.subnet.daemon_ip()
        {
            attachments.issue(
                &record.name(),
                record.box_id(),
                record.switch_addr,
                record.loopback_addr,
                record.declares_credentialed_upstream(),
            );
        }
        rows.insert(record.switch_addr.octets(), Arc::clone(&record));
        for task in &task_rows {
            rows.insert(task.switch_addr.octets(), Arc::clone(task));
        }
        // Under the write that published the rows: a relay that reads the
        // new epoch finds them ([`BoxTable::carry`]).
        let created = creation.is_some();
        // BOX-004: a registration under a dormant creation's name takes the
        // name over. The creation it replaces is superseded, not ended: it
        // keeps its addresses and its id, so its creator can resume it by
        // that id once no live row holds the name. A superseded creation
        // that resumes is the name's own again.
        let replaced = creation.and_then(|creation| {
            let id = creation.id();
            let mut creations = self.creations();
            creations.superseded.retain(|kept| kept.id() != id);
            let old = creations
                .insert(canonical_box_name(&creation.name), creation)
                .filter(|old| old.id() != id && !old.standing)?;
            let replaced = (old.name.clone(), old.id());
            creations.superseded.push(old);
            Some(replaced)
        });
        drop(rows);
        if let Some((name, old_id)) = &replaced {
            tracing::info!(
                box = %name,
                replaced = %crate::bep_attach::BoxIdText(old_id),
                by = %crate::bep_attach::BoxIdText(&record.box_id()),
                "a new box took over a stopped box's name; the stopped box keeps its creation \
                 and its addresses, and resumes by its box id once no running box holds the name"
            );
        }
        if created {
            self.persist();
        }
        // The newest declaration is a namespace that is running: whatever
        // stopped mark the address carried is stale now, and the change is
        // a ping every subscriber re-derives from.
        self.stopped
            .write()
            .expect("the stopped set's lock is never held across a panic, so it cannot be poisoned")
            .remove(&record.switch_addr.octets());
        self.ping();
        Ok(record)
    }

    /// Removes the task rows filed with `record` ([`BoxRecord::task_row_of`])
    /// from `rows`, under the write of the row lock that removed `record`,
    /// and takes each one's revocation hold under the same lock: a task row
    /// is withdrawn with its box, on every path that removes the box
    /// (NET-138). A row at a task address that is not this box's task row
    /// is left alone. Hand the result to [`Self::retire_task_rows`] once
    /// the lock is dropped.
    fn remove_task_rows(
        &self,
        rows: &mut Rows,
        record: &BoxRecord,
    ) -> Vec<(Arc<BoxRecord>, Option<RowWithdrawal>)> {
        let mut removed = Vec::new();
        for addr in &record.task_addrs {
            let ours = rows.get(&addr.octets()).is_some_and(|task| {
                task.task_row_of == Some(record.switch_addr) && task.box_id == record.box_id
            });
            if let Some(task) = rows.remove(&addr.octets()).filter(|_| ours) {
                let withdrawal = self.begin_revocation(&task);
                removed.push((task, withdrawal));
            }
        }
        removed
    }

    /// Retires the task rows [`Self::remove_task_rows`] removed, as the
    /// box's own row is retired, and returns each one's switch address to
    /// the hand-out book when `give_back` says to — not for a box whose
    /// creation keeps them reserved. Called after the row lock is dropped.
    fn retire_task_rows(
        &self,
        task_rows: Vec<(Arc<BoxRecord>, Option<RowWithdrawal>)>,
        give_back: bool,
    ) {
        for (task, withdrawal) in task_rows {
            let (addr, attributed, box_id) = (task.switch_addr, task.was_used(), task.box_id);
            self.retired(&Some(task), withdrawal);
            if give_back {
                self.give_back_switch_addr(addr, attributed, box_id);
            }
        }
    }

    /// [`Self::try_register`] for a test that never registers at a held
    /// address.
    #[cfg(test)]
    pub fn register(&self, registration: BoxRegistration) -> Arc<BoxRecord> {
        self.try_register(registration)
            .expect("a test registration never lands at an address a revocation holds")
    }

    /// Waits up to `bound` for a withdrawn box's revocation to release
    /// `addrs` ([`RowWithdrawal`]). Returns the first address still held at
    /// the bound, or `None` once none is.
    fn wait_for_revocations(&self, addrs: &[[u8; 4]], bound: Duration) -> Option<Ipv4Addr> {
        self.revoking
            .wait_released(addrs, bound)
            .map(Ipv4Addr::from)
    }

    /// Withdraws the row published for `switch_addr`, returning it when one
    /// was held. From here on the gate holds no namespace at that address, and
    /// no rules are decided by it: withdrawing is how the host retires a
    /// namespace's declaration, never a way to leave its address attributed.
    ///
    /// What the address's frames do next is unconditional
    /// ([`crate::net::egress_gate`]): an address inside the plan's lease block
    /// is an unregistered source the gate drops (NET-085), so a withdrawal
    /// inside that block ends the address's reach at once, and outside it the
    /// frames were already an unknown source's refusal (NET-081's failure
    /// case). The row is gone either way, and a re-registration starts from
    /// the newest declaration.
    pub fn withdraw(&self, switch_addr: Ipv4Addr) -> Option<Arc<BoxRecord>> {
        // The box's end is observed here, so the withdrawal's own line
        // measures itself against this instant (NET-133's bound).
        self.withdraw_where(switch_addr, |_, _| Some(Instant::now()))
    }

    /// Withdraws the row at `switch_addr` when `ended_at` says its box
    /// ended — the instant it ended — deciding under the write of the row
    /// lock the row leaves under, so nothing that changes the row's
    /// liveness lands between the decision and the removal. The proxy
    /// attachment is retired inside the same critical section, as the
    /// creator's withdrawal retires it ([`Self::withdraw_client_box`]);
    /// the row's creation, when it is a client box's, goes dormant
    /// ([`Creation`]) and is persisted; and the switch address returns to
    /// the hand-out book, quarantined when the row was ever attributed.
    ///
    /// It sends the proxy no revocation (BEP-043). A live client row always
    /// has its standing creation, because a registration under a held name
    /// is refused. So a row this removes goes dormant, and its creator can
    /// resume it under the same box id, which a revocation refuses for good
    /// (BEP-071). Only the creator's destroy of a live box revokes it
    /// ([`Self::withdraw_client_box`]).
    fn withdraw_where(
        &self,
        switch_addr: Ipv4Addr,
        ended_at: impl FnOnce(&Rows, &BoxRecord) -> Option<Instant>,
    ) -> Option<Arc<BoxRecord>> {
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let box_ended = ended_at(&rows, rows.get(&switch_addr.octets())?)?;
        self.retire_proxy_attachment(switch_addr, box_ended);
        let removed = rows.remove(&switch_addr.octets());
        let mut rowless = false;
        let mut task_rows = Vec::new();
        if let Some(record) = removed.as_deref().filter(|record| !record.is_task_row()) {
            self.bump_withdrawal_generation(&record.name());
            rowless = self.creation_rowless(record);
            task_rows = self.remove_task_rows(&mut rows, record);
        }
        // The hold is taken under the same lock the row leaves under, so no
        // registration can land at the address in between.
        let withdrawal = removed
            .as_deref()
            .and_then(|record| self.begin_revocation(record));
        drop(rows);
        self.retired(&removed, withdrawal);
        // A dormant creation keeps its switch and task addresses reserved
        // ([`Creation`]): only a row no creation is kept for returns them.
        self.retire_task_rows(task_rows, !rowless);
        if let Some(record) = removed.as_ref().filter(|_| !rowless) {
            self.give_back_switch_addr(record.switch_addr, record.was_used(), record.box_id);
        }
        if rowless {
            self.persist();
        }
        // The node's own row ended, by any path that removes it: its
        // mirrored binds end with it (NET-138's node end).
        if removed
            .as_deref()
            .is_some_and(|record| &*record.name() == NODE_NAMESPACE && !record.is_task_row())
        {
            self.node_mirror.end_node();
        }
        removed
    }

    /// Retires the proxy attachment issued for `switch_addr`, when this
    /// registry feeds a table and one is held: the host-side half of the
    /// requirement's "the attachment is the box's row, withdrawn with it"
    /// (NET-133). Retired **before** the row it goes with, so a delivery
    /// racing the box's end finds no attachment and is refused rather than
    /// attributed to a namespace the table no longer holds.
    ///
    /// `box_ended` is the instant this process observed the box's end —
    /// the drainer's arrival of the relay's report, or the creator's
    /// withdrawal request reaching the control socket — and the one line
    /// the withdrawal logs measures itself against, so a tail can see a
    /// withdrawal that did not keep the requirement's bound.
    fn retire_proxy_attachment(&self, switch_addr: Ipv4Addr, box_ended: Instant) {
        if let Some(attachments) = &self.attachments {
            attachments.withdraw(switch_addr, box_ended);
        }
    }

    /// Registers a client box: allocates its switch address from the plan's
    /// lease run and its published loopback address from the slice this
    /// subnet's switch serves at, then fills the row from `spec` — the same
    /// compile [`Self::try_register`] does, addressed at the allocation — and
    /// returns the row, whose addresses are the ones to hand back over the
    /// control socket.
    ///
    /// The switch address comes from the hand-out book
    /// ([`SwitchAddressBook`]), shared by every clone of this registry, so
    /// no address is ever out to two rows at once. The book draws only from
    /// the hand-out run — the plan run's upper half, above the daemon's
    /// self-allocation reserve (`hand_out_run`) — so the two allocators
    /// cannot meet. The run is finite, and exhausting it is the
    /// [`AllocationError::SwitchExhausted`] the control socket hands back as
    /// the registration's failure, naming the live, quarantined and total
    /// counts.
    ///
    /// Every path that removes a row returns its switch address — the
    /// drainer's [`Self::withdraw`], the creator's
    /// [`Self::withdraw_client_box`], and a refusal after the draw — and a
    /// returned address is handed again only after its quarantine and once
    /// nothing holds it. A withdrawn address's host-side state — the gate's
    /// reply flows and DNS pins, the BEP leg's neighbour entry — is keyed
    /// by it, and the quarantine outlasts every one of those timers
    /// ([`SWITCH_REUSE_QUARANTINE`]), so a re-handed address starts clean.
    /// A row never attributed keyed nothing, and its address comes back at
    /// once.
    ///
    /// While a row this registration filled stands, the box's frames are
    /// decided by its rules; a box with **no** row — one whose registration
    /// never reached the daemon, or whose row was withdrawn — is an
    /// unregistered source the gate drops unconditionally (NET-085), so no
    /// egress default phase changes it, and this registration makes none.
    ///
    /// The published loopback address is not this registry's to pick:
    /// allocation is host-global (design §7.1), so `loopback_addr` comes from
    /// the machine's answerer — the installed service, or the interim when
    /// this daemon hosts it — which hands each node's boxes distinct
    /// addresses from the reserved range. Co-resident nodes never
    /// self-assign.
    ///
    /// The box's id is always minted here, for this creation
    /// ([`crate::bep_attach::mint_box_id`]): a spec carries none, so no
    /// client can present an id, and a re-registration under the same
    /// name and addresses is a new box with a new id. Ids are never reused.
    /// A mint that collides with an id a live row, a kept creation, an
    /// attachment or a revocation record the proxy retains already holds
    /// is refused ([`AllocationError::CollidingBoxId`], BEP-070) —
    /// never re-minted — before any address is spent, and said as one warn
    /// line naming the id. A name that folds to one a live row already
    /// holds is refused the same way ([`AllocationError::NameAlreadyHeld`]):
    /// the answerer keys a published address by the name's canonical form,
    /// so two rows under folded-equal names would share one address.
    pub fn register_client_box_at(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(
            spec,
            loopback_addr,
            0,
            crate::bep_attach::mint_box_id(),
            None,
        )
    }

    /// [`Self::register_client_box_at`] for a registration that read its
    /// name's withdrawal generation as `generation`
    /// ([`Self::begin_registration`]) before the answerer allocated
    /// `loopback_addr`. When a withdrawal under the name
    /// landed since, the registration is refused with
    /// [`AllocationError::WithdrawnWhileAllocating`]: no row, no attachment,
    /// and the caller hands the address back to the answerer unless
    /// something else owns it ([`Self::release_unless_owned`]).
    ///
    /// Up to `task_slots` task addresses are filed with the box (NET-138) —
    /// at most [`minimald_rpc::TASK_SLOTS_PER_BOX`], whatever the client
    /// asked for — each drawn from the same hand-out book as the box's own
    /// and published as a task row of it ([`BoxRecord::task_row_of`]). They
    /// are best-effort: the draw stops while the book is at
    /// [`TASK_SLOT_FLOOR`], and the box registers with however many it got,
    /// which the row's [`BoxRecord::task_addrs`] says.
    pub fn register_client_box_since(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
        task_slots: u8,
        generation: u64,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(
            spec,
            loopback_addr,
            task_slots,
            crate::bep_attach::mint_box_id(),
            Some(generation),
        )
    }

    /// Mints the box id of a `host_ip` box (BEP-082): the box leaves the VM
    /// from the node's own address, so it gets no switch address and no row
    /// in the address table. The id is recorded in [`Self::host_ip_ids`].
    /// The id takes the collision check an own-address box's id takes
    /// ([`Self::holds_box_id`]): live rows, kept creations, attachments and
    /// the proxy's revocation records. A colliding mint is refused, never
    /// re-minted.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::holds_box_id`], and
    /// [`AllocationError::CollidingBoxId`] when a record holds the id, and
    /// [`AllocationError::NameAlreadyHeld`] when a live `host_ip`
    /// registration holds the name. A registration whose box is not
    /// admitted ([`Self::admit_host_ip_box_with_lane`]) is live for
    /// [`HOST_IP_UNADMITTED_NAME_BOUND`] from its register.
    pub fn register_host_ip_box(&self, name: &str) -> Result<BoxId, AllocationError> {
        self.register_host_ip_box_as(name, crate::bep_attach::mint_box_id())
    }

    /// [`Self::register_host_ip_box`] with the freshly minted `id`, split
    /// out so a test can drive a colliding mint.
    fn register_host_ip_box_as(&self, name: &str, id: BoxId) -> Result<BoxId, AllocationError> {
        if let Some(holder) = self.holds_box_id(id)? {
            tracing::warn!(
                box = %name,
                box_id = %crate::bep_attach::BoxIdText(&id),
                held_by = holder.as_str(),
                "refused a host_ip box registration whose id is already held: the check \
                 reads live rows, kept creations, attachments and the proxy's revocation \
                 records"
            );
            return Err(AllocationError::CollidingBoxId { id });
        }
        let now = self.now();
        // The resident set's read lock is taken before the ids' lock, and
        // held across the check, so an admission cannot land between the
        // check and the replace. No path takes the two the other way round.
        let resident = self
            .host_ip_boxes
            .read()
            .expect("the resident host_ip boxes' lock is never held across a panic");
        let mut ids = self.host_ip_id_set();
        // BOX-163 parity: a live registration keeps its name until its box
        // retires or its creator withdraws it. A second registration under
        // the name is refused as an own-address row's is, and it never
        // takes the name from the first. The check and the insert run under
        // one lock, so two registrations cannot both take the name.
        let asked = canonical_box_name(name);
        if let Some((held, named)) = ids
            .by_name
            .iter()
            .find(|(named, _)| canonical_box_name(named) == asked)
            .map(|(held, named)| (held.clone(), *named))
        {
            // A registration holds no connection, so a creator that died
            // before its box was admitted leaves nothing to withdraw the
            // name. Once no box is admitted under the id and the bound has
            // passed, the name is free for a new creation.
            let session = boxes::SessionId::from_bytes(named.id);
            let admitted = resident.boxes.contains_key(&session);
            let stale = !admitted
                && now.saturating_duration_since(named.since) >= HOST_IP_UNADMITTED_NAME_BOUND;
            if !stale {
                tracing::warn!(
                    asked = %name,
                    held = %held,
                    admitted,
                    "refused a host_ip box registration whose name a live registration already holds"
                );
                return Err(AllocationError::NameAlreadyHeld { held });
            }
            ids.by_name.remove(&held);
            tracing::info!(
                asked = %name,
                held = %held,
                stale_box_id = %crate::bep_attach::BoxIdText(&named.id),
                bound = ?HOST_IP_UNADMITTED_NAME_BOUND,
                "withdrew a host_ip registration name no box was admitted under within the bound"
            );
        }
        drop(resident);
        ids.ids.insert(id);
        ids.by_name
            .insert(name.to_owned(), HostIpName { id, since: now });
        drop(ids);
        self.persist_host_ip_ids();
        Ok(id)
    }

    /// The minted `host_ip` box ids and the registration names that still
    /// answer them ([`Self::host_ip_ids`]).
    fn host_ip_id_set(&self) -> MutexGuard<'_, HostIpIds> {
        self.host_ip_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `id` is a `host_ip` box id this registry minted
    /// ([`Self::register_host_ip_box`]).
    #[must_use]
    pub fn holds_host_ip_id(&self, id: BoxId) -> bool {
        self.host_ip_id_set().ids.contains(&id)
    }

    /// Whether a live `host_ip` registration name still answers `id`
    /// ([`Self::host_ip_id_for`]): the box has not retired, and its creator
    /// did not withdraw the name.
    #[must_use]
    pub fn host_ip_id_is_named(&self, id: BoxId) -> bool {
        self.host_ip_id_set()
            .by_name
            .values()
            .any(|named| named.id == id)
    }

    /// The id the live `host_ip` registration under `name` minted
    /// ([`Self::register_host_ip_box`], BEP-082), so the box's record takes
    /// the id its grants are sealed under. `None` when no live `host_ip`
    /// registration uses the name: a `host_ip` box with no credentialed
    /// upstream registers nothing, and a retired box's name is withdrawn
    /// ([`Self::retire_host_ip_box`]).
    #[must_use]
    pub fn host_ip_id_for(&self, name: &str) -> Option<BoxId> {
        self.host_ip_id_set()
            .by_name
            .get(name)
            .map(|named| named.id)
    }

    /// Withdraws the `host_ip` registration name `name` while it still
    /// answers `id`: the creator's activation failed after it registered,
    /// so no box will retire under the name ([`Self::retire_host_ip_box`]),
    /// or the box was renamed and keeps its id under its new name. The
    /// withdraw retires nothing and revokes nothing.
    /// A name a later registration took answers another id and stays. The
    /// id stays for the collision check (BEP-082). Returns whether the name
    /// was withdrawn.
    pub fn withdraw_host_ip_name(&self, name: &str, id: BoxId) -> bool {
        let mut ids = self.host_ip_id_set();
        if ids.by_name.get(name).map(|named| named.id) != Some(id) {
            return false;
        }
        ids.by_name.remove(name);
        true
    }

    /// [`Self::register_client_box_at`] with the freshly minted `id` it
    /// creates the box as: the one door the collision checks guard, split
    /// out so a test can drive a colliding mint.
    fn register_client_box_as(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
        task_slots: u8,
        id: BoxId,
        generation: Option<u64>,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        // One id names one box (BEP-070): the check runs before any
        // address is spent, so a refused registration leaves nothing
        // behind — no row, no share, no attachment, no spent address.
        // A colliding mint is refused, never re-minted: a collision means
        // the mint is broken, and a second draw would hide it.
        if let Some(holder) = self.holds_box_id(id)? {
            let (record, audit) = match &holder {
                IdHolder::AuditedRevocation { record, audit } => {
                    (record.as_str(), audit.display().to_string())
                }
                _ => ("", String::new()),
            };
            tracing::warn!(
                box_id = %crate::bep_attach::BoxIdText(&id),
                held_by = holder.as_str(),
                record,
                audit,
                "refused a box registration whose id is already held: the check reads live \
                 rows, kept creations, attachments and the proxy's revocation records"
            );
            return Err(AllocationError::CollidingBoxId { id });
        }
        if self.loopback_slice.is_none() {
            return Err(AllocationError::UnplannedSubnet(self.subnet));
        }
        // A withdrawal that landed while the address was being allocated
        // refuses the registration before anything is waited on or spent;
        // the check under the row lock in `try_register_since` is the one
        // that decides.
        if generation.is_some_and(|read| read != self.withdrawal_generation(&spec.name)) {
            return Err(AllocationError::WithdrawnWhileAllocating);
        }
        // The answerer keys a published address by the name's canonical
        // form, so a registration whose name folds to a live row's would
        // share that row's address: one box, one address, one row. The
        // check runs after the withdrawal-generation one — a registration
        // raced by a withdrawal answers as withdrawn while allocating —
        // and before any address is spent. The collision is decided in
        // the answerer's fold, and the refusal reports the held row's own
        // spelling, so the asking client learns which box holds the name.
        if let Some(held) = self.held_name_for(&spec.name) {
            tracing::warn!(
                asked = %spec.name,
                held = %held,
                "refused a box registration whose name a live row already holds"
            );
            return Err(AllocationError::NameAlreadyHeld { held });
        }
        // A withdrawn box's revocation may still hold the published address
        // the answerer handed back: the answerer releases a box's address at
        // its withdrawal, and the next box can draw it at once. The wait is
        // bounded, and normally the revocation is long done. It runs before a
        // switch address is drawn, so a registration refused here holds none.
        // The book never draws an address a row or a revocation holds, and
        // `try_register` still checks both.
        if let Some(addr) = self.wait_for_revocations(&[loopback_addr.octets()], REVOCATION_WAIT) {
            tracing::warn!(
                box = %spec.name,
                %addr,
                wait = ?REVOCATION_WAIT,
                "a withdrawn box's revocation still holds an address this registration needs"
            );
            return Err(AllocationError::RevocationPending { addr });
        }
        let switch_addr = self.draw_switch_addr()?;
        // The task addresses come from the same book, after the box's own,
        // best-effort: as many as the book can spare above the floor it
        // keeps for new boxes ([`TASK_SLOT_FLOOR`]), zero included. A box
        // is refused only when its own address cannot be drawn.
        let task_addrs: Vec<Ipv4Addr> = (0..task_slots.min(minimald_rpc::TASK_SLOTS_PER_BOX))
            .map_while(|_| self.draw_task_addr())
            .collect();
        if task_addrs.len() < usize::from(task_slots.min(minimald_rpc::TASK_SLOTS_PER_BOX)) {
            tracing::warn!(
                box = %spec.name,
                asked = task_slots,
                filed = task_addrs.len(),
                floor = TASK_SLOT_FLOOR,
                "the hand-out run is nearly full; the box registers with fewer task addresses \
                 than it asked for"
            );
        }
        let creation = Creation::new(&spec, switch_addr, loopback_addr, task_addrs.clone(), id);
        let registration =
            self.client_registration(spec, switch_addr, loopback_addr, task_addrs.clone(), id);
        // A refusal after the draw publishes no row, so no frame of the box
        // was ever attributed: the addresses go straight back, with no
        // quarantine, and the refusal spends nothing.
        self.try_register_since(registration, generation, Some(creation))
            .inspect_err(|_| {
                for &addr in std::iter::once(&switch_addr).chain(&task_addrs) {
                    self.give_back_switch_addr(addr, false, id);
                }
            })
    }

    /// The registration a client box's declaration compiles to at its
    /// addresses, as box `id`: the one compile a registration, a reload
    /// ([`Self::persisting_to`]) and a resume ([`Self::resume_client_box`])
    /// all run, so a reinstated row is the row its declaration registers
    /// under this registry's egress default.
    fn client_registration(
        &self,
        spec: ClientBoxSpec,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        task_addrs: Vec<Ipv4Addr>,
        id: BoxId,
    ) -> BoxRegistration {
        let mut registration = BoxRegistration::new(spec.name, switch_addr, loopback_addr)
            .with_admitted_ports(spec.ingress_ports)
            .with_task_addresses(task_addrs);
        if let Some(declaration) = spec.credentialed_upstream {
            registration = registration.with_credentialed_upstream(declaration);
        }
        // The dynamic-ingress grant rides the same registration: the
        // stance's absent default is deny, so a pre-grant client's row
        // admits no runtime port — and a range declared without a stance
        // changes nothing under it, exactly as it does inside the VM.
        if let Some(stance) = spec.dynamic_ingress {
            registration = registration.with_dynamic_ingress(stance, spec.dynamic_allowed_range);
        }
        registration.box_id = Some(id);
        registration
    }

    /// [`Self::register_client_box_at`] with the published loopback address
    /// drawn from this registry's own slice cursor — the single-node shape
    /// the registry's own tests drive, where no answerer arbitrates. The
    /// daemon never registers this way: its addresses are the answerer's.
    #[cfg(test)]
    pub fn register_client_box(
        &self,
        spec: ClientBoxSpec,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        let slice = self
            .loopback_slice
            .ok_or(AllocationError::UnplannedSubnet(self.subnet))?;
        let (first, last) = box_loopback_run(slice);
        let loopback_addr = take_next(&self.next_loopback_addr, first, last)
            .ok_or(AllocationError::LoopbackExhausted)?;
        self.register_client_box_at(spec, loopback_addr)
    }

    /// [`Self::register_client_box`] with `task_slots` task addresses filed
    /// with the box, as the control socket's registration files them
    /// ([`Self::register_client_box_since`]).
    #[cfg(test)]
    pub fn register_client_box_with_task_slots(
        &self,
        spec: ClientBoxSpec,
        task_slots: u8,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        let slice = self
            .loopback_slice
            .ok_or(AllocationError::UnplannedSubnet(self.subnet))?;
        let (first, last) = box_loopback_run(slice);
        let loopback_addr = take_next(&self.next_loopback_addr, first, last)
            .ok_or(AllocationError::LoopbackExhausted)?;
        self.register_client_box_at_with_task_slots(spec, loopback_addr, task_slots)
    }

    /// [`Self::register_client_box_with_task_slots`] at a published
    /// loopback address the test picks.
    #[cfg(test)]
    pub fn register_client_box_at_with_task_slots(
        &self,
        spec: ClientBoxSpec,
        loopback_addr: Ipv4Addr,
        task_slots: u8,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(
            spec,
            loopback_addr,
            task_slots,
            crate::bep_attach::mint_box_id(),
            None,
        )
    }

    /// Which record already holds `id`, if any (BEP-070): a live row, a
    /// kept creation, an attachment, or a revocation record the Box Egress
    /// Proxy retains. It is the collision check every client-driven
    /// registration runs on the id it minted. A dormant creation
    /// ([`Creation`]) is a retained box record: its id stays its box's
    /// while its creator may still resume it. A revocation record names
    /// its id for as long as the proxy keeps it, restored from its audit
    /// log at each start ([`proxy_revoked_box_ids`]). An id is never reused
    /// because no client can present one and the mint never draws the same
    /// UUIDv7 twice, not because this check remembers spent ids.
    ///
    /// # Errors
    ///
    /// [`AllocationError::RevocationsUnread`] when a proxy answers its
    /// control socket but does not list its revocations. Only a socket
    /// that is absent or refuses the connect reads as no proxy. With no
    /// proxy, the check reads the revocation records in the proxy's audit
    /// log ([`audit_revocation_holding`]), and
    /// [`AllocationError::AuditUnread`] when that log is not read whole.
    fn holds_box_id(&self, id: BoxId) -> Result<Option<IdHolder>, AllocationError> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        if rows.values().any(|record| record.box_id == id) {
            return Ok(Some(IdHolder::LiveRow));
        }
        drop(rows);
        if self.creations().all().any(|creation| creation.id() == id) {
            return Ok(Some(IdHolder::KeptCreation));
        }
        if self.host_ip_id_set().ids.contains(&id) {
            return Ok(Some(IdHolder::HostIpBox));
        }
        if self
            .attachments
            .as_ref()
            .is_some_and(|attachments| attachments.holds_id(id))
        {
            return Ok(Some(IdHolder::Attachment));
        }
        let Some(path) = self.proxy_control.as_deref() else {
            return Ok(None);
        };
        match proxy_revoked_box_ids(path) {
            Ok(revoked) => Ok(revoked
                .contains(&box_id_hex(id))
                .then_some(IdHolder::RevocationRecord)),
            // No proxy serves the socket, so the check reads the revocation
            // records the proxy's audit log retains: the ones its next start
            // puts back in force (BEP-068).
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                tracing::debug!(
                    %error,
                    "no Box Egress Proxy answers its control socket: the box id check reads the \
                     revocation records in its audit log"
                );
                audit_revocation_holding(&proxy_audit_dir(path), id)
            }
            // A proxy is there but its list was not read: a timeout, a
            // refusal or a malformed reply. The check cannot show that no
            // record holds the id, so it fails closed.
            Err(error) => {
                tracing::warn!(
                    box_id = %crate::bep_attach::BoxIdText(&id),
                    %error,
                    "refused a box registration: the Box Egress Proxy did not list its \
                     revocation records, so the box id check did not finish"
                );
                Err(AllocationError::RevocationsUnread {
                    id,
                    why: error.to_string(),
                })
            }
        }
    }

    /// The name a live row holds that `name` folds to, in its own
    /// spelling, or `None` when none folds to it. The answerer allocates a
    /// published address by the name's canonical form
    /// ([`canonical_box_name`]), so two live rows under folded-equal names
    /// would share one address; this is the check that keeps the live set
    /// one row per folded name. A dormant creation holds no name (BOX-004):
    /// its box stopped, and a registration under the name takes the name
    /// over ([`Self::try_register`]). The replaced creation is superseded,
    /// not ended: it keeps its addresses and its box id, so its box can
    /// still resume once no live row holds the name.
    fn held_name_for(&self, name: &str) -> Option<String> {
        let asked = canonical_box_name(name);
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .find(|record| canonical_box_name(&record.name()) == asked)
            .map(|record| record.name().to_string())
    }

    /// Withdraws the client box's row when the pair `(name, switch_addr,
    /// loopback_addr)` proves its client is the row's creator, returning the
    /// row removed — `Ok(None)` when no row is published at `switch_addr` at
    /// all: the row is already withdrawn, or the daemon restarted since the
    /// registration, and either way the goal state — nothing admits the
    /// pair's addresses by a row — already holds. Lookup, proof, and removal
    /// happen under one write of the row lock, so no registration can land
    /// between the proof and the removal.
    ///
    /// The proof is the same pair the registration handed back
    /// ([`ClientBoxSpec`]'s allocation), which only the registering session's
    /// record carries; a row published under another name or another
    /// loopback is not the requesting client's to remove and is refused with
    /// [`WithdrawError`]. The name in the proof is compared in its
    /// canonical form, the answerer's fold: a box registered under "Web"
    /// is withdrawn by its own name in any spelling that folds to it.
    ///
    /// `box_id`, when the withdrawing client knows it, is the epoch the
    /// proof is held to: the id the registration minted for the row it
    /// handed the pair with. A row at the pair under another id is a newer
    /// creation that was handed the same name and addresses — the switch
    /// address re-handed after its quarantine, or at once when the old row
    /// was never attributed, and the loopback one handed back to the same
    /// name by the answerer — so a stale creator's withdrawal is refused
    /// with [`WithdrawError::NotTheBoxId`] and removes nothing of it.
    /// `None`, from a client that predates the field, keeps the pair proof
    /// alone.
    ///
    /// A box id that is the row's own also stands in for its name (#1116):
    /// a session renamed since its registration withdraws under its new
    /// name, while the host keeps the row, its creation and its published
    /// address under the name it was registered by. The id and the pair
    /// prove the creator, as a resume finds a renamed box by its id
    /// ([`Self::resumable_creation`]), so the row and its creation end and
    /// the old name is free again. A withdrawal without the id is still
    /// held to the name.
    ///
    /// The withdrawn switch address returns to the hand-out book
    /// ([`SwitchAddressBook`]): quarantined when the row was ever
    /// attributed, at once when it never was. What the address's frames do
    /// next is the gate phase's to say ([`Self::withdraw`]). The box's
    /// proxy attachment goes with the row (NET-133), retired under the same
    /// row lock that removes it.
    ///
    /// This is the host-side half of the withdrawal a destroyed or failed
    /// activation sends over the control socket
    /// ([`crate::control::serve_request`]) — the guest daemon never asserts
    /// or withdraws address→box facts (NET-138).
    pub fn withdraw_client_box(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<Option<Arc<BoxRecord>>, WithdrawError> {
        self.withdraw_client_box_held(name, switch_addr, loopback_addr, box_id)
            .map(|(removed, _)| removed)
    }

    /// [`Self::withdraw_client_box`], also answering the name the
    /// withdrawn box held on the host: the removed row's or the ended
    /// creation's own name, which is the presented one unless the session
    /// was renamed since its registration (#1116), and the presented one
    /// when nothing was withdrawn. The box's published address is the
    /// answerer's under that name, so it is the name the address is
    /// released by.
    pub fn withdraw_client_box_held(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<(Option<Arc<BoxRecord>>, String), WithdrawError> {
        #[expect(
            clippy::unwrap_in_result,
            reason = "the expect is the lock's poison guard, not this function's error \
                      handling: the row lock is never held across a panic, so it cannot be \
                      poisoned"
        )]
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        // A task row is never withdrawn by itself: it goes with its box's
        // row, which is what the pair names (NET-138).
        let Some(record) = rows
            .get(&switch_addr.octets())
            .filter(|record| !record.is_task_row())
        else {
            // Nothing to remove, but the withdrawal still counts: a
            // registration under the name whose address is still being
            // allocated must not land after it.
            self.bump_withdrawal_generation(name);
            // A dormant creation the pair proves is the creator's ends
            // with its box: nothing can resume it from here on.
            let ended = {
                let mut creations = self.creations();
                let proves = |creation: &Creation| {
                    !creation.standing
                        && creation.switch_address == switch_addr
                        && creation.loopback_address == loopback_addr
                        && box_id.is_none_or(|asked| asked == creation.id())
                };
                // The box id finds the creation first, as a resume finds
                // it: a session renamed since its registration still ends
                // the creation kept under its old name (#1116). Without the
                // id, the presented name is the key.
                let key = box_id
                    .and_then(|asked| {
                        creations
                            .iter()
                            .find(|(_, creation)| creation.id() == asked)
                            .map(|(held, _)| held.clone())
                    })
                    .unwrap_or_else(|| canonical_box_name(name));
                if creations.get(&key).is_some_and(proves) {
                    creations.remove(&key)
                } else {
                    // A superseded creation (BOX-004) ends the same way:
                    // its creator destroyed the stopped box. The id, when
                    // presented, is the proof alone; the name otherwise.
                    let asked_key = canonical_box_name(name);
                    creations
                        .superseded
                        .iter()
                        .position(|creation| {
                            (box_id.is_some() || canonical_box_name(&creation.name) == asked_key)
                                && proves(creation)
                        })
                        .map(|at| creations.superseded.remove(at))
                }
            };
            // A registration in flight under the creation's own name must
            // not land after its end either.
            if let Some(creation) = &ended
                && canonical_box_name(&creation.name) != canonical_box_name(name)
            {
                self.bump_withdrawal_generation(&creation.name);
            }
            drop(rows);
            // Its addresses were reserved for it while it was dormant; they
            // go back with it.
            if let Some(creation) = &ended {
                self.give_back_creation_addrs(creation);
                self.persist();
            }
            // A dormant box with a credentialed upstream is revoked at the
            // proxy by its destroy, as a box whose row stands is.
            if let (Some(creation), Some(path)) = (&ended, self.proxy_control.as_deref())
                && creation.credentialed_upstream.is_some()
            {
                spawn_revocation(path.clone(), creation.id(), BoxEnd::Destroy);
            }
            let held = ended.map_or_else(|| name.to_string(), |creation| creation.name);
            return Ok((None, held));
        };
        // The row's own id proves its creator whatever the session is
        // named now (#1116); without it the name must be the row's.
        let id_proves = box_id.is_some_and(|asked| asked == record.box_id);
        if !id_proves && canonical_box_name(&record.name()) != canonical_box_name(name) {
            return Err(WithdrawError::NotTheCreatorsRow {
                switch_addr,
                held_name: record.name().to_string(),
                asked_name: name.to_string(),
            });
        }
        if record.loopback_addr() != loopback_addr {
            return Err(WithdrawError::NotTheHandedPair {
                switch_addr,
                held_loopback: record.loopback_addr(),
                asked_loopback: loopback_addr,
            });
        }
        if let Some(asked) = box_id
            && asked != record.box_id
        {
            return Err(WithdrawError::NotTheBoxId {
                switch_addr,
                held_box_id: record.box_id,
                asked_box_id: asked,
            });
        }
        // The attachment goes with the row (NET-133), retired inside the
        // same critical section that removes the row: a registration
        // landing after cannot retire the new box's attachment, and one
        // landing before is the row the proof above matched. The paths
        // that hold a row lock across the attachment table's — this one
        // and the drainer's ([`Self::withdraw_where`]) — take the row lock
        // first, and no path takes them the other way, so the order never
        // inverts.
        self.retire_proxy_attachment(switch_addr, Instant::now());
        let removed = rows.remove(&switch_addr.octets());
        // The row's own name, which is the presented one unless the
        // session was renamed since its registration.
        let held = removed
            .as_deref()
            .map_or_else(|| name.to_string(), |record| record.name().to_string());
        self.bump_withdrawal_generation(&held);
        // The creator withdrew its box: its creation ends with the row,
        // when the row is the creation's.
        let ended = removed.as_deref().is_some_and(|record| {
            let mut creations = self.creations();
            let key = canonical_box_name(&record.name());
            creations
                .get(&key)
                .is_some_and(|creation| creation.id() == record.box_id)
                && creations.remove(&key).is_some()
        });
        let task_rows = removed
            .as_deref()
            .map(|record| self.remove_task_rows(&mut rows, record))
            .unwrap_or_default();
        let withdrawal = removed
            .as_deref()
            .and_then(|record| self.begin_revocation(record));
        drop(rows);
        // BEP-043: the destroy of a live box with a credentialed lane
        // records a revocation of its id with the proxy. The destroy never
        // waits for it: with the proxy down, the attachment retired above
        // refuses the box's values (NET-133).
        if let (Some(record), Some(path)) = (removed.as_deref(), self.proxy_control.as_deref())
            && record.declares_credentialed_upstream()
        {
            spawn_revocation(path.clone(), record.box_id, BoxEnd::Destroy);
        }
        self.retired(&removed, withdrawal);
        self.retire_task_rows(task_rows, true);
        if let Some(record) = &removed {
            self.give_back_switch_addr(record.switch_addr, record.was_used(), record.box_id);
        }
        if ended {
            self.persist();
        }
        Ok((removed, held))
    }

    /// Moves the client box `box_id` to `new_name` (#1116): a session
    /// renamed in the in-VM daemon, whose creator presents the pair and the
    /// id its registration handed back. Its row, its task rows and its
    /// creation are re-keyed to the new name under one write of the row
    /// lock, the creations are persisted, and the table pings its
    /// subscribers: the zone then answers the box's address under the new
    /// name and nothing under the old one, the gate's name rules read the
    /// new name, and a later withdrawal or resume finds the box under it.
    /// The row's identity (its id, its addresses, its liveness and its
    /// runtime ports) is untouched: a rename is not a re-registration.
    ///
    /// The id is the proof, with the pair: a row at the switch address
    /// under another id is refused ([`RenameError::NotTheBoxId`]), as is a
    /// creation of the id at another pair. A row of another box under the
    /// new name refuses the rename ([`RenameError::NameHeld`]); a dormant
    /// creation of another box under it is superseded, as a registration
    /// under its name supersedes it (BOX-004), and keeps its addresses and
    /// its id. A box with no row stands only as its creation, which is
    /// re-keyed alone.
    ///
    /// Answers the name the host held the box under before, or `None`
    /// when the host holds neither a row at the pair nor a creation of the
    /// id: the box is not this host's, or not any more, and nothing moves.
    pub fn rename_client_box(
        &self,
        new_name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: BoxId,
    ) -> Result<Option<String>, RenameError> {
        #[expect(
            clippy::unwrap_in_result,
            reason = "the expect is the lock's poison guard, not this function's error \
                      handling: the row lock is never held across a panic, so it cannot be \
                      poisoned"
        )]
        let rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let new_key = canonical_box_name(new_name);
        let row = rows
            .get(&switch_addr.octets())
            .filter(|record| !record.is_task_row())
            .map(Arc::clone);
        if let Some(record) = &row {
            if record.box_id != box_id {
                return Err(RenameError::NotTheBoxId {
                    switch_addr,
                    held_box_id: record.box_id,
                    asked_box_id: box_id,
                });
            }
            if record.loopback_addr() != loopback_addr {
                return Err(RenameError::NotTheHandedPair {
                    box_id,
                    held_switch: record.switch_addr(),
                    held_loopback: record.loopback_addr(),
                    asked_switch: switch_addr,
                    asked_loopback: loopback_addr,
                });
            }
        }
        if let Some(holder) = rows.values().find(|other| {
            !other.is_task_row()
                && other.box_id != box_id
                && canonical_box_name(&other.name()) == new_key
        }) {
            return Err(RenameError::NameHeld {
                name: new_name.to_string(),
                holder: holder.name().to_string(),
            });
        }
        let mut creations = self.creations();
        // The box's own creation, found by its id wherever it is kept: the
        // name's own, or superseded (BOX-004).
        let own_key = creations
            .iter()
            .find(|(_, creation)| creation.id() == box_id)
            .map(|(key, _)| key.clone());
        let own_superseded = creations
            .superseded
            .iter()
            .position(|creation| creation.id() == box_id);
        let own = own_key
            .as_ref()
            .and_then(|key| creations.get(key))
            .or_else(|| own_superseded.and_then(|at| creations.superseded.get(at)));
        if let Some(creation) = own
            && (creation.switch_address != switch_addr
                || creation.loopback_address != loopback_addr)
        {
            return Err(RenameError::NotTheHandedPair {
                box_id,
                held_switch: creation.switch_address,
                held_loopback: creation.loopback_address,
                asked_switch: switch_addr,
                asked_loopback: loopback_addr,
            });
        }
        let Some(held) = row
            .as_deref()
            .map(|record| record.name().to_string())
            .or_else(|| own.map(|creation| creation.name.clone()))
        else {
            return Ok(None);
        };
        if let Some(other) = creations.get(&new_key)
            && other.id() != box_id
        {
            if other.standing {
                // A standing creation's row holds the name; the check above
                // found none, so the two disagree. Refuse rather than guess.
                return Err(RenameError::NameHeld {
                    name: new_name.to_string(),
                    holder: other.name.clone(),
                });
            }
            if let Some(superseded) = creations.remove(&new_key) {
                tracing::info!(
                    box = %superseded.name,
                    by = %crate::bep_attach::BoxIdText(&box_id),
                    "a renamed box took over a stopped box's name; the stopped box keeps its \
                     creation and its addresses"
                );
                creations.superseded.push(superseded);
            }
        }
        let moved = match (own_key, own_superseded) {
            (Some(key), _) => creations.remove(&key),
            (None, Some(at)) => Some(creations.superseded.remove(at)),
            (None, None) => None,
        };
        let persist = moved.is_some();
        if let Some(mut creation) = moved {
            creation.name = new_name.to_string();
            creations.insert(new_key, creation);
        }
        drop(creations);
        if let Some(record) = &row {
            record.rename(new_name);
            for addr in &record.task_addrs {
                if let Some(task) = rows.get(&addr.octets())
                    && task.task_row_of == Some(record.switch_addr)
                    && task.box_id == record.box_id
                {
                    task.rename(new_name);
                }
            }
        }
        drop(rows);
        if persist {
            self.persist();
        }
        self.ping();
        Ok(Some(held))
    }

    /// The creation a resume presenting `(name, switch_addr, loopback_addr)`
    /// and `box_id` proves its creator holds: looked up by the box id when
    /// the resume names one — a session renamed since its registration
    /// still finds its box — and by the name otherwise, or when no creation
    /// holds the id.
    fn resumable_creation(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<Creation, ResumeError> {
        let creations = self.creations();
        let creation = box_id
            .and_then(|asked| creations.all().find(|creation| creation.id() == asked))
            .or_else(|| creations.get(&canonical_box_name(name)))
            .cloned();
        let superseded = creation.as_ref().is_some_and(|creation| {
            creations
                .superseded
                .iter()
                .any(|kept| kept.id() == creation.id())
        });
        drop(creations);
        let Some(creation) = creation else {
            return Err(ResumeError::NoCreation {
                name: name.to_string(),
            });
        };
        if creation.switch_address != switch_addr || creation.loopback_address != loopback_addr {
            return Err(ResumeError::NotTheHandedPair {
                name: name.to_string(),
                held_switch: creation.switch_address,
                held_loopback: creation.loopback_address,
            });
        }
        if let Some(asked) = box_id
            && asked != creation.id()
        {
            return Err(ResumeError::NotTheBoxId {
                name: name.to_string(),
                held_box_id: creation.id(),
                asked_box_id: asked,
            });
        }
        // BOX-004: a superseded creation's name went to a newer box. Its
        // box resumes only while no live row holds the name; a resume
        // now would put two running boxes under one name.
        if superseded && let Some(held) = self.held_name_for(&creation.name) {
            tracing::info!(
                box = %creation.name,
                box_id = %crate::bep_attach::BoxIdText(&creation.id()),
                "refused the resume of a stopped box: a running box holds its name"
            );
            return Err(AllocationError::NameAlreadyHeld { held }.into());
        }
        Ok(creation)
    }

    /// What a resume presenting `(name, switch_addr, loopback_addr)` and
    /// `box_id` finds, read before anything is allocated for it: the row,
    /// when it stands — the resume's whole answer, which needs no published
    /// address asked of the answerer — or the creation's own name, under
    /// which its dormant row is reinstated ([`Self::resume_client_box`]).
    ///
    /// # Errors
    ///
    /// [`ResumeError`], as [`Self::resume_client_box`] refuses.
    pub fn resumable(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
    ) -> Result<Resumable, ResumeError> {
        let creation = self.resumable_creation(name, switch_addr, loopback_addr, box_id)?;
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        Ok(match standing_row_of(&rows, &creation) {
            Some(record) => Resumable::Standing(Arc::clone(record)),
            None => Resumable::Dormant {
                name: creation.name,
            },
        })
    }

    /// Gives a creator its box's row back (NET-138): the row its creator
    /// registered as box `name`, handed the pair `(switch_addr,
    /// loopback_addr)` — and, when the creator knows it, created as
    /// `box_id` — reinstated from the registry's own creation ([`Creation`])
    /// when the row was withdrawn after its detach grace, or held as it
    /// stands when it was not. The pair is the creator's proof, as for a
    /// withdrawal ([`Self::withdraw_client_box`]), and the lookup key: every
    /// fact the row holds comes from the creation this host kept — the
    /// declaration its creator registered, compiled under this registry's
    /// egress default — never from the request, and never from the guest.
    ///
    /// A row that stands is answered as it stands ([`RowLiveness`]): a
    /// detached row's grace keeps running from its attachment's end, so a
    /// resume never holds it past [`NET_138_WITHDRAWAL_BOUND`]. A dormant
    /// creation's row is published at its own switch address and task
    /// addresses, which the creation kept reserved while it was dormant
    /// ([`Creation`]), and at the published loopback address the answerer
    /// holds for the name now, `allocated_loopback`, which must be the one
    /// the box was created with. The creation is found by `box_id` when
    /// the resume names one, so a session renamed since still resumes it. The reinstated row is awaiting, under its original id: no
    /// grace runs until a relay that carried it ends, and a row no relay
    /// carries — neither its box nor any of its task rows — within
    /// [`RESUME_ATTACH_BOUND`] is withdrawn as at a grace's end, its
    /// creation kept for a later resume.
    ///
    /// `generation` is the name's withdrawal generation read before the
    /// answerer allocated ([`Self::begin_registration`]): a withdrawal that
    /// landed since refuses the resume, as it refuses a registration.
    ///
    /// # Errors
    ///
    /// [`ResumeError`]: the registry keeps no creation under the name, the
    /// pair or the id is not the creation's, or the row cannot be
    /// published. A refusal
    /// changes nothing; the caller hands the answerer's address back unless
    /// something else owns it ([`Self::release_unless_owned`]).
    pub fn resume_client_box(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        box_id: Option<BoxId>,
        allocated_loopback: Ipv4Addr,
        generation: u64,
    ) -> Result<Arc<BoxRecord>, ResumeError> {
        let creation = self.resumable_creation(name, switch_addr, loopback_addr, box_id)?;
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let name = creation.name.clone();
        // A row that stands is answered as it stands.
        if let Some(record) = standing_row_of(&rows, &creation) {
            tracing::info!(
                box = %record.name(),
                switch_addr = %record.switch_addr(),
                "its creator resumed a box whose row stands; the row is left as it stands"
            );
            return Ok(Arc::clone(record));
        }
        drop(rows);
        // The creator holds the pair it was handed and proves itself with
        // it: a row at another loopback address would leave the creator's
        // pair stale, and every later resume or withdrawal would be refused
        // as not the handed pair. So the address never moves on a resume.
        // The answerer's book keeps a dormant creation's address claimed
        // (`zone_rows` in the answerer), so a moved allocation is a box that
        // took it while no publish held it, and the resume is refused.
        if allocated_loopback != creation.loopback_address {
            return Err(ResumeError::LoopbackMoved {
                name: name.to_string(),
                held: creation.loopback_address,
                allocated: allocated_loopback,
            });
        }
        let mut addrs = revocation_addrs(creation.switch_address, creation.loopback_address);
        addrs.extend(creation.task_addresses.iter().map(|addr| addr.octets()));
        if let Some(addr) = self.wait_for_revocations(&addrs, REVOCATION_WAIT) {
            return Err(AllocationError::RevocationPending { addr }.into());
        }
        // The box's switch and task addresses stayed reserved for its
        // creation while it was dormant ([`Creation`]), so the row and its
        // task rows are restored at them with nothing to take.
        let registration = self.client_registration(
            creation.spec(),
            creation.switch_address,
            creation.loopback_address,
            creation.task_addresses.clone(),
            creation.id(),
        );
        let standing = Creation {
            standing: true,
            ..creation
        };
        let record = self.try_register_since(registration, Some(generation), Some(standing))?;
        tracing::info!(
            box = %record.name(),
            switch_addr = %record.switch_addr(),
            "its creator resumed a box whose row was withdrawn; the row is reinstated from \
             the host's own record of its creation"
        );
        Ok(record)
    }

    /// Holds a removed row's addresses against reuse until its revocation
    /// ends ([`RowWithdrawal`]). Called under the row lock that removed it.
    /// `None`, and no hold, when nothing subscribes to withdrawals: then
    /// nothing will unbind the row's forwards, and nothing would release
    /// the hold either.
    fn begin_revocation(&self, record: &BoxRecord) -> Option<RowWithdrawal> {
        let subscribed = !self
            .row_withdrawals
            .lock()
            .expect("the withdrawal subscribers' lock is held only across pushes and sends")
            .is_empty();
        if !subscribed {
            return None;
        }
        let addrs = record.revocation_addrs();
        self.revoking.hold(&addrs);
        Some(RowWithdrawal {
            switch_addr: record.switch_addr,
            box_id: record.box_id,
            hold: Arc::new(RevocationHold {
                addrs,
                revoking: Arc::clone(&self.revoking),
            }),
        })
    }

    /// Retires a removed row's side facts: its pending asks are cancelled
    /// (NET-045), its stopped mark is stale with the row gone, the
    /// row-withdrawal subscribers are each handed a copy of `withdrawal`
    /// (design §7.1: the gate unbinds the box's forwards, holding the row's
    /// addresses until it has), and the change is a ping like any other. A
    /// subscriber that is gone drops its copy, so it holds nothing.
    fn retired(&self, removed: &Option<Arc<BoxRecord>>, withdrawal: Option<RowWithdrawal>) {
        if let Some(record) = removed {
            if let Some(withdrawal) = withdrawal {
                self.row_withdrawals
                    .lock()
                    .expect("the withdrawal subscribers' lock is held only across pushes and sends")
                    .retain(|subscriber| subscriber.send(withdrawal.clone()).is_ok());
            }
            // The row's pending asks go with it (NET-045): with no grant
            // left to publish under, each ends cancelled, and its guest's
            // serving thread audits the cancellation it receives.
            for ended in self.cancel_asks_for_row(record.switch_addr) {
                tracing::info!(
                    ask_id = %ended.ask_id,
                    box = %ended.facts.name,
                    port = ended.facts.port,
                    proto = %ended.facts.proto,
                    dismissed = ended.dismissed,
                    "cancelled a pending ask: its box's row was withdrawn"
                );
            }
            self.stopped
                .write()
                .expect(
                    "the stopped set's lock is never held across a panic, so it cannot be \
                     poisoned",
                )
                .remove(&record.switch_addr.octets());
            self.ping();
        }
    }

    /// Records the in-VM daemon's admit report of one runtime-published
    /// port (NET-138, NET-045) into the row at `switch_addr` — the one row
    /// dimension a guest's own report fills, and only within the grant the
    /// row's host-side registration holds. The checks, in order:
    ///
    /// 1. **A row exists** at the switch address the registration handed
    ///    back — a report keyed anywhere else is no row's and is refused.
    /// 2. **The stance** is `allow`: `deny`, the default an absent
    ///    declaration carries, admits nothing, and `ask` admits nothing a
    ///    guest reports — ask-yes must be host-recorded, because only the
    ///    host sees the attached human's answer.
    /// 3. **The port is inside the row's allowed range**, inclusively at
    ///    both ends; a row that declared no range permits nothing.
    /// 4. **A port the row already holds** is answered as recorded, a
    ///    no-op: the report's goal state already holds, so it spends
    ///    neither the cap nor the rate. A retry after a lost reply is this
    ///    case, and it must never be refused for a port the host holds —
    ///    a refusal is not withdrawn, so the row would keep a port its
    ///    reporter believes was refused.
    /// 5. **The row holds fewer than [`RUNTIME_PORT_CAP`] runtime ports.**
    /// 6. **The row is inside its admit rate** — at most
    ///    [`ROW_ADMIT_RATE_PER_SECOND`] recorded reports per trailing
    ///    second, counting every report that records a new port: the rate
    ///    bounds the reporting, not the ports.
    ///
    /// A report that passes records the port idempotently — the port and
    /// protocol pair the report named — and answers the row it recorded
    /// into, so the caller can name the box its line speaks for. A refusal
    /// answers [`PortReportRefusal`] naming the box where the row exists and
    /// the check that refused, and records nothing: no rate timestamp, no
    /// port, no fact the host did not hold.
    ///
    /// `now` is the instant the report arrived, injected so the rate and
    /// the cap are testable without waiting real seconds.
    ///
    /// # Errors
    ///
    /// [`PortReportRefusal`] — never a panic; the lock guards are poison
    /// guards only, and no lock is held across a panic.
    pub fn admit_runtime_port(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
        now: Instant,
    ) -> Result<Arc<BoxRecord>, PortReportRefusal> {
        // The rows guard is a read lock held for the whole call — the row's
        // registration-frozen facts first, then the runtime half nested
        // inside — so reports against different rows run concurrently and
        // the registration's write lock only waits out its own turn. No
        // path takes the two in the other order (a row's withdrawal drops
        // the row from the map without touching its runtime half), so the
        // nesting is acyclic.
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record = rows
            .get(&switch_addr.octets())
            .ok_or(PortReportRefusal::NoRow {
                switch_addr,
                port,
                proto,
            })?;
        let name = record.name().to_string();
        match record.dynamic_ingress() {
            DynamicIngress::Deny => {
                return Err(PortReportRefusal::DenyStance { name, port, proto });
            }
            // `ask` records only what the attached human answered yes to
            // (NET-045), and the guest's report is not that answer: ask-yes
            // must be host-recorded, so a guest report under `ask` is
            // refused and records nothing.
            DynamicIngress::Ask => {
                return Err(PortReportRefusal::AskNotHostRecorded { name, port, proto });
            }
            DynamicIngress::Allow => {}
        }
        let range = record
            .dynamic_range()
            .ok_or_else(|| PortReportRefusal::NoAllowedRange {
                name: name.clone(),
                port,
                proto,
            })?;
        if port < range.0 || port > range.1 {
            return Err(PortReportRefusal::OutsideAllowedRange {
                name,
                port,
                proto,
                range,
            });
        }
        // The row's runtime half: a held port, then cap, then rate, then the
        // recording — one lock section, so a report that passes every check
        // is recorded in the order it arrived.
        let reported = RuntimePort { port, proto };
        let mut runtime = record
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if runtime.ports.contains(&reported) {
            return Ok(Arc::clone(record));
        }
        if runtime.ports.len() >= RUNTIME_PORT_CAP {
            return Err(PortReportRefusal::RowCapReached {
                name,
                port,
                proto,
                cap: RUNTIME_PORT_CAP,
            });
        }
        // The trailing-second window: every recorded report inside it
        // counts, and a report over the rate is refused without pacing.
        while runtime
            .admits
            .front()
            .is_some_and(|at| now.duration_since(*at) >= ADMIT_RATE_WINDOW)
        {
            runtime.admits.pop_front();
        }
        if runtime.admits.len() >= ROW_ADMIT_RATE_PER_SECOND {
            return Err(PortReportRefusal::RateExceeded {
                name,
                port,
                proto,
                rate: ROW_ADMIT_RATE_PER_SECOND,
            });
        }
        runtime.admits.push_back(now);
        runtime.ports.push(reported);
        Ok(Arc::clone(record))
    }

    /// Applies the in-VM daemon's withdrawal report of one runtime-published
    /// port: the port leaves the row's runtime set, so the gate no longer
    /// admits a retraction of it and the read-only row verb no longer lists
    /// it. Never refused — the cap and the rate are the admit path's bounds,
    /// and removing a fact the row holds (or already lacks) is always the
    /// goal state — and never counted against the rate. Answers the row the
    /// port was withdrawn from, `None` when no row is held at the address:
    /// the report was accepted either way.
    pub fn withdraw_runtime_port(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
    ) -> Option<Arc<BoxRecord>> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record = rows.get(&switch_addr.octets())?;
        let mut runtime = record
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime
            .ports
            .retain(|reported| !(reported.port == port && reported.proto == proto));
        Some(Arc::clone(record))
    }

    /// The live row registered under `name` (the read-only row verb's
    /// resolution, NET-138), under the alias rule: a name is an alias,
    /// never identity — the box's identity is its id (BEP-070) — so the
    /// name resolves to the live box that holds it, and liveness is the
    /// table's own fact. A box whose row is withdrawn is gone, not
    /// archived, so a name no live row holds answers no row, never a
    /// destroyed box's last row. `None` when no live row carries the name.
    ///
    /// Exact match alone is not the rule: the table does not hold names
    /// unique. Rows are keyed by switch address; a client registration is
    /// refused while a live row holds its folded name
    /// ([`AllocationError::NameAlreadyHeld`]), but a row registered in
    /// process ([`Self::try_register`]) can sit beside an older one under
    /// the same name until the older one's withdrawal lands.
    /// While both are held, the alias resolves to the newest creation —
    /// the row with the greatest id, because every id is a UUIDv7 this
    /// process minted ([`crate::bep_attach::mint_box_id`]), and the crate
    /// orders those by creation within a process. The name is matched in
    /// its canonical form ([`canonical_box_name`]):
    /// the answerer keys the box's published address by that form, so the
    /// row table and the address hold one box to a folded-equal name.
    #[must_use]
    pub fn row_by_name(&self, name: &str) -> Option<Arc<BoxRecord>> {
        let asked = canonical_box_name(name);
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        rows.values()
            .filter(|record| !record.is_task_row() && canonical_box_name(&record.name()) == asked)
            .max_by_key(|record| record.box_id())
            .cloned()
    }

    /// The box row with this id, when one stands. A task row is not a box's
    /// row and is never returned.
    #[must_use]
    pub fn row_by_box_id(&self, id: BoxId) -> Option<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .find(|record| record.box_id == id && !record.is_task_row())
            .cloned()
    }

    /// Whether `record` is still the row at its address.
    #[must_use]
    pub fn row_stands(&self, record: &Arc<BoxRecord>) -> bool {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .get(&record.switch_addr.octets())
            .is_some_and(|held| Arc::ptr_eq(held, record))
    }

    /// Marks the namespace published at `switch_addr` stopped: its row
    /// stays — a stopped namespace is never mistaken for one that never
    /// existed, so its zone name stays held and answers NODATA rather than
    /// NXDOMAIN (NET-128) — but it answers no address while the mark
    /// stands. A registration at the same address clears the mark, because
    /// the newest declaration is a namespace that is running. Returns
    /// whether a row was published at the address: marking an address no
    /// row holds marks nothing.
    ///
    /// No production path marks a row stopped yet. A box's lifecycle lives
    /// with the guest daemon that runs it, and the host learns a box
    /// stopped when the task that carries box lifecycle over the host's
    /// control path lands; this mutator is the seam that task writes
    /// through, and the zone view and the state dump already carry the
    /// mark.
    pub fn mark_stopped(&self, switch_addr: Ipv4Addr) -> bool {
        let held = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .contains_key(&switch_addr.octets());
        if held {
            self.stopped
                .write()
                .expect(
                    "the stopped set's lock is never held across a panic, so it cannot be \
                     poisoned",
                )
                .insert(switch_addr.octets());
            self.ping();
        }
        held
    }

    /// Holds box `name`'s name in the zone with no row behind it (the
    /// `host_ip` interim): from here a lookup of `<name>.min.internal`
    /// answers NODATA where an unheld name answers NXDOMAIN. Idempotent;
    /// a name a live row publishes is the row's — the fold in
    /// [`Self::zone_view`] keeps the row's entry, so the two coexist.
    /// `owner` is the session the hold is for: a later hold of the name
    /// takes it over. Returns whether the table did not hold the name
    /// already.
    ///
    /// The hold is persisted ([`Self::persisting_to`]), so it survives a
    /// daemon restart.
    pub fn hold_box_name(&self, name: &str, owner: Option<boxes::SessionId>) -> bool {
        let old = {
            let mut held = self.held_names.write().expect(
                "the held names' lock is never held across a panic, so it cannot be poisoned",
            );
            let canonical = canonical_box_name(name);
            // A hold re-confirms a reloaded one: the name has a live
            // session again, whichever session holds it now.
            self.unconfirmed_holds().remove(&canonical);
            held.insert(canonical, owner)
        };
        if old != Some(owner) {
            self.persist_held_names();
        }
        let inserted = old.is_none();
        if inserted {
            tracing::info!(
                box = %name,
                "held a box name in the zone with no row behind it"
            );
            self.ping();
        }
        inserted
    }

    /// The names [`Self::hold_box_name`] holds, each with the session the
    /// hold is for, in name order. The host answerer reads them to answer
    /// a running host-address box's name with its node's address (NET-129).
    #[must_use]
    pub fn held_name_owners(&self) -> Vec<(String, Option<boxes::SessionId>)> {
        self.held_names
            .read()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned")
            .iter()
            .map(|(name, owner)| (name.clone(), *owner))
            .collect()
    }

    /// Releases a name [`Self::hold_box_name`] holds: the name answers
    /// nothing again — NXDOMAIN, the pre-box state. A name no hold kept
    /// is the goal state already holding. Returns whether a hold was
    /// actually released.
    ///
    /// The release is persisted ([`Self::persisting_to`]), so it
    /// survives a daemon restart.
    ///
    /// With an `owner`, the release frees every hold that session made,
    /// under whatever name it holds now (a rename moved it), plus `name`'s
    /// hold when no session owns it; a hold another session made under
    /// `name` stays. Without one, `name`'s hold goes whoever made it.
    pub fn release_held_name(&self, name: &str, owner: Option<boxes::SessionId>) -> bool {
        let canonical = canonical_box_name(name);
        let mut held = self
            .held_names
            .write()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned");
        let before = held.len();
        match owner {
            Some(owner) => held.retain(|held_name, held_by| match held_by {
                Some(session) => *session != owner,
                None => *held_name != canonical,
            }),
            None => {
                held.remove(&canonical);
            }
        }
        let removed = held.len() != before;
        if removed {
            self.unconfirmed_holds()
                .retain(|unconfirmed, _| held.contains_key(unconfirmed));
        }
        drop(held);
        if removed {
            self.persist_held_names();
            tracing::info!(
                box = %name,
                "released a held box name; it answers nothing again"
            );
            self.ping();
        }
        removed
    }

    /// Drops every hold reloaded from [`HELD_NAMES_FILE`] that no hold has
    /// re-made within [`HELD_NAME_RECONFIRM_BOUND`] of its reload, and
    /// returns how many it dropped. No host client has asked for such a
    /// hold since the restart, so its name answers NXDOMAIN again
    /// (NET-012) rather than NODATA for good: a session that ended with no
    /// release is cleared this way, and a live session nobody attached to
    /// or exec'd into loses its hold until its next attach or exec makes
    /// it again. Each drop is
    /// decided again under the held names' write, so a hold re-made since
    /// the scan stays. Run on the withdrawal drainer's sweep
    /// ([`Self::spawn_withdrawal_drainer`]).
    pub fn expire_unconfirmed_holds(&self) -> usize {
        let now = self.now();
        let due =
            |since: &Instant| now.saturating_duration_since(*since) >= HELD_NAME_RECONFIRM_BOUND;
        if !self.unconfirmed_holds().values().any(due) {
            return 0;
        }
        let mut held = self
            .held_names
            .write()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned");
        let mut dropped = Vec::new();
        self.unconfirmed_holds().retain(|name, since| {
            if !due(since) {
                return true;
            }
            if held.remove(name).is_some() {
                dropped.push(name.clone());
            }
            false
        });
        drop(held);
        if !dropped.is_empty() {
            self.persist_held_names();
            tracing::info!(
                boxes = ?dropped,
                bound = ?HELD_NAME_RECONFIRM_BOUND,
                "dropped held box names reloaded from the last run that nothing held \
                 again; they answer nothing again"
            );
            self.ping();
        }
        dropped.len()
    }

    /// The reloaded holds no hold has re-made yet
    /// ([`Self::unconfirmed_holds`]'s field), locked.
    fn unconfirmed_holds(&self) -> MutexGuard<'_, BTreeMap<String, Instant>> {
        self.unconfirmed_holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Subscribes to the table's change pings: one `()` per registration,
    /// withdrawal, and stopped mark, for as long as the returned receiver
    /// lives. The host answerer subscribes — a daemon that does not hold
    /// the answerer port re-registers its zone rows with the one that does
    /// on every change — and so does the zone-table dump
    /// ([`crate::diag`]); a subscriber is pruned with its receiver, and a
    /// ping to a dead one is dropped, never a registration held back. The
    /// channel is unbounded and every sender drops a refused send, so a
    /// slow registrar holds its own pings back, never the table's.
    pub fn subscribe_table_pings(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.table_pings
            .lock()
            .expect("the ping channels' lock is held only across pushes and pings")
            .push(sender);
        receiver
    }

    /// Files one change ping to every live subscriber, pruning the dead
    /// ones as it goes.
    fn ping(&self) {
        self.table_pings
            .lock()
            .expect("the ping channels' lock is held only across pushes and pings")
            .retain(|sender| sender.send(()).is_ok());
    }

    /// The zone view the host answerer answers the box zone from (NET-138):
    /// every published row's name under the zone apex —
    /// `<name>.min.internal`, the form the shared decision matches — with
    /// the host-answerable address a lookup may be told (NET-127) and the
    /// row's liveness (NET-128). One row per namespace, held in name
    /// order, so the view a lookup answers from and the table the state
    /// dump writes are the same rows.
    ///
    /// The address is the row's published loopback address when it is one
    /// the host may be told and `None` when it is not: a row's switch
    /// lease is inside the guest's fabric, nothing on the host OS routes
    /// to it, and a name held only there answers NODATA rather than
    /// pointing a lookup somewhere it cannot go (the same gate the native
    /// daemon's registry applies, [`is_host_answerable`]). The node's own
    /// namespace is a row like any other — its services sit at the
    /// machine's shared loopback address, which is answerable, so the row
    /// answers with it.
    ///
    /// Liveness is the table's own fact: a row is live from its
    /// registration, and [`Self::mark_stopped`] holds it NODATA while the
    /// namespace it names is not running. The view is a snapshot, built
    /// fresh by whoever asks — a lookup, a dump, a registration — so it
    /// can never hold a row the table has already let go.
    ///
    /// The names held with no row behind them ([`Self::hold_box_name`],
    /// the `host_ip` interim) fold in after the rows as address-less
    /// entries: a name a row publishes is the row's, and a name only
    /// held answers NODATA.
    #[must_use]
    pub fn zone_view(&self) -> zone_answer::ZoneView {
        // The rows lock first, the stopped set inside it — the order every
        // other path through both takes (`register`, `retired`,
        // `mark_stopped`), so the two locks never wait on each other.
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let stopped = self.stopped.read().expect(
            "the stopped set's lock is never held across a panic, so it cannot be \
                 poisoned",
        );
        let mut view = zone_answer::ZoneView::new();
        // A task row publishes no name: its box's row holds the box's.
        for record in rows.values().filter(|record| !record.is_task_row()) {
            view.hold(
                zone_name(&record.name()),
                zone_answer::ZoneRow {
                    address: is_host_answerable(record.loopback_addr())
                        .then_some(record.loopback_addr()),
                    live: !stopped.contains(&record.switch_addr.octets()),
                },
            );
        }
        drop(stopped);
        drop(rows);
        // Held names fold in after the rows: a name a row publishes keeps
        // the row's entry — replacing it would drop the address a live box
        // answers with — and a name only held answers NODATA.
        let held_names = self
            .held_names
            .read()
            .expect("the held names' lock is never held across a panic, so it cannot be poisoned");
        for name in held_names.keys() {
            let zone_name = zone_name(name);
            if view.rows().find(|(held, _)| *held == zone_name).is_none() {
                view.hold(
                    zone_name,
                    zone_answer::ZoneRow {
                        address: None,
                        live: true,
                    },
                );
            }
        }
        view
    }

    /// Publishes the guest **node's** own namespace: the in-VM daemon's
    /// root-netns tap, the plane design §5.1 names node-plane. The address is
    /// the host's own derivation from the subnet it configured the switch
    /// with ([`SwitchSubnet::daemon_ip`]) — the guest is neither asked nor
    /// able to influence what this row holds.
    ///
    /// The admitted port is the one the daemon's own setup publishes at its
    /// address: the hostname proxy's, assigned by the VM host before the VM
    /// boots ([`crate::cmd::run`] hands it to the guest on the kernel command
    /// line) and bound by the guest daemon as handed — so the publishes the
    /// daemon makes to attach it are publishes of a port this row already
    /// names, not requests for the host to open its own. The zone answerer is
    /// not the node's to admit (NET-138): on a VM-backed host the in-VM daemon
    /// starts no answerer — the host answerer serves the zone — so an
    /// answerer port on this row would be an admitted port with nothing
    /// behind it, a standing grant.
    ///
    /// The rules are the allow-all interim the absent-policy default ships:
    /// the node-plane baseline set is un-enrolled until NET-130's enumeration
    /// lands, and until then the daemon keeps the reach it had before the
    /// gate existed — its own package fetches above all, which is the
    /// VM-side shape of NET-080. NET-130 tightens this row to the categories
    /// design §5.1 enumerates.
    ///
    /// # Errors
    ///
    /// [`AllocationError::RevocationPending`] when the node's previous row
    /// was withdrawn and its revocation still holds the node's address past
    /// [`REVOCATION_WAIT`] ([`Self::try_register`]).
    pub fn try_register_node_namespace(
        &self,
        proxy_port: u16,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        let daemon_ip = self.subnet.daemon_ip();
        let _still_held = self.wait_for_revocations(
            &revocation_addrs(daemon_ip, Ipv4Addr::LOCALHOST),
            REVOCATION_WAIT,
        );
        let node = self.try_register(
            BoxRegistration::new(NODE_NAMESPACE, daemon_ip, Ipv4Addr::LOCALHOST)
                .with_admitted_ports([proxy_port]),
        )?;
        // The node's own listeners now include its hostname proxy port, so
        // the mirror leaves it out, a port it held before included
        // (NET-138: a node listener is never mirrored).
        self.node_mirror
            .set_node_own(&crate::control::guest_infrastructure_ports(self));
        Ok(node)
    }

    /// [`Self::try_register_node_namespace`] for a test whose node address
    /// no revocation holds.
    #[cfg(test)]
    pub fn register_node_namespace(&self, proxy_port: u16) -> Arc<BoxRecord> {
        self.try_register_node_namespace(proxy_port)
            .expect("a test's node address is never held by a revocation")
    }

    /// Spawns the thread that drops reloaded name holds nobody confirmed
    /// ([`Self::expire_unconfirmed_holds`]), once a second, for the life of
    /// the process.
    pub fn spawn_upkeep(&self) {
        let registry = self.clone();
        let spawned = std::thread::Builder::new()
            .name("box-registry-upkeep".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    registry.expire_unconfirmed_holds();
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(%error, "could not spawn the box registry's upkeep thread");
        }
    }

    /// The read-only view the egress gate decides by — the same rows this
    /// registry holds, shared, so every later registration reaches the
    /// running gate. The view carries a clone of the withdrawal reports'
    /// sender with it: filing one is the view's single write-shaped act, and
    /// it is a report to this process, not a row operation — see
    /// [`BoxTable`].
    #[must_use]
    pub fn table(&self) -> BoxTable {
        BoxTable {
            rows: Arc::clone(&self.rows),
            subnet: self.subnet,
            row_withdrawals: Arc::clone(&self.row_withdrawals),
            revoking: Arc::clone(&self.revoking),
        }
    }

    /// Makes a `host_ip` box resident: a box that shares the guest node's
    /// address and has no row. While it is resident its held name answers the
    /// node's address, its listeners are mirrored on the host, and, when
    /// `credentialed_upstream` is set, the stream door carries its
    /// connections to the credential proxy.
    ///
    /// The admit is the host-side client's, over the host's control socket,
    /// never anything the guest says. The box stays resident until the guest
    /// reports its end ([`Self::end_host_ip_box`]), a client retires it
    /// ([`Self::retire_host_ip_box`]), or the VM ends. Returns `true`.
    pub fn admit_host_ip_box(
        &self,
        session_id: boxes::SessionId,
        credentialed_upstream: bool,
    ) -> bool {
        let mut resident = self
            .host_ip_boxes
            .write()
            .expect("the resident host_ip boxes' lock is never held across a panic");
        // A minted id admitted with a credentialed upstream is revoked at
        // its box's destroy, a destroy after a restart too. The resident
        // set's lock is taken before the ids' lock, as on the register path.
        let credentialed_changed = credentialed_upstream && {
            let id = session_id.to_bytes();
            let mut ids = self.host_ip_id_set();
            ids.ids.contains(&id) && ids.credentialed.insert(id)
        };
        let newly_resident = resident
            .boxes
            .insert(session_id, credentialed_upstream)
            .is_none();
        let count = resident.boxes.len();
        // Under the resident set's lock, so the mirror's flag follows the
        // set in order.
        let was_published = self
            .node_mirror
            .set_published(resident.boxes.keys().copied().collect());
        drop(resident);
        if credentialed_changed {
            self.persist_host_ip_ids();
        }
        // The first box since the last one ended binds the ports the guest
        // still holds as listening.
        if !was_published {
            self.node_mirror.bind_held();
        }
        // A resident box's held name answers its node's address, so the
        // answerer's table changed.
        if newly_resident {
            self.ping();
            let mirrored = self
                .node_mirror
                .mirrored_address()
                .map_or_else(|| "none".to_string(), |address| address.to_string());
            tracing::info!(
                session = %session_id,
                resident_host_ip_boxes = count,
                credentialed_upstream,
                mirrored_address = %mirrored,
                "a host_ip box is resident"
            );
        }
        true
    }

    /// Whether a resident `host_ip` box with this id was admitted with a
    /// credentialed upstream. `None` when no such box is resident.
    #[must_use]
    pub fn resident_host_ip_box(&self, id: BoxId) -> Option<bool> {
        self.host_ip_boxes
            .read()
            .expect("the resident host_ip boxes' lock is never held across a panic")
            .boxes
            .get(&boxes::SessionId::from_bytes(id))
            .copied()
    }

    /// Ends a resident `host_ip` box at the guest's word: the box stopped in
    /// the VM. Returns whether it was resident.
    pub fn end_host_ip_box(&self, id: BoxId) -> bool {
        self.retire_host_ip_box(
            boxes::SessionId::from_bytes(id),
            minimald_rpc::HostIpBoxEnd::Stopped,
        )
    }

    /// Drops the egress [`Self::admit_host_ip_box`] holds for a session:
    /// its box stopped or was destroyed, as `end` says, so its rules admit
    /// nothing from now on. A session the set does not hold is the goal
    /// state already holding. Only a destroy revokes: a destroyed box that
    /// declared a credentialed upstream under an id this registry minted
    /// has its id revoked at the Box Egress Proxy (BEP-043). A stopped box
    /// keeps its id, because a restart brings it back. Returns whether a
    /// box's rules were dropped.
    pub fn retire_host_ip_box(
        &self,
        session_id: boxes::SessionId,
        end: minimald_rpc::HostIpBoxEnd,
    ) -> bool {
        let mut resident = self
            .host_ip_boxes
            .write()
            .expect("the resident host_ip boxes' lock is never held across a panic");
        let removed_box = resident.boxes.remove(&session_id);
        let removed = removed_box.is_some();
        let credentialed = removed_box.unwrap_or(false);
        let count = resident.boxes.len();
        if removed {
            // Under the resident set's lock, so the mirror's flag follows
            // the set in order (NET-138).
            self.node_mirror
                .set_published(resident.boxes.keys().copied().collect());
        }
        drop(resident);
        // The box ended, so its registration name no longer answers a mint
        // ask: a later box under the name is a new creation. The id stays
        // for the collision check (BEP-082).
        let id = session_id.to_bytes();
        let mut ids = self.host_ip_id_set();
        let named_before = ids.by_name.len();
        ids.by_name.retain(|_, named| named.id != id);
        let name_withdrawn = ids.by_name.len() != named_before;
        let minted = ids.ids.contains(&id);
        // A stop drops the rules, so a later destroy of the stopped box
        // finds none. The id set keeps whether the box was credentialed,
        // for that destroy to revoke, across a restart too.
        let (credentialed, ids_changed) = match end {
            minimald_rpc::HostIpBoxEnd::Stopped => {
                let changed = credentialed && minted && ids.credentialed.insert(id);
                (false, changed)
            }
            minimald_rpc::HostIpBoxEnd::Destroyed => {
                let was = ids.credentialed.remove(&id);
                (was || credentialed, was)
            }
        };
        drop(ids);
        if ids_changed {
            self.persist_host_ip_ids();
        }
        // BEP-043: the destroy of a host_ip box with a credentialed lane
        // records a revocation of its minted id with the proxy, as the
        // destroy of an own-address box does. A stop revokes nothing. The
        // id stays in the id set, so no later mint takes it (BEP-082). The
        // retire never waits for the proxy.
        if credentialed
            && minted
            && let Some(path) = self.proxy_control.as_deref()
        {
            spawn_revocation(path.clone(), id, BoxEnd::HostIpRetire);
        }
        if name_withdrawn {
            tracing::info!(
                session = %session_id,
                "withdrew the host_ip box's registration name"
            );
        }
        if removed {
            tracing::info!(
                session = %session_id,
                resident_host_ip_boxes = count,
                "a host_ip box is no longer resident"
            );
            // The last host-address box ended: no box shares the node's
            // namespace any more, so nothing the mirror binds has a
            // listener behind it (NET-138's box end). The mirror checks
            // the flag again under its own lock, so a box published since
            // keeps its binds.
            if count == 0 {
                self.node_mirror.end_binds(MirrorEnd::BoxEnd);
            }
            // The box's held name answers NODATA again (NET-128).
            self.ping();
        }
        removed
    }

    /// The ids of the resident `host_ip` boxes.
    #[must_use]
    pub fn resident_host_ip_boxes(&self) -> BTreeSet<boxes::SessionId> {
        self.host_ip_boxes
            .read()
            .expect("the resident host_ip boxes' lock is never held across a panic")
            .boxes
            .keys()
            .copied()
            .collect()
    }

    /// Whether any `host_ip` box is resident.
    #[must_use]
    pub fn holds_host_ip_boxes(&self) -> bool {
        !self
            .host_ip_boxes
            .read()
            .expect("the resident host_ip boxes' lock is never held across a panic")
            .boxes
            .is_empty()
    }

    /// Sets the binder the node's mirror binds with ([`MirrorBinder`]):
    /// the host-side party that opens a listener at the node's address on
    /// the host and undoes it. Returns `self`, for the caller's chain. A
    /// registry with no binder holds every notice and binds nothing.
    #[must_use]
    pub fn with_mirror_binder(self, binder: Arc<dyn MirrorBinder>) -> Self {
        self.node_mirror.set_binder(binder);
        self
    }

    /// The node row's mirror ([`NodeMirror`]).
    pub fn node_mirror(&self) -> &NodeMirror {
        &self.node_mirror
    }

    /// Opens the node's mirror at `address`, the reserved-range address the
    /// host allocated for this node (NET-129, NET-138). The address must be
    /// in the run of the reserved local range the answerer hands out
    /// ([`switch::box_loopback_interior`]), so `127.0.0.1`, the wildcard and
    /// the answerer's own `.1` are refused, and it must not be a box row's
    /// published loopback address. A changed address undoes every bind at the old
    /// one first.
    ///
    /// # Errors
    ///
    /// [`MirrorAddressRefused`] names why the address cannot hold the
    /// node's binds. The mirror keeps its earlier address, if it had one.
    pub fn open_node_mirror(&self, address: Ipv4Addr) -> Result<(), MirrorAddressRefused> {
        // The run the answerer hands addresses out of: the range's `.1` is
        // the answerer's own, so the node's binds never open there.
        let (first, last) = switch::box_loopback_interior();
        if !(first..=last).contains(&address) {
            return Err(MirrorAddressRefused::OutsideReservedRange(address));
        }
        let held_by_a_row = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .any(|record| record.loopback_addr() == address);
        if held_by_a_row {
            return Err(MirrorAddressRefused::HeldByAnotherNamespace(address));
        }
        self.node_mirror.open(address);
        // The resident host-address boxes' names answer at the address now
        // (NET-129).
        self.ping();
        Ok(())
    }

    /// Records the whole-range probe's verdict on the node's mirror
    /// ([`NodeMirror::set_range_probe`]) and pings the table when the
    /// mirrored address changed. A failing probe then republishes the
    /// host-address names as NODATA at once (NET-129), and a passing one
    /// republishes the node's address, never a recheck interval later.
    pub fn set_node_range_probe(&self, passes: bool) {
        let before = self.node_mirror.mirrored_address();
        self.node_mirror.set_range_probe(passes);
        let after = self.node_mirror.mirrored_address();
        if before != after {
            tracing::debug!(
                ?before,
                ?after,
                range_passes = passes,
                "the node's mirrored address changed on a range probe verdict"
            );
            self.ping();
        }
    }

    /// Takes one listen notice from the in-VM daemon ([`NodeMirror::notice`])
    /// with this node's host-address boxes' residency as the gate: while
    /// no host-address box is published, a listening notice binds nothing.
    /// A listening notice for one of the node's infrastructure ports
    /// ([`crate::control::guest_infrastructure_ports`]) is refused here, so
    /// no caller can reach a bind without that check.
    pub fn mirror_notice(&self, notice: minimald_rpc::ListenNotice) -> MirrorOutcome {
        // NET-138: the node's own listeners are never mirrored.
        let infrastructure = crate::control::guest_infrastructure_ports(self);
        self.node_mirror
            .notice(notice, &infrastructure, Instant::now())
    }
}

/// The working cap on listening notices the node's mirror takes per
/// trailing second (NET-138): 20. A stop notice is never counted or
/// refused, because it can only narrow what the host binds.
pub const MIRROR_NOTICES_PER_SECOND: usize = 20;

/// The trailing window [`MIRROR_NOTICES_PER_SECOND`] counts over.
const MIRROR_NOTICE_WINDOW: Duration = Duration::from_secs(1);

/// The working cap on the ports the node's mirror holds at once, bound or
/// waiting for its bind (NET-138): 64. A listening notice for a new port
/// past it is refused as capped.
pub const MIRRORED_BINDS_CAP: usize = 64;

/// The host-side party that makes the node's mirrored binds: it opens a
/// TCP listener at the node's address on the host that forwards to the
/// same port at the guest node, and undoes it.
pub trait MirrorBinder: Send + Sync + std::fmt::Debug {
    /// Binds `port` at `address` on the host, at that port only.
    ///
    /// # Errors
    ///
    /// [`MirrorBindError::Occupied`] when something on the host already
    /// holds the port at the address. The binder never tries another port
    /// or another address.
    fn bind(&self, address: Ipv4Addr, port: u16) -> Result<(), MirrorBindError>;

    /// Undoes the bind of `port` at `address`. When the undo stands, it
    /// also resets the connections the bind still carries, and says how
    /// many it reset.
    fn unbind(&self, address: Ipv4Addr, port: u16) -> MirrorUnbind;
}

/// What a [`MirrorBinder::unbind`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorUnbind {
    /// The bind is undone, and `connections_reset` connections it carried
    /// were reset.
    Undone {
        /// How many tracked connections the undo reset.
        connections_reset: usize,
    },
    /// The host refused the undo. The bind can still stand.
    Refused(String),
    /// The host did not answer the undo. The bind can still stand.
    Unanswered(String),
}

/// Why a [`MirrorBinder`] made no bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MirrorBindError {
    /// Something on the host already holds the port at the address.
    #[error("the host port is already in use")]
    Occupied,
    /// The bind failed for another reason.
    #[error("{0}")]
    Failed(String),
    /// The host did not answer the bind. The calls after it in the same
    /// change wait for the next retry, so a stalled host costs one wait.
    #[error("{0}")]
    Unanswered(String),
}

/// Why [`BoxRegistry::open_node_mirror`] refused an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MirrorAddressRefused {
    /// The address is not in the run of the reserved local range that
    /// boxes take addresses from: the wildcard, `127.0.0.1`, the range's
    /// `.1`, or any other address.
    #[error("{0} is not an address of the reserved local range that boxes use")]
    OutsideReservedRange(Ipv4Addr),
    /// A box row publishes at the address.
    #[error("{0} is the published address of a box")]
    HeldByAnotherNamespace(Ipv4Addr),
}

/// What the node's mirror did with one listen notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorOutcome {
    /// The port is bound at the node's address.
    Bound,
    /// The port is held, and binds once the range probe passes and the
    /// node's address is open.
    Waiting,
    /// The bind is undone, or was never made.
    Unbound,
    /// Something on the host already holds the port at the node's address.
    /// Nothing was bound, at that port or any other.
    Collided,
    /// The port is one the VM host provisioned for the guest's own
    /// services. Nothing was bound.
    RefusedInfrastructure,
    /// The notice rate or the bind cap refused the notice.
    Capped,
    /// No host-address box is published on the node.
    NoHostAddressBox,
    /// The binder failed for a reason other than a held port.
    BindFailed,
    /// The notice named port 0, which no listener holds. A bind there
    /// takes whatever port the host picks, so nothing was bound.
    PortZero,
}

impl MirrorOutcome {
    /// The outcome as the audit lines name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Waiting => "waiting",
            Self::Unbound => "unbound",
            Self::Collided => "collided",
            Self::RefusedInfrastructure => "refused-infrastructure",
            Self::Capped => "capped",
            Self::NoHostAddressBox => "no-host-address-box",
            Self::BindFailed => "bind-failed",
            Self::PortZero => "port-zero",
        }
    }
}

/// What ended the node's mirrored binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorEnd {
    /// The last host-address box ended.
    BoxEnd,
    /// The node's own row ended.
    NodeEnd,
    /// The range probe stopped passing.
    RangeProbeFailed,
    /// The node's address changed.
    AddressChanged,
}

impl MirrorEnd {
    fn as_str(self) -> &'static str {
        match self {
            Self::BoxEnd => "box-end",
            Self::NodeEnd => "node-end",
            Self::RangeProbeFailed => "range-probe-failed",
            Self::AddressChanged => "address-changed",
        }
    }
}

/// The node row's mirrored binds (NET-138, NET-129). A host-address box
/// shares the guest node's namespace, so on a VM-backed host its listeners
/// are reachable on the host only when the host binds the same port at the
/// node's own reserved-range address and forwards it in. The in-VM daemon
/// tells the host which ports listen ([`minimald_rpc::ListenNotice`]): a
/// port and a state, never an address. So the host decides the address
/// alone: the node's allocated reserved-range address, never `127.0.0.1`,
/// a wildcard or another namespace's address.
///
/// The rules the mirror keeps:
///
/// * A bind is made only while the whole-range probe passes
///   ([`Self::set_range_probe`]) and the node's address is open
///   ([`BoxRegistry::open_node_mirror`]). Before that, a listening port is
///   held and bound when both hold.
/// * A port that is already in use on the host is a collision. It is
///   recorded ([`Self::collisions`]) for the surfaces that list it, and
///   never moved to another port or address.
/// * A stop notice, the last host-address box's end and the node's end
///   undo the bind. The binder resets the connections it carries. An undo
///   the host refused or did not answer is owed, and retried before every
///   later change and on every probe verdict ([`Self::set_range_probe`]).
/// * The last host-address box's end keeps the held ports: the guest
///   sends a stop notice for each one that closes. The next box's
///   publication binds the ones still held, so a port a new box listens
///   on within one guest poll is bound with no new notice.
/// * A bind that a probe pass or a new box's publication made and that
///   failed stays held, and every probe verdict retries it.
/// * A port of the node's own listeners, the ones the VM host provisioned
///   for the guest's own services and the node's hostname proxy port, is
///   never bound ([`Self::set_node_own`]). The mirror binds only the
///   host-address boxes' listeners. A port that becomes the node's own
///   after a notice held it is unbound and forgotten.
/// * Every refusal is a warn line. [`MIRROR_NOTICES_PER_SECOND`] bounds how
///   many a guest can cause.
/// * [`MIRROR_NOTICES_PER_SECOND`] and [`MIRRORED_BINDS_CAP`] bound what
///   the guest can make the host do. Each notice the rate drops counts in
///   [`Self::notices_dropped_by_rate`].
///
/// Every bind and unbind is an info line, and every refusal a warn line,
/// on the `host_table` span. Each names the node, the address, the port
/// and the outcome. A bind also names the host-address boxes published
/// on the node: they share its namespace, so the bind is theirs. Each
/// listener of the node's own that the mirror leaves out is a debug line.
#[derive(Debug)]
pub struct NodeMirror {
    /// The node's switch address: the node's name in every audit line.
    node: Ipv4Addr,
    /// Serialises every change to the mirror, with the binder calls it
    /// makes, so the binds the host holds follow the decisions in order.
    /// It is always taken before `state` and never while `state` is held.
    turn: Mutex<()>,
    /// What the mirror holds. It is held only to read or decide, and never
    /// across a binder call, so a slow switch stalls no reader and no
    /// caller that only records a fact here.
    state: Mutex<MirrorState>,
    dropped_by_rate: AtomicU64,
}

#[derive(Debug, Default)]
struct MirrorState {
    /// The node's allocated reserved-range address, once open.
    address: Option<Ipv4Addr>,
    /// Whether the whole-range probe passes.
    range_passes: bool,
    /// The host-address boxes published on the node. The registry sets
    /// them under the resident boxes' lock ([`Self::set_published`]),
    /// and a listening notice reads them under this lock, so a notice and
    /// the last box's end cannot pass each other.
    cohort: Vec<boxes::SessionId>,
    /// The ports of the node's own listeners, on the host's authority
    /// ([`crate::control::guest_infrastructure_ports`]). The mirror never
    /// binds one of them.
    node_own: BTreeSet<u16>,
    binder: Option<Arc<dyn MirrorBinder>>,
    /// The ports a listening notice holds: bound or waiting.
    wanted: BTreeSet<u16>,
    /// The ports bound at `address`.
    bound: BTreeSet<u16>,
    /// The ports whose bind collided with a holder on the host, each with
    /// the time its first collision was seen. A port leaves the map when it
    /// binds, when its listener stops, or when the binds end.
    collided: BTreeMap<u16, Instant>,
    /// The undone binds whose undo the host refused or did not answer, by
    /// port, with the address each stands at. Each is retried before the
    /// next change's calls.
    unbind_owed: BTreeMap<u16, Ipv4Addr>,
    /// When each listening notice in the trailing window arrived.
    notices: VecDeque<Instant>,
}

impl MirrorState {
    /// Whether a host-address box is published on the node.
    fn published(&self) -> bool {
        !self.cohort.is_empty()
    }

    /// The published host-address boxes, for an audit line.
    fn cohort_names(&self) -> String {
        self.cohort
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
    /// The address and binder a bind needs now: both set and the range
    /// probe passing.
    fn bind_target(&self) -> Option<(Ipv4Addr, Arc<dyn MirrorBinder>)> {
        match (self.address, self.range_passes, self.binder.clone()) {
            (Some(address), true, Some(binder)) => Some((address, binder)),
            _ => None,
        }
    }
}

/// The binder calls one change decided, made after the state lock is
/// released and under the mirror's turn.
#[derive(Debug, Default)]
struct MirrorCalls {
    unbinds: Vec<(Arc<dyn MirrorBinder>, Ipv4Addr, u16, &'static str)>,
    binds: Vec<(Arc<dyn MirrorBinder>, Ipv4Addr, u16)>,
}

impl NodeMirror {
    fn new(node: Ipv4Addr) -> Self {
        Self {
            node,
            turn: Mutex::new(()),
            state: Mutex::new(MirrorState::default()),
            dropped_by_rate: AtomicU64::new(0),
        }
    }

    fn span(&self) -> tracing::Span {
        tracing::info_span!("host_table", node = %self.node)
    }

    fn lock(&self) -> MutexGuard<'_, MirrorState> {
        self.state
            .lock()
            .expect("the node mirror's lock is never held across a panic")
    }

    fn take_turn(&self) -> MutexGuard<'_, ()> {
        self.turn
            .lock()
            .expect("the node mirror's turn is never held across a panic")
    }

    fn set_binder(&self, binder: Arc<dyn MirrorBinder>) {
        self.lock().binder = Some(binder);
    }

    /// Records the host-address boxes published on the node, and returns
    /// whether one was before. The registry calls it under the resident
    /// boxes' lock, so the set follows the resident set in order. It makes
    /// no binder call: [`Self::bind_held`] makes them after the lock.
    fn set_published(&self, cohort: Vec<boxes::SessionId>) -> bool {
        let mut state = self.lock();
        let was = state.published();
        state.cohort = cohort;
        was
    }

    /// Records the ports of the node's own listeners, the ones the VM host
    /// provisioned for the guest's own services and the node's hostname
    /// proxy port. The mirror never binds one of them. A held one is
    /// forgotten, and a bound one is undone.
    pub fn set_node_own(&self, ports: &BTreeSet<u16>) {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let calls = self.leave_out_node_own(&mut self.lock(), ports);
        self.run(calls);
    }

    /// Records `ports` as the node's own, and forgets each held port among
    /// them. Returns the unbinds that undo the bound ones. The caller holds
    /// the turn.
    fn leave_out_node_own(&self, state: &mut MirrorState, ports: &BTreeSet<u16>) -> MirrorCalls {
        state.node_own.clone_from(ports);
        let own: Vec<u16> = state.wanted.intersection(ports).copied().collect();
        let mut calls = MirrorCalls::default();
        for port in own {
            state.wanted.remove(&port);
            state.collided.remove(&port);
            if state.bound.remove(&port)
                && let (Some(address), Some(binder)) = (state.address, state.binder.clone())
            {
                calls
                    .unbinds
                    .push((binder, address, port, "node-own-listener"));
            }
            self.debug_left_out(state, port);
        }
        calls
    }

    fn debug_left_out(&self, state: &MirrorState, port: u16) {
        tracing::debug!(
            node = %self.node,
            address = ?state.address,
            port,
            "left a listener of the node's own unmirrored at the node's address"
        );
    }

    /// Binds every held port while a host-address box is published: the
    /// first box's publication after the last one ended.
    fn bind_held(&self) {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let calls = Self::bind_wanted(&self.lock());
        self.run(calls);
    }

    /// The node's address the mirror binds at, once open.
    pub fn address(&self) -> Option<Ipv4Addr> {
        self.lock().address
    }

    /// The node's address while its binds are mirrored there: the mirror
    /// is open, the whole-range probe passes, and a binder is set. `None`
    /// otherwise, and a host-address box's name then answers NODATA
    /// (NET-129).
    pub fn mirrored_address(&self) -> Option<Ipv4Addr> {
        self.lock().bind_target().map(|(address, _)| address)
    }

    /// The ports bound at the node's address.
    pub fn bound_ports(&self) -> Vec<u16> {
        self.lock().bound.iter().copied().collect()
    }

    /// The ports whose bind collided with a holder on the host, recorded on
    /// the node and logged. The host control socket's read-only
    /// `mirror_collisions` verb answers them, and `min ls` and
    /// `min session activate` show them.
    pub fn collisions(&self) -> Vec<u16> {
        self.lock().collided.keys().copied().collect()
    }

    /// [`Self::collisions`] with the time each port's first collision was
    /// seen. A port that collides again keeps its first time.
    pub fn collisions_since(&self) -> Vec<(u16, Instant)> {
        self.lock()
            .collided
            .iter()
            .map(|(port, since)| (*port, *since))
            .collect()
    }

    /// How many listening notices the rate cap dropped on this node.
    pub fn notices_dropped_by_rate(&self) -> u64 {
        self.dropped_by_rate.load(Ordering::Relaxed)
    }

    /// Records the whole-range probe's verdict. A passing verdict binds the
    /// held ports that are not bound, a repeated pass included, so a bind
    /// that failed is retried. A failing one undoes every bind and keeps
    /// the ports held, so the next pass binds them again. Either verdict
    /// retries the owed undos first.
    pub fn set_range_probe(&self, passes: bool) {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let mut state = self.lock();
        state.range_passes = passes;
        let calls = if passes {
            Self::bind_wanted(&state)
        } else {
            Self::unbind_all(&mut state, MirrorEnd::RangeProbeFailed, false)
        };
        drop(state);
        self.run(calls);
    }

    fn open(&self, address: Ipv4Addr) {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let mut state = self.lock();
        if state.address == Some(address) {
            return;
        }
        let mut calls = Self::unbind_all(&mut state, MirrorEnd::AddressChanged, false);
        state.address = Some(address);
        calls.binds = Self::bind_wanted(&state).binds;
        drop(state);
        self.run(calls);
    }

    /// Undoes every bind. [`MirrorEnd::NodeEnd`] also forgets every held
    /// port, because the node's processes are gone. Any other end keeps
    /// them: the guest sends a stop notice for each one that closes, and
    /// the next box's publication binds the rest ([`Self::bind_held`]).
    /// For [`MirrorEnd::BoxEnd`] it does nothing when a host-address box is
    /// published again by the time it runs, because that box's binds stand.
    pub fn end_binds(&self, end: MirrorEnd) {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let mut state = self.lock();
        if end == MirrorEnd::BoxEnd && state.published() {
            return;
        }
        let calls = Self::unbind_all(&mut state, end, end == MirrorEnd::NodeEnd);
        drop(state);
        self.run(calls);
    }

    /// The node's end: every bind undone and the address closed.
    pub fn end_node(&self) {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let mut state = self.lock();
        let calls = Self::unbind_all(&mut state, MirrorEnd::NodeEnd, true);
        // The unbinds name the address they undo, so it closes now.
        state.address = None;
        drop(state);
        self.run(calls);
    }

    /// Takes one listen notice that arrived at `now`. A listening notice
    /// binds only while a host-address box is published on the node. A
    /// listening notice for a port in `infrastructure`, the ports the VM
    /// host provisioned for the guest's own services, is refused on the
    /// host's authority, whatever the notice says. Every listening notice
    /// spends the notice rate, a refused one included.
    pub fn notice(
        &self,
        notice: minimald_rpc::ListenNotice,
        infrastructure: &BTreeSet<u16>,
        now: Instant,
    ) -> MirrorOutcome {
        let _span = self.span().entered();
        let _turn = self.take_turn();
        let port = notice.port;
        let mut state = self.lock();
        // The host's own view of the node's listeners comes first, so a
        // port that became the node's own since an earlier notice is
        // undone before anything else.
        let own = self.leave_out_node_own(&mut state, infrastructure);
        if !own.unbinds.is_empty() {
            drop(state);
            self.run(own);
            state = self.lock();
        }
        if notice.state == minimald_rpc::ListenState::Stopped {
            state.wanted.remove(&port);
            state.collided.remove(&port);
            let mut calls = MirrorCalls::default();
            if state.bound.remove(&port)
                && let (Some(address), Some(binder)) = (state.address, state.binder.clone())
            {
                calls.unbinds.push((binder, address, port, "stop-notice"));
            }
            drop(state);
            self.run(calls);
            return MirrorOutcome::Unbound;
        }
        while state
            .notices
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= MIRROR_NOTICE_WINDOW)
        {
            state.notices.pop_front();
        }
        if state.notices.len() >= MIRROR_NOTICES_PER_SECOND {
            let dropped = self.dropped_by_rate.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                node = %self.node,
                address = ?state.address,
                port,
                outcome = MirrorOutcome::Capped.as_str(),
                reason = "notice-rate",
                notices_dropped_by_rate = dropped,
                per_second = MIRROR_NOTICES_PER_SECOND,
                "refused a mirrored bind at the node's address"
            );
            return MirrorOutcome::Capped;
        }
        state.notices.push_back(now);
        // Checked after the rate cap, so the cap bounds the warn lines a
        // guest that repeats a forged notice can cause.
        if state.node_own.contains(&port) {
            self.debug_left_out(&state, port);
            self.warn_refused(
                &state,
                port,
                MirrorOutcome::RefusedInfrastructure,
                "guest-infrastructure-port",
            );
            return MirrorOutcome::RefusedInfrastructure;
        }
        if port == 0 {
            // A bind at port 0 takes a port the host picks, which moves the
            // listener to another port. No listener holds port 0.
            self.warn_refused(&state, port, MirrorOutcome::PortZero, "port-zero");
            return MirrorOutcome::PortZero;
        }
        if !state.published() {
            self.warn_refused(&state, port, MirrorOutcome::NoHostAddressBox, "no-cohort");
            return MirrorOutcome::NoHostAddressBox;
        }
        if state.bound.contains(&port) {
            return MirrorOutcome::Bound;
        }
        if !state.wanted.contains(&port) && state.wanted.len() >= MIRRORED_BINDS_CAP {
            self.warn_refused(&state, port, MirrorOutcome::Capped, "bind-cap");
            return MirrorOutcome::Capped;
        }
        state.wanted.insert(port);
        let Some((address, binder)) = state.bind_target() else {
            self.info_waiting(&state, port);
            return MirrorOutcome::Waiting;
        };
        drop(state);
        // The owed undos go first, as in every change ([`Self::run`]).
        let outcome = if self.retry_owed(&[(address, port)]) {
            self.bind(&binder, address, port).0
        } else {
            MirrorOutcome::BindFailed
        };
        if matches!(outcome, MirrorOutcome::Collided | MirrorOutcome::BindFailed) {
            // The reply refuses the notice, so the guest holds the port as
            // owed and sends it again. The mirror does not hold it: it is
            // not counted against the cap, and a later probe pass does not
            // bind a port that no notice holds. The turn is still held, so
            // no other change ran since the bind.
            self.lock().wanted.remove(&port);
        }
        outcome
    }

    /// The binds that make every held port bound, or none while the mirror
    /// cannot bind or no host-address box is published.
    fn bind_wanted(state: &MirrorState) -> MirrorCalls {
        let mut calls = MirrorCalls::default();
        if state.published()
            && let Some((address, binder)) = state.bind_target()
        {
            calls.binds = state
                .wanted
                .difference(&state.bound)
                .filter(|port| !state.node_own.contains(port))
                .map(|port| (Arc::clone(&binder), address, *port))
                .collect();
        }
        calls
    }

    /// Forgets every bind and returns the unbinds that undo them.
    fn unbind_all(state: &mut MirrorState, end: MirrorEnd, forget: bool) -> MirrorCalls {
        let bound = std::mem::take(&mut state.bound);
        state.collided.clear();
        if forget {
            state.wanted.clear();
        }
        let mut calls = MirrorCalls::default();
        if let (Some(address), Some(binder)) = (state.address, state.binder.clone()) {
            calls.unbinds = bound
                .into_iter()
                .map(|port| (Arc::clone(&binder), address, port, end.as_str()))
                .collect();
        }
        calls
    }

    /// Makes the binder calls one change decided: the owed undos first,
    /// then the unbinds, then the binds. The caller holds the turn and not
    /// the state lock. Once the host leaves one call unanswered, the calls
    /// after it wait: an unbind is owed, and a bind stays held for the next
    /// probe verdict. So a stalled host costs one change one wait.
    fn run(&self, calls: MirrorCalls) {
        let binding: Vec<(Ipv4Addr, u16)> = calls
            .binds
            .iter()
            .map(|(_, address, port)| (*address, *port))
            .collect();
        let mut answered = self.retry_owed(&binding);
        for (binder, address, port, reason) in calls.unbinds {
            if !answered {
                self.lock().unbind_owed.insert(port, address);
                continue;
            }
            answered = self.unbind(&binder, address, port, reason);
        }
        for (binder, address, port) in calls.binds {
            if !answered {
                tracing::debug!(
                    node = %self.node,
                    %address,
                    port,
                    "left a mirrored bind for the next retry: the host did not answer an \
                     earlier call"
                );
                continue;
            }
            answered = self.bind(&binder, address, port).1;
        }
    }

    /// Retries every owed undo, except one for a bind in `binding`: that
    /// bind is wanted again, so its undo is moot. Returns `false` when the
    /// host left a call unanswered. The caller holds the turn and not the
    /// state lock.
    fn retry_owed(&self, binding: &[(Ipv4Addr, u16)]) -> bool {
        let (owed, binder) = {
            let mut state = self.lock();
            state
                .unbind_owed
                .retain(|port, address| !binding.contains(&(*address, *port)));
            let Some(binder) = state.binder.clone() else {
                return true;
            };
            (std::mem::take(&mut state.unbind_owed), binder)
        };
        let mut answered = true;
        for (port, address) in owed {
            if !answered {
                self.lock().unbind_owed.insert(port, address);
                continue;
            }
            answered = self.unbind(&binder, address, port, "retry");
        }
        answered
    }

    /// Undoes the bind of `port` at `address` and logs what the host did.
    /// An undo the host refused or did not answer is owed. Returns `false`
    /// when the host did not answer.
    fn unbind(
        &self,
        binder: &Arc<dyn MirrorBinder>,
        address: Ipv4Addr,
        port: u16,
        reason: &str,
    ) -> bool {
        match binder.unbind(address, port) {
            MirrorUnbind::Undone { connections_reset } => {
                tracing::info!(
                    node = %self.node,
                    %address,
                    port,
                    outcome = MirrorOutcome::Unbound.as_str(),
                    reason,
                    connections_reset,
                    "undid a mirrored bind at the node's address"
                );
                true
            }
            MirrorUnbind::Refused(error) => {
                self.lock().unbind_owed.insert(port, address);
                tracing::warn!(
                    node = %self.node,
                    %address,
                    port,
                    outcome = "unbind-refused",
                    reason,
                    %error,
                    "the host refused to undo a mirrored bind at the node's address; the \
                     bind can still stand, and the undo is retried"
                );
                true
            }
            MirrorUnbind::Unanswered(error) => {
                self.lock().unbind_owed.insert(port, address);
                tracing::warn!(
                    node = %self.node,
                    %address,
                    port,
                    outcome = "unbind-unanswered",
                    reason,
                    %error,
                    "the host did not answer the undo of a mirrored bind at the node's \
                     address; the bind can still stand, and the undo is retried"
                );
                false
            }
        }
    }

    /// Binds `port` at `address` and records the outcome. Returns it, and
    /// `false` when the host did not answer. The caller holds the turn and
    /// not the state lock, so the state the bind was decided under is the
    /// state it commits to.
    fn bind(
        &self,
        binder: &Arc<dyn MirrorBinder>,
        address: Ipv4Addr,
        port: u16,
    ) -> (MirrorOutcome, bool) {
        let result = binder.bind(address, port);
        let mut state = self.lock();
        match result {
            Ok(()) => {
                state.bound.insert(port);
                state.collided.remove(&port);
                let host_address_boxes = state.cohort_names();
                drop(state);
                tracing::info!(
                    node = %self.node,
                    %address,
                    port,
                    outcome = MirrorOutcome::Bound.as_str(),
                    %host_address_boxes,
                    "mirrored a host-address box's bind at the node's address"
                );
                (MirrorOutcome::Bound, true)
            }
            Err(MirrorBindError::Occupied) => {
                state.collided.entry(port).or_insert_with(Instant::now);
                self.warn_refused(&state, port, MirrorOutcome::Collided, "port-in-use");
                (MirrorOutcome::Collided, true)
            }
            Err(MirrorBindError::Failed(error)) => {
                drop(state);
                self.warn_bind_failed(address, port, &error);
                (MirrorOutcome::BindFailed, true)
            }
            Err(MirrorBindError::Unanswered(error)) => {
                // The host may have bound it all the same, so an undo is
                // owed. A later bind of the same port makes it moot
                // ([`Self::retry_owed`]).
                state.unbind_owed.insert(port, address);
                drop(state);
                self.warn_bind_failed(address, port, &error);
                (MirrorOutcome::BindFailed, false)
            }
        }
    }

    // One warn line per refusal (NET-138's observability terms). The
    // per-node notice rate cap bounds how many reach this line.
    fn warn_bind_failed(&self, address: Ipv4Addr, port: u16, error: &str) {
        tracing::warn!(
            node = %self.node,
            %address,
            port,
            outcome = MirrorOutcome::BindFailed.as_str(),
            %error,
            "could not mirror a host-address box's bind at the node's address"
        );
    }

    fn info_waiting(&self, state: &MirrorState, port: u16) {
        tracing::info!(
            node = %self.node,
            address = ?state.address,
            port,
            outcome = MirrorOutcome::Waiting.as_str(),
            range_probe_passes = state.range_passes,
            "holding a mirrored bind until the range probe passes at the node's address"
        );
    }

    /// Logs a refusal as a warn line, each time. The per-node notice rate
    /// cap bounds how many notices reach a refusal.
    fn warn_refused(&self, state: &MirrorState, port: u16, outcome: MirrorOutcome, reason: &str) {
        tracing::warn!(
            node = %self.node,
            address = ?state.address,
            port,
            outcome = outcome.as_str(),
            reason,
            "refused a mirrored bind at the node's address"
        );
    }
}

/// A [`MirrorBinder`] for the tests: it opens a real TCP listener at the
/// port it is asked for, so a port another socket holds collides as it
/// does on a host, and records every call it took with the address the
/// mirror asked for. The listener itself is on `127.0.0.1`, because a host
/// without the reserved range's aliases (a stock macOS host) cannot bind
/// the range's addresses.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct TestMirrorBinder {
    listeners: Mutex<BTreeMap<(Ipv4Addr, u16), std::net::TcpListener>>,
    pub(crate) calls: Mutex<Vec<(&'static str, Ipv4Addr, u16)>>,
}

#[cfg(test)]
impl TestMirrorBinder {
    /// The calls taken, in order: `("bind" | "unbind", address, port)`.
    pub(crate) fn calls(&self) -> Vec<(&'static str, Ipv4Addr, u16)> {
        self.calls.lock().expect("the test binder's lock").clone()
    }

    /// The listeners open now.
    pub(crate) fn open(&self) -> Vec<(Ipv4Addr, u16)> {
        self.listeners
            .lock()
            .expect("the test binder's lock")
            .keys()
            .copied()
            .collect()
    }
}

#[cfg(test)]
impl MirrorBinder for TestMirrorBinder {
    fn bind(&self, address: Ipv4Addr, port: u16) -> Result<(), MirrorBindError> {
        self.calls
            .lock()
            .expect("the test binder's lock")
            .push(("bind", address, port));
        match std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(listener) => {
                self.listeners
                    .lock()
                    .expect("the test binder's lock")
                    .insert((address, port), listener);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                Err(MirrorBindError::Occupied)
            }
            Err(error) => Err(MirrorBindError::Failed(error.to_string())),
        }
    }

    fn unbind(&self, address: Ipv4Addr, port: u16) -> MirrorUnbind {
        self.calls
            .lock()
            .expect("the test binder's lock")
            .push(("unbind", address, port));
        self.listeners
            .lock()
            .expect("the test binder's lock")
            .remove(&(address, port));
        MirrorUnbind::Undone {
            connections_reset: 0,
        }
    }
}

/// The ids minted for `host_ip` boxes ([`BoxRegistry::register_host_ip_box`],
/// BEP-082). `ids` holds every id the daemon minted, for the collision
/// check. `by_name` holds the id each live registration name answers: one
/// entry for each name, withdrawn when the box retires.
///
/// `ids` never shrinks, on purpose. A `host_ip` box has no row, so after it
/// ends no live row holds its id, and a revocation record holds it only if
/// the proxy revoked a grant. The set is what keeps an ended box's id out
/// of a later mint's reach ([`BoxRegistry::holds_box_id`]). Its bound is
/// one 16-byte id for each `host_ip` registration since the VM host daemon
/// started. `ids` and `credentialed` persist to [`HOST_IP_IDS_FILE`], so a
/// restart keeps them: a million registrations cost about 16 MB in memory.
#[derive(Debug, Default)]
struct HostIpIds {
    ids: BTreeSet<BoxId>,
    by_name: BTreeMap<String, HostIpName>,
    /// The minted ids admitted with a credentialed lane, until their box
    /// is destroyed. Their destroy revokes them, though a stop or a
    /// restart dropped the rules that said so (BEP-043).
    credentialed: BTreeSet<BoxId>,
}

/// The id a live `host_ip` registration name answers, and when the name
/// was registered ([`HOST_IP_UNADMITTED_NAME_BOUND`]).
#[derive(Debug, Clone, Copy)]
struct HostIpName {
    id: BoxId,
    since: Instant,
}

/// The resident `host_ip` boxes: the ones a host client admitted and that
/// have not ended. The value says whether the box was admitted with a
/// credentialed upstream.
#[derive(Debug, Default)]
struct HostIpBoxes {
    boxes: BTreeMap<boxes::SessionId, bool>,
}

/// The run of published loopback addresses a box may take inside `slice`:
/// the slice clamped to the reserved local range's interior. The range's
/// network address, `.1` and its broadcast address are never a box's — a
/// slice that starts at or ends on one of them keeps it out of a box's
/// hands too.
///
/// That interior is the answerer's own hand-out run, read from its one
/// definition ([`switch::box_loopback_interior`]) rather than restated;
/// this run is the tests' single-node cursor clamped to it, so a test box
/// never holds an address the answerer would refuse.
#[cfg(test)]
fn box_loopback_run(slice: switch::LoopbackSlice) -> (u32, u32) {
    let (box_first, box_last) = switch::box_loopback_interior();
    let first = u32::from(slice.first()).max(u32::from(box_first));
    let last = u32::from(slice.last()).min(u32::from(box_last));
    (first, last)
}

/// Takes the next unspent address from `cursor`, when `first..=last` still
/// holds one: the tests' single-node loopback cursor
/// ([`BoxRegistry::register_client_box`]); the daemon's switch addresses
/// come from the hand-out book ([`SwitchAddressBook`]). Relaxed ordering: a
/// cursor's only invariant is that no two takes return the same address,
/// which an atomic update gives on every ordering. The cursor advances by
/// a checked add, so it stops at `u32::MAX` rather than wrapping back
/// into a run it already handed out, and the run's bounds are checked on
/// the taken value, so a cursor past its run's end hands out nothing.
#[cfg(test)]
fn take_next(cursor: &AtomicU32, first: u32, last: u32) -> Option<Ipv4Addr> {
    let next = cursor
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .ok()?;
    (first <= next && next <= last).then(|| Ipv4Addr::from(next))
}

/// A namespace's name under the zone apex, as the zone view holds it:
/// `<name>.min.internal`. The view normalizes what it is given, so the
/// row's name passes through exactly as the declaration spelled it.
fn zone_name(name: &str) -> String {
    format!("{name}.{}", zone_answer::ZONE_APEX)
}

/// The one form a box's registry name is compared in wherever it keys the
/// box's published address: the answerer's allocations and releases
/// ([`crate::net::answerer::box_zone_name`]), the box registry's in-flight
/// registrations ([`BoxRegistry::begin_registration`]), and its
/// live rows — the row table's name lookups
/// ([`BoxRegistry::row_by_name`]), a client
/// registration's name-collision refusal
/// ([`AllocationError::NameAlreadyHeld`]), and a
/// client withdrawal's name proof. Names are DNS labels, so the fold is
/// ASCII lower-case: "Web" and "web" are one box to the answerer, and must
/// be one to everything its hold is checked against.
pub(crate) fn canonical_box_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Whether `addr` is one an A answer in the box zone may carry (NET-127):
/// the host's shared loopback address, or an address from the reserved
/// local range the address plan publishes boxes at. Anything else — a box's
/// switch lease inside the guest's fabric, an address another host holds —
/// is not one the host OS can reach, and a name held only there answers
/// NODATA rather than pointing a lookup somewhere it cannot go. The same
/// gate the native daemon's registry applies
/// (`minimald::net::dns::is_host_answerable`), restated against the range's
/// one definition in the switch crate so the two cannot drift.
pub(crate) fn is_host_answerable(addr: Ipv4Addr) -> bool {
    addr == Ipv4Addr::LOCALHOST || in_reserved_local_range(addr)
}

/// Whether `addr` falls in the reserved local range the address plan
/// publishes boxes at.
fn in_reserved_local_range(addr: Ipv4Addr) -> bool {
    let (network, prefix) = switch::RESERVED_LOCAL_RANGE;
    let host_bits = 32 - u32::from(prefix);
    // A /0 range would mean "every address"; the shift below needs a
    // network part to keep.
    if host_bits >= 32 {
        return true;
    }
    let mask = u32::MAX << host_bits;
    u32::from(network) & mask == u32::from(addr) & mask
}

/// The read-only view of the published rows the egress gate decides by: the
/// lookup a frame's source address resolves through, and nothing else that
/// touches a row. The registry hands the gate this view because its row
/// operations are lookups only — the component that reads guest frames
/// cannot add, replace, or withdraw a row (NET-138: the table is filled on
/// the host, never from the guest).
///
/// What the view carries beside the lookups is one channel: filing a
/// withdrawal report at a relay's end. It is deliberately **not** a row
/// operation — the report leaves this process as a fact the host acts on
/// ([`BoxRegistry::detach`] through the drainer, then the withdrawal once
/// the grace passes unreattributed), so the guest's
/// influence on the table is still bounded by what it can make the host
/// observe: that a connection whose relayed traffic named an address is
/// over. Which is the withdrawal NET-133 asks for, and nothing more.
///
/// Cheap to clone; every clone shares the registry's rows, carries the
/// registry's plan beside them, and files its reports into the one channel.
#[derive(Debug, Clone)]
pub struct BoxTable {
    rows: Arc<RwLock<Rows>>,
    subnet: SwitchSubnet,
    row_withdrawals: RowWithdrawals,
    revoking: Arc<Revoking>,
}

impl BoxTable {
    /// Subscribes to row withdrawals: the receiver gets the switch address
    /// of every row the registry removes from here on, whichever path
    /// removed it (the drainer's grace sweep, [`BoxRegistry::withdraw`] or
    /// the creator's
    /// [`BoxRegistry::withdraw_client_box`]). Like the withdrawal report,
    /// this is a fact the host observed, never a row operation: the
    /// subscriber learns that a box ended and cannot add, replace or
    /// withdraw a row. The egress gate subscribes, so that it unbinds a
    /// withdrawn box's forwards and terminates their connections (design
    /// §7.1, host-side ingress revocation). A subscriber that drops its
    /// receiver is pruned on the next withdrawal.
    ///
    /// Each [`RowWithdrawal`] holds the row's addresses against reuse until
    /// the subscriber drops it, so a subscriber keeps it exactly as long as
    /// the work it does for the row's end.
    #[must_use]
    pub fn subscribe_row_withdrawals(&self) -> std::sync::mpsc::Receiver<RowWithdrawal> {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.row_withdrawals
            .lock()
            .expect("the withdrawal subscribers' lock is held only across pushes and sends")
            .push(sender);
        receiver
    }

    /// Whether a withdrawn box's revocation still holds `addr` against
    /// reuse ([`RowWithdrawal`]): the gate refuses a publish there until
    /// the revocation ends, so that it never unbinds a forward that a later
    /// publish at the same address bound.
    #[must_use]
    pub fn revocation_pending(&self, addr: [u8; 4]) -> bool {
        self.revoking.first_held(&[addr]).is_some()
    }
}

impl BoxTable {
    /// The published namespace holding the switch address `src`, when one
    /// does. This is the whole of the gate's per-frame routing: an address a
    /// row holds is decided by that row's rules, and an address no row holds
    /// is the phase's to decide ([`crate::net::egress_gate`]), never a
    /// rule's.
    #[must_use]
    pub fn by_source(&self, src: [u8; 4]) -> Option<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .get(&src)
            .cloned()
    }

    /// Whether the plan could ever hand `src` to a box: inside the registry's
    /// subnet, and inside the run its address plan allocates PTask leases from
    /// ([`SwitchSubnet::first_ptask`] through [`SwitchSubnet::last_ptask`]) —
    /// the one set of addresses a published row is ever keyed by, and so the
    /// one set whose rows the host-side creator will supply (T66's registration
    /// path). The run spans both of the plan's sub-runs — the daemon's
    /// self-allocation reserve included, which an in-VM daemon no longer
    /// draws from (NET-138), so a source there is an unregistered one; the
    /// host hands registered boxes and their task addresses only from the
    /// upper half (`hand_out_run`). The subnet's own infrastructure sits outside that
    /// run: the gateway the resolver carve-out is keyed to, the host alias,
    /// and the guest daemon's own tap, which the registry publishes a row for
    /// itself. The gate's unregistered drop (NET-085) refuses a source only
    /// from here, so no amount of it can borrow the plan's infrastructure as
    /// a source, and this predicate is what keeps that drop and the
    /// unknown-source refusal one address range apart.
    #[must_use]
    pub fn is_allocatable(&self, src: [u8; 4]) -> bool {
        let addr = u32::from(Ipv4Addr::from(src));
        self.subnet.first_ptask() <= addr && addr <= self.subnet.last_ptask()
    }

    /// Every published row, in switch-address order.
    #[must_use]
    pub fn rows(&self) -> Vec<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Whether no namespace is published.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .is_empty()
    }

    /// The plan's lease run — `first_ptask` through `last_ptask` — as the
    /// octet arrays the publish decision compares a request's switch address
    /// by. The same bounds [`Self::is_allocatable`] decides frames by; the
    /// publish decision needs them as values because its table is an owned,
    /// pure one ([`boxes::core::switch_request`]), built fresh per
    /// request.
    #[must_use]
    pub fn ptask_run(&self) -> ([u8; 4], [u8; 4]) {
        (
            Ipv4Addr::from(self.subnet.first_ptask()).octets(),
            Ipv4Addr::from(self.subnet.last_ptask()).octets(),
        )
    }

    /// The switch's own address — the plan's gateway, the address the
    /// resolver answers at ([`SwitchSubnet::dns_server`], which is the same
    /// address) — as the octet array a frame's destination is compared by.
    /// The one destination inside the fabric that is a control surface, not
    /// a destination a box's egress rules decide: the gate refuses every
    /// frame headed here but a TCP or UDP query to the resolver's port,
    /// before any row or phase is consulted — a row's admitted ports are its
    /// own ingress, never a flow to the gateway.
    #[must_use]
    pub fn gateway(&self) -> [u8; 4] {
        self.subnet.gateway().octets()
    }

    /// The subnet the rows live in — the node's own switch block, the one
    /// slice of the fabric plane a box's frames may name as local reach
    /// (a sibling, the host alias, the daemon), decided by the row's own
    /// rules and the target's ingress rather than by the gate's
    /// infrastructure rule ([`crate::net::egress_gate`]).
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }
}

#[cfg(test)]
mod tests {
    use minimald_rpc::HostIpBoxEnd;
    use std::time::Duration;

    use boxes::IpProto;
    use switch::SwitchSubnet;

    use super::*;

    /// The default switch subnet, the plan every registry below is built for.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// A published namespace's identity, as a comparable value: the row's
    /// whole content, flattened — what a before/after comparison of the table
    /// asserts on (see `host_table_never_sourced_from_guest`).
    fn row_identity(record: &BoxRecord) -> (Ipv4Addr, String, Ipv4Addr, Vec<u16>) {
        (
            record.switch_addr(),
            record.name().to_string(),
            record.loopback_addr(),
            record.admitted_ports().to_vec(),
        )
    }

    /// The host hands registered boxes only from the hand-out run — the plan
    /// run's upper half, above the daemon's self-allocation reserve — and
    /// the loopback run's exhaustion stays an explicit refusal, with no
    /// wrap. Driven on a planned carved /24, whose runs are small enough to
    /// see both edges of.
    #[test]
    fn client_boxes_hand_out_from_the_run_above_the_reserve() {
        // The plan's default subnet splits at 100.64.127.255 — pinned
        // literally, mirrored from `minimald::net::self_allocation_run`:
        // the first box takes the hand-out run's first address, never the
        // PTask run's first (that is the daemon's reserve).
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the default plan has hand-out addresses");
        assert_eq!(
            first.switch_addr(),
            Ipv4Addr::new(100, 64, 127, 255),
            "the first box takes the hand-out run's first address, above the \
             daemon's reserve"
        );

        // A planned carved /24: its PTask run is 100.64.1.2 through
        // 100.64.1.252, so its hand-out run starts at .127 — and its
        // loopback slice holds 32 addresses, which run out first. The
        // refusal is explicit and repeats: no wrap, no reuse.
        let carved = SwitchSubnet::new(Ipv4Addr::new(100, 64, 1, 0), 24).expect("valid");
        assert!(
            switch::AddressPlan::default()
                .loopback_slice_for_switch(carved)
                .is_some(),
            "the carved subnet is planned, so a refusal is a run's exhaustion, not the plan's absence"
        );
        let registry = BoxRegistry::new(carved);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the carved subnet has hand-out addresses");
        assert_eq!(
            first.switch_addr(),
            Ipv4Addr::new(100, 64, 1, 127),
            "the carved /24's hand-out run also starts above its reserve"
        );
        for index in 1..32 {
            registry
                .register_client_box(ClientBoxSpec {
                    name: format!("box{index}"),
                    ingress_ports: Vec::new(),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the slice holds 32 published addresses");
        }
        for _ in 0..2 {
            assert!(
                matches!(
                    registry.register_client_box(ClientBoxSpec {
                        name: "late".to_string(),
                        ingress_ports: Vec::new(),
                        credentialed_upstream: None,
                        dynamic_ingress: None,
                        dynamic_allowed_range: None,
                    }),
                    Err(AllocationError::LoopbackExhausted)
                ),
                "exhaustion is explicit and never wraps"
            );
        }
    }

    /// Design §7.1, the loopback run a box may take: the reserved local
    /// range's `.2` to its last-but-one address, never its network
    /// address, `.1` or its broadcast — the answerer's own hand-out run
    /// ([`switch::box_loopback_interior`]), clamped to the single-node
    /// cursor's slice. Pinned on both ends: the reserved local range's
    /// default slice and its last.
    #[test]
    fn client_boxes_take_only_the_range_s_interior() {
        // The default plan's slice starts at the range's network address,
        // and a box takes none of it: its first loopback is the run's.
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the default plan has published addresses");
        assert_eq!(
            first.loopback_addr(),
            Ipv4Addr::new(127, 0, 64, 2),
            "the first box takes the run's first address, never the range's \
             network address nor .1"
        );

        // The last slice ends on the range's broadcast address, and a box
        // takes none of that either: its last address is the run's, and a
        // further box is refused as before.
        let last = SwitchSubnet::new(Ipv4Addr::new(100, 64, 7, 0), 24).expect("valid");
        assert!(
            switch::AddressPlan::default()
                .loopback_slice_for_switch(last)
                .is_some(),
            "the last slice's subnet is planned, so the refusal below is a \
             run's exhaustion, not the plan's absence"
        );
        let registry = BoxRegistry::new(last);
        for index in 0..30 {
            registry
                .register_client_box(ClientBoxSpec {
                    name: format!("box{index}"),
                    ingress_ports: Vec::new(),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the last slice hands out 30 addresses below its last");
        }
        assert_eq!(
            registry
                .register_client_box(ClientBoxSpec {
                    name: "last".to_string(),
                    ingress_ports: Vec::new(),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the last slice holds one more published address")
                .loopback_addr(),
            Ipv4Addr::new(127, 0, 64, 254),
            "the last box takes the run's last address, never the range's \
             broadcast"
        );
        assert!(
            matches!(
                registry.register_client_box(ClientBoxSpec {
                    name: "late".to_string(),
                    ingress_ports: Vec::new(),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                }),
                Err(AllocationError::LoopbackExhausted)
            ),
            "exhaustion stays explicit and never wraps"
        );

        // A slice inside the range touches none of its reserved ends, so
        // the clamp keeps every one of its addresses.
        let middle = switch::AddressPlan::default()
            .loopback_slice_for_switch(
                SwitchSubnet::new(Ipv4Addr::new(100, 64, 3, 0), 24).expect("valid"),
            )
            .expect("a middle slice is planned");
        assert_eq!(
            box_loopback_run(middle),
            (u32::from(middle.first()), u32::from(middle.last())),
            "a middle slice loses no address to the clamp"
        );
    }

    /// BEP-070, one id names one box, so a registration whose minted id a
    /// live row or attachment already holds is refused — never re-minted,
    /// and before any address is spent, so the refusal leaves no new fact
    /// on the host — and said as one warn line naming the id. A real mint
    /// does not collide, so the test drives the collision through the
    /// registration's own door with the id it would have minted fixed.
    #[test]
    fn colliding_box_id_refused() {
        let (log, _guard) = crate::test_support::capture_log();
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");
        assert!(
            attachments.holds_id(web.box_id()),
            "the box's id is held by its row's attachment, the half of the live \
             set a source's delivery resolves through"
        );

        // A registration whose mint landed on the live row's id would name
        // the web box: refused, and the refusal names the colliding id.
        let refused = registry
            .register_client_box_as(
                ClientBoxSpec {
                    name: "impostor".to_string(),
                    ingress_ports: Vec::new(),
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
                Ipv4Addr::from(u32::from(web.loopback_addr()) + 1),
                0,
                web.box_id(),
                None,
            )
            .expect_err("an id a live box holds is not a second box's");
        assert_eq!(
            refused,
            AllocationError::CollidingBoxId { id: web.box_id() },
            "the refusal names the colliding id, the one the registration claimed"
        );

        // The refusal spent nothing: no row was published for the impostor,
        // the live row is untouched, and the hand-out run's next address is
        // still the next registration's to take.
        let rows = registry.table().rows();
        assert_eq!(rows.len(), 1, "a refused registration publishes no row");
        assert_eq!(
            row_identity(&rows[0]),
            row_identity(&web),
            "the live row is the live box's, untouched by the refusal"
        );
        let next = registry
            .register_client_box(ClientBoxSpec {
                name: "db".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a second hand-out address");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refusal spent no address: the next registration takes the \
             hand-out run's next, the address the refused one would have spent"
        );

        // One warn line names the refusal and the id it refused — the line a
        // bundle's daemon log tail reads a refused registration by.
        let logged = log.contents();
        assert_eq!(
            logged
                .matches("refused a box registration whose id is already held")
                .count(),
            1,
            "one warn line per refused registration, got: {logged}"
        );
        assert!(
            logged.contains(&format!(
                "box_id={}",
                crate::bep_attach::BoxIdText(&web.box_id())
            )),
            "the warn line names the colliding id, got: {logged}"
        );
    }

    /// A row-withdrawal subscriber is told every removed row's address,
    /// whichever path removed it: the drainer's withdrawal and the
    /// creator's. A withdrawal that removes nothing tells it nothing, and a
    /// subscriber that dropped its receiver is pruned without failing the
    /// withdrawal.
    #[test]
    fn row_withdrawals_reach_every_subscriber_by_either_path() {
        let registry = BoxRegistry::new(SUBNET);
        let spec = |name: &str| ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: vec![8080],
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let withdrawn = registry.table().subscribe_row_withdrawals();
        drop(registry.table().subscribe_row_withdrawals());
        let web = registry
            .register_client_box(spec("web"))
            .expect("the plan has an address for the first box");
        let db = registry
            .register_client_box(spec("db"))
            .expect("the plan has an address for the second box");

        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.withdraw(web.switch_addr()).is_none());
        assert!(
            registry
                .withdraw_client_box("db", db.switch_addr(), db.loopback_addr(), None)
                .expect("the withdrawing client is the row's creator")
                .is_some()
        );

        assert_eq!(
            withdrawn.try_recv().map(|w| w.switch_addr()),
            Ok(web.switch_addr())
        );
        assert_eq!(
            withdrawn.try_recv().map(|w| w.switch_addr()),
            Ok(db.switch_addr())
        );
        assert!(
            withdrawn.try_recv().is_err(),
            "a withdrawal that removed nothing told the subscriber nothing"
        );
    }

    /// The registration half of design §7.1's revocation, for a new row
    /// that arrives before the old box's revocation has run. While a
    /// subscriber holds a withdrawal, neither the row's switch address nor
    /// its per-box published address can be registered again, by any door.
    /// A row there now would receive the old box's forwarded connections,
    /// or have its own forwards unbound at the old box's end. Once the
    /// subscriber drops the withdrawal (its revocation is done), both are
    /// free.
    #[test]
    fn a_withdrawn_rows_addresses_stay_unregistrable_until_its_revocation_ends() {
        let registry = BoxRegistry::new(SUBNET);
        let withdrawn = registry.table().subscribe_row_withdrawals();
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: vec![8080],
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        let withdrawal = withdrawn.try_recv().expect("the subscriber is told");
        assert_eq!(
            withdrawal.held_addrs(),
            [web.switch_addr().octets(), web.loopback_addr().octets()],
            "the switch address and the per-box published address are both held"
        );

        // The same switch address, under another published address.
        let other_switch = Ipv4Addr::from(u32::from(web.switch_addr()) + 7);
        assert_eq!(
            registry
                .try_register(BoxRegistration::new(
                    "again",
                    web.switch_addr(),
                    Ipv4Addr::LOCALHOST
                ))
                .map(|row| row.name().to_string()),
            Err(AllocationError::RevocationPending {
                addr: web.switch_addr()
            }),
        );
        // The same published address, at another switch address.
        assert_eq!(
            registry
                .try_register(BoxRegistration::new(
                    "again",
                    other_switch,
                    web.loopback_addr()
                ))
                .map(|row| row.name().to_string()),
            Err(AllocationError::RevocationPending {
                addr: web.loopback_addr()
            }),
        );
        assert!(
            registry
                .table()
                .by_source(web.switch_addr().octets())
                .is_none()
                && registry.table().by_source(other_switch.octets()).is_none(),
            "a refused registration leaves no row behind"
        );
        assert!(
            registry
                .table()
                .revocation_pending(web.switch_addr().octets())
        );

        drop(withdrawal);
        assert!(
            !registry
                .table()
                .revocation_pending(web.switch_addr().octets())
        );
        registry
            .try_register(BoxRegistration::new(
                "again",
                web.switch_addr(),
                web.loopback_addr(),
            ))
            .expect("the revocation is done, so the addresses are free");
    }

    /// The client door waits, bounded, for a revocation to release the
    /// published address the answerer handed back, rather than refusing a
    /// box created just after another one ended.
    #[test]
    fn a_client_registration_waits_for_the_revocation_holding_its_address() {
        let registry = BoxRegistry::new(SUBNET);
        let withdrawn = registry.table().subscribe_row_withdrawals();
        let spec = |name: &str| ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: vec![8080],
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let web = registry
            .register_client_box(spec("web"))
            .expect("the plan has an address for the box");
        // Its creator's destroy, which ends the creation and its name's
        // hold, not only the row.
        assert!(
            registry
                .withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None)
                .expect("the creator's pair")
                .is_some()
        );
        let withdrawal = withdrawn.try_recv().expect("the subscriber is told");

        let started = Instant::now();
        let revoker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(withdrawal);
        });
        let again = registry
            .register_client_box_at(spec("web"), web.loopback_addr())
            .expect("the registration waited for the revocation to end");
        revoker.join().expect("the revoker thread");
        assert_eq!(again.loopback_addr(), web.loopback_addr());
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < REVOCATION_WAIT);
    }

    /// A client registration refused because a revocation still holds its
    /// published address spends no switch address: the cursor never hands
    /// one out twice, so a retry loop against a held address would
    /// otherwise use up the plan.
    #[test]
    fn a_registration_refused_for_a_held_address_spends_no_switch_address() {
        let registry = BoxRegistry::new(SUBNET);
        let withdrawn = registry.table().subscribe_row_withdrawals();
        let spec = |name: &str| ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: vec![8080],
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let web = registry
            .register_client_box(spec("web"))
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        let withdrawal = withdrawn.try_recv().expect("the subscriber is told");

        assert_eq!(
            registry
                .register_client_box_at(spec("db"), web.loopback_addr())
                .map(|row| row.name().to_string()),
            Err(AllocationError::RevocationPending {
                addr: web.loopback_addr()
            }),
        );
        drop(withdrawal);
        let next = registry
            .register_client_box(spec("next"))
            .expect("the plan has an address for the next box");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refused registration drew no switch address"
        );
    }

    /// A planned carved /24 — its hand-out run is 100.64.1.127 through
    /// 100.64.1.251, 125 addresses — small enough to draw through, with the
    /// one loopback address every box below registers at: the answerer's
    /// half is not under test, and with no withdrawal subscriber nothing
    /// holds it.
    fn carved() -> SwitchSubnet {
        SwitchSubnet::new(Ipv4Addr::new(100, 64, 1, 0), 24).expect("a /24 is a valid plan")
    }
    const CARVED_RUN: usize = 125;
    const CARVED_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 40);

    fn client_spec(name: &str) -> ClientBoxSpec {
        ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: Vec::new(),
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        }
    }

    fn register_carved(
        registry: &BoxRegistry,
        name: &str,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        registry.register_client_box_at(client_spec(name), CARVED_LOOPBACK)
    }

    /// Draws the carved run through: one row per address, each marked as a
    /// box the in-VM daemon started.
    fn fill_carved_run(registry: &BoxRegistry) -> Vec<Arc<BoxRecord>> {
        (0..CARVED_RUN)
            .map(|index| {
                let row = register_carved(registry, &format!("box{index}"))
                    .expect("the carved run holds an address for every box");
                // As a box the in-VM daemon started.
                row.mark_used();
                row
            })
            .collect()
    }

    /// Its creator's destroy of the client box `row` is: the creator's
    /// withdrawal, which ends the creation and returns its addresses — a
    /// row the drainer withdraws leaves them reserved ([`Creation`]).
    fn destroy(registry: &BoxRegistry, row: &BoxRecord) {
        assert!(
            registry
                .withdraw_client_box(
                    &row.name(),
                    row.switch_addr(),
                    row.loopback_addr(),
                    Some(row.box_id())
                )
                .expect("the creator's own pair")
                .is_some(),
            "the creator's destroy removes the row"
        );
    }

    /// The registry a test persists at `dir`, under its default plan.
    fn persisted_registry(dir: &tempfile::TempDir) -> BoxRegistry {
        BoxRegistry::new(SUBNET).persisting_to(dir.path().join(REGISTRY_FILE))
    }

    /// NET-148, NET-152: a VM's persisted box records read without a daemon
    /// — each box's name and id — and a file of another version, or one that
    /// does not parse, reads as no boxes and is left exactly as it was.
    #[test]
    fn persisted_box_names_read_without_a_daemon() {
        let dir = tempfile::tempdir().expect("a temp dir");
        assert!(
            persisted_box_names(dir.path()).is_empty(),
            "a VM with no file holds no boxes"
        );
        let registry = persisted_registry(&dir);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let api = registry
            .register_client_box(client_spec("api"))
            .expect("the plan has an address for another box");
        drop(registry);

        let mut read = persisted_box_names(dir.path());
        read.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            read,
            vec![
                PersistedBox {
                    name: "api".to_string(),
                    id: minimald_rpc::BoxId::from_bytes(api.box_id()),
                },
                PersistedBox {
                    name: "web".to_string(),
                    id: minimald_rpc::BoxId::from_bytes(web.box_id()),
                },
            ],
            "each persisted box, by name and id"
        );

        let path = dir.path().join(REGISTRY_FILE);
        for unusable in [
            r#"{"version": 99, "boxes": []}"#.as_bytes(),
            b"not json at all".as_slice(),
        ] {
            std::fs::write(&path, unusable).expect("write the unusable file");
            assert!(
                persisted_box_names(dir.path()).is_empty(),
                "an unusable file reads as no boxes"
            );
            assert_eq!(
                std::fs::read(&path).expect("the file is still there"),
                unusable,
                "and is never written or set aside"
            );
            let set_aside = std::fs::read_dir(dir.path())
                .expect("list the state dir")
                .map(|entry| entry.expect("an entry").file_name())
                .any(|name| name.to_string_lossy().contains("unusable"));
            assert!(!set_aside, "a read never sets the file aside");
        }
    }

    /// NET-138: the persisted registry is its owner's alone — mode 0600,
    /// whatever a stale temporary file left behind held — written whole by
    /// a rename, versioned, and a file of another version reloads nothing.
    #[test]
    fn the_persisted_registry_is_0600_and_atomic() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join(REGISTRY_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, b"half a file").expect("a stale temporary file");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
            .expect("a world-readable stale file");

        let registry = persisted_registry(&dir);
        registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");

        let mode = std::fs::metadata(&path)
            .expect("the file is written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the registry is its owner's alone");
        assert!(
            !tmp.exists(),
            "the temporary file was renamed over the registry"
        );
        let file: RegistryFile =
            serde_json_lenient::from_slice(&std::fs::read(&path).expect("the file reads"))
                .expect("the file parses whole");
        assert_eq!(file.version, REGISTRY_FILE_VERSION);
        assert_eq!(file.boxes.len(), 1);

        let text = std::fs::read_to_string(&path).expect("the file reads");
        std::fs::write(&path, text.replacen("\"version\": 1", "\"version\": 99", 1))
            .expect("a future version's file");
        assert!(
            persisted_registry(&dir).row_by_name("web").is_none(),
            "a file of another version reloads no row"
        );
    }

    /// A held box name is persisted and reloaded, so it survives a VM host
    /// daemon restart: a hold, an owner's takeover, and a release all land
    /// in the held-names file, and the registry the restarted daemon builds
    /// from it holds exactly the names the file says.
    #[test]
    fn held_box_names_persist_and_reload() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let owner = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000001")
            .expect("a session id");
        let other = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000002")
            .expect("a session id");

        let registry = persisted_registry(&dir);
        assert!(
            registry.hold_box_name("web", Some(owner)),
            "a name nothing holds is held"
        );
        assert!(
            !registry.hold_box_name("web", Some(owner)),
            "the same owner's hold is idempotent"
        );

        let after = persisted_registry(&dir);
        assert!(
            !after.hold_box_name("web", Some(owner)),
            "the hold is reloaded, so it is not new to the restarted daemon"
        );
        assert!(
            !after.hold_box_name("web", Some(other)),
            "and another session's hold takes it over"
        );

        let third = persisted_registry(&dir);
        let file: HeldNamesFile = serde_json_lenient::from_slice(
            &std::fs::read(dir.path().join(HELD_NAMES_FILE)).expect("the file reads"),
        )
        .expect("the file parses whole");
        assert_eq!(
            file.held_names.get("web"),
            Some(&Some(other)),
            "the takeover is what the file holds"
        );
        assert!(third.release_held_name("web", Some(other)));
        assert!(
            persisted_registry(&dir).hold_box_name("web", Some(owner)),
            "the release is persisted, so the name is free again after a restart"
        );
    }

    /// A hold never changes the registry file's format: a daemon that
    /// predates held-name persistence still reads the file a hold was made
    /// beside (its [`RegistryFile`] denies unknown fields), so rolling back
    /// costs the holds, never a creation.
    #[test]
    fn a_hold_leaves_the_registry_file_in_its_older_format() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let registry = persisted_registry(&dir);
        registry
            .register_client_box(client_spec("db"))
            .expect("the plan has an address for the box");
        let owner = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000001")
            .expect("a session id");
        assert!(registry.hold_box_name("web", Some(owner)));

        let bytes = std::fs::read(dir.path().join(REGISTRY_FILE)).expect("the file reads");
        assert_eq!(
            serde_json_lenient::from_slice::<serde_json_lenient::Value>(&bytes)
                .expect("the file parses")
                .as_object()
                .expect("the file is an object")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["boxes", "version"]),
            "the registry file carries exactly the older format's keys"
        );
        let file: RegistryFile =
            serde_json_lenient::from_slice(&bytes).expect("the file parses whole");
        assert_eq!(file.boxes.len(), 1, "and its creation");
    }

    /// The held-names file is read by each name's canonical form, so a hold
    /// the file spells another way is still the hold a release frees.
    #[test]
    fn held_box_names_reload_by_their_canonical_form() {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::write(
            dir.path().join(HELD_NAMES_FILE),
            br#"{"version": 1, "held_names": {"WEB": null}}"#,
        )
        .expect("a held-names file");

        let registry = persisted_registry(&dir);
        assert!(
            !registry.hold_box_name("web", None),
            "the reloaded hold is the canonical name's"
        );
        assert!(registry.release_held_name("web", None));
    }

    /// Two spellings in the held-names file that fold to one canonical name
    /// reload as one hold — the spelling that sorts first by its bytes,
    /// whatever order the file lists them in — so one release frees the
    /// name, and the next write holds it once.
    #[test]
    fn held_box_names_that_fold_together_reload_once() {
        let dir = tempfile::tempdir().expect("a temp dir");
        std::fs::write(
            dir.path().join(HELD_NAMES_FILE),
            br#"{"version": 1, "held_names": {
                "web": "00000000-0000-4000-8000-000000000002",
                "WEB": "00000000-0000-4000-8000-000000000001"
            }}"#,
        )
        .expect("a held-names file");
        let first = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000001")
            .expect("a session id");

        let registry = persisted_registry(&dir);
        assert_eq!(
            registry
                .held_names
                .read()
                .expect("the held names read")
                .clone(),
            BTreeMap::from([("web".to_string(), Some(first))]),
            "one hold, the spelling's that sorts first, though the file lists it last"
        );
        assert!(registry.release_held_name("Web", Some(first)));
        let file: HeldNamesFile = serde_json_lenient::from_slice(
            &std::fs::read(dir.path().join(HELD_NAMES_FILE)).expect("the file reads"),
        )
        .expect("the file parses whole");
        assert!(file.held_names.is_empty(), "the one release freed the name");
    }

    /// A reloaded hold nothing re-makes is dropped once
    /// [`HELD_NAME_RECONFIRM_BOUND`] has passed, in memory and in the file,
    /// so a session destroyed without its release does not keep its name
    /// answering NODATA for good; a reloaded hold a session re-makes in time
    /// stays, past the bound too.
    #[test]
    fn an_unconfirmed_reloaded_hold_expires_and_a_reconfirmed_one_stays() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let gone = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000001")
            .expect("a session id");
        let live = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000002")
            .expect("a session id");
        let before = persisted_registry(&dir);
        assert!(before.hold_box_name("old", Some(gone)));
        assert!(before.hold_box_name("web", Some(live)));

        let registry = persisted_registry(&dir);
        registry.advance_clock(HELD_NAME_RECONFIRM_BOUND.saturating_sub(Duration::from_secs(10)));
        assert_eq!(
            registry.expire_unconfirmed_holds(),
            0,
            "nothing is dropped inside the bound"
        );
        assert!(
            !registry.hold_box_name("web", Some(live)),
            "the live session re-makes its reloaded hold"
        );
        registry.advance_clock(Duration::from_secs(10));
        assert_eq!(
            registry.expire_unconfirmed_holds(),
            1,
            "the hold nothing re-made is dropped at the bound"
        );
        let held = |registry: &BoxRegistry, name: &str| {
            registry
                .zone_view()
                .rows()
                .any(|(held, _)| held == zone_name(name))
        };
        assert!(!held(&registry, "old"), "the dropped name answers nothing");
        assert!(held(&registry, "web"), "the re-made hold stands");
        registry.advance_clock(HELD_NAME_RECONFIRM_BOUND);
        assert_eq!(
            registry.expire_unconfirmed_holds(),
            0,
            "a re-made hold has no bound"
        );

        let file: HeldNamesFile = serde_json_lenient::from_slice(
            &std::fs::read(dir.path().join(HELD_NAMES_FILE)).expect("the file reads"),
        )
        .expect("the file parses whole");
        assert_eq!(
            file.held_names,
            BTreeMap::from([("web".to_string(), Some(live))]),
            "the drop is persisted"
        );
    }

    /// A held-names file this build cannot use — of another version, or not
    /// parsing — is set aside like an unusable registry file and reloads no
    /// hold, and it costs the holds alone: the registry file's creations
    /// reload as they would without it, and the next hold writes a new one.
    #[test]
    fn an_unusable_held_names_file_is_set_aside_and_keeps_the_creations() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let held = dir.path().join(HELD_NAMES_FILE);
        persisted_registry(&dir)
            .register_client_box(client_spec("db"))
            .expect("the plan has an address for the box");
        for unusable in [
            &br#"{"version": 99, "held_names": {}}"#[..],
            b"{\"version\": 1, \"held_na",
        ] {
            std::fs::write(&held, unusable).expect("an unusable file");

            let registry = persisted_registry(&dir);
            assert_eq!(
                registry.dormant_creation_rows().len(),
                1,
                "the registry file's creation reloads"
            );
            assert!(
                registry.hold_box_name("web", None),
                "the unusable file reloads no hold"
            );

            let aside: Vec<_> = std::fs::read_dir(dir.path())
                .expect("the dir lists")
                .map(|entry| entry.expect("an entry").path())
                .filter(|entry| {
                    entry
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(HELD_NAMES_FILE))
                        && entry.to_string_lossy().contains(".unusable-")
                })
                .collect();
            assert_eq!(aside.len(), 1, "the unusable file is set aside");
            assert_eq!(
                std::fs::read(&aside[0]).expect("the set-aside file reads"),
                unusable,
                "as it was"
            );
            std::fs::remove_file(&aside[0]).expect("the set-aside file removed");
            let file: HeldNamesFile =
                serde_json_lenient::from_slice(&std::fs::read(&held).expect("the file reads"))
                    .expect("the new file parses whole");
            assert_eq!(
                file.held_names.len(),
                1,
                "and a new file holds the new hold"
            );
        }
    }

    /// NET-138: a registry file this build cannot use — of another version,
    /// or not parsing — is set aside under a suffixed name, never written
    /// over by the next registration, so what it held is there to recover.
    #[test]
    fn an_unusable_registry_file_is_set_aside_not_overwritten() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join(REGISTRY_FILE);
        for unusable in [&br#"{"version": 99, "boxes": []}"#[..], b"not json at all"] {
            for entry in std::fs::read_dir(dir.path()).expect("the dir lists") {
                std::fs::remove_file(entry.expect("an entry").path()).expect("a file removed");
            }
            std::fs::write(&path, unusable).expect("an unusable file");

            let registry = persisted_registry(&dir);
            registry
                .register_client_box(client_spec("web"))
                .expect("the plan has an address for the box");

            let aside: Vec<_> = std::fs::read_dir(dir.path())
                .expect("the dir lists")
                .map(|entry| entry.expect("an entry").path())
                .filter(|entry| entry.to_string_lossy().contains(".unusable-"))
                .collect();
            assert_eq!(aside.len(), 1, "the unusable file is set aside");
            assert_eq!(
                std::fs::read(&aside[0]).expect("the set-aside file reads"),
                unusable,
                "as it was"
            );
            let file: RegistryFile =
                serde_json_lenient::from_slice(&std::fs::read(&path).expect("the file reads"))
                    .expect("the new file parses whole");
            assert_eq!(file.boxes.len(), 1, "and a new file holds the new creation");
        }
    }

    /// A registry file an older run could have written twice — one creation
    /// parked on a loopback an earlier line already holds — is reloaded
    /// with only the first box at that address, in the file's order: the
    /// later line is set aside, because a loopback held twice cannot serve
    /// two boxes. The file keeps no registration time, so the file's order
    /// is the only order the reload has.
    #[test]
    fn a_registry_file_holding_one_loopback_twice_reloads_the_first_box_only() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let before = persisted_registry(&dir);
        let api = before
            .register_client_box(client_spec("api"))
            .expect("the plan has an address for the box");
        let _web = before
            .register_client_box_at(client_spec("web"), api.loopback_addr())
            .expect("a second box parks itself on the first box's address");

        let after = persisted_registry(&dir);
        let reloaded = after.dormant_creation_rows();
        assert_eq!(
            reloaded.len(),
            1,
            "the second box at the address is dropped"
        );
        assert_eq!(reloaded[0].1, api.loopback_addr());
        assert!(
            resume(&after, &api).is_ok(),
            "the first box at the address is the one reloaded"
        );
    }

    /// NET-138: a resume keeps the box at the loopback address it was
    /// created with. An allocation at another address is refused even when
    /// no row holds the old one, and nothing is moved or persisted: the
    /// creator proves itself with the pair it was handed, so a moved pair
    /// would refuse its every later resume and withdrawal.
    #[test]
    fn a_resume_never_moves_the_creation_to_another_loopback() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let registry = persisted_registry(&dir);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.row_by_name("web").is_none(), "the row is gone");

        let allocated = Ipv4Addr::new(127, 0, 64, 200);
        let claim = registry.begin_registration("web");
        assert_eq!(
            registry.resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                allocated,
                claim.generation(),
            ),
            Err(ResumeError::LoopbackMoved {
                name: "web".to_string(),
                held: web.loopback_addr(),
                allocated,
            })
        );
        assert!(registry.row_by_name("web").is_none(), "nothing stands");

        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
            .expect("the creator's own pair still resumes the box");
        assert_eq!(resumed.loopback_addr(), web.loopback_addr());
    }

    /// NET-138: a resume of a creation whose loopback a live row now holds
    /// is refused, changing nothing — the answerer's allocation cannot
    /// take an address already standing on another box, and the refusal is
    /// only ever the live row's, never the dormant creation's own.
    #[test]
    fn a_resume_of_a_creation_whose_loopback_a_row_holds_is_refused() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let registry = persisted_registry(&dir);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.row_by_name("web").is_none(), "the row is gone");
        registry
            .register_client_box_at(client_spec("peer"), web.loopback_addr())
            .expect("a fresh box takes the dormant creation's address");

        let allocated = Ipv4Addr::new(127, 0, 64, 200);
        let claim = registry.begin_registration("web");
        assert_eq!(
            registry.resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                allocated,
                claim.generation(),
            ),
            Err(ResumeError::LoopbackMoved {
                name: "web".to_string(),
                held: web.loopback_addr(),
                allocated,
            })
        );
        assert!(registry.row_by_name("web").is_none(), "nothing stands");
        assert!(
            registry.row_by_name("peer").is_some(),
            "the row holding the address is untouched"
        );
    }

    /// BOX-004: a dormant creation is a stopped box, and it holds no name.
    /// A registration under the name, in any spelling that folds to it,
    /// takes the name over: it gets a row of its own under a new id. The
    /// stopped box keeps its creation and its addresses. Its resume by its
    /// box id is refused while the new box's row stands, and is accepted
    /// once that row is withdrawn. A later zone hold of the name takes over
    /// the stopped box's hold too.
    #[test]
    fn reuse_of_a_stopped_name_takes_over_its_hold() {
        let (log, _guard) = crate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        let stopped = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000001")
            .expect("a session id");
        let reused = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000002")
            .expect("a session id");
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        assert!(registry.hold_box_name("web", Some(stopped)));
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.row_by_name("web").is_none(), "the row is gone");

        let new = registry
            .register_client_box(client_spec("WEB"))
            .expect("a stopped box's name is free for a new box");
        assert_ne!(new.box_id(), web.box_id(), "the new box has its own id");
        assert_eq!(
            registry
                .row_by_name("web")
                .expect("the new box's row stands")
                .box_id(),
            new.box_id()
        );
        assert!(
            registry.live_box_ids().contains(&box_id_hex(web.box_id())),
            "the stopped box's creation is kept"
        );
        assert!(
            log.contents()
                .contains("a new box took over a stopped box's name"),
            "the log says the name was taken over: {}",
            log.contents()
        );

        let resume = || {
            let claim = registry.begin_registration("web");
            registry.resume_client_box(
                "web",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id()),
                web.loopback_addr(),
                claim.generation(),
            )
        };
        assert_eq!(
            registry
                .resumable(
                    "web",
                    web.switch_addr(),
                    web.loopback_addr(),
                    Some(web.box_id())
                )
                .map(|_| ()),
            Err(ResumeError::Allocation(AllocationError::NameAlreadyHeld {
                held: "WEB".to_string()
            })),
            "the stopped box does not resume while the new box's row stands"
        );
        assert_eq!(
            resume().map(|row| row.box_id()),
            Err(ResumeError::Allocation(AllocationError::NameAlreadyHeld {
                held: "WEB".to_string()
            })),
            "the refusal names the running box that holds the name"
        );
        assert_eq!(
            registry
                .row_by_name("web")
                .expect("the new box's row is untouched")
                .box_id(),
            new.box_id()
        );

        assert!(
            !registry.hold_box_name("WEB", Some(reused)),
            "the new box's hold takes the stopped box's hold over"
        );
        assert!(
            registry.release_held_name("web", Some(reused)),
            "the hold is the new box's now"
        );

        assert!(registry.withdraw(new.switch_addr()).is_some());
        let resumed = resume().expect("the stopped box resumes once no row holds its name");
        assert_eq!(resumed.box_id(), web.box_id(), "under its own id");
        assert_eq!(resumed.switch_addr(), web.switch_addr());
        assert_eq!(resumed.loopback_addr(), web.loopback_addr());
        assert!(
            registry.live_box_ids().contains(&box_id_hex(new.box_id())),
            "the new box, stopped now, keeps its creation in turn"
        );
        assert_eq!(
            registry.withdraw_client_box("WEB", new.switch_addr(), new.loopback_addr(), None),
            Ok(None),
            "the new box's creator can destroy its stopped box"
        );
        assert!(
            !registry.live_box_ids().contains(&box_id_hex(new.box_id())),
            "the destroy ends the new box's creation"
        );
    }

    /// NET-138: a resume naming the box's id finds its creation whatever the
    /// session is called now — renamed since its registration — and answers
    /// the row under the creation's own name; without the id, a renamed
    /// session's resume finds nothing. [`BoxRegistry::resumable`] reads
    /// the same lookup, answering a standing row as itself and a dormant
    /// creation by its own name.
    #[test]
    fn a_resume_by_box_id_survives_a_rename() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let (switch, loopback) = (web.switch_addr(), web.loopback_addr());
        assert!(
            matches!(
                registry.resumable("renamed", switch, loopback, Some(web.box_id())),
                Ok(Resumable::Standing(row)) if Arc::ptr_eq(&row, &web)
            ),
            "a standing row is the resume's whole answer"
        );
        assert!(registry.withdraw(switch).is_some());
        assert!(
            matches!(
                registry.resumable("renamed", switch, loopback, Some(web.box_id())),
                Ok(Resumable::Dormant { name }) if name == "web"
            ),
            "a dormant creation is resumed under its own name"
        );
        assert!(
            matches!(
                registry.resumable("renamed", switch, loopback, None),
                Err(ResumeError::NoCreation { .. })
            ),
            "by name alone a renamed session finds nothing"
        );

        let claim = registry.begin_registration("web");
        let resumed = registry
            .resume_client_box(
                "renamed",
                switch,
                loopback,
                Some(web.box_id()),
                loopback,
                claim.generation(),
            )
            .expect("the id finds the creation");
        assert_eq!(&*resumed.name(), "web", "under the creation's own name");
        assert_eq!(resumed.box_id(), web.box_id());
    }

    /// The task rows filed with `web`, as the gate resolves them by source.
    fn task_rows_of(registry: &BoxRegistry, web: &BoxRecord) -> Vec<Arc<BoxRecord>> {
        let table = registry.table();
        web.task_addrs()
            .iter()
            .filter_map(|addr| table.by_source(addr.octets()))
            .collect()
    }

    fn register_carved_with_task_slots(
        registry: &BoxRegistry,
        name: &str,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        registry.register_client_box_at_with_task_slots(
            client_spec(name),
            CARVED_LOOPBACK,
            minimald_rpc::TASK_SLOTS_PER_BOX,
        )
    }

    /// NET-138: task slots are best-effort. A box registers with as many as
    /// the book can spare above [`TASK_SLOT_FLOOR`] — fewer than it asked
    /// for, down to none — and is never refused for want of them.
    #[test]
    fn a_box_registers_with_fewer_task_slots_when_the_book_is_short() {
        let registry = BoxRegistry::new(carved());
        // Leave the floor and three more: the box's own address and two
        // task slots.
        for index in 0..CARVED_RUN - TASK_SLOT_FLOOR - 3 {
            register_carved(&registry, &format!("box{index}"))
                .expect("the carved run holds an address for every box");
        }

        let web = register_carved_with_task_slots(&registry, "web")
            .expect("a box is registered on its own address");
        assert_eq!(web.task_addrs().len(), 2, "two of the four task slots");
        assert_eq!(task_rows_of(&registry, &web).len(), 2);

        let api = register_carved_with_task_slots(&registry, "api")
            .expect("a box with no task slot to spare still registers");
        assert!(api.task_addrs().is_empty(), "the book is at its floor");
        assert_eq!(
            registry.live_switch_addrs(),
            CARVED_RUN - TASK_SLOT_FLOOR + 1,
            "the floor gave only the new box's own address"
        );
    }

    /// NET-138: task slots never take the addresses new boxes need. Boxes
    /// that each ask for every task slot register until the run is drawn
    /// through, and the last [`TASK_SLOT_FLOOR`] of them register with none:
    /// the floor was held for their own addresses.
    #[test]
    fn task_slots_never_starve_a_new_box() {
        let registry = BoxRegistry::new(carved());
        let mut boxes = Vec::new();
        let refusal = loop {
            match register_carved_with_task_slots(&registry, &format!("box{}", boxes.len())) {
                Ok(row) => boxes.push(row),
                Err(error) => break error,
            }
        };
        assert!(
            matches!(refusal, AllocationError::SwitchExhausted(_)),
            "only an exhausted run refuses a box: {refusal:?}"
        );
        assert_eq!(
            registry.live_switch_addrs(),
            CARVED_RUN,
            "every address out"
        );
        let slotless = boxes
            .iter()
            .rev()
            .take_while(|row| row.task_addrs().is_empty())
            .count();
        assert!(
            slotless >= TASK_SLOT_FLOOR,
            "the floor kept {slotless} addresses for new boxes, short of {TASK_SLOT_FLOOR}"
        );
        assert!(
            boxes[0].task_addrs().len() == usize::from(minimald_rpc::TASK_SLOTS_PER_BOX),
            "a box registered while the book is roomy gets every task slot"
        );
    }

    /// NET-138: a box whose creator withdrew it cannot be resumed — the
    /// creation ends with the creator's withdrawal, row or no row.
    #[test]
    fn a_withdrawn_box_cannot_be_resumed() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        registry
            .withdraw_client_box("web", web.switch_addr(), web.loopback_addr(), None)
            .expect("the creator withdraws its box");
        let claim = registry.begin_registration("web");
        assert_eq!(
            registry
                .resume_client_box(
                    "web",
                    web.switch_addr(),
                    web.loopback_addr(),
                    None,
                    web.loopback_addr(),
                    claim.generation(),
                )
                .map(|row| row.box_id()),
            Err(ResumeError::NoCreation {
                name: "web".to_string()
            })
        );
    }

    /// NET-138, design §7.1: a withdrawn row's switch address goes back to
    /// the hand-out book, but is handed again only once the shared reuse
    /// quarantine has passed — not a second before — and then to a new box
    /// with a new id.
    #[test]
    fn withdrawn_switch_address_rehanded_only_after_quarantine() {
        let registry = BoxRegistry::new(carved());
        let rows = fill_carved_run(&registry);
        let gone = &rows[7];
        destroy(&registry, gone);

        assert!(
            matches!(
                register_carved(&registry, "late"),
                Err(AllocationError::SwitchExhausted(_))
            ),
            "a returned address is not handed inside its quarantine"
        );
        registry.advance_clock(SWITCH_REUSE_QUARANTINE.saturating_sub(Duration::from_secs(1)));
        assert!(
            matches!(
                register_carved(&registry, "late"),
                Err(AllocationError::SwitchExhausted(_))
            ),
            "nor a second before the quarantine ends"
        );
        registry.advance_clock(Duration::from_secs(1));
        let again = register_carved(&registry, "late").expect("the quarantine has passed");
        assert_eq!(again.switch_addr(), gone.switch_addr());
        assert_ne!(
            again.box_id(),
            gone.box_id(),
            "a re-handed address is a new box"
        );
        assert_eq!(registry.live_switch_addrs(), CARVED_RUN);
    }

    /// The book hands never-drawn addresses first, then returned ones in
    /// return order: the address free longest goes first.
    #[test]
    fn hand_out_reuses_longest_free_first() {
        let registry = BoxRegistry::new(carved());
        let rows = fill_carved_run(&registry);
        let (first_back, second_back) = (&rows[40], &rows[3]);
        destroy(&registry, first_back);
        registry.advance_clock(Duration::from_secs(10));
        destroy(&registry, second_back);
        registry.advance_clock(SWITCH_REUSE_QUARANTINE);

        let next = register_carved(&registry, "next").expect("both quarantines have passed");
        assert_eq!(
            next.switch_addr(),
            first_back.switch_addr(),
            "the longest free goes first"
        );
        let after = register_carved(&registry, "after").expect("one more address is free");
        assert_eq!(after.switch_addr(), second_back.switch_addr());
    }

    /// An exhausted hand-out run names where it stands: the live and
    /// quarantined counts, the capacity, and when the next address frees.
    #[test]
    fn switch_exhaustion_names_live_and_quarantined() {
        let registry = BoxRegistry::new(carved());
        let rows = fill_carved_run(&registry);
        destroy(&registry, &rows[0]);
        registry.advance_clock(Duration::from_secs(100));
        let error = register_carved(&registry, "late").expect_err("the run is exhausted");
        let AllocationError::SwitchExhausted(counts) = &error else {
            panic!("the refusal is the run's exhaustion, got: {error}");
        };
        assert_eq!(
            (counts.live, counts.quarantined, counts.capacity),
            (CARVED_RUN - 1, 1, CARVED_RUN as u64)
        );
        // The real clock moves under the test's skew, so the wait is a
        // hair under the 200 s left.
        let wait = counts.next_free_in.expect("one address is quarantined");
        assert!(
            Duration::from_secs(199) < wait && wait <= Duration::from_secs(200),
            "the next address frees when its quarantine ends, got {wait:?}"
        );
        let said = error.to_string();
        assert!(
            said.contains(
                "124 of 125 box addresses are in use and 1 was released but cannot be reused yet \
                 (an address rests 300 s after its release); the next one frees in 200 s"
            ),
            "the refusal names the counts, got: {said}"
        );
        assert_eq!(
            registry.live_switch_addrs(),
            CARVED_RUN - 1,
            "the refusal holds nothing"
        );
    }

    /// The exhaustion's sentence names the resting rule only when an address
    /// is resting, and counts the resting addresses in the right number.
    #[test]
    fn switch_exhaustion_words_follow_the_quarantined_count() {
        let registry = BoxRegistry::new(carved());
        let _rows = fill_carved_run(&registry);
        let error = register_carved(&registry, "late").expect_err("the run is exhausted");
        assert!(
            matches!(&error, AllocationError::SwitchExhausted(counts) if counts.quarantined == 0),
            "nothing was returned, got: {error}"
        );
        let said = error.to_string();
        assert!(
            said.ends_with("125 of 125 box addresses are in use"),
            "a run with every address live says only that, got: {said}"
        );

        let two = HandOutCounts {
            live: 123,
            quarantined: 2,
            capacity: 125,
            next_free_in: None,
        };
        assert_eq!(
            two.to_string(),
            "123 of 125 box addresses are in use and 2 were released but cannot be reused yet \
             (an address rests 300 s after its release)"
        );
    }

    /// The box id is the epoch a withdrawal is held to: once a newer box
    /// was handed the same name and both addresses, a stale creator naming
    /// the old id removes nothing; the new row's own creator, or a client
    /// predating the field, still withdraws it.
    #[test]
    fn stale_withdrawal_with_old_box_id_leaves_new_row() {
        let registry = BoxRegistry::new(carved());
        let mut rows = fill_carved_run(&registry);
        let filler = rows.pop().expect("the run is full");
        destroy(&registry, &filler);
        registry.advance_clock(SWITCH_REUSE_QUARANTINE);
        let old = register_carved(&registry, "web").expect("the address is free again");
        // The old box is destroyed; a duplicate of its creator's
        // withdrawal arrives late.
        destroy(&registry, &old);
        let new = register_carved(&registry, "web").expect("never attributed, so free at once");
        assert_eq!(
            (new.switch_addr(), new.loopback_addr()),
            (old.switch_addr(), old.loopback_addr())
        );

        assert_eq!(
            registry.withdraw_client_box(
                "web",
                old.switch_addr(),
                old.loopback_addr(),
                Some(old.box_id())
            ),
            Err(WithdrawError::NotTheBoxId {
                switch_addr: old.switch_addr(),
                held_box_id: new.box_id(),
                asked_box_id: old.box_id(),
            })
        );
        assert_eq!(
            registry.row_by_name("web").map(|row| row.box_id()),
            Some(new.box_id()),
            "the stale withdrawal left the newer row"
        );
        assert_eq!(
            registry.withdraw_client_box("web", new.switch_addr(), new.loopback_addr(), None),
            Ok(Some(Arc::clone(&new))),
            "a client predating the field keeps the pair proof alone"
        );
    }

    /// #1116: a session renamed since its registration withdraws under its
    /// new name, while the host keeps the row and its creation under the
    /// name it was registered by. The row's own id and pair prove the
    /// creator: the row and its creation end, the withdrawal names the old
    /// name, and the old name takes a new box. Without the id, or with
    /// another box's, the new name is still refused.
    #[test]
    fn renamed_creator_withdraws_its_row_by_box_id() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let api = registry
            .register_client_box(client_spec("api"))
            .expect("the plan has an address for the box");
        let refused: Result<Option<Arc<BoxRecord>>, WithdrawError> =
            Err(WithdrawError::NotTheCreatorsRow {
                switch_addr: web.switch_addr(),
                held_name: "web".to_string(),
                asked_name: "front".to_string(),
            });

        assert_eq!(
            registry.withdraw_client_box("front", web.switch_addr(), web.loopback_addr(), None),
            refused,
            "without the id the name must be the row's"
        );
        assert_eq!(
            registry.withdraw_client_box(
                "front",
                web.switch_addr(),
                web.loopback_addr(),
                Some(api.box_id())
            ),
            refused,
            "another box's id proves nothing of this row"
        );
        assert!(
            registry.row_by_name("web").is_some(),
            "the refusals removed nothing"
        );

        assert_eq!(
            registry.withdraw_client_box_held(
                "front",
                web.switch_addr(),
                web.loopback_addr(),
                Some(web.box_id())
            ),
            Ok((Some(Arc::clone(&web)), "web".to_string())),
            "the row's own id proves the renamed creator"
        );
        assert!(
            registry.row_by_name("web").is_none(),
            "the row is withdrawn"
        );
        assert!(
            registry.release_withdrawn_unless_owned("web", || {}),
            "the creation ended with the row, so nothing owns the old name"
        );
        registry
            .register_client_box(client_spec("web"))
            .expect("the old name takes a new box");
        assert!(
            registry.row_by_name("api").is_some(),
            "the other box's row stands"
        );
    }

    /// #1116: a rename re-keys the host side. The renamed creator's
    /// request, by the row's own id and pair, moves the row and its
    /// creation to the new name: the zone answers the box's address under
    /// the new name and nothing under the old, a lookup by the new name
    /// finds the same row (its id and pair untouched), the persisted
    /// registry names the new name, and the box is withdrawn later under
    /// the new name with no id at all. Another box's id, another pair, and
    /// a name another box's row holds (in any folded spelling) are refused
    /// and move nothing.
    #[test]
    fn a_rename_re_keys_the_row_and_its_creation_by_box_id() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let registry = persisted_registry(&dir);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let api = registry
            .register_client_box(client_spec("api"))
            .expect("the plan has an address for the box");
        let answer = |name: &str| {
            registry
                .zone_view()
                .rows()
                .find(|(held, _)| *held == zone_name(name))
                .map(|(_, row)| row.address)
        };
        let before = answer("web").expect("the box's name answers");

        assert_eq!(
            registry.rename_client_box(
                "front",
                web.switch_addr(),
                web.loopback_addr(),
                api.box_id()
            ),
            Err(RenameError::NotTheBoxId {
                switch_addr: web.switch_addr(),
                held_box_id: web.box_id(),
                asked_box_id: api.box_id(),
            }),
            "another box's id proves nothing of this row"
        );
        assert!(
            matches!(
                registry.rename_client_box(
                    "front",
                    web.switch_addr(),
                    api.loopback_addr(),
                    web.box_id()
                ),
                Err(RenameError::NotTheHandedPair { .. })
            ),
            "another pair proves nothing of this row"
        );
        assert_eq!(
            registry.rename_client_box("API", web.switch_addr(), web.loopback_addr(), web.box_id()),
            Err(RenameError::NameHeld {
                name: "API".to_string(),
                holder: "api".to_string(),
            }),
            "a name another box's row holds is refused"
        );
        assert_eq!(answer("web"), Some(before), "the refusals moved nothing");
        assert_eq!(answer("front"), None);

        assert_eq!(
            registry.rename_client_box(
                "front",
                web.switch_addr(),
                web.loopback_addr(),
                web.box_id()
            ),
            Ok(Some("web".to_string())),
            "the row's own id and pair move it; the answer names the old name"
        );
        assert_eq!(
            answer("front"),
            Some(before),
            "the new name answers the box"
        );
        assert_eq!(answer("web"), None, "the old name answers nothing");
        let row = registry
            .row_by_name("front")
            .expect("the row is found by its new name");
        assert!(Arc::ptr_eq(&row, &web), "the same row, re-keyed in place");
        assert_eq!(&*web.name(), "front");
        assert!(registry.row_by_name("web").is_none());
        let persisted: Vec<_> = persisted_box_names(dir.path())
            .into_iter()
            .map(|persisted| persisted.name)
            .collect();
        assert!(
            persisted.contains(&"front".to_string()) && !persisted.contains(&"web".to_string()),
            "the persisted registry names the new name: {persisted:?}"
        );
        assert!(
            registry.release_withdrawn_unless_owned("web", || {}),
            "nothing owns the old name any more"
        );
        assert_eq!(
            registry.rename_client_box(
                "front",
                web.switch_addr(),
                web.loopback_addr(),
                web.box_id()
            ),
            Ok(Some("front".to_string())),
            "a repeated rename is answered and moves nothing"
        );

        assert_eq!(
            registry.withdraw_client_box_held(
                "front",
                web.switch_addr(),
                web.loopback_addr(),
                None
            ),
            Ok((Some(Arc::clone(&web)), "front".to_string())),
            "the row is the new name's: no id is needed to withdraw it"
        );
        assert!(
            registry.release_withdrawn_unless_owned("front", || {}),
            "the creation ended with the row"
        );
        registry
            .register_client_box(client_spec("web"))
            .expect("the old name takes a new box");
        assert!(
            registry.row_by_name("api").is_some(),
            "the other box stands"
        );
    }

    /// The loopback cursor never wraps (#1790): at `u32::MAX` it stops,
    /// so a run that spans the whole space hands nothing past its end
    /// rather than handing its first address again.
    #[test]
    fn take_next_never_wraps_its_cursor() {
        let cursor = AtomicU32::new(u32::MAX - 1);
        assert_eq!(
            take_next(&cursor, 0, u32::MAX),
            Some(Ipv4Addr::from(u32::MAX - 1))
        );
        assert_eq!(take_next(&cursor, 0, u32::MAX), None, "the cursor's end");
        assert_eq!(
            take_next(&cursor, 0, u32::MAX),
            None,
            "a cursor at its end stays there, never wrapping back to 0.0.0.0"
        );
        assert_eq!(cursor.load(Ordering::Relaxed), u32::MAX);
    }

    /// An autogen name's retry — register, withdraw the unused row, re-mint
    /// and register again — leaves the live count where one activation
    /// leaves it, and the abandoned row's address free at once.
    #[test]
    fn autogen_retry_leaves_live_counts_unchanged() {
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(client_spec("proj-ab12"))
            .expect("the plan has an address for the box");
        assert_eq!(registry.live_switch_addrs(), 1);
        assert!(
            registry
                .withdraw_client_box(
                    "proj-ab12",
                    first.switch_addr(),
                    first.loopback_addr(),
                    Some(first.box_id())
                )
                .expect("the creator's pair and id")
                .is_some()
        );
        registry
            .register_client_box(client_spec("proj-cd34"))
            .expect("the plan has an address for the retry");
        assert_eq!(
            registry.live_switch_addrs(),
            1,
            "the retry holds one address, not two"
        );
        assert_eq!(
            registry.returned_switch_addrs(),
            vec![(first.switch_addr(), true)],
            "the abandoned row's address is free to hand at once"
        );
    }

    /// With nothing subscribed to withdrawals, nothing would ever release a
    /// hold, so a withdrawal takes none.
    #[test]
    fn a_withdrawal_with_no_subscriber_holds_nothing() {
        let registry = BoxRegistry::new(SUBNET);
        let row = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::from(SUBNET.first_ptask() + 1),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(registry.withdraw(row.switch_addr()).is_some());
        assert!(
            !registry
                .table()
                .revocation_pending(row.switch_addr().octets())
        );
    }

    /// BEP-070: ids are never reused. A box registered, withdrawn, and
    /// registered again under the same name is a new creation with a new
    /// id — through the client-driven door, which spends fresh addresses,
    /// and through the explicit one on the very addresses the first box
    /// held — so a revocation scoped to the first id never names the
    /// second box.
    #[test]
    fn re_registration_never_reuses_an_id() {
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let spec = || ClientBoxSpec {
            name: "web".to_string(),
            ingress_ports: vec![8080],
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let first = registry
            .register_client_box(spec())
            .expect("the plan has an address for the first box");
        assert!(
            registry
                .withdraw_client_box("web", first.switch_addr(), first.loopback_addr(), None)
                .expect("the withdrawing client is the row's creator")
                .is_some(),
            "the first box's row was published"
        );

        // The client-driven re-registration under the same name: a new id.
        let second = registry
            .register_client_box(spec())
            .expect("the plan has an address for the second box");
        assert_ne!(
            second.box_id(),
            first.box_id(),
            "a re-registration under the same name is a new box with a new id"
        );

        // The explicit door on the first box's own name and addresses: a
        // new id again, neither of the two before it.
        let third = registry.register(
            BoxRegistration::new("web", first.switch_addr(), first.loopback_addr())
                .with_admitted_ports([8080]),
        );
        assert_eq!(
            (third.switch_addr(), third.loopback_addr()),
            (first.switch_addr(), first.loopback_addr()),
            "the third box sits on the first box's addresses"
        );
        assert!(
            third.box_id() != first.box_id() && third.box_id() != second.box_id(),
            "a box on the same name and addresses is a new box with a new id"
        );
        assert!(
            !attachments.holds_id(first.box_id())
                && attachments.holds_id(second.box_id())
                && attachments.holds_id(third.box_id()),
            "the live attachments carry the new ids; the withdrawn id is never handed out again"
        );
    }

    /// The zone view the host answerer answers from (NET-138): every
    /// published row's name under the zone apex, the host-answerable
    /// address a lookup may be told (NET-127), and the row's liveness
    /// (NET-128) — a row live from its registration, held NODATA once it
    /// is marked stopped, and gone with its withdrawal, never NXDOMAIN for
    /// a namespace that exists.
    #[test]
    fn the_zone_view_exposes_every_row_s_name_address_and_liveness() {
        let registry = BoxRegistry::new(SUBNET);
        assert!(
            registry.zone_view().is_empty(),
            "a fresh table's zone view holds nothing"
        );

        // One published box at its own address from the reserved local
        // range, one whose declared loopback address is not one the host
        // may be told — its switch lease, inside the guest's fabric — and
        // the node's own namespace at the shared loopback.
        let web = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(127, 0, 64, 9),
        ));
        registry.register(BoxRegistration::new(
            "lease-only",
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::new(100, 64, 0, 10),
        ));
        registry.register_node_namespace(7654);

        let view = registry.zone_view();
        let rows: Vec<(String, Option<Ipv4Addr>, bool)> = view
            .rows()
            .map(|(name, row)| (name.to_string(), row.address, row.live))
            .collect();
        assert_eq!(
            rows,
            [
                ("lease-only.min.internal".to_string(), None, true),
                (
                    "minimald.min.internal".to_string(),
                    Some(Ipv4Addr::LOCALHOST),
                    true
                ),
                (
                    "web.min.internal".to_string(),
                    Some(web.loopback_addr()),
                    true
                ),
            ],
            "every published row is held under its name, its host-answerable \
             address, and its liveness, in name order"
        );

        // The decision over the view answers the same shapes the native
        // daemon's registry does: an A lookup for the published address,
        // NODATA for the name held at an address the host may not be told,
        // NXDOMAIN for a name no row holds.
        let a = boxes::core::zone_answer::Lookup {
            name: "web.min.internal".to_string(),
            record: boxes::core::zone_answer::RecordType::A,
            origin: boxes::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &view),
            boxes::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a held live name answers A with its published address"
        );
        let lease_only = boxes::core::zone_answer::Lookup {
            name: "lease-only.min.internal".to_string(),
            record: boxes::core::zone_answer::RecordType::A,
            origin: boxes::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            boxes::core::zone_answer::decide(&lease_only, &view),
            boxes::core::zone_answer::Verdict::Nodata,
            "a name held only at an address the host may not be told is NODATA"
        );

        // A stopped namespace keeps its name held and answers NODATA, never
        // NXDOMAIN (NET-128), and its re-registration clears the mark: the
        // newest declaration is a namespace that is running.
        assert!(registry.mark_stopped(web.switch_addr()));
        let view = registry.zone_view();
        assert_eq!(
            view.rows()
                .find(|(name, _)| *name == "web.min.internal")
                .map(|(_, row)| *row),
            Some(zone_answer::ZoneRow {
                address: Some(web.loopback_addr()),
                live: false,
            }),
            "a stopped namespace keeps its name held, live: false"
        );
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &view),
            boxes::core::zone_answer::Verdict::Nodata,
            "a stopped namespace answers NODATA, held"
        );
        registry.register(BoxRegistration::new(
            "web",
            web.switch_addr(),
            web.loopback_addr(),
        ));
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &registry.zone_view()),
            boxes::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a re-registration is a namespace that is running again"
        );

        // And a withdrawn namespace's name is gone with its row — held by
        // no name, so NXDOMAIN, never a stopped name held forever.
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &registry.zone_view()),
            boxes::core::zone_answer::Verdict::Nxdomain,
            "a withdrawn namespace's name is held by nothing"
        );
    }

    /// The `host_ip` interim: a box that shares the node's own row
    /// publishes no row of its own, so its name is held with no row
    /// behind it — NODATA, never NXDOMAIN for a box that exists — and the
    /// release ends the interim with the session that bought it.
    #[test]
    fn the_zone_view_holds_a_host_ip_box_name_with_no_row_behind_it() {
        let registry = BoxRegistry::new(SUBNET);
        let a = boxes::core::zone_answer::Lookup {
            name: "web.min.internal".to_string(),
            record: boxes::core::zone_answer::RecordType::A,
            origin: boxes::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &registry.zone_view()),
            boxes::core::zone_answer::Verdict::Nxdomain,
            "a name nothing holds is NXDOMAIN, the pre-box state"
        );

        // The hold: NODATA, idempotent whatever the case it was asked in.
        assert!(registry.hold_box_name("web", None));
        assert!(!registry.hold_box_name("WEB", None));
        let view = registry.zone_view();
        assert_eq!(
            view.rows()
                .find(|(name, _)| *name == "web.min.internal")
                .map(|(_, row)| *row),
            Some(zone_answer::ZoneRow {
                address: None,
                live: true,
            }),
            "a held name is held with no address and live"
        );
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &view),
            boxes::core::zone_answer::Verdict::Nodata,
            "a held name answers NODATA: the box exists, no address to tell"
        );

        // The release: back to the pre-box state; a repeat is the goal
        // state already holding.
        assert!(registry.release_held_name("web", None));
        assert!(!registry.release_held_name("web", None));
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &registry.zone_view()),
            boxes::core::zone_answer::Verdict::Nxdomain,
            "a released name answers nothing again"
        );

        // A row's name is the row's: the hold does not shadow the address
        // the row answers with, and releasing it leaves the row standing.
        let web = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(127, 0, 64, 9),
        ));
        assert!(registry.hold_box_name("web", None));
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &registry.zone_view()),
            boxes::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a name a row publishes answers the row's address, hold or no hold"
        );
        assert!(registry.release_held_name("web", None));
        assert_eq!(
            boxes::core::zone_answer::decide(&a, &registry.zone_view()),
            boxes::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "the row keeps answering its address once the hold is gone"
        );
    }

    /// A release that names its session frees only that session's hold: a
    /// newer session that took the name keeps its own, and a hold a rename
    /// moved to another name is freed by the session it belongs to.
    #[test]
    fn a_session_release_frees_only_that_sessions_holds() {
        let registry = BoxRegistry::new(SUBNET);
        let held = |registry: &BoxRegistry, name: &str| {
            registry
                .zone_view()
                .rows()
                .any(|(held, _)| held == zone_name(name))
        };
        let old = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let new = boxes::SessionId::parse_str("00000000-0000-4000-8000-000000000002").unwrap();

        // A newer session took the name: the old session's release leaves it.
        assert!(registry.hold_box_name("web", Some(old)));
        assert!(!registry.hold_box_name("web", Some(new)));
        assert!(!registry.release_held_name("web", Some(old)));
        assert!(held(&registry, "web"), "the newer session's hold stays");
        assert!(registry.release_held_name("web", Some(new)));
        assert!(!held(&registry, "web"));

        // A rename moved the hold: the session's release frees it there.
        assert!(registry.hold_box_name("api", Some(old)));
        assert!(registry.release_held_name("web", Some(old)));
        assert!(
            !held(&registry, "api"),
            "the moved hold went with its session"
        );

        // A hold no session owns goes with its name.
        assert!(registry.hold_box_name("db", None));
        assert!(registry.release_held_name("db", Some(new)));
        assert!(!held(&registry, "db"));
    }

    /// NET-045: under `ask` a guest's admit report is refused — ask-yes
    /// must be host-recorded, because only the host sees the attached
    /// human's answer — with a typed refusal naming the box, and nothing is
    /// recorded: not the port, not a rate timestamp.
    #[test]
    fn ask_admit_from_guest_refused_without_host_record() {
        let registry = BoxRegistry::new(SUBNET);
        let asked = registry.register(
            BoxRegistration::new("ask-box", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Ask, Some((3000, 3999))),
        );

        let refused = registry
            .admit_runtime_port(asked.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a guest report under ask is refused");
        assert_eq!(
            refused,
            PortReportRefusal::AskNotHostRecorded {
                name: "ask-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp,
            }
        );
        assert!(
            refused
                .to_string()
                .contains("ask-yes must be host-recorded"),
            "the refusal's reason names the rule: {refused}"
        );
        assert!(
            asked.runtime_port_numbers().is_empty(),
            "the refused report records no port"
        );
        assert!(
            asked
                .runtime_ports
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .admits
                .is_empty(),
            "the refused report records no rate timestamp"
        );
    }

    /// NET-138: the alias rule resolves a name held by two live rows — a box
    /// recreated under its name while the old row's withdrawal is pending —
    /// to the newest creation, never the old row, whatever the switch
    /// addresses' order; once the newest row is withdrawn the old one is the
    /// name's live box, and once both are gone the name answers no row.
    #[test]
    fn row_by_name_resolves_newest_live_creation() {
        let registry = BoxRegistry::new(SUBNET);
        // The newer creation sits at the lower address, so the map's own
        // order would answer it last.
        let old = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 20),
            Ipv4Addr::LOCALHOST,
        ));
        let new = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
        ));
        assert!(new.box_id() > old.box_id(), "ids order by creation");
        let resolved = registry.row_by_name("web").expect("the name is live");
        assert_eq!(
            resolved.box_id(),
            new.box_id(),
            "the alias resolves to the newest creation"
        );
        let _ = registry.withdraw(new.switch_addr());
        assert_eq!(
            registry
                .row_by_name("web")
                .expect("the old row is still live")
                .box_id(),
            old.box_id()
        );
        let _ = registry.withdraw(old.switch_addr());
        assert!(registry.row_by_name("web").is_none());
        assert!(
            registry.row_by_name("Web").is_none(),
            "a withdrawn name answers no row in any folded spelling"
        );
    }

    /// The answerer keys a published address by the name's canonical
    /// form, so a client registration whose name folds to a live row's
    /// is refused — one box, one address, one row — before any address
    /// is spent, naming the spelling the live row holds; the row's own
    /// spelling is what everyone reads back.
    #[test]
    fn folded_equal_name_refused_and_the_live_row_keeps_its_spelling() {
        let (log, _guard) = crate::test_support::capture_log();
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "Web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");

        // A second client asks under a spelling that folds to the live
        // row's name: refused, naming the spelling the row holds.
        let refused = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect_err("one published address is one box's");
        assert_eq!(
            refused,
            AllocationError::NameAlreadyHeld {
                held: "Web".to_string()
            },
            "the refusal names the held spelling, not the asking one"
        );
        assert!(
            refused
                .to_string()
                .contains("a box named Web already exists"),
            "the refusal's sentence names the held spelling: {refused}"
        );

        // The refusal spent nothing: the live row stands untouched, in
        // its own spelling, and resolves under every folded spelling.
        let rows = registry.table().rows();
        assert_eq!(rows.len(), 1, "a refused registration publishes no row");
        assert_eq!(
            row_identity(&rows[0]),
            row_identity(&web),
            "the live row is the live box's, untouched by the refusal"
        );
        assert_eq!(
            &*registry
                .row_by_name("WEB")
                .expect("the name resolves in every folded spelling")
                .name(),
            "Web",
            "the row keeps its holder's spelling, the one its holder reads"
        );
        let next = registry
            .register_client_box(ClientBoxSpec {
                name: "db".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a second hand-out address");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refusal spent no address: the next registration takes the \
             hand-out run's next, the address the refused one would have spent"
        );

        // One warn line names the refusal and both spellings — the line a
        // bundle's daemon log tail reads a refused registration by.
        let logged = log.contents();
        assert_eq!(
            logged
                .matches("refused a box registration whose name a live row already holds")
                .count(),
            1,
            "one warn line per refused registration, got: {logged}"
        );
        assert!(
            logged.contains("asked=web") && logged.contains("held=Web"),
            "the warn line names the asking and the held spelling, got: {logged}"
        );
    }

    /// A withdrawal presents the same name-folding proof the registration
    /// answers under: a box registered as "web" is withdrawn by its own
    /// creator under "WEB", and the row the matching address pair points
    /// at is removed — never refused as another box's row.
    #[test]
    fn withdraw_folds_the_asking_name() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");
        assert!(
            registry
                .withdraw_client_box("WEB", web.switch_addr(), web.loopback_addr(), None)
                .expect("the asking name folds to the row's, so the proof stands")
                .is_some(),
            "the folded-equal name withdraws the row its pair proves"
        );
        assert!(
            registry.row_by_name("web").is_none(),
            "the row is withdrawn, not held against a folded-equal ask"
        );
    }

    /// NET-138, NET-045: every grant check refuses its own case, naming the
    /// box where a row exists and the check that refused — a report at an
    /// address no row holds, a deny stance (declared or the absent
    /// declaration's default), a stance whose declaration named no range, and
    /// a port outside the range — and a refusal records nothing: not the
    /// port, not a rate timestamp, no fact the host did not already hold.
    #[test]
    fn admit_report_refused_outside_range_or_under_deny() {
        let registry = BoxRegistry::new(SUBNET);
        let allow = registry.register(
            BoxRegistration::new(
                "allow-box",
                Ipv4Addr::new(100, 64, 0, 9),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let denied = registry.register(
            BoxRegistration::new(
                "denied-box",
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Deny, Some((3000, 3999))),
        );
        let ungranted = registry.register(BoxRegistration::new(
            "ungranted-box",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::LOCALHOST,
        ));
        let rangeless = registry.register(
            BoxRegistration::new(
                "rangeless-box",
                Ipv4Addr::new(100, 64, 0, 12),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, None),
        );

        // No row at the address the report named: the box is exactly what the
        // report could not prove.
        let refused = registry
            .admit_runtime_port(
                Ipv4Addr::new(100, 64, 0, 99),
                3000,
                IpProto::Tcp,
                Instant::now(),
            )
            .expect_err("a report at an address no row holds is refused");
        assert_eq!(
            refused,
            PortReportRefusal::NoRow {
                switch_addr: Ipv4Addr::new(100, 64, 0, 99),
                port: 3000,
                proto: IpProto::Tcp
            },
            "the refusal names the address no row answered at and the report it refused"
        );
        assert_eq!(
            refused.to_string(),
            "no box row is held at switch address 100.64.0.99; the reported port 3000 records \
             nowhere",
            "the wire carries the refusal's sentence verbatim"
        );

        // The deny stance — and the absent declaration's own default, which
        // is the same stance — admits nothing, whatever its range says.
        let refused = registry
            .admit_runtime_port(denied.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a report under a deny stance is refused");
        assert_eq!(
            refused,
            PortReportRefusal::DenyStance {
                name: "denied-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            }
        );
        let refused = registry
            .admit_runtime_port(ungranted.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a registration that carried no grant admits nothing");
        assert_eq!(
            refused,
            PortReportRefusal::DenyStance {
                name: "ungranted-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            },
            "an absent stance is the declaration's deny default, not a permissive one"
        );

        // A stance without a range permits nothing, and a port outside the
        // range is refused naming the range it missed — inclusive at both
        // ends, so the boundaries themselves record.
        let refused = registry
            .admit_runtime_port(rangeless.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a stance with no range permits nothing");
        assert_eq!(
            refused,
            PortReportRefusal::NoAllowedRange {
                name: "rangeless-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            }
        );
        for outside in [2999, 4000] {
            let refused = registry
                .admit_runtime_port(allow.switch_addr(), outside, IpProto::Tcp, Instant::now())
                .expect_err("a report outside the range is refused");
            assert_eq!(
                refused,
                PortReportRefusal::OutsideAllowedRange {
                    name: "allow-box".to_string(),
                    port: outside,
                    proto: IpProto::Tcp,
                    range: (3000, 3999)
                },
                "the range is inclusive, so {outside} alone is outside it"
            );
            assert_eq!(
                refused.to_string(),
                format!(
                    "runtime port {outside} is outside box allow-box's allowed range 3000-3999"
                ),
                "the refusal names the port, the box and the range it missed"
            );
        }
        for boundary in [3000, 3999] {
            registry
                .admit_runtime_port(allow.switch_addr(), boundary, IpProto::Tcp, Instant::now())
                .unwrap_or_else(|refusal| panic!("the range's own ends record, got {refusal}"));
        }

        // Every refusal recorded nothing: no port a refused report named
        // sits on any row it was checked against — the allow row holds only
        // the boundaries that recorded, and the refusals paced no rate
        // timestamp the rows' later reports answer to.
        assert_eq!(
            allow.runtime_port_numbers(),
            vec![3000, 3999],
            "only the range's own ends recorded on the allow row: no refused \
             report's port joined them"
        );
        assert!(
            denied.runtime_port_numbers().is_empty()
                && ungranted.runtime_port_numbers().is_empty()
                && rangeless.runtime_port_numbers().is_empty(),
            "a refused report records no port on any row it was checked against"
        );
        let refused = registry
            .admit_runtime_port(allow.switch_addr(), 3001, IpProto::Tcp, Instant::now())
            .expect("the refusals above did not spend the row's rate");
        assert_eq!(&*refused.name(), "allow-box");
    }

    /// A re-admit of a port the row already holds — the retry after a lost
    /// reply — is answered as recorded and spends neither the rate nor the
    /// cap: a row whose window is full still answers it, a full row still
    /// answers it, and the row's set is unchanged. A withdrawal of a port the
    /// row does not hold is answered too.
    #[test]
    fn readmit_of_a_held_port_is_idempotent_and_consumes_no_budget() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let at = Instant::now();
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, at)
            .expect("the first admit records");
        for _ in 0..ROW_ADMIT_RATE_PER_SECOND * 3 {
            registry
                .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, at)
                .expect("a re-admit of a held port is answered as recorded");
        }
        assert_eq!(
            web.runtime_port_numbers(),
            vec![3000],
            "the re-admits change nothing"
        );
        // The re-admits spent nothing: the rest of the second's rate still
        // records new ports, and only the report past it is refused.
        for port in 3001..3000 + ROW_ADMIT_RATE_PER_SECOND as u16 {
            registry
                .admit_runtime_port(web.switch_addr(), port, IpProto::Tcp, at)
                .unwrap_or_else(|refusal| panic!("port {port} records inside the rate: {refusal}"));
        }
        assert!(matches!(
            registry.admit_runtime_port(web.switch_addr(), 3999, IpProto::Tcp, at),
            Err(PortReportRefusal::RateExceeded { .. })
        ));
        // With the window full, a held port is still answered.
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, at)
            .expect("a full window still answers a re-admit of a held port");
        assert_eq!(web.runtime_port_numbers().len(), ROW_ADMIT_RATE_PER_SECOND);

        // A withdrawal of a port the row does not hold is answered.
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3998, IpProto::Tcp)
                .is_some(),
            "a withdrawal of an unheld port is the goal state already"
        );
        assert_eq!(web.runtime_port_numbers().len(), ROW_ADMIT_RATE_PER_SECOND);
    }

    /// NET-138: the per-row cap and the per-row admit rate bound what the
    /// reports can do to the host's state. A row holding
    /// [`RUNTIME_PORT_CAP`] ports refuses a report of a new port, and a row
    /// over [`ROW_ADMIT_RATE_PER_SECOND`] recorded reports in a
    /// trailing second refuses until the second passes, while a refusal paces
    /// nothing and a withdrawal never counts.
    #[test]
    fn admit_report_refused_past_row_cap_or_rate() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );

        // The cap: one report per port of a 256-port span, each a second
        // apart — past the rate window, so the cap is the only bound the
        // reports meet — and then the 257th is refused.
        let base = Instant::now();
        for (spent, port) in (3000..3000 + RUNTIME_PORT_CAP as u16).enumerate() {
            registry
                .admit_runtime_port(
                    web.switch_addr(),
                    port,
                    IpProto::Tcp,
                    base + Duration::from_secs(spent as u64),
                )
                .unwrap_or_else(|refusal| {
                    panic!("report {spent} records inside the cap, got {refusal}")
                });
        }
        assert_eq!(
            web.runtime_port_numbers().len(),
            RUNTIME_PORT_CAP,
            "the row holds the cap's worth of runtime ports"
        );
        let refused = registry
            .admit_runtime_port(
                web.switch_addr(),
                3999,
                IpProto::Tcp,
                base + Duration::from_secs(300),
            )
            .expect_err("a report past the cap is refused");
        assert_eq!(
            refused,
            PortReportRefusal::RowCapReached {
                name: "web".to_string(),
                port: 3999,
                proto: IpProto::Tcp,
                cap: RUNTIME_PORT_CAP
            }
        );
        assert_eq!(
            refused.to_string(),
            "box web already holds 256 runtime-admitted ports, its per-row cap; the reported \
             port 3999 records nothing"
        );
        registry
            .admit_runtime_port(
                web.switch_addr(),
                3000,
                IpProto::Tcp,
                base + Duration::from_secs(301),
            )
            .expect("a full row still answers a re-admit of a port it holds");

        // The rate: a fresh row's own trailing second. Ten distinct ports
        // record in one instant; the eleventh is refused, is still refused
        // half a second later, and records again once the second has passed.
        let ratebound = registry.register(
            BoxRegistration::new(
                "ratebound",
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let at = Instant::now();
        for port in 3000..3000 + ROW_ADMIT_RATE_PER_SECOND as u16 {
            registry
                .admit_runtime_port(ratebound.switch_addr(), port, IpProto::Tcp, at)
                .unwrap_or_else(|refusal| {
                    panic!("report {port} records inside the rate, got {refusal}")
                });
        }
        let refused = registry
            .admit_runtime_port(ratebound.switch_addr(), 3999, IpProto::Tcp, at)
            .expect_err("the eleventh report inside one second is refused");
        assert_eq!(
            refused,
            PortReportRefusal::RateExceeded {
                name: "ratebound".to_string(),
                port: 3999,
                proto: IpProto::Tcp,
                rate: ROW_ADMIT_RATE_PER_SECOND
            }
        );
        // A refused report paces nothing: the row's window still holds the
        // ten recorded reports, so the half-second mark refuses the same way.
        let refused = registry
            .admit_runtime_port(
                ratebound.switch_addr(),
                3999,
                IpProto::Tcp,
                at + Duration::from_millis(500),
            )
            .expect_err("a refused report does not spend the window it was refused in");
        assert!(
            matches!(refused, PortReportRefusal::RateExceeded { .. }),
            "the window holds recorded reports alone: got {refused}"
        );
        registry
            .admit_runtime_port(
                ratebound.switch_addr(),
                3999,
                IpProto::Tcp,
                at + Duration::from_secs(1),
            )
            .expect("the rate is a trailing second, so the second's passing records again");
        assert_eq!(
            ratebound.runtime_port_numbers().len(),
            ROW_ADMIT_RATE_PER_SECOND + 1,
            "eleven ports record across the window's passing"
        );

        // A withdrawal never counts against the rate and is never refused:
        // the eleventh report that the rate refused records the instant a
        // withdrawal answered between it and the window's edge.
        registry
            .withdraw_runtime_port(ratebound.switch_addr(), 3999, IpProto::Tcp)
            .expect("a withdrawal report is answered with the row it named");
    }

    /// NET-138: a withdrawal report removes the port and protocol pair it
    /// named — never refused by the cap or the rate — and a row's withdrawal
    /// takes its runtime set with it structurally: a re-registration at the
    /// same address starts empty, never inheriting the box it replaced's
    /// runtime facts.
    #[test]
    fn runtime_port_withdrawn_on_report_and_on_row_withdrawal() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let now = Instant::now();
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("the first report records");
        registry
            .admit_runtime_port(web.switch_addr(), 3001, IpProto::Tcp, now)
            .expect("the second report records");
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Udp, now)
            .expect("the third report records");

        // The withdrawal report removes the pair it named and only that pair:
        // the same port number under the other protocol stays — the pair is
        // the unit the report names and the withdrawal removes.
        let row = registry
            .withdraw_runtime_port(web.switch_addr(), 3000, IpProto::Tcp)
            .expect("the withdrawal is answered with the row it named");
        assert_eq!(&*row.name(), "web");
        assert_eq!(
            web.runtime_port_numbers(),
            [3001, 3000],
            "the withdrawn pair is gone and the same number under the other protocol stays, \
             in report order"
        );

        // Withdrawing a pair the row no longer holds is accepted all the
        // same: the row already at the report's goal state.
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3000, IpProto::Tcp)
                .is_some(),
            "a repeated withdrawal is answered with the row, never refused"
        );
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3999, IpProto::Tcp)
                .is_some(),
            "a withdrawal of a port the row never held is accepted: the goal state already holds"
        );

        // The row's own withdrawal takes the runtime set with it: the row is
        // gone, a report at its address finds no row, and the re-registration
        // that follows starts the set empty.
        let removed = registry
            .withdraw(web.switch_addr())
            .expect("the row's withdrawal answers with the row it removed");
        assert_eq!(&*removed.name(), "web");
        assert!(
            registry.row_by_name("web").is_none(),
            "a withdrawn row is gone, not archived"
        );
        assert!(
            matches!(
                registry.admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now),
                Err(PortReportRefusal::NoRow { .. })
            ),
            "a report at the withdrawn row's address records nowhere"
        );
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3001, IpProto::Tcp)
                .is_none(),
            "a withdrawal report after the row's withdrawal answers no row, and is accepted"
        );
        let fresh = registry.register(
            BoxRegistration::new("web", web.switch_addr(), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        assert!(
            fresh.runtime_port_numbers().is_empty(),
            "a re-registration starts the runtime set empty — the newest declaration never \
             inherits the row it replaced's runtime facts"
        );
    }

    /// A control socket at `path` that answers one line on each of
    /// `replies.len()` connections with that reply, and hands back the lines.
    fn stub_control(
        path: &std::path::Path,
        replies: &'static [&'static str],
    ) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
        use std::io::{BufRead as _, Write as _};

        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            replies
                .iter()
                .map(|reply| {
                    let (stream, _) = listener.accept().unwrap();
                    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                    let mut writer = stream;
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    writer.write_all(reply.as_bytes()).unwrap();
                    serde_json::from_str(&line).unwrap()
                })
                .collect()
        })
    }

    // BEP-043: the destroy's revocation is a `revoke_box` line and then a
    // `forget_box` line, each naming the box id in 32 hex digits. With no
    // proxy listening, both requests fail, and the destroy does not wait.
    #[test]
    fn destroy_revocation_sends_revoke_then_forget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let server = stub_control(&path, &["{\"ok\":true}\n", "{\"ok\":true}\n"]);
        let id = [0xab; 16];
        let submitted = super::submit_revocation(&path, id);
        assert!(submitted.revoke.is_ok() && submitted.forget.is_ok());
        let hex = "ab".repeat(16);
        let lines = server.join().unwrap();
        assert_eq!(
            lines[0],
            serde_json::json!({"op": "revoke_box", "box_id": hex})
        );
        assert_eq!(
            lines[1],
            serde_json::json!({"op": "forget_box", "box_id": hex})
        );

        let absent = super::submit_revocation(&dir.path().join("absent.sock"), id);
        assert!(absent.revoke.is_err() && absent.forget.is_err());
    }

    // BEP-063 (#2617): the live box list names each box the registry holds,
    // in 32 hex digits, in one `live_boxes` line. A registry with no control
    // socket sends nothing.
    #[test]
    fn live_boxes_names_every_box_the_registry_holds() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("the plan has an address for the box");
        let db = registry
            .register_client_box(client_spec("db"))
            .expect("the plan has an address for the box");
        let mut expected = vec![super::box_id_hex(web.box_id), super::box_id_hex(db.box_id)];
        expected.sort();
        assert_eq!(registry.live_box_ids(), expected);
        registry.send_live_boxes();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let server = stub_control(&path, &["{\"ok\":true}\n"]);
        registry
            .clone()
            .with_proxy_control(Some(path))
            .send_live_boxes();
        assert_eq!(
            server.join().unwrap(),
            [serde_json::json!({"op": "live_boxes", "box_ids": expected})]
        );
    }

    // T41: a refused `revoke_box` still sends `forget_box`, so the proxy
    // attributes the destroyed box's id to no live box.
    #[test]
    fn destroy_forgets_the_box_when_the_revocation_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let server = stub_control(
            &path,
            &["{\"ok\":false,\"error\":\"no\"}\n", "{\"ok\":true}\n"],
        );
        let id = [0xcd; 16];
        let submitted = super::submit_revocation(&path, id);
        let refused = submitted.revoke.unwrap_err().to_string();
        assert!(refused.contains("refused revoke_box: no"), "{refused}");
        assert!(submitted.forget.is_ok());
        let lines = server.join().unwrap();
        assert_eq!(
            lines[1],
            serde_json::json!({"op": "forget_box", "box_id": "cd".repeat(16)})
        );
    }

    // BEP-043: a registry from `new` sends no revocation, so a test's
    // registry never reaches a developer's running proxy. Only
    // `with_proxy_control` sets the socket, and a clone keeps it.
    #[test]
    fn new_registry_sends_no_revocation() {
        let registry = BoxRegistry::new(SUBNET);
        assert_eq!(registry.proxy_control(), None);
        assert_eq!(registry.clone().proxy_control(), None);

        let path = std::path::PathBuf::from("/run/test/control.sock");
        let wired = BoxRegistry::new(SUBNET).with_proxy_control(Some(path.clone()));
        assert_eq!(wired.proxy_control(), Some(path.as_path()));
        assert_eq!(wired.clone().proxy_control(), Some(path.as_path()));
    }

    // BEP-070: a minted id that only a revocation record holds is refused.
    // The proxy wrote the record at a destroy, and its next start restored
    // it from the audit log. No row, creation or attachment holds the id,
    // so the proxy's control socket is the only source that names it.
    #[test]
    fn a_minted_id_a_revocation_holds_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        let id = crate::bep_attach::mint_box_id();
        let hex = super::box_id_hex(id);

        // The proxy's first run revokes the box and records it in the log.
        {
            let log = bep::audit::AuditLog::open_dir(&audit_dir, bep::audit::Rotation::default())
                .unwrap();
            let records = bep::control::Records {
                audit: Some(Arc::new(Mutex::new(log))),
                ..bep::control::Records::default()
            };
            let line = serde_json::json!({"op": "revoke_box", "box_id": hex}).to_string();
            assert!(records.handle(&line).ok);
        }

        // Its next start restores the record, and serves its control socket.
        let restored = bep::revoke::restore(&audit_dir).unwrap();
        assert_eq!(restored.box_ids, vec![hex.clone()]);
        let socket = dir.path().join("bep").join("control.sock");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let control = runtime.block_on(async {
            bep::control::Control::bind(&socket, Default::default(), Default::default())
                .unwrap()
                .with_revocations(Arc::new(RwLock::new(restored.box_ids)))
        });
        let serving = runtime.spawn(control.run());

        let registry = BoxRegistry::new(SUBNET).with_proxy_control(Some(socket));
        assert_eq!(
            registry.holds_box_id(id),
            Ok(Some(super::IdHolder::RevocationRecord)),
            "only the proxy's revocation record holds the id"
        );
        let refused = registry
            .register_client_box_as(client_spec("web"), Ipv4Addr::new(127, 0, 0, 2), 0, id, None)
            .expect_err("an id a revocation record holds is not a new box's");
        assert_eq!(refused, AllocationError::CollidingBoxId { id });
        let text = refused.to_string();
        assert!(
            text.contains(&crate::bep_attach::BoxIdText(&id).to_string()),
            "{text}"
        );
        for source in [
            "running box",
            "stopped box that can resume",
            "attachment",
            "revocation record",
        ] {
            assert!(text.contains(source), "the refusal names {source}: {text}");
        }
        assert!(
            registry.table().rows().is_empty(),
            "a refused registration publishes no row"
        );

        // A fresh mint that no record holds still registers.
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("an id no record holds registers");
        assert_ne!(web.box_id(), id);
        serving.abort();
    }

    // BEP-070: a proxy that answers its control socket but does not list
    // its revocations leaves the id check unfinished, so the mint is
    // refused rather than let through. A missing socket reads as no proxy.
    #[test]
    fn a_minted_id_a_revocation_holds_is_refused_when_the_proxy_does_not_list_them() {
        use std::io::{BufRead as _, Write as _};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let answered = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            (&stream)
                .write_all(b"{\"ok\":false,\"error\":\"unknown op\"}\n")
                .unwrap();
        });
        let registry = BoxRegistry::new(SUBNET).with_proxy_control(Some(path));
        let id = crate::bep_attach::mint_box_id();
        let refused = registry
            .register_client_box_as(client_spec("web"), Ipv4Addr::new(127, 0, 0, 2), 0, id, None)
            .expect_err("an unfinished id check refuses the registration");
        answered.join().unwrap();
        assert!(
            matches!(&refused, AllocationError::RevocationsUnread { id: refused_id, why }
                if *refused_id == id && why.contains("unknown op")),
            "got {refused:?}"
        );
        assert!(
            registry.table().rows().is_empty(),
            "a refused registration publishes no row"
        );

        // No socket at the path reads as no proxy, and the box registers.
        let absent =
            BoxRegistry::new(SUBNET).with_proxy_control(Some(dir.path().join("absent.sock")));
        absent
            .register_client_box(client_spec("web"))
            .expect("with no proxy, no revocation is in force");
    }

    // BEP-070: with no proxy running, a minted id that a revocation record
    // in the proxy's audit log holds is refused. The check reads the
    // records a `bep serve` start puts back in force, and the refusal's
    // log line names the record that holds the id.
    #[test]
    fn a_minted_id_a_revocation_holds_is_refused_with_no_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let bep_dir = dir.path().join("bep");
        let audit_dir = bep_dir.join("audit");
        let socket = bep_dir.join("control.sock");
        let id = crate::bep_attach::mint_box_id();
        let hex = super::box_id_hex(id);

        // A proxy revoked the box and recorded it in the log, then stopped.
        {
            let log = bep::audit::AuditLog::open_dir(&audit_dir, bep::audit::Rotation::default())
                .unwrap();
            let records = bep::control::Records {
                audit: Some(Arc::new(Mutex::new(log))),
                ..bep::control::Records::default()
            };
            let line = serde_json::json!({"op": "revoke_box", "box_id": hex}).to_string();
            assert!(records.handle(&line).ok);
        }
        assert!(!socket.exists(), "no proxy serves the control socket");

        let registry = BoxRegistry::new(SUBNET).with_proxy_control(Some(socket.clone()));
        match registry.holds_box_id(id) {
            Ok(Some(super::IdHolder::AuditedRevocation { record, audit })) => {
                assert!(record.contains(&hex), "the record names the id: {record}");
                assert_eq!(audit, audit_dir);
            }
            other => panic!("only the audit log's revocation record holds the id: {other:?}"),
        }
        let refused = registry
            .register_client_box_as(client_spec("web"), Ipv4Addr::new(127, 0, 0, 2), 0, id, None)
            .expect_err("an id a revocation record holds is not a new box's");
        assert_eq!(refused, AllocationError::CollidingBoxId { id });
        assert!(
            refused.to_string().contains("revocation record"),
            "{refused}"
        );
        assert!(
            registry.table().rows().is_empty(),
            "a refused registration publishes no row"
        );

        // A fresh mint that no record holds still registers.
        let web = registry
            .register_client_box(client_spec("web"))
            .expect("an id no record holds registers");
        assert_ne!(web.box_id(), id);

        // A complete line that does not parse can be a revocation, so the
        // check fails closed and names the segment that holds it.
        let segment = bep::audit::segments(&audit_dir).unwrap().remove(0);
        let mut bytes = std::fs::read(&segment).unwrap();
        bytes.extend_from_slice(b"not a record\n");
        std::fs::write(&segment, bytes).unwrap();
        let other = crate::bep_attach::mint_box_id();
        let refused = registry
            .register_client_box_as(
                client_spec("api"),
                Ipv4Addr::new(127, 0, 0, 3),
                0,
                other,
                None,
            )
            .expect_err("an unreadable audit line refuses the registration");
        assert!(
            matches!(&refused, AllocationError::AuditUnread { id: refused_id, why, .. }
                if *refused_id == other && why.contains(&segment.display().to_string())),
            "got {refused:?}"
        );
        assert!(
            refused.to_string().contains("--quarantine-unreadable"),
            "the refusal names the way out: {refused}"
        );

        // The id the record holds is still refused: the record still reads.
        assert_eq!(
            registry
                .register_client_box_as(client_spec("db"), Ipv4Addr::new(127, 0, 0, 4), 0, id, None)
                .expect_err("the record still holds the id"),
            AllocationError::CollidingBoxId { id }
        );
    }

    /// The node's reserved-range address the mirror tests open at: a host
    /// of the reserved local range that no row publishes.
    fn mirror_address() -> Ipv4Addr {
        switch::loopback::range_hosts()
            .nth(200)
            .expect("the reserved range has more than 200 hosts")
    }

    /// A registry whose node mirror binds through a [`TestMirrorBinder`],
    /// with the node's row registered, the mirror open at
    /// [`mirror_address`], and one `host_ip` box resident.
    fn mirror_registry(range_passes: bool) -> (BoxRegistry, Arc<TestMirrorBinder>) {
        let binder = Arc::new(TestMirrorBinder::default());
        let registry = BoxRegistry::new(SUBNET)
            .with_mirror_binder(Arc::clone(&binder) as Arc<dyn MirrorBinder>);
        registry.register_node_namespace(7654);
        registry
            .open_node_mirror(mirror_address())
            .expect("a reserved-range address no row holds opens the mirror");
        registry.node_mirror().set_range_probe(range_passes);
        assert!(registry.admit_host_ip_box(mirror_session(1), false));
        (registry, binder)
    }

    fn mirror_session(n: u8) -> boxes::SessionId {
        boxes::SessionId::parse_str(&format!("00000000-0000-4000-8000-0000000000{n:02}"))
            .expect("a session id")
    }

    fn listening(port: u16) -> minimald_rpc::ListenNotice {
        minimald_rpc::ListenNotice {
            port,
            state: minimald_rpc::ListenState::Listening,
        }
    }

    fn stopped(port: u16) -> minimald_rpc::ListenNotice {
        minimald_rpc::ListenNotice {
            port,
            state: minimald_rpc::ListenState::Stopped,
        }
    }

    /// A free TCP port on this host, released before return.
    fn free_port() -> u16 {
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|listener| listener.local_addr())
            .expect("a free port")
            .port()
    }

    /// NET-138: a listener of the node's own in the host-address namespace,
    /// such as the hostname proxy or the in-VM daemon's sockets, is never
    /// mirrored at the node's address. A port the mirror held before the
    /// node claimed it is undone, and no later probe pass or box
    /// publication binds it again. A host-address box's bind stands.
    #[test]
    fn node_own_listener_never_mirrored() {
        let binder = Arc::new(TestMirrorBinder::default());
        let registry = BoxRegistry::new(SUBNET)
            .with_mirror_binder(Arc::clone(&binder) as Arc<dyn MirrorBinder>);
        registry
            .open_node_mirror(mirror_address())
            .expect("a reserved-range address no row holds opens the mirror");
        registry.node_mirror().set_range_probe(true);
        assert!(registry.admit_host_ip_box(mirror_session(1), false));
        let node = mirror_address();
        let proxy = free_port();
        let web = free_port();

        // Before the node's row stands, the host does not know the proxy
        // port is the node's own, so a notice for it binds.
        assert_eq!(
            registry.mirror_notice(listening(proxy)),
            MirrorOutcome::Bound
        );
        assert_eq!(registry.mirror_notice(listening(web)), MirrorOutcome::Bound);

        // The node's row claims the port for its hostname proxy: the bind is
        // undone, and the box's bind stands.
        registry.register_node_namespace(proxy);
        assert_eq!(binder.open(), vec![(node, web)]);
        assert_eq!(registry.node_mirror().bound_ports(), vec![web]);

        // A notice for the node's own listeners binds nothing: the hostname
        // proxy and the in-VM daemon's own sockets.
        for port in [proxy, crate::net::answerer::DEFAULT_ANSWERER_PORT] {
            assert_eq!(
                registry.mirror_notice(listening(port)),
                MirrorOutcome::RefusedInfrastructure,
                "port {port} is the node's own"
            );
        }

        // A probe pass and the next box's publication bind the held ports
        // again, and never the node's own.
        registry.node_mirror().set_range_probe(true);
        assert!(registry.retire_host_ip_box(mirror_session(1), HostIpBoxEnd::Destroyed));
        assert!(binder.open().is_empty());
        assert!(registry.admit_host_ip_box(mirror_session(2), false));
        assert_eq!(binder.open(), vec![(node, web)]);
        assert!(
            binder
                .calls()
                .iter()
                .filter(|(call, _, port)| *call == "bind" && *port == proxy)
                .count()
                == 1,
            "the proxy port was bound once, before the node claimed it: {:?}",
            binder.calls()
        );
        assert!(
            !binder.calls().iter().any(|(call, _, port)| *call == "bind"
                && *port == crate::net::answerer::DEFAULT_ANSWERER_PORT),
            "the in-VM daemon's socket is never bound"
        );
    }

    /// A [`MirrorBinder`] that reads the mirror's state from inside every
    /// call. It deadlocks if the mirror calls it with its state lock held.
    #[derive(Debug, Default)]
    struct ReentrantBinder {
        registry: std::sync::OnceLock<BoxRegistry>,
        seen: Mutex<Vec<Vec<u16>>>,
    }

    impl MirrorBinder for ReentrantBinder {
        fn bind(&self, _: Ipv4Addr, _: u16) -> Result<(), MirrorBindError> {
            let registry = self.registry.get().expect("the registry is set");
            let bound = registry.node_mirror().bound_ports();
            self.seen.lock().expect("the seen lock").push(bound);
            Ok(())
        }

        fn unbind(&self, _: Ipv4Addr, _: u16) -> MirrorUnbind {
            let registry = self.registry.get().expect("the registry is set");
            let bound = registry.node_mirror().bound_ports();
            self.seen.lock().expect("the seen lock").push(bound);
            MirrorUnbind::Undone {
                connections_reset: 0,
            }
        }
    }

    /// NET-138: the mirror makes every binder call with its state lock
    /// released, so a slow switch stalls no reader of the mirror.
    #[test]
    fn mirror_calls_the_binder_without_its_state_lock() {
        let binder = Arc::new(ReentrantBinder::default());
        let registry = BoxRegistry::new(SUBNET)
            .with_mirror_binder(Arc::clone(&binder) as Arc<dyn MirrorBinder>);
        binder
            .registry
            .set(registry.clone())
            .expect("the registry is set once");
        registry.register_node_namespace(7654);
        registry
            .open_node_mirror(mirror_address())
            .expect("the mirror opens");
        registry.node_mirror().set_range_probe(true);
        assert!(registry.admit_host_ip_box(mirror_session(1), false));
        assert_eq!(
            registry.mirror_notice(listening(18_080)),
            MirrorOutcome::Bound
        );
        assert!(registry.retire_host_ip_box(mirror_session(1), HostIpBoxEnd::Destroyed));
        assert!(registry.node_mirror().bound_ports().is_empty());
        assert_eq!(
            *binder.seen.lock().expect("the seen lock"),
            vec![Vec::<u16>::new(), Vec::<u16>::new()],
            "the bind ran before it was recorded, and the unbind after it was forgotten"
        );
    }

    /// NET-138: the node's mirror opens only at a reserved-range address
    /// that no box row publishes at: never `127.0.0.1`, never the wildcard.
    #[test]
    fn mirror_opens_only_at_the_nodes_reserved_range_address() {
        let registry = BoxRegistry::new(SUBNET);
        assert_eq!(
            registry.open_node_mirror(Ipv4Addr::LOCALHOST),
            Err(MirrorAddressRefused::OutsideReservedRange(
                Ipv4Addr::LOCALHOST
            ))
        );
        assert_eq!(
            registry.open_node_mirror(Ipv4Addr::UNSPECIFIED),
            Err(MirrorAddressRefused::OutsideReservedRange(
                Ipv4Addr::UNSPECIFIED
            ))
        );
        // The range's `.1` is the answerer's, never the node's.
        let answerer = switch::loopback::range_hosts()
            .next()
            .expect("the reserved range's first host");
        assert_eq!(
            registry.open_node_mirror(answerer),
            Err(MirrorAddressRefused::OutsideReservedRange(answerer))
        );
        let row_address = switch::loopback::range_hosts()
            .nth(3)
            .expect("a reserved-range host");
        registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            row_address,
        ));
        assert_eq!(
            registry.open_node_mirror(row_address),
            Err(MirrorAddressRefused::HeldByAnotherNamespace(row_address))
        );
        assert_eq!(registry.node_mirror().address(), None);
        assert_eq!(registry.open_node_mirror(mirror_address()), Ok(()));
        assert_eq!(registry.node_mirror().address(), Some(mirror_address()));
    }

    /// NET-138: the node's mirror makes no bind until the whole-range probe
    /// passes. A notice before that holds the port, the pass binds it, and
    /// a failed probe undoes the bind until the next pass.
    #[test]
    fn mirror_binds_nothing_before_the_range_probe_passes() {
        let (registry, binder) = mirror_registry(false);
        let node = mirror_address();
        let port = free_port();
        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Waiting
        );
        assert!(binder.calls().is_empty(), "no bind before the probe passes");

        registry.node_mirror().set_range_probe(true);
        assert_eq!(
            binder.open(),
            vec![(node, port)],
            "the pass binds the held port"
        );

        registry.node_mirror().set_range_probe(false);
        assert!(binder.open().is_empty(), "a failed probe undoes the bind");
        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Waiting
        );
        assert!(binder.open().is_empty());

        registry.node_mirror().set_range_probe(true);
        assert_eq!(binder.open(), vec![(node, port)]);

        // A mirror with no address open binds nothing either, whatever the
        // probe says.
        let unopened = Arc::new(TestMirrorBinder::default());
        let registry = BoxRegistry::new(SUBNET)
            .with_mirror_binder(Arc::clone(&unopened) as Arc<dyn MirrorBinder>);
        registry.node_mirror().set_range_probe(true);
        assert!(registry.admit_host_ip_box(mirror_session(1), false));
        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Waiting
        );
        assert!(unopened.calls().is_empty());
    }

    /// NET-138: a host port already held at the node's address is a
    /// collision. The mirror records it for the surfaces that list it, and
    /// never tries another port or another address.
    #[test]
    fn mirror_reports_an_occupied_host_port_and_never_remaps() {
        let (registry, binder) = mirror_registry(true);
        let node = mirror_address();
        // The test binder's listeners stand on `127.0.0.1`, so the holder
        // does too ([`TestMirrorBinder`]).
        let holder =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a holder on the host");
        let port = holder.local_addr().expect("the holder's address").port();

        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Collided
        );
        assert_eq!(
            binder.calls(),
            vec![("bind", node, port)],
            "one bind, at the noticed port and the node's address only"
        );
        assert!(binder.open().is_empty());
        assert_eq!(registry.node_mirror().collisions(), vec![port]);
        assert!(registry.node_mirror().bound_ports().is_empty());
        // The refused notice holds nothing: a probe pass binds nothing at
        // the port, and the guest sends the notice again.
        registry.node_mirror().set_range_probe(false);
        registry.node_mirror().set_range_probe(true);
        assert_eq!(
            binder.calls().len(),
            1,
            "a refused notice is not bound later"
        );

        // Once the holder is gone, the next notice binds the same port.
        drop(holder);
        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Bound
        );
        assert_eq!(binder.open(), vec![(node, port)]);
        assert!(registry.node_mirror().collisions().is_empty());

        // A bind a probe pass makes for a held port and that collides
        // stays held, and the next verdict retries it at the same port.
        let (registry, binder) = mirror_registry(false);
        let holder =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a holder on the host");
        let port = holder.local_addr().expect("the holder's address").port();
        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Waiting
        );
        registry.node_mirror().set_range_probe(true);
        assert_eq!(registry.node_mirror().collisions(), vec![port]);
        assert!(binder.open().is_empty());
        drop(holder);
        registry.node_mirror().set_range_probe(true);
        assert_eq!(binder.open(), vec![(node, port)]);
        assert!(
            binder
                .calls()
                .iter()
                .all(|(_, at, held)| *at == node && *held == port),
            "the retry binds the same port at the same address"
        );
    }

    /// A [`TestMirrorBinder`] whose host refuses the first `refusals`
    /// undos, as a switch that answers an error does.
    #[derive(Debug, Default)]
    struct RefusingBinder {
        inner: TestMirrorBinder,
        refusals: AtomicU32,
    }

    impl MirrorBinder for RefusingBinder {
        fn bind(&self, address: Ipv4Addr, port: u16) -> Result<(), MirrorBindError> {
            self.inner.bind(address, port)
        }

        fn unbind(&self, address: Ipv4Addr, port: u16) -> MirrorUnbind {
            let refused = self
                .refusals
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            if refused {
                return MirrorUnbind::Refused("HTTP 500".to_string());
            }
            self.inner.unbind(address, port)
        }
    }

    /// NET-138: an undo the host refused is owed, and the mirror retries
    /// it with its next change, so the bind does not outlive its listener.
    #[test]
    fn mirror_retries_an_undo_the_host_refused() {
        let binder = Arc::new(RefusingBinder {
            refusals: AtomicU32::new(1),
            ..RefusingBinder::default()
        });
        let registry = BoxRegistry::new(SUBNET)
            .with_mirror_binder(Arc::clone(&binder) as Arc<dyn MirrorBinder>);
        registry.register_node_namespace(7654);
        registry
            .open_node_mirror(mirror_address())
            .expect("the mirror opens");
        registry.node_mirror().set_range_probe(true);
        assert!(registry.admit_host_ip_box(mirror_session(1), false));
        let port = free_port();
        assert_eq!(
            registry.mirror_notice(listening(port)),
            MirrorOutcome::Bound
        );
        assert_eq!(
            registry.mirror_notice(stopped(port)),
            MirrorOutcome::Unbound
        );
        assert_eq!(
            binder.inner.open(),
            vec![(mirror_address(), port)],
            "the refused undo leaves the bind standing"
        );
        registry.node_mirror().set_range_probe(true);
        assert!(
            binder.inner.open().is_empty(),
            "the next change retries the undo"
        );
    }

    /// NET-138: the per-node caps, at their working values. Listening
    /// notices past the rate are dropped and counted, a stop notice is
    /// never refused, and a new port past the bind cap is refused.
    #[test]
    fn mirror_caps_notices_and_binds() {
        let (registry, binder) = mirror_registry(false);
        let mirror = registry.node_mirror();
        let start = Instant::now();
        for port in 0..MIRROR_NOTICES_PER_SECOND {
            let port = 20_000 + u16::try_from(port).expect("a small count");
            assert_eq!(
                mirror.notice(listening(port), &BTreeSet::new(), start),
                MirrorOutcome::Waiting
            );
        }
        assert_eq!(
            mirror.notice(listening(30_000), &BTreeSet::new(), start),
            MirrorOutcome::Capped
        );
        assert_eq!(mirror.notices_dropped_by_rate(), 1);
        assert_eq!(
            mirror.notice(stopped(20_000), &BTreeSet::new(), start),
            MirrorOutcome::Unbound,
            "a stop notice is never refused by the rate"
        );

        let mut at = start + MIRROR_NOTICE_WINDOW;
        let mut port = 40_000;
        while mirror.notice(listening(port), &BTreeSet::new(), at) == MirrorOutcome::Waiting {
            port += 1;
            at += MIRROR_NOTICE_WINDOW;
        }
        assert_eq!(
            mirror.notice(listening(port), &BTreeSet::new(), at + MIRROR_NOTICE_WINDOW),
            MirrorOutcome::Capped,
            "a new port past the bind cap is refused"
        );
        assert_eq!(
            usize::from(port - 40_000) + MIRROR_NOTICES_PER_SECOND - 1,
            MIRRORED_BINDS_CAP
        );
        assert!(binder.calls().is_empty());
    }

    // BEP-043: the destroy of a host_ip box that declared a credentialed
    // upstream revokes the id its registration minted, as the destroy of an
    // own-address box does: a `revoke_box` line and then a `forget_box`
    // line. The id stays in the id set, so no later mint takes it.
    #[test]
    fn retiring_a_host_ip_grant_box_revokes_its_minted_id() {
        let registry = BoxRegistry::new(SUBNET);
        let id = registry
            .register_host_ip_box_as("agent", [0x5a; 16])
            .expect("no record holds the id");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let server = stub_control(&path, &["{\"ok\":true}\n", "{\"ok\":true}\n"]);
        let wired = registry.clone().with_proxy_control(Some(path));
        let session = boxes::SessionId::from_bytes(id);
        assert!(wired.admit_host_ip_box(session, true));

        assert!(wired.retire_host_ip_box(session, HostIpBoxEnd::Destroyed));
        let hex = "5a".repeat(16);
        assert_eq!(
            server.join().unwrap(),
            [
                serde_json::json!({"op": "revoke_box", "box_id": hex}),
                serde_json::json!({"op": "forget_box", "box_id": hex}),
            ]
        );
        assert!(
            wired.holds_host_ip_id(id),
            "the revoked id stays in the id set"
        );
        assert_eq!(wired.host_ip_id_for("agent"), None);
    }

    // BEP-043: a stop is not a destroy. A restart brings the stopped box
    // back under the same id, so the retire of a stopped grant box sends
    // the proxy nothing and its id stays in the id set. The destroy that
    // follows the stop finds no rules, and still revokes the id.
    #[test]
    fn retiring_a_stopped_host_ip_grant_box_sends_no_revocation() {
        let registry = BoxRegistry::new(SUBNET);
        let id = registry
            .register_host_ip_box_as("paused", [0x4e; 16])
            .expect("no record holds the id");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let wired = registry.clone().with_proxy_control(Some(path.clone()));
        let session = boxes::SessionId::from_bytes(id);
        assert!(wired.admit_host_ip_box(session, true));

        assert!(wired.retire_host_ip_box(session, HostIpBoxEnd::Stopped));
        assert!(
            !revocation_spawned(id),
            "the stop of a grant box revokes nothing"
        );
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the stop of a grant box sends nothing to the proxy"
        );
        assert!(wired.holds_host_ip_id(id), "the stopped box keeps its id");

        drop(listener);
        std::fs::remove_file(&path).unwrap();
        let server = stub_control(&path, &["{\"ok\":true}\n", "{\"ok\":true}\n"]);
        assert!(!wired.retire_host_ip_box(session, HostIpBoxEnd::Destroyed));
        let hex = "4e".repeat(16);
        assert_eq!(
            server.join().unwrap(),
            [
                serde_json::json!({"op": "revoke_box", "box_id": hex}),
                serde_json::json!({"op": "forget_box", "box_id": hex}),
            ],
            "the destroy of the stopped box revokes its id"
        );
    }

    // BEP-043: a grant box's minted id and its credentialed lane persist
    // beside the registry file. After a VM host daemon restart the destroy
    // of the box finds no rules, and still revokes its id at the proxy.
    #[test]
    fn restarted_registry_revokes_a_destroyed_grant_box_id() {
        let dir = tempfile::tempdir().unwrap();
        let before = persisted_registry(&dir);
        let id = before
            .register_host_ip_box_as("agent", [0x6a; 16])
            .expect("no record holds the id");
        let session = boxes::SessionId::from_bytes(id);
        assert!(before.admit_host_ip_box(session, true));
        drop(before);

        let sock = dir.path().join("control.sock");
        let server = stub_control(&sock, &["{\"ok\":true}\n", "{\"ok\":true}\n"]);
        let after = BoxRegistry::new(SUBNET)
            .with_proxy_control(Some(sock))
            .persisting_to(dir.path().join(REGISTRY_FILE));
        assert!(after.holds_host_ip_id(id), "the reloaded id is held");
        assert!(
            !after.holds_host_ip_boxes(),
            "no box is resident after a restart"
        );
        assert!(
            !after.retire_host_ip_box(session, HostIpBoxEnd::Destroyed),
            "a restart holds no rules for the box"
        );
        assert!(
            revocation_spawned(id),
            "the destroy revokes the reloaded id"
        );
        let hex = "6a".repeat(16);
        assert_eq!(
            server.join().unwrap(),
            [
                serde_json::json!({"op": "revoke_box", "box_id": hex}),
                serde_json::json!({"op": "forget_box", "box_id": hex}),
            ]
        );
        let file: HostIpIdsFile = serde_json_lenient::from_slice(
            &std::fs::read(dir.path().join(HOST_IP_IDS_FILE)).expect("the id file reads"),
        )
        .expect("the id file parses");
        assert_eq!(file.ids, vec![boxes::BoxId::from_bytes(id)]);
        assert!(
            file.credentialed.is_empty(),
            "the destroyed box's id leaves the credentialed set"
        );
    }

    // BEP-082: the ids a registry minted persist, so the registry of the
    // next VM host daemon run refuses a mint that takes one of them. An
    // unusable id file is set aside and reloads no id.
    #[test]
    fn restarted_registry_never_mints_an_id_it_minted_before() {
        let dir = tempfile::tempdir().unwrap();
        let before = persisted_registry(&dir);
        let id = before
            .register_host_ip_box_as("first", [0x6b; 16])
            .expect("no record holds the id");
        drop(before);

        let after = persisted_registry(&dir);
        assert!(after.holds_host_ip_id(id), "the reloaded id is held");
        assert!(
            matches!(
                after.register_host_ip_box_as("second", id),
                Err(AllocationError::CollidingBoxId { id: refused }) if refused == id
            ),
            "a mint of an id minted before the restart is refused"
        );

        let path = dir.path().join(HOST_IP_IDS_FILE);
        std::fs::write(&path, b"not json").unwrap();
        let unusable = persisted_registry(&dir);
        assert!(
            !unusable.holds_host_ip_id(id),
            "an unusable file reloads no id"
        );
        assert!(!path.exists(), "the unusable file is moved");
        let aside = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{HOST_IP_IDS_FILE}.unusable-"))
            });
        assert!(aside, "the unusable file is set aside");
    }

    // BEP-043: a host_ip box with no credentialed upstream holds no grant,
    // so its end sends the proxy nothing. Neither does the end of a
    // credentialed box under an id this registry did not mint.
    #[test]
    fn retiring_a_host_ip_box_with_no_grant_sends_no_revocation() {
        let registry = BoxRegistry::new(SUBNET);
        let id = registry
            .register_host_ip_box_as("plain", [0x6b; 16])
            .expect("no record holds the id");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let wired = registry.clone().with_proxy_control(Some(path));

        let plain = boxes::SessionId::from_bytes(id);
        assert!(wired.admit_host_ip_box(plain, false));
        assert!(wired.retire_host_ip_box(plain, HostIpBoxEnd::Destroyed));
        let unminted = boxes::SessionId::from_bytes([0x7c; 16]);
        assert!(wired.admit_host_ip_box(unminted, true));
        assert!(wired.retire_host_ip_box(unminted, HostIpBoxEnd::Destroyed));

        // The retire decides to revoke before it returns, so the record of
        // spawned revocations answers with no wait.
        assert!(!revocation_spawned(id));
        assert!(!revocation_spawned([0x7c; 16]));
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the end of a box with no grant sends nothing to the proxy"
        );
        assert!(wired.holds_host_ip_id(id));
    }

    // BEP-082: a rename withdraws the old registration name by the box's
    // id. The box stays admitted under its id, and a new grant box under
    // the old name takes a fresh id. The first id stays in the minted set,
    // so no later mint takes it.
    #[test]
    fn a_renamed_host_ip_grant_box_frees_its_old_name_for_a_fresh_id() {
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_host_ip_box_as("web", [0x2f; 16])
            .expect("no record holds the id");
        let session = boxes::SessionId::from_bytes(first);
        assert!(registry.admit_host_ip_box(session, true));
        assert!(
            matches!(
                registry.register_host_ip_box_as("web", [0x30; 16]),
                Err(AllocationError::NameAlreadyHeld { .. })
            ),
            "an admitted box holds its registration name"
        );

        assert!(registry.withdraw_host_ip_name("web", first));
        assert!(!revocation_spawned(first), "the withdraw revokes nothing");
        assert!(!registry.host_ip_id_is_named(first));

        let fresh = registry
            .register_host_ip_box_as("web", [0x31; 16])
            .expect("the old name is free once withdrawn");
        assert_ne!(fresh, first, "a new box under the name takes a fresh id");
        assert_eq!(registry.host_ip_id_for("web"), Some(fresh));
        assert!(
            registry.holds_host_ip_id(first),
            "the renamed box's id stays in the minted set"
        );
    }

    /// The creator's resume of `row`, as the control door makes it.
    fn resume(registry: &BoxRegistry, row: &BoxRecord) -> Result<Arc<BoxRecord>, ResumeError> {
        let claim = registry.begin_registration(&row.name());
        registry.resume_client_box(
            &row.name(),
            row.switch_addr(),
            row.loopback_addr(),
            Some(row.box_id()),
            row.loopback_addr(),
            claim.generation(),
        )
    }

    #[test]
    fn a_row_ended_by_the_guest_leaves_a_creation_its_creator_resumes() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box_with_task_slots(
                ClientBoxSpec {
                    ingress_ports: vec![8080],
                    ..client_spec("web")
                },
                2,
            )
            .unwrap();
        let task_addrs = web.task_addrs().to_vec();
        assert_eq!(task_addrs.len(), 2);

        // The guest's word that the box ended withdraws the row and its
        // task rows. The creation stays, dormant.
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(registry.row_by_box_id(web.box_id()).is_none());
        let table = registry.table();
        for addr in &task_addrs {
            assert!(table.by_source(addr.octets()).is_none());
        }
        assert_eq!(registry.dormant_creation_rows().len(), 1);

        // No other box is handed the dormant box's addresses.
        let other = registry.register_client_box(client_spec("other")).unwrap();
        assert_ne!(other.switch_addr(), web.switch_addr());
        assert!(!task_addrs.contains(&other.switch_addr()));

        // The creator's resume brings the same row back, with the same id,
        // addresses, declared ports and task rows.
        let resumed = resume(&registry, &web).unwrap();
        assert_eq!(resumed.box_id(), web.box_id());
        assert_eq!(resumed.switch_addr(), web.switch_addr());
        assert_eq!(resumed.admitted_ports(), &[8080]);
        assert_eq!(resumed.task_addrs(), task_addrs.as_slice());
        assert!(registry.row_by_box_id(web.box_id()).is_some());
        assert!(registry.dormant_creation_rows().is_empty());
        // A resume of a row that stands answers the row as it stands.
        assert!(Arc::ptr_eq(&resume(&registry, &web).unwrap(), &resumed));
    }

    #[test]
    fn persisted_creations_reload_dormant_and_a_resume_restores_the_row() {
        let dir = tempfile::tempdir().unwrap();
        let (web, idle) = {
            let registry = persisted_registry(&dir);
            let web = registry.register_client_box(client_spec("web")).unwrap();
            let idle = registry.register_client_box(client_spec("idle")).unwrap();
            (web, idle)
        };
        // A start of the daemon is a boot of the VM: no box of the earlier
        // run is running, so no row is reloaded, whatever stood before.
        let reloaded = persisted_registry(&dir);
        assert!(reloaded.table().rows().is_empty());
        assert_eq!(reloaded.dormant_creation_rows().len(), 2);
        // The addresses stay reserved for the creations.
        let fresh = reloaded.register_client_box(client_spec("fresh")).unwrap();
        assert_ne!(fresh.switch_addr(), web.switch_addr());
        assert_ne!(fresh.switch_addr(), idle.switch_addr());

        let resumed = resume(&reloaded, &web).unwrap();
        assert_eq!(resumed.box_id(), web.box_id());
        assert_eq!(resumed.switch_addr(), web.switch_addr());
        assert_eq!(reloaded.dormant_creation_rows().len(), 1);
    }

    #[test]
    fn a_registry_file_of_the_previous_version_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(REGISTRY_FILE);
        std::fs::write(&path, r#"{"version":1,"boxes":[]}"#).unwrap();
        let registry = BoxRegistry::new(SUBNET).persisting_to(path.clone());
        assert!(registry.table().rows().is_empty());
        assert!(registry.dormant_creation_rows().is_empty());
    }

    #[test]
    fn row_by_box_id_finds_the_box_row_and_never_a_task_row() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 1)
            .unwrap();
        let found = registry.row_by_box_id(web.box_id()).unwrap();
        assert!(Arc::ptr_eq(&found, &web));
        assert!(!found.is_task_row());
        assert!(registry.row_stands(&web));
        assert!(registry.row_by_box_id([7u8; 16]).is_none());

        registry.withdraw(web.switch_addr());
        assert!(!registry.row_stands(&web));
        assert!(registry.row_by_box_id(web.box_id()).is_none());
    }

    #[test]
    fn a_withdrawal_tells_its_subscribers_which_box_ended() {
        let registry = BoxRegistry::new(SUBNET);
        let withdrawn = registry.table().subscribe_row_withdrawals();
        let web = registry.register_client_box(client_spec("web")).unwrap();
        registry.withdraw(web.switch_addr());
        let withdrawal = withdrawn
            .recv_timeout(Duration::from_secs(5))
            .expect("the withdrawal reaches the subscriber");
        assert_eq!(withdrawal.box_id(), web.box_id());
        assert_eq!(withdrawal.switch_addr(), web.switch_addr());
        // The addresses stay held until the subscriber is done with them.
        assert!(
            registry
                .table()
                .revocation_pending(web.switch_addr().octets())
        );
        drop(withdrawal);
        assert!(
            !registry
                .table()
                .revocation_pending(web.switch_addr().octets())
        );
    }

    #[test]
    fn a_host_ip_box_is_resident_from_its_admit_until_its_end() {
        let registry = BoxRegistry::new(SUBNET);
        let plain = registry.register_host_ip_box("plain").unwrap();
        let grant = registry.register_host_ip_box("grant").unwrap();
        // A registered id is not resident until a host client admits it.
        assert_eq!(registry.resident_host_ip_box(plain), None);
        assert!(!registry.holds_host_ip_boxes());

        assert!(registry.admit_host_ip_box(boxes::SessionId::from_bytes(plain), false));
        assert!(registry.admit_host_ip_box(boxes::SessionId::from_bytes(grant), true));
        assert_eq!(registry.resident_host_ip_box(plain), Some(false));
        assert_eq!(registry.resident_host_ip_box(grant), Some(true));
        assert_eq!(registry.resident_host_ip_boxes().len(), 2);

        // The guest's word ends one. A second end finds nothing.
        assert!(registry.end_host_ip_box(grant));
        assert!(!registry.end_host_ip_box(grant));
        assert_eq!(registry.resident_host_ip_box(grant), None);
        assert!(registry.holds_host_ip_boxes());
        // A host client retires the other.
        assert!(registry.retire_host_ip_box(
            boxes::SessionId::from_bytes(plain),
            minimald_rpc::HostIpBoxEnd::Destroyed
        ));
        assert!(!registry.holds_host_ip_boxes());
    }

    /// Boxes come and go for as long as the daemon lives, and neither the
    /// addresses nor the ids run out. A box the guest never started returns
    /// its address at once. A started box's address comes back after the
    /// quarantine.
    #[test]
    fn create_and_destroy_cycles_never_run_out_of_addresses_or_ids() {
        let registry = BoxRegistry::new(carved());
        let mut ids = std::collections::HashSet::new();
        // Never started: three times the run's addresses, with no time
        // passing.
        for cycle in 0..CARVED_RUN * 3 {
            let row = register_carved(&registry, &format!("idle{cycle}"))
                .unwrap_or_else(|error| panic!("cycle {cycle}: {error}"));
            assert!(!row.was_used());
            assert!(ids.insert(row.box_id()), "cycle {cycle} repeats an id");
            destroy(&registry, &row);
        }
        assert_eq!(registry.live_switch_addrs(), 0);
        // Started: the whole run at once, four times over.
        for round in 0..4 {
            let rows = fill_carved_run(&registry);
            for row in &rows {
                assert!(ids.insert(row.box_id()), "round {round} repeats an id");
            }
            assert!(matches!(
                register_carved(&registry, "one-more"),
                Err(AllocationError::SwitchExhausted(_))
            ));
            for row in &rows {
                destroy(&registry, row);
            }
            assert_eq!(registry.live_switch_addrs(), 0);
            assert!(
                matches!(
                    register_carved(&registry, "too-early"),
                    Err(AllocationError::SwitchExhausted(_))
                ),
                "round {round}: a started box's address waits out the quarantine"
            );
            registry.advance_clock(SWITCH_REUSE_QUARANTINE);
        }
    }

    #[test]
    fn concurrent_registrations_get_distinct_ids_and_addresses() {
        let registry = BoxRegistry::new(SUBNET);
        let (first, last) = box_loopback_run(registry.loopback_slice.unwrap());
        let (rows, host_ip_ids) = std::thread::scope(|scope| {
            let rows: Vec<_> = (first..=last)
                .take(24)
                .map(|loopback| {
                    let registry = registry.clone();
                    scope.spawn(move || {
                        registry
                            .register_client_box_at_with_task_slots(
                                client_spec(&format!("box{loopback}")),
                                Ipv4Addr::from(loopback),
                                2,
                            )
                            .expect("the plan holds every box")
                    })
                })
                .collect();
            let host_ip: Vec<_> = (0..16)
                .map(|n| {
                    let registry = registry.clone();
                    scope.spawn(move || {
                        registry
                            .register_host_ip_box(&format!("hostip{n}"))
                            .unwrap()
                    })
                })
                .collect();
            (
                rows.into_iter()
                    .map(|row| row.join().unwrap())
                    .collect::<Vec<_>>(),
                host_ip
                    .into_iter()
                    .map(|id| id.join().unwrap())
                    .collect::<Vec<_>>(),
            )
        });
        let mut ids = std::collections::HashSet::new();
        let mut switch = std::collections::HashSet::new();
        let mut loopback = std::collections::HashSet::new();
        assert!(
            rows.len() >= 8,
            "the loopback run holds {} boxes",
            rows.len()
        );
        for row in &rows {
            assert!(ids.insert(row.box_id()));
            assert!(switch.insert(row.switch_addr()));
            assert!(loopback.insert(row.loopback_addr()));
            assert_eq!(row.task_addrs().len(), 2);
            for task in row.task_addrs() {
                assert!(switch.insert(*task), "a task address is handed twice");
            }
        }
        for id in host_ip_ids {
            assert!(ids.insert(id), "a host_ip box shares an id");
        }
    }

    #[test]
    fn task_rows_follow_their_box_through_withdraw_resume_and_destroy() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry
            .register_client_box_with_task_slots(client_spec("web"), 2)
            .unwrap();
        let tasks = task_rows_of(&registry, &web);
        assert_eq!(tasks.len(), 2);
        for task in &tasks {
            assert_eq!(task.task_row_of(), Some(web.switch_addr()));
        }

        // The guest reports the box ended: the task rows go with its row.
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert!(task_rows_of(&registry, &web).is_empty());

        // The creator resumes it: the task rows are back at their addresses.
        let resumed = resume(&registry, &web).unwrap();
        let again = task_rows_of(&registry, &resumed);
        assert_eq!(again.len(), 2);
        for task in &again {
            assert_eq!(task.task_row_of(), Some(web.switch_addr()));
        }

        // The creator destroys it: the rows and all three addresses go.
        destroy(&registry, &resumed);
        assert!(task_rows_of(&registry, &web).is_empty());
        assert_eq!(registry.live_switch_addrs(), 0);
    }

    #[test]
    fn a_refused_registration_keeps_no_address() {
        let registry = BoxRegistry::new(carved());
        register_carved(&registry, "web").unwrap();
        for _ in 0..CARVED_RUN {
            assert!(
                register_carved(&registry, "web").is_err(),
                "the name is a live box's"
            );
        }
        assert_eq!(registry.live_switch_addrs(), 1);
        // Every other address of the run is still there to hand.
        for n in 1..CARVED_RUN {
            register_carved(&registry, &format!("box{n}")).unwrap();
        }
    }

    /// A box with a credentialed upstream whose row the guest ended is not
    /// revoked: its creator may resume it. The creator's destroy of the
    /// dormant box revokes its id at the credential proxy.
    #[test]
    fn a_dormant_credentialed_box_is_revoked_at_its_destroy_and_not_before() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let server = stub_control(
            &path,
            &[
                "{\"ok\":true,\"box_ids\":[]}\n",
                "{\"ok\":true}\n",
                "{\"ok\":true}\n",
            ],
        );
        let registry = BoxRegistry::new(SUBNET).with_proxy_control(Some(path));
        let agent = registry
            .register_client_box(ClientBoxSpec {
                credentialed_upstream: Some(boxes::CredentialedUpstream::default()),
                ..client_spec("agent")
            })
            .unwrap();

        // The guest reports the box ended. Nothing is sent for that: the
        // lines below are all the proxy hears.
        assert!(registry.withdraw(agent.switch_addr()).is_some());
        assert_eq!(registry.dormant_creation_rows().len(), 1);

        registry
            .withdraw_client_box(
                &agent.name(),
                agent.switch_addr(),
                agent.loopback_addr(),
                Some(agent.box_id()),
            )
            .expect("the creator's own box");
        let hex = super::box_id_hex(agent.box_id());
        assert_eq!(
            server.join().unwrap(),
            [
                // The registration asked which ids the proxy holds revoked.
                serde_json::json!({"op": "revoked_box_ids"}),
                serde_json::json!({"op": "revoke_box", "box_id": hex}),
                serde_json::json!({"op": "forget_box", "box_id": hex}),
            ]
        );
        assert!(registry.dormant_creation_rows().is_empty());
    }
}
