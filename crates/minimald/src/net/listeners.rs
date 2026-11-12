//! Listen-published ingress (NET-016, NET-017): the ports a box publishes
//! because its processes listen on them.
//!
//! A declaration's forwards are static — bound at publish, held until the
//! box stops (NET-121) — but a port a permit range names has no forward to
//! hold: it exists to the processes inside the box alone, so the story's
//! shape is the kernel's socket table's. This module reads the box's
//! listening sockets from the engine's record ([`super::listens`]), diffs
//! them, and:
//!
//! * **publishes** each new listening port the shared verdict permits
//!   ([`IngressGate::listen_verdict`]): a forward bound at
//!   the box's own address, at the port the process listens on — no
//!   translation, the same number on both sides, exactly as a declaration's
//!   mapping publishes its external port (NET-010) — and the port admitted
//!   at the box's ingress gate for as long as the listener holds it;
//! * **leaves unpublished** every listening port the rules do not permit,
//!   so a connection to it is refused at the box's address (NET-014) and
//!   never forwarded by a listener nobody declared;
//! * **withdraws** each published port whose listener closed: the gate
//!   refuses it first, and the forward comes down after (NET-017).
//!
//! The watcher owns only the runtime-published set. A declared port is
//! never its to publish — its forward was bound before the box's name was
//! even registered — and never its to withdraw: a withdrawal applies only to
//! the runtime-published set (NET-081's sub-requirement), which is why the
//! two halves are tracked apart all the way down to the gate.
//!
//! But the runtime-published set has two publishers. The runtime
//! `min net expose` (NET-044) publishes a port on the user's own request,
//! and the watcher publishes one because the box's process listens on it —
//! and both bind at the box's published address, on whatever port they were
//! each asked for, so a port both surfaces reached unguarded would be asked
//! of the switch twice. The guard is the set itself
//! ([`BoxPublications`]): a surface *reserves* the port there — a pending
//! entry carrying its owner and the reservation's own token — before it
//! asks the switch to bind, and the reservation is an RAII guard
//! ([`Reservation`]) whose `record` commits it as the publication and whose
//! every other end, error or cancellation, gives the port back. So the
//! surface that loses to an entry, pending or published, is answered — by
//! the expose path with the typed already-published refusal naming the
//! owner that holds the port, by the watcher with a settled skip that never
//! retries, because a publication that stands is not a failure — and it
//! never asks the switch at all: the port is bound once, by the surface
//! whose reservation won, whichever that is. A bind that fails releases
//! the reservation it held, keyed by its own token, so the other surface's
//! next observation publishes the port normally. Withdrawal belongs to
//! whoever published: the watcher never withdraws a port the expose path
//! holds, and the expose path never asks down a port the watcher published
//! — and revocation overrides both, because an ingress revocation unbinds
//! and clears a port whoever owns it. A pending entry is not a mapping: it
//! lists nowhere — `min session policy` and the publication lines name a
//! port only once its reservation is recorded.
//!
//! In a VM the VM host holds the forward. The publish asks it through the
//! guest door ([`ControlChannel::VmHost`]), and one it refuses publishes
//! nothing: the reservation releases, and the port is owed again on the
//! backoff a refused publish earns.
//!
//! The plan a launch gathers rides [`crate::box_runtime::Launched`] to the
//! host that runs its box — no process-global table between them — so a
//! plan is the launch's own from the moment it is built, and a launch that
//! built none starts no watcher at all.
//!
//! Two properties the story's shape rides on, beside the diff itself. The
//! table is read as the forward reads the box: a listener counts only when
//! its bind can answer the dial a publication makes — to the box's lease —
//! so a process bound to the box's loopback alone is not published at all
//! ([`super::listens::reachable_ports`]); and nothing here is one-shot — a
//! publication whose bind failed is retried on a per-port backoff that
//! doubles off the poll interval, a withdrawal whose unexpose failed is
//! retried on every poll the box still runs and through the stop's passes,
//! so a transient
//! refusal on the control channel never settles into a port that stays
//! missing or a forward that stays bound. Neither half says its failure
//! more than once while it keeps failing: the first refusal of a streak
//! is the line, and the line that ends a streak is the publication's or
//! the withdrawal's own — so a forwarder that is down for as long as the
//! box lives is waited for, not written over and over.
//!
//! One info line per publication and per withdrawal — each naming the port,
//! the box, and whether the rules permitted it — so the diagnostics
//! bundle's daemon log tail reads the whole surface (the observability
//! contract of the story this module implements).
//!
//! A listen the watcher publishes is a dynamic ingress request the box's
//! `allow` stance decided: every `Publish` verdict is an in-range port under
//! `allow`, because a port the declaration names is `Declared` and never the
//! watcher's. So the publication owes what NET-044 and NET-046 owe every
//! allowed request: its row in `min session policy` — the committed entry
//! carries the mapping it lists as ([`BoxPublications::listen_rows`]), and
//! the row goes with the entry when the listener closes — and its decision
//! record in the local audit log ([`crate::audit`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
#[cfg(test)]
use std::io;
use std::net::Ipv4Addr;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::sync::watch;

use boxes::IpProto;
use boxes::core::ingress::ListenVerdict;

use super::ingress_gate::IngressGate;
use super::listens::Listeners;
use super::policy::{
    ControlChannel, ExposedMapping, expose_mapping, log_withdrawal, unexpose_mapping,
};

/// The watcher's short wait: before the first retry of a publish that
/// failed, between the passes of a stop's withdrawal, and between two reads
/// of a guest node's socket table.
const LISTEN_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long the watcher of a box goes without reading the box's listening
/// sockets when the engine reports no change. A report that was lost costs
/// this much delay and no port.
const LISTEN_REREAD: Duration = Duration::from_secs(5);

/// How many passes the stop's withdrawal ([`WatchState::withdraw_all`])
/// makes at the forwards still standing: the first, then a bounded number
/// of retries for those a pass could not bring down — enough that a
/// transient refusal does not leave a forward bound past its box, holding
/// the box's published address:port against a future session there, never
/// enough that a control channel that is down outright hangs the stop.
const WITHDRAW_PASSES: usize = 3;

/// The longest a permitted port's publish waits between attempts: the
/// backoff doubles off the poll interval once per refusal in the streak, so
/// the first refusal costs exactly the one poll the one-shot retry paid and
/// a refusal that persists is *waited for* — one attempt every half minute,
/// never one per poll — while never being given up on.
const PUBLISH_RETRY_CAP: Duration = Duration::from_secs(30);

/// Everything a box's listener watcher needs, gathered by the launch that
/// attached the box: its name (each publication's line names the box), its
/// switch lease (the address a publication's forward delivers to), the
/// published address the forward binds — the box's own address (NET-010),
/// wherever it was granted, read back the same way the attach path reads
/// it — the gvproxy control channel the forwarder verbs ride, the box's
/// ingress gate, which holds the shared permit decision
/// ([`IngressGate::listen_verdict`]) and the admission a published port is
/// given through, the box's publication set, shared with the runtime
/// expose surface so neither binds a port the other already holds, and the
/// daemon's state directory, under which each publication's decision record
/// is appended (NET-046).
pub struct ListenPlan {
    /// The box's name, as the daemon's own session lines name it.
    box_name: String,
    /// The box's address on the switch — where a publication's forward
    /// delivers.
    lease: Ipv4Addr,
    /// The box's published address (NET-010) — where a publication binds.
    published: Ipv4Addr,
    /// The gvproxy control channel: `expose` to publish, `unexpose` to
    /// withdraw.
    control: ControlChannel,
    /// The box's ingress gate: the permit decision and the admission.
    gate: Arc<IngressGate>,
    /// The box's publications, shared with the runtime expose surface
    /// ([`crate::box_actor::Session`]): the one set both read before they
    /// bind, and the one place a publication's owner is written down.
    publications: BoxPublications,
    /// The daemon's state directory: the audit log the publication's
    /// decision record is appended to lives under it ([`crate::audit`]).
    state_dir: PathBuf,
    /// The hostname registry (NET-129), where each published port is
    /// recorded as held by this box's stable session id — so a declared
    /// publish of the same port elsewhere sees the holder and yields,
    /// and the close hands the port over. `None` when the launch carried
    /// no reporter: a box with no registry behind it records nothing.
    hostnames: Option<Arc<RwLock<crate::net::dns::HostnameRegistry>>>,
    /// The stable id the holds are recorded under (NET-129): the box's
    /// own id, keying the registry's holder table exactly as its declared
    /// publish does.
    session_id: boxes::SessionId,
}

impl ListenPlan {
    /// The box's listening sockets, where the engine records them.
    pub(crate) fn listeners(&self) -> Option<Arc<dyn Listeners>> {
        self.gate.listeners()
    }

    /// Assembles the plan from the facts its launch holds. The gate must be
    /// the one the box's attach registered, which admits the connections a
    /// publication forwards, and the publication set must be the one the
    /// session's runtime expose surface reads, so the two surfaces never
    /// bind the same port. `state_dir` is the daemon's state directory, the one the
    /// runtime expose path audits its decisions under, so both surfaces'
    /// records land in the one log.
    #[expect(
        clippy::too_many_arguments,
        reason = "the plan is built once per launch from facts only the launch holds; \
                  a builder would add a type for one call site"
    )]
    #[must_use]
    pub fn new(
        box_name: String,
        lease: Ipv4Addr,
        published: Ipv4Addr,
        control: ControlChannel,
        gate: Arc<IngressGate>,
        publications: BoxPublications,
        state_dir: PathBuf,
        hostnames: Option<Arc<RwLock<crate::net::dns::HostnameRegistry>>>,
        session_id: boxes::SessionId,
    ) -> Self {
        Self {
            box_name,
            lease,
            published,
            control,
            gate,
            publications,
            state_dir,
            hostnames,
            session_id,
        }
    }

    /// Records `port` as held by this box at `address`, where its forward
    /// is bound (NET-129): the dynamic port's one holder of record, read by
    /// every declared publish of the port — so another box's declaration
    /// collides with the box that is serving and yields its forward, instead
    /// of failing on a bind the forwarder refuses. A port another box already
    /// holds is left alone: the record never displaces a holder.
    fn record_dynamic_hold(&self, address: Ipv4Addr, port: u16) {
        let Some(registry) = self.hostnames.as_ref() else {
            return;
        };
        registry
            .write()
            .expect("hostname registry lock poisoned")
            .record_dynamic_hold(self.session_id, address, port);
    }

    /// Releases the hold [`Self::record_dynamic_hold`] recorded — the
    /// listener closed or the box stopped — returning the hand-overs the
    /// release elected, so the close's own line can say them beside the
    /// registry's. A port the box still declares keeps its record: the
    /// declaration is the claim now. `address` is where the forward was
    /// bound, which is where the hold was recorded.
    fn release_dynamic_hold(
        &self,
        address: Ipv4Addr,
        port: u16,
    ) -> Vec<crate::net::dns::PortHandOver> {
        let Some(registry) = self.hostnames.as_ref() else {
            return Vec::new();
        };
        registry
            .write()
            .expect("hostname registry lock poisoned")
            .release_dynamic_hold(self.session_id, address, port)
    }
}

/// Which of the box's two runtime ingress surfaces owns a publication: the
/// runtime `min net expose` (NET-044), or the listen watcher this module
/// runs (NET-016). Ownership decides who may withdraw — a publication comes
/// down with whoever published it, never with the other surface that
/// declined to bind it — and it is the field the publication and refusal
/// lines carry, so a daemon log's tail reads whose publication every port
/// is from either surface's lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOwner {
    /// The runtime expose path: a publication the user asked for with
    /// `min net expose`.
    Expose,
    /// The listen watcher: a publication the box's own listening process
    /// earned.
    Listen,
}

impl PublicationOwner {
    /// How the owner is named on the lines its publications and their
    /// refusals carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Expose => "expose",
            Self::Listen => "listen",
        }
    }
}

/// Why a reservation was refused: the port is held, by which surface, and
/// whether the holder's publication stands yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Held {
    /// The surface holding the port — the owner the loser's answer names,
    /// the one whose bind is in flight when `published` is `false`.
    pub owner: PublicationOwner,
    /// Whether the holder's publication stands. `false` while its bind is
    /// still in flight: the port is held against this caller all the same,
    /// and the holder may still lose it to a bind that fails.
    pub published: bool,
}

/// One entry in the box's publication set: which surface holds the port,
/// keyed by the reservation that wrote it, and whether that reservation's
/// bind has been committed as a publication yet.
#[derive(Debug)]
struct PublicationEntry {
    /// The surface that holds the port.
    owner: PublicationOwner,
    /// The reservation that wrote this entry — the key every rollback of
    /// it is checked against, so a release can only ever take down the
    /// reservation that made it, never whatever holds the port since.
    token: u64,
    /// Whether the entry is a publication. `false` while the holder's bind
    /// is in flight: the port is held against the other surface, but no
    /// mapping stands and none is listed anywhere.
    published: bool,
    /// The row the publication is listed as in `min session policy`, when
    /// its owner lists it from this set: the listen watcher's publications
    /// (NET-044), committed with [`Reservation::record_listed`]. `None` for
    /// a pending entry, and for the expose path's publications, whose rows
    /// the session's runtime-ingress table holds beside their forwarders.
    listed: Option<minimald_rpc::LiveMapping>,
}

/// The box's runtime publications, one entry per port one of its surfaces
/// holds — reserved before any bind, committed by the reservation that
/// bound it. Both surfaces that publish at runtime — the expose path and
/// the listen watcher — reserve in this one set before they ask the switch
/// for anything, so a port the other surface holds, pending or published,
/// is never asked of the switch twice, and the set is the one place the
/// answer to "who owns this publication" lives, so withdrawal can be
/// refused everywhere it does not belong.
///
/// The set belongs to one *launch*, not to the session for good: the
/// session's launcher ([`crate::box_actor::Session::session_launcher`])
/// builds a fresh one for the spawn it is about to run, hands it to the
/// launcher beside the plan, and the session actor reads the same one — so
/// a respawn starts with an empty set by construction, never with the
/// entries of a spawn whose box has gone, and the set is bounded by the
/// ports one box has published, never grown over the daemon's life.
#[derive(Debug, Default, Clone)]
pub struct BoxPublications {
    /// The ports this box's two surfaces hold, each with its owner and the
    /// reservation that wrote it. The lock is a plain mutex held for map
    /// reads and writes only, never across a switch round trip — it is the
    /// atomic half of every check-then-bind, not a hold on the bind.
    set: Arc<Mutex<PublicationSet>>,
}

/// The mutable half of a [`BoxPublications`]: the entries and the counter
/// that mints reservation tokens under the one lock, so a token is never
/// reused for two reservations of one set.
#[derive(Debug, Default)]
struct PublicationSet {
    /// Ordered by port, so the rows [`BoxPublications::listen_rows`] lists
    /// read the same way on every call.
    ports: BTreeMap<u16, PublicationEntry>,
    next_token: u64,
    /// The permitted listening ports the watcher could not publish because
    /// their allow's `Published` record could not be written (NET-046):
    /// the box listens, the rules permit, and nothing is published until
    /// the audit log takes the record. Kept here, beside the rows, so
    /// `min session policy` reads the failure from the same set it reads
    /// the publications from, and never hears a silent drop.
    audit_refused: BTreeSet<u16>,
}

impl BoxPublications {
    /// Reserves `port` for `owner` before any bind: the check and the hold
    /// are one step under the set's lock, so two surfaces that reach the
    /// same port together cannot both pass the check and both ask the
    /// switch to bind — the second is refused here, naming the holder,
    /// before it holds anything of the switch's. The entry is *pending* —
    /// the port is held against the other surface, but no publication
    /// stands until the guard's [`Reservation::record`] commits the bind —
    /// and it stays the reserving call's alone: dropped without record, on
    /// any error path or any cancellation, the guard releases it by its
    /// own token.
    pub fn reserve(&self, port: u16, owner: PublicationOwner) -> Result<Reservation, Held> {
        let mut set = self.set.lock().expect("box publications lock poisoned");
        match set.ports.get(&port) {
            Some(held) => Err(Held {
                owner: held.owner,
                published: held.published,
            }),
            None => {
                set.next_token += 1;
                let token = set.next_token;
                set.ports.insert(
                    port,
                    PublicationEntry {
                        owner,
                        token,
                        published: false,
                        listed: None,
                    },
                );
                Ok(Reservation {
                    set: self.clone(),
                    port,
                    token,
                    recorded: false,
                })
            }
        }
    }

    /// The surface that holds `port`, if the box's set names one: the owner
    /// a reservation refused under this set answers with — the answer
    /// before they bind, and the answer a refusal line names when the other
    /// surface already holds the port.
    #[cfg(test)]
    pub(crate) fn held_by(&self, port: u16) -> Option<PublicationOwner> {
        self.set
            .lock()
            .expect("box publications lock poisoned")
            .ports
            .get(&port)
            .map(|entry| entry.owner)
    }

    /// The rows the listen watcher's standing publications are listed as in
    /// `min session policy` (NET-044), in port order: one per port the
    /// watcher published and has not withdrawn. A pending reservation lists
    /// nothing, and neither does a publication of the expose path — its row
    /// is the session's runtime-ingress table's — so a port is never listed
    /// twice, and a row goes the moment its entry does: the listener's
    /// close, or a revocation.
    pub fn listen_rows(&self) -> Vec<minimald_rpc::LiveMapping> {
        self.set
            .lock()
            .expect("box publications lock poisoned")
            .ports
            .values()
            .filter(|entry| entry.owner == PublicationOwner::Listen && entry.published)
            .filter_map(|entry| entry.listed.clone())
            .collect()
    }

    /// The row the listen watcher's standing publication of `port` is
    /// listed as, when one is: the publication stands and its gate admits
    /// the port, so the port is reachable at the row's `local`. `None` for a
    /// port the watcher does not hold, a pending reservation, and a
    /// publication committed unlisted because its record was refused.
    pub fn listen_row(&self, port: u16) -> Option<minimald_rpc::LiveMapping> {
        self.set
            .lock()
            .expect("box publications lock poisoned")
            .ports
            .get(&port)
            .filter(|entry| entry.owner == PublicationOwner::Listen && entry.published)
            .and_then(|entry| entry.listed.clone())
    }

    /// Withdraws `port` from the set — `owner`'s own publication only. The
    /// other surface's entry is left standing whatever the caller meant,
    /// because the publisher is the one who withdraws: a port held by
    /// `Expose` here is never taken down by the watcher, and one held by
    /// `Listen` is never taken down by the expose path.
    pub fn withdraw(&self, port: u16, owner: PublicationOwner) {
        let mut set = self.set.lock().expect("box publications lock poisoned");
        if set
            .ports
            .get(&port)
            .is_some_and(|held| held.owner == owner && held.published)
        {
            set.ports.remove(&port);
        }
    }

    /// Revokes every entry in the set without asking who owns it. A
    /// revocation — the box's stop unbinding whatever it published —
    /// overrides ownership: the port comes down whoever published it, and
    /// the set stops naming ports the revocation unbound. The publisher's
    /// own lifecycle withdrawal ([`Self::withdraw`]) stays owner-checked;
    /// this is the ingress revocation's half.
    ///
    /// Any future revocation path (an expose-revoke, a `dynamic_ingress`
    /// policy change) calls this, with no owner check.
    pub fn revoke_all(&self) {
        let mut set = self.set.lock().expect("box publications lock poisoned");
        set.ports.clear();
        set.audit_refused.clear();
    }

    /// Lists the listen watcher's committed publication of `port` as `row`
    /// in `min session policy` (NET-044): the row a publication committed
    /// unadmitted — its allow's record refused — carries only once its gate
    /// admits the port, so a policy read never lists a port the gate
    /// refuses. `owner`'s own published entry only.
    pub fn list(&self, port: u16, owner: PublicationOwner, row: minimald_rpc::LiveMapping) {
        let mut set = self.set.lock().expect("box publications lock poisoned");
        if let Some(entry) = set
            .ports
            .get_mut(&port)
            .filter(|entry| entry.owner == owner && entry.published)
        {
            entry.listed = Some(row);
        }
    }

    /// Marks `port` as a permitted listen the watcher could not publish
    /// because the audit log refused its record (`refused`), or clears the
    /// mark once the record is written or the listener is gone.
    pub fn mark_audit_refused(&self, port: u16, refused: bool) {
        let mut set = self.set.lock().expect("box publications lock poisoned");
        if refused {
            set.audit_refused.insert(port);
        } else {
            set.audit_refused.remove(&port);
        }
    }

    /// Keeps the audit-refused marks only for the ports `keep` still names:
    /// a listener that closed takes its mark with it.
    pub fn retain_audit_refused(&self, keep: impl Fn(u16) -> bool) {
        self.set
            .lock()
            .expect("box publications lock poisoned")
            .audit_refused
            .retain(|port| keep(*port));
    }

    /// The permitted listening ports left unpublished because their audit
    /// record could not be written, in port order — the warning rows
    /// `min session policy` prints.
    pub fn audit_refused(&self) -> Vec<u16> {
        self.set
            .lock()
            .expect("box publications lock poisoned")
            .audit_refused
            .iter()
            .copied()
            .collect()
    }
}

/// One port reserved in a [`BoxPublications`] before its bind: the RAII
/// half of the set's check-then-hold. The reservation exists so the port is
/// held against the other surface from *before* the bind — the loser never
/// reaches the switch — and [`Self::record`] is the only thing that turns
/// it into a publication: committed, the entry stands as the caller's own
/// until its publisher withdraws it or a revocation clears it.
///
/// Every other end is a release, without the caller doing anything:
/// a bind that fails, a box that stopped under the bind, a future cancelled
/// mid-bind — each drops this guard, and the drop takes the pending entry
/// out by the token it was written with, so a release can never touch an
/// entry another reservation has since put in its place.
pub struct Reservation {
    /// The set the reservation was made in, so the guard can release
    /// itself wherever the holding future is dropped.
    set: BoxPublications,
    port: u16,
    /// The entry's key: what the release is checked against.
    token: u64,
    /// Set only by [`Self::record`], which consumes the guard — the drop
    /// below releases nothing that was committed.
    recorded: bool,
}

impl Reservation {
    /// Commits the reservation as `owner`'s publication: the bind the
    /// reservation was made for stood, so the port is a mapping from here —
    /// listed by the policy surfaces, withdrawable by its publisher — and
    /// the guard disarms. Consumes the guard, so a committed entry has no
    /// drop left that could take it down.
    ///
    /// Returns whether the reservation was still standing. `false` means a
    /// revocation cleared it under the bind: nothing is committed, and the
    /// forward the caller just bound is one the revocation never saw, so
    /// the caller unbinds it itself — ingress revocation unbinds (design
    /// §7.1), and nothing else names that forward to take it down.
    #[must_use = "a `false` record leaves a bound forward only its caller can unbind"]
    pub fn record(self) -> bool {
        self.commit(None)
    }

    /// [`Self::record`], with the row the publication is listed as in
    /// `min session policy` (NET-044) kept on its entry, for a surface that
    /// lists its publications from this set — the listen watcher, whose
    /// forwards no other table holds. The row stands exactly as long as the
    /// entry does.
    #[must_use = "a `false` record leaves a bound forward only its caller can unbind"]
    pub fn record_listed(self, row: minimald_rpc::LiveMapping) -> bool {
        self.commit(Some(row))
    }

    /// The commit both records share: the entry this guard wrote, still its
    /// own by token, turns published and takes `listed` as its row.
    fn commit(mut self, listed: Option<minimald_rpc::LiveMapping>) -> bool {
        self.recorded = true;
        let mut set = self.set.set.lock().expect("box publications lock poisoned");
        match set
            .ports
            .get_mut(&self.port)
            .filter(|e| e.token == self.token)
        {
            Some(entry) => {
                entry.published = true;
                entry.listed = listed;
                true
            }
            None => false,
        }
    }
}

/// Commits a bound listen publication in the order its row's claim needs:
/// `admit` lets the port through the box's gate first, and only then does
/// the reservation commit with the row it lists as (NET-044). The row reads
/// reachable, so it is the last thing made visible: a policy read never
/// lists a port its gate does not yet admit, and a publish that ends before
/// the admission lists nothing. The design's own order for a publication —
/// bind, then admit, then the visible claim (design §7.1) — held for the
/// listing.
///
/// Returns [`Reservation::record_listed`]'s answer: `false` means a
/// revocation cleared the reservation under the bind, nothing was listed,
/// and the caller takes back the admission `admit` made.
fn admit_then_list(
    reservation: Reservation,
    row: minimald_rpc::LiveMapping,
    admit: impl FnOnce(),
) -> bool {
    admit();
    reservation.record_listed(row)
}

impl Drop for Reservation {
    /// The reservation's own rollback, on every path that is not a
    /// record: release the pending entry this guard wrote, keyed by its
    /// token — a revocation that cleared the set under the bind leaves
    /// nothing to release, and a token that is no longer the entry's (the
    /// set was cleared and the port re-reserved) releases nothing either.
    /// Never unbinds: a reservation that was not recorded has no bind of
    /// its own, and the winner's `local` is the loser's `local` too — the
    /// release takes the reservation out of the set, and the bind it never
    /// committed stays whatever the winner holds.
    fn drop(&mut self) {
        if self.recorded {
            return;
        }
        // Never `expect` here: a drop can run during an unwind, and a
        // second panic there aborts. A poisoned map is still the map.
        let mut set = self
            .set
            .set
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if set
            .ports
            .get(&self.port)
            .is_some_and(|entry| entry.token == self.token)
        {
            set.ports.remove(&self.port);
        }
    }
}

/// The running watcher: what a host holds for its box's lifetime, stopped by
/// [`Self::stop`] at session end. Stopping is the one other thing the
/// watcher does — its loop polls, and everything it published comes down
/// before `stop` returns, so no runtime-published forward outlives its box.
pub struct ListenWatcher {
    /// Signals the loop out of its poll cycle. The withdrawal that follows
    /// is the stop's own work, and the loop's last.
    stop: watch::Sender<bool>,
    /// The loop task: it ends after withdrawing everything, so awaiting it
    /// *is* awaiting the withdrawal.
    task: tokio::task::JoinHandle<()>,
}

impl ListenWatcher {
    /// Starts the box's watcher: a loop that reads the box's listening
    /// sockets from `source` and keeps the box's publications in step with
    /// them. The first poll happens at once, so a listener that outlived a
    /// previous host is published before a person can look for it.
    #[must_use]
    pub(crate) fn start(plan: ListenPlan, source: Arc<dyn Listeners>) -> Self {
        let (stop, mut stop_rx) = watch::channel(false);
        tracing::debug!(
            session = %plan.box_name,
            lease = %plan.lease,
            published = %plan.published,
            "listen watcher started"
        );
        // Detached: the watcher lives as long as the box, so spawned in the
        // caller's span (the host-launch message's) it would hold that span
        // open for the box's whole life and parent every poll to a one-shot
        // message. Its own root links back to the launch instead
        // (`traced::spawn_detached`).
        let root = tracing::info_span!(
            parent: None,
            "net.listen_watcher",
            session = %plan.box_name,
            lease = %plan.lease,
        );
        let task = crate::traced::spawn_detached(root, async move {
            let mut state = WatchState::new(plan, source);
            loop {
                state.poll().await;
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    () = state.source.changed() => {}
                    () = tokio::time::sleep(LISTEN_REREAD) => {}
                }
            }
            // The stop's own work: everything the box's processes published
            // comes down here, before the stopper's teardown continues.
            state.withdraw_all().await;
        });
        Self { stop, task }
    }

    /// Stops the watcher and withdraws every port it still publishes — the
    /// gate refusing each first, the switch's forward second — so that when
    /// this returns, no port the box's processes published by listening is
    /// published any more. The declared forwards are not this call's:
    /// they come down with the attachment's own teardown (NET-121).
    pub async fn stop(mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the loop may already have ended; the join below is what reports that"
        )]
        let _ = self.stop.send(true);
        // The task is awaited by reference, not moved out of `self` — the
        // [`Drop`] below ends the watcher a host that never reaches this
        // stop leaves, and the drop at this stop's end finds a loop that
        // has already finished.
        if let Err(join) = (&mut self.task).await {
            tracing::warn!(
                error = %join,
                "the listen-publication watcher ended without withdrawing everything"
            );
        }
    }
}

impl Drop for ListenWatcher {
    /// The ending a host that never reached its mainloop's stop gives its
    /// watcher: dropped, not stopped — a host build abandoned, a future
    /// cancelled mid-flight. The drop is the loop's stop signal, so the poll
    /// ends and the loop runs the same withdrawal every stop runs: the gate
    /// refusing each port first, the forward coming down after, everything
    /// it published — no forward a box's processes published by listening
    /// outlives the watcher, whichever way the watcher ended.
    ///
    /// The signal is all the guard sends; the task is not aborted, on
    /// purpose. The withdrawal is the loop's own last act, and the loop is
    /// the only owner of the forwards map — an abort would kill it
    /// mid-withdrawal and leave every forward still standing on the switch
    /// for the switch's lifetime, the outcome the stop exists to prevent.
    /// Dropping the task's handle detaches it, so it finishes its epilogue
    /// the way `Host::mainloop`'s own kill does (the session's
    /// detach-over-abort choice, held here for the same reason).
    fn drop(&mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the loop may already have ended, and nothing here awaits its \
                      join to report that — the drop's caller is gone"
        )]
        let _ = self.stop.send(true);
    }
}

/// The watcher's own state: what the box's processes were listening on at
/// the last read, and which of those the watcher published. `forwards` is
/// exactly the runtime-published set (NET-081's sub-requirement's own set):
/// a declared port is never in it, and a port the rules did not permit
/// never enters it.
struct WatchState {
    plan: ListenPlan,
    /// The box's listening sockets.
    source: Arc<dyn Listeners>,
    /// Whether the streak of polls that could not read the box's socket
    /// table has been said already, once per streak.
    reported_read_failure: bool,
    /// The listening ports the last table read named, for the debug line
    /// a change in them owes (so a poll that sees the same set says
    /// nothing).
    last_seen: HashSet<u16>,
    /// The listening ports the last read settled — published, declined by
    /// the rules, a declaration's own, or another surface's standing
    /// publication. A port whose publication failed to bind, and a port
    /// another surface is still binding, are held out until a poll settles
    /// them, so the diff reads each as appeared again: the retry the bind
    /// failure's line promises, the re-read a pending holder's resolve
    /// owes.
    listening: HashSet<u16>,
    /// The forwards standing for the ports the watcher published — standing
    /// on the switch, including one whose unexpose failed and whose
    /// withdrawal is therefore still owed.
    forwards: HashMap<u16, ExposedMapping>,
    /// One entry per permitted port whose publish the switch has refused
    /// and not yet re-granted: when its next attempt may run, and how many
    /// attempts the streak has refused. A port with an entry is one the
    /// box is still listening on and the watcher still owes a publication,
    /// which is exactly the set [`Self::listening`] is held down to.
    backoff: HashMap<u16, PublishBackoff>,
    /// The ports whose contention has been said once already: a port the
    /// other surface is binding is read on *every* poll until its
    /// holder's bind resolves, and the same pending owner named four times
    /// a second is the publish half's discipline given away — the line is
    /// written when the contention starts, and the appearance that settles
    /// — the holder's publication, its release, this watcher's own bind —
    /// ends the streak.
    reported_contention: HashSet<u16>,
    /// The ports whose failed unexpose has been said once already: a
    /// withdrawal that keeps failing is the *same* failure on every poll
    /// and every stop pass, so its line is written once — the withdrawal's
    /// own line, when the unexpose finally comes down, ends the streak.
    reported_withdrawal_failures: HashSet<u16>,
    /// The ports whose standing forward was never recorded: the publish's
    /// `Published` append failed and the unwind's unexpose failed too
    /// (NET-046 fails closed, [`Self::unpublish_unaudited`]), so the
    /// forward stands on the switch while the gate refuses it. The poll
    /// retries the record on the backoff the failure earned, and the
    /// re-admit a returning listener would make is held until the record
    /// is written — an allow nobody can read is never admitted, not even
    /// twice. The entry goes when the forward comes down, recorded or not.
    unrecorded: HashSet<u16>,
}

/// One permitted port whose publish the switch refused: the book
/// [`WatchState::poll`] keeps so a refusal that is not transient is waited
/// out per port rather than re-asked on every poll.
struct PublishBackoff {
    /// When the next expose attempt may run — the backoff the streak's last
    /// refusal chose.
    retry_at: std::time::Instant,
    /// How many attempts the streak has refused: the count the publication
    /// that ends it carries, and the doubling's own counter.
    refusals: u32,
}

/// The wait a refused publish's next attempt takes: the poll interval
/// doubled once per refusal already in the streak, capped at
/// [`PUBLISH_RETRY_CAP`]. The first refusal costs one poll — exactly the
/// retry a single failure always paid — and each one after it doubles, so a
/// forwarder that is down for as long as it takes is asked about once every
/// half minute at most instead of four times a second.
fn retry_after(refusals: u32) -> Duration {
    let mut delay = LISTEN_POLL_INTERVAL;
    for _ in 1..refusals {
        delay = delay.saturating_mul(2).min(PUBLISH_RETRY_CAP);
    }
    delay
}

/// What one appearance of a listening port came to. The distinction the
/// poll's book ([`WatchState::listening`]) is drawn along: only a settled
/// appearance enters the book, so every appearance that is not settled is
/// read as appeared again by the next poll.
enum Appearance {
    /// The appearance is decided — published by this watcher, re-admitted
    /// after a failed withdrawal, declined by the rules, a declaration's
    /// own, or another surface's standing publication. It enters the
    /// book: the port is not read as appeared again while its fact holds.
    Settled,
    /// The switch refused this watcher's own bind. The appearance is
    /// still owed, and the port is retried on the backoff its refusals
    /// have earned — held out of the book so the next poll that may ask
    /// reads it as appeared again.
    Owing,
    /// Another surface holds the port with a reservation whose bind is
    /// still in flight: nothing was asked of the switch, nothing failed,
    /// and the fact that decided the appearance may not outlive the
    /// moment — the holder's bind can still fail and give the port back.
    /// The appearance is left undecided on purpose: no line is written,
    /// no backoff is earned, and the port is held out of the book, so
    /// the very next poll reads it again — the holder that recorded
    /// settles it, the holder that released leaves it to publish.
    Contended,
}

impl WatchState {
    fn new(plan: ListenPlan, source: Arc<dyn Listeners>) -> Self {
        Self {
            plan,
            source,
            reported_read_failure: false,
            last_seen: HashSet::new(),
            listening: HashSet::new(),
            forwards: HashMap::new(),
            backoff: HashMap::new(),
            reported_contention: HashSet::new(),
            reported_withdrawal_failures: HashSet::new(),
            unrecorded: HashSet::new(),
        }
    }

    /// One poll: read the box's listening sockets, publish what appeared,
    /// withdraw what closed, and ask again for what a refusal has left
    /// owed. A publication that failed to bind keeps its port out of the
    /// book ([`Self::listening`]), and so does a port another surface is
    /// reserving, so the next poll reads both as appeared again — neither
    /// appearance is consumed by what it came to, and neither a transient
    /// refusal on the control channel nor a concurrent expose can turn
    /// into a permitted port that stays unpublished until its server
    /// restarts.
    async fn poll(&mut self) {
        let listening = match self.source.listening() {
            Ok(listening) => super::listens::reachable_ports(&listening, self.plan.lease),
            Err(e) => {
                // Keep the last diff rather than publishing or withdrawing
                // on a table that could not be read: the stop withdraws
                // everything still standing. Said once per
                // streak at warn: a box whose table cannot be read
                // publishes no listen at all.
                if !self.reported_read_failure {
                    self.reported_read_failure = true;
                    tracing::warn!(
                        session = %self.plan.box_name,
                        error = %e,
                        "reading the box's listening sockets failed; retrying on every poll"
                    );
                }
                return;
            }
        };
        self.reported_read_failure = false;
        if listening != self.last_seen {
            let mut ports: Vec<u16> = listening.iter().copied().collect();
            ports.sort_unstable();
            tracing::debug!(
                session = %self.plan.box_name,
                lease = %self.plan.lease,
                ports = ?ports,
                "the box's listening sockets that a forward to its lease can reach"
            );
            self.last_seen = listening.clone();
        }
        // The diff is taken before anything mutates, so a publication made
        // here cannot be seen by the withdrawal beside it.
        let appeared: Vec<u16> = listening.difference(&self.listening).copied().collect();
        let disappeared: HashSet<u16> = self.listening.difference(&listening).copied().collect();
        // The appearances this poll could not decide: another surface is
        // binding the port, so the next poll reads the port again rather
        // than settling for whichever way the holder's bind was heading.
        let mut contended: HashSet<u16> = HashSet::new();
        for port in appeared {
            if matches!(self.publish(port).await, Appearance::Contended) {
                contended.insert(port);
            }
        }
        for port in &disappeared {
            self.close(*port, "listener closed").await;
        }
        // The withdraw half of the nothing-is-one-shot promise: a forward
        // whose unexpose failed is still standing on the switch —
        // delivering to a lease:port nothing answers — for as long as the
        // box runs, and the port left the listening book the poll its
        // listener closed in, so the diff above never reads it as
        // disappeared twice. Every port held in `forwards` that this
        // poll's table does not name is a withdrawal the watcher still
        // owes, and is asked for again here — bar one the diff above just
        // tried, which this poll has already asked for and the next one
        // will.
        let owed: Vec<u16> = self
            .forwards
            .keys()
            .copied()
            .filter(|port| !listening.contains(port) && !disappeared.contains(port))
            .collect();
        for port in owed {
            self.close(port, "the listener had closed and its unexpose failed")
                .await;
        }
        // A port whose listener closed takes its backoff streak and its
        // contention streak with it: the book keeps both out of the
        // listening table (below), so the diff above never reads one as
        // disappeared — without this, the entry outlives the listener it
        // was refused for, and the next server the box binds on that port
        // number inherits a wait it did not earn and a count whose first
        // failure was never said. The fresh table is the fact that
        // decides: an entry survives only while a process in the box is
        // still listening on its port.
        self.backoff.retain(|port, _| listening.contains(port));
        self.plan
            .publications
            .retain_audit_refused(|port| listening.contains(&port));
        self.reported_contention
            .retain(|port| listening.contains(port));
        self.listening = listening;
        // A port in the backoff book is one the box is listening on and
        // the watcher has still not published; a port in the contended
        // set is one the box is listening on and another surface is
        // binding. Both stay out of the book the diff reads: every poll
        // that does not retry them sees them as appeared again, the poll
        // that does keeps the backed-off one unsettled until the forward
        // binds, and the contended one is re-read the moment after its
        // holder's bind resolved — recorded by its winner, released for
        // this watcher to publish.
        self.listening
            .retain(|port| !self.backoff.contains_key(port) && !contended.contains(port));
    }

    /// NET-016: one listening port appeared, published unless the switch is
    /// still refusing its publish or another surface is publishing it. A
    /// port whose last attempt failed waits its backoff out first — the
    /// appearance it still owes is kept while it waits, never dropped and
    /// never re-asked on every poll. A port another surface is binding
    /// earns no backoff and no line beyond the one that names the holder,
    /// and is simply read again on the next poll.
    async fn publish(&mut self, port: u16) -> Appearance {
        let refusals = match self.backoff.get(&port) {
            // The streak's backoff has not elapsed: this poll does not ask.
            // The appearance is still owed, and the backoff book holds the
            // port out of the poll's table until the wait is done.
            Some(wait) if wait.retry_at > std::time::Instant::now() => return Appearance::Owing,
            Some(wait) => wait.refusals,
            None => 0,
        };
        match self.open(port, refusals).await {
            // The streak ends: the port is published, and the next failure
            // — if the box's server ever makes one — is a streak of its own.
            Appearance::Settled => {
                self.backoff.remove(&port);
                Appearance::Settled
            }
            Appearance::Owing => {
                let refusals = refusals + 1;
                self.backoff.insert(
                    port,
                    PublishBackoff {
                        retry_at: std::time::Instant::now() + retry_after(refusals),
                        refusals,
                    },
                );
                Appearance::Owing
            }
            // A pending reservation is not a publish that failed — the
            // switch was never asked — so no backoff is earned and none
            // is kept for it: the poll's contended set holds the port
            // out of the book, and the next poll reads it again.
            contended => contended,
        }
    }

    /// NET-016: one listening port appeared. The shared verdict decides
    /// what the appearance is worth before anything is bound, and the
    /// box's publication set decides it with them — by reservation, the
    /// check and the hold in one step, so a port the other surface is
    /// binding is never asked of the switch here at all. A port the
    /// runtime expose already published is settled the way one the rules
    /// do not permit is — left alone, never bound, never withdrawn, never
    /// retried — because a publication that already stands is not this
    /// watcher's to double; a port it is still *binding* is contended:
    /// not this watcher's yet, and possibly not the holder's either.
    ///
    /// `refusals` counts the attempts this port's publish streak has
    /// already been refused, so the failure is said once per streak — the
    /// first refusal's line, never the retries' — and the publication that
    /// ends a streak names what it took.
    async fn open(&mut self, port: u16, refusals: u32) -> Appearance {
        // TCP is the transport the watcher knows a listener in: the kernel
        // tables it reads name TCP listening sockets, and the forward it
        // binds answers TCP — so TCP is the transport it asks the shared
        // verdict for. A declaration that names the port on UDP alone is
        // not a publication of this listener (its forward would never
        // answer the protocol the watcher dials), so the verdict falls to
        // the rules rather than answering `Declared` transport-blind.
        let verdict = self.plan.gate.listen_verdict(IpProto::Tcp, port);
        tracing::debug!(
            session = %self.plan.box_name,
            port,
            verdict = ?verdict,
            "listen verdict for a port that appeared"
        );
        match verdict {
            ListenVerdict::Publish => {
                if self.forwards.contains_key(&port) {
                    if self.unrecorded.contains(&port) {
                        // The forward never came down after its allow could
                        // not be recorded (NET-046): the gate stays refusing
                        // until the record is written, and the backoff the
                        // failure earned paces this retry. When the log
                        // takes the record the forward it already holds is
                        // the published one — admitted, said, settled — so
                        // service restores the moment the audit can carry
                        // it; while it does not, the allow stays refused,
                        // which is the closed side. The stop's withdrawal
                        // passes bring the forward down when the box ends.
                        if let Err(error) = crate::audit::try_append(
                            &self.plan.state_dir,
                            &self.listen_record(
                                port,
                                crate::audit::DecisionOutcome::Published,
                                None,
                            ),
                        )
                        .await
                        {
                            if refusals == 0 {
                                tracing::warn!(
                                    session = %self.plan.box_name,
                                    host = %self.plan.published,
                                    port,
                                    verdict = "permitted",
                                    owner = %PublicationOwner::Listen.as_str(),
                                    retry_in = ?retry_after(refusals + 1),
                                    error = %error,
                                    "the standing listening port's allow is still unaudited; \
                                     it stays withdrawn"
                                );
                            }
                            return Appearance::Owing;
                        }
                        self.unrecorded.remove(&port);
                        self.reported_withdrawal_failures.remove(&port);
                        self.reported_contention.remove(&port);
                        self.plan.publications.mark_audit_refused(port, false);
                        // Admitted first, listed after: the entry was
                        // committed unlisted when its record was refused,
                        // so the row that reads reachable appears only
                        // once the gate admits (NET-044).
                        self.plan.gate.admit_published(port);
                        // The standing forward serves from here on, so the
                        // box holds its port of record (NET-129), exactly
                        // as the fresh publish below records it.
                        self.plan.record_dynamic_hold(self.plan.published, port);
                        if let Some(mapping) = self.forwards.get(&port) {
                            self.plan.publications.list(
                                port,
                                PublicationOwner::Listen,
                                minimald_rpc::LiveMapping {
                                    local: mapping.local().to_string(),
                                    internal_port: port,
                                    proto: IpProto::Tcp,
                                    pending: Some(false),
                                },
                            );
                        }
                        tracing::info!(
                            session = %self.plan.box_name,
                            host = %self.plan.published,
                            port,
                            verdict = "permitted",
                            reason = "the audit log took the standing forward's record",
                            "re-admitted a listening port on the box's address"
                        );
                        return Appearance::Settled;
                    }
                    // The port's listener closed, the withdrawal's unexpose
                    // failed, and the listener is back before the stop
                    // could retry the forward down: the forward never came
                    // down, so the publication still stands and still
                    // delivers to a port the rules permit. Re-admit it
                    // rather than ask the switch to bind a second forward
                    // onto the bind this one still holds.
                    self.reported_withdrawal_failures.remove(&port);
                    self.reported_contention.remove(&port);
                    self.plan.gate.admit_published(port);
                    tracing::info!(
                        session = %self.plan.box_name,
                        host = %self.plan.published,
                        port,
                        verdict = "permitted",
                        reason = "the listener returned while its withdrawal had failed",
                        "re-admitted a listening port on the box's address"
                    );
                    return Appearance::Settled;
                }
                // Reserve the port before asking the switch for anything:
                // the reservation is the check-then-bind's atomic half —
                // the box's other runtime surface (NET-044) can be binding
                // this very port across this await, and whichever surface
                // reserves second is answered here, before it holds
                // anything of the switch's, so the port is bound once,
                // by whichever surface's reservation won.
                match self
                    .plan
                    .publications
                    .reserve(port, PublicationOwner::Listen)
                {
                    Err(held) if held.published => {
                        // The other surface's publication stands: a
                        // `min net expose` published it live, and its
                        // forward stands until the box does. A second bind
                        // would double-bind the box's own address at the
                        // same port, and the publication is not this
                        // watcher's to withdraw — so the appearance is
                        // settled the way one the rules do not permit
                        // settles: said once, naming the owner that holds
                        // the port, never bound, never withdrawn, and
                        // never retried, because the settlement enters
                        // the port in the poll's book and a backoff is
                        // for a publish that failed, not for a
                        // publication that already stands. Nor is the
                        // port admitted here: the expose admitted it at the
                        // gate when it published (NET-044), and that
                        // admission is the expose's to withdraw, not this
                        // listener's.
                        self.reported_contention.remove(&port);
                        tracing::info!(
                            session = %self.plan.box_name,
                            host = %self.plan.published,
                            port,
                            verdict = "permitted",
                            owner = %held.owner.as_str(),
                            "left a listening port the runtime expose already published"
                        );
                        Appearance::Settled
                    }
                    Err(held) => {
                        // The other surface holds the port with a
                        // reservation whose bind is still in flight:
                        // settled neither way, because the fact can change
                        // — the holder's bind can still fail and give the
                        // port back. Nothing was asked of the switch, so
                        // nothing failed and no backoff is earned; the
                        // line is said once per streak of contention, the
                        // publish half's own discipline, and the port is
                        // held out of the poll's book so the very next
                        // poll reads it again: the holder that records
                        // settles the skip above, the holder that
                        // releases leaves the port for this watcher to
                        // publish.
                        if self.reported_contention.insert(port) {
                            tracing::info!(
                                session = %self.plan.box_name,
                                host = %self.plan.published,
                                port,
                                verdict = "permitted",
                                owner = %held.owner.as_str(),
                                "left a listening port the runtime expose is publishing"
                            );
                        }
                        Appearance::Contended
                    }
                    Ok(reservation) => {
                        // The forward binds before the gate admits — the
                        // order the declaration's own apply holds
                        // (NET-121), so a port is never admitted while
                        // nothing answers for it, and a bind that fails
                        // admits nothing: the failure is said below, once
                        // per streak, and the poll keeps the port out of
                        // its book, so a later poll sees it still
                        // unpublished and asks again on the backoff the
                        // refusals have earned. The reservation is the
                        // rollback's own key the whole way: it releases
                        // itself — by its token, never by the winner's
                        // local — on every end but `record`.
                        match expose_mapping(
                            &self.plan.control,
                            self.plan.published,
                            self.plan.lease,
                            port,
                        )
                        .await
                        {
                            Ok(mapping) => {
                                self.reported_contention.remove(&port);
                                tracing::debug!(
                                    session = %self.plan.box_name,
                                    port,
                                    lease = %self.plan.lease,
                                    gate = ?Arc::as_ptr(&self.plan.gate),
                                    is_live_gate = crate::net::ingress_gate::live_gate(self.plan.lease)
                                        .is_some_and(|live| Arc::ptr_eq(&live, &self.plan.gate)),
                                    "admitting a listen-published port at the box's gate"
                                );
                                let row = minimald_rpc::LiveMapping {
                                    local: mapping.local().to_string(),
                                    internal_port: port,
                                    proto: IpProto::Tcp,
                                    pending: Some(false),
                                };
                                // NET-046 fails closed: the allow's
                                // `Published` record is written while the
                                // forward is bound but the gate still
                                // refuses the port, so nothing reaches the
                                // box through a publish the log could not
                                // take. A record the log refuses unwinds the
                                // publish before it was ever admitted: the
                                // reservation commits unadmitted and
                                // unlisted — no policy row claims a port
                                // the gate refuses — only so
                                // [`Self::close`] owns the forward's unwind —
                                // a forward whose unexpose fails stays held,
                                // with its `unrecorded` mark, for the retry —
                                // and the port is owed again on the backoff
                                // the return earns, retried until the log
                                // takes the record or the listener closes.
                                if let Err(error) = crate::audit::try_append(
                                    &self.plan.state_dir,
                                    &self.listen_record(
                                        port,
                                        crate::audit::DecisionOutcome::Published,
                                        None,
                                    ),
                                )
                                .await
                                {
                                    if !reservation.record() {
                                        // Revoked under the bind as well:
                                        // nothing was admitted, so the
                                        // revoked arm's unbind is the whole
                                        // unwind.
                                        self.unbind_revoked(port, &mapping).await;
                                        return Appearance::Settled;
                                    }
                                    self.forwards.insert(port, mapping);
                                    self.unpublish_unaudited(port, refusals, error).await;
                                    return Appearance::Owing;
                                }
                                // The bind stood and its record is written:
                                // the gate admits the port, and only then
                                // does the reservation commit as this
                                // watcher's publication — listed in
                                // `min session policy` as the row it carries
                                // (NET-044), withdrawable by its publisher.
                                // The row reads reachable, so it is the last
                                // thing made visible ([`admit_then_list`]).
                                if !admit_then_list(reservation, row, || {
                                    self.plan.gate.admit_published(port);
                                }) {
                                    // A revocation cleared the reservation
                                    // under the bind, so the forward this
                                    // watcher just bound is one it never
                                    // saw: this watcher takes its admission
                                    // back, unbinds it, and settles — a
                                    // revoked port is not retried, and it
                                    // was never listed.
                                    self.plan.gate.withdraw_published(port);
                                    self.unbind_revoked(port, &mapping).await;
                                    // The allow's `Published` record is
                                    // already written, but the publish never
                                    // stood: the log says so, so it never
                                    // claims a publication that did not
                                    // happen (NET-046). Best-effort, like
                                    // every refusal's record.
                                    self.audit_listen(
                                        port,
                                        crate::audit::DecisionOutcome::PublishFailed,
                                        Some(
                                            "the publication was revoked before it stood"
                                                .to_string(),
                                        ),
                                    )
                                    .await;
                                    return Appearance::Settled;
                                }
                                self.forwards.insert(port, mapping);
                                // The publication stands at the box's
                                // published address, so the box is the
                                // port's one holder of record (NET-129):
                                // recorded here, at the moment the forward
                                // is bound and admitted, so a declared
                                // publish of the same port elsewhere sees
                                // the box that is serving and yields
                                // instead of failing on it.
                                self.plan.record_dynamic_hold(self.plan.published, port);
                                self.plan.publications.mark_audit_refused(port, false);
                                tracing::info!(
                                    session = %self.plan.box_name,
                                    host = %self.plan.published,
                                    port,
                                    verdict = "permitted",
                                    owner = %PublicationOwner::Listen.as_str(),
                                    refusals,
                                    "published a listening port on the box's address"
                                );
                                Appearance::Settled
                            }
                            Err(e) => {
                                if refusals == 0 {
                                    // One line per streak: the refusals after this
                                    // one are the same failure, waited out rather
                                    // than repeated — the daemon log's tail is the
                                    // diagnostics bundle's.
                                    tracing::warn!(
                                        session = %self.plan.box_name,
                                        host = %self.plan.published,
                                        port,
                                        verdict = "permitted",
                                        owner = %PublicationOwner::Listen.as_str(),
                                        retry_in = ?retry_after(refusals + 1),
                                        error = %e,
                                        "publishing a listening port on the switch failed"
                                    );
                                }
                                // The bind failed, so the reservation
                                // releases itself here — the guard's
                                // drop, keyed by its token — and the port
                                // is free again: the other surface's next
                                // observation, or this watcher's own
                                // retry, publishes it normally.
                                drop(reservation);
                                if refusals == 0 {
                                    // The streak's one decision record
                                    // (NET-046): the allow stood and the bind
                                    // failed. The retries are the same
                                    // decision, waited out, and write none;
                                    // the publish that ends the streak
                                    // writes its own.
                                    self.audit_listen(
                                        port,
                                        crate::audit::DecisionOutcome::PublishFailed,
                                        Some(e.to_string()),
                                    )
                                    .await;
                                }
                                Appearance::Owing
                            }
                        }
                    }
                }
            }
            // A declaration names the port: its forward was bound at
            // publish and is held until the box stops (NET-121), so there
            // is nothing to publish — and when the listener closes, nothing
            // to withdraw (NET-081's sub-requirement). The declaration's
            // own bind lines already name the port.
            ListenVerdict::Declared => Appearance::Settled,
            ListenVerdict::Deny => {
                let reason = match self.plan.gate.dynamic_verdict(port) {
                    boxes::core::ingress::DynamicPortVerdict::Deny => {
                        "the box's dynamic ingress stance is deny".to_string()
                    }
                    boxes::core::ingress::DynamicPortVerdict::Ask => {
                        "the box's dynamic ingress stance is ask; a listen cannot answer it"
                            .to_string()
                    }
                    boxes::core::ingress::DynamicPortVerdict::NoRange => {
                        "the box declared no dynamic allowed range".to_string()
                    }
                    boxes::core::ingress::DynamicPortVerdict::OutOfRange { .. } => {
                        "the port is outside the box's dynamic allowed range".to_string()
                    }
                    // Not reached: an allowed port is a `Publish` verdict.
                    boxes::core::ingress::DynamicPortVerdict::Allow => {
                        "the stance allows it but the verdict did not".to_string()
                    }
                };
                // Out of range is the one refusal a box whose stance is
                // allow with a range can draw: said at warn, so a listen the
                // box's declaration could have published is never quiet.
                if matches!(
                    self.plan.gate.dynamic_verdict(port),
                    boxes::core::ingress::DynamicPortVerdict::OutOfRange { .. }
                ) {
                    tracing::warn!(
                        session = %self.plan.box_name,
                        port,
                        verdict = "not permitted",
                        reason = %reason,
                        "left a listening port unpublished"
                    );
                } else {
                    tracing::info!(
                        session = %self.plan.box_name,
                        port,
                        verdict = "not permitted",
                        reason = %reason,
                        "left a listening port unpublished"
                    );
                }
                Appearance::Settled
            }
        }
    }

    /// NET-046: the decision record a listen the watcher publishes owes.
    /// The listen was a dynamic ingress request — an in-range port, under
    /// the box's `allow` stance — and the box's own declaration decided it,
    /// so the record names the box policy as decider, the same record the
    /// runtime expose path writes for an allowed request. `outcome` is what
    /// became of the publish: `Published` once it stands, never before, or
    /// `PublishFailed` with the failure's text as `reason` on the first
    /// refusal of a streak — the retries the backoff makes are the same
    /// decision waited out, and the publish that ends the streak writes its
    /// own `Published`. Best-effort, the way every audit append is.
    async fn audit_listen(
        &self,
        port: u16,
        outcome: crate::audit::DecisionOutcome,
        reason: Option<String>,
    ) {
        crate::audit::append(
            &self.plan.state_dir,
            &self.listen_record(port, outcome, reason),
        )
        .await;
    }

    /// The record [`Self::audit_listen`] appends, kept apart for the publish
    /// itself: its `Published` record is the one an allow stands or falls
    /// on (NET-046), so the publish appends it through
    /// [`crate::audit::try_append`] and fails closed on a record that could
    /// not be written — the same line every other outcome writes best-effort.
    fn listen_record(
        &self,
        port: u16,
        outcome: crate::audit::DecisionOutcome,
        reason: Option<String>,
    ) -> crate::audit::DecisionRecord {
        crate::audit::DecisionRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            box_name: self.plan.box_name.clone(),
            port,
            decision: boxes::DynamicIngress::Allow,
            decided_by: crate::audit::DecidedBy::BoxPolicy,
            outcome,
            reason,
        }
    }

    /// NET-046's fail-closed half, the publish's own: an allow whose
    /// `Published` record could not be written is withdrawn rather than
    /// published — the watch's one decision that can still be taken back —
    /// taken down in the same order a listener's closing takes
    /// ([`Self::close`]): the gate refuses the port first, then the forward
    /// comes down, then the publication's entry goes, so no new connection
    /// crosses the gap. The port stays owed: the poll retries it on
    /// the backoff this refusal earns, and the publish that finds the log
    /// writable again ends the streak. `refusals` gates the line and the
    /// record to the streak's first refusal, the way every refusal the
    /// watcher writes is.
    async fn unpublish_unaudited(&mut self, port: u16, refusals: u32, error: std::io::Error) {
        if refusals == 0 {
            // One line per streak, naming the refusal's reason: the retries
            // the backoff makes are the same refusal, waited out.
            tracing::warn!(
                session = %self.plan.box_name,
                host = %self.plan.published,
                port,
                verdict = "permitted",
                owner = %PublicationOwner::Listen.as_str(),
                retry_in = ?retry_after(refusals + 1),
                error = %error,
                "the listening port's allow could not be audited; the publish unwound"
            );
        }
        self.close(port, "its allow could not be audited").await;
        // The mark rides only a forward that outlived the unwind: one the
        // switch took down needs no record retry — the next publish binds
        // afresh — and leaving the mark on it would make every retry's
        // close write a second `PublishFailed` the streak already wrote.
        if self.forwards.contains_key(&port) {
            self.unrecorded.insert(port);
            // The forward still occupies the box's published address:port
            // on the switch, so the box holds the port of record (NET-129)
            // while it stands — another box's declared publish yields to it
            // rather than binding onto the forward this one still holds.
            // The re-admit records it again, idempotently, and the close
            // whose unexpose comes down releases it.
            self.plan.record_dynamic_hold(self.plan.published, port);
        }
        // The failure reaches `min session policy` as a warning row for as
        // long as the box listens and the log refuses: a watcher-driven
        // publish has no caller to answer, so the row is where the user
        // reads it.
        self.plan.publications.mark_audit_refused(port, true);
        if refusals == 0 {
            // The streak's one decision record (NET-046): the allow stood,
            // the publish did not. Best-effort, like every refusal's — a
            // log that refused the allow's record says so itself if it
            // refuses this one too.
            self.audit_listen(
                port,
                crate::audit::DecisionOutcome::PublishFailed,
                Some(format!(
                    "the decision could not be recorded in the audit log: {error}"
                )),
            )
            .await;
        }
    }

    /// Unbinds the forward a publish bound under a reservation a revocation
    /// cleared while the bind was in flight. The revocation never saw this
    /// forward, so this watcher, the one that holds it, takes it down; the
    /// gate never admitted the port, so there is nothing to withdraw there.
    /// A failed unexpose is said and left: the revocation's own pass has
    /// already run, so there is no later pass to hand it to.
    async fn unbind_revoked(&mut self, port: u16, mapping: &ExposedMapping) {
        match unexpose_mapping(&self.plan.control, mapping).await {
            Ok(closed) => tracing::info!(
                session = %self.plan.box_name,
                host = %self.plan.published,
                port,
                owner = %PublicationOwner::Listen.as_str(),
                closed_connections = %closed,
                "unbound a listening port whose publication was revoked mid-bind"
            ),
            Err(e) => tracing::warn!(
                session = %self.plan.box_name,
                host = %self.plan.published,
                port,
                owner = %PublicationOwner::Listen.as_str(),
                error = %e,
                "unbinding a listening port revoked mid-bind failed"
            ),
        }
    }

    /// NET-017: one published listening port closed — or the box stopped,
    /// which closes all of them at once. The gate refuses the port first,
    /// so no new connection crosses the gap between a listener already gone
    /// and a forward still bound; the forward comes down after.
    ///
    /// `reason` names what ended the publication: the listener closing under
    /// the box's own life, the box's stop taking every publication with it,
    /// or a poll asking again for a forward whose unexpose failed while the
    /// box still runs. A port the runtime expose published never reaches
    /// the unexpose here — it is not in the watcher's forwards — so a
    /// publication comes down with whoever published it, never with the
    /// other surface that declined to bind it.
    async fn close(&mut self, port: u16, reason: &'static str) {
        let was_unrecorded = self.unrecorded.remove(&port);
        let Some(mapping) = self.forwards.remove(&port) else {
            // Never published by the watcher: a declared port, whose
            // forward is the declaration's (NET-121), one the rules did
            // not permit, whose publication never existed — or one the
            // runtime expose holds, whose forward is the expose path's and
            // whose withdrawal is the expose path's alone.
            return;
        };
        // The gate withdraws before the forward comes down, and the order is
        // the point: between the two, the listener is already gone and the
        // forward still bound, so a connection arriving in that gap would be
        // accepted by the box's own address and delivered to nothing. With
        // the gate first, that connection is refused at the address instead.
        self.plan.gate.withdraw_published(port);
        match unexpose_mapping(&self.plan.control, &mapping).await {
            Ok(closed) => {
                // NET-017's own line: the only caller of the shared unexpose
                // that withdraws a published port, so the only one to say so.
                log_withdrawal(&mapping, closed);
                // The publication is the watcher's own and it came down, so
                // the set gives the port back: the next surface that wants
                // it — this watcher, when the box's next server binds the
                // same number, or the expose path on a runtime request —
                // finds it free to publish.
                self.plan
                    .publications
                    .withdraw(port, PublicationOwner::Listen);
                // The forward is down, so the box's hold of record ends with
                // it (NET-129): the port passes to the box created earliest
                // among those still publishing it — a declared yielder's
                // forward binds at its next hand-over or attach, so a port
                // the closing listener held is never left unheld while
                // another box waits on it. Said here beside the withdraw,
                // as the hand-over's own line; the registry has already sent
                // each to the sessions manager.
                for hand_over in self.plan.release_dynamic_hold(self.plan.published, port) {
                    tracing::info!(
                        session_id = %hand_over.holder,
                        address = %hand_over.address,
                        port = hand_over.port,
                        from = %self.plan.box_name,
                        action = "shared-address-port-hand-over",
                        "a shared-address port passes to the earliest-created box still publishing it"
                    );
                }
                // The withdrawal came down, so the streak of its failures —
                // if it had one — is over and a later failure is its own.
                self.reported_withdrawal_failures.remove(&port);
                tracing::info!(
                    session = %self.plan.box_name,
                    host = %self.plan.published,
                    port,
                    verdict = "permitted",
                    owner = %PublicationOwner::Listen.as_str(),
                    reason,
                    "withdrew a listening port from the box's address"
                );
                if was_unrecorded {
                    // The allow's `Published` record could not be written
                    // and now never can be (NET-046): say the one the
                    // forward's whole life owed. Best-effort, like the
                    // refusal's own — the forward is down and the gate
                    // already refuses the port either way.
                    self.audit_listen(
                        port,
                        crate::audit::DecisionOutcome::PublishFailed,
                        Some(
                            "the decision could not be recorded in the audit log; \
                             the publish was withdrawn before it stood"
                                .to_string(),
                        ),
                    )
                    .await;
                }
            }
            Err(e) => {
                // One line per streak, like the publish half: the retries
                // the poll makes while the box runs and the stop's own
                // passes are the same failure, and repeating it four times
                // a second is what a forwarder that is down outright fills
                // the daemon log with.
                if self.reported_withdrawal_failures.insert(port) {
                    tracing::warn!(
                        session = %self.plan.box_name,
                        host = %self.plan.published,
                        port,
                        verdict = "permitted",
                        owner = %PublicationOwner::Listen.as_str(),
                        error = %e,
                        "unpublishing a listening port on the switch failed"
                    );
                }
                // The unexpose failed and said so. The gate already refuses
                // the port, so nothing reaches the box through the forward
                // left standing; keep it in the published set — and in the
                // box's publication set, whose entry says the watcher owns
                // a forward that is still bound, so no second surface asks
                // the switch for a port the first still holds — the next
                // poll asks for it again while the box runs, the stop's
                // withdrawal passes retry it before the watcher ends, and a
                // listener that comes back first re-admits the forward it
                // still holds — rather than leaving it for the switch's
                // lifetime.
                self.forwards.insert(port, mapping);
                if was_unrecorded {
                    // The forward this close took down outlives its own
                    // unwind: its allow was never recorded (NET-046), and
                    // the mark close took must return with the forward —
                    // the next poll's re-admit retries the record, and
                    // never admits an allow nobody can read.
                    self.unrecorded.insert(port);
                }
            }
        }
    }

    /// Stops the box's whole runtime-published surface: every forward still
    /// standing, withdrawn in the same order a listener's closing takes. A
    /// forward whose unexpose failed is retried on the next pass, one
    /// poll-interval apart, so a transient refusal does not leave it bound
    /// past its box holding the box's published address:port — and the
    /// passes are bounded, so a control channel that is down outright ends
    /// the stop rather than hanging it. Whatever still stands when they are
    /// spent is named, never left silent — and nothing else is: a last pass
    /// that brings everything down ends the stop with nothing to warn
    /// about.
    async fn withdraw_all(&mut self) {
        for attempt in 0..WITHDRAW_PASSES {
            if self.forwards.is_empty() {
                return;
            }
            if attempt > 0 {
                // A moment between passes, so a forwarder that was refusing
                // while mid-restart can answer the retry.
                tokio::time::sleep(LISTEN_POLL_INTERVAL).await;
            }
            let ports: Vec<u16> = self.forwards.keys().copied().collect();
            for port in ports {
                self.close(port, "box stopped").await;
            }
        }
        if self.forwards.is_empty() {
            // The last pass brought the last forward down: every port the
            // box's processes published is unpublished, and a warning that
            // named none of them would only say the stop happened — which
            // the stop itself already says.
            return;
        }
        let still: Vec<&str> = self.forwards.values().map(ExposedMapping::local).collect();
        tracing::warn!(
            session = %self.plan.box_name,
            still_published = ?still,
            "the box stopped with listening ports its watcher could not withdraw"
        );
    }
}

/// The listening ports of `entry`'s network namespace whose socket `entry`'s
/// own process holds a descriptor for: the rows of its `tcp` and `tcp6`
/// tables ([`listen_port`]) matched by socket inode against the
/// `socket:[<inode>]` links under its `fd` directory. A missing `tcp6`
/// table reads as no v6 listeners, as in [`listening_ports_in`].
#[cfg(test)]
fn listening_ports_held_by(entry: &Path, lease: Ipv4Addr) -> io::Result<HashSet<u16>> {
    let held: HashSet<u64> = std::fs::read_dir(entry.join("fd"))?
        .flatten()
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .filter_map(|target| {
            target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect();
    let mut ports = HashSet::new();
    for (table, v6) in [("net/tcp", false), ("net/tcp6", true)] {
        let text = match std::fs::read_to_string(entry.join(table)) {
            Ok(text) => text,
            Err(error) if v6 && error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in text.lines().skip(1) {
            let inode = line
                .split_whitespace()
                .nth(9)
                .and_then(|word| word.parse::<u64>().ok());
            if let (Some(port), Some(inode)) = (listen_port(line, v6, lease), inode)
                && held.contains(&inode)
            {
                ports.insert(port);
            }
        }
    }
    Ok(ports)
}

/// The listening ports of one `/proc` entry that a forward to `lease` can
/// reach.
#[cfg(test)]
fn listening_ports_in(entry: &Path, lease: Ipv4Addr) -> io::Result<HashSet<u16>> {
    let mut ports = read_listening(&entry.join("net/tcp"), false, lease)?;
    match read_listening(&entry.join("net/tcp6"), true, lease) {
        Ok(v6) => ports.extend(v6),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    Ok(ports)
}

/// One kernel socket table's listening ports: every row in state `0A`
/// (`TCP_LISTEN`) whose local address a forward dialing the box's lease can
/// deliver to. The first line is the table's header.
#[cfg(test)]
fn read_listening(table: &Path, v6: bool, lease: Ipv4Addr) -> io::Result<HashSet<u16>> {
    let text = std::fs::read_to_string(table)?;
    Ok(text
        .lines()
        .skip(1)
        .filter_map(|line| listen_port(line, v6, lease))
        .collect())
}

/// The port of one listening row of the kernel's socket table, or `None`
/// for any other row: the header, a truncated row, a socket in any state
/// but `TCP_LISTEN` — an established or time-wait socket is a connection,
/// not a listener — or a listener whose bind the forward's dial cannot
/// reach, whichever table it is in.
#[cfg(test)]
fn listen_port(line: &str, v6: bool, lease: Ipv4Addr) -> Option<u16> {
    let mut fields = line.split_whitespace();
    // `sl:` — the table's index column, always first.
    fields.next()?;
    let local = fields.next()?;
    // `rem_address`, then `st`.
    fields.next()?;
    if fields.next()? != "0A" {
        return None;
    }
    let (address, port) = local.rsplit_once(':')?;
    if !binds_for_the_lease(address, v6, lease) {
        return None;
    }
    u16::from_str_radix(port, 16).ok()
}

/// Whether a listening row's local address can answer the connection a
/// publication's forward makes. The forward dials `lease:port` — never
/// another address in the box's namespace — so only a socket bound to the
/// any address, which answers on every address the namespace holds, or to
/// the lease itself ever hears it. A socket bound anywhere else — the
/// box's loopback, the shape a dev server binds by default — would leave
/// the publication a phantom: the box's address accepting a connection
/// only for the dial to be refused at the lease, a reset in the place
/// NET-014 owes a refusal. Such a row is left unpublished, so nothing is
/// ever bound at the box's address for the port at all.
///
/// For a `tcp6` row the same rule reads the IPv4 address the v6 socket can
/// serve: the dual-stack any (`::`), which accepts IPv4 by mapping, or a
/// mapped address (`::ffff:a.b.c.d`) whose v4 part is the any or the lease.
/// A listener on any other v6 address cannot be reached at the box's IPv4
/// lease at all.
#[cfg(test)]
fn binds_for_the_lease(address: &str, v6: bool, lease: Ipv4Addr) -> bool {
    if !v6 {
        return match v4_word(address) {
            Some(bound) => bound.is_unspecified() || bound == lease,
            None => false,
        };
    }
    if address.len() != 32 {
        return false;
    }
    // The kernel prints each 32-bit word little-endian, so the mapped
    // marker reads `FFFF0000` and the dual-stack any as four zero words.
    if address.bytes().all(|b| b == b'0') {
        return true;
    }
    address.starts_with("0000000000000000FFFF0000")
        && match address.get(24..32).and_then(v4_word) {
            Some(bound) => bound.is_unspecified() || bound == lease,
            None => false,
        }
}

/// One word of the kernel's address column as the IPv4 address it names:
/// the table prints each 32-bit word little-endian — `127.0.0.1` reads
/// `0100007F` — so the eight hex digits are byte-swapped back into network
/// order. `None` for anything that is not exactly that.
#[cfg(test)]
fn v4_word(word: &str) -> Option<Ipv4Addr> {
    if word.len() != 8 || !word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(word, 16)
        .ok()
        .map(|word| Ipv4Addr::from(word.swap_bytes()))
}

/// The longest wait before a refused or unanswered listen notice is sent
/// again. The wait doubles from [`LISTEN_POLL_INTERVAL`] up to this bound.
const LISTEN_NOTICE_RETRY_MAX: Duration = Duration::from_secs(30);

/// The listen notices the in-VM daemon owes the VM host daemon for the
/// host-address boxes (NET-138): the diff of one read of the listening
/// ports at the node's address against the ports the host holds as
/// listening. A port moves into or out of that set only on a holding
/// answer from the host ([`Self::answered`]). A notice the host refused or
/// never answered stays owed, and is sent again after a per-port wait that
/// doubles up to [`LISTEN_NOTICE_RETRY_MAX`].
#[derive(Debug, Default)]
pub(crate) struct HostAddressListens {
    /// The ports the host answered a listening notice for and no stopped
    /// notice since.
    noticed: BTreeSet<u16>,
    /// The ports whose last listening notice the host did not hold, and no
    /// holding answer since. The host can still record such a port, for
    /// example as a collision, so a port here that stops listening owes a
    /// stopped notice too.
    refused: BTreeSet<u16>,
    /// Per port with a notice the host did not hold: when it is owed
    /// again, and the wait the next failure earns.
    retry: HashMap<u16, (std::time::Instant, Duration)>,
}

impl HostAddressListens {
    /// The notices owed at `at` to move the host's ports to `now`: one
    /// listening notice per new port and one stopped notice per closed
    /// port, held or refused, less each port still in its retry wait. It
    /// commits nothing.
    pub(crate) fn notices(
        &mut self,
        now: &BTreeSet<u16>,
        at: std::time::Instant,
    ) -> Vec<minimald_rpc::ListenNotice> {
        let stopped = self
            .noticed
            .union(&self.refused)
            .filter(|port| !now.contains(port))
            .map(|port| minimald_rpc::ListenNotice {
                port: *port,
                state: minimald_rpc::ListenState::Stopped,
            });
        let listening = now
            .difference(&self.noticed)
            .map(|port| minimald_rpc::ListenNotice {
                port: *port,
                state: minimald_rpc::ListenState::Listening,
            });
        let owed: Vec<_> = stopped.chain(listening).collect();
        // A port that owes nothing any more forgets its wait.
        self.retry
            .retain(|port, _| owed.iter().any(|notice| notice.port == *port));
        owed.into_iter()
            .filter(|notice| {
                self.retry
                    .get(&notice.port)
                    .is_none_or(|(due, _)| *due <= at)
            })
            .collect()
    }

    /// Records the host's answer to `notice` at `at`. `held` is whether
    /// the host holds the notice: a listening port is then the host's, and
    /// a stopped one is not. Any other answer leaves the port owed, and
    /// sends it again after its wait.
    pub(crate) fn answered(
        &mut self,
        notice: minimald_rpc::ListenNotice,
        held: bool,
        at: std::time::Instant,
    ) {
        if held {
            self.retry.remove(&notice.port);
            self.refused.remove(&notice.port);
            match notice.state {
                minimald_rpc::ListenState::Listening => self.noticed.insert(notice.port),
                minimald_rpc::ListenState::Stopped => self.noticed.remove(&notice.port),
            };
            return;
        }
        if notice.state == minimald_rpc::ListenState::Listening {
            self.refused.insert(notice.port);
        }
        let wait = self
            .retry
            .get(&notice.port)
            .map_or(LISTEN_POLL_INTERVAL, |(_, wait)| *wait);
        let next = (wait * 2).min(LISTEN_NOTICE_RETRY_MAX);
        self.retry.insert(notice.port, (at + wait, next));
    }
}

/// Tells the VM host which ports of the node's own address the boxes that
/// share it listen on, and when one stops, until `stop` is set. The VM
/// host publishes them under those boxes' names.
pub(crate) async fn watch_host_address_listens(
    door: Arc<dyn crate::net::door::HostDoor>,
    source: Arc<dyn Listeners>,
    lease: Ipv4Addr,
    mut stop: watch::Receiver<bool>,
) {
    let mut listens = HostAddressListens::default();
    while !*stop.borrow() {
        match source.listening() {
            Ok(listening) => {
                let ports: BTreeSet<u16> = super::listens::reachable_ports(&listening, lease)
                    .into_iter()
                    .collect();
                for notice in listens.notices(&ports, std::time::Instant::now()) {
                    let answer = door.listen_notice(notice).await;
                    if let Err(error) = &answer {
                        tracing::warn!(
                            port = notice.port,
                            state = ?notice.state,
                            reason = %error,
                            "the VM host did not take a listen notice of the node's address"
                        );
                    }
                    listens.answered(notice, answer.is_ok(), std::time::Instant::now());
                }
            }
            Err(error) => tracing::warn!(
                reason = %error,
                "could not read the listening sockets of the boxes at the node's address"
            ),
        }
        tokio::select! {
            () = source.changed() => {}
            () = tokio::time::sleep(LISTEN_REREAD) => {}
            changed = stop.changed() => if changed.is_err() { return; },
        }
    }
}

/// The listening sockets this test process holds that a forward to `lease`
/// could reach, standing in for the engine's record of a box's. It says
/// that something changed ten times a second, as the engine's reports
/// would.
#[cfg(test)]
pub(crate) fn held_by_this_process(lease: Ipv4Addr) -> Arc<dyn Listeners> {
    struct Held(Ipv4Addr);

    impl Listeners for Held {
        fn listening(&self) -> io::Result<Vec<super::listens::Listener>> {
            Ok(listening_ports_held_by(Path::new("/proc/self"), self.0)?
                .into_iter()
                .map(|port| super::listens::Listener {
                    address: std::net::IpAddr::V4(self.0),
                    port,
                })
                .collect())
        }

        fn changed(&self) -> futures::future::BoxFuture<'_, ()> {
            Box::pin(tokio::time::sleep(Duration::from_millis(100)))
        }
    }

    Arc::new(Held(lease))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use crate::net::SwitchSubnet;

    use super::*;

    fn held_here() -> Arc<dyn Listeners> {
        held_by_this_process(LEASE)
    }

    /// One request the fake forwarder served: the verb's path and the
    /// `local`/`remote`/`protocol` fields its body carried.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Served {
        path: String,
        local: String,
        remote: String,
        protocol: String,
    }

    /// The `name` field of a JSON request body, spelled as the serializer
    /// wrote it.
    fn field_of(body: &[u8], name: &str) -> String {
        let text = String::from_utf8_lossy(body);
        text.split(&format!("\"{name}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_string()
    }

    /// Reads one control request off `sock`: its head up to the end-of-head
    /// marker, then exactly its `Content-Length` body — the mirror of
    /// `post_json`'s keep-alive framing, so the fake forwarder never blocks
    /// reading past what the watcher sent. Returns the request's path and
    /// body.
    async fn read_request(sock: &mut UnixStream) -> (String, Vec<u8>) {
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
            assert!(n > 0, "the watcher closed before sending its head");
            buf.extend_from_slice(&scratch[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let path = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
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
            assert!(n > 0, "the watcher closed mid-body");
            buf.extend_from_slice(&scratch[..n]);
        }
        (path, buf[head_end..head_end + len].to_vec())
    }

    /// A gvproxy-shaped control channel at `path`: every request is read in
    /// full, answered with the status `decide` picks for it, and recorded as
    /// its verb, `local` and `remote`. The channel the real switch's
    /// forwarder verbs ride, with its binds recorded instead of performed —
    /// what the proofs here read is the request the watcher made, because
    /// the switch's behaviour is `policy`'s own to prove. The server ends
    /// when the test drops its receiver.
    fn spawn_forwarder_deciding(
        path: PathBuf,
        decide: impl Fn(&Served) -> u16 + Send + Sync + 'static,
    ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<Served>) {
        let listener = UnixListener::bind(&path).expect("the control socket binds");
        let (tx, rx) = mpsc::channel(64);
        let decide = std::sync::Arc::new(decide);
        let handle = crate::traced::spawn(async move {
            // Sequential on purpose: the watcher publishes and withdraws one
            // port at a time, awaited, so one connection served at a time is
            // its shape.
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (path, body) = read_request(&mut sock).await;
                let served = Served {
                    path,
                    local: field_of(&body, "local"),
                    remote: field_of(&body, "remote"),
                    protocol: field_of(&body, "protocol"),
                };
                let status = decide(&served);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                sock.write_all(
                    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                )
                .await
                .expect("the fake forwarder must answer");
                if tx.send(served).await.is_err() {
                    return;
                }
            }
        });
        (handle, rx)
    }

    /// [`spawn_forwarder_deciding`] for a forwarder that accepts everything
    /// — the shape every proof needs but the ones whose refusals are the
    /// point.
    fn spawn_forwarder(path: PathBuf) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<Served>) {
        spawn_forwarder_deciding(path, |_| 200)
    }

    /// A bound, listening TCP socket in this process — the stand-in for the
    /// server a box's process runs: the test's source reads this process's
    /// socket table, and the port is genuinely in it. Bound to the any
    /// address, the one bind a publication's dial can always reach at the
    /// box's lease, so the row is one the watcher publishes.
    fn listening_socket() -> TcpListener {
        TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
            .expect("an ephemeral port binds on the any address")
    }

    /// The port a bound listener holds.
    fn port_of(listener: &TcpListener) -> u16 {
        listener
            .local_addr()
            .expect("a bound socket has an address")
            .port()
    }

    /// A loopback-bound and an any-bound listener on adjacent ports, so a
    /// range spanning the two names exactly the ports this test holds:
    /// nothing another process bound elsewhere in the ephemeral range falls
    /// inside it, so no such listener can race this test's publication.
    /// Port `p + 1` is skipped when something else holds it and the next
    /// ephemeral pair is tried, a bounded number of times.
    fn adjacent_listeners() -> (TcpListener, TcpListener) {
        const ATTEMPTS: usize = 64;
        for _ in 0..ATTEMPTS {
            let loopback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("an ephemeral port binds on the loopback alone");
            let Some(next) = port_of(&loopback).checked_add(1) else {
                continue;
            };
            match TcpListener::bind((Ipv4Addr::UNSPECIFIED, next)) {
                Ok(any) => return (loopback, any),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(error) => panic!("binding the adjacent any-address listener failed: {error}"),
            }
        }
        panic!(
            "no adjacent loopback/any port pair after {ATTEMPTS} tries; the ephemeral range is crowded"
        );
    }

    /// Two any-bound listeners on adjacent ports, as [`adjacent_listeners`]
    /// pairs a loopback and an any bind: a range spanning the two names
    /// exactly the ports this test holds, so no listener another process
    /// bound elsewhere in the ephemeral range is published beside them.
    fn adjacent_any_listeners() -> (TcpListener, TcpListener) {
        const ATTEMPTS: usize = 64;
        for _ in 0..ATTEMPTS {
            let first = listening_socket();
            let Some(next) = port_of(&first).checked_add(1) else {
                continue;
            };
            match TcpListener::bind((Ipv4Addr::UNSPECIFIED, next)) {
                Ok(second) => return (first, second),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(error) => panic!("binding the adjacent any-address listener failed: {error}"),
            }
        }
        panic!(
            "no adjacent any/any port pair after {ATTEMPTS} tries; the ephemeral range is crowded"
        );
    }

    /// The box's lease on the test switch.
    const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    /// The box's published address (NET-010).
    const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 64, 0, 9);

    /// The box's ingress declaration: nothing statically mapped, a permit
    /// range covering exactly `port`, and the stance that lets listening
    /// publish (NET-016).
    fn permit_policy(port: u16) -> boxes::BoxPolicy {
        permit_range_policy(port, port)
    }

    /// [`permit_policy`] over `low..=high`, for a proof that holds every
    /// port in the range itself — so the range admits nothing it does not
    /// hold (see [`adjacent_any_listeners`]).
    fn permit_range_policy(low: u16, high: u16) -> boxes::BoxPolicy {
        boxes::BoxPolicy {
            ingress: Some(boxes::IngressPolicy {
                port_mappings: Vec::new(),
                dynamic_allowed_range: Some((low, high)),
                dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            }),
            egress: None,
            // No credentialed upstream (NET-134): these tests hold no lane,
            // so the compiled egress they observe is the rules' alone.
            credentialed_upstream: None,
        }
    }

    /// The box's watcher against the fake forwarder bound at `sock`, with
    /// its gate answering the given policy and the source the test names.
    /// The box's publication set is the watcher's alone here — no expose
    /// surface shares it in these proofs — so an empty one stands in for
    /// the set the launch would share.
    fn watcher_with(
        sock: PathBuf,
        policy: &boxes::BoxPolicy,
        source: Arc<dyn Listeners>,
    ) -> (ListenWatcher, Arc<IngressGate>) {
        let gate = crate::net::ingress_gate::IngressGate::detached(policy);
        let state_dir = state_dir_beside(&sock);
        let plan = ListenPlan::new(
            "listen-box".into(),
            LEASE,
            PUBLISHED,
            ControlChannel::Unix(sock),
            Arc::clone(&gate),
            BoxPublications::default(),
            state_dir,
            None,
            boxes::SessionId::nil(),
        );
        (ListenWatcher::start(plan, source), gate)
    }

    /// The state directory a test's watcher audits under: the test's own
    /// temporary directory, the one its fake forwarder's socket sits in, so
    /// each test reads only the decision records its own watcher wrote.
    fn state_dir_beside(sock: &Path) -> PathBuf {
        sock.parent()
            .expect("the forwarder's socket sits in the test's directory")
            .to_path_buf()
    }

    /// The box's watcher, reading this process's own listening sockets: the
    /// sockets the test binds are among them.
    fn watcher_at(sock: PathBuf, policy: &boxes::BoxPolicy) -> (ListenWatcher, Arc<IngressGate>) {
        watcher_with(sock, policy, held_here())
    }

    /// The box's watcher, started against a fake gvproxy control channel
    /// bound at a fresh socket, with its gate answering the given policy.
    /// Returns the watcher, the gate, and the fake's served-request
    /// receiver.
    fn started_watcher(
        dir: &tempfile::TempDir,
        policy: &boxes::BoxPolicy,
    ) -> (
        ListenWatcher,
        Arc<IngressGate>,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Served>,
    ) {
        let sock = dir.path().join("gvproxy.sock");
        let (server, served) = spawn_forwarder(sock.clone());
        let (watcher, gate) = watcher_at(sock, policy);
        (watcher, gate, server, served)
    }

    /// [`started_watcher`], with the box's publication set seeded by `seed`
    /// before the watcher starts — the way a launch hands its host the set
    /// already holding what the expose surface published.
    fn started_watcher_with_publications(
        dir: &tempfile::TempDir,
        policy: &boxes::BoxPolicy,
        seed: impl FnOnce(&BoxPublications),
    ) -> (
        ListenWatcher,
        Arc<IngressGate>,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Served>,
    ) {
        let sock = dir.path().join("gvproxy.sock");
        let (server, served) = spawn_forwarder(sock.clone());
        let publications = BoxPublications::default();
        seed(&publications);
        let gate = crate::net::ingress_gate::IngressGate::detached(policy);
        let plan = ListenPlan::new(
            "listen-box".into(),
            LEASE,
            PUBLISHED,
            ControlChannel::Unix(sock),
            Arc::clone(&gate),
            publications,
            dir.path().to_path_buf(),
            None,
            boxes::SessionId::nil(),
        );
        let watcher = ListenWatcher::start(plan, held_here());
        (watcher, gate, server, served)
    }

    /// Awaits the fake forwarder's next record, or fails the proof: nothing
    /// the watcher does should take past this bound — one poll interval for
    /// the work, and the bound is a person's patience, not the poll's.
    async fn next_served(served: &mut mpsc::Receiver<Served>) -> Served {
        tokio::time::timeout(Duration::from_secs(10), served.recv())
            .await
            .expect("the watcher acts within the bound")
            .expect("the fake forwarder stays alive")
    }

    /// Awaits `what` until it holds, or fails the proof: the fake serves
    /// its record *before* the watcher takes the step the proof reads next
    /// (the gate's admission follows the bind, the withdrawal's unexpose
    /// follows the refusal), so a served record alone does not order them.
    async fn soon(mut what: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !what() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the watcher did not reach the awaited state in the bound"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Every record the fake forwarder holds that the test has not read:
    /// called after the watcher has stopped, so the set is complete.
    fn drained(served: &mut mpsc::Receiver<Served>) -> Vec<Served> {
        let mut records = Vec::new();
        while let Ok(served) = served.try_recv() {
            records.push(served);
        }
        records
    }

    /// NET-016: a process in the box listens on a permitted port and the
    /// port is published — a forward bound at the box's own address, at the
    /// port the process listens on (NET-010: the same number on both sides,
    /// no translation), delivering to the box's lease at that same number —
    /// and admitted at the box's ingress gate, with no ingress declaration
    /// involved anywhere.
    #[tokio::test]
    async fn listen_publishes_permitted_port() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        assert!(
            !gate.admits_tcp(port),
            "nothing is published before the listener is seen"
        );
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        assert_eq!(
            published.remote,
            format!("{LEASE}:{port}"),
            "the port is published at its own number, delivered at its own number"
        );
        // The admission is the step after the bind the record names, so it
        // is awaited, not assumed: the gate admits a port only once
        // something answers for it.
        soon(|| gate.admits_tcp(port)).await;

        // The stop withdraws what it published: the port's publication ends
        // with the watcher, exactly as the story ends it with the box.
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// NET-016, the declaration's transport: a mapping named for UDP answers
    /// UDP alone, so a TCP listener on a port the declaration names on UDP
    /// only is not published already — the verdict reads the transport
    /// before it answers `Declared`, and a box whose rules permit the port
    /// publishes the TCP listener, bound for the protocol the listener
    /// holds. The shape a transport-blind `Declared` answered wrong: the
    /// UDP mapping's forward never answers a TCP dial, so holding the
    /// listener back would leave the server unreachable at the box's
    /// address on TCP whatever the rules said.
    #[tokio::test]
    async fn listen_publishes_a_tcp_port_the_declaration_names_only_on_udp() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        // The declaration maps the port for UDP alone, while the range and
        // the stance permit it: the TCP listener must fall to the rules and
        // be published by them, not answered "published already" under a
        // forward that would never answer its protocol.
        let policy = boxes::BoxPolicy {
            ingress: Some(boxes::IngressPolicy {
                port_mappings: vec![boxes::PortMapping {
                    external_port: port,
                    internal_port: port,
                    proto: boxes::IpProto::Udp,
                }],
                dynamic_allowed_range: Some((port, port)),
                dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            }),
            egress: None,
            credentialed_upstream: None,
        };
        let (watcher, gate, server, mut served) = started_watcher(&dir, &policy);

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(
            published.protocol, "tcp",
            "the publication is bound for the transport the listener holds"
        );
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        assert_eq!(published.remote, format!("{LEASE}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // The stop withdraws it like any runtime-published port: the
        // declaration's UDP forward is not the watcher's and never comes
        // down this path (NET-081's sub-requirement).
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.protocol, "tcp");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        server.abort();
    }

    /// NET-016's sub-requirement: a listener on a port the rules do not
    /// permit is never published — no forward, no admission — while a
    /// permitted listener beside it publishes, so the proof's silence is
    /// the watcher's own decision and not a loop that never ran.
    #[tokio::test]
    async fn listen_on_undeclared_port_not_published() {
        let permitted = listening_socket();
        let port = port_of(&permitted);
        let declined = listening_socket();
        let other = port_of(&declined);
        assert_ne!(port, other, "two bound sockets hold two ports");
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        // The permitted listener publishes: this is the control that the
        // poll ran and read both sockets.
        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;
        assert!(
            !gate.admits_tcp(other),
            "a port the rules do not permit is never admitted"
        );

        // The other listener, seen in the same poll, publishes nothing: no
        // request ever names it — across the stop's own withdrawal too, so
        // the silence is the watcher's decision and not a drained record.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records
                .iter()
                .all(|served| served.local != format!("{PUBLISHED}:{other}")),
            "no request ever names the port the rules do not permit: {records:?}"
        );
        server.abort();
    }

    /// The watcher lives as long as the box, so it runs in a root span of
    /// its own and the span it was started in (the host launch's message)
    /// closes when the launch is done, while the watcher runs on.
    #[tokio::test]
    async fn a_watcher_does_not_hold_its_launch_span_open() {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::registry::LookupSpan as _;
        // Layered: a bare `Registry` never frees a closed span's slot (the
        // close is `Layered::try_close`'s), so every span would read open.
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(tracing_subscriber::layer::Identity::new()),
        );
        let is_open = |id: &tracing::Id| {
            tracing::dispatcher::get_default(|d| {
                d.downcast_ref::<tracing_subscriber::Registry>()
                    .unwrap()
                    .span(id)
                    .is_some()
            })
        };
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        let (server, _served) = spawn_forwarder(sock.clone());
        let gate = crate::net::ingress_gate::IngressGate::detached(&permit_policy(1));
        let state_dir = state_dir_beside(&sock);
        let plan = ListenPlan::new(
            "listen-box".into(),
            LEASE,
            PUBLISHED,
            ControlChannel::Unix(sock),
            gate,
            BoxPublications::default(),
            state_dir,
            None,
            boxes::SessionId::nil(),
        );
        let launch = tracing::info_span!("session.host.message");
        let launch_id = launch.id().unwrap();
        let watcher = launch.in_scope(|| ListenWatcher::start(plan, held_here()));
        drop(launch);
        tokio::task::yield_now().await;
        assert!(
            !is_open(&launch_id),
            "the launch's span closed while the watcher runs"
        );
        watcher.stop().await;
        server.abort();
    }

    /// NET-017: the listener closes and the port's publication is withdrawn
    /// — the forward comes down, the gate stops admitting — and a fresh
    /// listener on the same port (the restart every server makes) is
    /// published again.
    #[tokio::test]
    async fn listener_close_withdraws_publication() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes. The next poll sees the port gone and
        // withdraws the publication.
        drop(listener);
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(
            !gate.admits_tcp(port),
            "the port's admission went with its listener"
        );

        // A fresh listener on the same port publishes it again: the
        // withdrawal held nothing back.
        let restarted = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("a closed listener leaves its port free to rebind");
        let republished = next_served(&mut served).await;
        assert_eq!(republished.path, "/services/forwarder/expose");
        assert_eq!(republished.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        drop(restarted);
        watcher.stop().await;
        let last = next_served(&mut served).await;
        assert_eq!(last.path, "/services/forwarder/unexpose");
        server.abort();
    }

    /// NET-044: an in-range listen under `allow` is a dynamic ingress request
    /// the box's stance decided, so its publication is listed — one row at
    /// the box's address, at the listener's own port, reachable — for as long
    /// as the listener holds the port, and the row goes when the listener
    /// closes.
    #[tokio::test]
    async fn a_listen_publication_is_listed_until_its_listener_closes() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let mut shared = None;
        let (watcher, gate, server, mut served) =
            started_watcher_with_publications(&dir, &permit_policy(port), |publications| {
                shared = Some(publications.clone());
            });
        let publications = shared.expect("the seed hands back the box's set");

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;
        assert_eq!(
            publications.listen_rows(),
            vec![minimald_rpc::LiveMapping {
                local: format!("{PUBLISHED}:{port}"),
                internal_port: port,
                proto: IpProto::Tcp,
                pending: Some(false),
            }],
            "the published listen is listed as the box's live ingress"
        );

        drop(listener);
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        soon(|| publications.listen_rows().is_empty()).await;

        watcher.stop().await;
        server.abort();
    }

    /// NET-046: each listen the watcher publishes leaves one decision record
    /// in the local audit log — the box, the port, the `allow` its stance
    /// made, decided by the box's own policy, outcome published — and a
    /// listen it does not publish leaves none.
    #[tokio::test]
    async fn a_listen_publication_is_audited() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        next_served(&mut served).await;
        soon(|| gate.admits_tcp(port)).await;
        // The record is the publish's last step, inside the poll that
        // admitted the port, and the stop is taken only between polls: once
        // the stop returns, the record is on disk.
        watcher.stop().await;
        server.abort();
        drop(listener);

        let text = tokio::fs::read_to_string(crate::audit::log_path(dir.path()))
            .await
            .expect("the audit log was written");
        let records: Vec<serde_json_lenient::Value> = text
            .lines()
            .map(|line| serde_json_lenient::from_str(line).expect("each line is one JSON record"))
            .collect();
        assert_eq!(records.len(), 1, "one publish, one record: {text}");
        let record = &records[0];
        assert_eq!(record["box"], "listen-box");
        assert_eq!(record["port"], port);
        assert_eq!(record["decision"], "allow");
        assert_eq!(record["decided_by"], "box-policy");
        assert_eq!(record["outcome"], "published");
        assert!(record.get("reason").is_none(), "{record}");
    }

    /// NET-046's other half, for the watcher: a listen the rules leave
    /// unpublished was no allowed request, and writes no record.
    #[tokio::test]
    async fn an_unpublished_listen_is_not_audited() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        // A range that does not cover the listener: the verdict is `Deny`.
        let other = if port == u16::MAX { port - 1 } else { port + 1 };
        let (watcher, _gate, server, _served) = started_watcher(&dir, &permit_policy(other));
        tokio::time::sleep(LISTEN_POLL_INTERVAL * 3).await;
        watcher.stop().await;
        server.abort();
        drop(listener);
        assert!(
            !tokio::fs::try_exists(crate::audit::log_path(dir.path()))
                .await
                .expect("the test's directory reads"),
            "a listen nothing published leaves no decision record"
        );
    }

    /// The decision records the test's watcher appended under `dir`, one
    /// JSON value per line, in the order written — none while the log does
    /// not exist yet.
    fn audit_records(dir: &Path) -> Vec<serde_json_lenient::Value> {
        let text = std::fs::read_to_string(crate::audit::log_path(dir)).unwrap_or_default();
        text.lines()
            .map(|line| serde_json_lenient::from_str(line).expect("each line is one JSON record"))
            .collect()
    }

    /// A listen row reads reachable, so it is the last thing a publish makes
    /// visible: at the moment the gate admits the port, the set lists
    /// nothing for it, and the row stands only once the admission is done.
    /// A reservation a revocation cleared under the bind lists nothing at
    /// all, admission or not.
    #[test]
    fn a_listen_row_is_listed_only_after_its_admission() {
        let publications = BoxPublications::default();
        let row = |port: u16| minimald_rpc::LiveMapping {
            local: format!("{PUBLISHED}:{port}"),
            internal_port: port,
            proto: IpProto::Tcp,
            pending: Some(false),
        };

        let reservation = publications
            .reserve(8080, PublicationOwner::Listen)
            .expect("nothing holds the port yet");
        let mut listed_at_admission = None;
        assert!(
            admit_then_list(reservation, row(8080), || {
                listed_at_admission = Some(publications.listen_rows());
            }),
            "nothing revoked the reservation"
        );
        assert_eq!(
            listed_at_admission,
            Some(Vec::new()),
            "no row is listed while the gate is still admitting the port"
        );
        assert_eq!(
            publications.listen_rows(),
            vec![row(8080)],
            "the row stands once the admission is done"
        );

        // A revocation clears the set under the next bind: the admission the
        // publish made is the caller's to take back, and nothing is listed.
        let reservation = publications
            .reserve(8081, PublicationOwner::Listen)
            .expect("nothing holds the port yet");
        publications.revoke_all();
        let mut admitted = false;
        assert!(
            !admit_then_list(reservation, row(8081), || admitted = true),
            "a revoked reservation does not commit"
        );
        assert!(admitted, "the gate was asked before the commit was tried");
        assert!(
            publications.listen_rows().is_empty(),
            "a revoked publish lists nothing"
        );
    }

    /// NET-046 for a publish the switch refuses: the box's `allow` decided
    /// the listen, so the refusal writes one record — decision `allow`,
    /// outcome `publish-failed`, the failure's own text as reason — on the
    /// streak's first refusal only. The backoff's retries are the same
    /// decision waited out and write nothing; the retry that binds writes
    /// the normal `published` record. No row is listed and nothing is
    /// admitted while the bind keeps failing.
    #[tokio::test]
    async fn a_refused_listen_publish_is_audited_once_per_streak() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        let refusing = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&refusing);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose") && flag.load(Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let publications = BoxPublications::default();
        let gate = crate::net::ingress_gate::IngressGate::detached(&permit_policy(port));
        let watcher = ListenWatcher::start(
            ListenPlan::new(
                "listen-box".into(),
                LEASE,
                PUBLISHED,
                ControlChannel::Unix(sock),
                Arc::clone(&gate),
                publications.clone(),
                dir.path().to_path_buf(),
                None,
                boxes::SessionId::nil(),
            ),
            held_here(),
        );

        // Three refused attempts: the first and two backoff retries.
        for _ in 0..3 {
            let attempt = next_served(&mut served).await;
            assert_eq!(attempt.path, "/services/forwarder/expose");
            assert!(
                publications.listen_rows().is_empty(),
                "a refused publish lists nothing"
            );
            assert!(!gate.admits_tcp(port), "a refused publish admits nothing");
        }
        // The third refusal's record, if it wrongly wrote one, follows its
        // served request: give it the moment it would take.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let records = audit_records(dir.path());
        assert_eq!(
            records.len(),
            1,
            "one record for the streak, none for its retries: {records:?}"
        );
        let refused = &records[0];
        assert_eq!(refused["box"], "listen-box");
        assert_eq!(refused["port"], port);
        assert_eq!(refused["decision"], "allow");
        assert_eq!(refused["decided_by"], "box-policy");
        assert_eq!(refused["outcome"], "publish-failed");
        assert!(
            refused["reason"].as_str().is_some_and(|r| !r.is_empty()),
            "the record carries the bind failure's reason: {refused}"
        );

        // The forwarder accepts: the retry binds, admits, lists, and writes
        // the publish's own record.
        refusing.store(false, Ordering::SeqCst);
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| audit_records(dir.path()).len() == 2).await;
        assert!(gate.admits_tcp(port));
        assert_eq!(publications.listen_rows().len(), 1);
        let records = audit_records(dir.path());
        assert_eq!(records[1]["port"], port);
        assert_eq!(records[1]["decision"], "allow");
        assert_eq!(records[1]["outcome"], "published");
        assert!(records[1].get("reason").is_none(), "{}", records[1]);

        watcher.stop().await;
        server.abort();
        drop(listener);
        assert_eq!(
            audit_records(dir.path()).len(),
            2,
            "the streak's refusal and its publish, nothing else"
        );
    }

    /// NET-046 fails closed for the watcher's own publish: a listen the
    /// rules permit, whose `Published` record the audit log refuses, is
    /// unwound — the forward unexposed, the row and the admission gone —
    /// rather than published unaudited, and the port stays refused while
    /// the log keeps refusing. The unwind whose unexpose fails holds the
    /// forward and its `unrecorded` mark together, so the next poll
    /// re-reaches the record retry rather than a fresh bind: the retry
    /// that finds the log writable again writes the record, admits the
    /// forward the whole streak held and settles — nothing outlives the
    /// failure but the backoff.
    #[tokio::test]
    async fn a_listen_publish_that_cannot_be_audited_is_unwound_and_refused() {
        let (lines, _guard) = captured_lines();
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        // The planted link the audit log refuses to write through: the
        // append opens the state dir's own `audit` with `O_NOFOLLOW`, so a
        // directory symlink fails the open and the record cannot be
        // written — before any append has created the real directory.
        let planted = dir.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        std::os::unix::fs::symlink(&planted, dir.path().join("audit")).unwrap();
        // The forwarder refuses the unwind's unexpose — the shape of a
        // forwarder mid-restart — so the forward the audit refused stays
        // standing, held with its `unrecorded` mark for the retry.
        let refusing_unexpose = Arc::new(AtomicBool::new(true));
        let unexpose_flag = Arc::clone(&refusing_unexpose);
        let sock = dir.path().join("gvproxy.sock");
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && unexpose_flag.load(Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // The bind stood — the forwarder served the expose — and the
        // record's failure unwound it in the same poll; the unexpose
        // failed, so the forward stays standing, refused and unrecorded.
        let bound = next_served(&mut served).await;
        assert_eq!(bound.path, "/services/forwarder/expose");
        assert_eq!(bound.local, format!("{PUBLISHED}:{port}"));
        let unwound = next_served(&mut served).await;
        assert_eq!(unwound.path, "/services/forwarder/unexpose");
        assert_eq!(unwound.local, format!("{PUBLISHED}:{port}"));
        soon(|| !gate.admits_tcp(port)).await;
        // The unexpose the forwarder refused and its one-time line land
        // in the same poll the gate's withdrawal did; the warn is the
        // forward's own record of what still stands, so the proof reads
        // it once the poll has written it.
        soon(|| {
            lines_saying(
                &lines.contents(),
                "unpublishing a listening port on the switch failed",
            )
            .len()
                == 1
        })
        .await;
        assert!(
            audit_records(dir.path()).is_empty(),
            "no record was written for the unwound publish"
        );
        assert!(
            !planted.join("decisions.log").exists(),
            "the planted link's target is untouched"
        );
        let log = lines.contents();
        assert_eq!(
            lines_saying(&log, "could not be audited; the publish unwound").len(),
            1,
            "the unwind is said once, for the streak's first refusal: {log}"
        );
        assert_eq!(
            lines_saying(&log, "unpublishing a listening port on the switch failed").len(),
            1,
            "the failed unexpose is said once, not once per retry: {log}"
        );

        // The listener still holds the port and the forward still stands,
        // so once the log takes records again the next retry writes the
        // record through the re-admit the mark holds — no second bind, the
        // forward the streak held is the published one — and settles.
        std::fs::remove_file(dir.path().join("audit")).unwrap();
        refusing_unexpose.store(false, Ordering::SeqCst);
        soon(|| gate.admits_tcp(port)).await;
        assert!(
            served.try_recv().is_err(),
            "the standing forward is re-admitted, never bound a second time"
        );
        let records = audit_records(dir.path());
        assert_eq!(records.len(), 1, "the settled publish wrote its record");
        assert_eq!(records[0]["port"], port);
        assert_eq!(records[0]["decision"], "allow");
        assert_eq!(records[0]["outcome"], "published");

        // The publication is the watcher's to withdraw like any other,
        // and the close that ends it writes no second record.
        drop(listener);
        let closed = next_served(&mut served).await;
        assert_eq!(closed.path, "/services/forwarder/unexpose");
        soon(|| !gate.admits_tcp(port)).await;
        watcher.stop().await;
        server.abort();
        assert_eq!(
            audit_records(dir.path()).len(),
            1,
            "the record the retry wrote is the publication's whole audit: {:?}",
            audit_records(dir.path())
        );
    }

    /// NET-129 holds an unaudited forward to the fresh publish's record: a
    /// forward whose allow could not be audited and whose unwind's unexpose
    /// failed stands refused but still occupies the port, so the box holds
    /// it of record; the retry that writes the record re-admits it with the
    /// hold standing, so a declared publish of the port yields to it. The
    /// close releases the hold.
    #[tokio::test]
    async fn a_re_admitted_unaudited_forward_records_its_dynamic_hold() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        std::os::unix::fs::symlink(&planted, dir.path().join("audit")).unwrap();
        let refusing_unexpose = Arc::new(AtomicBool::new(true));
        let unexpose_flag = Arc::clone(&refusing_unexpose);
        let sock = dir.path().join("gvproxy.sock");
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && unexpose_flag.load(Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let gate = crate::net::ingress_gate::IngressGate::detached(&permit_policy(port));
        let registry = Arc::new(RwLock::new(crate::net::dns::HostnameRegistry::new(
            "dev", false,
        )));
        let holder = boxes::SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let declared = boxes::SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let watcher = ListenWatcher::start(
            ListenPlan::new(
                "listen-box".into(),
                LEASE,
                PUBLISHED,
                ControlChannel::Unix(sock),
                Arc::clone(&gate),
                BoxPublications::default(),
                dir.path().to_path_buf(),
                Some(Arc::clone(&registry)),
                holder,
            ),
            held_here(),
        );

        // Bound, unwound for the audit, and the unwind's unexpose refused:
        // the forward stands refused, and because it still occupies the
        // box's published address:port the box holds the port of record.
        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/expose"
        );
        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/unexpose"
        );
        soon(|| registry.read().unwrap().shared_port_holder(PUBLISHED, port) == Some(holder)).await;
        assert!(
            !gate.admits_tcp(port),
            "the unaudited forward stays refused"
        );

        // The log heals: the retry re-admits the standing forward and the
        // hold stands through it, so a declared publish of the port yields.
        std::fs::remove_file(dir.path().join("audit")).unwrap();
        refusing_unexpose.store(false, Ordering::SeqCst);
        soon(|| gate.admits_tcp(port)).await;
        assert!(
            registry.read().unwrap().shared_port_holder(PUBLISHED, port) == Some(holder),
            "the re-admitted forward's box holds its port of record"
        );
        let collisions = registry.write().unwrap().publish_own_address(
            declared,
            "declared",
            PUBLISHED,
            BTreeSet::from([port]),
        );
        assert_eq!(
            collisions.iter().map(|c| c.port).collect::<Vec<_>>(),
            vec![port],
            "the declared publish yields to the re-admitted forward's hold"
        );

        // The listener closes: the hold passes to the declared publisher.
        drop(listener);
        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/unexpose"
        );
        soon(|| {
            registry
                .read()
                .unwrap()
                .holds_shared_port(declared, PUBLISHED, port)
        })
        .await;
        watcher.stop().await;
        server.abort();
    }

    /// A watcher publishing `port` under `holder` into `registry`, against
    /// a forwarder that accepts everything and an audit log that takes
    /// every record — the fresh publish's whole happy path (NET-129).
    fn watcher_recording_into(
        dir: &tempfile::TempDir,
        port: u16,
        registry: &Arc<RwLock<crate::net::dns::HostnameRegistry>>,
        holder: boxes::SessionId,
    ) -> (
        ListenWatcher,
        tokio::task::JoinHandle<()>,
        mpsc::Receiver<Served>,
    ) {
        let sock = dir.path().join("gvproxy.sock");
        let (server, served) = spawn_forwarder(sock.clone());
        let gate = crate::net::ingress_gate::IngressGate::detached(&permit_policy(port));
        let watcher = ListenWatcher::start(
            ListenPlan::new(
                "listen-box".into(),
                LEASE,
                PUBLISHED,
                ControlChannel::Unix(sock),
                gate,
                BoxPublications::default(),
                dir.path().to_path_buf(),
                Some(Arc::clone(registry)),
                holder,
            ),
            held_here(),
        );
        (watcher, server, served)
    }

    /// NET-129's fresh publish: a port the box's process listens on is
    /// published and recorded as the box's to hold at its published address,
    /// so a declared publish of the port yields to it; the listener's close
    /// releases the hold and hands the port to the declared publisher.
    #[tokio::test]
    async fn a_fresh_listen_publish_records_its_hold_and_the_close_hands_it_over() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(RwLock::new(crate::net::dns::HostnameRegistry::new(
            "dev", false,
        )));
        let holder = boxes::SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let declared = boxes::SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let (watcher, server, mut served) = watcher_recording_into(&dir, port, &registry, holder);

        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/expose"
        );
        soon(|| registry.read().unwrap().shared_port_holder(PUBLISHED, port) == Some(holder)).await;
        let collisions = registry.write().unwrap().publish_own_address(
            declared,
            "declared",
            PUBLISHED,
            BTreeSet::from([port]),
        );
        assert_eq!(
            collisions.iter().map(|c| c.port).collect::<Vec<_>>(),
            vec![port],
            "the declared publish yields to the listen-published port's hold"
        );

        drop(listener);
        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/unexpose"
        );
        soon(|| {
            registry
                .read()
                .unwrap()
                .holds_shared_port(declared, PUBLISHED, port)
        })
        .await;
        watcher.stop().await;
        server.abort();
    }

    /// NET-129 on the stop path: the box stopping withdraws every forward
    /// its watcher holds, and each withdrawal releases the port's hold, so a
    /// declared publisher waiting on the port takes it — the stop leaves no
    /// hold behind the forward it took down.
    #[tokio::test]
    async fn the_watchers_stop_hands_its_listen_holds_over() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(RwLock::new(crate::net::dns::HostnameRegistry::new(
            "dev", false,
        )));
        let holder = boxes::SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let declared = boxes::SessionId::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let (watcher, server, mut served) = watcher_recording_into(&dir, port, &registry, holder);

        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/expose"
        );
        soon(|| registry.read().unwrap().shared_port_holder(PUBLISHED, port) == Some(holder)).await;
        let collisions = registry.write().unwrap().publish_own_address(
            declared,
            "declared",
            PUBLISHED,
            BTreeSet::from([port]),
        );
        assert_eq!(
            collisions.iter().map(|c| c.port).collect::<Vec<_>>(),
            vec![port]
        );

        // The listener is still open: only the stop takes the forward down.
        watcher.stop().await;
        assert_eq!(
            next_served(&mut served).await.path,
            "/services/forwarder/unexpose"
        );
        assert!(
            registry
                .read()
                .unwrap()
                .holds_shared_port(declared, PUBLISHED, port),
            "the stop hands the listen-held port to the declared publisher"
        );
        drop(listener);
        server.abort();
    }

    /// NET-046's common unwind: the listen whose `Published` record the log
    /// refuses is bound, never admitted, and unexposed again — the switch
    /// takes the forward down, so the box's publication set lists nothing
    /// and the gate never let a connection through. The port stays owed:
    /// once the log takes records again the next retry binds afresh,
    /// writes the record, and only then admits the port.
    #[tokio::test]
    async fn an_unauditable_listen_publish_is_never_admitted_and_publishes_afresh_once_healed() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        // The same planted link as above: the append refuses to open the
        // state dir's `audit` through a symlink.
        let planted = dir.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        std::os::unix::fs::symlink(&planted, dir.path().join("audit")).unwrap();
        let mut shared = None;
        let (watcher, gate, server, mut served) =
            started_watcher_with_publications(&dir, &permit_policy(port), |seed| {
                shared = Some(seed.clone());
            });
        let publications = shared.expect("the seed hands over the watcher's set");
        // A sampler that reads the gate the whole time the log refuses: an
        // admission that stood even for the audit write's length is seen.
        let ever_admitted = Arc::new(AtomicBool::new(false));
        let sampling = Arc::new(AtomicBool::new(true));
        let sampler = {
            let gate = Arc::clone(&gate);
            let ever_admitted = Arc::clone(&ever_admitted);
            let sampling = Arc::clone(&sampling);
            crate::traced::spawn(async move {
                while sampling.load(Ordering::SeqCst) {
                    if gate.admits_tcp(port) {
                        ever_admitted.store(true, Ordering::SeqCst);
                    }
                    tokio::task::yield_now().await;
                }
            })
        };

        let bound = next_served(&mut served).await;
        assert_eq!(bound.path, "/services/forwarder/expose");
        let unwound = next_served(&mut served).await;
        assert_eq!(unwound.path, "/services/forwarder/unexpose");
        assert_eq!(unwound.local, format!("{PUBLISHED}:{port}"));
        sampling.store(false, Ordering::SeqCst);
        sampler.await.unwrap();
        assert!(
            !ever_admitted.load(Ordering::SeqCst),
            "a publish whose record the log refused is never admitted at the gate"
        );
        assert!(!gate.admits_tcp(port));
        // The unwind gives the row back after the switch answered the
        // unexpose, so the set is read once the unwind has run.
        soon(|| publications.listen_rows().is_empty()).await;
        assert!(
            audit_records(dir.path()).is_empty(),
            "no record was written through the planted link"
        );
        // The failure is not silent: the set `min session policy` reads
        // names the permitted port the audit log kept unpublished.
        soon(|| publications.audit_refused() == vec![port]).await;

        // The log heals: the port is still owed, so the backoff's retry
        // binds afresh, records the allow, and admits it.
        std::fs::remove_file(dir.path().join("audit")).unwrap();
        let rebound = next_served(&mut served).await;
        assert_eq!(rebound.path, "/services/forwarder/expose");
        assert_eq!(rebound.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;
        // The streak writes at most one `publish_failed` — its first
        // refusal's, best-effort, which the refusing log may have dropped —
        // and the retries the backoff made wrote none; the publication's
        // `published` record is the healed publish's own.
        let records = audit_records(dir.path());
        let failed = records
            .iter()
            .filter(|record| record["outcome"] == "publish_failed")
            .count();
        assert!(
            failed <= 1,
            "one publish_failed record per streak at most: {records:?}"
        );
        let published: Vec<_> = records
            .iter()
            .filter(|record| record["outcome"] == "published")
            .collect();
        assert_eq!(published.len(), 1, "the healed publish wrote its record");
        assert_eq!(published[0]["port"], port);
        assert_eq!(publications.listen_rows().len(), 1);
        assert!(
            publications.audit_refused().is_empty(),
            "the healed publish clears the policy warning"
        );

        drop(listener);
        watcher.stop().await;
        server.abort();
    }

    /// A port the box's declaration names is the declaration's: the box
    /// listening on it gets no listen row and no listen decision record,
    /// and the watcher asks the switch for nothing.
    #[tokio::test]
    async fn a_declared_port_is_never_listed_or_audited_by_the_watcher() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let policy = boxes::BoxPolicy {
            ingress: Some(boxes::IngressPolicy {
                port_mappings: vec![boxes::PortMapping {
                    external_port: port,
                    internal_port: port,
                    proto: boxes::IpProto::Tcp,
                }],
                dynamic_allowed_range: Some((port, port)),
                dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            }),
            egress: None,
            credentialed_upstream: None,
        };
        let mut shared = None;
        let (watcher, _gate, server, mut served) =
            started_watcher_with_publications(&dir, &policy, |publications| {
                shared = Some(publications.clone());
            });
        let publications = shared.expect("the seed hands back the box's set");

        tokio::time::sleep(LISTEN_POLL_INTERVAL * 3).await;
        assert!(publications.listen_rows().is_empty());
        drop(listener);
        tokio::time::sleep(LISTEN_POLL_INTERVAL * 3).await;
        watcher.stop().await;
        server.abort();
        assert!(
            publications.listen_rows().is_empty(),
            "a declared port is never a listen row"
        );
        assert!(
            drained(&mut served).is_empty(),
            "the watcher asked the switch nothing"
        );
        assert!(
            audit_records(dir.path()).is_empty(),
            "a declared port writes no listen decision record"
        );
    }

    /// A publication whose bind failed is not consumed by the failure: the
    /// next poll sees the port still unpublished — a transient refusal on
    /// the control channel must not leave a permitted port unpublished
    /// until its server restarts — and the retry that binds admits the
    /// port, so the failure cost only the moment between the two requests.
    #[tokio::test]
    async fn a_failed_publish_is_retried_on_the_next_poll() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first expose — the shape of a
        // forwarder mid-restart, or a bind not free yet — and accepts every
        // request after it.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // The first poll's expose is refused: nothing is published and
        // nothing is admitted.
        let first = next_served(&mut served).await;
        assert_eq!(first.path, "/services/forwarder/expose");
        assert_eq!(first.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));

        // A later poll asks for the same port again — the appearance the
        // failure could not settle — and the retry binds and admits.
        let retried = next_served(&mut served).await;
        assert_eq!(
            retried,
            Served {
                path: "/services/forwarder/expose".into(),
                local: format!("{PUBLISHED}:{port}"),
                remote: format!("{LEASE}:{port}"),
                protocol: "tcp".into(),
            },
            "the retry is the same publication the refusal turned away"
        );
        soon(|| gate.admits_tcp(port)).await;

        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        server.abort();
    }

    /// A withdrawal whose unexpose failed is not abandoned by the stop: the
    /// stop retries it before it returns, so no forward a box's processes
    /// published by listening outlives the box — a stale forward would hold
    /// the box's published address:port against a future session there.
    #[tokio::test]
    async fn a_failed_withdrawal_is_retried_before_the_stop_returns() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first unexpose — the stop's first
        // pass — and accepts every request after it, the retry included.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        // The stop refuses to return with the forward still standing: the
        // refused withdrawal is retried inside it and comes down.
        watcher.stop().await;
        let records = drained(&mut served);
        let withdrawals: Vec<&Served> = records
            .iter()
            .filter(|served| served.path == "/services/forwarder/unexpose")
            .collect();
        assert_eq!(
            withdrawals.len(),
            2,
            "the refused withdrawal was retried before the stop returned: {records:?}"
        );
        assert!(
            withdrawals
                .iter()
                .all(|served| served.local == format!("{PUBLISHED}:{port}")),
            "both passes named the same publication: {records:?}"
        );
        assert!(!gate.admits_tcp(port), "the publication ended with the box");
        server.abort();
    }

    /// A listener bound to the box's loopback alone is never published,
    /// whatever the rules permit: a publication's forward dials the box's
    /// lease, which such a bind never answers, so publishing it would bind
    /// a forward to nothing — the box's address accepting a connection only
    /// to have it refused at the lease. The port the rules permit beside it
    /// publishes, which is the control that the poll ran and read both
    /// sockets and chose between them.
    #[tokio::test]
    async fn a_loopback_bound_listener_is_not_published() {
        let (loopback, any) = adjacent_listeners();
        let loop_port = port_of(&loopback);
        let any_port = port_of(&any);
        let dir = tempfile::tempdir().unwrap();
        // The rules permit both ports: only the binds differ.
        let policy = boxes::BoxPolicy {
            ingress: Some(boxes::IngressPolicy {
                port_mappings: Vec::new(),
                dynamic_allowed_range: Some((loop_port.min(any_port), loop_port.max(any_port))),
                dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            }),
            egress: None,
            credentialed_upstream: None,
        };
        let (watcher, gate, server, mut served) = started_watcher(&dir, &policy);

        // The any-bound listener publishes: the poll ran, read both rows,
        // and it is the loopback bind alone that made the other unpublished.
        let published = next_served(&mut served).await;
        assert_eq!(published.local, format!("{PUBLISHED}:{any_port}"));
        soon(|| gate.admits_tcp(any_port)).await;
        assert!(
            !gate.admits_tcp(loop_port),
            "a bind the forward's dial cannot reach is never admitted"
        );

        // No request ever names the loopback port — across the stop's own
        // withdrawal too, so the silence is the watcher's decision and not a
        // record the test drained early.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records
                .iter()
                .all(|served| served.local != format!("{PUBLISHED}:{loop_port}")),
            "no request ever names the loopback-bound port: {records:?}"
        );
        server.abort();
    }

    /// A listener that returns while its withdrawal had failed finds the
    /// forward it never lost: the publication never came down, so it is
    /// re-admitted rather than re-bound — the switch still holds the first
    /// forward, and a second expose against that bind would fail every poll
    /// the port's rules permit. The withdrawal it still owes is asked for
    /// again while the box runs, and the stop that ends the watcher tries
    /// the forward down too, bounded, never hanging on a channel that
    /// refuses every unexpose — so how many unexposes were made is not a
    /// number this proof can fix, only that they never stopped.
    #[tokio::test]
    async fn a_listener_back_before_its_failed_withdrawal_keeps_the_publication() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder accepts every expose and refuses every unexpose: a
        // switch whose unbind verb is failing outright.
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), |served| {
            if served.path.ends_with("/unexpose") {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // Every request the watcher made: the awaited ones kept beside the
        // ones the stop's teardown leaves unread, so the counts below read
        // the whole exchange and not a tail of it.
        let mut requests = Vec::new();
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        requests.push(published);
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes and the withdrawal is refused: the record is
        // awaited, not assumed, so the rebind below cannot race the poll
        // that has to see the closure first.
        drop(listener);
        let refused = next_served(&mut served).await;
        assert_eq!(refused.path, "/services/forwarder/unexpose");
        requests.push(refused);
        soon(|| !gate.admits_tcp(port)).await;

        // The listener returns on the same port. The forward never came
        // down, so the publication it still holds serves the port again —
        // re-admitted, with no second bind asked of the switch.
        let restarted = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("a closed listener leaves its port free to rebind");
        soon(|| gate.admits_tcp(port)).await;

        // The stop tries the never-withdrawn forward down across its
        // bounded passes and returns without hanging on the channel that
        // refuses them all.
        watcher.stop().await;
        requests.extend(drained(&mut served));
        let exposes = requests
            .iter()
            .filter(|served| served.path == "/services/forwarder/expose")
            .count();
        assert_eq!(
            exposes, 1,
            "the returning listener was served by the forward still standing, never re-bound: {requests:?}"
        );
        let withdrawals = requests
            .iter()
            .filter(|served| served.path == "/services/forwarder/unexpose")
            .count();
        assert!(
            withdrawals > WITHDRAW_PASSES,
            "the refused withdrawal is asked for again — once mid-life, then on every one \
             of the stop's {} passes: {} requests, {requests:?}",
            WITHDRAW_PASSES,
            withdrawals
        );
        assert!(!gate.admits_tcp(port), "the publication ended with the box");
        drop(restarted);
        server.abort();
    }

    /// A withdrawal whose unexpose failed is retried while the box still
    /// runs, not only at its stop: the forward left standing delivers to a
    /// lease:port nothing answers, so every poll asks for it again until it
    /// comes down — here the second unexpose, one poll later, with no stop
    /// anywhere near it, and the stop that follows has nothing left to ask
    /// of the switch.
    #[tokio::test]
    async fn a_failed_withdrawal_is_retried_while_the_box_runs() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first unexpose — the shape of a
        // forwarder mid-restart — and accepts every request after it.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        // The listener closes and the unexpose is refused.
        drop(listener);
        let first = next_served(&mut served).await;
        assert_eq!(first.path, "/services/forwarder/unexpose");
        assert_eq!(first.local, format!("{PUBLISHED}:{port}"));
        soon(|| !gate.admits_tcp(port)).await;

        // The box is still running — no stop has been asked for — and the
        // poll asks again for the withdrawal it owes, one poll later, for
        // the same `local`.
        let retried = next_served(&mut served).await;
        assert_eq!(
            retried,
            Served {
                path: "/services/forwarder/unexpose".into(),
                local: format!("{PUBLISHED}:{port}"),
                remote: String::new(),
                protocol: "tcp".into(),
            },
            "the failed withdrawal is retried while the box runs"
        );

        // So the stop has nothing left to withdraw: not one request.
        watcher.stop().await;
        let records = drained(&mut served);
        assert!(
            records.is_empty(),
            "the withdrawal was already made while the box ran: {records:?}"
        );
        assert!(
            !gate.admits_tcp(port),
            "the publication ended with its listener"
        );
        server.abort();
    }

    /// A permitted port whose publish the switch refuses every time is
    /// retried on a per-port backoff, not on every poll: the attempts space
    /// out, doubling off the poll interval, so a forwarder that is down for
    /// as long as it takes is waited for rather than hammered — and the
    /// backoff never gives up on the port, which publishes the moment the
    /// forwarder starts accepting.
    #[tokio::test]
    async fn a_persistently_refused_publish_backs_off() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's exposes while the test says so,
        // and accepts them once the test clears the flag.
        let refusing = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&refusing);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose") && flag.load(Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        // Three seconds of the switch refusing every publish: far fewer
        // attempts than one per poll once the first few failures have the
        // backoff doubling.
        let started = std::time::Instant::now();
        let mut attempts = 0;
        while started.elapsed() < Duration::from_secs(3) {
            match served.try_recv() {
                Ok(attempt) => {
                    assert_eq!(
                        attempt.path, "/services/forwarder/expose",
                        "only the port's publish is asked for: {attempt:?}"
                    );
                    assert_eq!(attempt.local, format!("{PUBLISHED}:{port}"));
                    attempts += 1;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    panic!("the fake forwarder ended before the backoff was read")
                }
            }
        }
        assert!(
            attempts <= 6,
            "a forwarder that refuses every publish is waited for, not asked \
             on every poll: {attempts} attempts in three seconds"
        );
        assert!(
            !gate.admits_tcp(port),
            "nothing is published while the switch refuses the bind"
        );

        // The moment the forwarder accepts, the next attempt lands: the
        // port a box's process is listening on is published, late, never
        // missing.
        refusing.store(false, Ordering::SeqCst);
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// A backoff streak belongs to one listener: a port whose listener closed
    /// while its publish was waiting out a refusal starts a fresh streak when
    /// the box's next server binds the same port number — not the wait and the
    /// count the closed listener earned. The book keeps a backed-off port out
    /// of the listening table, so the poll's diff never reads one as
    /// disappeared, and the entry would otherwise outlive its listener: the
    /// next server would inherit a wait it did not earn and a count whose
    /// first failure was never said. The fresh server's first failure is its
    /// own streak's first — said, at the poll's own cadence — and the streak
    /// still ends the way every one does: the port publishes the moment the
    /// forwarder accepts.
    ///
    /// The entry goes with a poll that reads a table without the port, and
    /// that read leaves no line of its own, so the proof holds a witness
    /// beside the port: an any-bound listener at the next port up, which the
    /// forwarder accepts, closed together with the port. The withdrawal the
    /// poll writes for the witness is the proof that the table both had left
    /// was read — the line is written after the unexpose and before the poll
    /// drops the entries whose ports that table no longer names. A fixed wait
    /// is not that proof: a stall of the test's process that outlasts the
    /// wait leaves the poll and the test due together, the runtime polls the
    /// test's body before the watcher's task, and the rebind lands before the
    /// table is read — so the port never left it and the entry stands.
    #[tokio::test]
    async fn a_backed_off_port_that_closes_starts_a_fresh_streak() {
        let (listener, witness) = adjacent_any_listeners();
        let port = port_of(&listener);
        let witness_port = port_of(&witness);
        let port_local = format!("{PUBLISHED}:{port}");
        let witness_local = format!("{PUBLISHED}:{witness_port}");
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's every expose while the test says
        // so — both servers' publishes fail under it until the test clears
        // the flag — and accepts the witness's.
        let refusing = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&refusing);
        let refused = port_local.clone();
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/expose")
                && served.local == refused
                && flag.load(Ordering::SeqCst)
            {
                500
            } else {
                200
            }
        });
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_at(sock, &permit_range_policy(port, witness_port));

        // The first poll asks for both ports, in the table's own order: the
        // witness publishes, and the port's publish is refused and said —
        // one streak's first failure, at the poll's own cadence: the fresh
        // wait is one poll (`retry_in` below).
        let asked = [
            next_served(&mut served).await,
            next_served(&mut served).await,
        ];
        for attempt in &asked {
            assert_eq!(
                attempt.path, "/services/forwarder/expose",
                "the first poll only publishes: {attempt:?}"
            );
        }
        let mut asked_for = [asked[0].local.as_str(), asked[1].local.as_str()];
        asked_for.sort_unstable();
        let mut held = [port_local.as_str(), witness_local.as_str()];
        held.sort_unstable();
        assert_eq!(
            asked_for, held,
            "the first poll asks for the port and its witness, nothing else"
        );
        soon(|| gate.admits_tcp(witness_port)).await;
        soon(|| {
            !lines_saying(
                &lines.contents(),
                "publishing a listening port on the switch failed",
            )
            .is_empty()
        })
        .await;
        assert!(
            !gate.admits_tcp(port),
            "nothing is published while the switch refuses the bind"
        );

        // The first server closes, and the witness with it. The poll that
        // reads the table both have left withdraws the witness and says so;
        // the port's streak, which that same read ends, leaves no line of
        // its own. The withdrawal's line is written after the unexpose and
        // before the poll drops the entries whose ports the table no longer
        // names, so once it is read here the port's entry is gone.
        drop(listener);
        drop(witness);
        // If this process stalled past the poll interval between the first
        // poll and the drop, the port's retried expose is served before the
        // witness's withdrawal; the withdrawal is the proof, and anything
        // served before it can only be that retry.
        let withdrawn = loop {
            let next = next_served(&mut served).await;
            if next.path == "/services/forwarder/unexpose" {
                break next;
            }
            assert_eq!(next.path, "/services/forwarder/expose", "{next:?}");
            assert_eq!(
                next.local, port_local,
                "only the refused port retries: {next:?}"
            );
        };
        assert_eq!(withdrawn.local, witness_local);
        soon(|| {
            !lines_saying(
                &lines.contents(),
                "withdrew a listening port from the box's address",
            )
            .is_empty()
        })
        .await;
        assert_eq!(
            lines_saying(
                &lines.contents(),
                "publishing a listening port on the switch failed"
            )
            .len(),
            1,
            "the closed listener's streak said its one failure and no more"
        );

        // The box's next server binds the same port number: a listener of its
        // own, whose first failure must be said too — the count the old
        // streak earned would swallow it — and at the poll's cadence, not
        // made to wait the old streak's backoff out.
        let second = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("the box's next server binds the port its old one held");
        let second_attempt = next_served(&mut served).await;
        assert_eq!(
            second_attempt,
            Served {
                path: "/services/forwarder/expose".into(),
                local: port_local.clone(),
                remote: format!("{LEASE}:{port}"),
                protocol: "tcp".into(),
            },
            "the new server's publish is asked for like any fresh appearance"
        );
        soon(|| {
            lines_saying(
                &lines.contents(),
                "publishing a listening port on the switch failed",
            )
            .len()
                == 2
        })
        .await;
        let log = lines.contents();
        let failed = lines_saying(&log, "publishing a listening port on the switch failed");
        assert_eq!(failed.len(), 2, "two streaks, one line each: {failed:?}");
        for line in failed {
            assert!(
                line.contains("retry_in=250ms"),
                "each streak's first failure waits one poll, not the count \
                 an earlier listener earned: {line}"
            );
        }
        assert!(
            !gate.admits_tcp(port),
            "nothing is published while the switch refuses the binds"
        );

        // The fresh streak still ends the way every one does: the moment the
        // forwarder accepts, the port the new server holds publishes.
        refusing.store(false, Ordering::SeqCst);
        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, port_local);
        soon(|| gate.admits_tcp(port)).await;

        drop(second);
        watcher.stop().await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, port_local);
        assert!(!gate.admits_tcp(port));
        server.abort();
    }

    /// Everything the watcher wrote on the thread it runs on, so a proof can
    /// read the lines it left. The watcher's task shares a current-thread
    /// runtime with the test, so `set_default` reaches it.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            let kept = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            String::from_utf8(kept.clone()).unwrap()
        }
    }

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // A poisoned buffer is a bug in this proof's own code, and the
            // lines it holds are what the proof reads: recover the buffer
            // rather than drop the write on the floor.
            let mut kept = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            kept.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// Starts reading the watcher's own lines: the guard holds this thread's
    /// default subscriber for as long as the proof does.
    fn captured_lines() -> (CaptureWriter, tracing::subscriber::DefaultGuard) {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (buf, guard)
    }

    /// The whole log lines carrying `what`, so a proof reads one event's
    /// fields off the line that event landed on.
    fn lines_saying<'a>(log: &'a str, what: &str) -> Vec<&'a str> {
        log.lines().filter(|line| line.contains(what)).collect()
    }

    /// The publication's two endings carry the same facts its start does:
    /// the withdrawal that ends it, and the failure of the unexpose that
    /// cannot end it yet, each name the port, the box and the verdict — so
    /// the daemon log's tail reads a publication's whole life whichever way
    /// it ends. And the failure is said once per streak, not once per
    /// attempt: the poll's retry is the same failure.
    #[tokio::test]
    async fn the_withdrawal_lines_carry_the_box_port_and_verdict() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the port's first unexpose and accepts every
        // request after it, so the publication ends through one failed
        // withdrawal and the retry that lands.
        let refused = AtomicBool::new(true);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose") && refused.swap(false, Ordering::SeqCst) {
                500
            } else {
                200
            }
        });
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        drop(listener);
        let first = next_served(&mut served).await;
        assert_eq!(first.path, "/services/forwarder/unexpose");
        let retried = next_served(&mut served).await;
        assert_eq!(retried.path, "/services/forwarder/unexpose");
        soon(|| !gate.admits_tcp(port)).await;
        watcher.stop().await;
        let log = lines.contents();

        let withdrew = lines_saying(&log, "withdrew a listening port from the box's address");
        assert_eq!(withdrew.len(), 1, "one withdrawal line, got: {log}");
        assert!(
            withdrew[0].contains("session=listen-box"),
            "{}",
            withdrew[0]
        );
        assert!(
            withdrew[0].contains(&format!("port={port}")),
            "{}",
            withdrew[0]
        );
        assert!(
            withdrew[0].contains("verdict=\"permitted\""),
            "the withdrawal names its verdict as the publication does: {}",
            withdrew[0]
        );

        let failed = lines_saying(&log, "unpublishing a listening port on the switch failed");
        assert_eq!(
            failed.len(),
            1,
            "the failed unexpose is said once, not once per attempt, got: {log}"
        );
        assert!(failed[0].contains("session=listen-box"), "{}", failed[0]);
        assert!(failed[0].contains(&format!("port={port}")), "{}", failed[0]);
        assert!(
            failed[0].contains("verdict=\"permitted\""),
            "the failure names its verdict as the publication does: {}",
            failed[0]
        );
        server.abort();
    }

    /// The stop's "could not withdraw" warning names what it could not bring
    /// down, and nothing else: a stop whose last pass succeeds — two refused
    /// unexposes, then the third that comes down — warns of nothing, because
    /// there is no forward left standing to name.
    #[tokio::test]
    async fn a_withdrawal_that_succeeds_on_the_last_pass_warns_of_nothing() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");
        // The forwarder refuses the stop's first two unexposes — its first
        // two passes — and accepts the third, the last.
        let refused = AtomicU32::new(2);
        let (server, mut served) = spawn_forwarder_deciding(sock.clone(), move |served| {
            if served.path.ends_with("/unexpose")
                && refused.load(Ordering::SeqCst) > 0
                && refused.fetch_sub(1, Ordering::SeqCst) > 0
            {
                500
            } else {
                200
            }
        });
        let (lines, _guard) = captured_lines();
        let (watcher, gate) = watcher_at(sock, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        soon(|| gate.admits_tcp(port)).await;

        // The listener still holds the port when the box stops, so the
        // stop's own passes are the whole withdrawal: two refused, the
        // third down.
        watcher.stop().await;
        let records = drained(&mut served);
        let withdrawals = records
            .iter()
            .filter(|served| served.path == "/services/forwarder/unexpose")
            .count();
        assert_eq!(
            withdrawals, 3,
            "two refused passes and the one that came down: {records:?}"
        );
        assert!(!gate.admits_tcp(port), "the publication ended with the box");
        let log = lines.contents();
        assert!(
            lines_saying(&log, "could not withdraw").is_empty(),
            "a stop whose last pass withdrew everything warns of nothing: {log}"
        );
        assert_eq!(
            lines_saying(&log, "unpublishing a listening port on the switch failed").len(),
            1,
            "the refusal is said once across the passes, got: {log}"
        );
        server.abort();
    }

    /// The watcher a host never stopped — dropped or abandoned before its
    /// mainloop reached the stop — ends itself: no poll outlives the
    /// watcher, and everything it published comes down the way a stop takes
    /// it down, so no runtime-published forward outlives the watcher
    /// whichever way its host ended.
    #[tokio::test]
    async fn dropping_a_watcher_stops_its_poll() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (watcher, gate, server, mut served) = started_watcher(&dir, &permit_policy(port));

        let published = next_served(&mut served).await;
        assert_eq!(published.path, "/services/forwarder/expose");
        assert_eq!(published.local, format!("{PUBLISHED}:{port}"));
        soon(|| gate.admits_tcp(port)).await;

        // Dropped, not stopped: the ending a host build abandoned mid-flight
        // gives its watcher.
        drop(watcher);

        // The drop ends the poll, and the loop runs the stop's own last act:
        // the gate refuses the port first, the forward comes down after.
        soon(|| !gate.admits_tcp(port)).await;
        let withdrawn = next_served(&mut served).await;
        assert_eq!(withdrawn.path, "/services/forwarder/unexpose");
        assert_eq!(withdrawn.local, format!("{PUBLISHED}:{port}"));

        // And the loop is gone, not merely quiet: the box's server restarts
        // on the same port — the appearance a still-polling watcher would
        // publish again — and several poll intervals later nothing has been
        // asked for it.
        drop(listener);
        tokio::time::sleep(Duration::from_millis(700)).await;
        let again = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .expect("the box's server restarts on its own port");
        tokio::time::sleep(Duration::from_millis(700)).await;
        let records = drained(&mut served);
        assert!(
            records.is_empty(),
            "a dropped watcher never polls again: {records:?}"
        );
        drop(again);
        server.abort();
    }

    /// A port the runtime expose already published is treated as published
    /// by the watcher too: the appearance is settled — never bound, so the
    /// switch is never asked for a second forward onto the one address —
    /// and the settlement is said once, never retried under a backoff a
    /// publication that stands does not earn, and never withdrawn, because
    /// the publication is the expose surface's to take down: closing the
    /// listener the box held on the port changes nothing the switch holds.
    #[tokio::test]
    async fn a_port_the_runtime_expose_published_is_never_bound_or_withdrawn() {
        let listener = listening_socket();
        let port = port_of(&listener);
        let dir = tempfile::tempdir().unwrap();
        let (_watcher, gate, server, mut served) = started_watcher_with_publications(
            &dir,
            &permit_policy(port),
            // The expose surface's own publication of the port, standing
            // before the watcher ever polls: the set both surfaces read,
            // holding the port the way a runtime `min net expose` does.
            |publications| {
                let reservation = publications
                    .reserve(port, PublicationOwner::Expose)
                    .expect("nothing holds the port yet");
                assert!(reservation.record(), "nothing revoked the reservation");
            },
        );
        // The expose's own admission at the gate (NET-044), made when it
        // published: the watcher must leave it alone.
        gate.admit_exposed(port);
        let (lines, _guard) = captured_lines();

        // Several poll intervals with the listener standing: the watcher
        // reads its port, sees whose publication it is, and asks nothing —
        // one skip line, and no expose the fake forwarder would record.
        tokio::time::sleep(Duration::from_millis(900)).await;
        let log = lines.contents();
        let skipped = lines_saying(
            &log,
            "left a listening port the runtime expose already published",
        );
        assert_eq!(
            skipped.len(),
            1,
            "the skip is said once, never retried under backoff: {log}"
        );
        assert!(
            skipped[0].contains("owner=expose"),
            "the refusal line names whose publication holds the port: {}",
            skipped[0]
        );
        assert!(
            skipped[0].contains(&format!("port={port}")),
            "the refusal line names the port the other surface holds: {}",
            skipped[0]
        );

        // The box's listener on the port closes, and the publication is
        // the expose surface's — so nothing comes down: no unexpose is
        // asked, across several more poll intervals, and the skip stays
        // the one line the port ever wrote.
        drop(listener);
        tokio::time::sleep(Duration::from_millis(900)).await;
        let records = drained(&mut served);
        assert!(
            records.is_empty(),
            "the watcher neither published the port nor withdrew the expose \
             surface's publication: {records:?}"
        );
        let log = lines.contents();
        assert_eq!(
            lines_saying(
                &log,
                "left a listening port the runtime expose already published"
            )
            .len(),
            1,
            "the settlement is one line, not one per poll: {log}"
        );
        assert!(
            lines_saying(&log, "published a listening port on the box's address").is_empty(),
            "the port the expose surface holds is never bound by the watcher: {log}"
        );
        assert!(
            gate.admits_tcp(port),
            "a listener closing never withdraws an exposed port's admission"
        );
        server.abort();
    }

    /// The two halves of the shared set's ownership rule: a publication is
    /// withdrawn by whoever published it and by nobody else — a `Listen`
    /// entry ignores an `Expose` withdrawal and an `Expose` entry ignores a
    /// `Listen` one — and a reservation refuses the other owner's port
    /// naming the owner that holds it, so the bind races both surfaces
    /// close are answered before either has bound anything.
    #[test]
    fn publications_withdraw_with_their_owner_only() {
        let publications = BoxPublications::default();
        assert!(
            publications.held_by(8080).is_none(),
            "a fresh box's set holds nothing"
        );
        for (holder, other) in [
            (PublicationOwner::Listen, PublicationOwner::Expose),
            (PublicationOwner::Expose, PublicationOwner::Listen),
        ] {
            let reservation = publications
                .reserve(8080, holder)
                .expect("the first surface to reserve wins the port");
            assert!(reservation.record(), "nothing revoked the reservation");
            match publications.reserve(8080, other) {
                Err(held) => assert_eq!(
                    held,
                    Held {
                        owner: holder,
                        published: true,
                    },
                    "the other surface's reservation names the owner that holds the port"
                ),
                Ok(_) => panic!("a published port is not free to reserve twice"),
            }
            assert_eq!(publications.held_by(8080), Some(holder));
            // The other surface's withdrawal is refused by the rule, not
            // by an error: the entry stands, because the publisher is the
            // one who withdraws.
            publications.withdraw(8080, other);
            assert_eq!(
                publications.held_by(8080),
                Some(holder),
                "the other surface's withdrawal leaves the publication standing"
            );
            // And the owner's own withdrawal is the one that clears it, so
            // the next publisher finds the port free.
            publications.withdraw(8080, holder);
            assert!(
                publications.held_by(8080).is_none(),
                "the publisher's withdrawal gives the port back"
            );
        }
    }

    /// The reservation is the check-then-bind's atomic half and its own
    /// rollback: the second surface to reach a port is refused before either
    /// binds, a dropped reservation releases the port whether its holder
    /// fell off an error path or was cancelled mid-bind, and a recorded one
    /// is the publication its publisher withdraws.
    #[test]
    fn reservations_release_the_port_they_never_recorded() {
        let publications = BoxPublications::default();
        // One surface reserves; the other is refused naming the holder —
        // pending, because the holder's bind has not stood yet.
        let held = publications
            .reserve(8080, PublicationOwner::Expose)
            .expect("nothing holds the port yet");
        match publications.reserve(8080, PublicationOwner::Listen) {
            Err(held) => assert_eq!(
                held,
                Held {
                    owner: PublicationOwner::Expose,
                    published: false,
                },
                "a pending reservation holds the port against the other surface"
            ),
            Ok(_) => panic!("a reserved port is not free to reserve twice"),
        }
        // The holder's bind failed — or its future was cancelled mid-bind —
        // and the guard released on drop: the port is free again, and the
        // other surface's next reservation takes it.
        drop(held);
        let published = publications
            .reserve(8080, PublicationOwner::Listen)
            .expect("the failed reservation gave the port back");
        assert!(published.record(), "nothing revoked the reservation");
        assert_eq!(
            publications.held_by(8080),
            Some(PublicationOwner::Listen),
            "the recorded reservation is the publication that stands"
        );
        // A release is keyed by the reservation that wrote it, never by
        // the port alone: a second reservation of the port cannot be
        // released by the first one's remains, and a revocation that
        // clears the set under a reservation leaves the record a no-op
        // rather than re-writing an entry into a set the revocation
        // emptied.
        let stale = publications
            .reserve(8081, PublicationOwner::Expose)
            .expect("nothing holds the other port yet");
        publications.revoke_all();
        assert!(
            !stale.record(),
            "a record after a revocation reports the reservation gone"
        );
        assert!(
            publications.held_by(8081).is_none(),
            "a record after a revocation writes nothing back"
        );
    }

    /// The kernel socket table's rows read as the watcher reads them: a
    /// listener's port, and only a listener's — an established socket is a
    /// connection, not a publication — from either table, and only where
    /// the bind can answer a forward dialing the box's lease: the any
    /// address and the lease itself, in either table's spelling.
    #[test]
    fn socket_rows_read_their_listening_port() {
        // The v4 table: header, a listener on the any address
        // (`00000000:1F90`), one on the box's lease (`09004064`, the
        // little-endian word for 100.64.0.9), a loopback-bound listener
        // (`0100007F:1F92`) no dial at the lease can reach, an established
        // socket, and a row too short to read.
        let v4 = "  sl  local_address  rem_address   st\n\
                  0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n\
                  1: 09004064:1F91 00000000:0000 0A 00000000:00000000\n\
                  2: 0100007F:1F92 00000000:0000 0A 00000000:00000000\n\
                  3: 0100007F:1F90 0100007F:9C4A 01 00000000:00000000\n\
                  4: 0100007F";
        let ports: HashSet<u16> = v4
            .lines()
            .skip(1)
            .filter_map(|line| listen_port(line, false, LEASE))
            .collect();
        assert_eq!(ports, HashSet::from([8080, 8081]));

        // The v6 table: the dual-stack any (`::`), a v4-mapped bind on the
        // lease, a v4-mapped loopback bind, and a pure v6 address — the
        // last two answer no IPv4 dial at the lease.
        let v6 = "  sl  local_address  rem_address   st\n\
                  0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A\n\
                  1: 0000000000000000FFFF000009004064:2328 00000000000000000000000000000000:0000 0A\n\
                  2: 0000000000000000FFFF00000100007F:2329 00000000000000000000000000000000:0000 0A\n\
                  3: 00000000000000000000000100000000:2329 00000000000000000000000000000000:0000 0A\n";
        let ports: HashSet<u16> = v6
            .lines()
            .skip(1)
            .filter_map(|line| listen_port(line, true, LEASE))
            .collect();
        assert_eq!(ports, HashSet::from([8080, 9000]));
        assert!(
            binds_for_the_lease("00000000000000000000000000000000", true, LEASE),
            "the dual-stack any"
        );
        assert!(
            binds_for_the_lease("0000000000000000FFFF000009004064", true, LEASE),
            "a mapped bind on the lease"
        );
        assert!(
            !binds_for_the_lease("0000000000000000FFFF00000100007F", true, LEASE),
            "a mapped loopback bind"
        );
        assert!(
            !binds_for_the_lease("00000000000000000000000100000000", true, LEASE),
            "a pure v6 address"
        );
        assert!(binds_for_the_lease("00000000", false, LEASE), "the v4 any");
        assert!(binds_for_the_lease("09004064", false, LEASE), "the lease");
        assert!(
            !binds_for_the_lease("0100007F", false, LEASE),
            "the box's loopback"
        );
    }

    /// A process entry names its own listening sockets, and stops naming
    /// them when they close, proved against the real kernel rather than a
    /// fixture — with the bind shape the watcher distinguishes: a
    /// loopback-bound listener is in the kernel's table but is never one of
    /// the box's publications.
    #[test]
    fn the_leader_entry_names_its_own_listeners() {
        let reachable = listening_socket();
        let reachable_port = port_of(&reachable);
        let loopback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("an ephemeral port binds on the loopback alone");
        let loop_port = port_of(&loopback);
        let ports = listening_ports_in(Path::new("/proc/self"), LEASE)
            .expect("this process's entry is readable");
        assert!(
            ports.contains(&reachable_port),
            "a listener bound to the any address is in the leader's table"
        );
        assert!(
            !ports.contains(&loop_port),
            "a loopback-bound listener is no publication: a forward dials the lease"
        );
        drop(reachable);
        let ports = listening_ports_in(Path::new("/proc/self"), LEASE)
            .expect("this process's entry is readable");
        assert!(
            !ports.contains(&reachable_port),
            "a closed listener leaves the leader's table"
        );
    }

    /// A kernel without IPv6 has no `tcp6` table: the entry's v4 listeners
    /// still read, while a missing `tcp` table stays a failure.
    #[test]
    fn an_entry_without_a_v6_table_reads_its_v4_listeners() {
        let entry = tempfile::tempdir().expect("a scratch /proc entry");
        std::fs::create_dir(entry.path().join("net")).expect("its net directory");
        assert_eq!(
            listening_ports_in(entry.path(), LEASE)
                .expect_err("no tcp table is a failure")
                .kind(),
            io::ErrorKind::NotFound
        );
        std::fs::write(
            entry.path().join("net/tcp"),
            "  sl  local_address  rem_address   st\n\
             0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n",
        )
        .expect("its tcp table");
        assert_eq!(
            listening_ports_in(entry.path(), LEASE).expect("no tcp6 table reads as empty"),
            HashSet::from([8080])
        );
    }

    /// The test-only read the watcher polls under test keeps a namespace's
    /// listeners to the ones the entry's own process holds: a listener
    /// another process on the machine opened is in the same table and is
    /// not the test's box's. Proved on a fake entry whose fd links name one
    /// of two listening sockets, and on this process's own entry, where a
    /// listener the test binds is held and leaves when it closes.
    #[test]
    fn under_test_the_box_reads_only_the_listeners_its_test_holds() {
        let entry = tempfile::tempdir().expect("a scratch /proc entry");
        std::fs::create_dir_all(entry.path().join("net")).expect("its net directory");
        std::fs::create_dir_all(entry.path().join("fd")).expect("its fd directory");
        std::fs::write(
            entry.path().join("net/tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   \
             uid  timeout inode\n\
             0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  \
             1000        0 123 1 0000000000000000 100 0 0 10 0\n\
             1: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  \
             1000        0 456 1 0000000000000000 100 0 0 10 0\n",
        )
        .expect("its tcp table");
        std::os::unix::fs::symlink("socket:[123]", entry.path().join("fd/3"))
            .expect("a fake socket fd");
        std::os::unix::fs::symlink("/dev/null", entry.path().join("fd/4"))
            .expect("a fake non-socket fd");
        assert_eq!(
            listening_ports_held_by(entry.path(), LEASE).expect("the fake entry reads"),
            HashSet::from([8080]),
            "only the listener the entry's process holds is read; 8081 is another's"
        );

        let own = listening_socket();
        let own_port = port_of(&own);
        assert!(
            listening_ports_held_by(Path::new("/proc/self"), LEASE)
                .expect("this process's entry is readable")
                .contains(&own_port),
            "a listener this process binds is one it holds"
        );
        drop(own);
        assert!(
            !listening_ports_held_by(Path::new("/proc/self"), LEASE)
                .expect("this process's entry is readable")
                .contains(&own_port),
            "a closed listener is held no longer"
        );
    }

    /// The listen-publication surface against the real gvproxy, not the
    /// stand-in: the watcher's expose verbs land on a real forwarder, which
    /// binds the box's published address at the port the process listens on
    /// — and, when the listener closes, comes down with the port, so a
    /// client after the close is refused at the box's own address, never
    /// accepted by a forward delivering to nothing (NET-016's publish half
    /// and NET-017's withdraw half, against the switch the daemon itself
    /// spawns). The proof's client is the client a published box serves:
    /// what it sees is the bind at the box's own address — the address it
    /// connects to — appearing when the listener appears and refusing when
    /// the listener closes. The bytes' other leg, through the switch to the
    /// attached box's tap, is the netns and VM lanes' own proof — a
    /// stand-in process has no tap on the switch's stack, so it is not
    /// proven here.
    ///
    /// The stand-in box is this process: its listener is bound at its lease
    /// — the host's own loopback, the address a dial into this namespace
    /// reaches — and the watcher reads this process's listening sockets as
    /// the box's, the way every proof in this module does. The bind at
    /// the lease alone is what makes the proof's connect read the forward
    /// rather than the listener: a wildcard bind answers at every local
    /// address, the published one included, and the connect would reach
    /// the listener without the forward at all. Gated on `GVPROXY_BIN`, the
    /// way the netns proofs are gated on their own host facts:
    /// `scripts/fetch-gvproxy.sh` fetches the pinned binary, so the proof is
    /// run as
    /// `GVPROXY_BIN=./gvproxy cargo nextest run -p minimald --run-ignored only a_published_listener_is_reachable_and_refused_on_the_real_switch`.
    #[ignore = "needs the real gvproxy binary; gated on GVPROXY_BIN (scripts/fetch-gvproxy.sh fetches the pinned one)"]
    #[tokio::test]
    async fn a_published_listener_is_reachable_and_refused_on_the_real_switch() {
        let Some(bin) = std::env::var_os("GVPROXY_BIN") else {
            eprintln!(
                "skipping real-switch listen proof: GVPROXY_BIN not set \
                 (scripts/fetch-gvproxy.sh fetches the pinned binary)"
            );
            return;
        };
        // The stand-in box's lease: this process's own loopback, so a dial
        // the real forwarder makes to the lease reaches the listener the
        // test binds — the reachability a real box's own address is its
        // published address for (NET-010).
        const STANDIN_LEASE: Ipv4Addr = Ipv4Addr::LOCALHOST;
        // The box's listener is bound at its lease, not the any address: in
        // the stand-in's own namespace a wildcard bind answers at every
        // local address, the published one included, so the proof's connect
        // would reach the listener without the forward at all. A lease bind
        // answers only the forward's dial — the shape a publication carries
        // — and `binds_for_the_lease` reads it as the box's own.
        let listener = TcpListener::bind((STANDIN_LEASE, 0))
            .expect("the stand-in box's listener binds at its lease");
        let port = port_of(&listener);
        listener
            .set_nonblocking(true)
            .expect("the listener can go nonblocking");
        let listener = tokio::net::TcpListener::from_std(listener)
            .expect("the listener joins the runtime that awaits it");
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gvproxy.sock");

        // The real switch, brought up the way the daemon brings it up: the
        // rendered config, the control socket, the PID file, and no SSH
        // forward. `kill_on_drop` takes it with the handle, so a proof that
        // ends anywhere leaves no gvproxy behind.
        let config = dir.path().join("switch.yml");
        std::fs::write(
            &config,
            crate::net::render_gvproxy_config(SwitchSubnet::default(), &[]),
        )
        .expect("the switch config writes");
        let gvproxy = tokio::process::Command::new(&bin)
            .arg("-config")
            .arg(&config)
            .arg("-listen")
            .arg(format!("unix://{}", sock.display()))
            .arg("-pid-file")
            .arg(dir.path().join("gvproxy.pid"))
            .arg("-ssh-port")
            .arg("-1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("GVPROXY_BIN spawns the real gvproxy");
        // Waited for with a real connect, the way the daemon's own bring-up
        // waits: the socket's file appears before its listen does.
        soon(|| std::os::unix::net::UnixStream::connect(&sock).is_ok()).await;

        let gate = crate::net::ingress_gate::IngressGate::detached(&permit_policy(port));
        let watcher = ListenWatcher::start(
            ListenPlan::new(
                "listen-box".into(),
                STANDIN_LEASE,
                PUBLISHED,
                ControlChannel::Unix(sock.clone()),
                Arc::clone(&gate),
                BoxPublications::default(),
                dir.path().to_path_buf(),
                None,
                boxes::SessionId::nil(),
            ),
            held_here(),
        );

        // The watcher publishes the listener's port on the real switch: a
        // forward bound at the box's published address, at the process's own
        // port number, delivering to the box's lease — the no-translation
        // rule NET-010 holds of runtime publications too. Until the bind
        // lands, a connect at the published address is refused, so the probe
        // retries within the bound — and the bind it waits for is the
        // forward's own: the stand-in's listener answers at its lease alone,
        // so nothing but the published forward can answer at `PUBLISHED`.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut last_probe = String::new();
        let published = loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the listener's port never published at the box's own \
                 address (last probe: {last_probe})"
            );
            match tokio::net::TcpStream::connect((std::net::IpAddr::from(PUBLISHED), port)).await {
                Ok(client) => break client,
                Err(e) => last_probe = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        drop(published);

        // The box's server closes — the one fact NET-017 turns on — and the
        // watcher withdraws the publication: the gate refuses the port
        // first, the forward comes down after.
        drop(listener);
        soon(|| !gate.admits_tcp(port)).await;

        // A fresh client is refused at the box's own address — a connection
        // refused, the port bound by nothing, not a published forward
        // accepting a connection to deliver to a listener that is gone. The
        // refusal is waited for within the bound, because the unbind follows
        // the gate's own withdrawal by a control round trip.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut last_probe = String::new();
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the port is still published after its listener closed \
                 (last probe: {last_probe})"
            );
            match tokio::net::TcpStream::connect((std::net::IpAddr::from(PUBLISHED), port)).await {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                Ok(_) => last_probe = "still connected".into(),
                Err(e) => last_probe = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        watcher.stop().await;
        drop(gvproxy);
    }
}
