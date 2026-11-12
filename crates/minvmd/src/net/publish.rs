//! Port publishing: which host ports forward into the VM.
//!
//! This module protects the host. A forward is a listener on the host's
//! loopback, so every one is decided here, against what the box's creator
//! registered on the host: the declared ports, the dynamic ingress stance
//! and range, and a person's answer to an ask. The guest daemon says which
//! box wants a port and when. It cannot name a host address, publish for a
//! box the host does not know, or go past the box's grant.
//!
//! It does not decide what a box may reach or who inside the virtual network
//! may reach a box. That is per-box network policy, and the kernel that runs
//! the box enforces it.
//!
//! The ledger holds every forward minvmd asked gvproxy for, including its
//! own (the node's hostname proxy, the mirrored listeners of `host_ip`
//! boxes). gvproxy forgets its forwards when it restarts, so the ledger is
//! what they are bound from again.

#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use minimald_rpc::{ForwardState, IpProto, PublishOrigin, PublishPortRequest, PublishRefusal};

use crate::box_id::{BoxId, BoxIdText};
use crate::box_registry::{BoxRecord, BoxRegistry, PortReportRefusal, RowWithdrawal};
use crate::net::gvproxy_api::{ExposeError, SwitchApi, UnexposeError};

/// How many forwards the ledger holds. Past it a publish is refused: a
/// forward the ledger cannot hold could never be unbound at its box's end.
pub(crate) const LEDGER_CAP: usize = 1024;

/// The waits between attempts to unbind an ended box's forwards. After the
/// last one the forwards are left bound and the box's addresses stay held
/// against reuse.
const UNBIND_RETRY: [Duration; 5] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// How often the worker tries again to bind forwards whose bind is owed.
const OWED_RETRY: Duration = Duration::from_secs(2);

/// Who a forward belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    Box(BoxId),
    /// minvmd's own forwards into the guest node's namespace.
    Node,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Declared,
    Dynamic,
    Node,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// gvproxy holds the forward.
    Bound,
    /// The forward should be bound and is not: its bind failed after a
    /// hand-over or a gvproxy restart. The worker retries it.
    Owed,
    /// Another owner holds the listener.
    Waiting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Forward {
    listener: SocketAddrV4,
    proto: IpProto,
    owner: Owner,
    target: SocketAddrV4,
    kind: Kind,
    state: State,
}

impl Forward {
    fn at(&self, listener: SocketAddrV4, proto: IpProto) -> bool {
        self.listener == listener && self.proto == proto
    }

    fn holds(&self) -> bool {
        self.state != State::Waiting
    }
}

/// What the ledger made of a forward offered to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Noted as held by its owner. The caller binds it.
    New,
    /// The owner already holds this very forward.
    Same(State),
    /// The owner holds the listener with another target.
    Retarget,
    /// Another owner holds the listener, and the forward now waits.
    Waiting,
    /// Another owner holds the listener, and this kind does not wait.
    HeldElsewhere,
    Full,
}

/// The forwards in arrival order.
#[derive(Debug, Default)]
struct Ledger {
    forwards: Vec<Forward>,
}

impl Ledger {
    fn holder(&self, listener: SocketAddrV4, proto: IpProto) -> Option<&Forward> {
        self.forwards
            .iter()
            .find(|forward| forward.at(listener, proto) && forward.holds())
    }

    fn admit(&mut self, offered: Forward) -> Admit {
        match self.holder(offered.listener, offered.proto).copied() {
            Some(held) if held.owner == offered.owner && held.target == offered.target => {
                Admit::Same(held.state)
            }
            Some(held) if held.owner == offered.owner => Admit::Retarget,
            Some(_) if offered.kind != Kind::Declared => Admit::HeldElsewhere,
            Some(_) => {
                // One waiting forward per owner and listener: a repeat
                // replaces the earlier one.
                self.forwards.retain(|forward| {
                    !(forward.at(offered.listener, offered.proto)
                        && forward.owner == offered.owner
                        && forward.state == State::Waiting)
                });
                if self.forwards.len() >= LEDGER_CAP {
                    return Admit::Full;
                }
                self.forwards.push(Forward {
                    state: State::Waiting,
                    ..offered
                });
                Admit::Waiting
            }
            None if self.forwards.len() >= LEDGER_CAP => Admit::Full,
            None => {
                self.forwards.push(Forward {
                    state: State::Bound,
                    ..offered
                });
                Admit::New
            }
        }
    }

    /// Removes the forward `owner` holds at the listener.
    fn release(&mut self, listener: SocketAddrV4, proto: IpProto, owner: Owner) -> Option<Forward> {
        let at = self.forwards.iter().position(|forward| {
            forward.at(listener, proto) && forward.owner == owner && forward.holds()
        })?;
        Some(self.forwards.remove(at))
    }

    /// Gives a free listener to the forward that waited longest for it.
    fn promote(&mut self, listener: SocketAddrV4, proto: IpProto) -> Option<Forward> {
        if self.holder(listener, proto).is_some() {
            return None;
        }
        let next = self
            .forwards
            .iter_mut()
            .find(|forward| forward.at(listener, proto) && forward.state == State::Waiting)?;
        next.state = State::Bound;
        Some(*next)
    }

    fn set_state(&mut self, of: &Forward, state: State) {
        if let Some(forward) = self.forwards.iter_mut().find(|forward| {
            forward.at(of.listener, of.proto) && forward.owner == of.owner && forward.holds()
        }) {
            forward.state = state;
        }
    }

    fn held_by(&self, owner: Owner) -> Vec<Forward> {
        self.forwards
            .iter()
            .filter(|forward| forward.owner == owner && forward.holds())
            .copied()
            .collect()
    }

    fn drop_waiting_of(&mut self, owner: Owner) {
        self.forwards
            .retain(|forward| !(forward.owner == owner && forward.state == State::Waiting));
    }
}

/// A forward as the reply to a publish names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Published {
    pub(crate) listener: SocketAddrV4,
    pub(crate) internal: u16,
    pub(crate) proto: IpProto,
    pub(crate) state: ForwardState,
}

/// What a publish request comes to before anything is bound.
#[derive(Debug)]
pub(crate) enum Decision {
    /// The grant covers the port. Bind it.
    Bind(Grant),
    /// The box's stance is ask and the request may ask. The caller runs the
    /// ask and binds on a yes.
    Ask(Grant),
    Refuse(PublishRefusal),
}

/// A publish the box's registration covers, ready to bind.
#[derive(Debug, Clone)]
pub(crate) struct Grant {
    row: Arc<BoxRecord>,
    request: PublishPortRequest,
    kind: GrantKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantKind {
    Declared,
    Dynamic,
}

impl Grant {
    pub(crate) fn row(&self) -> &Arc<BoxRecord> {
        &self.row
    }
}

/// Why minvmd's own forward did not bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum NodeBindError {
    #[error("the host port is already in use")]
    Occupied,
    #[error("a box holds the listener")]
    Held,
    #[error("the publish ledger is full")]
    Full,
    #[error("{0}")]
    Failed(String),
    #[error("{0}")]
    Unanswered(String),
}

/// What ending a box unbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Ended {
    pub(crate) ended: bool,
    pub(crate) forwards_unbound: u32,
    pub(crate) still_bound: u32,
}

/// The publishing service of one VM.
#[derive(Debug, Clone)]
pub(crate) struct Publisher {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    api: SwitchApi,
    boxes: BoxRegistry,
    ledger: Mutex<Ledger>,
    /// Serialises every change that calls gvproxy, so the ledger and
    /// gvproxy change in the same order.
    turn: Mutex<()>,
    audit: Option<PathBuf>,
}

impl Publisher {
    /// A publisher for the gvproxy behind `api`, deciding by `boxes`. It
    /// starts the worker that unbinds a box's forwards when its row is
    /// withdrawn.
    pub(crate) fn start(api: SwitchApi, boxes: BoxRegistry, audit: Option<PathBuf>) -> Self {
        let withdrawn = boxes.table().subscribe_row_withdrawals();
        let publisher = Self {
            inner: Arc::new(Inner {
                api,
                boxes,
                ledger: Mutex::new(Ledger::default()),
                turn: Mutex::new(()),
                audit,
            }),
        };
        let worker = publisher.clone();
        let span = crate::telemetry::vm_task("net.publish");
        let spawned = std::thread::Builder::new()
            .name("minvmd-publish".into())
            .spawn(move || {
                let _span = span.entered();
                worker.work(&withdrawn);
            });
        if let Err(error) = spawned {
            tracing::error!(%error, "the publish worker did not start; ended boxes keep their forwards");
        }
        publisher
    }

    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        self.inner
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn turn(&self) -> MutexGuard<'_, ()> {
        self.inner
            .turn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Decides a publish request against the box's registration. Nothing is
    /// bound and nothing is recorded.
    pub(crate) fn decide(&self, request: &PublishPortRequest) -> Decision {
        let id = request.box_id.to_bytes();
        let Some(row) = self.inner.boxes.row_by_box_id(id) else {
            // A box that shares the node's address has no row. It is known
            // by the id minted for it, when it has a credentialed upstream,
            // or as a resident, which is how the stream door knows it.
            let shares_the_node = self.inner.boxes.holds_host_ip_id(id)
                || self.inner.boxes.resident_host_ip_box(id).is_some();
            return Decision::Refuse(if shares_the_node {
                PublishRefusal::HostIpBox
            } else {
                PublishRefusal::UnknownBox
            });
        };
        row.mark_used();
        if request.external == 0
            || request.internal == 0
            || !matches!(request.proto, IpProto::Tcp | IpProto::Udp)
        {
            return Decision::Refuse(PublishRefusal::InvalidPort);
        }
        let grant = |kind| Grant {
            row: Arc::clone(&row),
            request: *request,
            kind,
        };
        // A host port the box declared is forwarded as declared and no
        // other way: to the port in the box its creator named.
        match row.declared_internal(request.external, request.proto) {
            Some(internal) if internal == request.internal => {
                return Decision::Bind(grant(GrantKind::Declared));
            }
            Some(_) => return Decision::Refuse(PublishRefusal::NotDeclared),
            None => {}
        }
        // A run-time publish is one TCP port, the same on both sides.
        if request.origin == PublishOrigin::Declared
            || request.proto != IpProto::Tcp
            || request.external != request.internal
        {
            return Decision::Refuse(PublishRefusal::NotDeclared);
        }
        let range = row.dynamic_range();
        let outside = |range: (u16, u16)| request.external < range.0 || request.external > range.1;
        match row.dynamic_ingress() {
            boxes::DynamicIngress::Deny => Decision::Refuse(PublishRefusal::Denied),
            boxes::DynamicIngress::Allow => match range {
                None => Decision::Refuse(PublishRefusal::NoRange),
                Some(range) if outside(range) => {
                    Decision::Refuse(PublishRefusal::OutOfRange { range })
                }
                Some(_) => Decision::Bind(grant(GrantKind::Dynamic)),
            },
            boxes::DynamicIngress::Ask => match range {
                Some(range) if outside(range) => {
                    Decision::Refuse(PublishRefusal::OutOfRange { range })
                }
                _ if request.origin == PublishOrigin::Listen => {
                    Decision::Refuse(PublishRefusal::AskNeedsExpose)
                }
                _ => Decision::Ask(grant(GrantKind::Dynamic)),
            },
        }
    }

    /// Binds a granted forward. `asked` says a person allowed it, which the
    /// ask already recorded in the box's row.
    pub(crate) fn bind(&self, grant: &Grant, asked: bool) -> Result<Published, PublishRefusal> {
        let outcome = self.bind_inner(grant, asked);
        self.audit_publish(grant, asked, &outcome);
        outcome
    }

    fn bind_inner(&self, grant: &Grant, asked: bool) -> Result<Published, PublishRefusal> {
        let row = &grant.row;
        let request = &grant.request;
        let _turn = self.turn();
        // The row may have been withdrawn since the decision.
        if !self.inner.boxes.row_stands(row) {
            return Err(PublishRefusal::UnknownBox);
        }
        if grant.kind == GrantKind::Dynamic && !asked {
            self.inner
                .boxes
                .admit_runtime_port(
                    row.switch_addr(),
                    request.external,
                    request.proto,
                    Instant::now(),
                )
                .map_err(|refusal| match refusal {
                    PortReportRefusal::NoRow { .. } => PublishRefusal::UnknownBox,
                    PortReportRefusal::RowCapReached { .. } => PublishRefusal::BoxCap,
                    PortReportRefusal::RateExceeded { .. } => PublishRefusal::RateExceeded,
                    // The decision checked the stance and the range under
                    // the same registration.
                    PortReportRefusal::DenyStance { .. }
                    | PortReportRefusal::AskNotHostRecorded { .. } => PublishRefusal::Denied,
                    PortReportRefusal::NoAllowedRange { .. } => PublishRefusal::NoRange,
                    PortReportRefusal::OutsideAllowedRange { range, .. } => {
                        PublishRefusal::OutOfRange { range }
                    }
                })?;
        }
        let forward = Forward {
            listener: SocketAddrV4::new(listener_address(row), request.external),
            proto: request.proto,
            owner: Owner::Box(row.box_id()),
            target: SocketAddrV4::new(row.switch_addr(), request.internal),
            kind: match grant.kind {
                GrantKind::Declared => Kind::Declared,
                GrantKind::Dynamic => Kind::Dynamic,
            },
            state: State::Bound,
        };
        let result = self.bind_forward(forward);
        if result.is_err() && grant.kind == GrantKind::Dynamic {
            self.inner.boxes.withdraw_runtime_port(
                row.switch_addr(),
                request.external,
                request.proto,
            );
        }
        result.map(|state| Published {
            listener: forward.listener,
            internal: request.internal,
            proto: request.proto,
            state,
        })
    }

    /// Notes `forward` in the ledger and binds it on gvproxy. Called with
    /// the turn held.
    fn bind_forward(&self, forward: Forward) -> Result<ForwardState, PublishRefusal> {
        let admit = self.ledger().admit(forward);
        match admit {
            Admit::Same(State::Bound) => return Ok(ForwardState::Bound),
            Admit::Same(State::Waiting) | Admit::Waiting => return Ok(ForwardState::Waiting),
            // A box's host port leads to one port in the box: the declared
            // one, or for a run-time publish the same number.
            Admit::HeldElsewhere | Admit::Retarget => return Err(PublishRefusal::ListenerHeld),
            Admit::Full => return Err(PublishRefusal::LedgerFull),
            Admit::New | Admit::Same(State::Owed) => {}
        }
        match self.expose(&forward) {
            Ok(()) => {
                self.ledger().set_state(&forward, State::Bound);
                Ok(ForwardState::Bound)
            }
            Err(error) => {
                self.ledger()
                    .release(forward.listener, forward.proto, forward.owner);
                self.hand_over(forward.listener, forward.proto);
                Err(match error {
                    ExposeError::AddressInUse => PublishRefusal::PortInUse,
                    _ => PublishRefusal::SwitchUnavailable,
                })
            }
        }
    }

    /// One expose for a forward the ledger says should be bound. gvproxy
    /// answering that it already holds the listener means it holds a forward
    /// the ledger did not put there, so that one is replaced.
    fn expose(&self, forward: &Forward) -> Result<(), ExposeError> {
        let api = &self.inner.api;
        match api.expose(forward.listener, forward.target, forward.proto) {
            Err(ExposeError::AlreadyBound) => {
                api.unexpose(forward.listener, forward.proto)
                    .map_err(|error| ExposeError::Unanswered(error.to_string()))?;
                api.expose(forward.listener, forward.target, forward.proto)
            }
            // The forward may be bound all the same. It must not stay bound
            // with nothing in the ledger to unbind it.
            Err(error @ ExposeError::Unanswered(_)) => {
                let _ = api.unexpose(forward.listener, forward.proto);
                Err(error)
            }
            other => other,
        }
    }

    /// Binds the forward that waited for a listener which just came free.
    fn hand_over(&self, listener: SocketAddrV4, proto: IpProto) {
        let Some(next) = self.ledger().promote(listener, proto) else {
            return;
        };
        match self.expose(&next) {
            Ok(()) => tracing::info!(
                %listener,
                %proto,
                target = %next.target,
                "bound the forward that waited for the listener"
            ),
            Err(error) => {
                self.ledger().set_state(&next, State::Owed);
                tracing::warn!(
                    %listener,
                    %proto,
                    %error,
                    "the forward that waited for the listener did not bind; it is retried"
                );
            }
        }
    }

    /// Ends a forward a box published at run time.
    pub(crate) fn unpublish(
        &self,
        box_id: BoxId,
        external: u16,
        proto: IpProto,
    ) -> Result<(SocketAddrV4, u32), PublishRefusal> {
        let Some(row) = self.inner.boxes.row_by_box_id(box_id) else {
            return Err(PublishRefusal::UnknownBox);
        };
        let listener = SocketAddrV4::new(listener_address(&row), external);
        let owner = Owner::Box(box_id);
        let _turn = self.turn();
        let held = self
            .ledger()
            .held_by(owner)
            .into_iter()
            .find(|forward| forward.at(listener, proto));
        let outcome = match held {
            None => Err(PublishRefusal::NotPublished),
            Some(forward) if forward.kind != Kind::Dynamic => Err(PublishRefusal::DeclaredPort),
            Some(_) => match self.inner.api.unexpose(listener, proto) {
                Ok(unexposed) => {
                    self.ledger().release(listener, proto, owner);
                    self.inner
                        .boxes
                        .withdraw_runtime_port(row.switch_addr(), external, proto);
                    self.hand_over(listener, proto);
                    Ok((listener, unexposed.closed))
                }
                Err(_) => Err(PublishRefusal::SwitchUnavailable),
            },
        };
        tracing::info!(
            box = %row.name(),
            box_id = %BoxIdText(&box_id),
            %listener,
            %proto,
            outcome = %outcome_text(outcome.as_ref().map(|_| ())),
            "unpublish"
        );
        self.audit(&AuditLine {
            ts: unix_now_secs(),
            event: "unpublish",
            box_name: row.name().to_string(),
            box_id: BoxIdText(&box_id).to_string(),
            listener: Some(listener),
            internal: None,
            proto: Some(proto),
            origin: None,
            asked: None,
            outcome: outcome_text(outcome.as_ref().map(|_| ())),
        });
        outcome
    }

    /// Ends a box at the guest's word: unbinds its forwards and withdraws
    /// its row. The creation stays, so its creator can ask for the row back.
    pub(crate) fn end_box(&self, box_id: BoxId) -> Ended {
        let boxes = &self.inner.boxes;
        let Some(row) = boxes.row_by_box_id(box_id) else {
            // A host_ip box has no row. Ending it takes it out of the
            // resident set.
            let ended = boxes.end_host_ip_box(box_id);
            return Ended {
                ended,
                ..Ended::default()
            };
        };
        let (forwards_unbound, still_bound) = {
            let _turn = self.turn();
            self.unbind_owner(Owner::Box(box_id))
        };
        // The worker sees the withdrawal next. It retries what is still
        // bound and holds the box's addresses until it is done.
        boxes.withdraw(row.switch_addr());
        tracing::info!(
            box = %row.name(),
            box_id = %BoxIdText(&box_id),
            forwards_unbound,
            still_bound,
            "the guest ended the box; its row is withdrawn"
        );
        self.audit(&AuditLine {
            ts: unix_now_secs(),
            event: "box_end",
            box_name: row.name().to_string(),
            box_id: BoxIdText(&box_id).to_string(),
            listener: None,
            internal: None,
            proto: None,
            origin: None,
            asked: None,
            outcome: format!("unbound {forwards_unbound}, still bound {still_bound}"),
        });
        Ended {
            ended: true,
            forwards_unbound,
            still_bound,
        }
    }

    /// One pass over the forwards `owner` holds: unbinds each and hands its
    /// listener on. Returns how many were unbound and how many are still
    /// bound. Called with the turn held.
    fn unbind_owner(&self, owner: Owner) -> (u32, u32) {
        self.ledger().drop_waiting_of(owner);
        let (mut unbound, mut still) = (0, 0);
        // Taken before the loop: the lock is not held across a call to
        // gvproxy, nor while the loop takes it again.
        let held = self.ledger().held_by(owner);
        for forward in held {
            // An owed forward is not bound on gvproxy, and an unexpose of
            // it answers that it was not.
            match self.inner.api.unexpose(forward.listener, forward.proto) {
                Ok(unexposed) => {
                    self.ledger()
                        .release(forward.listener, forward.proto, owner);
                    unbound += 1;
                    tracing::info!(
                        listener = %forward.listener,
                        proto = %forward.proto,
                        closed = unexposed.closed,
                        "unbound an ended box's forward"
                    );
                    self.hand_over(forward.listener, forward.proto);
                }
                Err(error) => {
                    still += 1;
                    tracing::warn!(
                        listener = %forward.listener,
                        proto = %forward.proto,
                        %error,
                        "an ended box's forward did not unbind; it is retried"
                    );
                }
            }
        }
        (unbound, still)
    }

    /// Binds every forward again after gvproxy was restarted. The new
    /// gvproxy holds none of them, whatever the ledger says.
    pub(crate) fn reapply(&self) {
        let _turn = self.turn();
        let forwards: Vec<Forward> = self
            .ledger()
            .forwards
            .iter()
            .filter(|forward| forward.holds())
            .copied()
            .collect();
        let mut bound = 0usize;
        for forward in &forwards {
            match self.expose(forward) {
                Ok(()) => {
                    self.ledger().set_state(forward, State::Bound);
                    bound += 1;
                }
                Err(error) => {
                    self.ledger().set_state(forward, State::Owed);
                    tracing::warn!(
                        listener = %forward.listener,
                        proto = %forward.proto,
                        %error,
                        "a forward did not bind on the restarted gvproxy; it is retried"
                    );
                }
            }
        }
        tracing::info!(
            forwards = forwards.len(),
            bound,
            "bound the forwards again on the restarted gvproxy"
        );
    }

    /// Binds one of minvmd's own forwards: `listener` on the host to
    /// `node_port` at the guest node's address.
    pub(crate) fn bind_node(
        &self,
        listener: SocketAddrV4,
        node: Ipv4Addr,
        node_port: u16,
    ) -> Result<(), NodeBindError> {
        let forward = Forward {
            listener,
            proto: IpProto::Tcp,
            owner: Owner::Node,
            target: SocketAddrV4::new(node, node_port),
            kind: Kind::Node,
            state: State::Bound,
        };
        let _turn = self.turn();
        let admit = self.ledger().admit(forward);
        match admit {
            Admit::Same(State::Bound) => return Ok(()),
            Admit::New | Admit::Same(State::Owed) => {}
            Admit::Full => return Err(NodeBindError::Full),
            Admit::Retarget => {
                self.inner
                    .api
                    .unexpose(listener, IpProto::Tcp)
                    .map_err(|error| NodeBindError::Unanswered(error.to_string()))?;
                let mut ledger = self.ledger();
                ledger.release(listener, IpProto::Tcp, Owner::Node);
                ledger.admit(forward);
            }
            Admit::HeldElsewhere | Admit::Waiting | Admit::Same(State::Waiting) => {
                return Err(NodeBindError::Held);
            }
        }
        self.expose(&forward).map_err(|error| {
            self.ledger().release(listener, IpProto::Tcp, Owner::Node);
            self.hand_over(listener, IpProto::Tcp);
            match error {
                ExposeError::AddressInUse => NodeBindError::Occupied,
                ExposeError::Unanswered(text) => NodeBindError::Unanswered(text),
                other => NodeBindError::Failed(other.to_string()),
            }
        })
    }

    /// Unbinds one of minvmd's own forwards. Returns how many connections
    /// gvproxy closed with it.
    pub(crate) fn unbind_node(&self, listener: SocketAddrV4) -> Result<u32, UnexposeError> {
        let _turn = self.turn();
        let unexposed = self.inner.api.unexpose(listener, IpProto::Tcp)?;
        self.ledger().release(listener, IpProto::Tcp, Owner::Node);
        self.hand_over(listener, IpProto::Tcp);
        Ok(unexposed.closed)
    }

    /// The remote a bound forward at `listener` dials.
    #[cfg(test)]
    pub(crate) fn dials(&self, listener: SocketAddrV4, proto: IpProto) -> Option<SocketAddrV4> {
        self.ledger()
            .holder(listener, proto)
            .map(|forward| forward.target)
    }

    #[cfg(test)]
    pub(crate) fn forward_count(&self) -> usize {
        self.ledger().forwards.len()
    }

    /// The worker: unbinds the forwards of every withdrawn row, whichever
    /// path withdrew it, and retries binds that are owed. It ends when the
    /// registry is gone.
    fn work(&self, withdrawn: &std::sync::mpsc::Receiver<RowWithdrawal>) {
        struct Unbind {
            withdrawal: RowWithdrawal,
            attempt: usize,
            due: Instant,
        }
        let mut unbinds: Vec<Unbind> = Vec::new();
        // Withdrawals whose forwards could not be unbound. Keeping them
        // keeps the addresses held against reuse.
        let mut stranded: Vec<RowWithdrawal> = Vec::new();
        let mut owed_due = Instant::now() + OWED_RETRY;
        loop {
            let now = Instant::now();
            let next = unbinds
                .iter()
                .map(|unbind| unbind.due)
                .chain(std::iter::once(owed_due))
                .min()
                .unwrap_or(owed_due);
            match withdrawn.recv_timeout(next.saturating_duration_since(now)) {
                Ok(withdrawal) => unbinds.push(Unbind {
                    withdrawal,
                    attempt: 0,
                    due: Instant::now(),
                }),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
            let now = Instant::now();
            let mut later = Vec::new();
            for mut unbind in unbinds.drain(..) {
                if unbind.due > now {
                    later.push(unbind);
                    continue;
                }
                let owner = Owner::Box(unbind.withdrawal.box_id());
                let (_, still) = {
                    let _turn = self.turn();
                    self.unbind_owner(owner)
                };
                if still == 0 {
                    // Dropping the withdrawal frees the box's addresses.
                    continue;
                }
                match UNBIND_RETRY.get(unbind.attempt) {
                    Some(wait) => {
                        unbind.attempt += 1;
                        unbind.due = now + *wait;
                        later.push(unbind);
                    }
                    None => {
                        tracing::error!(
                            switch_addr = %unbind.withdrawal.switch_addr(),
                            still_bound = still,
                            "gave up unbinding an ended box's forwards; they stay bound, and \
                             the box's addresses stay held against reuse"
                        );
                        stranded.push(unbind.withdrawal);
                    }
                }
            }
            unbinds = later;
            if now >= owed_due {
                owed_due = now + OWED_RETRY;
                self.retry_owed();
            }
        }
    }

    fn retry_owed(&self) {
        let owed: Vec<Forward> = self
            .ledger()
            .forwards
            .iter()
            .filter(|forward| forward.state == State::Owed)
            .copied()
            .collect();
        if owed.is_empty() {
            return;
        }
        let _turn = self.turn();
        for forward in owed {
            // The forward may have gone while the turn was awaited.
            if !self.ledger().forwards.contains(&forward) {
                continue;
            }
            if self.expose(&forward).is_ok() {
                self.ledger().set_state(&forward, State::Bound);
                tracing::info!(
                    listener = %forward.listener,
                    proto = %forward.proto,
                    "bound a forward whose bind was owed"
                );
            }
        }
    }

    fn audit_publish(
        &self,
        grant: &Grant,
        asked: bool,
        outcome: &Result<Published, PublishRefusal>,
    ) {
        let row = &grant.row;
        let request = &grant.request;
        let text = match outcome {
            Ok(published) => match published.state {
                ForwardState::Bound => "bound".to_string(),
                ForwardState::Waiting => "waiting".to_string(),
            },
            Err(refusal) => format!("refused: {refusal}"),
        };
        match outcome {
            Ok(published) => tracing::info!(
                box = %row.name(),
                box_id = %BoxIdText(&row.box_id()),
                listener = %published.listener,
                internal = request.internal,
                proto = %request.proto,
                origin = ?request.origin,
                outcome = %text,
                "publish"
            ),
            Err(_) => tracing::warn!(
                box = %row.name(),
                box_id = %BoxIdText(&row.box_id()),
                external = request.external,
                internal = request.internal,
                proto = %request.proto,
                origin = ?request.origin,
                outcome = %text,
                "publish"
            ),
        }
        self.audit(&AuditLine {
            ts: unix_now_secs(),
            event: "publish",
            box_name: row.name().to_string(),
            box_id: BoxIdText(&row.box_id()).to_string(),
            listener: Some(SocketAddrV4::new(listener_address(row), request.external)),
            internal: Some(request.internal),
            proto: Some(request.proto),
            origin: Some(request.origin),
            asked: asked.then_some(true),
            outcome: text,
        });
    }

    /// Records a publish refused before any grant existed.
    pub(crate) fn audit_refusal(&self, request: &PublishPortRequest, refusal: &PublishRefusal) {
        let id = request.box_id.to_bytes();
        let name = self
            .inner
            .boxes
            .row_by_box_id(id)
            .map(|row| row.name().to_string())
            .unwrap_or_default();
        tracing::warn!(
            box = %name,
            box_id = %BoxIdText(&id),
            external = request.external,
            internal = request.internal,
            proto = %request.proto,
            origin = ?request.origin,
            reason = %refusal,
            "refused a publish"
        );
        self.audit(&AuditLine {
            ts: unix_now_secs(),
            event: "publish",
            box_name: name,
            box_id: BoxIdText(&id).to_string(),
            listener: None,
            internal: Some(request.internal),
            proto: Some(request.proto),
            origin: Some(request.origin),
            asked: None,
            outcome: format!("refused: {refusal}"),
        });
    }

    fn audit(&self, line: &AuditLine) {
        if let Some(path) = &self.inner.audit {
            crate::control::append_audit_line(path, line);
        }
    }
}

/// One line of `audit/box-admissions.log` for a decision this module made.
#[derive(Debug, serde::Serialize)]
struct AuditLine {
    ts: u64,
    event: &'static str,
    #[serde(rename = "box")]
    box_name: String,
    box_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    listener: Option<SocketAddrV4>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internal: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proto: Option<IpProto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<PublishOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asked: Option<bool>,
    outcome: String,
}

fn outcome_text(outcome: Result<(), &PublishRefusal>) -> String {
    match outcome {
        Ok(()) => "done".to_string(),
        Err(refusal) => format!("refused: {refusal}"),
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The host address a box's ports are published at: its own address in the
/// reserved loopback range when the host handed it one, otherwise the
/// shared `127.0.0.1`. Never an address the guest names.
fn listener_address(row: &BoxRecord) -> Ipv4Addr {
    let address = row.loopback_addr();
    let (base, prefix) = switch::RESERVED_LOCAL_RANGE;
    let mask = u32::MAX << (32 - u32::from(prefix));
    if u32::from(address) & mask == u32::from(base) & mask {
        address
    } else {
        Ipv4Addr::LOCALHOST
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::box_registry::ClientBoxSpec;
    use crate::net::gvproxy_api::testing::FakeSwitch;
    use crate::test_support::tcp_mapping;
    use boxes::DynamicIngress;

    struct Bed {
        fake: FakeSwitch,
        boxes: BoxRegistry,
        publisher: Publisher,
    }

    fn bed() -> Bed {
        let fake = FakeSwitch::start();
        let boxes = BoxRegistry::new(switch::DEFAULT_SUBNET);
        let publisher = Publisher::start(SwitchApi::new(fake.sock.clone()), boxes.clone(), None);
        Bed {
            fake,
            boxes,
            publisher,
        }
    }

    fn spec(name: &str) -> ClientBoxSpec {
        ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: Vec::new(),
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        }
    }

    impl Bed {
        fn register(&self, spec: &ClientBoxSpec, loopback: Ipv4Addr) -> Arc<BoxRecord> {
            self.boxes
                .register_client_box_at(spec.clone(), loopback)
                .expect("the box registers")
        }

        fn publish(&self, request: PublishPortRequest) -> Result<Published, PublishRefusal> {
            match self.publisher.decide(&request) {
                Decision::Bind(grant) => self.publisher.bind(&grant, false),
                Decision::Ask(_) => panic!("the test did not expect an ask"),
                Decision::Refuse(refusal) => Err(refusal),
            }
        }
    }

    fn request(
        row: &BoxRecord,
        external: u16,
        internal: u16,
        origin: PublishOrigin,
    ) -> PublishPortRequest {
        PublishPortRequest {
            box_id: minimald_rpc::BoxId::from_bytes(row.box_id()),
            external,
            internal,
            proto: IpProto::Tcp,
            origin,
        }
    }

    fn until(what: &str, mut holds: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !holds() {
            assert!(Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    const OWN: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 2);
    const OTHER: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 3);

    #[test]
    fn a_declared_port_binds_at_the_boxs_own_host_address() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("web")
            },
            OWN,
        );
        let published = bed
            .publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        assert_eq!(published.listener, SocketAddrV4::new(OWN, 8080));
        assert_eq!(published.state, ForwardState::Bound);
        assert_eq!(
            bed.fake.dials("127.0.64.2:8080", "tcp"),
            Some(format!("{}:80", row.switch_addr()))
        );
        // A repeat answers the same and asks gvproxy for nothing new.
        let calls = bed.fake.log().len();
        assert_eq!(
            bed.publish(request(&row, 8080, 80, PublishOrigin::Declared)),
            Ok(published)
        );
        assert_eq!(bed.fake.log().len(), calls);
    }

    #[test]
    fn a_box_without_a_range_address_publishes_at_the_shared_loopback() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("web")
            },
            Ipv4Addr::LOCALHOST,
        );
        let published = bed
            .publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        assert_eq!(
            published.listener,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)
        );
    }

    #[test]
    fn an_undeclared_port_is_refused_unless_the_dynamic_grant_covers_it() {
        let bed = bed();
        let deny = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("deny")
            },
            OWN,
        );
        // Claimed as declared, and not in the declaration.
        assert_eq!(
            bed.publish(request(&deny, 9090, 9090, PublishOrigin::Declared)),
            Err(PublishRefusal::NotDeclared)
        );
        // The default stance is deny.
        assert_eq!(
            bed.publish(request(&deny, 9090, 9090, PublishOrigin::Expose)),
            Err(PublishRefusal::Denied)
        );
        assert!(bed.fake.forwards().is_empty());

        let allow = bed.register(
            &ClientBoxSpec {
                dynamic_ingress: Some(DynamicIngress::Allow),
                dynamic_allowed_range: Some((3000, 3999)),
                ..spec("allow")
            },
            OTHER,
        );
        assert_eq!(
            bed.publish(request(&allow, 3000, 3000, PublishOrigin::Listen))
                .map(|published| published.state),
            Ok(ForwardState::Bound)
        );
        assert_eq!(allow.runtime_port_numbers(), vec![3000]);
        assert_eq!(
            bed.publish(request(&allow, 4000, 4000, PublishOrigin::Expose)),
            Err(PublishRefusal::OutOfRange {
                range: (3000, 3999)
            })
        );
        // A run-time publish has the same port on both sides.
        assert_eq!(
            bed.publish(request(&allow, 3001, 22, PublishOrigin::Expose)),
            Err(PublishRefusal::NotDeclared)
        );
        let mut udp = request(&allow, 3002, 3002, PublishOrigin::Expose);
        udp.proto = IpProto::Udp;
        assert_eq!(bed.publish(udp), Err(PublishRefusal::NotDeclared));

        let no_range = bed.register(
            &ClientBoxSpec {
                dynamic_ingress: Some(DynamicIngress::Allow),
                ..spec("norange")
            },
            Ipv4Addr::new(127, 0, 64, 4),
        );
        assert_eq!(
            bed.publish(request(&no_range, 3000, 3000, PublishOrigin::Expose)),
            Err(PublishRefusal::NoRange)
        );
    }

    /// The guest names the port in the box and the protocol of a publish.
    /// For a host port the box declared, the host takes neither from it.
    #[test]
    fn a_declared_port_is_forwarded_only_as_its_creator_declared_it() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                dynamic_ingress: Some(DynamicIngress::Allow),
                dynamic_allowed_range: Some((8000, 8999)),
                ..spec("web")
            },
            OWN,
        );
        // Another port in the box.
        assert_eq!(
            bed.publish(request(&row, 8080, 22, PublishOrigin::Declared)),
            Err(PublishRefusal::NotDeclared)
        );
        // Another protocol.
        let mut udp = request(&row, 8080, 80, PublishOrigin::Declared);
        udp.proto = IpProto::Udp;
        assert_eq!(bed.publish(udp), Err(PublishRefusal::NotDeclared));
        // The dynamic grant covers the number, and the port is not its to
        // give: the declaration holds it.
        for origin in [PublishOrigin::Expose, PublishOrigin::Listen] {
            assert_eq!(
                bed.publish(request(&row, 8080, 8080, origin)),
                Err(PublishRefusal::NotDeclared)
            );
        }
        assert!(bed.fake.forwards().is_empty());
        assert!(row.runtime_port_numbers().is_empty());

        bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        // Bound, it stays where it was declared to lead.
        assert_eq!(
            bed.publish(request(&row, 8080, 22, PublishOrigin::Declared)),
            Err(PublishRefusal::NotDeclared)
        );
        assert_eq!(
            bed.fake.dials("127.0.64.2:8080", "tcp"),
            Some(format!("{}:80", row.switch_addr()))
        );
    }

    #[test]
    fn the_ask_stance_asks_only_for_an_explicit_expose_inside_the_range() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                dynamic_ingress: Some(DynamicIngress::Ask),
                dynamic_allowed_range: Some((3000, 3999)),
                ..spec("ask")
            },
            OWN,
        );
        assert!(matches!(
            bed.publisher
                .decide(&request(&row, 3000, 3000, PublishOrigin::Expose)),
            Decision::Ask(_)
        ));
        assert!(matches!(
            bed.publisher
                .decide(&request(&row, 3000, 3000, PublishOrigin::Listen)),
            Decision::Refuse(PublishRefusal::AskNeedsExpose)
        ));
        assert!(matches!(
            bed.publisher
                .decide(&request(&row, 4000, 4000, PublishOrigin::Expose)),
            Decision::Refuse(PublishRefusal::OutOfRange { .. })
        ));
    }

    #[test]
    fn an_unknown_box_and_a_host_ip_box_are_refused() {
        let bed = bed();
        let stranger = PublishPortRequest {
            box_id: minimald_rpc::BoxId::mint(),
            external: 8080,
            internal: 80,
            proto: IpProto::Tcp,
            origin: PublishOrigin::Declared,
        };
        assert_eq!(bed.publish(stranger), Err(PublishRefusal::UnknownBox));
        let host_ip = bed.boxes.register_host_ip_box("shared").unwrap();
        assert_eq!(
            bed.publish(PublishPortRequest {
                box_id: minimald_rpc::BoxId::from_bytes(host_ip),
                ..stranger
            }),
            Err(PublishRefusal::HostIpBox)
        );
        // A resident box with no credentialed upstream has no minted id.
        // The stream door serves it by its session id, and a publish under
        // that id gets the same answer as one under a minted id.
        let resident = boxes::SessionId::from_bytes(minimald_rpc::BoxId::mint().to_bytes());
        bed.boxes.admit_host_ip_box(resident, false);
        assert_eq!(
            bed.publish(PublishPortRequest {
                box_id: minimald_rpc::BoxId::from_bytes(resident.to_bytes()),
                ..stranger
            }),
            Err(PublishRefusal::HostIpBox)
        );
        assert_eq!(
            bed.publish(PublishPortRequest {
                external: 0,
                ..stranger
            }),
            Err(PublishRefusal::UnknownBox)
        );
    }

    #[test]
    fn a_box_cannot_take_or_end_another_boxs_port() {
        let bed = bed();
        // Both boxes publish at the shared loopback, so they contend.
        let dynamic = |name: &str| ClientBoxSpec {
            dynamic_ingress: Some(DynamicIngress::Allow),
            dynamic_allowed_range: Some((3000, 3999)),
            ..spec(name)
        };
        let first = bed.register(&dynamic("first"), Ipv4Addr::LOCALHOST);
        let second = bed.register(&dynamic("second"), Ipv4Addr::LOCALHOST);
        bed.publish(request(&first, 3000, 3000, PublishOrigin::Expose))
            .unwrap();
        assert_eq!(
            bed.publish(request(&second, 3000, 3000, PublishOrigin::Expose)),
            Err(PublishRefusal::ListenerHeld)
        );
        // The refused port is not left in the second box's grant.
        assert!(second.runtime_port_numbers().is_empty());
        assert_eq!(
            bed.publisher.unpublish(second.box_id(), 3000, IpProto::Tcp),
            Err(PublishRefusal::NotPublished)
        );
        assert_eq!(
            bed.fake.dials("127.0.0.1:3000", "tcp"),
            Some(format!("{}:3000", first.switch_addr()))
        );
        // A request under the first box's id for a port only the second
        // declared is decided by the first box's grant.
        let declared = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8443, 8443)],
                ..spec("declared")
            },
            OWN,
        );
        assert_eq!(
            bed.publish(request(&first, 8443, 8443, PublishOrigin::Declared)),
            Err(PublishRefusal::NotDeclared)
        );
        drop(declared);
    }

    #[test]
    fn unpublish_ends_a_dynamic_forward_and_never_a_declared_one() {
        let bed = bed();
        bed.fake.report_closed(2);
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                dynamic_ingress: Some(DynamicIngress::Allow),
                dynamic_allowed_range: Some((3000, 3999)),
                ..spec("web")
            },
            OWN,
        );
        bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        bed.publish(request(&row, 3000, 3000, PublishOrigin::Expose))
            .unwrap();
        assert_eq!(
            bed.publisher.unpublish(row.box_id(), 3000, IpProto::Tcp),
            Ok((SocketAddrV4::new(OWN, 3000), 2))
        );
        assert!(row.runtime_port_numbers().is_empty());
        assert_eq!(bed.fake.dials("127.0.64.2:3000", "tcp"), None);
        assert_eq!(
            bed.publisher.unpublish(row.box_id(), 8080, IpProto::Tcp),
            Err(PublishRefusal::DeclaredPort)
        );
        assert!(bed.fake.dials("127.0.64.2:8080", "tcp").is_some());
    }

    #[test]
    fn a_port_another_program_holds_is_refused_and_leaves_nothing_behind() {
        let bed = bed();
        bed.fake.occupy("127.0.64.2:8080");
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("web")
            },
            OWN,
        );
        assert_eq!(
            bed.publish(request(&row, 8080, 80, PublishOrigin::Declared)),
            Err(PublishRefusal::PortInUse)
        );
        assert_eq!(bed.publisher.forward_count(), 0);
        bed.fake.free("127.0.64.2:8080");
        assert!(
            bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
                .is_ok()
        );
    }

    #[test]
    fn a_declared_port_waits_for_its_listener_and_binds_when_the_holder_ends() {
        let bed = bed();
        let declared = |name: &str, internal| ClientBoxSpec {
            ingress_ports: vec![tcp_mapping(8080, internal)],
            ..spec(name)
        };
        let holder = bed.register(&declared("holder", 80), Ipv4Addr::LOCALHOST);
        let waiter = bed.register(&declared("waiter", 81), Ipv4Addr::LOCALHOST);
        bed.publish(request(&holder, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        assert_eq!(
            bed.publish(request(&waiter, 8080, 81, PublishOrigin::Declared))
                .map(|published| published.state),
            Ok(ForwardState::Waiting)
        );
        assert_eq!(
            bed.fake.dials("127.0.0.1:8080", "tcp"),
            Some(format!("{}:80", holder.switch_addr()))
        );

        let ended = bed.publisher.end_box(holder.box_id());
        assert_eq!(
            ended,
            Ended {
                ended: true,
                forwards_unbound: 1,
                still_bound: 0
            }
        );
        assert!(bed.boxes.row_by_box_id(holder.box_id()).is_none());
        assert_eq!(
            bed.fake.dials("127.0.0.1:8080", "tcp"),
            Some(format!("{}:81", waiter.switch_addr()))
        );
        // Asked again, the waiter's forward answers as bound.
        assert_eq!(
            bed.publish(request(&waiter, 8080, 81, PublishOrigin::Declared))
                .map(|published| published.state),
            Ok(ForwardState::Bound)
        );
    }

    #[test]
    fn a_row_withdrawn_by_its_creator_loses_its_forwards() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80), tcp_mapping(8081, 81)],
                ..spec("web")
            },
            OWN,
        );
        bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        bed.publish(request(&row, 8081, 81, PublishOrigin::Declared))
            .unwrap();
        // The creator's withdrawal does not go through `end_box`.
        bed.boxes.withdraw(row.switch_addr());
        until("the worker unbinds the forwards", || {
            bed.fake.forwards().is_empty()
        });
        until("the ledger is empty", || bed.publisher.forward_count() == 0);
        assert_eq!(
            bed.publish(request(&row, 8080, 80, PublishOrigin::Declared)),
            Err(PublishRefusal::UnknownBox)
        );
    }

    #[test]
    fn an_unbind_that_fails_is_retried_and_holds_the_address_meanwhile() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("web")
            },
            OWN,
        );
        bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        bed.fake.fail_next(2);
        let ended = bed.publisher.end_box(row.box_id());
        assert_eq!(ended.still_bound, 1);
        assert!(
            bed.boxes
                .table()
                .revocation_pending(row.switch_addr().octets())
        );
        until("the retry unbinds the forward", || {
            bed.fake.forwards().is_empty()
        });
        until("the address is released", || {
            !bed.boxes
                .table()
                .revocation_pending(row.switch_addr().octets())
        });
    }

    #[test]
    fn ending_a_box_twice_or_an_unknown_one_ends_nothing() {
        let bed = bed();
        let row = bed.register(&spec("web"), OWN);
        assert!(bed.publisher.end_box(row.box_id()).ended);
        assert_eq!(bed.publisher.end_box(row.box_id()), Ended::default());
        let host_ip = bed.boxes.register_host_ip_box("shared").unwrap();
        bed.boxes
            .admit_host_ip_box(minimald_rpc::BoxId::from_bytes(host_ip), false);
        assert!(bed.boxes.holds_host_ip_boxes());
        assert!(bed.publisher.end_box(host_ip).ended);
        assert!(!bed.boxes.holds_host_ip_boxes());
    }

    #[test]
    fn a_restarted_gvproxy_gets_every_forward_again() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                dynamic_ingress: Some(DynamicIngress::Allow),
                dynamic_allowed_range: Some((3000, 3999)),
                ..spec("web")
            },
            OWN,
        );
        bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        bed.publish(request(&row, 3000, 3000, PublishOrigin::Expose))
            .unwrap();
        let node = switch::DEFAULT_SUBNET.daemon_ip();
        bed.publisher
            .bind_node("127.0.0.1:7654".parse().unwrap(), node, 7654)
            .unwrap();
        let before = bed.fake.forwards();
        assert_eq!(before.len(), 3);

        bed.fake.restart();
        assert!(bed.fake.forwards().is_empty());
        bed.publisher.reapply();
        assert_eq!(bed.fake.forwards(), before);
    }

    #[test]
    fn a_forward_that_does_not_bind_after_a_restart_is_retried() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("web")
            },
            OWN,
        );
        bed.publish(request(&row, 8080, 80, PublishOrigin::Declared))
            .unwrap();
        bed.fake.restart();
        bed.fake.fail_next(1);
        bed.publisher.reapply();
        assert!(bed.fake.forwards().is_empty());
        // Nothing waits on the forward that died with the old gvproxy: the
        // worker binds it once gvproxy answers.
        until("the owed forward binds", || {
            bed.fake.dials("127.0.64.2:8080", "tcp").is_some()
        });
    }

    #[test]
    fn a_gvproxy_that_is_away_refuses_the_publish_and_keeps_nothing() {
        let bed = bed();
        let row = bed.register(
            &ClientBoxSpec {
                ingress_ports: vec![tcp_mapping(8080, 80)],
                ..spec("web")
            },
            OWN,
        );
        bed.fake.stop();
        assert_eq!(
            bed.publish(request(&row, 8080, 80, PublishOrigin::Declared)),
            Err(PublishRefusal::SwitchUnavailable)
        );
        assert_eq!(bed.publisher.forward_count(), 0);
    }

    #[test]
    fn the_nodes_own_forwards_share_the_ledger_with_the_boxes() {
        let bed = bed();
        let node = switch::DEFAULT_SUBNET.daemon_ip();
        let listener: SocketAddrV4 = "127.0.0.1:7654".parse().unwrap();
        bed.publisher.bind_node(listener, node, 7654).unwrap();
        // Bound again, it is the same forward.
        bed.publisher.bind_node(listener, node, 7654).unwrap();
        assert_eq!(
            bed.publisher.dials(listener, IpProto::Tcp),
            Some(SocketAddrV4::new(node, 7654))
        );
        // A box cannot take the node's listener.
        let row = bed.register(
            &ClientBoxSpec {
                dynamic_ingress: Some(DynamicIngress::Allow),
                dynamic_allowed_range: Some((7000, 7999)),
                ..spec("grabby")
            },
            Ipv4Addr::LOCALHOST,
        );
        assert_eq!(
            bed.publish(request(&row, 7654, 7654, PublishOrigin::Expose)),
            Err(PublishRefusal::ListenerHeld)
        );
        bed.fake.occupy("127.0.0.1:7655");
        assert_eq!(
            bed.publisher
                .bind_node("127.0.0.1:7655".parse().unwrap(), node, 7655),
            Err(NodeBindError::Occupied)
        );
        assert_eq!(bed.publisher.unbind_node(listener), Ok(0));
        assert_eq!(bed.publisher.forward_count(), 0);
    }

    #[test]
    fn decisions_are_written_to_the_audit_log() {
        let fake = FakeSwitch::start();
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit/box-admissions.log");
        let boxes = BoxRegistry::new(switch::DEFAULT_SUBNET);
        let publisher = Publisher::start(
            SwitchApi::new(fake.sock.clone()),
            boxes.clone(),
            Some(audit.clone()),
        );
        let row = boxes
            .register_client_box_at(
                ClientBoxSpec {
                    ingress_ports: vec![tcp_mapping(8080, 80)],
                    ..spec("web")
                },
                OWN,
            )
            .unwrap();
        let declared = request(&row, 8080, 80, PublishOrigin::Declared);
        let Decision::Bind(grant) = publisher.decide(&declared) else {
            panic!("a declared port is granted");
        };
        publisher.bind(&grant, false).unwrap();
        let refused = request(&row, 9090, 9090, PublishOrigin::Expose);
        let Decision::Refuse(refusal) = publisher.decide(&refused) else {
            panic!("the default stance refuses");
        };
        publisher.audit_refusal(&refused, &refusal);
        publisher.end_box(row.box_id());

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&audit)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["event"], "publish");
        assert_eq!(lines[0]["outcome"], "bound");
        assert_eq!(lines[0]["listener"], "127.0.64.2:8080");
        assert_eq!(lines[0]["box"], "web");
        assert!(lines[1]["outcome"].as_str().unwrap().starts_with("refused"));
        assert_eq!(lines[2]["event"], "box_end");
    }
}
