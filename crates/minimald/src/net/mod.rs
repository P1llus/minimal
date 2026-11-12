//! gvproxy switch lifecycle and IP allocation for `OwnIp` PTasks.
//!
//! This module owns the per-host gvproxy ("gvisor-tap-vsock") switch process
//! and the address book that backs it. An `OwnIp` PTask gets its own network
//! namespace, which `net::attach` connects to the switch. From the switch's
//! point of view every PTask is one more L2 client on the same subnet, so two
//! `OwnIp` PTasks on the same host can talk directly (UC6). A `NoNet` PTask
//! is never connected, so it sees only an empty namespace and cannot egress
//! (UC1).
//!
//! Covers R1.4 (gvproxy child lifecycle), R1.6 (per-host IP allocation, each
//! address to one live attach at a time, reused only under an allocation epoch
//! and a quarantine), and R1.8 (structured tracing for every switch lifecycle event).

pub mod answerer;
pub mod dns;
// The listen-publication watcher (NET-016, NET-017): publishes the ports a
// box's processes listen on, when its ingress rules permit them, and
// withdraws them when the listeners close. `pub mod` (not `pub(crate)`)
// because its unit tests live beside it and the launcher hands its plan to
// the session host.
pub mod listeners;
pub mod loopback;
pub mod policy;
pub mod proxy;

// The own-IP switch attach, and the mode-to-provider factory that reaches it.
// Not `#[cfg(not(test))]`: `provider` carries unit tests, and gating the module
// would compile them out.
pub(crate) mod gvproxy_network;
pub(crate) mod provider;

pub(crate) mod attach;
pub(crate) mod door;
// Whether a box's network policy can be enforced on this host.
pub(crate) mod endpoints;
pub(crate) mod engine;
pub mod ingress_gate;
pub(crate) mod listens;
pub(crate) mod nl;
pub(crate) mod relay;
pub(crate) mod resolver;
pub(crate) mod run_reports;
pub(crate) mod spec;
pub(crate) mod steer;

use std::collections::VecDeque;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, watch};

// The switch primitives live in the `switch` crate, which `minvmd` links too.
pub use ::switch::{DEFAULT_SUBNET, MacAddr, SwitchSubnet, render_gvproxy_config};

/// Whose gvproxy this daemon's switch is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SwitchTransport {
    /// A native node: the daemon spawns gvproxy and draws its own addresses.
    #[default]
    LocalSpawn,
    /// A VM guest: the VM host runs gvproxy, hands every address and holds
    /// the forwards. The daemon spawns nothing.
    VmHost,
}

/// How long to wait for gvproxy's control socket to appear after spawn.
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for gvproxy to exit after `SIGTERM` before escalating to
/// `SIGKILL`. Mirrors the vmm child teardown budget in `minvmd`.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// Errors produced while managing the gvproxy switch or allocating addresses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// The daemon's self-allocation reserve — the sub-run of the plan's PTask
    /// run a native daemon draws its task sandboxes and boxes from — has no
    /// address free: every one is held by a live attach, still inside its
    /// reuse quarantine, or a live ingress gate is still registered at it.
    #[error(
        "the self-allocation reserve on subnet {0} is exhausted; no daemon-side address is free"
    )]
    SubnetExhausted(SwitchSubnet),
    /// The host handed the box a switch address outside the plan's PTask run
    /// (T66): the daemon's subnet cannot honor it, and attaching with it
    /// would source frames from an address no row of the host-side table is
    /// keyed by.
    #[error("handed switch address {address} is outside the plan's PTask run on subnet {subnet}")]
    HandedAddressOutsidePlan {
        address: Ipv4Addr,
        subnet: SwitchSubnet,
    },
    /// The host handed the box a switch address an attach still holds (T66):
    /// the collision is refused, never shared. Every lease is withdrawn when
    /// its attach ends ([`IpAllocator::release`], via
    /// [`SwitchClient::detach`]), so the same box re-attaching — the
    /// re-attach an in-process host rebuild produces, where this allocator
    /// survives the rebuild — re-hands its own address instead of meeting
    /// this refusal.
    #[error("handed switch address {address} is already held by a lease (MAC {holder})")]
    HandedAddressCollision { address: Ipv4Addr, holder: MacAddr },
    /// The host handed the box a switch address inside this daemon's
    /// self-allocation reserve (T66) — the sub-run a native daemon draws
    /// from. Host and daemon keep disjoint sub-runs
    /// of the plan's PTask run (the daemon's half is [`self_allocation_run`],
    /// the host's mirror `minvmd`'s `box_registry::hand_out_run`), so a
    /// handed address inside the reserve means the two sides disagree about
    /// the split — a skewed pair, a misconfigured host. Attaching with it
    /// would put the box's tap beside the daemon's own draws; refused, never
    /// shared.
    #[error(
        "handed switch address {address} is inside this daemon's self-allocation reserve on subnet {subnet}"
    )]
    HandedAddressInReserve {
        address: Ipv4Addr,
        subnet: SwitchSubnet,
    },
    /// An attach on a switch the VM host owns asked this daemon to draw an
    /// address of its own (NET-138): once a control socket exists the host
    /// registers every box and task address, and the in-VM daemon draws
    /// nothing. The session predates host registration — its record carries
    /// no handed address for this attach — and must be re-activated.
    #[error(
        "this session predates host registration of its addresses, and the VM host no longer \
         lets the daemon draw one; destroy the session and re-activate it"
    )]
    SelfAllocationRetired,
    /// Every task address the host registered with the session's box
    /// (NET-138) is held by a task run still in progress: one task run
    /// attaches per address at a time.
    #[error("{slots} task runs already in progress for this session; wait for one to finish")]
    TaskSlotsBusy { slots: usize },
    /// A task run on a switch the VM host owns, for a box the host
    /// registered no task address with (NET-138): task addresses are
    /// best-effort, and the host files none while its hand-out run is near
    /// full — or the session predates them. The in-VM daemon draws nothing,
    /// so the run cannot attach.
    #[error(
        "this box has no task addresses on this host (the VM host registers up to {capacity} \
         per box, and registered none: its address run was nearly full when the box \
         registered, or the session predates task addresses); destroy the session and \
         re-activate it once other boxes have been destroyed"
    )]
    NoTaskAddresses { capacity: u8 },
    /// Spawning the gvproxy binary failed.
    #[error("spawning gvproxy at {path:?}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// gvproxy's control socket never appeared within [`SOCKET_READY_TIMEOUT`].
    #[error("gvproxy control socket {0:?} did not appear within {1:?}")]
    SocketTimeout(PathBuf, Duration),
    /// Writing the generated gvproxy YAML config failed.
    #[error("writing gvproxy config {path:?}: {source}")]
    WriteConfig {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// gvproxy exited before it was asked to stop.
    #[error("gvproxy exited unexpectedly (status {0:?})")]
    UnexpectedExit(Option<i32>),
    /// An I/O error not attributable to a more specific failure mode.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One PTask's place on the switch: an IP, its derived MAC, and the
/// allocation epoch it was handed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtaskLease {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    /// The allocator's hand count when this lease was made. An address
    /// handed again carries a new epoch, so equality names one hand of an
    /// address, never the address alone.
    pub epoch: u64,
}

/// The sub-run of `subnet`'s PTask run this daemon **self-allocates** from:
/// the run's lower half, `[first_ptask, midpoint]`, as an inclusive
/// `(first, last)` pair — the hand-out run above it keeps one address
/// more, a PTask run holding an odd number of addresses.
///
/// The plan's PTask run is split into two disjoint sub-runs so the two
/// allocators that draw on it cannot meet: a native daemon self-allocates
/// from the lower half, and the VM host daemon hands registered boxes and
/// their task addresses only from the upper half — the run above this
/// reserve. The host's half is the same midpoint rule mirrored in
/// `minvmd`'s `box_registry::hand_out_run`; one rule, two statements, so
/// change both together — each side's tests pin the default plan's split
/// literally.
///
/// A daemon whose switch is the VM host's ([`SwitchTransport::VmHost`])
/// draws nothing from it (NET-138): every own-address box arrives handed,
/// and every task run attaches at a task address registered with its box
/// ([`SwitchClient::attach_task_slot`]). [`SwitchClient::attach`] refuses
/// there with [`NetError::SelfAllocationRetired`].
#[must_use]
pub fn self_allocation_run(subnet: SwitchSubnet) -> (u32, u32) {
    let first = subnet.first_ptask();
    let last = subnet.last_ptask();
    let reserve_len = (last - first).div_ceil(2);
    (first, first + reserve_len - 1)
}

/// How long a released drawn address waits before it may be handed again.
///
/// It outlasts every record that can still name the address once its
/// holder is gone: a pin another box holds for it, which is asserted below
/// at compile time. Waiting out the quarantine is necessary
/// but not sufficient: [`IpAllocator`] also skips an address a live ingress
/// gate is still registered at.
///
/// The value is the switch crate's one quarantine
/// ([`::switch::SWITCH_ADDRESS_REUSE_QUARANTINE`]), shared with the VM host
/// daemon's hand-out run, so the two allocators that hand addresses on one
/// switch never wait out different spans.
pub const REUSE_QUARANTINE: Duration = ::switch::SWITCH_ADDRESS_REUSE_QUARANTINE;

// A pin a box holds for the address of a peer that is gone must have run
// out before another box gets the address.
#[cfg(target_os = "linux")]
const _: () = assert!(
    REUSE_QUARANTINE.as_millis() >= netpol::pins::PIN_TTL.as_millis(),
    "the reuse quarantine must outlast a pin for a peer's address"
);

/// Hands out switch addresses, each to one live attach at a time, and
/// reuses a released drawn one only under an allocation epoch and a
/// quarantine (R1.6).
///
/// Two allocation shapes: [`Self::allocate`] draws a self-allocation from
/// the plan run's lower half — the sub-run [`self_allocation_run`] reserves
/// for a native daemon — and [`Self::hand`] records the address the VM host
/// daemon handed a registered box or one of its task runs, from the upper
/// half. The two sub-runs are disjoint, so a self-allocation can never
/// spend a handed address, nor the reverse. A lease's life is its
/// attachment's, handed or drawn alike: it joins the static-lease table the
/// switch is configured from when the tap arrives and leaves with the attach
/// ([`Self::release`], via [`SwitchClient::detach`]), so the table holds only
/// live taps.
///
/// Every lease carries an allocation epoch, a counter that advances at each
/// hand, so a lease names one hand of its address rather than the address
/// alone. A release withdraws only the lease whose address *and* epoch it
/// names: a stale release from an address's previous holder withdraws
/// nothing of its next one.
///
/// A drawn address is reused, never shared. Release returns it to the
/// reserve's free queue, and [`Self::allocate`] hands it again only when
/// [`REUSE_QUARANTINE`] has passed since its release **and** no live ingress
/// gate is registered at it. Addresses are handed longest-free first: the
/// cursor's never-drawn addresses before any released one, then released
/// ones in release order, so the quarantine is the normal case rather than
/// the edge. A handed address, by contrast, is the registered box's — the
/// host-side row is keyed by it — and the same box re-attaching re-hands
/// it: that re-hand is the same row coming back, and the collision refusal
/// guards only an address an attach still holds.
///
/// Under a VM host no daemon-side draw happens (NET-138): every own-address
/// box and every task run arrives handed, and [`SwitchClient::attach`]
/// refuses to reach [`Self::allocate`] on a switch the host owns.
#[derive(Debug)]
pub struct IpAllocator {
    subnet: SwitchSubnet,
    /// This daemon's self-allocation reserve, inclusive — both bounds from
    /// [`self_allocation_run`]. `allocate` draws inside it and nothing else.
    reserve: (u32, u32),
    /// The next never-drawn host offset in the reserve; only ever advances.
    next: u32,
    /// Released drawn addresses with the instant each was released, oldest
    /// release first: the order [`Self::allocate`] reuses them in.
    released: VecDeque<(Ipv4Addr, Instant)>,
    /// The last allocation epoch handed; the next hand takes one more.
    epoch: u64,
    /// Every live lease, in allocation order. Doubles as the static-lease
    /// table written into gvproxy's config, which therefore holds only live
    /// taps: a lease leaves with its attach ([`Self::release`]), handed or
    /// drawn alike.
    leases: Vec<PtaskLease>,
}

impl IpAllocator {
    /// Creates an allocator over the given subnet, starting at the first
    /// allocatable PTask address.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        Self {
            next: subnet.first_ptask(),
            reserve: self_allocation_run(subnet),
            subnet,
            released: VecDeque::new(),
            epoch: 0,
            leases: Vec::new(),
        }
    }

    /// The subnet this allocator draws from.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// Allocates a free address and its derived MAC under a new epoch,
    /// drawing from the daemon's self-allocation reserve — the plan run's
    /// lower half.
    ///
    /// A never-drawn address is taken first, in order. Once the reserve has
    /// been drawn through, the released address free longest is reused,
    /// provided [`REUSE_QUARANTINE`] has passed since its release and no
    /// live ingress gate is registered at it.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::SubnetExhausted`] when no address in the reserve
    /// is free: every one is held, still quarantined, or still referenced.
    pub fn allocate(&mut self) -> Result<PtaskLease, NetError> {
        self.allocate_at(Instant::now(), |ip| ingress_gate::live_gate(ip).is_some())
    }

    /// [`Self::allocate`] at `now`, with `referenced` saying whether a live
    /// ingress gate is registered at an address — the clock and the check
    /// injected so the quarantine can be driven without waiting it out.
    fn allocate_at(
        &mut self,
        now: Instant,
        referenced: impl Fn(Ipv4Addr) -> bool,
    ) -> Result<PtaskLease, NetError> {
        let ip = if self.next <= self.reserve.1 {
            let ip = Ipv4Addr::from(self.next);
            self.next += 1;
            ip
        } else {
            let reusable = self.released.iter().position(|&(ip, released_at)| {
                now.saturating_duration_since(released_at) >= REUSE_QUARANTINE && !referenced(ip)
            });
            let Some((ip, _)) = reusable.and_then(|at| self.released.remove(at)) else {
                return Err(NetError::SubnetExhausted(self.subnet));
            };
            ip
        };
        Ok(self.record(ip))
    }

    /// Records a lease for `ip` under the next epoch.
    fn record(&mut self, ip: Ipv4Addr) -> PtaskLease {
        self.epoch += 1;
        let lease = PtaskLease {
            ip,
            mac: MacAddr::for_switch_ip(ip),
            epoch: self.epoch,
        };
        self.leases.push(lease);
        lease
    }

    /// Every live lease, oldest first.
    #[must_use]
    pub fn leases(&self) -> &[PtaskLease] {
        &self.leases
    }

    /// Records `ip` as the switch address a registered box attaches at (T66):
    /// the VM host daemon allocated it into its table and handed it back, so
    /// the daemon mints nothing. The lease joins [`Self::leases`] — the
    /// static-lease table the switch is configured from — under a new epoch,
    /// and leaves with the box's attach ([`Self::release`]), so the same box
    /// re-attaching re-hands it: the host's persisted row still holds the
    /// address, and detach never touches that row. A drawn lease
    /// ([`Self::allocate`]) leaves the same way, and its address is never
    /// handed here — it sits in the reserve, which this refuses.
    ///
    /// Three refusals, never a share:
    ///
    /// * an address outside the plan's PTask run
    ///   ([`NetError::HandedAddressOutsidePlan`]) — the subnet cannot honor
    ///   it;
    /// * an address inside this daemon's self-allocation reserve
    ///   ([`NetError::HandedAddressInReserve`]) — the host hands only from
    ///   the run above the reserve, so one there means the two sides
    ///   disagree about the split;
    /// * an address a recorded lease still holds
    ///   ([`NetError::HandedAddressCollision`]). What the refusal guards is
    ///   a live attach: the lease of an attach that ended is withdrawn
    ///   ([`Self::release`]), so the same box's re-attach re-hands its own
    ///   address instead of meeting this refusal.
    ///
    /// # Errors
    ///
    /// [`NetError::HandedAddressOutsidePlan`] when `ip` is outside the
    /// plan's PTask run: the address cannot be honored on this subnet.
    /// [`NetError::HandedAddressInReserve`] when `ip` is inside the daemon's
    /// self-allocation reserve. [`NetError::HandedAddressCollision`] when a
    /// recorded lease still holds `ip`.
    pub fn hand(&mut self, ip: Ipv4Addr) -> Result<PtaskLease, NetError> {
        let ip_num = u32::from(ip);
        if ip_num < self.subnet.first_ptask() || ip_num > self.subnet.last_ptask() {
            return Err(NetError::HandedAddressOutsidePlan {
                address: ip,
                subnet: self.subnet,
            });
        }
        let (reserve_first, reserve_last) = self.reserve;
        if (reserve_first..=reserve_last).contains(&ip_num) {
            return Err(NetError::HandedAddressInReserve {
                address: ip,
                subnet: self.subnet,
            });
        }
        if let Some(lease) = self.leases.iter().find(|lease| lease.ip == ip) {
            return Err(NetError::HandedAddressCollision {
                address: ip,
                holder: lease.mac,
            });
        }
        Ok(self.record(ip))
    }

    /// Withdraws `lease` — its address at its epoch — when the allocator
    /// holds it: the attachment ended, so the lease ends with it, handed or
    /// drawn alike. A lease from an earlier epoch of the same address
    /// withdraws nothing, so a stale release cannot end the address's
    /// current holder. A handed address is free for the same box to re-hand
    /// on the re-attach an in-process host rebuild or a restart produces
    /// (T66): the host's persisted row still holds it, and nothing here
    /// does. A drawn address joins the reserve's free queue, to be handed
    /// again under a new epoch once [`Self::allocate`]'s quarantine and
    /// reference check both pass.
    ///
    /// Returns whether a lease was withdrawn.
    pub(crate) fn release(&mut self, lease: PtaskLease) -> bool {
        self.release_at(lease, Instant::now())
    }

    /// [`Self::release`] at `now`, the clock injected as in
    /// [`Self::allocate_at`].
    fn release_at(&mut self, lease: PtaskLease, now: Instant) -> bool {
        let Some(at) = self.leases.iter().position(|held| *held == lease) else {
            return false;
        };
        self.leases.remove(at);
        let (reserve_first, reserve_last) = self.reserve;
        if (reserve_first..=reserve_last).contains(&u32::from(lease.ip)) {
            self.released.push_back((lease.ip, now));
        }
        true
    }
}

/// Why `binary` cannot be run as gvproxy, when it cannot. Asked when a box
/// with an address of its own is created, so the box is refused there and
/// not at its first start.
pub(crate) fn gvproxy_missing(binary: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt as _;

    let why = match std::fs::metadata(binary) {
        Ok(file) if file.is_file() && file.permissions().mode() & 0o111 != 0 => return None,
        Ok(_) => "is not a program".to_owned(),
        Err(error) => format!("cannot be read ({error})"),
    };
    Some(format!(
        "the box was not created: it asks for an address of its own, and this daemon has no \
         gvproxy to run the virtual network with: {} {why}. Install gvproxy there, or start \
         the daemon with `--gvproxy-bin`.",
        binary.display()
    ))
}

/// How a gvproxy process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ended {
    code: Option<i32>,
    /// For a log line and a box event.
    cause: String,
}

impl Ended {
    fn of(status: Option<std::process::ExitStatus>) -> Self {
        use std::os::unix::process::ExitStatusExt as _;

        let code = status.and_then(|status| status.code());
        let signal = status.and_then(|status| status.signal());
        let cause = match (code, signal) {
            (Some(code), _) => format!("gvproxy exited with status {code}"),
            (None, Some(signal)) => format!("gvproxy was killed by signal {signal}"),
            (None, None) => "gvproxy ended and left no status".to_owned(),
        };
        Self { code, cause }
    }
}

/// A gvproxy that ended without being asked to.
#[derive(Debug)]
pub(crate) struct Died {
    cause: String,
    /// How long it ran.
    ran: Duration,
}

/// A started gvproxy. A task of its own waits for the process, so the
/// daemon learns of its end when it happens and not at the next attach.
#[derive(Debug)]
struct Gvproxy {
    pid: u32,
    /// Asks the task to end the process.
    stop: Option<oneshot::Sender<()>>,
    /// How the process ended, once it has.
    ended: watch::Receiver<Option<Ended>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Gvproxy {
    fn drop(&mut self) {
        // The task holds the child, which is killed when dropped.
        self.task.abort();
    }
}

/// Waits for `child` to end. An end nobody asked for is reported on
/// `died`, once the gvproxy was `up`: whoever starts it sees for itself
/// that it never came up. A stop sends `SIGTERM`, and `SIGKILL` after
/// [`TERM_GRACE`].
async fn tend(
    mut child: Child,
    pid: u32,
    stop: oneshot::Receiver<()>,
    ended: watch::Sender<Option<Ended>>,
    up: Arc<std::sync::atomic::AtomicBool>,
    died: mpsc::UnboundedSender<Died>,
) {
    let started = Instant::now();
    tokio::select! {
        status = child.wait() => {
            let end = Ended::of(status.ok());
            let cause = end.cause.clone();
            ended.send_replace(Some(end));
            if up.load(std::sync::atomic::Ordering::SeqCst) {
                // Nobody listens in a daemon that does not supervise its
                // switch.
                let _unsupervised = died.send(Died { cause, ran: started.elapsed() });
            }
        }
        // A dropped sender is a stop as well: nobody holds the switch.
        _ = stop => {
            tracing::info!(pid, "stopping gvproxy switch (SIGTERM)");
            if let Ok(pid) = libc::pid_t::try_from(pid) {
                // SAFETY: the signal goes to the child this task still owns
                // and has not reaped, so the pid is that child's.
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
            let status = match tokio::time::timeout(TERM_GRACE, child.wait()).await {
                Ok(status) => status.ok(),
                Err(_) => {
                    tracing::warn!("gvproxy did not exit after SIGTERM; sending SIGKILL");
                    let _gone = child.start_kill();
                    child.wait().await.ok()
                }
            };
            tracing::info!(?status, "gvproxy switch stopped");
            ended.send_replace(Some(Ended::of(status)));
        }
    }
}

/// The virtual network went away under attached boxes.
#[derive(Debug, Clone)]
struct Outage {
    since: Instant,
    cause: String,
}

/// What happened to the virtual network under the boxes attached to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UplinkChange {
    /// gvproxy ended by itself, was started again, and holds the boxes'
    /// forwards again.
    Restored {
        cause: String,
        offline: Duration,
        /// The forwards the new gvproxy took, and those it refused.
        forwards: usize,
        forwards_failed: usize,
    },
    /// gvproxy keeps dying and is not started again until a box attaches.
    Down { cause: String, starts: u32 },
}

/// Told of every [`UplinkChange`].
#[derive(Clone)]
pub(crate) struct UplinkWatch(Arc<dyn Fn(&UplinkChange) + Send + Sync>);

impl UplinkWatch {
    pub(crate) fn new(told: impl Fn(&UplinkChange) + Send + Sync + 'static) -> Self {
        Self(Arc::new(told))
    }
}

impl std::fmt::Debug for UplinkWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UplinkWatch")
    }
}

/// The switch is reference-counted against the set of attached `OwnIp` PTasks:
/// it is spawned lazily on the first attach and torn down after the last
/// detach. Teardown follows the same `SIGTERM` → grace → `SIGKILL` escalation
/// the vmm child uses.
///
/// A gvproxy that ends by itself while boxes are attached is started again
/// ([`Self::supervise`]). The frame pump of each box redials by itself.
#[derive(Debug)]
pub struct SwitchClient {
    /// Path to the pinned gvproxy binary (see `scripts/fetch-gvproxy.sh`).
    binary: PathBuf,
    /// Directory for the generated config, control socket, and pid file.
    state_dir: PathBuf,
    /// The address book; also the source of the static-lease table.
    allocator: IpAllocator,
    /// Number of attached PTasks; the switch runs while this is non-zero.
    attached: usize,
    /// The running gvproxy, if started. Always `None` in
    /// [`SwitchTransport::VmHost`] mode (the host owns gvproxy).
    gvproxy: Option<Gvproxy>,
    /// Where a gvproxy's own end is reported, and the receiving side until
    /// [`Self::watched`] hands it to the supervising task.
    died: mpsc::UnboundedSender<Died>,
    deaths: Option<mpsc::UnboundedReceiver<Died>>,
    /// Set from gvproxy's death under attached boxes until a gvproxy runs
    /// for them again.
    outage: Option<Outage>,
    /// The forwards gvproxy holds for boxes. A new gvproxy gets them back.
    forwards: Arc<policy::Forwards>,
    /// Who is told what happened to the boxes' network.
    watch: Option<UplinkWatch>,
    /// Whose gvproxy the switch is: spawned here (DM2) or the VM host's
    /// (DM1/3/4).
    transport: SwitchTransport,
    /// Which daemon instance this switch belongs to, as a hostname label:
    /// the daemon's own id, which its hostname registry answers under.
    /// Defaults to the single-daemon id `local`.
    host_id: String,
    /// Whether [`Self::attach`] may draw on a [`SwitchTransport::VmHost`]
    /// switch: never in production (NET-138), and only for a test that
    /// drives the draw path over a VM-host switch without a host to hand it
    /// addresses ([`Self::allowing_self_allocation`]).
    #[cfg(test)]
    allow_self_allocation: bool,
}

impl SwitchClient {
    /// A switch supervisor over the default subnet, for a test.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(binary: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self::with_subnet(binary, state_dir, DEFAULT_SUBNET)
    }

    /// Builds a switch supervisor over `subnet`. Does not spawn anything;
    /// the first [`attach`](Self::attach) starts gvproxy.
    #[must_use]
    pub fn with_subnet(
        binary: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        subnet: SwitchSubnet,
    ) -> Self {
        let (died, deaths) = mpsc::unbounded_channel();
        Self {
            binary: binary.into(),
            state_dir: state_dir.into(),
            allocator: IpAllocator::new(subnet),
            attached: 0,
            gvproxy: None,
            died,
            deaths: Some(deaths),
            outage: None,
            forwards: Arc::default(),
            watch: None,
            transport: SwitchTransport::default(),
            host_id: crate::net::dns::DEFAULT_HOST_ID.to_owned(),
            #[cfg(test)]
            allow_self_allocation: false,
        }
    }

    /// Sets a host id label other than the single-daemon default. The
    /// daemon passes its own instance id, which its hostname registry
    /// answers under.
    #[must_use]
    pub fn with_host_id(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = host_id.into();
        self
    }

    /// The host id label of this daemon instance.
    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Names who is told when the boxes' network went away and came back.
    /// Returns the ends of gvproxy for [`Self::supervise`], once.
    pub(crate) fn watched(&mut self, watch: UplinkWatch) -> Option<mpsc::UnboundedReceiver<Died>> {
        self.watch = Some(watch);
        self.deaths.take()
    }

    /// Starts gvproxy again whenever it ends by itself while boxes are
    /// attached, until `switch` is dropped. Each start waits longer than
    /// the one before, and a gvproxy that keeps dying is left down
    /// ([`::switch::restart::Restarts`]). Must be called on the runtime.
    pub(crate) fn supervise(
        switch: &Arc<tokio::sync::Mutex<Self>>,
        deaths: mpsc::UnboundedReceiver<Died>,
    ) {
        crate::traced::spawn_detached(
            tracing::info_span!(parent: None, "net.switch.supervise"),
            revive(
                Arc::downgrade(switch),
                deaths,
                ::switch::restart::Restarts::gvproxy(),
            ),
        );
    }

    /// The forwards this node's gvproxy holds.
    pub(crate) fn forwards(&self) -> Arc<policy::Forwards> {
        Arc::clone(&self.forwards)
    }

    /// Sets whose gvproxy the switch is. The DM2 default is
    /// [`SwitchTransport::LocalSpawn`]; in a libkrun VM (DM1/3/4) the caller sets
    /// [`SwitchTransport::VmHost`] so this `minimald` uses the host-owned
    /// gvproxy instead of spawning one in-guest.
    #[must_use]
    pub fn with_transport(mut self, transport: SwitchTransport) -> Self {
        self.transport = transport;
        self
    }

    /// Lets [`Self::attach`] draw on a [`SwitchTransport::VmHost`]
    /// switch, for a test of the draw path that has no host to hand it
    /// addresses. Production has no such switch (NET-138).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn allowing_self_allocation(mut self) -> Self {
        self.allow_self_allocation = true;
        self
    }

    /// Whether this switch may draw an address of its own: only when it
    /// spawns its own gvproxy, the native shape (NET-102). A switch the VM
    /// host owns draws nothing (NET-138).
    fn self_allocates(&self) -> bool {
        #[cfg(test)]
        if self.allow_self_allocation {
            return true;
        }
        matches!(self.transport, SwitchTransport::LocalSpawn)
    }

    /// Whose gvproxy this switch is.
    #[must_use]
    pub fn transport(&self) -> SwitchTransport {
        self.transport
    }

    /// How many `OwnIp` PTasks are attached; the switch runs while non-zero.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn attached(&self) -> usize {
        self.attached
    }

    /// The control socket path gvproxy listens on (host side only).
    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        self.state_dir.join("gvproxy-api.sock")
    }

    /// The subnet this switch hands PTask addresses out of. The launcher needs
    /// it to render a lease's CIDR and the gateway when configuring a tap.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.allocator.subnet()
    }

    /// Every lease this switch knows — self-allocated and handed (T66)
    /// alike, oldest first — the table the generated config is written
    /// from. A diagnostic surface for the addresses the switch has handed
    /// out and which shape of attach took them, without reaching into the
    /// allocator.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn leases(&self) -> &[PtaskLease] {
        self.allocator.leases()
    }

    fn config_path(&self) -> PathBuf {
        self.state_dir.join("gvproxy.yaml")
    }

    fn pid_path(&self) -> PathBuf {
        self.state_dir.join("gvproxy.pid")
    }

    fn token_path(&self) -> PathBuf {
        self.state_dir.join(::switch::api_token::FILE)
    }

    /// The arguments gvproxy is started with. The token file closes its
    /// API at the gateway address to the boxes ([`::switch::api_token`]).
    fn argv(&self) -> Vec<std::ffi::OsString> {
        vec![
            "-config".into(),
            self.config_path().into(),
            "-listen".into(),
            format!("unix://{}", self.control_socket().display()).into(),
            "-pid-file".into(),
            self.pid_path().into(),
            // gvproxy's own default forward targets an address that is not
            // on this subnet.
            "-ssh-port".into(),
            "-1".into(),
            ::switch::api_token::FLAG.into(),
            self.token_path().into(),
        ]
    }

    /// Allocates an address for a new PTask, (re)writes the config, ensures
    /// gvproxy is running, and bumps the attach count.
    ///
    /// Returns the allocated lease.
    ///
    /// Only a native switch draws ([`SwitchTransport::LocalSpawn`],
    /// NET-102). On a switch the VM host owns, every address is the host's
    /// to hand (NET-138) — a box's at [`Self::attach_handed`], a task
    /// run's at [`Self::attach_task_slot`] — and a draw is refused.
    ///
    /// # Errors
    ///
    /// [`NetError::SelfAllocationRetired`] on a
    /// [`SwitchTransport::VmHost`] switch; propagates config-write,
    /// spawn, and socket-readiness failures.
    pub async fn attach(&mut self) -> Result<PtaskLease, NetError> {
        if !self.self_allocates() {
            return Err(NetError::SelfAllocationRetired);
        }
        let lease = self.allocator.allocate()?;
        self.start_for(lease).await?;
        tracing::info!(
            ip = %lease.ip,
            mac = %lease.mac,
            epoch = lease.epoch,
            attached = self.attached,
            "attached OwnIp PTask to gvproxy switch"
        );
        Ok(lease)
    }

    /// Counts `lease` as attached, with gvproxy running for it where this
    /// daemon runs gvproxy itself. A VM host runs its own. When gvproxy
    /// does not start, the lease is given back: an attach that failed
    /// holds no address.
    async fn start_for(&mut self, lease: PtaskLease) -> Result<(), NetError> {
        if matches!(self.transport, SwitchTransport::LocalSpawn) {
            let started = match self.write_config().await {
                Ok(()) => self.ensure_running().await,
                Err(error) => Err(error),
            };
            if let Err(error) = started {
                self.allocator.release(lease);
                return Err(error);
            }
        }
        self.attached += 1;
        Ok(())
    }

    /// Attaches a PTask at the switch address the VM host handed its box,
    /// and draws nothing. The lease joins the static-lease table
    /// ([`IpAllocator::hand`]) and leaves with the attach
    /// ([`Self::detach`]), so the same box re-attaches at the same address.
    /// The address is the one the create request carries. This daemon does
    /// not check it against the host's row. The spawn steps and the attach
    /// count are those of [`Self::attach`].
    ///
    /// # Errors
    ///
    /// [`NetError::HandedAddressOutsidePlan`] when the host handed an
    /// address this daemon's subnet cannot honor,
    /// [`NetError::HandedAddressInReserve`] when it handed one from the
    /// daemon's own self-allocation reserve, and
    /// [`NetError::HandedAddressCollision`] when an attach still holds the
    /// handed address; propagates config-write, spawn, and socket-readiness
    /// failures as [`Self::attach`] does.
    pub async fn attach_handed(&mut self, handed: Ipv4Addr) -> Result<PtaskLease, NetError> {
        let lease = self.allocator.hand(handed)?;
        self.start_for(lease).await?;
        tracing::info!(
            ip = %lease.ip,
            mac = %lease.mac,
            epoch = lease.epoch,
            attached = self.attached,
            "attached OwnIp PTask to gvproxy switch at its handed address"
        );
        Ok(lease)
    }

    /// Attaches a task run at one of the task addresses the host registered
    /// with its session's box (NET-138): the first of `slots` no attach
    /// holds, through [`Self::attach_handed`]. A slot frees when the task
    /// run that held it detaches, so the session's runs in progress are
    /// exactly the slots the switch's live leases hold, and no other state
    /// is kept.
    ///
    /// No slots at all is the plain [`Self::attach`] on a native switch,
    /// which draws; a switch the VM host owns refuses it with
    /// [`NetError::NoTaskAddresses`] — the session's registration handed
    /// none (task addresses are best-effort), or it predates them.
    ///
    /// # Errors
    ///
    /// [`NetError::TaskSlotsBusy`] when every slot is held,
    /// [`NetError::NoTaskAddresses`] as above; otherwise what
    /// [`Self::attach_handed`] or [`Self::attach`] returns.
    pub async fn attach_task_slot(&mut self, slots: &[Ipv4Addr]) -> Result<PtaskLease, NetError> {
        if slots.is_empty() {
            if !self.self_allocates() {
                return Err(NetError::NoTaskAddresses {
                    capacity: minimald_rpc::TASK_SLOTS_PER_BOX,
                });
            }
            return self.attach().await;
        }
        for &slot in slots {
            match self.attach_handed(slot).await {
                Err(NetError::HandedAddressCollision { .. }) => {}
                attached => return attached,
            }
        }
        Err(NetError::TaskSlotsBusy { slots: slots.len() })
    }

    /// Records that a PTask detached, withdrawing its lease with it (T66):
    /// a lease's life is its attachment's, handed or drawn alike — a task
    /// sandbox's self-drawn address ends with the sandbox the way a
    /// registered box's handed one ends with the box's attach. The handed
    /// address is the registered box's, keyed by the host-side row, so once
    /// the box's attach ends the same box re-attaching re-hands it — the
    /// collision refusal then guards only an address an attach still holds.
    /// A drawn address goes back to the reserve's free queue, handed again
    /// only under a new epoch, after the reuse quarantine, and once nothing
    /// still names it (R1.6); see [`IpAllocator::release`]. A lease from an
    /// earlier epoch than the address's current one releases nothing. When
    /// the last one leaves, the switch is stopped.
    ///
    /// # Errors
    ///
    /// Propagates teardown failures from [`stop`](Self::stop).
    pub async fn detach(&mut self, released: PtaskLease) -> Result<(), NetError> {
        self.attached = self.attached.saturating_sub(1);
        if self.allocator.release(released) {
            tracing::debug!(
                ip = %released.ip,
                epoch = released.epoch,
                "released the lease with the attach"
            );
        }
        tracing::info!(attached = self.attached, "detached OwnIp PTask from switch");
        if self.attached == 0 {
            // No box is left to restore the network for.
            self.outage = None;
            self.stop().await?;
        }
        Ok(())
    }

    async fn write_config(&self) -> Result<(), NetError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(|source| NetError::WriteConfig {
                path: self.state_dir.clone(),
                source,
            })?;
        let path = self.config_path();
        let leases: Vec<_> = self
            .allocator
            .leases()
            .iter()
            .map(|l| (l.ip, l.mac))
            .collect();
        let body = render_gvproxy_config(self.allocator.subnet(), &leases);
        tokio::fs::write(&path, body)
            .await
            .map_err(|source| NetError::WriteConfig { path, source })
    }

    /// Forgets a gvproxy that has ended. With boxes attached their network
    /// is down from here on, until [`Self::restore`] after the next start.
    fn forget_ended(&mut self) {
        let Some(running) = &self.gvproxy else {
            return;
        };
        let Some(ended) = running.ended.borrow().clone() else {
            return;
        };
        tracing::error!(
            pid = running.pid,
            cause = %ended.cause,
            attached = self.attached,
            "gvproxy ended by itself"
        );
        self.gvproxy = None;
        if self.attached > 0 && self.outage.is_none() {
            self.outage = Some(Outage {
                since: Instant::now(),
                cause: ended.cause,
            });
        }
    }

    /// Starts gvproxy if it is not running and waits for its control socket
    /// to accept. A start that follows gvproxy's own end restores what the
    /// attached boxes had.
    async fn ensure_running(&mut self) -> Result<(), NetError> {
        self.forget_ended();
        if self.gvproxy.is_some() {
            return Ok(());
        }
        self.start().await?;
        self.restore().await;
        Ok(())
    }

    async fn start(&mut self) -> Result<(), NetError> {
        let sock = self.control_socket();
        // A stale socket from a previous run blocks gvproxy's own bind. If it
        // cannot be cleared, fail now rather than let `wait_for_socket` mistake
        // the leftover path for a freshly-bound one and report a switch that
        // never actually came up.
        match tokio::fs::remove_file(&sock).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(NetError::Io(e)),
        }

        // A new token for each start. A blocking write of one small file.
        ::switch::api_token::write(&self.token_path()).map_err(|source| NetError::WriteConfig {
            path: self.token_path(),
            source,
        })?;
        let mut cmd = Command::new(&self.binary);
        crate::box_cgroups::place_helper(cmd.as_std_mut());
        cmd.args(self.argv())
            .env_remove(::switch::api_token::ENV)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The task that waits for the child holds it. A task that is
        // dropped without a stop takes gvproxy with it.
        cmd.kill_on_drop(true);

        tracing::info!(binary = %self.binary.display(), socket = %sock.display(), "spawning gvproxy switch");
        let child = cmd.spawn().map_err(|source| NetError::Spawn {
            path: self.binary.clone(),
            source,
        })?;
        let pid = child.id().unwrap_or_default();
        let (stop, stopped) = oneshot::channel();
        let (ended_tx, ended) = watch::channel(None);
        let up = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task = crate::traced::spawn_detached(
            tracing::info_span!(parent: None, "net.switch.gvproxy", pid),
            tend(
                child,
                pid,
                stopped,
                ended_tx,
                Arc::clone(&up),
                self.died.clone(),
            ),
        );
        self.gvproxy = Some(Gvproxy {
            pid,
            stop: Some(stop),
            ended,
            task,
        });

        // If the control socket never appears, tear the half-started child down
        // so its timeout cannot leave gvproxy orphaned and a later attach does
        // not connect to a process that never bound.
        if let Err(e) = self.wait_for_socket(&sock).await {
            let _ = self.stop().await;
            return Err(e);
        }
        // From here its end is the supervisor's to act on. One that ended
        // between the socket's answer and this line never came up.
        up.store(true, std::sync::atomic::Ordering::SeqCst);
        let ended = self
            .gvproxy
            .as_ref()
            .and_then(|running| running.ended.borrow().clone());
        if let Some(ended) = ended {
            self.gvproxy = None;
            return Err(NetError::UnexpectedExit(ended.code));
        }
        Ok(())
    }

    /// After a start that follows gvproxy's own end under attached boxes:
    /// gives the new gvproxy the forwards the old one held and tells who
    /// watches. The boxes' frame pumps redial by themselves.
    async fn restore(&mut self) {
        let Some(outage) = self.outage.take() else {
            return;
        };
        let (forwards, forwards_failed) = self.forwards.replay(&self.control_socket()).await;
        let offline = outage.since.elapsed();
        tracing::info!(
            cause = %outage.cause,
            offline_ms = u64::try_from(offline.as_millis()).unwrap_or(u64::MAX),
            attached = self.attached,
            forwards,
            forwards_failed,
            "gvproxy is up again and holds the boxes' forwards"
        );
        self.tell(&UplinkChange::Restored {
            cause: outage.cause,
            offline,
            forwards,
            forwards_failed,
        });
    }

    /// Leaves gvproxy down after `starts` starts that did not last. The
    /// outage stays on record: the start a later attach makes restores the
    /// boxes that are still attached.
    fn give_up(&self, starts: u32) {
        let cause = self
            .outage
            .as_ref()
            .map_or_else(|| "gvproxy ended".to_owned(), |outage| outage.cause.clone());
        tracing::error!(
            %cause,
            starts,
            attached = self.attached,
            "gvproxy keeps dying and is not started again; the boxes attached to it have no \
             network until a box attaches and gvproxy stays up"
        );
        self.tell(&UplinkChange::Down { cause, starts });
    }

    fn tell(&self, change: &UplinkChange) {
        if let Some(UplinkWatch(told)) = &self.watch {
            told(change);
        }
    }

    async fn wait_for_socket(&mut self, sock: &Path) -> Result<(), NetError> {
        let deadline = tokio::time::Instant::now() + SOCKET_READY_TIMEOUT;
        loop {
            // Probe with an actual connect rather than just checking file
            // existence: bind() creates the socket file before listen() is
            // called, so sock.exists() can return true while ECONNREFUSED
            // would still occur on the first connect, on a scheduler stall
            // between gvproxy's bind and listen.
            match tokio::net::UnixStream::connect(sock).await {
                Ok(_) => return Ok(()),
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        || e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(NetError::Io(e)),
            }
            // If gvproxy died during startup, surface its status rather than
            // spinning until the timeout.
            let ended = self
                .gvproxy
                .as_ref()
                .and_then(|running| running.ended.borrow().clone());
            if let Some(ended) = ended {
                self.gvproxy = None;
                return Err(NetError::UnexpectedExit(ended.code));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetError::SocketTimeout(
                    sock.to_path_buf(),
                    SOCKET_READY_TIMEOUT,
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Stops gvproxy with `SIGTERM`, escalating to `SIGKILL` after [`TERM_GRACE`].
    ///
    /// # Errors
    ///
    /// None today. The signature is the one its callers handle.
    pub async fn stop(&mut self) -> Result<(), NetError> {
        let Some(mut running) = self.gvproxy.take() else {
            return Ok(());
        };
        if let Some(stop) = running.stop.take() {
            // The task is gone when gvproxy ended by itself.
            let _ended = stop.send(());
        }
        // The task ends the process and reaps it within the grace.
        let _reaped = (&mut running.task).await;
        let _ = tokio::fs::remove_file(self.control_socket()).await;
        let _ = tokio::fs::remove_file(self.token_path()).await;
        Ok(())
    }
}

/// The supervising task of [`SwitchClient::supervise`].
async fn revive(
    switch: Weak<tokio::sync::Mutex<SwitchClient>>,
    mut deaths: mpsc::UnboundedReceiver<Died>,
    mut restarts: ::switch::restart::Restarts,
) {
    while let Some(died) = deaths.recv().await {
        let mut wait = restarts.died(died.ran);
        loop {
            let Some(switch) = switch.upgrade() else {
                return;
            };
            {
                let mut switch = switch.lock().await;
                switch.forget_ended();
                // An attach started it meanwhile, or no box is left.
                if switch.gvproxy.is_some() || switch.attached == 0 {
                    break;
                }
                if wait.is_none() {
                    switch.give_up(restarts.starts());
                    break;
                }
            }
            // The switch is free while this waits, so an attach is not held up.
            tokio::time::sleep(wait.unwrap_or_default()).await;
            let mut switch = switch.lock().await;
            switch.forget_ended();
            if switch.gvproxy.is_some() || switch.attached == 0 {
                break;
            }
            let started = match switch.write_config().await {
                Ok(()) => switch.start().await,
                Err(error) => Err(error),
            };
            match started {
                Ok(()) => {
                    switch.restore().await;
                    break;
                }
                Err(error) => {
                    tracing::warn!(%error, died = %died.cause, "gvproxy was not started again");
                    if let Some(outage) = switch.outage.as_mut() {
                        outage.cause = format!("{}; then: {error}", died.cause);
                    }
                    wait = restarts.failed_to_start();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_subnet_is_rfc6598_slash16() {
        let s = SwitchSubnet::default();
        assert_eq!(s.to_string(), "100.64.0.0/16");
        assert_eq!(s.gateway(), Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(s.broadcast(), Ipv4Addr::new(100, 64, 255, 255));
        assert_eq!(s.host_alias(), Ipv4Addr::new(100, 64, 255, 254));
    }

    #[test]
    fn allocate_yields_unique_sequential_addresses() {
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let first = a.allocate().unwrap();
        let second = a.allocate().unwrap();
        assert_eq!(first.ip, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(second.ip, Ipv4Addr::new(100, 64, 0, 3));
        assert_ne!(first.ip, second.ip);
        assert_eq!(a.leases().len(), 2);
    }

    #[test]
    fn allocate_never_shares_an_address_between_live_leases() {
        // Live leases never share an address, and each hand is a new epoch.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let one = a.allocate().unwrap();
        let two = a.allocate().unwrap();
        let three = a.allocate().unwrap();
        assert!(one.ip < two.ip && two.ip < three.ip);
        assert!(one.epoch < two.epoch && two.epoch < three.epoch);
    }

    #[test]
    fn mac_is_derived_deterministically_from_ip() {
        // 52:54:00 OUI followed by the low three octets of 100.64.0.2 in hex:
        // 64 -> 0x40, 0 -> 0x00, 2 -> 0x02.
        let ip = Ipv4Addr::new(100, 64, 0, 2);
        assert_eq!(MacAddr::for_switch_ip(ip).to_string(), "52:54:00:40:00:02");
        // Stable across calls.
        assert_eq!(MacAddr::for_switch_ip(ip), MacAddr::for_switch_ip(ip));
    }

    #[test]
    fn allocator_exhausts_a_tiny_subnet() {
        // /29 => 8 addresses; network, gateway, daemon, host-alias and
        // broadcast reserved, leaving three allocatable hosts (.2 to .4).
        // The run's ends are the switch crate's, read rather than restated:
        // the run splits at its midpoint, so this daemon's reserve is .2
        // alone and the host's hand-out run is .3 and .4 — exhaustion is
        // explicit on each side while every address is held.
        let subnet = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        let first = Ipv4Addr::from(subnet.first_ptask());
        let last = Ipv4Addr::from(subnet.last_ptask());
        assert_eq!(
            (first, last),
            (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 4))
        );
        let mut a = IpAllocator::new(subnet);
        assert_eq!(a.allocate().unwrap().ip, first);
        assert!(matches!(a.allocate(), Err(NetError::SubnetExhausted(_))));
        // The reserve bounds only the daemon's draws: the run's remainder is
        // still there for the host's hand-outs, none of them ever drawn.
        a.hand(last).unwrap();
        assert!(matches!(
            a.hand(last),
            Err(NetError::HandedAddressCollision { .. })
        ));
        // The address above the run is the node's, outside the plan's run.
        assert!(matches!(
            a.hand(subnet.daemon_ip()),
            Err(NetError::HandedAddressOutsidePlan { .. })
        ));
    }

    #[test]
    fn self_allocation_run_splits_the_plan_ptask_run() {
        // The default plan's split, pinned literally: the daemon's reserve
        // is the PTask run's lower half and the host hands registered boxes
        // from the run above it. The mirror is `minvmd`'s
        // `box_registry::hand_out_run` — one rule, two statements; change
        // both together.
        let subnet = SwitchSubnet::default();
        let (reserve_first, reserve_last) = self_allocation_run(subnet);
        assert_eq!(
            (reserve_first, reserve_last),
            (
                u32::from(Ipv4Addr::new(100, 64, 0, 2)),
                u32::from(Ipv4Addr::new(100, 64, 127, 254)),
            ),
            "the reserve is the run's lower half, starting at the first PTask address"
        );
        assert_eq!(
            reserve_last + 1,
            u32::from(Ipv4Addr::new(100, 64, 127, 255)),
            "the host's hand-out run starts immediately above the reserve"
        );
        assert!(
            subnet.first_ptask() <= reserve_first && reserve_last < subnet.last_ptask(),
            "both sub-runs are inside the plan's PTask run, and neither is empty"
        );
        // A tiny subnet splits in half, so both sides keep at least one
        // address: a /29's two PTask addresses give the reserve .2 and the
        // hand-out run .3.
        let tiny = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        assert_eq!(
            self_allocation_run(tiny),
            (
                u32::from(Ipv4Addr::new(10, 0, 0, 2)),
                u32::from(Ipv4Addr::new(10, 0, 0, 2)),
            )
        );
    }

    #[test]
    fn hand_refuses_an_address_in_the_self_allocation_reserve() {
        // The host hands registered boxes only from the run above this
        // daemon's self-allocation reserve, so an address inside the reserve
        // means the two sides disagree about the split — a skewed pair, a
        // misconfigured host. Refused, never attached beside the daemon's
        // own draws: the sequence a shared run once allowed, a task sandbox
        // self-allocating an address a box is then handed, ends at the
        // refusal.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let task = a.allocate().unwrap();
        assert_eq!(task.ip, Ipv4Addr::new(100, 64, 0, 2));
        let err = a.hand(task.ip).unwrap_err();
        assert!(
            matches!(
                err,
                NetError::HandedAddressInReserve { address, .. } if address == task.ip
            ),
            "handing a reserve address is refused, held or not"
        );
        // The refusal is positional, not lease-dependent: an unheld reserve
        // address refuses the same way, and a refusal records nothing — the
        // table holds the task's draw alone.
        assert!(matches!(
            a.hand(Ipv4Addr::new(100, 64, 64, 128)),
            Err(NetError::HandedAddressInReserve { .. })
        ));
        assert_eq!(a.leases().len(), 1, "a refusal adds no lease");
        // The task's address stays the task's: the next draw takes the
        // reserve's next address, never the refused one again.
        assert_eq!(a.allocate().unwrap().ip, Ipv4Addr::new(100, 64, 0, 3));
    }

    #[test]
    fn hand_refuses_an_address_a_local_lease_holds() {
        // An address a recorded lease still holds refuses a second hand.
        // What the refusal guards is a live attach:
        // `handed_lease_releases_on_detach_and_the_box_rehands` covers the
        // release that lets the same box re-attach. With the run split, a
        // locally-drawn lease always sits in the daemon's reserve
        // (`hand_refuses_an_address_in_the_self_allocation_reserve` refuses
        // that shape outright), so the lease this one exercises is a handed
        // one — the same refusal rule.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let box_a = a.hand(Ipv4Addr::new(100, 64, 127, 255)).unwrap();
        // A task's sandbox self-allocates beside it, from the reserve...
        let task = a.allocate().unwrap();
        assert_eq!(task.ip, Ipv4Addr::new(100, 64, 0, 2));
        // ...and handing the box's address again is refused with the holder
        // named. The refusal changes nothing: no duplicate joined the table,
        // and handing the same address again refuses just the same — the
        // address stays with its holder while its attach lives.
        let err = a.hand(box_a.ip).unwrap_err();
        assert!(
            matches!(
                err,
                NetError::HandedAddressCollision { address, holder }
                    if address == box_a.ip && holder == box_a.mac
            ),
            "handing a lease's address is refused with the holder named"
        );
        assert_eq!(a.leases().len(), 2);
        assert!(matches!(
            a.hand(box_a.ip),
            Err(NetError::HandedAddressCollision { .. })
        ));
    }

    #[test]
    fn handed_lease_releases_on_detach_and_the_box_rehands() {
        // T66's re-attach: a lease — handed or drawn alike — leaves the
        // table when its attach ends, so the same box re-attaching — the
        // re-attach an in-process host rebuild produces, where this
        // allocator survives the rebuild — re-hands its own address instead
        // of meeting the collision refusal.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let handed_ip = Ipv4Addr::new(100, 64, 128, 9);
        let lease = a
            .hand(handed_ip)
            .expect("the hand-out run's address is handed");
        assert_eq!(a.leases().len(), 1);

        // A drawn lease leaves the same way — a task sandbox's self-drawn
        // address ends with its sandbox — and the next draw takes a
        // never-drawn address before the withdrawn one (longest free first).
        let task = a.allocate().unwrap();
        assert!(a.release(task), "the drawn lease is withdrawn");
        assert_eq!(a.leases(), &[lease], "only the handed lease remains");
        let redrawn = a.allocate().unwrap();
        assert_eq!(
            redrawn.ip,
            Ipv4Addr::new(100, 64, 0, 3),
            "a never-drawn address goes before the withdrawn one"
        );
        // A lease the allocator never recorded releases nothing.
        let stranger = Ipv4Addr::new(100, 64, 200, 1);
        assert!(!a.release(PtaskLease {
            ip: stranger,
            mac: MacAddr::for_switch_ip(stranger),
            epoch: 1,
        }));
        assert_eq!(a.leases().len(), 2);

        // A handed address an attach still holds refuses a second hand: the
        // refusal guards a live attach, and the lease's withdrawal is what
        // lets the re-attach through.
        assert!(matches!(
            a.hand(handed_ip),
            Err(NetError::HandedAddressCollision { .. })
        ));

        // The handed lease releases, and the re-hand records the same lease
        // again — the same address, the same derived MAC, the same row the
        // host-side table is keyed by — beside the draw that replaced the
        // withdrawn one.
        assert!(a.release(lease));
        assert_eq!(
            a.leases(),
            &[redrawn],
            "the table holds the live draw alone"
        );
        let rehanded = a
            .hand(handed_ip)
            .expect("the same box re-attaching re-hands its own address");
        assert_eq!(rehanded.ip, lease.ip);
        assert_eq!(rehanded.mac, lease.mac);
        assert!(rehanded.epoch > lease.epoch, "the re-hand is a new epoch");
    }

    #[test]
    fn config_contains_subnet_gateway_and_leases() {
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let lease = a.allocate().unwrap();
        let leases: Vec<_> = a.leases().iter().map(|l| (l.ip, l.mac)).collect();
        let cfg = render_gvproxy_config(a.subnet(), &leases);
        assert!(cfg.contains("subnet: \"100.64.0.0/16\""));
        assert!(cfg.contains("gatewayIP: \"100.64.0.1\""));
        assert!(cfg.contains(&format!("\"{}\": \"{}\"", lease.ip, lease.mac)));
        // The switch gives the virtual network no way to the host's
        // loopback and answers no zone: the host alias is reached through
        // the daemon, and the daemon's resolver answers box names.
        assert!(!cfg.contains("127.0.0.1"), "{cfg}");
        assert!(!cfg.contains("100.64.255.254"), "{cfg}");
        assert!(!cfg.contains("min.internal"), "{cfg}");
    }

    #[test]
    fn empty_config_still_emits_a_lease_map() {
        let cfg = render_gvproxy_config(SwitchSubnet::default(), &[]);
        assert!(cfg.contains("dhcpStaticLeases:"));
        assert!(cfg.contains("{}"));
    }

    #[test]
    fn transport_defaults_to_local_spawn() {
        let switch = SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy");
        assert_eq!(switch.transport(), SwitchTransport::LocalSpawn);
    }

    #[test]
    fn with_transport_selects_vm_host() {
        let switch = SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy")
            .with_transport(SwitchTransport::VmHost);
        assert_eq!(switch.transport(), SwitchTransport::VmHost);
    }

    /// A switch the VM host owns, pointed at a gvproxy binary that does not
    /// exist: `minvmd` owns gvproxy in VmHost mode, so nothing here may
    /// try to spawn it.
    /// A stand-in for gvproxy that exits at once with status 3.
    fn dying_gvproxy(dir: &std::path::Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = dir.join("dying-gvproxy.sh");
        std::fs::write(&path, "#!/bin/sh\nexit 3\n").expect("write the stand-in");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the stand-in");
        path
    }

    /// A gvproxy that dies under an attached box is started again a
    /// bounded number of times. Then the box is told its network is down,
    /// and the next attach fails with what gvproxy did.
    #[tokio::test]
    async fn a_gvproxy_that_keeps_dying_is_left_down_and_the_boxes_are_told() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut switch = SwitchClient::new(dying_gvproxy(dir.path()), dir.path().join("gvproxy"));
        let told = Arc::new(std::sync::Mutex::new(Vec::new()));
        let heard = Arc::clone(&told);
        let deaths = switch
            .watched(UplinkWatch::new(move |change| {
                heard.lock().unwrap().push(change.clone());
            }))
            .expect("the first watch gets the ends of gvproxy");
        // A box is attached, and its gvproxy was just killed.
        switch.attached = 1;
        switch.outage = Some(Outage {
            since: Instant::now(),
            cause: "gvproxy was killed by signal 9".to_owned(),
        });
        let died = switch.died.clone();
        let switch = Arc::new(tokio::sync::Mutex::new(switch));
        let ms = Duration::from_millis(1);
        let quick = ::switch::restart::Restarts::new(
            ::switch::restart::Backoff::new(ms, 4 * ms),
            3,
            Duration::from_secs(30),
        );
        let supervisor = crate::traced::spawn(revive(Arc::downgrade(&switch), deaths, quick));
        died.send(Died {
            cause: "gvproxy was killed by signal 9".to_owned(),
            ran: Duration::from_secs(1),
        })
        .expect("the supervisor listens");

        let deadline = Instant::now() + Duration::from_secs(20);
        while told.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the supervisor never gave up");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let told = told.lock().unwrap().clone();
        let [UplinkChange::Down { cause, starts }] = told.as_slice() else {
            panic!("one report, that the network is down: {told:?}");
        };
        assert_eq!(*starts, 3);
        assert!(
            cause.starts_with("gvproxy was killed by signal 9; then: ")
                && cause.contains("status Some(3)"),
            "{cause}"
        );

        // The box is still attached and no gvproxy runs. An attach starts
        // one, and says how that went.
        let mut switch = switch.lock().await;
        assert!(switch.gvproxy.is_none() && switch.outage.is_some());
        let refused = switch.attach().await.expect_err("gvproxy dies at once");
        assert!(
            matches!(refused, NetError::UnexpectedExit(Some(3))),
            "{refused}"
        );
        assert_eq!(switch.attached, 1, "a failed attach holds no place");
        supervisor.abort();
    }

    /// A gvproxy that never came up is its starter's to report, and one
    /// that ended with no box attached is nobody's to start again.
    #[tokio::test]
    async fn a_gvproxy_nobody_needs_is_not_started_again() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut switch = SwitchClient::new(dying_gvproxy(dir.path()), dir.path().join("gvproxy"));
        let told = Arc::new(std::sync::Mutex::new(Vec::new()));
        let heard = Arc::clone(&told);
        let mut deaths = switch
            .watched(UplinkWatch::new(move |change| {
                heard.lock().unwrap().push(change.clone());
            }))
            .expect("the ends of gvproxy");
        // The first attach of a box: gvproxy dies during its start, and
        // the attach says so.
        let refused = switch.attach().await.expect_err("gvproxy dies at once");
        assert!(matches!(refused, NetError::UnexpectedExit(Some(3))));
        assert_eq!(switch.attached, 0);
        assert!(deaths.try_recv().is_err(), "the attach reported it");

        let died = switch.died.clone();
        let switch = Arc::new(tokio::sync::Mutex::new(switch));
        let supervisor = crate::traced::spawn(revive(
            Arc::downgrade(&switch),
            deaths,
            ::switch::restart::Restarts::gvproxy(),
        ));
        died.send(Died {
            cause: "gvproxy exited with status 3".to_owned(),
            ran: Duration::from_secs(1),
        })
        .expect("the supervisor listens");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(told.lock().unwrap().is_empty(), "no box was attached");
        assert!(switch.lock().await.outage.is_none());
        supervisor.abort();
    }

    fn vm_host_switch(dir: &std::path::Path) -> SwitchClient {
        SwitchClient::new("/nonexistent/gvproxy-binary", dir.join("gvproxy"))
            .with_transport(SwitchTransport::VmHost)
    }

    /// The first `n` addresses of the default plan's hand-out run: the
    /// upper half the VM host hands boxes and task addresses from.
    fn handed_addresses(n: u32) -> Vec<Ipv4Addr> {
        let (_, reserve_last) = self_allocation_run(DEFAULT_SUBNET);
        (1..=n).map(|k| Ipv4Addr::from(reserve_last + k)).collect()
    }

    #[tokio::test]
    async fn vm_host_attach_handed_without_spawning_gvproxy() {
        // In VmHost mode `minvmd` owns gvproxy, so a handed attach must
        // not try to spawn the (here nonexistent) binary: it records the
        // lease and only tracks the attach count. A LocalSpawn switch
        // pointed at the same missing binary would instead fail in
        // `ensure_running`.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut switch = vm_host_switch(dir.path());
        let handed = handed_addresses(1)[0];
        let lease = switch.attach_handed(handed).await.expect("VM-host attach");
        assert_eq!(lease.ip, handed);
        // No gvproxy child was spawned; detach decrements the count and
        // withdraws the lease with the attach.
        switch.detach(lease).await.expect("detach");
    }

    /// NET-138's hard guarantee: on a switch the VM host owns, the daemon
    /// draws nothing — a draw is refused, telling the user to re-activate,
    /// and leaves no lease and no attach behind.
    #[tokio::test]
    async fn vm_host_switch_refuses_self_allocation() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut switch = vm_host_switch(dir.path());
        let Err(err) = switch.attach().await else {
            panic!("a switch the VM host owns draws nothing");
        };
        assert!(
            matches!(err, NetError::SelfAllocationRetired),
            "refused as retired: {err}"
        );
        assert!(
            err.to_string().contains("re-activate"),
            "the refusal names the remedy: {err}"
        );
        assert!(switch.leases().is_empty(), "nothing was drawn");
        assert_eq!(switch.attached(), 0);
        // A task run with no task address on its record draws nothing
        // either, refused as a box without task addresses on this host.
        let Err(err) = switch.attach_task_slot(&[]).await else {
            panic!("a task run with no task address draws nothing either");
        };
        assert!(
            matches!(err, NetError::NoTaskAddresses { capacity: 4 }),
            "{err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("no task addresses on this host") && message.contains("up to 4"),
            "the refusal names the box's state and the capacity: {message}"
        );
        assert!(switch.leases().is_empty(), "nothing was drawn");
    }

    /// A native switch draws its own addresses. With no gvproxy to start,
    /// the attach fails at the spawn, after the draw reached the reserve,
    /// and gives the address back.
    #[tokio::test]
    async fn local_spawn_switch_still_self_allocates() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut switch =
            SwitchClient::new("/nonexistent/gvproxy-binary", dir.path().join("gvproxy"));
        let err = match switch.attach().await {
            Ok(_) => panic!("the missing gvproxy binary cannot be spawned"),
            Err(err) => err,
        };
        assert!(
            !matches!(err, NetError::SelfAllocationRetired),
            "a native switch is never refused the draw: {err}"
        );
        assert!(matches!(err, NetError::Spawn { .. }), "{err}");
        let (reserve_first, _) = self_allocation_run(switch.subnet());
        let config = std::fs::read_to_string(dir.path().join("gvproxy/gvproxy.yaml"))
            .expect("the config the failed attach wrote");
        assert!(
            config.contains(&format!("\"{}\"", Ipv4Addr::from(reserve_first))),
            "the draw reached the reserve: {config}"
        );
        assert!(
            switch.leases().is_empty(),
            "a failed attach holds no address"
        );
        assert_eq!(switch.attached(), 0);
    }

    /// A task run attaches at a task address registered with its box
    /// (NET-138): the first one no run holds, and a slot frees when the run
    /// holding it detaches.
    #[tokio::test]
    async fn own_ip_task_attaches_at_a_handed_task_address() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut switch = vm_host_switch(dir.path());
        let slots = handed_addresses(2);
        let first = switch.attach_task_slot(&slots).await.expect("a free slot");
        assert_eq!(first.ip, slots[0]);
        let second = switch.attach_task_slot(&slots).await.expect("a free slot");
        assert_eq!(second.ip, slots[1], "a held slot is skipped");
        switch.detach(first).await.expect("detach");
        let again = switch.attach_task_slot(&slots).await.expect("a freed slot");
        assert_eq!(again.ip, slots[0], "the freed slot is taken again");
    }

    /// Every task address held: the run is refused with how many are in
    /// progress, and nothing is drawn in their place.
    #[tokio::test]
    async fn own_ip_task_refused_when_no_task_address_free() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut switch = vm_host_switch(dir.path());
        let slots = handed_addresses(2);
        for _ in &slots {
            switch.attach_task_slot(&slots).await.expect("a free slot");
        }
        let Err(err) = switch.attach_task_slot(&slots).await else {
            panic!("no slot is free");
        };
        assert!(matches!(err, NetError::TaskSlotsBusy { slots: 2 }), "{err}");
        assert!(
            err.to_string()
                .contains("2 task runs already in progress for this session"),
            "{err}"
        );
        assert_eq!(switch.leases().len(), 2, "nothing was drawn beside them");
        assert_eq!(switch.attached(), 2);
    }

    /// A native daemon's switch: a /24 inside the default /16, whose
    /// self-allocation reserve is `.2..=.126`.
    fn native_slash24() -> SwitchSubnet {
        SwitchSubnet::new(Ipv4Addr::new(100, 64, 37, 0), 24).unwrap()
    }

    #[test]
    fn reuse_quarantine_is_five_minutes_or_more() {
        assert!(REUSE_QUARANTINE >= Duration::from_secs(300));
    }

    #[test]
    fn a_thousand_launch_release_cycles_on_a_native_slash24_never_exhaust() {
        let subnet = native_slash24();
        let (first, last) = self_allocation_run(subnet);
        assert_eq!(
            (Ipv4Addr::from(first), Ipv4Addr::from(last)),
            (
                Ipv4Addr::new(100, 64, 37, 2),
                Ipv4Addr::new(100, 64, 37, 126)
            ),
            "125 addresses: the reserve that used to be a lifetime cap"
        );
        // One launch every 3 s: the reserve's 125 addresses cover the
        // 300 s quarantine at any pace slower than one per 2.4 s.
        let step = Duration::from_secs(3);
        let mut a = IpAllocator::new(subnet);
        let mut now = Instant::now();
        let mut released_at = std::collections::HashMap::new();
        let mut last_epoch = 0;
        for cycle in 0..1000 {
            let lease = a
                .allocate_at(now, |_| false)
                .unwrap_or_else(|e| panic!("cycle {cycle} failed: {e}"));
            assert!(lease.epoch > last_epoch, "every hand is a new epoch");
            last_epoch = lease.epoch;
            if let Some(at) = released_at.get(&lease.ip) {
                assert!(
                    now.duration_since(*at) >= REUSE_QUARANTINE,
                    "cycle {cycle} re-handed {} inside the quarantine",
                    lease.ip
                );
            }
            assert!(a.release_at(lease, now));
            released_at.insert(lease.ip, now);
            now += step;
        }
        assert!(a.leases().is_empty());
    }

    #[test]
    fn a_rehanded_address_carries_a_new_epoch_and_its_old_lease_ends_nothing() {
        // A /29's reserve is one address, so every draw after the first is
        // a re-hand of it.
        let subnet = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        let mut a = IpAllocator::new(subnet);
        let t0 = Instant::now();
        let old = a.allocate_at(t0, |_| false).unwrap();
        assert!(a.release_at(old, t0));
        let new = a.allocate_at(t0 + REUSE_QUARANTINE, |_| false).unwrap();
        assert_eq!((new.ip, new.mac), (old.ip, old.mac), "the same address");
        assert!(new.epoch > old.epoch, "under a new epoch");
        assert_ne!(new, old, "so the two leases are not the same lease");
        // The old holder's lease admits nothing for the new one: a stale
        // release ends nothing, and the static-lease table keeps the new
        // holder's row.
        assert!(!a.release_at(old, t0 + REUSE_QUARANTINE));
        assert_eq!(a.leases(), &[new]);
        assert!(a.release_at(new, t0 + REUSE_QUARANTINE));
        assert!(a.leases().is_empty());
    }

    #[test]
    fn no_rehand_inside_the_quarantine_or_while_referenced() {
        let subnet = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        let mut a = IpAllocator::new(subnet);
        let t0 = Instant::now();
        let lease = a.allocate_at(t0, |_| false).unwrap();
        // Held: nothing to hand.
        assert!(matches!(
            a.allocate_at(t0 + REUSE_QUARANTINE, |_| false),
            Err(NetError::SubnetExhausted(_))
        ));
        assert!(a.release_at(lease, t0));
        // Released, but inside the quarantine.
        assert!(matches!(
            a.allocate_at(
                t0 + REUSE_QUARANTINE.saturating_sub(Duration::from_millis(1)),
                |_| false
            ),
            Err(NetError::SubnetExhausted(_))
        ));
        // Past the quarantine, but a live ingress gate is registered at it.
        assert!(matches!(
            a.allocate_at(t0 + REUSE_QUARANTINE, |ip| ip == lease.ip),
            Err(NetError::SubnetExhausted(_))
        ));
        // Past the quarantine with nothing naming it: handed again.
        let again = a.allocate_at(t0 + REUSE_QUARANTINE, |_| false).unwrap();
        assert_eq!(again.ip, lease.ip);
    }

    #[test]
    fn released_addresses_are_handed_longest_free_first() {
        let mut a = IpAllocator::new(native_slash24());
        let t0 = Instant::now();
        let drawn: Vec<PtaskLease> =
            std::iter::from_fn(|| a.allocate_at(t0, |_| false).ok()).collect();
        assert_eq!(drawn.len(), 125, "the never-drawn addresses go first");
        // Released out of address order, a second apart.
        for (offset, index) in [7usize, 3, 5].into_iter().enumerate() {
            let at = t0 + Duration::from_secs(offset as u64);
            assert!(a.release_at(drawn[index], at));
        }
        let later = t0 + REUSE_QUARANTINE + Duration::from_secs(10);
        let order: Vec<Ipv4Addr> = (0..3)
            .map(|_| a.allocate_at(later, |_| false).unwrap().ip)
            .collect();
        assert_eq!(order, vec![drawn[7].ip, drawn[3].ip, drawn[5].ip]);
        // A referenced address is skipped, not waited on: the next free one
        // in release order goes instead.
        assert!(a.release_at(drawn[9], later));
        assert!(a.release_at(drawn[11], later));
        let skip = drawn[9].ip;
        let next = a
            .allocate_at(later + REUSE_QUARANTINE, |ip| ip == skip)
            .unwrap();
        assert_eq!(next.ip, drawn[11].ip);
    }
}
