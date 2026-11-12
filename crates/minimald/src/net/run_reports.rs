//! What this daemon tells the VM host about each box: whether it runs it.
//!
//! A box runs from the moment it has an entry in the policy engine until
//! the entry is removed. Each of the two changes takes a sequence number
//! when it happens ([`next_seq`]), and the VM host acts on a report only
//! when it took no report of the box with a higher number. So a report that
//! arrives late, behind a newer one, changes nothing on the VM host.
//!
//! One task per box sends the box's newest word and repeats it until the VM
//! host answers. A word that a newer one overtook before it was sent is
//! never sent. A launch waits for the answer to "it runs" before it starts
//! anything in the box ([`Told::answered_within`]), so the VM host has put
//! back what it holds for the box before the box asks for a forward or
//! opens a stream.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use boxes::BoxId;
use minimald_rpc::BoxRunReport;
use tokio::sync::watch;

use super::door::HostDoor;

/// The waits between two tries to tell the VM host a box's newest word.
const FIRST_WAIT: Duration = Duration::from_millis(200);
const LONGEST_WAIT: Duration = Duration::from_secs(5);

/// How long a launch waits for the VM host to answer that the box runs. It
/// covers one try that the VM host does not answer and the try after it.
pub(crate) const RUN_ANSWER_LIMIT: Duration = Duration::from_secs(15);

/// The sequence number of a change that happens now: higher than every
/// number given before. It starts from the time since the VM booted, so a
/// daemon that starts again in the same VM continues above the numbers of
/// the one before it.
pub(crate) fn next_seq() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let since_boot = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
        .ok()
        .and_then(|at| {
            let secs = u64::try_from(at.tv_sec()).ok()?;
            let nanos = u64::try_from(at.tv_nsec()).ok()?;
            secs.checked_mul(1_000_000_000)?.checked_add(nanos)
        })
        .unwrap_or(0);
    let mut last = LAST.load(Ordering::SeqCst);
    loop {
        let next = since_boot.max(last + 1);
        match LAST.compare_exchange_weak(last, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

/// A box's newest word, and the sequence number of the newest one the VM
/// host has answered.
struct Slot {
    seq: u64,
    runs: bool,
    answered: watch::Sender<u64>,
}

/// The run reports of one daemon to its VM host.
pub(crate) struct RunReports {
    door: Arc<dyn HostDoor>,
    /// The boxes whose newest word the VM host has not answered yet. Each
    /// has one sending task.
    boxes: Mutex<HashMap<BoxId, Slot>>,
}

static CURRENT: OnceLock<Arc<RunReports>> = OnceLock::new();

/// This daemon's run reports. `None` on a node that has no VM host, where
/// there is nobody to tell.
pub(crate) fn current() -> Option<&'static Arc<RunReports>> {
    CURRENT.get()
}

/// Makes `door` the VM host this daemon reports to. Called once, by a
/// daemon that runs in a VM.
pub(crate) fn start(door: Arc<dyn HostDoor>) {
    // A second call keeps the first door.
    drop(CURRENT.set(Arc::new(RunReports::new(door))));
}

impl RunReports {
    pub(crate) fn new(door: Arc<dyn HostDoor>) -> Self {
        Self {
            door,
            boxes: Mutex::new(HashMap::new()),
        }
    }

    fn boxes(&self) -> std::sync::MutexGuard<'_, HashMap<BoxId, Slot>> {
        self.boxes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Tells the VM host that the box runs or does not, as of the change
    /// numbered `seq`. A word older than the box's newest is dropped. Must
    /// be called on the daemon's runtime: the sending task starts here.
    pub(crate) fn tell(self: &Arc<Self>, box_id: BoxId, seq: u64, runs: bool) -> Told {
        let mut boxes = self.boxes();
        let answered = match boxes.entry(box_id) {
            Entry::Occupied(mut slot) => {
                let slot = slot.get_mut();
                if seq > slot.seq {
                    slot.seq = seq;
                    slot.runs = runs;
                }
                slot.answered.subscribe()
            }
            Entry::Vacant(vacant) => {
                let (answered, receiver) = watch::channel(0);
                vacant.insert(Slot {
                    seq,
                    runs,
                    answered,
                });
                crate::traced::spawn_detached(
                    tracing::info_span!(parent: None, "net.run_report", %box_id),
                    Arc::clone(self).send(box_id),
                );
                receiver
            }
        };
        Told { seq, answered }
    }

    /// Sends the box's newest word until the VM host has answered it.
    async fn send(self: Arc<Self>, box_id: BoxId) {
        let mut wait = FIRST_WAIT;
        loop {
            let Some((seq, runs)) = self.boxes().get(&box_id).map(|slot| (slot.seq, slot.runs))
            else {
                return;
            };
            match self
                .door
                .report_run(BoxRunReport { box_id, seq, runs })
                .await
            {
                Ok(effect) => {
                    tracing::info!(
                        %box_id,
                        seq,
                        runs,
                        ?effect,
                        "told the VM host whether the box runs"
                    );
                    wait = FIRST_WAIT;
                    let mut boxes = self.boxes();
                    if let Entry::Occupied(slot) = boxes.entry(box_id) {
                        slot.get().answered.send_replace(seq);
                        // A newer word came meanwhile: it goes next.
                        if slot.get().seq == seq {
                            slot.remove();
                            return;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%box_id, seq, runs, %error, "could not tell the VM host whether the box runs");
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(LONGEST_WAIT);
                }
            }
        }
    }
}

/// A word on its way to the VM host.
pub(crate) struct Told {
    seq: u64,
    answered: watch::Receiver<u64>,
}

impl Told {
    /// Waits until the VM host has answered this word or a newer one of
    /// the same box. `false` when `limit` passed first.
    pub(crate) async fn answered_within(mut self, limit: Duration) -> bool {
        let seq = self.seq;
        tokio::time::timeout(limit, self.answered.wait_for(|answered| *answered >= seq))
            .await
            .is_ok_and(|answered| answered.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::door::GuestDoor;
    use crate::net::door::testing::{FakeHost, box_id};
    use minimald_rpc::{BoxRunEffect, GuestDoorReply, GuestDoorRequest};

    /// A VM host that records each run report and answers it when `answers`
    /// says so for the report and the number of reports seen before it.
    fn host(
        answers: impl Fn(&BoxRunReport, usize) -> bool + Send + Sync + 'static,
    ) -> (Arc<RunReports>, Arc<Mutex<Vec<BoxRunReport>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let fake = FakeHost::answering(move |request| {
            let GuestDoorRequest::BoxRun(report) = request else {
                panic!("{request:?}")
            };
            let before = {
                let mut log = log.lock().unwrap();
                log.push(report);
                log.len() - 1
            };
            answers(&report, before).then_some(GuestDoorReply::BoxRunTaken {
                box_id: report.box_id,
                seq: report.seq,
                effect: BoxRunEffect::Unchanged,
            })
        });
        let reports = Arc::new(RunReports::new(Arc::new(GuestDoor::new(fake))));
        (reports, seen)
    }

    fn word(seq: u64, runs: bool) -> BoxRunReport {
        BoxRunReport {
            box_id: box_id(1),
            seq,
            runs,
        }
    }

    #[test]
    fn each_number_is_above_the_one_before_and_starts_from_the_time_since_boot() {
        let first = next_seq();
        let second = next_seq();
        assert!(second > first);
        // The test host booted more than a second ago.
        assert!(first > 1_000_000_000, "{first}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_word_is_sent_until_the_host_answers() {
        let (reports, seen) = host(|_, before| before >= 2);
        let told = reports.tell(box_id(1), 5, false);
        assert!(told.answered_within(Duration::from_secs(60)).await);
        assert_eq!(*seen.lock().unwrap(), vec![word(5, false); 3]);
        assert!(reports.boxes().is_empty(), "nothing is left to send");
    }

    #[tokio::test(start_paused = true)]
    async fn a_newer_word_overtakes_one_the_host_has_not_answered() {
        // The host answers only the word that the box runs.
        let (reports, seen) = host(|report, _| report.runs);
        let ended = reports.tell(box_id(1), 5, false);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(seen.lock().unwrap().contains(&word(5, false)));
        let runs = reports.tell(box_id(1), 6, true);
        assert!(runs.answered_within(Duration::from_secs(60)).await);
        // The answer to the newer word answers the older one too.
        assert!(ended.answered_within(Duration::ZERO).await);
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.last(), Some(&word(6, true)));
        assert_eq!(seen.iter().filter(|sent| sent.runs).count(), 1);
        assert!(reports.boxes().is_empty(), "nothing is left to send");
    }

    #[tokio::test(start_paused = true)]
    async fn a_word_older_than_the_newest_is_dropped() {
        let (reports, seen) = host(|_, before| before >= 1);
        let runs = reports.tell(box_id(1), 6, true);
        // The end of the run before, told late.
        let ended = reports.tell(box_id(1), 5, false);
        assert!(runs.answered_within(Duration::from_secs(60)).await);
        assert!(ended.answered_within(Duration::ZERO).await);
        assert_eq!(*seen.lock().unwrap(), vec![word(6, true); 2]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_launch_stops_waiting_for_a_host_that_does_not_answer() {
        let (reports, _seen) = host(|_, _| false);
        let told = reports.tell(box_id(1), 5, true);
        assert!(!told.answered_within(RUN_ANSWER_LIMIT).await);
    }
}
