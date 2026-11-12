//! When to start gvproxy again after it died.
//!
//! Both daemons that run a gvproxy start it again when it ends by itself.
//! The waits between the attempts are the same for both ([`Backoff`]). A
//! daemon that must not try forever counts the attempts too ([`Restarts`]).

use std::time::Duration;

/// The waits between attempts: the shortest first, twice as long after
/// each, up to the longest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    first: Duration,
    next: Duration,
    longest: Duration,
}

impl Backoff {
    #[must_use]
    pub const fn new(first: Duration, longest: Duration) -> Self {
        Self {
            first,
            next: first,
            longest,
        }
    }

    /// The waits a gvproxy that died is started again with: a quarter of a
    /// second, then up to four seconds.
    #[must_use]
    pub const fn gvproxy() -> Self {
        Self::new(Duration::from_millis(250), Duration::from_secs(4))
    }

    /// The wait before the next attempt.
    pub fn wait(&mut self) -> Duration {
        let wait = self.next;
        self.next = (wait * 2).min(self.longest);
        wait
    }

    /// Starts over with the shortest wait.
    pub const fn reset(&mut self) {
        self.next = self.first;
    }
}

/// Bounds the restarts of a gvproxy that keeps dying.
///
/// A gvproxy that ran for a while and then died is a new trouble: it is
/// started again at once, with the count at zero. One that dies soon after
/// each start is the same trouble again: each start waits longer, and
/// after `most` of them in a row nothing is started any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restarts {
    backoff: Backoff,
    /// Deaths and failed starts in a row.
    failed: u32,
    most: u32,
    /// A gvproxy that ran this long was working.
    settled: Duration,
}

impl Restarts {
    #[must_use]
    pub const fn new(backoff: Backoff, most: u32, settled: Duration) -> Self {
        Self {
            backoff,
            failed: 0,
            most,
            settled,
        }
    }

    /// The bound for a daemon whose gvproxy carries its boxes' traffic:
    /// five starts in a row that did not last half a minute.
    #[must_use]
    pub const fn gvproxy() -> Self {
        Self::new(Backoff::gvproxy(), 5, Duration::from_secs(30))
    }

    /// gvproxy ended by itself after running for `ran`. Returns the wait
    /// before it is started again, or `None` when it is not.
    pub fn died(&mut self, ran: Duration) -> Option<Duration> {
        if ran >= self.settled {
            self.failed = 0;
            self.backoff.reset();
        }
        self.failed_to_start()
    }

    /// A start did not bring gvproxy up. Returns the wait before the next
    /// start, or `None` when there is none.
    pub fn failed_to_start(&mut self) -> Option<Duration> {
        if self.failed >= self.most {
            return None;
        }
        self.failed += 1;
        Some(self.backoff.wait())
    }

    /// The starts since gvproxy last ran long enough to count as working.
    #[must_use]
    pub const fn starts(&self) -> u32 {
        self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn the_wait_doubles_up_to_the_longest() {
        let mut backoff = Backoff::gvproxy();
        let waits: Vec<_> = (0..7).map(|_| backoff.wait().as_millis()).collect();
        assert_eq!(waits, [250, 500, 1000, 2000, 4000, 4000, 4000]);
        backoff.reset();
        assert_eq!(backoff.wait(), 250 * MS);
    }

    #[test]
    fn a_gvproxy_that_dies_at_once_is_started_a_bounded_number_of_times() {
        let mut restarts = Restarts::new(Backoff::new(100 * MS, 400 * MS), 4, 10_000 * MS);
        // Each start dies within a second of it.
        let waits: Vec<_> = (0..6).map(|_| restarts.died(900 * MS)).collect();
        assert_eq!(
            waits,
            [
                Some(100 * MS),
                Some(200 * MS),
                Some(400 * MS),
                Some(400 * MS),
                None,
                None
            ]
        );
        assert_eq!(restarts.starts(), 4);
        // A start that never came up counts like one that died.
        let mut restarts = Restarts::new(Backoff::new(100 * MS, 400 * MS), 2, 10_000 * MS);
        assert_eq!(restarts.died(Duration::ZERO), Some(100 * MS));
        assert_eq!(restarts.failed_to_start(), Some(200 * MS));
        assert_eq!(restarts.failed_to_start(), None);
    }

    #[test]
    fn a_gvproxy_that_worked_for_a_while_starts_the_count_again() {
        let mut restarts = Restarts::new(Backoff::new(100 * MS, 400 * MS), 2, 10_000 * MS);
        assert_eq!(restarts.died(500 * MS), Some(100 * MS));
        assert_eq!(restarts.died(500 * MS), Some(200 * MS));
        // It then ran for a minute before it died: a new trouble.
        assert_eq!(restarts.died(60_000 * MS), Some(100 * MS));
        assert_eq!(restarts.starts(), 1);
        assert_eq!(restarts.died(500 * MS), Some(200 * MS));
        assert_eq!(restarts.died(500 * MS), None);
    }

    #[test]
    fn the_shipped_bound_gives_up_within_ten_seconds_of_waiting() {
        let mut restarts = Restarts::gvproxy();
        let mut waited = Duration::ZERO;
        let mut starts = 0;
        while let Some(wait) = restarts.died(Duration::ZERO) {
            waited += wait;
            starts += 1;
        }
        assert_eq!(starts, 5);
        assert_eq!(waited, Duration::from_millis(7750));
    }
}
