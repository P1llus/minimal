//! The requesting side of a spawner's socket.
//!
//! Requests go out under one lock. One thread reads what comes back and
//! hands each event to whoever waits for it: the caller of a request waits
//! for its answer, and a job's handle waits for its exit.

use std::collections::HashMap;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};

use super::ExitStatus;
use super::wire::{self, Event, Request};
use crate::cgroup::BoxCgroup;

/// How a job ended, for every holder of its handle.
#[derive(Default)]
pub(crate) struct Outcome {
    status: Mutex<Option<ExitStatus>>,
    set: Condvar,
    notify: tokio::sync::Notify,
}

impl Outcome {
    pub(crate) fn get(&self) -> Option<ExitStatus> {
        self.status.lock().expect("outcome lock").clone()
    }

    /// Blocks until the job has ended.
    pub(crate) fn wait(&self) -> ExitStatus {
        let mut status = self.status.lock().expect("outcome lock");
        loop {
            if let Some(status) = status.as_ref() {
                return status.clone();
            }
            status = self.set.wait(status).expect("outcome lock");
        }
    }

    /// Resolves once the job has ended.
    pub(crate) async fn ended(&self) -> ExitStatus {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Registered before the check, so an exit between the two wakes it.
            notified.as_mut().enable();
            if let Some(status) = self.get() {
                return status;
            }
            notified.await;
        }
    }

    fn end(&self, status: ExitStatus) {
        let mut slot = self.status.lock().expect("outcome lock");
        if slot.is_none() {
            *slot = Some(status);
        }
        drop(slot);
        self.set.notify_all();
        self.notify.notify_waiters();
    }
}

/// The answer to a request that starts something.
enum Answer {
    Started { pid: u32, tap: Option<OwnedFd> },
    Socket(OwnedFd),
    Failed(String),
}

/// A job that has not been seen to end.
struct Job {
    outcome: Arc<Outcome>,
    /// Whether the job is a container, whose process is its supervisor.
    container: bool,
    /// The pid of the job's process, once it has started.
    pid: Option<u32>,
    /// The cgroup made for this one container, which goes when it does.
    own_cgroup: Option<BoxCgroup>,
}

impl Job {
    /// The job is over.
    fn end(self, status: ExitStatus) {
        self.outcome.end(status);
        if let Some(cgroup) = self.own_cgroup {
            remove_own_cgroup(cgroup);
        }
    }
}

/// How long the processes of an ended container get to leave its cgroup.
const OWN_CGROUP_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Removes the cgroup of a container that has ended, on a thread of its
/// own: the last processes of the container may still be on their way out,
/// and the events thread does not wait for them.
fn remove_own_cgroup(cgroup: BoxCgroup) {
    let removal = std::thread::Builder::new()
        .name("spawner-cgroup".into())
        .spawn(move || {
            if let Err(error) = cgroup.destroy_blocking(OWN_CGROUP_LIMIT) {
                tracing::warn!(%error, "removing the cgroup of an ended container");
            }
        });
    if let Err(error) = removal {
        tracing::warn!(%error, "no thread to remove the cgroup of an ended container");
    }
}

#[derive(Default)]
struct Table {
    /// Set once the spawner is gone.
    closed: bool,
    answers: HashMap<u64, mpsc::SyncSender<Answer>>,
    jobs: HashMap<u64, Job>,
}

#[derive(Default)]
struct Shared {
    next_id: AtomicU64,
    table: Mutex<Table>,
}

impl Shared {
    fn deliver(&self, event: Event, fds: Vec<OwnedFd>) {
        let mut table = self.table.lock().expect("spawner table lock");
        let mut fds = fds.into_iter();
        let (id, answer) = match event {
            Event::Started { id, pid, tap } => {
                let tap = if tap { fds.next() } else { None };
                if let Some(job) = table.jobs.get_mut(&id) {
                    job.pid = Some(pid);
                }
                (id, Answer::Started { pid, tap })
            }
            Event::Socket { id } => match fds.next() {
                Some(socket) => (id, Answer::Socket(socket)),
                None => (id, Answer::Failed("the spawner sent no socket".into())),
            },
            Event::Failed { id, error } => (id, Answer::Failed(error)),
            Event::Exited { id, status } => {
                if let Some(job) = table.jobs.remove(&id) {
                    job.end(status);
                }
                return;
            }
        };
        if let Some(waiter) = table.answers.remove(&id) {
            let _ = waiter.send(answer);
        }
    }

    /// The spawner is gone, and what it started died with it.
    fn close(&self) {
        let mut table = self.table.lock().expect("spawner table lock");
        table.closed = true;
        table.answers.clear();
        for (_, job) in table.jobs.drain() {
            job.end(ExitStatus::failure(GONE));
        }
    }
}

const GONE: &str = "the spawner exited";

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, GONE)
}

/// A started job, as its handle needs it.
pub(crate) struct Started {
    pub(crate) id: u64,
    pub(crate) pid: u32,
    pub(crate) tap: Option<OwnedFd>,
    pub(crate) outcome: Arc<Outcome>,
}

/// One spawner, reached over its socket.
pub(crate) struct Connection {
    writer: Mutex<UnixStream>,
    shared: Arc<Shared>,
    /// The spawner process, when the spawner is one.
    process: Mutex<Option<std::process::Child>>,
}

impl Connection {
    /// Takes the requesting end of a spawner's socket.
    pub(crate) fn open(
        sock: UnixStream,
        process: Option<std::process::Child>,
    ) -> io::Result<Arc<Self>> {
        let shared = Arc::new(Shared::default());
        let mut reader = sock.try_clone()?;
        let events = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("spawner-events".into())
            .spawn(move || {
                while let Ok(Some((event, fds))) = wire::recv::<Event>(&mut reader) {
                    events.deliver(event, fds);
                }
                events.close();
            })?;
        Ok(Arc::new(Self {
            writer: Mutex::new(sock),
            shared,
            process: Mutex::new(process),
        }))
    }

    /// Whether the spawner is gone.
    pub(crate) fn closed(&self) -> bool {
        self.shared.table.lock().expect("spawner table lock").closed
    }

    fn send(&self, request: &Request, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let mut writer = self.writer.lock().expect("spawner socket lock");
        wire::send(&mut writer, request, fds).map_err(|_| gone())
    }

    /// Sends the request `make` builds for a fresh id, and waits for its
    /// answer. `job` registers the id as a job whose exit is reported.
    fn ask(
        &self,
        make: impl FnOnce(u64) -> Request,
        fds: &[BorrowedFd<'_>],
        job: Option<Job>,
    ) -> io::Result<(u64, Answer)> {
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (answer, answered) = mpsc::sync_channel(1);
        {
            let mut table = self.shared.table.lock().expect("spawner table lock");
            if table.closed {
                drop(table);
                if let Some(job) = job {
                    job.end(ExitStatus::failure(GONE));
                }
                return Err(gone());
            }
            table.answers.insert(id, answer);
            if let Some(job) = job {
                table.jobs.insert(id, job);
            }
        }
        // A job that never started is over.
        let never_started = || {
            let mut table = self.shared.table.lock().expect("spawner table lock");
            table.answers.remove(&id);
            let job = table.jobs.remove(&id);
            drop(table);
            if let Some(job) = job {
                job.end(ExitStatus::failure("the job did not start"));
            }
        };
        if let Err(error) = self.send(&make(id), fds) {
            never_started();
            return Err(error);
        }
        // The events thread drops the sender when the spawner goes.
        let answer = answered.recv().map_err(|_| gone())?;
        if matches!(answer, Answer::Failed(_)) {
            never_started();
        }
        Ok((id, answer))
    }

    /// Starts a job: `make` builds a `Run` or an `Enter` request. A
    /// container is a `Run`, and `own_cgroup` is the cgroup made for it
    /// alone, which is removed when it ends.
    pub(crate) fn start(
        &self,
        make: impl FnOnce(u64) -> Request,
        fds: &[BorrowedFd<'_>],
        container: bool,
        own_cgroup: Option<BoxCgroup>,
    ) -> io::Result<Started> {
        let outcome = Arc::<Outcome>::default();
        let job = Job {
            outcome: Arc::clone(&outcome),
            container,
            pid: None,
            own_cgroup,
        };
        match self.ask(make, fds, Some(job))? {
            (id, Answer::Started { pid, tap }) => Ok(Started {
                id,
                pid,
                tap,
                outcome,
            }),
            (_, Answer::Failed(error)) => Err(io::Error::other(error)),
            (_, Answer::Socket(_)) => Err(io::Error::other("the spawner answered out of turn")),
        }
    }

    /// Whether `pid` is the supervisor of a container this spawner runs.
    pub(crate) fn supervises(&self, pid: u32) -> bool {
        let table = self.shared.table.lock().expect("spawner table lock");
        table
            .jobs
            .values()
            .any(|job| job.container && job.pid == Some(pid))
    }

    /// Has the spawner create a socket in `cgroup`, and in the network
    /// namespace of job `netns_of` when one is named.
    pub(crate) fn socket(
        &self,
        netns_of: Option<u64>,
        v6: bool,
        datagram: bool,
        cgroup: Option<BorrowedFd<'_>>,
    ) -> io::Result<OwnedFd> {
        let make = |id| Request::Socket {
            id,
            netns_of,
            v6,
            datagram,
            cgroup: cgroup.is_some(),
        };
        match self.ask(make, cgroup.as_slice(), None)? {
            (_, Answer::Socket(socket)) => Ok(socket),
            (_, Answer::Failed(error)) => Err(io::Error::other(error)),
            (_, Answer::Started { .. }) => {
                Err(io::Error::other("the spawner answered out of turn"))
            }
        }
    }

    /// Signals a job. A job that has ended takes no signal.
    pub(crate) fn signal(&self, id: u64, signal: i32, to_init: bool) {
        let _ = self.send(
            &Request::Signal {
                id,
                signal,
                to_init,
            },
            &[],
        );
    }

    /// Gives up a job's handle, which kills the job.
    pub(crate) fn forget(&self, id: u64) {
        let _ = self.send(&Request::Forget { id }, &[]);
    }
}

impl Connection {
    /// Closes the socket. The spawner kills its jobs when it reads the end.
    pub(crate) fn hang_up(&self) {
        if let Ok(writer) = self.writer.lock() {
            let _ = writer.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.hang_up();
        if let Ok(mut process) = self.process.lock()
            && let Some(mut process) = process.take()
        {
            let _ = process.wait();
        }
    }
}
