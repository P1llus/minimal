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
use super::wire::{self, Event, LinkSpec, Request};

/// Runs a wait that holds the calling thread. A worker of a multi-threaded
/// tokio runtime tells the runtime first, which moves the worker's other
/// tasks to another thread: no task waits behind a spawner that is slow.
fn off_worker<T>(wait: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(wait)
        }
        _ => wait(),
    }
}

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
        off_worker(|| {
            let mut status = self.status.lock().expect("outcome lock");
            loop {
                if let Some(status) = status.as_ref() {
                    return status.clone();
                }
                status = self.set.wait(status).expect("outcome lock");
            }
        })
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
    Started { pid: u32, netns: Option<OwnedFd> },
    Socket(OwnedFd),
    Linked(Option<OwnedFd>),
    Init(bool),
    Failed(String),
}

fn out_of_turn() -> io::Error {
    io::Error::other("the spawner answered out of turn")
}

/// A job that has not been seen to end.
struct Job {
    outcome: Arc<Outcome>,
    /// Whether the job is a container, whose process is its supervisor.
    container: bool,
    /// The pid of the job's process, once it has started.
    pid: Option<u32>,
}

impl Job {
    /// The job is over.
    fn end(self, status: ExitStatus) {
        self.outcome.end(status);
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
    /// The spawner process, when the spawner is one, until it is reaped.
    process: Mutex<Option<std::process::Child>>,
    /// Set when this side closed the socket: the spawner's end is then
    /// asked for, not a death.
    hung_up: std::sync::atomic::AtomicBool,
}

/// What a requester does when its spawner process dies under it.
pub(crate) struct Lost {
    /// Run first, while the dead spawner's jobs still count as running.
    pub(crate) before: Box<dyn FnOnce() + Send>,
    /// Run once every job has been told it ended.
    pub(crate) after: Box<dyn FnOnce() + Send>,
}

impl Shared {
    fn deliver(&self, event: Event, fds: Vec<OwnedFd>) {
        let mut table = self.table.lock().expect("spawner table lock");
        let mut fds = fds.into_iter();
        let (id, answer) = match event {
            Event::Started { id, pid, netns } => {
                let netns = if netns { fds.next() } else { None };
                if let Some(job) = table.jobs.get_mut(&id) {
                    job.pid = Some(pid);
                }
                (id, Answer::Started { pid, netns })
            }
            Event::Socket { id } => match fds.next() {
                Some(socket) => (id, Answer::Socket(socket)),
                None => (id, Answer::Failed("the spawner sent no socket".into())),
            },
            Event::Linked { id, tap } => match (tap, fds.next()) {
                (true, None) => (id, Answer::Failed("the spawner sent no device".into())),
                (true, tap) => (id, Answer::Linked(tap)),
                (false, _) => (id, Answer::Linked(None)),
            },
            Event::Init { id, exists } => (id, Answer::Init(exists)),
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
    pub(crate) netns: Option<OwnedFd>,
    pub(crate) outcome: Arc<Outcome>,
}

/// One spawner, reached over its socket.
pub(crate) struct Connection {
    writer: Mutex<UnixStream>,
    shared: Arc<Shared>,
}

impl Connection {
    /// Takes the requesting end of a spawner's socket. `process` is the
    /// spawner when it is a process, and `lost` is what to do if it dies
    /// without being asked to end.
    pub(crate) fn open(
        sock: UnixStream,
        process: Option<std::process::Child>,
        lost: Option<Lost>,
    ) -> io::Result<Arc<Self>> {
        let shared = Arc::new(Shared {
            process: Mutex::new(process),
            ..Shared::default()
        });
        let mut reader = sock.try_clone()?;
        let events = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("spawner-events".into())
            .spawn(move || {
                while let Ok(Some((event, fds))) = wire::recv::<Event>(&mut reader) {
                    events.deliver(event, fds);
                }
                // The socket ended, so the spawner process is gone or going.
                let process = events.process.lock().expect("spawner process lock").take();
                if let Some(mut process) = process {
                    let _ = process.wait();
                }
                let lost = lost.filter(|_| !events.hung_up.load(Ordering::SeqCst));
                let (before, after) = match lost {
                    Some(lost) => (Some(lost.before), Some(lost.after)),
                    None => (None, None),
                };
                if let Some(before) = before {
                    before();
                }
                events.close();
                if let Some(after) = after {
                    after();
                }
            })?;
        Ok(Arc::new(Self {
            writer: Mutex::new(sock),
            shared,
        }))
    }

    /// Whether the spawner is gone.
    pub(crate) fn closed(&self) -> bool {
        self.shared.table.lock().expect("spawner table lock").closed
    }

    fn send(&self, request: &Request, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        off_worker(|| {
            let mut writer = self.writer.lock().expect("spawner socket lock");
            wire::send(&mut writer, request, fds).map_err(|_| gone())
        })
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
        let answer = off_worker(|| answered.recv()).map_err(|_| gone())?;
        if matches!(answer, Answer::Failed(_)) {
            never_started();
        }
        Ok((id, answer))
    }

    /// Starts a job: `make` builds a `Run` or an `Enter` request. A
    /// container is a `Run`.
    pub(crate) fn start(
        &self,
        make: impl FnOnce(u64) -> Request,
        fds: &[BorrowedFd<'_>],
        container: bool,
    ) -> io::Result<Started> {
        let outcome = Arc::<Outcome>::default();
        let job = Job {
            outcome: Arc::clone(&outcome),
            container,
            pid: None,
        };
        match self.ask(make, fds, Some(job))? {
            (id, Answer::Started { pid, netns }) => Ok(Started {
                id,
                pid,
                netns,
                outcome,
            }),
            (_, Answer::Failed(error)) => Err(io::Error::other(error)),
            _ => Err(out_of_turn()),
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
            _ => Err(out_of_turn()),
        }
    }

    /// Has the spawner set up the interface of container `netns_of`, with a
    /// child that starts in `cgroup`. Returns the device when the spawner
    /// created one.
    pub(crate) fn link(
        &self,
        netns_of: u64,
        link: LinkSpec,
        cgroup: Option<BorrowedFd<'_>>,
    ) -> io::Result<Option<OwnedFd>> {
        let make = |id| Request::Link {
            id,
            netns_of,
            link,
            cgroup: cgroup.is_some(),
        };
        match self.ask(make, cgroup.as_slice(), None)? {
            (_, Answer::Linked(tap)) => Ok(tap),
            (_, Answer::Failed(error)) => Err(io::Error::other(error)),
            _ => Err(out_of_turn()),
        }
    }

    /// Whether the first process of container `of` exists.
    pub(crate) fn has_init(&self, of: u64) -> io::Result<bool> {
        match self.ask(|id| Request::HasInit { id, of }, &[], None)? {
            (_, Answer::Init(exists)) => Ok(exists),
            (_, Answer::Failed(error)) => Err(io::Error::other(error)),
            _ => Err(out_of_turn()),
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
        self.shared.hung_up.store(true, Ordering::SeqCst);
        if let Ok(writer) = self.writer.lock() {
            let _ = writer.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.hang_up();
        // Reaped here unless the events thread got to it first.
        let process = self
            .shared
            .process
            .lock()
            .ok()
            .and_then(|mut process| process.take());
        if let Some(mut process) = process {
            let _ = off_worker(|| process.wait());
        }
    }
}
