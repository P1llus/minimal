//! The spawner's loop.
//!
//! One thread serves one peer. It starts what the peer asks for, is the
//! parent of all of it, and reaps it. It waits on the peer's socket and on a
//! pidfd per job, so it needs no signal handler. When the peer closes the
//! socket, every job is killed: nothing the spawner started outlives the
//! process that asked for it.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use super::core;
use super::wire::{self, Event, Request};
use super::{ExitStatus, title};

/// The descriptor a spawner process finds its peer's socket on.
pub(crate) const SOCKET_FD: libc::c_int = 3;

/// How often a running foreground job is looked at, in milliseconds.
const FOREGROUND_WATCH: libc::c_int = 100;

/// What a job's direct child is.
enum Process {
    Container(Box<core::Container>),
    Shim(core::Shim),
}

struct Job {
    process: Process,
    /// A container's first process, pinned the first time something needs it.
    init: Option<(u32, OwnedFd)>,
    /// Whether the job took the foreground of the spawner's terminal.
    foreground: bool,
}

impl Job {
    fn pidfd(&self) -> BorrowedFd<'_> {
        match &self.process {
            Process::Container(container) => container.supervisor.as_fd(),
            Process::Shim(shim) => shim.pidfd.as_fd(),
        }
    }

    /// A container's first process. Looked up again when the pinned one has
    /// exited, which no running container's has.
    fn init(&mut self) -> Option<(u32, BorrowedFd<'_>)> {
        let Process::Container(container) = &self.process else {
            return None;
        };
        if self
            .init
            .as_ref()
            .is_none_or(|(_, pidfd)| core::exited(pidfd.as_fd()))
        {
            self.init = core::pinned_init(container.child.id());
        }
        self.init.as_ref().map(|(pid, pidfd)| (*pid, pidfd.as_fd()))
    }
}

struct Server {
    sock: UnixStream,
    /// The binary that runs as the enter shim.
    exe: Option<PathBuf>,
    /// Whether this is a spawner process, which names what it forks.
    titled: bool,
    jobs: HashMap<u64, Job>,
    /// Set once the peer cannot be told anything more.
    peer_gone: bool,
}

/// The entry point of a spawner process: `args` is what follows the mode
/// word, the path of the binary to run as the enter shim.
pub(crate) fn main(mut args: impl Iterator<Item = OsString>) -> ! {
    title::set_comm(c"minimal-spawner");
    let exe = args.next().map(PathBuf::from);
    // SAFETY: the process that started this one put the socket on this
    // descriptor, and nothing else here owns it.
    let sock = unsafe { UnixStream::from_raw_fd(SOCKET_FD) };
    // Nothing this process execs gets the socket.
    // SAFETY: `fcntl` on the descriptor just adopted.
    unsafe { libc::fcntl(SOCKET_FD, libc::F_SETFD, libc::FD_CLOEXEC) };
    serve(sock, exe, true);
    std::process::exit(0)
}

/// Serves `sock` until its peer closes it, then ends every job.
pub(crate) fn serve(sock: UnixStream, exe: Option<PathBuf>, titled: bool) {
    let mut server = Server {
        sock,
        exe,
        titled,
        jobs: HashMap::new(),
        peer_gone: false,
    };
    while !server.peer_gone {
        server.turn();
    }
    server.end();
}

impl Server {
    /// Waits for the peer or a job, and serves whichever is ready.
    fn turn(&mut self) {
        let ids: Vec<u64> = self.jobs.keys().copied().collect();
        let mut polled = vec![libc::pollfd {
            fd: self.sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        polled.extend(ids.iter().map(|id| libc::pollfd {
            fd: self.jobs[id].pidfd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }));
        // A foreground job can stop without ending, which no descriptor
        // reports, so it is looked at between waits.
        let foreground = self.jobs.values().any(|job| job.foreground);
        let wait = if foreground { FOREGROUND_WATCH } else { -1 };
        // SAFETY: `poll` reads and writes the `pollfd`s of the vector.
        let ready = unsafe { libc::poll(polled.as_mut_ptr(), polled.len() as libc::nfds_t, wait) };
        if ready < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                self.peer_gone = true;
            }
            return;
        }
        for (id, poll) in ids.iter().zip(&polled[1..]) {
            if poll.revents != 0 {
                self.reap(*id);
            }
        }
        if foreground {
            self.watch_foreground();
        }
        if polled[0].revents != 0 {
            match wire::recv::<Request>(&mut self.sock) {
                Ok(Some((request, fds))) => self.handle(request, fds),
                Ok(None) | Err(_) => self.peer_gone = true,
            }
        }
    }

    /// Suspends this process's own job with any foreground job whose
    /// program the terminal's stop key has stopped. Returns once the job
    /// is continued.
    fn watch_foreground(&mut self) {
        for job in self.jobs.values_mut().filter(|job| job.foreground) {
            let Some((init, _)) = job.init() else {
                continue;
            };
            if core::foreground_program(init).is_some_and(core::stopped) {
                core::suspend_with(init);
            }
        }
    }

    fn send(&mut self, event: &Event, fds: &[BorrowedFd<'_>]) {
        if wire::send(&mut self.sock, event, fds).is_err() {
            self.peer_gone = true;
        }
    }

    /// Reaps job `id`, whose pidfd reported an exit, and tells the peer.
    fn reap(&mut self, id: u64) {
        let Some(job) = self.jobs.get_mut(&id) else {
            return;
        };
        let status = match &mut job.process {
            Process::Container(container) => {
                let status = match container.child.try_wait() {
                    Ok(Some(status)) => core::exit_status(status),
                    Ok(None) => return,
                    Err(error) => ExitStatus::failure(format!("waiting for the box: {error}")),
                };
                // hakoniwa answers from its own record for a container it
                // killed during setup, and leaves that one unreaped.
                let _ = core::reap(container.child.id(), false);
                status
            }
            Process::Shim(shim) => match core::reap(shim.pid, false) {
                Ok(Some(status)) => core::shim_status(status),
                Ok(None) => return,
                Err(error) => ExitStatus::failure(format!("waiting for the enter shim: {error}")),
            },
        };
        if job.foreground
            && let Some((init, _)) = &job.init
        {
            core::retake_foreground(*init);
        }
        self.jobs.remove(&id);
        self.send(&Event::Exited { id, status }, &[]);
    }

    fn handle(&mut self, request: Request, fds: Vec<OwnedFd>) {
        match request {
            Request::Run { id, run, cgroup } => {
                let foreground = run.session == wire::Session::Foreground;
                let started = stdio_and_cgroup(fds, cgroup)
                    .and_then(|(stdio, cgroup)| core::run(&run, stdio, cgroup, self.titled));
                match started {
                    Ok(mut container) => {
                        let netns = container.netns.take();
                        let tap = container.tap.take();
                        let event = Event::Started {
                            id,
                            pid: container.child.id(),
                            netns: netns.is_some(),
                            tap: tap.is_some(),
                        };
                        let fds: Vec<BorrowedFd<'_>> =
                            netns.iter().chain(&tap).map(|fd| fd.as_fd()).collect();
                        self.send(&event, &fds);
                        self.jobs.insert(
                            id,
                            Job {
                                process: Process::Container(Box::new(container)),
                                init: None,
                                foreground,
                            },
                        );
                        // The group a foreground job runs in is its first
                        // process's, which is needed even after a job that
                        // ends at once.
                        if foreground && let Some(job) = self.jobs.get_mut(&id) {
                            job.init();
                        }
                    }
                    Err(error) => self.fail(id, &error),
                }
            }
            Request::Enter {
                id,
                into,
                enter,
                cgroup,
            } => match self.enter(into, &enter, fds, cgroup) {
                Ok(shim) => {
                    let event = Event::Started {
                        id,
                        pid: shim.pid,
                        netns: false,
                        tap: false,
                    };
                    self.send(&event, &[]);
                    self.jobs.insert(
                        id,
                        Job {
                            process: Process::Shim(shim),
                            init: None,
                            foreground: false,
                        },
                    );
                }
                Err(error) => self.fail(id, &error),
            },
            Request::Socket {
                id,
                netns_of,
                v6,
                datagram,
                cgroup,
            } => {
                let cgroup = if cgroup { fds.into_iter().next() } else { None };
                let netns_of = match netns_of {
                    // A job in the table is not reaped, so its pid is its own.
                    Some(job) => match self.jobs.get(&job).map(|job| &job.process) {
                        Some(Process::Container(container)) => Ok(Some(container.child.id())),
                        _ => Err(io::Error::other("the network's process has exited")),
                    },
                    None => Ok(None),
                };
                let made = netns_of.and_then(|netns_of| {
                    core::socket(netns_of, v6, datagram, cgroup.as_ref().map(|fd| fd.as_fd()))
                });
                match made {
                    Ok(socket) => self.send(&Event::Socket { id }, &[socket.as_fd()]),
                    Err(error) => self.fail(id, &error),
                }
            }
            Request::Signal {
                id,
                signal,
                to_init,
            } => {
                if let Some(job) = self.jobs.get_mut(&id) {
                    if to_init {
                        if let Some((_, init)) = job.init() {
                            core::signal(init, signal);
                        }
                    } else {
                        core::signal(job.pidfd(), signal);
                    }
                }
            }
            Request::Forget { id } => {
                if let Some(job) = self.jobs.get(&id) {
                    core::signal(job.pidfd(), libc::SIGKILL);
                }
            }
        }
    }

    fn fail(&mut self, id: u64, error: &io::Error) {
        let event = Event::Failed {
            id,
            error: error.to_string(),
        };
        self.send(&event, &[]);
    }

    fn enter(
        &mut self,
        into: u64,
        enter: &wire::Enter,
        fds: Vec<OwnedFd>,
        cgroup: bool,
    ) -> io::Result<core::Shim> {
        let (stdio, cgroup) = stdio_and_cgroup(fds, cgroup)?;
        let exe = self.exe.clone().ok_or_else(|| {
            io::Error::other("this spawner has no binary to run as the enter shim")
        })?;
        let (init_pid, init) = self
            .jobs
            .get_mut(&into)
            .and_then(Job::init)
            .ok_or_else(|| io::Error::other("the box has no running first process"))?;
        core::enter(
            &exe,
            init_pid,
            init,
            enter,
            stdio,
            cgroup.as_ref().map(|fd| fd.as_fd()),
        )
    }

    /// Kills every job and reaps it.
    fn end(mut self) {
        for job in self.jobs.values() {
            core::signal(job.pidfd(), libc::SIGKILL);
        }
        for (_, job) in self.jobs.drain() {
            match job.process {
                Process::Container(mut container) => {
                    let _ = container.child.wait();
                    let _ = core::reap(container.child.id(), false);
                }
                Process::Shim(shim) => {
                    let _ = core::reap(shim.pid, true);
                }
            }
        }
    }
}

/// Splits a request's descriptors into the three of its stdio and the box
/// cgroup that follows them when `cgroup` says one does.
fn stdio_and_cgroup(
    fds: Vec<OwnedFd>,
    cgroup: bool,
) -> io::Result<([OwnedFd; 3], Option<OwnedFd>)> {
    let mut fds = fds.into_iter();
    let mut next = || {
        fds.next()
            .ok_or_else(|| io::Error::other("the request carried too few descriptors"))
    };
    let stdio = [next()?, next()?, next()?];
    let cgroup = if cgroup { Some(next()?) } else { None };
    Ok((stdio, cgroup))
}
