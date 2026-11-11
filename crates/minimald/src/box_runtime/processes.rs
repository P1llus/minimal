//! The processes of a box, as a stop reaches them.

use super::*;

/// The processes a stop signals (BOX-013).
///
/// A box's boundary is its cgroup: every process that runs in the box or for
/// it starts there, and none can leave. A daemon with no cgroup root runs
/// its boxes without one. Such a box is reached through its entrypoint, the
/// init of its PID namespace, which the namespace's other processes die
/// with.
///
/// The kernel delivers a signal from outside a PID namespace to the
/// namespace's init only when the init handles it, and for SIGKILL and
/// SIGSTOP.
#[derive(Debug, Clone)]
pub(crate) enum BoxProcesses {
    /// Every process in the box's cgroup.
    Cgroup(sandbox::cgroup::BoxCgroup),
    /// The entrypoint of a box that has no cgroup, through its host.
    Entrypoint(HostHandle),
}

impl BoxProcesses {
    /// Whether a signal leaves `pid` out. The supervisor of a container
    /// ends when the container's program does, and a supervisor that dies
    /// first takes the program with it at once, which is what a stop's
    /// grace period is there to avoid.
    fn spared(pid: u32) -> bool {
        sandbox::Spawner::current().supervises(pid)
    }

    /// Sends `signal` to the box's processes, and says how many it reached.
    /// SIGKILL goes to the whole cgroup at once, which also ends a process
    /// that forks faster than it can be listed.
    pub(crate) async fn signal(&self, signal: i32) -> usize {
        match self {
            Self::Cgroup(cgroup) if signal == libc::SIGKILL => {
                let reached = cgroup.procs().map_or(0, |pids| pids.len());
                if let Err(error) = cgroup.kill() {
                    tracing::warn!(%error, cgroup = cgroup.name(), "stop: killing the box's cgroup");
                }
                reached
            }
            Self::Cgroup(cgroup) => cgroup.signal(signal, Self::spared).unwrap_or_else(|error| {
                tracing::debug!(%error, cgroup = cgroup.name(), "stop: the box's cgroup is gone");
                0
            }),
            Self::Entrypoint(host) => usize::from(host.signal_entrypoint(signal).await.is_ok()),
        }
    }

    /// How many of the box's processes still run, the supervisors of its
    /// containers aside. A box with no cgroup cannot list its processes,
    /// and answers zero: its stop goes by its entrypoint's end alone.
    pub(crate) fn left(&self) -> usize {
        match self {
            Self::Cgroup(cgroup) => cgroup.procs().map_or(0, |pids| {
                pids.into_iter().filter(|pid| !Self::spared(*pid)).count()
            }),
            Self::Entrypoint(_) => 0,
        }
    }
}
