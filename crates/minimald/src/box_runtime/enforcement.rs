//! The processes of a box, and the box behind a process.

use super::*;

/// Every process of one box, as a stop signals them (BOX-013): the
/// entrypoint and its descendants, every exec and its descendants, and every
/// process any of them moved to its own session with `setsid`.
///
/// The box's boundary is the PID namespace its container supervisor creates
/// for its children. Every one of those processes is in it: the entrypoint
/// is its init, a `setsid` does not leave it, and an exec joins it. Only a
/// host-address box has a cgroup of its own, and a cohort's UDP 443 block can
/// move several boxes' processes into one shared leaf, so no cgroup is the
/// box's boundary on every host.
///
/// [`BoxProcesses::signal`] reaches the namespace's init only for a signal
/// the init handles, and for SIGKILL and SIGSTOP. The kernel drops any other
/// signal that a process outside the namespace sends to its init.
///
/// A supervisor whose children share the daemon's own PID namespace (the
/// test launcher's plain process) has no namespace to scan. The box is then
/// the supervisor and its descendants.
///
/// A supervisor that is no longer this daemon's child, or whose namespace
/// cannot be read, is gone: it exited and was reaped. Its pid can belong to
/// an unrelated process by now, so the box has no processes and a stop
/// signals nothing. The daemon spawns every supervisor itself, so a process
/// with another parent is never the box's supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoxProcesses {
    /// The box's container supervisor.
    root: u32,
    /// Where the box's processes are.
    scope: ProcessScope,
}

/// Where a box's processes are, as `BoxProcesses::of_container` found them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessScope {
    /// Every process in the PID namespace with this `(device, inode)`.
    Namespace((u64, u64)),
    /// The supervisor and its descendants, in the daemon's own namespace.
    Tree,
    /// No process: the supervisor is not this daemon's child, or its
    /// namespace could not be read.
    Gone,
}

impl BoxProcesses {
    /// The processes of the box whose container supervisor is `root`.
    pub(crate) fn of_container(root: u32) -> Self {
        // BOX-013: a reaped supervisor's pid can be reused. Only a child of
        // this daemon can still be the supervisor it spawned.
        if parent_of(root) != Some(std::process::id()) {
            tracing::debug!(
                container_pid = root,
                "stop: the container supervisor is no longer this daemon's child; no process to signal"
            );
            return Self {
                root,
                scope: ProcessScope::Gone,
            };
        }
        let own = namespace_id(std::path::Path::new("/proc/self/ns/pid"));
        let boxed = namespace_id(std::path::Path::new(&format!(
            "/proc/{root}/ns/pid_for_children"
        )));
        let scope = match (boxed, own) {
            (Some(boxed), Some(own)) if boxed != own => ProcessScope::Namespace(boxed),
            (Some(_), Some(_)) => ProcessScope::Tree,
            _ => {
                // A pid whose namespace is not confirmed is never signalled:
                // the kernel can reuse a reaped supervisor's pid.
                tracing::debug!(
                    container_pid = root,
                    "stop: the container supervisor was already reaped; no process to signal"
                );
                ProcessScope::Gone
            }
        };
        Self { root, scope }
    }

    /// The box's live processes. A zombie has ended, so it is not one.
    pub(crate) fn pids(&self) -> Vec<i32> {
        match self.scope {
            ProcessScope::Gone => Vec::new(),
            ProcessScope::Namespace(namespace) => procfs_pids()
                .into_iter()
                .filter(|pid| {
                    namespace_id(std::path::Path::new(&format!("/proc/{pid}/ns/pid")))
                        == Some(namespace)
                })
                .filter(|pid| is_live(*pid))
                .collect(),
            ProcessScope::Tree => {
                let mut tree = Vec::new();
                let mut next = vec![i32::try_from(self.root).unwrap_or(i32::MAX)];
                while let Some(pid) = next.pop() {
                    if tree.contains(&pid) || !is_live(pid) {
                        continue;
                    }
                    tree.push(pid);
                    next.extend(children_of(pid));
                }
                tree
            }
        }
    }

    /// Sends `signal` to every live process of the box. Answers how many
    /// processes it reached. A process that ends between the scan and the
    /// signal is not counted.
    pub(crate) fn signal(&self, signal: i32) -> usize {
        self.pids()
            .into_iter()
            .filter(|pid| {
                // SAFETY: `kill` reads no memory of ours. A pid that is gone
                // answers ESRCH, which the count leaves out.
                unsafe { libc::kill(*pid, signal) == 0 }
            })
            .count()
    }
}

/// The `(device, inode)` that names the namespace `link` points at.
fn namespace_id(link: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(link).ok().map(|m| (m.dev(), m.ino()))
}

/// The parent pid of `pid`, as `/proc/<pid>/stat` names it.
fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The state and then the parent pid follow the last `)`, which closes
    // the command name.
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_ascii_whitespace().nth(1)?.parse().ok()
}

/// Every pid `/proc` lists.
fn procfs_pids() -> Vec<i32> {
    std::fs::read_dir("/proc")
        .map(|dir| {
            dir.filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The children of every thread of `pid`.
fn children_of(pid: i32) -> Vec<i32> {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    tasks
        .filter_map(Result::ok)
        .filter_map(|task| std::fs::read_to_string(task.path().join("children")).ok())
        .flat_map(|children| {
            children
                .split_ascii_whitespace()
                .filter_map(|child| child.parse().ok())
                .collect::<Vec<i32>>()
        })
        .collect()
}

/// Whether `pid` names a process that has not ended: it exists, and its
/// state is not zombie (`Z`) or dead (`X`).
fn is_live(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // The state follows the last `)`, which closes the command name.
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
        .is_some_and(|state| !matches!(state, 'Z' | 'X' | 'x'))
}

/// One host-address box's PID namespace, as its launch recorded it for the
/// hostname proxy's owner lookup (NET-070).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoxNamespace {
    /// The box's container supervisor, a child of this daemon.
    supervisor: u32,
    /// The `(device, inode)` of the PID namespace the supervisor's children
    /// run in: every process of the box.
    namespace: (u64, u64),
}

impl BoxNamespace {
    /// Whether the box still runs: its supervisor is still this daemon's
    /// child, and its children's PID namespace is still the recorded one.
    /// A supervisor that exited, or a pid the kernel gave to another
    /// process, fails one of the two checks.
    fn runs(&self) -> bool {
        parent_of(self.supervisor) == Some(std::process::id())
            && namespace_id(std::path::Path::new(&format!(
                "/proc/{}/ns/pid_for_children",
                self.supervisor
            ))) == Some(self.namespace)
    }
}

/// The PID namespaces of the running host-address boxes, by box (NET-070).
///
/// A host-address box shares the node's network namespace, so the hostname
/// proxy names the box behind a connection from the processes that hold its
/// socket. On a host with the classifier, a holder's classifier leaf names
/// the box. On a host without it, no box has a leaf, and the holder's PID
/// namespace is the one fact that names its box: every process of a box runs
/// in the namespace its supervisor made for it ([`BoxProcesses`]).
#[derive(Debug, Default)]
pub(crate) struct BoxNamespaces {
    by_box: BTreeMap<boxes::SessionId, BoxNamespace>,
}

impl BoxNamespaces {
    /// Records `namespace` as the PID namespace of box `id`, whose
    /// supervisor is `supervisor`. A later launch of the same box replaces
    /// the record.
    fn record(&mut self, id: boxes::SessionId, supervisor: u32, namespace: (u64, u64)) {
        self.by_box.retain(|_, recorded| recorded.runs());
        self.by_box.insert(
            id,
            BoxNamespace {
                supervisor,
                namespace,
            },
        );
    }

    /// Drops the record of box `id`.
    fn forget(&mut self, id: boxes::SessionId) {
        self.by_box.remove(&id);
    }

    /// The running box whose PID namespace is `namespace`, if one is. Each
    /// record of a box that stopped is dropped first, so a namespace the
    /// kernel freed and gave to another process names no box.
    fn owner(&mut self, namespace: (u64, u64)) -> Option<boxes::SessionId> {
        self.by_box.retain(|_, recorded| recorded.runs());
        self.by_box
            .iter()
            .find_map(|(id, recorded)| (recorded.namespace == namespace).then_some(*id))
    }
}

/// The running host-address boxes' PID namespaces, for the hostname proxy's
/// owner lookup ([`host_address_box_in_namespace`]).
static HOST_ADDRESS_NAMESPACES: std::sync::Mutex<BoxNamespaces> =
    std::sync::Mutex::new(BoxNamespaces {
        by_box: BTreeMap::new(),
    });

fn host_address_namespaces() -> std::sync::MutexGuard<'static, BoxNamespaces> {
    HOST_ADDRESS_NAMESPACES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Records the PID namespace of the host-address box `id`, whose container
/// supervisor `supervisor` this daemon just spawned (NET-070). The hostname
/// proxy names the box by it when no holder of a connection runs in a
/// classifier leaf. The record drops when the box stops: a lookup checks that
/// the supervisor still runs first.
///
/// Answers whether it recorded one. A supervisor whose children share this
/// daemon's PID namespace (the test launcher's plain process) records
/// nothing, because that namespace holds every process of the host. A
/// namespace that cannot be read records nothing too.
pub(crate) fn record_host_address_box_namespace(id: boxes::SessionId, supervisor: u32) -> bool {
    let own = namespace_id(std::path::Path::new("/proc/self/ns/pid"));
    let boxed = namespace_id(std::path::Path::new(&format!(
        "/proc/{supervisor}/ns/pid_for_children"
    )));
    match (boxed, own) {
        (Some(boxed), Some(own)) if boxed != own => {
            host_address_namespaces().record(id, supervisor, boxed);
            tracing::debug!(
                session = %id,
                supervisor,
                "recorded the host-address box's PID namespace for the hostname proxy's owner lookup"
            );
            true
        }
        _ => {
            host_address_namespaces().forget(id);
            tracing::debug!(
                session = %id,
                supervisor,
                "the host-address box has no PID namespace of its own to record"
            );
            false
        }
    }
}

/// Records the host-address box's PID namespace, or refuses the launch
/// when there is none to record (NET-070). A box the launch cannot record
/// is one the hostname proxy cannot tell from a process outside every box,
/// so the launch fails closed rather than run it unattributed.
pub(crate) fn require_host_address_box_namespace(
    id: boxes::SessionId,
    supervisor: u32,
) -> std::io::Result<()> {
    if record_host_address_box_namespace(id, supervisor) {
        return Ok(());
    }
    tracing::warn!(
        session = %id,
        supervisor,
        "refused the host-address box: no PID namespace of its own to record for the hostname proxy's owner lookup"
    );
    Err(std::io::Error::other(
        "the box did not start: Minimal cannot read the box's process namespace, \
         so the hostname proxy cannot tell which box opens a connection",
    ))
}

/// The running host-address box whose PID namespace is `namespace`, the
/// `(device, inode)` of a process's `/proc/<pid>/ns/pid` (NET-070). `None`
/// when no running host-address box runs in it.
pub(crate) fn host_address_box_in_namespace(namespace: (u64, u64)) -> Option<boxes::SessionId> {
    host_address_namespaces().owner(namespace)
}

/// The `(device, inode)` of process `pid`'s PID namespace, or `None` when
/// `/proc` does not show it to this daemon.
#[cfg(test)]
pub(crate) fn pid_namespace_of(pid: u32) -> Option<(u64, u64)> {
    namespace_id(std::path::Path::new(&format!("/proc/{pid}/ns/pid")))
}

/// The deepest PID namespace nesting the kernel allows, plus the daemon's own.
const MAX_PID_NAMESPACE_DEPTH: usize = 33;

/// The `(device, inode)` of process `pid`'s PID namespace and of each of its
/// parents, innermost first, up to the daemon's own (NET-070). A process in a
/// box that makes a nested PID namespace (`unshare -p`, a container in the
/// box) runs in a namespace no box recorded. Its box's namespace is one of
/// the parents, so the owner lookup checks each of them. `None` when `/proc`
/// does not show the namespace or the kernel refuses to name a parent.
pub(crate) fn pid_namespaces_of(pid: u32) -> Option<Vec<(u64, u64)>> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::MetadataExt as _;
    // `_IO(0xb7, 0x2)` from `<linux/nsfs.h>`.
    const NS_GET_PARENT: u32 = 0xb702;
    let mut current = std::fs::File::open(format!("/proc/{pid}/ns/pid")).ok()?;
    let mut lineage = Vec::new();
    loop {
        let meta = current.metadata().ok()?;
        lineage.push((meta.dev(), meta.ino()));
        if lineage.len() > MAX_PID_NAMESPACE_DEPTH {
            return None;
        }
        // SAFETY: `current` is an open namespace file for the whole call,
        // and `NS_GET_PARENT` takes no argument.
        // The request is `c_ulong` on glibc and `c_int` on musl.
        let parent = unsafe { libc::ioctl(current.as_raw_fd(), NS_GET_PARENT as _) };
        if parent < 0 {
            // EPERM: the parent lies outside the daemon's own namespace, or
            // there is none. The walk is complete.
            return (std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
                .then_some(lineage);
        }
        // SAFETY: the ioctl returned a new descriptor that nothing else owns.
        current = unsafe { std::fs::File::from_raw_fd(parent) };
    }
}

#[cfg(test)]
mod namespace_tests {
    use super::*;

    /// NET-070: a record names its box while the supervisor runs, and drops
    /// when the supervisor stops. A supervisor that is not this process's
    /// child names no box.
    #[test]
    fn owner_by_pid_namespace_without_classifier_leaf_drops_at_stop() {
        let id = boxes::SessionId::parse_str("00000000-0000-0000-0000-0000000000c1").unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in supervisor");
        let namespace = namespace_id(std::path::Path::new(&format!(
            "/proc/{}/ns/pid_for_children",
            child.id()
        )))
        .expect("the child's namespace is readable");
        let mut namespaces = BoxNamespaces::default();
        namespaces.record(id, child.id(), namespace);
        assert_eq!(namespaces.owner(namespace), Some(id));
        assert_eq!(namespaces.owner((0, 0)), None, "another namespace");

        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(namespaces.owner(namespace), None, "the box stopped");
        assert!(namespaces.by_box.is_empty(), "the record dropped");

        // pid 1 is never this process's child.
        namespaces.record(id, 1, namespace);
        assert_eq!(namespaces.owner(namespace), None);

        // A supervisor whose children share this process's namespace records
        // nothing.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert!(!record_host_address_box_namespace(id, child.id()));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// NET-070: a launch whose box has no PID namespace of its own to record
    /// fails, so the box never runs unattributed. A plain child shares this
    /// process's namespace, which is the case the launcher must refuse.
    #[test]
    fn owner_by_pid_namespace_without_classifier_leaf_refuses_unrecorded_launch() {
        let id = boxes::SessionId::parse_str("00000000-0000-0000-0000-0000000000c2").unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let refused = require_host_address_box_namespace(id, child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        let err = refused.expect_err("an unrecorded host-address box must not start");
        assert!(
            err.to_string()
                .contains("cannot tell which box opens a connection"),
            "{err}"
        );
        assert!(
            !host_address_namespaces().by_box.contains_key(&id),
            "no record"
        );
    }
}
