//! How an unprivileged daemon gets its engine from a root loader.
//!
//! The daemon connects to the loader's `SOCK_SEQPACKET` socket and sends one
//! message with the descriptor of its `boxes/` cgroup. The loader checks
//! who is asking, loads and attaches the programs there, and answers with
//! one message that carries the map descriptors.
//!
//! The loader keeps no state. The attachment belongs to the cgroup, and a
//! repeated request for the same cgroup finds the programs through the
//! kernel and hands out the same maps.
//!
//! On a host without a systemd user manager nobody delegates a cgroup to the
//! daemon. There the daemon first asks for a root: the loader creates a
//! cgroup for it, marks it delegated, moves the daemon into its
//! `supervisor/` and hands the directory over. The attach request that
//! follows is checked exactly like any other.
//!
//! Wire format, one line of text per message:
//! - request: `attach abi=<n>`, with one descriptor
//! - reply: `ok abi=<n> object=<id> cgroup=<id> reused=<0|1>`, with one
//!   descriptor per map in a fixed order. `object` names the programs the
//!   loader carries, and the daemon refuses any but its own.
//! - request: `root abi=<n>`
//! - reply: `ok abi=<n> root=<path>`, with the descriptor of the new root
//! - any refusal: `err <reason>`

use std::{
    fs, io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use netpol::abi;
use nix::{
    fcntl::{OFlag, openat},
    sys::{
        socket::{
            self, AddressFamily, SockFlag, SockType, UnixAddr,
            sockopt::{PeerCredentials, ReceiveTimeout},
        },
        stat::Mode,
        time::TimeVal,
    },
};

use crate::{Engine, Error, Handles, MapSizes, engine, sys};

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const REQUEST_TIMEOUT_SECS: i64 = 5;
const REPLY_TIMEOUT_SECS: i64 = 30;

/// What the loader does for a request it accepts.
#[derive(Debug, Clone, Default)]
pub struct ServeOptions {
    pub sizes: MapSizes,
    /// Where to create cgroup roots for daemons that ask for one, as a
    /// path below the cgroup mount. `None` refuses such requests: on a
    /// systemd host the daemon gets its root from systemd.
    pub handover_base: Option<PathBuf>,
}

/// A request the loader served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Served {
    /// An engine at the peer's `boxes/`.
    Engine {
        uid: u32,
        /// Cgroup id of the attach point.
        cgroup: u64,
        /// The cgroup path below the cgroup mount, as the loader sees it.
        path: PathBuf,
        /// True when the programs were already attached there.
        reused: bool,
    },
    /// A new cgroup root for the peer, which now runs in its `supervisor/`.
    Root { uid: u32, path: PathBuf },
}

/// Why a request was turned down. The text goes to the peer and to the log.
#[derive(Debug, thiserror::Error)]
enum Refusal {
    #[error("{0}")]
    Policy(String),
    #[error("{what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

fn policy<T>(reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal::Policy(reason.into()))
}

fn io_step(what: &'static str) -> impl FnOnce(io::Error) -> Refusal {
    move |source| Refusal::Io { what, source }
}

fn nix_step(what: &'static str) -> impl FnOnce(nix::Error) -> Refusal {
    move |e| Refusal::Io {
        what,
        source: io::Error::from(e),
    }
}

fn cgroup_path(fd: BorrowedFd<'_>) -> Result<PathBuf, Refusal> {
    let path = sys::fd_path(fd).map_err(io_step("resolve a cgroup descriptor"))?;
    match path.strip_prefix(CGROUP_MOUNT) {
        Ok(rel) => Ok(rel.to_path_buf()),
        Err(_e) => policy(format!("{} is not below {CGROUP_MOUNT}", path.display())),
    }
}

/// The peer's cgroup path below the cgroup mount.
///
/// With a pidfd the kernel reports the cgroup of exactly that process, so
/// a recycled pid cannot mislead us. Before 6.13 the pidfd has no cgroup
/// query: we read `/proc/<pid>/cgroup` and then check that the pidfd still
/// names a live process, which rules out reuse of the pid during the read.
fn peer_cgroup(conn: BorrowedFd<'_>, pid: i32) -> Result<PathBuf, Refusal> {
    let pidfd = sys::peer_pidfd(conn).map_err(io_step("get a pidfd of the peer"))?;
    if let Ok(id) = sys::pidfd_cgroup_id(pidfd.as_fd()) {
        let mount =
            sys::open_dir(Path::new(CGROUP_MOUNT)).map_err(io_step("open the cgroup mount"))?;
        let dir =
            sys::open_cgroup_by_id(mount.as_fd(), id).map_err(io_step("open the peer's cgroup"))?;
        return cgroup_path(dir.as_fd());
    }
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(io_step("read the peer's cgroup"))?;
    if !sys::pidfd_alive(pidfd.as_fd()) {
        return policy("the peer exited during the check");
    }
    match text.lines().find_map(|l| l.strip_prefix("0::")) {
        Some(path) => Ok(PathBuf::from(path.trim_start_matches('/'))),
        None => policy("the peer has no cgroup v2 membership"),
    }
}

struct Target {
    uid: u32,
    path: PathBuf,
}

fn owner(dir: BorrowedFd<'_>) -> Result<u32, Refusal> {
    let dir = dir
        .try_clone_to_owned()
        .map_err(io_step("duplicate the descriptor"))?;
    let meta = fs::File::from(dir)
        .metadata()
        .map_err(io_step("stat a cgroup"))?;
    Ok(meta.uid())
}

/// Decides whether the peer may have an engine at `boxes`.
///
/// Everything is read from the descriptor the peer sent: ownership,
/// filesystem, name. No path the peer controls is resolved.
fn authorize(conn: BorrowedFd<'_>, boxes: BorrowedFd<'_>) -> Result<Target, Refusal> {
    let cred = socket::getsockopt(&conn, PeerCredentials)
        .map_err(nix_step("read the peer's credentials"))?;
    let uid = cred.uid();

    if !sys::is_cgroup2(boxes).map_err(io_step("stat the descriptor"))? {
        return policy("the descriptor is not a cgroup2 directory");
    }
    let path = cgroup_path(boxes)?;
    if path.file_name().is_none_or(|n| n != "boxes") {
        return policy("the attach point must be a cgroup named boxes");
    }

    // A cgroup belongs to a user only when root gave it away: a delegated
    // unit, or a root this loader handed over. So `boxes` and the root
    // above it must be the peer's. Root itself needs no loader.
    if uid == 0 {
        return policy("root loads the programs itself");
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    let root =
        openat(boxes, "..", flags, Mode::empty()).map_err(nix_step("open the parent cgroup"))?;
    for dir in [boxes, root.as_fd()] {
        if owner(dir)? != uid {
            return policy(format!(
                "the attach point and the cgroup above it must belong to uid {uid}: \
                 the daemon needs a delegated cgroup"
            ));
        }
    }

    // Only the daemon's own cgroup may ask. A process in boxes/ is a box
    // process: it has the daemon's uid and must not get the policy maps.
    let Some(root) = path.parent() else {
        return policy("the attach point has no parent cgroup");
    };
    let supervisor = root.join("supervisor");
    let peer = peer_cgroup(conn, cred.pid())?;
    if peer != supervisor {
        return policy(format!(
            "the peer runs in /{}, not in /{}",
            peer.display(),
            supervisor.display()
        ));
    }
    Ok(Target { uid, path })
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// The reply line and the descriptors that go with it.
type Reply = (String, Vec<OwnedFd>);

fn attach(
    conn: BorrowedFd<'_>,
    mut fds: Vec<OwnedFd>,
    options: &ServeOptions,
) -> Result<(Served, Reply), Refusal> {
    let (Some(boxes), None) = (fds.pop(), fds.pop()) else {
        return policy("an attach request must carry exactly one descriptor");
    };
    let target = authorize(conn, boxes.as_fd())?;
    let cgroup = sys::cgroup_id(boxes.as_fd()).map_err(io_step("read the cgroup id"))?;

    let engine_error = |e: Error| Refusal::Policy(e.to_string());
    let (maps, reused) = match engine::find_attached(boxes.as_fd()).map_err(engine_error)? {
        Some(maps) => (maps, true),
        None => {
            let mut engine = Engine::load(boxes.as_fd(), &options.sizes).map_err(engine_error)?;
            engine.attach(boxes.as_fd()).map_err(engine_error)?;
            (engine.map_fds().map_err(engine_error)?, false)
        }
    };
    let reply = format!(
        "ok abi={} object={} cgroup={cgroup} reused={}",
        abi::VERSION,
        engine::object_id(),
        u8::from(reused)
    );
    Ok((
        Served::Engine {
            uid: target.uid,
            cgroup,
            path: target.path,
            reused,
        },
        (reply, maps),
    ))
}

/// Removes roots of earlier daemons that have ended. A cgroup that still
/// has processes or children refuses the removal, which is the check.
fn sweep_roots(base: &Path) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for root in entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
        if let Ok(boxes) = fs::read_dir(root.join("boxes")) {
            for stale in boxes.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
                let _busy = fs::remove_dir(stale);
            }
        }
        for dir in [root.join("boxes"), root.join("supervisor"), root] {
            let _busy = fs::remove_dir(dir);
        }
    }
}

/// What a delegation hands to the owner, per the kernel's cgroup rules: the
/// directory and the files that move processes and enable controllers.
fn delegate(dir: &Path, uid: u32, gid: u32) -> Result<(), Refusal> {
    for file in [
        "",
        "cgroup.procs",
        "cgroup.threads",
        "cgroup.subtree_control",
    ] {
        std::os::unix::fs::chown(dir.join(file), Some(uid), Some(gid))
            .map_err(io_step("chown the new root"))?;
    }
    Ok(())
}

/// A root is for a daemon nobody delegated a cgroup to. A peer below a
/// cgroup that belongs to a user already has one: it is a daemon in a
/// delegated unit, which asks systemd, or it is a process of a box, which
/// must stay where it is. Every cgroup outside a delegation belongs to root.
fn refuse_delegated_peer(conn: BorrowedFd<'_>, pid: i32) -> Result<(), Refusal> {
    let peer = peer_cgroup(conn, pid)?;
    let mut dir = Path::new(CGROUP_MOUNT).join(&peer);
    while dir.starts_with(CGROUP_MOUNT) && dir != Path::new(CGROUP_MOUNT) {
        let meta = fs::metadata(&dir).map_err(io_step("stat the peer's cgroup"))?;
        if meta.uid() != 0 {
            return policy(format!(
                "the peer runs below /{}, a cgroup that is delegated already",
                dir.strip_prefix(CGROUP_MOUNT).unwrap_or(&dir).display()
            ));
        }
        if !dir.pop() {
            break;
        }
    }
    Ok(())
}

fn hand_over_root(
    conn: BorrowedFd<'_>,
    options: &ServeOptions,
) -> Result<(Served, Reply), Refusal> {
    let Some(base) = &options.handover_base else {
        return policy(
            "this loader hands out no cgroup roots: start the daemon in a delegated systemd unit",
        );
    };
    let cred = socket::getsockopt(&conn, PeerCredentials)
        .map_err(nix_step("read the peer's credentials"))?;
    let pidfd = sys::peer_pidfd(conn).map_err(io_step("get a pidfd of the peer"))?;
    refuse_delegated_peer(conn, cred.pid())?;

    let base_dir = Path::new(CGROUP_MOUNT).join(base);
    fs::create_dir_all(&base_dir).map_err(io_step("create the base cgroup"))?;
    sweep_roots(&base_dir);
    // Controllers reach the new root only if every level above passes them
    // on. Where one cannot, the root simply has fewer: limits are optional.
    for level in [Path::new(CGROUP_MOUNT), base_dir.as_path()] {
        let _partial = fs::write(level.join("cgroup.subtree_control"), "+cpu +memory +pids");
    }

    let rel = base.join(format!("u{}-{}", cred.uid(), cred.pid()));
    let root = Path::new(CGROUP_MOUNT).join(&rel);
    let supervisor = root.join("supervisor");
    fs::create_dir(&root).map_err(io_step("create the new root"))?;
    fs::create_dir(&supervisor).map_err(io_step("create supervisor/"))?;
    delegate(&root, cred.uid(), cred.gid())?;
    delegate(&supervisor, cred.uid(), cred.gid())?;
    let root_fd = sys::open_dir(&root).map_err(io_step("open the new root"))?;

    // The daemon cannot move itself: that takes write access to a cgroup
    // above both its old place and the new one.
    fs::write(supervisor.join("cgroup.procs"), cred.pid().to_string())
        .map_err(io_step("move the peer"))?;
    // The pid could have been recycled between the peer's connect and the
    // write. The pidfd still names the peer: if it is gone, so is our claim
    // on whoever got moved.
    if !sys::pidfd_alive(pidfd.as_fd()) {
        return policy("the peer exited during the handover");
    }
    let reply = format!("ok abi={} root={}", abi::VERSION, root.display());
    Ok((
        Served::Root {
            uid: cred.uid(),
            path: rel,
        },
        (reply, vec![root_fd]),
    ))
}

fn serve_inner(conn: BorrowedFd<'_>, options: &ServeOptions) -> Result<(Served, Reply), Refusal> {
    // The loader serves one connection at a time. A peer that connects and
    // then says nothing must not hold it up.
    socket::setsockopt(
        &conn,
        ReceiveTimeout,
        &TimeVal::new(REQUEST_TIMEOUT_SECS, 0),
    )
    .map_err(nix_step("set the request timeout"))?;
    let (request, fds) =
        sys::recv_with_fds(conn.as_raw_fd()).map_err(io_step("read the request"))?;
    let request = String::from_utf8_lossy(&request);
    // A daemon built against other layouts would misread every map.
    let theirs = field(&request, "abi").and_then(|v| v.parse::<u32>().ok());
    if theirs != Some(abi::VERSION) {
        return policy(format!(
            "abi mismatch: loader={} daemon={}",
            abi::VERSION,
            theirs.map_or_else(|| "?".to_owned(), |v| v.to_string())
        ));
    }
    match request.split_whitespace().next() {
        Some("attach") => attach(conn, fds, options),
        Some("root") if fds.is_empty() => hand_over_root(conn, options),
        _ => policy("unknown request"),
    }
}

/// Serves one accepted connection of the loader socket. Needs root.
///
/// On refusal the peer is told why, and the same reason comes back as
/// [`Error::Refused`] for the loader's log.
pub fn serve(conn: BorrowedFd<'_>, options: &ServeOptions) -> Result<Served, Error> {
    match serve_inner(conn, options) {
        Ok((served, (reply, fds))) => {
            let raw: Vec<_> = fds.iter().map(AsRawFd::as_raw_fd).collect();
            sys::send_with_fds(conn.as_raw_fd(), reply.as_bytes(), &raw)
                .map_err(Error::sys("send the reply"))?;
            Ok(served)
        }
        Err(refusal) => {
            let reason = refusal.to_string();
            // The peer may be gone already. The refusal itself is what matters.
            let _unsent =
                sys::send_with_fds(conn.as_raw_fd(), format!("err {reason}").as_bytes(), &[]);
            Err(Error::Refused(reason))
        }
    }
}

/// One request and its reply, checked for refusal and ABI.
fn exchange(
    socket: &Path,
    request: &str,
    fds: &[std::os::fd::RawFd],
) -> Result<(String, Vec<OwnedFd>), Error> {
    let addr = UnixAddr::new(socket).map_err(|e| Error::Sys {
        what: "name the loader socket",
        source: e.into(),
    })?;
    let conn = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| Error::Sys {
        what: "create a socket",
        source: e.into(),
    })?;
    socket::connect(conn.as_raw_fd(), &addr).map_err(|e| Error::Sys {
        what: "connect to the policy loader",
        source: e.into(),
    })?;
    // Loading and verifying thirteen programs takes well under a second.
    // A loader that stays silent this long is not going to answer.
    socket::setsockopt(&conn, ReceiveTimeout, &TimeVal::new(REPLY_TIMEOUT_SECS, 0)).map_err(
        |e| Error::Sys {
            what: "set the reply timeout",
            source: e.into(),
        },
    )?;
    let line = format!("{request} abi={}", abi::VERSION);
    sys::send_with_fds(conn.as_raw_fd(), line.as_bytes(), fds)
        .map_err(Error::sys("send the request to the policy loader"))?;
    let (reply, fds) = sys::recv_with_fds(conn.as_raw_fd())
        .map_err(Error::sys("read the policy loader's reply"))?;
    let reply = String::from_utf8_lossy(&reply).into_owned();

    if let Some(reason) = reply.strip_prefix("err ") {
        // Name the fix when the two sides were built from different layouts.
        if reason.starts_with("abi mismatch")
            && let Some(loader) = field(reason, "loader").and_then(|v| v.parse().ok())
        {
            return Err(Error::AbiMismatch {
                loader,
                daemon: abi::VERSION,
            });
        }
        return Err(Error::Refused(reason.to_owned()));
    }
    if !reply.starts_with("ok ") {
        return Err(Error::Protocol(reply));
    }
    match field(&reply, "abi").and_then(|v| v.parse::<u32>().ok()) {
        Some(v) if v == abi::VERSION => Ok((reply, fds)),
        Some(loader) => Err(Error::AbiMismatch {
            loader,
            daemon: abi::VERSION,
        }),
        None => Err(Error::Protocol(reply)),
    }
}

/// Asks the loader at `socket` for an engine at `boxes` and returns its
/// handles. The caller must run in the `supervisor` cgroup next to `boxes`.
///
/// A loader that carries other programs than this build is refused: the
/// daemon would write maps for programs it does not know.
pub fn request(socket: &Path, boxes: BorrowedFd<'_>) -> Result<Handles, Error> {
    let (reply, fds) = exchange(socket, "attach", &[boxes.as_raw_fd()])?;
    let loader = field(&reply, "object").unwrap_or("unknown");
    if loader != engine::object_id() {
        return Err(Error::ObjectMismatch {
            loader: loader.to_owned(),
            daemon: engine::object_id().to_owned(),
        });
    }
    Handles::from_fds(fds)
}

/// Asks the loader for a cgroup root, for a daemon that has none because
/// the host has no systemd user manager. On return the calling process runs
/// in `supervisor/` of the root whose directory is returned. The caller
/// creates `boxes/` in it and calls [`request`].
///
/// Call this before starting any thread: the loader moves the process.
pub fn request_root(socket: &Path) -> Result<OwnedFd, Error> {
    let (reply, mut fds) = exchange(socket, "root", &[])?;
    match (fds.pop(), fds.pop()) {
        (Some(root), None) => Ok(root),
        _ => Err(Error::Protocol(reply)),
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::socket::{Backlog, accept, bind, listen};

    use super::*;

    /// A loader that answers every request with `reply` and no descriptors.
    fn fake_loader(socket: &Path, reply: String) -> std::thread::JoinHandle<()> {
        let listener = socket::socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .expect("socket");
        bind(
            listener.as_raw_fd(),
            &UnixAddr::new(socket).expect("address"),
        )
        .expect("bind");
        listen(&listener, Backlog::new(1).expect("backlog")).expect("listen");
        std::thread::spawn(move || {
            let conn = accept(listener.as_raw_fd()).expect("accept");
            let _request = sys::recv_with_fds(conn).expect("request");
            sys::send_with_fds(conn, reply.as_bytes(), &[]).expect("reply");
        })
    }

    #[test]
    fn a_loader_with_other_programs_is_refused_with_the_fix() {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("loader.sock");
        let reply = format!(
            "ok abi={} object={} cgroup=7 reused=0",
            abi::VERSION,
            "0".repeat(64)
        );
        let loader = fake_loader(&socket, reply);
        let boxes: OwnedFd = fs::File::open(dir.path()).expect("open").into();
        let error = request(&socket, boxes.as_fd())
            .err()
            .expect("a loader with other programs");
        loader.join().expect("loader thread");
        assert!(
            matches!(&error, Error::ObjectMismatch { daemon, .. } if daemon == engine::object_id()),
            "{error}"
        );
        assert!(error.to_string().contains("min finalize-install"));
    }

    #[test]
    fn a_loader_of_another_abi_is_refused_with_the_fix() {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("loader.sock");
        let loader = fake_loader(
            &socket,
            format!("err abi mismatch: loader=1 daemon={}", abi::VERSION),
        );
        let boxes: OwnedFd = fs::File::open(dir.path()).expect("open").into();
        let error = request(&socket, boxes.as_fd())
            .err()
            .expect("a loader of another ABI");
        loader.join().expect("loader thread");
        assert!(
            matches!(error, Error::AbiMismatch { loader: 1, .. }),
            "{error}"
        );
        assert!(error.to_string().contains("min finalize-install"));
    }
}
