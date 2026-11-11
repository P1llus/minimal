//! How an unprivileged daemon gets its engine from a root loader.
//!
//! The daemon connects to the loader's `SOCK_SEQPACKET` socket and sends one
//! message with the descriptor of its `boxes/` cgroup. The loader checks
//! who is asking and that both sides were built with the same programs,
//! loads and attaches them there, and answers with one message that
//! carries the map descriptors. The daemon confirms that it can use them.
//! Without that confirmation the loader takes the programs off again: no
//! cgroup is left with programs whose maps nobody holds.
//!
//! The loader keeps no state, and it attaches only to a `boxes/` that has
//! no programs yet. A daemon makes that cgroup anew every time it starts.
//!
//! On a host without a systemd user manager nobody delegates a cgroup to the
//! daemon. There the daemon first asks for a root: the loader creates a
//! cgroup for it, moves the daemon into its `supervisor/`, hands the
//! directory over and delegates it. The attach request that follows is
//! checked exactly like any other.
//!
//! Wire format, one line of text per message:
//! - request: `attach abi=<n> object=<id>`, with one descriptor. `object`
//!   names the programs the daemon was built with.
//! - reply: `ok abi=<n> cgroup=<id>`, with one descriptor per map in a
//!   fixed order
//! - confirmation: `done`, answered with `attached`
//! - request: `root abi=<n>`
//! - reply: `ok abi=<n> root=<path>`, with the descriptor of the new root
//! - any refusal: `err <reason>`

use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
};

use netpol::abi;
use nix::sys::{
    socket::{
        self, AddressFamily, SockFlag, SockType, UnixAddr,
        sockopt::{PeerCredentials, ReceiveTimeout},
    },
    time::TimeVal,
};

use crate::{Engine, Error, Handles, MapSizes, engine, sys};

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const REQUEST_TIMEOUT_SECS: i64 = 5;
const REPLY_TIMEOUT_SECS: i64 = 30;
/// More levels than any cgroup hierarchy has. Bounds the walks upwards.
const MAX_DEPTH: usize = 64;

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

/// A cgroup's path below the cgroup mount, for messages. No decision reads
/// it: cgroups are told apart by id.
fn shown(dir: BorrowedFd<'_>) -> String {
    sys::fd_path(dir).map_or_else(
        |_e| "(unknown cgroup)".to_owned(),
        |path| {
            path.strip_prefix(CGROUP_MOUNT).map_or_else(
                |_e| path.display().to_string(),
                |rel| format!("/{}", rel.display()),
            )
        },
    )
}

fn id_of(dir: BorrowedFd<'_>) -> Result<u64, Refusal> {
    sys::cgroup_id(dir).map_err(io_step("read a cgroup id"))
}

fn owner_of(dir: BorrowedFd<'_>) -> Result<u32, Refusal> {
    sys::stat(dir)
        .map(|(uid, _, _)| uid)
        .map_err(io_step("stat a cgroup"))
}

/// The cgroup above `dir`, or `None` when `dir` is the top of the cgroup
/// mount.
fn parent_of(dir: BorrowedFd<'_>) -> Result<Option<OwnedFd>, Refusal> {
    let up = sys::open_dir_at(dir, "..").map_err(io_step("open the parent cgroup"))?;
    let same = sys::stat(dir).map_err(io_step("stat a cgroup"))?
        == sys::stat(up.as_fd()).map_err(io_step("stat a cgroup"))?;
    let inside = sys::is_cgroup2(up.as_fd()).map_err(io_step("stat a cgroup"))?;
    Ok((inside && !same).then_some(up))
}

/// The peer of the connection: its credentials at connect, and a pidfd
/// that names that process and no later one with the same pid.
struct Peer {
    uid: u32,
    gid: u32,
    pid: i32,
    pidfd: OwnedFd,
}

impl Peer {
    fn of(conn: BorrowedFd<'_>) -> Result<Self, Refusal> {
        let cred = socket::getsockopt(&conn, PeerCredentials)
            .map_err(nix_step("read the peer's credentials"))?;
        let pidfd = sys::peer_pidfd(conn).map_err(io_step("get a pidfd of the peer"))?;
        Ok(Self {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
            pidfd,
        })
    }

    /// The cgroup the peer runs in, open.
    ///
    /// With a pidfd the kernel reports the cgroup of exactly that process.
    /// Before 6.13 the pidfd has no cgroup query: there the loader reads
    /// `/proc/<pid>/cgroup`, opens what it names, and then checks that the
    /// pidfd still names a live process, which rules out that the pid went
    /// to another process during the read.
    fn cgroup(&self) -> Result<OwnedFd, Refusal> {
        let mount =
            sys::open_dir(Path::new(CGROUP_MOUNT)).map_err(io_step("open the cgroup mount"))?;
        if let Ok(id) = sys::pidfd_cgroup_id(self.pidfd.as_fd()) {
            return sys::open_cgroup_by_id(mount.as_fd(), id)
                .map_err(io_step("open the peer's cgroup"));
        }
        let text = std::fs::read_to_string(format!("/proc/{}/cgroup", self.pid))
            .map_err(io_step("read the peer's cgroup"))?;
        let Some(path) = text.lines().find_map(|l| l.strip_prefix("0::")) else {
            return policy("the peer has no cgroup v2 membership");
        };
        let rel = path.trim_start_matches('/');
        let dir = sys::open_dir_at(mount.as_fd(), if rel.is_empty() { "." } else { rel })
            .map_err(io_step("open the peer's cgroup"))?;
        if !sys::pidfd_alive(self.pidfd.as_fd()) {
            return policy("the peer exited during the check");
        }
        Ok(dir)
    }
}

struct Target {
    uid: u32,
    path: PathBuf,
}

/// Decides whether the peer may have an engine at `boxes`.
///
/// Everything is read from the descriptor the peer sent and from the
/// kernel's answers about the peer. Cgroups are compared by id, so a path
/// that only looks right does not pass, and no path the peer has a say in
/// is resolved.
fn authorize(peer: &Peer, boxes: BorrowedFd<'_>) -> Result<Target, Refusal> {
    let uid = peer.uid;
    if !sys::is_cgroup2(boxes).map_err(io_step("stat the descriptor"))? {
        return policy("the descriptor is not a cgroup2 directory");
    }
    // Root itself needs no loader.
    if uid == 0 {
        return policy("root loads the programs itself");
    }
    let Some(root) = parent_of(boxes)? else {
        return policy("the attach point has no parent cgroup");
    };
    // The attach point is the child of its parent that is called `boxes`.
    let named = sys::open_dir_at(root.as_fd(), "boxes").ok();
    let is_boxes = match &named {
        Some(named) => id_of(named.as_fd())? == id_of(boxes)?,
        None => false,
    };
    if !is_boxes {
        return policy("the attach point must be a cgroup named boxes");
    }

    // A cgroup belongs to a user only when root gave it away, or when the
    // user made it inside what root gave away. So `boxes` and the root
    // above it must be the peer's.
    for dir in [boxes, root.as_fd()] {
        if owner_of(dir)? != uid {
            return policy(format!(
                "the attach point and the cgroup above it must belong to uid {uid}: \
                 the daemon needs a delegated cgroup"
            ));
        }
    }

    // Only the daemon's own cgroup may ask. A process in boxes/ is a box
    // process: it has the daemon's uid and must not get the policy maps.
    let Ok(supervisor) = sys::open_dir_at(root.as_fd(), "supervisor") else {
        return policy("there is no supervisor cgroup beside the attach point");
    };
    let running_in = peer.cgroup()?;
    if id_of(running_in.as_fd())? != id_of(supervisor.as_fd())? {
        return policy(format!(
            "the peer runs in {}, not in {}",
            shown(running_in.as_fd()),
            shown(supervisor.as_fd())
        ));
    }

    // A root made inside the root of a running engine is not a second
    // daemon: it is something below a daemon, in its helpers cgroup for
    // one, making itself a place to ask from.
    let mut above = parent_of(root.as_fd())?;
    for _ in 0..MAX_DEPTH {
        let Some(dir) = above else { break };
        if let Ok(other) = sys::open_dir_at(dir.as_fd(), "boxes")
            && engine::has_programs(other.as_fd()).map_err(|e| Refusal::Policy(e.to_string()))?
        {
            return policy(format!(
                "the attach point lies inside {}, the cgroup root of an engine that is running",
                shown(dir.as_fd())
            ));
        }
        above = parent_of(dir.as_fd())?;
    }

    let path = PathBuf::from(shown(boxes).trim_start_matches('/'));
    Ok(Target { uid, path })
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// An engine that is attached and not yet confirmed by its daemon.
struct Pending {
    engine: Engine,
    boxes: OwnedFd,
}

/// What `serve` sends back, and for an engine what it then waits for.
struct Reply {
    line: String,
    fds: Vec<OwnedFd>,
    pending: Option<Pending>,
}

fn attach(
    conn: BorrowedFd<'_>,
    request: &str,
    mut fds: Vec<OwnedFd>,
    options: &ServeOptions,
) -> Result<(Served, Reply), Refusal> {
    // Before anything is loaded: a daemon built with other programs would
    // write maps for programs it does not know, and could not use what the
    // loader attached.
    let theirs = field(request, "object").unwrap_or("?");
    if theirs != engine::object_id() {
        return policy(format!(
            "object mismatch: loader={} daemon={theirs}",
            engine::object_id()
        ));
    }
    let (Some(boxes), None) = (fds.pop(), fds.pop()) else {
        return policy("an attach request must carry exactly one descriptor");
    };
    let peer = Peer::of(conn)?;
    let target = authorize(&peer, boxes.as_fd())?;
    let cgroup = id_of(boxes.as_fd())?;

    let engine_error = |e: Error| Refusal::Policy(e.to_string());
    if engine::has_programs(boxes.as_fd()).map_err(engine_error)? {
        return policy(Error::InUse.to_string());
    }
    let mut engine = Engine::load(boxes.as_fd(), &options.sizes).map_err(engine_error)?;
    engine.attach(boxes.as_fd()).map_err(engine_error)?;
    let maps = match engine.map_fds() {
        Ok(maps) => maps,
        Err(error) => {
            engine.detach(boxes.as_fd());
            return Err(engine_error(error));
        }
    };
    Ok((
        Served::Engine {
            uid: target.uid,
            cgroup,
            path: target.path,
        },
        Reply {
            line: format!("ok abi={} cgroup={cgroup}", abi::VERSION),
            fds: maps,
            pending: Some(Pending { engine, boxes }),
        },
    ))
}

/// Removes roots of earlier daemons that have ended. A cgroup that still
/// has processes or children refuses the removal, which is the check.
fn sweep_roots(base: BorrowedFd<'_>) {
    let Ok(listing) = sys::fd_path(base).and_then(std::fs::read_dir) else {
        return;
    };
    for name in listing.flatten().map(|e| e.file_name()) {
        let Some(name) = name.to_str() else { continue };
        let Ok(root) = sys::open_dir_at(base, name) else {
            continue;
        };
        if let Ok(boxes) = sys::open_dir_at(root.as_fd(), "boxes") {
            let stale = sys::fd_path(boxes.as_fd()).and_then(std::fs::read_dir);
            for left in stale.into_iter().flatten().flatten() {
                if let Some(left) = left.file_name().to_str() {
                    let _busy = sys::remove_dir_at(boxes.as_fd(), left);
                }
            }
        }
        for child in ["boxes", "helpers", "supervisor"] {
            let _busy = sys::remove_dir_at(root.as_fd(), child);
        }
        let _busy = sys::remove_dir_at(base, name);
    }
}

/// What a delegation hands to the owner, per the kernel's cgroup rules: the
/// directory and the files that move processes and enable controllers.
fn delegate(dir: BorrowedFd<'_>, uid: u32, gid: u32) -> Result<(), Refusal> {
    for file in [
        "",
        "cgroup.procs",
        "cgroup.threads",
        "cgroup.subtree_control",
    ] {
        sys::chown_at(dir, file, uid, gid).map_err(io_step("chown the new root"))?;
    }
    Ok(())
}

/// A root is for a daemon nobody delegated a cgroup to. A peer below a
/// cgroup that belongs to a user already has one: it is a daemon in a
/// delegated unit, which asks systemd, or it is a process of a box, which
/// must stay where it is. Every cgroup outside a delegation belongs to root.
fn refuse_delegated_peer(peer: &Peer) -> Result<(), Refusal> {
    let mut dir = Some(peer.cgroup()?);
    for _ in 0..MAX_DEPTH {
        let Some(at) = dir else { break };
        if owner_of(at.as_fd())? != 0 {
            return policy(format!(
                "the peer runs below {}, a cgroup that is delegated already",
                shown(at.as_fd())
            ));
        }
        dir = parent_of(at.as_fd())?;
    }
    Ok(())
}

/// Moves the peer into `supervisor` and checks that it arrived.
///
/// A cgroup takes a process by pid, and the peer's pid could have gone to
/// another process since it connected. The pidfd still names the peer, so
/// afterwards the loader asks it: alive, and in the new cgroup. If not,
/// whatever the write moved is put back out, into the top cgroup.
fn move_peer(
    peer: &Peer,
    mount: BorrowedFd<'_>,
    supervisor: BorrowedFd<'_>,
) -> Result<(), Refusal> {
    let moved = sys::write_at(supervisor, "cgroup.procs", &peer.pid.to_string());
    let arrived = moved.is_ok()
        && sys::pidfd_alive(peer.pidfd.as_fd())
        && peer
            .cgroup()
            .and_then(|at| Ok(id_of(at.as_fd())? == id_of(supervisor)?))
            .unwrap_or(false);
    if arrived {
        return Ok(());
    }
    let strangers = sys::read_at(supervisor, "cgroup.procs").unwrap_or_default();
    for pid in strangers.lines() {
        let _gone = sys::write_at(mount, "cgroup.procs", pid);
    }
    match moved {
        Err(source) => Err(Refusal::Io {
            what: "move the peer",
            source,
        }),
        Ok(()) => policy("the peer exited during the handover"),
    }
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
    let peer = Peer::of(conn)?;
    refuse_delegated_peer(&peer)?;

    let mount = sys::open_dir(Path::new(CGROUP_MOUNT)).map_err(io_step("open the cgroup mount"))?;
    let base_path = Path::new(CGROUP_MOUNT).join(base);
    std::fs::create_dir_all(&base_path).map_err(io_step("create the base cgroup"))?;
    let base_dir = sys::open_dir(&base_path).map_err(io_step("open the base cgroup"))?;
    sweep_roots(base_dir.as_fd());
    // Controllers reach the new root only if every level above passes them
    // on. Where one cannot, the root simply has fewer: limits are optional.
    for level in [mount.as_fd(), base_dir.as_fd()] {
        let _partial = sys::write_at(level, "cgroup.subtree_control", "+cpu +memory +pids");
    }

    let name = format!("u{}-{}", peer.uid, peer.pid);
    sys::make_dir_at(base_dir.as_fd(), &name).map_err(io_step("create the new root"))?;
    let made = (|| {
        let root =
            sys::open_dir_at(base_dir.as_fd(), &name).map_err(io_step("open the new root"))?;
        sys::make_dir_at(root.as_fd(), "supervisor").map_err(io_step("create supervisor/"))?;
        let supervisor =
            sys::open_dir_at(root.as_fd(), "supervisor").map_err(io_step("open supervisor/"))?;
        // The daemon cannot move itself: that takes write access to a
        // cgroup above both its old place and the new one. The root stays
        // root's until the peer is seen in it, so a process moved in its
        // place is never in a cgroup the user controls.
        move_peer(&peer, mount.as_fd(), supervisor.as_fd())?;
        delegate(root.as_fd(), peer.uid, peer.gid)?;
        delegate(supervisor.as_fd(), peer.uid, peer.gid)?;
        Ok(root)
    })();
    let root = match made {
        Ok(root) => root,
        Err(refusal) => {
            if let Ok(root) = sys::open_dir_at(base_dir.as_fd(), &name) {
                let _busy = sys::remove_dir_at(root.as_fd(), "supervisor");
            }
            let _busy = sys::remove_dir_at(base_dir.as_fd(), &name);
            return Err(refusal);
        }
    };
    let path = base_path.join(&name);
    Ok((
        Served::Root {
            uid: peer.uid,
            path: base.join(&name),
        },
        Reply {
            line: format!("ok abi={} root={}", abi::VERSION, path.display()),
            fds: vec![root],
            pending: None,
        },
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
        Some("attach") => attach(conn, &request, fds, options),
        Some("root") if fds.is_empty() => hand_over_root(conn, options),
        _ => policy("unknown request"),
    }
}

/// Sends the reply. For an engine, waits for the daemon to say it holds
/// the maps and answers that the engine is its. On any failure the
/// programs come off again.
fn deliver(conn: BorrowedFd<'_>, reply: Reply) -> Result<(), Error> {
    let raw: Vec<_> = reply.fds.iter().map(AsRawFd::as_raw_fd).collect();
    let sent = sys::send_with_fds(conn.as_raw_fd(), reply.line.as_bytes(), &raw)
        .map_err(Error::sys("send the reply"));
    let Some(mut pending) = reply.pending else {
        return sent;
    };
    let confirmed = sent.and_then(|()| {
        let (line, _) = sys::recv_with_fds(conn.as_raw_fd())
            .map_err(Error::sys("read the daemon's confirmation"))?;
        if line != b"done" {
            return Err(Error::Unconfirmed(
                "the daemon did not confirm that it holds the maps".to_owned(),
            ));
        }
        sys::send_with_fds(conn.as_raw_fd(), b"attached", &[])
            .map_err(Error::sys("tell the daemon the engine is attached"))
    });
    if confirmed.is_err() {
        pending.engine.detach(pending.boxes.as_fd());
    }
    confirmed
}

/// Serves one accepted connection of the loader socket. Needs root.
///
/// On refusal the peer is told why, and the same reason comes back as
/// [`Error::Refused`] for the loader's log.
pub fn serve(conn: BorrowedFd<'_>, options: &ServeOptions) -> Result<Served, Error> {
    match serve_inner(conn, options) {
        Ok((served, reply)) => deliver(conn, reply).map(|()| served),
        Err(refusal) => {
            let reason = refusal.to_string();
            // The peer may be gone already. The refusal itself is what matters.
            let _unsent =
                sys::send_with_fds(conn.as_raw_fd(), format!("err {reason}").as_bytes(), &[]);
            Err(Error::Refused(reason))
        }
    }
}

/// One request and its reply, checked for refusal and ABI. The connection
/// comes back for a caller that has more to say.
fn exchange(
    socket: &Path,
    request: &str,
    fds: &[std::os::fd::RawFd],
) -> Result<(OwnedFd, String, Vec<OwnedFd>), Error> {
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
    // Loading and verifying the programs takes well under a second.
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
        // Name the fix when the two sides were built from different
        // layouts or programs.
        if reason.starts_with("abi mismatch")
            && let Some(loader) = field(reason, "loader").and_then(|v| v.parse().ok())
        {
            return Err(Error::AbiMismatch {
                loader,
                daemon: abi::VERSION,
            });
        }
        if reason.starts_with("object mismatch") {
            return Err(Error::ObjectMismatch {
                loader: field(reason, "loader").unwrap_or("unknown").to_owned(),
                daemon: engine::object_id().to_owned(),
            });
        }
        return Err(Error::Refused(reason.to_owned()));
    }
    if !reply.starts_with("ok ") {
        return Err(Error::Protocol(reply));
    }
    match field(&reply, "abi").and_then(|v| v.parse::<u32>().ok()) {
        Some(v) if v == abi::VERSION => Ok((conn, reply, fds)),
        Some(loader) => Err(Error::AbiMismatch {
            loader,
            daemon: abi::VERSION,
        }),
        None => Err(Error::Protocol(reply)),
    }
}

/// Asks the loader at `socket` for an engine at `boxes` and returns its
/// handles. The caller must run in the `supervisor` cgroup next to `boxes`,
/// and `boxes` must have no programs attached: a cgroup made for this
/// start of the daemon.
///
/// The request names the programs this build carries. A loader that
/// carries others refuses before it loads anything. On any error no
/// programs are attached at `boxes`: when this side cannot use the maps it
/// was sent, it does not confirm, and the loader takes the programs off.
pub fn request(socket: &Path, boxes: BorrowedFd<'_>) -> Result<Handles, Error> {
    let line = format!("attach object={}", engine::object_id());
    let (conn, _reply, fds) = exchange(socket, &line, &[boxes.as_raw_fd()])?;
    let handles = Handles::from_fds(fds)?;
    sys::send_with_fds(conn.as_raw_fd(), b"done", &[])
        .map_err(Error::sys("confirm the engine to the policy loader"))?;
    let (answer, _) = sys::recv_with_fds(conn.as_raw_fd())
        .map_err(Error::sys("read the policy loader's last word"))?;
    if answer != b"attached" {
        return Err(Error::Unconfirmed(
            String::from_utf8_lossy(&answer).into_owned(),
        ));
    }
    Ok(handles)
}

/// Asks the loader for a cgroup root, for a daemon that has none because
/// the host has no systemd user manager. On return the calling process runs
/// in `supervisor/` of the root whose directory is returned. The caller
/// creates `boxes/` in it and calls [`request`].
///
/// Call this before starting any thread: the loader moves the process.
pub fn request_root(socket: &Path) -> Result<OwnedFd, Error> {
    let (_conn, reply, mut fds) = exchange(socket, "root", &[])?;
    match (fds.pop(), fds.pop()) {
        (Some(root), None) => Ok(root),
        _ => Err(Error::Protocol(reply)),
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::socket::{Backlog, accept, bind, listen};

    use super::*;

    /// A loader that reads one request, hands it to the test, and answers
    /// with `reply` and no descriptors.
    fn fake_loader(socket: &Path, reply: String) -> std::thread::JoinHandle<String> {
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
            let (request, _) = sys::recv_with_fds(conn).expect("request");
            sys::send_with_fds(conn, reply.as_bytes(), &[]).expect("reply");
            String::from_utf8_lossy(&request).into_owned()
        })
    }

    fn ask(reply: String) -> (Error, String) {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("loader.sock");
        let loader = fake_loader(&socket, reply);
        let boxes: OwnedFd = std::fs::File::open(dir.path()).expect("open").into();
        let error = request(&socket, boxes.as_fd())
            .err()
            .expect("the loader said no");
        (error, loader.join().expect("loader thread"))
    }

    #[test]
    fn the_request_names_the_layouts_and_the_programs_of_this_build() {
        let (_, request) = ask("err no".to_owned());
        assert_eq!(
            request,
            format!("attach object={} abi={}", engine::object_id(), abi::VERSION)
        );
    }

    #[test]
    fn a_loader_with_other_programs_is_refused_with_the_fix() {
        let other = "0".repeat(64);
        let (error, _) = ask(format!(
            "err object mismatch: loader={other} daemon={}",
            engine::object_id()
        ));
        assert!(
            matches!(&error, Error::ObjectMismatch { loader, daemon }
                if *loader == other && daemon == engine::object_id()),
            "{error}"
        );
        assert!(error.to_string().contains("min finalize-install"));
    }

    #[test]
    fn a_loader_of_another_abi_is_refused_with_the_fix() {
        let (error, _) = ask(format!(
            "err abi mismatch: loader=1 daemon={}",
            abi::VERSION
        ));
        assert!(
            matches!(error, Error::AbiMismatch { loader: 1, .. }),
            "{error}"
        );
        assert!(error.to_string().contains("min finalize-install"));
    }

    #[test]
    fn maps_this_side_cannot_use_are_not_confirmed() {
        // An `ok` with no descriptors: the handles cannot be made, and the
        // loader is never told `done`.
        let (error, _) = ask(format!("ok abi={} cgroup=7", abi::VERSION));
        assert!(matches!(error, Error::HandleCount(0, _)), "{error}");
    }
}
