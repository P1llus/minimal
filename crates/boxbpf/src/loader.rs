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
//! Wire format, one line of text per message:
//! - request: `attach abi=<n>`, with one descriptor
//! - reply: `ok abi=<n> cgroup=<id> reused=<0|1>`, with one descriptor per
//!   map in a fixed order, or `err <reason>`

use std::{
    ffi::CStr,
    fs, io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use netpol::abi;
use nix::{
    fcntl::{OFlag, openat},
    sys::{
        socket::{self, AddressFamily, SockFlag, SockType, UnixAddr, sockopt::PeerCredentials},
        stat::Mode,
    },
};

use crate::{Engine, Error, Handles, MapSizes, engine, sys};

const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
/// systemd sets this on the cgroup of a unit it delegates. Only root can
/// set a `trusted.` attribute, so the owner of the cgroup cannot forge it.
const DELEGATE_XATTR: &CStr = c"trusted.delegate";

/// What the loader does for a request it accepts.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServeOptions {
    pub sizes: MapSizes,
}

/// A request the loader served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub uid: u32,
    /// Cgroup id of the attach point.
    pub cgroup: u64,
    /// The cgroup path below the cgroup mount, as the loader sees it.
    pub path: PathBuf,
    /// True when the programs were already attached there.
    pub reused: bool,
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

    // Walk up to the unit systemd delegated. Every cgroup on the way must
    // belong to the peer, or it could not have been delegated to it.
    let mut dir: OwnedFd = boxes
        .try_clone_to_owned()
        .map_err(io_step("duplicate the descriptor"))?;
    let mut delegated = false;
    for _ in path.components() {
        let meta = fs::File::from(
            dir.try_clone()
                .map_err(io_step("duplicate the descriptor"))?,
        )
        .metadata()
        .map_err(io_step("stat a cgroup"))?;
        if !meta.is_dir() || meta.uid() != uid {
            return policy(format!(
                "the cgroup is not owned by uid {uid} up to its delegated unit"
            ));
        }
        if sys::xattr(dir.as_fd(), DELEGATE_XATTR).as_deref() == Some(b"1") {
            delegated = true;
            break;
        }
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        dir =
            openat(&dir, "..", flags, Mode::empty()).map_err(nix_step("open the parent cgroup"))?;
    }
    if !delegated {
        return policy(format!(
            "no delegated unit of uid {uid} above the attach point"
        ));
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

fn serve_inner(
    conn: BorrowedFd<'_>,
    options: &ServeOptions,
) -> Result<(Served, Vec<OwnedFd>), Refusal> {
    let (request, mut fds) =
        sys::recv_with_fds(conn.as_raw_fd()).map_err(io_step("read the request"))?;
    let request = String::from_utf8_lossy(&request);
    if !request.starts_with("attach ") {
        return policy("unknown request");
    }
    // A daemon built against other layouts would misread every map.
    let theirs = field(&request, "abi").and_then(|v| v.parse::<u32>().ok());
    if theirs != Some(abi::VERSION) {
        return policy(format!(
            "abi mismatch: loader={} daemon={}",
            abi::VERSION,
            theirs.map_or_else(|| "?".to_owned(), |v| v.to_string())
        ));
    }
    let (Some(boxes), None) = (fds.pop(), fds.pop()) else {
        return policy("the request must carry exactly one descriptor");
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
    Ok((
        Served {
            uid: target.uid,
            cgroup,
            path: target.path,
            reused,
        },
        maps,
    ))
}

/// Serves one accepted connection of the loader socket. Needs root.
///
/// On refusal the peer is told why, and the same reason comes back as
/// [`Error::Refused`] for the loader's log.
pub fn serve(conn: BorrowedFd<'_>, options: &ServeOptions) -> Result<Served, Error> {
    match serve_inner(conn, options) {
        Ok((served, maps)) => {
            let reply = format!(
                "ok abi={} cgroup={} reused={}",
                abi::VERSION,
                served.cgroup,
                u8::from(served.reused)
            );
            let raw: Vec<_> = maps.iter().map(AsRawFd::as_raw_fd).collect();
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

/// Asks the loader at `socket` for an engine at `boxes` and returns its
/// handles. The caller must run in the `supervisor` cgroup next to `boxes`.
pub fn request(socket: &Path, boxes: BorrowedFd<'_>) -> Result<Handles, Error> {
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
    sys::send_with_fds(
        conn.as_raw_fd(),
        format!("attach abi={}", abi::VERSION).as_bytes(),
        &[boxes.as_raw_fd()],
    )
    .map_err(Error::sys("send the request to the policy loader"))?;
    let (reply, fds) = sys::recv_with_fds(conn.as_raw_fd())
        .map_err(Error::sys("read the policy loader's reply"))?;
    let reply = String::from_utf8_lossy(&reply).into_owned();

    if let Some(reason) = reply.strip_prefix("err ") {
        // Name the fix when the two sides were built from different layouts.
        if reason.starts_with("abi mismatch") {
            let loader = field(reason, "loader").and_then(|v| v.parse().ok());
            if let Some(loader) = loader {
                return Err(Error::AbiMismatch {
                    loader,
                    daemon: abi::VERSION,
                });
            }
        }
        return Err(Error::Refused(reason.to_owned()));
    }
    if !reply.starts_with("ok ") {
        return Err(Error::Protocol(reply));
    }
    match field(&reply, "abi").and_then(|v| v.parse::<u32>().ok()) {
        Some(v) if v == abi::VERSION => Handles::from_fds(fds),
        Some(loader) => Err(Error::AbiMismatch {
            loader,
            daemon: abi::VERSION,
        }),
        None => Err(Error::Protocol(reply)),
    }
}
