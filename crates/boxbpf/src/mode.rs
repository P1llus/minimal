//! The root loader as a mode of the daemon's binary.
//!
//! An unprivileged daemon cannot load the engine's programs. It asks this
//! loader, which systemd starts as root for each connection on the loader
//! socket. The loader checks who asks, loads the programs at the daemon's
//! `boxes` cgroup, hands the maps back, and exits. It keeps no state.
//!
//! Everything that runs as root for a daemon is in this crate, so one hash
//! over the crate ([`crate::loader_id`]) says whether an installed copy
//! still runs the code this build has.

use std::{
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
    path::{Path, PathBuf},
};

use nix::sys::socket::{self, AddressFamily, Backlog, SockFlag, SockType, UnixAddr};

use crate::loader::{ServeOptions, Served, serve};

/// The first argument that selects this mode.
pub const MODE: &str = "__policy-loader";

/// Where roots for daemons without a delegated cgroup are made, below the
/// cgroup mount.
const HANDOVER_BASE: &str = "minimal";

/// What this build is as a loader, on one line: the layouts it speaks, the
/// programs it loads, and its own code. A daemon works with a loader of
/// the same `abi` and `object`. An installed copy with another `loader`
/// still works and is out of date.
#[must_use]
pub fn identity() -> String {
    format!(
        "abi={} object={} loader={}",
        netpol::abi::VERSION,
        crate::object_id(),
        crate::loader_id()
    )
}

#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// Serve the one connection on standard input.
    Connection,
    /// Bind a socket and serve connections until killed.
    Listen {
        path: PathBuf,
        owner: Option<u32>,
    },
    Identity,
}

impl Invocation {
    fn parse(args: &[String]) -> Result<Self, String> {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        match args.as_slice() {
            [] => Ok(Self::Connection),
            ["--identity"] => Ok(Self::Identity),
            ["--listen", path] => Ok(Self::Listen {
                path: PathBuf::from(path),
                owner: None,
            }),
            ["--listen", path, "--owner", uid] => Ok(Self::Listen {
                path: PathBuf::from(path),
                owner: Some(
                    uid.parse()
                        .map_err(|_| format!("`{uid}` is not a user id"))?,
                ),
            }),
            _ => Err(format!(
                "usage: minimald {MODE} [--identity | --listen <socket> [--owner <uid>]]"
            )),
        }
    }
}

/// Runs the loader and exits, when this process was started as one.
/// Returns for every other invocation.
pub fn run_internal_mode() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some(MODE) {
        return;
    }
    let rest: Vec<String> = args.collect();
    let code = match Invocation::parse(&rest) {
        Ok(Invocation::Identity) => {
            println!("{}", identity());
            0
        }
        Ok(Invocation::Connection) => {
            // SAFETY: systemd passed the accepted connection as standard
            // input, and nothing else in this process uses descriptor 0.
            let conn = unsafe { BorrowedFd::borrow_raw(0) };
            i32::from(!serve_one(conn))
        }
        Ok(Invocation::Listen { path, owner }) => match listen(&path, owner) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("minimald policy loader: {}: {error}", path.display());
                1
            }
        },
        Err(usage) => {
            eprintln!("{usage}");
            2
        }
    };
    std::process::exit(code);
}

fn options() -> ServeOptions {
    ServeOptions {
        handover_base: Some(PathBuf::from(HANDOVER_BASE)),
        ..ServeOptions::default()
    }
}

/// Serves one connection and says what happened on standard error, which
/// is the journal under systemd. True when the request was served.
fn serve_one(conn: BorrowedFd<'_>) -> bool {
    match serve(conn, &options()) {
        Ok(Served::Engine { uid, path, .. }) => {
            eprintln!(
                "minimald policy loader: loaded the policy engine at /{} for uid {uid}",
                path.display()
            );
            true
        }
        Ok(Served::Root { uid, path }) => {
            eprintln!(
                "minimald policy loader: made the cgroup root /{} for uid {uid}",
                path.display()
            );
            true
        }
        Err(error) => {
            eprintln!("minimald policy loader: {error}");
            false
        }
    }
}

fn listen(path: &Path, owner: Option<u32>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let listener = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    socket::bind(listener.as_raw_fd(), &UnixAddr::new(path)?)?;
    if let Some(uid) = owner {
        std::os::unix::fs::chown(path, Some(uid), None)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    socket::listen(&listener, Backlog::new(4)?)?;
    loop {
        let conn = socket::accept(listener.as_raw_fd())?;
        // SAFETY: accept returned a new descriptor that nothing else owns.
        let conn = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(conn) };
        serve_one(conn.as_fd());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Invocation, String> {
        Invocation::parse(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn the_arguments_select_one_of_three_jobs() {
        assert_eq!(parse(&[]), Ok(Invocation::Connection));
        assert_eq!(parse(&["--identity"]), Ok(Invocation::Identity));
        assert_eq!(
            parse(&["--listen", "/run/x.sock", "--owner", "1000"]),
            Ok(Invocation::Listen {
                path: "/run/x.sock".into(),
                owner: Some(1000)
            })
        );
        assert!(parse(&["--listen"]).is_err());
        assert!(parse(&["--listen", "/run/x.sock", "--owner", "me"]).is_err());
        assert!(parse(&["serve"]).is_err());
    }

    #[test]
    fn the_identity_line_names_the_layouts_and_the_programs() {
        let line = identity();
        let fields: Vec<&str> = line.split(' ').collect();
        let [abi, object, loader] = fields.as_slice() else {
            panic!("three fields: {line}");
        };
        assert_eq!(*abi, format!("abi={}", netpol::abi::VERSION));
        for (field, key) in [(object, "object="), (loader, "loader=")] {
            let hash = field.strip_prefix(key).expect(key);
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        // The two name different things and are not the same hash.
        assert_ne!(
            object.strip_prefix("object="),
            loader.strip_prefix("loader=")
        );
    }
}
