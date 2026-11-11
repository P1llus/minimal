//! The helper roles of the test binary: the root loader, and the probe
//! that runs socket actions inside a box.

use std::{
    io::Read,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use boxbpf::loader::{ServeOptions, serve};
use nix::sys::socket::{self, AddressFamily, Backlog, SockFlag, SockType, UnixAddr};

use super::{LO_ADDRS, ROLE, SOCKET, probe};

/// Runs the role this process was started for, if any.
pub fn run() {
    match std::env::var(ROLE).as_deref() {
        Ok("loader") => loader(),
        Ok("probe") => probe::run(),
        _ => {}
    }
}

fn lo_addr(action: &str, addr: &str) {
    let status = Command::new("ip")
        .args([
            "-6",
            "addr",
            action,
            &format!("{addr}/128"),
            "dev",
            "lo",
            "nodad",
        ])
        .status();
    if !status.is_ok_and(|s| s.success()) {
        eprintln!("loader helper: ip -6 addr {action} {addr} failed");
    }
}

/// Removes a cgroup directory tree, deepest first. Whatever is still
/// populated stays.
fn remove_cgroups(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for child in entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()) {
            remove_cgroups(&child);
        }
    }
    let _busy = std::fs::remove_dir(dir);
}

/// The loader as root: serves requests until stdin closes, which happens
/// when the test that started it ends, however it ends.
fn loader() {
    let socket_path = std::env::var(SOCKET).expect("socket path");
    let lo_addrs: Vec<String> = std::env::var(LO_ADDRS)
        .unwrap_or_default()
        .split(',')
        .filter(|a| !a.is_empty())
        .map(str::to_owned)
        .collect();
    for addr in &lo_addrs {
        lo_addr("add", addr);
    }

    // Roots handed over to tests live below a base of this helper's own.
    let handover = PathBuf::from(format!("boxbpf-test-{}", std::process::id()));
    let handover_dir = Path::new("/sys/fs/cgroup").join(&handover);

    let cleanup_path = socket_path.clone();
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        // An error ends the wait just like end of input does.
        let _read = std::io::stdin().read_to_end(&mut sink);
        for addr in &lo_addrs {
            lo_addr("del", addr);
        }
        let _removed = std::fs::remove_file(&cleanup_path);
        // A handed-over root empties when the test process that was moved
        // into it has exited, which is a moment after it closed our stdin.
        for _ in 0..100 {
            remove_cgroups(&handover_dir);
            if !handover_dir.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::process::exit(0);
    });

    let listener = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("create the loader socket");
    socket::bind(
        listener.as_raw_fd(),
        &UnixAddr::new(socket_path.as_str()).expect("socket address"),
    )
    .expect("bind the loader socket");
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
        .expect("open the socket to all users");
    socket::listen(&listener, Backlog::new(16).expect("backlog")).expect("listen");

    let options = ServeOptions {
        handover_base: Some(handover),
        ..ServeOptions::default()
    };
    loop {
        let conn = socket::accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC).expect("accept");
        // SAFETY: accept4 returned a new descriptor that nothing else owns.
        let conn = unsafe { OwnedFd::from_raw_fd(conn) };
        match serve(conn.as_fd(), &options) {
            Ok(served) => eprintln!("loader helper: served {served:?}"),
            Err(e) => eprintln!("loader helper: {e}"),
        }
    }
}
