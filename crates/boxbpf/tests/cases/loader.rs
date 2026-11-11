//! The loader's checks on who asks, the handles it gives out, and the
//! asynchronous event reader on top of them.

use std::{
    fs,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    time::Duration,
};

use boxbpf::{Error, events::Reader, loader};
use netpol::{abi::Hook, policy::BoxPolicy};
use nix::sys::socket::{
    self, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr,
};

use crate::support::{Cgroups, Harness, host_ip};

fn open(path: &std::path::Path) -> OwnedFd {
    fs::File::open(path).expect("open a directory").into()
}

fn refusal(result: Result<boxbpf::Handles, Error>) -> String {
    let error = result.err().expect("the loader should have refused");
    assert!(
        matches!(error, Error::Refused(_)),
        "expected a refusal, got {error}"
    );
    error.to_string()
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn the_loader_serves_only_the_supervisor_of_a_delegated_boxes_cgroup() {
    let Some(mut h) = Harness::start(
        "cases::loader::the_loader_serves_only_the_supervisor_of_a_delegated_boxes_cgroup",
    ) else {
        return;
    };
    let boxes_dir = h.root.join("boxes");

    // A box process has the daemon's uid. It must not get the maps.
    h.install("intruder", host_ip(), BoxPolicy::default());
    let out = h.probe(
        "intruder",
        &[
            "loader-request",
            &h.socket.to_string_lossy(),
            &boxes_dir.to_string_lossy(),
        ],
    );
    assert!(
        out.starts_with("err ") && out.contains("boxes/intruder, not in"),
        "{out}"
    );

    // The descriptor must be a cgroup named boxes that systemd delegated
    // to the caller.
    let reason = refusal(loader::request(
        &h.socket,
        open(&h.root.join("supervisor")).as_fd(),
    ));
    assert!(reason.contains("named boxes"), "{reason}");
    let reason = refusal(loader::request(
        &h.socket,
        open(std::path::Path::new("/tmp")).as_fd(),
    ));
    assert!(reason.contains("not a cgroup2 directory"), "{reason}");
    let nested = h.root.join("supervisor").join("boxes");
    fs::create_dir(&nested).expect("create a nested cgroup");
    let reason = refusal(loader::request(&h.socket, open(&nested).as_fd()));
    assert!(
        reason.contains("not in"),
        "a boxes cgroup whose supervisor we are not in: {reason}"
    );
    fs::remove_dir(&nested).expect("remove the nested cgroup");

    // A daemon built against other layouts is told so.
    let conn = socket::socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("socket");
    socket::connect(
        conn.as_raw_fd(),
        &UnixAddr::new(&h.socket).expect("address"),
    )
    .expect("connect");
    let rights = [h.boxes.as_raw_fd()];
    let iov = [std::io::IoSlice::new(b"attach abi=4000000000")];
    socket::sendmsg::<()>(
        conn.as_raw_fd(),
        &iov,
        &[ControlMessage::ScmRights(&rights)],
        MsgFlags::empty(),
        None,
    )
    .expect("send");
    let mut buf = [0u8; 256];
    let n = socket::recv(conn.as_raw_fd(), &mut buf, MsgFlags::empty()).expect("reply");
    let reply = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(
        reply,
        format!(
            "err abi mismatch: loader={} daemon=4000000000",
            netpol::abi::VERSION
        )
    );

    // Asking again attaches nothing new: the same maps come back.
    let again = loader::request(&h.socket, h.boxes.as_fd()).expect("a second request");
    let id = h.new_box("shared");
    let live = h.handles.install(
        id,
        netpol::Spec {
            deployment: host_ip(),
            policy: BoxPolicy::default(),
            options: netpol::compile::Options::default(),
        },
    );
    let live = live.expect("install through the first handles");
    assert!(
        again
            .stats(live.id())
            .expect("read through the second handles")
            .is_some()
    );
    let attached = std::process::Command::new("sudo")
        .args([
            "-n",
            "/usr/lib/linux-tools/6.8.0-149-generic/bpftool",
            "cgroup",
            "show",
        ])
        .arg(&boxes_dir)
        .output();
    if let Ok(out) = attached
        && out.status.success()
    {
        let listing = String::from_utf8_lossy(&out.stdout);
        assert_eq!(listing.matches("bp_").count(), 13, "{listing}");
        assert_eq!(listing.matches(" multi ").count(), 13, "{listing}");
    }
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn the_async_reader_yields_refusals() {
    let Some(mut h) = Harness::start("cases::loader::the_async_reader_yields_refusals") else {
        return;
    };
    let source = h.handles.take_events().expect("event source");
    assert!(
        h.handles.take_events().is_none(),
        "there is one reader per engine"
    );
    let bare = h.new_box("bare");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let mut reader = Reader::new(source).expect("register the ring buffer");
        // Nothing has happened yet: the reader waits.
        let early = tokio::time::timeout(Duration::from_millis(100), reader.next()).await;
        assert!(early.is_err(), "an event before anything was refused");

        for _ in 0..3 {
            let out = h.probe(
                "bare",
                &[
                    "sock",
                    &libc::AF_INET.to_string(),
                    &libc::SOCK_STREAM.to_string(),
                    "0",
                ],
            );
            assert_eq!(out, "err 1");
        }
        for _ in 0..3 {
            let event = tokio::time::timeout(Duration::from_secs(5), reader.next())
                .await
                .expect("an event within five seconds")
                .expect("read an event");
            assert_eq!((event.box_id, event.hook), (bare.0, Hook::SockCreate));
            // Stamped with the boot-time clock, a moment ago.
            let age = boxbpf::boot_time_ns().saturating_sub(event.time_ns);
            assert!(age < 10_000_000_000, "event is {age} ns old");
        }
        assert_eq!(reader.skipped(), 0);
    });
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_daemon_without_a_delegated_cgroup_gets_a_root_from_the_loader() {
    let Some(h) = Harness::start(
        "cases::loader::a_daemon_without_a_delegated_cgroup_gets_a_root_from_the_loader",
    ) else {
        return;
    };
    let own_cgroup = || {
        fs::read_to_string("/proc/self/cgroup")
            .expect("own cgroup")
            .trim()
            .to_owned()
    };
    let before = own_cgroup();

    // The loader creates the root, marks it delegated and moves us into
    // its supervisor/. systemd is not involved.
    let root = loader::request_root(&h.socket).expect("a root from the loader");
    let root_path =
        fs::read_link(format!("/proc/self/fd/{}", root.as_raw_fd())).expect("path of the root");
    let rel = root_path
        .strip_prefix("/sys/fs/cgroup")
        .expect("below the cgroup mount");
    assert_eq!(
        own_cgroup(),
        format!("0::/{}/supervisor", rel.display()),
        "moved from {before}"
    );
    let meta = fs::metadata(&root_path).expect("stat the root");
    assert_eq!(
        std::os::unix::fs::MetadataExt::uid(&meta),
        nix::unistd::getuid().as_raw()
    );

    // From here on it is the ordinary path: our boxes/, our request.
    fs::create_dir(root_path.join("boxes")).expect("create boxes/ in the new root");
    let boxes = open(&root_path.join("boxes"));
    let mut handles = loader::request(&h.socket, boxes.as_fd()).expect("an engine in the new root");
    let cg = Cgroups::at(root_path.clone());
    let id = cg.new_box("b");
    let socket_args = [
        "sock",
        &libc::AF_INET.to_string(),
        &libc::SOCK_STREAM.to_string(),
        "0",
    ];
    assert_eq!(cg.probe("b", &socket_args), "err 1", "no policy yet");
    let spec = netpol::Spec {
        deployment: host_ip(),
        policy: BoxPolicy::default(),
        options: netpol::compile::Options::default(),
    };
    let live = handles.install(id, spec).expect("install");
    assert_eq!(cg.probe("b", &socket_args), "ok");
    handles.uninstall(&live).expect("uninstall");

    // A box process of that root is refused like any other.
    let out = cg.probe(
        "b",
        &[
            "loader-request",
            &h.socket.to_string_lossy(),
            &root_path.join("boxes").to_string_lossy(),
        ],
    );
    assert!(out.starts_with("err ") && out.contains("not in"), "{out}");
    fs::remove_dir(root_path.join("boxes").join("b")).expect("remove the box cgroup");
}
