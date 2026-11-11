//! The loader's checks on who asks, the handles it gives out, and the
//! asynchronous event reader on top of them.

use std::{
    fs,
    os::fd::{AsFd, OwnedFd},
    time::Duration,
};

use boxbpf::{Error, events::Reader, loader};
use netpol::{abi::Hook, policy::BoxPolicy};

use crate::support::{Cgroups, Harness, host_ip, probe};

fn open(path: &std::path::Path) -> OwnedFd {
    fs::File::open(path).expect("open a directory").into()
}

fn refusal<T>(result: Result<T, Error>) -> String {
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
        reason.contains("no supervisor cgroup beside"),
        "a boxes cgroup with no supervisor of its own: {reason}"
    );
    fs::remove_dir(&nested).expect("remove the nested cgroup");

    // A process below the daemon, in its helpers cgroup, that makes a
    // root of its own there and moves into it: every name is right, and
    // it is still not a daemon.
    let fake = h.root.join("helpers").join("x");
    for dir in ["supervisor", "boxes"] {
        fs::create_dir_all(fake.join(dir)).expect("create a root inside the root");
    }
    let out = h.cgroups().probe_at(
        "helpers/x/supervisor",
        &[
            "loader-request",
            &h.socket.to_string_lossy(),
            &fake.join("boxes").to_string_lossy(),
        ],
    );
    assert!(
        out.starts_with("err ") && out.contains("the cgroup root of an engine that is running"),
        "{out}"
    );

    // A daemon built against other layouts is told so, and so is one
    // built with other programs, before anything is loaded for it.
    let say = |line: String| {
        let (_conn, reply, fds) =
            probe::loader_message(&h.socket, &line, Some(h.boxes.as_fd())).expect("exchange");
        assert!(fds.is_empty(), "{reply}");
        reply
    };
    assert_eq!(
        say("attach abi=4000000000".to_owned()),
        format!(
            "err abi mismatch: loader={} daemon=4000000000",
            netpol::abi::VERSION
        )
    );
    assert_eq!(
        say(format!("attach object=0000 abi={}", netpol::abi::VERSION)),
        format!(
            "err object mismatch: loader={} daemon=0000",
            boxbpf::object_id()
        )
    );

    // The cgroup has its engine. Nobody gets a second one there, or the
    // maps of the first.
    let reason = refusal(loader::request(&h.socket, h.boxes.as_fd()));
    assert!(
        reason.contains("already has policy programs attached"),
        "{reason}"
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
        assert_eq!(listing.matches("bp_").count(), 14, "{listing}");
        assert_eq!(listing.matches(" multi ").count(), 14, "{listing}");
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
fn one_box_cannot_crowd_out_the_events_of_another() {
    let Some(mut h) =
        Harness::start("cases::loader::one_box_cannot_crowd_out_the_events_of_another")
    else {
        return;
    };
    let mut events = h.handles.take_events().expect("event source");
    let closed = || BoxPolicy {
        default: Some(netpol::Verdict::Deny),
        ..BoxPolicy::default()
    };
    let loud = h.install("loud", host_ip(), closed());
    let quiet = h.install("quiet", host_ip(), closed());
    let target = h.v4(1, 1).to_string();

    // More refusals than the ring buffer holds records, with nobody
    // reading. Then a hundred of another box.
    assert_eq!(h.probe("loud", &["flood", &target, "9", "5000"]), "ok 5000");
    assert_eq!(h.probe("quiet", &["flood", &target, "9", "100"]), "ok 100");
    let seen = Harness::drain(&mut events);
    let of = |id: boxbpf::BoxId| seen.iter().filter(|e| e.box_id == id.0).count();
    assert_eq!(
        of(quiet.id()),
        100,
        "every refusal of the quiet box arrives"
    );
    let stats = |h: &Harness, id| h.handles.stats(id).expect("stats").expect("counters");
    let (loud_stats, quiet_stats) = (stats(&h, loud.id()), stats(&h, quiet.id()));
    assert_eq!(
        (
            quiet_stats.refused,
            quiet_stats.ev_limited,
            quiet_stats.ev_lost
        ),
        (100, 0, 0)
    );
    // The loud box got its burst and a little more. The rest is counted,
    // and the refusals themselves all are.
    let reported = of(loud.id());
    assert!(
        (200..600).contains(&reported),
        "{reported} events of the loud box"
    );
    assert_eq!(loud_stats.refused, 5000);
    assert_eq!(loud_stats.ev_lost, 0);
    assert_eq!(
        loud_stats.ev_limited,
        5000 - u64::try_from(reported).expect("count")
    );

    // The bucket fills again: after a pause the loud box is heard.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(h.probe("loud", &["flood", &target, "9", "10"]), "ok 10");
    let seen = Harness::drain(&mut events);
    assert_eq!(seen.iter().filter(|e| e.box_id == loud.id().0).count(), 10);
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_daemon_without_a_delegated_cgroup_gets_a_root_from_the_loader() {
    let Some(h) = Harness::start(
        "cases::loader::a_daemon_without_a_delegated_cgroup_gets_a_root_from_the_loader",
    ) else {
        return;
    };
    // This process runs in a delegated unit, as a box process does. It has
    // a root, or must stay where it is: the loader moves neither.
    let reason = refusal(loader::request_root(&h.socket).map(drop));
    assert!(reason.contains("delegated already"), "{reason}");

    // A process of this user in a cgroup nobody delegated: a plain system
    // service. The loader makes it a root, moves it into supervisor/, and
    // serves its attach request like any other.
    let line = Cgroups::outside_probe(&["root-request", &h.socket.to_string_lossy()]);
    assert!(line.starts_with("ok root="), "{line}");
    let value = |key: &str| {
        line.split_whitespace()
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key}: {line}"))
            .to_owned()
    };
    let root = value("root");
    let rel = root
        .strip_prefix("/sys/fs/cgroup")
        .expect("below the cgroup mount");
    assert_eq!(value("cgroup"), format!("0::{rel}/supervisor"));
    assert_eq!(value("owner"), nix::unistd::getuid().as_raw().to_string());
    assert_eq!(value("engine"), "ok");
    assert_ne!(value("before"), value("cgroup"));

    // A daemon that asks and dies. Whatever the loader had made for it by
    // then is gone again: no cgroup of that user is left behind.
    let line = Cgroups::outside_probe(&["root-request-abandoned", &h.socket.to_string_lossy()]);
    let pid = line
        .strip_prefix("ok pid=")
        .unwrap_or_else(|| panic!("{line}"));
    // The loader serves one request at a time: when it answers this one,
    // it is done with the one before.
    let _refused = loader::request_root(&h.socket);
    let name = format!("u{}-{pid}", nix::unistd::getuid().as_raw());
    let left: Vec<_> = fs::read_dir("/sys/fs/cgroup")
        .expect("list the cgroup mount")
        .flatten()
        .map(|base| base.path().join(&name))
        .filter(|root| root.exists())
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn an_engine_nobody_confirms_is_taken_off_again() {
    let Some(g) = Harness::bare("cases::loader::an_engine_nobody_confirms_is_taken_off_again")
    else {
        return;
    };
    let attach = format!(
        "attach object={} abi={}",
        boxbpf::object_id(),
        netpol::abi::VERSION
    );
    // A daemon that gets the maps and goes away without a word, and one
    // that answers something else.
    for answer in [None, Some("thanks")] {
        let (conn, reply, maps) =
            probe::loader_message(&g.socket, &attach, Some(g.boxes.as_fd())).expect("exchange");
        assert!(reply.starts_with("ok abi="), "{reply}");
        assert_eq!(maps.len(), 10);
        if let Some(word) = answer {
            nix::sys::socket::send(
                std::os::fd::AsRawFd::as_raw_fd(&conn),
                word.as_bytes(),
                nix::sys::socket::MsgFlags::empty(),
            )
            .expect("answer");
        }
        drop(conn);
    }
    // Had the programs stayed, this request would be refused: the cgroup
    // would have an engine whose maps nobody holds, and every box in it
    // no network.
    let mut handles =
        loader::request(&g.socket, g.boxes.as_fd()).expect("an engine after the abandoned ones");
    assert!(handles.take_events().is_some());
    // This one was confirmed, and stays.
    let reason = refusal(loader::request(&g.socket, g.boxes.as_fd()));
    assert!(
        reason.contains("already has policy programs attached"),
        "{reason}"
    );
}
