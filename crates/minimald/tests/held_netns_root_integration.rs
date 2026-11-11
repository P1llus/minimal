//! A network held up with no program in it, and a fetch placed in it.
//!
//! `#[ignore]`, and returns early unless `MINIMALD_NETNS_TEST` is set. Run it
//! with `just test-root-integration`.
#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::path::Path;

use sandbox::{NetPlan, Network, PlanFuture, Resolver};

/// A network with an empty namespace and a name server that nothing serves.
#[derive(Debug)]
struct Empty;

impl Network for Empty {
    fn plan(&self) -> PlanFuture<'_> {
        Box::pin(std::future::ready(Ok(NetPlan::isolated().with_resolver(
            Resolver::Nameservers(vec![Ipv4Addr::LOCALHOST]),
        ))))
    }
}

/// NET-155: a fetch placed in a held namespace leaves from that namespace and
/// not from this process's. A listener on this process's loopback serves the
/// file to an unplaced download. The placed download of the same URL cannot
/// reach it, and the listener sees no connection. The namespace's process
/// goes when the hold ends.
#[tokio::test]
#[ignore = "creates a user+network namespace; gated on MINIMALD_NETNS_TEST; runs in the ci-linux-native netns job"]
async fn a_placed_fetch_leaves_from_the_held_namespace() {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    if std::env::var_os("MINIMALD_NETNS_TEST").is_none() {
        eprintln!("skipping the held namespace proof: MINIMALD_NETNS_TEST not set");
        return;
    }
    let body = b"the source archive";
    let sha = "1f8ba2cd2f1fae8c6d3f4b2fc2e31a97f2bfb3bb70e6cfa3f6a4a6d3c1f6f7f0";
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&served);
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            assert!(stream.read(&mut buf).unwrap() > 0);
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        }
    });

    let tmp = tempfile::TempDir::new().unwrap();
    let storage = common::RemoteStorage::new(tmp.path().join("downloads"), false)
        .await
        .unwrap();
    let op = ot::OpTracker::new_root();
    let url = format!("http://{addr}/pkg-1.0.tar.gz");

    let held = Arc::new(
        sandbox::hold_network(&tmp.path().join("held"), Arc::new(Empty), None)
            .await
            .expect("a held namespace"),
    );
    let pid = held.pid();
    assert!(Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(held.nameservers(), &[Ipv4Addr::LOCALHOST]);
    let sockets = {
        let held = Arc::clone(&held);
        common::Sockets::new(move |v6, kind| held.socket(v6, kind == common::SocketKind::Datagram))
    };
    let namespace = common::NetNamespace::new(sockets, held.nameservers(), Arc::new(|_| true));

    let placed = storage
        .download_web_placed(&url, sha, &common::Placement::Namespace(namespace), &op)
        .await
        .expect_err("this process's loopback is not in the namespace");
    assert!(
        placed
            .to_string()
            .starts_with(&format!("could not connect to {addr}: ")),
        "{placed:#}"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        0,
        "nothing reached the listener"
    );

    drop(held);
    for _ in 0..50 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!Path::new(&format!("/proc/{pid}")).exists());

    // The control: the same URL from this process's namespace reaches the
    // listener, so the placed download's failure was its placement.
    drop(
        storage
            .download_web_with_verification_and_caching(&url, sha, None, &op)
            .await,
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the listener was reachable"
    );
}
