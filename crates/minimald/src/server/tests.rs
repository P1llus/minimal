use std::time::Duration;

use minimald_rpc::{GetVersion, Shutdown, ShutdownRequest, ShutdownResponse};
use tempfile::TempDir;

use super::*;
use crate::test_harness::connect_uds;

/// A `Config` backed by a fresh tempdir, mirroring `TestServer::new`.
fn test_config(dir: &TempDir) -> Config {
    super::test_config(dir.path())
}

/// The inactivity deadline is the whole keepalive budget, derived from the
/// keepalive settings rather than restated: a healthy idle attach answers a
/// keepalive every interval (resetting the clock), so the deadline must
/// outlast every keepalive round the budget allows.
#[test]
fn inactivity_deadline_spans_the_full_keepalive_budget() {
    assert_eq!(INACTIVITY_TIMEOUT, Duration::from_secs(2 * 60 * 60));
    assert!(INACTIVITY_TIMEOUT > KEEPALIVE_INTERVAL * KEEPALIVE_MAX as u32);
}

/// A client that hangs up with daemon output still unread resets the
/// connection instead of closing it, and that is the same abrupt client loss
/// as an end of file: it is logged as a closed connection, not as an error.
/// A fault on this side still is one.
#[test]
fn a_reset_connection_was_closed_by_its_peer() {
    use crate::connection::ConnectionError;
    use std::io::{Error, ErrorKind};

    let io = |kind| ConnectionError::Protocol(russh::Error::IO(Error::from(kind)));
    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::UnexpectedEof,
        ErrorKind::BrokenPipe,
    ] {
        assert!(closed_by_peer(&io(kind)), "{kind:?} is the peer hanging up");
    }
    assert!(closed_by_peer(&ConnectionError::Protocol(
        russh::Error::Disconnect
    )));
    assert!(!closed_by_peer(&io(ErrorKind::PermissionDenied)));
    assert!(!closed_by_peer(&ConnectionError::Internal(
        "the session store is unreadable".to_string()
    )));
}

/// The production config arms the inactivity deadline: with `None` a
/// wedged transport write parks the session loop forever.
#[tokio::test]
async fn the_production_config_arms_the_inactivity_deadline() {
    let server = crate::test_harness::TestServer::new().await;
    let config = build_russh_config(&server.state).await.unwrap();
    assert_eq!(config.inactivity_timeout, Some(INACTIVITY_TIMEOUT));
    assert_eq!(config.keepalive_interval, Some(KEEPALIVE_INTERVAL));
    assert_eq!(config.keepalive_max, KEEPALIVE_MAX);
}

/// The volume-log release must run exactly once no matter how many
/// times the Shutdown path invokes it, and a harness-style `None`
/// release must be a no-op.
#[tokio::test]
async fn log_release_runs_exactly_once() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let dir = TempDir::new().unwrap();
    let count = Arc::new(AtomicU32::new(0));
    let counted = count.clone();
    let release = DaemonLogRelease::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    let state = ServerStateHandle::new(test_config(&dir), Some(release))
        .await
        .unwrap();
    state.release_log().await;
    state.release_log().await;
    assert_eq!(count.load(Ordering::SeqCst), 1, "one-shot, then a no-op");

    let none = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    none.release_log().await;
}

/// Binds a UDS in `dir` and spawns `Server::run` against it, returning the
/// run task's join handle alongside the socket path clients dial.
fn spawn_server(
    dir: &TempDir,
) -> (
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
    std::path::PathBuf,
) {
    spawn_server_with(dir, test_config(dir))
}

/// [`spawn_server`] with an explicit [`Config`]: the tests that pin ports
/// or flip the deployment model drive the flags' path through
/// [`Server::run`] rather than around it.
fn spawn_server_with(
    dir: &TempDir,
    config: Config,
) -> (
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
    std::path::PathBuf,
) {
    let sock = dir.path().join("minimald.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let run = crate::traced::spawn(Server::run(config, listener, None));
    (run, sock)
}

/// [`spawn_server_with`] with the built state handed back to the caller.
/// The start path is the one `Server::run` takes — the same proxy startup
/// against the config's port choices, then the real accept loop off the
/// same listener — but the state stays reachable, for the tests that must
/// fill the hostname registry the running proxy routes against: no RPC
/// does, it is the session launch path that fills it.
#[cfg(target_os = "linux")]
async fn spawn_stateful_server_with(
    dir: &TempDir,
    config: Config,
) -> (
    ServerStateHandle,
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
    std::path::PathBuf,
) {
    let in_microvm = config.in_microvm;
    let hostname_proxy_port = config.hostname_proxy_port;
    let zone_answerer_port = config.zone_answerer_port;
    let state = ServerStateHandle::new(config, None).await.unwrap();
    start_host_proxies(&state, in_microvm, hostname_proxy_port, zone_answerer_port).await;
    let sock = dir.path().join("minimald.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let run = crate::traced::spawn(Server::serve(state.clone(), listener));
    (state, run, sock)
}

#[tokio::test]
async fn shutdown_rpc_drives_run_to_return_once_the_client_disconnects() {
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    {
        let mut client = connect_uds(&sock).await;
        let resp = client
            .call::<Shutdown>(&ShutdownRequest { force: false })
            .await;
        assert_eq!(resp, ShutdownResponse::ShuttingDown);
        // Dropping `client` closes the connection, so the drain sees the
        // last in-flight session finish and `run` returns without waiting
        // out the grace period.
    }

    let res = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("run should return promptly once the client disconnects");
    assert!(res.unwrap().is_ok(), "run should return Ok after shutdown");
}

#[tokio::test]
async fn shutdown_rpc_returns_even_if_the_initiating_client_lingers() {
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    // Keep the client — and thus its connection — open past the shutdown.
    // The drain can't complete gracefully, so the grace period must elapse
    // and abort the straggler, guaranteeing `run` still returns.
    let mut client = connect_uds(&sock).await;
    let resp = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    assert_eq!(resp, ShutdownResponse::ShuttingDown);

    let res = tokio::time::timeout(SHUTDOWN_GRACE + Duration::from_secs(3), run)
        .await
        .expect("run must return after the grace period aborts lingering connections");
    assert!(res.unwrap().is_ok(), "run should return Ok after shutdown");
    drop(client);
}

/// The first `conn` span `log` saw, once it has closed: its task has then
/// recorded the outcome and logged how the connection ended.
async fn first_conn_once_closed(
    log: &crate::test_harness::SpanLog,
) -> crate::test_harness::LoggedSpan {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(first) = log.spans().into_iter().find(|s| s.name == "conn")
                && first.closed
            {
                return first;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first conn span closes")
}

/// `min` probes the daemon's socket before every command by connecting
/// and hanging up without an SSH id line; that is not a failed handshake
/// and is not logged as one. The `conn` span says what became of the
/// connection instead.
#[tokio::test]
async fn a_peer_that_hangs_up_before_the_ssh_id_is_not_a_handshake_failure() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let capture = crate::test_harness::CaptureWriter::default();
    let log = crate::test_harness::SpanLog::default();
    let _g = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(log.clone()).with(
            tracing_subscriber::fmt::layer()
                .with_writer(capture.clone())
                .with_ansi(false),
        ),
    );
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    let probe = tokio::net::UnixStream::connect(&sock).await.unwrap();
    drop(probe);
    // The probe's `conn` span closes when its task has classified the
    // hang-up and logged it, so the log is complete for the probe then.
    let probe_conn = first_conn_once_closed(&log).await;
    assert_eq!(
        probe_conn.field("outcome"),
        Some("closed_before_id"),
        "{probe_conn:?}"
    );
    let mut client = connect_uds(&sock).await;
    let resp = client.call::<GetVersion>(&()).await;
    assert!(!resp.version.is_empty());

    let logged = capture.contents();
    assert!(
        !logged.contains("SSH handshake failed"),
        "a peer that hung up before the id exchange is not a failed handshake: {logged}"
    );
    assert!(
        logged.contains("peer closed before the SSH id exchange"),
        "the probe's hang-up is logged at debug: {logged}"
    );
    assert!(
        logged.matches("accepted connection").count() >= 2,
        "both the probe and the client were accepted: {logged}"
    );

    let _ = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}

/// `run_stream` returns once the SSH ids are exchanged, with key exchange
/// still to run in russh's task: a peer that sends its id and then fails key
/// exchange is a failed handshake, not a session, while a real client that
/// gets through is one. The `conn` span's outcome says which.
#[tokio::test]
async fn a_peer_that_fails_key_exchange_after_its_id_is_a_failed_handshake() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tracing_subscriber::layer::SubscriberExt as _;
    let log = crate::test_harness::SpanLog::default();
    let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    let mut peer = tokio::net::UnixStream::connect(&sock).await.unwrap();
    peer.write_all(b"SSH-2.0-not-a-client\r\n").await.unwrap();
    // A packet length no SSH implementation accepts. The daemon may close
    // before all of it is written.
    let _ = peer.write_all(&[0xff; 64]).await;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut sink)).await;
    drop(peer);

    let mut client = connect_uds(&sock).await;
    let resp = client.call::<GetVersion>(&()).await;
    assert!(!resp.version.is_empty());
    let _ = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;

    let outcomes: Vec<Option<String>> = log
        .spans()
        .iter()
        .filter(|s| s.name == "conn")
        .map(|s| s.field("outcome").map(str::to_owned))
        .collect();
    assert_eq!(
        outcomes,
        [
            Some("handshake_failed".to_owned()),
            Some("session".to_owned())
        ],
        "{:#?}",
        log.spans()
    );
}

/// A peer that gets through key exchange and asks for ssh-userauth, but
/// hangs up without authenticating, had no session: its `conn` outcome is
/// `closed_before_auth`, and only the client that authenticates is a
/// `session`.
#[tokio::test]
async fn a_peer_that_never_authenticates_is_not_a_session() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let log = crate::test_harness::SpanLog::default();
    let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let mut peer = russh::client::connect_stream(
        std::sync::Arc::new(russh::client::Config::default()),
        stream,
        crate::test_harness::TestClientHandler,
    )
    .await
    .unwrap();
    // The daemon takes no passwords: the request is refused, after the
    // ssh-userauth service was granted.
    let auth = peer.authenticate_password("test", "wrong").await.unwrap();
    assert!(!auth.success());
    drop(peer);
    first_conn_once_closed(&log).await;

    let mut client = connect_uds(&sock).await;
    let resp = client.call::<GetVersion>(&()).await;
    assert!(!resp.version.is_empty());
    let _ = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;

    let outcomes: Vec<Option<String>> = log
        .spans()
        .iter()
        .filter(|s| s.name == "conn")
        .map(|s| s.field("outcome").map(str::to_owned))
        .collect();
    assert_eq!(
        outcomes,
        [
            Some("closed_before_auth".to_owned()),
            Some("session".to_owned())
        ],
        "{:#?}",
        log.spans()
    );
}

/// A connection that connects and never sends its SSH id line must not
/// stall the accept loop: a second connection completes a full handshake
/// and a `GetVersion` RPC while the silent one is still open.
#[tokio::test]
async fn silent_client_does_not_stall_the_accept_loop() {
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    // Open a connection and send nothing: it holds the socket without
    // ever completing the handshake.
    let silent = tokio::net::UnixStream::connect(&sock).await.unwrap();

    // A second connection must handshake and serve an RPC promptly. The
    // bound covers the connect too: a stalled accept loop shows up there.
    let (mut client, resp) = tokio::time::timeout(Duration::from_secs(2), async {
        let mut client = connect_uds(&sock).await;
        let resp = client.call::<GetVersion>(&()).await;
        (client, resp)
    })
    .await
    .expect("a second connection must complete a handshake and RPC within 2s");
    assert!(!resp.version.is_empty(), "GetVersion must return a version");

    // Close the silent connection so shutdown does not wait out its grace.
    drop(silent);

    let _ = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}

/// A connection that never sends its id line is dropped once the
/// handshake deadline elapses, rather than holding its task and socket
/// forever.
#[tokio::test(start_paused = true)]
async fn silent_client_is_dropped_after_the_handshake_deadline() {
    use tokio::io::AsyncReadExt as _;

    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    let mut silent = tokio::net::UnixStream::connect(&sock).await.unwrap();
    // The paused clock auto-advances while the runtime is idle, so this
    // read resolves once the server's handshake deadline drops the
    // connection and closes the socket.
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(HANDSHAKE_DEADLINE + Duration::from_secs(5), async {
        loop {
            match silent.read(&mut buf).await {
                Ok(0) => break true,
                Ok(_) => {}
                Err(_) => break true,
            }
        }
    })
    .await
    .expect("the silent connection must be closed after the handshake deadline");
    assert!(closed, "the server must close the silent connection");

    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}

/// A session left unfinalized when its creating connection closes —
/// the state an interrupted `min session activate` (Ctrl-C at the gating
/// prompt) leaves on the daemon — is reaped, while a finalized
/// (`Active`) session created over that same connection survives.
#[tokio::test]
async fn dropping_a_connection_reaps_only_its_unfinalized_sessions() {
    use crate::test_harness::{create_configured_session, create_session_req};
    use minimald_rpc::{CreateSession, GetSessionRecord, GetSessionRecordRequest};

    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    // Connection A: create a Pending session (no ConfigureLoadout) AND a
    // fully-finalized Active session, then drop the connection.
    let (pending_id, active_id) = {
        let mut client = connect_uds(&sock).await;
        let pending = client
            .call::<CreateSession>(&create_session_req("interrupted", "/tmp"))
            .await
            .ok()
            .expect("create pending session")
            .id;
        let active = create_configured_session(&mut client, "finalized", "/tmp").await;
        (pending, active)
        // `client` dropped here → connection closes → the server's
        // per-connection task runs the teardown reap.
    };

    // The reap is asynchronous (it runs once the socket close is
    // observed), so poll a fresh connection until the Pending record is
    // gone. The Active record must remain throughout.
    let mut client = connect_uds(&sock).await;
    let mut reaped = false;
    for _ in 0..100 {
        let pending_gone = client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(pending_id))
            .await
            .record
            .is_none();
        if pending_gone {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        reaped,
        "an unfinalized (Pending) session must be reaped when its creating connection closes",
    );
    assert!(
        client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(active_id))
            .await
            .record
            .is_some(),
        "an Active session must survive the connection that created it",
    );

    let _ = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}

/// TEL-022: the reap of a session its creating connection left
/// unfinalized is that CreateSession's cleanup: its span is a child of the
/// CreateSession `rpc` span, in the client's trace, and so is the record
/// read it sends. Under the connection's `conn` span alone it was a trace
/// of its own (a stray trace in every lab run). In the file log the reap
/// stays under `conn`, as the `rpc` span does.
///
/// Driven through `Server::run`: the teardown reap lives in its accept
/// loop's per-connection task, which `TestServer::connect` does not run.
#[tokio::test]
async fn the_reap_of_an_unfinalized_session_joins_its_creators_trace() {
    use crate::test_harness::{SpanLog, create_session_req};
    use minimald_rpc::CreateSession;
    use tracing_subscriber::layer::SubscriberExt as _;

    const TRACE: &str = "0af7651916cd43dd8448eb211c80319c";
    let env = [(
        minimald_rpc::trace::TRACEPARENT_ENV,
        "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    )];
    let log = SpanLog::default();
    let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
    let dir = TempDir::new().unwrap();
    let (run, sock) = spawn_server(&dir);

    {
        let mut client = connect_uds(&sock).await;
        client
            .call_with_env::<CreateSession>(&env, &create_session_req("s", "/tmp"))
            .await
            .unwrap();
        // `client` dropped here → connection closes → the teardown reaps
        // the still-Pending session.
    }

    // Wait for the reap span to close, not merely to open: its record read
    // is sent from inside it, so only once it has closed is that read
    // certain to be in the log.
    let reap = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(reap) = log
                .find("sessions.reap_unfinalized", "trace_id", TRACE)
                .into_iter()
                .find(|s| s.closed)
            {
                return reap;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the teardown's reap span closes");

    let create = log.one("rpc", "rpc", "minimald-v1-CreateSession");
    assert_eq!(
        reap.field("parent_span_id"),
        create.field("span_id"),
        "the reap is a child of its CreateSession: {reap:?} {create:?}"
    );
    assert_eq!(
        log.parent_of(&reap).map(|p| p.name),
        Some("conn"),
        "in the file log the reap stays under its connection"
    );
    let parent = reap.field("span_id");
    let read = log
        .find("sessions.manager.message", "kind", "GetRecord")
        .into_iter()
        .find(|read| read.field("parent_span_id") == parent)
        .expect("the reap's record read is its child");
    assert_eq!(read.field("trace_id"), Some(TRACE));

    let mut client = connect_uds(&sock).await;
    let _ = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}

/// A creator that disconnects mid-upload leaves a half-populated `Draft`
/// for its teardown to reap. An attach from another connection that
/// lands after the creator is gone but before that reap is refused — the
/// creator-only gate holds until the reap is done — rather than running
/// the Draft shortcut, which would scaffold a root `minimal.toml` over
/// the half-uploaded tree and could carry the session to `Active` ahead
/// of the reap, alive behind a layout conflict. The teardown is parked
/// just before its reap, so the attach lands in exactly that window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_from_elsewhere_between_a_creators_close_and_its_reap_is_refused() {
    use crate::test_harness::create_session_req;
    use minimald_rpc::{CreateSession, GetSessionRecord, GetSessionRecordRequest};
    use russh::ChannelMsg;
    use tokio::io::AsyncWriteExt as _;

    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("minimald.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let run = tokio::spawn(Server::serve(state.clone(), listener));

    let mut creator = connect_uds(&sock).await;
    let mut other = connect_uds(&sock).await;
    let id = creator
        .call::<CreateSession>(&create_session_req("abandoned-mid-upload", "/tmp"))
        .await
        .ok()
        .expect("create session")
        .id;
    let (parked, release) = reap_seam::hold(id);
    let working = state
        .sessions_manager()
        .await
        .get_session(box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("session should resolve")
        .paths()
        .await
        .expect("paths should resolve")
        .working
        .as_utf8_path()
        .to_owned();

    // The creator streams the first half of its workspace: a small file
    // ahead of incompressible noise several zstd blocks long, so that
    // half already carries the small file whole.
    let noise: Vec<u8> = (0..512 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut tar = async_tar::Builder::new(Vec::new());
    for (path, contents) in [("first.txt", &b"first\n"[..]), ("big.bin", &noise[..])] {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        tar.append_data(&mut header, path, contents).await.unwrap();
    }
    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder
        .write_all(&tar.into_inner().await.unwrap())
        .await
        .unwrap();
    encoder.shutdown().await.unwrap();
    let payload = encoder.into_inner();
    let upload = creator
        .open_subsystem(
            crate::rpc::STREAM_WORKSPACE_FILES,
            &[(crate::MINIMAL_SESSION_ID_ENV, &id.to_string())],
        )
        .await;
    upload.data(&payload[..payload.len() / 2]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !working.join("first.txt").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first half of the upload should start unpacking");

    // The creator goes away mid-upload, and its teardown parks before
    // the reap.
    drop(upload);
    drop(creator);
    tokio::time::timeout(Duration::from_secs(10), parked)
        .await
        .expect("the creator's teardown should reach its reap")
        .expect("the teardown should park, not skip the seam");

    // The window. The torn-down upload clears its own mark on the way
    // out, and until it has the attach is refused for that instead; once
    // it has, the creator-only gate is all that stands in the way.
    let refusal = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut channel = other.open_shell(id).await;
            let mut out = Vec::new();
            while let Some(msg) = channel.wait().await {
                if let ChannelMsg::Data { data } = msg {
                    out.extend_from_slice(&data);
                }
            }
            let out = String::from_utf8_lossy(&out).into_owned();
            if !out.contains("session is still receiving its workspace upload") {
                break out;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("an attach in the window must be refused, not mint a shell");
    assert!(
        refusal.contains("session isn't attachable yet"),
        "an attach before the creator's reap must be refused, got: {refusal:?}"
    );
    assert!(
        !working.join(mfile::MFILE_NAME).exists(),
        "a refused attach must not scaffold the half-uploaded workspace"
    );
    assert_eq!(
        other
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
            .await
            .record
            .map(|record| record.status),
        Some(::boxes::BoxState::Pending),
        "the refused attach must leave the session unfinalized for the reap"
    );

    // Let the teardown go on: the reap finds the session still
    // unfinalized and deletes it.
    let _ = release.send(());
    let mut reaped = false;
    for _ in 0..500 {
        if other
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
            .await
            .record
            .is_none()
        {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        reaped,
        "the session a creator abandoned mid-upload must be reaped"
    );

    let _ = other
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), run).await;
}

/// A `MakeWriter` accumulating everything written into a shared buffer, so
/// a test can assert on the structured fields a `tracing` event emitted.
/// Local twin of the helper the `net::proxy` tests used before the bind
/// failure's log line moved to the startup retry that owns the schedule.
#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
struct CaptureWriter(Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(target_os = "linux")]
impl CaptureWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[cfg(target_os = "linux")]
impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// The `next_retry=<delay>` values the startup retry's failure warnings
/// carried, in the order they were logged.
#[cfg(target_os = "linux")]
fn logged_next_retries(log: &str) -> Vec<&str> {
    log.match_indices("next_retry=")
        .map(|(start, _)| {
            let rest = &log[start + "next_retry=".len()..];
            rest.split([' ', '\n', ',']).next().unwrap_or_default()
        })
        .collect()
}

/// The hostname proxy's startup retry keeps trying a held listen address:
/// each failed bind warns once with the reason, the remedy, and the next
/// (doubling, capped) retry delay and records the reason-and-remedy report
/// on the state note (NET-021); once the address frees, the next attempt
/// binds, the note clears, and the recovery is logged (NET-022) — no
/// daemon restart anywhere.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn listener_retries_with_backoff() {
    // Hold an address so the startup retry's binds fail deterministically.
    let held = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = held.local_addr().unwrap();

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    // A compressed schedule: first retry 5 ms after the failure, doubling
    // to a 20 ms cap, so a loop's worth of failures costs milliseconds.
    let retrier = crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base: addr.ip(),
            // Pinned: a configured port's bind failure is the operator's
            // to clear, never a relocation.
            port: ProxyPort::Pinned(addr.port()),
        },
        RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
    ));

    // Three failures are enough to see the doubling and the cap.
    let mut saw_three_warnings = false;
    for _ in 0..200 {
        if buf
            .contents()
            .matches("could not bind its listener")
            .count()
            >= 3
        {
            saw_three_warnings = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        saw_three_warnings,
        "expected three failure warnings while the address is held, got: {}",
        buf.contents()
    );
    let note = state
        .proxy_unavailable()
        .await
        .expect("a held address must be recorded as the unavailable note");
    assert!(
        note.contains("could not bind") && note.contains("Remedy"),
        "the note must carry the reason and the remedy, got: {note}"
    );

    // The retry delays double from the schedule's initial wait and cap at
    // its max: 5 ms, 10 ms, then 20 ms for as long as the address stays
    // held.
    let logged = buf.contents();
    let delays = logged_next_retries(&logged);
    assert_eq!(
        &delays[..3.min(delays.len())],
        &["5ms", "10ms", "20ms"][..3.min(delays.len())],
        "retry delays must grow with backoff and cap, got: {delays:?}"
    );
    assert!(
        delays.iter().skip(3).all(|d| *d == "20ms"),
        "retries past the cap must wait the cap, got: {delays:?}"
    );

    // Freeing the address lets the next attempt bind: the retry task
    // resolves, the note clears, and the recovery is on the log.
    drop(held);
    tokio::time::timeout(Duration::from_secs(5), retrier)
        .await
        .expect("the retry must finish once the address frees")
        .expect("the retry task must not panic");
    assert!(
        state.proxy_unavailable().await.is_none(),
        "recovery must clear the unavailable note without a restart"
    );
    let logged = buf.contents();
    assert!(
        logged.contains(r#"status="recovered""#),
        "the recovery must be logged, got: {logged}"
    );
    assert!(
        logged.contains(r#"status="reachable""#),
        "the successful bind must be logged as reachable, got: {logged}"
    );
}

/// Spawns a backend on `addr` that answers every request with a `200 OK`
/// whose body is `body`. Local twin of `net::proxy`'s one-shot helper,
/// with a body so the two-daemon test can tell its backends apart — and
/// with the address as a parameter, so two daemons' boxes can publish the
/// same port on different addresses.
#[cfg(target_os = "linux")]
async fn spawn_backend_on(addr: std::net::SocketAddr, body: &'static str) {
    let backend = TcpListener::bind(addr).await.unwrap();
    crate::traced::spawn(async move {
        while let Ok((mut sock, _)) = backend.accept().await {
            crate::traced::spawn(async move {
                use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

                let mut scratch = [0u8; 1024];
                let _ = sock.read(&mut scratch).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                // `sock` drops here, closing the upstream side.
            });
        }
    });
}

/// Spawns a backend (see [`spawn_backend_on`]) at `0.0.0.0` on a free port,
/// returning the port it listens on. A host-address box's name reaches only
/// a port held at `0.0.0.0`, never one held at `127.0.0.1` only (NET-071).
#[cfg(target_os = "linux")]
async fn spawn_backend_saying(body: &'static str) -> u16 {
    use std::net::{IpAddr, Ipv4Addr};

    // Reserve then drop: the bind below re-takes the port for keeps.
    let port = {
        let bind = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
        bind.local_addr().unwrap().port()
    };
    spawn_backend_on(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        body,
    )
    .await;
    port
}

/// Drives the hostname proxy with a `GET` carrying `Host: <authority>`
/// and returns the raw response the client read back — the proxy's own
/// test-facing shape, driven through the port a daemon's startup bound.
#[cfg(target_os = "linux")]
async fn proxy_get(proxy_addr: SocketAddr, authority: &str) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

/// Waits until the state reports the port its hostname proxy ended up on.
#[cfg(target_os = "linux")]
async fn wait_for_proxy_port(state: &ServerStateHandle) -> u16 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(port) = state.hostname_proxy_port().await {
                return port;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the hostname proxy must bind and report its port")
}

/// T63 (NET-025, NET-138): a VM-hosted daemon binds the port its host
/// handed it on the boot line, and selects none of its own. The handed
/// port is read exactly the way pid-1 reads it — off the environment
/// the kernel passes through — and the startup is driven the way a VM
/// daemon's is: bind 0.0.0.0, publish behind the host-loopback gate, then
/// record the bound port for the discovery reply to carry. With a handed
/// port held busy, the startup keeps retrying that port and never
/// re-picks: the host's box table names it, so a silent move would strand
/// every client pointed at it.
///
/// The handed port is the hostname proxy's alone: a VM-hosted daemon
/// starts no zone answerer (NET-138 — the VM host daemon's host answerer
/// owns the zone), so no answerer token exists to read or drive.
///
/// The host-loopback publish is the `Fixed(None)` stand-in — the real
/// gate's decisions are proven from the gate side (`minvmd`'s
/// `switch_request_refused_and_logged`); what is under test here is the
/// port policy the handed values feed.
// Env is process state: nextest runs every test in its own process.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn vm_hosted_daemon_binds_handed_port() {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::guest;

    // Reserve a free port, then write it onto the boot line the way
    // minvmd does: as a token the kernel hands pid-1 as an environment
    // variable.
    let probe = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let proxy_port = probe.local_addr().unwrap().port();
    drop(probe);
    unsafe {
        std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, proxy_port.to_string());
    }
    // What pid-1's CLI is built with: the handed port.
    assert_eq!(guest::handed_proxy_port().unwrap(), Some(proxy_port));

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();

    // The VM startup shape: bind UNSPECIFIED, publish behind the
    // host-loopback gate, record the bound port. The compressed backoff
    // keeps a failed attempt cheap should the box be noisy.
    let retry = RetryBackoff::new(Duration::from_millis(10), Duration::from_millis(100));
    crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: ProxyPort::from_config(
                guest::handed_proxy_port().unwrap(),
                crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
            ),
        },
        retry,
    ));

    // Bound as handed, and reported on the discovery path the RPC
    // replies carry.
    assert_eq!(
        wait_for_proxy_port(&state).await,
        proxy_port,
        "the handed proxy port is bound, not re-picked"
    );

    // And it really is a listener on the handed port: the proxy answers
    // (a name no live box owns gets its refusal).
    let routed = proxy_get(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port),
        "ghost.min.internal",
    )
    .await;
    assert!(routed.contains("502"), "the handed port answers: {routed}");

    // Selects none: with a handed port held, the startup keeps retrying
    // that port and never re-picks — the state stays portless while the
    // loop is alive. A fresh state, so the first phase's recorded port
    // cannot stand in for this one's.
    let probe = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let held = probe.local_addr().unwrap().port();
    unsafe { std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, held.to_string()) };
    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let drive = crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: ProxyPort::from_config(
                guest::handed_proxy_port().unwrap(),
                crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
            ),
        },
        RetryBackoff::new(Duration::from_millis(10), Duration::from_millis(50)),
    ));
    // Several retries on the compressed backoff, then prove it stayed put.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !drive.is_finished(),
        "a busy handed port is retried, not abandoned"
    );
    assert_eq!(
        state.hostname_proxy_port().await,
        None,
        "a busy handed port is never re-picked"
    );
    drive.abort();
    drop(probe);
}

/// T65 (NET-009 on a VM host): a VM-hosted daemon starts no zone answerer
/// and publishes none through the forwarder. The zone on a VM-backed host
/// is the VM host daemon's to answer — `minvmd`'s host answerer serves it
/// on the host loopback, from the host-authored table (NET-138) — so an
/// in-guest answerer behind the switch would only shadow it. What must
/// stay is the *other* half of `start_host_proxies`: the hostname proxy
/// starts in a microVM exactly as before.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn vm_hosted_daemon_starts_no_answerer() {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::rr::RecordType;

    use crate::net::answerer::encode_query;

    // A free UDP port the daemon is configured to put its answerer on —
    // the handed-answerer port a VM-hosted daemon used to bind before the
    // host answerer took the zone. Reserved here only to learn a free
    // number, then released: if the daemon starts an answerer despite its
    // deployment model, it is this port it binds and answers on, which is
    // exactly what the datagram below would find.
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let configured = probe.local_addr().unwrap().port();
    drop(probe);

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(
        Config {
            in_microvm: true,
            zone_answerer_port: Some(configured),
            ..test_config(&dir)
        },
        None,
    )
    .await
    .unwrap();

    // The real startup path, the way a VM-hosted `Server::run` takes it.
    start_host_proxies(&state, true, None, Some(configured)).await;

    // The positive control: the hostname proxy's half ran — its listen
    // address bindable line is the first thing the VM startup logs, well
    // before the host publish this harness has no gvproxy to answer. What
    // changed is the answerer, not the daemon's whole proxy half.
    let mut proxy_bound = false;
    for _ in 0..200 {
        if buf
            .contents()
            .contains("egress proxy listen address is bindable")
        {
            proxy_bound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        proxy_bound,
        "the hostname proxy must start in a microVM as before, got: {}",
        buf.contents()
    );

    // The answerer never does: no line of its component — not a bind, not
    // a retry, not a serving — and its discovery field, the one `min ls`
    // prints its DNS SERVICE line from, stays empty for a window the
    // native startup fills it in within its first bind attempt.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        state.zone_answerer_port().await,
        None,
        "a VM-hosted daemon reports no zone answerer: the host answerer owns the zone"
    );
    assert!(
        !buf.contents().contains("zone-answerer"),
        "no zone-answerer line may appear in a VM-hosted daemon's log, got: {}",
        buf.contents()
    );

    // And nothing listens for zone datagrams on the port it was
    // configured to take: a query sent there gets no reply at all — no
    // rcode, no error, nothing — which is the port's state a VM host's
    // host answerer finds when it takes it.
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    socket
        .send_to(
            &encode_query("web.min.internal.", RecordType::A),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), configured),
        )
        .unwrap();
    let mut reply = [0u8; 512];
    match socket.recv_from(&mut reply) {
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut => {}
        outcome => panic!(
            "the daemon must answer nothing in the zone's place on a VM host, got: {outcome:?}"
        ),
    }

    // The same deployment model with nothing handed at all — no handed
    // boot token and no configured port, the state a VM boots in now the
    // handoff carries the proxy port only: an answerer that ran anyway
    // would take the documented default (7656) on the guest's wildcard.
    // Both of its outcomes are caught without this test binding that
    // port itself (a dev host may hold it): a bind that succeeded would
    // set the discovery claim, and one that failed would log its
    // component line — neither may appear.
    let dir = TempDir::new().unwrap();
    let unconfigured = ServerStateHandle::new(
        Config {
            in_microvm: true,
            zone_answerer_port: None,
            ..test_config(&dir)
        },
        None,
    )
    .await
    .unwrap();
    start_host_proxies(&unconfigured, true, None, None).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        unconfigured.zone_answerer_port().await,
        None,
        "a VM-hosted daemon with nothing handed binds no answerer on the \
         default port either: the host answerer owns the zone (NET-138)"
    );
    assert!(
        !buf.contents().contains("zone-answerer"),
        "no zone-answerer line may appear for a VM-hosted daemon with \
         nothing handed, got: {}",
        buf.contents()
    );
}

/// T63 (NET-025): the pid-1 boot reads its handed port fail-closed and
/// binds it before anything else answers. A token present but unusable
/// is a surfaced boot error — the read is an `Err` naming the token and
/// the value it carried, not a `None` the daemon would fall back from —
/// and a handed port something already holds fails the probe bind, which
/// is boot-fatal: the startup pid-1 would drive next is driven here and
/// stays portless, the boot was over before it, never rescued by a
/// re-pick.
// Env is process state: nextest runs every test in its own process.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_broken_handoff_fails_the_boot_before_any_listener_comes_up() {
    use std::net::Ipv4Addr;

    use crate::guest;

    // A present token that carries no port: the surfaced error, not a
    // quiet absence.
    unsafe { std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, "no-port-here") };
    let error = guest::handed_proxy_port()
        .expect_err("an unusable token is a surfaced boot error, not an absence");
    assert_eq!(error.token, guest::HANDED_PROXY_PORT_TOKEN);
    assert_eq!(error.value, "no-port-here");

    // A handed port something already holds — the way a stale daemon or
    // an unrelated process in the guest holds one: the probe bind fails
    // it, with the port named, and that is the boot's end.
    let held_listener = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let held = held_listener.local_addr().unwrap().port();
    unsafe { std::env::set_var(guest::HANDED_PROXY_PORT_TOKEN, held.to_string()) };
    let proxy = guest::handed_proxy_port().unwrap();
    assert_eq!(proxy, Some(held));
    let error = guest::probe_handed_node_port(proxy)
        .expect_err("a held handed port cannot bind for the probe");
    assert!(
        error.to_string().contains(&held.to_string()),
        "the boot-fatal bind names the port it failed on, got: {error}"
    );

    // And no listener ever comes up from it: the startup pid-1 would
    // drive next, driven here, keeps retrying the held handed port and
    // never re-picks — the boot was over before it.
    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let drive = crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base: std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: ProxyPort::from_config(
                guest::handed_proxy_port().unwrap(),
                crate::net::proxy::DEFAULT_EGRESS_PROXY_PORT,
            ),
        },
        RetryBackoff::new(Duration::from_millis(10), Duration::from_millis(50)),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !drive.is_finished(),
        "the held handed port is retried, not abandoned"
    );
    assert_eq!(
        state.hostname_proxy_port().await,
        None,
        "a boot that failed its probe bind never publishes a listener"
    );
    drive.abort();
    drop(held_listener);
}

/// NET-024: a daemon configured with a hostname-proxy port listens on
/// exactly that one — driven through the start path [`Server::run`] takes,
/// so the flags a deployment passes are the ones proven. The startup
/// binds the port rather than re-picking, both listeners' discovery
/// fields (the proxy's and the answerer's) carry the configured ports to
/// the RPC replies a client reads, the startup lines name the ports as
/// configured, the proxy answers on that port — refusing a name no live
/// box owns and routing one a live box owns — and the answerer replies
/// from the port the host resolver would be pointed at.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn proxy_listens_on_configured_port() {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::RecordType;
    use minimald_rpc::ListSessions;

    use crate::net::answerer::encode_query;

    // Reserve free ports, then hand them to the daemon the way a pinned
    // deployment does: unheld, for its own binds.
    let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let answerer_port = probe.local_addr().unwrap().port();
    drop(probe);

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let (state, run, sock) = spawn_stateful_server_with(
        &dir,
        Config {
            hostname_proxy_port: Some(port),
            zone_answerer_port: Some(answerer_port),
            ..test_config(&dir)
        },
    )
    .await;

    // The daemon reports its listeners once they are up — that report is
    // the discovery path a client takes, so this poll is the proof the
    // ports are the configured ones.
    let mut client = connect_uds(&sock).await;
    let resp = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let resp = client.call::<ListSessions>(&()).await;
            if resp.hostname_proxy_port.is_some() && resp.zone_answerer_port.is_some() {
                return resp;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the daemon must report its listeners on the list reply");
    assert_eq!(
        resp.hostname_proxy_port,
        Some(port),
        "a configured port must be listened on, not re-picked"
    );
    assert_eq!(
        resp.zone_answerer_port,
        Some(answerer_port),
        "the answerer's configured port must be listened on, not re-picked"
    );

    // And it really is a listener there: the proxy answers on the
    // configured port (refusing a name no live box owns, which is its
    // answer for one), and the answerer replies over UDP from the same
    // port the resolver would be pointed at.
    let routed = proxy_get(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        "ghost.min.internal",
    )
    .await;
    assert!(
        routed.contains("502"),
        "the configured port must answer, got: {routed}"
    );

    let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let query = encode_query("ghost.min.internal.", RecordType::A);
    let mut scratch = [0u8; 512];
    let mut reply = None;
    for _ in 0..200 {
        client
            .send_to(
                &query,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), answerer_port),
            )
            .await
            .unwrap();
        if let Ok(Ok((bytes, _))) =
            tokio::time::timeout(Duration::from_millis(25), client.recv_from(&mut scratch)).await
        {
            reply = Some(scratch[..bytes].to_vec());
            break;
        }
    }
    let bytes = reply.expect("the answerer must answer on its configured port");
    let message = Message::from_vec(&bytes).expect("the reply decodes");
    assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        message.answers.is_empty(),
        "a name no live box owns must answer NXDOMAIN, got: {bytes:?}"
    );

    // And a name a live box owns routes with a 200 through the same
    // configured port — the refusal above only means something once a
    // routed name is proved beside it.
    let backend = spawn_backend_saying("live").await;
    state
        .sessions_manager()
        .await
        .hostnames()
        .write()
        .unwrap()
        .register_host_net(::boxes::SessionId::nil(), "web");
    let authority = format!("web.min.internal:{backend}");
    let routed = proxy_get(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        &authority,
    )
    .await;
    assert!(
        routed.contains("200 OK"),
        "the configured port must route a live name, got: {routed}"
    );

    let logged = buf.contents();
    assert!(
        logged.contains(&format!("port={port}")),
        "the startup line must name the port, got: {logged}"
    );
    assert!(
        logged.contains(r#"port_source="configured""#),
        "the startup line must say the port was configured, got: {logged}"
    );
    run.abort();
}

/// NET-025: a daemon started without a configured port takes the
/// documented default when it is free — and only when something on the
/// host already holds it asks the OS for a free one, reporting the port it
/// got. That is what lets a second daemon on the same host keep its names
/// instead of silently losing routing: it relocates, it does not fail.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn proxy_auto_selects_free_port() {
    use std::net::{IpAddr, Ipv4Addr};

    // Hold the "default" so the fallback is observable: the daemon's
    // first bind must fail, its second must land elsewhere. An OS-picked
    // port this process owns, not the documented one: the `Server::run`
    // tests beside this one bind the real default in their own
    // processes, and one could release it between a failed hold here and
    // the proxy's bind, which would then take the default.
    let held = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let default = held.local_addr().unwrap().port();

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    // The native startup shape `start_host_proxies` spawns, with the
    // held port as the default.
    crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: ProxyPort::DefaultThenSelect { default },
        },
        RetryBackoff::production(),
    ));

    let bound = wait_for_proxy_port(&state).await;
    assert_ne!(bound, 0, "port 0 is a request for a port, not an answer");
    assert_ne!(
        bound, default,
        "a busy default must not be waited on or taken"
    );
    assert!(
        state.proxy_unavailable().await.is_none(),
        "a relocated default must not report the proxy unavailable"
    );

    // The picked port is a real listener, the relocation is said out
    // loud, and the startup line reports the port as selected.
    let backend = spawn_backend_saying("selected").await;
    state
        .sessions_manager()
        .await
        .hostnames()
        .write()
        .unwrap()
        .register_host_net(::boxes::SessionId::nil(), "web");
    let authority = format!("web.min.internal:{backend}");
    let routed = proxy_get(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound),
        &authority,
    )
    .await;
    assert!(
        routed.contains("200 OK"),
        "the selected port must route a name, got: {routed}"
    );

    let logged = buf.contents();
    assert!(
        logged.contains("the default hostname-proxy port is busy"),
        "the busy default must be reported as the reason the daemon moved, got: {logged}"
    );
    assert!(
        logged.contains(&format!("port={bound}")),
        "the startup line must name the port, got: {logged}"
    );
    assert!(
        logged.contains(r#"port_source="selected""#),
        "the startup line must say the port was selected, got: {logged}"
    );
    drop(held);
}

/// NET-024's hard edge: a daemon *configured* with a port that is busy
/// keeps retrying it with backoff rather than relocating — the operator
/// named the port, and moving the listener would hide the loss the
/// report is there to surface.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_busy_configured_port_is_not_relocated() {
    use std::net::{IpAddr, Ipv4Addr};

    // A free port this test holds for its whole lifetime: the daemon is
    // configured with it, and its bind must fail on it — deterministically,
    // whatever else on the box holds the documented default.
    let held = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let configured = held.local_addr().unwrap().port();

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let retrier = crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            bind_base: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: ProxyPort::Pinned(configured),
        },
        RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
    ));

    // The bind keeps failing on the *same* address — no relocation line,
    // and the note stays, because a pinned port is the operator's to fix.
    let mut saw_two_failures = false;
    for _ in 0..200 {
        if buf
            .contents()
            .matches("could not bind its listener")
            .count()
            >= 2
        {
            saw_two_failures = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        saw_two_failures,
        "a busy configured port must keep failing loudly, got: {}",
        buf.contents()
    );
    assert!(
        !buf.contents().contains("selecting a free one"),
        "a configured port must not be relocated, got: {}",
        buf.contents()
    );
    assert!(
        state.proxy_unavailable().await.is_some(),
        "the busy configured port must stay reported as unavailable"
    );
    retrier.abort();
    drop(held);
}

/// NET-025's other edge: only a *busy* address relocates. Any other bind
/// failure keeps the address it named and retries with backoff (NET-021),
/// because it is not another daemon holding the port and moving the
/// listener would hide the report. Driven with an address the host cannot
/// assign — the shape a half-up or misconfigured interface gives — which
/// fails with `EADDRNOTAVAIL` under glibc and musl alike, so this also
/// holds for the musl guest build the busy-port predicate once missed.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_non_busy_bind_failure_keeps_its_address() {
    use std::net::{IpAddr, Ipv4Addr};

    // A free port stands in for the documented default, as in the other
    // retry tests: what fails here is the address, not the port.
    let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let default_port = probe.local_addr().unwrap().port();
    drop(probe);

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let retrier = crate::traced::spawn(drive_proxy_until_serving(
        state.clone(),
        HostProxyStartup::Egress {
            // `192.0.2.1` is TEST-NET-1: no interface holds it, so every
            // bind fails `EADDRNOTAVAIL`, deterministically, root or not.
            bind_base: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: ProxyPort::DefaultThenSelect {
                default: default_port,
            },
        },
        RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
    ));

    // At least two failed binds on the *same* address — no relocation
    // line, and the note stays, because the failure is not a busy port.
    let mut saw_two_failures = false;
    for _ in 0..200 {
        if buf
            .contents()
            .matches("could not bind its listener")
            .count()
            >= 2
        {
            saw_two_failures = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let logged = buf.contents();
    assert!(
        saw_two_failures,
        "a non-busy bind failure must keep retrying loudly, got: {logged}"
    );
    assert!(
        !logged.contains("selecting a free one"),
        "a bind failure that is not a busy port must not relocate, got: {logged}"
    );
    assert!(
        logged
            .matches(&format!("addr=192.0.2.1:{default_port}"))
            .count()
            >= 2,
        "the retries must keep the address the report names, got: {logged}"
    );
    assert!(
        state.proxy_unavailable().await.is_some(),
        "the bind failure must stay reported as unavailable"
    );
    assert!(
        state.hostname_proxy_port().await.is_none(),
        "a proxy that never bound must not report serving"
    );
    retrier.abort();
}

/// NET-002 beside NET-027: the registry a daemon builds — through its
/// generated instance id, the way [`crate::ServerState::new`] builds it —
/// still answers the `local` zone every daemon promised before instance
/// ids existed, beside its own instance's zone.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn local_zone_routes_on_an_instance_scoped_registry() {
    use ::boxes::SessionId;

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let id = state.daemon_id().await;
    assert_ne!(
        id, "local",
        "a daemon's instance id is its own, not the shared label"
    );

    let registry = state.sessions_manager().await.hostnames();
    registry
        .write()
        .unwrap()
        .register_host_net(SessionId::nil(), "web");

    // The two-label name, the instance's own three-label zone, and the
    // `local` zone a pre-instance name lives in all route; another
    // daemon's zone does not, and neither does an unknown session under
    // any of them.
    let read = registry.read().unwrap();
    assert!(read.resolve("web.min.internal:8080").is_some());
    assert!(
        read.resolve(&format!("web.{id}.min.internal:8080"))
            .is_some()
    );
    assert!(
        read.resolve("web.local.min.internal:8080").is_some(),
        "the local zone must keep routing on every daemon"
    );
    assert!(read.resolve("ghost.local.min.internal:8080").is_none());
    assert!(read.resolve("ghost.min.internal:8080").is_none());
}

/// NET-027: two daemons on one machine route both sets of names at the
/// same time — including, each, the `local` zone NET-002 promised (which
/// is a per-daemon zone now, answered from that daemon's own
/// registration). The daemons are shaped the way two on one host really
/// are: VM hosts (`in_microvm`), each box published on its own address,
/// so both publish the **same** port and carry the **same** Host header —
/// the only things that pick a backend are the name and which daemon's
/// proxy the request goes through.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn two_daemons_route_hostnames_concurrently() {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use ::boxes::SessionId;

    // `in_microvm` is what makes a daemon's registry route an own-IP box
    // to its reported address (a lease on the switch) rather than to the
    // one loopback address every native box would share — the shape two
    // daemons must take to publish the same port at the same time.
    let vm_host = |dir: &TempDir| Config {
        in_microvm: true,
        ..test_config(dir)
    };
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let a = ServerStateHandle::new(vm_host(&dir_a), None).await.unwrap();
    let b = ServerStateHandle::new(vm_host(&dir_b), None).await.unwrap();

    // Two daemon instances: distinct ids, or the names they mint below
    // would not be distinct either.
    let id_a = a.daemon_id().await;
    let id_b = b.daemon_id().await;
    assert_ne!(id_a, id_b, "two daemon instances must mint two host ids");

    // Neither daemon was configured with a port, so each drives its own
    // startup and ends up on its own.
    let auto = || SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let compressed = RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20));
    let (_, _) = tokio::join!(
        retry_hostname_proxy_until_serving(a.clone(), auto(), compressed),
        retry_hostname_proxy_until_serving(b.clone(), auto(), compressed),
    );
    let port_a = wait_for_proxy_port(&a).await;
    let port_b = wait_for_proxy_port(&b).await;
    assert_ne!(port_a, port_b, "two daemons must not land on one port");

    // Each daemon's `web` box, published at its own address on the same
    // port — the two "leases" the attach path would report. The external
    // port is 80 (a `Host:` header with no port routes as 80) and both
    // publish the same one: which box answers is decided by the name and
    // the proxy alone.
    let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let published = probe.local_addr().unwrap().port();
    drop(probe);
    let lease_a = Ipv4Addr::new(127, 0, 0, 1);
    let lease_b = Ipv4Addr::new(127, 0, 0, 2);
    spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_a), published), "daemon-a").await;
    spawn_backend_on(SocketAddr::new(IpAddr::V4(lease_b), published), "daemon-b").await;

    let registry_a = a.sessions_manager().await.hostnames();
    let registry_b = b.sessions_manager().await.hostnames();
    registry_a.write().unwrap().report_own_address(
        SessionId::nil(),
        "web",
        lease_a,
        BTreeMap::from([(80, published)]),
    );
    registry_b.write().unwrap().report_own_address(
        SessionId::nil(),
        "web",
        lease_b,
        BTreeMap::from([(80, published)]),
    );

    // The two daemons' registries do not see each other's instance
    // zones — each answers its own instance's three-label form (and the
    // shared two-label and `local` forms, each from its own
    // registration), and not the other daemon's.
    let own_a = format!("web.{id_a}.min.internal");
    let own_b = format!("web.{id_b}.min.internal");
    assert!(
        registry_a.read().unwrap().resolve(&own_a).is_some(),
        "daemon A must answer its own instance's name"
    );
    assert!(
        registry_a.read().unwrap().resolve(&own_b).is_none(),
        "daemon A must not answer daemon B's name"
    );
    assert!(
        registry_b.read().unwrap().resolve(&own_b).is_some(),
        "daemon B must answer its own instance's name"
    );
    assert!(
        registry_b.read().unwrap().resolve(&own_a).is_none(),
        "daemon B must not answer daemon A's name"
    );

    // Both sets of names route at the same time, decided by the Host
    // header alone: the same authority through each daemon's proxy
    // reaches that daemon's own box, concurrently — and the deprecated
    // three-label forms (instance's own, and `local`) route to it too,
    // while the *other* daemon's instance form is refused with a 502
    // (the proxy serves it: "no live box owns this host").
    let proxy_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a);
    let proxy_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_b);
    let (a_two_label, a_local, a_own, a_foreign, b_two_label, b_local, b_own, b_foreign) = tokio::join!(
        proxy_get(proxy_a, "web.min.internal"),
        proxy_get(proxy_a, "web.local.min.internal"),
        proxy_get(proxy_a, &own_a),
        proxy_get(proxy_a, &own_b),
        proxy_get(proxy_b, "web.min.internal"),
        proxy_get(proxy_b, "web.local.min.internal"),
        proxy_get(proxy_b, &own_b),
        proxy_get(proxy_b, &own_a),
    );
    assert!(a_two_label.contains("daemon-a"), "got: {a_two_label}");
    assert!(a_local.contains("daemon-a"), "got: {a_local}");
    assert!(a_own.contains("daemon-a"), "got: {a_own}");
    assert!(b_two_label.contains("daemon-b"), "got: {b_two_label}");
    assert!(b_local.contains("daemon-b"), "got: {b_local}");
    assert!(b_own.contains("daemon-b"), "got: {b_own}");
    assert!(
        a_foreign.contains("502"),
        "daemon A must refuse daemon B's instance name, got: {a_foreign}"
    );
    assert!(
        b_foreign.contains("502"),
        "daemon B must refuse daemon A's instance name, got: {b_foreign}"
    );
}

/// NET-027's switch half beside NET-010's address half: two daemons on
/// one machine take two different switch /24s — the pinned pair here, 37
/// and 52 — while the addresses their published boxes are granted from
/// are the *same* host-wide pool, the reserved local range the answerer's
/// lease record arbitrates (design §7.1). Each daemon's start line
/// carries both facts, so a reader of two daemons' logs (a diagnostics
/// bundle tails exactly this log) sees what distinguishes them — the
/// switch — and what cannot distinguish them: the pool is the host's,
/// never the daemon's, so no octet pair, congruent modulo the slice
/// count of the carve this line replaced or otherwise, can hand two
/// daemons one address between them.
///
/// The `in_microvm: true` daemon keeps the host's default /16 whatever
/// octet it was pinned to (it does not own its switch) and still draws
/// its published addresses from the same one pool.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn two_daemons_log_one_host_wide_loopback_pool() {
    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // Two daemons pinned onto different /24s of the host switch, through
    // `Server::run` the way a deployment starts them.
    let dir_a = TempDir::new().unwrap();
    let (run_a, _sock_a) = spawn_server_with(
        &dir_a,
        Config {
            switch_subnet_octet: Some(37),
            ..test_config(&dir_a)
        },
    );
    let dir_b = TempDir::new().unwrap();
    let (run_b, _sock_b) = spawn_server_with(
        &dir_b,
        Config {
            switch_subnet_octet: Some(52),
            ..test_config(&dir_b)
        },
    );
    // A VM daemon on the first pinned octet: the octet does not reach
    // its switch (the host gvproxy's /16 stays), and its published
    // addresses come from the same pool as both native daemons'.
    let dir_c = TempDir::new().unwrap();
    let state_c = ServerStateHandle::new(
        Config {
            in_microvm: true,
            switch_subnet_octet: Some(37),
            ..test_config(&dir_c)
        },
        None,
    )
    .await
    .unwrap();

    // The start lines are logged as each daemon comes up; wait for all
    // three before reading the pool back out of them.
    let logged = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let logged = buf.contents();
            if logged.matches("reserved_loopback=").count() >= 3 {
                return logged;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all three daemons must log the pool their published boxes come from");

    // Each daemon's start line, found by the field that identifies the
    // daemon: the configured /24 for the two pinned ones, the host's /16
    // for the VM one.
    let id_c = state_c.daemon_id().await;
    let line_of = |marker: &str| {
        logged
            .lines()
            .find(|line| line.contains(marker) && line.contains("reserved_loopback="))
            .unwrap_or_else(|| panic!("no start line carrying {marker}, got: {logged}"))
            .to_owned()
    };
    let line_a = line_of("subnet=100.64.37.0/24");
    let line_b = line_of("subnet=100.64.52.0/24");
    let line_c = line_of("subnet=100.64.0.0/16");
    assert!(
        line_c.contains(&format!("daemon_id={id_c}")),
        "the /16 line is the VM daemon's own, got: {line_c}"
    );

    // Every daemon's line carries the same one pool: the answerer's
    // whole grantable range, first address to last, never a per-daemon
    // carve of it.
    for line in [&line_a, &line_b, &line_c] {
        assert!(
            line.contains("reserved_loopback=127.0.64.2-127.0.64.254"),
            "a daemon's published boxes come from this host's one pool, got: {line}"
        );
    }
    // And what distinguishes the daemons is their switches, not their
    // pools: two different /24s for the pinned pair.
    assert_ne!(
        line_a, line_b,
        "two daemons pinned to different octets take different switches"
    );

    run_a.abort();
    run_b.abort();
}

/// NET-027: the /24 a daemon's id derives is stable — the same id names
/// the same /24 start after start — and distinct ids name distinct ones
/// often enough that two daemons on a host do not meet on one /24 by
/// accident. Every derived octet stays inside the `100.64/16`: never
/// the `0` of the /16's own gateway /24 nor the `255` of its host-alias
/// and daemon-address /24, which the host switch keeps for itself.
#[cfg(target_os = "linux")]
#[test]
fn derived_switch_octets_are_stable_and_in_range() {
    assert_eq!(octet_for_daemon_id("abc12"), 21);
    assert_eq!(
        octet_for_daemon_id("abc12"),
        21,
        "derivation must be stable"
    );
    assert_ne!(
        octet_for_daemon_id("abc12"),
        octet_for_daemon_id("abc13"),
        "near ids must not collapse onto one /24"
    );
    for id in ["aaaaa", "abc12", "abc13", "x9y8z", "zzzzz"] {
        let octet = octet_for_daemon_id(id);
        assert!(
            (1..=254).contains(&octet),
            "{id} derived {octet}, which is outside 1..=254"
        );
    }
}

/// A native daemon's switch octet is stable across restarts: the
/// identity is persisted under the state root on first start and read
/// back on subsequent starts, so the derived /24 stays the same. Each
/// "start" uses its own lock dir, since the first start's lock is held
/// for the life of this test process.
#[cfg(target_os = "linux")]
#[test]
fn native_switch_octet_is_stable_across_restarts() {
    let dir = TempDir::new().unwrap();
    let state_dir = DaemonAbsPath::try_new(
        camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
    )
    .unwrap();
    let start = |state_dir: &DaemonAbsPath| {
        let locks = TempDir::new().unwrap();
        let identity = load_or_create_daemon_identity(state_dir).unwrap();
        resolve_switch_octet(Some(locks.path()), &identity)
    };
    let first = start(&state_dir);
    let second = start(&state_dir);
    assert_eq!(
        first, second,
        "the switch octet must be stable across restarts"
    );
    assert!(
        (1..=254).contains(&first),
        "derived octet {first} is outside 1..=254"
    );
}

/// An empty identity file is regenerated and persisted rather than
/// sending every start to the per-start fallback.
#[test]
fn empty_daemon_identity_file_is_regenerated() {
    let dir = TempDir::new().unwrap();
    let state_dir = DaemonAbsPath::try_new(
        camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
    )
    .unwrap();
    let path = dir.path().join(DAEMON_IDENTITY_FILE);
    std::fs::write(&path, "  \n").unwrap();
    let identity = load_or_create_daemon_identity(&state_dir).unwrap();
    assert!(!identity.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), identity);
    assert_eq!(
        load_or_create_daemon_identity(&state_dir).unwrap(),
        identity
    );
}

/// Two daemons on one machine that derive the same octet end up on
/// different blocks: the first holds the per-octet lock, so the second
/// re-derives.
#[cfg(target_os = "linux")]
#[test]
fn colliding_daemons_end_up_on_different_octets() {
    let locks = TempDir::new().unwrap();
    let first = resolve_switch_octet(Some(locks.path()), "same-identity");
    let second = resolve_switch_octet(Some(locks.path()), "same-identity");
    assert_eq!(first, octet_for_daemon_id("same-identity"));
    assert_ne!(
        first, second,
        "a daemon whose octet is already held must re-derive to a different one"
    );
}

/// A microVM daemon never persists an identity: its octet is always
/// derived from the per-start id, because the guest does not own its
/// switch.
#[cfg(target_os = "linux")]
#[test]
fn microvm_daemon_never_persists_identity() {
    let dir = TempDir::new().unwrap();
    let state_dir = DaemonAbsPath::try_new(
        camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap(),
    )
    .unwrap();
    let first = native_switch_octet(true, Some(&state_dir), "per-start-id");
    let second = native_switch_octet(true, Some(&state_dir), "different-per-start-id");
    assert_ne!(
        first, second,
        "a microVM daemon must derive its octet from the per-start id, not a persisted identity"
    );
    // The identity file must not have been written.
    let identity_path = state_dir
        .as_utf8_path()
        .as_std_path()
        .join(DAEMON_IDENTITY_FILE);
    assert!(
        !identity_path.exists(),
        "a microVM daemon must not persist a daemon identity"
    );
}

/// NET-027: a configured third octet places the daemon's switch /24
/// inside the host gvproxy's `100.64/16`, where its leases stay valid
/// beside the host's own gateway, host-alias, and PTask reservations.
#[cfg(target_os = "linux")]
#[test]
fn a_configured_octet_places_the_switch_inside_the_host_s_16() {
    let subnet = switch_subnet_for_octet(200);
    assert_eq!(subnet.to_string(), "100.64.200.0/24");
    let octets = subnet.network().octets();
    assert_eq!(&octets[..2], &[100, 64], "the /24 must stay in 100.64/16");
    assert_eq!(octets[3], 0, "a /24's network address ends in 0");
}

/// The other half of the ownership rule [`switch_subnet_for`] states —
/// the half the macOS e2e caught: a daemon in a microVM does not own its
/// gvproxy (it attaches its boxes' taps to the one `minvmd` runs on the
/// host, whose config renders the default /16), so the guest must carry
/// that switch's subnet, never derive a /24 of its own. Every address a
/// guest daemon derives from its switch must be one that switch answers
/// at: the gateway is where a box's default route and DNS server live
/// (a host-address box's resolver is the switch's DNS server, an
/// own-IP box's tap carries the subnet's gateway and netmask), and a
/// derived /24's gateway — `100.64.<octet>.1` — is an address no
/// gvproxy answers, so every box in the VM lost egress, DNS first.
/// Read off the daemon's own start line, which names the subnet its
/// switch carries, with an octet pinned to show the pin cannot move a
/// switch the guest does not own.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_microvm_daemon_attaches_to_the_host_switch_s_own_subnet() {
    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(
        Config {
            in_microvm: true,
            switch_subnet_octet: Some(37),
            ..test_config(&dir)
        },
        None,
    )
    .await
    .unwrap();

    let id = state.daemon_id().await;
    let logged = buf.contents();
    let line = logged
        .lines()
        .find(|l| l.contains("reserved_loopback=") && l.contains(&format!("daemon_id={id}")))
        .unwrap_or_else(|| panic!("no start line for daemon {id}, got: {logged}"));
    assert!(
        line.contains("subnet=100.64.0.0/16"),
        "a microVM daemon must carry the host gvproxy's /16, got: {line}"
    );

    // The mapping's native arms beside it: a native daemon honors the
    // pin — it renders its own gvproxy's config — and an unpinned one
    // derives its /24 from its instance id (NET-027).
    assert_eq!(
        switch_subnet_for(false, 37).to_string(),
        "100.64.37.0/24",
        "a pinned native daemon owns its switch and takes the pinned /24"
    );
    assert_eq!(
        switch_subnet_for(false, octet_for_daemon_id(&id)),
        switch_subnet_for_octet(octet_for_daemon_id(&id)),
        "an unpinned native daemon derives its own /24"
    );
    // The published-address half the octet no longer touches: the pool a
    // daemon's boxes are granted from is the host's one pool, the same
    // for a VM daemon as for every native one, whatever octet either
    // carries (NET-010 — allocation is the answerer's, never the
    // daemon's).
    assert!(
        line.contains("reserved_loopback=127.0.64.2-127.0.64.254"),
        "a daemon's published boxes come from this host's one pool, \
         got: {line}"
    );
    // And the address that broke the e2e follows: the /16's gateway is
    // where the host gvproxy answers DNS, and a native /24's is inside
    // the /16's span but is no switch's address.
    assert_eq!(
        crate::net::DEFAULT_SUBNET.dns_server().to_string(),
        "100.64.0.1",
        "the host switch's /16 answers DNS at its own gateway"
    );
}

/// The box-zone answerer starts beside the hostname proxy and serves the
/// zone on loopback (NET-009): `drive_answerer_until_serving` binds the
/// address, the log names the listener's address and port at start, and a
/// real UDP exchange over the bound socket answers a box name with its
/// local address.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn answerer_starts_and_serves_the_zone_on_loopback() {
    use std::net::{IpAddr, Ipv4Addr};

    use ::boxes::SessionId;
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, RecordType};

    use crate::net::answerer::{AnswerScope, ZoneAnswerer, encode_query};

    // A free port, handed to the driver the way startup hands it a fixed
    // one: bound and dropped, uncontended in a test binary.
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let hostnames = state.sessions_manager().await.hostnames();
    hostnames
        .write()
        .expect("registry lock")
        .register_host_net(SessionId::nil(), "web");

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let answerer = ZoneAnswerer::new(hostnames, AnswerScope::Native);
    crate::traced::spawn(drive_answerer_until_serving(
        state.clone(),
        answerer,
        addr.ip(),
        ProxyPort::Pinned(port),
        RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
    ));

    // Poll until the driver's bind lands, then do one real exchange.
    let client = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let query = encode_query("web.min.internal.", RecordType::A);
    let mut scratch = [0u8; 512];
    let mut reply = None;
    for _ in 0..200 {
        client.send_to(&query, addr).await.unwrap();
        if let Ok(Ok((bytes, _))) =
            tokio::time::timeout(Duration::from_millis(25), client.recv_from(&mut scratch)).await
        {
            reply = Some(scratch[..bytes].to_vec());
            break;
        }
    }
    let bytes = reply.expect("the answerer must answer once the driver binds it");
    let reply = Message::from_vec(&bytes).expect("the reply decodes");
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    let [answer] = &reply.answers[..] else {
        panic!("an A lookup on a held name answers once")
    };
    let RData::A(A(address)) = &answer.data else {
        panic!("the answer is an A record")
    };
    assert_eq!(*address, Ipv4Addr::LOCALHOST);

    // The daemon log names the answerer's listener address and port, the
    // state records the port for the discovery replies to carry, and the
    // serving line says who chose it.
    let logged = buf.contents();
    assert!(
        logged.contains("zone-answerer") && logged.contains(&format!("{addr}")),
        "the answerer's start must name its listener, got: {logged}"
    );
    assert!(
        logged.contains(r#"port_source="configured""#),
        "the answerer's serving line must name its port source, got: {logged}"
    );
    let reported = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if state.zone_answerer_port().await == Some(port) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        reported.is_ok(),
        "the answerer's bound port must be recorded on the state, got: {logged}"
    );
}

/// The answerer shares the hostname proxy's port policy (NET-025): a
/// busy default is relocated — loudly — rather than failed, and the
/// relocated port is the one the discovery field reports as selected.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn answerer_relocates_when_its_default_port_is_busy() {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::net::answerer::{AnswerScope, ZoneAnswerer};

    // Hold the "default" for the whole test: an OS-picked port this
    // process owns, not the documented one. The `Server::run` tests
    // beside this one bind the real defaults in their own processes, so
    // a hold on the documented port could fail while another process
    // held it, and that process could release it before the answerer's
    // bind, which would then take the default.
    let held = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let default = held.local_addr().unwrap().port();

    let buf = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let hostnames = state.sessions_manager().await.hostnames();
    let answerer = ZoneAnswerer::new(hostnames, AnswerScope::Native);
    crate::traced::spawn(drive_answerer_until_serving(
        state.clone(),
        answerer,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        ProxyPort::DefaultThenSelect { default },
        RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(20)),
    ));

    let reported = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(port) = state.zone_answerer_port().await {
                return port;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the answerer must relocate and report its port");
    assert_ne!(
        reported, default,
        "a busy default must not be waited on or taken"
    );

    let logged = buf.contents();
    assert!(
        logged.contains("the default zone-answerer port is busy"),
        "the busy default must be reported as the reason the answerer moved, got: {logged}"
    );
    assert!(
        logged.contains(r#"port_source="selected""#),
        "the serving line must say the port was selected, got: {logged}"
    );
    drop(held);
}

/// A vsock-shaped listener a test feeds: each accept hands back the next
/// queued stream with the peer address the test chose, so a test can stand
/// a peer at any CID without a VM. It refuses peers exactly as the real
/// vsock listener does, through that listener's own `refused_cid`.
#[cfg(target_os = "linux")]
struct FedVsockListener {
    queued: tokio::sync::Mutex<
        tokio::sync::mpsc::UnboundedReceiver<(tokio::io::DuplexStream, tokio_vsock::VsockAddr)>,
    >,
}

#[cfg(target_os = "linux")]
impl Listener for FedVsockListener {
    type Stream = tokio::io::DuplexStream;
    type Addr = tokio_vsock::VsockAddr;

    const TRANSPORT: &'static str = "vsock";
    const IS_LOCAL: bool = true;

    async fn accept(&self) -> std::io::Result<(Self::Stream, Self::Addr)> {
        match self.queued.lock().await.recv().await {
            Some(accepted) => Ok(accepted),
            None => std::future::pending().await,
        }
    }

    fn refused_cid(peer: &Self::Addr) -> Option<u32> {
        <tokio_vsock::VsockListener as Listener>::refused_cid(peer)
    }
}

/// NET-139: the in-VM daemon's vsock RPC listener serves only the host. A
/// peer at any other CID (here a sibling at CID 3 and the guest's own
/// loopback at CID 1) is dropped at accept. The daemon never sends it the
/// SSH banner and never reads what it wrote. One audited line names the
/// CID. A peer at CID 2 is served as before.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn vsock_rpc_refuses_non_host_cid() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    assert!(vsock_peer_refused(1), "the guest's loopback CID is refused");
    assert!(vsock_peer_refused(3), "a sibling CID is refused");
    assert!(
        !vsock_peer_refused(tokio_vsock::VMADDR_CID_HOST),
        "the host's CID is served"
    );

    let capture = crate::test_harness::captured_log();
    let dir = TempDir::new().unwrap();
    let state = ServerStateHandle::new(test_config(&dir), None)
        .await
        .unwrap();
    let (feed, queued) = tokio::sync::mpsc::unbounded_channel();
    let listener = FedVsockListener {
        queued: tokio::sync::Mutex::new(queued),
    };
    let run = tokio::spawn(Server::serve(state, listener));

    for cid in [3, 1] {
        let (mut peer, served) = tokio::io::duplex(4096);
        // The peer speaks first. A refusal at accept must not read it.
        peer.write_all(b"SSH-2.0-not-the-host\r\n").await.unwrap();
        feed.send((served, tokio_vsock::VsockAddr::new(cid, 22)))
            .unwrap();
        let mut heard = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), peer.read_to_end(&mut heard))
            .await
            .expect("a refused peer's connection is closed at once");
        assert!(
            read.is_ok() && heard.is_empty(),
            "a peer at CID {cid} hears nothing before its connection closes: {heard:?}"
        );
    }

    let (mut host, served) = tokio::io::duplex(4096);
    feed.send((
        served,
        tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, 22),
    ))
    .unwrap();
    let mut banner = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), host.read_exact(&mut banner))
        .await
        .expect("the host is answered")
        .expect("the host reads the daemon's SSH banner");
    assert_eq!(&banner, b"SSH-", "the host's connection is served");

    let log = capture.contents();
    for cid in [3, 1] {
        assert!(
            log.contains(&format!("peer_cid={cid}")) && log.contains("audit=true"),
            "the refusal of CID {cid} is one audited line naming it: {log}"
        );
    }
    assert!(
        !log.contains("peer_cid=2"),
        "the host's CID is never refused: {log}"
    );
    run.abort();
}

/// NET-139's rate limit: the first refusal of a CID writes the line, the
/// refusals inside its window are counted and not written, and the first
/// refusal after the window writes a line that covers them all.
#[test]
fn refused_peer_line_is_rate_limited_per_cid() {
    // A CID no other test refuses: the limiter is process-wide.
    let cid = 0xdead_beef;
    let start = std::time::Instant::now();
    assert_eq!(peer_refusal_due(cid, start), Some(1));
    assert_eq!(peer_refusal_due(cid, start + Duration::from_secs(1)), None);
    assert_eq!(peer_refusal_due(cid, start + Duration::from_secs(2)), None);
    assert_eq!(
        peer_refusal_due(cid, start + PEER_REFUSAL_LOG_INTERVAL),
        Some(3),
        "the next line counts the refusals its window suppressed"
    );
}
