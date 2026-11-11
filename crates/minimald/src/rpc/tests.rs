use boxes::{NetworkMode, SessionId};
use minimald_rpc::{
    BoxPolicy, CreateSession, CreateSessionRequest, DestroySessionRequest, EffectiveBoxPolicy,
    EffectiveEgress, EgressPolicy, GetEffectiveSessionPolicy, GetEffectiveSessionPolicyRequest,
    GetSessionPolicy, GetSessionPolicyRequest, IngressPolicy, IpProto, PortMapping,
    RenameSessionRequest, Shutdown, ShutdownRequest, ShutdownResponse,
};
use paths::HostAbsPath;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::MINIMAL_SESSION_ID_ENV;
use crate::box_manager::BoxKeyPredicate;
use crate::net::loopback::PROBE_TEST_MUTEX;
use crate::test_harness::{TestClient, TestServer};

/// Serializes `(path, contents)` entries into a tar archive and
/// zstd-compresses it, producing exactly the wire format that
/// [`serve_stream_workspace_files`] decodes.
async fn tar_zst(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = async_tar::Builder::new(Vec::new());
    for (path, contents) in entries {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        tar.append_data(&mut header, path, *contents).await.unwrap();
    }
    let tar_bytes = tar.into_inner().await.unwrap();

    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder.write_all(&tar_bytes).await.unwrap();
    encoder.shutdown().await.unwrap();
    encoder.into_inner()
}

use crate::test_harness::create_session_req as req;

/// Creates a session through the public RPCs and returns its id, ready
/// to attach.
async fn fresh_session(client: &mut TestClient) -> SessionId {
    crate::test_harness::create_configured_session(client, "stream-test", "/tmp").await
}

#[tokio::test]
async fn stream_workspace_files_unpacks_tarball_into_workspace() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // Bare `CreateSession`: the workspace upload belongs to the create
    // flow, between the create and the `ConfigureLoadout`.
    let session_id = client
        .call::<CreateSession>(&req("stream-test", "/tmp"))
        .await
        .unwrap()
        .id;

    let payload = tar_zst(&[
        ("hello.txt", b"hello world\n"),
        ("dir/nested.txt", b"nested contents"),
    ])
    .await;

    let channel = client
        .open_subsystem(
            STREAM_WORKSPACE_FILES,
            &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
        )
        .await;
    let mut stream = channel.into_stream();
    stream.write_all(&payload).await.unwrap();
    // Half-close so the server's decoder sees EOF; then read to the
    // server's channel close so the unpack has completed on-disk
    // before we assert.
    stream.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    stream.read_to_end(&mut trailing).await.unwrap();

    let mngr = server.state.sessions_manager().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("freshly-created session should be retrievable");
    let paths = handle.paths().await.unwrap();

    assert_eq!(
        tokio::fs::read(paths.working.as_utf8_path().join("hello.txt"))
            .await
            .unwrap(),
        b"hello world\n",
    );
    assert_eq!(
        tokio::fs::read(paths.working.as_utf8_path().join("dir/nested.txt"))
            .await
            .unwrap(),
        b"nested contents",
    );
}

/// Drives the `CleanCache` subsystem to completion, returning every update
/// it streamed back in order.
async fn clean_cache(client: &mut TestClient, req: CleanCacheRequest) -> Vec<CleanCacheUpdate> {
    let channel = client
        .open_subsystem(minimald_rpc::CLEAN_CACHE_SUBSYSTEM, &[])
        .await;
    let mut stream = channel.into_stream();
    stream
        .write_all(&serde_json_lenient::to_vec(&req).unwrap())
        .await
        .unwrap();
    // Half-close: the handler reads the request until the client is done.
    stream.shutdown().await.unwrap();

    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    String::from_utf8(body)
        .unwrap()
        .lines()
        .map(|line| serde_json_lenient::from_str(line).expect("each line is an update"))
        .collect()
}

/// The clean runs through the daemon's actor and reports back: a line per
/// thing reclaimed, then exactly one terminal `Done` carrying the totals.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_cache_streams_progress_then_a_terminal_done() {
    use lcache::{EntryMeta, FileSystem, MetaInner};
    use std::io::Write as _;

    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // Two cold entries — nothing has read them, and no session needs them.
    let cache = server.state.daemon_context().await.local_cache();
    for byte in [1u8, 2] {
        let w = cache
            .write_dir(&common::SpecHash::from_bytes([byte; 32]))
            .unwrap();
        w.open_write("f").unwrap().write_all(b"x").unwrap();
        w.finalize(EntryMeta {
            inner: MetaInner::Spec(format!("pkg-{byte}")),
            fetched: false,
            ..Default::default()
        })
        .unwrap();
    }

    // `older_than_secs` of 1 rather than the daemon default, so entries
    // written a moment ago are in scope.
    let updates = clean_cache(
        &mut client,
        CleanCacheRequest::default().with_older_than_secs(1),
    )
    .await;

    let (terminal, progress) = updates.split_last().expect("at least a terminal update");
    assert_eq!(
        *terminal,
        CleanCacheUpdate::Done {
            entries: 2,
            dirs: 0
        }
    );
    assert_eq!(
        progress.len(),
        2,
        "one line per reclaimed entry: {progress:?}"
    );
    assert!(
        progress.iter().all(|u| matches!(u, CleanCacheUpdate::Removed { detail } if detail.starts_with("Deleting package pkg-"))),
        "progress should name what went: {progress:?}",
    );
    assert_eq!(cache.iter_entries().count(), 0);
}

/// An empty cache still terminates the stream properly — a client can
/// always read to a terminal update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_cache_with_nothing_to_do_still_terminates() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let updates = clean_cache(&mut client, CleanCacheRequest::default()).await;

    assert_eq!(
        updates,
        vec![CleanCacheUpdate::Done {
            entries: 0,
            dirs: 0
        }]
    );
}

#[tokio::test]
async fn stream_workspace_files_rejects_unknown_session() {
    use russh::ChannelMsg;

    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // A well-formed but unknown session id: the handler should report
    // an error on stderr (ssh extended data) rather than unpacking.
    let mut channel = client
        .open_subsystem(
            STREAM_WORKSPACE_FILES,
            &[(MINIMAL_SESSION_ID_ENV, &SessionId::nil().to_string())],
        )
        .await;
    channel.eof().await.unwrap();

    let mut stderr = Vec::new();
    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
            stderr.extend_from_slice(&data);
        }
    }

    assert!(
        String::from_utf8_lossy(&stderr).contains("unknown session"),
        "expected an unknown-session error on stderr, got {:?}",
        String::from_utf8_lossy(&stderr),
    );
}

/// A workspace upload belongs to the create flow: one into a session
/// that has already been configured and finalized is refused, and
/// nothing it carries lands in the live tree.
#[tokio::test]
async fn stream_workspace_files_refuses_a_configured_session() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst(&[("late.txt", b"too late\n")]).await;
    let stderr =
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_FILES, session_id, &payload).await;
    assert!(
        stderr.contains("a workspace upload is accepted only while the session is being created"),
        "expected the configured-session refusal, got {stderr:?}"
    );

    let paths = server
        .state
        .sessions_manager()
        .await
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("the session should resolve")
        .paths()
        .await
        .unwrap();
    assert!(
        !paths.working.as_utf8_path().join("late.txt").exists(),
        "a refused upload must not land in the workspace"
    );
}

/// A session whose loadout has composed and is parked awaiting its
/// verdict (`Draft { pending: Some(..) }`) is past the upload's place in
/// the create flow too: an upload would change the tree under a
/// composition already computed, so it is refused and lands nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_workspace_files_refuses_a_session_awaiting_its_verdict() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = client
        .call::<CreateSession>(&req("stream-test", "/tmp"))
        .await
        .unwrap()
        .id;
    // A daemon-collected var must be gated by the client, so the
    // configure parks the session instead of finalizing it.
    server
        .seed_workspace_mfile(session_id, "[session.vars]\nRUST_LOG = \"info\"\n")
        .await;
    let configured = client
        .call::<minimald_rpc::ConfigureLoadout>(&minimald_rpc::ConfigureLoadoutRequest {
            session_id,
            contribution: Default::default(),
        })
        .await
        .unwrap();
    assert!(
        matches!(
            configured,
            minimald_rpc::ConfigureLoadoutResponse::Pending { .. }
        ),
        "the configure should park awaiting a verdict, got {configured:?}"
    );

    let payload = tar_zst(&[("late.txt", b"too late\n")]).await;
    let stderr =
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_FILES, session_id, &payload).await;
    assert!(
        stderr.contains("a workspace upload is accepted only while the session is being created"),
        "expected the upload refusal, got {stderr:?}"
    );

    let paths = server
        .state
        .sessions_manager()
        .await
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("the session should resolve")
        .paths()
        .await
        .unwrap();
    assert!(
        !paths.working.as_utf8_path().join("late.txt").exists(),
        "a refused upload must not land in the workspace"
    );
}

/// The upload reader's idle deadline counts only a stall: reads that
/// keep arriving inside the limit run past it in total, time the
/// consumer spends between reads is not counted, and the peer's silence
/// longer than the limit fails the read with `TimedOut`.
#[tokio::test(start_paused = true)]
async fn idle_deadline_fails_a_stalled_read_but_not_a_slow_one() {
    let limit = std::time::Duration::from_secs(10);
    let (mut writer, reader) = tokio::io::duplex(64);
    let mut reader = IdleDeadline::new(reader, limit);
    let mut buf = [0u8; 8];
    for _ in 0..3 {
        tokio::time::advance(limit * 6 / 10).await;
        writer.write_all(b"x").await.unwrap();
        assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    }
    // Time the consumer spends between reads is not the peer's stall.
    writer.write_all(b"y").await.unwrap();
    tokio::time::advance(limit * 2).await;
    assert_eq!(reader.read(&mut buf).await.unwrap(), 1);
    // `writer` is still open, so this read can only end on the deadline.
    let err = reader.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

/// The upload's `bytes_received` field is only worth logging if it is
/// exact, so pull a payload through in many small polls and check the
/// tally accumulates across them rather than recording the last read.
#[tokio::test]
async fn counting_reader_tallies_every_byte_pulled_through() {
    let payload: Vec<u8> = (0..8192u32).map(|i| i as u8).collect();
    let count = Arc::new(AtomicU64::new(0));
    let mut sunk = Vec::new();

    let read = tokio::io::copy(
        &mut CountingReader {
            inner: payload.as_slice(),
            count: Arc::clone(&count),
        },
        &mut sunk,
    )
    .await
    .unwrap();

    assert_eq!(sunk, payload);
    assert_eq!(read, payload.len() as u64);
    assert_eq!(count.load(Ordering::Relaxed), payload.len() as u64);
}

/// `WorkspacePatchesTarZst` unpacks each entry under
/// `<workspace>/patches/<archive-path>` and drops the ready
/// marker on success. Guards the write ordering
/// (staging-dir → atomic rename → marker) that FinalizeSession
/// depends on.
#[tokio::test]
async fn stream_workspace_patches_unpacks_and_writes_marker() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst(&[
        (".config/helix/config.toml", b"theme = 'nord'\n"),
        (".config/other.toml", b"key = 'value'\n"),
    ])
    .await;

    let channel = client
        .open_subsystem(
            STREAM_WORKSPACE_PATCHES,
            &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
        )
        .await;
    let mut stream = channel.into_stream();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    stream.read_to_end(&mut trailing).await.unwrap();

    let mngr = server.state.sessions_manager().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should be retrievable");
    let paths = handle.paths().await.unwrap();
    let patches = paths.patches.as_utf8_path();

    assert_eq!(
        tokio::fs::read(patches.join(".config/helix/config.toml"))
            .await
            .unwrap(),
        b"theme = 'nord'\n",
    );
    assert_eq!(
        tokio::fs::read(patches.join(".config/other.toml"))
            .await
            .unwrap(),
        b"key = 'value'\n",
    );
    assert!(
        tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
            .await
            .unwrap(),
        "patches-ready marker must be written on successful unpack",
    );
}

/// Build a tar+zstd archive whose entries carry the modes given,
/// rather than `tar_zst`'s uniform `0o644` — the shape the patches
/// uploader produces once it stopped flattening the source's mode.
async fn tar_zst_with_modes(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut tar = async_tar::Builder::new(Vec::new());
    for (path, contents, mode) in entries {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(*mode);
        tar.append_data(&mut header, path, *contents).await.unwrap();
    }
    let tar_bytes = tar.into_inner().await.unwrap();
    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder.write_all(&tar_bytes).await.unwrap();
    encoder.shutdown().await.unwrap();
    encoder.into_inner()
}

/// An entry's permission bits reach the staged file, so a patched
/// script stays executable and a patched secret stays private. The
/// `0o600` case is the one that proves the mode is applied
/// explicitly rather than left to the daemon's umask, which would
/// have produced `0o644` from the same header.
///
/// setuid is masked off: the header arrives over the wire, so a
/// peer must not be able to ask the daemon to create a setuid file
/// in a session's tree. (`async_tar::Archive::unpack`, which
/// handles the workspace stream, drops it for the same reason.)
#[tokio::test]
async fn stream_workspace_patches_preserves_entry_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst_with_modes(&[
        (".local/bin/tool", b"#!/bin/sh\necho hi\n", 0o755),
        (".config/secret.toml", b"token = 'hunter2'\n", 0o600),
        (".local/bin/suid", b"#!/bin/sh\n", 0o4755),
    ])
    .await;

    let channel = client
        .open_subsystem(
            STREAM_WORKSPACE_PATCHES,
            &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
        )
        .await;
    let mut stream = channel.into_stream();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    stream.read_to_end(&mut trailing).await.unwrap();

    let mngr = server.state.sessions_manager().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should be retrievable");
    let paths = handle.paths().await.unwrap();
    let patches = paths.patches.as_utf8_path();

    let mode_of = async |rel: &str| {
        tokio::fs::metadata(patches.join(rel))
            .await
            .unwrap_or_else(|e| panic!("staged patch `{rel}` should exist: {e}"))
            .permissions()
            .mode()
            & 0o7777
    };

    assert_eq!(mode_of(".local/bin/tool").await, 0o755, "exec bit survives");
    assert_eq!(
        mode_of(".config/secret.toml").await,
        0o600,
        "a private mode is applied exactly, not widened by the umask",
    );
    assert_eq!(
        mode_of(".local/bin/suid").await,
        0o755,
        "setuid is masked off, the rest of the mode is kept",
    );
}

/// Build a tar+zstd archive with full control over each entry's
/// type and declared size, so tests can produce the malformed
/// shapes a hostile peer would hand-craft — `tar_zst` can only
/// build well-formed regular-file entries.
///
/// `declared_size` overrides the header's size field without
/// changing the body, which is how the forged-header case is
/// reproduced.
async fn tar_zst_raw(entries: &[(&str, &[u8], async_tar::EntryType, Option<u64>)]) -> Vec<u8> {
    let mut tar = async_tar::Builder::new(Vec::new());
    for (path, contents, entry_type, declared_size) in entries {
        let mut header = async_tar::Header::new_gnu();
        header.set_size(declared_size.unwrap_or(contents.len() as u64));
        header.set_mode(0o644);
        header.set_entry_type(*entry_type);
        tar.append_data(&mut header, path, *contents).await.unwrap();
    }
    let tar_bytes = tar.into_inner().await.unwrap();
    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder.write_all(&tar_bytes).await.unwrap();
    encoder.shutdown().await.unwrap();
    encoder.into_inner()
}

/// Build a tar+zstd archive whose entry name is written straight
/// into the header's raw name field, bypassing the path validation
/// `Builder::append_data` performs.
///
/// This is the only way to produce the archive shape the daemon's
/// traversal guard exists for: `async_tar`'s builder refuses to
/// *construct* a `..` entry, so a well-behaved client cannot make
/// one — but a hostile peer writing tar bytes by hand can, and that
/// is the case the guard has to catch.
async fn tar_zst_forged_name(name: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut header = async_tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_entry_type(async_tar::EntryType::Regular);
    // Raw name write: `set_path` would reject or normalize this.
    {
        let gnu = header.as_gnu_mut().expect("new_gnu produces a GNU header");
        gnu.name[..name.len()].copy_from_slice(name);
    }
    header.set_cksum();

    let mut tar = async_tar::Builder::new(Vec::new());
    tar.append(&header, contents).await.unwrap();
    let tar_bytes = tar.into_inner().await.unwrap();

    let mut encoder = async_compression::tokio::write::ZstdEncoder::new(Vec::new());
    encoder.write_all(&tar_bytes).await.unwrap();
    encoder.shutdown().await.unwrap();
    encoder.into_inner()
}

/// Push `payload` through `subsystem` for `session_id` and return
/// whatever the daemon relayed on stderr — empty on success. Keeps
/// the channel (rather than `into_stream`) so extended data stays
/// readable, which is how a rejection is signalled.
async fn upload_and_collect_stderr(
    client: &mut TestClient,
    subsystem: &str,
    session_id: SessionId,
    payload: &[u8],
) -> String {
    use russh::ChannelMsg;
    let mut channel = client
        .open_subsystem(
            subsystem,
            &[(MINIMAL_SESSION_ID_ENV, &session_id.to_string())],
        )
        .await;
    channel.data(payload).await.unwrap();
    channel.eof().await.unwrap();
    let mut stderr = Vec::new();
    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
            stderr.extend_from_slice(&data);
        }
    }
    String::from_utf8_lossy(&stderr).into_owned()
}

/// Resolve a session's staged-patches and staged-hooks dirs.
async fn staged_dirs(
    server: &TestServer,
    session_id: SessionId,
) -> (camino::Utf8PathBuf, camino::Utf8PathBuf) {
    let mngr = server.state.sessions_manager().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("session should be retrievable");
    let paths = handle.paths().await.unwrap();
    (
        paths.patches.as_utf8_path().to_owned(),
        paths.hooks.as_utf8_path().to_owned(),
    )
}

/// A `..` entry is refused end-to-end, not merely by the
/// `safe_relative_path` unit above: the guard has to actually be
/// wired into the unpack loop, before any byte reaches disk.
#[tokio::test]
async fn stream_workspace_patches_rejects_traversal_end_to_end() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst_forged_name(b"../escape.toml", b"pwned\n").await;
    let stderr =
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
            .await;

    assert!(
        stderr.contains("`..`") || stderr.contains("absolute path"),
        "expected a traversal rejection, got: {stderr:?}",
    );
    let (patches, _) = staged_dirs(&server, session_id).await;
    assert!(
        !tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
            .await
            .unwrap_or(false),
        "a rejected upload must not leave a ready marker",
    );
}

/// An entry named exactly like the ready marker is refused: it
/// would otherwise be copied into the sandbox home by
/// `materialize_patches_into_home`, zeroing whatever the user had
/// at that path.
#[tokio::test]
async fn stream_workspace_patches_rejects_marker_collision() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst(&[(PATCHES_READY_MARKER, b"")]).await;
    let stderr =
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
            .await;

    assert!(
        stderr.contains("ready-marker"),
        "expected a marker-collision rejection, got: {stderr:?}",
    );
}

/// Only regular files are unpacked. A directory entry would
/// otherwise be written as an empty *file*, which then breaks
/// `create_dir_all` for anything nested beneath it.
#[tokio::test]
async fn stream_workspace_patches_rejects_non_regular_entry() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst_raw(&[("adir", b"", async_tar::EntryType::Directory, None)]).await;
    let stderr =
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
            .await;

    assert!(
        stderr.contains("only regular files"),
        "expected a non-regular-entry rejection, got: {stderr:?}",
    );
}

/// A forged header declaring more bytes than the per-entry cap is
/// refused on the header alone, before the body is read — the
/// check that stops `Vec::with_capacity` being driven into an
/// allocation failure.
#[tokio::test]
async fn stream_workspace_patches_rejects_oversize_declared_entry() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst_raw(&[(
        "big.toml",
        b"small body",
        async_tar::EntryType::Regular,
        Some(MAX_PATCH_ENTRY_BYTES + 1),
    )])
    .await;
    let stderr =
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &payload)
            .await;

    assert!(
        stderr.contains("per-entry cap"),
        "expected an oversize rejection, got: {stderr:?}",
    );
}

/// A second upload replaces the first tree wholesale rather than
/// merging into it, and the marker survives. Exercises both swap
/// branches: the first upload takes the plain-rename path (no
/// prior tree), the second takes `RENAME_EXCHANGE`.
#[tokio::test]
async fn stream_workspace_patches_second_upload_replaces_the_tree() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let first = tar_zst(&[("only-in-first.toml", b"a\n")]).await;
    assert_eq!(
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &first).await,
        "",
    );
    let second = tar_zst(&[("only-in-second.toml", b"b\n")]).await;
    assert_eq!(
        upload_and_collect_stderr(&mut client, STREAM_WORKSPACE_PATCHES, session_id, &second).await,
        "",
    );

    let (patches, _) = staged_dirs(&server, session_id).await;
    assert!(
        tokio::fs::try_exists(patches.join("only-in-second.toml"))
            .await
            .unwrap(),
        "the second upload's contents must be present",
    );
    assert!(
        !tokio::fs::try_exists(patches.join("only-in-first.toml"))
            .await
            .unwrap(),
        "the first upload's contents must be gone, not merged",
    );
    assert!(
        tokio::fs::try_exists(patches.join(PATCHES_READY_MARKER))
            .await
            .unwrap(),
        "the marker must survive the swap",
    );
}

// -- hook scripts ---------------------------------------------------

/// The hook-script stream unpacks under `<workspace>/hooks/` at the
/// staged path the client derived, and drops its own ready marker.
#[tokio::test]
async fn stream_workspace_hook_scripts_unpacks_and_writes_marker() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let payload = tar_zst(&[
        ("loadout/dev/activate.sh", b"echo hi\n"),
        ("project/scripts/setup.sh", b"echo setup\n"),
    ])
    .await;
    let stderr = upload_and_collect_stderr(
        &mut client,
        STREAM_WORKSPACE_HOOK_SCRIPTS,
        session_id,
        &payload,
    )
    .await;
    assert_eq!(stderr, "", "upload should succeed");

    let (_, hooks) = staged_dirs(&server, session_id).await;
    assert_eq!(
        tokio::fs::read(hooks.join("loadout/dev/activate.sh"))
            .await
            .unwrap(),
        b"echo hi\n",
    );
    assert_eq!(
        tokio::fs::read(hooks.join("project/scripts/setup.sh"))
            .await
            .unwrap(),
        b"echo setup\n",
    );
    assert!(
        tokio::fs::try_exists(hooks.join(HOOKS_READY_MARKER))
            .await
            .unwrap(),
        "hooks-ready marker must be written on successful unpack",
    );
}

/// The hook-script stream enforces the same entry guards as the
/// patch stream. Parameterized over the malformed shapes so the two
/// paths can't drift in what they refuse.
#[tokio::test]
async fn stream_workspace_hook_scripts_rejects_malformed_entries() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "`..`",
            tar_zst_forged_name(b"../escape.sh", b"pwned\n").await,
        ),
        ("ready-marker", tar_zst(&[(HOOKS_READY_MARKER, b"")]).await),
        (
            "only regular files",
            tar_zst_raw(&[("adir", b"", async_tar::EntryType::Directory, None)]).await,
        ),
        (
            "per-entry cap",
            tar_zst_raw(&[(
                "big.sh",
                b"small",
                async_tar::EntryType::Regular,
                Some(MAX_HOOK_SCRIPT_BYTES + 1),
            )])
            .await,
        ),
    ];
    for (needle, payload) in cases {
        let stderr = upload_and_collect_stderr(
            &mut client,
            STREAM_WORKSPACE_HOOK_SCRIPTS,
            session_id,
            &payload,
        )
        .await;
        assert!(
            stderr.contains(needle),
            "expected a rejection mentioning {needle:?}, got: {stderr:?}",
        );
    }

    let (_, hooks) = staged_dirs(&server, session_id).await;
    assert!(
        !tokio::fs::try_exists(hooks.join(HOOKS_READY_MARKER))
            .await
            .unwrap_or(false),
        "no rejected upload may leave a ready marker",
    );
}

/// Unit test on the daemon-side traversal guard — the piece
/// covering a malicious peer that hand-crafts a raw tar with
/// `..` entries (the client's own `async_tar` builder refuses
/// to construct one, and `SandboxRelPath::try_new` already
/// rejects them at the wire-schema level, so this is a
/// defense-in-depth check for the "hand-crafted bytes"
/// scenario the earlier layers don't cover).
#[test]
fn safe_relative_path_rejects_absolute_and_traversal() {
    use std::path::Path as StdPath;
    // Absolute — must reject.
    assert!(!super::safe_relative_path(StdPath::new("/etc/foo")));
    // `..` at any position — must reject.
    assert!(!super::safe_relative_path(StdPath::new("../evil")));
    assert!(!super::safe_relative_path(StdPath::new("a/../b")));
    assert!(!super::safe_relative_path(StdPath::new("a/b/..")));
    // Ordinary relative paths — must accept.
    assert!(super::safe_relative_path(StdPath::new("a")));
    assert!(super::safe_relative_path(StdPath::new("a/b/c")));
    assert!(super::safe_relative_path(StdPath::new(
        ".config/helix/config.toml"
    )));
}

/// When the daemon fails to parse a request (or the handler errors),
/// the error message must reach the client on extended data instead
/// of the client seeing an opaque EOF on the response stream (#901).
#[tokio::test]
async fn oneshot_rpc_surfaces_handler_errors_as_extended_data() {
    use russh::ChannelMsg;

    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // Send invalid JSON to a known subsystem: handle_channel will fail
    // at serde_json_lenient::from_slice, which now writes the error to extended
    // data before closing the channel.
    let mut channel = client.open_subsystem(GetVersion::NAME, &[]).await;
    channel
        .data_bytes(b"not valid json".to_vec())
        .await
        .unwrap();
    channel.eof().await.unwrap();

    let mut err_buf = Vec::new();
    let mut data_buf = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExtendedData { data, ext: 1 } => err_buf.extend_from_slice(&data),
            ChannelMsg::Data { data } => data_buf.extend_from_slice(&data),
            _ => {}
        }
    }

    assert!(
        !err_buf.is_empty(),
        "expected an error on extended data, got data={:?}, err=empty",
        String::from_utf8_lossy(&data_buf),
    );
    assert!(
        data_buf.is_empty(),
        "expected no response data on error, got {:?}",
        String::from_utf8_lossy(&data_buf),
    );
}

#[tokio::test]
async fn get_version_returns_compiled_in_versions() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client.call::<GetVersion>(&()).await;

    assert_eq!(resp.version, version::VERSION);
    assert_eq!(resp.long_version, version::LONG_VERSION);
    assert_eq!(resp.stdlib_version, stdlib::VERSION);
}

#[tokio::test]
async fn list_sessions_is_empty_on_a_fresh_state_dir() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client.call::<ListSessions>(&()).await;

    assert!(
        resp.sessions.is_empty(),
        "fresh tempdir should yield no sessions, got {:?}",
        resp.sessions,
    );
}

#[tokio::test]
async fn get_session_record_returns_none_for_unknown_name() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Name("does-not-exist".to_string()))
        .await;

    assert!(resp.record.is_none());
}

#[tokio::test]
async fn get_session_record_returns_none_for_unknown_id() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(SessionId::nil()))
        .await;

    assert!(resp.record.is_none());
}

#[tokio::test]
async fn one_server_serves_multiple_back_to_back_clients() {
    // Each connect() spawns its own server-side task; this proves
    // the harness reuses a single ServerStateHandle across them.
    let server = TestServer::new().await;

    for _ in 0..3 {
        let mut client = server.connect().await;
        let resp = client.call::<GetVersion>(&()).await;
        assert_eq!(resp.version, version::VERSION);
    }
}

/// NET-079's per-box enforcement is a daemon-owned launch record, never
/// a client attr, displayed as the record lowered by the current fact.
/// A box no launch has recorded yet shows the daemon's one classifier
/// fact: a listing shows the same state the create response said for a
/// host-address box (this test's default create is one, never
/// launched), and the fact a test that set its own wrote. The guard is taken
/// before the server is built and held across the awaited creates on
/// purpose: the fact is process-global, so under libtest — where the
/// tests of one binary share a process — a listing driven by another
/// test would answer over a fact that test set.
#[expect(
    clippy::await_holding_lock,
    reason = "the fact is process-global, so the guard must span the awaited \
              reads it is held for"
)]
#[tokio::test]
async fn create_session_shows_in_get_and_list() {
    let _fact_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let created = client
        .call::<CreateSession>(&req("my-session", "/uwu"))
        .await
        .unwrap();
    let id = created.id;
    assert!(id != SessionId::nil());

    let get_session = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
        .await;
    assert_eq!(get_session.record.as_ref().unwrap().id, id);
    assert_eq!(
        get_session.record.as_ref().unwrap().name,
        Some("my-session".to_string())
    );
    assert_eq!(
        get_session.record.as_ref().unwrap().project_path,
        HostAbsPath::try_new("/uwu").unwrap()
    );
    assert!(
        !get_session
            .record
            .as_ref()
            .unwrap()
            .attrs
            .contains_key(super::HOST_IP_ENFORCEMENT_ATTR),
        "the per-box enforcement is a daemon-owned launch record, never \
         an attr: the record's own field carries it, written only by a \
         launch, and displayed as that record lowered by the host's \
         current fact, got: {:?}",
        get_session.record.as_ref().unwrap().attrs
    );

    let list_sessions = client.call::<ListSessions>(&()).await;
    assert!(list_sessions.resource_pool.is_some());
    assert_eq!(
        list_sessions.sessions,
        vec![ListSessionsEntry {
            id,
            name: Some("my-session".to_string()),
            project_path: Some(HostAbsPath::try_new("/uwu").unwrap()),
            // A freshly-created session that hasn't been configured yet
            // sits in `Pending` until `ConfigureLoadout` promotes it.
            status: boxes::BoxState::Pending,
            // /uwu is not a git repository, so the probe yields nothing.
            git: None,
            host_ip_enforcement: None,
            shared_port_collisions: Vec::new(),
            attrs: None,
        }]
    );
}

/// NET-081's host-table rule at the create: on a VM-backed node an
/// own-address create that carries no handed addresses is refused with
/// `InvalidInput`, naming the registration the client skipped, because
/// the guest never mints a box-plane address and a box with no host row
/// would start silently dark (NET-085). Pinned pure over the create's
/// gate: the test harness builds native daemons only. A handed create
/// passes, a native own-address create keeps NET-010's own allocator,
/// and a box that is not own-address has nothing to hand.
#[test]
fn vm_backed_create_without_handed_addresses_is_refused() {
    let refused = super::refuse_unhanded_vm_box(true, NetworkMode::OwnIp, None)
        .expect_err("a VM-backed own-address create with no handed addresses");
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        refused.to_string(),
        "box not registered with the VM host (no handed addresses); register \
         through minvmd's control socket first"
    );
    let handed = boxes::BoxAddresses {
        switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
        loopback_address: std::net::Ipv4Addr::new(127, 0, 0, 2),
    };
    assert!(
        super::refuse_unhanded_vm_box(true, NetworkMode::OwnIp, Some(&handed)).is_ok(),
        "a VM-backed create carrying the host's handed addresses passes"
    );
    assert!(
        super::refuse_unhanded_vm_box(false, NetworkMode::OwnIp, None).is_ok(),
        "a native own-address create keeps its own allocator (NET-010)"
    );
    for network in [NetworkMode::HostNet, NetworkMode::NoNet] {
        assert!(
            super::refuse_unhanded_vm_box(true, network, None).is_ok(),
            "a VM-backed {network:?} create has no box-plane address to hand"
        );
    }
}

/// The user-namespace gate (NET-143): a host whose verdict refuses the
/// sandbox refuses the create itself, and the reply carries the verdict
/// — the cause in words and that cause's own remedy — with nothing
/// allocated for a caller to tear down. The gate is this server's own
/// state, so no other test's create sees the fixed verdict.
#[tokio::test]
async fn create_reply_carries_user_namespace_verdict() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // Each cause carries its own remedy: the install step lifts only the
    // AppArmor restriction — and only for the daemon that next starts, so
    // the restart is named — while a switched-off namespace names the
    // persistent sysctl instead and never the install step.
    // The harness daemon is this process, so the path the remedy names
    // for a source-built daemon is this test binary's own.
    let bin = crate::server::this_daemon_path();
    for (verdict, expected, never) in [
        (
            crate::server::UsernsRestriction::ApparmorUnconfined,
            format!(
                "this machine blocks the private sandbox every box runs in (Ubuntu restricts \
                 unprivileged user namespaces), so no box can start here yet.\n\
                 Finish the install to allow it for Minimal only: min finalize-install   (see \
                 what it changes first: min finalize-install --show). The profile takes \
                 effect when the daemon next starts: run min stop, then your command \
                 again.\n\
                 A daemon built from source is not covered: attach the profile to this \
                 binary instead, from a checkout: sudo scripts/install-apparmor-profile.sh \
                 --path {bin}, then the same restart."
            ),
            "sysctl",
        ),
        (
            crate::server::UsernsRestriction::Disabled,
            "this machine blocks the private sandbox every box runs in (user namespaces \
             are switched off (user.max_user_namespaces=0 or no kernel support)), so no \
             box can start here yet.\n\
             Set user.max_user_namespaces above 0: sudo sysctl -w \
             user.max_user_namespaces=15000 takes effect now, a /etc/sysctl.d drop-in \
             keeps it across reboots; or use a kernel with CONFIG_USER_NS."
                .to_string(),
            "finalize-install",
        ),
    ] {
        server
            .state
            .set_user_namespace_gate(crate::server::UsernsGate::Fixed(verdict))
            .await;
        let refused = client.call::<CreateSession>(&req("refused", "/uwu")).await;
        server
            .state
            .set_user_namespace_gate(crate::server::UsernsGate::Off)
            .await;
        let error = refused
            .err()
            .expect("a create under a refusing verdict must be refused");
        assert!(
            error.starts_with(minimald_rpc::USER_NAMESPACE_REFUSAL_LEAD),
            "the refusal must be the user-namespace one, got: {error}"
        );
        assert_eq!(error, expected);
        assert!(
            !error.contains(never),
            "the other cause's remedy must not be named: {error}"
        );
        assert!(
            client.call::<ListSessions>(&()).await.sessions.is_empty(),
            "a refused create must not have allocated a session"
        );
    }
}

/// The gate reads the verdict on every create, never once at start: a
/// create refused under a verdict goes through once the verdict clears,
/// on the same running server, with no restart between. The live gate
/// re-probes `/proc` the same way; a fixed verdict stands in for the
/// host here because the harness's own host may be restricted.
#[tokio::test]
async fn create_succeeds_once_the_user_namespace_verdict_clears() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    server
        .state
        .set_user_namespace_gate(crate::server::UsernsGate::Fixed(
            crate::server::UsernsRestriction::Disabled,
        ))
        .await;
    let refused = client.call::<CreateSession>(&req("remedied", "/uwu")).await;
    assert!(
        refused.err().is_some(),
        "the create before the remedy must be refused"
    );

    // The remedy applied: the same server, the same connection, no
    // restart — the next create goes through.
    server
        .state
        .set_user_namespace_gate(crate::server::UsernsGate::Off)
        .await;
    client
        .call::<CreateSession>(&req("remedied", "/uwu"))
        .await
        .ok()
        .expect("a create after the verdict clears must succeed without a restart");
}

/// The version gate, made by the RPC the activation path already sends
/// rather than by a `GetVersion` ahead of it (#1251).
///
/// A matching assertion is invisible; a differing one fails the call with
/// the skew message *and leaves nothing behind* — which is the whole
/// point, since the failure this closes is a session that exists and is
/// then destroyed by its own caller's cleanup. An absent assertion (an
/// older client) behaves exactly as this RPC always did.
#[tokio::test]
async fn create_session_refuses_a_version_skew_before_allocating_anything() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let mut skewed = req("skewed", "/uwu");
    skewed.must_match_version = Some("0.0.0-not-this-build".to_string());
    let refused = client.call::<CreateSession>(&skewed).await;
    let error = refused.err().expect("a skewed create must be refused");
    assert!(
        error.contains("0.0.0-not-this-build") && error.contains(OWN_VERSION),
        "the refusal must name both builds, got: {error}"
    );
    assert!(error.contains("min stop"), "missing the recovery: {error}");
    assert!(
        error.contains(minimald_rpc::SKEW_OVERRIDE_VAR),
        "missing the override: {error}"
    );
    assert!(
        client.call::<ListSessions>(&()).await.sessions.is_empty(),
        "a refused create must not have allocated a session"
    );

    // The matching assertion goes through, and the reply names the build
    // that honoured it — the half of the handshake that catches a daemon
    // too old to have looked at `must_match_version` at all.
    let mut matching = req("matching", "/uwu");
    matching.must_match_version = Some(OWN_VERSION.to_string());
    let created = client
        .call::<CreateSession>(&matching)
        .await
        .ok()
        .expect("a matching assertion must be accepted");
    assert_eq!(created.daemon_version.as_deref(), Some(OWN_VERSION));

    // And a client that asserts nothing — an older one, or one running
    // under the skew override — is unaffected.
    let created = client
        .call::<CreateSession>(&req("unasserted", "/uwu"))
        .await
        .ok()
        .expect("an unasserted create must behave as it always has");
    assert_eq!(created.daemon_version.as_deref(), Some(OWN_VERSION));
}

/// The two read RPCs the attach / exec / setup-zed paths gate on must
/// report the daemon's build, or those paths have nothing to assert
/// against and would have to spend a `GetVersion` to find out.
#[tokio::test]
async fn the_read_rpcs_report_the_daemon_build() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let id = client
        .call::<CreateSession>(&req("my-session", "/uwu"))
        .await
        .unwrap()
        .id;

    assert_eq!(
        client
            .call::<ListSessions>(&())
            .await
            .daemon_version
            .as_deref(),
        Some(OWN_VERSION)
    );
    assert_eq!(
        client
            .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(id))
            .await
            .daemon_version
            .as_deref(),
        Some(OWN_VERSION)
    );
}

/// The probe a host whose `lo0` carries no range alias reads: the stock
/// macOS the spike measured — every bind refused, first at `.1`.
fn absent_range_probe() -> crate::net::loopback::RangeProbe {
    crate::net::loopback::RangeProbe {
        bound: 0,
        probed: 254,
        first_failure: Some((
            std::net::Ipv4Addr::new(127, 0, 64, 1),
            std::io::ErrorKind::AddrNotAvailable,
        )),
    }
}

/// The one session-start probe line this session's create produced: the
/// record that carries the probe's result and the surface it picked
/// (NET-123's observability contract). Attributed by session id, because
/// under libtest the capture buffer is shared by every test in the
/// binary — assertions on it say `contains`, never `equals`.
fn probe_line(log: &str, session_id: &SessionId) -> String {
    let message = "session-start loopback probe picked the publish surface";
    let id = format!("session_id={session_id}");
    log.lines()
        .find(|line| line.contains(message) && line.contains(&id))
        .unwrap_or_else(|| panic!("no session-start loopback probe record for {id}, got: {log}"))
        .to_string()
}

/// NET-123's reply flag: the create response carries the interim verdict
/// the session-start probe reached — `true` when the reserved range read
/// absent, `false` when it read present. The flag is the whole re-advise
/// contract: a client that reads `true` surfaces the naming advisory
/// again (NET-122).
// The guard is taken before the server is even built: both creates read
// the process-global probe, the first because it *must not* see another
// test's stand-in, the second because it must. It is held across both
// awaited creates on purpose.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn create_response_carries_interim_flag() {
    let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // The present verdict needs no stand-in: on Linux the whole 127/8 is
    // local to `lo`, so the real probe finds the range present.
    let present = client
        .call::<CreateSession>(&req("interim-present", "/uwu"))
        .await
        .ok()
        .expect("a create with the range present must publish");
    assert!(
        !present.interim_loopback,
        "a present reserved range must not report the interim"
    );

    // The absent verdict does — no real bind on this host can produce it.
    crate::net::loopback::install_probe_standin(absent_range_probe);
    let absent = client
        .call::<CreateSession>(&req("interim-absent", "/uwu"))
        .await
        .ok()
        .expect("a create with the range absent must still publish");
    crate::net::loopback::clear_probe_standin();
    assert!(
        absent.interim_loopback,
        "an absent reserved range must report the interim on the reply"
    );
}

/// NET-123's probe: session start bind-probes the reserved local range
/// before publishing, and the one session-start log line carries the
/// probe's result and the surface it picked. On this host the whole
/// `127/8` is local to `lo`, so the probe covers every address, finds
/// the range present, and the reply stays off the interim.
// The guard covers the awaited create for the same reason it covers the
// absent arm's window: this test drives no stand-in of its own, so
// another test's installed one must not leak into its create.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn session_start_probes_reserved_range() {
    let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let log = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let created = client
        .call::<CreateSession>(&req("probe-covered", "/uwu"))
        .await
        .ok()
        .expect("a create with a present range");
    assert!(!created.interim_loopback);

    let line = probe_line(&log.contents(), &created.id);
    assert!(
        line.contains("127.0.64.0/24 254/254 bound"),
        "the probe covers the whole reserved range, and the line says so: {line}"
    );
    assert!(
        line.contains("surface=reserved-range"),
        "the surface the probe picked is named: {line}"
    );
}

/// NET-123's absent arm: when the session-start probe finds the reserved
/// range absent the reply carries the interim and the log names it as the
/// surface picked — the two things that make the client surface the
/// naming advisory again. The stand-in stands in for the host without
/// the aliases; no real bind on this Linux one can reproduce it, and the
/// flag itself still switches no published address (see
/// `net::loopback`'s module doc for what the verdict carries).
// The stand-in window must cover the awaited create, so the mutex guard
// is held across the await on purpose.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn absent_range_publishes_interim_and_readvises() {
    let log = crate::test_harness::captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    crate::net::loopback::install_probe_standin(absent_range_probe);
    let interim = client
        .call::<CreateSession>(&req("interim-published", "/uwu"))
        .await
        .ok()
        .expect("an absent range must not refuse the session");
    crate::net::loopback::clear_probe_standin();

    assert!(
        interim.interim_loopback,
        "the reply carries the interim — the flag a client re-surfaces \
         the naming advisory on"
    );
    let line = probe_line(&log.contents(), &interim.id);
    assert!(
        line.contains("surface=127.0.0.1-interim"),
        "the log names the interim as the surface chosen: {line}"
    );
    assert!(
        line.contains("interim_loopback=true"),
        "the interim verdict is on the line, for the log's reader: {line}"
    );
}

/// NET-123 on a VM-backed daemon, after `min finalize-install`: the
/// create handler asks the forwarder's walk of the host's loopback, not the
/// guest's own `lo`. Each session start walks again, whatever verdict
/// landed last. The walk after the host gains the range lands present: the
/// box standing at the `127.0.0.1` interim moves onto a range address, the
/// new box's grant comes from the range, and its reply clears the interim
/// flag. A present verdict is walked again too. When the range goes away
/// under the running VM, the next walk lands absent: the reply carries the
/// interim flag and the earlier box moves back to `127.0.0.1`. The stand-in
/// walk stands in for the host forwarder, which a harness daemon does not
/// have.
#[allow(clippy::await_holding_lock)]
#[cfg(target_os = "linux")]
// Multi-thread: the held-forward step runs the real forwarder walk from
// inside the sync stand-in, through `block_in_place`.
/// NET-018: once the answerer is serving beside the proxy, the replies
/// report the one fact that is the daemon's to know — its answerer
/// bound — and the one log line, emitted the moment the answerer binds,
/// names that surface and that the hostname proxy keeps serving beside
/// it: the verdict switches what a client *reports*, never what the
/// proxy does (NET-019). NET-019's other half is proved on this
/// daemon's own proxy too: after the native line, one request still
/// routes through the listener whose port the reply carries — the
/// pure verdict in `proxy`'s test routes through a serve loop a test
/// spun up itself; this is the daemon's. The answerer is the half the
/// daemon's start path brings up on a detached driver; here it is
/// driven to serving the same way, the proxy beside it — the proxy
/// first, so the answerer's line reads an already-recorded port
/// deterministically rather than racing the proxy's record moment.
///
/// The fresh-daemon list first proves the absent half: no answerer, no
/// bound report — and no surface line at all, the line being the
/// answerer's bind moment, not a request's.
// The answerer helper binds the host loopback, so this test runs only
// where the helper does. The stand-in window covers the awaited
// create — the one call left that runs the process-global probe — for
// the same reason the interim tests take it. The log assertions say
// `contains`, never `equals`: the capture buffer is shared
// process-wide, and any test that drives an answerer to serving
// writes a surface line into it.
#[expect(
    clippy::await_holding_lock,
    reason = "the stand-in window has to cover the awaited create's probe"
)]
#[cfg(target_os = "linux")]
#[tokio::test]
async fn name_surface_reported_when_both_deployed() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    let log = crate::test_harness::captured_log();
    let _standin_window = PROBE_TEST_MUTEX.lock().unwrap_or_else(|p| p.into_inner());
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // A daemon with neither listener up reports the read that changes
    // nothing: not bound.
    let bare = client.call::<ListSessions>(&()).await;
    assert!(
        !bare.answerer_bound,
        "a daemon whose answerer has not come up must not report it bound"
    );

    // Bring both listeners to serving — the startup loops
    // `start_host_proxies` spawns — with a compressed backoff. The
    // proxy first: the answerer's serving tail is what logs the
    // surface line, and its proxy half reads the recorded port, so
    // recording it before the answerer binds is what makes the line's
    // "keeps serving" half deterministic here.
    let compressed =
        crate::server::RetryBackoff::new(Duration::from_millis(5), Duration::from_millis(40));
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    crate::server::retry_hostname_proxy_until_serving(server.state.clone(), loopback, compressed)
        .await;
    crate::server::retry_zone_answerer_until_serving(server.state.clone(), loopback, compressed)
        .await;

    // Both listeners up: the list and create replies report the
    // answerer bound, and the activation reply carries the same fact
    // the list does.
    let listed = client.call::<ListSessions>(&()).await;
    assert!(
        listed.answerer_bound,
        "a daemon whose answerer serves reports it bound"
    );
    let created = client
        .call::<CreateSession>(&req("surface-native", "/uwu"))
        .await
        .ok()
        .expect("a create on a host whose answerer serves must succeed");
    assert!(
        created.answerer_bound,
        "the activation reply carries the same bound fact the list does"
    );

    // The log says what this daemon knows and no more: the bound
    // answerer and its port — the one fact the replies carry — that
    // native DNS waits on the host's resolver before it is the live
    // surface there, that `min ls` reports the host's verdict, and the
    // proxy's half beside it. The assertions read the message, plus the
    // two fields a bundle's reader greps (`answerer_bound`,
    // `proxy_serves`); the rest of the field quoting is the
    // subscriber's business.
    let log = log.contents();
    let answerer_line = log
        .lines()
        .find(|line| line.contains("box-zone answerer is bound"))
        .expect("the answerer's bind logs one line a diagnostics bundle can tail");
    let answerer_port = created
        .zone_answerer_port
        .expect("with the answerer up, the reply carries its port");
    assert!(
        answerer_line.contains("answerer_bound=true"),
        "the line's field is the fact the daemon knows, not a surface verdict: {answerer_line}"
    );
    assert!(
        answerer_line.contains(&format!("is bound on 127.0.0.1:{answerer_port}")),
        "the line names the bound answerer and its port: {answerer_line}"
    );
    assert!(
        answerer_line.contains("once its resolver routes the zone"),
        "the line says native DNS waits on the host's resolver routing the zone: {answerer_line}"
    );
    assert!(
        answerer_line.contains("`min ls` reports the host's surface"),
        "the line points at where the host's verdict is reported: {answerer_line}"
    );
    assert!(
        !answerer_line.contains("the live name surface is native"),
        "the daemon cannot read the host's resolver, so the line must not claim its surface: \
         {answerer_line}"
    );
    assert!(
        answerer_line.contains("proxy_serves=true"),
        "the line says the proxy still serves beside the answerer (NET-019): {answerer_line}"
    );
    assert!(
        answerer_line.contains("the hostname proxy keeps serving"),
        "the line says the proxy keeps serving, in the words its reader reads: {answerer_line}"
    );
    let port = created
        .hostname_proxy_port
        .expect("with the proxy up, the reply carries its port");
    assert!(
        answerer_line.contains(&format!("127.0.0.1:{port}")),
        "the line names the port a client keeps routing through: {answerer_line}"
    );

    // NET-019 on the daemon's own proxy: the verdict that just reported
    // native DNS stops nothing — one request still routes through the
    // listener whose port the reply carries. The registry holds the
    // create's session as a host-net route the way the session-start
    // path registers one, so the request has a target to reach.
    let backend_port = crate::net::proxy::spawn_backend().await;
    server
        .state
        .sessions_manager()
        .await
        .hostnames()
        .write()
        .expect("hostname registry lock poisoned")
        .register_host_net(created.id, "surface-native");
    let routed = crate::net::proxy::proxy_get(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        &format!("surface-native.min.internal:{backend_port}"),
    )
    .await;
    assert!(
        routed.contains("200 OK"),
        "the daemon's own proxy still routes beside the native verdict (NET-019), got: {routed}"
    );
}

#[tokio::test]
async fn get_session_policy_returns_the_policy_configured_at_launch() {
    // R2.6: GetSessionPolicy reads the live per-session policy from the
    // record, not a hardcoded default. Create an `OwnIp` session carrying an
    // explicit egress policy, then read it back over the RPC.
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let egress = EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        allow_dns_hosts: None,
        allow_protocols: None,
        deny_subnets: Some(vec!["192.168.0.0/16".to_string()]),
    };
    let created_id = client
        .call::<CreateSession>(&CreateSessionRequest::new(
            "policy-session",
            HostAbsPath::try_new("/uwu").unwrap(),
            NetworkMode::OwnIp,
            BoxPolicy::new(Some(egress.clone()), None),
        ))
        .await
        .unwrap()
        .id;

    let policy = client
        .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(created_id))
        .await
        .unwrap();
    assert_eq!(policy.egress, Some(egress));
    // The configured ingress was `None`, and the read reflects that rather
    // than the old hardcoded `Some(IngressPolicy::default())`.
    assert_eq!(policy.ingress, None);
}

/// Creates an own-address session carrying `policy` and returns the
/// whole create reply — the box shape the deny-all default is about
/// (NET-074): an own-address box, whatever its egress declaration.
/// Tests that only need the box take [`own_ip_session`].
async fn own_ip_create_reply(
    client: &mut TestClient,
    name: &str,
    policy: BoxPolicy,
) -> minimald_rpc::CreateSessionResponse {
    client
        .call::<CreateSession>(&CreateSessionRequest::new(
            name,
            HostAbsPath::try_new("/uwu").unwrap(),
            NetworkMode::OwnIp,
            policy,
        ))
        .await
        .unwrap()
}

/// Creates an own-address session carrying `policy` and returns its id —
/// [`own_ip_create_reply`] for a caller that needs only the box.
async fn own_ip_session(client: &mut TestClient, name: &str, policy: BoxPolicy) -> SessionId {
    own_ip_create_reply(client, name, policy).await.id
}

/// NET-074/NET-075: `GetEffectiveSessionPolicy` answers, over the real
/// SSH wire, what the gate enforces. The wire half asserts the reply the
/// shipped phase resolves — in force, so `deny_all` — and the in-force
/// posture is also proven by passing the phase explicitly to the same
/// resolver the handler serves. In force, an own-address box with no
/// `egress` section answers `deny_all` — reported as the posture, not as
/// a materialized section — and that reply survives the wire codec it
/// travels as, while the strict `GetSessionPolicy` reply still carries
/// the absent section as `None`: the default reaches the client without
/// rewriting the record. A box that declared its own egress answers it
/// verbatim, survived the JSON round trip, with its ingress beside it.
/// NET-134: a box that declared a credentialed upstream answers the lane
/// over the same reply — `Some` over the wire, spelled in the JSON —
/// while a box that declared none answers `None` and serializes without
/// the key, byte-identical to the reply this field did not exist for.
#[tokio::test]
async fn effective_policy_response_round_trips() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let egress = EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        allow_dns_hosts: None,
        allow_protocols: None,
        deny_subnets: Some(vec!["192.168.0.0/16".to_string()]),
    };
    let declared_id = own_ip_session(
        &mut client,
        "declared-egress",
        BoxPolicy::new(Some(egress.clone()), None),
    )
    .await;
    let bare_id = own_ip_session(&mut client, "bare-egress", BoxPolicy::default()).await;
    let laned_policy = BoxPolicy {
        egress: None,
        ingress: None,
        credentialed_upstream: Some(boxes::CredentialedUpstream::default()),
        quic443: None,
    };
    let laned_id = own_ip_session(&mut client, "laned-egress", laned_policy.clone()).await;

    // The default's own case, with the phase passed explicitly
    // (NET-074): an own-address box that declared nothing is deny-all
    // once the default is in force.
    assert_eq!(
        super::effective_policy_reply(
            &BoxPolicy::default(),
            NetworkMode::OwnIp,
            boxes::EgressDefaultPhase::InForce,
            false,
        ),
        EffectiveBoxPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
            credentialed_upstream: None,
        },
        "an own-address box with no egress section must answer deny-all in force",
    );

    // The response carries that posture across the wire codec it
    // travels as — the strict shape untouched beside it: the effective
    // reply spells the default, `deny_all`, and decodes back to the
    // same value. A lane-less reply serializes without the lane's key:
    // the shape an older client reads.
    let deny_all = EffectiveBoxPolicy {
        egress: EffectiveEgress::DenyAll,
        ingress: None,
        credentialed_upstream: None,
    };
    let wire = serde_json_lenient::to_string(&minimald_rpc::Errorable::Ok(deny_all.clone()))
        .expect("the deny-all reply must serialize");
    assert!(
        wire.contains(r#""egress":"deny_all""#),
        "the wire must carry the deny-all posture, got: {wire}",
    );
    assert!(
        !wire.contains("credentialed_upstream"),
        "a reply without a lane must serialize without the lane's key, got: {wire}",
    );
    assert_eq!(
        serde_json_lenient::from_str::<minimald_rpc::Errorable<EffectiveBoxPolicy>>(&wire)
            .expect("the deny-all reply must decode back"),
        minimald_rpc::Errorable::Ok(deny_all),
    );

    // Over the real wire, the reply follows the phase this build ships:
    // whatever [`boxes::EGRESS_DEFAULT_PHASE`] resolves for a bare
    // own-address box is what the daemon answers.
    let bare = client
        .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(bare_id))
        .await
        .unwrap();
    assert_eq!(
        bare,
        super::effective_policy_reply(
            &BoxPolicy::default(),
            NetworkMode::OwnIp,
            boxes::EGRESS_DEFAULT_PHASE,
            false,
        ),
        "the wire must answer the shipped phase's resolution for a bare box",
    );
    assert_eq!(
        bare.egress,
        EffectiveEgress::DenyAll,
        "with the default in force the wire answers deny-all for a bare box",
    );

    // The strict reply is unchanged: the declaration the box was
    // launched with, absent section still absent.
    let strict = client
        .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(bare_id))
        .await
        .unwrap();
    assert_eq!(
        strict,
        BoxPolicy::default(),
        "the strict policy reply must keep the declaration as launched",
    );

    // A declared section round-trips as the gate resolves it, ingress
    // beside it: the effective reply is what the box is held to, so the
    // names list the declaration left absent comes back present and
    // empty (NET-074, in force on an own-address box), while the
    // declared lists ride verbatim. The strict reply above is the one
    // that echoes the declaration.
    let declared = client
        .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(declared_id))
        .await
        .unwrap();
    assert_eq!(
        declared.egress,
        EffectiveEgress::Declared(EgressPolicy {
            allow_dns_hosts: Some(Vec::new()),
            ..egress
        }),
    );
    assert_eq!(declared.ingress, None);

    // A declared lane round-trips too: the reply answers it as `Some`
    // over the real wire, spelled in the JSON the codec travels as,
    // while the strict declaration keeps it beside the record.
    let laned = client
        .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(laned_id))
        .await
        .unwrap();
    assert_eq!(
        laned.credentialed_upstream,
        Some(boxes::CredentialedUpstream::default()),
        "the wire must answer the lane a declared box carries",
    );
    let lane_wire = serde_json_lenient::to_string(&minimald_rpc::Errorable::Ok(laned.clone()))
        .expect("the laned reply must serialize");
    assert!(
        lane_wire.contains(r#""credentialed_upstream":{}"#),
        "the wire must spell the lane, got: {lane_wire}",
    );
    let strict_laned = client
        .call::<GetSessionPolicy>(&GetSessionPolicyRequest::Id(laned_id))
        .await
        .unwrap();
    assert_eq!(
        strict_laned, laned_policy,
        "the strict policy reply must keep the lane as declared",
    );

    // The bare box answers no lane: `None` on the reply, and absent
    // from the wire — the reply that predates the lane.
    assert_eq!(
        bare.credentialed_upstream, None,
        "a box that declared no lane must answer none",
    );
}

/// NET-077: a daemon started with the deny-all opt-out keeps the earlier
/// allow-all default — an own-address box with no `egress` section
/// answers `allow_all` where the same box on an opted-in daemon answers
/// `deny_all` with the default in force — and
/// its gate resolves no section, so nothing is enforced. A box that
/// declared its own egress keeps it either way.
#[tokio::test]
async fn deny_all_opt_out_keeps_prior_default() {
    let server = TestServer::new_opted_out_in(tempfile::tempdir().unwrap()).await;
    let mut client = server.connect().await;

    let egress = EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        ..EgressPolicy::default()
    };
    let declared_id = own_ip_session(
        &mut client,
        "opt-out-declared",
        BoxPolicy::new(Some(egress.clone()), None),
    )
    .await;
    let bare_id = own_ip_session(&mut client, "opt-out-bare", BoxPolicy::default()).await;

    let bare = client
        .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(bare_id))
        .await
        .unwrap();
    assert_eq!(
        bare,
        EffectiveBoxPolicy {
            egress: EffectiveEgress::AllowAll,
            ingress: None,
            credentialed_upstream: None,
        },
        "behind the opt-out, an absent egress section keeps the earlier allow-all",
    );

    // The report and the gate agree, even in force: the same resolution
    // the launcher applies materializes no section to enforce. The phase
    // is passed explicitly so the opt-out stays proven against the
    // posture it exists to defer whatever the shipped constant says.
    assert_eq!(
        crate::box_actor::effective_egress_section(
            &boxes::BoxPolicy::default(),
            NetworkMode::OwnIp,
            boxes::EgressDefaultPhase::InForce,
            true,
        ),
        None,
        "behind the opt-out, the gate compiles no egress section at all",
    );

    // The opt-out never rewrites a declaration: what the box said is
    // what it gets, whichever daemon it runs on.
    let declared = client
        .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(declared_id))
        .await
        .unwrap();
    assert_eq!(declared.egress, EffectiveEgress::Declared(egress));
}

/// NET-076/NET-077: the create reply carries the daemon's opt-out —
/// the rollout's one fact the client cannot know from its own build,
/// since the phase is a build-time constant both sides share and the
/// flag is set on the daemon alone. `min session activate` reads it to
/// keep its coming-change notice off a deployment that has already
/// chosen to keep the shipped default; the create reply is the RPC the
/// activation path already holds, so the answer costs no extra round
/// trip. An opted-out daemon says `true`, a daemon without the flag
/// says `false` — never `None`, which is reserved for a daemon that
/// predates the field and so cannot have opted out.
#[tokio::test]
async fn create_reply_reports_the_deny_all_opt_out() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    assert_eq!(
        own_ip_create_reply(&mut client, "opt-out-reply-default", BoxPolicy::default())
            .await
            .deny_all_opt_out,
        Some(false),
        "a daemon without the flag must say it did not opt out",
    );

    let server = TestServer::new_opted_out_in(tempfile::tempdir().unwrap()).await;
    let mut client = server.connect().await;
    assert_eq!(
        own_ip_create_reply(&mut client, "opt-out-reply-set", BoxPolicy::default())
            .await
            .deny_all_opt_out,
        Some(true),
        "an opted-out daemon must say so, so the notice can stay off",
    );
}

#[tokio::test]
async fn get_session_screen_snapshots_the_live_terminal() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    // Before anything attaches there is no host: the RPC answers with a
    // soft error instead of minting one.
    let inactive = client.call::<GetSessionScreen>(&session_id).await;
    assert!(
        matches!(&inactive, Errorable::Err { error } if error.contains("not active")),
        "expected a not-active error, got {inactive:?}",
    );

    // Attach a shell (the mock launcher runs an echo program), then write
    // a line the program echoes back prefixed with `got:`.
    let shell = client.open_shell(session_id).await;
    shell.data_bytes(&b"hello-screen\n"[..]).await.unwrap();

    // The echo round-trips through the pty asynchronously; poll the RPC
    // until the parser has seen it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let snapshot = loop {
        let resp = client.call::<GetSessionScreen>(&session_id).await;
        match resp {
            Errorable::Ok(snap) => {
                let text: String = snap
                    .lines
                    .iter()
                    .map(|row| row.cells.iter().map(|c| c.ch).collect::<String>())
                    .collect::<Vec<_>>()
                    .join("\n");
                if text.contains("got:hello-screen") {
                    break snap;
                }
            }
            Errorable::Err { .. } => {}
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the echo to reach the screen snapshot",
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!((snapshot.rows, snapshot.cols), (24, 80));
}

#[tokio::test]
async fn create_session_errors_if_name_not_unique() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let id = client
        .call::<CreateSession>(&req("my-session", "/uwu"))
        .await
        .unwrap()
        .id;
    assert!(id != SessionId::nil());

    let Errorable::Err { error } = client
        .call::<CreateSession>(&req("my-session", "/uwu"))
        .await
    else {
        panic!("a second create under a held name must be refused");
    };
    // The refusal names the holder (its name and id) and the rename hint.
    assert!(error.contains("`my-session`"), "{error}");
    assert!(error.contains(&id.to_string()), "{error}");
    assert!(
        error.contains(&format!("min session rename {id} <new-name>")),
        "{error}"
    );
}

/// The `session created` log line names the session's network mode beside
/// its id and name, in the CLI's `--network` spellings (`none` / `host_ip`
/// / `own_ip`) so the bundle's tail reads like the command a person typed.
/// Attributed by session id, because under libtest the capture buffer is
/// shared by every test in the binary — assertions on it say `contains`,
/// never `equals`.
#[tokio::test]
async fn session_created_line_names_the_network_mode() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let capture = crate::test_harness::captured_log();

    // One box per mode: the default (host-address), a NoNet box, and an
    // own-address box. Each create succeeds because none declares egress
    // (so the unenforceable-declaration gate never fires) and the native
    // test host is not a microVM (so an own-address box needs no handed
    // addresses).
    let host_ip = req("host-address", "/uwu");
    let host_id = client.call::<CreateSession>(&host_ip).await.unwrap().id;

    let mut no_net = req("no-network", "/uwu");
    no_net.config.network = NetworkMode::NoNet;
    let none_id = client.call::<CreateSession>(&no_net).await.unwrap().id;

    let mut own_ip = req("own-address", "/uwu");
    own_ip.config.network = NetworkMode::OwnIp;
    let own_id = client.call::<CreateSession>(&own_ip).await.unwrap().id;

    let log = capture.contents();
    for (id, spelling) in [
        (&host_id, "host_ip"),
        (&none_id, "none"),
        (&own_id, "own_ip"),
    ] {
        assert!(
            log.lines().any(|line| {
                line.contains("session created")
                    && line.contains(&format!("session_id={id}"))
                    && line.contains(&format!("network_mode={spelling} "))
            }),
            "the session created line for {id} must name its network mode \
             {spelling}, got: {log}"
        );
    }
}

#[tokio::test]
async fn create_session_rejects_policy_incompatible_with_network_mode() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // NET-065: an egress policy on a none (`NoNet`) box is rejected at
    // declaration time, so the invalid session is never stored. Egress on
    // a host-address box is accepted (NET-120), so `NoNet` is the only
    // mode that still refuses it.
    let egress = EgressPolicy {
        allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
        allow_dns_hosts: None,
        allow_protocols: None,
        deny_subnets: None,
    };
    let resp = client
        .call::<CreateSession>(&CreateSessionRequest::new(
            "bad-policy",
            HostAbsPath::try_new("/uwu").unwrap(),
            NetworkMode::NoNet,
            BoxPolicy::new(Some(egress), None),
        ))
        .await;
    assert_eq!(
        resp,
        Errorable::Err {
            error: "egress rules need network mode own_ip or host_ip (this box is none): \
                    a none box has no network to apply them to"
                .to_string()
        }
    );

    // The rejected session left nothing behind in the store.
    let mngr = server.state.sessions_manager().await;
    assert!(mngr.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn create_session_rejects_static_ingress_on_host_net() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    // A static ingress mapping on a host-address box is a configuration the
    // daemon refuses at create time, naming the policy field and the box's
    // mode (not a CLI flag: any client may send this): an own-IP box is the
    // only mode with a published address to apply the mapping to. Built by
    // hand to bypass the CLI-side refusal so the daemon path itself is what
    // is exercised.
    let ingress = IngressPolicy {
        port_mappings: vec![PortMapping {
            external_port: 18080,
            internal_port: 80,
            proto: IpProto::Tcp,
        }],
        dynamic_allowed_range: None,
        dynamic_ingress: None,
    };
    let resp = client
        .call::<CreateSession>(&CreateSessionRequest::new(
            "bad-ingress",
            HostAbsPath::try_new("/uwu").unwrap(),
            NetworkMode::HostNet,
            BoxPolicy::new(None, Some(ingress)),
        ))
        .await;
    assert_eq!(
        resp,
        Errorable::Err {
            error: "ingress port mappings need network mode own_ip (this box is host_ip): \
                    only an own-IP box has a published address to apply them to"
                .to_string()
        }
    );

    // The rejected session left nothing behind in the store.
    let mngr = server.state.sessions_manager().await;
    assert!(mngr.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn rename_session_propagates_into_the_running_session() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    // Bring the session up before renaming, so the rename has to reach the
    // live actor's in-memory record rather than only touching disk.
    let mngr = server.state.sessions_manager().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("freshly-created session should be retrievable");

    let resp = client
        .call::<RenameSession>(&RenameSessionRequest {
            id: session_id,
            new_name: "renamed".to_string(),
        })
        .await;
    assert_eq!(resp, Errorable::Ok(RenameSessionResponse));

    // The record held by the running session reflects the new name...
    let record = handle.record().await.unwrap();
    assert_eq!(record.name.as_deref(), Some("renamed"));
    // ...while its id is untouched by the rename.
    assert_eq!(record.id, session_id);

    // The rename is reflected by GetRecord...
    let get_session = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(record.id))
        .await;
    assert_eq!(
        get_session.record.as_ref().unwrap().name,
        Some("renamed".to_string())
    );
}

#[tokio::test]
async fn rename_session_to_its_current_name_is_an_error() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    // `fresh_session` names the session "stream-test"; renaming it to that
    // same name must fail rather than silently no-op.
    let resp = client
        .call::<RenameSession>(&RenameSessionRequest {
            id: session_id,
            new_name: "stream-test".to_string(),
        })
        .await;

    assert!(
        matches!(&resp, Errorable::Err { error } if error.contains("session is already named")),
        "expected a rename-to-self error, got {resp:?}",
    );

    // The failed rename left the name intact.
    let mngr = server.state.sessions_manager().await;
    let handle = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("freshly-created session should be retrievable");
    let record = handle.record().await.unwrap();
    assert_eq!(record.name.as_deref(), Some("stream-test"));
}

#[tokio::test]
async fn rename_session_errors_for_unknown_id() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<RenameSession>(&RenameSessionRequest {
            id: SessionId::nil(),
            new_name: "renamed".to_string(),
        })
        .await;

    assert!(
        matches!(resp, Errorable::Err { error } if error.contains(minimald_rpc::UNKNOWN_SESSION_ID_LEAD)),
        "expected an unknown-id error",
    );
}

/// A verdict for an id with no live session is a terminal, structured
/// `Fault::UnknownSessionId` on the wire — not a transport error. This
/// mapping lives in `serve_submit_verdict` now that verdicts route to
/// per-session actors.
#[tokio::test]
async fn submit_verdict_unknown_id_returns_unknown_session_id() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<minimald_rpc::SubmitVerdict>(&boxes::wire::request::ContributionVerdict {
            session_id: SessionId::nil(),
            vars: vec![],
            patches: vec![],
            lifecycle_hooks: vec![],
        })
        .await;
    match resp {
        Errorable::Ok(boxes::wire::request::BoxStep::Fault {
            error: boxes::wire::errors::WireError::UnknownSessionId,
        }) => {}
        other => panic!("expected Fault::UnknownSessionId, got {other:?}"),
    }
}

#[tokio::test]
async fn destroy_session_removes_it_from_get_and_list() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let resp = client
        .call::<DestroySession>(&DestroySessionRequest {
            id: session_id,
            only_if_unfinalized: false,
        })
        .await;
    assert_eq!(resp, Errorable::Ok(DestroySessionResponse::default()));

    // The record is gone: it no longer resolves by id...
    let get_session = client
        .call::<GetSessionRecord>(&GetSessionRecordRequest::Id(session_id))
        .await;
    assert!(get_session.record.is_none());

    // ...and it's dropped from the listing.
    let list_sessions = client.call::<ListSessions>(&()).await;
    assert!(
        list_sessions.sessions.is_empty(),
        "destroyed session should not be listed, got {:?}",
        list_sessions.sessions,
    );
}

#[tokio::test]
async fn destroy_session_errors_for_unknown_id() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<DestroySession>(&DestroySessionRequest {
            id: SessionId::nil(),
            only_if_unfinalized: false,
        })
        .await;

    assert!(
        matches!(resp, Errorable::Err { error } if error.starts_with(minimald_rpc::UNKNOWN_SESSION_ID_LEAD)),
        "expected an unknown-id error",
    );
}

/// Every step that releases a write-open fd under the state volume runs
/// before the quiesce, or the read-only remount fails and the journal
/// stays dirty; the flush runs before the spool's release and the ack.
#[test]
fn a_clean_stop_releases_its_fds_before_the_quiesce() {
    use CleanStopStep::{FlushTelemetry, QuiesceVolume, ReleaseLog, ReleaseSpool};
    assert_eq!(
        clean_stop_steps(true),
        [ReleaseLog, FlushTelemetry, ReleaseSpool, QuiesceVolume]
    );
}

/// With no volume of its own there is nothing to quiesce, so the spool
/// stays open for the records still to come.
#[test]
fn a_clean_stop_without_a_mounted_volume_keeps_its_spool() {
    assert_eq!(clean_stop_steps(false), [CleanStopStep::ReleaseLog]);
}

#[tokio::test]
async fn shutdown_reports_shutting_down_when_no_sessions_are_live() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    assert_eq!(resp, ShutdownResponse::ShuttingDown);
}

#[tokio::test]
async fn shutdown_rejects_further_session_work_once_shut_down() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    assert_eq!(resp, ShutdownResponse::ShuttingDown);

    // After shutdown the manager refuses to bring sessions up, so even a
    // lookup for a well-formed id is rejected rather than answered.
    let mngr = server.state.sessions_manager().await;
    assert!(
        mngr.get_session(BoxKeyPredicate::Id(SessionId::nil()))
            .await
            .is_err(),
        "manager should reject session work while shutting down",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_without_force_refuses_while_a_session_is_live() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    // A session is only "busy" once it hosts a live shell (an idle actor
    // no longer blocks an unforced shutdown). Open one and drive an echo
    // round trip so the host is provably up before the shutdown request.
    let mut channel = client.open_shell(session_id).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => panic!("channel closed before the echo arrived"),
        }
    }

    let resp = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    assert_eq!(resp, ShutdownResponse::SessionsLive);

    // The refusal left the daemon fully operational: the live session is
    // still reachable and no shutdown flag was latched.
    let mngr = server.state.sessions_manager().await;
    assert!(
        mngr.get_session(BoxKeyPredicate::Id(session_id))
            .await
            .unwrap()
            .is_some(),
        "an unforced, refused shutdown must not tear down live sessions",
    );
}

/// A session whose shell has exited still holds its host (the slot
/// outlives the process), but nothing runs there for an unforced shutdown
/// to interrupt, so it must not refuse. Driven the way the session e2e
/// meets it: exit the shell, which ends the box, then stop the daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_without_force_proceeds_once_a_sessions_shell_has_exited() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let mut channel = client.open_shell(session_id).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut stdout = Vec::new();
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Data { data }) => {
                stdout.extend_from_slice(&data);
                if String::from_utf8_lossy(&stdout).contains("got:hello") {
                    break;
                }
            }
            Some(_) => {}
            None => panic!("channel closed before the echo arrived"),
        }
    }

    // Exit the shell: the box ends with it, its record kept, and no prompt
    // holds the channel open (BOX-038).
    channel
        .data_bytes(format!("{}\n", crate::box_runtime::MOCK_EXIT_LINE).into_bytes())
        .await
        .unwrap();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), channel.wait()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => panic!("channel stayed open 10s after the shell exited"),
        }
    }

    let mngr = server.state.sessions_manager().await;
    let session = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("an ended box keeps its record");
    // The host loop winds down after the channel closes; bounded wait.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while session.is_busy().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a session whose shell has exited stayed busy",
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let resp = client
        .call::<Shutdown>(&ShutdownRequest { force: false })
        .await;
    assert_eq!(resp, ShutdownResponse::ShuttingDown);
}

#[tokio::test]
async fn shutdown_with_force_tears_down_live_sessions() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let session_id = fresh_session(&mut client).await;

    let mngr = server.state.sessions_manager().await;
    mngr.get_session(BoxKeyPredicate::Id(session_id))
        .await
        .unwrap()
        .expect("freshly-created session should be retrievable");

    // `force` overrides the live-session guard: the daemon shuts down...
    let resp = client
        .call::<Shutdown>(&ShutdownRequest { force: true })
        .await;
    assert_eq!(resp, ShutdownResponse::ShuttingDown);

    // ...and, being in shutdown, refuses to hand out sessions afterwards,
    // with the refusal text the client matches on.
    let refused = mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .await
        .expect_err("a forced shutdown should leave the manager rejecting session work");
    assert_eq!(refused.to_string(), minimald_rpc::SHUTDOWN_REFUSAL);

    // The same refusal reaches a client's `CreateSession` as the stderr
    // text the client-side match keys on, exactly.
    let mut channel = client.open_subsystem(CreateSession::NAME, &[]).await;
    let body = serde_json_lenient::to_vec(&crate::test_harness::create_session_req(
        "after-shutdown",
        "/tmp",
    ))
    .expect("request serializes");
    channel.data_bytes(body).await.unwrap();
    channel.eof().await.unwrap();
    let mut err_buf = Vec::new();
    while let Some(msg) = channel.wait().await {
        if let russh::ChannelMsg::ExtendedData { data, ext: 1 } = msg {
            err_buf.extend_from_slice(&data);
        }
    }
    let stderr = String::from_utf8_lossy(&err_buf);
    assert_eq!(
        stderr,
        format!("Internal error: {}", minimald_rpc::SHUTDOWN_REFUSAL),
        "a create refused in shutdown should carry exactly the refusal",
    );
}

#[tokio::test]
async fn get_mesh_status_is_unconfigured_by_default() {
    // Without a mesh installed, the RPC answers cleanly with `configured =
    // false` rather than erroring (this is also the answer a daemon built
    // without the `networking-wg` feature gives).
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let resp = client.call::<minimald_rpc::GetMeshStatus>(&()).await;

    assert!(!resp.configured);
    assert!(resp.own_public_key.is_none());
    assert!(resp.peers.is_empty());
}

#[cfg(feature = "networking-wg")]
#[tokio::test]
async fn get_mesh_status_reports_own_key_and_peers() {
    use crate::net::wg::{Keypair, MeshConfig, PeerConfig};

    let server = TestServer::new().await;

    // Stand up a real mesh peer with one configured peer and install it.
    let remote = Keypair::generate();
    let cfg = MeshConfig {
        keypair: Keypair::generate(),
        listen_port: 0, // ephemeral; no traffic is sent in this test
        advertised_subnets: vec!["100.64.0.0/16".parse().unwrap()],
        peers: vec![PeerConfig {
            name: "remote".to_string(),
            public_key: remote.public(),
            endpoint: None,
            allowed_ips: vec!["100.65.0.0/16".parse().unwrap()],
        }],
    };
    let (sink_tx, _sink_rx) = tokio::sync::mpsc::channel(1);
    let mesh = std::sync::Arc::new(crate::net::wg::start(cfg, sink_tx).await.unwrap());
    let own_pub = mesh.own_public_key().to_base64();
    server.state.set_mesh(mesh).await;

    let mut client = server.connect().await;
    let resp = client.call::<minimald_rpc::GetMeshStatus>(&()).await;

    assert!(resp.configured);
    assert_eq!(resp.own_public_key.as_deref(), Some(own_pub.as_str()));
    assert_eq!(resp.advertised_subnets, vec!["100.64.0.0/16".to_string()]);
    assert_eq!(resp.peers.len(), 1);
    assert_eq!(resp.peers[0].name, "remote");
    assert_eq!(resp.peers[0].public_key, remote.public().to_base64());
    // Keep the sink alive until the assertions complete.
    drop(_sink_rx);
}

/// The answerer control socket's gate mirrors the VM host daemon's
/// door: the daemon's own uid asks every verb, root only the handover's
/// release and its cancel — a status ask or a box verb from root is
/// refused — and any other uid nothing.
#[test]
fn answerer_control_admits_root_only_the_handover_verbs() {
    let own = 1000;
    for request in [
        BoxControlRequest::AnswererStatus,
        BoxControlRequest::ReleaseAnswerer,
        BoxControlRequest::ReleaseAnswererCancel,
    ] {
        assert!(answerer_control_admits(own, own, &request), "{request:?}");
    }
    assert!(answerer_control_admits(
        0,
        own,
        &BoxControlRequest::ReleaseAnswerer
    ));
    assert!(answerer_control_admits(
        0,
        own,
        &BoxControlRequest::ReleaseAnswererCancel
    ));
    assert!(
        !answerer_control_admits(0, own, &BoxControlRequest::AnswererStatus),
        "root asking the status is refused"
    );
    assert!(
        !answerer_control_admits(
            0,
            own,
            &BoxControlRequest::ReadRow(minimald_rpc::ReadRowRequest {
                name: "web".to_string(),
            })
        ),
        "root asking a row read is refused"
    );
    assert!(!answerer_control_admits(
        4242,
        own,
        &BoxControlRequest::ReleaseAnswerer
    ));
}

/// A stale control socket — a file at the daemon's own path that no
/// listener answers — is unlinked and re-bound; a live one is refused
/// and left in place, never taken out from under the daemon serving it.
#[tokio::test]
async fn answerer_control_rebinds_a_stale_socket_and_refuses_a_live_one() {
    let server = TestServer::new().await;
    let dir = std::path::PathBuf::from(server.state.minimal_state_dir().await.as_str());
    let sock = dir.join(ANSWERER_CONTROL_SOCK_FILE);

    // A corpse: bound, then its listener dropped, so the file stays.
    drop(std::os::unix::net::UnixListener::bind(&sock).expect("a stale socket binds"));
    assert!(sock.exists(), "the stale socket file is left behind");
    spawn_answerer_control(
        &server.state,
        crate::net::answerer::AnswererStatus::starting(),
    )
    .await
    .expect("a stale socket is unlinked and re-bound");
    let mut stream = tokio::net::UnixStream::connect(&sock)
        .await
        .expect("the re-bound socket answers");
    stream
        .write_all(b"{\"verb\":\"answerer_status\"}\n")
        .await
        .expect("the ask is written");
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .await
        .expect("the reply is read");
    assert!(
        reply.contains("state"),
        "the re-bound door answers its own uid a status: {reply}"
    );

    // Live: a second bind at the same path is refused, the file kept.
    let refused = spawn_answerer_control(
        &server.state,
        crate::net::answerer::AnswererStatus::starting(),
    )
    .await
    .expect_err("a live door is not taken");
    assert_eq!(refused.kind(), std::io::ErrorKind::AddrInUse);
    assert!(
        tokio::net::UnixStream::connect(&sock).await.is_ok(),
        "the live door still answers"
    );
}

/// T110: the listing reports each box's address and egress posture, keyed
/// by its id. A host-address box answers at the node's address. An
/// own-address or `none` box answers at the address its publish holds, and
/// reports none before it publishes. The posture is the one the effective
/// policy reply resolves for the same box.
#[tokio::test]
async fn list_sessions_reports_box_address_and_posture() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;

    let host_id = client
        .call::<CreateSession>(&CreateSessionRequest::new(
            "host-address",
            HostAbsPath::try_new("/uwu").unwrap(),
            NetworkMode::HostNet,
            BoxPolicy::new(None, None),
        ))
        .await
        .unwrap()
        .id;
    let own_id = own_ip_session(&mut client, "own-address", BoxPolicy::new(None, None)).await;
    let mut no_net = req("no-network", "/uwu");
    no_net.config.network = NetworkMode::NoNet;
    let none_id = client.call::<CreateSession>(&no_net).await.unwrap().id;

    // Before either box publishes, neither has an address to report.
    let listed = client.call::<ListSessions>(&()).await;
    assert_eq!(
        listed.box_networks[&own_id].loopback_address, None,
        "an unpublished box reports no address, never an invented one"
    );

    let mngr = server.state.sessions_manager().await;
    let own_address = std::net::Ipv4Addr::new(127, 0, 64, 2);
    // The `none` box stands on the `127.0.0.1` fallback, so the reply
    // marks it there, while a host-address box at the node address is not.
    let none_address = std::net::Ipv4Addr::LOCALHOST;
    let node = {
        let registry = mngr.hostnames();
        let mut routes = registry.write().unwrap();
        routes.publish_own_address(own_id, "own-address", own_address, Default::default());
        routes.publish_own_address(none_id, "no-network", none_address, Default::default());
        routes.node_address()
    };

    let listed = client.call::<ListSessions>(&()).await;
    let facts = |id: SessionId| {
        listed
            .box_networks
            .get(&id)
            .cloned()
            .unwrap_or_else(|| panic!("facts for {id} in {:?}", listed.box_networks))
    };
    assert_eq!(
        facts(own_id),
        minimald_rpc::BoxNetworkFacts {
            loopback_address: Some(own_address),
            egress_posture: Some(minimald_rpc::EgressPosture::DenyAllDefault),
            at_fallback: Some(false),
        }
    );
    assert_eq!(
        facts(host_id),
        minimald_rpc::BoxNetworkFacts {
            loopback_address: Some(node),
            egress_posture: Some(minimald_rpc::EgressPosture::AllowAllDefault),
            at_fallback: Some(false),
        }
    );
    assert_eq!(
        facts(none_id),
        minimald_rpc::BoxNetworkFacts {
            loopback_address: Some(none_address),
            egress_posture: Some(minimald_rpc::EgressPosture::NoNetwork),
            at_fallback: Some(true),
        }
    );

    // The posture agrees with the reply `min session policy` reads.
    let policy = client
        .call::<GetEffectiveSessionPolicy>(&GetEffectiveSessionPolicyRequest::Id(own_id))
        .await
        .unwrap();
    assert_eq!(
        minimald_rpc::EgressPosture::of(&policy.egress, NetworkMode::OwnIp),
        minimald_rpc::EgressPosture::DenyAllDefault
    );
    // In a microVM, a host-address box at the node's `127.0.0.1` is not
    // mirrored there, so it reports no address until the node is granted
    // one. A native node's `127.0.0.1` is the box's published address.
    let localhost = std::net::Ipv4Addr::LOCALHOST;
    let granted = std::net::Ipv4Addr::new(127, 0, 64, 1);
    assert_eq!(host_address_loopback(localhost, true), None);
    assert_eq!(host_address_loopback(granted, true), Some(granted));
    assert_eq!(host_address_loopback(localhost, false), Some(localhost));
    // A withheld host-address box is reached only through the proxy, so it
    // reads as the fallback. A box of another mode with no address says
    // nothing.
    assert_eq!(box_at_fallback(true, None), Some(true));
    assert_eq!(box_at_fallback(true, Some(localhost)), Some(false));
    assert_eq!(box_at_fallback(false, Some(localhost)), Some(true));
    assert_eq!(box_at_fallback(false, Some(granted)), Some(false));
    assert_eq!(box_at_fallback(false, None), None);
}
