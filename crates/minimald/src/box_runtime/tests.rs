use paths::DaemonAbsPath;

use super::*;
use std::time::Duration;

use crate::box_actor::tests::{fake_forwarder, fake_report_door, finalize_dynamic_ingress_session};
use crate::test_harness::{TestServer, captured_log};

const DEFAULT_SIZE: WinSize = WinSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

/// Wraps a chunk as a current-generation [`StdinMsg`] for the test
/// harness: hosts here never attach a binding, so the host's active
/// binding generation stays 0.
fn stdin_bytes(b: impl Into<bytes::Bytes>) -> StdinMsg {
    StdinMsg::new(0, StdinMsgKind::Bytes(b.into()))
}

/// Builds the `hakoniwa` account of a normal exit: the inner process
/// reported its own status, so `exit_code` is `Some`.
fn exited(code: i32) -> ExitReason {
    ExitReason {
        code,
        exit_code: Some(code),
        reason: format!("process(/usr/bin/bash) exited with code {code}"),
    }
}

/// Builds the account of a death `hakoniwa` attributes to a signal. Its
/// `new_failure` path leaves `exit_code` `None` and stamps code 125 —
/// the shape a container-level SIGKILL arrives in.
fn signalled(reason: &str) -> ExitReason {
    ExitReason {
        code: 125,
        exit_code: None,
        reason: reason.to_string(),
    }
}

fn eio() -> Option<std::io::Error> {
    Some(std::io::Error::from_raw_os_error(EIO_ON_EXIT))
}

/// The expected teardown, and the reason the prompt is silent by default:
/// a shell the user exited closes the last slave fd, the master reports
/// `EIO`, and the prompt alone tells the whole story.
#[test]
fn a_clean_exit_says_nothing_beyond_the_prompt() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: Some(exited(0)),
    };
    assert!(
        cause.notices().is_empty(),
        "a clean exit must stay silent: {:?}",
        cause.notices(),
    );
}

/// The regression this all exists for. A SIGKILLed container reaches the
/// binding as the *same* `EIO` a clean exit does, so before the exit
/// reason was carried through it rendered the identical silent prompt —
/// a killed session impersonating one the user ended.
#[test]
fn a_signalled_container_is_named_not_silently_passed_off_as_an_exit() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: Some(signalled("container received signal SIGKILL")),
    };
    assert_eq!(
        cause.notices(),
        vec!["Session ended abnormally: container received signal SIGKILL"],
        "a signalled container must say so, despite the expected EIO",
    );
}

/// A non-zero *exit* is still the shell exiting under its own control —
/// `exit 1` is not an anomaly, and must not be dressed up as one.
#[test]
fn a_non_zero_exit_is_still_a_normal_exit() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: Some(exited(1)),
    };
    assert!(
        cause.notices().is_empty(),
        "a non-zero exit is not abnormal: {:?}",
        cause.notices(),
    );
}

/// A master error that is *not* the expected on-exit `EIO` means the
/// session ended without the shell necessarily having died — surfaced as
/// before this change.
#[test]
fn an_unexpected_master_error_is_surfaced() {
    let cause = TeardownCause {
        pty_err: Some(std::io::Error::from_raw_os_error(libc::EINTR)),
        exit: Some(exited(0)),
    };
    let notices = cause.notices();
    assert_eq!(notices.len(), 1, "expected one notice: {notices:?}");
    assert!(
        notices[0].starts_with("Error reading stdout:"),
        "got: {notices:?}",
    );
}

/// The two notices are independent: an unexpected master error and an
/// abnormal end are different facts and both get said.
#[test]
fn both_halves_are_reported_together() {
    let cause = TeardownCause {
        pty_err: Some(std::io::Error::from_raw_os_error(libc::EINTR)),
        exit: Some(signalled("process(/usr/bin/bash) received signal SIGSEGV")),
    };
    let notices = cause.notices();
    assert_eq!(notices.len(), 2, "expected both notices: {notices:?}");
    assert!(notices[0].starts_with("Error reading stdout:"));
    assert_eq!(
        notices[1],
        "Session ended abnormally: process(/usr/bin/bash) received signal SIGSEGV",
    );
}

/// The reap failed, so there is no account of the end. The pty error still
/// governs, and an expected `EIO` still stays silent rather than inventing
/// an anomaly from missing information.
#[test]
fn a_missing_exit_reason_falls_back_to_the_pty_error() {
    let cause = TeardownCause {
        pty_err: eio(),
        exit: None,
    };
    assert!(
        cause.notices().is_empty(),
        "an unknown end is not evidence of an abnormal one: {:?}",
        cause.notices(),
    );
}

/// Which pty failures the host may block on before notifying the binding.
/// Only `EIO` promises a reap that returns; blocking on anything else
/// risks waiting on a live shell, so the user has to be told first.
#[test]
fn only_eio_promises_the_shell_is_already_gone() {
    assert!(
        shell_is_already_gone(&std::io::Error::from_raw_os_error(EIO_ON_EXIT)),
        "EIO is the last slave fd closing — the shell is gone",
    );
    for errno in [libc::EINTR, libc::EBADF, libc::ENXIO] {
        assert!(
            !shell_is_already_gone(&std::io::Error::from_raw_os_error(errno)),
            "errno {errno} can leave a live process; the host must not block on the reap",
        );
    }
}

/// Wires a channel into a host's binding slot and hands back the receiving
/// end, so a test can see exactly what the host tells an attached binding.
/// The join handle is a stand-in — nothing under test awaits it.
fn watch_binding<P: BoxProcess, G: BoxGuard>(host: &mut Host<P, G>) -> mpsc::Receiver<BindingMsg> {
    let (tx, rx) = mpsc::channel(16);
    host.remote = Some((tx, crate::traced::spawn(async {}), CancellationToken::new()));
    rx
}

/// Drains the binding's queue and returns the teardown it was handed — the
/// cause together with the unwind codes that travel with it — if any.
/// Stdout traffic is noise here — the shell echoes its own prompt.
fn teardown_from(rx: &mut mpsc::Receiver<BindingMsg>) -> Option<(TeardownCause, Vec<u8>)> {
    std::iter::from_fn(|| rx.try_recv().ok()).find_map(|msg| match msg {
        BindingMsg::TeardownDueToProcessExit {
            cause,
            unwind_codes,
        } => Some((cause, unwind_codes)),
        _ => None,
    })
}

/// The reorder this change turns on: the binding is told why it is going
/// away only *after* the process has been reaped, so the notice can carry
/// the reap's account of the end. An exit reason on the message is proof
/// of the ordering — notifying from `step`, as this used to, could not
/// have supplied one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_exit_reaches_the_binding_with_the_reaped_exit_reason() {
    let (mut host, _handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let mut rx = watch_binding(&mut host);
    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.mainloop());

    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let (cause, _) = teardown_from(&mut rx).expect("the binding must be told the shell exited");
    assert!(
        cause.notices().is_empty(),
        "a clean exit stays silent: {:?}",
        cause.notices(),
    );
    let exit = cause
        .exit
        .as_ref()
        .expect("the teardown must carry the reap's account of the end");
    assert!(
        !exit.is_abnormal(),
        "a shell that exited on its own is not abnormal: {exit:?}",
    );
}

/// A binding whose client transport has stopped draining must not wedge the
/// host loop. The host forwards each pty read into the binding's mailbox;
/// once that mailbox fills, an unbounded send parked the loop for good, so
/// the host could no longer pump the pty, drain its own mailbox, or observe
/// the shell exiting — one dark client froze the whole session. The host now
/// stops reading the pty while the mailbox is full, keeps serving, and sheds
/// the binding once the stall bound passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_binding_does_not_wedge_the_host_loop() {
    let (mut host, handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");

    // A binding at the production mailbox size, pre-filled to capacity and
    // never drained: the receiver is held open but never read, standing in
    // for a client whose transport has gone dark mid-write. The next
    // forwarded pty read cannot be queued.
    let (tx, _rx_never_drained) = mpsc::channel(4);
    for _ in 0..4 {
        tx.try_send(BindingMsg::Stdin(Vec::new()))
            .expect("pre-fill stays within the mailbox capacity");
    }
    host.remote = Some((tx, crate::traced::spawn(async {}), CancellationToken::new()));
    // Short, so the shed this test goes on to rely on comes quickly.
    host.output_stall_timeout = Duration::from_millis(200);

    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.mainloop());

    // Make the shell echo so the host has output for the full binding, and
    // reads it once the stalled binding has been shed.
    stdin
        .send(stdin_bytes(b"ping\n".to_vec()))
        .await
        .expect("failed to send line");

    // Proof the loop did not wedge: it still answers its mailbox and has
    // stamped the stdout it read. An unbounded forward-send would have
    // parked the loop, and this probe would hang until the outer deadline.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let attrs = handle
                .get_attrs()
                .await
                .expect("host must keep answering its mailbox");
            if attrs.stdout_last.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a stalled binding must not wedge the host loop");

    // The shed bumped the binding generation, so input still stamped with
    // the shed generation must be discarded rather than reach the shell.
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send stale exit line");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !task.is_finished(),
        "input from the shed generation must not reach the shell",
    );

    // The same bytes on the post-shed generation still drive the shell to
    // exit: the host keeps serving after shedding the stalled binding.
    stdin
        .send(StdinMsg::new(
            1,
            StdinMsgKind::Bytes(bytes::Bytes::from(
                format!("{MOCK_EXIT_LINE}\n").into_bytes(),
            )),
        ))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
}

/// Stands in for the daemon's connection handler: accepts any client and
/// hands each session channel it opens to the test.
struct ChannelCatcher(mpsc::UnboundedSender<Channel<Msg>>);

impl russh::server::Handler for ChannelCatcher {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.0.send(channel);
        reply.accept().await;
        Ok(())
    }
}

struct TrustingClient;

impl russh::client::Handler for TrustingClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A host whose shell is attached through a real ssh channel and kept busy
/// printing, plus the client end of that channel.
struct FloodedAttach {
    handle: HostHandle,
    task: JoinHandle<Result<i32, std::io::Error>>,
    channel: russh::Channel<russh::client::Msg>,
    feeder: JoinHandle<()>,
    // Held so the ssh connection stays up.
    _client: russh::client::Handle<TrustingClient>,
}

impl FloodedAttach {
    /// Builds the host with `output_stall_timeout`, attaches it over an
    /// in-process ssh connection, and feeds the shell long lines for as long
    /// as the host takes them. Every line comes back twice, as the tty's echo
    /// and the shell's `got:` line.
    ///
    /// The client's receive window and channel buffer are tiny. A client
    /// that stops reading then stops the server within a few tens of KiB,
    /// where the defaults would let megabytes through first.
    async fn start(output_stall_timeout: Duration) -> Self {
        Self::start_with(output_stall_timeout, DEFAULT_SIZE, &[]).await
    }

    /// [`Self::start`] at terminal size `sz`, with `screen` fed to the host's
    /// screen model before the loop starts, so the attach's redraw renders
    /// that screen.
    async fn start_with(output_stall_timeout: Duration, sz: WinSize, screen: &[u8]) -> Self {
        let (mut host, handle) = Host::build(
            MockLauncher::default(),
            HostParams {
                name: "test-session".to_string(),
                username: "user".to_string(),
                paths: test_paths(),
                sz,
                channel: None,
                control: None,
                delta: None,
                archives_dir: std::env::temp_dir(),
                holds_host_row: false,
                ends_with_entrypoint: false,
                session_id: boxes::SessionId::nil(),
                composition: None,
                connection_env: ConnectionEnv::new(),
                #[cfg(target_os = "linux")]
                name_marker: None,
            },
        )
        .await
        .expect("failed to build host");
        host.output_stall_timeout = output_stall_timeout;
        host.parser.process(screen);
        let stdin = host.remote_tx.clone();
        let task = crate::traced::spawn(host.mainloop());

        let (server_side, client_side) = tokio::net::UnixStream::pair().unwrap();
        let key = russh::keys::PrivateKey::random(
            &mut russh::keys::key::safe_rng(),
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let server_config = Arc::new(russh::server::Config {
            keys: vec![key],
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let client_config = Arc::new(russh::client::Config {
            window_size: 16 * 1024,
            channel_buffer_size: 1,
            ..Default::default()
        });
        let (caught_tx, mut caught) = mpsc::unbounded_channel();
        // The server reads the client's ssh id before it returns, so the two
        // halves have to be driven together.
        let (server, client) = tokio::join!(
            russh::server::run_stream(server_config, server_side, ChannelCatcher(caught_tx)),
            russh::client::connect_stream(client_config, client_side, TrustingClient),
        );
        crate::traced::spawn(server.expect("ssh server handshake"));
        let mut client = client.expect("ssh client handshake");
        let auth = client.authenticate_none("test").await.unwrap();
        assert!(auth.success(), "the test server accepts anyone");
        let channel = client.channel_open_session().await.unwrap();
        let server_channel = caught.recv().await.expect("the server caught the channel");

        assert!(
            handle
                .attach(
                    server_channel,
                    sz,
                    ConnectionEnv::new(),
                    SessionKeys::default(),
                )
                .await
                .is_ok(),
            "the host must take the attach",
        );

        // Stamped with the generation the attach installs. Lines that reach
        // the host before it has processed the attach are dropped as stale,
        // and so is everything after a shed; neither matters here.
        let line = format!("{}\n", "x".repeat(2000));
        let feeder = crate::traced::spawn(async move {
            while stdin
                .send(StdinMsg::new(
                    1,
                    StdinMsgKind::Bytes(bytes::Bytes::from(line.clone())),
                ))
                .await
                .is_ok()
            {}
        });

        Self {
            handle,
            task,
            channel,
            feeder,
            _client: client,
        }
    }

    async fn stop(self) {
        self.feeder.abort();
        let _ = self.handle.kill(false).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

/// A shed must close the client's channel. The client of a shed binding
/// has stopped reading, but it is still connected, and when it reads again
/// it has to find the attach over: EOF, the shed exit status, and a close,
/// so `min` exits and the user can re-attach. Aborting the binding task, as
/// the shed once did, dropped the channel halves, and russh sends no close
/// for those. The client then stayed connected forever with nothing behind
/// it: no output, keystrokes swallowed, no detach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shedding_a_stalled_binding_closes_the_client_channel() {
    let mut attach = FloodedAttach::start(Duration::from_millis(200)).await;

    // Read nothing for long enough that the output backs up to the host and
    // the stall bound passes.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let (mut eof, mut exit_status, mut closed) = (false, None, false);
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = attach.channel.wait().await {
            match msg {
                russh::ChannelMsg::Eof => eof = true,
                russh::ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                russh::ChannelMsg::Close => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(
        drained.is_ok() && closed,
        "the shed binding left the client's channel open (eof: {eof}, exit status: {exit_status:?})",
    );
    assert!(eof, "the channel must see EOF before it closes");
    assert_eq!(
        exit_status,
        Some(SHED_EXIT_STATUS),
        "a shed reports the status that has the client restore the terminal",
    );

    // Only the attach was dropped; the session carries on.
    assert!(
        !attach.task.is_finished(),
        "a shed must not end the session"
    );
    tokio::time::timeout(Duration::from_secs(5), attach.handle.get_attrs())
        .await
        .expect("the host keeps answering after a shed")
        .expect("the host is still running");

    attach.stop().await;
}

/// A big terminal, for a redraw far past what the test client's window and
/// buffers hold unread.
const BIG_SIZE: WinSize = WinSize {
    rows: 200,
    cols: 400,
    xpixel: 0,
    ypixel: 0,
};

/// Paints every cell of a `sz` screen with its own truecolor foreground and
/// background, so the screen's redraw carries an SGR per cell.
fn truecolor_screen(sz: WinSize) -> Vec<u8> {
    let mut out = Vec::new();
    for r in 0..sz.rows {
        out.extend_from_slice(format!("\x1b[{};1H", r + 1).as_bytes());
        for c in 0..sz.cols {
            let (r8, c8) = (r % 256, c % 256);
            out.extend_from_slice(
                format!(
                    "\x1b[38;2;{r8};{c8};{};48;2;{c8};{r8};{}m#",
                    (r + c) % 256,
                    (r * 7 + c) % 256,
                )
                .as_bytes(),
            );
        }
    }
    out.extend_from_slice(b"\x1b[0m\x1b[H");
    out
}

/// scenario 643b: the attach redraw must not be written on the host loop.
/// The host rendered the screen for a new client and awaited its write to
/// the channel right there. russh parks a write while the client's window is
/// spent, so a client whose terminal made the redraw bigger than its unread
/// window, and that never read, stopped the host loop for good: no probes
/// answered, no output pumped, every other client of the session frozen.
/// The redraw now goes to the new binding as its first message, written on
/// the binding's own task and raced against the shed like any stdout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_redraw_the_client_never_reads_does_not_wedge_the_host_loop() {
    let screen = truecolor_screen(BIG_SIZE);
    let mut model = vt100::Parser::new(BIG_SIZE.rows, BIG_SIZE.cols, 0);
    model.process(&screen);
    let redraw = model.screen().state_formatted().len();
    assert!(
        redraw > 1024 * 1024,
        "the redraw must dwarf the client's 16 KiB window and buffers: {redraw} bytes",
    );

    // The client never reads: the redraw alone exhausts its window, and the
    // flood behind it backs the binding's mailbox up into the host.
    let mut attach = FloodedAttach::start_with(Duration::from_millis(200), BIG_SIZE, &screen).await;

    // The probe queues behind the attach in the host's mailbox, so it is
    // answered only once the attach has returned. A redraw written on the
    // host loop never returns, and this times out.
    tokio::time::timeout(Duration::from_secs(10), attach.handle.get_attrs())
        .await
        .expect("an unread attach redraw wedged the host loop")
        .expect("the host is still running");

    // Keep probing past the stall bound: the host goes on serving while the
    // binding is parked on the redraw, and sheds it.
    for _ in 0..10 {
        tokio::time::timeout(
            crate::box_actor::HOST_PROBE_TIMEOUT * 2,
            attach.handle.get_attrs(),
        )
        .await
        .expect("a binding parked on its redraw must not stop the host answering probes")
        .expect("the host is still running");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The parked binding is shed, not left holding the session: reading at
    // last, the client finds the attach over.
    let (mut eof, mut exit_status, mut closed) = (false, None, false);
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = attach.channel.wait().await {
            match msg {
                russh::ChannelMsg::Eof => eof = true,
                russh::ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                russh::ChannelMsg::Close => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(
        drained.is_ok() && closed,
        "the binding parked on its redraw was never shed (eof: {eof}, exit status: {exit_status:?})",
    );
    assert_eq!(
        exit_status,
        Some(SHED_EXIT_STATUS),
        "the attach ends as a shed",
    );
    assert!(
        !attach.task.is_finished(),
        "a shed must not end the session"
    );

    attach.stop().await;
}

/// scenario 643b's control arm: a client that reads its redraw at full speed
/// and types while it is still arriving must get the rest of the redraw and
/// see the shell answer. The binding wrote the redraw with one `write_all`
/// and read nothing from the channel meanwhile; russh queues every window
/// adjust the client sends into that channel's bounded inbound queue and,
/// once it is full, blocks its session loop on the keystroke. A blocked loop
/// applies no more window adjusts, so the write starves on credit the
/// client already granted: the duplex deadlock of #2197, on the attach path.
/// The binding now drains the read half while a write is in flight, and
/// forwards what it read as the host's stdin queue takes it, never parking on
/// that queue with its own mailbox unread (with the shell blocked on output
/// behind a full mailbox, that queue only empties once output moves).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keystroke_typed_mid_redraw_does_not_wedge_the_binding() {
    let screen = truecolor_screen(BIG_SIZE);
    let mut model = vt100::Parser::new(BIG_SIZE.rows, BIG_SIZE.cols, 0);
    model.process(&screen);
    let redraw = model.screen().state_formatted().len();
    // The server's inbound queue holds 100 messages (russh's default) and the
    // client's 16 KiB window sends an adjust per 16 KiB at most, so the queue
    // is full after 1.6 MiB; the keystroke goes in at nine tenths of the
    // redraw, which must be well past that.
    let type_at = redraw * 9 / 10;
    assert!(
        type_at > 100 * 16 * 1024 * 5 / 4,
        "the keystroke must land after the server's inbound queue has filled with window adjusts: {redraw}-byte redraw",
    );

    // The shell keeps printing throughout (the feeder stays on). That is the
    // harder case: with the binding busy on the redraw, its mailbox fills
    // and the host stops reading the pty, so the shell blocks on output and
    // stops reading its input, and the host's stdin queue fills behind the
    // pty. The keystroke must still get through once the client reads.
    let mut attach = FloodedAttach::start_with(Duration::from_secs(30), BIG_SIZE, &screen).await;

    // Read at full speed; type once at nine tenths of the redraw, as the
    // scenario does, when the inbound queue is already full of window adjusts.
    // Waited for: the full redraw, then the shell's own line carrying the
    // keystroke (`got:…ping-643b`).
    let needle = b"ping-643b";
    let (mut got, mut typed, mut tail) = (0usize, false, Vec::new());
    let mut seen = Seen::default();
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(msg) = attach.channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                got += data.len();
                let answered = saw_answer(&mut tail, needle, &data, &mut seen);
                if !typed && got >= type_at {
                    typed = true;
                    attach.channel.data(&b"ping-643b\n"[..]).await.unwrap();
                }
                if got >= redraw && answered {
                    return;
                }
            }
        }
        panic!("the channel closed after {got} of {redraw} redraw bytes (typed: {typed})");
    })
    .await;
    assert!(
        outcome.is_ok(),
        "a keystroke typed mid-redraw wedged the binding: {got} of {redraw} redraw bytes arrived (typed: {typed}), and the shell never answered ({seen:?})",
    );
    assert!(
        !attach.task.is_finished(),
        "the session must outlive a keystroke typed mid-redraw"
    );

    attach.stop().await;
}

/// Scans output as it streams in for the keystroke coming back, line by
/// line (`tail` holds the unfinished last line between chunks, so nothing is
/// re-read). The keystroke comes back twice, as the tty's echo and in the
/// shell's `got:` line, but with the shell printing throughout the two
/// interleave: the echo lands wherever the shell's output was at that
/// moment, and its newline can cut the shell's own line in two. So the
/// shell is taken to have answered when a line carries `got:` before the
/// keystroke, or when the keystroke has come back twice in any form.
fn saw_answer(tail: &mut Vec<u8>, needle: &[u8], data: &[u8], seen: &mut Seen) -> bool {
    tail.extend_from_slice(data);
    while let Some(nl) = tail.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = tail.drain(..=nl).collect();
        seen.lines += 1;
        let at = line.windows(needle.len()).position(|w| w == needle);
        if let Some(at) = at {
            seen.carrying += 1;
            if line[..at].windows(4).any(|w| w == b"got:") {
                seen.answered = true;
            }
        }
    }
    seen.answered || seen.carrying >= 2
}

/// What the client saw while waiting for the shell's answer: how many lines,
/// how many carried the keystroke, and whether one was the shell's.
#[derive(Default, Debug)]
struct Seen {
    lines: usize,
    carrying: usize,
    answered: bool,
}

/// An attach the daemon ended exits non-zero, so a script can tell it from
/// one the user ended. A detach and a session process that exited are the
/// user's own ends and stay 0; a shed keeps ssh's 255.
#[test]
fn daemon_ended_attaches_report_a_non_zero_exit_status() {
    for reason in [
        MainloopExitReason::Shutdown,
        MainloopExitReason::HostGone,
        MainloopExitReason::Superceded,
    ] {
        assert_eq!(
            reason.exit_status(),
            DAEMON_ENDED_EXIT_STATUS,
            "{reason:?} must report the daemon-ended status",
        );
    }
    assert_ne!(DAEMON_ENDED_EXIT_STATUS, 0);
    assert_ne!(
        DAEMON_ENDED_EXIT_STATUS, SHED_EXIT_STATUS,
        "the daemon-ended status must not arm the client's blind unwind",
    );
    assert_eq!(MainloopExitReason::Detach.exit_status(), 0);
    assert_eq!(MainloopExitReason::ProcessExited.exit_status(), 0);
    assert_eq!(MainloopExitReason::Shed.exit_status(), SHED_EXIT_STATUS);
}

/// A terminal that falls behind is slowed down, not dropped. The shed used
/// to fire whenever one forward waited longer than the 2 s probe deadline,
/// which any terminal draining under about 800 KB/s hit while a session
/// printed a few megabytes. Now the host stops reading the pty while the
/// binding catches up, answering probes all the while, and the attach
/// carries on once the client reads again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_reader_is_held_back_not_shed() {
    let mut attach = FloodedAttach::start(OUTPUT_STALL_TIMEOUT).await;

    // Stall well past the probe deadline, probing the host throughout.
    let stall = tokio::time::Instant::now() + 2 * crate::box_actor::HOST_PROBE_TIMEOUT;
    while tokio::time::Instant::now() < stall {
        tokio::time::timeout(
            crate::box_actor::HOST_PROBE_TIMEOUT,
            attach.handle.get_attrs(),
        )
        .await
        .expect("a backed-up binding must not stop the host answering probes")
        .expect("the host is still running");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Reading again, the output keeps coming: far more of it than the
    // stalled pipeline could hold, so the shell was only held up.
    let mut received = 0usize;
    let flowing = tokio::time::timeout(Duration::from_secs(30), async {
        while received < 1024 * 1024 {
            match attach.channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => received += data.len(),
                Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) | None => {
                    panic!("a slow reader was shed after {received} bytes");
                }
                Some(_) => {}
            }
        }
    })
    .await;
    assert!(
        flowing.is_ok(),
        "output stopped after {received} bytes once the client read again",
    );

    attach.stop().await;
}

/// Reads forwarded stdout off the binding channel until `needle` shows up.
/// The host feeds its parser from the same read it forwards, and in that
/// order, so seeing the bytes here proves the screen has already absorbed
/// them — which is what keeps the assertion below off a race with the mock
/// shell's echo.
async fn await_forwarded(rx: &mut mpsc::Receiver<BindingMsg>, needle: &[u8]) {
    let mut seen: Vec<u8> = Vec::new();
    let wait = async {
        while let Some(msg) = rx.recv().await {
            if let BindingMsg::Stdin(b) = msg {
                seen.extend_from_slice(&b);
                if seen.windows(needle.len()).any(|w| w == needle) {
                    return;
                }
            }
        }
        panic!("the binding channel closed before the session echoed {needle:?}");
    };
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for the session to echo {needle:?}"));
}

/// #1210: a process that dies while a full-screen app still has mouse
/// reporting on must hand the binding the codes that turn it back off. The
/// exit notices and the shell-exit prompt render into that same terminal,
/// and the user keeps it after answering — so this teardown has to carry
/// the unwind exactly as detach, supercede, and shutdown do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_exit_hands_the_binding_the_codes_that_leave_mouse_mode() {
    let (mut host, _handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let mut rx = watch_binding(&mut host);
    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.mainloop());

    // The mock shell echoes every line back, which is how a test drives the
    // host's screen into the state a full-screen app leaves behind: here,
    // any-motion mouse tracking left on.
    const MOUSE_ON: &[u8] = b"\x1b[?1003h";
    const MOUSE_OFF: &[u8] = b"\x1b[?1003l";
    let mut line = MOUSE_ON.to_vec();
    line.push(b'\n');
    stdin
        .send(stdin_bytes(line))
        .await
        .expect("failed to send the mouse-enable line");
    await_forwarded(&mut rx, MOUSE_ON).await;

    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let (_, unwind) = teardown_from(&mut rx).expect("the binding must be told the shell exited");
    assert!(
        unwind.windows(MOUSE_OFF.len()).any(|w| w == MOUSE_OFF),
        "the teardown must leave mouse mode: {unwind:?}",
    );
}

/// The host's unwind codes are deliberately *narrow*: it has a screen
/// model, so it emits only the modes this session actually set. That is
/// the whole reason the daemon-side set is better than the `min` client's
/// blind fallback, and it is what keeps `\x1b[?1049l` — the one sequence
/// that is not inert against a terminal on the normal buffer — off the
/// wire for a session that never left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unwind_codes_narrow_to_what_the_screen_actually_set() {
    let (host, _handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");

    // A pristine screen: no alternate buffer, no hidden cursor, no input
    // modes to diff. Only the two unconditional resets may appear.
    let codes = host.unwind_codes();
    let rendered = String::from_utf8_lossy(&codes).into_owned();
    assert!(
        !rendered.contains(boxes::terminal::LEAVE_ALT_SCREEN),
        "rmcup must not be sent for a session that never left the normal buffer: {rendered:?}",
    );
    assert!(
        !rendered.contains(boxes::terminal::SHOW_CURSOR),
        "the cursor was never hidden, so nothing should unhide it: {rendered:?}",
    );
    assert_eq!(
        rendered,
        format!(
            "{}{}",
            boxes::terminal::SGR_RESET,
            boxes::terminal::FOCUS_REPORTING_OFF
        ),
        "a clean screen unwinds to the two blind resets and nothing else",
    );
}

/// A deliberate kill must not raise a shell-exit prompt: the caller already
/// decided the session's fate. `Message::Kill` returns `Err` from `step`
/// exactly as a pty failure does, so only the absence of a stashed pty
/// error keeps the two apart — an invariant a refactor could quietly drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kill_tells_the_binding_nothing() {
    let (mut host, handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let mut rx = watch_binding(&mut host);
    let task = crate::traced::spawn(host.mainloop());

    handle
        .kill(false)
        .await
        .expect("kill should reach the host");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("host mainloop should terminate after kill")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    assert!(
        teardown_from(&mut rx).is_none(),
        "a kill is not a shell exit and must raise no prompt",
    );
}

/// Builds a mock host under `name`, so a test can pick its own lines out of
/// the process-wide log capture.
async fn reap_log_host(name: &str) -> (Host<MockProcess, ()>, HostHandle) {
    Host::build(
        MockLauncher::default(),
        HostParams {
            name: name.to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host")
}

/// The captured log lines that name session `name`.
fn reap_lines(capture: &crate::test_harness::CaptureWriter, name: &str) -> Vec<String> {
    let field = format!("session={name} ");
    capture
        .contents()
        .lines()
        .filter(|l| l.contains(&field) && l.contains("session process reaped"))
        .map(str::to_string)
        .collect()
}

/// A destroy kills the leader, and the reap then reports the same SIGKILL an
/// OOM kill does. The kill was asked for, so the reap is logged at info as a
/// requested teardown, never as the warn a real abnormal death gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_requested_kill_logs_its_reap_at_info() {
    let capture = captured_log();
    let (host, handle) = reap_log_host("reap-requested").await;
    let task = crate::traced::spawn(host.mainloop());

    handle
        .kill(false)
        .await
        .expect("kill should reach the host");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("host mainloop should terminate after kill")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let lines = reap_lines(&capture, "reap-requested");
    assert_eq!(lines.len(), 1, "exactly one reap line: {lines:?}");
    let line = &lines[0];
    assert!(
        line.contains(" INFO ") && line.contains("session process reaped after requested teardown"),
        "a requested kill reaps at info: {line}",
    );
}

/// The other half: a leader killed by something nobody asked — an OOM kill,
/// an external SIGKILL — still reaps with the warn and `abnormal=true`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrequested_kill_still_warns_abnormal() {
    let capture = captured_log();
    let (mut host, _handle) = reap_log_host("reap-unrequested").await;
    let pid = host.container_pid();
    let mut rx = watch_binding(&mut host);
    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.mainloop());

    // Kill only once the loop is parked in `step`, as it is for a live
    // session: killed before its first `try_wait`, the shell is reaped there
    // and never reaches the pty/step path this test is about.
    stdin
        .send(stdin_bytes(b"ready\n".to_vec()))
        .await
        .expect("failed to send a line to the shell");
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !String::from_utf8_lossy(&seen).contains("got:ready") {
            match rx.recv().await {
                Some(BindingMsg::Stdin(b)) => seen.extend_from_slice(&b),
                Some(_) => {}
                None => panic!("the binding closed before the shell echoed"),
            }
        }
    })
    .await
    .expect("the shell should echo before it is killed");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let pid = libc::pid_t::try_from(pid).expect("pid fits in pid_t");
    // SAFETY: `kill` takes plain integers; `pid` is the mock shell this test
    // spawned, which has not been reaped yet.
    let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(rc, 0, "failed to SIGKILL the mock shell");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("host mainloop should terminate after the shell dies")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");

    let lines = reap_lines(&capture, "reap-unrequested");
    assert_eq!(lines.len(), 1, "exactly one reap line: {lines:?}");
    let line = &lines[0];
    assert!(
        line.contains(" WARN ")
            && line.contains("session process reaped after pty/step error")
            && line.contains("abnormal=true"),
        "an unrequested SIGKILL reaps as an abnormal warn: {line}",
    );
}

/// Precedence: the launcher `baseline` sits below the client-forwarded
/// `inherited`, which sits below the composition, which sits below the
/// per-connection `connection` facts. Later layers win on a shared key;
/// non-colliding keys from every layer survive.
#[test]
fn layer_session_env_precedence() {
    let sv = |k: &str, v: &str| (k.to_string(), v.to_string());
    let env = layer_session_env(
        // baseline: its LANG is overridden by inherited; NAME survives.
        vec![sv("LANG", "C"), sv("NAME", "box-1")],
        // inherited: LANG is overridden by composition; TZ survives.
        vec![sv("LANG", "de_DE.UTF-8"), sv("TZ", "Europe/Berlin")],
        // composition: beats inherited LANG; its TERM is overridden by the
        // connection; EDITOR survives.
        vec![
            sv("LANG", "fr_FR.UTF-8"),
            sv("TERM", "dumb"),
            sv("EDITOR", "hx"),
        ],
        // connection: authoritative TERM.
        vec![sv("TERM", "xterm-256color")],
    );

    assert_eq!(env.get("LANG").map(String::as_str), Some("fr_FR.UTF-8")); // composition > inherited > baseline
    assert_eq!(env.get("NAME").map(String::as_str), Some("box-1")); // baseline-only survives
    assert_eq!(env.get("TZ").map(String::as_str), Some("Europe/Berlin")); // inherited-only survives
    assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color")); // connection > composition
    assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx")); // composition-only survives
    assert_eq!(env.len(), 5);
}

/// A composed `SHELL` reaches the layered map, which is the input
/// the launcher hands [`crate::attach_shell::resolve`] to pick the
/// shell it spawns. Nothing else sets the key — the sandbox's
/// `/usr/bin/bash` default lives a layer below this, inside
/// `sandbox`'s `command_env` — so its absence here is exactly the
/// "no shell was asked for" case that keeps bash the default.
#[test]
fn a_composed_shell_reaches_the_layered_env() {
    let sv = |k: &str, v: &str| (k.to_string(), v.to_string());
    let without = layer_session_env(
        session_baseline_env("box-1", None),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        without.get("SHELL"),
        None,
        "nothing but a composition may name the session's shell",
    );

    let with = layer_session_env(
        session_baseline_env("box-1", None),
        Vec::new(),
        vec![sv("SHELL", "/usr/bin/fish")],
        Vec::new(),
    );
    assert_eq!(with.get("SHELL").map(String::as_str), Some("/usr/bin/fish"));
}

/// The per-attach environment is written in each shell's own syntax, with
/// values quoted so a terminal name carrying shell metacharacters is
/// data rather than code, plus a JSON form for shells that read data
/// instead of evaluating a script. An empty map writes nothing at all: an
/// attach that carries no facts leaves the last known ones standing.
#[tokio::test]
async fn write_connection_env_renders_every_form() {
    let tmp = tempfile::tempdir().unwrap();
    let home =
        DaemonAbsPath::try_new(camino::Utf8PathBuf::try_from(tmp.path().to_path_buf()).unwrap())
            .unwrap();
    let sh = home.sub_path_unchecked(ATTACH_ENV_SH_REL);
    let fish = home.sub_path_unchecked(ATTACH_ENV_FISH_REL);
    let json = home.sub_path_unchecked(ATTACH_ENV_JSON_REL);

    write_connection_env(home.clone(), ConnectionEnv::new()).await;
    for path in [&sh, &json] {
        assert!(
            !std::fs::exists(path.as_str()).unwrap(),
            "an empty attach has nothing to publish"
        );
    }

    let env: ConnectionEnv = [
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("ODD".to_string(), "it's \\ odd".to_string()),
    ]
    .into_iter()
    .collect();
    write_connection_env(home, env).await;

    let sh = std::fs::read_to_string(sh.as_str()).unwrap();
    assert!(sh.contains("export TERM='xterm-256color'"), "{sh}");
    // POSIX has no escape inside single quotes: close, escape, reopen.
    assert!(sh.contains(r"export ODD='it'\''s \ odd'"), "{sh}");

    let fish = std::fs::read_to_string(fish.as_str()).unwrap();
    assert!(fish.contains("set -gx TERM 'xterm-256color'"), "{fish}");
    // fish does take a backslash escape, and escapes the backslash too.
    assert!(fish.contains(r"set -gx ODD 'it\'s \\ odd'"), "{fish}");

    // The JSON form round-trips the values themselves rather than a
    // rendering of them, and carries nothing but the variables — every
    // key in it becomes one, so a "generated by" banner would too.
    let json = std::fs::read_to_string(json.as_str()).unwrap();
    let back: ConnectionEnv = serde_json_lenient::from_str(&json).expect("{json}");
    assert_eq!(back.get("TERM").map(String::as_str), Some("xterm-256color"));
    assert_eq!(back.get("ODD").map(String::as_str), Some("it's \\ odd"));
    assert_eq!(back.len(), 2, "{json}");
}

/// The launcher baseline seeds the session's identity plus the
/// once-only orientation banner pair: the session name verbatim in
/// `MINIMAL_SESSION_NAME`, the self-unsetting `PROMPT_COMMAND`
/// trigger, and a STATIC `MINIMAL_MOTD` template that defers the
/// dynamic parts to print time — env interpolation for the name and
/// loadout list (with `${VAR:-fallback}` unset-safety), a direct
/// in-shell filesystem test of the session workspace for the
/// blueprint clause (never a var: the client can't know the
/// workspace's state).
#[test]
fn layer_session_env_seeds_baseline_banner() {
    let env = layer_session_env(
        session_baseline_env("api-server-4f2a", Some("default (built-in)")),
        vec![],
        vec![],
        vec![],
    );

    assert_eq!(
        env.get("MINIMAL_SESSION_NAME").map(String::as_str),
        Some("api-server-4f2a")
    );
    // The loadout list is seeded daemon-side from the composition's
    // first-class orientation field — never from a user var.
    assert_eq!(
        env.get("MINIMAL_LOADOUTS").map(String::as_str),
        Some("default (built-in)")
    );
    let pc = env.get("PROMPT_COMMAND").expect("baseline PROMPT_COMMAND");
    assert!(pc.contains(r#"eval "$MINIMAL_MOTD""#));
    assert!(pc.contains("unset PROMPT_COMMAND MINIMAL_MOTD"));
    // The banner and the per-attach environment are deliberately not
    // wired together: this variable is composed, so a loadout could
    // replace it (and the MOTD recipe unsets it outright). The refresh
    // lives in the shell hooks `crate::env` installs into the rootfs.
    assert!(
        !pc.contains("MINIMAL_ATTACH_ENV"),
        "the refresh must not ride on a composed variable: {pc}"
    );

    // The paths are still named in the environment, for anything
    // scripting against them; the hooks themselves do not read these.
    assert_eq!(
        env.get("MINIMAL_ATTACH_ENV").map(String::as_str),
        Some("/home/.local/state/minimal/attach-env.sh")
    );
    assert_eq!(
        env.get("MINIMAL_ATTACH_ENV_FISH").map(String::as_str),
        Some("/home/.local/state/minimal/attach-env.fish")
    );
    assert_eq!(
        env.get("MINIMAL_ATTACH_ENV_JSON").map(String::as_str),
        Some("/home/.local/state/minimal/attach-env.json")
    );
    // The POSIX tier's only startup hook. Unlike the other shells' hooks
    // this one has to be a variable, because a plain `sh` reads nothing
    // else — so the baseline names the daemon-owned file.
    assert_eq!(
        env.get("ENV").map(String::as_str),
        Some("/usr/share/minimal/attach-env-posix.sh")
    );

    let motd = env.get("MINIMAL_MOTD").expect("baseline MINIMAL_MOTD");
    assert!(motd.starts_with("[ -t 1 ]"), "banner must be TTY-gated");
    // Static template, dynamic vars: interpolated in-shell, unset-safe.
    assert!(motd.contains("${MINIMAL_SESSION_NAME:-"));
    assert!(motd.contains("${MINIMAL_LOADOUTS:-"));
    // The detach hint is a third %s filled by the negotiated keys var,
    // with the default chord as the unset fallback.
    assert!(motd.contains("detach: %s"));
    assert!(motd.contains("${MINIMAL_DETACH_HINT:-ctrl-] then d}"));
    // The blueprint clause tests the session workspace itself at
    // print time — both mfile layouts — pinned to the same constant
    // that is the shell's initial cwd.
    assert!(motd.contains("[ -f /workbench/minimal.toml ]"));
    assert!(motd.contains("[ -f /workbench/.minimal/minimal.toml ]"));
    assert!(
        !motd.contains("MINIMAL_BLUEPRINT"),
        "blueprint is a session-filesystem fact, not an env var"
    );
    assert!(motd.contains("min init"));
}

/// The detach hint in the orientation banner reflects the negotiated
/// session keys: when the connection layer seeds `MINIMAL_DETACH_HINT`
/// (the daemon does this from the channel's key env vars at attach), the
/// layered env carries it so the banner's `${MINIMAL_DETACH_HINT:-…}`
/// renders the actual chord rather than the default fallback.
#[test]
fn connection_layer_seeds_negotiated_detach_hint() {
    let env = layer_session_env(
        session_baseline_env("box-1", None),
        vec![],
        vec![],
        vec![(
            "MINIMAL_DETACH_HINT".to_string(),
            "ctrl-^ then x".to_string(),
        )],
    );
    assert_eq!(
        env.get("MINIMAL_DETACH_HINT").map(String::as_str),
        Some("ctrl-^ then x"),
    );
}

/// A missing loadout display (old client / no composition) leaves
/// `MINIMAL_LOADOUTS` unset so the templates' own `${…:-}` fallbacks
/// render, each correct for its surface.
#[test]
fn baseline_env_omits_loadouts_var_when_display_unknown() {
    let env = layer_session_env(session_baseline_env("box-1", None), vec![], vec![], vec![]);
    assert!(!env.contains_key("MINIMAL_LOADOUTS"));
    assert!(env.contains_key("MINIMAL_SESSION_NAME"));
}

/// A composed `PROMPT_COMMAND` — a user loadout's, or the built-in
/// default's — overrides the baseline banner trigger cleanly, while
/// the baseline identity vars survive for that override to
/// interpolate.
#[test]
fn composed_prompt_command_overrides_baseline_banner() {
    let env = layer_session_env(
        session_baseline_env("box-1", Some("helix, fish")),
        vec![],
        vec![(
            "PROMPT_COMMAND".to_string(),
            r#"eval "$MY_MOTD""#.to_string(),
        )],
        vec![],
    );

    assert_eq!(
        env.get("PROMPT_COMMAND").map(String::as_str),
        Some(r#"eval "$MY_MOTD""#)
    );
    assert_eq!(
        env.get("MINIMAL_SESSION_NAME").map(String::as_str),
        Some("box-1")
    );
    assert_eq!(
        env.get("MINIMAL_LOADOUTS").map(String::as_str),
        Some("helix, fish")
    );
}

#[test]
fn open_and_get_fds() {
    let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
    assert!(pty.master_fd() >= 0);
    assert!(pty.slave_fd() >= 0);
    assert_ne!(pty.master_fd(), pty.slave_fd());
}

/// A wide glyph occupies two grid cells; the snapshot must emit only the
/// glyph itself, not a placeholder space for its continuation cell, so
/// the flattened row keeps the terminal's display width.
#[test]
fn screen_snapshot_drops_wide_continuation_cells() {
    let mut parser = vt100::Parser::new(2, 10, 0);
    parser.process("abあcd".as_bytes());
    let snapshot = screen_to_snapshot(parser.screen());
    let text: String = snapshot.lines[0].cells.iter().map(|c| c.ch).collect();
    assert_eq!(text.trim_end(), "abあcd");
}

#[test]
fn hvp_positions_like_cup() {
    // btop positions exclusively with HVP (`f`); it must behave like CUP
    // (gominimal/minimal#1197). Guards the gominimal/vt100-rust fork's
    // patch against being dropped.
    let mut parser = vt100::Parser::new(5, 10, 0);
    parser.process("\u{1b}[3;7fX\u{1b}[fY".as_bytes());
    assert_eq!(parser.screen().cell(2, 6).unwrap().contents(), "X");
    assert_eq!(parser.screen().cell(0, 0).unwrap().contents(), "Y");
    assert_eq!(parser.screen().cursor_position(), (0, 1));
}

#[test]
fn open_sets_initial_size() {
    let size = WinSize {
        rows: 40,
        cols: 120,
        xpixel: 0,
        ypixel: 0,
    };
    let pty = Pty::open(size).expect("failed to open pty");

    let got = pty.get_size().expect("failed to get size");
    assert_eq!(got.rows, 40);
    assert_eq!(got.cols, 120);
}

#[test]
fn dup_fd_produces_independent_fd() {
    let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
    let (master, _slave) = pty.into_fds();
    let duped = dup_fd(&master).expect("failed to dup fd");
    assert!(duped.as_raw_fd() >= 0);
    assert_ne!(master.as_raw_fd(), duped.as_raw_fd());
}

#[test]
fn win_size_from_requested_pty_clamps_oversized() {
    let requested = RequestedPty {
        char_sizes: (u32::MAX, u32::MAX),
        pixel_sizes: (0, 0),
        term: String::new(),
        modes: Vec::new(),
    };
    let size = WinSize::from(&requested);
    assert_eq!(size.cols, u16::MAX);
    assert_eq!(size.rows, u16::MAX);
}

#[test]
fn set_and_get_size() {
    let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");

    let size = WinSize {
        rows: 50,
        cols: 200,
        xpixel: 0,
        ypixel: 0,
    };
    pty.set_size(size).expect("failed to set size");

    let got = pty.get_size().expect("failed to get size");
    assert_eq!(got.rows, 50);
    assert_eq!(got.cols, 200);
}

/// Drives a host backed by the mock echo program and confirms the terminal
/// attributes are tracked and surfaced via [`HostHandle::get_attrs`]:
/// feeding stdin an OSC "set window title" escape makes the mock echo it
/// back onto the terminal, where the parser records the title; the round
/// trip also stamps the stdin/stdout activity times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_attrs_tracks_title_and_io_times() {
    // Build the host directly (no SSH binding) so the test can feed stdin
    // through a clone of the host's own remote sender, then drive its
    // runtime loop on a background task.
    let (host, handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: BoxPaths {
                working: DaemonAbsPath::root(),
                cache: DaemonAbsPath::root(),
                home: DaemonAbsPath::root(),
                patches: DaemonAbsPath::root(),
                hooks: DaemonAbsPath::root(),
            },
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    crate::traced::spawn(host.mainloop());

    // OSC "set window title" (ESC ] 0 ; <title> BEL), sent as one line. The
    // mock echoes the line back (prefixed with `got:`), so the raw escape
    // reaches the host's terminal parser on stdout and fires the set-title
    // callback. The trailing newline is what makes the mock's `read` return
    // and echo via `printf`, carrying the escape bytes through unmangled.
    let title = "hello-title";
    let osc = format!("\x1b]0;{title}\x07\n");
    stdin
        .send(stdin_bytes(osc.into_bytes()))
        .await
        .expect("failed to send stdin");

    // Poll until the title has been recorded (or time out).
    let attrs = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let attrs = handle.get_attrs().await.unwrap();
            if attrs.title.is_some() {
                break attrs;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timed out waiting for the terminal title to be recorded");

    let (got_title, _when) = attrs.title.expect("title should be set");
    assert_eq!(
        got_title, title,
        "the parsed title should match what was set"
    );

    // The stdin write and the echoed stdout should both have stamped their
    // last-activity times.
    assert!(
        attrs.stdin_last.is_some(),
        "stdin_last should be stamped after feeding stdin",
    );
    assert!(
        attrs.stdout_last.is_some(),
        "stdout_last should be stamped after the echo arrived",
    );
}

/// Killing a host tears it down cleanly: the runtime loop observes the
/// process die (its slave fds close, so the master reports `EIO`), reaps it,
/// and returns — the task terminates without panicking or leaking a zombie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_tears_down_host_and_reaps_process() {
    let (host, handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: BoxPaths {
                working: DaemonAbsPath::root(),
                cache: DaemonAbsPath::root(),
                home: DaemonAbsPath::root(),
                patches: DaemonAbsPath::root(),
                hooks: DaemonAbsPath::root(),
            },
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let task = crate::traced::spawn(host.mainloop());

    handle
        .kill(false)
        .await
        .expect("kill should reach the host");

    // The mainloop must terminate (task resolves) without panicking. A
    // `JoinError` here would mean the host task panicked during teardown.
    let outcome = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("host mainloop should terminate after kill")
        .expect("host task should not panic during teardown");
    assert!(
        outcome.is_ok(),
        "mainloop should return the reaped exit status, got: {outcome:?}",
    );
}

/// A kill aimed at a host whose loop has stopped draining its mailbox
/// gives up on its own deadline instead of parking forever. Left
/// unbounded, this send blocked once the mailbox filled — the wedged-host
/// hang behind a stuck `min stop` and, via the same send, `min session
/// attach`.
#[tokio::test(start_paused = true)]
async fn kill_to_a_wedged_host_gives_up_instead_of_parking() {
    // Holding the mailbox is what makes the host wedged: it accepts
    // messages up to its capacity and never drains one.
    let (host, _mailbox) = HostHandle::wedged();

    // Queue past the mailbox so the next send has to block trying to
    // enqueue at all — the case an unbounded send never returned from.
    for _ in 0..HOST_MAILBOX_CAPACITY {
        host.kill(false)
            .await
            .expect("queuing into an open mailbox should succeed");
    }

    // Far longer than the send's own deadline, so under the paused clock
    // the send's timeout is the one that fires; reaching this outer bound
    // would mean the send had no deadline at all.
    let outcome = tokio::time::timeout(Duration::from_secs(600), host.kill(false))
        .await
        .expect("a bounded kill must return on its own deadline, not park forever");
    assert!(
        outcome.is_err(),
        "a kill that cannot be queued before the deadline must report failure",
    );
}

/// A [`sandbox::NetGuard`] that records whether its teardown ran, so a test
/// can assert the session's network is released exactly when the shell
/// process ends — and left up while it is merely detached.
struct RecordingNetGuard {
    torn_down: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl sandbox::NetGuard for RecordingNetGuard {
    fn teardown(
        self: Box<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        self.torn_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {})
    }
}

fn test_paths() -> BoxPaths {
    BoxPaths {
        working: DaemonAbsPath::root(),
        cache: DaemonAbsPath::root(),
        home: DaemonAbsPath::root(),
        patches: DaemonAbsPath::root(),
        hooks: DaemonAbsPath::root(),
    }
}

/// The load-bearing half of "detach != exit": when the shell process exits,
/// the session network is torn down. Pins the teardown in `mainloop` so a
/// refactor cannot silently leave a lease/switch attachment leaked after exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_releases_the_network() {
    let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (host, _handle) = Host::build(
        MockLauncher::with_net_guard(Box::new(RecordingNetGuard {
            torn_down: torn_down.clone(),
        })),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.mainloop());

    // While the shell is alive the network must stay up.
    assert!(
        !torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "network must not be torn down while the shell is running",
    );

    // Make the shell exit; the network must then be released.
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
    assert!(
        torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "network must be torn down once the shell exits",
    );
}

/// The other half of "detach != exit": the detach chord (leader then `d`)
/// is swallowed as a detach signal — never forwarded to the shell — and does
/// not end the session or release the network. The shell keeps running (a
/// later line still round-trips) and only an explicit kill/exit releases the
/// network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_keystroke_holds_the_session_and_network() {
    let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (host, handle) = Host::build(
        MockLauncher::with_net_guard(Box::new(RecordingNetGuard {
            torn_down: torn_down.clone(),
        })),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.mainloop());

    // The default detach chord is `ctrl-]` (0x1d, the leader) then `d`.
    // Both bytes are consumed by the command-mode state machine rather
    // than written to the pty: the leader enters command mode, `d`
    // detaches. (The host is built without a binding, so the detach is a
    // no-op on the channel — what matters is that neither byte reaches
    // the shell.)
    stdin
        .send(stdin_bytes(vec![0x1d]))
        .await
        .expect("failed to send leader");
    stdin
        .send(stdin_bytes(b"d".to_vec()))
        .await
        .expect("failed to send detach key");

    // The shell survived the detach: a normal line still echoes back, which
    // stamps stdout activity. (If the chord had been forwarded or had killed
    // the process, no echo would ever arrive.)
    stdin
        .send(stdin_bytes(b"ping\n".to_vec()))
        .await
        .expect("failed to send line after detach");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let attrs = handle.get_attrs().await.unwrap();
            if attrs.stdout_last.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("echo should arrive, proving the shell survived the detach keystroke");
    assert!(
        !torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "detach must not tear down the network while the shell is still running",
    );

    // Only now, on an explicit kill (destroy), is the network released.
    handle.kill(true).await.expect("kill should reach the host");
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("mainloop should terminate after kill")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
    assert!(
        torn_down.load(std::sync::atomic::Ordering::SeqCst),
        "kill/destroy must release the network",
    );
}

/// The PTY write queue appends: bytes queued later land *after* anything
/// already buffered, so an idle chord-candidate flush can never overwrite
/// forwarded input still waiting on an unwritable pty.
#[test]
fn queue_stdin_appends_after_unwritten_remainder() {
    // Two bytes of a queued chunk written; three still pending. The flush
    // must not resurrect the written prefix or drop either remainder.
    let mut buf = Some((bytes::Bytes::from_static(b"abcde"), 2));
    queue_stdin(&mut buf, vec![0x1b]);
    let (pending, written) = buf.as_ref().unwrap();
    assert_eq!(*written, 0);
    assert_eq!(&pending[..], b"cde\x1b");

    // An empty queue takes the new bytes wholesale.
    let mut buf = None;
    queue_stdin(&mut buf, vec![0x1d, 0x64]);
    let (pending, written) = buf.as_ref().unwrap();
    assert_eq!(*written, 0);
    assert_eq!(&pending[..], b"\x1d\x64");
}

/// Input stamped with a stale binding generation — what a superseded
/// binding left queued in the shared stdin channel — must never reach
/// the shell. (A real supersession attaches a new channel; here no
/// binding ever attaches, so the active generation stays 0 and a manual
/// generation-1 message stands in for the queued leftovers.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_binding_generation_input_is_discarded() {
    let (host, _handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let stdin = host.remote_tx.clone();
    let mut task = crate::traced::spawn(host.mainloop());

    // The exit sentinel on a stale generation: if this reached the shell
    // the mainloop would reap the process and the task would complete.
    stdin
        .send(StdinMsg::new(
            1,
            StdinMsgKind::Bytes(bytes::Bytes::from(
                format!("{MOCK_EXIT_LINE}\n").into_bytes(),
            )),
        ))
        .await
        .expect("failed to send stale stdin");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !task.is_finished(),
        "stale-generation input must not reach the shell",
    );

    // The same bytes on the active generation must still go through.
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send stdin");
    tokio::time::timeout(Duration::from_secs(10), &mut task)
        .await
        .expect("mainloop should terminate after the shell exits")
        .expect("host task should not panic during teardown")
        .expect("mainloop should return the reaped exit status");
}

// ---------------------------------------------------------------------
// NET-079: the daemon in a classifier leaf of its own, and every box's
// leaf placed in a cohort it is a sibling of.
// ---------------------------------------------------------------------

/// The files the kernel makes when it makes a cgroup — `cgroup.procs`,
/// `cgroup.threads`, `cgroup.subtree_control` — modelled empty over a
/// stand-in tree, which has no kernel behind it to make them. Modelling them
/// is what makes a stand-in the installer's tree: directories delegated to
/// the daemon's account, with the kernel's own files in them, and nothing
/// left for the entry to make but the migration.
const CGROUP_KERNEL_FILES: [&str; 3] = ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"];

/// Stands in for the kernel over a stand-in tree: writes
/// [`CGROUP_KERNEL_FILES`] into `dir`, empty, as the kernel leaves them when
/// it makes a cgroup.
fn model_cgroup_files(dir: &std::path::Path) {
    for name in CGROUP_KERNEL_FILES {
        std::fs::write(dir.join(name), "")
            .unwrap_or_else(|e| panic!("modeling {name} in {}: {e}", dir.display()));
    }
}

/// The daemon enters a classifier leaf of its own at start: `<root>/daemon`,
/// a **sibling** of every box leaf — never the tree root, where enabling a
/// controller would make the box leaves unusable and where the daemon's own
/// fetches could not be told apart from a box's, and never inside `boxes/`,
/// the cohort that holds boxes and nothing else.
///
/// The placement is this process's pid written to its leaf's `cgroup.procs`,
/// the one migration primitive the whole classifier rests on. Asserted over
/// a stand-in tree because the host running this test may have no cgroup2 of
/// its own: on a real tree the kernel holds the membership, and the write
/// that performs the migration is the same either way. Natively the
/// installer owns the tree — the slice itself delegated to the daemon's
/// account, `daemon/` and `boxes/` made, the kernel's files in them — and a
/// daemon that cannot enter it is left outside, its boxes unenforced; only
/// the guest's pid 1 builds the tree, on the cgroup2 it mounted itself.
#[test]
fn daemon_enters_its_own_leaf() {
    let tree = tempfile::tempdir().expect("a temp dir standing in for the tree");
    let root = tree.path();

    // The installer's tree, as a stand-in holds it: both directories made,
    // and the kernel's files modelled into the daemon's leaf, because
    // nothing behind the stand-in makes them at `mkdir` time.
    std::fs::create_dir_all(sandbox::classifier::daemon_leaf(root))
        .expect("the installer makes the daemon's leaf");
    std::fs::create_dir_all(root.join(sandbox::classifier::BOXES_DIR))
        .expect("the installer makes the box cohort");
    model_cgroup_files(&sandbox::classifier::daemon_leaf(root));

    sandbox::classifier::enter_daemon_leaf(root)
        .expect("the daemon enters its own leaf in the installer's tree");

    let daemon = sandbox::classifier::daemon_leaf(root);
    let procs = daemon.join("cgroup.procs");
    assert_eq!(
        std::fs::read_to_string(&procs).expect("reading the daemon leaf's procs file"),
        format!("{}\n", std::process::id()),
        "the daemon is placed by writing its own pid to its leaf's cgroup.procs"
    );
    assert_eq!(
        daemon,
        root.join(sandbox::classifier::DAEMON_LEAF),
        "the daemon's leaf is one component under the tree root"
    );
    let cohort = root.join(sandbox::classifier::BOXES_DIR);
    assert!(
        cohort.is_dir(),
        "the cohort directory exists for the boxes to come"
    );

    // The cohort asks the kernel for the memory controller: a box leaf only
    // carries a `memory.max` — the limit a host-side reader or a future
    // box-held view would name — when the cgroup above the leaf carries the
    // controller, and `boxes/` holds no process, so enabling it breaks no
    // internal-process rule.
    assert_eq!(
        std::fs::read_to_string(cohort.join("cgroup.subtree_control"))
            .expect("the daemon enables the memory controller on the cohort"),
        "+memory\n",
        "the leaf must carry the limit a reader would look for in it"
    );

    // The two identities: a box's leaf lives in its verdict's subtree inside
    // the cohort, never beside it and never in the daemon's leaf, so no box
    // is ever placed in the daemon's leaf and the daemon never in a box's.
    let a_box =
        sandbox::classifier::create_box_leaf(root, "a session", sandbox::config::Verdict::Deny)
            .expect("creating a box's leaf in the same tree");
    assert_eq!(
        a_box.parent(),
        Some(
            root.join(sandbox::classifier::BOXES_DIR)
                .join(sandbox::config::DENY_DIR)
                .as_path()
        ),
        "a box's leaf lives in its verdict's subtree, one level under the \
         cohort — never directly under the cohort, where the refusing rule's \
         match would silently miss it: {}",
        a_box.display()
    );
    assert_ne!(
        a_box.parent(),
        daemon.parent(),
        "a box's leaf and the daemon's are siblings' subtrees apart, never the \
         same directory"
    );

    // Entering again is harmless: a daemon that restarts into the leaf it
    // already holds stays one member, and on a real tree the kernel keeps
    // the membership set — the second write is a no-op there.
    sandbox::classifier::enter_daemon_leaf(root).expect("re-entering the daemon's leaf");
    let members = std::fs::read_to_string(&procs).expect("re-reading the daemon leaf's procs");
    assert!(
        members
            .lines()
            .any(|member| member == std::process::id().to_string()),
        "the daemon is still a member of its own leaf: {members:?}"
    );

    // And the one daemon that builds the tree itself — the guest's pid 1, on
    // the cgroup2 it mounted — makes the whole layout where there was
    // nothing, and then reports the stand-in's one gap as what it is: no
    // kernel made the `cgroup.procs` its entry writes into, so the write
    // says the leaf is missing, which over a real tree it never is. Nothing
    // boxes into a tree the entry could not enter.
    //
    // The root is a path that does not exist yet, because that is the
    // guest's actual shape: a cgroup2 mounted with nothing in it, whose
    // `minimald.slice` no other hand makes — the installer is a native
    // host's, and inside the VM there is nobody to run it. An entry that
    // made only the levels below the root would fail on the first one and
    // leave the guest with no tree at all, which is the state every
    // host-address box there is refused on.
    let bare = tempfile::tempdir().expect("a bare stand-in tree, nothing installed in it");
    let slice = std::path::Path::new(sandbox::classifier::TREE_ROOT)
        .file_name()
        .expect("the tree root is a path with a name");
    let root = bare.path().join(slice);
    let entry = sandbox::classifier::enter_daemon_leaf(&root)
        .expect_err("over a bare stand-in no kernel made the daemon leaf's cgroup.procs");
    assert_eq!(
        entry.kind(),
        std::io::ErrorKind::NotFound,
        "the entry's write is a migration into a leaf that must already hold \
         its kernel-made files: a missing one is a missing leaf"
    );
    let cohort = root.join(sandbox::classifier::BOXES_DIR);
    for (dir, level) in [
        (root.as_path(), "the tree root"),
        (cohort.as_path(), "the cohort the subtrees live in"),
        (
            cohort.join(sandbox::config::DENY_DIR).as_path(),
            "the deny subtree",
        ),
        (
            cohort.join(sandbox::config::ALLOW_DIR).as_path(),
            "the allow subtree",
        ),
    ] {
        assert!(
            dir.is_dir(),
            "the pid-1 entry builds {level} where it has the privilege to: {}",
            dir.display()
        );
    }
    assert!(
        sandbox::classifier::daemon_leaf(&root).is_dir(),
        "the pid-1 entry builds its own leaf where it has the privilege to"
    );
}

// ---------------------------------------------------------------------------
// The runtime port-publish ask (NET-045) and the decision log (NET-046)
// ---------------------------------------------------------------------------

/// The state the ask tests' boxes publish at, mirroring the session tests'
/// dynamic-ingress boxes: an own-address box whose creator handed it the
/// address pair a publish needs, with the switch lease the publish rides.
const ASK_SWITCH: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 128, 21);
const ASK_LOOPBACK: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127, 0, 64, 21);

/// Finalizes one dynamic-ingress box and returns its id alongside a handle to
/// its session actor, which is what a runtime port-publish request reaches.
async fn dynamic_ingress_box(
    server: &TestServer,
    client: &mut crate::test_harness::TestClient,
    name: &str,
    mode: Option<boxes::DynamicIngress>,
    range: Option<(u16, u16)>,
) -> (boxes::SessionId, crate::box_actor::BoxHandle) {
    // The loopback verdict vouches for the handed address, so the registry
    // publishes the box at it — the address a runtime publish binds at.
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    let id =
        finalize_dynamic_ingress_session(client, name, ASK_SWITCH, ASK_LOOPBACK, mode, range).await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("the {name} box should resolve"));
    (id, handle)
}

/// The daemon's local decision log (NET-046) as parsed records, in the order
/// the decisions were made. Only the decisions the test drove are there: a
/// harness server's state dir starts empty.
async fn audit_records(state_dir: &DaemonAbsPath) -> Vec<serde_json_lenient::Value> {
    let logged = tokio::fs::read_to_string(crate::audit::log_path(
        state_dir.as_utf8_path().as_std_path(),
    ))
    .await
    .expect("a decision should have been audited");
    logged
        .lines()
        .map(|line| {
            serde_json_lenient::from_str(line)
                .unwrap_or_else(|e| panic!("one audit line is one record: {e} in {logged}"))
        })
        .collect()
}

/// Reads the attached client's channel until the ask dialog renders, then
/// answers it the way the shell-exit prompt's tests do: a down-arrow off the
/// highlighted deny, then Enter. Returns everything the dialog rendered, so a
/// test can assert the lead-in named the box and the port.
async fn answer_ask_on(channel: &mut russh::Channel<russh::client::Msg>, accept: bool) -> Vec<u8> {
    let mut seen = Vec::new();
    let drained = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains(ASK_PROMPT) {
                        // Deny stands highlighted, so accepting moves once
                        // and confirms; denying — or refusing — confirms the
                        // highlighted deny as it is.
                        let keys = if accept {
                            b"\x1b[B\r".to_vec()
                        } else {
                            b"\r".to_vec()
                        };
                        channel.data_bytes(keys).await.unwrap();
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the ask dialog rendered"),
            }
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the ask dialog never rendered: {}",
        String::from_utf8_lossy(&seen),
    );
    seen
}

/// Reads the attached client's channel until the ask dialog renders, and
/// leaves it standing: for a test that has to let the dialog sit there
/// before answering, which [`answer_ask_on`] has no patience for. Returns
/// everything the channel carried to that point, so a test can assert the
/// lead-in named the box and the port.
async fn await_ask_prompt(channel: &mut russh::Channel<russh::client::Msg>) -> Vec<u8> {
    let mut seen = Vec::new();
    let rendered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains(ASK_PROMPT) {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the ask dialog rendered"),
            }
        }
    })
    .await;
    assert!(
        rendered.is_ok(),
        "the ask dialog never rendered: {}",
        String::from_utf8_lossy(&seen),
    );
    seen
}

/// NET-045's deny half: a human who denies the publish is the box's own deny
/// answer in their hand — the request is refused with the typed deny error,
/// the switch is asked nothing, and the decision lands in the daemon log and
/// the audit record (NET-046) naming the human as the decider. The allow half
/// alone would let an implementation that ignored the answer pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_human_deny_refused() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });

    let rendered = answer_ask_on(&mut channel, false).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect_err("the human's deny refuses the publish");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByHuman,
        ) => {}
        other => panic!("the denial is the typed deny error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a denied request asks the switch nothing: {:?}",
        served.lock().expect("served lock"),
    );

    // The prompt the human answered says its line, the answer says its own,
    // and the refusal is logged as the human's decision — not the daemon's
    // fail-closed one, which is what a dialog nobody answered would have
    // been.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("the attached client answered the runtime port publish ask"),
        "the answer says its line: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=attached-human"),
        "the refusal is logged as the human's own decision: {log}"
    );

    // And the decision's own audit record (NET-046): the human decided it,
    // and it names the typed error the in-box caller read.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "attached-human",
        "the human's deny is the decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is denied for this box",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// NET-045's slow half: taking the time to think must not cost the human
/// their attach. The dialog holds the binding off its own mailbox, so before
/// the dialog drained beside it, a session that printed more than the mailbox
/// holds while the human thought wedged the pty feed behind it — and the
/// stall bound shed the very client the dialog was waiting on, answering the
/// ask as the human's refusal. Here the bound is shortened, the session is
/// made to print throughout the dialog, and the human answers only after the
/// bound has passed: the attach survives, the answer is the one that
/// publishes, the output that printed arrives, and the decision is audited
/// as the human's publish (NET-046) — not as their refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_answered_after_the_stall_bound_publishes() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Shorten the stall bound on the live host, so the shed this test guards
    // against would fire in half a second rather than thirty.
    let host = handle
        .ensure_host("user".to_string())
        .await
        .expect("the attached box has a live host");
    host.set_output_stall_timeout(Duration::from_millis(500))
        .await;

    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });

    // The dialog has to be up before the session starts printing, so the
    // printing lands inside it — where the binding used to stop draining.
    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // The session prints for the whole time the human is thinking — several
    // mailbox-loads, so a binding that stopped draining would have wedged
    // the pty feed behind it. Fed into the pty rather than the channel,
    // which is the point: the dialog holds the channel's reader.
    host.feed_stdin(format!("{}\n", "x".repeat(120)).repeat(2000).into_bytes())
        .await;

    // The human takes longer than the stall bound to answer.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // A shed here would have closed the channel; the keys go nowhere then, so
    // the ask's own answer below carries the assertion.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "a shed binding may refuse the write; the ask's answer names the failure"
    )]
    let _ = channel.data_bytes(b"\x1b[B\r".to_vec()).await;
    let mapping = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{}:3000", ASK_LOOPBACK),
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
            pending: Some(false),
        },
        "the publish the human allowed is the one an allow box's takes"
    );
    forwarder.abort();
    {
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "the allowed ask publishes exactly once: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the allowed ask rides the forwarder's expose verb: {served:?}"
        );
    }

    // The attach outlived the dialog. The output that printed while the
    // human thought arrives now that the terminal is the relay's again, and
    // the channel never sees the shed: no EOF, no shed exit status, no
    // close.
    let mut flushed = 0usize;
    let mut shed = None;
    let mut closed = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    flushed += data.len();
                    if flushed > 64 * 1024 {
                        return;
                    }
                }
                Some(russh::ChannelMsg::Eof) => shed = Some("eof".to_string()),
                Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                    shed = Some(format!("exit status {exit_status}"));
                }
                Some(russh::ChannelMsg::Close) => {
                    closed = true;
                    return;
                }
                Some(_) => {}
                None => {
                    closed = true;
                    return;
                }
            }
        }
    })
    .await
    .expect("the output that printed during the dialog should flush back");
    assert!(
        shed.is_none() && !closed,
        "the dialog must not cost the human their attach (shed: {shed:?}, closed: {closed})",
    );
    assert!(
        flushed > 64 * 1024,
        "the output that printed while the human thought reaches them: {flushed} bytes",
    );

    // And the decision is audited as the human's publish (NET-046) — not as
    // the refusal a shed would have answered it with.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "attached-human",
        "the human's late answer is the decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "published");
    assert!(records[0].get("reason").is_none());
}

/// A dialog that ends without the human's answer is the daemon's refusal,
/// not the human's (the review thread on `Binding::run`): a binding shed
/// mid-dialog — its client stopped reading, so the host dropped it once the
/// stall bound passed — used to break the dialog loop with the default
/// [`Refused`](AskAnswer::Refused) answer and send that up as the human's
/// own, so the audit recorded `attached-human` for a denial no human made.
/// Here the stall bound is shortened, the dialog is left standing while the
/// session prints more than [`ASK_HELD_OUTPUT`] into the pty and the client
/// reads none of it, and the binding sheds mid-dialog: the ask ends with
/// the typed nobody-is-attached refusal, the switch is asked nothing, and
/// the decision is audited as the daemon's — because no human answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_shed_mid_dialog_is_the_daemons_refusal() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Shorten the stall bound on the live host, so the shed this test drives
    // fires in half a second rather than thirty.
    let host = handle
        .ensure_host("user".to_string())
        .await
        .expect("the attached box has a live host");
    host.set_output_stall_timeout(Duration::from_millis(500))
        .await;

    // Ask off the test's own task: the reply waits on the human.
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });

    // The dialog has to be up before the client stops reading, so the shed
    // lands inside it.
    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // The client reads nothing from here on. The session prints more than
    // one dialog's held-output bound ([`ASK_HELD_OUTPUT`]) into the pty
    // while the human is nowhere, so the drain beside the dialog gives up,
    // the mailbox fills behind it, and the stall bound sheds the binding
    // with the dialog still standing.
    host.feed_stdin(format!("{}\n", "x".repeat(120)).repeat(30000).into_bytes())
        .await;

    // The ask ends with the daemon's typed nobody-is-attached refusal — not
    // the human's deny a shed used to answer with.
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("a dialog its binding was shed from must end the ask, not park it")
        .expect("the spawned request should not panic")
        .expect_err("a shed mid-dialog fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the shed's refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an ask nobody answered asks the switch nothing"
    );

    // The client's channel saw the shed itself — EOF, the shed exit status,
    // and a close — so the refusal above is the one a shed answers with,
    // not one a dialog that ended some other way produced.
    let (mut eof, mut exit_status, mut closed, mut drained) = (false, None, false, Vec::new());
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => drained.extend_from_slice(&data),
                russh::ChannelMsg::Eof => eof = true,
                russh::ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                russh::ChannelMsg::Close => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("the shed binding's channel should close within the bound");
    assert!(eof, "the channel must see EOF before it closes");
    assert_eq!(
        exit_status,
        Some(SHED_EXIT_STATUS),
        "a shed reports the status that has the client restore the terminal",
    );
    assert!(closed, "the channel should close after the shed");

    // The shed notice is the channel's last words, and it must survive the
    // write the shed dropped mid-send: russh's channel writer keeps an
    // interrupted write's state and would answer this shorter buffer with
    // the interrupted write's byte count — tokio's `write_all` panics past
    // the notice's end, the binding dies mid-epilogue, and the client hangs
    // on a channel that never closes. The flood above is what put a write
    // mid-send when the shed took it, so this is the proof the binding
    // leaves a usable writer in its place instead.
    let tail = String::from_utf8_lossy(&drained[drained.len().saturating_sub(400)..]);
    assert!(
        tail.contains("the terminal stopped keeping up with session output"),
        "the shed notice should still reach the client after the flood; \
         the channel's last bytes: {tail}"
    );

    // The prompt says its line, and the refusal is logged as the daemon's
    // fail-closed decision — not the human's, which is what a shed used to
    // be recorded as.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );

    // And one audit record (NET-046) for the decision, naming the daemon as
    // the decider — because the human the dialog was for never answered.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "daemon",
        "a dialog nobody answered is the daemon's decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// The same rule for a teardown mid-dialog: a second client attaching
/// supersedes the binding whose dialog is standing, and the ask it was
/// holding is the daemon's refusal too — not the superseded human's deny,
/// which is what the ended dialog's default answer used to record it as.
/// The first channel sees its supersede farewell, the ask ends with the
/// typed nobody-is-attached refusal, the switch is asked nothing, and the
/// decision is audited as the daemon's (NET-046).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_superseded_mid_dialog_is_the_daemons_refusal() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });

    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // A second shell on the same box supersedes the first binding, with its
    // dialog still standing: the teardown it takes cannot wait for a human,
    // so the dialog ends unanswered and the ask ends with it.
    let mut second = client.open_shell(web).await;

    // The ask ends with the daemon's typed nobody-is-attached refusal — not
    // the human's deny the ended dialog's default answer used to send.
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("a dialog its binding was superseded from must end the ask, not park it")
        .expect("the spawned request should not panic")
        .expect_err("a teardown mid-dialog fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the supersede's refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an ask nobody answered asks the switch nothing"
    );

    // The first channel saw the supersede itself — its farewell and a close
    // — so the refusal above is the one a teardown mid-dialog answers with.
    let (mut superseded, mut closed) = (false, false);
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen)
                        .contains("session attached to from a different connection")
                    {
                        superseded = true;
                    }
                }
                Some(_) => {}
                None => {
                    closed = true;
                    return;
                }
            }
        }
    })
    .await
    .expect("the superseded binding's channel should close within the bound");
    assert!(
        superseded,
        "the first client saw its supersede farewell: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(closed, "the channel should close after the supersede");

    // The second binding took the box over, and is live to prove it.
    second.data_bytes(b"still-here\n".to_vec()).await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match second.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    echoed.extend_from_slice(&data);
                    if String::from_utf8_lossy(&echoed).contains("got:still-here") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the new shell echoed"),
            }
        }
    })
    .await
    .expect("the superseding client should hold a live shell");

    // And one audit record (NET-046) for the decision, naming the daemon as
    // the decider — no human answered, the dialog was torn down under them.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "daemon",
        "a dialog torn down mid-thought is the daemon's decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// A client that goes away mid-dialog is the daemon's refusal, not the
/// human's deny (the review thread on `ask_prompt`): `async-dialog` reports
/// an input EOF as the same `Selection::Cancelled` a keyed Ctrl-C produces,
/// and the arm that read both as the human's own deny recorded a denial no
/// human made. Under a raw `ssh -tt` tty no keystroke produces channel EOF,
/// so EOF means the connection or client went away — a terminal that can no
/// longer carry the dialog. Here the dialog is up and the client's channel
/// reaches EOF under it: the ask ends with the typed nobody-is-attached
/// refusal, the switch is asked nothing, and the decision is audited as the
/// daemon's, exactly one record for it — because no human answered. A keyed
/// cancel stays the human's own deny; [`expose_ask_human_deny_refused`]
/// proves that half.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_client_eof_mid_dialog_is_the_daemons_refusal() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });

    // The dialog has to be up before the client goes away, so the EOF lands
    // inside it.
    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the dialog's lead-in names the box and the port: {rendered}"
    );

    // The client's channel reaches EOF with the dialog standing — what a
    // connection or client that went away looks like from the binding's side.
    channel.eof().await.unwrap();

    // The ask ends with the daemon's typed nobody-is-attached refusal — not
    // the human's deny an input EOF used to be answered with.
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("a dialog whose client went away must end the ask, not park it")
        .expect("the spawned request should not panic")
        .expect_err("an input EOF mid-dialog fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the EOF's refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "an ask nobody answered asks the switch nothing"
    );

    // The prompt says its line, and the refusal is logged as the daemon's
    // fail-closed decision — not the human's, which is what an input EOF used
    // to be recorded as.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );

    // And exactly one audit record (NET-046) for the decision, naming the
    // daemon as the decider — because the human the dialog was for never
    // answered.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "daemon",
        "a dialog whose client went away is the daemon's decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// NET-045's no-client case against a live host: the box is up and detached
/// (NET-015), so the refusal has to come from the host that has nobody
/// attached rather than the no-host shortcut. Attaches, detaches, asks — the
/// typed nobody-is-attached refusal, the switch asked nothing, the
/// daemon-decided audit record (NET-046) — and the box still alive to take
/// another attach afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_after_detaching_is_refused_by_the_live_host() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach, prove the shell is live through the binding, then detach: the
    // box stays up with nobody bound to it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");
    channel.data_bytes(vec![0x1d]).await.unwrap();
    channel.data_bytes(vec![b'd']).await.unwrap();
    let mut detached = Vec::new();
    let mut closed = false;
    while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await {
        match msg {
            Some(russh::ChannelMsg::Data { data }) => detached.extend_from_slice(&data),
            Some(_) => {}
            None => {
                closed = true;
                break;
            }
        }
    }
    let detached = String::from_utf8_lossy(&detached);
    assert!(
        detached.contains("Detaching from session."),
        "the detach says its line: {detached:?}"
    );
    assert!(closed, "the channel should close after the detach chord");

    // The host is live — asserted, not presumed, because a dead host would
    // take the session's no-host shortcut and answer the same words from a
    // different place, and this test exists to pin the live one. The probe
    // goes through the session to the running host, and `Some` answers only
    // from a live host.
    tokio::time::timeout(Duration::from_secs(5), handle.get_attrs())
        .await
        .expect("the detached box's host probe should answer within its own bound")
        .expect("the host that served the detach is still live, nobody attached to it");

    // The host is live and nobody is attached: the ask must be refused with
    // the typed nobody-is-attached error, not parked and not a plain
    // "no session" answer.
    let refused = tokio::time::timeout(Duration::from_secs(30), handle.expose_dynamic(3000))
        .await
        .expect("an ask nobody can answer must be refused, not parked")
        .expect_err("nobody being attached fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a refused request asks the switch nothing"
    );

    // Both halves in the daemon log, with the typed reason the in-box caller
    // read.
    let log = capture.contents();
    assert!(
        log.contains("dynamic ingress is set to ask and nobody is attached to answer"),
        "the refusal names why, with the typed error's own words: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );
    // And the refusal came from the live host's own nobody-attached branch —
    // the plan's one info line per refusal for want of a client, naming the
    // box and the port — which the session's no-host shortcut never says,
    // so this line is what tells the two apart. The captured log is shared
    // by every test in the process, so pick this box's line, not the first.
    log.lines()
        .find(|line| {
            line.contains("refusing the runtime port publish ask for want of a client to answer it")
                && line.contains("session=web")
                && line.contains("port=3000")
        })
        .unwrap_or_else(|| panic!("the live host should name the box and port it refused: {log}"));

    // And the decision is audited (NET-046): the daemon decided it, because
    // no human was there to.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one request is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );

    // The box outlived its detached ask (NET-015): it takes another attach
    // and echoes through it.
    let mut again = client.open_shell(web).await;
    again.data_bytes(b"still-here\n".to_vec()).await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match again.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    echoed.extend_from_slice(&data);
                    if String::from_utf8_lossy(&echoed).contains("got:still-here") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the reattached shell echoed"),
            }
        }
    })
    .await
    .expect("the detached box should still be alive to reattach to");
}

/// NET-045's ordering: two asks can share a port, and each answer must reach
/// the ask it answers. Keyed by port alone, an answer popped whichever ask
/// parked on that port first — so a fail-closed answer for an ask whose
/// hand-off failed refused a *different* ask while its dialog was still on
/// screen, and the human's answer for that one then published for the ask
/// that had already failed. Here two asks park on one port, the second's
/// continuation arrives first as the answer nobody was attached to give, and
/// then the human answers the dialog that is still standing: the second's
/// caller is refused, the first's publish, each audited as its own decision
/// (NET-046) — and the late real answer for the ended ask reaches no asker
/// and fabricates no third decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_answers_reach_their_own_ask_on_a_shared_port() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human both asks will be routed to.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Two asks for the same port, parked one at a time — the first's dialog
    // confirmed standing before the second is even sent, so the parked
    // book's order and the binding's dialog order are the same order, and
    // the ids below say whose caller they are.
    let asked_first = crate::traced::spawn({
        let handle = handle.clone();
        async move { handle.expose_dynamic(3000).await }
    });
    let first_parked = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let parked = handle.pending_ask_ids().await;
            if parked.len() == 1 {
                return parked;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first ask on the shared port should park");
    let [(first, first_port)] = first_parked
        .try_into()
        .expect("exactly one ask parks first");
    assert_eq!(first_port, 3000, "the first ask is for the shared port");

    let rendered = await_ask_prompt(&mut channel).await;
    let rendered = String::from_utf8_lossy(&rendered);
    assert!(
        rendered.contains("web asks to publish port 3000"),
        "the first dialog's lead-in names the box and the port: {rendered}"
    );

    let asked_second = crate::traced::spawn({
        let handle = handle.clone();
        async move { handle.expose_dynamic(3000).await }
    });
    let parked = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let parked = handle.pending_ask_ids().await;
            if parked.len() == 2 {
                return parked;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both asks on the shared port should park");
    let (second, second_port) = parked
        .last()
        .copied()
        .expect("the second ask parks beside the first");
    assert_eq!(
        second_port, 3000,
        "the second ask is for the shared port too"
    );
    assert_ne!(
        first, second,
        "two asks on one port park under their own keys"
    );

    // The second ask's continuation arrives as the answer nobody was
    // attached to give — the shape a failed hand-off comes back in — while
    // the first ask's dialog is still standing on the human's screen.
    // Delivered through the same handle the routed task delivers through, so
    // the interleaving production can race over is the only thing forged
    // here.
    handle.ask_answered(second, 3000, None).await;

    let refused = tokio::time::timeout(Duration::from_secs(30), asked_second)
        .await
        .expect("the ask whose hand-off failed should be refused, not parked")
        .expect("the spawned request should not panic")
        .expect_err("the failed hand-off fails the second ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => {
            panic!("the second ask's refusal is the typed nobody-is-attached error: {other:?}")
        }
    }
    let still_parked = handle.pending_ask_ids().await;
    assert_eq!(
        still_parked,
        vec![(first, 3000)],
        "the fail-closed answer must not have popped the ask whose dialog is still up: {still_parked:?}",
    );

    // The human answers the dialog that is still standing — the first ask's,
    // its rendering confirmed before the second was even sent — so that
    // answer belongs to the first ask, and only to it. The prompt is already
    // on screen, so the keys go straight to it.
    channel.data_bytes(b"\x1b[B\r".to_vec()).await.unwrap();
    let mapping = tokio::time::timeout(Duration::from_secs(30), asked_first)
        .await
        .expect("the ask whose dialog was answered should publish, not park")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port their dialog was for");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{}:3000", ASK_LOOPBACK),
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
            pending: Some(false),
        },
        "the publish is the one an allow box's request takes"
    );
    forwarder.abort();
    {
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "only the answered ask publishes: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the answered ask rides the forwarder's expose verb: {served:?}"
        );
    }

    // One decision per ask, each its own: the daemon's fail-closed refusal
    // for the ask whose hand-off failed, then the human's publish for the ask
    // they answered.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 2, "two asks are two decisions: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the failed hand-off carries the typed error its caller read: {records:?}"
    );
    assert_eq!(records[1]["box"], "web");
    assert_eq!(records[1]["port"], 3000);
    assert_eq!(records[1]["decision"], "ask");
    assert_eq!(records[1]["decided_by"], "attached-human");
    assert_eq!(records[1]["outcome"], "published");
    assert!(records[1].get("reason").is_none());

    // The binding still renders the dialog for the ask that already ended.
    // The dialog answered above redraws its own prompt on the way out, so
    // the lead-in — not the prompt line — is what says a fresh one is
    // standing. Answering it must reach no asker and fabricate no third
    // decision.
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut seen = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    seen.extend_from_slice(&data);
                    if String::from_utf8_lossy(&seen).contains("web asks to publish port 3000") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the ended ask's dialog rendered"),
            }
        }
    })
    .await
    .expect("the ended ask's dialog should render too");
    channel.data_bytes(b"\r".to_vec()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if capture
                .contents()
                .contains("a runtime port-publish answer arrived with no ask waiting for it")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the late answer for the ended ask should say its line");
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(
        records.len(),
        2,
        "a late answer for an ended ask fabricates no decision: {records:?}"
    );
}

/// NET-045: a runtime port-publish request a box decided `ask` reaches the
/// human attached to it — the dialog renders on their terminal with the box
/// and the port named — and the answer they give is the answer the request
/// gets: an allow publishes, and the publish that follows is the one an
/// `allow` box's request takes. The prompt says its own line in the daemon
/// log, and the decision it produced lands in the local audit log (NET-046)
/// naming who decided it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_prompts_attached_human() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking: the mock shell's echo round-trips through it.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    // Ask off the test's own task: the reply waits on the human.
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });

    let rendered = answer_ask_on(&mut channel, true).await;
    let rendered = String::from_utf8_lossy(&rendered);
    // The frame is the one the VM-backed host's dialog draws: the protocol
    // on the lead-in and the `? ` the question leads with, so a human — and
    // the e2e's pty driver — meets one dialog on either host.
    assert!(
        rendered.contains("web asks to publish port 3000/tcp."),
        "the dialog's lead-in names the box, the port and the protocol: {rendered}"
    );
    assert!(
        rendered.contains(&format!("? {ASK_PROMPT}")),
        "the question leads with the `? ` the VM-backed dialog draws: {rendered}"
    );

    let mapping = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port");
    assert_eq!(
        mapping,
        minimald_rpc::LiveMapping {
            local: format!("{}:3000", ASK_LOOPBACK),
            internal_port: 3000,
            proto: boxes::IpProto::Tcp,
            pending: Some(false),
        },
        "the publish the human allowed is the one an allow box's takes"
    );
    forwarder.abort();
    {
        let served = served.lock().expect("served lock");
        assert_eq!(
            served.len(),
            1,
            "the allowed ask publishes exactly once: {served:?}"
        );
        assert!(
            served[0].starts_with("POST /services/forwarder/expose "),
            "the allowed ask rides the forwarder's expose verb: {served:?}"
        );
    }

    // One line for the prompt, and the decision's own line, in the daemon log
    // the diagnostics bundle ships.
    let log = capture.contents();
    assert!(
        log.contains("asking the attached client to allow a runtime port publish"),
        "the prompt the human saw says its line: {log}"
    );
    assert!(
        log.contains("the attached client answered the runtime port publish ask"),
        "the answer says its line: {log}"
    );

    // And one audit record for the decision, naming who made it (NET-046).
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(
        records[0]["decided_by"], "attached-human",
        "the human's answer is the decision: {records:?}"
    );
    assert_eq!(records[0]["outcome"], "published");
    assert!(records[0].get("reason").is_none());
}

/// NET-044/NET-045: an `ask` answered yes admits the port at the box's relay
/// gate the way an `allow` does — the publish the human allowed is reachable
/// — while a port nobody published stays refused. The gate is registered
/// under the box's switch address the way its relay's spawn registers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_yes_admits_the_port_at_the_box_gate() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    // An address no other test's box uses: the live-gate table is
    // process-wide.
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 92);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "askgate",
        switch,
        std::net::Ipv4Addr::new(127, 0, 64, 92),
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the asking box resolves");
    let gate = std::sync::Arc::new(crate::net::switch::BoxGate::for_session(
        "askgate".to_string(),
        switch,
        &boxes::BoxPolicy::default(),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::net::switch::register_live_gate_for_test(switch, &gate);
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, _served) = fake_forwarder(sock, 200).await;

    // Attach the human the ask will be routed to, and prove the binding is
    // live before asking.
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");

    assert!(!gate.admits_tcp(3000), "nothing is published yet");
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });
    answer_ask_on(&mut channel, true).await;
    tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask should be answered once the human answers")
        .expect("the spawned request should not panic")
        .expect("the human's allow publishes the port");
    forwarder.abort();

    assert!(
        gate.admits_tcp(3000),
        "the port the human allowed is admitted at the box's relay gate"
    );
    assert!(
        !gate.admits_tcp(3001),
        "a port nobody published stays refused"
    );
}

/// NET-045's unwanted branch: a box decided `ask` with nobody attached — no
/// client ever bound, so no human to render the dialog to — is refused with
/// the typed error that says nobody is attached to answer, the switch is
/// asked nothing at all, and both facts land in the log and the audit record
/// like every other decision (NET-046).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_ask_without_client_refused() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    // Nobody ever attaches: no binding to render the dialog, and the request
    // is refused rather than parked on a human who is not there.
    let refused = tokio::time::timeout(Duration::from_secs(30), handle.expose_dynamic(3000))
        .await
        .expect("an ask nobody can answer must be refused, not parked")
        .expect_err("nobody being attached fails the ask closed");
    match refused {
        crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::AskNeedsAnswer,
        ) => {}
        other => panic!("the refusal is the typed nobody-is-attached error: {other:?}"),
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "a refused request asks the switch nothing"
    );

    // The refusal for want of a client says its line, carrying the typed
    // reason the in-box caller read.
    let log = capture.contents();
    assert!(
        log.contains("dynamic ingress is set to ask and nobody is attached to answer"),
        "the refusal names why, with the typed error's own words: {log}"
    );
    assert!(
        log.contains("outcome=\"refused\"") && log.contains("decided_by=daemon"),
        "the refusal is logged as the daemon's fail-closed decision: {log}"
    );

    // And the decision is audited (NET-046): the daemon decided it, because
    // there was no human to.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one request is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "ask");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(
        records[0]["reason"], "dynamic ingress is set to ask and nobody is attached to answer",
        "the audit record carries the typed error the caller read: {records:?}"
    );
}

/// NET-046: on the un-enrolled host, every dynamic ingress decision lands in
/// the local audit log — the publish an allowing box made and the refusal the
/// deny-all default answered an un-enrolled box with alike — each as one
/// parseable record naming the box, the port, the decision, who decided it,
/// and the outcome, so the log reads without the session it was about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_unenrolled_decision_audited() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, web_handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let (_db, db_handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "db",
        // Declared nothing: the deny-all default the un-enrolled box runs
        // under, which is what "un-enrolled" means for a decision's sake.
        None,
        None,
    )
    .await;
    // A publish needs a box running behind it (NET-047's stopped-box
    // refusal), so the allowing box launches its host first.
    web_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = web_handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, _served) = fake_forwarder(sock.clone(), 200).await;
    // On a VM host each decision is also reported to the VM host daemon,
    // which keeps its own copy outside the VM. The two boxes' audit routes
    // go to one stand-in door, each under a row key of its own.
    let web_row = std::net::Ipv4Addr::new(100, 64, 128, 201);
    let db_row = std::net::Ipv4Addr::new(100, 64, 128, 202);
    let door_sock = sock.with_file_name("audit-door.sock");
    let (door, mut reports, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_host_audit_route_for_tests("web", web_row, &door_sock);
    crate::net::listeners::seed_host_audit_route_for_tests("db", db_row, &door_sock);

    web_handle
        .expose_dynamic(3000)
        .await
        .expect("the allowing box publishes");
    match db_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("the deny-all default refuses the request: {other:?}"),
    }

    // Each decision reaches the host as one report keyed by its box's row.
    let mut host_reports = Vec::new();
    for _ in 0..2 {
        let report = tokio::time::timeout(Duration::from_secs(10), reports.recv())
            .await
            .expect("each decision is reported to the VM host daemon")
            .expect("the report door stand-in lives");
        replies
            .send(minimald_rpc::BoxControlReply::Audited { audited: true })
            .expect("the report door stand-in lives");
        match report {
            minimald_rpc::BoxControlRequest::ReportExposeDecision(report) => {
                host_reports.push(report);
            }
            other => panic!("a decision is reported as an expose decision: {other:?}"),
        }
    }
    host_reports.sort_by_key(|report| report.switch_address);
    assert_eq!(
        host_reports,
        vec![
            minimald_rpc::ExposeDecisionReport {
                switch_address: Some(web_row),
                box_id: None,
                port: 3000,
                decision: boxes::DynamicIngress::Allow,
                decided_by: minimald_rpc::ExposeDecidedBy::BoxPolicy,
                outcome: minimald_rpc::ExposeDecisionOutcome::Published,
            },
            minimald_rpc::ExposeDecisionReport {
                switch_address: Some(db_row),
                box_id: None,
                port: 3000,
                decision: boxes::DynamicIngress::Deny,
                decided_by: minimald_rpc::ExposeDecidedBy::BoxPolicy,
                outcome: minimald_rpc::ExposeDecisionOutcome::Refused,
            },
        ],
        "the host hears each decision the local log records"
    );

    // With the host unreachable, the local record still lands.
    crate::net::listeners::seed_host_audit_route_for_tests(
        "db",
        db_row,
        sock.with_file_name("no-door.sock"),
    );
    match db_handle.expose_dynamic(3001).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("the deny-all default refuses the request: {other:?}"),
    }
    forwarder.abort();
    door.abort();
    crate::net::listeners::clear_host_audit_route_for_tests("web", web_row);
    crate::net::listeners::clear_host_audit_route_for_tests("db", db_row);

    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 3, "each decision is one record: {records:?}");
    assert_eq!(records[2]["box"], "db");
    assert_eq!(
        records[2]["port"], 3001,
        "a decision the host cannot hear is still recorded locally: {records:?}"
    );
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["port"], 3000);
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["decided_by"], "box-policy");
    assert_eq!(records[0]["outcome"], "published");
    assert!(
        records[0].get("reason").is_none(),
        "a publish has no refusal to name: {records:?}"
    );
    assert_eq!(records[1]["box"], "db");
    assert_eq!(records[1]["port"], 3000);
    assert_eq!(records[1]["decision"], "deny");
    assert_eq!(records[1]["decided_by"], "box-policy");
    assert_eq!(records[1]["outcome"], "refused");
    assert_eq!(
        records[1]["reason"], "dynamic ingress is denied for this box",
        "the refusal carries the typed error's own words: {records:?}"
    );
}

/// NET-046 fails closed on an unrecordable allow: with a link planted where
/// the audit directory should be, every append is refused, so the allowing
/// box's publish is withdrawn — the switch asked to unbind what it bound, no
/// live mapping left — and the caller hears a failed publish naming the
/// audit log, with the refusal in the daemon's log. A deny under the same
/// refusal still refuses: an unrecordable deny is never turned into a
/// publish. The link's target is untouched either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expose_unrecordable_allow_is_refused_and_deny_still_refuses() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let manager = server.state.sessions_manager().await;
    manager.land_range_verdict(crate::net::dns::RangeVerdict::Present);
    // An address no other test's box uses: the live-gate table is
    // process-wide, and this test's point is the gate's own state.
    let switch = std::net::Ipv4Addr::new(100, 64, 128, 93);
    let web = finalize_dynamic_ingress_session(
        &mut client,
        "web",
        switch,
        std::net::Ipv4Addr::new(127, 0, 64, 93),
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    let web_handle = manager
        .get_session(crate::box_manager::BoxKeyPredicate::Id(web))
        .await
        .unwrap()
        .expect("the allowing box resolves");
    let (_db, db_handle) = dynamic_ingress_box(&server, &mut client, "db", None, None).await;
    let gate = std::sync::Arc::new(crate::net::switch::BoxGate::for_session(
        "web".to_string(),
        switch,
        &boxes::BoxPolicy::default(),
        crate::net::SwitchSubnet::default(),
        None,
    ));
    crate::net::switch::register_live_gate_for_test(switch, &gate);
    web_handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = web_handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock, 200).await;

    let state_dir = server.state.minimal_state_dir().await;
    let state_dir = state_dir.as_utf8_path().as_std_path();
    let planted = state_dir.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::os::unix::fs::symlink(&planted, state_dir.join("audit")).unwrap();

    // A sampler that reads the gate the whole time the refused publish
    // runs: the admission waits on the record (NET-046), so an allow the
    // log refuses is never admitted, not even for the length of the audit
    // write and the unwind after it.
    let ever_admitted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sampling = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sampler = {
        let gate = std::sync::Arc::clone(&gate);
        let ever_admitted = std::sync::Arc::clone(&ever_admitted);
        let sampling = std::sync::Arc::clone(&sampling);
        crate::traced::spawn(async move {
            while sampling.load(std::sync::atomic::Ordering::SeqCst) {
                if gate.admits_tcp(3000) {
                    ever_admitted.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                tokio::task::yield_now().await;
            }
        })
    };
    match web_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Publish { port: 3000, source }) => assert!(
            source.to_string().contains("audit log"),
            "the failure says the decision could not be recorded: {source}"
        ),
        other => panic!("an allow that cannot be audited is refused: {other:?}"),
    }
    sampling.store(false, std::sync::atomic::Ordering::SeqCst);
    sampler.await.unwrap();
    assert!(
        !ever_admitted.load(std::sync::atomic::Ordering::SeqCst),
        "an allow whose record the log refused is never admitted at the relay gate"
    );
    assert!(
        !gate.admits_tcp(3000),
        "the unaudited allow is not admitted at the relay gate"
    );
    assert!(
        web_handle
            .live_ingress()
            .await
            .expect("the actor answers")
            .exposed
            .is_empty(),
        "the withdrawn publish leaves no live mapping"
    );
    assert!(
        served
            .lock()
            .expect("served lock")
            .iter()
            .any(|line| line.starts_with("POST /services/forwarder/unexpose ")),
        "the forward the publish bound is unbound again"
    );
    match db_handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("an unrecordable deny still refuses: {other:?}"),
    }

    // Once the audit log takes records again the same publish stands: the
    // gate holds no residue of the refused attempt, and the allow is
    // admitted afresh — a refusal withdrawn leaves the box none the
    // worse for having been refused.
    std::fs::remove_file(state_dir.join("audit")).unwrap();
    web_handle
        .expose_dynamic(3000)
        .await
        .expect("an auditable allow publishes again");
    assert!(
        gate.admits_tcp(3000),
        "the republished allow is admitted at the box's relay gate"
    );
    forwarder.abort();

    let log = capture.contents();
    assert!(
        log.contains("the dynamic ingress allow could not be audited"),
        "the refused allow is said in the daemon's log: {log}"
    );
    assert!(
        log.contains("the dynamic ingress decision could not be audited"),
        "the unrecordable refusals are warned about, not silent: {log}"
    );
    assert!(
        !planted.join("decisions.log").exists(),
        "the planted link's target is untouched"
    );
}

/// Drives one VM-backed publish under `mode` whose allow cannot be audited
/// and returns the withdrawal the VM host daemon's door read. The door holds
/// the withdrawal's reply while the switch's requests are checked, so the
/// unexpose is proved to come first, the order every unwind holds.
async fn unaudited_vm_withdrawal(mode: boxes::DynamicIngress) -> minimald_rpc::BoxControlRequest {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) =
        dynamic_ingress_box(&server, &mut client, "web", Some(mode), Some((3000, 3999))).await;
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served, door, mut requests, replies) = vm_backed_ask_box(&handle).await;

    let state_dir = server.state.minimal_state_dir().await;
    let state_dir = state_dir.as_utf8_path().as_std_path();
    let planted = state_dir.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::os::unix::fs::symlink(&planted, state_dir.join("audit")).unwrap();

    let exposing = handle.clone();
    let expose = crate::traced::spawn(async move { exposing.expose_dynamic(3000).await });
    let admit = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the publish reaches the VM host daemon's door")
        .expect("the report door stand-in lives");
    let admitted = if mode == boxes::DynamicIngress::Ask {
        assert!(
            matches!(admit, minimald_rpc::BoxControlRequest::AdmitAsk(_)),
            "an ask is raised with the host first: {admit:?}"
        );
        host_end(minimald_rpc::AskAdmitOutcome::Admitted {
            ask_id: host_ask_id(),
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
    } else {
        assert!(
            matches!(admit, minimald_rpc::BoxControlRequest::AdmitPort(_)),
            "an allow reports the port before it binds: {admit:?}"
        );
        minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        }
    };
    replies
        .send(admitted)
        .expect("the report door stand-in lives");
    let withdrawal = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the unaudited publish withdraws its row entry")
        .expect("the report door stand-in lives");
    {
        let served = served.lock().expect("served lock");
        assert!(
            served
                .iter()
                .any(|line| line.starts_with("POST /services/forwarder/unexpose ")),
            "the forward is unbound before the row entry is withdrawn: {served:?}"
        );
    }
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    assert!(
        matches!(
            expose.await.expect("the expose task should not panic"),
            Err(crate::net::policy::ExposeFailure::Publish { port: 3000, .. })
        ),
        "an allow that cannot be audited is refused"
    );
    forwarder.abort();
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    withdrawal
}

/// NET-046's fail-closed withdrawal on a VM-backed host gives the VM host
/// daemon's row entry back under the surface the publish used: the box's
/// own expose for an `allow`, the answered ask for an `ask` (NET-045).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unaudited_allow_withdraws_the_vm_row_under_its_source() {
    for (mode, source) in [
        (
            boxes::DynamicIngress::Allow,
            minimald_rpc::PortReportSource::Expose,
        ),
        (
            boxes::DynamicIngress::Ask,
            minimald_rpc::PortReportSource::Ask,
        ),
    ] {
        assert_eq!(
            unaudited_vm_withdrawal(mode).await,
            minimald_rpc::BoxControlRequest::WithdrawPort(minimald_rpc::WithdrawPortRequest {
                switch_address: ASK_SWITCH,
                port: 3000,
                proto: boxes::IpProto::Tcp,
                source,
            }),
            "the {mode} publish's row entry is withdrawn under its own source"
        );
    }
}

/// The unaudited withdrawal keeps what it cannot take down: a forward whose
/// unexpose the switch refuses — the very failure the fail-closed path can
/// meet on a switch that is wedged or gone — stays recorded in the box's
/// live set, `unrevoked`, so the box's stop sweep can ask for it again, and
/// the VM host daemon's row entry stays beside it, because the host's gate
/// retracts a runtime port only while the row still holds it. What the
/// caller hears does not change: the publish is refused either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unaudited_allow_keeps_a_forward_the_switch_would_not_unbind() {
    let capture = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    // VM-backed, so the publish is admitted at a report door the test owns
    // and the withdrawal would report back to it.
    let door_sock = sock.with_file_name("report-door.sock");
    let (door, mut requests, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);
    // The switch accepts the publish's bind and then refuses the
    // withdrawal's unexpose — the failure the retention is for.
    let (forwarder, served) =
        crate::box_actor::tests::scripted_forwarder(sock.clone(), vec![200, 500]).await;

    // Every append is refused: the audit directory is a planted link.
    let state_dir = server.state.minimal_state_dir().await;
    let state_dir = state_dir.as_utf8_path().as_std_path();
    let planted = state_dir.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::os::unix::fs::symlink(&planted, state_dir.join("audit")).unwrap();

    let exposing = handle.clone();
    let expose = crate::traced::spawn(async move { exposing.expose_dynamic(3000).await });
    // The publish reports its port first; the door admits it.
    let admit = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the publish reaches the VM host daemon's door")
        .expect("the report door stand-in lives");
    assert!(
        matches!(admit, minimald_rpc::BoxControlRequest::AdmitPort(_)),
        "an allow reports the port before it binds: {admit:?}"
    );
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    // The caller hears the failed publish the fail-closed path owes, naming
    // the audit log.
    match expose.await.expect("the expose task should not panic") {
        Err(crate::net::policy::ExposeFailure::Publish { port: 3000, source }) => assert!(
            source.to_string().contains("audit log"),
            "the failure says the decision could not be recorded: {source}"
        ),
        other => panic!("an allow that cannot be audited is refused: {other:?}"),
    }

    let live = handle
        .live_ingress()
        .await
        .expect("the actor answers")
        .exposed;
    assert_eq!(
        live.len(),
        1,
        "the forward the switch would not unbind stays recorded for the \
         box's stop to ask for again: {live:?}"
    );
    assert_eq!(
        live[0].internal_port, 3000,
        "the recorded forward is the unaudited publish's own"
    );
    assert_eq!(
        live[0].pending,
        Some(true),
        "the gate refuses the retained forward, so its row reads pending, \
         never reachable"
    );
    let served = served.lock().expect("served lock").clone();
    assert_eq!(
        served.len(),
        2,
        "the publish's bind and the withdrawal's refused unexpose: {served:?}"
    );
    assert!(
        served[1].starts_with("POST /services/forwarder/unexpose "),
        "the withdrawal did ask the switch to unbind: {served:?}"
    );
    // No withdrawal report reached the door: the row entry stays with the
    // forward, so the host's gate can still retract the port.
    match tokio::time::timeout(Duration::from_millis(200), requests.recv()).await {
        Err(_) => {}
        Ok(received) => {
            panic!("the row entry is held back with the forward it names: {received:?}")
        }
    }
    let log = capture.contents();
    assert!(
        log.contains("the unaudited publish's forward could not be unbound"),
        "the refused unexpose is said, not silent: {log}"
    );
    forwarder.abort();
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
}

/// The retention above has one case it cannot keep: the box's spawn ends
/// while the refused unexpose is in flight, so the guard that would unbind
/// the forward has already swept the cell, and the cell refuses it back. The
/// withdrawal then unbinds it once more, best-effort, and gives the port back
/// the way every detached publish does — the publication-set entry released
/// and the VM host daemon's row entry withdrawn, after the unexposes — since
/// no sweep is left that would ever retry them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unaudited_allow_whose_spawn_ends_mid_unbind_gives_the_port_back() {
    use tokio::io::AsyncWriteExt;
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Allow),
        Some((3000, 3999)),
    )
    .await;
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the allowing box launches its host");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let door_sock = sock.with_file_name("report-door.sock");
    let (door, mut requests, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);
    let (runtime_ingress, publications) = handle.ingress_cells().await.expect("the actor answers");

    // The switch accepts the bind and refuses every unexpose, and the box's
    // spawn ends while the first of them is in flight: the stand-in empties
    // the cell the way the spawn's guard does before it answers.
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).expect("create the switch state dir");
    }
    let listener = tokio::net::UnixListener::bind(&sock).expect("bind the control socket");
    let served = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let forwarder = {
        let served = served.clone();
        let runtime_ingress = runtime_ingress.clone();
        crate::traced::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let Some(request) =
                    crate::box_actor::tests::read_control_request(&mut stream).await
                else {
                    continue;
                };
                let status = if request.starts_with("POST /services/forwarder/unexpose ") {
                    // The guard's sweep is what is simulated; what it took
                    // is not this test's concern.
                    drop(runtime_ingress.detach());
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                served.lock().expect("served lock").push(request);
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "the answer's fate is not what the stand-in records; the request is"
                )]
                let _ = stream
                    .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .await;
            }
        })
    };

    // Every append is refused: the audit directory is a planted link.
    let state_dir = server.state.minimal_state_dir().await;
    let state_dir = state_dir.as_utf8_path().as_std_path();
    let planted = state_dir.join("planted");
    std::fs::create_dir_all(&planted).unwrap();
    std::os::unix::fs::symlink(&planted, state_dir.join("audit")).unwrap();

    let exposing = handle.clone();
    let expose = crate::traced::spawn(async move { exposing.expose_dynamic(3000).await });
    let admit = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the publish reaches the VM host daemon's door")
        .expect("the report door stand-in lives");
    assert!(
        matches!(admit, minimald_rpc::BoxControlRequest::AdmitPort(_)),
        "an allow reports the port before it binds: {admit:?}"
    );
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");

    // The row entry is withdrawn, under the expose's own source, and only
    // after the switch was asked to unbind: the refused unexpose, then the
    // best-effort one the detached forward gets.
    let withdrawal = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the detached publish withdraws its row entry")
        .expect("the report door stand-in lives");
    assert_eq!(
        withdrawal,
        minimald_rpc::BoxControlRequest::WithdrawPort(minimald_rpc::WithdrawPortRequest {
            switch_address: ASK_SWITCH,
            port: 3000,
            proto: boxes::IpProto::Tcp,
            source: minimald_rpc::PortReportSource::Expose,
        }),
        "the row entry is withdrawn once no sweep is left to retry it"
    );
    {
        let served = served.lock().expect("served lock");
        let unexposes = served
            .iter()
            .filter(|line| line.starts_with("POST /services/forwarder/unexpose "))
            .count();
        assert_eq!(
            unexposes, 2,
            "the refused unexpose and the detached forward's best-effort one both \
             precede the withdrawal: {served:?}"
        );
    }
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    assert!(
        matches!(
            expose.await.expect("the expose task should not panic"),
            Err(crate::net::policy::ExposeFailure::Publish { port: 3000, .. })
        ),
        "an allow that cannot be audited is refused"
    );
    assert!(
        publications.held_by(3000).is_none(),
        "the publication-set entry is given back with the row entry"
    );
    assert!(
        handle
            .live_ingress()
            .await
            .expect("the actor answers")
            .exposed
            .is_empty(),
        "the cell the spawn's end emptied does not take the forward back"
    );
    forwarder.abort();
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
}

/// The host-level half of NET-045's no-client case: an ask reaching a host
/// nobody is bound to answers no-one rather than parking — the dialog has no
/// terminal to render on — which is the fail-closed answer the session turns
/// into the typed nobody-is-attached refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_expose_without_a_binding_answers_no_one() {
    let (host, handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            // No channel and no binding: the host is up, but nobody is
            // attached to it.
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");
    let task = crate::traced::spawn(host.mainloop());

    let answer = tokio::time::timeout(Duration::from_secs(5), handle.ask_expose(3000))
        .await
        .expect("an ask with nobody attached must answer, not park on a dialog nobody can see");
    assert_eq!(
        answer, None,
        "no binding means nobody is attached to answer the ask"
    );

    // Teardown of the host this test minted. Best-effort both ways: the kill
    // of a host that is fine, and a join that a wedged loop would outrun.
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the host this test minted is not the fact under test; a kill that lands is enough"
    )]
    let _ = handle.kill(false).await;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "the ask already answered is the fact; the loop may outlive the test's bound"
    )]
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
}

/// Attach a shell to `web` and prove the binding is live: the mock shell's
/// echo round-trips through it.
async fn attach_live_shell(
    client: &mut crate::test_harness::TestClient,
    web: boxes::SessionId,
) -> russh::Channel<russh::client::Msg> {
    let mut channel = client.open_shell(web).await;
    channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
    let mut live = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    live.extend_from_slice(&data);
                    if String::from_utf8_lossy(&live).contains("got:hello") {
                        return;
                    }
                }
                Some(_) => {}
                None => panic!("the channel closed before the shell came up"),
            }
        }
    })
    .await
    .expect("the attached shell should echo within the bound");
    channel
}

/// Seed `handle`'s switch as VM-backed, its report door the test's
/// stand-in, and stand up a forwarder for the publish.
async fn vm_backed_ask_box(
    handle: &crate::box_actor::BoxHandle,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
    tokio::sync::mpsc::UnboundedSender<minimald_rpc::BoxControlReply>,
) {
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    let (forwarder, served) = fake_forwarder(sock.clone(), 200).await;
    let door_sock = sock.with_file_name("report-door.sock");
    let (door, requests, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);
    (forwarder, served, door, requests, replies)
}

/// The ask the door read: the row key, the port and the protocol.
async fn expect_admit_ask(
    requests: &mut tokio::sync::mpsc::UnboundedReceiver<minimald_rpc::BoxControlRequest>,
) {
    let request = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the ask reaches the VM host daemon's report door")
        .expect("the report door stand-in lives");
    assert_eq!(
        request,
        minimald_rpc::BoxControlRequest::AdmitAsk(minimald_rpc::AdmitAskRequest {
            switch_address: ASK_SWITCH,
            port: 3000,
            proto: boxes::IpProto::Tcp,
        }),
        "the ask carries the row key, the port and the protocol, and nothing else"
    );
}

/// The VM host daemon's end for the ask on port 3000.
fn host_end(outcome: minimald_rpc::AskAdmitOutcome) -> minimald_rpc::BoxControlReply {
    minimald_rpc::BoxControlReply::AskAdmit(outcome)
}

fn host_ask_id() -> minimald_rpc::AskId {
    minimald_rpc::AskId::from_bytes([5; 16])
}

/// NET-045 on a VM-backed host: the guest's binding renders no dialog. The
/// ask crosses the report door as the row key, the port and the protocol,
/// the attached shell sees no prompt, and the publish runs only once the
/// VM host daemon answers admitted — with no admit report after it, because
/// the host already recorded the yes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_ask_prompt_not_rendered_on_vm_host() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let (forwarder, served, _door, mut requests, replies) = vm_backed_ask_box(&handle).await;
    let mut channel = attach_live_shell(&mut client, web).await;

    let asking = handle.clone();
    let asked = crate::traced::spawn(async move { asking.expose_dynamic(3000).await });
    expect_admit_ask(&mut requests).await;

    // The attached guest shell is shown nothing while the host asks.
    let mut seen = Vec::new();
    let _quiet = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(message) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = message {
                seen.extend_from_slice(&data);
            }
        }
    })
    .await;
    assert!(
        !String::from_utf8_lossy(&seen).contains(ASK_PROMPT),
        "the guest binding renders no ask dialog on a VM-backed host: {}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        !asked.is_finished(),
        "the expose waits on the host's answer"
    );
    assert!(served.lock().expect("served lock").is_empty());

    replies
        .send(host_end(minimald_rpc::AskAdmitOutcome::Admitted {
            ask_id: host_ask_id(),
            port: 3000,
            proto: boxes::IpProto::Tcp,
        }))
        .expect("the report door stand-in lives");
    let mapping = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask is answered once the host answers")
        .expect("the spawned request should not panic")
        .expect("the host's admitted ask publishes the port");
    assert_eq!(mapping.internal_port, 3000);
    forwarder.abort();
    assert_eq!(served.lock().expect("served lock").len(), 1);
    assert!(
        requests.try_recv().is_err(),
        "the answered ask is not reported to the host again"
    );
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decided_by"], "attached-human");
    assert_eq!(records[0]["outcome"], "published");
}

/// NET-045 on a native host is unchanged: the ask renders through the
/// binding on the attached client, and the human's deny refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_ask_prompt_still_renders() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    let mut channel = attach_live_shell(&mut client, web).await;
    let asked = crate::traced::spawn(async move { handle.expose_dynamic(3000).await });
    let rendered = answer_ask_on(&mut channel, false).await;
    assert!(
        String::from_utf8_lossy(&rendered).contains("web asks to publish port 3000"),
        "the native binding renders the dialog: {}",
        String::from_utf8_lossy(&rendered)
    );
    let refused = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask is answered")
        .expect("the spawned request should not panic");
    assert!(
        matches!(
            refused,
            Err(crate::net::policy::ExposeFailure::Refused(
                crate::net::policy::ExposeRefusal::DeniedByHuman
            ))
        ),
        "the human's deny refuses the request: {refused:?}"
    );
}

/// NET-045 on a VM-backed host: a no, and an ask the host found no
/// terminal for, publish nothing and leave nothing behind — the switch is
/// asked nothing, no admit is reported, and a later expose asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_no_or_no_tty_records_nothing() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    // The box runs, with no guest binding: on a VM-backed host the ask is
    // the host's to put to its attached client, never this daemon's.
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the ask box launches its host");
    let (forwarder, served, _door, mut requests, replies) = vm_backed_ask_box(&handle).await;

    for (reason, expected) in [
        (
            minimald_rpc::AskRefused::Denied,
            crate::net::policy::ExposeRefusal::DeniedByHuman,
        ),
        (
            minimald_rpc::AskRefused::NoTty,
            crate::net::policy::ExposeRefusal::AskNoTerminal,
        ),
    ] {
        let asking = handle.clone();
        let asked = crate::traced::spawn(async move { asking.expose_dynamic(3000).await });
        expect_admit_ask(&mut requests).await;
        replies
            .send(host_end(minimald_rpc::AskAdmitOutcome::Refused {
                ask_id: host_ask_id(),
                reason,
                cause: None,
            }))
            .expect("the report door stand-in lives");
        let refused = tokio::time::timeout(Duration::from_secs(30), asked)
            .await
            .expect("the ask is answered")
            .expect("the spawned request should not panic");
        assert!(
            matches!(&refused, Err(crate::net::policy::ExposeFailure::Refused(r)) if *r == expected),
            "{reason:?} refuses the expose with {expected:?}: {refused:?}"
        );
    }
    forwarder.abort();
    assert!(
        served.lock().expect("served lock").is_empty(),
        "nothing was asked of the switch"
    );
    assert!(
        requests.try_recv().is_err(),
        "nothing was reported to the host past the asks"
    );
    assert_eq!(
        handle.live_ingress().await.expect("the session answers"),
        crate::box_actor::LiveIngressRows::default(),
        "no mapping stands"
    );
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0]["decided_by"], "attached-human");
    assert_eq!(records[1]["decided_by"], "daemon");
    assert!(records.iter().all(|record| record["outcome"] == "refused"));
}

/// One VM-backed ask the host ends with `outcome`: the expose's result.
async fn vm_ask_ended_by_host(
    outcome: minimald_rpc::AskAdmitOutcome,
) -> Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure> {
    vm_ask_ended_by_host_audited(outcome).await.0
}

/// [`vm_ask_ended_by_host`], with the decision records the ask left.
async fn vm_ask_ended_by_host_audited(
    outcome: minimald_rpc::AskAdmitOutcome,
) -> (
    Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>,
    Vec<serde_json_lenient::Value>,
) {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the ask box launches its host");
    let (forwarder, served, _door, mut requests, replies) = vm_backed_ask_box(&handle).await;
    let asking = handle.clone();
    let asked = crate::traced::spawn(async move { asking.expose_dynamic(3000).await });
    expect_admit_ask(&mut requests).await;
    replies
        .send(host_end(outcome))
        .expect("the report door stand-in lives");
    let result = tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask is answered")
        .expect("the spawned request should not panic");
    forwarder.abort();
    if result.is_err() {
        assert!(
            served.lock().expect("served lock").is_empty(),
            "a refused ask asks the switch nothing"
        );
    }
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    (result, records)
}

fn host_refused(
    reason: minimald_rpc::AskRefused,
    cause: Option<minimald_rpc::AskCancelCause>,
) -> minimald_rpc::AskAdmitOutcome {
    minimald_rpc::AskAdmitOutcome::Refused {
        ask_id: host_ask_id(),
        reason,
        cause,
    }
}

/// NET-045 mapping: no client attached on the host when the ask arrived is
/// the typed nobody-is-attached refusal — the only host end that uses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_ask_no_client_is_nobody_attached() {
    let result = vm_ask_ended_by_host(host_refused(minimald_rpc::AskRefused::NoClient, None)).await;
    assert!(
        matches!(
            result,
            Err(crate::net::policy::ExposeFailure::Refused(
                crate::net::policy::ExposeRefusal::AskNeedsAnswer
            ))
        ),
        "{result:?}"
    );
}

/// NET-045 mapping: a client that could not show the prompt is the denied
/// refusal, never the nobody-attached one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_ask_no_tty_is_denied() {
    let capture = captured_log();
    let (result, records) =
        vm_ask_ended_by_host_audited(host_refused(minimald_rpc::AskRefused::NoTty, None)).await;
    assert!(
        matches!(
            result,
            Err(crate::net::policy::ExposeFailure::Refused(
                crate::net::policy::ExposeRefusal::AskNoTerminal
            ))
        ),
        "{result:?}"
    );
    assert!(
        capture
            .contents()
            .contains("the attached client could not show the prompt; treated as no"),
        "the no-tty end says why it was treated as no"
    );
    assert_eq!(records.len(), 1, "one ask is one decision: {records:?}");
    assert_eq!(records[0]["outcome"], "refused");
    assert_eq!(records[0]["decided_by"], "daemon");
    assert_eq!(
        records[0]["reason"], "the attached client could not show the prompt; treated as no",
        "the audit says the client could not show the prompt, not a plain deny"
    );
}

/// NET-045 mapping: a cancellation is a publish failure carrying its cause,
/// and the last detach adds that nobody is attached any more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_ask_cancelled_is_a_publish_failure_with_its_cause() {
    for (cause, says) in [
        (
            minimald_rpc::AskCancelCause::LastDetach,
            "nobody is attached any more",
        ),
        (
            minimald_rpc::AskCancelCause::RowWithdrawn,
            "row was withdrawn",
        ),
        (
            minimald_rpc::AskCancelCause::GuestClosed,
            "guest connection closed",
        ),
        (
            minimald_rpc::AskCancelCause::MinvmdStopping,
            "minvmd is stopping",
        ),
    ] {
        let result = vm_ask_ended_by_host(host_refused(
            minimald_rpc::AskRefused::Cancelled,
            Some(cause),
        ))
        .await;
        match result {
            Err(crate::net::policy::ExposeFailure::Publish { port: 3000, source }) => assert!(
                source.to_string().contains(says),
                "{cause:?} says {says}: {source}"
            ),
            other => panic!("{cause:?} is a publish failure, got {other:?}"),
        }
    }
}

/// NET-045 mapping: the host's own refusals are publish failures with the
/// host's reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_ask_host_refusals_are_publish_failures() {
    for (reason, says) in [
        (
            minimald_rpc::AskRefused::QueueFull,
            "already waiting for an answer",
        ),
        (
            minimald_rpc::AskRefused::OutsideGrant,
            "outside this box's --dynamic-range",
        ),
        (minimald_rpc::AskRefused::StanceNotAsk, "set to ask"),
        (
            minimald_rpc::AskRefused::NoRow,
            "not registered on the host",
        ),
    ] {
        let result = vm_ask_ended_by_host(host_refused(reason, None)).await;
        match result {
            Err(crate::net::policy::ExposeFailure::Publish { port: 3000, source }) => assert!(
                source.to_string().contains(says),
                "{reason:?} says {says}: {source}"
            ),
            other => panic!("{reason:?} is a publish failure, got {other:?}"),
        }
    }
}

/// NET-045, NET-138: a port published from a host-recorded yes is withdrawn
/// from the host's row when the box stops — the stop's sweep reports the
/// withdrawal like any runtime publish's, after the switch's unexpose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ask_yes_publish_withdraws_on_unexpose() {
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let (_web, handle) = dynamic_ingress_box(
        &server,
        &mut client,
        "web",
        Some(boxes::DynamicIngress::Ask),
        Some((3000, 3999)),
    )
    .await;
    handle
        .ensure_host("tester".to_string())
        .await
        .expect("the ask box launches its host");
    let (forwarder, served, _door, mut requests, replies) = vm_backed_ask_box(&handle).await;
    let asking = handle.clone();
    let asked = crate::traced::spawn(async move { asking.expose_dynamic(3000).await });
    expect_admit_ask(&mut requests).await;
    replies
        .send(host_end(minimald_rpc::AskAdmitOutcome::Admitted {
            ask_id: host_ask_id(),
            port: 3000,
            proto: boxes::IpProto::Tcp,
        }))
        .expect("the report door stand-in lives");
    tokio::time::timeout(Duration::from_secs(30), asked)
        .await
        .expect("the ask is answered")
        .expect("the spawned request should not panic")
        .expect("the host's yes publishes");

    let stopping = handle.clone();
    let stop = crate::traced::spawn(async move { stopping.stop().await });
    let withdrawal = tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the stop reports a withdrawal")
        .expect("the report door stand-in lives");
    assert!(
        matches!(
            withdrawal,
            minimald_rpc::BoxControlRequest::WithdrawPort(minimald_rpc::WithdrawPortRequest {
                switch_address: ASK_SWITCH,
                port: 3000,
                ..
            })
        ),
        "the ask-yes port is withdrawn from the host row: {withdrawal:?}"
    );
    assert!(
        served
            .lock()
            .expect("served lock")
            .iter()
            .any(|line| line.starts_with("POST /services/forwarder/unexpose ")),
        "the switch's unexpose precedes the withdrawal"
    );
    replies
        .send(minimald_rpc::BoxControlReply::PortRecorded {
            port: 3000,
            proto: boxes::IpProto::Tcp,
        })
        .expect("the report door stand-in lives");
    tokio::time::timeout(Duration::from_secs(30), stop)
        .await
        .expect("the stop finishes")
        .expect("the stop task should not panic");
    forwarder.abort();
}

/// Renders the shell-exit prompt with Enter answering it (the Keep item,
/// listed first) and returns what reached the terminal.
async fn rendered_shell_exit_prompt(holds_host_row: bool) -> String {
    let mut out: Vec<u8> = Vec::new();
    let disposition = Binding::shell_exit_prompt(
        None,
        None,
        &std::env::temp_dir(),
        "box",
        holds_host_row,
        &b"\r"[..],
        &mut out,
    )
    .await;
    assert_eq!(
        disposition,
        ExitDisposition::Kept,
        "Enter takes the Keep item"
    );
    String::from_utf8_lossy(&out).into_owned()
}

/// A registered box's Keep item says what keeping it leaves (NET-138): the
/// files, with the network registration that ends with the shell restored on
/// the next attach or exec. An unregistered box's prompt is unchanged.
#[tokio::test]
async fn shell_exit_keep_item_names_the_restored_registration_for_a_registered_box() {
    let registered = rendered_shell_exit_prompt(true).await;
    assert!(
        registered.contains(
            "Exit, keeping the session's files. Its network registration ends with the \
             shell and is restored when you attach or exec into the session again."
        ),
        "the registered box's Keep item; got: {registered:?}"
    );
    assert!(
        !registered.contains(SHELL_EXIT_KEEP),
        "the recoverable wording is not offered to a registered box; got: {registered:?}"
    );

    let unregistered = rendered_shell_exit_prompt(false).await;
    assert!(
        unregistered.contains("Exit, leaving the session filesystem in place and recoverable"),
        "an unregistered box keeps its Keep item; got: {unregistered:?}"
    );
    assert!(
        !unregistered.contains("network registration ends"),
        "an unregistered box's prompt is unchanged; got: {unregistered:?}"
    );
    let delete = "Delete, all in-session files permanently deleted";
    assert!(
        registered.contains(delete) && unregistered.contains(delete),
        "both prompts keep the Delete item"
    );
}

/// BEP-007: a grant's sealed value is placed in the grant's environment
/// variable, over any value the session's environment held there, and is
/// the only value the variable holds: in the published per-attach files the
/// shell re-reads before every command, and in what the host runs in the
/// box. A box with no grant gets no such variable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealed_value_is_placed_in_its_grant_variable_only() {
    const SEALED: &str = "v1.sealed-to-this-host";
    const PLAINTEXT: &str = "ghp_plaintexttoken";
    let tmp = tempfile::tempdir().unwrap();
    let home =
        DaemonAbsPath::try_new(camino::Utf8PathBuf::try_from(tmp.path().to_path_buf()).unwrap())
            .unwrap();
    let paths = BoxPaths {
        home: home.clone(),
        ..test_paths()
    };
    // A value already in the variable is the one a delivery must replace.
    // The launch places the deliveries before the host is built, the way
    // `launch_host` does.
    let mut attach_env = AttachEnv {
        inherited: vec![],
        connection: vec![
            ("TERM".to_string(), "xterm-256color".to_string()),
            ("GH_TOKEN".to_string(), PLAINTEXT.to_string()),
        ],
        entrypoint: vec![],
    };
    let connection_env = place_launch_deliveries(
        &mut attach_env,
        boxes::SessionId::nil(),
        &[boxes::SealedDelivery {
            variable: "GH_TOKEN".to_string(),
            sealed: SEALED.to_string(),
        }],
    );
    let (host, _handle) = Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths,
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env,
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host");

    // The shell's half: the files it re-reads before every command.
    let json = std::fs::read_to_string(home.sub_path_unchecked(ATTACH_ENV_JSON_REL).as_str())
        .expect("the build publishes the per-attach environment");
    let published: ConnectionEnv = serde_json_lenient::from_str(&json).expect("{json}");
    assert_eq!(published.get("GH_TOKEN").map(String::as_str), Some(SEALED));
    assert_eq!(
        published.get("TERM").map(String::as_str),
        Some("xterm-256color")
    );
    assert_eq!(published.len(), 2, "nothing else is placed: {published:?}");
    for rel in [ATTACH_ENV_SH_REL, ATTACH_ENV_FISH_REL, ATTACH_ENV_JSON_REL] {
        let body = std::fs::read_to_string(home.sub_path_unchecked(rel).as_str()).unwrap();
        assert!(body.contains(SEALED), "{rel}: {body}");
        assert!(
            !body.contains(PLAINTEXT),
            "{rel} holds the plaintext: {body}"
        );
    }

    // The host's half: what it runs in the box sees the sealed value.
    let output = host
        .command_in_session("sh", ["-c", "printenv GH_TOKEN"], Default::default())
        .expect("a host-side command under test")
        .output()
        .expect("printenv runs");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim_end(), SEALED);

    // A box with no grant places nothing.
    let mut env = ConnectionEnv::new();
    place_sealed_deliveries(&mut env, boxes::SessionId::nil(), &[]);
    assert!(env.is_empty(), "{env:?}");

    // A name that is not a variable name places nothing: it would be
    // shell code in the file the box's shell sources.
    place_sealed_deliveries(
        &mut env,
        boxes::SessionId::nil(),
        &[boxes::SealedDelivery {
            variable: "X=1; touch /tmp/owned #".to_string(),
            sealed: SEALED.to_string(),
        }],
    );
    assert!(env.is_empty(), "{env:?}");
}

/// BEP-007: the `AttachEnv` a launch hands the launcher holds each grant's
/// sealed value, so the shell's launch environment has it before its
/// entrypoint runs. The connection layer sits above the composition, so the
/// sealed value wins over a composition value in the same variable.
#[test]
fn sealed_value_reaches_the_shell_launch_environment() {
    const SEALED: &str = "v1.sealed-to-this-host";
    let mut attach_env = AttachEnv {
        inherited: vec![("LANG".to_string(), "C.UTF-8".to_string())],
        connection: vec![("TERM".to_string(), "xterm-256color".to_string())],
        entrypoint: vec![],
    };
    let kept = place_launch_deliveries(
        &mut attach_env,
        boxes::SessionId::nil(),
        &[boxes::SealedDelivery {
            variable: "GH_TOKEN".to_string(),
            sealed: SEALED.to_string(),
        }],
    );
    assert_eq!(kept.get("GH_TOKEN").map(String::as_str), Some(SEALED));
    assert_eq!(attach_env.connection_env(), kept);
    assert!(
        attach_env
            .connection
            .contains(&("GH_TOKEN".to_string(), SEALED.to_string())),
        "{:?}",
        attach_env.connection
    );
    let env = layer_session_env(
        session_baseline_env("box-1", None),
        attach_env.inherited.clone(),
        vec![("GH_TOKEN".to_string(), "from-the-composition".to_string())],
        attach_env.connection.clone(),
    );
    assert_eq!(env.get("GH_TOKEN").map(String::as_str), Some(SEALED));
    assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color"));
    assert_eq!(env.get("LANG").map(String::as_str), Some("C.UTF-8"));

    // A box with no grant changes nothing in the launch environment.
    let mut plain = AttachEnv {
        inherited: vec![],
        connection: vec![("TERM".to_string(), "xterm-256color".to_string())],
        entrypoint: vec![],
    };
    let kept = place_launch_deliveries(&mut plain, boxes::SessionId::nil(), &[]);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(
        plain.connection,
        vec![("TERM".to_string(), "xterm-256color".to_string())]
    );
}

// BEP-011: a box with the proxy's root and its own bundle gets the three
// trust variables, at its own bundle and root. A box whose packages ship no
// bundle gets NODE_EXTRA_CA_CERTS alone, so a tool that reads the bundle
// variables keeps its public roots. A box without the root gets none.
#[test]
fn trust_env_points_at_bundle_and_root() {
    let vars = launch_trust_env(true, true);
    let names: Vec<&str> = vars.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, boxes::core::bep::TRUST_ENV_VARIABLES);
    let get = |name: &str| {
        vars.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(get("SSL_CERT_FILE"), Some(BOX_CA_BUNDLE));
    assert_eq!(get("REQUESTS_CA_BUNDLE"), Some(BOX_CA_BUNDLE));
    assert_eq!(get("NODE_EXTRA_CA_CERTS"), Some(BOX_ROOT_CERTIFICATE));
    assert!(BOX_CA_BUNDLE.starts_with(BOX_CA_DIR));
    assert!(BOX_ROOT_CERTIFICATE.starts_with(BOX_CA_DIR));

    assert_eq!(
        launch_trust_env(true, false),
        vec![(
            "NODE_EXTRA_CA_CERTS".to_string(),
            BOX_ROOT_CERTIFICATE.to_string()
        )],
        "with no bundle only the root is named"
    );
    assert!(launch_trust_env(false, true).is_empty());
    assert!(launch_trust_env(false, false).is_empty());
}

// BEP-011: the trust variables sit below the composed environment, so a box
// spec that sets one keeps its own value, and the others still reach the box.
#[test]
fn trust_env_keeps_a_spec_value() {
    let mut env = layer_session_env(
        session_baseline_env("box", None),
        Vec::new(),
        vec![("SSL_CERT_FILE".to_string(), "/spec/roots.pem".to_string())],
        Vec::new(),
    )
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    layer_trust_env(&mut env, true, true);
    assert_eq!(env["SSL_CERT_FILE"], "/spec/roots.pem");
    assert_eq!(env["REQUESTS_CA_BUNDLE"], BOX_CA_BUNDLE);
    assert_eq!(env["NODE_EXTRA_CA_CERTS"], BOX_ROOT_CERTIFICATE);
}

/// Reads the pty master of a launch on a thread until `want` appears or
/// the far side closes, and hands back what it read.
fn read_pty_until(master: OwnedFd, want: &'static str) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut file = std::fs::File::from(master);
        let mut seen = String::new();
        let mut buf = [0u8; 1024];
        loop {
            match file.read(&mut buf) {
                // EIO when the last slave closes: the process is gone.
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if seen.contains(want) {
                        break;
                    }
                }
            }
        }
        let _ = tx.send(seen);
    });
    rx
}

// T42: the launch span and its info event name an argv entrypoint by its
// program and its argument count. An argument can carry a secret, so no
// argument reaches the daemon log. The name extends the T42 test line's
// filter, so that line runs this test too.
#[test]
fn launcher_starts_session_and_task_entrypoints_from_spec_without_logging_args() {
    let secret = "--token=s3cr3t-VALUE-0042";
    let entrypoint = LaunchEntrypoint::Argv {
        program: "/usr/bin/min".to_string(),
        args: vec!["task".to_string(), "run".to_string(), secret.to_string()],
    };
    let capture = crate::test_harness::CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let span = launch_span(boxes::SessionId::nil(), "dev", &entrypoint);
        let _entered = span.enter();
        tracing::info!("inside the launch");
    });
    let log = capture.contents();
    assert!(
        log.lines().any(|l| l.contains("INFO")
            && l.contains("launching the box's entrypoint from its spec")
            && l.contains("entrypoint=\"/usr/bin/min\"")
            && l.contains("args=3")),
        "the info event names the program and the argument count: {log}"
    );
    assert!(log.contains("box.launch"), "the span is in the log: {log}");
    for word in [secret, "s3cr3t", "task run"] {
        assert!(!log.contains(word), "no argument is logged ({word}): {log}");
    }

    // The shell logs as the login shell, with no arguments.
    assert_eq!(LaunchEntrypoint::Shell.log_name(), "login shell");
    assert_eq!(LaunchEntrypoint::Shell.arg_count(), 0);
}

// T42, T43: one launcher reads the box's first process from its spec. A
// session's spec starts its login shell. A task's spec starts its argv,
// except on a launch minted only for hooks, which holds the shell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launcher_starts_session_and_task_entrypoints_from_spec() {
    use mfile::spec::{BoxSpec, Entrypoint, SpecFlags};
    use std::sync::Arc;

    let session = Arc::new(BoxSpec::for_session(None, SpecFlags::default()));
    let task = mfile::Task::default();
    let task = Arc::new(
        BoxSpec::for_task("lint", &task, SpecFlags::default())
            .expect("a task that is not interactive has a spec"),
    );
    let launch = |spec: Option<Arc<BoxSpec>>, for_hooks: bool| LaunchSpec { spec, for_hooks };

    // The decision, for every kind of launch.
    assert_eq!(
        launch(Some(session.clone()), false).entrypoint().unwrap(),
        LaunchEntrypoint::Shell
    );
    assert_eq!(
        launch(Some(task.clone()), false).entrypoint().unwrap(),
        LaunchEntrypoint::Argv {
            program: "/usr/bin/min".to_string(),
            args: vec!["task".to_string(), "run".to_string(), "lint".to_string()],
        },
        "a bare program word names the program under /usr/bin"
    );
    assert_eq!(
        launch(Some(task.clone()), true).entrypoint().unwrap(),
        LaunchEntrypoint::Shell,
        "a hook launch holds the shell, so the task does not run before its hooks"
    );
    assert_eq!(
        launch(None, false).entrypoint().unwrap(),
        LaunchEntrypoint::Shell,
        "a box filed with no spec starts its shell"
    );
    let mut empty = (*task).clone();
    empty.entrypoint = Entrypoint::Exec(Vec::new());
    assert_eq!(
        launch(Some(Arc::new(empty)), false)
            .entrypoint()
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );

    // A session's launch starts the shell: the mock's echo loop.
    let launched = MockLauncher::default()
        .and_spec(launch(Some(session), false))
        .launch(
            boxes::SessionId::nil(),
            "dev".to_string(),
            "user".to_string(),
            test_paths(),
            DEFAULT_SIZE,
        )
        .await
        .expect("the session launches");
    let mut process = launched.process;
    let mut input = std::fs::File::from(launched.master.try_clone().unwrap());
    let output = read_pty_until(launched.master, "got:hello");
    input.write_all(b"hello\n").unwrap();
    let seen = output
        .recv_timeout(Duration::from_secs(10))
        .expect("the shell answers");
    assert!(seen.contains("got:hello"), "{seen:?}");
    input
        .write_all(format!("{MOCK_EXIT_LINE}\n").as_bytes())
        .unwrap();
    assert_eq!(process.wait().unwrap(), 0);

    // A task's launch starts the argv its spec names, here an absolute one
    // that exists on the test host.
    let mut echo = (*task).clone();
    echo.entrypoint = Entrypoint::Exec(vec!["/bin/echo".to_string(), "task-ran".to_string()]);
    let launched = MockLauncher::default()
        .and_spec(launch(Some(Arc::new(echo)), false))
        .launch(
            boxes::SessionId::nil(),
            "lint".to_string(),
            "user".to_string(),
            test_paths(),
            DEFAULT_SIZE,
        )
        .await
        .expect("the task launches");
    let mut process = launched.process;
    let output = read_pty_until(launched.master, "task-ran");
    let seen = output
        .recv_timeout(Duration::from_secs(10))
        .expect("the entrypoint prints");
    assert!(seen.contains("task-ran"), "{seen:?}");
    assert_eq!(
        process.wait().unwrap(),
        0,
        "the entrypoint returns on its own"
    );
}

/// Builds a mock host whose box ends when its entrypoint returns, with no
/// client bound to it.
async fn until_complete_host() -> (Host<MockProcess, ()>, HostHandle) {
    Host::build(
        MockLauncher::default(),
        HostParams {
            name: "test-session".to_string(),
            username: "user".to_string(),
            paths: test_paths(),
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: true,
            session_id: boxes::SessionId::nil(),
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        },
    )
    .await
    .expect("failed to build host")
}

// BOX-038: with no client attached, the entrypoint's return ends the host's
// loop by itself, and the loop says the entrypoint ended it, not a kill. The
// box's actor ends the box from that account. A kill from the daemon ends
// the loop too, and says so, so a stop or a replacement never reads as the
// entrypoint's own return.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn until_complete_ends_on_entrypoint_return_without_client() {
    let (host, _handle) = until_complete_host().await;
    assert!(host.remote.is_none(), "no client is bound to the host");
    let stdin = host.remote_tx.clone();
    let task = crate::traced::spawn(host.run());
    stdin
        .send(stdin_bytes(format!("{MOCK_EXIT_LINE}\n").into_bytes()))
        .await
        .expect("failed to send exit line");
    let exit = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the loop ends when the entrypoint returns, with no client attached")
        .expect("host task should not panic")
        .expect("the loop reaps the entrypoint");
    assert_eq!(exit.code, 0, "the entrypoint exited 0: {exit:?}");
    assert!(
        !exit.requested,
        "the entrypoint returned on its own, and no kill was asked for: {exit:?}"
    );

    let (host, handle) = until_complete_host().await;
    let task = crate::traced::spawn(host.run());
    handle.kill(false).await.expect("the host takes the kill");
    let killed = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the loop ends on a kill")
        .expect("host task should not panic")
        .expect("the loop reaps the killed entrypoint");
    assert!(
        killed.requested,
        "a kill from the daemon is not the entrypoint's return: {killed:?}"
    );
}

// BOX-013, BOX-038: a kill from the daemon can lose the race to the loop's
// own reap. The kill is queued, but the process is already dead, and the
// loop reaps it before `step` takes the kill. The daemon asked for that end,
// so the loop never reports it as the entrypoint's own return. With no kill
// queued, the same reap is not a requested end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_kill_racing_reap_is_not_a_natural_exit() {
    /// Kills the host's process and waits until it is a zombie, so the
    /// loop's first `try_wait` reaps it.
    async fn kill_and_await_zombie(host: &Host<MockProcess, ()>) {
        let pid = libc::pid_t::try_from(host.container_pid()).expect("pid fits in pid_t");
        // SAFETY: `kill` takes plain integers; `pid` is the mock entrypoint
        // this test spawned, which is not reaped yet.
        let rc = unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!(rc, 0, "failed to SIGKILL the mock entrypoint");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                let state = stat
                    .rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().next());
                if state == Some("Z") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the killed entrypoint becomes a zombie");
    }

    let capture = captured_log();
    let (host, handle) = until_complete_host().await;
    kill_and_await_zombie(&host).await;
    handle.kill(false).await.expect("the kill is queued");
    let exit = tokio::time::timeout(Duration::from_secs(10), crate::traced::spawn(host.run()))
        .await
        .expect("the loop ends on the reaped process")
        .expect("host task should not panic")
        .expect("the loop reaps the killed entrypoint");
    assert!(
        exit.requested,
        "a queued kill that lost the race to the reap is still the daemon's end: {exit:?}"
    );
    let logged = capture.contents();
    assert!(
        logged.contains("session host killed on request; the process was already reaped"),
        "the log says the kill lost the race to the reap:\n{logged}"
    );

    let (host, _handle) = until_complete_host().await;
    kill_and_await_zombie(&host).await;
    let exit = tokio::time::timeout(Duration::from_secs(10), crate::traced::spawn(host.run()))
        .await
        .expect("the loop ends on the reaped process")
        .expect("host task should not panic")
        .expect("the loop reaps the killed entrypoint");
    assert!(
        !exit.requested,
        "with no kill queued, the daemon did not ask for the end: {exit:?}"
    );
}

// BOX-038: a pty error can be stashed before a kill from the daemon arrives.
// The kill still ends the box, so the loop reports the end as requested, not
// as the entrypoint's own return.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_kill_racing_reap_is_not_a_natural_exit_after_pty_error() {
    let capture = captured_log();
    let (mut host, handle) = until_complete_host().await;
    host.record_pty_err(PtyOp::Read, std::io::Error::from_raw_os_error(libc::EIO));
    handle.kill(false).await.expect("the kill is queued");
    let exit = tokio::time::timeout(Duration::from_secs(10), crate::traced::spawn(host.run()))
        .await
        .expect("the loop ends on the kill")
        .expect("host task should not panic")
        .expect("the loop reaps the killed entrypoint");
    assert!(
        exit.requested,
        "a kill after a stashed pty error is the daemon's end: {exit:?}"
    );
    let logged = capture.contents();
    assert!(
        logged.contains("session process reaped after requested teardown"),
        "the reap is logged as a requested teardown:\n{logged}"
    );
}

/// A box filed in a real store under a temp dir, so its host writes the
/// box's log and its bindings write the box's events beside a real record.
struct StoredBox {
    _tmp: tempfile::TempDir,
    dir: boxes::store::BoxDir,
    paths: BoxPaths,
    id: boxes::SessionId,
    parent: boxes::SessionId,
}

impl StoredBox {
    fn new() -> Self {
        use boxes::store::{BoxObject as _, Loader as _};

        let tmp = tempfile::TempDir::new().unwrap();
        let root = DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap();
        let mut loader = boxes::store::DiskLoader::new(root).unwrap();
        let parent = boxes::SessionId::mint();
        let key = loader.create(stored_record(parent)).unwrap();
        let object = loader.get(&key).unwrap();
        let paths = BoxPaths {
            working: object.workspace_path(),
            cache: object.cache_path(),
            home: object.home_path(),
            patches: object.patches_path(),
            hooks: object.hooks_path(),
        };
        for dir in [&paths.working, &paths.cache, &paths.home] {
            std::fs::create_dir_all(dir.as_utf8_path()).unwrap();
        }
        Self {
            _tmp: tmp,
            dir: object.dir(),
            paths,
            id: object.record().id,
            parent,
        }
    }

    fn params(&self) -> HostParams {
        HostParams {
            name: "logged".to_string(),
            username: "user".to_string(),
            paths: BoxPaths {
                working: self.paths.working.clone(),
                cache: self.paths.cache.clone(),
                home: self.paths.home.clone(),
                patches: self.paths.patches.clone(),
                hooks: self.paths.hooks.clone(),
            },
            sz: DEFAULT_SIZE,
            channel: None,
            control: None,
            delta: None,
            archives_dir: std::env::temp_dir(),
            holds_host_row: false,
            ends_with_entrypoint: false,
            session_id: self.id,
            composition: None,
            connection_env: ConnectionEnv::new(),
            #[cfg(target_os = "linux")]
            name_marker: None,
        }
    }

    /// The box's log as it stands.
    fn log(&self) -> String {
        String::from_utf8_lossy(&self.dir.read_log_from(0, usize::MAX).unwrap()).into_owned()
    }

    /// Waits until the box's log contains `needle`, and returns the log.
    async fn await_log(&self, needle: &str) -> String {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let log = self.log();
                if log.contains(needle) {
                    return log;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the log never showed {needle:?}: {:?}", self.log()))
    }

    /// The box's `detached` events as they stand.
    fn detached(&self) -> Vec<boxes::events::BoxEvent> {
        let text =
            std::fs::read_to_string(self.dir.events_path().as_utf8_path()).unwrap_or_default();
        text.lines()
            .map(|line| serde_json_lenient::from_str::<boxes::events::BoxEvent>(line).unwrap())
            .filter(|event| event.kind == boxes::events::BoxEventType::Detached)
            .collect()
    }

    /// Waits until the box has `n` `detached` events, and returns them.
    async fn await_detached(&self, n: usize) -> Vec<boxes::events::BoxEvent> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let events = self.detached();
                if events.len() >= n {
                    return events;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the box never had {n} detached events: {:?}",
                self.detached()
            )
        })
    }
}

fn stored_record(parent: boxes::SessionId) -> boxes::Record {
    boxes::Record {
        id: boxes::SessionId::nil(),
        name: Some("logged".to_string()),
        username: None,
        project_path: paths::HostAbsPath::try_new("/p").unwrap(),
        network: boxes::NetworkMode::default(),
        policy: boxes::BoxPolicy::default(),
        status: boxes::BoxState::default(),
        reason: None,
        exit_code: None,
        signal: None,
        hooks_enabled: true,
        task_addresses: Vec::new(),
        box_addresses: None,
        host_ip_enforcement: None,
        box_id: None,
        host_row_bound: false,
        bound_ports: std::collections::BTreeSet::new(),
        sealed_deliveries: Vec::new(),
        root_certificate: None,
        ends_with_run: false,
        box_type: None,
        parent: Some(parent),
        project_root: None,
        attrs: BTreeMap::new(),
    }
}

/// Attaches a client to the host over an in-process ssh connection, and
/// returns the client's end of the channel and the connection.
async fn ssh_attach(
    handle: &HostHandle,
) -> (
    russh::Channel<russh::client::Msg>,
    russh::client::Handle<TrustingClient>,
) {
    let (server_side, client_side) = tokio::net::UnixStream::pair().unwrap();
    let key = russh::keys::PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        russh::keys::Algorithm::Ed25519,
    )
    .unwrap();
    let server_config = Arc::new(russh::server::Config {
        keys: vec![key],
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let (caught_tx, mut caught) = mpsc::unbounded_channel();
    let (server, client) = tokio::join!(
        russh::server::run_stream(server_config, server_side, ChannelCatcher(caught_tx)),
        russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            client_side,
            TrustingClient
        ),
    );
    crate::traced::spawn(server.expect("ssh server handshake"));
    let mut client = client.expect("ssh client handshake");
    let auth = client.authenticate_none("test").await.unwrap();
    assert!(auth.success(), "the test server accepts anyone");
    let channel = client.channel_open_session().await.unwrap();
    let server_channel = caught.recv().await.expect("the server caught the channel");
    assert!(
        handle
            .attach(
                server_channel,
                DEFAULT_SIZE,
                ConnectionEnv::new(),
                SessionKeys::default(),
            )
            .await
            .is_ok(),
        "the host must take the attach",
    );
    (channel, client)
}

/// BOX-016: a PTY client that leaves without a detach, by closing its
/// channel or by losing its connection, is recorded as one `detached`
/// event each, naming the box and its parent. The box runs on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pty_client_loss_records_detach() {
    let stored = StoredBox::new();
    let (host, handle) = Host::build(MockLauncher::default(), stored.params())
        .await
        .expect("failed to build host");
    let task = crate::traced::spawn(host.mainloop());
    assert!(stored.detached().is_empty(), "no client has left yet");

    // A client that closes its channel.
    let (channel, first) = ssh_attach(&handle).await;
    channel.close().await.unwrap();
    let events = stored.await_detached(1).await;
    assert_eq!(events.len(), 1, "one event per client loss: {events:?}");

    // A client whose connection drops.
    let (_channel, second) = ssh_attach(&handle).await;
    second
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    drop(second);
    let events = stored.await_detached(2).await;
    assert_eq!(events.len(), 2, "one event per client loss: {events:?}");
    for event in &events {
        assert_eq!(event.box_id, stored.id);
        assert_eq!(event.parent, Some(stored.parent));
    }

    // The box runs on.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!task.is_finished(), "a client loss must not end the box");
    tokio::time::timeout(Duration::from_secs(5), handle.get_attrs())
        .await
        .expect("the host keeps answering after a client loss")
        .expect("the host is still running");

    handle.kill(true).await.expect("kill should reach the host");
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
    drop(first);
}

/// BOX-016: a PTY client that leaves without a detach runs the box's
/// `on_detach` hooks, as a detach does, so the hooks agree with the
/// `detached` event the loss records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pty_client_loss_records_detach_and_runs_detach_hooks() {
    use crate::test_harness::{create_session_req, unwrap_ready};
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };

    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("detached");
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let id = client
        .call::<CreateSession>(&create_session_req("lost-client-hooks", "/uwu"))
        .await
        .unwrap()
        .id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: boxes::wire::request::WireContribution {
                    lifecycle_hooks: vec![boxes::wire::primitives::WireProvenancedHook {
                        hook: boxes::wire::primitives::WireLifecycleHook {
                            on_detach: Some(boxes::wire::primitives::WireHookScript::Inline {
                                body: format!("echo ran > {}", marker.display()),
                                timeout_secs: 60,
                            }),
                            ..Default::default()
                        },
                        source: boxes::wire::primitives::WireSource::UserLoadout {
                            name: "test".to_string(),
                        },
                    }],
                    ..Default::default()
                },
            })
            .await
            .unwrap(),
    );
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }

    let mut channel = client.open_shell(id).await;
    // The shell is up once its first output arrives.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { .. }) => return,
                Some(_) => {}
                None => panic!("the channel closed before the shell wrote"),
            }
        }
    })
    .await
    .expect("the shell writes to the attached client");
    assert!(!marker.exists(), "no client has left yet");

    channel.close().await.unwrap();
    let ran = tokio::time::timeout(Duration::from_secs(10), async {
        while !marker.exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(ran.is_ok(), "a lost client did not run the detach hooks");
}

/// BOX-155: a box that writes past the cap runs on, and leaves a log no
/// larger than [`boxes::store::LOG_CAP`] that holds its newest output after
/// the dropped-output line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_output_logged_from_start_complete_after_disconnect_past_cap_keeps_newest() {
    use mfile::spec::{BoxSpec, Entrypoint, SpecFlags};

    let stored = StoredBox::new();
    let past_cap = boxes::store::LOG_CAP + boxes::store::LOG_CAP / 8;
    let script = format!("head -c {past_cap} /dev/zero | tr '\\0' a; printf 'newest\\n'; sleep 60");
    let mut spec = BoxSpec::for_session(None, SpecFlags::default());
    spec.entrypoint = Entrypoint::Exec(vec!["/bin/sh".to_string(), "-c".to_string(), script]);
    let launcher = MockLauncher::default().and_spec(LaunchSpec {
        spec: Some(Arc::new(spec)),
        for_hooks: false,
    });
    let (host, handle) = Host::build(launcher, stored.params())
        .await
        .expect("failed to build host");
    let task = crate::traced::spawn(host.mainloop());

    let log = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let log = stored.dir.read_log_from(0, usize::MAX).unwrap();
            if log.ends_with(b"newest\r\n") {
                return log;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the box's newest output reaches its log");

    assert!(
        log.len() as u64 <= boxes::store::LOG_CAP,
        "the log is {} bytes, past the cap",
        log.len()
    );
    assert!(
        log.starts_with(boxes::store::LOG_DROPPED),
        "the log says older output was dropped"
    );
    let kept = &log[boxes::store::LOG_DROPPED.len()..];
    let output = kept.strip_suffix(b"newest\r\n").unwrap();
    assert!(
        !output.is_empty() && output.iter().all(|&b| b == b'a'),
        "the log keeps the newest output and nothing else"
    );
    assert!(!task.is_finished(), "the box runs on past the cap");
    handle.kill(true).await.expect("kill should reach the host");
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
}

/// T43: an entrypoint on pipes that ends before its run takes the streams
/// keeps its output for the run. The host reaps it, then still answers the
/// run's take with what the entrypoint wrote, and its exit follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fast_entrypoint_on_pipes_keeps_its_output_for_a_late_run() {
    use mfile::spec::{BoxSpec, Entrypoint, SpecFlags};

    let stored = StoredBox::new();
    let mut spec = BoxSpec::for_session(None, SpecFlags::default());
    spec.pty_enabled = false;
    spec.entrypoint = Entrypoint::Exec(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "echo fast-out; echo fast-err >&2; exit 3".to_string(),
    ]);
    let launcher = MockLauncher::default().and_spec(LaunchSpec {
        spec: Some(Arc::new(spec)),
        for_hooks: false,
    });
    let (host, handle) = Host::build(launcher, stored.params())
        .await
        .expect("failed to build host");
    let task = crate::traced::spawn(host.run());

    // Several exit polls go by, so the host has reaped the entrypoint before
    // the run asks for its streams.
    tokio::time::sleep(pipes::PIPE_EXIT_POLL * 5).await;
    assert!(
        !task.is_finished(),
        "the host holds the ended entrypoint's output for its run"
    );

    let io = match handle.take_entrypoint_io().await {
        EntrypointIoTake::Taken(io) => io,
        EntrypointIoTake::OnTerminal => panic!("an entrypoint on pipes read as on a terminal"),
        EntrypointIoTake::Relayed => panic!("no other run took the streams"),
        EntrypointIoTake::HostGone => panic!("the host ended before the run took the streams"),
    };
    let collect = |mut rx: mpsc::Receiver<Vec<u8>>| async move {
        let mut out = Vec::new();
        while let Some(chunk) = rx.recv().await {
            out.extend_from_slice(&chunk);
        }
        String::from_utf8(out).unwrap()
    };
    let (stdout, stderr) = tokio::time::timeout(
        Duration::from_secs(10),
        futures::future::join(collect(io.stdout), collect(io.stderr)),
    )
    .await
    .expect("the streams end with the host");
    assert_eq!(stdout, "fast-out\n", "the run gets the entrypoint's stdout");
    assert_eq!(stderr, "fast-err\n", "the run gets the entrypoint's stderr");

    let exit = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the host ends once the run took the streams");
    let exit = exit
        .expect("host task should not panic")
        .expect("the host reaps the entrypoint");
    assert_eq!(exit.code, 3, "the entrypoint's own exit code");
    assert!(!exit.requested, "nobody asked for the end");
}

/// T43: the host hands its entrypoint's streams to one run at a time. A
/// second take while the first run still reads them is refused, and the
/// first run keeps every byte. Once the first run's streams close, a later
/// run takes them in its place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_take_of_entrypoint_streams_is_refused_while_the_first_reads() {
    use mfile::spec::{BoxSpec, Entrypoint, SpecFlags};

    let stored = StoredBox::new();
    let mark = stored._tmp.path().join("go");
    let script = format!(
        r#"while [ ! -e '{}' ]; do sleep 0.05; done; echo first-out; echo first-err >&2; sleep 60"#,
        mark.display()
    );
    let mut spec = BoxSpec::for_session(None, SpecFlags::default());
    spec.pty_enabled = false;
    spec.entrypoint = Entrypoint::Exec(vec!["/bin/sh".to_string(), "-c".to_string(), script]);
    let launcher = MockLauncher::default().and_spec(LaunchSpec {
        spec: Some(Arc::new(spec)),
        for_hooks: false,
    });
    let (host, handle) = Host::build(launcher, stored.params())
        .await
        .expect("failed to build host");
    let task = crate::traced::spawn(host.run());

    let EntrypointIoTake::Taken(mut first) = handle.take_entrypoint_io().await else {
        panic!("the first run takes the streams");
    };
    assert!(first.stdin.is_some(), "the first run gets the stdin");
    assert!(
        matches!(handle.take_entrypoint_io().await, EntrypointIoTake::Relayed),
        "a second run is refused while the first reads"
    );

    std::fs::write(&mark, b"").unwrap();
    async fn recv(rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("the output reaches the first run")
            .expect("the first run's stream is still open")
    }
    assert_eq!(recv(&mut first.stdout).await, b"first-out\n");
    assert_eq!(recv(&mut first.stderr).await, b"first-err\n");

    drop(first);
    let EntrypointIoTake::Taken(later) = handle.take_entrypoint_io().await else {
        panic!("a run takes the streams once the first run's streams closed");
    };
    assert!(
        later.stdin.is_none(),
        "only the first run gets the entrypoint's stdin"
    );

    handle.kill(true).await.expect("kill should reach the host");
    let _ended = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the host ends after the kill");
}

/// BOX-155: the box's output is in its log from the start, with no client
/// attached. An attached client reads the same output as a second reader,
/// and after the client drops, the log holds what came before, during and
/// after the attach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn box_output_logged_from_start_complete_after_disconnect() {
    use mfile::spec::{BoxSpec, Entrypoint, SpecFlags};
    use tokio::io::AsyncWriteExt as _;

    let stored = StoredBox::new();
    let mark = stored._tmp.path().join("client-gone");
    let script = format!(
        r#"printf 'early\n'; read x; printf 'during:%s\n' "$x"; while [ ! -e '{}' ]; do sleep 0.05; done; printf 'after\n'; sleep 60"#,
        mark.display()
    );
    let mut spec = BoxSpec::for_session(None, SpecFlags::default());
    spec.entrypoint = Entrypoint::Exec(vec!["/bin/sh".to_string(), "-c".to_string(), script]);
    let launcher = MockLauncher::default().and_spec(LaunchSpec {
        spec: Some(Arc::new(spec)),
        for_hooks: false,
    });
    let (host, handle) = Host::build(launcher, stored.params())
        .await
        .expect("failed to build host");
    let task = crate::traced::spawn(host.mainloop());

    // Logged with no client attached.
    stored.await_log("early").await;
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(stored.dir.log_path().as_utf8_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "only the daemon's user can open the log"
        );
    }

    // An attached client reads the output too.
    let (mut channel, client) = ssh_attach(&handle).await;
    channel.make_writer().write_all(b"hello\n").await.unwrap();
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !String::from_utf8_lossy(&seen).contains("during:hello") {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => seen.extend_from_slice(&data),
                Some(_) => {}
                None => panic!("the channel closed before the output arrived"),
            }
        }
    })
    .await
    .expect("the attached client reads the box's output");

    // The client drops, then the box writes more.
    client
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .unwrap();
    drop(channel);
    drop(client);
    stored.await_detached(1).await;
    std::fs::write(&mark, b"").unwrap();

    let log = stored.await_log("after").await;
    let at = |needle: &str| {
        log.find(needle)
            .unwrap_or_else(|| panic!("the log has no {needle:?}: {log:?}"))
    };
    assert!(
        at("early") < at("during:hello") && at("during:hello") < at("after"),
        "the log holds the output in order: {log:?}"
    );

    assert!(
        !task.is_finished(),
        "the box runs on after its client drops"
    );
    handle.kill(true).await.expect("kill should reach the host");
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
}

/// NET-046: a box with no switch address, on a VM host, asks to publish a
/// port, is refused, and the VM host daemon still hears the decision. On a
/// microVM the box with no switch is a `none` box: an `own_ip` box with no
/// handed addresses is refused at create. No audit route names a box with no
/// switch, so the report carries the box's id in place of a switch address,
/// over the box's own control channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_switch_box_reports_expose_decision_by_id() {
    use crate::test_harness::unwrap_ready;
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    // A `none` box that declares no `dynamic_ingress`: the deny-all default
    // decides its request.
    let request = minimald_rpc::CreateSessionRequest::new(
        "web",
        paths::HostAbsPath::try_new("/uwu").unwrap(),
        boxes::NetworkMode::NoNet,
        boxes::BoxPolicy {
            egress: None,
            ingress: None,
            credentialed_upstream: None,
            quic443: None,
        },
    );
    assert!(request.config.box_addresses.is_none());
    let id = client.call::<CreateSession>(&request).await.unwrap().id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
    let handle = server
        .state
        .sessions_manager()
        .await
        .get_session(crate::box_manager::BoxKeyPredicate::Id(id))
        .await
        .unwrap()
        .expect("the web box should resolve");
    let sock = handle
        .net_switch()
        .await
        .unwrap()
        .lock()
        .await
        .control_socket();
    // The switch's control channel is VM-shaped: its door is the stand-in.
    let door_sock = sock.with_file_name("no-switch-door.sock");
    let (door, mut reports, replies) = fake_report_door(&door_sock).await;
    crate::net::listeners::seed_vm_report_door_for_tests(&sock, &door_sock);

    match handle.expose_dynamic(3000).await {
        Err(crate::net::policy::ExposeFailure::Refused(
            crate::net::policy::ExposeRefusal::DeniedByPolicy,
        )) => {}
        other => panic!("a box that declares no dynamic ingress is refused: {other:?}"),
    }

    let report = tokio::time::timeout(Duration::from_secs(10), reports.recv())
        .await
        .expect("the refusal is reported to the VM host daemon")
        .expect("the report door stand-in lives");
    replies
        .send(minimald_rpc::BoxControlReply::Audited { audited: true })
        .expect("the report door stand-in lives");
    door.abort();
    crate::net::listeners::clear_vm_report_door_for_tests(&sock);
    assert_eq!(
        report,
        minimald_rpc::BoxControlRequest::ReportExposeDecision(minimald_rpc::ExposeDecisionReport {
            switch_address: None,
            box_id: Some(id),
            port: 3000,
            decision: boxes::DynamicIngress::Deny,
            decided_by: minimald_rpc::ExposeDecidedBy::BoxPolicy,
            outcome: minimald_rpc::ExposeDecisionOutcome::Refused,
        }),
        "a box with no switch is named to the host by its id"
    );

    // The local record lands as it always did.
    let records = audit_records(&server.state.minimal_state_dir().await).await;
    assert_eq!(records.len(), 1, "one request is one decision: {records:?}");
    assert_eq!(records[0]["box"], "web");
    assert_eq!(records[0]["outcome"], "refused");
}

/// BEP-085: a `host_ip` box with `proxy_env` or `both` steering gets the four
/// proxy variables on a VM host, where the host-side gate admits its cohort
/// to the proxy's listener. On a native host it shares the host's network,
/// no gate admits it, and it gets none.
#[test]
fn host_ip_box_on_vm_host_gets_the_proxy_variables() {
    use super::proxy_env_tests::{record, steering};
    use boxes::NetworkMode;
    use boxes::core::bep::Steering;

    for mode in [Steering::ProxyEnv, Steering::Both] {
        let laned = record(NetworkMode::HostNet, Some(steering(mode)));
        let vars = launch_proxy_env(&laned, switch::DEFAULT_SUBNET, paths::HostKind::Minvmd);
        let names: Vec<&str> = vars.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "NO_PROXY",
                "NODE_USE_ENV_PROXY"
            ],
            "{mode:?}: {vars:?}"
        );
        assert_eq!(vars[0].1, "http://100.64.255.252:8118", "{mode:?}");

        let native = launch_proxy_env(&laned, switch::DEFAULT_SUBNET, paths::HostKind::Minimald);
        assert!(native.is_empty(), "{mode:?} on a native host: {native:?}");
    }
    // The launch reads the host kind from the switch's transport.
    assert_eq!(
        host_kind_of(crate::net::SwitchTransport::HostShuttle { cid: 2, port: 1024 }),
        paths::HostKind::Minvmd
    );
    assert_eq!(
        host_kind_of(crate::net::SwitchTransport::LocalSpawn),
        paths::HostKind::Minimald
    );
}

/// Creates and finalizes a task box for task `check` whose entrypoint is
/// `argv`, as `min task run` creates one, and returns its id.
async fn create_task_box_for_run(
    client: &mut crate::test_harness::TestClient,
    argv: &[&str],
) -> boxes::SessionId {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, CreateSession, Errorable, FinalizeSession,
        FinalizeSessionRequest,
    };
    let mut spec = mfile::spec::BoxSpec::for_task(
        "check",
        &mfile::Task::default(),
        mfile::spec::SpecFlags::default(),
    )
    .expect("a task that is not interactive has a spec");
    spec.entrypoint = mfile::spec::Entrypoint::Exec(argv.iter().map(ToString::to_string).collect());
    let mut req = crate::test_harness::create_session_req("check", "/tmp");
    req.config.creating_verb = minimald_rpc::CreatingVerb::Task;
    req.config.ends_with_run = true;
    req.spec = Some(serde_json_lenient::to_value(&spec).expect("a spec serializes"));
    let id = client.call::<CreateSession>(&req).await.unwrap().id;
    crate::test_harness::unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    match client
        .call::<FinalizeSession>(&FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        })
        .await
    {
        Errorable::Ok(_) => {}
        Errorable::Err { error } => panic!("FinalizeSession failed: {error}"),
    }
    id
}

/// Reads a box's whole output log over the `ReadLog` subsystem, without
/// following, and returns its bytes as text.
async fn read_box_output(
    client: &mut crate::test_harness::TestClient,
    id: boxes::SessionId,
) -> String {
    use minimald_rpc::{ReadLogRequest, ReadLogUpdate};
    use tokio::io::AsyncWriteExt as _;

    let mut channel = client
        .open_subsystem(minimald_rpc::READ_LOG_SUBSYSTEM, &[])
        .await;
    let req = ReadLogRequest {
        id,
        offset: 0,
        follow: false,
    };
    let mut writer = channel.make_writer();
    writer
        .write_all(&serde_json_lenient::to_vec(&req).unwrap())
        .await
        .unwrap();
    drop(writer);
    channel.eof().await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => out.extend_from_slice(&data),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("the log read answers in time");
    let mut output = Vec::new();
    let mut done = false;
    for line in String::from_utf8(out).unwrap().lines() {
        match serde_json_lenient::from_str::<ReadLogUpdate>(line).expect("each line is an update") {
            ReadLogUpdate::Output { data, .. } => output.extend_from_slice(&data),
            ReadLogUpdate::Done { .. } => done = true,
            other => panic!("the log read ended with {other:?}"),
        }
    }
    assert!(done, "the log read reaches the end of the log");
    String::from_utf8_lossy(&output).into_owned()
}

// T11, end to end: a task run starts a task box, and its client goes away
// while the task still runs. The task then writes more and exits 3. The box
// ends by itself as `exited` with code 3. Its record, its `exited` event and
// its whole output stay readable by a new client, and the daemon log names
// the box's end and its code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_box_exits_with_code_and_output_after_client_drop() {
    use boxes::core::record::{ExitEnding, RecordState};

    let log = captured_log();
    let server = TestServer::new().await;
    let mut client = server.connect().await;
    let mark = tempfile::tempdir().unwrap();
    let mark = mark.path().join("client-gone");
    let script = format!(
        "echo before-drop; while [ ! -e '{}' ]; do sleep 0.05; done; \
         echo after-drop; echo task-err >&2; sleep 1; exit 3",
        mark.display()
    );
    let id = create_task_box_for_run(&mut client, &["/bin/sh", "-c", &script]).await;

    let run = crate::traced::spawn(async move {
        let outcome = client
            .exec(
                &[(crate::MINIMAL_SESSION_ID_ENV, &id.to_string())],
                false,
                &minimald_rpc::exec::ExecRequest::TaskRun {
                    task: "check".to_string(),
                    owns_box: false,
                    args: vec![],
                    cwd: String::new(),
                }
                .encode(),
                b"",
            )
            .await;
        drop(client);
        outcome
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while !log
            .contents()
            .contains("task box: the run relays the box's entrypoint")
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the run relays the box's entrypoint");

    // The client goes away mid-run: its channel and connection drop.
    run.abort();
    let _ = run.await;
    std::fs::write(&mark, b"").unwrap();

    let manager = server.state.sessions_manager().await;
    let record = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let record = manager
                .get_record(crate::box_manager::BoxKeyPredicate::Id(id))
                .await
                .unwrap()
                .expect("an ended task box keeps its record");
            if record.status == boxes::BoxState::Exited {
                break record;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the task box never exited: {}", log.contents()));
    assert_eq!(
        record.state().unwrap(),
        RecordState::Exited(ExitEnding::Exit { exit_code: 3 }),
        "the box is exited with the task's own code"
    );
    assert_eq!(record.exit_code, Some(3));

    let mut events = manager.box_events(id).await.unwrap();
    let events = events.read_new().unwrap();
    let exited = events
        .iter()
        .find(|e| e.kind == boxes::events::BoxEventType::Exited)
        .unwrap_or_else(|| panic!("the end records an exited event: {events:?}"));
    assert_eq!(exited.data["reason"], "exit");
    assert_eq!(exited.data["exit_code"], 3);

    // A new client reads the box's whole output after its end.
    let mut reader = server.connect().await;
    let output = read_box_output(&mut reader, id).await;
    for line in ["before-drop", "after-drop", "task-err"] {
        assert!(
            output.contains(line),
            "the box's output keeps {line:?} after the client drop: {output:?}"
        );
    }

    let log = log.contents();
    let ended = log
        .lines()
        .find(|line| line.contains("task box ended") && line.contains(&id.to_string()))
        .unwrap_or_else(|| panic!("the daemon log names the task box's end: {log}"));
    assert!(
        ended.contains("exit_code=3"),
        "the daemon log names the task's exit code: {ended}"
    );
    assert!(
        log.contains("reading a box's log") && log.contains(&id.to_string()),
        "the daemon log names the read of the box's output: {log}"
    );
}
