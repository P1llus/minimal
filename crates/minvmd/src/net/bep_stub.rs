//! A stand-in for the credential proxy's acceptor, for tests and for hosts
//! where the proxy does not run (it keeps its keys in the macOS Keychain).
//!
//! The supervisor binds it behind `MINVMD_BEP_STUB`. It checks what the real
//! acceptor checks first, the peer's credentials and the boot token, and
//! reads the delivery header with the proxy's own parser. Like the proxy it
//! takes the box id the supervisor wrote: the token proves who wrote it. It
//! answers one line naming what it was presented and closes, and it keeps
//! every line and every refusal for a test to read.

use std::io::{Read, Write};
// Both peer-credential reads ask the kernel over the stream's own fd —
// `SO_PEERCRED` on Linux, `getpeereid` off it — so the import is ungated.
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;

use bep::listener::{DELIVERY_HEADER_LEN, Delivery, Entry, TOKEN_LEN};

/// How long one connection may take to present its token and header. The
/// pool writes both in one go, so this bound only catches a connection that
/// is stalling; it must not let one hold the serving thread forever.
const PRESENT_TIMEOUT: Duration = Duration::from_secs(30);

/// The start-up facts the supervisor hands the stand-in over the channel it
/// receives at [`spawn`]: the per-boot token minted for this boot — the same
/// bytes wired into the peer — the host daemon's pid, the process the
/// pool's deliveries are supposed to come from, and the proxy's attachment
/// table, the stand-in's own facts about which boxes are attached
/// (NET-133).
pub struct StubStart {
    /// The token every delivered connection presents first.
    pub token: [u8; TOKEN_LEN],
    /// The host daemon's pid; on Linux a connection from any other process
    /// is refused before it presents anything.
    pub daemon_pid: u32,
}

/// What the stand-in holds for its caller: the handle of the serving thread
/// — held for its lifetime, never joined; it ends with the process — and
/// the two records the tests read, shared with every connection it serves.
pub struct BepStub {
    /// The answer lines sent, one per accepted connection.
    presented: Arc<Mutex<Vec<String>>>,
    /// The refusal reasons audited, one per refused connection.
    refusals: Arc<Mutex<Vec<&'static str>>>,
    /// The serving thread; dropped without joining, so the thread runs
    /// until the process exits.
    _thread: JoinHandle<()>,
}

impl BepStub {
    /// The answer lines the stand-in sent, in the order it sent them.
    pub fn presented(&self) -> Vec<String> {
        self.presented
            .lock()
            .expect("the presented lock is never held across a panic, so it cannot be poisoned")
            .clone()
    }

    /// The reasons the stand-in refused connections for, in arrival order.
    pub fn refusals(&self) -> Vec<&'static str> {
        self.refusals
            .lock()
            .expect("the refusals lock is never held across a panic, so it cannot be poisoned")
            .clone()
    }
}

/// Bind the stand-in acceptor at `sock_path` — the proxy socket path the
/// supervisor names — and serve until the process exits, reading its
/// start-up facts (the token, the daemon's pid) from `start`.
///
/// The bind happens on the calling thread so its failure surfaces to the
/// supervisor's own startup error handling; the accept loop moves to the
/// thread, in the shape of [`crate::control::spawn`]. The socket gets the
/// bridge-socket posture: path-length check, a 0700 parent dir, a stale
/// socket removed, and 0600 on the socket itself.
///
/// # Errors
///
/// Returns the I/O error if the socket path is too long, its parent dir
/// cannot be prepared, a stale file cannot be removed, the bind fails, or
/// the permissions cannot be enforced.
pub fn spawn(sock_path: PathBuf, start: Receiver<StubStart>) -> std::io::Result<BepStub> {
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    let presented: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let refusals: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let thread_presented = Arc::clone(&presented);
    let thread_refusals = Arc::clone(&refusals);
    let thread = std::thread::Builder::new()
        .name("minvmd-bep-stub".to_string())
        .spawn(move || {
            // The supervisor hands the start facts once it has minted the
            // token; a channel closed before then is a supervisor that went
            // away, and there is nothing left to serve.
            let Ok(start) = start.recv() else {
                return;
            };
            let shared = Arc::new(Shared {
                token: start.token,
                daemon_pid: start.daemon_pid,
                daemon_uid: daemon_uid(),
                presented: thread_presented,
                refusals: thread_refusals,
            });
            // One thread per connection: a presentation that stalls must
            // not hold up the next box's delivery behind it.
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let shared = Arc::clone(&shared);
                        let _conn = std::thread::Builder::new()
                            .name("minvmd-bep-stub-conn".to_string())
                            .spawn(move || serve_connection(stream, &shared));
                    }
                    Err(error) => {
                        tracing::debug!(error = %error, "box egress proxy stand-in accept failed")
                    }
                }
            }
        })?;
    Ok(BepStub {
        presented,
        refusals,
        _thread: thread,
    })
}

/// The facts every served connection is checked against, and the records
/// it is audited into.
struct Shared {
    /// The per-boot token a delivered connection must present first.
    token: [u8; TOKEN_LEN],
    /// The host daemon's pid: the only process the pool's deliveries come
    /// from, so on Linux any other pid is refused.
    daemon_pid: u32,
    /// The daemon's own uid: the peer's uid is checked against it before
    /// anything is read.
    daemon_uid: u32,
    /// The host's attachment table: what a delivered connection is
    /// attributed by (NET-133), looked up through and never written.
    /// The answer lines sent, one per accepted connection.
    presented: Arc<Mutex<Vec<String>>>,
    /// The refusal reasons audited, one per refused connection.
    refusals: Arc<Mutex<Vec<&'static str>>>,
}

/// Which credential proof a connection failed, or `None` when it passed:
/// the peer's uid first — only the same user may hold a connection to a
/// 0600 socket, so a mismatch names a socket that is not this daemon's —
/// then, where the kernel names the peer's process, that pid against the
/// host daemon's: a same-uid host process is refused before it presents a
/// byte, never on its bytes' merits.
fn credential_refusal(
    peer_uid: u32,
    peer_pid: Option<u32>,
    daemon_uid: u32,
    daemon_pid: u32,
) -> Option<&'static str> {
    if peer_uid != daemon_uid {
        return Some("uid");
    }
    if let Some(pid) = peer_pid
        && pid != daemon_pid
    {
        return Some("pid");
    }
    None
}

/// The daemon's own uid: the peer's uid is checked against it.
fn daemon_uid() -> u32 {
    // SAFETY: getuid() reads the calling user's real uid; it has no side
    // effects and cannot fail.
    unsafe { libc::getuid() }
}

/// Whether `presented` is this boot's token, decided in time independent
/// of where the two first differ: the token is a shared secret, and a
/// byte-at-a-time comparison would leak how many leading bytes a guess
/// got right through the moment the refusal closes the connection — a
/// channel a same-uid host process could read across guesses. Both
/// arrays are the fixed [`TOKEN_LEN`], so the fold runs over every byte
/// every time and only the accumulation of their differences decides.
fn token_matches(presented: &[u8; TOKEN_LEN], expected: &[u8; TOKEN_LEN]) -> bool {
    let mut diff = 0u8;
    for byte in 0..TOKEN_LEN {
        diff |= presented[byte] ^ expected[byte];
    }
    diff == 0
}

/// The peer's credentials, the kernel's own answer for who holds the other
/// end of `stream`: its uid, and its pid where the platform names one —
/// Linux does. `SO_PEERCRED` is decided at connect time, so nothing the
/// peer writes can influence what this reads.
#[cfg(target_os = "linux")]
fn peer_credentials(stream: &UnixStream) -> std::io::Result<(u32, Option<u32>)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `size_of::<ucred>()` bytes into
    // `cred`, whose length is passed alongside it; the fd is the stream's
    // own and stays valid for the borrow's life.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The pid the kernel reports is the peer's process's; zero is only the
    // placeholder this read was seeded with, and no process holds it.
    Ok((
        cred.uid,
        (cred.pid > 0).then(|| u32::try_from(cred.pid).unwrap_or(0)),
    ))
}

/// Off Linux the kernel offers one credential fact for a connected unix
/// socket: the peer's uid, read with `getpeereid`. It comes with no pid,
/// so the pid check is vacuous there — naming the peer's process is
/// `SO_PEERCRED`'s, a Linux extra — but the uid check is real: a 0600
/// socket in a 0700 dir bounds who may *connect*, and this bounds what
/// the stand-in believes about the one who did, the same user this
/// process runs as and no other.
#[cfg(not(target_os = "linux"))]
fn peer_credentials(stream: &UnixStream) -> std::io::Result<(u32, Option<u32>)> {
    let mut uid = libc::uid_t::default();
    let mut gid = libc::gid_t::default();
    // SAFETY: getpeereid writes the peer's uid and gid into the two
    // locals; the fd is the stream's own and stays valid for the
    // borrow's life.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((uid, None))
}

/// Serves one presented connection: checks the credentials, reads the
/// token, then the header, and answers one line that names the box and how
/// its flow entered. Anything the presentation fails is refused and
/// audited, and the connection is closed without an answer, so nothing
/// refused is ever presented as a box.
fn serve_connection(mut stream: UnixStream, shared: &Shared) {
    if let Err(error) = stream.set_read_timeout(Some(PRESENT_TIMEOUT)) {
        tracing::debug!(error = %error, "box egress proxy stand-in could not arm its read bound");
        return;
    }
    // The credentials are read at accept, before any byte of the
    // presentation: a foreign process is refused on what it is, not on what
    // it says.
    let (peer_uid, peer_pid) = match peer_credentials(&stream) {
        Ok(cred) => cred,
        Err(error) => {
            tracing::warn!(error = %error, "box egress proxy stand-in could not read peer credentials");
            audit(shared, "credentials");
            return;
        }
    };
    if let Some(reason) =
        credential_refusal(peer_uid, peer_pid, shared.daemon_uid, shared.daemon_pid)
    {
        audit(shared, reason);
        return;
    }
    // The token first: the proof the connection belongs to this boot.
    let mut token = [0u8; TOKEN_LEN];
    if stream.read_exact(&mut token).is_err() {
        audit(shared, "short");
        return;
    }
    if !token_matches(&token, &shared.token) {
        audit(shared, "token");
        return;
    }
    // Then the fixed header, and its version first of all.
    let mut head = [0u8; DELIVERY_HEADER_LEN];
    if stream.read_exact(&mut head).is_err() {
        audit(shared, "short");
        return;
    }
    let Some(delivery) = Delivery::parse(&head) else {
        audit(shared, "header");
        return;
    };
    // The mint cannot make a zero id, so a zero id is a header that was
    // never filled.
    if delivery.box_id == [0u8; 16] {
        audit(shared, "box_id");
        return;
    }
    let entry = match delivery.entry {
        Entry::Redirected { destination } => format!("redirected destination={destination}"),
        Entry::Dialled => "dialled".to_owned(),
    };
    let line = format!(
        "box_id={} entry={entry}\n",
        crate::bep_attach::BoxIdText(&delivery.box_id),
    );
    if stream.write_all(line.as_bytes()).is_err() {
        return;
    }
    tracing::debug!(
        entry = %delivery.entry,
        "credential proxy stand-in answered a delivered connection"
    );
    shared
        .presented
        .lock()
        .expect("the presented lock is never held across a panic, so it cannot be poisoned")
        .push(line);
}

/// Refuse one connection for `reason`: audit it and close it without an
/// answer, so the refusal carries no bytes a caller could mistake for a
/// box being presented.
fn audit(shared: &Shared, reason: &'static str) {
    tracing::warn!(
        reason,
        "box egress proxy stand-in refused a connection; nothing is presented from it"
    );
    shared
        .refusals
        .lock()
        .expect("the refusals lock is never held across a panic, so it cannot be poisoned")
        .push(reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: [u8; TOKEN_LEN] = [7u8; TOKEN_LEN];

    fn stub(dir: &tempfile::TempDir, daemon_pid: u32) -> (PathBuf, BepStub) {
        let sock = dir.path().join("bep.sock");
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = spawn(sock.clone(), start_rx).unwrap();
        start_tx
            .send(StubStart {
                token: TOKEN,
                daemon_pid,
            })
            .unwrap();
        (sock, stub)
    }

    fn delivery(box_id: [u8; 16]) -> Delivery {
        Delivery {
            box_id,
            entry: Entry::Redirected {
                destination: "140.82.112.3:443".parse().unwrap(),
            },
        }
    }

    /// Presents `token` and `head` and returns everything the stub answers.
    fn present(sock: &std::path::Path, token: &[u8], head: &[u8]) -> String {
        let mut stream = UnixStream::connect(sock).unwrap();
        stream.write_all(token).unwrap();
        stream.write_all(head).unwrap();
        // Nothing more follows, so a short presentation is seen at once.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        // A refusal closes with bytes unread, which can reset the
        // connection: either way nothing was answered.
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer
    }

    fn until_refusals(stub: &BepStub, count: usize) -> Vec<&'static str> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while stub.refusals().len() < count {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        stub.refusals()
    }

    #[test]
    fn a_delivery_with_the_token_is_presented_under_the_id_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, stub) = stub(&dir, std::process::id());
        let id = crate::bep_attach::mint_box_id();
        let answer = present(&sock, &TOKEN, &delivery(id).emit());
        assert_eq!(
            answer,
            format!(
                "box_id={} entry=redirected destination=140.82.112.3:443\n",
                crate::bep_attach::BoxIdText(&id)
            )
        );
        assert_eq!(stub.presented(), vec![answer]);
        assert!(stub.refusals().is_empty());
    }

    #[test]
    fn a_wrong_token_a_bad_header_and_a_zero_id_are_refused_without_an_answer() {
        let dir = tempfile::tempdir().unwrap();
        let (sock, stub) = stub(&dir, std::process::id());
        let id = crate::bep_attach::mint_box_id();

        assert_eq!(present(&sock, &[0u8; TOKEN_LEN], &delivery(id).emit()), "");
        let mut wrong_version = delivery(id).emit();
        wrong_version[0] = 9;
        assert_eq!(present(&sock, &TOKEN, &wrong_version), "");
        assert_eq!(present(&sock, &TOKEN, &delivery([0u8; 16]).emit()), "");
        assert_eq!(present(&sock, &TOKEN, &[1, 2, 3]), "");

        assert_eq!(
            until_refusals(&stub, 4),
            vec!["token", "header", "box_id", "short"]
        );
        assert!(stub.presented().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_connection_from_another_process_is_refused_before_it_presents() {
        let dir = tempfile::tempdir().unwrap();
        // The stub expects deliveries from a pid that is not this test's.
        let (sock, stub) = stub(&dir, std::process::id().wrapping_add(1));
        let id = crate::bep_attach::mint_box_id();
        assert_eq!(present(&sock, &TOKEN, &delivery(id).emit()), "");
        assert_eq!(until_refusals(&stub, 1), vec!["pid"]);
    }
}
