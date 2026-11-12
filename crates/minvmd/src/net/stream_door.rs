//! The stream door: single streams from boxes to two places on the host.
//!
//! This module protects the host. A VM has no route to the host's loopback
//! and none to the credential proxy. The guest daemon opens a stream here
//! instead, with a header that names the box and one of two purposes. Where
//! the stream lands is decided on the host: the credential proxy's own
//! socket, or the host's own loopback (`127.0.0.1`, then `::1`) at a port
//! the `[host-exposures]` table lists at that moment. The header carries no
//! host address, so the guest cannot choose another target.
//!
//! It does not decide which box may open which stream beyond what the box's
//! registration says (a credentialed grant). Whether a box's policy lets it
//! reach the host alias or a steered name is the guest's to enforce.
//!
//! The guest is not believed about which of its boxes a stream belongs to
//! either: the door cannot see inside the VM. What it checks is that the
//! box id is one this host registered for this VM, with a grant, and it
//! writes the proxy's delivery header itself. The proxy then decides each
//! request by the sealed value in it, which is bound to the box id.

#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use minimald_rpc::{
    ProxyEntry, STREAM_OPEN_MAX, StreamOpen, StreamPurpose, StreamRefusal, StreamReply,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tracing::Instrument as _;

use crate::box_id::{BoxId, BoxIdText};
use crate::box_registry::BoxRegistry;
use crate::control::BepListening;
use crate::net::host_exposures::{Holder, HostExposures};

/// Names the door's socket to the VMM child, which maps the guest's vsock
/// port to it.
pub(crate) const STREAM_DOOR_SOCK_ENV: &str = "MINVMD_GUEST_STREAM_SOCK";

/// How long a connection may take to send its header.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// The shortest wait between two looks at the exposure table for an open
/// stream.
const SHORTEST_EXPOSURE_CHECK: Duration = Duration::from_millis(10);

/// How often an open credential proxy stream looks whether its box is
/// still registered.
const BOX_CHECK: Duration = Duration::from_millis(100);

/// How long the connect on the host side may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the open direction of a half-closed stream may stay silent.
#[cfg(not(test))]
const HALF_CLOSED_IDLE: Duration = Duration::from_secs(60);
#[cfg(test)]
const HALF_CLOSED_IDLE: Duration = Duration::from_millis(400);

/// How often a silent direction checks whether the other one has ended.
const IDLE_TICK: Duration = Duration::from_millis(200);

/// The connections the door holds that it has neither let through nor
/// refused yet. A box is known only once the header is read, so this bound
/// is for the whole guest.
const MAX_UNDECIDED: usize = 512;

/// The credential proxy streams one box holds at once.
const MAX_PROXY_STREAMS_PER_BOX: usize = minimald_rpc::MAX_CREDENTIAL_PROXY_STREAMS;

/// The host port streams one box holds at once, as on a native node.
#[cfg(not(test))]
const MAX_HOST_PORT_STREAMS_PER_BOX: usize = minimald_rpc::MAX_HOST_PORT_STREAMS;
#[cfg(test)]
const MAX_HOST_PORT_STREAMS_PER_BOX: usize = 8;

/// What a stream is for, as the door counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Proxy,
    HostPort,
}

impl Kind {
    /// The streams of this kind one box holds at once.
    const fn most(self) -> usize {
        match self {
            Self::Proxy => MAX_PROXY_STREAMS_PER_BOX,
            Self::HostPort => MAX_HOST_PORT_STREAMS_PER_BOX,
        }
    }
}

/// How the door reaches the credential proxy.
#[derive(Clone)]
pub(crate) struct ProxyDelivery {
    /// The proxy's acceptor socket.
    pub(crate) sock: PathBuf,
    /// The token that proves a delivery comes from this supervisor.
    pub(crate) token: [u8; bep::listener::TOKEN_LEN],
    /// Whether the proxy listens.
    pub(crate) listening: BepListening,
}

impl std::fmt::Debug for ProxyDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a secret.
        f.debug_struct("ProxyDelivery")
            .field("sock", &self.sock)
            .finish_non_exhaustive()
    }
}

/// What the door decides by.
#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) boxes: BoxRegistry,
    /// The `[host-exposures]` table, read again when the file changes.
    pub(crate) exposures: HostExposures,
    /// Minimal's own listeners on the host's loopback at this moment. An
    /// exposure at one of their ports is not opened.
    pub(crate) own_listeners: Arc<dyn Fn() -> Vec<Holder> + Send + Sync>,
    /// `None` when this boot has no credential proxy.
    pub(crate) proxy: Option<ProxyDelivery>,
}

/// The running door. Dropping it does not stop the door: it serves until
/// the process ends, like the control doors.
#[derive(Debug)]
pub(crate) struct StreamDoor {
    sock: PathBuf,
}

impl StreamDoor {
    pub(crate) fn sock(&self) -> &Path {
        &self.sock
    }
}

struct Door {
    config: Config,
    undecided: AtomicUsize,
    /// The streams each box holds, by kind.
    held: std::sync::Mutex<std::collections::HashMap<(BoxId, Kind), usize>>,
}

/// One place among the undecided connections, given back on drop.
struct Undecided<'a>(&'a AtomicUsize);

impl Drop for Undecided<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One of a box's streams of one kind, given back on drop.
struct BoxSlot<'a> {
    door: &'a Door,
    of: (BoxId, Kind),
}

impl Drop for BoxSlot<'_> {
    fn drop(&mut self) {
        let mut held = self
            .door
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.of) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.of);
            }
        }
    }
}

/// Binds the door at `sock_path` and serves it on a thread of its own.
///
/// # Errors
///
/// The I/O error of preparing or binding the socket, or of starting the
/// thread.
pub(crate) fn spawn(sock_path: PathBuf, config: Config) -> io::Result<StreamDoor> {
    crate::sock::check_uds_path_len(&sock_path)?;
    crate::sock::prepare_socket_dir(&sock_path)?;
    crate::sock::remove_stale_socket(&sock_path)?;
    let listener = std::os::unix::net::UnixListener::bind(&sock_path)?;
    crate::sock::enforce_socket_permissions(&sock_path)?;
    listener.set_nonblocking(true)?;
    let door = Arc::new(Door {
        config,
        undecided: AtomicUsize::new(0),
        held: std::sync::Mutex::default(),
    });
    let span = crate::telemetry::vm_task("net.stream_door");
    std::thread::Builder::new()
        .name("minvmd-streams".into())
        .spawn(move || {
            let _span = span.clone().entered();
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::error!(%error, "the stream door has no runtime");
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match UnixListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::error!(%error, "the stream door could not listen");
                        return;
                    }
                };
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let door = Arc::clone(&door);
                            tokio::spawn(
                                async move { door.serve(stream).await }.instrument(span.clone()),
                            );
                        }
                        Err(error) => {
                            tracing::debug!(%error, "stream door accept failed");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        })?;
    tracing::info!(
        sock = %sock_path.display(),
        vsock_port = minimald_rpc::VM_HOST_STREAM_PORT,
        "bound the stream door"
    );
    Ok(StreamDoor { sock: sock_path })
}

/// Where a stream was let through to.
enum Target<'a> {
    Proxy(UnixStream, BoxSlot<'a>, Standing),
    Host(TcpStream, BoxSlot<'a>),
}

/// The registration a stream was admitted on.
enum Standing {
    /// The box's row, as it was then.
    Row(Arc<crate::box_registry::BoxRecord>),
    /// A box that shares the node's address and has no row.
    HostIp(BoxId),
}

impl Door {
    async fn serve(&self, stream: UnixStream) {
        // Only the VMM child and this user connect here, as on the control
        // door.
        let admitted = stream
            .peer_cred()
            .ok()
            .is_some_and(|cred| crate::control::check_guest_peer_uid(cred.uid()).is_ok());
        if !admitted {
            tracing::debug!("stream door peer check failed");
            return;
        }
        let mut guest = BufReader::with_capacity(STREAM_OPEN_MAX, stream);
        let undecided = match self.undecided.fetch_add(1, Ordering::AcqRel) {
            held if held >= MAX_UNDECIDED => {
                self.undecided.fetch_sub(1, Ordering::AcqRel);
                refuse(&mut guest, StreamRefusal::Busy).await;
                return;
            }
            _ => Undecided(&self.undecided),
        };
        let open = match tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut guest)).await {
            Ok(Some(open)) => open,
            Ok(None) | Err(_) => {
                refuse(&mut guest, StreamRefusal::Malformed).await;
                return;
            }
        };
        let id = open.box_id.to_bytes();
        let target = match self.admit(&open).await {
            Ok(admitted) => admitted,
            Err(reason) => {
                tracing::warn!(
                    box_id = %BoxIdText(&id),
                    purpose = ?open.purpose,
                    ?reason,
                    "refused a stream"
                );
                refuse(&mut guest, reason).await;
                return;
            }
        };
        // From here the stream counts against its box alone.
        drop(undecided);
        if write_reply(&mut guest, StreamReply::Open).await.is_err() {
            return;
        }
        tracing::debug!(box_id = %BoxIdText(&id), purpose = ?open.purpose, "opened a stream");
        let ended = match target {
            Target::Proxy(proxy, _slot, standing) => {
                tokio::select! {
                    ended = splice(guest, proxy) => ended,
                    // The guest is not relied on to close the streams of a
                    // box that is gone.
                    () = self.box_gone(&standing) => {
                        tracing::info!(
                            box_id = %BoxIdText(&id),
                            "ended a credential proxy stream of a box that is no longer registered"
                        );
                        Ok(())
                    }
                }
            }
            Target::Host(host, _slot) => {
                let StreamPurpose::HostPort { port } = open.purpose else {
                    return;
                };
                let service = std::os::fd::AsFd::as_fd(&host).try_clone_to_owned();
                tokio::select! {
                    ended = splice(guest, host) => ended,
                    // The user took the exposure away: the stream ends
                    // now, not when one of its ends is done with it.
                    () = self.no_longer_exposed(port) => {
                        if let Ok(service) = service {
                            reset_on_close(&service);
                        }
                        tracing::info!(
                            box_id = %BoxIdText(&id),
                            port,
                            "ended a stream to a host port that is no longer exposed"
                        );
                        Ok(())
                    }
                }
            }
        };
        if let Err(error) = ended {
            tracing::debug!(box_id = %BoxIdText(&id), %error, "a stream ended with an error");
        }
    }

    fn exposed(&self, port: u16) -> bool {
        self.config
            .exposures
            .current(&(self.config.own_listeners)())
            .iter()
            .any(|exposure| exposure.port == port)
    }

    /// Resolves when no exposure opens `port` any more. Never for a table
    /// that cannot change.
    async fn no_longer_exposed(&self, port: u16) {
        let Some(every) = self.config.exposures.changes_every() else {
            return std::future::pending().await;
        };
        loop {
            tokio::time::sleep(every.max(SHORTEST_EXPOSURE_CHECK)).await;
            if !self.exposed(port) {
                return;
            }
        }
    }

    /// Whether the box is still registered as it was when its stream was
    /// admitted: the same row, or still resident with its grant.
    fn stands(&self, standing: &Standing) -> bool {
        let boxes = &self.config.boxes;
        match standing {
            Standing::Row(row) => boxes.row_stands(row),
            Standing::HostIp(id) => boxes.resident_host_ip_box(*id) == Some(true),
        }
    }

    /// Resolves when the registration a stream was admitted on has ended.
    async fn box_gone(&self, standing: &Standing) {
        loop {
            tokio::time::sleep(BOX_CHECK).await;
            if !self.stands(standing) {
                return;
            }
        }
    }

    /// Decides one stream and connects its host side.
    async fn admit(&self, open: &StreamOpen) -> Result<Target<'_>, StreamRefusal> {
        let id = open.box_id.to_bytes();
        let boxes = &self.config.boxes;
        // A box is a row, or a resident host_ip box, which has no row.
        let (credentialed, standing) = match boxes.row_by_box_id(id) {
            Some(row) => {
                row.mark_used();
                (row.declares_credentialed_upstream(), Standing::Row(row))
            }
            None => (
                boxes
                    .resident_host_ip_box(id)
                    .ok_or(StreamRefusal::UnknownBox)?,
                Standing::HostIp(id),
            ),
        };
        match open.purpose {
            StreamPurpose::CredentialProxy { entry } => {
                if !credentialed {
                    return Err(StreamRefusal::NoCredentialedGrant);
                }
                let entry = match entry {
                    // No connection was ever headed for port 0.
                    ProxyEntry::Redirected { destination } if destination.port() == 0 => {
                        return Err(StreamRefusal::Malformed);
                    }
                    ProxyEntry::Redirected { destination } => {
                        bep::listener::Entry::Redirected { destination }
                    }
                    ProxyEntry::Dialled {} => bep::listener::Entry::Dialled,
                };
                let proxy = self
                    .config
                    .proxy
                    .as_ref()
                    .filter(|proxy| proxy.listening.is_listening())
                    .ok_or(StreamRefusal::ProxyDown)?;
                let slot = self.slot(id, Kind::Proxy).ok_or(StreamRefusal::Busy)?;
                let delivery = bep::listener::Delivery { box_id: id, entry };
                let stream = deliver(proxy, &delivery)
                    .await
                    .map_err(|_| StreamRefusal::ConnectFailed)?;
                Ok(Target::Proxy(stream, slot, standing))
            }
            StreamPurpose::HostPort { port } => {
                if !self.exposed(port) {
                    return Err(StreamRefusal::PortNotExposed);
                }
                let slot = self.slot(id, Kind::HostPort).ok_or(StreamRefusal::Busy)?;
                // Always the host's own loopback. The header names a port
                // and nothing else.
                match dial_loopback(port).await {
                    Ok(stream) => Ok(Target::Host(stream, slot)),
                    Err(_) => Err(StreamRefusal::ConnectFailed),
                }
            }
        }
    }

    /// A place for one more stream of `kind` of the box, when it holds
    /// fewer than the kind allows.
    fn slot(&self, id: BoxId, kind: Kind) -> Option<BoxSlot<'_>> {
        let of = (id, kind);
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = held.entry(of).or_insert(0);
        if *count >= kind.most() {
            return None;
        }
        *count += 1;
        Some(BoxSlot { door: self, of })
    }
}

/// Copies bytes both ways until both directions have ended or one fails.
///
/// Each side's end of file is passed on as a shutdown of the other side's
/// write half, so a half-closed connection keeps its open direction. Once
/// one direction has ended, the other may stay silent for
/// [`HALF_CLOSED_IDLE`] and is then ended too: a side that closed entirely
/// looks the same as one that only stopped sending, and a peer that never
/// answers must not hold the stream's place for good.
async fn splice<H>(guest: BufReader<UnixStream>, host: H) -> io::Result<()>
where
    H: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    // Bytes the guest sent behind its header are the stream's first bytes.
    let early = guest.buffer().to_vec();
    let mut guest = guest.into_inner();
    let (mut guest_read, mut guest_write) = guest.split();
    let (mut host_read, mut host_write) = tokio::io::split(host);
    let half_closed = std::sync::atomic::AtomicBool::new(false);
    let up = async {
        if let Err(error) = host_write.write_all(&early).await {
            half_closed.store(true, Ordering::Release);
            return Err(error);
        }
        copy_one_way(&mut guest_read, &mut host_write, &half_closed).await
    };
    let down = copy_one_way(&mut host_read, &mut guest_write, &half_closed);
    let (up, down) = tokio::join!(up, down);
    up.and(down)
}

/// Copies `from` to `to` until `from` ends, then shuts down `to`'s write
/// half.
async fn copy_one_way<R, W>(
    from: &mut R,
    to: &mut W,
    half_closed: &std::sync::atomic::AtomicBool,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let mut idle = Duration::ZERO;
    let result = loop {
        match tokio::time::timeout(IDLE_TICK, from.read(&mut buf)).await {
            Ok(Ok(0)) => break Ok(()),
            Ok(Ok(n)) => {
                idle = Duration::ZERO;
                if let Err(error) = to.write_all(&buf[..n]).await {
                    break Err(error);
                }
            }
            Ok(Err(error)) => break Err(error),
            Err(_tick) => {
                if half_closed.load(Ordering::Acquire) {
                    idle += IDLE_TICK;
                    if idle >= HALF_CLOSED_IDLE {
                        break Err(io::ErrorKind::TimedOut.into());
                    }
                }
            }
        }
    };
    half_closed.store(true, Ordering::Release);
    let _ = to.shutdown().await;
    result
}

/// Makes the socket send a reset when its last descriptor closes, so the
/// service does not read an orderly end.
fn reset_on_close(socket: &std::os::fd::OwnedFd) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: the descriptor is open, and the option value is a `linger`
    // of the length passed.
    let set = unsafe {
        libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            std::ptr::from_ref(&linger).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::linger>()).unwrap_or(0),
        )
    };
    if set != 0 {
        tracing::debug!(error = %io::Error::last_os_error(), "a stream's host side closes without a reset");
    }
}

/// Connects to `port` on the host's loopback: `127.0.0.1` first, then `::1`
/// when nothing listens on the port there, so a service bound to one family
/// alone is reachable.
async fn dial_loopback(port: u16) -> io::Result<TcpStream> {
    let dial = |address: std::net::IpAddr| async move {
        tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect((address, port)))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    };
    match dial(Ipv4Addr::LOCALHOST.into()).await {
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            dial(Ipv6Addr::LOCALHOST.into()).await
        }
        dialled => dialled,
    }
}

/// Connects to the credential proxy and presents the delivery: the boot
/// token, then the header that names the box and how its flow entered.
async fn deliver(
    proxy: &ProxyDelivery,
    delivery: &bep::listener::Delivery,
) -> io::Result<UnixStream> {
    let mut stream = tokio::time::timeout(DIAL_TIMEOUT, UnixStream::connect(&proxy.sock))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let mut presented = Vec::with_capacity(proxy.token.len() + bep::listener::DELIVERY_HEADER_LEN);
    presented.extend_from_slice(&proxy.token);
    presented.extend_from_slice(&delivery.emit());
    stream.write_all(&presented).await?;
    Ok(stream)
}

/// Reads the header line. `None` when it is too long, not a header, or the
/// connection ended first. Bytes after the line stay in the reader: they are
/// the stream's.
async fn read_header(guest: &mut BufReader<UnixStream>) -> Option<StreamOpen> {
    let mut line = Vec::with_capacity(128);
    let read = (&mut *guest)
        .take(STREAM_OPEN_MAX as u64)
        .read_until(b'\n', &mut line)
        .await
        .ok()?;
    if read == 0 || line.last() != Some(&b'\n') {
        return None;
    }
    serde_json::from_slice(&line).ok()
}

async fn write_reply(guest: &mut BufReader<UnixStream>, reply: StreamReply) -> io::Result<()> {
    let mut line = serde_json::to_vec(&reply).map_err(io::Error::other)?;
    line.push(b'\n');
    guest.get_mut().write_all(&line).await
}

/// Answers a refusal. The caller then closes the connection.
async fn refuse(guest: &mut BufReader<UnixStream>, reason: StreamRefusal) {
    let _ = write_reply(guest, StreamReply::Refused { reason }).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::box_registry::ClientBoxSpec;
    use crate::net::bep_stub;
    use crate::net::host_exposures::HostExposure;
    use std::io::{BufRead as _, Read as _, Write as _};

    const WAIT: Duration = Duration::from_secs(5);

    struct Bed {
        dir: tempfile::TempDir,
        boxes: BoxRegistry,
        door: StreamDoor,
        stub: bep_stub::BepStub,
        listening: Arc<std::sync::atomic::AtomicBool>,
    }

    const TOKEN: [u8; bep::listener::TOKEN_LEN] = [0x5a; bep::listener::TOKEN_LEN];

    fn bed(exposures: HostExposures) -> Bed {
        let dir = tempfile::tempdir().unwrap();
        let boxes = BoxRegistry::new(switch::DEFAULT_SUBNET);
        let proxy_sock = dir.path().join("bep.sock");
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let stub = bep_stub::spawn(proxy_sock.clone(), start_rx).unwrap();
        start_tx
            .send(bep_stub::StubStart {
                token: TOKEN,
                daemon_pid: std::process::id(),
            })
            .unwrap();
        let listening = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let cell = BepListening::new();
        cell.attach(Arc::clone(&listening));
        let door = spawn(
            dir.path().join(crate::net::GUEST_STREAM_SOCK_FILE),
            Config {
                boxes: boxes.clone(),
                exposures,
                own_listeners: Arc::new(Vec::new),
                proxy: Some(ProxyDelivery {
                    sock: proxy_sock,
                    token: TOKEN,
                    listening: cell,
                }),
            },
        )
        .unwrap();
        Bed {
            dir,
            boxes,
            door,
            stub,
            listening,
        }
    }

    fn spec(name: &str, credentialed: bool) -> ClientBoxSpec {
        ClientBoxSpec {
            name: name.to_string(),
            ingress_ports: Vec::new(),
            credentialed_upstream: credentialed.then(boxes::CredentialedUpstream::default),
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        }
    }

    /// A stand-in for the guest daemon's end of one stream.
    struct Guest {
        reader: std::io::BufReader<std::os::unix::net::UnixStream>,
    }

    impl Guest {
        fn connect(door: &StreamDoor) -> Self {
            let stream = std::os::unix::net::UnixStream::connect(door.sock()).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            Self {
                reader: std::io::BufReader::new(stream),
            }
        }

        fn open(door: &StreamDoor, open: &StreamOpen) -> (Self, StreamReply) {
            let mut guest = Self::connect(door);
            let mut line = serde_json::to_vec(open).unwrap();
            line.push(b'\n');
            guest.write(&line);
            let reply = guest.reply();
            (guest, reply)
        }

        fn write(&mut self, bytes: &[u8]) {
            self.reader.get_mut().write_all(bytes).unwrap();
        }

        fn reply(&mut self) -> StreamReply {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("reply {line:?}: {e}"))
        }

        fn read_to_end(&mut self) -> Vec<u8> {
            let mut rest = Vec::new();
            self.reader.read_to_end(&mut rest).unwrap();
            rest
        }
    }

    fn host_port(id: BoxId, port: u16) -> StreamOpen {
        StreamOpen {
            box_id: minimald_rpc::BoxId::from_bytes(id),
            purpose: StreamPurpose::HostPort { port },
        }
    }

    fn proxy_by(id: BoxId, entry: ProxyEntry) -> StreamOpen {
        StreamOpen {
            box_id: minimald_rpc::BoxId::from_bytes(id),
            purpose: StreamPurpose::CredentialProxy { entry },
        }
    }

    /// A stream for a connection the box made to an upstream.
    fn proxy(id: BoxId) -> StreamOpen {
        proxy_by(
            id,
            ProxyEntry::Redirected {
                destination: "140.82.112.3:443".parse().unwrap(),
            },
        )
    }

    fn refused(reason: StreamRefusal) -> StreamReply {
        StreamReply::Refused { reason }
    }

    /// A service on the host's loopback that answers each connection with
    /// what it read, reversed, and closes.
    fn loopback_service() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        reverse_on(listener, b"");
        port
    }

    /// Answers each connection on `listener` with its request reversed and
    /// `mark` behind it.
    fn reverse_on(listener: std::net::TcpListener, mark: &'static [u8]) {
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                std::thread::spawn(move || {
                    // Read to the client's end of file, which the door
                    // passes on as a shutdown.
                    let mut request = Vec::new();
                    stream.read_to_end(&mut request).unwrap();
                    request.reverse();
                    request.extend_from_slice(mark);
                    stream.write_all(&request).unwrap();
                });
            }
        });
    }

    /// When the user removes an exposure, the open streams to its port end
    /// and the service reads a reset. A stream to a port that stays exposed
    /// goes on.
    #[test]
    fn removing_an_exposure_ends_its_open_streams_and_no_other() {
        /// A service that tells how its one connection ended.
        fn service() -> (u16, std::sync::mpsc::Receiver<std::io::Result<usize>>) {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (ended, end) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(b"hello").unwrap();
                let _sent = ended.send(stream.read(&mut [0u8; 16]));
            });
            (port, end)
        }
        let (gone, gone_end) = service();
        let (kept, kept_end) = service();
        let config = tempfile::tempdir().unwrap();
        let path = config.path().join("config.toml");
        std::fs::write(
            &path,
            format!("[host-exposures]\na = {{ port = {gone} }}\nb = {{ port = {kept} }}\n"),
        )
        .unwrap();
        let bed = bed(HostExposures::at(path.clone(), Duration::from_millis(10)));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();
        let hello = |guest: &mut Guest| {
            let mut read = [0u8; 5];
            guest.reader.read_exact(&mut read).unwrap();
            assert_eq!(&read, b"hello");
        };
        let (mut to_gone, reply) = Guest::open(&bed.door, &host_port(web.box_id(), gone));
        assert_eq!(reply, StreamReply::Open);
        hello(&mut to_gone);
        let (mut to_kept, reply) = Guest::open(&bed.door, &host_port(web.box_id(), kept));
        assert_eq!(reply, StreamReply::Open);
        hello(&mut to_kept);

        std::fs::write(
            &path,
            format!("[host-exposures]\nb = {{ port = {kept} }}\n"),
        )
        .unwrap();
        let ended = gone_end.recv_timeout(WAIT).expect("the stream ends");
        assert_eq!(
            ended.map_err(|error| error.kind()),
            Err(std::io::ErrorKind::ConnectionReset),
            "the service must not read an orderly end"
        );
        assert!(
            to_gone.read_to_end().is_empty(),
            "the guest's side ends too"
        );
        assert!(
            kept_end.recv_timeout(Duration::from_millis(200)).is_err(),
            "a stream to a port that is still exposed goes on"
        );
        to_kept.reader.get_ref().write_all(b"x").unwrap();
        drop(to_kept);
        assert_eq!(kept_end.recv_timeout(WAIT).unwrap().unwrap(), 1);
    }

    #[test]
    fn a_host_port_stream_tries_the_ipv4_loopback_first_and_the_ipv6_one_when_refused() {
        use std::net::TcpListener;
        // A service on `::1` alone, and one port with a different service
        // in each family.
        let Ok(v6_only) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            eprintln!("skipped: this machine has no IPv6 loopback");
            return;
        };
        let v6_port = v6_only.local_addr().unwrap().port();
        assert!(
            std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, v6_port)).is_err(),
            "nothing listens on the port in IPv4"
        );
        reverse_on(v6_only, b"6");
        let (both_v4, both_v6) = std::iter::repeat_with(|| {
            let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
            let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, v4.local_addr().ok()?.port())).ok()?;
            Some((v4, v6))
        })
        .take(20)
        .flatten()
        .next()
        .expect("one port free in both families");
        let both_port = both_v4.local_addr().unwrap().port();
        reverse_on(both_v4, b"4");
        reverse_on(both_v6, b"6");

        let bed = bed(HostExposures::fixed(vec![
            HostExposure::tcp(v6_port),
            HostExposure::tcp(both_port),
        ]));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();
        let answer = |port| {
            let (mut guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), port));
            assert_eq!(reply, StreamReply::Open);
            guest.write(b"ab");
            guest
                .reader
                .get_ref()
                .shutdown(std::net::Shutdown::Write)
                .unwrap();
            guest.read_to_end()
        };
        assert_eq!(answer(v6_port), b"ba6");
        assert_eq!(answer(both_port), b"ba4");
    }

    #[test]
    fn a_host_port_stream_reaches_the_exposed_loopback_port_and_passes_half_close() {
        let port = loopback_service();
        let bed = bed(HostExposures::fixed(vec![HostExposure::tcp(port)]));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();

        let (mut guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), port));
        assert_eq!(reply, StreamReply::Open);
        // A megabyte each way, with the guest closing its write side first
        // and the host answering after that.
        let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        guest.write(&payload);
        guest
            .reader
            .get_ref()
            .shutdown(std::net::Shutdown::Write)
            .unwrap();
        let mut answer = guest.read_to_end();
        answer.reverse();
        assert_eq!(answer, payload);
        assert!(web.was_used());
    }

    #[test]
    fn a_port_outside_the_table_is_refused_and_never_dialled() {
        let exposed = loopback_service();
        let hidden = loopback_service();
        let bed = bed(HostExposures::fixed(vec![HostExposure::tcp(exposed)]));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();
        let (mut guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), hidden));
        assert_eq!(reply, refused(StreamRefusal::PortNotExposed));
        // After a refusal the door sends nothing more.
        drop(guest.reader.get_ref().shutdown(std::net::Shutdown::Write));
        assert!(guest.read_to_end().is_empty());
    }

    #[test]
    fn an_exposed_port_nothing_listens_on_is_a_failed_connect() {
        // Bound and dropped, so the port is free and nothing listens.
        let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let bed = bed(HostExposures::fixed(vec![HostExposure::tcp(port)]));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();
        let (_guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), port));
        assert_eq!(reply, refused(StreamRefusal::ConnectFailed));
    }

    #[test]
    fn the_table_is_read_at_each_stream_so_a_change_takes_effect_at_once() {
        let port = loopback_service();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();
        let bed = bed(HostExposures::at(config.clone(), Duration::ZERO));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();
        let open = host_port(web.box_id(), port);

        let (_guest, reply) = Guest::open(&bed.door, &open);
        assert_eq!(reply, refused(StreamRefusal::PortNotExposed));

        let write = |text: String| {
            // A new file each time, so the change is seen whatever the
            // file system's timestamp grain.
            let next = dir.path().join("config.next");
            std::fs::write(&next, text).unwrap();
            std::fs::rename(&next, &config).unwrap();
        };
        write(format!("[host-exposures]\ndb = {{ port = {port} }}\n"));
        let (_guest, reply) = Guest::open(&bed.door, &open);
        assert_eq!(reply, StreamReply::Open);

        write("[host-exposures]\n".to_string());
        let (_guest, reply) = Guest::open(&bed.door, &open);
        assert_eq!(reply, refused(StreamRefusal::PortNotExposed));
    }

    #[test]
    fn an_exposure_at_one_of_minimals_own_listeners_is_not_opened() {
        let port = loopback_service();
        let dir = tempfile::tempdir().unwrap();
        let boxes = BoxRegistry::new(switch::DEFAULT_SUBNET);
        let door = spawn(
            dir.path().join(crate::net::GUEST_STREAM_SOCK_FILE),
            Config {
                boxes: boxes.clone(),
                exposures: HostExposures::fixed(vec![HostExposure::tcp(port)]),
                own_listeners: Arc::new(move || {
                    crate::net::host_exposures::minimal_listeners(&[port])
                }),
                proxy: None,
            },
        )
        .unwrap();
        let web = boxes.register_client_box(spec("web", false)).unwrap();
        let (_guest, reply) = Guest::open(&door, &host_port(web.box_id(), port));
        assert_eq!(reply, refused(StreamRefusal::PortNotExposed));
    }

    #[test]
    fn a_credentialed_box_is_delivered_to_the_proxy_under_its_own_id() {
        let bed = bed(HostExposures::fixed(Vec::new()));
        let web = bed.boxes.register_client_box(spec("web", true)).unwrap();
        let (mut guest, reply) = Guest::open(&bed.door, &proxy(web.box_id()));
        assert_eq!(reply, StreamReply::Open);
        // The stand-in answers with what it was presented, then closes.
        let presented = String::from_utf8(guest.read_to_end()).unwrap();
        assert_eq!(
            presented,
            format!(
                "box_id={} entry=redirected destination=140.82.112.3:443\n",
                BoxIdText(&web.box_id())
            )
        );
        // A connection the box made to its endpoint, and one to an IPv6
        // address, arrive as what they are.
        let dialled = proxy_by(web.box_id(), ProxyEntry::Dialled {});
        let to_v6 = proxy_by(
            web.box_id(),
            ProxyEntry::Redirected {
                destination: "[2001:db8::7]:8443".parse().unwrap(),
            },
        );
        let mut lines = vec![presented];
        for (open, entry) in [
            (dialled, "entry=dialled"),
            (to_v6, "entry=redirected destination=[2001:db8::7]:8443"),
        ] {
            let (mut guest, reply) = Guest::open(&bed.door, &open);
            assert_eq!(reply, StreamReply::Open);
            let presented = String::from_utf8(guest.read_to_end()).unwrap();
            assert_eq!(
                presented,
                format!("box_id={} {entry}\n", BoxIdText(&web.box_id()))
            );
            lines.push(presented);
        }
        assert_eq!(bed.stub.presented(), lines);
        assert!(bed.stub.refusals().is_empty());
    }

    /// The header the proxy reads is the door's. Nothing of the guest's
    /// line but the box id and the entry is in it, and a destination no
    /// connection has is not passed on.
    #[test]
    fn the_guest_cannot_shape_the_header_beyond_its_box_and_entry() {
        let bed = bed(HostExposures::fixed(Vec::new()));
        let web = bed.boxes.register_client_box(spec("web", true)).unwrap();
        let id = minimald_rpc::BoxId::from_bytes(web.box_id());
        let to_port_zero = proxy_by(
            web.box_id(),
            ProxyEntry::Redirected {
                destination: "140.82.112.3:0".parse().unwrap(),
            },
        );
        let (_guest, reply) = Guest::open(&bed.door, &to_port_zero);
        assert_eq!(reply, refused(StreamRefusal::Malformed));
        let lines = [
            // The header of the wire before this one.
            format!(
                "{{\"box_id\":\"{id}\",\"purpose\":{{\"kind\":\"credential_proxy\",\"source_port\":51234,\"destination\":\"140.82.112.3:443\"}}}}\n"
            ),
            // A source of the guest's choosing.
            format!(
                "{{\"box_id\":\"{id}\",\"purpose\":{{\"kind\":\"credential_proxy\",\"entry\":{{\"via\":\"dialled\",\"source\":\"10.0.0.1:1\"}}}}}}\n"
            ),
            // A box id beside the one the door checks.
            format!(
                "{{\"box_id\":\"{id}\",\"purpose\":{{\"kind\":\"credential_proxy\",\"box_id\":\"{id}\",\"entry\":{{\"via\":\"dialled\"}}}}}}\n"
            ),
        ];
        for line in lines {
            let mut guest = Guest::connect(&bed.door);
            guest.write(line.as_bytes());
            assert_eq!(guest.reply(), refused(StreamRefusal::Malformed), "{line}");
        }
        assert!(bed.stub.presented().is_empty());
    }

    #[test]
    fn a_host_ip_box_is_delivered_under_its_own_id() {
        let bed = bed(HostExposures::fixed(Vec::new()));
        let id = bed.boxes.register_host_ip_box("shared").unwrap();
        let session = boxes::SessionId::from_bytes(id);
        // Registered, not yet admitted by a host client: unknown.
        let (_guest, reply) = Guest::open(&bed.door, &proxy(id));
        assert_eq!(reply, refused(StreamRefusal::UnknownBox));

        bed.boxes.admit_host_ip_box(session, false);
        let (_guest, reply) = Guest::open(&bed.door, &proxy(id));
        assert_eq!(reply, refused(StreamRefusal::NoCredentialedGrant));

        bed.boxes.admit_host_ip_box(session, true);
        let (mut guest, reply) = Guest::open(&bed.door, &proxy(id));
        assert_eq!(reply, StreamReply::Open);
        let presented = String::from_utf8(guest.read_to_end()).unwrap();
        assert!(
            presented.starts_with(&format!("box_id={} entry=redirected ", BoxIdText(&id))),
            "{presented}"
        );

        // Once the guest reports the box ended, its streams are refused.
        bed.boxes.end_host_ip_box(id);
        let (_guest, reply) = Guest::open(&bed.door, &proxy(id));
        assert_eq!(reply, refused(StreamRefusal::UnknownBox));
    }

    #[test]
    fn proxy_streams_need_a_grant_a_known_box_and_a_listening_proxy() {
        let bed = bed(HostExposures::fixed(Vec::new()));
        let plain = bed.boxes.register_client_box(spec("plain", false)).unwrap();
        let grant = bed.boxes.register_client_box(spec("grant", true)).unwrap();

        let (_guest, reply) = Guest::open(&bed.door, &proxy(plain.box_id()));
        assert_eq!(reply, refused(StreamRefusal::NoCredentialedGrant));
        let (_guest, reply) = Guest::open(&bed.door, &proxy([9u8; 16]));
        assert_eq!(reply, refused(StreamRefusal::UnknownBox));
        let (_guest, reply) = Guest::open(&bed.door, &host_port([9u8; 16], 80));
        assert_eq!(reply, refused(StreamRefusal::UnknownBox));

        bed.listening.store(false, Ordering::Release);
        let (_guest, reply) = Guest::open(&bed.door, &proxy(grant.box_id()));
        assert_eq!(reply, refused(StreamRefusal::ProxyDown));
        bed.listening.store(true, Ordering::Release);

        // A row the guest ended is gone for streams too.
        bed.boxes.withdraw(grant.switch_addr());
        let (_guest, reply) = Guest::open(&bed.door, &proxy(grant.box_id()));
        assert_eq!(reply, refused(StreamRefusal::UnknownBox));
        // Nothing refused reached the proxy.
        assert!(bed.stub.presented().is_empty());
        let _ = &bed.dir;
    }

    /// An acceptor at a proxy socket that takes connections and holds them
    /// open, with a door in front of it.
    fn holding_bed() -> (tempfile::TempDir, BoxRegistry, StreamDoor) {
        let dir = tempfile::tempdir().unwrap();
        let proxy_sock = dir.path().join("hold.sock");
        let acceptor = std::os::unix::net::UnixListener::bind(&proxy_sock).unwrap();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in acceptor.incoming() {
                held.push(stream);
            }
        });
        let boxes = BoxRegistry::new(switch::DEFAULT_SUBNET);
        let cell = BepListening::new();
        cell.attach(Arc::new(std::sync::atomic::AtomicBool::new(true)));
        let door = spawn(
            dir.path().join(crate::net::GUEST_STREAM_SOCK_FILE),
            Config {
                boxes: boxes.clone(),
                exposures: HostExposures::fixed(Vec::new()),
                own_listeners: Arc::new(Vec::new),
                proxy: Some(ProxyDelivery {
                    sock: proxy_sock,
                    token: TOKEN,
                    listening: cell,
                }),
            },
        )
        .unwrap();
        (dir, boxes, door)
    }

    /// Whether the door has closed the guest's end of a stream. A stream
    /// that is still open has nothing to read.
    fn closed(guest: &mut Guest, within: Duration) -> bool {
        guest
            .reader
            .get_ref()
            .set_read_timeout(Some(within))
            .unwrap();
        let mut byte = [0u8; 1];
        matches!(guest.reader.read(&mut byte), Ok(0))
    }

    /// The door does not wait for the guest to close the streams of a box
    /// that is gone: a guest that keeps one open holds a way to the proxy
    /// under an id the host no longer vouches for.
    #[test]
    fn a_proxy_stream_ends_when_its_box_is_no_longer_registered() {
        let (_dir, boxes, door) = holding_bed();
        let web = boxes.register_client_box(spec("web", true)).unwrap();
        let other = boxes.register_client_box(spec("other", true)).unwrap();
        let shared = boxes.register_host_ip_box("shared").unwrap();
        boxes.admit_host_ip_box(boxes::SessionId::from_bytes(shared), true);
        let open = |id| {
            let (guest, reply) = Guest::open(&door, &proxy(id));
            assert_eq!(reply, StreamReply::Open);
            guest
        };
        let (mut of_web, mut of_other, mut of_shared) =
            (open(web.box_id()), open(other.box_id()), open(shared));
        let short = Duration::from_millis(300);
        assert!(!closed(&mut of_web, short) && !closed(&mut of_shared, short));

        boxes.withdraw(web.switch_addr());
        assert!(
            closed(&mut of_web, WAIT),
            "the row is gone and its stream is still open"
        );
        boxes.end_host_ip_box(shared);
        assert!(
            closed(&mut of_shared, WAIT),
            "the box ended and its stream is still open"
        );
        // A box that is still registered keeps its stream.
        assert!(!closed(&mut of_other, short));

        // The same name registered again is another box: the old stream
        // does not come back, and a new one is admitted for the new id.
        let again = boxes.register_client_box(spec("web", true)).unwrap();
        assert_ne!(again.box_id(), web.box_id());
        let (_guest, reply) = Guest::open(&door, &proxy(web.box_id()));
        assert_eq!(reply, refused(StreamRefusal::UnknownBox));
        let mut of_again = open(again.box_id());
        assert!(!closed(&mut of_again, short));
    }

    #[test]
    fn a_box_holds_a_bounded_number_of_proxy_streams() {
        let (_dir, boxes, door) = holding_bed();
        let web = boxes.register_client_box(spec("web", true)).unwrap();
        let other = boxes.register_client_box(spec("other", true)).unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_PROXY_STREAMS_PER_BOX {
            let (guest, reply) = Guest::open(&door, &proxy(web.box_id()));
            assert_eq!(reply, StreamReply::Open);
            held.push(guest);
        }
        let (_guest, reply) = Guest::open(&door, &proxy(web.box_id()));
        assert_eq!(reply, refused(StreamRefusal::Busy));
        // Another box has its own share.
        let (_other, reply) = Guest::open(&door, &proxy(other.box_id()));
        assert_eq!(reply, StreamReply::Open);
        // A stream that ends gives its place back.
        held.pop();
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let (_guest, reply) = Guest::open(&door, &proxy(web.box_id()));
            if reply == StreamReply::Open {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the place never came back"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// One box at its bound leaves the other boxes their streams, and its
    /// streams of one kind do not count against the other kind.
    #[test]
    fn a_box_holds_a_bounded_number_of_host_port_streams() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });
        let bed = bed(HostExposures::fixed(vec![HostExposure::tcp(port)]));
        let web = bed.boxes.register_client_box(spec("web", true)).unwrap();
        let other = bed.boxes.register_client_box(spec("other", false)).unwrap();
        let mut held = Vec::new();
        for _ in 0..MAX_HOST_PORT_STREAMS_PER_BOX {
            let (guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), port));
            assert_eq!(reply, StreamReply::Open);
            held.push(guest);
        }
        let (_guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), port));
        assert_eq!(reply, refused(StreamRefusal::Busy));
        let (_other, reply) = Guest::open(&bed.door, &host_port(other.box_id(), port));
        assert_eq!(reply, StreamReply::Open);
        let (_proxied, reply) = Guest::open(&bed.door, &proxy(web.box_id()));
        assert_eq!(reply, StreamReply::Open);
        // A stream that ends gives its place back.
        held.pop();
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let (_guest, reply) = Guest::open(&bed.door, &host_port(web.box_id(), port));
            if reply == StreamReply::Open {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the place never came back"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_header_that_is_not_a_header_is_refused() {
        let bed = bed(HostExposures::fixed(vec![HostExposure::tcp(80)]));
        let web = bed.boxes.register_client_box(spec("web", false)).unwrap();
        let id = minimald_rpc::BoxId::from_bytes(web.box_id());
        let lines: Vec<Vec<u8>> = vec![
            b"GET / HTTP/1.1\r\n".to_vec(),
            b"{}\n".to_vec(),
            // A header may not name where on the host the stream lands.
            format!(
                "{{\"box_id\":\"{id}\",\"purpose\":{{\"kind\":\"host_port\",\"port\":80,\"address\":\"10.0.0.1\"}}}}\n"
            )
            .into_bytes(),
            format!(
                "{{\"box_id\":\"{id}\",\"host\":\"10.0.0.1\",\"purpose\":{{\"kind\":\"host_port\",\"port\":80}}}}\n"
            )
            .into_bytes(),
            // Longer than a header may be, with no newline in reach.
            vec![b'x'; STREAM_OPEN_MAX + 10],
        ];
        for line in lines {
            let mut guest = Guest::connect(&bed.door);
            guest.write(&line);
            assert_eq!(
                guest.reply(),
                refused(StreamRefusal::Malformed),
                "{:?}",
                String::from_utf8_lossy(&line)
            );
        }
    }

    #[test]
    fn a_connection_that_sends_no_header_is_refused_after_the_timeout() {
        let bed = bed(HostExposures::fixed(Vec::new()));
        let mut guest = Guest::connect(&bed.door);
        guest
            .reader
            .get_ref()
            .set_read_timeout(Some(HEADER_TIMEOUT + WAIT))
            .unwrap();
        let started = std::time::Instant::now();
        assert_eq!(guest.reply(), refused(StreamRefusal::Malformed));
        assert!(started.elapsed() + Duration::from_millis(200) >= HEADER_TIMEOUT);
    }
}
