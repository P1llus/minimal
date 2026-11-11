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

#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use minimald_rpc::{STREAM_OPEN_MAX, StreamOpen, StreamPurpose, StreamRefusal, StreamReply};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tracing::Instrument as _;

use crate::bep_attach::{BoxId, BoxIdText};
use crate::box_registry::BoxRegistry;
use crate::control::BepListening;
use crate::net::host_exposures::{Holder, HostExposures};

/// Names the door's socket to the VMM child, which maps the guest's vsock
/// port to it.
pub(crate) const STREAM_DOOR_SOCK_ENV: &str = "MINVMD_GUEST_STREAM_SOCK";

/// How long a connection may take to send its header.
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the connect on the host side may take.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the open direction of a half-closed stream may stay silent.
#[cfg(not(test))]
const HALF_CLOSED_IDLE: Duration = Duration::from_secs(60);
#[cfg(test)]
const HALF_CLOSED_IDLE: Duration = Duration::from_millis(400);

/// How often a silent direction checks whether the other one has ended.
const IDLE_TICK: Duration = Duration::from_millis(200);

/// The streams the door carries at once.
const MAX_STREAMS: usize = 512;

/// The credential proxy streams one box holds at once.
const MAX_PROXY_STREAMS_PER_BOX: usize = 16;

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
    streams: AtomicUsize,
    proxy_streams: std::sync::Mutex<std::collections::HashMap<BoxId, usize>>,
}

/// One slot of the door's stream count, given back on drop.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One of a box's credential proxy streams, given back on drop.
struct ProxySlot<'a> {
    door: &'a Door,
    id: BoxId,
}

impl Drop for ProxySlot<'_> {
    fn drop(&mut self) {
        let mut held = self
            .door
            .proxy_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.id) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.id);
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
        streams: AtomicUsize::new(0),
        proxy_streams: std::sync::Mutex::default(),
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
enum Target {
    Proxy(UnixStream),
    Host(TcpStream),
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
        let outcome = match self.streams.fetch_add(1, Ordering::AcqRel) {
            held if held >= MAX_STREAMS => {
                self.streams.fetch_sub(1, Ordering::AcqRel);
                refuse(&mut guest, StreamRefusal::Busy).await;
                return;
            }
            _ => Slot(&self.streams),
        };
        let _slot = outcome;
        let open = match tokio::time::timeout(HEADER_TIMEOUT, read_header(&mut guest)).await {
            Ok(Some(open)) => open,
            Ok(None) | Err(_) => {
                refuse(&mut guest, StreamRefusal::Malformed).await;
                return;
            }
        };
        let id = open.box_id.to_bytes();
        let (target, _proxy_slot) = match self.admit(&open).await {
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
        if write_reply(&mut guest, StreamReply::Open).await.is_err() {
            return;
        }
        tracing::debug!(box_id = %BoxIdText(&id), purpose = ?open.purpose, "opened a stream");
        let ended = match target {
            Target::Proxy(proxy) => splice(guest, proxy).await,
            Target::Host(host) => splice(guest, host).await,
        };
        if let Err(error) = ended {
            tracing::debug!(box_id = %BoxIdText(&id), %error, "a stream ended with an error");
        }
    }

    /// Decides one stream and connects its host side.
    async fn admit(
        &self,
        open: &StreamOpen,
    ) -> Result<(Target, Option<ProxySlot<'_>>), StreamRefusal> {
        let id = open.box_id.to_bytes();
        let boxes = &self.config.boxes;
        // A box is a row, or a resident host_ip box, which has no row and
        // shares the node's address.
        let (source, credentialed) = match boxes.row_by_box_id(id) {
            Some(row) => {
                row.mark_used();
                (row.switch_addr(), row.declares_credentialed_upstream())
            }
            None => match boxes.resident_host_ip_box(id) {
                Some(credentialed) => (boxes.subnet().daemon_ip(), credentialed),
                None => return Err(StreamRefusal::UnknownBox),
            },
        };
        match open.purpose {
            StreamPurpose::CredentialProxy {
                source_port,
                destination,
            } => {
                if !credentialed {
                    return Err(StreamRefusal::NoCredentialedGrant);
                }
                let proxy = self
                    .config
                    .proxy
                    .as_ref()
                    .filter(|proxy| proxy.listening.is_listening())
                    .ok_or(StreamRefusal::ProxyDown)?;
                let slot = self.proxy_slot(id).ok_or(StreamRefusal::Busy)?;
                let delivery = bep::listener::Delivery {
                    box_id: id,
                    source: SocketAddrV4::new(source, source_port),
                    destination,
                };
                let stream = deliver(proxy, &delivery)
                    .await
                    .map_err(|_| StreamRefusal::ConnectFailed)?;
                Ok((Target::Proxy(stream), Some(slot)))
            }
            StreamPurpose::HostPort { port } => {
                let open_now = self
                    .config
                    .exposures
                    .current(&(self.config.own_listeners)())
                    .iter()
                    .any(|exposure| exposure.port == port);
                if !open_now {
                    return Err(StreamRefusal::PortNotExposed);
                }
                // Always the host's own loopback. The header names a port
                // and nothing else.
                match dial_loopback(port).await {
                    Ok(stream) => Ok((Target::Host(stream), None)),
                    Err(_) => Err(StreamRefusal::ConnectFailed),
                }
            }
        }
    }

    fn proxy_slot(&self, id: BoxId) -> Option<ProxySlot<'_>> {
        let mut held = self
            .proxy_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = held.entry(id).or_insert(0);
        if *count >= MAX_PROXY_STREAMS_PER_BOX {
            return None;
        }
        *count += 1;
        Some(ProxySlot { door: self, id })
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
/// token, then the header that names the box and the two endpoints.
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

    fn proxy(id: BoxId) -> StreamOpen {
        StreamOpen {
            box_id: minimald_rpc::BoxId::from_bytes(id),
            purpose: StreamPurpose::CredentialProxy {
                source_port: 51234,
                destination: "140.82.112.3:443".parse().unwrap(),
            },
        }
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
                "box_id={} source={}:51234 destination=140.82.112.3:443\n",
                BoxIdText(&web.box_id()),
                web.switch_addr()
            )
        );
        assert_eq!(bed.stub.presented(), vec![presented]);
        assert!(bed.stub.refusals().is_empty());
    }

    #[test]
    fn a_host_ip_box_is_delivered_under_its_own_id_from_the_node_address() {
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
            presented.starts_with(&format!(
                "box_id={} source={}:51234 ",
                BoxIdText(&id),
                switch::DEFAULT_SUBNET.daemon_ip()
            )),
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

    #[test]
    fn a_box_holds_a_bounded_number_of_proxy_streams() {
        let dir = tempfile::tempdir().unwrap();
        // An acceptor that takes connections and holds them open.
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
