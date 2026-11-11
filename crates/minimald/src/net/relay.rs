//! Stream endpoints of a box.
//!
//! The engine redirects a box's connection to an address the box has no
//! route to, such as the host alias, into an endpoint the daemon serves for
//! that box. The relay accepts the connection, learns from the engine's
//! flow record which box sent it and where it was headed, and has a
//! [`Dial`] open the other end. The dialler decides at that moment whether
//! the stream may exist.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use boxes::BoxId;
use client_config::host_exposures::{HostExposures, HostExposuresFile};
use futures::future::BoxFuture;
use minimald_rpc::{StreamOpen, StreamPurpose, StreamRefusal};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use super::door::{self, Connect, StreamError, VmHost};
use super::endpoints::Service;
use super::engine::{Engine, Installed, Peers};
use crate::events::{NetRefusal, Source};

/// TCP's number in an IP header, as the exposure table names protocols.
const TCP: u8 = 6;

/// How long a host service may take to accept.
const CONNECT_LIMIT: Duration = Duration::from_secs(10);

/// How often the exposure table is read again while a stream that depends
/// on it is open.
const EXPOSURE_RECHECK: Duration = Duration::from_secs(1);

/// The wait after an accept that failed for want of a descriptor or memory.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// The far end of a relayed stream.
pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {
    /// Ends the stream at once, with a reset where the transport has one.
    fn reset(self: Box<Self>);
}

impl Stream for TcpStream {
    fn reset(self: Box<Self>) {
        let _ = self.set_zero_linger();
    }
}

impl Stream for tokio_vsock::VsockStream {
    // A vsock connection that closes with the peer still sending is reset.
    fn reset(self: Box<Self>) {}
}

/// An open stream.
pub(crate) struct Dialled {
    pub(crate) stream: Box<dyn Stream>,
    /// Resolves when the stream may no longer exist. `None` when whoever
    /// holds the far end ends it for that reason by itself.
    pub(crate) revoked: Option<BoxFuture<'static, ()>>,
}

/// Why no stream was opened.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The host exposures table does not open the port.
    NotExposed,
    /// Nothing accepted the connection.
    Unreachable(io::Error),
    /// The VM host decided against the stream.
    Door(StreamRefusal),
}

impl Refused {
    /// The refusal as an event names it, when a rule of the user's is
    /// behind it. A service that is not running is no rule.
    fn reason(&self) -> Option<&'static str> {
        match self {
            Self::NotExposed | Self::Door(StreamRefusal::PortNotExposed) => {
                Some("host_port_not_exposed")
            }
            Self::Door(StreamRefusal::NoCredentialedGrant) => Some("no_credentialed_grant"),
            Self::Unreachable(_) | Self::Door(_) => None,
        }
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotExposed => f.write_str("the host exposures table does not open the port"),
            Self::Unreachable(error) => write!(f, "nothing accepted the connection: {error}"),
            Self::Door(reason) => write!(f, "the VM host refused the stream: {reason:?}"),
        }
    }
}

/// Where a relayed stream goes, decided at the moment it is dialled.
pub(crate) trait Dial: Send + Sync {
    /// Opens the far end of a connection that box `from` made to
    /// `original` from its port `peer_port`.
    fn dial(
        &self,
        from: BoxId,
        original: SocketAddr,
        peer_port: u16,
    ) -> BoxFuture<'_, Result<Dialled, Refused>>;
}

/// The ports of the host's loopback that this daemon's own listeners hold:
/// its hostname proxy and the box-name answerer. An exposure never opens
/// one, whatever the table says: a box would get the daemon's own surface,
/// as a program of the host.
#[derive(Debug)]
pub(crate) struct OwnListeners(std::sync::Mutex<std::collections::BTreeSet<u16>>);

impl OwnListeners {
    /// The listeners of this daemon. The answerer's default port is held
    /// from the start, because the answerer may be another process's.
    pub(crate) fn daemon() -> &'static Self {
        static DAEMON: std::sync::LazyLock<OwnListeners> = std::sync::LazyLock::new(|| {
            OwnListeners(std::sync::Mutex::new(
                [crate::net::answerer::ANSWERER_PORT].into(),
            ))
        });
        &DAEMON
    }

    /// Records that a listener of the daemon holds `port` from now on.
    pub(crate) fn hold(&self, port: u16) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(port);
    }

    fn holds(&self, port: u16) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&port)
    }
}

/// The host's loopback on a native node: a connection to the host alias at
/// a port goes to the same port of the host, when the user's host exposures
/// table opens it.
pub(crate) struct NativeHostPorts {
    exposures: Arc<HostExposuresFile>,
    /// The table as last read, for the streams that are open.
    table: watch::Sender<Arc<HostExposures>>,
}

impl NativeHostPorts {
    /// Must be called on the runtime: a task reads the table again while
    /// streams are open.
    pub(crate) fn new(exposures: Arc<HostExposuresFile>) -> Arc<Self> {
        Self::rechecking(exposures, EXPOSURE_RECHECK)
    }

    fn rechecking(exposures: Arc<HostExposuresFile>, every: Duration) -> Arc<Self> {
        let (table, _) = watch::channel(exposures.current());
        let ports = Arc::new(Self { exposures, table });
        crate::traced::spawn_detached(
            tracing::info_span!(parent: None, "relay.host_exposures"),
            Self::recheck(Arc::downgrade(&ports), every),
        );
        ports
    }

    /// Reads the table and tells the open streams when it changed.
    fn refresh(&self) -> Arc<HostExposures> {
        let now = self.exposures.current();
        self.table.send_if_modified(|known| {
            let changed = !Arc::ptr_eq(known, &now);
            if changed {
                *known = Arc::clone(&now);
            }
            changed
        });
        now
    }

    async fn recheck(ports: Weak<Self>, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let Some(ports) = ports.upgrade() else {
                return;
            };
            // The file is read only for streams that could lose their entry.
            if ports.table.receiver_count() > 0 {
                ports.refresh();
            }
        }
    }
}

/// Connects to a port of this machine's loopback: IPv4 first, and IPv6 when
/// nothing listens there on IPv4.
async fn dial_loopback(port: u16) -> io::Result<TcpStream> {
    let connect = async {
        match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                TcpStream::connect((Ipv6Addr::LOCALHOST, port)).await
            }
            other => other,
        }
    };
    tokio::time::timeout(CONNECT_LIMIT, connect)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

impl Dial for NativeHostPorts {
    fn dial(
        &self,
        _from: BoxId,
        original: SocketAddr,
        _peer_port: u16,
    ) -> BoxFuture<'_, Result<Dialled, Refused>> {
        Box::pin(async move {
            let port = original.port();
            // Subscribed before the read, so no change after it is missed.
            let mut table = self.table.subscribe();
            if !self.refresh().opens(TCP, port) || OwnListeners::daemon().holds(port) {
                return Err(Refused::NotExposed);
            }
            let stream = dial_loopback(port).await.map_err(Refused::Unreachable)?;
            let revoked = async move {
                loop {
                    if !table.borrow_and_update().opens(TCP, port) {
                        return;
                    }
                    // With nobody left to read the table, nobody can say
                    // the entry is still there.
                    if table.changed().await.is_err() {
                        return;
                    }
                }
            };
            Ok(Dialled {
                stream: Box::new(stream),
                revoked: Some(Box::pin(revoked)),
            })
        })
    }
}

/// The host's loopback from inside a VM: the VM host opens the port when
/// its own copy of the exposures table says so, and ends the stream when
/// the entry goes.
pub(crate) struct DoorHostPorts<C = VmHost> {
    host: Arc<C>,
}

impl<C: Connect> DoorHostPorts<C> {
    pub(crate) const fn new(host: Arc<C>) -> Self {
        Self { host }
    }
}

impl<C: Connect> Dial for DoorHostPorts<C>
where
    C::Stream: Stream,
{
    fn dial(
        &self,
        from: BoxId,
        original: SocketAddr,
        _peer_port: u16,
    ) -> BoxFuture<'_, Result<Dialled, Refused>> {
        Box::pin(async move {
            let open = StreamOpen {
                box_id: from,
                purpose: StreamPurpose::HostPort {
                    port: original.port(),
                },
            };
            match door::open_stream(&*self.host, open).await {
                Ok(stream) => Ok(Dialled {
                    stream: Box::new(stream),
                    revoked: None,
                }),
                Err(StreamError::Refused(reason)) => Err(Refused::Door(reason)),
                Err(StreamError::Unreachable(error)) => Err(Refused::Unreachable(error)),
            }
        })
    }
}

/// Serves one stream endpoint of a box until the listener fails or the
/// task is aborted.
pub(crate) async fn serve(
    listener: TcpListener,
    engine: &'static Engine,
    of: Arc<Installed>,
    peers: Peers,
    service: Service,
    dial: Arc<dyn Dial>,
) {
    let from = of.session();
    let attributed = Arc::clone(&of);
    let attribute = move |peer: SocketAddr| {
        peers
            .of_box(&attributed, service, peer, netpol::Protocol::Tcp)
            .map(|flow| flow.destination)
    };
    let report = move |original: SocketAddr, reason: &'static str| {
        engine.observe(
            Arc::clone(&of),
            NetRefusal {
                source: Source::HostRelay,
                direction: netpol::Direction::Egress,
                protocol: Some(netpol::Protocol::Tcp),
                remote: Some(original.ip()),
                port: Some(original.port()),
                name: None,
                reason: reason.to_owned(),
                rule: None,
                pid: None,
            },
        );
    };
    relay(listener, from, attribute, dial, Arc::new(report)).await;
}

type Report = dyn Fn(SocketAddr, &'static str) + Send + Sync;

/// Accepts connections and carries each one the engine names as the box's.
/// `attribute` gives where a peer's connection was headed, or `None` for a
/// peer that is no socket of the box.
async fn relay(
    listener: TcpListener,
    from: BoxId,
    attribute: impl Fn(SocketAddr) -> Option<SocketAddr>,
    dial: Arc<dyn Dial>,
    report: Arc<Report>,
) {
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => continue,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
                ) =>
            {
                tokio::time::sleep(ACCEPT_RETRY).await;
                continue;
            }
            Err(error) => {
                tracing::warn!(box_id = %from, %error, "a box's stream endpoint stopped");
                return;
            }
        };
        // A process outside the box gets nothing from the box's endpoint.
        let Some(original) = attribute(peer) else {
            continue;
        };
        crate::traced::spawn(carry(
            client,
            peer,
            from,
            original,
            Arc::clone(&dial),
            Arc::clone(&report),
        ));
    }
}

fn reset(client: TcpStream) {
    let _ = client.set_zero_linger();
}

/// Carries one connection of the box until either end closes it or the
/// dialler takes its permission back.
async fn carry(
    mut client: TcpStream,
    peer: SocketAddr,
    from: BoxId,
    original: SocketAddr,
    dial: Arc<dyn Dial>,
    report: Arc<Report>,
) {
    let Dialled {
        mut stream,
        revoked,
    } = match dial.dial(from, original, peer.port()).await {
        Ok(dialled) => dialled,
        Err(refused) => {
            tracing::debug!(box_id = %from, %original, %refused, "a relayed connection was refused");
            if let Some(reason) = refused.reason() {
                report(original, reason);
            }
            // The box sees what a closed port answers.
            reset(client);
            return;
        }
    };
    let revoked = async {
        match revoked {
            Some(revoked) => revoked.await,
            None => std::future::pending().await,
        }
    };
    let ended = tokio::select! {
        copied = tokio::io::copy_bidirectional(&mut client, &mut stream) => copied.map(drop),
        () = revoked => Err(io::Error::other("the stream's permission ended")),
    };
    if let Err(error) = ended {
        tracing::debug!(box_id = %from, %original, %error, "a relayed connection was cut");
        // A stream that broke on one side breaks on the other. An orderly
        // close would tell the box that all the data arrived.
        stream.reset();
        reset(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::door::testing::{FakeHost, box_id};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    impl Stream for tokio::io::DuplexStream {
        fn reset(self: Box<Self>) {}
    }

    type Reports = Arc<Mutex<Vec<(SocketAddr, &'static str)>>>;

    /// A relay on a loopback listener that takes every peer for the box's,
    /// headed for `original`, unless `outsider` is set.
    struct Bench {
        at: SocketAddr,
        reports: Reports,
        outsider: Arc<std::sync::atomic::AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn bench(dial: Arc<dyn Dial>, original: SocketAddr) -> Bench {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let reports = Reports::default();
        let outsider = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, is_outsider) = (Arc::clone(&reports), Arc::clone(&outsider));
        let task = crate::traced::spawn(relay(
            listener,
            box_id(1),
            move |_| (!is_outsider.load(std::sync::atomic::Ordering::SeqCst)).then_some(original),
            dial,
            Arc::new(move |original, reason| seen.lock().unwrap().push((original, reason))),
        ));
        Bench {
            at,
            reports,
            outsider,
            task,
        }
    }

    /// How a connection ended for the box: what it read, and whether the
    /// end was a reset.
    async fn read_to_end(mut client: TcpStream) -> (Vec<u8>, bool) {
        let mut read = Vec::new();
        let reset =
            match tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut read))
                .await
                .expect("the connection ends")
            {
                Ok(_) => false,
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error}");
                    true
                }
            };
        (read, reset)
    }

    fn exposures(dir: &std::path::Path, body: &str) -> Arc<HostExposuresFile> {
        let path = dir.join("config.toml");
        std::fs::write(&path, body).unwrap();
        Arc::new(HostExposuresFile::new(path))
    }

    /// A service on the loopback that answers each connection with `hello`
    /// and then echoes.
    async fn service(v6: bool) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = if v6 {
            TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap()
        } else {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()
        };
        let port = listener.local_addr().unwrap().port();
        let task = crate::traced::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                crate::traced::spawn(async move {
                    stream.write_all(b"hello").await.unwrap();
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        (port, task)
    }

    fn alias(port: u16) -> SocketAddr {
        SocketAddr::from(([100, 64, 255, 254], port))
    }

    #[tokio::test]
    async fn an_exposed_host_port_is_reached_through_the_relay() {
        let (port, _service) = service(false).await;
        let dir = tempfile::tempdir().unwrap();
        let table = exposures(
            dir.path(),
            &format!("[host-exposures]\ndb = {{ port = {port} }}\n"),
        );
        let bench = bench(NativeHostPorts::new(table), alias(port)).await;
        let mut client = TcpStream::connect(bench.at).await.unwrap();
        client.write_all(b" there").await.unwrap();
        client.shutdown().await.unwrap();
        let (read, reset) = read_to_end(client).await;
        assert_eq!(read, b"hello there");
        assert!(!reset);
        assert!(bench.reports.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_port_the_table_does_not_open_is_reset_and_reported() {
        let (port, _service) = service(false).await;
        let dir = tempfile::tempdir().unwrap();
        // The table opens the port for UDP, which is another port.
        let table = exposures(
            dir.path(),
            &format!("[host-exposures]\ndb = {{ port = {port}, proto = \"udp\" }}\n"),
        );
        let bench = bench(NativeHostPorts::new(table), alias(port)).await;
        let client = TcpStream::connect(bench.at).await.unwrap();
        let (read, reset) = read_to_end(client).await;
        assert!(read.is_empty());
        assert!(reset, "the box must not read an orderly close");
        assert_eq!(
            *bench.reports.lock().unwrap(),
            [(alias(port), "host_port_not_exposed")]
        );
    }

    #[tokio::test]
    async fn an_exposure_at_a_listener_of_the_daemon_opens_nothing() {
        let (port, _service) = service(false).await;
        OwnListeners::daemon().hold(port);
        let dir = tempfile::tempdir().unwrap();
        let table = exposures(
            dir.path(),
            &format!("[host-exposures]\nproxy = {{ port = {port} }}\n"),
        );
        let bench = bench(NativeHostPorts::new(table), alias(port)).await;
        let client = TcpStream::connect(bench.at).await.unwrap();
        let (read, reset) = read_to_end(client).await;
        assert!(read.is_empty() && reset);
        assert_eq!(
            *bench.reports.lock().unwrap(),
            [(alias(port), "host_port_not_exposed")]
        );
    }

    #[tokio::test]
    async fn an_exposed_port_nothing_listens_on_is_reset_and_is_no_refusal_of_a_rule() {
        let unused = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let dir = tempfile::tempdir().unwrap();
        let table = exposures(
            dir.path(),
            &format!("[host-exposures]\ndb = {{ port = {unused} }}\n"),
        );
        let bench = bench(NativeHostPorts::new(table), alias(unused)).await;
        let client = TcpStream::connect(bench.at).await.unwrap();
        let (_, reset) = read_to_end(client).await;
        assert!(reset);
        assert!(bench.reports.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_service_on_the_ipv6_loopback_alone_is_reached() {
        if TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.is_err() {
            eprintln!("skipped: this machine has no IPv6 loopback");
            return;
        }
        let (port, _service) = service(true).await;
        let dir = tempfile::tempdir().unwrap();
        let table = exposures(
            dir.path(),
            &format!("[host-exposures]\ndb = {{ port = {port} }}\n"),
        );
        let bench = bench(NativeHostPorts::new(table), alias(port)).await;
        let mut client = TcpStream::connect(bench.at).await.unwrap();
        client.shutdown().await.unwrap();
        let (read, _) = read_to_end(client).await;
        assert_eq!(read, b"hello");
    }

    #[tokio::test]
    async fn removing_an_exposure_resets_its_open_streams_and_no_other() {
        let (gone, _first) = service(false).await;
        let (kept, _second) = service(false).await;
        let dir = tempfile::tempdir().unwrap();
        let both = format!("[host-exposures]\na = {{ port = {gone} }}\nb = {{ port = {kept} }}\n");
        let table = exposures(dir.path(), &both);
        let ports = NativeHostPorts::rechecking(table, Duration::from_millis(20));
        let to_gone = bench(Arc::clone(&ports) as Arc<dyn Dial>, alias(gone)).await;
        let to_kept = bench(ports, alias(kept)).await;

        let mut cut = TcpStream::connect(to_gone.at).await.unwrap();
        let mut stays = TcpStream::connect(to_kept.at).await.unwrap();
        let mut hello = [0u8; 5];
        cut.read_exact(&mut hello).await.unwrap();
        stays.read_exact(&mut hello).await.unwrap();

        std::fs::write(
            dir.path().join("config.toml"),
            format!("[host-exposures]\nb = {{ port = {kept} }}\n"),
        )
        .unwrap();
        let (_, reset) = read_to_end(cut).await;
        assert!(reset);
        // The other stream still carries data both ways.
        stays.write_all(b"still").await.unwrap();
        stays.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"still");
        // And the removed port takes no new stream.
        let again = TcpStream::connect(to_gone.at).await.unwrap();
        assert!(read_to_end(again).await.1);
    }

    #[tokio::test]
    async fn a_peer_that_is_not_the_box_gets_nothing() {
        struct Never;
        impl Dial for Never {
            fn dial(
                &self,
                _: BoxId,
                _: SocketAddr,
                _: u16,
            ) -> BoxFuture<'_, Result<Dialled, Refused>> {
                panic!("an outsider's connection was dialled");
            }
        }
        let bench = bench(Arc::new(Never), alias(80)).await;
        bench
            .outsider
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let client = TcpStream::connect(bench.at).await.unwrap();
        let (read, _) = read_to_end(client).await;
        assert!(read.is_empty());
    }

    #[tokio::test]
    async fn in_a_vm_the_stream_door_carries_the_connection() {
        let host = FakeHost::new(|port, mut stream| async move {
            assert_eq!(port, minimald_rpc::VM_HOST_STREAM_PORT);
            let mut line = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                if byte == b'\n' {
                    break;
                }
                line.push(byte);
            }
            let open: StreamOpen = serde_json_lenient::from_slice(&line).unwrap();
            assert_eq!(open.box_id, box_id(1));
            let StreamPurpose::HostPort { port } = open.purpose else {
                panic!("{open:?}")
            };
            if port != 5432 {
                stream
                    .write_all(b"{\"stream\":\"refused\",\"reason\":\"port_not_exposed\"}\n")
                    .await
                    .unwrap();
                return;
            }
            stream.write_all(b"{\"stream\":\"open\"}\n").await.unwrap();
            let mut said = Vec::new();
            stream.read_to_end(&mut said).await.unwrap();
            said.reverse();
            stream.write_all(&said).await.unwrap();
        });
        let dial: Arc<dyn Dial> = Arc::new(DoorHostPorts::new(Arc::clone(&host)));

        let open = bench(Arc::clone(&dial), alias(5432)).await;
        let mut client = TcpStream::connect(open.at).await.unwrap();
        client.write_all(b"abc").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_to_end(client).await, (b"cba".to_vec(), false));

        let closed = bench(dial, alias(22)).await;
        let client = TcpStream::connect(closed.at).await.unwrap();
        assert!(read_to_end(client).await.1);
        assert_eq!(
            *closed.reports.lock().unwrap(),
            [(alias(22), "host_port_not_exposed")]
        );
    }

    /// A far end that says `ok` and then fails.
    struct Breaks {
        said: bool,
    }

    impl AsyncRead for Breaks {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.said {
                return std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            self.said = true;
            buffer.put_slice(b"ok");
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Breaks {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl Stream for Breaks {
        fn reset(self: Box<Self>) {}
    }

    impl Dial for Breaks {
        fn dial(&self, _: BoxId, _: SocketAddr, _: u16) -> BoxFuture<'_, Result<Dialled, Refused>> {
            Box::pin(async {
                Ok(Dialled {
                    stream: Box::new(Self { said: false }),
                    revoked: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn a_far_end_that_breaks_resets_the_box() {
        let bench = bench(Arc::new(Breaks { said: false }), alias(80)).await;
        let client = TcpStream::connect(bench.at).await.unwrap();
        // What was in flight may be lost, as with any reset.
        let (_, reset) = read_to_end(client).await;
        assert!(reset);
    }
}
