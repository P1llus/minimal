//! The guest daemon's two connections to the VM host daemon.
//!
//! The guest door takes one request line and answers with one reply line.
//! The stream door takes one header line, answers with one line, and from
//! then on the connection carries a stream's bytes. Each request is a
//! connection of its own, so dropping a request's future closes its
//! connection, and the VM host reads that as the request withdrawn.

use std::io;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use boxes::BoxId;
use futures::future::BoxFuture;
use minimald_rpc::{
    BoxRunEffect, BoxRunReport, BoxStandingRequest, ForwardState, GuestDoorReply, GuestDoorRequest,
    ListenNotice, MintBoxIdRequest, PublishOrigin, PublishPortRequest, PublishRefusal, StreamOpen,
    StreamRefusal, StreamReply, UnpublishPortRequest, VM_HOST_GUEST_DOOR_PORT, VM_HOST_STREAM_PORT,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// How long the VM host may take to answer a request that waits for no
/// person.
const ANSWER_LIMIT: Duration = Duration::from_secs(10);

/// The longest reply line of the guest door. The longest real one is a
/// refusal with its fields, well below this.
const REPLY_MAX: usize = 4096;

/// The longest reply line of the stream door.
const STREAM_REPLY_MAX: usize = 256;

/// A way to open a connection to a port of the VM host daemon.
pub(crate) trait Connect: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn connect(&self, port: u32) -> BoxFuture<'_, io::Result<Self::Stream>>;
}

/// The VM host daemon, over vsock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct VmHost {
    cid: u32,
}

impl VmHost {
    /// The host of the VM this daemon runs in.
    pub(crate) const fn of_this_guest() -> Self {
        Self {
            cid: tokio_vsock::VMADDR_CID_HOST,
        }
    }
}

impl Connect for VmHost {
    type Stream = tokio_vsock::VsockStream;

    fn connect(&self, port: u32) -> BoxFuture<'_, io::Result<Self::Stream>> {
        Box::pin(tokio_vsock::VsockStream::connect(
            tokio_vsock::VsockAddr::new(self.cid, port),
        ))
    }
}

/// Why a request on the guest door got no result.
#[derive(Debug)]
pub enum DoorError {
    /// The VM host was not reached, or its answer was not one the door
    /// gives to this request.
    Unreachable(io::Error),
    /// The VM host could not serve the request, in its own words.
    Failed(String),
    /// The VM host decided against the publish or the unpublish.
    Refused(PublishRefusal),
}

impl std::fmt::Display for DoorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(error) => write!(f, "the VM host did not answer: {error}"),
            Self::Failed(error) => write!(f, "the VM host could not serve the request: {error}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for DoorError {}

impl From<io::Error> for DoorError {
    fn from(error: io::Error) -> Self {
        Self::Unreachable(error)
    }
}

/// A forward the VM host made for a box's port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forwarded {
    /// Where the host listens.
    pub listener: SocketAddrV4,
    /// Whether the listener is bound, or waits for another box to end.
    pub state: ForwardState,
}

/// The guest door of the VM host daemon.
#[derive(Debug)]
pub(crate) struct GuestDoor<C = VmHost> {
    host: Arc<C>,
}

impl<C> Clone for GuestDoor<C> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}

fn unexpected(reply: &GuestDoorReply) -> DoorError {
    DoorError::Unreachable(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the VM host answered with {reply:?}"),
    ))
}

impl<C: Connect> GuestDoor<C> {
    pub(crate) fn new(host: Arc<C>) -> Self {
        Self { host }
    }

    /// One request, one reply, on a connection of its own. `limit` bounds
    /// the whole exchange.
    async fn ask(
        &self,
        request: &GuestDoorRequest,
        limit: Option<Duration>,
    ) -> Result<GuestDoorReply, DoorError> {
        let exchange = async {
            let mut stream = self.host.connect(VM_HOST_GUEST_DOOR_PORT).await?;
            let mut line = serde_json_lenient::to_vec(request).map_err(io::Error::other)?;
            line.push(b'\n');
            stream.write_all(&line).await?;
            stream.flush().await?;
            let reply = read_line(&mut stream, REPLY_MAX).await?;
            serde_json_lenient::from_slice::<GuestDoorReply>(&reply)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        };
        let reply = match limit {
            Some(limit) => tokio::time::timeout(limit, exchange)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
            None => exchange.await?,
        };
        match reply {
            GuestDoorReply::Error { error } => Err(DoorError::Failed(error)),
            reply => Ok(reply),
        }
    }

    /// Asks the VM host to forward a host port to a box's port.
    ///
    /// A publish that a person may be asked about waits for as long as the
    /// VM host keeps the question open. Dropping the future withdraws it.
    pub(crate) async fn publish(
        &self,
        request: PublishPortRequest,
    ) -> Result<Forwarded, DoorError> {
        let limit = (request.origin != PublishOrigin::Expose).then_some(ANSWER_LIMIT);
        let reply = self
            .ask(&GuestDoorRequest::PublishPort(request), limit)
            .await?;
        match reply {
            GuestDoorReply::Published {
                listener,
                box_id,
                internal,
                proto,
                state,
            } if box_id == request.box_id
                && internal == request.internal
                && proto == request.proto =>
            {
                Ok(Forwarded { listener, state })
            }
            GuestDoorReply::PublishRefused {
                refusal, box_id, ..
            } if box_id == request.box_id => Err(DoorError::Refused(refusal)),
            other => Err(unexpected(&other)),
        }
    }

    /// Asks the VM host to end a forward published at run time. Returns
    /// how many connections the host closed with it.
    pub(crate) async fn unpublish(&self, request: UnpublishPortRequest) -> Result<u32, DoorError> {
        let reply = self
            .ask(
                &GuestDoorRequest::UnpublishPort(request),
                Some(ANSWER_LIMIT),
            )
            .await?;
        match reply {
            GuestDoorReply::Unpublished { closed, .. } => Ok(closed),
            GuestDoorReply::PublishRefused {
                refusal, box_id, ..
            } if box_id == request.box_id => Err(DoorError::Refused(refusal)),
            other => Err(unexpected(&other)),
        }
    }

    /// Tells the VM host whether this daemon runs a box, once. Returns what
    /// the host did with the word.
    pub(crate) async fn report_run(&self, report: BoxRunReport) -> Result<BoxRunEffect, DoorError> {
        let request = GuestDoorRequest::BoxRun(report);
        match self.ask(&request, Some(ANSWER_LIMIT)).await? {
            GuestDoorReply::BoxRunTaken {
                box_id,
                seq,
                effect,
            } if box_id == report.box_id && seq == report.seq => Ok(effect),
            other => Err(unexpected(&other)),
        }
    }

    /// Asks the VM host for the id of a box this daemon is about to
    /// create. A request with the token of an earlier one gets the same id.
    pub(crate) async fn mint_box_id(&self, request: MintBoxIdRequest) -> Result<BoxId, DoorError> {
        let request = GuestDoorRequest::MintBoxId(request);
        match self.ask(&request, Some(ANSWER_LIMIT)).await? {
            GuestDoorReply::BoxIdMinted { minted_box_id } => Ok(minted_box_id),
            other => Err(unexpected(&other)),
        }
    }

    /// Tells the VM host that a port of the node's own address started or
    /// stopped listening.
    pub(crate) async fn listen_notice(&self, notice: ListenNotice) -> Result<(), DoorError> {
        let request = GuestDoorRequest::ListenNotice(notice);
        match self.ask(&request, Some(ANSWER_LIMIT)).await? {
            GuestDoorReply::ListenRecorded { port } if port == notice.port => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    /// Whether the VM host holds a row for the box.
    pub(crate) async fn box_standing(&self, box_id: BoxId) -> Result<bool, DoorError> {
        let request = GuestDoorRequest::BoxStanding(BoxStandingRequest { box_id });
        match self.ask(&request, Some(ANSWER_LIMIT)).await? {
            GuestDoorReply::BoxStanding {
                box_id: answered,
                standing,
            } if answered == box_id => Ok(standing),
            other => Err(unexpected(&other)),
        }
    }
}

/// The guest door as the code that publishes sees it, so a test can stand
/// in for the VM host.
pub trait HostDoor: Send + Sync + std::fmt::Debug {
    fn publish(&self, request: PublishPortRequest) -> BoxFuture<'_, Result<Forwarded, DoorError>>;
    fn unpublish(&self, request: UnpublishPortRequest) -> BoxFuture<'_, Result<u32, DoorError>>;
    fn report_run(&self, report: BoxRunReport) -> BoxFuture<'_, Result<BoxRunEffect, DoorError>>;
    fn box_standing(&self, box_id: BoxId) -> BoxFuture<'_, Result<bool, DoorError>>;
    fn mint_box_id(&self, request: MintBoxIdRequest) -> BoxFuture<'_, Result<BoxId, DoorError>>;
    fn listen_notice(&self, notice: ListenNotice) -> BoxFuture<'_, Result<(), DoorError>>;
}

impl<C: Connect + std::fmt::Debug> HostDoor for GuestDoor<C> {
    fn publish(&self, request: PublishPortRequest) -> BoxFuture<'_, Result<Forwarded, DoorError>> {
        Box::pin(Self::publish(self, request))
    }

    fn unpublish(&self, request: UnpublishPortRequest) -> BoxFuture<'_, Result<u32, DoorError>> {
        Box::pin(Self::unpublish(self, request))
    }

    fn report_run(&self, report: BoxRunReport) -> BoxFuture<'_, Result<BoxRunEffect, DoorError>> {
        Box::pin(Self::report_run(self, report))
    }

    fn box_standing(&self, box_id: BoxId) -> BoxFuture<'_, Result<bool, DoorError>> {
        Box::pin(Self::box_standing(self, box_id))
    }

    fn mint_box_id(&self, request: MintBoxIdRequest) -> BoxFuture<'_, Result<BoxId, DoorError>> {
        Box::pin(Self::mint_box_id(self, request))
    }

    fn listen_notice(&self, notice: ListenNotice) -> BoxFuture<'_, Result<(), DoorError>> {
        Box::pin(Self::listen_notice(self, notice))
    }
}

/// The guest door of the VM host this daemon runs under.
pub(crate) fn of_this_guest() -> Arc<dyn HostDoor> {
    Arc::new(GuestDoor::new(Arc::new(VmHost::of_this_guest())))
}

/// Why the stream door opened no stream.
#[derive(Debug)]
pub(crate) enum StreamError {
    /// The VM host was not reached or did not answer as the door answers.
    Unreachable(io::Error),
    /// The VM host decided against the stream.
    Refused(StreamRefusal),
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(error) => write!(f, "the VM host did not answer: {error}"),
            Self::Refused(reason) => write!(f, "the VM host refused the stream: {reason:?}"),
        }
    }
}

impl std::error::Error for StreamError {}

/// Opens a stream to the host side of the VM. What comes back carries the
/// stream's bytes and nothing of the door's own.
pub(crate) async fn open_stream<C: Connect>(
    host: &C,
    open: StreamOpen,
) -> Result<C::Stream, StreamError> {
    let exchange = async {
        let mut stream = host.connect(VM_HOST_STREAM_PORT).await?;
        let mut line = serde_json_lenient::to_vec(&open).map_err(io::Error::other)?;
        line.push(b'\n');
        stream.write_all(&line).await?;
        stream.flush().await?;
        let reply = read_line(&mut stream, STREAM_REPLY_MAX).await?;
        let reply = serde_json_lenient::from_slice::<StreamReply>(&reply)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        io::Result::Ok((stream, reply))
    };
    let (stream, reply) = tokio::time::timeout(ANSWER_LIMIT, exchange)
        .await
        .map_err(|_| StreamError::Unreachable(io::ErrorKind::TimedOut.into()))?
        .map_err(StreamError::Unreachable)?;
    match reply {
        StreamReply::Open => Ok(stream),
        StreamReply::Refused { reason } => Err(StreamError::Refused(reason)),
    }
}

/// Reads up to the first newline, which it leaves out. A byte at a time:
/// what follows the line on a stream door connection belongs to the stream.
async fn read_line(stream: &mut (impl AsyncRead + Unpin), longest: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the connection closed before the reply line ended",
            ));
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() == longest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the reply line is longer than any reply",
            ));
        }
        line.push(byte[0]);
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A VM host for tests: every connection is handed to a closure.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::DuplexStream;

    type Serve = dyn Fn(u32, DuplexStream) -> BoxFuture<'static, ()> + Send + Sync;

    pub(crate) struct FakeHost {
        serve: Box<Serve>,
        pub(crate) connections: AtomicUsize,
    }

    impl FakeHost {
        pub(crate) fn new<F, Fut>(serve: F) -> Arc<Self>
        where
            F: Fn(u32, DuplexStream) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = ()> + Send + 'static,
        {
            Arc::new(Self {
                serve: Box::new(move |port, stream| Box::pin(serve(port, stream))),
                connections: AtomicUsize::new(0),
            })
        }

        /// A host whose guest door answers each request line with what
        /// `answer` gives for it. `None` closes the connection unanswered.
        pub(crate) fn answering(
            answer: impl Fn(GuestDoorRequest) -> Option<GuestDoorReply> + Send + Sync + 'static,
        ) -> Arc<Self> {
            let answer = Arc::new(answer);
            Self::new(move |port, mut stream| {
                let answer = Arc::clone(&answer);
                async move {
                    assert_eq!(port, VM_HOST_GUEST_DOOR_PORT);
                    let line = read_line(&mut stream, 4096).await.expect("a request line");
                    let request =
                        serde_json_lenient::from_slice(&line).expect("a guest door request");
                    if let Some(reply) = answer(request) {
                        let mut line = serde_json_lenient::to_vec(&reply).unwrap();
                        line.push(b'\n');
                        let _ = stream.write_all(&line).await;
                    }
                }
            })
        }
    }

    impl std::fmt::Debug for FakeHost {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeHost").finish_non_exhaustive()
        }
    }

    impl Connect for FakeHost {
        type Stream = DuplexStream;

        fn connect(&self, port: u32) -> BoxFuture<'_, io::Result<Self::Stream>> {
            self.connections.fetch_add(1, Ordering::SeqCst);
            let (ours, theirs) = tokio::io::duplex(64 * 1024);
            crate::traced::spawn((self.serve)(port, theirs));
            Box::pin(std::future::ready(Ok(ours)))
        }
    }

    pub(crate) fn box_id(last: u8) -> BoxId {
        let mut bytes = [0x11; 16];
        bytes[15] = last;
        BoxId::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeHost, box_id};
    use super::*;
    use boxes::IpProto;
    use minimald_rpc::StreamPurpose;
    use std::sync::atomic::Ordering;

    fn request(origin: PublishOrigin) -> PublishPortRequest {
        PublishPortRequest {
            box_id: box_id(1),
            external: 18080,
            internal: 8080,
            proto: IpProto::Tcp,
            origin,
        }
    }

    fn published(request: &PublishPortRequest, state: ForwardState) -> GuestDoorReply {
        GuestDoorReply::Published {
            listener: "127.0.0.1:18080".parse().unwrap(),
            box_id: request.box_id,
            internal: request.internal,
            proto: request.proto,
            state,
        }
    }

    #[tokio::test]
    async fn a_publish_sends_the_request_and_returns_the_listener() {
        let host = FakeHost::answering(|asked| match asked {
            GuestDoorRequest::PublishPort(asked) => {
                assert_eq!(asked, request(PublishOrigin::Declared));
                Some(published(&asked, ForwardState::Waiting))
            }
            other => panic!("{other:?}"),
        });
        let door = GuestDoor::new(Arc::clone(&host));
        let forwarded = door
            .publish(request(PublishOrigin::Declared))
            .await
            .unwrap();
        assert_eq!(
            forwarded,
            Forwarded {
                listener: "127.0.0.1:18080".parse().unwrap(),
                // A forward that waits for its listener is a forward.
                state: ForwardState::Waiting,
            }
        );
        assert_eq!(host.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_refusal_and_a_host_error_are_told_apart() {
        let host = FakeHost::answering(|asked| match asked {
            GuestDoorRequest::PublishPort(asked) => Some(GuestDoorReply::PublishRefused {
                refusal: PublishRefusal::OutOfRange {
                    range: (3000, 3010),
                },
                box_id: asked.box_id,
                external: asked.external,
                proto: asked.proto,
            }),
            GuestDoorRequest::UnpublishPort(_) => Some(GuestDoorReply::Error {
                error: "the ledger is closed".into(),
            }),
            other => panic!("{other:?}"),
        });
        let door = GuestDoor::new(host);
        let refused = door.publish(request(PublishOrigin::Listen)).await;
        assert!(
            matches!(
                refused,
                Err(DoorError::Refused(PublishRefusal::OutOfRange {
                    range: (3000, 3010)
                }))
            ),
            "{refused:?}"
        );
        let failed = door
            .unpublish(UnpublishPortRequest {
                box_id: box_id(1),
                external: 18080,
                proto: IpProto::Tcp,
            })
            .await;
        assert!(
            matches!(&failed, Err(DoorError::Failed(error)) if error == "the ledger is closed"),
            "{failed:?}"
        );
    }

    #[tokio::test]
    async fn a_reply_about_another_box_is_no_answer() {
        let host = FakeHost::answering(|asked| match asked {
            GuestDoorRequest::PublishPort(asked) => Some(GuestDoorReply::Published {
                listener: "127.0.0.1:18080".parse().unwrap(),
                box_id: box_id(2),
                internal: asked.internal,
                proto: asked.proto,
                state: ForwardState::Bound,
            }),
            GuestDoorRequest::BoxStanding(_) => Some(GuestDoorReply::BoxStanding {
                box_id: box_id(2),
                standing: true,
            }),
            other => panic!("{other:?}"),
        });
        let door = GuestDoor::new(host);
        let publish = door.publish(request(PublishOrigin::Declared)).await;
        assert!(
            matches!(publish, Err(DoorError::Unreachable(_))),
            "{publish:?}"
        );
        let standing = door.box_standing(box_id(1)).await;
        assert!(
            matches!(standing, Err(DoorError::Unreachable(_))),
            "{standing:?}"
        );
    }

    #[tokio::test]
    async fn an_unpublish_returns_the_closed_connections() {
        let host = FakeHost::answering(|asked| match asked {
            GuestDoorRequest::UnpublishPort(asked) => {
                assert_eq!((asked.external, asked.proto), (3005, IpProto::Tcp));
                Some(GuestDoorReply::Unpublished {
                    listener: "127.0.0.1:3005".parse().unwrap(),
                    closed: 3,
                })
            }
            other => panic!("{other:?}"),
        });
        let closed = GuestDoor::new(host)
            .unpublish(UnpublishPortRequest {
                box_id: box_id(1),
                external: 3005,
                proto: IpProto::Tcp,
            })
            .await
            .unwrap();
        assert_eq!(closed, 3);
    }

    #[tokio::test]
    async fn a_run_report_returns_what_the_host_did_with_it() {
        let report = BoxRunReport {
            box_id: box_id(7),
            seq: 12,
            runs: false,
        };
        let host = FakeHost::answering(move |asked| {
            assert_eq!(asked, GuestDoorRequest::BoxRun(report));
            Some(GuestDoorReply::BoxRunTaken {
                box_id: report.box_id,
                seq: report.seq,
                effect: BoxRunEffect::SetAside,
            })
        });
        let effect = GuestDoor::new(host).report_run(report).await;
        assert!(matches!(effect, Ok(BoxRunEffect::SetAside)), "{effect:?}");

        // An answer about another report is no answer to this one.
        let host = FakeHost::answering(move |_| {
            Some(GuestDoorReply::BoxRunTaken {
                box_id: report.box_id,
                seq: report.seq - 1,
                effect: BoxRunEffect::Stale,
            })
        });
        let effect = GuestDoor::new(host).report_run(report).await;
        assert!(
            matches!(effect, Err(DoorError::Unreachable(_))),
            "{effect:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_publish_that_may_ask_a_person_waits_and_any_other_does_not() {
        // The host reads the request and holds the connection open.
        let host = FakeHost::new(|_, mut stream| async move {
            let _ = read_line(&mut stream, 4096).await;
            std::future::pending::<()>().await;
        });
        let door = GuestDoor::new(host);
        let listen = door.publish(request(PublishOrigin::Listen)).await;
        assert!(
            matches!(&listen, Err(DoorError::Unreachable(error)) if error.kind() == io::ErrorKind::TimedOut),
            "{listen:?}"
        );
        let expose = tokio::time::timeout(
            Duration::from_secs(3600),
            door.publish(request(PublishOrigin::Expose)),
        )
        .await;
        assert!(expose.is_err(), "the ask ended by itself: {expose:?}");
    }

    #[tokio::test]
    async fn dropping_a_publish_closes_its_connection() {
        let (closed, mut was_closed) = tokio::sync::mpsc::channel(1);
        let host = FakeHost::new(move |_, mut stream| {
            let closed = closed.clone();
            async move {
                let _ = read_line(&mut stream, 4096).await;
                let mut rest = Vec::new();
                // End of file: the guest's end is gone.
                let _ = stream.read_to_end(&mut rest).await;
                let _ = closed.send(()).await;
            }
        });
        let door = GuestDoor::new(host);
        let asking =
            crate::traced::spawn(async move { door.publish(request(PublishOrigin::Expose)).await });
        tokio::task::yield_now().await;
        asking.abort();
        tokio::time::timeout(Duration::from_secs(5), was_closed.recv())
            .await
            .expect("the host saw the connection close");
    }

    #[tokio::test]
    async fn an_opened_stream_carries_only_the_streams_bytes() {
        let host = FakeHost::new(|port, mut stream| async move {
            assert_eq!(port, VM_HOST_STREAM_PORT);
            let line = read_line(&mut stream, minimald_rpc::STREAM_OPEN_MAX)
                .await
                .unwrap();
            let open: StreamOpen = serde_json_lenient::from_slice(&line).unwrap();
            assert_eq!(open.purpose, StreamPurpose::HostPort { port: 5432 });
            // The reply and the first bytes of the stream in one write.
            stream
                .write_all(b"{\"stream\":\"open\"}\nhello")
                .await
                .unwrap();
            let mut said = [0u8; 4];
            stream.read_exact(&mut said).await.unwrap();
            assert_eq!(&said, b"ping");
            stream.write_all(b" back").await.unwrap();
        });
        let mut stream = open_stream(
            &*host,
            StreamOpen {
                box_id: box_id(1),
                purpose: StreamPurpose::HostPort { port: 5432 },
            },
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut heard = String::new();
        stream.read_to_string(&mut heard).await.unwrap();
        assert_eq!(heard, "hello back");
    }

    #[tokio::test]
    async fn a_refused_stream_says_why() {
        let host = FakeHost::new(|_, mut stream| async move {
            let _ = read_line(&mut stream, minimald_rpc::STREAM_OPEN_MAX).await;
            let reply = StreamReply::Refused {
                reason: StreamRefusal::PortNotExposed,
            };
            let mut line = serde_json_lenient::to_vec(&reply).unwrap();
            line.push(b'\n');
            stream.write_all(&line).await.unwrap();
        });
        let refused = open_stream(
            &*host,
            StreamOpen {
                box_id: box_id(1),
                purpose: StreamPurpose::HostPort { port: 22 },
            },
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(StreamError::Refused(StreamRefusal::PortNotExposed))
            ),
            "{:?}",
            refused.err()
        );
    }

    #[tokio::test]
    async fn a_reply_longer_than_any_reply_is_refused() {
        let host = FakeHost::new(|_, mut stream| async move {
            let _ = read_line(&mut stream, 4096).await;
            let _ = stream.write_all(&vec![b'x'; REPLY_MAX + 1]).await;
        });
        let standing = GuestDoor::new(host).box_standing(box_id(1)).await;
        assert!(
            matches!(&standing, Err(DoorError::Unreachable(error)) if error.kind() == io::ErrorKind::InvalidData),
            "{standing:?}"
        );
    }
}
