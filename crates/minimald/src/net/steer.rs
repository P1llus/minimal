//! The far end of a box's credential proxy endpoint.
//!
//! A connection arrives there in one of two ways. The box dialled the
//! endpoint as its HTTP proxy, and the connection goes to the credential
//! proxy as it is. Or the engine redirected a connection the box made to
//! an address of a steered name. The redirect is by address, and other
//! names can share the address, so the node reads the server name the
//! connection asks for: a steered one goes to the proxy, and anything else
//! goes where the box sent it.
//!
//! A redirect changes where a connection goes, not whether it may exist.
//! The rest of the box's rules judge every redirected connection first.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boxes::BoxId;
use futures::future::BoxFuture;
use minimald_rpc::{ProxyEntry, StreamOpen, StreamPurpose};
use netpol::NamePattern;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::door::{self, Connect, StreamError, VmHost};
use super::engine::Engine;
use super::relay::{CONNECT_LIMIT, Dial, Dialled, Refused, Stream};
use crate::events::{NetRefusal, RuleRef, Source};

/// How long a redirected connection may stay silent before it counts as
/// one that asks for no server name.
const FIRST_BYTE_LIMIT: Duration = Duration::from_secs(2);
/// How long a connection may take to send its whole first message.
const HELLO_LIMIT: Duration = Duration::from_secs(5);
/// The most the node reads of a connection before it decides.
const HELLO_MAX: usize = 32 * 1024;

/// Opens a stream to the credential proxy for a box.
pub(crate) trait Proxy: Send + Sync {
    fn open(
        &self,
        from: BoxId,
        entry: ProxyEntry,
    ) -> BoxFuture<'_, Result<Box<dyn Stream>, Refused>>;
}

/// The credential proxy of a node in a VM: it runs on the VM's host, which
/// opens a stream to it for a box it registered with a grant.
pub(crate) struct DoorProxy<C = VmHost> {
    host: Arc<C>,
}

impl<C: Connect> DoorProxy<C> {
    pub(crate) const fn new(host: Arc<C>) -> Self {
        Self { host }
    }
}

impl<C: Connect> Proxy for DoorProxy<C>
where
    C::Stream: Stream,
{
    fn open(
        &self,
        from: BoxId,
        entry: ProxyEntry,
    ) -> BoxFuture<'_, Result<Box<dyn Stream>, Refused>> {
        Box::pin(async move {
            let open = StreamOpen {
                box_id: from,
                purpose: StreamPurpose::CredentialProxy { entry },
            };
            match door::open_stream(&*self.host, open).await {
                Ok(stream) => Ok(Box::new(stream) as Box<dyn Stream>),
                Err(StreamError::Refused(reason)) => Err(Refused::Door(reason)),
                Err(StreamError::Unreachable(error)) => Err(Refused::Unreachable(error)),
            }
        })
    }
}

/// How a connection came to a box's credential proxy endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entered {
    /// The box dialled the endpoint itself.
    Dialled,
    /// The engine redirected the connection.
    Redirected {
        /// The names steered at the port the box connected to.
        steered: Vec<NamePattern>,
        /// Whether the rest of the box's rules let the connection exist.
        allowed: bool,
    },
}

/// What the dialler asks about a connection at a box's endpoint.
pub(crate) trait Entries: Send + Sync {
    /// How the connection box `from` made to `original` came to the
    /// endpoint. `None` when the box is gone. A connection that the box's
    /// rules refuse is reported here, with the rule that decided.
    fn entered(&self, from: BoxId, original: SocketAddr) -> Option<Entered>;
}

impl Entries for &'static Engine {
    fn entered(&self, from: BoxId, original: SocketAddr) -> Option<Entered> {
        let of = self.installed(from)?;
        if of.is_credential_proxy(original) {
            return Some(Entered::Dialled);
        }
        let flow = netpol::Flow {
            direction: netpol::Direction::Egress,
            protocol: netpol::Protocol::Tcp,
            remote: original.ip(),
            port: original.port(),
            local: None,
        };
        let decision = self.evaluate_unsteered(&of, &flow);
        let allowed = decision.verdict == netpol::FlowVerdict::Allow;
        let steered = of.steered_at(original.port());
        if !allowed {
            let rule = RuleRef::of(&of.compiled(), decision.rule);
            self.observe(
                of,
                NetRefusal {
                    source: Source::CredentialProxy,
                    direction: flow.direction,
                    protocol: Some(flow.protocol),
                    remote: Some(flow.remote),
                    port: Some(flow.port),
                    name: None,
                    reason: crate::events::snake(&decision.reason),
                    rule,
                    pid: None,
                },
            );
        }
        Some(Entered::Redirected { steered, allowed })
    }
}

/// What the bytes a connection has sent so far say about its server name.
#[derive(Debug, PartialEq, Eq)]
enum Hello {
    /// A TLS ClientHello that is not all there yet.
    Partial,
    /// A whole ClientHello, with the server name it asks for.
    Complete(Option<String>),
    /// Not the start of a TLS connection.
    Other,
}

/// Reads `len` bytes at `*at` and moves past them.
fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Option<&'a [u8]> {
    let part = bytes.get(*at..at.checked_add(len)?)?;
    *at += len;
    Some(part)
}

/// Reads a length of `width` bytes at `*at`, then that many bytes.
fn take_sized<'a>(bytes: &'a [u8], at: &mut usize, width: usize) -> Option<&'a [u8]> {
    let len = take(bytes, at, width)?
        .iter()
        .fold(0usize, |len, byte| (len << 8) | usize::from(*byte));
    take(bytes, at, len)
}

/// The host name in the server name extension of a ClientHello body.
fn server_name(body: &[u8]) -> Option<String> {
    let mut at = 0;
    // Version and random.
    take(body, &mut at, 2 + 32)?;
    // Session id, cipher suites, compression methods.
    take_sized(body, &mut at, 1)?;
    take_sized(body, &mut at, 2)?;
    take_sized(body, &mut at, 1)?;
    let extensions = take_sized(body, &mut at, 2)?;
    let mut at = 0;
    while at < extensions.len() {
        let kind = take(extensions, &mut at, 2)?;
        let data = take_sized(extensions, &mut at, 2)?;
        if kind != [0, 0] {
            continue;
        }
        let mut at = 0;
        let names = take_sized(data, &mut at, 2)?;
        let mut at = 0;
        while at < names.len() {
            let kind = take(names, &mut at, 1)?;
            let name = take_sized(names, &mut at, 2)?;
            if kind == [0] {
                let name = std::str::from_utf8(name).ok()?;
                return Some(name.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        return None;
    }
    None
}

/// Reads the start of a TLS connection: handshake records that carry one
/// ClientHello, which may be split over several of them.
fn hello(read: &[u8]) -> Hello {
    const HANDSHAKE: u8 = 22;
    const CLIENT_HELLO: u8 = 1;
    let mut message = Vec::new();
    let mut at = 0;
    loop {
        // What the message needs is known once its header is there.
        if let Some(&[kind, a, b, c]) = message.get(..4) {
            if kind != CLIENT_HELLO {
                return Hello::Other;
            }
            let len = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
            if let Some(body) = message.get(4..4 + len) {
                return Hello::Complete(server_name(body));
            }
        }
        let Some(header) = read.get(at..at + 5) else {
            // A record header that is not all there yet, if what is there
            // can start one.
            return match read.get(at) {
                Some(&kind) if kind != HANDSHAKE => Hello::Other,
                _ => Hello::Partial,
            };
        };
        let len = (usize::from(header[3]) << 8) | usize::from(header[4]);
        // A record holds at most 2^14 bytes, and one of a handshake holds
        // at least one.
        if header[0] != HANDSHAKE || header[1] != 3 || len == 0 || len > 1 << 14 {
            return Hello::Other;
        }
        at += 5;
        let Some(record) = read.get(at..at + len) else {
            return Hello::Partial;
        };
        message.extend_from_slice(record);
        at += len;
    }
}

/// Reads from `client` until it is known which server name the connection
/// asks for, and gives that with everything read. A connection that asks
/// for none, is not TLS, or sends too little in time gives no name.
async fn read_hello(client: &mut TcpStream) -> (Vec<u8>, Option<String>) {
    let mut read = Vec::new();
    let whole = tokio::time::Instant::now() + HELLO_LIMIT;
    loop {
        match hello(&read) {
            Hello::Complete(name) => return (read, name),
            Hello::Other => return (read, None),
            Hello::Partial if read.len() >= HELLO_MAX => return (read, None),
            Hello::Partial => {}
        }
        let until = if read.is_empty() {
            tokio::time::Instant::now() + FIRST_BYTE_LIMIT
        } else {
            whole
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout_at(until, client.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => read.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            // The end of the connection, an error or silence: whatever
            // came decides.
            _ => return (read, None),
        }
    }
}

/// Connects to an address for a box, from the node.
type Direct = fn(SocketAddr) -> BoxFuture<'static, Result<Box<dyn Stream>, Refused>>;

/// Connects to where the box sent a connection that asks for no steered
/// name, from the node, as the box's own packets would leave it.
fn connect_direct(to: SocketAddr) -> BoxFuture<'static, Result<Box<dyn Stream>, Refused>> {
    Box::pin(async move {
        // The node's loopback is not the box's.
        let ip = netpol::eval::canonical(to.ip());
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(Refused::Unreachable(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the node does not dial its own loopback for a box",
            )));
        }
        match tokio::time::timeout(CONNECT_LIMIT, TcpStream::connect(to)).await {
            Ok(Ok(stream)) => Ok(Box::new(stream) as Box<dyn Stream>),
            Ok(Err(error)) => Err(Refused::Unreachable(error)),
            Err(_) => Err(Refused::Unreachable(io::ErrorKind::TimedOut.into())),
        }
    })
}

/// Decides where a connection at a box's credential proxy endpoint goes.
pub(crate) struct CredentialProxy {
    entries: Box<dyn Entries>,
    proxy: Box<dyn Proxy>,
    direct: Direct,
}

impl CredentialProxy {
    pub(crate) fn new(entries: impl Entries + 'static, proxy: impl Proxy + 'static) -> Self {
        Self {
            entries: Box::new(entries),
            proxy: Box::new(proxy),
            direct: connect_direct,
        }
    }

    /// Opens the far end of a redirected connection that the box's rules
    /// allow: the proxy for a steered server name, and else the address
    /// the box connected to. Sends on what was read to tell the two apart.
    async fn redirected(
        &self,
        from: BoxId,
        original: SocketAddr,
        steered: &[NamePattern],
        client: &mut TcpStream,
    ) -> Result<Box<dyn Stream>, Refused> {
        let (read, name) = read_hello(client).await;
        let to_proxy = name
            .as_deref()
            .is_some_and(|name| steered.iter().any(|pattern| pattern.matches(name)));
        let mut far = if to_proxy {
            let entry = ProxyEntry::Redirected {
                destination: original,
            };
            self.proxy.open(from, entry).await?
        } else {
            (self.direct)(original).await?
        };
        far.write_all(&read).await.map_err(Refused::Unreachable)?;
        Ok(far)
    }
}

impl Dial for CredentialProxy {
    fn dial<'a>(
        &'a self,
        from: BoxId,
        original: SocketAddr,
        _peer_port: u16,
        client: &'a mut TcpStream,
    ) -> BoxFuture<'a, Result<Dialled, Refused>> {
        Box::pin(async move {
            let stream = match self.entries.entered(from, original) {
                Some(Entered::Dialled) => self.proxy.open(from, ProxyEntry::Dialled {}).await?,
                Some(Entered::Redirected { allowed: false, .. }) => return Err(Refused::Denied),
                Some(Entered::Redirected { steered, .. }) => {
                    self.redirected(from, original, &steered, client).await?
                }
                None => {
                    return Err(Refused::Unreachable(io::Error::other(
                        "the box of this connection is gone",
                    )));
                }
            };
            Ok(Dialled {
                stream,
                // Whoever holds the far end ends the stream with the
                // box's grant.
                revoked: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::door::testing::{FakeHost, box_id};
    use minimald_rpc::StreamRefusal;
    use proptest::prelude::*;
    use tokio::net::TcpListener;

    /// Entries that say the same of every connection.
    struct Always(Option<Entered>);

    impl Entries for Always {
        fn entered(&self, _: BoxId, _: SocketAddr) -> Option<Entered> {
            self.0.clone()
        }
    }

    /// A VM host whose stream door records each request line and answers
    /// it with `reply`. An opened stream gets `proxied` and is closed.
    fn door(reply: &'static str) -> (Arc<FakeHost>, Arc<std::sync::Mutex<Vec<StreamOpen>>>) {
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&asked);
        let host = FakeHost::new(move |port, mut stream| {
            let seen = Arc::clone(&seen);
            async move {
                assert_eq!(port, minimald_rpc::VM_HOST_STREAM_PORT);
                let mut line = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    if byte == b'\n' {
                        break;
                    }
                    line.push(byte);
                }
                seen.lock()
                    .unwrap()
                    .push(serde_json_lenient::from_slice(&line).unwrap());
                stream.write_all(reply.as_bytes()).await.unwrap();
                if reply.contains("open") {
                    // What the stream carried first comes back after it.
                    stream.write_all(b"proxied").await.unwrap();
                    let mut first = vec![0u8; 4096];
                    if let Ok(n) = stream.read(&mut first).await {
                        let _ = stream.write_all(&first[..n]).await;
                    }
                }
            }
        });
        (host, asked)
    }

    /// A connection of the box, as its endpoint accepted it.
    async fn accepted() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    const ENDPOINT: &str = "127.0.80.1:20482";

    #[tokio::test]
    async fn a_dialled_endpoint_opens_an_explicit_stream() {
        let (host, asked) = door("{\"stream\":\"open\"}\n");
        let dial = CredentialProxy::new(Always(Some(Entered::Dialled)), DoorProxy::new(host));
        let (_client, mut server) = accepted().await;
        let Ok(mut dialled) = dial
            .dial(box_id(3), ENDPOINT.parse().unwrap(), 40000, &mut server)
            .await
        else {
            panic!("the door opened the stream");
        };
        assert_eq!(
            *asked.lock().unwrap(),
            [StreamOpen {
                box_id: box_id(3),
                purpose: StreamPurpose::CredentialProxy {
                    entry: ProxyEntry::Dialled {}
                },
            }]
        );
        dialled.stream.write_all(b"CONNECT").await.unwrap();
        let mut said = Vec::new();
        dialled.stream.read_to_end(&mut said).await.unwrap();
        assert_eq!(said, b"proxiedCONNECT");
        assert!(dialled.revoked.is_none());
    }

    #[tokio::test]
    async fn a_refusal_of_the_door_is_named_for_the_box_s_events() {
        for (reply, refusal, reason) in [
            (
                "{\"stream\":\"refused\",\"reason\":\"proxy_down\"}\n",
                StreamRefusal::ProxyDown,
                Some("credential_proxy_down"),
            ),
            (
                "{\"stream\":\"refused\",\"reason\":\"no_credentialed_grant\"}\n",
                StreamRefusal::NoCredentialedGrant,
                Some("no_credentialed_grant"),
            ),
            (
                "{\"stream\":\"refused\",\"reason\":\"unknown_box\"}\n",
                StreamRefusal::UnknownBox,
                Some("unknown_box"),
            ),
            (
                "{\"stream\":\"refused\",\"reason\":\"busy\"}\n",
                StreamRefusal::Busy,
                Some("too_many_streams"),
            ),
            // Nothing listens on the host: the box's connection fails as
            // it would there, and no decision is behind it.
            (
                "{\"stream\":\"refused\",\"reason\":\"connect_failed\"}\n",
                StreamRefusal::ConnectFailed,
                None,
            ),
        ] {
            let (host, _) = door(reply);
            let dial = CredentialProxy::new(Always(Some(Entered::Dialled)), DoorProxy::new(host));
            let (_client, mut server) = accepted().await;
            let Err(refused) = dial
                .dial(box_id(3), ENDPOINT.parse().unwrap(), 40000, &mut server)
                .await
            else {
                panic!("the door refused the stream");
            };
            assert!(
                matches!(&refused, Refused::Door(got) if *got == refusal),
                "{refused}"
            );
            assert_eq!(refused.reason(), reason);
        }
    }

    #[tokio::test]
    async fn a_connection_no_box_has_at_its_endpoint_opens_nothing() {
        let (host, asked) = door("{\"stream\":\"open\"}\n");
        let dial = CredentialProxy::new(Always(None), DoorProxy::new(Arc::clone(&host)));
        let (_client, mut server) = accepted().await;
        let refused = dial
            .dial(box_id(3), ENDPOINT.parse().unwrap(), 40000, &mut server)
            .await;
        assert!(matches!(refused, Err(Refused::Unreachable(_))));
        assert!(asked.lock().unwrap().is_empty());
    }

    /// A ClientHello that asks for `name`, as one handshake message.
    fn client_hello(name: Option<&str>) -> Vec<u8> {
        let sized = |width: usize, data: &[u8]| {
            let mut out = data.len().to_be_bytes()[8 - width..].to_vec();
            out.extend_from_slice(data);
            out
        };
        let mut extensions = Vec::new();
        // An extension the reader passes over, before the name.
        extensions.extend_from_slice(&[0, 10]);
        extensions.extend(sized(2, &[0, 2, 0, 29]));
        if let Some(name) = name {
            let mut entry = vec![0];
            entry.extend(sized(2, name.as_bytes()));
            extensions.extend_from_slice(&[0, 0]);
            extensions.extend(sized(2, &sized(2, &entry)));
        }
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.extend(sized(1, &[9; 32]));
        body.extend(sized(2, &[0x13, 0x01]));
        body.extend(sized(1, &[0]));
        body.extend(sized(2, &extensions));
        let mut message = vec![1];
        message.extend(sized(3, &body));
        message
    }

    /// `message` as TLS handshake records of at most `most` bytes each.
    fn records(message: &[u8], most: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in message.chunks(most) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&u16::try_from(part.len()).unwrap().to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn a_client_hello_gives_its_server_name_once_it_is_all_there() {
        let message = client_hello(Some("GitHub.com."));
        for most in [message.len(), 40, 1] {
            let wire = records(&message, most);
            for cut in 0..wire.len() {
                assert_eq!(hello(&wire[..cut]), Hello::Partial, "{most} {cut}");
            }
            assert_eq!(
                hello(&wire),
                Hello::Complete(Some("github.com".to_owned())),
                "{most}"
            );
        }
        let unnamed = records(&client_hello(None), 16384);
        assert_eq!(hello(&unnamed), Hello::Complete(None));
        // What is no ClientHello is known as soon as it cannot be one.
        assert_eq!(hello(b"G"), Hello::Other);
        assert_eq!(hello(b"GET / HTTP/1.1\r\n"), Hello::Other);
        assert_eq!(hello(&[22, 3, 1, 0, 0]), Hello::Other);
        assert_eq!(hello(&[22, 3, 1, 0x7f, 0xff]), Hello::Other);
        // A ServerHello in a handshake record.
        assert_eq!(hello(&[22, 3, 3, 0, 4, 2, 0, 0, 0]), Hello::Other);
    }

    proptest! {
        /// Whatever a box sends, the reader ends, and a name it gives is
        /// one a whole ClientHello carried.
        #[test]
        fn arbitrary_bytes_are_read_without_a_panic(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
            let _ = hello(&bytes);
            let _ = server_name(&bytes);
        }

        #[test]
        fn a_name_survives_any_split_into_records(
            name in "[a-z0-9-]{1,20}(\\.[a-z0-9-]{1,20}){0,3}",
            most in 1usize..300,
            tail in prop::collection::vec(any::<u8>(), 0..50),
        ) {
            let mut wire = records(&client_hello(Some(&name)), most);
            wire.extend(tail);
            prop_assert_eq!(hello(&wire), Hello::Complete(Some(name)));
        }
    }

    fn steered(names: &[&str], allowed: bool) -> Always {
        Always(Some(Entered::Redirected {
            steered: names.iter().map(|n| n.parse().unwrap()).collect(),
            allowed,
        }))
    }

    /// A destination that says `direct` and then echoes what it got first.
    fn direct(to: SocketAddr) -> BoxFuture<'static, Result<Box<dyn Stream>, Refused>> {
        Box::pin(async move {
            assert_eq!(to, ORIGINAL.parse().unwrap());
            let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
            crate::traced::spawn(async move {
                theirs.write_all(b"direct").await.unwrap();
                let mut first = vec![0u8; 4096];
                if let Ok(n) = theirs.read(&mut first).await {
                    let _ = theirs.write_all(&first[..n]).await;
                }
            });
            Ok(Box::new(ours) as Box<dyn Stream>)
        })
    }

    const ORIGINAL: &str = "140.82.112.3:443";

    /// Dials for a redirected connection whose first bytes are `first`,
    /// and gives what the far end said: who it is, then those bytes back.
    async fn redirected(
        entries: Always,
        first: &[u8],
    ) -> (Result<Vec<u8>, Refused>, Vec<StreamOpen>) {
        let (host, asked) = door("{\"stream\":\"open\"}\n");
        let mut dial = CredentialProxy::new(entries, DoorProxy::new(host));
        dial.direct = direct;
        let (mut client, mut server) = accepted().await;
        client.write_all(first).await.unwrap();
        let dialled = dial
            .dial(box_id(3), ORIGINAL.parse().unwrap(), 40000, &mut server)
            .await;
        let said = match dialled {
            Ok(mut dialled) => {
                let mut said = Vec::new();
                dialled.stream.read_to_end(&mut said).await.unwrap();
                Ok(said)
            }
            Err(refused) => Err(refused),
        };
        let asked = asked.lock().unwrap().clone();
        (said, asked)
    }

    #[tokio::test]
    async fn a_steered_server_name_goes_to_the_proxy_with_the_bytes_already_read() {
        let wire = records(&client_hello(Some("github.com")), 16384);
        let (said, asked) = redirected(steered(&["github.com"], true), &wire).await;
        assert_eq!(said.unwrap(), [b"proxied".as_slice(), &wire].concat());
        assert_eq!(
            asked,
            [StreamOpen {
                box_id: box_id(3),
                purpose: StreamPurpose::CredentialProxy {
                    entry: ProxyEntry::Redirected {
                        destination: ORIGINAL.parse().unwrap()
                    }
                },
            }]
        );
    }

    #[tokio::test]
    async fn another_server_name_at_a_steered_address_goes_to_its_destination() {
        // A name that shares the address, a connection that names nobody,
        // and one that is not TLS.
        let gist = records(&client_hello(Some("gist.github.com")), 16384);
        let unnamed = records(&client_hello(None), 16384);
        for first in [gist.as_slice(), &unnamed, b"SSH-2.0-client\r\n"] {
            let (said, asked) = redirected(steered(&["github.com"], true), first).await;
            assert_eq!(said.unwrap(), [b"direct".as_slice(), first].concat());
            assert!(asked.is_empty(), "the proxy was asked: {asked:?}");
        }
    }

    #[tokio::test]
    async fn a_connection_the_box_s_own_rules_refuse_goes_nowhere() {
        let wire = records(&client_hello(Some("github.com")), 16384);
        let (said, asked) = redirected(steered(&["github.com"], false), &wire).await;
        assert!(matches!(said, Err(Refused::Denied)));
        assert!(asked.is_empty());
        // The refusal was reported where it was decided, so the endpoint
        // adds no event of its own.
        assert_eq!(Refused::Denied.reason(), None);
    }

    #[tokio::test]
    async fn the_node_does_not_dial_its_own_loopback_for_a_box() {
        for to in [
            "127.0.0.1:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "0.0.0.0:443",
        ] {
            let Err(Refused::Unreachable(error)) = connect_direct(to.parse().unwrap()).await else {
                panic!("{to} was dialled");
            };
            assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable, "{to}");
        }
    }
}
