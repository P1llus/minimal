//! The far end of a box's credential proxy endpoint.
//!
//! A connection arrives there in one of two ways. The box dialled the
//! endpoint as its HTTP proxy, and the connection goes to the credential
//! proxy as it is. Or the engine redirected a connection the box made to
//! an address of a steered name.

use std::net::SocketAddr;
use std::sync::Arc;

use boxes::BoxId;
use futures::future::BoxFuture;
use minimald_rpc::{ProxyEntry, StreamOpen, StreamPurpose};
use tokio::net::TcpStream;

use super::door::{self, Connect, StreamError, VmHost};
use super::engine::Engine;
use super::relay::{Dial, Dialled, Refused, Stream};

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
}

/// What the dialler asks about a connection at a box's endpoint.
pub(crate) trait Entries: Send + Sync {
    /// How the connection box `from` made to `original` came to the
    /// endpoint. `None` when the box has no such connection: it is gone,
    /// or nothing sends a connection to `original` there.
    fn entered(&self, from: BoxId, original: SocketAddr) -> Option<Entered>;
}

impl Entries for &'static Engine {
    fn entered(&self, from: BoxId, original: SocketAddr) -> Option<Entered> {
        let of = self.installed(from)?;
        of.is_credential_proxy(original).then_some(Entered::Dialled)
    }
}

/// Decides where a connection at a box's credential proxy endpoint goes.
pub(crate) struct CredentialProxy {
    entries: Box<dyn Entries>,
    proxy: Box<dyn Proxy>,
}

impl CredentialProxy {
    pub(crate) fn new(entries: impl Entries + 'static, proxy: impl Proxy + 'static) -> Self {
        Self {
            entries: Box::new(entries),
            proxy: Box::new(proxy),
        }
    }
}

impl Dial for CredentialProxy {
    fn dial<'a>(
        &'a self,
        from: BoxId,
        original: SocketAddr,
        _peer_port: u16,
        _client: &'a mut TcpStream,
    ) -> BoxFuture<'a, Result<Dialled, Refused>> {
        Box::pin(async move {
            let stream = match self.entries.entered(from, original) {
                Some(Entered::Dialled) => self.proxy.open(from, ProxyEntry::Dialled {}).await?,
                None => {
                    return Err(Refused::Unreachable(std::io::Error::other(
                        "no box has this connection at its credential proxy endpoint",
                    )));
                }
            };
            Ok(Dialled {
                stream,
                // Whoever holds the proxy ends the stream with the box's
                // grant.
                revoked: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::door::testing::{FakeHost, box_id};
    use crate::net::relay::CREDENTIAL_PROXY;
    use minimald_rpc::StreamRefusal;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
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
                    stream.write_all(b"proxied").await.unwrap();
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
        let mut said = Vec::new();
        dialled.stream.read_to_end(&mut said).await.unwrap();
        assert_eq!(said, b"proxied");
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
            assert_eq!((CREDENTIAL_PROXY.reason)(&refused), reason);
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
}
