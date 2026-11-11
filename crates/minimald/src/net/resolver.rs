//! The daemon's resolver for boxes.
//!
//! Every box whose DNS the policy engine redirects asks here, at an
//! endpoint of its own. The resolver answers the box-name zone itself,
//! refuses names the box's policy does not admit, forwards the rest to the
//! node's resolver, and pins the addresses of admitted names into the
//! engine, which is what lets the box connect to them.
//!
//! The core ([`decide`], [`vet`], [`Resolver::answer`]) knows nothing about
//! sockets. [`serve_udp`] and [`serve_tcp`] put it behind any bound socket.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use boxes::core::zone_answer;
use hickory_proto::{
    op::{Message, MessageType, Metadata, OpCode, ResponseCode},
    rr::{RData, Record, RecordType, rdata::A},
};
use netpol::{Compiled, Prefix, Protocol, pins};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};

use super::{
    answerer,
    dns::ZoneEntry,
    endpoints::Service,
    engine::{Engine, Installed, Peers},
};
use crate::events::{NetRefusal, Source};

/// Names the resolvers boxes' queries are forwarded to, as a
/// comma-separated list of `address:port`, in place of the node's own.
pub const UPSTREAM_ENV: &str = "MINIMALD_UPSTREAM_DNS";

const DNS_PORT: u16 = 53;
/// The largest message taken over UDP, from a box or from upstream, and
/// the payload size the resolver tells upstream it takes. TCP carries
/// whatever its two-byte length can say.
const MAX_DATAGRAM: usize = 4096;
/// Addresses pinned from one answer.
const MAX_PINS: usize = 32;
/// How long one upstream server gets, and all of them together.
const UPSTREAM_TRY: Duration = Duration::from_secs(2);
const UPSTREAM_TOTAL: Duration = Duration::from_secs(5);
/// Queries of one box answered at a time over UDP, and its open TCP
/// connections. More are dropped: the box retries.
const UDP_IN_FLIGHT: usize = 64;
const TCP_CONNECTIONS: usize = 16;
const TCP_IDLE: Duration = Duration::from_secs(10);

/// How a query arrived, and so how it goes upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

/// What the resolver knows of the box that asks.
#[derive(Debug, Clone, Copy)]
pub(crate) struct View<'a> {
    pub(crate) compiled: &'a Compiled,
    /// Prefixes the box allows: an internal address inside one may be
    /// pinned.
    pub(crate) allowed: &'a [Prefix],
    /// Addresses of the node's own infrastructure.
    pub(crate) infrastructure: &'a [Prefix],
    /// Whether the box has an IPv6 route off the node.
    pub(crate) ipv6: bool,
}

/// What to do with one query.
#[derive(Debug)]
pub(crate) enum Decided {
    /// Nothing can be sent back.
    Drop,
    Reply(Vec<u8>),
    /// The box's policy does not admit the name.
    Refused {
        reply: Vec<u8>,
        name: String,
    },
    /// A name of the box zone, which the daemon answers.
    Zone {
        name: String,
        query: Box<Message>,
    },
    /// A name for the node's resolver, with the query to send there:
    /// built from the one question the policy checked, and nothing else
    /// of what the box sent.
    Forward {
        name: String,
        query: Vec<u8>,
    },
}

fn normalized(name: &hickory_proto::rr::Name) -> String {
    let lower = name.to_lowercase().to_string();
    lower.strip_suffix('.').unwrap_or(&lower).to_owned()
}

fn in_zone(name: &str) -> bool {
    name == zone_answer::ZONE_APEX
        || name
            .strip_suffix(zone_answer::ZONE_APEX)
            .is_some_and(|head| head.ends_with('.'))
}

/// A reply to `query` with no records.
fn empty(query: &Message, rcode: ResponseCode) -> Message {
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata = Metadata::response_from_request(&query.metadata);
    reply.metadata.recursion_available = true;
    reply.metadata.response_code = rcode;
    for question in &query.queries {
        reply.add_query(question.clone());
    }
    reply
}

fn encoded(message: &Message) -> Option<Vec<u8>> {
    message.to_vec().ok()
}

/// Decides one query of a box from its policy alone.
pub(crate) fn decide(query: &[u8], view: &View<'_>) -> Decided {
    let Ok(message) = Message::from_vec(query) else {
        return Decided::Drop;
    };
    if message.metadata.message_type != MessageType::Query {
        return Decided::Drop;
    }
    let reply = |rcode| encoded(&empty(&message, rcode)).map_or(Decided::Drop, Decided::Reply);
    if message.metadata.op_code != OpCode::Query {
        return reply(ResponseCode::NotImp);
    }
    // One question is what resolvers send and what the policy checks. A
    // second one would go upstream unchecked.
    let [question] = message.queries.as_slice() else {
        return reply(ResponseCode::FormErr);
    };
    let name = normalized(question.name());
    let qtype = question.query_type();

    if !view.compiled.resolvable(&name) {
        return match encoded(&empty(&message, ResponseCode::NXDomain)) {
            Some(reply) => Decided::Refused { reply, name },
            None => Decided::Drop,
        };
    }
    if in_zone(&name) {
        return Decided::Zone {
            name,
            query: Box::new(message),
        };
    }
    // Without an IPv6 route an AAAA answer only makes the box try
    // addresses its policy refuses.
    if qtype == RecordType::AAAA && !view.ipv6 {
        return reply(ResponseCode::NoError);
    }
    // These records carry addresses and endpoints of their own, which
    // would bypass the pins a name rule works through.
    if matches!(qtype, RecordType::HTTPS | RecordType::SVCB) && !view.compiled.names.is_empty() {
        return reply(ResponseCode::NoError);
    }
    match upstream_query(&message, question) {
        Some(query) => Decided::Forward { name, query },
        None => Decided::Drop,
    }
}

/// The query the node's resolver gets for a box's question: the box's id
/// and recursion flag, the one question, and an EDNS record of the
/// resolver's own when the box sent one. Of the box's EDNS record only the
/// DNSSEC bit and a payload size within the resolver's own limit carry
/// over, so no option and no second record of the box reaches upstream.
fn upstream_query(message: &Message, question: &hickory_proto::op::Query) -> Option<Vec<u8>> {
    let mut query = Message::query();
    query.metadata.id = message.metadata.id;
    query.metadata.recursion_desired = message.metadata.recursion_desired;
    query.add_query(question.clone());
    if let Some(theirs) = &message.edns {
        let mut ours = hickory_proto::op::Edns::new();
        let limit = u16::try_from(MAX_DATAGRAM).unwrap_or(u16::MAX);
        ours.set_max_payload(theirs.max_payload().clamp(512, limit));
        ours.set_dnssec_ok(theirs.flags().dnssec_ok);
        query.set_edns(ours);
    }
    encoded(&query)
}

/// What the zone holds for a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZoneAnswer {
    Address(Ipv4Addr),
    /// The name exists and has no address to tell.
    NoData,
    NoSuchName,
}

/// A zone answer after the pin check, for a name a rule of the box names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZoneAdmission {
    /// What the box is told.
    pub(crate) answer: ZoneAnswer,
    /// The address to admit for the box.
    pub(crate) pin: Option<IpAddr>,
    /// The address the zone holds and the box is not told: one its policy
    /// would have to allow by prefix before a name may open it.
    pub(crate) refused: Option<IpAddr>,
}

/// Puts a zone answer through the check every pinned address passes. A
/// listed name opens the address it resolves to on every port, so a zone
/// name gets no more than an upstream name would: an internal address is
/// pinned only when a prefix the box allows covers it.
pub(crate) fn admit_zone(answer: ZoneAnswer, name: &str, view: &View<'_>) -> ZoneAdmission {
    let told = ZoneAdmission {
        answer,
        pin: None,
        refused: None,
    };
    let (ZoneAnswer::Address(address), Some(_)) = (answer, view.compiled.set_for_name(name)) else {
        return told;
    };
    let address = IpAddr::V4(address);
    if pins::may_pin(address, view.allowed, view.infrastructure) {
        ZoneAdmission {
            pin: Some(address),
            ..told
        }
    } else {
        ZoneAdmission {
            answer: ZoneAnswer::NoData,
            pin: None,
            refused: Some(address),
        }
    }
}

/// The reply for a zone name.
pub(crate) fn zone_reply(query: &Message, answer: ZoneAnswer) -> Option<Vec<u8>> {
    let question = query.queries.first()?;
    let (rcode, record) = match answer {
        ZoneAnswer::Address(address) if question.query_type() == RecordType::A => (
            ResponseCode::NoError,
            Some(Record::from_rdata(
                question.name().clone(),
                zone_answer::ANSWER_TTL_SECS,
                RData::A(A(address)),
            )),
        ),
        ZoneAnswer::Address(_) | ZoneAnswer::NoData => (ResponseCode::NoError, None),
        ZoneAnswer::NoSuchName => (ResponseCode::NXDomain, None),
    };
    let mut reply = empty(query, rcode);
    reply.metadata.authoritative = true;
    match record {
        Some(record) => {
            reply.add_answer(record);
        }
        // A negative answer carries the zone's SOA, so the box's resolver
        // library caches it for the zone's short lifetime and no longer.
        None => {
            reply.add_authority(answerer::zone_soa());
        }
    }
    encoded(&reply)
}

/// An upstream reply after the rebinding filter.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Vetted {
    pub(crate) reply: Vec<u8>,
    /// Addresses to admit for the box as addresses of the name asked for.
    pub(crate) pins: Vec<IpAddr>,
    /// Addresses taken out of the reply: the name resolved to something a
    /// public name has no business pointing at.
    pub(crate) refused: Vec<IpAddr>,
}

fn address_of(record: &Record) -> Option<IpAddr> {
    match &record.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

/// Vets the upstream's reply for `name`.
///
/// When a rule of the box names `name`, the addresses the reply gives for
/// it are what the box may then connect to. Only records that follow from
/// the question count: the name's own, and those of the CNAME chain that
/// starts at it. An address that fails the rebinding filter is removed, and
/// so is one the chain does not lead to.
///
/// A name no rule of the box names is pinned nowhere and passes unchanged:
/// such a box is judged by address alone.
pub(crate) fn vet(reply: Vec<u8>, name: &str, view: &View<'_>) -> Vetted {
    if view.compiled.set_for_name(name).is_none() {
        return Vetted {
            reply,
            ..Vetted::default()
        };
    }
    let Ok(mut message) = Message::from_vec(&reply) else {
        // Nothing can be pinned from what cannot be read, so the box could
        // connect to none of it. Say so in a way it understands.
        return Vetted::default();
    };
    let mut chain: BTreeSet<String> = BTreeSet::from([name.to_owned()]);
    let mut vetted = Vetted::default();
    let answers = std::mem::take(&mut message.answers);
    let before = answers.len();
    let mut kept = Vec::with_capacity(before);
    for record in answers {
        let owner = normalized(&record.name);
        if let RData::CNAME(target) = &record.data {
            if chain.contains(&owner) {
                chain.insert(normalized(&target.0));
            }
            kept.push(record);
            continue;
        }
        let Some(address) = address_of(&record) else {
            kept.push(record);
            continue;
        };
        if !chain.contains(&owner) {
            continue;
        }
        if !pins::may_pin(address, view.allowed, view.infrastructure) {
            vetted.refused.push(address);
            continue;
        }
        if vetted.pins.len() < MAX_PINS {
            vetted.pins.push(address);
            kept.push(record);
        }
    }
    let unchanged = kept.len() == before;
    message.answers = kept;
    vetted.reply = if unchanged {
        reply
    } else {
        encoded(&message).unwrap_or_default()
    };
    vetted
}

/// The node's resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Upstream {
    servers: Vec<SocketAddr>,
}

impl Upstream {
    pub(crate) const fn servers(servers: Vec<SocketAddr>) -> Self {
        Self { servers }
    }

    /// The resolvers a native node is configured with.
    pub(crate) fn of_this_host() -> Self {
        let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        Self::from_resolv_conf(&text)
    }

    fn from_resolv_conf(text: &str) -> Self {
        let servers = text
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("nameserver"))
                    .then(|| words.next())
                    .flatten()
            })
            // A scoped link-local server would need its interface, and a
            // host has another server whenever it has one of those.
            .filter_map(|word| word.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, DNS_PORT))
            .collect();
        Self { servers }
    }

    async fn ask_udp(server: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let bind: SocketAddr = match server {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server).await?;
        socket.send(query).await?;
        // One byte more than a datagram may have: a read that fills the
        // buffer was cut short, and half an answer is no answer.
        let mut buf = vec![0u8; MAX_DATAGRAM + 1];
        loop {
            let n = socket.recv(&mut buf).await?;
            // The reply to this query carries its id. Anything else on the
            // socket is not an answer.
            if (2..=MAX_DATAGRAM).contains(&n) && buf.get(..2) == query.get(..2) {
                buf.truncate(n);
                return Ok(buf);
            }
        }
    }

    async fn ask_tcp(server: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(server).await?;
        write_framed(&mut stream, query).await?;
        read_framed(&mut stream)
            .await?
            .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }

    /// One query to the node's resolvers, each in turn until one answers.
    pub(crate) async fn ask(&self, query: &[u8], via: Transport) -> Option<Vec<u8>> {
        let all = async {
            for server in &self.servers {
                let one = async {
                    match via {
                        Transport::Udp => Self::ask_udp(*server, query).await,
                        Transport::Tcp => Self::ask_tcp(*server, query).await,
                    }
                };
                match tokio::time::timeout(UPSTREAM_TRY, one).await {
                    Ok(Ok(reply)) => return Some(reply),
                    Ok(Err(error)) => {
                        tracing::debug!(%server, %error, "an upstream resolver did not answer");
                    }
                    Err(_elapsed) => {
                        tracing::debug!(%server, "an upstream resolver timed out");
                    }
                }
            }
            None
        };
        tokio::time::timeout(UPSTREAM_TOTAL, all)
            .await
            .ok()
            .flatten()
    }
}

/// The box-name zone as the resolver reads it.
pub(crate) struct Zone {
    names: Arc<dyn answerer::Zone>,
}

impl Zone {
    pub(crate) fn new(names: Arc<dyn answerer::Zone>) -> Self {
        Self { names }
    }

    fn lookup(&self, name: &str) -> ZoneAnswer {
        // The host's name exists and has no address a box may be told:
        // the host's loopback is not a box's to reach by a name.
        if name == zone_answer::HOST_ROW_NAME {
            return ZoneAnswer::NoData;
        }
        match self.names.zone_entry(name, &[]) {
            ZoneEntry::Held {
                address: Some(address),
                ..
            } => ZoneAnswer::Address(address),
            ZoneEntry::Held { address: None, .. } => ZoneAnswer::NoData,
            ZoneEntry::Absent => ZoneAnswer::NoSuchName,
        }
    }
}

pub(crate) struct Resolver {
    engine: &'static Engine,
    zone: Zone,
    upstream: Upstream,
}

impl Resolver {
    pub(crate) const fn new(engine: &'static Engine, zone: Zone, upstream: Upstream) -> Self {
        Self {
            engine,
            zone,
            upstream,
        }
    }

    fn refused(&self, of: &Arc<Installed>, name: &str, reason: &str, remote: Option<IpAddr>) {
        self.engine.observe(
            Arc::clone(of),
            NetRefusal {
                source: Source::Resolver,
                direction: netpol::Direction::Egress,
                protocol: None,
                remote,
                port: None,
                name: Some(name.to_owned()),
                reason: reason.to_owned(),
                rule: None,
                pid: None,
            },
        );
    }

    fn pin(&self, of: &Installed, address: IpAddr, name: &str) {
        if let Err(error) = self.engine.pin(of, address, name) {
            tracing::warn!(
                box_id = %of.session(),
                %address,
                %error,
                "an address the box resolved could not be admitted"
            );
        }
    }

    /// One query of one box in, its reply out. `None` sends nothing.
    pub(crate) async fn answer(
        &self,
        of: &Arc<Installed>,
        query: &[u8],
        via: Transport,
    ) -> Option<Vec<u8>> {
        let compiled = of.compiled();
        let (allowed, infrastructure) = (of.allowed_prefixes(), of.infrastructure());
        let view = View {
            compiled: &compiled,
            allowed: &allowed,
            infrastructure: &infrastructure,
            ipv6: of.has_ipv6(),
        };
        match decide(query, &view) {
            Decided::Drop => None,
            Decided::Reply(reply) => Some(reply),
            Decided::Refused { reply, name } => {
                self.refused(of, &name, "name_not_allowed", None);
                Some(reply)
            }
            Decided::Zone { name, query } => {
                let admitted = admit_zone(self.zone.lookup(&name), &name, &view);
                if let Some(address) = admitted.pin {
                    self.pin(of, address, &name);
                }
                if let Some(address) = admitted.refused {
                    self.refused(of, &name, "rebinding", Some(address));
                }
                zone_reply(&query, admitted.answer)
            }
            Decided::Forward {
                name,
                query: upstream,
            } => {
                let Some(reply) = self.upstream.ask(&upstream, via).await else {
                    let query = Message::from_vec(query).ok()?;
                    return encoded(&empty(&query, ResponseCode::ServFail));
                };
                let vetted = vet(reply, &name, &view);
                for address in &vetted.pins {
                    self.pin(of, *address, &name);
                }
                for address in &vetted.refused {
                    self.refused(of, &name, "rebinding", Some(*address));
                }
                if vetted.reply.is_empty() {
                    let query = Message::from_vec(query).ok()?;
                    return encoded(&empty(&query, ResponseCode::ServFail));
                }
                Some(vetted.reply)
            }
        }
    }
}

async fn read_framed(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

async fn write_framed(stream: &mut TcpStream, message: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(message.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    stream.write_all(&framed).await
}

/// Serves the box's resolver on a UDP socket until the task is aborted.
/// A datagram from a peer the engine does not name as this box's is
/// ignored.
pub(crate) async fn serve_udp(
    resolver: Arc<Resolver>,
    of: Arc<Installed>,
    peers: Peers,
    socket: UdpSocket,
) {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(Semaphore::new(UDP_IN_FLIGHT));
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                tracing::warn!(box_id = %of.session(), %error, "a resolver endpoint stopped");
                return;
            }
        };
        if peers
            .of_box(&of, Service::Resolver, peer, Protocol::Udp)
            .is_none()
        {
            continue;
        }
        let Ok(permit) = Arc::clone(&in_flight).try_acquire_owned() else {
            continue;
        };
        let query = buf.get(..n).unwrap_or_default().to_vec();
        let (resolver, of, socket) = (Arc::clone(&resolver), Arc::clone(&of), Arc::clone(&socket));
        crate::traced::spawn(async move {
            if let Some(reply) = resolver.answer(&of, &query, Transport::Udp).await {
                let _sent = socket.send_to(&reply, peer).await;
            }
            drop(permit);
        });
    }
}

/// Serves the box's resolver on a TCP listener until the task is aborted.
/// A connection from a peer the engine does not name as this box's is
/// closed unread.
pub(crate) async fn serve_tcp(
    resolver: Arc<Resolver>,
    of: Arc<Installed>,
    peers: Peers,
    listener: TcpListener,
) {
    let open = Arc::new(Semaphore::new(TCP_CONNECTIONS));
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(box_id = %of.session(), %error, "a resolver endpoint stopped");
                return;
            }
        };
        if peers
            .of_box(&of, Service::Resolver, peer, Protocol::Tcp)
            .is_none()
        {
            continue;
        }
        let Ok(permit) = Arc::clone(&open).try_acquire_owned() else {
            continue;
        };
        let (resolver, of) = (Arc::clone(&resolver), Arc::clone(&of));
        crate::traced::spawn(async move {
            while let Ok(Ok(Some(query))) =
                tokio::time::timeout(TCP_IDLE, read_framed(&mut stream)).await
            {
                let Some(reply) = resolver.answer(&of, &query, Transport::Tcp).await else {
                    break;
                };
                if write_framed(&mut stream, &reply).await.is_err() {
                    break;
                }
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::Query,
        rr::{
            Name,
            rdata::{AAAA, CNAME},
        },
    };
    use netpol::{
        BoxPolicy, Spec,
        base::{Deployment, Mode, NodeKind},
    };

    use super::*;

    fn compiled(policy: BoxPolicy) -> Compiled {
        Spec {
            deployment: Deployment::new(NodeKind::Native, Mode::HostIp),
            policy,
            options: crate::net::spec::OPTIONS,
        }
        .compile()
        .expect("compile")
    }

    fn by_name(names: &[&str]) -> Compiled {
        compiled(BoxPolicy {
            names: names.iter().map(|n| n.parse().expect("name")).collect(),
            ..BoxPolicy::default()
        })
    }

    fn view(compiled: &Compiled) -> View<'_> {
        View {
            compiled,
            allowed: &[],
            infrastructure: &[],
            ipv6: true,
        }
    }

    fn name(text: &str) -> Name {
        Name::from_utf8(format!("{text}.")).expect("name")
    }

    fn query(host: &str, rtype: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 0x1234;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(name(host), rtype));
        message.to_vec().expect("encode")
    }

    fn upstream_reply(host: &str, records: Vec<Record>) -> Vec<u8> {
        let question = Message::from_vec(&query(host, RecordType::A)).expect("decode");
        let mut reply = empty(&question, ResponseCode::NoError);
        for record in records {
            reply.add_answer(record);
        }
        reply.to_vec().expect("encode")
    }

    fn a(owner: &str, address: &str) -> Record {
        Record::from_rdata(name(owner), 60, RData::A(A(address.parse().expect("v4"))))
    }

    fn aaaa(owner: &str, address: &str) -> Record {
        Record::from_rdata(
            name(owner),
            60,
            RData::AAAA(AAAA(address.parse().expect("v6"))),
        )
    }

    fn cname(owner: &str, target: &str) -> Record {
        Record::from_rdata(name(owner), 60, RData::CNAME(CNAME(name(target))))
    }

    fn rcode(reply: &[u8]) -> ResponseCode {
        Message::from_vec(reply)
            .expect("decode")
            .metadata
            .response_code
    }

    fn addresses(reply: &[u8]) -> Vec<IpAddr> {
        Message::from_vec(reply)
            .expect("decode")
            .answers
            .iter()
            .filter_map(address_of)
            .collect()
    }

    #[test]
    fn a_name_the_policy_does_not_admit_is_nxdomain_and_reported() {
        let policy = by_name(&["api.example.com", "*.pkg.example.org"]);
        let view = view(&policy);
        for host in ["other.example.com", "example.org", "pkg.example.org"] {
            match decide(&query(host, RecordType::A), &view) {
                Decided::Refused { reply, name } => {
                    assert_eq!(rcode(&reply), ResponseCode::NXDomain);
                    assert_eq!(name, host);
                    // The reply answers the question that was asked.
                    let reply = Message::from_vec(&reply).expect("decode");
                    assert_eq!(reply.metadata.id, 0x1234);
                    assert_eq!(reply.queries.len(), 1);
                }
                other => panic!("{host}: {other:?}"),
            }
        }
        for host in [
            "api.example.com",
            "API.Example.COM",
            "a.pkg.example.org",
            "a.b.pkg.example.org",
        ] {
            assert!(
                matches!(
                    decide(&query(host, RecordType::A), &view),
                    Decided::Forward { .. }
                ),
                "{host}"
            );
        }
    }

    #[test]
    fn a_box_that_allows_everything_has_every_name_forwarded() {
        let policy = compiled(BoxPolicy::default());
        let view = view(&policy);
        for rtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::TXT,
        ] {
            assert!(
                matches!(
                    decide(&query("anything.example", rtype), &view),
                    Decided::Forward { .. }
                ),
                "{rtype:?}"
            );
        }
    }

    #[test]
    fn records_that_would_bypass_the_pins_are_answered_empty() {
        let policy = by_name(&["api.example.com"]);
        let mut view = view(&policy);
        for rtype in [RecordType::HTTPS, RecordType::SVCB] {
            match decide(&query("api.example.com", rtype), &view) {
                Decided::Reply(reply) => {
                    assert_eq!(rcode(&reply), ResponseCode::NoError);
                    assert!(addresses(&reply).is_empty());
                }
                other => panic!("{rtype:?}: {other:?}"),
            }
        }
        // AAAA is forwarded where the box has an IPv6 route, and answered
        // empty where it has none.
        assert!(matches!(
            decide(&query("api.example.com", RecordType::AAAA), &view),
            Decided::Forward { .. }
        ));
        view.ipv6 = false;
        assert!(matches!(
            decide(&query("api.example.com", RecordType::AAAA), &view),
            Decided::Reply(_)
        ));
    }

    #[test]
    fn zone_names_are_the_daemon_s_to_answer_when_the_policy_admits_them() {
        let open = compiled(BoxPolicy::default());
        assert!(matches!(
            decide(&query("peer.min.internal", RecordType::A), &view(&open)),
            Decided::Zone { .. }
        ));
        let listed = by_name(&["peer.min.internal"]);
        assert!(matches!(
            decide(&query("peer.min.internal", RecordType::A), &view(&listed)),
            Decided::Zone { .. }
        ));
        assert!(matches!(
            decide(&query("other.min.internal", RecordType::A), &view(&listed)),
            Decided::Refused { .. }
        ));
        // A name that only ends like the zone is not in it.
        assert!(matches!(
            decide(&query("notmin.internal", RecordType::A), &view(&open)),
            Decided::Forward { .. }
        ));
    }

    #[test]
    fn a_query_with_more_than_one_question_is_refused_and_never_forwarded() {
        let policy = by_name(&["example.com"]);
        let mut two = Message::query();
        two.metadata.id = 7;
        two.add_query(Query::query(name("example.com"), RecordType::A));
        two.add_query(Query::query(
            name("secret-data.exfil.test"),
            RecordType::TXT,
        ));
        match decide(&two.to_vec().expect("encode"), &view(&policy)) {
            Decided::Reply(reply) => assert_eq!(rcode(&reply), ResponseCode::FormErr),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_upstream_query_carries_the_checked_question_and_nothing_else_of_the_box() {
        use hickory_proto::op::Edns;
        use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

        let policy = by_name(&["example.com"]);
        let mut theirs = Message::query();
        theirs.metadata.id = 0x4242;
        theirs.metadata.recursion_desired = true;
        theirs.add_query(Query::query(name("example.com"), RecordType::A));
        // What a box could smuggle out beside the question: an extra
        // record, and an EDNS option with bytes of its choosing.
        theirs.add_additional(Record::from_rdata(
            name("secret-data.exfil.test"),
            1,
            RData::A(A("192.0.2.1".parse().expect("v4"))),
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(65_000);
        edns.set_dnssec_ok(true);
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Padding),
            b"secret-data".to_vec(),
        ));
        theirs.set_edns(edns);

        let Decided::Forward { name: asked, query } =
            decide(&theirs.to_vec().expect("encode"), &view(&policy))
        else {
            panic!("a listed name is forwarded");
        };
        assert_eq!(asked, "example.com");
        assert!(
            !query.windows(6).any(|w| w == b"secret"),
            "bytes of the box beyond its question went upstream"
        );
        let ours = Message::from_vec(&query).expect("decode");
        assert_eq!(ours.metadata.id, 0x4242);
        assert!(ours.metadata.recursion_desired);
        assert_eq!(ours.queries.len(), 1);
        assert!(ours.answers.is_empty() && ours.additionals.is_empty());
        let edns = ours.edns.expect("the resolver's own EDNS record");
        assert!(edns.flags().dnssec_ok);
        assert_eq!(usize::from(edns.max_payload()), MAX_DATAGRAM);
        assert!(edns.options().as_ref().is_empty());

        // A box that sent no EDNS record gets a query without one.
        let Decided::Forward { query, .. } = decide(
            &super::tests::query("example.com", RecordType::A),
            &view(&policy),
        ) else {
            panic!("a listed name is forwarded");
        };
        assert!(Message::from_vec(&query).expect("decode").edns.is_none());
    }

    #[test]
    fn a_zone_name_opens_no_more_than_an_upstream_name_would() {
        let listed = by_name(&["peer.min.internal"]);
        let loopback = ZoneAnswer::Address(Ipv4Addr::new(127, 0, 64, 9));
        // An internal address is told and pinned only inside a prefix the
        // box allows. Otherwise the box learns the name exists and gets no
        // address, which is also what it is refused.
        let closed = admit_zone(loopback, "peer.min.internal", &view(&listed));
        assert_eq!(closed.answer, ZoneAnswer::NoData);
        assert_eq!(closed.pin, None);
        assert_eq!(closed.refused, Some("127.0.64.9".parse().expect("address")));

        let allowed = ["127.0.64.0/24".parse().expect("prefix")];
        let mut open = view(&listed);
        open.allowed = &allowed;
        let admitted = admit_zone(loopback, "peer.min.internal", &open);
        assert_eq!(admitted.answer, loopback);
        assert_eq!(admitted.pin, Some("127.0.64.9".parse().expect("address")));
        // A box that allows everything pins nothing and is told the answer.
        let everything = compiled(BoxPolicy::default());
        let told = admit_zone(loopback, "peer.min.internal", &view(&everything));
        assert_eq!(
            (told.answer, told.pin, told.refused),
            (loopback, None, None)
        );
    }

    #[test]
    fn the_host_s_name_has_no_address_for_a_box() {
        struct Empty;
        impl answerer::Zone for Empty {
            fn zone_entry(&self, _host: &str, _node: &[Ipv4Addr]) -> ZoneEntry {
                ZoneEntry::Absent
            }
        }
        let zone = Zone::new(Arc::new(Empty));
        assert_eq!(zone.lookup("host.min.internal"), ZoneAnswer::NoData);
        assert_eq!(zone.lookup("nobody.min.internal"), ZoneAnswer::NoSuchName);
    }

    #[test]
    fn zone_replies_follow_what_the_zone_holds() {
        let question =
            Message::from_vec(&query("peer.min.internal", RecordType::A)).expect("decode");
        let held = zone_reply(&question, ZoneAnswer::Address(Ipv4Addr::new(127, 0, 64, 9)))
            .expect("reply");
        assert_eq!(
            addresses(&held),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 64, 9))]
        );
        let gone = zone_reply(&question, ZoneAnswer::NoSuchName).expect("reply");
        assert_eq!(rcode(&gone), ResponseCode::NXDomain);
        assert_eq!(
            Message::from_vec(&gone).expect("decode").authorities.len(),
            1
        );
        // Another record type of a held name: the name exists, no data.
        let other =
            Message::from_vec(&query("peer.min.internal", RecordType::AAAA)).expect("decode");
        let nodata = zone_reply(&other, ZoneAnswer::Address(Ipv4Addr::LOCALHOST)).expect("reply");
        assert_eq!(rcode(&nodata), ResponseCode::NoError);
        assert!(addresses(&nodata).is_empty());
    }

    #[test]
    fn malformed_and_unusual_messages_get_no_forwarding() {
        let policy = compiled(BoxPolicy::default());
        let view = view(&policy);
        assert!(matches!(decide(&[0x12, 0x34, 0x01], &view), Decided::Drop));
        // A response sent to the resolver is not a query.
        let response = upstream_reply("example.com", Vec::new());
        assert!(matches!(decide(&response, &view), Decided::Drop));
        let mut no_question = Message::query();
        no_question.metadata.id = 9;
        match decide(&no_question.to_vec().expect("encode"), &view) {
            Decided::Reply(reply) => assert_eq!(rcode(&reply), ResponseCode::FormErr),
            other => panic!("{other:?}"),
        }
        let mut update = Message::query();
        update.metadata.op_code = OpCode::Update;
        update.add_query(Query::query(name("example.com"), RecordType::A));
        match decide(&update.to_vec().expect("encode"), &view) {
            Decided::Reply(reply) => assert_eq!(rcode(&reply), ResponseCode::NotImp),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn addresses_of_a_listed_name_are_pinned_through_its_cname_chain() {
        let policy = by_name(&["api.example.com"]);
        let reply = upstream_reply(
            "api.example.com",
            vec![
                cname("api.example.com", "edge.cdn.example.net"),
                a("edge.cdn.example.net", "198.51.100.7"),
                aaaa("edge.cdn.example.net", "2001:db8::7"),
                // Not reached from the question: no part of the answer.
                a("unrelated.example.net", "198.51.100.99"),
            ],
        );
        let vetted = vet(reply, "api.example.com", &view(&policy));
        assert_eq!(
            vetted.pins,
            vec![
                "198.51.100.7".parse::<IpAddr>().expect("address"),
                "2001:db8::7".parse().expect("address"),
            ]
        );
        assert!(vetted.refused.is_empty());
        assert_eq!(addresses(&vetted.reply).len(), 2);
    }

    #[test]
    fn a_public_name_that_points_inside_is_not_pinned_unless_the_box_allows_the_range() {
        let policy = by_name(&["api.example.com"]);
        let reply = || {
            upstream_reply(
                "api.example.com",
                vec![
                    a("api.example.com", "10.1.2.3"),
                    a("api.example.com", "127.0.0.1"),
                    a("api.example.com", "198.51.100.7"),
                ],
            )
        };
        let vetted = vet(reply(), "api.example.com", &view(&policy));
        assert_eq!(vetted.pins.len(), 1);
        assert_eq!(vetted.refused.len(), 2);
        assert_eq!(
            addresses(&vetted.reply),
            vec!["198.51.100.7".parse::<IpAddr>().expect("address")]
        );

        let allowed = ["10.0.0.0/8".parse().expect("prefix")];
        let mut with_range = view(&policy);
        with_range.allowed = &allowed;
        let vetted = vet(reply(), "api.example.com", &with_range);
        assert_eq!(vetted.pins.len(), 2);
        assert_eq!(
            vetted.refused,
            vec!["127.0.0.1".parse::<IpAddr>().expect("address")]
        );

        // The node's own infrastructure is refused like an internal range.
        let infrastructure = ["198.51.100.0/24".parse().expect("prefix")];
        let mut guarded = view(&policy);
        guarded.infrastructure = &infrastructure;
        assert!(vet(reply(), "api.example.com", &guarded).pins.is_empty());
    }

    #[test]
    fn a_name_no_rule_names_passes_unchanged_and_pins_nothing() {
        let policy = compiled(BoxPolicy::default());
        let reply = upstream_reply("example.com", vec![a("example.com", "10.1.2.3")]);
        let vetted = vet(reply.clone(), "example.com", &view(&policy));
        assert_eq!(vetted.reply, reply);
        assert!(vetted.pins.is_empty() && vetted.refused.is_empty());
    }

    #[test]
    fn a_reply_that_cannot_be_read_pins_nothing_and_is_not_passed_on() {
        let policy = by_name(&["api.example.com"]);
        let vetted = vet(vec![1, 2, 3], "api.example.com", &view(&policy));
        assert_eq!(vetted, Vetted::default());
    }

    #[test]
    fn the_node_s_resolvers_are_read_from_its_configuration() {
        let upstream = Upstream::from_resolv_conf(
            "# comment\nnameserver 127.0.0.53\noptions edns0\nnameserver 2001:db8::53\n\
             nameserver fe80::1%eth0\nsearch example.com\n",
        );
        assert_eq!(
            upstream,
            Upstream::servers(vec![
                "127.0.0.53:53".parse().expect("address"),
                "[2001:db8::53]:53".parse().expect("address"),
            ])
        );
    }

    #[tokio::test]
    async fn a_query_goes_to_the_first_server_that_answers() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let at = server.local_addr().expect("address");
        crate::traced::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = server.recv_from(&mut buf).await {
                let question = Message::from_vec(buf.get(..n).unwrap_or_default()).expect("decode");
                let mut reply = empty(&question, ResponseCode::NoError);
                reply.add_answer(a("example.com", "198.51.100.7"));
                let _sent = server.send_to(&reply.to_vec().expect("encode"), peer).await;
            }
        });
        // The first server is a port nothing listens on.
        let dead = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let dead_at = dead.local_addr().expect("address");
        drop(dead);
        let upstream = Upstream::servers(vec![dead_at, at]);
        let reply = upstream
            .ask(&query("example.com", RecordType::A), Transport::Udp)
            .await
            .expect("an answer");
        assert_eq!(
            addresses(&reply),
            vec!["198.51.100.7".parse::<IpAddr>().expect("address")]
        );
        assert_eq!(
            Upstream::servers(Vec::new())
                .ask(&[0, 1], Transport::Udp)
                .await,
            None
        );
    }
}
