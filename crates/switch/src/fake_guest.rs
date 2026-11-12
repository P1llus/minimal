//! A guest made of hand-built frames, for tests that ask what the virtual
//! network answers to a guest that owns its network device.
//!
//! It connects to gvproxy's `-listen` socket the way the frame pump does and
//! writes Ethernet frames itself. No kernel stack sits between the test and
//! the switch, so a test can send what no well-behaved guest would: a packet
//! for an address nothing answers ARP for, addressed to the gateway's MAC.

use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{GATEWAY_MAC, MacAddr};

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
/// The SYN and ACK bits of a TCP header's flags.
pub const TCP_SYN_ACK: u8 = 0x12;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
/// The sequence number of the guest's SYN.
const FIRST_SEQ: u32 = 1000;
/// The source port of everything the guest sends.
const SOURCE_PORT: u16 = 40_000;

/// One frame the switch sent to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// An ARP reply that says who has `owner`.
    ArpReply { owner: Ipv4Addr },
    /// A TCP segment.
    Tcp {
        from: SocketAddrV4,
        flags: u8,
        seq: u32,
        payload: Vec<u8>,
    },
    /// A UDP datagram.
    Udp {
        from: SocketAddrV4,
        payload: Vec<u8>,
    },
    /// An ICMP message.
    Icmp { from: Ipv4Addr, kind: u8, code: u8 },
}

/// A guest attached to a gvproxy switch.
#[derive(Debug)]
pub struct FakeGuest {
    stream: UnixStream,
    mac: MacAddr,
    address: Ipv4Addr,
    unread: Vec<u8>,
}

impl FakeGuest {
    /// Attaches a guest with `address` to the switch at `socket` and waits
    /// until the gateway at `gateway` answers its ARP request, which shows
    /// that the switch carries the guest's frames in both directions.
    ///
    /// # Errors
    ///
    /// The socket's I/O error, or `TimedOut` when the gateway stays silent.
    pub fn attach(socket: &Path, address: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<Self> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(crate::pump::CONNECT_REQUEST)?;
        let mut guest = Self {
            stream,
            mac: MacAddr::for_switch_ip(address),
            address,
            unread: Vec::new(),
        };
        // gvproxy takes the connection over some time after the request, and
        // drops what arrived before that. Ask until it answers.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            guest.arp_request(gateway)?;
            let seen = guest.listen(Duration::from_millis(200))?;
            if seen.contains(&Seen::ArpReply { owner: gateway }) {
                return Ok(guest);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the gateway {gateway} answered no ARP request"),
        ))
    }

    /// Asks the whole network who has `target`.
    ///
    /// # Errors
    ///
    /// The socket's I/O error.
    pub fn arp_request(&mut self, target: Ipv4Addr) -> io::Result<()> {
        let frame = self.arp(ARP_REQUEST, MacAddr([0xff; 6]), MacAddr([0; 6]), target);
        self.send(&frame)
    }

    /// Sends a TCP SYN for `to`, in a frame addressed to the gateway.
    ///
    /// # Errors
    ///
    /// The socket's I/O error.
    pub fn tcp_syn(&mut self, to: SocketAddrV4) -> io::Result<()> {
        self.tcp(to, TCP_SYN, FIRST_SEQ, 0, &[])
    }

    /// Opens a TCP connection to `to`, sends `request` and returns what
    /// the other side sent back within `time`. Enough of TCP for one
    /// request that fits a segment and a reply read in order. An empty
    /// result means the connection did not open or nothing came back.
    ///
    /// # Errors
    ///
    /// The socket's I/O error.
    pub fn tcp_request(
        &mut self,
        to: SocketAddrV4,
        request: &[u8],
        time: Duration,
    ) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + time;
        self.tcp_syn(to)?;
        let mut their_seq = None;
        while their_seq.is_none() && Instant::now() < deadline {
            their_seq = self
                .listen(Duration::from_millis(100))?
                .into_iter()
                .find_map(|seen| match seen {
                    Seen::Tcp {
                        from, flags, seq, ..
                    } if from == to && flags == TCP_SYN_ACK => Some(seq),
                    _ => None,
                });
        }
        let Some(their_seq) = their_seq else {
            return Ok(Vec::new());
        };
        let mut expected = their_seq.wrapping_add(1);
        let sent = FIRST_SEQ.wrapping_add(1);
        self.tcp(to, TCP_ACK | TCP_PSH, sent, expected, request)?;
        let after = sent.wrapping_add(request.len() as u32);
        let mut reply = Vec::new();
        while Instant::now() < deadline {
            for seen in self.listen(Duration::from_millis(100))? {
                let Seen::Tcp {
                    from,
                    flags,
                    seq,
                    payload,
                } = seen
                else {
                    continue;
                };
                if from != to || seq != expected {
                    continue;
                }
                expected = expected.wrapping_add(payload.len() as u32);
                reply.extend_from_slice(&payload);
                if flags & TCP_FIN != 0 {
                    self.tcp(to, TCP_ACK | TCP_RST, after, expected.wrapping_add(1), &[])?;
                    return Ok(reply);
                }
                self.tcp(to, TCP_ACK, after, expected, &[])?;
            }
        }
        Ok(reply)
    }

    fn tcp(
        &mut self,
        to: SocketAddrV4,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        let mut segment = Vec::with_capacity(20 + payload.len());
        segment.extend_from_slice(&SOURCE_PORT.to_be_bytes());
        segment.extend_from_slice(&to.port().to_be_bytes());
        segment.extend_from_slice(&seq.to_be_bytes());
        segment.extend_from_slice(&ack.to_be_bytes());
        segment.extend_from_slice(&[5 << 4, flags]);
        segment.extend_from_slice(&u16::MAX.to_be_bytes());
        segment.extend_from_slice(&[0, 0, 0, 0]);
        segment.extend_from_slice(payload);
        let sum = self.transport_checksum(*to.ip(), PROTO_TCP, &segment);
        segment[16..18].copy_from_slice(&sum.to_be_bytes());
        let frame = self.ipv4(*to.ip(), PROTO_TCP, &segment);
        self.send(&frame)
    }

    /// Sends a UDP datagram to `to`, in a frame addressed to the gateway.
    ///
    /// # Errors
    ///
    /// The socket's I/O error.
    pub fn udp(&mut self, to: SocketAddrV4, payload: &[u8]) -> io::Result<()> {
        let length = u16::try_from(8 + payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too long"))?;
        let mut datagram = Vec::with_capacity(usize::from(length));
        datagram.extend_from_slice(&SOURCE_PORT.to_be_bytes());
        datagram.extend_from_slice(&to.port().to_be_bytes());
        datagram.extend_from_slice(&length.to_be_bytes());
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(payload);
        let sum = match self.transport_checksum(*to.ip(), PROTO_UDP, &datagram) {
            // Zero on the wire means "no checksum".
            0 => u16::MAX,
            sum => sum,
        };
        datagram[6..8].copy_from_slice(&sum.to_be_bytes());
        let frame = self.ipv4(*to.ip(), PROTO_UDP, &datagram);
        self.send(&frame)
    }

    /// Collects what the switch sends for `time`. ARP requests for the
    /// guest's own address are answered meanwhile, so a reply the switch
    /// routes to the guest can arrive.
    ///
    /// # Errors
    ///
    /// The socket's I/O error. The switch closing the connection is
    /// `UnexpectedEof`.
    pub fn listen(&mut self, time: Duration) -> io::Result<Vec<Seen>> {
        let deadline = Instant::now() + time;
        let mut seen = Vec::new();
        loop {
            while let Some(frame) = self.next_frame() {
                if let Some(asker) = self.asks_for_me(&frame) {
                    let reply = self.arp(ARP_REPLY, asker.0, asker.0, asker.1);
                    self.send(&reply)?;
                } else if let Some(parsed) = parse(&frame) {
                    seen.push(parsed);
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(seen);
            }
            self.stream.set_read_timeout(Some(left))?;
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.unread.extend_from_slice(&chunk[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let length = u16::try_from(frame.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too long"))?;
        let mut out = Vec::with_capacity(2 + frame.len());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(frame);
        self.stream.write_all(&out)
    }

    fn next_frame(&mut self) -> Option<Vec<u8>> {
        let head: [u8; 2] = self.unread.get(..2)?.try_into().ok()?;
        let end = 2 + usize::from(u16::from_le_bytes(head));
        let frame = self.unread.get(2..end)?.to_vec();
        self.unread.drain(..end);
        Some(frame)
    }

    /// The MAC and address of whoever asks for the guest's address in
    /// `frame`.
    fn asks_for_me(&self, frame: &[u8]) -> Option<(MacAddr, Ipv4Addr)> {
        let arp = frame
            .get(14..42)
            .filter(|_| frame.get(12..14) == Some(&ETHERTYPE_ARP))?;
        let asked_for = Ipv4Addr::from(<[u8; 4]>::try_from(&arp[24..28]).ok()?);
        (arp[6..8] == ARP_REQUEST.to_be_bytes() && asked_for == self.address).then(|| {
            let mac: [u8; 6] = arp[8..14].try_into().unwrap_or_default();
            let address: [u8; 4] = arp[14..18].try_into().unwrap_or_default();
            (MacAddr(mac), Ipv4Addr::from(address))
        })
    }

    fn arp(&self, op: u16, to: MacAddr, target_mac: MacAddr, target: Ipv4Addr) -> Vec<u8> {
        let mut frame = Vec::with_capacity(42);
        frame.extend_from_slice(&to.0);
        frame.extend_from_slice(&self.mac.0);
        frame.extend_from_slice(&ETHERTYPE_ARP);
        // Ethernet, IPv4, 6-byte and 4-byte addresses.
        frame.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
        frame.extend_from_slice(&op.to_be_bytes());
        frame.extend_from_slice(&self.mac.0);
        frame.extend_from_slice(&self.address.octets());
        frame.extend_from_slice(&target_mac.0);
        frame.extend_from_slice(&target.octets());
        frame
    }

    fn ipv4(&self, to: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX);
        let mut header = Vec::with_capacity(20);
        header.extend_from_slice(&[0x45, 0]);
        header.extend_from_slice(&total.to_be_bytes());
        header.extend_from_slice(&[0, 1, 0, 0, 64, protocol, 0, 0]);
        header.extend_from_slice(&self.address.octets());
        header.extend_from_slice(&to.octets());
        let sum = checksum(&[&header]);
        header[10..12].copy_from_slice(&sum.to_be_bytes());

        let mut frame = Vec::with_capacity(14 + 20 + payload.len());
        frame.extend_from_slice(&GATEWAY_MAC.0);
        frame.extend_from_slice(&self.mac.0);
        frame.extend_from_slice(&ETHERTYPE_IPV4);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(payload);
        frame
    }

    fn transport_checksum(&self, to: Ipv4Addr, protocol: u8, segment: &[u8]) -> u16 {
        let length = u16::try_from(segment.len()).unwrap_or(u16::MAX);
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&self.address.octets());
        pseudo.extend_from_slice(&to.octets());
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(&length.to_be_bytes());
        checksum(&[&pseudo, segment])
    }
}

/// The internet checksum over `parts`, each of even length but the last.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for pair in part.chunks(2) {
            let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
            sum += u32::from(word);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn parse(frame: &[u8]) -> Option<Seen> {
    let ethertype = frame.get(12..14)?;
    if ethertype == ETHERTYPE_ARP {
        let arp = frame.get(14..42)?;
        let owner: [u8; 4] = arp[14..18].try_into().ok()?;
        return (arp[6..8] == ARP_REPLY.to_be_bytes()).then(|| Seen::ArpReply {
            owner: Ipv4Addr::from(owner),
        });
    }
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let packet = frame.get(14..)?;
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    let from = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
    let transport = packet.get(header_len..)?;
    let port = || {
        Some(u16::from_be_bytes([
            *transport.first()?,
            *transport.get(1)?,
        ]))
    };
    match *packet.get(9)? {
        PROTO_TCP => {
            let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
            let data_at = usize::from(transport.get(12)? >> 4) * 4;
            Some(Seen::Tcp {
                from: SocketAddrV4::new(from, port()?),
                flags: *transport.get(13)?,
                seq: u32::from_be_bytes(transport.get(4..8)?.try_into().ok()?),
                // Without the padding a short frame carries.
                payload: packet.get(header_len + data_at..total)?.to_vec(),
            })
        }
        PROTO_UDP => Some(Seen::Udp {
            from: SocketAddrV4::new(from, port()?),
            payload: transport.get(8..)?.to_vec(),
        }),
        PROTO_ICMP => Some(Seen::Icmp {
            from,
            kind: *transport.first()?,
            code: *transport.get(1)?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksum_of_a_header_that_carries_its_checksum_is_zero() {
        let (ours, _theirs) = UnixStream::pair().expect("socket pair");
        let guest = FakeGuest {
            stream: ours,
            mac: MacAddr([2, 0, 0, 0, 0, 1]),
            address: Ipv4Addr::new(100, 64, 0, 9),
            unread: Vec::new(),
        };
        let frame = guest.ipv4(Ipv4Addr::new(100, 64, 0, 1), PROTO_UDP, b"12345678");
        assert_eq!(checksum(&[&frame[14..34]]), 0);
    }

    #[test]
    fn frames_arrive_whole_and_arp_for_the_guest_is_answered() {
        let (ours, mut switch) = UnixStream::pair().expect("socket pair");
        let address = Ipv4Addr::new(100, 64, 0, 9);
        let mut guest = FakeGuest {
            stream: ours,
            mac: MacAddr::for_switch_ip(address),
            address,
            unread: Vec::new(),
        };
        // What the gateway would send: who has the guest's address?
        let gateway = FakeGuest {
            stream: UnixStream::pair().expect("socket pair").0,
            mac: GATEWAY_MAC,
            address: Ipv4Addr::new(100, 64, 0, 1),
            unread: Vec::new(),
        };
        let ask = gateway.arp(ARP_REQUEST, MacAddr([0xff; 6]), MacAddr([0; 6]), address);
        let mut wire = Vec::new();
        wire.extend_from_slice(&(ask.len() as u16).to_le_bytes());
        wire.extend_from_slice(&ask);
        // Split in the middle of the frame.
        switch.write_all(&wire[..10]).expect("write");
        switch.write_all(&wire[10..]).expect("write");

        let seen = guest.listen(Duration::from_millis(200)).expect("listen");
        assert_eq!(seen, Vec::new(), "a request is answered, not reported");

        let mut head = [0u8; 2];
        switch.read_exact(&mut head).expect("the reply's length");
        let mut reply = vec![0u8; usize::from(u16::from_le_bytes(head))];
        switch.read_exact(&mut reply).expect("the reply");
        assert_eq!(
            parse(&reply),
            Some(Seen::ArpReply { owner: address }),
            "{reply:?}"
        );
        assert_eq!(&reply[..6], &GATEWAY_MAC.0, "sent to the asker");
    }
}
