//! The sockets the daemon serves to one box.
//!
//! A box whose sockets live in the node's network namespace reaches the
//! daemon's services at loopback sockets of its own: a block of ports on
//! two fixed addresses. The base policy lets the box reach its block and
//! no other, and the engine records which box is behind each peer, so an
//! endpoint serves its box and nobody else.

use std::{
    collections::BTreeSet,
    io,
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, UdpSocket,
    },
    sync::Mutex,
};

use netpol::{Endpoint, EndpointIndex, PortRange};

/// The IPv4 address of every box's endpoints. Nothing else listens on it,
/// so closing the port range to boxes there takes nothing from them.
pub(crate) const V4: Ipv4Addr = Ipv4Addr::new(127, 0, 80, 1);
/// IPv6 loopback has one address. The port range on it is closed to boxes.
pub(crate) const V6: Ipv6Addr = Ipv6Addr::LOCALHOST;
/// The ports endpoints are drawn from, below the range the kernel picks
/// outgoing ports from.
const FIRST_PORT: u16 = 20480;
const LAST_PORT: u16 = 24575;
/// Ports per box: one per service.
const BLOCK: u16 = 4;
const BLOCKS: u16 = (LAST_PORT - FIRST_PORT + 1) / BLOCK;

/// The services a box can have an endpoint for, by their place in the
/// box's block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Service {
    Resolver,
    HostnameProxy,
    HostRelay,
}

impl Service {
    const fn offset(self) -> u16 {
        match self {
            Self::Resolver => 0,
            Self::HostnameProxy => 1,
            Self::HostRelay => 3,
        }
    }

    /// The endpoint index the base policy and the engine know it by.
    pub(crate) const fn index(self) -> EndpointIndex {
        match self {
            Self::Resolver => netpol::base::RESOLVER,
            Self::HostnameProxy => netpol::base::HOSTNAME_PROXY,
            Self::HostRelay => netpol::base::HOST_RELAY,
        }
    }
}

/// The ports of every block, for the base policy.
pub(crate) fn port_range() -> PortRange {
    PortRange::new(FIRST_PORT, LAST_PORT).unwrap_or(PortRange::ALL)
}

/// The ports of the one block a box has in a network namespace of its
/// own, where no other box's endpoints are.
pub(crate) fn own_namespace_ports() -> PortRange {
    PortRange::new(FIRST_PORT, FIRST_PORT + BLOCK - 1).unwrap_or(PortRange::ALL)
}

/// The addresses endpoints sit on.
pub(crate) const fn addresses() -> [IpAddr; 2] {
    [IpAddr::V4(V4), IpAddr::V6(V6)]
}

/// One box's ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block {
    number: u16,
    /// Whether the node has an IPv6 loopback to put the other half on.
    v6: bool,
}

impl Block {
    /// A block that stands in for a box's own where only the shape of its
    /// endpoints matters, not their ports.
    pub(crate) const fn sample() -> Self {
        Self {
            number: 0,
            v6: true,
        }
    }

    /// The block of a box in a network namespace of its own.
    pub(crate) const fn own_namespace(v6: bool) -> Self {
        Self { number: 0, v6 }
    }

    const fn port(self, service: Service) -> u16 {
        FIRST_PORT + self.number * BLOCK + service.offset()
    }

    /// Where the box reaches `service`.
    pub(crate) fn endpoint(self, service: Service) -> Endpoint {
        let port = self.port(service);
        Endpoint {
            v4: Some(SocketAddrV4::new(V4, port)),
            v6: self.v6.then(|| SocketAddrV6::new(V6, port, 0, 0)),
        }
    }
}

/// Which endpoints a box gets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Wants {
    pub(crate) resolver: bool,
    pub(crate) hostname_proxy: bool,
    pub(crate) host_relay: bool,
}

impl Wants {
    pub(crate) const fn any(self) -> bool {
        self.resolver || self.hostname_proxy || self.host_relay
    }
}

/// The bound sockets of one box, not yet served.
#[derive(Debug, Default)]
pub(crate) struct Sockets {
    pub(crate) resolver_udp: Vec<UdpSocket>,
    pub(crate) resolver_tcp: Vec<TcpListener>,
    pub(crate) hostname_proxy: Vec<TcpListener>,
    pub(crate) host_relay: Vec<TcpListener>,
}

/// Makes one unbound socket of a block: of the family asked for (`true`
/// for IPv6), for datagrams (`true`) or streams.
type Unbound<'a> = &'a dyn Fn(bool, bool) -> io::Result<std::os::fd::OwnedFd>;

fn bound(
    socket: std::os::fd::OwnedFd,
    at: SocketAddr,
    listen: bool,
) -> io::Result<std::os::fd::OwnedFd> {
    let socket = socket2::Socket::from(socket);
    socket.set_reuse_address(true)?;
    socket.bind(&at.into())?;
    if listen {
        socket.listen(1024)?;
    }
    Ok(socket.into())
}

/// Binds the endpoints of `block` on sockets `unbound` makes: those of a
/// box in a network namespace of its own, where the daemon cannot bind
/// with sockets of its own.
pub(crate) fn bind_with(block: Block, wants: Wants, unbound: Unbound<'_>) -> io::Result<Sockets> {
    let mut sockets = Sockets::default();
    let mut addrs = vec![IpAddr::V4(V4)];
    if block.v6 {
        addrs.push(IpAddr::V6(V6));
    }
    for addr in addrs {
        let v6 = addr.is_ipv6();
        let stream = |service: Service| -> io::Result<TcpListener> {
            let at = SocketAddr::new(addr, block.port(service));
            Ok(TcpListener::from(bound(unbound(v6, false)?, at, true)?))
        };
        if wants.resolver {
            let at = SocketAddr::new(addr, block.port(Service::Resolver));
            sockets
                .resolver_udp
                .push(UdpSocket::from(bound(unbound(v6, true)?, at, false)?));
            sockets.resolver_tcp.push(stream(Service::Resolver)?);
        }
        if wants.hostname_proxy {
            sockets.hostname_proxy.push(stream(Service::HostnameProxy)?);
        }
        if wants.host_relay {
            sockets.host_relay.push(stream(Service::HostRelay)?);
        }
    }
    Ok(sockets)
}

/// Hands out blocks and binds their sockets.
#[derive(Debug)]
pub(crate) struct Allocator {
    taken: Mutex<Taken>,
    v6: bool,
}

#[derive(Debug, Default)]
struct Taken {
    blocks: BTreeSet<u16>,
    /// Where the next search starts, so a block just given back is not the
    /// first one handed out again.
    next: u16,
}

impl Allocator {
    pub(crate) fn new() -> Self {
        Self {
            taken: Mutex::new(Taken::default()),
            // A node without IPv6 has no `::1` to bind.
            v6: UdpSocket::bind(SocketAddr::new(IpAddr::V6(V6), 0)).is_ok(),
        }
    }

    fn bind(&self, block: Block, wants: Wants) -> io::Result<Sockets> {
        let mut sockets = Sockets::default();
        let mut addrs = vec![IpAddr::V4(V4)];
        if self.v6 {
            addrs.push(IpAddr::V6(V6));
        }
        for addr in addrs {
            if wants.resolver {
                let at = SocketAddr::new(addr, block.port(Service::Resolver));
                sockets.resolver_udp.push(UdpSocket::bind(at)?);
                sockets.resolver_tcp.push(TcpListener::bind(at)?);
            }
            if wants.hostname_proxy {
                let at = SocketAddr::new(addr, block.port(Service::HostnameProxy));
                sockets.hostname_proxy.push(TcpListener::bind(at)?);
            }
            if wants.host_relay {
                let at = SocketAddr::new(addr, block.port(Service::HostRelay));
                sockets.host_relay.push(TcpListener::bind(at)?);
            }
        }
        Ok(sockets)
    }

    /// A free block with its sockets bound. A block whose ports something
    /// else on the node holds is passed over.
    pub(crate) fn take(&self, wants: Wants) -> io::Result<(Block, Sockets)> {
        let mut taken = self.taken.lock().expect("endpoint allocator lock");
        for step in 0..BLOCKS {
            let number = (taken.next + step) % BLOCKS;
            if taken.blocks.contains(&number) {
                continue;
            }
            let block = Block {
                number,
                v6: self.v6,
            };
            match self.bind(block, wants) {
                Ok(sockets) => {
                    taken.blocks.insert(number);
                    taken.next = (number + 1) % BLOCKS;
                    return Ok((block, sockets));
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no free block of service ports between {FIRST_PORT} and {LAST_PORT} on {V4}"),
        ))
    }

    /// Whether the node has an IPv6 loopback, and with it every network
    /// namespace made on it.
    pub(crate) const fn v6(&self) -> bool {
        self.v6
    }

    pub(crate) fn release(&self, block: Block) {
        self.taken
            .lock()
            .expect("endpoint allocator lock")
            .blocks
            .remove(&block.number);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_disjoint_and_inside_the_range() {
        let range = port_range();
        let mut seen = BTreeSet::new();
        for number in [0, 1, BLOCKS - 1] {
            let block = Block { number, v6: true };
            for service in [
                Service::Resolver,
                Service::HostnameProxy,
                Service::HostRelay,
            ] {
                let endpoint = block.endpoint(service);
                let port = endpoint.v4.expect("v4").port();
                assert_eq!(endpoint.v6.expect("v6").port(), port);
                assert!(range.contains(port));
                assert!(seen.insert(port), "port {port} handed out twice");
            }
        }
        assert!(
            Block {
                number: 0,
                v6: false
            }
            .endpoint(Service::Resolver)
            .v6
            .is_none()
        );
    }

    #[test]
    fn a_block_is_bound_when_taken_and_free_again_when_released() {
        let allocator = Allocator::new();
        let wants = Wants {
            resolver: true,
            hostname_proxy: true,
            host_relay: true,
        };
        let (first, sockets) = allocator.take(wants).expect("a block");
        let (second, _other) = allocator.take(wants).expect("another block");
        assert_ne!(first, second);
        let at = sockets
            .resolver_udp
            .first()
            .expect("udp")
            .local_addr()
            .expect("address");
        assert_eq!(
            Some(at),
            first.endpoint(Service::Resolver).v4.map(SocketAddr::V4)
        );
        // The ports are held: nobody else binds them.
        assert!(UdpSocket::bind(at).is_err());
        drop(sockets);
        allocator.release(first);
        assert!(UdpSocket::bind(at).is_ok());
    }
}
