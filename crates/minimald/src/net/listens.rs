//! The listening TCP sockets of boxes, as the engine records them.
//!
//! The engine keeps the listening sockets of every box in a map and reports
//! when one starts or stops. The watchers that publish a box's ports read
//! the map through [`Listeners`]: after a report, and every few seconds
//! besides, so a report that was lost costs a delay and no port.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use futures::future::BoxFuture;

/// A listening TCP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Listener {
    /// The address the socket is bound to.
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
}

/// The listening sockets of one network namespace of one box.
pub(crate) trait Listeners: Send + Sync {
    /// The sockets that listen now.
    fn listening(&self) -> io::Result<Vec<Listener>>;

    /// Resolves when a socket of the box has started to listen since the
    /// last call resolved.
    fn changed(&self) -> BoxFuture<'_, ()>;
}

/// The ports among `listening` that a connection from outside the
/// namespace can reach: those of sockets bound to every address or to
/// `address`, the namespace's own. A socket bound to the loopback takes
/// nothing from outside.
pub(crate) fn reachable_ports(
    listening: &[Listener],
    address: std::net::Ipv4Addr,
) -> std::collections::HashSet<u16> {
    listening
        .iter()
        .filter(|listener| {
            listener.address.is_unspecified() || listener.address == IpAddr::V4(address)
        })
        .map(|listener| listener.port)
        .collect()
}

/// The listening sockets of one namespace of a box, read from the
/// engine's table.
pub(crate) struct EngineListeners {
    pub(crate) table: boxbpf::Listens,
    pub(crate) of: boxbpf::BoxId,
    pub(crate) netns: u64,
    /// Notified when the engine reports that a socket of the box started
    /// or stopped listening.
    pub(crate) wake: Arc<tokio::sync::Notify>,
}

impl Listeners for EngineListeners {
    fn listening(&self) -> io::Result<Vec<Listener>> {
        let listening = self
            .table
            .listening(self.of, self.netns)
            .map_err(io::Error::other)?;
        Ok(listening
            .into_iter()
            .map(|socket| Listener {
                address: socket.address,
                port: socket.port,
            })
            .collect())
    }

    fn changed(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.wake.notified())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_is_reachable_when_its_socket_takes_connections_from_outside() {
        let at = |address: &str, port| Listener {
            address: address.parse().expect("address"),
            port,
        };
        let own = "100.64.1.7".parse().expect("address");
        let listening = [
            at("0.0.0.0", 3000),
            at("100.64.1.7", 3001),
            at("127.0.0.1", 3002),
            at("100.64.1.8", 3003),
            at("::", 3004),
        ];
        let mut reachable: Vec<u16> = reachable_ports(&listening, own).into_iter().collect();
        reachable.sort_unstable();
        assert_eq!(reachable, [3000, 3001, 3004]);
    }
}
