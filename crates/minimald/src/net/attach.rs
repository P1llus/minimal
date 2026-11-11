//! Connecting a box's network namespace to the virtual network.
//!
//! A box with an address of its own has a network namespace with one
//! interface, `eth0`, that carries the box's lease. What is on the other
//! side of `eth0` depends on the node: a guest node hangs the namespace off
//! its bridge with a veth pair.

pub(crate) mod veth;

use std::io;
use std::net::Ipv4Addr;

use futures::future::BoxFuture;
use switch::{MacAddr, SwitchSubnet};

/// A box's place on the virtual network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Place {
    pub(crate) address: Ipv4Addr,
    pub(crate) subnet: SwitchSubnet,
}

impl Place {
    /// The hardware address of the box's interface, which the virtual
    /// network derives from the lease as well.
    pub(crate) fn mac(self) -> [u8; 6] {
        MacAddr::for_switch_ip(self.address).0
    }

    /// What the spawner's link job sets up inside the namespace.
    pub(crate) fn link_spec(self, kind: sandbox::LinkKind) -> sandbox::LinkSpec {
        sandbox::LinkSpec {
            kind,
            mac: self.mac(),
            address: self.address,
            prefix: self.subnet.prefix(),
            gateway: self.subnet.gateway(),
            mtu: switch::DEFAULT_MTU,
        }
    }
}

/// How a box's network namespace reaches the virtual network on this node.
pub(crate) trait Uplink: Send + Sync {
    /// Connects the namespace of `job` at `place`. Inside, the link is
    /// `eth0`, up, with the lease as its address and the gateway as its
    /// default route. The job's program should be held at its start gate
    /// until this returns.
    fn connect<'a>(
        &'a self,
        job: &'a sandbox::Child,
        place: Place,
    ) -> BoxFuture<'a, io::Result<Link>>;
}

/// A connected namespace. Dropping it disconnects.
pub(crate) struct Link {
    /// What ends the connection on this side of the namespace.
    disconnect: Option<Box<dyn FnOnce() + Send>>,
}

impl Link {
    pub(crate) fn new(disconnect: impl FnOnce() + Send + 'static) -> Self {
        Self {
            disconnect: Some(Box::new(disconnect)),
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        if let Some(disconnect) = self.disconnect.take() {
            disconnect();
        }
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_job_gets_the_lease_the_gateway_and_the_derived_address() {
        let place = Place {
            address: Ipv4Addr::new(100, 64, 1, 7),
            subnet: crate::net::DEFAULT_SUBNET,
        };
        let spec = place.link_spec(sandbox::LinkKind::Existing("eth0".into()));
        assert_eq!(spec.mac, [0x52, 0x54, 0x00, 64, 1, 7]);
        assert_eq!(spec.address, place.address);
        assert_eq!(spec.prefix, 16);
        assert_eq!(spec.gateway, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(spec.mtu, 1500);
    }

    #[test]
    fn a_link_disconnects_once_when_it_is_dropped() {
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&count);
        let link = Link::new(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(link);
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
