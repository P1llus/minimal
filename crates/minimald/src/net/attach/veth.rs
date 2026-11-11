//! The uplink of a guest node: a veth pair between the node's bridge and
//! the box's namespace.
//!
//! The daemon creates the pair from the node's namespace with the far end
//! already inside the box's, so it never enters that namespace itself. The
//! spawner's link job then gives the far end its address and route.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

use futures::future::BoxFuture;

use super::{Link, Place, Uplink};
use crate::guest_net::BRIDGE;
use crate::net::nl::{Netlink, Veth};

/// The interface a box sees.
const INSIDE: &str = sandbox::spawner::INTERFACE;

/// The name of the node's end of a box's pair. Two boxes never hold one
/// address, and the last two octets tell the addresses of the node's `/16`
/// apart. The longest such name fits an interface name.
fn node_end(address: Ipv4Addr) -> String {
    let [_, _, third, fourth] = address.octets();
    format!("vb{third}_{fourth}")
}

/// Hangs box namespaces off the guest node's bridge.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct VethUplink;

/// Creates the pair, in the node's namespace. Blocks on the kernel.
fn create(netns: &OwnedFd, place: Place) -> io::Result<String> {
    use std::os::fd::AsFd as _;

    let mut netlink = Netlink::open()?;
    let bridge = netlink.link(BRIDGE)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("the node has no bridge ({BRIDGE}) to connect the box to"),
        )
    })?;
    let host = node_end(place.address);
    // A pair of this name is one a box at this address left behind, whose
    // namespace is gone or going.
    if netlink.link(&host)?.is_some() {
        netlink.delete_link(&host)?;
    }
    netlink.add_veth(&Veth {
        host: &host,
        bridge: bridge.index,
        mtu: u32::from(switch::DEFAULT_MTU),
        peer: INSIDE,
        peer_mac: place.mac(),
        peer_netns: netns.as_fd(),
    })?;
    Ok(host)
}

fn delete(host: &str) {
    let deleted = Netlink::open().and_then(|mut netlink| netlink.delete_link(host));
    match deleted {
        Ok(()) => {}
        // The pair went with the box's namespace.
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => {}
        Err(error) => tracing::warn!(interface = host, %error, "a box's veth pair stays behind"),
    }
}

impl Uplink for VethUplink {
    fn connect<'a>(
        &'a self,
        job: &'a sandbox::Child,
        place: Place,
    ) -> BoxFuture<'a, io::Result<Link>> {
        Box::pin(async move {
            let netns = job
                .netns()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the box has no network namespace of its own",
                    )
                })?
                .try_clone_to_owned()?;
            let host = crate::traced::spawn_blocking(move || create(&netns, place))
                .await
                .map_err(io::Error::other)??;
            let node_end = host.clone();
            let link = Link::new(move || delete(&node_end));
            let spec = place.link_spec(sandbox::LinkKind::Existing(INSIDE.to_owned()));
            job.link(spec)?;
            tracing::debug!(interface = %host, address = %place.address, "connected a box to the node's bridge");
            Ok(link)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nodes_end_is_named_by_the_address_and_fits_an_interface_name() {
        assert_eq!(node_end(Ipv4Addr::new(100, 64, 1, 7)), "vb1_7");
        let longest = node_end(Ipv4Addr::new(100, 64, 255, 255));
        assert_eq!(longest, "vb255_255");
        assert!(longest.len() < libc::IFNAMSIZ);
    }
}
