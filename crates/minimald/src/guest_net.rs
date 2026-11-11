//! The network of a guest node.
//!
//! The VM has one network device, `eth0`, which leads to the virtual
//! network the VM host runs. The guest daemon puts a bridge over it and
//! takes the node's address on the bridge. A box with an address of its
//! own becomes another port of the bridge.
//!
//! The daemon wires this once at boot, before it serves its first request,
//! so no launch can run before the result is known. A guest whose wiring
//! failed starts no box that asks for a network.

use std::io;
use std::sync::OnceLock;

use switch::SwitchSubnet;

use crate::net::nl::Netlink;

/// The VM's network device.
pub(crate) const UPLINK: &str = "eth0";
/// The bridge the node and its boxes share.
pub(crate) const BRIDGE: &str = "br0";

/// Why the guest has no network.
#[derive(Debug)]
pub enum Unwired {
    /// The VM was started without a network device.
    NoDevice,
    Failed {
        doing: &'static str,
        error: io::Error,
    },
}

impl std::fmt::Display for Unwired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDevice => write!(f, "the VM has no network device ({UPLINK})"),
            Self::Failed { doing, error } => write!(f, "{doing} failed: {error}"),
        }
    }
}

impl std::error::Error for Unwired {}

fn doing<T>(doing: &'static str, result: io::Result<T>) -> Result<T, Unwired> {
    result.map_err(|error| Unwired::Failed { doing, error })
}

/// Brings `lo` up. The kernel leaves it down, and the daemon's own
/// listeners bind on it.
///
/// # Errors
///
/// The netlink error.
pub fn loopback_up() -> io::Result<()> {
    let mut netlink = Netlink::open()?;
    let lo = netlink
        .link("lo")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no loopback interface"))?;
    netlink.set_up(lo.index)
}

/// Stops the kernel from passing bridged frames through the packet filter
/// tables, where the kernel has that feature. Nothing here writes such
/// tables, and a frame between two boxes is no business of the node's.
fn bridge_frames_skip_packet_filters() -> io::Result<()> {
    for table in ["iptables", "arptables"] {
        let setting = format!("/proc/sys/net/bridge/bridge-nf-call-{table}");
        match std::fs::write(&setting, "0") {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Builds the bridge over the VM's device and gives the node its address
/// and default route on `subnet`.
fn bridge(netlink: &mut Netlink, subnet: SwitchSubnet) -> Result<(), Unwired> {
    let mtu = u32::from(switch::DEFAULT_MTU);
    let uplink =
        doing("reading the VM's network device", netlink.link(UPLINK))?.ok_or(Unwired::NoDevice)?;
    let Some(mac) = uplink.mac else {
        return Err(Unwired::Failed {
            doing: "reading the VM's network device",
            error: io::Error::new(io::ErrorKind::InvalidData, "it has no hardware address"),
        });
    };
    // The bridge takes the device's address: it is the one the virtual
    // network knows the node by.
    doing("creating the bridge", netlink.add_bridge(BRIDGE, mac, mtu))?;
    let bridge = doing("reading the bridge", netlink.link(BRIDGE))?
        .ok_or_else(|| Unwired::Failed {
            doing: "reading the bridge",
            error: io::Error::new(io::ErrorKind::NotFound, "it is gone"),
        })?
        .index;
    doing(
        "putting the VM's network device on the bridge",
        netlink.enslave(uplink.index, bridge, mtu),
    )?;
    doing(
        "setting up the bridge's port to the virtual network",
        netlink.quiet_port(uplink.index),
    )?;
    doing(
        "bringing the VM's network device up",
        netlink.set_up(uplink.index),
    )?;
    // The port learns nothing, so the one address behind it is set here.
    doing(
        "telling the bridge where the gateway is",
        netlink.add_forwarding_entry(uplink.index, switch::GATEWAY_MAC.0),
    )?;
    doing(
        "setting the node's address",
        netlink.add_address(bridge, subnet.daemon_ip(), subnet.prefix()),
    )?;
    doing("bringing the bridge up", netlink.set_up(bridge))?;
    doing(
        "setting the default route",
        netlink.add_default_route(subnet.gateway(), bridge),
    )
}

/// Makes `/etc/resolv.conf` name `nameserver`. The rootfs is read-only, so
/// the file lives on `/run` and is bound over the path.
fn install_resolv_conf(nameserver: std::net::Ipv4Addr) -> io::Result<()> {
    std::fs::write("/run/resolv.conf", format!("nameserver {nameserver}\n"))?;
    // SAFETY: a bind mount of one constant path over another.
    let mounted = unsafe {
        libc::mount(
            c"/run/resolv.conf".as_ptr(),
            c"/etc/resolv.conf".as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if mounted != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wire(subnet: SwitchSubnet) -> Result<(), Unwired> {
    doing(
        "turning packet filtering of bridged frames off",
        bridge_frames_skip_packet_filters(),
    )?;
    let mut netlink = doing("opening a netlink socket", Netlink::open())?;
    bridge(&mut netlink, subnet)?;
    doing(
        "writing the node's resolv.conf",
        install_resolv_conf(subnet.dns_server()),
    )
}

/// The result of the wiring, set once at boot. Unset outside a guest.
static WIRING: OnceLock<Result<(), String>> = OnceLock::new();

/// Wires the guest node's network and keeps the result for every launch.
/// Call once, before the daemon serves a request.
pub fn wire_at_boot(subnet: SwitchSubnet) {
    let result = wire(subnet);
    match &result {
        Ok(()) => tracing::info!(
            address = %subnet.daemon_ip(),
            prefix = subnet.prefix(),
            gateway = %subnet.gateway(),
            "the guest node's network is up"
        ),
        Err(why) => tracing::error!(
            "the guest node has no network: {why}. Boxes that ask for a network are refused."
        ),
    }
    if WIRING.set(result.map_err(|why| why.to_string())).is_err() {
        tracing::warn!("the guest node's network was wired twice");
    }
}

/// Why a box that asks for a network cannot have one on this node. `None`
/// on a node whose network is up, and on a native node, which wires none.
pub(crate) fn missing() -> Option<&'static str> {
    match WIRING.get() {
        Some(Err(why)) => Some(why),
        Some(Ok(())) | None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSIDE: &str = "guest_net::tests::inside_a_namespace_of_its_own";
    const INSIDE_ENV: &str = "MINIMALD_GUEST_NET_TEST_INSIDE";

    /// Wires a node in a user and network namespace of its own, where this
    /// test is root and one end of a veth pair stands in for the VM's
    /// device.
    #[test]
    fn a_node_is_wired_over_its_one_device() {
        let exe = std::env::current_exe().unwrap();
        let ran = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "--"])
            .arg(exe)
            .args(["--exact", INSIDE, "--ignored", "--nocapture"])
            .env(INSIDE_ENV, "1")
            .output();
        let output = match ran {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skipped: unshare does not run: {error}");
                return;
            }
        };
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if said.contains("unshare: ") && !said.contains("running 1 test") {
            eprintln!("skipped: no user namespace with a network of its own: {said}");
            return;
        }
        assert!(output.status.success(), "{said}");
        assert!(said.contains("1 passed"), "{said}");
    }

    fn json(arguments: &[&str]) -> serde_json_lenient::Value {
        let output = std::process::Command::new(arguments[0])
            .args(&arguments[1..])
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}");
        serde_json_lenient::from_slice(&output.stdout).unwrap()
    }

    #[test]
    #[ignore = "runs inside the namespaces `a_node_is_wired_over_its_one_device` makes"]
    fn inside_a_namespace_of_its_own() {
        if std::env::var_os(INSIDE_ENV).is_none() {
            return;
        }
        let subnet = crate::net::DEFAULT_SUBNET;
        let mut netlink = Netlink::open().unwrap();
        // A VM that was started without a device.
        let none = bridge(&mut netlink, subnet).unwrap_err();
        assert!(matches!(none, Unwired::NoDevice), "{none}");
        assert_eq!(netlink.link(BRIDGE).unwrap(), None);

        let made = std::process::Command::new("ip")
            .args(["link", "add", UPLINK, "address", "5a:94:ef:00:00:02"])
            .args(["type", "veth", "peer", "name", "up0"])
            .status()
            .unwrap();
        assert!(made.success());
        loopback_up().unwrap();
        bridge(&mut netlink, subnet).unwrap();

        assert!(netlink.link("lo").unwrap().unwrap().up);
        let node = netlink.link(BRIDGE).unwrap().expect("the bridge");
        assert!(node.up);
        assert_eq!(node.mac, Some([0x5a, 0x94, 0xef, 0x00, 0x00, 0x02]));
        let uplink = netlink.link(UPLINK).unwrap().unwrap();
        assert!(uplink.up);
        assert_eq!(uplink.bridge, Some(node.index));

        let addresses = json(&["ip", "-json", "address", "show", "dev", BRIDGE]);
        let address = &addresses[0]["addr_info"][0];
        assert_eq!(address["local"], subnet.daemon_ip().to_string());
        assert_eq!(address["prefixlen"], subnet.prefix());
        let routes = json(&["ip", "-json", "route", "show", "default"]);
        assert_eq!(routes[0]["gateway"], subnet.gateway().to_string());
        assert_eq!(routes[0]["dev"], BRIDGE);
        let entries = json(&["bridge", "-json", "fdb", "show", "dev", UPLINK]);
        let gateway = switch::GATEWAY_MAC
            .0
            .map(|byte| format!("{byte:02x}"))
            .join(":");
        assert!(
            entries
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["mac"] == gateway.as_str() && entry["state"] == "static"),
            "{entries}"
        );

        // A second wiring finds the bridge and says so.
        let again = bridge(&mut netlink, subnet).unwrap_err();
        assert!(
            matches!(&again, Unwired::Failed { doing: "creating the bridge", error }
                if error.kind() == io::ErrorKind::AlreadyExists),
            "{again}"
        );
    }
}
