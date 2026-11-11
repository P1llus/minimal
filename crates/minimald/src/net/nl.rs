//! The route netlink calls of the guest daemon.
//!
//! The guest's node is a bridge over the VM's one network device, and each
//! box with an address of its own hangs off the bridge by a veth pair. This
//! module holds the requests that build that, and nothing that decides
//! when to make them. Every call is one request and its acknowledgement on
//! a socket in the network namespace of the thread that opened it.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd as _, BorrowedFd};

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::{AddressAttribute, AddressMessage},
    link::{
        BridgeStpState, InfoBridge, InfoBridgePort, InfoData, InfoKind, InfoPortData, InfoPortKind,
        InfoVeth, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
    },
    neighbour::{NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState},
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

/// A network interface, as far as the guest's wiring reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    pub(crate) index: u32,
    pub(crate) mac: Option<[u8; 6]>,
    pub(crate) mtu: Option<u32>,
    pub(crate) up: bool,
    /// The bridge the interface is a port of.
    pub(crate) bridge: Option<u32>,
}

/// A veth pair whose one end is a port of the node's bridge and whose
/// other end is created inside a box's network namespace.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Veth<'a> {
    /// The name of the end that stays in the node's namespace.
    pub(crate) host: &'a str,
    pub(crate) bridge: u32,
    pub(crate) mtu: u32,
    /// The name of the end in the box's namespace.
    pub(crate) peer: &'a str,
    pub(crate) peer_mac: [u8; 6],
    pub(crate) peer_netns: BorrowedFd<'a>,
}

/// One request: what to send and the flags beside `NLM_F_REQUEST`.
struct Request {
    message: RouteNetlinkMessage,
    flags: u16,
}

const ACK: u16 = NLM_F_ACK;
const CREATE: u16 = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

fn link_of(index: u32) -> LinkMessage {
    let mut link = LinkMessage::default();
    link.header.index = index;
    link
}

fn get_link(name: &str) -> Request {
    let mut link = LinkMessage::default();
    link.attributes.push(LinkAttribute::IfName(name.to_owned()));
    Request {
        message: RouteNetlinkMessage::GetLink(link),
        flags: 0,
    }
}

/// A bridge that forwards at once and floods as its ports say: no spanning
/// tree, no forwarding delay, no multicast snooping. It carries `mac` so
/// the node keeps the address the virtual network knows it by.
fn add_bridge(name: &str, mac: [u8; 6], mtu: u32) -> Request {
    let mut link = LinkMessage::default();
    link.attributes = vec![
        LinkAttribute::IfName(name.to_owned()),
        LinkAttribute::Address(mac.to_vec()),
        LinkAttribute::Mtu(mtu),
        LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Bridge),
            LinkInfo::Data(InfoData::Bridge(vec![
                InfoBridge::StpState(BridgeStpState::Disabled),
                InfoBridge::ForwardDelay(0),
                InfoBridge::MulticastSnooping(false),
            ])),
        ]),
    ];
    Request {
        message: RouteNetlinkMessage::NewLink(link),
        flags: CREATE,
    }
}

fn enslave(link: u32, bridge: u32, mtu: u32) -> Request {
    let mut message = link_of(link);
    message.attributes = vec![LinkAttribute::Mtu(mtu), LinkAttribute::Controller(bridge)];
    Request {
        message: RouteNetlinkMessage::SetLink(message),
        flags: ACK,
    }
}

/// Stops a bridge port from learning addresses and from getting frames
/// flooded to it. The uplink is such a port: what lives behind it is the
/// gateway alone, whose address is set by hand, and a box that forges a
/// source address must not move it.
fn quiet_port(link: u32) -> Request {
    let mut message = link_of(link);
    message.attributes = vec![LinkAttribute::LinkInfo(vec![
        LinkInfo::PortKind(InfoPortKind::Bridge),
        LinkInfo::PortData(InfoPortData::BridgePort(vec![
            InfoBridgePort::Learning(false),
            InfoBridgePort::UnicastFlood(false),
            InfoBridgePort::MulticastFlood(false),
        ])),
    ])];
    Request {
        // Port settings travel in a link's info, which only `RTM_NEWLINK`
        // reads. Without `NLM_F_CREATE` it changes the link that exists.
        message: RouteNetlinkMessage::NewLink(message),
        flags: ACK,
    }
}

fn set_up(link: u32) -> Request {
    let mut message = link_of(link);
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;
    Request {
        message: RouteNetlinkMessage::SetLink(message),
        flags: ACK,
    }
}

/// A forwarding entry of the bridge that `port` belongs to: frames for
/// `mac` leave through `port`, and the entry does not age.
fn add_forwarding_entry(port: u32, mac: [u8; 6]) -> Request {
    let mut message = NeighbourMessage::default();
    message.header.family = AddressFamily::Bridge;
    message.header.ifindex = port;
    message.header.state = NeighbourState::Noarp;
    message.header.flags = NeighbourFlags::Controller;
    message
        .attributes
        .push(NeighbourAttribute::LinkLayerAddress(mac.to_vec()));
    Request {
        message: RouteNetlinkMessage::NewNeighbour(message),
        flags: NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
    }
}

fn add_address(link: u32, address: Ipv4Addr, prefix: u8) -> Request {
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = prefix;
    message.header.index = link;
    let host_bits = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
    let broadcast = Ipv4Addr::from(u32::from(address) | host_bits);
    message.attributes = vec![
        AddressAttribute::Address(IpAddr::V4(address)),
        AddressAttribute::Local(IpAddr::V4(address)),
        AddressAttribute::Broadcast(broadcast),
    ];
    Request {
        message: RouteNetlinkMessage::NewAddress(message),
        flags: CREATE,
    }
}

fn add_default_route(gateway: Ipv4Addr, link: u32) -> Request {
    let mut message = RouteMessage::default();
    message.header.address_family = AddressFamily::Inet;
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.protocol = RouteProtocol::Static;
    message.header.scope = RouteScope::Universe;
    message.header.kind = RouteType::Unicast;
    message.attributes = vec![
        RouteAttribute::Gateway(RouteAddress::Inet(gateway)),
        RouteAttribute::Oif(link),
    ];
    Request {
        message: RouteNetlinkMessage::NewRoute(message),
        flags: CREATE,
    }
}

fn add_veth(veth: &Veth<'_>) -> Request {
    let mut peer = LinkMessage::default();
    peer.attributes = vec![
        LinkAttribute::IfName(veth.peer.to_owned()),
        LinkAttribute::Address(veth.peer_mac.to_vec()),
        LinkAttribute::Mtu(veth.mtu),
        LinkAttribute::NetNsFd(veth.peer_netns.as_raw_fd()),
    ];
    let mut host = LinkMessage::default();
    host.header.flags = LinkFlags::Up;
    host.header.change_mask = LinkFlags::Up;
    host.attributes = vec![
        LinkAttribute::IfName(veth.host.to_owned()),
        LinkAttribute::Mtu(veth.mtu),
        LinkAttribute::Controller(veth.bridge),
        LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer))),
        ]),
    ];
    Request {
        message: RouteNetlinkMessage::NewLink(host),
        flags: CREATE,
    }
}

fn delete_link(name: &str) -> Request {
    let mut link = LinkMessage::default();
    link.attributes.push(LinkAttribute::IfName(name.to_owned()));
    Request {
        message: RouteNetlinkMessage::DelLink(link),
        flags: ACK,
    }
}

/// The bytes of a request with sequence number `sequence`.
fn encode(request: Request, sequence: u32) -> Vec<u8> {
    let mut message = NetlinkMessage::from(request.message);
    message.header.flags = NLM_F_REQUEST | request.flags;
    message.header.sequence_number = sequence;
    message.finalize();
    let mut bytes = vec![0; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

fn read_link(link: &LinkMessage) -> Link {
    let mut read = Link {
        index: link.header.index,
        mac: None,
        mtu: None,
        up: link.header.flags.contains(LinkFlags::Up),
        bridge: None,
    };
    for attribute in &link.attributes {
        match attribute {
            LinkAttribute::Address(bytes) => read.mac = bytes.as_slice().try_into().ok(),
            LinkAttribute::Mtu(mtu) => read.mtu = Some(*mtu),
            LinkAttribute::Controller(index) => read.bridge = Some(*index),
            _ => {}
        }
    }
    read
}

fn malformed(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("netlink reply: {what}"))
}

/// A route netlink socket in the network namespace of the thread that
/// opened it. Its calls block for as long as the kernel takes to answer.
pub(crate) struct Netlink {
    socket: Socket,
    sequence: u32,
}

impl Netlink {
    pub(crate) fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    /// Sends a request and reads up to the kernel's verdict on it. Returns
    /// the object the kernel answered with, for a request that asks for
    /// one.
    fn call(&mut self, request: Request) -> io::Result<Option<RouteNetlinkMessage>> {
        self.sequence = self.sequence.wrapping_add(1);
        let acknowledged = request.flags & NLM_F_ACK != 0;
        self.socket.send(&encode(request, self.sequence), 0)?;
        let mut answer = None;
        loop {
            let (datagram, _) = self.socket.recv_from_full()?;
            let mut rest = datagram.as_slice();
            while !rest.is_empty() {
                let message =
                    NetlinkMessage::<RouteNetlinkMessage>::deserialize(rest).map_err(malformed)?;
                let length = message.header.length as usize;
                if length == 0 || length > rest.len() {
                    return Err(malformed("a message longer than its datagram"));
                }
                // Messages are padded to four bytes.
                rest = &rest[length.next_multiple_of(4).min(rest.len())..];
                if message.header.sequence_number != self.sequence {
                    continue;
                }
                match message.payload {
                    NetlinkPayload::Error(error) => {
                        return match error.code {
                            None => Ok(answer),
                            Some(code) => Err(io::Error::from_raw_os_error(-code.get())),
                        };
                    }
                    NetlinkPayload::InnerMessage(object) => {
                        if !acknowledged {
                            return Ok(Some(object));
                        }
                        answer = Some(object);
                    }
                    NetlinkPayload::Done(_) => return Ok(answer),
                    _ => {}
                }
            }
        }
    }

    /// The interface named `name`, or `None` when there is none.
    pub(crate) fn link(&mut self, name: &str) -> io::Result<Option<Link>> {
        match self.call(get_link(name)) {
            Ok(Some(RouteNetlinkMessage::NewLink(link))) => Ok(Some(read_link(&link))),
            Ok(other) => Err(malformed(format_args!("{other:?} for a link"))),
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn add_bridge(&mut self, name: &str, mac: [u8; 6], mtu: u32) -> io::Result<()> {
        self.call(add_bridge(name, mac, mtu)).map(drop)
    }

    /// Makes `link` a port of `bridge`, with the bridge's MTU.
    pub(crate) fn enslave(&mut self, link: u32, bridge: u32, mtu: u32) -> io::Result<()> {
        self.call(enslave(link, bridge, mtu)).map(drop)
    }

    pub(crate) fn quiet_port(&mut self, link: u32) -> io::Result<()> {
        self.call(quiet_port(link)).map(drop)
    }

    pub(crate) fn set_up(&mut self, link: u32) -> io::Result<()> {
        self.call(set_up(link)).map(drop)
    }

    pub(crate) fn add_forwarding_entry(&mut self, port: u32, mac: [u8; 6]) -> io::Result<()> {
        self.call(add_forwarding_entry(port, mac)).map(drop)
    }

    pub(crate) fn add_address(
        &mut self,
        link: u32,
        address: Ipv4Addr,
        prefix: u8,
    ) -> io::Result<()> {
        self.call(add_address(link, address, prefix)).map(drop)
    }

    pub(crate) fn add_default_route(&mut self, gateway: Ipv4Addr, link: u32) -> io::Result<()> {
        self.call(add_default_route(gateway, link)).map(drop)
    }

    pub(crate) fn add_veth(&mut self, veth: &Veth<'_>) -> io::Result<()> {
        self.call(add_veth(veth)).map(drop)
    }

    /// Deletes an interface. The other end of a veth pair goes with it.
    pub(crate) fn delete_link(&mut self, name: &str) -> io::Result<()> {
        self.call(delete_link(name)).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    const NODE_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0x00, 0x00, 0x02];
    const GATEWAY_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd];
    const BOX_MAC: [u8; 6] = [0x02, 0x00, 0x64, 0x40, 0x01, 0x07];
    const NODE: Ipv4Addr = Ipv4Addr::new(100, 64, 255, 253);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

    // The requests below are the ones `the_calls_wire_a_node_and_a_box`
    // sends to a kernel, with the interface indexes of that run: `eth0` is
    // 3 and `br0` is 4. The bytes were captured from it with strace and
    // differ from these in the sequence numbers only.

    #[test]
    fn a_link_is_looked_up_by_name() {
        assert_eq!(
            hex(&encode(get_link("eth0"), 1)),
            "2c000000120001000100000000000000\
             00000000000000000000000000000000\
             090003006574683000000000"
        );
    }

    #[test]
    fn the_bridge_is_made_with_the_uplinks_address_and_no_protocol_of_its_own() {
        assert_eq!(
            hex(&encode(add_bridge("br0", NODE_MAC, 1500), 2)),
            "68000000100005060200000000000000\
             00000000000000000000000000000000\
             08000300627230000a0001005a94ef00\
             0002000008000400dc0500002c001200\
             0b00010062726964676500001c000200\
             08000500000000000800010000000000\
             0500170000000000"
        );
    }

    #[test]
    fn the_uplink_becomes_a_port_that_learns_and_floods_nothing() {
        assert_eq!(
            hex(&encode(enslave(3, 4, 1500), 4)),
            "30000000130005000400000000000000\
             00000000030000000000000000000000\
             08000400dc05000008000a0004000000"
        );
        assert_eq!(
            hex(&encode(quiet_port(3), 5)),
            "4c000000100005000500000000000000\
             00000000030000000000000000000000\
             2c0012000b0004006272696467650000\
             1c000500050008000000000005000900\
             0000000005001b0000000000"
        );
    }

    #[test]
    fn a_link_is_brought_up_by_its_one_flag() {
        assert_eq!(
            hex(&encode(set_up(3), 6)),
            "20000000130005000600000000000000\
             00000000030000000100000001000000"
        );
    }

    #[test]
    fn the_gateway_is_pinned_to_the_uplink_and_replaces_an_entry_that_is_there() {
        assert_eq!(
            hex(&encode(add_forwarding_entry(3, GATEWAY_MAC), 7)),
            "280000001c0005050700000000000000\
             0700000003000000400004000a000200\
             5a94efe40cdd0000"
        );
    }

    #[test]
    fn the_node_address_goes_on_the_bridge_with_its_broadcast_address() {
        assert_eq!(
            hex(&encode(add_address(4, NODE, 16), 8)),
            "30000000140005060800000000000000\
             0210000004000000080001006440fffd\
             080002006440fffd080004006440ffff"
        );
    }

    #[test]
    fn the_default_route_names_the_gateway_and_the_bridge() {
        assert_eq!(
            hex(&encode(add_default_route(GATEWAY, 4), 10)),
            "2c000000180005060a00000000000000\
             02000000fe0400010000000008000500\
             644000010800040004000000"
        );
    }

    #[test]
    fn a_veth_pair_is_made_in_one_request_with_its_peer_in_the_boxs_namespace() {
        let netns = std::fs::File::open("/proc/self/ns/net").unwrap();
        let bytes = encode(
            add_veth(&Veth {
                host: "vb1_7",
                bridge: 4,
                mtu: 1500,
                peer: "eth0",
                peer_mac: BOX_MAC,
                peer_netns: netns.as_fd(),
            }),
            3,
        );
        // The last four bytes are the namespace's descriptor.
        let (request, descriptor) = bytes.split_at(bytes.len() - 4);
        assert_eq!(
            hex(request),
            "8c000000100005060300000000000000\
             00000000000000000100000001000000\
             0a0003007662315f3700000008000400\
             dc05000008000a000400000050001200\
             09000100766574680000000040000200\
             3c000100000000000000000000000000\
             00000000090003006574683000000000\
             0a000100020064400107000008000400\
             dc05000008001c00"
        );
        assert_eq!(descriptor, netns.as_raw_fd().to_le_bytes());
    }

    #[test]
    fn a_link_is_deleted_by_name() {
        assert_eq!(
            hex(&encode(delete_link("vb1_7"), 1)),
            "2c000000110005000100000000000000\
             00000000000000000000000000000000\
             0a0003007662315f37000000"
        );
    }

    /// The name of the test that runs as root of a user namespace.
    const INSIDE: &str = "net::nl::tests::inside_a_namespace_of_its_own";
    const INSIDE_ENV: &str = "MINIMALD_NL_TEST_INSIDE";

    /// Runs the calls against the kernel, in a user and network namespace
    /// of their own where this test is root.
    #[test]
    fn the_calls_wire_a_node_and_a_box() {
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

    fn ip(arguments: &[&str]) -> serde_json_lenient::Value {
        let output = std::process::Command::new(arguments[0])
            .args(&arguments[1..])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json_lenient::from_slice(&output.stdout).unwrap()
    }

    #[test]
    #[ignore = "runs inside the namespaces `the_calls_wire_a_node_and_a_box` makes"]
    fn inside_a_namespace_of_its_own() {
        if std::env::var_os(INSIDE_ENV).is_none() {
            return;
        }
        // The VM's device, stood in for by one end of a veth pair.
        let made = std::process::Command::new("ip")
            .args(["link", "add", "eth0", "address", "5a:94:ef:00:00:02"])
            .args(["type", "veth", "peer", "name", "up0"])
            .status()
            .unwrap();
        assert!(made.success());

        let mut netlink = Netlink::open().unwrap();
        assert_eq!(netlink.link("br0").unwrap(), None);
        let uplink = netlink.link("eth0").unwrap().expect("the uplink");
        assert_eq!(uplink.mac, Some(NODE_MAC));
        assert!(!uplink.up);

        netlink.add_bridge("br0", NODE_MAC, 1500).unwrap();
        let exists = netlink.add_bridge("br0", NODE_MAC, 1500).unwrap_err();
        assert_eq!(exists.kind(), io::ErrorKind::AlreadyExists);
        let bridge = netlink.link("br0").unwrap().expect("the bridge").index;
        netlink.enslave(uplink.index, bridge, 1500).unwrap();
        netlink.quiet_port(uplink.index).unwrap();
        netlink.set_up(uplink.index).unwrap();
        netlink
            .add_forwarding_entry(uplink.index, GATEWAY_MAC)
            .unwrap();
        // A second time replaces the entry.
        netlink
            .add_forwarding_entry(uplink.index, GATEWAY_MAC)
            .unwrap();
        netlink.add_address(bridge, NODE, 16).unwrap();
        netlink.set_up(bridge).unwrap();
        netlink.add_default_route(GATEWAY, bridge).unwrap();

        let uplink = netlink.link("eth0").unwrap().unwrap();
        assert!(uplink.up);
        assert_eq!(uplink.bridge, Some(bridge));
        assert_eq!(uplink.mtu, Some(1500));

        let links = ip(&["ip", "-json", "-details", "link", "show"]);
        let link = |name: &str| {
            links
                .as_array()
                .unwrap()
                .iter()
                .find(|link| link["ifname"] == name)
                .unwrap_or_else(|| panic!("no {name} in {links}"))
                .clone()
        };
        let br0 = link("br0");
        assert_eq!(br0["address"], "5a:94:ef:00:00:02");
        assert_eq!(br0["mtu"], 1500);
        let settings = &br0["linkinfo"]["info_data"];
        assert_eq!(settings["stp_state"], 0);
        assert_eq!(settings["forward_delay"], 0);
        assert_eq!(settings["mcast_snooping"], 0);
        assert!(
            br0["flags"]
                .as_array()
                .unwrap()
                .contains(&serde_json_lenient::Value::from("UP"))
        );
        let port = &link("eth0")["linkinfo"]["info_slave_data"];
        assert_eq!(port["learning"], false);
        assert_eq!(port["flood"], false);
        assert_eq!(port["mcast_flood"], false);

        let entries = ip(&["bridge", "-json", "fdb", "show", "dev", "eth0"]);
        let pinned = entries.as_array().unwrap().iter().any(|entry| {
            entry["mac"] == "5a:94:ef:e4:0c:dd"
                && entry["master"] == "br0"
                && entry["state"] == "static"
        });
        assert!(pinned, "{entries}");

        let addresses = ip(&["ip", "-json", "address", "show", "dev", "br0"]);
        let address = &addresses[0]["addr_info"][0];
        assert_eq!(address["local"], "100.64.255.253");
        assert_eq!(address["prefixlen"], 16);
        assert_eq!(address["broadcast"], "100.64.255.255");

        let routes = ip(&["ip", "-json", "route", "show", "default"]);
        assert_eq!(routes[0]["gateway"], "100.64.0.1");
        assert_eq!(routes[0]["dev"], "br0");

        // A box: a second network namespace, held by a process.
        let mut held = std::process::Command::new("unshare")
            .args(["--net", "sleep", "60"])
            .spawn()
            .unwrap();
        let path = format!("/proc/{}/ns/net", held.id());
        let own = std::fs::read_link("/proc/self/ns/net").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::fs::read_link(&path).ok().is_none_or(|ns| ns == own) {
            assert!(
                std::time::Instant::now() < deadline,
                "no namespace for the box"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let netns = std::fs::File::open(&path).unwrap();
        netlink
            .add_veth(&Veth {
                host: "vb1_7",
                bridge,
                mtu: 1500,
                peer: "eth0",
                peer_mac: BOX_MAC,
                peer_netns: netns.as_fd(),
            })
            .unwrap();
        let host_end = netlink.link("vb1_7").unwrap().expect("the host end");
        assert!(host_end.up);
        assert_eq!(host_end.bridge, Some(bridge));
        assert_eq!(host_end.mtu, Some(1500));
        let pid = held.id().to_string();
        let inside = ip(&[
            "nsenter", "--net", "--target", &pid, "ip", "-json", "link", "show", "eth0",
        ]);
        assert_eq!(inside[0]["address"], "02:00:64:40:01:07");
        assert_eq!(inside[0]["mtu"], 1500);

        netlink.delete_link("vb1_7").unwrap();
        assert_eq!(netlink.link("vb1_7").unwrap(), None);
        let gone = std::process::Command::new("nsenter")
            .args(["--net", "--target", &pid, "ip", "link", "show", "eth0"])
            .output()
            .unwrap();
        assert!(!gone.status.success(), "the peer outlived the host end");
        let missing = netlink.delete_link("vb1_7").unwrap_err();
        assert_eq!(missing.raw_os_error(), Some(libc::ENODEV));

        held.kill().unwrap();
        held.wait().unwrap();
    }
}
