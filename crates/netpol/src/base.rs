//! The base policy: the rules a deployment and mode imply for every box,
//! before the box declares anything.
//!
//! It is data in the same rule model as the box's own rules. Each entry is
//! built by one small function below and carries an [`Origin`] that names it.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use crate::model::{
    Action, Defaults, Direction, Endpoint, EndpointIndex, NamePattern, Origin, PortRange, Prefix,
    Protocols, Rule, Target, Verdict,
};

/// Endpoint indexes the base policy uses.
pub const RESOLVER: EndpointIndex = EndpointIndex(0);
pub const CREDENTIAL_PROXY: EndpointIndex = EndpointIndex(1);
pub const HOSTNAME_PROXY: EndpointIndex = EndpointIndex(2);
pub const HOST_RELAY: EndpointIndex = EndpointIndex(3);

/// The kernel a box runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Native,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// A fresh network namespace with loopback only.
    None,
    /// The node's network namespace.
    HostIp,
    /// Its own namespace with an address on the virtual network.
    OwnIp,
}

impl Mode {
    /// True when the box's sockets live in a namespace of its own.
    #[must_use]
    pub const fn own_namespace(self) -> bool {
        !matches!(self, Self::HostIp)
    }
}

/// The virtual network a box, or the node of a `host_ip` box, sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualNetwork {
    pub subnet: Prefix,
    pub gateway: IpAddr,
}

/// A port with the transport protocols it is open for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortOf {
    pub protocols: Protocols,
    pub port: u16,
}

/// The per-box sockets of the daemon. `None` means the box does not get
/// that service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Services {
    /// All DNS of the box is redirected here.
    pub resolver: Option<Endpoint>,
    /// TCP to steered authorities is redirected here.
    pub credential_proxy: Option<Endpoint>,
    /// Where the box's requests to the node's hostname proxy end up.
    pub hostname_proxy: Option<Endpoint>,
    /// TCP to the host alias is redirected here. The relay behind it dials
    /// the host port if the user has exposed it.
    pub host_relay: Option<Endpoint>,
}

/// Where the daemon's endpoints for all boxes live, when boxes could reach
/// each other's: a loopback prefix, or a port range on one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRange {
    pub prefix: Prefix,
    pub ports: PortRange,
}

/// A name and port whose TCP connections go through the credential proxy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Steered {
    pub name: NamePattern,
    pub port: u16,
}

/// What the base policy is built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub node: NodeKind,
    pub mode: Mode,
    pub network: Option<VirtualNetwork>,
    /// Whether the transport under the box carries IPv6 at all.
    pub transport_ipv6: bool,
    /// The address that stands for the host's loopback. It is never
    /// routed: a box reaches the host through its host relay endpoint, or
    /// not at all. A box that is on no virtual network has one too.
    pub host_alias: Option<IpAddr>,
    /// Ports of the box that accept inbound flows.
    pub published: Vec<PortOf>,
    pub services: Services,
    pub endpoint_ranges: Vec<EndpointRange>,
    /// The authorities whose TCP goes through the credential proxy.
    pub steered: Vec<Steered>,
    /// Where the node's hostname proxy listens for programs outside boxes.
    /// A box that dials one of these gets its own proxy endpoint instead.
    pub node_hostname_proxy: Vec<SocketAddr>,
}

impl Deployment {
    /// A deployment with nothing but node and mode set.
    #[must_use]
    pub const fn new(node: NodeKind, mode: Mode) -> Self {
        Self {
            node,
            mode,
            network: None,
            transport_ipv6: false,
            host_alias: None,
            published: Vec::new(),
            services: Services {
                resolver: None,
                credential_proxy: None,
                hostname_proxy: None,
                host_relay: None,
            },
            endpoint_ranges: Vec::new(),
            steered: Vec::new(),
            node_hostname_proxy: Vec::new(),
        }
    }
}

/// The rules and settings a deployment gives a box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasePolicy {
    /// Decided before anything the box declares.
    pub before: Vec<Rule>,
    /// Ranges that are denied after the box's rules, and that a wide allow
    /// of the box does not open: see [`Rule::reaches_into`]. Egress only.
    pub protected: Vec<Prefix>,
    pub defaults: Defaults,
    pub endpoints: Vec<(EndpointIndex, Endpoint)>,
    /// Packets must leave from the box's own addresses: the set the daemon
    /// keeps for the box.
    pub source_check: bool,
}

const LOOPBACK4: Prefix = prefix4(Ipv4Addr::new(127, 0, 0, 0), 8);
const LOOPBACK6: Prefix = Prefix::host(IpAddr::V6(Ipv6Addr::LOCALHOST));
/// Holds the address cloud hosts serve instance metadata on.
const LINK_LOCAL4: Prefix = prefix4(Ipv4Addr::new(169, 254, 0, 0), 16);
const LINK_LOCAL6: Prefix = prefix6(0xfe80, 10);
const MULTICAST_LINK6: Prefix = prefix6(0xff02, 16);

/// Everything IPv6 that needs a route off the node: global unicast, unique
/// local, link-local, multicast, and the NAT64 prefix.
const ROUTED6: [Prefix; 5] = [
    prefix6(0x2000, 3),
    prefix6(0xfc00, 7),
    LINK_LOCAL6,
    prefix6(0xff00, 8),
    Prefix::host(IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0))).truncated(96),
];

pub(crate) const fn prefix4(addr: Ipv4Addr, len: u8) -> Prefix {
    Prefix::host(IpAddr::V4(addr)).truncated(len)
}

pub(crate) const fn prefix6(first: u16, len: u8) -> Prefix {
    Prefix::host(IpAddr::V6(Ipv6Addr::new(first, 0, 0, 0, 0, 0, 0, 0))).truncated(len)
}

const ICMP6_ROUTER_SOLICIT: u16 = 133;
const ICMP6_NEIGHBOUR_SOLICIT: u16 = 135;
const ICMP6_NEIGHBOUR_ADVERT: u16 = 136;
const ICMP6_MLD_QUERY: u16 = 130;
const ICMP6_MLD_DONE: u16 = 132;
const ICMP6_MLD2_REPORT: u16 = 143;

fn range(lo: u16, hi: u16) -> PortRange {
    PortRange::new(lo, hi).unwrap_or(PortRange::ALL)
}

fn egress(target: Target, action: Action, origin: Origin) -> Rule {
    Rule::new(Direction::Egress, target, action, origin)
}

/// The box reaches its own endpoints, also when a later entry would refuse
/// the address they sit on.
fn own_endpoints(s: &Services, out: &mut Vec<Rule>) {
    let entries = [
        (s.resolver, Protocols::TCP_UDP),
        (s.credential_proxy, Protocols::TCP),
        (s.hostname_proxy, Protocols::TCP),
        (s.host_relay, Protocols::TCP),
    ];
    for (endpoint, protocols) in entries {
        let Some(e) = endpoint else { continue };
        let socks = [
            e.v4.map(|a| (IpAddr::V4(*a.ip()), a.port())),
            e.v6.map(|a| (IpAddr::V6(*a.ip()), a.port())),
        ];
        for (addr, port) in socks.into_iter().flatten() {
            out.push(
                egress(
                    Target::Net(Prefix::host(addr)),
                    Action::Allow,
                    Origin::OwnEndpoints,
                )
                .protocols(protocols)
                .ports(PortRange::one(port)),
            );
        }
    }
}

/// No box reaches the endpoints the daemon serves to other boxes, and no
/// box binds a port the daemon's endpoints are drawn from. A bind on any
/// address would do: a wildcard bind takes the port on every address.
fn other_endpoints(ranges: &[EndpointRange], out: &mut Vec<Rule>) {
    for r in ranges {
        // A port range only means something for TCP and UDP.
        let protocols = if r.ports == PortRange::ALL {
            Protocols::ALL
        } else {
            Protocols::TCP_UDP
        };
        out.push(
            egress(Target::Net(r.prefix), Action::Deny, Origin::OtherEndpoints)
                .protocols(protocols)
                .ports(r.ports),
        );
        if r.ports != PortRange::ALL {
            out.push(
                Rule::new(
                    Direction::Bind,
                    Target::Any,
                    Action::Deny,
                    Origin::OtherEndpoints,
                )
                .protocols(Protocols::TCP_UDP)
                .ports(r.ports),
            );
        }
    }
}

/// A box that dials the node's hostname proxy is served by its own
/// endpoint, so the proxy knows the box and judges the request by its rules.
fn hostname_proxy(endpoint: Option<Endpoint>, shared: &[SocketAddr], out: &mut Vec<Rule>) {
    let Some(e) = endpoint else { return };
    for addr in shared {
        let family_ok = match addr {
            SocketAddr::V4(_) => e.v4.is_some(),
            SocketAddr::V6(_) => e.v6.is_some(),
        };
        if !family_ok {
            continue;
        }
        let target = if addr.ip().is_unspecified() {
            Prefix::all(crate::model::Family::of(&addr.ip()))
        } else {
            Prefix::host(addr.ip())
        };
        out.push(
            egress(
                Target::Net(target),
                Action::Redirect(HOSTNAME_PROXY),
                Origin::HostnameProxy,
            )
            .protocols(Protocols::TCP)
            .ports(PortRange::one(addr.port())),
        );
    }
}

/// All DNS goes to the resolver endpoint, whatever server the box asks.
/// One rule per family the endpoint has: a redirect cannot change family.
fn resolver(endpoint: Option<Endpoint>, out: &mut Vec<Rule>) {
    let Some(e) = endpoint else { return };
    let families = [
        (e.v4.is_some(), Prefix::V4_ALL),
        (e.v6.is_some(), Prefix::V6_ALL),
    ];
    for (_, all) in families.into_iter().filter(|(has, _)| *has) {
        out.push(
            egress(
                Target::Net(all),
                Action::Redirect(RESOLVER),
                Origin::Resolver,
            )
            .protocols(Protocols::TCP_UDP)
            .ports(PortRange::one(53)),
        );
    }
}

/// TCP to a steered authority goes through the credential proxy. UDP to it
/// is refused, so that a client falls back from QUIC at once.
fn steering(proxy: Option<Endpoint>, steered: &[Steered], out: &mut Vec<Rule>) {
    if proxy.is_none() {
        return;
    }
    for Steered { name, port } in steered {
        let target = Target::Names(name.clone());
        out.push(
            egress(
                target.clone(),
                Action::Redirect(CREDENTIAL_PROXY),
                Origin::Steering,
            )
            .protocols(Protocols::TCP)
            .ports(PortRange::one(*port)),
        );
        out.push(
            egress(target, Action::Deny, Origin::Steering)
                .protocols(Protocols::UDP)
                .ports(PortRange::one(*port)),
        );
    }
}

/// A box with its own namespace may always talk to itself: its loopback
/// and its own addresses, both ways.
fn own_addresses(out: &mut Vec<Rule>) {
    let itself = [
        Target::Net(LOOPBACK4),
        Target::Net(LOOPBACK6),
        Target::OwnAddresses,
    ];
    for target in itself {
        for direction in [Direction::Egress, Direction::Ingress] {
            out.push(Rule::new(
                direction,
                target.clone(),
                Action::Allow,
                Origin::OwnAddresses,
            ));
        }
    }
}

/// The kernel sends neighbour discovery from sockets that belong to the
/// box's cgroup when a box process created the namespace. Without these the
/// box has no IPv6 neighbours and none can find it.
fn neighbour_discovery(out: &mut Vec<Rule>) {
    let icmp = |target: Prefix, types: PortRange| {
        egress(
            Target::Net(target),
            Action::Allow,
            Origin::NeighbourDiscovery,
        )
        .protocols(Protocols::ICMP)
        .ports(types)
    };
    // Solicitations and advertisements also go to a neighbour's unicast
    // address. Only the kernel can send these types: raw sockets are refused.
    out.push(icmp(
        Prefix::V6_ALL,
        range(ICMP6_NEIGHBOUR_SOLICIT, ICMP6_NEIGHBOUR_ADVERT),
    ));
    out.push(icmp(MULTICAST_LINK6, PortRange::one(ICMP6_ROUTER_SOLICIT)));
    out.push(icmp(
        MULTICAST_LINK6,
        range(ICMP6_MLD_QUERY, ICMP6_MLD_DONE),
    ));
    out.push(icmp(MULTICAST_LINK6, PortRange::one(ICMP6_MLD2_REPORT)));
}

/// Where the transport carries no IPv6, IPv6 off the node fails at once
/// instead of timing out.
fn no_ipv6_transport(out: &mut Vec<Rule>) {
    for prefix in ROUTED6 {
        out.push(egress(
            Target::Net(prefix),
            Action::Deny,
            Origin::NoIpv6Transport,
        ));
    }
}

/// TCP to the host alias goes to the box's host relay, which knows what the
/// user has exposed and dials it. Nothing else goes to the alias, and
/// without a relay nothing at all. DNS to it is redirected before this is
/// reached.
fn host_alias(alias: Option<IpAddr>, relay: Option<Endpoint>, out: &mut Vec<Rule>) {
    let Some(alias) = alias else { return };
    let target = Target::Net(Prefix::host(alias));
    // A redirect cannot change the family of a flow.
    if relay.is_some_and(|e| e.has(crate::model::Family::of(&alias))) {
        out.push(
            egress(
                target.clone(),
                Action::Redirect(HOST_RELAY),
                Origin::HostAlias,
            )
            .protocols(Protocols::TCP),
        );
    }
    out.push(egress(target, Action::Deny, Origin::HostAlias));
}

/// No box talks to the gateway of its virtual network.
fn infrastructure(net: &VirtualNetwork, out: &mut Vec<Rule>) {
    out.push(egress(
        Target::Net(Prefix::host(net.gateway)),
        Action::Deny,
        Origin::Infrastructure,
    ));
}

/// New inbound flows are admitted on published ports.
fn published(ports: &[PortOf], out: &mut Vec<Rule>) {
    for p in ports {
        out.push(
            Rule::new(
                Direction::Ingress,
                Target::Any,
                Action::Allow,
                Origin::Published,
            )
            .protocols(p.protocols)
            .ports(PortRange::one(p.port)),
        );
    }
}

const fn defaults(mode: Mode) -> Defaults {
    match mode {
        Mode::HostIp => Defaults {
            egress: Verdict::Allow,
            ingress: Verdict::Allow,
            bind: Verdict::Allow,
        },
        Mode::OwnIp | Mode::None => Defaults {
            egress: Verdict::Deny,
            ingress: Verdict::Deny,
            bind: Verdict::Allow,
        },
    }
}

/// The protected ranges of a box on a virtual network: the network itself,
/// where the other boxes and the node are, and the link-local ranges, which
/// lead to whatever shares a link with the node. A box that shares a native
/// node's network is on the host's network by the user's choice and has
/// none.
fn protected(d: &Deployment) -> Vec<Prefix> {
    let on_virtual_network = match d.mode {
        Mode::None => false,
        Mode::OwnIp => true,
        Mode::HostIp => d.node == NodeKind::Guest || d.network.is_some(),
    };
    if !on_virtual_network {
        return Vec::new();
    }
    let mut out = vec![LINK_LOCAL4, LINK_LOCAL6];
    out.extend(d.network.map(|net| net.subnet));
    out
}

/// Builds the base policy of one box.
#[must_use]
pub fn base_policy(d: &Deployment) -> BasePolicy {
    let mut before = Vec::new();

    own_endpoints(&d.services, &mut before);
    other_endpoints(&d.endpoint_ranges, &mut before);
    resolver(d.services.resolver, &mut before);
    hostname_proxy(
        d.services.hostname_proxy,
        &d.node_hostname_proxy,
        &mut before,
    );
    steering(d.services.credential_proxy, &d.steered, &mut before);
    if d.mode.own_namespace() {
        own_addresses(&mut before);
    }
    if d.mode == Mode::OwnIp && d.transport_ipv6 {
        neighbour_discovery(&mut before);
    }
    if d.mode != Mode::None && !d.transport_ipv6 {
        no_ipv6_transport(&mut before);
    }
    if d.mode != Mode::None {
        host_alias(d.host_alias, d.services.host_relay, &mut before);
    }
    if let Some(net) = &d.network {
        infrastructure(net, &mut before);
    }
    published(&d.published, &mut before);

    let endpoints = [
        (RESOLVER, d.services.resolver),
        (CREDENTIAL_PROXY, d.services.credential_proxy),
        (HOSTNAME_PROXY, d.services.hostname_proxy),
        (HOST_RELAY, d.services.host_relay),
    ]
    .into_iter()
    .filter_map(|(index, endpoint)| endpoint.map(|e| (index, e)))
    .collect();

    BasePolicy {
        before,
        protected: protected(d),
        defaults: defaults(d.mode),
        endpoints,
        source_check: d.mode == Mode::OwnIp,
    }
}

impl fmt::Display for BasePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "defaults: egress {}, ingress {}, bind {}",
            self.defaults.egress, self.defaults.ingress, self.defaults.bind
        )?;
        if self.source_check {
            writeln!(f, "source address must be the box's own")?;
        }
        for (EndpointIndex(i), e) in &self.endpoints {
            write!(f, "endpoint {i}:")?;
            if let Some(a) = e.v4 {
                write!(f, " {a}")?;
            }
            if let Some(a) = e.v6 {
                write!(f, " {a}")?;
            }
            writeln!(f)?;
        }
        if !self.before.is_empty() {
            writeln!(f, "before the box's rules:")?;
            for rule in &self.before {
                writeln!(f, "  {rule}  ({})", rule.origin)?;
            }
        }
        if !self.protected.is_empty() {
            writeln!(f, "protected ranges, after the box's rules:")?;
            for range in &self.protected {
                writeln!(f, "  {range}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddrV4, SocketAddrV6};

    use super::*;

    fn own_ip() -> Deployment {
        let mut d = Deployment::new(NodeKind::Guest, Mode::OwnIp);
        d.network = Some(VirtualNetwork {
            subnet: "192.168.127.0/24".parse().unwrap(),
            gateway: "192.168.127.1".parse().unwrap(),
        });
        d.host_alias = Some("192.168.127.254".parse().unwrap());
        d.published = vec![PortOf {
            protocols: Protocols::TCP,
            port: 8080,
        }];
        d.services.resolver = Some(Endpoint {
            v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            v6: None,
        });
        d
    }

    #[test]
    fn host_ip_without_services_is_only_defaults_and_the_ipv6_limit() {
        let mut d = Deployment::new(NodeKind::Native, Mode::HostIp);
        d.transport_ipv6 = true;
        let base = base_policy(&d);
        assert!(base.before.is_empty() && base.protected.is_empty());
        assert_eq!(base.defaults.egress, Verdict::Allow);
        assert!(!base.source_check);

        d.transport_ipv6 = false;
        let base = base_policy(&d);
        assert_eq!(base.before.len(), ROUTED6.len());
        assert!(
            base.before
                .iter()
                .all(|r| r.origin == Origin::NoIpv6Transport && r.action == Action::Deny)
        );
    }

    #[test]
    fn own_ip_entries_are_in_protection_order() {
        let base = base_policy(&own_ip());
        let origins: Vec<Origin> = base.before.iter().map(|r| r.origin).collect();
        let first = |o: Origin| origins.iter().position(|x| *x == o).unwrap();
        assert!(first(Origin::OwnEndpoints) < first(Origin::Resolver));
        assert!(first(Origin::Resolver) < first(Origin::Infrastructure));
        assert!(first(Origin::Resolver) < first(Origin::HostAlias));
        assert!(first(Origin::OwnAddresses) < first(Origin::NoIpv6Transport));
        assert!(origins.contains(&Origin::Published));
        assert_eq!(
            base.protected,
            [
                LINK_LOCAL4,
                LINK_LOCAL6,
                "192.168.127.0/24".parse().unwrap()
            ]
        );
        assert_eq!(base.defaults.egress, Verdict::Deny);
        assert!(base.source_check);
        // An endpoint without an IPv6 address gets no IPv6 redirect.
        let redirects: Vec<&Rule> = base
            .before
            .iter()
            .filter(|r| r.origin == Origin::Resolver)
            .collect();
        assert_eq!(redirects.len(), 1);
        assert_eq!(
            redirects.first().unwrap().target,
            Target::Net(Prefix::V4_ALL)
        );
    }

    #[test]
    fn a_box_that_dials_the_node_s_hostname_proxy_gets_its_own_endpoint() {
        let mut d = Deployment::new(NodeKind::Native, Mode::HostIp);
        d.services.hostname_proxy = Some(Endpoint {
            v4: Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 80, 1), 20481)),
            v6: None,
        });
        d.node_hostname_proxy = vec![
            "127.0.0.1:7654".parse().unwrap(),
            "[::1]:7654".parse().unwrap(),
        ];
        let base = base_policy(&d);
        let redirects: Vec<&Rule> = base
            .before
            .iter()
            .filter(|r| r.origin == Origin::HostnameProxy)
            .collect();
        // The endpoint has no IPv6 address, and a redirect keeps the family.
        assert_eq!(redirects.len(), 1);
        let rule = redirects.first().unwrap();
        assert_eq!(rule.action, Action::Redirect(HOSTNAME_PROXY));
        assert_eq!(
            rule.target,
            Target::Net(Prefix::host("127.0.0.1".parse().unwrap()))
        );
        assert!(rule.matches_l4(crate::model::Protocol::Tcp, 7654));
        assert!(!rule.matches_l4(crate::model::Protocol::Udp, 7654));

        // A listener on every address is every address of that family.
        d.node_hostname_proxy = vec!["0.0.0.0:7654".parse().unwrap()];
        let base = base_policy(&d);
        let rule = base
            .before
            .iter()
            .find(|r| r.origin == Origin::HostnameProxy)
            .unwrap();
        assert_eq!(rule.target, Target::Net(Prefix::V4_ALL));
    }

    #[test]
    fn a_box_cannot_bind_a_port_the_daemon_s_endpoints_are_drawn_from() {
        // On the node's network the endpoints of all boxes share an
        // address and a port range. In a namespace of the box's own they
        // are one block on its loopback. Either way the box must not take
        // a port before the daemon binds it.
        let shared = PortRange::new(20480, 24575).unwrap();
        let block = PortRange::new(20480, 20483).unwrap();
        for (node, mode, ports) in [
            (NodeKind::Native, Mode::HostIp, shared),
            (NodeKind::Native, Mode::OwnIp, block),
            (NodeKind::Guest, Mode::OwnIp, block),
        ] {
            let mut d = Deployment::new(node, mode);
            d.endpoint_ranges = ["127.0.80.1/32", "::1/128"]
                .map(|prefix| EndpointRange {
                    prefix: prefix.parse().unwrap(),
                    ports,
                })
                .to_vec();
            let base = base_policy(&d);
            let binds: Vec<&Rule> = base
                .before
                .iter()
                .filter(|r| r.direction == Direction::Bind)
                .collect();
            // A wildcard bind takes the port on every address, so the
            // deny is for any address, once per range.
            assert_eq!(binds.len(), 2, "{node:?} {mode:?}");
            for rule in binds {
                assert_eq!(
                    (rule.action, rule.origin, &rule.target, rule.ports),
                    (Action::Deny, Origin::OtherEndpoints, &Target::Any, ports)
                );
                assert_eq!(rule.protocols, Protocols::TCP_UDP);
            }
            // Before the rule that lets a box with its own namespace use
            // its loopback, where it has one.
            let first = |o: Origin| base.before.iter().position(|r| r.origin == o);
            if let Some(own) = first(Origin::OwnAddresses) {
                assert!(first(Origin::OtherEndpoints).unwrap() < own);
            }
        }
    }

    #[test]
    fn ipv6_transport_adds_neighbour_discovery_and_drops_the_ipv6_limit() {
        let mut d = own_ip();
        d.transport_ipv6 = true;
        d.services.resolver = Some(Endpoint {
            v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0)),
        });
        let base = base_policy(&d);
        assert!(
            base.before
                .iter()
                .any(|r| r.origin == Origin::NeighbourDiscovery)
        );
        assert!(
            base.before
                .iter()
                .all(|r| r.origin != Origin::NoIpv6Transport)
        );
        assert_eq!(
            base.before
                .iter()
                .filter(|r| r.origin == Origin::Resolver)
                .count(),
            2
        );
    }

    #[test]
    fn steering_needs_a_proxy_endpoint_and_follows_the_authority_s_port() {
        let mut d = own_ip();
        d.steered = vec![Steered {
            name: "api.example.com".parse().unwrap(),
            port: 8443,
        }];
        assert!(
            base_policy(&d)
                .before
                .iter()
                .all(|r| r.origin != Origin::Steering)
        );
        d.services.credential_proxy = Some(Endpoint {
            v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8443)),
            v6: None,
        });
        let base = base_policy(&d);
        let steer: Vec<&Rule> = base
            .before
            .iter()
            .filter(|r| r.origin == Origin::Steering)
            .collect();
        assert_eq!(steer.len(), 2);
        assert_eq!(
            steer.first().unwrap().action,
            Action::Redirect(CREDENTIAL_PROXY)
        );
        assert_eq!(steer.last().unwrap().action, Action::Deny);
        // Each rule is for the authority's own port and one transport.
        let l4: Vec<(Protocols, PortRange)> =
            steer.iter().map(|r| (r.protocols, r.ports)).collect();
        assert_eq!(
            l4,
            [
                (Protocols::TCP, PortRange::one(8443)),
                (Protocols::UDP, PortRange::one(8443))
            ]
        );
    }

    #[test]
    fn display_names_every_entry() {
        let text = base_policy(&own_ip()).to_string();
        assert!(text.contains("defaults: egress deny, ingress deny, bind allow"));
        assert!(text.contains("(DNS to the box resolver)"));
        assert!(text.contains("protected ranges, after the box's rules:"));
        assert!(text.contains("  192.168.127.0/24\n"));
    }

    #[test]
    fn the_host_alias_leads_to_the_host_relay_or_nowhere() {
        let alias: IpAddr = "100.64.255.254".parse().unwrap();
        let rules = |d: &Deployment| -> Vec<(Action, Protocols)> {
            base_policy(d)
                .before
                .iter()
                .filter(|r| r.origin == Origin::HostAlias)
                .map(|r| {
                    assert_eq!(r.target, Target::Net(Prefix::host(alias)));
                    assert_eq!(r.ports, PortRange::ALL);
                    (r.action, r.protocols)
                })
                .collect()
        };
        // A box on the host's own network has the alias too, and no
        // virtual network.
        let mut d = Deployment::new(NodeKind::Native, Mode::HostIp);
        d.host_alias = Some(alias);
        assert_eq!(rules(&d), [(Action::Deny, Protocols::ALL)]);
        assert!(base_policy(&d).protected.is_empty());

        let relay = Endpoint {
            v4: Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 80, 1), 20483)),
            v6: None,
        };
        d.services.host_relay = Some(relay);
        assert_eq!(
            rules(&d),
            [
                (Action::Redirect(HOST_RELAY), Protocols::TCP),
                (Action::Deny, Protocols::ALL)
            ]
        );
        let base = base_policy(&d);
        assert!(base.endpoints.contains(&(HOST_RELAY, relay)));
        // The box may dial its relay endpoint itself, as any of its own.
        assert!(base.before.iter().any(|r| r.origin == Origin::OwnEndpoints
            && r.target == Target::Net(Prefix::host("127.0.80.1".parse().unwrap()))
            && r.ports == PortRange::one(20483)
            && r.protocols == Protocols::TCP));

        // A relay with no address of the alias's family cannot take it.
        d.services.host_relay = Some(Endpoint {
            v4: None,
            v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 20483, 0, 0)),
        });
        assert_eq!(rules(&d), [(Action::Deny, Protocols::ALL)]);
        // A box with no network has no host to reach.
        d.mode = Mode::None;
        assert!(rules(&d).is_empty());
    }

    #[test]
    fn who_has_protected_ranges() {
        let ranges = |node, mode| protected(&Deployment::new(node, mode));
        // On the host's network by the user's choice.
        assert!(ranges(NodeKind::Native, Mode::HostIp).is_empty());
        assert!(ranges(NodeKind::Native, Mode::None).is_empty());
        assert!(ranges(NodeKind::Guest, Mode::None).is_empty());
        // The metadata address of a cloud host is link-local.
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        for (node, mode) in [
            (NodeKind::Guest, Mode::HostIp),
            (NodeKind::Guest, Mode::OwnIp),
            (NodeKind::Native, Mode::OwnIp),
        ] {
            let list = ranges(node, mode);
            assert!(
                list.iter().any(|r| r.contains(metadata)),
                "{node:?} {mode:?}"
            );
            assert!(list.contains(&LINK_LOCAL6), "{node:?} {mode:?}");
        }
    }
}
