//! From what a box declares to what the policy engine compiles.
//!
//! Nothing here touches the engine or the network: it maps the box's mode
//! and its egress section, plus what the node is, onto `netpol`'s inputs.

use std::net::{IpAddr, SocketAddr};

use boxes::NetworkMode;
pub(crate) use boxes::egress::{SpecError, box_policy};
use netpol::{
    PortRange, Prefix, Verdict,
    base::{Deployment, EndpointRange, NodeKind, Services, VirtualNetwork},
    compile::Options,
};

/// Allowed flows are not logged.
pub(crate) const OPTIONS: Options = Options { log_flows: false };

/// What the node is, as far as a box's policy depends on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) kind: NodeKind,
    /// The virtual network the node itself sits on, which a box that
    /// shares the node's address sits on with it: a VM guest's.
    pub(crate) network: Option<VirtualNetwork>,
    /// The virtual network of boxes with an address of their own, which
    /// also holds the address that stands for the host's loopback. A
    /// native node learns it when its switch is made.
    pub(crate) switch: Option<switch::SwitchSubnet>,
    /// Where the node's hostname proxy listens for programs outside boxes.
    pub(crate) hostname_proxy: Vec<SocketAddr>,
}

fn virtual_network(subnet: switch::SwitchSubnet) -> Option<VirtualNetwork> {
    Prefix::new(IpAddr::V4(subnet.network()), subnet.prefix())
        .ok()
        .map(|prefix| VirtualNetwork {
            subnet: prefix,
            gateway: IpAddr::V4(subnet.gateway()),
        })
}

impl Node {
    pub(crate) const fn native() -> Self {
        Self {
            kind: NodeKind::Native,
            network: None,
            switch: None,
            hostname_proxy: Vec::new(),
        }
    }

    /// A VM guest on `subnet`.
    pub(crate) fn guest(subnet: switch::SwitchSubnet) -> Self {
        Self {
            kind: NodeKind::Guest,
            network: virtual_network(subnet),
            switch: Some(subnet),
            hostname_proxy: Vec::new(),
        }
    }

    /// The address that stands for the host's loopback, the same for every
    /// box of the node.
    pub(crate) fn host_alias(&self) -> Option<IpAddr> {
        self.switch.map(|subnet| IpAddr::V4(subnet.host_alias()))
    }
}

/// Whether the box's DNS goes through its resolver endpoint.
///
/// A box whose policy admits by name needs it, and so does one that denies
/// by default: its own resolver is the only one it can reach. In a guest
/// every box needs it, because the node's resolver is the gateway, which no
/// box may reach. A native box that allows everything asks the node's
/// resolver itself.
pub(crate) fn needs_resolver(node: &Node, mode: NetworkMode, policy: &netpol::BoxPolicy) -> bool {
    match mode {
        NetworkMode::NoNet => false,
        // Its namespace has no other resolver the box may reach.
        NetworkMode::OwnIp => true,
        _ => {
            node.kind == NodeKind::Guest
                || !policy.names.is_empty()
                || policy.egress_default(Verdict::Allow) == Verdict::Deny
        }
    }
}

/// The deployment of one box. `services` are the box's endpoints and
/// `ranges` is where the endpoints of all boxes live.
pub(crate) fn deployment(
    node: &Node,
    mode: NetworkMode,
    services: Services,
    ranges: Vec<EndpointRange>,
) -> Deployment {
    let mut d = Deployment::new(node.kind, mode.into());
    match mode {
        NetworkMode::NoNet => {}
        NetworkMode::OwnIp => {
            // The box sits on the virtual network alone, in a namespace of
            // its own, and the daemon's endpoints for it are in there too.
            d.network = node.switch.and_then(virtual_network);
            d.host_alias = node.host_alias();
            d.services = services;
            d.endpoint_ranges = ranges;
            d.node_hostname_proxy.clone_from(&node.hostname_proxy);
        }
        _ => {
            d.network = node.network;
            d.host_alias = node.host_alias();
            // A native box uses the host's own routes. The virtual network
            // a guest sits on carries IPv4 only.
            d.transport_ipv6 = node.kind == NodeKind::Native;
            d.services = services;
            d.endpoint_ranges = ranges;
            d.node_hostname_proxy.clone_from(&node.hostname_proxy);
        }
    }
    d
}

/// The endpoint ranges for a port block scheme: every address the
/// endpoints sit on, with the ports they are drawn from.
pub(crate) fn endpoint_ranges(addrs: &[IpAddr], ports: PortRange) -> Vec<EndpointRange> {
    addrs
        .iter()
        .map(|addr| EndpointRange {
            prefix: Prefix::host(*addr),
            ports,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use boxes::EgressPolicy;
    use netpol::{
        Action, Direction, Flow, FlowVerdict, Origin, Protocol, base::Mode, compile::Spec,
    };

    use super::*;

    fn section(edit: impl FnOnce(&mut EgressPolicy)) -> EgressPolicy {
        let mut section = EgressPolicy {
            allow_subnets: None,
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: None,
        };
        edit(&mut section);
        section
    }

    fn list(entries: &[&str]) -> Option<Vec<String>> {
        Some(entries.iter().map(|e| (*e).to_owned()).collect())
    }

    #[test]
    fn who_gets_a_resolver_endpoint() {
        let native = Node::native();
        let guest = Node::guest(switch::DEFAULT_SUBNET);
        let allow_all = netpol::BoxPolicy::default();
        let by_name = box_policy(
            Some(&section(|s| s.allow_dns_hosts = list(&["example.com"]))),
            NetworkMode::HostNet,
            false,
        )
        .expect("policy");
        let by_subnet = box_policy(
            Some(&section(|s| s.allow_subnets = list(&["10.0.0.0/8"]))),
            NetworkMode::HostNet,
            false,
        )
        .expect("policy");
        let only_denies = box_policy(
            Some(&section(|s| s.deny_subnets = list(&["10.0.0.0/8"]))),
            NetworkMode::HostNet,
            false,
        )
        .expect("policy");

        let host = NetworkMode::HostNet;
        assert!(!needs_resolver(&native, host, &allow_all));
        assert!(!needs_resolver(&native, host, &only_denies));
        assert!(needs_resolver(&native, host, &by_name));
        assert!(needs_resolver(&native, host, &by_subnet));
        // The guest's resolver is the gateway, which no box may reach.
        assert!(needs_resolver(&guest, host, &allow_all));
        assert!(!needs_resolver(&guest, NetworkMode::NoNet, &allow_all));
        // In a namespace of its own a box has no other resolver.
        assert!(needs_resolver(&native, NetworkMode::OwnIp, &allow_all));
    }

    #[test]
    fn deployments_per_node_and_mode() {
        let native = Node::native();
        let guest = Node::guest(switch::DEFAULT_SUBNET);
        let d = |node: &Node, mode| deployment(node, mode, Services::default(), Vec::new());

        let native_host = d(&native, NetworkMode::HostNet);
        assert_eq!(
            (
                native_host.mode,
                native_host.network,
                native_host.transport_ipv6
            ),
            (Mode::HostIp, None, true)
        );
        let guest_host = d(&guest, NetworkMode::HostNet);
        assert_eq!(guest_host.node, NodeKind::Guest);
        assert!(guest_host.network.is_some() && !guest_host.transport_ipv6);
        let none = d(&guest, NetworkMode::NoNet);
        assert_eq!((none.mode, none.network), (Mode::None, None));

        // A box with its own address sits on the node's switch, behind the
        // rules of its own entry.
        let mut switched = native.clone();
        switched.switch = Some(switch::DEFAULT_SUBNET);
        let own = d(&switched, NetworkMode::OwnIp);
        assert_eq!(own.mode, Mode::OwnIp);
        assert!(own.network.is_some() && !own.transport_ipv6);
        assert_eq!(
            own.host_alias,
            Some(IpAddr::V4(switch::DEFAULT_SUBNET.host_alias()))
        );
        // The alias is the same address for a box that shares the node's.
        assert_eq!(
            d(&switched, NetworkMode::HostNet).host_alias,
            own.host_alias
        );
        assert_eq!(d(&native, NetworkMode::HostNet).host_alias, None);
        let compiled = Spec {
            deployment: own,
            policy: box_policy(Some(&EgressPolicy::deny_all()), NetworkMode::OwnIp, false)
                .expect("policy"),
            options: OPTIONS,
        }
        .compile()
        .expect("compile");
        let flow = Flow {
            direction: Direction::Egress,
            protocol: Protocol::Tcp,
            remote: "192.0.2.1".parse().expect("address"),
            port: 443,
            local: None,
        };
        assert_eq!(
            compiled.evaluate(&flow, |_| Vec::new()).verdict,
            FlowVerdict::Deny
        );
    }

    #[test]
    fn a_listener_on_every_address_is_redirected_whatever_address_the_box_dials() {
        let endpoint: std::net::SocketAddrV4 = "127.0.80.1:20481".parse().expect("address");
        let services = Services {
            hostname_proxy: Some(netpol::Endpoint {
                v4: Some(endpoint),
                v6: None,
            }),
            ..Services::default()
        };
        let verdict = |listener: &str, dialled: &str| {
            let mut node = Node::guest(switch::DEFAULT_SUBNET);
            node.hostname_proxy = vec![listener.parse().expect("address")];
            let compiled = Spec {
                deployment: deployment(&node, NetworkMode::HostNet, services, Vec::new()),
                policy: netpol::BoxPolicy::default(),
                options: OPTIONS,
            }
            .compile()
            .expect("compile");
            let flow = Flow {
                direction: Direction::Egress,
                protocol: Protocol::Tcp,
                remote: dialled.parse().expect("address"),
                port: 7654,
                local: None,
            };
            compiled.evaluate(&flow, |_| Vec::new()).verdict
        };
        let redirected = FlowVerdict::Redirect(SocketAddr::V4(endpoint));
        // The guest's listener accepts on every address, and a box can
        // dial any of them: each one lands on the box's own endpoint.
        for dialled in ["127.0.0.1", "127.0.0.2", "100.64.255.253"] {
            assert_eq!(verdict("0.0.0.0:7654", dialled), redirected, "{dialled}");
        }
        // A listener on one address is redirected at that address only.
        assert_eq!(verdict("127.0.0.1:7654", "127.0.0.1"), redirected);
        assert_ne!(verdict("127.0.0.1:7654", "127.0.0.2"), redirected);
    }

    #[test]
    fn a_guest_box_is_kept_off_the_gateway_and_its_dns_redirected() {
        let guest = Node::guest(switch::DEFAULT_SUBNET);
        let resolver = netpol::Endpoint {
            v4: Some("127.0.80.1:20480".parse().expect("address")),
            v6: None,
        };
        let services = Services {
            resolver: Some(resolver),
            ..Services::default()
        };
        let spec = Spec {
            deployment: deployment(&guest, NetworkMode::HostNet, services, Vec::new()),
            policy: netpol::BoxPolicy::default(),
            options: OPTIONS,
        };
        let compiled = spec.compile().expect("compile");
        let to = |port: u16, protocol| Flow {
            direction: Direction::Egress,
            protocol,
            remote: IpAddr::V4(switch::DEFAULT_SUBNET.gateway()),
            port,
            local: None,
        };
        assert!(matches!(
            compiled
                .evaluate(&to(53, Protocol::Udp), |_| Vec::new())
                .verdict,
            FlowVerdict::Redirect(_)
        ));
        let api = compiled.evaluate(&to(80, Protocol::Tcp), |_| Vec::new());
        assert_eq!(api.verdict, FlowVerdict::Deny);
        let rule = &compiled.rules[usize::from(api.rule.expect("a rule decided"))];
        assert_eq!(
            (rule.action, rule.origin),
            (Action::Deny, Origin::Infrastructure)
        );
    }
}
