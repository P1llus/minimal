//! From what a box declares to what the policy engine compiles.
//!
//! Nothing here touches the engine or the network: it maps the box's mode
//! and its egress section, plus what the node is, onto `netpol`'s inputs.

use std::net::{IpAddr, SocketAddr};

use boxes::{EgressPolicy, IpProto, NetworkMode};
use netpol::{
    NamePattern, PortRange, Prefix, Protocols, Verdict,
    base::{Deployment, EndpointRange, Mode, NodeKind, Services, VirtualNetwork},
    compile::Options,
};

/// Allowed flows are not logged.
pub(crate) const OPTIONS: Options = Options { log_flows: false };

/// An entry of a box's egress section that is not what its list holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SpecError {
    #[error("`{entry}` in `{list}` is not a subnet (write it as address/prefix-length)")]
    Subnet { list: &'static str, entry: String },
    #[error("`{entry}` in `allow_dns_hosts` is not a host name or a `*.domain` pattern")]
    Name { entry: String },
}

/// What the node is, as far as a box's policy depends on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) kind: NodeKind,
    /// The virtual network the node itself sits on: a VM guest's.
    pub(crate) network: Option<VirtualNetwork>,
    /// The address that stands for the host's loopback there.
    pub(crate) host_alias: Option<IpAddr>,
    /// Where the node's hostname proxy listens for programs outside boxes.
    pub(crate) hostname_proxy: Vec<SocketAddr>,
}

impl Node {
    pub(crate) const fn native() -> Self {
        Self {
            kind: NodeKind::Native,
            network: None,
            host_alias: None,
            hostname_proxy: Vec::new(),
        }
    }

    /// A VM guest on `subnet`.
    pub(crate) fn guest(subnet: switch::SwitchSubnet) -> Self {
        let network = Prefix::new(IpAddr::V4(subnet.network()), subnet.prefix())
            .ok()
            .map(|prefix| VirtualNetwork {
                subnet: prefix,
                gateway: IpAddr::V4(subnet.gateway()),
            });
        Self {
            kind: NodeKind::Guest,
            network,
            host_alias: Some(IpAddr::V4(subnet.host_alias())),
            hostname_proxy: Vec::new(),
        }
    }
}

fn prefixes(list: &'static str, entries: Option<&Vec<String>>) -> Result<Vec<Prefix>, SpecError> {
    entries
        .into_iter()
        .flatten()
        .map(|entry| {
            entry.trim().parse().map_err(|_| SpecError::Subnet {
                list,
                entry: entry.clone(),
            })
        })
        .collect()
}

/// The box's egress section as the engine's policy.
///
/// A section that has an allow list, even an empty one, denies what it does
/// not list. One with only deny entries or a protocol list allows the rest.
/// No section leaves the default to the box's mode, which the daemon's
/// opt-out turns to allow for a box with its own address.
pub(crate) fn box_policy(
    egress: Option<&EgressPolicy>,
    mode: NetworkMode,
    deny_all_opt_out: bool,
) -> Result<netpol::BoxPolicy, SpecError> {
    let Some(section) = egress else {
        let default = (mode == NetworkMode::OwnIp && deny_all_opt_out).then_some(Verdict::Allow);
        return Ok(netpol::BoxPolicy {
            default,
            ..netpol::BoxPolicy::default()
        });
    };
    let names = section
        .allow_dns_hosts
        .iter()
        .flatten()
        .map(|entry| {
            entry.parse::<NamePattern>().map_err(|_| SpecError::Name {
                entry: entry.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let protocols = section.allow_protocols.as_ref().map(|list| {
        list.iter().fold(Protocols::NONE, |all, proto| {
            all.union(match proto {
                IpProto::Tcp => Protocols::TCP,
                IpProto::Udp => Protocols::UDP,
                IpProto::Icmp => Protocols::ICMP,
                // A protocol this build cannot name is one it cannot admit.
                _ => Protocols::NONE,
            })
        })
    });
    let lists_what_it_allows = section.allow_subnets.is_some() || section.allow_dns_hosts.is_some();
    Ok(netpol::BoxPolicy {
        rules: Vec::new(),
        protocols,
        deny: prefixes("deny_subnets", section.deny_subnets.as_ref())?,
        allow: prefixes("allow_subnets", section.allow_subnets.as_ref())?,
        names,
        default: lists_what_it_allows.then_some(Verdict::Deny),
    })
}

/// Whether the box's DNS goes through its resolver endpoint.
///
/// A box whose policy admits by name needs it, and so does one that denies
/// by default: its own resolver is the only one it can reach. In a guest
/// every box needs it, because the node's resolver is the gateway, which no
/// box may reach. A native box that allows everything asks the node's
/// resolver itself.
pub(crate) fn needs_resolver(node: &Node, mode: NetworkMode, policy: &netpol::BoxPolicy) -> bool {
    mode == NetworkMode::HostNet
        && (node.kind == NodeKind::Guest
            || !policy.names.is_empty()
            || policy.egress_default(Verdict::Allow) == Verdict::Deny)
}

/// The deployment of one box. `services` are the box's endpoints and
/// `ranges` is where the endpoints of all boxes live.
pub(crate) fn deployment(
    node: &Node,
    mode: NetworkMode,
    services: Services,
    ranges: Vec<EndpointRange>,
) -> Deployment {
    let mut d = Deployment::new(
        node.kind,
        match mode {
            NetworkMode::NoNet => Mode::None,
            NetworkMode::OwnIp => Mode::OwnIp,
            // `NetworkMode` may grow; a mode this build does not know
            // shares the node's network like `host_ip` and is judged so.
            _ => Mode::HostIp,
        },
    );
    match mode {
        NetworkMode::NoNet => {}
        NetworkMode::OwnIp => d.transport_enforces = true,
        _ => {
            d.network = node.network;
            d.host_alias = node.host_alias;
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
    use netpol::{Action, Direction, Flow, FlowVerdict, Origin, Protocol, compile::Spec};

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
    fn the_default_follows_what_the_section_lists() {
        let host = NetworkMode::HostNet;
        let policy = |s: &EgressPolicy| box_policy(Some(s), host, false).expect("policy");

        // No section: the mode decides.
        assert_eq!(box_policy(None, host, false).expect("policy").default, None);
        // An empty section declares nothing and denies nothing.
        let empty = policy(&section(|_| {}));
        assert_eq!(empty.egress_default(Verdict::Allow), Verdict::Allow);
        // Any allow list denies the rest, also when it is empty.
        for s in [
            section(|s| s.allow_subnets = list(&["10.0.0.0/8"])),
            section(|s| s.allow_subnets = list(&[])),
            section(|s| s.allow_dns_hosts = list(&["example.com"])),
            section(|s| s.allow_dns_hosts = list(&[])),
            EgressPolicy::deny_all(),
        ] {
            assert_eq!(policy(&s).default, Some(Verdict::Deny), "{s:?}");
        }
        // Only deny entries or only protocols: the rest is allowed.
        for s in [
            section(|s| s.deny_subnets = list(&["10.0.0.0/8"])),
            section(|s| s.allow_protocols = Some(vec![IpProto::Tcp])),
        ] {
            assert_eq!(
                policy(&s).egress_default(Verdict::Allow),
                Verdict::Allow,
                "{s:?}"
            );
        }
    }

    #[test]
    fn lists_keep_both_families_wildcards_and_protocols() {
        let s = section(|s| {
            s.allow_subnets = list(&["10.20.0.0/16", "2001:db8::/32"]);
            s.deny_subnets = list(&["10.20.30.0/24", "fd00::/8"]);
            s.allow_dns_hosts = list(&["api.example.com", "*.pkg.example.org"]);
            s.allow_protocols = Some(vec![IpProto::Tcp, IpProto::Icmp]);
        });
        let policy = box_policy(Some(&s), NetworkMode::HostNet, false).expect("policy");
        assert_eq!(policy.allow.len(), 2);
        assert_eq!(policy.deny.len(), 2);
        assert!(policy.names.iter().any(NamePattern::is_wildcard));
        assert_eq!(
            policy.protocols,
            Some(Protocols::TCP.union(Protocols::ICMP))
        );
        // An empty protocol list allows no protocol at all.
        let none = section(|s| s.allow_protocols = Some(Vec::new()));
        assert_eq!(
            box_policy(Some(&none), NetworkMode::HostNet, false)
                .expect("policy")
                .protocols,
            Some(Protocols::NONE)
        );
    }

    #[test]
    fn an_entry_that_is_not_what_its_list_holds_is_named() {
        let bad_subnet = section(|s| s.deny_subnets = list(&["10.0.0.0/8", "ten-dot"]));
        assert_eq!(
            box_policy(Some(&bad_subnet), NetworkMode::HostNet, false),
            Err(SpecError::Subnet {
                list: "deny_subnets",
                entry: "ten-dot".to_owned()
            })
        );
        let bad_name = section(|s| s.allow_dns_hosts = list(&["exa mple.com"]));
        assert!(matches!(
            box_policy(Some(&bad_name), NetworkMode::HostNet, false),
            Err(SpecError::Name { .. })
        ));
    }

    #[test]
    fn the_opt_out_only_changes_a_box_with_its_own_address_and_no_section() {
        let default = |mode, opt_out| box_policy(None, mode, opt_out).expect("policy").default;
        assert_eq!(default(NetworkMode::OwnIp, true), Some(Verdict::Allow));
        assert_eq!(default(NetworkMode::OwnIp, false), None);
        assert_eq!(default(NetworkMode::HostNet, true), None);
        let declared = EgressPolicy::deny_all();
        assert_eq!(
            box_policy(Some(&declared), NetworkMode::OwnIp, true)
                .expect("policy")
                .default,
            Some(Verdict::Deny)
        );
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
        assert!(!needs_resolver(&native, NetworkMode::OwnIp, &by_name));
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

        // A box with its own address is judged by the relay it sends
        // through, so its entry refuses nothing.
        let own = d(&native, NetworkMode::OwnIp);
        assert!(own.transport_enforces);
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
            compiled.evaluate(&flow, |_| None).verdict,
            FlowVerdict::Allow
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
            compiled.evaluate(&flow, |_| None).verdict
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
            compiled.evaluate(&to(53, Protocol::Udp), |_| None).verdict,
            FlowVerdict::Redirect(_)
        ));
        let api = compiled.evaluate(&to(80, Protocol::Tcp), |_| None);
        assert_eq!(api.verdict, FlowVerdict::Deny);
        let rule = &compiled.rules[usize::from(api.rule.expect("a rule decided"))];
        assert_eq!(
            (rule.action, rule.origin),
            (Action::Deny, Origin::Infrastructure)
        );
    }
}
