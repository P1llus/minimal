//! Whether this host can enforce a box's network policy.
//!
//! A launch asks before it starts anything for the box. A policy that needs
//! enforcement the host does not have is refused there: a box never runs
//! with rules nothing applies.

use boxes::{BoxPolicy, NetworkMode};

/// Why a box's policy cannot be enforced here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unenforceable {
    /// The first setting that needs enforcement, as `minimal.toml` spells it.
    pub(crate) setting: &'static str,
}

impl std::fmt::Display for Unenforceable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the box did not start: its network policy sets `{}`, and this version of Minimal \
             cannot enforce a network policy on a box that shares the host's address \
             (`host_ip`). Give the box its own address (`own_ip`), or remove the setting.",
            self.setting
        )
    }
}

impl std::error::Error for Unenforceable {}

/// The component that enforces network policy on boxes.
pub(crate) trait PolicyEngine: Send + Sync {
    /// Whether a box in `mode` with `policy` can run with every rule of the
    /// policy applied.
    fn can_enforce(&self, mode: NetworkMode, policy: &BoxPolicy) -> Result<(), Unenforceable>;
}

/// No engine for boxes that share the host's network namespace. Such a box
/// runs only when its policy asks for nothing. A box with a namespace of its
/// own is enforced on its own network path, and a box with no network has
/// nothing to enforce.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NoEngine;

impl PolicyEngine for NoEngine {
    fn can_enforce(&self, mode: NetworkMode, policy: &BoxPolicy) -> Result<(), Unenforceable> {
        match mode {
            NetworkMode::HostNet => match needs_enforcement(policy) {
                Some(setting) => Err(Unenforceable { setting }),
                None => Ok(()),
            },
            _ => Ok(()),
        }
    }
}

/// The engine this daemon enforces with.
pub(crate) fn engine() -> &'static dyn PolicyEngine {
    &NoEngine
}

/// The IPv4 prefix that covers every address.
const EVERYWHERE: &str = "0.0.0.0/0";

/// The first setting of `policy` that only an engine can honour, or `None`
/// for a policy that allows everything: no egress section or one that only
/// spells out the allow-all prefix, no credentialed upstream, and no block
/// of UDP 443.
fn needs_enforcement(policy: &BoxPolicy) -> Option<&'static str> {
    if let Some(egress) = &policy.egress {
        let declared = |list: &Option<Vec<String>>| list.as_ref().is_some_and(|l| !l.is_empty());
        if declared(&egress.deny_subnets) {
            return Some("deny_subnets");
        }
        if declared(&egress.allow_dns_hosts) {
            return Some("allow_dns_hosts");
        }
        if egress.allow_protocols.is_some() {
            return Some("allow_protocols");
        }
        let everywhere = egress
            .allow_subnets
            .as_ref()
            .is_some_and(|subnets| subnets.iter().any(|subnet| subnet == EVERYWHERE));
        if egress.allow_subnets.is_some() && !everywhere {
            return Some("allow_subnets");
        }
    }
    if policy.credentialed_upstream.is_some() {
        return Some("secrets");
    }
    if policy.quic443 == Some(boxes::core::bep::Quic443::Block) {
        return Some("quic443");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::EgressPolicy;

    fn egress(edit: impl FnOnce(&mut EgressPolicy)) -> BoxPolicy {
        let mut section = EgressPolicy {
            allow_subnets: None,
            allow_dns_hosts: None,
            allow_protocols: None,
            deny_subnets: None,
        };
        edit(&mut section);
        BoxPolicy::new(Some(section), None)
    }

    #[test]
    fn a_host_ip_box_runs_only_with_a_policy_that_allows_everything() {
        let engine = NoEngine;
        let allowed = [
            BoxPolicy::new(None, None),
            egress(|_| {}),
            egress(|e| e.allow_subnets = Some(vec![EVERYWHERE.to_string()])),
            egress(|e| {
                e.allow_subnets = Some(vec![EVERYWHERE.to_string()]);
                e.allow_dns_hosts = Some(Vec::new());
            }),
        ];
        for policy in &allowed {
            assert_eq!(
                engine.can_enforce(NetworkMode::HostNet, policy),
                Ok(()),
                "{policy:?}"
            );
        }
        let refused = [
            (
                BoxPolicy::new(Some(EgressPolicy::deny_all()), None),
                "allow_protocols",
            ),
            (
                egress(|e| {
                    e.allow_subnets = Some(Vec::new());
                    e.allow_dns_hosts = Some(Vec::new());
                }),
                "allow_subnets",
            ),
            (
                egress(|e| e.allow_subnets = Some(vec!["10.0.0.0/8".to_string()])),
                "allow_subnets",
            ),
            (
                egress(|e| e.allow_dns_hosts = Some(vec!["example.com".to_string()])),
                "allow_dns_hosts",
            ),
            (
                egress(|e| e.allow_protocols = Some(Vec::new())),
                "allow_protocols",
            ),
            (
                egress(|e| e.deny_subnets = Some(vec!["10.0.0.0/8".to_string()])),
                "deny_subnets",
            ),
        ];
        for (policy, setting) in &refused {
            assert_eq!(
                engine.can_enforce(NetworkMode::HostNet, policy),
                Err(Unenforceable { setting }),
                "{policy:?}"
            );
        }
        let mut blocked = BoxPolicy::new(None, None);
        blocked.quic443 = Some(boxes::core::bep::Quic443::Block);
        assert_eq!(
            engine.can_enforce(NetworkMode::HostNet, &blocked),
            Err(Unenforceable { setting: "quic443" })
        );
    }

    #[test]
    fn a_box_with_its_own_namespace_is_not_this_engine_s_to_refuse() {
        let deny_all = BoxPolicy::new(Some(EgressPolicy::deny_all()), None);
        for mode in [NetworkMode::OwnIp, NetworkMode::NoNet] {
            assert_eq!(NoEngine.can_enforce(mode, &deny_all), Ok(()));
        }
    }
}
