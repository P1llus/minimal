//! A box's egress section as the policy engine reads it.

use netpol::{NamePattern, Prefix, Protocols, Verdict, base::Mode};

use crate::{EgressPolicy, IpProto, NetworkMode};

/// An entry of a box's egress section that is not what its list holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("`{entry}` in `{list}` is not a subnet (write it as address/prefix-length)")]
    Subnet { list: &'static str, entry: String },
    #[error("`{entry}` in `allow_dns_hosts` is not a host name or a `*.domain` pattern")]
    Name { entry: String },
}

impl From<NetworkMode> for Mode {
    fn from(mode: NetworkMode) -> Self {
        match mode {
            NetworkMode::NoNet => Self::None,
            NetworkMode::HostNet => Self::HostIp,
            NetworkMode::OwnIp => Self::OwnIp,
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
///
/// # Errors
///
/// [`SpecError`] names the first entry that is not what its list holds.
pub fn box_policy(
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

/// Whether the engine refuses what the box's egress section does not
/// list. A section the engine cannot read is one no box runs with, and
/// reads as refusing.
#[must_use]
pub fn denies_by_default(
    egress: Option<&EgressPolicy>,
    mode: NetworkMode,
    deny_all_opt_out: bool,
) -> bool {
    let of_mode = netpol::base::defaults(mode.into()).egress;
    box_policy(egress, mode, deny_all_opt_out)
        .map_or(Verdict::Deny, |policy| policy.egress_default(of_mode))
        == Verdict::Deny
}

#[cfg(test)]
mod tests {
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

    #[expect(
        clippy::unnecessary_wraps,
        reason = "the value goes straight into a section's optional list"
    )]
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
}
