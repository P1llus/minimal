//! What a box declares for itself.

use serde::{Deserialize, Serialize};

use crate::{
    base::{self, Mode},
    model::{
        Action, Direction, NamePattern, Origin, PortRange, Prefix, Protocol, Protocols, Rule,
        Target, Verdict,
    },
};

/// The action of a rule a box writes. A box cannot redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxAction {
    Allow,
    Deny,
}

/// One entry of the box's `rules`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BoxRule {
    pub action: BoxAction,
    pub protocols: Protocols,
    pub ports: PortRange,
    pub to: Target,
}

/// The egress policy of a box. All lists may be empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxPolicy {
    /// Explicit rules, judged in the order written, before the lists below.
    pub rules: Vec<BoxRule>,
    /// The protocols the box may use. `None` is every protocol.
    pub protocols: Option<Protocols>,
    pub deny: Vec<Prefix>,
    pub allow: Vec<Prefix>,
    pub names: Vec<NamePattern>,
    /// The verdict for a destination nothing above matches. `None` leaves it
    /// to [`Self::implied_default`].
    pub default: Option<Verdict>,
}

impl BoxPolicy {
    /// The default the entries imply: deny when the box lists anything it
    /// allows, allow when it only lists what it denies, nothing when it
    /// declares nothing.
    #[must_use]
    pub fn implied_default(&self) -> Option<Verdict> {
        let allows = !self.allow.is_empty()
            || !self.names.is_empty()
            || self.rules.iter().any(|r| r.action == BoxAction::Allow);
        let denies = !self.deny.is_empty()
            || self.protocols.is_some()
            || self.rules.iter().any(|r| r.action == BoxAction::Deny);
        if allows {
            Some(Verdict::Deny)
        } else if denies {
            Some(Verdict::Allow)
        } else {
            None
        }
    }

    /// The egress default: explicit, else implied, else the base policy's.
    #[must_use]
    pub fn egress_default(&self, base: Verdict) -> Verdict {
        self.default
            .or_else(|| self.implied_default())
            .unwrap_or(base)
    }

    /// The box's entries as rules, in the order they are judged: explicit
    /// rules, the protocol limit, denied prefixes, allowed prefixes, names.
    #[must_use]
    pub fn rules(&self) -> Vec<Rule> {
        let egress = |target, action, origin| Rule::new(Direction::Egress, target, action, origin);
        let mut out = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            let action = match r.action {
                BoxAction::Allow => Action::Allow,
                BoxAction::Deny => Action::Deny,
            };
            let origin = Origin::BoxRule(u16::try_from(i).unwrap_or(u16::MAX));
            out.push(
                egress(r.to.clone(), action, origin)
                    .protocols(r.protocols)
                    .ports(r.ports),
            );
        }
        if let Some(allowed) = self.protocols {
            let refused = allowed.complement();
            if !refused.is_empty() {
                out.push(
                    egress(Target::Any, Action::Deny, Origin::BoxProtocols).protocols(refused),
                );
            }
        }
        out.extend(
            self.deny
                .iter()
                .map(|p| egress(Target::Net(*p), Action::Deny, Origin::BoxDeny)),
        );
        out.extend(
            self.allow
                .iter()
                .map(|p| egress(Target::Net(*p), Action::Allow, Origin::BoxAllow)),
        );
        out.extend(
            self.names
                .iter()
                .map(|n| egress(Target::Names(n.clone()), Action::Allow, Origin::BoxName)),
        );
        out
    }

    /// Whether a box of `mode` with these entries lets TCP to `port` out to
    /// a destination it knows only as `name`.
    ///
    /// An entry by prefix judges an address, and the name has none until
    /// the box looks it up. So only the entries by name, the entries for
    /// every address and the default decide here.
    #[must_use]
    pub fn admits_tcp_by_name(&self, mode: Mode, name: &str, port: u16) -> bool {
        let decides = |rule: &Rule| {
            rule.matches_l4(Protocol::Tcp, port)
                && match &rule.target {
                    Target::Any => true,
                    Target::Names(pattern) => pattern.matches(name),
                    Target::Net(_) | Target::OwnAddresses => false,
                }
        };
        match self.rules().into_iter().find(decides) {
            Some(rule) => rule.action == Action::Allow,
            None => self.egress_default(base::defaults(mode).egress) == Verdict::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implied_default_follows_what_the_box_lists() {
        let mut p = BoxPolicy::default();
        assert_eq!(p.implied_default(), None);
        assert_eq!(p.egress_default(Verdict::Allow), Verdict::Allow);
        assert_eq!(p.egress_default(Verdict::Deny), Verdict::Deny);

        p.deny = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(p.implied_default(), Some(Verdict::Allow));
        p.protocols = Some(Protocols::TCP);
        assert_eq!(p.egress_default(Verdict::Deny), Verdict::Allow);

        p.names = vec!["example.com".parse().unwrap()];
        assert_eq!(p.implied_default(), Some(Verdict::Deny));
        p.default = Some(Verdict::Allow);
        assert_eq!(p.egress_default(Verdict::Deny), Verdict::Allow);
    }

    #[test]
    fn rules_come_out_in_judging_order() {
        let p = BoxPolicy {
            rules: vec![BoxRule {
                action: BoxAction::Allow,
                protocols: Protocols::UDP,
                ports: PortRange::one(53),
                to: Target::Any,
            }],
            protocols: Some(Protocols::TCP),
            deny: vec!["10.1.0.0/16".parse().unwrap()],
            allow: vec!["10.0.0.0/8".parse().unwrap()],
            names: vec!["*.example.com".parse().unwrap()],
            default: None,
        };
        let origins: Vec<Origin> = p.rules().iter().map(|r| r.origin).collect();
        assert_eq!(
            origins,
            [
                Origin::BoxRule(0),
                Origin::BoxProtocols,
                Origin::BoxDeny,
                Origin::BoxAllow,
                Origin::BoxName
            ]
        );
        let limit = p
            .rules()
            .into_iter()
            .find(|r| r.origin == Origin::BoxProtocols)
            .unwrap();
        assert_eq!(limit.protocols, Protocols::UDP.union(Protocols::ICMP));
    }

    #[test]
    fn a_name_is_admitted_by_the_first_entry_that_can_decide_it() {
        let names = |list: &[&str]| BoxPolicy {
            names: list.iter().map(|n| n.parse().unwrap()).collect(),
            ..BoxPolicy::default()
        };
        let rule = |action, protocols, ports, to| BoxRule {
            action,
            protocols,
            ports,
            to,
        };

        // Nothing declared: the mode decides.
        let nothing = BoxPolicy::default();
        assert!(nothing.admits_tcp_by_name(Mode::HostIp, "example.com", 443));
        assert!(!nothing.admits_tcp_by_name(Mode::OwnIp, "example.com", 443));
        assert!(!nothing.admits_tcp_by_name(Mode::None, "example.com", 443));

        // A list of names denies the rest in every mode. A wildcard matches
        // the names below its domain and not the domain.
        let listed = names(&["example.com", "*.pkg.example.org"]);
        for mode in [Mode::HostIp, Mode::OwnIp] {
            assert!(listed.admits_tcp_by_name(mode, "Example.COM.", 443));
            assert!(listed.admits_tcp_by_name(mode, "a.pkg.example.org", 8443));
            assert!(!listed.admits_tcp_by_name(mode, "pkg.example.org", 443));
            assert!(!listed.admits_tcp_by_name(mode, "other.example", 443));
        }

        // A protocol list without TCP refuses the name before its entry.
        let no_tcp = BoxPolicy {
            protocols: Some(Protocols::UDP),
            ..names(&["example.com"])
        };
        assert!(!no_tcp.admits_tcp_by_name(Mode::HostIp, "example.com", 443));

        // An entry by prefix decides no name. An allowed prefix still makes
        // the default deny, and a denied one leaves it allow.
        let allowed_prefix = BoxPolicy {
            allow: vec!["0.0.0.0/0".parse().unwrap()],
            ..BoxPolicy::default()
        };
        assert!(!allowed_prefix.admits_tcp_by_name(Mode::HostIp, "example.com", 443));
        let denied_prefix = BoxPolicy {
            deny: vec!["0.0.0.0/0".parse().unwrap()],
            ..BoxPolicy::default()
        };
        assert!(denied_prefix.admits_tcp_by_name(Mode::OwnIp, "example.com", 443));

        // Explicit rules come first and are read by protocol and port.
        let ruled = BoxPolicy {
            rules: vec![
                rule(
                    BoxAction::Deny,
                    Protocols::TCP,
                    PortRange::one(8443),
                    Target::Names("example.com".parse().unwrap()),
                ),
                rule(
                    BoxAction::Deny,
                    Protocols::UDP,
                    PortRange::one(443),
                    Target::Any,
                ),
                rule(
                    BoxAction::Allow,
                    Protocols::TCP,
                    PortRange::one(443),
                    Target::Names("*.example.com".parse().unwrap()),
                ),
            ],
            ..names(&["example.com"])
        };
        assert!(ruled.admits_tcp_by_name(Mode::OwnIp, "example.com", 443));
        assert!(!ruled.admits_tcp_by_name(Mode::OwnIp, "example.com", 8443));
        assert!(ruled.admits_tcp_by_name(Mode::OwnIp, "api.example.com", 443));
        assert!(!ruled.admits_tcp_by_name(Mode::OwnIp, "api.example.com", 80));

        // An explicit default stands in for the implied one.
        let open = BoxPolicy {
            default: Some(Verdict::Allow),
            ..names(&["example.com"])
        };
        assert!(open.admits_tcp_by_name(Mode::OwnIp, "other.example", 443));
    }

    #[test]
    fn every_protocol_allowed_adds_no_rule() {
        let p = BoxPolicy {
            protocols: Some(Protocols::ALL),
            ..BoxPolicy::default()
        };
        assert!(p.rules().is_empty());
    }
}
