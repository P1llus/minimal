//! From an ordered rule list to the entries the kernel programs read.
//!
//! The programs do one longest-prefix lookup per flow, so the rule list of a
//! prefix must already hold the rules of every prefix that covers it. The
//! copying happens here, and so does the check that a list still fits.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    abi,
    base::{BasePolicy, BoxAddrs, Deployment, base_policy},
    model::{
        Action, Defaults, Direction, Endpoint, EndpointIndex, Family, NamePattern, PortRange,
        Prefix, Protocols, Rule, SetId, Target, Verdict,
    },
    policy::BoxPolicy,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    #[error(
        "{needed} rules apply to {direction} {target}, the limit is {max}. {}",
        landed(entries, *base)
    )]
    TooManyRules {
        direction: Direction,
        target: String,
        needed: usize,
        max: usize,
        /// The entries the user wrote that land in the list, each as the
        /// setting it comes from.
        entries: Vec<String>,
        /// How many rules of the list the base policy adds.
        base: usize,
    },
    #[error("rule {rule} names no protocol and can match nothing: give it one or remove it")]
    NoProtocol { rule: usize },
    #[error("the engine cannot tell the names {0} and {1} apart: remove one of them")]
    NameSetClash(String, String),
    #[error("the policy has {0} rules, more than the engine can number")]
    TooManyRulesTotal(usize),
    #[error("rule {rule} redirects a {direction} flow: only egress can be redirected")]
    RedirectDirection { rule: usize, direction: Direction },
    #[error("rule {rule} redirects to endpoint {endpoint}, which the box does not have")]
    UnknownEndpoint { rule: usize, endpoint: u8 },
    #[error(
        "rule {rule} redirects {family:?} flows to endpoint {endpoint}, which has no address of that family"
    )]
    EndpointFamily {
        rule: usize,
        endpoint: u8,
        family: Family,
    },
    #[error("endpoint {0} is defined twice")]
    DuplicateEndpoint(u8),
    #[error("endpoint index {0} is beyond what the engine holds per box")]
    EndpointIndex(u8),
}

fn landed(entries: &[String], base: usize) -> String {
    let mut out = String::new();
    if !entries.is_empty() {
        out.push_str("These entries land there: ");
        out.push_str(&entries.join("; "));
        out.push_str(". ");
    }
    if base > 0 {
        out.push_str(&format!("The base policy adds {base}. "));
    }
    out.push_str("Remove some of the entries or merge them.");
    out
}

/// A rule as the setting the user wrote it in, or `None` for a rule the
/// user has no setting for.
fn declared(rule: &Rule) -> Option<String> {
    use crate::model::Origin;

    let l4 = || format!("{} {}", rule.protocols, rule.ports);
    Some(match rule.origin {
        Origin::BoxRule(i) => format!("rules[{i}] ({} {} to {})", rule.action, l4(), rule.target),
        Origin::BoxProtocols => "allow_protocols".to_owned(),
        Origin::BoxDeny => format!("deny_subnets {}", rule.target),
        Origin::BoxAllow => format!("allow_subnets {}", rule.target),
        Origin::BoxName => format!("allow_dns_hosts {}", rule.target),
        Origin::HostExposure => format!("host exposure {}", l4()),
        Origin::Published => format!("published port {}", l4()),
        _ => return None,
    })
}

/// One rule as the programs see it: `prio` is its position in the box's list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Slot {
    pub prio: u16,
    pub protocols: Protocols,
    pub ports: PortRange,
    pub action: Action,
}

/// The rule list of one prefix, with the rules of covering prefixes copied in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEntry {
    pub direction: Direction,
    pub prefix: Prefix,
    pub rules: Vec<Slot>,
}

/// The rule list of the addresses pinned for one name pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetEntry {
    pub id: SetId,
    pub direction: Direction,
    pub rules: Vec<Slot>,
}

/// The settings of a box that are not rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxConfig {
    pub defaults: Defaults,
    pub source_check: bool,
    pub log_flows: bool,
    /// The errno a refused system call returns. 0 means `EPERM`.
    pub refuse_errno: u16,
    pub addrs: BoxAddrs,
}

/// Everything the engine holds for one box, as plain data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compiled {
    pub config: BoxConfig,
    /// The whole policy in judging order. A slot's `prio` indexes this.
    pub rules: Vec<Rule>,
    pub nets: Vec<NetEntry>,
    pub sets: Vec<SetEntry>,
    /// Which set the pins of a name go to. See [`Self::set_for_name`].
    pub names: Vec<(NamePattern, SetId)>,
    pub endpoints: Vec<(EndpointIndex, Endpoint)>,
}

/// Settings of the compile that are neither deployment nor policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    pub refuse_errno: u16,
    /// Report allowed connects and sends as events too.
    pub log_flows: bool,
}

/// What the daemon keeps per box: enough to compile again when a published
/// port or a host exposure changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub deployment: Deployment,
    pub policy: BoxPolicy,
    pub options: Options,
}

impl Spec {
    pub fn compile(&self) -> Result<Compiled, CompileError> {
        if self.deployment.transport_enforces {
            // The transport judges this box's traffic. The engine lets
            // everything through, so the box's rules are not compiled.
            return compile(
                &BasePolicy::pass_through(),
                &BoxPolicy::default(),
                self.options,
            );
        }
        compile(&base_policy(&self.deployment), &self.policy, self.options)
    }
}

/// The ports one protocol has rules for so far: sorted ranges that neither
/// overlap nor touch.
#[derive(Default)]
struct Taken(Vec<(u32, u32)>);

impl Taken {
    fn covers(&self, ports: PortRange) -> bool {
        let (lo, hi) = (u32::from(ports.lo()), u32::from(ports.hi()));
        self.0.iter().any(|(a, b)| *a <= lo && hi <= *b)
    }

    fn add(&mut self, ports: PortRange) {
        self.0.push((u32::from(ports.lo()), u32::from(ports.hi())));
        self.0.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.0.len());
        for (lo, hi) in self.0.drain(..) {
            match merged.last_mut() {
                Some((_, end)) if lo <= *end + 1 => *end = (*end).max(hi),
                _ => merged.push((lo, hi)),
            }
        }
        self.0 = merged;
    }
}

/// Drops rules that can never be the first match in their list: the rules
/// before them take every protocol and port they take, between them.
fn prune(slots: impl Iterator<Item = Slot>) -> Vec<Slot> {
    let mut taken: [Taken; 3] = Default::default();
    let mut kept: Vec<Slot> = Vec::new();
    for s in slots {
        let shadowed = s
            .protocols
            .iter()
            .all(|p| taken.get(index_of(p)).is_some_and(|t| t.covers(s.ports)));
        if shadowed {
            continue;
        }
        for p in s.protocols.iter() {
            if let Some(t) = taken.get_mut(index_of(p)) {
                t.add(s.ports);
            }
        }
        kept.push(s);
    }
    kept
}

const fn index_of(protocol: crate::model::Protocol) -> usize {
    match protocol {
        crate::model::Protocol::Tcp => 0,
        crate::model::Protocol::Udp => 1,
        crate::model::Protocol::Icmp => 2,
    }
}

fn check_len(
    direction: Direction,
    target: &dyn fmt::Display,
    list: &[Slot],
    rules: &[Rule],
) -> Result<(), CompileError> {
    if list.len() <= abi::RULES_MAX {
        return Ok(());
    }
    let entries: Vec<String> = list
        .iter()
        .filter_map(|slot| rules.get(usize::from(slot.prio)))
        .filter_map(declared)
        .collect();
    Err(CompileError::TooManyRules {
        direction,
        target: target.to_string(),
        needed: list.len(),
        max: abi::RULES_MAX,
        base: list.len() - entries.len(),
        entries,
    })
}

fn validate(rules: &[Rule], endpoints: &[(EndpointIndex, Endpoint)]) -> Result<(), CompileError> {
    for (i, (index, _)) in endpoints.iter().enumerate() {
        if endpoints
            .iter()
            .skip(i + 1)
            .any(|(other, _)| other == index)
        {
            return Err(CompileError::DuplicateEndpoint(index.0));
        }
        if index.0 >= abi::ENDPOINTS_MAX {
            return Err(CompileError::EndpointIndex(index.0));
        }
    }
    for (rule, r) in rules.iter().enumerate() {
        if r.protocols.is_empty() {
            return Err(CompileError::NoProtocol { rule });
        }
        let Action::Redirect(index) = r.action else {
            continue;
        };
        if r.direction != Direction::Egress {
            return Err(CompileError::RedirectDirection {
                rule,
                direction: r.direction,
            });
        }
        let Some((_, endpoint)) = endpoints.iter().find(|(i, _)| *i == index) else {
            return Err(CompileError::UnknownEndpoint {
                rule,
                endpoint: index.0,
            });
        };
        // A pinned address can be of either family and is checked when the
        // flow is judged. A prefix names its family now.
        let needed: &[Family] = match &r.target {
            Target::Any => &[Family::V4, Family::V6],
            Target::Net(p) if p.family() == Family::V4 => &[Family::V4],
            Target::Net(_) => &[Family::V6],
            Target::Names(_) => &[],
        };
        if let Some(family) = needed.iter().copied().find(|f| !endpoint.has(*f)) {
            return Err(CompileError::EndpointFamily {
                rule,
                endpoint: index.0,
                family,
            });
        }
    }
    Ok(())
}

/// Compiles a base policy and a box's own policy.
///
/// Judging order: the base policy's `before` rules, the box's rules, the
/// base policy's `after` rules, then the default.
pub fn compile(
    base: &BasePolicy,
    policy: &BoxPolicy,
    options: Options,
) -> Result<Compiled, CompileError> {
    let rules: Vec<Rule> = base
        .before
        .iter()
        .cloned()
        .chain(policy.rules())
        .chain(base.after.iter().cloned())
        .collect();
    if rules.len() >= usize::from(abi::NO_RULE) {
        return Err(CompileError::TooManyRulesTotal(rules.len()));
    }
    validate(&rules, &base.endpoints)?;

    let numbered: Vec<(Slot, &Rule)> = rules
        .iter()
        .zip(0u16..)
        .map(|(r, prio)| {
            (
                Slot {
                    prio,
                    protocols: r.protocols,
                    ports: r.ports,
                    action: r.action,
                },
                r,
            )
        })
        .collect();

    let mut nets = Vec::new();
    for direction in Direction::ALL {
        for family in [Family::V4, Family::V6] {
            let scoped: Vec<(Slot, Prefix)> = numbered
                .iter()
                .filter(|(_, r)| r.direction == direction)
                .filter_map(|(slot, r)| match &r.target {
                    Target::Any => Some((*slot, Prefix::all(family))),
                    Target::Net(p) if p.family() == family => Some((*slot, *p)),
                    Target::Net(_) | Target::Names(_) => None,
                })
                .collect();
            let prefixes: BTreeSet<Prefix> = scoped.iter().map(|(_, p)| *p).collect();
            for prefix in prefixes {
                let list = prune(
                    scoped
                        .iter()
                        .filter(|(_, p)| p.covers(&prefix))
                        .map(|(s, _)| *s),
                );
                check_len(direction, &prefix, &list, &rules)?;
                nets.push(NetEntry {
                    direction,
                    prefix,
                    rules: list,
                });
            }
        }
    }

    let mut names: Vec<(NamePattern, SetId)> = Vec::new();
    for (_, r) in &numbered {
        let Target::Names(n) = &r.target else {
            continue;
        };
        if names.iter().any(|(known, _)| known == n) {
            continue;
        }
        let id = n.set_id();
        // Two patterns with one hash: possible, and never seen.
        if let Some((other, _)) = names.iter().find(|(_, known)| *known == id) {
            return Err(CompileError::NameSetClash(other.to_string(), n.to_string()));
        }
        names.push((n.clone(), id));
    }
    let mut sets = Vec::new();
    for (pattern, id) in &names {
        for direction in Direction::ALL {
            let list = prune(
                numbered
                    .iter()
                    .filter(|(_, r)| r.direction == direction)
                    .filter(|(_, r)| matches!(&r.target, Target::Names(n) if n.covers(pattern)))
                    .map(|(s, _)| *s),
            );
            if list.is_empty() {
                continue;
            }
            check_len(direction, pattern, &list, &rules)?;
            sets.push(SetEntry {
                id: *id,
                direction,
                rules: list,
            });
        }
    }

    Ok(Compiled {
        config: BoxConfig {
            defaults: Defaults {
                egress: policy.egress_default(base.defaults.egress),
                ingress: base.defaults.ingress,
                bind: base.defaults.bind,
            },
            source_check: base.source_check,
            log_flows: options.log_flows,
            refuse_errno: options.refuse_errno,
            addrs: base.addrs,
        },
        rules,
        nets,
        sets,
        names,
        endpoints: base.endpoints.clone(),
    })
}

impl Compiled {
    /// The set that addresses resolved for `name` are pinned to: the one of
    /// the most specific pattern that matches. `None` when no rule names it.
    #[must_use]
    pub fn set_for_name(&self, name: &str) -> Option<SetId> {
        self.names
            .iter()
            .filter(|(pattern, _)| pattern.matches(name))
            .max_by_key(|(pattern, _)| pattern.specificity())
            .map(|(_, id)| *id)
    }

    /// Whether the resolver should answer for `name` at all. It should when
    /// some rule admits the name, or when the box's egress default is allow.
    #[must_use]
    pub fn resolvable(&self, name: &str) -> bool {
        if self.config.defaults.egress == Verdict::Allow {
            return true;
        }
        let Some(id) = self.set_for_name(name) else {
            return false;
        };
        self.sets
            .iter()
            .filter(|s| s.id == id && s.direction == Direction::Egress)
            .flat_map(|s| &s.rules)
            .any(|slot| slot.action != Action::Deny)
    }

    #[must_use]
    pub fn endpoint(&self, index: EndpointIndex) -> Option<&Endpoint> {
        self.endpoints
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, e)| e)
    }

    pub(crate) fn set_rules(&self, id: SetId, direction: Direction) -> Option<&[Slot]> {
        self.sets
            .iter()
            .find(|s| s.id == id && s.direction == direction)
            .map(|s| s.rules.as_slice())
    }
}

impl fmt::Display for Compiled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.config.defaults;
        writeln!(
            f,
            "defaults: egress {}, ingress {}, bind {}",
            d.egress, d.ingress, d.bind
        )?;
        if self.config.source_check {
            writeln!(f, "source address must be the box's own")?;
        }
        for (i, rule) in self.rules.iter().enumerate() {
            writeln!(f, "{i:>4}  {rule}  ({})", rule.origin)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use crate::{
        base::{Mode, NodeKind, RESOLVER},
        model::Origin,
        policy::{BoxAction, BoxRule},
    };

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }

    fn host_ip() -> BasePolicy {
        let mut d = Deployment::new(NodeKind::Native, Mode::HostIp);
        d.transport_ipv6 = true;
        base_policy(&d)
    }

    fn entry<'a>(c: &'a Compiled, direction: Direction, prefix: &str) -> &'a NetEntry {
        c.nets
            .iter()
            .find(|e| e.direction == direction && e.prefix == p(prefix))
            .unwrap()
    }

    #[test]
    fn covering_rules_are_copied_into_longer_prefixes() {
        let policy = BoxPolicy {
            deny: vec![p("10.1.2.0/24")],
            allow: vec![p("10.1.0.0/16"), p("192.0.2.0/24")],
            ..BoxPolicy::default()
        };
        let c = compile(&host_ip(), &policy, Options::default()).unwrap();
        assert_eq!(c.config.defaults.egress, Verdict::Deny);
        // rules: 0 deny /24, 1 allow /16, 2 allow 192.0.2.0/24
        let long = entry(&c, Direction::Egress, "10.1.2.0/24");
        // The deny takes everything, so the allow of the /16 can never be
        // first and is dropped.
        assert_eq!(long.rules.iter().map(|s| s.prio).collect::<Vec<_>>(), [0]);
        let short = entry(&c, Direction::Egress, "10.1.0.0/16");
        assert_eq!(short.rules.iter().map(|s| s.prio).collect::<Vec<_>>(), [1]);
        assert_eq!(c.nets.len(), 3);
    }

    #[test]
    fn a_partial_rule_keeps_the_covering_rule_behind_it() {
        let policy = BoxPolicy {
            rules: vec![BoxRule {
                action: BoxAction::Deny,
                protocols: Protocols::UDP,
                ports: PortRange::one(443),
                to: Target::Net(p("10.1.2.0/24")),
            }],
            allow: vec![p("10.0.0.0/8")],
            ..BoxPolicy::default()
        };
        let c = compile(&host_ip(), &policy, Options::default()).unwrap();
        let long = entry(&c, Direction::Egress, "10.1.2.0/24");
        assert_eq!(
            long.rules
                .iter()
                .map(|s| (s.prio, s.action))
                .collect::<Vec<_>>(),
            [(0, Action::Deny), (1, Action::Allow)]
        );
    }

    #[test]
    fn any_target_lands_in_both_families() {
        let policy = BoxPolicy {
            protocols: Some(Protocols::TCP),
            ..BoxPolicy::default()
        };
        let c = compile(&host_ip(), &policy, Options::default()).unwrap();
        assert_eq!(c.config.defaults.egress, Verdict::Allow);
        assert_eq!(entry(&c, Direction::Egress, "0.0.0.0/0").rules.len(), 1);
        assert_eq!(entry(&c, Direction::Egress, "::/0").rules.len(), 1);
    }

    #[test]
    fn a_list_that_does_not_fit_is_an_error() {
        let rules = (0..=u16::try_from(abi::RULES_MAX).unwrap())
            .map(|i| BoxRule {
                action: BoxAction::Allow,
                protocols: Protocols::TCP,
                ports: PortRange::one(1000 + i),
                to: Target::Net(p("10.0.0.0/8")),
            })
            .collect();
        let err = compile(
            &host_ip(),
            &BoxPolicy {
                rules,
                ..BoxPolicy::default()
            },
            Options::default(),
        );
        let Err(CompileError::TooManyRules {
            direction: Direction::Egress,
            target,
            needed,
            max,
            entries,
            base: 0,
        }) = &err
        else {
            panic!("{err:?}");
        };
        assert_eq!(
            (target.as_str(), *needed, *max),
            ("10.0.0.0/8", abi::RULES_MAX + 1, abi::RULES_MAX)
        );
        assert_eq!(entries.len(), abi::RULES_MAX + 1);
        // The message names what the user wrote, so they know what to merge.
        let message = err.unwrap_err().to_string();
        assert!(
            message.contains("rules[0] (allow tcp 1000 to 10.0.0.0/8)")
                && message.contains("rules[32]"),
            "{message}"
        );
    }

    #[test]
    fn the_error_tells_host_exposures_from_the_base_policy() {
        let mut d = Deployment::new(NodeKind::Guest, Mode::HostIp);
        d.network = Some(crate::base::VirtualNetwork {
            subnet: p("100.64.0.0/24"),
            gateway: "100.64.0.1".parse().unwrap(),
            host_alias: Some("100.64.0.254".parse().unwrap()),
        });
        d.host_exposures = (0..40)
            .map(|i| crate::base::PortOf {
                protocols: Protocols::TCP,
                port: 5000 + i,
            })
            .collect();
        let err = compile(&base_policy(&d), &BoxPolicy::default(), Options::default()).unwrap_err();
        let CompileError::TooManyRules { entries, base, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(entries.len(), 40);
        assert!(*base >= 1, "the deny of the rest of the alias");
        assert!(err.to_string().contains("host exposure tcp 5000"), "{err}");
    }

    #[test]
    fn a_rule_without_a_protocol_is_refused() {
        let policy = BoxPolicy {
            rules: vec![BoxRule {
                action: BoxAction::Allow,
                protocols: Protocols::NONE,
                ports: PortRange::ALL,
                to: Target::Net(p("127.0.0.0/8")),
            }],
            deny: vec![p("127.0.0.0/8")],
            ..BoxPolicy::default()
        };
        assert_eq!(
            compile(&host_ip(), &policy, Options::default()),
            Err(CompileError::NoProtocol { rule: 0 })
        );
    }

    #[test]
    fn rules_that_earlier_rules_cover_between_them_are_dropped() {
        let rule = |protocols, lo, hi, action| BoxRule {
            action,
            protocols,
            ports: PortRange::new(lo, hi).unwrap(),
            to: Target::Net(p("10.0.0.0/8")),
        };
        let policy = BoxPolicy {
            rules: vec![
                rule(Protocols::TCP, 0, 1023, BoxAction::Deny),
                rule(Protocols::TCP, 1024, u16::MAX, BoxAction::Deny),
                rule(Protocols::UDP, 53, 53, BoxAction::Allow),
                // TCP is taken in full by the first two together.
                rule(Protocols::TCP, 443, 2000, BoxAction::Allow),
                // UDP 53 is taken, the rest of UDP is not.
                rule(Protocols::TCP_UDP, 53, 53, BoxAction::Deny),
                rule(Protocols::TCP_UDP, 50, 60, BoxAction::Deny),
            ],
            ..BoxPolicy::default()
        };
        let c = compile(&host_ip(), &policy, Options::default()).unwrap();
        let list = &entry(&c, Direction::Egress, "10.0.0.0/8").rules;
        assert_eq!(
            list.iter().map(|s| s.prio).collect::<Vec<_>>(),
            [0, 1, 2, 5]
        );
    }

    #[test]
    fn name_sets_follow_pattern_cover() {
        let policy = BoxPolicy {
            rules: vec![BoxRule {
                action: BoxAction::Deny,
                protocols: Protocols::UDP,
                ports: PortRange::ALL,
                to: Target::Names("api.example.com".parse().unwrap()),
            }],
            names: vec!["*.example.com".parse().unwrap()],
            ..BoxPolicy::default()
        };
        let c = compile(&host_ip(), &policy, Options::default()).unwrap();
        let exact = c.set_for_name("API.example.com.").unwrap();
        let wild = c.set_for_name("www.example.com").unwrap();
        assert_ne!(exact, wild);
        assert_eq!(c.set_for_name("example.com"), None);
        // The exact name gets its own rule and the wildcard's.
        assert_eq!(c.set_rules(exact, Direction::Egress).unwrap().len(), 2);
        assert_eq!(c.set_rules(wild, Direction::Egress).unwrap().len(), 1);
        assert!(c.resolvable("www.example.com"));
        assert!(!c.resolvable("example.org"));
    }

    #[test]
    fn a_set_id_does_not_depend_on_what_else_the_policy_names() {
        let names = |list: &[&str]| BoxPolicy {
            names: list.iter().map(|n| n.parse().unwrap()).collect(),
            ..BoxPolicy::default()
        };
        let before = compile(
            &host_ip(),
            &names(&["removed.test", "kept.test"]),
            Options::default(),
        )
        .unwrap();
        let after = compile(
            &host_ip(),
            &names(&["added.test", "kept.test"]),
            Options::default(),
        )
        .unwrap();
        assert_eq!(
            before.set_for_name("kept.test"),
            after.set_for_name("kept.test")
        );
        // The set of the removed name is gone, and no other name got its id.
        let removed = before.set_for_name("removed.test").unwrap();
        assert_eq!(after.set_for_name("removed.test"), None);
        assert!(after.sets.iter().all(|s| s.id != removed));
        assert!(after.set_rules(removed, Direction::Egress).is_none());
    }

    #[test]
    fn redirects_are_validated() {
        let mut base = host_ip();
        let redirect = Rule::new(
            Direction::Egress,
            Target::Net(Prefix::V6_ALL),
            Action::Redirect(RESOLVER),
            Origin::Resolver,
        );
        base.before.push(redirect.clone());
        let none = BoxPolicy::default();
        assert_eq!(
            compile(&base, &none, Options::default()),
            Err(CompileError::UnknownEndpoint {
                rule: 0,
                endpoint: 0
            })
        );
        base.endpoints.push((
            RESOLVER,
            Endpoint {
                v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353)),
                v6: None,
            },
        ));
        assert_eq!(
            compile(&base, &none, Options::default()),
            Err(CompileError::EndpointFamily {
                rule: 0,
                endpoint: 0,
                family: Family::V6
            })
        );
        base.before.clear();
        base.before.push(Rule {
            direction: Direction::Ingress,
            target: Target::Any,
            ..redirect
        });
        assert_eq!(
            compile(&base, &none, Options::default()),
            Err(CompileError::RedirectDirection {
                rule: 0,
                direction: Direction::Ingress
            })
        );
    }

    #[test]
    fn spec_compiles_deployment_and_policy() {
        let spec = Spec {
            deployment: Deployment::new(NodeKind::Guest, Mode::OwnIp),
            policy: BoxPolicy::default(),
            options: Options {
                refuse_errno: 111,
                log_flows: true,
            },
        };
        let c = spec.compile().unwrap();
        assert_eq!(c.config.defaults.egress, Verdict::Deny);
        assert!(c.config.source_check && c.config.log_flows);
        assert_eq!(c.config.refuse_errno, 111);
        assert!(c.to_string().contains("(the box itself)"));
    }

    #[test]
    fn a_box_whose_transport_enforces_gets_an_entry_that_refuses_nothing() {
        let mut deployment = Deployment::new(NodeKind::Native, Mode::OwnIp);
        deployment.addrs.v4 = Some("100.64.7.2".parse().unwrap());
        deployment.transport_enforces = true;
        let spec = Spec {
            deployment,
            policy: BoxPolicy {
                deny: vec!["10.0.0.0/8".parse().unwrap()],
                ..BoxPolicy::default()
            },
            options: Options::default(),
        };
        let compiled = spec.compile().unwrap();
        assert!(compiled.rules.is_empty());
        assert!(!compiled.config.source_check);
        for direction in Direction::ALL {
            assert_eq!(compiled.config.defaults.of(direction), Verdict::Allow);
        }
    }
}
