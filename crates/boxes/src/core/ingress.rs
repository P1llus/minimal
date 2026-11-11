//! Which ports of a box may be published, decided from its declaration.
//!
//! A declared port is published when the box starts and stays until it
//! stops. Any other port is published at runtime, by `min net expose` or
//! because a process of the box listens on it, and only when the box's
//! dynamic setting and its permitted range allow it. Every caller that
//! publishes reads the answer here, so two of them cannot disagree about a
//! port.

use crate::{DynamicIngress, IngressPolicy, IpProto};

/// The ingress part of a box's network policy, in the form the decisions
/// read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressRules {
    /// The internal ports the declaration names, each with its transport.
    declared: Vec<(IpProto, u16)>,
    /// The range a port published at runtime must be in, inclusive at both
    /// ends. `None` permits no port.
    permitted: Option<(u16, u16)>,
    /// The box's dynamic setting. `None` means deny.
    dynamic: Option<DynamicIngress>,
}

impl IngressRules {
    #[must_use]
    pub fn new(
        declared: Vec<(IpProto, u16)>,
        permitted: Option<(u16, u16)>,
        dynamic: Option<DynamicIngress>,
    ) -> Self {
        Self {
            declared,
            permitted,
            dynamic,
        }
    }

    /// The rules of a box's ingress policy. A box with none declares no
    /// port and permits none at runtime.
    #[must_use]
    pub fn from_policy(ingress: Option<&IngressPolicy>) -> Self {
        let Some(ingress) = ingress else {
            return Self::default();
        };
        Self::new(
            ingress
                .port_mappings
                .iter()
                .map(|mapping| (mapping.proto, mapping.internal_port))
                .collect(),
            ingress.dynamic_allowed_range,
            ingress.dynamic_ingress,
        )
    }

    /// The internal ports the declaration names on `proto`.
    pub fn declared(&self, proto: IpProto) -> impl Iterator<Item = u16> + '_ {
        self.declared
            .iter()
            .filter(move |(declared, _)| *declared == proto)
            .map(|(_, port)| *port)
    }

    /// Whether the declaration names `port` on `proto`. The transport
    /// counts: a port declared for UDP alone is not declared for TCP.
    #[must_use]
    pub fn declares(&self, proto: IpProto, port: u16) -> bool {
        self.declared
            .iter()
            .any(|(declared, declared_port)| *declared == proto && *declared_port == port)
    }

    /// Whether `port` may be published at runtime. The setting decides
    /// before the range, so a box that denies does not show whether the
    /// port would have been in range.
    #[must_use]
    pub fn dynamic_verdict(&self, port: u16) -> DynamicPortVerdict {
        match self.dynamic {
            None | Some(DynamicIngress::Deny) => DynamicPortVerdict::Deny,
            Some(DynamicIngress::Ask) => DynamicPortVerdict::Ask,
            Some(DynamicIngress::Allow) => match self.permitted {
                None => DynamicPortVerdict::NoRange,
                Some((low, high)) if low <= port && port <= high => DynamicPortVerdict::Allow,
                Some(range) => DynamicPortVerdict::OutOfRange { range },
            },
        }
    }

    /// What to do about a port a process of the box listens on.
    ///
    /// Listening publishes a port only under `allow`. Under `ask` a person
    /// has to answer, and a listening socket is no answer.
    #[must_use]
    pub fn listen_verdict(&self, proto: IpProto, port: u16) -> ListenVerdict {
        if self.declares(proto, port) {
            return ListenVerdict::Declared;
        }
        match self.dynamic_verdict(port) {
            DynamicPortVerdict::Allow => ListenVerdict::Publish,
            DynamicPortVerdict::Deny
            | DynamicPortVerdict::Ask
            | DynamicPortVerdict::NoRange
            | DynamicPortVerdict::OutOfRange { .. } => ListenVerdict::Deny,
        }
    }
}

/// What a box's dynamic setting and permitted range say about one port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicPortVerdict {
    /// The setting is `allow` and the port is in the range.
    Allow,
    /// The setting is `deny` or absent.
    Deny,
    /// The setting is `ask`: a person decides.
    Ask,
    /// The setting is `allow` and the box names no range.
    NoRange,
    /// The setting is `allow` and the port is outside the range.
    OutOfRange {
        /// The box's range, inclusive at both ends.
        range: (u16, u16),
    },
}

/// What to do about a port a process of the box listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenVerdict {
    /// Publish it for as long as the process listens.
    Publish,
    /// The declaration names the port on this transport, so it is
    /// published already and stays published when the listener closes.
    Declared,
    /// Leave it unpublished.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PortMapping;

    fn rules(
        declared: &[(IpProto, u16)],
        range: Option<(u16, u16)>,
        dynamic: Option<DynamicIngress>,
    ) -> IngressRules {
        IngressRules::from_policy(Some(&IngressPolicy {
            port_mappings: declared
                .iter()
                .map(|(proto, port)| PortMapping {
                    external_port: port + 10_000,
                    internal_port: *port,
                    proto: *proto,
                })
                .collect(),
            dynamic_allowed_range: range,
            dynamic_ingress: dynamic,
        }))
    }

    #[test]
    fn the_setting_decides_before_the_range() {
        let range = Some((3000, 3010));
        for (dynamic, port, expected) in [
            (None, 3005, DynamicPortVerdict::Deny),
            (Some(DynamicIngress::Deny), 3005, DynamicPortVerdict::Deny),
            (Some(DynamicIngress::Ask), 3005, DynamicPortVerdict::Ask),
            (Some(DynamicIngress::Ask), 9, DynamicPortVerdict::Ask),
            (Some(DynamicIngress::Allow), 3000, DynamicPortVerdict::Allow),
            (Some(DynamicIngress::Allow), 3010, DynamicPortVerdict::Allow),
            (
                Some(DynamicIngress::Allow),
                2999,
                DynamicPortVerdict::OutOfRange {
                    range: (3000, 3010),
                },
            ),
            (
                Some(DynamicIngress::Allow),
                3011,
                DynamicPortVerdict::OutOfRange {
                    range: (3000, 3010),
                },
            ),
        ] {
            assert_eq!(
                rules(&[], range, dynamic).dynamic_verdict(port),
                expected,
                "{dynamic:?} {port}"
            );
        }
        assert_eq!(
            rules(&[], None, Some(DynamicIngress::Allow)).dynamic_verdict(3005),
            DynamicPortVerdict::NoRange
        );
        assert_eq!(
            IngressRules::from_policy(None).dynamic_verdict(3005),
            DynamicPortVerdict::Deny
        );
    }

    #[test]
    fn listening_publishes_only_under_allow_and_inside_the_range() {
        let allow = rules(&[], Some((3000, 3010)), Some(DynamicIngress::Allow));
        assert_eq!(
            allow.listen_verdict(IpProto::Tcp, 3005),
            ListenVerdict::Publish
        );
        assert_eq!(
            allow.listen_verdict(IpProto::Tcp, 3011),
            ListenVerdict::Deny
        );
        for held_back in [None, Some(DynamicIngress::Deny), Some(DynamicIngress::Ask)] {
            assert_eq!(
                rules(&[], Some((3000, 3010)), held_back).listen_verdict(IpProto::Tcp, 3005),
                ListenVerdict::Deny,
                "{held_back:?}"
            );
        }
        assert_eq!(
            rules(&[], None, Some(DynamicIngress::Allow)).listen_verdict(IpProto::Tcp, 3005),
            ListenVerdict::Deny
        );
    }

    #[test]
    fn a_declared_port_is_declared_on_its_own_transport_only() {
        let declared = [(IpProto::Tcp, 8080), (IpProto::Udp, 3005)];
        let open = rules(&declared, Some((3000, 3010)), Some(DynamicIngress::Allow));
        assert_eq!(
            open.listen_verdict(IpProto::Tcp, 8080),
            ListenVerdict::Declared
        );
        assert_eq!(
            open.listen_verdict(IpProto::Udp, 3005),
            ListenVerdict::Declared
        );
        // The UDP declaration says nothing about a TCP listener on the port.
        assert_eq!(
            open.listen_verdict(IpProto::Tcp, 3005),
            ListenVerdict::Publish
        );
        let closed = rules(&declared, None, None);
        assert_eq!(
            closed.listen_verdict(IpProto::Tcp, 8080),
            ListenVerdict::Declared
        );
        assert_eq!(
            closed.listen_verdict(IpProto::Tcp, 3005),
            ListenVerdict::Deny
        );
        assert_eq!(closed.declared(IpProto::Tcp).collect::<Vec<_>>(), [8080]);
        assert_eq!(closed.declared(IpProto::Udp).collect::<Vec<_>>(), [3005]);
        assert!(closed.declares(IpProto::Udp, 3005));
        assert!(!closed.declares(IpProto::Tcp, 3005));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// A listening port gets `Declared` exactly when the declaration names
    /// it on its transport, and `Publish` exactly when it is not declared,
    /// the setting is `allow` and the port is in the range. Checked for
    /// every setting, every range, the inverted one included, and every
    /// pair of declared ports.
    #[kani::proof]
    #[kani::unwind(4)]
    fn kani_listen_verdict_publishes_only_what_the_rules_permit() {
        let declared = if kani::any() {
            vec![(IpProto::Tcp, kani::any()), (IpProto::Udp, kani::any())]
        } else {
            Vec::new()
        };
        let range: Option<(u16, u16)> = kani::any::<bool>().then(|| (kani::any(), kani::any()));
        let dynamic = match (kani::any::<bool>(), kani::any::<bool>()) {
            (false, false) => None,
            (false, true) => Some(DynamicIngress::Allow),
            (true, false) => Some(DynamicIngress::Deny),
            (true, true) => Some(DynamicIngress::Ask),
        };
        let port: u16 = kani::any();
        let proto = if kani::any() {
            IpProto::Tcp
        } else {
            IpProto::Udp
        };
        let rules = IngressRules::new(declared.clone(), range, dynamic);
        let named = declared.iter().any(|(p, n)| *p == proto && *n == port);
        let in_range = range.is_some_and(|(low, high)| low <= port && port <= high);
        let expected = if named {
            ListenVerdict::Declared
        } else if dynamic == Some(DynamicIngress::Allow) && in_range {
            ListenVerdict::Publish
        } else {
            ListenVerdict::Deny
        };
        assert_eq!(rules.listen_verdict(proto, port), expected);
    }
}
