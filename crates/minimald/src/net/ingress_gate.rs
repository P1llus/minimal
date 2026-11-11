//! Which ports of a box take connections from outside it.
//!
//! The engine refuses a new inbound connection to a box with an address of
//! its own unless the port is published. A box's gate holds why each of its
//! ports is published: the box declares it, a process listens on it, or
//! `min net expose` opened it. It writes the engine's entry when the first
//! reason for a port appears and removes it with the last.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use boxes::core::ingress::{DynamicPortVerdict, IngressRules, ListenVerdict};
use boxes::{IngressPolicy, IpProto};
use netpol::{Protocols, base::PortOf};

use super::engine::{Engine, Installed};
use super::listens::Listeners;

#[derive(Default)]
struct Open {
    /// Ports a process of the box listens on and the box's rules publish.
    listening: BTreeSet<u16>,
    /// Ports `min net expose` opened.
    exposed: BTreeSet<u16>,
    /// Declared ports whose forward was taken away while the box runs.
    revoked: BTreeSet<u16>,
}

/// The engine's part of a published port.
pub(crate) trait Admission: Send + Sync {
    fn admit(&self, port: PortOf) -> Result<(), String>;
    fn refuse(&self, port: PortOf) -> Result<(), String>;
}

/// The ingress entries of one box in the engine.
pub(crate) struct EngineAdmission {
    pub(crate) engine: &'static Engine,
    pub(crate) of: Arc<Installed>,
}

impl Admission for EngineAdmission {
    fn admit(&self, port: PortOf) -> Result<(), String> {
        self.engine
            .publish(&self.of, port)
            .map_err(|error| error.to_string())
    }

    fn refuse(&self, port: PortOf) -> Result<(), String> {
        self.engine
            .unpublish(&self.of, port)
            .map_err(|error| error.to_string())
    }
}

/// The ingress side of one box at one address.
pub struct IngressGate {
    rules: IngressRules,
    /// The TCP ports the box declares. Each is open while the gate lives,
    /// unless it is revoked.
    declared: BTreeSet<u16>,
    open: Mutex<Open>,
    admission: Arc<dyn Admission>,
    /// The listening sockets of the box's namespace, where the engine
    /// records them.
    listeners: Option<Arc<dyn Listeners>>,
}

impl std::fmt::Debug for IngressGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressGate")
            .field("declared", &self.declared)
            .finish_non_exhaustive()
    }
}

const fn tcp(port: u16) -> PortOf {
    PortOf {
        protocols: Protocols::TCP,
        port,
    }
}

impl IngressGate {
    /// The gate of a box with `ingress`, with its declared ports open in
    /// the engine from here on.
    ///
    /// # Errors
    ///
    /// The engine's, when a declared port's entry cannot be written.
    pub(crate) fn new(
        ingress: Option<&IngressPolicy>,
        admission: Arc<dyn Admission>,
        listeners: Option<Arc<dyn Listeners>>,
    ) -> Result<Arc<Self>, String> {
        let rules = IngressRules::from_policy(ingress);
        for proto in [IpProto::Tcp, IpProto::Udp] {
            let protocols = if proto == IpProto::Tcp {
                Protocols::TCP
            } else {
                Protocols::UDP
            };
            for port in rules.declared(proto) {
                admission.admit(PortOf { protocols, port })?;
            }
        }
        Ok(Arc::new(Self {
            declared: rules.declared(IpProto::Tcp).collect(),
            rules,
            open: Mutex::default(),
            admission,
            listeners,
        }))
    }

    fn open(&self) -> std::sync::MutexGuard<'_, Open> {
        self.open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Changes the reasons a port is open, and makes the engine's entry
    /// follow when the port opens or closes with the change.
    fn change(&self, port: u16, change: impl FnOnce(&mut Open)) {
        let mut open = self.open();
        let before = self.admits(&open, port);
        change(&mut open);
        let after = self.admits(&open, port);
        if before == after {
            return;
        }
        let written = if after {
            self.admission.admit(tcp(port))
        } else {
            self.admission.refuse(tcp(port))
        };
        if let Err(error) = written {
            tracing::error!(port, open = after, %error, "a box's ingress entry could not be changed");
        }
    }

    /// Opens a port a process of the box listens on.
    pub(crate) fn admit_published(&self, port: u16) {
        self.change(port, |open| {
            open.listening.insert(port);
        });
    }

    pub(crate) fn withdraw_published(&self, port: u16) {
        self.change(port, |open| {
            open.listening.remove(&port);
        });
    }

    /// Opens a port `min net expose` asked for.
    pub(crate) fn admit_exposed(&self, port: u16) {
        self.change(port, |open| {
            open.exposed.insert(port);
        });
    }

    pub(crate) fn withdraw_exposed(&self, port: u16) {
        self.change(port, |open| {
            open.exposed.remove(&port);
        });
    }

    /// Closes a declared port for the rest of the gate's life, unless
    /// something else keeps it open.
    pub(crate) fn revoke_port(&self, port: u16) {
        self.change(port, |open| {
            open.revoked.insert(port);
        });
    }

    fn admits(&self, open: &Open, port: u16) -> bool {
        (self.declared.contains(&port) && !open.revoked.contains(&port))
            || open.listening.contains(&port)
            || open.exposed.contains(&port)
    }

    /// Whether a new TCP connection to `port` reaches the box.
    pub(crate) fn admits_tcp(&self, port: u16) -> bool {
        self.admits(&self.open(), port)
    }

    /// The TCP ports that are open beside the declared ones.
    pub(crate) fn runtime_published_tcp(&self) -> BTreeSet<u16> {
        let open = self.open();
        open.listening.union(&open.exposed).copied().collect()
    }

    /// The box's listening sockets, for the watcher that publishes them.
    /// `None` for a box no engine judges: nothing records its sockets.
    pub(crate) fn listeners(&self) -> Option<Arc<dyn Listeners>> {
        self.listeners.clone()
    }

    pub(crate) fn listen_verdict(&self, proto: IpProto, port: u16) -> ListenVerdict {
        self.rules.listen_verdict(proto, port)
    }

    pub(crate) fn dynamic_verdict(&self, port: u16) -> DynamicPortVerdict {
        self.rules.dynamic_verdict(port)
    }

    /// A gate that writes no entry anywhere, for a test of what decides
    /// above it.
    #[cfg(test)]
    pub(crate) fn detached(policy: &boxes::BoxPolicy) -> Arc<Self> {
        struct Nowhere;
        impl Admission for Nowhere {
            fn admit(&self, _: PortOf) -> Result<(), String> {
                Ok(())
            }
            fn refuse(&self, _: PortOf) -> Result<(), String> {
                Ok(())
            }
        }
        // Its listening sockets are the wildcard listeners of the test's
        // own process.
        let listeners = super::listeners::held_by_this_process(Ipv4Addr::UNSPECIFIED);
        Self::new(policy.ingress.as_ref(), Arc::new(Nowhere), Some(listeners))
            .expect("nothing to fail")
    }
}

impl Drop for IngressGate {
    fn drop(&mut self) {
        let open = self.open();
        let run_time = open.listening.union(&open.exposed).copied();
        let mut ports: Vec<PortOf> = run_time
            .filter(|port| !self.declared.contains(port))
            .map(tcp)
            .collect();
        for proto in [IpProto::Tcp, IpProto::Udp] {
            let protocols = if proto == IpProto::Tcp {
                Protocols::TCP
            } else {
                Protocols::UDP
            };
            ports.extend(
                self.rules
                    .declared(proto)
                    .map(|port| PortOf { protocols, port }),
            );
        }
        for port in ports {
            // The box's entry may be gone already, which closes every port.
            let _closed = self.admission.refuse(port);
        }
    }
}

/// The gates of the boxes that are attached, by their address on the
/// virtual network.
static LIVE: LazyLock<Mutex<HashMap<Ipv4Addr, Weak<IngressGate>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Makes `gate` the one [`live_gate`] finds at `lease`, for as long as it
/// lives.
pub(crate) fn register(lease: Ipv4Addr, gate: &Arc<IngressGate>) {
    let mut live = LIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    live.retain(|_, gate| gate.strong_count() > 0);
    live.insert(lease, Arc::downgrade(gate));
}

/// The gate of the box attached at `lease`, if one is.
pub(crate) fn live_gate(lease: Ipv4Addr) -> Option<Arc<IngressGate>> {
    LIVE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&lease)
        .and_then(Weak::upgrade)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::{DynamicIngress, PortMapping};

    #[derive(Default)]
    struct Journal(Mutex<Vec<String>>);

    impl Admission for Journal {
        fn admit(&self, port: PortOf) -> Result<(), String> {
            self.0.lock().unwrap().push(format!(
                "admit {}{}",
                if port.protocols == Protocols::UDP {
                    "udp "
                } else {
                    ""
                },
                port.port
            ));
            Ok(())
        }

        fn refuse(&self, port: PortOf) -> Result<(), String> {
            self.0.lock().unwrap().push(format!(
                "refuse {}{}",
                if port.protocols == Protocols::UDP {
                    "udp "
                } else {
                    ""
                },
                port.port
            ));
            Ok(())
        }
    }

    fn gate() -> (Arc<IngressGate>, Arc<Journal>) {
        let journal = Arc::new(Journal::default());
        let ingress = IngressPolicy {
            port_mappings: vec![
                PortMapping {
                    external_port: 18080,
                    internal_port: 8080,
                    proto: IpProto::Tcp,
                },
                PortMapping {
                    external_port: 5353,
                    internal_port: 53,
                    proto: IpProto::Udp,
                },
            ],
            dynamic_allowed_range: Some((3000, 3010)),
            dynamic_ingress: Some(DynamicIngress::Allow),
        };
        let gate = IngressGate::new(
            Some(&ingress),
            Arc::clone(&journal) as Arc<dyn Admission>,
            None,
        )
        .unwrap();
        (gate, journal)
    }

    fn take(journal: &Journal) -> Vec<String> {
        std::mem::take(&mut journal.0.lock().unwrap())
    }

    #[test]
    fn declared_ports_are_open_for_the_gates_life() {
        let (gate, journal) = gate();
        assert_eq!(take(&journal), ["admit 8080", "admit udp 53"]);
        assert!(gate.admits_tcp(8080));
        // A UDP declaration says nothing about TCP on the port.
        assert!(!gate.admits_tcp(53));
        // Exposing and withdrawing a declared port changes nothing.
        gate.admit_exposed(8080);
        gate.withdraw_exposed(8080);
        assert!(gate.admits_tcp(8080));
        assert!(take(&journal).is_empty());
        drop(gate);
        assert_eq!(take(&journal), ["refuse 8080", "refuse udp 53"]);
    }

    #[test]
    fn a_revoked_declared_port_closes_unless_something_else_holds_it_open() {
        let (gate, journal) = gate();
        take(&journal);
        gate.admit_exposed(8080);
        gate.revoke_port(8080);
        assert!(gate.admits_tcp(8080));
        assert!(take(&journal).is_empty());
        gate.withdraw_exposed(8080);
        assert!(!gate.admits_tcp(8080));
        assert_eq!(take(&journal), ["refuse 8080"]);
    }

    #[test]
    fn a_port_closes_with_the_last_reason_it_was_open() {
        let (gate, journal) = gate();
        take(&journal);
        gate.admit_published(3005);
        gate.admit_exposed(3005);
        assert_eq!(take(&journal), ["admit 3005"]);
        gate.withdraw_published(3005);
        assert!(gate.admits_tcp(3005));
        assert!(take(&journal).is_empty());
        gate.withdraw_exposed(3005);
        assert!(!gate.admits_tcp(3005));
        assert_eq!(take(&journal), ["refuse 3005"]);
        // Withdrawing what is not open writes nothing.
        gate.withdraw_published(3005);
        assert!(take(&journal).is_empty());
    }

    #[test]
    fn a_gate_that_goes_closes_what_it_opened_at_run_time() {
        let (gate, journal) = gate();
        gate.admit_published(3001);
        take(&journal);
        drop(gate);
        assert_eq!(
            take(&journal),
            ["refuse 3001", "refuse 8080", "refuse udp 53"]
        );
    }

    #[test]
    fn the_gate_at_an_address_is_found_while_it_lives() {
        let lease = Ipv4Addr::new(100, 64, 200, 9);
        let (gate, _journal) = gate();
        register(lease, &gate);
        assert!(live_gate(lease).is_some_and(|found| Arc::ptr_eq(&found, &gate)));
        drop(gate);
        assert!(live_gate(lease).is_none());
    }
}
