//! What a box was refused, as box events.
//!
//! Three sources report refusals: the policy programs in the kernel, the
//! box's resolver, and the hostname proxy. All send the same
//! [`Observation`]. One task limits them per box and appends what passes
//! to the box's event log, where `min box events` reads it.
//!
//! A later source of another kind (system calls, files) adds a variant to
//! [`Body`] and its own event type. Nothing here is specific to the network
//! beyond [`NetRefusal`].

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use boxes::events::{BoxEventType, EventData};
use serde_json_lenient::Value;

use crate::net::engine::Installed;

/// One thing observed about a box.
#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub(crate) of: Arc<Installed>,
    pub(crate) body: Body,
}

#[derive(Debug, Clone)]
pub(crate) enum Body {
    Net(NetRefusal),
}

/// Who refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    /// A policy program, at the hook named.
    Kernel(netpol::abi::Hook),
    Resolver,
    HostnameProxy,
}

impl Source {
    const fn name(self) -> &'static str {
        match self {
            Self::Kernel(_) => "kernel",
            Self::Resolver => "resolver",
            Self::HostnameProxy => "hostname_proxy",
        }
    }
}

/// The rule that decided, so a user can find it in their policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleRef {
    pub(crate) index: u16,
    /// Where the rule comes from: `allow_subnets`, `virtual network`, ...
    pub(crate) origin: String,
    pub(crate) text: String,
}

impl RuleRef {
    pub(crate) fn of(compiled: &netpol::Compiled, index: Option<u16>) -> Option<Self> {
        let index = index?;
        let rule = compiled.rules.get(usize::from(index))?;
        Some(Self {
            index,
            origin: rule.origin.to_string(),
            text: rule.to_string(),
        })
    }
}

/// A flow, a bind or a name the box's network policy refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetRefusal {
    pub(crate) source: Source,
    pub(crate) direction: netpol::Direction,
    pub(crate) protocol: Option<netpol::Protocol>,
    pub(crate) remote: Option<IpAddr>,
    pub(crate) port: Option<u16>,
    /// The name asked for, where the source knows it.
    pub(crate) name: Option<String>,
    pub(crate) reason: String,
    pub(crate) rule: Option<RuleRef>,
    pub(crate) pid: Option<u32>,
}

pub(crate) fn snake(value: &impl serde::Serialize) -> String {
    match serde_json_lenient::to_value(value) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}

impl NetRefusal {
    /// A refusal the kernel programs reported, for the box whose compiled
    /// policy is `compiled`.
    pub(crate) fn from_kernel(
        event: &netpol::event::NetEvent,
        compiled: &netpol::Compiled,
    ) -> Self {
        use netpol::abi::Hook;

        let direction = match event.hook {
            Hook::Bind4 | Hook::Bind6 => netpol::Direction::Bind,
            Hook::Ingress => netpol::Direction::Ingress,
            _ => netpol::Direction::Egress,
        };
        let protocol = match event.protocol {
            6 => Some(netpol::Protocol::Tcp),
            17 => Some(netpol::Protocol::Udp),
            1 | 58 => Some(netpol::Protocol::Icmp),
            _ => None,
        };
        // The other end of the flow: where an outbound one was headed,
        // where an inbound one came from, the address a bind asked for.
        let (remote, port) = match direction {
            netpol::Direction::Ingress => (event.src, event.dst_port),
            _ => (event.dst, event.dst_port),
        };
        Self {
            source: Source::Kernel(event.hook),
            direction,
            protocol,
            remote: (!remote.is_unspecified()).then_some(remote),
            port: (event.hook != Hook::SockCreate).then_some(port),
            name: None,
            reason: snake(&event.reason),
            rule: RuleRef::of(compiled, event.rule),
            pid: (event.pid != 0).then_some(event.pid),
        }
    }

    fn key(&self) -> Key {
        Key {
            source: self.source.name(),
            direction: self.direction,
            protocol: self.protocol,
            remote: self.remote,
            port: self.port,
            name: self.name.clone(),
        }
    }

    fn data(&self, repeats: u32) -> EventData {
        let mut data = EventData::new();
        let mut put = |key: &str, value: Value| {
            data.insert(key.to_owned(), value);
        };
        put("source", self.source.name().into());
        if let Source::Kernel(hook) = self.source {
            put("hook", snake(&hook).into());
        }
        put("direction", self.direction.to_string().into());
        if let Some(protocol) = self.protocol {
            put("protocol", protocol.to_string().into());
        }
        if let Some(remote) = self.remote {
            put("remote", remote.to_string().into());
        }
        if let Some(port) = self.port {
            put("port", port.into());
        }
        if let Some(name) = &self.name {
            put("name", name.clone().into());
        }
        put("reason", self.reason.clone().into());
        if let Some(rule) = &self.rule {
            put("rule", rule.index.into());
            put("rule_origin", rule.origin.clone().into());
            put("rule_text", rule.text.clone().into());
        }
        if let Some(pid) = self.pid {
            put("pid", pid.into());
        }
        if repeats > 0 {
            put("repeats", repeats.into());
        }
        data
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    source: &'static str,
    direction: netpol::Direction,
    protocol: Option<netpol::Protocol>,
    remote: Option<IpAddr>,
    port: Option<u16>,
    name: Option<String>,
}

/// A repeat of the same refusal within this time is counted, not written.
const REPEAT_WINDOW: Duration = Duration::from_secs(30);
/// A box writes at most [`BURST`] events per window of this length.
const BURST_WINDOW: Duration = Duration::from_secs(10);
const BURST: u32 = 20;
/// Distinct refusals remembered per box.
const KEYS_MAX: usize = 512;

#[derive(Debug)]
struct Seen {
    written: Instant,
    repeats: u32,
}

/// What the limiter lets through for one box.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Passed {
    /// Write the event, with this many repeats since it was last written.
    pub(crate) write: Option<u32>,
    /// Write a summary first: this many events fell to the burst limit in
    /// the window that just ended.
    pub(crate) suppressed: Option<u32>,
}

/// Keeps one box from flooding its event log.
#[derive(Debug)]
pub(crate) struct Limiter {
    seen: HashMap<Key, Seen>,
    window: Instant,
    written: u32,
    suppressed: u32,
}

impl Limiter {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            seen: HashMap::new(),
            window: now,
            written: 0,
            suppressed: 0,
        }
    }

    /// Ends the burst window when its time is up. Returns how many events
    /// it suppressed, if any.
    pub(crate) fn roll(&mut self, now: Instant) -> Option<u32> {
        if now.duration_since(self.window) < BURST_WINDOW {
            return None;
        }
        self.window = now;
        self.written = 0;
        let suppressed = std::mem::take(&mut self.suppressed);
        (suppressed > 0).then_some(suppressed)
    }

    fn admit(&mut self, key: Key, now: Instant) -> Passed {
        let suppressed = self.roll(now);
        if let Some(seen) = self.seen.get_mut(&key)
            && now.duration_since(seen.written) < REPEAT_WINDOW
        {
            seen.repeats = seen.repeats.saturating_add(1);
            return Passed {
                write: None,
                suppressed,
            };
        }
        if self.written >= BURST {
            self.suppressed = self.suppressed.saturating_add(1);
            return Passed {
                write: None,
                suppressed,
            };
        }
        if self.seen.len() >= KEYS_MAX
            && !self.seen.contains_key(&key)
            && let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, seen)| seen.written)
                .map(|(key, _)| key.clone())
        {
            self.seen.remove(&oldest);
        }
        let repeats = self
            .seen
            .insert(
                key,
                Seen {
                    written: now,
                    repeats: 0,
                },
            )
            .map_or(0, |earlier| earlier.repeats);
        self.written += 1;
        Passed {
            write: Some(repeats),
            suppressed,
        }
    }
}

fn summary(suppressed: u32) -> EventData {
    let mut data = EventData::new();
    data.insert("suppressed".to_owned(), suppressed.into());
    data.insert(
        "reason".to_owned(),
        "more refusals than the event log takes at once".into(),
    );
    data
}

/// The events to write for one observation, after the box's limiter.
pub(crate) fn limited(observation: &Observation, now: Instant) -> Vec<(BoxEventType, EventData)> {
    let Body::Net(refusal) = &observation.body;
    let passed = observation.of.limiter().admit(refusal.key(), now);
    let mut out = Vec::new();
    if let Some(suppressed) = passed.suppressed {
        out.push((BoxEventType::NetRefused, summary(suppressed)));
    }
    if let Some(repeats) = passed.write {
        out.push((BoxEventType::NetRefused, refusal.data(repeats)));
    }
    out
}

/// The summary a box owes when its burst window ended with events
/// suppressed and nothing came after to carry the count.
pub(crate) fn overdue(of: &Installed, now: Instant) -> Option<(BoxEventType, EventData)> {
    of.limiter()
        .roll(now)
        .map(|suppressed| (BoxEventType::NetRefused, summary(suppressed)))
}

/// Where a box's events are appended.
pub(crate) trait Log: Send + Sync + std::fmt::Debug {
    fn append(&self, kind: BoxEventType, data: EventData);
}

/// The box's `events.jsonl`, through the daemon's event writer.
#[derive(Debug)]
pub(crate) struct DiskLog(pub(crate) boxes::store::DiskBox);

impl Log for DiskLog {
    fn append(&self, kind: BoxEventType, data: EventData) {
        if let Err(error) = crate::box_manager::write_box_event(&self.0, kind, data) {
            tracing::warn!(%error, "a box event could not be written");
        }
    }
}

/// Takes observations until every sender is gone, and writes what the
/// limiters pass. The append locks and syncs a file, so it runs off the
/// async workers.
pub(crate) async fn sink(
    mut observations: tokio::sync::mpsc::Receiver<Observation>,
    boxes: impl Fn() -> Vec<Arc<Installed>> + Send + 'static,
) {
    let mut tick = tokio::time::interval(BURST_WINDOW);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let writes: Vec<(Arc<Installed>, BoxEventType, EventData)> = tokio::select! {
            observation = observations.recv() => {
                let Some(observation) = observation else { return };
                limited(&observation, Instant::now())
                    .into_iter()
                    .map(|(kind, data)| (Arc::clone(&observation.of), kind, data))
                    .collect()
            }
            _ = tick.tick() => {
                let now = Instant::now();
                boxes()
                    .into_iter()
                    .filter_map(|of| overdue(&of, now).map(|(kind, data)| (of, kind, data)))
                    .collect()
            }
        };
        if writes.is_empty() {
            continue;
        }
        let written = crate::traced::spawn_blocking(move || {
            for (of, kind, data) in writes {
                of.log().append(kind, data);
            }
        })
        .await;
        if let Err(error) = written {
            tracing::warn!(%error, "writing box events");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> Key {
        Key {
            source: "kernel",
            direction: netpol::Direction::Egress,
            protocol: Some(netpol::Protocol::Tcp),
            remote: Some("192.0.2.1".parse().expect("address")),
            port: Some(port),
            name: None,
        }
    }

    #[test]
    fn a_repeat_is_counted_and_carried_by_the_next_written_event() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        assert_eq!(limiter.admit(key(443), start).write, Some(0));
        for second in 1..=5 {
            let passed = limiter.admit(key(443), start + Duration::from_secs(second));
            assert_eq!(passed.write, None);
        }
        // Another destination is its own event.
        assert_eq!(limiter.admit(key(80), start).write, Some(0));
        let later = start + REPEAT_WINDOW + Duration::from_secs(1);
        assert_eq!(limiter.admit(key(443), later).write, Some(5));
    }

    #[test]
    fn a_burst_is_cut_and_summed_up_once() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        let written = (0..200)
            .filter(|port| limiter.admit(key(*port), start).write.is_some())
            .count();
        assert_eq!(written, BURST as usize);
        assert_eq!(limiter.roll(start + Duration::from_secs(1)), None);
        let next = start + BURST_WINDOW;
        let passed = limiter.admit(key(9000), next);
        assert_eq!(passed.suppressed, Some(180));
        assert_eq!(passed.write, Some(0));
        assert_eq!(limiter.roll(next + BURST_WINDOW), None);
    }

    #[test]
    fn the_refusals_remembered_per_box_are_bounded() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        for (i, port) in (0..2000_u16).enumerate() {
            // Spread over time so the burst limit does not interfere.
            let now = start + BURST_WINDOW * u32::try_from(i).expect("fits");
            limiter.admit(key(port), now);
        }
        assert_eq!(limiter.seen.len(), KEYS_MAX);
    }

    #[test]
    fn a_kernel_event_names_the_rule_that_decided() {
        use netpol::{
            BoxPolicy, Spec,
            base::{Deployment, Mode, NodeKind},
            event::{NetEvent, Outcome},
        };

        let spec = Spec {
            deployment: Deployment::new(NodeKind::Native, Mode::HostIp),
            policy: BoxPolicy {
                deny: vec!["10.0.0.0/8".parse().expect("prefix")],
                ..BoxPolicy::default()
            },
            options: crate::net::spec::OPTIONS,
        };
        let compiled = spec.compile().expect("compile");
        let rule = compiled
            .rules
            .iter()
            .position(|r| r.origin == netpol::Origin::BoxDeny)
            .expect("the deny rule");
        let event = NetEvent {
            box_id: 7,
            time_ns: 1,
            hook: netpol::abi::Hook::Connect4,
            outcome: Outcome::Denied,
            reason: netpol::abi::Reason::Rule,
            rule: Some(u16::try_from(rule).expect("fits")),
            protocol: 6,
            sock_type: 1,
            src: "0.0.0.0".parse().expect("address"),
            src_port: 0,
            dst: "10.1.2.3".parse().expect("address"),
            dst_port: 443,
            pid: 4242,
            cookie: 0,
        };
        let refusal = NetRefusal::from_kernel(&event, &compiled);
        let data = refusal.data(3);
        let text = |key: &str| data.get(key).and_then(Value::as_str).map(str::to_owned);
        assert_eq!(text("source").as_deref(), Some("kernel"));
        assert_eq!(text("hook").as_deref(), Some("connect4"));
        assert_eq!(text("direction").as_deref(), Some("egress"));
        assert_eq!(text("protocol").as_deref(), Some("tcp"));
        assert_eq!(text("remote").as_deref(), Some("10.1.2.3"));
        assert_eq!(text("reason").as_deref(), Some("rule"));
        assert_eq!(text("rule_origin").as_deref(), Some("deny_subnets"));
        assert_eq!(data.get("port").and_then(Value::as_u64), Some(443));
        assert_eq!(data.get("pid").and_then(Value::as_u64), Some(4242));
        assert_eq!(data.get("repeats").and_then(Value::as_u64), Some(3));
    }
}
