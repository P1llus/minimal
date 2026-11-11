//! Publishes the ports the processes of a box listen on.
//!
//! The engine keeps the listening TCP sockets of every box in a map. A
//! watcher reads the entries of one network namespace of one box, opens
//! the ports the box's ingress rules permit, and closes a port when its
//! last listener is gone. It reads when the engine reports a new listener
//! and every few seconds besides, so a report that was lost costs a delay
//! and no port.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use boxes::core::ingress::{IngressRules, ListenVerdict};
use boxes::{IpProto, PortMapping};
use futures::future::BoxFuture;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::publish::{self, Origin, PublishCtx, PublishError, Published};

/// How long the watcher goes without reading the map when nothing wakes it.
const POLL: Duration = Duration::from_secs(5);

/// The wait after a port's first failed open. Each further failure doubles
/// it, up to the longest.
const RETRY_FIRST: Duration = Duration::from_millis(500);
const RETRY_LONGEST: Duration = Duration::from_secs(30);

/// A listening TCP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Listener {
    /// The address the socket is bound to.
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
}

/// The listening sockets of one network namespace of one box.
pub(crate) trait Listeners: Send + Sync {
    /// The sockets that listen now.
    fn listening(&self) -> io::Result<Vec<Listener>>;

    /// Resolves when a socket of the box has started to listen since the
    /// last call resolved.
    fn changed(&self) -> BoxFuture<'_, ()>;
}

/// The ports among `listening` that a connection from outside the
/// namespace can reach: those of sockets bound to every address or to
/// `address`, the namespace's own. A socket bound to the loopback takes
/// nothing from outside.
pub(crate) fn reachable_ports(
    listening: &[Listener],
    address: std::net::Ipv4Addr,
) -> std::collections::HashSet<u16> {
    listening
        .iter()
        .filter(|listener| {
            listener.address.is_unspecified() || listener.address == IpAddr::V4(address)
        })
        .map(|listener| listener.port)
        .collect()
}

/// The listening sockets of one namespace of a box, read from the
/// engine's table.
pub(crate) struct EngineListeners {
    pub(crate) table: boxbpf::Listens,
    pub(crate) of: boxbpf::BoxId,
    pub(crate) netns: u64,
    /// Notified when the engine reports that a socket of the box started
    /// or stopped listening.
    pub(crate) wake: Arc<tokio::sync::Notify>,
}

impl Listeners for EngineListeners {
    fn listening(&self) -> io::Result<Vec<Listener>> {
        let listening = self
            .table
            .listening(self.of, self.netns)
            .map_err(io::Error::other)?;
        Ok(listening
            .into_iter()
            .map(|socket| Listener {
                address: socket.address,
                port: socket.port,
            })
            .collect())
    }

    fn changed(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.wake.notified())
    }
}

/// What became of the try to open a port.
pub(crate) enum Opened<T> {
    Open(T),
    /// Something else has the port open. It is not this watcher's to open
    /// or to close.
    Held,
    Failed(String),
}

/// What a watcher does with a port that should be open.
pub(crate) trait Sink: Send + Sync {
    /// What stands for an open port.
    type Open: Send;

    fn open(&self, port: u16) -> BoxFuture<'_, Opened<Self::Open>>;

    fn close(&self, port: u16, open: Self::Open) -> BoxFuture<'_, ()>;

    /// Called for the first failure of a port since it last opened or its
    /// listener last went away.
    fn failed(&self, port: u16, error: &str) -> BoxFuture<'_, ()>;
}

/// Publishes a listening port at the same port number outside.
pub(crate) struct PublishSink {
    pub(crate) ctx: Arc<PublishCtx>,
}

impl Sink for PublishSink {
    type Open = Published;

    fn open(&self, port: u16) -> BoxFuture<'_, Opened<Published>> {
        Box::pin(async move {
            let mapping = PortMapping {
                external_port: port,
                internal_port: port,
                proto: IpProto::Tcp,
            };
            match publish::publish(&self.ctx, mapping, Origin::Listen).await {
                Ok(published) => {
                    tracing::info!(
                        port,
                        listener = %published.forward().listener,
                        "published a port the box listens on"
                    );
                    Opened::Open(published)
                }
                Err(PublishError::Held { .. }) => Opened::Held,
                Err(error) => Opened::Failed(error.to_string()),
            }
        })
    }

    fn close(&self, port: u16, open: Published) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            match open.withdraw().await {
                Ok(closed) => tracing::info!(
                    port,
                    closed_connections = ?closed,
                    "unpublished a port the box no longer listens on"
                ),
                Err(error) => tracing::warn!(
                    port,
                    %error,
                    "the forward of a port the box no longer listens on could not be closed"
                ),
            }
        })
    }

    fn failed(&self, port: u16, error: &str) -> BoxFuture<'_, ()> {
        let error = error.to_owned();
        Box::pin(async move {
            publish::record_failure(&self.ctx, port, Origin::Listen, error).await;
        })
    }
}

/// What a watcher needs.
pub(crate) struct Watch<S> {
    pub(crate) listeners: Arc<dyn Listeners>,
    pub(crate) rules: IngressRules,
    /// The addresses of the namespace that are reachable from outside it.
    /// A socket bound to another address, the loopback's for one, takes no
    /// connection from outside, so its port is not opened.
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) sink: S,
}

/// A port whose open failed.
struct Failing {
    failures: u32,
    retry_at: Instant,
}

struct State<S: Sink> {
    watch: Watch<S>,
    open: BTreeMap<u16, S::Open>,
    failing: BTreeMap<u16, Failing>,
    /// Whether the last read of the map failed, so a broken map is logged
    /// once.
    unread: bool,
}

impl<S: Sink> State<S> {
    /// The ports that should be open: those a socket listens on at an
    /// address reachable from outside, and that the rules let listening
    /// publish.
    fn wanted(&self, listening: &[Listener]) -> BTreeSet<u16> {
        listening
            .iter()
            .filter(|listener| {
                listener.address.is_unspecified()
                    || self.watch.addresses.contains(&listener.address)
            })
            .map(|listener| listener.port)
            .filter(|port| {
                self.watch.rules.listen_verdict(IpProto::Tcp, *port) == ListenVerdict::Publish
            })
            .collect()
    }

    /// Reads the map once and makes the open ports match it.
    async fn pass(&mut self) {
        let listening = match self.watch.listeners.listening() {
            Ok(listening) => {
                self.unread = false;
                listening
            }
            Err(error) => {
                if !self.unread {
                    tracing::warn!(%error, "the box's listening sockets could not be read");
                }
                // What is open stays open: an unread map says nothing.
                self.unread = true;
                return;
            }
        };
        let wanted = self.wanted(&listening);
        let gone: Vec<u16> = self
            .open
            .keys()
            .filter(|port| !wanted.contains(port))
            .copied()
            .collect();
        for port in gone {
            if let Some(open) = self.open.remove(&port) {
                self.watch.sink.close(port, open).await;
            }
        }
        self.failing.retain(|port, _| wanted.contains(port));
        let now = Instant::now();
        for port in wanted {
            if self.open.contains_key(&port)
                || self
                    .failing
                    .get(&port)
                    .is_some_and(|failing| failing.retry_at > now)
            {
                continue;
            }
            match self.watch.sink.open(port).await {
                Opened::Open(open) => {
                    self.failing.remove(&port);
                    self.open.insert(port, open);
                }
                Opened::Held => {
                    self.failing.remove(&port);
                }
                Opened::Failed(error) => {
                    let failures = self.failing.get(&port).map_or(0, |f| f.failures) + 1;
                    if failures == 1 {
                        tracing::warn!(port, %error, "a port the box listens on could not be published");
                        self.watch.sink.failed(port, &error).await;
                    }
                    let wait = RETRY_FIRST
                        .saturating_mul(1 << (failures - 1).min(16))
                        .min(RETRY_LONGEST);
                    self.failing.insert(
                        port,
                        Failing {
                            failures,
                            retry_at: Instant::now() + wait,
                        },
                    );
                }
            }
        }
    }

    /// When to read the map again if nothing wakes the watcher first.
    fn next_read(&self) -> Instant {
        let poll = Instant::now() + POLL;
        self.failing
            .values()
            .map(|failing| failing.retry_at)
            .fold(poll, Instant::min)
    }

    async fn run(mut self, stop: CancellationToken) {
        loop {
            self.pass().await;
            tokio::select! {
                () = stop.cancelled() => break,
                () = self.watch.listeners.changed() => {}
                () = tokio::time::sleep_until(self.next_read()) => {}
            }
        }
        for (port, open) in std::mem::take(&mut self.open) {
            self.watch.sink.close(port, open).await;
        }
    }
}

/// A running watcher. Dropping it ends it without waiting, and what it
/// opened closes as its `Open` values drop.
pub(crate) struct Watcher {
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Watcher {
    /// Starts watching. `root` is the span the watcher's lines carry.
    pub(crate) fn start<S>(watch: Watch<S>, root: tracing::Span) -> Self
    where
        S: Sink + 'static,
    {
        let stop = CancellationToken::new();
        let state = State {
            watch,
            open: BTreeMap::new(),
            failing: BTreeMap::new(),
            unread: false,
        };
        let task = crate::traced::spawn_detached(root, state.run(stop.clone()));
        Self {
            stop,
            task: Some(task),
        }
    }

    /// Ends the watcher and returns once every port it opened is closed.
    pub(crate) async fn stop(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxes::DynamicIngress;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;

    #[derive(Default)]
    struct FakeListeners {
        listening: Mutex<Vec<Listener>>,
        unreadable: AtomicBool,
        wake: Notify,
    }

    impl FakeListeners {
        /// Sets what listens, without the engine's report.
        fn set(&self, listeners: &[(&str, u16)]) {
            *self.listening.lock().unwrap() = listeners
                .iter()
                .map(|(address, port)| Listener {
                    address: address.parse().unwrap(),
                    port: *port,
                })
                .collect();
        }

        /// Sets what listens and reports it.
        fn report(&self, listeners: &[(&str, u16)]) {
            self.set(listeners);
            self.wake.notify_one();
        }
    }

    impl Listeners for FakeListeners {
        fn listening(&self) -> io::Result<Vec<Listener>> {
            if self.unreadable.load(Ordering::SeqCst) {
                return Err(io::Error::other("the map is gone"));
            }
            Ok(self.listening.lock().unwrap().clone())
        }

        fn changed(&self) -> BoxFuture<'_, ()> {
            Box::pin(self.wake.notified())
        }
    }

    /// What a port's next opens return.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Answer {
        Open,
        Held,
        Fail,
    }

    #[derive(Default)]
    struct FakeSink {
        journal: Mutex<Vec<String>>,
        answers: Mutex<BTreeMap<u16, Answer>>,
    }

    impl FakeSink {
        fn answer(&self, port: u16, answer: Answer) {
            self.answers.lock().unwrap().insert(port, answer);
        }

        fn take(&self) -> Vec<String> {
            std::mem::take(&mut self.journal.lock().unwrap())
        }
    }

    impl Sink for Arc<FakeSink> {
        type Open = u16;

        fn open(&self, port: u16) -> BoxFuture<'_, Opened<u16>> {
            let answer = self
                .answers
                .lock()
                .unwrap()
                .get(&port)
                .copied()
                .unwrap_or(Answer::Open);
            let mut journal = self.journal.lock().unwrap();
            let opened = match answer {
                Answer::Open => {
                    journal.push(format!("open {port}"));
                    Opened::Open(port)
                }
                Answer::Held => {
                    journal.push(format!("held {port}"));
                    Opened::Held
                }
                Answer::Fail => {
                    journal.push(format!("try {port}"));
                    Opened::Failed("address already in use".into())
                }
            };
            Box::pin(std::future::ready(opened))
        }

        fn close(&self, port: u16, open: u16) -> BoxFuture<'_, ()> {
            assert_eq!(port, open);
            self.journal.lock().unwrap().push(format!("close {port}"));
            Box::pin(std::future::ready(()))
        }

        fn failed(&self, port: u16, error: &str) -> BoxFuture<'_, ()> {
            self.journal
                .lock()
                .unwrap()
                .push(format!("failed {port}: {error}"));
            Box::pin(std::future::ready(()))
        }
    }

    struct Bench {
        listeners: Arc<FakeListeners>,
        sink: Arc<FakeSink>,
        watcher: Watcher,
    }

    /// A watcher of a box at 100.64.1.7 that declares TCP 8080 and lets
    /// listening publish 3000 to 3010.
    fn bench() -> Bench {
        let listeners = Arc::new(FakeListeners::default());
        let sink = Arc::new(FakeSink::default());
        let watcher = Watcher::start(
            Watch {
                listeners: Arc::clone(&listeners) as Arc<dyn Listeners>,
                rules: IngressRules::new(
                    vec![(IpProto::Tcp, 8080)],
                    Some((3000, 3010)),
                    Some(DynamicIngress::Allow),
                ),
                addresses: vec!["100.64.1.7".parse().unwrap()],
                sink: Arc::clone(&sink),
            },
            tracing::info_span!(parent: None, "listens.test"),
        );
        Bench {
            listeners,
            sink,
            watcher,
        }
    }

    /// Lets the watcher run until it waits again, without moving the clock.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_reported_listener_is_published_at_once_and_unpublished_when_it_closes() {
        let bench = bench();
        settle().await;
        assert!(bench.sink.take().is_empty());
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        assert_eq!(bench.sink.take(), ["open 3005"]);
        // Nothing reports a close, so the next read finds it.
        bench.listeners.set(&[]);
        settle().await;
        assert!(bench.sink.take().is_empty());
        tokio::time::sleep(POLL).await;
        settle().await;
        assert_eq!(bench.sink.take(), ["close 3005"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listener_whose_report_was_lost_is_found_by_the_next_read() {
        let bench = bench();
        settle().await;
        bench.listeners.set(&[("100.64.1.7", 3001)]);
        let almost = Duration::from_millis(4999);
        tokio::time::sleep(almost).await;
        settle().await;
        assert!(bench.sink.take().is_empty());
        tokio::time::sleep(POLL.saturating_sub(almost)).await;
        settle().await;
        assert_eq!(bench.sink.take(), ["open 3001"]);
    }

    #[tokio::test(start_paused = true)]
    async fn only_ports_the_rules_let_listening_publish_are_opened() {
        let bench = bench();
        bench.listeners.report(&[
            // Outside the range.
            ("0.0.0.0", 2999),
            ("0.0.0.0", 3011),
            // Declared, so published already and not the watcher's.
            ("0.0.0.0", 8080),
            // Bound where nothing outside the box can connect.
            ("127.0.0.1", 3002),
            ("::1", 3003),
            ("100.64.9.9", 3004),
            // The IPv6 wildcard takes IPv4 connections too.
            ("::", 3006),
            ("100.64.1.7", 3007),
        ]);
        settle().await;
        assert_eq!(bench.sink.take(), ["open 3006", "open 3007"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_port_stays_open_until_its_last_listener_is_gone() {
        let bench = bench();
        bench
            .listeners
            .report(&[("0.0.0.0", 3005), ("100.64.1.7", 3005)]);
        settle().await;
        assert_eq!(bench.sink.take(), ["open 3005"]);
        bench.listeners.report(&[("100.64.1.7", 3005)]);
        settle().await;
        assert!(bench.sink.take().is_empty());
        // The one that is left cannot be reached from outside.
        bench.listeners.report(&[("127.0.0.1", 3005)]);
        settle().await;
        assert_eq!(bench.sink.take(), ["close 3005"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_port_that_does_not_open_is_tried_again_with_growing_waits() {
        let bench = bench();
        bench.sink.answer(3005, Answer::Fail);
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        // The first failure of the streak is the one that is recorded.
        assert_eq!(
            bench.sink.take(),
            ["try 3005", "failed 3005: address already in use"]
        );
        let mut waits = Vec::new();
        for _ in 0..8 {
            let before = Instant::now();
            while bench.sink.take().is_empty() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                settle().await;
            }
            waits.push(before.elapsed().as_millis() / 100);
        }
        // Half a second, doubled each time, up to thirty seconds.
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 300, 300]);

        bench.sink.answer(3005, Answer::Open);
        tokio::time::sleep(RETRY_LONGEST).await;
        settle().await;
        assert_eq!(bench.sink.take(), ["open 3005"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_streak_of_failures_is_recorded_again() {
        let bench = bench();
        bench.sink.answer(3005, Answer::Fail);
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        assert_eq!(bench.sink.take().len(), 2);
        // The listener goes away and comes back.
        bench.listeners.report(&[]);
        settle().await;
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        assert_eq!(
            bench.sink.take(),
            ["try 3005", "failed 3005: address already in use"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_port_something_else_holds_is_left_alone_and_taken_when_it_is_free() {
        let bench = bench();
        settle().await;
        bench.sink.answer(3005, Answer::Held);
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        assert_eq!(bench.sink.take(), ["held 3005"]);
        // The listener closes: nothing of the watcher's to close.
        bench.listeners.report(&[]);
        settle().await;
        assert!(bench.sink.take().is_empty());
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        assert_eq!(bench.sink.take(), ["held 3005"]);
        bench.sink.answer(3005, Answer::Open);
        tokio::time::sleep(POLL).await;
        settle().await;
        assert_eq!(bench.sink.take(), ["open 3005"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_map_that_cannot_be_read_closes_nothing() {
        let bench = bench();
        bench.listeners.report(&[("0.0.0.0", 3005)]);
        settle().await;
        bench.sink.take();
        bench.listeners.unreadable.store(true, Ordering::SeqCst);
        bench.listeners.report(&[]);
        settle().await;
        tokio::time::sleep(POLL * 3).await;
        settle().await;
        assert!(bench.sink.take().is_empty());
        bench.listeners.unreadable.store(false, Ordering::SeqCst);
        tokio::time::sleep(POLL).await;
        settle().await;
        assert_eq!(bench.sink.take(), ["close 3005"]);
    }

    #[tokio::test(start_paused = true)]
    async fn stopping_the_watcher_closes_what_it_opened() {
        let bench = bench();
        bench
            .listeners
            .report(&[("0.0.0.0", 3005), ("0.0.0.0", 3006)]);
        settle().await;
        bench.sink.take();
        bench.watcher.stop().await;
        assert_eq!(bench.sink.take(), ["close 3005", "close 3006"]);
    }

    mod publishing {
        use super::*;
        use crate::net::publish::{Admission, Forward, Forwarder};
        use minimald_rpc::PublishOrigin;
        use netpol::base::PortOf;

        /// A forwarder and an engine that note what they were asked.
        #[derive(Default)]
        struct Outside {
            journal: Mutex<Vec<String>>,
            in_use: AtomicBool,
        }

        impl Forwarder for Outside {
            fn open(
                &self,
                port: PortMapping,
                origin: PublishOrigin,
            ) -> BoxFuture<'_, Result<Forward, PublishError>> {
                Box::pin(async move {
                    if self.in_use.load(Ordering::SeqCst) {
                        return Err(PublishError::Forward(io::ErrorKind::AddrInUse.into()));
                    }
                    self.journal.lock().unwrap().push(format!(
                        "forward {}->{} {origin:?}",
                        port.external_port, port.internal_port
                    ));
                    Ok(Forward {
                        listener: ([127, 0, 64, 9], port.external_port).into(),
                        bound: true,
                    })
                })
            }

            fn close(
                &self,
                port: PortMapping,
                _: PublishOrigin,
            ) -> BoxFuture<'_, Result<Option<u64>, PublishError>> {
                self.journal
                    .lock()
                    .unwrap()
                    .push(format!("unforward {}", port.external_port));
                Box::pin(std::future::ready(Ok(Some(0))))
            }
        }

        impl Admission for Outside {
            fn admit(&self, _: PortOf) -> Result<(), String> {
                Ok(())
            }

            fn refuse(&self, _: PortOf) -> Result<(), String> {
                Ok(())
            }
        }

        #[tokio::test]
        async fn a_listening_port_is_published_at_its_own_number_and_recorded() {
            let outside = Arc::new(Outside::default());
            let dir = tempfile::tempdir().unwrap();
            let ctx = PublishCtx::new(
                "web".into(),
                Arc::clone(&outside) as Arc<dyn Forwarder>,
                Arc::clone(&outside) as Arc<dyn Admission>,
                dir.path().to_path_buf(),
            );
            let sink = PublishSink {
                ctx: Arc::clone(&ctx),
            };
            let Opened::Open(published) = sink.open(3005).await else {
                panic!("the port did not open");
            };
            // A second open of the port finds it held, by this very publish.
            assert!(matches!(sink.open(3005).await, Opened::Held));
            sink.close(3005, published).await;

            outside.in_use.store(true, Ordering::SeqCst);
            let Opened::Failed(error) = sink.open(3006).await else {
                panic!("the port opened");
            };
            sink.failed(3006, &error).await;

            assert_eq!(
                *outside.journal.lock().unwrap(),
                ["forward 3005->3005 Listen", "unforward 3005"]
            );
            let log = std::fs::read_to_string(crate::audit::log_path(dir.path())).unwrap();
            let outcomes: Vec<(u64, String)> = log
                .lines()
                .map(|line| {
                    let record: serde_json_lenient::Value =
                        serde_json_lenient::from_str(line).unwrap();
                    (
                        record["port"].as_u64().unwrap(),
                        record["outcome"].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            assert_eq!(
                outcomes,
                [
                    (3005, "published".to_owned()),
                    (3006, "publish-failed".to_owned())
                ]
            );
        }
    }
}
