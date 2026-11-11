//! One-line progress for the in-sandbox `min` helper.
//!
//! The helper speaks a line protocol (`msg:`, `set_env:`, `error:`). A fetch
//! already records byte progress on the session [`OpTracker`], but the helper
//! can only redraw a single line, so this paints that tree as one `bar:` line
//! the helper reprints in place. An empty `bar:` tells the helper to clear the
//! row. Byte fetches win over status rows: several packages downloading at
//! once collapse into one meter.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use common::fetchers::AnyUrl;
use futures::{Stream, StreamExt as _};
use ot::{OpId, OpSnapshot, OpStartHook, OpTracker, Operation, Progress};

/// Width of the package-name field, so the meter stays put as names change.
const NAME_WIDTH: usize = 18;
/// Cells inside the `[` `]` meter.
const BAR_WIDTH: usize = 16;
/// ~12 Hz, the same cap the SSH progress renderer uses. A fetch reports every
/// chunk; painting each one would flood the socket.
const PAINT_INTERVAL: Duration = Duration::from_millis(80);

/// Drives `bar:` lines from a session operation tree.
///
/// A missing tracker means this install has nothing to paint; [`refresh`] is a
/// no-op and the helper keeps the one-shot `msg:` lines.
///
/// [`refresh`]: SandboxProgress::refresh
pub(crate) struct SandboxProgress {
    tracker: Option<OpTracker>,
    /// Package names this run builds. The tracker is the whole session's, so a
    /// task building in another shell reports into it too; `None` shows every
    /// package row.
    scope: Option<HashSet<String>>,
    /// Every fetch seen since downloads last went idle, finished ones included,
    /// so the meter totals never shrink when one download of several completes.
    fetches: BTreeMap<OpId, Fetch>,
    /// NET-080: the hook recording this install's fetches as each starts;
    /// `None` records nothing, which is every progress but an install's.
    /// Dropped with the progress, so the record ends with the install.
    _fetch_hook: Option<OpStartHook>,
    /// Last line written, so an unchanged tree does not repaint.
    last: Option<String>,
}

impl SandboxProgress {
    pub(crate) fn new(tracker: Option<OpTracker>, scope: Option<HashSet<String>>) -> Self {
        Self {
            tracker,
            scope,
            fetches: BTreeMap::new(),
            _fetch_hook: None,
            last: None,
        }
    }

    /// NET-080: records each fetch this install triggers as node-plane
    /// traffic, under [`FetchRecord`]'s context — the daemon's own fetches,
    /// made for the box that asked, each named with the host it left for
    /// and the object it brought back.
    ///
    /// Recorded from the tracker's op-start hook, not the meter: the meter
    /// reads a snapshot every paint, and a fetch that starts and ends between
    /// two paints has left the tree before the next, so a record taken there
    /// would miss it. The hook sees every op the tree starts, exactly once.
    /// Without a tracker there is no fetch to see and nothing is recorded.
    pub(crate) fn with_fetch_record(mut self, record: FetchRecord) -> Self {
        if let Some(tracker) = &self.tracker {
            let scope = self.scope.clone();
            self._fetch_hook =
                Some(tracker.on_op_start(move |op| record_fetch(&record, scope.as_ref(), op)));
        }
        self
    }

    /// Writes a `bar:` line when the visible text changed; an empty one when
    /// the meter went away, so the helper clears the row.
    ///
    /// A client that has gone away must not fail the install the bar is
    /// describing; the download still completes.
    pub(crate) fn refresh(&mut self, stream: &mut UnixStream) {
        let Some(tracker) = &self.tracker else {
            return;
        };
        let line = self.line(&tracker.snapshot());
        if line == self.last {
            return;
        }
        let _ = writeln!(stream, "bar:{}", line.as_deref().unwrap_or(""));
        self.last = line;
    }

    /// Writes a `msg:` line. The helper clears the meter to print it, so the
    /// next [`refresh`] repaints even when the meter has not moved.
    ///
    /// [`refresh`]: SandboxProgress::refresh
    pub(crate) fn message(&mut self, stream: &mut UnixStream, text: &str) {
        let _ = writeln!(stream, "msg:{text}");
        self.last = None;
    }

    /// The single line to show for `snapshot`, or `None` when nothing relevant
    /// is in flight. Check and test rows are omitted so a concurrent
    /// `min check` does not take over an add's meter.
    fn line(&mut self, snapshot: &[OpSnapshot]) -> Option<String> {
        let mut live = HashSet::new();
        let mut statuses = Vec::new();
        for row in snapshot {
            let Some(op) = &row.op else { continue };
            let Progress { pos, len } = row.progress.unwrap_or(Progress { pos: 0, len: None });
            // A zero length (chunked transfer, no Content-Length) is an
            // unknown one: a meter drawn against it would read full at once.
            let len = len.filter(|n| *n > 0);
            match self.activity(op) {
                Some(Activity::Fetch(name)) => {
                    live.insert(row.id);
                    self.fetches.insert(
                        row.id,
                        Fetch {
                            name,
                            pos,
                            len,
                            live: true,
                        },
                    );
                }
                Some(Activity::Status(status)) => statuses.push(status),
                None => {}
            }
        }
        // A fetch no longer reporting (its row dropped, or moved on to
        // extracting) is finished: count it as complete. One whose length was
        // never known is as long as what it received, so it cannot hide the
        // meter of the fetches still running beside it.
        for (id, fetch) in &mut self.fetches {
            if fetch.live && !live.contains(id) {
                fetch.live = false;
                match fetch.len {
                    Some(len) => fetch.pos = len,
                    None => fetch.len = Some(fetch.pos),
                }
            }
        }

        if !live.is_empty() {
            return Some(format_fetches(self.fetches.values()));
        }
        // No download in flight: a later fetch (after an extract or a build)
        // starts a fresh meter instead of inheriting these totals.
        self.fetches.clear();
        if statuses.is_empty() {
            return None;
        }
        Some(truncate(&statuses.join(", "), 60))
    }

    fn activity(&self, op: &Operation) -> Option<Activity> {
        let in_scope = |name: &str| self.scope.as_ref().is_none_or(|s| s.contains(name));
        match op {
            Operation::FetchPkg { name } if in_scope(name) => Some(Activity::Fetch(name.clone())),
            // Neither names a package, so neither can be scoped; both are
            // rare mid-install and belong to whatever is building.
            Operation::FetchSource { url } => Some(Activity::Fetch(url.clone())),
            Operation::FetchIndex => Some(Activity::Fetch("index".to_string())),
            Operation::ExtractPkg { name } if in_scope(name) => {
                Some(Activity::Status(format!("Extract {name}")))
            }
            Operation::PackageBuild { name } if in_scope(name) => {
                Some(Activity::Status(format!("Building {name}")))
            }
            Operation::CompressPkg { name } if in_scope(name) => {
                Some(Activity::Status(format!("Compress {name}")))
            }
            Operation::CollectOutputs { name, .. } if in_scope(name) => {
                Some(Activity::Status(format!("Collect {name}")))
            }
            _ => None,
        }
    }
}

/// NET-080: one node-plane record for the fetch `op` names, under the
/// [`FetchRecord`] an install was started with: the box the fetch was made
/// for, and — per operation, the same division the meter shows — the host it
/// leaves for and the object it brings back. A package or the index is
/// fetched from the configured remote cache. A source a package declares is
/// a package build's traffic (NET-155), never the node plane's, so it is not
/// recorded. Scoping is the meter's own: a package outside the install's
/// `scope` is not this install's fetch, while the index names no package to
/// scope by and is attributed to whatever is building, the same caveat the
/// meter's row carries. Run from the tracker's op-start hook, once per op as
/// it starts.
fn record_fetch(record: &FetchRecord, scope: Option<&HashSet<String>>, op: &Operation) {
    let (host, object) = match op {
        Operation::FetchPkg { name } if scope.is_none_or(|s| s.contains(name)) => (
            record.cache_host.clone(),
            record
                .objects
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone()),
        ),
        // A source with no scheme is a tarball read off the operator's
        // own disk: it crosses no network, so it is no node-plane fetch.
        Operation::FetchSource { url } if !url.contains("://") => return,
        // A source is a package build's traffic, under the box's rules
        // (NET-155), and never the node plane's.
        Operation::FetchSource { url } => {
            tracing::debug!(
                box_id = %record.box_id,
                host = %url_host(url),
                object = %url_object(url),
                "a source is the box's own fetch, so the node plane keeps no record of it",
            );
            return;
        }
        Operation::FetchIndex => (record.cache_host.clone(), "index".to_owned()),
        _ => return,
    };
    tracing::info!(
        host = %host,
        box_id = %record.box_id,
        object = %object,
        "the daemon's own fetch is node-plane traffic, made in the daemon's own process and \
         never the box's"
    );
}

/// The host a fetch location is fetched from, spelled for the two forms the
/// configured remote cache takes: the mirror URL's own host, or the bucket
/// a GCS location names. The mirror's host is read from the URL the
/// newtype holds — its own `host_str` for the host, its own `port` for the
/// port — never from a rendering of it: a `Debug` print is a formatting
/// choice of the newtype's, and a spelling that changes with it changes
/// which host the record names while nothing else does. The port rides the
/// one rule every fetch kind's host field carries: a mirror on a
/// non-default port is named with it, one on https's own default without.
pub(crate) fn cache_host(location: &AnyUrl) -> String {
    match location {
        // The mirror is an https location, so the one port rule reads its
        // scheme as https: 443 is the default it drops.
        AnyUrl::Https(https) => {
            host_field(https.host_str().unwrap_or_default(), https.port(), "https")
        }
        AnyUrl::Gcs(gcs) => gcs.bucket.clone(),
    }
}

/// The host inside an authority: the authority minus any userinfo before
/// the last `@`. A `FetchSource` URL may carry a credential in its userinfo
/// (`https://<token>@github.com/…`), and the record is a log line a bundle
/// keeps on disk, so no spelling it writes carries one; the host the fetch
/// left for is the host, never the credential before it.
fn authority_host(authority: &str) -> &str {
    match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    }
}

/// The port a fetch record's host field carries, one rule for both
/// spellings a fetch's host is read from — the configured cache's
/// location and a source URL: the port the fetch's URL spells, kept when
/// it is not the scheme's own default and dropped when it is (443 for
/// `https`, 80 for `http`). A non-default port is the one way two
/// fetches of the same host differ, so the record keeps it the same way
/// for every fetch kind; a default port is a fact the scheme already
/// says, so the field never carries it.
fn kept_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    match (scheme, port) {
        ("https", Some(443)) | ("http", Some(80)) => None,
        (_, port) => port,
    }
}

/// The host a fetch's record names — `host` with the port [`kept_port`]
/// keeps — one spelling for both spellings the host is read from, so the
/// field reads the same way whatever the fetch left for.
fn host_field(host: &str, port: Option<u16>, scheme: &str) -> String {
    match kept_port(scheme, port) {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// The host a URL names — its authority, between the scheme and the first
/// path, query, or fragment delimiter, with any userinfo dropped and the
/// port carried only as the one rule every fetch kind's host field
/// carries it — which is where a `FetchSource` fetch leaves for. A
/// spelling with no scheme (a local source tarball) names no host and
/// crosses no network: the record's object still carries the whole
/// spelling, so the fetch is read whole from the two fields.
fn url_host(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    let authority = authority_host(rest.split(['/', '?', '#']).next().unwrap_or_default());
    // The port the authority spells after its last colon, when what
    // follows that colon is one: the colons inside a bracketed IPv6
    // literal are not a port, so an authority that spells none is the
    // host whole.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    };
    host_field(host, port, scheme)
}

/// The object a `FetchSource` record names its fetch by: the URL's own
/// spelling minus the parts that never belong in a log line — the userinfo
/// before the last `@` (a credential), and the query and fragment after the
/// path (a query is where a signed URL carries its signature). A spelling
/// with no scheme (a local source tarball) names no host and crosses no
/// network, and is the object whole: the way the record has always spelled
/// a source it read off the operator's own disk.
fn url_object(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let before_query = rest.split(['?', '#']).next().unwrap_or_default();
    let (authority, path) = match before_query.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (before_query, String::new()),
    };
    format!("{scheme}://{}{path}", authority_host(authority))
}

/// What an install knows when it starts, so each fetch's record carries only
/// the fetch's own facts: the box the fetch was made for, the host the
/// configured remote cache is fetched from, and the object each package in
/// the install's scope is spelled as.
pub(crate) struct FetchRecord {
    /// The requesting box.
    pub(crate) box_id: String,
    /// The host the daemon's cache fetches — packages and the index — leave
    /// for, spelled from the configured remote cache.
    pub(crate) cache_host: String,
    /// The object each in-scope package fetch is recorded as: its name with
    /// the upstream version appended when the graph knows one — the same
    /// spelling `min search` answers with.
    pub(crate) objects: BTreeMap<String, String>,
}

/// Relays `events` to the helper through `on_event` until the stream ends,
/// painting the meter between them, then clears it.
pub(crate) async fn relay<T>(
    stream: &mut UnixStream,
    mut progress: SandboxProgress,
    mut events: impl Stream<Item = T> + Unpin,
    mut on_event: impl FnMut(T, &mut SandboxProgress, &mut UnixStream),
) {
    let mut tick = tokio::time::interval(PAINT_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` is ready immediately. Consume that tick so the first paint
    // waits until a fetch has had a chance to report progress.
    tick.tick().await;

    loop {
        tokio::select! {
            biased;
            event = events.next() => {
                let Some(event) = event else { break };
                on_event(event, &mut progress, stream);
            }
            _ = tick.tick() => progress.refresh(stream),
        }
    }
    progress.refresh(stream);
}

struct Fetch {
    name: String,
    pos: u64,
    len: Option<u64>,
    live: bool,
}

enum Activity {
    Fetch(String),
    Status(String),
}

/// Names the live fetches; sizes cover every fetch this run has seen.
fn format_fetches<'a>(fetches: impl Iterator<Item = &'a Fetch> + Clone) -> String {
    let names = fetches
        .clone()
        .filter(|fetch| fetch.live)
        .map(|fetch| fetch.name.as_str())
        .collect::<Vec<_>>();
    let names = pad(&truncate(&join_names(&names), NAME_WIDTH), NAME_WIDTH);
    let pos = fetches
        .clone()
        .fold(0u64, |acc, fetch| acc.saturating_add(fetch.pos));
    // A missing length on a live fetch means the total is unknown (zero
    // lengths are already `None`). A total of zero is only possible for
    // finished fetches that received nothing; there is no meter to draw.
    let len = fetches
        .clone()
        .try_fold(0u64, |acc, fetch| fetch.len.map(|n| acc.saturating_add(n)))
        .filter(|n| *n > 0);

    match len {
        Some(len) => {
            let shown = pos.min(len);
            format!(
                "Fetch {names} {} {:>10} / {:>10}",
                render_bar(shown, len),
                human_bytes(shown),
                human_bytes(len),
            )
        }
        None => format!("Fetch {names} {:>10}", human_bytes(pos)),
    }
}

/// `go`, `go, gcc`, or `go +2` once a third name would no longer fit.
fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [a, b] => format!("{a}, {b}"),
        [a, rest @ ..] => format!("{a} +{}", rest.len()),
    }
}

fn render_bar(pos: u64, len: u64) -> String {
    let filled = ((pos as u128 * BAR_WIDTH as u128) / len as u128) as usize;
    let filled = filled.min(BAR_WIDTH);
    let body = match filled {
        0 => format!(">{}", " ".repeat(BAR_WIDTH - 1)),
        BAR_WIDTH => "=".repeat(BAR_WIDTH),
        n => format!("{}>{}", "=".repeat(n - 1), " ".repeat(BAR_WIDTH - n)),
    };
    format!("[{body}]")
}

fn human_bytes(n: u64) -> String {
    size::Size::from_bytes(n)
        .format()
        .with_style(size::Style::Abbreviated)
        .to_string()
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let keep = width.saturating_sub(3);
        let truncated: String = s.chars().take(keep).collect();
        format!("{truncated}...")
    }
}

fn pad(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn fetch(root: &OpTracker, name: &str, len: u64, pos: u64) -> OpTracker {
        let op = root.new_child().with_op(Operation::FetchPkg {
            name: name.to_string(),
        });
        op.set_length(len);
        op.increment(pos);
        op
    }

    fn line(root: &OpTracker) -> Option<String> {
        SandboxProgress::new(None, None).line(&root.snapshot())
    }

    fn read_lines(stream: &UnixStream) -> Vec<String> {
        BufReader::new(stream)
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .expect("peer writes utf-8 lines")
    }

    #[test]
    fn a_partial_fetch_draws_a_meter_with_sizes() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 256);

        let line = line(&root).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(line.contains("[===>            ]"), "{line}");
        assert!(line.contains("256 B"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    #[test]
    fn a_finished_fetch_fills_the_meter() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 1024);

        let line = line(&root).expect("a fetch is visible");
        assert!(line.contains("[================]"), "{line}");
    }

    #[test]
    fn concurrent_fetches_share_one_meter() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 512);
        let _gcc = fetch(&root, "gcc", 1024, 512);

        let line = line(&root).expect("fetches are visible");
        assert!(line.contains("go, gcc"), "{line}");
        // 1024/2048 is half of the 16-cell meter: seven fills, a head, eight blanks.
        assert!(line.contains("[=======>        ]"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn a_completed_fetch_keeps_counting_toward_the_total() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let small = fetch(&root, "sqlite", 1024, 512);
        let _big = fetch(&root, "llvm", 3072, 1024);
        let before = progress
            .line(&root.snapshot())
            .expect("fetches are visible");
        assert!(before.contains("1.50 KiB"), "{before}");
        assert!(before.contains("4.00 KiB"), "{before}");

        // sqlite finishes: it leaves the name list, but its bytes stay in the
        // totals, so the meter moves forward instead of jumping back.
        drop(small);
        let after = progress.line(&root.snapshot()).expect("llvm is live");
        assert!(after.starts_with("Fetch llvm "), "{after}");
        assert!(!after.contains("sqlite"), "{after}");
        assert!(after.contains("2.00 KiB"), "{after}");
        assert!(after.contains("4.00 KiB"), "{after}");
    }

    #[test]
    fn a_fetch_moving_on_to_extract_counts_as_complete() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let go = fetch(&root, "go", 1024, 100);
        let _gcc = fetch(&root, "gcc", 1024, 0);
        progress.line(&root.snapshot());

        go.set_op(Operation::ExtractPkg {
            name: "go".to_string(),
        });
        let line = progress.line(&root.snapshot()).expect("gcc is live");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn a_finished_unknown_length_fetch_does_not_hide_the_meter() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let chunked = root.new_child().with_op(Operation::FetchPkg {
            name: "index-ish".to_string(),
        });
        chunked.increment(1024);
        let _go = fetch(&root, "go", 1024, 0);
        let before = progress
            .line(&root.snapshot())
            .expect("fetches are visible");
        assert!(!before.contains('['), "{before}");

        // Finished, it counts as the 1 KiB it received: go's meter returns.
        drop(chunked);
        let after = progress.line(&root.snapshot()).expect("go is live");
        assert!(after.contains("[=======>        ]"), "{after}");
        assert!(after.contains("2.00 KiB"), "{after}");
    }

    #[test]
    fn a_zero_length_is_unknown_and_never_counts_backwards() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let chunked = fetch(&root, "sqlite", 0, 5120);
        let _go = fetch(&root, "go", 1024, 0);

        // A zero length is not a total: no meter, just the bytes so far.
        let before = progress
            .line(&root.snapshot())
            .expect("fetches are visible");
        assert!(!before.contains('['), "{before}");
        assert!(before.contains("5.00 KiB"), "{before}");

        // Finished, its bytes stay counted rather than dropping to zero.
        drop(chunked);
        let after = progress.line(&root.snapshot()).expect("go is live");
        assert!(after.contains("5.00 KiB / "), "{after}");
        assert!(after.contains("6.00 KiB"), "{after}");
    }

    #[test]
    fn a_fetch_after_an_idle_gap_starts_a_fresh_meter() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let go = fetch(&root, "go", 4096, 4096);
        progress.line(&root.snapshot());
        drop(go);
        let build = root.new_child().with_op(Operation::PackageBuild {
            name: "gcc".to_string(),
        });
        assert_eq!(
            progress.line(&root.snapshot()).as_deref(),
            Some("Building gcc")
        );
        drop(build);

        let _gcc = fetch(&root, "gcc", 1024, 0);
        let line = progress.line(&root.snapshot()).expect("gcc is live");
        assert!(line.contains("[>               ]"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(!line.contains("5.00 KiB"), "{line}");
    }

    #[test]
    fn a_third_fetch_collapses_to_a_count() {
        let root = OpTracker::new_root();
        let _a = fetch(&root, "go", 100, 0);
        let _b = fetch(&root, "gcc", 100, 0);
        let _c = fetch(&root, "binutils", 100, 0);

        let line = line(&root).expect("fetches are visible");
        assert!(line.contains("go +2"), "{line}");
        assert!(!line.contains("gcc"), "{line}");
    }

    #[test]
    fn an_unknown_length_shows_bytes_without_a_meter() {
        let root = OpTracker::new_root();
        let op = root.new_child().with_op(Operation::FetchPkg {
            name: "go".to_string(),
        });
        op.increment(2048);

        let line = line(&root).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(!line.contains('['), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn extract_is_a_status_line_and_a_check_is_ignored() {
        let root = OpTracker::new_root();
        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "go".to_string(),
        });
        let _check = root.new_child().with_op(Operation::Check {
            kind: ot::CheckKind::CheckPackages,
            name: "unrelated".to_string(),
        });

        assert_eq!(line(&root).as_deref(), Some("Extract go"));
    }

    #[test]
    fn a_live_fetch_hides_the_extract_status() {
        let root = OpTracker::new_root();
        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "gcc".to_string(),
        });
        let _go = fetch(&root, "go", 1024, 0);

        let line = line(&root).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(!line.contains("Extract"), "{line}");
    }

    #[test]
    fn a_cleared_tree_has_nothing_to_paint() {
        let root = OpTracker::new_root();
        let op = fetch(&root, "go", 1024, 1024);
        op.set_done();

        assert_eq!(line(&root), None);
    }

    #[test]
    fn packages_outside_the_scope_are_not_shown() {
        let root = OpTracker::new_root();
        let scope = HashSet::from(["go".to_string()]);
        let mut progress = SandboxProgress::new(None, Some(scope));
        let _other = fetch(&root, "llvm", 4096, 2048);
        let _build = root.new_child().with_op(Operation::PackageBuild {
            name: "llvm".to_string(),
        });
        assert_eq!(progress.line(&root.snapshot()), None);

        let _go = fetch(&root, "go", 1024, 256);
        let line = progress.line(&root.snapshot()).expect("go is in scope");
        assert!(line.starts_with("Fetch go "), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(!line.contains("4.00 KiB"), "{line}");
    }

    #[test]
    fn refresh_writes_a_bar_line_once_until_the_meter_moves() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()), None);

        progress.refresh(&mut ours);
        let op = fetch(&root, "go", 1024, 256);
        progress.refresh(&mut ours);
        progress.refresh(&mut ours);
        op.increment(256);
        progress.refresh(&mut ours);
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("bar:Fetch go"), "{lines:?}");
        assert!(lines[0].contains("[===>            ]"), "{lines:?}");
        assert!(lines[1].contains("[=======>        ]"), "{lines:?}");
    }

    #[test]
    fn refresh_clears_the_bar_when_the_fetch_ends() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()), None);

        let op = fetch(&root, "go", 1024, 256);
        progress.refresh(&mut ours);
        drop(op);
        progress.refresh(&mut ours);
        progress.refresh(&mut ours);
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("bar:Fetch go"), "{lines:?}");
        assert_eq!(lines[1], "bar:", "{lines:?}");
    }

    #[test]
    fn a_message_forces_the_next_repaint() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()), None);

        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "go".to_string(),
        });
        progress.refresh(&mut ours);
        progress.message(&mut ours, "building gcc");
        progress.refresh(&mut ours);
        drop(ours);

        assert_eq!(
            read_lines(&theirs),
            ["bar:Extract go", "msg:building gcc", "bar:Extract go"]
        );
    }

    #[test]
    fn refresh_without_a_tracker_writes_nothing() {
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(None, None);
        progress.refresh(&mut ours);
        drop(ours);
        assert!(read_lines(&theirs).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn relay_forwards_events_and_clears_the_meter_at_the_end() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let progress = SandboxProgress::new(Some(root.clone()), None);
        let op = fetch(&root, "go", 1024, 256);

        let (tx, rx) = futures::channel::mpsc::unbounded();
        tx.unbounded_send("fetching go").expect("receiver is live");
        let feed = async {
            tokio::time::sleep(PAINT_INTERVAL * 2).await;
            drop(op);
            drop(tx);
        };
        let run = relay(&mut ours, progress, rx, |text, progress, stream| {
            progress.message(stream, text)
        });
        tokio::join!(run, feed);
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.first().map(String::as_str), Some("msg:fetching go"));
        assert!(lines[1].starts_with("bar:Fetch go"), "{lines:?}");
        assert_eq!(lines.last().map(String::as_str), Some("bar:"), "{lines:?}");
    }

    /// Captures what this process writes to its log, so a test can read the
    /// NET-080 record the way a diagnostics bundle's daemon-log tail does.
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
        type Writer = LogCapture;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// One install's [`FetchRecord`].
    fn fetch_record() -> FetchRecord {
        FetchRecord {
            box_id: "a session".to_string(),
            cache_host: "cache.minimal.dev".to_string(),
            objects: BTreeMap::from([("jq".to_string(), "jq (version 1.7.1)".to_string())]),
        }
    }

    /// Captures this thread's log from the moment it is called.
    fn capture_log() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let log = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (log, guard)
    }

    /// The node-plane records in `log`, one per line.
    fn records(log: &LogCapture) -> Vec<String> {
        log.contents()
            .lines()
            .filter(|line| line.contains("node-plane traffic"))
            .map(str::to_string)
            .collect()
    }

    /// NET-080: an install's package fetch is recorded as node-plane traffic
    /// at the seam, where the op starts — one info line naming the box the
    /// fetch was made for, the daemon's own leaf, the cache host it left
    /// for, and the package with its version. One line per fetch, whatever
    /// the repaints, none for a package outside the install's scope, and
    /// none for a fully cached add, which fetches nothing: its ops extract
    /// and build what the cache already holds.
    #[test]
    fn a_fetch_op_start_records_one_node_plane_line() {
        let root = OpTracker::new_root();
        let scope = HashSet::from(["jq".to_string()]);
        let (log, _guard) = capture_log();
        let mut progress = SandboxProgress::new(Some(root.clone()), Some(scope.clone()))
            .with_fetch_record(fetch_record());
        let _jq = fetch(&root, "jq", 1024, 128);

        let recorded = log.contents();
        let lines: Vec<&str> = recorded
            .lines()
            .filter(|line| line.contains("node-plane traffic"))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one record per fetch, one fetch: {recorded}"
        );
        let line = lines[0];
        assert!(
            line.contains("INFO"),
            "the record is at the level a bundle's tail reads: {line}"
        );
        assert!(
            line.contains("box_id=a session"),
            "the record names the box the fetch was made for: {line}"
        );
        assert!(
            line.contains("host=cache.minimal.dev"),
            "the record names the configured cache host: {line}"
        );
        assert!(
            line.contains("object=jq (version 1.7.1)"),
            "the record names the package and its version: {line}"
        );

        // The meter repaints at ~12 Hz while a fetch runs; a fetch is an
        // event, not a meter, so the repaints record nothing more. Nor does
        // a package outside the install's scope: it is not this install's.
        progress.line(&root.snapshot());
        progress.line(&root.snapshot());
        let _llvm = fetch(&root, "llvm", 4096, 0);
        assert_eq!(
            records(&log).len(),
            1,
            "the fetch is recorded once, at its start"
        );

        // A fully cached add fetches nothing — extract and build ops over
        // what the cache already holds — so it records nothing.
        let cached = OpTracker::new_root();
        let (quiet, _guard) = capture_log();
        let mut cached_progress = SandboxProgress::new(Some(cached.clone()), Some(scope))
            .with_fetch_record(fetch_record());
        let _extract = cached.new_child().with_op(Operation::ExtractPkg {
            name: "jq".to_string(),
        });
        assert!(
            cached_progress.line(&cached.snapshot()).is_some(),
            "the cached add still paints its extract"
        );
        assert!(
            !quiet.contents().contains("node-plane traffic"),
            "a fully cached add emits no record: {}",
            quiet.contents()
        );
    }

    /// NET-080: each kind of fetch the daemon makes for itself on the
    /// install path is recorded with its own host and object — a package
    /// from the configured remote cache, named with its version, and the
    /// index from the same cache. One line each, spelled from the op that
    /// started. A web source is the box's own fetch (NET-155), made in the
    /// box's leaf, so it is not recorded as node-plane traffic.
    #[test]
    fn each_fetch_kind_is_recorded_with_its_own_host_and_object() {
        let root = OpTracker::new_root();
        let (log, _guard) = capture_log();
        let _progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());
        let _pkg = root.new_child().with_op(Operation::FetchPkg {
            name: "jq".to_string(),
        });
        let _source = root.new_child().with_op(Operation::FetchSource {
            url: "https://github.com/example/example/archive/v1.tar.gz".to_string(),
        });
        let _index = root.new_child().with_op(Operation::FetchIndex);

        let lines = records(&log);
        assert_eq!(
            lines.len(),
            2,
            "one record per node-plane fetch, two fetches: {lines:?}"
        );
        let read = |needle: &str| {
            lines
                .iter()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("a record names {needle}: {lines:?}"))
        };
        let pkg = read("object=jq (version 1.7.1)");
        assert!(
            pkg.contains("host=cache.minimal.dev"),
            "a package is fetched from the configured cache: {pkg}"
        );
        let index = read("object=index");
        assert!(
            index.contains("host=cache.minimal.dev"),
            "the index is fetched from the configured cache: {index}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("v1.tar.gz") || line.contains("github.com")),
            "a web source is the box's fetch, not the node plane's: {lines:?}"
        );
    }

    /// NET-080: a local source tarball — a `FetchSource` with no scheme —
    /// crosses no network, so it is never recorded as node-plane traffic.
    #[test]
    fn a_local_source_is_not_recorded_as_node_plane_traffic() {
        let root = OpTracker::new_root();
        let (log, _guard) = capture_log();
        let _progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());
        let _source = root.new_child().with_op(Operation::FetchSource {
            url: "../tarballs/v4.tar.gz".to_string(),
        });

        let recorded = log.contents();
        assert!(
            !recorded.contains("node-plane traffic"),
            "a local source read is no network fetch: {recorded}"
        );
    }

    /// NET-155: a source is a package build's traffic, never the node
    /// plane's, wherever it is fetched. No `http`, `https` or `gs://` source
    /// is recorded, so neither a URL nor a credential in it reaches the log
    /// through the record.
    #[test]
    fn no_source_is_recorded_as_node_plane_traffic() {
        for url in [
            "https://ghp_deadbeef@github.com/example/example/archive/v1.tar.gz?X-Amz-Signature=deadbeef",
            "http://downloads.example.org/pkg-1.0.tar.gz",
            "gs://sources-bucket/pkg-1.0.tar.gz",
        ] {
            let root = OpTracker::new_root();
            let (log, _guard) = capture_log();
            let _progress =
                SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());
            let _source = root.new_child().with_op(Operation::FetchSource {
                url: url.to_string(),
            });

            let recorded = log.contents();
            assert!(
                !recorded.contains("node-plane traffic"),
                "a source is the box's fetch: {recorded}"
            );
            assert!(
                !recorded.contains("ghp_deadbeef") && !recorded.contains("X-Amz-Signature"),
                "neither the token nor the signature reaches the log: {recorded}"
            );
        }
    }

    /// NET-080: a fetch that starts and ends between two paints — gone from
    /// the tree before the meter's next snapshot — is still recorded, once:
    /// the record is taken where the op starts, not where the meter looks.
    #[test]
    fn a_fetch_that_starts_and_ends_between_ticks_is_still_recorded() {
        let root = OpTracker::new_root();
        let (log, _guard) = capture_log();
        let mut progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());

        let jq = root.new_child().with_op(Operation::FetchPkg {
            name: "jq".to_string(),
        });
        jq.set_done();
        drop(jq);

        let lines = records(&log);
        assert_eq!(lines.len(), 1, "one fetch, one record: {lines:?}");
        assert!(
            lines[0].contains("object=jq (version 1.7.1)"),
            "the record names the fetch that came and went: {}",
            lines[0]
        );
        // The meter never saw it, and painting now records nothing more.
        assert_eq!(progress.line(&root.snapshot()), None);
        assert_eq!(records(&log).len(), 1);
    }

    /// NET-080: the host each fetch's record names, read from the location
    /// the configured remote cache takes. The mirror's is the URL's own
    /// host — the parsed host, with neither the path nor the scheme spelled
    /// beside it, and the port carried only when it is not https's own
    /// default, the one rule every fetch kind's host field keeps — and the
    /// GCS location's is the bucket it names, the spelling `mctx` resolves
    /// `gs://…` and a bare bucket name into. Both spellings are what a
    /// person reading a bundle's daemon-log tail matches the fetch
    /// against, so a host read out of a rendering of the URL rather than
    /// out of the URL itself is a host the record can silently stop
    /// naming.
    #[test]
    fn cache_host_reads_https_host_and_gcs_bucket() {
        // The mirror's own non-default port, kept: a fetch to port 8443
        // and one to the default are two different fetches, and the
        // record's one port rule names them apart.
        let mirror = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from(
                "https://cache.example.com:8443/prefix/index.shisha",
            )
            .expect("the configured remote cache's mirror URL parses"),
        );
        assert_eq!(
            cache_host(&mirror),
            "cache.example.com:8443",
            "the mirror's host keeps its own non-default port: the path is \
             never part of the host a fetch leaves for, but a port is"
        );
        // The scheme's own default, dropped by the same one rule the
        // source-URL spelling below is read by: a default port is a fact
        // the scheme already says, so the field never carries it.
        let default = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from(
                "https://cache.example.com:443/prefix/index.shisha",
            )
            .expect("the default-port mirror URL parses"),
        );
        assert_eq!(
            cache_host(&default),
            "cache.example.com",
            "the mirror's host drops https's own default port: 443 is what \
             the scheme already says"
        );
        let bare = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from("https://cache.example.com/prefix/index.shisha")
                .expect("the portless mirror URL parses"),
        );
        assert_eq!(
            cache_host(&bare),
            "cache.example.com",
            "a mirror that spells no port is named without one"
        );
        let ipv6 = AnyUrl::Https(
            common::fetchers::ReqwestUrl::try_from("https://[::1]:8080/prefix/index.shisha")
                .expect("the IPv6 mirror URL parses"),
        );
        assert_eq!(
            cache_host(&ipv6),
            "[::1]:8080",
            "host_str keeps an IPv6 mirror's brackets, so its port reads apart from the address"
        );
        assert_eq!(
            cache_host(&ipv6),
            url_host("https://[::1]:8080/prefix/index.shisha"),
            "the cache and source spellings agree for the same IPv6 host"
        );
        let bucket = AnyUrl::Gcs(common::fetchers::GcsUrl {
            bucket: "projects/_/buckets/minimal-cache".to_string(),
            object: String::new(),
        });
        assert_eq!(
            cache_host(&bucket),
            "projects/_/buckets/minimal-cache",
            "a GCS location's host is the bucket it names"
        );
    }

    /// NET-080: the two spellings a `FetchSource` URL's record carries — the
    /// host it names and the object it is recorded as — never carry the
    /// parts of the URL that must not reach a log line. The record is an
    /// INFO line a bundle's daemon-log tail keeps on disk, and a source URL
    /// can carry a credential in its userinfo (`https://<token>@github.com/…`)
    /// and a signature in its query (`?X-Amz-Signature=…`), so the host is
    /// the URL's authority minus its userinfo and the object is its spelling
    /// minus the userinfo, the query, and the fragment. The port rides the
    /// one rule every fetch kind's host field keeps — kept when it is not
    /// the scheme's own default, dropped when it is, the same rule the
    /// cache's host is spelled by — and that rule is the host field's
    /// alone: the object keeps the URL's own spelling. A source with no
    /// scheme — a tarball off the operator's own disk — names no host and
    /// crosses no network, and stays the object whole.
    #[test]
    fn url_host_and_object_carry_no_credentials() {
        // A credential in the userinfo, before the host a GitHub source
        // fetch actually leaves for.
        let tokened = "https://ghp_deadbeef@github.com/example/example/archive/v1.tar.gz";
        assert_eq!(
            url_host(tokened),
            "github.com",
            "the host is the authority minus its userinfo, so the token never \
             reaches the record: {}",
            url_host(tokened)
        );
        assert_eq!(
            url_object(tokened),
            "https://github.com/example/example/archive/v1.tar.gz",
            "the object is the URL minus its userinfo, so the token never \
             reaches the record: {}",
            url_object(tokened)
        );
        // A login pair, a port, a query, and a fragment: each is dropped or
        // kept by what it is, not by where it sits.
        let signed = "https://user:pass@mirror.example.com:8443/src/v2.tar.gz?X-Amz-Signature=deadbeef#fragment";
        assert_eq!(
            url_host(signed),
            "mirror.example.com:8443",
            "the host keeps the port and drops the login pair before it"
        );
        assert_eq!(
            url_object(signed),
            "https://mirror.example.com:8443/src/v2.tar.gz",
            "the object keeps the host and port and drops the login pair, the \
             query, and the fragment"
        );
        // Each scheme's own default port, dropped by the same one rule the
        // cache's host is spelled by — while the object keeps the URL's
        // whole spelling, because the port rule is the host field's.
        let https_default = "https://mirror.example.com:443/src/v2.tar.gz";
        assert_eq!(
            url_host(https_default),
            "mirror.example.com",
            "the host drops https's own default port: 443 is what the scheme \
             already says"
        );
        assert_eq!(
            url_object(https_default),
            "https://mirror.example.com:443/src/v2.tar.gz",
            "the object keeps the URL's spelling whole minus what must not be \
             logged: the port rule is the host field's alone"
        );
        let http_default = "http://mirror.example.com:80/src/v2.tar.gz";
        assert_eq!(
            url_host(http_default),
            "mirror.example.com",
            "the host drops http's own default port, the same one rule"
        );
        let http_kept = "http://mirror.example.com:8080/src/v2.tar.gz";
        assert_eq!(
            url_host(http_kept),
            "mirror.example.com:8080",
            "the host keeps http's non-default port the same way it keeps \
             https's: one rule for every fetch kind"
        );
        // A URL with nothing to drop is spelled whole in both fields.
        let plain = "https://example.com/src/v3.tar.gz";
        assert_eq!(url_host(plain), "example.com");
        assert_eq!(url_object(plain), "https://example.com/src/v3.tar.gz");
        // A local source names no host and is the object whole.
        let local = "../tarballs/v4.tar.gz";
        assert_eq!(url_host(local), "", "a local source names no host");
        assert_eq!(
            url_object(local),
            "../tarballs/v4.tar.gz",
            "a local source stays the object whole"
        );
    }
}
