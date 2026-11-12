use super::*;

/// A launched host: its handle, paired with the `JoinHandle` of its runtime
/// loop so teardown can be awaited on destroy.
pub(super) type LaunchedHost = (
    box_runtime::HostHandle,
    JoinHandle<Result<box_runtime::HostExit, std::io::Error>>,
);

/// Aborts the host's runtime loop when the task that watches it is
/// aborted, so an abort of the watched handle reaches the loop as before.
struct AbortLoopOnDrop(Option<tokio::task::AbortHandle>);

impl AbortLoopOnDrop {
    /// The loop ended by itself: nothing is left to abort.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for AbortLoopOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// The variables a task run hands the next entrypoint launch of its box
/// (T43). `min task run` resolves a task's `env_vars` against the caller's
/// shell and sends them on the run's exec channel. The box's entrypoint is
/// the in-box `min task run`, which fills the task's `inherit` variables
/// from its own environment, so the values must reach the launch that
/// starts it. The exec stages them here by box id, and the next
/// [`BoxActor::ensure_host`] of the box takes them, whether it launches or
/// not, so no value outlives the run it was sent for.
///
/// The run also stages the names the client's `[vars] ignore` matched
/// (`TaskExec::drop_env`). The in-box `min task run` reads the task's
/// declarations again from the uploaded `minimal.toml`, so a launch of the
/// entrypoint records the names for the box ([`record`], [`drops`]), and
/// the daemon's in-box run removes each of them from the task's variables
/// before it fills any `inherit` one. A dropped name then never reaches the
/// task, as on the old path. A run that joins an entrypoint already running
/// records nothing: the in-box run it relays is the one that launch
/// started, with that launch's names.
///
/// Interim: a seam beside the actor, because the actor's `EnsureHost`
/// message carries no environment. The values move into that message
/// when it gains one: https://github.com/gominimal/minimal/issues/3043.
pub(crate) mod entrypoint_env {
    use std::collections::{BTreeSet, HashMap};
    use std::sync::{LazyLock, Mutex};

    /// The variables staged for one box.
    type Vars = Vec<(String, String)>;

    /// The names a task's variables lose for one box.
    pub(crate) type Drops = BTreeSet<String>;

    /// What one run stages for its box's entrypoint launch: the variables,
    /// the directory in the box where the entrypoint starts (`None` starts
    /// it at the root of the tree), and the names to drop.
    type Staged = (Vars, Option<String>, Drops);

    static STAGED: LazyLock<Mutex<HashMap<boxes::SessionId, Staged>>> =
        LazyLock::new(Mutex::default);

    /// The names to drop for each box whose entrypoint a launch started
    /// with any. Replaced by the box's next entrypoint launch. A stopped box
    /// keeps its record, and its names with it. They are removed when the
    /// box is destroyed ([`forget`]).
    static DROPS: LazyLock<Mutex<HashMap<boxes::SessionId, Drops>>> = LazyLock::new(Mutex::default);

    /// Stages `vars`, `start_dir` and `drops` for the next entrypoint
    /// launch of box `id`, in place of any staged before. Only a task run
    /// that relays the box's entrypoint stages, so a staged entry also
    /// tells the next [`super::BoxActor::ensure_host`] that it starts the
    /// entrypoint.
    pub(crate) fn stage(id: boxes::SessionId, vars: Vars, start_dir: Option<String>, drops: Drops) {
        STAGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, (vars, start_dir, drops));
    }

    /// Takes what is staged for box `id`: the launch's entrypoint
    /// variables (`AttachEnv::entrypoint`), and the names to drop. A staged directory rides among the
    /// variables under [`crate::box_runtime::START_DIR_KEY`], which the
    /// launch takes out and starts the entrypoint in. A dropped name is left
    /// out of them. Only a launch records the names for the box's in-box run
    /// ([`record`]). `None` when no run staged anything.
    pub(crate) fn take(id: &boxes::SessionId) -> Option<(Vars, Drops)> {
        let (mut vars, start_dir, dropped) = STAGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id)?;
        vars.retain(|(name, _)| {
            name != crate::box_runtime::START_DIR_KEY && !dropped.contains(name)
        });
        if let Some(dir) = start_dir {
            vars.push((crate::box_runtime::START_DIR_KEY.to_string(), dir));
        }
        Some((vars, dropped))
    }

    /// Records `dropped` as the names box `id`'s in-box run drops, in place
    /// of any a launch recorded before. Called by a launch of the box's
    /// entrypoint only.
    pub(crate) fn record(id: boxes::SessionId, dropped: Drops) {
        let mut recorded = DROPS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if dropped.is_empty() {
            recorded.remove(&id);
        } else {
            recorded.insert(id, dropped);
        }
    }

    /// Removes all that is staged or recorded for box `id`. Called when the
    /// box is destroyed, so neither map keeps an entry for a box that is
    /// gone.
    pub(crate) fn forget(id: &boxes::SessionId) {
        STAGED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
        DROPS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// The names the launch of box `id`'s entrypoint recorded to drop from
    /// its task's variables. Empty for a box no task run launched.
    pub(crate) fn drops(id: &boxes::SessionId) -> Drops {
        DROPS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
            .unwrap_or_default()
    }
}

/// Why a task run cannot start the entrypoint of a box that has its own
/// network address while a shell for its activate hooks runs (T43). The
/// run prints it after the line that names the task and the box. No
/// command ends that shell, so the text states the situation and stops.
pub(crate) const ENTRYPOINT_BEHIND_HOOK_SHELL: &str = "The box has its own network address. \
     The shell that ran the project's activate hooks holds that address, \
     and that shell does not end.";

/// The refusal of a task run whose entrypoint cannot start behind a hook
/// shell, as [`BoxActor::ensure_host`] returns it inside
/// [`AttachError::SpawnFailed`]. The run finds it by type, not by text,
/// and answers with [`ENTRYPOINT_BEHIND_HOOK_SHELL`].
///
/// Known gap: this refusal fails closed, so a box with its own network
/// address and activate hooks cannot run its task. Tracked by
/// https://github.com/gominimal/minimal/issues/3042.
#[derive(Debug)]
pub(crate) struct EntrypointBehindHookShell;

impl std::fmt::Display for EntrypointBehindHookShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(ENTRYPOINT_BEHIND_HOOK_SHELL)
    }
}

impl std::error::Error for EntrypointBehindHookShell {}

impl EntrypointBehindHookShell {
    /// Whether `error` is this refusal.
    pub(crate) fn is(error: &AttachError) -> bool {
        matches!(
            error,
            AttachError::SpawnFailed(e)
                if e.get_ref().is_some_and(|inner| inner.is::<EntrypointBehindHookShell>())
        )
    }
}

/// The actor's end of an [`watch_entrypoint_exit`] watch: it receives how
/// the watched host's runtime loop ended, once, when it ends with an exit.
pub(super) type EntrypointWatch = tokio::sync::oneshot::Receiver<box_runtime::HostExit>;

/// Whether a box ends when its entrypoint returns (BOX-038): its spec sets
/// `lifetime = "until_complete"`. A box with no stored spec reads as one,
/// as a spec stored without `box.lifetime` does.
pub(super) fn ends_with_entrypoint(spec: Option<&mfile::spec::BoxSpec>) -> bool {
    spec.is_none_or(|spec| spec.lifetime == mfile::spec::Lifetime::UntilComplete)
}

/// The entry a box runs as its entrypoint and ends with (T43): the spec
/// sets `lifetime = "until_complete"` and names an argv entrypoint. A task
/// run relays such a box's entrypoint, and the daemon log names the entry
/// when it returns. The settings decide it, never the Box Type's name.
pub(crate) fn entry_run_as_entrypoint(spec: &mfile::spec::BoxSpec) -> Option<&str> {
    let runs = spec.lifetime == mfile::spec::Lifetime::UntilComplete
        && matches!(spec.entrypoint, mfile::spec::Entrypoint::Exec(_));
    runs.then_some(spec.entry.as_str())
}

/// The `timeout` of a box that ends at it (BOX-037), in whole seconds: the
/// spec sets `lifetime = "until_complete"` and a timeout. A box that runs
/// until it is stopped runs past its timeout.
pub(super) fn timeout_of(spec: &mfile::spec::BoxSpec) -> Option<u64> {
    (spec.lifetime == mfile::spec::Lifetime::UntilComplete)
        .then_some(spec.timeout)
        .flatten()
}

/// Watches a host's runtime loop `task` for the box's actor. When the loop
/// ends, the watch receives its [`box_runtime::HostExit`], and the actor
/// decides from it whether the box ends.
///
/// This is the one way a box ends without a request (BOX-015, BOX-038):
/// its entrypoint returns. Nothing here, or anywhere in the daemon, ends a
/// box because it is idle or because its clients went away. A client that
/// detaches or drops leaves the entrypoint running, and the loop with it.
///
/// The handle it returns stands in for `task`: it yields the loop's result,
/// and an abort of it aborts the loop.
///
/// `entry` names the task a launch runs as its entrypoint (see
/// [`entry_run_as_entrypoint`]). When that entrypoint returns on its own,
/// the watch logs the box, the task and the exit code. It logs whether or
/// not a client is connected, so the daemon log names each task box's end.
pub(super) fn watch_entrypoint_exit(
    task: JoinHandle<Result<box_runtime::HostExit, std::io::Error>>,
    box_id: boxes::SessionId,
    box_name: String,
    entry: Option<String>,
) -> (
    JoinHandle<Result<box_runtime::HostExit, std::io::Error>>,
    EntrypointWatch,
) {
    let (watch_tx, watch) = tokio::sync::oneshot::channel();
    let mut abort_loop = AbortLoopOnDrop(Some(task.abort_handle()));
    let root = tracing::info_span!(
        parent: None,
        "session.host.entrypoint_exit",
        box_id = %box_id,
    );
    let watched = crate::traced::spawn_detached(root, async move {
        let result = task.await;
        abort_loop.disarm();
        if let (Ok(Ok(exit)), Some(task)) = (&result, entry.as_deref())
            && !exit.requested
        {
            let exit_code = exit
                .reason
                .as_ref()
                .and_then(|r| r.exit_code)
                .unwrap_or(exit.code);
            tracing::info!(
                box_id = %box_id,
                box_name = %box_name,
                task,
                exit_code,
                "task box ended: its entrypoint returned"
            );
        }
        #[cfg(test)]
        if let Some(hold) = super::exit_settle_seam::held(&box_id) {
            tokio::time::sleep(hold).await;
        }
        if let Ok(Ok(exit)) = &result {
            // The actor may be gone, or may hold a later launch's watch: the
            // exit is then nobody's to act on.
            #[expect(
                clippy::let_underscore_must_use,
                reason = "an actor that dropped the watch has nothing to end"
            )]
            let _ = watch_tx.send(exit.clone());
        }
        match result {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => Err(std::io::Error::other(error)),
        }
    });
    (watched, watch)
}

/// Where in the session lifecycle a host launch is happening, which decides
/// whether the launch has to wait for an `Active` record.
///
/// Only [`BoxActor::finalize`]'s launch is `Activating`. Every other
/// launch happens after the session is attachable and keeps the status gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchPhase {
    /// A launch against a session that is already `Active`: an attach, or an
    /// exec's [`BoxActor::ensure_host`]. Both check the record's status
    /// themselves before getting here; the gate in [`BoxActor::context`] is
    /// their backstop.
    Attached,
    /// The pre-activation launch inside [`BoxActor::finalize`]. It runs while
    /// the record is still `Materializing` by construction — promoting to
    /// `Active` is what finalize does *after* the activation hooks this host
    /// exists to run — so it cannot take the `Active` gate without
    /// deadlocking against itself.
    Activating,
}

/// How long *all* of a teardown transition's hooks get, together.
///
/// A hook's own timeout is capped at
/// [`MAX_HOOK_TIMEOUT`](boxes::core::lifecyclehook::MAX_HOOK_TIMEOUT)
/// to keep one from holding a session open, but nothing bounds how many
/// hooks a composition may carry — so without a total, N of them at the
/// cap would hold a destroy for N×5 minutes and defeat the point. This
/// is that total. Wide enough that an honest teardown never meets it;
/// the hooks are a courtesy, and the destroy is the contract.
pub(super) const TEARDOWN_HOOK_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// How long a teardown transition will wait for the sandbox it needs to
/// run its hooks in.
///
/// Nothing else about a host launch is time-bounded, because every other
/// caller is a user waiting on their own attach. A teardown is not: the
/// hooks are a courtesy and the destroy is the contract, so the launch
/// gets a deadline and the session is torn down either way. Generous
/// enough to cover a cold cache on a loaded box — this is a backstop
/// against a wedge, not a performance budget.
pub(super) const HOOK_LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Deadline for a read-only probe of a session's host — the terminal
/// attributes and the screen snapshot.
///
/// Spawning those probes off the session actor (see
/// [`BoxActor::handle_message`]) keeps the *actor* responsive, but says
/// nothing about the spawned task: against a host that never answers, an
/// unbounded probe outlives every caller that gave up on it. Nor does it
/// stay parked in the same place:
/// [`HOST_MAILBOX_CAPACITY`](crate::box_runtime::HOST_MAILBOX_CAPACITY)
/// messages in, a wedged host's mailbox is full and the probe blocks in
/// `send` rather than `recv` — still forever, and still one stranded task
/// per poll. `min dash` polls the focused session's screen on every refresh
/// tick, which makes that leak unbounded in the one case the bound exists
/// for.
///
/// So the probe is bounded here too, not only at its callers: a task that
/// cannot answer within the deadline ends, and the caller reads the same
/// `None` a session with no running host already reports.
///
/// [`crate::box_manager::BoxManager`] bounds these probes again on its own
/// mainloop. That is not redundant — this deadline covers a wedged *host*,
/// and the manager's covers a wedged *session actor*, which can be parked in
/// an inline `EnsureHost`, `Attach`, or `ConfigureLoadout` and never reach
/// the spawn at all.
pub(crate) const HOST_PROBE_TIMEOUT: std::time::Duration = minimald_rpc::HOST_PROBE_TIMEOUT;

/// Awaits a host probe under [`HOST_PROBE_TIMEOUT`], collapsing both a
/// missed deadline and a dead host to `None`.
pub(crate) async fn probe_host<T>(
    probe: impl std::future::Future<Output = Result<T, ()>>,
) -> Option<T> {
    tokio::time::timeout(HOST_PROBE_TIMEOUT, probe)
        .await
        .ok()?
        .ok()
}

/// The PTY size a host minted with nothing attached starts at. A client that
/// attaches later resizes it; until then only an unattached shell sees it.
pub(super) const UNATTACHED_WIN_SIZE: WinSize = WinSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

/// Why a session host was launched.
///
/// The sandbox and the interactive shell are one spawn — the shell *is* the
/// sandbox's session leader — so a launch that only wanted the sandbox still
/// creates the shell a user may later attach to, and that shell's `environ`
/// is fixed for its lifetime. This records which case a live host is in, so
/// an attach can tell "the shell was made for a terminal" from "the shell was
/// made for a hook, and no terminal has ever described itself to it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostOrigin {
    /// Minted by an attach, from a client with a PTY. Its environment already
    /// describes a terminal.
    Interactive,
    /// Minted by [`BoxActor::launch_host_for_hooks`] to run lifecycle hooks.
    /// Nothing of the user's runs in it: its shell waits at the launch's
    /// start gate, before it execs, until an attach releases it (see
    /// `box_runtime::Launched::start_gate`), so neither the shell nor its
    /// startup files have run when an attach arrives, and it is safe to
    /// replace. A host kept instead ([`replaces_host_for_terminal`]) starts
    /// its shell at that attach, after the activate hooks.
    Hooks,
    /// Minted by [`BoxActor::ensure_host`] to serve an exec. The command is
    /// live inside that sandbox, so replacing the shell would kill it — this
    /// one is never respawned, and the attaching terminal's facts reach it
    /// through the per-attach environment instead.
    Exec,
}

/// Whether replacing a live host for an attaching terminal is safe for the
/// box it serves. A [`HostOrigin::Hooks`] host is replaceable — nothing of
/// the user's runs in it — unless the record holds a registered host-side
/// row: on a VM-backed host, the end of that host's PTask tells the VM host
/// that the box ended, which withdraws the row, and the in-VM daemon cannot
/// register it again, so a respawn would leave the box with no row. The
/// guard is the record's handed `box_addresses`, not a VM check, so any
/// registered box is kept, native ones included: keeping costs nothing,
/// because the terminal rides the per-attach environment the host
/// republishes, exactly as it does for an [`HostOrigin::Exec`] host.
pub(super) fn replaces_host_for_terminal(
    origin: HostOrigin,
    declares_terminal: bool,
    holds_host_row: bool,
) -> bool {
    origin == HostOrigin::Hooks && declares_terminal && !holds_host_row
}

impl BoxActor {
    /// Kills `host` and stops its runtime loop `task`, bounded so a wedged
    /// host cannot park the caller. Both the kill and the wait for the loop to
    /// act on it are bounded: `HostHandle::kill`'s `send_timeout` only bounds
    /// the wait for mailbox *capacity*, so a loop parked mid-`step()` (mailbox
    /// nearly empty) queues the kill yet never processes it, and awaiting that
    /// loop unbounded would park the caller behind it forever.
    ///
    /// When the kill cannot be queued the loop is aborted. When the kill
    /// landed but the loop does not finish within `HOST_PROBE_TIMEOUT`, the
    /// task is detached rather than aborted so the `NetGuard` teardown at the
    /// end of `Host::mainloop` can still run once the loop drains.
    pub(super) async fn kill_and_stop_loop(
        host: &box_runtime::HostHandle,
        task: &mut JoinHandle<Result<box_runtime::HostExit, std::io::Error>>,
        for_shutdown: bool,
    ) {
        let killed = host.kill(for_shutdown).await.is_ok();
        if !killed {
            // The kill could not be queued — the host is wedged past the
            // mailbox-capacity deadline. Abort the loop; the NetGuard
            // teardown in mainloop is skipped, but the host was already
            // unreachable.
            task.abort();
        } else if tokio::time::timeout(HOST_PROBE_TIMEOUT, &mut *task)
            .await
            .is_err()
        {
            // The kill landed but the loop did not finish within the
            // deadline. Detach rather than abort: the task continues
            // running and will run the NetGuard teardown at the end of
            // mainloop once it drains. Dropping the JoinHandle (when the
            // caller's `task` binding goes out of scope) detaches it.
            //
            // worker-iterate: declined CodeRabbit's "keep timed-out hosts
            // owned until cleanup is coordinated" finding. The suggested
            // change — retain the timed-out JoinHandle under supervision and
            // coordinate sandbox/NetGuard teardown before Destroy deletes the
            // session or terminal-triggered replacement mints a second host —
            // is a heavy architectural lift, not a behavior-preserving patch.
            // It would restructure `BoxInner` to hold and later await the
            // detached task and thread teardown coordination through both the
            // Destroy and replacement paths, a change that cannot be validated
            // here (the wedged-host scenario is not reproducible in this
            // environment) and that risks regressing the bounded-caller
            // response (`HOST_PROBE_TIMEOUT`) this function exists to
            // preserve. The detach-on-timeout trade-off is deliberate and
            // documented; full reclamation is a tracked follow-up.
        }
    }

    /// The actor's own answer to "is a box running behind this session": an
    /// `active` session holding a live host. A stopped box's record still
    /// reads `active`, but the actor resurrected for it holds no host — so
    /// this, not the record's status, is what a publish must consult (and
    /// what `IsBusy` consults for the same reason).
    pub(super) fn has_live_host(&self) -> bool {
        matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        )
    }

    /// Tears down any runtime objects, such as the host or side ops. Shutdown
    /// of these objects is complete once awaited.
    ///
    /// `for_shutdown` is threaded to the host's kill so attached clients get
    /// the daemon-shutdown message (and a terminal reset) rather than a bare
    /// disconnect when the session dies because the daemon is going away.
    pub(super) async fn stop_running(&mut self, for_shutdown: bool) {
        // The session's forwards relay into its box: a session that is going
        // away takes them with it, rather than leaving live relays pointed at
        // a box that is being torn down. Both teardown paths — `Stop` and
        // `Destroy` — come through here.
        for forward in std::mem::take(&mut self.forwards) {
            forward.abort();
        }

        // The ports the box published at runtime go with it too (NET-044):
        // unbind each forward the switch accepted, so a box that stops leaves
        // no live publish behind. Best-effort, like the declared forwards'
        // teardown — `remove_ingress` logs a failed unexpose and moves on,
        // since there is no caller left to propagate to. This is the box's
        // one ingress *revocation*: it takes every runtime publication down
        // whoever published it — the expose surface's request-published
        // forwards above, the watcher's listener-published forwards in the
        // stop the host runs beside this — and the box's shared publication
        // set is revoked with them, without asking who owns what: the set
        // stops naming ports the revocation unbound, in the same turn, so a
        // publish asked in the window between this stop and the next launch
        // answers what stopped the box, not an entry whose publication came
        // down with it.
        let forwarders = self.live_ingress.take_all();
        self.publications.revoke_all();
        // A declared port bound for this box at a shared-address port's
        // hand-over (NET-129) goes the way the forwards its attach bound
        // go: unbound here on a native host, left for the host on a
        // VM-backed one.
        let handed = self.live_ingress.take_handed();
        if !handed.is_empty() {
            let control = self.switch_control().await;
            crate::net::policy::release_declared_ingress(&control, &handed).await;
        }
        if !forwarders.is_empty() {
            // The expose's revocation withdraws its admission at the box's
            // gate first (NET-044), so no new connection crosses the gap
            // between a port the gate still admits and a forward that is
            // coming down. An attach already gone took its gate with it.
            if let Some(gate) = self
                .reported_switch_address
                .and_then(crate::net::ingress_gate::live_gate)
            {
                for forwarder in &forwarders {
                    gate.withdraw_exposed(forwarder.internal_port());
                }
            }
            let control = self.switch_control().await;
            crate::net::policy::remove_ingress(&control, &forwarders).await;
        }

        for ask in std::mem::take(&mut self.pending_asks) {
            if let Some(host_ask) = &ask.host_ask {
                host_ask.abort();
            }
            self.answer_expose(
                &ask.box_name,
                ask.port,
                boxes::DynamicIngress::Ask,
                crate::audit::DecidedBy::Daemon,
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::AskNeedsAnswer,
                )),
                ask.reply,
            )
            .await;
        }

        let inner = match &mut self.inner {
            BoxInner::Active { host, sops, .. } => Some((host.take(), std::mem::take(sops))),
            BoxInner::Draft { .. } => None,
        };
        // The host is out of the actor's hands now: out of the slot too, so a
        // handle that outlives a `Stop` reads no host rather than probing the
        // one being stopped.
        self.publish_host();
        if let Some((host, mut sops)) = inner {
            for s in sops.drain(..) {
                s.shutdown().await;
            }
            if let Some((host, mut task)) = host {
                // Signal the process to die, then stop its runtime loop so the
                // sandbox files backing its rootfs are released before the
                // caller removes the session's directory tree. The wait is
                // bounded and aborts a wedged loop rather than parking shutdown
                // behind it — see [`BoxActor::kill_and_stop_loop`].
                Self::kill_and_stop_loop(&host, &mut task, for_shutdown).await;
            }
        }
        // Nothing of the box is meant to run now, so its cgroup goes, and
        // anything still in it goes with it. The next start makes a new one.
        self.destroy_cgroup().await;
    }

    /// The box's cgroup, made at first use with the box's network policy
    /// in place: nothing of the box starts in a cgroup the policy engine
    /// has no entry for. `None` on a daemon with no cgroup root, where
    /// boxes run without one.
    ///
    /// # Errors
    ///
    /// When the daemon has a cgroup root and the box's cgroup cannot be
    /// made in it, or the box's network policy cannot be enforced here.
    pub(super) async fn ensure_cgroup(
        &mut self,
    ) -> std::io::Result<Option<sandbox::cgroup::BoxCgroup>> {
        use crate::net::engine::{BoxFacts, Engine};

        let Some(root) = crate::box_cgroups::root() else {
            return Ok(None);
        };
        let record = self.record.record().await?;
        let facts = BoxFacts {
            session: record.id,
            mode: record.network,
            policy: record.policy.clone(),
            deny_all_opt_out: self.deny_all_opt_out,
        };
        let engine = Engine::current();
        let refused = |error: crate::net::engine::InstallError| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        };
        if let Some(cgroup) = &self.cgroup {
            // A launch after the one that made the cgroup: the entry is
            // there, and follows the record if that changed in between.
            if let Some(installed) = engine.installed(record.id)
                && !Engine::matches(&installed, &facts)
            {
                engine.reconfigure(&installed, &facts).map_err(refused)?;
            }
            return Ok(Some(cgroup.clone()));
        }
        // Everything that can fail without the cgroup comes before it, so
        // an error leaves none behind.
        let log = Arc::new(crate::events::DiskLog(self.record.object().await?));
        let cgroup = root.create_box(&record.id.to_string())?;
        if let Err(error) = engine.install(&cgroup, facts, log) {
            // Nothing ran in it. Without an entry it must not stay around
            // for a later launch to find.
            if let Err(error) = cgroup.destroy(CGROUP_DESTROY_LIMIT).await {
                tracing::warn!(box_id = %record.id, %error, "removing the box's unused cgroup");
            }
            return Err(refused(error));
        }
        tracing::debug!(
            box_id = %record.id,
            cgroup = %cgroup.path().display(),
            cgroup_id = cgroup.id(),
            "made the box's cgroup"
        );
        self.cgroup = Some(cgroup.clone());
        Ok(Some(cgroup))
    }

    /// Ends the box's cgroup: kills what is left in it, waits for it to
    /// empty, removes it, and takes the box out of the policy engine. The
    /// engine's entry goes also when processes outlived the kill, which
    /// leaves them without network.
    async fn destroy_cgroup(&mut self) {
        let Some(cgroup) = self.cgroup.take() else {
            return;
        };
        if let Err(error) = cgroup.destroy(CGROUP_DESTROY_LIMIT).await {
            tracing::warn!(
                box_id = %self.record.id(),
                %error,
                "the box's cgroup could not be removed; the next daemon start removes it"
            );
        }
        crate::net::engine::Engine::current().uninstall(*self.record.id());
    }

    /// The processes a stop of this box signals: its cgroup's, or its
    /// entrypoint when it has no cgroup.
    fn processes(&self, host: &box_runtime::HostHandle) -> box_runtime::BoxProcesses {
        match &self.cgroup {
            Some(cgroup) => box_runtime::BoxProcesses::Cgroup(cgroup.clone()),
            None => box_runtime::BoxProcesses::Entrypoint(host.clone()),
        }
    }

    /// Launches a host for this session.
    ///
    /// The one path all callers take: [`Self::attach`], which has a client
    /// channel and passes it in as `progress` so the sandbox coming up is
    /// rendered on the client's terminal, [`Self::ensure_host`], which has
    /// no channel at all, and [`Self::launch_host_for_hooks`], which
    /// runs before the session is `Active` (hence `phase`). The channel goes
    /// in and comes back out because progress rendering borrows it for the
    /// duration; storing the result is left to the caller, since attach only
    /// keeps a host it could bind to.
    ///
    /// `for_hooks` says what the launch is *for*, which `phase` cannot say:
    /// the phase records the status-gate posture (an attach and a teardown
    /// hook launch are both `Attached`; finalize's activation launch is
    /// `Activating`), while this flag marks the launches minted only for
    /// lifecycle hooks, whose pty nobody reads. It is the launcher's to
    /// carry, so the launch-scoped decisions downstream (the
    /// unenforced-placement advisory) can tell a session start from a hook
    /// run.
    // Left positional: three call sites, each naming every argument it means,
    // so a struct would be ceremony rather than clarity.
    #[expect(
        clippy::too_many_arguments,
        reason = "three call sites, each naming every argument it means"
    )]
    pub(super) async fn launch_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
        sz: WinSize,
        attach_env: box_runtime::AttachEnv,
        progress: Option<ChannelProgress>,
        phase: LaunchPhase,
        for_hooks: bool,
    ) -> Result<(Option<Channel<Msg>>, LaunchedHost), AttachError> {
        let launched = self
            .start_host(
                session_hnd,
                conn_username,
                sz,
                attach_env,
                progress,
                phase,
                for_hooks,
            )
            .await;
        if launched.is_err() {
            self.release_failed_launch().await;
        }
        launched
    }

    /// Takes back what a launch that failed made for the box: its cgroup,
    /// and with it the box's entry in the policy engine and its endpoints.
    /// The launch's own guards have released the rest (the address on the
    /// virtual network, the forwards). A host that still runs keeps
    /// everything: the failed launch was to replace it, and the cgroup is
    /// the one its processes are in.
    async fn release_failed_launch(&mut self) {
        let host_alive = matches!(
            &self.inner,
            BoxInner::Active { host: Some((host, _)), .. } if host.is_alive()
        );
        if host_alive || self.cgroup.is_none() {
            return;
        }
        tracing::info!(
            box_id = %self.record.id(),
            "the box did not start; removing its cgroup and its network policy"
        );
        self.destroy_cgroup().await;
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments of `launch_host`, passed on"
    )]
    async fn start_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
        sz: WinSize,
        attach_env: box_runtime::AttachEnv,
        progress: Option<ChannelProgress>,
        phase: LaunchPhase,
        for_hooks: bool,
    ) -> Result<(Option<Channel<Msg>>, LaunchedHost), AttachError> {
        // BOX-013: a stop ended the box's processes and could not set its
        // record to `stopped`. The record still says running, so no launch
        // starts new processes in the box before the retried stop.
        // BOX-037: the same for a timeout that ended the box's processes and
        // could not set its record to `exited`.
        if let Some(ending) = self.unrecorded_exit {
            tracing::warn!(
                box_id = %self.record.id(),
                ending = ?ending,
                "launch refused: the timeout ended the box and its record is not exited yet"
            );
            return Err(AttachError::LaunchRecordUnwritable(std::io::Error::other(
                "this session ran past its timeout and ended, and its exited state is not saved yet",
            )));
        }
        if let Some(ending) = self.unrecorded_stop {
            tracing::warn!(
                box_id = %self.record.id(),
                ending = ?ending,
                "launch refused: a stop ended the box and its record is not stopped yet"
            );
            return Err(AttachError::LaunchRecordUnwritable(std::io::Error::other(
                "a stop ended this session's processes, and its stopped state is not saved yet",
            )));
        }
        // Taken first, so a confirmation never outlives the launch it was
        // read for, whichever way that launch ends.
        let rejoins_row = std::mem::take(&mut self.relaunch_row_confirmed) && !for_hooks;
        let record = self.record.record().await.unwrap();
        let paths = self.paths().await;
        // Kept before the launcher consumes `attach_env`: the launch folds
        // these into the shell's environment, and the host keeps them so it
        // can layer them onto everything it later runs in the session and
        // republish them for the shell to re-read. BEP-007: the grants'
        // sealed values join this layer here, so the shell's launch
        // environment holds them before its entrypoint runs.
        let mut attach_env = attach_env;
        let connection_env = box_runtime::place_launch_deliveries(
            &mut attach_env,
            record.id,
            &box_runtime::launch_deliveries(&record),
        );
        // The box starts from its stored spec. The actor keeps its hold, so
        // the next launch reads the same spec. A stored spec that cannot be
        // read refuses the launch, as a resume of it is refused: the box's
        // first process cannot be decided without it.
        let spec = self.held_spec().await.map_err(|error| {
            AttachError::SpawnFailed(std::io::Error::new(
                error.kind(),
                format!(
                    "{error} Destroy it with `min session destroy {name}`, then start a new \
                     one with `min session activate`.",
                    name = registry_name(&record),
                ),
            ))
        })?;
        // A hook launch holds the shell. Every other launch starts the
        // spec's entrypoint, so a task box runs its task as its first
        // process, and the box ends when that process returns (BOX-038).
        let spec = box_runtime::LaunchSpec { spec, for_hooks };
        // Read before the launcher takes the spec: the host hands it to each
        // binding, which raises no shell-exit prompt for a box that ends.
        let ends_with_entrypoint = ends_with_entrypoint(spec.spec.as_deref());
        let entry = (!for_hooks)
            .then(|| spec.spec.as_deref().and_then(entry_run_as_entrypoint))
            .flatten()
            .map(str::to_string);
        // BOX-037: a launch that starts the entrypoint of an `until_complete`
        // box with a timeout arms the deadline. A hook launch starts no
        // entrypoint and leaves the deadline as it is.
        let timeout_secs = (!for_hooks)
            .then(|| spec.spec.as_deref().and_then(timeout_of))
            .flatten();
        let launcher = self
            .session_launcher(session_hnd, &record, spec, attach_env, phase, for_hooks)
            .await?;
        // Where the shell-exit prompt's save-then-delete lane archives the
        // changed files. Daemon-side and session-independent; created on
        // demand at save time.
        let archives_dir = self
            .minimal_state_dir
            .as_utf8_path()
            .as_std_path()
            .join("archives");
        // Arm the workspace baseline once, before this session's first host
        // launches; a host rebuilt on reattach reuses it rather than
        // re-snapshotting the already-modified workspace. See
        // [`WorkspaceBaseline`].
        let delta = match &self.workspace_baseline {
            WorkspaceBaseline::Armed(delta) => delta.clone(),
            WorkspaceBaseline::Unarmed => {
                let workspace_root = paths.working.as_utf8_path().as_std_path().to_path_buf();
                let delta = self.load_or_arm_baseline(workspace_root).await;
                self.workspace_baseline = WorkspaceBaseline::Armed(delta.clone());
                delta
            }
        };
        // NET-129: the shared-address ports this box holds are the ones
        // this launch binds forwards for. Marked before the spawn binds
        // them, so no publish takes one from under the bind, and recorded
        // below so a restarted daemon gives them back to this box.
        #[cfg(target_os = "linux")]
        let bound_ports = matches!(record.network, boxes::NetworkMode::OwnIp).then(|| {
            self.hostnames
                .write()
                .expect("hostname registry lock poisoned")
                .mark_held_ports_bound(record.id)
        });
        // NET-070: a resumed box stays `stopped` until its host's loop calls
        // `mark_running`, and the launch can start its processes before that.
        // The launch mark counts the box as live from here, so the hostname
        // proxy looks up who owns a connection from the node's address.
        // The launch number guards the stop mark: a host loop that this
        // launch replaces cannot mark this launch's box stopped.
        let host_launch = self
            .hostnames
            .write()
            .expect("hostname registry lock poisoned")
            .begin_host_launch(record.id);
        let spawn = Box::pin(box_runtime::Host::spawn(
            launcher,
            box_runtime::HostParams {
                name: registry_name(&record),
                username: conn_username,
                paths,
                sz,
                channel: None,
                // Mint a handle to this session ID in the sessions actor/manager.
                control: Some(BoxControl::new(self.manager.clone(), record.id)),
                delta,
                archives_dir,
                // A registered box: its shell-exit prompt says a kept session's
                // network registration is restored on its next attach or exec
                // (NET-138).
                holds_host_row: record.box_addresses.is_some(),
                ends_with_entrypoint,
                session_id: record.id,
                // The host runs attach and detach itself: it owns the terminal
                // they write to and the process whose namespaces they join.
                composition: self.composition(),
                connection_env,
                // The host owns the box's name-lifecycle half (NET-128): its
                // `mainloop` marks the name running on the way in and stopped
                // on the way out, so a shared-address name answers NODATA while
                // no host is alive to answer it.
                #[cfg(target_os = "linux")]
                name_marker: Some(box_runtime::NameMarker::new(
                    Arc::clone(&self.hostnames),
                    record.id,
                    host_launch,
                )),
            },
        ));

        let (channel, spawned) = match progress {
            Some(progress) => {
                let (channel, spawned) = progress.run(spawn).await;
                (Some(channel), spawned)
            }
            None => (None, spawn.await),
        };
        let (host, task) = spawned.map_err(|e| {
            AttachError::SpawnFailed(with_userns_hint(e, userns_spawn_hint().as_deref()))
        })?;
        // The confirmation was a read, not a reservation: the VM host daemon
        // may have withdrawn the row between that read
        // and this launch (NET-138). Read it again now the new host is up,
        // before the slot is marked as holding it; a row gone in between
        // ends the launch as the read before it would have.
        if rejoins_row && !self.host_row_stands(&record).await {
            let _ = host.kill(false).await;
            return Err(AttachError::BoxHostRowEnded);
        }
        // Whatever this launch replaces, the slot it goes into no longer
        // holds the launch that bound the box's host-side row; only the
        // binding launch itself, below, sets this again — or a relaunch the
        // VM host daemon just confirmed its standing row for, which rejoins
        // the switch under that row.
        self.slot_holds_row =
            record.box_addresses.is_some() && record.host_row_bound && rejoins_row;
        // The first launch of a registered box binds its host-side row
        // (NET-138). Recorded on the record, so a restarted daemon knows the
        // row is gone, before anything else can fail the launch: the kill
        // below ends the switch attachment, and with it the row, so a
        // binding not yet recorded by then would let a later launch run
        // rowless. A binding that cannot be recorded fails the launch the
        // same way.
        if record.box_addresses.is_some()
            && !record.host_row_bound
            && let Err(e) = self.record_host_row_bound().await
        {
            let _ = host.kill(false).await;
            return Err(AttachError::LaunchRecordUnwritable(e));
        }
        // BOX-038: the actor reads how this launch's loop ends. A later
        // launch replaces the watch, so an earlier loop never ends the box.
        let box_name = record.name.clone().unwrap_or_else(|| record.id.to_string());
        let (task, watch) = watch_entrypoint_exit(task, record.id, box_name, entry);
        self.entrypoint_watch = Some(watch);
        if let Some(secs) = timeout_secs {
            self.arm_timeout(secs);
        }
        // A write that fails costs only the restart's memory of who bound
        // the port, never this launch: said, and the box is handed back.
        #[cfg(target_os = "linux")]
        if let Some(bound_ports) = bound_ports
            && let Err(error) = self.record_bound_ports(bound_ports).await
        {
            tracing::warn!(
                session_id = %record.id,
                %error,
                "the launch could not record the shared-address ports it bound; \
                 a daemon restart may hand them to another box"
            );
        }
        Ok((channel, (host, task)))
    }

    /// Records on this session's record that a launch bound the box's
    /// host-side row, and marks the slot's coming host as that launch. See
    /// [`Self::host_row_lost`].
    pub(super) async fn record_host_row_bound(&mut self) -> Result<(), std::io::Error> {
        let mut record = self.record.record().await?;
        record.host_row_bound = true;
        self.record.write(record).await?;
        self.slot_holds_row = true;
        Ok(())
    }

    /// Whether this registered box's host-side row is gone (NET-138): the
    /// record says a launch bound it, and the slot does not hold that
    /// launch's host alive. The row lives exactly as long as the binding
    /// launch's switch attachment and the daemon never registers it again,
    /// so a box in this state must not be handed a host — every one would
    /// be rowless.
    /// False for a box that carries no host-handed addresses, and for a
    /// registered box no launch has bound yet: its first launch binds it.
    ///
    /// When the binding launch's host is gone, the VM host daemon is asked
    /// whether its row still stands: the box's creator may resume a
    /// withdrawn one, so a row that stands is the host's own word that a
    /// relaunch rejoins the switch under it. The answer is the host's
    /// table, never a fact this daemon asserts; a host that cannot be asked
    /// — a native host, or a door that does not answer — reads as no row.
    ///
    /// A row the host confirms while the slot holds no live host is left
    /// for the relaunch that follows ([`Self::relaunch_row_confirmed`]), so
    /// later attaches and execs reuse that host without asking again.
    pub(super) async fn host_row_lost(&mut self, record: &Record) -> bool {
        self.relaunch_row_confirmed = false;
        let slot_alive = matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        );
        if record.box_addresses.is_none()
            || !record.host_row_bound
            || (self.slot_holds_row && slot_alive)
        {
            return false;
        }
        let standing = self.host_row_stands(record).await;
        self.relaunch_row_confirmed = standing && !slot_alive;
        !standing
    }

    /// Whether the VM host daemon says this registered box's row stands.
    /// A host that cannot be asked reads as no row.
    pub(super) async fn host_row_stands(&mut self, record: &Record) -> bool {
        if record.box_addresses.is_none() {
            return false;
        }
        self.switch_control().await.box_standing().await == Some(true)
    }

    /// The spec stored beside this box's record, read by the first launch
    /// and then held by the actor. `None` for a box filed with no spec: that
    /// box starts its shell, as every box did before its spec named an
    /// entrypoint.
    ///
    /// # Errors
    ///
    /// A stored spec this daemon cannot read, or a failed read of the store.
    /// The launch is refused, and the error is not held.
    pub(super) async fn held_spec(&mut self) -> std::io::Result<Option<Arc<mfile::spec::BoxSpec>>> {
        if let Some(held) = &self.held_spec {
            return Ok(held.clone());
        }
        let stored = match self.record.object().await {
            Ok(object) => object.load_spec(),
            Err(error) => Err(error),
        };
        // An error is not held: the next launch reads the store again.
        let spec = match stored {
            Ok(Some(bytes)) => match box_runtime::stored_spec(&bytes) {
                Ok(spec) => Some(Arc::new(spec)),
                Err(error) => {
                    tracing::warn!(
                        box_id = %self.record.id(),
                        %error,
                        "launch: the stored spec cannot be read; the launch is refused"
                    );
                    return Err(error);
                }
            },
            // A box filed with no spec starts its shell.
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    box_id = %self.record.id(),
                    %error,
                    "launch: reading the stored spec failed; the launch is refused"
                );
                return Err(std::io::Error::new(
                    error.kind(),
                    "The settings it was created with cannot be read.",
                ));
            }
        };
        self.held_spec = Some(spec.clone());
        Ok(spec)
    }

    /// Hands back this session's host, launching one if none is running.
    ///
    /// Unlike [`Self::attach`] there is no channel: the host is minted with
    /// nothing bound to it, because the caller wants the *sandbox* — to run a
    /// command inside it — not a terminal. A client that attaches later reuses
    /// this host and resizes its PTY, so the placeholder size is only ever what
    /// an unattached session's shell sees.
    ///
    /// Gated on the same `Active` record status as `attach`, without its
    /// draft-session shortcut: composing a loadout is a client-driven flow, and
    /// an exec request is not the place to start one.
    pub(super) async fn ensure_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
    ) -> Result<box_runtime::HostHandle, AttachError> {
        // Taken first, so a staged value never waits for a later launch.
        let staged = entrypoint_env::take(self.record.id());
        let entrypoint_run = staged.is_some();
        let (staged_env, staged_drops) = staged.unwrap_or_default();
        let holds_host_row = {
            let record = self
                .record
                .record()
                .await
                .map_err(AttachError::LoadoutFailed)?;
            // An ended box is resumed only by an attach (BOX-025). A host
            // launched here would run its entrypoint again behind the
            // record's back. Checked before the `Active` gate below: an
            // ended box is not `Active` either, and the gate's refusal says
            // the box is still activating, which an ended box is not.
            if let Ok(
                state @ (boxes::core::record::RecordState::Stopped(_)
                | boxes::core::record::RecordState::Exited(_)),
            ) = record.state()
            {
                return Err(AttachError::ResumeRefused(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "box {} is {}. Only a running box can run a command.",
                            record
                                .name
                                .clone()
                                .unwrap_or_else(|| self.record.id().to_string()),
                            state.name()
                        ),
                    ),
                    2,
                ));
            }
            if record.status != BoxState::Active {
                return Err(AttachError::SessionPending);
            }
            // Attach's refusal, for the same reason: neither the host a
            // later launch left in the slot nor a fresh one would hold the
            // registered box's host-side row.
            if self.host_row_lost(&record).await {
                return Err(AttachError::BoxHostRowEnded);
            }
            record.box_addresses.is_some()
        };

        let running = match &self.inner {
            BoxInner::Draft { .. } => return Err(AttachError::SessionPending),
            BoxInner::Active {
                host: Some((h, _)), ..
            } if h.is_alive() => Some(h.clone()),
            BoxInner::Active { .. } => None,
        };
        if let Some(host) = running {
            // A hook launch holds the shell, never the spec's argv. A task
            // run on a box whose entrypoint is an argv, a task box,
            // replaces that shell with its entrypoint here, or the task
            // never runs. Any other caller (an exec, an attach, a resume)
            // keeps the shell: it staged no environment for the entrypoint.
            // A box that holds a host-side row keeps it, as an attach keeps
            // it.
            let replace =
                entrypoint_run && self.host_origin == HostOrigin::Hooks && self.starts_argv().await;
            if replace && !holds_host_row {
                tracing::info!(
                    box_id = %self.record.id(),
                    "replacing the hook-launched shell with the box's entrypoint"
                );
                if let BoxInner::Active {
                    host: slot @ Some(_),
                    ..
                } = &mut self.inner
                {
                    let (handle, mut join) = slot.take().expect("matched on Some");
                    Self::kill_and_stop_loop(&handle, &mut join, false).await;
                }
            } else {
                if replace {
                    // The hook shell never exits (BOX-015), so a run that
                    // relayed it would wait for a task that never starts.
                    tracing::warn!(
                        box_id = %self.record.id(),
                        "refused the run: replacing the hook-launched shell would end the \
                         box's host-side row, so the box's entrypoint cannot start"
                    );
                    return Err(AttachError::SpawnFailed(std::io::Error::other(
                        EntrypointBehindHookShell,
                    )));
                }
                if entrypoint_run {
                    self.clear_ends_with_run().await;
                }
                // Same claim as the launch below, for a host this call did
                // not mint: an exec is about to run in this sandbox, so a
                // later attach must not replace the shell out from under
                // it. Without this, a host minted for lifecycle hooks stays
                // `Hooks` through every exec that reuses it, and the first
                // interactive attach would respawn it — killing a command
                // that is still running.
                self.host_origin = HostOrigin::Exec;
                return Ok(host);
            }
        }

        // The wait for a closed host's exit did not settle, so the box may
        // be ending. A launch here could run an `until_complete`
        // entrypoint a second time (BOX-038): refuse, and launch nothing.
        if self.exit_unsettled {
            tracing::warn!(
                box_id = %self.record.id(),
                "refused the exec: the box's last host ended and its exit is not known yet"
            );
            let name = self
                .record
                .record()
                .await
                .ok()
                .and_then(|record| record.name)
                .unwrap_or_else(|| self.record.id().to_string());
            return Err(AttachError::ResumeRefused(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("box {name} is ending. Only a running box can run a command."),
                ),
                2,
            ));
        }
        // Only a launch records the run's dropped names: a run that joined
        // the running host above relays the in-box run an earlier launch
        // started, with that launch's names. Recorded before the launch, so
        // the in-box run the entrypoint starts finds them.
        if entrypoint_run {
            entrypoint_env::record(*self.record.id(), staged_drops);
        }
        let (_, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                UNATTACHED_WIN_SIZE,
                box_runtime::AttachEnv {
                    inherited: Vec::new(),
                    connection: Vec::new(),
                    // For the entrypoint's process alone: a later exec in
                    // the box never sees a task run's variables.
                    entrypoint: staged_env,
                },
                None,
                LaunchPhase::Attached,
                false,
            )
            .await?;

        let host = launched.0.clone();
        let BoxInner::Active { host: slot, .. } = &mut self.inner else {
            unreachable!("ensure_host returns early on a Draft session");
        };
        *slot = Some(launched);
        // Minted for an exec: a command is about to run in this sandbox, so a
        // later attach must not replace it. See [`HostOrigin::Exec`].
        self.host_origin = HostOrigin::Exec;
        self.publish_host();
        if entrypoint_run {
            self.clear_ends_with_run().await;
        }
        Ok(host)
    }

    /// Starts the box's entrypoint again for a restart (BOX-176), with no
    /// client attached. The restart already set the record to `running`
    /// from the stored spec.
    ///
    /// A host that the restart launched for `on_activate` (BOX-028) is kept
    /// when the box starts its shell, and the shell starts when a client
    /// attaches, as after an activation. It is replaced when the box starts
    /// an argv, or the entrypoint never starts. A box that holds a host-side
    /// row keeps its host, as an attach keeps it. The launch runs no
    /// lifecycle hook (BOX-177).
    pub(super) async fn restart_launch(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
    ) -> Result<(), AttachError> {
        let holds_host_row = self
            .record
            .record()
            .await
            .map_err(AttachError::LoadoutFailed)?
            .box_addresses
            .is_some();
        let live_hooks_host = matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        ) && self.host_origin == HostOrigin::Hooks;
        if live_hooks_host {
            let starts_argv = self.starts_argv().await;
            if holds_host_row && starts_argv {
                // As `ensure_host` refuses it: replacing the hook shell would
                // end the box's host-side row, and keeping it never starts
                // the entrypoint (BOX-176, BOX-178).
                // Known gap: a restart of such a box fails closed. Tracked by
                // https://github.com/gominimal/minimal/issues/3231. It flips
                // when the hook shell can be replaced without ending the
                // host-side row (#3042).
                tracing::warn!(
                    box_id = %self.record.id(),
                    "restart: refused the start: replacing the hook-launched shell would end \
                     the box's host-side row, so the box's entrypoint cannot start"
                );
                return Err(AttachError::SpawnFailed(std::io::Error::other(
                    EntrypointBehindHookShell,
                )));
            }
            if !starts_argv {
                tracing::info!(
                    box_id = %self.record.id(),
                    "restart: keeping the host launched for on_activate"
                );
                return Ok(());
            }
            tracing::info!(
                box_id = %self.record.id(),
                "restart: replacing the host launched for on_activate with the box's entrypoint"
            );
        }
        // A host left in the slot runs nothing the restart keeps.
        if let BoxInner::Active {
            host: slot @ Some(_),
            ..
        } = &mut self.inner
        {
            let (handle, mut join) = slot.take().expect("matched on Some");
            Self::kill_and_stop_loop(&handle, &mut join, false).await;
        }
        #[cfg(test)]
        if restart_launch_seam::fails(self.record.id()) {
            return Err(AttachError::SpawnFailed(std::io::Error::other(
                "the test failed this launch",
            )));
        }
        let (_, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                UNATTACHED_WIN_SIZE,
                box_runtime::AttachEnv::default(),
                None,
                LaunchPhase::Attached,
                false,
            )
            .await?;
        let BoxInner::Active { host: slot, .. } = &mut self.inner else {
            return Err(AttachError::SessionPending);
        };
        *slot = Some(launched);
        // No client attached: a later attach reuses this host, as it reuses
        // one an exec launched.
        self.host_origin = HostOrigin::Exec;
        self.publish_host();
        Ok(())
    }

    /// Clears the record's `ends_with_run` mark once a task run started
    /// the box's entrypoint (T43, NET-131). Until then a daemon restart
    /// destroys the box, so a client lost before the task starts strands
    /// no box. After it, the box ends with its entrypoint and keeps its
    /// record (BOX-038). A failed write keeps the mark, and is logged.
    async fn clear_ends_with_run(&mut self) {
        let cleared = async {
            let mut record = self.record.record().await?;
            if !record.ends_with_run {
                return Ok(());
            }
            record.ends_with_run = false;
            self.record.write(record).await
        }
        .await;
        if let Err(error) = cleared {
            tracing::warn!(
                box_id = %self.record.id(),
                %error,
                "the task started, but the box's record still says a daemon restart \
                 destroys it"
            );
        }
    }

    /// Whether a launch of this box that is not for hooks starts an argv,
    /// not the shell: the spec names an argv entrypoint. A spec that cannot
    /// be read says no here, and the launch refuses it.
    async fn starts_argv(&mut self) -> bool {
        let Ok(spec) = self.held_spec().await else {
            return false;
        };
        let launch = box_runtime::LaunchSpec {
            spec,
            for_hooks: false,
        };
        matches!(
            launch.entrypoint(),
            Ok(box_runtime::LaunchEntrypoint::Argv { .. })
        )
    }

    pub(super) async fn mint_session_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
        channel: Channel<Msg>,
        sz: WinSize,
        attach_env: box_runtime::AttachEnv,
        session_keys: SessionKeys,
    ) -> Result<(), AttachError> {
        let progress = ChannelProgress::new(channel, self.tracker.clone(), (sz.cols, sz.rows));
        let (channel, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                sz,
                attach_env,
                Some(progress),
                LaunchPhase::Attached,
                false,
            )
            .await?;
        let channel = channel.expect("progress hands back the channel it was given");

        #[cfg(test)]
        let launched = mint_attach_seam::apply(*self.record.id(), launched).await;

        // Wire the channel to the freshly launched host. A failure here is
        // one of two things: the host died in the window between launch and
        // attach, or it is alive but wedged and its mailbox stayed full past
        // the attach deadline. The first is surfaced as a spawn failure rather
        // than leaving a dead, channel-less host — which is why a host whose
        // loop already ended is never stored. The second must not read as
        // death: it is the same wedged case the re-attach path refuses with
        // `SessionBusy`, and the host is stored before refusing, so a retry
        // reaches it through that path instead of minting a second host over
        // it, and teardown stops it instead of a dropped `JoinHandle`
        // detaching a live loop.
        //
        // The launch already folded this attach's connection facts into the
        // shell's environment, so nothing new is passed here: the host holds
        // them, and an empty map means "no revision", not "no terminal".
        let outcome = match launched
            .0
            .attach(channel, sz, box_runtime::ConnectionEnv::new(), session_keys)
            .await
        {
            Ok(()) => Ok(()),
            // The host's loop ended before the attach could be delivered.
            Err(box_runtime::HostAttachError::Closed(..)) => {
                return Err(AttachError::SpawnFailed(spawn_failed_error(
                    userns_spawn_hint().as_deref(),
                )));
            }
            // The host is alive but its mailbox stayed full past the attach
            // deadline: the same wedged case the re-attach path refuses with
            // `SessionBusy`, and for the same reason — re-minting would abort
            // a busy-but-healthy shell. The host is still stored below.
            Err(box_runtime::HostAttachError::Timeout) => Err(AttachError::SessionBusy),
        };
        let BoxInner::Active { host, .. } = &mut self.inner else {
            unreachable!("mint_session_host is only reachable from the Active state");
        };
        // A wedged-but-alive host can reach here via attach's re-mint branch
        // (`box_runtime.rs` `SendTimeoutError::Timeout`): its loop task is
        // still running. Dropping the replaced `(HostHandle, JoinHandle)`
        // would detach that task, leaking the old sandbox process, pty master,
        // and `NetGuard` for the daemon's lifetime — one leak per attach to the
        // same wedged host. Abort the task being replaced, mirroring
        // `stop_running` (a no-op when the old loop had already exited).
        if let Some((_, task)) = host.replace(launched) {
            task.abort();
        }
        // Minted by an attach: its environment describes the terminal that is
        // here, so nothing may replace it out from under that client.
        self.host_origin = HostOrigin::Interactive;
        self.publish_host();
        outcome
    }

    /// True when this session's composition declares at least one script for
    /// `event`. Gates the headless host launches ([`Self::finalize`]'s and
    /// [`Self::run_detach_hooks`]'s): without it, a transition would pay for
    /// a sandbox no hook is going to use.
    pub(super) fn has_hooks_for(&self, event: crate::hooks::HookEvent) -> bool {
        let BoxInner::Active {
            composition: Some(c),
            ..
        } = &self.inner
        else {
            return false;
        };
        c.lifecycle_hooks()
            .iter()
            .any(|ph| event.script_of(ph.hook()).is_some())
    }

    /// Runs this session's hooks for `event` headlessly, minting a host
    /// first when none is running.
    ///
    /// The launch is what makes this reliable. A hook runs *inside* the
    /// session, so it needs a process whose namespaces it can join, and
    /// neither teardown transition is guaranteed one: the host slot outlives
    /// the host process, so a session whose shell has exited still holds a
    /// handle to a host that can no longer run anything, and a session that
    /// was never attached may have no host at all. Minting here — the same
    /// launch [`Self::finalize`] does for activation — covers both, and a
    /// session whose shell is still up (the ctrl-w detach, a destroy from a
    /// second terminal) reuses it rather than starting a second one.
    ///
    /// Best effort, and *bounded*: a teardown that cannot run its hooks
    /// still happens, so every failure is logged, none is propagated, and
    /// nothing here may block indefinitely — see [`HOOK_LAUNCH_TIMEOUT`].
    /// Activation is the exception and keeps its own path in
    /// [`Self::finalize`] — a failed activate hook aborts the activation
    /// rather than being logged past.
    ///
    /// Returns the outcomes of the hooks that ran, for a caller that
    /// reports them (destroy does); empty when none could.
    pub(super) async fn run_hooks_headless(
        &mut self,
        event: crate::hooks::HookEvent,
    ) -> Vec<crate::hooks::HookOutcome> {
        if !self.has_hooks_for(event) {
            return Vec::new();
        }
        // `Attached`, not `Activating`: both transitions only happen once the
        // session is `Active`, so neither has reason to skip the status gate.
        // A session torn down before it activated (an aborted finalize leaves
        // it `Materializing`) is refused here and skips its hooks — teardown
        // for setup that never completed.
        //
        // Timed out rather than simply awaited: this runs on the destroy
        // path, and building a sandbox reaches the filesystem, the package
        // cache, and (for an own-IP session) the network switch. A session
        // must always be destroyable, so a launch that wedges has to cost
        // its hooks rather than the whole teardown.
        match tokio::time::timeout(
            HOOK_LAUNCH_TIMEOUT,
            self.launch_host_for_hooks(LaunchPhase::Attached),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    event = event.as_str(),
                    error = %e,
                    "launching the session to run its hooks failed; skipping them",
                );
                return Vec::new();
            }
            Err(_elapsed) => {
                tracing::warn!(
                    event = event.as_str(),
                    timeout_secs = HOOK_LAUNCH_TIMEOUT.as_secs(),
                    "launching the session to run its hooks timed out; skipping them",
                );
                return Vec::new();
            }
        }
        run_session_hooks(&self.inner, &self.record, event).await
    }

    /// Launch the session host so lifecycle hooks have namespaces to
    /// join, and keep it as the session's host.
    ///
    /// Headless: there is no client channel, no PTY negotiated, and no
    /// forwarded locale — neither the activating RPC nor a departing
    /// binding is an attach. The window size is a placeholder the first
    /// real attach replaces.
    ///
    /// A host that is still *running* (an attach raced the finalize; a
    /// ctrl-w detach left the shell up) is left alone. A dead one is
    /// replaced rather than reused: the slot outlives the process, so a
    /// session whose shell exited still holds a handle to a host that can no
    /// longer run anything — which is exactly the state a detach hook meets
    /// on the shell-exit path. Mirrors [`Self::ensure_host`]'s liveness
    /// check for the same reason.
    pub(super) async fn launch_host_for_hooks(
        &mut self,
        phase: LaunchPhase,
    ) -> Result<(), std::io::Error> {
        if matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        ) {
            return Ok(());
        }
        let session_hnd = self.weak_self.upgrade().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is shutting down; cannot run lifecycle hooks",
            )
        })?;
        let username = self
            .record
            .record()
            .await?
            .username
            .unwrap_or_else(|| "user".to_string());
        let launched = self
            .launch_host(
                session_hnd,
                username,
                WinSize {
                    rows: 24,
                    cols: 80,
                    xpixel: 0,
                    ypixel: 0,
                },
                box_runtime::AttachEnv::default(),
                None,
                phase,
                // This launch exists only so the hooks have namespaces to
                // join — a hook run, not a session start. See
                // [`BoxActor::launch_host`].
                true,
            )
            .await
            .map_err(|e| {
                std::io::Error::other(format!("launching the session to run its hooks: {e}"))
            })?
            .1;
        let BoxInner::Active { host, .. } = &mut self.inner else {
            unreachable!("a headless hook launch only reaches here from the Active state");
        };
        *host = Some(launched);
        // Minted for hooks, with no terminal to describe: an interactive
        // attach may replace this shell rather than inherit its blank `TERM`.
        // See [`HostOrigin::Hooks`].
        self.host_origin = HostOrigin::Hooks;
        self.publish_host();
        Ok(())
    }
}

/// The daemon's grace period between a stop's SIGTERM and its SIGKILL
/// (BOX-013). The daemon has no setting for it yet.
pub(crate) const STOP_GRACE: std::time::Duration = minimald_rpc::STOP_GRACE;

/// How often a stop checks, inside its grace period, whether the box ended.
const STOP_POLL: std::time::Duration = std::time::Duration::from_millis(50);

/// The name of a signal a stop sends, for the log.
fn stop_signal_name(signal: i32) -> &'static str {
    match signal {
        libc::SIGTERM => "SIGTERM",
        libc::SIGKILL => "SIGKILL",
        _ => "signal",
    }
}

/// The names of `signals`, in order, for the log and the span.
pub(super) fn signal_names(signals: &[i32]) -> Vec<&'static str> {
    signals.iter().map(|s| stop_signal_name(*s)).collect()
}

/// The grace period between the SIGTERM and the SIGKILL a timeout sends
/// (BOX-037): the stop's [`STOP_GRACE`]. A test can shorten it per box.
fn timeout_grace(box_id: &boxes::SessionId) -> std::time::Duration {
    #[cfg(test)]
    if let Some(grace) = super::timeout_grace_seam::grace(box_id) {
        return grace;
    }
    let _ = box_id;
    STOP_GRACE
}

/// How long the processes of a stopped box get to leave its cgroup after
/// the kill, before the cgroup is left for the next daemon start.
const CGROUP_DESTROY_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// What a stop's signals did to the box (BOX-013).
#[derive(Debug)]
pub(crate) struct StopOutcome {
    /// How the box ended, as its record stores it.
    pub(crate) ending: boxes::core::record::StopEnding,
    /// The signals the stop sent, in order.
    pub(crate) sent: Vec<i32>,
    /// The host's runtime loop, when it did not end inside
    /// [`HOST_PROBE_TIMEOUT`] after the last signal. The caller stops it.
    pub(crate) unfinished: Option<JoinHandle<Result<box_runtime::HostExit, std::io::Error>>>,
}

/// Sends a stop's signals to every process in the box (BOX-013), and reads
/// how the entrypoint ended from the host loop `entrypoint`, which ends when
/// the entrypoint does.
///
/// A graceful stop sends SIGTERM, waits up to `grace` for the box to have no
/// process left, then sends SIGKILL to the processes still running. A forced
/// stop sends SIGKILL at once. A graceful stop that finds `forced` set, at
/// its start or in its grace period, ends the grace and sends SIGKILL at
/// once: a forced stop sent meanwhile sets it. The ending stores the signal
/// that the entrypoint ended after, unless the entrypoint exited with a
/// status of its own.
///
/// In a real box the entrypoint is the init of the box's PID namespace. The
/// kernel delivers SIGTERM from the daemon's namespace to that init only
/// when the init has a handler for it. An entrypoint without a SIGTERM
/// handler, such as a plain shell, keeps running through the grace period.
/// The SIGKILL then ends it, and the ending stores SIGKILL. BOX-013 asks for
/// that order: SIGTERM, the grace period, then SIGKILL to what still runs.
pub(crate) async fn stop_box_processes(
    box_id: boxes::SessionId,
    processes: box_runtime::BoxProcesses,
    mut entrypoint: JoinHandle<Result<box_runtime::HostExit, std::io::Error>>,
    force: bool,
    grace: std::time::Duration,
    forced: &std::sync::atomic::AtomicBool,
) -> StopOutcome {
    use boxes::core::record::StopEnding;

    let signal = async |signal: i32| -> usize {
        let reached = processes.signal(signal).await;
        tracing::info!(
            box_id = %box_id,
            signal = stop_signal_name(signal),
            signal_number = signal,
            processes = reached,
            "stop: signalled every process in the box"
        );
        reached
    };
    let left = || processes.left();

    // `Some(None)`: the entrypoint ended before the stop sent a signal.
    // `Some(Some(s))`: it ended after the signal `s`.
    let mut ended_after: Option<Option<i32>> = entrypoint.is_finished().then_some(None);
    let mut sent = Vec::new();
    let forced_now = || forced.load(std::sync::atomic::Ordering::SeqCst);
    if force || forced_now() {
        signal(libc::SIGKILL).await;
        sent.push(libc::SIGKILL);
    } else {
        signal(libc::SIGTERM).await;
        sent.push(libc::SIGTERM);
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            if ended_after.is_none() && entrypoint.is_finished() {
                ended_after = Some(Some(libc::SIGTERM));
            }
            if ended_after.is_some() && left() == 0 {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            if forced_now() {
                tracing::info!(
                    box_id = %box_id,
                    "stop: a forced stop arrived; the grace period ends now"
                );
                break;
            }
            tokio::time::sleep(STOP_POLL).await;
        }
        let still_running = left();
        tracing::info!(
            box_id = %box_id,
            grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX),
            entrypoint_ended = ended_after.is_some(),
            still_running,
            "stop: the grace period is over"
        );
        if ended_after.is_none() || still_running > 0 {
            if ended_after.is_none() && entrypoint.is_finished() {
                ended_after = Some(Some(libc::SIGTERM));
            }
            signal(libc::SIGKILL).await;
            sent.push(libc::SIGKILL);
        }
    }

    let last = sent.last().copied().unwrap_or(libc::SIGKILL);
    let mut unfinished = None;
    // The entrypoint's own exit status, from the reaped reason. The exit
    // code alone cannot say it: `hakoniwa` reports 125 both for a signalled
    // container and for an entrypoint that exits 125 itself.
    let exit_status = match tokio::time::timeout(HOST_PROBE_TIMEOUT, &mut entrypoint).await {
        Ok(Ok(Ok(exit))) => {
            tracing::info!(
                box_id = %box_id,
                code = exit.code,
                exit_code = exit.reason.as_ref().and_then(|r| r.exit_code),
                reason = exit.reason.as_ref().map_or("", |r| r.reason.as_str()),
                "stop: the host loop reaped the entrypoint"
            );
            exit.reason.and_then(|r| r.exit_code)
        }
        Ok(Ok(Err(error))) => {
            tracing::warn!(box_id = %box_id, %error, "stop: the host loop ended on an error");
            None
        }
        Ok(Err(error)) => {
            tracing::warn!(box_id = %box_id, %error, "stop: the host loop task failed");
            None
        }
        Err(_) => {
            tracing::warn!(
                box_id = %box_id,
                "stop: the host loop did not end after the last signal; the host is killed"
            );
            unfinished = Some(entrypoint);
            None
        }
    };
    let ending = match (ended_after.unwrap_or(Some(last)), exit_status) {
        (_, Some(status)) => StopEnding::ExitedFirst { exit_code: status },
        (Some(signal), None) => StopEnding::Signalled { signal },
        // It ended before the stop, and no signal of this daemon ended it.
        (None, _) => StopEnding::AtDaemonStart,
    };
    StopOutcome {
        ending,
        sent,
        unfinished,
    }
}

/// The `data` of the `exited` event a stop records (BOX-013): the reason,
/// and the exit code or the signal the record stores.
pub(crate) fn stopped_event_data(
    ending: boxes::core::record::StopEnding,
) -> boxes::events::EventData {
    let state = boxes::core::record::RecordState::Stopped(ending);
    let mut data = boxes::events::EventData::new();
    data.insert("reason".to_string(), "stopped".into());
    if let Some(code) = state.exit_code() {
        data.insert("exit_code".to_string(), code.into());
    }
    if let Some(signal) = state.signal() {
        data.insert("signal".to_string(), signal.into());
    }
    data
}

impl BoxActor {
    /// Stops the box and keeps its record (BOX-013): signals every process
    /// in it, tears its host down, sets the record to `stopped` with how the
    /// entrypoint ended, and records an `exited` event. One `box.stop` span
    /// covers the whole stop and carries the ending signal.
    pub(super) async fn stop_box(
        &mut self,
        force: bool,
        grace: std::time::Duration,
    ) -> Result<boxes::core::record::StopEnding, std::io::Error> {
        let box_id = *self.record.id();
        let span = tracing::info_span!(
            "box.stop",
            box_id = %box_id,
            force,
            grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX),
            ending_signal = tracing::field::Empty,
            ending_exit_code = tracing::field::Empty,
        );
        let stopped =
            tracing::Instrument::instrument(self.stop_box_inner(force, grace), span.clone()).await;
        if let Ok(ending) = &stopped {
            let state = boxes::core::record::RecordState::Stopped(*ending);
            if let Some(signal) = state.signal() {
                span.record("ending_signal", signal);
            }
            if let Some(code) = state.exit_code() {
                span.record("ending_exit_code", code);
            }
        }
        stopped
    }

    async fn stop_box_inner(
        &mut self,
        force: bool,
        grace: std::time::Duration,
    ) -> Result<boxes::core::record::StopEnding, std::io::Error> {
        let box_id = *self.record.id();
        tracing::info!(box_id = %box_id, force, "stop: requested");
        let launched = match &mut self.inner {
            BoxInner::Active { host, .. } => host.take(),
            BoxInner::Draft { .. } => None,
        };
        self.publish_host();
        // BOX-037: the timeout ended the processes and could not write the
        // `exited` record. `launch_host` refuses while it is unrecorded, so
        // no process runs, and this stop writes the timeout's ending.
        if launched.is_none()
            && let Some(ending) = self.unrecorded_exit
        {
            return self.write_kept_exit(ending).await;
        }
        let ending = match (self.unrecorded_stop, launched) {
            // An earlier stop ended the processes and could not write the
            // record. This one writes how they ended then. `launch_host`
            // refuses while that ending is unrecorded, so no host is here.
            (Some(ending), None) => {
                tracing::info!(
                    box_id = %box_id,
                    ending = ?ending,
                    "stop: the processes ended in an earlier stop; writing its record"
                );
                ending
            }
            // A host is in the slot: whether or not an earlier stop left an
            // unrecorded ending, its processes run now. This stop signals
            // them, and the record keeps how they ended.
            (_, Some((host, task))) => {
                let outcome = stop_box_processes(
                    box_id,
                    self.processes(&host),
                    task,
                    force,
                    grace,
                    &self.weak_self.3,
                )
                .await;
                tracing::info!(
                    box_id = %box_id,
                    signals = ?outcome
                        .sent
                        .iter()
                        .map(|s| stop_signal_name(*s))
                        .collect::<Vec<_>>(),
                    ending = ?outcome.ending,
                    "stop: the box's processes ended"
                );
                if let Some(mut task) = outcome.unfinished {
                    Self::kill_and_stop_loop(&host, &mut task, false).await;
                }
                outcome.ending
            }
            (None, None) => {
                tracing::info!(box_id = %box_id, "stop: the box has no process to signal");
                boxes::core::record::StopEnding::AtDaemonStart
            }
        };
        // The box is signalled: a forced stop that set the flag meanwhile
        // has had its effect, and the next stop starts without it.
        self.weak_self
            .3
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // The host is gone: this takes down what ran beside it, as every
        // other stop does.
        self.stop_running(false).await;

        // The `stopped` record is the step a stop cannot skip. A failed
        // read or write keeps the ending on the actor and returns the error,
        // and the actor keeps hosting the box for a retried stop.
        self.unrecorded_stop = Some(ending);
        if let Err(error) = self.write_stopped_record(ending).await {
            tracing::warn!(
                box_id = %box_id,
                %error,
                "stop: the processes ended, but the record could not be set to stopped"
            );
            return Err(error);
        }
        self.unrecorded_stop = None;
        let state = boxes::core::record::RecordState::Stopped(ending);
        tracing::info!(
            box_id = %box_id,
            exit_code = state.exit_code(),
            signal = state.signal(),
            "stop: set the record to stopped"
        );
        // The record already says `stopped`, so a failed event write is
        // logged and the stop still answers with its ending.
        let event = match self.record.object().await {
            Ok(object) => crate::box_manager::write_box_event(
                &object,
                boxes::events::BoxEventType::Exited,
                stopped_event_data(ending),
            )
            .map(drop),
            Err(error) => Err(error),
        };
        if let Err(error) = event {
            tracing::warn!(
                box_id = %box_id,
                %error,
                "stop: the record is stopped, but its exited event could not be written"
            );
        }
        Ok(ending)
    }

    /// Arms the deadline of an `until_complete` box whose spec sets a
    /// timeout of `secs` seconds (BOX-037), from now. A timeout too large
    /// for the clock arms nothing: the box never reaches it.
    pub(super) fn arm_timeout(&mut self, secs: u64) {
        let at = tokio::time::Instant::now().checked_add(std::time::Duration::from_secs(secs));
        self.timeout_deadline = at.map(|at| super::TimeoutDeadline { at, secs });
        tracing::info!(
            box_id = %self.record.id(),
            timeout_secs = secs,
            armed = self.timeout_deadline.is_some(),
            "timeout: the box's entrypoint started; the box ends when it runs past its timeout"
        );
    }

    /// Signals every process in a box that ran past its timeout (BOX-037),
    /// execs included, as a graceful stop does: SIGTERM, the grace period,
    /// then SIGKILL to what still runs. Then tears the host down, sets the
    /// record to `exited` with `reason = "timeout"` and no exit code, and
    /// records the `exited` event. Answers the signals sent, in order.
    ///
    /// A record write that fails returns the error. The processes are gone
    /// then, and the actor keeps hosting the box, so a `min box stop` can
    /// still set its record.
    pub(super) async fn time_out_box(
        &mut self,
        timeout_secs: u64,
    ) -> Result<Vec<i32>, std::io::Error> {
        let box_id = *self.record.id();
        tracing::info!(
            box_id = %box_id,
            timeout_secs,
            "timeout: the box ran past its timeout; ending it"
        );
        // The loop ends on these signals, and the exit is then nobody's:
        // the box ends with `reason = "timeout"`, not with the code.
        self.entrypoint_watch = None;
        let launched = match &mut self.inner {
            BoxInner::Active { host, .. } => host.take(),
            BoxInner::Draft { .. } => None,
        };
        self.publish_host();
        let sent = match launched {
            Some((host, task)) => {
                let outcome = stop_box_processes(
                    box_id,
                    self.processes(&host),
                    task,
                    false,
                    timeout_grace(&box_id),
                    &self.weak_self.3,
                )
                .await;
                if let Some(mut task) = outcome.unfinished {
                    Self::kill_and_stop_loop(&host, &mut task, false).await;
                }
                outcome.sent
            }
            None => {
                tracing::info!(box_id = %box_id, "timeout: the box has no process to signal");
                Vec::new()
            }
        };
        // A forced stop sent meanwhile has had its effect.
        self.weak_self
            .3
            .store(false, std::sync::atomic::Ordering::SeqCst);
        tracing::info!(
            box_id = %box_id,
            timeout_secs,
            signals = ?signal_names(&sent),
            "timeout: the box's processes ended"
        );
        self.stop_running(false).await;
        self.mark_name_stopped().await;

        let ending = boxes::core::record::ExitEnding::Timeout;
        // Kept until the write succeeds, as a stop keeps `unrecorded_stop`.
        self.unrecorded_exit = Some(ending);
        self.write_exited_record(ending).await?;
        self.unrecorded_exit = None;
        tracing::info!(
            box_id = %box_id,
            timeout_secs,
            signals = ?signal_names(&sent),
            reason = boxes::core::record::EndReason::Timeout.name(),
            "box exited: it ran past its timeout"
        );
        self.write_exited_event(ending).await;
        Ok(sent)
    }

    /// Writes the `exited` record and event that a timeout (BOX-037) kept
    /// on the actor when its own write failed. On success the box is
    /// `exited`, not `stopped`, so this answers an error, and the stop's
    /// caller answers from the record that the box already exited.
    async fn write_kept_exit(
        &mut self,
        ending: boxes::core::record::ExitEnding,
    ) -> Result<boxes::core::record::StopEnding, std::io::Error> {
        let box_id = *self.record.id();
        tracing::info!(
            box_id = %box_id,
            ending = ?ending,
            "stop: the timeout ended the processes earlier; writing its exited record"
        );
        self.write_exited_record(ending).await?;
        self.unrecorded_exit = None;
        tracing::info!(
            box_id = %box_id,
            ending = ?ending,
            "box exited: it ran past its timeout"
        );
        self.write_exited_event(ending).await;
        Err(std::io::Error::other(
            "the session already ended at its timeout",
        ))
    }

    /// Sets the box's record to `stopped` with `ending`.
    async fn write_stopped_record(
        &self,
        ending: boxes::core::record::StopEnding,
    ) -> Result<(), std::io::Error> {
        let mut record = self.record.record().await?;
        record.set_state(boxes::core::record::RecordState::Stopped(ending));
        self.record.write(record).await
    }
}

/// Test-only: fails the launch of a restart of a box (BOX-176), once,
/// before it starts anything, so a test can see what a failed start leaves.
/// Keyed by box id, so tests running beside each other keep their own.
#[cfg(test)]
pub(crate) mod restart_launch_seam {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use boxes::SessionId;

    static SEEDED: Mutex<Option<HashSet<SessionId>>> = Mutex::new(None);

    /// Makes the next restart launch of `id` fail.
    pub(crate) fn fail_next(id: SessionId) {
        SEEDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(HashSet::new)
            .insert(id);
    }

    /// Whether this restart launch of `id` fails. Takes the seed.
    pub(super) fn fails(id: &SessionId) -> bool {
        SEEDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .is_some_and(|seeded| seeded.remove(id))
    }
}
