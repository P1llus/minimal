//! The process backends: how a box's process is waited on, signalled and
//! accounted for when it ends.

use super::*;

/// How a session process ended, as `hakoniwa` accounts for it.
///
/// Kept alongside the portable exit code because the code alone cannot say
/// whether a session *ended* or was *killed*: a clean `exit 0` and a SIGKILL
/// both close every slave fd, both surface on the master as the same `EIO`,
/// and both otherwise raise the same silent shell-exit prompt. This is what
/// separates them, in the log and on the user's terminal.
#[derive(Debug, Clone)]
pub(crate) struct ExitReason {
    /// `hakoniwa`'s portable code: the inner process's own status when it
    /// exited normally, or `125` when the container itself failed or was
    /// signalled.
    pub(crate) code: i32,
    /// `Some(status)` when the inner process exited on its own, `None` when it
    /// was signalled or the container failed out from under it — the
    /// discriminator behind [`Self::is_abnormal`].
    pub(crate) exit_code: Option<i32>,
    /// `hakoniwa`'s human account, e.g. `container received signal SIGKILL` or
    /// `process(/usr/bin/bash) exited with code 0`. Shown to the user verbatim
    /// when the end was abnormal.
    pub(crate) reason: String,
}

impl ExitReason {
    /// Whether the process failed to exit under its own control — signalled,
    /// or the container failed. Exactly `hakoniwa`'s `exit_code: None`, which
    /// it sets both on its `received signal` path and on the `new_failure`
    /// path behind a container-level SIGKILL.
    pub(crate) fn is_abnormal(&self) -> bool {
        self.exit_code.is_none()
    }
}

/// A handle to a launched session process.
///
/// Abstracts the process the [`Host`] supervises so its runtime loop can be
/// driven against a real sandboxed process or a test double. `try_wait` and
/// `wait` reduce the `hakoniwa::ExitStatus` payload to a portable exit code;
/// [`Self::exit_reason`] carries the part of it that has to reach the user.
pub(crate) trait BoxProcess: Send + 'static {
    /// Returns the PID of hakoniwa's container supervisor — **not** the PID of
    /// the shell it exec'd.
    ///
    /// The supervisor unshared the sandbox's namespaces itself, so this is a
    /// valid handle for all of them except the PID namespace, which it created
    /// for its children without entering. Use
    /// [`Host::session_leader_pid`](Host::session_leader_pid) for the shell's
    /// own PID.
    fn container_pid(&self) -> u32;
    /// The way into the box for more programs.
    fn entrance(&self) -> crate::box_command::BoxEntrance;
    /// Returns `Some(code)` if the process has exited, `None` if still running.
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    /// Blocks until the process exits, returning its exit code.
    fn wait(&mut self) -> io::Result<i32>;
    /// Sends a kill signal to the process.
    fn kill(&mut self) -> io::Result<()>;
    /// Sends `signal` to the box's entrypoint, the program the box was
    /// started for.
    fn signal_entrypoint(&self, signal: i32);
    /// `hakoniwa`'s account of how the process ended, available once
    /// [`Self::try_wait`] has returned `Some` or [`Self::wait`] has returned.
    ///
    /// `None` until the reap; [`HostProcess`] caches the reason at that point
    /// and answers from it thereafter.
    fn exit_reason(&self) -> Option<ExitReason>;
}

/// A backend's answer to a reap: the portable code a [`BoxProcess`] reduces
/// the child's status to, plus the account to cache for
/// [`BoxProcess::exit_reason`].
pub(crate) struct ExitReport {
    /// The code `wait`/`try_wait` returns.
    pub(super) code: i32,
    /// The account cached on the first reap.
    pub(super) reason: ExitReason,
}

/// The process-creation backend behind [`HostProcess`]: the one part of a
/// [`BoxProcess`] that differs between the real sandboxed child and the
/// test double. Everything else — the exit-reason cache and its record-once
/// policy — lives in [`HostProcess`] and is shared.
pub(crate) trait ProcessBackend: Send + 'static {
    /// See [`BoxProcess::container_pid`].
    fn container_pid(&self) -> u32;
    /// See [`BoxProcess::entrance`].
    fn entrance(&self) -> crate::box_command::BoxEntrance;
    /// See [`BoxProcess::try_wait`]; `Ok(None)` while the process runs.
    fn try_wait(&mut self) -> io::Result<Option<ExitReport>>;
    /// See [`BoxProcess::wait`].
    fn wait(&mut self) -> io::Result<ExitReport>;
    /// See [`BoxProcess::kill`].
    fn kill(&mut self) -> io::Result<()>;
    /// See [`BoxProcess::signal_entrypoint`].
    fn signal_entrypoint(&self, signal: i32);
    /// Logs the backend's account of an observed exit. Called exactly once per
    /// session by [`HostProcess::record_exit`]; the default is silent, so a
    /// backend with nothing to say (the mock) need not implement it.
    fn log_exit(_reason: &ExitReason) {}
}

/// The single [`BoxProcess`] implementation, generic over the backend that
/// owns the actual child. Holds the exit reason cached at the first reap, so
/// [`BoxProcess::exit_reason`] can answer after the fact for both the real
/// sandboxed child and the test double.
pub(crate) struct HostProcess<B: ProcessBackend> {
    backend: B,
    /// The reason captured at the reap; `None` until then.
    exit: Option<ExitReason>,
}

impl<B: ProcessBackend> HostProcess<B> {
    pub(super) fn new(backend: B) -> Self {
        Self {
            backend,
            exit: None,
        }
    }

    /// Logs the backend's account of an observed exit and caches it for
    /// [`BoxProcess::exit_reason`], returning the portable code.
    ///
    /// Caches and logs on the first reap only, not on every subsequent one: the
    /// child caches its own status, so a `wait` following a `try_wait` that
    /// already saw the death would otherwise log the same end twice.
    fn record_exit(&mut self, report: ExitReport) -> i32 {
        if self.exit.is_none() {
            B::log_exit(&report.reason);
            self.exit = Some(report.reason);
        }
        report.code
    }
}

impl<B: ProcessBackend> BoxProcess for HostProcess<B> {
    fn container_pid(&self) -> u32 {
        self.backend.container_pid()
    }

    fn entrance(&self) -> crate::box_command::BoxEntrance {
        self.backend.entrance()
    }

    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        let report = self.backend.try_wait()?;
        Ok(report.map(|r| self.record_exit(r)))
    }

    fn wait(&mut self) -> io::Result<i32> {
        let report = self.backend.wait()?;
        Ok(self.record_exit(report))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.backend.kill()
    }

    fn signal_entrypoint(&self, signal: i32) {
        self.backend.signal_entrypoint(signal);
    }

    fn exit_reason(&self) -> Option<ExitReason> {
        self.exit.clone()
    }
}

/// The real sandboxed child backend: a container the spawner runs.
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct SandboxBackend {
    pub(super) child: sandbox::Child,
}

#[cfg_attr(test, allow(dead_code))]
impl SandboxBackend {
    /// Reduces the spawner's account of an exit to the shared [`ExitReport`].
    fn report(s: sandbox::ExitStatus) -> ExitReport {
        ExitReport {
            code: s.code,
            reason: ExitReason {
                code: s.code,
                exit_code: s.exit_code,
                reason: s.reason,
            },
        }
    }
}

impl ProcessBackend for SandboxBackend {
    fn container_pid(&self) -> u32 {
        self.child.id()
    }

    fn entrance(&self) -> crate::box_command::BoxEntrance {
        crate::box_command::BoxEntrance::Sandbox(self.child.entrance())
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitReport>> {
        Ok(self.child.try_wait().map(Self::report))
    }

    fn wait(&mut self) -> io::Result<ExitReport> {
        // The blocking wait the pty/step error path takes — in practice the
        // one that fires, since the master's `EIO` beats the loop's `try_wait`
        // poll to every ordinary exit.
        Ok(Self::report(self.child.wait()))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child.kill();
        Ok(())
    }

    fn signal_entrypoint(&self, signal: i32) {
        self.child.signal(signal, sandbox::SignalTarget::Program);
    }

    /// Logs on every exit, not just the non-zero ones, exactly once per session
    /// (gated by [`HostProcess::record_exit`]'s cache): `hakoniwa` caches the
    /// status, so a `wait` following a `try_wait` that already saw it would
    /// otherwise log the same death twice.
    fn log_exit(reason: &ExitReason) {
        if reason.code != 0 {
            tracing::warn!(
                code = reason.code,
                exit_code = ?reason.exit_code,
                reason = %reason.reason,
                "DIAG hakoniwa container/process exited non-zero"
            );
        } else {
            tracing::info!(
                code = reason.code,
                exit_code = ?reason.exit_code,
                reason = %reason.reason,
                "hakoniwa container/process exited"
            );
        }
    }
}

impl Drop for SandboxBackend {
    /// Ends the box if nothing has yet, and waits until it is gone: a host
    /// loop that was aborted never waited for its process. After an exit
    /// both calls return at once.
    fn drop(&mut self) {
        self.child.kill();
        self.child.wait();
    }
}

/// A launched session process backed by a sandboxed [`sandbox::Child`].
#[cfg_attr(test, allow(dead_code))]
pub(crate) type SandboxProcess = HostProcess<SandboxBackend>;
