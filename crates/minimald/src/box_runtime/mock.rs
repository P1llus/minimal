//! Test doubles for the process backend and the launcher.

use super::*;

/// The test backend: a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) struct MockBackend {
    pub(super) child: std::process::Child,
}

#[cfg(test)]
impl MockBackend {
    /// The stand-in process, for a test that signals it.
    pub(super) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Translates a plain process status into the shape `hakoniwa` reports, so
    /// the host cannot tell a mock reap from a sandboxed one: a signalled
    /// process has no exit code of its own and carries the container's 125.
    ///
    /// The report's `code` is unchanged from what this mock always returned, so
    /// the reap value every existing test asserts on is untouched.
    fn report(s: std::process::ExitStatus) -> ExitReport {
        use std::os::unix::process::ExitStatusExt;
        let code = s.code().unwrap_or(-1);
        let reason = match s.signal() {
            Some(sig) => ExitReason {
                code: 125,
                exit_code: None,
                reason: format!("process(mock) received signal {sig}"),
            },
            None => ExitReason {
                code,
                exit_code: Some(code),
                reason: format!("process(mock) exited with code {code}"),
            },
        };
        ExitReport { code, reason }
    }
}

#[cfg(test)]
impl ProcessBackend for MockBackend {
    fn has_init(&self) -> bool {
        sandbox::spawner::enter::init_of(self.child.id()).is_ok()
    }

    fn entrance(&self) -> crate::box_command::BoxEntrance {
        crate::box_command::BoxEntrance::Host
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitReport>> {
        let status = self.child.try_wait()?;
        Ok(status.map(Self::report))
    }

    fn wait(&mut self) -> io::Result<ExitReport> {
        let s = self.child.wait()?;
        Ok(Self::report(s))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    fn signal_entrypoint(&self, signal: i32) {
        // The entrypoint leads a process group of its own, which stands in
        // for the PID namespace a real entrypoint is the init of: what the
        // entrypoint started is reached with it.
        // SAFETY: `kill` of the group of the child this backend holds
        // unreaped.
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), signal) };
    }
}

/// A launched session process backed by a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) type MockProcess = HostProcess<MockBackend>;

/// The sentinel stdin line that makes [`MockLauncher`]'s program exit; any
/// other line is echoed back. Lets a test observe an echo round trip while the
/// process is still alive, then trigger teardown deterministically.
#[cfg(test)]
pub(crate) const MOCK_EXIT_LINE: &str = "quit";

/// A test [`BoxLauncher`] that wires a plain, un-sandboxed host process to a
/// freshly opened PTY — so the [`Host`] runtime can be exercised end-to-end
/// without building a real sandbox (which needs packages unavailable in the
/// unit-test environment).
///
/// The launched program echoes each line of stdin back prefixed with `got:`,
/// and exits only on the [`MOCK_EXIT_LINE`] sentinel — so a test can confirm
/// stdin delivery and stdout forwarding before deterministically triggering
/// process-exit teardown.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockLauncher {
    /// Attached to the launched process as `Launched::net_guard`, so a test can
    /// observe network teardown; `None` for the plain mock (mirroring
    /// `HostNet`/`NoNet`).
    net_guard: Option<Box<dyn sandbox::NetGuard>>,
    /// The listen plan this mock launch carries in its [`Launched`], so a
    /// test can drive the host's listener watcher over the mock box the way
    /// a real launch drives one over a sandboxed box — and, left `None`,
    /// prove a launch that carries no plan starts no watcher at all.
    listen_plan: Option<crate::net::listeners::ListenPlan>,
    /// The spec the box's actor handed this launch. Its entrypoint decides
    /// what the mock starts, through [`LaunchSpec::entrypoint`], as it
    /// decides what the real launcher starts.
    spec: LaunchSpec,
    /// A task run's variables for the argv entrypoint alone
    /// ([`super::AttachEnv::entrypoint`]), set on its process as the real
    /// launcher sets them.
    entrypoint_env: Vec<(String, String)>,
}

#[cfg(test)]
impl MockLauncher {
    /// A mock that attaches `net_guard`, for the network-teardown tests.
    pub(crate) fn with_net_guard(net_guard: Box<dyn sandbox::NetGuard>) -> Self {
        Self {
            net_guard: Some(net_guard),
            ..Default::default()
        }
    }

    /// This mock with `listen_plan` attached, so a test can drive a box's
    /// listener watcher under whatever else its launch mirrors.
    pub(crate) fn and_listen_plan(
        mut self,
        listen_plan: crate::net::listeners::ListenPlan,
    ) -> Self {
        self.listen_plan = Some(listen_plan);
        self
    }

    /// This mock with `spec` handed over, as the box's actor hands the
    /// spec to every launcher it builds.
    pub(crate) fn and_spec(mut self, spec: LaunchSpec) -> Self {
        self.spec = spec;
        self
    }

    /// This mock with a task run's entrypoint variables, as the box's
    /// actor hands them to the launch that starts the entrypoint. The
    /// start directory among them is left out: the mock runs host-side.
    pub(crate) fn and_entrypoint_env(mut self, mut vars: Vec<(String, String)>) -> Self {
        vars.retain(|(key, _)| key != super::START_DIR_KEY);
        self.entrypoint_env = vars;
        self
    }
}

#[cfg(test)]
impl BoxLauncher for MockLauncher {
    type Process = MockProcess;
    type Guard = ();

    fn entrypoint(&self) -> io::Result<LaunchEntrypoint> {
        self.spec.entrypoint()
    }

    async fn launch(
        self,
        _session_id: boxes::SessionId,
        _name: String,
        _username: String,
        _paths: BoxPaths,
        sz: WinSize,
    ) -> io::Result<Launched<MockProcess, ()>> {
        let entrypoint = self.entrypoint()?;
        let pty = Pty::open(sz)?;

        // The child is not a job-control one, because the mock's shell is
        // not interactive, so it reads no tty and touches no foreground
        // rights.
        let script = format!(
            r#"while read line; do [ "$line" = {MOCK_EXIT_LINE} ] && exit 0; printf 'got:%s\n' "$line"; done"#
        );
        // The shell entrypoint is the echo loop every runtime test drives.
        // An argv entrypoint runs as the spec names it, host-side.
        let mut command = match &entrypoint {
            LaunchEntrypoint::Shell => {
                let mut command = std::process::Command::new("/bin/sh");
                command.arg("-c").arg(&script);
                command
            }
            LaunchEntrypoint::Argv { program, args } => {
                let mut command = std::process::Command::new(program);
                command.args(args);
                command.envs(self.entrypoint_env.iter().cloned());
                command
            }
        };
        // A box without a terminal runs its argv on three pipes, as the
        // real launcher runs it.
        let (master, tty_path, pipes) = if self.spec.runs_on_pipes(&entrypoint) {
            let child = ChildPipes::open()?;
            command.stdin(std::process::Stdio::from(child.stdin));
            command.stdout(std::process::Stdio::from(child.stdout));
            command.stderr(std::process::Stdio::from(child.stderr));
            drop(pty);
            (
                child.stdout_reader,
                std::path::PathBuf::from("/dev/null"),
                Some(child.parent),
            )
        } else {
            command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
            command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
            let tty_path = pty.slave_path().to_path_buf();
            let (master, slave) = pty.into_fds();
            command.stderr(std::process::Stdio::from(slave));
            (master, tty_path, None)
        };

        // See `MockBackend::signal_entrypoint`.
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let process = command.spawn()?;
        // The child holds its own ends now. The daemon's copies close here,
        // so the child's exit closes its pipes.
        drop(command);

        Ok(Launched {
            master,
            process: MockProcess::new(MockBackend { child: process }),
            guard: (),
            net_guard: self.net_guard,
            tty_path,
            // The plan the launch gathered, riding to the host the way a
            // real launch's plan rides: taken when the host builds.
            listen_plan: self.listen_plan,
            // The mock's process is a plain host child with no pre-exec
            // closure to hold it.
            start_gate: None,
            pipes,
        })
    }
}
