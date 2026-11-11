//! A program the daemon starts for a box, in the shape its async code uses.
//!
//! A program that enters a running box is started by the spawner, which is
//! its parent. A program that serves a box from outside it, like the `git`
//! behind a push, is a child of the daemon. Both are started, fed and waited
//! for the same way, so the exec machinery handles one type.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt as _;

pub(crate) use sandbox::Stdio;
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

/// The way into a running box for more programs.
#[derive(Debug, Clone)]
pub(crate) enum BoxEntrance {
    /// A sandboxed box, entered through its spawner.
    #[cfg_attr(test, allow(dead_code))]
    Sandbox(sandbox::Entrance),
    /// A box that is a plain process of this host, as the test launcher's
    /// is. A program enters it by running beside it.
    #[cfg(test)]
    Host,
}

impl BoxEntrance {
    /// A command that runs `program` in the box, with `vars` as its whole
    /// environment, started in `cwd` as the box names it.
    pub(crate) fn command<I, S>(
        &self,
        program: &str,
        args: I,
        vars: BTreeMap<String, String>,
        cwd: &str,
    ) -> BoxCommand
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        match self {
            Self::Sandbox(entrance) => {
                let mut command = entrance.command(program, args);
                command.envs(vars);
                if !cwd.is_empty() {
                    command.current_dir(cwd);
                }
                BoxCommand(Kind::Entered(command))
            }
            #[cfg(test)]
            Self::Host => {
                let mut command = std::process::Command::new(program);
                command.args(args.into_iter().map(|arg| arg.as_ref().to_string()));
                command.env_clear();
                command.envs(vars);
                // A path of the box names nothing on this host, so only a
                // directory that exists here is used.
                if !cwd.is_empty() && std::path::Path::new(cwd).is_dir() {
                    command.current_dir(cwd);
                }
                BoxCommand(Kind::Host(command))
            }
        }
    }
}

enum Kind {
    Entered(sandbox::Command),
    Host(std::process::Command),
}

/// A program to start for a box.
pub(crate) struct BoxCommand(Kind);

impl std::fmt::Debug for BoxCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Kind::Entered(command) => command.fmt(f),
            Kind::Host(command) => command.fmt(f),
        }
    }
}

impl From<std::process::Command> for BoxCommand {
    /// A program that runs on the daemon's host, as a child of the daemon.
    fn from(command: std::process::Command) -> Self {
        Self(Kind::Host(command))
    }
}

fn host_stdio(stdio: Stdio) -> std::process::Stdio {
    match stdio {
        Stdio::Inherit => std::process::Stdio::inherit(),
        Stdio::MakePipe => std::process::Stdio::piped(),
        Stdio::Null => std::process::Stdio::null(),
        Stdio::Fd(fd) => std::process::Stdio::from(fd),
    }
}

impl BoxCommand {
    pub(crate) fn stdin(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        match &mut self.0 {
            Kind::Entered(command) => drop(command.stdin(stdio)),
            Kind::Host(command) => drop(command.stdin(host_stdio(stdio.into()))),
        }
        self
    }

    pub(crate) fn stdout(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        match &mut self.0 {
            Kind::Entered(command) => drop(command.stdout(stdio)),
            Kind::Host(command) => drop(command.stdout(host_stdio(stdio.into()))),
        }
        self
    }

    pub(crate) fn stderr(&mut self, stdio: impl Into<Stdio>) -> &mut Self {
        match &mut self.0 {
            Kind::Entered(command) => drop(command.stderr(stdio)),
            Kind::Host(command) => drop(command.stderr(host_stdio(stdio.into()))),
        }
        self
    }

    /// Runs the program to its end with its output captured.
    #[cfg(test)]
    pub(crate) fn output(self) -> io::Result<std::process::Output> {
        match self.0 {
            Kind::Entered(mut command) => {
                let output = command.output()?;
                Ok(std::process::Output {
                    status: entered_status(&output.status),
                    stdout: output.stdout,
                    stderr: output.stderr,
                })
            }
            Kind::Host(mut command) => command.output(),
        }
    }

    /// Starts the program. Dropping the returned child kills it.
    ///
    /// The descriptors given as the program's standard streams are closed
    /// here once the program has them.
    pub(crate) fn spawn(self) -> io::Result<BoxChild> {
        match self.0 {
            Kind::Entered(mut command) => {
                let mut child = command.spawn()?;
                let stdin = child.stdin.take().map(OwnedFd::from);
                let stdout = child.stdout.take().map(OwnedFd::from);
                let stderr = child.stderr.take().map(OwnedFd::from);
                Ok(BoxChild {
                    stdin: stdin
                        .map(|fd| ChildStdin::from_std(fd.into()))
                        .transpose()?,
                    stdout: stdout
                        .map(|fd| ChildStdout::from_std(fd.into()))
                        .transpose()?,
                    stderr: stderr
                        .map(|fd| ChildStderr::from_std(fd.into()))
                        .transpose()?,
                    process: Process::Entered(child),
                })
            }
            Kind::Host(command) => {
                let mut command = tokio::process::Command::from(command);
                command.kill_on_drop(true);
                Ok(command.spawn()?.into())
            }
        }
    }
}

enum Process {
    Entered(sandbox::Child),
    Host(tokio::process::Child),
}

/// A started program. Dropping it kills the program.
pub(crate) struct BoxChild {
    pub(crate) stdin: Option<ChildStdin>,
    pub(crate) stdout: Option<ChildStdout>,
    pub(crate) stderr: Option<ChildStderr>,
    process: Process,
}

impl std::fmt::Debug for BoxChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.process {
            Process::Entered(child) => child.fmt(f),
            Process::Host(child) => child.fmt(f),
        }
    }
}

impl From<tokio::process::Child> for BoxChild {
    fn from(mut child: tokio::process::Child) -> Self {
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            process: Process::Host(child),
        }
    }
}

/// A spawner's account of an entered program's end, as the status a child
/// of the daemon would have had.
fn entered_status(status: &sandbox::ExitStatus) -> std::process::ExitStatus {
    let raw = match status.exit_code {
        Some(code) => (code & 0xff) << 8,
        // A signal's number, which is also what ended a program whose
        // spawner is gone.
        None if status.code > 128 => status.code - 128,
        None => libc::SIGKILL,
    };
    std::process::ExitStatus::from_raw(raw)
}

impl BoxChild {
    /// Closes the program's standard input and waits for it to end.
    pub(crate) async fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        drop(self.stdin.take());
        match &mut self.process {
            Process::Entered(child) => Ok(entered_status(&child.exited().await)),
            Process::Host(child) => child.wait().await,
        }
    }

    /// Kills the program.
    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        match &mut self.process {
            Process::Entered(child) => {
                child.kill();
                Ok(())
            }
            Process::Host(child) => child.start_kill(),
        }
    }

    /// Asks the program to end, with SIGTERM. An entered program's shim
    /// passes that on to the program's whole process group.
    pub(crate) fn start_terminate(&mut self) -> io::Result<()> {
        match &mut self.process {
            Process::Entered(child) => {
                child.signal(libc::SIGTERM, sandbox::SignalTarget::Job);
                Ok(())
            }
            Process::Host(child) => {
                // `None` once the child is reaped, when nothing is left to
                // signal.
                let Some(pid) = child.id() else {
                    return Ok(());
                };
                // SAFETY: `kill` with the pid of a child this handle has not
                // reaped, so the pid is the child's.
                if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == -1 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error);
                    }
                }
                Ok(())
            }
        }
    }
}
