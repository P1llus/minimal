//! The VM's uplink: the socket pair behind its network device, and the pump
//! that carries its frames to gvproxy.
//!
//! The VMM child gives one end to libkrun. The supervisor keeps the other
//! and pumps frames between it and gvproxy's `/connect`. libkrun never talks
//! to gvproxy itself, so the device does not depend on gvproxy being up at
//! boot and survives a gvproxy restart.

#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use switch::pump;

/// Names the inherited descriptor of the VM end to the VMM child.
pub(crate) const UPLINK_FD_ENV: &str = "MINVMD_UPLINK_FD";

/// The socket buffer asked for on both ends. The kernel may grant less.
const SOCKET_BUFFER: libc::c_int = 4 * 1024 * 1024;

/// How long the supervisor waits for the pump to see the VM end close.
const JOIN_BOUND: Duration = Duration::from_secs(2);

/// Both ends of the uplink before the VMM child is spawned.
#[derive(Debug)]
pub(crate) struct Prepared {
    vm_end: OwnedFd,
    host_end: UnixStream,
}

/// Creates the socket pair for one boot.
pub(crate) fn prepare() -> io::Result<Prepared> {
    let (vm_end, host_end) = UnixStream::pair()?;
    let size = SOCKET_BUFFER;
    for end in [&vm_end, &host_end] {
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            // SAFETY: the option value is a live `c_int` of the length
            // given. A refusal leaves the default buffer, which works.
            unsafe {
                libc::setsockopt(
                    end.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&raw const size).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }
    Ok(Prepared {
        vm_end: vm_end.into(),
        host_end,
    })
}

impl Prepared {
    /// Arranges for `cmd`'s child, and only that child, to inherit the VM
    /// end, and names it in the child's environment.
    #[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
    pub(crate) fn inherit_into(&self, cmd: &mut std::process::Command) {
        use std::os::unix::process::CommandExt as _;
        let fd = self.vm_end.as_raw_fd();
        cmd.env(UPLINK_FD_ENV, fd.to_string());
        // SAFETY: fcntl in the forked child is async-signal-safe. Clearing
        // FD_CLOEXEC there keeps the descriptor out of every other spawn.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// Starts the pump once the child holds its copy of the VM end. This
    /// closes the supervisor's copy, so the child's exit is the pump's end of
    /// file.
    pub(crate) fn start(self, gvproxy: PathBuf) -> io::Result<Uplink> {
        drop(self.vm_end);
        self.host_end.set_nonblocking(true)?;
        let host_end = self.host_end;
        let stats = Arc::new(pump::Stats::default());
        let pump_stats = Arc::clone(&stats);
        let (ended_tx, ended_rx) = std::sync::mpsc::channel();
        let span = crate::telemetry::vm_task("net.uplink");
        let thread = std::thread::Builder::new()
            .name("minvmd-uplink".into())
            .spawn(move || {
                let _span = span.entered();
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        tracing::error!(%error, "the uplink pump has no runtime; the VM has no network");
                        return;
                    }
                };
                let end = runtime.block_on(async move {
                    let host_end = match tokio::net::UnixStream::from_std(host_end) {
                        Ok(host_end) => host_end,
                        Err(error) => return pump::End::LocalFailed(error),
                    };
                    pump::run(
                        pump::Prefixed(host_end),
                        pump::Config::new(gvproxy),
                        pump_stats,
                    )
                    .await
                });
                let _ = ended_tx.send(end);
            })?;
        Ok(Uplink {
            stats,
            ended: ended_rx,
            thread: Some(thread),
        })
    }
}

/// The running pump of one boot.
#[derive(Debug)]
pub(crate) struct Uplink {
    stats: Arc<pump::Stats>,
    ended: std::sync::mpsc::Receiver<pump::End>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Uplink {
    #[cfg(test)]
    pub(crate) fn stats(&self) -> &pump::Stats {
        &self.stats
    }

    /// Waits for the pump to end after the VM is gone, and logs what it
    /// carried.
    pub(crate) fn finish(mut self) {
        let end = self.ended.recv_timeout(JOIN_BOUND);
        let stats = &self.stats;
        let (to_switch, to_vm, oversized, link_down, redials) = (
            stats.to_switch.load(Ordering::Relaxed),
            stats.to_local.load(Ordering::Relaxed),
            stats.dropped_oversized.load(Ordering::Relaxed),
            stats.dropped_link_down.load(Ordering::Relaxed),
            stats.redials.load(Ordering::Relaxed),
        );
        match end {
            Ok(pump::End::LocalClosed) => {
                tracing::info!(
                    to_switch,
                    to_vm,
                    oversized,
                    link_down,
                    redials,
                    "the VM's uplink ended with the VM"
                );
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
            Ok(pump::End::LocalFailed(error)) => {
                tracing::warn!(%error, to_switch, to_vm, "the VM's uplink failed on the VM side");
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
            // The VM end is still open somewhere. The thread ends with the
            // process.
            Err(_) => tracing::warn!(to_switch, to_vm, "the VM's uplink did not end with the VM"),
        }
    }
}

/// The descriptor the supervisor handed this VMM child, if it handed one.
#[cfg_attr(not(minvmd_libkrun), allow(dead_code))]
pub(crate) fn inherited_fd() -> anyhow::Result<Option<RawFd>> {
    use anyhow::Context as _;
    let Some(value) = std::env::var_os(UPLINK_FD_ENV).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let fd: RawFd = value
        .to_str()
        .and_then(|text| text.parse().ok())
        .with_context(|| format!("{UPLINK_FD_ENV} is not a descriptor number: {value:?}"))?;
    // SAFETY: F_GETFD touches no memory. It fails when `fd` is not open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        anyhow::bail!("{UPLINK_FD_ENV} names descriptor {fd}, which is not open");
    }
    Ok(Some(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    /// The pump thread carries a frame from the VM end to a stand-in gvproxy
    /// and ends when the last copy of the VM end closes.
    #[test]
    fn the_pump_thread_carries_frames_and_ends_with_the_vm_end() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("gv.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let prepared = prepare().unwrap();
        // The child's copy of the VM end.
        let mut vm = UnixStream::from(prepared.vm_end.try_clone().unwrap());
        let uplink = prepared.start(sock).unwrap();

        let (mut gv, _) = listener.accept().unwrap();
        gv.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            gv.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        // The frame is written only once the pump holds its connection.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !uplink.stats().link_up.load(Ordering::Relaxed) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        vm.write_all(&[0, 0, 0, 3, b'a', b'b', b'c']).unwrap();
        let mut frame = [0u8; 5];
        gv.read_exact(&mut frame).unwrap();
        assert_eq!(&frame, &[3, 0, b'a', b'b', b'c']);

        drop(vm);
        uplink.finish();
        let mut rest = Vec::new();
        assert_eq!(gv.read_to_end(&mut rest).unwrap(), 0);
    }

    #[test]
    fn an_unset_descriptor_variable_means_no_uplink() {
        // Other tests in this process do not set the variable.
        assert_eq!(inherited_fd().unwrap(), None);
    }
}
