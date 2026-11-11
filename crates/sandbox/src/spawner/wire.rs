//! What crosses the socket between a process and its spawner.
//!
//! Each message is one frame: a header of two little-endian `u32`s, the
//! body's length and the number of descriptors, then the body as JSON. The
//! descriptors ride on the header as `SCM_RIGHTS`.

use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::path::PathBuf;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::ExitStatus;

/// A mount of the container, as hakoniwa takes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Mount {
    pub(crate) source: String,
    pub(crate) target: String,
    /// Empty for a bind mount.
    pub(crate) fstype: String,
    /// `hakoniwa::MountOptions` bits.
    pub(crate) options: u32,
    pub(crate) data: Option<String>,
}

/// The tap hakoniwa builds inside the container's network namespace.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Tap {
    pub(crate) address: std::net::Ipv4Addr,
    pub(crate) netmask: std::net::Ipv4Addr,
    pub(crate) gateway: std::net::Ipv4Addr,
    pub(crate) mtu: u16,
}

/// A container, as data: what `Sandbox::new_container` decided.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ContainerSpec {
    pub(crate) rootfs: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The mounts beyond `/dev`, `/tmp` and `/proc`, which every container has.
    pub(crate) mounts: Vec<Mount>,
    /// `(original, link)` pairs.
    pub(crate) symlinks: Vec<(String, String)>,
    pub(crate) hostname: Option<String>,
    /// Whether the container gets a network namespace of its own.
    pub(crate) netns: bool,
    pub(crate) tap: Option<Tap>,
    /// Whether mounts fall back to the flags of their source, and `/proc` is
    /// the outer one bound in.
    pub(crate) mount_fallback: bool,
}

/// The session of the container's program.
///
/// The program never shares a process group with the spawner or with the
/// process that asked for it. A box runs with the spawner's uid, so
/// `kill(0, sig)` from a shared group would reach them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum Session {
    /// A new session with no controlling terminal. The supervisor leaves
    /// the spawner's session too.
    New,
    /// A new session whose controlling terminal is the program's stdin. The
    /// supervisor leaves the spawner's session too.
    NewWithTerminal,
    /// The spawner's session, in a process group of its own that is made
    /// the foreground group of the session's terminal, as a shell runs a
    /// job. For a tool that runs one program on its user's terminal.
    Foreground,
}

/// A program to run in a new container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Run {
    pub(crate) container: ContainerSpec,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) cwd: Option<PathBuf>,
    /// The start gate, as the container names it.
    pub(crate) gate: Option<PathBuf>,
    pub(crate) session: Session,
    /// Whether the program's pre-exec step brings `lo` up.
    pub(crate) lo_up: bool,
}

/// A program to run in a running container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Enter {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    /// The program's whole environment.
    pub(crate) env: Vec<(String, String)>,
    pub(crate) cwd: Option<PathBuf>,
}

/// What a process asks of its spawner. `id` names the job in every later
/// message about it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Request {
    /// Descriptors: stdin, stdout, stderr, then the box cgroup if `cgroup`.
    Run { id: u64, run: Run, cgroup: bool },
    /// Descriptors: stdin, stdout, stderr, then the box cgroup if `cgroup`.
    Enter {
        id: u64,
        into: u64,
        enter: Enter,
        cgroup: bool,
    },
    /// Descriptors: the box cgroup if `cgroup`.
    Socket {
        id: u64,
        /// The container whose network namespace the socket is made in.
        netns_of: Option<u64>,
        v6: bool,
        datagram: bool,
        cgroup: bool,
    },
    /// Signals the job's own process, or a container's first process.
    Signal { id: u64, signal: i32, to_init: bool },
    /// The requester dropped the job's handle. The job is killed.
    Forget { id: u64 },
}

/// What a spawner tells the process it serves.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Event {
    /// The job's process exists. Descriptors: the tap if `tap`.
    Started {
        id: u64,
        pid: u32,
        tap: bool,
    },
    Failed {
        id: u64,
        error: String,
    },
    Exited {
        id: u64,
        status: ExitStatus,
    },
    /// Descriptors: the socket.
    Socket {
        id: u64,
    },
}

/// The most descriptors one frame carries.
const MAX_FDS: usize = 8;

/// The largest body a frame may claim, far above any real request.
const MAX_BODY: u32 = 64 << 20;

/// Sends one frame.
pub(crate) fn send(
    sock: &mut std::os::unix::net::UnixStream,
    message: &impl Serialize,
    fds: &[BorrowedFd<'_>],
) -> io::Result<()> {
    assert!(
        fds.len() <= MAX_FDS,
        "a frame carries at most {MAX_FDS} descriptors"
    );
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    header[4..].copy_from_slice(&(fds.len() as u32).to_le_bytes());

    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    // Room for the descriptors, aligned as a control message needs.
    let mut control = [0u64; 8];
    // SAFETY: a zeroed `msghdr` is a valid empty one.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        let bytes = std::mem::size_of_val(fds) as u32;
        // SAFETY: the control buffer is larger than `CMSG_SPACE` of
        // `MAX_FDS` descriptors, and the header and data are written inside it.
        unsafe {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(bytes) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(bytes) as _;
            let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
            for (i, fd) in fds.iter().enumerate() {
                data.add(i).write_unaligned(fd.as_raw_fd());
            }
        }
    }
    loop {
        // SAFETY: `msg` points at buffers that outlive the call.
        let sent = unsafe { libc::sendmsg(sock.as_raw_fd(), &raw const msg, libc::MSG_NOSIGNAL) };
        if sent == header.len() as isize {
            break;
        }
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // A stream socket takes eight bytes whole or blocks.
        return Err(io::Error::other("the frame header was cut short"));
    }
    sock.write_all(&body)
}

/// Receives one frame, or `None` when the peer closed the socket.
pub(crate) fn recv<T: DeserializeOwned>(
    sock: &mut std::os::unix::net::UnixStream,
) -> io::Result<Option<(T, Vec<OwnedFd>)>> {
    let mut header = [0u8; 8];
    let mut filled = 0;
    let mut fds = Vec::new();
    while filled < header.len() {
        let mut iov = libc::iovec {
            iov_base: header[filled..].as_mut_ptr().cast(),
            iov_len: header.len() - filled,
        };
        let mut control = [0u64; 8];
        // SAFETY: a zeroed `msghdr` is a valid empty one.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        // SAFETY: `msg` points at buffers that outlive the call.
        let got = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if got < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if got == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        filled += got as usize;
        // SAFETY: the kernel filled the control buffer, and each message in
        // it is read inside its own stated length.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                    for i in 0..bytes / std::mem::size_of::<libc::c_int>() {
                        fds.push(OwnedFd::from_raw_fd(data.add(i).read_unaligned()));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
            }
        }
    }
    let len = u32::from_le_bytes(header[..4].try_into().expect("four bytes"));
    let count = u32::from_le_bytes(header[4..].try_into().expect("four bytes")) as usize;
    if len > MAX_BODY || count != fds.len() {
        return Err(io::Error::other(format!(
            "a frame of {len} bytes named {count} descriptors and carried {}",
            fds.len()
        )));
    }
    let mut body = vec![0u8; len as usize];
    sock.read_exact(&mut body)?;
    let message = serde_json::from_slice(&body).map_err(io::Error::other)?;
    Ok(Some((message, fds)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn a_frame_carries_its_message_and_its_descriptors() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let big = "x".repeat(300_000);
        let sender = std::thread::spawn(move || {
            send(&mut a, &Event::Failed { id: 7, error: big }, &[]).unwrap();
            send(&mut a, &Event::Socket { id: 8 }, &[reader.as_fd()]).unwrap();
        });
        let (first, fds): (Event, _) = recv(&mut b).unwrap().unwrap();
        assert!(matches!(first, Event::Failed { id: 7, error } if error.len() == 300_000));
        assert!(fds.is_empty());
        let (second, fds): (Event, _) = recv(&mut b).unwrap().unwrap();
        assert!(matches!(second, Event::Socket { id: 8 }));
        assert_eq!(fds.len(), 1);
        // The descriptor that arrived is the pipe's read end.
        writer.write_all(b"through").unwrap();
        drop(writer);
        let mut text = String::new();
        std::fs::File::from(fds.into_iter().next().unwrap())
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "through");
        sender.join().unwrap();
        // The sender is gone: the next read is the end of the stream.
        assert!(recv::<Event>(&mut b).unwrap().is_none());
    }
}
