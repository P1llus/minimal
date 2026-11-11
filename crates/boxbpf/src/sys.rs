//! System calls aya has no wrapper for: legacy cgroup attach and query,
//! cgroup ids, the identity of a socket peer, and descriptor passing.

use std::{
    ffi::CString,
    fs, io,
    mem::size_of,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

const BPF_PROG_ATTACH: libc::c_long = 8;
const BPF_PROG_QUERY: libc::c_long = 16;
pub(crate) const BPF_F_ALLOW_MULTI: u32 = 2;

fn cvt(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn fd_u32(fd: BorrowedFd<'_>) -> io::Result<u32> {
    u32::try_from(fd.as_raw_fd()).map_err(|_e| io::Error::from(io::ErrorKind::InvalidInput))
}

/// The fields `BPF_PROG_ATTACH` reads from `union bpf_attr`.
#[repr(C)]
#[derive(Default)]
struct AttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
    relative_fd: u32,
    expected_revision: u64,
}

/// `BPF_PROG_ATTACH` with `BPF_F_ALLOW_MULTI`.
///
/// The attachment belongs to the cgroup, not to a descriptor: it stays when
/// this process exits and the kernel frees it with the cgroup. A multi
/// attachment can only be detached by someone who holds the program.
pub(crate) fn prog_attach(
    prog: BorrowedFd<'_>,
    cgroup: BorrowedFd<'_>,
    attach_type: u32,
) -> io::Result<()> {
    let mut attr = AttachAttr {
        target_fd: fd_u32(cgroup)?,
        attach_bpf_fd: fd_u32(prog)?,
        attach_type,
        attach_flags: BPF_F_ALLOW_MULTI,
        ..AttachAttr::default()
    };
    // SAFETY: attr is a valid prefix of bpf_attr of the size passed.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &raw mut attr,
            size_of::<AttachAttr>(),
        )
    };
    cvt(ret).map(drop)
}

/// The fields `BPF_PROG_QUERY` reads and writes.
#[repr(C)]
#[derive(Default)]
struct QueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    _pad: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

/// Ids of the programs attached directly to `cgroup` for one attach type.
pub(crate) fn prog_query(cgroup: BorrowedFd<'_>, attach_type: u32) -> io::Result<Vec<u32>> {
    let mut ids = [0u32; 64];
    let mut attr = QueryAttr {
        target_fd: fd_u32(cgroup)?,
        attach_type,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: 64,
        ..QueryAttr::default()
    };
    // SAFETY: attr is a valid prefix of bpf_attr, and prog_ids points at
    // prog_cnt writable ids.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_QUERY,
            &raw mut attr,
            size_of::<QueryAttr>(),
        )
    };
    cvt(ret)?;
    let n = usize::try_from(attr.prog_cnt).unwrap_or(usize::MAX);
    Ok(ids.into_iter().take(n).collect())
}

#[repr(C)]
struct FileHandle {
    bytes: u32,
    kind: i32,
    id: u64,
}

/// The cgroup id of an open cgroup directory: the value the programs use
/// as box id. It is the same in every cgroup namespace.
pub fn cgroup_id(dir: BorrowedFd<'_>) -> io::Result<u64> {
    let mut handle = FileHandle {
        bytes: 8,
        kind: 0,
        id: 0,
    };
    let mut mount_id = 0i32;
    // SAFETY: handle has room for the 8 bytes it announces, and the path is
    // an empty C string that AT_EMPTY_PATH makes refer to `dir` itself.
    let ret = unsafe {
        libc::name_to_handle_at(
            dir.as_raw_fd(),
            c"".as_ptr(),
            (&raw mut handle).cast(),
            &raw mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    cvt(libc::c_long::from(ret))?;
    Ok(handle.id)
}

pub(crate) fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: c is a valid C string.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    cvt(libc::c_long::from(fd))?;
    // SAFETY: open just returned this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens a cgroup directory by id. Needs `CAP_DAC_READ_SEARCH`.
pub(crate) fn open_cgroup_by_id(cgroup_mount: BorrowedFd<'_>, id: u64) -> io::Result<OwnedFd> {
    const FILEID_KERNFS: i32 = 0xfe;
    let mut handle = FileHandle {
        bytes: 8,
        kind: FILEID_KERNFS,
        id,
    };
    // SAFETY: handle is a complete file_handle of the kernfs kind.
    let fd = unsafe {
        libc::open_by_handle_at(
            cgroup_mount.as_raw_fd(),
            (&raw mut handle).cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    cvt(libc::c_long::from(fd))?;
    // SAFETY: open_by_handle_at just returned this descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(crate) fn fd_path(fd: BorrowedFd<'_>) -> io::Result<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

pub(crate) fn is_cgroup2(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let stat = nix::sys::statfs::fstatfs(fd)?;
    Ok(stat.filesystem_type() == nix::sys::statfs::CGROUP2_SUPER_MAGIC)
}

/// The peer of a unix socket as a pidfd. Linux 6.5.
pub(crate) fn peer_pidfd(sock: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut fd: libc::c_int = -1;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or(4);
    // SAFETY: fd and len describe one writable int.
    let ret = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&raw mut fd).cast(),
            &raw mut len,
        )
    };
    cvt(libc::c_long::from(ret))?;
    // SAFETY: the kernel installed a new descriptor for us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The cgroup id of the process behind a pidfd. Linux 6.13.
pub(crate) fn pidfd_cgroup_id(pidfd: BorrowedFd<'_>) -> io::Result<u64> {
    const PIDFD_INFO_CGROUPID: u64 = 1 << 2;
    /// The first, 64-byte version of `struct pidfd_info`.
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        mask: u64,
        cgroupid: u64,
        ids: [u32; 11],
        exit_code: i32,
    }
    // _IOWR(0xFF, 11, struct pidfd_info) for that size. The request type is
    // c_ulong on glibc and c_int on musl: the number is a bit pattern.
    const PIDFD_GET_INFO: libc::Ioctl = 0xC040_FF0B_u32 as libc::Ioctl;

    let mut info = Info {
        mask: PIDFD_INFO_CGROUPID,
        ..Info::default()
    };
    // SAFETY: info has the size the request number encodes.
    let ret = unsafe { libc::ioctl(pidfd.as_raw_fd(), PIDFD_GET_INFO, &raw mut info) };
    cvt(libc::c_long::from(ret))?;
    if info.mask & PIDFD_INFO_CGROUPID == 0 {
        return Err(io::Error::other("the kernel did not report a cgroup id"));
    }
    Ok(info.cgroupid)
}

/// True while the process behind the pidfd exists.
pub(crate) fn pidfd_alive(pidfd: BorrowedFd<'_>) -> bool {
    // SAFETY: a plain system call with a valid descriptor and signal 0.
    let ret =
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(), 0, 0usize, 0) };
    ret == 0
}

/// The boot-time clock in nanoseconds: what the programs stamp events with
/// and compare pin expiry against.
#[must_use]
pub fn boot_time_ns() -> u64 {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
        .unwrap_or(nix::sys::time::TimeSpec::new(0, 0));
    let secs = u64::try_from(ts.tv_sec()).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec()).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

pub(crate) fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let iov = [io::IoSlice::new(data)];
    let rights = [ControlMessage::ScmRights(fds)];
    let cmsgs: &[ControlMessage<'_>] = if fds.is_empty() { &[] } else { &rights };
    sendmsg::<()>(sock, &iov, cmsgs, MsgFlags::MSG_NOSIGNAL, None)?;
    Ok(())
}

/// One message and the descriptors that came with it.
pub(crate) fn recv_with_fds(sock: RawFd) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 4096];
    let mut space = nix::cmsg_space!([RawFd; 32]);
    let (n, fds) = {
        let mut iov = [io::IoSliceMut::new(&mut buf)];
        let msg = recvmsg::<()>(sock, &mut iov, Some(&mut space), MsgFlags::MSG_CMSG_CLOEXEC)?;
        let mut fds = Vec::new();
        for cmsg in msg.cmsgs()? {
            if let ControlMessageOwned::ScmRights(received) = cmsg {
                for fd in received {
                    // SAFETY: the kernel just installed this descriptor for
                    // us and nothing else owns it.
                    fds.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }
        (msg.bytes, fds)
    };
    buf.truncate(n);
    Ok((buf, fds))
}
