//! One cgroup per box.
//!
//! The daemon owns a cgroup, the root, with two children:
//!
//! ```text
//! <root>/
//!   supervisor/     the daemon and its helpers
//!   boxes/
//!     <box-id>/     every process that runs in or for that box
//! ```
//!
//! A box cgroup is created before anything is started for the box and holds
//! no cgroup below it, so the box is exactly this one cgroup and its kernel
//! id names the box. The layout is the same on a native host and in a VM
//! guest. Only the root differs: a delegated systemd unit on a native host,
//! the real cgroup root in a guest.

use std::fs;
use std::io;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Where cgroup v2 is mounted.
pub const MOUNT: &str = "/sys/fs/cgroup";

/// The child of the root that holds the daemon and its helpers.
pub const SUPERVISOR: &str = "supervisor";

/// The child of the root that holds one cgroup per box.
pub const BOXES: &str = "boxes";

/// Where this process can keep its box cgroups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    /// The real cgroup root, which a VM guest's daemon owns.
    Guest(PathBuf),
    /// The cgroup of the systemd unit this process runs in, which the unit
    /// delegates to it.
    DelegatedUnit(PathBuf),
    /// No cgroup this process may manage.
    None {
        /// What was found instead.
        why: String,
    },
}

/// The controllers enabled for box cgroups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Controllers {
    /// `cpu`, for `cpu.weight`.
    pub cpu: bool,
    /// `memory`, for `memory.max`.
    pub memory: bool,
    /// `pids`, for `pids.max`.
    pub pids: bool,
}

/// Why a limit was not set.
#[derive(Debug, thiserror::Error)]
pub enum LimitError {
    /// The box has no cgroup, because the daemon has no cgroup root.
    #[error("this box has no cgroup to carry a limit: the daemon runs outside a delegated cgroup")]
    NoCgroup,
    /// The controller the limit needs is not delegated to the daemon.
    #[error("the `{0}` cgroup controller is not delegated to the daemon on this host")]
    ControllerNotDelegated(&'static str),
    /// Writing the limit failed.
    #[error("writing the limit failed: {0}")]
    Io(#[from] io::Error),
}

/// A `cpu.weight` value: 1 to 10000, where 100 is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuWeight(u64);

impl CpuWeight {
    /// `weight` as a CPU weight, or `None` outside 1 to 10000.
    #[must_use]
    pub fn new(weight: u64) -> Option<Self> {
        (1..=10_000).contains(&weight).then_some(Self(weight))
    }

    /// `weight` moved into the valid range.
    #[must_use]
    pub fn clamped(weight: u64) -> Self {
        Self(weight.clamp(1, 10_000))
    }
}

/// This process's cgroup, as `/proc/self/cgroup` names it: a path below the
/// cgroup mount, `/` for the root.
///
/// # Errors
///
/// When `/proc/self/cgroup` cannot be read or holds no cgroup v2 line.
pub fn own_cgroup() -> io::Result<String> {
    cgroup_of("self")
}

fn cgroup_of(pid: &str) -> io::Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("no cgroup v2 entry"))
}

/// The systemd unit a cgroup path ends in, the root that unit's delegation
/// gives, and whether the user manager owns it. A process that systemd
/// started in the `supervisor` sub-cgroup of its unit reads the unit one
/// level up. `None` when the path names no unit.
fn unit_of(cgroup: &str) -> Option<(&str, &str, bool)> {
    let path = cgroup.strip_suffix('/').unwrap_or(cgroup);
    let root = path
        .strip_suffix(SUPERVISOR)
        .and_then(|parent| parent.strip_suffix('/'))
        .unwrap_or(path);
    let unit = root.rsplit('/').next()?;
    if !(unit.ends_with(".service") || unit.ends_with(".scope")) {
        return None;
    }
    let user = root
        .split('/')
        .any(|part| part.starts_with("user@") && part.ends_with(".service"));
    Some((unit, root, user))
}

/// Whether systemd delegates `unit`'s cgroup to the unit's own processes.
fn unit_delegates(unit: &str, user: bool) -> io::Result<bool> {
    let mut systemctl = std::process::Command::new("systemctl");
    if user {
        systemctl.arg("--user");
    }
    let shown = systemctl
        .args(["show", "--property=Delegate", "--value", "--"])
        .arg(unit)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()?;
    Ok(shown.status.success() && String::from_utf8_lossy(&shown.stdout).trim() == "yes")
}

/// Finds the cgroup a native daemon may manage: the cgroup of the systemd
/// unit it runs in, when that unit has `Delegate=yes`.
#[must_use]
pub fn locate() -> Located {
    let own = match own_cgroup() {
        Ok(own) => own,
        Err(error) => {
            return Located::None {
                why: format!("this process's cgroup cannot be read: {error}"),
            };
        }
    };
    let Some((unit, root, user)) = unit_of(&own) else {
        return Located::None {
            why: format!("this process's cgroup `{own}` is not a systemd unit's"),
        };
    };
    match unit_delegates(unit, user) {
        Ok(true) => Located::DelegatedUnit(PathBuf::from(format!("{MOUNT}{root}"))),
        Ok(false) => Located::None {
            why: format!("the systemd unit `{unit}` does not delegate its cgroup (Delegate=yes)"),
        },
        Err(error) => Located::None {
            why: format!("asking systemd about the unit `{unit}` failed: {error}"),
        },
    }
}

/// `systemctl` for the manager that runs this process's scopes: the user
/// manager, or the system manager for root.
fn systemctl() -> std::process::Command {
    let mut systemctl = std::process::Command::new("systemctl");
    // SAFETY: `geteuid` reads this process's credentials.
    if unsafe { libc::geteuid() } != 0 {
        systemctl.arg("--user");
    }
    systemctl
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    systemctl
}

/// A name for a transient scope, so a later start can find the scope an
/// earlier one ran in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeUnit {
    /// The unit name, ending in `.scope`.
    pub name: String,
    /// What `systemctl status` shows beside the name.
    pub description: String,
}

impl ScopeUnit {
    /// Whether the manager knows a unit of this name.
    #[must_use]
    pub fn exists(&self) -> bool {
        systemctl()
            .args(["show", "--property=LoadState", "--value", "--"])
            .arg(&self.name)
            .output()
            .is_ok_and(|shown| String::from_utf8_lossy(&shown.stdout).trim() == "loaded")
    }

    /// Stops the scope: kills every process in it and waits until the
    /// manager has let go of the unit.
    ///
    /// # Errors
    ///
    /// When `systemctl` cannot be run or the unit is still there afterwards.
    pub fn stop(&self) -> io::Result<()> {
        // The kill first: a plain stop waits out the unit's stop timeout
        // for a process that ignores the termination signal.
        for verb in [
            &["kill", "--signal=SIGKILL", "--"][..],
            &["stop", "--"],
            &["reset-failed", "--"],
        ] {
            systemctl()
                .args(verb)
                .arg(&self.name)
                .stdout(std::process::Stdio::null())
                .status()?;
        }
        if self.exists() {
            return Err(io::Error::other(format!(
                "the unit {} is still there after its stop",
                self.name
            )));
        }
        Ok(())
    }
}

/// The command that runs `program` with `args` in a new transient scope
/// with a delegated cgroup: a scope of the user manager, or of the system
/// manager for root. `systemd-run --scope` execs the program in place, so
/// the process keeps its pid. With `unit` the scope gets that name, which
/// must not be in use.
#[must_use]
pub fn delegated_scope_command(
    unit: Option<&ScopeUnit>,
    program: &Path,
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> std::process::Command {
    let mut run = std::process::Command::new("systemd-run");
    // SAFETY: `geteuid` reads this process's credentials.
    if unsafe { libc::geteuid() } != 0 {
        run.arg("--user");
    }
    run.args(["--scope", "--quiet", "--collect", "--property=Delegate=yes"]);
    if let Some(unit) = unit {
        run.arg(format!("--unit={}", unit.name));
        run.arg(format!("--description={}", unit.description));
    }
    run.arg("--").arg(program).args(args);
    run
}

/// Whether [`delegated_scope_command`] works on this host, found by running
/// `true` through it. A process asks before it replaces itself with the
/// command, because a host with no service manager to ask would leave it
/// with nothing running.
#[must_use]
pub fn delegated_scope_available() -> bool {
    delegated_scope_command(None, Path::new("true"), [])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The daemon's cgroup root, with its `supervisor` and `boxes` children.
#[derive(Debug, Clone)]
pub struct Root {
    dir: PathBuf,
    /// The `boxes` cgroup, open: what box cgroups are made in and removed
    /// from.
    boxes: Arc<OwnedFd>,
    /// The root as `/proc/<pid>/cgroup` spells it, with no trailing slash:
    /// empty for the real cgroup root.
    name: String,
    controllers: Controllers,
}

impl Root {
    /// Takes `dir` as the root: creates `supervisor` and `boxes`, moves this
    /// process into `supervisor` unless it is there already, and enables the
    /// `cpu`, `memory` and `pids` controllers for box cgroups where the root
    /// has them.
    ///
    /// # Errors
    ///
    /// When `dir` is not a cgroup this process may manage, or its mount
    /// lacks `nsdelegate`. Nothing is left half-made that a later call
    /// cannot finish.
    pub fn open(dir: &Path) -> io::Result<Self> {
        mount_delegates(dir)?;
        let name = dir
            .strip_prefix(MOUNT)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not below {MOUNT}", dir.display()),
                )
            })?
            .to_str()
            .map(|rel| {
                if rel.is_empty() {
                    String::new()
                } else {
                    format!("/{rel}")
                }
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "cgroup path is not UTF-8")
            })?;
        let supervisor = dir.join(SUPERVISOR);
        let boxes = dir.join(BOXES);
        for child in [&supervisor, &boxes] {
            match fs::create_dir(child) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(named(e, "creating", child)),
            }
        }
        let own = own_cgroup()?;
        if own != format!("{name}/{SUPERVISOR}") {
            let procs = supervisor.join("cgroup.procs");
            fs::write(&procs, std::process::id().to_string())
                .map_err(|e| named(e, "moving the daemon into", &supervisor))?;
        }
        // A controller reaches a box cgroup only when every level above it
        // passes it down. The root must hold no process for this, which is
        // why the daemon moved first. The real cgroup root is exempt.
        let available = fs::read_to_string(dir.join("cgroup.controllers"))
            .map_err(|e| named(e, "reading the controllers of", dir))?;
        let wanted: Vec<&str> = ["cpu", "memory", "pids"]
            .into_iter()
            .filter(|controller| available.split_whitespace().any(|have| have == *controller))
            .collect();
        if !wanted.is_empty() {
            let enable = wanted
                .iter()
                .map(|controller| format!("+{controller}"))
                .collect::<Vec<_>>()
                .join(" ");
            for level in [dir, boxes.as_path()] {
                fs::write(level.join("cgroup.subtree_control"), &enable)
                    .map_err(|e| named(e, "enabling controllers on", level))?;
            }
        }
        let enabled = fs::read_to_string(boxes.join("cgroup.subtree_control"))
            .map_err(|e| named(e, "reading the controllers of", &boxes))?;
        let has = |controller: &str| enabled.split_whitespace().any(|have| have == controller);
        let boxes_fd: OwnedFd = fs::File::open(&boxes)
            .map_err(|e| named(e, "opening", &boxes))?
            .into();
        Ok(Self {
            dir: dir.to_path_buf(),
            boxes: Arc::new(boxes_fd),
            name,
            controllers: Controllers {
                cpu: has("cpu"),
                memory: has("memory"),
                pids: has("pids"),
            },
        })
    }

    /// The root's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The `supervisor` cgroup as `/proc/<pid>/cgroup` spells it.
    #[must_use]
    pub fn supervisor_name(&self) -> String {
        format!("{}/{SUPERVISOR}", self.name)
    }

    /// The controllers a box cgroup has.
    #[must_use]
    pub fn controllers(&self) -> Controllers {
        self.controllers
    }

    fn boxes(&self) -> PathBuf {
        self.dir.join(BOXES)
    }

    /// Ends and removes every box cgroup an earlier daemon left behind, and
    /// returns their names. Each gets up to `limit` to empty after the kill.
    ///
    /// # Errors
    ///
    /// When `boxes` cannot be listed. A cgroup that cannot be removed is
    /// logged and left.
    pub fn sweep(&self, limit: Duration) -> io::Result<Vec<String>> {
        let mut swept = Vec::new();
        for entry in fs::read_dir(self.boxes())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let removed = open_dir_in(self.boxes.as_fd(), &name).and_then(|dir| {
                kill(dir.as_fd())?;
                emptied_blocking(dir.as_fd(), limit)?;
                remove(self.boxes.as_fd(), &name, cgroup_id(&dir)?)
            });
            match removed {
                Ok(()) => swept.push(name),
                Err(error) => tracing::warn!(
                    cgroup = %entry.path().display(),
                    %error,
                    "could not remove a box cgroup an earlier daemon left behind"
                ),
            }
        }
        Ok(swept)
    }

    /// Kills every process in every box cgroup, and removes nothing. For a
    /// daemon whose spawner died: what the spawner had started is to die
    /// with it, and this ends what did not.
    pub fn kill_boxes(&self) {
        let Ok(entries) = fs::read_dir(self.boxes()) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(dir) = open_dir_in(self.boxes.as_fd(), &name) {
                let _ = kill(dir.as_fd());
            }
        }
    }

    /// Creates the cgroup of box `box_id`, empty and with no room for a
    /// cgroup below it. A cgroup of that name left by an incomplete teardown
    /// is emptied and removed first, so the new one is never the cgroup an
    /// older handle still names.
    ///
    /// # Errors
    ///
    /// When the cgroup cannot be created, or one of that name still holds
    /// processes after a kill.
    pub fn create_box(&self, box_id: &str) -> io::Result<BoxCgroup> {
        let name = box_name(box_id)?;
        let dir = self.boxes().join(&name);
        let c_name = std::ffi::CString::new(name.as_bytes()).map_err(io::Error::other)?;
        let make = || {
            // SAFETY: `mkdirat` with a live descriptor and a NUL-terminated
            // name.
            if unsafe { libc::mkdirat(self.boxes.as_raw_fd(), c_name.as_ptr(), 0o755) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        };
        match make() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let leftover = open_dir_in(self.boxes.as_fd(), &name)
                    .map_err(|e| named(e, "opening the leftover", &dir))?;
                kill(leftover.as_fd()).map_err(|e| named(e, "emptying the leftover", &dir))?;
                if !emptied_blocking(leftover.as_fd(), Duration::from_secs(2))? {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{} still holds processes", dir.display()),
                    ));
                }
                remove(self.boxes.as_fd(), &name, cgroup_id(&leftover)?)
                    .map_err(|e| named(e, "removing the leftover", &dir))?;
                make().map_err(|e| named(e, "creating", &dir))?;
            }
            Err(e) => return Err(named(e, "creating", &dir)),
        }
        let fd = open_dir_in(self.boxes.as_fd(), &name).map_err(|e| named(e, "opening", &dir))?;
        // No cgroup below the box, ever: a process in the box cannot create
        // one, whatever namespaces it makes, and cannot raise this limit.
        write_in(fd.as_fd(), "cgroup.max.descendants", "0")
            .map_err(|e| named(e, "closing the subtree of", &dir))?;
        let id = cgroup_id(&fd).map_err(|e| named(e, "reading the id of", &dir))?;
        Ok(BoxCgroup(Arc::new(Inner {
            name,
            dir,
            fd,
            parent: Arc::clone(&self.boxes),
            id,
            controllers: self.controllers,
            destroyed: AtomicBool::new(false),
        })))
    }

    /// The box whose cgroup process `pid` is in, by the name its cgroup was
    /// created under. `None` for a process in no box cgroup of this root, or
    /// one that is gone.
    #[must_use]
    pub fn box_of_pid(&self, pid: u32) -> Option<String> {
        self.box_of_cgroup(&cgroup_of(&pid.to_string()).ok()?)
    }

    /// The box a cgroup path belongs to; see [`Self::box_of_pid`].
    #[must_use]
    pub fn box_of_cgroup(&self, cgroup: &str) -> Option<String> {
        box_below(&self.name, cgroup).map(str::to_owned)
    }

    /// The root as `/proc/<pid>/cgroup` spells it, with no trailing slash:
    /// empty for the real cgroup root.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The name of the box cgroup that `cgroup` is, below the root named `root`:
/// both as `/proc/<pid>/cgroup` spells them. `None` for a cgroup that is not
/// a box cgroup of that root.
#[must_use]
pub fn box_below<'a>(root: &str, cgroup: &'a str) -> Option<&'a str> {
    let below = cgroup
        .strip_prefix(root)?
        .strip_prefix('/')?
        .strip_prefix(BOXES)?
        .strip_prefix('/')?;
    let name = below.split('/').next()?;
    (!name.is_empty()).then_some(name)
}

/// The directory name of a box's cgroup: the id, when it is a plain name.
fn box_name(box_id: &str) -> io::Result<String> {
    let plain = !box_id.is_empty()
        && box_id != "."
        && box_id != ".."
        && box_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if plain {
        Ok(box_id.to_owned())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{box_id}` cannot name a cgroup"),
        ))
    }
}

fn named(error: io::Error, doing: &str, path: &Path) -> io::Error {
    io::Error::new(error.kind(), format!("{doing} {}: {error}", path.display()))
}

/// The kernel's id of the cgroup behind `dir`: what a BPF program reads as
/// the cgroup id of a process in it.
fn cgroup_id(dir: &OwnedFd) -> io::Result<u64> {
    // `struct file_handle` with room for the 8 bytes cgroup2 fills in.
    #[repr(C)]
    struct Handle {
        bytes: libc::c_uint,
        kind: libc::c_int,
        id: u64,
    }
    let mut handle = Handle {
        bytes: 8,
        kind: 0,
        id: 0,
    };
    let mut mount_id: libc::c_int = 0;
    // SAFETY: `handle` and `mount_id` outlive the call, and `handle.bytes`
    // says how much room follows the header.
    let got = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            dir.as_raw_fd(),
            c"".as_ptr(),
            &raw mut handle,
            &raw mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if got == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(handle.id)
}

/// Whether the cgroup2 mount that covers `dir` has `nsdelegate`.
///
/// The option makes the root of a cgroup namespace a delegation boundary.
/// A box runs with the daemon's uid, so file permissions let it write the
/// limits of its own cgroup from a mount it makes itself. Only this option
/// stops it.
///
/// # Errors
///
/// When the mount table cannot be read, no cgroup2 mount covers `dir`, or
/// the mount lacks the option. The error names the option.
pub fn mount_delegates(dir: &Path) -> io::Result<()> {
    let table = fs::read_to_string("/proc/self/mountinfo")?;
    match covering_cgroup2_mount(&table, dir) {
        Some((_, options)) if options.split(',').any(|option| option == "nsdelegate") => Ok(()),
        Some((mount, options)) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the cgroup2 mount at {mount} is mounted without `nsdelegate` (its options are \
                 `{options}`), so a box could change the limits of its own cgroup"
            ),
        )),
        None => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("no cgroup2 mount covers {}", dir.display()),
        )),
    }
}

/// The mount point and superblock options of the cgroup2 mount that covers
/// `dir`, from the text of a `mountinfo` file. The last mount on the longest
/// matching mount point is the one in effect.
fn covering_cgroup2_mount<'a>(table: &'a str, dir: &Path) -> Option<(&'a str, &'a str)> {
    let mut found: Option<(&str, &str, &str)> = None;
    for line in table.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let Some(point) = before.split(' ').nth(4) else {
            continue;
        };
        if !dir.starts_with(point) {
            continue;
        }
        let mut after = after.split(' ');
        let (Some(fstype), Some(_source), Some(options)) =
            (after.next(), after.next(), after.next())
        else {
            continue;
        };
        if found.is_none_or(|(longest, _, _)| point.len() >= longest.len()) {
            found = Some((point, fstype, options));
        }
    }
    found
        .filter(|(_, fstype, _)| *fstype == "cgroup2")
        .map(|(point, _, options)| (point, options))
}

/// Opens the file `name` of the cgroup behind `dir`.
fn open_in(dir: BorrowedFd<'_>, name: &str, flags: libc::c_int) -> io::Result<fs::File> {
    let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `openat` with a live descriptor and a NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor that nothing else owns.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

/// Opens the cgroup `name` below the cgroup behind `parent`.
fn open_dir_in(parent: BorrowedFd<'_>, name: &str) -> io::Result<OwnedFd> {
    open_in(parent, name, libc::O_RDONLY | libc::O_DIRECTORY).map(OwnedFd::from)
}

fn write_in(dir: BorrowedFd<'_>, file: &str, value: &str) -> io::Result<()> {
    use std::io::Write as _;
    open_in(dir, file, libc::O_WRONLY)?.write_all(value.as_bytes())
}

fn read_in(dir: BorrowedFd<'_>, file: &str) -> io::Result<String> {
    use std::io::Read as _;
    let mut text = String::new();
    open_in(dir, file, libc::O_RDONLY)?.read_to_string(&mut text)?;
    Ok(text)
}

fn kill(dir: BorrowedFd<'_>) -> io::Result<()> {
    write_in(dir, "cgroup.kill", "1")
}

/// Removes the cgroup `name` below `parent`, if it is still the cgroup with
/// the id `id`. A cgroup made later under the same name is left alone.
fn remove(parent: BorrowedFd<'_>, name: &str, id: u64) -> io::Result<()> {
    match open_dir_in(parent, name) {
        Ok(current) if cgroup_id(&current)? != id => return Ok(()),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `unlinkat` with a live descriptor and a NUL-terminated name.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

fn populated(events: &str) -> bool {
    events.lines().any(|line| line.trim() == "populated 1")
}

/// Waits until the cgroup behind `dir` holds no process, for at most
/// `limit`. Whether it emptied.
fn emptied_blocking(dir: BorrowedFd<'_>, limit: Duration) -> io::Result<bool> {
    use std::io::{Read as _, Seek as _};
    let mut events = open_in(dir, "cgroup.events", libc::O_RDONLY)?;
    let deadline = Instant::now() + limit;
    loop {
        let mut text = String::new();
        events.rewind()?;
        events.read_to_string(&mut text)?;
        if !populated(&text) {
            return Ok(true);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        // The kernel raises a priority event on this file when `populated`
        // changes. The cap is for an event that came before the poll.
        let mut poll = libc::pollfd {
            fd: events.as_raw_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        let wait = left.min(Duration::from_millis(100));
        // SAFETY: one valid pollfd that outlives the call.
        unsafe { libc::poll(&raw mut poll, 1, wait.as_millis() as libc::c_int) };
    }
}

/// The cgroup of one box.
///
/// Clones name the same cgroup. The code that owns the box's lifetime calls
/// [`BoxCgroup::destroy`] when the box is gone. Dropping the last clone
/// without it only issues a kill and tries one removal.
///
/// Every operation goes through the open directory, never through the
/// path: a handle that outlives its cgroup cannot touch a cgroup made later
/// under the same name.
#[derive(Debug, Clone)]
pub struct BoxCgroup(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    name: String,
    /// For messages only.
    dir: PathBuf,
    fd: OwnedFd,
    /// The `boxes` cgroup, which the cgroup is removed from.
    parent: Arc<OwnedFd>,
    id: u64,
    controllers: Controllers,
    destroyed: AtomicBool,
}

impl BoxCgroup {
    /// The name the cgroup was created under.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0.name
    }

    /// The cgroup's directory, for a message or a test. Nothing here acts
    /// on the path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0.dir
    }

    /// The kernel's id of this cgroup. A BPF program attached above the box
    /// cgroups reads the same number for every process of the box.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// The cgroup's directory, open: what a process is created into.
    #[must_use]
    pub fn dir_fd(&self) -> BorrowedFd<'_> {
        self.0.fd.as_fd()
    }

    fn write(&self, file: &str, value: &str) -> io::Result<()> {
        write_in(self.0.fd.as_fd(), file, value)
    }

    /// Sets the box's share of CPU time under contention (`cpu.weight`).
    ///
    /// # Errors
    ///
    /// [`LimitError::ControllerNotDelegated`] without the `cpu` controller.
    pub fn set_cpu_weight(&self, weight: CpuWeight) -> Result<(), LimitError> {
        if !self.0.controllers.cpu {
            return Err(LimitError::ControllerNotDelegated("cpu"));
        }
        Ok(self.write("cpu.weight", &weight.0.to_string())?)
    }

    /// Sets the most memory the box may use, in bytes (`memory.max`). `None`
    /// lifts the limit.
    ///
    /// # Errors
    ///
    /// [`LimitError::ControllerNotDelegated`] without the `memory` controller.
    pub fn set_memory_max(&self, bytes: Option<NonZeroU64>) -> Result<(), LimitError> {
        if !self.0.controllers.memory {
            return Err(LimitError::ControllerNotDelegated("memory"));
        }
        Ok(self.write("memory.max", &max_value(bytes))?)
    }

    /// Sets the most processes the box may hold (`pids.max`). `None` lifts
    /// the limit.
    ///
    /// # Errors
    ///
    /// [`LimitError::ControllerNotDelegated`] without the `pids` controller.
    pub fn set_pids_max(&self, processes: Option<NonZeroU64>) -> Result<(), LimitError> {
        if !self.0.controllers.pids {
            return Err(LimitError::ControllerNotDelegated("pids"));
        }
        Ok(self.write("pids.max", &max_value(processes))?)
    }

    /// The processes in the cgroup, as this process's PID namespace numbers
    /// them.
    ///
    /// # Errors
    ///
    /// When `cgroup.procs` cannot be read.
    pub fn procs(&self) -> io::Result<Vec<u32>> {
        Ok(read_in(self.0.fd.as_fd(), "cgroup.procs")?
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect())
    }

    /// Sends `signal` to every process in the cgroup that `skip` does not
    /// name, and says how many it reached.
    ///
    /// Each process is pinned by a pidfd and signalled only if its pid is
    /// still listed in the cgroup afterwards. A pid that a process outside
    /// the box took over in between is not listed, and a process that left
    /// after the check takes no signal through its pidfd.
    ///
    /// # Errors
    ///
    /// When `cgroup.procs` cannot be read.
    pub fn signal(&self, signal: i32, skip: impl Fn(u32) -> bool) -> io::Result<usize> {
        let pinned: Vec<(u32, OwnedFd)> = self
            .procs()?
            .into_iter()
            .filter(|pid| !skip(*pid))
            .filter_map(|pid| {
                // SAFETY: `pidfd_open` takes a pid and flags.
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                // SAFETY: a fresh descriptor that nothing else owns.
                (fd >= 0).then(|| (pid, unsafe { OwnedFd::from_raw_fd(fd as i32) }))
            })
            .collect();
        let still = self.procs()?;
        Ok(pinned
            .iter()
            .filter(|(pid, _)| still.contains(pid))
            .filter(|(_, pidfd)| {
                // SAFETY: `pidfd_send_signal` with no `siginfo` reads no
                // memory.
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        signal,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                sent == 0
            })
            .count())
    }

    /// Whether the cgroup holds a live process.
    ///
    /// # Errors
    ///
    /// When `cgroup.events` cannot be read.
    pub fn populated(&self) -> io::Result<bool> {
        Ok(populated(&read_in(self.0.fd.as_fd(), "cgroup.events")?))
    }

    /// Kills every process in the cgroup (`cgroup.kill`).
    ///
    /// # Errors
    ///
    /// When the kill cannot be written.
    pub fn kill(&self) -> io::Result<()> {
        kill(self.0.fd.as_fd())
    }

    /// Waits until the cgroup holds no process, for at most `limit`. Whether
    /// it emptied.
    ///
    /// # Errors
    ///
    /// When `cgroup.events` cannot be read.
    pub async fn emptied(&self, limit: Duration) -> io::Result<bool> {
        let cgroup = self.clone();
        // The wait is a poll on `cgroup.events`, off the async threads.
        tokio::task::spawn_blocking(move || emptied_blocking(cgroup.0.fd.as_fd(), limit))
            .await
            .map_err(io::Error::other)?
    }

    /// Ends the box: kills every process in the cgroup, waits up to `limit`
    /// for it to empty, and removes it. A second call does nothing.
    ///
    /// # Errors
    ///
    /// When the cgroup still holds a process after `limit`, or cannot be
    /// removed. The cgroup then stays for the next daemon start to sweep.
    pub async fn destroy(&self, limit: Duration) -> io::Result<()> {
        let cgroup = self.clone();
        // The wait is a poll on `cgroup.events`, off the async threads.
        tokio::task::spawn_blocking(move || cgroup.destroy_blocking(limit))
            .await
            .map_err(io::Error::other)?
    }

    /// [`Self::destroy`], for a caller on a thread of its own.
    ///
    /// # Errors
    ///
    /// As [`Self::destroy`].
    pub fn destroy_blocking(&self, limit: Duration) -> io::Result<()> {
        if self.0.destroyed.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self.kill() {
            Ok(()) => {}
            // Removed already, by a sweep or by hand: the kernel answers
            // `ENODEV` for a file of a cgroup that is gone.
            Err(e) if is_gone(&e) => {
                self.0.destroyed.store(true, Ordering::SeqCst);
                return Ok(());
            }
            Err(e) => return Err(named(e, "killing", &self.0.dir)),
        }
        if !emptied_blocking(self.0.fd.as_fd(), limit)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{} still holds processes {limit:?} after the kill",
                    self.0.dir.display()
                ),
            ));
        }
        remove(self.0.parent.as_fd(), &self.0.name, self.0.id)
            .map_err(|e| named(e, "removing", &self.0.dir))?;
        self.0.destroyed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn max_value(limit: Option<NonZeroU64>) -> String {
    limit.map_or_else(|| "max".to_owned(), |limit| limit.to_string())
}

impl Drop for Inner {
    /// The safety net for a box nobody destroyed: one kill and one removal
    /// attempt, neither waited on.
    fn drop(&mut self) {
        if self.destroyed.load(Ordering::SeqCst) {
            return;
        }
        let _ = kill(self.fd.as_fd());
        let _ = remove(self.parent.as_fd(), &self.name, self.id);
    }
}

/// Whether an error on a cgroup's file says the cgroup is gone.
fn is_gone(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENODEV)
}

/// A delegated cgroup for a test.
pub mod testing {
    use super::{Located, Root, locate};

    /// Set in the copy of a test that runs inside the scope made for it.
    const IN_SCOPE: &str = "MINIMAL_TEST_IN_DELEGATED_SCOPE";

    /// A cgroup root for the test named `test`, the full name the test
    /// harness lists it under.
    ///
    /// A test needs a cgroup it may manage, and a developer's shell is not in
    /// one. So this runs the same test again inside a transient delegated
    /// scope of the user manager, passes or fails with that run, and returns
    /// `None` so the caller ends. In that second run it returns the root.
    /// Root makes a cgroup of its own at the top of the hierarchy instead.
    /// Where neither is possible it prints why and returns `None`.
    ///
    /// # Panics
    ///
    /// When the run inside the scope fails.
    #[must_use]
    pub fn delegated_root(test: &str) -> Option<Root> {
        if std::env::var_os(IN_SCOPE).is_some() {
            return match locate() {
                Located::DelegatedUnit(dir) | Located::Guest(dir) => {
                    Some(Root::open(&dir).expect("taking the scope's cgroup as the root"))
                }
                Located::None { why } => panic!("the test's scope is not delegated: {why}"),
            };
        }
        // SAFETY: `geteuid` reads this process's credentials.
        if unsafe { libc::geteuid() } == 0 {
            let dir = std::path::PathBuf::from(format!(
                "{}/minimal-test-{}",
                super::MOUNT,
                std::process::id()
            ));
            return match std::fs::create_dir(&dir).and_then(|()| Root::open(&dir)) {
                Ok(root) => Some(root),
                Err(error) => {
                    eprintln!("skipping {test}: root could not make a cgroup for it: {error}");
                    None
                }
            };
        }
        let exe = std::env::current_exe().expect("this test binary's path");
        let run = super::delegated_scope_command(
            None,
            &exe,
            ["--exact", test, "--nocapture", "--test-threads=1"].map(Into::into),
        )
        .env(IN_SCOPE, "1")
        .output();
        let output = match run {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skipping {test}: systemd-run is not available: {error}");
                return None;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() && !stdout.contains("running 1 test") {
            eprintln!(
                "skipping {test}: no delegated cgroup on this host (systemd-run --user --scope \
                 failed: {})",
                stderr.trim()
            );
            return None;
        }
        print!("{stdout}");
        eprint!("{stderr}");
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{test} failed inside its delegated scope"
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::testing::delegated_root;
    use super::*;

    #[test]
    fn a_unit_s_cgroup_names_its_unit_and_manager() {
        assert_eq!(
            unit_of("/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1.scope"),
            Some((
                "run-r1.scope",
                "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1.scope",
                true
            ))
        );
        // A unit that starts its main process in the `supervisor` sub-cgroup.
        assert_eq!(
            unit_of(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/minimald.service/supervisor"
            ),
            Some((
                "minimald.service",
                "/user.slice/user-1000.slice/user@1000.service/app.slice/minimald.service",
                true
            ))
        );
        assert_eq!(
            unit_of("/system.slice/minimald.service"),
            Some(("minimald.service", "/system.slice/minimald.service", false))
        );
        assert_eq!(
            unit_of("/user.slice/user-1000.slice/session-3.scope/x"),
            None
        );
        assert_eq!(unit_of("/non-systemd"), None);
        assert_eq!(unit_of("/"), None);
    }

    #[test]
    fn a_box_cgroup_is_the_one_directly_below_boxes() {
        let root = "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1.scope";
        assert_eq!(box_below(root, &format!("{root}/boxes/b1")), Some("b1"));
        assert_eq!(box_below(root, &format!("{root}/supervisor")), None);
        assert_eq!(box_below(root, &format!("{root}/boxes")), None);
        assert_eq!(box_below(root, &format!("{root}/boxes/")), None);
        assert_eq!(box_below(root, &format!("{root}x/boxes/b1")), None);
        assert_eq!(box_below(root, "/elsewhere/boxes/b1"), None);
        // The real cgroup root, as a guest's daemon has it.
        assert_eq!(box_below("", "/boxes/b1"), Some("b1"));
        assert_eq!(box_below("", "/supervisor"), None);
    }

    #[test]
    fn a_box_name_is_a_plain_directory_name() {
        assert!(box_name("0198c7de-5a0b-7c31-9d7e-1f2a3b4c5d6e").is_ok());
        assert!(box_name("build-7").is_ok());
        for bad in ["", ".", "..", "a/b", "a b", "../x", "x\n"] {
            assert!(box_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_cpu_weight_is_one_to_ten_thousand() {
        assert!(CpuWeight::new(0).is_none());
        assert!(CpuWeight::new(1).is_some());
        assert!(CpuWeight::new(10_000).is_some());
        assert!(CpuWeight::new(10_001).is_none());
        assert_eq!(CpuWeight::clamped(0), CpuWeight(1));
        assert_eq!(CpuWeight::clamped(50_000), CpuWeight(10_000));
    }

    #[test]
    fn the_root_has_a_supervisor_and_boxes_with_controllers() {
        let Some(root) =
            delegated_root("cgroup::tests::the_root_has_a_supervisor_and_boxes_with_controllers")
        else {
            return;
        };
        assert_eq!(own_cgroup().unwrap(), root.supervisor_name());
        assert!(root.dir().join(BOXES).is_dir());
        let delegated = fs::read_to_string(root.dir().join("cgroup.controllers")).unwrap();
        let has = |controller: &str| delegated.split_whitespace().any(|c| c == controller);
        assert_eq!(
            root.controllers(),
            Controllers {
                cpu: has("cpu"),
                memory: has("memory"),
                pids: has("pids"),
            }
        );
        // Opening it again, now from `supervisor`, changes nothing.
        let again = Root::open(root.dir()).unwrap();
        assert_eq!(again.controllers(), root.controllers());
        assert_eq!(own_cgroup().unwrap(), root.supervisor_name());
    }

    #[test]
    fn a_box_cgroup_is_one_cgroup_with_an_id_and_limits() {
        let Some(root) =
            delegated_root("cgroup::tests::a_box_cgroup_is_one_cgroup_with_an_id_and_limits")
        else {
            return;
        };
        let cgroup = root.create_box("b1").unwrap();
        assert_eq!(cgroup.name(), "b1");
        assert_eq!(cgroup.path(), root.dir().join(BOXES).join("b1"));
        // The id is the cgroup directory's inode number.
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(cgroup.id(), fs::metadata(cgroup.path()).unwrap().ino());
        assert_ne!(cgroup.id(), 0);
        // Nothing can be made below it.
        assert_eq!(
            fs::read_to_string(cgroup.path().join("cgroup.max.descendants"))
                .unwrap()
                .trim(),
            "0"
        );
        let below = fs::create_dir(cgroup.path().join("sub")).unwrap_err();
        assert_eq!(below.raw_os_error(), Some(libc::EAGAIN), "{below}");

        let read = |file: &str| fs::read_to_string(cgroup.path().join(file)).unwrap();
        let controllers = root.controllers();
        if controllers.cpu {
            cgroup.set_cpu_weight(CpuWeight::new(250).unwrap()).unwrap();
            assert_eq!(read("cpu.weight").trim(), "250");
        } else {
            assert!(matches!(
                cgroup.set_cpu_weight(CpuWeight::clamped(250)),
                Err(LimitError::ControllerNotDelegated("cpu"))
            ));
        }
        if controllers.memory {
            cgroup.set_memory_max(NonZeroU64::new(64 << 20)).unwrap();
            assert_eq!(read("memory.max").trim(), (64u64 << 20).to_string());
            cgroup.set_memory_max(None).unwrap();
            assert_eq!(read("memory.max").trim(), "max");
        }
        if controllers.pids {
            cgroup.set_pids_max(NonZeroU64::new(32)).unwrap();
            assert_eq!(read("pids.max").trim(), "32");
        }
        assert_eq!(
            root.box_of_cgroup(&format!("{}/boxes/b1", root.name)),
            Some("b1".into())
        );
        assert_eq!(root.box_of_cgroup(&root.supervisor_name()), None);
        assert_eq!(root.box_of_pid(std::process::id()), None);
        assert!(root.create_box("../escape").is_err());
    }

    /// A process placed in the cgroup by a write, for a test: the cgroup
    /// module itself never moves a process.
    fn sleeper_in(cgroup: &BoxCgroup) -> std::process::Child {
        use std::os::unix::process::CommandExt as _;
        let procs = cgroup.path().join("cgroup.procs");
        let mut sleep = std::process::Command::new("sleep");
        sleep.arg("600");
        // SAFETY: the hook only opens and writes a file.
        unsafe {
            sleep.pre_exec(move || fs::write(&procs, "0"));
        }
        sleep.spawn().unwrap()
    }

    #[test]
    fn the_covering_mount_decides_whether_boxes_are_contained() {
        let line = |point: &str, fstype: &str, options: &str| {
            format!("30 25 0:26 / {point} rw,nosuid shared:4 - {fstype} {fstype} {options}\n")
        };
        let delegated = line("/", "ext4", "rw")
            + &line("/sys", "sysfs", "rw")
            + &line(
                "/sys/fs/cgroup",
                "cgroup2",
                "rw,nsdelegate,memory_recursiveprot",
            );
        let dir = Path::new("/sys/fs/cgroup/user.slice/x.scope");
        assert_eq!(
            covering_cgroup2_mount(&delegated, dir),
            Some(("/sys/fs/cgroup", "rw,nsdelegate,memory_recursiveprot"))
        );
        // A later mount on the same point is the one in effect.
        let remounted = delegated.clone() + &line("/sys/fs/cgroup", "cgroup2", "rw");
        assert_eq!(
            covering_cgroup2_mount(&remounted, dir),
            Some(("/sys/fs/cgroup", "rw"))
        );
        // A directory no cgroup2 mount covers has none.
        assert_eq!(
            covering_cgroup2_mount(&delegated, Path::new("/sys/fs")),
            None
        );
        let hidden = delegated + &line("/sys/fs/cgroup/user.slice", "tmpfs", "rw");
        assert_eq!(covering_cgroup2_mount(&hidden, dir), None);
    }

    /// A handle that outlives its cgroup does nothing to a cgroup made later
    /// under the same name: not through its methods, and not when it drops.
    #[tokio::test]
    async fn a_stale_handle_cannot_touch_a_newer_cgroup_of_the_same_name() {
        let Some(root) = delegated_root(
            "cgroup::tests::a_stale_handle_cannot_touch_a_newer_cgroup_of_the_same_name",
        ) else {
            return;
        };
        let old = root.create_box("same").unwrap();
        let newer = root.create_box("same").unwrap();
        assert_ne!(
            old.id(),
            newer.id(),
            "the leftover was replaced, not reused"
        );
        let mut sleeper = sleeper_in(&newer);

        assert!(old.kill().is_err(), "the old cgroup is gone");
        assert!(old.procs().is_err());
        old.destroy(Duration::from_secs(1)).await.unwrap();
        drop(old);
        assert_eq!(newer.procs().unwrap(), [sleeper.id()]);
        assert!(newer.path().exists());

        // The same for a handle that is only dropped.
        let old = newer;
        let newest = root.create_box("same").unwrap();
        sleeper.wait().unwrap();
        let mut sleeper = sleeper_in(&newest);
        drop(old);
        assert_eq!(newest.procs().unwrap(), [sleeper.id()]);
        newest.destroy(Duration::from_secs(10)).await.unwrap();
        sleeper.wait().unwrap();
    }

    /// A signal reaches the processes of the cgroup, the skipped ones aside.
    #[test]
    fn a_signal_reaches_the_cgroups_processes_but_the_skipped() {
        use std::os::unix::process::ExitStatusExt as _;
        let Some(root) =
            delegated_root("cgroup::tests::a_signal_reaches_the_cgroups_processes_but_the_skipped")
        else {
            return;
        };
        let cgroup = root.create_box("signalled").unwrap();
        let mut spared = sleeper_in(&cgroup);
        let mut reached = sleeper_in(&cgroup);
        let skip = spared.id();
        assert_eq!(cgroup.signal(libc::SIGTERM, |pid| pid == skip).unwrap(), 1);
        assert_eq!(reached.wait().unwrap().signal(), Some(libc::SIGTERM));
        assert_eq!(cgroup.procs().unwrap(), [spared.id()]);
        assert_eq!(cgroup.signal(libc::SIGKILL, |_| false).unwrap(), 1);
        spared.wait().unwrap();
        assert_eq!(cgroup.signal(libc::SIGKILL, |_| false).unwrap(), 0);
    }

    #[tokio::test]
    async fn a_kill_empties_a_box_cgroup_and_destroy_removes_it() {
        let Some(root) =
            delegated_root("cgroup::tests::a_kill_empties_a_box_cgroup_and_destroy_removes_it")
        else {
            return;
        };
        let cgroup = root.create_box("b2").unwrap();
        assert!(!cgroup.populated().unwrap());
        assert!(cgroup.emptied(Duration::from_millis(10)).await.unwrap());

        let mut one = sleeper_in(&cgroup);
        let mut two = sleeper_in(&cgroup);
        let mut pids = cgroup.procs().unwrap();
        pids.sort_unstable();
        let mut expected = vec![one.id(), two.id()];
        expected.sort_unstable();
        assert_eq!(pids, expected);
        assert!(cgroup.populated().unwrap());
        assert_eq!(root.box_of_pid(one.id()), Some("b2".to_owned()));
        assert!(
            !cgroup.emptied(Duration::from_millis(50)).await.unwrap(),
            "a cgroup with live processes does not read as empty"
        );

        // The wait sees the cgroup empty without the children being reaped.
        let waiting = cgroup.clone();
        let emptied = tokio::spawn(async move { waiting.emptied(Duration::from_secs(10)).await });
        cgroup.kill().unwrap();
        assert!(emptied.await.unwrap().unwrap());
        assert!(cgroup.procs().unwrap().is_empty());
        one.wait().unwrap();
        two.wait().unwrap();

        let mut three = sleeper_in(&cgroup);
        cgroup.destroy(Duration::from_secs(10)).await.unwrap();
        assert!(!cgroup.path().exists());
        three.wait().unwrap();
        // A second destroy, and the drop after it, do nothing.
        cgroup.destroy(Duration::from_secs(1)).await.unwrap();
    }

    #[test]
    fn a_dropped_box_cgroup_is_killed_and_a_sweep_removes_leftovers() {
        let Some(root) = delegated_root(
            "cgroup::tests::a_dropped_box_cgroup_is_killed_and_a_sweep_removes_leftovers",
        ) else {
            return;
        };
        // Dropped while empty: the one removal attempt succeeds.
        let empty = root.create_box("empty").unwrap();
        let path = empty.path().to_path_buf();
        drop(empty);
        assert!(!path.exists());

        // Dropped with a process in it: the process is killed, and the
        // cgroup may stay until a sweep.
        let busy = root.create_box("busy").unwrap();
        let mut child = sleeper_in(&busy);
        let path = busy.path().to_path_buf();
        drop(busy);
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));

        // A leftover with a live process, as a crashed daemon leaves one.
        let leftover = root.create_box("leftover").unwrap();
        let mut orphan = sleeper_in(&leftover);
        std::mem::forget(leftover);
        let mut swept = root.sweep(Duration::from_secs(10)).unwrap();
        swept.sort();
        assert!(swept.contains(&"leftover".to_owned()), "{swept:?}");
        assert_eq!(orphan.wait().unwrap().signal(), Some(libc::SIGKILL));
        assert!(!path.exists());
        let left = fs::read_dir(root.dir().join(BOXES))
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir())
            .count();
        assert_eq!(left, 0);

        // A name left behind is emptied and reused.
        let again = root.create_box("again").unwrap();
        let mut stale = sleeper_in(&again);
        std::mem::forget(again);
        let reused = root.create_box("again").unwrap();
        assert!(reused.procs().unwrap().is_empty());
        assert_eq!(stale.wait().unwrap().signal(), Some(libc::SIGKILL));
    }
}
