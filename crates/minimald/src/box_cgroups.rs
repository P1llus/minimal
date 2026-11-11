//! The daemon's cgroup root and the cgroups of its boxes.
//!
//! The root is a fact about this process: the cgroup it runs in. It is set
//! once at start and read here, by the code that creates a box's cgroup and
//! by the lookups that name the box behind a process.

use std::sync::OnceLock;

use sandbox::cgroup::Root;

/// The daemon's cgroup root, or `None` where it has none. Unset until the
/// daemon has looked for one.
static ROOT: OnceLock<Option<Root>> = OnceLock::new();

/// Records the root the daemon found at start. The first call wins.
pub fn set_root(root: Option<Root>) {
    let _ = ROOT.set(root);
}

/// The root the policy loader handed this process, if it asked for one.
static HANDED: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Asks the policy loader for a cgroup root, for a daemon nobody delegates
/// one to: a host without a systemd user manager. The loader makes the
/// root and moves this process into it, so call this before any thread
/// starts. Says on standard error why there is none.
pub fn take_root_from_loader() {
    use std::os::fd::AsRawFd as _;

    let socket = crate::net::engine::loader_socket();
    if !socket.exists() {
        eprintln!(
            "minimald: no systemd user manager and no policy loader at {}; boxes get no cgroup",
            socket.display()
        );
        return;
    }
    let root = boxbpf::loader::request_root(&socket)
        .map_err(|error| error.to_string())
        .and_then(|root| {
            std::fs::read_link(format!("/proc/self/fd/{}", root.as_raw_fd()))
                .map_err(|error| error.to_string())
        });
    match root {
        Ok(path) => {
            let _ = HANDED.set(path);
        }
        Err(error) => eprintln!(
            "minimald: the policy loader gave no cgroup root ({error}); boxes get no cgroup"
        ),
    }
}

/// Where this daemon's cgroup root is: the one the loader handed it, or
/// the delegated unit it runs in.
#[must_use]
pub fn located() -> sandbox::cgroup::Located {
    match HANDED.get() {
        Some(path) => sandbox::cgroup::Located::Handed(path.clone()),
        None => sandbox::cgroup::locate(),
    }
}

/// Takes the daemon's cgroup root and starts its spawner, in that order:
/// the daemon moves into the root's `supervisor` cgroup, and the spawner
/// starts there.
///
/// `located` is where the root is, and `exe` is this binary, which the
/// spawner is. A daemon with no root runs its boxes without cgroups, and
/// says so once here.
pub fn boot(located: sandbox::cgroup::Located, exe: std::path::PathBuf, guest: bool) {
    use sandbox::cgroup::Located;

    let root = match located {
        Located::Guest(dir) | Located::DelegatedUnit(dir) | Located::Handed(dir) => {
            match Root::open(&dir) {
                // Taking the root ends the boxes of a daemon that ran in
                // this cgroup before and did not stop them. Their records
                // are stopped at start too.
                Ok(root) => {
                    tracing::info!(
                        root = %root.dir().display(),
                        controllers = ?root.controllers(),
                        "box cgroups are below the daemon's cgroup root"
                    );
                    Some(root)
                }
                Err(error) => {
                    tracing::warn!(
                        root = %dir.display(),
                        %error,
                        "the daemon's cgroup root cannot be used; boxes run without a cgroup, \
                         and a box that needs one is refused"
                    );
                    None
                }
            }
        }
        Located::None { why } => {
            tracing::warn!(
                %why,
                "the daemon has no cgroup root; boxes run without a cgroup, and a box that \
                 needs one is refused"
            );
            None
        }
    };
    // The policy engine for the boxes below the root, before any box can
    // start: every box cgroup gets its entry at creation.
    let node = if guest {
        crate::net::spec::Node::guest(crate::net::DEFAULT_SUBNET)
    } else {
        crate::net::spec::Node::native()
    };
    let root = crate::net::engine::Engine::boot(root, node);
    let spawner = sandbox::Spawner::process(exe, sandbox::Terminal::Detached, root.clone());
    set_root(root);

    if let Err(error) = spawner.start() {
        // Each launch tries again, and fails with the reason.
        tracing::error!(%error, "the daemon's spawner did not start; no box can run");
    }
    if spawner.install().is_err() {
        tracing::warn!("a spawner was installed before the daemon's own");
    }
}

/// Makes `command` start in the cgroup for the daemon's helper programs
/// and not beside the daemon: a helper works on input a box controls, and
/// the policy loader trusts every process in the daemon's own cgroup.
/// Without a cgroup root there is no loader either, and the command is left
/// as it is.
pub(crate) fn place_helper(command: &mut std::process::Command) {
    if let Some(root) = root() {
        root.helpers().place(command);
    }
}

/// Ends every helper program, at the daemon's clean stop.
pub fn kill_helpers() {
    if let Some(root) = root()
        && let Err(error) = root.helpers().kill()
    {
        tracing::warn!(%error, "ending the daemon's helper programs");
    }
}

/// The daemon's cgroup root, if it has one.
pub(crate) fn root() -> Option<&'static Root> {
    ROOT.get().and_then(Option::as_ref)
}

/// The root as `/proc/<pid>/cgroup` spells it, if the daemon has one.
fn root_name() -> Option<String> {
    #[cfg(test)]
    if let Some(name) = TEST_ROOT_NAME.with(|name| name.borrow().clone()) {
        return Some(name);
    }
    root().map(|root| root.name().to_owned())
}

/// Whether the cgroup path is a box cgroup of this daemon.
pub(crate) fn in_a_box(cgroup: &str) -> bool {
    root_name().is_some_and(|root| sandbox::cgroup::box_below(&root, cgroup.trim()).is_some())
}

#[cfg(test)]
thread_local! {
    static TEST_ROOT_NAME: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Runs `test` as a daemon whose cgroup root is named `name`.
#[cfg(test)]
pub(crate) fn with_root_name<T>(name: &str, test: impl FnOnce() -> T) -> T {
    TEST_ROOT_NAME.with(|slot| *slot.borrow_mut() = Some(name.to_owned()));
    let result = test();
    TEST_ROOT_NAME.with(|slot| *slot.borrow_mut() = None);
    result
}
