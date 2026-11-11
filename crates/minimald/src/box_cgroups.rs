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

/// The box whose cgroup a process is in, from the path its
/// `/proc/<pid>/cgroup` names after `0::`. `None` for a process in no box
/// cgroup of this daemon.
pub(crate) fn box_of_cgroup(cgroup: &str) -> Option<boxes::SessionId> {
    boxes::SessionId::parse_str(sandbox::cgroup::box_below(&root_name()?, cgroup.trim())?).ok()
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
