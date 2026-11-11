//! The engine against the running kernel.
//!
//! Every test here loads the real programs through a root loader and then
//! works as the daemon does: unprivileged, with handed-over map handles,
//! judging what processes in box cgroups can do.
//!
//! They need passwordless `sudo -n`, a systemd host and cgroup v2, and are
//! skipped unless `BOXBPF_ROOT_TEST` is set. Run them with
//! `scripts/boxbpf-root-tests.sh`.
#![cfg(target_os = "linux")]

mod support;

mod cases {
    pub mod loader;
    pub mod netns;
    pub mod parity;
    pub mod redirect;
    pub mod rules;
    pub mod sockets;
}

/// Not a test: the entry point of the helper processes the tests start.
#[test]
#[ignore = "helper process of the root tests; does nothing when run directly"]
fn helper() {
    support::roles::run();
}
