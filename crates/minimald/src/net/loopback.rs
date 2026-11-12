//! The session-start loopback probe. It binds every address of the reserved
//! local range on this daemon's own loopback. The `CreateSession` reply
//! carries the verdict as `interim_loopback`, and the handler logs it once
//! per session.
//!
//! The probe is `switch::loopback`, which the CLI and the VM host daemon run
//! too. This daemon is a Linux process, and Linux carries all of `127/8` on
//! `lo`, so its probe reads the range present. A macOS host's `lo0` can lack
//! the range, and there the VM host daemon probes its own loopback before it
//! hands a box an address in the range.
//!
//! This module adds the stand-in a test installs so the handler sees an
//! absent range.

pub use ::switch::loopback::{RangeProbe, probe};

/// The test stand-in for the session-start probe, when one is installed: a
/// `fn` so it needs no capture, process-global because the probe has no
/// caller to thread through — the `CreateSession` handler reads it at
/// session start. Production builds never read this (the field is compiled
/// out); a test that installs one serializes against every other test in
/// the binary that drives a create, since the stand-in is process-global.
#[cfg(any(test, feature = "test-support"))]
static PROBE_STANDIN: std::sync::Mutex<Option<fn() -> RangeProbe>> = std::sync::Mutex::new(None);

/// Serialises the tests that install a probe stand-in, and the tests whose
/// creates must not see another test's.
#[cfg(test)]
pub(crate) static PROBE_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Installs the probe a test wants the session-start path to see.
///
/// The tests that use this take [`PROBE_TEST_MUTEX`]
/// for the whole install→create→assert→clear window: under libtest the tests
/// of one binary share a process, and a concurrent create would read the
/// stand-in too.
#[cfg(any(test, feature = "test-support"))]
pub fn install_probe_standin(probe: fn() -> RangeProbe) {
    *PROBE_STANDIN.lock().unwrap() = Some(probe);
}

/// Clears the test stand-in, restoring the real bind probe.
#[cfg(any(test, feature = "test-support"))]
pub fn clear_probe_standin() {
    *PROBE_STANDIN.lock().unwrap() = None;
}

/// The probe to run at session start: the test stand-in when one is
/// installed, else the real bind probe. Test-support only: the production
/// handler calls [`probe`] directly.
#[cfg(any(test, feature = "test-support"))]
pub fn session_start_probe() -> RangeProbe {
    let standin = *PROBE_STANDIN.lock().unwrap();
    (standin.unwrap_or(probe))()
}
