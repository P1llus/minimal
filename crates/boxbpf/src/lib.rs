//! The box policy engine in the kernel.
//!
//! - [`Engine`] loads the cgroup programs and attaches them at a `boxes/`
//!   cgroup. It needs root.
//! - [`Handles`] are the maps of an attached engine. They work without
//!   privilege, also after being passed to another process.
//! - [`events`] reads the engine's event ring buffer.
//! - [`loader`] is the protocol by which an unprivileged daemon gets its
//!   handles from a root loader.
//!
//! Policy itself, and the layouts shared with the programs, are in `netpol`.
//! This crate only exists on Linux. On other targets it is empty.

#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
pub mod events;
#[cfg(target_os = "linux")]
mod handles;
#[cfg(target_os = "linux")]
pub mod loader;
#[cfg(target_os = "linux")]
mod sys;

#[cfg(target_os = "linux")]
pub use engine::{Engine, MapSizes, object_id};
#[cfg(target_os = "linux")]
pub use error::Error;
#[cfg(target_os = "linux")]
pub use handles::{BoxId, Flows, Handles, LiveBox, OriginalDestination};
#[cfg(target_os = "linux")]
pub use sys::{boot_time_ns, cgroup_id};
