//! Network policy of a box.
//!
//! A policy is an ordered list of [`Rule`]s. The first rule that matches a
//! flow decides it. If none matches, the default of the flow's direction
//! applies. Everything the engine does is such a rule: subnets, protocol
//! limits, published ports, DNS interception, steering to a proxy, and the
//! protections every box gets.
//!
//! - [`base`] builds the rules a deployment and mode imply.
//! - [`policy`] holds what the box declares for itself.
//! - [`compile()`] turns both into the entries the kernel programs read.
//! - [`Compiled::evaluate`] judges a flow the same way those programs do.
//! - [`abi`] has the map and event layouts shared with the C side.
//! - [`pins`] has the bookkeeping for addresses the resolver admits by name.
//!
//! Nothing here calls the operating system.

pub mod abi;
pub mod base;
pub mod compile;
pub mod eval;
pub mod event;
pub mod model;
pub mod pins;
pub mod policy;

pub use compile::{CompileError, Compiled, NetEntry, SetEntry, Slot, Spec, compile};
pub use eval::{Decision, Flow, FlowVerdict, Reason, evaluate_ordered};
pub use model::{
    Action, Defaults, Direction, Endpoint, EndpointIndex, Family, ModelError, NamePattern, Origin,
    PortRange, Prefix, Protocol, Protocols, Rule, SetId, Target, Verdict,
};
