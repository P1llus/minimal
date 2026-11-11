use std::io;

/// What can go wrong between this crate and the kernel or the loader.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("loading the policy programs failed: {0}")]
    Load(#[source] Box<aya::EbpfError>),
    #[error("policy program {name}: {source}")]
    Program {
        name: &'static str,
        #[source]
        source: Box<aya::programs::ProgramError>,
    },
    #[error("policy map {name}: {source}")]
    Map {
        name: &'static str,
        #[source]
        source: Box<aya::maps::MapError>,
    },
    #[error("the policy object has no {kind} named {name}")]
    Missing {
        kind: &'static str,
        name: &'static str,
    },
    #[error("{what}: {source}")]
    Sys {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Compile(#[from] netpol::CompileError),
    #[error("box id 0 is what the programs see outside any box and cannot be configured")]
    BoxIdZero,
    #[error("the engine holds no policy for this box")]
    UnknownBox,
    #[error("the policy needs {needed} rule entries, and a box may have {limit}")]
    RuleEntryLimit { needed: usize, limit: usize },
    #[error("the box has {limit} addresses pinned, the most a box may have")]
    PinLimit { limit: usize },
    #[error("no rule of the box names {0}")]
    NameWithoutRule(String),
    #[error("{0} map descriptors were handed over, {1} are needed")]
    HandleCount(usize, usize),
    /// The loader looked at the request and said no. The text is its reason.
    #[error("the policy loader refused: {0}")]
    Refused(String),
    #[error("the policy loader sent a reply this daemon cannot read: {0}")]
    Protocol(String),
    #[error(
        "the installed policy loader speaks ABI {loader}, this daemon speaks ABI {daemon}: run `min finalize-install` to update the loader"
    )]
    AbiMismatch { loader: u32, daemon: u32 },
    #[error(
        "the installed policy loader carries other policy programs than this daemon: run `min finalize-install` to update the loader"
    )]
    ObjectMismatch { loader: String, daemon: String },
    #[error(
        "the boxes cgroup already has policy programs attached: a daemon makes the cgroup anew when it starts"
    )]
    InUse,
    #[error("the policy loader took the programs off again: {0}")]
    Unconfirmed(String),
}

impl Error {
    pub(crate) fn sys(what: &'static str) -> impl FnOnce(io::Error) -> Self {
        move |source| Self::Sys { what, source }
    }

    pub(crate) fn map(name: &'static str) -> impl FnOnce(aya::maps::MapError) -> Self {
        move |source| Self::Map {
            name,
            source: Box::new(source),
        }
    }
}
