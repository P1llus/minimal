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
    #[error("not supported: {0}")]
    NotSupported(&'static str),
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
