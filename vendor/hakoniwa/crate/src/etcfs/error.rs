pub(crate) type Result<T> = std::result::Result<T, Error>;

#[allow(clippy::enum_variant_names)]
#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("parse line `{line}..` failed: {errmsg}")]
    InvalidLine { line: String, errmsg: String },
    #[error("not enough parts")]
    NotEnoughParts,
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),
    #[error(transparent)]
    StdNumParseIntError(#[from] std::num::ParseIntError),
}
