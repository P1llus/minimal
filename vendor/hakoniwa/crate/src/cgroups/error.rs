pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Error type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    AnyManagerError(#[from] libcgroups::common::AnyManagerError),
    #[error(transparent)]
    CreateCgroupSetupError(#[from] libcgroups::common::CreateCgroupSetupError),
    #[error(transparent)]
    OciSpecError(#[from] oci_spec::OciSpecError),
}
