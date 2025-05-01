//! Error Module

use lean_imt::lean_imt::LeanIMTError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SemaphoreError {
    #[error("Member already removed")]
    AlreadyRemovedMember,
    #[error("Member value is empty")]
    EmptyLeaf,
    #[error("Input array of size {0} exceeds maximum allowed length of 32 bytes")]
    InputSizeExceeded(usize),
    #[error("LeanIMT error: {0}")]
    LeanIMTError(LeanIMTError),
    #[error("Message of size {0} exceeds maximum allowed length of 32 bytes")]
    MessageSizeExceeded(usize),
    #[error("Public key validation failed: point is not on curve")]
    PublicKeyNotOnCurve,
    #[error("Member has been removed")]
    RemovedMember,
    #[error("Signature point R is not on curve")]
    SignaturePointNotOnCurve,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<LeanIMTError> for SemaphoreError {
    fn from(error: LeanIMTError) -> Self {
        SemaphoreError::LeanIMTError(error)
    }
}
