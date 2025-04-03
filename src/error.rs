//! Error Module

use thiserror::Error;
use zk_kit_lean_imt::lean_imt::LeanIMTError;

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
}

impl From<LeanIMTError> for SemaphoreError {
    fn from(error: LeanIMTError) -> Self {
        SemaphoreError::LeanIMTError(error)
    }
}
