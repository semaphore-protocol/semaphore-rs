//! Error Module

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SemaphoreError {
    #[error("Input array of size {0} exceeds maximum allowed length of 32 bytes")]
    InputSizeExceeded(usize),
    #[error("Public key validation failed: point is not on curve")]
    PublicKeyNotOnCurve,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Message of size {0} exceeds maximum allowed length of 32 bytes")]
    MessageSizeExceeded(usize),
    #[error("Signature point R is not on curve")]
    SignaturePointNotOnCurve,
}
