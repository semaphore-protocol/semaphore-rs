//! Error Module

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SemaphoreError {
    #[error("Array too long")]
    ArrayTooLong,
    #[error("Field element conversion error")]
    FieldConversionError,
    #[error("Hex decoding error: {0}")]
    HexDecodingError(String),
    #[error("Invalid field element format: {0}")]
    InvalidFieldFormat(String),
    #[error("Invalid field element length: got {actual}, expected {expected}")]
    InvalidFieldLength { actual: usize, expected: usize },
    #[error("Public key is not on curve")]
    InvalidPublicKey,
    #[error("Signature is invalid")]
    InvalidSignature,
    #[error("Leaf index is greater than the tree size")]
    LeafIndexGreaterThanTreeSize,
    #[error("Message should be less than 32 bytes")]
    MessageTooLong,
    #[error("Private key import error: {0}")]
    PrivateKeyImportError(String),
    #[error("Signature is not on curve")]
    SignatureNotOnCurve,
}
