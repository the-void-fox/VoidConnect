/// error.rs — единый тип ошибок крейта void-crypto.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Machine fingerprint error: {0}")]
    MachineFingerprint(String),

    #[error("Key generation error: {0}")]
    KeyGeneration(String),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption failed")]
    Decryption,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}
