use thiserror::Error;

#[derive(Debug, Error)]
pub enum VoidError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

pub type VoidResult<T> = Result<T, VoidError>;