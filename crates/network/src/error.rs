use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Bind error: {0}")]
    Bind(String),

    #[error("Disconnected")]
    Disconnected,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Rate limit exceeded")]
    RateLimited,
}