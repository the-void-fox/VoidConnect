use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("mDNS error: {0}")]
    Mdns(String),

    #[error("UDP broadcast error: {0}")]
    Udp(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}