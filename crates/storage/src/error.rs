use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Db(#[from] void_db::DbError),

    #[error("chunk integrity check failed: expected {expected}, got {actual}")]
    IntegrityFailure { expected: String, actual: String },

    #[error("file not found: {0}")]
    FileNotFound(String),

    #[error("chunk not found: {0}")]
    ChunkNotFound(String),

    #[error("no peers available for chunk: {0}")]
    NoPeersForChunk(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("transfer timeout for chunk: {0}")]
    Timeout(String),
}