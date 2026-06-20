use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebError {
    #[error("storage error: {0}")]
    Storage(#[from] void_storage::StorageError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("site not found: {0}")]
    SiteNotFound(String),

    #[error("invalid site: {0}")]
    Invalid(String),
}
