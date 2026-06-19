use thiserror::Error;

use void_crypto::CryptoError;
use void_db::DbError;

#[derive(Debug, Error, Clone)]
pub enum ReputationError {
    /// Заглушка «всё хорошо» — используется в init() для упрощения API.
    #[error("ok")]
    Ok,

    #[error("database error: {0}")]
    Db(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("signature signer field does not match reporter node id")]
    SignerMismatch,

    #[error("cannot file a report against yourself")]
    SelfReport,

    #[error("deserialization error: {0}")]
    Deserialize(String),
}

impl From<DbError> for ReputationError {
    fn from(e: DbError) -> Self {
        ReputationError::Db(e.to_string())
    }
}

impl From<CryptoError> for ReputationError {
    fn from(e: CryptoError) -> Self {
        ReputationError::Crypto(e.to_string())
    }
}