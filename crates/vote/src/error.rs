use thiserror::Error;

#[derive(Debug, Error)]
pub enum VoteError {
    #[error("crypto error: {0}")]
    Crypto(#[from] void_crypto::error::CryptoError),

    #[error("db error: {0}")]
    Db(#[from] void_db::DbError),

    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("serialize/deserialize error: {0}")]
    Serde(String),

    /// signed.signer не совпадает с заявленным автором/голосующим.
    #[error("signer mismatch")]
    SignerMismatch,

    /// proposal_id в голосе не совпал с пересчитанным из предложения.
    #[error("proposal id mismatch")]
    ProposalIdMismatch,
}
