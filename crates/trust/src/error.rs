use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    /// Запись не прошла проверку (подпись, формат, поручитель ≠ подписант…).
    #[error("invalid vouch: {0}")]
    Invalid(String),

    #[error("database error: {0}")]
    Db(String),
}

impl From<sqlx::Error> for TrustError {
    fn from(e: sqlx::Error) -> Self {
        TrustError::Db(e.to_string())
    }
}
