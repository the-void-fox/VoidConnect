pub mod chunks;
pub mod messages;
pub mod peers;
pub mod profiles;

use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::path::Path;

pub type DbPool = SqlitePool;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("not found")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, DbError>;

/// Открывает (или создаёт) базу данных по указанному пути и
/// прогоняет все pending-миграции.
pub async fn open(db_path: &Path) -> Result<DbPool> {
    // sqlx требует строку вида "sqlite:./path/to/db.sqlite"
    let url = format!("sqlite:{}", db_path.display());

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(
            url.parse::<sqlx::sqlite::SqliteConnectOptions>()
                .unwrap()
                .create_if_missing(true)
                // WAL уже задан в миграции, но дублируем на уровне соединения
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .foreign_keys(true),
        )
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}