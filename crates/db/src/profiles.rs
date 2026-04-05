use crate::{DbError, DbPool, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProfile {
    pub public_key: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub status_text: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Возвращает профиль локального пользователя, если он уже создан.
pub async fn get(pool: &DbPool) -> Result<Option<LocalProfile>> {
    let row = sqlx::query!(
        r#"
        SELECT public_key, username, avatar_url, status_text, created_at
        FROM local_profile
        WHERE id = 1
        "#
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| LocalProfile {
        public_key: r.public_key,
        username: r.username,
        avatar_url: r.avatar_url,
        status_text: r.status_text,
        created_at: r
            .created_at
            .parse()
            .unwrap_or_else(|_| Utc::now()),
    }))
}

/// Создаёт профиль при первом запуске.
/// Вызывать только один раз — синглтон (id = 1).
pub async fn create(
    pool: &DbPool,
    public_key: &str,
    username: &str,
) -> Result<LocalProfile> {
    sqlx::query!(
        r#"
        INSERT INTO local_profile (id, public_key, username)
        VALUES (1, ?, ?)
        "#,
        public_key,
        username,
    )
    .execute(pool)
    .await?;

    get(pool).await?.ok_or(DbError::NotFound)
}

/// Обновляет редактируемые поля профиля.
pub async fn update(
    pool: &DbPool,
    username: Option<&str>,
    avatar_url: Option<&str>,
    status_text: Option<&str>,
) -> Result<()> {
    // Обновляем только переданные поля через COALESCE
    sqlx::query!(
        r#"
        UPDATE local_profile
        SET
            username    = COALESCE(?, username),
            avatar_url  = COALESCE(?, avatar_url),
            status_text = COALESCE(?, status_text)
        WHERE id = 1
        "#,
        username,
        avatar_url,
        status_text,
    )
    .execute(pool)
    .await?;

    Ok(())
}