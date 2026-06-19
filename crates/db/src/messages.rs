use crate::{DbPool, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Модели ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicMessage {
    pub id: i64,
    pub message_id: String,   // UUID от отправителя
    pub sender_key: String,
    pub content: String,
    pub signature: String,
    pub sent_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateMessage {
    pub id: i64,
    pub message_id: String,
    pub peer_key: String,
    pub direction: Direction,
    pub encrypted_blob: Vec<u8>,
    pub sent_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub is_read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
    fn from_str(s: &str) -> Self {
        if s == "out" { Direction::Out } else { Direction::In }
    }
}

// ─── Public chat ──────────────────────────────────────────────────────────────

/// Сохраняет входящее/исходящее сообщение общего чата.
/// Игнорирует дубли (по message_id).
pub async fn save_public_message(
    pool: &DbPool,
    message_id: &str,
    sender_key: &str,
    content: &str,
    signature: &str,
    sent_at: DateTime<Utc>,
) -> Result<()> {
    let sent = sent_at.to_rfc3339();
    sqlx::query!(
        r#"
        INSERT OR IGNORE INTO public_messages
            (message_id, sender_key, content, signature, sent_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
        message_id,
        sender_key,
        content,
        signature,
        sent,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Возвращает последние `limit` сообщений общего чата (от новых к старым).
pub async fn get_public_history(pool: &DbPool, limit: i64) -> Result<Vec<PublicMessage>> {
    let rows = sqlx::query!(
        r#"
        SELECT id as "id!", message_id, sender_key, content, signature, sent_at, received_at
        FROM public_messages
        ORDER BY sent_at DESC
        LIMIT ?
        "#,
        limit,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PublicMessage {
            id: r.id,
            message_id: r.message_id,
            sender_key: r.sender_key,
            content: r.content,
            signature: r.signature,
            sent_at: r.sent_at.parse().unwrap_or_else(|_| Utc::now()),
            received_at: r.received_at.parse().unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

/// Проверяет, есть ли уже сообщение с данным ID (дедупликация при relay).
pub async fn public_message_exists(pool: &DbPool, message_id: &str) -> Result<bool> {
    let row = sqlx::query!(
        "SELECT COUNT(1) as cnt FROM public_messages WHERE message_id = ?",
        message_id,
    )
    .fetch_one(pool)
    .await?;

    Ok(row.cnt > 0)
}

// ─── Private chat ─────────────────────────────────────────────────────────────

/// Сохраняет зашифрованное личное сообщение.
pub async fn save_private_message(
    pool: &DbPool,
    message_id: &str,
    peer_key: &str,
    direction: Direction,
    encrypted_blob: &[u8],
    sent_at: DateTime<Utc>,
) -> Result<()> {
    let dir = direction.as_str();
    let sent = sent_at.to_rfc3339();

    sqlx::query!(
        r#"
        INSERT OR IGNORE INTO private_messages
            (message_id, peer_key, direction, encrypted_blob, sent_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
        message_id,
        peer_key,
        dir,
        encrypted_blob,
        sent,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Возвращает историю переписки с конкретным узлом, `limit` последних записей.
pub async fn get_private_history(
    pool: &DbPool,
    peer_key: &str,
    limit: i64,
) -> Result<Vec<PrivateMessage>> {
    let rows = sqlx::query!(
        r#"
        SELECT id as "id!", message_id, peer_key, direction, encrypted_blob,
               sent_at, received_at, is_read
        FROM private_messages
        WHERE peer_key = ?
        ORDER BY sent_at DESC
        LIMIT ?
        "#,
        peer_key,
        limit,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PrivateMessage {
            id: r.id,
            message_id: r.message_id,
            peer_key: r.peer_key,
            direction: Direction::from_str(&r.direction),
            encrypted_blob: r.encrypted_blob,
            sent_at: r.sent_at.parse().unwrap_or_else(|_| Utc::now()),
            received_at: r.received_at.parse().unwrap_or_else(|_| Utc::now()),
            is_read: r.is_read != 0,
        })
        .collect())
}

/// Помечает все непрочитанные сообщения от узла как прочитанные.
pub async fn mark_read(pool: &DbPool, peer_key: &str) -> Result<u64> {
    let affected = sqlx::query!(
        r#"
        UPDATE private_messages
        SET is_read = 1
        WHERE peer_key = ? AND direction = 'in' AND is_read = 0
        "#,
        peer_key,
    )
    .execute(pool)
    .await?
    .rows_affected();

    Ok(affected)
}

/// Количество непрочитанных входящих сообщений от узла.
pub async fn unread_count(pool: &DbPool, peer_key: &str) -> Result<i64> {
    let row = sqlx::query!(
        r#"
        SELECT COUNT(1) as "cnt: i64"
        FROM private_messages
        WHERE peer_key = ? AND direction = 'in' AND is_read = 0
        "#,
        peer_key,
    )
    .fetch_one(pool)
    .await?;

    Ok(row.cnt)
}