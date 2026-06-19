use crate::{DbPool, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Модели ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub public_key: String,
    pub username: Option<String>,
    pub avatar_url: Option<String>,
    pub status_text: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<i64>,
    pub is_bootstrap: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reputation {
    pub public_key: String,
    pub score: f64,
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub valid_chunks_sent: i64,
    pub bad_chunks_sent: i64,
    pub spam_strikes: i64,
    pub uptime_seconds: i64,
    pub bootstrap_bonus: f64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationReport {
    pub id: i64,
    pub target_key: String,
    pub reporter_key: String,
    pub reason: String,
    pub signature: String,
    pub created_at: DateTime<Utc>,
}

// ─── Peers ────────────────────────────────────────────────────────────────────

/// Добавляет или обновляет известный узел (upsert).
pub async fn upsert_peer(pool: &DbPool, peer: &Peer) -> Result<()> {
    let is_bootstrap = peer.is_bootstrap as i32;
    let last_seen = peer.last_seen_at.map(|d| d.to_rfc3339());

    sqlx::query!(
        r#"
        INSERT INTO peers (public_key, username, avatar_url, status_text,
                           ip_address, port, is_bootstrap, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (public_key) DO UPDATE SET
            username     = COALESCE(excluded.username, username),
            avatar_url   = COALESCE(excluded.avatar_url, avatar_url),
            status_text  = COALESCE(excluded.status_text, status_text),
            ip_address   = COALESCE(excluded.ip_address, ip_address),
            port         = COALESCE(excluded.port, port),
            is_bootstrap = excluded.is_bootstrap,
            last_seen_at = excluded.last_seen_at
        "#,
        peer.public_key,
        peer.username,
        peer.avatar_url,
        peer.status_text,
        peer.ip_address,
        peer.port,
        is_bootstrap,
        last_seen,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Возвращает узел по публичному ключу.
pub async fn get_peer(pool: &DbPool, public_key: &str) -> Result<Option<Peer>> {
    let row = sqlx::query!(
        r#"
        SELECT public_key as "public_key!", username, avatar_url, status_text,
               ip_address, port, is_bootstrap, last_seen_at, first_seen_at
        FROM peers
        WHERE public_key = ?
        "#,
        public_key,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| Peer {
        public_key: r.public_key,
        username: r.username,
        avatar_url: r.avatar_url,
        status_text: r.status_text,
        ip_address: r.ip_address,
        port: r.port,
        is_bootstrap: r.is_bootstrap != 0,
        last_seen_at: r.last_seen_at.as_deref().and_then(|s| s.parse().ok()),
        first_seen_at: r.first_seen_at.parse().unwrap_or_else(|_| Utc::now()),
    }))
}

/// Возвращает всех известных узлов, отсортированных по last_seen DESC.
pub async fn list_peers(pool: &DbPool) -> Result<Vec<Peer>> {
    let rows = sqlx::query!(
        r#"
        SELECT public_key as "public_key!", username, avatar_url, status_text,
               ip_address, port, is_bootstrap, last_seen_at, first_seen_at
        FROM peers
        ORDER BY last_seen_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Peer {
            public_key: r.public_key,
            username: r.username,
            avatar_url: r.avatar_url,
            status_text: r.status_text,
            ip_address: r.ip_address,
            port: r.port,
            is_bootstrap: r.is_bootstrap != 0,
            last_seen_at: r.last_seen_at.as_deref().and_then(|s| s.parse().ok()),
            first_seen_at: r.first_seen_at.parse().unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

/// Возвращает только bootstrap-узлы.
pub async fn list_bootstrap_peers(pool: &DbPool) -> Result<Vec<Peer>> {
    let rows = sqlx::query!(
        r#"
        SELECT public_key as "public_key!", username, avatar_url, status_text,
               ip_address, port, is_bootstrap, last_seen_at, first_seen_at
        FROM peers
        WHERE is_bootstrap = 1
        ORDER BY last_seen_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Peer {
            public_key: r.public_key,
            username: r.username,
            avatar_url: r.avatar_url,
            status_text: r.status_text,
            ip_address: r.ip_address,
            port: r.port,
            is_bootstrap: true,
            last_seen_at: r.last_seen_at.as_deref().and_then(|s| s.parse().ok()),
            first_seen_at: r.first_seen_at.parse().unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

/// Обновляет last_seen_at узла до текущего момента.
pub async fn touch_peer(pool: &DbPool, public_key: &str) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE peers
        SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE public_key = ?
        "#,
        public_key,
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ─── Reputation ───────────────────────────────────────────────────────────────

/// Возвращает репутацию узла. Если записи нет — возвращает None.
pub async fn get_reputation(pool: &DbPool, public_key: &str) -> Result<Option<Reputation>> {
    let row = sqlx::query!(
        r#"
        SELECT public_key as "public_key!", score, upload_bytes, download_bytes,
               valid_chunks_sent, bad_chunks_sent, spam_strikes,
               uptime_seconds, bootstrap_bonus, updated_at
        FROM reputation
        WHERE public_key = ?
        "#,
        public_key,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| Reputation {
        public_key: r.public_key,
        score: r.score,
        upload_bytes: r.upload_bytes,
        download_bytes: r.download_bytes,
        valid_chunks_sent: r.valid_chunks_sent,
        bad_chunks_sent: r.bad_chunks_sent,
        spam_strikes: r.spam_strikes,
        uptime_seconds: r.uptime_seconds,
        bootstrap_bonus: r.bootstrap_bonus,
        updated_at: r.updated_at.parse().unwrap_or_else(|_| Utc::now()),
    }))
}

/// Инициализирует запись репутации для нового узла (score = 0).
pub async fn init_reputation(pool: &DbPool, public_key: &str) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT OR IGNORE INTO reputation (public_key)
        VALUES (?)
        "#,
        public_key,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Применяет дельту к полям репутации и пересчитывает итоговый score.
/// Передавай только те поля, которые изменились (остальные = 0).
pub async fn apply_reputation_delta(
    pool: &DbPool,
    public_key: &str,
    delta: ReputationDelta,
) -> Result<()> {
    sqlx::query!(
        r#"
        UPDATE reputation
        SET
            upload_bytes      = upload_bytes      + ?,
            download_bytes    = download_bytes    + ?,
            valid_chunks_sent = valid_chunks_sent + ?,
            bad_chunks_sent   = bad_chunks_sent   + ?,
            spam_strikes      = spam_strikes      + ?,
            uptime_seconds    = uptime_seconds    + ?,
            bootstrap_bonus   = bootstrap_bonus   + ?,
            -- упрощённая формула score; пересчитай в reputation::score.rs при желании
            score = score
                + (? * 0.01)          -- upload ratio
                - (? * 0.5)           -- bad chunks penalty
                - (? * 1.0)           -- spam penalty
                + (? * 0.001)         -- uptime bonus
                + ?,                  -- bootstrap bonus
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE public_key = ?
        "#,
        delta.upload_bytes,
        delta.download_bytes,
        delta.valid_chunks_sent,
        delta.bad_chunks_sent,
        delta.spam_strikes,
        delta.uptime_seconds,
        delta.bootstrap_bonus,
        // score formula args:
        delta.upload_bytes,
        delta.bad_chunks_sent,
        delta.spam_strikes,
        delta.uptime_seconds,
        delta.bootstrap_bonus,
        public_key,
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct ReputationDelta {
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub valid_chunks_sent: i64,
    pub bad_chunks_sent: i64,
    pub spam_strikes: i64,
    pub uptime_seconds: i64,
    pub bootstrap_bonus: f64,
}

// ─── Reports ──────────────────────────────────────────────────────────────────

/// Сохраняет жалобу на узел.
pub async fn add_report(
    pool: &DbPool,
    target_key: &str,
    reporter_key: &str,
    reason: &str,
    signature: &str,
) -> Result<i64> {
    let id = sqlx::query!(
        r#"
        INSERT INTO reputation_reports (target_key, reporter_key, reason, signature)
        VALUES (?, ?, ?, ?)
        "#,
        target_key,
        reporter_key,
        reason,
        signature,
    )
    .execute(pool)
    .await?
    .last_insert_rowid();

    Ok(id)
}

/// Считает количество уникальных жалоб на узел.
pub async fn count_reports(pool: &DbPool, target_key: &str) -> Result<i64> {
    let row = sqlx::query!(
        r#"
        SELECT COUNT(DISTINCT reporter_key) as "cnt: i64"
        FROM reputation_reports
        WHERE target_key = ?
        "#,
        target_key,
    )
    .fetch_one(pool)
    .await?;

    Ok(row.cnt)
}