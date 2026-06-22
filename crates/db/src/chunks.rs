use crate::{DbPool, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Модели ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub file_id: String,
    pub name: String,
    pub size_bytes: i64,
    pub total_chunks: i64,
    pub owner_key: String,
    pub mime_type: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub hash: String,
    pub file_id: String,
    pub chunk_index: i64,
    pub size_bytes: i64,
    pub is_local: bool,
    pub local_path: Option<String>,
}

// ─── Files ────────────────────────────────────────────────────────────────────

/// Регистрирует метаданные файла в сети.
pub async fn insert_file(pool: &DbPool, file: &FileRecord) -> Result<()> {
    let created = file.created_at.to_rfc3339();
    sqlx::query!(
        r#"
        INSERT OR IGNORE INTO files
            (file_id, name, size_bytes, total_chunks, owner_key, mime_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
        file.file_id,
        file.name,
        file.size_bytes,
        file.total_chunks,
        file.owner_key,
        file.mime_type,
        created,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Возвращает метаданные файла.
pub async fn get_file(pool: &DbPool, file_id: &str) -> Result<Option<FileRecord>> {
    let row = sqlx::query!(
        r#"
        SELECT file_id as "file_id!", name, size_bytes, total_chunks, owner_key, mime_type, created_at
        FROM files WHERE file_id = ?
        "#,
        file_id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| FileRecord {
        file_id: r.file_id,
        name: r.name,
        size_bytes: r.size_bytes,
        total_chunks: r.total_chunks,
        owner_key: r.owner_key,
        mime_type: r.mime_type,
        created_at: r.created_at.parse().unwrap_or_else(|_| Utc::now()),
    }))
}

/// Список всех известных файлов.
pub async fn list_files(pool: &DbPool) -> Result<Vec<FileRecord>> {
    let rows = sqlx::query!(
        "SELECT file_id as \"file_id!\", name, size_bytes, total_chunks, owner_key, mime_type, created_at
         FROM files ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| FileRecord {
            file_id: r.file_id,
            name: r.name,
            size_bytes: r.size_bytes,
            total_chunks: r.total_chunks,
            owner_key: r.owner_key,
            mime_type: r.mime_type,
            created_at: r.created_at.parse().unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

// ─── Chunks ───────────────────────────────────────────────────────────────────

/// Добавляет или обновляет запись о чанке.
pub async fn upsert_chunk(pool: &DbPool, chunk: &Chunk) -> Result<()> {
    let is_local = chunk.is_local as i32;
    sqlx::query!(
        r#"
        INSERT INTO chunks (hash, file_id, chunk_index, size_bytes, is_local, local_path)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (hash) DO UPDATE SET
            is_local   = excluded.is_local,
            local_path = excluded.local_path
        "#,
        chunk.hash,
        chunk.file_id,
        chunk.chunk_index,
        chunk.size_bytes,
        is_local,
        chunk.local_path,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Возвращает все чанки файла, отсортированные по индексу.
pub async fn get_chunks_for_file(pool: &DbPool, file_id: &str) -> Result<Vec<Chunk>> {
    let rows = sqlx::query!(
        r#"
        SELECT hash as "hash!", file_id, chunk_index, size_bytes, is_local, local_path
        FROM chunks
        WHERE file_id = ?
        ORDER BY chunk_index ASC
        "#,
        file_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Chunk {
            hash: r.hash,
            file_id: r.file_id,
            chunk_index: r.chunk_index,
            size_bytes: r.size_bytes,
            is_local: r.is_local != 0,
            local_path: r.local_path,
        })
        .collect())
}

/// Только локально хранящиеся чанки (которые мы можем раздавать).
pub async fn get_local_chunks(pool: &DbPool) -> Result<Vec<Chunk>> {
    let rows = sqlx::query!(
        r#"
        SELECT hash as "hash!", file_id, chunk_index, size_bytes, is_local, local_path
        FROM chunks WHERE is_local = 1
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Chunk {
            hash: r.hash,
            file_id: r.file_id,
            chunk_index: r.chunk_index,
            size_bytes: r.size_bytes,
            is_local: true,
            local_path: r.local_path,
        })
        .collect())
}

// ─── Chunk owners ─────────────────────────────────────────────────────────────

/// Записывает, что узел `peer_key` владеет чанком `chunk_hash`.
pub async fn add_chunk_owner(
    pool: &DbPool,
    chunk_hash: &str,
    peer_key: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query!(
        r#"
        INSERT OR REPLACE INTO chunk_owners (chunk_hash, peer_key, verified_at)
        VALUES (?, ?, ?)
        "#,
        chunk_hash,
        peer_key,
        now,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Возвращает список публичных ключей узлов, у которых есть данный чанк.
pub async fn get_chunk_owners(pool: &DbPool, chunk_hash: &str) -> Result<Vec<String>> {
    let rows = sqlx::query!(
        "SELECT peer_key FROM chunk_owners WHERE chunk_hash = ?",
        chunk_hash,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.peer_key).collect())
}

/// Удаляет узел из владельцев всех чанков (например при бане или дисконнекте).
pub async fn remove_peer_chunks(pool: &DbPool, peer_key: &str) -> Result<()> {
    sqlx::query!(
        "DELETE FROM chunk_owners WHERE peer_key = ?",
        peer_key,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Полностью удаляет файл: его чанки (каскадом — и владельцев из `chunk_owners`)
/// и метаданные из `files`. Возвращает хэши чанков, которые были локальными —
/// чтобы вызывающий удалил блобы с диска.
///
/// Runtime-запросы (`sqlx::query`), а не макросы — чтобы не перегенерировать
/// offline-кэш `.sqlx` ради двух DELETE.
pub async fn delete_file(pool: &DbPool, file_id: &str) -> Result<Vec<String>> {
    let local: Vec<String> = get_chunks_for_file(pool, file_id)
        .await?
        .into_iter()
        .filter(|c| c.is_local)
        .map(|c| c.hash)
        .collect();

    sqlx::query("DELETE FROM chunks WHERE file_id = ?")
        .bind(file_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM files WHERE file_id = ?")
        .bind(file_id)
        .execute(pool)
        .await?;

    Ok(local)
}

/// Процент скачанности файла (сколько чанков уже локально).
pub async fn local_completion(pool: &DbPool, file_id: &str) -> Result<f64> {
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(is_local) as local_count
        FROM chunks
        WHERE file_id = ?
        "#,
        file_id,
    )
    .fetch_one(pool)
    .await?;

    let total = row.total as f64;
    if total == 0.0 {
        return Ok(0.0);
    }
    Ok(row.local_count.unwrap_or(0) as f64 / total)
}