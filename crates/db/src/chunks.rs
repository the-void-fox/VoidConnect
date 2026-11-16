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

/// Строка чанка из рантайм-запроса.
fn chunk_from_row(r: sqlx::sqlite::SqliteRow) -> Chunk {
    use sqlx::Row;
    Chunk {
        hash: r.get("hash"),
        file_id: r.get("file_id"),
        chunk_index: r.get("chunk_index"),
        size_bytes: r.get("size_bytes"),
        is_local: r.get::<i64, _>("is_local") != 0,
        local_path: r.get("local_path"),
    }
}

/// Добавляет или обновляет запись о чанке — место `(file_id, chunk_index)`.
/// Флаг «есть локально» только поднимается: повторное объявление файла из сети
/// (`is_local = false`) не забудет уже скачанный чанк.
///
/// Рантайм-запросы во всём разделе: схема чанков поменялась в миграции 0006, а
/// `query!`-макросы потребовали бы перегенерации офлайн-кэша `.sqlx`.
pub async fn upsert_chunk(pool: &DbPool, chunk: &Chunk) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO chunks (file_id, chunk_index, hash, size_bytes, is_local, local_path)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT (file_id, chunk_index) DO UPDATE SET
            hash       = excluded.hash,
            size_bytes = excluded.size_bytes,
            is_local   = MAX(chunks.is_local, excluded.is_local),
            local_path = COALESCE(excluded.local_path, chunks.local_path)
        "#,
    )
    .bind(&chunk.file_id)
    .bind(chunk.chunk_index)
    .bind(&chunk.hash)
    .bind(chunk.size_bytes)
    .bind(chunk.is_local as i64)
    .bind(&chunk.local_path)
    .execute(pool)
    .await?;
    Ok(())
}

/// Блоб чанка `hash` появился на диске: он общий для всех файлов, где стоит
/// этот хэш, — помечаем все такие места.
pub async fn mark_local(pool: &DbPool, hash: &str, local_path: &str) -> Result<()> {
    sqlx::query("UPDATE chunks SET is_local = 1, local_path = ? WHERE hash = ?")
        .bind(local_path)
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Возвращает все чанки файла, отсортированные по индексу.
pub async fn get_chunks_for_file(pool: &DbPool, file_id: &str) -> Result<Vec<Chunk>> {
    let rows = sqlx::query(
        "SELECT hash, file_id, chunk_index, size_bytes, is_local, local_path
         FROM chunks WHERE file_id = ? ORDER BY chunk_index ASC",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(chunk_from_row).collect())
}

/// Только локально хранящиеся чанки (которые мы можем раздавать).
pub async fn get_local_chunks(pool: &DbPool) -> Result<Vec<Chunk>> {
    let rows = sqlx::query(
        "SELECT hash, file_id, chunk_index, size_bytes, is_local, local_path
         FROM chunks WHERE is_local = 1",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(chunk_from_row).collect())
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

/// Все записи «чанк → владелец» (для загрузки индекса при запуске). Рантайм-
/// запрос (без `query!`-макроса, чтобы не перегенерировать `.sqlx`-кэш).
pub async fn get_all_chunk_owners(pool: &DbPool) -> Result<Vec<(String, String)>> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT chunk_hash, peer_key FROM chunk_owners")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get::<String, _>("chunk_hash"), r.get::<String, _>("peer_key")))
        .collect())
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

/// Полностью удаляет файл: его чанки и метаданные. Возвращает хэши локальных
/// блобов, которые больше не нужны ни одному файлу, — их вызывающий стирает с
/// диска (блоб общий: тот же блок может стоять и в другом файле).
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
    sqlx::query("DELETE FROM file_signatures WHERE file_id = ?")
        .bind(file_id)
        .execute(pool)
        .await?;
    // Владельцы чанков, которых не осталось ни в одном файле.
    sqlx::query("DELETE FROM chunk_owners WHERE chunk_hash NOT IN (SELECT hash FROM chunks)")
        .execute(pool)
        .await?;

    let mut orphaned = Vec::new();
    for hash in local {
        let still_used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chunks WHERE hash = ?")
            .bind(&hash)
            .fetch_one(pool)
            .await?;
        if still_used == 0 && !orphaned.contains(&hash) {
            orphaned.push(hash);
        }
    }
    Ok(orphaned)
}

/// Сохраняет подпись публикатора манифеста. Первая принятая подпись остаётся
/// (`INSERT OR IGNORE`): тот же контент (`file_id`), опубликованный другим
/// узлом позже, не перепишет уже известного публикатора.
pub async fn save_file_signature(
    pool: &DbPool,
    file_id: &str,
    publisher: &str,
    signature: &str,
) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO file_signatures (file_id, publisher, signature) VALUES (?, ?, ?)")
        .bind(file_id)
        .bind(publisher)
        .bind(signature)
        .execute(pool)
        .await?;
    Ok(())
}

/// Подпись публикатора манифеста: `(publisher, signature)`, если известна.
pub async fn get_file_signature(pool: &DbPool, file_id: &str) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT publisher, signature FROM file_signatures WHERE file_id = ?")
            .bind(file_id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// Процент скачанности файла (сколько чанков уже локально).
pub async fn local_completion(pool: &DbPool, file_id: &str) -> Result<f64> {
    let (total, local): (i64, Option<i64>) =
        sqlx::query_as("SELECT COUNT(*), SUM(is_local) FROM chunks WHERE file_id = ?")
            .bind(file_id)
            .fetch_one(pool)
            .await?;
    if total == 0 {
        return Ok(0.0);
    }
    Ok(local.unwrap_or(0) as f64 / total as f64)
}
