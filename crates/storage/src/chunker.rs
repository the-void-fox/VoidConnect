//! Разбивка файлов на чанки и сборка обратно.
//!
//! Чанки — 256 КБ (последний может быть меньше).
//! Каждый чанк идентифицируется по SHA-256 хэшу своих данных.

use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::error::StorageError;
use crate::integrity::{compute_file_id, hash_chunk};

/// Размер одного чанка: 256 КБ
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Метаданные одного чанка (без самих байт)
#[derive(Debug, Clone)]
pub struct ChunkMeta {
    pub hash: String,
    pub index: u32,
    pub size: usize,
}

/// Результат разбивки файла
#[derive(Debug)]
pub struct SplitResult {
    pub file_id: String,
    pub file_name: String,
    pub total_size: u64,
    pub chunks: Vec<ChunkMeta>,
    /// Сырые данные каждого чанка (порядок совпадает с `chunks`)
    pub data: Vec<Vec<u8>>,
}

/// Разбивает файл на чанки.
///
/// Читает весь файл в память — подходит для файлов до ~1 ГБ.
/// Для очень больших файлов в будущем можно добавить потоковый вариант.
pub async fn split_file(path: &Path) -> Result<SplitResult, StorageError> {
    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    let total_size = metadata.len();

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut buffer = Vec::with_capacity(total_size as usize);
    file.read_to_end(&mut buffer).await?;

    let mut chunks = Vec::new();
    let mut data_chunks = Vec::new();

    for (index, raw_chunk) in buffer.chunks(CHUNK_SIZE).enumerate() {
        let hash = hash_chunk(raw_chunk);
        chunks.push(ChunkMeta {
            hash: hash.clone(),
            index: index as u32,
            size: raw_chunk.len(),
        });
        data_chunks.push(raw_chunk.to_vec());
        debug!("Chunk {}: {} bytes, hash={}", index, raw_chunk.len(), &hash[..8]);
    }

    let all_hashes: Vec<String> = chunks.iter().map(|c| c.hash.clone()).collect();
    let file_id = compute_file_id(&all_hashes);

    info!(
        "Split '{}': {} bytes → {} chunks, file_id={}",
        file_name,
        total_size,
        chunks.len(),
        &file_id[..8]
    );

    Ok(SplitResult {
        file_id,
        file_name,
        total_size,
        chunks,
        data: data_chunks,
    })
}

/// Собирает файл из чанков и записывает его на диск.
///
/// `ordered_chunks` — данные чанков, **отсортированные по chunk_index**.
/// `dest_path` — куда записать результат.
pub async fn assemble_file(
    ordered_chunks: &[Vec<u8>],
    dest_path: &Path,
) -> Result<u64, StorageError> {
    if let Some(parent) = dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = tokio::fs::File::create(dest_path).await?;
    let mut total = 0u64;

    for chunk_data in ordered_chunks {
        file.write_all(chunk_data).await?;
        total += chunk_data.len() as u64;
    }

    file.flush().await?;
    info!(
        "Assembled file at '{}': {} bytes",
        dest_path.display(),
        total
    );

    Ok(total)
}