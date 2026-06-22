//! Локальное хранилище чанков на диске.
//!
//! Чанки кладутся в плоскую директорию:
//!   <storage_dir>/<первые 2 символа хэша>/<полный хэш>.chunk
//!
//! Двухуровневая структура (аналог git objects) предотвращает
//! появление тысяч файлов в одной директории.

use std::path::{Path, PathBuf};
use tracing::debug;

use crate::error::StorageError;
use crate::integrity::verify_chunk;

#[derive(Debug, Clone)]
pub struct ChunkStore {
    base_dir: PathBuf,
}

impl ChunkStore {
    /// Создаёт хранилище, при необходимости создаёт директорию.
    pub async fn new(base_dir: PathBuf) -> Result<Self, StorageError> {
        tokio::fs::create_dir_all(&base_dir).await?;
        Ok(ChunkStore { base_dir })
    }

    /// Путь к файлу чанка на диске.
    pub fn chunk_path(&self, hash: &str) -> PathBuf {
        let prefix = &hash[..2.min(hash.len())];
        self.base_dir.join(prefix).join(format!("{}.chunk", hash))
    }

    /// Сохраняет чанк на диск. Перед записью верифицирует хэш.
    ///
    /// Если чанк уже существует — пропускает (idempotent).
    pub async fn put(&self, hash: &str, data: &[u8]) -> Result<(), StorageError> {
        verify_chunk(hash, data)?;

        let path = self.chunk_path(hash);

        // Уже есть — ничего не делаем
        if path.exists() {
            debug!("Chunk {} already stored, skipping", &hash[..8]);
            return Ok(());
        }

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::write(&path, data).await?;
        debug!("Stored chunk {} ({} bytes)", &hash[..8], data.len());
        Ok(())
    }

    /// Читает чанк с диска. Верифицирует хэш после чтения.
    pub async fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.chunk_path(hash);
        if !path.exists() {
            return Err(StorageError::ChunkNotFound(hash.to_string()));
        }

        let data = tokio::fs::read(&path).await?;
        verify_chunk(hash, &data)?;
        Ok(data)
    }

    /// Проверяет наличие чанка на диске (без чтения).
    pub fn has(&self, hash: &str) -> bool {
        self.chunk_path(hash).exists()
    }

    /// Удаляет чанк с диска.
    pub async fn delete(&self, hash: &str) -> Result<(), StorageError> {
        let path = self.chunk_path(hash);
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
            debug!("Deleted chunk {}", &hash[..8]);
        }
        Ok(())
    }

    /// Возвращает список хэшей всех локально хранящихся чанков.
    /// Обходит двухуровневое дерево директорий.
    pub async fn list_all(&self) -> Result<Vec<String>, StorageError> {
        let mut hashes = Vec::new();
        let mut dir = tokio::fs::read_dir(&self.base_dir).await?;

        while let Some(prefix_entry) = dir.next_entry().await? {
            if !prefix_entry.file_type().await?.is_dir() {
                continue;
            }
            let mut sub = tokio::fs::read_dir(prefix_entry.path()).await?;
            while let Some(chunk_entry) = sub.next_entry().await? {
                let name = chunk_entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.ends_with(".chunk") {
                    let hash = name_str.trim_end_matches(".chunk").to_string();
                    hashes.push(hash);
                }
            }
        }

        Ok(hashes)
    }

    /// Путь к базовой директории (нужен db-слою для local_path).
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}