//! `StorageManager` — главный фасад модуля хранилища.
//!
//! Использование:
//! ```ignore
//! let manager = StorageManager::new(pool, chunk_store, peer_list, my_id).await?;
//! manager.start_server(storage_port).await;
//!
//! // Опубликовать файл
//! let file_id = manager.publish_file(Path::new("/tmp/photo.jpg")).await?;
//!
//! // Скачать файл
//! manager.download_file(&file_id, Path::new("/tmp/output/photo.jpg")).await?;
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use tracing::{error, info, warn};
use void_core::identity::NodeId;
use void_core::peer::PeerInfo;
use void_db::chunks as db_chunks;
use void_db::DbPool;

use crate::chunk_store::ChunkStore;
use crate::chunker::{split_file, assemble_file};
use crate::error::StorageError;
use crate::index::ChunkIndex;
use crate::integrity::verify_chunk;
use crate::transfer::{fetch_chunk_from_peer, run_chunk_server};

/// Параллельность при скачивании (одновременно N чанков)
const DOWNLOAD_CONCURRENCY: usize = 4;

#[derive(Clone)]
pub struct StorageManager {
    pool: DbPool,
    store: ChunkStore,
    index: ChunkIndex,
    my_id: NodeId,
}

impl StorageManager {
    /// Создаёт менеджер и загружает индекс чанков из БД.
    pub async fn new(
        pool: DbPool,
        store: ChunkStore,
        my_id: NodeId,
    ) -> Result<Self, StorageError> {
        let index = ChunkIndex::new();

        // Загружаем в индекс наши собственные чанки из БД
        let local_chunks = db_chunks::get_local_chunks(&pool).await?;
        let entries: Vec<(String, NodeId)> = local_chunks
            .iter()
            .map(|c| (c.hash.clone(), my_id.clone()))
            .collect();
        index.bulk_load(entries).await;

        info!(
            "StorageManager ready: {} local chunks loaded",
            local_chunks.len()
        );

        Ok(StorageManager {
            pool,
            store,
            index,
            my_id,
        })
    }

    /// Запускает TCP chunk-сервер.
    /// Вызывай через `tokio::spawn` — блокирует задачу.
    pub async fn start_server(&self, port: u16) -> Result<(), StorageError> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()
            .map_err(|e: std::net::AddrParseError| StorageError::Network(e.to_string()))?;
        run_chunk_server(addr, self.store.clone()).await
    }

    // ─── Публикация ──────────────────────────────────────────────────────────

    /// Разбивает файл на чанки, сохраняет локально и регистрирует в БД.
    ///
    /// Возвращает `file_id` — SHA-256 от манифеста чанков.
    pub async fn publish_file(&self, path: &Path) -> Result<String, StorageError> {
        let result = split_file(path).await?;
        let file_id = result.file_id.clone();

        // Регистрируем метаданные файла
        let file_record = void_db::chunks::FileRecord {
            file_id: file_id.clone(),
            name: result.file_name.clone(),
            size_bytes: result.total_size as i64,
            total_chunks: result.chunks.len() as i64,
            owner_key: self.my_id.as_str().to_string(),
            mime_type: mime_type_from_name(&result.file_name),
            created_at: chrono::Utc::now(),
        };
        db_chunks::insert_file(&self.pool, &file_record).await?;

        // Сохраняем каждый чанк
        for (meta, data) in result.chunks.iter().zip(result.data.iter()) {
            self.store.put(&meta.hash, data).await?;

            let chunk_record = void_db::chunks::Chunk {
                hash: meta.hash.clone(),
                file_id: file_id.clone(),
                chunk_index: meta.index as i64,
                size_bytes: meta.size as i64,
                is_local: true,
                local_path: Some(
                    self.store.chunk_path(&meta.hash)
                        .to_string_lossy()
                        .to_string()
                ),
            };
            db_chunks::upsert_chunk(&self.pool, &chunk_record).await?;
            db_chunks::add_chunk_owner(&self.pool, &meta.hash, self.my_id.as_str()).await?;
            self.index.add_owner(&meta.hash, self.my_id.clone()).await;
        }

        info!(
            "Published '{}': file_id={}, {} chunks",
            result.file_name,
            &file_id[..8],
            result.chunks.len()
        );

        Ok(file_id)
    }

    // ─── Скачивание ──────────────────────────────────────────────────────────

    /// Скачивает файл из сети и сохраняет по `dest_path`.
    ///
    /// Алгоритм:
    /// 1. Берём список чанков файла из БД
    /// 2. Для каждого чанка ищем владельцев в индексе
    /// 3. Качаем параллельно (до DOWNLOAD_CONCURRENCY за раз)
    /// 4. Собираем файл из чанков
    pub async fn download_file(
        &self,
        file_id: &str,
        dest_path: &Path,
        peers: &[PeerInfo],
    ) -> Result<(), StorageError> {
        let file_meta = db_chunks::get_file(&self.pool, file_id)
            .await?
            .ok_or_else(|| StorageError::FileNotFound(file_id.to_string()))?;

        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        let total = chunks.len();
        info!(
            "Downloading '{}' ({} chunks)...",
            file_meta.name, total
        );

        // Скачиваем параллельно батчами
        let mut ordered_data: Vec<Option<Vec<u8>>> = vec![None; total];

        for batch in chunks.chunks(DOWNLOAD_CONCURRENCY) {
            let mut handles = Vec::new();

            for chunk in batch {
                // Если уже есть локально — читаем с диска
                if chunk.is_local {
                    let data = self.store.get(&chunk.hash).await?;
                    ordered_data[chunk.chunk_index as usize] = Some(data);
                    continue;
                }

                let owners = self.index.get_owners(&chunk.hash).await;
                if owners.is_empty() {
                    warn!("No peers for chunk {}", &chunk.hash[..8]);
                    return Err(StorageError::NoPeersForChunk(chunk.hash.clone()));
                }

                let chunk_hash = chunk.hash.clone();
                let chunk_index = chunk.chunk_index as usize;
                let my_id = self.my_id.clone();
                let peers = peers.to_vec();
                let owners_clone = owners.clone();
                let pool = self.pool.clone();
                let store = self.store.clone();

                handles.push(tokio::spawn(async move {
                    fetch_chunk_with_fallback(
                        &chunk_hash,
                        chunk_index,
                        &owners_clone,
                        &peers,
                        &my_id,
                        &store,
                        &pool,
                    )
                    .await
                }));
            }

            for handle in handles {
                match handle.await {
                    Ok(Ok((index, data))) => {
                        ordered_data[index] = Some(data);
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(e) => {
                        return Err(StorageError::Network(format!("task panic: {}", e)));
                    }
                }
            }
        }

        // Все чанки получены — собираем файл
        let flat: Vec<Vec<u8>> = ordered_data
            .into_iter()
            .enumerate()
            .map(|(i, opt)| opt.unwrap_or_else(|| {
                error!("BUG: chunk {} missing after download loop", i);
                Vec::new()
            }))
            .collect();

        assemble_file(&flat, dest_path).await?;
        info!("Downloaded '{}' → {}", file_meta.name, dest_path.display());
        Ok(())
    }

    // ─── Объявления о чанках ─────────────────────────────────────────────────

    /// Обрабатывает входящее объявление от узла: "у меня есть эти чанки".
    ///
    /// Обновляет in-memory индекс и БД.
    pub async fn handle_announce(
        &self,
        peer_id: &NodeId,
        chunk_hashes: Vec<String>,
    ) {
        for hash in &chunk_hashes {
            self.index.add_owner(hash, peer_id.clone()).await;
            if let Err(e) = db_chunks::add_chunk_owner(
                &self.pool,
                hash,
                peer_id.as_str(),
            ).await {
                warn!("Failed to persist chunk owner {}: {}", &hash[..8], e);
            }
        }
        if !chunk_hashes.is_empty() {
            info!(
                "Peer {} announced {} chunks",
                peer_id,
                chunk_hashes.len()
            );
        }
    }

    /// Возвращает список хэшей всех наших локальных чанков
    /// (для отправки объявлений другим узлам).
    pub async fn local_chunk_hashes(&self) -> Result<Vec<String>, StorageError> {
        Ok(self.store.list_all().await?)
    }

    /// Регистрирует факт отключения узла — убирает его из индекса.
    pub async fn on_peer_disconnected(&self, peer_id: &NodeId) {
        self.index.remove_peer(peer_id).await;
        if let Err(e) = void_db::chunks::remove_peer_chunks(
            &self.pool,
            peer_id.as_str(),
        ).await {
            warn!("Failed to remove peer chunks from db: {}", e);
        }
    }

    /// Возвращает процент скачанности файла (0.0 – 1.0).
    pub async fn download_progress(&self, file_id: &str) -> Result<f64, StorageError> {
        Ok(db_chunks::local_completion(&self.pool, file_id).await?)
    }
}

// ─── Вспомогательные функции ─────────────────────────────────────────────────

/// Скачивает чанк, перебирая владельцев по очереди.
/// При успехе — сохраняет локально и обновляет БД.
async fn fetch_chunk_with_fallback(
    hash: &str,
    index: usize,
    owners: &[NodeId],
    peers: &[PeerInfo],
    my_id: &NodeId,
    store: &ChunkStore,
    pool: &DbPool,
) -> Result<(usize, Vec<u8>), StorageError> {
    for owner_id in owners {
        // Найдём IP:port этого узла в списке активных пиров
        let peer_info = peers.iter().find(|p| &p.id == owner_id);
        let addr = match peer_info {
            Some(p) => SocketAddr::new(p.ip, p.port),
            None => {
                warn!("Owner {} not in active peer list, skipping", owner_id);
                continue;
            }
        };

        match fetch_chunk_from_peer(addr, hash, my_id).await {
            Ok(data) => {
                // Сохраняем локально
                if let Err(e) = store.put(hash, &data).await {
                    warn!("Failed to store chunk {}: {}", &hash[..8], e);
                }

                // Обновляем БД
                let record = void_db::chunks::Chunk {
                    hash: hash.to_string(),
                    file_id: String::new(), // file_id неизвестен здесь, обновится через upsert
                    chunk_index: index as i64,
                    size_bytes: data.len() as i64,
                    is_local: true,
                    local_path: Some(
                        store.chunk_path(hash).to_string_lossy().to_string()
                    ),
                };
                // Только обновляем is_local и local_path для существующей записи
                let _ = db_chunks::upsert_chunk(pool, &record).await;

                return Ok((index, data));
            }
            Err(StorageError::IntegrityFailure { expected, actual }) => {
                // Плохой чанк — логируем, продолжаем к следующему узлу
                warn!(
                    "Integrity failure from {}: chunk {}, expected {}, got {}",
                    owner_id,
                    &hash[..8],
                    &expected[..8],
                    &actual[..8]
                );
                // TODO: передать штраф репутации через канал events
                continue;
            }
            Err(e) => {
                warn!("Failed to fetch chunk {} from {}: {}", &hash[..8], owner_id, e);
                continue;
            }
        }
    }

    Err(StorageError::NoPeersForChunk(hash.to_string()))
}

/// Простое определение MIME типа по расширению файла.
fn mime_type_from_name(name: &str) -> Option<String> {
    let ext = name.rsplit('.').next()?.to_lowercase();
    let mime = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png"          => "image/png",
        "gif"          => "image/gif",
        "mp4"          => "video/mp4",
        "mkv"          => "video/x-matroska",
        "pdf"          => "application/pdf",
        "zip"          => "application/zip",
        "txt"          => "text/plain",
        "html"         => "text/html",
        _              => return None,
    };
    Some(mime.to_string())
}