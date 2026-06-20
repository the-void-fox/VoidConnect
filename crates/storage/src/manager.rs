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

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{error, info, warn};
use void_core::identity::NodeId;
use void_core::manifest::{ChunkMeta, FileManifest};
use void_core::peer::PeerInfo;
use void_db::chunks as db_chunks;
use void_db::DbPool;

use crate::chunk_store::ChunkStore;
use crate::chunker::{split_file, assemble_file};
use crate::error::StorageError;
use crate::events::ChunkEvent;
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
    /// Опциональный канал событий о качестве чанков (для репутации).
    events: Option<mpsc::UnboundedSender<ChunkEvent>>,
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
            events: None,
        })
    }

    /// Подключает канал событий о качестве чанков (для системы репутации).
    /// Без него storage работает как прежде (события просто не шлются).
    pub fn set_event_sink(&mut self, tx: mpsc::UnboundedSender<ChunkEvent>) {
        self.events = Some(tx);
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

    // ─── Манифесты (Фаза 2: обнаружение файлов в сети) ────────────────────────

    /// Строит манифест файла из локальной БД — для рассылки объявления другим
    /// узлам. Возвращает `None`, если файл неизвестен.
    pub async fn file_manifest(&self, file_id: &str) -> Result<Option<FileManifest>, StorageError> {
        let Some(file) = db_chunks::get_file(&self.pool, file_id).await? else {
            return Ok(None);
        };
        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        let chunk_meta = chunks
            .iter()
            .map(|c| ChunkMeta {
                hash: c.hash.clone(),
                index: c.chunk_index,
                size: c.size_bytes,
            })
            .collect();

        // Объявляем себя владельцем: каждый узел, рассылающий манифест,
        // утверждает, что у него есть чанки (для публикатора — он один; для
        // скачавшего — он добавляется к уже известным сидерам через merge).
        Ok(Some(FileManifest {
            file_id: file.file_id,
            name: file.name,
            size_bytes: file.size_bytes,
            mime_type: file.mime_type,
            owners: vec![self.my_id.clone()],
            chunks: chunk_meta,
        }))
    }

    /// Обрабатывает входящий манифест файла от сети: регистрирует файл и его
    /// чанки локально (`is_local = false`), фиксирует владельца. После этого
    /// файл доступен для скачивания через [`download_file`].
    ///
    /// Уже скачанные локально чанки не затираются (на случай частичной загрузки
    /// и повторного объявления).
    ///
    /// [`download_file`]: Self::download_file
    pub async fn handle_manifest(&self, manifest: &FileManifest) -> Result<(), StorageError> {
        // owner_key хранит исходного публикатора (для отображения); полный
        // список сидеров живёт в chunk_owners.
        let owner_key = manifest
            .original_owner()
            .map(|n| n.as_str().to_string())
            .unwrap_or_default();
        let file_record = void_db::chunks::FileRecord {
            file_id: manifest.file_id.clone(),
            name: manifest.name.clone(),
            size_bytes: manifest.size_bytes,
            total_chunks: manifest.chunks.len() as i64,
            owner_key,
            mime_type: manifest.mime_type.clone(),
            created_at: chrono::Utc::now(),
        };
        db_chunks::insert_file(&self.pool, &file_record).await?;

        // Хэши уже имеющихся локально чанков — их не перезаписываем в remote.
        let existing = db_chunks::get_chunks_for_file(&self.pool, &manifest.file_id).await?;
        let local_hashes: HashSet<&str> = existing
            .iter()
            .filter(|c| c.is_local)
            .map(|c| c.hash.as_str())
            .collect();

        for cm in &manifest.chunks {
            if !local_hashes.contains(cm.hash.as_str()) {
                let chunk = void_db::chunks::Chunk {
                    hash: cm.hash.clone(),
                    file_id: manifest.file_id.clone(),
                    chunk_index: cm.index,
                    size_bytes: cm.size,
                    is_local: false,
                    local_path: None,
                };
                db_chunks::upsert_chunk(&self.pool, &chunk).await?;
            }
            // Регистрируем всех заявленных владельцев чанка (мульти-сидинг).
            for owner in &manifest.owners {
                db_chunks::add_chunk_owner(&self.pool, &cm.hash, owner.as_str()).await?;
                self.index.add_owner(&cm.hash, owner.clone()).await;
            }
        }

        info!(
            "Manifest registered: '{}' ({} chunks, {} seeder(s))",
            manifest.name,
            manifest.chunks.len(),
            manifest.owners.len(),
        );
        Ok(())
    }

    // ─── Скачивание ──────────────────────────────────────────────────────────

    /// Скачивает файл из сети и сохраняет по `dest_path`.
    /// Без поддержки отмены — обёртка над [`download_file_cancellable`].
    ///
    /// [`download_file_cancellable`]: Self::download_file_cancellable
    pub async fn download_file(
        &self,
        file_id: &str,
        dest_path: &Path,
        peers: &[PeerInfo],
    ) -> Result<(), StorageError> {
        self.download_file_cancellable(file_id, dest_path, peers, Arc::new(AtomicBool::new(false)))
            .await
    }

    /// Скачивает файл с возможностью отмены (пауза). Если `cancel` выставлен в
    /// `true`, скачивание останавливается между батчами и возвращает
    /// [`StorageError::Cancelled`]; уже полученные чанки сохраняются локально,
    /// поэтому повторный запуск продолжит с места остановки (resume).
    ///
    /// Алгоритм:
    /// 1. Берём список чанков файла из БД
    /// 2. Для каждого чанка ищем владельцев в индексе
    /// 3. Качаем параллельно (до DOWNLOAD_CONCURRENCY за раз)
    /// 4. Собираем файл из чанков и объявляем себя владельцем (мульти-сидинг)
    pub async fn download_file_cancellable(
        &self,
        file_id: &str,
        dest_path: &Path,
        peers: &[PeerInfo],
        cancel: Arc<AtomicBool>,
    ) -> Result<(), StorageError> {
        let file_meta = db_chunks::get_file(&self.pool, file_id)
            .await?
            .ok_or_else(|| StorageError::FileNotFound(file_id.to_string()))?;

        info!("Downloading '{}'...", file_meta.name);

        // Скачиваем все чанки в локальное хранилище (с поддержкой паузы).
        let flat = self.fetch_all_chunks(file_id, peers, &cancel).await?;

        // Все чанки получены — собираем файл на диск.
        assemble_file(&flat, dest_path).await?;

        // Теперь все чанки локально — объявляем себя их владельцем, чтобы другие
        // узлы могли качать у нас (мульти-сидинг).
        self.register_self_as_owner(file_id).await;

        info!("Downloaded '{}' → {}", file_meta.name, dest_path.display());
        Ok(())
    }

    /// Скачивает все чанки файла в локальное хранилище и возвращает их данные в
    /// порядке индексов. Уже локальные чанки читаются с диска. Между батчами
    /// проверяется флаг `cancel` (для паузы) → [`StorageError::Cancelled`].
    async fn fetch_all_chunks(
        &self,
        file_id: &str,
        peers: &[PeerInfo],
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        let total = chunks.len();

        // Скачиваем параллельно батчами
        let mut ordered_data: Vec<Option<Vec<u8>>> = vec![None; total];

        for batch in chunks.chunks(DOWNLOAD_CONCURRENCY) {
            if cancel.load(Ordering::Relaxed) {
                info!("Download cancelled: {}", &file_id[..8.min(file_id.len())]);
                return Err(StorageError::Cancelled);
            }
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
                let events = self.events.clone();

                handles.push(tokio::spawn(async move {
                    fetch_chunk_with_fallback(
                        &chunk_hash,
                        chunk_index,
                        &owners_clone,
                        &peers,
                        &my_id,
                        &store,
                        &pool,
                        events.as_ref(),
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

        Ok(ordered_data
            .into_iter()
            .enumerate()
            .map(|(i, opt)| opt.unwrap_or_else(|| {
                error!("BUG: chunk {} missing after download loop", i);
                Vec::new()
            }))
            .collect())
    }

    /// Объявляет нас владельцем всех чанков файла (после полного скачивания) —
    /// чтобы другие узлы могли качать их у нас (мульти-сидинг). `is_local` уже
    /// зафиксирован при сохранении каждого чанка.
    async fn register_self_as_owner(&self, file_id: &str) {
        let chunks = match db_chunks::get_chunks_for_file(&self.pool, file_id).await {
            Ok(c) => c,
            Err(e) => { warn!("register_self_as_owner({}): {}", &file_id[..8.min(file_id.len())], e); return; }
        };
        for chunk in &chunks {
            if let Err(e) = db_chunks::add_chunk_owner(&self.pool, &chunk.hash, self.my_id.as_str()).await {
                warn!("Не удалось записать себя владельцем чанка {}: {}", &chunk.hash[..8.min(chunk.hash.len())], e);
            }
            self.index.add_owner(&chunk.hash, self.my_id.clone()).await;
        }
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

    /// Читает файл целиком из локальных чанков (в порядке индексов) и собирает
    /// его в память. Ошибка, если какой-то чанк ещё не скачан локально.
    /// Используется для раздачи файлов сайта HTTP-сервером.
    pub async fn read_file(&self, file_id: &str) -> Result<Vec<u8>, StorageError> {
        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        if chunks.is_empty() {
            return Err(StorageError::FileNotFound(file_id.to_string()));
        }
        let mut data = Vec::new();
        for c in chunks {
            if !c.is_local {
                return Err(StorageError::ChunkNotFound(c.hash.clone()));
            }
            data.extend_from_slice(&self.store.get(&c.hash).await?);
        }
        Ok(data)
    }

    /// Читает файл из локальных чанков; если каких-то чанков нет, докачивает их
    /// у `peers` и собирает файл в память. После докачки регистрирует нас
    /// сидером (мульти-сидинг). Используется HTTP-сервером сайтов для раздачи
    /// файлов чужих (сетевых) сайтов по запросу — первый запрос скачивает,
    /// последующие идут по быстрому пути (все чанки уже локальны).
    pub async fn read_or_fetch_file(
        &self,
        file_id: &str,
        peers: &[PeerInfo],
    ) -> Result<Vec<u8>, StorageError> {
        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        if chunks.is_empty() {
            return Err(StorageError::FileNotFound(file_id.to_string()));
        }
        // Быстрый путь: все чанки уже локально.
        if chunks.iter().all(|c| c.is_local) {
            let mut data = Vec::new();
            for c in &chunks {
                data.extend_from_slice(&self.store.get(&c.hash).await?);
            }
            return Ok(data);
        }
        // Иначе докачиваем недостающие чанки и собираем файл в память.
        let flat = self
            .fetch_all_chunks(file_id, peers, &Arc::new(AtomicBool::new(false)))
            .await?;
        self.register_self_as_owner(file_id).await;
        Ok(flat.concat())
    }
}

// ─── Вспомогательные функции ─────────────────────────────────────────────────

/// Скачивает чанк, перебирая владельцев по очереди.
/// При успехе — сохраняет локально и обновляет БД.
#[allow(clippy::too_many_arguments)]
async fn fetch_chunk_with_fallback(
    hash: &str,
    index: usize,
    owners: &[NodeId],
    peers: &[PeerInfo],
    my_id: &NodeId,
    store: &ChunkStore,
    pool: &DbPool,
    events: Option<&mpsc::UnboundedSender<ChunkEvent>>,
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

                // Репутация: пир отдал валидный чанк.
                if let Some(tx) = events {
                    let _ = tx.send(ChunkEvent::Valid {
                        peer: owner_id.clone(),
                        size_bytes: data.len() as i64,
                    });
                }

                return Ok((index, data));
            }
            Err(StorageError::IntegrityFailure { expected, actual }) => {
                // Плохой чанк — логируем, штрафуем репутацию, идём к следующему узлу
                warn!(
                    "Integrity failure from {}: chunk {}, expected {}, got {}",
                    owner_id,
                    &hash[..8],
                    &expected[..8],
                    &actual[..8]
                );
                if let Some(tx) = events {
                    let _ = tx.send(ChunkEvent::Bad { peer: owner_id.clone() });
                }
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

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use void_core::peer::Service;
    use void_db::{open, DbPool};

    fn node(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&[seed; 32])
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    async fn make_node(seed: u8) -> (tempfile::TempDir, DbPool, StorageManager) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let store = ChunkStore::new(dir.path().join("chunks")).await.unwrap();
        let mgr = StorageManager::new(pool.clone(), store, node(seed)).await.unwrap();
        (dir, pool, mgr)
    }

    /// ~600 КБ → 3 чанка (256K + 256K + остаток).
    fn sample_content() -> Vec<u8> {
        (0..600_000u32).map(|i| (i % 251) as u8).collect()
    }

    /// Публикация: файл и чанки регистрируются локально, прогресс = 100%.
    #[tokio::test]
    async fn publish_creates_local_state() {
        let (dir, pool, mgr) = make_node(1).await;
        let content = sample_content();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();

        let file_id = mgr.publish_file(&path).await.unwrap();

        let frec = void_db::chunks::get_file(&pool, &file_id).await.unwrap().unwrap();
        assert_eq!(frec.name, "data.bin");
        assert_eq!(frec.size_bytes, 600_000);

        let chunks = void_db::chunks::get_chunks_for_file(&pool, &file_id).await.unwrap();
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.is_local));

        let progress = mgr.download_progress(&file_id).await.unwrap();
        assert!((progress - 1.0).abs() < 1e-9, "ожидался прогресс 1.0, получено {progress}");

        // read_file собирает файл из локальных чанков побайтово.
        let read_back = mgr.read_file(&file_id).await.unwrap();
        assert_eq!(read_back, content, "read_file должен вернуть исходное содержимое");
    }

    /// Сквозной P2P: A публикует и раздаёт, B скачивает через chunk-сервер.
    /// Метаданные файла/чанков реплицируются вручную (имитация будущего протокола
    /// анонсов из Фазы 2), владелец чанков — A.
    #[tokio::test]
    async fn publish_then_download_between_two_nodes() {
        let (dir_a, pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();

        // chunk-сервер A
        let a_port = free_port();
        let srv = mgr_a.clone();
        tokio::spawn(async move { let _ = srv.start_server(a_port).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Узел B знает метаданные файла, но чанков локально нет; владелец — A.
        let (dir_b, pool_b, mgr_b) = make_node(2).await;
        let frec = void_db::chunks::get_file(&pool_a, &file_id).await.unwrap().unwrap();
        void_db::chunks::insert_file(&pool_b, &frec).await.unwrap();

        let a_chunks = void_db::chunks::get_chunks_for_file(&pool_a, &file_id).await.unwrap();
        let mut hashes = Vec::new();
        for c in &a_chunks {
            let remote = void_db::chunks::Chunk {
                hash: c.hash.clone(),
                file_id: c.file_id.clone(),
                chunk_index: c.chunk_index,
                size_bytes: c.size_bytes,
                is_local: false,
                local_path: None,
            };
            void_db::chunks::upsert_chunk(&pool_b, &remote).await.unwrap();
            hashes.push(c.hash.clone());
        }
        mgr_b.handle_announce(&node(1), hashes).await;

        // A в списке пиров B (port = порт chunk-сервера A — туда идёт fetch)
        let a_peer = PeerInfo {
            id:        node(1),
            name:      "A".into(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      a_port,
            chat_port: a_port.wrapping_add(2),
            services:  vec![Service::Storage],
            last_seen: 0,
        };

        let dest = dir_b.path().join("downloaded.bin");
        mgr_b.download_file(&file_id, &dest, &[a_peer]).await.unwrap();

        let got = std::fs::read(&dest).unwrap();
        assert_eq!(got, content, "скачанный файл должен побайтово совпадать с исходным");

        // После скачивания у B чанки стали локальными → прогресс 100%
        let progress = mgr_b.download_progress(&file_id).await.unwrap();
        assert!((progress - 1.0).abs() < 1e-9, "у B прогресс должен быть 1.0, получено {progress}");
    }

    /// Фаза 2 целиком: A публикует → строит манифест; B получает манифест через
    /// `handle_manifest` (как по сети) и скачивает файл, не зная заранее ничего
    /// о чанках. Проверяет, что обнаружение + скачивание работают через манифест.
    #[tokio::test]
    async fn manifest_announce_then_download() {
        let (dir_a, _pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();

        // A строит манифест для рассылки.
        let manifest = mgr_a.file_manifest(&file_id).await.unwrap()
            .expect("манифест опубликованного файла должен существовать");
        assert_eq!(manifest.owners, vec![node(1)]);
        assert_eq!(manifest.total_chunks(), 3);

        // chunk-сервер A.
        let a_port = free_port();
        let srv = mgr_a.clone();
        tokio::spawn(async move { let _ = srv.start_server(a_port).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // B узнаёт о файле ТОЛЬКО из манифеста (никакой ручной репликации).
        let (dir_b, pool_b, mgr_b) = make_node(2).await;
        mgr_b.handle_manifest(&manifest).await.unwrap();

        // У B файл уже виден в списке, но чанков локально нет.
        let frec = void_db::chunks::get_file(&pool_b, &file_id).await.unwrap().unwrap();
        assert_eq!(frec.name, "data.bin");
        assert!((mgr_b.download_progress(&file_id).await.unwrap()).abs() < 1e-9,
            "до скачивания прогресс у B должен быть 0");

        // A в списке активных пиров B (port = порт chunk-сервера A).
        let a_peer = PeerInfo {
            id:        node(1),
            name:      "A".into(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      a_port,
            chat_port: a_port.wrapping_add(2),
            services:  vec![Service::Storage],
            last_seen: 0,
        };

        let dest = dir_b.path().join("downloaded.bin");
        mgr_b.download_file(&file_id, &dest, &[a_peer]).await.unwrap();

        let got = std::fs::read(&dest).unwrap();
        assert_eq!(got, content, "скачанный по манифесту файл должен совпадать с исходным");
        let progress = mgr_b.download_progress(&file_id).await.unwrap();
        assert!((progress - 1.0).abs() < 1e-9, "после скачивания прогресс у B = 1.0, получено {progress}");

        // Мульти-сидинг: B, скачав файл, должен числиться владельцем его чанков.
        let chunks_b = void_db::chunks::get_chunks_for_file(&pool_b, &file_id).await.unwrap();
        for c in &chunks_b {
            let owners = void_db::chunks::get_chunk_owners(&pool_b, &c.hash).await.unwrap();
            assert!(owners.iter().any(|o| o == node(2).as_str()),
                "после скачивания B должен быть владельцем чанка {}", &c.hash[..8]);
        }
    }

    /// Мульти-сидинг через merge: узел, получив манифесты одного файла от двух
    /// разных сидеров, регистрирует обоих как владельцев чанков.
    #[tokio::test]
    async fn manifest_merge_registers_multiple_seeders() {
        let (dir_a, _pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();

        // Манифест от публикатора A (owners=[A]).
        let m1 = mgr_a.file_manifest(&file_id).await.unwrap().unwrap();
        assert_eq!(m1.owners, vec![node(1)]);

        // Тот же файл, но объявленный другим сидером B (owners=[B]).
        let mut m2 = m1.clone();
        m2.owners = vec![node(2)];

        // Узел C получает оба объявления.
        let (_dir_c, pool_c, mgr_c) = make_node(3).await;
        mgr_c.handle_manifest(&m1).await.unwrap();
        mgr_c.handle_manifest(&m2).await.unwrap();

        // У каждого чанка теперь два владельца: A и B.
        let chunks = void_db::chunks::get_chunks_for_file(&pool_c, &file_id).await.unwrap();
        assert_eq!(chunks.len(), 3);
        for c in &chunks {
            let owners = void_db::chunks::get_chunk_owners(&pool_c, &c.hash).await.unwrap();
            assert!(owners.iter().any(|o| o == node(1).as_str()), "владелец A отсутствует");
            assert!(owners.iter().any(|o| o == node(2).as_str()), "владелец B отсутствует");
        }
    }

    /// Отмена (пауза) скачивания: при выставленном флаге скачивание прекращается
    /// и возвращает `Cancelled`, не докачивая файл.
    #[tokio::test]
    async fn download_can_be_cancelled() {
        let (dir_a, _pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();

        // B знает манифест, но чанков нет.
        let (dir_b, _pool_b, mgr_b) = make_node(2).await;
        let manifest = mgr_a.file_manifest(&file_id).await.unwrap().unwrap();
        mgr_b.handle_manifest(&manifest).await.unwrap();

        // Флаг отмены выставлен заранее → скачивание прекращается сразу.
        let cancel = Arc::new(AtomicBool::new(true));
        let dest = dir_b.path().join("out.bin");
        let res = mgr_b
            .download_file_cancellable(&file_id, &dest, &[], cancel)
            .await;

        assert!(matches!(res, Err(StorageError::Cancelled)),
            "ожидалась отмена, получено {res:?}");
        assert!(!dest.exists(), "файл не должен быть собран при отмене");
        let progress = mgr_b.download_progress(&file_id).await.unwrap();
        assert!(progress.abs() < 1e-9, "прогресс должен остаться 0 после отмены, получено {progress}");
    }

    /// Репутация: успешное скачивание чанков у пира порождает события Valid
    /// с указанием владельца и размера (питают начисление репутации).
    #[tokio::test]
    async fn download_emits_valid_chunk_events() {
        let (dir_a, _pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();

        let a_port = free_port();
        let srv = mgr_a.clone();
        tokio::spawn(async move { let _ = srv.start_server(a_port).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // B с подключённым каналом событий.
        let (dir_b, _pool_b, mut mgr_b) = make_node(2).await;
        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel::<ChunkEvent>();
        mgr_b.set_event_sink(ev_tx);
        let manifest = mgr_a.file_manifest(&file_id).await.unwrap().unwrap();
        mgr_b.handle_manifest(&manifest).await.unwrap();

        let a_peer = PeerInfo {
            id:        node(1),
            name:      "A".into(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      a_port,
            chat_port: a_port.wrapping_add(2),
            services:  vec![Service::Storage],
            last_seen: 0,
        };
        let dest = dir_b.path().join("out.bin");
        mgr_b.download_file(&file_id, &dest, &[a_peer]).await.unwrap();

        // Собираем все события: должно быть 3 Valid от node(1), суммарно = размер файла.
        let mut total = 0i64;
        let mut count = 0;
        while let Ok(ev) = ev_rx.try_recv() {
            match ev {
                ChunkEvent::Valid { peer, size_bytes } => {
                    assert_eq!(peer, node(1), "владелец валидного чанка — A");
                    total += size_bytes;
                    count += 1;
                }
                ChunkEvent::Bad { .. } => panic!("неожиданное Bad-событие"),
            }
        }
        assert_eq!(count, 3, "ожидалось 3 события Valid (по чанку)");
        assert_eq!(total, content.len() as i64, "сумма размеров чанков = размер файла");
    }
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