//! `StorageManager` — главный фасад модуля хранилища.
//!
//! Использование:
//! ```ignore
//! let manager = StorageManager::new(pool, chunk_store, noise_identity).await?;
//! manager.start_server(storage_port).await;
//!
//! // Опубликовать файл
//! let file_id = manager.publish_file(Path::new("/tmp/photo.jpg")).await?;
//!
//! // Скачать файл
//! manager.download_file(&file_id, Path::new("/tmp/output/photo.jpg")).await?;
//! ```

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn};
use void_core::identity::NodeId;
use void_core::manifest::{ChunkMeta, FileManifest};
use void_core::peer::PeerInfo;
use void_db::chunks as db_chunks;
use void_db::DbPool;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_network::secure::NoiseIdentity;

use crate::chunk_store::ChunkStore;
use crate::chunker::CHUNK_SIZE;
use crate::error::StorageError;
use crate::events::ChunkEvent;
use crate::index::ChunkIndex;
use crate::integrity::{compute_file_id, hash_chunk, validate_manifest, verify_publisher};
use crate::transfer::{fetch_chunk_from_peer, run_chunk_server};

/// Параллельность при скачивании (одновременно N чанков)
const DOWNLOAD_CONCURRENCY: usize = 4;

#[derive(Clone)]
pub struct StorageManager {
    pool: DbPool,
    store: ChunkStore,
    index: ChunkIndex,
    my_id: NodeId,
    /// Noise-ключ для соединений с другими узлами (раздача и скачивание чанков).
    noise: NoiseIdentity,
    /// Ключ подписи манифестов публикуемых файлов.
    signing: Arc<SigningKeypair>,
    /// Опциональный канал событий о качестве чанков (для репутации).
    events: Option<mpsc::UnboundedSender<ChunkEvent>>,
    /// Счётчик отданных байт (чанки, разосланные пирам). Для статистики профиля.
    bytes_uploaded: Arc<AtomicU64>,
    /// Счётчик принятых байт (чанки, скачанные у пиров по сети).
    bytes_downloaded: Arc<AtomicU64>,
}

impl StorageManager {
    /// Создаёт менеджер и загружает индекс чанков из БД.
    pub async fn new(
        pool: DbPool,
        store: ChunkStore,
        signing: Arc<SigningKeypair>,
    ) -> Result<Self, StorageError> {
        let noise = NoiseIdentity::new(&signing);
        let my_id = noise.node_id().clone();
        let index = ChunkIndex::new();

        // Загружаем в индекс наши собственные чанки из БД
        let local_chunks = db_chunks::get_local_chunks(&pool).await?;
        let entries: Vec<(String, NodeId)> = local_chunks
            .iter()
            .map(|c| (c.hash.clone(), my_id.clone()))
            .collect();
        index.bulk_load(entries).await;

        // И владельцев чужих чанков, известных с прошлого запуска: без этого после
        // перезапуска чужие файлы и сайты не докачивались, пока владелец не
        // объявит файл заново. Владельцев не в сети отсеивает список активных
        // пиров при скачивании.
        let remote: Vec<(String, NodeId)> = db_chunks::get_all_chunk_owners(&pool)
            .await?
            .into_iter()
            .filter(|(_, key)| key != my_id.as_str())
            .map(|(hash, key)| (hash, NodeId(key)))
            .collect();
        let remote_count = remote.len();
        index.bulk_load(remote).await;

        info!(
            "StorageManager ready: {} local chunks, {} remote owner records loaded",
            local_chunks.len(),
            remote_count,
        );

        Ok(StorageManager {
            pool,
            store,
            index,
            my_id,
            noise,
            signing,
            events: None,
            bytes_uploaded: Arc::new(AtomicU64::new(0)),
            bytes_downloaded: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Подключает канал событий о качестве чанков (для системы репутации).
    /// Без него storage работает как прежде (события просто не шлются).
    pub fn set_event_sink(&mut self, tx: mpsc::UnboundedSender<ChunkEvent>) {
        self.events = Some(tx);
    }

    /// Подключает внешние счётчики трафика (общие с GUI). Вызывать ДО клонирования
    /// менеджера в задачи — Arc делится между всеми клонами. Без него счётчики
    /// локальны для менеджера (storage/тесты работают как прежде).
    pub fn set_traffic_counters(
        &mut self,
        uploaded: Arc<AtomicU64>,
        downloaded: Arc<AtomicU64>,
    ) {
        self.bytes_uploaded = uploaded;
        self.bytes_downloaded = downloaded;
    }

    /// Запускает TCP chunk-сервер.
    /// Вызывай через `tokio::spawn` — блокирует задачу.
    pub async fn start_server(&self, port: u16) -> Result<(), StorageError> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()
            .map_err(|e: std::net::AddrParseError| StorageError::Network(e.to_string()))?;
        run_chunk_server(addr, self.store.clone(), Arc::clone(&self.bytes_uploaded), self.noise.clone()).await
    }

    // ─── Публикация ──────────────────────────────────────────────────────────

    /// Разбивает файл на чанки, сохраняет локально и регистрирует в БД.
    ///
    /// Возвращает `file_id` — SHA-256 от манифеста чанков.
    pub async fn publish_file(&self, path: &Path) -> Result<String, StorageError> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        self.publish_file_as(path, &name).await
    }

    /// Публикует файл под именем `name` (загрузка с сайта: байты лежат во
    /// временном файле со служебным именем).
    ///
    /// Файл читается потоково, по чанку: раньше он целиком загружался в память
    /// (и ещё раз копировался по кускам) — видео на гигабайт съедало два.
    pub async fn publish_file_as(&self, path: &Path, name: &str) -> Result<String, StorageError> {
        let mut file = tokio::fs::File::open(path).await?;
        let mut metas: Vec<(String, usize)> = Vec::new();
        let mut total_size: u64 = 0;
        let mut buf = vec![0u8; CHUNK_SIZE];
        loop {
            let n = read_full(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }
            let data = &buf[..n];
            let hash = hash_chunk(data);
            self.store.put(&hash, data).await?;
            metas.push((hash, n));
            total_size += n as u64;
            if n < CHUNK_SIZE {
                break;
            }
        }
        let hashes: Vec<String> = metas.iter().map(|(h, _)| h.clone()).collect();
        let file_id = compute_file_id(&hashes);

        // Регистрируем метаданные файла
        let file_record = void_db::chunks::FileRecord {
            file_id: file_id.clone(),
            name: name.to_string(),
            size_bytes: total_size as i64,
            total_chunks: metas.len() as i64,
            owner_key: self.my_id.as_str().to_string(),
            mime_type: mime_type_from_name(name),
            created_at: chrono::Utc::now(),
        };
        db_chunks::insert_file(&self.pool, &file_record).await?;

        for (index, (hash, size)) in metas.iter().enumerate() {
            let chunk_record = void_db::chunks::Chunk {
                hash: hash.clone(),
                file_id: file_id.clone(),
                chunk_index: index as i64,
                size_bytes: *size as i64,
                is_local: true,
                local_path: Some(self.store.chunk_path(hash).to_string_lossy().to_string()),
            };
            db_chunks::upsert_chunk(&self.pool, &chunk_record).await?;
            // Тот же блок мог ждать скачивания в чужом файле — теперь он есть.
            if let Some(path) = &chunk_record.local_path {
                db_chunks::mark_local(&self.pool, hash, path).await?;
            }
            db_chunks::add_chunk_owner(&self.pool, hash, self.my_id.as_str()).await?;
            self.index.add_owner(hash, self.my_id.clone()).await;
        }

        // Подписываем манифест как публикатор — если этот контент ещё не
        // известен от другого публикатора (тот же file_id = те же байты).
        if db_chunks::get_file_signature(&self.pool, &file_id).await?.is_none()
            && let Some(mut manifest) = self.file_manifest(&file_id).await? {
                manifest.publisher = Some(self.my_id.clone());
                let signed = SignedMessage::sign(manifest.signing_bytes(), &self.signing)
                    .map_err(|e| StorageError::InvalidManifest(format!("подпись: {:?}", e)))?;
                db_chunks::save_file_signature(&self.pool, &file_id, self.my_id.as_str(), &signed.signature)
                    .await?;
            }

        info!(
            "Published '{}': file_id={}, {} chunks",
            name,
            &file_id[..8],
            metas.len()
        );

        Ok(file_id)
    }

    // ─── Манифесты (Фаза 2: обнаружение файлов в сети) ────────────────────────

    /// Строит манифест файла из локальной БД — для рассылки объявления другим
    /// узлам. Возвращает `None`, если файл неизвестен.
    /// Файлы, которые у нас есть целиком (раздаём): после перезапуска их снова
    /// объявляют сети, чтобы соседи узнали, что у нас можно докачать.
    pub async fn seeded_files(&self) -> Result<Vec<String>, StorageError> {
        let mut out = Vec::new();
        for file in db_chunks::list_files(&self.pool).await? {
            if db_chunks::local_completion(&self.pool, &file.file_id).await? >= 1.0 {
                out.push(file.file_id);
            }
        }
        Ok(out)
    }

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

        // Подпись публикатора (своя или принятая из сети) — без неё манифест
        // другие узлы не примут.
        let (publisher, signature) = match db_chunks::get_file_signature(&self.pool, file_id).await? {
            Some((p, s)) => (Some(NodeId(p)), Some(s)),
            None => (None, None),
        };

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
            publisher,
            signature,
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
        validate_manifest(manifest)?;
        let publisher = verify_publisher(manifest)?;
        // owner_key хранит исходного публикатора (подписавшего манифест, для
        // отображения); полный список сидеров живёт в chunk_owners.
        let owner_key = publisher.as_str().to_string();
        let file_record = void_db::chunks::FileRecord {
            file_id: manifest.file_id.clone(),
            // Имя храним как подписано (иначе пересланный сидером манифест не
            // сойдётся с подписью). В путь и в UI оно идёт только через
            // `safe_file_name` — в backend (скачивание) и на странице хранилища.
            name: manifest.name.clone(),
            size_bytes: manifest.size_bytes,
            total_chunks: manifest.chunks.len() as i64,
            owner_key: owner_key.clone(),
            mime_type: manifest.mime_type.clone(),
            created_at: chrono::Utc::now(),
        };
        db_chunks::insert_file(&self.pool, &file_record).await?;
        if let Some(signature) = &manifest.signature {
            db_chunks::save_file_signature(&self.pool, &manifest.file_id, &owner_key, signature).await?;
        }

        for cm in &manifest.chunks {
            // Блок мог уже лежать на диске (из другого файла с тем же блоком) —
            // тогда он сразу локальный. Уже скачанное upsert не «забывает».
            let have = self.store.has(&cm.hash);
            let chunk = void_db::chunks::Chunk {
                hash: cm.hash.clone(),
                file_id: manifest.file_id.clone(),
                chunk_index: cm.index,
                size_bytes: cm.size,
                is_local: have,
                local_path: have.then(|| self.store.chunk_path(&cm.hash).to_string_lossy().to_string()),
            };
            db_chunks::upsert_chunk(&self.pool, &chunk).await?;
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

        // Скачиваем недостающие чанки в локальное хранилище (с поддержкой паузы).
        let chunks = self.fetch_missing_chunks(file_id, peers, &cancel).await?;

        // Все чанки получены — собираем файл на диск по одному чанку.
        self.assemble_to(&chunks, dest_path).await?;

        // Теперь все чанки локально — объявляем себя их владельцем, чтобы другие
        // узлы могли качать у нас (мульти-сидинг).
        self.register_self_as_owner(file_id).await;

        info!("Downloaded '{}' → {}", file_meta.name, dest_path.display());
        Ok(())
    }

    /// Собирает файл из локальных чанков на диск, держа в памяти один чанк.
    /// Пишет во временный файл и переименовывает: оборванная сборка не
    /// оставит «скачанный» обрубок.
    async fn assemble_to(&self, chunks: &[void_db::chunks::Chunk], dest_path: &Path) -> Result<(), StorageError> {
        use tokio::io::AsyncWriteExt;
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = dest_path.with_extension("part");
        let mut out = tokio::fs::File::create(&tmp).await?;
        for c in chunks {
            out.write_all(&self.store.get(&c.hash).await?).await?;
        }
        out.flush().await?;
        drop(out);
        tokio::fs::rename(&tmp, dest_path).await?;
        Ok(())
    }

    /// Докачивает все недостающие чанки файла в локальное хранилище и
    /// возвращает список чанков в порядке индексов. Данные чанков в памяти не
    /// копятся (раньше весь файл собирался в `Vec`). Между батчами проверяется
    /// флаг `cancel` (для паузы) → [`StorageError::Cancelled`].
    async fn fetch_missing_chunks(
        &self,
        file_id: &str,
        peers: &[PeerInfo],
        cancel: &Arc<AtomicBool>,
    ) -> Result<Vec<void_db::chunks::Chunk>, StorageError> {
        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        check_contiguous(&chunks, file_id)?;
        let missing: Vec<&void_db::chunks::Chunk> = chunks.iter().filter(|c| !c.is_local).collect();

        for batch in missing.chunks(DOWNLOAD_CONCURRENCY) {
            if cancel.load(Ordering::Relaxed) {
                info!("Download cancelled: {}", &file_id[..8.min(file_id.len())]);
                return Err(StorageError::Cancelled);
            }
            let mut handles = Vec::new();
            for chunk in batch {
                handles.push(self.spawn_fetch(&chunk.hash, chunk.chunk_index as usize, peers).await?);
            }
            for handle in handles {
                match handle.await {
                    // Учёт принятого по сети трафика (локальные чанки сюда не попадают).
                    Ok(Ok((_, data))) => {
                        self.bytes_downloaded.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(StorageError::Network(format!("task panic: {}", e))),
                }
            }
        }
        Ok(chunks)
    }

    /// Запускает скачивание одного чанка у его известных владельцев.
    async fn spawn_fetch(
        &self,
        hash: &str,
        index: usize,
        peers: &[PeerInfo],
    ) -> Result<tokio::task::JoinHandle<Result<(usize, Vec<u8>), StorageError>>, StorageError> {
        let owners = self.index.get_owners(hash).await;
        if owners.is_empty() {
            warn!("No peers for chunk {}", &hash[..8.min(hash.len())]);
            return Err(StorageError::NoPeersForChunk(hash.to_string()));
        }
        let chunk_hash = hash.to_string();
        let noise = self.noise.clone();
        let peers = peers.to_vec();
        let pool = self.pool.clone();
        let store = self.store.clone();
        let events = self.events.clone();
        Ok(tokio::spawn(async move {
            fetch_chunk_with_fallback(&chunk_hash, index, &owners, &peers, &noise, &store, &pool, events.as_ref())
                .await
        }))
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
        self.store.list_all().await
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

    /// Знаем ли мы файл (есть его манифест), независимо от того, скачан ли он.
    pub async fn knows_file(&self, file_id: &str) -> Result<bool, StorageError> {
        Ok(db_chunks::get_file(&self.pool, file_id).await?.is_some())
    }

    /// Сколько файлов знает узел (свои, скачанные и известные из сети).
    pub async fn known_file_count(&self) -> Result<usize, StorageError> {
        Ok(db_chunks::list_files(&self.pool).await?.len())
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
        let chunks = self
            .fetch_missing_chunks(file_id, peers, &Arc::new(AtomicBool::new(false)))
            .await?;
        self.register_self_as_owner(file_id).await;
        let mut data = Vec::new();
        for c in &chunks {
            data.extend_from_slice(&self.store.get(&c.hash).await?);
        }
        Ok(data)
    }

    // ─── Чтение по частям (видео, большие файлы) ─────────────────────────────

    /// Раскладка файла по чанкам: смещения, размеры, что уже есть локально.
    /// Нужна для HTTP Range (перемотка видео) и потоковой отдачи — без чтения
    /// файла целиком в память.
    pub async fn file_layout(&self, file_id: &str) -> Result<FileLayout, StorageError> {
        let file = db_chunks::get_file(&self.pool, file_id)
            .await?
            .ok_or_else(|| StorageError::FileNotFound(file_id.to_string()))?;
        let chunks = db_chunks::get_chunks_for_file(&self.pool, file_id).await?;
        check_contiguous(&chunks, file_id)?;
        if chunks.len() as i64 != file.total_chunks {
            return Err(StorageError::InvalidManifest(format!(
                "у файла {} известно {} чанков из {}",
                &file_id[..8.min(file_id.len())], chunks.len(), file.total_chunks,
            )));
        }
        let mut offset = 0u64;
        let slots = chunks
            .into_iter()
            .map(|c| {
                let slot = ChunkSlot { hash: c.hash, offset, size: c.size_bytes.max(0) as u64, is_local: c.is_local };
                offset += slot.size;
                slot
            })
            .collect();
        Ok(FileLayout {
            file_id: file.file_id,
            name: file.name,
            mime_type: file.mime_type,
            size: offset,
            chunks: slots,
        })
    }

    /// Байты `[start, end]` (включительно) файла. Недостающие чанки этого
    /// диапазона докачиваются у пиров; остальной файл не трогается. Когда файл
    /// оказывается у нас целиком — регистрируемся его сидером.
    pub async fn read_range(
        &self,
        layout: &FileLayout,
        start: u64,
        end: u64,
        peers: &[PeerInfo],
    ) -> Result<Vec<u8>, StorageError> {
        if start > end || end >= layout.size {
            return Err(StorageError::InvalidManifest("диапазон вне файла".into()));
        }
        let wanted: Vec<(usize, &ChunkSlot)> = layout
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| c.offset <= end && c.offset + c.size > start)
            .collect();

        // Недостающие — параллельно, батчами.
        let missing: Vec<(usize, &ChunkSlot)> = wanted.iter().copied().filter(|(_, c)| !c.is_local).collect();
        let mut fetched: std::collections::HashMap<usize, Vec<u8>> = Default::default();
        for batch in missing.chunks(DOWNLOAD_CONCURRENCY) {
            let mut handles = Vec::new();
            for (i, c) in batch {
                handles.push(self.spawn_fetch(&c.hash, *i, peers).await?);
            }
            for handle in handles {
                match handle.await {
                    Ok(Ok((i, data))) => {
                        self.bytes_downloaded.fetch_add(data.len() as u64, Ordering::Relaxed);
                        fetched.insert(i, data);
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(StorageError::Network(format!("task panic: {}", e))),
                }
            }
        }

        let mut out = Vec::with_capacity((end - start + 1) as usize);
        for (i, c) in wanted {
            let data = match fetched.remove(&i) {
                Some(d) => d,
                None => self.store.get(&c.hash).await?,
            };
            let from = start.saturating_sub(c.offset) as usize;
            let to = ((end - c.offset + 1) as usize).min(data.len());
            if from >= to {
                return Err(StorageError::ChunkNotFound(c.hash.clone()));
            }
            out.extend_from_slice(&data[from..to]);
        }

        if !missing.is_empty() && db_chunks::local_completion(&self.pool, &layout.file_id).await? >= 1.0 {
            self.register_self_as_owner(&layout.file_id).await;
        }
        Ok(out)
    }

    /// Удаляет файл из раздачи: стирает локальные блобы чанков с диска и все
    /// записи о файле из БД (чанки, владельцы, метаданные). После этого мы
    /// больше не сидируем файл. Другие сидеры (если есть) на это не влияют.
    pub async fn delete_file(&self, file_id: &str) -> Result<(), StorageError> {
        let local_hashes = db_chunks::delete_file(&self.pool, file_id).await?;
        for h in &local_hashes {
            if let Err(e) = self.store.delete(h).await {
                warn!("Не удалось удалить блоб чанка {}: {}", &h[..8.min(h.len())], e);
            }
        }
        info!(
            "Файл {} удалён из раздачи ({} локальных чанков стёрто)",
            &file_id[..8.min(file_id.len())],
            local_hashes.len()
        );
        Ok(())
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
    noise: &NoiseIdentity,
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

        match fetch_chunk_from_peer(addr, owner_id, hash, noise).await {
            Ok(data) => {
                // Сохраняем локально
                if let Err(e) = store.put(hash, &data).await {
                    warn!("Failed to store chunk {}: {}", &hash[..8], e);
                }

                // Блоб общий для всех файлов с этим хэшем — помечаем все места.
                let path = store.chunk_path(hash).to_string_lossy().to_string();
                if let Err(e) = db_chunks::mark_local(pool, hash, &path).await {
                    warn!("Не удалось отметить чанк {} локальным: {}", &hash[..8], e);
                }

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

/// Раскладка файла по чанкам (см. [`StorageManager::file_layout`]).
#[derive(Debug, Clone)]
pub struct FileLayout {
    pub file_id: String,
    /// Имя как подписано публикатором (для показа — через `safe_file_name`).
    pub name: String,
    pub mime_type: Option<String>,
    /// Полный размер в байтах (сумма размеров чанков).
    pub size: u64,
    pub chunks: Vec<ChunkSlot>,
}

/// Один чанк в раскладке файла.
#[derive(Debug, Clone)]
pub struct ChunkSlot {
    pub hash: String,
    pub offset: u64,
    pub size: u64,
    pub is_local: bool,
}

/// Читает до заполнения буфера или конца файла.
async fn read_full(file: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize, StorageError> {
    use tokio::io::AsyncReadExt;
    let mut filled = 0;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Индексы чанков идут подряд с нуля. Иначе часть строк потеряна (таблица
/// `chunks` хранит чанк по хэшу: одинаковый блок в двух файлах — одна строка),
/// и сборка дала бы файл с дырой.
fn check_contiguous(chunks: &[void_db::chunks::Chunk], file_id: &str) -> Result<(), StorageError> {
    if chunks.iter().enumerate().any(|(i, c)| c.chunk_index != i as i64) {
        return Err(StorageError::InvalidManifest(format!(
            "у файла {} пропущены чанки",
            &file_id[..8.min(file_id.len())],
        )));
    }
    Ok(())
}

/// Простое определение MIME типа по расширению файла.
fn mime_type_from_name(name: &str) -> Option<String> {
    let ext = name.rsplit('.').next()?.to_lowercase();
    let mime = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png"          => "image/png",
        "gif"          => "image/gif",
        "webp"         => "image/webp",
        "mp4" | "m4v"  => "video/mp4",
        "webm"         => "video/webm",
        "mkv"          => "video/x-matroska",
        "mov"          => "video/quicktime",
        "ogv"          => "video/ogg",
        "mp3"          => "audio/mpeg",
        "ogg" | "oga"  => "audio/ogg",
        "opus"         => "audio/opus",
        "wav"          => "audio/wav",
        "flac"         => "audio/flac",
        "m4a"          => "audio/mp4",
        "pdf"          => "application/pdf",
        "zip"          => "application/zip",
        "txt"          => "text/plain",
        "html"         => "text/html",
        _              => return None,
    };
    Some(mime.to_string())
}

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use void_core::peer::Service;
    use void_db::{open, DbPool};

    /// Ключ тестового узла: NodeId должен быть настоящим (его проверяет Noise).
    fn kp(seed: u8) -> Arc<SigningKeypair> {
        Arc::new(SigningKeypair::from_seed(&[seed; 32]).unwrap())
    }

    fn node(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&kp(seed).public_bytes())
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    async fn make_node(seed: u8) -> (tempfile::TempDir, DbPool, StorageManager) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let store = ChunkStore::new(dir.path().join("chunks")).await.unwrap();
        let mgr = StorageManager::new(pool.clone(), store, kp(seed)).await.unwrap();
        (dir, pool, mgr)
    }

    /// Владельцы чужих чанков переживают перезапуск: индекс загружается из БД,
    /// иначе файл нельзя докачать, пока владелец не объявит его заново.
    #[tokio::test]
    async fn remote_owners_survive_restart() {
        let (_seed_dir, _seed_pool, seeder) = make_node(1).await;
        let path = _seed_dir.path().join("data.bin");
        std::fs::write(&path, sample_content()).unwrap();
        let file_id = seeder.publish_file(&path).await.unwrap();
        let manifest = seeder.file_manifest(&file_id).await.unwrap().unwrap();
        assert_eq!(seeder.seeded_files().await.unwrap(), vec![file_id.clone()]);

        let (dir, pool, leecher) = make_node(2).await;
        leecher.handle_manifest(&manifest).await.unwrap();
        let hash = manifest.chunks[0].hash.clone();
        assert_eq!(leecher.index.get_owners(&hash).await, vec![node(1)]);
        assert!(leecher.seeded_files().await.unwrap().is_empty(), "чанков у нас нет — не раздаём");
        drop(leecher);

        // «Перезапуск»: новый менеджер на той же БД.
        let store = ChunkStore::new(dir.path().join("chunks")).await.unwrap();
        let restarted = StorageManager::new(pool, store, kp(2)).await.unwrap();
        assert_eq!(restarted.index.get_owners(&hash).await, vec![node(1)]);
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

    /// Публикация потоковая: файл ровно в N чанков и с остатком даёт тот же
    /// file_id, что и разбивка целиком в памяти (совместимость с сетью).
    #[tokio::test]
    async fn streaming_publish_matches_in_memory_split() {
        let (dir, _pool, mgr) = make_node(1).await;
        for len in [0usize, 1, CHUNK_SIZE, CHUNK_SIZE * 2, CHUNK_SIZE * 2 + 17] {
            let content: Vec<u8> = (0..len as u32).map(|i| (i % 253) as u8).collect();
            let path = dir.path().join(format!("f{len}.bin"));
            std::fs::write(&path, &content).unwrap();
            let expected = crate::chunker::split_file(&path).await.unwrap().file_id;
            assert_eq!(mgr.publish_file(&path).await.unwrap(), expected, "длина {len}");
            if len > 0 {
                assert_eq!(mgr.read_file(&expected).await.unwrap(), content);
            }
        }
    }

    /// Общий блок у двух файлов: оба собираются, удаление одного не стирает
    /// блоб, нужный другому (раньше чанк хранился по хэшу и второй файл ломался).
    #[tokio::test]
    async fn files_sharing_a_chunk_stay_intact() {
        let (dir, _pool, mgr) = make_node(1).await;
        let a: Vec<u8> = (0..CHUNK_SIZE as u32 * 2).map(|i| (i % 253) as u8).collect();
        let b: Vec<u8> = a[..CHUNK_SIZE].iter().copied().chain(std::iter::repeat_n(7u8, 1000)).collect();
        std::fs::write(dir.path().join("a.bin"), &a).unwrap();
        std::fs::write(dir.path().join("b.bin"), &b).unwrap();
        let ida = mgr.publish_file(&dir.path().join("a.bin")).await.unwrap();
        let idb = mgr.publish_file(&dir.path().join("b.bin")).await.unwrap();
        assert_eq!(mgr.read_file(&ida).await.unwrap(), a);
        assert_eq!(mgr.read_file(&idb).await.unwrap(), b);
        mgr.delete_file(&ida).await.unwrap();
        assert_eq!(mgr.read_file(&idb).await.unwrap(), b, "общий блоб не должен стереться");
        mgr.delete_file(&idb).await.unwrap();
        assert!(mgr.store.list_all().await.unwrap().is_empty(), "после удаления обоих блобов не остаётся");
    }

    /// Имя при публикации задаётся отдельно от пути (загрузка с сайта).
    #[tokio::test]
    async fn publish_as_keeps_given_name() {
        let (dir, pool, mgr) = make_node(1).await;
        let path = dir.path().join("upload-1234.tmp");
        std::fs::write(&path, b"hello").unwrap();
        let id = mgr.publish_file_as(&path, "clip.webm").await.unwrap();
        let frec = void_db::chunks::get_file(&pool, &id).await.unwrap().unwrap();
        assert_eq!(frec.name, "clip.webm");
        assert_eq!(frec.mime_type.as_deref(), Some("video/webm"));
    }

    /// Диапазоны локального файла: внутри чанка, через границу, последний байт.
    #[tokio::test]
    async fn read_range_local_across_chunk_boundaries() {
        let (dir, _pool, mgr) = make_node(1).await;
        let content = sample_content();
        let path = dir.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let id = mgr.publish_file(&path).await.unwrap();
        let layout = mgr.file_layout(&id).await.unwrap();
        assert_eq!(layout.size, content.len() as u64);
        assert_eq!(layout.chunks.len(), 3);
        let c = CHUNK_SIZE as u64;
        for (a, b) in [(0, 0), (10, 99), (c - 5, c + 5), (c - 1, 2 * c), (0, layout.size - 1), (layout.size - 1, layout.size - 1)] {
            let got = mgr.read_range(&layout, a, b, &[]).await.unwrap();
            assert_eq!(got, &content[a as usize..=b as usize], "диапазон {a}-{b}");
        }
        assert!(mgr.read_range(&layout, 5, layout.size, &[]).await.is_err());
        assert!(mgr.read_range(&layout, 9, 3, &[]).await.is_err());
    }

    /// Диапазон чужого файла докачивает только нужные чанки; полный файл
    /// потом собирается и делает нас сидером.
    #[tokio::test]
    async fn read_range_fetches_only_needed_chunks_from_peer() {
        let (dir_a, _pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();
        let manifest = mgr_a.file_manifest(&file_id).await.unwrap().unwrap();
        let a_port = free_port();
        let srv = mgr_a.clone();
        tokio::spawn(async move { let _ = srv.start_server(a_port).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let (_dir_b, pool_b, mgr_b) = make_node(2).await;
        mgr_b.handle_manifest(&manifest).await.unwrap();
        let a_peer = PeerInfo {
            id: node(1),
            name: "A".into(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: a_port,
            chat_port: a_port.wrapping_add(2),
            services: vec![Service::Storage],
            last_seen: 0,
        };
        let layout = mgr_b.file_layout(&file_id).await.unwrap();
        assert!(layout.chunks.iter().all(|c| !c.is_local));
        let c = CHUNK_SIZE as u64;
        let got = mgr_b.read_range(&layout, c + 10, c + 20, std::slice::from_ref(&a_peer)).await.unwrap();
        assert_eq!(got, &content[(c + 10) as usize..=(c + 20) as usize]);
        let local: Vec<bool> = void_db::chunks::get_chunks_for_file(&pool_b, &file_id)
            .await.unwrap().iter().map(|c| c.is_local).collect();
        assert_eq!(local, vec![false, true, false], "скачан только второй чанк");

        // Докачка остального — и B становится сидером.
        let layout = mgr_b.file_layout(&file_id).await.unwrap();
        let all = mgr_b.read_range(&layout, 0, layout.size - 1, &[a_peer]).await.unwrap();
        assert_eq!(all, content);
        let owners = void_db::chunks::get_chunk_owners(&pool_b, &manifest.chunks[0].hash).await.unwrap();
        assert!(owners.iter().any(|o| o == node(2).as_str()));
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

    /// Адрес владельца подменён (анонс чужого узла): самозванец раздаёт тот же
    /// файл, но рукопожатие видит, что это не владелец, и чанки у него не берутся.
    #[tokio::test]
    async fn chunks_not_taken_from_impostor_address() {
        let (dir_a, pool_a, mgr_a) = make_node(1).await;
        let content = sample_content();
        let path = dir_a.path().join("data.bin");
        std::fs::write(&path, &content).unwrap();
        let file_id = mgr_a.publish_file(&path).await.unwrap();
        let manifest = mgr_a.file_manifest(&file_id).await.unwrap().unwrap();
        drop(pool_a);

        // Самозванец M раздаёт тот же файл со своего chunk-сервера.
        let (dir_m, _pool_m, mgr_m) = make_node(9).await;
        let m_path = dir_m.path().join("data.bin");
        std::fs::write(&m_path, &content).unwrap();
        mgr_m.publish_file(&m_path).await.unwrap();
        let m_port = free_port();
        let srv = mgr_m.clone();
        tokio::spawn(async move { let _ = srv.start_server(m_port).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // B знает манифест (владелец A), но адрес «A» указывает на M.
        let (dir_b, _pool_b, mgr_b) = make_node(2).await;
        mgr_b.handle_manifest(&manifest).await.unwrap();
        let spoofed = PeerInfo {
            id:        node(1),
            name:      "A".into(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      m_port,
            chat_port: m_port.wrapping_add(2),
            services:  vec![Service::Storage],
            last_seen: 0,
        };
        let dest = dir_b.path().join("downloaded.bin");
        let res = mgr_b.download_file(&file_id, &dest, &[spoofed]).await;
        assert!(res.is_err(), "чанки не должны браться у самозванца");
        let progress = mgr_b.download_progress(&file_id).await.unwrap();
        assert_eq!(progress, 0.0);
    }
}
