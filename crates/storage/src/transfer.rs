//! Передача чанков по TCP между узлами.
//!
//! Протокол (length-prefixed JSON + binary):
//!
//!   Запрос:  [4 байта len BE] [JSON ChunkRequest]
//!   Ответ:   [4 байта len BE] [JSON ChunkResponse] [data если ok]
//!
//! Сервер запускается в `StorageManager::start_server`.
//! Клиент вызывает `fetch_chunk_from_peer`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use void_core::identity::NodeId;

use crate::chunk_store::ChunkStore;
use crate::error::StorageError;
use crate::integrity::verify_chunk;

/// Таймаут на получение одного чанка
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

// ─── Протокол ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub chunk_hash: String,
    /// ID запрашивающего узла — для будущего учёта репутации
    pub requester_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkResponse {
    pub chunk_hash: String,
    pub status: ChunkResponseStatus,
    /// Размер следующего за JSON бинарного payload (0 если not_found/error)
    pub data_len: u32,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChunkResponseStatus {
    Ok,
    NotFound,
    Error,
}

// ─── Вспомогательные функции I/O ──────────────────────────────────────────────

/// Записывает length-prefixed JSON в stream.
async fn write_message<T: Serialize>(
    stream: &mut TcpStream,
    msg: &T,
) -> Result<(), StorageError> {
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    stream.write_all(&len.to_be_bytes()).await
        .map_err(|e| StorageError::Network(e.to_string()))?;
    stream.write_all(&json).await
        .map_err(|e| StorageError::Network(e.to_string()))?;
    Ok(())
}

/// Читает length-prefixed JSON из stream.
async fn read_message<T: for<'de> Deserialize<'de>>(
    stream: &mut TcpStream,
) -> Result<T, StorageError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| StorageError::Network(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Ограничение на размер заголовка — не более 64 КБ
    if len > 65_536 {
        return Err(StorageError::Network("message header too large".into()));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await
        .map_err(|e| StorageError::Network(e.to_string()))?;
    Ok(serde_json::from_slice(&buf)?)
}

// ─── Сервер ───────────────────────────────────────────────────────────────────

/// Запускает TCP-сервер, раздающий чанки.
///
/// Принимает входящие соединения и обрабатывает каждое в отдельной задаче.
/// Блокирует текущую задачу — вызывай через `tokio::spawn`.
pub async fn run_chunk_server(
    bind_addr: SocketAddr,
    store: ChunkStore,
    bytes_uploaded: Arc<AtomicU64>,
) -> Result<(), StorageError> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| StorageError::Network(e.to_string()))?;

    info!("Chunk server listening on {}", bind_addr);

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Accept error: {}", e);
                continue;
            }
        };

        let store = store.clone();
        let bytes_uploaded = Arc::clone(&bytes_uploaded);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, store, bytes_uploaded).await {
                debug!("Connection from {} closed: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    store: ChunkStore,
    bytes_uploaded: Arc<AtomicU64>,
) -> Result<(), StorageError> {
    debug!("Incoming chunk request from {}", peer_addr);

    let request: ChunkRequest = read_message(&mut stream).await?;
    debug!(
        "Request chunk {} from {}",
        &request.chunk_hash[..8.min(request.chunk_hash.len())],
        peer_addr
    );

    match store.get(&request.chunk_hash).await {
        Ok(data) => {
            let response = ChunkResponse {
                chunk_hash: request.chunk_hash.clone(),
                status: ChunkResponseStatus::Ok,
                data_len: data.len() as u32,
            };
            write_message(&mut stream, &response).await?;
            stream.write_all(&data).await
                .map_err(|e| StorageError::Network(e.to_string()))?;
            // Учёт отданного трафика (для статистики профиля).
            bytes_uploaded.fetch_add(data.len() as u64, Ordering::Relaxed);
            debug!(
                "Sent chunk {} ({} bytes) to {}",
                &request.chunk_hash[..8],
                data.len(),
                peer_addr
            );
        }
        Err(StorageError::ChunkNotFound(_)) => {
            let response = ChunkResponse {
                chunk_hash: request.chunk_hash,
                status: ChunkResponseStatus::NotFound,
                data_len: 0,
            };
            write_message(&mut stream, &response).await?;
        }
        Err(e) => {
            error!("Error reading chunk {}: {}", &request.chunk_hash[..8], e);
            let response = ChunkResponse {
                chunk_hash: request.chunk_hash,
                status: ChunkResponseStatus::Error,
                data_len: 0,
            };
            write_message(&mut stream, &response).await?;
        }
    }

    Ok(())
}

// ─── Клиент ───────────────────────────────────────────────────────────────────

/// Запрашивает один чанк у конкретного узла.
///
/// Проверяет целостность после получения.
/// Если хэш не совпадает — возвращает `IntegrityFailure`
/// (вызывающий код должен попробовать другой узел и занести штраф репутации).
pub async fn fetch_chunk_from_peer(
    peer_addr: SocketAddr,
    chunk_hash: &str,
    my_id: &NodeId,
) -> Result<Vec<u8>, StorageError> {
    let connect = TcpStream::connect(peer_addr);
    let mut stream = timeout(FETCH_TIMEOUT, connect)
        .await
        .map_err(|_| StorageError::Timeout(chunk_hash.to_string()))?
        .map_err(|e| StorageError::Network(e.to_string()))?;

    let request = ChunkRequest {
        chunk_hash: chunk_hash.to_string(),
        requester_id: my_id.as_str().to_string(),
    };
    write_message(&mut stream, &request).await?;

    let response: ChunkResponse = timeout(FETCH_TIMEOUT, read_message(&mut stream))
        .await
        .map_err(|_| StorageError::Timeout(chunk_hash.to_string()))??;

    match response.status {
        ChunkResponseStatus::Ok => {
            if response.data_len == 0 || response.data_len > 512 * 1024 {
                return Err(StorageError::Network(format!(
                    "invalid data_len: {}",
                    response.data_len
                )));
            }
            let mut data = vec![0u8; response.data_len as usize];
            timeout(FETCH_TIMEOUT, stream.read_exact(&mut data))
                .await
                .map_err(|_| StorageError::Timeout(chunk_hash.to_string()))?
                .map_err(|e| StorageError::Network(e.to_string()))?;

            // Верифицируем — никогда не доверяем сети
            verify_chunk(chunk_hash, &data)?;
            Ok(data)
        }
        ChunkResponseStatus::NotFound => {
            Err(StorageError::ChunkNotFound(chunk_hash.to_string()))
        }
        ChunkResponseStatus::Error => {
            Err(StorageError::Network(format!(
                "peer {} returned error for chunk {}",
                peer_addr,
                &chunk_hash[..8]
            )))
        }
    }
}