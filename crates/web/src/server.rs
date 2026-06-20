//! HTTP-сервер сайтов на Axum.
//!
//! Маршруты:
//!   GET /<site>            → index.html сайта
//!   GET /<site>/<path...>  → файл сайта по относительному пути
//!
//! Файлы берутся из `void-storage` (локально имеющиеся чанки). Имя сайта можно
//! указывать с зоной `.void` или без неё.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path as AxPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use void_core::peer::PeerInfo;
use void_storage::StorageManager;

use crate::content_type;
use crate::registry::SiteRegistry;

/// Снимок активных пиров для докачки файлов чужих сайтов по запросу.
/// `Vec` пуст для чисто локальной раздачи (все чанки уже на диске).
pub type PeerSnapshot = Arc<Mutex<Vec<PeerInfo>>>;

#[derive(Clone)]
struct AppState {
    registry: SiteRegistry,
    storage: StorageManager,
    /// Активные пиры — источник для докачки файлов сетевых сайтов.
    peers: PeerSnapshot,
}

/// Собирает Axum-роутер для раздачи сайтов.
pub fn router(registry: SiteRegistry, storage: StorageManager, peers: PeerSnapshot) -> Router {
    let state = AppState { registry, storage, peers };
    Router::new()
        .route("/:site", get(index_handler))
        .route("/:site/", get(index_handler))
        .route("/:site/*path", get(path_handler))
        .with_state(state)
}

/// Запускает HTTP-сервер сайтов на указанном адресе (блокирует задачу).
pub async fn serve(
    addr: SocketAddr,
    registry: SiteRegistry,
    storage: StorageManager,
    peers: PeerSnapshot,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Site server listening on http://{}", addr);
    axum::serve(listener, router(registry, storage, peers)).await
}

async fn index_handler(State(s): State<AppState>, AxPath(site): AxPath<String>) -> Response {
    serve_file(&s, &site, "index.html").await
}

async fn path_handler(
    State(s): State<AppState>,
    AxPath((site, path)): AxPath<(String, String)>,
) -> Response {
    serve_file(&s, &site, &path).await
}

async fn serve_file(s: &AppState, site: &str, path: &str) -> Response {
    let Some(manifest) = s.registry.get(site).await else {
        return (StatusCode::NOT_FOUND, format!("сайт '{}' не найден", site)).into_response();
    };
    let Some(entry) = manifest.entry(path) else {
        return (StatusCode::NOT_FOUND, format!("страница '{}' не найдена", path)).into_response();
    };
    // Снимок активных пиров для возможной докачки (для своих сайтов чанки уже
    // локальны → докачка не понадобится). Гард std::Mutex держим вне await.
    let peers = { s.peers.lock().unwrap().clone() };
    match s.storage.read_or_fetch_file(&entry.file_id, &peers).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, content_type(path))], bytes).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("файл недоступен (нет сидеров?): {}", e),
        )
            .into_response(),
    }
}
