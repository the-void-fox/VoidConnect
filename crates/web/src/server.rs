//! HTTP-сервер сайтов на Axum.
//!
//! Основной адрес сайта — свой поддомен `localhost`:
//!   http://<site>.localhost:<порт>/<path...>
//! Браузеры сами направляют `*.localhost` на 127.0.0.1. Так у каждого сайта
//! свой origin (скрипты одного сайта не читают cookies и localStorage другого),
//! а ссылки от корня (`/style.css`) ведут внутрь сайта.
//!
//! Запасной адрес (общий origin для всех сайтов):
//!   GET /<site>            → index.html сайта
//!   GET /<site>/<path...>  → файл сайта по относительному пути
//!
//! Путь, оканчивающийся на `/`, отдаёт `index.html` этой папки. Файлы берутся
//! из `void-storage` (с докачкой у пиров). Имя сайта можно указывать с зоной
//! `.void` или без неё. Запросы с чужим Host (не loopback) отклоняются — защита
//! от DNS rebinding.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, StatusCode},
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
        .route("/", get(root_handler))
        .route("/:site", get(index_handler))
        .route("/:site/", get(dir_handler))
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

/// Хост без порта: `blog.localhost:7704` → `blog.localhost`, `[::1]:80` → `[::1]`.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map_or(host, |i| &host[..=i]);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// Сайт из заголовка Host: `blog.localhost` (или `blog.void.localhost`) → `blog`.
fn host_site(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let name = strip_port(host).strip_suffix(".localhost")?;
    let name = name.strip_suffix(".void").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// Пускаем только loopback-адреса. Сервер слушает 127.0.0.1, но чужая страница
/// может направить свой домен на 127.0.0.1 (DNS rebinding) — такие запросы
/// приходят с её Host и получают отказ.
fn host_allowed(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST) else { return true }; // HTTP/1.0
    let Ok(host) = host.to_str() else { return false };
    let host = strip_port(host).to_ascii_lowercase();
    host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host.ends_with(".localhost")
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "доступ только с этого компьютера").into_response()
}

/// Путь внутри сайта: «папка/» → «папка/index.html».
fn with_index(path: String) -> String {
    if path.is_empty() || path.ends_with('/') { format!("{path}index.html") } else { path }
}

async fn root_handler(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, "index.html").await,
        None => (
            StatusCode::NOT_FOUND,
            "Сайты Void Connect: http://<имя>.localhost:<порт>/ или http://127.0.0.1:<порт>/<имя>",
        )
            .into_response(),
    }
}

/// `/x`: на адресе сайта — файл `x` в его корне, иначе — главная сайта `x`.
async fn index_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(seg): AxPath<String>,
) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, &seg).await,
        None => serve_file(&s, &seg, "index.html").await,
    }
}

/// `/x/`: на адресе сайта — `x/index.html`, иначе — главная сайта `x`.
async fn dir_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(seg): AxPath<String>,
) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, &format!("{seg}/index.html")).await,
        None => serve_file(&s, &seg, "index.html").await,
    }
}

/// `/x/y…`: на адресе сайта — файл `x/y…`, иначе — файл `y…` сайта `x`.
async fn path_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath((seg, path)): AxPath<(String, String)>,
) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, &with_index(format!("{seg}/{path}"))).await,
        None => serve_file(&s, &seg, &with_index(path)).await,
    }
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
