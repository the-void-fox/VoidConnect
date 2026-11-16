//! HTTP-сервер сайтов на Axum.
//!
//! Адрес сайта — свой поддомен `localhost`:
//!   http://<site>.localhost:<порт>/<path...>
//! Браузеры сами направляют `*.localhost` на 127.0.0.1. Так у каждого сайта
//! свой origin (скрипты одного сайта не читают cookies, localStorage и API
//! другого), а ссылки от корня (`/style.css`) ведут внутрь сайта.
//!
//! Старый адрес `http://127.0.0.1:<порт>/<site>/<path...>` давал всем сайтам
//! один origin — теперь он только перенаправляет на адрес сайта.
//!
//! Путь, оканчивающийся на `/`, отдаёт `index.html` этой папки. Файлы берутся
//! из `void-storage` (с докачкой у пиров, с поддержкой Range). Пути `/.void/…`
//! зарезервированы за JS API ([`crate::api`]). Запросы с чужим Host (не
//! loopback) отклоняются — защита от DNS rebinding. Каждый ответ сайта несёт
//! заголовки безопасности ([`crate::security`]).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{DefaultBodyLimit, Path as AxPath, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use void_core::peer::PeerInfo;
use void_storage::StorageManager;

use crate::api::{self, SiteApi};
use crate::content_type;
use crate::registry::SiteRegistry;
use crate::security;

/// Снимок активных пиров для докачки файлов чужих сайтов по запросу.
/// `Vec` пуст для чисто локальной раздачи (все чанки уже на диске).
pub type PeerSnapshot = Arc<Mutex<Vec<PeerInfo>>>;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) registry: SiteRegistry,
    pub(crate) storage: StorageManager,
    /// Активные пиры — источник для докачки файлов сетевых сайтов.
    pub(crate) peers: PeerSnapshot,
    /// JS API (без него сайты — только статика).
    pub(crate) api: Option<SiteApi>,
}

/// Собирает роутер раздачи сайтов без JS API (только статика).
pub fn router(registry: SiteRegistry, storage: StorageManager, peers: PeerSnapshot) -> Router {
    router_with_api(registry, storage, peers, None)
}

/// Собирает роутер раздачи сайтов с JS API.
pub fn router_with_api(
    registry: SiteRegistry,
    storage: StorageManager,
    peers: PeerSnapshot,
    api: Option<SiteApi>,
) -> Router {
    let state = AppState { registry, storage, peers, api };
    let json_limit = DefaultBodyLimit::max(api::MAX_JSON_BYTES);
    Router::new()
        .route("/.void/sdk.js", get(api::sdk))
        .route("/.void/api/site", get(api::site_info))
        .route("/.void/api/me", get(api::me))
        .route("/.void/api/permissions", get(api::permissions).post(api::request_permissions).layer(json_limit))
        .route("/.void/api/profiles/:id", get(api::profile))
        .route(
            "/.void/api/records",
            get(api::list_records).put(api::put_record).delete(api::delete_record).layer(json_limit),
        )
        .route("/.void/api/events", get(api::events))
        // Тело загрузки читается потоком — общий лимит тел снят только здесь.
        .route("/.void/api/files", post(api::upload).layer(DefaultBodyLimit::disable()))
        .route("/.void/api/files/:id", get(api::file_info))
        .route("/.void/files/:id", get(api::file_content))
        .route("/.void/*rest", get(reserved))
        .route("/", get(root_handler))
        .route("/:site", get(index_handler))
        .route("/:site/", get(dir_handler))
        .route("/:site/*path", get(path_handler))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Запускает HTTP-сервер сайтов без JS API (блокирует задачу).
pub async fn serve(
    addr: SocketAddr,
    registry: SiteRegistry,
    storage: StorageManager,
    peers: PeerSnapshot,
) -> std::io::Result<()> {
    serve_with_api(addr, registry, storage, peers, None).await
}

/// Запускает HTTP-сервер сайтов с JS API (блокирует задачу).
pub async fn serve_with_api(
    addr: SocketAddr,
    registry: SiteRegistry,
    storage: StorageManager,
    peers: PeerSnapshot,
    api: Option<SiteApi>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Site server listening on http://{}", addr);
    axum::serve(listener, router_with_api(registry, storage, peers, api)).await
}

/// Заголовки безопасности на каждом ответе (см. [`crate::security`]).
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    security::site_headers(resp.headers_mut());
    resp
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

/// Порт из заголовка Host (`127.0.0.1:7704` → `7704`).
fn host_port(headers: &HeaderMap) -> Option<u16> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let (_, port) = host.rsplit_once(':')?;
    port.parse().ok()
}

/// Сайт из заголовка Host: `blog.localhost` (или `blog.void.localhost`) → `blog`.
pub(crate) fn host_site(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let name = strip_port(host).strip_suffix(".localhost")?;
    let name = name.strip_suffix(".void").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// Пускаем только loopback-адреса. Сервер слушает 127.0.0.1, но чужая страница
/// может направить свой домен на 127.0.0.1 (DNS rebinding) — такие запросы
/// приходят с её Host и получают отказ.
pub(crate) fn host_allowed(headers: &HeaderMap) -> bool {
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

/// `/.void/…`, которого нет в API: зарезервировано, файлы сайта тут не ищем.
async fn reserved() -> Response {
    (StatusCode::NOT_FOUND, "нет такого метода API").into_response()
}

/// Общий адрес `127.0.0.1:<порт>/<сайт>/<путь>` → адрес сайта.
fn redirect_to_site(headers: &HeaderMap, site: &str, path: &str) -> Response {
    let site = site.trim_end_matches(".void").to_ascii_lowercase();
    let Some(site) = void_core::dns::normalize_name(&site) else {
        return (StatusCode::NOT_FOUND, "недопустимое имя сайта").into_response();
    };
    let port = host_port(headers).map(|p| format!(":{p}")).unwrap_or_default();
    let target = format!("http://{site}.localhost{port}/{path}");
    match HeaderValue::from_str(&target) {
        Ok(v) => (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, v)]).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "недопустимый адрес").into_response(),
    }
}

async fn root_handler(State(s): State<AppState>, headers: HeaderMap) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, "index.html", &headers).await,
        None => (
            StatusCode::NOT_FOUND,
            "Сайты Void Connect: http://<имя>.localhost:<порт>/",
        )
            .into_response(),
    }
}

/// `/x`: на адресе сайта — файл `x` в его корне, иначе — перенаправление на сайт `x`.
async fn index_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(seg): AxPath<String>,
) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, &seg, &headers).await,
        None => redirect_to_site(&headers, &seg, ""),
    }
}

/// `/x/`: на адресе сайта — `x/index.html`, иначе — перенаправление на сайт `x`.
async fn dir_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(seg): AxPath<String>,
) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, &format!("{seg}/index.html"), &headers).await,
        None => redirect_to_site(&headers, &seg, ""),
    }
}

/// `/x/y…`: на адресе сайта — файл `x/y…`, иначе — перенаправление на `y…` сайта `x`.
async fn path_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath((seg, path)): AxPath<(String, String)>,
) -> Response {
    if !host_allowed(&headers) {
        return forbidden();
    }
    match host_site(&headers) {
        Some(site) => serve_file(&s, &site, &with_index(format!("{seg}/{path}")), &headers).await,
        None => redirect_to_site(&headers, &seg, &path),
    }
}

/// Файл сайта: свой код и данные сайта, с поддержкой Range (видео в статике).
async fn serve_file(s: &AppState, site: &str, path: &str, headers: &HeaderMap) -> Response {
    let Some(manifest) = s.registry.get(site).await else {
        return (StatusCode::NOT_FOUND, format!("сайт '{}' не найден", site)).into_response();
    };
    let Some(entry) = manifest.entry(path) else {
        return (StatusCode::NOT_FOUND, format!("страница '{}' не найдена", path)).into_response();
    };
    let layout = match s.storage.file_layout(&entry.file_id).await {
        Ok(l) => l,
        Err(e) => {
            return (StatusCode::SERVICE_UNAVAILABLE, format!("файл недоступен (нет сидеров?): {}", e))
                .into_response()
        }
    };
    let mut extra = HeaderMap::new();
    // Сайт могут обновить — браузер должен перепроверять.
    extra.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    api::serve_layout(s, layout, headers, content_type(path), extra).await
}
