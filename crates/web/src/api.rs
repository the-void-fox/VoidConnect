//! JS API для сайтов сети.
//!
//! Сайт подключает `/.void/sdk.js` и через него обращается к узлу
//! пользователя: кто я (с разрешения), профили других, общие записи сайта
//! (видео, комментарии, лайки), загрузка файлов в сеть и их потоковая отдача.
//! Все вызовы идут на origin самого сайта (`http://<имя>.localhost:<порт>`),
//! и имя сайта узел берёт из заголовка Host — сайт не может действовать от
//! имени другого сайта. Модель защиты — в [`crate::security`].
//!
//! | Метод и путь                     | Разрешение | Что делает                         |
//! |----------------------------------|------------|------------------------------------|
//! | `GET  /.void/api/site`           | —          | имя и владелец сайта               |
//! | `GET  /.void/api/me`             | identity   | ID, имя, аватар пользователя       |
//! | `GET  /.void/api/permissions`    | —          | выданные сайту разрешения          |
//! | `POST /.void/api/permissions`    | —          | спросить разрешения (диалог в окне) |
//! | `GET  /.void/api/profiles/:id`   | —          | публичный профиль узла             |
//! | `GET  /.void/api/records`        | —          | выборка записей сайта              |
//! | `PUT  /.void/api/records`        | publish    | создать/изменить свою запись       |
//! | `DELETE /.void/api/records`      | publish    | удалить свою запись                |
//! | `WS   /.void/api/events`         | —          | поток изменений записей            |
//! | `POST /.void/api/files`          | вопрос     | опубликовать файл (диалог в окне)  |
//! | `GET  /.void/api/files/:id`      | —          | сведения о файле                   |
//! | `GET  /.void/files/:id`          | —          | содержимое файла (Range, потоком)  |

// Ошибка обработчика — готовый HTTP-ответ (обычный приём в axum); он больше
// 128 байт, но путь ошибки не горячий.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Path as AxPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use void_core::identity::NodeId;
use void_core::sanitize::{is_hex64, safe_file_name};
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_db::DbPool;

use crate::consent::{ConsentBroker, ConsentKind, Refused, REQUEST_TTL};
use crate::permissions::{Permission, PermissionStore};
use crate::records::{self, Applied, RecordQuery, SiteRecord};
use crate::security;
use crate::server::{host_allowed, host_site, AppState};

/// Публичный профиль узла — то, что видит сайт.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PublicProfile {
    pub id: String,
    pub name: String,
    /// `data:image/png;base64,…` или `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Доверие к узлу с точки зрения пользователя (сеть доверия).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTag {
    /// Проверен лично.
    Verified,
    /// Через знакомых.
    Trusted,
    /// Освоившийся.
    Settled,
    /// Незнакомец.
    Stranger,
    /// Заблокирован пользователем — его данные сайтам не показываются.
    Blocked,
}

/// Что API знает об узле пользователя (реализует backend приложения).
pub trait NodeView: Send + Sync + 'static {
    /// Свой профиль.
    fn me(&self) -> PublicProfile;
    /// Профиль другого узла, если известен.
    fn profile(&self, id: &NodeId) -> Option<PublicProfile>;
    /// Доверие к узлу.
    fn trust(&self, id: &NodeId) -> TrustTag;
}

/// Сколько своих записей на одном сайте мы готовы хранить.
pub const OWN_RECORD_QUOTA: i64 = 10_000;
/// Предел загружаемого файла.
pub const MAX_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Сколько байт отдаём на один Range-запрос (браузер дозапросит остальное).
pub const MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;
/// Файлы до этого размера отдаются одним куском, больше — потоком по чанкам.
pub const SMALL_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Тело JSON-запроса API.
pub const MAX_JSON_BYTES: usize = 64 * 1024;
/// Одновременных потоков событий на сайт (одна открытая вкладка — один поток).
pub const MAX_STREAMS_PER_SITE: u64 = 32;

/// Частота: пополнение в секунду и запас.
#[derive(Clone, Copy)]
struct Rate {
    per_sec: f64,
    burst: f64,
}

/// Любые вызовы API сайтом — защита узла от зациклившегося скрипта.
const API_RATE: Rate = Rate { per_sec: 100.0, burst: 300.0 };
/// Запись/удаление записей сайтом от имени пользователя. Ограничивает и
/// скорость «червя», если сайт уязвим к XSS.
const WRITE_RATE: Rate = Rate { per_sec: 1.0, burst: 30.0 };

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Состояние API (общее для всех сайтов). Клонируется дёшево.
#[derive(Clone)]
pub struct SiteApi {
    node: Arc<dyn NodeView>,
    signing: Arc<SigningKeypair>,
    me: NodeId,
    db: Option<DbPool>,
    /// Новые свои записи — backend разошлёт их по сети.
    record_out: mpsc::UnboundedSender<SignedMessage>,
    /// Изменения записей (свои и из сети) — для потоков событий.
    events: broadcast::Sender<SiteRecord>,
    permissions: PermissionStore,
    consent: ConsentBroker,
    uploads_dir: PathBuf,
    /// Опубликованные загрузкой файлы — backend объявит их сети.
    file_out: mpsc::UnboundedSender<String>,
    buckets: Arc<Mutex<HashMap<(String, &'static str), Bucket>>>,
    streams: Arc<Mutex<HashMap<String, Arc<AtomicU64>>>>,
}

/// Что нужно, чтобы собрать [`SiteApi`].
pub struct SiteApiParts {
    pub node: Arc<dyn NodeView>,
    pub signing: Arc<SigningKeypair>,
    pub db: Option<DbPool>,
    pub record_out: mpsc::UnboundedSender<SignedMessage>,
    pub events: broadcast::Sender<SiteRecord>,
    pub permissions: PermissionStore,
    pub consent: ConsentBroker,
    pub uploads_dir: PathBuf,
    pub file_out: mpsc::UnboundedSender<String>,
}

impl SiteApi {
    pub fn new(p: SiteApiParts) -> Self {
        let me = NodeId::from_public_key_bytes(&p.signing.public_bytes());
        // Недокачанные загрузки прошлого запуска.
        if let Ok(dir) = std::fs::read_dir(&p.uploads_dir) {
            for e in dir.flatten() {
                if e.path().extension().is_some_and(|x| x == "part") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Self {
            node: p.node,
            signing: p.signing,
            me,
            db: p.db,
            record_out: p.record_out,
            events: p.events,
            permissions: p.permissions,
            consent: p.consent,
            uploads_dir: p.uploads_dir,
            file_out: p.file_out,
            buckets: Default::default(),
            streams: Default::default(),
        }
    }

    pub fn permissions(&self) -> &PermissionStore {
        &self.permissions
    }

    pub fn consent(&self) -> &ConsentBroker {
        &self.consent
    }

    /// Поток изменений записей (backend публикует сюда записи из сети).
    pub fn events(&self) -> broadcast::Sender<SiteRecord> {
        self.events.clone()
    }

    fn take(&self, site: &str, class: &'static str, rate: Rate) -> bool {
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 10_000 {
            map.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(60));
        }
        let b = map
            .entry((site.to_string(), class))
            .or_insert(Bucket { tokens: rate.burst, last: now });
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * rate.per_sec).min(rate.burst);
        b.last = now;
        if b.tokens < 1.0 {
            return false;
        }
        b.tokens -= 1.0;
        true
    }
}

// ─── Ответы ──────────────────────────────────────────────────────────────────

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut r = (status, Json(serde_json::json!({ "error": message, "code": code }))).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn json<T: Serialize>(v: T) -> Response {
    let mut r = Json(v).into_response();
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn need_permission(p: Permission) -> Response {
    let mut r = error(
        StatusCode::FORBIDDEN,
        "permission_required",
        &format!("нужно разрешение «{}»", p.as_str()),
    );
    if let Ok(v) = HeaderValue::from_str(p.as_str()) {
        r.headers_mut().insert("x-void-permission", v);
    }
    r
}

/// Запись в ответе API.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordOut {
    collection: String,
    key: String,
    author: String,
    updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    data: Option<serde_json::Value>,
    deleted: bool,
    trust: TrustTag,
    /// Автор — сам пользователь. Только при разрешении identity: иначе сайт
    /// узнал бы ID пользователя без спроса.
    #[serde(skip_serializing_if = "Option::is_none")]
    mine: Option<bool>,
}

impl RecordOut {
    fn new(r: SiteRecord, trust: TrustTag, me: Option<&NodeId>) -> Self {
        Self {
            mine: me.map(|m| *m == r.author),
            deleted: r.data.is_none(),
            collection: r.collection,
            key: r.key,
            author: r.author.0,
            updated_at: r.updated_at,
            link: r.link,
            data: r.data,
            trust,
        }
    }
}

// ─── Проверки ────────────────────────────────────────────────────────────────

/// Общая проверка вызова API: адрес сайта, известный сайт, тот же origin,
/// лимит частоты. Возвращает имя сайта и API.
async fn guard(s: &AppState, headers: &HeaderMap) -> Result<(String, SiteApi), Response> {
    if !host_allowed(headers) {
        return Err(error(StatusCode::FORBIDDEN, "forbidden", "доступ только с этого компьютера"));
    }
    let Some(site) = host_site(headers) else {
        return Err(error(StatusCode::NOT_FOUND, "no_site", "API доступно только на адресе сайта"));
    };
    let Some(api) = s.api.clone() else {
        return Err(error(StatusCode::SERVICE_UNAVAILABLE, "disabled", "API сайтов выключено"));
    };
    if !security::api_request_allowed(headers) {
        return Err(error(StatusCode::FORBIDDEN, "cross_origin", "запрос не со страницы этого сайта"));
    }
    if s.registry.get(&site).await.is_none() {
        return Err(error(StatusCode::NOT_FOUND, "no_site", "сайт не найден"));
    }
    if !api.take(&site, "api", API_RATE) {
        return Err(error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "слишком много запросов"));
    }
    Ok((site, api))
}

fn db_of(api: &SiteApi) -> Result<&DbPool, Response> {
    api.db
        .as_ref()
        .ok_or_else(|| error(StatusCode::SERVICE_UNAVAILABLE, "no_db", "база данных недоступна"))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// ─── Сайт, пользователь, профили ─────────────────────────────────────────────

pub(crate) async fn site_info(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(m) = s.registry.get(&site).await else {
        return error(StatusCode::NOT_FOUND, "no_site", "сайт не найден");
    };
    let owner_name = if m.owner == api.me {
        Some(api.node.me().name)
    } else {
        api.node.profile(&m.owner).map(|p| p.name)
    };
    json(serde_json::json!({
        "name": m.name,
        "owner": {
            "id": m.owner.as_str(),
            "name": owner_name,
            "trust": if m.owner == api.me { TrustTag::Verified } else { api.node.trust(&m.owner) },
        },
        "publishedAt": m.created_at * 1000,
        "files": m.entries.len(),
    }))
}

pub(crate) async fn me(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !api.permissions.has(&site, Permission::Identity) {
        return need_permission(Permission::Identity);
    }
    json(api.node.me())
}

pub(crate) async fn permissions(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    json(serde_json::json!({ "granted": api.permissions.of(&site) }))
}

#[derive(Deserialize)]
pub(crate) struct PermissionRequest {
    permissions: Vec<String>,
}

pub(crate) async fn request_permissions(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(req) = serde_json::from_slice::<PermissionRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request", "ожидался {\"permissions\": [...]}");
    };
    let mut wanted: Vec<Permission> = Vec::new();
    for p in &req.permissions {
        match Permission::parse(p) {
            Some(p) if !wanted.contains(&p) => wanted.push(p),
            Some(_) => {}
            None => return error(StatusCode::BAD_REQUEST, "unknown_permission", &format!("нет разрешения «{p}»")),
        }
    }
    let missing: Vec<Permission> =
        wanted.iter().copied().filter(|p| !api.permissions.has(&site, *p)).collect();
    if missing.is_empty() {
        return json(serde_json::json!({ "granted": api.permissions.of(&site) }));
    }
    let rx = match api.consent.ask(&site, ConsentKind::Permissions(missing.clone())) {
        Ok(rx) => rx,
        Err(Refused::Cooldown) => {
            return error(StatusCode::TOO_MANY_REQUESTS, "cooldown", "пользователь недавно отказал — спросите позже")
        }
        Err(Refused::TooMany) => {
            return error(StatusCode::TOO_MANY_REQUESTS, "busy", "сайт уже ждёт ответа пользователя")
        }
    };
    let allowed = tokio::time::timeout(REQUEST_TTL + Duration::from_secs(5), rx)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    if !allowed {
        return error(StatusCode::FORBIDDEN, "denied", "пользователь не разрешил");
    }
    api.permissions.grant(&site, &missing);
    json(serde_json::json!({ "granted": api.permissions.of(&site) }))
}

pub(crate) async fn profile(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    let (_site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let id = id.to_ascii_lowercase();
    if !is_hex64(&id) {
        return error(StatusCode::BAD_REQUEST, "bad_id", "ID — 64 hex-символа");
    }
    let id = NodeId(id);
    let trust = if id == api.me { TrustTag::Verified } else { api.node.trust(&id) };
    if trust == TrustTag::Blocked {
        return error(StatusCode::NOT_FOUND, "not_found", "профиль не найден");
    }
    let found = if id == api.me { Some(api.node.me()) } else { api.node.profile(&id) };
    match found {
        Some(p) => json(serde_json::json!({
            "id": p.id, "name": p.name, "avatar": p.avatar,
            "status": p.status, "description": p.description, "trust": trust,
        })),
        None => error(StatusCode::NOT_FOUND, "not_found", "профиль не найден"),
    }
}

// ─── Записи ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct RecordsParams {
    collection: String,
    author: Option<String>,
    key: Option<String>,
    link: Option<String>,
    since: Option<i64>,
    before: Option<i64>,
    limit: Option<i64>,
}

pub(crate) async fn list_records(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RecordsParams>,
) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let db = match db_of(&api) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if !records::valid_collection(&q.collection) {
        return error(StatusCode::BAD_REQUEST, "bad_collection", "имя коллекции: 1–32 символа [a-z0-9_-]");
    }
    let query = RecordQuery {
        site: site.clone(),
        collection: q.collection,
        author: q.author.map(|a| a.to_ascii_lowercase()),
        key: q.key,
        link: q.link,
        since: q.since,
        before: q.before,
        limit: q.limit.unwrap_or(100),
        include_deleted: false,
    };
    let found = match records::query(db, &query).await {
        Ok(r) => r,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, "db", &e.to_string()),
    };
    let me = api.permissions.has(&site, Permission::Identity).then_some(&api.me);
    let mut trust_cache: HashMap<NodeId, TrustTag> = HashMap::new();
    let out: Vec<RecordOut> = found
        .into_iter()
        .filter_map(|r| {
            let t = *trust_cache.entry(r.author.clone()).or_insert_with(|| {
                if r.author == api.me { TrustTag::Verified } else { api.node.trust(&r.author) }
            });
            (t != TrustTag::Blocked).then(|| RecordOut::new(r, t, me))
        })
        .collect();
    json(serde_json::json!({ "records": out }))
}

#[derive(Deserialize)]
pub(crate) struct PutRecord {
    collection: String,
    key: String,
    #[serde(default)]
    link: Option<String>,
    data: serde_json::Value,
}

pub(crate) async fn put_record(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Ok(req) = serde_json::from_slice::<PutRecord>(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request", "ожидался {collection, key, data, link?}");
    };
    if req.data.is_null() {
        return error(StatusCode::BAD_REQUEST, "bad_request", "для удаления используйте DELETE");
    }
    write_record(&site, &api, req.collection, req.key, req.link, Some(req.data)).await
}

#[derive(Deserialize)]
pub(crate) struct DeleteParams {
    collection: String,
    key: String,
}

pub(crate) async fn delete_record(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DeleteParams>,
) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    write_record(&site, &api, q.collection, q.key, None, None).await
}

/// Подписывает и сохраняет свою запись (или надгробие), отдаёт её в сеть и
/// подписчикам событий.
async fn write_record(
    site: &str,
    api: &SiteApi,
    collection: String,
    key: String,
    link: Option<String>,
    data: Option<serde_json::Value>,
) -> Response {
    if !api.permissions.has(site, Permission::Publish) {
        return need_permission(Permission::Publish);
    }
    let db = match db_of(api) {
        Ok(d) => d,
        Err(r) => return r,
    };
    if !api.take(site, "write", WRITE_RATE) {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "слишком частая запись");
    }
    let prev = match records::current(db, site, &collection, &api.me, &key).await {
        Ok(v) => v,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, "db", &e.to_string()),
    };
    // Удаление: запись должна существовать; надгробие сохраняет её ссылку.
    let link = match (&data, &prev) {
        (None, None) | (None, Some((_, _, true))) => {
            return error(StatusCode::NOT_FOUND, "not_found", "записи нет")
        }
        (None, Some((_, old_link, false))) => old_link.clone(),
        (Some(_), _) => link,
    };
    let now = now_ms();
    let record = SiteRecord {
        site: site.to_string(),
        collection,
        key,
        author: api.me.clone(),
        updated_at: now.max(prev.map(|p| p.0).unwrap_or(0) + 1),
        link,
        data,
    };
    let signed = match record.sign(&api.signing) {
        Ok(s) => s,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid", &e.to_string()),
    };
    match records::apply_signed(db, &signed, OWN_RECORD_QUOTA, now).await {
        Ok(Applied::Changed(rec)) => {
            let _ = api.record_out.send(signed);
            let _ = api.events.send(rec.clone());
            json(RecordOut::new(rec, TrustTag::Verified, Some(&api.me)))
        }
        Ok(Applied::Stale) => error(StatusCode::CONFLICT, "stale", "есть более новая версия"),
        Ok(Applied::Refused(why)) => error(StatusCode::INSUFFICIENT_STORAGE, "quota", why),
        Err(e) => error(StatusCode::BAD_REQUEST, "invalid", &e.to_string()),
    }
}

/// Счётчик открытых потоков сайта; уменьшается, когда поток закрыт.
struct StreamSlot(Arc<AtomicU64>);

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Живые изменения записей сайта — WebSocket `/.void/api/events`.
///
/// Именно WebSocket, а не поток HTTP: браузер держит не больше 6 HTTP/1.1-
/// соединений на адрес, и пара подписок в каждой из трёх вкладок занимала их
/// все — остальные запросы к API вставали в очередь навсегда. WebSocket в этот
/// лимит не входит, а SDK открывает одно соединение на страницу.
///
/// Заголовок `X-Void-Api` в WebSocket не поставить, зато браузер всегда шлёт
/// `Origin` — он обязан совпадать с адресом сайта (защита от подключения со
/// страницы чужого сайта).
pub(crate) async fn events(
    State(s): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !host_allowed(&headers) {
        return error(StatusCode::FORBIDDEN, "forbidden", "доступ только с этого компьютера");
    }
    let Some(site) = host_site(&headers) else {
        return error(StatusCode::NOT_FOUND, "no_site", "API доступно только на адресе сайта");
    };
    let Some(api) = s.api.clone() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "disabled", "API сайтов выключено");
    };
    if !headers.contains_key(header::ORIGIN) || !security::same_origin_request(&headers, false) {
        return error(StatusCode::FORBIDDEN, "cross_origin", "подключение не со страницы этого сайта");
    }
    if s.registry.get(&site).await.is_none() {
        return error(StatusCode::NOT_FOUND, "no_site", "сайт не найден");
    }
    if !api.take(&site, "api", API_RATE) {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "слишком много запросов");
    }
    let counter = {
        let mut map = api.streams.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(map.entry(site.clone()).or_default())
    };
    if counter.fetch_add(1, Ordering::SeqCst) >= MAX_STREAMS_PER_SITE {
        counter.fetch_sub(1, Ordering::SeqCst);
        return error(StatusCode::TOO_MANY_REQUESTS, "too_many_streams", "слишком много открытых вкладок сайта");
    }
    let slot = StreamSlot(counter);
    ws.max_message_size(4096)
        .on_upgrade(move |socket| events_loop(socket, api, site, slot))
}

async fn events_loop(mut socket: WebSocket, api: SiteApi, site: String, _slot: StreamSlot) {
    let mut rx = api.events.subscribe();
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    ping.tick().await;
    loop {
        let out = tokio::select! {
            ev = rx.recv() => match ev {
                Ok(r) if r.site == site => {
                    let trust = if r.author == api.me { TrustTag::Verified } else { api.node.trust(&r.author) };
                    if trust == TrustTag::Blocked {
                        continue;
                    }
                    // Разрешение могли выдать или отозвать на ходу — смотрим каждый раз.
                    let me = api.permissions.has(&site, Permission::Identity).then_some(&api.me);
                    let rec = RecordOut::new(r, trust, me);
                    Message::Text(serde_json::json!({ "type": "record", "record": rec }).to_string())
                }
                Ok(_) => continue,
                // Отстали от потока — пусть страница перечитает данные.
                Err(broadcast::error::RecvError::Lagged(_)) => Message::Text(r#"{"type":"resync"}"#.into()),
                Err(broadcast::error::RecvError::Closed) => break,
            },
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => continue,
            },
            _ = ping.tick() => Message::Ping(Vec::new()),
        };
        if socket.send(out).await.is_err() {
            break;
        }
    }
}

// ─── Файлы ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct UploadParams {
    name: String,
}

pub(crate) async fn upload(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UploadParams>,
    body: Body,
) -> Response {
    let (site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = safe_file_name(&q.name);
    if name.is_empty() || name.len() > 200 {
        return error(StatusCode::BAD_REQUEST, "bad_name", "недопустимое имя файла");
    }
    let Some(size) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return error(StatusCode::LENGTH_REQUIRED, "length_required", "нужен Content-Length");
    };
    if size == 0 || size > MAX_UPLOAD_BYTES {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "файл пустой или больше 4 ГБ");
    }

    // Пользователь подтверждает в окне приложения — до приёма байт.
    let rx = match api.consent.ask(&site, ConsentKind::Upload { name: name.clone(), size }) {
        Ok(rx) => rx,
        Err(Refused::Cooldown) => {
            return error(StatusCode::TOO_MANY_REQUESTS, "cooldown", "пользователь только что отказал — подождите")
        }
        Err(Refused::TooMany) => {
            return error(StatusCode::TOO_MANY_REQUESTS, "busy", "сайт уже ждёт ответа пользователя")
        }
    };
    let allowed = tokio::time::timeout(REQUEST_TTL + Duration::from_secs(5), rx)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    if !allowed {
        return error(StatusCode::FORBIDDEN, "denied", "пользователь не разрешил загрузку");
    }

    if let Err(e) = tokio::fs::create_dir_all(&api.uploads_dir).await {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "io", &e.to_string());
    }
    let tmp = api.uploads_dir.join(format!("{:016x}.part", rand::random::<u64>()));
    let result = receive_body(body, &tmp, size).await;
    let file_id = match result {
        Ok(()) => s.storage.publish_file_as(&tmp, &name).await,
        Err(r) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return r;
        }
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    match file_id {
        Ok(id) => {
            let _ = api.file_out.send(id.clone());
            let (mime, _) = security::safe_file_type(&name);
            json(serde_json::json!({ "fileId": id, "name": name, "size": size, "type": mime }))
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, "storage", &e.to_string()),
    }
}

/// Принимает тело ровно в `size` байт во временный файл.
async fn receive_body(body: Body, path: &std::path::Path, size: u64) -> Result<(), Response> {
    use tokio::io::AsyncWriteExt;
    let io = |e: std::io::Error| error(StatusCode::INTERNAL_SERVER_ERROR, "io", &e.to_string());
    let mut file = tokio::fs::File::create(path).await.map_err(io)?;
    let mut got: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| error(StatusCode::BAD_REQUEST, "aborted", "загрузка прервана"))?;
        got += chunk.len() as u64;
        if got > size {
            return Err(error(StatusCode::BAD_REQUEST, "size_mismatch", "данных больше, чем заявлено"));
        }
        file.write_all(&chunk).await.map_err(io)?;
    }
    if got != size {
        return Err(error(StatusCode::BAD_REQUEST, "size_mismatch", "данных меньше, чем заявлено"));
    }
    file.flush().await.map_err(io)?;
    Ok(())
}

pub(crate) async fn file_info(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    let (_site, api) = match guard(&s, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !is_hex64(&id) {
        return error(StatusCode::BAD_REQUEST, "bad_id", "ID файла — 64 hex-символа");
    }
    let layout = match s.storage.file_layout(&id).await {
        Ok(l) => l,
        Err(_) => return error(StatusCode::NOT_FOUND, "not_found", "файл неизвестен"),
    };
    let publisher = match s.storage.file_manifest(&id).await {
        Ok(Some(m)) => m.publisher.map(|p| p.0),
        _ => None,
    };
    if publisher.as_deref().is_some_and(|p| api.node.trust(&NodeId(p.to_string())) == TrustTag::Blocked) {
        return error(StatusCode::NOT_FOUND, "not_found", "файл неизвестен");
    }
    let local = layout.chunks.iter().filter(|c| c.is_local).count();
    let (mime, inline) = security::safe_file_type(&layout.name);
    json(serde_json::json!({
        "id": layout.file_id,
        "name": safe_file_name(&layout.name),
        "size": layout.size,
        "type": mime,
        "playable": inline,
        "publisher": publisher,
        "local": if layout.chunks.is_empty() { 1.0 } else { local as f64 / layout.chunks.len() as f64 },
    }))
}

/// Содержимое пользовательского файла — безопасного типа, с Range.
pub(crate) async fn file_content(
    State(s): State<AppState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    if !host_allowed(&headers) || host_site(&headers).is_none() {
        return error(StatusCode::NOT_FOUND, "no_site", "файлы доступны только на адресе сайта");
    }
    // `<video src>` не ставит наш заголовок — проверяем origin/Sec-Fetch-Site.
    if !security::same_origin_request(&headers, true) {
        return error(StatusCode::FORBIDDEN, "cross_origin", "запрос не со страницы этого сайта");
    }
    if !is_hex64(&id) {
        return error(StatusCode::BAD_REQUEST, "bad_id", "ID файла — 64 hex-символа");
    }
    let layout = match s.storage.file_layout(&id).await {
        Ok(l) => l,
        Err(_) => return error(StatusCode::NOT_FOUND, "not_found", "файл неизвестен"),
    };
    let (mime, inline) = security::safe_file_type(&layout.name);
    let mut extra = HeaderMap::new();
    extra.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(security::FILE_CSP));
    if let Ok(v) = HeaderValue::from_str(&security::content_disposition(&layout.name, inline)) {
        extra.insert(header::CONTENT_DISPOSITION, v);
    }
    // file_id — хэш содержимого: файл по этому адресу никогда не меняется.
    extra.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=31536000, immutable"));
    serve_layout(&s, layout, &headers, mime, extra).await
}

/// Разбор `Range: bytes=…` (один диапазон). `None` — заголовка нет или
/// диапазонов несколько (отдаём файл целиком); `Some(Err)` — вне файла.
fn parse_range(headers: &HeaderMap, size: u64) -> Option<Result<(u64, u64), ()>> {
    let v = headers.get(header::RANGE)?.to_str().ok()?;
    let spec = v.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if size == 0 {
        return Some(Err(()));
    }
    let r = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return Some(Err(()));
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end: u64 = if b.is_empty() { size - 1 } else { b.parse::<u64>().ok()?.min(size - 1) };
        if start > end || start >= size {
            return Some(Err(()));
        }
        (start, end)
    };
    Some(Ok(r))
}

/// Отдаёт файл хранилища по раскладке: Range → 206 (не больше
/// [`MAX_RANGE_BYTES`]), маленький файл — целиком, большой — потоком по
/// чанкам. Недостающие чанки докачиваются у пиров по ходу.
pub(crate) async fn serve_layout(
    s: &AppState,
    layout: void_storage::FileLayout,
    headers: &HeaderMap,
    content_type: &'static str,
    extra: HeaderMap,
) -> Response {
    let peers = { s.peers.lock().unwrap_or_else(|e| e.into_inner()).clone() };
    let size = layout.size;
    let mut resp = match parse_range(headers, size) {
        Some(Err(())) => {
            let mut r = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            if let Ok(v) = HeaderValue::from_str(&format!("bytes */{size}")) {
                r.headers_mut().insert(header::CONTENT_RANGE, v);
            }
            return r;
        }
        Some(Ok((start, end))) => {
            let end = end.min(start + MAX_RANGE_BYTES - 1);
            match s.storage.read_range(&layout, start, end, &peers).await {
                Ok(bytes) => {
                    let mut r = (StatusCode::PARTIAL_CONTENT, bytes).into_response();
                    if let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end}/{size}")) {
                        r.headers_mut().insert(header::CONTENT_RANGE, v);
                    }
                    r
                }
                Err(e) => return unavailable(e),
            }
        }
        None if size == 0 => Body::empty().into_response(),
        None if size <= SMALL_FILE_BYTES => match s.storage.read_range(&layout, 0, size - 1, &peers).await {
            Ok(bytes) => bytes.into_response(),
            Err(e) => return unavailable(e),
        },
        None => {
            // Первый чанк читаем заранее: если файла нет ни у кого, ответим
            // ошибкой, а не оборванным потоком.
            let first_end = layout.chunks.first().map(|c| c.size.saturating_sub(1)).unwrap_or(0);
            let first = match s.storage.read_range(&layout, 0, first_end, &peers).await {
                Ok(b) => b,
                Err(e) => return unavailable(e),
            };
            let storage = s.storage.clone();
            let state = (storage, layout, peers, 1usize, Some(first));
            let stream = futures_util::stream::unfold(state, |mut st| async move {
                if let Some(first) = st.4.take() {
                    return Some((Ok::<_, std::io::Error>(Bytes::from(first)), st));
                }
                let (storage, layout, peers, next, _) = &mut st;
                let c = layout.chunks.get(*next)?.clone();
                *next += 1;
                match storage.read_range(layout, c.offset, c.offset + c.size - 1, peers).await {
                    Ok(b) => Some((Ok(Bytes::from(b)), st)),
                    Err(e) => Some((Err(std::io::Error::other(e.to_string())), st)),
                }
            });
            let mut r = Body::from_stream(stream).into_response();
            if let Ok(v) = HeaderValue::from_str(&size.to_string()) {
                r.headers_mut().insert(header::CONTENT_LENGTH, v);
            }
            r
        }
    };
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    for (k, v) in extra.iter() {
        h.insert(k.clone(), v.clone());
    }
    resp
}

fn unavailable(e: void_storage::StorageError) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, format!("файл недоступен (нет сидеров?): {e}")).into_response()
}

/// SDK для страниц сайтов.
pub(crate) async fn sdk() -> Response {
    let mut r = include_str!("sdk.js").into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(range: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert(header::RANGE, HeaderValue::from_str(range).unwrap());
        m
    }

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range(&HeaderMap::new(), 100), None);
        assert_eq!(parse_range(&h("bytes=0-9"), 100), Some(Ok((0, 9))));
        assert_eq!(parse_range(&h("bytes=90-"), 100), Some(Ok((90, 99))));
        assert_eq!(parse_range(&h("bytes=-10"), 100), Some(Ok((90, 99))));
        assert_eq!(parse_range(&h("bytes=50-500"), 100), Some(Ok((50, 99))));
        assert_eq!(parse_range(&h("bytes=100-"), 100), Some(Err(())));
        assert_eq!(parse_range(&h("bytes=9-3"), 100), Some(Err(())));
        assert_eq!(parse_range(&h("bytes=0-1,5-6"), 100), None, "несколько диапазонов — целиком");
        assert_eq!(parse_range(&h("items=0-1"), 100), None);
    }
}
