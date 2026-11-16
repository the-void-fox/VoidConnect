//! Сквозные тесты JS API сайтов: запросы к роутеру без сети (tower oneshot).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tokio::sync::{broadcast, mpsc};
use tower::ServiceExt;
use void_core::identity::NodeId;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_storage::{ChunkStore, StorageManager};
use void_web::records::{self, SiteRecord};
use void_web::{
    publish_site, router_with_api, ConsentBroker, ConsentKind, NodeView, Permission, PermissionStore,
    PublicProfile, SiteApi, SiteApiParts, SiteRegistry, TrustTag,
};

fn kp(seed: u8) -> SigningKeypair {
    SigningKeypair::from_seed(&[seed; 32]).unwrap()
}

fn id(seed: u8) -> NodeId {
    NodeId::from_public_key_bytes(&kp(seed).public_bytes())
}

/// Узел пользователя в тестах: «я» = ключ 1, узел 3 заблокирован.
struct TestNode;

impl NodeView for TestNode {
    fn me(&self) -> PublicProfile {
        PublicProfile { id: id(1).0, name: "Алиса".into(), avatar: None, status: None, description: None }
    }
    fn profile(&self, node: &NodeId) -> Option<PublicProfile> {
        (*node == id(2)).then(|| PublicProfile {
            id: id(2).0,
            name: "Боб".into(),
            avatar: None,
            status: Some("online".into()),
            description: None,
        })
    }
    fn trust(&self, node: &NodeId) -> TrustTag {
        if *node == id(3) { TrustTag::Blocked } else if *node == id(2) { TrustTag::Trusted } else { TrustTag::Stranger }
    }
}

struct Env {
    _dir: tempfile::TempDir,
    app: Router,
    pool: void_db::DbPool,
    perms: PermissionStore,
    consent: ConsentBroker,
    records_rx: mpsc::UnboundedReceiver<SignedMessage>,
    files_rx: mpsc::UnboundedReceiver<String>,
    events: broadcast::Sender<SiteRecord>,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let pool = void_db::open(&dir.path().join("db.sqlite")).await.unwrap();
    let store = ChunkStore::new(dir.path().join("chunks")).await.unwrap();
    let storage = StorageManager::new(pool.clone(), store, Arc::new(kp(1))).await.unwrap();

    let site_dir = dir.path().join("site");
    std::fs::create_dir_all(&site_dir).unwrap();
    std::fs::write(site_dir.join("index.html"), b"<h1>tube</h1>").unwrap();
    let registry = SiteRegistry::new();
    registry.register(publish_site(&storage, &site_dir, "tube", &kp(2)).await.unwrap()).await;
    registry.register(publish_site(&storage, &site_dir, "evil", &kp(3)).await.unwrap()).await;

    let (record_out, records_rx) = mpsc::unbounded_channel();
    let (file_out, files_rx) = mpsc::unbounded_channel();
    let (events, _) = broadcast::channel(64);
    let perms = PermissionStore::default();
    let consent = ConsentBroker::new();
    let api = SiteApi::new(SiteApiParts {
        node: Arc::new(TestNode),
        signing: Arc::new(kp(1)),
        db: Some(pool.clone()),
        record_out,
        events: events.clone(),
        permissions: perms.clone(),
        consent: consent.clone(),
        uploads_dir: dir.path().join("uploads"),
        file_out,
    });
    let app = router_with_api(registry, storage, Arc::new(Mutex::new(Vec::new())), Some(api));
    Env { _dir: dir, app, pool, perms, consent, records_rx, files_rx, events }
}

const HOST: &str = "tube.localhost:7704";
const ORIGIN: &str = "http://tube.localhost:7704";

/// Запрос со страницы сайта: как его шлёт браузер через SDK.
fn api(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST)
        .header("origin", ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header("x-void-api", "1")
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, body)
}

async fn send_json(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let (status, _, body) = send(app, req).await;
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

/// Отвечает на первый вопрос к пользователю, когда он появится.
fn answer_when_asked(consent: ConsentBroker, allow: bool) -> tokio::task::JoinHandle<ConsentKind> {
    tokio::spawn(async move {
        loop {
            if let Some(req) = consent.pending().into_iter().next() {
                consent.answer(req.id, allow);
                return req.kind;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
}

#[tokio::test]
async fn foreign_pages_cannot_call_api() {
    let e = env().await;
    let get = |pairs: &[(&str, &str)]| {
        let mut b = Request::builder().uri("/.void/api/site");
        for (k, v) in pairs {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    };
    // Своя страница — можно.
    let (s, _) = send_json(&e.app, api("GET", "/.void/api/site").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    // Без заголовка API (форма, <img>, простой fetch чужого сайта).
    let (s, v) = send_json(&e.app, get(&[("host", HOST), ("sec-fetch-site", "same-origin")])).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("cross_origin")));
    // Другой сайт сети (для браузера same-site!).
    let (s, _) = send_json(
        &e.app,
        get(&[("host", HOST), ("x-void-api", "1"), ("origin", "http://evil.localhost:7704"), ("sec-fetch-site", "same-site")]),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Страница из интернета.
    let (s, _) = send_json(&e.app, get(&[("host", HOST), ("x-void-api", "1"), ("sec-fetch-site", "cross-site")])).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // DNS rebinding — чужой Host.
    let (s, _, _) = send(&e.app, get(&[("host", "evil.example:7704"), ("x-void-api", "1")])).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Общий адрес без сайта — API нет.
    let (s, _) = send_json(&e.app, get(&[("host", "127.0.0.1:7704"), ("x-void-api", "1")])).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // CORS-preflight не разрешаем (нет обработчика OPTIONS, нет Allow-Origin).
    let (s, h, _) = send(
        &e.app,
        Request::builder()
            .method("OPTIONS")
            .uri("/.void/api/me")
            .header("host", HOST)
            .header("origin", "http://evil.localhost:7704")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_ne!(s, StatusCode::OK);
    assert!(h.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn identity_needs_consent_in_app() {
    let e = env().await;
    let (s, v) = send_json(&e.app, api("GET", "/.void/api/me").body(Body::empty()).unwrap()).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("permission_required")));

    let asked = answer_when_asked(e.consent.clone(), true);
    let body = Body::from(r#"{"permissions":["identity"]}"#);
    let (s, v) = send_json(&e.app, api("POST", "/.void/api/permissions").body(body).unwrap()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["granted"], serde_json::json!(["identity"]));
    assert_eq!(asked.await.unwrap(), ConsentKind::Permissions(vec![Permission::Identity]));

    let (s, v) = send_json(&e.app, api("GET", "/.void/api/me").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["name"], "Алиса");
    assert_eq!(v["id"], id(1).0);
    // Разрешение принадлежит сайту tube — evil его не получает.
    assert!(!e.perms.has("evil", Permission::Identity));
}

#[tokio::test]
async fn denial_is_final_for_a_while() {
    let e = env().await;
    let _answerer = answer_when_asked(e.consent.clone(), false);
    let ask = || api("POST", "/.void/api/permissions").body(Body::from(r#"{"permissions":["publish"]}"#)).unwrap();
    let (s, v) = send_json(&e.app, ask()).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("denied")));
    let (s, v) = send_json(&e.app, ask()).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("cooldown")));
    assert!(!e.perms.has("tube", Permission::Publish));
    // Неизвестное разрешение — ошибка без вопроса пользователю.
    let (s, _) = send_json(
        &e.app,
        api("POST", "/.void/api/permissions").body(Body::from(r#"{"permissions":["keys"]}"#)).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn records_roundtrip_and_privacy() {
    let mut e = env().await;
    let put = |key: &str| {
        api("PUT", "/.void/api/records")
            .body(Body::from(serde_json::json!({ "collection": "videos", "key": key, "data": { "title": key } }).to_string()))
            .unwrap()
    };
    let (s, v) = send_json(&e.app, put("v1")).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("permission_required")));

    e.perms.grant("tube", &[Permission::Publish]);
    let mut live = e.events.subscribe();
    let (s, v) = send_json(&e.app, put("v1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Своя запись подписана нашим ключом и ушла в сеть и подписчикам.
    let signed = e.records_rx.try_recv().expect("запись для рассылки");
    let rec = SiteRecord::from_signed(&signed).unwrap();
    assert_eq!((rec.site.as_str(), rec.author.clone()), ("tube", id(1)));
    assert_eq!(live.try_recv().unwrap().key, "v1");

    // Записи других авторов (как из сети): Боб и заблокированный узел 3.
    for (seed, key) in [(2u8, "bob"), (3u8, "spam")] {
        let r = SiteRecord {
            site: "tube".into(),
            collection: "videos".into(),
            key: key.into(),
            author: id(seed),
            updated_at: 1,
            link: None,
            data: Some(serde_json::json!({ "title": key })),
        };
        records::apply_signed(&e.pool, &r.sign(&kp(seed)).unwrap(), 100, 10).await.unwrap();
    }
    let list = || api("GET", "/.void/api/records?collection=videos").body(Body::empty()).unwrap();
    let (s, v) = send_json(&e.app, list()).await;
    assert_eq!(s, StatusCode::OK);
    let recs = v["records"].as_array().unwrap();
    let keys: Vec<&str> = recs.iter().map(|r| r["key"].as_str().unwrap()).collect();
    assert_eq!(keys, vec!["v1", "bob"], "заблокированный автор скрыт");
    assert_eq!(recs[1]["trust"], "trusted");
    // Без identity сайт не узнаёт, какая запись — пользователя.
    assert!(recs[0].get("mine").is_none());
    e.perms.grant("tube", &[Permission::Identity]);
    let (_, v) = send_json(&e.app, list()).await;
    assert_eq!(v["records"][0]["mine"], true);
    assert_eq!(v["records"][1]["mine"], false);

    // Записи сайта tube не видны на сайте evil.
    let (_, v) = send_json(
        &e.app,
        Request::builder()
            .uri("/.void/api/records?collection=videos")
            .header("host", "evil.localhost:7704")
            .header("origin", "http://evil.localhost:7704")
            .header("x-void-api", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(v["records"].as_array().unwrap().len(), 0);

    // Удаление своей записи; чужую удалить нельзя (её просто нет у автора «я»).
    // Надгробие сохраняет ссылку: подписчики по link узнают об удалении.
    let linked = api("PUT", "/.void/api/records")
        .body(Body::from(r#"{"collection":"likes","key":"l1","link":"v1","data":{"at":1}}"#))
        .unwrap();
    assert_eq!(send_json(&e.app, linked).await.0, StatusCode::OK);
    let mut live = e.events.subscribe();
    let (s, v) = send_json(&e.app, api("DELETE", "/.void/api/records?collection=likes&key=l1").body(Body::empty()).unwrap()).await;
    assert_eq!((s, v["deleted"].as_bool(), v["link"].as_str()), (StatusCode::OK, Some(true), Some("v1")));
    assert_eq!(live.try_recv().unwrap().link.as_deref(), Some("v1"));
    let (s, _) = send_json(&e.app, api("DELETE", "/.void/api/records?collection=likes&key=l1").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "повторное удаление — записи уже нет");
    let (s, _) = send_json(&e.app, api("DELETE", "/.void/api/records?collection=videos&key=v1").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send_json(&e.app, api("DELETE", "/.void/api/records?collection=videos&key=bob").body(Body::empty()).unwrap()).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, v) = send_json(&e.app, list()).await;
    assert_eq!(v["records"].as_array().unwrap().len(), 1);

    // Недопустимые поля отклоняются.
    let bad = api("PUT", "/.void/api/records")
        .body(Body::from(r#"{"collection":"Bad Name","key":"x","data":1}"#))
        .unwrap();
    assert_eq!(send_json(&e.app, bad).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn profiles_hide_blocked() {
    let e = env().await;
    let get = |who: &NodeId| api("GET", &format!("/.void/api/profiles/{}", who.0)).body(Body::empty()).unwrap();
    let (s, v) = send_json(&e.app, get(&id(2))).await;
    assert_eq!((s, v["name"].as_str(), v["trust"].as_str()), (StatusCode::OK, Some("Боб"), Some("trusted")));
    assert_eq!(send_json(&e.app, get(&id(3))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send_json(&e.app, get(&id(9))).await.0, StatusCode::NOT_FOUND);
    let bad = api("GET", "/.void/api/profiles/../keystore").body(Body::empty()).unwrap();
    assert_ne!(send_json(&e.app, bad).await.0, StatusCode::OK);
}

#[tokio::test]
async fn upload_needs_consent_and_streams_back_safely() {
    let mut e = env().await;
    let content: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let upload = |name: &str| {
        api("POST", &format!("/.void/api/files?name={name}"))
            .header("content-length", content.len().to_string())
            .body(Body::from(content.clone()))
            .unwrap()
    };

    // Согласие — опубликован, объявлен сети.
    let asked = answer_when_asked(e.consent.clone(), true);
    let (s, v) = send_json(&e.app, upload("clip.webm")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(asked.await.unwrap(), ConsentKind::Upload { name: "clip.webm".into(), size: content.len() as u64 });
    let file_id = v["fileId"].as_str().unwrap().to_string();
    assert_eq!(e.files_rx.try_recv().unwrap(), file_id);
    assert_eq!(v["type"], "video/webm");

    // Перемотка видео: Range → 206.
    let ranged = Request::builder()
        .uri(format!("/.void/files/{file_id}"))
        .header("host", HOST)
        .header("sec-fetch-site", "same-origin")
        .header("range", "bytes=262140-262150")
        .body(Body::empty())
        .unwrap();
    let (s, h, body) = send(&e.app, ranged).await;
    assert_eq!(s, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body, &content[262140..=262150]);
    assert_eq!(h["content-range"], format!("bytes 262140-262150/{}", content.len()));
    assert_eq!(h["content-type"], "video/webm");
    assert_eq!(h["accept-ranges"], "bytes");

    // Целиком.
    let full = Request::builder()
        .uri(format!("/.void/files/{file_id}"))
        .header("host", HOST)
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    let (s, _, body) = send(&e.app, full).await;
    assert_eq!((s, body.len()), (StatusCode::OK, content.len()));
    assert_eq!(body, content);

    // Встраивание с чужой страницы (<video src> на сайте из интернета).
    let embed = Request::builder()
        .uri(format!("/.void/files/{file_id}"))
        .header("host", HOST)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&e.app, embed).await.0, StatusCode::FORBIDDEN);

    // Отказ — файл не публикуется, и сразу спросить снова сайт не может.
    let _answerer = answer_when_asked(e.consent.clone(), false);
    let (s, _) = send_json(&e.app, upload("other.webm")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(e.files_rx.try_recv().is_err());
    let (s, v) = send_json(&e.app, upload("other.webm")).await;
    assert_eq!((s, v["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("cooldown")));
}

#[tokio::test]
async fn uploaded_html_is_never_rendered_on_site_origin() {
    let e = env().await;
    let _answerer = answer_when_asked(e.consent.clone(), true);
    let html = b"<script>steal()</script>".to_vec();
    let req = api("POST", "/.void/api/files?name=evil.html")
        .header("content-length", html.len().to_string())
        .body(Body::from(html))
        .unwrap();
    let (s, v) = send_json(&e.app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let get = Request::builder()
        .uri(format!("/.void/files/{}", v["fileId"].as_str().unwrap()))
        .header("host", HOST)
        .header("sec-fetch-site", "none")
        .body(Body::empty())
        .unwrap();
    let (s, h, _) = send(&e.app, get).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "application/octet-stream");
    assert!(h["content-disposition"].to_str().unwrap().starts_with("attachment"));
    assert!(h["content-security-policy"].to_str().unwrap().contains("sandbox"));
    assert_eq!(h["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn upload_size_must_match() {
    let e = env().await;
    let _answerer = answer_when_asked(e.consent.clone(), true);
    let req = api("POST", "/.void/api/files?name=a.bin")
        .header("content-length", "10")
        .body(Body::from(vec![0u8; 5]))
        .unwrap();
    let (s, _) = send_json(&e.app, req).await;
    assert_ne!(s, StatusCode::OK);
}

/// Подключение к WebSocket событий с заданным Origin.
async fn ws_connect(
    addr: std::net::SocketAddr,
    origin: Option<&str>,
) -> Result<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>, String> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{addr}/.void/api/events").into_client_request().unwrap();
    req.headers_mut().insert("host", HOST.parse().unwrap());
    if let Some(o) = origin {
        req.headers_mut().insert("origin", o.parse().unwrap());
    }
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio_tungstenite::client_async(req, stream).await.map(|(ws, _)| ws).map_err(|e| e.to_string())
}

#[tokio::test]
async fn live_events_reach_page_of_the_site_only() {
    use futures_util::StreamExt;
    let e = env().await;
    e.perms.grant("tube", &[Permission::Publish]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = e.app.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Без Origin (не браузер со страницы) и с Origin другого сайта — отказ.
    assert!(ws_connect(addr, None).await.is_err());
    assert!(ws_connect(addr, Some("http://evil.localhost:7704")).await.is_err());

    let mut ws = ws_connect(addr, Some(ORIGIN)).await.expect("своя страница подключается");
    // Запись другого сайта — мимо; своя — приходит.
    let other = SiteRecord {
        site: "evil".into(),
        collection: "comments".into(),
        key: "x".into(),
        author: id(2),
        updated_at: 5,
        link: Some("v1".into()),
        data: Some(serde_json::json!("nope")),
    };
    let _ = e.events.send(other);
    let put = api("PUT", "/.void/api/records")
        .body(Body::from(r#"{"collection":"comments","key":"c1","link":"v1","data":{"text":"привет"}}"#))
        .unwrap();
    assert_eq!(send_json(&e.app, put).await.0, StatusCode::OK);

    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
    let text = msg.into_text().unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "record", "{text}");
    assert_eq!(v["record"]["data"]["text"], "привет");
    assert_eq!(v["record"]["collection"], "comments");
    assert!(v["record"].get("mine").is_none(), "без identity сайт не узнаёт автора-пользователя");
}

#[tokio::test]
async fn sdk_is_served_and_reserved_paths_are_not_site_files() {
    let e = env().await;
    let (s, h, body) = send(
        &e.app,
        Request::builder().uri("/.void/sdk.js").header("host", HOST).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/javascript"));
    assert!(String::from_utf8_lossy(&body).contains("window.Void"));
    let (s, _, _) = send(
        &e.app,
        Request::builder().uri("/.void/whatever").header("host", HOST).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
