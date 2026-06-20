//! `void-web` — хостинг простых сайтов поверх `void-storage`.
//!
//! Сайт = каталог файлов. Каждый файл публикуется в хранилище (получает
//! `file_id`), а [`SiteManifest`] связывает относительные пути с `file_id` и
//! даёт сайту имя в зоне `.void`. Локальный HTTP-сервер ([`server`]) отдаёт
//! файлы сайта, читая их из хранилища.
//!
//! ```ignore
//! let manifest = publish_site(&storage, Path::new("./site"), "blog", my_id).await?;
//! registry.register(manifest).await;
//! serve("127.0.0.1:8080".parse()?, registry, storage).await?;
//! // → http://127.0.0.1:8080/blog
//! ```

pub mod dns;
pub mod error;
pub mod registry;
pub mod server;

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use void_core::identity::NodeId;
use void_core::site::{SiteEntry, SiteManifest};
use void_storage::StorageManager;

pub use dns::DnsRegistry;
pub use error::WebError;
pub use registry::SiteRegistry;
pub use server::{router, serve, PeerSnapshot};

/// Публикует каталог как сайт: каждый файл уходит в хранилище, из путей и
/// `file_id` собирается манифест. Имя — без зоны (`blog`, не `blog.void`).
pub async fn publish_site(
    storage: &StorageManager,
    dir: &Path,
    name: &str,
    owner: NodeId,
) -> Result<SiteManifest, WebError> {
    if !dir.is_dir() {
        return Err(WebError::Invalid(format!("не каталог: {}", dir.display())));
    }

    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    if files.is_empty() {
        return Err(WebError::Invalid(format!("в каталоге нет файлов: {}", dir.display())));
    }

    let mut entries = Vec::with_capacity(files.len());
    for (rel, abs) in files {
        let file_id = storage.publish_file(&abs).await?;
        let size_bytes = std::fs::metadata(&abs).map(|m| m.len() as i64).unwrap_or(0);
        entries.push(SiteEntry { path: rel, file_id, size_bytes });
    }
    // Детерминированный порядок → детерминированный site_id.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let site_id = compute_site_id(name, &entries);
    Ok(SiteManifest {
        site_id,
        name: name.to_string(),
        owner,
        entries,
        created_at: chrono::Utc::now().timestamp(),
    })
}

/// Рекурсивно собирает файлы каталога как пары (относительный путь, абсолютный путь).
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

fn compute_site_id(name: &str, entries: &[SiteEntry]) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\0");
    for e in entries {
        h.update(e.path.as_bytes());
        h.update(b"\0");
        h.update(e.file_id.as_bytes());
        h.update(b"\0");
    }
    hex::encode(h.finalize())
}

/// MIME-тип по расширению файла (для заголовка Content-Type).
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css"          => "text/css; charset=utf-8",
        "js" | "mjs"   => "text/javascript; charset=utf-8",
        "json"         => "application/json",
        "txt" | "md"   => "text/plain; charset=utf-8",
        "png"          => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif"          => "image/gif",
        "svg"          => "image/svg+xml",
        "ico"          => "image/x-icon",
        "webp"         => "image/webp",
        "wasm"         => "application/wasm",
        "woff2"        => "font/woff2",
        "woff"         => "font/woff",
        _              => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use void_storage::ChunkStore;

    fn node(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&[seed; 32])
    }

    async fn storage(seed: u8) -> (tempfile::TempDir, StorageManager) {
        let dir = tempfile::tempdir().unwrap();
        let pool = void_db::open(&dir.path().join("db.sqlite")).await.unwrap();
        let store = ChunkStore::new(dir.path().join("chunks")).await.unwrap();
        let mgr = StorageManager::new(pool, store, node(seed)).await.unwrap();
        (dir, mgr)
    }

    fn write_sample_site(dir: &Path) {
        std::fs::write(dir.join("index.html"), b"<h1>Hello Void</h1>").unwrap();
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::write(dir.join("css/style.css"), b"h1{color:red}").unwrap();
    }

    #[tokio::test]
    async fn publish_site_builds_manifest() {
        let (_sdir, mgr) = storage(1).await;
        let site_dir = tempfile::tempdir().unwrap();
        write_sample_site(site_dir.path());

        let manifest = publish_site(&mgr, site_dir.path(), "blog", node(1)).await.unwrap();
        assert_eq!(manifest.name, "blog");
        assert_eq!(manifest.dns_name(), "blog.void");
        assert_eq!(manifest.entries.len(), 2);
        assert!(manifest.index().is_some(), "index.html должен быть в манифесте");
        assert!(manifest.entry("css/style.css").is_some());
        assert!(!manifest.site_id.is_empty());

        // Файлы реально читаются из хранилища.
        let index = manifest.index().unwrap();
        let bytes = mgr.read_file(&index.file_id).await.unwrap();
        assert_eq!(bytes, b"<h1>Hello Void</h1>");
    }

    /// Сквозной HTTP: публикуем сайт, поднимаем сервер, GET'ом получаем страницу.
    #[tokio::test]
    async fn serve_returns_page_over_http() {
        let (_sdir, mgr) = storage(2).await;
        let site_dir = tempfile::tempdir().unwrap();
        write_sample_site(site_dir.path());

        let registry = SiteRegistry::new();
        let manifest = publish_site(&mgr, site_dir.path(), "blog", node(2)).await.unwrap();
        registry.register(manifest).await;

        // Поднимаем сервер на свободном порту. Сайт локальный → пиры не нужны.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = router(registry, mgr, peers);
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // index по имени с зоной .void
        let body = http_get(addr, "/blog.void").await;
        assert!(body.contains("<h1>Hello Void</h1>"), "ожидался index сайта, получено: {body}");

        // конкретный файл
        let css = http_get(addr, "/blog/css/style.css").await;
        assert!(css.contains("color:red"), "ожидался css, получено: {css}");

        // несуществующая страница → 404
        let missing = http_get(addr, "/blog/nope.js").await;
        assert!(missing.contains("404"), "ожидался 404, получено: {missing}");
    }

    /// Фаза 2: сквозная раздача ЧУЖОГО сайта. Узел A публикует сайт и поднимает
    /// chunk-сервер. Узел B знает сайт и манифесты файлов (как по сети), но
    /// чанков локально нет. HTTP-сервер B по запросу докачивает файлы у A и
    /// отдаёт страницу — без ручного скачивания.
    #[tokio::test]
    async fn serve_remote_site_downloads_from_peer() {
        use std::net::{IpAddr, Ipv4Addr};
        use void_core::peer::{PeerInfo, Service};

        fn free_port() -> u16 {
            std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
        }

        // A публикует сайт.
        let (_da, mgr_a) = storage(10).await;
        let site_dir = tempfile::tempdir().unwrap();
        write_sample_site(site_dir.path());
        let manifest = publish_site(&mgr_a, site_dir.path(), "remote", node(10)).await.unwrap();

        // chunk-сервер A.
        let a_port = free_port();
        let srv = mgr_a.clone();
        tokio::spawn(async move { let _ = srv.start_server(a_port).await; });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // B узнаёт о файлах сайта ТОЛЬКО из манифестов (никаких локальных чанков).
        let (_db, mgr_b) = storage(11).await;
        for entry in &manifest.entries {
            let fm = mgr_a.file_manifest(&entry.file_id).await.unwrap().unwrap();
            mgr_b.handle_manifest(&fm).await.unwrap();
        }

        // Реестр B знает сайт; A — в списке активных пиров (порт = chunk-сервер A).
        let registry = SiteRegistry::new();
        registry.register(manifest.clone()).await;
        let a_peer = PeerInfo {
            id:        node(10),
            name:      "A".into(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      a_port,
            chat_port: a_port.wrapping_add(2),
            services:  vec![Service::Storage],
            last_seen: 0,
        };
        let peers = std::sync::Arc::new(std::sync::Mutex::new(vec![a_peer]));

        // HTTP-сервер B.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(registry, mgr_b.clone(), peers);
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Первый запрос → докачка у A → страница отдаётся.
        let body = http_get(addr, "/remote.void").await;
        assert!(body.contains("<h1>Hello Void</h1>"),
            "ожидался докачанный index чужого сайта, получено: {body}");

        // После докачки файл стал локальным у B (быстрый путь).
        let local = mgr_b.read_file(&manifest.index().unwrap().file_id).await.unwrap();
        assert_eq!(local, b"<h1>Hello Void</h1>");
    }

    /// Минимальный HTTP/1.1 GET через сырой TCP (без сторонних http-клиентов).
    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }
}
