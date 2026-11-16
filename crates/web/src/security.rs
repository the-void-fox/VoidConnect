//! Защита сайтов и JS API на уровне HTTP.
//!
//! Модель угроз:
//! * код сайта недоверенный — его пишет кто угодно;
//! * в том же браузере открыты страницы из интернета и другие сайты сети;
//! * пользовательские файлы (загрузки) — недоверенные данные.
//!
//! Что делаем:
//! * **Отдельный origin у каждого сайта** (`<имя>.localhost:<порт>`) —
//!   браузер сам не даёт сайтам читать данные друг друга. Общий адрес
//!   `127.0.0.1:<порт>/<имя>` только перенаправляет на свой origin.
//! * **CSP** на страницах сайтов: скрипты только из файлов самого сайта (без
//!   inline-скриптов и `eval`) — внедрённый в комментарий HTML не выполнится;
//!   запросы, картинки, шрифты — только к своему origin, поэтому сайт не может
//!   отправить данные пользователя на чужой сервер или подгрузить трекер.
//! * **API только для своей страницы**: обязательный заголовок `X-Void-Api`
//!   (чужой origin не может его поставить без CORS-preflight, а мы preflight
//!   не разрешаем), `Origin` и `Sec-Fetch-Site` должны указывать на тот же
//!   сайт. Все `*.localhost` для браузера — один «site», поэтому сверяем
//!   именно origin, а не site.
//! * **Загруженные файлы** отдаются только безопасных типов (картинки без SVG,
//!   видео, аудио, текст); остальное — `attachment`. Плюс `nosniff`, `sandbox` и
//!   `Cross-Origin-Resource-Policy`: файл нельзя выполнить как скрипт или
//!   страницу на origin сайта (иначе загрузка `evil.html` = XSS).

use axum::http::{header, HeaderMap, HeaderValue};

/// Заголовок, без которого API не отвечает.
pub const API_HEADER: &str = "x-void-api";

/// CSP страниц сайта.
pub const SITE_CSP: &str = "default-src 'self'; \
     script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data: blob:; \
     media-src 'self' blob:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     worker-src 'self' blob:; \
     frame-src 'self'; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'self'";

/// CSP пользовательского файла, открытого как документ: никаких скриптов,
/// уникальный (непрозрачный) origin.
pub const FILE_CSP: &str = "default-src 'none'; img-src 'self'; media-src 'self'; \
     style-src 'unsafe-inline'; sandbox";

/// Заголовки безопасности для любого ответа сайта.
pub fn site_headers(h: &mut HeaderMap) {
    let set = |h: &mut HeaderMap, k: header::HeaderName, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        set(h, header::CONTENT_SECURITY_POLICY, SITE_CSP);
    }
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::HeaderName::from_static("cross-origin-opener-policy"), "same-origin");
    set(h, header::HeaderName::from_static("cross-origin-resource-policy"), "same-origin");
    set(
        h,
        header::HeaderName::from_static("permissions-policy"),
        "geolocation=(), payment=(), usb=(), serial=(), hid=()",
    );
}

/// Ожидаемый origin страницы по заголовку Host (`http://tube.localhost:7704`).
pub fn own_origin(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    Some(format!("http://{}", host.to_ascii_lowercase()))
}

/// Запрос пришёл со страницы этого же сайта (или не из браузера вовсе).
/// `Sec-Fetch-Site: none` — пользователь открыл адрес сам (закладка, ссылка
/// из приложения), это тоже допустимо.
pub fn same_origin_request(headers: &HeaderMap, allow_direct: bool) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN)
        && Some(origin.to_str().unwrap_or("").to_ascii_lowercase()) != own_origin(headers)
    {
        return false;
    }
    match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        None | Some("same-origin") => true,
        Some("none") => allow_direct,
        Some(_) => false,
    }
}

/// Проверка вызова API: свой заголовок + тот же origin.
pub fn api_request_allowed(headers: &HeaderMap) -> bool {
    headers.get(API_HEADER).is_some_and(|v| v == "1") && same_origin_request(headers, false)
}

/// Тип пользовательского файла для отдачи: `(content-type, inline?)`. Inline
/// только для того, что браузер не исполнит; остальное — скачивание.
pub fn safe_file_type(name: &str) -> (&'static str, bool) {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let inline = |t| (t, true);
    match ext.as_str() {
        "png" => inline("image/png"),
        "jpg" | "jpeg" => inline("image/jpeg"),
        "gif" => inline("image/gif"),
        "webp" => inline("image/webp"),
        "avif" => inline("image/avif"),
        "bmp" => inline("image/bmp"),
        "mp4" | "m4v" => inline("video/mp4"),
        "webm" => inline("video/webm"),
        "ogv" => inline("video/ogg"),
        "mov" => inline("video/quicktime"),
        "mkv" => inline("video/x-matroska"),
        "mp3" => inline("audio/mpeg"),
        "ogg" | "oga" => inline("audio/ogg"),
        "opus" => inline("audio/opus"),
        "wav" => inline("audio/wav"),
        "flac" => inline("audio/flac"),
        "m4a" => inline("audio/mp4"),
        "txt" | "md" | "srt" | "vtt" => inline(if ext == "vtt" { "text/vtt; charset=utf-8" } else { "text/plain; charset=utf-8" }),
        _ => ("application/octet-stream", false),
    }
}

/// `Content-Disposition` с безопасным именем (RFC 6266 / 5987).
pub fn content_disposition(name: &str, inline: bool) -> String {
    let safe = void_core::sanitize::safe_file_name(name);
    let ascii: String = safe
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .collect();
    let mut encoded = String::new();
    for b in safe.bytes() {
        if b.is_ascii_alphanumeric() || b"._-".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    let kind = if inline { "inline" } else { "attachment" };
    format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(header::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn api_requires_header_and_same_origin() {
        let ok = headers(&[
            ("host", "tube.localhost:7704"),
            ("x-void-api", "1"),
            ("origin", "http://tube.localhost:7704"),
            ("sec-fetch-site", "same-origin"),
        ]);
        assert!(api_request_allowed(&ok));

        let no_header = headers(&[("host", "tube.localhost:7704"), ("sec-fetch-site", "same-origin")]);
        assert!(!api_request_allowed(&no_header));

        // Другой сайт сети: для браузера same-site, но origin чужой.
        let other_site = headers(&[
            ("host", "tube.localhost:7704"),
            ("x-void-api", "1"),
            ("origin", "http://evil.localhost:7704"),
            ("sec-fetch-site", "same-site"),
        ]);
        assert!(!api_request_allowed(&other_site));

        let internet = headers(&[
            ("host", "tube.localhost:7704"),
            ("x-void-api", "1"),
            ("sec-fetch-site", "cross-site"),
        ]);
        assert!(!api_request_allowed(&internet));

        // Адрес, открытый напрямую, — не вызов API со страницы.
        let direct = headers(&[("host", "tube.localhost:7704"), ("x-void-api", "1"), ("sec-fetch-site", "none")]);
        assert!(!api_request_allowed(&direct));
        assert!(same_origin_request(&direct, true));
    }

    #[test]
    fn dangerous_uploads_are_not_inline() {
        for name in ["evil.html", "x.htm", "a.svg", "s.js", "p.pdf", "x.xhtml", "noext"] {
            let (t, inline) = safe_file_type(name);
            assert!(!inline, "{name} не должен открываться inline");
            assert_eq!(t, "application/octet-stream");
        }
        assert_eq!(safe_file_type("clip.WEBM"), ("video/webm", true));
        assert_eq!(safe_file_type("cat.png"), ("image/png", true));
    }

    #[test]
    fn disposition_escapes_name() {
        let d = content_disposition("ви\"део\r\n.mp4", true);
        assert!(d.starts_with("inline; filename=\""));
        assert!(!d.contains('\r') && !d.contains('\n'));
        assert_eq!(d.matches('"').count(), 2, "кавычка из имени не должна разорвать заголовок: {d}");
    }
}
