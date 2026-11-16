//! Общие данные сайтов — подписанные записи пользователей (JS API).
//!
//! Сайт вроде видеохостинга хранит своё «серверное» состояние (список видео,
//! комментарии, лайки) как записи: каждую подписывает автор своим ключом, и
//! они расходятся по сети. Модель «у каждого автора свои ключи»:
//!
//! * запись адресуется `(сайт, коллекция, автор, ключ)`; последняя версия
//!   (`updated_at`) побеждает;
//! * чужую запись нельзя ни перезаписать, ни удалить — подпись не сойдётся;
//! * удаление — надгробие (`data = None`), чтобы старая копия не воскресла;
//! * имя сайта входит в подпись: запись одного сайта не выдать за запись
//!   другого, а контекст `void-connect/site-record/v1` не даёт выдать её за
//!   подписанные данные другого типа (поручительство, DNS и т. п.).

use serde::{Deserialize, Serialize};
use sqlx::Row;
use void_core::dns::normalize_name;
use void_core::identity::NodeId;
use void_core::sanitize::is_hex64;
use void_core::site::SiteDigestItem;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_db::DbPool;

use crate::error::WebError;

/// Контекст подписи записи.
pub const RECORD_CONTEXT: &[u8] = b"void-connect/site-record/v1\n";
/// Предел содержимого записи (JSON), байт.
pub const MAX_DATA_BYTES: usize = 8 * 1024;
/// Длина имени коллекции: `[a-z0-9_-]`.
pub const MAX_COLLECTION_LEN: usize = 32;
/// Длина ключа записи: `[A-Za-z0-9_.:-]`.
pub const MAX_KEY_LEN: usize = 64;
/// Длина ссылки (`link`): `[A-Za-z0-9_.:/-]`.
pub const MAX_LINK_LEN: usize = 128;
/// Насколько запись может быть «из будущего» (расхождение часов).
pub const MAX_FUTURE_SKEW_MS: i64 = 10 * 60 * 1000;
/// Сколько записей храним всего (все сайты, все авторы).
pub const MAX_RECORDS_TOTAL: i64 = 500_000;
/// Сколько записей отдаёт один запрос.
pub const MAX_QUERY_LIMIT: i64 = 500;

/// Запись общих данных сайта.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteRecord {
    /// Имя сайта без зоны (нормализованное).
    pub site: String,
    pub collection: String,
    pub key: String,
    pub author: NodeId,
    /// Версия (unix-мс). Принимается только более новая версия записи.
    pub updated_at: i64,
    /// Ссылка для выборок: например, у комментария — ключ видео.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Содержимое. `None` — запись удалена (надгробие).
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

fn chars_ok(s: &str, max: usize, extra: &[u8], lower_only: bool) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || b.is_ascii_lowercase()
                || (!lower_only && b.is_ascii_uppercase())
                || extra.contains(&b)
        })
}

/// Имя коллекции: 1–32 символа `[a-z0-9_-]`.
pub fn valid_collection(s: &str) -> bool {
    chars_ok(s, MAX_COLLECTION_LEN, b"_-", true)
}

/// Ключ записи: 1–64 символа `[A-Za-z0-9_.:-]`.
pub fn valid_key(s: &str) -> bool {
    chars_ok(s, MAX_KEY_LEN, b"_.:-", false)
}

/// Ссылка: 1–128 символов `[A-Za-z0-9_.:/-]`.
pub fn valid_link(s: &str) -> bool {
    chars_ok(s, MAX_LINK_LEN, b"_.:/-", false)
}

impl SiteRecord {
    /// Поля в пределах лимитов (проверяется и для своих, и для чужих записей).
    pub fn validate(&self) -> Result<(), WebError> {
        let bad = |m: &str| Err(WebError::Invalid(m.to_string()));
        if normalize_name(&self.site).as_deref() != Some(self.site.as_str()) {
            return bad("имя сайта не нормализовано");
        }
        if !valid_collection(&self.collection) {
            return bad("недопустимое имя коллекции");
        }
        if !valid_key(&self.key) {
            return bad("недопустимый ключ записи");
        }
        if self.link.as_deref().is_some_and(|l| !valid_link(l)) {
            return bad("недопустимая ссылка");
        }
        if !is_hex64(self.author.as_str()) {
            return bad("автор не hex64");
        }
        if self.updated_at <= 0 {
            return bad("версия должна быть положительной");
        }
        if let Some(data) = &self.data {
            let len = serde_json::to_vec(data).map(|v| v.len()).unwrap_or(usize::MAX);
            if len > MAX_DATA_BYTES {
                return bad("содержимое больше 8 КБ");
            }
        }
        Ok(())
    }

    /// Подписываемые байты: контекст + JSON записи.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = RECORD_CONTEXT.to_vec();
        out.extend_from_slice(&serde_json::to_vec(self).expect("SiteRecord сериализуется"));
        out
    }

    /// Подписывает запись ключом автора (он должен совпадать с `author`).
    pub fn sign(&self, kp: &SigningKeypair) -> Result<SignedMessage, WebError> {
        self.validate()?;
        if NodeId::from_public_key_bytes(&kp.public_bytes()) != self.author {
            return Err(WebError::Invalid("ключ подписи не принадлежит автору".into()));
        }
        SignedMessage::sign(self.payload(), kp).map_err(|e| WebError::Invalid(format!("подпись: {e:?}")))
    }

    /// Проверяет подписанную запись из сети: контекст, формат, лимиты,
    /// подпись и `signer == author`.
    pub fn from_signed(signed: &SignedMessage) -> Result<Self, WebError> {
        let body = signed
            .payload
            .strip_prefix(RECORD_CONTEXT)
            .ok_or_else(|| WebError::Invalid("не запись сайта (нет контекста)".into()))?;
        if body.len() > MAX_DATA_BYTES + 2048 {
            return Err(WebError::Invalid("запись слишком большая".into()));
        }
        let record: SiteRecord =
            serde_json::from_slice(body).map_err(|e| WebError::Invalid(format!("формат: {e}")))?;
        record.validate()?;
        if signed.signer != record.author.as_str() {
            return Err(WebError::Invalid("подписант ≠ автор".into()));
        }
        signed.verify().map_err(|_| WebError::Invalid("подпись неверна".into()))?;
        Ok(record)
    }
}

fn db_err(e: sqlx::Error) -> WebError {
    WebError::Invalid(format!("БД: {e}"))
}

/// Итог приёма записи.
#[derive(Debug, Clone, PartialEq)]
pub enum Applied {
    /// Запись новая или свежее известной — база изменилась (переслать дальше).
    Changed(SiteRecord),
    /// Дубликат или старая версия.
    Stale,
    /// Не принята: лимит хранения автора или общий, запись «из будущего».
    Refused(&'static str),
}

/// Принимает подписанную запись (свою или из сети). `max_per_author` —
/// сколько записей этого автора на этом сайте мы готовы хранить (зависит от
/// доверия к автору; решает вызывающий).
pub async fn apply_signed(
    pool: &DbPool,
    signed: &SignedMessage,
    max_per_author: i64,
    now_ms: i64,
) -> Result<Applied, WebError> {
    let rec = SiteRecord::from_signed(signed)?;
    if rec.updated_at - now_ms > MAX_FUTURE_SKEW_MS {
        return Ok(Applied::Refused("запись из будущего"));
    }
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT updated_at FROM site_records WHERE site = ? AND collection = ? AND author = ? AND key = ?",
    )
    .bind(&rec.site)
    .bind(&rec.collection)
    .bind(rec.author.as_str())
    .bind(&rec.key)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    match existing {
        Some(at) if at >= rec.updated_at => return Ok(Applied::Stale),
        Some(_) => {}
        None => {
            let by_author: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM site_records WHERE site = ? AND author = ?")
                    .bind(&rec.site)
                    .bind(rec.author.as_str())
                    .fetch_one(pool)
                    .await
                    .map_err(db_err)?;
            if by_author >= max_per_author {
                return Ok(Applied::Refused("лимит записей автора на сайте"));
            }
            let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM site_records")
                .fetch_one(pool)
                .await
                .map_err(db_err)?;
            if total >= MAX_RECORDS_TOTAL {
                return Ok(Applied::Refused("общий лимит записей"));
            }
        }
    }
    let data = rec.data.as_ref().map(|d| d.to_string());
    let signed_json = serde_json::to_string(signed).map_err(|e| WebError::Invalid(e.to_string()))?;
    sqlx::query(
        "INSERT INTO site_records
            (site, collection, author, key, updated_at, link, deleted, data, signed_json, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (site, collection, author, key) DO UPDATE SET
            updated_at = excluded.updated_at, link = excluded.link, deleted = excluded.deleted,
            data = excluded.data, signed_json = excluded.signed_json, received_at = excluded.received_at",
    )
    .bind(&rec.site)
    .bind(&rec.collection)
    .bind(rec.author.as_str())
    .bind(&rec.key)
    .bind(rec.updated_at)
    .bind(&rec.link)
    .bind(rec.data.is_none() as i64)
    .bind(data)
    .bind(signed_json)
    .bind(now_ms)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(Applied::Changed(rec))
}

/// Параметры выборки записей одного сайта.
#[derive(Debug, Clone, Default)]
pub struct RecordQuery {
    pub site: String,
    pub collection: String,
    pub author: Option<String>,
    pub key: Option<String>,
    pub link: Option<String>,
    /// Только записи новее (unix-мс, не включая).
    pub since: Option<i64>,
    /// Только записи старше (unix-мс, не включая) — постраничная прокрутка.
    pub before: Option<i64>,
    pub limit: i64,
    /// Возвращать и надгробия (нужно живым подпискам, чтобы убрать запись).
    pub include_deleted: bool,
}

fn record_from_row(r: &sqlx::sqlite::SqliteRow) -> SiteRecord {
    SiteRecord {
        site: r.get("site"),
        collection: r.get("collection"),
        key: r.get("key"),
        author: NodeId(r.get("author")),
        updated_at: r.get("updated_at"),
        link: r.get("link"),
        data: r
            .get::<Option<String>, _>("data")
            .and_then(|d| serde_json::from_str(&d).ok()),
    }
}

/// Записи по запросу, свежие первыми.
pub async fn query(pool: &DbPool, q: &RecordQuery) -> Result<Vec<SiteRecord>, WebError> {
    let mut sql = String::from(
        "SELECT site, collection, author, key, updated_at, link, data FROM site_records
         WHERE site = ? AND collection = ?",
    );
    if q.author.is_some() {
        sql.push_str(" AND author = ?");
    }
    if q.key.is_some() {
        sql.push_str(" AND key = ?");
    }
    if q.link.is_some() {
        sql.push_str(" AND link = ?");
    }
    if q.since.is_some() {
        sql.push_str(" AND updated_at > ?");
    }
    if q.before.is_some() {
        sql.push_str(" AND updated_at < ?");
    }
    if !q.include_deleted {
        sql.push_str(" AND deleted = 0");
    }
    sql.push_str(" ORDER BY updated_at DESC LIMIT ?");

    let mut qq = sqlx::query(&sql).bind(&q.site).bind(&q.collection);
    if let Some(a) = &q.author {
        qq = qq.bind(a);
    }
    if let Some(k) = &q.key {
        qq = qq.bind(k);
    }
    if let Some(l) = &q.link {
        qq = qq.bind(l);
    }
    if let Some(s) = q.since {
        qq = qq.bind(s);
    }
    if let Some(b) = q.before {
        qq = qq.bind(b);
    }
    qq = qq.bind(q.limit.clamp(1, MAX_QUERY_LIMIT));
    let rows = qq.fetch_all(pool).await.map_err(db_err)?;
    Ok(rows.iter().map(record_from_row).collect())
}

/// Версия и ссылка записи, если она известна: версия нужна для монотонной
/// версии своих правок, ссылка — чтобы надгробие сохранило `link` (иначе
/// подписчики, следящие за ссылкой, не узнали бы об удалении).
pub async fn current(
    pool: &DbPool,
    site: &str,
    collection: &str,
    author: &NodeId,
    key: &str,
) -> Result<Option<(i64, Option<String>, bool)>, WebError> {
    let row: Option<(i64, Option<String>, i64)> = sqlx::query_as(
        "SELECT updated_at, link, deleted FROM site_records
         WHERE site = ? AND collection = ? AND author = ? AND key = ?",
    )
    .bind(site)
    .bind(collection)
    .bind(author.as_str())
    .bind(key)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    Ok(row.map(|(at, link, deleted)| (at, link, deleted != 0)))
}

/// Сколько записей у каждого сайта (для страницы «Сайты»).
pub async fn counts_by_site(pool: &DbPool) -> Result<Vec<(String, i64)>, WebError> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT site, COUNT(*) FROM site_records WHERE deleted = 0 GROUP BY site")
            .fetch_all(pool)
            .await
            .map_err(db_err)?;
    Ok(rows)
}

/// Сколько строк дайджеста отправляем максимум (на очень больших базах
/// остальное догонится при следующей связи или живой рассылкой).
pub const MAX_DIGEST_ITEMS: usize = 20_000;

/// Дайджест всех записей: сводка на каждую пару (сайт, автор).
pub async fn digest(pool: &DbPool) -> Result<Vec<SiteDigestItem>, WebError> {
    let rows = sqlx::query(
        "SELECT site, author, COUNT(*) AS cnt, MAX(updated_at) AS max_ts, SUM(updated_at) AS sum_ts
         FROM site_records GROUP BY site, author ORDER BY max_ts DESC LIMIT ?",
    )
    .bind(MAX_DIGEST_ITEMS as i64)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    Ok(rows
        .iter()
        .map(|r| SiteDigestItem {
            site: r.get("site"),
            author: r.get("author"),
            count: r.get("cnt"),
            max_ts: r.get("max_ts"),
            sum_ts: r.get("sum_ts"),
        })
        .collect())
}

/// Что дослать соседу по его дайджесту: для каждой нашей пары (сайт, автор),
/// которой у него нет или которая расходится, — записи новее его `max_ts`, а
/// если версии сходятся по максимуму, но не по сумме, — все записи пары.
/// Не больше `limit` записей за раз.
pub async fn missing_for(
    pool: &DbPool,
    theirs: &[SiteDigestItem],
    limit: usize,
) -> Result<Vec<SignedMessage>, WebError> {
    use std::collections::HashMap;
    let theirs: HashMap<(&str, &str), &SiteDigestItem> =
        theirs.iter().map(|d| ((d.site.as_str(), d.author.as_str()), d)).collect();
    let mut out = Vec::new();
    for mine in digest(pool).await? {
        if out.len() >= limit {
            break;
        }
        let since = match theirs.get(&(mine.site.as_str(), mine.author.as_str())) {
            Some(t) if t.count == mine.count && t.max_ts == mine.max_ts && t.sum_ts == mine.sum_ts => continue,
            Some(t) if t.max_ts < mine.max_ts => t.max_ts,
            Some(_) => i64::MIN, // расходятся при том же максимуме — шлём всё
            None => i64::MIN,
        };
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT signed_json FROM site_records WHERE site = ? AND author = ? AND updated_at > ?
             ORDER BY updated_at ASC LIMIT ?",
        )
        .bind(&mine.site)
        .bind(&mine.author)
        .bind(since)
        .bind((limit - out.len()) as i64)
        .fetch_all(pool)
        .await
        .map_err(db_err)?;
        out.extend(rows.iter().filter_map(|j| serde_json::from_str(j).ok()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    fn id(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&kp(seed).public_bytes())
    }

    fn rec(author: u8, key: &str, at: i64) -> SiteRecord {
        SiteRecord {
            site: "tube".into(),
            collection: "videos".into(),
            key: key.into(),
            author: id(author),
            updated_at: at,
            link: None,
            data: Some(serde_json::json!({ "title": key })),
        }
    }

    async fn pool() -> (tempfile::TempDir, DbPool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = void_db::open(&dir.path().join("db.sqlite")).await.unwrap();
        (dir, pool)
    }

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn sign_verify_and_reject_tampering() {
        let r = rec(1, "a", 5);
        let signed = r.sign(&kp(1)).unwrap();
        assert_eq!(SiteRecord::from_signed(&signed).unwrap(), r);
        // Чужим ключом не подписать.
        assert!(r.sign(&kp(2)).is_err());
        // Подмена содержимого ломает подпись.
        let mut forged = signed.clone();
        forged.payload = rec(1, "b", 5).payload();
        assert!(SiteRecord::from_signed(&forged).is_err());
        // Подпись другого типа данных без контекста — не запись.
        let other = SignedMessage::sign(b"{}".to_vec(), &kp(1)).unwrap();
        assert!(SiteRecord::from_signed(&other).is_err());
    }

    #[test]
    fn site_name_is_bound_into_signature() {
        let signed = rec(1, "a", 5).sign(&kp(1)).unwrap();
        // Переписать сайт в payload нельзя — подпись над исходными байтами.
        let mut moved = signed.clone();
        let mut r = rec(1, "a", 5);
        r.site = "other".into();
        moved.payload = r.payload();
        assert!(SiteRecord::from_signed(&moved).is_err());
    }

    #[test]
    fn limits_are_enforced() {
        let mut r = rec(1, "a", 5);
        r.collection = "Videos".into();
        assert!(r.validate().is_err(), "коллекция только в нижнем регистре");
        let mut r = rec(1, "a b", 5);
        assert!(r.validate().is_err(), "пробел в ключе");
        r.key = "k".repeat(65);
        assert!(r.validate().is_err());
        let mut r = rec(1, "a", 5);
        r.data = Some(serde_json::json!({ "x": "y".repeat(MAX_DATA_BYTES) }));
        assert!(r.validate().is_err(), "содержимое больше 8 КБ");
        let mut r = rec(1, "a", 5);
        r.site = "Tube".into();
        assert!(r.validate().is_err(), "имя сайта не нормализовано");
        let mut r = rec(1, "a", 5);
        r.link = Some("video:1".into());
        assert!(r.validate().is_ok());
        r.link = Some("<script>".into());
        assert!(r.validate().is_err());
    }

    #[tokio::test]
    async fn newer_version_wins_and_replay_is_stale() {
        let (_d, pool) = pool().await;
        let v1 = rec(1, "a", 10).sign(&kp(1)).unwrap();
        let v2 = rec(1, "a", 20).sign(&kp(1)).unwrap();
        assert!(matches!(apply_signed(&pool, &v1, 100, NOW).await.unwrap(), Applied::Changed(_)));
        assert!(matches!(apply_signed(&pool, &v2, 100, NOW).await.unwrap(), Applied::Changed(_)));
        assert_eq!(apply_signed(&pool, &v1, 100, NOW).await.unwrap(), Applied::Stale, "старая версия");
        assert_eq!(apply_signed(&pool, &v2, 100, NOW).await.unwrap(), Applied::Stale, "повтор");

        // Удаление — надгробие: обычная выборка его не видит.
        let mut del = rec(1, "a", 30);
        del.data = None;
        apply_signed(&pool, &del.sign(&kp(1)).unwrap(), 100, NOW).await.unwrap();
        let q = RecordQuery { site: "tube".into(), collection: "videos".into(), limit: 10, ..Default::default() };
        assert!(query(&pool, &q).await.unwrap().is_empty());
        let q = RecordQuery { include_deleted: true, ..q };
        assert_eq!(query(&pool, &q).await.unwrap().len(), 1);
        // Старая версия после удаления не воскрешает запись.
        assert_eq!(apply_signed(&pool, &v2, 100, NOW).await.unwrap(), Applied::Stale);
    }

    #[tokio::test]
    async fn authors_keys_are_separate() {
        let (_d, pool) = pool().await;
        apply_signed(&pool, &rec(1, "same", 10).sign(&kp(1)).unwrap(), 100, NOW).await.unwrap();
        apply_signed(&pool, &rec(2, "same", 5).sign(&kp(2)).unwrap(), 100, NOW).await.unwrap();
        let q = RecordQuery { site: "tube".into(), collection: "videos".into(), limit: 10, ..Default::default() };
        assert_eq!(query(&pool, &q).await.unwrap().len(), 2, "один ключ у двух авторов — две записи");
        let q = RecordQuery { author: Some(id(2).as_str().to_string()), ..q };
        let got = query(&pool, &q).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].author, id(2));
    }

    #[tokio::test]
    async fn quota_and_future_are_refused() {
        let (_d, pool) = pool().await;
        for i in 0..3 {
            let r = rec(1, &format!("k{i}"), 10 + i);
            apply_signed(&pool, &r.sign(&kp(1)).unwrap(), 3, NOW).await.unwrap();
        }
        let extra = rec(1, "k9", 50).sign(&kp(1)).unwrap();
        assert!(matches!(apply_signed(&pool, &extra, 3, NOW).await.unwrap(), Applied::Refused(_)));
        // Обновление существующей записи в лимит не упирается.
        let upd = rec(1, "k0", 60).sign(&kp(1)).unwrap();
        assert!(matches!(apply_signed(&pool, &upd, 3, NOW).await.unwrap(), Applied::Changed(_)));
        let future = rec(2, "f", NOW + MAX_FUTURE_SKEW_MS + 1).sign(&kp(2)).unwrap();
        assert!(matches!(apply_signed(&pool, &future, 3, NOW).await.unwrap(), Applied::Refused(_)));
    }

    #[tokio::test]
    async fn query_filters_by_link_and_pages() {
        let (_d, pool) = pool().await;
        for i in 0..5 {
            let mut r = rec(1, &format!("c{i}"), 100 + i);
            r.collection = "comments".into();
            r.link = Some(if i % 2 == 0 { "v1" } else { "v2" }.into());
            apply_signed(&pool, &r.sign(&kp(1)).unwrap(), 100, NOW).await.unwrap();
        }
        let q = RecordQuery {
            site: "tube".into(),
            collection: "comments".into(),
            link: Some("v1".into()),
            limit: 10,
            ..Default::default()
        };
        let got = query(&pool, &q).await.unwrap();
        assert_eq!(got.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(), vec!["c4", "c2", "c0"]);
        let page = query(&pool, &RecordQuery { before: Some(104), limit: 1, ..q }).await.unwrap();
        assert_eq!(page[0].key, "c2");
    }

    #[tokio::test]
    async fn digest_sync_sends_only_missing() {
        let (_a, pa) = pool().await;
        let (_b, pb) = pool().await;
        let r1 = rec(1, "a", 10).sign(&kp(1)).unwrap();
        let r2 = rec(1, "b", 20).sign(&kp(1)).unwrap();
        let r3 = rec(2, "c", 30).sign(&kp(2)).unwrap();
        for r in [&r1, &r2, &r3] {
            apply_signed(&pa, r, 100, NOW).await.unwrap();
        }
        apply_signed(&pb, &r1, 100, NOW).await.unwrap();

        // B знает только r1 — A досылает r2 и r3.
        let missing = missing_for(&pa, &digest(&pb).await.unwrap(), 100).await.unwrap();
        let mut keys: Vec<String> =
            missing.iter().map(|s| SiteRecord::from_signed(s).unwrap().key).collect();
        keys.sort();
        assert_eq!(keys, vec!["b", "c"]);
        for s in &missing {
            apply_signed(&pb, s, 100, NOW).await.unwrap();
        }
        assert_eq!(digest(&pa).await.unwrap(), digest(&pb).await.unwrap(), "базы сошлись");
        assert!(missing_for(&pa, &digest(&pb).await.unwrap(), 100).await.unwrap().is_empty());

        // Расхождение при том же максимуме (у B другая версия старой записи) —
        // A шлёт все записи пары; новая версия у B останется.
        let r1_new = rec(1, "a", 15).sign(&kp(1)).unwrap();
        apply_signed(&pb, &r1_new, 100, NOW).await.unwrap();
        let resend = missing_for(&pa, &digest(&pb).await.unwrap(), 100).await.unwrap();
        assert_eq!(resend.len(), 2);
        let back = missing_for(&pb, &digest(&pa).await.unwrap(), 100).await.unwrap();
        for s in &back {
            apply_signed(&pa, s, 100, NOW).await.unwrap();
        }
        assert_eq!(digest(&pa).await.unwrap(), digest(&pb).await.unwrap());
    }
}
