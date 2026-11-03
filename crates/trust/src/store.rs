//! Хранение поручительств и наблюдений (SQLite, миграция `0005_trust.sql`).
//!
//! Запросы рантаймовые (`sqlx::query`), без `query!`-макросов — офлайн-кэш
//! sqlx не нужен.

use std::collections::HashSet;

use sqlx::Row;
use void_core::identity::NodeId;
use void_crypto::sign::SignedMessage;
use void_db::DbPool;

use crate::error::TrustError;
use crate::types::{Vouch, VouchKind};

/// Сколько поручительств одного поручителя храним. Больше — новые не
/// принимаются: это защита хранилища от флуда (вес и так делится на их число).
pub const MAX_VOUCHES_PER_VOUCHER: i64 = 1000;
/// Сколько поручительств храним всего.
pub const MAX_VOUCHES_TOTAL: i64 = 100_000;

/// «Освоившийся по поведению»: столько секунд с первой встречи…
pub const SETTLE_SECS: i64 = 7 * 24 * 3600;
/// …и столько дней с «живыми» сообщениями.
pub const SETTLE_ACTIVE_DAYS: i64 = 3;

const DAY_SECS: i64 = 24 * 3600;

/// Принимает подписанное поручительство (из сети или своё). `Some(vouch)` —
/// таблица изменилась (новая пара или более свежая версия): это и сигнал
/// переслать дальше. `None` — дубликат, старая версия или лимит хранения.
pub async fn apply_signed(pool: &DbPool, signed: &SignedMessage) -> Result<Option<Vouch>, TrustError> {
    let vouch = Vouch::from_signed(signed)?;
    let existing: Option<i64> =
        sqlx::query_scalar("SELECT updated_at FROM vouches WHERE voucher = ? AND subject = ?")
            .bind(vouch.voucher.as_str())
            .bind(vouch.subject.as_str())
            .fetch_optional(pool)
            .await?;
    match existing {
        // Повтор или старая версия (например, до отзыва) — не принимаем.
        Some(at) if at >= vouch.updated_at => return Ok(None),
        Some(_) => {}
        None => {
            let by_voucher: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vouches WHERE voucher = ?")
                .bind(vouch.voucher.as_str())
                .fetch_one(pool)
                .await?;
            let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vouches").fetch_one(pool).await?;
            if by_voucher >= MAX_VOUCHES_PER_VOUCHER || total >= MAX_VOUCHES_TOTAL {
                return Ok(None);
            }
        }
    }
    let signed_json = serde_json::to_string(signed).map_err(|e| TrustError::Db(e.to_string()))?;
    sqlx::query(
        "INSERT INTO vouches (voucher, subject, kind, updated_at, revoked, signed_json)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (voucher, subject) DO UPDATE SET
             kind = excluded.kind, updated_at = excluded.updated_at,
             revoked = excluded.revoked, signed_json = excluded.signed_json",
    )
    .bind(vouch.voucher.as_str())
    .bind(vouch.subject.as_str())
    .bind(vouch.kind.as_str())
    .bind(vouch.updated_at)
    .bind(vouch.revoked)
    .bind(signed_json)
    .execute(pool)
    .await?;
    Ok(Some(vouch))
}

/// Все поручительства (последние версии пар, включая отозванные) — вход расчёта.
pub async fn load_vouches(pool: &DbPool) -> Result<Vec<Vouch>, TrustError> {
    let rows = sqlx::query("SELECT voucher, subject, kind, updated_at, revoked FROM vouches")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(Vouch {
                voucher: NodeId(r.get("voucher")),
                subject: NodeId(r.get("subject")),
                kind: VouchKind::parse(r.get::<String, _>("kind").as_str())?,
                updated_at: r.get("updated_at"),
                revoked: r.get("revoked"),
            })
        })
        .collect())
}

/// Подписанные записи (для передачи новой связи).
pub async fn signed_vouches(pool: &DbPool) -> Result<Vec<SignedMessage>, TrustError> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT signed_json FROM vouches").fetch_all(pool).await?;
    Ok(rows.iter().filter_map(|j| serde_json::from_str(j).ok()).collect())
}

/// Действующие поручительства за `subject` («за вас поручились N»).
pub async fn vouchers_of(pool: &DbPool, subject: &NodeId) -> Result<Vec<NodeId>, TrustError> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT voucher FROM vouches WHERE subject = ? AND revoked = 0")
            .bind(subject.as_str())
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(NodeId).collect())
}

/// Последняя версия нашего поручительства за `subject` (для отзыва/повтора).
pub async fn get_vouch(pool: &DbPool, voucher: &NodeId, subject: &NodeId) -> Result<Option<Vouch>, TrustError> {
    let row = sqlx::query("SELECT kind, updated_at, revoked FROM vouches WHERE voucher = ? AND subject = ?")
        .bind(voucher.as_str())
        .bind(subject.as_str())
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|r| {
        Some(Vouch {
            voucher: voucher.clone(),
            subject: subject.clone(),
            kind: VouchKind::parse(r.get::<String, _>("kind").as_str())?,
            updated_at: r.get("updated_at"),
            revoked: r.get("revoked"),
        })
    }))
}

// ─── Наблюдения (уровень «освоившийся по поведению») ─────────────────────────

/// Мы видим узел в сети (`now` — unix-секунды).
pub async fn note_seen(pool: &DbPool, id: &NodeId, now: i64) -> Result<(), TrustError> {
    sqlx::query(
        "INSERT INTO peer_activity (node_id, first_seen, last_seen) VALUES (?, ?, ?)
         ON CONFLICT (node_id) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)",
    )
    .bind(id.as_str())
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// От узла пришло «живое» сообщение: считаем дни активности (не чаще дня за раз).
pub async fn note_live_message(pool: &DbPool, id: &NodeId, now: i64) -> Result<(), TrustError> {
    let day = now.div_euclid(DAY_SECS);
    note_seen(pool, id, now).await?;
    sqlx::query(
        "UPDATE peer_activity SET
             live_messages   = live_messages + 1,
             active_days     = active_days + (CASE WHEN last_active_day = ? THEN 0 ELSE 1 END),
             last_active_day = ?
         WHERE node_id = ?",
    )
    .bind(day)
    .bind(day)
    .bind(id.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Освоившиеся «по поведению» на момент `now`: видим не меньше
/// [`SETTLE_SECS`] и писали не меньше чем в [`SETTLE_ACTIVE_DAYS`] разных дней.
/// (Отсутствие жалоб учитывает расчёт: узел под жалобами — не освоившийся.)
pub async fn settled(pool: &DbPool, now: i64) -> Result<HashSet<NodeId>, TrustError> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT node_id FROM peer_activity WHERE first_seen <= ? AND active_days >= ?",
    )
    .bind(now - SETTLE_SECS)
    .bind(SETTLE_ACTIVE_DAYS)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(NodeId).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_crypto::keys::SigningKeypair;

    fn kp(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    fn id(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&kp(seed).public_bytes())
    }

    fn signed(from: u8, to: u8, at: i64, revoked: bool) -> SignedMessage {
        Vouch { voucher: id(from), subject: id(to), kind: VouchKind::Personal, updated_at: at, revoked }
            .sign(&kp(from))
            .unwrap()
    }

    async fn db() -> (tempfile::TempDir, DbPool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = void_db::open(&dir.path().join("db.sqlite")).await.unwrap();
        (dir, pool)
    }

    #[tokio::test]
    async fn newer_version_wins_and_replay_cannot_undo_revocation() {
        let (_d, pool) = db().await;
        let original = signed(1, 2, 100, false);
        assert!(apply_signed(&pool, &original).await.unwrap().is_some());
        assert!(apply_signed(&pool, &original).await.unwrap().is_none(), "дубликат");

        assert!(apply_signed(&pool, &signed(1, 2, 200, true)).await.unwrap().is_some(), "отзыв");
        assert!(apply_signed(&pool, &original).await.unwrap().is_none(), "повтор старого после отзыва");

        let all = load_vouches(&pool).await.unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].revoked);
        assert!(vouchers_of(&pool, &id(2)).await.unwrap().is_empty());
        assert_eq!(signed_vouches(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_records_rejected() {
        let (_d, pool) = db().await;
        let forged = SignedMessage::sign(
            Vouch { voucher: id(1), subject: id(2), kind: VouchKind::Personal, updated_at: 1, revoked: false }
                .payload(),
            &kp(9),
        )
        .unwrap();
        assert!(apply_signed(&pool, &forged).await.is_err());
        assert!(load_vouches(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn per_voucher_cap_limits_storage() {
        let (_d, pool) = db().await;
        let flooder = kp(1);
        let mut accepted = 0;
        for i in 0..(MAX_VOUCHES_PER_VOUCHER + 5) {
            let subject = NodeId(format!("{:064x}", i + 1));
            let s = Vouch { voucher: id(1), subject, kind: VouchKind::Personal, updated_at: 1, revoked: false }
                .sign(&flooder)
                .unwrap();
            if apply_signed(&pool, &s).await.unwrap().is_some() {
                accepted += 1;
            }
        }
        assert_eq!(accepted, MAX_VOUCHES_PER_VOUCHER);
    }

    #[tokio::test]
    async fn settled_needs_time_and_active_days() {
        let (_d, pool) = db().await;
        let day = DAY_SECS;
        let t0 = 1_000 * day;
        let a = id(1);
        let b = id(2);
        // A: активен 3 разных дня, B — 3 сообщения в один день.
        for d in 0..3 {
            note_live_message(&pool, &a, t0 + d * day).await.unwrap();
            note_live_message(&pool, &b, t0 + 10 + d).await.unwrap();
        }
        assert!(settled(&pool, t0 + 3 * day).await.unwrap().is_empty(), "неделя ещё не прошла");
        let later = settled(&pool, t0 + 8 * day).await.unwrap();
        assert!(later.contains(&a));
        assert!(!later.contains(&b), "активность в один день не считается за три");
    }
}
