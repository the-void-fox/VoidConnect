/// reports.rs — система жалоб.
///
/// Любой узел может подать жалобу на другой. Жалоба подписывается ключом
/// заявителя и расходится по сети. Здесь — только приём и хранение: вес жалобы
/// (доверие к заявителю, своя = 1) и порог «под жалобами» (сумма ≥ 1 за 30
/// дней) считает сеть доверия в backend, а не репутация.

use serde::{Deserialize, Serialize};
use tracing::info;

use void_core::identity::NodeId;
use void_crypto::sign::SignedMessage;
use void_crypto::keys::SigningKeypair;
use void_db::{peers as db_peers, DbPool};

use crate::error::ReputationError;
use crate::score::ScoreManager;

// ─── Константы ───────────────────────────────────────────────────────────────

/// Жалобы старше этого срока не учитываются (и не принимаются).
pub const REPORT_MAX_AGE_SECS: i64 = 30 * 24 * 3600;

/// Допуск на расхождение часов: жалоба «из будущего» дальше — отбрасывается.
const REPORT_MAX_SKEW_SECS: i64 = 3600;

// ─── Причины жалоб ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportReason {
    /// Спам в чате
    Spam,
    /// Вредоносный/нежелательный контент
    MaliciousContent,
    /// Битые файловые чанки
    BadChunks,
}

impl std::fmt::Display for ReportReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportReason::Spam => write!(f, "spam"),
            ReportReason::MaliciousContent => write!(f, "malicious_content"),
            ReportReason::BadChunks => write!(f, "bad_chunks"),
        }
    }
}

// ─── Структура жалобы (для подписи и передачи по сети) ───────────────────────

/// Payload жалобы — то, что подписывается.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPayload {
    /// Публичный ключ узла, на которого жалуются
    pub target_key: String,
    /// Причина жалобы
    pub reason: ReportReason,
    /// Метка времени — защита от replay-атак (unix timestamp)
    pub timestamp: i64,
}

impl ReportPayload {
    pub fn new(target_key: String, reason: ReportReason) -> Self {
        Self {
            target_key,
            reason,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ReportPayload serialization failed")
    }
}

// ─── ReportManager ────────────────────────────────────────────────────────────

/// Управляет приёмом и хранением жалоб.
#[derive(Clone)]
pub struct ReportManager {
    pool: DbPool,
    score_manager: ScoreManager,
}

impl ReportManager {
    pub fn new(pool: DbPool, score_manager: ScoreManager) -> Self {
        Self { pool, score_manager }
    }

    /// Создаёт подписанную жалобу. Вызывается на стороне заявителя.
    pub fn create_report(
        target_id: &NodeId,
        reason: ReportReason,
        keypair: &SigningKeypair,
    ) -> Result<SignedMessage, ReputationError> {
        let payload = ReportPayload::new(target_id.as_str().to_string(), reason);
        let bytes = payload.to_bytes();
        SignedMessage::sign(bytes, keypair).map_err(ReputationError::from)
    }

    /// Принимает жалобу, проверяет подпись, срок и сохраняет. `Ok(false)` —
    /// такая жалоба уже есть (повтор по сети).
    ///
    /// `reporter_id` должен совпадать с `signed.signer` — защита от спуфинга.
    /// Чьи жалобы вообще принимать (по доверию к заявителю), решает вызывающий.
    pub async fn receive_report(
        &self,
        signed: SignedMessage,
        reporter_id: &NodeId,
    ) -> Result<bool, ReputationError> {
        signed.verify().map_err(ReputationError::from)?;
        if signed.signer != reporter_id.as_str() {
            return Err(ReputationError::SignerMismatch);
        }
        let payload: ReportPayload = serde_json::from_slice(&signed.payload)
            .map_err(|e| ReputationError::Deserialize(e.to_string()))?;
        if payload.target_key == reporter_id.as_str() {
            return Err(ReputationError::SelfReport);
        }
        let now = chrono::Utc::now().timestamp();
        if payload.timestamp < now - REPORT_MAX_AGE_SECS || payload.timestamp > now + REPORT_MAX_SKEW_SECS {
            return Err(ReputationError::StaleReport);
        }
        if db_peers::report_exists(&self.pool, &signed.signature).await? {
            return Ok(false);
        }

        // reputation_reports.target_key ссылается на peers (FK) — строка нужна.
        let target_id = NodeId(payload.target_key.clone());
        let _ = self.score_manager.init(&target_id).await;
        db_peers::add_report(
            &self.pool,
            &payload.target_key,
            reporter_id.as_str(),
            &payload.reason.to_string(),
            &signed.signature,
        )
        .await
        .map_err(ReputationError::from)?;

        info!("Report received: {} reported {} for {}", reporter_id, target_id, payload.reason);
        Ok(true)
    }

    /// Количество уникальных жалоб на узел.
    pub async fn report_count(&self, peer_id: &NodeId) -> Result<i64, ReputationError> {
        db_peers::count_reports(&self.pool, peer_id.as_str())
            .await
            .map_err(ReputationError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_core::identity::NodeId;
    use void_db::open;

    use crate::score::ScoreManager;

    fn reporter(seed: u8) -> (SigningKeypair, NodeId) {
        let kp = SigningKeypair::from_seed(&[seed; 32]).unwrap();
        let id = NodeId::from_public_key_bytes(&kp.public_bytes());
        (kp, id)
    }

    async fn manager() -> (tempfile::TempDir, ReportManager, ScoreManager) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let score = ScoreManager::new(pool.clone());
        (dir, ReportManager::new(pool, score.clone()), score)
    }

    /// Жалобы сохраняются, повтор не дублируется, репутацию они не трогают
    /// (их вес считает сеть доверия).
    #[tokio::test]
    async fn reports_stored_once_without_score_penalty() {
        let (_dir, mgr, score) = manager().await;
        let target = NodeId::from_public_key_bytes(&[200u8; 32]);
        for seed in 1..=3u8 {
            let (kp, rid) = reporter(seed);
            let signed = ReportManager::create_report(&target, ReportReason::Spam, &kp).unwrap();
            assert!(mgr.receive_report(signed.clone(), &rid).await.unwrap());
            assert!(!mgr.receive_report(signed, &rid).await.unwrap(), "повтор по сети");
        }
        assert_eq!(mgr.report_count(&target).await.unwrap(), 3);
        assert_eq!(score.score(&target).await, 0.0);
    }

    /// Подмена подписанта и жалоба на себя отклоняются.
    #[tokio::test]
    async fn signer_mismatch_and_self_report_rejected() {
        let (_dir, mgr, _) = manager().await;
        let target = NodeId::from_public_key_bytes(&[200u8; 32]);
        let (kp, real) = reporter(1);
        let (_kp2, other) = reporter(2);
        let signed = ReportManager::create_report(&target, ReportReason::Spam, &kp).unwrap();
        assert!(matches!(mgr.receive_report(signed, &other).await, Err(ReputationError::SignerMismatch)));
        let selfie = ReportManager::create_report(&real, ReportReason::Spam, &kp).unwrap();
        assert!(matches!(mgr.receive_report(selfie, &real).await, Err(ReputationError::SelfReport)));
    }

    /// Жалоба старше 30 дней или «из будущего» не принимается.
    #[tokio::test]
    async fn stale_reports_rejected() {
        let (_dir, mgr, _) = manager().await;
        let (kp, rid) = reporter(1);
        let now = chrono::Utc::now().timestamp();
        for ts in [now - REPORT_MAX_AGE_SECS - 10, now + 2 * REPORT_MAX_SKEW_SECS] {
            let payload = ReportPayload { target_key: "aa".repeat(32), reason: ReportReason::Spam, timestamp: ts };
            let signed = SignedMessage::sign(payload.to_bytes(), &kp).unwrap();
            assert!(matches!(mgr.receive_report(signed, &rid).await, Err(ReputationError::StaleReport)));
        }
    }
}
