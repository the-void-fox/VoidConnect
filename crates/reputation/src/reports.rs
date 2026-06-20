/// reports.rs — система жалоб.
///
/// Любой узел может подать жалобу на другой.
/// Жалоба подписывается приватным ключом заявителя.
/// При накоплении N уникальных жалоб — автоматический штраф репутации.

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use void_core::identity::NodeId;
use void_crypto::sign::SignedMessage;
use void_crypto::keys::SigningKeypair;
use void_db::{peers as db_peers, DbPool};

use crate::error::ReputationError;
use crate::score::ScoreManager;

// ─── Константы ───────────────────────────────────────────────────────────────

/// Сколько уникальных жалоб нужно для автоматического штрафа.
const REPORTS_THRESHOLD: i64 = 3;

/// Штраф за превышение порога жалоб.
const REPORT_PENALTY: f64 = -5.0;

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

    // ─── Создание жалобы (на стороне репортера) ───────────────────────────────

    /// Создаёт подписанную жалобу. Вызывается на стороне заявителя.
    ///
    /// # Пример
    /// ```ignore
    /// let signed = manager.create_report(
    ///     &target_id,
    ///     ReportReason::Spam,
    ///     &my_keypair,
    /// ).await?;
    /// // затем signed сериализуется и отправляется через Router
    /// ```
    pub fn create_report(
        target_id: &NodeId,
        reason: ReportReason,
        keypair: &SigningKeypair,
    ) -> Result<SignedMessage, ReputationError> {
        let payload = ReportPayload::new(target_id.as_str().to_string(), reason);
        let bytes = payload.to_bytes();
        SignedMessage::sign(bytes, keypair).map_err(ReputationError::from)
    }

    // ─── Приём жалобы (на принимающей стороне) ────────────────────────────────

    /// Принимает жалобу от другого узла, верифицирует подпись и сохраняет.
    ///
    /// `reporter_id` — NodeId отправителя (из Router event), должен совпадать
    /// с `signed.signer` для защиты от спуфинга.
    pub async fn receive_report(
        &self,
        signed: SignedMessage,
        reporter_id: &NodeId,
    ) -> Result<(), ReputationError> {
        // 1. Верифицируем подпись
        signed.verify().map_err(ReputationError::from)?;

        // 2. Проверяем что reporter_id совпадает с подписантом
        //    (нельзя отправить жалобу от имени чужого ключа)
        if signed.signer != reporter_id.as_str() {
            warn!(
                "Report signer mismatch: signed.signer={}, reporter={}",
                signed.signer, reporter_id
            );
            return Err(ReputationError::SignerMismatch);
        }

        // 3. Десериализуем payload
        let payload: ReportPayload = serde_json::from_slice(&signed.payload)
            .map_err(|e| ReputationError::Deserialize(e.to_string()))?;

        // 4. Нельзя пожаловаться на себя
        if payload.target_key == reporter_id.as_str() {
            return Err(ReputationError::SelfReport);
        }

        // 5. Сохраняем жалобу в БД. Сначала гарантируем наличие узла-цели —
        //    reputation_reports.target_key ссылается на peers (FK), а строка
        //    репутации нужна для последующего штрафа.
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

        info!(
            "Report received: {} reported {} for {}",
            reporter_id, target_id, payload.reason
        );

        // 6. Проверяем порог — если накопилось N жалоб, применяем штраф
        self.maybe_apply_report_penalty(&target_id).await?;

        Ok(())
    }

    // ─── Чтение ──────────────────────────────────────────────────────────────

    /// Количество уникальных жалоб на узел.
    pub async fn report_count(&self, peer_id: &NodeId) -> Result<i64, ReputationError> {
        db_peers::count_reports(&self.pool, peer_id.as_str())
            .await
            .map_err(ReputationError::from)
    }

    // ─── Внутреннее ──────────────────────────────────────────────────────────

    /// Применяет штраф если число жалоб достигло порога.
    async fn maybe_apply_report_penalty(&self, target_id: &NodeId) -> Result<(), ReputationError> {
        let count = self.report_count(target_id).await?;

        // Штраф применяется кратно порогу:
        // 3 жалобы → первый штраф, 6 жалоб → второй, и т.д.
        if count > 0 && count % REPORTS_THRESHOLD == 0 {
            warn!(
                "Reputation: {} has {} reports, applying penalty {}",
                target_id, count, REPORT_PENALTY
            );

            use void_db::peers::ReputationDelta;
            let _ = db_peers::init_reputation(&self.pool, target_id.as_str()).await;
            db_peers::apply_reputation_delta(
                &self.pool,
                target_id.as_str(),
                ReputationDelta {
                    // Фиксируем через spam_strikes т.к. это ближайший сематически
                    // подходящий счётчик; штраф на score уже применится через формулу в БД.
                    // Здесь используем прямой подход — передаём в bootstrap_bonus отрицательное
                    // значение, т.к. оно напрямую суммируется со score.
                    bootstrap_bonus: REPORT_PENALTY,
                    ..Default::default()
                },
            )
            .await
            .map_err(ReputationError::from)?;
        }

        Ok(())
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

    /// Три уникальные жалобы достигают порога и снижают репутацию цели;
    /// подмена подписанта отклоняется.
    #[tokio::test]
    async fn three_unique_reports_apply_penalty() {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let score = ScoreManager::new(pool.clone());
        let mgr = ReportManager::new(pool, score.clone());

        let target = NodeId::from_public_key_bytes(&[200u8; 32]);
        let before = score.score(&target).await;

        for seed in 1..=3u8 {
            let (kp, rid) = reporter(seed);
            let signed = ReportManager::create_report(&target, ReportReason::Spam, &kp).unwrap();
            mgr.receive_report(signed, &rid).await.unwrap();
        }

        assert_eq!(mgr.report_count(&target).await.unwrap(), 3);
        let after = score.score(&target).await;
        assert!(after < before, "после 3 жалоб репутация падает (before={before}, after={after})");
    }

    /// Жалоба с подписантом, не совпадающим с reporter_id, отклоняется.
    #[tokio::test]
    async fn report_signer_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let score = ScoreManager::new(pool.clone());
        let mgr = ReportManager::new(pool, score);

        let target = NodeId::from_public_key_bytes(&[200u8; 32]);
        let (kp, _real) = reporter(1);
        let (_kp2, other) = reporter(2);
        let signed = ReportManager::create_report(&target, ReportReason::Spam, &kp).unwrap();

        // reporter_id (other) ≠ подписант (real) → отклонение.
        let res = mgr.receive_report(signed, &other).await;
        assert!(matches!(res, Err(ReputationError::SignerMismatch)));
    }
}