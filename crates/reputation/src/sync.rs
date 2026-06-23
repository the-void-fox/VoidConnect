/// sync.rs — синхронизация репутации между узлами.
///
/// При подключении нового пира обмениваемся нашими локальными оценками.
/// Все оценки подписаны ключом оценивающего — нельзя анонимно накрутить.
/// Применяется взвешенное усреднение: вес голоса = score оценивающего.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;

use void_core::identity::NodeId;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_db::{peers as db_peers, DbPool};

use crate::error::ReputationError;
use crate::score::ScoreManager;

// ─── Константы ───────────────────────────────────────────────────────────────

/// Максимальное число записей репутации в одном sync-пакете.
const MAX_SYNC_ENTRIES: usize = 200;

/// Минимальный вес голоса нового узла (score = 0).
const MIN_VOTE_WEIGHT: f64 = 0.1;

// ─── Структуры синхронизации ──────────────────────────────────────────────────

/// Одна запись в sync-пакете: оценка конкретного узла.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEntry {
    /// Чей score передаём
    pub target_key: String,
    /// Значение score по мнению отправляющего узла
    pub score: f64,
}

/// Payload пакета синхронизации (подписывается целиком).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    /// Оценки отправителя
    pub entries: Vec<ReputationEntry>,
    /// Метка времени (unix timestamp)
    pub timestamp: i64,
}

impl SyncPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SyncPayload serialization failed")
    }
}

/// Payload одной оценки репутации (входит в SignedMessage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationVote {
    /// Чью репутацию оцениваем
    pub target_key: String,
    /// Оценка score
    pub score: f64,
    /// Метка времени
    pub timestamp: i64,
}

impl ReputationVote {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ReputationVote serialization failed")
    }
}

// ─── SyncManager ──────────────────────────────────────────────────────────────

/// Управляет синхронизацией репутации между узлами (gossip через relay чата).
pub struct SyncManager {
    pool: DbPool,
    score_manager: ScoreManager,
    my_keypair: Arc<SigningKeypair>,
    my_id: NodeId,
}

impl SyncManager {
    pub fn new(
        pool: DbPool,
        score_manager: ScoreManager,
        my_keypair: Arc<SigningKeypair>,
        my_id: NodeId,
    ) -> Self {
        Self {
            pool,
            score_manager,
            my_keypair,
            my_id,
        }
    }

    // ─── Построение sync-пакета ───────────────────────────────────────────────

    /// Строит подписанный снимок наших локальных оценок — транспорт-независимо
    /// (используется и Router-путём, и gossip через relay чата).
    pub async fn build_signed_sync(&self) -> Result<SignedMessage, ReputationError> {
        let all_peers = db_peers::list_peers(&self.pool)
            .await
            .map_err(ReputationError::from)?;

        let entries: Vec<ReputationEntry> = {
            let mut result = Vec::new();
            for peer in all_peers.iter().take(MAX_SYNC_ENTRIES) {
                if let Ok(Some(rep)) =
                    db_peers::get_reputation(&self.pool, &peer.public_key).await
                {
                    result.push(ReputationEntry {
                        target_key: peer.public_key.clone(),
                        score: rep.score,
                    });
                }
            }
            result
        };

        let payload = SyncPayload {
            entries,
            timestamp: chrono::Utc::now().timestamp(),
        };

        SignedMessage::sign(payload.to_bytes(), &self.my_keypair).map_err(ReputationError::from)
    }

    /// Применяет подписанный снимок от узла `from` (взвешенное усреднение).
    /// Транспорт-независимый приём (для gossip через relay чата).
    pub async fn apply_signed_sync(
        &self,
        from: &NodeId,
        signed: &SignedMessage,
    ) -> Result<(), ReputationError> {
        if signed.signer != from.as_str() {
            return Err(ReputationError::SignerMismatch);
        }
        signed.verify().map_err(ReputationError::from)?;

        let sync: SyncPayload = serde_json::from_slice(&signed.payload)
            .map_err(|e| ReputationError::Deserialize(e.to_string()))?;

        let sender_score = self.score_manager.score(from).await;
        let vote_weight = (sender_score / 100.0).clamp(MIN_VOTE_WEIGHT, 1.0);
        debug!(
            "Applying reputation sync from {} (weight={:.2}, entries={})",
            from, vote_weight, sync.entries.len()
        );
        self.apply_sync(sync, vote_weight, from).await
    }

    // ─── Применение входящих данных ───────────────────────────────────────────

    /// Применяет взвешенное среднее от sync-пакета к локальным данным.
    ///
    /// Формула: new_score = current * (1 - w) + received * w
    /// где w = vote_weight (от 0.1 до 1.0)
    async fn apply_sync(
        &self,
        sync: SyncPayload,
        vote_weight: f64,
        from: &NodeId,
    ) -> Result<(), ReputationError> {
        for entry in sync.entries.iter().take(MAX_SYNC_ENTRIES) {
            // Не принимаем оценки себя самого
            if entry.target_key == self.my_id.as_str() {
                continue;
            }

            // Не принимаем оценки от того, кого оцениваем (круговые)
            if entry.target_key == from.as_str() {
                continue;
            }

            let target_id = NodeId(entry.target_key.clone());

            // Гарантируем существование строк peers+reputation (FK), иначе
            // последующий UPDATE не найдёт записи.
            let _ = self.score_manager.init(&target_id).await;

            // Получаем текущий score
            let current = self.score_manager.score(&target_id).await;

            // Взвешенное среднее
            let blended = current * (1.0 - vote_weight) + entry.score * vote_weight;
            let delta = blended - current;

            if delta.abs() < 0.01 {
                // Изменение слишком мало — пропускаем
                continue;
            }

            // Применяем дельту через bootstrap_bonus (прямое сложение со score)
            db_peers::apply_reputation_delta(
                &self.pool,
                &entry.target_key,
                void_db::peers::ReputationDelta {
                    bootstrap_bonus: delta,
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
    use void_db::open;
    use void_crypto::keys::SigningKeypair;

    use crate::score::ScoreManager;

    fn keypair(seed: u8) -> (Arc<SigningKeypair>, NodeId) {
        let kp = Arc::new(SigningKeypair::from_seed(&[seed; 32]).unwrap());
        let id = NodeId::from_public_key_bytes(&kp.public_bytes());
        (kp, id)
    }

    async fn manager(seed: u8) -> (tempfile::TempDir, ScoreManager, Arc<SyncManager>, NodeId) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let (kp, id) = keypair(seed);
        let score = ScoreManager::new(pool.clone());
        let sync = Arc::new(SyncManager::new(pool, score.clone(), kp, id.clone()));
        (dir, score, sync, id)
    }

    /// Подписанный снимок оценок применяется получателем взвешенно: B, не зная
    /// A (вес минимальный), сдвигает свою оценку X к присланной.
    #[tokio::test]
    async fn signed_sync_applies_weighted() {
        // A знает X с заметным score.
        let (_da, score_a, sync_a, _a_id) = manager(1).await;
        let x = NodeId::from_public_key_bytes(&[9u8; 32]);
        score_a.record_bootstrap_assist(&x, 50.0).await;
        assert!((score_a.score(&x).await - 50.0).abs() < 1e-6);

        let signed = sync_a.build_signed_sync().await.unwrap();
        let (_a_kp, a_id) = keypair(1);

        // B применяет снимок A. B не знает A → минимальный вес (0.1).
        let (_db, score_b, sync_b, _b_id) = manager(2).await;
        assert_eq!(score_b.score(&x).await, 0.0);
        sync_b.apply_signed_sync(&a_id, &signed).await.unwrap();

        let blended = score_b.score(&x).await;
        assert!(blended > 0.0 && blended < 50.0,
            "B сдвигает оценку X к присланной с малым весом, получено {blended}");
        assert!((blended - 5.0).abs() < 0.5, "ожидался ~5.0 (вес 0.1), получено {blended}");
    }

    /// Снимок с подписантом ≠ from отклоняется.
    #[tokio::test]
    async fn sync_signer_mismatch_rejected() {
        let (_da, _score_a, sync_a, _a_id) = manager(1).await;
        let signed = sync_a.build_signed_sync().await.unwrap();
        let (_kp, wrong) = keypair(7);
        let res = sync_a.apply_signed_sync(&wrong, &signed).await;
        assert!(matches!(res, Err(ReputationError::SignerMismatch)));
    }
}