/// sync.rs — синхронизация репутации между узлами.
///
/// При подключении нового пира обмениваемся нашими локальными оценками.
/// Все оценки подписаны ключом оценивающего — нельзя анонимно накрутить.
/// Применяется взвешенное усреднение: вес голоса = score оценивающего.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::debug;

use void_core::identity::NodeId;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_db::{peers as db_peers, DbPool};

use crate::error::ReputationError;
use crate::score::{ScoreManager, MIN_TRUSTED_SCORE, SCORE_MAX, SCORE_MIN};

// ─── Константы ───────────────────────────────────────────────────────────────

/// Максимальное число записей репутации в одном sync-пакете.
const MAX_SYNC_ENTRIES: usize = 200;

/// Вес мнения узла с максимальным score. Даже самый уважаемый узел сдвигает
/// нашу оценку лишь частично — один узел не диктует репутацию другого.
const MAX_VOTE_WEIGHT: f64 = 0.2;

/// Максимальный сдвиг оценки одного узла за один принятый снимок.
const MAX_DELTA_PER_SYNC: f64 = 2.0;

/// Не чаще одного принятого снимка от отправителя за этот интервал (секунды
/// по меткам времени снимков). Заодно отсекает повторы (replay) старых снимков.
const MIN_SYNC_INTERVAL_SECS: i64 = 60;

/// Допустимое расхождение часов отправителя с нашими (секунды).
const MAX_CLOCK_SKEW_SECS: i64 = 600;

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
    /// Метка времени последнего ПРИНЯТОГО снимка от каждого отправителя.
    last_accepted: Mutex<HashMap<String, i64>>,
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
            last_accepted: Mutex::new(HashMap::new()),
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
        let sync = Self::verify_sync(from, signed)?;

        // Мнение влияет, только если отправитель уже заслужил доверие У НАС.
        let sender_score = self.score_manager.score(from).await;
        if !(sender_score >= MIN_TRUSTED_SCORE) {
            return Err(ReputationError::UntrustedSender);
        }

        // Повтор/слишком частые снимки: метка времени должна расти не меньше
        // чем на MIN_SYNC_INTERVAL_SECS с последнего принятого.
        {
            let mut last = self.last_accepted.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(&prev) = last.get(from.as_str()) {
                if sync.timestamp < prev + MIN_SYNC_INTERVAL_SECS {
                    return Err(ReputationError::StaleSync);
                }
            }
            last.insert(from.as_str().to_string(), sync.timestamp);
        }

        let vote_weight = MAX_VOTE_WEIGHT * (sender_score / SCORE_MAX).min(1.0);
        debug!(
            "Applying reputation sync from {} (weight={:.2}, entries={})",
            from, vote_weight, sync.entries.len()
        );
        self.apply_sync(sync, vote_weight, from).await
    }

    /// Проверяет снимок без применения: подписант = `from`, подпись верна,
    /// payload разбирается, метка времени близка к нашим часам. Backend
    /// использует это и для чтения «что пир думает о нас» (только отображение).
    pub fn verify_sync(from: &NodeId, signed: &SignedMessage) -> Result<SyncPayload, ReputationError> {
        if signed.signer != from.as_str() {
            return Err(ReputationError::SignerMismatch);
        }
        signed.verify().map_err(ReputationError::from)?;
        let sync: SyncPayload = serde_json::from_slice(&signed.payload)
            .map_err(|e| ReputationError::Deserialize(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();
        if (sync.timestamp - now).abs() > MAX_CLOCK_SKEW_SECS {
            return Err(ReputationError::StaleSync);
        }
        Ok(sync)
    }

    // ─── Применение входящих данных ───────────────────────────────────────────

    /// Применяет взвешенное среднее от sync-пакета к локальным данным.
    ///
    /// Формула: new_score = current * (1 - w) + received * w, где
    /// w = vote_weight (0..MAX_VOTE_WEIGHT), received обрезается до
    /// [SCORE_MIN, SCORE_MAX], а сдвиг — до ±MAX_DELTA_PER_SYNC.
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

            if !entry.score.is_finite() {
                continue;
            }
            let received = entry.score.clamp(SCORE_MIN, SCORE_MAX);

            let target_id = NodeId(entry.target_key.clone());

            // Гарантируем существование строк peers+reputation (FK), иначе
            // последующий UPDATE не найдёт записи.
            let _ = self.score_manager.init(&target_id).await;

            // Получаем текущий score
            let current = self.score_manager.score(&target_id).await;

            // Взвешенное среднее
            let blended = current * (1.0 - vote_weight) + received * vote_weight;
            let delta = (blended - current).clamp(-MAX_DELTA_PER_SYNC, MAX_DELTA_PER_SYNC);

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

    /// Подписанный снимок оценок применяется получателем взвешенно: B доверяет
    /// A (score 50 → вес 0.1) и сдвигает свою оценку X к присланной, но не
    /// больше чем на MAX_DELTA_PER_SYNC за снимок.
    #[tokio::test]
    async fn signed_sync_applies_weighted() {
        // A знает X с заметным score.
        let (_da, score_a, sync_a, _a_id) = manager(1).await;
        let x = NodeId::from_public_key_bytes(&[9u8; 32]);
        score_a.record_bootstrap_assist(&x, 50.0).await;
        assert!((score_a.score(&x).await - 50.0).abs() < 1e-6);

        let signed = sync_a.build_signed_sync().await.unwrap();
        let (_a_kp, a_id) = keypair(1);

        let (_db, score_b, sync_b, _b_id) = manager(2).await;
        score_b.record_bootstrap_assist(&a_id, 50.0).await;
        assert_eq!(score_b.score(&x).await, 0.0);
        sync_b.apply_signed_sync(&a_id, &signed).await.unwrap();

        // Без лимита было бы 0·0.9 + 50·0.1 = 5.0; сдвиг ограничен 2.0.
        let blended = score_b.score(&x).await;
        assert!((blended - MAX_DELTA_PER_SYNC).abs() < 1e-6,
            "ожидался сдвиг ровно на {MAX_DELTA_PER_SYNC}, получено {blended}");
    }

    /// Подписывает произвольный снимок ключом `seed` (как это сделал бы злой узел).
    fn forged_sync(seed: u8, target: &NodeId, score: f64, timestamp: i64) -> (NodeId, SignedMessage) {
        let (kp, id) = keypair(seed);
        let payload = SyncPayload {
            entries: vec![ReputationEntry { target_key: target.as_str().to_string(), score }],
            timestamp,
        };
        (id, SignedMessage::sign(payload.to_bytes(), &kp).unwrap())
    }

    /// Свежий ключ (у нас score 0) не влияет на чужую репутацию — иначе одна
    /// машина с пачкой новых ключей назначала бы кому угодно любой score.
    #[tokio::test]
    async fn untrusted_sender_has_no_influence() {
        let (_d, score, sync, _id) = manager(2).await;
        let x = NodeId::from_public_key_bytes(&[9u8; 32]);
        let (from, signed) = forged_sync(1, &x, 100.0, chrono::Utc::now().timestamp());

        let res = sync.apply_signed_sync(&from, &signed).await;
        assert!(matches!(res, Err(ReputationError::UntrustedSender)));
        assert_eq!(score.score(&x).await, 0.0);
    }

    /// Огромная оценка от доверенного узла обрезается: сдвиг не больше лимита.
    #[tokio::test]
    async fn huge_score_is_clamped() {
        let (_d, score, sync, _id) = manager(2).await;
        let x = NodeId::from_public_key_bytes(&[9u8; 32]);
        let (from, signed) = forged_sync(1, &x, 1e300, chrono::Utc::now().timestamp());
        score.record_bootstrap_assist(&from, 100.0).await;

        sync.apply_signed_sync(&from, &signed).await.unwrap();
        let s = score.score(&x).await;
        assert!(s > 0.0 && s <= MAX_DELTA_PER_SYNC + 1e-9, "score X = {s}");
    }

    /// Повтор того же снимка и снимок со старой меткой времени отклоняются.
    #[tokio::test]
    async fn replayed_or_stale_sync_rejected() {
        let (_d, score, sync, _id) = manager(2).await;
        let x = NodeId::from_public_key_bytes(&[9u8; 32]);
        let now = chrono::Utc::now().timestamp();
        let (from, signed) = forged_sync(1, &x, 50.0, now);
        score.record_bootstrap_assist(&from, 100.0).await;

        sync.apply_signed_sync(&from, &signed).await.unwrap();
        let after_first = score.score(&x).await;
        let replay = sync.apply_signed_sync(&from, &signed).await;
        assert!(matches!(replay, Err(ReputationError::StaleSync)));
        assert_eq!(score.score(&x).await, after_first, "повтор не должен двигать score");

        let (from2, old) = forged_sync(3, &x, 50.0, now - 3600);
        score.record_bootstrap_assist(&from2, 100.0).await;
        assert!(matches!(
            sync.apply_signed_sync(&from2, &old).await,
            Err(ReputationError::StaleSync)
        ));
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