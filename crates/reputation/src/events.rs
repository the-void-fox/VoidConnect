/// events.rs — события, влияющие на репутацию.
///
/// Репутация — локальная оценка **качества раздачи** (валидные и битые чанки,
/// отдача) плюс спам-страйки флуда. Доверие к людям считает сеть доверия
/// (`void-trust`), а не она: бонус за аптайм и обмен снимками убраны.

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use void_core::identity::NodeId;
use void_network::rate_limit::RateLimiter;

use crate::score::ScoreManager;

// ─── Тип события ──────────────────────────────────────────────────────────────

/// Всё, что может повлиять на репутацию узла.
#[derive(Debug, Clone)]
pub enum ReputationEvent {
    /// Узел успешно передал чанк нужного размера.
    ValidChunk {
        peer_id: NodeId,
        size_bytes: i64,
    },
    /// Узел передал чанк, не прошедший SHA-256 верификацию.
    BadChunk {
        peer_id: NodeId,
    },
    /// Узел превысил rate limit (спам/флуд).
    SpamStrike {
        peer_id: NodeId,
    },
}

// ─── EventProcessor ───────────────────────────────────────────────────────────

/// Принимает ReputationEvent и применяет их к ScoreManager.
#[derive(Clone)]
pub struct EventProcessor {
    score_manager: ScoreManager,
    /// Rate limiter — для принудительной блокировки после спам-страйков.
    rate_limiter: Arc<RateLimiter>,
}

impl EventProcessor {
    pub fn new(score_manager: ScoreManager, rate_limiter: Arc<RateLimiter>) -> Self {
        Self { score_manager, rate_limiter }
    }

    // ─── Публичный API ────────────────────────────────────────────────────────

    /// Обрабатывает событие репутации. Вызывать из любого места крейта.
    pub async fn process(&self, event: ReputationEvent) {
        match event {
            ReputationEvent::ValidChunk { peer_id, size_bytes } => {
                self.score_manager.record_valid_chunk(&peer_id, size_bytes).await;
            }

            ReputationEvent::BadChunk { peer_id } => {
                self.score_manager.record_bad_chunk(&peer_id).await;
                // Дополнительно проверяем — если репутация упала до отрицательной,
                // принудительно блокируем через rate limiter
                self.maybe_block_negative(&peer_id).await;
            }

            ReputationEvent::SpamStrike { peer_id } => {
                self.score_manager.record_spam_strike(&peer_id).await;
                self.maybe_block_negative(&peer_id).await;
            }
        }
    }

    // ─── Внутреннее ──────────────────────────────────────────────────────────

    /// Если репутация ушла в отрицательную зону — блокируем узел на 10 минут.
    async fn maybe_block_negative(&self, peer_id: &NodeId) {
        use crate::score::ReputationLevel;

        if self.score_manager.level(peer_id).await == ReputationLevel::Negative {
            warn!(
                "Reputation: {} has negative score, applying temp block",
                peer_id
            );
            self.rate_limiter
                .block_peer(peer_id, Duration::from_secs(600))
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_db::open;
    use void_network::rate_limit::RateLimiter;

    fn node(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&[seed; 32])
    }

    async fn make_processor() -> (tempfile::TempDir, ScoreManager, EventProcessor) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("db.sqlite")).await.unwrap();
        let score = ScoreManager::new(pool);
        let proc = EventProcessor::new(score.clone(), Arc::new(RateLimiter::new()));
        (dir, score, proc)
    }

    /// Валидный чанк поднимает репутацию, поток битых чанков уводит её в минус.
    #[tokio::test]
    async fn chunk_events_move_score_in_expected_direction() {
        let (_dir, score, proc) = make_processor().await;
        let peer = node(1);

        proc.process(ReputationEvent::ValidChunk { peer_id: peer.clone(), size_bytes: 1000 }).await;
        let after_valid = score.score(&peer).await;
        assert!(after_valid > 0.0, "валидный чанк должен поднять score, получено {after_valid}");

        for _ in 0..50 {
            proc.process(ReputationEvent::BadChunk { peer_id: peer.clone() }).await;
        }
        let after_bad = score.score(&peer).await;
        assert!(after_bad < after_valid, "битые чанки должны понизить score");
        assert!(after_bad < 0.0, "поток битых чанков уводит score в минус, получено {after_bad}");
    }
}
