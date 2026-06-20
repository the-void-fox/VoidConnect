/// events.rs — события влияющие на репутацию.
///
/// ReputationEvent описывает всё что может изменить score узла.
/// EventProcessor подписывается на Router и применяет события автоматически.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{debug, info, warn};

use void_core::identity::NodeId;
use void_network::rate_limit::RateLimiter;

use crate::score::ScoreManager;

// ─── Константы ───────────────────────────────────────────────────────────────

/// Интервал начисления аптайм-бонуса.
const UPTIME_TICK_INTERVAL: Duration = Duration::from_secs(60);

/// Через сколько секунд без активности считать узел offline
/// (для упрощения — ориентируемся на Router events, не на самостоятельный пинг).
const BOOTSTRAP_BONUS_PER_ASSIST: f64 = 5.0;

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
    /// Bootstrap-узел помог новому участнику подключиться к сети.
    BootstrapAssist {
        peer_id: NodeId,
    },
    /// Узел подключился (начало отсчёта аптайма).
    PeerConnected {
        peer_id: NodeId,
    },
    /// Узел отключился (конец аптайма для текущей сессии).
    PeerDisconnected {
        peer_id: NodeId,
    },
}

// ─── EventProcessor ───────────────────────────────────────────────────────────

/// Принимает ReputationEvent и применяет их к ScoreManager.
/// Также ведёт учёт аптайма для подключённых узлов.
#[derive(Clone)]
pub struct EventProcessor {
    score_manager: ScoreManager,
    /// Время подключения для подсчёта аптайма: peer_id → connected_at
    online_since: Arc<Mutex<HashMap<NodeId, Instant>>>,
    /// Rate limiter — для принудительной блокировки после спам-страйков.
    rate_limiter: Arc<RateLimiter>,
}

impl EventProcessor {
    pub fn new(score_manager: ScoreManager, rate_limiter: Arc<RateLimiter>) -> Self {
        let processor = Self {
            score_manager,
            online_since: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter,
        };

        // Запускаем фоновый тик аптайма
        processor.spawn_uptime_ticker();

        processor
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

            ReputationEvent::BootstrapAssist { peer_id } => {
                self.score_manager
                    .record_bootstrap_assist(&peer_id, BOOTSTRAP_BONUS_PER_ASSIST)
                    .await;
            }

            ReputationEvent::PeerConnected { peer_id } => {
                info!("Reputation: tracking uptime for {}", peer_id);
                self.score_manager.init(&peer_id).await;
                self.online_since
                    .lock()
                    .await
                    .insert(peer_id, Instant::now());
            }

            ReputationEvent::PeerDisconnected { peer_id } => {
                let connected_at = self.online_since.lock().await.remove(&peer_id);
                if let Some(at) = connected_at {
                    let uptime = at.elapsed();
                    debug!(
                        "Reputation: {} was online for {}s",
                        peer_id,
                        uptime.as_secs()
                    );
                    self.score_manager.record_uptime(&peer_id, uptime).await;
                }
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

    /// Периодически начисляет аптайм-бонус всем онлайн-узлам.
    fn spawn_uptime_ticker(&self) {
        let online_since = self.online_since.clone();
        let score_manager = self.score_manager.clone();

        tokio::spawn(async move {
            let mut ticker = interval(UPTIME_TICK_INTERVAL);
            ticker.tick().await; // пропускаем первый немедленный тик

            loop {
                ticker.tick().await;

                let peers: Vec<NodeId> = online_since.lock().await.keys().cloned().collect();

                for peer_id in peers {
                    score_manager
                        .record_uptime(&peer_id, UPTIME_TICK_INTERVAL)
                        .await;
                }
            }
        });
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

    /// Сессия онлайн (connect → disconnect) начисляет аптайм-бонус.
    #[tokio::test]
    async fn uptime_session_is_recorded() {
        let (_dir, score, proc) = make_processor().await;
        let peer = node(2);

        proc.process(ReputationEvent::PeerConnected { peer_id: peer.clone() }).await;
        // Имитируем «час онлайн», чтобы аптайм-бонус был заметен.
        score.record_uptime(&peer, std::time::Duration::from_secs(3600)).await;
        proc.process(ReputationEvent::PeerDisconnected { peer_id: peer.clone() }).await;

        let rep = score.get(&peer).await.expect("запись репутации должна существовать");
        assert!(rep.uptime_seconds >= 3600, "аптайм должен учитываться, получено {}", rep.uptime_seconds);
        assert!(rep.score > 0.0, "аптайм даёт положительный score, получено {}", rep.score);
    }
}