/// void-reputation — система репутации для Void Connect.
///
/// ## Архитектура
///
/// ```text
/// Router (network events)
///     │
///     ▼
/// SyncManager ──► EventProcessor ──► ScoreManager ──► void-db
///                      │
///                      ▼
///                 RateLimiter (block negative peers)
/// ```
///
/// ## Быстрый старт
///
/// ```rust,ignore
/// let reputation = reputation::start(
///     db_pool,
///     router,
///     rate_limiter,
///     my_keypair,
///     my_node_id,
/// ).await;
///
/// // Отметить плохой чанк
/// reputation.bad_chunk(&peer_id).await;
///
/// // Подать жалобу
/// reputation.report(&target_id, ReportReason::Spam, &keypair)?;
/// ```

pub mod error;
pub mod events;
pub mod reports;
pub mod score;
pub mod sync;

use std::sync::Arc;

use void_core::identity::NodeId;
use void_crypto::keys::SigningKeypair;
use void_db::DbPool;
use void_network::{rate_limit::RateLimiter, router::Router};

pub use error::ReputationError;
pub use events::{EventProcessor, ReputationEvent};
pub use reports::{ReportManager, ReportReason};
pub use score::{ReputationLevel, ScoreManager};
pub use sync::SyncManager;

/// Единая точка входа в систему репутации.
///
/// Создаёт все компоненты, запускает фоновые задачи.
pub struct ReputationSystem {
    pub score: ScoreManager,
    pub events: EventProcessor,
    pub reports: ReportManager,
}

impl ReputationSystem {
    // ─── Публичный API ────────────────────────────────────────────────────────

    /// Сообщает о успешно переданном чанке.
    pub async fn valid_chunk(&self, peer_id: &NodeId, size_bytes: i64) {
        self.events
            .process(ReputationEvent::ValidChunk {
                peer_id: peer_id.clone(),
                size_bytes,
            })
            .await;
    }

    /// Сообщает о плохом чанке (не прошёл SHA-256).
    pub async fn bad_chunk(&self, peer_id: &NodeId) {
        self.events
            .process(ReputationEvent::BadChunk {
                peer_id: peer_id.clone(),
            })
            .await;
    }

    /// Сообщает о спам-страйке (превышение rate limit).
    pub async fn spam_strike(&self, peer_id: &NodeId) {
        self.events
            .process(ReputationEvent::SpamStrike {
                peer_id: peer_id.clone(),
            })
            .await;
    }

    /// Сообщает о bootstrap-помощи новому узлу.
    pub async fn bootstrap_assist(&self, peer_id: &NodeId) {
        self.events
            .process(ReputationEvent::BootstrapAssist {
                peer_id: peer_id.clone(),
            })
            .await;
    }

    /// Событие подключения пира (начало аптайм-трекинга).
    pub async fn peer_connected(&self, peer_id: &NodeId) {
        self.events
            .process(ReputationEvent::PeerConnected {
                peer_id: peer_id.clone(),
            })
            .await;
    }

    /// Событие отключения пира (финализация аптайм-бонуса).
    pub async fn peer_disconnected(&self, peer_id: &NodeId) {
        self.events
            .process(ReputationEvent::PeerDisconnected {
                peer_id: peer_id.clone(),
            })
            .await;
    }

    /// Текущий уровень репутации узла.
    pub async fn level(&self, peer_id: &NodeId) -> ReputationLevel {
        self.score.level(peer_id).await
    }

    /// Подходит ли узел для использования как источник чанков?
    /// (не отрицательная репутация)
    pub async fn is_eligible_source(&self, peer_id: &NodeId) -> bool {
        self.score.level(peer_id).await != ReputationLevel::Negative
    }

    /// Создаёт подписанную жалобу на узел (для отправки через Router).
    pub fn create_report(
        target_id: &NodeId,
        reason: ReportReason,
        keypair: &SigningKeypair,
    ) -> Result<void_crypto::sign::SignedMessage, ReputationError> {
        ReportManager::create_report(target_id, reason, keypair)
    }
}

// ─── Инициализация ────────────────────────────────────────────────────────────

/// Создаёт и запускает систему репутации.
///
/// Запускает фоновые задачи:
/// - аптайм-тикер (каждую минуту)
/// - sync при подключении новых пиров
/// - обработка входящих ReputationSync / ReputationReport
pub async fn start(
    pool: DbPool,
    router: Arc<Router>,
    rate_limiter: Arc<RateLimiter>,
    my_keypair: Arc<SigningKeypair>,
    my_id: NodeId,
) -> Arc<ReputationSystem> {
    let score_manager = ScoreManager::new(pool.clone());
    let event_processor = EventProcessor::new(score_manager.clone(), rate_limiter);
    let report_manager = ReportManager::new(pool.clone(), score_manager.clone());

    let sync_manager = Arc::new(SyncManager::new(
        pool.clone(),
        score_manager.clone(),
        event_processor.clone(),
        my_keypair,
        my_id,
    ));

    sync_manager.start(router).await;

    Arc::new(ReputationSystem {
        score: score_manager,
        events: event_processor,
        reports: report_manager,
    })
}