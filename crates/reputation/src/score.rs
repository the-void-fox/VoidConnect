/// score.rs — подсчёт и хранение репутации узлов.
///
/// Репутация хранится в SQLite через void-db.
/// Этот модуль предоставляет высокоуровневый API поверх сырых DB-операций.

use std::time::Duration;

use tracing::{debug, warn};
use void_core::identity::NodeId;
use void_db::{peers as db_peers, DbPool};

pub use void_db::peers::{Reputation, ReputationDelta};

// ─── Пороги репутации ─────────────────────────────────────────────────────────

/// Репутация выше этого значения — «высокая» (приоритет при выборе источника).
pub const SCORE_HIGH: f64 = 50.0;

/// Репутация ниже этого значения — «низкая» (ужесточённый rate limit).
pub const SCORE_LOW: f64 = 0.0;

/// Репутация ниже этого значения — «отрицательная» (временная блокировка).
pub const SCORE_NEGATIVE: f64 = -20.0;

// ─── Весовые коэффициенты ─────────────────────────────────────────────────────

/// Штраф за каждый плохой чанк.
pub const PENALTY_BAD_CHUNK: f64 = -2.0;

/// Штраф за спам-страйк (превышение rate limit).
pub const PENALTY_SPAM_STRIKE: f64 = -3.0;

/// Бонус за каждый мегабайт загруженных данных.
pub const BONUS_UPLOAD_PER_MB: f64 = 0.05;

/// Бонус за час аптайма.
pub const BONUS_UPTIME_PER_HOUR: f64 = 0.5;

/// Бонус за каждый успешный чанк.
pub const BONUS_VALID_CHUNK: f64 = 0.1;

// ─── Уровни репутации ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationLevel {
    /// score > SCORE_HIGH
    High,
    /// SCORE_LOW <= score <= SCORE_HIGH
    Normal,
    /// SCORE_NEGATIVE <= score < SCORE_LOW
    Low,
    /// score < SCORE_NEGATIVE
    Negative,
}

impl ReputationLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= SCORE_HIGH {
            ReputationLevel::High
        } else if score >= SCORE_LOW {
            ReputationLevel::Normal
        } else if score >= SCORE_NEGATIVE {
            ReputationLevel::Low
        } else {
            ReputationLevel::Negative
        }
    }
}

impl std::fmt::Display for ReputationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReputationLevel::High => write!(f, "High"),
            ReputationLevel::Normal => write!(f, "Normal"),
            ReputationLevel::Low => write!(f, "Low"),
            ReputationLevel::Negative => write!(f, "Negative"),
        }
    }
}

// ─── ScoreManager ─────────────────────────────────────────────────────────────

/// Высокоуровневый менеджер репутации.
/// Всё состояние хранится в БД — этот объект stateless.
#[derive(Clone)]
pub struct ScoreManager {
    pool: DbPool,
}

impl ScoreManager {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // ─── Чтение ──────────────────────────────────────────────────────────────

    /// Возвращает репутацию узла. Если нет записи — возвращает `None`.
    pub async fn get(&self, peer_id: &NodeId) -> Option<Reputation> {
        db_peers::get_reputation(&self.pool, peer_id.as_str())
            .await
            .unwrap_or_else(|e| {
                warn!("Failed to get reputation for {}: {}", peer_id, e);
                None
            })
    }

    /// Текущий уровень репутации.
    pub async fn level(&self, peer_id: &NodeId) -> ReputationLevel {
        let score = self.score(peer_id).await;
        ReputationLevel::from_score(score)
    }

    /// Текущий score (0.0 если узел неизвестен).
    pub async fn score(&self, peer_id: &NodeId) -> f64 {
        self.get(peer_id).await.map(|r| r.score).unwrap_or(0.0)
    }

    // ─── Инициализация ────────────────────────────────────────────────────────

    /// Создаёт запись репутации для нового узла (score = 0).
    /// Идемпотентно — безопасно вызывать повторно.
    pub async fn init(&self, peer_id: &NodeId) -> crate::error::ReputationError {
        self.ensure_peer(peer_id).await;
        db_peers::init_reputation(&self.pool, peer_id.as_str())
            .await
            .map_err(crate::error::ReputationError::from)
            .err()
            .unwrap_or(crate::error::ReputationError::Ok)
    }

    /// Гарантирует наличие строки в таблице `peers` — она нужна как FK-цель для
    /// записи в `reputation` (иначе INSERT падает по внешнему ключу). Создаёт
    /// минимальную запись (только публичный ключ), не затирая уже известные поля.
    async fn ensure_peer(&self, peer_id: &NodeId) {
        let peer = db_peers::Peer {
            public_key: peer_id.as_str().to_string(),
            username: None,
            avatar_url: None,
            status_text: None,
            ip_address: None,
            port: None,
            is_bootstrap: false,
            last_seen_at: None,
            first_seen_at: chrono::Utc::now(),
        };
        if let Err(e) = db_peers::upsert_peer(&self.pool, &peer).await {
            warn!("Failed to ensure peer row for {}: {}", peer_id, e);
        }
    }

    // ─── Применение событий ───────────────────────────────────────────────────

    /// Засчитывает успешно переданный чанк.
    pub async fn record_valid_chunk(&self, peer_id: &NodeId, size_bytes: i64) {
        self.apply(
            peer_id,
            ReputationDelta {
                upload_bytes: size_bytes,
                valid_chunks_sent: 1,
                ..Default::default()
            },
        )
        .await;
        debug!("Valid chunk from {}: +{}B", peer_id, size_bytes);
    }

    /// Засчитывает плохой чанк (не прошёл SHA-256 верификацию).
    pub async fn record_bad_chunk(&self, peer_id: &NodeId) {
        self.apply(
            peer_id,
            ReputationDelta {
                bad_chunks_sent: 1,
                ..Default::default()
            },
        )
        .await;
        warn!("Bad chunk from {}: reputation penalty", peer_id);
    }

    /// Засчитывает спам-страйк (превышение rate limit).
    pub async fn record_spam_strike(&self, peer_id: &NodeId) {
        self.apply(
            peer_id,
            ReputationDelta {
                spam_strikes: 1,
                ..Default::default()
            },
        )
        .await;
        warn!("Spam strike from {}: reputation penalty", peer_id);
    }

    /// Добавляет аптайм-бонус за указанный период.
    pub async fn record_uptime(&self, peer_id: &NodeId, duration: Duration) {
        let seconds = duration.as_secs() as i64;
        self.apply(
            peer_id,
            ReputationDelta {
                uptime_seconds: seconds,
                ..Default::default()
            },
        )
        .await;
    }

    /// Добавляет bootstrap-бонус (узел помог новому участнику войти в сеть).
    pub async fn record_bootstrap_assist(&self, peer_id: &NodeId, bonus: f64) {
        self.apply(
            peer_id,
            ReputationDelta {
                bootstrap_bonus: bonus,
                ..Default::default()
            },
        )
        .await;
        debug!("Bootstrap bonus +{} for {}", bonus, peer_id);
    }

    // ─── Внутреннее ──────────────────────────────────────────────────────────

    async fn apply(&self, peer_id: &NodeId, delta: ReputationDelta) {
        // Гарантируем что запись существует перед обновлением
        self.ensure_peer(peer_id).await;
        let _ = db_peers::init_reputation(&self.pool, peer_id.as_str()).await;

        if let Err(e) =
            db_peers::apply_reputation_delta(&self.pool, peer_id.as_str(), delta).await
        {
            warn!("Failed to apply reputation delta for {}: {}", peer_id, e);
        }
    }
}