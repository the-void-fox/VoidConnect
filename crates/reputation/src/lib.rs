/// void-reputation — система репутации для Void Connect.
///
/// ## Архитектура
///
/// ```text
/// SyncManager ──► EventProcessor ──► ScoreManager ──► void-db
///                      │
///                      ▼
///                 RateLimiter (block negative peers)
/// ```
///
/// Компоненты используются по отдельности (см. как их связывает backend в
/// `void-ui`): синхронизация репутации идёт gossip'ом через relay чата
/// ([`sync::SyncManager::build_signed_sync`] / `apply_signed_sync`), а не через
/// отдельный сетевой Router.

pub mod error;
pub mod events;
pub mod reports;
pub mod score;
pub mod sync;

pub use error::ReputationError;
pub use events::{EventProcessor, ReputationEvent};
pub use reports::{ReportManager, ReportReason};
pub use score::{ReputationLevel, ScoreManager};
pub use sync::SyncManager;

/// Re-export, чтобы потребители (например, UI) могли создать `RateLimiter`
/// для `EventProcessor` без прямой зависимости на `void-network`.
pub use void_network::rate_limit::RateLimiter;