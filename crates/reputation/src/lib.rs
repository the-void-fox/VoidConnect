/// void-reputation — локальная репутация узлов для Void Connect.
///
/// Репутация — оценка **качества раздачи** глазами этого узла (валидные и
/// битые чанки, отдача) и спам-страйков флуда; плюс приём и хранение жалоб.
/// Доверие к людям, вес голосов и жалоб считает сеть доверия (`void-trust`):
/// бонус за аптайм и обмен снимками репутации убраны — их накручивали
/// подставные узлы, просто сидя в сети.
///
/// ```text
/// EventProcessor ──► ScoreManager ──► void-db
///       │
///       ▼
///  RateLimiter (block negative peers)
/// ```

pub mod error;
pub mod events;
pub mod reports;
pub mod score;

pub use error::ReputationError;
pub use events::{EventProcessor, ReputationEvent};
pub use reports::{ReportManager, ReportReason};
pub use score::{ReputationLevel, ScoreManager};

/// Re-export, чтобы потребители (например, UI) могли создать `RateLimiter`
/// для `EventProcessor` без прямой зависимости на `void-network`.
pub use void_network::rate_limit::RateLimiter;
