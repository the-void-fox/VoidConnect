use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::warn;

use void_core::identity::NodeId;

// ─── Константы ───────────────────────────────────────────────────────────────

/// Максимальное количество сообщений в секунду от одного узла
const DEFAULT_RATE: u32 = 20;

/// Ёмкость «ведра» (burst capacity) — можно отправить пачку
const DEFAULT_BURST: u32 = 50;

/// Через сколько секунд без нарушений сбросить счётчик страйков
const STRIKE_RESET_SECS: u64 = 300; // 5 минут

/// После скольких страйков временно блокировать узел
const MAX_STRIKES_BEFORE_BLOCK: u32 = 3;

/// Длительность временной блокировки
const TEMP_BLOCK_DURATION: Duration = Duration::from_secs(60);

// ─── Token Bucket ─────────────────────────────────────────────────────────────

/// Классический token bucket для rate limiting.
///
/// Токены пополняются со скоростью `rate` токенов в секунду.
/// Каждое сообщение расходует 1 токен.
/// Если токены кончились — сообщение отклоняется.
struct TokenBucket {
    /// Текущий запас токенов (дробное для точного пополнения)
    tokens: f64,
    /// Максимальный запас (burst)
    capacity: f64,
    /// Скорость пополнения (токенов/сек)
    rate: f64,
    /// Когда последний раз пополняли
    last_refill: Instant,
    /// Счётчик нарушений (превышений лимита)
    strikes: u32,
    /// Когда зафиксировали первый страйк в текущей серии
    first_strike_at: Option<Instant>,
    /// До какого момента узел заблокирован (None = не заблокирован)
    blocked_until: Option<Instant>,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            capacity: burst as f64,
            rate: rate as f64,
            last_refill: Instant::now(),
            strikes: 0,
            first_strike_at: None,
            blocked_until: None,
        }
    }

    /// Пытается «потратить» один токен.
    /// Возвращает `true` если сообщение пропустить, `false` если отклонить.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();

        // Проверяем временную блокировку
        if let Some(blocked_until) = self.blocked_until {
            if now < blocked_until {
                return false;
            } else {
                // Блокировка истекла — сброс
                self.blocked_until = None;
                self.strikes = 0;
                self.first_strike_at = None;
            }
        }

        // Пополняем токены
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;

        // Сбрасываем страйки если прошло достаточно времени
        if let Some(first) = self.first_strike_at {
            if now.duration_since(first).as_secs() > STRIKE_RESET_SECS {
                self.strikes = 0;
                self.first_strike_at = None;
            }
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            // Нарушение
            self.strikes += 1;
            if self.first_strike_at.is_none() {
                self.first_strike_at = Some(now);
            }

            // Если превышено число страйков — временная блокировка
            if self.strikes >= MAX_STRIKES_BEFORE_BLOCK {
                warn!(
                    "Rate limit: blocking peer after {} strikes for {:?}",
                    self.strikes, TEMP_BLOCK_DURATION
                );
                self.blocked_until = Some(now + TEMP_BLOCK_DURATION);
            }

            false
        }
    }

    fn strikes(&self) -> u32 {
        self.strikes
    }

    fn is_blocked(&self) -> bool {
        self.blocked_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn block_remaining_secs(&self) -> Option<u64> {
        self.blocked_until.and_then(|t| {
            let now = Instant::now();
            if now < t {
                Some((t - now).as_secs())
            } else {
                None
            }
        })
    }
}

// ─── RateLimiter ──────────────────────────────────────────────────────────────

/// Хранилище token bucket для всех известных узлов.
/// Thread-safe, клонируемый (Arc внутри).
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<NodeId, TokenBucket>>>,
    rate: u32,
    burst: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_RATE, DEFAULT_BURST)
    }

    pub fn with_limits(rate: u32, burst: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            rate,
            burst,
        }
    }

    /// Проверяет, можно ли пропустить сообщение от данного узла.
    /// `true` = пропустить, `false` = отклонить.
    pub async fn check(&self, peer_id: &NodeId) -> bool {
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets
            .entry(peer_id.clone())
            .or_insert_with(|| TokenBucket::new(self.rate, self.burst));
        bucket.try_consume()
    }

    /// Принудительно блокирует узел на заданное время.
    /// Используется системой репутации при жалобах.
    pub async fn block_peer(&self, peer_id: &NodeId, duration: Duration) {
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets
            .entry(peer_id.clone())
            .or_insert_with(|| TokenBucket::new(self.rate, self.burst));
        bucket.blocked_until = Some(Instant::now() + duration);
        warn!("Peer {} manually blocked for {:?}", peer_id, duration);
    }

    /// Снимает блокировку с узла.
    pub async fn unblock_peer(&self, peer_id: &NodeId) {
        let mut buckets = self.buckets.lock().await;
        if let Some(bucket) = buckets.get_mut(peer_id) {
            bucket.blocked_until = None;
            bucket.strikes = 0;
        }
    }

    /// Проверяет, заблокирован ли узел прямо сейчас.
    pub async fn is_blocked(&self, peer_id: &NodeId) -> bool {
        let buckets = self.buckets.lock().await;
        buckets
            .get(peer_id)
            .map(|b| b.is_blocked())
            .unwrap_or(false)
    }

    /// Возвращает количество страйков узла.
    pub async fn strikes(&self, peer_id: &NodeId) -> u32 {
        let buckets = self.buckets.lock().await;
        buckets.get(peer_id).map(|b| b.strikes()).unwrap_or(0)
    }

    /// Оставшееся время блокировки в секундах, если заблокирован.
    pub async fn block_remaining_secs(&self, peer_id: &NodeId) -> Option<u64> {
        let buckets = self.buckets.lock().await;
        buckets.get(peer_id)?.block_remaining_secs()
    }

    /// Удаляет запись об узле (при дисконнекте, чтобы не копить в памяти).
    pub async fn remove_peer(&self, peer_id: &NodeId) {
        self.buckets.lock().await.remove(peer_id);
    }

    /// Очищает старые записи об отключённых узлах.
    /// Рекомендуется вызывать периодически (например, раз в час).
    pub async fn cleanup(&self, connected_peers: &[NodeId]) {
        let mut buckets = self.buckets.lock().await;
        let connected_set: std::collections::HashSet<_> = connected_peers.iter().collect();
        buckets.retain(|id, _| connected_set.contains(id));
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Тесты ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_rate_limiting() {
        let limiter = RateLimiter::with_limits(10, 10);
        let peer = NodeId("test_peer".into());

        // Первые 10 должны пройти (burst)
        for _ in 0..10 {
            assert!(limiter.check(&peer).await);
        }

        // Следующие — отклоняться (bucket пуст)
        assert!(!limiter.check(&peer).await);
    }

    #[tokio::test]
    async fn test_manual_block() {
        let limiter = RateLimiter::new();
        let peer = NodeId("spammer".into());

        limiter
            .block_peer(&peer, Duration::from_secs(60))
            .await;

        assert!(limiter.is_blocked(&peer).await);
        assert!(!limiter.check(&peer).await);

        limiter.unblock_peer(&peer).await;
        assert!(!limiter.is_blocked(&peer).await);
    }
}