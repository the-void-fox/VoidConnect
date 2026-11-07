//! Лимиты частоты по уровню доверия автора (проект — `Obsidian/Сеть доверия.md`,
//! раздел «Общий чат»).
//!
//! Уровень автора определяет backend по своей сети доверия и передаёт чату
//! функцией [`TierFn`]. Каждый узел применяет свой взгляд: поток бота гаснет на
//! первом же узле, который его не знает, а сообщения новичка расходятся через
//! тех, кто ему доверяет. Сверх лимита — тихий отброс, без спам-штрафа.
//! Доверенных авторов ограничивает только общий лимит пакетов (`RateLimiter`,
//! 20/с) — как раньше.
//!
//! Кроме лимита на автора у незнакомцев и освоившихся есть общий бюджет на
//! всех: иначе тысяча ботов по сообщению в 30 с дала бы 33 сообщения в секунду.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use void_core::identity::NodeId;

/// Канал знакомства: незнакомцы пишут в нём без 30-секундного лимита.
pub const NEWCOMERS_CHANNEL: &str = "newcomers";

/// Уровень автора в глазах этого узла.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorTier {
    /// Ничего не известно (или заблокирован): самые строгие лимиты.
    Stranger,
    /// Освоившийся: лимиты мягче.
    Settled,
    /// Через знакомых или проверен лично: без дополнительных лимитов.
    Trusted,
}

/// Уровень автора по его NodeId (backend читает снимок сети доверия).
pub type TierFn = Arc<dyn Fn(&NodeId) -> AuthorTier + Send + Sync>;

/// Что рассылает автор: у каждого вида свой лимит.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    /// Сообщение в канал, кроме «Новичков».
    Message,
    /// Сообщение в канал «Новички».
    NewcomersMessage,
    Profile,
    /// Новый файл или новая версия сайта.
    Publish,
    Dns,
    Proposal,
    Vote,
    /// Жалоба на узел.
    Report,
}

impl Kind {
    pub(crate) fn message(channel: &str) -> Self {
        if channel == NEWCOMERS_CHANNEL { Kind::NewcomersMessage } else { Kind::Message }
    }
}

/// Частота: пополнение в секунду и запас.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Rate {
    per_sec: f64,
    burst: f64,
}

/// `count` за `secs` секунд, запас `burst`.
const fn per(count: f64, secs: f64, burst: f64) -> Rate {
    Rate { per_sec: count / secs, burst }
}

const MIN: f64 = 60.0;
const HOUR: f64 = 3600.0;

/// Лимит одного автора (не доверенного). `None` — запрещено.
fn author_rate(tier: AuthorTier, kind: Kind) -> Option<Rate> {
    use AuthorTier::*;
    use Kind::*;
    Some(match (tier, kind) {
        (Stranger, Message) => per(1.0, 30.0, 3.0),
        (_, Message) => per(1.0, 5.0, 10.0),
        (_, NewcomersMessage) => per(1.0, 2.0, 10.0),
        (_, Profile) => per(1.0, MIN, 2.0),
        (Stranger, Publish) => per(10.0, HOUR, 10.0),
        (_, Publish) => per(30.0, HOUR, 30.0),
        (Stranger, Dns) => per(3.0, HOUR, 3.0),
        (_, Dns) => per(10.0, HOUR, 10.0),
        // Предложения незнакомцев не пересылаются вовсе.
        (Stranger, Proposal) => return None,
        (_, Proposal | Vote | Report) => per(1.0, MIN, 2.0),
    })
}

/// Общий бюджет всех авторов уровня: ферма ботов упирается в него, а не в
/// число ключей. Ключ — имя бюджета.
fn shared_rate(tier: AuthorTier, kind: Kind) -> Option<(&'static str, Rate)> {
    use AuthorTier::*;
    use Kind::*;
    match (tier, kind) {
        (Stranger, NewcomersMessage) => Some(("strangers/newcomers", per(10.0, 1.0, 20.0))),
        (Stranger, Message) => Some(("strangers/chat", per(2.0, 1.0, 10.0))),
        (Settled, Message | NewcomersMessage) => Some(("settled/chat", per(10.0, 1.0, 30.0))),
        _ => None,
    }
}

/// Сколько авторов отслеживаем. При переполнении забываем полные бюджеты (они
/// равны отсутствующим); если не помогло — новых авторов не пропускаем.
const MAX_TRACKED: usize = 50_000;

/// Бюджет (token bucket).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
    rate: Rate,
}

impl Bucket {
    fn full(rate: Rate, now: Instant) -> Self {
        Self { tokens: rate.burst, last: now, rate }
    }

    /// Пополняет по текущей частоте (уровень автора мог смениться).
    fn refill(&mut self, rate: Rate, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * rate.per_sec).min(rate.burst);
        self.last = now;
        self.rate = rate;
    }

    fn is_full(&self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens + dt * self.rate.per_sec >= self.rate.burst
    }
}

#[derive(Default)]
struct State {
    authors: HashMap<(NodeId, Kind), Bucket>,
    shared: HashMap<&'static str, Bucket>,
}

/// Лимиты незнакомцев и освоившихся.
#[derive(Default)]
pub(crate) struct TierLimits {
    state: Mutex<State>,
}

impl TierLimits {
    /// `true` — пропустить (и списать из бюджетов автора и уровня).
    pub(crate) fn admit(&self, author: &NodeId, tier: AuthorTier, kind: Kind) -> bool {
        self.admit_at(author, tier, kind, Instant::now())
    }

    fn admit_at(&self, author: &NodeId, tier: AuthorTier, kind: Kind, now: Instant) -> bool {
        if tier == AuthorTier::Trusted {
            return true;
        }
        let Some(rate) = author_rate(tier, kind) else { return false };
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let key = (author.clone(), kind);
        if !st.authors.contains_key(&key) && st.authors.len() >= MAX_TRACKED {
            st.authors.retain(|_, b| !b.is_full(now));
            if st.authors.len() >= MAX_TRACKED {
                return false;
            }
        }
        let State { authors, shared } = &mut *st;

        let own = authors.entry(key).or_insert_with(|| Bucket::full(rate, now));
        own.refill(rate, now);
        if own.tokens < 1.0 {
            return false;
        }
        // Отказ по общему бюджету не списывает с автора, и наоборот.
        if let Some((name, srate)) = shared_rate(tier, kind) {
            let pool = shared.entry(name).or_insert_with(|| Bucket::full(srate, now));
            pool.refill(srate, now);
            if pool.tokens < 1.0 {
                return false;
            }
            pool.tokens -= 1.0;
        }
        own.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn id(n: u32) -> NodeId {
        NodeId(format!("{n:064x}"))
    }

    /// Сколько из `n` попыток подряд (в один момент) пропущено.
    fn burst(l: &TierLimits, who: &NodeId, tier: AuthorTier, kind: Kind, n: usize, at: Instant) -> usize {
        (0..n).filter(|_| l.admit_at(who, tier, kind, at)).count()
    }

    #[test]
    fn stranger_writes_once_per_30s_after_small_burst() {
        let l = TierLimits::default();
        let t0 = Instant::now();
        let a = id(1);
        assert_eq!(burst(&l, &a, AuthorTier::Stranger, Kind::Message, 10, t0), 3);
        assert!(!l.admit_at(&a, AuthorTier::Stranger, Kind::Message, t0 + Duration::from_secs(20)));
        assert!(l.admit_at(&a, AuthorTier::Stranger, Kind::Message, t0 + Duration::from_secs(31)));
        // Освоившийся — мягче.
        assert_eq!(burst(&l, &id(2), AuthorTier::Settled, Kind::Message, 20, t0), 10);
    }

    #[test]
    fn newcomers_channel_is_a_normal_conversation_for_strangers() {
        let l = TierLimits::default();
        let t0 = Instant::now();
        let a = id(1);
        assert_eq!(burst(&l, &a, AuthorTier::Stranger, Kind::NewcomersMessage, 20, t0), 10);
        assert!(l.admit_at(&a, AuthorTier::Stranger, Kind::NewcomersMessage, t0 + Duration::from_secs(2)));
        // Лимит «Новичков» отдельный: в общем канале у него свой запас.
        assert_eq!(burst(&l, &a, AuthorTier::Stranger, Kind::Message, 5, t0), 3);
    }

    #[test]
    fn bot_farm_hits_the_shared_budget() {
        let l = TierLimits::default();
        let t0 = Instant::now();
        // 1000 ботов по одному сообщению в «Новички» в один момент.
        let passed = (0..1000)
            .filter(|n| l.admit_at(&id(*n), AuthorTier::Stranger, Kind::NewcomersMessage, t0))
            .count();
        assert_eq!(passed, 20, "запас общего бюджета");
        // Через секунду — ещё ~10 сообщений на всех.
        let t1 = t0 + Duration::from_secs(1);
        let passed = (1000..2000)
            .filter(|n| l.admit_at(&id(*n), AuthorTier::Stranger, Kind::NewcomersMessage, t1))
            .count();
        assert_eq!(passed, 10);
        // В остальных каналах у незнакомцев свой общий бюджет, у доверенных — нет.
        let passed = (2000..3000)
            .filter(|n| l.admit_at(&id(*n), AuthorTier::Stranger, Kind::Message, t1))
            .count();
        assert_eq!(passed, 10);
        assert_eq!(burst(&l, &id(1), AuthorTier::Trusted, Kind::Message, 100, t1), 100);
    }

    #[test]
    fn refusal_by_one_budget_does_not_spend_the_other() {
        let l = TierLimits::default();
        let t0 = Instant::now();
        let spammer = id(1);
        // Автор исчерпал свой запас; дальнейшие попытки не трогают общий бюджет.
        assert_eq!(burst(&l, &spammer, AuthorTier::Stranger, Kind::Message, 1000, t0), 3);
        let others = (2..100)
            .filter(|n| l.admit_at(&id(*n), AuthorTier::Stranger, Kind::Message, t0))
            .count();
        assert_eq!(others, 7, "общий запас 10 минус 3 сообщения спамера");
    }

    #[test]
    fn proposals_and_slow_kinds() {
        let l = TierLimits::default();
        let t0 = Instant::now();
        assert!(!l.admit_at(&id(1), AuthorTier::Stranger, Kind::Proposal, t0));
        assert_eq!(burst(&l, &id(2), AuthorTier::Settled, Kind::Proposal, 5, t0), 2);
        assert_eq!(burst(&l, &id(1), AuthorTier::Stranger, Kind::Vote, 5, t0), 2);
        assert_eq!(burst(&l, &id(1), AuthorTier::Stranger, Kind::Publish, 50, t0), 10);
        assert_eq!(burst(&l, &id(1), AuthorTier::Stranger, Kind::Dns, 50, t0), 3);
        assert_eq!(burst(&l, &id(1), AuthorTier::Stranger, Kind::Profile, 5, t0), 2);
        // Публикации пополняются по часу: через 6 минут — ещё одна.
        assert!(l.admit_at(&id(1), AuthorTier::Stranger, Kind::Publish, t0 + Duration::from_secs(361)));
    }

    #[test]
    fn overflow_forgets_full_budgets() {
        let l = TierLimits::default();
        let t0 = Instant::now();
        for n in 0..MAX_TRACKED as u32 {
            assert!(l.admit_at(&id(n), AuthorTier::Stranger, Kind::Profile, t0));
        }
        // Все бюджеты частично потрачены — новый автор не помещается.
        assert!(!l.admit_at(&id(u32::MAX), AuthorTier::Stranger, Kind::Profile, t0));
        // Через минуту они полны — забываются, место есть.
        assert!(l.admit_at(&id(u32::MAX), AuthorTier::Stranger, Kind::Profile, t0 + Duration::from_secs(61)));
    }
}
