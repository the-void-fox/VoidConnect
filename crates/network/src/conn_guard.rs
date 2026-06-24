//! Ограничитель числа одновременных входящих TCP-соединений.
//!
//! Защита от **connection-flood**: без него каждый `accept()` порождает задачу
//! (а с ней — файловый дескриптор и буферы) без какого-либо предела. Один
//! злоумышленник может открыть десятки тысяч соединений и исчерпать ресурсы
//! узла, даже не отправив ни байта полезных данных.
//!
//! [`ConnLimiter`] вводит два независимых предела:
//!   - **глобальный** (`max_total`) — сколько соединений сервер обслуживает
//!     одновременно суммарно;
//!   - **на один IP** (`max_per_ip`) — чтобы один адрес не занял все слоты и не
//!     вытеснил легитимных участников (актуально для долгоживущих соединений
//!     чата, где честных пиров много, но каждый — с отдельного адреса).
//!
//! Слот занимается через [`ConnLimiter::try_accept`] и освобождается
//! автоматически, когда возвращённый [`ConnGuard`] выходит из области видимости
//! (например, когда завершается задача обработки соединения). При достижении
//! предела соединение **сразу отклоняется** (а не ставится в очередь), чтобы
//! атакующий трафик не накапливался.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Потокобезопасный ограничитель одновременных соединений (клонируемый — Arc
/// внутри). Используется из accept-цикла каждого TCP-сервера.
#[derive(Clone)]
pub struct ConnLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    max_total: usize,
    max_per_ip: usize,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

impl ConnLimiter {
    /// Создаёт лимитер с глобальным пределом `max_total` и пределом на один IP
    /// `max_per_ip`. Оба должны быть > 0.
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                max_total: max_total.max(1),
                max_per_ip: max_per_ip.max(1),
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Пытается занять слот под соединение с адреса `ip`.
    ///
    /// Возвращает [`ConnGuard`], удерживающий слот, либо `None`, если достигнут
    /// глобальный лимит или лимит на этот IP — тогда соединение нужно сразу
    /// закрыть. Lock-poison трактуется как «нет слота» (безопасный отказ).
    pub fn try_accept(&self, ip: IpAddr) -> Option<ConnGuard> {
        let mut s = self.inner.state.lock().ok()?;
        if s.total >= self.inner.max_total {
            return None;
        }
        let per_ip = s.per_ip.get(&ip).copied().unwrap_or(0);
        if per_ip >= self.inner.max_per_ip {
            return None;
        }
        s.total += 1;
        s.per_ip.insert(ip, per_ip + 1);
        Some(ConnGuard { inner: Arc::clone(&self.inner), ip })
    }

    /// Текущее число занятых слотов (для метрик/тестов).
    pub fn active(&self) -> usize {
        self.inner.state.lock().map(|s| s.total).unwrap_or(0)
    }
}

/// RAII-токен занятого слота. При сбросе освобождает слот (глобальный и для IP).
pub struct ConnGuard {
    inner: Arc<Inner>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.inner.state.lock() {
            s.total = s.total.saturating_sub(1);
            if let Some(c) = s.per_ip.get_mut(&self.ip) {
                *c -= 1;
                if *c == 0 {
                    s.per_ip.remove(&self.ip);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn per_ip_cap_blocks_single_address() {
        let lim = ConnLimiter::new(100, 2);
        let a = ip(1);
        let _g1 = lim.try_accept(a).expect("1st ok");
        let _g2 = lim.try_accept(a).expect("2nd ok");
        // Третье соединение с того же IP — отказ.
        assert!(lim.try_accept(a).is_none());
        // Но другой IP свободен.
        assert!(lim.try_accept(ip(2)).is_some());
    }

    #[test]
    fn global_cap_blocks_across_ips() {
        let lim = ConnLimiter::new(2, 10);
        let _g1 = lim.try_accept(ip(1)).expect("ok");
        let _g2 = lim.try_accept(ip(2)).expect("ok");
        // Глобальный предел исчерпан, хотя по каждому IP ещё есть запас.
        assert!(lim.try_accept(ip(3)).is_none());
    }

    #[test]
    fn dropping_guard_frees_slot() {
        let lim = ConnLimiter::new(1, 1);
        let a = ip(1);
        {
            let _g = lim.try_accept(a).expect("ok");
            assert_eq!(lim.active(), 1);
            assert!(lim.try_accept(a).is_none());
        }
        // Гард сброшен — слот снова доступен, счётчик IP очищен.
        assert_eq!(lim.active(), 0);
        assert!(lim.try_accept(a).is_some());
    }

    #[test]
    fn zero_limits_clamped_to_one() {
        let lim = ConnLimiter::new(0, 0);
        assert!(lim.try_accept(ip(1)).is_some());
    }
}
