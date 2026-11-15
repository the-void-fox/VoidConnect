//! Кто может писать мне в личку (`dm_access.json` в папке данных): разрешённые
//! мной, заблокированные мной и ожидающие запросы. Решения локальные — в сеть
//! не уходят (проект — `Obsidian/Сеть доверия.md`, «Личные сообщения»).
//!
//! От «через знакомых», «проверен лично» и разрешённых — во «Входящие». От
//! остальных — в «Запросы»: первое сообщение обязано нести марку работы, в
//! очереди запроса не больше [`MAX_REQUEST_MSGS`] сообщений, лишнее отбрасывается.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use void_trust::TrustLevel;

/// Сколько сообщений принимаем от отправителя, пока запрос не принят.
pub const MAX_REQUEST_MSGS: u32 = 5;
/// Сколько запросов храним одновременно (ключей можно наделать сколько угодно,
/// а марку — нет, но папку «Запросы» всё равно не даём раздуть).
pub const MAX_REQUESTS: usize = 500;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct DmAccess {
    /// Пишут сразу во «Входящие»: принят их запрос или я написал им сам.
    pub allowed: BTreeSet<String>,
    /// Заблокированы мной: личка и сообщения в чате не показываются.
    pub blocked: BTreeSet<String>,
    /// Ожидающие запросы: отправитель → сколько сообщений принято в очередь.
    pub requests: BTreeMap<String, u32>,
}

/// Куда входящее личное сообщение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Inbox,
    Request,
    Drop,
}

impl DmAccess {
    /// Решает судьбу входящего сообщения и учитывает его в очереди запроса.
    /// `stamped` — к сообщению приложена действующая марка работы.
    pub fn route(&mut self, from: &str, level: TrustLevel, stamped: bool) -> Route {
        if self.blocked.contains(from) || level == TrustLevel::Blocked {
            return Route::Drop;
        }
        if matches!(level, TrustLevel::Trusted | TrustLevel::Verified) || self.allowed.contains(from) {
            self.requests.remove(from);
            return Route::Inbox;
        }
        let folder_full = self.requests.len() >= MAX_REQUESTS;
        match self.requests.get_mut(from) {
            Some(n) if *n >= MAX_REQUEST_MSGS => Route::Drop,
            Some(n) => {
                *n += 1;
                Route::Request
            }
            None if stamped && !folder_full => {
                self.requests.insert(from.to_string(), 1);
                Route::Request
            }
            None => Route::Drop,
        }
    }

    /// Разрешить писать во «Входящие» (принят запрос или пишу сам).
    pub fn allow(&mut self, id: &str) {
        self.requests.remove(id);
        self.allowed.insert(id.to_string());
    }

    /// Заблокировать (в том числе «Отклонить» запрос).
    pub fn block(&mut self, id: &str) {
        self.requests.remove(id);
        self.allowed.remove(id);
        self.blocked.insert(id.to_string());
    }

    pub fn unblock(&mut self, id: &str) {
        self.blocked.remove(id);
    }

    /// Беседа с узлом — запрос, ожидающий решения.
    pub fn is_request(&self, id: &str) -> bool {
        self.requests.contains_key(id) && !self.allowed.contains(id)
    }
}

fn path() -> std::path::PathBuf {
    crate::profile_store::profile_dir().join("dm_access.json")
}

pub fn load() -> DmAccess {
    match std::fs::read_to_string(path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => {
            // Первый запуск с запросами: с кем уже переписывались — разрешены.
            // Иначе их ответы без марки (собеседник нам уже писал — марку не
            // прикладывает) молча пропали бы.
            let access = DmAccess {
                allowed: crate::private_store::list_convs()
                    .into_iter()
                    .map(|c| c.peer_id)
                    .filter(|id| void_core::sanitize::is_hex64(id))
                    .collect(),
                ..DmAccess::default()
            };
            save(&access);
            access
        }
    }
}

pub fn save(access: &DmAccess) {
    if let Ok(json) = serde_json::to_string_pretty(access) {
        if let Err(e) = std::fs::write(path(), json) {
            tracing::warn!("dm_access.json не сохранён: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aa";

    #[test]
    fn stranger_needs_stamp_and_gets_five_messages() {
        let mut acc = DmAccess::default();
        assert_eq!(acc.route(A, TrustLevel::Stranger, false), Route::Drop, "без марки");
        assert_eq!(acc.route(A, TrustLevel::Stranger, true), Route::Request);
        for _ in 1..MAX_REQUEST_MSGS {
            // Следующие сообщения запроса — уже без марки.
            assert_eq!(acc.route(A, TrustLevel::Stranger, false), Route::Request);
        }
        assert_eq!(acc.route(A, TrustLevel::Stranger, true), Route::Drop, "очередь полна");
        assert_eq!(acc.requests[A], MAX_REQUEST_MSGS);
        assert!(acc.is_request(A));
    }

    #[test]
    fn trusted_and_allowed_go_to_inbox() {
        let mut acc = DmAccess::default();
        assert_eq!(acc.route(A, TrustLevel::Trusted, false), Route::Inbox);
        assert_eq!(acc.route("bb", TrustLevel::Verified, false), Route::Inbox);
        // Освоившийся — тоже через запрос.
        assert_eq!(acc.route("cc", TrustLevel::Settled, false), Route::Drop);

        acc.route("dd", TrustLevel::Stranger, true);
        acc.allow("dd");
        assert!(!acc.is_request("dd"));
        assert_eq!(acc.route("dd", TrustLevel::Stranger, false), Route::Inbox);
    }

    #[test]
    fn block_drops_everything_until_unblocked() {
        let mut acc = DmAccess::default();
        acc.route(A, TrustLevel::Stranger, true);
        acc.block(A);
        assert!(!acc.is_request(A));
        assert_eq!(acc.route(A, TrustLevel::Verified, true), Route::Drop);
        assert_eq!(acc.route("bb", TrustLevel::Blocked, true), Route::Drop, "бан голосованием");
        acc.unblock(A);
        assert_eq!(acc.route(A, TrustLevel::Verified, false), Route::Inbox);
    }

    #[test]
    fn requests_folder_is_capped() {
        let mut acc = DmAccess::default();
        for i in 0..MAX_REQUESTS {
            assert_eq!(acc.route(&format!("{i}"), TrustLevel::Stranger, true), Route::Request);
        }
        assert_eq!(acc.route("new", TrustLevel::Stranger, true), Route::Drop);
    }
}
