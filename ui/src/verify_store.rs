//! verify_store.rs — локальный список проверенных контактов.
//!
//! Хранит NodeId (hex) узлов, чей код безопасности (safety number) пользователь
//! сверил вне сети. Чисто локальная пометка доверия: в сеть не уходит, на других
//! узлах не видна. JSON рядом с профилем.

use std::collections::HashSet;
use std::path::PathBuf;

fn verified_path() -> PathBuf {
    crate::profile_store::profile_dir().join("verified_contacts.json")
}

pub fn load_verified() -> HashSet<String> {
    std::fs::read_to_string(verified_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_verified(set: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string_pretty(set) {
        let _ = std::fs::write(verified_path(), json);
    }
}
