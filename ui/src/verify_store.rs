//! verify_store.rs — неопубликованные отметки «проверен».
//!
//! До сети доверия отметка «проверен» была чисто локальной и хранилась здесь.
//! Теперь «проверен» — это публичное поручительство (`void-trust`, в БД), а в
//! этом файле остаются только старые отметки, которые пользователь решил не
//! публиковать: для его узла они по-прежнему значат «проверен лично».
//! JSON рядом с профилем.

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

fn asked_path() -> PathBuf {
    crate::profile_store::profile_dir().join("trust_migration_asked")
}

/// Спрашивали ли уже, публиковать ли старые отметки (вопрос задаётся один раз).
pub fn migration_asked() -> bool {
    asked_path().exists()
}

pub fn mark_migration_asked() {
    let _ = std::fs::write(asked_path(), b"1");
}
