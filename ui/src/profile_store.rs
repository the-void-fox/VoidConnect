use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use void_core::identity::NodeId;

/// Переопределение корневой папки данных (identity, профиль, БД, DM-история).
/// Если не задано — используется `~/.config/void-connect`.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Задаёт корневую папку данных. Нужно вызвать один раз в начале `main()`,
/// до любых обращений к [`profile_dir`]. Позволяет запускать несколько
/// инстансов на одной машине с раздельными ключами/БД/историей.
pub fn set_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir);
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SavedProfile {
    pub node_id:     String,
    pub name:        String,
    pub description: String,
    pub status:      String,
}

impl Default for SavedProfile {
    fn default() -> Self {
        Self {
            node_id:     String::new(),
            name:        String::new(),
            description: String::new(),
            status:      "online".into(),
        }
    }
}

/// Папка по умолчанию: `~/.config/void-connect` (или `%APPDATA%\void-connect`).
fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    #[cfg(not(target_os = "windows"))]
    let base = {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{}/.config", home)
    };
    std::path::Path::new(&base).join("void-connect")
}

pub fn profile_dir() -> PathBuf {
    let dir = DATA_DIR.get().cloned().unwrap_or_else(default_data_dir);
    std::fs::create_dir_all(&dir).ok();
    dir
}

pub fn profile_path() -> std::path::PathBuf {
    profile_dir().join("profile.json")
}

/// Load saved profile from disk, or create a fresh default.
/// Note: `node_id` is populated by main.rs via `void_crypto::Identity`.
pub fn load_or_create() -> SavedProfile {
    let path = profile_path();
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(p) = serde_json::from_str::<SavedProfile>(&data) {
            return p;
        }
    }
    let fresh = SavedProfile::default();
    save_profile(&fresh).ok();
    fresh
}

pub fn save_profile(p: &SavedProfile) -> std::io::Result<()> {
    let path = profile_path();
    let data = serde_json::to_string_pretty(p)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, data)
}

pub fn node_id_from_saved(p: &SavedProfile) -> NodeId {
    NodeId(p.node_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_override_is_respected_and_set_once() {
        let want = std::env::temp_dir().join("void-connect-test-data-dir");
        set_data_dir(want.clone());
        assert_eq!(profile_dir(), want);
        // void.db и dm/ должны лежать внутри переопределённой папки
        assert!(profile_path().starts_with(&want));

        // OnceLock: повторный вызов игнорируется (первый выигрывает)
        set_data_dir(std::env::temp_dir().join("void-connect-other"));
        assert_eq!(profile_dir(), want);
    }
}
