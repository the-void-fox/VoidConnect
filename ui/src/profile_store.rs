use serde::{Deserialize, Serialize};
use void_core::identity::NodeId;

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

pub fn profile_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    #[cfg(not(target_os = "windows"))]
    let base = {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{}/.config", home)
    };
    let dir = std::path::Path::new(&base).join("void-connect");
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
