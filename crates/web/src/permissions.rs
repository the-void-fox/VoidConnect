//! Разрешения сайтов (JS API): что пользователь позволил каждому сайту.
//!
//! Разрешение выдаётся только в окне Void Connect (см. [`crate::consent`]) —
//! страница сайта не может ни выдать его себе, ни подделать диалог. Хранится
//! по имени сайта: имя закреплено за владельцем (первая подпись), чужой сайт
//! под тем же именем не получит чужие разрешения.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Что сайт может делать от имени пользователя.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Знать, кто пользователь: ID, имя, аватар.
    Identity,
    /// Публиковать записи сайта (комментарии, видео, лайки), подписанные
    /// ключом пользователя. Их видят все узлы, где открыт этот сайт.
    Publish,
}

impl Permission {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "identity" => Some(Permission::Identity),
            "publish" => Some(Permission::Publish),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Identity => "identity",
            Permission::Publish => "publish",
        }
    }

    /// Описание для диалога согласия.
    pub fn describe(self) -> &'static str {
        match self {
            Permission::Identity => "узнать ваш ID, имя и аватар",
            Permission::Publish => "публиковать от вашего имени записи этого сайта (комментарии, публикации, отметки)",
        }
    }
}

type Map = BTreeMap<String, BTreeSet<Permission>>;

/// Разрешения всех сайтов. Клонируется дёшево; `path = None` — только в памяти.
#[derive(Clone, Default)]
pub struct PermissionStore {
    path: Option<PathBuf>,
    map: Arc<Mutex<Map>>,
}

impl PermissionStore {
    /// Загружает разрешения из файла (нет файла или он битый — пусто).
    pub fn load(path: PathBuf) -> Self {
        let map: Map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path: Some(path), map: Arc::new(Mutex::new(map)) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Map> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn has(&self, site: &str, p: Permission) -> bool {
        self.lock().get(site).is_some_and(|s| s.contains(&p))
    }

    /// Разрешения сайта.
    pub fn of(&self, site: &str) -> Vec<Permission> {
        self.lock().get(site).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }

    /// Все сайты с разрешениями (для настроек).
    pub fn all(&self) -> Vec<(String, Vec<Permission>)> {
        self.lock()
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(k, s)| (k.clone(), s.iter().copied().collect()))
            .collect()
    }

    pub fn grant(&self, site: &str, perms: &[Permission]) {
        let snapshot = {
            let mut map = self.lock();
            map.entry(site.to_string()).or_default().extend(perms.iter().copied());
            map.clone()
        };
        self.save(&snapshot);
    }

    pub fn revoke(&self, site: &str, p: Permission) {
        let snapshot = {
            let mut map = self.lock();
            if let Some(set) = map.get_mut(site) {
                set.remove(&p);
                if set.is_empty() {
                    map.remove(site);
                }
            }
            map.clone()
        };
        self.save(&snapshot);
    }

    pub fn revoke_all(&self, site: &str) {
        let snapshot = {
            let mut map = self.lock();
            map.remove(site);
            map.clone()
        };
        self.save(&snapshot);
    }

    /// Атомарная запись: временный файл + rename.
    fn save(&self, map: &Map) {
        let Some(path) = &self.path else { return };
        let Ok(json) = serde_json::to_vec_pretty(map) else { return };
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_revoke_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site_permissions.json");
        let store = PermissionStore::load(path.clone());
        assert!(!store.has("tube", Permission::Identity));
        store.grant("tube", &[Permission::Identity, Permission::Publish]);
        assert!(store.has("tube", Permission::Publish));
        assert!(!store.has("blog", Permission::Identity), "разрешения не переходят на другой сайт");

        let reloaded = PermissionStore::load(path.clone());
        assert_eq!(reloaded.of("tube"), vec![Permission::Identity, Permission::Publish]);
        reloaded.revoke("tube", Permission::Publish);
        assert_eq!(PermissionStore::load(path.clone()).of("tube"), vec![Permission::Identity]);
        reloaded.revoke_all("tube");
        assert!(PermissionStore::load(path).all().is_empty());
    }

    #[test]
    fn parse_roundtrip() {
        for p in [Permission::Identity, Permission::Publish] {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
        assert_eq!(Permission::parse("keys"), None);
    }
}
