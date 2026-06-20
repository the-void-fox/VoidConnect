//! Реестр известных сайтов: имя (без зоны `.void`) → манифест.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use void_core::site::SiteManifest;

/// Потокобезопасный реестр сайтов. Клонируется дёшево (Arc внутри).
#[derive(Clone, Default)]
pub struct SiteRegistry {
    sites: Arc<RwLock<HashMap<String, SiteManifest>>>,
}

impl SiteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Регистрирует (или заменяет) сайт по его имени.
    pub async fn register(&self, manifest: SiteManifest) {
        self.sites.write().await.insert(manifest.name.clone(), manifest);
    }

    /// Манифест сайта по имени (с зоной `.void` или без неё).
    pub async fn get(&self, name: &str) -> Option<SiteManifest> {
        let key = name.trim_end_matches(".void");
        self.sites.read().await.get(key).cloned()
    }

    /// Все известные сайты.
    pub async fn list(&self) -> Vec<SiteManifest> {
        self.sites.read().await.values().cloned().collect()
    }

    pub async fn remove(&self, name: &str) {
        let key = name.trim_end_matches(".void");
        self.sites.write().await.remove(key);
    }
}
