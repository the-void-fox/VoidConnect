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

    /// Реестр, сразу заполненный сайтами (восстановление с диска при запуске:
    /// без блокировок и до того, как фоновые задачи начнут его читать).
    pub fn with_sites(sites: impl IntoIterator<Item = SiteManifest>) -> Self {
        let map = sites.into_iter().map(|m| (m.name.clone(), m)).collect();
        Self { sites: Arc::new(RwLock::new(map)) }
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

#[cfg(test)]
mod tests {
    use super::*;
    use void_core::identity::NodeId;

    fn manifest(name: &str) -> SiteManifest {
        SiteManifest {
            site_id: format!("id-{name}"),
            name: name.into(),
            owner: NodeId("a".repeat(64)),
            entries: Vec::new(),
            created_at: 1,
            signature: None,
        }
    }

    #[tokio::test]
    async fn with_sites_prefills_registry() {
        let reg = SiteRegistry::with_sites([manifest("blog"), manifest("docs")]);
        assert_eq!(reg.list().await.len(), 2);
        assert!(reg.get("blog.void").await.is_some(), "имя с зоной тоже находится");
        reg.remove("docs").await;
        assert!(reg.get("docs").await.is_none());
    }
}
