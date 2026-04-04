use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use void_core::peer::PeerInfo;
use void_core::identity::NodeId;

/// Живой список известных узлов сети.
///
/// Оборачивается в Arc<PeerList> и передаётся во все подсистемы,
/// которым нужен доступ к списку — чат, хранилище, DNS и т.д.
///
/// Внутри — RwLock: много читателей одновременно, один писатель.
#[derive(Debug, Clone)]
pub struct PeerList {
    peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>>,
}

impl PeerList {
    pub fn new() -> Self {
        PeerList {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Добавить или обновить запись об узле
    pub async fn upsert(&self, peer: PeerInfo) {
        let mut map = self.peers.write().await;
        map.insert(peer.id.clone(), peer);
    }

    /// Удалить узел из списка (отключился)
    pub async fn remove(&self, id: &NodeId) {
        let mut map = self.peers.write().await;
        map.remove(id);
    }

    /// Получить снимок всех известных узлов
    pub async fn all(&self) -> Vec<PeerInfo> {
        let map = self.peers.read().await;
        map.values().cloned().collect()
    }

    /// Найти узел по ID
    pub async fn get(&self, id: &NodeId) -> Option<PeerInfo> {
        let map = self.peers.read().await;
        map.get(id).cloned()
    }

    /// Количество известных узлов
    pub async fn len(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Удалить "мёртвые" узлы (не отвечали больше 60 секунд)
    pub async fn prune_stale(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut map = self.peers.write().await;
        map.retain(|_, peer| peer.is_alive(now));
    }
}

impl Default for PeerList {
    fn default() -> Self {
        Self::new()
    }
}