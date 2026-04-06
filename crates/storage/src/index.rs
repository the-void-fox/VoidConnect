//! Индекс: кто какие чанки имеет.
//!
//! Хранит в памяти маппинг chunk_hash → {peer_key, ...}.
//! При старте загружается из БД, обновляется при получении
//! объявлений от пиров (ChunkAnnounce).
//!
//! Используется `transfer.rs` для выбора, у кого качать чанк.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use void_core::identity::NodeId;

/// Потокобезопасный индекс владельцев чанков.
#[derive(Debug, Clone)]
pub struct ChunkIndex {
    /// chunk_hash → set of NodeId
    inner: Arc<RwLock<HashMap<String, HashSet<NodeId>>>>,
}

impl ChunkIndex {
    pub fn new() -> Self {
        ChunkIndex {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Записывает, что узел `peer` владеет чанком `hash`.
    pub async fn add_owner(&self, hash: &str, peer: NodeId) {
        let mut map = self.inner.write().await;
        map.entry(hash.to_string())
            .or_default()
            .insert(peer);
    }

    /// Удаляет узел из всех чанков (отключился или забанен).
    pub async fn remove_peer(&self, peer: &NodeId) {
        let mut map = self.inner.write().await;
        for owners in map.values_mut() {
            owners.remove(peer);
        }
        // Убираем пустые записи
        map.retain(|_, owners| !owners.is_empty());
        debug!("Removed peer {} from chunk index", peer);
    }

    /// Возвращает список узлов, у которых есть данный чанк.
    pub async fn get_owners(&self, hash: &str) -> Vec<NodeId> {
        let map = self.inner.read().await;
        map.get(hash)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Возвращает все хэши чанков, которые есть у данного узла.
    pub async fn get_peer_chunks(&self, peer: &NodeId) -> Vec<String> {
        let map = self.inner.read().await;
        map.iter()
            .filter(|(_, owners)| owners.contains(peer))
            .map(|(hash, _)| hash.clone())
            .collect()
    }

    /// Загружает начальное состояние из уже имеющихся данных.
    /// Вызывается при старте из `StorageManager::new`.
    pub async fn bulk_load(&self, entries: Vec<(String, NodeId)>) {
        let mut map = self.inner.write().await;
        for (hash, peer) in entries {
            map.entry(hash).or_default().insert(peer);
        }
    }

    /// Количество известных чанков в индексе.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
}

impl Default for ChunkIndex {
    fn default() -> Self {
        Self::new()
    }
}