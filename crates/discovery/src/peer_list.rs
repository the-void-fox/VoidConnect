use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use void_core::peer::PeerInfo;
use void_core::identity::NodeId;

/// Живой список известных узлов сети.
///
/// Оборачивается в Arc<PeerList> и передаётся во все подсистемы,
/// которым нужен доступ к списку — чат, хранилище, DNS и т.д.
///
/// Внутри — RwLock: много читателей одновременно, один писатель.
#[derive(Clone)]
pub struct PeerList {
    peers: Arc<RwLock<HashMap<NodeId, PeerInfo>>>,
    /// Уведомление об изменении *состава* списка (добавление/удаление/апгрейд
    /// stub→реальный ID), но НЕ при обновлении last_seen/ip существующего пира.
    /// Позволяет подписчикам (например relay_manager) реагировать мгновенно,
    /// не дожидаясь следующего опроса.
    changed: Arc<Notify>,
}

impl std::fmt::Debug for PeerList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerList").finish_non_exhaustive()
    }
}

impl PeerList {
    pub fn new() -> Self {
        PeerList {
            peers:   Arc::new(RwLock::new(HashMap::new())),
            changed: Arc::new(Notify::new()),
        }
    }

    /// Возвращает уведомитель об изменении состава списка.
    /// `notified().await` завершится при следующем структурном изменении
    /// (или сразу, если изменение произошло между вызовами — благодаря
    /// сохранённому permit'у `notify_one`).
    pub fn subscribe_changes(&self) -> Arc<Notify> {
        Arc::clone(&self.changed)
    }

    /// Добавить или обновить запись об узле.
    /// Если вставляется реальный пир — удаляем stub-заглушки с тем же IP.
    /// На loopback (127.x) сравниваем ещё и порт, чтобы не затереть чужие stubs.
    pub async fn upsert(&self, peer: PeerInfo) {
        let mut structural = false;
        {
            let mut map = self.peers.write().await;
            if !peer.id.as_str().starts_with("stub-") {
                let is_loopback = peer.ip.is_loopback();
                let stale: Vec<NodeId> = map.values()
                    .filter(|p| {
                        p.id.as_str().starts_with("stub-")
                            && p.ip == peer.ip
                            // На loopback несколько экземпляров — убираем только stub с тем же портом
                            && (!is_loopback || p.port == peer.port)
                    })
                    .map(|p| p.id.clone())
                    .collect();
                for id in stale {
                    map.remove(&id);
                    structural = true;
                }
            }
            // Появление нового ID — структурное изменение; обновление полей
            // существующего (heartbeat) — нет.
            if !map.contains_key(&peer.id) {
                structural = true;
            }
            map.insert(peer.id.clone(), peer);
        }
        if structural {
            self.changed.notify_one();
        }
    }

    /// Удалить узел из списка (отключился)
    pub async fn remove(&self, id: &NodeId) {
        let removed = {
            let mut map = self.peers.write().await;
            map.remove(id).is_some()
        };
        if removed {
            self.changed.notify_one();
        }
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

    /// Удалить "мёртвые" узлы (не отвечали больше 60 секунд).
    /// Ручно добавленные узлы (id начинается на "stub-") не удаляются —
    /// они живут до тех пор, пока реальный пир не заменит их.
    pub async fn prune_stale(&self) {
        let now = chrono::Utc::now().timestamp();
        let removed_any = {
            let mut map = self.peers.write().await;
            let before = map.len();
            map.retain(|_, peer| {
                peer.id.as_str().starts_with("stub-") || peer.is_alive(now)
            });
            before != map.len()
        };
        if removed_any {
            self.changed.notify_one();
        }
    }
}

impl Default for PeerList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::time::timeout;
    use void_core::peer::Service;

    fn peer(id: &str, ip: [u8; 4], port: u16, last_seen: i64) -> PeerInfo {
        PeerInfo {
            id:        NodeId(id.to_string()),
            name:      "p".into(),
            ip:        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            port,
            chat_port: port + 2,
            services:  vec![Service::Chat],
            last_seen,
        }
    }

    #[tokio::test]
    async fn upsert_get_remove_len() {
        let pl = PeerList::new();
        assert_eq!(pl.len().await, 0);

        let p = peer("aaaa", [192, 168, 0, 2], 7700, 0);
        pl.upsert(p.clone()).await;
        assert_eq!(pl.len().await, 1);
        assert_eq!(pl.get(&p.id).await.unwrap().port, 7700);

        // upsert с тем же id обновляет, а не дублирует
        let mut p2 = p.clone();
        p2.port = 7800;
        pl.upsert(p2).await;
        assert_eq!(pl.len().await, 1);
        assert_eq!(pl.get(&p.id).await.unwrap().port, 7800);

        pl.remove(&p.id).await;
        assert_eq!(pl.len().await, 0);
    }

    /// Реальный пир с тем же (не-loopback) IP вытесняет stub-заглушку.
    #[tokio::test]
    async fn real_peer_replaces_stub_same_ip() {
        let pl = PeerList::new();
        pl.upsert(peer("stub-192.168.0.5:7700", [192, 168, 0, 5], 7700, 0)).await;
        assert_eq!(pl.len().await, 1);

        let real = peer("realid64", [192, 168, 0, 5], 7700, 0);
        pl.upsert(real.clone()).await;

        // stub удалён, остался только реальный
        assert_eq!(pl.len().await, 1);
        let all = pl.all().await;
        assert_eq!(all[0].id, real.id);
    }

    /// На loopback несколько экземпляров: реальный пир убирает только stub
    /// с тем же портом, чужие stubs на других портах сохраняются.
    #[tokio::test]
    async fn loopback_keeps_stubs_on_other_ports() {
        let pl = PeerList::new();
        pl.upsert(peer("stub-127.0.0.1:7700", [127, 0, 0, 1], 7700, 0)).await;
        pl.upsert(peer("stub-127.0.0.1:7710", [127, 0, 0, 1], 7710, 0)).await;

        // Реальный пир на порту 7700 вытесняет только stub :7700
        pl.upsert(peer("realid64", [127, 0, 0, 1], 7700, 0)).await;

        let ids: Vec<String> = pl.all().await.iter().map(|p| p.id.0.clone()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.iter().any(|i| i == "realid64"));
        assert!(ids.iter().any(|i| i == "stub-127.0.0.1:7710"));
        assert!(!ids.iter().any(|i| i == "stub-127.0.0.1:7700"));
    }

    /// prune_stale убирает протухшие реальные пиры, но сохраняет свежие и stub-заглушки.
    #[tokio::test]
    async fn prune_removes_stale_keeps_fresh_and_stubs() {
        let pl = PeerList::new();
        let now = chrono::Utc::now().timestamp();

        pl.upsert(peer("fresh", [10, 0, 0, 1], 7700, now)).await;
        pl.upsert(peer("stale", [10, 0, 0, 2], 7700, now - 120)).await;
        pl.upsert(peer("stub-10.0.0.3:7700", [10, 0, 0, 3], 7700, now - 9999)).await;

        pl.prune_stale().await;

        let ids: Vec<String> = pl.all().await.iter().map(|p| p.id.0.clone()).collect();
        assert!(ids.iter().any(|i| i == "fresh"), "свежий пир должен остаться");
        assert!(ids.iter().any(|i| i == "stub-10.0.0.3:7700"), "stub должен остаться");
        assert!(!ids.iter().any(|i| i == "stale"), "протухший пир должен быть удалён");
    }

    #[tokio::test]
    async fn upsert_new_peer_notifies() {
        let pl = PeerList::new();
        let n = pl.subscribe_changes();
        pl.upsert(peer("aaaa", [10, 0, 0, 1], 7700, 0)).await;
        // permit от notify_one сохранён → notified() завершится сразу
        assert!(
            timeout(Duration::from_millis(200), n.notified()).await.is_ok(),
            "появление нового пира должно уведомлять"
        );
    }

    #[tokio::test]
    async fn remove_notifies() {
        let pl = PeerList::new();
        let p = peer("aaaa", [10, 0, 0, 1], 7700, 0);
        pl.upsert(p.clone()).await;
        let n = pl.subscribe_changes();
        let _ = timeout(Duration::from_millis(50), n.notified()).await; // сливаем permit от upsert
        pl.remove(&p.id).await;
        assert!(
            timeout(Duration::from_millis(200), n.notified()).await.is_ok(),
            "удаление пира должно уведомлять"
        );
    }

    /// Обновление существующего пира (heartbeat: новый last_seen/ip) НЕ уведомляет —
    /// иначе relay_manager переизбирался бы на каждый UDP-пакет.
    #[tokio::test]
    async fn heartbeat_does_not_notify() {
        let pl = PeerList::new();
        let p = peer("aaaa", [10, 0, 0, 1], 7700, 0);
        pl.upsert(p.clone()).await;
        let n = pl.subscribe_changes();
        let _ = timeout(Duration::from_millis(50), n.notified()).await; // сливаем permit от первого upsert

        // Тот же ID, обновлён только last_seen — структура не изменилась.
        let mut hb = p.clone();
        hb.last_seen = 12_345;
        pl.upsert(hb).await;

        assert!(
            timeout(Duration::from_millis(150), n.notified()).await.is_err(),
            "heartbeat существующего пира не должен уведомлять"
        );
    }
}