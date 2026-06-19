use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use void_core::identity::NodeId;
use void_core::message::NetworkMessage;
use void_core::peer::PeerInfo;
use void_discovery::PeerList;

use crate::connection::{ConnectionEvent, ConnectionManager};
use crate::error::NetworkError;

// ─── Подписчики ───────────────────────────────────────────────────────────────

/// Тип сообщения — используется для подписки на конкретный вид событий.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// Объявление узла (Announce / GetPeers / Peers)
    Discovery,
    /// Сообщения общего чата (ChatMessage)
    Chat,
    /// Синхронизация и жалобы репутации (ReputationSync / ReputationReport)
    Reputation,
    /// Ping / Pong
    Keepalive,
    /// Все сообщения (wildcard)
    All,
}

/// Событие, которое Router доставляет подписчику.
#[derive(Debug, Clone)]
pub struct RouterEvent {
    pub from: NodeId,
    pub message: NetworkMessage,
}

// ─── Router ───────────────────────────────────────────────────────────────────

/// Получает события от ConnectionManager и раздаёт их подписчикам.
///
/// Архитектура:
/// ```
/// ConnectionManager --ConnectionEvent--> Router --RouterEvent--> subscribers
/// ```
///
/// Каждый крейт (chat, discovery, storage…) подписывается на свой MessageKind
/// и получает только нужные сообщения через свой mpsc-приёмник.
#[derive(Clone)]
pub struct Router {
    /// Таблица подписчиков: kind → список sender-ов
    subscribers: Arc<RwLock<HashMap<MessageKind, Vec<mpsc::Sender<RouterEvent>>>>>,
    /// ConnectionManager для ответных отправок
    conn_manager: Arc<ConnectionManager>,
    /// Общий список узлов — обновляется при connect/disconnect
    peer_list: PeerList,
}

impl Router {
    /// Создаёт Router и запускает фоновую задачу обработки событий.
    ///
    /// `event_rx` — приёмная сторона канала из ConnectionManager.
    /// `peer_list` — разделяемый список узлов из крейта discovery.
    pub fn new(
        conn_manager: Arc<ConnectionManager>,
        peer_list: PeerList,
        mut event_rx: mpsc::Receiver<ConnectionEvent>,
    ) -> Self {
        let router = Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            conn_manager,
            peer_list,
        };

        let r = router.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                r.handle_event(event).await;
            }
        });

        router
    }

    // ─── Подписки ─────────────────────────────────────────────────────────────

    /// Подписывается на определённый вид сообщений.
    /// Возвращает Receiver для чтения событий.
    ///
    /// Пример:
    /// ```rust
    /// let mut rx = router.subscribe(MessageKind::Chat, 128).await;
    /// while let Some(event) = rx.recv().await {
    ///     // обработка сообщений чата
    /// }
    /// ```
    pub async fn subscribe(
        &self,
        kind: MessageKind,
        buffer: usize,
    ) -> mpsc::Receiver<RouterEvent> {
        let (tx, rx) = mpsc::channel(buffer);
        let mut subs = self.subscribers.write().await;
        subs.entry(kind).or_default().push(tx);
        rx
    }

    // ─── Отправка ─────────────────────────────────────────────────────────────

    /// Отправляет сообщение конкретному узлу.
    pub async fn send_to(
        &self,
        peer_id: &NodeId,
        msg: NetworkMessage,
    ) -> Result<(), NetworkError> {
        self.conn_manager.send_to(peer_id, msg).await
    }

    /// Рассылает сообщение всем подключённым узлам.
    pub async fn broadcast(&self, msg: NetworkMessage) {
        self.conn_manager.broadcast(msg).await;
    }

    /// Рассылает всем, кроме указанного узла.
    pub async fn broadcast_except(&self, exclude: &NodeId, msg: NetworkMessage) {
        self.conn_manager.broadcast_except(exclude, msg).await;
    }

    // ─── Peer info ────────────────────────────────────────────────────────────

    pub async fn connected_peers(&self) -> Vec<NodeId> {
        self.conn_manager.connected_peers().await
    }

    pub async fn peer_count(&self) -> usize {
        self.conn_manager.peer_count().await
    }

    // ─── Внутренняя обработка ─────────────────────────────────────────────────

    async fn handle_event(&self, event: ConnectionEvent) {
        match event {
            ConnectionEvent::Connected { peer_info, addr } => {
                info!("Peer connected: {} at {}", peer_info.id, addr);

                // Обновляем PeerList реальными данными из handshake.
                // Это единственный авторитетный источник для TCP-соединений —
                // mDNS/UDP мог ещё не успеть получить этот узел.
                self.peer_list.upsert(peer_info.clone()).await;

                // Запрашиваем список узлов у нового пира
                let _ = self
                    .conn_manager
                    .send_to(&peer_info.id, NetworkMessage::GetPeers)
                    .await;
            }

            ConnectionEvent::Disconnected { peer_id } => {
                info!("Peer disconnected: {}", peer_id);
                // Удаляем из PeerList — prune_stale тоже уберёт его со временем,
                // но явное удаление даёт немедленную согласованность.
                self.peer_list.remove(&peer_id).await;
            }

            ConnectionEvent::Message { from, message } => {
                debug!("Message from {}: {:?}", from, message);

                // Обновляем last_seen при любом входящем сообщении,
                // чтобы prune_stale не удалил активный узел.
                if let Some(mut peer) = self.peer_list.get(&from).await {
                    peer.last_seen = chrono::Utc::now().timestamp();
                    self.peer_list.upsert(peer).await;
                }

                // Ping обрабатываем здесь же, не гоняем по подписчикам
                if matches!(message, NetworkMessage::Ping) {
                    let _ = self
                        .conn_manager
                        .send_to(&from, NetworkMessage::Pong)
                        .await;
                    return;
                }

                // Peers { peers } — сразу добавляем в PeerList,
                // не требуя отдельного подписчика для этого.
                if let NetworkMessage::Peers { ref peers } = message {
                    for peer in peers {
                        // Не перезаписываем уже подключённых — у них актуальный IP
                        if self.peer_list.get(&peer.id).await.is_none() {
                            self.peer_list.upsert(peer.clone()).await;
                        }
                    }
                }

                let kind = classify_message(&message);
                let event = RouterEvent { from, message };
                self.dispatch(kind, event).await;
            }
        }
    }

    /// Доставляет событие всем подписчикам нужного типа + wildcard All.
    async fn dispatch(&self, kind: MessageKind, event: RouterEvent) {
        let subs = self.subscribers.read().await;

        let targets: Vec<_> = subs
            .get(&kind)
            .into_iter()
            .chain(subs.get(&MessageKind::All))
            .flatten()
            .cloned()
            .collect();

        drop(subs); // отпускаем лок перед async отправкой

        let mut dead = Vec::new();
        for (i, tx) in targets.iter().enumerate() {
            if tx.send(event.clone()).await.is_err() {
                // Получатель закрыт — помечаем для удаления
                dead.push(i);
            }
        }

        // Чистим мёртвые подписки
        if !dead.is_empty() {
            let mut subs = self.subscribers.write().await;
            if let Some(list) = subs.get_mut(&kind) {
                // Удаляем закрытые каналы
                list.retain(|tx| !tx.is_closed());
            }
            if let Some(list) = subs.get_mut(&MessageKind::All) {
                list.retain(|tx| !tx.is_closed());
            }
        }
    }
}

// ─── Классификатор сообщений ──────────────────────────────────────────────────

fn classify_message(msg: &NetworkMessage) -> MessageKind {
    match msg {
        NetworkMessage::Announce { .. }
        | NetworkMessage::GetPeers
        | NetworkMessage::Peers { .. } => MessageKind::Discovery,

        NetworkMessage::ChatMessage { .. } => MessageKind::Chat,

        NetworkMessage::ReputationSync { .. }
        | NetworkMessage::ReputationReport { .. } => MessageKind::Reputation,

        NetworkMessage::Ping | NetworkMessage::Pong => MessageKind::Keepalive,
    }
}