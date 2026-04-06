use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use void_core::identity::NodeId;
use void_core::message::NetworkMessage;

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
}

impl Router {
    /// Создаёт Router и запускает фоновую задачу обработки событий.
    ///
    /// `event_rx` — приёмная сторона канала из ConnectionManager.
    pub fn new(
        conn_manager: Arc<ConnectionManager>,
        mut event_rx: mpsc::Receiver<ConnectionEvent>,
    ) -> Self {
        let router = Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            conn_manager,
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
            ConnectionEvent::Connected { peer_id, addr } => {
                info!("Peer connected: {} at {}", peer_id, addr);

                // Автоматически запрашиваем список узлов у нового пира
                let _ = self
                    .conn_manager
                    .send_to(&peer_id, NetworkMessage::GetPeers)
                    .await;
            }

            ConnectionEvent::Disconnected { peer_id } => {
                info!("Peer disconnected: {}", peer_id);
                // Подписчики узнают об этом косвенно — через отсутствие сообщений
                // или через отдельный канал состояния (можно добавить позже)
            }

            ConnectionEvent::Message { from, message } => {
                debug!("Message from {}: {:?}", from, message);

                // Автоматически обрабатываем Ping на уровне роутера
                if matches!(message, NetworkMessage::Ping) {
                    let _ = self
                        .conn_manager
                        .send_to(&from, NetworkMessage::Pong)
                        .await;
                    return;
                }

                // Определяем тип сообщения
                let kind = classify_message(&message);

                // Рассылаем подписчикам
                let event = RouterEvent {
                    from,
                    message,
                };

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

        NetworkMessage::Ping | NetworkMessage::Pong => MessageKind::Keepalive,
    }
}