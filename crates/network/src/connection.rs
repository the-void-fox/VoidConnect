use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use void_core::identity::NodeId;
use void_core::message::NetworkMessage;
use void_core::peer::PeerInfo;

use crate::error::NetworkError;
use crate::rate_limit::RateLimiter;
use crate::transport::{Frame, TcpTransport, Transport};

// ─── Константы ───────────────────────────────────────────────────────────────

/// Интервал между Ping-пакетами для keepalive
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Таймаут — если Pong не пришёл за это время, соединение закрывается
const PONG_TIMEOUT: Duration = Duration::from_secs(30);

/// Размер буфера входящих сообщений от одного соединения
const INBOUND_BUFFER: usize = 256;

// ─── Событие соединения ───────────────────────────────────────────────────────

/// Событие, которое ConnectionManager отправляет наружу через mpsc-канал.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Новое соединение установлено; содержит полный PeerInfo для обновления PeerList
    Connected {
        peer_info: PeerInfo,
        addr: SocketAddr,
    },
    /// Соединение закрыто
    Disconnected {
        peer_id: NodeId,
    },
    /// Получено сообщение от узла
    Message {
        from: NodeId,
        message: NetworkMessage,
    },
}

// ─── Дескриптор соединения ────────────────────────────────────────────────────

/// Хэндл для отправки сообщений в конкретное соединение.
#[derive(Debug, Clone)]
pub struct ConnectionHandle {
    pub peer_id: NodeId,
    pub addr: SocketAddr,
    /// Канал для отправки исходящих сообщений в задачу соединения
    pub tx: mpsc::Sender<NetworkMessage>,
    pub connected_at: Instant,
    pub last_seen: Arc<Mutex<Instant>>,
}

impl ConnectionHandle {
    pub async fn send(&self, msg: NetworkMessage) -> Result<(), NetworkError> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| NetworkError::Disconnected)
    }

    pub async fn seconds_since_last_seen(&self) -> u64 {
        self.last_seen.lock().await.elapsed().as_secs()
    }
}

// ─── ConnectionManager ────────────────────────────────────────────────────────

/// Управляет всеми активными соединениями.
/// Запускает TCP-сервер, принимает входящие подключения,
/// инициирует исходящие, рассылает сообщения.
#[derive(Clone)]
pub struct ConnectionManager {
    /// Карта peer_id → хэндл соединения
    connections: Arc<RwLock<HashMap<NodeId, ConnectionHandle>>>,
    /// Канал для отправки событий в Router
    event_tx: mpsc::Sender<ConnectionEvent>,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// Полные данные о нашем узле — используются в handshake
    my_peer: Arc<PeerInfo>,
}

impl ConnectionManager {
    pub fn new(
        my_peer: PeerInfo,
        rate_limiter: Arc<RateLimiter>,
        event_tx: mpsc::Sender<ConnectionEvent>,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            rate_limiter,
            my_peer: Arc::new(my_peer),
        }
    }

    // ─── Сервер ───────────────────────────────────────────────────────────────

    /// Запускает TCP-сервер на указанном порту.
    /// Принимает входящие соединения в отдельной задаче.
    pub async fn listen(&self, port: u16) -> Result<(), NetworkError> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| NetworkError::Bind(e.to_string()))?;

        info!("TCP server listening on {}", addr);

        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("Incoming TCP connection from {}", peer_addr);
                        let m = manager.clone();
                        tokio::spawn(async move {
                            if let Err(e) = m.handle_incoming_tcp(stream, peer_addr).await {
                                warn!("Error handling connection from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    // ─── Исходящие соединения ─────────────────────────────────────────────────

    /// Подключается к узлу по адресу.
    pub async fn connect(&self, addr: SocketAddr) -> Result<(), NetworkError> {
        // Не подключаемся к себе
        {
            let conns = self.connections.read().await;
            if conns.values().any(|c| c.addr == addr) {
                debug!("Already connected to {}", addr);
                return Ok(());
            }
        }

        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;

        info!("Connected to {}", addr);

        let transport = Transport::Tcp(TcpTransport::new(stream, addr));
        self.spawn_connection_task(transport).await;

        Ok(())
    }

    // ─── Рассылка ─────────────────────────────────────────────────────────────

    /// Отправляет сообщение конкретному узлу.
    pub async fn send_to(&self, peer_id: &NodeId, msg: NetworkMessage) -> Result<(), NetworkError> {
        let conns = self.connections.read().await;
        match conns.get(peer_id) {
            Some(handle) => handle.send(msg).await,
            None => Err(NetworkError::PeerNotFound(peer_id.as_str().to_string())),
        }
    }

    /// Рассылает сообщение всем подключённым узлам.
    pub async fn broadcast(&self, msg: NetworkMessage) {
        let conns = self.connections.read().await;
        for handle in conns.values() {
            if let Err(e) = handle.send(msg.clone()).await {
                warn!("Broadcast failed to {}: {}", handle.peer_id, e);
            }
        }
    }

    /// Рассылает всем, кроме указанного узла (для relay в чате).
    pub async fn broadcast_except(&self, exclude: &NodeId, msg: NetworkMessage) {
        let conns = self.connections.read().await;
        for (id, handle) in conns.iter() {
            if id == exclude {
                continue;
            }
            if let Err(e) = handle.send(msg.clone()).await {
                warn!("Broadcast failed to {}: {}", id, e);
            }
        }
    }

    // ─── Информация ───────────────────────────────────────────────────────────

    /// Список всех подключённых узлов.
    pub async fn connected_peers(&self) -> Vec<NodeId> {
        self.connections
            .read()
            .await
            .keys()
            .cloned()
            .collect()
    }

    pub async fn peer_count(&self) -> usize {
        self.connections.read().await.len()
    }

    pub async fn is_connected(&self, peer_id: &NodeId) -> bool {
        self.connections.read().await.contains_key(peer_id)
    }

    // ─── Внутренние методы ────────────────────────────────────────────────────

    async fn handle_incoming_tcp(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(), NetworkError> {
        let transport = Transport::Tcp(TcpTransport::new(stream, peer_addr));
        self.spawn_connection_task(transport).await;
        Ok(())
    }

    /// Запускает задачу для конкретного соединения.
    /// Задача читает входящие фреймы и отправляет события в Router.
    async fn spawn_connection_task(&self, mut transport: Transport) {
        let peer_addr = transport.peer_addr();
        let event_tx = self.event_tx.clone();
        let connections = self.connections.clone();
        let rate_limiter = self.rate_limiter.clone();
        let my_peer = self.my_peer.clone();

        tokio::spawn(async move {
            // Шаг 1: Handshake — обмен полными PeerInfo
            let peer_id = match perform_handshake(&mut transport, &my_peer).await {
                Ok(id) => id,
                Err(e) => {
                    warn!("Handshake failed with {}: {}", peer_addr, e);
                    return;
                }
            };

            info!("Handshake complete with {} ({})", peer_id.id, peer_addr);

            // Шаг 2: Регистрируем соединение
            let node_id = peer_id.id.clone();
            let (outbound_tx, mut outbound_rx) = mpsc::channel::<NetworkMessage>(INBOUND_BUFFER);
            let last_seen = Arc::new(Mutex::new(Instant::now()));

            let handle = ConnectionHandle {
                peer_id: node_id.clone(),
                addr: peer_addr,
                tx: outbound_tx,
                connected_at: Instant::now(),
                last_seen: last_seen.clone(),
            };

            connections.write().await.insert(node_id.clone(), handle);

            // Шаг 3: Уведомляем Router — передаём полный PeerInfo для обновления PeerList
            let _ = event_tx
                .send(ConnectionEvent::Connected {
                    peer_info: peer_id,
                    addr: peer_addr,
                })
                .await;

            // Шаг 4: Запускаем keepalive пинг
            let mut ping_interval = interval(PING_INTERVAL);
            let mut last_pong = Instant::now();

            // Шаг 5: Основной цикл чтения/записи
            loop {
                tokio::select! {
                    // Входящий фрейм
                    result = transport.recv() => {
                        match result {
                            Ok(frame) => {
                                *last_seen.lock().await = Instant::now();

                                match serde_json::from_slice::<NetworkMessage>(&frame.payload) {
                                    Ok(NetworkMessage::Pong) => {
                                        last_pong = Instant::now();
                                    }
                                    Ok(msg) => {
                                        // Rate limiting
                                        if rate_limiter.check(&node_id).await {
                                            let _ = event_tx
                                                .send(ConnectionEvent::Message {
                                                    from: node_id.clone(),
                                                    message: msg,
                                                })
                                                .await;
                                        } else {
                                            warn!("Rate limit exceeded for {}", node_id);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to deserialize message from {}: {}", node_id, e);
                                    }
                                }
                            }
                            Err(NetworkError::Disconnected) | Err(_) => {
                                info!("Connection closed with {}", node_id);
                                break;
                            }
                        }
                    }

                    // Исходящее сообщение
                    Some(msg) = outbound_rx.recv() => {
                        match serde_json::to_vec(&msg) {
                            Ok(payload) => {
                                if let Err(e) = transport.send(Frame::new(payload)).await {
                                    warn!("Send error to {}: {}", node_id, e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Serialization error: {}", e);
                            }
                        }
                    }

                    // Keepalive ping
                    _ = ping_interval.tick() => {
                        if last_pong.elapsed() > PONG_TIMEOUT {
                            warn!("Pong timeout for {}", node_id);
                            break;
                        }

                        let payload = serde_json::to_vec(&NetworkMessage::Ping).unwrap_or_default();
                        if let Err(e) = transport.send(Frame::new(payload)).await {
                            warn!("Ping failed to {}: {}", node_id, e);
                            break;
                        }
                    }
                }
            }

            // Шаг 6: Очищаем соединение
            connections.write().await.remove(&node_id);
            let _ = event_tx
                .send(ConnectionEvent::Disconnected {
                    peer_id: node_id.clone(),
                })
                .await;

            info!("Connection task ended for {}", node_id);
        });
    }
}

// ─── Handshake ────────────────────────────────────────────────────────────────

/// Handshake: обмениваемся полными PeerInfo через Announce.
/// Возвращает PeerInfo удалённого узла — Router сразу передаст его в PeerList.
async fn perform_handshake(
    transport: &mut Transport,
    my_peer: &PeerInfo,
) -> Result<PeerInfo, NetworkError> {
    // Отправляем полный Announce с реальными данными
    let announce = NetworkMessage::Announce {
        peer: my_peer.clone(),
    };

    let payload = serde_json::to_vec(&announce)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;
    transport.send(Frame::new(payload)).await?;

    // Ждём Announce от собеседника
    let frame = transport.recv().await?;
    let msg: NetworkMessage = serde_json::from_slice(&frame.payload)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;

    match msg {
        NetworkMessage::Announce { peer } => Ok(peer),
        _ => Err(NetworkError::Protocol(
            "Expected Announce as first message".into(),
        )),
    }
}