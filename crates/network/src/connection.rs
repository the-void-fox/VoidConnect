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
    /// Новое соединение установлено
    Connected {
        peer_id: NodeId,
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
    /// Наш собственный NodeId
    local_id: NodeId,
}

impl ConnectionManager {
    pub fn new(
        local_id: NodeId,
        rate_limiter: Arc<RateLimiter>,
        event_tx: mpsc::Sender<ConnectionEvent>,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            rate_limiter,
            local_id,
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
        let local_id = self.local_id.clone();

        tokio::spawn(async move {
            // Шаг 1: Handshake — обмен NodeId
            let peer_id = match perform_handshake(&mut transport, &local_id).await {
                Ok(id) => id,
                Err(e) => {
                    warn!("Handshake failed with {}: {}", peer_addr, e);
                    return;
                }
            };

            info!("Handshake complete with {} ({})", peer_id, peer_addr);

            // Шаг 2: Регистрируем соединение
            let (outbound_tx, mut outbound_rx) = mpsc::channel::<NetworkMessage>(INBOUND_BUFFER);
            let last_seen = Arc::new(Mutex::new(Instant::now()));

            let handle = ConnectionHandle {
                peer_id: peer_id.clone(),
                addr: peer_addr,
                tx: outbound_tx,
                connected_at: Instant::now(),
                last_seen: last_seen.clone(),
            };

            connections.write().await.insert(peer_id.clone(), handle);

            // Шаг 3: Уведомляем Router о новом соединении
            let _ = event_tx
                .send(ConnectionEvent::Connected {
                    peer_id: peer_id.clone(),
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

                                // Десериализуем сообщение
                                match serde_json::from_slice::<NetworkMessage>(&frame.payload) {
                                    Ok(NetworkMessage::Pong) => {
                                        last_pong = Instant::now();
                                    }
                                    Ok(msg) => {
                                        // Rate limiting
                                        if rate_limiter.check(&peer_id).await {
                                            let _ = event_tx
                                                .send(ConnectionEvent::Message {
                                                    from: peer_id.clone(),
                                                    message: msg,
                                                })
                                                .await;
                                        } else {
                                            warn!("Rate limit exceeded for {}", peer_id);
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to deserialize message from {}: {}", peer_id, e);
                                    }
                                }
                            }
                            Err(NetworkError::Disconnected) | Err(_) => {
                                info!("Connection closed with {}", peer_id);
                                break;
                            }
                        }
                    }

                    // Исходящее сообщение
                    Some(msg) = outbound_rx.recv() => {
                        match serde_json::to_vec(&msg) {
                            Ok(payload) => {
                                if let Err(e) = transport.send(Frame::new(payload)).await {
                                    warn!("Send error to {}: {}", peer_id, e);
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
                        // Проверяем таймаут pong
                        if last_pong.elapsed() > PONG_TIMEOUT {
                            warn!("Pong timeout for {}", peer_id);
                            break;
                        }

                        let payload = serde_json::to_vec(&NetworkMessage::Ping).unwrap_or_default();
                        if let Err(e) = transport.send(Frame::new(payload)).await {
                            warn!("Ping failed to {}: {}", peer_id, e);
                            break;
                        }
                    }
                }
            }

            // Шаг 6: Очищаем соединение
            connections.write().await.remove(&peer_id);
            let _ = event_tx
                .send(ConnectionEvent::Disconnected {
                    peer_id: peer_id.clone(),
                })
                .await;

            info!("Connection task ended for {}", peer_id);
        });
    }
}

// ─── Handshake ────────────────────────────────────────────────────────────────

/// Простой handshake: отправляем Announce, получаем Announce от собеседника.
/// Возвращает NodeId удалённого узла.
async fn perform_handshake(
    transport: &mut Transport,
    local_id: &NodeId,
) -> Result<NodeId, NetworkError> {
    use void_core::peer::PeerInfo;

    // Отправляем наш Announce (минимальный, без полных данных)
    // В реальности PeerInfo берётся из конфига приложения
    let announce = NetworkMessage::Announce {
        peer: PeerInfo {
            id: local_id.clone(),
            name: String::new(),
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
            chat_port: 0,
            services: vec![],
            last_seen: 0,
        },
    };

    let payload = serde_json::to_vec(&announce)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;
    transport.send(Frame::new(payload)).await?;

    // Ждём Announce от собеседника
    let frame = transport.recv().await?;
    let msg: NetworkMessage = serde_json::from_slice(&frame.payload)
        .map_err(|e| NetworkError::Serialization(e.to_string()))?;

    match msg {
        NetworkMessage::Announce { peer } => Ok(peer.id),
        _ => Err(NetworkError::Protocol(
            "Expected Announce as first message".into(),
        )),
    }
}