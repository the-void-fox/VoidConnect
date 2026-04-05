//! Общий чат — рассылка сообщений всем участникам сети.
//!
//! Схема: один узел — ретранслятор (hub), остальные подключаются к нему.
//! Ретранслятор — узел с лексически наименьшим ID среди всех известных.
//!
//! Протокол поверх TCP (length-prefixed JSON):
//!   Клиент → сервер: Hello, затем Message*
//!   Сервер → клиент: History сразу после Hello, затем форвард Message*

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use void_core::identity::NodeId;
use void_core::peer::PeerInfo;
use void_discovery::PeerList;

const MAX_MESSAGE_LEN: usize = 4096;
const BROADCAST_BUFFER: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEDUP_WINDOW: usize = 256;

// ─── Протокол ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChatPacket {
    Message(ChatMessage),
    History { messages: Vec<ChatMessage> },
    Hello { node_id: NodeId, name: String },
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub from: NodeId,
    pub from_name: String,
    pub text: String,
    pub timestamp: i64,
    pub seq: u64,
    pub signature: Option<String>,
}

impl ChatMessage {
    pub fn new(from: NodeId, from_name: String, text: String, seq: u64) -> Self {
        ChatMessage { from, from_name, text, timestamp: Utc::now().timestamp(), seq, signature: None }
    }
}

// ─── Состояние ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PublicChat {
    inner: Arc<PublicChatInner>,
}

struct PublicChatInner {
    my_peer:     PeerInfo,
    peer_list:   PeerList,
    chat_port:   u16,
    incoming_tx: broadcast::Sender<ChatMessage>,
    history:     Mutex<VecDeque<ChatMessage>>,
    seq_counter: Mutex<u64>,
    seen:        Mutex<HashSet<(String, u64)>>,
    seen_order:  Mutex<VecDeque<(String, u64)>>,
    /// None = мы ретранслятор; Some = ID ретранслятора
    relay:       RwLock<Option<NodeId>>,
    /// Канал для отправки исходящих сообщений через постоянное соединение с ретранслятором
    outbox_tx:   Mutex<Option<mpsc::Sender<ChatMessage>>>,
    /// Подключённые клиенты (когда мы ретранслятор): id → канал форварда
    clients:     Mutex<HashMap<NodeId, mpsc::Sender<ChatMessage>>>,
}

impl PublicChat {
    fn new(my_peer: PeerInfo, peer_list: PeerList, chat_port: u16) -> Self {
        let (incoming_tx, _) = broadcast::channel(BROADCAST_BUFFER);
        PublicChat {
            inner: Arc::new(PublicChatInner {
                my_peer, peer_list, chat_port, incoming_tx,
                history:     Mutex::new(VecDeque::with_capacity(100)),
                seq_counter: Mutex::new(0),
                seen:        Mutex::new(HashSet::new()),
                seen_order:  Mutex::new(VecDeque::with_capacity(DEDUP_WINDOW)),
                relay:       RwLock::new(None),
                outbox_tx:   Mutex::new(None),
                clients:     Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> {
        self.inner.incoming_tx.subscribe()
    }

    pub async fn recent(&self, n: usize) -> Vec<ChatMessage> {
        let h = self.inner.history.lock().await;
        h.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect()
    }
}

// ─── Запуск ──────────────────────────────────────────────────────────────────

pub async fn start_public_chat(
    my_peer: PeerInfo,
    peer_list: PeerList,
    chat_port: u16,
) -> anyhow::Result<ChatHandle> {
    let chat = PublicChat::new(my_peer, peer_list, chat_port);

    let c = chat.clone();
    tokio::spawn(async move {
        if let Err(e) = run_server(c).await { error!("Chat server: {}", e); }
    });

    let c = chat.clone();
    tokio::spawn(async move { relay_manager(c).await; });

    info!("Public chat started");
    Ok(ChatHandle { chat })
}

// ─── TCP-сервер (роль ретранслятора) ─────────────────────────────────────────

async fn run_server(chat: PublicChat) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", chat.inner.chat_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Chat TCP server listening on {}", addr);
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let c = chat.clone();
                tokio::spawn(async move { handle_client(stream, addr, c).await; });
            }
            Err(e) => warn!("Accept error: {}", e),
        }
    }
}

async fn handle_client(mut stream: TcpStream, addr: std::net::SocketAddr, chat: PublicChat) {
    debug!("New connection from {}", addr);

    // Шаг 1: читаем Hello
    let hello = match read_packet(&mut stream).await {
        Ok(p) => p,
        Err(e) => { warn!("No Hello from {}: {}", addr, e); return; }
    };
    let (node_id, _name) = match hello {
        ChatPacket::Hello { node_id, name } => (node_id, name),
        _ => { warn!("Expected Hello from {}", addr); return; }
    };
    info!("Client connected: {} from {}", node_id, addr);

    // Обновляем peer_list: если этот адрес был заглушкой (stub-...) — заменяем на реальный ID
    {
        let peers = chat.inner.peer_list.all().await;
        for p in peers {
            if p.ip == addr.ip() && p.id.as_str().starts_with("stub-") {
                let mut real = p.clone();
                real.id = node_id.clone();
                chat.inner.peer_list.remove(&p.id).await;
                chat.inner.peer_list.upsert(real).await;
                debug!("Updated stub peer to real ID: {}", node_id);
                break;
            }
        }
    }

    // Шаг 2: шлём историю
    let history: Vec<ChatMessage> = chat.inner.history.lock().await.iter().cloned().collect();
    if let Err(e) = send_packet(&mut stream, &ChatPacket::History { messages: history }).await {
        warn!("History send failed: {}", e); return;
    }

    // Шаг 3: регистрируем клиента
    let (fwd_tx, mut fwd_rx) = mpsc::channel::<ChatMessage>(64);
    chat.inner.clients.lock().await.insert(node_id.clone(), fwd_tx);

    let (mut rd, mut wr) = stream.into_split();

    // Читаем сообщения от клиента
    let chat_r = chat.clone();
    let nid = node_id.clone();
    let read_task = tokio::spawn(async move {
        loop {
            match read_packet_rd(&mut rd).await {
                Ok(ChatPacket::Message(msg)) => { chat_r.handle_incoming(msg).await; }
                Ok(_) => {}
                Err(_) => { debug!("Client {} disconnected (read)", nid); break; }
            }
        }
    });

    // Форвардим сообщения клиенту
    let nid2 = node_id.clone();
    let write_task = tokio::spawn(async move {
        while let Some(msg) = fwd_rx.recv().await {
            if send_packet_wr(&mut wr, &ChatPacket::Message(msg)).await.is_err() {
                debug!("Client {} disconnected (write)", nid2);
                break;
            }
        }
    });

    tokio::select! { _ = read_task => {}, _ = write_task => {} }

    chat.inner.clients.lock().await.remove(&node_id);
    info!("Client {} disconnected", node_id);
}

// ─── Обработка входящего сообщения ───────────────────────────────────────────

impl PublicChat {
    async fn handle_incoming(&self, msg: ChatMessage) {
        // Дедупликация
        let key = (msg.from.as_str().to_string(), msg.seq);
        {
            let mut seen = self.inner.seen.lock().await;
            if seen.contains(&key) { return; }
            seen.insert(key.clone());
            let mut order = self.inner.seen_order.lock().await;
            order.push_back(key);
            if order.len() > DEDUP_WINDOW {
                if let Some(old) = order.pop_front() { seen.remove(&old); }
            }
        }

        // История
        {
            let mut h = self.inner.history.lock().await;
            if h.len() >= 100 { h.pop_front(); }
            h.push_back(msg.clone());
        }

        // Локальным подписчикам (UI)
        let _ = self.inner.incoming_tx.send(msg.clone());

        // Форвард всем подключённым клиентам (роль ретранслятора)
        let clients = self.inner.clients.lock().await;
        for (id, tx) in clients.iter() {
            if *id != msg.from {
                let _ = tx.send(msg.clone()).await;
            }
        }
    }

    /// Отправить своё сообщение
    pub async fn send(&self, text: String) -> anyhow::Result<()> {
        let seq = { let mut c = self.inner.seq_counter.lock().await; *c += 1; *c };
        let msg = ChatMessage::new(
            self.inner.my_peer.id.clone(),
            self.inner.my_peer.name.clone(),
            text, seq,
        );

        let is_relay = self.inner.relay.read().await.is_none();
        if is_relay {
            // Мы ретранслятор — обрабатываем напрямую
            self.handle_incoming(msg).await;
        } else {
            // Шлём через постоянное соединение с ретранслятором
            let outbox = self.inner.outbox_tx.lock().await;
            if let Some(tx) = outbox.as_ref() {
                tx.send(msg).await.map_err(|_| anyhow::anyhow!("Relay connection lost"))?;
            } else {
                // Соединение ещё не установлено — покажем локально чтобы не потерять
                warn!("Not connected to relay yet, message shown locally only");
                self.handle_incoming(msg).await;
            }
        }
        Ok(())
    }
}

// ─── Менеджер соединения с ретранслятором ────────────────────────────────────
//
// Следит за peer_list, выбирает ретранслятора, держит с ним постоянный коннект.
// При разрыве — переподключается.

async fn relay_manager(chat: PublicChat) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;

        let peers = chat.inner.peer_list.all().await;
        if peers.is_empty() {
            // Нет пиров — мы ретранслятор по умолчанию
            continue;
        }

        // Выбираем ретранслятора: наименьший реальный ID среди узлов с известным chat_port.
        // Заглушки (--peer=) имеют id вида "stub-...", настоящие ID — hex 64 символа.
        // Используем только реальные ID (длина 64) для честного сравнения.
        let my_id = chat.inner.my_peer.id.as_str().to_string();
        let real_peers: Vec<_> = peers.iter()
            .filter(|p| p.id.as_str().len() == 64) // только настоящие hex ID
            .collect();

        let elected = if real_peers.is_empty() {
            // Все пиры — заглушки (--peer=). Подключаемся к первому из них напрямую.
            // Он станет нашим ретранслятором пока не узнаем его настоящий ID.
            peers[0].id.as_str().to_string()
        } else {
            // Честный выбор среди реальных ID
            let mut candidates: Vec<String> = real_peers.iter()
                .map(|p| p.id.as_str().to_string())
                .collect();
            candidates.push(my_id.clone());
            candidates.sort();
            candidates.into_iter().next().unwrap()
        };

        if elected == my_id {
            // Мы ретранслятор
            if chat.inner.relay.read().await.is_some() {
                info!("I am now the relay");
                *chat.inner.relay.write().await = None;
                *chat.inner.outbox_tx.lock().await = None;
            }
        } else {
            let relay_id = NodeId(elected.clone());
            let current = chat.inner.relay.read().await.clone();

            if current.as_ref() == Some(&relay_id) {
                // Уже подключены — проверяем живость
                let alive = chat.inner.outbox_tx.lock().await.as_ref()
                    .map(|tx| !tx.is_closed())
                    .unwrap_or(false);
                if alive { continue; }
                info!("Relay connection lost, reconnecting...");
            } else {
                info!("Connecting to relay {}...", &elected[..8.min(elected.len())]);
            }

            let peer = match peers.iter().find(|p| p.id.as_str() == elected) {
                Some(p) => p.clone(),
                None => continue,
            };

            match connect_to_relay(&chat, peer).await {
                Ok(tx) => {
                    *chat.inner.relay.write().await = Some(relay_id);
                    *chat.inner.outbox_tx.lock().await = Some(tx);
                    info!("Connected to relay {}", &elected[..8.min(elected.len())]);
                }
                Err(e) => {
                    warn!("Failed to connect to relay: {}", e);
                }
            }
        }
    }
}

/// Устанавливает постоянное TCP-соединение с ретранслятором.
/// Возвращает канал для отправки сообщений.
/// Запускает фоновый таск который читает форварды и пишет их в handle_incoming.
async fn connect_to_relay(chat: &PublicChat, peer: PeerInfo) -> anyhow::Result<mpsc::Sender<ChatMessage>> {
    let addr = peer.chat_addr();
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await??;
    let (mut rd, mut wr) = stream.into_split();

    // Hello
    send_packet_wr(&mut wr, &ChatPacket::Hello {
        node_id: chat.inner.my_peer.id.clone(),
        name:    chat.inner.my_peer.name.clone(),
    }).await?;

    // История (читаем но пока просто добавляем в историю)
    match read_packet_rd(&mut rd).await? {
        ChatPacket::History { messages } => {
            let mut h = chat.inner.history.lock().await;
            for msg in messages {
                if h.len() >= 100 { h.pop_front(); }
                h.push_back(msg);
            }
        }
        _ => {}
    }

    // Канал для исходящих сообщений
    let (tx, mut rx) = mpsc::channel::<ChatMessage>(64);

    // Таск записи (наши сообщения → ретранслятор)
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if send_packet_wr(&mut wr, &ChatPacket::Message(msg)).await.is_err() {
                debug!("Write to relay failed");
                break;
            }
        }
    });

    // Таск чтения (форварды от ретранслятора → наш UI)
    let chat_r = chat.clone();
    tokio::spawn(async move {
        loop {
            match read_packet_rd(&mut rd).await {
                Ok(ChatPacket::Message(msg)) => { chat_r.handle_incoming(msg).await; }
                Ok(_) => {}
                Err(e) => { debug!("Relay read error: {}", e); break; }
            }
        }
        // Сбрасываем outbox чтобы relay_manager переподключился
        *chat_r.inner.outbox_tx.lock().await = None;
    });

    Ok(tx)
}

// ─── Handle ──────────────────────────────────────────────────────────────────

pub struct ChatHandle {
    chat: PublicChat,
}

impl ChatHandle {
    pub async fn send(&self, text: String) -> anyhow::Result<()> { self.chat.send(text).await }
    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> { self.chat.subscribe() }
    pub async fn recent(&self, n: usize) -> Vec<ChatMessage> { self.chat.recent(n).await }
}

// ─── Сериализация ────────────────────────────────────────────────────────────

async fn send_packet<W: AsyncWriteExt + Unpin>(stream: &mut W, packet: &ChatPacket) -> anyhow::Result<()> {
    let json = serde_json::to_vec(packet)?;
    if json.len() > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large"); }
    stream.write_all(&(json.len() as u32).to_be_bytes()).await?;
    stream.write_all(&json).await?;
    Ok(())
}

async fn send_packet_wr(wr: &mut tokio::net::tcp::OwnedWriteHalf, packet: &ChatPacket) -> anyhow::Result<()> {
    let json = serde_json::to_vec(packet)?;
    if json.len() > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large"); }
    wr.write_all(&(json.len() as u32).to_be_bytes()).await?;
    wr.write_all(&json).await?;
    Ok(())
}

async fn read_packet<R: AsyncReadExt + Unpin>(stream: &mut R) -> anyhow::Result<ChatPacket> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large"); }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn read_packet_rd(rd: &mut tokio::net::tcp::OwnedReadHalf) -> anyhow::Result<ChatPacket> {
    let mut len_buf = [0u8; 4];
    rd.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large"); }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}