//! Общий чат — рассылка сообщений всем участникам сети.
//!
//! Схема: один узел — ретранслятор (hub), остальные подключаются к нему.
//! Ретранслятор — узел с лексически наименьшим ID среди всех известных.
//!
//! Протокол поверх TCP (length-prefixed JSON):
//!   Клиент → сервер: Hello, затем ProfileUpdate, затем Message* / Ping
//!   Сервер → клиент: History, затем все известные ProfileUpdate, затем форвард* / Ping

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_discovery::PeerList;

const MAX_MESSAGE_LEN: usize = 65536;
const BROADCAST_BUFFER: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEDUP_WINDOW: usize = 256;
/// Интервал между пингами для обнаружения "тихой" потери соединения.
const PING_INTERVAL_SECS: u64 = 15;

// ─── Протокол ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChatPacket {
    Message(ChatMessage),
    History { messages: Vec<ChatMessage> },
    /// hello_port = chat_port этого узла (нужен для матчинга stub-пиров на loopback)
    Hello { node_id: NodeId, name: String, chat_port: u16 },
    ProfileUpdate(PeerProfile),
    Ping,
    Pong,
    /// Неизвестный тип пакета — игнорируется для совместимости версий
    #[serde(other)]
    Unknown,
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
    /// Ключ подписи исходящих сообщений. Его публичная часть должна
    /// совпадать с `my_peer.id` (NodeId = hex(Ed25519 pubkey)).
    signing_kp:  Arc<SigningKeypair>,
    incoming_tx: broadcast::Sender<ChatMessage>,
    history:     Mutex<VecDeque<ChatMessage>>,
    seq_counter: Mutex<u64>,
    seen:        Mutex<HashSet<(String, u64)>>,
    seen_order:  Mutex<VecDeque<(String, u64)>>,
    /// None = мы ретранслятор; Some = ID ретранслятора
    relay:       RwLock<Option<NodeId>>,
    /// Канал для отправки пакетов через постоянное соединение с ретранслятором
    outbox_tx:   Mutex<Option<mpsc::Sender<ChatPacket>>>,
    /// Подключённые клиенты (когда мы ретранслятор): id → канал форварда
    clients:     Mutex<HashMap<NodeId, mpsc::Sender<ChatPacket>>>,
    /// Профили известных пиров
    profiles:    Mutex<HashMap<NodeId, PeerProfile>>,
    /// Наш собственный профиль (для рассылки при подключении)
    my_profile:  Mutex<Option<PeerProfile>>,
    /// Счётчик поколений соединения — чтобы старый read-task не затёр новый outbox
    conn_gen:    AtomicU64,
}

impl PublicChat {
    fn new(my_peer: PeerInfo, peer_list: PeerList, chat_port: u16, signing_kp: Arc<SigningKeypair>) -> Self {
        let (incoming_tx, _) = broadcast::channel(BROADCAST_BUFFER);
        PublicChat {
            inner: Arc::new(PublicChatInner {
                my_peer, peer_list, chat_port, signing_kp, incoming_tx,
                history:     Mutex::new(VecDeque::with_capacity(100)),
                seq_counter: Mutex::new(0),
                seen:        Mutex::new(HashSet::new()),
                seen_order:  Mutex::new(VecDeque::with_capacity(DEDUP_WINDOW)),
                relay:       RwLock::new(None),
                outbox_tx:   Mutex::new(None),
                clients:     Mutex::new(HashMap::new()),
                profiles:    Mutex::new(HashMap::new()),
                my_profile:  Mutex::new(None),
                conn_gen:    AtomicU64::new(0),
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

    pub async fn get_profiles(&self) -> Vec<PeerProfile> {
        self.inner.profiles.lock().await.values().cloned().collect()
    }

    /// Обновить собственный профиль и разослать всем подключённым.
    pub async fn set_profile(&self, profile: PeerProfile) {
        *self.inner.my_profile.lock().await = Some(profile.clone());
        let clients = self.inner.clients.lock().await;
        for tx in clients.values() {
            let _ = tx.try_send(ChatPacket::ProfileUpdate(profile.clone()));
        }
        let outbox = self.inner.outbox_tx.lock().await;
        if let Some(tx) = outbox.as_ref() {
            let _ = tx.try_send(ChatPacket::ProfileUpdate(profile));
        }
    }
}

// ─── Запуск ──────────────────────────────────────────────────────────────────

pub async fn start_public_chat(
    my_peer: PeerInfo,
    peer_list: PeerList,
    chat_port: u16,
    signing_kp: Arc<SigningKeypair>,
) -> anyhow::Result<ChatHandle> {
    let chat = PublicChat::new(my_peer, peer_list, chat_port, signing_kp);

    let c = chat.clone();
    tokio::spawn(async move {
        if let Err(e) = run_server(c).await { error!("Chat server: {}", e); }
    });

    let c = chat.clone();
    tokio::spawn(async move { relay_manager(c).await; });

    info!("Public chat started on port {}", chat_port);
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
    debug!("Incoming connection from {}", addr);

    // Шаг 1: читаем Hello
    let hello = match read_packet(&mut stream).await {
        Ok(p) => p,
        Err(e) => { warn!("No Hello from {}: {}", addr, e); return; }
    };
    let (node_id, peer_name, client_chat_port) = match hello {
        ChatPacket::Hello { node_id, name, chat_port } => (node_id, name, chat_port),
        _ => { warn!("Expected Hello from {}, got something else", addr); return; }
    };
    info!("Client connected: {} ({}) from {} chat_port={}", peer_name, node_id, addr, client_chat_port);

    // Обновляем peer_list: если это stub — апгрейдим, иначе обновляем имя/chat_port.
    {
        let peers = chat.inner.peer_list.all().await;
        let mut upgraded = false;
        for p in &peers {
            if p.ip == addr.ip() && p.id.as_str().starts_with("stub-") {
                // В режиме loopback уточняем stub по chat_port, иначе просто по IP
                if addr.ip().is_loopback() && p.chat_port != client_chat_port {
                    continue;
                }
                let mut real = p.clone();
                real.id        = node_id.clone();
                real.name      = peer_name.clone();
                real.chat_port = client_chat_port;
                chat.inner.peer_list.remove(&p.id).await;
                chat.inner.peer_list.upsert(real).await;
                info!("Stub peer upgraded to real ID: {} ({})", peer_name, node_id);
                upgraded = true;
                break;
            }
        }
        if !upgraded {
            // Не stub — просто обновляем имя и chat_port если изменились
            if let Some(mut p) = chat.inner.peer_list.get(&node_id).await {
                let mut changed = false;
                if !peer_name.is_empty() && p.name != peer_name {
                    p.name = peer_name.clone();
                    changed = true;
                }
                if p.chat_port != client_chat_port {
                    p.chat_port = client_chat_port;
                    changed = true;
                }
                if changed {
                    chat.inner.peer_list.upsert(p).await;
                    debug!("Updated peer info for {} ({})", peer_name, node_id);
                }
            }
        }
    }

    // Шаг 2: шлём историю
    let history: Vec<ChatMessage> = chat.inner.history.lock().await.iter().cloned().collect();
    if let Err(e) = send_packet(&mut stream, &ChatPacket::History { messages: history }).await {
        warn!("History send to {} failed: {}", addr, e); return;
    }

    // Шаг 3: шлём все известные профили (включая свой)
    {
        let profiles = chat.inner.profiles.lock().await;
        for profile in profiles.values() {
            let _ = send_packet(&mut stream, &ChatPacket::ProfileUpdate(profile.clone())).await;
        }
    }
    if let Some(my_p) = chat.inner.my_profile.lock().await.as_ref() {
        let _ = send_packet(&mut stream, &ChatPacket::ProfileUpdate(my_p.clone())).await;
    }

    // Шаг 4: регистрируем клиента
    let (fwd_tx, mut fwd_rx) = mpsc::channel::<ChatPacket>(64);
    chat.inner.clients.lock().await.insert(node_id.clone(), fwd_tx.clone());

    let (mut rd, mut wr) = stream.into_split();

    // Таск чтения: пакеты от клиента → обрабатываем
    let chat_r = chat.clone();
    let nid    = node_id.clone();
    let read_task = tokio::spawn(async move {
        loop {
            match read_packet_rd(&mut rd).await {
                Ok(ChatPacket::Message(msg)) => {
                    debug!("Message from client {}: {} chars", nid, msg.text.len());
                    chat_r.handle_incoming(msg).await;
                }
                Ok(ChatPacket::ProfileUpdate(prof)) => {
                    debug!("ProfileUpdate from client {}", nid);
                    chat_r.handle_profile_update(prof).await;
                }
                Ok(ChatPacket::Ping) => {
                    debug!("Ping from client {}", nid);
                    let _ = fwd_tx.try_send(ChatPacket::Pong);
                }
                Ok(ChatPacket::Pong) => {}
                Ok(_) => {}
                Err(e) => {
                    debug!("Client {} disconnected (read): {}", nid, e);
                    break;
                }
            }
        }
    });

    // Таск записи: форвардим пакеты клиенту
    let nid2 = node_id.clone();
    let write_task = tokio::spawn(async move {
        while let Some(pkt) = fwd_rx.recv().await {
            if send_packet_wr(&mut wr, &pkt).await.is_err() {
                debug!("Client {} disconnected (write)", nid2);
                break;
            }
        }
    });

    tokio::select! { _ = read_task => {}, _ = write_task => {} }

    chat.inner.clients.lock().await.remove(&node_id);
    info!("Client {} ({}) disconnected", peer_name, node_id);
}

// ─── Обработка входящих данных ────────────────────────────────────────────────

/// Канонические байты сообщения для подписи/проверки.
/// Привязывает отправителя, порядковый номер, время и текст.
fn message_signing_bytes(from: &NodeId, seq: u64, timestamp: i64, text: &str) -> Vec<u8> {
    format!("{}\n{}\n{}\n{}", from.as_str(), seq, timestamp, text).into_bytes()
}

impl PublicChat {
    /// Подписывает исходящее сообщение нашим Ed25519-ключом.
    fn sign_message(&self, msg: &mut ChatMessage) {
        let bytes = message_signing_bytes(&msg.from, msg.seq, msg.timestamp, &msg.text);
        match SignedMessage::sign(bytes, &self.inner.signing_kp) {
            Ok(signed) => msg.signature = Some(signed.signature),
            Err(e) => warn!("Failed to sign chat message: {:?}", e),
        }
    }

    /// Проверяет подпись входящего сообщения ключом, выведенным из `from`
    /// (NodeId == hex(Ed25519 pubkey)). Сообщения без подписи или с неверной
    /// подписью отбрасываются — это защита от подмены отправителя.
    fn verify_message(&self, msg: &ChatMessage) -> bool {
        let Some(signature) = msg.signature.clone() else {
            return false;
        };
        let signed = SignedMessage {
            payload:   message_signing_bytes(&msg.from, msg.seq, msg.timestamp, &msg.text),
            signature,
            signer:    msg.from.as_str().to_string(),
        };
        signed.verify().is_ok()
    }

    async fn handle_incoming(&self, msg: ChatMessage) {
        if !self.verify_message(&msg) {
            warn!("Отброшено сообщение с неверной/отсутствующей подписью от {}", msg.from);
            return;
        }

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

        {
            let mut h = self.inner.history.lock().await;
            if h.len() >= 100 { h.pop_front(); }
            h.push_back(msg.clone());
        }

        let _ = self.inner.incoming_tx.send(msg.clone());

        let clients = self.inner.clients.lock().await;
        for (id, tx) in clients.iter() {
            if *id != msg.from {
                let _ = tx.try_send(ChatPacket::Message(msg.clone()));
            }
        }
    }

    async fn handle_profile_update(&self, profile: PeerProfile) {
        self.inner.profiles.lock().await.insert(profile.node_id.clone(), profile.clone());

        // Обновляем имя в PeerInfo тоже — чтобы граф и чат показывали актуальное имя
        if !profile.name.is_empty() {
            if let Some(mut peer) = self.inner.peer_list.get(&profile.node_id).await {
                if peer.name != profile.name {
                    peer.name = profile.name.clone();
                    self.inner.peer_list.upsert(peer).await;
                    debug!("PeerInfo name updated via profile: {} -> {}", profile.node_id, profile.name);
                }
            }
        }

        let clients = self.inner.clients.lock().await;
        for (id, tx) in clients.iter() {
            if *id != profile.node_id {
                let _ = tx.try_send(ChatPacket::ProfileUpdate(profile.clone()));
            }
        }
    }

    pub async fn send(&self, text: String) -> anyhow::Result<()> {
        let seq = { let mut c = self.inner.seq_counter.lock().await; *c += 1; *c };

        // Используем имя из профиля если оно установлено
        let my_name = {
            let p = self.inner.my_profile.lock().await;
            p.as_ref()
                .map(|p| p.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| self.inner.my_peer.name.clone())
        };

        let mut msg = ChatMessage::new(self.inner.my_peer.id.clone(), my_name, text, seq);
        self.sign_message(&mut msg);

        let is_relay = self.inner.relay.read().await.is_none();
        if is_relay {
            debug!("Sending message as relay (seq={})", seq);
            self.handle_incoming(msg).await;
        } else {
            // Показываем своё сообщение локально сразу
            self.handle_incoming(msg.clone()).await;
            let outbox = self.inner.outbox_tx.lock().await;
            if let Some(tx) = outbox.as_ref() {
                tx.send(ChatPacket::Message(msg)).await
                    .map_err(|_| anyhow::anyhow!("Relay connection lost"))?;
                debug!("Message forwarded to relay (seq={})", seq);
            } else {
                warn!("Not connected to relay yet — message shown locally only (seq={})", seq);
            }
        }
        Ok(())
    }
}

// ─── Менеджер соединения с ретранслятором ────────────────────────────────────

async fn relay_manager(chat: PublicChat) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    interval.tick().await; // поглощаем немедленный первый тик
    let changes = chat.inner.peer_list.subscribe_changes();

    loop {
        relay_pass(&chat).await;

        // Реагируем сразу на изменение состава пиров (апгрейд stub→real,
        // подключение/отключение узла), а не дожидаясь следующего тика —
        // это убирает ~3-секундное окно релей-флаппинга. Между изменениями
        // работает периодическая проверка живости соединения.
        let notified = changes.notified();
        tokio::select! {
            _ = interval.tick() => {}
            _ = notified => {
                debug!("relay_manager: состав пиров изменился — немедленный перевыбор");
            }
        }
    }
}

/// Один проход: выбирает ретранслятор и при необходимости (пере)подключается.
async fn relay_pass(chat: &PublicChat) {
    let peers = chat.inner.peer_list.all().await;
    if peers.is_empty() {
        return;
    }

    let my_id = chat.inner.my_peer.id.as_str().to_string();
    let real_peers: Vec<_> = peers.iter()
        .filter(|p| p.id.as_str().len() == 64)
        .collect();

    let elected = if real_peers.is_empty() {
        peers[0].id.as_str().to_string()
    } else {
        let mut candidates: Vec<String> = real_peers.iter()
            .map(|p| p.id.as_str().to_string())
            .collect();
        candidates.push(my_id.clone());
        candidates.sort();
        candidates.into_iter().next().unwrap()
    };

    if elected == my_id {
        let was_client = chat.inner.relay.read().await.is_some();
        if was_client {
            info!("I am now the relay (transitioned from client)");
            *chat.inner.relay.write().await = None;
            *chat.inner.outbox_tx.lock().await = None;
        } else {
            debug!("Relay check: I am the relay, {} client(s) connected",
                chat.inner.clients.lock().await.len());
        }
    } else {
        let relay_id  = NodeId(elected.clone());
        let current   = chat.inner.relay.read().await.clone();

        let peer = match peers.iter().find(|p| p.id.as_str() == elected) {
            Some(p) => p.clone(),
            None    => {
                warn!("Elected relay {} not found in peer_list", &elected[..8.min(elected.len())]);
                return;
            }
        };
        let relay_addr = peer.chat_addr();

        if current.as_ref() == Some(&relay_id) {
            let alive = chat.inner.outbox_tx.lock().await.as_ref()
                .map(|tx| !tx.is_closed())
                .unwrap_or(false);
            if alive {
                debug!("Relay connection alive: {} ({})", &elected[..8.min(elected.len())], relay_addr);
                return;
            }
            info!("Relay connection lost — reconnecting to {} ({})", &elected[..8.min(elected.len())], relay_addr);
        } else {
            info!("Elected new relay: id={}... addr={}", &elected[..8.min(elected.len())], relay_addr);
        }

        match connect_to_relay(chat, peer).await {
            Ok(tx) => {
                let cgen = chat.inner.conn_gen.fetch_add(1, Ordering::SeqCst) + 1;
                *chat.inner.relay.write().await    = Some(relay_id);
                *chat.inner.outbox_tx.lock().await = Some(tx.clone());
                info!("Connected to relay {} ({}) cgen={}", &elected[..8.min(elected.len())], relay_addr, cgen);

                // Пинг-задача: периодически пишем в канал чтобы обнаружить обрыв
                let chat_ping = chat.clone();
                tokio::spawn(async move {
                    let mut ivl = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
                    ivl.tick().await; // пропускаем первый немедленный тик
                    loop {
                        ivl.tick().await;
                        if tx.send(ChatPacket::Ping).await.is_err() {
                            debug!("Ping failed (cgen={}) — relay connection dead", cgen);
                            // Очищаем outbox только если мы всё ещё актуальное поколение
                            let cur_gen = chat_ping.inner.conn_gen.load(Ordering::SeqCst);
                            if cur_gen == cgen {
                                *chat_ping.inner.outbox_tx.lock().await = None;
                            }
                            break;
                        }
                        debug!("Ping sent to relay (cgen={})", cgen);
                    }
                });
            }
            Err(e) => {
                warn!("Failed to connect to relay {} ({}): {}", &elected[..8.min(elected.len())], relay_addr, e);
            }
        }
    }
}

async fn connect_to_relay(chat: &PublicChat, peer: PeerInfo) -> anyhow::Result<mpsc::Sender<ChatPacket>> {
    let addr = peer.chat_addr();
    info!("TCP connect → {}", addr);
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await??;
    let (mut rd, mut wr) = stream.into_split();

    // Hello — используем актуальное имя из профиля (не PeerInfo.name который может устареть)
    let hello_name = {
        let p = chat.inner.my_profile.lock().await;
        p.as_ref()
            .map(|p| p.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| chat.inner.my_peer.name.clone())
    };
    send_packet_wr(&mut wr, &ChatPacket::Hello {
        node_id:   chat.inner.my_peer.id.clone(),
        name:      hello_name,
        chat_port: chat.inner.chat_port,
    }).await?;

    // Читаем History (первый пакет от ретранслятора)
    match read_packet_rd(&mut rd).await? {
        ChatPacket::History { messages } => {
            let mut h = chat.inner.history.lock().await;
            for msg in messages {
                if h.len() >= 100 { h.pop_front(); }
                h.push_back(msg);
            }
            debug!("Received history from relay ({} messages)", h.len());
        }
        other => {
            warn!("Expected History from relay, got {:?}", other);
        }
    }

    // Отправляем свой профиль ретранслятору
    if let Some(profile) = chat.inner.my_profile.lock().await.as_ref() {
        send_packet_wr(&mut wr, &ChatPacket::ProfileUpdate(profile.clone())).await?;
    }

    let (tx, mut rx) = mpsc::channel::<ChatPacket>(64);

    // Таск записи (наши пакеты → ретранслятор)
    tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            if send_packet_wr(&mut wr, &pkt).await.is_err() {
                debug!("Write to relay failed");
                break;
            }
        }
        debug!("Relay write task ended");
    });

    // Таск чтения (форварды от ретранслятора → наш UI + хранилище профилей)
    // ВАЖНО: не трогаем outbox_tx здесь, чтобы не затереть новое соединение при гонке.
    // Обнаружение обрыва выполняется ping-таском (через is_closed) и relay_manager.
    let chat_r = chat.clone();
    tokio::spawn(async move {
        loop {
            match read_packet_rd(&mut rd).await {
                Ok(ChatPacket::Message(msg)) => {
                    debug!("Message from relay: {} chars", msg.text.len());
                    chat_r.handle_incoming(msg).await;
                }
                Ok(ChatPacket::ProfileUpdate(prof)) => {
                    debug!("ProfileUpdate from relay: {}", prof.node_id);
                    chat_r.handle_profile_update(prof).await;
                }
                Ok(ChatPacket::Ping) => {
                    // Ретранслятор пингует нас — отвечаем Pong через outbox
                    let outbox = chat_r.inner.outbox_tx.lock().await;
                    if let Some(tx) = outbox.as_ref() {
                        let _ = tx.try_send(ChatPacket::Pong);
                    }
                }
                Ok(ChatPacket::Pong) => {}
                Ok(_) => {}
                Err(e) => {
                    debug!("Relay read error: {}", e);
                    break;
                }
            }
        }
        debug!("Relay read task ended");
    });

    Ok(tx)
}

// ─── Handle ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ChatHandle {
    chat: PublicChat,
}

impl ChatHandle {
    pub async fn send(&self, text: String) -> anyhow::Result<()> { self.chat.send(text).await }
    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> { self.chat.subscribe() }
    pub async fn recent(&self, n: usize) -> Vec<ChatMessage> { self.chat.recent(n).await }
    pub async fn set_profile(&self, profile: PeerProfile) { self.chat.set_profile(profile).await }
    pub async fn get_profiles(&self) -> Vec<PeerProfile> { self.chat.get_profiles().await }
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
    if len > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large: {} bytes", len); }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn read_packet_rd(rd: &mut tokio::net::tcp::OwnedReadHalf) -> anyhow::Result<ChatPacket> {
    let mut len_buf = [0u8; 4];
    rd.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large: {} bytes", len); }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::sync::broadcast;
    use tokio::time::timeout;
    use void_core::peer::Service;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn node_id(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&[seed; 32])
    }

    /// Детерминированный ключ подписи + соответствующий ему NodeId.
    fn keypair(seed: u8) -> (Arc<SigningKeypair>, NodeId) {
        let kp = Arc::new(SigningKeypair::from_seed(&[seed; 32]).unwrap());
        let id = NodeId::from_public_key_bytes(&kp.public_bytes());
        (kp, id)
    }

    fn test_peer(name: &str, id: NodeId, chat_port: u16) -> PeerInfo {
        PeerInfo {
            id,
            name:      name.to_string(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      chat_port.wrapping_sub(2),
            chat_port,
            services:  vec![Service::Chat],
            last_seen: 0,
        }
    }

    /// Ждёт в broadcast-приёмнике сообщение с заданным текстом (пропуская прочие).
    async fn wait_for_text(rx: &mut broadcast::Receiver<ChatMessage>, text: &str, secs: u64) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { return false; }
            match timeout(remaining, rx.recv()).await {
                Ok(Ok(m)) if m.text == text => return true,
                Ok(Ok(_)) => continue,             // другое сообщение — пропускаем
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                _ => return false,
            }
        }
    }

    /// Сериализация ChatPacket: roundtrip Message + неизвестный тип → Unknown.
    #[test]
    fn chat_packet_serde_roundtrip() {
        let msg = ChatMessage::new(node_id(1), "alice".into(), "привет".into(), 42);
        let json = serde_json::to_string(&ChatPacket::Message(msg)).unwrap();
        let back: ChatPacket = serde_json::from_str(&json).unwrap();
        match back {
            ChatPacket::Message(m) => {
                assert_eq!(m.text, "привет");
                assert_eq!(m.seq, 42);
                assert_eq!(m.from_name, "alice");
            }
            other => panic!("ожидался Message, получено {other:?}"),
        }

        let unknown: ChatPacket = serde_json::from_str(r#"{"kind":"future_packet"}"#).unwrap();
        assert!(matches!(unknown, ChatPacket::Unknown));
    }

    /// Подпись исходящего сообщения проверяется получателем; подмена любого
    /// поля или отправителя, как и отсутствие подписи, отклоняется.
    #[tokio::test]
    async fn signature_roundtrip_and_tamper_detection() {
        let (kp, id) = keypair(5);
        let peer = test_peer("x", id.clone(), 1);
        let chat = PublicChat::new(peer, PeerList::new(), 1, kp);

        let mut msg = ChatMessage::new(id.clone(), "x".into(), "secret".into(), 1);
        chat.sign_message(&mut msg);
        assert!(msg.signature.is_some(), "сообщение должно быть подписано");
        assert!(chat.verify_message(&msg), "валидная подпись должна проходить");

        // Подмена текста инвалидирует подпись.
        let mut tampered = msg.clone();
        tampered.text = "evil".into();
        assert!(!chat.verify_message(&tampered));

        // Отсутствие подписи → отклоняется.
        let mut unsigned = msg.clone();
        unsigned.signature = None;
        assert!(!chat.verify_message(&unsigned));

        // Подмена отправителя (чужой NodeId) → подпись не сходится с ключом.
        let (_other_kp, other_id) = keypair(9);
        let mut spoofed = msg.clone();
        spoofed.from = other_id;
        assert!(!chat.verify_message(&spoofed));
    }

    /// Два узла: меньший по ID становится релеем, второй — клиентом.
    /// Сообщения подписываются отправителем и проходят проверку у получателя
    /// в обе стороны (роли определяются реальными ключами — тест к ним нейтрален).
    #[tokio::test]
    async fn relay_election_and_two_way_delivery() {
        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id, a_port);
        let b_peer = test_peer("bob", b_id, b_port);

        // Каждый узел заранее знает другого (на loopback mDNS/UDP не работают).
        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp).await.unwrap();

        let mut alice_rx = alice.subscribe();
        let mut bob_rx = bob.subscribe();

        // Клиент → релей. Повторяем отправку, пока релей-соединение не установится
        // (relay_manager опрашивает список пиров с интервалом, первое соединение
        // может прийтись на момент до биндинга сервера релея).
        let mut delivered = false;
        for _ in 0..30 {
            bob.send("from_bob".into()).await.unwrap();
            if wait_for_text(&mut alice_rx, "from_bob", 1).await {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "релей (Alice) не получил сообщение клиента (Bob)");

        // Релей → клиент.
        alice.send("from_alice".into()).await.unwrap();
        assert!(
            wait_for_text(&mut bob_rx, "from_alice", 5).await,
            "клиент (Bob) не получил сообщение релея (Alice)"
        );
    }

    /// Три узла: сообщение от одного доходит до обоих остальных через релей
    /// (проверяет форвардинг релея клиентам при N>2). Тест нейтрален к тому,
    /// какой именно узел стал релеем.
    #[tokio::test]
    async fn three_nodes_broadcast_via_relay() {
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let (c_kp, c_id) = keypair(3);
        let a_port = free_port();
        let b_port = free_port();
        let c_port = free_port();
        let a_peer = test_peer("a", a_id, a_port);
        let b_peer = test_peer("b", b_id, b_port);
        let c_peer = test_peer("c", c_id, c_port);

        // Каждый узел заранее знает двух других.
        let a_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        a_pl.upsert(c_peer.clone()).await;
        let b_pl = PeerList::new();
        b_pl.upsert(a_peer.clone()).await;
        b_pl.upsert(c_peer.clone()).await;
        let c_pl = PeerList::new();
        c_pl.upsert(a_peer.clone()).await;
        c_pl.upsert(b_peer.clone()).await;

        let a = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp).await.unwrap();
        let b = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp).await.unwrap();
        let c = start_public_chat(c_peer.clone(), c_pl, c_port, c_kp).await.unwrap();

        let mut b_rx = b.subscribe();
        let mut c_rx = c.subscribe();

        // Отправляем от A, пока сообщение не дойдёт и до B, и до C
        // (с запасом на установку клиентских соединений с релеем).
        let mut got_b = false;
        let mut got_c = false;
        for _ in 0..40 {
            a.send("from_a".into()).await.unwrap();
            if !got_b { got_b = wait_for_text(&mut b_rx, "from_a", 1).await; }
            if !got_c { got_c = wait_for_text(&mut c_rx, "from_a", 1).await; }
            if got_b && got_c { break; }
        }
        assert!(got_b, "узел B не получил сообщение от A");
        assert!(got_c, "узел C не получил сообщение от A");
    }
}
