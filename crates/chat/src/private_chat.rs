//! Личный P2P чат — прямые зашифрованные TCP-соединения между узлами.
//!
//! Порт: base_port + 3  (например 7703 при base 7700)
//! Протокол: length-prefixed JSON поверх TCP
//! Шифрование: X25519 DH + BLAKE3 KDF + XChaCha20-Poly1305

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener, TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use void_core::identity::NodeId;
use void_core::peer::PeerInfo;
use void_crypto::encrypt::EncryptedMessage;
use void_crypto::keys::EncryptionKeypair;

const MAX_PKT: usize = 65_536;
const BCAST_BUF: usize = 128;

// ── Протокол ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DmPacket {
    Hello {
        node_id:    NodeId,
        name:       String,
        /// X25519 публичный ключ отправителя (hex) для DH key exchange
        enc_pubkey: String,
    },
    Message {
        message_id:     String,
        /// JSON-сериализованный EncryptedMessage
        encrypted_blob: String,
        timestamp:      i64,
    },
    Ping,
    Pong,
    #[serde(other)]
    Unknown,
}

// ── Публичные типы ────────────────────────────────────────────────────────────

/// Входящее расшифрованное личное сообщение, доставляемое в GUI.
#[derive(Debug, Clone)]
pub struct IncomingDm {
    pub from:           NodeId,
    pub from_name:      String,
    pub message_id:     String,
    pub plaintext:      String,
    pub timestamp:      i64,
    /// Оригинальный зашифрованный blob (для хранения на диске).
    pub encrypted_blob: String,
}

/// Команда из GUI: отправить личное сообщение пиру.
#[derive(Clone)]
pub struct DmSendCmd {
    pub to:               NodeId,
    /// Адрес DM-сервера пира: "ip:dm_port"
    pub to_dm_addr:       String,
    /// X25519 публичный ключ получателя (для шифрования)
    pub their_enc_pubkey: [u8; 32],
    pub plaintext:        String,
    pub message_id:       String,
}

// ── Внутреннее состояние ──────────────────────────────────────────────────────

/// Пакет на отправку + одноразовый канал подтверждения фактической записи в
/// сокет. `true` = записано, `false`/закрытие = соединение мертво (нужен fallback).
type FwdItem = (DmPacket, oneshot::Sender<bool>);

struct PeerConn {
    fwd_tx: mpsc::Sender<FwdItem>,
}

struct Inner {
    my_peer:       PeerInfo,
    my_enc_kp:     Arc<EncryptionKeypair>,
    incoming_tx:   broadcast::Sender<IncomingDm>,
    /// Активные соединения (входящие + исходящие)
    connections:   Mutex<HashMap<NodeId, PeerConn>>,
    /// Кэш enc_pubkey пиров, полученных при handshake
    known_pubkeys: Mutex<HashMap<NodeId, ([u8; 32], String)>>,
}

// ── Handle ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PrivateChatHandle {
    inner: Arc<Inner>,
}

/// Запускает DM-сервер и возвращает хэндл для работы с личными сообщениями.
pub async fn start_private_chat(
    my_peer:   PeerInfo,
    my_enc_kp: Arc<EncryptionKeypair>,
    dm_port:   u16,
) -> anyhow::Result<PrivateChatHandle> {
    let (incoming_tx, _) = broadcast::channel(BCAST_BUF);
    let handle = PrivateChatHandle {
        inner: Arc::new(Inner {
            my_peer,
            my_enc_kp,
            incoming_tx,
            connections:   Mutex::new(HashMap::new()),
            known_pubkeys: Mutex::new(HashMap::new()),
        }),
    };

    let h = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = run_dm_server(h, dm_port).await {
            warn!("DM server error: {}", e);
        }
    });

    Ok(handle)
}

// ── TCP-сервер (принимаем входящие DM) ────────────────────────────────────────

async fn run_dm_server(handle: PrivateChatHandle, port: u16) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!("DM server listening on {}", addr);
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let h = handle.clone();
                tokio::spawn(async move { accept_dm_conn(stream, h).await; });
            }
            Err(e) => warn!("DM accept error: {}", e),
        }
    }
}

async fn accept_dm_conn(stream: TcpStream, handle: PrivateChatHandle) {
    let addr = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<relay>".to_string());
    debug!("DM incoming from {}", addr);
    let (mut rd, mut wr) = stream.into_split();

    // Читаем Hello от клиента
    let hello = match read_dm_pkt(&mut rd).await {
        Ok(p) => p,
        Err(e) => { warn!("DM: no Hello from {}: {}", addr, e); return; }
    };
    let (peer_id, peer_name, their_enc_pub) = match hello {
        DmPacket::Hello { node_id, name, enc_pubkey } => {
            let bytes: [u8; 32] = match hex::decode(&enc_pubkey)
                .ok().and_then(|b| b.try_into().ok())
            {
                Some(b) => b,
                None => { warn!("DM: invalid enc_pubkey from {}", addr); return; }
            };
            (node_id, name, bytes)
        }
        _ => { warn!("DM: expected Hello from {}", addr); return; }
    };

    info!("DM accepted: {} ({}) from {}", peer_name, peer_id, addr);

    // Отвечаем своим Hello
    if let Err(e) = write_dm_pkt(&mut wr, &DmPacket::Hello {
        node_id:    handle.inner.my_peer.id.clone(),
        name:       handle.inner.my_peer.name.clone(),
        enc_pubkey: hex::encode(handle.inner.my_enc_kp.public_bytes()),
    }).await {
        warn!("DM: hello reply failed: {}", e);
        return;
    }

    // Кэшируем enc_pubkey
    handle.inner.known_pubkeys.lock().await
        .insert(peer_id.clone(), (their_enc_pub, peer_name.clone()));

    let (fwd_tx, fwd_rx) = mpsc::channel::<FwdItem>(64);
    handle.inner.connections.lock().await
        .insert(peer_id.clone(), PeerConn { fwd_tx });

    run_conn_tasks(
        Arc::clone(&handle.inner),
        peer_id.clone(), peer_name, their_enc_pub,
        rd, wr, fwd_rx,
    ).await;

    // cleanup после завершения run_conn_tasks
    handle.inner.connections.lock().await.remove(&peer_id);
}

// ── API хэндла ────────────────────────────────────────────────────────────────

impl PrivateChatHandle {
    /// Подписаться на входящие расшифрованные DM.
    pub fn subscribe(&self) -> broadcast::Receiver<IncomingDm> {
        self.inner.incoming_tx.subscribe()
    }

    /// Обрабатывает уже установленный поток как ВХОДЯЩЕЕ DM-соединение.
    /// Используется для туннелей через relay (symmetric NAT): поток приходит не
    /// из `accept()`, а из [`void-discovery`] relay-клиента, но логика та же.
    pub async fn accept_stream(&self, stream: TcpStream) {
        accept_dm_conn(stream, self.clone()).await;
    }

    /// Получить кэшированный enc_pubkey пира (если он подключался ранее).
    pub async fn known_pubkey(&self, id: &NodeId) -> Option<[u8; 32]> {
        self.inner.known_pubkeys.lock().await.get(id).map(|(k, _)| *k)
    }

    /// Зашифровать и отправить личное сообщение пиру.
    pub async fn send_dm(&self, cmd: DmSendCmd) -> anyhow::Result<()> {
        use anyhow::anyhow;

        // Шифруем для получателя
        let enc = EncryptedMessage::encrypt(
            cmd.plaintext.as_bytes(),
            &cmd.their_enc_pubkey,
            &self.inner.my_enc_kp,
        ).map_err(|e| anyhow!("DM encrypt: {:?}", e))?;

        let blob = serde_json::to_string(&enc)?;

        let pkt = DmPacket::Message {
            message_id:     cmd.message_id,
            encrypted_blob: blob,
            timestamp:      chrono::Utc::now().timestamp(),
        };

        // Пробуем существующее соединение (в т.ч. ранее поднятый relay-туннель).
        // Берём отправитель под локом и СРАЗУ освобождаем лок: держать его на время
        // await нельзя — cleanup соединения (`run_conn_tasks`) тоже берёт
        // `connections.lock()`, иначе возможен дедлок.
        let existing = {
            let conns = self.inner.connections.lock().await;
            conns.get(&cmd.to).map(|c| c.fwd_tx.clone())
        };
        if let Some(fwd_tx) = existing {
            let (ack_tx, ack_rx) = oneshot::channel();
            // Ok из send() лишь подтверждает постановку в очередь; доставку
            // подтверждает ack из write-задачи (фактическая запись в сокет).
            if fwd_tx.send((pkt.clone(), ack_tx)).await.is_ok() {
                if let Ok(true) = ack_rx.await {
                    return Ok(());
                }
            }
            // Соединение мертво (очередь закрыта или запись не удалась) — выбрасываем
            // его из кэша и пробуем заново прямой дозвон, а выше по стеку — relay.
            self.inner.connections.lock().await.remove(&cmd.to);
        }

        // Устанавливаем новое исходящее соединение (прямое)
        let stream = dial(&cmd.to_dm_addr).await?;
        self.establish_outbound(stream, cmd.to, &cmd.their_enc_pubkey, pkt).await
    }

    /// Отправляет DM по УЖЕ установленному потоку (например, relay-туннелю), когда
    /// прямое соединение невозможно (symmetric NAT). Шифрует и проводит тот же
    /// handshake, что и прямой дозвон, но без `TcpStream::connect`.
    pub async fn send_dm_over_stream(
        &self,
        cmd:    DmSendCmd,
        stream: TcpStream,
    ) -> anyhow::Result<()> {
        use anyhow::anyhow;

        let enc = EncryptedMessage::encrypt(
            cmd.plaintext.as_bytes(),
            &cmd.their_enc_pubkey,
            &self.inner.my_enc_kp,
        ).map_err(|e| anyhow!("DM encrypt: {:?}", e))?;
        let blob = serde_json::to_string(&enc)?;
        let pkt = DmPacket::Message {
            message_id:     cmd.message_id,
            encrypted_blob: blob,
            timestamp:      chrono::Utc::now().timestamp(),
        };

        self.establish_outbound(stream, cmd.to, &cmd.their_enc_pubkey, pkt).await
    }

    /// Общая часть исходящего соединения: handshake (наш/их Hello), кэширование
    /// enc_pubkey, отправка первого пакета и запуск задач соединения. Работает
    /// поверх любого подключённого потока — прямого TCP или relay-туннеля.
    async fn establish_outbound(
        &self,
        stream:        TcpStream,
        to:            NodeId,
        their_enc_pub: &[u8; 32],
        first_pkt:     DmPacket,
    ) -> anyhow::Result<()> {
        let (mut rd, mut wr) = stream.into_split();

        // Наш Hello
        write_dm_pkt(&mut wr, &DmPacket::Hello {
            node_id:    self.inner.my_peer.id.clone(),
            name:       self.inner.my_peer.name.clone(),
            enc_pubkey: hex::encode(self.inner.my_enc_kp.public_bytes()),
        }).await?;

        // Их Hello
        let (peer_name, confirmed_pub) = match read_dm_pkt(&mut rd).await? {
            DmPacket::Hello { name, enc_pubkey, .. } => {
                let bytes: [u8; 32] = hex::decode(&enc_pubkey)
                    .ok().and_then(|b| b.try_into().ok())
                    .unwrap_or(*their_enc_pub);
                (name, bytes)
            }
            _ => (String::new(), *their_enc_pub),
        };

        // Кэшируем
        self.inner.known_pubkeys.lock().await
            .insert(to.clone(), (confirmed_pub, peer_name.clone()));

        // Отправляем первый пакет
        write_dm_pkt(&mut wr, &first_pkt).await?;

        let (fwd_tx, fwd_rx) = mpsc::channel::<FwdItem>(64);
        self.inner.connections.lock().await
            .insert(to.clone(), PeerConn { fwd_tx });

        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            run_conn_tasks(inner, to.clone(), peer_name, confirmed_pub, rd, wr, fwd_rx).await;
            // cleanup делается внутри run_conn_tasks
        });

        Ok(())
    }
}

/// Прямой дозвон до DM-сервера пира (`ip:dm_port`).
async fn dial(addr: &str) -> anyhow::Result<TcpStream> {
    match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
        Err(_) => {
            warn!("DM: connect timeout to {}", addr);
            anyhow::bail!("DM connect timeout to {}", addr);
        }
        Ok(Err(e)) => {
            warn!("DM: connect to {} failed: {}", addr, e);
            anyhow::bail!("DM connect to {} failed: {}", addr, e);
        }
        Ok(Ok(s)) => Ok(s),
    }
}

// ── Жизненный цикл соединения ─────────────────────────────────────────────────

async fn run_conn_tasks(
    inner:         Arc<Inner>,
    peer_id:       NodeId,
    peer_name:     String,
    their_enc_pub: [u8; 32],
    mut rd:        OwnedReadHalf,
    mut wr:        OwnedWriteHalf,
    mut fwd_rx:    mpsc::Receiver<FwdItem>,
) {
    let inner_r = Arc::clone(&inner);
    let pid_r   = peer_id.clone();
    let pname_r = peer_name.clone();

    let read_task = tokio::spawn(async move {
        loop {
            match read_dm_pkt(&mut rd).await {
                Ok(DmPacket::Message { message_id, encrypted_blob, timestamp }) => {
                    on_dm_message(&inner_r, &pid_r, &pname_r, message_id, encrypted_blob, timestamp).await;
                }
                Ok(DmPacket::Ping) | Ok(DmPacket::Pong)
                | Ok(DmPacket::Hello { .. }) | Ok(DmPacket::Unknown) => {}
                Err(e) => {
                    debug!("DM read from {}: {}", pid_r, e);
                    break;
                }
            }
        }
    });

    let _their_enc_pub = their_enc_pub; // подавляем предупреждение

    let write_task = tokio::spawn(async move {
        while let Some((pkt, ack)) = fwd_rx.recv().await {
            // Подтверждаем отправителю РЕЗУЛЬТАТ фактической записи в сокет, а не
            // только постановки в очередь — иначе разорванное соединение тихо
            // съедало бы DM, не давая сработать fallback через relay.
            let ok = write_dm_pkt(&mut wr, &pkt).await.is_ok();
            let _ = ack.send(ok);
            if !ok {
                break;
            }
        }
    });

    tokio::select! {
        _ = read_task  => {}
        _ = write_task => {}
    }

    inner.connections.lock().await.remove(&peer_id);
    debug!("DM connection closed: {}", peer_id);
}

async fn on_dm_message(
    inner:          &Inner,
    from:           &NodeId,
    from_name:      &str,
    message_id:     String,
    encrypted_blob: String,
    timestamp:      i64,
) {
    let enc: EncryptedMessage = match serde_json::from_str(&encrypted_blob) {
        Ok(e) => e,
        Err(e) => { warn!("DM: bad blob from {}: {}", from, e); return; }
    };
    let plaintext_bytes = match enc.decrypt(&inner.my_enc_kp) {
        Ok(b) => b,
        Err(e) => { warn!("DM: decrypt from {} failed: {:?}", from, e); return; }
    };
    let plaintext = String::from_utf8_lossy(&plaintext_bytes).to_string();

    let dm = IncomingDm {
        from:           from.clone(),
        from_name:      from_name.to_string(),
        message_id,
        plaintext,
        timestamp,
        encrypted_blob,
    };
    let _ = inner.incoming_tx.send(dm);
}

// ── I/O хелперы ───────────────────────────────────────────────────────────────

async fn write_dm_pkt(wr: &mut OwnedWriteHalf, pkt: &DmPacket) -> anyhow::Result<()> {
    let json = serde_json::to_vec(pkt)?;
    if json.len() > MAX_PKT { anyhow::bail!("DM packet too large"); }
    wr.write_all(&(json.len() as u32).to_be_bytes()).await?;
    wr.write_all(&json).await?;
    Ok(())
}

async fn read_dm_pkt(rd: &mut OwnedReadHalf) -> anyhow::Result<DmPacket> {
    let mut len_buf = [0u8; 4];
    rd.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PKT { anyhow::bail!("DM packet too large: {}", len); }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

// ── Тесты ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::time::{sleep, timeout};
    use void_core::peer::Service;

    /// Берёт свободный TCP-порт на loopback (закрывая временный листенер).
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

    fn test_peer(name: &str, id_seed: u8, dm_port: u16) -> PeerInfo {
        PeerInfo {
            id:        node_id(id_seed),
            name:      name.to_string(),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            // base_port/chat_port не используются DM-сервером (он слушает dm_port),
            // но заполняем правдоподобно: dm_port = base + 3
            port:      dm_port.wrapping_sub(3),
            chat_port: dm_port.wrapping_sub(1),
            services:  vec![Service::Chat],
            last_seen: 0,
        }
    }

    /// Запускает узел DM-чата на заданном порту.
    async fn start_node(
        name: &str,
        id_seed: u8,
        dm_port: u16,
    ) -> (PrivateChatHandle, Arc<EncryptionKeypair>, NodeId) {
        let kp = Arc::new(EncryptionKeypair::generate());
        let peer = test_peer(name, id_seed, dm_port);
        let id = peer.id.clone();
        let handle = start_private_chat(peer, Arc::clone(&kp), dm_port)
            .await
            .expect("start_private_chat");
        (handle, kp, id)
    }

    /// Сквозной сценарий: Alice шифрует и отправляет DM → Bob получает расшифрованный текст.
    #[tokio::test]
    async fn dm_delivered_and_decrypted() {
        let a_port = free_port();
        let b_port = free_port();
        let (alice, _a_kp, a_id) = start_node("alice", 1, a_port).await;
        let (bob, b_kp, b_id) = start_node("bob", 2, b_port).await;

        let mut bob_rx = bob.subscribe();

        // Ждём, пока DM-сервер Боба забиндится.
        sleep(Duration::from_millis(300)).await;

        alice
            .send_dm(DmSendCmd {
                to:               b_id.clone(),
                to_dm_addr:       format!("127.0.0.1:{}", b_port),
                their_enc_pubkey: b_kp.public_bytes(),
                plaintext:        "привет, Боб 🔒".into(),
                message_id:       "m1".into(),
            })
            .await
            .expect("send_dm");

        let dm = timeout(Duration::from_secs(3), bob_rx.recv())
            .await
            .expect("таймаут ожидания DM")
            .expect("broadcast закрыт");

        assert_eq!(dm.plaintext, "привет, Боб 🔒");
        assert_eq!(dm.from, a_id, "from должен быть NodeId Алисы");
        assert_eq!(dm.message_id, "m1");
    }

    /// Двунаправленный обмен: Bob отвечает Alice, используя enc_pubkey,
    /// закэшированный во время handshake (проверяет known_pubkey + переиспользование).
    #[tokio::test]
    async fn dm_bidirectional_reply() {
        let a_port = free_port();
        let b_port = free_port();
        let (alice, a_kp, a_id) = start_node("alice", 1, a_port).await;
        let (bob, b_kp, b_id) = start_node("bob", 2, b_port).await;

        let mut alice_rx = alice.subscribe();
        let mut bob_rx = bob.subscribe();
        sleep(Duration::from_millis(300)).await;

        // Alice → Bob
        alice
            .send_dm(DmSendCmd {
                to:               b_id.clone(),
                to_dm_addr:       format!("127.0.0.1:{}", b_port),
                their_enc_pubkey: b_kp.public_bytes(),
                plaintext:        "ping".into(),
                message_id:       "m1".into(),
            })
            .await
            .expect("send ping");

        let ping = timeout(Duration::from_secs(3), bob_rx.recv())
            .await
            .expect("таймаут ping")
            .unwrap();
        assert_eq!(ping.plaintext, "ping");

        // Bob должен был закэшировать enc_pubkey Алисы во время handshake.
        let a_pub = bob
            .known_pubkey(&a_id)
            .await
            .expect("enc_pubkey Алисы закэширован у Боба");
        assert_eq!(a_pub, a_kp.public_bytes());

        // Bob → Alice (ответ)
        bob.send_dm(DmSendCmd {
            to:               a_id.clone(),
            to_dm_addr:       format!("127.0.0.1:{}", a_port),
            their_enc_pubkey: a_pub,
            plaintext:        "pong".into(),
            message_id:       "m2".into(),
        })
        .await
        .expect("send pong");

        let pong = timeout(Duration::from_secs(3), alice_rx.recv())
            .await
            .expect("таймаут pong")
            .unwrap();
        assert_eq!(pong.plaintext, "pong");
        assert_eq!(pong.from, b_id);
    }

    /// Несколько сообщений подряд по одному соединению доставляются по порядку.
    #[tokio::test]
    async fn dm_multiple_messages_reuse_connection() {
        let a_port = free_port();
        let b_port = free_port();
        let (alice, _a_kp, _a_id) = start_node("alice", 1, a_port).await;
        let (bob, b_kp, b_id) = start_node("bob", 2, b_port).await;

        let mut bob_rx = bob.subscribe();
        sleep(Duration::from_millis(300)).await;

        for i in 0..5 {
            alice
                .send_dm(DmSendCmd {
                    to:               b_id.clone(),
                    to_dm_addr:       format!("127.0.0.1:{}", b_port),
                    their_enc_pubkey: b_kp.public_bytes(),
                    plaintext:        format!("msg-{i}"),
                    message_id:       format!("m{i}"),
                })
                .await
                .expect("send_dm");
        }

        for i in 0..5 {
            let dm = timeout(Duration::from_secs(3), bob_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("таймаут на сообщении {i}"))
                .unwrap();
            assert_eq!(dm.plaintext, format!("msg-{i}"));
        }
    }

    /// DM поверх ПРЕДОСТАВЛЕННОГО потока (модель relay-туннеля): Alice шлёт через
    /// `send_dm_over_stream`, Bob принимает через `accept_stream` — оба конца это
    /// просто пара сокетов, как если бы их состыковал relay. Доказывает, что
    /// handshake/доставка не зависят от прямого `TcpStream::connect`.
    #[tokio::test]
    async fn dm_over_provided_stream() {
        let (alice, _a_kp, a_id) = start_node("alice", 1, free_port()).await;
        let (bob, b_kp, b_id) = start_node("bob", 2, free_port()).await;
        let mut bob_rx = bob.subscribe();
        sleep(Duration::from_millis(200)).await;

        // Состыкованная пара сокетов (эмулирует туннель relay).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (alice_side, accepted) = tokio::join!(
            TcpStream::connect(addr),
            listener.accept(),
        );
        let alice_side = alice_side.unwrap();
        let bob_side = accepted.unwrap().0;

        // Bob обрабатывает свою сторону как входящее DM-соединение.
        let bob2 = bob.clone();
        tokio::spawn(async move { bob2.accept_stream(bob_side).await; });

        // Alice шлёт сообщение по своей стороне.
        alice
            .send_dm_over_stream(
                DmSendCmd {
                    to:               b_id.clone(),
                    to_dm_addr:       String::new(), // не используется
                    their_enc_pubkey: b_kp.public_bytes(),
                    plaintext:        "через туннель".into(),
                    message_id:       "rm1".into(),
                },
                alice_side,
            )
            .await
            .expect("send_dm_over_stream");

        let dm = timeout(Duration::from_secs(3), bob_rx.recv())
            .await
            .expect("таймаут ожидания DM через туннель")
            .expect("broadcast закрыт");
        assert_eq!(dm.plaintext, "через туннель");
        assert_eq!(dm.from, a_id);
        assert_eq!(dm.message_id, "rm1");
    }

    /// Сериализация протокольных пакетов: roundtrip + неизвестный тип → Unknown.
    #[test]
    fn dm_packet_serde_roundtrip() {
        let hello = DmPacket::Hello {
            node_id:    node_id(7),
            name:       "alice".into(),
            enc_pubkey: "deadbeef".into(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        let back: DmPacket = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, DmPacket::Hello { .. }));

        // Пакет неизвестного типа от будущей версии не должен ломать парсинг.
        let unknown: DmPacket = serde_json::from_str(r#"{"kind":"from_the_future"}"#).unwrap();
        assert!(matches!(unknown, DmPacket::Unknown));
    }
}
