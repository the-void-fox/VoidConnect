//! Личный P2P чат — прямые зашифрованные TCP-соединения между узлами.
//!
//! Порт: base_port + 3  (например 7703 при base 7700)
//! Протокол: length-prefixed JSON поверх TCP
//! Шифрование: X25519 DH + BLAKE3 KDF + XChaCha20-Poly1305

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener, TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{broadcast, mpsc, Mutex};
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

struct PeerConn {
    fwd_tx: mpsc::Sender<DmPacket>,
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
            Ok((stream, addr)) => {
                let h = handle.clone();
                tokio::spawn(async move { accept_dm_conn(stream, addr, h).await; });
            }
            Err(e) => warn!("DM accept error: {}", e),
        }
    }
}

async fn accept_dm_conn(stream: TcpStream, addr: SocketAddr, handle: PrivateChatHandle) {
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

    let (fwd_tx, fwd_rx) = mpsc::channel::<DmPacket>(64);
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

        // Пробуем существующее соединение
        {
            let conns = self.inner.connections.lock().await;
            if let Some(conn) = conns.get(&cmd.to) {
                if conn.fwd_tx.send(pkt.clone()).await.is_ok() {
                    return Ok(());
                }
            }
        }

        // Устанавливаем новое исходящее соединение
        self.dial_peer(cmd.to, &cmd.to_dm_addr, &cmd.their_enc_pubkey, pkt).await
    }

    async fn dial_peer(
        &self,
        to:            NodeId,
        addr:          &str,
        their_enc_pub: &[u8; 32],
        first_pkt:     DmPacket,
    ) -> anyhow::Result<()> {
        use anyhow::anyhow;

        let stream = match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Err(_) => {
                warn!("DM: connect timeout to {}", addr);
                anyhow::bail!("DM connect timeout to {}", addr);
            }
            Ok(Err(e)) => {
                warn!("DM: connect to {} failed: {}", addr, e);
                anyhow::bail!("DM connect to {} failed: {}", addr, e);
            }
            Ok(Ok(s)) => s,
        };

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

        let (fwd_tx, fwd_rx) = mpsc::channel::<DmPacket>(64);
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

// ── Жизненный цикл соединения ─────────────────────────────────────────────────

async fn run_conn_tasks(
    inner:         Arc<Inner>,
    peer_id:       NodeId,
    peer_name:     String,
    their_enc_pub: [u8; 32],
    mut rd:        OwnedReadHalf,
    mut wr:        OwnedWriteHalf,
    mut fwd_rx:    mpsc::Receiver<DmPacket>,
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
        while let Some(pkt) = fwd_rx.recv().await {
            if write_dm_pkt(&mut wr, &pkt).await.is_err() {
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
