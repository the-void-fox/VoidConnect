//! Личный P2P чат — прямые зашифрованные TCP-соединения между узлами.
//!
//! Порт: base_port + 3  (например 7703 при base 7700)
//! Транспорт: Noise XX ([`void_network::secure`]) — собеседник доказывает свой
//! NodeId до обмена данными, поток зашифрован (в т.ч. через relay-туннель).
//! Протокол: length-prefixed JSON поверх защищённого потока.
//! Сообщения дополнительно шифруются для хранения на диске:
//! X25519 DH + BLAKE3 KDF + XChaCha20-Poly1305 (ключом из аутентифицированного Hello).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use void_core::identity::NodeId;
use void_core::peer::PeerInfo;
use void_core::sanitize::display_text;
use void_network::conn_guard::ConnLimiter;
use void_network::secure::{self, BoxStream, Channel, NoiseIdentity, SecureStream};
use void_crypto::encrypt::EncryptedMessage;
use void_crypto::keys::EncryptionKeypair;

const MAX_PKT: usize = 65_536;
const BCAST_BUF: usize = 128;

/// DM-соединение после Noise-рукопожатия (прямое TCP или relay-туннель).
type DmStream = SecureStream<BoxStream>;
type DmRead = ReadHalf<DmStream>;
type DmWrite = WriteHalf<DmStream>;

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
        /// «Марка работы» ([`crate::dm_pow`]) — нужна, если получатель нас
        /// не знает: без неё он отбросит сообщение.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pow:            Option<u64>,
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
    /// К сообщению приложена действующая марка работы (отправитель → мы).
    pub stamped:        bool,
}

/// Команда из GUI: отправить личное сообщение пиру.
#[derive(Clone)]
pub struct DmSendCmd {
    pub to:               NodeId,
    /// Адрес DM-сервера пира: "ip:dm_port"
    pub to_dm_addr:       String,
    /// X25519-ключ получателя из профиля — только запасной вариант: шифруем
    /// ключом, который получатель сам назвал в аутентифицированном Hello.
    pub their_enc_pubkey: [u8; 32],
    pub plaintext:        String,
    pub message_id:       String,
    /// Приложить марку работы (получатель нас, возможно, не знает). Марка
    /// подбирается раз в день на собеседника (1–2 с CPU) и кэшируется.
    pub stamp:            bool,
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
    /// Noise-ключ, привязанный к нашему NodeId.
    noise:         NoiseIdentity,
    incoming_tx:   broadcast::Sender<IncomingDm>,
    /// Активные соединения (входящие + исходящие)
    connections:   Mutex<HashMap<NodeId, PeerConn>>,
    /// Кэш enc_pubkey пиров из аутентифицированного Hello
    known_pubkeys: Mutex<HashMap<NodeId, ([u8; 32], String)>>,
    /// Подобранные марки работы: получатель → (день UTC, nonce).
    stamps:        Mutex<HashMap<NodeId, (i64, u64)>>,
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
    noise:     NoiseIdentity,
    dm_port:   u16,
) -> anyhow::Result<PrivateChatHandle> {
    let (incoming_tx, _) = broadcast::channel(BCAST_BUF);
    let handle = PrivateChatHandle {
        inner: Arc::new(Inner {
            my_peer,
            my_enc_kp,
            noise,
            incoming_tx,
            connections:   Mutex::new(HashMap::new()),
            known_pubkeys: Mutex::new(HashMap::new()),
            stamps:        Mutex::new(HashMap::new()),
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

/// Глобальный потолок одновременных входящих DM-соединений.
const MAX_DM_CONNS: usize = 1024;
/// Лимит одновременных DM-соединений с одного IP (защита от connection-flood).
const MAX_DM_CONNS_PER_IP: usize = 64;
/// Таймаут на приветственный Hello (slowloris-защита).
const DM_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

async fn run_dm_server(handle: PrivateChatHandle, port: u16) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!("DM server listening on {}", addr);
    let limiter = ConnLimiter::new(MAX_DM_CONNS, MAX_DM_CONNS_PER_IP);
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let permit = match limiter.try_accept(peer_addr.ip()) {
                    Some(p) => p,
                    None => {
                        debug!("DM server at capacity, dropping {}", peer_addr);
                        drop(stream);
                        continue;
                    }
                };
                let h = handle.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    accept_dm_conn(Box::new(stream), peer_addr.to_string(), h).await;
                });
            }
            Err(e) => warn!("DM accept error: {}", e),
        }
    }
}

async fn accept_dm_conn(stream: BoxStream, addr: String, handle: PrivateChatHandle) {
    debug!("DM incoming from {}", addr);

    // Noise: собеседник доказывает свой NodeId до любого обмена данными.
    let secure = match secure::accept(stream, &handle.inner.noise, Channel::Dm).await {
        Ok(s) => s,
        Err(e) => { warn!("DM: handshake with {} failed: {}", addr, e); return; }
    };
    let peer_id = secure.peer().clone();
    let (mut rd, mut wr) = tokio::io::split(secure);

    // Читаем Hello от клиента (с таймаутом — защита от slowloris)
    let hello = match timeout(DM_HELLO_TIMEOUT, read_dm_pkt(&mut rd)).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => { warn!("DM: no Hello from {}: {}", addr, e); return; }
        Err(_) => { warn!("DM: Hello timeout from {}", addr); return; }
    };
    let (peer_name, their_enc_pub) = match hello {
        DmPacket::Hello { node_id, name, enc_pubkey } => {
            // node_id из Hello обязан совпасть с доказанным рукопожатием: иначе
            // узел выдаёт себя за другого (а id ещё и становится именем файла
            // переписки — «../keystore» перезаписал бы ключи).
            if node_id != peer_id {
                warn!("DM: Hello node_id ≠ authenticated {} from {}", peer_id, addr);
                return;
            }
            let bytes: [u8; 32] = match hex::decode(&enc_pubkey)
                .ok().and_then(|b| b.try_into().ok())
            {
                Some(b) => b,
                None => { warn!("DM: invalid enc_pubkey from {}", addr); return; }
            };
            (display_text(&name, void_core::peer::MAX_PROFILE_NAME_CHARS), bytes)
        }
        _ => { warn!("DM: expected Hello from {}", addr); return; }
    };

    info!("DM accepted: {} ({}) from {}", peer_name, peer_id, addr);

    // Отвечаем своим Hello
    if let Err(e) = write_dm_pkt(&mut wr, &handle.hello()).await {
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
    /// из `accept()`, а из [`void-discovery`] relay-клиента, но логика та же —
    /// включая Noise-рукопожатие с собеседником (relay видит только шифротекст).
    pub async fn accept_stream(&self, stream: BoxStream) {
        accept_dm_conn(stream, "<relay>".to_string(), self.clone()).await;
    }

    /// Наш Hello для DM-рукопожатия.
    fn hello(&self) -> DmPacket {
        DmPacket::Hello {
            node_id:    self.inner.my_peer.id.clone(),
            name:       self.inner.my_peer.name.clone(),
            enc_pubkey: hex::encode(self.inner.my_enc_kp.public_bytes()),
        }
    }

    /// Получить кэшированный enc_pubkey пира (если он подключался ранее).
    pub async fn known_pubkey(&self, id: &NodeId) -> Option<[u8; 32]> {
        self.inner.known_pubkeys.lock().await.get(id).map(|(k, _)| *k)
    }

    /// Марка работы для `cmd` (если она нужна): из кэша на сегодня или
    /// подобранная заново в отдельном потоке. Звать ДО открытия соединения:
    /// подбор занимает секунды, и открытое соединение собеседник закрыл бы по
    /// таймауту рукопожатия. `send_dm` делает это сам.
    pub async fn prepare_stamp(&self, cmd: &DmSendCmd) -> Option<u64> {
        if !cmd.stamp {
            return None;
        }
        let to = &cmd.to;
        let today = crate::dm_pow::utc_day(chrono::Utc::now().timestamp());
        if let Some((_, nonce)) = self.inner.stamps.lock().await.get(to).filter(|(day, _)| *day == today) {
            return Some(*nonce);
        }
        let (from, to_id) = (self.inner.my_peer.id.clone(), to.clone());
        let nonce = tokio::task::spawn_blocking(move || crate::dm_pow::mint(&from, &to_id, today))
            .await
            .ok()?;
        self.inner.stamps.lock().await.insert(to.clone(), (today, nonce));
        Some(nonce)
    }

    /// Зашифровать и отправить личное сообщение пиру.
    pub async fn send_dm(&self, cmd: DmSendCmd) -> anyhow::Result<()> {
        let pow = self.prepare_stamp(&cmd).await;
        // Пробуем существующее соединение (в т.ч. ранее поднятый relay-туннель).
        // Берём отправитель под локом и СРАЗУ освобождаем лок: держать его на время
        // await нельзя — cleanup соединения (`run_conn_tasks`) тоже берёт
        // `connections.lock()`, иначе возможен дедлок.
        let existing = {
            let conns = self.inner.connections.lock().await;
            conns.get(&cmd.to).map(|c| c.fwd_tx.clone())
        };
        if let Some(fwd_tx) = existing {
            // Соединение аутентифицировано — ключ из его Hello уже в кэше.
            let to_pub = self.known_pubkey(&cmd.to).await.unwrap_or(cmd.their_enc_pubkey);
            let pkt = encrypt_message(&self.inner.my_enc_kp, &to_pub, &cmd.plaintext, cmd.message_id.clone(), pow)?;
            let (ack_tx, ack_rx) = oneshot::channel();
            // Ok из send() лишь подтверждает постановку в очередь; доставку
            // подтверждает ack из write-задачи (фактическая запись в сокет).
            if fwd_tx.send((pkt, ack_tx)).await.is_ok() {
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
        self.establish_outbound(Box::new(stream), cmd, pow).await
    }

    /// Отправляет DM по УЖЕ установленному потоку (например, relay-туннелю), когда
    /// прямое соединение невозможно (symmetric NAT). Проводит то же рукопожатие,
    /// что и прямой дозвон, но без `TcpStream::connect`. Марку работы готовьте
    /// заранее ([`Self::prepare_stamp`]) — до открытия потока.
    pub async fn send_dm_over_stream(
        &self,
        cmd:    DmSendCmd,
        stream: BoxStream,
    ) -> anyhow::Result<()> {
        let pow = self.prepare_stamp(&cmd).await;
        self.establish_outbound(stream, cmd, pow).await
    }

    /// Общая часть исходящего соединения: Noise-рукопожатие с проверкой, что на
    /// том конце именно `cmd.to`, обмен Hello, шифрование первого сообщения
    /// ключом из аутентифицированного Hello и запуск задач соединения. Работает
    /// поверх любого потока — прямого TCP или relay-туннеля.
    async fn establish_outbound(&self, stream: BoxStream, cmd: DmSendCmd, pow: Option<u64>) -> anyhow::Result<()> {
        use anyhow::anyhow;

        // Подменённый адрес (чужой узел, злой relay) обрывается здесь, до того
        // как мы что-либо отправим.
        let secure = secure::connect(stream, &self.inner.noise, Channel::Dm, Some(&cmd.to)).await?;
        let (mut rd, mut wr) = tokio::io::split(secure);

        // Наш Hello
        write_dm_pkt(&mut wr, &self.hello()).await?;

        // Их Hello
        let (peer_name, confirmed_pub) = match timeout(DM_HELLO_TIMEOUT, read_dm_pkt(&mut rd)).await {
            Ok(Ok(DmPacket::Hello { node_id, name, enc_pubkey })) if node_id == cmd.to => {
                let bytes: [u8; 32] = hex::decode(&enc_pubkey)
                    .ok().and_then(|b| b.try_into().ok())
                    .ok_or_else(|| anyhow!("DM: invalid enc_pubkey in Hello from {}", cmd.to))?;
                (display_text(&name, void_core::peer::MAX_PROFILE_NAME_CHARS), bytes)
            }
            Ok(Ok(_)) => anyhow::bail!("DM: expected Hello from {}", cmd.to),
            Ok(Err(e)) => return Err(e),
            Err(_) => anyhow::bail!("DM: Hello timeout from {}", cmd.to),
        };

        // Кэшируем
        self.inner.known_pubkeys.lock().await
            .insert(cmd.to.clone(), (confirmed_pub, peer_name.clone()));

        // Ключ берём из аутентифицированного Hello, а не из неподписанного профиля.
        let first_pkt = encrypt_message(&self.inner.my_enc_kp, &confirmed_pub, &cmd.plaintext, cmd.message_id, pow)?;
        write_dm_pkt(&mut wr, &first_pkt).await?;

        let to = cmd.to;
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

/// Шифрует текст для получателя (хранится на диске в зашифрованном виде).
fn encrypt_message(
    my_kp:      &EncryptionKeypair,
    to_pub:     &[u8; 32],
    plaintext:  &str,
    message_id: String,
    pow:        Option<u64>,
) -> anyhow::Result<DmPacket> {
    let enc = EncryptedMessage::encrypt(plaintext.as_bytes(), to_pub, my_kp)
        .map_err(|e| anyhow::anyhow!("DM encrypt: {:?}", e))?;
    Ok(DmPacket::Message {
        message_id,
        encrypted_blob: serde_json::to_string(&enc)?,
        timestamp:      chrono::Utc::now().timestamp(),
        pow,
    })
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
    mut rd:        DmRead,
    mut wr:        DmWrite,
    mut fwd_rx:    mpsc::Receiver<FwdItem>,
) {
    let inner_r = Arc::clone(&inner);
    let pid_r   = peer_id.clone();
    let pname_r = peer_name.clone();

    let read_task = tokio::spawn(async move {
        loop {
            match read_dm_pkt(&mut rd).await {
                Ok(pkt @ DmPacket::Message { .. }) => {
                    on_dm_message(&inner_r, &pid_r, &pname_r, &their_enc_pub, pkt).await;
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
    their_enc_pub:  &[u8; 32],
    pkt:            DmPacket,
) {
    let DmPacket::Message { message_id, encrypted_blob, timestamp, pow } = pkt else { return };
    let stamped = pow.is_some_and(|n| {
        crate::dm_pow::verify(from, &inner.my_peer.id, chrono::Utc::now().timestamp(), n)
    });
    let enc: EncryptedMessage = match serde_json::from_str(&encrypted_blob) {
        Ok(e) => e,
        Err(e) => { warn!("DM: bad blob from {}: {}", from, e); return; }
    };
    // Блоб должен быть зашифрован ключом, который отправитель назвал в своём
    // аутентифицированном Hello — иначе это не его сообщение.
    if enc.sender_pubkey != hex::encode(their_enc_pub) {
        warn!("DM: blob from {} encrypted by a foreign key, dropped", from);
        return;
    }
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
        stamped,
    };
    let _ = inner.incoming_tx.send(dm);
}

// ── I/O хелперы ───────────────────────────────────────────────────────────────

async fn write_dm_pkt<W: AsyncWrite + Unpin>(wr: &mut W, pkt: &DmPacket) -> anyhow::Result<()> {
    let json = serde_json::to_vec(pkt)?;
    if json.len() > MAX_PKT { anyhow::bail!("DM packet too large"); }
    wr.write_all(&(json.len() as u32).to_be_bytes()).await?;
    wr.write_all(&json).await?;
    wr.flush().await?;
    Ok(())
}

async fn read_dm_pkt<R: AsyncRead + Unpin>(rd: &mut R) -> anyhow::Result<DmPacket> {
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
    use void_crypto::keys::SigningKeypair;

    /// Берёт свободный TCP-порт на loopback (закрывая временный листенер).
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// Ed25519-ключ узла: NodeId должен быть настоящим — Noise его проверяет.
    fn signing(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    fn node_id(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&signing(seed).public_bytes())
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
        let noise = NoiseIdentity::new(&signing(id_seed));
        let handle = start_private_chat(peer, Arc::clone(&kp), noise, dm_port)
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
                stamp:            false,
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

    /// Марка работы: подбирается один раз и прикладывается ко всем сообщениям
    /// дня; получатель видит её как действующую. Без запроса марки — нет.
    #[tokio::test]
    async fn dm_stamp_attached_and_verified() {
        let a_port = free_port();
        let b_port = free_port();
        let (alice, _a_kp, a_id) = start_node("alice", 1, a_port).await;
        let (bob, b_kp, b_id) = start_node("bob", 2, b_port).await;
        let mut bob_rx = bob.subscribe();
        sleep(Duration::from_millis(300)).await;

        let send = |id: &str, stamp: bool| DmSendCmd {
            to:               b_id.clone(),
            to_dm_addr:       format!("127.0.0.1:{}", b_port),
            their_enc_pubkey: b_kp.public_bytes(),
            plaintext:        id.into(),
            message_id:       id.into(),
            stamp,
        };
        alice.send_dm(send("s1", true)).await.expect("send s1");
        let today = crate::dm_pow::utc_day(chrono::Utc::now().timestamp());
        let cached = alice.inner.stamps.lock().await.get(&b_id).copied();
        assert!(matches!(cached, Some((day, _)) if day == today), "марка закэширована на сегодня");
        alice.send_dm(send("s2", true)).await.expect("send s2");
        assert_eq!(alice.inner.stamps.lock().await.get(&b_id).copied(), cached, "вторая — та же марка");
        alice.send_dm(send("plain", false)).await.expect("send plain");

        for (id, stamped) in [("s1", true), ("s2", true), ("plain", false)] {
            let dm = timeout(Duration::from_secs(5), bob_rx.recv()).await.unwrap().unwrap();
            assert_eq!(dm.message_id, id);
            assert_eq!(dm.from, a_id);
            assert_eq!(dm.stamped, stamped, "{id}");
        }
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
                stamp:            false,
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
            stamp:            false,
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
                    stamp:            false,
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
        tokio::spawn(async move { bob2.accept_stream(Box::new(bob_side)).await; });

        // Alice шлёт сообщение по своей стороне.
        alice
            .send_dm_over_stream(
                DmSendCmd {
                    to:               b_id.clone(),
                    to_dm_addr:       String::new(), // не используется
                    their_enc_pubkey: b_kp.public_bytes(),
                    plaintext:        "через туннель".into(),
                    message_id:       "rm1".into(),
                    stamp:            false,
                },
                Box::new(alice_side),
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

    /// Узел не может назваться в Hello чужим NodeId (или путём «../keystore»):
    /// node_id обязан совпасть с доказанным Noise-рукопожатием.
    #[tokio::test]
    async fn dm_hello_must_match_authenticated_id() {
        let b_port = free_port();
        let (bob, b_kp, _b_id) = start_node("bob", 2, b_port).await;
        let mut bob_rx = bob.subscribe();
        sleep(Duration::from_millis(300)).await;

        let mallory = NoiseIdentity::new(&signing(9));
        for claimed in [node_id(1), NodeId("../keystore".into())] {
            let evil_kp = EncryptionKeypair::generate();
            let tcp = TcpStream::connect(("127.0.0.1", b_port)).await.unwrap();
            let secure = secure::connect(tcp, &mallory, Channel::Dm, None).await.unwrap();
            let (mut rd, mut wr) = tokio::io::split(secure);
            write_dm_pkt(&mut wr, &DmPacket::Hello {
                node_id:    claimed,
                name:       "alice".into(),
                enc_pubkey: hex::encode(evil_kp.public_bytes()),
            }).await.unwrap();
            assert!(read_dm_pkt(&mut rd).await.is_err(), "сервер не должен отвечать на чужой node_id");

            let enc = EncryptedMessage::encrypt(b"pwned", &b_kp.public_bytes(), &evil_kp).unwrap();
            let _ = write_dm_pkt(&mut wr, &DmPacket::Message {
                message_id:     "x".into(),
                encrypted_blob: serde_json::to_string(&enc).unwrap(),
                timestamp:      0,
                pow:            None,
            }).await;
        }

        assert!(
            timeout(Duration::from_millis(500), bob_rx.recv()).await.is_err(),
            "сообщение от самозванца не должно доходить до UI"
        );
    }

    /// Отправка «Бобу» по адресу, где на самом деле другой узел (подменённый IP
    /// в discovery или злой relay), обрывается на рукопожатии: сообщение не уходит.
    #[tokio::test]
    async fn dm_to_impostor_address_fails() {
        let c_port = free_port();
        let (carol, _c_kp, _c_id) = start_node("carol", 3, c_port).await;
        let (alice, _a_kp, _a_id) = start_node("alice", 1, free_port()).await;
        let mut carol_rx = carol.subscribe();
        sleep(Duration::from_millis(300)).await;

        let res = alice.send_dm(DmSendCmd {
            to:               node_id(2), // Боб
            to_dm_addr:       format!("127.0.0.1:{}", c_port),
            their_enc_pubkey: [7u8; 32],
            plaintext:        "секрет".into(),
            message_id:       "x".into(),
            stamp:            false,
        }).await;
        assert!(res.is_err(), "рукопожатие с самозванцем должно провалиться");
        assert!(
            timeout(Duration::from_millis(500), carol_rx.recv()).await.is_err(),
            "самозванец не должен получить сообщение"
        );
    }
}
