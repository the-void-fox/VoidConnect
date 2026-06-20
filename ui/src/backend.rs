//! Мост между асинхронным бэкендом (tokio) и синхронным GUI (egui).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile, Service};
use void_chat::public_chat::{start_public_chat, ChatMessage};
use void_chat::private_chat::{start_private_chat, IncomingDm, DmSendCmd};
use void_crypto::keys::{EncryptionKeypair, SigningKeypair};
use void_discovery::PeerList;

pub struct BackendHandle {
    pub chat_inbox:    Arc<Mutex<VecDeque<ChatMessage>>>,
    pub chat_sender:   tokio::sync::mpsc::UnboundedSender<String>,
    /// Вручную добавить пир: отправить "ip:base_port"
    pub connect_tx:    tokio::sync::mpsc::UnboundedSender<String>,
    /// Отправить обновление своего профиля
    pub profile_tx:    tokio::sync::mpsc::UnboundedSender<PeerProfile>,
    pub peers:         Arc<Mutex<Vec<PeerInfo>>>,
    /// Профили других узлов (name, description, status)
    pub peer_profiles: Arc<Mutex<HashMap<NodeId, PeerProfile>>>,
    pub my_name:       String,
    pub my_id_short:   String,
    pub my_id_full:    String,
    pub my_id_node:    NodeId,
    pub my_ip:         String,
    pub base_port:     u16,
    /// Запущен ли режим локального тестирования (--local)
    pub local_mode:    bool,
    /// X25519 keypair для E2E шифрования (разделяется с GUI для само-шифрования)
    pub my_enc_kp:     Arc<EncryptionKeypair>,
    /// X25519 публичный ключ (hex) — для включения в профиль
    pub my_enc_pub_hex: String,
    /// Входящие расшифрованные личные сообщения (опрашивается GUI каждый кадр)
    pub dm_inbox:      Arc<Mutex<VecDeque<IncomingDm>>>,
    /// Канал GUI → backend: отправить DM пиру
    pub dm_sender:     tokio::sync::mpsc::UnboundedSender<DmSendCmd>,
    /// DM-порт нашего узла = base_port + 3
    pub dm_port:       u16,
    /// История общего чата, загруженная из БД при старте.
    /// `None` пока бэкенд не загрузил; GUI забирает её один раз (`take`).
    pub chat_history:  Arc<Mutex<Option<Vec<ChatMessage>>>>,
}

pub fn start_backend(
    name:       String,
    base_port:  u16,
    my_id:      NodeId,
    local_mode: bool,
    enc_kp:     Arc<EncryptionKeypair>,
    sign_kp:    Arc<SigningKeypair>,
    data_dir:   PathBuf,
) -> BackendHandle {
    let chat_inbox:    Arc<Mutex<VecDeque<ChatMessage>>>         = Arc::new(Mutex::new(VecDeque::new()));
    let peers:         Arc<Mutex<Vec<PeerInfo>>>                  = Arc::new(Mutex::new(Vec::new()));
    let peer_profiles: Arc<Mutex<HashMap<NodeId, PeerProfile>>>  = Arc::new(Mutex::new(HashMap::new()));
    let dm_inbox:      Arc<Mutex<VecDeque<IncomingDm>>>          = Arc::new(Mutex::new(VecDeque::new()));
    let chat_history:  Arc<Mutex<Option<Vec<ChatMessage>>>>     = Arc::new(Mutex::new(None));

    let (chat_tx,    chat_rx)    = tokio::sync::mpsc::unbounded_channel::<String>();
    let (connect_tx, connect_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (profile_tx, profile_rx) = tokio::sync::mpsc::unbounded_channel::<PeerProfile>();
    let (dm_tx,      dm_rx)      = tokio::sync::mpsc::unbounded_channel::<DmSendCmd>();

    let my_ip = if local_mode {
        IpAddr::from([127, 0, 0, 1])
    } else {
        get_local_ip()
    };
    let chat_port = base_port + 2;
    let dm_port   = base_port + 3;

    tracing::info!("Mode: {}  IP: {}", if local_mode { "local" } else { "LAN" }, my_ip);

    let my_peer = PeerInfo {
        id:        my_id.clone(),
        name:      name.clone(),
        ip:        my_ip,
        port:      base_port,
        chat_port,
        services:  vec![Service::Chat],
        last_seen: chrono::Utc::now().timestamp(),
    };

    let my_id_full  = my_id.as_str().to_string();
    let my_id_short = format!("{}...{}", &my_id_full[..8], &my_id_full[my_id_full.len()-4..]);
    let my_enc_pub_hex = hex::encode(enc_kp.public_bytes());

    let inbox_bg    = Arc::clone(&chat_inbox);
    let peers_bg    = Arc::clone(&peers);
    let profiles_bg = Arc::clone(&peer_profiles);
    let dm_inbox_bg = Arc::clone(&dm_inbox);
    let enc_kp_bg   = Arc::clone(&enc_kp);
    let sign_kp_bg  = Arc::clone(&sign_kp);
    let history_bg  = Arc::clone(&chat_history);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            backend_main(
                my_peer, base_port, local_mode,
                inbox_bg, peers_bg, profiles_bg, dm_inbox_bg,
                enc_kp_bg, sign_kp_bg, dm_port,
                chat_rx, connect_rx, profile_rx, dm_rx,
                data_dir, history_bg,
            ).await;
        });
    });

    BackendHandle {
        chat_inbox,
        chat_sender: chat_tx,
        connect_tx,
        profile_tx,
        peers,
        peer_profiles,
        my_name:     name,
        my_id_short,
        my_id_full,
        my_id_node: my_id,
        my_ip:      my_ip.to_string(),
        base_port,
        local_mode,
        my_enc_kp:     enc_kp,
        my_enc_pub_hex,
        dm_inbox,
        dm_sender: dm_tx,
        dm_port,
        chat_history,
    }
}

// ─── Внутренний async-рантайм ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn backend_main(
    my_peer:     PeerInfo,
    base_port:   u16,
    local_mode:  bool,
    inbox:       Arc<Mutex<VecDeque<ChatMessage>>>,
    peers_out:   Arc<Mutex<Vec<PeerInfo>>>,
    profiles_out: Arc<Mutex<HashMap<NodeId, PeerProfile>>>,
    dm_inbox:    Arc<Mutex<VecDeque<IncomingDm>>>,
    enc_kp:      Arc<EncryptionKeypair>,
    sign_kp:     Arc<SigningKeypair>,
    dm_port:     u16,
    mut chat_rx:    tokio::sync::mpsc::UnboundedReceiver<String>,
    mut connect_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    mut profile_rx: tokio::sync::mpsc::UnboundedReceiver<PeerProfile>,
    mut dm_rx:      tokio::sync::mpsc::UnboundedReceiver<DmSendCmd>,
    data_dir:       PathBuf,
    chat_history_out: Arc<Mutex<Option<Vec<ChatMessage>>>>,
) {
    // Открываем БД для персистентности истории общего чата.
    // При ошибке работаем без персистентности — это не критично для чата.
    let db_pool: Option<void_db::DbPool> = match void_db::open(&data_dir.join("void.db")).await {
        Ok(pool) => {
            tracing::info!("DB opened at {}", data_dir.join("void.db").display());
            Some(pool)
        }
        Err(e) => {
            tracing::error!("DB open failed — история чата не будет сохраняться: {}", e);
            None
        }
    };

    // Загружаем сохранённую историю общего чата и отдаём её GUI (один раз).
    let loaded = match &db_pool {
        Some(pool) => match void_db::messages::get_public_history(pool, 300).await {
            Ok(rows) => rows.into_iter().rev().map(db_msg_to_chat).collect(),
            Err(e)   => { tracing::warn!("Не удалось загрузить историю чата: {}", e); Vec::new() }
        },
        None => Vec::new(),
    };
    *chat_history_out.lock().unwrap() = Some(loaded);

    let peer_list = PeerList::new();

    if local_mode {
        void_discovery::local_discovery::start_local_discovery(
            my_peer.clone(), peer_list.clone(), base_port,
        ).await;
    } else {
        if let Err(e) = void_discovery::mdns::start_mdns(my_peer.clone(), peer_list.clone()).await {
            tracing::warn!("mDNS failed (есть UDP-fallback): {}", e);
        }
        if let Err(e) = void_discovery::udp_broadcast::start_udp_broadcast(
            my_peer.clone(), peer_list.clone(), base_port,
        ).await {
            tracing::warn!("UDP broadcast failed: {}", e);
        }
    }

    let chat = match start_public_chat(my_peer.clone(), peer_list.clone(), my_peer.chat_port, sign_kp).await {
        Ok(h)  => h,
        Err(e) => {
            tracing::error!("Chat TCP server failed on port {}: {}", my_peer.chat_port, e);
            loop { tokio::time::sleep(tokio::time::Duration::from_secs(60)).await; }
        }
    };

    // Начальный профиль с enc_pubkey
    let enc_pub_hex = hex::encode(enc_kp.public_bytes());
    let mut initial_profile = PeerProfile::new(my_peer.id.clone(), my_peer.name.clone());
    initial_profile.enc_pubkey = Some(enc_pub_hex.clone());
    chat.set_profile(initial_profile).await;

    // Запускаем DM-сервер
    let dm_handle = match start_private_chat(my_peer.clone(), Arc::clone(&enc_kp), dm_port).await {
        Ok(h)  => h,
        Err(e) => {
            tracing::error!("DM server failed on port {}: {}", dm_port, e);
            loop { tokio::time::sleep(tokio::time::Duration::from_secs(60)).await; }
        }
    };

    // Задача: входящие публичные сообщения → inbox GUI + персистентность в БД
    let mut rx = chat.subscribe();
    let inbox_task = Arc::clone(&inbox);
    let pool_for_save = db_pool.clone();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    // Сохраняем в БД (best-effort, дедуп по message_id внутри INSERT OR IGNORE)
                    if let Some(pool) = &pool_for_save {
                        if let Err(e) = persist_public_message(pool, &msg).await {
                            tracing::warn!("Не удалось сохранить сообщение чата: {}", e);
                        }
                    }
                    let mut q = inbox_task.lock().unwrap();
                    if q.len() > 500 { q.pop_front(); }
                    q.push_back(msg);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Chat inbox lagged by {} messages", n);
                }
                Err(_) => break,
            }
        }
    });

    // Задача: входящие DM → dm_inbox GUI
    let mut dm_rx_sub = dm_handle.subscribe();
    let dm_inbox_task = Arc::clone(&dm_inbox);
    tokio::spawn(async move {
        loop {
            match dm_rx_sub.recv().await {
                Ok(msg) => {
                    let mut q = dm_inbox_task.lock().unwrap();
                    if q.len() > 1000 { q.pop_front(); }
                    q.push_back(msg);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("DM inbox lagged by {} messages", n);
                }
                Err(_) => break,
            }
        }
    });

    // Задача: исходящий текст GUI → chat.send()
    let chat_send = chat.clone();
    tokio::spawn(async move {
        while let Some(text) = chat_rx.recv().await {
            if let Err(e) = chat_send.send(text).await {
                tracing::warn!("Chat send error: {}", e);
            }
        }
    });

    // Задача: обновление профиля из GUI → включаем enc_pubkey, отправляем
    let chat_profile = chat.clone();
    let enc_pub_hex2 = enc_pub_hex.clone();
    tokio::spawn(async move {
        while let Some(mut profile) = profile_rx.recv().await {
            // Всегда включаем наш enc_pubkey в рассылаемый профиль
            profile.enc_pubkey = Some(enc_pub_hex2.clone());
            chat_profile.set_profile(profile).await;
        }
    });

    // Задача: исходящие DM из GUI → DM handle
    let dm_h = dm_handle.clone();
    tokio::spawn(async move {
        while let Some(cmd) = dm_rx.recv().await {
            if let Err(e) = dm_h.send_dm(cmd).await {
                tracing::warn!("DM send error: {}", e);
            }
        }
    });

    // Задача: ручное добавление пира (из GUI)
    let pl = peer_list.clone();
    tokio::spawn(async move {
        while let Some(addr_str) = connect_rx.recv().await {
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(addr) => {
                    let base = addr.port();
                    let stub = PeerInfo {
                        id:        NodeId(format!("stub-{}", addr)),
                        name:      "пир".to_string(),
                        ip:        addr.ip(),
                        port:      base,
                        chat_port: base + 2,
                        services:  vec![Service::Chat],
                        last_seen: chrono::Utc::now().timestamp(),
                    };
                    tracing::info!("Manually added peer: {} (chat_port={})", addr, base + 2);
                    pl.upsert(stub).await;
                }
                Err(_) => {
                    tracing::warn!("Invalid peer address: '{}'", addr_str);
                }
            }
        }
    });

    // Задача: периодически снимаем peer_list и профили для GUI
    let pl      = peer_list.clone();
    let chat_p  = chat.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            *peers_out.lock().unwrap()   = pl.all().await;
            let profiles = chat_p.get_profiles().await;
            let mut map = profiles_out.lock().unwrap();
            for p in profiles {
                map.insert(p.node_id.clone(), p);
            }
        }
    });

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}

// ─── Определение реального LAN-IP ────────────────────────────────────────────

fn get_local_ip() -> IpAddr {
    let targets = ["8.8.8.8:80", "1.1.1.1:80", "192.168.1.1:80", "10.0.0.1:80"];
    for target in targets {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    let ip = addr.ip();
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        return ip;
                    }
                }
            }
        }
    }
    tracing::warn!("Не удалось определить LAN IP. Используется 0.0.0.0.");
    IpAddr::from([0, 0, 0, 0])
}

// ─── Персистентность истории общего чата ─────────────────────────────────────

/// Сохраняет сообщение общего чата в БД. message_id = "{from}:{seq}" —
/// детерминированный ключ для дедупликации (INSERT OR IGNORE).
async fn persist_public_message(pool: &void_db::DbPool, msg: &ChatMessage) -> void_db::Result<()> {
    let message_id = format!("{}:{}", msg.from.as_str(), msg.seq);
    let sent_at = chrono::DateTime::from_timestamp(msg.timestamp, 0)
        .unwrap_or_else(chrono::Utc::now);
    void_db::messages::save_public_message(
        pool,
        &message_id,
        msg.from.as_str(),
        &msg.from_name,
        &msg.text,
        msg.signature.as_deref().unwrap_or(""),
        sent_at,
    )
    .await
}

/// Преобразует запись из БД в ChatMessage для GUI.
/// seq не хранится (для отображения истории не нужен) → 0.
fn db_msg_to_chat(m: void_db::messages::PublicMessage) -> ChatMessage {
    ChatMessage {
        from:      NodeId(m.sender_key),
        from_name: m.sender_name,
        text:      m.content,
        timestamp: m.sent_at.timestamp(),
        seq:       0,
        signature: if m.signature.is_empty() { None } else { Some(m.signature) },
    }
}
