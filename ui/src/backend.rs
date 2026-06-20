//! Мост между асинхронным бэкендом (tokio) и синхронным GUI (egui).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile, Service};
use void_chat::public_chat::{start_public_chat, ChatHandle, ChatMessage, RepGossip};
use void_chat::private_chat::{start_private_chat, IncomingDm, DmSendCmd};
use void_crypto::keys::{EncryptionKeypair, SigningKeypair};
use void_discovery::PeerList;
use void_storage::{ChunkEvent, ChunkStore, StorageManager};
use void_reputation::{
    EventProcessor, RateLimiter, ReportManager, ReportReason, ReputationEvent, ScoreManager, SyncManager,
};
use void_web::{publish_site, SiteRegistry};

/// Запись о файле в хранилище — снимок для GUI.
#[derive(Clone)]
pub struct StorageFileInfo {
    pub file_id:      String,
    pub name:         String,
    pub size_bytes:   i64,
    pub total_chunks: i64,
    /// Доля локально имеющихся чанков, 0.0..1.0
    pub progress:     f64,
    /// Опубликован нами (мы владелец)
    pub is_mine:      bool,
    /// Сколько узлов раздают файл (по данным манифеста)
    pub seeders:      i64,
}

/// Запись о сайте — снимок для GUI.
#[derive(Clone)]
pub struct SiteInfo {
    pub name:       String,
    pub dns_name:   String,
    pub file_count: usize,
    pub size_bytes: i64,
    /// Опубликован нами.
    pub is_mine:    bool,
    /// Локальный URL для открытия в браузере.
    pub url:        String,
}

/// Команда GUI → backend для управления скачиванием файла.
#[derive(Clone, Debug)]
pub enum DownloadCmd {
    /// Начать (или продолжить) скачивание файла по его file_id.
    Start(String),
    /// Поставить на паузу скачивание файла по его file_id.
    Pause(String),
}

/// Компоненты системы репутации, разделяемые между фоновыми задачами.
#[derive(Clone)]
struct Reputation {
    score:   ScoreManager,
    events:  EventProcessor,
    sync:    Arc<SyncManager>,
    reports: ReportManager,
    /// Наш ключ подписи — для создания подписанных жалоб.
    keypair: Arc<SigningKeypair>,
}

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
    /// Канал GUI → backend: опубликовать файл по указанному пути.
    pub publish_tx:    tokio::sync::mpsc::UnboundedSender<PathBuf>,
    /// Канал GUI → backend: управление скачиванием (старт/пауза).
    pub download_tx:   tokio::sync::mpsc::UnboundedSender<DownloadCmd>,
    /// Снимок списка файлов хранилища (обновляется бэкендом каждые ~2с).
    pub storage_files: Arc<Mutex<Vec<StorageFileInfo>>>,
    /// Папка, куда сохраняются скачанные файлы (для «Открыть» в UI).
    pub downloads_dir: PathBuf,
    /// Снимок репутации известных узлов: NodeId → score (обновляется ~2с).
    pub peer_reputation: Arc<Mutex<HashMap<NodeId, f64>>>,
    /// Канал GUI → backend: пожаловаться на узел (target, причина).
    pub report_tx: tokio::sync::mpsc::UnboundedSender<(NodeId, ReportReason)>,
    /// Запущены ли мы в публичном (bootstrap) режиме.
    pub bootstrap: bool,
    /// Канал GUI → backend: опубликовать сайт (каталог, имя).
    pub publish_site_tx: tokio::sync::mpsc::UnboundedSender<(PathBuf, String)>,
    /// Снимок списка сайтов (обновляется бэкендом).
    pub sites: Arc<Mutex<Vec<SiteInfo>>>,
    /// Порт локального HTTP-сервера сайтов (base_port + 4).
    pub site_http_port: u16,
}

pub fn start_backend(
    name:        String,
    base_port:   u16,
    my_id:       NodeId,
    local_mode:  bool,
    public_mode: bool,
    enc_kp:      Arc<EncryptionKeypair>,
    sign_kp:     Arc<SigningKeypair>,
    data_dir:   PathBuf,
) -> BackendHandle {
    let chat_inbox:    Arc<Mutex<VecDeque<ChatMessage>>>         = Arc::new(Mutex::new(VecDeque::new()));
    let peers:         Arc<Mutex<Vec<PeerInfo>>>                  = Arc::new(Mutex::new(Vec::new()));
    let peer_profiles: Arc<Mutex<HashMap<NodeId, PeerProfile>>>  = Arc::new(Mutex::new(HashMap::new()));
    let dm_inbox:      Arc<Mutex<VecDeque<IncomingDm>>>          = Arc::new(Mutex::new(VecDeque::new()));
    let chat_history:  Arc<Mutex<Option<Vec<ChatMessage>>>>     = Arc::new(Mutex::new(None));
    let storage_files: Arc<Mutex<Vec<StorageFileInfo>>>         = Arc::new(Mutex::new(Vec::new()));
    let peer_reputation: Arc<Mutex<HashMap<NodeId, f64>>>       = Arc::new(Mutex::new(HashMap::new()));

    let (chat_tx,    chat_rx)    = tokio::sync::mpsc::unbounded_channel::<String>();
    let (connect_tx, connect_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (profile_tx, profile_rx) = tokio::sync::mpsc::unbounded_channel::<PeerProfile>();
    let (dm_tx,      dm_rx)      = tokio::sync::mpsc::unbounded_channel::<DmSendCmd>();
    let (publish_tx, publish_rx) = tokio::sync::mpsc::unbounded_channel::<PathBuf>();
    let (download_tx, download_rx) = tokio::sync::mpsc::unbounded_channel::<DownloadCmd>();
    let (report_tx, report_rx) = tokio::sync::mpsc::unbounded_channel::<(NodeId, ReportReason)>();
    let (publish_site_tx, publish_site_rx) = tokio::sync::mpsc::unbounded_channel::<(PathBuf, String)>();
    let sites: Arc<Mutex<Vec<SiteInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let site_http_port = base_port + 4;

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
    let storage_bg  = Arc::clone(&storage_files);
    let reputation_bg = Arc::clone(&peer_reputation);
    let sites_bg      = Arc::clone(&sites);

    let downloads_dir = data_dir.join("downloads");

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            backend_main(
                my_peer, base_port, local_mode, public_mode,
                inbox_bg, peers_bg, profiles_bg, dm_inbox_bg,
                enc_kp_bg, sign_kp_bg, dm_port,
                chat_rx, connect_rx, profile_rx, dm_rx,
                data_dir, history_bg,
                publish_rx, download_rx, storage_bg,
                reputation_bg, report_rx,
                publish_site_rx, sites_bg, site_http_port,
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
        publish_tx,
        download_tx,
        storage_files,
        downloads_dir,
        peer_reputation,
        report_tx,
        bootstrap: public_mode,
        publish_site_tx,
        sites,
        site_http_port,
    }
}

// ─── Внутренний async-рантайм ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn backend_main(
    my_peer:     PeerInfo,
    base_port:   u16,
    local_mode:  bool,
    bootstrap:   bool,
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
    publish_rx: tokio::sync::mpsc::UnboundedReceiver<PathBuf>,
    download_rx: tokio::sync::mpsc::UnboundedReceiver<DownloadCmd>,
    storage_files_out: Arc<Mutex<Vec<StorageFileInfo>>>,
    reputation_out: Arc<Mutex<HashMap<NodeId, f64>>>,
    mut report_rx: tokio::sync::mpsc::UnboundedReceiver<(NodeId, ReportReason)>,
    publish_site_rx: tokio::sync::mpsc::UnboundedReceiver<(PathBuf, String)>,
    sites_out: Arc<Mutex<Vec<SiteInfo>>>,
    site_http_port: u16,
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

    // ── Система репутации (локальный скоринг + сетевая синхронизация) ─────────
    // Доступна, если есть БД.
    let reputation: Option<Reputation> = db_pool.clone().map(|pool| {
        let score = ScoreManager::new(pool.clone());
        let rate_limiter = Arc::new(RateLimiter::new());
        let events = EventProcessor::new(score.clone(), rate_limiter);
        let sync = Arc::new(SyncManager::new(
            pool.clone(), score.clone(), events.clone(),
            sign_kp.clone(), my_peer.id.clone(),
        ));
        let reports = ReportManager::new(pool, score.clone());
        Reputation { score, events, sync, reports, keypair: sign_kp.clone() }
    });

    // Канал событий о качестве чанков из storage → события репутации.
    let chunk_ev_tx: Option<tokio::sync::mpsc::UnboundedSender<ChunkEvent>> =
        reputation.as_ref().map(|rep| {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ChunkEvent>();
            let ev = rep.events.clone();
            tokio::spawn(async move {
                while let Some(e) = rx.recv().await {
                    match e {
                        ChunkEvent::Valid { peer, size_bytes } => {
                            ev.process(ReputationEvent::ValidChunk { peer_id: peer, size_bytes }).await;
                        }
                        ChunkEvent::Bad { peer } => {
                            ev.process(ReputationEvent::BadChunk { peer_id: peer }).await;
                        }
                    }
                }
            });
            tx
        });

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
    initial_profile.is_bootstrap = bootstrap;
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
            // Всегда включаем наш enc_pubkey и bootstrap-флаг в рассылаемый профиль
            profile.enc_pubkey = Some(enc_pub_hex2.clone());
            profile.is_bootstrap = bootstrap;
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

    // Снимок активных пиров для HTTP-сервера сайтов (докачка файлов чужих
    // сайтов по запросу). Клонируем до того, как peers_out уедет в задачу ниже.
    let sites_peers = Arc::clone(&peers_out);

    // Задача: периодически снимаем peer_list и профили для GUI.
    // Здесь же ведём репутацию: события подключения/отключения (аптайм) и
    // обновление снимка score для GUI.
    let pl       = peer_list.clone();
    let chat_p   = chat.clone();
    let rep_snap = reputation.clone();
    let rep_out  = Arc::clone(&reputation_out);
    let my_rep_id = my_peer.id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
        let mut prev_ids: HashSet<NodeId> = HashSet::new();
        loop {
            interval.tick().await;
            let peers = pl.all().await;
            *peers_out.lock().unwrap() = peers.clone();
            let profiles = chat_p.get_profiles().await;
            {
                let mut map = profiles_out.lock().unwrap();
                for p in profiles {
                    map.insert(p.node_id.clone(), p);
                }
            }

            if let Some(rep) = &rep_snap {
                // Только реальные узлы (64-hex), не stub-заглушки.
                let cur_ids: HashSet<NodeId> = peers.iter()
                    .filter(|p| p.id.as_str().len() == 64)
                    .map(|p| p.id.clone())
                    .collect();
                let newly: Vec<NodeId> = cur_ids.difference(&prev_ids).cloned().collect();
                for id in &newly {
                    rep.events.process(ReputationEvent::PeerConnected { peer_id: id.clone() }).await;
                }
                for id in prev_ids.difference(&cur_ids) {
                    rep.events.process(ReputationEvent::PeerDisconnected { peer_id: id.clone() }).await;
                }
                // Появились новые узлы — рассылаем им наш снимок оценок (gossip).
                if !newly.is_empty() {
                    if let Ok(signed) = rep.sync.build_signed_sync().await {
                        chat_p.broadcast_reputation_sync(my_rep_id.clone(), signed).await;
                    }
                }
                // Снимок репутации для GUI.
                let mut snapshot = HashMap::with_capacity(cur_ids.len());
                for id in &cur_ids {
                    snapshot.insert(id.clone(), rep.score.score(id).await);
                }
                *rep_out.lock().unwrap() = snapshot;
                prev_ids = cur_ids;
            }
        }
    });

    // Задача: входящие пакеты репутации из сети (sync/жалобы) → применяем.
    if let Some(rep) = reputation.clone() {
        let mut rep_rx = chat.subscribe_reputation();
        tokio::spawn(async move {
            loop {
                match rep_rx.recv().await {
                    Ok(RepGossip::Sync { from, signed }) => {
                        if let Err(e) = rep.sync.apply_signed_sync(&from, &signed).await {
                            tracing::debug!("Отклонён sync репутации от {}: {}", from, e);
                        }
                    }
                    Ok(RepGossip::Report { signed }) => {
                        let reporter = NodeId(signed.signer.clone());
                        if let Err(e) = rep.reports.receive_report(signed, &reporter).await {
                            tracing::debug!("Отклонена жалоба от {}: {}", reporter, e);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Reputation gossip lagged by {}", n);
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Задача: исходящие жалобы из GUI → подписываем, применяем локально, рассылаем.
    if let Some(rep) = reputation.clone() {
        let chat_rep = chat.clone();
        let my_report_id = my_peer.id.clone();
        tokio::spawn(async move {
            while let Some((target, reason)) = report_rx.recv().await {
                if target == my_report_id {
                    tracing::warn!("Нельзя пожаловаться на себя");
                    continue;
                }
                match ReportManager::create_report(&target, reason, &rep.keypair) {
                    Ok(signed) => {
                        // Учитываем свою жалобу локально и рассылаем сети.
                        if let Err(e) = rep.reports.receive_report(signed.clone(), &my_report_id).await {
                            tracing::warn!("Локальная жалоба не принята: {}", e);
                        }
                        chat_rep.broadcast_report(signed).await;
                        tracing::info!("Отправлена жалоба на {}", target);
                    }
                    Err(e) => tracing::warn!("Не удалось создать жалобу: {}", e),
                }
            }
        });
    }

    // ── Подсистема хранилища (требует БД) ─────────────────────────────────────
    // chunk-сервер слушает base_port (он свободен: чат на +2, DM на +3),
    // download у пиров идёт именно на их base_port.
    if let Some(pool) = db_pool.clone() {
        match ChunkStore::new(data_dir.join("chunks")).await {
            Ok(store) => match StorageManager::new(pool.clone(), store, my_peer.id.clone()).await {
                Ok(mut manager) => {
                    // Подключаем события качества чанков к репутации (если включена).
                    if let Some(tx) = chunk_ev_tx.clone() {
                        manager.set_event_sink(tx);
                    }
                    // Сайты: HTTP-сервер + публикация + обнаружение по сети.
                    start_site_tasks(
                        manager.clone(), my_peer.id.clone(), site_http_port,
                        chat.clone(), Arc::clone(&sites_peers),
                        publish_site_rx, sites_out,
                    );
                    start_storage_tasks(
                        manager, pool, chat.clone(), peer_list.clone(),
                        my_peer.id.clone(), base_port, data_dir.clone(),
                        publish_rx, download_rx, storage_files_out,
                    );
                    tracing::info!("Storage subsystem ready (chunk server on {}, sites on {})",
                        base_port, site_http_port);
                }
                Err(e) => tracing::error!("StorageManager init failed: {}", e),
            },
            Err(e) => tracing::error!("ChunkStore init failed: {}", e),
        }
    } else {
        tracing::warn!("Хранилище отключено: нет БД");
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}

/// Запускает фоновые задачи сайтов: локальный HTTP-сервер раздачи (с докачкой
/// файлов чужих сайтов по запросу), публикацию каталогов как сайтов с рассылкой
/// по сети и обнаружение чужих сайтов через relay чата. Реестр in-memory.
#[allow(clippy::too_many_arguments)]
fn start_site_tasks(
    manager:    StorageManager,
    my_id:      NodeId,
    http_port:  u16,
    chat:       ChatHandle,
    peers:      Arc<Mutex<Vec<PeerInfo>>>,
    mut publish_site_rx: tokio::sync::mpsc::UnboundedReceiver<(PathBuf, String)>,
    sites_out:  Arc<Mutex<Vec<SiteInfo>>>,
) {
    let registry = SiteRegistry::new();
    let my_key = my_id.as_str().to_string();

    // HTTP-сервер сайтов (peers — источник для докачки файлов сетевых сайтов).
    let srv_reg = registry.clone();
    let srv_mgr = manager.clone();
    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
        if let Err(e) = void_web::serve(addr, srv_reg, srv_mgr, peers).await {
            tracing::error!("Site HTTP server failed on {}: {}", http_port, e);
        }
    });

    // Обнаружение чужих сайтов: манифесты из сети → реестр + снимок для GUI.
    let disc_reg  = registry.clone();
    let disc_out  = Arc::clone(&sites_out);
    let disc_key  = my_key.clone();
    let mut site_rx = chat.subscribe_sites();
    tokio::spawn(async move {
        loop {
            match site_rx.recv().await {
                Ok(manifest) => {
                    tracing::info!("Обнаружен сайт в сети: '{}' ({} файлов)",
                        manifest.name, manifest.entries.len());
                    disc_reg.register(manifest).await;
                    refresh_sites(&disc_reg, &disc_key, http_port, &disc_out).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(k)) => {
                    tracing::warn!("Site stream lagged by {}", k);
                }
                Err(_) => break,
            }
        }
    });

    // Публикация сайтов из GUI: публикуем файлы, объявляем их манифесты
    // (чтобы пиры могли докачать), затем объявляем сам сайт.
    let pub_chat = chat.clone();
    tokio::spawn(async move {
        while let Some((dir, name)) = publish_site_rx.recv().await {
            match publish_site(&manager, &dir, &name, my_id.clone()).await {
                Ok(manifest) => {
                    tracing::info!("Опубликован сайт '{}' ({} файлов) → http://127.0.0.1:{}/{}",
                        manifest.name, manifest.entries.len(), http_port, manifest.name);
                    // Объявляем каждый файл сайта (мульти-сидинг + докачка у пиров).
                    for entry in &manifest.entries {
                        if let Ok(Some(fm)) = manager.file_manifest(&entry.file_id).await {
                            pub_chat.announce_file(fm).await;
                        }
                    }
                    registry.register(manifest.clone()).await;
                    // Объявляем сайт сети.
                    pub_chat.announce_site(manifest).await;
                    refresh_sites(&registry, &my_key, http_port, &sites_out).await;
                }
                Err(e) => tracing::warn!("Публикация сайта '{}' не удалась: {}", name, e),
            }
        }
    });
}

/// Обновляет снимок списка сайтов для GUI из реестра.
async fn refresh_sites(
    registry: &SiteRegistry,
    my_key: &str,
    http_port: u16,
    out: &Arc<Mutex<Vec<SiteInfo>>>,
) {
    let infos: Vec<SiteInfo> = registry.list().await.into_iter().map(|m| SiteInfo {
        url:        format!("http://127.0.0.1:{}/{}", http_port, m.name),
        dns_name:   m.dns_name(),
        file_count: m.entries.len(),
        size_bytes: m.total_size(),
        is_mine:    m.owner.as_str() == my_key,
        name:       m.name,
    }).collect();
    *out.lock().unwrap() = infos;
}

/// Запускает фоновые задачи хранилища: chunk-сервер, обработку публикаций
/// (с рассылкой манифеста по сети), приём чужих манифестов, скачивание по
/// запросу и периодическое обновление списка файлов для GUI.
#[allow(clippy::too_many_arguments)]
fn start_storage_tasks(
    manager:    StorageManager,
    pool:       void_db::DbPool,
    chat:       ChatHandle,
    peer_list:  PeerList,
    my_id:      NodeId,
    base_port:  u16,
    data_dir:   PathBuf,
    mut publish_rx:  tokio::sync::mpsc::UnboundedReceiver<PathBuf>,
    mut download_rx: tokio::sync::mpsc::UnboundedReceiver<DownloadCmd>,
    files_out:  Arc<Mutex<Vec<StorageFileInfo>>>,
) {
    // chunk-сервер
    let srv = manager.clone();
    tokio::spawn(async move {
        if let Err(e) = srv.start_server(base_port).await {
            tracing::error!("Chunk server failed on {}: {}", base_port, e);
        }
    });

    // публикация файлов из GUI + рассылка манифеста сети
    let pub_mgr  = manager.clone();
    let pub_chat = chat.clone();
    tokio::spawn(async move {
        while let Some(path) = publish_rx.recv().await {
            match pub_mgr.publish_file(&path).await {
                Ok(fid) => {
                    tracing::info!("Опубликован {} → file_id={}",
                        path.display(), &fid[..8.min(fid.len())]);
                    // Объявляем файл сети, чтобы пиры его обнаружили.
                    match pub_mgr.file_manifest(&fid).await {
                        Ok(Some(manifest)) => pub_chat.announce_file(manifest).await,
                        Ok(None) => {}
                        Err(e) => tracing::warn!("Не удалось построить манифест {}: {}",
                            &fid[..8.min(fid.len())], e),
                    }
                }
                Err(e) => tracing::warn!("Публикация не удалась ({}): {}", path.display(), e),
            }
        }
    });

    // приём манифестов файлов из сети → регистрация файла локально
    let ann_mgr = manager.clone();
    let mut manifest_rx = chat.subscribe_manifests();
    tokio::spawn(async move {
        loop {
            match manifest_rx.recv().await {
                Ok(manifest) => {
                    let name = manifest.name.clone();
                    let n = manifest.chunks.len();
                    if let Err(e) = ann_mgr.handle_manifest(&manifest).await {
                        tracing::warn!("Не удалось обработать манифест '{}': {}", name, e);
                    } else {
                        tracing::info!("Обнаружен файл в сети: '{}' ({} чанков)", name, n);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(k)) => {
                    tracing::warn!("Manifest stream lagged by {}", k);
                }
                Err(_) => break,
            }
        }
    });

    // скачивание по запросу из GUI: старт/пауза, по задаче на файл.
    // Для каждого активного скачивания держим флаг отмены (пауза = выставить).
    let dl_mgr   = manager.clone();
    let dl_chat  = chat.clone();
    let dl_pool  = pool.clone();
    let dl_pl    = peer_list.clone();
    let downloads_dir = data_dir.join("downloads");
    // Флаги отмены активных скачиваний. Завершившаяся задача убирает свой флаг,
    // поэтому карта не растёт бесконечно.
    let cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(async move {
        while let Some(cmd) = download_rx.recv().await {
            match cmd {
                DownloadCmd::Pause(file_id) => {
                    let flag = cancels.lock().unwrap().get(&file_id).cloned();
                    if let Some(flag) = flag {
                        flag.store(true, Ordering::Relaxed);
                        tracing::info!("Пауза скачивания {}", &file_id[..8.min(file_id.len())]);
                    }
                }
                DownloadCmd::Start(file_id) => {
                    let name = match void_db::chunks::get_file(&dl_pool, &file_id).await {
                        Ok(Some(f)) => f.name,
                        Ok(None) => {
                            tracing::warn!("Скачивание: файл {} неизвестен", &file_id[..8.min(file_id.len())]);
                            continue;
                        }
                        Err(e) => { tracing::warn!("Скачивание: ошибка БД: {}", e); continue; }
                    };
                    if let Err(e) = tokio::fs::create_dir_all(&downloads_dir).await {
                        tracing::warn!("Не удалось создать папку загрузок: {}", e);
                        continue;
                    }
                    // Свежий (сброшенный) флаг отмены на этот запуск.
                    let flag = Arc::new(AtomicBool::new(false));
                    cancels.lock().unwrap().insert(file_id.clone(), Arc::clone(&flag));

                    let dest  = downloads_dir.join(&name);
                    let peers = dl_pl.all().await;
                    let mgr   = dl_mgr.clone();
                    let chat  = dl_chat.clone();
                    let cancels_task = Arc::clone(&cancels);
                    tracing::info!("Скачивание '{}' → {}", name, dest.display());
                    tokio::spawn(async move {
                        let dl_flag = Arc::clone(&flag);
                        match mgr.download_file_cancellable(&file_id, &dest, &peers, dl_flag).await {
                            Ok(()) => {
                                tracing::info!("Файл '{}' скачан в {}", name, dest.display());
                                // Мульти-сидинг: объявляем себя новым сидером.
                                if let Ok(Some(manifest)) = mgr.file_manifest(&file_id).await {
                                    chat.announce_file(manifest).await;
                                }
                            }
                            Err(void_storage::StorageError::Cancelled) =>
                                tracing::info!("Скачивание '{}' приостановлено", name),
                            Err(e) =>
                                tracing::warn!("Скачивание '{}' не удалось: {}", name, e),
                        }
                        // Убираем флаг этого запуска (если его не вытеснил новый старт).
                        let mut map = cancels_task.lock().unwrap();
                        if map.get(&file_id).map(|f| Arc::ptr_eq(f, &flag)).unwrap_or(false) {
                            map.remove(&file_id);
                        }
                    });
                }
            }
        }
    });

    // периодический снимок списка файлов для GUI (с числом сидеров из манифестов)
    let my_key = my_id.as_str().to_string();
    let snap_chat = chat.clone();
    let snap_pl   = peer_list.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            let files = match void_db::chunks::list_files(&pool).await {
                Ok(f)  => f,
                Err(e) => { tracing::warn!("list_files failed: {}", e); continue; }
            };
            // Живые узлы: активные пиры + мы сами. Сидером считаем только тех
            // владельцев из манифеста, кто сейчас на связи (приблизительно).
            let live: HashSet<String> = snap_pl.all().await
                .into_iter()
                .map(|p| p.id.as_str().to_string())
                .chain(std::iter::once(my_key.clone()))
                .collect();
            // Число живых сидеров из объединённых манифестов чата.
            let seeders: HashMap<String, i64> = snap_chat.get_manifests().await
                .into_iter()
                .map(|m| {
                    let live_count = m.owners.iter()
                        .filter(|o| live.contains(o.as_str()))
                        .count() as i64;
                    (m.file_id, live_count)
                })
                .collect();
            let mut out = Vec::with_capacity(files.len());
            for f in files {
                let progress = manager.download_progress(&f.file_id).await.unwrap_or(0.0);
                let is_mine  = f.owner_key == my_key;
                let seeders  = seeders.get(&f.file_id).copied()
                    .unwrap_or(if is_mine { 1 } else { 0 });
                out.push(StorageFileInfo {
                    is_mine,
                    seeders,
                    file_id:      f.file_id,
                    name:         f.name,
                    size_bytes:   f.size_bytes,
                    total_chunks: f.total_chunks,
                    progress,
                });
            }
            *files_out.lock().unwrap() = out;
        }
    });
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
