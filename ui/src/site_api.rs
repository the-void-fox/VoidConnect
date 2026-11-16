//! JS API сайтов на стороне приложения: что API знает об узле (профили,
//! доверие) и синхронизация общих данных сайтов по сети.
//!
//! Сам API (HTTP, разрешения, подписи) живёт в `void_web::api`; здесь —
//! связка с backend: снимки профилей и сети доверия, приём и пересылка
//! записей сайтов через чат, сверка дайджестами с соседями, объявление
//! загруженных с сайтов файлов.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc};
use void_chat::public_chat::{ChatHandle, SiteDataGossip};
use void_core::identity::NodeId;
use void_core::peer::PeerProfile;
use void_crypto::sign::SignedMessage;
use void_storage::StorageManager;
use void_trust::{TrustLevel, TrustMap};
use void_web::records::{self, Applied, SiteRecord};
use void_web::{ConsentBroker, NodeView, PermissionStore, PublicProfile, TrustTag};

/// Разрешения и вопросы к пользователю — общие для API (backend) и окна
/// приложения (диалог согласия, управление доступом сайтов).
#[derive(Clone)]
pub struct SiteAccess {
    pub permissions: PermissionStore,
    pub consent: ConsentBroker,
}

impl SiteAccess {
    pub fn load(data_dir: &std::path::Path) -> Self {
        Self {
            permissions: PermissionStore::load(data_dir.join("site_permissions.json")),
            consent: ConsentBroker::new(),
        }
    }
}

/// Узел пользователя глазами API.
pub struct BackendNodeView {
    pub my_id: NodeId,
    /// Свой профиль (последний разосланный).
    pub my_profile: Arc<Mutex<Option<PeerProfile>>>,
    pub fallback_name: String,
    /// Профили других узлов.
    pub profiles: Arc<Mutex<HashMap<NodeId, PeerProfile>>>,
    /// Снимок сети доверия.
    pub trust: Arc<Mutex<TrustMap>>,
}

fn public(p: &PeerProfile) -> PublicProfile {
    let opt = |s: &str| (!s.trim().is_empty()).then(|| s.to_string());
    PublicProfile {
        id: p.node_id.0.clone(),
        name: void_core::sanitize::display_text(&p.name, 64),
        // Чужой аватар проверяем как и для своего окна: «PNG-бомба» не уйдёт
        // в страницу сайта.
        avatar: p
            .avatar_png
            .as_deref()
            .filter(|b| crate::avatar::is_safe_avatar(b))
            .map(|b| format!("data:image/png;base64,{b}")),
        status: opt(&p.status),
        description: opt(&p.description),
    }
}

impl NodeView for BackendNodeView {
    fn me(&self) -> PublicProfile {
        match self.my_profile.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(p) => public(p),
            None => PublicProfile {
                id: self.my_id.0.clone(),
                name: self.fallback_name.clone(),
                avatar: None,
                status: None,
                description: None,
            },
        }
    }

    fn profile(&self, id: &NodeId) -> Option<PublicProfile> {
        self.profiles.lock().unwrap_or_else(|e| e.into_inner()).get(id).map(public)
    }

    fn trust(&self, id: &NodeId) -> TrustTag {
        let level = self.trust.lock().map(|m| m.level(id)).unwrap_or(TrustLevel::Stranger);
        match level {
            TrustLevel::Verified => TrustTag::Verified,
            TrustLevel::Trusted => TrustTag::Trusted,
            TrustLevel::Settled => TrustTag::Settled,
            TrustLevel::Stranger => TrustTag::Stranger,
            TrustLevel::Blocked => TrustTag::Blocked,
        }
    }
}

/// Сколько записей автора на одном сайте храним — по доверию к нему. Бот-ферма
/// незнакомцев не забьёт базу: у каждого ключа маленькая квота.
fn quota(level: TrustLevel) -> i64 {
    match level {
        TrustLevel::Verified | TrustLevel::Trusted => 5_000,
        TrustLevel::Settled => 1_000,
        TrustLevel::Stranger => 200,
        TrustLevel::Blocked => 0,
    }
}

/// Сколько записей досылаем соседу за один ответ на дайджест.
const SYNC_LIMIT: usize = 2_000;
/// Как часто сверяемся с соседями (кроме момента новой связи).
const DIGEST_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Каналы между API и backend.
pub struct SiteDataChannels {
    /// Свои новые записи (из API) → разослать.
    pub record_rx: mpsc::UnboundedReceiver<SignedMessage>,
    /// Файлы, загруженные сайтами → объявить сети.
    pub file_rx: mpsc::UnboundedReceiver<String>,
    /// Изменения записей → потоки событий API.
    pub events: broadcast::Sender<SiteRecord>,
}

/// Фоновые задачи данных сайтов.
pub fn start_site_data_tasks(
    chat: ChatHandle,
    pool: void_db::DbPool,
    manager: StorageManager,
    trust: Arc<Mutex<TrustMap>>,
    ch: SiteDataChannels,
) {
    let SiteDataChannels { mut record_rx, mut file_rx, events } = ch;

    // Свои записи → соседям.
    let out_chat = chat.clone();
    tokio::spawn(async move {
        while let Some(signed) = record_rx.recv().await {
            out_chat.relay_site_record(signed, None).await;
        }
    });

    // Загрузки с сайтов → объявление файла сети (как публикация из окна).
    let file_chat = chat.clone();
    tokio::spawn(async move {
        while let Some(fid) = file_rx.recv().await {
            match manager.file_manifest(&fid).await {
                Ok(Some(m)) => {
                    tracing::info!("Файл с сайта опубликован: '{}' ({})", m.name, &fid[..8.min(fid.len())]);
                    file_chat.announce_file(m).await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("Манифест загруженного файла: {}", e),
            }
        }
    });

    // Записи из сети: проверка, квота по доверию, пересылка новых.
    let in_chat = chat.clone();
    let in_pool = pool.clone();
    let mut data_rx = chat.subscribe_site_data();
    tokio::spawn(async move {
        loop {
            let gossip = match data_rx.recv().await {
                Ok(g) => g,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Данные сайтов: пропущено {} пакетов (догонятся по дайджесту)", n);
                    continue;
                }
                Err(_) => break,
            };
            match gossip {
                SiteDataGossip::Record { signed, from } => {
                    if let Some(rec) = apply(&in_pool, &trust, &signed).await {
                        in_chat.relay_site_record(signed, Some(&from)).await;
                        let _ = events.send(rec);
                    }
                }
                SiteDataGossip::Sync { records, .. } => {
                    for signed in records {
                        if let Some(rec) = apply(&in_pool, &trust, &signed).await {
                            let _ = events.send(rec);
                        }
                    }
                }
                SiteDataGossip::Digest { items, from } => {
                    match records::missing_for(&in_pool, &items, SYNC_LIMIT).await {
                        Ok(missing) if !missing.is_empty() => {
                            tracing::debug!("Досылаю соседу {} записей сайтов", missing.len());
                            in_chat.push_site_records(&from, missing).await;
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("Дайджест записей сайтов: {}", e),
                    }
                }
            }
        }
    });

    // Сверка с соседями: при новой связи и раз в несколько минут.
    let dg_chat = chat.clone();
    let mut links = chat.subscribe_links();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(DIGEST_EVERY);
        tick.tick().await;
        loop {
            let peers: Vec<NodeId> = tokio::select! {
                link = links.recv() => match link {
                    Ok(peer) => vec![peer],
                    Err(broadcast::error::RecvError::Lagged(_)) => dg_chat.neighbors().await,
                    Err(_) => break,
                },
                _ = tick.tick() => dg_chat.neighbors().await,
            };
            if peers.is_empty() {
                continue;
            }
            let items = match records::digest(&pool).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("Дайджест записей сайтов: {}", e);
                    continue;
                }
            };
            for peer in peers {
                dg_chat.send_site_digest(&peer, items.clone()).await;
            }
        }
    });
}

/// Принимает запись из сети. `Some` — база изменилась.
async fn apply(pool: &void_db::DbPool, trust: &Arc<Mutex<TrustMap>>, signed: &SignedMessage) -> Option<SiteRecord> {
    let author = NodeId(signed.signer.clone());
    let level = trust.lock().map(|m| m.level(&author)).unwrap_or(TrustLevel::Stranger);
    let now = chrono::Utc::now().timestamp_millis();
    match records::apply_signed(pool, signed, quota(level), now).await {
        Ok(Applied::Changed(rec)) => Some(rec),
        Ok(Applied::Stale) => None,
        Ok(Applied::Refused(why)) => {
            tracing::debug!("Запись сайта от {} не принята: {}", &author.0[..8.min(author.0.len())], why);
            None
        }
        Err(e) => {
            tracing::debug!("Запись сайта отклонена: {}", e);
            None
        }
    }
}
