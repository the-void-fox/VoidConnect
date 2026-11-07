//! Мост между асинхронным бэкендом (tokio) и синхронным GUI (egui).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use void_core::dns::{DnsKind, DnsRecord};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile, Service};
use void_chat::public_chat::{start_public_chat, ChatHandle, ChatMessage, VoteGossip};
use void_chat::trust_limits::AuthorTier;
use void_chat::private_chat::{start_private_chat, IncomingDm, DmSendCmd, PrivateChatHandle};
use void_crypto::keys::{EncryptionKeypair, SigningKeypair};
use void_crypto::sign::SignedMessage;
use void_discovery::PeerList;
use void_network::secure::NoiseIdentity;
use void_storage::{ChunkEvent, ChunkStore, StorageManager};
use void_reputation::{
    EventProcessor, RateLimiter, ReportManager, ReportReason, ReputationEvent, ScoreManager,
};
use void_core::site::SiteRevocation;
use void_web::{publish_site, DnsRegistry, SiteRegistry};

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
    /// Исходный публикатор файла (его публичный ключ = ID). Сохраняется навсегда
    /// при первом появлении файла — по нему файлы группируются в «папки» и можно
    /// найти/пожаловаться на того, кто опубликовал вредоносный контент.
    pub owner_key:    String,
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
    /// Мы держим кэш-копию (зеркало) сайта и помогаем его раздавать.
    pub is_mirrored: bool,
    /// Локальный URL для открытия в браузере.
    pub url:        String,
}

/// Запись внутреннего DNS (.void) — снимок для GUI.
#[derive(Clone)]
pub struct DnsInfo {
    /// Полное имя в зоне, напр. `vasya.void`.
    pub dns_name:    String,
    /// "узел" | "сайт".
    pub kind:        String,
    /// Короткий ID владельца.
    pub owner_short: String,
    /// IP (для узлов), если известен.
    pub ip:          Option<String>,
    /// Запись принадлежит нам.
    pub is_mine:     bool,
}

/// Сервис внутреннего DNS зоны `.void`: подпись/заявка наших имён, применение
/// чужих записей и перерассылка наших новым пирам. Тонкая обёртка над
/// [`DnsRegistry`] + relay чата. Клонируется дёшево (всё внутри — Arc/clone).
#[derive(Clone)]
struct DnsService {
    registry: DnsRegistry,
    chat:     ChatHandle,
    keypair:  Arc<SigningKeypair>,
    my_id:    NodeId,
    /// Снимок известных имён для GUI.
    snapshot: Arc<Mutex<Vec<DnsInfo>>>,
    /// Файл таблицы имён: занятые имена переживают перезапуск (иначе после
    /// рестарта имя достаётся тому, кто первым его снова объявит).
    store:    PathBuf,
}

impl DnsService {
    /// Заявляет наше имя (подписывает запись, применяет локально, рассылает сети).
    /// Конфликт имён разрешит [`DnsRegistry`] (первый по времени).
    async fn claim(&self, kind: DnsKind, name: &str, ip: Option<String>, port: Option<u16>) {
        let record = DnsRecord {
            name: name.to_string(),
            kind,
            node_id: self.my_id.clone(),
            ip,
            port,
            created_at: chrono::Utc::now().timestamp(),
            updated_at: chrono::Utc::now().timestamp_millis(),
            deleted: false,
        };
        let signed = match SignedMessage::sign(record.to_bytes(), &self.keypair) {
            Ok(s) => s,
            Err(e) => { tracing::warn!("DNS: не удалось подписать запись '{}': {}", name, e); return; }
        };
        match self.registry.apply_signed(&signed).await {
            Ok(Some(_)) => {
                tracing::info!("Заявлено DNS-имя '{}.void'", name);
                self.chat.announce_dns(signed).await;
                self.refresh().await;
            }
            Ok(None) => tracing::debug!("DNS-имя '{}.void' уже занято/без изменений", name),
            Err(e)   => tracing::warn!("DNS-заявка '{}' отклонена: {}", name, e),
        }
    }

    /// Применяет входящую (чужую) запись из сети.
    async fn apply_incoming(&self, signed: SignedMessage) {
        match self.registry.apply_signed(&signed).await {
            Ok(Some(rec)) => {
                tracing::info!("DNS: запись '{}.void' от {}", rec.name, rec.node_id);
                self.refresh().await;
            }
            Ok(None) => {}
            Err(e)   => tracing::debug!("DNS: запись отклонена: {}", e),
        }
    }

    /// Отзывает наше DNS-имя (надгробие): помечает запись удалённой, сохраняя
    /// `created_at` (имя остаётся зарезервированным за нами по «первый по
    /// времени»), применяет локально и рассылает сети. Имя перестаёт резолвиться
    /// и исчезает из списков, но переопубликовать его можем только мы.
    async fn revoke(&self, name: &str) {
        let key = name.trim_end_matches(".void");
        // Берём текущую запись (она ещё не удалена → resolve её вернёт).
        let Some(mut rec) = self.registry.resolve(key).await else { return };
        if rec.node_id != self.my_id { return; } // отзываем только своё
        rec.deleted = true;
        rec.updated_at = chrono::Utc::now().timestamp_millis().max(rec.updated_at + 1);
        let signed = match SignedMessage::sign(rec.to_bytes(), &self.keypair) {
            Ok(s) => s,
            Err(e) => { tracing::warn!("DNS: не удалось подписать надгробие '{}': {}", key, e); return; }
        };
        match self.registry.apply_signed(&signed).await {
            Ok(Some(_)) => {
                tracing::info!("DNS-имя '{}.void' отозвано (надгробие)", key);
                self.chat.announce_dns(signed).await;
                self.refresh().await;
            }
            Ok(None) => {}
            Err(e)   => tracing::warn!("DNS: надгробие '{}' отклонено: {}", key, e),
        }
    }

    /// Перерассылает наши записи (например, при появлении новых пиров).
    async fn reannounce(&self) {
        for signed in self.registry.mine(&self.my_id).await {
            self.chat.announce_dns(signed).await;
        }
    }

    /// Загружает сохранённую таблицу имён (записи проверяются как из сети).
    async fn load(&self) {
        let Ok(json) = std::fs::read_to_string(&self.store) else { return };
        match serde_json::from_str::<Vec<SignedMessage>>(&json) {
            Ok(records) => {
                let n = self.registry.import(&records).await;
                tracing::info!("DNS: загружено {} сохранённых имён", n);
            }
            Err(e) => tracing::warn!("DNS: файл {} повреждён: {}", self.store.display(), e),
        }
    }

    /// Сохраняет таблицу имён (временный файл → rename, без «полузаписанного» JSON).
    async fn save(&self) {
        let records = self.registry.export().await;
        let Ok(json) = serde_json::to_vec(&records) else { return };
        let tmp = self.store.with_extension("json.tmp");
        if std::fs::write(&tmp, json).and_then(|_| std::fs::rename(&tmp, &self.store)).is_err() {
            tracing::warn!("DNS: не удалось сохранить {}", self.store.display());
        }
    }

    /// Обновляет снимок имён для GUI и сохраняет таблицу на диск.
    async fn refresh(&self) {
        self.save().await;
        let my_key = self.my_id.as_str();
        let infos: Vec<DnsInfo> = self.registry.list().await.into_iter().map(|r| {
            let owner = r.node_id.as_str();
            let owner_short = format!("{}…", &owner[..8.min(owner.len())]);
            DnsInfo {
                dns_name:    r.dns_name(),
                kind:        match r.kind { DnsKind::Node => "узел", DnsKind::Site => "сайт" }.into(),
                owner_short,
                ip:          r.ip,
                is_mine:     owner == my_key,
            }
        }).collect();
        *self.snapshot.lock().unwrap() = infos;
    }
}

/// Команда GUI → backend для сети доверия.
#[derive(Clone, Debug)]
pub enum TrustCmd {
    /// Поручиться за узел лично (код безопасности сверён). Публично.
    Vouch(NodeId),
    /// Поприветствовать новичка (роль встречающего): слабое публичное
    /// поручительство «похож на живого человека», вес ×0.3 от личного.
    Greet(NodeId),
    /// Отозвать своё поручительство (или снять локальную отметку).
    Revoke(NodeId),
    /// Опубликовать старые локальные отметки «проверен» как поручительства.
    PublishPrivate,
    /// Принять запрос в личку: узел пишет во «Входящие» (не поручительство).
    Allow(NodeId),
    /// Заблокировать узел (в том числе «Отклонить» запрос в личку).
    Block(NodeId),
    Unblock(NodeId),
}

/// Подробности сети доверия для GUI: кого я поприветствовал и что мой узел
/// видел за узлами (подсказка «когда освоится по поведению»).
#[derive(Default, Clone)]
pub struct TrustDetails {
    pub greeted: HashSet<NodeId>,
    pub activity: HashMap<NodeId, void_trust::store::Activity>,
}

/// Сеть доверия: подпись своих поручительств, приём чужих (пересылаем дальше
/// только то, что изменило нашу базу), передача графа новым связям, пересчёт
/// доверия и наблюдения для уровня «освоившийся». Клонируется дёшево.
#[derive(Clone)]
struct TrustService {
    pool:      void_db::DbPool,
    chat:      ChatHandle,
    keypair:   Arc<SigningKeypair>,
    my_id:     NodeId,
    /// Снимок доверия для GUI и остальных подсистем.
    snapshot:  Arc<Mutex<void_trust::TrustMap>>,
    /// Неопубликованные отметки «проверен» (см. `verify_store`).
    private:   Arc<Mutex<HashSet<NodeId>>>,
    /// Баны голосованием (NodeId → ts истечения) — для расчёта это «заблокированные».
    blocklist: Arc<Mutex<HashMap<NodeId, i64>>>,
    /// Сколько узлов поручились за нас (подсказка новичку в чате).
    my_vouchers: Arc<AtomicUsize>,
    /// Доступ к личке: разрешённые, заблокированные мной, запросы.
    access:    Arc<Mutex<crate::dm_access::DmAccess>>,
    /// Подробности для GUI (мои приветствия, наблюдения).
    details:   Arc<Mutex<TrustDetails>>,
    /// Сигнал «граф изменился — пересчитать».
    dirty:     Arc<tokio::sync::Notify>,
}

impl TrustService {
    fn start(self, peer_list: PeerList, mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<TrustCmd>) {
        // Команды GUI: свои действия пересчитываем сразу (бейдж меняется без задержки).
        let svc = self.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    TrustCmd::Vouch(id)     => svc.set_vouch(&id, void_trust::VouchKind::Personal, false).await,
                    TrustCmd::Greet(id)     => svc.set_vouch(&id, void_trust::VouchKind::Greeter, false).await,
                    TrustCmd::Revoke(id)    => svc.set_vouch(&id, void_trust::VouchKind::Personal, true).await,
                    TrustCmd::PublishPrivate => svc.publish_private().await,
                    TrustCmd::Allow(id)     => update_access(&svc.access, |a| a.allow(id.as_str())),
                    TrustCmd::Block(id)     => update_access(&svc.access, |a| a.block(id.as_str())),
                    TrustCmd::Unblock(id)   => update_access(&svc.access, |a| a.unblock(id.as_str())),
                }
                svc.recompute().await;
            }
        });

        // Входящие поручительства.
        let svc = self.clone();
        let mut vouch_rx = self.chat.subscribe_vouches();
        tokio::spawn(async move {
            loop {
                match vouch_rx.recv().await {
                    Ok(g) => svc.apply_incoming(g).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Поручительства: пропущено {} (переполнение)", n);
                    }
                    Err(_) => break,
                }
            }
        });

        // Новая связь: передаём соседу граф — так новичок узнаёт поручительства,
        // даже не связанный напрямую с поручителями.
        let svc = self.clone();
        let mut link_rx = self.chat.subscribe_links();
        tokio::spawn(async move {
            loop {
                match link_rx.recv().await {
                    Ok(peer) => svc.sync_to(&peer).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
            }
        });

        // Пересчёт: после изменений графа (с задержкой, чтобы собрать пачку) и раз
        // в минуту; раз в минуту же отмечаем, кого видим в сети.
        let svc = self;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = tick.tick() => svc.note_online(&peer_list).await,
                    _ = svc.dirty.notified() => {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
                svc.recompute().await;
            }
        });
    }

    /// Ставит (или отзывает) наше поручительство за `subject` и рассылает его.
    /// Приветствие не понижает уже выданное личное поручительство; отзыв
    /// снимает любое (вид берётся у действующего).
    async fn set_vouch(&self, subject: &NodeId, kind: void_trust::VouchKind, revoked: bool) {
        if *subject == self.my_id || !void_core::sanitize::is_hex64(subject.as_str()) {
            return;
        }
        // Отметка больше не «только у меня»: она опубликована либо снята.
        self.forget_private(subject);
        let prev = void_trust::store::get_vouch(&self.pool, &self.my_id, subject).await.ok().flatten();
        let Some(kind) = next_vouch_kind(prev.as_ref(), kind, revoked) else { return };
        let updated_at = chrono::Utc::now().timestamp_millis()
            .max(prev.map(|p| p.updated_at + 1).unwrap_or(0));
        let vouch = void_trust::Vouch {
            voucher: self.my_id.clone(),
            subject: subject.clone(),
            kind,
            updated_at,
            revoked,
        };
        let signed = match vouch.sign(&self.keypair) {
            Ok(s) => s,
            Err(e) => { tracing::warn!("Поручительство не подписано: {}", e); return; }
        };
        match void_trust::store::apply_signed(&self.pool, &signed).await {
            Ok(Some(_)) => {
                tracing::info!("{} поручительство за {}", if revoked { "Отозвано" } else { "Выдано" }, subject);
                self.chat.relay_vouch(signed, None).await;
            }
            Ok(None) => tracing::warn!("Поручительство за {} не сохранено (лимит)", subject),
            Err(e) => tracing::warn!("Поручительство за {}: {}", subject, e),
        }
    }

    /// Публикует старые локальные отметки «проверен».
    async fn publish_private(&self) {
        let ids: Vec<NodeId> = self.private.lock().unwrap().iter().cloned().collect();
        for id in ids {
            self.set_vouch(&id, void_trust::VouchKind::Personal, false).await;
        }
    }

    fn forget_private(&self, id: &NodeId) {
        let mut private = self.private.lock().unwrap();
        if private.remove(id) {
            crate::verify_store::save_verified(&private.iter().map(|n| n.as_str().to_string()).collect());
        }
    }

    /// Чужое поручительство: в базу, и дальше — только если что-то изменилось.
    async fn apply_incoming(&self, g: void_chat::public_chat::VouchGossip) {
        match void_trust::store::apply_signed(&self.pool, &g.signed).await {
            Ok(Some(_)) => {
                self.chat.relay_vouch(g.signed, Some(&g.from)).await;
                self.dirty.notify_one();
            }
            Ok(None) => {}
            Err(e) => tracing::debug!("Поручительство от {} отклонено: {}", g.from, e),
        }
    }

    async fn sync_to(&self, peer: &NodeId) {
        match void_trust::store::signed_vouches(&self.pool).await {
            Ok(all) if !all.is_empty() => self.chat.push_vouches(peer, all).await,
            Ok(_) => {}
            Err(e) => tracing::warn!("Граф доверия не прочитан: {}", e),
        }
    }

    async fn note_online(&self, peer_list: &PeerList) {
        let now = chrono::Utc::now().timestamp();
        for p in peer_list.all().await {
            if void_core::sanitize::is_hex64(p.id.as_str()) {
                let _ = void_trust::store::note_seen(&self.pool, &p.id, now).await;
            }
        }
    }

    async fn recompute(&self) {
        let now = chrono::Utc::now().timestamp();
        let vouches = void_trust::store::load_vouches(&self.pool).await.unwrap_or_default();
        let settled = void_trust::store::settled(&self.pool, now).await.unwrap_or_default();
        let mine = vouches.iter().filter(|v| v.subject == self.my_id && !v.revoked).count();
        self.my_vouchers.store(mine, Ordering::Relaxed);
        let greeted = vouches.iter()
            .filter(|v| v.voucher == self.my_id && !v.revoked && v.kind == void_trust::VouchKind::Greeter)
            .map(|v| v.subject.clone())
            .collect();
        let activity = void_trust::store::activity(&self.pool).await.unwrap_or_default();
        *self.details.lock().unwrap() = TrustDetails { greeted, activity };
        let mut blocked: HashSet<NodeId> = self.blocklist.lock().unwrap().iter()
            .filter(|(_, until)| **until > now)
            .map(|(id, _)| id.clone())
            .collect();
        blocked.extend(self.access.lock().unwrap().blocked.iter().cloned().map(NodeId));
        let private = self.private.lock().unwrap().clone();
        let compute = |reported: &HashSet<NodeId>| void_trust::compute(&void_trust::TrustInputs {
            me: &self.my_id,
            vouches: &vouches,
            blocked: &blocked,
            reported,
            settled: &settled,
            private_verified: &private,
        });
        // Вес жалобы — доверие к заявителю, посчитанное без учёта жалоб (иначе
        // круг); найденные цели «под жалобами» — во втором проходе.
        let base = compute(&HashSet::new());
        let reported = void_trust::reported(&base, &self.my_id, &self.recent_reports(now).await);
        let map = if reported.is_empty() { base } else { compute(&reported) };
        *self.snapshot.lock().unwrap() = map;
    }

    /// Пары (цель, заявитель) жалоб, полученных за срок учёта (30 дней).
    async fn recent_reports(&self, now: i64) -> Vec<(NodeId, NodeId)> {
        let since = chrono::DateTime::from_timestamp(now - void_reputation::reports::REPORT_MAX_AGE_SECS, 0)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        void_db::peers::recent_report_pairs(&self.pool, &since)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(target, reporter)| (NodeId(target), NodeId(reporter)))
            .collect()
    }
}

/// Какой вид записать в нашу новую версию поручительства (`None` — ничего не
/// менять): отзывать нечего — пропуск; приветствие не понижает уже выданное
/// (личное или приветствие); отзыв сохраняет вид действующего.
fn next_vouch_kind(
    prev: Option<&void_trust::Vouch>,
    kind: void_trust::VouchKind,
    revoked: bool,
) -> Option<void_trust::VouchKind> {
    let active = prev.filter(|p| !p.revoked).map(|p| p.kind);
    match (revoked, active) {
        (true, None) => None,
        (true, Some(current)) => Some(current),
        (false, Some(_)) if kind == void_trust::VouchKind::Greeter => None,
        (false, _) => Some(kind),
    }
}

/// Меняет доступ к личке и сохраняет его на диск.
fn update_access(access: &Mutex<crate::dm_access::DmAccess>, f: impl FnOnce(&mut crate::dm_access::DmAccess)) {
    let mut a = access.lock().unwrap();
    let before = a.clone();
    f(&mut a);
    if *a != before {
        crate::dm_access::save(&a);
    }
}

/// Уровень автора для лимитов чата — по снимку сети доверия.
fn author_tier(snapshot: &Mutex<void_trust::TrustMap>, id: &NodeId) -> AuthorTier {
    use void_trust::TrustLevel::*;
    match snapshot.lock().map(|m| m.level(id)).unwrap_or(Stranger) {
        Verified | Trusted => AuthorTier::Trusted,
        Settled => AuthorTier::Settled,
        Stranger | Blocked => AuthorTier::Stranger,
    }
}

/// Команда GUI → backend для зеркалирования (кэширования) чужого сайта.
#[derive(Clone, Debug)]
pub enum MirrorCmd {
    /// Закэшировать сайт целиком и стать его сидером (по имени сайта).
    Mirror(String),
    /// Перестать кэшировать сайт: убрать из набора и стереть его файлы.
    Unmirror(String),
    /// Удалить НАШ сайт: разослать надгробие, стереть файлы, отозвать домен.
    Delete(String),
}

/// Команда GUI → backend для управления скачиванием файла.
#[derive(Clone, Debug)]
pub enum DownloadCmd {
    /// Начать (или продолжить) скачивание файла по его file_id.
    Start(String),
    /// Поставить на паузу скачивание файла по его file_id.
    Pause(String),
    /// Удалить файл из СЕТИ целиком. Разрешено только владельцу и только если файл
    /// больше никто (из живых узлов) не раздаёт: стираем локально + подавляем
    /// «воскрешение» входящим манифестом.
    Remove(String),
    /// Убрать только свою ЛОКАЛЬНУЮ копию (перестать раздавать). Доступно всем, кто
    /// скачал файл; сам файл остаётся в сети у других сидеров.
    RemoveLocal(String),
}

/// Компоненты системы репутации (локальное качество раздачи + приём жалоб),
/// разделяемые между фоновыми задачами.
#[derive(Clone)]
struct Reputation {
    score:   ScoreManager,
    events:  EventProcessor,
    reports: ReportManager,
    /// Наш ключ подписи — для создания подписанных жалоб.
    keypair: Arc<SigningKeypair>,
}

/// Состояние доставки исходящего личного сообщения (для индикации в UI).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryState {
    /// Отправляется / стоит в очереди на повтор.
    Sending,
    /// Подтверждена запись получателю (прямо или через relay).
    Delivered,
    /// Не доставлено после всех попыток.
    Failed,
}

/// Смещение порта DM-сервера относительно базового порта узла (base + 3).
const DM_PORT_OFFSET: u16 = 3;
/// Период повторной попытки доставки недоставленного DM.
const DM_RETRY_SECS: u64 = 15;
/// Максимум попыток доставки, после чего DM помечается как Failed.
const DM_MAX_ATTEMPTS: u32 = 20;

/// Недоставленное личное сообщение в очереди на повтор.
struct PendingDm {
    cmd:      DmSendCmd,
    attempts: u32,
    next_at:  std::time::Instant,
}

/// Записать статус доставки DM (для опроса из GUI).
fn set_dm_status(
    map: &Arc<Mutex<HashMap<String, DeliveryState>>>,
    message_id: &str,
    state: DeliveryState,
) {
    map.lock().unwrap().insert(message_id.to_string(), state);
}

/// Одна попытка доставки DM: сначала прямое соединение (`send_dm`), затем
/// fallback через все известные relay. Возвращает `true`, если доставлено.
async fn try_deliver_dm(
    dm_h:      &PrivateChatHandle,
    relay_set: &Arc<Mutex<HashSet<String>>>,
    noise:     &NoiseIdentity,
    cmd:       &DmSendCmd,
) -> bool {
    // Марку работы — до любых соединений: её подбор занимает секунды.
    dm_h.prepare_stamp(cmd).await;
    // send_dm переиспользует уже поднятое соединение (в т.ч. relay-туннель),
    // иначе пытается прямой дозвон.
    if dm_h.send_dm(cmd.clone()).await.is_ok() {
        return true;
    }
    // Снимок текущих relay-адресов (статические + узнанные по gossip).
    let relay_addrs: Vec<String> = { relay_set.lock().unwrap().iter().cloned().collect() };
    for raddr in &relay_addrs {
        match void_discovery::relay::open_tunnel(raddr, noise, &cmd.to).await {
            Ok(stream) => {
                // Поверх relay-хопа DM проводит своё сквозное Noise-рукопожатие с
                // `cmd.to` — relay не может ни прочитать, ни подменить собеседника.
                if let Err(e) = dm_h.send_dm_over_stream(cmd.clone(), Box::new(stream)).await {
                    tracing::debug!("DM через relay {} не прошёл: {}", raddr, e);
                } else {
                    tracing::info!("DM доставлено через relay {}", raddr);
                    return true;
                }
            }
            Err(e) => tracing::debug!("relay {} недоступен: {}", raddr, e),
        }
    }
    false
}

pub struct BackendHandle {
    pub chat_inbox:    Arc<Mutex<VecDeque<ChatMessage>>>,
    /// Канал GUI → backend: отправить сообщение общего чата как `(канал, текст)`.
    pub chat_sender:   tokio::sync::mpsc::UnboundedSender<(String, String)>,
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
    /// Входящие расшифрованные личные сообщения (опрашивается GUI каждый кадр)
    pub dm_inbox:      Arc<Mutex<VecDeque<IncomingDm>>>,
    /// Канал GUI → backend: отправить DM пиру
    pub dm_sender:     tokio::sync::mpsc::UnboundedSender<DmSendCmd>,
    /// Статус доставки исходящих DM: message_id → состояние. Опрашивается GUI.
    pub dm_status:     Arc<Mutex<HashMap<String, DeliveryState>>>,
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
    /// Снимок жалоб на известные узлы: NodeId → список жалоб (дошедших до нас).
    pub reports: Arc<Mutex<HashMap<NodeId, Vec<void_db::peers::ReportRow>>>>,
    /// Канал GUI → backend: пожаловаться на узел (target, причина).
    pub report_tx: tokio::sync::mpsc::UnboundedSender<(NodeId, ReportReason)>,
    /// Запущены ли мы в публичном (bootstrap) режиме.
    pub bootstrap: bool,
    /// Подключены ли мы к глобальной сети как клиент (заданы bootstrap-узлы).
    pub has_bootstrap: bool,
    /// Канал GUI → backend: опубликовать сайт (каталог, имя).
    pub publish_site_tx: tokio::sync::mpsc::UnboundedSender<(PathBuf, String)>,
    /// Канал GUI → backend: зеркалировать / убрать из кэша сайт (по имени).
    pub mirror_tx: tokio::sync::mpsc::UnboundedSender<MirrorCmd>,
    /// Снимок списка сайтов (обновляется бэкендом).
    pub sites: Arc<Mutex<Vec<SiteInfo>>>,
    /// Порт локального HTTP-сервера сайтов (base_port + 4).
    pub site_http_port: u16,
    /// Снимок известных имён внутреннего DNS (.void).
    pub dns_names: Arc<Mutex<Vec<DnsInfo>>>,
    /// Доступны ли наши порты извне (по обратной пробе bootstrap-узла).
    /// `Unknown`, пока нет bootstrap-узлов или первый обмен не завершён.
    pub reachability: Arc<Mutex<void_discovery::bootstrap::Reachability>>,

    // ── Голосования (void-vote) ──────────────────────────────────────────────
    /// Канал GUI → backend: создать предложение (gated: нужна High-репутация).
    pub propose_tx: tokio::sync::mpsc::UnboundedSender<void_vote::ProposalKind>,
    /// Канал GUI → backend: проголосовать `(proposal_id, choice)`.
    pub vote_cast_tx: tokio::sync::mpsc::UnboundedSender<(String, bool)>,
    /// Снимок предложений + подсчёт для GUI (обновляется бэкендом).
    pub proposals: Arc<Mutex<Vec<crate::vote_service::ProposalView>>>,
    /// Локальный блок-лист по итогам BanUser: NodeId → unix-таймстемп истечения.
    pub blocklist: Arc<Mutex<HashMap<NodeId, i64>>>,
    /// Каналы чата, добавленные голосованием (мерджатся со встроенными).
    pub voted_channels: Arc<Mutex<Vec<crate::vote_service::ChannelDef>>>,

    // ── Статистика сессии (для профиля) ──────────────────────────────────────
    /// Момент старта бэкенда — для подсчёта аптайма сессии.
    pub start_time: std::time::Instant,
    /// Всего отдано байт чанков пирам за сессию.
    pub bytes_uploaded: Arc<AtomicU64>,
    /// Всего принято байт чанков по сети за сессию.
    pub bytes_downloaded: Arc<AtomicU64>,
    /// Снимок доверия к узлам (сеть доверия, от лица нашего узла).
    pub trust: Arc<Mutex<void_trust::TrustMap>>,
    /// Неопубликованные отметки «проверен» (старые локальные).
    pub private_verified: Arc<Mutex<HashSet<NodeId>>>,
    /// Команды сети доверия: поручиться / отозвать / опубликовать старые отметки.
    pub trust_tx: tokio::sync::mpsc::UnboundedSender<TrustCmd>,
    /// Сколько узлов поручились за нас (0 — для других узлов мы новичок).
    pub my_vouchers: Arc<AtomicUsize>,
    /// Мои приветствия и наблюдения за узлами (для профиля узла).
    pub trust_details: Arc<Mutex<TrustDetails>>,
    /// Сколько живых связей у общего чата (0 — сообщения пока никуда не уходят).
    pub chat_links: Arc<AtomicUsize>,
    /// Доступ к личке: разрешённые, заблокированные мной, запросы (меняется
    /// командами `TrustCmd::{Allow, Block, Unblock}`).
    pub dm_access: Arc<Mutex<crate::dm_access::DmAccess>>,
}

#[allow(clippy::too_many_arguments)]
pub fn start_backend(
    name:        String,
    base_port:   u16,
    my_id:       NodeId,
    local_mode:  bool,
    public_mode: bool,
    bootstrap_addrs: Vec<String>,
    enc_kp:      Arc<EncryptionKeypair>,
    sign_kp:     Arc<SigningKeypair>,
    data_dir:   PathBuf,
) -> BackendHandle {
    let chat_inbox:    Arc<Mutex<VecDeque<ChatMessage>>>         = Arc::new(Mutex::new(VecDeque::new()));
    let peers:         Arc<Mutex<Vec<PeerInfo>>>                  = Arc::new(Mutex::new(Vec::new()));
    let peer_profiles: Arc<Mutex<HashMap<NodeId, PeerProfile>>>  = Arc::new(Mutex::new(HashMap::new()));
    let dm_inbox:      Arc<Mutex<VecDeque<IncomingDm>>>          = Arc::new(Mutex::new(VecDeque::new()));
    let dm_status:     Arc<Mutex<HashMap<String, DeliveryState>>> = Arc::new(Mutex::new(HashMap::new()));
    let chat_history:  Arc<Mutex<Option<Vec<ChatMessage>>>>     = Arc::new(Mutex::new(None));
    let storage_files: Arc<Mutex<Vec<StorageFileInfo>>>         = Arc::new(Mutex::new(Vec::new()));
    let peer_reputation: Arc<Mutex<HashMap<NodeId, f64>>>       = Arc::new(Mutex::new(HashMap::new()));
    let reports: Arc<Mutex<HashMap<NodeId, Vec<void_db::peers::ReportRow>>>> = Arc::new(Mutex::new(HashMap::new()));
    let reachability: Arc<Mutex<void_discovery::bootstrap::Reachability>> =
        Arc::new(Mutex::new(void_discovery::bootstrap::Reachability::Unknown));

    let (chat_tx,    chat_rx)    = tokio::sync::mpsc::unbounded_channel::<(String, String)>();
    let (connect_tx, connect_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (profile_tx, profile_rx) = tokio::sync::mpsc::unbounded_channel::<PeerProfile>();
    let (dm_tx,      dm_rx)      = tokio::sync::mpsc::unbounded_channel::<DmSendCmd>();
    let (publish_tx, publish_rx) = tokio::sync::mpsc::unbounded_channel::<PathBuf>();
    let (download_tx, download_rx) = tokio::sync::mpsc::unbounded_channel::<DownloadCmd>();
    let (report_tx, report_rx) = tokio::sync::mpsc::unbounded_channel::<(NodeId, ReportReason)>();
    let (publish_site_tx, publish_site_rx) = tokio::sync::mpsc::unbounded_channel::<(PathBuf, String)>();
    let (mirror_tx,  mirror_rx)  = tokio::sync::mpsc::unbounded_channel::<MirrorCmd>();
    let (propose_tx, propose_rx) = tokio::sync::mpsc::unbounded_channel::<void_vote::ProposalKind>();
    let (vote_cast_tx, vote_cast_rx) = tokio::sync::mpsc::unbounded_channel::<(String, bool)>();
    let sites: Arc<Mutex<Vec<SiteInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let dns_names: Arc<Mutex<Vec<DnsInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let site_http_port = base_port + 4;

    // Состояние голосований (восстанавливаем исполненные решения с диска).
    let proposals: Arc<Mutex<Vec<crate::vote_service::ProposalView>>> = Arc::new(Mutex::new(Vec::new()));
    let blocklist: Arc<Mutex<HashMap<NodeId, i64>>> = Arc::new(Mutex::new(
        crate::vote_service::load_bans()
            .into_iter()
            .map(|(k, v)| (NodeId(k), v))
            .collect(),
    ));
    let voted_channels: Arc<Mutex<Vec<crate::vote_service::ChannelDef>>> =
        Arc::new(Mutex::new(crate::vote_service::load_voted_channels()));

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

    let inbox_bg    = Arc::clone(&chat_inbox);
    let peers_bg    = Arc::clone(&peers);
    let profiles_bg = Arc::clone(&peer_profiles);
    let dm_inbox_bg = Arc::clone(&dm_inbox);
    let dm_status_bg = Arc::clone(&dm_status);
    let enc_kp_bg   = Arc::clone(&enc_kp);
    let sign_kp_bg  = Arc::clone(&sign_kp);
    let history_bg  = Arc::clone(&chat_history);
    let storage_bg  = Arc::clone(&storage_files);
    let reputation_bg = Arc::clone(&peer_reputation);
    let reports_bg    = Arc::clone(&reports);
    let sites_bg      = Arc::clone(&sites);
    let dns_bg        = Arc::clone(&dns_names);
    let reach_bg      = Arc::clone(&reachability);
    let proposals_bg  = Arc::clone(&proposals);
    let blocklist_bg  = Arc::clone(&blocklist);
    let voted_channels_bg = Arc::clone(&voted_channels);

    // Статистика сессии (профиль): аптайм + реальные счётчики трафика.
    let start_time = std::time::Instant::now();
    let bytes_uploaded:   Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let bytes_downloaded: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let bytes_uploaded_bg   = Arc::clone(&bytes_uploaded);
    let bytes_downloaded_bg = Arc::clone(&bytes_downloaded);
    let trust: Arc<Mutex<void_trust::TrustMap>> = Arc::new(Mutex::new(void_trust::TrustMap::default()));
    let trust_bg = Arc::clone(&trust);
    let private_verified: Arc<Mutex<HashSet<NodeId>>> = Arc::new(Mutex::new(
        crate::verify_store::load_verified().into_iter().map(NodeId).collect(),
    ));
    let private_bg = Arc::clone(&private_verified);
    let (trust_tx, trust_rx) = tokio::sync::mpsc::unbounded_channel::<TrustCmd>();
    let my_vouchers = Arc::new(AtomicUsize::new(0));
    let my_vouchers_bg = Arc::clone(&my_vouchers);
    let dm_access = Arc::new(Mutex::new(crate::dm_access::load()));
    let dm_access_bg = Arc::clone(&dm_access);
    let trust_details: Arc<Mutex<TrustDetails>> = Arc::new(Mutex::new(TrustDetails::default()));
    let trust_details_bg = Arc::clone(&trust_details);
    let chat_links = Arc::new(AtomicUsize::new(0));
    let chat_links_bg = Arc::clone(&chat_links);

    let downloads_dir = data_dir.join("downloads");

    // Подключены ли мы к глобальной сети как клиент (заданы bootstrap-узлы).
    // Захватываем до move в фоновый поток.
    let has_bootstrap = !bootstrap_addrs.is_empty();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            backend_main(
                my_peer, base_port, local_mode, public_mode, bootstrap_addrs,
                inbox_bg, peers_bg, profiles_bg, dm_inbox_bg, dm_status_bg,
                enc_kp_bg, sign_kp_bg, dm_port,
                chat_rx, connect_rx, profile_rx, dm_rx,
                data_dir, history_bg,
                publish_rx, download_rx, storage_bg,
                reputation_bg, reports_bg, report_rx,
                publish_site_rx, sites_bg, site_http_port,
                dns_bg, reach_bg, mirror_rx,
                propose_rx, vote_cast_rx, proposals_bg,
                blocklist_bg, voted_channels_bg,
                bytes_uploaded_bg, bytes_downloaded_bg,
                trust_bg, private_bg, trust_rx, my_vouchers_bg, dm_access_bg, trust_details_bg,
                chat_links_bg,
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
        dm_inbox,
        dm_status,
        dm_sender: dm_tx,
        chat_history,
        publish_tx,
        download_tx,
        storage_files,
        downloads_dir,
        peer_reputation,
        reports,
        report_tx,
        bootstrap: public_mode,
        has_bootstrap,
        publish_site_tx,
        mirror_tx,
        sites,
        site_http_port,
        dns_names,
        reachability,
        propose_tx,
        vote_cast_tx,
        proposals,
        blocklist,
        voted_channels,
        start_time,
        bytes_uploaded,
        bytes_downloaded,
        trust,
        private_verified,
        trust_tx,
        my_vouchers,
        dm_access,
        trust_details,
        chat_links,
    }
}

// ─── Внутренний async-рантайм ────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn backend_main(
    my_peer:     PeerInfo,
    base_port:   u16,
    local_mode:  bool,
    bootstrap:   bool,
    bootstrap_addrs: Vec<String>,
    inbox:       Arc<Mutex<VecDeque<ChatMessage>>>,
    peers_out:   Arc<Mutex<Vec<PeerInfo>>>,
    profiles_out: Arc<Mutex<HashMap<NodeId, PeerProfile>>>,
    dm_inbox:    Arc<Mutex<VecDeque<IncomingDm>>>,
    dm_status:   Arc<Mutex<HashMap<String, DeliveryState>>>,
    enc_kp:      Arc<EncryptionKeypair>,
    sign_kp:     Arc<SigningKeypair>,
    dm_port:     u16,
    mut chat_rx:    tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
    mut connect_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    mut profile_rx: tokio::sync::mpsc::UnboundedReceiver<PeerProfile>,
    mut dm_rx:      tokio::sync::mpsc::UnboundedReceiver<DmSendCmd>,
    data_dir:       PathBuf,
    chat_history_out: Arc<Mutex<Option<Vec<ChatMessage>>>>,
    publish_rx: tokio::sync::mpsc::UnboundedReceiver<PathBuf>,
    download_rx: tokio::sync::mpsc::UnboundedReceiver<DownloadCmd>,
    storage_files_out: Arc<Mutex<Vec<StorageFileInfo>>>,
    reputation_out: Arc<Mutex<HashMap<NodeId, f64>>>,
    reports_out: Arc<Mutex<HashMap<NodeId, Vec<void_db::peers::ReportRow>>>>,
    mut report_rx: tokio::sync::mpsc::UnboundedReceiver<(NodeId, ReportReason)>,
    publish_site_rx: tokio::sync::mpsc::UnboundedReceiver<(PathBuf, String)>,
    sites_out: Arc<Mutex<Vec<SiteInfo>>>,
    site_http_port: u16,
    dns_out: Arc<Mutex<Vec<DnsInfo>>>,
    reachability_out: Arc<Mutex<void_discovery::bootstrap::Reachability>>,
    mirror_rx: tokio::sync::mpsc::UnboundedReceiver<MirrorCmd>,
    propose_rx: tokio::sync::mpsc::UnboundedReceiver<void_vote::ProposalKind>,
    vote_cast_rx: tokio::sync::mpsc::UnboundedReceiver<(String, bool)>,
    proposals_out: Arc<Mutex<Vec<crate::vote_service::ProposalView>>>,
    blocklist_out: Arc<Mutex<HashMap<NodeId, i64>>>,
    voted_channels_out: Arc<Mutex<Vec<crate::vote_service::ChannelDef>>>,
    bytes_uploaded: Arc<AtomicU64>,
    bytes_downloaded: Arc<AtomicU64>,
    trust_out: Arc<Mutex<void_trust::TrustMap>>,
    private_out: Arc<Mutex<HashSet<NodeId>>>,
    trust_rx: tokio::sync::mpsc::UnboundedReceiver<TrustCmd>,
    my_vouchers: Arc<AtomicUsize>,
    dm_access: Arc<Mutex<crate::dm_access::DmAccess>>,
    trust_details: Arc<Mutex<TrustDetails>>,
    chat_links: Arc<AtomicUsize>,
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
    let history_for_chat: Vec<ChatMessage> = loaded.clone();
    *chat_history_out.lock().unwrap() = Some(loaded);

    // Ограничитель частоты (флуд-защита). ОДИН экземпляр на оба потребителя:
    // чат (дроп живых сообщений автора сверх лимита) и репутация (авто-блок узлов
    // с отрицательным score). Clone дешёвый — состояние (bucket map) общее.
    let rate_limiter = RateLimiter::new();

    // Noise-ключ узла (привязан подписью к NodeId): им аутентифицируются все
    // TCP-соединения — DM, чанки, bootstrap, relay (чат создаёт свой из sign_kp).
    let noise = NoiseIdentity::new(&sign_kp);

    // ── Репутация: локальное качество раздачи и приём жалоб ──────────────────
    // Доступна, если есть БД.
    let reputation: Option<Reputation> = db_pool.clone().map(|pool| {
        let score = ScoreManager::new(pool.clone());
        let events = EventProcessor::new(score.clone(), Arc::new(rate_limiter.clone()));
        let reports = ReportManager::new(pool, score.clone());
        Reputation { score, events, reports, keypair: sign_kp.clone() }
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

    // ── Глобальная сеть: bootstrap-узлы (первое знакомство между LAN) ─────────
    // Клиент: периодически опрашиваем заданные bootstrap-адреса (host:base_port
    // → host:base_port+5), регистрируемся и забираем известных им пиров.
    let service_addrs: Vec<String> = bootstrap_addrs.iter()
        .filter_map(|a| match void_discovery::bootstrap::service_addr(a) {
            Ok(s) => Some(s),
            Err(e) => { tracing::warn!("Неверный bootstrap-адрес '{}': {}", a, e); None }
        })
        .collect();
    if !service_addrs.is_empty() {
        tracing::info!("Bootstrap-адреса: {:?}", service_addrs);
        void_discovery::bootstrap::start_bootstrap_client(
            my_peer.clone(), peer_list.clone(), service_addrs,
            Arc::clone(&reachability_out), noise.clone(),
        );
    }
    // Relay-адреса тех же bootstrap-узлов (host:base+6). Через них идёт fallback
    // DM, когда прямое соединение невозможно (symmetric NAT). Регистрация и
    // приём входящих туннелей подключаются ниже, после старта DM-сервера.
    let relay_addrs: Vec<String> = bootstrap_addrs.iter()
        .filter_map(|a| void_discovery::relay::service_addr(a).ok())
        .collect();
    // Сервер: в публичном режиме сами становимся точкой входа. Сначала узнаём
    // свой ВНЕШНИЙ адрес (UPnP-проброс портов → внешний IP, иначе STUN-фолбэк),
    // затем поднимаем bootstrap-сервер, рекламирующий доступный извне адрес
    // (чтобы узлы из других сетей могли к нам подключиться, а не на LAN-IP).
    if bootstrap {
        let me = my_peer.clone();
        let pl = peer_list.clone();
        let srv_noise = noise.clone();
        tokio::spawn(async move {
            // 0. Relay-сервер не зависит от внешнего адреса — поднимаем сразу,
            //    не дожидаясь UPnP/STUN (иначе он стартует с задержкой в десятки
            //    секунд, пока идут таймауты поиска UPnP-шлюза).
            let rport = base_port + void_discovery::relay::RELAY_PORT_OFFSET;
            if let Err(e) = void_discovery::relay::start_relay_server(rport, srv_noise.clone()).await {
                tracing::error!("Relay server failed on {}: {}", rport, e);
            }
            // 1. UPnP: открываем TCP-порты на роутере (base/+2/+3/+5/+6) + внешний IP.
            //    +4 (HTTP сайтов) не пробрасываем — он только для своего браузера.
            let ports = [base_port, base_port + 2, base_port + 3, base_port + 5, base_port + 6];
            let upnp_ip = void_discovery::nat::map_ports(me.ip, &ports, "Void Connect").await;
            // 2. Если UPnP не дал внешний IP — пробуем STUN (публичные серверы).
            let ext_ip = match upnp_ip {
                Some(ip) => Some(ip),
                None => void_discovery::stun::discover_external_ip(
                    void_discovery::stun::DEFAULT_STUN_SERVERS,
                ).await,
            };
            // 3. Объявляем доступный адрес: внешний (если определён) иначе локальный.
            let advertised = match ext_ip {
                Some(ip) => {
                    tracing::info!(
                        "Внешний адрес узла: {} — раздавайте bootstrap-адрес {}:{}",
                        ip, ip, base_port);
                    PeerInfo { ip, ..me.clone() }
                }
                None => {
                    tracing::warn!(
                        "Внешний IP не определён (нет UPnP/STUN) — доступ извне только \
                         по вручную проброшенному адресу; объявляю локальный {}", me.ip);
                    me.clone()
                }
            };
            // 4. Bootstrap-сервер с рекламируемым адресом.
            let bport = base_port + void_discovery::bootstrap::BOOTSTRAP_PORT_OFFSET;
            if let Err(e) = void_discovery::bootstrap::start_bootstrap_server(
                advertised, pl, bport, srv_noise,
            ).await {
                tracing::error!("Bootstrap server failed on {}: {}", bport, e);
            }
        });
    } else if !local_mode {
        // Не публичный режим, но в LAN/глобальной сети: best-effort пробуем
        // UPnP-проброс наших рабочих портов (чанки/чат/DM). В паре со
        // штамповкой внешнего адреса на bootstrap это даёт прямое подключение к
        // нам из других сетей (если роутер поддерживает UPnP) — без relay.
        // Неудача (нет UPnP-шлюза) игнорируется молча.
        let ip = my_peer.ip;
        tokio::spawn(async move {
            let ports = [base_port, base_port + 2, base_port + 3];
            if void_discovery::nat::map_ports(ip, &ports, "Void Connect").await.is_some() {
                tracing::info!("UPnP: рабочие порты проброшены на роутере");
            }
        });
    }

    // Ключ подписи нужен и DNS (заявка имён), и голосованиям, и удалению сайтов
    // (подпись надгробия) — клонируем до передачи в чат.
    let dns_kp = sign_kp.clone();
    let vote_kp = sign_kp.clone();
    let site_kp = sign_kp.clone();
    let storage_kp = sign_kp.clone(); // подпись манифестов публикуемых файлов
    let trust_kp = sign_kp.clone();   // подпись поручительств
    let chat = match start_public_chat(
        my_peer.clone(), peer_list.clone(), my_peer.chat_port, sign_kp,
        Some(rate_limiter.clone()),
    ).await {
        Ok(h)  => h,
        Err(e) => {
            tracing::error!("Chat TCP server failed on port {}: {}", my_peer.chat_port, e);
            loop { tokio::time::sleep(tokio::time::Duration::from_secs(60)).await; }
        }
    };
    // История из БД: соседи догонят пропущенное через нас, а их копии уже
    // показанных сообщений не всплывут в GUI повторно.
    chat.preload_history(history_for_chat).await;

    // Начальный профиль с enc_pubkey
    let enc_pub_hex = hex::encode(enc_kp.public_bytes());
    let mut initial_profile = PeerProfile::new(my_peer.id.clone(), my_peer.name.clone());
    initial_profile.enc_pubkey = Some(enc_pub_hex.clone());
    initial_profile.is_bootstrap = bootstrap;
    chat.set_profile(initial_profile).await;

    // ── Внутренний DNS зоны .void ─────────────────────────────────────────────
    // Слушаем чужие записи (синхронизация через relay) и заявляем имена САЙТОВ при
    // публикации. Имя самого узла НЕ заявляем: пользователю .void-адрес узла не нужен.
    let dns = DnsService {
        registry: DnsRegistry::new(),
        chat:     chat.clone(),
        keypair:  dns_kp,
        my_id:    my_peer.id.clone(),
        snapshot: Arc::clone(&dns_out),
        store:    data_dir.join("dns.json"),
    };
    dns.load().await;
    dns.refresh().await;

    // ── Сеть доверия ──────────────────────────────────────────────────────────
    let trust_snapshot = Arc::clone(&trust_out);
    // Сигнал «пересчитать доверие» — и от жалоб (они меняют уровни узлов).
    let trust_dirty = Arc::new(tokio::sync::Notify::new());
    let my_vouchers_votes = Arc::clone(&my_vouchers);
    // Без БД (поручительства хранятся в ней) команды GUI просто не исполняются.
    if let Some(pool) = db_pool.clone() {
        let trust = TrustService {
            pool,
            chat:      chat.clone(),
            keypair:   trust_kp,
            my_id:     my_peer.id.clone(),
            snapshot:  trust_out,
            private:   private_out,
            blocklist: Arc::clone(&blocklist_out),
            my_vouchers,
            access:    Arc::clone(&dm_access),
            details:   trust_details,
            dirty:     Arc::clone(&trust_dirty),
        };
        // Лимиты чата по уровню доверия — после первого расчёта, иначе в первые
        // секунды все авторы были бы незнакомцами (до этого чат их не ограничивает).
        trust.recompute().await;
        let snapshot = Arc::clone(&trust.snapshot);
        chat.set_author_tiers(Arc::new(move |id: &NodeId| author_tier(&snapshot, id)));
        trust.start(peer_list.clone(), trust_rx);
    }
    // Задача: входящие DNS-записи из сети → проверяем подпись и применяем.
    {
        let dns_in = dns.clone();
        let mut dns_rx = chat.subscribe_dns();
        tokio::spawn(async move {
            loop {
                match dns_rx.recv().await {
                    Ok(signed) => dns_in.apply_incoming(signed).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("DNS gossip lagged by {}", n);
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Запускаем DM-сервер
    let dm_handle = match start_private_chat(my_peer.clone(), Arc::clone(&enc_kp), noise.clone(), dm_port).await {
        Ok(h)  => h,
        Err(e) => {
            tracing::error!("DM server failed on port {}: {}", dm_port, e);
            loop { tokio::time::sleep(tokio::time::Duration::from_secs(60)).await; }
        }
    };

    // Множество relay-адресов, на которых мы зарегистрированы. Сидируется
    // статическими bootstrap-узлами и динамически пополняется адресами узлов,
    // объявивших себя bootstrap'ами по gossip (см. периодическую задачу ниже).
    // Читается fallback-доставкой DM.
    let relay_set: Arc<Mutex<HashSet<String>>> =
        Arc::new(Mutex::new(relay_addrs.iter().cloned().collect()));

    // Relay-клиент: регистрируемся на relay каждого известного bootstrap-узла и
    // принимаем входящие туннели — поток скармливаем DM-серверу как входящее
    // соединение (так доходят DM от пиров за symmetric NAT).
    if !relay_addrs.is_empty() {
        tracing::info!("Relay-адреса: {:?}", relay_addrs);
        for raddr in &relay_addrs {
            let mut accepted = void_discovery::relay::start_relay_client(
                raddr.clone(), noise.clone(),
            );
            let dm_accept = dm_handle.clone();
            tokio::spawn(async move {
                while let Some((stream, from)) = accepted.recv().await {
                    tracing::info!("Relay: входящий туннель от {}", from);
                    let h = dm_accept.clone();
                    tokio::spawn(async move { h.accept_stream(Box::new(stream)).await; });
                }
            });
        }
    }

    // Задача: входящие публичные сообщения → inbox GUI + персистентность в БД
    let mut rx = chat.subscribe();
    let inbox_task = Arc::clone(&inbox);
    let pool_for_save = db_pool.clone();
    let chat_blocklist = Arc::clone(&blocklist_out);
    let chat_access = Arc::clone(&dm_access);
    let chat_my_id = my_peer.id.clone();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    // Узлы, забаненные голосованием или мной, не показываем и не сохраняем.
                    let now = chrono::Utc::now().timestamp();
                    if is_banned(&chat_blocklist, &msg.from, now)
                        || chat_access.lock().unwrap().blocked.contains(msg.from.as_str())
                    {
                        continue;
                    }
                    // Наблюдение для уровня «освоившийся»: «живое» чужое сообщение.
                    if let Some(pool) = &pool_for_save {
                        if msg.from != chat_my_id && (now - msg.timestamp).abs() <= 120 {
                            let _ = void_trust::store::note_live_message(pool, &msg.from, now).await;
                        }
                    }
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
    let dm_blocklist = Arc::clone(&blocklist_out);
    let dm_trust = Arc::clone(&trust_snapshot);
    let dm_access_in = Arc::clone(&dm_access);
    // Без БД сеть доверия не работает (и «Принять» тоже) — пускаем всех, как раньше.
    let dm_gate = db_pool.is_some();
    tokio::spawn(async move {
        loop {
            match dm_rx_sub.recv().await {
                Ok(msg) => {
                    // DM от забаненных голосованием узлов игнорируем.
                    if is_banned(&dm_blocklist, &msg.from, chrono::Utc::now().timestamp()) {
                        continue;
                    }
                    // Незнакомцы — только в «Запросы» и только с маркой работы.
                    let level = dm_trust.lock().unwrap().level(&msg.from);
                    let route = if !dm_gate {
                        crate::dm_access::Route::Inbox
                    } else {
                        let mut access = dm_access_in.lock().unwrap();
                        let before = access.requests.get(msg.from.as_str()).copied();
                        let route = access.route(msg.from.as_str(), level, msg.stamped);
                        if access.requests.get(msg.from.as_str()).copied() != before {
                            crate::dm_access::save(&access);
                        }
                        route
                    };
                    if route == crate::dm_access::Route::Drop {
                        tracing::debug!("Личное сообщение от {} отброшено (нет марки / очередь запроса полна / блок)", msg.from);
                        continue;
                    }
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
        while let Some((channel, text)) = chat_rx.recv().await {
            if let Err(e) = chat_send.send(channel, text).await {
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

    // Задача: исходящие DM из GUI → DM handle. При неудаче прямого соединения
    // (symmetric NAT) пробуем relay известных bootstrap-узлов. Недоставленные
    // ставим в очередь и периодически повторяем (пир мог быть офлайн), сообщая
    // GUI статус доставки через `dm_status`.
    let dm_h = dm_handle.clone();
    let dm_relay_set = Arc::clone(&relay_set);
    let dm_noise = noise.clone();
    let dm_status_loop = Arc::clone(&dm_status);
    let dm_peer_list = peer_list.clone();
    let dm_access_out = Arc::clone(&dm_access);
    tokio::spawn(async move {
        let mut retry_q: VecDeque<PendingDm> = VecDeque::new();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(DM_RETRY_SECS));
        loop {
            tokio::select! {
                maybe_cmd = dm_rx.recv() => {
                    let Some(cmd) = maybe_cmd else { break; }; // канал закрыт — выходим
                    // Пишу сам — значит, жду ответа: он пойдёт во «Входящие».
                    update_access(&dm_access_out, |a| a.allow(cmd.to.as_str()));
                    set_dm_status(&dm_status_loop, &cmd.message_id, DeliveryState::Sending);
                    if try_deliver_dm(&dm_h, &dm_relay_set, &dm_noise, &cmd).await {
                        set_dm_status(&dm_status_loop, &cmd.message_id, DeliveryState::Delivered);
                    } else {
                        // Пир, возможно, офлайн — повторим позже.
                        retry_q.push_back(PendingDm {
                            cmd,
                            attempts: 1,
                            next_at: std::time::Instant::now()
                                + std::time::Duration::from_secs(DM_RETRY_SECS),
                        });
                    }
                }
                _ = tick.tick() => {
                    if retry_q.is_empty() { continue; }
                    let now = std::time::Instant::now();
                    let mut still: VecDeque<PendingDm> = VecDeque::new();
                    while let Some(mut p) = retry_q.pop_front() {
                        if p.next_at > now { still.push_back(p); continue; }
                        // Переразрешаем адрес пира из peer_list — он мог смениться.
                        if let Some(info) = dm_peer_list.get(&p.cmd.to).await {
                            p.cmd.to_dm_addr =
                                format!("{}:{}", info.ip, info.port.saturating_add(DM_PORT_OFFSET));
                        }
                        if try_deliver_dm(&dm_h, &dm_relay_set, &dm_noise, &p.cmd).await {
                            set_dm_status(&dm_status_loop, &p.cmd.message_id, DeliveryState::Delivered);
                        } else if p.attempts >= DM_MAX_ATTEMPTS {
                            tracing::warn!(
                                "DM {} не доставлено после {} попыток",
                                &p.cmd.message_id, p.attempts);
                            set_dm_status(&dm_status_loop, &p.cmd.message_id, DeliveryState::Failed);
                        } else {
                            p.attempts += 1;
                            p.next_at = now + std::time::Duration::from_secs(DM_RETRY_SECS);
                            still.push_back(p);
                        }
                    }
                    retry_q = still;
                }
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

    // Задача: периодически снимаем peer_list и профили для GUI, снимок
    // качества раздачи и жалоб.
    let snap_links = Arc::clone(&chat_links);
    let pl       = peer_list.clone();
    let chat_p   = chat.clone();
    let rep_snap = reputation.clone();
    let rep_out  = Arc::clone(&reputation_out);
    let reports_pool = db_pool.clone();
    let reports_out_t = Arc::clone(&reports_out);
    let dns_snap = dns.clone();
    let rl_clean = rate_limiter.clone();
    // Для динамической регистрации на relay узлов, узнанных по gossip.
    let dm_for_relay = dm_handle.clone();
    let relay_set_disc = Arc::clone(&relay_set);
    let my_relay_id = my_peer.id.clone();
    let relay_noise = noise.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
        let mut prev_ids: HashSet<NodeId> = HashSet::new();
        let mut tick: u64 = 0;
        loop {
            interval.tick().await;
            tick = tick.wrapping_add(1);
            let peers = pl.all().await;
            *peers_out.lock().unwrap() = peers.clone();
            snap_links.store(chat_p.link_count().await, Ordering::Relaxed);
            let profiles = chat_p.get_profiles().await;
            {
                let mut map = profiles_out.lock().unwrap();
                for p in profiles {
                    map.insert(p.node_id.clone(), p);
                }
            }

            // Динамическая регистрация на relay узлов, объявивших себя
            // bootstrap'ами (узнаны по gossip профилей). Без этого fallback-DM
            // покрывал лишь статически заданные bootstrap-адреса.
            let bootstrap_ids: Vec<NodeId> = {
                let map = profiles_out.lock().unwrap();
                map.values()
                    .filter(|p| p.is_bootstrap)
                    .map(|p| p.node_id.clone())
                    .collect()
            };
            for bid in bootstrap_ids {
                if bid == my_relay_id { continue; } // не регистрируемся у самих себя
                let Some(info) = pl.get(&bid).await else { continue; };
                // только реальные узлы (64-hex), не stub-заглушки
                if info.id.as_str().len() != 64 { continue; }
                let Some(rport) = info.port.checked_add(void_discovery::relay::RELAY_PORT_OFFSET)
                    else { continue; };
                let raddr = format!("{}:{}", info.ip, rport);
                let is_new = relay_set_disc.lock().unwrap().insert(raddr.clone());
                if is_new {
                    tracing::info!("Relay (gossip): регистрируюсь на {} ({})", raddr, info.name);
                    let mut accepted = void_discovery::relay::start_relay_client(
                        raddr.clone(), relay_noise.clone(),
                    );
                    let dm_accept = dm_for_relay.clone();
                    tokio::spawn(async move {
                        while let Some((stream, from)) = accepted.recv().await {
                            tracing::info!("Relay: входящий туннель от {}", from);
                            let h = dm_accept.clone();
                            tokio::spawn(async move { h.accept_stream(Box::new(stream)).await; });
                        }
                    });
                }
            }

            // Только реальные узлы (64-hex), не stub-заглушки.
            let cur_ids: HashSet<NodeId> = peers.iter()
                .filter(|p| p.id.as_str().len() == 64)
                .map(|p| p.id.clone())
                .collect();
            let newly: Vec<NodeId> = cur_ids.difference(&prev_ids).cloned().collect();

            // Снимок качества раздачи (локальная репутация) для GUI.
            if let Some(rep) = &rep_snap {
                let mut snapshot = HashMap::with_capacity(cur_ids.len());
                for id in &cur_ids {
                    snapshot.insert(id.clone(), rep.score.score(id).await);
                }
                *rep_out.lock().unwrap() = snapshot;
            }

            // Снимок жалоб на текущие узлы (для просмотра в профиле). Реже —
            // раз в ~10с, т.к. жалобы меняются нечасто. Только дошедшие до нас.
            if tick % 5 == 0 {
                if let Some(pool) = &reports_pool {
                    let mut map: HashMap<NodeId, Vec<void_db::peers::ReportRow>> = HashMap::new();
                    for id in &cur_ids {
                        if let Ok(rows) = void_db::peers::list_reports(pool, id.as_str()).await {
                            if !rows.is_empty() {
                                map.insert(id.clone(), rows);
                            }
                        }
                    }
                    *reports_out_t.lock().unwrap() = map;
                }
            }

            // Новым пирам — наши DNS-записи (работает и без репутации).
            if !newly.is_empty() {
                dns_snap.reannounce().await;
            }
            // Чистим бакеты лимитера от отключившихся узлов (не копим память).
            let live: Vec<NodeId> = cur_ids.iter().cloned().collect();
            rl_clean.cleanup(&live).await;
            prev_ids = cur_ids;
        }
    });

    // Задача: входящие жалобы → в БД. Жалоба незнакомца веса не имеет — не
    // храним; вес остальных учитывает пересчёт доверия (он же ставит «под жалобами»).
    if let Some(rep) = reputation.clone() {
        let mut reports_rx = chat.subscribe_reports();
        let reports_trust = Arc::clone(&trust_snapshot);
        let dirty = Arc::clone(&trust_dirty);
        tokio::spawn(async move {
            loop {
                match reports_rx.recv().await {
                    Ok(signed) => {
                        let reporter = NodeId(signed.signer.clone());
                        if reports_trust.lock().unwrap().level(&reporter) < void_trust::TrustLevel::Settled {
                            continue;
                        }
                        match rep.reports.receive_report(signed, &reporter).await {
                            Ok(true) => dirty.notify_one(),
                            Ok(false) => {}
                            Err(e) => tracing::debug!("Отклонена жалоба от {}: {}", reporter, e),
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Жалобы: пропущено {} (переполнение)", n);
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Задача: сигналы о флуде из чата → спам-страйк репутации (с дебаунсом).
    // Лимитер уже дропает пакеты сверх лимита; здесь только наказываем репутацию
    // (она при отрицательном score доблокирует узел через тот же лимитер).
    if let Some(rep) = reputation.clone() {
        let mut spam_rx = chat.subscribe_spam();
        tokio::spawn(async move {
            // Не чаще одного страйка на узел в 5с — чтобы флуд не завалил БД.
            let mut last: HashMap<NodeId, std::time::Instant> = HashMap::new();
            loop {
                match spam_rx.recv().await {
                    Ok(peer) => {
                        let now = std::time::Instant::now();
                        let fresh = last.get(&peer)
                            .map(|t| now.duration_since(*t).as_secs() >= 5)
                            .unwrap_or(true);
                        if fresh {
                            last.insert(peer.clone(), now);
                            tracing::warn!("Флуд от {} — спам-страйк репутации", peer);
                            rep.events.process(ReputationEvent::SpamStrike { peer_id: peer }).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Spam stream lagged by {}", n);
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
        let my_report_dirty = Arc::clone(&trust_dirty);
        tokio::spawn(async move {
            while let Some((target, reason)) = report_rx.recv().await {
                if target == my_report_id {
                    tracing::warn!("Нельзя пожаловаться на себя");
                    continue;
                }
                match ReportManager::create_report(&target, reason, &rep.keypair) {
                    Ok(signed) => {
                        // Учитываем свою жалобу локально (весит 1 — цель сразу
                        // «под жалобами» у нас) и рассылаем сети.
                        match rep.reports.receive_report(signed.clone(), &my_report_id).await {
                            Ok(_) => my_report_dirty.notify_one(),
                            Err(e) => tracing::warn!("Локальная жалоба не принята: {}", e),
                        }
                        chat_rep.broadcast_report(signed).await;
                        tracing::info!("Отправлена жалоба на {}", target);
                    }
                    Err(e) => tracing::warn!("Не удалось создать жалобу: {}", e),
                }
            }
        });
    }

    // Файлы, удалённые голосованием (RemoveFile) — чтобы не докачивать обратно.
    let removed_files: Arc<Mutex<HashSet<String>>> =
        Arc::new(Mutex::new(crate::vote_service::load_removed_files()));

    // ── Подсистема хранилища (требует БД) ─────────────────────────────────────
    // chunk-сервер слушает base_port (он свободен: чат на +2, DM на +3),
    // download у пиров идёт именно на их base_port.
    if let Some(pool) = db_pool.clone() {
        match ChunkStore::new(data_dir.join("chunks")).await {
            Ok(store) => match StorageManager::new(pool.clone(), store, Arc::clone(&storage_kp)).await {
                Ok(mut manager) => {
                    // Подключаем события качества чанков к репутации (если включена).
                    if let Some(tx) = chunk_ev_tx.clone() {
                        manager.set_event_sink(tx);
                    }
                    // Общие с GUI счётчики трафика (до клонирования менеджера в задачи).
                    manager.set_traffic_counters(
                        Arc::clone(&bytes_uploaded),
                        Arc::clone(&bytes_downloaded),
                    );
                    // Голосования (нужны БД + storage для RemoveFile).
                    start_vote_tasks(
                        manager.clone(), pool.clone(), chat.clone(),
                        Arc::clone(&trust_snapshot), Arc::clone(&my_vouchers_votes),
                        my_peer.id.clone(), vote_kp,
                        propose_rx, vote_cast_rx,
                        proposals_out, blocklist_out, voted_channels_out,
                        Arc::clone(&removed_files),
                    );
                    // Сайты: HTTP-сервер + публикация + обнаружение по сети.
                    start_site_tasks(
                        manager.clone(), my_peer.id.clone(), site_http_port,
                        chat.clone(), Arc::clone(&sites_peers), dns.clone(),
                        site_kp, publish_site_rx, sites_out, mirror_rx,
                    );
                    start_storage_tasks(
                        manager, pool, chat.clone(), peer_list.clone(),
                        my_peer.id.clone(), base_port, data_dir.clone(),
                        publish_rx, download_rx, storage_files_out,
                        Arc::clone(&removed_files),
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
#[allow(clippy::too_many_arguments)]
fn start_site_tasks(
    manager:    StorageManager,
    my_id:      NodeId,
    http_port:  u16,
    chat:       ChatHandle,
    peers:      Arc<Mutex<Vec<PeerInfo>>>,
    dns:        DnsService,
    keypair:    Arc<SigningKeypair>,
    mut publish_site_rx: tokio::sync::mpsc::UnboundedReceiver<(PathBuf, String)>,
    sites_out:  Arc<Mutex<Vec<SiteInfo>>>,
    mut mirror_rx: tokio::sync::mpsc::UnboundedReceiver<MirrorCmd>,
) {
    let registry = SiteRegistry::new();
    let my_key = my_id.as_str().to_string();

    // Набор зеркалируемых (кэшируемых нами) сайтов — переживает перезапуск.
    let mirrored: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(load_mirrored_sites()));
    // Клоны для задачи зеркалирования (создаём до того, как оригиналы уедут в
    // другие задачи ниже).
    let mirror_reg   = registry.clone();
    let mirror_mgr   = manager.clone();
    let mirror_chat  = chat.clone();
    let mirror_peers = Arc::clone(&peers);
    let mirror_out   = Arc::clone(&sites_out);
    let mirror_key   = my_key.clone();
    let mirror_set   = Arc::clone(&mirrored);
    let mirror_dns   = dns.clone();   // для отзыва домена при удалении сайта
    let mirror_kp    = Arc::clone(&keypair); // для подписи надгробия
    let pub_kp       = keypair;              // для подписи манифестов публикуемых сайтов

    // HTTP-сервер сайтов (peers — источник для докачки файлов сетевых сайтов).
    let srv_reg = registry.clone();
    let srv_mgr = manager.clone();
    tokio::spawn(async move {
        // Только loopback: страницы сайтов нужны своему браузеру. Открытый в сеть
        // порт позволял бы любому заставить узел скачивать произвольные файлы.
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], http_port));
        if let Err(e) = void_web::serve(addr, srv_reg, srv_mgr, peers).await {
            tracing::error!("Site HTTP server failed on {}: {}", http_port, e);
        }
    });

    // Обнаружение чужих сайтов: манифесты из сети → реестр + снимок для GUI.
    let disc_reg  = registry.clone();
    let disc_out  = Arc::clone(&sites_out);
    let disc_key  = my_key.clone();
    let disc_mirror = Arc::clone(&mirrored);
    let mut site_rx = chat.subscribe_sites();
    tokio::spawn(async move {
        loop {
            match site_rx.recv().await {
                Ok(manifest) => {
                    tracing::info!("Обнаружен сайт в сети: '{}' ({} файлов)",
                        manifest.name, manifest.entries.len());
                    disc_reg.register(manifest).await;
                    refresh_sites(&disc_reg, &disc_key, http_port, &disc_mirror, &disc_out).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(k)) => {
                    tracing::warn!("Site stream lagged by {}", k);
                }
                Err(_) => break,
            }
        }
    });

    // Реакция на удаление сайтов другими узлами: надгробие владельца → стираем
    // кэш-копию файлов, убираем из реестра и из набора зеркал. (Свои удаления
    // мы выполняем напрямую в задаче ниже и собственный broadcast не получаем.)
    let rev_reg    = registry.clone();
    let rev_mgr    = manager.clone();
    let rev_out    = Arc::clone(&sites_out);
    let rev_mirror = Arc::clone(&mirrored);
    let rev_key    = my_key.clone();
    let mut revoke_rx = chat.subscribe_site_revokes();
    tokio::spawn(async move {
        loop {
            match revoke_rx.recv().await {
                Ok(rev) => {
                    if let Some(manifest) = rev_reg.get(&rev.name).await {
                        if manifest.owner == rev.owner {
                            for entry in &manifest.entries {
                                let _ = rev_mgr.delete_file(&entry.file_id).await;
                            }
                            rev_reg.remove(&rev.name).await;
                            tracing::info!("Сайт '{}' удалён владельцем — стёрта кэш-копия", rev.name);
                        }
                    }
                    {
                        let mut set = rev_mirror.lock().unwrap();
                        if set.remove(&rev.name) { save_mirrored_sites(&set); }
                    }
                    refresh_sites(&rev_reg, &rev_key, http_port, &rev_mirror, &rev_out).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(k)) => {
                    tracing::warn!("Site-revoke stream lagged by {}", k);
                }
                Err(_) => break,
            }
        }
    });

    // Публикация сайтов из GUI: публикуем файлы, объявляем их манифесты
    // (чтобы пиры могли докачать), затем объявляем сам сайт.
    let pub_chat = chat.clone();
    let pub_mirror = Arc::clone(&mirrored);
    tokio::spawn(async move {
        while let Some((dir, name)) = publish_site_rx.recv().await {
            match publish_site(&manager, &dir, &name, &pub_kp).await {
                Ok(manifest) => {
                    tracing::info!("Опубликован сайт '{}' ({} файлов) → http://127.0.0.1:{}/{}",
                        manifest.name, manifest.entries.len(), http_port, manifest.name);
                    // Объявляем каждый файл сайта (мульти-сидинг + докачка у пиров).
                    for entry in &manifest.entries {
                        if let Ok(Some(fm)) = manager.file_manifest(&entry.file_id).await {
                            pub_chat.announce_file(fm).await;
                        }
                    }
                    let site_name = manifest.name.clone();
                    registry.register(manifest.clone()).await;
                    // Объявляем сайт сети.
                    pub_chat.announce_site(manifest).await;
                    refresh_sites(&registry, &my_key, http_port, &pub_mirror, &sites_out).await;
                    // Заявляем DNS-имя сайта (.void) — владение + резолв.
                    dns.claim(DnsKind::Site, &site_name, None, Some(http_port)).await;
                }
                Err(e) => tracing::warn!("Публикация сайта '{}' не удалась: {}", name, e),
            }
        }
    });

    // Задача зеркалирования: команды GUI (кэшировать/убрать) + раз в 30с
    // до-качивает все файлы зеркалируемых сайтов (восстановление после рестарта и
    // подхват сайтов, обнаруженных позже) и объявляет нас их сидером.
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                cmd = mirror_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        MirrorCmd::Mirror(name) => {
                            {
                                let mut set = mirror_set.lock().unwrap();
                                set.insert(name.clone());
                                save_mirrored_sites(&set);
                            }
                            tracing::info!("Зеркалирую сайт '{}'", name);
                            ensure_site_mirrored(&mirror_mgr, &mirror_reg, &mirror_chat, &mirror_peers, &name).await;
                        }
                        MirrorCmd::Unmirror(name) => {
                            {
                                let mut set = mirror_set.lock().unwrap();
                                set.remove(&name);
                                save_mirrored_sites(&set);
                            }
                            // Стираем кэшированные файлы (только если сайт не наш).
                            if let Some(manifest) = mirror_reg.get(&name).await {
                                if mirror_key.as_str() != manifest.owner.as_str() {
                                    for entry in &manifest.entries {
                                        let _ = mirror_mgr.delete_file(&entry.file_id).await;
                                    }
                                }
                            }
                            tracing::info!("Сайт '{}' убран из кэша", name);
                        }
                        MirrorCmd::Delete(name) => {
                            // Удаляем ТОЛЬКО свой сайт (UI предлагает кнопку лишь владельцу).
                            match mirror_reg.get(&name).await {
                                Some(manifest) if manifest.owner.as_str() == mirror_key.as_str() => {
                                    // 1. Подписываем и рассылаем надгробие (ставит и локальный
                                    //    tombstone в чате — старые анонсы не воскресят сайт).
                                    let rev = SiteRevocation {
                                        name: name.clone(),
                                        owner: manifest.owner.clone(),
                                        revoked_at: chrono::Utc::now().timestamp(),
                                    };
                                    match SignedMessage::sign(rev.to_bytes(), &mirror_kp) {
                                        Ok(signed) => mirror_chat.announce_site_revoke(signed).await,
                                        Err(e) => tracing::warn!("Подпись надгробия '{}' не удалась: {}", name, e),
                                    }
                                    // 2. Убираем из локального реестра рассылки.
                                    mirror_reg.remove(&name).await;
                                    // 3. Стираем файлы сайта из хранилища.
                                    for entry in &manifest.entries {
                                        let _ = mirror_mgr.delete_file(&entry.file_id).await;
                                    }
                                    // 4. На всякий случай убираем из набора зеркал.
                                    {
                                        let mut set = mirror_set.lock().unwrap();
                                        if set.remove(&name) { save_mirrored_sites(&set); }
                                    }
                                    // 5. Отзываем DNS-домен (.void).
                                    mirror_dns.revoke(&name).await;
                                    tracing::info!("Сайт '{}' удалён: домен отозван, файлы стёрты", name);
                                }
                                Some(_) => tracing::warn!("Отказано в удалении '{}': сайт не наш", name),
                                None     => tracing::warn!("Удаление '{}': сайт не найден", name),
                            }
                        }
                    }
                    refresh_sites(&mirror_reg, &mirror_key, http_port, &mirror_set, &mirror_out).await;
                }
                _ = ticker.tick() => {
                    let names: Vec<String> = { mirror_set.lock().unwrap().iter().cloned().collect() };
                    for name in &names {
                        ensure_site_mirrored(&mirror_mgr, &mirror_reg, &mirror_chat, &mirror_peers, name).await;
                    }
                    if !names.is_empty() {
                        refresh_sites(&mirror_reg, &mirror_key, http_port, &mirror_set, &mirror_out).await;
                    }
                }
            }
        }
    });
}

/// Скачивает все файлы сайта локально (делая нас сидером) и пере-анонсирует его —
/// так зеркало остаётся доступным, даже когда владелец офлайн.
async fn ensure_site_mirrored(
    manager:  &StorageManager,
    registry: &SiteRegistry,
    chat:     &ChatHandle,
    peers:    &Arc<Mutex<Vec<PeerInfo>>>,
    name:     &str,
) {
    let Some(manifest) = registry.get(name).await else { return };
    let peers_snap = { peers.lock().unwrap().clone() };
    for entry in &manifest.entries {
        // read_or_fetch_file докачивает недостающие чанки, сохраняет их локально и
        // регистрирует нас владельцем (мульти-сидинг). Содержимое нам не нужно.
        if let Err(e) = manager.read_or_fetch_file(&entry.file_id, &peers_snap).await {
            tracing::debug!("Зеркало '{}': файл {} пока недоступен: {}",
                name, &entry.file_id[..8.min(entry.file_id.len())], e);
        }
        if let Ok(Some(fm)) = manager.file_manifest(&entry.file_id).await {
            chat.announce_file(fm).await;
        }
    }
    // Объявляем, что мы тоже хостим этот сайт.
    chat.announce_site(manifest).await;
}

/// Путь к файлу со списком зеркалируемых сайтов.
fn mirrored_sites_path() -> PathBuf {
    crate::profile_store::profile_dir().join("mirrored_sites.json")
}

/// Загружает набор зеркалируемых сайтов с диска (пустой при отсутствии/ошибке).
fn load_mirrored_sites() -> HashSet<String> {
    match std::fs::read_to_string(mirrored_sites_path()) {
        Ok(s)  => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => HashSet::new(),
    }
}

/// Сохраняет набор зеркалируемых сайтов на диск.
fn save_mirrored_sites(set: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string_pretty(set) {
        let _ = std::fs::write(mirrored_sites_path(), json);
    }
}

/// Обновляет снимок списка сайтов для GUI из реестра.
async fn refresh_sites(
    registry: &SiteRegistry,
    my_key: &str,
    http_port: u16,
    mirrored: &Arc<Mutex<HashSet<String>>>,
    out: &Arc<Mutex<Vec<SiteInfo>>>,
) {
    let mset = { mirrored.lock().unwrap().clone() };
    let infos: Vec<SiteInfo> = registry.list().await.into_iter().map(|m| SiteInfo {
        url:         format!("http://127.0.0.1:{}/{}", http_port, m.name),
        dns_name:    m.dns_name(),
        file_count:  m.entries.len(),
        size_bytes:  m.total_size(),
        is_mine:     m.owner.as_str() == my_key,
        is_mirrored: mset.contains(&m.name),
        name:        m.name,
    }).collect();
    *out.lock().unwrap() = infos;
}

/// Запускает фоновые задачи хранилища: chunk-сервер, обработку публикаций
/// (с рассылкой манифеста по сети), приём чужих манифестов, скачивание по
/// запросу и периодическое обновление списка файлов для GUI.
/// Останавливает активное скачивание файла (если идёт) и ДОЖИДАЕТСЯ фактического
/// завершения задачи — иначе она может дописать чанк/владельца уже после
/// `delete_file` (гонка с осиротевшими блобами). Общий шаг для обоих видов удаления.
async fn cancel_active_download(
    cancels: &Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    tasks: &mut HashMap<String, tokio::task::JoinHandle<()>>,
    file_id: &str,
) {
    if let Some(flag) = cancels.lock().unwrap().get(file_id).cloned() {
        flag.store(true, Ordering::Relaxed);
    }
    if let Some(mut handle) = tasks.remove(file_id) {
        if tokio::time::timeout(std::time::Duration::from_secs(15), &mut handle)
            .await
            .is_err()
        {
            tracing::warn!(
                "Задача скачивания {} не завершилась за 15с — прерываю",
                &file_id[..8.min(file_id.len())]
            );
            handle.abort();
            let _ = handle.await;
        }
    }
}

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
    removed_files: Arc<Mutex<HashSet<String>>>,
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
    let ann_removed = Arc::clone(&removed_files);
    let mut manifest_rx = chat.subscribe_manifests();
    tokio::spawn(async move {
        loop {
            match manifest_rx.recv().await {
                Ok(manifest) => {
                    let name = manifest.name.clone();
                    let n = manifest.chunks.len();
                    // Файл, удалённый голосованием, не принимаем обратно.
                    if ann_removed.lock().unwrap().contains(&manifest.file_id) {
                        tracing::debug!("Манифест '{}' игнорирован: файл удалён голосованием", name);
                        continue;
                    }
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
    let dl_my_id = my_id.clone();
    let dl_removed = Arc::clone(&removed_files);
    let downloads_dir = data_dir.join("downloads");
    // Флаги отмены активных скачиваний. Завершившаяся задача убирает свой флаг,
    // поэтому карта не растёт бесконечно.
    let cancels: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(async move {
        // JoinHandle'ы активных задач скачивания — чтобы при удалении файла
        // дождаться фактического завершения задачи перед стиранием данных.
        let mut tasks: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        while let Some(cmd) = download_rx.recv().await {
            match cmd {
                DownloadCmd::Pause(file_id) => {
                    let flag = cancels.lock().unwrap().get(&file_id).cloned();
                    if let Some(flag) = flag {
                        flag.store(true, Ordering::Relaxed);
                        tracing::info!("Пауза скачивания {}", &file_id[..8.min(file_id.len())]);
                    }
                }
                DownloadCmd::Remove(file_id) => {
                    // Удаление из СЕТИ: только владелец и только если файл больше никто
                    // (из живых узлов) не раздаёт. Иначе отказ — файл живёт у других
                    // сидеров, его нельзя выпилить из сети (UI это тоже не предлагает,
                    // но проверяем на стороне backend для надёжности).
                    let is_owner = matches!(
                        void_db::chunks::get_file(&dl_pool, &file_id).await,
                        Ok(Some(f)) if f.owner_key == dl_my_id.as_str()
                    );
                    if !is_owner {
                        tracing::warn!("Удаление из сети {} отклонено: не владелец файла",
                            &file_id[..8.min(file_id.len())]);
                        continue;
                    }
                    let live: HashSet<String> = dl_pl.all().await.into_iter()
                        .map(|p| p.id.as_str().to_string())
                        .chain(std::iter::once(dl_my_id.as_str().to_string()))
                        .collect();
                    let others_seed = dl_chat.get_manifests().await.into_iter()
                        .find(|m| m.file_id == file_id)
                        .map(|m| m.owners.iter()
                            .any(|o| o.as_str() != dl_my_id.as_str() && live.contains(o.as_str())))
                        .unwrap_or(false);
                    if others_seed {
                        tracing::warn!("Удаление из сети {} отклонено: файл раздают другие узлы",
                            &file_id[..8.min(file_id.len())]);
                        continue;
                    }
                    // Подавляем «воскрешение» файла входящим манифестом, затем стираем.
                    {
                        let mut set = dl_removed.lock().unwrap();
                        set.insert(file_id.clone());
                        crate::vote_service::save_removed_files(&set);
                    }
                    cancel_active_download(&cancels, &mut tasks, &file_id).await;
                    match dl_mgr.delete_file(&file_id).await {
                        Ok(()) => tracing::info!("Файл {} удалён из сети", &file_id[..8.min(file_id.len())]),
                        Err(e) => tracing::warn!("Не удалось удалить файл {}: {}", &file_id[..8.min(file_id.len())], e),
                    }
                }
                DownloadCmd::RemoveLocal(file_id) => {
                    // Убираем ТОЛЬКО свою локальную копию (перестаём раздавать). Файл
                    // остаётся в сети у других сидеров и может быть скачан снова, поэтому
                    // в removed_files НЕ заносим (не подавляем будущие манифесты).
                    cancel_active_download(&cancels, &mut tasks, &file_id).await;
                    match dl_mgr.delete_file(&file_id).await {
                        Ok(()) => tracing::info!("Локальная копия {} удалена", &file_id[..8.min(file_id.len())]),
                        Err(e) => tracing::warn!("Не удалось убрать копию {}: {}", &file_id[..8.min(file_id.len())], e),
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

                    // Имя из чужого манифеста: только безопасное имя файла, иначе
                    // `join` с абсолютным путём или `../` вышел бы за пределы папки.
                    let dest  = downloads_dir.join(void_core::sanitize::safe_file_name(&name));
                    let peers = dl_pl.all().await;
                    let mgr   = dl_mgr.clone();
                    let chat  = dl_chat.clone();
                    let cancels_task = Arc::clone(&cancels);
                    tracing::info!("Скачивание '{}' → {}", name, dest.display());
                    // Прибираем завершившиеся задачи, чтобы карта не росла.
                    tasks.retain(|_, h| !h.is_finished());
                    let task_key = file_id.clone();
                    let handle = tokio::spawn(async move {
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
                    tasks.insert(task_key, handle);
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
                    owner_key:    f.owner_key,
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

// ─── Голосования (void-vote) ─────────────────────────────────────────────────

/// Период подсчёта/синхронизации голосований.
const VOTE_TICK_SECS: u64 = 15;

/// Запускает задачи подсистемы голосований: приём/хранение/anti-entropy
/// предложений и голосов, создание/подачу из GUI, периодический подсчёт,
/// финализацию закрытых голосований и исполнение принятых решений.
#[allow(clippy::too_many_arguments)]
fn start_vote_tasks(
    manager: StorageManager,
    pool: void_db::DbPool,
    chat: ChatHandle,
    trust: Arc<Mutex<void_trust::TrustMap>>,
    my_vouchers: Arc<AtomicUsize>,
    my_id: NodeId,
    sign_kp: Arc<SigningKeypair>,
    mut propose_rx: tokio::sync::mpsc::UnboundedReceiver<void_vote::ProposalKind>,
    mut vote_cast_rx: tokio::sync::mpsc::UnboundedReceiver<(String, bool)>,
    proposals_out: Arc<Mutex<Vec<crate::vote_service::ProposalView>>>,
    blocklist_out: Arc<Mutex<HashMap<NodeId, i64>>>,
    voted_channels_out: Arc<Mutex<Vec<crate::vote_service::ChannelDef>>>,
    removed_files: Arc<Mutex<HashSet<String>>>,
) {

    // ── Приём из сети: предложения/голоса → БД; дайджест → re-announce. ──────
    {
        let recv_pool = pool.clone();
        let recv_chat = chat.clone();
        let mut votes_rx = chat.subscribe_votes();
        tokio::spawn(async move {
            loop {
                match votes_rx.recv().await {
                    Ok(VoteGossip::Proposal(signed)) => {
                        match void_vote::Proposal::from_signed(signed) {
                            Ok(p) => { let _ = void_vote::store::insert_proposal(&recv_pool, &p).await; }
                            Err(e) => tracing::debug!("Отклонено предложение: {}", e),
                        }
                    }
                    Ok(VoteGossip::Vote(signed)) => {
                        match void_vote::Vote::from_signed(signed) {
                            Ok(v) => { let _ = void_vote::store::upsert_vote(&recv_pool, &v).await; }
                            Err(e) => tracing::debug!("Отклонён голос: {}", e),
                        }
                    }
                    Ok(VoteGossip::Digest(remote)) => {
                        // anti-entropy: до-рассылаем то, чего нет/расходится у соседа.
                        let now = chrono::Utc::now().timestamp();
                        let open = void_vote::store::list_open_proposals(&recv_pool, now).await
                            .unwrap_or_default();
                        let mut local = Vec::with_capacity(open.len());
                        for sp in &open {
                            let votes = void_vote::store::list_votes(&recv_pool, &sp.id).await
                                .unwrap_or_default();
                            local.push((sp.id.clone(), void_vote::votes_digest(&votes)));
                        }
                        for pid in void_vote::proposals_to_push(&local, &remote) {
                            if let Ok(Some(sp)) = void_vote::store::get_proposal(&recv_pool, &pid).await {
                                recv_chat.announce_proposal(sp.signed).await;
                            }
                            if let Ok(msgs) = void_vote::store::list_vote_messages(&recv_pool, &pid).await {
                                for m in msgs { recv_chat.announce_vote(m).await; }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Vote gossip lagged by {}", n);
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // ── GUI → создать предложение. Его покажут только те, у кого мы доверены, —
    // без единого поручительства за нас его не увидит никто. ────────────────
    {
        let pool = pool.clone();
        let chat = chat.clone();
        let kp = sign_kp.clone();
        tokio::spawn(async move {
            while let Some(kind) = propose_rx.recv().await {
                if my_vouchers.load(Ordering::Relaxed) == 0 {
                    tracing::warn!("Создание голосования отклонено: за нас никто не поручился");
                    continue;
                }
                let p = match void_vote::Proposal::create(kind, &kp) {
                    Ok(p) => p,
                    Err(e) => { tracing::warn!("Не удалось создать предложение: {}", e); continue; }
                };
                let _ = void_vote::store::insert_proposal(&pool, &p).await;
                // Автор автоматически голосует «за».
                if let Ok(v) = void_vote::Vote::create(p.id.clone(), true, &kp) {
                    let _ = void_vote::store::upsert_vote(&pool, &v).await;
                    chat.announce_vote(v.signed).await;
                }
                chat.announce_proposal(p.signed).await;
                tracing::info!("Создано голосование: {}", crate::vote_service::kind_label(&p.payload.kind));
            }
        });
    }

    // ── GUI → проголосовать (окно открыто). Вес голоса каждый узел считает сам. ─
    {
        let pool = pool.clone();
        let chat = chat.clone();
        let kp = sign_kp.clone();
        tokio::spawn(async move {
            while let Some((proposal_id, choice)) = vote_cast_rx.recv().await {
                let now = chrono::Utc::now().timestamp();
                match void_vote::store::get_proposal(&pool, &proposal_id).await {
                    Ok(Some(sp)) if !void_vote::tally::is_closed(sp.created_at, now) => {
                        if let Ok(v) = void_vote::Vote::create(proposal_id, choice, &kp) {
                            let _ = void_vote::store::upsert_vote(&pool, &v).await;
                            chat.announce_vote(v.signed).await;
                        }
                    }
                    Ok(Some(_)) => tracing::warn!("Голос отклонён: окно голосования закрыто"),
                    _ => tracing::warn!("Голос отклонён: предложение неизвестно"),
                }
            }
        });
    }

    // ── Периодика: дайджест, финализация+исполнение, снимок. ────────────────
    {
        let pool = pool.clone();
        let chat = chat.clone();
        let me = my_id.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(VOTE_TICK_SECS));
            loop {
                interval.tick().await;
                let now = chrono::Utc::now().timestamp();

                // Истёкшие баны убираем (с сохранением на диск).
                {
                    let expired = {
                        let mut bl = blocklist_out.lock().unwrap();
                        let before = bl.len();
                        bl.retain(|_, until| *until > now);
                        bl.len() != before
                    };
                    if expired {
                        save_blocklist(&blocklist_out);
                    }
                }

                // Дайджест открытых предложений → рассылаем (anti-entropy).
                let open = void_vote::store::list_open_proposals(&pool, now).await.unwrap_or_default();
                let mut digest = Vec::with_capacity(open.len());
                for sp in &open {
                    let votes = void_vote::store::list_votes(&pool, &sp.id).await.unwrap_or_default();
                    digest.push((sp.id.clone(), void_vote::votes_digest(&votes)));
                }
                if !digest.is_empty() {
                    chat.announce_vote_digest(digest).await;
                }

                // Все предложения: финализация закрытых + снимок для UI.
                let all = void_vote::store::list_proposals(&pool).await.unwrap_or_default();
                let mut views = Vec::with_capacity(all.len());
                for sp in &all {
                    // Предложение недоверенного автора — спам: не показываем и не исполняем.
                    let proposer_ok = proposer_trusted(&trust, &me, &sp.proposer_key);
                    let votes = void_vote::store::list_votes(&pool, &sp.id).await.unwrap_or_default();
                    let weights = voter_weights(&trust, &me, &votes);
                    let t = void_vote::tally(&sp.kind, sp.created_at, &votes, &weights, now);

                    // Финализация: окно + grace прошли, ещё не исполнено.
                    let finalize_at = sp.created_at
                        + void_vote::VOTING_WINDOW_SECS + void_vote::VOTING_GRACE_SECS;
                    if sp.closed_at.is_none() && now >= finalize_at {
                        if t.outcome == void_vote::Outcome::Passed && proposer_ok {
                            enforce_outcome(
                                &sp.kind, &manager,
                                &blocklist_out, &voted_channels_out, &removed_files, now,
                            ).await;
                            tracing::info!("Голосование принято и исполнено: {}",
                                crate::vote_service::kind_label(&sp.kind));
                        }
                        let _ = void_vote::store::mark_closed(&pool, &sp.id, now).await;
                    }
                    if !proposer_ok {
                        continue;
                    }

                    let my_vote = votes.iter()
                        .find(|v| v.voter_key == me.as_str())
                        .map(|v| v.choice);
                    views.push(crate::vote_service::ProposalView {
                        id: sp.id.clone(),
                        kind: sp.kind.clone(),
                        label: crate::vote_service::kind_label(&sp.kind),
                        proposer_short: format!("{}…", &sp.proposer_key[..8.min(sp.proposer_key.len())]),
                        created_at: sp.created_at,
                        closes_at: sp.created_at + void_vote::VOTING_WINDOW_SECS,
                        open: t.open,
                        tally: t,
                        outcome: t.outcome,
                        my_vote,
                        finalized: sp.closed_at.is_some(),
                    });
                }
                views.sort_by(|a, b| b.created_at.cmp(&a.created_at));
                *proposals_out.lock().unwrap() = views;
            }
        });
    }
}

/// Автор предложения доверен у нас («через знакомых» или лично) — или это мы.
/// Иначе предложение — спам: его не показываем и не исполняем.
fn proposer_trusted(trust: &Mutex<void_trust::TrustMap>, me: &NodeId, proposer: &str) -> bool {
    use void_trust::TrustLevel::{Trusted, Verified};
    proposer == me.as_str()
        || matches!(trust.lock().unwrap().level(&NodeId(proposer.to_string())), Trusted | Verified)
}

/// Веса голосующих в наших глазах: свой голос — 1, остальные — доверие к ним
/// (освоившиеся — из общего пула), незнакомцы — 0.
fn voter_weights(
    trust: &Mutex<void_trust::TrustMap>,
    me: &NodeId,
    votes: &[void_vote::VoteRecord],
) -> HashMap<String, void_vote::VoterWeight> {
    use void_trust::TrustLevel::{Trusted, Verified};
    let map = trust.lock().unwrap();
    let others: Vec<NodeId> = votes.iter()
        .map(|v| NodeId(v.voter_key.clone()))
        .filter(|id| id != me)
        .collect();
    let mut out: HashMap<String, void_vote::VoterWeight> = map.weights(others.iter())
        .into_iter()
        .map(|(id, weight)| {
            let trusted = matches!(map.level(&id), Trusted | Verified);
            (id.0, void_vote::VoterWeight { weight, trusted })
        })
        .collect();
    if votes.iter().any(|v| v.voter_key == me.as_str()) {
        out.insert(me.0.clone(), void_vote::VoterWeight { weight: 1.0, trusted: true });
    }
    out
}

/// Исполняет принятое решение локально и персистит результат.
async fn enforce_outcome(
    kind: &void_vote::ProposalKind,
    manager: &StorageManager,
    blocklist: &Arc<Mutex<HashMap<NodeId, i64>>>,
    channels: &Arc<Mutex<Vec<crate::vote_service::ChannelDef>>>,
    removed: &Arc<Mutex<HashSet<String>>>,
    now: i64,
) {
    use void_vote::ProposalKind as K;
    match kind {
        K::BanUser { target } => {
            blocklist.lock().unwrap()
                .insert(NodeId(target.clone()), now + void_vote::BAN_DURATION_SECS);
            save_blocklist(blocklist);
        }
        K::UnbanUser { target } => {
            blocklist.lock().unwrap().remove(&NodeId(target.clone()));
            save_blocklist(blocklist);
        }
        K::AddChannel { id, name, icon } => {
            let mut ch = channels.lock().unwrap();
            if !ch.iter().any(|c| c.id == *id) {
                ch.push(crate::vote_service::ChannelDef {
                    id: id.clone(), name: name.clone(), icon: icon.clone(),
                });
                crate::vote_service::save_voted_channels(&ch);
            }
        }
        K::RemoveFile { file_id } => {
            {
                let mut set = removed.lock().unwrap();
                set.insert(file_id.clone());
                crate::vote_service::save_removed_files(&set);
            }
            // Стираем локальную копию и перестаём сидировать.
            let _ = manager.delete_file(file_id).await;
        }
    }
}

/// Забанен ли узел на момент `now` (бан не истёк).
fn is_banned(blocklist: &Arc<Mutex<HashMap<NodeId, i64>>>, who: &NodeId, now: i64) -> bool {
    blocklist.lock().unwrap().get(who).is_some_and(|until| *until > now)
}

/// Сохраняет блок-лист на диск (NodeId → ts истечения).
fn save_blocklist(blocklist: &Arc<Mutex<HashMap<NodeId, i64>>>) {
    let snap: HashMap<String, i64> = blocklist
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), *v))
        .collect();
    crate::vote_service::save_bans(&snap);
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
        &msg.channel,
        sent_at,
    )
    .await
}

/// Преобразует запись из БД в ChatMessage (для GUI и для истории чата).
fn db_msg_to_chat(m: void_db::messages::PublicMessage) -> ChatMessage {
    ChatMessage {
        from:      NodeId(m.sender_key),
        from_name: m.sender_name,
        text:      m.content,
        timestamp: m.sent_at.timestamp(),
        // seq нужен для проверки подписи (история уходит соседям): он хранится
        // в message_id = "{sender_key}:{seq}".
        seq:       m.message_id.rsplit_once(':').and_then(|(_, s)| s.parse().ok()).unwrap_or(0),
        signature: if m.signature.is_empty() { None } else { Some(m.signature) },
        channel:   m.channel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(i: u32) -> NodeId {
        NodeId(format!("{i:064x}"))
    }

    fn vote(i: u32) -> void_vote::VoteRecord {
        void_vote::VoteRecord { voter_key: n(i).0, choice: true, created_at: 0 }
    }

    /// Я — узел 0; лично проверил 1, через 1 знаю 2 (t = 0.5).
    fn trust() -> Mutex<void_trust::TrustMap> {
        let v = |from: u32, to: u32| void_trust::Vouch {
            voucher: n(from), subject: n(to), kind: void_trust::VouchKind::Personal,
            updated_at: 1, revoked: false,
        };
        let empty = HashSet::new();
        Mutex::new(void_trust::compute(&void_trust::TrustInputs {
            me: &n(0),
            vouches: &[v(0, 1), v(1, 2)],
            blocked: &empty,
            reported: &empty,
            settled: &empty,
            private_verified: &empty,
        }))
    }

    #[test]
    fn my_vote_weighs_one_strangers_nothing() {
        let w = voter_weights(&trust(), &n(0), &[vote(0), vote(1), vote(2), vote(9)]);
        assert_eq!(w[&n(0).0], void_vote::VoterWeight { weight: 1.0, trusted: true });
        assert_eq!(w[&n(1).0], void_vote::VoterWeight { weight: 1.0, trusted: true });
        assert!((w[&n(2).0].weight - 0.5).abs() < 1e-9 && w[&n(2).0].trusted);
        assert!(w.get(&n(9).0).is_none_or(|x| x.weight == 0.0), "незнакомец не весит");
    }

    #[test]
    fn only_trusted_authors_proposals_count() {
        let t = trust();
        assert!(proposer_trusted(&t, &n(0), n(0).as_str()), "своё предложение");
        assert!(proposer_trusted(&t, &n(0), n(2).as_str()), "через знакомых");
        assert!(!proposer_trusted(&t, &n(0), n(9).as_str()), "незнакомец — спам");
    }

    #[test]
    fn greeting_never_downgrades_and_revoke_keeps_kind() {
        use void_trust::VouchKind::{Greeter, Personal};
        let rec = |kind, revoked| void_trust::Vouch {
            voucher: n(0), subject: n(1), kind, updated_at: 1, revoked,
        };
        assert_eq!(next_vouch_kind(None, Greeter, false), Some(Greeter));
        assert_eq!(next_vouch_kind(Some(&rec(Personal, false)), Greeter, false), None, "не понижаем");
        assert_eq!(next_vouch_kind(Some(&rec(Greeter, false)), Personal, false), Some(Personal), "повышаем");
        assert_eq!(next_vouch_kind(Some(&rec(Greeter, false)), Personal, true), Some(Greeter), "отзыв приветствия");
        assert_eq!(next_vouch_kind(Some(&rec(Personal, true)), Personal, true), None, "отзывать нечего");
        assert_eq!(next_vouch_kind(Some(&rec(Personal, true)), Greeter, false), Some(Greeter), "после отзыва — можно");
    }
}
