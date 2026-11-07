//! Общий чат и рассылка (gossip) — сеть без центра.
//!
//! Каждый узел держит соединения («связи») с несколькими соседями: сам
//! дозванивается до [`TARGET_OUT_LINKS`] случайных известных узлов и принимает
//! входящие. Всё новое (сообщение, профиль, манифест, DNS-запись, голос…)
//! пересылается всем соседям, кроме того, от кого пришло. Повторы гасятся
//! дедупом, поэтому пакет проходит по каждой связи не больше одного раза.
//!
//! Раньше схема была «звездой»: все подключались к узлу с наименьшим ID. Такой
//! ID подбирается за секунды, и узел-злоумышленник законно становился
//! ретранслятором — мог молча выбрасывать сообщения и рассылку всей сети.
//! Теперь один узел ничего не скроет: пакеты обходят его по другим связям.
//!
//! Связь — Noise ([`void_network::secure`], канал `Chat`) + length-prefixed JSON:
//!   инициатор → Hello, ответчик → Hello (оба NodeId доказаны рукопожатием);
//!   затем обе стороны присылают, что знают: History, профили, манифесты,
//!   сайты, надгробия, DNS-записи; дальше — пересылка и Ping/Pong.
//! Если два узла дозвонились друг другу одновременно, остаётся связь,
//! открытая узлом с меньшим ID (обе стороны выбирают одну и ту же).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, Notify};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use void_core::dns::{normalize_name, DnsRecord};
use void_core::identity::NodeId;
use void_core::manifest::FileManifest;
use void_core::peer::{PeerInfo, PeerProfile};
use void_core::site::{SiteManifest, SiteRevocation};
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_discovery::PeerList;
use void_network::rate_limit::RateLimiter;
use void_network::conn_guard::ConnLimiter;
use void_network::secure::{self, Channel, NoiseIdentity};

use crate::trust_limits::{AuthorTier, Kind, TierFn, TierLimits};

/// Потолок размера одного пакета на проводе. Поднят до 16 МиБ, чтобы вмещать
/// манифесты крупных файлов (список хэшей чанков): при 256 КБ/чанк это
/// ~176 000 чанков ≈ 43 ГБ файл. Текстовые сообщения/профили на порядки меньше.
const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;
const BROADCAST_BUFFER: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Сколько последних сообщений помним для дедупа. С запасом больше истории,
/// которой обмениваются связи, и истории, подгружаемой из БД при старте.
const DEDUP_WINDOW: usize = 4096;
/// Сколько подписанных пакетов (DNS, голоса, репутация, надгробия) помним для
/// дедупа по подписи — без этого в сети с циклами они ходили бы по кругу.
const GOSSIP_DEDUP_WINDOW: usize = 8192;
/// Сколько последних DNS-записей храним, чтобы передать новой связи.
const MAX_DNS_CACHE: usize = 4096;
/// Лимит текста одного сообщения чата (байт). Пакет может быть до
/// `MAX_MESSAGE_LEN` (манифесты больших файлов), но 16 МиБ текста в чате —
/// это DoS интерфейса у всех получателей.
pub const MAX_CHAT_TEXT_BYTES: usize = 8 * 1024;
/// Лимиты служебных полей сообщения (символов).
const MAX_CHANNEL_CHARS: usize = 64;
const MAX_SENDER_NAME_CHARS: usize = void_core::peer::MAX_PROFILE_NAME_CHARS;
/// Сколько исходящих связей держит узел (плюс входящие от других). Случайный
/// граф со степенью 3 связен с подавляющей вероятностью даже для больших сетей.
pub const TARGET_OUT_LINKS: usize = 3;
/// Таймаут установки связи: TCP + Noise + обмен Hello. Защита от узла,
/// который принял соединение и молчит.
const LINK_SETUP_TIMEOUT: Duration = Duration::from_secs(20);
/// Пауза перед повторным дозвоном до недоступного узла (удваивается до максимума).
const DIAL_RETRY_BASE: Duration = Duration::from_secs(5);
const DIAL_RETRY_MAX: Duration = Duration::from_secs(60);
/// Очередь пакетов на отправку в одну связь. Переполнение = медленный сосед:
/// пакет для него теряется (его догонит обмен при следующей связи).
const LINK_QUEUE: usize = 256;
/// Бюджет пакетов от одного соседа (token bucket): запас на обмен при
/// установке связи и скорость пополнения. Сосед, долго выжигающий бюджет,
/// отключается — но спам-штраф репутации получает автор, а не пересыльщик.
const LINK_BURST: f64 = 4000.0;
const LINK_RATE_PER_SEC: f64 = 400.0;
const LINK_MAX_DROPS: u32 = 2000;
/// Сообщение «живое» (а не догоняющая история), если его время в этом окне.
/// Только живые считаются в лимите частоты автора (спам-защита).
const LIVE_WINDOW_SECS: i64 = 120;
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
    /// Объявление о публикации файла — рассылается всем (как ProfileUpdate).
    FileAnnounce(FileManifest),
    /// Объявление о публикации сайта — рассылается всем (как FileAnnounce).
    SiteAnnounce(SiteManifest),
    /// Подписанное надгробие сайта: владелец удалил сайт (payload = SiteRevocation,
    /// signer = owner). Получатели стирают сайт и подавляют его воскрешение.
    SiteRevoke { signed: SignedMessage },
    /// Подписанная жалоба на узел (reporter = signed.signer).
    ReputationReport { signed: SignedMessage },
    /// Подписанная DNS-запись зоны `.void` (owner = signed.signer).
    DnsAnnounce { signed: SignedMessage },
    /// Подписанное предложение голосования (proposer = signed.signer).
    ProposalAnnounce { signed: SignedMessage },
    /// Подписанный голос (voter = signed.signer).
    VoteAnnounce { signed: SignedMessage },
    /// Дайджест для anti-entropy: `(proposal_id, votes_hash)` по открытым
    /// предложениям. Получатель до-рассылает то, чего у отправителя нет.
    VoteDigest { items: Vec<(String, String)> },
    /// Подписанное поручительство (voucher = signed.signer). Чат его не
    /// пересылает сам: дальше его отправляет backend, если запись изменила его
    /// базу — иначе на каждой новой связи весь граф заново обходил бы сеть.
    Vouch { signed: SignedMessage },
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
    /// Канал («доска») сообщения. Сообщения рассылаются всем, но UI фильтрует
    /// их по каналу. По умолчанию — глобальный канал ("global").
    #[serde(default = "default_channel")]
    pub channel: String,
}

/// Канал по умолчанию для пакетов без поля `channel` (совместимость версий).
pub fn default_channel() -> String {
    "global".to_string()
}

impl ChatMessage {
    pub fn new(from: NodeId, from_name: String, text: String, channel: String, seq: u64) -> Self {
        ChatMessage {
            from, from_name, text, channel,
            timestamp: Utc::now().timestamp(), seq, signature: None,
        }
    }
}

/// Входящее событие голосований, переданное backend'у (он проверяет подпись и
/// трактует payload — чат лишь переносит подписанные пакеты, не зная их смысла).
#[derive(Debug, Clone)]
pub enum VoteGossip {
    /// Предложение (proposer = signed.signer).
    Proposal(SignedMessage),
    /// Голос (voter = signed.signer).
    Vote(SignedMessage),
    /// Дайджест соседа `(proposal_id, votes_hash)` — backend сравнит со своим
    /// и до-рассылает недостающее (anti-entropy union).
    Digest(Vec<(String, String)>),
}

/// Входящее поручительство и сосед, от которого оно пришло (backend решает,
/// пересылать ли его дальше, и не отправляет его обратно источнику).
#[derive(Debug, Clone)]
pub struct VouchGossip {
    pub signed: SignedMessage,
    pub from: NodeId,
}

// ─── Состояние ───────────────────────────────────────────────────────────────

/// Связь с соседом.
struct Link {
    /// Очередь пакетов на отправку соседу.
    tx: mpsc::Sender<ChatPacket>,
    /// Номер связи (см. `link_seq`).
    id: u64,
    /// Мы дозвонились (иначе — сосед к нам).
    initiated_by_me: bool,
    /// Сигнал закрыть связь (её вытеснила встречная — см. `register_link`).
    close: Arc<Notify>,
}

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
    /// Noise-ключ соединений чата, привязанный к нашему NodeId.
    noise:       NoiseIdentity,
    incoming_tx: broadcast::Sender<ChatMessage>,
    history:     Mutex<VecDeque<ChatMessage>>,
    seq_counter: Mutex<u64>,
    seen:        Mutex<HashSet<(String, u64)>>,
    seen_order:  Mutex<VecDeque<(String, u64)>>,
    /// Связи с соседями (входящие и исходящие): NodeId соседа → связь.
    links:       Mutex<HashMap<NodeId, Link>>,
    /// Узлы, до которых сейчас идёт дозвон (не звоним дважды параллельно).
    dialing:     Mutex<HashSet<NodeId>>,
    /// Профили известных пиров
    profiles:    Mutex<HashMap<NodeId, PeerProfile>>,
    /// Наш собственный профиль (для рассылки при подключении)
    my_profile:  Mutex<Option<PeerProfile>>,
    /// Известные манифесты файлов (file_id → манифест) — для рассылки и дедупа
    manifests:   Mutex<HashMap<String, FileManifest>>,
    /// Уведомление backend о новых (впервые увиденных) манифестах
    manifest_tx: broadcast::Sender<FileManifest>,
    /// Известные манифесты сайтов (имя → манифест) — для рассылки и дедупа
    sites:       Mutex<HashMap<String, SiteManifest>>,
    /// Уведомление backend о новых/обновлённых манифестах сайтов
    site_tx:     broadcast::Sender<SiteManifest>,
    /// Надгробия удалённых сайтов (имя → (надгробие, подписанный оригинал)).
    /// Подавляют воскрешение устаревших анонсов и распространяются новым пирам.
    site_tombstones: Mutex<HashMap<String, (SiteRevocation, SignedMessage)>>,
    /// Уведомление backend об удалении сайта (он стирает кэш-файлы/реестр)
    site_revoke_tx:  broadcast::Sender<SiteRevocation>,
    /// Входящие жалобы → backend (он проверяет и считает их вес)
    report_tx:   broadcast::Sender<SignedMessage>,
    /// Входящие подписанные DNS-записи → backend (он проверяет/применяет)
    dns_tx:      broadcast::Sender<SignedMessage>,
    /// Входящие предложения/голоса → backend (он проверяет подпись и считает)
    vote_tx:     broadcast::Sender<VoteGossip>,
    /// Входящие поручительства → backend (он проверяет и решает о пересылке)
    vouch_tx:    broadcast::Sender<VouchGossip>,
    /// Новая связь с соседом → backend (передать ему свои данные, например граф доверия)
    link_tx:     broadcast::Sender<NodeId>,
    /// Ограничитель частоты пакетов (флуд-защита на релее). None = выключен.
    rate_limiter: Option<RateLimiter>,
    /// Сигнал backend'у: узел превысил лимит (→ спам-страйк репутации).
    spam_tx:     broadcast::Sender<NodeId>,
    /// Уровень автора по сети доверия (ставит backend). Пока не задан — все
    /// авторы считаются доверенными (как до сети доверия).
    tiers:       std::sync::OnceLock<TierFn>,
    /// Лимиты незнакомцев и освоившихся.
    tier_limits: TierLimits,
    /// Номер для очередной связи — чтобы закрытие старой связи не удалило новую.
    link_seq:    AtomicU64,
    /// Недоступные узлы: id → (не звонить до, число неудач подряд).
    dial_failures: Mutex<HashMap<String, (Instant, u32)>>,
    /// Подписи уже виденных подписанных пакетов (дедуп рассылки в сети с циклами).
    seen_gossip:       Mutex<HashSet<String>>,
    seen_gossip_order: Mutex<VecDeque<String>>,
    /// Последние DNS-записи по (имя, подписант) — передаются новой связи, чтобы
    /// новичок узнал имена, даже не соединённый напрямую с их владельцами.
    dns_cache:   Mutex<HashMap<(String, String), (i64, SignedMessage)>>,
}

impl PublicChat {
    fn new(
        my_peer: PeerInfo,
        peer_list: PeerList,
        chat_port: u16,
        signing_kp: Arc<SigningKeypair>,
        rate_limiter: Option<RateLimiter>,
    ) -> Self {
        let (incoming_tx, _) = broadcast::channel(BROADCAST_BUFFER);
        let (manifest_tx, _) = broadcast::channel(BROADCAST_BUFFER);
        let (site_tx, _)     = broadcast::channel(BROADCAST_BUFFER);
        let (site_revoke_tx, _) = broadcast::channel(BROADCAST_BUFFER);
        let (report_tx, _)   = broadcast::channel(BROADCAST_BUFFER);
        let (dns_tx, _)      = broadcast::channel(BROADCAST_BUFFER);
        let (vote_tx, _)     = broadcast::channel(BROADCAST_BUFFER);
        let (vouch_tx, _)    = broadcast::channel(4 * BROADCAST_BUFFER);
        let (link_tx, _)     = broadcast::channel(BROADCAST_BUFFER);
        let (spam_tx, _)     = broadcast::channel(BROADCAST_BUFFER);
        let noise = NoiseIdentity::new(&signing_kp);
        PublicChat {
            inner: Arc::new(PublicChatInner {
                my_peer, peer_list, chat_port, signing_kp, noise, incoming_tx,
                history:     Mutex::new(VecDeque::with_capacity(100)),
                seq_counter: Mutex::new(0),
                seen:        Mutex::new(HashSet::new()),
                seen_order:  Mutex::new(VecDeque::with_capacity(DEDUP_WINDOW)),
                links:       Mutex::new(HashMap::new()),
                dialing:     Mutex::new(HashSet::new()),
                profiles:    Mutex::new(HashMap::new()),
                my_profile:  Mutex::new(None),
                manifests:   Mutex::new(HashMap::new()),
                manifest_tx,
                sites:       Mutex::new(HashMap::new()),
                site_tx,
                site_tombstones: Mutex::new(HashMap::new()),
                site_revoke_tx,
                report_tx,
                dns_tx,
                vote_tx,
                vouch_tx,
                link_tx,
                rate_limiter,
                spam_tx,
                tiers:       std::sync::OnceLock::new(),
                tier_limits: TierLimits::default(),
                link_seq:    AtomicU64::new(0),
                dial_failures: Mutex::new(HashMap::new()),
                seen_gossip:       Mutex::new(HashSet::new()),
                seen_gossip_order: Mutex::new(VecDeque::with_capacity(GOSSIP_DEDUP_WINDOW)),
                dns_cache:   Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> {
        self.inner.incoming_tx.subscribe()
    }

    /// Подписка backend на сигналы о превышении лимита (узел → спам-страйк).
    pub fn subscribe_spam(&self) -> broadcast::Receiver<NodeId> {
        self.inner.spam_tx.subscribe()
    }

    /// Проверяет лимит частоты пакетов от `from` (флуд-защита на релее).
    /// При превышении — дропаем пакет и сигналим backend'у (спам-страйк).
    /// Возвращает `true`, если пакет можно обрабатывать. Без лимитера — всегда `true`.
    async fn allow_packet(&self, from: &NodeId) -> bool {
        if let Some(rl) = &self.inner.rate_limiter {
            if !rl.check(from).await {
                let _ = self.inner.spam_tx.send(from.clone());
                return false;
            }
        }
        true
    }

    /// Задаёт уровень авторов по сети доверия (один раз; повторный вызов
    /// игнорируется — функция сама читает свежий снимок).
    pub fn set_author_tiers(&self, tiers: TierFn) {
        let _ = self.inner.tiers.set(tiers);
    }

    fn author_tier(&self, author: &NodeId) -> AuthorTier {
        self.inner.tiers.get().map_or(AuthorTier::Trusted, |f| f(author))
    }

    /// Лимит по уровню доверия автора: `true` — пропустить. Вызывать только
    /// после проверки подписи автора — иначе чужим ID можно выжечь его бюджет.
    fn admit(&self, author: &NodeId, kind: Kind) -> bool {
        self.inner.tier_limits.admit(author, self.author_tier(author), kind)
    }

    /// То же для подписанного пакета рассылки (автор = подписант).
    fn admit_signed(&self, signed: &SignedMessage, kind: Kind) -> bool {
        let author = NodeId(signed.signer.clone());
        if self.author_tier(&author) == AuthorTier::Trusted {
            return true;
        }
        signed.verify().is_ok() && self.admit(&author, kind)
    }

    /// Отправляет пакет всем соседям, кроме `except` (того, от кого он пришёл).
    async fn forward(&self, pkt: ChatPacket, except: Option<&NodeId>) {
        let links = self.inner.links.lock().await;
        for (id, link) in links.iter() {
            if Some(id) != except {
                let _ = link.tx.try_send(pkt.clone());
            }
        }
    }

    /// `true`, если подписанный пакет видим впервые. Дедуп по подписи: в сети с
    /// циклами без него DNS-записи, голоса и снимки репутации ходили бы по кругу.
    async fn first_seen_gossip(&self, signed: &SignedMessage) -> bool {
        let mut seen = self.inner.seen_gossip.lock().await;
        if !seen.insert(signed.signature.clone()) {
            return false;
        }
        let mut order = self.inner.seen_gossip_order.lock().await;
        order.push_back(signed.signature.clone());
        if order.len() > GOSSIP_DEDUP_WINDOW {
            if let Some(old) = order.pop_front() {
                seen.remove(&old);
            }
        }
        true
    }

    /// Забывает подпись пакета, отброшенного по лимиту: копия, пришедшая
    /// позже (когда бюджет автора восстановится), обработается заново.
    async fn unsee_gossip(&self, signed: &SignedMessage) {
        self.inner.seen_gossip.lock().await.remove(&signed.signature);
    }

    /// Запоминает DNS-запись для передачи новым связям (последняя версия по
    /// паре имя+подписант; проверку и разрешение конфликтов делает backend).
    async fn cache_dns(&self, signed: &SignedMessage) {
        let Ok(rec) = serde_json::from_slice::<DnsRecord>(&signed.payload) else { return };
        let mut cache = self.inner.dns_cache.lock().await;
        let key = (rec.name, signed.signer.clone());
        if cache.get(&key).is_some_and(|(v, _)| *v >= rec.updated_at) {
            return;
        }
        if cache.len() >= MAX_DNS_CACHE && !cache.contains_key(&key) {
            return; // переполнение (флуд записей) — новые не кэшируем
        }
        cache.insert(key, (rec.updated_at, signed.clone()));
    }

    /// Число текущих связей с соседями.
    pub async fn link_count(&self) -> usize {
        self.inner.links.lock().await.len()
    }

    /// Подгружает историю (например, из БД после перезапуска): помечает её
    /// виденной — пришедшие от соседей копии не покажутся повторно — и отдаёт
    /// её новым связям, чтобы соседи догнали пропущенное.
    pub async fn preload_history(&self, messages: Vec<ChatMessage>) {
        for msg in messages {
            if !message_within_limits(&msg) || !self.verify_message(&msg) {
                continue; // старые записи (до подписи имени) соседям бесполезны
            }
            if !self.mark_seen(&msg).await {
                continue;
            }
            let mut h = self.inner.history.lock().await;
            if h.len() >= 100 { h.pop_front(); }
            h.push_back(msg);
        }
    }

    /// Отмечает сообщение виденным. `false` — уже было (дубликат).
    async fn mark_seen(&self, msg: &ChatMessage) -> bool {
        let key = (msg.from.as_str().to_string(), msg.seq);
        let mut seen = self.inner.seen.lock().await;
        if !seen.insert(key.clone()) {
            return false;
        }
        let mut order = self.inner.seen_order.lock().await;
        order.push_back(key);
        if order.len() > DEDUP_WINDOW {
            if let Some(old) = order.pop_front() {
                seen.remove(&old);
            }
        }
        true
    }

    /// Снимает отметку «видено» с сообщения, отброшенного по лимиту.
    async fn unmark_seen(&self, msg: &ChatMessage) {
        let key = (msg.from.as_str().to_string(), msg.seq);
        self.inner.seen.lock().await.remove(&key);
    }

    pub async fn recent(&self, n: usize) -> Vec<ChatMessage> {
        let h = self.inner.history.lock().await;
        h.iter().rev().take(n).cloned().collect::<Vec<_>>().into_iter().rev().collect()
    }

    pub async fn get_profiles(&self) -> Vec<PeerProfile> {
        self.inner.profiles.lock().await.values().cloned().collect()
    }

    /// Обновить собственный профиль и разослать всем подключённым. Профиль
    /// приводится к лимитам, получает метку времени и подписывается нашим ключом.
    pub async fn set_profile(&self, mut profile: PeerProfile) {
        profile.node_id = self.inner.my_peer.id.clone();
        profile.sanitize();
        {
            let mut mine = self.inner.my_profile.lock().await;
            // Строго растущая метка: два обновления за одну миллисекунду не
            // должны выглядеть у получателей как «старая версия».
            let prev = mine.as_ref().map(|p| p.updated_at).unwrap_or(0);
            profile.updated_at = Utc::now().timestamp_millis().max(prev + 1);
            profile.signature = None;
            match SignedMessage::sign(profile.signing_bytes(), &self.inner.signing_kp) {
                Ok(signed) => profile.signature = Some(signed.signature),
                Err(e) => warn!("Не удалось подписать профиль: {:?}", e),
            }
            *mine = Some(profile.clone());
        }
        self.forward(ChatPacket::ProfileUpdate(profile), None).await;
    }

    /// Подписка backend на новые манифесты файлов, пришедшие из сети.
    pub fn subscribe_manifests(&self) -> broadcast::Receiver<FileManifest> {
        self.inner.manifest_tx.subscribe()
    }

    /// Все известные на данный момент манифесты файлов.
    pub async fn get_manifests(&self) -> Vec<FileManifest> {
        self.inner.manifests.lock().await.values().cloned().collect()
    }

    /// Объявляет наш файл сети: добавляет себя в список сидеров манифеста и
    /// рассылает объединённый манифест соседям (они перешлют дальше).
    pub async fn announce_file(&self, manifest: FileManifest) {
        // Сливаем с уже известным (мы могли знать других сидеров) и рассылаем
        // объединённый вариант. Даже если ничего нового не добавилось, шлём
        // нашу версию — получатели дедуплицируют сами.
        let merged = self.merge_manifest(manifest.clone(), None).await.unwrap_or(manifest);
        self.forward(ChatPacket::FileAnnounce(merged), None).await;
    }

    /// Объединяет входящий манифест с уже известным по `file_id`: добавляет
    /// новых сидеров. Возвращает обновлённый манифест, если появилась новая
    /// информация (новый файл или новый владелец), иначе `None` (дедуп — это
    /// гасит петли форвардинга). Новый файл из сети (`src`) проходит лимит
    /// публикаций по уровню доверия публикатора.
    async fn merge_manifest(&self, incoming: FileManifest, src: Option<&NodeId>) -> Option<FileManifest> {
        let mut map = self.inner.manifests.lock().await;
        match map.get_mut(&incoming.file_id) {
            Some(existing) => {
                let mut changed = false;
                for owner in &incoming.owners {
                    if existing.add_owner(owner.clone()) {
                        changed = true;
                    }
                }
                if changed { Some(existing.clone()) } else { None }
            }
            None => {
                // Новый файл принимаем только с подписью публикатора: иначе
                // любой узел объявлял бы файлы «от имени» другого (или
                // переименовывал чужие). Для уже известного file_id из входящего
                // берём лишь сидеров — подписанная часть остаётся прежней.
                if !verify_file_manifest(&incoming) {
                    warn!("Отброшен манифест файла {} без верной подписи публикатора", incoming.file_id);
                    return None;
                }
                if src.is_some() {
                    let publisher = incoming.publisher.as_ref()?;
                    if !self.admit(publisher, Kind::Publish) {
                        return None;
                    }
                }
                map.insert(incoming.file_id.clone(), incoming.clone());
                Some(incoming)
            }
        }
    }

    // ─── Сайты (обнаружение в сети) ───────────────────────────────────────────

    /// Подписка backend на манифесты сайтов, пришедшие из сети.
    pub fn subscribe_sites(&self) -> broadcast::Receiver<SiteManifest> {
        self.inner.site_tx.subscribe()
    }

    /// Все известные на данный момент манифесты сайтов.
    pub async fn get_sites(&self) -> Vec<SiteManifest> {
        self.inner.sites.lock().await.values().cloned().collect()
    }

    /// Объявляет наш сайт сети: запоминает его и рассылает соседям.
    pub async fn announce_site(&self, manifest: SiteManifest) {
        // Это НАШ сайт — всегда регистрируем его локально (даже если имя занял
        // кто-то ещё) и рассылаем. Перехват у нас не работает: чужие узлы
        // применяют first-owner-wins в `merge_site` и наш манифест на чужое имя
        // отклонят.
        self.inner.sites.lock().await
            .insert(manifest.name.clone(), manifest.clone());
        self.forward(ChatPacket::SiteAnnounce(manifest), None).await;
    }

    /// Объединяет входящий (из сети) манифест сайта с известным по имени.
    /// Возвращает `Some`, если это новый сайт или более свежая версия того же
    /// владельца (по `created_at`), иначе `None` (дедуп / отказ в перехвате).
    /// Новая версия из сети проходит лимит публикаций по уровню владельца.
    async fn merge_site(&self, incoming: SiteManifest, src: Option<&NodeId>) -> Option<SiteManifest> {
        // Имя сайта попадает в URL, который UI отдаёт системе на открытие:
        // принимаем только нормализованную метку `[a-z0-9-]` (как при публикации).
        if !is_normalized_site_name(&incoming.name) {
            warn!("Отброшен анонс сайта с недопустимым именем {:?}", incoming.name);
            return None;
        }
        // Владелец подписывает манифест: подменить файлы сайта «от его имени» нельзя.
        if !verify_site(&incoming) {
            warn!("Отброшен манифест сайта '{}' без верной подписи владельца", incoming.name);
            return None;
        }
        // Надгробие подавляет воскрешение: устаревший анонс того же владельца
        // (created_at <= revoked_at) отбрасываем. Более новая публикация того же
        // владельца проходит (re-publish после удаления).
        {
            let tombs = self.inner.site_tombstones.lock().await;
            if let Some((rev, _)) = tombs.get(&incoming.name) {
                if rev.owner == incoming.owner && incoming.created_at <= rev.revoked_at {
                    return None;
                }
            }
        }
        let mut map = self.inner.sites.lock().await;
        match map.get(&incoming.name) {
            // Тот же контент — дедуп (гасит петли форвардинга).
            Some(existing) if existing.site_id == incoming.site_id => None,
            // Имя уже принадлежит ДРУГОМУ владельцу — не даём перехватить его
            // чужим манифестом (first-owner-wins, защита от подмены имени).
            Some(existing) if existing.owner != incoming.owner => {
                warn!(
                    "Сайт '{}' уже принадлежит {} — игнорирую манифест от {}",
                    incoming.name, existing.owner, incoming.owner
                );
                None
            }
            // Более старая версия того же владельца — игнорируем.
            Some(existing) if existing.created_at > incoming.created_at => None,
            _ if src.is_some() && !self.admit(&incoming.owner, Kind::Publish) => None,
            _ => {
                map.insert(incoming.name.clone(), incoming.clone());
                Some(incoming)
            }
        }
    }

    /// Обрабатывает входящее объявление о сайте: сливает с известным, уведомляет
    /// backend (регистрация в реестре) и пересылает соседям, кроме источника.
    /// Дедуп через `merge_site` гасит петли пересылки.
    async fn handle_site_announce(&self, manifest: SiteManifest, src: Option<&NodeId>) {
        let Some(merged) = self.merge_site(manifest, src).await else {
            return; // ничего нового — не пересылаем повторно
        };
        let _ = self.inner.site_tx.send(merged.clone());
        self.forward(ChatPacket::SiteAnnounce(merged), src).await;
    }

    // ─── Удаление сайта (надгробия) ───────────────────────────────────────────

    /// Подписка backend на надгробия удалённых сайтов (стереть кэш-файлы/реестр).
    pub fn subscribe_site_revokes(&self) -> broadcast::Receiver<SiteRevocation> {
        self.inner.site_revoke_tx.subscribe()
    }

    /// Объявляет удаление НАШЕГО сайта: записывает надгробие локально (чтобы
    /// устаревшие анонсы не воскрешали сайт) и рассылает его сети.
    pub async fn announce_site_revoke(&self, signed: SignedMessage) {
        let Ok(rev) = serde_json::from_slice::<SiteRevocation>(&signed.payload) else {
            warn!("announce_site_revoke: некорректный payload надгробия");
            return;
        };
        self.apply_revoke_local(rev, signed.clone()).await;
        self.first_seen_gossip(&signed).await;
        self.forward(ChatPacket::SiteRevoke { signed }, None).await;
    }

    /// Применяет надгробие локально: запоминает его (latest-wins по revoked_at) и
    /// убирает сайт из реестра рассылки. Не трогает файлы/backend — это делает
    /// `handle_site_revoke` (для входящих) или backend (для своих).
    async fn apply_revoke_local(&self, rev: SiteRevocation, signed: SignedMessage) {
        {
            let mut tombs = self.inner.site_tombstones.lock().await;
            match tombs.get(&rev.name) {
                Some((existing, _)) if existing.revoked_at >= rev.revoked_at => {}
                _ => { tombs.insert(rev.name.clone(), (rev.clone(), signed)); }
            }
        }
        // Убираем сайт из карты рассылки, только если владелец совпадает.
        let mut sites = self.inner.sites.lock().await;
        if sites.get(&rev.name).map(|m| m.owner == rev.owner).unwrap_or(false) {
            sites.remove(&rev.name);
        }
    }

    /// Обрабатывает входящее надгробие: проверяет подпись (`signer == owner`),
    /// применяет локально, уведомляет backend и пересылает соседям, кроме источника.
    async fn handle_site_revoke(&self, signed: SignedMessage, src: Option<&NodeId>) {
        if !self.first_seen_gossip(&signed).await {
            return;
        }
        let Ok(rev) = serde_json::from_slice::<SiteRevocation>(&signed.payload) else {
            warn!("SiteRevoke: некорректный payload надгробия");
            return;
        };
        if signed.verify().is_err() || signed.signer != rev.owner.as_str() {
            warn!("SiteRevoke '{}': подпись неверна или signer ≠ владелец", rev.name);
            return;
        }
        if !is_normalized_site_name(&rev.name) {
            warn!("SiteRevoke: недопустимое имя сайта {:?}", rev.name);
            return;
        }
        self.apply_revoke_local(rev.clone(), signed.clone()).await;
        let _ = self.inner.site_revoke_tx.send(rev);
        self.forward(ChatPacket::SiteRevoke { signed }, src).await;
    }

    // ─── Жалобы (gossip) ──────────────────────────────────────────────────────

    /// Подписка backend на входящие жалобы (reporter = signed.signer).
    pub fn subscribe_reports(&self) -> broadcast::Receiver<SignedMessage> {
        self.inner.report_tx.subscribe()
    }

    /// Рассылает нашу жалобу на узел.
    pub async fn broadcast_report(&self, signed: SignedMessage) {
        self.broadcast_gossip_packet(ChatPacket::ReputationReport { signed }).await;
    }

    /// Рассылает наш подписанный пакет соседям (жалобы/голосования). Свои
    /// пакеты помечаем виденными — эхо из сети не обработаем повторно.
    async fn broadcast_gossip_packet(&self, pkt: ChatPacket) {
        if let Some(signed) = gossip_signature(&pkt) {
            self.first_seen_gossip(signed).await;
        }
        self.forward(pkt, None).await;
    }

    /// Обрабатывает входящую жалобу: отдаёт backend'у и пересылает соседям,
    /// кроме источника. Смысл жалобы и её вес — в backend; чат гасит повторы
    /// по подписи и держит лимит частоты по уровню доверия заявителя.
    async fn handle_report(&self, signed: SignedMessage, src: Option<&NodeId>) {
        if !self.first_seen_gossip(&signed).await {
            return;
        }
        if src.is_some() && !self.admit_signed(&signed, Kind::Report) {
            self.unsee_gossip(&signed).await;
            return;
        }
        let _ = self.inner.report_tx.send(signed.clone());
        self.forward(ChatPacket::ReputationReport { signed }, src).await;
    }

    // ─── Голосования (void-vote) ──────────────────────────────────────────────

    /// Подписка backend на входящие предложения/голоса.
    pub fn subscribe_votes(&self) -> broadcast::Receiver<VoteGossip> {
        self.inner.vote_tx.subscribe()
    }

    /// Рассылает наше предложение голосования.
    pub async fn announce_proposal(&self, signed: SignedMessage) {
        self.broadcast_gossip_packet(ChatPacket::ProposalAnnounce { signed }).await;
    }

    /// Рассылает наш голос.
    pub async fn announce_vote(&self, signed: SignedMessage) {
        self.broadcast_gossip_packet(ChatPacket::VoteAnnounce { signed }).await;
    }

    /// Рассылает наш дайджест открытых предложений (anti-entropy) прямым соседям;
    /// получатель до-рассылает недостающее.
    pub async fn announce_vote_digest(&self, items: Vec<(String, String)>) {
        self.broadcast_gossip_packet(ChatPacket::VoteDigest { items }).await;
    }

    /// Обрабатывает входящее событие голосований. Предложение/голос отдаёт
    /// backend'у и пересылает соседям, кроме источника. Дайджест только отдаём
    /// backend'у (он реагирует re-announce'ом): пересылать его не нужно — это
    /// сверка с прямым соседом. Подпись/подсчёт — в backend.
    async fn handle_vote_gossip(&self, gossip: VoteGossip, src: Option<&NodeId>) {
        let (pkt, kind) = match gossip.clone() {
            VoteGossip::Proposal(signed) => (ChatPacket::ProposalAnnounce { signed }, Kind::Proposal),
            VoteGossip::Vote(signed) => (ChatPacket::VoteAnnounce { signed }, Kind::Vote),
            VoteGossip::Digest(_) => {
                let _ = self.inner.vote_tx.send(gossip);
                return; // дайджест не пересылаем
            }
        };
        if let Some(signed) = gossip_signature(&pkt) {
            if !self.first_seen_gossip(signed).await {
                return;
            }
            // Предложения незнакомцев не пересылаются, голоса — не чаще лимита.
            if src.is_some() && !self.admit_signed(signed, kind) {
                self.unsee_gossip(signed).await;
                return;
            }
        }
        let _ = self.inner.vote_tx.send(gossip);
        self.forward(pkt, src).await;
    }

    // ─── Внутренний DNS (зона .void) ──────────────────────────────────────────

    /// Подписка backend на входящие подписанные DNS-записи.
    pub fn subscribe_dns(&self) -> broadcast::Receiver<SignedMessage> {
        self.inner.dns_tx.subscribe()
    }

    /// Рассылает нашу подписанную DNS-запись соседям (они перешлют дальше).
    pub async fn announce_dns(&self, signed: SignedMessage) {
        self.cache_dns(&signed).await;
        self.first_seen_gossip(&signed).await;
        self.forward(ChatPacket::DnsAnnounce { signed }, None).await;
    }

    /// Обрабатывает входящую DNS-запись: отдаёт backend'у (он проверяет подпись
    /// и разрешает конфликт имён) и пересылает соседям, кроме источника.
    async fn handle_dns(&self, signed: SignedMessage, src: Option<&NodeId>) {
        if !self.first_seen_gossip(&signed).await {
            return;
        }
        if signed.verify().is_err() {
            return; // мусор не кэшируем и не пересылаем
        }
        if src.is_some() && !self.admit(&NodeId(signed.signer.clone()), Kind::Dns) {
            self.unsee_gossip(&signed).await;
            return;
        }
        self.cache_dns(&signed).await;
        let _ = self.inner.dns_tx.send(signed.clone());
        self.forward(ChatPacket::DnsAnnounce { signed }, src).await;
    }

    // ─── Сеть доверия (поручительства) ────────────────────────────────────────

    /// Входящее поручительство: дубликаты гасим, остальное отдаём backend'у.
    async fn handle_vouch(&self, signed: SignedMessage, from: &NodeId) {
        if !self.first_seen_gossip(&signed).await || signed.verify().is_err() {
            return;
        }
        let _ = self.inner.vouch_tx.send(VouchGossip { signed, from: from.clone() });
    }

    /// Рассылает поручительство соседям, кроме `except` (своё — `None`).
    pub async fn relay_vouch(&self, signed: SignedMessage, except: Option<&NodeId>) {
        self.first_seen_gossip(&signed).await;
        self.forward(ChatPacket::Vouch { signed }, except).await;
    }

    /// Отправляет поручительства одному соседу (например, при новой связи).
    /// Через очередь связи с ожиданием места — граф может быть большим.
    pub async fn push_vouches(&self, peer: &NodeId, vouches: Vec<SignedMessage>) {
        let Some(tx) = self.inner.links.lock().await.get(peer).map(|l| l.tx.clone()) else { return };
        tokio::spawn(async move {
            for signed in vouches {
                if tx.send(ChatPacket::Vouch { signed }).await.is_err() {
                    break;
                }
            }
        });
    }
}

// ─── Запуск ──────────────────────────────────────────────────────────────────

pub async fn start_public_chat(
    my_peer: PeerInfo,
    peer_list: PeerList,
    chat_port: u16,
    signing_kp: Arc<SigningKeypair>,
    rate_limiter: Option<RateLimiter>,
) -> anyhow::Result<ChatHandle> {
    let chat = PublicChat::new(my_peer, peer_list, chat_port, signing_kp, rate_limiter);

    let c = chat.clone();
    tokio::spawn(async move {
        if let Err(e) = run_server(c).await { error!("Chat server: {}", e); }
    });

    let c = chat.clone();
    tokio::spawn(async move { mesh_manager(c).await; });

    info!("Public chat started on port {}", chat_port);
    Ok(ChatHandle { chat })
}

// ─── TCP-сервер (входящие связи) ─────────────────────────────────────────────

/// Глобальный потолок одновременных входящих соединений чата.
const MAX_CHAT_CONNS: usize = 1024;
/// Лимит одновременных соединений с одного IP (защита от connection-flood; берём
/// с запасом, чтобы не мешать локальному запуску нескольких узлов на 127.0.0.1).
const MAX_CHAT_CONNS_PER_IP: usize = 64;
/// Таймаут на приветственный Hello (slowloris-защита; не затрагивает уже
/// установленное долгоживущее соединение).
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

async fn run_server(chat: PublicChat) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", chat.inner.chat_port);
    let listener = TcpListener::bind(&addr).await?;
    info!("Chat TCP server listening on {}", addr);
    let limiter = ConnLimiter::new(MAX_CHAT_CONNS, MAX_CHAT_CONNS_PER_IP);
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let permit = match limiter.try_accept(addr.ip()) {
                    Some(p) => p,
                    None => {
                        debug!("Chat server at capacity, dropping {}", addr);
                        drop(stream);
                        continue;
                    }
                };
                let c = chat.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    accept_link(stream, addr, c).await;
                });
            }
            Err(e) => warn!("Accept error: {}", e),
        }
    }
}

/// Входящая связь: Noise (сосед доказывает свой NodeId), обмен Hello, затем
/// общий цикл связи.
async fn accept_link(stream: TcpStream, addr: std::net::SocketAddr, chat: PublicChat) {
    debug!("Incoming connection from {}", addr);
    let setup = async {
        let mut stream = secure::accept(stream, &chat.inner.noise, Channel::Chat).await?;
        let authed = stream.peer().clone();
        let (name, chat_port) = read_hello(&mut stream, &authed).await?;
        send_packet(&mut stream, &chat.hello().await).await?;
        anyhow::Ok((stream, authed, name, chat_port))
    };
    let (stream, peer_id, name, chat_port) = match timeout(LINK_SETUP_TIMEOUT, setup).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => { warn!("Входящая связь с {} не установлена: {}", addr, e); return; }
        Err(_) => { warn!("Входящая связь с {}: таймаут установки", addr); return; }
    };
    chat.note_inbound_peer(&peer_id, &name, chat_port, addr).await;
    run_link(chat, stream, peer_id, name, false).await;
}

/// Исходящая связь до `peer`. Рукопожатие проверяет, что на том конце именно
/// этот NodeId (подменённый адрес обрывается здесь). У stub-записи ручного
/// `--peer` настоящий ID ещё неизвестен — узнаём его и заменяем заглушку.
async fn dial_link(chat: PublicChat, peer: PeerInfo) {
    let is_stub = peer.id.as_str().starts_with("stub-");
    let setup = async {
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer.chat_addr())).await??;
        let expected = (!is_stub).then_some(&peer.id);
        let mut stream = secure::connect(tcp, &chat.inner.noise, Channel::Chat, expected).await?;
        let authed = stream.peer().clone();
        if authed == chat.inner.my_peer.id {
            anyhow::bail!("адрес ведёт к нам самим");
        }
        send_packet(&mut stream, &chat.hello().await).await?;
        let (name, _chat_port) = read_hello(&mut stream, &authed).await?;
        anyhow::Ok((stream, authed, name))
    };
    let result = timeout(LINK_SETUP_TIMEOUT, setup).await;
    chat.inner.dialing.lock().await.remove(&peer.id);
    let (stream, peer_id, name) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            warn!("Связь с {} ({}) не установлена: {}", short(&peer.id), peer.chat_addr(), e);
            note_dial_failure(&chat, peer.id.as_str()).await;
            return;
        }
        Err(_) => {
            warn!("Связь с {} ({}): таймаут установки", short(&peer.id), peer.chat_addr());
            note_dial_failure(&chat, peer.id.as_str()).await;
            return;
        }
    };
    chat.inner.dial_failures.lock().await.remove(peer.id.as_str());
    if is_stub {
        let mut real = peer.clone();
        real.id = peer_id.clone();
        if !name.is_empty() {
            real.name = name.clone();
        }
        chat.inner.peer_list.remove(&peer.id).await;
        chat.inner.peer_list.upsert(real).await;
        info!("Stub {} → настоящий ID {} ({})", peer.id, short(&peer_id), name);
    }
    run_link(chat, stream, peer_id, name, true).await;
}

/// Читает Hello соседа: NodeId обязан совпасть с доказанным рукопожатием.
async fn read_hello<S: AsyncReadExt + Unpin>(stream: &mut S, authed: &NodeId) -> anyhow::Result<(String, u16)> {
    match timeout(HELLO_TIMEOUT, read_packet(stream)).await?? {
        ChatPacket::Hello { node_id, name, chat_port } if node_id == *authed => {
            Ok((void_core::sanitize::display_text(&name, MAX_SENDER_NAME_CHARS), chat_port))
        }
        ChatPacket::Hello { node_id, .. } => {
            anyhow::bail!("Hello от {} заявляет чужой node_id {}", authed, node_id)
        }
        _ => anyhow::bail!("ожидался Hello"),
    }
}

/// Общий цикл связи (входящей и исходящей): регистрация, обмен известным,
/// приём с пересылкой, отправка, пинги. По завершении связь удаляется.
async fn run_link(
    chat: PublicChat,
    stream: secure::SecureStream<TcpStream>,
    peer_id: NodeId,
    name: String,
    initiated_by_me: bool,
) {
    let (tx, mut rx) = mpsc::channel::<ChatPacket>(LINK_QUEUE);
    let Some((link_id, close)) = chat.register_link(&peer_id, tx.clone(), initiated_by_me).await else {
        debug!("Лишняя связь с {} закрыта (уже есть встречная)", short(&peer_id));
        return;
    };
    info!(
        "Связь с {} ({}) установлена ({})",
        name, short(&peer_id), if initiated_by_me { "исходящая" } else { "входящая" }
    );
    let _ = chat.inner.link_tx.send(peer_id.clone());

    let (mut rd, mut wr) = tokio::io::split(stream);

    // Отправка: очередь связи → сокет.
    let mut writer = tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
            if send_packet(&mut wr, &pkt).await.is_err() {
                break;
            }
        }
    });

    // Обмен известным — через очередь связи, а не напрямую в сокет: обе стороны
    // шлют одновременно, и без параллельного чтения они могли бы заблокировать
    // друг друга на переполненных буферах TCP.
    let sync_chat = chat.clone();
    let sync_tx = tx.clone();
    let syncer = tokio::spawn(async move {
        for pkt in sync_chat.sync_packets().await {
            if sync_tx.send(pkt).await.is_err() {
                break;
            }
        }
    });

    // Пинги: обнаружение «тихой» потери связи (запись в мёртвый сокет упадёт).
    let ping_tx = tx.clone();
    let pinger = tokio::spawn(async move {
        let mut ivl = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
        ivl.tick().await;
        loop {
            ivl.tick().await;
            if ping_tx.send(ChatPacket::Ping).await.is_err() {
                break;
            }
        }
    });

    let reader = read_loop(chat.clone(), &mut rd, peer_id.clone(), tx);
    tokio::select! {
        _ = reader => {}
        _ = &mut writer => {}
        _ = close.notified() => debug!("Связь с {} вытеснена встречной", short(&peer_id)),
    }
    writer.abort();
    syncer.abort();
    pinger.abort();

    // Удаляем, только если это всё ещё наша связь (её могли заменить встречной).
    let mut links = chat.inner.links.lock().await;
    if links.get(&peer_id).is_some_and(|l| l.id == link_id) {
        links.remove(&peer_id);
    }
    info!("Связь с {} ({}) закрыта", name, short(&peer_id));
}

/// Бюджет пакетов от соседа (token bucket).
struct LinkBudget {
    tokens: f64,
    last: Instant,
    /// Подряд отброшенных пакетов.
    drops: u32,
}

impl LinkBudget {
    fn new() -> Self {
        Self { tokens: LINK_BURST, last: Instant::now(), drops: 0 }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.last).as_secs_f64() * LINK_RATE_PER_SEC;
        self.tokens = (self.tokens + refill).min(LINK_BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.drops = 0;
            true
        } else {
            self.drops += 1;
            false
        }
    }
}

/// Цикл приёма связи: бюджет пакетов соседа, разбор и обработка (с пересылкой
/// остальным соседям — источник `peer`).
async fn read_loop<R: AsyncReadExt + Unpin>(
    chat: PublicChat,
    rd: &mut R,
    peer: NodeId,
    tx: mpsc::Sender<ChatPacket>,
) {
    let mut budget = LinkBudget::new();
    loop {
        let pkt = match read_packet(rd).await {
            Ok(p) => p,
            Err(e) => {
                debug!("Связь с {}: чтение завершено: {}", short(&peer), e);
                return;
            }
        };
        if !budget.take() {
            if budget.drops > LINK_MAX_DROPS {
                warn!("Сосед {} шлёт пакеты сверх бюджета — связь разорвана", short(&peer));
                note_dial_failure(&chat, peer.as_str()).await;
                return;
            }
            continue;
        }
        let src = Some(&peer);
        match pkt {
            ChatPacket::Message(msg) => chat.handle_incoming(msg, src).await,
            ChatPacket::History { messages } => {
                for msg in messages {
                    chat.accept_message(msg, src, false).await;
                }
            }
            ChatPacket::ProfileUpdate(prof) => chat.handle_profile_update(prof, src).await,
            ChatPacket::FileAnnounce(manifest) => chat.handle_file_announce(manifest, src).await,
            ChatPacket::SiteAnnounce(manifest) => chat.handle_site_announce(manifest, src).await,
            ChatPacket::SiteRevoke { signed } => chat.handle_site_revoke(signed, src).await,
            ChatPacket::ReputationReport { signed } => chat.handle_report(signed, src).await,
            ChatPacket::DnsAnnounce { signed } => chat.handle_dns(signed, src).await,
            ChatPacket::ProposalAnnounce { signed } => {
                chat.handle_vote_gossip(VoteGossip::Proposal(signed), src).await
            }
            ChatPacket::VoteAnnounce { signed } => {
                chat.handle_vote_gossip(VoteGossip::Vote(signed), src).await
            }
            ChatPacket::VoteDigest { items } => {
                chat.handle_vote_gossip(VoteGossip::Digest(items), src).await
            }
            ChatPacket::Vouch { signed } => chat.handle_vouch(signed, &peer).await,
            ChatPacket::Ping => {
                let _ = tx.try_send(ChatPacket::Pong);
            }
            ChatPacket::Pong | ChatPacket::Hello { .. } | ChatPacket::Unknown => {}
        }
    }
}

fn short(id: &NodeId) -> &str {
    &id.as_str()[..8.min(id.as_str().len())]
}

impl PublicChat {
    /// Наш Hello: имя из профиля (PeerInfo.name может устареть).
    async fn hello(&self) -> ChatPacket {
        let name = {
            let p = self.inner.my_profile.lock().await;
            p.as_ref()
                .map(|p| p.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| self.inner.my_peer.name.clone())
        };
        ChatPacket::Hello {
            node_id:   self.inner.my_peer.id.clone(),
            name:      void_core::sanitize::display_text(&name, MAX_SENDER_NAME_CHARS),
            chat_port: self.inner.chat_port,
        }
    }

    /// Регистрирует связь с `peer`. Если с ним уже есть живая связь (узлы
    /// дозвонились друг другу одновременно), остаётся одна — открытая узлом с
    /// меньшим ID; обе стороны выбирают одну и ту же. `None` — эта связь лишняя.
    async fn register_link(
        &self,
        peer: &NodeId,
        tx: mpsc::Sender<ChatPacket>,
        initiated_by_me: bool,
    ) -> Option<(u64, Arc<Notify>)> {
        let i_am_smaller = self.inner.my_peer.id.as_str() < peer.as_str();
        let canonical = |by_me: bool| by_me == i_am_smaller;
        let mut links = self.inner.links.lock().await;
        if let Some(existing) = links.get(peer) {
            if !existing.tx.is_closed()
                && (canonical(existing.initiated_by_me) || !canonical(initiated_by_me))
            {
                return None;
            }
            existing.close.notify_one();
        }
        let id = self.inner.link_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let close = Arc::new(Notify::new());
        links.insert(peer.clone(), Link { tx, id, initiated_by_me, close: Arc::clone(&close) });
        Some((id, close))
    }

    /// Что передаём новой связи: историю, профили (и свой), манифесты, сайты,
    /// надгробия и DNS-записи — чтобы сосед догнал пропущенное.
    async fn sync_packets(&self) -> Vec<ChatPacket> {
        let mut out = vec![ChatPacket::History {
            messages: self.inner.history.lock().await.iter().cloned().collect(),
        }];
        if let Some(mine) = self.inner.my_profile.lock().await.clone() {
            out.push(ChatPacket::ProfileUpdate(mine));
        }
        out.extend(self.inner.profiles.lock().await.values().cloned().map(ChatPacket::ProfileUpdate));
        out.extend(self.inner.manifests.lock().await.values().cloned().map(ChatPacket::FileAnnounce));
        out.extend(self.inner.sites.lock().await.values().cloned().map(ChatPacket::SiteAnnounce));
        out.extend(
            self.inner.site_tombstones.lock().await.values()
                .map(|(_, signed)| ChatPacket::SiteRevoke { signed: signed.clone() }),
        );
        out.extend(
            self.inner.dns_cache.lock().await.values()
                .map(|(_, signed)| ChatPacket::DnsAnnounce { signed: signed.clone() }),
        );
        out
    }

    /// Входящая связь: обновляем peer_list — апгрейд stub-записи ручного
    /// `--peer` до настоящего ID либо актуализация имени/порта чата.
    async fn note_inbound_peer(&self, node_id: &NodeId, peer_name: &str, chat_port: u16, addr: std::net::SocketAddr) {
        let peers = self.inner.peer_list.all().await;
        for p in &peers {
            if p.ip == addr.ip() && p.id.as_str().starts_with("stub-") {
                // В режиме loopback уточняем stub по chat_port, иначе просто по IP
                if addr.ip().is_loopback() && p.chat_port != chat_port {
                    continue;
                }
                let mut real = p.clone();
                real.id        = node_id.clone();
                real.name      = peer_name.to_string();
                real.chat_port = chat_port;
                self.inner.peer_list.remove(&p.id).await;
                self.inner.peer_list.upsert(real).await;
                info!("Stub peer upgraded to real ID: {} ({})", peer_name, node_id);
                return;
            }
        }
        if let Some(mut p) = self.inner.peer_list.get(node_id).await {
            let mut changed = false;
            if !peer_name.is_empty() && p.name != peer_name {
                p.name = peer_name.to_string();
                changed = true;
            }
            if p.chat_port != chat_port {
                p.chat_port = chat_port;
                changed = true;
            }
            if changed {
                self.inner.peer_list.upsert(p).await;
            }
        }
    }
}

// ─── Обработка входящих данных ────────────────────────────────────────────────

/// Подписанное содержимое пакета рассылки (для дедупа по подписи).
fn gossip_signature(pkt: &ChatPacket) -> Option<&SignedMessage> {
    match pkt {
        ChatPacket::ReputationReport { signed }
        | ChatPacket::DnsAnnounce { signed }
        | ChatPacket::ProposalAnnounce { signed }
        | ChatPacket::VoteAnnounce { signed }
        | ChatPacket::SiteRevoke { signed }
        | ChatPacket::Vouch { signed } => Some(signed),
        _ => None,
    }
}

/// Подпись профиля сделана ключом его `node_id`.
fn verify_profile(p: &PeerProfile) -> bool {
    let Some(signature) = p.signature.clone() else { return false };
    SignedMessage { payload: p.signing_bytes(), signature, signer: p.node_id.as_str().to_string() }
        .verify()
        .is_ok()
}

/// Подпись манифеста файла сделана ключом его публикатора.
fn verify_file_manifest(m: &FileManifest) -> bool {
    let (Some(publisher), Some(signature)) = (m.publisher.as_ref(), m.signature.clone()) else {
        return false;
    };
    SignedMessage { payload: m.signing_bytes(), signature, signer: publisher.as_str().to_string() }
        .verify()
        .is_ok()
}

/// Подпись манифеста сайта сделана ключом его владельца.
fn verify_site(m: &SiteManifest) -> bool {
    let Some(signature) = m.signature.clone() else { return false };
    SignedMessage { payload: m.signing_bytes(), signature, signer: m.owner.as_str().to_string() }
        .verify()
        .is_ok()
}

/// Имя сайта — нормализованная метка зоны `.void` (`[a-z0-9-]`).
fn is_normalized_site_name(name: &str) -> bool {
    normalize_name(name).as_deref() == Some(name)
}

/// Поля сообщения в пределах лимитов (проверяется до проверки подписи — дёшево).
/// Имя отправителя подписано, поэтому «чистить» его нельзя — только отвергнуть.
fn message_within_limits(msg: &ChatMessage) -> bool {
    msg.text.len() <= MAX_CHAT_TEXT_BYTES
        && msg.channel.chars().count() <= MAX_CHANNEL_CHARS
        && void_core::sanitize::display_text(&msg.from_name, MAX_SENDER_NAME_CHARS) == msg.from_name
}

/// Канонические байты сообщения для подписи/проверки.
/// Привязывает отправителя, порядковый номер, время и текст.
fn message_signing_bytes(msg: &ChatMessage) -> Vec<u8> {
    // Имя отправителя тоже подписано: иначе релей мог бы переименовать автора.
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        msg.from.as_str(), msg.seq, msg.timestamp, msg.channel, msg.from_name, msg.text
    )
    .into_bytes()
}

impl PublicChat {
    /// Подписывает исходящее сообщение нашим Ed25519-ключом.
    fn sign_message(&self, msg: &mut ChatMessage) {
        let bytes = message_signing_bytes(msg);
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
            payload:   message_signing_bytes(msg),
            signature,
            signer:    msg.from.as_str().to_string(),
        };
        signed.verify().is_ok()
    }

    /// Принимает сообщение (своё — `src = None`, или от соседа `src`):
    /// лимиты → подпись → дедуп → спам-лимит автора → история, UI, пересылка
    /// соседям (кроме источника).
    async fn handle_incoming(&self, msg: ChatMessage, src: Option<&NodeId>) {
        self.accept_message(msg, src, true).await;
    }

    /// `live_check` — учитывать ли сообщение в лимите пакетов доверенного автора.
    /// Для догоняющей истории (пакет History) не учитываем: это не поток в
    /// реальном времени, и плодовитый автор не должен получать спам-штраф за
    /// свою историю. Незнакомцев и освоившихся лимит по уровню считает всегда.
    async fn accept_message(&self, msg: ChatMessage, src: Option<&NodeId>, live_check: bool) {
        if !message_within_limits(&msg) {
            warn!("Отброшено сообщение сверх лимитов от {}", msg.from);
            return;
        }
        if !self.verify_message(&msg) {
            warn!("Отброшено сообщение с неверной/отсутствующей подписью от {}", msg.from);
            return;
        }
        if !self.mark_seen(&msg).await {
            return; // уже видели — гасим петлю пересылки
        }
        // Спам-защита: чужие сообщения считаются в лимите частоты АВТОРА
        // (подпись доказывает авторство), а не соседа, который их переслал.
        if src.is_some() {
            if self.author_tier(&msg.from) == AuthorTier::Trusted {
                let live = (Utc::now().timestamp() - msg.timestamp).abs() <= LIVE_WINDOW_SECS;
                if live_check && live && !self.allow_packet(&msg.from).await {
                    debug!("Сообщение {} сверх лимита частоты — отброшено", msg.from);
                    return;
                }
            } else if !self.admit(&msg.from, Kind::message(&msg.channel)) {
                // Незнакомцу и освоившемуся считаются и история, и сообщения с
                // датой в прошлом — иначе старая дата обходила бы лимит. Отброс
                // тихий; отметку снимаем, чтобы копия прошла позже.
                self.unmark_seen(&msg).await;
                debug!("Сообщение {} сверх лимита его уровня доверия — отброшено", msg.from);
                return;
            }
        }

        {
            let mut h = self.inner.history.lock().await;
            if h.len() >= 100 { h.pop_front(); }
            h.push_back(msg.clone());
        }

        let _ = self.inner.incoming_tx.send(msg.clone());
        self.forward(ChatPacket::Message(msg), src).await;
    }

    async fn handle_profile_update(&self, profile: PeerProfile, src: Option<&NodeId>) {
        // Профиль подписан владельцем: чужое имя/аватар от имени узла не пройдут.
        if !verify_profile(&profile) {
            warn!("Отброшен профиль {} без верной подписи владельца", profile.node_id);
            return;
        }
        // Подписанное нельзя «почистить» — профиль вне лимитов (аватар-бомба,
        // bidi-символы в имени, ключ неверного формата) просто отвергаем.
        let mut clean = profile.clone();
        clean.sanitize();
        if clean != profile {
            warn!("Отброшен профиль {} вне лимитов", profile.node_id);
            return;
        }
        {
            let mut profiles = self.inner.profiles.lock().await;
            // Повтор старой версии не откатывает профиль (и гасит петли рассылки).
            if profiles.get(&profile.node_id).is_some_and(|old| old.updated_at >= profile.updated_at) {
                return;
            }
            if src.is_some() && !self.admit(&profile.node_id, Kind::Profile) {
                return; // не сохраняем — копия пройдёт позже
            }
            profiles.insert(profile.node_id.clone(), profile.clone());
        }

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

        self.forward(ChatPacket::ProfileUpdate(profile), src).await;
    }

    /// Обрабатывает входящее объявление о файле из сети: сливает манифест с
    /// известным (объединяя сидеров), уведомляет backend (запись в БД + индекс
    /// владельцев) и пересылает объединённый манифест соседям, кроме источника.
    /// Дедуп через `merge_manifest`: если новой информации нет, обработка
    /// прекращается, что гасит петли пересылки.
    async fn handle_file_announce(&self, manifest: FileManifest, src: Option<&NodeId>) {
        let Some(merged) = self.merge_manifest(manifest, src).await else {
            return; // ничего нового — не пересылаем повторно
        };

        // Уведомляем backend (персистентность + регистрация владельцев чанков)
        let _ = self.inner.manifest_tx.send(merged.clone());

        self.forward(ChatPacket::FileAnnounce(merged), src).await;
    }

    pub async fn send(&self, channel: String, text: String) -> anyhow::Result<()> {
        if text.len() > MAX_CHAT_TEXT_BYTES {
            anyhow::bail!("Сообщение длиннее {} байт — другие узлы его отбросят", MAX_CHAT_TEXT_BYTES);
        }
        // seq растёт и между перезапусками (не меньше текущего времени в мс):
        // иначе после рестарта (from, 1) совпал бы с уже виденным сообщением и
        // соседи отбросили бы новое как повтор (а БД — по message_id).
        let seq = {
            let mut c = self.inner.seq_counter.lock().await;
            *c = (*c + 1).max(Utc::now().timestamp_millis() as u64);
            *c
        };

        // Используем имя из профиля если оно установлено
        let my_name = {
            let p = self.inner.my_profile.lock().await;
            p.as_ref()
                .map(|p| p.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| self.inner.my_peer.name.clone())
        };

        let my_name = void_core::sanitize::display_text(&my_name, MAX_SENDER_NAME_CHARS);
        let mut msg = ChatMessage::new(self.inner.my_peer.id.clone(), my_name, text, channel, seq);
        self.sign_message(&mut msg);

        if self.inner.links.lock().await.is_empty() {
            warn!("Нет связей с соседями — сообщение пока видно только локально (seq={})", seq);
        }
        // Показываем у себя и рассылаем соседям (они перешлют дальше).
        self.handle_incoming(msg, None).await;
        Ok(())
    }
}

// ─── Поддержание связей ──────────────────────────────────────────────────────

async fn mesh_manager(chat: PublicChat) {
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    interval.tick().await; // поглощаем немедленный первый тик
    let changes = chat.inner.peer_list.subscribe_changes();

    loop {
        mesh_pass(&chat).await;

        // Реагируем сразу на изменение состава пиров (новый узел, апгрейд
        // stub→real), между изменениями — периодическая проверка.
        let notified = changes.notified();
        tokio::select! {
            _ = interval.tick() => {}
            _ = notified => {}
        }
    }
}

/// Один проход: если исходящих связей меньше [`TARGET_OUT_LINKS`], дозваниваемся
/// до случайных известных узлов (без связи, не в паузе после неудачи).
/// Случайный выбор важен: предсказуемый (например, «наименьший ID») позволил бы
/// злоумышленнику занять все наши связи подобранными ключами.
async fn mesh_pass(chat: &PublicChat) {
    let peers = chat.inner.peer_list.all().await;
    let now = Instant::now();
    let paused: HashSet<String> = {
        let mut failures = chat.inner.dial_failures.lock().await;
        // Ушедшие из peer_list узлы больше не нужны.
        failures.retain(|id, _| peers.iter().any(|p| p.id.as_str() == id));
        failures.iter()
            .filter(|(_, (until, _))| *until > now)
            .map(|(id, _)| id.clone())
            .collect()
    };
    let (linked, outbound): (HashSet<NodeId>, usize) = {
        let links = chat.inner.links.lock().await;
        let out = links.values().filter(|l| l.initiated_by_me && !l.tx.is_closed()).count();
        (links.keys().cloned().collect(), out)
    };
    let dialing: HashSet<NodeId> = chat.inner.dialing.lock().await.clone();
    let want = TARGET_OUT_LINKS.saturating_sub(outbound + dialing.len());
    if want == 0 {
        return;
    }

    let my_id = &chat.inner.my_peer.id;
    let mut candidates: Vec<PeerInfo> = peers
        .into_iter()
        .filter(|p| {
            &p.id != my_id
                && !linked.contains(&p.id)
                && !dialing.contains(&p.id)
                && !paused.contains(p.id.as_str())
        })
        .collect();
    candidates.shuffle(&mut rand::thread_rng());

    for peer in candidates.into_iter().take(want) {
        chat.inner.dialing.lock().await.insert(peer.id.clone());
        let c = chat.clone();
        tokio::spawn(async move { dial_link(c, peer).await });
    }
}

/// Запоминает неудачный дозвон до `id` (экспоненциальная пауза).
async fn note_dial_failure(chat: &PublicChat, id: &str) {
    let mut failures = chat.inner.dial_failures.lock().await;
    let streak = failures.get(id).map(|(_, n)| n + 1).unwrap_or(1);
    let delay = DIAL_RETRY_BASE
        .saturating_mul(1u32 << (streak - 1).min(4))
        .min(DIAL_RETRY_MAX);
    failures.insert(id.to_string(), (Instant::now() + delay, streak));
}

// ─── Handle ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ChatHandle {
    chat: PublicChat,
}

impl ChatHandle {
    pub async fn send(&self, channel: String, text: String) -> anyhow::Result<()> { self.chat.send(channel, text).await }
    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> { self.chat.subscribe() }
    pub async fn recent(&self, n: usize) -> Vec<ChatMessage> { self.chat.recent(n).await }
    /// Подгрузить историю (из БД) — соседи догонят её через нас, а пришедшие
    /// от них копии не покажутся повторно.
    pub async fn preload_history(&self, messages: Vec<ChatMessage>) { self.chat.preload_history(messages).await }
    /// Сколько сейчас связей с соседями.
    pub async fn link_count(&self) -> usize { self.chat.link_count().await }
    pub async fn set_profile(&self, profile: PeerProfile) { self.chat.set_profile(profile).await }
    pub async fn get_profiles(&self) -> Vec<PeerProfile> { self.chat.get_profiles().await }
    pub async fn announce_file(&self, manifest: FileManifest) { self.chat.announce_file(manifest).await }
    pub fn subscribe_manifests(&self) -> broadcast::Receiver<FileManifest> { self.chat.subscribe_manifests() }
    pub async fn get_manifests(&self) -> Vec<FileManifest> { self.chat.get_manifests().await }
    pub async fn announce_site(&self, manifest: SiteManifest) { self.chat.announce_site(manifest).await }
    pub fn subscribe_sites(&self) -> broadcast::Receiver<SiteManifest> { self.chat.subscribe_sites() }
    pub async fn get_sites(&self) -> Vec<SiteManifest> { self.chat.get_sites().await }
    pub async fn announce_site_revoke(&self, signed: SignedMessage) { self.chat.announce_site_revoke(signed).await }
    pub fn subscribe_site_revokes(&self) -> broadcast::Receiver<SiteRevocation> { self.chat.subscribe_site_revokes() }
    pub fn subscribe_reports(&self) -> broadcast::Receiver<SignedMessage> { self.chat.subscribe_reports() }
    pub async fn broadcast_report(&self, signed: SignedMessage) { self.chat.broadcast_report(signed).await }
    pub async fn announce_dns(&self, signed: SignedMessage) { self.chat.announce_dns(signed).await }
    pub fn subscribe_dns(&self) -> broadcast::Receiver<SignedMessage> { self.chat.subscribe_dns() }
    pub fn subscribe_spam(&self) -> broadcast::Receiver<NodeId> { self.chat.subscribe_spam() }
    pub fn subscribe_votes(&self) -> broadcast::Receiver<VoteGossip> { self.chat.subscribe_votes() }
    pub async fn announce_proposal(&self, signed: SignedMessage) { self.chat.announce_proposal(signed).await }
    pub async fn announce_vote(&self, signed: SignedMessage) { self.chat.announce_vote(signed).await }
    pub async fn announce_vote_digest(&self, items: Vec<(String, String)>) { self.chat.announce_vote_digest(items).await }
    /// Входящие поручительства (с соседом-источником).
    pub fn subscribe_vouches(&self) -> broadcast::Receiver<VouchGossip> { self.chat.inner.vouch_tx.subscribe() }
    /// Новые связи с соседями.
    pub fn subscribe_links(&self) -> broadcast::Receiver<NodeId> { self.chat.inner.link_tx.subscribe() }
    /// Уровень авторов по сети доверия — для лимитов частоты (см. [`crate::trust_limits`]).
    pub fn set_author_tiers(&self, tiers: TierFn) { self.chat.set_author_tiers(tiers) }
    pub async fn relay_vouch(&self, signed: SignedMessage, except: Option<&NodeId>) {
        self.chat.relay_vouch(signed, except).await
    }
    pub async fn push_vouches(&self, peer: &NodeId, vouches: Vec<SignedMessage>) {
        self.chat.push_vouches(peer, vouches).await
    }
}

// ─── Сериализация ────────────────────────────────────────────────────────────

async fn send_packet<W: AsyncWriteExt + Unpin>(stream: &mut W, packet: &ChatPacket) -> anyhow::Result<()> {
    let json = serde_json::to_vec(packet)?;
    if json.len() > MAX_MESSAGE_LEN { anyhow::bail!("Packet too large"); }
    stream.write_all(&(json.len() as u32).to_be_bytes()).await?;
    stream.write_all(&json).await?;
    // Noise-поток буферизует кадр до flush (как TLS).
    stream.flush().await?;
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


// ─── Тесты ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use tokio::sync::broadcast;
    use tokio::time::timeout;
    use void_core::manifest::{ChunkMeta, FileManifest};
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

    /// Подписывает манифест файла ключом публикатора (как это делает storage).
    fn sign_file(mut m: FileManifest, kp: &SigningKeypair) -> FileManifest {
        m.publisher = Some(NodeId::from_public_key_bytes(&kp.public_bytes()));
        m.signature = Some(SignedMessage::sign(m.signing_bytes(), kp).unwrap().signature);
        m
    }

    /// Подписывает манифест сайта ключом владельца (как это делает `publish_site`).
    fn sign_site(mut m: SiteManifest, kp: &SigningKeypair) -> SiteManifest {
        m.signature = None;
        m.signature = Some(SignedMessage::sign(m.signing_bytes(), kp).unwrap().signature);
        m
    }

    /// Две пары ключей, упорядоченные по NodeId: первая выигрывает выборы релея.
    fn ordered_keypairs(a: u8, b: u8) -> ((Arc<SigningKeypair>, NodeId), (Arc<SigningKeypair>, NodeId)) {
        let (ka, ia) = keypair(a);
        let (kb, ib) = keypair(b);
        if ia.as_str() < ib.as_str() { ((ka, ia), (kb, ib)) } else { ((kb, ib), (ka, ia)) }
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
        let msg = ChatMessage::new(node_id(1), "alice".into(), "привет".into(), "global".into(), 42);
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
        let chat = PublicChat::new(peer, PeerList::new(), 1, kp, None);

        let mut msg = ChatMessage::new(id.clone(), "x".into(), "secret".into(), "global".into(), 1);
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

    /// Два узла знают друг друга: связь устанавливается (а встречная лишняя —
    /// закрывается), сообщения подписаны и проходят проверку в обе стороны.
    #[tokio::test]
    async fn two_nodes_exchange_both_ways() {
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

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp, None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut alice_rx = alice.subscribe();
        let mut bob_rx = bob.subscribe();

        // Клиент → релей. Повторяем отправку, пока релей-соединение не установится
        // (relay_manager опрашивает список пиров с интервалом, первое соединение
        // может прийтись на момент до биндинга сервера релея).
        let mut delivered = false;
        for _ in 0..30 {
            bob.send("global".into(), "from_bob".into()).await.unwrap();
            if wait_for_text(&mut alice_rx, "from_bob", 1).await {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "релей (Alice) не получил сообщение клиента (Bob)");

        // Релей → клиент.
        alice.send("global".into(), "from_alice".into()).await.unwrap();
        assert!(
            wait_for_text(&mut bob_rx, "from_alice", 5).await,
            "клиент (Bob) не получил сообщение релея (Alice)"
        );
    }

    /// Три узла: сообщение от одного доходит до обоих остальных.
    #[tokio::test]
    async fn three_nodes_broadcast() {
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

        let a = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp, None).await.unwrap();
        let b = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();
        let c = start_public_chat(c_peer.clone(), c_pl, c_port, c_kp, None).await.unwrap();

        let mut b_rx = b.subscribe();
        let mut c_rx = c.subscribe();

        // Отправляем от A, пока сообщение не дойдёт и до B, и до C
        // (с запасом на установку клиентских соединений с релеем).
        let mut got_b = false;
        let mut got_c = false;
        for _ in 0..40 {
            a.send("global".into(), "from_a".into()).await.unwrap();
            if !got_b { got_b = wait_for_text(&mut b_rx, "from_a", 1).await; }
            if !got_c { got_c = wait_for_text(&mut c_rx, "from_a", 1).await; }
            if got_b && got_c { break; }
        }
        assert!(got_b, "узел B не получил сообщение от A");
        assert!(got_c, "узел C не получил сообщение от A");
    }

    /// Ждёт в приёмнике манифест с заданным file_id (пропуская прочие).
    async fn wait_for_manifest(
        rx: &mut broadcast::Receiver<FileManifest>,
        file_id: &str,
        secs: u64,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { return false; }
            match timeout(remaining, rx.recv()).await {
                Ok(Ok(m)) if m.file_id == file_id => return true,
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                _ => return false,
            }
        }
    }

    /// Объявление о файле, сделанное одним узлом, доходит до второго через relay
    /// (механизм Фазы 2 — обнаружение файлов в сети). Тест нейтрален к тому,
    /// какой узел стал релеем.
    #[tokio::test]
    async fn file_announce_propagates_to_peer() {
        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id.clone(), a_port);
        let b_peer = test_peer("bob", b_id.clone(), b_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let a_sign = a_kp.clone();
        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp, None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut bob_manifests = bob.subscribe_manifests();

        let manifest = sign_file(FileManifest {
            file_id:    "deadbeefcafe".into(),
            name:       "photo.jpg".into(),
            size_bytes: 1000,
            mime_type:  Some("image/jpeg".into()),
            owners:     vec![a_id.clone()],
            chunks:     vec![ChunkMeta { hash: "a".repeat(64), index: 0, size: 1000 }],
            publisher:  None,
            signature:  None,
        }, &a_sign);

        // Повторяем анонс, пока relay-соединение не установится и объявление
        // не дойдёт до Bob (первые попытки могут прийтись на момент до связи).
        let mut delivered = false;
        for _ in 0..40 {
            alice.announce_file(manifest.clone()).await;
            if wait_for_manifest(&mut bob_manifests, "deadbeefcafe", 1).await {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "Bob не получил объявление о файле от Alice");

        // Манифест должен осесть в известных у Bob (доступен для скачивания).
        let known = bob.get_manifests().await;
        assert!(known.iter().any(|m| m.file_id == "deadbeefcafe"),
            "манифест должен сохраниться в списке известных у Bob");
    }

    /// Ждёт в приёмнике манифест сайта с заданным именем (пропуская прочие).
    async fn wait_for_site(
        rx: &mut broadcast::Receiver<SiteManifest>,
        name: &str,
        secs: u64,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() { return false; }
            match timeout(remaining, rx.recv()).await {
                Ok(Ok(m)) if m.name == name => return true,
                Ok(Ok(_)) => continue,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                _ => return false,
            }
        }
    }

    /// Объявление о сайте, сделанное одним узлом, доходит до второго через relay
    /// (механизм Фазы 2 сайтов — обнаружение сайтов в сети).
    #[tokio::test]
    async fn site_announce_propagates_to_peer() {
        use void_core::site::SiteEntry;

        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id.clone(), a_port);
        let b_peer = test_peer("bob", b_id.clone(), b_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp.clone(), None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut bob_sites = bob.subscribe_sites();

        let manifest = sign_site(SiteManifest {
            site_id:    "site-abc".into(),
            name:       "blog".into(),
            owner:      a_id.clone(),
            entries:    vec![SiteEntry { path: "index.html".into(), file_id: "f1".into(), size_bytes: 10 }],
            created_at: 1,
            signature:  None,
        }, &a_kp);

        let mut delivered = false;
        for _ in 0..40 {
            alice.announce_site(manifest.clone()).await;
            if wait_for_site(&mut bob_sites, "blog", 1).await {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "Bob не получил объявление о сайте от Alice");

        let known = bob.get_sites().await;
        assert!(known.iter().any(|m| m.name == "blog"),
            "манифест сайта должен сохраниться у Bob");
    }

    /// Подписанная DNS-запись, объявленная одним узлом, доходит до второго через
    /// relay (механизм внутреннего DNS — синхронизация зоны `.void`).
    #[tokio::test]
    async fn dns_announce_propagates_to_peer() {
        use void_core::dns::{DnsKind, DnsRecord};

        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id.clone(), a_port);
        let b_peer = test_peer("bob", b_id.clone(), b_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp.clone(), None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut bob_dns = bob.subscribe_dns();

        let record = DnsRecord {
            name: "alice".into(),
            kind: DnsKind::Node,
            node_id: a_id.clone(),
            ip: Some("10.0.0.1".into()),
            port: Some(a_port.wrapping_sub(2)),
            created_at: 1,
            updated_at: 1,
            deleted: false,
        };
        let signed = SignedMessage::sign(record.to_bytes(), &a_kp).unwrap();

        let mut delivered = false;
        for _ in 0..40 {
            alice.announce_dns(signed.clone()).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                match timeout(remaining, bob_dns.recv()).await {
                    Ok(Ok(s)) if s.signer == a_id.as_str() => {
                        let rec: DnsRecord = serde_json::from_slice(&s.payload).unwrap();
                        assert_eq!(rec.name, "alice");
                        assert!(s.verify().is_ok(), "подпись DNS-записи должна проверяться");
                        delivered = true;
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    _ => break,
                }
            }
            if delivered { break; }
        }
        assert!(delivered, "Bob не получил DNS-запись от Alice");
    }

    /// Предложение голосования, объявленное Alice, доходит до Bob как
    /// `VoteGossip::Proposal` с проверяемой подписью (чат переносит его опаквно).
    #[tokio::test]
    async fn proposal_announce_propagates_to_peer() {
        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id.clone(), a_port);
        let b_peer = test_peer("bob", b_id.clone(), b_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp.clone(), None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut bob_votes = bob.subscribe_votes();

        // Содержимое для чата непрозрачно — подписываем произвольные байты.
        let signed = SignedMessage::sign(b"proposal-payload".to_vec(), &a_kp).unwrap();

        let mut delivered = false;
        for _ in 0..40 {
            alice.announce_proposal(signed.clone()).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                match timeout(remaining, bob_votes.recv()).await {
                    Ok(Ok(VoteGossip::Proposal(s))) if s.signer == a_id.as_str() => {
                        assert!(s.verify().is_ok(), "подпись предложения должна проверяться");
                        assert_eq!(s.payload, b"proposal-payload");
                        delivered = true;
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    _ => break,
                }
            }
            if delivered { break; }
        }
        assert!(delivered, "Bob не получил предложение от Alice");
    }

    /// Дайджест anti-entropy, объявленный Alice, доходит до Bob как
    /// `VoteGossip::Digest` (для последующего re-announce недостающего).
    #[tokio::test]
    async fn vote_digest_propagates_to_peer() {
        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id.clone(), a_port);
        let b_peer = test_peer("bob", b_id.clone(), b_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp.clone(), None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut bob_votes = bob.subscribe_votes();
        let digest = vec![("prop1".to_string(), "hashA".to_string())];

        let mut delivered = false;
        for _ in 0..40 {
            alice.announce_vote_digest(digest.clone()).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                match timeout(remaining, bob_votes.recv()).await {
                    Ok(Ok(VoteGossip::Digest(items))) => {
                        assert_eq!(items, digest);
                        delivered = true;
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    _ => break,
                }
            }
            if delivered { break; }
        }
        assert!(delivered, "Bob не получил дайджест от Alice");
    }

    /// Флуд-защита: при исчерпании лимита пакеты дропаются и backend получает
    /// спам-сигнал; без лимитера пропускается всё.
    #[tokio::test]
    async fn rate_limit_drops_and_signals_spam() {
        let (kp, id) = keypair(5);
        let peer = test_peer("x", id, 1);
        // Жёсткий лимит: burst=2, пополнение 1/с.
        let rl = RateLimiter::with_limits(1, 2);
        let chat = PublicChat::new(peer, PeerList::new(), 1, kp, Some(rl));
        let mut spam_rx = chat.subscribe_spam();

        let from = node_id(9);
        // Первые два пакета (burst) проходят.
        assert!(chat.allow_packet(&from).await, "1-й пакет должен пройти");
        assert!(chat.allow_packet(&from).await, "2-й пакет должен пройти");
        // Третий — сверх лимита → дроп.
        assert!(!chat.allow_packet(&from).await, "3-й пакет должен быть отброшен");

        // Backend получил спам-сигнал именно об этом узле.
        let got = timeout(Duration::from_secs(1), spam_rx.recv()).await;
        assert!(matches!(got, Ok(Ok(ref p)) if *p == from),
            "ожидался спам-сигнал о {from}, получено {got:?}");

        // Без лимитера ничего не дропается.
        let (kp2, id2) = keypair(6);
        let chat2 = PublicChat::new(test_peer("y", id2, 2), PeerList::new(), 2, kp2, None);
        for _ in 0..100 {
            assert!(chat2.allow_packet(&node_id(1)).await, "без лимитера всё проходит");
        }
    }

    /// Надгробие удалённого сайта, объявленное Alice, доходит до Bob как
    /// `SiteRevocation` с проверяемой подписью (signer == владелец).
    #[tokio::test]
    async fn site_revoke_propagates_to_peer() {
        let a_port = free_port();
        let b_port = free_port();
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id.clone(), a_port);
        let b_peer = test_peer("bob", b_id.clone(), b_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        b_pl.upsert(a_peer.clone()).await;

        let alice = start_public_chat(a_peer.clone(), a_pl, a_port, a_kp.clone(), None).await.unwrap();
        let bob = start_public_chat(b_peer.clone(), b_pl, b_port, b_kp, None).await.unwrap();

        let mut bob_revokes = bob.subscribe_site_revokes();

        let rev = SiteRevocation { name: "blog".into(), owner: a_id.clone(), revoked_at: 1700 };
        let signed = SignedMessage::sign(rev.to_bytes(), &a_kp).unwrap();

        let mut delivered = false;
        for _ in 0..40 {
            alice.announce_site_revoke(signed.clone()).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                match timeout(remaining, bob_revokes.recv()).await {
                    Ok(Ok(r)) if r.name == "blog" => {
                        assert_eq!(r.owner, a_id);
                        assert_eq!(r.revoked_at, 1700);
                        delivered = true;
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    _ => break,
                }
            }
            if delivered { break; }
        }
        assert!(delivered, "Bob не получил надгробие сайта от Alice");
    }

    /// Надгробие подавляет воскрешение: устаревший анонс того же владельца
    /// (`created_at <= revoked_at`) отбрасывается `merge_site`, а более новая
    /// публикация (re-publish) проходит.
    #[tokio::test]
    async fn tombstone_suppresses_site_resurrection() {
        use void_core::site::SiteManifest;
        let (kp, id) = keypair(7);
        let chat = PublicChat::new(test_peer("o", id.clone(), 1), PeerList::new(), 1, kp.clone(), None);

        let mk = |sid: &str, created_at: i64| sign_site(SiteManifest {
            site_id: sid.into(), name: "blog".into(), owner: id.clone(),
            entries: vec![], created_at, signature: None,
        }, &kp);

        // Сайт сперва известен.
        assert!(chat.merge_site(mk("s1", 100), None).await.is_some());

        // Надгробие в момент 150.
        let rev = SiteRevocation { name: "blog".into(), owner: id.clone(), revoked_at: 150 };
        let signed = SignedMessage::sign(rev.to_bytes(), &kp).unwrap();
        chat.apply_revoke_local(rev, signed).await;

        // Устаревшие анонсы (created_at <= revoked_at) подавлены.
        assert!(chat.merge_site(mk("s1", 100), None).await.is_none(), "старый анонс не воскрешает сайт");
        assert!(chat.merge_site(mk("s2", 150), None).await.is_none(), "created_at == revoked_at тоже подавлен");

        // Переопубликация позже надгробия проходит.
        assert!(chat.merge_site(mk("s3", 200), None).await.is_some(), "новая публикация владельца проходит");
    }

    /// Фальшивый анонс узла («000…0», за ним никого нет) не мешает: дозвон до
    /// него уходит на паузу, а два реальных узла продолжают общаться.
    #[tokio::test]
    async fn unreachable_peer_does_not_block_chat() {
        let a_port = free_port();
        let b_port = free_port();
        let dead_port = free_port(); // никто не слушает
        let (a_kp, a_id) = keypair(1);
        let (b_kp, b_id) = keypair(2);
        let a_peer = test_peer("alice", a_id, a_port);
        let b_peer = test_peer("bob", b_id, b_port);
        let fake = test_peer("fake", NodeId("0".repeat(64)), dead_port);

        let a_pl = PeerList::new();
        let b_pl = PeerList::new();
        a_pl.upsert(b_peer.clone()).await;
        a_pl.upsert(fake.clone()).await;
        b_pl.upsert(a_peer.clone()).await;
        b_pl.upsert(fake).await;

        let alice = start_public_chat(a_peer, a_pl, a_port, a_kp, None).await.unwrap();
        let bob = start_public_chat(b_peer, b_pl, b_port, b_kp, None).await.unwrap();
        let mut alice_rx = alice.subscribe();
        let mut bob_rx = bob.subscribe();

        let mut delivered = false;
        for _ in 0..30 {
            bob.send("global".into(), "from_bob".into()).await.unwrap();
            if wait_for_text(&mut alice_rx, "from_bob", 1).await {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "фальшивый кандидат с минимальным ID заблокировал чат");
        let mut back = false;
        for _ in 0..10 {
            alice.send("global".into(), "from_alice".into()).await.unwrap();
            if wait_for_text(&mut bob_rx, "from_alice", 1).await {
                back = true;
                break;
            }
        }
        assert!(back, "обратное направление не работает");
    }

    /// Сосед присылает историю с поддельным сообщением — принимаются только
    /// сообщения с верной подписью автора.
    #[tokio::test]
    async fn forged_history_from_peer_is_dropped() {
        let relay_port = free_port();
        let my_port = free_port();
        let (author_kp, author_id) = keypair(3);
        let author_chat = PublicChat::new(test_peer("author", author_id.clone(), 1), PeerList::new(), 1, author_kp, None);

        let mut genuine = ChatMessage::new(author_id.clone(), "author".into(), "genuine".into(), "global".into(), 1);
        author_chat.sign_message(&mut genuine);
        let mut forged = genuine.clone();
        forged.seq = 2;
        forged.text = "forged".into();

        // Злой сосед (настоящий узел): проходит рукопожатие, обменивается Hello,
        // шлёт историю с подделкой и держит соединение.
        let ((relay_kp, relay_id), (my_kp, my_id)) = ordered_keypairs(4, 8);
        let relay_noise = NoiseIdentity::new(&relay_kp);
        let evil_id = relay_id.clone();
        let listener = TcpListener::bind(("127.0.0.1", relay_port)).await.unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = secure::accept(tcp, &relay_noise, Channel::Chat).await.unwrap();
            let _hello = read_packet(&mut stream).await.unwrap();
            send_packet(&mut stream, &ChatPacket::Hello { node_id: evil_id, name: "evil".into(), chat_port: 1 })
                .await
                .unwrap();
            send_packet(&mut stream, &ChatPacket::History { messages: vec![genuine, forged] })
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let pl = PeerList::new();
        pl.upsert(test_peer("relay", relay_id, relay_port)).await;
        let me = start_public_chat(test_peer("me", my_id, my_port), pl, my_port, my_kp, None).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let texts = loop {
            let texts: Vec<String> = me.recent(10).await.into_iter().map(|m| m.text).collect();
            if !texts.is_empty() || tokio::time::Instant::now() > deadline {
                break texts;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(texts, vec!["genuine".to_string()], "поддельное сообщение из истории принято");
    }

    /// Подписанное, но гигантское сообщение отбрасывается; своё слишком
    /// длинное сообщение не отправляется.
    #[tokio::test]
    async fn oversized_message_rejected() {
        let (kp, id) = keypair(6);
        let chat = PublicChat::new(test_peer("x", id.clone(), 1), PeerList::new(), 1, kp, None);
        let mut rx = chat.subscribe();

        let mut big = ChatMessage::new(id.clone(), "x".into(), "a".repeat(MAX_CHAT_TEXT_BYTES + 1), "global".into(), 1);
        chat.sign_message(&mut big);
        assert!(chat.verify_message(&big));
        chat.handle_incoming(big, None).await;
        assert!(rx.try_recv().is_err(), "сообщение сверх лимита не должно доходить до UI");

        assert!(chat.send("global".into(), "a".repeat(MAX_CHAT_TEXT_BYTES + 1)).await.is_err());
        assert!(chat.send("global".into(), "ok".into()).await.is_ok());
    }

    /// Анонс сайта с ненормализованным именем (уходит в URL → в обработчик ОС)
    /// не принимается.
    #[tokio::test]
    async fn site_with_unsafe_name_rejected() {
        let (kp, id) = keypair(7);
        let chat = PublicChat::new(test_peer("x", id.clone(), 1), PeerList::new(), 1, kp.clone(), None);
        let mk = |name: &str| sign_site(SiteManifest {
            site_id: "sid".into(), name: name.into(), owner: id.clone(),
            entries: vec![], created_at: 1, signature: None,
        }, &kp);
        assert!(chat.merge_site(mk("x&calc"), None).await.is_none());
        assert!(chat.merge_site(mk("My Site"), None).await.is_none());
        assert!(chat.merge_site(mk("../blog"), None).await.is_none());
        assert!(chat.merge_site(mk("my-site"), None).await.is_some());
    }

    /// Анонс «Алисы» с адресом самозванца: узел обрывает рукопожатие — на том
    /// конце не Алиса — и не отдаёт самозванцу сообщения.
    #[tokio::test]
    async fn impostor_at_peer_address_gets_nothing() {
        let ((_alice_kp, alice_id), (bob_kp, bob_id)) = ordered_keypairs(1, 2);
        let (mallory_kp, mallory_id) = keypair(3);
        let m_port = free_port();
        let b_port = free_port();

        let mallory = start_public_chat(
            test_peer("mallory", mallory_id, m_port), PeerList::new(), m_port, mallory_kp, None,
        ).await.unwrap();
        let mut m_rx = mallory.subscribe();

        let b_pl = PeerList::new();
        b_pl.upsert(test_peer("alice", alice_id, m_port)).await; // ID Алисы, адрес Мэллори
        let bob = start_public_chat(test_peer("bob", bob_id, b_port), b_pl, b_port, bob_kp, None)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(500)).await;
        for _ in 0..3 {
            bob.send("global".into(), "secret".into()).await.unwrap();
        }
        assert!(
            !wait_for_text(&mut m_rx, "secret", 2).await,
            "самозванец получил сообщения, выдав себя за релей"
        );
    }

    /// Манифест сайта «от имени» владельца, но без его подписи (или с подменой
    /// после подписи) не принимается.
    #[tokio::test]
    async fn forged_site_manifest_rejected() {
        let (owner_kp, owner_id) = keypair(1);
        let (evil_kp, _evil_id) = keypair(9);
        let (kp, id) = keypair(5);
        let chat = PublicChat::new(test_peer("x", id, 1), PeerList::new(), 1, kp, None);

        let base = SiteManifest {
            site_id: "sid".into(), name: "bank".into(), owner: owner_id.clone(),
            entries: vec![], created_at: 1, signature: None,
        };
        assert!(chat.merge_site(base.clone(), None).await.is_none(), "без подписи");
        assert!(chat.merge_site(sign_site(base.clone(), &evil_kp), None).await.is_none(), "подписал не владелец");

        let mut tampered = sign_site(base.clone(), &owner_kp);
        tampered.entries.push(void_core::site::SiteEntry {
            path: "index.html".into(), file_id: "evil".into(), size_bytes: 1,
        });
        assert!(chat.merge_site(tampered, None).await.is_none(), "подмена файлов после подписи");

        assert!(chat.merge_site(sign_site(base, &owner_kp), None).await.is_some(), "подпись владельца проходит");
    }

    /// Профиль принимается только с подписью своего узла; старая версия не
    /// откатывает новую.
    #[tokio::test]
    async fn profiles_must_be_signed_by_owner() {
        let (alice_kp, alice_id) = keypair(1);
        let (evil_kp, _) = keypair(9);
        let (kp, id) = keypair(5);
        let chat = PublicChat::new(test_peer("x", id, 1), PeerList::new(), 1, kp, None);

        let sign = |mut p: PeerProfile, k: &SigningKeypair| {
            p.signature = None;
            p.signature = Some(SignedMessage::sign(p.signing_bytes(), k).unwrap().signature);
            p
        };
        let mut genuine = PeerProfile::new(alice_id.clone(), "Alice".into());
        genuine.updated_at = 10;
        let mut fake = PeerProfile::new(alice_id.clone(), "Alice (настоящая)".into());
        fake.updated_at = 20;

        chat.handle_profile_update(fake.clone(), None).await;
        chat.handle_profile_update(sign(fake.clone(), &evil_kp), None).await;
        assert!(chat.get_profiles().await.is_empty(), "неподписанный/чужой профиль не принят");

        chat.handle_profile_update(sign(genuine.clone(), &alice_kp), None).await;
        assert_eq!(chat.get_profiles().await[0].name, "Alice");

        let mut renamed = sign(genuine.clone(), &alice_kp);
        renamed.name = "Mallory".into(); // подмена после подписи
        renamed.updated_at = 30;
        chat.handle_profile_update(renamed, None).await;
        assert_eq!(chat.get_profiles().await[0].name, "Alice");

        let mut newer = genuine.clone();
        newer.name = "Alice 2".into();
        newer.updated_at = 40;
        chat.handle_profile_update(sign(newer, &alice_kp), None).await;
        chat.handle_profile_update(sign(genuine, &alice_kp), None).await; // повтор старой версии
        assert_eq!(chat.get_profiles().await[0].name, "Alice 2", "старая версия не откатывает новую");
    }

    /// Свой профиль подписывается при set_profile и проходит проверку получателем.
    #[tokio::test]
    async fn own_profile_is_signed() {
        let (kp, id) = keypair(3);
        let chat = PublicChat::new(test_peer("x", id.clone(), 1), PeerList::new(), 1, kp, None);
        chat.set_profile(PeerProfile::new(id.clone(), "Боб".into())).await;
        chat.set_profile(PeerProfile::new(id, "Боб 2".into())).await;
        let mine = chat.inner.my_profile.lock().await.clone().unwrap();
        assert!(verify_profile(&mine));
        assert_eq!(mine.name, "Боб 2");
    }

    /// Имя отправителя входит в подпись: релей не может переименовать автора.
    #[tokio::test]
    async fn sender_name_is_signed() {
        let (kp, id) = keypair(5);
        let chat = PublicChat::new(test_peer("x", id.clone(), 1), PeerList::new(), 1, kp, None);
        let mut msg = ChatMessage::new(id, "Alice".into(), "привет".into(), "global".into(), 1);
        chat.sign_message(&mut msg);
        assert!(chat.verify_message(&msg));
        msg.from_name = "Admin".into();
        assert!(!chat.verify_message(&msg), "переименование автора ломает подпись");
    }

    /// Новый файл без подписи публикатора (или переименованный после подписи)
    /// не принимается; известный — пополняется сидерами.
    #[tokio::test]
    async fn file_manifest_requires_publisher_signature() {
        let (alice_kp, _) = keypair(1);
        let (kp, id) = keypair(5);
        let chat = PublicChat::new(test_peer("x", id, 1), PeerList::new(), 1, kp, None);
        let base = FileManifest {
            file_id: "f1".into(), name: "report.pdf".into(), size_bytes: 1, mime_type: None,
            owners: vec![], chunks: vec![ChunkMeta { hash: "a".repeat(64), index: 0, size: 1 }],
            publisher: None, signature: None,
        };
        assert!(chat.merge_manifest(base.clone(), None).await.is_none(), "без подписи");

        let mut renamed = sign_file(base.clone(), &alice_kp);
        renamed.name = "report.pdf.exe".into();
        assert!(chat.merge_manifest(renamed, None).await.is_none(), "переименование после подписи");

        assert!(chat.merge_manifest(sign_file(base.clone(), &alice_kp), None).await.is_some());
        // Сидер без подписи пополняет уже известный файл.
        let mut seeder = base;
        seeder.owners = vec![NodeId("c".repeat(64))];
        let merged = chat.merge_manifest(seeder, None).await.expect("новый сидер");
        assert_eq!(merged.name, "report.pdf");
        assert!(merged.signature.is_some(), "подписанная часть сохранилась");
    }

    // ─── Сеть без центра ─────────────────────────────────────────────────────

    /// Ключ и PeerInfo узла на свободном порту.
    fn mesh_peer(seed: u8) -> (Arc<SigningKeypair>, PeerInfo) {
        let (kp, id) = keypair(seed);
        let port = free_port();
        (kp, test_peer(&format!("n{seed}"), id, port))
    }

    /// Запускает узел, знающий `known` соседей.
    async fn start_mesh_node(kp: Arc<SigningKeypair>, me: &PeerInfo, known: &[&PeerInfo]) -> ChatHandle {
        let pl = PeerList::new();
        for p in known {
            pl.upsert((*p).clone()).await;
        }
        start_public_chat(me.clone(), pl, me.chat_port, kp, None).await.unwrap()
    }

    /// Шлёт сообщение, пока его не увидит получатель (связи поднимаются не сразу).
    async fn deliver(from: &ChatHandle, rx: &mut broadcast::Receiver<ChatMessage>, text: &str) -> bool {
        for _ in 0..30 {
            from.send("global".into(), text.into()).await.unwrap();
            if wait_for_text(rx, text, 1).await {
                return true;
            }
        }
        false
    }

    /// Цепочка A — B — C: A и C не знают друг друга, сообщения идут через B.
    #[tokio::test]
    async fn messages_travel_over_multiple_hops() {
        let (ka, a) = mesh_peer(1);
        let (kb, b) = mesh_peer(2);
        let (kc, c) = mesh_peer(3);
        let _node_b = start_mesh_node(kb, &b, &[]).await;
        let node_a = start_mesh_node(ka, &a, &[&b]).await;
        let node_c = start_mesh_node(kc, &c, &[&b]).await;
        let mut rx_a = node_a.subscribe();
        let mut rx_c = node_c.subscribe();

        assert!(deliver(&node_a, &mut rx_c, "a-to-c").await, "A → B → C не дошло");
        assert!(deliver(&node_c, &mut rx_a, "c-to-a").await, "C → B → A не дошло");
    }

    /// Узел-«чёрная дыра» (проходит рукопожатие, но ничего не пересылает)
    /// связан с обоими собеседниками — сообщения всё равно доходят через
    /// честного соседа. В «звезде» такой узел, став релеем, глушил всю сеть.
    #[tokio::test]
    async fn silent_node_cannot_censor() {
        let (km, m) = mesh_peer(9);
        let m_noise = NoiseIdentity::new(&km);
        let m_id = m.id.clone();
        let listener = TcpListener::bind(("127.0.0.1", m.chat_port)).await.unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let (noise, id) = (m_noise.clone(), m_id.clone());
                tokio::spawn(async move {
                    let Ok(mut s) = secure::accept(tcp, &noise, Channel::Chat).await else { return };
                    let _ = read_packet(&mut s).await;
                    let hello = ChatPacket::Hello { node_id: id, name: "m".into(), chat_port: 1 };
                    let _ = send_packet(&mut s, &hello).await;
                    while read_packet(&mut s).await.is_ok() {} // глотает всё
                });
            }
        });

        let (kc, c) = mesh_peer(3);
        let (ka, a) = mesh_peer(1);
        let (kb, b) = mesh_peer(2);
        let _node_c = start_mesh_node(kc, &c, &[]).await;
        let node_a = start_mesh_node(ka, &a, &[&m, &c]).await;
        let node_b = start_mesh_node(kb, &b, &[&m, &c]).await;
        let mut rx_b = node_b.subscribe();

        assert!(deliver(&node_a, &mut rx_b, "через честного соседа").await, "«чёрная дыра» заглушила сообщение");
    }

    /// Треугольник: все знают всех. Встречные связи схлопываются в одну на пару,
    /// а каждое сообщение доходит до каждого ровно один раз (дедуп гасит петли).
    #[tokio::test]
    async fn triangle_delivers_each_message_once() {
        let (ka, a) = mesh_peer(1);
        let (kb, b) = mesh_peer(2);
        let (kc, c) = mesh_peer(3);
        let node_a = start_mesh_node(ka, &a, &[&b, &c]).await;
        let node_b = start_mesh_node(kb, &b, &[&a, &c]).await;
        let node_c = start_mesh_node(kc, &c, &[&a, &b]).await;

        // Ждём, пока у каждого будет ровно по две связи.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let counts = (node_a.link_count().await, node_b.link_count().await, node_c.link_count().await);
            if counts == (2, 2, 2) {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "связи не сошлись: {counts:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut rx_b = node_b.subscribe();
        for i in 0..5 {
            node_a.send("global".into(), format!("m{i}")).await.unwrap();
        }
        let mut got = Vec::new();
        let until = tokio::time::Instant::now() + Duration::from_secs(2);
        while let Ok(Ok(msg)) = timeout(until.saturating_duration_since(tokio::time::Instant::now()), rx_b.recv()).await {
            got.push(msg.text);
        }
        got.sort();
        assert_eq!(got, vec!["m0", "m1", "m2", "m3", "m4"], "каждое сообщение — ровно один раз");
    }

    /// Узел, подключившийся позже, получает уже отправленные сообщения из
    /// истории соседа (и они попадают в его UI/БД).
    #[tokio::test]
    async fn late_joiner_catches_up_from_history() {
        let (ka, a) = mesh_peer(1);
        let node_a = start_mesh_node(ka, &a, &[]).await;
        node_a.send("global".into(), "раннее".into()).await.unwrap();

        let (kb, b) = mesh_peer(2);
        let node_b = start_mesh_node(kb, &b, &[&a]).await;
        let mut rx_b = node_b.subscribe();
        assert!(wait_for_text(&mut rx_b, "раннее", 10).await, "история не догнала новичка");
    }

    /// DNS-запись доходит до новичка, который не связан с её владельцем: сосед
    /// передаёт известные записи при установке связи (а повторная рассылка
    /// владельца до новичка не дошла бы — промежуточные узлы её уже видели).
    #[tokio::test]
    async fn late_joiner_learns_dns_via_neighbor() {
        let (ka, a) = mesh_peer(1);
        let (kb, b) = mesh_peer(2);
        let node_b = start_mesh_node(kb, &b, &[]).await;
        let node_a = start_mesh_node(ka.clone(), &a, &[&b]).await;
        let mut rx_b = node_b.subscribe();
        assert!(deliver(&node_a, &mut rx_b, "a-b связаны").await);

        let record = DnsRecord {
            name: "blog".into(), kind: void_core::dns::DnsKind::Site, node_id: a.id.clone(),
            ip: None, port: Some(1), created_at: 1, updated_at: 1, deleted: false,
        };
        let signed = SignedMessage::sign(record.to_bytes(), &ka).unwrap();
        let mut dns_b = node_b.subscribe_dns();
        node_a.announce_dns(signed.clone()).await;
        assert!(timeout(Duration::from_secs(5), dns_b.recv()).await.is_ok(), "B получил запись");

        let (kc, c) = mesh_peer(3);
        let node_c = start_mesh_node(kc, &c, &[&b]).await;
        let mut dns_c = node_c.subscribe_dns();
        let got = timeout(Duration::from_secs(10), dns_c.recv()).await;
        assert!(matches!(got, Ok(Ok(ref s)) if s.signature == signed.signature), "новичок не узнал имя: {got:?}");
    }

    /// Новая связь сигналит backend'у; поручительство доходит до соседа с
    /// указанием источника; push_vouches отправляет записи конкретному соседу.
    #[tokio::test]
    async fn vouches_reach_neighbor_with_source() {
        let (ka, a) = mesh_peer(1);
        let (kb, b) = mesh_peer(2);
        let node_b = start_mesh_node(kb, &b, &[]).await;
        let mut links_b = node_b.subscribe_links();
        let mut vouches_b = node_b.subscribe_vouches();
        let node_a = start_mesh_node(ka.clone(), &a, &[&b]).await;

        let linked = timeout(Duration::from_secs(10), links_b.recv()).await;
        assert!(matches!(linked, Ok(Ok(ref id)) if *id == a.id), "B узнал о связи с A: {linked:?}");
        // У A связь регистрируется чуть позже (он дочитывает Hello от B).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while node_a.link_count().await == 0 {
            assert!(tokio::time::Instant::now() < deadline, "у A нет связи");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let rec1 = SignedMessage::sign(b"vouch-1".to_vec(), &ka).unwrap();
        node_a.relay_vouch(rec1.clone(), None).await;
        let got = timeout(Duration::from_secs(5), vouches_b.recv()).await.unwrap().unwrap();
        assert_eq!(got.signed.signature, rec1.signature);
        assert_eq!(got.from, a.id, "источник — сосед A");

        let rec2 = SignedMessage::sign(b"vouch-2".to_vec(), &ka).unwrap();
        node_a.push_vouches(&b.id, vec![rec2.clone(), rec1.clone()]).await;
        let got = timeout(Duration::from_secs(5), vouches_b.recv()).await.unwrap().unwrap();
        assert_eq!(got.signed.signature, rec2.signature, "дубликат rec1 погашен, rec2 дошёл");
        assert!(timeout(Duration::from_millis(300), vouches_b.recv()).await.is_err());
    }

    /// Собирает тексты сообщений из приёмника за `ms` миллисекунд.
    async fn collect_texts(rx: &mut broadcast::Receiver<ChatMessage>, ms: u64) -> Vec<String> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        while let Ok(Ok(m)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            out.push(m.text);
        }
        out
    }

    /// Незнакомец в глазах получателя: в общем канале проходит лишь запас
    /// (и для догоняющей истории — дата в прошлом лимит не обходит), в
    /// «Новичках» он пишет свободно; ответы доверенного не ограничены.
    #[tokio::test]
    async fn stranger_limited_by_receiver_view() {
        use crate::trust_limits::NEWCOMERS_CHANNEL;
        let (ka, a) = mesh_peer(1);
        let (kb, b) = mesh_peer(2);
        // A пишет, пока ни с кем не связан: сообщения уйдут B историей.
        let node_a = start_mesh_node(ka, &a, &[]).await;
        for i in 0..6 {
            node_a.send("global".into(), format!("old{i}")).await.unwrap();
        }

        // B считает A незнакомцем; узнаёт о нём только после этого.
        let b_pl = PeerList::new();
        let node_b = start_public_chat(b.clone(), b_pl.clone(), b.chat_port, kb, None).await.unwrap();
        let stranger = a.id.clone();
        node_b.set_author_tiers(Arc::new(move |id: &NodeId| {
            if *id == stranger { AuthorTier::Stranger } else { AuthorTier::Trusted }
        }));
        let mut rx_b = node_b.subscribe();
        let mut rx_a = node_a.subscribe();
        b_pl.upsert(a.clone()).await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while node_a.link_count().await == 0 || node_b.link_count().await == 0 {
            assert!(tokio::time::Instant::now() < deadline, "связь A–B не установилась");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = collect_texts(&mut rx_b, 1500).await;
        assert_eq!(got.len(), 3, "из истории незнакомца прошёл только запас: {got:?}");

        for i in 0..4 {
            node_a.send("global".into(), format!("live{i}")).await.unwrap();
        }
        for i in 0..6 {
            node_a.send(NEWCOMERS_CHANNEL.into(), format!("hi{i}")).await.unwrap();
        }
        let got = collect_texts(&mut rx_b, 1500).await;
        assert!(got.iter().all(|t| t.starts_with("hi")), "запас общего канала исчерпан: {got:?}");
        assert_eq!(got.len(), 6, "в «Новичках» незнакомец пишет свободно: {got:?}");

        // У A политики нет — B для него как прежде без доп. лимитов.
        for i in 0..8 {
            node_b.send("global".into(), format!("reply{i}")).await.unwrap();
        }
        let got = collect_texts(&mut rx_a, 1500).await;
        assert_eq!(got.iter().filter(|t| t.starts_with("reply")).count(), 8, "{got:?}");
    }
}
