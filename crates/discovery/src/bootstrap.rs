//! Bootstrap-узлы — первое знакомство узлов из разных сетей.
//!
//! mDNS/UDP работают только в пределах одной LAN. Bootstrap-узел даёт точку
//! входа: новый узел подключается к нему по TCP, регистрирует себя и забирает
//! список известных пиров. После знакомства узлы общаются напрямую (по
//! `PeerInfo.ip:port` / `chat_addr`), а bootstrap из цепочки выпадает.
//!
//! Протокол (length-prefixed JSON, как у чата):
//!   клиент → сервер: `Hello(PeerInfo)`   — «вот я, добавь меня»
//!   сервер → клиент: `Peers(Vec<PeerInfo>)` — известные сервером пиры + он сам
//!
//! Bootstrap-сервис слушает на `base_port + BOOTSTRAP_PORT_OFFSET`.

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use void_core::peer::PeerInfo;
use void_network::conn_guard::ConnLimiter;

use crate::peer_list::PeerList;

/// Смещение порта bootstrap-сервиса относительно `base_port` узла.
/// base (чанки), +1 UDP, +2 чат, +3 DM, +4 сайты HTTP, +5 bootstrap.
pub const BOOTSTRAP_PORT_OFFSET: u16 = 5;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Таймаут обратной пробы доступности (bootstrap → клиент). Короткий: успех на
/// открытом порту мгновенен, а блокировка/CGNAT выглядит как зависший connect.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Списки пиров невелики; ограничиваем размер пакета.
const MAX_MSG: usize = 1024 * 1024;
/// Как часто переопрашивать bootstrap-узлы (на случай новых участников/рестарта).
const REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// Реальный узел имеет 64-символьный hex NodeId (не stub-заглушка).
const REAL_ID_LEN: usize = 64;
/// Сколько одновременных регистраций обслуживает bootstrap суммарно.
const MAX_BOOTSTRAP_CONNS: usize = 128;
/// Лимит одновременных соединений с одного IP (защита от connection-flood).
const MAX_BOOTSTRAP_CONNS_PER_IP: usize = 8;
/// Таймаут на чтение Hello от клиента (защита от slowloris).
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BootstrapMsg {
    /// Клиент представляется bootstrap-узлу.
    Hello { peer: PeerInfo },
    /// Сервер отдаёт известных ему пиров (включая себя).
    /// Struct-вариант, а не newtype-над-Vec: внутренне-тегированные enum'ы
    /// (`tag = "kind"`) не умеют тегировать последовательность.
    ///
    /// `reachable` — результат обратной пробы: смог ли bootstrap-узел сам
    /// подключиться к base-порту клиента по его ВНЕШНЕМУ адресу (источник TCP).
    /// `Some(true)` — порт открыт извне, `Some(false)` — заблокирован
    /// (провайдер/файрвол/CGNAT), `None` — проба не делалась (стар. версия/stub).
    Peers {
        peers: Vec<PeerInfo>,
        #[serde(default)]
        reachable: Option<bool>,
    },
    /// Неизвестный тип — игнорируется (совместимость версий).
    #[serde(other)]
    Unknown,
}

/// Доступность наших портов извне (по результату обратной пробы bootstrap-узла).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    /// Ещё не проверяли (нет bootstrap-узлов или первый обмен не прошёл).
    Unknown,
    /// Bootstrap-узел успешно подключился к нам — порты открыты извне.
    Reachable,
    /// Bootstrap-узел не смог подключиться — входящие соединения блокируются.
    Blocked,
}

/// Результат одного обмена с bootstrap-узлом.
pub struct ExchangeOutcome {
    /// Сколько пиров узнали впервые.
    pub learned: usize,
    /// Доступны ли наши порты извне (если узел делал пробу).
    pub reachable: Option<bool>,
}

/// Преобразует базовый адрес `host:base_port` в адрес bootstrap-сервиса
/// `host:(base_port + OFFSET)` — на него подключается клиент.
pub fn service_addr(base_addr: &str) -> io::Result<String> {
    let (host, port) = base_addr
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ожидался host:port"))?;
    let base: u16 = port
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "неверный порт"))?;
    let svc = base.checked_add(BOOTSTRAP_PORT_OFFSET).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "базовый порт слишком велик (переполнение)")
    })?;
    Ok(format!("{}:{}", host.trim(), svc))
}

// ─── Сервер (роль bootstrap-узла) ─────────────────────────────────────────────

/// Запускает bootstrap-сервер: принимает `Hello`, регистрирует новичка и
/// отдаёт ему известных пиров. Неблокирующий — спавнит фоновую задачу.
pub async fn start_bootstrap_server(
    my_peer: PeerInfo,
    peer_list: PeerList,
    port: u16,
) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("Bootstrap server listening on 0.0.0.0:{}", port);
    let limiter = ConnLimiter::new(MAX_BOOTSTRAP_CONNS, MAX_BOOTSTRAP_CONNS_PER_IP);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    // Защита от connection-flood: при переполнении сразу закрываем.
                    let permit = match limiter.try_accept(addr.ip()) {
                        Some(p) => p,
                        None => {
                            debug!("Bootstrap at capacity, dropping {}", addr);
                            drop(stream);
                            continue;
                        }
                    };
                    let pl = peer_list.clone();
                    let me = my_peer.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = handle_bootstrap_client(stream, me, pl).await {
                            debug!("Bootstrap client {} error: {}", addr, e);
                        }
                    });
                }
                Err(e) => warn!("Bootstrap accept error: {}", e),
            }
        }
    });
    Ok(())
}

async fn handle_bootstrap_client(
    mut stream: TcpStream,
    my_peer: PeerInfo,
    peer_list: PeerList,
) -> io::Result<()> {
    // Внешний адрес клиента — это источник TCP-соединения (не LAN-IP из Hello).
    let src_ip = stream.peer_addr().ok().map(|a| a.ip());

    // Шаг 1: читаем Hello и регистрируем новичка (только реальные узлы).
    // Slowloris-защита: ограничиваем время ожидания первого сообщения.
    let mut probe_port: Option<u16> = None;
    let first = timeout(CLIENT_READ_TIMEOUT, read_msg(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client read timed out"))??;
    if let BootstrapMsg::Hello { mut peer } = first {
        if peer.id.as_str().len() == REAL_ID_LEN {
            // NAT-traversal: узел рекламирует свой LAN-адрес, но из другой сети он
            // недостижим. Подменяем приватный/loopback ip на ВНЕШНИЙ (источник
            // TCP-соединения, как его видит bootstrap), чтобы остальные пиры могли
            // подключиться к узлу напрямую (если порт открыт/проброшен) и не гонять
            // трафик через relay. Публичный (маршрутизируемый) адрес не трогаем.
            if looks_private(peer.ip) {
                if let Some(src) = src_ip {
                    if peer.ip != src {
                        debug!("Bootstrap: внешний адрес {} → {} для {}", peer.ip, src, peer.name);
                    }
                    peer.ip = src;
                }
            }
            debug!("Bootstrap: registered peer {} ({}) at {}", peer.name, peer.id, peer.ip);
            probe_port = Some(peer.port);
            peer_list.upsert(peer).await;
        }
    }

    // Шаг 2: обратная проба — пробуем подключиться к base-порту клиента по его
    // внешнему адресу. Так клиент узнаёт, открыты ли его порты извне.
    let reachable = match (src_ip, probe_port) {
        (Some(ip), Some(port)) => Some(probe_reachable(ip, port).await),
        _ => None,
    };

    // Шаг 3: отдаём известных пиров + себя + вердикт по доступности.
    let mut peers: Vec<PeerInfo> = peer_list
        .all()
        .await
        .into_iter()
        .filter(|p| p.id.as_str().len() == REAL_ID_LEN)
        .collect();
    peers.push(my_peer);
    write_msg(&mut stream, &BootstrapMsg::Peers { peers, reachable }).await
}

/// «Похож на приватный/локальный» адрес — недостижим из другой сети, поэтому
/// bootstrap заменяет его на внешний (источник TCP-соединения).
fn looks_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Пробует за короткий таймаут подключиться к `ip:port`. `true` — порт принимает
/// входящие (открыт извне), `false` — отказ/таймаут (заблокирован/недоступен).
async fn probe_reachable(ip: IpAddr, port: u16) -> bool {
    matches!(
        timeout(PROBE_TIMEOUT, TcpStream::connect((ip, port))).await,
        Ok(Ok(_))
    )
}

// ─── Клиент ───────────────────────────────────────────────────────────────────

/// Одна попытка обмена с bootstrap-сервисом по адресу `service_addr`
/// (`host:(base_port+OFFSET)`). Регистрирует нас и добавляет полученных пиров в
/// `peer_list`. Возвращает число впервые узнанных пиров.
pub async fn bootstrap_exchange(
    my_peer: &PeerInfo,
    peer_list: &PeerList,
    service_addr: &str,
) -> io::Result<ExchangeOutcome> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(service_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;

    write_msg(&mut stream, &BootstrapMsg::Hello { peer: my_peer.clone() }).await?;

    let mut learned = 0usize;
    let mut reachable = None;
    if let BootstrapMsg::Peers { peers, reachable: r } = read_msg(&mut stream).await? {
        reachable = r;
        for p in peers {
            if p.id != my_peer.id && p.id.as_str().len() == REAL_ID_LEN {
                let known = peer_list.get(&p.id).await.is_some();
                peer_list.upsert(p).await;
                if !known {
                    learned += 1;
                }
            }
        }
    }
    Ok(ExchangeOutcome { learned, reachable })
}

/// Периодически опрашивает заданные bootstrap-сервисы (точные адреса
/// `host:port`, уже со смещением). Неблокирующий — спавнит фоновую задачу.
/// Пустой список → ничего не делает.
pub fn start_bootstrap_client(
    my_peer: PeerInfo,
    peer_list: PeerList,
    service_addrs: Vec<String>,
    reach: std::sync::Arc<std::sync::Mutex<Reachability>>,
) {
    if service_addrs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        loop {
            interval.tick().await; // первый тик немедленный
            // Доступность за тик: достаточно одного «дозвонились» (true побеждает).
            let mut tick_reach: Option<bool> = None;
            for addr in &service_addrs {
                match bootstrap_exchange(&my_peer, &peer_list, addr).await {
                    Ok(out) => {
                        info!("Bootstrap {} → узнали {} новых пир(ов)", addr, out.learned);
                        if let Some(r) = out.reachable {
                            tick_reach = Some(tick_reach.unwrap_or(false) || r);
                        }
                    }
                    Err(e) => debug!("Bootstrap {} недоступен: {}", addr, e),
                }
            }
            if let Some(r) = tick_reach {
                let verdict = if r { Reachability::Reachable } else { Reachability::Blocked };
                *reach.lock().unwrap() = verdict;
                match verdict {
                    Reachability::Blocked => info!(
                        "Проверка портов: ВХОДЯЩИЕ заблокированы (провайдер/файрвол/NAT) — \
                         прямые подключения извне недоступны"),
                    Reachability::Reachable => info!("Проверка портов: порты открыты извне"),
                    Reachability::Unknown => {}
                }
            }
        }
    });
}

// ─── Сериализация (length-prefixed JSON) ───────────────────────────────────────

async fn write_msg<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &BootstrapMsg) -> io::Result<()> {
    let json = serde_json::to_vec(msg).map_err(to_io)?;
    if json.len() > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    w.write_all(&(json.len() as u32).to_be_bytes()).await?;
    w.write_all(&json).await?;
    w.flush().await
}

async fn read_msg<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<BootstrapMsg> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(to_io)
}

fn to_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

// ─── Тесты ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use void_core::identity::NodeId;
    use void_core::peer::Service;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn peer(seed: u8, base_port: u16) -> PeerInfo {
        PeerInfo {
            id:        NodeId::from_public_key_bytes(&[seed; 32]),
            name:      format!("node{seed}"),
            ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:      base_port,
            chat_port: base_port + 2,
            services:  vec![Service::Chat],
            last_seen: 0,
        }
    }

    #[test]
    fn service_addr_applies_offset() {
        assert_eq!(service_addr("1.2.3.4:7700").unwrap(), "1.2.3.4:7705");
        assert_eq!(service_addr("host:80").unwrap(), "host:85");
        assert!(service_addr("no-port").is_err());
    }

    /// Узел B знакомится с bootstrap-узлом A: B узнаёт A, A регистрирует B.
    #[tokio::test]
    async fn exchange_registers_and_learns() {
        let a = peer(1, free_port());
        let svc_port = free_port();
        let pl_a = PeerList::new();
        start_bootstrap_server(a.clone(), pl_a.clone(), svc_port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let b = peer(2, free_port());
        let pl_b = PeerList::new();
        let svc = format!("127.0.0.1:{svc_port}");
        let learned = bootstrap_exchange(&b, &pl_b, &svc).await.unwrap().learned;

        assert_eq!(learned, 1, "B должен узнать ровно A");
        assert!(pl_b.get(&a.id).await.is_some(), "B знает A");
        assert!(pl_a.get(&b.id).await.is_some(), "A зарегистрировал B");
    }

    /// Рандеву: A — bootstrap; B и C знакомятся через него и узнают друг о друге.
    #[tokio::test]
    async fn rendezvous_via_bootstrap() {
        let a = peer(1, free_port());
        let svc_port = free_port();
        let pl_a = PeerList::new();
        start_bootstrap_server(a.clone(), pl_a.clone(), svc_port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let svc = format!("127.0.0.1:{svc_port}");

        // B знакомится первым (A теперь знает B).
        let b = peer(2, free_port());
        let pl_b = PeerList::new();
        bootstrap_exchange(&b, &pl_b, &svc).await.unwrap();

        // C знакомится позже — должен узнать и A, и B.
        let c = peer(3, free_port());
        let pl_c = PeerList::new();
        let learned = bootstrap_exchange(&c, &pl_c, &svc).await.unwrap().learned;

        assert_eq!(learned, 2, "C узнаёт A и B");
        assert!(pl_c.get(&a.id).await.is_some(), "C знает A");
        assert!(pl_c.get(&b.id).await.is_some(), "C знает B (через bootstrap)");
    }

    /// NAT-traversal: bootstrap подменяет приватный LAN-адрес клиента на его
    /// внешний (источник соединения), чтобы другие узлы подключались напрямую.
    #[tokio::test]
    async fn exchange_stamps_external_ip() {
        let a = peer(1, free_port());
        let svc_port = free_port();
        let pl_a = PeerList::new();
        start_bootstrap_server(a.clone(), pl_a.clone(), svc_port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let svc = format!("127.0.0.1:{svc_port}");

        // B рекламирует «LAN»-адрес 10.0.0.5, но подключается с 127.0.0.1.
        let mut b = peer(2, free_port());
        b.ip = "10.0.0.5".parse().unwrap();
        bootstrap_exchange(&b, &PeerList::new(), &svc).await.unwrap();

        let stored = pl_a.get(&b.id).await.expect("A зарегистрировал B");
        assert_eq!(stored.ip.to_string(), "127.0.0.1",
            "приватный адрес должен быть заменён на внешний (источник соединения)");
    }

    /// Повторный обмен не считает уже известных пиров новыми.
    #[tokio::test]
    async fn repeat_exchange_no_double_count() {
        let a = peer(1, free_port());
        let svc_port = free_port();
        let pl_a = PeerList::new();
        start_bootstrap_server(a.clone(), pl_a.clone(), svc_port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let svc = format!("127.0.0.1:{svc_port}");

        let b = peer(2, free_port());
        let pl_b = PeerList::new();
        assert_eq!(bootstrap_exchange(&b, &pl_b, &svc).await.unwrap().learned, 1);
        assert_eq!(bootstrap_exchange(&b, &pl_b, &svc).await.unwrap().learned, 0, "A уже известен");
    }

    /// Обратная проба: если у клиента открыт base-порт (есть листенер), bootstrap
    /// сообщает `reachable = Some(true)`; если порт закрыт — `Some(false)`.
    #[tokio::test]
    async fn reachability_probe_reflects_open_port() {
        let a = peer(1, free_port());
        let svc_port = free_port();
        let pl_a = PeerList::new();
        start_bootstrap_server(a.clone(), pl_a.clone(), svc_port).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let svc = format!("127.0.0.1:{svc_port}");

        // Клиент B с ОТКРЫТЫМ base-портом (поднимаем листенер на нём).
        let b_base = free_port();
        let _b_listener = tokio::net::TcpListener::bind(("127.0.0.1", b_base)).await.unwrap();
        let mut b = peer(2, free_port());
        b.port = b_base; // base-порт, который пробует bootstrap
        let out = bootstrap_exchange(&b, &PeerList::new(), &svc).await.unwrap();
        assert_eq!(out.reachable, Some(true), "открытый порт → reachable");

        // Клиент C с ЗАКРЫТЫМ base-портом (никто не слушает).
        let mut c = peer(3, free_port());
        c.port = free_port(); // свободный, но без листенера → connection refused
        let out_c = bootstrap_exchange(&c, &PeerList::new(), &svc).await.unwrap();
        assert_eq!(out_c.reachable, Some(false), "закрытый порт → not reachable");
    }
}
