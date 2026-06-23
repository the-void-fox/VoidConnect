//! Relay (TURN-подобный туннель) — связь между узлами за symmetric NAT.
//!
//! Прямое TCP-соединение (`dial_peer` в DM, скачивание чанков) не проходит,
//! если оба узла за symmetric NAT: их внешние порты непредсказуемы и UPnP
//! недоступен. Решение — публичный узел-ретранслятор: оба клиента держат с ним
//! постоянное «контрольное» соединение и регистрируют свой `NodeId`; когда A не
//! может достучаться до B напрямую, A открывает «туннель» через relay, relay
//! уведомляет B по его контрольному каналу, B подключается обратно, и relay
//! начинает слепо перекачивать сырые байты между двумя data-соединениями.
//! Прикладной протокол (DM-handshake и т.д.) работает поверх туннеля без
//! изменений.
//!
//! Порты узла: base (чанки), +1 UDP, +2 чат, +3 DM, +4 сайты, +5 bootstrap,
//! +6 relay. Relay-сервис поднимается на публичных (`--public`) узлах.
//!
//! Протокол — length-prefixed JSON-кадры (как у bootstrap/DM). Первый кадр
//! соединения задаёт его роль:
//!   * `Register{node_id}`     — это контрольное соединение узла;
//!   * `Open{session,from,to}` — это data-соединение инициатора A;
//!   * `Accept{session}`       — это data-соединение принимающего B.
//! После спаривания relay шлёт обеим сторонам `Ready` и переходит в режим
//! двунаправленной перекачки сырых байт (`copy_bidirectional`).

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use void_core::identity::NodeId;

/// Смещение порта relay-сервиса относительно `base_port`.
pub const RELAY_PORT_OFFSET: u16 = 6;

const MAX_FRAME: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Сколько relay ждёт, пока принимающая сторона откроет data-соединение.
const PAIR_TIMEOUT: Duration = Duration::from_secs(10);
/// Период keep-alive контрольного соединения.
const KEEPALIVE: Duration = Duration::from_secs(20);
/// Backoff переподключения контрольного соединения.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

// ─── Протокол ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayFrame {
    /// Контрольное соединение: узел регистрирует свой NodeId на relay.
    Register { node_id: NodeId },
    /// relay → зарегистрированному узлу: к тебе хотят подключиться, открой
    /// data-соединение с этим `session` и кадром `Accept`.
    Incoming { session: u64, from: NodeId },
    /// data-соединение инициатора: проложи туннель до `to`.
    Open { session: u64, from: NodeId, to: NodeId },
    /// data-соединение принимающего (в ответ на `Incoming`).
    Accept { session: u64 },
    /// relay → обеим сторонам: туннель готов, дальше идут сырые байты.
    Ready,
    /// relay → инициатору: цель не зарегистрирована на этом relay.
    Unreachable,
    Ping,
    Pong,
    /// Неизвестный тип (совместимость версий).
    #[serde(other)]
    Unknown,
}

/// Преобразует базовый адрес `host:base_port` в адрес relay-сервиса
/// `host:(base_port + RELAY_PORT_OFFSET)`.
pub fn service_addr(base_addr: &str) -> io::Result<String> {
    let (host, port) = base_addr
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ожидался host:port"))?;
    let base: u16 = port
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "неверный порт"))?;
    let svc = base.checked_add(RELAY_PORT_OFFSET).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "базовый порт слишком велик (переполнение)")
    })?;
    Ok(format!("{}:{}", host.trim(), svc))
}

// ─── Сервер (роль публичного узла) ──────────────────────────────────────────────

type ControlTx = mpsc::Sender<RelayFrame>;

struct RelayInner {
    /// Зарегистрированные узлы: NodeId → отправитель в их контрольное соединение
    /// (для проталкивания `Incoming`).
    registry: Mutex<HashMap<NodeId, ControlTx>>,
    /// Незавершённые туннели: session → канал, по которому Accept-обработчик
    /// передаёт свой stream ожидающему Open-обработчику.
    pending: Mutex<HashMap<u64, oneshot::Sender<TcpStream>>>,
}

/// Запускает relay-сервер. Неблокирующий — спавнит фоновую задачу.
pub async fn start_relay_server(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("Relay server listening on 0.0.0.0:{}", port);
    let inner = Arc::new(RelayInner {
        registry: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
    });
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let inner = Arc::clone(&inner);
                    tokio::spawn(async move {
                        if let Err(e) = handle_relay_conn(stream, inner).await {
                            debug!("Relay conn {} ended: {}", addr, e);
                        }
                    });
                }
                Err(e) => warn!("Relay accept error: {}", e),
            }
        }
    });
    Ok(())
}

/// Разбирает первый кадр соединения и направляет в нужную роль.
async fn handle_relay_conn(mut stream: TcpStream, inner: Arc<RelayInner>) -> io::Result<()> {
    match read_frame(&mut stream).await? {
        RelayFrame::Register { node_id } => serve_control(stream, node_id, inner).await,
        RelayFrame::Open { session, from, to } => {
            serve_open(stream, session, from, to, inner).await
        }
        RelayFrame::Accept { session } => serve_accept(stream, session, inner).await,
        other => {
            debug!("Relay: unexpected first frame: {:?}", other);
            Ok(())
        }
    }
}

/// Контрольное соединение узла: регистрируем NodeId, держим канал для пушей
/// `Incoming`, обслуживаем keep-alive. Снимаем регистрацию при разрыве.
async fn serve_control(
    stream: TcpStream,
    node_id: NodeId,
    inner: Arc<RelayInner>,
) -> io::Result<()> {
    debug!("Relay: registered control for {}", node_id);
    let (tx, mut rx) = mpsc::channel::<RelayFrame>(32);
    inner.registry.lock().await.insert(node_id.clone(), tx);

    let (mut rd, mut wr) = stream.into_split();

    // Пишущая половина: проталкиваем Incoming/Pong, периодически Ping.
    let write_task = tokio::spawn(async move {
        let mut ka = tokio::time::interval(KEEPALIVE);
        loop {
            tokio::select! {
                frame = rx.recv() => match frame {
                    Some(f) => { if write_frame(&mut wr, &f).await.is_err() { break; } }
                    None => break,
                },
                _ = ka.tick() => {
                    if write_frame(&mut wr, &RelayFrame::Ping).await.is_err() { break; }
                }
            }
        }
    });

    // Читающая половина: клиент шлёт Ping/Pong; разрыв = конец соединения.
    let read_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut rd).await {
                Ok(_) => {} // Ping/Pong/прочее игнорируем
                Err(_) => break,
            }
        }
    });

    tokio::select! {
        _ = write_task => {}
        _ = read_task  => {}
    }

    // Снимаем регистрацию (только если это всё ещё мы — не затёрли реконнектом).
    let mut reg = inner.registry.lock().await;
    if let Some(existing) = reg.get(&node_id) {
        if existing.is_closed() {
            reg.remove(&node_id);
        }
    }
    debug!("Relay: control for {} closed", node_id);
    Ok(())
}

/// data-соединение инициатора: уведомляем цель по её контрольному каналу и ждём,
/// пока она откроет встречное data-соединение (`Accept`), затем перекачиваем байты.
async fn serve_open(
    mut stream: TcpStream,
    session: u64,
    from: NodeId,
    to: NodeId,
    inner: Arc<RelayInner>,
) -> io::Result<()> {
    // Цель должна быть зарегистрирована.
    let ctrl = inner.registry.lock().await.get(&to).cloned();
    let Some(ctrl) = ctrl else {
        debug!("Relay: target {} not registered", to);
        let _ = write_frame(&mut stream, &RelayFrame::Unreachable).await;
        return Ok(());
    };

    // Парковка: Accept-обработчик передаст нам свой stream через этот канал.
    let (pair_tx, pair_rx) = oneshot::channel::<TcpStream>();
    inner.pending.lock().await.insert(session, pair_tx);

    // Уведомляем цель.
    if ctrl.send(RelayFrame::Incoming { session, from: from.clone() }).await.is_err() {
        inner.pending.lock().await.remove(&session);
        let _ = write_frame(&mut stream, &RelayFrame::Unreachable).await;
        return Ok(());
    }

    // Ждём встречное соединение.
    let mut peer = match timeout(PAIR_TIMEOUT, pair_rx).await {
        Ok(Ok(s)) => s,
        _ => {
            inner.pending.lock().await.remove(&session);
            debug!("Relay: session {} pairing timed out", session);
            let _ = write_frame(&mut stream, &RelayFrame::Unreachable).await;
            return Ok(());
        }
    };

    // Обе стороны готовы — сигналим и переходим в режим перекачки.
    write_frame(&mut stream, &RelayFrame::Ready).await?;
    write_frame(&mut peer, &RelayFrame::Ready).await?;
    debug!("Relay: piping session {} ({} ↔ {})", session, from, to);
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut peer).await;
    debug!("Relay: session {} closed", session);
    Ok(())
}

/// data-соединение принимающего: отдаём свой stream ожидающему Open-обработчику.
async fn serve_accept(
    stream: TcpStream,
    session: u64,
    inner: Arc<RelayInner>,
) -> io::Result<()> {
    let pair_tx = inner.pending.lock().await.remove(&session);
    match pair_tx {
        Some(tx) => {
            // Передаём stream инициатору; перекачку ведёт его обработчик.
            let _ = tx.send(stream);
            Ok(())
        }
        None => {
            debug!("Relay: Accept for unknown session {}", session);
            Ok(())
        }
    }
}

// ─── Клиент ─────────────────────────────────────────────────────────────────────

/// Открывает туннель до `to` через relay по адресу `relay_addr`
/// (`host:relay_port`). Возвращает поток, по которому уже можно гнать прикладной
/// протокол (relay перекачивает байты на встречную сторону).
pub async fn open_tunnel(
    relay_addr: &str,
    from: &NodeId,
    to: &NodeId,
) -> io::Result<TcpStream> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(relay_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay connect timeout"))??;

    let session = rand::random::<u64>();
    write_frame(&mut stream, &RelayFrame::Open {
        session,
        from: from.clone(),
        to: to.clone(),
    }).await?;

    match timeout(PAIR_TIMEOUT, read_frame(&mut stream)).await {
        Ok(Ok(RelayFrame::Ready)) => Ok(stream),
        Ok(Ok(RelayFrame::Unreachable)) => {
            Err(io::Error::new(io::ErrorKind::NotConnected, "peer unreachable via relay"))
        }
        Ok(Ok(other)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected relay reply: {:?}", other),
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "relay pairing timeout")),
    }
}

/// Принимает встречное data-соединение по `session` (после `Incoming`): дозвон до
/// relay, кадр `Accept`, ожидание `Ready`. Возвращает поток для прикладного
/// протокола (как будто это входящее прямое соединение).
pub async fn accept_tunnel(relay_addr: &str, session: u64) -> io::Result<TcpStream> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(relay_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay connect timeout"))??;

    write_frame(&mut stream, &RelayFrame::Accept { session }).await?;

    match timeout(PAIR_TIMEOUT, read_frame(&mut stream)).await {
        Ok(Ok(RelayFrame::Ready)) => Ok(stream),
        Ok(Ok(other)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected relay reply: {:?}", other),
        )),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "relay accept timeout")),
    }
}

/// Поддерживает контрольное соединение с relay: регистрирует `my_id`, и для
/// каждого `Incoming` открывает встречный туннель, отправляя `(stream, from)` в
/// возвращаемый канал. Бесконечно переподключается с backoff. Неблокирующий.
///
/// `relay_addr` — `host:relay_port`. Потребитель канала должен скормить каждый
/// поток своему серверу прикладного протокола (например, DM-accept).
pub fn start_relay_client(
    relay_addr: String,
    my_id: NodeId,
) -> mpsc::Receiver<(TcpStream, NodeId)> {
    let (accepted_tx, accepted_rx) = mpsc::channel::<(TcpStream, NodeId)>(16);
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_control_once(&relay_addr, &my_id, &accepted_tx).await {
                debug!("Relay control {} dropped: {}", relay_addr, e);
            }
            if accepted_tx.is_closed() {
                break; // потребитель ушёл — прекращаем
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    });
    accepted_rx
}

/// Одна сессия контрольного соединения: регистрация + чтение `Incoming` до разрыва.
async fn run_control_once(
    relay_addr: &str,
    my_id: &NodeId,
    accepted_tx: &mpsc::Sender<(TcpStream, NodeId)>,
) -> io::Result<()> {
    let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(relay_addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay connect timeout"))??;
    write_frame(&mut stream, &RelayFrame::Register { node_id: my_id.clone() }).await?;
    info!("Relay: registered on {}", relay_addr);

    loop {
        match read_frame(&mut stream).await? {
            RelayFrame::Incoming { session, from } => {
                debug!("Relay: incoming tunnel from {} (session {})", from, session);
                let addr = relay_addr.to_string();
                let tx = accepted_tx.clone();
                tokio::spawn(async move {
                    match accept_tunnel(&addr, session).await {
                        Ok(s) => { let _ = tx.send((s, from)).await; }
                        Err(e) => debug!("Relay: accept_tunnel failed: {}", e),
                    }
                });
            }
            RelayFrame::Ping => { write_frame(&mut stream, &RelayFrame::Pong).await?; }
            _ => {}
        }
    }
}

// ─── Сериализация (length-prefixed JSON) ────────────────────────────────────────

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, frame: &RelayFrame) -> io::Result<()> {
    let json = serde_json::to_vec(frame).map_err(to_io)?;
    if json.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    w.write_all(&(json.len() as u32).to_be_bytes()).await?;
    w.write_all(&json).await?;
    w.flush().await
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<RelayFrame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(to_io)
}

fn to_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

// ─── Тесты ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    fn nid(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&[seed; 32])
    }

    #[test]
    fn service_addr_applies_offset() {
        assert_eq!(service_addr("1.2.3.4:7700").unwrap(), "1.2.3.4:7706");
        assert!(service_addr("no-port").is_err());
    }

    #[test]
    fn frame_serde_roundtrip_and_unknown() {
        let f = RelayFrame::Open { session: 42, from: nid(1), to: nid(2) };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<RelayFrame>(&json).unwrap(), f);

        let unknown: RelayFrame =
            serde_json::from_str(r#"{"kind":"from_the_future"}"#).unwrap();
        assert_eq!(unknown, RelayFrame::Unknown);
    }

    /// Полный путь: B регистрируется, A открывает туннель, relay перекачивает
    /// байты в обе стороны.
    #[tokio::test]
    async fn tunnel_pipes_bytes_both_ways() {
        let port = free_port();
        start_relay_server(port).await.unwrap();
        let relay = format!("127.0.0.1:{port}");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // B держит контрольное соединение и принимает встречные туннели.
        let mut b_rx = start_relay_client(relay.clone(), nid(2));
        tokio::time::sleep(Duration::from_millis(200)).await;

        // A открывает туннель к B.
        let mut a = open_tunnel(&relay, &nid(1), &nid(2)).await.expect("open_tunnel");

        // B получает свою сторону туннеля.
        let (mut b, from) = timeout(Duration::from_secs(3), b_rx.recv())
            .await.expect("timeout").expect("channel closed");
        assert_eq!(from, nid(1), "B видит, что инициатор — A");

        // A → B
        a.write_all(b"hello-B").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 7];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-B");

        // B → A
        b.write_all(b"hi-A!!!").await.unwrap();
        b.flush().await.unwrap();
        let mut buf2 = [0u8; 7];
        a.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hi-A!!!");
    }

    /// Цель не зарегистрирована → инициатор получает Unreachable (ошибку).
    #[tokio::test]
    async fn open_to_unregistered_is_unreachable() {
        let port = free_port();
        start_relay_server(port).await.unwrap();
        let relay = format!("127.0.0.1:{port}");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let err = open_tunnel(&relay, &nid(1), &nid(9)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    /// Несколько туннелей к одному и тому же узлу не мешают друг другу.
    #[tokio::test]
    async fn concurrent_sessions_are_independent() {
        let port = free_port();
        start_relay_server(port).await.unwrap();
        let relay = format!("127.0.0.1:{port}");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut b_rx = start_relay_client(relay.clone(), nid(2));
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut a1 = open_tunnel(&relay, &nid(1), &nid(2)).await.unwrap();
        let (mut b1, _) = timeout(Duration::from_secs(3), b_rx.recv()).await.unwrap().unwrap();
        let mut a2 = open_tunnel(&relay, &nid(3), &nid(2)).await.unwrap();
        let (mut b2, _) = timeout(Duration::from_secs(3), b_rx.recv()).await.unwrap().unwrap();

        a1.write_all(b"one").await.unwrap(); a1.flush().await.unwrap();
        a2.write_all(b"two").await.unwrap(); a2.flush().await.unwrap();

        let mut x = [0u8; 3]; b1.read_exact(&mut x).await.unwrap();
        let mut y = [0u8; 3]; b2.read_exact(&mut y).await.unwrap();
        assert_eq!(&x, b"one");
        assert_eq!(&y, b"two");
    }
}
