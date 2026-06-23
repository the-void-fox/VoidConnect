//! # void-network
//!
//! ВНИМАНИЕ: бóльшая часть этого крейта — экспериментальный сетевой слой,
//! который НЕ подключён к работающему приложению. В живой сборке используются
//! только:
//!   - [`rate_limit::RateLimiter`] — общий лимитер (chat, reputation);
//!   - типы [`router`] — на них ссылается (тоже не подключённый) Router-путь
//!     репутации `void_reputation::start`.
//!
//! Реальная сеть реализована напрямую в других крейтах:
//!   - чат и личные сообщения — `void-chat` (свой length-prefixed JSON поверх TCP);
//!   - bootstrap и relay — `void-discovery` (свой протокол, не этот транспорт).
//!
//! Поэтому [`start`], [`connection::ConnectionManager`] и `transport`
//! (TCP/WebSocket) сейчас НИКЕМ не вызываются. Слой оставлен как заготовка;
//! не считайте его действующим и перед использованием убедитесь, что он
//! подключён к точке входа.

pub mod connection;
pub mod error;
pub mod rate_limit;
pub mod router;
pub mod transport;

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::info;

use void_core::peer::PeerInfo;
use void_discovery::PeerList;

use crate::connection::ConnectionManager;
use crate::rate_limit::RateLimiter;
use crate::router::Router;

const EVENT_BUFFER: usize = 1024;

/// Точка входа экспериментального сетевого слоя — создаёт и связывает Router,
/// ConnectionManager и транспорт.
///
/// НЕ ИСПОЛЬЗУЕТСЯ работающим приложением (см. доки крейта). Оставлено как
/// заготовка. Живая сеть — в `void-chat` и `void-discovery`.
///
/// `my_peer` — полные данные о локальном узле (используются в handshake).
/// `peer_list` — разделяемый список из крейта discovery; Router будет его обновлять.
///
/// # Пример
/// ```ignore
/// let peer_list = PeerList::new();
/// let router = network::start(my_peer, peer_list.clone(), 7777).await?;
/// ```
pub async fn start(
    my_peer: PeerInfo,
    peer_list: PeerList,
    tcp_port: u16,
) -> Result<Arc<Router>, error::NetworkError> {
    let rate_limiter = Arc::new(RateLimiter::new());
    let (event_tx, event_rx) = mpsc::channel(EVENT_BUFFER);

    let conn_manager = Arc::new(ConnectionManager::new(
        my_peer.clone(),
        rate_limiter.clone(),
        event_tx,
    ));

    conn_manager.listen(tcp_port).await?;

    info!(
        "Network layer started. Node: {}, TCP port: {}",
        my_peer.id, tcp_port
    );

    let router = Arc::new(Router::new(conn_manager, peer_list, event_rx));

    Ok(router)
}