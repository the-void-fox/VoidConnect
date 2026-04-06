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

/// Точка входа — создаёт и связывает все компоненты сетевого слоя.
///
/// `my_peer` — полные данные о локальном узле (используются в handshake).
/// `peer_list` — разделяемый список из крейта discovery; Router будет его обновлять.
///
/// # Пример
/// ```rust
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