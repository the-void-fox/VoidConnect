pub mod connection;
pub mod error;
pub mod rate_limit;
pub mod router;
pub mod transport;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::info;

use void_core::identity::NodeId;

use crate::connection::ConnectionManager;
use crate::rate_limit::RateLimiter;
use crate::router::Router;

/// Размер буфера канала событий между ConnectionManager и Router
const EVENT_BUFFER: usize = 1024;

/// Точка входа — создаёт и связывает все компоненты сетевого слоя.
///
/// Возвращает `Router` — основной интерфейс для остальных крейтов.
///
/// # Пример
/// ```rust
/// let router = network::start(local_id, 7777).await?;
///
/// // Подписка на сообщения чата
/// let mut chat_rx = router.subscribe(MessageKind::Chat, 256).await;
///
/// // Отправка сообщения
/// router.broadcast(NetworkMessage::ChatMessage { ... }).await;
/// ```
pub async fn start(
    local_id: NodeId,
    tcp_port: u16,
) -> Result<Arc<Router>, error::NetworkError> {
    let rate_limiter = Arc::new(RateLimiter::new());

    let (event_tx, event_rx) = mpsc::channel(EVENT_BUFFER);

    let conn_manager = Arc::new(ConnectionManager::new(
        local_id.clone(),
        rate_limiter.clone(),
        event_tx,
    ));

    // Запускаем TCP-сервер
    conn_manager.listen(tcp_port).await?;

    info!(
        "Network layer started. Node: {}, TCP port: {}",
        local_id, tcp_port
    );

    let router = Arc::new(Router::new(conn_manager.clone(), event_rx));

    Ok(router)
}