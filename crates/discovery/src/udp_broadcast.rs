//! UDP broadcast — резервный метод обнаружения узлов.
//!
//! Используется когда mDNS заблокирован администратором роутера.
//! Каждый узел:
//! 1. Каждые N секунд рассылает UDP-пакет на 255.255.255.255
//! 2. Слушает входящие broadcast-пакеты от других узлов
//!
//! При запуске нескольких экземпляров на одной машине listener
//! привязывается к base_port + 1, чтобы не конфликтовать.
//! В реальной сети все узлы используют одинаковый BROADCAST_PORT.

use crate::{DiscoveryError, PeerList};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use tracing::{debug, error, info, warn};
use void_core::identity::NodeId;
use void_core::peer::PeerInfo;
use std::sync::Arc;

/// Стандартный порт broadcast в реальной сети (одно устройство = один экземпляр)
const BROADCAST_PORT: u16 = 7701;

/// Интервал между рассылками (секунды)
const BROADCAST_INTERVAL_SECS: u64 = 5;

/// Запускает UDP broadcast.
///
/// `base_port` — основной порт узла. Listener привязывается к
/// `base_port + 1`, отправка всегда идёт на стандартный BROADCAST_PORT.
/// Это позволяет запустить два экземпляра на одной машине без конфликта.
pub async fn start_udp_broadcast(
    my_peer: PeerInfo,
    peer_list: PeerList,
    base_port: u16,
) -> Result<(), DiscoveryError> {
    let listen_port = base_port + 1;

    // Отправка
    let my_peer_clone = my_peer.clone();
    tokio::spawn(async move {
        if let Err(e) = broadcast_loop(my_peer_clone).await {
            error!("UDP broadcast sender error: {}", e);
        }
    });

    // Приём
    let my_id = my_peer.id.clone();
    tokio::spawn(async move {
        if let Err(e) = listen_loop(peer_list, listen_port, my_id).await {
            error!("UDP broadcast listener error: {}", e);
        }
    });

    info!("UDP broadcast started (sending to :{}, listening on :{})", BROADCAST_PORT, listen_port);
    Ok(())
}

async fn broadcast_loop(my_peer: PeerInfo) -> Result<(), DiscoveryError> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0")?);
    socket.set_broadcast(true)?;

    let broadcast_addr = SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::BROADCAST),
        BROADCAST_PORT,
    );

    let payload = serde_json::to_vec(&my_peer)
        .map_err(DiscoveryError::Serialization)?;

    let mut interval = tokio::time::interval(
        tokio::time::Duration::from_secs(BROADCAST_INTERVAL_SECS)
    );

    loop {
        interval.tick().await;

        let socket_clone = Arc::clone(&socket);
        let payload_clone = payload.clone();

        let result = tokio::task::spawn_blocking(move || {
            socket_clone.send_to(&payload_clone, broadcast_addr)
        }).await;

        match result {
            Ok(Ok(bytes)) => debug!("Broadcast sent ({} bytes)", bytes),
            Ok(Err(e))    => warn!("Broadcast send error: {}", e),
            Err(e)        => warn!("spawn_blocking error: {}", e),
        }
    }
}

async fn listen_loop(peer_list: PeerList, listen_port: u16, my_id: NodeId) -> Result<(), DiscoveryError> {
    let bind_addr = format!("0.0.0.0:{}", listen_port);
    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_broadcast(true)?;

    info!("UDP broadcast listener on {}", bind_addr);

    let socket = Arc::new(socket);

    loop {
        let socket_clone = Arc::clone(&socket);
        let result = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            socket_clone.recv_from(&mut buf).map(|(n, addr)| (buf, n, addr))
        }).await;

        match result {
            Ok(Ok((data, n, from_addr))) => {
                match serde_json::from_slice::<PeerInfo>(&data[..n]) {
                    Ok(mut peer) => {
                        if peer.id == my_id {
                            debug!("UDP broadcast: ignoring own packet from {}", from_addr);
                            continue;
                        }
                        let already = peer_list.get(&peer.id).await.is_some();
                        peer.ip = from_addr.ip();
                        peer.last_seen = chrono::Utc::now().timestamp();
                        peer_list.upsert(peer.clone()).await;
                        if !already {
                            info!("UDP broadcast: discovered new peer {} at {} (chat_port={})",
                                peer.name, from_addr.ip(), peer.chat_port);
                        } else {
                            debug!("UDP broadcast: heartbeat from {} ({})", peer.name, from_addr);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse UDP broadcast from {}: {}", from_addr, e);
                    }
                }
            }
            Ok(Err(e)) => warn!("UDP recv error: {}", e),
            Err(e)     => warn!("spawn_blocking error: {}", e),
        }
    }
}