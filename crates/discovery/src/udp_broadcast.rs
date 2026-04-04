//! UDP broadcast — резервный метод обнаружения узлов.
//!
//! Используется когда mDNS заблокирован администратором роутера.
//! Каждый узел:
//! 1. Каждые N секунд рассылает UDP-пакет на 255.255.255.255
//! 2. Слушает входящие broadcast-пакеты от других узлов
//!
//! Формат пакета: JSON с PeerInfo

use crate::{DiscoveryError, PeerList};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use tracing::{debug, error, info, warn};
use void_core::peer::PeerInfo;
use std::sync::Arc;


/// Порт для UDP broadcast. Должен совпадать на всех узлах.
const BROADCAST_PORT: u16 = 7701;

/// Интервал между рассылками (секунды)
const BROADCAST_INTERVAL_SECS: u64 = 10;

/// Запускает UDP broadcast: периодическую рассылку и прослушивание.
pub async fn start_udp_broadcast(
    my_peer: PeerInfo,
    peer_list: PeerList,
) -> Result<(), DiscoveryError> {
    // Запускаем отправку в фоне
    let my_peer_clone = my_peer.clone();
    tokio::spawn(async move {
        if let Err(e) = broadcast_loop(my_peer_clone).await {
            error!("UDP broadcast sender error: {}", e);
        }
    });

    // Запускаем приём в фоне
    tokio::spawn(async move {
        if let Err(e) = listen_loop(peer_list).await {
            error!("UDP broadcast listener error: {}", e);
        }
    });

    info!("UDP broadcast started on port {}", BROADCAST_PORT);
    Ok(())
}

/// Каждые BROADCAST_INTERVAL_SECS отправляем свои данные в сеть
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

        // Клонируем Arc для каждой итерации
        let socket_clone = Arc::clone(&socket);
        let payload_clone = payload.clone();
        
        let result = tokio::task::spawn_blocking(move || {
            socket_clone.send_to(&payload_clone, broadcast_addr)
        })
        .await;

        match result {
            Ok(Ok(bytes)) => debug!("Broadcast sent ({} bytes)", bytes),
            Ok(Err(e)) => warn!("Broadcast send error: {}", e),
            Err(e) => warn!("spawn_blocking error: {}", e),
        }
    }
}

/// Слушаем входящие broadcast-пакеты и добавляем узлы в peer list
async fn listen_loop(peer_list: PeerList) -> Result<(), DiscoveryError> {
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", BROADCAST_PORT))?;
    socket.set_broadcast(true)?;

    info!("UDP broadcast listener on 0.0.0.0:{}", BROADCAST_PORT);

    loop {
        // recv_from — блокирующий, используем spawn_blocking
        let socket_clone = socket.try_clone()?;
        let result = tokio::task::spawn_blocking(move || {
            let mut buf = [0u8; 4096];
            socket_clone.recv_from(&mut buf).map(|(n, addr)| (buf, n, addr))
        })
        .await;

        match result {
            Ok(Ok((data, n, from_addr))) => {
                match serde_json::from_slice::<PeerInfo>(&data[..n]) {
                    Ok(mut peer) => {
                        // Обновляем IP из реального адреса источника пакета
                        // (на случай если узел не знает свой внешний IP)
                        peer.ip = from_addr.ip();
                        peer.last_seen = chrono::Utc::now().timestamp();

                        debug!("UDP broadcast from: {} ({})", peer.name, from_addr);
                        peer_list.upsert(peer).await;
                    }
                    Err(e) => {
                        warn!("Failed to parse broadcast from {}: {}", from_addr, e);
                    }
                }
            }
            Ok(Err(e)) => warn!("UDP recv error: {}", e),
            Err(e) => warn!("spawn_blocking error: {}", e),
        }
    }
}