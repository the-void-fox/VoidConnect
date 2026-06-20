//! NAT traversal — автоматический проброс портов через UPnP/IGD.
//!
//! Домашний роутер прячет устройства за одним внешним IP. Чтобы bootstrap-узел
//! был доступен извне, программа просит роутер открыть порт (как это делают
//! торрент-клиенты). Работает на большинстве домашних роутеров с включённым
//! UPnP; если UPnP недоступен — это не ошибка, просто проброс пропускается
//! (порт можно открыть вручную).
//!
//! Это best-effort: любая ошибка (нет шлюза, UPnP выключен) → `None`, узел
//! продолжает работать в LAN-режиме.

use std::net::{IpAddr, SocketAddr};

use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use tracing::{info, warn};

/// Срок аренды проброса (сек). По истечении роутер сам снимет правило, если
/// узел не продлит — защищает от «протухших» проброшенных портов.
const LEASE_SECS: u32 = 3600;

/// Пытается пробросить TCP-порт `port` на роутере через UPnP/IGD.
///
/// `local_ip` — наш LAN-адрес (внутренний клиент проброса). Возвращает внешний
/// IP роутера при успехе, иначе `None` (нет UPnP / нет шлюза / loopback).
pub async fn try_map_port(local_ip: IpAddr, port: u16, description: &str) -> Option<IpAddr> {
    // На loopback/неопределённом адресе проброс бессмысленен.
    if local_ip.is_loopback() || local_ip.is_unspecified() {
        return None;
    }

    let gateway = match search_gateway(SearchOptions::default()).await {
        Ok(g) => g,
        Err(e) => {
            warn!("UPnP: шлюз не найден ({}), проброс порта {} пропущен", e, port);
            return None;
        }
    };

    let external_ip = match gateway.get_external_ip().await {
        Ok(ip) => ip,
        Err(e) => {
            warn!("UPnP: внешний IP недоступен: {}", e);
            return None;
        }
    };

    let local = SocketAddr::new(local_ip, port);
    match gateway
        .add_port(PortMappingProtocol::TCP, port, local, LEASE_SECS, description)
        .await
    {
        Ok(()) => {
            info!("UPnP: порт {} проброшен (внешний {}:{})", port, external_ip, port);
            Some(external_ip)
        }
        Err(e) => {
            warn!("UPnP: не удалось пробросить порт {}: {}", port, e);
            None
        }
    }
}

/// Пробрасывает набор портов узла. Возвращает внешний IP, если хотя бы один
/// проброс удался (для информирования оператора о публичном адресе).
pub async fn map_ports(local_ip: IpAddr, ports: &[u16], description: &str) -> Option<IpAddr> {
    let mut external = None;
    for &port in ports {
        if let Some(ip) = try_map_port(local_ip, port, description).await {
            external = Some(ip);
        }
    }
    external
}
