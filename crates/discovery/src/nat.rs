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
use std::time::Duration;

use igd_next::aio::tokio::search_gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use tracing::{info, warn};

/// Срок аренды проброса (сек). По истечении роутер сам снимет правило, если
/// узел не продлит — защищает от «протухших» проброшенных портов.
const LEASE_SECS: u32 = 3600;

/// Таймаут поиска UPnP-шлюза. По умолчанию igd ждёт 10с; укорачиваем — если
/// роутера с IGD нет (или SSDP заблокирован), нет смысла ждать так долго.
const GATEWAY_SEARCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Пробрасывает набор портов узла через UPnP. Шлюз ищется ОДИН раз и
/// переиспользуется для всех портов. Возвращает внешний IP, если удался хотя бы
/// один проброс (для информирования оператора о публичном адресе).
pub async fn map_ports(local_ip: IpAddr, ports: &[u16], description: &str) -> Option<IpAddr> {
    // На loopback/неопределённом адресе проброс бессмысленен.
    if local_ip.is_loopback() || local_ip.is_unspecified() {
        return None;
    }

    // Ищем UPnP-шлюз ОДИН раз (а не на каждый порт) с укороченным таймаутом.
    let opts = SearchOptions {
        timeout: Some(GATEWAY_SEARCH_TIMEOUT),
        ..Default::default()
    };
    let gateway = match search_gateway(opts).await {
        Ok(g) => g,
        Err(e) => {
            warn!("UPnP: шлюз не найден ({}) — проброс портов пропущен, узел работает без него", e);
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

    let mut mapped = 0usize;
    for &port in ports {
        let local = SocketAddr::new(local_ip, port);
        match gateway
            .add_port(PortMappingProtocol::TCP, port, local, LEASE_SECS, description)
            .await
        {
            Ok(()) => {
                mapped += 1;
                info!("UPnP: порт {} проброшен (внешний {}:{})", port, external_ip, port);
            }
            Err(e) => warn!("UPnP: не удалось пробросить порт {}: {}", port, e),
        }
    }

    (mapped > 0).then_some(external_ip)
}

/// Пробрасывает один порт через UPnP (обёртка над [`map_ports`]). Возвращает
/// внешний IP роутера при успехе.
pub async fn try_map_port(local_ip: IpAddr, port: u16, description: &str) -> Option<IpAddr> {
    map_ports(local_ip, &[port], description).await
}
