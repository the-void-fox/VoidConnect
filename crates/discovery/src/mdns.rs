//! mDNS обнаружение узлов в локальной сети.
//!
//! Каждый узел одновременно:
//! 1. Регистрирует себя — чтобы другие его нашли
//! 2. Слушает объявления других узлов
//!
//! Используем библиотеку `mdns-sd`.

use crate::{DiscoveryError, PeerList};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{debug, error, info, warn};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, Service};

/// Имя сервиса в mDNS. Все узлы Void Connect регистрируются под этим именем.
/// Формат: _<protocol>._<transport>.local.
const SERVICE_TYPE: &str = "_void-connect._tcp.local.";

/// Версия протокола — чтобы разные версии не мешали друг другу
const PROTOCOL_VERSION: &str = "1";

/// Запускает mDNS: регистрирует текущий узел и начинает слушать сеть.
///
/// # Аргументы
/// - `my_peer` — информация о текущем узле (наш ID, имя, порт)
/// - `peer_list` — разделяемый список узлов, куда добавляем найденных
///
/// Функция запускает два асинхронных таска и возвращает управление.
/// Таски живут до конца программы.
pub async fn start_mdns(
    my_peer: PeerInfo,
    peer_list: PeerList,
) -> Result<(), DiscoveryError> {
    // ServiceDaemon — основной объект mdns-sd.
    // Он работает в фоновом потоке и управляет mDNS multicast.
    let mdns = ServiceDaemon::new()
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    // Регистрируем себя в сети
    register_self(&mdns, &my_peer)?;

    // Запускаем прослушивание в отдельном таске Tokio
    let peer_list_clone = peer_list.clone();
    let mdns_clone = mdns.clone();
    tokio::spawn(async move {
        if let Err(e) = listen_for_peers(mdns_clone, peer_list_clone).await {
            error!("mDNS listener error: {}", e);
        }
    });

    // Периодически чистим "мёртвые" узлы
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(30)
        );
        loop {
            interval.tick().await;
            peer_list.prune_stale().await;
            debug!("Pruned stale peers. Active: {}", peer_list.len().await);
        }
    });

    info!(
        "mDNS started. Node: {} ({}:{})",
        my_peer.name, my_peer.ip, my_peer.port
    );

    Ok(())
}

/// Регистрирует текущий узел в mDNS, чтобы другие его нашли.
fn register_self(
    mdns: &ServiceDaemon,
    peer: &PeerInfo,
) -> Result<(), DiscoveryError> {
    // TXT-записи — метаданные сервиса.
    // Другие узлы прочитают их при обнаружении.
    let mut properties = HashMap::new();
    properties.insert("id".to_string(), peer.id.as_str().to_string());
    properties.insert("name".to_string(), peer.name.clone());
    properties.insert("version".to_string(), PROTOCOL_VERSION.to_string());

    // Список сервисов — через запятую
    let services_str: Vec<&str> = peer
        .services
        .iter()
        .map(|s| match s {
            Service::Chat => "chat",
            Service::Storage => "storage",
            Service::Web => "web",
            Service::Bootstrap => "bootstrap",
        })
        .collect();
    properties.insert("services".to_string(), services_str.join(","));

    // Имя инстанса должно быть уникальным в сети.
    // Используем первые 8 символов ID — коллизия маловероятна.
    let instance_name = format!(
        "void-{}", 
        &peer.id.as_str()[..peer.id.as_str().len().min(8)]
    );

    let ip_str = peer.ip.to_string();
    let ip_list: Vec<&str> = vec![&ip_str];

    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &format!("{}.local.", instance_name),
        ip_list.as_slice(),
        peer.port,
        Some(properties),
    )
    .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    mdns.register(service_info)
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    info!("Registered in mDNS as '{}'", instance_name);
    Ok(())
}

/// Слушает mDNS-события и обновляет peer list.
///
/// События бывают трёх типов:
/// - `ServiceResolved` — нашли новый узел
/// - `ServiceRemoved` — узел ушёл из сети
/// - остальные — служебные, игнорируем
async fn listen_for_peers(
    mdns: ServiceDaemon,
    peer_list: PeerList,
) -> Result<(), DiscoveryError> {
    // Подписываемся на события для нашего типа сервиса
    let receiver = mdns
        .browse(SERVICE_TYPE)
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    info!("Listening for peers via mDNS...");

    // mdns-sd использует std::sync::mpsc, поэтому блокирующий recv
    // запускаем в spawn_blocking, чтобы не блокировать async runtime
    loop {
        let event = tokio::task::spawn_blocking({
            let receiver = receiver.clone();
            move || receiver.recv()
        })
        .await
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        match event {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                handle_resolved(&peer_list, info).await;
            }
            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                handle_removed(&peer_list, &fullname).await;
            }
            Ok(_) => {
                // SearchStarted, SearchStopped — не интересны
            }
            Err(e) => {
                warn!("mDNS receive error: {:?}", e);
                // Не прерываем цикл — временные ошибки случаются
            }
        }
    }
}

/// Обрабатываем найденный узел: парсим TXT-записи и добавляем в peer list.
async fn handle_resolved(peer_list: &PeerList, info: mdns_sd::ServiceInfo) {
    // Получаем IP-адреса из записи
    let addresses: Vec<IpAddr> = info.get_addresses().iter().cloned().collect();
    let ip = match addresses.first() {
        Some(ip) => *ip,
        None => {
            warn!("Peer '{}' has no IP address, skipping", info.get_fullname());
            return;
        }
    };

    // Читаем TXT-свойства
    let props = info.get_properties();

    let id_str = match props.get("id") {
        Some(id) => id.val_str().to_string(),
        None => {
            warn!("Peer '{}' has no 'id' property, skipping", info.get_fullname());
            return;
        }
    };

    // Проверяем версию протокола
    let version = props
        .get("version")
        .map(|v| v.val_str().to_string())
        .unwrap_or_default();
    if version != PROTOCOL_VERSION {
        warn!(
            "Peer '{}' uses protocol v{}, we need v{}. Skipping.",
            info.get_fullname(), version, PROTOCOL_VERSION
        );
        return;
    }

    let name = props
        .get("name")
        .map(|v| v.val_str().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let services = parse_services(
        props.get("services").map(|v| v.val_str()).unwrap_or("")
    );

    let peer = PeerInfo {
        id: NodeId(id_str.clone()),
        name: name.clone(),
        ip,
        port: info.get_port(),
        services,
        last_seen: chrono::Utc::now().timestamp(),
    };

    info!("Discovered peer: {} ({}) at {}", name, &id_str[..8.min(id_str.len())], ip);
    peer_list.upsert(peer).await;
}

/// Обрабатываем уход узла из сети.
/// fullname имеет формат "void-abc12345._void-connect._tcp.local."
async fn handle_removed(peer_list: &PeerList, fullname: &str) {
    // Ищем узел по полному имени — сравниваем с адресами в peer list
    // Проще всего найти через полный список и сравнить по имени
    let peers = peer_list.all().await;
    for peer in peers {
        let instance = format!(
            "void-{}._void-connect._tcp.local.",
            &peer.id.as_str()[..peer.id.as_str().len().min(8)]
        );
        if instance == fullname {
            info!("Peer left: {} ({})", peer.name, peer.id);
            peer_list.remove(&peer.id).await;
            return;
        }
    }
    debug!("Received remove for unknown peer: {}", fullname);
}

/// Разбираем строку сервисов "chat,storage,web" в Vec<Service>
fn parse_services(s: &str) -> Vec<Service> {
    s.split(',')
        .filter_map(|part| match part.trim() {
            "chat" => Some(Service::Chat),
            "storage" => Some(Service::Storage),
            "web" => Some(Service::Web),
            "bootstrap" => Some(Service::Bootstrap),
            "" => None,
            unknown => {
                debug!("Unknown service type: '{}'", unknown);
                None
            }
        })
        .collect()
}