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

const SERVICE_TYPE: &str = "_void-connect._tcp.local.";
const PROTOCOL_VERSION: &str = "1";

pub async fn start_mdns(
    my_peer: PeerInfo,
    peer_list: PeerList,
) -> Result<(), DiscoveryError> {
    let mdns = ServiceDaemon::new()
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    register_self(&mdns, &my_peer)?;

    let my_id = my_peer.id.clone();
    let peer_list_clone = peer_list.clone();
    let mdns_clone = mdns.clone();
    tokio::spawn(async move {
        if let Err(e) = listen_for_peers(mdns_clone, peer_list_clone, my_id).await {
            error!("mDNS listener error: {}", e);
        }
    });

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            peer_list.prune_stale().await;
            debug!("Pruned stale peers. Active: {}", peer_list.len().await);
        }
    });

    info!("mDNS started. Node: {} ({}:{})", my_peer.name, my_peer.ip, my_peer.port);
    Ok(())
}

fn register_self(mdns: &ServiceDaemon, peer: &PeerInfo) -> Result<(), DiscoveryError> {
    let mut properties = HashMap::new();
    properties.insert("id".to_string(), peer.id.as_str().to_string());
    properties.insert("name".to_string(), peer.name.clone());
    properties.insert("version".to_string(), PROTOCOL_VERSION.to_string());
    // Передаём chat_port явно — получатель не должен угадывать его сам
    properties.insert("chat_port".to_string(), peer.chat_port.to_string());

    let services_str: Vec<&str> = peer.services.iter().map(|s| match s {
        Service::Chat      => "chat",
        Service::Storage   => "storage",
        Service::Web       => "web",
        Service::Bootstrap => "bootstrap",
    }).collect();
    properties.insert("services".to_string(), services_str.join(","));

    let instance_name = format!("void-{}", &peer.id.as_str()[..peer.id.as_str().len().min(8)]);

    let ip_str = peer.ip.to_string();
    let ip_list: Vec<&str> = vec![&ip_str];

    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &format!("{}.local.", instance_name),
        ip_list.as_slice(),
        peer.port,
        Some(properties),
    ).map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    mdns.register(service_info)
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    info!("Registered in mDNS as '{}' (chat_port={})", instance_name, peer.chat_port);
    Ok(())
}

async fn listen_for_peers(mdns: ServiceDaemon, peer_list: PeerList, my_id: NodeId) -> Result<(), DiscoveryError> {
    let receiver = mdns
        .browse(SERVICE_TYPE)
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

    info!("Listening for peers via mDNS...");

    loop {
        let event = tokio::task::spawn_blocking({
            let receiver = receiver.clone();
            move || receiver.recv()
        })
        .await
        .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;

        match event {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                handle_resolved(&peer_list, info, &my_id).await;
            }
            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                handle_removed(&peer_list, &fullname).await;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("mDNS receive error: {:?}", e);
            }
        }
    }
}

async fn handle_resolved(peer_list: &PeerList, info: mdns_sd::ServiceInfo, my_id: &NodeId) {
    let addresses: Vec<IpAddr> = info.get_addresses().iter().cloned().collect();
    let ip = match addresses.first() {
        Some(ip) => *ip,
        None => {
            warn!("Peer '{}' has no IP address, skipping", info.get_fullname());
            return;
        }
    };

    let props = info.get_properties();

    let id_str = match props.get("id") {
        Some(id) => id.val_str().to_string(),
        None => {
            warn!("Peer '{}' has no 'id' property, skipping", info.get_fullname());
            return;
        }
    };

    if id_str == my_id.as_str() {
        debug!("mDNS: ignoring own announcement");
        return;
    }

    let version = props.get("version").map(|v| v.val_str().to_string()).unwrap_or_default();
    if version != PROTOCOL_VERSION {
        warn!(
            "Peer '{}' uses protocol v{}, we need v{}. Skipping.",
            info.get_fullname(), version, PROTOCOL_VERSION
        );
        return;
    }

    let name = props.get("name")
        .map(|v| v.val_str().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    // Читаем chat_port из TXT; если нет — fallback: основной порт + 2
    let chat_port = props.get("chat_port")
        .and_then(|v| v.val_str().parse::<u16>().ok())
        .unwrap_or_else(|| info.get_port() + 2);

    let services = parse_services(props.get("services").map(|v| v.val_str()).unwrap_or(""));

    let peer = PeerInfo {
        id: NodeId(id_str.clone()),
        name: name.clone(),
        ip,
        port: info.get_port(),
        chat_port,
        services,
        last_seen: chrono::Utc::now().timestamp(),
    };

    info!(
        "Discovered peer: {} ({}) at {} chat_port={}",
        name, &id_str[..8.min(id_str.len())], ip, chat_port
    );
    peer_list.upsert(peer).await;
}

async fn handle_removed(peer_list: &PeerList, fullname: &str) {
    let peers = peer_list.all().await;
    for peer in peers {
        let instance = format!(
            "void-{}._void-connect._tcp.local.",
            &peer.id.as_str()[..peer.id.as_str().len().min(8)]
        );
        if instance == fullname {
            info!("mDNS: peer left — {} ({}) at {}", peer.name, peer.id, peer.ip);
            peer_list.remove(&peer.id).await;
            return;
        }
    }
    debug!("mDNS: received remove for unknown peer: {}", fullname);
}

fn parse_services(s: &str) -> Vec<Service> {
    s.split(',').filter_map(|part| match part.trim() {
        "chat"      => Some(Service::Chat),
        "storage"   => Some(Service::Storage),
        "web"       => Some(Service::Web),
        "bootstrap" => Some(Service::Bootstrap),
        ""          => None,
        unknown     => { debug!("Unknown service type: '{}'", unknown); None }
    }).collect()
}