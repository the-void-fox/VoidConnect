//! Локальное обнаружение через временные файлы — для тестов на одном устройстве.
//!
//! Каждый экземпляр пишет свой PeerInfo в /tmp/void-connect/PORT.json
//! и периодически сканирует директорию, подхватывая соседей.
//! Файл считается устаревшим, если last_seen > 30 секунд назад.

use crate::PeerList;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use void_core::identity::NodeId;
use void_core::peer::PeerInfo;

const DIR: &str = "/tmp/void-connect";
const TTL_SECS: i64 = 30;
const ANNOUNCE_INTERVAL_SECS: u64 = 5;
const SCAN_INTERVAL_SECS: u64 = 3;

fn dir() -> PathBuf {
    Path::new(DIR).to_path_buf()
}

fn my_file(base_port: u16) -> PathBuf {
    dir().join(format!("{}.json", base_port))
}

pub async fn start_local_discovery(
    my_peer: PeerInfo,
    peer_list: PeerList,
    base_port: u16,
) {
    std::fs::create_dir_all(dir()).ok();

    // Announce own presence
    let peer_clone = my_peer.clone();
    tokio::spawn(async move {
        announce_loop(peer_clone, base_port).await;
    });

    // Scan for other instances
    let my_id = my_peer.id.clone();
    tokio::spawn(async move {
        scan_loop(peer_list, my_id).await;
    });

    info!("Local discovery started (dir={})", DIR);
}

async fn announce_loop(mut my_peer: PeerInfo, base_port: u16) {
    let path = my_file(base_port);
    let mut interval = tokio::time::interval(
        tokio::time::Duration::from_secs(ANNOUNCE_INTERVAL_SECS)
    );
    loop {
        interval.tick().await;
        my_peer.last_seen = chrono::Utc::now().timestamp();
        match serde_json::to_string(&my_peer) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, &json) {
                    warn!("Local discovery: write failed: {}", e);
                } else {
                    debug!("Local discovery: announced to {}", path.display());
                }
            }
            Err(e) => warn!("Local discovery: serialize failed: {}", e),
        }
    }
}

async fn scan_loop(peer_list: PeerList, my_id: NodeId) {
    let mut interval = tokio::time::interval(
        tokio::time::Duration::from_secs(SCAN_INTERVAL_SECS)
    );
    loop {
        interval.tick().await;
        let now = chrono::Utc::now().timestamp();

        let entries = match std::fs::read_dir(dir()) {
            Ok(e) => e,
            Err(e) => {
                warn!("Local discovery: cannot read dir {}: {}", DIR, e);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(ext) = path.extension() else { continue };
            if ext != "json" { continue; }

            let Ok(data) = std::fs::read_to_string(&path) else { continue };
            let Ok(mut peer) = serde_json::from_str::<PeerInfo>(&data) else {
                warn!("Local discovery: bad JSON in {}", path.display());
                continue;
            };

            if peer.id == my_id { continue; }

            let age = now - peer.last_seen;
            if age > TTL_SECS {
                debug!("Local discovery: stale file {} (age={}s), removing", path.display(), age);
                std::fs::remove_file(&path).ok();
                continue;
            }

            let already = peer_list.get(&peer.id).await.is_some();
            peer.ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            peer_list.upsert(peer.clone()).await;
            if !already {
                info!("Local discovery: found new peer {} (port={}, id={}...)",
                    peer.name, peer.port, &peer.id.as_str()[..8.min(peer.id.as_str().len())]);
            }
        }
    }
}

/// Удалить собственный файл при завершении (вызывается из Drop или shutdown).
pub fn cleanup(base_port: u16) {
    std::fs::remove_file(my_file(base_port)).ok();
}
