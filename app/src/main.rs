use std::net::IpAddr;
use std::time::Duration;
use tracing::info;
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, Service};
use void_discovery::{
    mdns::start_mdns,
    udp_broadcast::start_udp_broadcast,
    PeerList,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("void_connect=info".parse()?)
                .add_directive("void_discovery=debug".parse()?),
        )
        .init();

    info!("Starting Void Connect...");

    let my_id = generate_temp_id();
    let my_ip = get_local_ip().unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let my_port = 7700u16;

    let my_peer = PeerInfo {
        id: my_id.clone(),
        name: "Vasya".to_string(),
        ip: my_ip,
        port: my_port,
        services: vec![Service::Chat, Service::Storage],
        last_seen: chrono::Utc::now().timestamp(),
    };

    info!("My node ID: {}", my_id);
    info!("Listening on {}:{}", my_ip, my_port);

    let peer_list = PeerList::new();

    start_mdns(my_peer.clone(), peer_list.clone()).await?;
    start_udp_broadcast(my_peer.clone(), peer_list.clone()).await?;

    info!("Void Connect is running. Discovering peers...");

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let peers = peer_list.all().await;
        if peers.is_empty() {
            info!("No peers found yet...");
        } else {
            info!("Known peers ({}):", peers.len());
            for peer in &peers {
                info!("  - {} @ {} [{}]", peer.name, peer.addr(), peer.id);
            }
        }
    }
}

fn generate_temp_id() -> NodeId {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    NodeId::from_public_key_bytes(&bytes)
}

fn get_local_ip() -> Option<IpAddr> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip())
}