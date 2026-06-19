use std::net::IpAddr;
use std::time::Duration;
use tracing::{info, warn};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, Service};
use void_discovery::{
    mdns::start_mdns,
    udp_broadcast::start_udp_broadcast,
    PeerList,
};
use void_chat::public_chat::start_public_chat;

/// Использование:
///   cargo run -- <name> [base_port] [--peer=ip:port]
///
/// Примеры:
///   Терминал 1:  cargo run -- Alice
///   Терминал 2:  cargo run -- Bob 7710 --peer=127.0.0.1:7700
///
/// Порты:
///   base_port     — основной порт узла          (default: 7700)
///   base_port + 2 — TCP-сервер чата             (default: 7702)
///
/// --peer=ip:port — вручную добавить первый узел (нужно при тесте на loopback,
///                  т.к. mDNS и UDP broadcast там не работают)
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let name      = args.get(1).cloned().unwrap_or_else(|| "Vasya".to_string());
    let base_port = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(7700u16);
    let chat_port = base_port + 2;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("void_connect=info".parse()?)
                .add_directive("void_discovery=debug".parse()?)
                .add_directive("void_chat=debug".parse()?),
        )
        .init();

    info!("Starting Void Connect as '{}' (port={}, chat_port={})", name, base_port, chat_port);

    let my_id = generate_temp_id();
    let my_ip  = IpAddr::from([127, 0, 0, 1]);

    let my_peer = PeerInfo {
        id:        my_id.clone(),
        name:      name.clone(),
        ip:        my_ip,
        port:      base_port,
        chat_port,
        services:  vec![Service::Chat],
        last_seen: chrono::Utc::now().timestamp(),
    };

    let peer_list = PeerList::new();

    // Вручную добавляем пира если передан --peer=ip:port
    // chat_port пира = его основной порт + 2 (соглашение)
    for arg in args.iter() {
        if let Some(addr_str) = arg.strip_prefix("--peer=") {
            if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                let peer_base = addr.port();
                let stub = PeerInfo {
                    id:        NodeId(format!("stub-{}", addr)),
                    name:      "peer".to_string(),
                    ip:        addr.ip(),
                    port:      peer_base,
                    chat_port: peer_base + 2,
                    services:  vec![Service::Chat],
                    last_seen: chrono::Utc::now().timestamp(),
                };
                info!("Manually added peer: {} (chat_port={})", stub.addr(), stub.chat_port);
                peer_list.upsert(stub).await;
            }
        }
    }

    start_mdns(my_peer.clone(), peer_list.clone()).await?;
    // Передаём base_port чтобы второй экземпляр не конфликтовал на 7701
    start_udp_broadcast(my_peer.clone(), peer_list.clone(), base_port).await?;

    let chat = start_public_chat(my_peer.clone(), peer_list.clone(), chat_port).await?;

    // Входящие сообщения → консоль
    let mut rx = chat.subscribe();
    tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            println!("\r[{}] <{}> {}",
                chrono::DateTime::from_timestamp(msg.timestamp, 0)
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%H:%M:%S").to_string())
                    .unwrap_or_default(),
                msg.from_name,
                msg.text
            );
            print!("> ");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    });

    // Фоновый вывод пиров каждые 30 сек
    let peer_list_bg = peer_list.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let peers = peer_list_bg.all().await;
            if !peers.is_empty() {
                info!("Known peers ({}):", peers.len());
                for p in &peers {
                    info!("  - {} @ {} (chat:{})", p.name, p.addr(), p.chat_port);
                }
            }
        }
    });

    info!("Ready! Type message + Enter. Ctrl+C to quit.");

    loop {
        print!("> ");
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let (n, line) = tokio::task::spawn_blocking(|| {
            let mut buf = String::new();
            let n = std::io::stdin().read_line(&mut buf)?;
            Ok::<(usize, String), std::io::Error>((n, buf))
        }).await??;

        // n == 0 — это EOF (stdin закрыт): выходим, а не крутимся в пустом цикле.
        if n == 0 {
            info!("stdin closed (EOF) — exiting.");
            break;
        }

        let text = line.trim().to_string();
        if text.is_empty() {
            continue;
        }

        if let Err(e) = chat.send(text).await {
            warn!("Failed to send: {}", e);
        }
    }

    Ok(())
}

fn generate_temp_id() -> NodeId {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    NodeId::from_public_key_bytes(&bytes)
}