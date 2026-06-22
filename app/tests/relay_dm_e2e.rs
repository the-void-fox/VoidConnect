//! Сквозной тест Фазы 2: личное сообщение доставляется ЧЕРЕЗ relay, когда
//! прямое соединение между узлами невозможно (модель symmetric NAT).
//!
//! Собирает всю цепочку из реальных компонентов:
//!   * публичный relay-сервер (`void-discovery`);
//!   * принимающий узел B регистрируется на relay и скармливает входящие
//!     туннели своему DM-серверу через `accept_stream`;
//!   * отправитель A открывает туннель `open_tunnel` и шлёт DM
//!     `send_dm_over_stream` — никакого прямого `connect` к B.
//! Это именно то, что делает backend в боевом режиме, но без GUI и NAT.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout};

use void_chat::private_chat::{start_private_chat, DmSendCmd};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, Service};
use void_crypto::keys::EncryptionKeypair;
use void_discovery::relay;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn peer(name: &str, seed: u8, dm_port: u16) -> PeerInfo {
    PeerInfo {
        id:        NodeId::from_public_key_bytes(&[seed; 32]),
        name:      name.to_string(),
        ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port:      dm_port.wrapping_sub(3),
        chat_port: dm_port.wrapping_sub(1),
        services:  vec![Service::Chat],
        last_seen: 0,
    }
}

#[tokio::test]
async fn dm_delivered_end_to_end_via_relay() {
    // 1. Публичный relay-сервер.
    let relay_port = free_port();
    relay::start_relay_server(relay_port).await.unwrap();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    sleep(Duration::from_millis(100)).await;

    // 2. Два узла со своими DM-серверами и ключами шифрования.
    let a_kp = Arc::new(EncryptionKeypair::generate());
    let b_kp = Arc::new(EncryptionKeypair::generate());
    let (a_dm, b_dm) = (free_port(), free_port());
    let a_peer = peer("alice", 1, a_dm);
    let b_peer = peer("bob", 2, b_dm);
    let a_id = a_peer.id.clone();
    let b_id = b_peer.id.clone();

    let alice = start_private_chat(a_peer, Arc::clone(&a_kp), a_dm).await.unwrap();
    let bob = start_private_chat(b_peer, Arc::clone(&b_kp), b_dm).await.unwrap();

    // 3. B регистрируется на relay; входящие туннели → DM-приём.
    let mut b_accept = relay::start_relay_client(relay_addr.clone(), b_id.clone());
    let bob_accept = bob.clone();
    tokio::spawn(async move {
        while let Some((stream, _from)) = b_accept.recv().await {
            let h = bob_accept.clone();
            tokio::spawn(async move { h.accept_stream(stream).await; });
        }
    });
    sleep(Duration::from_millis(300)).await; // даём B зарегистрироваться

    // 4. A открывает туннель к B и шлёт DM через relay (без прямого connect).
    let mut bob_rx = bob.subscribe();
    let stream = relay::open_tunnel(&relay_addr, &a_id, &b_id)
        .await
        .expect("open_tunnel должен пройти — B зарегистрирован");

    alice
        .send_dm_over_stream(
            DmSendCmd {
                to:               b_id.clone(),
                to_dm_addr:       String::new(),
                their_enc_pubkey: b_kp.public_bytes(),
                plaintext:        "привет через relay 🔒".into(),
                message_id:       "e2e1".into(),
            },
            stream,
        )
        .await
        .expect("send_dm_over_stream");

    // 5. B получает расшифрованное сообщение, пришедшее сквозь relay.
    let dm = timeout(Duration::from_secs(5), bob_rx.recv())
        .await
        .expect("таймаут ожидания DM через relay")
        .expect("broadcast закрыт");

    assert_eq!(dm.plaintext, "привет через relay 🔒");
    assert_eq!(dm.from, a_id, "отправитель — Alice");
    assert_eq!(dm.message_id, "e2e1");
}

/// Если получатель не зарегистрирован на relay — открытие туннеля не проходит
/// (backend в этом случае логирует «не доставлено»).
#[tokio::test]
async fn open_tunnel_fails_when_target_absent() {
    let relay_port = free_port();
    relay::start_relay_server(relay_port).await.unwrap();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    sleep(Duration::from_millis(100)).await;

    let a_id = NodeId::from_public_key_bytes(&[1; 32]);
    let absent = NodeId::from_public_key_bytes(&[9; 32]);
    assert!(
        relay::open_tunnel(&relay_addr, &a_id, &absent).await.is_err(),
        "туннель к незарегистрированному узлу должен падать"
    );
}
