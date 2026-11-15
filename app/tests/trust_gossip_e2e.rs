//! Сквозной тест сети доверия поверх настоящего общего чата: цепочка узлов
//! A — B — C, у каждого своя БД и та же обвязка, что у `TrustService` в backend
//! (принятое поручительство → в БД → дальше только если база изменилась;
//! новая связь → соседу весь граф).
//!
//! Проверяет то, ради чего поручительства не пересылает сам чат: запись доходит
//! через промежуточный узел, а узел, подключившийся позже, получает уже
//! выданные поручительства от соседа при установке связи.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use void_chat::public_chat::{start_public_chat, ChatHandle};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, Service};
use void_crypto::keys::SigningKeypair;
use void_db::DbPool;
use void_discovery::PeerList;
use void_trust::{store, TrustInputs, TrustLevel, Vouch, VouchKind};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn kp(seed: u8) -> Arc<SigningKeypair> {
    Arc::new(SigningKeypair::from_seed(&[seed; 32]).unwrap())
}

fn id(seed: u8) -> NodeId {
    NodeId::from_public_key_bytes(&kp(seed).public_bytes())
}

fn peer(seed: u8, chat_port: u16) -> PeerInfo {
    PeerInfo {
        id:        id(seed),
        name:      format!("n{seed}"),
        ip:        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port:      chat_port.wrapping_sub(2),
        chat_port,
        services:  vec![Service::Chat],
        last_seen: 0,
    }
}

struct Node {
    chat: ChatHandle,
    pool: DbPool,
    _dir: tempfile::TempDir,
}

/// Узел чата с БД и обвязкой сети доверия (как `TrustService`).
async fn node(seed: u8, me: &PeerInfo, known: &[&PeerInfo]) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let pool = void_db::open(&dir.path().join("db.sqlite")).await.unwrap();
    let pl = PeerList::new();
    for p in known {
        pl.upsert((*p).clone()).await;
    }
    let chat = start_public_chat(me.clone(), pl, me.chat_port, kp(seed), None).await.unwrap();

    let (c, p) = (chat.clone(), pool.clone());
    let mut vouches = chat.subscribe_vouches();
    tokio::spawn(async move {
        while let Ok(g) = vouches.recv().await {
            if let Ok(Some(_)) = store::apply_signed(&p, &g.signed).await {
                c.relay_vouch(g.signed, Some(&g.from)).await;
            }
        }
    });
    let (c, p) = (chat.clone(), pool.clone());
    let mut links = chat.subscribe_links();
    tokio::spawn(async move {
        while let Ok(peer) = links.recv().await {
            if let Ok(all) = store::signed_vouches(&p).await {
                c.push_vouches(&peer, all).await;
            }
        }
    });
    Node { chat, pool, _dir: dir }
}

/// Узел `seed` ручается за `subject`: подпись, своя БД, рассылка (как `set_vouch`).
async fn vouch(node: &Node, seed: u8, subject: &NodeId, at: i64) {
    let v = Vouch { voucher: id(seed), subject: subject.clone(), kind: VouchKind::Personal, updated_at: at, revoked: false };
    let signed = v.sign(&kp(seed)).unwrap();
    assert!(store::apply_signed(&node.pool, &signed).await.unwrap().is_some());
    node.chat.relay_vouch(signed, None).await;
}

/// Ждёт, пока в БД узла не окажется поручительство `voucher → subject`.
async fn wait_vouch(node: &Node, voucher: &NodeId, subject: &NodeId) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        if store::get_vouch(&node.pool, voucher, subject).await.unwrap().is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn wait_links(chat: &ChatHandle, n: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while chat.link_count().await < n {
        assert!(tokio::time::Instant::now() < deadline, "связи не установились");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn vouches_travel_hops_and_reach_late_joiner() {
    let (a, b, c) = (peer(1, free_port()), peer(2, free_port()), peer(3, free_port()));
    let node_b = node(2, &b, &[]).await;
    let node_a = node(1, &a, &[&b]).await;
    wait_links(&node_a.chat, 1).await;

    // A ручается за D, пока C ещё нет в сети.
    let d = id(40);
    vouch(&node_a, 1, &d, 1).await;
    assert!(wait_vouch(&node_b, &a.id, &d).await, "B получил поручительство A");

    // C подключается позже и только к B — узнаёт старое поручительство при связи.
    let node_c = node(3, &c, &[&b]).await;
    assert!(wait_vouch(&node_c, &a.id, &d).await, "новичок C не догнал граф через B");

    // Новое поручительство A доходит до C через B (B пересылает, т.к. база изменилась).
    let e = id(50);
    vouch(&node_a, 1, &e, 2).await;
    assert!(wait_vouch(&node_c, &a.id, &e).await, "поручительство не прошло A → B → C");

    // С точки зрения C, лично проверившего A, D и E — «через знакомых».
    let vouches = store::load_vouches(&node_c.pool).await.unwrap();
    let empty = HashSet::new();
    let private: HashSet<NodeId> = [a.id.clone()].into();
    let map = void_trust::compute(&TrustInputs {
        me: &c.id,
        vouches: &vouches,
        blocked: &empty,
        reported: &empty,
        settled: &empty,
        private_verified: &private,
    });
    assert_eq!(map.level(&d), TrustLevel::Trusted);
    assert_eq!(map.get(&e).via, vec![a.id.clone()]);
}
