//! STUN-клиент (RFC 5389) — определение внешнего адреса узла за NAT.
//!
//! Домашний роутер прячет узел за одним внешним IP. Чтобы узел мог объявить
//! сети свой доступный адрес, он спрашивает публичный STUN-сервер «какой у меня
//! внешний IP:порт?». Это та же reflexive-проверка, что у торрентов/WebRTC.
//!
//! Используются бесплатные публичные STUN-серверы (Google/Cloudflare) — свой
//! поднимать не нужно. Запрос best-effort: при недоступности → `None`.
//!
//! Реализован минимум: Binding Request + разбор `XOR-MAPPED-ADDRESS`
//! (с фолбэком на `MAPPED-ADDRESS`). Кодирование/разбор полностью юнит-тестируемы.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::debug;

/// Магическая константа STUN (RFC 5389) — в заголовке и для XOR-адресов.
const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// Публичные STUN-серверы по умолчанию (бесплатные).
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Собирает 20-байтный STUN Binding Request с заданным transaction id.
pub fn build_binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // length = 0 (нет атрибутов)
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(txid);
    buf
}

/// Разбирает STUN Binding Success Response и достаёт наш внешний адрес.
/// Проверяет тип, magic cookie и transaction id. Предпочитает
/// `XOR-MAPPED-ADDRESS`, при отсутствии — `MAPPED-ADDRESS`.
pub fn parse_mapped_address(resp: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if resp.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([resp[0], resp[1]]);
    if msg_type != BINDING_SUCCESS {
        return None;
    }
    if resp[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return None;
    }
    if resp[8..20] != txid[..] {
        return None;
    }
    let msg_len = u16::from_be_bytes([resp[2], resp[3]]) as usize;
    let end = (20 + msg_len).min(resp.len());

    let mut plain: Option<SocketAddr> = None;
    let mut i = 20;
    while i + 4 <= end {
        let atype = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let alen = u16::from_be_bytes([resp[i + 2], resp[i + 3]]) as usize;
        let val_start = i + 4;
        if val_start + alen > resp.len() {
            break;
        }
        let val = &resp[val_start..val_start + alen];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(sa) = parse_xor_mapped(val, txid) {
                    return Some(sa); // XOR предпочтительнее — возвращаем сразу
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if plain.is_none() {
                    plain = parse_plain_mapped(val);
                }
            }
            _ => {}
        }
        // атрибуты выровнены по 4 байта
        i = val_start + alen + (4 - (alen % 4)) % 4;
    }
    plain
}

fn parse_xor_mapped(val: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match family {
        0x01 => {
            let xaddr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
            let addr = Ipv4Addr::from(xaddr ^ MAGIC_COOKIE);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        0x02 => {
            if val.len() < 20 {
                return None;
            }
            // XOR-ключ для IPv6 = magic cookie ‖ transaction id.
            let mut key = [0u8; 16];
            key[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..16].copy_from_slice(txid);
            let mut a = [0u8; 16];
            a.copy_from_slice(&val[4..20]);
            for k in 0..16 {
                a[k] ^= key[k];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        _ => None,
    }
}

fn parse_plain_mapped(val: &[u8]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    match family {
        0x01 => {
            let addr = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        0x02 if val.len() >= 20 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&val[4..20]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        _ => None,
    }
}

/// Уникальный (не криптографический) transaction id из времени + счётчика.
fn gen_txid() -> [u8; 12] {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let ctr = CTR.fetch_add(1, Ordering::Relaxed);
    let mut id = [0u8; 12];
    id[0..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..12].copy_from_slice(&(ctr as u32).to_be_bytes());
    id
}

/// Спрашивает один STUN-сервер о нашем внешнем адресе (best-effort).
pub async fn query_external_addr(server: &str) -> io::Result<Option<SocketAddr>> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await?;
    sock.connect(server).await?;
    let txid = gen_txid();
    sock.send(&build_binding_request(&txid)).await?;

    let mut buf = [0u8; 512];
    let n = timeout(STUN_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "STUN timeout"))??;
    Ok(parse_mapped_address(&buf[..n], &txid))
}

/// Перебирает серверы и возвращает первый успешно определённый внешний IP.
pub async fn discover_external_ip(servers: &[&str]) -> Option<IpAddr> {
    for server in servers {
        match query_external_addr(server).await {
            Ok(Some(addr)) => {
                debug!("STUN {} → внешний адрес {}", server, addr);
                return Some(addr.ip());
            }
            Ok(None) => debug!("STUN {}: ответ без mapped-адреса", server),
            Err(e) => debug!("STUN {} недоступен: {}", server, e),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_has_magic_and_type() {
        let txid = [7u8; 12];
        let req = build_binding_request(&txid);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0); // нет атрибутов
        assert_eq!(req[4..8], MAGIC_COOKIE.to_be_bytes());
        assert_eq!(req[8..20], txid);
    }

    /// Собираем валидный Binding Success c XOR-MAPPED-ADDRESS и разбираем обратно.
    #[test]
    fn parse_xor_mapped_ipv4_roundtrip() {
        let txid = [0xABu8; 12];
        let ext = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 51234);

        // Атрибут XOR-MAPPED-ADDRESS (8 байт значения).
        let xport = 51234u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let xaddr = u32::from(Ipv4Addr::new(203, 0, 113, 5)) ^ MAGIC_COOKIE;
        let mut attr_val = vec![0u8, 0x01, (xport >> 8) as u8, xport as u8];
        attr_val.extend_from_slice(&xaddr.to_be_bytes());

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        resp.extend_from_slice(&((4 + attr_val.len()) as u16).to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&(attr_val.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr_val);

        assert_eq!(parse_mapped_address(&resp, &txid), Some(ext));
    }

    /// Фолбэк на (не-XOR) MAPPED-ADDRESS, если XOR-атрибута нет.
    #[test]
    fn parse_plain_mapped_ipv4() {
        let txid = [1u8; 12];
        let mut resp = Vec::new();
        let attr_val = vec![0u8, 0x01, 0x1F, 0x90, 192, 168, 1, 9]; // port 8080
        resp.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        resp.extend_from_slice(&((4 + attr_val.len()) as u16).to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&(attr_val.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr_val);

        assert_eq!(
            parse_mapped_address(&resp, &txid),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9)), 8080)),
        );
    }

    #[test]
    fn rejects_wrong_txid_and_non_success() {
        let txid = [2u8; 12];
        let req = build_binding_request(&txid); // тип = request, не success
        assert_eq!(parse_mapped_address(&req, &txid), None);

        // Правильный success, но txid не совпадает.
        let mut resp = build_binding_request(&txid).to_vec();
        resp[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        let wrong = [9u8; 12];
        assert_eq!(parse_mapped_address(&resp, &wrong), None);
    }
}
