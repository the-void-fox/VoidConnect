use crate::identity::NodeId;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Сервисы, которые может предоставлять узел
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Service {
    Chat,
    Storage,
    Web,
    Bootstrap,
}

/// Запись об известном узле сети.
/// Хранится в peer list и синхронизируется между узлами.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Публичный ключ = уникальный ID
    pub id: NodeId,

    /// Человекочитаемое имя (из профиля)
    pub name: String,

    pub ip: IpAddr,
    pub port: u16,

    /// Порт TCP-сервера общего чата.
    /// Обычно port + 2, но может быть любым — передаётся явно
    /// чтобы несколько экземпляров на одной машине не конфликтовали.
    pub chat_port: u16,

    /// Список активных сервисов этого узла
    pub services: Vec<Service>,

    /// Unix timestamp последнего появления в сети
    pub last_seen: i64,
}

/// Профиль узла — расширенные данные, которыми узлы обмениваются напрямую.
/// Не хранится в mDNS/UDP (слишком объёмно), передаётся через TCP-чат при подключении.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerProfile {
    pub node_id:     NodeId,
    pub name:        String,
    pub description: String,
    /// "online" | "away" | "busy" | "offline"
    pub status:      String,
    /// X25519 публичный ключ (hex) для E2E шифрования личных сообщений.
    /// None = старый узел без поддержки DM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_pubkey:  Option<String>,
}

impl PeerProfile {
    pub fn new(node_id: NodeId, name: String) -> Self {
        PeerProfile { node_id, name, description: String::new(), status: "online".into(), enc_pubkey: None }
    }
}

impl PeerInfo {
    /// Адрес для подключения в формате "ip:port"
    pub fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// Адрес чат-сервера в формате "ip:chat_port"
    pub fn chat_addr(&self) -> String {
        format!("{}:{}", self.ip, self.chat_port)
    }

    /// Считаем узел живым, если он был виден не позже 60 секунд назад
    pub fn is_alive(&self, now: i64) -> bool {
        now - self.last_seen < 60
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample(last_seen: i64) -> PeerInfo {
        PeerInfo {
            id:        NodeId("id".into()),
            name:      "bob".into(),
            ip:        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 7)),
            port:      7700,
            chat_port: 7702,
            services:  vec![Service::Chat],
            last_seen,
        }
    }

    #[test]
    fn addr_helpers_format_ip_and_ports() {
        let p = sample(0);
        assert_eq!(p.addr(), "192.168.0.7:7700");
        assert_eq!(p.chat_addr(), "192.168.0.7:7702");
    }

    #[test]
    fn is_alive_boundary() {
        let p = sample(1_000);
        assert!(p.is_alive(1_000));          // только что
        assert!(p.is_alive(1_059));          // 59 c назад — ещё жив
        assert!(!p.is_alive(1_060));         // ровно 60 c — уже нет
        assert!(!p.is_alive(2_000));
    }

    #[test]
    fn profile_new_defaults() {
        let prof = PeerProfile::new(NodeId("x".into()), "alice".into());
        assert_eq!(prof.status, "online");
        assert!(prof.description.is_empty());
        assert!(prof.enc_pubkey.is_none());
    }

    #[test]
    fn profile_omits_none_enc_pubkey_in_json() {
        // enc_pubkey = None не должен попадать в JSON (skip_serializing_if).
        let prof = PeerProfile::new(NodeId("x".into()), "alice".into());
        let json = serde_json::to_string(&prof).unwrap();
        assert!(!json.contains("enc_pubkey"));

        // А round-trip с Some — сохраняется.
        let mut prof2 = prof.clone();
        prof2.enc_pubkey = Some("deadbeef".into());
        let back: PeerProfile = serde_json::from_str(&serde_json::to_string(&prof2).unwrap()).unwrap();
        assert_eq!(back.enc_pubkey.as_deref(), Some("deadbeef"));
    }
}