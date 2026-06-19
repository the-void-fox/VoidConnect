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