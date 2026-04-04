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

    /// Список активных сервисов этого узла
    pub services: Vec<Service>,

    /// Unix timestamp последнего появления в сети
    pub last_seen: i64,
}

impl PeerInfo {
    /// Адрес для подключения в формате "ip:port"
    pub fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// Считаем узел живым, если он был виден не позже 60 секунд назад
    pub fn is_alive(&self, now: i64) -> bool {
        now - self.last_seen < 60
    }
}