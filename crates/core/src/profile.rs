use crate::identity::NodeId;
use serde::{Deserialize, Serialize};

/// Профиль пользователя — подписанный JSON, распространяется по сети
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: NodeId,
    pub name: String,
    /// Аватар в base64
    pub avatar: Option<String>,
    pub status: String,
    pub description: Option<String>,
    /// DNS-имя в зоне .void
    pub dns_name: Option<String>,
    pub updated_at: i64,
    /// Подпись всего профиля приватным ключом (hex)
    pub signature: Option<String>,
}