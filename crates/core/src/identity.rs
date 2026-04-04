use serde::{Deserialize, Serialize};

/// Уникальный идентификатор узла в сети — hex-строка публичного ключа.
/// Пример: "a3f8c2d1e4b7..."
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    pub fn from_public_key_bytes(bytes: &[u8]) -> Self {
        NodeId(hex::encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Показываем только первые 8 символов для читаемости в логах
        let short = &self.0[..self.0.len().min(8)];
        write!(f, "{}...", short)
    }
}