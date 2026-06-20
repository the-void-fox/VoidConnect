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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_is_64_char_hex() {
        let id = NodeId::from_public_key_bytes(&[0xAB; 32]);
        assert_eq!(id.as_str().len(), 64);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id.as_str(), "ab".repeat(32));
    }

    #[test]
    fn different_bytes_differ() {
        let a = NodeId::from_public_key_bytes(&[1u8; 32]);
        let b = NodeId::from_public_key_bytes(&[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn display_is_shortened() {
        let id = NodeId::from_public_key_bytes(&[0x12; 32]);
        // Display показывает первые 8 символов + "..."
        assert_eq!(format!("{id}"), "12121212...");
    }

    #[test]
    fn display_handles_short_id() {
        // Не должно паниковать на ID короче 8 символов (например stub-).
        let id = NodeId("abc".into());
        assert_eq!(format!("{id}"), "abc...");
    }

    #[test]
    fn serde_roundtrip() {
        let id = NodeId::from_public_key_bytes(&[7u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}