use crate::identity::NodeId;
use serde::{Deserialize, Serialize};

/// Базовый тип сообщения, которым обмениваются узлы
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NetworkMessage {
    /// Объявление о себе (рассылается при подключении)
    Announce { peer: crate::peer::PeerInfo },

    /// Запрос списка известных узлов
    GetPeers,

    /// Ответ со списком узлов
    Peers { peers: Vec<crate::peer::PeerInfo> },

    /// Сообщение в общий чат
    ChatMessage {
        from: NodeId,
        text: String,
        timestamp: i64,
        /// Монотонный счётчик от данного отправителя.
        /// Используется для дедупликации при P2P flood-схеме:
        /// если (from, seq) уже видели — отбрасываем.
        seq: u64,
        /// Подпись сообщения приватным ключом отправителя.
        /// sign(from || text || timestamp || seq)
        signature: String,
    },

    /// Синхронизация репутации между узлами.
    /// `signed_payload` — сериализованный `SyncPayload`, подписанный ключом `signer`.
    ReputationSync {
        from: NodeId,
        signed_payload: Vec<u8>,
        signature: String,
        signer: String,
    },

    /// Подписанная жалоба на узел `target`.
    ReputationReport {
        target: NodeId,
        signed_payload: Vec<u8>,
        signature: String,
        signer: String,
    },

    /// Пинг для проверки доступности
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_message_serde_roundtrip() {
        let msg = NetworkMessage::ChatMessage {
            from:      NodeId("abc".into()),
            text:      "привет".into(),
            timestamp: 123,
            seq:       7,
            signature: "sig".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"chat_message\""));
        let back: NetworkMessage = serde_json::from_str(&json).unwrap();
        match back {
            NetworkMessage::ChatMessage { text, seq, .. } => {
                assert_eq!(text, "привет");
                assert_eq!(seq, 7);
            }
            _ => panic!("ожидался ChatMessage"),
        }
    }

    /// Регрессия на P0: варианты репутации сериализуются с snake_case-тегом
    /// и переживают round-trip.
    #[test]
    fn reputation_variants_roundtrip() {
        let sync = NetworkMessage::ReputationSync {
            from:           NodeId("node".into()),
            signed_payload: vec![1, 2, 3],
            signature:      "s".into(),
            signer:         "node".into(),
        };
        let json = serde_json::to_string(&sync).unwrap();
        assert!(json.contains("\"type\":\"reputation_sync\""));
        assert!(matches!(
            serde_json::from_str::<NetworkMessage>(&json).unwrap(),
            NetworkMessage::ReputationSync { .. }
        ));

        let report = NetworkMessage::ReputationReport {
            target:         NodeId("victim".into()),
            signed_payload: vec![9],
            signature:      "s".into(),
            signer:         "reporter".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"type\":\"reputation_report\""));
        assert!(matches!(
            serde_json::from_str::<NetworkMessage>(&json).unwrap(),
            NetworkMessage::ReputationReport { .. }
        ));
    }
}