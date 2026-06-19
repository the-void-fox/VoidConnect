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