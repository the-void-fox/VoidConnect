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
        /// Подпись сообщения приватным ключом отправителя
        signature: String,
    },

    /// Пинг для проверки доступности
    Ping,
    Pong,
}