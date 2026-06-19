//! Персистентное хранение личных сообщений в зашифрованном виде.
//!
//! Схема хранения:
//!   ~/.config/void-connect/dm/{peer_node_id}.json
//!
//! Каждый файл — `StoredConv` (JSON), где каждое сообщение содержит
//! `encrypted_blob` (JSON-сериализованный EncryptedMessage):
//!   - входящие (direction="in") — зашифрованы отправителем нашим X25519 pubkey,
//!     расшифровываем нашим keypair;
//!   - исходящие (direction="out") — само-зашифрованы нашим X25519 keypair → pubkey,
//!     расшифровываем тем же keypair.

use serde::{Deserialize, Serialize};
use void_crypto::encrypt::EncryptedMessage;
use void_crypto::keys::EncryptionKeypair;

// ── Структуры ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredMsg {
    pub message_id:     String,
    /// "in" — от пира, "out" — наше исходящее
    pub direction:      String,
    /// JSON-сериализованный EncryptedMessage
    pub encrypted_blob: String,
    pub timestamp:      i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct StoredConv {
    pub peer_id:   String,
    pub peer_name: String,
    pub messages:  Vec<StoredMsg>,
}

// ── Пути ─────────────────────────────────────────────────────────────────────

fn dm_dir() -> std::path::PathBuf {
    let dir = crate::profile_store::profile_dir().join("dm");
    std::fs::create_dir_all(&dir).ok();
    dir
}

fn conv_path(peer_id: &str) -> std::path::PathBuf {
    dm_dir().join(format!("{}.json", peer_id))
}

// ── Загрузка / сохранение ─────────────────────────────────────────────────────

pub fn load_conv(peer_id: &str) -> StoredConv {
    std::fs::read_to_string(conv_path(peer_id))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(StoredConv {
            peer_id:   peer_id.to_string(),
            peer_name: String::new(),
            messages:  Vec::new(),
        })
}

pub fn save_conv(conv: &StoredConv) {
    if let Ok(json) = serde_json::to_string_pretty(conv) {
        let _ = std::fs::write(conv_path(&conv.peer_id), json);
    }
}

/// Добавляет одно сообщение к сохранённой беседе (инкрементально).
pub fn append_msg(peer_id: &str, peer_name: &str, msg: StoredMsg) {
    let mut conv = load_conv(peer_id);
    if !peer_name.is_empty() {
        conv.peer_name = peer_name.to_string();
    }
    // Дедупликация по message_id
    if !conv.messages.iter().any(|m| m.message_id == msg.message_id) {
        conv.messages.push(msg);
        save_conv(&conv);
    }
}

/// Возвращает список всех сохранённых бесед (отсортированных по последнему сообщению).
pub fn list_convs() -> Vec<StoredConv> {
    let dir = dm_dir();
    let mut convs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(c) = serde_json::from_str::<StoredConv>(&s) {
                        convs.push(c);
                    }
                }
            }
        }
    }
    convs.sort_by_key(|c| std::cmp::Reverse(
        c.messages.last().map(|m| m.timestamp).unwrap_or(0)
    ));
    convs
}

/// Расшифровывает все сообщения беседы для отображения в GUI.
/// Возвращает `(timestamp, plaintext, is_me, message_id)`.
pub fn decrypt_messages(
    conv: &StoredConv,
    kp:   &EncryptionKeypair,
) -> Vec<(i64, String, bool, String)> {
    let mut result = Vec::new();
    for msg in &conv.messages {
        let is_me = msg.direction == "out";
        if let Ok(enc) = serde_json::from_str::<EncryptedMessage>(&msg.encrypted_blob) {
            if let Ok(bytes) = enc.decrypt(kp) {
                let text = String::from_utf8_lossy(&bytes).to_string();
                result.push((msg.timestamp, text, is_me, msg.message_id.clone()));
            }
        }
    }
    result
}

/// Само-шифрует plaintext нашим keypair для хранения исходящих сообщений.
pub fn self_encrypt(plaintext: &str, kp: &EncryptionKeypair) -> Option<String> {
    let our_pub = kp.public_bytes();
    EncryptedMessage::encrypt(plaintext.as_bytes(), &our_pub, kp)
        .ok()
        .and_then(|enc| serde_json::to_string(&enc).ok())
}
