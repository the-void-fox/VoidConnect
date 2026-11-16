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

/// Путь файла переписки. `None` для ID не в формате hex64 — ID приходит из
/// сети, и `../keystore` иначе указал бы на файл ключей рядом с `dm/`.
fn conv_path(peer_id: &str) -> Option<std::path::PathBuf> {
    void_core::sanitize::is_hex64(peer_id).then(|| dm_dir().join(format!("{}.json", peer_id)))
}

// ── Загрузка / сохранение ─────────────────────────────────────────────────────

fn load_conv(peer_id: &str) -> StoredConv {
    conv_path(peer_id)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(StoredConv {
            peer_id:   peer_id.to_string(),
            peer_name: String::new(),
            messages:  Vec::new(),
        })
}

/// Записывает беседу атомарно: во временный файл, затем rename — обрыв
/// посреди записи не оставит полупустой JSON вместо всей переписки.
fn save_conv(conv: &StoredConv) {
    let Some(path) = conv_path(&conv.peer_id) else { return };
    let Ok(json) = serde_json::to_vec(conv) else { return };
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Добавляет одно сообщение к сохранённой беседе.
///
/// Запись идёт в отдельном потоке: раньше каждое сообщение в UI-потоке
/// перечитывало и переписывало весь файл переписки, и на длинной беседе это
/// заметно подтормаживало окно. Поток держит беседы в памяти и пишет на диск
/// только новое состояние.
pub fn append_msg(peer_id: &str, peer_name: &str, msg: StoredMsg) {
    let _ = writer().send((peer_id.to_string(), peer_name.to_string(), msg));
}

type WriteOp = (String, String, StoredMsg);

fn writer() -> &'static std::sync::mpsc::Sender<WriteOp> {
    static WRITER: std::sync::OnceLock<std::sync::mpsc::Sender<WriteOp>> = std::sync::OnceLock::new();
    WRITER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<WriteOp>();
        std::thread::Builder::new()
            .name("dm-store".into())
            .spawn(move || {
                let mut cache: std::collections::HashMap<String, StoredConv> = Default::default();
                while let Ok(op) = rx.recv() {
                    // Пачка подряд пришедших сообщений — одна запись на беседу.
                    let mut dirty = std::collections::HashSet::new();
                    dirty.extend(apply_append(&mut cache, op));
                    while let Ok(op) = rx.try_recv() {
                        dirty.extend(apply_append(&mut cache, op));
                    }
                    for id in dirty {
                        if let Some(conv) = cache.get(&id) {
                            save_conv(conv);
                        }
                    }
                }
            })
            .expect("поток записи личных сообщений");
        tx
    })
}

/// Применяет добавление к кэшу беседы. Возвращает ID беседы, если её надо
/// записать на диск (сообщение новое).
fn apply_append(
    cache: &mut std::collections::HashMap<String, StoredConv>,
    (peer_id, peer_name, msg): WriteOp,
) -> Option<String> {
    conv_path(&peer_id)?;
    let conv = cache.entry(peer_id.clone()).or_insert_with(|| load_conv(&peer_id));
    if !peer_name.is_empty() {
        conv.peer_name = peer_name;
    }
    // Дедупликация по message_id
    if conv.messages.iter().any(|m| m.message_id == msg.message_id) {
        return None;
    }
    conv.messages.push(msg);
    Some(peer_id)
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
