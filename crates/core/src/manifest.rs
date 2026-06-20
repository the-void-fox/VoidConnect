//! Манифест файла — описание опубликованного файла для рассылки по сети.
//!
//! Манифест рассылается через relay общего чата (так же, как профили), чтобы
//! другие узлы могли обнаружить файл и начать скачивать его чанки у владельца,
//! даже если сами этот файл не публиковали.

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// Описание одного чанка в манифесте.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkMeta {
    /// SHA-256 содержимого чанка (hex).
    pub hash: String,
    /// Порядковый номер чанка в файле.
    pub index: i64,
    /// Размер чанка в байтах.
    pub size: i64,
}

/// Манифест файла — всё, что нужно пиру, чтобы начать скачивание.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    /// Идентификатор файла (SHA-256 от манифеста чанков).
    pub file_id: String,
    pub name: String,
    pub size_bytes: i64,
    pub mime_type: Option<String>,
    /// Известные владельцы чанков файла (сидеры). Первый — исходный
    /// публикатор. Список объединяется при получении повторных объявлений,
    /// поэтому файл остаётся доступным, даже если публикатор ушёл в офлайн.
    pub owners: Vec<NodeId>,
    /// Чанки файла в порядке индексов.
    pub chunks: Vec<ChunkMeta>,
}

impl FileManifest {
    /// Количество чанков в файле.
    pub fn total_chunks(&self) -> i64 {
        self.chunks.len() as i64
    }

    /// Исходный публикатор файла (первый владелец), если известен.
    pub fn original_owner(&self) -> Option<&NodeId> {
        self.owners.first()
    }

    /// Добавляет владельца, если его ещё нет. Возвращает `true`, если список
    /// изменился (появился новый сидер).
    pub fn add_owner(&mut self, owner: NodeId) -> bool {
        if self.owners.contains(&owner) {
            false
        } else {
            self.owners.push(owner);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = FileManifest {
            file_id: "deadbeef".into(),
            name: "photo.jpg".into(),
            size_bytes: 600_000,
            mime_type: Some("image/jpeg".into()),
            owners: vec![NodeId::from_public_key_bytes(&[7u8; 32])],
            chunks: vec![
                ChunkMeta { hash: "a".repeat(64), index: 0, size: 262_144 },
                ChunkMeta { hash: "b".repeat(64), index: 1, size: 337_856 },
            ],
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let back: FileManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(back, manifest);
        assert_eq!(back.total_chunks(), 2);
    }

    #[test]
    fn add_owner_dedups() {
        let a = NodeId::from_public_key_bytes(&[1u8; 32]);
        let b = NodeId::from_public_key_bytes(&[2u8; 32]);
        let mut m = FileManifest {
            file_id: "f".into(),
            name: "x".into(),
            size_bytes: 1,
            mime_type: None,
            owners: vec![a.clone()],
            chunks: vec![],
        };
        assert_eq!(m.original_owner(), Some(&a));
        assert!(m.add_owner(b.clone()), "новый владелец → список изменился");
        assert!(!m.add_owner(b.clone()), "повторный владелец → без изменений");
        assert_eq!(m.owners, vec![a, b]);
    }
}
