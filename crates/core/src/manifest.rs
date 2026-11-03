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
    /// Публикатор, подписавший манифест (он же исходный владелец).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<NodeId>,
    /// Подпись публикатора над [`FileManifest::signing_bytes`]: имя, размер,
    /// тип, `file_id` и список чанков. Список сидеров `owners` НЕ подписан —
    /// это подсказки, каждого проверит Noise-рукопожатие при скачивании.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Подписываемая часть манифеста (без сидеров и самой подписи).
#[derive(Serialize)]
struct SignedPart<'a> {
    file_id: &'a str,
    name: &'a str,
    size_bytes: i64,
    mime_type: &'a Option<String>,
    publisher: &'a Option<NodeId>,
    chunks: &'a [ChunkMeta],
}

impl FileManifest {
    /// Количество чанков в файле.
    pub fn total_chunks(&self) -> i64 {
        self.chunks.len() as i64
    }

    /// Исходный публикатор файла: подписавший манифест, иначе первый владелец.
    pub fn original_owner(&self) -> Option<&NodeId> {
        self.publisher.as_ref().or(self.owners.first())
    }

    /// Канонические байты для подписи публикатором.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let part = SignedPart {
            file_id: &self.file_id,
            name: &self.name,
            size_bytes: self.size_bytes,
            mime_type: &self.mime_type,
            publisher: &self.publisher,
            chunks: &self.chunks,
        };
        let mut out = b"void-connect/file-manifest/v1\n".to_vec();
        out.extend_from_slice(&serde_json::to_vec(&part).expect("FileManifest сериализуется"));
        out
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
            publisher: None,
            signature: None,
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
            publisher: None,
            signature: None,
        };
        assert_eq!(m.original_owner(), Some(&a));
        assert!(m.add_owner(b.clone()), "новый владелец → список изменился");
        assert!(!m.add_owner(b.clone()), "повторный владелец → без изменений");
        assert_eq!(m.owners, vec![a, b]);
    }

    #[test]
    fn signing_bytes_cover_content_but_not_seeders() {
        let mut m = FileManifest {
            file_id: "f".into(),
            name: "report.pdf".into(),
            size_bytes: 1,
            mime_type: None,
            owners: vec![],
            chunks: vec![ChunkMeta { hash: "a".repeat(64), index: 0, size: 1 }],
            publisher: Some(NodeId::from_public_key_bytes(&[1u8; 32])),
            signature: None,
        };
        let base = m.signing_bytes();
        m.owners.push(NodeId::from_public_key_bytes(&[2u8; 32]));
        m.signature = Some("ab".into());
        assert_eq!(m.signing_bytes(), base, "сидеры и подпись не входят в подписываемое");
        m.name = "report.pdf.exe".into();
        assert_ne!(m.signing_bytes(), base, "переименование меняет подписываемое");
    }
}
