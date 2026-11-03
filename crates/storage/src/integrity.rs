//! Проверка целостности чанков по SHA-256.
//!
//! После получения каждого чанка по сети — всегда вызывай `verify_chunk`.
//! Если хэш не совпадает — чанк отбрасывается, узел получает штраф.

use sha2::{Digest, Sha256};
use void_core::identity::NodeId;
use void_core::manifest::FileManifest;
use void_core::sanitize::is_hex64;
use void_crypto::sign::SignedMessage;

use crate::error::StorageError;

/// Верхняя граница размера одного чанка в чужом манифесте (совпадает с лимитом
/// ответа chunk-сервера в `transfer.rs`).
pub const MAX_CHUNK_SIZE: i64 = 512 * 1024;

/// Вычисляет SHA-256 хэш переданных байт.
/// Возвращает hex-строку нижнего регистра.
pub fn hash_chunk(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Проверяет, что хэш данных совпадает с ожидаемым.
///
/// # Errors
/// Возвращает `StorageError::IntegrityFailure` если хэши не совпадают.
pub fn verify_chunk(expected_hash: &str, data: &[u8]) -> Result<(), StorageError> {
    let actual = hash_chunk(data);
    if actual != expected_hash {
        return Err(StorageError::IntegrityFailure {
            expected: expected_hash.to_string(),
            actual,
        });
    }
    Ok(())
}

/// Вычисляет SHA-256 от конкатенации всех хэшей чанков (файловый манифест ID).
///
/// Порядок важен: chunk_hashes должен быть отсортирован по chunk_index.
pub fn compute_file_id(chunk_hashes: &[String]) -> String {
    let mut hasher = Sha256::new();
    for h in chunk_hashes {
        hasher.update(h.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Проверяет манифест, пришедший из сети, до записи в БД.
///
/// Манифест пока не подписан, поэтому проверяем всё, что можно проверить без
/// подписи: формат хэшей и ID владельцев, индексы чанков `0..n` без пропусков и
/// повторов, размеры, и главное — что `file_id` действительно вычислен из хэшей
/// чанков. Иначе чужой узел мог бы объявить известный `file_id` со своими
/// чанками и подменить содержимое файла у тех, кто его скачивает.
pub fn validate_manifest(m: &FileManifest) -> Result<(), StorageError> {
    let bad = |why: &str| Err(StorageError::InvalidManifest(why.to_string()));

    if !is_hex64(&m.file_id) {
        return bad("file_id не hex64");
    }
    if m.owners.iter().any(|o| !is_hex64(o.as_str())) {
        return bad("ID владельца не hex64");
    }

    let mut chunks: Vec<_> = m.chunks.iter().collect();
    chunks.sort_by_key(|c| c.index);

    let mut total: i64 = 0;
    for (expected_index, c) in chunks.iter().enumerate() {
        if c.index != expected_index as i64 {
            return bad("индексы чанков не идут подряд с 0");
        }
        if !is_hex64(&c.hash) {
            return bad("хэш чанка не hex64");
        }
        if c.size <= 0 || c.size > MAX_CHUNK_SIZE {
            return bad("недопустимый размер чанка");
        }
        total = total.saturating_add(c.size);
    }
    if total != m.size_bytes {
        return bad("сумма размеров чанков не равна размеру файла");
    }

    let hashes: Vec<String> = chunks.iter().map(|c| c.hash.clone()).collect();
    if compute_file_id(&hashes) != m.file_id {
        return bad("file_id не совпадает с хэшами чанков");
    }
    Ok(())
}

/// Проверяет подпись публикатора манифеста и возвращает его NodeId. Без неё
/// любой узел мог бы объявить файл «от имени» другого или переименовать его.
pub fn verify_publisher(m: &FileManifest) -> Result<NodeId, StorageError> {
    let (Some(publisher), Some(signature)) = (&m.publisher, &m.signature) else {
        return Err(StorageError::InvalidManifest("манифест не подписан публикатором".into()));
    };
    let signed = SignedMessage {
        payload: m.signing_bytes(),
        signature: signature.clone(),
        signer: publisher.as_str().to_string(),
    };
    signed
        .verify()
        .map_err(|_| StorageError::InvalidManifest("подпись публикатора неверна".into()))?;
    Ok(publisher.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_core::manifest::ChunkMeta;

    fn valid_manifest() -> FileManifest {
        let chunks: Vec<ChunkMeta> = [b"part-0".as_slice(), b"part-1"]
            .iter()
            .enumerate()
            .map(|(i, data)| ChunkMeta {
                hash: hash_chunk(data),
                index: i as i64,
                size: data.len() as i64,
            })
            .collect();
        let hashes: Vec<String> = chunks.iter().map(|c| c.hash.clone()).collect();
        FileManifest {
            file_id: compute_file_id(&hashes),
            name: "a.txt".into(),
            size_bytes: 12,
            mime_type: None,
            owners: vec![NodeId("b".repeat(64))],
            chunks,
            publisher: None,
            signature: None,
        }
    }

    #[test]
    fn publisher_signature_checked() {
        let kp = void_crypto::keys::SigningKeypair::from_seed(&[4u8; 32]).unwrap();
        let mut m = valid_manifest();
        assert!(verify_publisher(&m).is_err(), "без подписи");

        m.publisher = Some(NodeId::from_public_key_bytes(&kp.public_bytes()));
        m.signature = Some(SignedMessage::sign(m.signing_bytes(), &kp).unwrap().signature);
        assert_eq!(verify_publisher(&m).unwrap(), m.publisher.clone().unwrap());

        let mut renamed = m.clone();
        renamed.name = "a.txt.exe".into();
        assert!(verify_publisher(&renamed).is_err(), "переименование после подписи");

        let mut foreign = m.clone();
        foreign.publisher = Some(NodeId("c".repeat(64)));
        assert!(verify_publisher(&foreign).is_err(), "чужой публикатор");
    }

    #[test]
    fn valid_manifest_accepted_in_any_chunk_order() {
        let mut m = valid_manifest();
        assert!(validate_manifest(&m).is_ok());
        m.chunks.reverse();
        assert!(validate_manifest(&m).is_ok(), "порядок в векторе не важен, важны индексы");
    }

    #[test]
    fn forged_file_id_rejected() {
        // Чужой узел объявляет известный file_id со своими чанками.
        let mut m = valid_manifest();
        m.chunks[0].hash = hash_chunk(b"evil-0");
        assert!(matches!(validate_manifest(&m), Err(StorageError::InvalidManifest(_))));
    }

    #[test]
    fn malformed_manifests_rejected() {
        let mut m = valid_manifest();
        m.chunks[1].hash = "../../../etc/passwd".into();
        assert!(validate_manifest(&m).is_err());

        let mut m = valid_manifest();
        m.chunks[1].index = 5;
        assert!(validate_manifest(&m).is_err());

        let mut m = valid_manifest();
        m.size_bytes = 1_000_000;
        assert!(validate_manifest(&m).is_err());

        let mut m = valid_manifest();
        m.owners.push(NodeId("stub-1".into()));
        assert!(validate_manifest(&m).is_err());
    }

    #[test]
    fn hash_roundtrip() {
        let data = b"hello void";
        let h = hash_chunk(data);
        assert!(verify_chunk(&h, data).is_ok());
    }

    #[test]
    fn bad_data_fails() {
        let data = b"hello void";
        let h = hash_chunk(data);
        let result = verify_chunk(&h, b"tampered");
        assert!(matches!(result, Err(StorageError::IntegrityFailure { .. })));
    }
}