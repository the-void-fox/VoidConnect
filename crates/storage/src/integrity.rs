//! Проверка целостности чанков по SHA-256.
//!
//! После получения каждого чанка по сети — всегда вызывай `verify_chunk`.
//! Если хэш не совпадает — чанк отбрасывается, узел получает штраф.

use sha2::{Digest, Sha256};

use crate::error::StorageError;

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

#[cfg(test)]
mod tests {
    use super::*;

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