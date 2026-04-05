/// hash.rs — хэши для верификации чанков и прочего.

use sha2::{Sha256, Digest};

/// SHA-256 хэш данных (для верификации чанков в хранилище).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 в виде hex-строки.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// BLAKE3 хэш (быстрее SHA-256, подходит для больших файлов).
pub fn blake3(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3(data))
}

/// Верифицирует чанк по ожидаемому SHA-256 хэшу.
/// Возвращает `true` если данные совпадают.
pub fn verify_chunk(data: &[u8], expected_sha256_hex: &str) -> bool {
    sha256_hex(data) == expected_sha256_hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        assert_eq!(sha256(b"hello"), sha256(b"hello"));
        assert_ne!(sha256(b"hello"), sha256(b"world"));
    }

    #[test]
    fn chunk_verify_works() {
        let data = b"chunk data";
        let good_hash = sha256_hex(data);
        assert!(verify_chunk(data, &good_hash));
        assert!(!verify_chunk(b"other data", &good_hash));
    }
}