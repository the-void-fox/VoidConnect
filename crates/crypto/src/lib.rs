/// void-crypto — криптографическая основа Void Connect.
///
/// Модули:
/// - `identity`  — генерация и хранение ID аккаунта, привязанного к железу
/// - `keys`      — работа с ключевыми парами (Ed25519 / X25519)
/// - `sign`      — подписи сообщений и верификация
/// - `encrypt`   — E2E шифрование (X25519 + XSalsa20-Poly1305)
/// - `hash`      — SHA-256, BLAKE3 для чанков и прочего
/// - `machine`   — сбор аппаратных отпечатков устройства
/// - `error`     — единый тип ошибок крейта

pub mod error;
pub mod hash;
pub mod identity;
pub mod keys;
pub mod machine;
pub mod sign;
pub mod encrypt;

pub use error::CryptoError;
pub use identity::{AccountId, Identity};
pub use keys::{SigningKeypair, EncryptionKeypair};