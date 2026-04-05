/// keys.rs — ключевые пары для подписей (Ed25519) и шифрования (X25519).

use crate::error::CryptoError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

// ---------------------------------------------------------------------------
// SigningKeypair — Ed25519 (подписи сообщений, профилей, DNS-записей)
// ---------------------------------------------------------------------------

/// Пара ключей Ed25519 для подписи.
#[derive(ZeroizeOnDrop)]
pub struct SigningKeypair {
    #[zeroize(skip)]
    pub verifying_key: VerifyingKey,
    signing_key: SigningKey,
}

impl SigningKeypair {
    /// Генерирует случайную пару ключей.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Восстанавливает пару из 32-байтового seed (детерминированно).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    /// Приватный ключ в виде байт (для сохранения в БД / файл).
    /// Никогда не передавать по сети!
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Публичный ключ в виде байт (ID аккаунта / для передачи пирам).
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

// ---------------------------------------------------------------------------
// EncryptionKeypair — X25519 (Diffie-Hellman для E2E шифрования)
// ---------------------------------------------------------------------------

/// Пара ключей X25519 для Диффи-Хеллмана (E2E чаты, зашифрованное хранилище).
#[derive(ZeroizeOnDrop)]
pub struct EncryptionKeypair {
    secret: StaticSecret,
    #[zeroize(skip)]
    pub public: X25519PublicKey,
}

impl EncryptionKeypair {
    /// Генерирует случайную пару.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Восстанавливает из 32-байтового seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*seed);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// DH shared secret с публичным ключом другого пира.
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

// ---------------------------------------------------------------------------
// Сериализуемые публичные ключи (для обмена с пирами)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeys {
    /// Ed25519 публичный ключ — используется как AccountId
    pub signing: String,   // hex
    /// X25519 публичный ключ — для E2E шифрования
    pub encryption: String, // hex
}

impl PublicKeys {
    pub fn new(signing: &[u8; 32], encryption: &[u8; 32]) -> Self {
        Self {
            signing: hex::encode(signing),
            encryption: hex::encode(encryption),
        }
    }

    pub fn signing_bytes(&self) -> Result<[u8; 32], CryptoError> {
        let bytes = hex::decode(&self.signing)?;
        bytes.try_into().map_err(|_| {
            CryptoError::KeyGeneration("Неверная длина signing key".into())
        })
    }

    pub fn encryption_bytes(&self) -> Result<[u8; 32], CryptoError> {
        let bytes = hex::decode(&self.encryption)?;
        bytes.try_into().map_err(|_| {
            CryptoError::KeyGeneration("Неверная длина encryption key".into())
        })
    }
}