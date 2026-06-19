/// encrypt.rs — E2E шифрование для личного чата.
///
/// Схема: X25519 DH + BLAKE3 KDF → shared_key → XChaCha20-Poly1305
///
/// Почему XChaCha20-Poly1305:
/// - Аутентифицированное шифрование (AEAD) — защита от подмены
/// - 192-битный nonce — безопасно генерировать случайно (нет коллизий)
/// - Быстро на любом железе (нет зависимости от AES-NI)

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use blake3::derive_key;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::error::CryptoError;
use crate::keys::EncryptionKeypair;

/// Зашифрованное сообщение для передачи по сети.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Случайный nonce (24 байта, hex)
    pub nonce: String,
    /// Зашифрованные данные + тег аутентификации (hex)
    pub ciphertext: String,
    /// Публичный ключ отправителя X25519 (для DH на стороне получателя)
    pub sender_pubkey: String,
}

impl EncryptedMessage {
    /// Шифрует `plaintext` для получателя с публичным ключом `recipient_pub`.
    ///
    /// `our_keypair` — наш X25519 keypair (отправитель).
    pub fn encrypt(
        plaintext: &[u8],
        recipient_pub: &[u8; 32],
        our_keypair: &EncryptionKeypair,
    ) -> Result<Self, CryptoError> {
        let their_pub = X25519PublicKey::from(*recipient_pub);
        let shared_key = derive_symmetric_key(our_keypair, &their_pub);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared_key));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        Ok(Self {
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
            sender_pubkey: hex::encode(our_keypair.public_bytes()),
        })
    }

    /// Расшифровывает сообщение для получателя (`our_keypair`).
    pub fn decrypt(&self, our_keypair: &EncryptionKeypair) -> Result<Vec<u8>, CryptoError> {
        // Извлекаем публичный ключ отправителя
        let sender_bytes: [u8; 32] = hex::decode(&self.sender_pubkey)?
            .try_into()
            .map_err(|_| CryptoError::Decryption)?;
        let sender_pub = X25519PublicKey::from(sender_bytes);

        let shared_key = derive_symmetric_key(our_keypair, &sender_pub);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared_key));

        let nonce_bytes = hex::decode(&self.nonce)?;
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ct = hex::decode(&self.ciphertext)?;

        cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|_| CryptoError::Decryption)
    }
}

/// Вычисляет общий симметричный ключ через X25519 DH + BLAKE3 KDF.
fn derive_symmetric_key(our: &EncryptionKeypair, their_pub: &X25519PublicKey) -> [u8; 32] {
    let dh_output = our.diffie_hellman(their_pub);
    // KDF с контекстом — защита от cross-protocol атак
    derive_key("void-connect/e2e-chat/v1", &dh_output)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EncryptionKeypair;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let alice = EncryptionKeypair::generate();
        let bob   = EncryptionKeypair::generate();

        let plaintext = b"Hello, Bob!";

        // Алиса шифрует для Боба
        let encrypted = EncryptedMessage::encrypt(
            plaintext,
            &bob.public_bytes(),
            &alice,
        ).unwrap();

        let decrypted = encrypted.decrypt(&bob).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = EncryptionKeypair::generate();
        let bob   = EncryptionKeypair::generate();
        let eve   = EncryptionKeypair::generate(); // злоумышленник

        let encrypted = EncryptedMessage::encrypt(
            b"secret",
            &bob.public_bytes(),
            &alice,
        ).unwrap();

        // Ева пытается расшифровать — должна получить ошибку
        assert!(encrypted.decrypt(&eve).is_err());
    }
}