/// sign.rs — подпись сообщений и верификация.
///
/// Используется для:
/// - Сообщений в общем чате (защита от ARP-spoofing)
/// - Профилей и DNS-записей
/// - Чанков хранилища (верификация источника)

use ed25519_dalek::{Signer, Verifier, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::keys::SigningKeypair;

/// Подписанное сообщение — данные + подпись + публичный ключ подписанта.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    /// Исходные данные (произвольные байты / JSON)
    pub payload: Vec<u8>,
    /// Подпись Ed25519 (64 байта, hex)
    pub signature: String,
    /// Публичный ключ подписанта (32 байта, hex) — совпадает с AccountId
    pub signer: String,
}

impl SignedMessage {
    /// Подписывает `payload` ключом из `keypair`.
    pub fn sign(payload: Vec<u8>, keypair: &SigningKeypair) -> Result<Self, CryptoError> {
        let signature = keypair
            .signing_key()
            .sign(&payload);

        Ok(Self {
            payload,
            signature: hex::encode(signature.to_bytes()),
            signer: hex::encode(keypair.public_bytes()),
        })
    }

    /// Верифицирует подпись. Возвращает `()` при успехе или ошибку.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let sig_bytes = hex::decode(&self.signature)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            CryptoError::Signing("Неверная длина подписи".into())
        })?;

        let key_bytes = hex::decode(&self.signer)?;
        let key_arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
            CryptoError::KeyGeneration("Неверная длина ключа".into())
        })?;

        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(&self.payload, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Верифицирует подпись и возвращает payload как `&[u8]`.
    pub fn verify_and_payload(&self) -> Result<&[u8], CryptoError> {
        self.verify()?;
        Ok(&self.payload)
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let keypair = SigningKeypair::generate();
        let msg = SignedMessage::sign(b"hello void".to_vec(), &keypair).unwrap();
        assert!(msg.verify().is_ok());
    }

    #[test]
    fn tampered_payload_fails() {
        let keypair = SigningKeypair::generate();
        let mut msg = SignedMessage::sign(b"hello".to_vec(), &keypair).unwrap();
        msg.payload[0] ^= 0xFF; // повреждаем данные
        assert!(msg.verify().is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        let mut msg = SignedMessage::sign(b"hello".to_vec(), &kp1).unwrap();
        // Подменяем ключ подписанта
        msg.signer = hex::encode(kp2.public_bytes());
        assert!(msg.verify().is_err());
    }
}