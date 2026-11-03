//! Поручительство — подписанная запись «я ручаюсь за этот ключ».

use serde::{Deserialize, Serialize};
use void_core::identity::NodeId;
use void_core::sanitize::is_hex64;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;

use crate::error::TrustError;

/// Контекст подписи: подписанные данные другого типа не выдать за поручительство.
const VOUCH_CONTEXT: &[u8] = b"void-connect/vouch/v1\n";

/// Вид поручительства.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VouchKind {
    /// «Сверил код безопасности лично».
    Personal,
    /// «Поприветствовал новичка» (роль встречающего) — слабое поручительство.
    Greeter,
}

impl VouchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            VouchKind::Personal => "personal",
            VouchKind::Greeter => "greeter",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "personal" => Some(VouchKind::Personal),
            "greeter" => Some(VouchKind::Greeter),
            _ => None,
        }
    }
}

/// Поручительство `voucher → subject`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vouch {
    pub voucher: NodeId,
    pub subject: NodeId,
    pub kind: VouchKind,
    /// Версия записи (unix-мс). Принимается только более новая версия пары
    /// (voucher, subject) — повтор старой записи не отменит отзыв.
    pub updated_at: i64,
    /// «Больше не ручаюсь».
    pub revoked: bool,
}

impl Vouch {
    /// Подписываемые байты: контекст + JSON записи.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = VOUCH_CONTEXT.to_vec();
        out.extend_from_slice(&serde_json::to_vec(self).expect("Vouch сериализуется"));
        out
    }

    /// Подписывает запись ключом поручителя (он должен совпадать с `voucher`).
    pub fn sign(&self, kp: &SigningKeypair) -> Result<SignedMessage, TrustError> {
        if NodeId::from_public_key_bytes(&kp.public_bytes()) != self.voucher {
            return Err(TrustError::Invalid("ключ подписи не принадлежит поручителю".into()));
        }
        SignedMessage::sign(self.payload(), kp).map_err(|e| TrustError::Invalid(format!("{e:?}")))
    }

    /// Проверяет подписанную запись из сети и возвращает поручительство:
    /// контекст, подпись, `signer == voucher`, ID в формате hex64, не за себя.
    pub fn from_signed(signed: &SignedMessage) -> Result<Self, TrustError> {
        let body = signed
            .payload
            .strip_prefix(VOUCH_CONTEXT)
            .ok_or_else(|| TrustError::Invalid("не поручительство (нет контекста)".into()))?;
        let vouch: Vouch = serde_json::from_slice(body)
            .map_err(|e| TrustError::Invalid(format!("формат: {e}")))?;
        signed
            .verify()
            .map_err(|_| TrustError::Invalid("подпись неверна".into()))?;
        if signed.signer != vouch.voucher.as_str() {
            return Err(TrustError::Invalid("подписант ≠ поручитель".into()));
        }
        if !is_hex64(vouch.voucher.as_str()) || !is_hex64(vouch.subject.as_str()) {
            return Err(TrustError::Invalid("ID не hex64".into()));
        }
        if vouch.voucher == vouch.subject {
            return Err(TrustError::Invalid("поручительство за себя".into()));
        }
        Ok(vouch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    fn id(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&kp(seed).public_bytes())
    }

    fn vouch(from: u8, to: u8) -> Vouch {
        Vouch { voucher: id(from), subject: id(to), kind: VouchKind::Personal, updated_at: 1, revoked: false }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let v = vouch(1, 2);
        let signed = v.sign(&kp(1)).unwrap();
        assert_eq!(Vouch::from_signed(&signed).unwrap(), v);
    }

    #[test]
    fn cannot_sign_for_someone_else() {
        assert!(vouch(1, 2).sign(&kp(3)).is_err());
    }

    #[test]
    fn forged_or_tampered_rejected() {
        // Злоумышленник подписывает своим ключом запись «от имени» узла 1.
        let forged = SignedMessage::sign(vouch(1, 9).payload(), &kp(9)).unwrap();
        assert!(Vouch::from_signed(&forged).is_err(), "подписант ≠ поручитель");

        let mut tampered = vouch(1, 2).sign(&kp(1)).unwrap();
        let n = tampered.payload.len();
        tampered.payload[n - 3] ^= 1;
        assert!(Vouch::from_signed(&tampered).is_err(), "подмена после подписи");
    }

    #[test]
    fn self_vouch_and_foreign_payload_rejected() {
        assert!(Vouch::from_signed(&vouch(1, 1).sign(&kp(1)).unwrap()).is_err());
        // Подписанный JSON без контекста поручительства (как у DNS-записей).
        let other = SignedMessage::sign(serde_json::to_vec(&vouch(1, 2)).unwrap(), &kp(1)).unwrap();
        assert!(Vouch::from_signed(&other).is_err());
    }
}
