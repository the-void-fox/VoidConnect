//! Резолвер внутренней зоны `.void` — таблица подписанных имён.
//!
//! Хранит записи `имя → DnsRecord`, синхронизируемые по сети (подписанные
//! сообщения форвардятся через relay чата). Приём проверяет подпись и что
//! `signer == record.node_id` (нельзя заявить чужое имя), а конфликты имён
//! разрешает по принципу «первый зарегистрировал» ([`DnsRecord::wins_over`]).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use void_core::dns::DnsRecord;
use void_core::identity::NodeId;
use void_crypto::sign::SignedMessage;

use crate::error::WebError;

/// Запись таблицы вместе с её подписанным оригиналом (для перерассылки).
#[derive(Clone)]
struct Entry {
    record: DnsRecord,
    signed: SignedMessage,
}

/// Потокобезопасная таблица имён зоны `.void`. Клонируется дёшево (Arc внутри).
#[derive(Clone, Default)]
pub struct DnsRegistry {
    names: Arc<RwLock<HashMap<String, Entry>>>,
}

impl DnsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Применяет подписанную запись из сети (или нашу собственную).
    ///
    /// Шаги: проверка подписи → `signer == node_id` → разрешение конфликта.
    /// Возвращает `Some(record)`, если таблица изменилась (новое имя, более
    /// ранний владелец или обновление от того же владельца) — это и сигнал
    /// «переслать дальше». `None` — запись отвергнута или дубликат (гасит петли
    /// форвардинга).
    pub async fn apply_signed(&self, signed: &SignedMessage) -> Result<Option<DnsRecord>, WebError> {
        let record: DnsRecord = serde_json::from_slice(&signed.payload)
            .map_err(|e| WebError::Invalid(format!("DNS payload: {e}")))?;

        signed
            .verify()
            .map_err(|e| WebError::Invalid(format!("DNS подпись неверна: {e}")))?;

        if signed.signer != record.node_id.as_str() {
            return Err(WebError::Invalid("DNS: signer ≠ владелец записи".into()));
        }

        let mut map = self.names.write().await;
        match map.get(&record.name) {
            // Тот же владелец: обновление (refresh ip/port/времени). Идентичную
            // запись отбрасываем — это дедуп, гасящий петли форвардинга.
            Some(e) if e.record.node_id == record.node_id => {
                if e.record == record {
                    return Ok(None);
                }
            }
            // Другой владелец удерживает имя: принимаем только более раннего.
            Some(e) if !record.wins_over(&e.record) => {
                return Ok(None);
            }
            _ => {}
        }

        map.insert(record.name.clone(), Entry { record: record.clone(), signed: signed.clone() });
        Ok(Some(record))
    }

    /// Резолвит `имя` или `имя.void` в запись.
    pub async fn resolve(&self, name: &str) -> Option<DnsRecord> {
        let key = name.trim().trim_end_matches(".void");
        self.names.read().await.get(key).map(|e| e.record.clone())
    }

    /// Все известные записи.
    pub async fn list(&self) -> Vec<DnsRecord> {
        self.names.read().await.values().map(|e| e.record.clone()).collect()
    }

    /// Подписанные записи, принадлежащие `owner` — для перерассылки новым пирам.
    pub async fn mine(&self, owner: &NodeId) -> Vec<SignedMessage> {
        self.names
            .read()
            .await
            .values()
            .filter(|e| &e.record.node_id == owner)
            .map(|e| e.signed.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_core::dns::{DnsKind, DnsRecord};
    use void_crypto::keys::SigningKeypair;

    fn keypair(seed: u8) -> (Arc<SigningKeypair>, NodeId) {
        let kp = Arc::new(SigningKeypair::from_seed(&[seed; 32]).unwrap());
        let id = NodeId::from_public_key_bytes(&kp.public_bytes());
        (kp, id)
    }

    fn signed_record(kp: &SigningKeypair, owner: NodeId, name: &str, created_at: i64) -> SignedMessage {
        let rec = DnsRecord {
            name: name.into(),
            kind: DnsKind::Site,
            node_id: owner,
            ip: None,
            port: Some(8080),
            created_at,
        };
        SignedMessage::sign(rec.to_bytes(), kp).unwrap()
    }

    #[tokio::test]
    async fn claim_and_resolve() {
        let (kp, id) = keypair(1);
        let reg = DnsRegistry::new();
        let s = signed_record(&kp, id.clone(), "blog", 100);

        assert!(reg.apply_signed(&s).await.unwrap().is_some(), "первая заявка принимается");
        // дубликат → None (дедуп)
        assert!(reg.apply_signed(&s).await.unwrap().is_none());

        let r = reg.resolve("blog.void").await.unwrap();
        assert_eq!(r.node_id, id);
        assert_eq!(r.dns_name(), "blog.void");
        assert_eq!(reg.mine(&id).await.len(), 1);
    }

    #[tokio::test]
    async fn signer_must_own_record() {
        // Подписываем ключом A, но node_id в записи — чужой (B).
        let (kp_a, _a) = keypair(1);
        let (_kp_b, b) = keypair(2);
        let reg = DnsRegistry::new();
        let s = signed_record(&kp_a, b, "evil", 100);
        let res = reg.apply_signed(&s).await;
        assert!(matches!(res, Err(WebError::Invalid(_))), "подпись ≠ владелец → отказ");
        assert!(reg.resolve("evil").await.is_none());
    }

    #[tokio::test]
    async fn earlier_owner_wins_conflict() {
        let (kp1, id1) = keypair(1);
        let (kp2, id2) = keypair(2);
        let reg = DnsRegistry::new();

        // Сначала приходит поздняя заявка от id2.
        reg.apply_signed(&signed_record(&kp2, id2.clone(), "blog", 200)).await.unwrap();
        assert_eq!(reg.resolve("blog").await.unwrap().node_id, id2);

        // Затем — более ранняя от id1: вытесняет (первый зарегистрировал).
        let accepted = reg.apply_signed(&signed_record(&kp1, id1.clone(), "blog", 100)).await.unwrap();
        assert!(accepted.is_some());
        assert_eq!(reg.resolve("blog").await.unwrap().node_id, id1);

        // Повторная поздняя заявка id2 теперь отвергается.
        let rejected = reg.apply_signed(&signed_record(&kp2, id2, "blog", 200)).await.unwrap();
        assert!(rejected.is_none());
        assert_eq!(reg.resolve("blog").await.unwrap().node_id, id1);
    }

    #[tokio::test]
    async fn tampered_signature_rejected() {
        let (kp, id) = keypair(1);
        let reg = DnsRegistry::new();
        let mut s = signed_record(&kp, id, "blog", 100);
        s.payload[0] ^= 0xFF; // ломаем payload → подпись не сходится
        assert!(reg.apply_signed(&s).await.is_err());
    }
}
