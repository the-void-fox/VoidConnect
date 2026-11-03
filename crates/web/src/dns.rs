//! Резолвер внутренней зоны `.void` — таблица подписанных имён.
//!
//! Хранит записи `имя → DnsRecord`, синхронизируемые по сети (подписанные
//! сообщения форвардятся через relay чата). Приём проверяет подпись и что
//! `signer == record.node_id` (нельзя заявить чужое имя). Конфликт имён:
//! имя остаётся за владельцем, которого этот узел узнал первым — «более ранняя»
//! заявка ничего не доказывает, ведь `created_at` указывает сам заявитель.
//! Обновления того же владельца принимаются только с большим `updated_at`.
//! Таблицу можно сохранить и загрузить ([`DnsRegistry::export`] /
//! [`DnsRegistry::import`]), чтобы занятые имена переживали перезапуск.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use void_core::dns::{normalize_name, DnsRecord};
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
    /// Шаги: проверка подписи → `signer == node_id` → имя нормализовано →
    /// разрешение конфликта. Возвращает `Some(record)`, если таблица изменилась
    /// (новое имя или более свежая версия того же владельца) — это и сигнал
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
        if normalize_name(&record.name).as_deref() != Some(record.name.as_str()) {
            return Err(WebError::Invalid(format!("DNS: недопустимое имя {:?}", record.name)));
        }

        let mut map = self.names.write().await;
        match map.get(&record.name) {
            // Тот же владелец: только более свежая версия. Повтор старой
            // подписанной записи не воскресит удалённое имя и не откатит адрес;
            // идентичная запись — дедуп, гасящий петли форвардинга.
            Some(e) if e.record.node_id == record.node_id => {
                if record.updated_at <= e.record.updated_at {
                    return Ok(None);
                }
            }
            // Имя уже за другим владельцем — остаётся за ним.
            Some(e) => {
                tracing::debug!(
                    "DNS: '{}' уже за {}, заявка {} отклонена",
                    record.name, e.record.node_id, record.node_id
                );
                return Ok(None);
            }
            None => {}
        }

        map.insert(record.name.clone(), Entry { record: record.clone(), signed: signed.clone() });
        Ok(Some(record))
    }

    /// Резолвит `имя` или `имя.void` в запись. Удалённые (надгробия) не
    /// резолвятся — имя зарезервировано за владельцем, но не указывает на сервис.
    pub async fn resolve(&self, name: &str) -> Option<DnsRecord> {
        let key = name.trim().trim_end_matches(".void");
        self.names.read().await.get(key)
            .map(|e| e.record.clone())
            .filter(|r| !r.deleted)
    }

    /// Все известные записи, кроме надгробий (для отображения списка имён).
    pub async fn list(&self) -> Vec<DnsRecord> {
        self.names.read().await.values()
            .map(|e| e.record.clone())
            .filter(|r| !r.deleted)
            .collect()
    }

    /// Все подписанные записи (включая надгробия) — для сохранения на диск.
    pub async fn export(&self) -> Vec<SignedMessage> {
        self.names.read().await.values().map(|e| e.signed.clone()).collect()
    }

    /// Загружает сохранённые записи, проверяя каждую так же, как пришедшую из
    /// сети (подпорченный файл не подсунет чужое имя). Возвращает число принятых.
    pub async fn import(&self, records: &[SignedMessage]) -> usize {
        let mut accepted = 0;
        for signed in records {
            if let Ok(Some(_)) = self.apply_signed(signed).await {
                accepted += 1;
            }
        }
        accepted
    }

    /// Подписанные записи, принадлежащие `owner` — для перерассылки новым пирам.
    /// Включает надгробия: их тоже распространяем, чтобы офлайн-узлы узнали об
    /// удалении имени.
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
        signed_record_del(kp, owner, name, created_at, false)
    }

    fn signed_record_del(kp: &SigningKeypair, owner: NodeId, name: &str, created_at: i64, deleted: bool) -> SignedMessage {
        let updated_at = created_at * 10 + deleted as i64; // надгробие новее записи
        signed_record_v(kp, owner, name, created_at, updated_at, deleted)
    }

    fn signed_record_v(
        kp: &SigningKeypair, owner: NodeId, name: &str, created_at: i64, updated_at: i64, deleted: bool,
    ) -> SignedMessage {
        let rec = DnsRecord {
            name: name.into(),
            kind: DnsKind::Site,
            node_id: owner,
            ip: None,
            port: Some(8080),
            created_at,
            updated_at,
            deleted,
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

    /// Имя остаётся за первым известным владельцем: заявка с датой «из прошлого»
    /// (её указывает сам заявитель) имя не отбирает.
    #[tokio::test]
    async fn backdated_claim_cannot_steal_name() {
        let (kp1, id1) = keypair(1);
        let (kp2, id2) = keypair(2);
        let reg = DnsRegistry::new();

        reg.apply_signed(&signed_record(&kp1, id1.clone(), "blog", 200)).await.unwrap();
        let stolen = reg.apply_signed(&signed_record(&kp2, id2, "blog", 0)).await.unwrap();
        assert!(stolen.is_none(), "заявка задним числом отклонена");
        assert_eq!(reg.resolve("blog").await.unwrap().node_id, id1);
    }

    /// Повтор старой подписанной записи владельца не воскрешает удалённое имя.
    #[tokio::test]
    async fn replayed_old_record_cannot_undelete() {
        let (kp, id) = keypair(1);
        let reg = DnsRegistry::new();
        let original = signed_record_v(&kp, id.clone(), "blog", 100, 1000, false);
        reg.apply_signed(&original).await.unwrap();
        reg.apply_signed(&signed_record_v(&kp, id, "blog", 100, 2000, true)).await.unwrap();
        assert!(reg.resolve("blog").await.is_none());

        assert!(reg.apply_signed(&original).await.unwrap().is_none(), "старая версия отвергнута");
        assert!(reg.resolve("blog").await.is_none(), "имя осталось удалённым");
    }

    #[tokio::test]
    async fn unnormalized_name_rejected() {
        let (kp, id) = keypair(1);
        let reg = DnsRegistry::new();
        assert!(reg.apply_signed(&signed_record(&kp, id, "x&calc", 1)).await.is_err());
    }

    /// Сохранённая таблица восстанавливается: имя остаётся за прежним владельцем.
    #[tokio::test]
    async fn export_import_roundtrip_keeps_owner() {
        let (kp1, id1) = keypair(1);
        let (kp2, id2) = keypair(2);
        let reg = DnsRegistry::new();
        reg.apply_signed(&signed_record(&kp1, id1.clone(), "blog", 100)).await.unwrap();
        let saved = reg.export().await;

        let restored = DnsRegistry::new();
        assert_eq!(restored.import(&saved).await, 1);
        restored.apply_signed(&signed_record(&kp2, id2, "blog", 0)).await.unwrap();
        assert_eq!(restored.resolve("blog").await.unwrap().node_id, id1);
    }

    #[tokio::test]
    async fn revocation_hides_name_but_keeps_reservation() {
        let (kp, id) = keypair(1);
        let reg = DnsRegistry::new();

        // Владелец заявляет имя, затем отзывает (надгробие с тем же created_at).
        reg.apply_signed(&signed_record(&kp, id.clone(), "blog", 100)).await.unwrap();
        assert!(reg.resolve("blog").await.is_some());

        let tomb = signed_record_del(&kp, id.clone(), "blog", 100, true);
        assert!(reg.apply_signed(&tomb).await.unwrap().is_some(), "надгробие принято (другой контент)");

        // Имя больше не резолвится и пропало из списка…
        assert!(reg.resolve("blog").await.is_none());
        assert!(reg.list().await.is_empty());
        // …но надгробие распространяется дальше (mine его отдаёт).
        assert_eq!(reg.mine(&id).await.len(), 1);

        // Чужой не может занять зарезервированное имя более поздней заявкой.
        let (kp2, id2) = keypair(2);
        assert!(reg.apply_signed(&signed_record(&kp2, id2, "blog", 200)).await.unwrap().is_none());
        assert!(reg.resolve("blog").await.is_none());

        // Владелец может переопубликовать (un-delete) тем же именем — более новой версией.
        reg.apply_signed(&signed_record(&kp, id.clone(), "blog", 300)).await.unwrap();
        assert_eq!(reg.resolve("blog").await.unwrap().node_id, id);
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
