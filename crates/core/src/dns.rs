//! Внутренний DNS зоны `.void`: записи `имя.void` → узел/сайт.
//!
//! Каждая запись подписывается ключом владельца (`signer == node_id`), поэтому
//! заявить чужое имя нельзя. Конфликт имён разрешается по принципу «кто первым
//! известен этому узлу»: метки времени самозаявляемы, и правило «самая ранняя
//! `created_at`» позволяло отобрать любое имя, указав дату из прошлого.
//! Записи рассылаются по сети так же, как репутация/манифесты — через relay
//! общего чата (как подписанные сообщения).

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// Зона внутренних имён.
pub const ZONE: &str = ".void";

/// Что именует запись.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsKind {
    /// Узел сети (`vasya.void` → узел Васи).
    Node,
    /// Сайт, размещённый узлом (`blog.void`).
    Site,
}

/// Запись внутреннего DNS. Подписывается целиком (см. [`DnsRecord::to_bytes`]);
/// подпись привязывает имя к `node_id` и времени регистрации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Метка без зоны: `vasya` (резолвится как `vasya.void`).
    pub name: String,
    pub kind: DnsKind,
    /// Владелец записи. Должен совпадать с подписантом (`signer`).
    pub node_id: NodeId,
    /// IP узла (для `Node`/прямого доступа), если известен.
    pub ip: Option<String>,
    /// Порт сервиса (HTTP-порт сайта / порт узла), если применимо.
    pub port: Option<u16>,
    /// Unix-таймстемп регистрации (информационно; конфликты им не решаются).
    pub created_at: i64,
    /// Версия записи (unix-миллисекунды), растёт с каждым обновлением владельца.
    /// Принимается только более новая версия того же владельца — повтор старой
    /// подписанной записи не воскресит удалённое имя и не откатит адрес.
    #[serde(default)]
    pub updated_at: i64,
    /// Надгробие: владелец отозвал имя (удалил сайт). Запись держит имя за собой
    /// (никто другой его не займёт), но не резолвится и скрыта из списков.
    /// `#[serde(default)]` — совместимость со старыми записями без поля.
    #[serde(default)]
    pub deleted: bool,
}

impl DnsRecord {
    /// Полное имя в зоне `.void`.
    pub fn dns_name(&self) -> String {
        format!("{}{}", self.name, ZONE)
    }

    /// Канонические байты для подписи/проверки (детерминированный JSON).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("DnsRecord serialization failed")
    }

}

/// Нормализует произвольную строку в DNS-метку зоны `.void`:
/// нижний регистр, пробелы → `-`, остаются только `[a-z0-9-]`, схлопывает и
/// обрезает `-`. Возвращает `None`, если после нормализации ничего не осталось.
pub fn normalize_name(input: &str) -> Option<String> {
    // отбрасываем зону, если её передали целиком
    let base = input.trim().trim_end_matches(ZONE);
    let mut out = String::with_capacity(base.len());
    let mut prev_dash = false;
    for ch in base.chars() {
        let c = ch.to_ascii_lowercase();
        let mapped = if c.is_ascii_alphanumeric() {
            prev_dash = false;
            Some(c)
        } else if c == '-' || c == '_' || c == ' ' {
            if prev_dash { None } else { prev_dash = true; Some('-') }
        } else {
            None
        };
        if let Some(m) = mapped {
            out.push(m);
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&[seed; 32])
    }

    fn rec(name: &str, owner: NodeId, created_at: i64) -> DnsRecord {
        DnsRecord {
            name: name.into(),
            kind: DnsKind::Node,
            node_id: owner,
            ip: Some("192.168.0.5".into()),
            port: Some(7700),
            created_at,
            updated_at: created_at,
            deleted: false,
        }
    }

    #[test]
    fn dns_name_and_serde_roundtrip() {
        let r = rec("vasya", node(3), 100);
        assert_eq!(r.dns_name(), "vasya.void");
        let back: DnsRecord = serde_json::from_slice(&r.to_bytes()).unwrap();
        assert_eq!(back, r);
        // kind сериализуется в нижнем регистре
        assert!(String::from_utf8_lossy(&r.to_bytes()).contains("\"node\""));
    }

    #[test]
    fn normalize_various() {
        assert_eq!(normalize_name("Vasya"), Some("vasya".into()));
        assert_eq!(normalize_name("My Cool Blog"), Some("my-cool-blog".into()));
        assert_eq!(normalize_name("  --weird__name!! "), Some("weird-name".into()));
        assert_eq!(normalize_name("blog.void"), Some("blog".into()));
        assert_eq!(normalize_name("***"), None);
        assert_eq!(normalize_name(""), None);
    }
}
