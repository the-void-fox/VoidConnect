use crate::identity::NodeId;
use crate::sanitize::{display_text, is_hex64, truncate_chars};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Лимиты полей профиля, присланного по сети (см. [`PeerProfile::sanitize`]).
pub const MAX_PROFILE_NAME_CHARS: usize = 64;
pub const MAX_PROFILE_STATUS_CHARS: usize = 32;
pub const MAX_PROFILE_DESCRIPTION_CHARS: usize = 1000;
/// Лимит base64-строки аватара (~24 КБ) — профиль должен оставаться лёгким
/// для рассылки по relay чата.
pub const MAX_AVATAR_B64: usize = 24 * 1024;

/// Сервисы, которые может предоставлять узел
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Service {
    Chat,
    Storage,
    Web,
    Bootstrap,
}

/// Запись об известном узле сети.
/// Хранится в peer list и синхронизируется между узлами.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Публичный ключ = уникальный ID
    pub id: NodeId,

    /// Человекочитаемое имя (из профиля)
    pub name: String,

    pub ip: IpAddr,
    pub port: u16,

    /// Порт TCP-сервера общего чата.
    /// Обычно port + 2, но может быть любым — передаётся явно
    /// чтобы несколько экземпляров на одной машине не конфликтовали.
    pub chat_port: u16,

    /// Список активных сервисов этого узла
    pub services: Vec<Service>,

    /// Unix timestamp последнего появления в сети
    pub last_seen: i64,
}

/// Профиль узла — расширенные данные, которыми узлы обмениваются напрямую.
/// Не хранится в mDNS/UDP (слишком объёмно), передаётся через TCP-чат при подключении.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerProfile {
    pub node_id:     NodeId,
    pub name:        String,
    pub description: String,
    /// "online" | "away" | "busy" | "offline"
    pub status:      String,
    /// X25519 публичный ключ (hex) для E2E шифрования личных сообщений.
    /// None = старый узел без поддержки DM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enc_pubkey:  Option<String>,
    /// Узел запущен в публичном (bootstrap) режиме — точка входа в сеть.
    /// Самодекларация: влияет только на отображение бейджа, не на репутацию.
    #[serde(default)]
    pub is_bootstrap: bool,
    /// Аватар: маленький PNG (64×64), закодированный в base64. `None` — нет.
    /// Рассылается с профилем, поэтому держим компактным (лимит на стороне UI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_png: Option<String>,
    /// Момент подписи профиля (unix-миллисекунды). Версия старее известной
    /// не принимается — повтор старого профиля не откатит имя/аватар.
    #[serde(default)]
    pub updated_at: i64,
    /// Подпись Ed25519 владельца (`node_id`) над [`PeerProfile::signing_bytes`].
    /// Профиль без верной подписи узлы не принимают: иначе любой мог бы
    /// разослать «профиль Алисы» со своим именем и аватаром.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl PeerProfile {
    pub fn new(node_id: NodeId, name: String) -> Self {
        PeerProfile {
            node_id, name,
            description: String::new(),
            status: "online".into(),
            enc_pubkey: None,
            is_bootstrap: false,
            avatar_png: None,
            updated_at: 0,
            signature: None,
        }
    }

    /// Канонические байты для подписи: профиль без поля подписи (JSON в порядке
    /// полей структуры) с контекстом протокола.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let unsigned = PeerProfile { signature: None, ..self.clone() };
        let mut out = b"void-connect/profile/v1\n".to_vec();
        out.extend_from_slice(&serde_json::to_vec(&unsigned).expect("PeerProfile сериализуется"));
        out
    }

    /// Приводит профиль, пришедший из сети, к безопасным границам: обрезает
    /// текстовые поля, убирает управляющие и bidi-символы из имени и статуса
    /// (подмена отображаемого имени), отбрасывает слишком большой аватар
    /// (PNG-бомба) и ключ шифрования неверного формата.
    pub fn sanitize(&mut self) {
        self.name = display_text(&self.name, MAX_PROFILE_NAME_CHARS);
        self.status = display_text(&self.status, MAX_PROFILE_STATUS_CHARS);
        self.description = truncate_chars(&self.description, MAX_PROFILE_DESCRIPTION_CHARS);
        if self.avatar_png.as_ref().is_some_and(|a| a.len() > MAX_AVATAR_B64) {
            self.avatar_png = None;
        }
        if self.enc_pubkey.as_ref().is_some_and(|k| !is_hex64(k)) {
            self.enc_pubkey = None;
        }
    }
}

impl PeerInfo {
    /// Адрес для подключения в формате "ip:port"
    pub fn addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }

    /// Адрес чат-сервера в формате "ip:chat_port"
    pub fn chat_addr(&self) -> String {
        format!("{}:{}", self.ip, self.chat_port)
    }

    /// Считаем узел живым, если он был виден не позже 60 секунд назад
    pub fn is_alive(&self, now: i64) -> bool {
        now - self.last_seen < 60
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeId;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample(last_seen: i64) -> PeerInfo {
        PeerInfo {
            id:        NodeId("id".into()),
            name:      "bob".into(),
            ip:        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 7)),
            port:      7700,
            chat_port: 7702,
            services:  vec![Service::Chat],
            last_seen,
        }
    }

    #[test]
    fn addr_helpers_format_ip_and_ports() {
        let p = sample(0);
        assert_eq!(p.addr(), "192.168.0.7:7700");
        assert_eq!(p.chat_addr(), "192.168.0.7:7702");
    }

    #[test]
    fn is_alive_boundary() {
        let p = sample(1_000);
        assert!(p.is_alive(1_000));          // только что
        assert!(p.is_alive(1_059));          // 59 c назад — ещё жив
        assert!(!p.is_alive(1_060));         // ровно 60 c — уже нет
        assert!(!p.is_alive(2_000));
    }

    #[test]
    fn profile_new_defaults() {
        let prof = PeerProfile::new(NodeId("x".into()), "alice".into());
        assert_eq!(prof.status, "online");
        assert!(prof.description.is_empty());
        assert!(prof.enc_pubkey.is_none());
    }

    #[test]
    fn profile_omits_none_enc_pubkey_in_json() {
        // enc_pubkey = None не должен попадать в JSON (skip_serializing_if).
        let prof = PeerProfile::new(NodeId("x".into()), "alice".into());
        let json = serde_json::to_string(&prof).unwrap();
        assert!(!json.contains("enc_pubkey"));

        // А round-trip с Some — сохраняется.
        let mut prof2 = prof.clone();
        prof2.enc_pubkey = Some("deadbeef".into());
        let back: PeerProfile = serde_json::from_str(&serde_json::to_string(&prof2).unwrap()).unwrap();
        assert_eq!(back.enc_pubkey.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn sanitize_enforces_profile_limits() {
        let mut prof = PeerProfile::new(NodeId("x".into()), format!("Ali\u{202E}ce{}", "z".repeat(500)));
        prof.status = "online\n\n\n".into();
        prof.description = "d".repeat(5000);
        prof.avatar_png = Some("A".repeat(MAX_AVATAR_B64 + 1));
        prof.enc_pubkey = Some("../not-a-key".into());
        prof.sanitize();

        assert!(prof.name.starts_with("Alice"));
        assert_eq!(prof.name.chars().count(), MAX_PROFILE_NAME_CHARS);
        assert_eq!(prof.status, "online");
        assert_eq!(prof.description.chars().count(), MAX_PROFILE_DESCRIPTION_CHARS);
        assert!(prof.avatar_png.is_none(), "слишком большой аватар отбрасывается");
        assert!(prof.enc_pubkey.is_none(), "ключ неверного формата отбрасывается");
    }

    #[test]
    fn sanitize_keeps_valid_profile() {
        let mut prof = PeerProfile::new(NodeId("x".into()), "Боб".into());
        prof.enc_pubkey = Some("ab".repeat(32));
        prof.avatar_png = Some("iVBOR".into());
        let before = prof.clone();
        prof.sanitize();
        assert_eq!(prof, before);
    }
}
