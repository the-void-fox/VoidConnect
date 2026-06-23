//! Манифест сайта — описание простого сайта, размещённого в сети.
//!
//! Сайт — это набор файлов (HTML/CSS/JS/картинки), каждый из которых хранится
//! в `void-storage` как обычный файл (со своим `file_id`). Манифест связывает
//! относительные пути с `file_id` и даёт сайту имя в зоне `.void`.
//!
//! Манифест рассылается по сети так же, как манифесты файлов (через relay чата),
//! чтобы другие узлы могли открыть сайт, скачав его файлы у владельца.

use serde::{Deserialize, Serialize};

use crate::identity::NodeId;

/// Один файл сайта: относительный путь → `file_id` в хранилище.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteEntry {
    /// Относительный путь, напр. `index.html`, `css/style.css`.
    pub path: String,
    /// Идентификатор файла в `void-storage`.
    pub file_id: String,
    pub size_bytes: i64,
}

/// Манифест сайта.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteManifest {
    /// SHA-256 от содержимого манифеста.
    pub site_id: String,
    /// Имя сайта без зоны (`mysite` → `mysite.void`).
    pub name: String,
    pub owner: NodeId,
    /// Файлы сайта.
    pub entries: Vec<SiteEntry>,
    /// Время публикации (unix-таймстемп).
    pub created_at: i64,
}

/// Подписанное «надгробие» сайта: владелец отзывает публикацию.
///
/// Рассылается по сети как [`SiteManifest`] (через relay чата), но подписывается
/// ключом владельца (`signer == owner`). Получив надгробие, узлы удаляют сайт из
/// реестра, стирают кэшированные файлы и больше не принимают анонсы того же
/// сайта с `created_at <= revoked_at` (подавление «воскрешения»). Имя остаётся
/// зарезервированным за владельцем (DNS-запись помечается удалённой, но держит
/// имя по принципу «первый зарегистрировал»).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteRevocation {
    /// Имя сайта без зоны (`blog`).
    pub name: String,
    /// Владелец — должен совпадать с подписантом (`signer`).
    pub owner: NodeId,
    /// Момент удаления (unix). Подавляет анонсы с `created_at <= revoked_at`.
    pub revoked_at: i64,
}

impl SiteRevocation {
    /// Канонические байты для подписи/проверки (детерминированный JSON).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SiteRevocation serialization failed")
    }
}

impl SiteManifest {
    /// Полное DNS-имя сайта в зоне `.void`.
    pub fn dns_name(&self) -> String {
        format!("{}.void", self.name)
    }

    /// Находит запись по нормализованному пути (ведущие `/` отбрасываются).
    pub fn entry(&self, path: &str) -> Option<&SiteEntry> {
        let needle = path.trim_start_matches('/');
        self.entries.iter().find(|e| e.path == needle)
    }

    /// Запись стартовой страницы (`index.html`), если есть.
    pub fn index(&self) -> Option<&SiteEntry> {
        self.entry("index.html")
    }

    /// Суммарный размер сайта в байтах.
    pub fn total_size(&self) -> i64 {
        self.entries.iter().map(|e| e.size_bytes).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SiteManifest {
        SiteManifest {
            site_id: "abc".into(),
            name: "blog".into(),
            owner: NodeId::from_public_key_bytes(&[3u8; 32]),
            entries: vec![
                SiteEntry { path: "index.html".into(), file_id: "f1".into(), size_bytes: 100 },
                SiteEntry { path: "css/style.css".into(), file_id: "f2".into(), size_bytes: 40 },
            ],
            created_at: 0,
        }
    }

    #[test]
    fn lookup_and_helpers() {
        let m = manifest();
        assert_eq!(m.dns_name(), "blog.void");
        assert_eq!(m.total_size(), 140);
        assert_eq!(m.index().unwrap().file_id, "f1");
        // ведущий слэш нормализуется
        assert_eq!(m.entry("/css/style.css").unwrap().file_id, "f2");
        assert!(m.entry("missing.js").is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let m = manifest();
        let back: SiteManifest = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn revocation_roundtrip() {
        let rev = SiteRevocation {
            name: "blog".into(),
            owner: NodeId::from_public_key_bytes(&[3u8; 32]),
            revoked_at: 1700,
        };
        let back: SiteRevocation = serde_json::from_slice(&rev.to_bytes()).unwrap();
        assert_eq!(back, rev);
    }
}
