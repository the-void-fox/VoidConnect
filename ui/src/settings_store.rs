//! Постоянные настройки приложения (`settings.json` в папке данных).
//!
//! Позволяют включать публичный режим и задавать bootstrap-узлы из интерфейса,
//! не передавая аргументы командной строки. Аргументы CLI имеют приоритет над
//! сохранёнными настройками (см. `main.rs`), поэтому старые сценарии запуска не
//! ломаются.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Базовый порт по умолчанию (от него отсчитываются чат/DM/сайты/bootstrap/relay).
pub const DEFAULT_BASE_PORT: u16 = 7700;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// Публичный режим: поднять bootstrap/relay-сервер, UPnP-проброс, STUN.
    /// Делает узел точкой входа в глобальную сеть.
    pub public_mode: bool,
    /// Адреса bootstrap-узлов (`host:base_port`) для подключения к глобальной сети.
    pub bootstrap_nodes: Vec<String>,
    /// Базовый порт.
    pub base_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            public_mode:     false,
            bootstrap_nodes: Vec::new(),
            base_port:       DEFAULT_BASE_PORT,
        }
    }
}

fn settings_path() -> PathBuf {
    crate::profile_store::profile_dir().join("settings.json")
}

/// Загружает настройки с диска. При отсутствии/ошибке — значения по умолчанию.
pub fn load() -> Settings {
    match std::fs::read_to_string(settings_path()) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_)   => Settings::default(),
    }
}

/// Сохраняет настройки на диск (в папку данных).
pub fn save(s: &Settings) -> std::io::Result<()> {
    let data = serde_json::to_string_pretty(s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(settings_path(), data)
}
