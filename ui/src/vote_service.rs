//! Состояние и персистентность подсистемы голосований (UI-сторона).
//!
//! Хранит на диске результаты исполненных решений (баны, проголосованные каналы,
//! удалённые файлы) рядом с профилем, чтобы они переживали перезапуск. Сам
//! приём/подсчёт/синхронизация — в backend (использует крейт `void-vote`).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use void_vote::{Outcome, ProposalKind};

/// Канал чата, добавленный голосованием (мерджится со встроенными `CHANNELS`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDef {
    pub id: String,
    pub name: String,
    pub icon: String,
}

/// Снимок предложения для UI: тип/цель, прогресс подсчёта, мой голос, статус.
#[derive(Debug, Clone)]
pub struct ProposalView {
    pub id: String,
    pub kind: ProposalKind,
    /// Человекочитаемое описание («Бан узла 1a2b…», «Добавить канал …»).
    pub label: String,
    pub proposer_short: String,
    pub created_at: i64,
    /// Момент закрытия окна (created_at + 3 суток).
    pub closes_at: i64,
    pub open: bool,
    pub yes: usize,
    pub no: usize,
    pub eligible: usize,
    pub high: usize,
    pub outcome: Outcome,
    /// Мой голос по предложению (`Some(true/false)`), если голосовал.
    pub my_vote: Option<bool>,
    /// Решение уже финализировано/исполнено (closed_at проставлен).
    pub finalized: bool,
}

/// Человекочитаемое описание предложения для UI.
pub fn kind_label(kind: &ProposalKind) -> String {
    fn short(s: &str) -> &str {
        &s[..8.min(s.len())]
    }
    match kind {
        ProposalKind::BanUser { target } => format!("Бан узла {}…", short(target)),
        ProposalKind::UnbanUser { target } => format!("Разбан узла {}…", short(target)),
        ProposalKind::AddChannel { name, .. } => format!("Добавить канал «{}»", name),
        ProposalKind::RemoveFile { file_id } => format!("Удалить файл {}…", short(file_id)),
    }
}

// ─── Персистентность (JSON рядом с профилем) ─────────────────────────────────

fn bans_path() -> PathBuf {
    crate::profile_store::profile_dir().join("bans.json")
}
fn channels_path() -> PathBuf {
    crate::profile_store::profile_dir().join("voted_channels.json")
}
fn removed_path() -> PathBuf {
    crate::profile_store::profile_dir().join("removed_files.json")
}

/// Баны: NodeId (hex) → unix-таймстемп истечения. Просроченные отбрасываем при загрузке.
pub fn load_bans() -> HashMap<String, i64> {
    let now = chrono::Utc::now().timestamp();
    let mut map: HashMap<String, i64> = std::fs::read_to_string(bans_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    map.retain(|_, until| *until > now);
    map
}

pub fn save_bans(map: &HashMap<String, i64>) {
    if let Ok(json) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write(bans_path(), json);
    }
}

pub fn load_voted_channels() -> Vec<ChannelDef> {
    std::fs::read_to_string(channels_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_voted_channels(channels: &[ChannelDef]) {
    if let Ok(json) = serde_json::to_string_pretty(channels) {
        let _ = std::fs::write(channels_path(), json);
    }
}

pub fn load_removed_files() -> HashSet<String> {
    std::fs::read_to_string(removed_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_removed_files(set: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string_pretty(set) {
        let _ = std::fs::write(removed_path(), json);
    }
}
