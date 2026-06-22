/// machine.rs — стабильный идентификатор устройства + аппаратный отпечаток.
///
/// Отпечаток используется как «соль» при деривации seed ключевой пары
/// (`identity.rs`), привязывая AccountId к конкретной машине: тот же
/// `machine.secret` на другом железе → другой seed → другой аккаунт.
///
/// Раньше отпечаток строился на MAC-адресе, но MAC нестабилен (рандомизация,
/// смена Wi-Fi↔Ethernet) — это молча меняло AccountId. Теперь основа —
/// `machine_id()` (стабильный идентификатор ОС), поэтому личность не «уезжает».

use crate::error::CryptoError;
use gethostname::gethostname;
use sha2::{Sha256, Digest};

/// Стабильный идентификатор машины — НЕ меняется при смене Wi-Fi/Ethernet и
/// рандомизации MAC. Основа привязки аккаунта к устройству.
///
/// Источник: Linux `/etc/machine-id` (или dbus), macOS `IOPlatformUUID`,
/// Windows `MachineGuid`. Запасной (более слабый) вариант — hostname.
pub fn machine_id() -> String {
    #[cfg(target_os = "linux")]
    {
        for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(p) {
                let s = s.trim();
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(uuid) = s
                .lines()
                .find(|l| l.contains("IOPlatformUUID"))
                .and_then(|l| l.split('"').nth(3))
            {
                if !uuid.is_empty() {
                    return uuid.to_string();
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("reg")
            .args(["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(guid) = s
                .lines()
                .find(|l| l.contains("MachineGuid"))
                .and_then(|l| l.split_whitespace().last())
            {
                if !guid.is_empty() {
                    return guid.to_string();
                }
            }
        }
    }
    // Запасной вариант (слабее, но детерминирован): hostname.
    gethostname().into_string().unwrap_or_else(|_| "unknown-machine".to_string())
}

/// Аппаратный отпечаток устройства (основан на стабильном machine-id).
#[derive(Debug, Clone)]
pub struct MachineFingerprint {
    /// Стабильный идентификатор машины.
    pub machine_id: String,
    /// Hostname (для диагностики/отображения; в digest НЕ входит).
    pub hostname: String,
    /// Итоговый хэш — детерминированная «соль» для деривации seed.
    pub digest: [u8; 32],
}

impl MachineFingerprint {
    /// Собирает отпечаток текущего устройства.
    pub fn collect() -> Result<Self, CryptoError> {
        let machine_id = machine_id();
        let hostname = gethostname()
            .into_string()
            .unwrap_or_else(|_| "unknown-host".to_string());
        let digest = Self::compute_digest(&machine_id);
        Ok(Self { machine_id, hostname, digest })
    }

    fn compute_digest(machine_id: &str) -> [u8; 32] {
        // Формат: machine_id || '\0' || VERSION_TAG.
        // v2: переход с MAC на machine-id. Новый тег намеренно даёт другой seed,
        // чем v1 — старые MAC-привязанные аккаунты не «оживут» молча.
        const VERSION_TAG: &[u8] = b"void-connect-fp-v2";

        let mut hasher = Sha256::new();
        hasher.update(machine_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(VERSION_TAG);
        hasher.finalize().into()
    }

    /// Hex-строка отпечатка (для отображения / логов).
    pub fn to_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// Краткое описание для UI/логов («machine-id: … | hostname: …»).
    pub fn summary(&self) -> String {
        let id_short: String = self.machine_id.chars().take(12).collect();
        format!("machine-id: {}… | hostname: {}", id_short, self.hostname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        // Один и тот же machine-id → один и тот же хэш.
        let d1 = MachineFingerprint::compute_digest("abc-123-id");
        let d2 = MachineFingerprint::compute_digest("abc-123-id");
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_machines_differ() {
        let d1 = MachineFingerprint::compute_digest("machine-A");
        let d2 = MachineFingerprint::compute_digest("machine-B");
        assert_ne!(d1, d2);
    }

    #[test]
    fn machine_id_is_nonempty() {
        // На любой платформе должен вернуться непустой идентификатор (хотя бы fallback).
        assert!(!machine_id().is_empty());
    }
}
