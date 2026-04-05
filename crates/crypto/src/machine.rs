/// machine.rs — сбор аппаратного отпечатка устройства.
///
/// Отпечаток используется как соль при деривации seed ключевой пары,
/// привязывая ID аккаунта к конкретному железу.
///
/// Что входит в отпечаток:
///   1. MAC-адрес первого non-loopback сетевого интерфейса
///   2. Hostname машины
///   3. Опционально: дополнительные поля (OS, CPU info — расширяемо)
///
/// ВАЖНО: отпечаток НЕ является секретом сам по себе —
/// секретом является итоговый seed, полученный через HMAC.

use crate::error::CryptoError;
use mac_address::get_mac_address;
use gethostname::gethostname;
use sha2::{Sha256, Digest};

/// Аппаратный отпечаток устройства.
#[derive(Debug, Clone)]
pub struct MachineFingerprint {
    /// MAC-адрес (6 байт), или нули если недоступен
    pub mac: [u8; 6],
    /// Hostname (строка)
    pub hostname: String,
    /// Итоговый хэш всех компонентов
    pub digest: [u8; 32],
}

impl MachineFingerprint {
    /// Собирает отпечаток текущего устройства.
    pub fn collect() -> Result<Self, CryptoError> {
        // --- MAC-адрес ---
        let mac: [u8; 6] = match get_mac_address() {
            Ok(Some(addr)) => addr.bytes(),
            Ok(None) => {
                // Интерфейс есть, но MAC не получен (например, loopback)
                [0u8; 6]
            }
            Err(e) => {
                return Err(CryptoError::MachineFingerprint(format!(
                    "MAC address error: {e}"
                )))
            }
        };

        // --- Hostname ---
        let hostname = gethostname()
            .into_string()
            .unwrap_or_else(|_| "unknown-host".to_string());

        // --- Итоговый хэш (SHA-256 всех компонентов) ---
        //
        // Формат: MAC || '\0' || hostname || '\0' || VERSION_TAG
        // VERSION_TAG позволит в будущем менять формат без конфликтов
        let digest = Self::compute_digest(&mac, &hostname);

        Ok(Self { mac, hostname, digest })
    }

    fn compute_digest(mac: &[u8; 6], hostname: &str) -> [u8; 32] {
        const VERSION_TAG: &[u8] = b"void-connect-fp-v1";

        let mut hasher = Sha256::new();
        hasher.update(mac);
        hasher.update(b"\x00");
        hasher.update(hostname.as_bytes());
        hasher.update(b"\x00");
        hasher.update(VERSION_TAG);
        hasher.finalize().into()
    }

    /// Возвращает hex-строку отпечатка (для отображения / логов).
    pub fn to_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// Краткое описание для UI («MAC: aa:bb:... | host: …»).
    pub fn summary(&self) -> String {
        let mac_str = self.mac.map(|b| format!("{b:02x}")).join(":");
        format!("MAC: {} | hostname: {}", mac_str, self.hostname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        // Один и тот же вход → один и тот же хэш
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let hostname = "test-machine";
        let d1 = MachineFingerprint::compute_digest(&mac, hostname);
        let d2 = MachineFingerprint::compute_digest(&mac, hostname);
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_machines_differ() {
        let mac1 = [0xAA; 6];
        let mac2 = [0xBB; 6];
        let d1 = MachineFingerprint::compute_digest(&mac1, "host");
        let d2 = MachineFingerprint::compute_digest(&mac2, "host");
        assert_ne!(d1, d2);
    }
}