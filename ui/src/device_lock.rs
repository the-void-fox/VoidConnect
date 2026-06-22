//! Привязка аккаунта к устройству (anti-transfer).
//!
//! Цель — чтобы аккаунт нельзя было просто скопировать на другой ПК. Помимо
//! криптографической привязки (ключи выводятся из отпечатка железа в
//! `void_crypto::identity`), здесь добавлена ЯВНАЯ проверка с понятным
//! сообщением: при первом запуске записываем стабильный `machine-id` в файл
//! `device.bind`, при последующих — сверяем. Несовпадение → доступ блокируется.
//!
//! Это локальный сдерживающий механизм: в open-source клиенте его можно обойти
//! (отредактировать/удалить файл, пересобрать), но он мешает «скопировал папку
//! и запустил на другой машине». `machine-id` стабилен (не зависит от смены
//! Wi-Fi/Ethernet и рандомизации MAC) — поэтому ложных блокировок своих же
//! пользователей не будет.

use std::path::Path;

const BIND_FILE: &str = "device.bind";

/// Результат проверки привязки устройства.
pub enum DeviceStatus {
    /// Устройство совпадает (или первый запуск — привязка только что создана).
    Ok,
    /// Аккаунт привязан к другому устройству — доступ должен быть заблокирован.
    Locked {
        /// Записанный (исходный) machine-id.
        recorded: String,
        /// Machine-id текущего устройства.
        current: String,
    },
}

/// Проверяет привязку аккаунта к устройству, при первом запуске создаёт её.
///
/// - Файла нет → первый запуск: записываем текущий machine-id, возвращаем `Ok`.
/// - Файл есть и совпадает → `Ok`.
/// - Файл есть и НЕ совпадает → `Locked`.
pub fn check_or_bind(data_dir: &Path) -> DeviceStatus {
    let current = void_crypto::machine::machine_id();
    let path = data_dir.join(BIND_FILE);

    match std::fs::read_to_string(&path) {
        Ok(recorded) => {
            let recorded = recorded.trim().to_string();
            if recorded.is_empty() {
                // Пустой/битый файл — перепривязываем к текущему устройству.
                let _ = std::fs::write(&path, &current);
                DeviceStatus::Ok
            } else if recorded == current {
                DeviceStatus::Ok
            } else {
                DeviceStatus::Locked { recorded, current }
            }
        }
        Err(_) => {
            // Первый запуск (или файл недоступен) — привязываем к этому устройству.
            let _ = std::fs::create_dir_all(data_dir);
            let _ = std::fs::write(&path, &current);
            DeviceStatus::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("void-devlock-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn first_run_binds_and_allows() {
        let dir = tmp();
        assert!(matches!(check_or_bind(&dir), DeviceStatus::Ok));
        // Файл создан и содержит текущий machine-id.
        let recorded = std::fs::read_to_string(dir.join(BIND_FILE)).unwrap();
        assert_eq!(recorded.trim(), void_crypto::machine::machine_id());
    }

    #[test]
    fn same_device_allows() {
        let dir = tmp();
        // Привязываем текущим id вручную.
        std::fs::write(dir.join(BIND_FILE), void_crypto::machine::machine_id()).unwrap();
        assert!(matches!(check_or_bind(&dir), DeviceStatus::Ok));
    }

    #[test]
    fn foreign_device_locks() {
        let dir = tmp();
        // Записываем заведомо чужой id.
        std::fs::write(dir.join(BIND_FILE), "foreign-machine-id-xyz").unwrap();
        match check_or_bind(&dir) {
            DeviceStatus::Locked { recorded, current } => {
                assert_eq!(recorded, "foreign-machine-id-xyz");
                assert_eq!(current, void_crypto::machine::machine_id());
            }
            DeviceStatus::Ok => panic!("ожидалась блокировка для чужого устройства"),
        }
    }

    #[test]
    fn empty_file_rebinds() {
        let dir = tmp();
        std::fs::write(dir.join(BIND_FILE), "   \n").unwrap();
        assert!(matches!(check_or_bind(&dir), DeviceStatus::Ok));
        assert_eq!(
            std::fs::read_to_string(dir.join(BIND_FILE)).unwrap().trim(),
            void_crypto::machine::machine_id()
        );
    }
}
