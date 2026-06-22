/// identity.rs — генерация и хранение Identity, привязанного к железу.
///
/// ## Как это работает
///
/// ```text
/// [MAC + hostname]  ──HMAC-SHA256──►  machine_seed (32 байта)
///                         ▲
///                   machine_secret  ←── файл ~/.void/machine.secret
///                   (генерируется 1 раз, 32 случайных байта)
///
/// machine_seed  ──BLAKE3-KDF──►  signing_seed   → Ed25519 keypair
///                           └──►  encryption_seed → X25519 keypair
///
/// AccountId = hex(Ed25519 public key)  — 64 символа
/// ```
///
/// ## Почему так безопасно
///
/// - Скопировать БД без `machine.secret` → ключ не восстановить
/// - Скопировать `machine.secret` на другое железо → HMAC вернёт
///   другой `machine_seed` (другой MAC/hostname) → другой keypair
/// - Оба файла на другом железе → ID совпадёт (это намеренно —
///   пользователь сам решает мигрировать аккаунт)

use std::path::Path;
use std::fs;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use blake3::derive_key;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{SigningKeypair, EncryptionKeypair, PublicKeys};
use crate::machine::MachineFingerprint;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// AccountId
// ---------------------------------------------------------------------------

/// Публичный идентификатор аккаунта — hex Ed25519 публичного ключа (64 символа).
///
/// Это то, что пользователи видят и передают друг другу.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(pub String);

impl AccountId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Сокращённый вид для UI: первые 8 + «…» + последние 8 символов.
    pub fn short(&self) -> String {
        let s = &self.0;
        if s.len() > 20 {
            format!("{}…{}", &s[..8], &s[s.len()-8..])
        } else {
            s.clone()
        }
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Полная криптографическая личность узла.
///
/// Содержит оба keypair (подпись + шифрование) и AccountId.
/// Хранится только в памяти во время работы программы —
/// при перезапуске восстанавливается из `machine.secret` + железо.
pub struct Identity {
    pub id: AccountId,
    pub signing: SigningKeypair,
    pub encryption: EncryptionKeypair,
    pub public_keys: PublicKeys,
}

impl Identity {
    // -----------------------------------------------------------------------
    // Загрузка / создание
    // -----------------------------------------------------------------------

    /// Загружает Identity для текущего устройства.
    ///
    /// - Если `machine.secret` не существует — создаёт его (первый запуск).
    /// - Собирает аппаратный отпечаток.
    /// - Деривирует keypair детерминированно.
    ///
    /// `data_dir` — директория данных приложения, например `~/.void/`.
    pub fn load_or_create(data_dir: &Path) -> Result<Self, CryptoError> {
        let secret_path = data_dir.join("machine.secret");

        // Читаем или создаём machine.secret
        let machine_secret = Self::load_or_create_machine_secret(&secret_path)?;

        // Собираем аппаратный отпечаток
        let fingerprint = MachineFingerprint::collect()?;

        // Деривируем seed через HMAC(fingerprint | machine_secret)
        let machine_seed = Self::derive_machine_seed(&fingerprint.digest, &machine_secret);

        // Из seed получаем два независимых seed через BLAKE3 KDF
        let signing_seed    = Self::kdf(&machine_seed, "void-connect/signing/v1");
        let encryption_seed = Self::kdf(&machine_seed, "void-connect/encryption/v1");

        // Создаём keypair
        let signing    = SigningKeypair::from_seed(&signing_seed)?;
        let encryption = EncryptionKeypair::from_seed(&encryption_seed);

        let public_keys = PublicKeys::new(&signing.public_bytes(), &encryption.public_bytes());
        let id = AccountId(hex::encode(signing.public_bytes()));

        Ok(Self { id, signing, encryption, public_keys })
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    /// Читает machine.secret из файла или генерирует новый (первый запуск).
    fn load_or_create_machine_secret(path: &Path) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        if path.exists() {
            let bytes = fs::read(path)?;
            if bytes.len() != 32 {
                return Err(CryptoError::MachineFingerprint(
                    "machine.secret повреждён (неверный размер)".into()
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Zeroizing::new(arr))
        } else {
            // Первый запуск — генерируем 32 случайных байта
            let mut secret = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);

            // Создаём директорию если нет
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &secret)?;

            // Устанавливаем права только для владельца (Unix)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }

            Ok(Zeroizing::new(secret))
        }
    }

    /// HMAC-SHA256(key=machine_secret, data=fingerprint_digest) → 32-байтовый seed.
    ///
    /// Результат зависит от ОБОИХ: секрета И железа.
    fn derive_machine_seed(fingerprint: &[u8; 32], secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(secret)
            .expect("HMAC принимает ключи любой длины");
        mac.update(fingerprint);
        let result = mac.finalize().into_bytes();

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);
        Zeroizing::new(seed)
    }

    /// BLAKE3 KDF: из master seed деривирует дочерний seed под конкретный контекст.
    ///
    /// Разные контексты (signing/encryption) → разные ключи, независимо.
    fn kdf(master: &[u8; 32], context: &str) -> [u8; 32] {
        // blake3::derive_key принимает строку-контекст + материал ключа
        derive_key(context, master)
    }

    // -----------------------------------------------------------------------
    // Удобные методы для остального кода
    // -----------------------------------------------------------------------

    /// Публичный ключ подписи (для отправки пирам в профиле).
    pub fn signing_public_bytes(&self) -> [u8; 32] {
        self.signing.public_bytes()
    }

    /// Публичный ключ шифрования (для E2E DH).
    pub fn encryption_public_bytes(&self) -> [u8; 32] {
        self.encryption.public_bytes()
    }

    /// Информация об устройстве (для отладки).
    pub fn device_info() -> Result<String, CryptoError> {
        let fp = MachineFingerprint::collect()?;
        Ok(fp.summary())
    }
}

// ---------------------------------------------------------------------------
// Сохраняемая часть (в БД хранится только публичная информация)
// ---------------------------------------------------------------------------

/// То, что сохраняется в БД для собственного профиля.
/// Приватные ключи НЕ хранятся в БД — восстанавливаются из iron+secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub account_id: AccountId,
    pub public_keys: PublicKeys,
    /// Отпечаток устройства (hex) — для диагностики
    pub device_fingerprint: String,
}

impl StoredIdentity {
    pub fn from_identity(identity: &Identity) -> Result<Self, CryptoError> {
        let fp = MachineFingerprint::collect()?;
        Ok(Self {
            account_id: identity.id.clone(),
            public_keys: identity.public_keys.clone(),
            device_fingerprint: fp.to_hex(),
        })
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn same_dir_same_identity() {
        let dir = tempdir().unwrap();
        let id1 = Identity::load_or_create(dir.path()).unwrap();
        let id2 = Identity::load_or_create(dir.path()).unwrap();
        // Один и тот же каталог + то же железо → один и тот же ID
        assert_eq!(id1.id, id2.id);
    }

    #[test]
    fn different_secrets_different_identity() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let id1 = Identity::load_or_create(dir1.path()).unwrap();
        let id2 = Identity::load_or_create(dir2.path()).unwrap();
        // Разные machine.secret → разные ID (даже на одном железе)
        assert_ne!(id1.id, id2.id);
    }

    #[test]
    fn account_id_format() {
        let dir = tempdir().unwrap();
        let id = Identity::load_or_create(dir.path()).unwrap();
        // AccountId должен быть 64-символьным hex (32 байта Ed25519)
        assert_eq!(id.id.0.len(), 64);
        assert!(id.id.0.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn kdf_contexts_are_independent() {
        let master = [42u8; 32];
        let s = Identity::kdf(&master, "void-connect/signing/v1");
        let e = Identity::kdf(&master, "void-connect/encryption/v1");
        assert_ne!(s, e);
    }
}