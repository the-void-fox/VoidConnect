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
use crate::keystore::{Keystore, KEYSTORE_FILE};
use crate::machine::MachineFingerprint;

type HmacSha256 = Hmac<Sha256>;

/// Нужен ли пароль для загрузки личности (результат `Identity::keystore_status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreState {
    /// Кейстора нет (первый запуск/легаси) или он без пароля — авто-разблокировка.
    NoPasswordNeeded,
    /// Кейстор защищён паролем — нужно спросить пользователя.
    PasswordRequired,
}

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

    /// Загружает Identity для текущего устройства (без пароля).
    ///
    /// Эквивалент `load_or_create_with_password(data_dir, None)`. Если кейстор
    /// защищён паролем — вернёт [`CryptoError::WrongPassword`]; в этом случае
    /// вызывающий код должен спросить пароль (см. [`Identity::keystore_status`]).
    pub fn load_or_create(data_dir: &Path) -> Result<Self, CryptoError> {
        Self::load_or_create_with_password(data_dir, None)
    }

    /// Загружает Identity, расшифровывая master-секрет паролем (если задан).
    ///
    /// Логика хранения секрета (machine.secret):
    /// - есть `keystore.json` → расшифровать им (`password` обязателен, если
    ///   кейстор защищён);
    /// - есть старый открытый `machine.secret` → мигрировать в кейстор
    ///   (без пароля), личность не меняется;
    /// - ничего нет → новый аккаунт: случайный секрет, сразу в кейстор.
    ///
    /// AccountId/NodeId зависит ТОЛЬКО от байт секрета + железа — пароль на него
    /// не влияет (его можно включать/снимать, не теряя личность).
    pub fn load_or_create_with_password(
        data_dir: &Path,
        password: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let machine_id = crate::machine::machine_id();
        let secret = Self::resolve_secret(data_dir, &machine_id, password)?;
        Self::build_from_secret(&secret)
    }

    /// Сообщает, нужен ли пароль для загрузки (для UI — спрашивать или нет).
    /// Не расшифровывает секрет, только читает заголовок кейстора.
    pub fn keystore_status(data_dir: &Path) -> KeystoreState {
        let path = data_dir.join(KEYSTORE_FILE);
        match Keystore::load(&path) {
            Ok(ks) if ks.password_protected => KeystoreState::PasswordRequired,
            _ => KeystoreState::NoPasswordNeeded,
        }
    }

    /// Устанавливает / меняет / снимает пароль.
    ///
    /// `current` — текущий пароль (None, если его нет), `new` — новый (None =
    /// снять пароль). При установке пароля удаляет устаревший открытый
    /// `machine.secret`, иначе защита на диске обходится.
    pub fn set_password(
        data_dir: &Path,
        current: Option<&str>,
        new: Option<&str>,
    ) -> Result<(), CryptoError> {
        let machine_id = crate::machine::machine_id();
        // Получаем секрет под текущим паролем (заодно мигрируем при необходимости).
        let secret = Self::resolve_secret(data_dir, &machine_id, current)?;
        // Перешифровываем под новым паролем.
        let keystore_path = data_dir.join(KEYSTORE_FILE);
        Keystore::create(&machine_id, &secret, new)?.save(&keystore_path)?;
        // С паролем открытый machine.secret больше не должен лежать на диске.
        if new.is_some() {
            let _ = fs::remove_file(data_dir.join("machine.secret"));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    /// Достаёт 32-байтовый master-секрет: из кейстора, из старого открытого
    /// файла (с миграцией) или генерирует новый.
    fn resolve_secret(
        data_dir: &Path,
        machine_id: &str,
        password: Option<&str>,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let keystore_path = data_dir.join(KEYSTORE_FILE);
        let legacy_path = data_dir.join("machine.secret");

        if keystore_path.exists() {
            let ks = Keystore::load(&keystore_path)?;
            return ks.unlock(machine_id, password);
        }

        if let Some(parent) = keystore_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if legacy_path.exists() {
            // Миграция: открытый machine.secret → зашифрованный кейстор без пароля.
            let bytes = fs::read(&legacy_path)?;
            if bytes.len() != 32 {
                return Err(CryptoError::MachineFingerprint(
                    "machine.secret повреждён (неверный размер)".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let secret = Zeroizing::new(arr);
            Keystore::create(machine_id, &secret, None)?.save(&keystore_path)?;
            return Ok(secret);
        }

        // Новый аккаунт — случайный секрет сразу в кейстор (без открытого файла).
        let mut arr = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut arr);
        let secret = Zeroizing::new(arr);
        Keystore::create(machine_id, &secret, None)?.save(&keystore_path)?;
        Ok(secret)
    }

    /// Детерминированно строит Identity из master-секрета + отпечатка железа.
    fn build_from_secret(machine_secret: &[u8; 32]) -> Result<Self, CryptoError> {
        let fingerprint = MachineFingerprint::collect()?;
        let machine_seed = Self::derive_machine_seed(&fingerprint.digest, machine_secret);

        let signing_seed    = Self::kdf(&machine_seed, "void-connect/signing/v1");
        let encryption_seed = Self::kdf(&machine_seed, "void-connect/encryption/v1");

        let signing    = SigningKeypair::from_seed(&signing_seed)?;
        let encryption = EncryptionKeypair::from_seed(&encryption_seed);

        let public_keys = PublicKeys::new(&signing.public_bytes(), &encryption.public_bytes());
        let id = AccountId(hex::encode(signing.public_bytes()));

        Ok(Self { id, signing, encryption, public_keys })
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

    #[test]
    fn first_run_creates_keystore_not_plaintext() {
        let dir = tempdir().unwrap();
        let _ = Identity::load_or_create(dir.path()).unwrap();
        // Новый аккаунт хранит секрет только в кейсторе, без открытого файла.
        assert!(dir.path().join(KEYSTORE_FILE).exists());
        assert!(!dir.path().join("machine.secret").exists());
        // Без пароля кейстор не помечен как защищённый.
        assert_eq!(Identity::keystore_status(dir.path()), KeystoreState::NoPasswordNeeded);
    }

    #[test]
    fn legacy_plaintext_migrates_preserving_identity() {
        let dir = tempdir().unwrap();
        // Эмулируем старую установку: открытый machine.secret из 32 байт.
        std::fs::write(dir.path().join("machine.secret"), [5u8; 32]).unwrap();

        let id1 = Identity::load_or_create(dir.path()).unwrap();
        // После загрузки появился кейстор; повторная загрузка даёт тот же ID.
        assert!(dir.path().join(KEYSTORE_FILE).exists());
        let id2 = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(id1.id, id2.id);
    }

    #[test]
    fn setting_password_preserves_identity_and_requires_it() {
        let dir = tempdir().unwrap();
        let id1 = Identity::load_or_create(dir.path()).unwrap();

        // Ставим пароль.
        Identity::set_password(dir.path(), None, Some("s3cret")).unwrap();
        assert_eq!(Identity::keystore_status(dir.path()), KeystoreState::PasswordRequired);

        // Без пароля теперь не загрузиться.
        assert!(matches!(
            Identity::load_or_create(dir.path()),
            Err(CryptoError::WrongPassword)
        ));

        // С верным паролем — тот же NodeId, что и до установки пароля.
        let id2 = Identity::load_or_create_with_password(dir.path(), Some("s3cret")).unwrap();
        assert_eq!(id1.id, id2.id);

        // Снимаем пароль — снова авто-разблокировка, ID сохраняется.
        Identity::set_password(dir.path(), Some("s3cret"), None).unwrap();
        assert_eq!(Identity::keystore_status(dir.path()), KeystoreState::NoPasswordNeeded);
        let id3 = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(id1.id, id3.id);
    }

    #[test]
    fn wrong_current_password_cannot_change() {
        let dir = tempdir().unwrap();
        let _ = Identity::load_or_create(dir.path()).unwrap();
        Identity::set_password(dir.path(), None, Some("right")).unwrap();
        // Неверный текущий пароль → смена отклонена.
        assert!(matches!(
            Identity::set_password(dir.path(), Some("wrong"), Some("new")),
            Err(CryptoError::WrongPassword)
        ));
    }
}