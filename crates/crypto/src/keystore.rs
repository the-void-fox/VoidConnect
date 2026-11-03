//! keystore.rs — зашифрованное хранилище 32-байтового master-секрета
//! (`machine.secret`) под ключом KEK = KDF(machine-id [+ опциональный пароль]).
//!
//! ## Зачем
//!
//! Раньше `machine.secret` лежал на диске открытым текстом: при изъятии
//! устройства злоумышленник просто читал файл и восстанавливал ключи. Кейстор
//! шифрует этот секрет:
//!
//! - **Без пароля** — KEK выводится только из machine-id. Авто-разблокировка
//!   (UX как раньше), привязка к устройству сохраняется; защита от изъятия —
//!   нулевая (machine-id тоже на устройстве), это осознанный выбор пользователя.
//! - **С паролем** — KEK = KDF(machine-id + пароль). Изъятия устройства уже
//!   недостаточно: без пароля секрет не расшифровать.
//!
//! ## Важно: NodeId не меняется
//!
//! Кейстор хранит **те же самые** байты master-секрета, что и старый
//! `machine.secret`. Так как `Identity` выводит ключи из этого секрета
//! (`HMAC(secret, fingerprint)`), AccountId/NodeId остаётся прежним — пароль
//! можно включать и выключать, не теряя личность. Поэтому KEK НЕ участвует в
//! деривации личности (это сменило бы NodeId), а только шифрует секрет на диске.
//!
//! ## KDF
//!
//! PBKDF2-HMAC-SHA256 (на стабильных `hmac`+`sha2`, без новых зависимостей).
//! Argon2id был бы предпочтительнее, но в офлайн-кэше доступны только
//! release-candidate версии — рискованно для деривации ключей. Для пароля берём
//! 600 000 итераций (рекомендация OWASP); без пароля — 1 итерация (брутить
//! нечего, machine-id и так на устройстве, не тормозим запуск).

use std::fs;
use std::io::Write;
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// Имя файла кейстора в каталоге данных.
pub const KEYSTORE_FILE: &str = "keystore.json";

const VERSION: u32 = 1;
/// Итерации PBKDF2, когда задан пароль (рекомендация OWASP для HMAC-SHA256).
/// В тестах берём малое число — кейсторы там одноразовые (tempdir), а 600k
/// в debug-сборке тестов занимали бы десятки секунд.
#[cfg(not(test))]
const PBKDF2_ITERS_PASSWORD: u32 = 600_000;
#[cfg(test)]
const PBKDF2_ITERS_PASSWORD: u32 = 2_000;
/// Итерации, когда пароля нет (только привязка к machine-id, перебирать нечего).
const PBKDF2_ITERS_NO_PASSWORD: u32 = 1;
/// Верхняя граница `iters` из файла: число итераций читается с диска, и
/// испорченное/подменённое значение (u32::MAX) повесило бы запуск на часы.
const PBKDF2_ITERS_MAX: u32 = 10_000_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SECRET_LEN: usize = 32;
const KEK_CONTEXT: &[u8] = b"void-connect/keystore-kek/v1";

/// Зашифрованный master-секрет на диске.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub version: u32,
    /// Требуется ли пароль для разблокировки.
    pub password_protected: bool,
    /// Число итераций PBKDF2 (зафиксировано при создании — для совместимости).
    pub iters: u32,
    /// Соль KDF (hex).
    pub salt: String,
    /// Nonce XChaCha20-Poly1305 (hex, 24 байта).
    pub nonce: String,
    /// Зашифрованный секрет + тег аутентификации (hex).
    pub ciphertext: String,
}

impl Keystore {
    /// Создаёт кейстор, шифруя `secret` под KEK = KDF(machine-id [+ password]).
    pub fn create(
        machine_id: &str,
        secret: &[u8; SECRET_LEN],
        password: Option<&str>,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let iters = if password.is_some() {
            PBKDF2_ITERS_PASSWORD
        } else {
            PBKDF2_ITERS_NO_PASSWORD
        };

        let kek = derive_kek(machine_id, password, &salt, iters);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, secret.as_ref())
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        Ok(Self {
            version: VERSION,
            password_protected: password.is_some(),
            iters,
            salt: hex::encode(salt),
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
        })
    }

    /// Расшифровывает master-секрет. Неверный пароль (или другое устройство) →
    /// [`CryptoError::WrongPassword`] — провал проверки AEAD-тега.
    pub fn unlock(
        &self,
        machine_id: &str,
        password: Option<&str>,
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>, CryptoError> {
        if self.iters == 0 || self.iters > PBKDF2_ITERS_MAX {
            return Err(CryptoError::Keystore(format!("недопустимое число итераций: {}", self.iters)));
        }
        let salt = hex::decode(&self.salt)?;
        let nonce_bytes = hex::decode(&self.nonce)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptoError::Keystore("неверная длина nonce".into()));
        }
        let ct = hex::decode(&self.ciphertext)?;

        let kek = derive_kek(machine_id, password, &salt, self.iters);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&kek));
        let nonce = XNonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|_| CryptoError::WrongPassword)?;

        if plaintext.len() != SECRET_LEN {
            return Err(CryptoError::Keystore("неверная длина секрета".into()));
        }
        let mut arr = [0u8; SECRET_LEN];
        arr.copy_from_slice(&plaintext);
        Ok(Zeroizing::new(arr))
    }

    /// Сохраняет кейстор на диск (права 0600 на Unix).
    /// Сохраняет кейстор атомарно: временный файл (сразу с правами 0600) →
    /// fsync → rename поверх старого. Обрыв питания посреди смены пароля не
    /// оставит битый файл, а без кейстора личность восстановить нельзя.
    pub fn save(&self, path: &Path) -> Result<(), CryptoError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CryptoError::Keystore(e.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp = path.with_extension("json.tmp");
        // Остаток прошлой неудачной записи мог быть создан с другими правами.
        let _ = fs::remove_file(&tmp);
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        // rename надёжен после fsync каталога (иначе запись каталога может не
        // дожить до диска). На Windows каталог так не открыть — пропускаем.
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Читает кейстор с диска.
    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        let s = fs::read_to_string(path)?;
        serde_json::from_str(&s).map_err(|e| CryptoError::Keystore(e.to_string()))
    }
}

/// Выводит KEK. Всегда привязан к machine-id; пароль — опционален.
fn derive_kek(
    machine_id: &str,
    password: Option<&str>,
    salt: &[u8],
    iters: u32,
) -> [u8; 32] {
    let mut ikm: Vec<u8> = Vec::new();
    ikm.extend_from_slice(KEK_CONTEXT);
    ikm.push(0);
    ikm.extend_from_slice(machine_id.as_bytes());
    if let Some(p) = password {
        ikm.push(0);
        ikm.extend_from_slice(p.as_bytes());
    }
    let kek = pbkdf2_hmac_sha256(&ikm, salt, iters);
    ikm.zeroize(); // в ikm попал пароль — затираем
    kek
}

/// PBKDF2-HMAC-SHA256 для одного выходного блока (dkLen = 32 = hLen).
///
/// `T_1 = U_1 XOR U_2 XOR … XOR U_c`, где `U_1 = HMAC(P, S || INT_32_BE(1))`,
/// `U_i = HMAC(P, U_{i-1})`. Итераций всегда ≥ 1.
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let iterations = iterations.max(1);

    // U_1 = HMAC(P, salt || 0x00000001)
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &block);

    let mut t = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (ti, ui) in t.iter_mut().zip(u.iter()) {
            *ti ^= *ui;
        }
    }
    t
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC принимает ключ любой длины");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MID: &str = "machine-id-AAAA";

    #[test]
    fn pbkdf2_c1_equals_single_hmac() {
        // Базовый случай PBKDF2: при c=1 выход равен одному HMAC(P, S||INT(1)).
        let pw = b"password";
        let salt = b"saltsalt";
        let got = pbkdf2_hmac_sha256(pw, salt, 1);

        let mut block = salt.to_vec();
        block.extend_from_slice(&1u32.to_be_bytes());
        let want = hmac_sha256(pw, &block);

        assert_eq!(got, want);
    }

    #[test]
    fn pbkdf2_more_iterations_differ_and_deterministic() {
        let a = pbkdf2_hmac_sha256(b"p", b"s", 1000);
        let b = pbkdf2_hmac_sha256(b"p", b"s", 1000);
        let c = pbkdf2_hmac_sha256(b"p", b"s", 1001);
        assert_eq!(a, b, "детерминирован");
        assert_ne!(a, c, "разное число итераций → разный ключ");
    }

    #[test]
    fn roundtrip_no_password() {
        let secret = [7u8; SECRET_LEN];
        let ks = Keystore::create(MID, &secret, None).unwrap();
        assert!(!ks.password_protected);
        let out = ks.unlock(MID, None).unwrap();
        assert_eq!(*out, secret);
    }

    #[test]
    fn roundtrip_with_password() {
        let secret = [9u8; SECRET_LEN];
        let ks = Keystore::create(MID, &secret, Some("hunter2")).unwrap();
        assert!(ks.password_protected);

        // Верный пароль.
        assert_eq!(*ks.unlock(MID, Some("hunter2")).unwrap(), secret);
        // Неверный пароль.
        assert!(matches!(ks.unlock(MID, Some("wrong")), Err(CryptoError::WrongPassword)));
        // Без пароля — тоже отказ.
        assert!(matches!(ks.unlock(MID, None), Err(CryptoError::WrongPassword)));
    }

    #[test]
    fn other_machine_cannot_unlock() {
        // KEK завязан на machine-id: тот же файл на другой машине не открывается,
        // даже без пароля.
        let secret = [3u8; SECRET_LEN];
        let ks = Keystore::create("machine-A", &secret, None).unwrap();
        assert!(matches!(ks.unlock("machine-B", None), Err(CryptoError::WrongPassword)));
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYSTORE_FILE);
        let secret = [42u8; SECRET_LEN];

        Keystore::create(MID, &secret, Some("pw"))
            .unwrap()
            .save(&path)
            .unwrap();

        let loaded = Keystore::load(&path).unwrap();
        assert_eq!(*loaded.unlock(MID, Some("pw")).unwrap(), secret);
    }

    /// Эталонные векторы PBKDF2-HMAC-SHA256 из RFC 7914 §11 (первые 32 байта):
    /// ручная реализация должна совпадать со стандартом бит в бит.
    #[test]
    fn pbkdf2_matches_rfc7914_vectors() {
        assert_eq!(
            hex::encode(pbkdf2_hmac_sha256(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        assert_eq!(
            hex::encode(pbkdf2_hmac_sha256(b"Password", b"NaCl", 80_000)),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
    }

    #[test]
    fn absurd_iteration_count_rejected() {
        let mut ks = Keystore::create(MID, &[1u8; SECRET_LEN], None).unwrap();
        ks.iters = u32::MAX;
        assert!(matches!(ks.unlock(MID, None), Err(CryptoError::Keystore(_))));
        ks.iters = 0;
        assert!(matches!(ks.unlock(MID, None), Err(CryptoError::Keystore(_))));
    }

    /// Перезапись не оставляет временных файлов; на Unix права — только владелец.
    #[test]
    fn save_overwrites_atomically_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(KEYSTORE_FILE);
        Keystore::create(MID, &[1u8; SECRET_LEN], None).unwrap().save(&path).unwrap();
        // Остаток «упавшей» записи с открытыми правами не должен помешать.
        std::fs::write(path.with_extension("json.tmp"), b"junk").unwrap();
        Keystore::create(MID, &[2u8; SECRET_LEN], None).unwrap().save(&path).unwrap();

        assert_eq!(*Keystore::load(&path).unwrap().unlock(MID, None).unwrap(), [2u8; SECRET_LEN]);
        assert!(!path.with_extension("json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
