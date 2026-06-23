//! Подписываемые типы предложений и голосов.
//!
//! Все записи неизменяемы и подписаны автором: предложение — инициатором,
//! голос — голосующим. `proposal_id` детерминирован (одинаков на всех узлах),
//! что позволяет синхронизировать их объединением множеств (anti-entropy) без
//! консенсуса в реальном времени.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;

use crate::error::VoteError;

/// Длительность окна голосования — 3 суток (в секундах).
pub const VOTING_WINDOW_SECS: i64 = 3 * 24 * 60 * 60;

/// Grace-период после закрытия окна, в течение которого ещё досинхронизируем
/// поздние голоса перед заморозкой результата.
pub const VOTING_GRACE_SECS: i64 = 6 * 60 * 60;

/// Срок локального бана по итогам BanUser — 30 суток (в секундах).
pub const BAN_DURATION_SECS: i64 = 30 * 24 * 60 * 60;

/// Тип предложения и его цель.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposalKind {
    /// Временный (на [`BAN_DURATION_SECS`]) локальный бан узла.
    BanUser { target: String },
    /// Досрочное снятие бана с узла.
    UnbanUser { target: String },
    /// Добавить канал («доску») в общий чат.
    AddChannel { id: String, name: String, icon: String },
    /// Удалить файл из общего хранилища (каждый узел стирает свою копию).
    RemoveFile { file_id: String },
}

impl ProposalKind {
    /// Строковый тег типа (для колонки `kind` в БД).
    pub fn tag(&self) -> &'static str {
        match self {
            ProposalKind::BanUser { .. } => "ban_user",
            ProposalKind::UnbanUser { .. } => "unban_user",
            ProposalKind::AddChannel { .. } => "add_channel",
            ProposalKind::RemoveFile { .. } => "remove_file",
        }
    }

    /// Цель предложения (денормализуется в БД для дедупа/индексации):
    /// NodeId для бана, id канала для AddChannel, file_id для RemoveFile.
    pub fn target(&self) -> &str {
        match self {
            ProposalKind::BanUser { target } | ProposalKind::UnbanUser { target } => target,
            ProposalKind::AddChannel { id, .. } => id,
            ProposalKind::RemoveFile { file_id } => file_id,
        }
    }
}

/// Тело предложения — то, что подписывается. Автор = `signed.signer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalPayload {
    pub kind: ProposalKind,
    /// Unix-таймстемп создания = начало окна голосования.
    pub created_at: i64,
}

impl ProposalPayload {
    pub fn new(kind: ProposalKind) -> Self {
        Self {
            kind,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ProposalPayload serialization")
    }
}

/// Подписанное предложение: тело + подпись инициатора + детерминированный id.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: String,
    pub payload: ProposalPayload,
    pub signed: SignedMessage,
}

impl Proposal {
    /// Создаёт и подписывает предложение нашим ключом.
    pub fn create(kind: ProposalKind, keypair: &SigningKeypair) -> Result<Self, VoteError> {
        let payload = ProposalPayload::new(kind);
        let signed = SignedMessage::sign(payload.to_bytes(), keypair)?;
        let id = compute_proposal_id(&signed.signer, &signed.payload);
        Ok(Self { id, payload, signed })
    }

    /// Восстанавливает предложение из принятого по сети `SignedMessage`,
    /// проверяя подпись и пересчитывая `id`. Автор берётся из подписи.
    pub fn from_signed(signed: SignedMessage) -> Result<Self, VoteError> {
        signed.verify()?;
        let payload: ProposalPayload = serde_json::from_slice(&signed.payload)
            .map_err(|e| VoteError::Serde(e.to_string()))?;
        let id = compute_proposal_id(&signed.signer, &signed.payload);
        Ok(Self { id, payload, signed })
    }

    /// Инициатор предложения (hex Ed25519-ключа).
    pub fn proposer(&self) -> &str {
        &self.signed.signer
    }
}

/// Тело голоса — то, что подписывается. Голосующий = `signed.signer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotePayload {
    pub proposal_id: String,
    /// `true` = за, `false` = против.
    pub choice: bool,
    pub created_at: i64,
}

impl VotePayload {
    pub fn new(proposal_id: String, choice: bool) -> Self {
        Self {
            proposal_id,
            choice,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("VotePayload serialization")
    }
}

/// Подписанный голос.
#[derive(Debug, Clone)]
pub struct Vote {
    pub payload: VotePayload,
    pub signed: SignedMessage,
}

impl Vote {
    /// Создаёт и подписывает голос нашим ключом.
    pub fn create(
        proposal_id: String,
        choice: bool,
        keypair: &SigningKeypair,
    ) -> Result<Self, VoteError> {
        let payload = VotePayload::new(proposal_id, choice);
        let signed = SignedMessage::sign(payload.to_bytes(), keypair)?;
        Ok(Self { payload, signed })
    }

    /// Восстанавливает голос из принятого `SignedMessage`, проверяя подпись.
    pub fn from_signed(signed: SignedMessage) -> Result<Self, VoteError> {
        signed.verify()?;
        let payload: VotePayload = serde_json::from_slice(&signed.payload)
            .map_err(|e| VoteError::Serde(e.to_string()))?;
        Ok(Self { payload, signed })
    }

    /// Голосующий (hex Ed25519-ключа).
    pub fn voter(&self) -> &str {
        &self.signed.signer
    }
}

/// Детерминированный id предложения = hex(sha256(proposer_key || payload)).
/// Привязка к автору исключает коллизии одинаковых тел от разных инициаторов.
pub fn compute_proposal_id(proposer_key: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(proposer_key.as_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}
