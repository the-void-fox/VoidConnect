//! # void-vote — децентрализованные голосования VoidConnect.
//!
//! Любой узел с высокой репутацией может создать предложение (бан/разбан узла,
//! добавление канала, удаление файла из хранилища); узлы с положительной
//! репутацией голосуют в течение окна ([`VOTING_WINDOW_SECS`], 3 суток).
//!
//! Записи (предложения и голоса) подписаны и неизменяемы. Узлы синхронизируют
//! их **объединением множеств** (anti-entropy): подделать подпись нельзя, а
//! спрятать долетевшую запись — тоже (доберётся от других соседей). Поэтому
//! подсчёт ([`tally`]) детерминирован: одинаковый набор голосов даёт одинаковый
//! результат на любом узле, без консенсуса в реальном времени.
//!
//! ## Ограничения (by design)
//! - Итог — **локальное** решение каждого узла по его набору данных и его
//!   взгляду на репутацию голосующих; у узлов с разными наборами он может
//!   отличаться, пока anti-entropy их не сведёт.
//! - Sybil-атака удорожается (порог + кворум высокой репутации + супербольшинство
//!   для опасных действий), но не исключается полностью.

pub mod error;
pub mod store;
pub mod sync;
pub mod tally;
pub mod types;

pub use error::VoteError;
pub use sync::{proposals_to_push, votes_digest};
pub use tally::{
    can_propose, can_vote, params, tally, Outcome, Tally, TallyParams, VoteRecord, HIGH_SCORE,
    MIN_VOTER_SCORE,
};
pub use types::{
    compute_proposal_id, Proposal, ProposalKind, ProposalPayload, Vote, VotePayload,
    BAN_DURATION_SECS, VOTING_GRACE_SECS, VOTING_WINDOW_SECS,
};

#[cfg(test)]
mod tests {
    use super::*;
    use void_crypto::keys::SigningKeypair;

    fn kp(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    #[test]
    fn proposal_id_is_deterministic_and_author_bound() {
        let a = kp(1);
        let b = kp(2);
        let kind = || ProposalKind::RemoveFile { file_id: "abc".into() };

        // Один автор + одинаковое тело → одинаковый id (детерминизм для sync).
        let p1 = Proposal::create(kind(), &a).unwrap();
        let id_again = compute_proposal_id(&p1.signed.signer, &p1.signed.payload);
        assert_eq!(p1.id, id_again);

        // Другой автор → другой id (нет коллизий между инициаторами).
        let p2 = Proposal::create(kind(), &b).unwrap();
        assert_ne!(p1.id, p2.id);
    }

    #[test]
    fn from_signed_rejects_tampered_payload() {
        let a = kp(1);
        let mut p = Proposal::create(ProposalKind::BanUser { target: "x".into() }, &a).unwrap();
        // Портим payload, не трогая подпись → verify должен упасть.
        p.signed.payload.push(b'!');
        assert!(Proposal::from_signed(p.signed).is_err());
    }

    #[test]
    fn vote_voter_matches_signer() {
        let voter = kp(7);
        let v = Vote::create("prop".into(), true, &voter).unwrap();
        let restored = Vote::from_signed(v.signed.clone()).unwrap();
        assert_eq!(restored.voter(), v.signed.signer);
        assert!(restored.payload.choice);
    }
}
