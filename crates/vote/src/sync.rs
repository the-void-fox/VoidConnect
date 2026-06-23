//! Anti-entropy синхронизация: примитивы сравнения наборов голосов.
//!
//! Записи неизменяемы и подписаны, поэтому расхождения разрешаются **только
//! объединением** (union) — никакого «голосования большинством». Узел шлёт
//! дайджест (на каждое открытое предложение — хэш его набора голосов); сосед
//! сравнивает со своим и **до-рассылает** (re-announce) то, чего у отправителя
//! дайджеста нет. Re-announce идемпотентен (INSERT OR IGNORE / latest-wins),
//! так что наборы детерминированно сходятся за несколько периодов.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::tally::VoteRecord;

/// Детерминированный хэш набора голосов предложения. Не зависит от порядка
/// (сортируем по `voter_key`). Учитывает выбор и время — переголосование меняет
/// хэш. В БД уже по одному голосу на узел (latest-wins), так что хэш отражает
/// финальное состояние.
pub fn votes_digest(votes: &[VoteRecord]) -> String {
    let mut sorted: Vec<&VoteRecord> = votes.iter().collect();
    sorted.sort_by(|a, b| a.voter_key.cmp(&b.voter_key));

    let mut hasher = Sha256::new();
    for v in sorted {
        hasher.update(v.voter_key.as_bytes());
        hasher.update([v.choice as u8]);
        hasher.update(v.created_at.to_le_bytes());
        hasher.update([0u8]); // разделитель — исключает склейку соседних полей
    }
    hex::encode(hasher.finalize())
}

/// По дайджесту соседа определяет, какие НАШИ предложения стоит ему до-разослать:
/// те, которых в его дайджесте нет вовсе, либо набор голосов отличается.
///
/// `local`/`remote` — списки `(proposal_id, votes_hash)`. Возвращает proposal_id'ы,
/// которые мы должны re-announce'нуть (предложение + его голоса), чтобы сосед
/// подтянул недостающее объединением.
pub fn proposals_to_push(local: &[(String, String)], remote: &[(String, String)]) -> Vec<String> {
    let remote_map: HashMap<&str, &str> = remote
        .iter()
        .map(|(id, h)| (id.as_str(), h.as_str()))
        .collect();

    local
        .iter()
        .filter(|(id, hash)| match remote_map.get(id.as_str()) {
            None => true,              // сосед не знает это предложение
            Some(rh) => *rh != hash,   // набор голосов отличается
        })
        .map(|(id, _)| id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(key: &str, choice: bool, ts: i64) -> VoteRecord {
        VoteRecord { voter_key: key.into(), choice, created_at: ts }
    }

    #[test]
    fn digest_is_order_independent() {
        let a = [v("a", true, 1), v("b", false, 2), v("c", true, 3)];
        let b = [v("c", true, 3), v("a", true, 1), v("b", false, 2)];
        assert_eq!(votes_digest(&a), votes_digest(&b));
    }

    #[test]
    fn digest_changes_on_revote_and_membership() {
        let base = [v("a", true, 1), v("b", true, 2)];
        // Иной выбор того же узла → другой хэш (переголосование уловлено).
        let revote = [v("a", false, 5), v("b", true, 2)];
        assert_ne!(votes_digest(&base), votes_digest(&revote));
        // Лишний голос → другой хэш.
        let extra = [v("a", true, 1), v("b", true, 2), v("c", true, 3)];
        assert_ne!(votes_digest(&base), votes_digest(&extra));
        // Пустой набор стабилен и отличается от непустого.
        assert_eq!(votes_digest(&[]), votes_digest(&[]));
        assert_ne!(votes_digest(&[]), votes_digest(&base));
    }

    #[test]
    fn push_missing_and_divergent_proposals() {
        let local = [
            ("p1".to_string(), "h1".to_string()),
            ("p2".to_string(), "h2".to_string()),
            ("p3".to_string(), "h3".to_string()),
        ];
        let remote = [
            ("p1".to_string(), "h1".to_string()),    // совпадает → не пушим
            ("p2".to_string(), "DIFFERENT".to_string()), // расходится → пушим
            // p3 у соседа отсутствует → пушим
        ];
        let mut push = proposals_to_push(&local, &remote);
        push.sort();
        assert_eq!(push, vec!["p2".to_string(), "p3".to_string()]);
    }

    #[test]
    fn nothing_to_push_when_in_sync() {
        let local = [("p1".to_string(), "h1".to_string())];
        let remote = [("p1".to_string(), "h1".to_string())];
        assert!(proposals_to_push(&local, &remote).is_empty());
    }
}
