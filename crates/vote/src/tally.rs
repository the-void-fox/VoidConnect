//! Детерминированный подсчёт голосов.
//!
//! Подсчёт — чистая функция от (тип, набор голосов, локальные репутации, время).
//! Без БД и async: одинаковый набор входов даёт одинаковый результат на любом
//! узле. Репутации передаются снаружи (backend заранее выгружает их из
//! `ScoreManager`), поэтому крейт не зависит от `void-reputation`.

use std::collections::HashMap;

use crate::types::{ProposalKind, VOTING_WINDOW_SECS};

/// Минимальный score для права голоса (нужна «плюсовая» репутация).
/// Зеркалит `void_reputation::score::SCORE_LOW`.
pub const MIN_VOTER_SCORE: f64 = 0.0;

/// Порог «высокой» репутации для кворума и права создавать предложения.
/// Зеркалит `void_reputation::score::SCORE_HIGH`.
pub const HIGH_SCORE: f64 = 50.0;

/// Может ли узел с таким score инициировать голосование (нужен High).
pub fn can_propose(score: f64) -> bool {
    score >= HIGH_SCORE
}

/// Имеет ли узел право голоса (нужна положительная репутация).
pub fn can_vote(score: f64) -> bool {
    score > MIN_VOTER_SCORE
}

/// Пороги валидности и прохождения для типа предложения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TallyParams {
    /// Минимум разных подходящих проголосовавших (кворум участия).
    pub min_voters: usize,
    /// Минимум высокорепутационных (`score >= HIGH_SCORE`) среди них (кворум доверия).
    pub min_high: usize,
    /// `true` — нужно супербольшинство ⅔; `false` — строгое большинство >50%.
    pub supermajority: bool,
}

/// Пороги по типу предложения (см. согласованную таблицу).
pub fn params(kind: &ProposalKind) -> TallyParams {
    match kind {
        // Безопасное аддитивное действие — мягкий порог.
        ProposalKind::AddChannel { .. } => TallyParams {
            min_voters: 3,
            min_high: 2,
            supermajority: false,
        },
        // Опасные/спорные действия — жёсткий порог.
        ProposalKind::BanUser { .. }
        | ProposalKind::UnbanUser { .. }
        | ProposalKind::RemoveFile { .. } => TallyParams {
            min_voters: 7,
            min_high: 3,
            supermajority: true,
        },
    }
}

/// Итог голосования.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Принято (порог пройден, кворум выполнен).
    Passed,
    /// Отклонено (кворум выполнен, но не хватило голосов «за»).
    Rejected,
    /// Нет кворума (мало участников или мало высокорепутационных).
    NoQuorum,
}

/// Результат подсчёта (учитываются только eligible — score > 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub yes: usize,
    pub no: usize,
    /// Число eligible-голосов (yes + no).
    pub eligible: usize,
    /// Сколько из eligible — высокорепутационные (для кворума доверия).
    pub high: usize,
    pub outcome: Outcome,
    /// Окно ещё открыто → `outcome` предварительный (живой подсчёт).
    pub open: bool,
}

/// Один уже дедуплицированный голос (по одному на узел — store отдаёт такой).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteRecord {
    pub voter_key: String,
    pub choice: bool,
    pub created_at: i64,
}

/// Финализировано ли голосование (окно закрыто) на момент `now`.
pub fn is_closed(created_at: i64, now: i64) -> bool {
    now >= created_at + VOTING_WINDOW_SECS
}

/// score голосующего по локальной карте; неизвестный узел = 0.0 (не eligible).
fn score_of(scores: &HashMap<String, f64>, voter_key: &str) -> f64 {
    scores.get(voter_key).copied().unwrap_or(0.0)
}

/// Подсчитывает итог. `scores` — локальный взгляд на репутацию голосующих.
pub fn tally(
    kind: &ProposalKind,
    created_at: i64,
    votes: &[VoteRecord],
    scores: &HashMap<String, f64>,
    now: i64,
) -> Tally {
    let p = params(kind);

    let mut yes = 0usize;
    let mut no = 0usize;
    let mut high = 0usize;
    for v in votes {
        let s = score_of(scores, &v.voter_key);
        if !can_vote(s) {
            continue; // нет права голоса — пропускаем
        }
        if v.choice {
            yes += 1;
        } else {
            no += 1;
        }
        if s >= HIGH_SCORE {
            high += 1;
        }
    }
    let eligible = yes + no;

    let outcome = if eligible < p.min_voters || high < p.min_high {
        Outcome::NoQuorum
    } else if passes(yes, eligible, p.supermajority) {
        Outcome::Passed
    } else {
        Outcome::Rejected
    };

    Tally {
        yes,
        no,
        eligible,
        high,
        outcome,
        open: !is_closed(created_at, now),
    }
}

/// Пройден ли порог. Целочисленная арифметика — детерминированно, без float.
fn passes(yes: usize, total: usize, supermajority: bool) -> bool {
    if total == 0 {
        return false;
    }
    if supermajority {
        yes * 3 >= total * 2 // ≥ 2/3
    } else {
        yes * 2 > total // строго > 1/2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(key: &str, choice: bool) -> VoteRecord {
        VoteRecord { voter_key: key.into(), choice, created_at: 0 }
    }

    /// Карта репутаций: подходящие узлы помечаем нужным score.
    fn scores(pairs: &[(&str, f64)]) -> HashMap<String, f64> {
        pairs.iter().map(|(k, s)| (k.to_string(), *s)).collect()
    }

    #[test]
    fn add_channel_passes_with_soft_quorum() {
        let kind = ProposalKind::AddChannel {
            id: "tech2".into(),
            name: "Tech2".into(),
            icon: "#".into(),
        };
        // 3 голоса, 2 из них высокорепутационные, все «за».
        let votes = [v("a", true), v("b", true), v("c", true)];
        let sc = scores(&[("a", 60.0), ("b", 55.0), ("c", 5.0)]);
        let t = tally(&kind, 0, &votes, &sc, VOTING_WINDOW_SECS + 1);
        assert_eq!(t.outcome, Outcome::Passed);
        assert_eq!((t.yes, t.no, t.high), (3, 0, 2));
        assert!(!t.open);
    }

    #[test]
    fn add_channel_no_quorum_without_two_high() {
        let kind = ProposalKind::AddChannel {
            id: "x".into(),
            name: "X".into(),
            icon: "#".into(),
        };
        // 3 голоса, но лишь 1 высокорепутационный → нет кворума доверия.
        let votes = [v("a", true), v("b", true), v("c", true)];
        let sc = scores(&[("a", 60.0), ("b", 5.0), ("c", 5.0)]);
        let t = tally(&kind, 0, &votes, &sc, VOTING_WINDOW_SECS + 1);
        assert_eq!(t.outcome, Outcome::NoQuorum);
    }

    #[test]
    fn ineligible_votes_excluded() {
        let kind = ProposalKind::AddChannel {
            id: "x".into(),
            name: "X".into(),
            icon: "#".into(),
        };
        // c — нулевая репутация (не eligible), d — неизвестен (=0). Останется 2 → < min_voters(3).
        let votes = [v("a", true), v("b", true), v("c", true), v("d", true)];
        let sc = scores(&[("a", 60.0), ("b", 55.0), ("c", 0.0)]);
        let t = tally(&kind, 0, &votes, &sc, VOTING_WINDOW_SECS + 1);
        assert_eq!(t.eligible, 2);
        assert_eq!(t.outcome, Outcome::NoQuorum);
    }

    #[test]
    fn ban_user_needs_two_thirds() {
        let kind = ProposalKind::BanUser { target: "victim".into() };
        // 7 голосов, 3 высокорепутационных. 5 «за» / 2 «против» = 71% ≥ ⅔ → проходит.
        let votes = [
            v("a", true), v("b", true), v("c", true), v("d", true), v("e", true),
            v("f", false), v("g", false),
        ];
        let sc = scores(&[
            ("a", 60.0), ("b", 55.0), ("c", 51.0),
            ("d", 10.0), ("e", 10.0), ("f", 10.0), ("g", 10.0),
        ]);
        let t = tally(&kind, 0, &votes, &sc, VOTING_WINDOW_SECS + 1);
        assert_eq!((t.yes, t.no, t.high), (5, 2, 3));
        assert_eq!(t.outcome, Outcome::Passed);
    }

    #[test]
    fn ban_user_rejected_below_two_thirds() {
        let kind = ProposalKind::BanUser { target: "victim".into() };
        // 7 голосов, 3 высокорепутационных, но 4 «за» / 3 «против» = 57% < ⅔.
        let votes = [
            v("a", true), v("b", true), v("c", true), v("d", true),
            v("e", false), v("f", false), v("g", false),
        ];
        let sc = scores(&[
            ("a", 60.0), ("b", 55.0), ("c", 51.0),
            ("d", 10.0), ("e", 10.0), ("f", 10.0), ("g", 10.0),
        ]);
        let t = tally(&kind, 0, &votes, &sc, VOTING_WINDOW_SECS + 1);
        assert_eq!(t.outcome, Outcome::Rejected);
    }

    #[test]
    fn open_window_marks_provisional() {
        let kind = ProposalKind::AddChannel {
            id: "x".into(),
            name: "X".into(),
            icon: "#".into(),
        };
        let votes = [v("a", true), v("b", true), v("c", true)];
        let sc = scores(&[("a", 60.0), ("b", 55.0), ("c", 5.0)]);
        // now внутри окна → open == true, но outcome уже считается (живой).
        let t = tally(&kind, 1_000, &votes, &sc, 1_001);
        assert!(t.open);
        assert_eq!(t.outcome, Outcome::Passed);
    }
}
