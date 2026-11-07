//! Подсчёт голосов по весам доверия (проект — `Obsidian/Сеть доверия.md`,
//! раздел «Голосования»).
//!
//! Подсчёт — чистая функция от (тип, набор голосов, веса голосующих, время).
//! Вес голоса — доверие к голосующему **в глазах этого узла** (лично
//! проверенный — 1, «через знакомых» — его `t`, освоившиеся — из общего пула,
//! незнакомцы — 0). Веса считает backend по сети доверия, поэтому крейт от неё
//! не зависит. Разные узлы видят разные итоги — это свойство модели: итог
//! применяется «в моей сети».

use std::collections::HashMap;

use crate::types::{ProposalKind, VOTING_WINDOW_SECS};

/// Голосующий в глазах этого узла.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VoterWeight {
    /// Вес голоса (0..=1).
    pub weight: f64,
    /// Доверен «через знакомых» или лично (`t ≥ 0.05`) — для кворума по людям.
    pub trusted: bool,
}

/// Пороги валидности и прохождения для типа предложения.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TallyParams {
    /// Минимальный суммарный вес проголосовавших (кворум по весу).
    pub min_weight: f64,
    /// Минимум доверенных (`t ≥ 0.05`) среди проголосовавших.
    pub min_trusted: usize,
    /// `true` — нужно ⅔ веса «за»; `false` — строго больше половины.
    pub supermajority: bool,
}

/// Пороги по типу предложения.
pub fn params(kind: &ProposalKind) -> TallyParams {
    match kind {
        // Безопасное добавление — мягкий порог.
        ProposalKind::AddChannel { .. } => TallyParams {
            min_weight: 1.5,
            min_trusted: 2,
            supermajority: false,
        },
        // Опасные и спорные действия — жёсткий порог.
        ProposalKind::BanUser { .. }
        | ProposalKind::UnbanUser { .. }
        | ProposalKind::RemoveFile { .. } => TallyParams {
            min_weight: 3.0,
            min_trusted: 3,
            supermajority: true,
        },
    }
}

/// Итог голосования.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Принято (порог пройден, кворум выполнен).
    Passed,
    /// Отклонено (кворум выполнен, но не хватило веса «за»).
    Rejected,
    /// Нет кворума (мало веса или мало доверенных голосующих).
    NoQuorum,
}

/// Результат подсчёта. Голоса с нулевым весом не учитываются.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tally {
    /// Вес «за» и «против».
    pub yes: f64,
    pub no: f64,
    /// Сколько голосов с ненулевым весом «за» и «против».
    pub yes_count: usize,
    pub no_count: usize,
    /// Сколько из них доверенных (для кворума по людям).
    pub trusted: usize,
    pub outcome: Outcome,
    /// Окно ещё открыто → `outcome` предварительный (живой подсчёт).
    pub open: bool,
}

impl Tally {
    /// Суммарный вес проголосовавших.
    pub fn weight(&self) -> f64 {
        self.yes + self.no
    }
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

/// Подсчитывает итог. `weights` — вес каждого голосующего в глазах этого узла
/// (нет в карте — вес 0).
pub fn tally(
    kind: &ProposalKind,
    created_at: i64,
    votes: &[VoteRecord],
    weights: &HashMap<String, VoterWeight>,
    now: i64,
) -> Tally {
    let p = params(kind);
    let mut t = Tally {
        yes: 0.0,
        no: 0.0,
        yes_count: 0,
        no_count: 0,
        trusted: 0,
        outcome: Outcome::NoQuorum,
        open: !is_closed(created_at, now),
    };
    for v in votes {
        let Some(w) = weights.get(&v.voter_key).filter(|w| w.weight > 0.0) else {
            continue; // голос без веса
        };
        if v.choice {
            t.yes += w.weight;
            t.yes_count += 1;
        } else {
            t.no += w.weight;
            t.no_count += 1;
        }
        if w.trusted {
            t.trusted += 1;
        }
    }
    t.outcome = if t.weight() + EPS < p.min_weight || t.trusted < p.min_trusted {
        Outcome::NoQuorum
    } else if passes(t.yes, t.weight(), p.supermajority) {
        Outcome::Passed
    } else {
        Outcome::Rejected
    };
    t
}

/// Допуск сравнения сумм весов (сумма дробей может недобрать в последнем знаке).
const EPS: f64 = 1e-9;

/// Пройден ли порог по весу.
fn passes(yes: f64, total: f64, supermajority: bool) -> bool {
    if total <= 0.0 {
        return false;
    }
    if supermajority {
        yes * 3.0 + EPS >= total * 2.0 // ≥ ⅔
    } else {
        yes * 2.0 > total + EPS // строго > ½
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(key: &str, choice: bool) -> VoteRecord {
        VoteRecord { voter_key: key.into(), choice, created_at: 0 }
    }

    /// Веса: `(ключ, вес, доверенный)`.
    fn weights(pairs: &[(&str, f64, bool)]) -> HashMap<String, VoterWeight> {
        pairs
            .iter()
            .map(|(k, w, t)| (k.to_string(), VoterWeight { weight: *w, trusted: *t }))
            .collect()
    }

    fn channel() -> ProposalKind {
        ProposalKind::AddChannel { id: "x".into(), name: "X".into(), icon: "#".into() }
    }

    const CLOSED: i64 = VOTING_WINDOW_SECS + 1;

    #[test]
    fn add_channel_passes_with_weight_quorum() {
        // Двое лично проверенных — вес 2.0 ≥ 1.5, доверенных 2.
        let votes = [v("a", true), v("b", true)];
        let w = weights(&[("a", 1.0, true), ("b", 1.0, true)]);
        let t = tally(&channel(), 0, &votes, &w, CLOSED);
        assert_eq!(t.outcome, Outcome::Passed);
        assert_eq!((t.yes_count, t.no_count, t.trusted), (2, 0, 2));
        assert!(!t.open);
    }

    #[test]
    fn many_weak_voters_do_not_make_quorum_of_people() {
        // Десять освоившихся из общего пула (вместе 1.0) и один доверенный:
        // вес 1.5 есть, но доверенных людей только один.
        let mut pairs: Vec<(String, f64, bool)> = (0..10).map(|i| (format!("s{i}"), 0.1, false)).collect();
        pairs.push(("a".into(), 0.5, true));
        let w: HashMap<String, VoterWeight> = pairs
            .iter()
            .map(|(k, w, t)| (k.clone(), VoterWeight { weight: *w, trusted: *t }))
            .collect();
        let votes: Vec<VoteRecord> = pairs.iter().map(|(k, _, _)| v(k, true)).collect();
        let t = tally(&channel(), 0, &votes, &w, CLOSED);
        assert!((t.weight() - 1.5).abs() < 1e-9);
        assert_eq!(t.outcome, Outcome::NoQuorum);
    }

    #[test]
    fn strangers_have_no_say() {
        // Тысяча незнакомцев против — их голоса не весят ничего.
        let mut votes = vec![v("a", true), v("b", true)];
        votes.extend((0..1000).map(|i| v(&format!("bot{i}"), false)));
        let w = weights(&[("a", 1.0, true), ("b", 0.6, true)]);
        let t = tally(&channel(), 0, &votes, &w, CLOSED);
        assert_eq!((t.yes_count, t.no_count), (2, 0));
        assert_eq!(t.outcome, Outcome::Passed);
    }

    #[test]
    fn ban_needs_two_thirds_of_weight() {
        let kind = ProposalKind::BanUser { target: "victim".into() };
        let w = weights(&[("a", 1.0, true), ("b", 1.0, true), ("c", 1.0, true), ("d", 0.5, true)]);
        // 2.0 «за» из 3.0 — ровно ⅔ → проходит.
        let t = tally(&kind, 0, &[v("a", true), v("b", true), v("c", false)], &w, CLOSED);
        assert_eq!(t.outcome, Outcome::Passed);
        // 2.0 «за» из 3.5 — меньше ⅔ → отклонено.
        let t = tally(&kind, 0, &[v("a", true), v("b", true), v("c", false), v("d", false)], &w, CLOSED);
        assert_eq!(t.outcome, Outcome::Rejected);
        // Вес 2.5 < 3.0 — нет кворума, даже если все «за».
        let t = tally(&kind, 0, &[v("a", true), v("b", true), v("d", true)], &w, CLOSED);
        assert_eq!(t.outcome, Outcome::NoQuorum);
    }

    #[test]
    fn simple_majority_is_strict() {
        let w = weights(&[("a", 1.0, true), ("b", 1.0, true)]);
        let t = tally(&channel(), 0, &[v("a", true), v("b", false)], &w, CLOSED);
        assert_eq!(t.outcome, Outcome::Rejected, "ровно половина — не большинство");
    }

    #[test]
    fn open_window_marks_provisional() {
        let w = weights(&[("a", 1.0, true), ("b", 1.0, true)]);
        let t = tally(&channel(), 1_000, &[v("a", true), v("b", true)], &w, 1_001);
        assert!(t.open);
        assert_eq!(t.outcome, Outcome::Passed);
    }
}
