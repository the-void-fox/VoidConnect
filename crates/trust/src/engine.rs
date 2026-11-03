//! Расчёт доверия от лица узла.
//!
//! ```text
//! t(X) = 1                                  я лично проверил X
//! t(Y) = min(1, Σ_{V→Y} t(V) · DECAY · w(kind) · m(V) / out(V))
//! ```
//!
//! Слоями от себя, не глубже [`MAX_DEPTH`] шагов; вклад идёт только от узлов
//! более ранних слоёв (без обратных потоков и циклов). `out(V)` — число
//! поручительств V: суммарный исходящий вклад узла не больше половины его
//! собственного доверия, поэтому доверие по графу только убывает — тысяча
//! ботов за одним обманутым весит не больше доли этого обманутого.
//! `m(V) = ACCOUNTABILITY^k`, где `k` — сколько подопечных V сейчас «плохие»
//! (заблокированы мной или под жалобами).

use std::collections::{HashMap, HashSet};

use void_core::identity::NodeId;

use crate::types::{Vouch, VouchKind};

/// Ослабление доверия за один шаг цепочки.
pub const DECAY: f64 = 0.5;
/// Сколько шагов от себя учитывается: я → А (лично) → Б → В.
pub const MAX_DEPTH: usize = 3;
/// Вес поручительства встречающего относительно личного.
pub const GREETER_WEIGHT: f64 = 0.3;
/// С этого доверия узел — «через знакомых».
pub const TRUSTED_THRESHOLD: f64 = 0.05;
/// С этого доверия по графу узел — «освоившийся». Ниже — незнакомец: иначе
/// злоумышленник, обманувший одного человека, раздал бы своим ботам по
/// микроскопической доле и вывел их всех из-под лимитов незнакомца.
pub const SETTLED_MIN_TRUST: f64 = 0.005;
/// Вес голоса освоившегося (до деления общего пула).
pub const SETTLED_WEIGHT: f64 = 0.02;
/// Все освоившиеся вместе весят не больше одного лично проверенного.
pub const SETTLED_POOL: f64 = 1.0;
/// Множитель вклада поручителя за каждого «плохого» подопечного.
pub const ACCOUNTABILITY: f64 = 0.5;
/// Сколько поручителей показывать в «через знакомых: …».
const VIA_SHOWN: usize = 3;

/// Уровень доверия (по возрастанию).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustLevel {
    /// Заблокирован мной.
    Blocked,
    /// Ничего не известно (или под жалобами).
    Stranger,
    /// Слабая цепочка, приветствие встречающего или «по поведению».
    Settled,
    /// Через знакомых: `t ≥ TRUSTED_THRESHOLD`.
    Trusted,
    /// Проверен лично.
    Verified,
}

/// Доверие к узлу с точки зрения моего узла.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustInfo {
    pub level: TrustLevel,
    /// Доверие по графу `t` (0..=1).
    pub weight: f64,
    /// Самые весомые поручители (для «через знакомых: Аня, Вика»).
    pub via: Vec<NodeId>,
    /// Под жалобами моей сети доверия.
    pub reported: bool,
    /// Освоился «по поведению» или поприветствован мной.
    pub settled: bool,
}

impl TrustInfo {
    fn stranger() -> Self {
        Self { level: TrustLevel::Stranger, weight: 0.0, via: Vec::new(), reported: false, settled: false }
    }
}

/// Что узел знает для расчёта.
pub struct TrustInputs<'a> {
    /// Мой узел.
    pub me: &'a NodeId,
    /// Последние версии поручительств (уже проверенные `Vouch::from_signed`).
    pub vouches: &'a [Vouch],
    /// Заблокированные мной.
    pub blocked: &'a HashSet<NodeId>,
    /// Под жалобами моей сети доверия.
    pub reported: &'a HashSet<NodeId>,
    /// Освоившиеся «по поведению» (мой узел видел их активными достаточно долго).
    pub settled: &'a HashSet<NodeId>,
}

/// Результат расчёта: доверие ко всем узлам, о которых что-то известно.
#[derive(Debug, Clone, Default)]
pub struct TrustMap {
    map: HashMap<NodeId, TrustInfo>,
}

impl TrustMap {
    /// Доверие к узлу (незнакомец, если о нём ничего не известно).
    pub fn get(&self, id: &NodeId) -> TrustInfo {
        self.map.get(id).cloned().unwrap_or_else(TrustInfo::stranger)
    }

    pub fn level(&self, id: &NodeId) -> TrustLevel {
        self.map.get(id).map(|i| i.level).unwrap_or(TrustLevel::Stranger)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &TrustInfo)> {
        self.map.iter()
    }

    /// Веса участников голосования (или жалоб): лично проверенные — 1,
    /// «через знакомых» — своё `t`, освоившиеся — своё `t` (освоившиеся «по
    /// поведению» — не меньше [`SETTLED_WEIGHT`]), все освоившиеся вместе — не
    /// больше [`SETTLED_POOL`]; незнакомцы и заблокированные — 0.
    pub fn weights<'a>(&self, ids: impl IntoIterator<Item = &'a NodeId>) -> HashMap<NodeId, f64> {
        let mut out = HashMap::new();
        let mut settled = Vec::new();
        for id in ids {
            let info = self.get(id);
            let w = match info.level {
                TrustLevel::Verified => 1.0,
                TrustLevel::Trusted => info.weight,
                TrustLevel::Settled => {
                    settled.push(id.clone());
                    continue;
                }
                TrustLevel::Stranger | TrustLevel::Blocked => 0.0,
            };
            out.insert(id.clone(), w);
        }
        let settled_weight = |info: &TrustInfo| {
            if info.settled { SETTLED_WEIGHT.max(info.weight) } else { info.weight }
        };
        let pool: f64 = settled.iter().map(|id| settled_weight(&self.get(id))).sum();
        let scale = if pool > SETTLED_POOL { SETTLED_POOL / pool } else { 1.0 };
        for id in settled {
            let w = settled_weight(&self.get(&id)) * scale;
            out.insert(id, w);
        }
        out
    }
}

fn kind_weight(kind: VouchKind) -> f64 {
    match kind {
        VouchKind::Personal => 1.0,
        VouchKind::Greeter => GREETER_WEIGHT,
    }
}

/// Считает доверие ко всем узлам от лица `inputs.me`.
pub fn compute(inputs: &TrustInputs) -> TrustMap {
    let me = inputs.me;
    // Исключённые: их поручительства не учитываются, сами они доверия не получают.
    let excluded = |id: &NodeId| inputs.blocked.contains(id) || inputs.reported.contains(id);

    // Действующие поручительства (рёбра графа) по поручителям.
    let mut edges: HashMap<&NodeId, Vec<(&NodeId, VouchKind)>> = HashMap::new();
    for v in inputs.vouches {
        if v.revoked || v.voucher == v.subject || &v.subject == me || excluded(&v.voucher) {
            continue;
        }
        edges.entry(&v.voucher).or_default().push((&v.subject, v.kind));
    }
    let multiplier = |v: &NodeId| -> f64 {
        let bad = edges.get(v).map(|es| es.iter().filter(|(s, _)| excluded(s)).count()).unwrap_or(0);
        ACCOUNTABILITY.powi(bad as i32)
    };

    let mut trust: HashMap<NodeId, f64> = HashMap::new();
    let mut depth_of: HashMap<NodeId, usize> = HashMap::new();
    let mut via: HashMap<NodeId, Vec<(f64, NodeId)>> = HashMap::new();
    let mut verified: HashSet<NodeId> = HashSet::new();
    let mut greeted_by_me: HashSet<NodeId> = HashSet::new();
    depth_of.insert(me.clone(), 0);

    // Слой 1: мои поручительства. Личное — полное доверие; моё приветствие
    // новичка — уровень «освоившийся» (это моё же слабое решение).
    let mut frontier: Vec<NodeId> = Vec::new();
    for (subject, kind) in edges.get(me).into_iter().flatten() {
        if excluded(subject) {
            continue;
        }
        match kind {
            VouchKind::Personal => {
                trust.insert((*subject).clone(), 1.0);
                depth_of.insert((*subject).clone(), 1);
                verified.insert((*subject).clone());
                frontier.push((*subject).clone());
            }
            VouchKind::Greeter => {
                greeted_by_me.insert((*subject).clone());
            }
        }
    }

    // Слои 2..=MAX_DEPTH: вклад только от узлов предыдущего слоя.
    for depth in 1..MAX_DEPTH {
        let mut next: HashMap<NodeId, f64> = HashMap::new();
        for voucher in &frontier {
            let Some(out) = edges.get(voucher) else { continue };
            let share = trust[voucher] * DECAY * multiplier(voucher) / out.len() as f64;
            for (subject, kind) in out {
                if excluded(subject) || depth_of.get(*subject).is_some_and(|d| *d <= depth) {
                    continue;
                }
                let c = share * kind_weight(*kind);
                *next.entry((*subject).clone()).or_insert(0.0) += c;
                via.entry((*subject).clone()).or_default().push((c, voucher.clone()));
            }
        }
        frontier = Vec::with_capacity(next.len());
        for (subject, t) in next {
            trust.insert(subject.clone(), t.min(1.0));
            depth_of.insert(subject.clone(), depth + 1);
            frontier.push(subject);
        }
    }

    let mut map: HashMap<NodeId, TrustInfo> = HashMap::new();
    for (id, t) in &trust {
        let level = if verified.contains(id) {
            TrustLevel::Verified
        } else if *t >= TRUSTED_THRESHOLD {
            TrustLevel::Trusted
        } else if *t >= SETTLED_MIN_TRUST {
            TrustLevel::Settled
        } else {
            TrustLevel::Stranger
        };
        let mut shown = via.remove(id).unwrap_or_default();
        shown.sort_by(|a, b| b.0.total_cmp(&a.0));
        let via = shown.into_iter().take(VIA_SHOWN).map(|(_, v)| v).collect();
        map.insert(id.clone(), TrustInfo { level, weight: *t, via, reported: false, settled: false });
    }
    // Освоившиеся по поведению и поприветствованные мной — не ниже Settled.
    for id in inputs.settled.iter().chain(greeted_by_me.iter()) {
        if id == me || excluded(id) {
            continue;
        }
        let info = map.entry(id.clone()).or_insert_with(TrustInfo::stranger);
        info.settled = true;
        info.level = info.level.max(TrustLevel::Settled);
    }
    for id in inputs.reported {
        map.insert(id.clone(), TrustInfo { reported: true, ..TrustInfo::stranger() });
    }
    for id in inputs.blocked {
        map.insert(id.clone(), TrustInfo { level: TrustLevel::Blocked, ..TrustInfo::stranger() });
    }
    TrustMap { map }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(i: u32) -> NodeId {
        NodeId(format!("{i:064x}"))
    }

    fn v(from: u32, to: u32) -> Vouch {
        Vouch { voucher: n(from), subject: n(to), kind: VouchKind::Personal, updated_at: 1, revoked: false }
    }

    fn greet(from: u32, to: u32) -> Vouch {
        Vouch { kind: VouchKind::Greeter, ..v(from, to) }
    }

    /// Я — узел 0.
    fn run(vouches: &[Vouch]) -> TrustMap {
        run_with(vouches, &[], &[], &[])
    }

    fn run_with(vouches: &[Vouch], blocked: &[u32], reported: &[u32], settled: &[u32]) -> TrustMap {
        let set = |xs: &[u32]| xs.iter().map(|i| n(*i)).collect::<HashSet<_>>();
        compute(&TrustInputs {
            me: &n(0),
            vouches,
            blocked: &set(blocked),
            reported: &set(reported),
            settled: &set(settled),
        })
    }

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn personal_check_is_full_trust() {
        let m = run(&[v(0, 1), v(0, 2)]);
        assert_eq!(m.level(&n(1)), TrustLevel::Verified);
        assert!(approx(m.get(&n(2)).weight, 1.0));
        assert_eq!(m.level(&n(3)), TrustLevel::Stranger);
    }

    /// Пример из документа: Аня (1) ручается за четверых, среди них Боря (2).
    #[test]
    fn trust_decays_and_splits_by_fanout() {
        let m = run(&[v(0, 1), v(1, 2), v(1, 3), v(1, 4), v(1, 5)]);
        assert!(approx(m.get(&n(2)).weight, 0.125));
        assert_eq!(m.level(&n(2)), TrustLevel::Trusted);
        assert_eq!(m.get(&n(2)).via, vec![n(1)]);
    }

    /// Несколько независимых поручителей складываются (и показываются по весу).
    #[test]
    fn independent_vouchers_add_up() {
        // Аня (1): за 4 человек; Вика (6): за двоих — Борю (2) и ещё одного.
        let m = run(&[v(0, 1), v(1, 2), v(1, 3), v(1, 4), v(1, 5), v(0, 6), v(6, 2), v(6, 7)]);
        assert!(approx(m.get(&n(2)).weight, 0.375));
        assert_eq!(m.get(&n(2)).via, vec![n(6), n(1)], "сначала самый весомый поручитель");
    }

    #[test]
    fn trust_is_capped_at_one() {
        let mut vs: Vec<Vouch> = (1..=10).map(|i| v(0, i)).collect();
        vs.extend((1..=10).map(|i| v(i, 100)));
        assert!(approx(run(&vs).get(&n(100)).weight, 1.0));
    }

    /// Цепочка я → 1 → 2 → 3 → 4: четвёртый шаг не учитывается.
    #[test]
    fn depth_is_limited() {
        let m = run(&[v(0, 1), v(1, 2), v(2, 3), v(3, 4)]);
        assert!(approx(m.get(&n(2)).weight, 0.5));
        assert!(approx(m.get(&n(3)).weight, 0.25));
        assert_eq!(m.level(&n(4)), TrustLevel::Stranger);
    }

    /// Главное свойство: злоумышленник обманул одного честного (H) и завёл
    /// 1000 ботов, которые ручаются друг за друга. Вся «бот-зона» весит меньше
    /// доли H, и ни один бот не становится «через знакомых».
    #[test]
    fn sybil_farm_is_bounded_by_the_attack_edge() {
        let attacker = 50u32;
        let bots: Vec<u32> = (1000..2000).collect();
        // Я лично проверил 10 человек, они ручаются друг за друга по кругу.
        let mut vs: Vec<Vouch> = (1..=10).map(|i| v(0, i)).collect();
        vs.extend((1..=10).map(|i| v(i, i % 10 + 1)));
        // Честный H = 1 ещё и поручился за злоумышленника (ребро атаки).
        vs.push(v(1, attacker));
        // Злоумышленник ручается за всех ботов, боты — друг за друга.
        vs.extend(bots.iter().map(|b| v(attacker, *b)));
        vs.extend(bots.windows(2).map(|w| v(w[0], w[1])));
        let m = run(&vs);

        let h = m.get(&n(1)).weight; // 1.0 — лично проверен
        let h_out = 2.0; // H ручается за соседа по кругу и за злоумышленника
        let attack_share = h * DECAY / h_out;
        let region: f64 = std::iter::once(attacker).chain(bots.iter().copied())
            .map(|i| m.get(&n(i)).weight)
            .sum();
        assert!(region <= 2.0 * attack_share + 1e-9, "бот-зона {region} > {}", 2.0 * attack_share);
        assert!(
            bots.iter().all(|b| m.level(&n(*b)) == TrustLevel::Stranger),
            "боты остаются незнакомцами (их доля ниже SETTLED_MIN_TRUST)"
        );
        // И вместе в голосовании они почти ничего не весят.
        let bot_ids: Vec<NodeId> = bots.iter().map(|b| n(*b)).collect();
        assert!(m.weights(bot_ids.iter()).values().sum::<f64>() < 1e-9);
    }

    #[test]
    fn revoked_vouch_is_ignored() {
        let m = run(&[v(0, 1), Vouch { revoked: true, ..v(1, 2) }]);
        assert_eq!(m.level(&n(2)), TrustLevel::Stranger);
    }

    /// Поручился за «плохого» — вес остальных твоих поручительств падает вдвое.
    #[test]
    fn voucher_is_accountable_for_bad_subjects() {
        let vs = [v(0, 1), v(1, 2), v(1, 3)];
        let before = run(&vs).get(&n(2)).weight;
        let m = run_with(&vs, &[], &[3], &[]);
        assert!(approx(m.get(&n(2)).weight, before * ACCOUNTABILITY));
        assert!(m.get(&n(3)).reported);
        assert_eq!(m.level(&n(3)), TrustLevel::Stranger);
    }

    #[test]
    fn blocked_node_gets_nothing_and_its_vouches_ignored() {
        let m = run_with(&[v(0, 1), v(1, 2), v(2, 3)], &[2], &[], &[]);
        assert_eq!(m.level(&n(2)), TrustLevel::Blocked);
        assert_eq!(m.level(&n(3)), TrustLevel::Stranger);
    }

    #[test]
    fn greeter_vouch_is_weaker() {
        let m = run(&[v(0, 1), greet(1, 2), v(1, 3)]);
        assert!(approx(m.get(&n(2)).weight, 0.25 * GREETER_WEIGHT));
        assert!(approx(m.get(&n(3)).weight, 0.25));
        // Моё собственное приветствие — уровень «освоившийся».
        assert_eq!(run(&[greet(0, 5)]).level(&n(5)), TrustLevel::Settled);
    }

    #[test]
    fn behavior_settled_nodes_share_a_pool() {
        let few: Vec<u32> = (100..110).collect();
        let m = run_with(&[], &[], &[], &few);
        let ids: Vec<NodeId> = few.iter().map(|i| n(*i)).collect();
        let w = m.weights(ids.iter());
        assert!(approx(w.values().sum::<f64>(), 10.0 * SETTLED_WEIGHT));

        let many: Vec<u32> = (100..400).collect();
        let m = run_with(&[], &[], &[], &many);
        let ids: Vec<NodeId> = many.iter().map(|i| n(*i)).collect();
        let total: f64 = m.weights(ids.iter()).values().sum();
        assert!(approx(total, SETTLED_POOL), "300 освоившихся весят вместе {total}");
    }

    #[test]
    fn weights_by_level() {
        let m = run_with(&[v(0, 1), v(1, 2), v(1, 3)], &[9], &[], &[5]);
        let ids = [n(1), n(2), n(5), n(8), n(9)];
        let w = m.weights(ids.iter());
        assert!(approx(w[&n(1)], 1.0));
        assert!(approx(w[&n(2)], 0.25));
        assert!(approx(w[&n(5)], SETTLED_WEIGHT));
        assert!(approx(w[&n(8)], 0.0), "незнакомец");
        assert!(approx(w[&n(9)], 0.0), "заблокирован");
    }

    /// Новичок, которого поприветствовал проверенный мной встречающий, —
    /// «освоившийся»: это путь для того, кто никого не знает.
    #[test]
    fn greeted_newcomer_is_settled() {
        // Встречающий (1) проверен мной и поприветствовал 10 новичков.
        let mut vs = vec![v(0, 1)];
        vs.extend((100..110).map(|i| greet(1, i)));
        let m = run(&vs);
        let t = m.get(&n(100)).weight;
        assert!(approx(t, 0.5 * GREETER_WEIGHT / 10.0));
        assert_eq!(m.level(&n(100)), TrustLevel::Settled);
    }
}
