//! Карта соединений сети: каждый узел рассылает подписанный список своих
//! соседей — с кем у его общего чата сейчас связь. Из этих списков строится
//! граф сети.
//!
//! Узел может солгать о своих соседях, поэтому связь считается подтверждённой,
//! только если её называют оба конца ([`edges`]). Свои связи узел знает сам.
//! Списки устаревают через [`TOPOLOGY_TTL_MS`]: узел, переставший их обновлять
//! (ушёл из сети), из карты выпадает.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use void_core::identity::NodeId;
use void_core::sanitize::is_hex64;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;

/// Контекст подписи: подписанные данные другого типа не выдать за список связей.
const CONTEXT: &[u8] = b"void-connect/links/v1\n";
/// Больше соседей в одном списке не принимаем (у узла их обычно 3–10).
pub const MAX_NEIGHBORS: usize = 64;
/// Сколько живёт список без обновления (узел обновляет его раз в 5 минут).
pub const TOPOLOGY_TTL_MS: i64 = 15 * 60 * 1000;
/// Сколько узлов держим в карте (сверх — новые не принимаем).
pub const MAX_NODES: usize = 4096;

/// Соседи узла на момент `updated_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkSet {
    pub node_id: NodeId,
    pub neighbors: Vec<NodeId>,
    /// Версия (unix-мс): принимается только более новая.
    pub updated_at: i64,
}

impl LinkSet {
    fn payload(&self) -> Vec<u8> {
        let mut out = CONTEXT.to_vec();
        out.extend_from_slice(&serde_json::to_vec(self).expect("LinkSet сериализуется"));
        out
    }

    /// Подписывает список ключом узла (он должен совпадать с `node_id`).
    pub fn sign(&self, kp: &SigningKeypair) -> Option<SignedMessage> {
        if NodeId::from_public_key_bytes(&kp.public_bytes()) != self.node_id {
            return None;
        }
        SignedMessage::sign(self.payload(), kp).ok()
    }

    /// Проверяет подписанный список из сети: контекст, подпись, подписант =
    /// узел, ID в формате hex64, не больше [`MAX_NEIGHBORS`], без себя.
    pub fn from_signed(signed: &SignedMessage) -> Option<Self> {
        let body = signed.payload.strip_prefix(CONTEXT)?;
        let set: LinkSet = serde_json::from_slice(body).ok()?;
        signed.verify().ok()?;
        let valid = signed.signer == set.node_id.as_str()
            && is_hex64(set.node_id.as_str())
            && set.neighbors.len() <= MAX_NEIGHBORS
            && set.neighbors.iter().all(|n| is_hex64(n.as_str()) && *n != set.node_id);
        valid.then_some(set)
    }
}

/// Последние списки соседей узлов (с подписью — для передачи новым связям).
#[derive(Default)]
pub struct Topology {
    sets: HashMap<NodeId, (LinkSet, SignedMessage)>,
}

impl Topology {
    /// Принимает список, если он новее известного. `true` — карта изменилась.
    pub fn apply(&mut self, set: LinkSet, signed: SignedMessage) -> bool {
        match self.sets.get(&set.node_id) {
            Some((old, _)) if old.updated_at >= set.updated_at => false,
            None if self.sets.len() >= MAX_NODES => false,
            _ => {
                self.sets.insert(set.node_id.clone(), (set, signed));
                true
            }
        }
    }

    /// Последняя версия списка узла.
    pub fn get(&self, id: &NodeId) -> Option<&LinkSet> {
        self.sets.get(id).map(|(s, _)| s)
    }

    /// Забывает устаревшие списки.
    pub fn prune(&mut self, now_ms: i64) {
        self.sets.retain(|_, (s, _)| now_ms - s.updated_at <= TOPOLOGY_TTL_MS);
    }

    /// Свежие подписанные списки — передать новой связи.
    pub fn signed_fresh(&self, now_ms: i64) -> Vec<SignedMessage> {
        self.sets
            .values()
            .filter(|(s, _)| now_ms - s.updated_at <= TOPOLOGY_TTL_MS)
            .map(|(_, signed)| signed.clone())
            .collect()
    }

    /// Свежая карта: узел → его соседи.
    pub fn snapshot(&self, now_ms: i64) -> HashMap<NodeId, Vec<NodeId>> {
        self.sets
            .values()
            .filter(|(s, _)| now_ms - s.updated_at <= TOPOLOGY_TTL_MS)
            .map(|(s, _)| (s.node_id.clone(), s.neighbors.clone()))
            .collect()
    }
}

/// Связь на графе.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edge {
    pub a: NodeId,
    pub b: NodeId,
    /// Её называют оба конца (или это наша собственная связь).
    pub confirmed: bool,
}

/// Связи из карты соединений. Каждая пара — один раз; связь подтверждена, если
/// оба узла назвали друг друга, а для наших связей достаточно нашего списка
/// (свои связи мы знаем точно). Чужие заявления о связи с нами, которых нет в
/// нашем списке, — ложь: такие связи не показываем вовсе.
pub fn edges(map: &HashMap<NodeId, Vec<NodeId>>, me: &NodeId) -> Vec<Edge> {
    let lists: HashMap<&NodeId, HashSet<&NodeId>> =
        map.iter().map(|(id, ns)| (id, ns.iter().collect())).collect();
    let claims = |from: &NodeId, to: &NodeId| lists.get(from).is_some_and(|ns| ns.contains(to));
    let mut seen: HashSet<(&NodeId, &NodeId)> = HashSet::new();
    let mut out = Vec::new();
    for (from, ns) in &lists {
        for to in ns {
            let (a, b) = if from.as_str() < to.as_str() { (*from, *to) } else { (*to, *from) };
            if !seen.insert((a, b)) {
                continue;
            }
            let confirmed = if a == me || b == me {
                let other = if a == me { b } else { a };
                if !claims(me, other) {
                    continue; // нас приписали к чужому списку
                }
                true
            } else {
                claims(a, b) && claims(b, a)
            };
            out.push(Edge { a: a.clone(), b: b.clone(), confirmed });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    fn id(seed: u8) -> NodeId {
        NodeId::from_public_key_bytes(&kp(seed).public_bytes())
    }

    fn set(seed: u8, ns: &[u8], at: i64) -> LinkSet {
        LinkSet { node_id: id(seed), neighbors: ns.iter().map(|n| id(*n)).collect(), updated_at: at }
    }

    #[test]
    fn signed_roundtrip_and_forgery_rejected() {
        let s = set(1, &[2, 3], 10);
        let signed = s.sign(&kp(1)).unwrap();
        assert_eq!(LinkSet::from_signed(&signed), Some(s.clone()));
        assert!(s.sign(&kp(9)).is_none(), "чужим ключом не подписать");
        // Список «от имени» узла 1, подписанный узлом 9.
        let mut forged = SignedMessage::sign(s.payload(), &kp(9)).unwrap();
        assert!(LinkSet::from_signed(&forged).is_none());
        forged.signer = id(1).as_str().to_string();
        assert!(LinkSet::from_signed(&forged).is_none(), "подпись не сходится");
        let selfie = set(1, &[1], 10).sign(&kp(1)).unwrap();
        assert!(LinkSet::from_signed(&selfie).is_none(), "сосед сам себе");
    }

    #[test]
    fn only_newer_version_applies_and_stale_expires() {
        let mut t = Topology::default();
        let a = set(1, &[2], 100);
        assert!(t.apply(a.clone(), a.sign(&kp(1)).unwrap()));
        let old = set(1, &[], 50);
        assert!(!t.apply(old.clone(), old.sign(&kp(1)).unwrap()), "старая версия");
        assert_eq!(t.snapshot(100)[&id(1)], vec![id(2)]);
        t.prune(100 + TOPOLOGY_TTL_MS + 1);
        assert!(t.snapshot(100).is_empty(), "устаревший список забыт");
    }

    #[test]
    fn edge_confirmed_only_by_both_ends() {
        let me = id(0);
        let map: HashMap<NodeId, Vec<NodeId>> = [
            (me.clone(), vec![id(1)]),
            (id(1), vec![me.clone(), id(2)]),
            (id(2), vec![id(1)]),
            // 9 заявляет связи со всеми — подтверждения нет, а связь с нами — ложь.
            (id(9), vec![id(1), id(2), me.clone()]),
        ]
        .into_iter()
        .collect();
        let es = edges(&map, &me);
        let find = |x: &NodeId, y: &NodeId| {
            es.iter().find(|e| (&e.a == x && &e.b == y) || (&e.a == y && &e.b == x)).map(|e| e.confirmed)
        };
        assert_eq!(find(&me, &id(1)), Some(true));
        assert_eq!(find(&id(1), &id(2)), Some(true));
        assert_eq!(find(&id(9), &id(1)), Some(false));
        assert_eq!(find(&id(9), &me), None, "нас к себе не приписать");
        assert_eq!(es.len(), 4, "каждая пара — один раз");
    }
}
