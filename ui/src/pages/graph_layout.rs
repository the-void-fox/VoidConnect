//! Раскладка графа «физикой», как в Obsidian: узлы отталкиваются, связи
//! стягивают их пружинами, всё слегка тянется к центру. Шаг считается раз в
//! кадр; когда движение затухает, расчёт засыпает до следующего изменения.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use eframe::egui::{Pos2, Vec2};
use void_core::identity::NodeId;

/// Сила отталкивания узлов (обратно квадрату расстояния).
const REPULSION: f32 = 9000.0;
/// Жёсткость пружины связи и её длина в покое.
const SPRING: f32 = 0.04;
const REST_LEN: f32 = 110.0;
/// Притяжение к центру — граф не разлетается.
const GRAVITY: f32 = 0.012;
/// Затухание скорости за шаг и предел скорости.
const DAMPING: f32 = 0.85;
const MAX_SPEED: f32 = 40.0;
/// Ближе этого узлы друг на друга не давят (без взрыва сил при совпадении).
const MIN_DIST: f32 = 8.0;
/// Средняя скорость, ниже которой раскладка считается устоявшейся.
const REST_SPEED: f32 = 0.05;

/// Положения узлов и их скорости.
#[derive(Default)]
pub struct Layout {
    pos: HashMap<NodeId, Pos2>,
    vel: HashMap<NodeId, Vec2>,
    /// Закреплённые пользователем (через меню) и якорь — не двигаются.
    pinned: HashSet<NodeId>,
    /// Узел, который сейчас тащат мышью: стоит под курсором, пока не отпустят.
    held: Option<NodeId>,
    moving: bool,
}

impl Layout {
    /// Приводит набор узлов к `nodes`: новые ставит рядом с уже размещённым
    /// соседом (или на окружность вокруг центра), пропавшие забывает. Якорь
    /// (свой узел) ставится в центр и закрепляется.
    pub fn sync(&mut self, nodes: &[NodeId], edges: &[(usize, usize, f32)], anchor: &NodeId) {
        let keep: HashSet<&NodeId> = nodes.iter().collect();
        self.pos.retain(|id, _| keep.contains(id));
        self.vel.retain(|id, _| keep.contains(id));
        self.pinned.retain(|id| keep.contains(id));
        if self.held.as_ref().is_some_and(|h| !keep.contains(h)) {
            self.held = None;
        }
        if !self.pos.contains_key(anchor) && keep.contains(anchor) {
            self.pos.insert(anchor.clone(), Pos2::ZERO);
            self.pinned.insert(anchor.clone());
        }
        for (i, id) in nodes.iter().enumerate() {
            if self.pos.contains_key(id) {
                continue;
            }
            let near = edges.iter().find_map(|&(a, b, _)| {
                let other = if a == i { b } else if b == i { a } else { return None };
                self.pos.get(&nodes[other]).copied()
            });
            let dir = Vec2::angled(angle_of(id));
            let p = match near {
                Some(n) => n + dir * REST_LEN,
                None => Pos2::ZERO + dir * 2.0 * REST_LEN,
            };
            self.pos.insert(id.clone(), p);
            self.moving = true;
        }
    }

    /// Один шаг симуляции. `edges` — пары индексов в `nodes` и сила пружины.
    pub fn step(&mut self, nodes: &[NodeId], edges: &[(usize, usize, f32)]) {
        if !self.moving || nodes.is_empty() {
            return;
        }
        let p: Vec<Vec2> = nodes.iter().map(|id| self.pos(id).to_vec2()).collect();
        let n = p.len();
        let mut f = vec![Vec2::ZERO; n];
        for i in 0..n {
            for j in i + 1..n {
                let mut d = p[i] - p[j];
                if d.length_sq() < 1e-6 {
                    d = Vec2::angled((i * 31 + j * 17) as f32); // совпали — разводим
                }
                let dist = d.length().max(MIN_DIST);
                let force = d / d.length() * (REPULSION / (dist * dist));
                f[i] += force;
                f[j] -= force;
            }
        }
        for &(a, b, w) in edges {
            let d = p[b] - p[a];
            let len = d.length().max(0.01);
            let force = d / len * (len - REST_LEN) * SPRING * w;
            f[a] += force;
            f[b] -= force;
        }
        let mut speed = 0.0;
        for (i, id) in nodes.iter().enumerate() {
            if self.pinned.contains(id) || self.held.as_ref() == Some(id) {
                self.vel.remove(id);
                continue;
            }
            let v = self.vel.entry(id.clone()).or_default();
            *v = (*v + f[i] - p[i] * GRAVITY) * DAMPING;
            if v.length() > MAX_SPEED {
                *v = *v / v.length() * MAX_SPEED;
            }
            speed += v.length();
            let v = *v;
            if let Some(pos) = self.pos.get_mut(id) {
                *pos += v;
            }
        }
        self.moving = speed / n as f32 > REST_SPEED;
    }

    /// Идёт ли ещё движение (нужна перерисовка).
    pub fn is_moving(&self) -> bool {
        self.moving
    }

    pub fn pos(&self, id: &NodeId) -> Pos2 {
        self.pos.get(id).copied().unwrap_or(Pos2::ZERO)
    }

    /// Перетаскивание: узел стоит под курсором, соседи подстраиваются. После
    /// [`Self::release`] он снова движется вместе с графом, если не закреплён.
    pub fn drag_to(&mut self, id: &NodeId, p: Pos2) {
        self.pos.insert(id.clone(), p);
        self.held = Some(id.clone());
        self.moving = true;
    }

    /// Узел отпустили.
    pub fn release(&mut self) {
        self.held = None;
        self.moving = true;
    }

    /// Закрепляет узел на его месте.
    pub fn pin(&mut self, id: &NodeId) {
        self.pinned.insert(id.clone());
    }

    /// Открепляет узел — он снова движется вместе с графом. Якорь не открепить.
    pub fn unpin(&mut self, id: &NodeId, anchor: &NodeId) {
        if id != anchor {
            self.pinned.remove(id);
            self.moving = true;
        }
    }

    /// Открепляет все узлы, кроме якоря.
    pub fn unpin_all(&mut self, anchor: &NodeId) {
        self.pinned.retain(|id| id == anchor);
        self.moving = true;
    }

    pub fn is_pinned(&self, id: &NodeId) -> bool {
        self.pinned.contains(id)
    }

    /// Рамка всех узлов (для «вписать в окно»).
    pub fn bounds(&self) -> Option<(Pos2, Pos2)> {
        let mut it = self.pos.values();
        let first = *it.next()?;
        Some(it.fold((first, first), |(lo, hi), p| (lo.min(*p), hi.max(*p))))
    }
}

/// Стабильное направление для узла: при каждом запуске он появляется на том
/// же месте, а не прыгает.
fn angle_of(id: &NodeId) -> f32 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    id.as_str().hash(&mut h);
    (h.finish() % 3600) as f32 / 3600.0 * std::f32::consts::TAU
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(i: u32) -> NodeId {
        NodeId(format!("{i:064x}"))
    }

    fn settle(l: &mut Layout, nodes: &[NodeId], edges: &[(usize, usize, f32)]) {
        for _ in 0..2000 {
            l.step(nodes, edges);
        }
    }

    #[test]
    fn linked_nodes_end_up_closer_than_unlinked() {
        // 0 — якорь; цепочка 0–1–2 и отдельный узел 3.
        let nodes: Vec<NodeId> = (0..4).map(n).collect();
        let edges = [(0, 1, 1.0), (1, 2, 1.0)];
        let mut l = Layout::default();
        l.sync(&nodes, &edges, &nodes[0]);
        settle(&mut l, &nodes, &edges);
        let d = |a: usize, b: usize| (l.pos(&nodes[a]) - l.pos(&nodes[b])).length();
        assert!(d(1, 2) < d(2, 3), "связанные ближе: {} vs {}", d(1, 2), d(2, 3));
        assert_eq!(l.pos(&nodes[0]), Pos2::ZERO, "якорь на месте");
        assert!(!l.is_moving(), "раскладка устоялась");
    }

    #[test]
    fn coincident_nodes_do_not_explode() {
        let nodes: Vec<NodeId> = (0..3).map(n).collect();
        let mut l = Layout::default();
        l.sync(&nodes, &[], &nodes[0]);
        l.drag_to(&nodes[1], Pos2::new(5.0, 5.0));
        l.drag_to(&nodes[2], Pos2::new(5.0, 5.0));
        l.release();
        settle(&mut l, &nodes, &[]);
        for id in &nodes {
            let p = l.pos(id);
            assert!(p.x.is_finite() && p.y.is_finite(), "без NaN");
        }
        assert!((l.pos(&nodes[1]) - l.pos(&nodes[2])).length() > MIN_DIST);
    }

    #[test]
    fn dragged_node_is_released_but_pinned_node_stays() {
        let nodes: Vec<NodeId> = (0..3).map(n).collect();
        let mut l = Layout::default();
        l.sync(&nodes, &[], &nodes[0]);

        // Перетащили и отпустили — узел не закреплён, гравитация тянет обратно.
        l.drag_to(&nodes[1], Pos2::new(600.0, 0.0));
        for _ in 0..5 {
            l.step(&nodes, &[]);
        }
        assert_eq!(l.pos(&nodes[1]), Pos2::new(600.0, 0.0), "пока держат — на месте");
        l.release();
        settle(&mut l, &nodes, &[]);
        assert!(l.pos(&nodes[1]).x < 500.0, "отпущенный узел вернулся в граф");
        assert!(!l.is_pinned(&nodes[1]));

        // Закрепили через меню — стоит, пока не открепят.
        l.drag_to(&nodes[1], Pos2::new(600.0, 0.0));
        l.release();
        l.pin(&nodes[1]);
        settle(&mut l, &nodes, &[]);
        assert_eq!(l.pos(&nodes[1]), Pos2::new(600.0, 0.0));
        l.unpin(&nodes[1], &nodes[0]);
        settle(&mut l, &nodes, &[]);
        assert!(l.pos(&nodes[1]).x < 500.0);

        // Якорь не открепляется ни по одному, ни «все».
        l.unpin(&nodes[0], &nodes[0]);
        l.unpin_all(&nodes[0]);
        assert!(l.is_pinned(&nodes[0]));
    }

    #[test]
    fn removed_nodes_are_forgotten() {
        let nodes: Vec<NodeId> = (0..3).map(n).collect();
        let mut l = Layout::default();
        l.sync(&nodes, &[], &nodes[0]);
        l.drag_to(&nodes[2], Pos2::new(300.0, 0.0));
        l.pin(&nodes[2]);
        l.sync(&nodes[..2], &[], &nodes[0]);
        assert!(!l.is_pinned(&nodes[2]));
        assert!(l.bounds().is_some_and(|(_, hi)| hi.x < 300.0));
    }
}
