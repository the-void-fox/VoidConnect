//! Граф сети: узлы, их соединения и поручительства; цвет обводки — доверие к
//! узлу в глазах моего узла.
//!
//! Соединения берутся из карты соединений (списки соседей, которые узлы
//! рассылают о себе, см. `void_chat::topology`): сплошная линия — связь
//! подтверждена обоими концами, пунктир — заявлена одним. Поручительства —
//! стрелки от поручителя: личное сплошное, приветствие пунктиром.
//!
//! Как в Obsidian: раскладка «физикой» ([`super::graph_layout`]), колесо —
//! масштаб, перетаскивание фона — сдвиг, узел можно перетащить (закрепится,
//! двойной щелчок открепляет), наведение подсвечивает соседей, щелчок
//! открывает профиль.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use eframe::egui::{self, Color32, Pos2, Stroke, Vec2};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use void_trust::{TrustLevel, VouchKind};

use super::graph_layout::Layout;
use crate::widgets::peer_popup::{show_peer_profile, status_colors};

/// Больше узлов не рисуем: сначала свой, свои соседи и узлы в сети.
const MAX_NODES: usize = 300;
/// Радиус узла и своего узла при масштабе 1.
const NODE_R: f32 = 16.0;
const ME_R: f32 = 22.0;
/// С этого масштаба подписаны все узлы (ниже — только подсвеченные).
const LABELS_ZOOM: f32 = 0.75;

const LINK_COLOR: Color32 = Color32::from_rgb(150, 160, 190);
const VOUCH_COLOR: Color32 = Color32::from_rgb(80, 190, 110);
const GREET_COLOR: Color32 = Color32::from_rgb(170, 160, 120);
const ME_COLOR: Color32 = Color32::from_rgb(80, 140, 255);
const MATCH_COLOR: Color32 = Color32::from_rgb(240, 200, 60);

/// Связь на графе.
#[derive(Clone, Copy, PartialEq)]
enum EdgeKind {
    /// Соединение в сети; `confirmed` — его называют оба конца.
    Link { confirmed: bool },
    /// Поручительство (стрелка от поручителя); `greeter` — приветствие.
    Vouch { greeter: bool },
}

struct GNode {
    id: NodeId,
    name: String,
    online: bool,
    level: Option<TrustLevel>,
    reported: bool,
}

struct GEdge {
    a: usize,
    b: usize,
    kind: EdgeKind,
}

/// Что показывать.
struct Filters {
    links: bool,
    unconfirmed: bool,
    vouches: bool,
    online_only: bool,
}

/// Что сейчас перетаскивают.
enum Drag {
    Node(NodeId),
    Pan,
}

pub struct Graph {
    my_name:   String,
    my_id:     NodeId,
    my_avatar: Option<String>,
    peers:     Vec<PeerInfo>,
    profiles:  HashMap<NodeId, PeerProfile>,
    /// Кэш загруженных текстур аватаров по узлам: NodeId → (хэш b64, текстура).
    /// Инвалидируется при смене аватара (другой хэш) и чистится для пропавших.
    avatar_tex: HashMap<NodeId, (u64, egui::TextureHandle)>,
    selected:  Option<NodeId>,
    /// Сигнал в VoidApp: открыть личный чат с этим пиром
    pub pending_dm: Option<NodeId>,
    /// Снимок репутации узлов из backend (NodeId → score).
    pub reputation: Option<Arc<Mutex<HashMap<NodeId, f64>>>>,
    /// Снимок жалоб на узлы из backend.
    pub reports: Option<Arc<Mutex<HashMap<NodeId, Vec<void_db::peers::ReportRow>>>>>,
    /// Снимок блок-листа (забаненные голосованием).
    pub blocklist: Option<Arc<Mutex<HashMap<NodeId, i64>>>>,
    /// Сигнал в VoidApp: пожаловаться на узел (target, причина).
    pub pending_report: Option<(NodeId, void_reputation::ReportReason)>,
    /// Сеть доверия: уровни узлов, поручительства и команды «поручиться/отозвать».
    pub trust: Option<crate::trust_ui::TrustUi>,
    /// Карта соединений сети из backend: узел → его соседи.
    pub topology: Option<Arc<Mutex<crate::backend::TopologyMap>>>,
    layout:  Layout,
    /// Камера: сдвиг центра графа от центра области и масштаб.
    offset:  Vec2,
    zoom:    f32,
    filters: Filters,
    search:  String,
    drag:    Option<Drag>,
}

impl Graph {
    pub fn new(my_name: String, my_id: NodeId) -> Self {
        Self {
            my_name, my_id, my_avatar: None,
            peers: Vec::new(), profiles: HashMap::new(), avatar_tex: HashMap::new(),
            selected: None, pending_dm: None, reputation: None,
            reports: None, blocklist: None, pending_report: None,
            trust: None, topology: None,
            layout: Layout::default(),
            offset: Vec2::ZERO,
            zoom: 1.0,
            filters: Filters { links: true, unconfirmed: false, vouches: true, online_only: false },
            search: String::new(),
            drag: None,
        }
    }

    /// Текущая репутация узла из снимка backend (если есть).
    fn peer_score(&self, id: &NodeId) -> Option<f64> {
        self.reputation.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).copied()))
    }

    /// Жалобы на узел из снимка backend.
    fn peer_reports(&self, id: &NodeId) -> Vec<void_db::peers::ReportRow> {
        self.reports.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).cloned()))
            .unwrap_or_default()
    }

    /// Забанен ли узел голосованием (бан не истёк).
    fn is_banned(&self, id: &NodeId) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.blocklist.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).copied()))
            .is_some_and(|until| until > now)
    }

    pub fn update_peers(&mut self, peers: Vec<PeerInfo>, profiles: HashMap<NodeId, PeerProfile>) {
        self.peers    = peers;
        self.profiles = profiles;
    }

    pub fn update_me(&mut self, name: &str, avatar: Option<&str>) {
        self.my_name = name.to_string();
        self.my_avatar = avatar.map(str::to_owned);
    }

    /// Обновляет кэш текстур аватаров для узлов на графе: декодирует новые и
    /// изменившиеся PNG, выгружает ненужные. Ключ «себя» — `my_id`.
    fn sync_avatar_textures(&mut self, ctx: &egui::Context, ids: &[NodeId]) {
        let mut wanted: HashMap<NodeId, u64> = HashMap::new();
        for id in ids {
            let b64 = if *id == self.my_id {
                self.my_avatar.clone()
            } else {
                self.profiles.get(id).and_then(|p| p.avatar_png.clone())
            };
            let Some(b64) = b64 else { continue };
            let h = crate::avatar::avatar_hash(&b64);
            wanted.insert(id.clone(), h);
            let fresh = self.avatar_tex.get(id).is_some_and(|(ph, _)| *ph == h);
            if !fresh {
                if let Some(img) = crate::avatar::color_image_from_b64(&b64) {
                    let tex = ctx.load_texture(
                        format!("graph_avatar_{}", id.as_str()),
                        img,
                        egui::TextureOptions::LINEAR,
                    );
                    self.avatar_tex.insert(id.clone(), (h, tex));
                }
            }
        }
        self.avatar_tex.retain(|id, _| wanted.contains_key(id));
    }

    fn display_name(&self, id: &NodeId) -> String {
        if *id == self.my_id {
            return format!("{} (я)", self.my_name);
        }
        self.profiles.get(id).map(|p| p.name.clone()).filter(|n| !n.is_empty())
            .or_else(|| self.peers.iter().find(|p| p.id == *id).map(|p| p.name.clone()))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("{}…", &id.as_str()[..8.min(id.as_str().len())]))
    }

    /// Собирает узлы и связи для отрисовки по снимкам backend и фильтрам.
    fn build(&self) -> (Vec<GNode>, Vec<GEdge>) {
        let topo: HashMap<NodeId, Vec<NodeId>> = self.topology.as_ref()
            .and_then(|t| t.lock().ok().map(|t| t.clone()))
            .unwrap_or_default();
        let online: HashSet<&NodeId> = self.peers.iter().map(|p| &p.id).chain(topo.keys()).collect();

        // Порядок важности: свой узел, свои соседи, узлы в сети, остальные из карты.
        let mut order: Vec<NodeId> = vec![self.my_id.clone()];
        order.extend(topo.get(&self.my_id).into_iter().flatten().cloned());
        order.extend(self.peers.iter().map(|p| p.id.clone()));
        for (id, ns) in &topo {
            order.push(id.clone());
            order.extend(ns.iter().cloned());
        }
        let vouches: Vec<(NodeId, NodeId, VouchKind)> = if self.filters.vouches {
            self.trust.as_ref()
                .and_then(|t| t.details.lock().ok().map(|d| d.vouches.clone()))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        {
            // Поручительства, касающиеся уже показанных узлов, приводят их соседей
            // по графу доверия (могут быть и не в сети).
            let base: HashSet<NodeId> = order.iter().cloned().collect();
            for (v, s, _) in &vouches {
                if base.contains(v) || base.contains(s) {
                    order.push(v.clone());
                    order.push(s.clone());
                }
            }
        }

        let mut index: HashMap<NodeId, usize> = HashMap::new();
        let mut ids: Vec<NodeId> = Vec::new();
        for id in order {
            if index.contains_key(&id) || ids.len() >= MAX_NODES {
                continue;
            }
            if self.filters.online_only && id != self.my_id && !online.contains(&id) {
                continue;
            }
            index.insert(id.clone(), ids.len());
            ids.push(id);
        }

        let trust = self.trust.as_ref().and_then(|t| t.map.lock().ok());
        let nodes: Vec<GNode> = ids.iter().map(|id| {
            let info = trust.as_ref().filter(|_| *id != self.my_id).map(|m| m.get(id));
            GNode {
                id: id.clone(),
                name: self.display_name(id),
                online: *id == self.my_id || online.contains(id),
                level: info.as_ref().map(|i| i.level),
                reported: info.as_ref().is_some_and(|i| i.reported),
            }
        }).collect();
        drop(trust);

        let mut edges = Vec::new();
        if self.filters.links {
            for e in void_chat::topology::edges(&topo, &self.my_id) {
                if !e.confirmed && !self.filters.unconfirmed {
                    continue;
                }
                if let (Some(&a), Some(&b)) = (index.get(&e.a), index.get(&e.b)) {
                    edges.push(GEdge { a, b, kind: EdgeKind::Link { confirmed: e.confirmed } });
                }
            }
        }
        for (v, s, kind) in &vouches {
            if let (Some(&a), Some(&b)) = (index.get(v), index.get(s)) {
                edges.push(GEdge { a, b, kind: EdgeKind::Vouch { greeter: *kind == VouchKind::Greeter } });
            }
        }
        (nodes, edges)
    }

    /// Вписывает граф в область.
    fn fit(&mut self, area: egui::Rect) {
        let Some((lo, hi)) = self.layout.bounds() else { return };
        let size = (hi - lo).max(Vec2::splat(1.0));
        let zoom = ((area.width() - 80.0) / size.x).min((area.height() - 80.0) / size.y);
        self.zoom = zoom.clamp(0.2, 2.0);
        let mid = lo + size / 2.0;
        self.offset = -mid.to_vec2() * self.zoom;
    }

    /// Профиль выбранного узла (окно поверх графа).
    fn show_profile_popup(&mut self, ctx: &egui::Context) {
        let Some(sel_id) = self.selected.clone() else { return };
        let peer    = self.peers.iter().find(|p| p.id == sel_id).cloned();
        let profile = self.profiles.get(&sel_id).cloned();
        if peer.is_none() && profile.is_none() {
            // Узел знаем только по графу (ни профиля, ни адреса) — показать нечего.
            self.selected = None;
            return;
        }
        let mut close_popup = false;
        let mut start_dm = false;
        let mut report_reason = None;
        let mut vouch_action = None;
        let mut block_action = None;
        egui::Window::new("Профиль узла")
            .id(egui::Id::new("graph_peer_profile_popup"))
            .collapsible(false)
            .resizable(false)
            .vscroll(true) // профиль выше окна приложения — иначе кнопки внизу недоступны
            .default_width(320.0)
            .show(ctx, |ui| {
                let rep = self.peer_score(&sel_id);
                let reports = self.peer_reports(&sel_id);
                let banned = self.is_banned(&sel_id);
                let trust = self.trust.as_ref().map(|t| t.view(&sel_id, &self.profiles));
                let action = show_peer_profile(
                    ui, peer.as_ref(), profile.as_ref(), rep, &reports, banned,
                    self.my_id.as_str(), trust.as_ref(),
                );
                ui.add_space(6.0);
                if action.start_dm {
                    start_dm = true;
                    close_popup = true;
                }
                if let Some(reason) = action.report {
                    report_reason = Some(reason);
                    close_popup = true;
                }
                vouch_action = action.vouch; // не закрываем попап — видно смену бейджа
                block_action = action.block;
                if ui.button("Закрыть").clicked() {
                    close_popup = true;
                }
            });
        if let Some(reason) = report_reason {
            self.pending_report = Some((sel_id.clone(), reason));
        }
        if let (Some(action), Some(trust)) = (vouch_action, &self.trust) {
            use crate::widgets::peer_popup::VouchAction;
            trust.send(match action {
                VouchAction::Vouch  => crate::backend::TrustCmd::Vouch(sel_id.clone()),
                VouchAction::Revoke => crate::backend::TrustCmd::Revoke(sel_id.clone()),
                VouchAction::Greet  => crate::backend::TrustCmd::Greet(sel_id.clone()),
            });
        }
        if let (Some(block), Some(trust)) = (block_action, &self.trust) {
            trust.send(if block {
                crate::backend::TrustCmd::Block(sel_id.clone())
            } else {
                crate::backend::TrustCmd::Unblock(sel_id.clone())
            });
        }
        if start_dm {
            self.pending_dm = Some(sel_id);
        }
        if close_popup {
            self.selected = None;
        }
    }
}

/// Цвет обводки узла — доверие к нему в моих глазах.
fn trust_color(node: &GNode) -> Color32 {
    if node.reported {
        return Color32::from_rgb(220, 140, 60);
    }
    match node.level {
        Some(TrustLevel::Verified) => Color32::from_rgb(80, 190, 110),
        Some(TrustLevel::Trusted)  => Color32::from_rgb(120, 170, 220),
        Some(TrustLevel::Settled)  => Color32::from_rgb(170, 160, 120),
        Some(TrustLevel::Blocked)  => Color32::from_rgb(220, 80, 60),
        _                          => Color32::from_gray(120),
    }
}

fn trust_label(node: &GNode) -> &'static str {
    if node.reported {
        return "под жалобами";
    }
    match node.level {
        Some(TrustLevel::Verified) => "проверен лично",
        Some(TrustLevel::Trusted)  => "через знакомых",
        Some(TrustLevel::Settled)  => "освоившийся",
        Some(TrustLevel::Blocked)  => "заблокирован",
        _                          => "незнакомец",
    }
}

fn faded(c: Color32, k: f32) -> Color32 {
    c.gamma_multiply(k)
}

impl Graph {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("\u{F1049} Граф сети");
        ui.add_space(6.0);

        // ── Панель: поиск, фильтры, «вписать» ────────────────────────────────
        let mut fit = false;
        let mut center_on_match = false;
        ui.horizontal_wrapped(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("\u{F0349}  Найти узел…")
                    .desired_width(160.0),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                center_on_match = true;
            }
            ui.checkbox(&mut self.filters.links, "Соединения");
            ui.checkbox(&mut self.filters.unconfirmed, "Неподтверждённые")
                .on_hover_text("Связи, которые заявил только один из узлов (могут быть ложью)");
            ui.checkbox(&mut self.filters.vouches, "Поручительства");
            ui.checkbox(&mut self.filters.online_only, "Только в сети");
            if ui.button("\u{F0293}  Вписать").clicked() {
                fit = true;
            }
        });
        ui.label(
            egui::RichText::new(
                "Колесо — масштаб, перетаскивание фона — сдвиг. Узел можно перетащить — он \
                 закрепится; двойной щелчок открепляет. Щелчок — профиль.",
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );
        ui.separator();

        self.show_profile_popup(ui.ctx());

        let (nodes, edges) = self.build();
        let ids: Vec<NodeId> = nodes.iter().map(|n| n.id.clone()).collect();
        let springs: Vec<(usize, usize, f32)> = edges.iter()
            .map(|e| (e.a, e.b, if matches!(e.kind, EdgeKind::Link { .. }) { 1.0 } else { 0.5 }))
            .collect();
        self.layout.sync(&ids, &springs, &self.my_id);
        self.layout.step(&ids, &springs);

        let ctx = ui.ctx().clone();
        self.sync_avatar_textures(&ctx, &ids);

        let rect = ui.available_rect_before_wrap();
        let resp = ui.allocate_rect(rect, egui::Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        if fit {
            self.fit(rect);
        }

        let query = self.search.trim().to_lowercase();
        let matches: HashSet<usize> = if query.is_empty() {
            HashSet::new()
        } else {
            nodes.iter().enumerate()
                .filter(|(_, n)| n.name.to_lowercase().contains(&query))
                .map(|(i, _)| i)
                .collect()
        };
        if center_on_match {
            if let Some(i) = matches.iter().min() {
                self.offset = -self.layout.pos(&nodes[*i].id).to_vec2() * self.zoom;
            }
        }

        // ── Ввод: масштаб, сдвиг, перетаскивание узлов, выбор ───────────────
        let pointer = resp.hover_pos().or_else(|| resp.interact_pointer_pos());
        if let Some(p) = resp.hover_pos() {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll != 0.0 {
                // Точка под курсором остаётся на месте.
                let world = (p - rect.center() - self.offset) / self.zoom;
                self.zoom = (self.zoom * (scroll * 0.002).exp()).clamp(0.2, 3.0);
                self.offset = p - rect.center() - world * self.zoom;
            }
        }
        let origin = rect.center() + self.offset;
        let zoom = self.zoom;
        let to_screen = |p: Pos2| origin + p.to_vec2() * zoom;
        let radius = |i: usize| {
            if nodes[i].id == self.my_id { (ME_R * zoom).clamp(8.0, 34.0) } else { (NODE_R * zoom).clamp(6.0, 28.0) }
        };
        let screen: Vec<Pos2> = ids.iter().map(|id| to_screen(self.layout.pos(id))).collect();
        let hovered = pointer.and_then(|p| {
            (0..nodes.len())
                .filter(|&i| (screen[i] - p).length() <= radius(i) + 3.0)
                .min_by(|&a, &b| (screen[a] - p).length().total_cmp(&(screen[b] - p).length()))
        });

        if resp.drag_started() {
            self.drag = Some(match hovered {
                Some(i) => Drag::Node(nodes[i].id.clone()),
                None => Drag::Pan,
            });
        }
        if resp.dragged() {
            match &self.drag {
                Some(Drag::Node(id)) => {
                    if let Some(p) = pointer {
                        self.layout.drag_to(id, Pos2::ZERO + (p - origin) / zoom);
                    }
                }
                Some(Drag::Pan) => self.offset += resp.drag_delta(),
                None => {}
            }
        }
        if resp.drag_stopped() {
            self.drag = None;
        }
        if resp.double_clicked() {
            if let Some(i) = hovered {
                self.layout.unpin(&nodes[i].id);
            }
        } else if resp.clicked() {
            self.selected = hovered.map(|i| nodes[i].id.clone()).filter(|id| *id != self.my_id);
        }

        // Подсветка: наведённый узел и его соседи; остальные тускнеют.
        let lit: Option<HashSet<usize>> = hovered.map(|h| {
            let mut s: HashSet<usize> = edges.iter()
                .filter(|e| e.a == h || e.b == h)
                .flat_map(|e| [e.a, e.b])
                .collect();
            s.insert(h);
            s
        });
        let is_lit = |i: usize| lit.as_ref().is_none_or(|s| s.contains(&i));

        // ── Связи ───────────────────────────────────────────────────────────
        for e in &edges {
            let k = if hovered.is_none() || hovered == Some(e.a) || hovered == Some(e.b) { 1.0 } else { 0.15 };
            let (pa, pb) = (screen[e.a], screen[e.b]);
            let dir = (pb - pa).normalized();
            match e.kind {
                EdgeKind::Link { confirmed: true } => {
                    let mine = nodes[e.a].id == self.my_id || nodes[e.b].id == self.my_id;
                    let w: f32 = if mine { 2.0 } else { 1.5 };
                    painter.line_segment([pa, pb], Stroke::new(w, faded(LINK_COLOR, 0.7 * k)));
                }
                EdgeKind::Link { confirmed: false } => {
                    painter.extend(egui::Shape::dashed_line(
                        &[pa, pb], Stroke::new(1.0_f32, faded(LINK_COLOR, 0.35 * k)), 4.0, 4.0,
                    ));
                }
                EdgeKind::Vouch { greeter } => {
                    // Сдвиг вбок: стрелка не закрывает соединение той же пары, а
                    // встречные поручительства (A→B и B→A) идут рядом.
                    let side = dir.rot90() * 4.0;
                    let start = pa + dir * radius(e.a) + side;
                    let end = pb - dir * (radius(e.b) + 2.0) + side;
                    let color = faded(if greeter { GREET_COLOR } else { VOUCH_COLOR }, 0.8 * k);
                    let stroke = Stroke::new(1.3_f32, color);
                    if greeter {
                        painter.extend(egui::Shape::dashed_line(&[start, end - dir * 8.0], stroke, 4.0, 3.0));
                        painter.arrow(end - dir * 8.0, dir * 8.0, stroke);
                    } else {
                        painter.arrow(start, end - start, stroke);
                    }
                }
            }
        }

        // ── Узлы ────────────────────────────────────────────────────────────
        for (i, node) in nodes.iter().enumerate() {
            let pos = screen[i];
            let r = radius(i);
            let k = if is_lit(i) { 1.0 } else { 0.25 };
            let is_me = node.id == self.my_id;
            let fill = if !node.online {
                Color32::from_gray(70)
            } else if is_me {
                Color32::from_rgb(40, 90, 200)
            } else {
                status_colors(self.profiles.get(&node.id).map(|p| p.status.as_str())).0
            };
            if let Some((_, tex)) = self.avatar_tex.get(&node.id) {
                crate::avatar::paint_circle_avatar(&painter, tex.id(), pos, r);
                if k < 1.0 || !node.online {
                    painter.circle_filled(pos, r, Color32::from_black_alpha(if node.online { 150 } else { 120 }));
                }
            } else {
                painter.circle_filled(pos, r, faded(fill, k));
                let initial = node.name.chars().next()
                    .map(|c| c.to_uppercase().to_string())
                    .unwrap_or_else(|| "?".into());
                painter.text(pos, egui::Align2::CENTER_CENTER, initial,
                    egui::FontId::proportional(r * 0.9), faded(Color32::WHITE, k));
            }
            let ring = if is_me { ME_COLOR } else { trust_color(node) };
            painter.circle_stroke(pos, r, Stroke::new(2.5_f32, faded(ring, k)));
            if matches.contains(&i) {
                painter.circle_stroke(pos, r + 4.0, Stroke::new(2.0_f32, MATCH_COLOR));
            }
            if self.layout.is_pinned(&node.id) && !is_me {
                painter.circle_filled(pos + Vec2::new(r * 0.75, -r * 0.75), 3.0, faded(MATCH_COLOR, k));
            }
            if self.selected.as_ref() == Some(&node.id) {
                painter.circle_stroke(pos, r + 3.0, Stroke::new(1.5_f32, Color32::WHITE));
            }
            let labeled = zoom >= LABELS_ZOOM || is_me || matches.contains(&i)
                || lit.as_ref().is_some_and(|s| s.contains(&i));
            if labeled {
                painter.text(pos + Vec2::new(0.0, r + 8.0), egui::Align2::CENTER_CENTER,
                    &node.name, egui::FontId::proportional(11.0), faded(Color32::from_gray(210), k));
            }
        }

        if nodes.len() <= 1 {
            painter.text(rect.center() + Vec2::new(0.0, 60.0), egui::Align2::CENTER_CENTER,
                "Ищем узлы в сети…", egui::FontId::proportional(14.0), Color32::from_gray(120));
        }

        // Подсказка у наведённого узла.
        if let Some(h) = hovered {
            let node = &nodes[h];
            let state = if node.id == self.my_id {
                "это вы".to_string()
            } else {
                format!("{} · {}", trust_label(node), if node.online { "в сети" } else { "не в сети" })
            };
            let pinned = if self.layout.is_pinned(&node.id) && node.id != self.my_id { " · закреплён" } else { "" };
            resp.clone().on_hover_text(format!("{}\n{state}{pinned}", node.name));
        }

        self.paint_legend(&painter, rect, nodes.len(), edges.len());

        if self.layout.is_moving() || self.drag.is_some() {
            ui.ctx().request_repaint();
        }
    }

    /// Легенда в углу: цвета доверия, виды связей, счётчики.
    fn paint_legend(&self, painter: &egui::Painter, rect: egui::Rect, nodes: usize, edges: usize) {
        let font = egui::FontId::proportional(11.0);
        let text = Color32::from_gray(170);
        let mut y = rect.bottom() - 12.0;
        let x = rect.left() + 12.0;
        /// Образец в легенде: кружок узла, линия соединения, стрелка (пунктиром — приветствие).
        enum Sample { Ring, Line, Arrow, DashedArrow }
        let rows: [(Color32, &str, Sample); 8] = [
            (Color32::from_rgb(80, 190, 110), "проверен лично", Sample::Ring),
            (Color32::from_rgb(120, 170, 220), "через знакомых", Sample::Ring),
            (Color32::from_rgb(170, 160, 120), "освоившийся", Sample::Ring),
            (Color32::from_gray(120), "незнакомец", Sample::Ring),
            (Color32::from_rgb(220, 140, 60), "под жалобами", Sample::Ring),
            (LINK_COLOR, "соединение", Sample::Line),
            (VOUCH_COLOR, "поручительство", Sample::Arrow),
            (GREET_COLOR, "приветствие", Sample::DashedArrow),
        ];
        for (color, label, sample) in rows.iter().rev() {
            let (a, b) = (Pos2::new(x - 4.0, y), Pos2::new(x + 9.0, y));
            let stroke = Stroke::new(2.0_f32, *color);
            match sample {
                Sample::Ring => {
                    painter.circle_stroke(Pos2::new(x + 2.0, y), 5.0, stroke);
                }
                Sample::Line => {
                    painter.line_segment([a, b], stroke);
                }
                Sample::Arrow => painter.arrow(a, b - a, stroke),
                Sample::DashedArrow => {
                    painter.extend(egui::Shape::dashed_line(&[a, b - Vec2::new(5.0, 0.0)], stroke, 3.0, 2.0));
                    painter.arrow(b - Vec2::new(5.0, 0.0), Vec2::new(5.0, 0.0), stroke);
                }
            }
            painter.text(Pos2::new(x + 16.0, y), egui::Align2::LEFT_CENTER, *label, font.clone(), text);
            y -= 16.0;
        }
        painter.text(Pos2::new(x - 4.0, y), egui::Align2::LEFT_CENTER,
            format!("узлов: {nodes} · связей: {edges}"), font, text);
    }
}
