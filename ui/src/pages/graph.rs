use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use eframe::egui;
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use crate::widgets::peer_popup::{status_colors, show_peer_profile};

pub struct Graph {
    my_name:  String,
    my_id:    NodeId,
    peers:    Vec<PeerInfo>,
    profiles: HashMap<NodeId, PeerProfile>,
    selected: Option<NodeId>,
    /// Сигнал в VoidApp: открыть личный чат с этим пиром
    pub pending_dm: Option<NodeId>,
    /// Снимок репутации узлов из backend (NodeId → score).
    pub reputation: Option<Arc<Mutex<HashMap<NodeId, f64>>>>,
    /// Сигнал в VoidApp: пожаловаться на узел (target, причина).
    pub pending_report: Option<(NodeId, void_reputation::ReportReason)>,
}

impl Graph {
    pub fn new(my_name: String, my_id: NodeId) -> Self {
        Self { my_name, my_id, peers: Vec::new(), profiles: HashMap::new(), selected: None, pending_dm: None, reputation: None, pending_report: None }
    }

    /// Текущая репутация узла из снимка backend (если есть).
    fn peer_score(&self, id: &NodeId) -> Option<f64> {
        self.reputation.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).copied()))
    }

    pub fn update_peers(&mut self, peers: Vec<PeerInfo>, profiles: HashMap<NodeId, PeerProfile>) {
        if let Some(sel) = &self.selected {
            if !peers.iter().any(|p| &p.id == sel) {
                self.selected = None;
            }
        }
        self.peers    = peers;
        self.profiles = profiles;
    }

    pub fn update_my_name(&mut self, name: &str) {
        self.my_name = name.to_string();
    }
}

impl Graph {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("  Граф сети");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        let mut close_popup = false;
        let mut start_dm_id: Option<NodeId> = None;
        let mut report_reason: Option<void_reputation::ReportReason> = None;
        if let Some(sel_id) = self.selected.clone() {
            let peer    = self.peers.iter().find(|p| p.id == sel_id).cloned();
            let profile = self.profiles.get(&sel_id).cloned();

            if let Some(peer) = peer {
                egui::Window::new("Профиль узла")
                    .id(egui::Id::new("graph_peer_profile_popup"))
                    .collapsible(false)
                    .resizable(false)
                    .default_width(320.0)
                    .show(ui.ctx(), |ui| {
                        let rep = self.peer_score(&sel_id);
                        let action = show_peer_profile(ui, Some(&peer), profile.as_ref(), rep);
                        ui.add_space(6.0);
                        if action.start_dm {
                            start_dm_id = Some(sel_id.clone());
                            close_popup = true;
                        }
                        if let Some(reason) = action.report {
                            report_reason = Some(reason);
                            close_popup = true;
                        }
                        if ui.button("Закрыть").clicked() {
                            close_popup = true;
                        }
                    });
            } else {
                close_popup = true;
            }
            if let Some(reason) = report_reason {
                self.pending_report = Some((sel_id.clone(), reason));
            }
        }
        if close_popup { self.selected = None; }
        if let Some(id) = start_dm_id {
            self.pending_dm = Some(id);
        }

        let avail  = ui.available_rect_before_wrap();
        let center = avail.center();
        let (rect, _) = ui.allocate_exact_size(avail.size(), egui::Sense::hover());
        let painter = ui.painter_at(rect);

        let n = self.peers.len();
        let orbit_r = (avail.width().min(avail.height()) * 0.35).clamp(80.0, 260.0);

        if n == 0 {
            painter.text(
                center + egui::Vec2::new(0.0, 30.0),
                egui::Align2::CENTER_CENTER,
                "Ищем узлы в сети...",
                egui::FontId::proportional(14.0),
                egui::Color32::from_gray(120),
            );
        }

        for (i, peer) in self.peers.iter().enumerate() {
            let angle = -std::f32::consts::FRAC_PI_2
                + 2.0 * std::f32::consts::PI * i as f32 / n.max(1) as f32;
            let pos = center + egui::Vec2::new(angle.cos() * orbit_r, angle.sin() * orbit_r);

            painter.line_segment(
                [center, pos],
                egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(100, 120, 180, 120)),
            );

            let profile = self.profiles.get(&peer.id);
            let (fill, stroke_col) = status_colors(profile.map(|p| p.status.as_str()));

            let is_selected = self.selected.as_ref() == Some(&peer.id);
            let stroke_w = if is_selected { 2.5 } else { 1.0 };

            let circle_rect = egui::Rect::from_center_size(pos, egui::Vec2::splat(36.0));
            let resp = ui.allocate_rect(circle_rect, egui::Sense::click());

            painter.circle_filled(pos, 18.0, fill);
            painter.circle_stroke(pos, 18.0, egui::Stroke::new(stroke_w, stroke_col));

            if resp.hovered() {
                painter.circle_stroke(pos, 20.0, egui::Stroke::new(1.0,
                    egui::Color32::from_rgba_unmultiplied(255, 255, 255, 60)));
            }
            if resp.clicked() {
                self.selected = if is_selected { None } else { Some(peer.id.clone()) };
            }

            let display_name = profile.map(|p| p.name.as_str()).unwrap_or(peer.name.as_str());
            let initial = display_name.chars().next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or("?".into());
            painter.text(pos, egui::Align2::CENTER_CENTER, &initial,
                egui::FontId::proportional(15.0), egui::Color32::WHITE);

            painter.text(pos + egui::Vec2::new(0.0, 26.0), egui::Align2::CENTER_CENTER,
                display_name, egui::FontId::proportional(11.0), egui::Color32::from_gray(200));

            painter.text(pos + egui::Vec2::new(0.0, 38.0), egui::Align2::CENTER_CENTER,
                &peer.ip.to_string(), egui::FontId::proportional(9.0), egui::Color32::from_gray(130));

            if resp.hovered() {
                let status = profile.map(|p| p.status.as_str()).unwrap_or("?");
                resp.on_hover_text(format!("{} · {} · {}", display_name, peer.ip, status));
            }
        }

        painter.circle_filled(center, 24.0, egui::Color32::from_rgb(40, 90, 200));
        painter.circle_stroke(center, 24.0, egui::Stroke::new(2.0, egui::Color32::from_rgb(80, 140, 255)));
        painter.text(center, egui::Align2::CENTER_CENTER,
            self.my_name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or("?".into()),
            egui::FontId::proportional(18.0), egui::Color32::WHITE);
        painter.text(center + egui::Vec2::new(0.0, 32.0), egui::Align2::CENTER_CENTER,
            &format!("{} (я)", self.my_name),
            egui::FontId::proportional(11.0), egui::Color32::from_gray(200));
    }
}
