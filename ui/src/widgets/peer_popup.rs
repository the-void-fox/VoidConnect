use eframe::egui;
use void_core::peer::{PeerInfo, PeerProfile};
use void_reputation::ReportReason;

/// Действие, выбранное пользователем в попапе профиля узла.
#[derive(Default)]
pub struct PeerPopupAction {
    /// Нажата «Начать беседу».
    pub start_dm: bool,
    /// Выбрана причина жалобы на узел.
    pub report: Option<ReportReason>,
}

pub fn status_colors(status: Option<&str>) -> (egui::Color32, egui::Color32) {
    match status {
        Some("online")  => (egui::Color32::from_rgb(35, 130, 70),  egui::Color32::from_rgb(80, 200, 80)),
        Some("away")    => (egui::Color32::from_rgb(130, 110, 20), egui::Color32::from_rgb(220, 180, 40)),
        Some("busy")    => (egui::Color32::from_rgb(130, 40, 40),  egui::Color32::from_rgb(220, 80, 60)),
        Some("offline") => (egui::Color32::from_rgb(60, 60, 60),   egui::Color32::from_gray(120)),
        _               => (egui::Color32::from_rgb(35, 130, 70),  egui::Color32::from_rgb(80, 200, 80)),
    }
}

/// Показывает профиль пира. Возвращает выбранное действие (начать беседу /
/// пожаловаться).
pub fn show_peer_profile(
    ui:         &mut egui::Ui,
    peer:       Option<&PeerInfo>,
    profile:    Option<&PeerProfile>,
    reputation: Option<f64>,
) -> PeerPopupAction {
    let name        = profile.map(|p| p.name.as_str())
        .or_else(|| peer.map(|p| p.name.as_str()))
        .unwrap_or("?");
    let description = profile.map(|p| p.description.as_str()).unwrap_or("");
    let status      = profile.map(|p| p.status.as_str()).unwrap_or("online");
    let has_dm_key  = profile.and_then(|p| p.enc_pubkey.as_ref()).is_some();
    let is_bootstrap = profile.map(|p| p.is_bootstrap).unwrap_or(false);

    // Avatar + name/status row
    ui.horizontal(|ui| {
        let initial = name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or("?".into());
        let size = 56.0;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        let (fill, _) = status_colors(Some(status));
        ui.painter().circle_filled(rect.center(), size / 2.0, fill);
        ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, &initial,
            egui::FontId::proportional(26.0), egui::Color32::WHITE);

        ui.add_space(12.0);
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(name).strong().size(16.0));
            ui.add_space(2.0);
            let status_label = match status {
                "online"  => "Online",
                "away"    => "Away",
                "busy"    => "Busy",
                "offline" => "Offline",
                _         => "Online",
            };
            let (_, stroke) = status_colors(Some(status));
            ui.label(egui::RichText::new(format!("● {}", status_label)).color(stroke).small());

            if has_dm_key {
                ui.label(
                    egui::RichText::new("🔒 E2E шифрование доступно")
                        .small()
                        .color(egui::Color32::from_rgb(80, 200, 80)),
                );
            }
            if is_bootstrap {
                ui.label(
                    egui::RichText::new("󰒋  Bootstrap-узел")
                        .small()
                        .strong()
                        .color(egui::Color32::from_rgb(150, 130, 230)),
                );
            }
        });
    });

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(6.0);

    // Network info
    if let Some(peer) = peer {
        egui::Grid::new("peer_info_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.label(egui::RichText::new("IP:").strong());
            ui.label(egui::RichText::new(peer.ip.to_string()).monospace());
            ui.end_row();

            ui.label(egui::RichText::new("Порт:").strong());
            ui.label(egui::RichText::new(peer.port.to_string()).monospace());
            ui.end_row();

            let id_str = peer.id.as_str();
            let id_short = if id_str.len() >= 12 {
                format!("{}...{}", &id_str[..8], &id_str[id_str.len()-4..])
            } else {
                id_str.to_string()
            };
            ui.label(egui::RichText::new("ID:").strong());
            ui.label(egui::RichText::new(id_short).monospace().color(ui.visuals().weak_text_color()));
            ui.end_row();
        });
    } else {
        ui.label(
            egui::RichText::new("Узел не в сети")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
    }

    // Репутация узла (по локальным данным; сетевая синхронизация — отд. фаза)
    if let Some(score) = reputation {
        use void_reputation::ReputationLevel;
        let (label, color) = match ReputationLevel::from_score(score) {
            ReputationLevel::High     => ("Высокая",       egui::Color32::from_rgb(80, 180, 100)),
            ReputationLevel::Normal   => ("Обычная",       egui::Color32::from_rgb(120, 170, 220)),
            ReputationLevel::Low      => ("Низкая",        egui::Color32::from_rgb(200, 160, 70)),
            ReputationLevel::Negative => ("Отрицательная", egui::Color32::from_rgb(220, 80, 60)),
        };
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Репутация:").strong());
            ui.label(egui::RichText::new(format!("{label}  ({score:.1})")).color(color));
        });
    }

    if !description.is_empty() {
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(egui::RichText::new("О себе:").strong());
        ui.add_space(2.0);
        ui.label(description);
    }

    // Кнопка "Начать беседу"
    ui.add_space(10.0);
    ui.separator();
    ui.add_space(6.0);

    let btn = egui::Button::new("💬  Начать беседу")
        .min_size(egui::vec2(ui.available_width(), 32.0));
    let resp = ui.add_enabled(peer.is_some() || profile.is_some(), btn);
    let clicked = resp.clicked();
    if resp.hovered() && !has_dm_key {
        resp.on_hover_text("Ключ шифрования ещё не получен. Подожди немного.");
    }

    // Жалоба на узел
    ui.add_space(4.0);
    let mut report = None;
    ui.menu_button("  󰀦  Пожаловаться", |ui| {
        if ui.button(" 󱃈  Спам").clicked() {
            report = Some(ReportReason::Spam);
            ui.close_menu();
        }
        if ui.button(" 󰶍  Вредоносный контент").clicked() {
            report = Some(ReportReason::MaliciousContent);
            ui.close_menu();
        }
        if ui.button(" 󰇮  Битые файлы").clicked() {
            report = Some(ReportReason::BadChunks);
            ui.close_menu();
        }
    });

    PeerPopupAction { start_dm: clicked, report }
}
