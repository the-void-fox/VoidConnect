use eframe::egui;

use crate::theme;

pub fn show_status_bar(
    ui: &mut egui::Ui,
    peer_count: usize,
    my_addr: &str,
    local_mode: bool,
    public_mode: bool,
    has_bootstrap: bool,
    reachable: Option<bool>,
) {
    ui.horizontal_centered(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;

        // Индикатор режима сети — должен отражать реальный режим backend.
        let (badge, badge_color, badge_hint): (&str, egui::Color32, &str) = if local_mode {
            (
                "󰍹 Local",
                theme::WARN,
                "Локальный режим (--local): только loopback, без выхода в сеть.",
            )
        } else if public_mode {
            (
                "󰒍 Public",
                theme::OK,
                "Публичный режим: узел работает как bootstrap/relay для глобальной сети.",
            )
        } else if has_bootstrap {
            (
                "󰖟 Global",
                theme::OK,
                "Подключены к глобальной сети через bootstrap-узлы.",
            )
        } else {
            (
                "󰛳 LAN",
                theme::OK,
                "Только локальная сеть (LAN): bootstrap-узлы не заданы.",
            )
        };
        ui.label(egui::RichText::new(badge).size(12.0).color(badge_color))
            .on_hover_text(badge_hint);
        dot(ui);

        // Peer count
        let peers_text = match peer_count {
            0 => "󰡉 нет узлов".to_string(),
            1 => "󰡉 1 узел".to_string(),
            n => format!("󰡉 {} узлов", n),
        };
        let peers_color = if peer_count == 0 { theme::WARN } else { theme::TEXT_DIM };
        ui.label(egui::RichText::new(peers_text).size(12.0).color(peers_color));
        dot(ui);

        // My address
        ui.label(egui::RichText::new(my_addr).size(11.5).monospace().color(theme::TEXT_FAINT));

        // Прямой доступ извне не подтверждён. Это не гарантия «портов закрыто»:
        // обратная проба бьёт по базовому порту, а при symmetric NAT внешний
        // порт может отличаться — возможны ложные срабатывания. Поэтому
        // формулировка мягкая, а доставка всё равно идёт через relay.
        if reachable == Some(false) {
            dot(ui);
            ui.label(
                egui::RichText::new("\u{F0026} прямой доступ не подтверждён")
                    .size(12.0)
                    .color(theme::WARN),
            )
            .on_hover_text(
                "Bootstrap-узел не смог подключиться к вам напрямую (провайдер/файрвол/\
                 symmetric NAT). Сообщения и файлы пойдут через relay. Проба проверяет \
                 совпадение внешнего и внутреннего порта, поэтому возможны ложные \
                 срабатывания. Подробнее — на странице «Профиль».",
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(concat!("Void Connect v", env!("CARGO_PKG_VERSION")))
                    .size(11.5)
                    .color(theme::TEXT_FAINT),
            );
        });
    });
}

/// Разделитель-точка между элементами строки статуса.
fn dot(ui: &mut egui::Ui) {
    ui.label(egui::RichText::new("·").color(theme::TEXT_FAINT));
}
