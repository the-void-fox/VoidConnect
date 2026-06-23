use eframe::egui;

pub fn show_status_bar(
    ui: &mut egui::Ui,
    peer_count: usize,
    my_addr: &str,
    local_mode: bool,
    public_mode: bool,
    has_bootstrap: bool,
    reachable: Option<bool>,
) {
    ui.horizontal(|ui| {
        ui.add_space(8.0);

        // Индикатор режима сети — должен отражать реальный режим backend.
        let (badge, badge_color, badge_hint): (&str, egui::Color32, &str) = if local_mode {
            (
                "󰍹 Local",
                egui::Color32::from_rgb(220, 160, 40),
                "Локальный режим (--local): только loopback, без выхода в сеть.",
            )
        } else if public_mode {
            (
                "󰒍 Public",
                egui::Color32::from_rgb(80, 180, 80),
                "Публичный режим: узел работает как bootstrap/relay для глобальной сети.",
            )
        } else if has_bootstrap {
            (
                "󰖟 Global",
                egui::Color32::from_rgb(80, 180, 80),
                "Подключены к глобальной сети через bootstrap-узлы.",
            )
        } else {
            (
                "󰛳 LAN",
                egui::Color32::from_rgb(80, 180, 80),
                "Только локальная сеть (LAN): bootstrap-узлы не заданы.",
            )
        };
        ui.label(egui::RichText::new(badge).small().color(badge_color))
            .on_hover_text(badge_hint);
        ui.separator();

        // Peer count
        let peers_text = match peer_count {
            0 => "󰡉 нет узлов".to_string(),
            1 => "󰡉 1 узел".to_string(),
            n => format!("󰡉 {} узлов", n),
        };
        let peers_color = if peer_count == 0 {
            egui::Color32::from_rgb(200, 120, 50)
        } else {
            ui.visuals().text_color()
        };
        ui.label(egui::RichText::new(peers_text).small().color(peers_color));
        ui.separator();

        // My address
        ui.label(egui::RichText::new(my_addr).small().weak());

        // Прямой доступ извне не подтверждён. Это не гарантия «портов закрыто»:
        // обратная проба бьёт по базовому порту, а при symmetric NAT внешний
        // порт может отличаться — возможны ложные срабатывания. Поэтому
        // формулировка мягкая, а доставка всё равно идёт через relay.
        if reachable == Some(false) {
            ui.separator();
            ui.label(
                egui::RichText::new("\u{F0026} прямой доступ не подтверждён")
                    .small()
                    .strong()
                    .color(egui::Color32::from_rgb(220, 150, 60)),
            )
            .on_hover_text(
                "Bootstrap-узел не смог подключиться к вам напрямую (провайдер/файрвол/\
                 symmetric NAT). Сообщения и файлы пойдут через relay. Проба проверяет \
                 совпадение внешнего и внутреннего порта, поэтому возможны ложные \
                 срабатывания. Подробнее — на странице «Профиль».",
            );
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(concat!("Void Connect v", env!("CARGO_PKG_VERSION")))
                    .small()
                    .weak(),
            );
        });
    });
}
