use eframe::egui;

pub fn show_status_bar(ui: &mut egui::Ui, peer_count: usize, my_addr: &str, local_mode: bool) {
    ui.horizontal(|ui| {
        ui.add_space(8.0);

        // Network mode badge
        if local_mode {
            ui.label(
                egui::RichText::new("󰍹 Local")
                    .small()
                    .color(egui::Color32::from_rgb(220, 160, 40)),
            );
        } else {
            ui.label(
                egui::RichText::new("󰛳 LAN")
                    .small()
                    .color(egui::Color32::from_rgb(80, 180, 80)),
            );
        }
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

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("Void Connect v0.1.0").small().weak());
        });
    });
}
