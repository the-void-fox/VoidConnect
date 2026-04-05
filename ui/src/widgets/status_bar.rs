use eframe::egui;

pub fn show_status_bar(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.add_space(8.0);

        // Network mode
        ui.label(egui::RichText::new("🔗 LAN").small().color(egui::Color32::from_rgb(80, 180, 80)));
        ui.separator();

        // Peer count
        ui.label(egui::RichText::new("👥 5 узлов").small());
        ui.separator();

        // Upload/Download speeds (mock)
        ui.label(egui::RichText::new("⬆ 1.2 МБ/с").small());
        ui.label(egui::RichText::new("⬇ 0.4 МБ/с").small());
        ui.separator();

        // My address
        ui.label(egui::RichText::new("vasya.void / 192.168.1.42").small().weak());

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("Void Connect v0.1.0").small().weak());
        });
    });
}