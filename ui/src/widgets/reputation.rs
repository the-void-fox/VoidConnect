use eframe::egui;

pub struct ReputationWidget;

impl ReputationWidget {
    pub fn show(ui: &mut egui::Ui, score: u32) {
        ui.horizontal(|ui| {
            ui.label("Репутация:");
            // Простая визуализация
            let color = if score > 80 { egui::Color32::GREEN } else { egui::Color32::YELLOW };
            ui.label(egui::RichText::new(format!("{} / 100", score)).color(color));
        });
    }
}