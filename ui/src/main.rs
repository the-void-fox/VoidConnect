mod app;
mod pages;
mod widgets;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("Void Connect"),
        ..Default::default()
    };

    eframe::run_native(
        "Void Connect",
        options,

        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());

            // Larger default font
            let mut fonts = egui::FontDefinitions::default();
            let font_bytes = include_bytes!("assets/fonts/FiraCode.ttf").to_vec();
            fonts.font_data.insert(
                "FiraCode".to_owned(),
                egui::FontData::from_owned(font_bytes).into(),
            );

            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "FiraCode".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "FiraCode".to_owned());

            cc.egui_ctx.set_fonts(fonts);
            cc.egui_ctx.set_pixels_per_point(1.5);

            Box::new(app::VoidApp::default())
        }),
    )
}