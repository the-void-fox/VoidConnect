use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::{Button, Frame, RichText, ScrollArea, TextEdit};
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::SiteInfo;

pub struct SitesPage {
    /// Канал GUI → backend: опубликовать каталог как сайт (путь, имя).
    pub publish_tx:     Option<UnboundedSender<(PathBuf, String)>>,
    /// Снимок списка сайтов из backend.
    pub sites:          Option<Arc<Mutex<Vec<SiteInfo>>>>,
    /// Порт локального HTTP-сервера сайтов (для открытия в браузере).
    pub site_http_port: u16,
    search:        String,
    publish_path:  String,
    publish_name:  String,
    snapshot:      Vec<SiteInfo>,
}

impl Default for SitesPage {
    fn default() -> Self {
        Self {
            publish_tx:     None,
            sites:          None,
            site_http_port: 0,
            search:         String::new(),
            publish_path:   String::new(),
            publish_name:   String::new(),
            snapshot:       Vec::new(),
        }
    }
}

fn human_size(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1e9      { format!("{:.1} GB", b / 1e9) }
    else if b >= 1e6 { format!("{:.1} MB", b / 1e6) }
    else if b >= 1e3 { format!("{:.1} KB", b / 1e3) }
    else             { format!("{} B", bytes) }
}

impl SitesPage {
    fn sync(&mut self) {
        if let Some(shared) = &self.sites {
            self.snapshot = shared.lock().unwrap().clone();
        }
    }

    fn publish(&mut self) {
        let path = self.publish_path.trim().to_string();
        let name = self.publish_name.trim().to_string();
        if path.is_empty() || name.is_empty() { return; }
        if let Some(tx) = &self.publish_tx {
            let _ = tx.send((PathBuf::from(path), name));
        }
        self.publish_path.clear();
        self.publish_name.clear();
    }

    fn open(url: &str) {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.sync();

        ui.add_space(8.0);
        ui.heading("Сайты");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // ── Публикация сайта ────────────────────────────────────────────────
        let mut do_publish = false;
        Frame::group(ui.style()).show(ui, |ui| {
            ui.label(RichText::new("Опубликовать сайт").strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Имя:");
                ui.add(
                    TextEdit::singleline(&mut self.publish_name)
                        .hint_text("blog")
                        .desired_width(140.0),
                );
                ui.label(".void");
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let btn_w = 130.0;
                let gap = ui.spacing().item_spacing.x;
                let path_w = (ui.available_width() - btn_w - gap).max(120.0);
                ui.add(
                    TextEdit::singleline(&mut self.publish_path)
                        .hint_text("󰉓  Путь к каталогу сайта…")
                        .desired_width(path_w - 4.0),
                );
                let enabled = self.publish_tx.is_some()
                    && !self.publish_path.trim().is_empty()
                    && !self.publish_name.trim().is_empty();
                if ui.add_enabled(enabled, Button::new("󰐕  Опубликовать").min_size(egui::vec2(btn_w, 26.0))).clicked() {
                    do_publish = true;
                }
            });
        });
        if do_publish {
            self.publish();
        }

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.search)
                    .hint_text("󰍉  Поиск сайтов...")
                    .desired_width(ui.available_width()),
            );
        });
        ui.add_space(8.0);

        // ── Список сайтов ───────────────────────────────────────────────────
        let search = self.search.to_lowercase();
        let mut open_url: Option<String> = None;

        ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            if self.snapshot.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("Пока нет сайтов. Опубликуйте каталог выше.")
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            }

            for site in &self.snapshot {
                if !search.is_empty()
                    && !site.name.to_lowercase().contains(&search)
                    && !site.dns_name.to_lowercase().contains(&search)
                {
                    continue;
                }

                Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&site.dns_name).strong().size(15.0));
                                if site.is_mine {
                                    ui.label(
                                        RichText::new("мой")
                                            .small()
                                            .color(egui::Color32::from_rgb(80, 180, 100)),
                                    );
                                }
                            });
                            ui.label(
                                RichText::new(format!(
                                    "{} файл(ов) · {}",
                                    site.file_count,
                                    human_size(site.size_bytes)
                                ))
                                .small()
                                .color(ui.visuals().weak_text_color()),
                            );
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(Button::new("󰖟  Открыть")).clicked() {
                                open_url = Some(site.url.clone());
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }
        });

        if let Some(url) = open_url {
            Self::open(&url);
        }
    }
}
