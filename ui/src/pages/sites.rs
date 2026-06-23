use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::{Button, Frame, RichText, ScrollArea, TextEdit};
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::{DnsInfo, MirrorCmd, SiteInfo};

pub struct SitesPage {
    /// Канал GUI → backend: опубликовать каталог как сайт (путь, имя).
    pub publish_tx:     Option<UnboundedSender<(PathBuf, String)>>,
    /// Канал GUI → backend: зеркалировать / убрать из кэша сайт.
    pub mirror_tx:      Option<UnboundedSender<MirrorCmd>>,
    /// Снимок списка сайтов из backend.
    pub sites:          Option<Arc<Mutex<Vec<SiteInfo>>>>,
    /// Снимок имён внутреннего DNS (.void) из backend.
    pub dns_names:      Option<Arc<Mutex<Vec<DnsInfo>>>>,
    /// Порт локального HTTP-сервера сайтов (для открытия в браузере).
    pub site_http_port: u16,
    search:        String,
    publish_path:  String,
    publish_name:  String,
    snapshot:      Vec<SiteInfo>,
    dns_snapshot:  Vec<DnsInfo>,
    /// Имя сайта, ожидающего подтверждения удаления (модальное окно).
    confirm_delete: Option<String>,
}

impl Default for SitesPage {
    fn default() -> Self {
        Self {
            publish_tx:     None,
            mirror_tx:      None,
            sites:          None,
            dns_names:      None,
            site_http_port: 0,
            search:         String::new(),
            publish_path:   String::new(),
            publish_name:   String::new(),
            snapshot:       Vec::new(),
            dns_snapshot:   Vec::new(),
            confirm_delete: None,
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
        if let Some(shared) = &self.dns_names {
            self.dns_snapshot = shared.lock().unwrap().clone();
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
        ui.heading("\u{F059F} Сайты");
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
                let browse_w = 96.0;
                let gap = ui.spacing().item_spacing.x;
                let path_w = (ui.available_width() - btn_w - browse_w - gap * 2.0).max(120.0);
                ui.add(
                    TextEdit::singleline(&mut self.publish_path)
                        .hint_text("󰉓  Каталог сайта…")
                        .desired_width(path_w - 4.0),
                );
                // Нативный выбор каталога
                if ui.add_sized([browse_w, 26.0], Button::new("󰉕  Обзор")).clicked() {
                    if let Some(dir) = rfd::FileDialog::new()
                        .set_title("Каталог сайта")
                        .pick_folder()
                    {
                        self.publish_path = dir.display().to_string();
                    }
                }
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
        let mut mirror_action: Option<MirrorCmd> = None;
        let mut request_delete: Option<String> = None;

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
                            // Удаление — только для своего сайта (отзыв домена + стирание файлов).
                            if site.is_mine
                                && ui
                                    .add(Button::new(
                                        RichText::new("\u{F05E8}  Удалить")
                                            .color(egui::Color32::from_rgb(220, 80, 60)),
                                    ))
                                    .on_hover_text(
                                        "Удалить сайт: освободить домен .void и стереть файлы. \
                                         Зеркала тоже удалят копию. Действие необратимо.",
                                    )
                                    .clicked()
                            {
                                request_delete = Some(site.name.clone());
                            }
                            // Кэширование (зеркалирование) — только для чужих сайтов;
                            // свои мы и так раздаём.
                            if !site.is_mine {
                                if site.is_mirrored {
                                    if ui
                                        .add(Button::new(
                                            RichText::new("\u{F05E0}  В кэше")
                                                .color(egui::Color32::from_rgb(80, 180, 100)),
                                        ))
                                        .on_hover_text("Перестать кэшировать (удалит локальную копию)")
                                        .clicked()
                                    {
                                        mirror_action = Some(MirrorCmd::Unmirror(site.name.clone()));
                                    }
                                } else if ui
                                    .add(Button::new("\u{F0867}  Кэшировать"))
                                    .on_hover_text(
                                        "Скачать копию сайта и помогать его раздавать — \
                                         сайт останется доступен, даже когда владелец офлайн",
                                    )
                                    .clicked()
                                {
                                    mirror_action = Some(MirrorCmd::Mirror(site.name.clone()));
                                }
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }

            // ── Имена сети (.void) ──────────────────────────────────────────
            ui.add_space(12.0);
            let names: Vec<&DnsInfo> = self.dns_snapshot.iter()
                .filter(|d| search.is_empty() || d.dns_name.to_lowercase().contains(&search))
                .collect();
            egui::CollapsingHeader::new(format!("󰇧  Имена сети (.void) — {}", names.len()))
                .default_open(true)
                .show(ui, |ui| {
                    if names.is_empty() {
                        ui.label(
                            RichText::new("Пока нет известных имён.")
                                .small()
                                .color(ui.visuals().weak_text_color()),
                        );
                    }
                    for d in names {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&d.dns_name).strong());
                            ui.label(
                                RichText::new(format!("[{}]", d.kind))
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            );
                            if d.is_mine {
                                ui.label(
                                    RichText::new("мой")
                                        .small()
                                        .color(egui::Color32::from_rgb(80, 180, 100)),
                                );
                            }
                            let detail = match &d.ip {
                                Some(ip) => format!("{} · {}", d.owner_short, ip),
                                None     => d.owner_short.clone(),
                            };
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(
                                    RichText::new(detail)
                                        .small()
                                        .color(ui.visuals().weak_text_color()),
                                );
                            });
                        });
                    }
                });
        });

        if let Some(url) = open_url {
            Self::open(&url);
        }
        if let Some(cmd) = mirror_action {
            if let Some(tx) = &self.mirror_tx {
                let _ = tx.send(cmd);
            }
        }
        if let Some(name) = request_delete {
            self.confirm_delete = Some(name);
        }

        // ── Подтверждение удаления своего сайта ─────────────────────────────
        if let Some(name) = self.confirm_delete.clone() {
            let mut do_delete = false;
            let mut close = false;
            egui::Window::new("Удалить сайт?")
                .id(egui::Id::new("confirm_delete_site"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ui.ctx(), |ui| {
                    ui.label(RichText::new(format!("«{name}.void»")).strong().size(15.0));
                    ui.add_space(6.0);
                    ui.label("Домен .void будет освобождён, а файлы сайта — стёрты.");
                    ui.label(
                        RichText::new(
                            "Узлы, закэшировавшие сайт (зеркала), тоже удалят копию. \
                             Действие необратимо.",
                        )
                        .small()
                        .color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add(Button::new(
                                RichText::new("\u{F0A7A}  Удалить")
                                    .color(egui::Color32::from_rgb(230, 90, 70)),
                            ))
                            .clicked()
                        {
                            do_delete = true;
                        }
                        if ui.button("Отмена").clicked() {
                            close = true;
                        }
                    });
                });
            if do_delete {
                if let Some(tx) = &self.mirror_tx {
                    let _ = tx.send(MirrorCmd::Delete(name));
                }
                close = true;
            }
            if close {
                self.confirm_delete = None;
            }
        }
    }
}
