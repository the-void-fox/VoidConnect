use eframe::egui;
use egui::{Button, Frame, RichText, ScrollArea, TextEdit};

pub struct SiteEntry {
    pub name:        String,
    pub address:     String,
    pub owner:       String,
    pub hosters:     u32,
    pub online:      bool,
    pub description: String,
}

pub struct SitesPage {
    pub sites:         Vec<SiteEntry>,
    pub search:        String,
    pub show_publish:  bool,
    pub new_site_name: String,
    pub new_site_desc: String,
}

impl Default for SitesPage {
    fn default() -> Self {
        Self {
            sites: vec![
                SiteEntry {
                    name:        "Vasya's Blog".into(),
                    address:     "vasya.void".into(),
                    owner:       "vasya".into(),
                    hosters:     3,
                    online:      true,
                    description: "Личный блог о сетях и Rust".into(),
                },
                SiteEntry {
                    name:        "Node Status Dashboard".into(),
                    address:     "status.void".into(),
                    owner:       "alex".into(),
                    hosters:     5,
                    online:      true,
                    description: "Мониторинг узлов сети в реальном времени".into(),
                },
                SiteEntry {
                    name:        "Void Wiki".into(),
                    address:     "wiki.void".into(),
                    owner:       "mira".into(),
                    hosters:     7,
                    online:      true,
                    description: "Документация и гайды по Void Connect".into(),
                },
                SiteEntry {
                    name:        "Music Archive".into(),
                    address:     "music.void".into(),
                    owner:       "node_7f4a".into(),
                    hosters:     1,
                    online:      false,
                    description: "Архив независимой музыки".into(),
                },
            ],
            search:        String::new(),
            show_publish:  false,
            new_site_name: String::new(),
            new_site_desc: String::new(),
        }
    }
}

impl SitesPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("  Сайты .void");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // Панель инструментов
        ui.horizontal(|ui| {
            let btn_w    = 130.0;
            let gap      = ui.spacing().item_spacing.x;
            let search_w = ui.available_width() - btn_w - gap * 2.0;

            ui.add(
                TextEdit::singleline(&mut self.search)
                    .hint_text("󰍉  Поиск сайтов...")
                    .desired_width(search_w),
            );

            if ui.add_sized([btn_w, 28.0], Button::new("  Опубликовать")).clicked() {
                self.show_publish = true;
            }
        });

        ui.add_space(8.0);

        // Шапка таблицы
        Frame::none()
            .inner_margin(egui::Margin::symmetric(8.0, 4.0))
            .fill(ui.visuals().widgets.noninteractive.bg_fill)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.allocate_ui(egui::vec2(16.0, 20.0), |ui| { ui.set_width(16.0); ui.label(""); });
                    ui.allocate_ui(egui::vec2(200.0, 20.0), |ui| {
                        ui.label(RichText::new("Название").strong().size(12.0));
                    });
                    ui.allocate_ui(egui::vec2(160.0, 20.0), |ui| {
                        ui.label(RichText::new("Адрес").strong().size(12.0));
                    });
                    ui.allocate_ui(egui::vec2(100.0, 20.0), |ui| {
                        ui.label(RichText::new("Владелец").strong().size(12.0));
                    });
                    ui.allocate_ui(egui::vec2(80.0, 20.0), |ui| {
                        ui.centered_and_justified(|ui| {
                            ui.label(RichText::new("Хостеры").strong().size(12.0));
                        });
                    });
                    ui.label(RichText::new("Описание").strong().size(12.0));
                });
            });

        ui.add_space(2.0);

        // Список сайтов
        let search_lo = self.search.to_lowercase();
        ScrollArea::vertical()
            .id_source("sites_scroll")
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for (i, site) in self.sites.iter().enumerate() {
                    if !search_lo.is_empty()
                        && !site.name.to_lowercase().contains(&search_lo)
                        && !site.address.to_lowercase().contains(&search_lo)
                    {
                        continue;
                    }

                    let row_fill = if i % 2 == 0 {
                        ui.visuals().extreme_bg_color
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    Frame::none()
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .fill(row_fill)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Индикатор онлайн/оффлайн
                                let dot_color = if site.online {
                                    egui::Color32::from_rgb(80, 200, 80)
                                } else {
                                    egui::Color32::from_rgb(180, 60, 60)
                                };
                                ui.allocate_ui(egui::vec2(16.0, 28.0), |ui| {
                                    ui.centered_and_justified(|ui| {
                                        ui.label(RichText::new("●").color(dot_color).size(10.0));
                                    });
                                });

                                // Название
                                ui.allocate_ui(egui::vec2(200.0, 28.0), |ui| {
                                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(&site.name).strong().size(13.0));
                                    });
                                });

                                // Адрес
                                ui.allocate_ui(egui::vec2(160.0, 28.0), |ui| {
                                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                        ui.label(
                                            RichText::new(&site.address)
                                                .monospace()
                                                .color(ui.visuals().hyperlink_color)
                                                .size(12.0),
                                        );
                                    });
                                });

                                // Владелец
                                ui.allocate_ui(egui::vec2(100.0, 28.0), |ui| {
                                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                        ui.label(RichText::new(&site.owner).size(12.0));
                                    });
                                });

                                // Хостеры
                                ui.allocate_ui(egui::vec2(80.0, 28.0), |ui| {
                                    ui.centered_and_justified(|ui| {
                                        ui.label(
                                            RichText::new(format!("{}", site.hosters))
                                                .color(ui.visuals().weak_text_color())
                                                .size(12.0),
                                        );
                                    });
                                });

                                // Описание
                                ui.label(
                                    RichText::new(&site.description)
                                        .color(ui.visuals().weak_text_color())
                                        .size(12.0),
                                );
                            });
                        });
                }
            });

        // Диалог публикации сайта
        if self.show_publish {
            egui::Window::new("  Опубликовать сайт")
                .collapsible(false)
                .resizable(false)
                .fixed_size([380.0, 260.0])
                .show(ui.ctx(), |ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Название сайта:").strong());
                    ui.add(TextEdit::singleline(&mut self.new_site_name).desired_width(f32::INFINITY));
                    ui.add_space(8.0);
                    ui.label(RichText::new("Описание:").strong());
                    ui.add(TextEdit::multiline(&mut self.new_site_desc)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY));
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new("Файлы сайта будут загружены из директории ~/void-sites/<name>/")
                            .small()
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.button("Опубликовать").clicked() {
                            // TODO: вызов backend
                            self.show_publish = false;
                            self.new_site_name.clear();
                            self.new_site_desc.clear();
                        }
                        if ui.button("Отмена").clicked() {
                            self.show_publish = false;
                        }
                    });
                });
        }
    }
}
