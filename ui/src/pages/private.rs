use eframe::egui;
use egui::{Button, Frame, ScrollArea, TextEdit};

pub struct PrivateMessage {
    pub text: String,
    pub time: String,
    pub is_me: bool,
}

pub struct Conversation {
    pub peer: String,
    pub last_message: String,
    pub unread: u32,
    pub messages: Vec<PrivateMessage>,
    scroll_to_bottom: bool,
    was_at_bottom: bool,
}

pub struct PrivatePage {
    pub conversations: Vec<Conversation>,
    pub selected: usize,
    pub input: String,
}

impl Default for PrivatePage {
    fn default() -> Self {
        Self {
            conversations: vec![
                Conversation {
                    peer: "alex".into(),
                    last_message: "Ок, жди".into(),
                    unread: 0,
                    scroll_to_bottom: true,
                    was_at_bottom: true,
                    messages: vec![
                        PrivateMessage { text: "Привет, можешь скинуть конфиг?".into(), time: "13:20".into(), is_me: true },
                        PrivateMessage { text: "Ок, жди".into(), time: "13:21".into(), is_me: false },
                    ],
                },
                Conversation {
                    peer: "mira".into(),
                    last_message: "Завтра проверим вместе".into(),
                    unread: 2,
                    scroll_to_bottom: true,
                    was_at_bottom: true,
                    messages: vec![
                        PrivateMessage { text: "Нашла баг в DNS резолвинге".into(), time: "14:00".into(), is_me: false },
                        PrivateMessage { text: "Завтра проверим вместе".into(), time: "14:01".into(), is_me: false },
                    ],
                },
                Conversation {
                    peer: "node_7f4a".into(),
                    last_message: "...".into(),
                    unread: 0,
                    scroll_to_bottom: true,
                    was_at_bottom: true,
                    messages: vec![],
                },
            ],
            selected: 0,
            input: String::new(),
        }
    }
}

impl PrivatePage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let line_height = ui.text_style_height(&egui::TextStyle::Body);
        let max_input_lines = 4;
        let input_scroll_height = line_height * max_input_lines as f32 + 12.0;
        let input_area_total_height = input_scroll_height + 32.0;
        let header_height = 60.0;
        let total_available = ui.available_height();
        let messages_height = (total_available - header_height - input_area_total_height).max(100.0);

        // Боковая панель со списком диалогов
        egui::SidePanel::left("private_sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show_inside(ui, |ui| {
                self.show_sidebar(ui);
            });

        // Основная область — текущий диалог
        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.show_chat(ui, messages_height, input_scroll_height);
        });
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("󰌾 Диалоги");
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        ScrollArea::vertical()
            .id_source("private_sidebar_scroll")
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for i in 0..self.conversations.len() {
                    let is_selected = self.selected == i;
                    let peer = self.conversations[i].peer.clone();
                    let last_msg = self.conversations[i].last_message.clone();
                    let unread = self.conversations[i].unread;

                    let frame_fill = if is_selected {
                        ui.visuals().widgets.active.bg_fill
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let frame = Frame::none()
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .fill(frame_fill);

                    let response = frame.show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            // Инициалы / аватар
                            let initials = peer
                                .chars()
                                .next()
                                .map(|c| c.to_uppercase().to_string())
                                .unwrap_or_else(|| "?".into());

                            let avatar_size = egui::vec2(30.0, 30.0);
                            let (rect, _) = ui.allocate_exact_size(avatar_size, egui::Sense::hover());
                            ui.painter().circle_filled(
                                rect.center(),
                                15.0,
                                ui.visuals().extreme_bg_color,
                            );
                            ui.painter().text(
                                rect.center(),
                                egui::Align2::CENTER_CENTER,
                                &initials,
                                egui::FontId::proportional(13.0),
                                ui.visuals().strong_text_color(),
                            );

                            ui.add_space(6.0);

                            ui.vertical(|ui| {
                                ui.set_min_width(0.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new(&peer)
                                            .strong()
                                            .size(13.0),
                                    );
                                    if unread > 0 {
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            let badge_text = format!("{}", unread);
                                            let badge_color = ui.visuals().hyperlink_color;
                                            ui.label(
                                                egui::RichText::new(badge_text)
                                                    .small()
                                                    .color(badge_color)
                                                    .strong(),
                                            );
                                        });
                                    }
                                });
                                ui.label(
                                    egui::RichText::new(&last_msg)
                                        .small()
                                        .color(ui.visuals().weak_text_color()),
                                );
                            });
                        });
                    });

                    let clicked = ui.interact(
                        response.response.rect,
                        ui.id().with(("convo_click", i)),
                        egui::Sense::click(),
                    ).clicked();

                    if clicked {
                        self.selected = i;
                        self.conversations[i].unread = 0;
                        self.input.clear();
                    }

                    ui.add_space(2.0);
                }
            });
    }

    fn show_chat(&mut self, ui: &mut egui::Ui, messages_height: f32, input_scroll_height: f32) {
        let selected = self.selected;
        let peer = self.conversations[selected].peer.clone();

        // Заголовок диалога
        ui.horizontal(|ui| {
            ui.heading(format!("󰭹 {}", peer));
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(12.0);

        // Пустое состояние
        if self.conversations[selected].messages.is_empty() {
            ui.allocate_ui(egui::vec2(ui.available_width(), messages_height), |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Нет сообщений. Начните диалог!")
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            });
        } else {
            // Область сообщений
            let scroll_output = ScrollArea::vertical()
                .id_source(format!("private_messages_{}", selected))
                .max_height(messages_height)
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let msgs_len = self.conversations[selected].messages.len();
                    for idx in 0..msgs_len {
                        let (text, time, is_me) = {
                            let m = &self.conversations[selected].messages[idx];
                            (m.text.clone(), m.time.clone(), m.is_me)
                        };
                        Self::render_message(ui, &text, &time, is_me, &peer);
                        ui.add_space(8.0);
                    }

                    if self.conversations[selected].scroll_to_bottom {
                        let r = ui.allocate_response(egui::vec2(0.0, 0.0), egui::Sense::hover());
                        r.scroll_to_me(Some(egui::Align::BOTTOM));
                        self.conversations[selected].scroll_to_bottom = false;
                    }
                });

            let scroll_offset = scroll_output.state.offset.y;
            let viewport_height = scroll_output.inner_rect.height();
            let content_height = scroll_output.content_size.y;
            let threshold = 75.0;
            self.conversations[selected].was_at_bottom =
                (scroll_offset + viewport_height) >= (content_height - threshold);
        }

        // Разделитель
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // Поле ввода
        let line_height = ui.text_style_height(&egui::TextStyle::Body);
        let line_count = self.input.lines().count().max(1).min(4);
        let mut should_send = false;

        ui.horizontal(|ui| {
            let button_width = 90.0;
            let spacing = ui.spacing().item_spacing.x + 20.0;
            let available_width = ui.available_width() - button_width - spacing;

            ui.allocate_ui(egui::vec2(available_width, input_scroll_height), |ui| {
                ScrollArea::vertical()
                    .id_source("private_input_scroll")
                    .max_height(input_scroll_height)
                    .auto_shrink([false; 2])
                    .show(ui, |ui: &mut egui::Ui| {
                        let text_edit = TextEdit::multiline(&mut self.input)
                            .hint_text("Введите сообщение...")
                            .desired_width(available_width - 8.0)
                            .desired_rows(line_count);

                        let response = ui.add(text_edit);

                        if response.has_focus() {
                            let (enter_pressed, shift_held) = ui.input(|i: &egui::InputState| {
                                (i.key_pressed(egui::Key::Enter), i.modifiers.shift)
                            });

                            if enter_pressed && !shift_held {
                                if self.input.ends_with('\n') {
                                    self.input.pop();
                                }
                                should_send = true;
                            }
                        }
                    });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_sized([button_width, 36.0], Button::new("📤 Отправить")).clicked() {
                    should_send = true;
                }
            });
        });

        if should_send {
            self.send_message();
        }
    }

    fn render_message(ui: &mut egui::Ui, text: &str, time: &str, is_me: bool, peer: &str) {
        let bubble = Frame::group(ui.style())
            .inner_margin(egui::Margin::same(8.0))
            .outer_margin(egui::Margin::symmetric(4.0, 2.0))
            .fill(if is_me {
                ui.visuals().widgets.active.bg_fill
            } else {
                ui.visuals().extreme_bg_color
            });

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                bubble.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(peer)
                                .strong()
                                .color(if is_me {
                                    ui.visuals().strong_text_color()
                                } else {
                                    ui.visuals().hyperlink_color
                                }),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(time)
                                .small()
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(text);
                });
            });

            if !is_me {
                ui.add_space(40.0);
            }
        });
    }

    fn send_message(&mut self) {
        let text = self.input.trim_end_matches('\n').trim().to_string();
        if text.is_empty() {
            self.input.clear();
            return;
        }

        let time = chrono::Local::now().format("%H:%M").to_string();
        let conv = &mut self.conversations[self.selected];

        conv.messages.push(PrivateMessage {
            text: text.clone(),
            time,
            is_me: true,
        });
        conv.last_message = text;

        self.input.clear();

        if self.conversations[self.selected].was_at_bottom {
            self.conversations[self.selected].scroll_to_bottom = true;
        }
    }

    pub fn receive_message(&mut self, peer: &str, msg: PrivateMessage) {
        let text_preview = msg.text.chars().take(40).collect::<String>();

        if let Some(conv) = self.conversations.iter_mut().find(|c| c.peer == peer) {
            conv.last_message = text_preview;
            if conv.was_at_bottom {
                conv.scroll_to_bottom = true;
            } else {
                conv.unread += 1;
            }
            conv.messages.push(msg);
        }
    }
}