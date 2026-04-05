use eframe::egui;
use egui::{Button, Frame, ScrollArea, TextEdit};

pub struct ChatMessage {
    pub author: String,
    pub text: String,
    pub time: String,
    pub is_me: bool,
}

pub struct ChatPage {
    pub messages: Vec<ChatMessage>,
    pub input: String,
    scroll_to_bottom: bool,
    was_at_bottom: bool,
}

impl Default for ChatPage {
    fn default() -> Self {
        Self {
            messages: vec![
                ChatMessage { author: "alex".into(), text: "Всем привет! Тестирую Void Connect 👋".into(), time: "14:01".into(), is_me: false },
                ChatMessage { author: "mira".into(), text: "Привет! Всё работает нормально, только что поднял узел".into(), time: "14:03".into(), is_me: false },
                ChatMessage { author: "vasya".into(), text: "Отлично, я тоже онлайн. Давайте проверим передачу файлов?".into(), time: "14:05".into(), is_me: true },
                ChatMessage { author: "alex".into(), text: "Давай, кинул файл в хранилище — можешь скачать".into(), time: "14:06".into(), is_me: false },
                ChatMessage { author: "bot_node".into(), text: "[Системное] Новый узел подключился: node_7f4a (rep: 0)".into(), time: "14:07".into(), is_me: false },
                ChatMessage { author: "mira".into(), text: "Репутация набирается медленно, но справедливо 😄".into(), time: "14:08".into(), is_me: false },
            ],
            input: String::new(),
            scroll_to_bottom: true,
            was_at_bottom: true,
        }
    }
}

impl ChatPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let line_height = ui.text_style_height(&egui::TextStyle::Body);
        let line_count = self.input.lines().count().max(1).min(4);
        
        // Фиксированная высота области ввода
        let max_input_lines = 4;
        let input_scroll_height = line_height * max_input_lines as f32 + 12.0;
        let input_area_total_height = input_scroll_height + 32.0; // + отступы и разделитель
        
        // Высота заголовка
        let header_height = 50.0;
        
        // Общий контейнер с ограничением размера
        let total_available = ui.available_height();
        let messages_height = (total_available - header_height - input_area_total_height).max(100.0);
        
        // === Заголовок ===
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("󰭹 Общий чат");
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        // === Область сообщений (фиксированная высота) ===
        let scroll_output = ScrollArea::vertical()
            .id_source("chat_messages_scroll")
            .max_height(messages_height)
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for msg in &self.messages {
                    self.render_message(ui, msg);
                    ui.add_space(8.0);
                }
                
                if self.scroll_to_bottom {
                    let bottom_response = ui.allocate_response(
                        egui::vec2(0.0, 0.0),
                        egui::Sense::hover()
                    );
                    bottom_response.scroll_to_me(Some(egui::Align::BOTTOM));
                    self.scroll_to_bottom = false;
                }
            });
        
        // Проверяем позицию скролла
        let scroll_offset = scroll_output.state.offset.y;
        let viewport_height = scroll_output.inner_rect.height();
        let content_height = scroll_output.content_size.y;
        let threshold = 50.0;
        self.was_at_bottom = (scroll_offset + viewport_height) >= (content_height - threshold);

        // === Разделитель ===
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // === Область ввода (фиксированная максимальная высота) ===
        let mut should_send = false;
        
        ui.horizontal(|ui| {
            let button_width = 90.0;
            let spacing = ui.spacing().item_spacing.x + 20.0;
            let available_width = ui.available_width() - button_width - spacing;
            
            // Поле ввода с прокруткой (максимум 4 строки)
            ui.allocate_ui(egui::vec2(available_width, input_scroll_height), |ui| {
                ScrollArea::vertical()
                    .id_source("input_scroll")
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

            // Кнопка отправки (вертикально по центру)
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

    fn render_message(&self, ui: &mut egui::Ui, msg: &ChatMessage) {
        let bubble = Frame::group(ui.style())
            .inner_margin(egui::Margin::same(8.0))
            .outer_margin(egui::Margin::symmetric(4.0, 2.0))
            .fill(if msg.is_me {
                ui.visuals().widgets.active.bg_fill
            } else {
                ui.visuals().extreme_bg_color
            });

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                bubble.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(&msg.author)
                                .strong()
                                .color(if msg.is_me {
                                    ui.visuals().strong_text_color()
                                } else {
                                    ui.visuals().hyperlink_color
                                }),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(&msg.time)
                                .small()
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(&msg.text);
                });
            });

            if !msg.is_me {
                ui.add_space(40.0);
            }
        });
    }

    fn send_message(&mut self) {
        let text = self.input.trim_end_matches('\n').trim();
        if text.is_empty() {
            self.input.clear();
            return;
        }
        
        self.messages.push(ChatMessage {
            author: "Вы".into(),
            text: text.to_string(),
            time: chrono::Local::now().format("%H:%M").to_string(),
            is_me: true,
        });
        self.input.clear();
        
        if self.was_at_bottom {
            self.scroll_to_bottom = true;
        }
    }
    
    pub fn receive_message(&mut self, msg: ChatMessage) {
        self.messages.push(msg);
        
        if self.was_at_bottom {
            self.scroll_to_bottom = true;
        }
    }
}