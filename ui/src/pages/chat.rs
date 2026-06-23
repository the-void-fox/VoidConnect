use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use eframe::egui;
use egui::{Button, Frame, ScrollArea, TextEdit};
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use crate::widgets::peer_popup::{status_colors, show_peer_profile};

/// Каналы («доски») общего чата: (id, иконка Nerd Font, название).
/// `id` хранится в каждом сообщении и в БД; глобальный канал — "global".
pub const CHANNELS: &[(&str, &str, &str)] = &[
    ("global", "\u{F01E7}", "Глобальный"),
    ("tech",   "\u{F061A}", "Технологии"),
    ("dev",    "\u{F0174}", "Разработка"),
    ("games",  "\u{F0EBF}", "Игры"),
    ("music",  "\u{F0387}", "Музыка"),
    ("movies", "\u{F0381}", "Кино"),
    ("art",    "\u{F033A}", "Творчество"),
    ("help",   "\u{F033B}", "Помощь"),
    ("random", "\u{F0177}", "Random"),
    ("trade",  "\u{F07D4}", "Барахолка"),
];

/// (иконка, название) канала по id; для неизвестного id — символ # и сам id.
pub fn channel_meta(id: &str) -> (&'static str, String) {
    CHANNELS
        .iter()
        .find(|(cid, _, _)| *cid == id)
        .map(|(_, icon, name)| (*icon, name.to_string()))
        .unwrap_or(("\u{F04C2}", id.to_string()))
}

pub struct ChatMessage {
    pub author:  String,
    pub text:    String,
    pub time:    String,
    pub is_me:   bool,
    pub from_id: Option<NodeId>,
    /// Канал («доска»), к которому относится сообщение.
    pub channel: String,
}

pub struct ChatPage {
    pub messages:     Vec<ChatMessage>,
    pub input:        String,
    scroll_to_bottom: bool,
    was_at_bottom:    bool,
    /// Текущий выбранный канал («доска»). По умолчанию "global".
    current_channel:  String,
    send_tx:  Option<tokio::sync::mpsc::UnboundedSender<(String, String)>>,
    my_name:  String,
    /// Свой аватар (base64-PNG) — для строк собственных сообщений.
    pub my_avatar: Option<String>,
    peers:    Vec<PeerInfo>,
    profiles: HashMap<NodeId, PeerProfile>,
    selected: Option<NodeId>,
    /// Сигнал в VoidApp: открыть личный чат с этим пиром
    pub pending_dm: Option<NodeId>,
    /// Снимок репутации узлов из backend (NodeId → score).
    pub reputation: Option<Arc<Mutex<HashMap<NodeId, f64>>>>,
    /// Сигнал в VoidApp: пожаловаться на узел (target, причина).
    pub pending_report: Option<(NodeId, void_reputation::ReportReason)>,
}

impl ChatPage {
    pub fn new(
        send_tx: tokio::sync::mpsc::UnboundedSender<(String, String)>,
        my_name: String,
    ) -> Self {
        Self {
            messages:         Vec::new(),
            input:            String::new(),
            scroll_to_bottom: true,
            was_at_bottom:    true,
            current_channel:  "global".into(),
            send_tx:          Some(send_tx),
            my_name,
            my_avatar:        None,
            peers:            Vec::new(),
            profiles:         HashMap::new(),
            selected:         None,
            pending_dm:       None,
            reputation:       None,
            pending_report:   None,
        }
    }

    pub fn update_context(&mut self, peers: Vec<PeerInfo>, profiles: HashMap<NodeId, PeerProfile>) {
        self.peers    = peers;
        self.profiles = profiles;
        // Don't auto-close popup — we now show it from profile cache even when offline
    }

    /// Текущая репутация узла из снимка backend (если есть).
    fn peer_score(&self, id: &NodeId) -> Option<f64> {
        self.reputation.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).copied()))
    }
}

impl Default for ChatPage {
    fn default() -> Self {
        Self {
            messages:         Vec::new(),
            input:            String::new(),
            scroll_to_bottom: true,
            was_at_bottom:    true,
            current_channel:  "global".into(),
            send_tx:          None,
            my_name:          "Вы".into(),
            my_avatar:        None,
            peers:            Vec::new(),
            profiles:         HashMap::new(),
            selected:         None,
            pending_dm:       None,
            reputation:       None,
            pending_report:   None,
        }
    }
}

impl ChatPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        // Profile popup — shown from cache even if peer is offline
        let mut close_popup = false;
        let mut start_dm_id: Option<NodeId> = None;
        let mut report_reason: Option<void_reputation::ReportReason> = None;
        if let Some(sel_id) = self.selected.clone() {
            let peer    = self.peers.iter().find(|p| p.id == sel_id).cloned();
            let profile = self.profiles.get(&sel_id).cloned();

            if peer.is_some() || profile.is_some() {
                egui::Window::new("Профиль участника")
                    .id(egui::Id::new("chat_peer_profile_popup"))
                    .collapsible(false)
                    .resizable(false)
                    .default_width(320.0)
                    .show(ui.ctx(), |ui| {
                        let rep = self.peer_score(&sel_id);
                        let action = show_peer_profile(ui, peer.as_ref(), profile.as_ref(), rep);
                        ui.add_space(6.0);
                        if action.start_dm {
                            start_dm_id = Some(sel_id.clone());
                            close_popup = true;
                        }
                        if let Some(reason) = action.report {
                            report_reason = Some(reason);
                            close_popup = true;
                        }
                        if ui.button("Закрыть").clicked() {
                            close_popup = true;
                        }
                    });
            } else {
                close_popup = true;
            }
            if let Some(reason) = report_reason {
                self.pending_report = Some((sel_id.clone(), reason));
            }
        }
        if close_popup { self.selected = None; }
        if let Some(id) = start_dm_id {
            self.pending_dm = Some(id);
        }

        let line_height        = ui.text_style_height(&egui::TextStyle::Body);
        let max_input_lines    = 4;
        let input_scroll_h     = line_height * max_input_lines as f32 + 12.0;
        let input_area_total_h = input_scroll_h + 32.0;
        ui.add_space(8.0);
        // Заголовок = текущий канал («доска»).
        let (ch_icon, ch_name) = channel_meta(&self.current_channel);
        ui.horizontal(|ui| {
            ui.heading(format!("{}  {}", ch_icon, ch_name));
            ui.label(
                egui::RichText::new("· общий чат").color(ui.visuals().weak_text_color()),
            );
        });
        ui.add_space(6.0);

        // Панель каналов («доски» в духе форчана): глобальный + тематические.
        ui.horizontal_wrapped(|ui| {
            for (id, icon, name) in CHANNELS {
                let selected = self.current_channel == *id;
                if ui
                    .selectable_label(selected, format!("{} {}", icon, name))
                    .clicked()
                {
                    self.current_channel = (*id).to_string();
                    self.scroll_to_bottom = true;
                }
            }
        });
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);

        // Высоту области сообщений считаем здесь — после панели каналов, чтобы
        // учесть её фактическую высоту (она может переноситься на пару строк).
        let messages_h = (ui.available_height() - input_area_total_h).max(100.0);

        // Есть ли сообщения в текущем канале (для заглушки пустого состояния).
        let channel_has_msgs = self.messages.iter().any(|m| m.channel == self.current_channel);

        // Collect click result outside scroll closure to avoid borrow conflict
        let mut clicked_id: Option<NodeId> = None;

        let scroll_out = ScrollArea::vertical()
            .id_source("chat_messages_scroll")
            .max_height(messages_h)
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if !channel_has_msgs {
                    ui.add_space(messages_h / 2.0 - 20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "В канале «{}» пока нет сообщений.", ch_name))
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                }

                for msg in self.messages.iter().filter(|m| m.channel == self.current_channel) {
                    if let Some(id) = Self::render_message(ui, msg, &self.profiles, self.my_avatar.as_deref()) {
                        clicked_id = Some(id);
                    }
                    ui.add_space(8.0);
                }

                if self.scroll_to_bottom {
                    let r = ui.allocate_response(egui::vec2(0.0, 0.0), egui::Sense::hover());
                    r.scroll_to_me(Some(egui::Align::BOTTOM));
                    self.scroll_to_bottom = false;
                }
            });

        // Apply click after scroll area finishes (avoids borrow conflict)
        if let Some(id) = clicked_id {
            self.selected = if self.selected.as_ref() == Some(&id) { None } else { Some(id) };
        }

        let scroll_offset  = scroll_out.state.offset.y;
        let viewport_h     = scroll_out.inner_rect.height();
        let content_h      = scroll_out.content_size.y;
        self.was_at_bottom = (scroll_offset + viewport_h) >= (content_h - 50.0);

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        let mut should_send = false;
        let line_count      = self.input.lines().count().max(1).min(4);

        ui.horizontal(|ui| {
            let btn_w   = 90.0;
            let spacing = ui.spacing().item_spacing.x + 20.0;
            let avail_w = ui.available_width() - btn_w - spacing;

            ui.allocate_ui(egui::vec2(avail_w, input_scroll_h), |ui| {
                ScrollArea::vertical()
                    .id_source("input_scroll")
                    .max_height(input_scroll_h)
                    .auto_shrink([false; 2])
                    .show(ui, |ui: &mut egui::Ui| {
                        let te = TextEdit::multiline(&mut self.input)
                            .hint_text("Введите сообщение...")
                            .desired_width(avail_w - 8.0)
                            .desired_rows(line_count);
                        let resp = ui.add(te);
                        if resp.has_focus() {
                            let (enter, shift) = ui.input(|i| {
                                (i.key_pressed(egui::Key::Enter), i.modifiers.shift)
                            });
                            if enter && !shift {
                                if self.input.ends_with('\n') { self.input.pop(); }
                                should_send = true;
                            }
                        }
                    });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_sized([btn_w, 36.0], Button::new("󰒊 Отправить")).clicked() {
                    should_send = true;
                }
            });
        });

        if should_send { self.send_message(); }
    }

    fn render_message(
        ui: &mut egui::Ui,
        msg: &ChatMessage,
        profiles: &HashMap<NodeId, PeerProfile>,
        my_avatar: Option<&str>,
    ) -> Option<NodeId> {
        let mut clicked_id: Option<NodeId> = None;

        // Resolve display name: profile name takes precedence
        let display_name = if let Some(id) = &msg.from_id {
            profiles.get(id)
                .map(|p| p.name.as_str())
                .filter(|n| !n.is_empty())
                .unwrap_or(msg.author.as_str())
                .to_string()
        } else {
            msg.author.clone()
        };

        // Статус автора (для цвета имени и запасного кружка аватара)
        let status = if msg.is_me {
            None
        } else {
            msg.from_id.as_ref()
                .and_then(|id| profiles.get(id))
                .map(|p| p.status.as_str())
        };

        // Аватар автора: свой для собственных сообщений, иначе из профиля пира.
        let avatar_b64 = if msg.is_me {
            my_avatar
        } else {
            msg.from_id.as_ref()
                .and_then(|id| profiles.get(id))
                .and_then(|p| p.avatar_png.as_deref())
        };
        let avatar_fill = if msg.is_me {
            ui.visuals().hyperlink_color
        } else {
            status_colors(status).0
        };

        // Name color: status-tinted for others, default for self
        let name_color = if msg.is_me {
            ui.visuals().strong_text_color()
        } else {
            let (_, stroke) = status_colors(status);
            stroke
        };

        let bubble = Frame::group(ui.style())
            .inner_margin(egui::Margin::same(8.0))
            .outer_margin(egui::Margin::symmetric(4.0, 2.0))
            .fill(if msg.is_me {
                ui.visuals().widgets.active.bg_fill
            } else {
                ui.visuals().extreme_bg_color
            });

        ui.horizontal_top(|ui| {
            crate::avatar::show_avatar(ui, avatar_b64, &display_name, avatar_fill, 28.0);
            ui.add_space(6.0);
            ui.vertical(|ui| {
                bubble.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if !msg.is_me {
                            // Clickable author name → triggers profile popup
                            let resp = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&display_name)
                                        .strong()
                                        .color(name_color)
                                )
                                .sense(egui::Sense::click())
                            );
                            if resp.clicked() {
                                clicked_id = msg.from_id.clone();
                            }
                            if resp.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }
                            resp.on_hover_text("Нажмите, чтобы посмотреть профиль");
                        } else {
                            ui.label(
                                egui::RichText::new(&display_name).strong().color(name_color)
                            );
                        }

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
            if !msg.is_me { ui.add_space(40.0); }
        });

        clicked_id
    }

    fn send_message(&mut self) {
        let text = self.input.trim_end_matches('\n').trim().to_string();
        if text.is_empty() {
            self.input.clear();
            return;
        }

        self.messages.push(ChatMessage {
            author:  self.my_name.clone(),
            text:    text.clone(),
            time:    chrono::Local::now().format("%H:%M").to_string(),
            is_me:   true,
            from_id: None,
            channel: self.current_channel.clone(),
        });
        self.input.clear();
        if self.was_at_bottom { self.scroll_to_bottom = true; }

        if let Some(tx) = &self.send_tx {
            let _ = tx.send((self.current_channel.clone(), text));
        }
    }

    pub fn receive_message(&mut self, msg: ChatMessage) {
        self.messages.push(msg);
        if self.was_at_bottom { self.scroll_to_bottom = true; }
    }
}
