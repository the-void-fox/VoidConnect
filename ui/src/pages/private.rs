use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui;
use egui::{Button, Frame, ScrollArea, TextEdit};

use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use void_chat::private_chat::{DmSendCmd, IncomingDm};
use void_crypto::keys::EncryptionKeypair;
use crate::widgets::peer_popup::status_colors;
use crate::backend::DeliveryState;

// ── Модели ────────────────────────────────────────────────────────────────────

pub struct UiMessage {
    pub message_id: String,
    pub text:       String,
    pub time:       String,
    pub is_me:      bool,
    /// Статус доставки исходящего сообщения. `None` — для входящих и истории.
    pub delivery:   Option<DeliveryState>,
}

pub struct Conversation {
    pub peer_id:      NodeId,
    pub peer_name:    String,
    pub messages:     Vec<UiMessage>,
    pub last_message: String,
    pub unread:       u32,
    scroll_to_bottom: bool,
    was_at_bottom:    bool,
}

// ── Страница ──────────────────────────────────────────────────────────────────

pub struct PrivatePage {
    pub conversations: Vec<Conversation>,
    pub selected:      usize,
    pub input:         String,

    // Доступ к backend
    pub dm_sender:  Option<tokio::sync::mpsc::UnboundedSender<DmSendCmd>>,
    pub my_enc_kp:  Option<Arc<EncryptionKeypair>>,
    pub my_enc_pub: [u8; 32],
    pub my_node_id: Option<NodeId>,
    pub my_name:    String,
    /// Свой аватар (base64-PNG) — для строк собственных сообщений.
    pub my_avatar:  Option<String>,
    pub base_port:  u16,

    // Актуальные данные о пирах (обновляется каждый кадр из app.rs)
    pub peers:         Vec<PeerInfo>,
    pub peer_profiles: HashMap<NodeId, PeerProfile>,
}

impl Default for PrivatePage {
    fn default() -> Self {
        Self {
            conversations: Vec::new(),
            selected:      0,
            input:         String::new(),
            dm_sender:     None,
            my_enc_kp:     None,
            my_enc_pub:    [0u8; 32],
            my_node_id:    None,
            my_name:       "Вы".into(),
            my_avatar:     None,
            base_port:     7700,
            peers:         Vec::new(),
            peer_profiles: HashMap::new(),
        }
    }
}

// ── Инициализация и загрузка истории ─────────────────────────────────────────

impl PrivatePage {
    /// Загружает историю всех бесед с диска и дешифрует для отображения.
    pub fn load_history_from_disk(&mut self) {
        let Some(kp) = &self.my_enc_kp else { return };

        let stored_convs = crate::private_store::list_convs();
        for sc in stored_convs {
            // Пропускаем уже загруженные
            if self.conversations.iter().any(|c| c.peer_id.as_str() == sc.peer_id) {
                continue;
            }

            let messages = crate::private_store::decrypt_messages(&sc, kp);
            let mut ui_msgs: Vec<UiMessage> = messages
                .into_iter()
                .map(|(ts, text, is_me, msg_id)| UiMessage {
                    message_id: msg_id,
                    text,
                    time: fmt_ts(ts),
                    is_me,
                    delivery: None, // история с диска — без живого статуса
                })
                .collect();
            ui_msgs.sort_by_key(|_| 0i64); // уже отсортированы по timestamp из decrypt_messages

            let last = ui_msgs.last().map(|m| m.text.chars().take(40).collect::<String>())
                .unwrap_or_default();

            self.conversations.push(Conversation {
                peer_id:      NodeId(sc.peer_id),
                peer_name:    sc.peer_name,
                messages:     ui_msgs,
                last_message: last,
                unread:       0,
                scroll_to_bottom: false,
                was_at_bottom:    true,
            });
        }
    }

    /// Открывает (или создаёт) беседу с пиром. Вызывается при нажатии "Начать беседу".
    pub fn open_conversation(&mut self, peer_id: NodeId, peer_name: String) {
        if let Some(idx) = self.conversations.iter().position(|c| c.peer_id == peer_id) {
            self.selected = idx;
            return;
        }
        self.conversations.push(Conversation {
            peer_id,
            peer_name,
            messages:         Vec::new(),
            last_message:     String::new(),
            unread:           0,
            scroll_to_bottom: false,
            was_at_bottom:    true,
        });
        self.selected = self.conversations.len() - 1;
    }

    /// Принимает входящий DM из backend-очереди.
    pub fn receive_dm(&mut self, dm: IncomingDm) {
        // Сохраняем на диск (входящий blob уже зашифрован нашим pubkey)
        crate::private_store::append_msg(
            dm.from.as_str(),
            &dm.from_name,
            crate::private_store::StoredMsg {
                message_id:     dm.message_id.clone(),
                direction:      "in".to_string(),
                encrypted_blob: dm.encrypted_blob.clone(),
                timestamp:      dm.timestamp,
            },
        );

        let time = fmt_ts(dm.timestamp);
        let preview = dm.plaintext.chars().take(40).collect::<String>();

        if let Some(conv) = self.conversations.iter_mut().find(|c| c.peer_id == dm.from) {
            conv.last_message = preview;
            if conv.was_at_bottom {
                conv.scroll_to_bottom = true;
            } else {
                conv.unread += 1;
            }
            // Дедупликация
            if !conv.messages.iter().any(|m| m.message_id == dm.message_id) {
                conv.messages.push(UiMessage {
                    message_id: dm.message_id,
                    text:       dm.plaintext,
                    time,
                    is_me:      false,
                    delivery:   None,
                });
            }
        } else {
            // Новая беседа
            let mut conv = Conversation {
                peer_id:      dm.from.clone(),
                peer_name:    dm.from_name.clone(),
                messages:     Vec::new(),
                last_message: preview,
                unread:       1,
                scroll_to_bottom: true,
                was_at_bottom:    true,
            };
            conv.messages.push(UiMessage {
                message_id: dm.message_id,
                text:       dm.plaintext,
                time,
                is_me:      false,
                delivery:   None,
            });
            self.conversations.push(conv);
        }
    }

    /// Применяет статус доставки к своему сообщению по message_id.
    /// Возвращает `true`, если сообщение найдено (статус можно считать применённым).
    pub fn apply_delivery(&mut self, message_id: &str, state: DeliveryState) -> bool {
        for conv in &mut self.conversations {
            if let Some(m) = conv.messages.iter_mut()
                .find(|m| m.is_me && m.message_id == message_id)
            {
                m.delivery = Some(state);
                return true;
            }
        }
        false
    }

    /// Обновляет имена пиров в беседах если они изменились.
    pub fn update_context(&mut self, peers: Vec<PeerInfo>, profiles: HashMap<NodeId, PeerProfile>) {
        self.peers         = peers;
        self.peer_profiles = profiles;

        // Обновляем имена в беседах
        for conv in &mut self.conversations {
            if let Some(p) = self.peer_profiles.get(&conv.peer_id) {
                if !p.name.is_empty() {
                    conv.peer_name = p.name.clone();
                }
            }
        }
    }
}

// ── Отрисовка ─────────────────────────────────────────────────────────────────

impl PrivatePage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        let line_height          = ui.text_style_height(&egui::TextStyle::Body);
        let max_input_lines      = 4;
        let input_scroll_height  = line_height * max_input_lines as f32 + 12.0;
        let input_area_total     = input_scroll_height + 32.0;
        let header_height        = 60.0;
        let messages_height      = (ui.available_height() - header_height - input_area_total).max(100.0);

        egui::SidePanel::left("private_sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show_inside(ui, |ui| {
                self.show_sidebar(ui);
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.show_chat(ui, messages_height, input_scroll_height);
        });
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("󰌾 Диалоги");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        if self.conversations.is_empty() {
            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Нет диалогов.\nОткрой профиль пира и\nнажми «Начать беседу».")
                        .small()
                        .color(ui.visuals().weak_text_color()),
                );
            });
            return;
        }

        ScrollArea::vertical()
            .id_source("private_sidebar_scroll")
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for i in 0..self.conversations.len() {
                    let is_selected  = self.selected == i;
                    let peer_name    = self.conversations[i].peer_name.clone();
                    let last_msg     = self.conversations[i].last_message.clone();
                    let unread       = self.conversations[i].unread;
                    let peer_id      = self.conversations[i].peer_id.clone();
                    let avatar_b64   = self.peer_profiles.get(&peer_id)
                        .and_then(|p| p.avatar_png.clone());
                    let status       = self.peer_profiles.get(&peer_id)
                        .map(|p| p.status.clone());

                    let frame_fill = if is_selected {
                        ui.visuals().widgets.active.bg_fill
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let frame = Frame::none()
                        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                        .fill(frame_fill);

                    let resp = frame.show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            // Аватар пира (или цветной кружок с буквой, как запасной).
                            let (fill, _) = status_colors(status.as_deref());
                            crate::avatar::show_avatar(ui, avatar_b64.as_deref(), &peer_name, fill, 30.0);

                            ui.add_space(6.0);
                            ui.vertical(|ui| {
                                ui.set_min_width(0.0);
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(&peer_name).strong().size(13.0));
                                    if unread > 0 {
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            ui.label(
                                                egui::RichText::new(format!("{}", unread))
                                                    .small().strong()
                                                    .color(ui.visuals().hyperlink_color),
                                            );
                                        });
                                    }
                                });
                                ui.label(
                                    egui::RichText::new(&last_msg).small()
                                        .color(ui.visuals().weak_text_color()),
                                );
                            });
                        });
                    });

                    let clicked = ui.interact(
                        resp.response.rect,
                        ui.id().with(("conv_click", i)),
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
        if self.conversations.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.label(
                    egui::RichText::new("󰌾  Нет активных диалогов")
                        .size(18.0)
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Нажми на пира в «Общем чате» или «Графе сети»\nи выбери «Начать беседу».")
                        .small()
                        .color(ui.visuals().weak_text_color()),
                );
            });
            return;
        }

        // Ограничиваем selected
        if self.selected >= self.conversations.len() {
            self.selected = 0;
        }

        let selected  = self.selected;
        let peer_name = self.conversations[selected].peer_name.clone();
        let peer_id   = self.conversations[selected].peer_id.clone();
        let peer_avatar = self.peer_profiles.get(&peer_id).and_then(|p| p.avatar_png.clone());
        let peer_status = self.peer_profiles.get(&peer_id).map(|p| p.status.clone());
        let my_avatar   = self.my_avatar.clone();

        // Заголовок: имя + признак шифрования
        ui.horizontal(|ui| {
            ui.heading(format!("󰭹 {}", peer_name));
            ui.add_space(8.0);
            let has_key = self.peer_profiles.get(&peer_id)
                .and_then(|p| p.enc_pubkey.as_ref())
                .is_some();
            if has_key {
                ui.label(
                    egui::RichText::new("󰌾 E2E")
                        .small()
                        .color(egui::Color32::from_rgb(80, 200, 80)),
                );
            } else {
                ui.label(
                    egui::RichText::new("󰔛 ожидание ключа…")
                        .small()
                        .color(ui.visuals().weak_text_color()),
                );
            }
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(12.0);

        // Область сообщений
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
            let scroll_output = ScrollArea::vertical()
                .id_source(format!("private_msgs_{}", selected))
                .max_height(messages_height)
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let len = self.conversations[selected].messages.len();
                    for idx in 0..len {
                        let (text, time, is_me, delivery) = {
                            let m = &self.conversations[selected].messages[idx];
                            (m.text.clone(), m.time.clone(), m.is_me, m.delivery)
                        };
                        let sender = if is_me { self.my_name.clone() } else { peer_name.clone() };
                        let (avatar, fill) = if is_me {
                            (my_avatar.as_deref(), ui.visuals().hyperlink_color)
                        } else {
                            (peer_avatar.as_deref(), status_colors(peer_status.as_deref()).0)
                        };
                        render_message(ui, &text, &time, is_me, &sender, avatar, fill, delivery);
                        ui.add_space(8.0);
                    }

                    if self.conversations[selected].scroll_to_bottom {
                        let r = ui.allocate_response(egui::vec2(0.0, 0.0), egui::Sense::hover());
                        r.scroll_to_me(Some(egui::Align::BOTTOM));
                        self.conversations[selected].scroll_to_bottom = false;
                    }
                });

            let offset    = scroll_output.state.offset.y;
            let viewport  = scroll_output.inner_rect.height();
            let content   = scroll_output.content_size.y;
            self.conversations[selected].was_at_bottom =
                (offset + viewport) >= (content - 75.0);
        }

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // Поле ввода + кнопка
        let line_count  = self.input.lines().count().max(1).min(4);
        let mut should_send = false;

        // Проверяем доступность отправки
        let can_send = self.peer_profiles.get(&peer_id)
            .and_then(|p| p.enc_pubkey.as_ref())
            .is_some()
            && self.peers.iter().any(|p| p.id == peer_id)
            && self.dm_sender.is_some();

        ui.horizontal(|ui| {
            let btn_w   = 100.0;
            let spacing = ui.spacing().item_spacing.x + 20.0;
            let avail_w = ui.available_width() - btn_w - spacing;

            ui.allocate_ui(egui::vec2(avail_w, input_scroll_height), |ui| {
                ScrollArea::vertical()
                    .id_source("private_input_scroll")
                    .max_height(input_scroll_height)
                    .auto_shrink([false; 2])
                    .show(ui, |ui: &mut egui::Ui| {
                        let hint = if can_send {
                            "Введите сообщение… (Enter — отправить)"
                        } else {
                            "Ожидание подключения пира…"
                        };
                        let te = TextEdit::multiline(&mut self.input)
                            .hint_text(hint)
                            .desired_width(avail_w - 8.0)
                            .desired_rows(line_count);

                        let resp = ui.add_enabled(can_send, te);
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
                if ui.add_enabled(can_send, Button::new("󰒊 Отправить").min_size(egui::vec2(btn_w, 36.0))).clicked() {
                    should_send = true;
                }
            });
        });

        if should_send {
            self.send_message();
        }
    }
}

// ── Отправка ─────────────────────────────────────────────────────────────────

impl PrivatePage {
    fn send_message(&mut self) {
        let text = self.input.trim_end_matches('\n').trim().to_string();
        if text.is_empty() { self.input.clear(); return; }

        let selected  = self.selected;
        let peer_id   = self.conversations[selected].peer_id.clone();
        let peer_name = self.conversations[selected].peer_name.clone();

        // Ключ шифрования получателя
        let their_enc_pubkey: Option<[u8; 32]> = self.peer_profiles.get(&peer_id)
            .and_then(|p| p.enc_pubkey.as_ref())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok());

        let their_enc_pubkey = match their_enc_pubkey {
            Some(k) => k,
            None    => return, // кнопка уже задизейблена, но на всякий случай
        };

        // Адрес DM-сервера пира
        let peer_info = self.peers.iter().find(|p| p.id == peer_id).cloned();
        let to_dm_addr = match &peer_info {
            Some(p) => format!("{}:{}", p.ip, p.base_port() + 3),
            None    => return,
        };

        // Уникальный ID сообщения
        let message_id = gen_message_id();
        let now_ts     = chrono::Utc::now().timestamp();

        // Само-шифрование для хранения на диске
        if let Some(kp) = &self.my_enc_kp {
            if let Some(blob) = crate::private_store::self_encrypt(&text, kp) {
                crate::private_store::append_msg(
                    peer_id.as_str(),
                    &peer_name,
                    crate::private_store::StoredMsg {
                        message_id:     message_id.clone(),
                        direction:      "out".to_string(),
                        encrypted_blob: blob,
                        timestamp:      now_ts,
                    },
                );
            }
        }

        // Добавляем в UI сразу (не ждём подтверждения)
        let conv = &mut self.conversations[selected];
        conv.messages.push(UiMessage {
            message_id: message_id.clone(),
            text:       text.clone(),
            time:       chrono::Local::now().format("%H:%M").to_string(),
            is_me:      true,
            delivery:   Some(DeliveryState::Sending),
        });
        conv.last_message = text.chars().take(40).collect();
        if conv.was_at_bottom { conv.scroll_to_bottom = true; }

        // Отправляем через backend
        if let Some(tx) = &self.dm_sender {
            let _ = tx.send(DmSendCmd {
                to:               peer_id,
                to_dm_addr,
                their_enc_pubkey,
                plaintext:        text,
                message_id,
            });
        }

        self.input.clear();
    }
}

// ── Вспомогательная функция для PeerInfo ──────────────────────────────────────

trait PeerInfoExt {
    fn base_port(&self) -> u16;
}
impl PeerInfoExt for PeerInfo {
    fn base_port(&self) -> u16 { self.port }
}

// ── Рендер пузырька ───────────────────────────────────────────────────────────

fn render_message(
    ui: &mut egui::Ui,
    text: &str,
    time: &str,
    is_me: bool,
    sender: &str,
    avatar: Option<&str>,
    avatar_fill: egui::Color32,
    delivery: Option<DeliveryState>,
) {
    let bubble = Frame::group(ui.style())
        .inner_margin(egui::Margin::same(8.0))
        .outer_margin(egui::Margin::symmetric(4.0, 2.0))
        .fill(if is_me {
            ui.visuals().widgets.active.bg_fill
        } else {
            ui.visuals().extreme_bg_color
        });

    ui.horizontal_top(|ui| {
        if is_me { ui.add_space(40.0); }
        if !is_me {
            crate::avatar::show_avatar(ui, avatar, sender, avatar_fill, 28.0);
            ui.add_space(6.0);
        }
        ui.vertical(|ui| {
            bubble.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(sender).strong()
                            .color(if is_me {
                                ui.visuals().strong_text_color()
                            } else {
                                ui.visuals().hyperlink_color
                            }),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(time).small()
                            .color(ui.visuals().weak_text_color()),
                    );
                    // Индикатор доставки — только для своих сообщений.
                    if let Some(state) = delivery {
                        let (glyph, color, hint) = match state {
                            DeliveryState::Sending =>
                                ("󰔟", ui.visuals().weak_text_color(), "Отправляется…"),
                            DeliveryState::Delivered =>
                                ("󰄬", egui::Color32::from_rgb(80, 180, 80), "Доставлено"),
                            DeliveryState::Failed =>
                                ("󰀪", egui::Color32::from_rgb(210, 90, 70), "Не доставлено"),
                        };
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new(glyph).small().color(color))
                            .on_hover_text(hint);
                    }
                });
                ui.add_space(4.0);
                ui.label(text);
            });
        });
        if is_me {
            ui.add_space(6.0);
            crate::avatar::show_avatar(ui, avatar, sender, avatar_fill, 28.0);
        }
        if !is_me { ui.add_space(40.0); }
    });
}

// ── Утилиты ───────────────────────────────────────────────────────────────────

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt: chrono::DateTime<chrono::Utc>| {
            dt.with_timezone(&chrono::Local).format("%H:%M").to_string()
        })
        .unwrap_or_default()
}

fn gen_message_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:016x}{:08x}", chrono::Utc::now().timestamp_millis(), rng.gen::<u32>())
}
