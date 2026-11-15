use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::{Frame, ScrollArea, TextEdit};

use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use void_chat::private_chat::{DmSendCmd, IncomingDm};
use void_crypto::keys::EncryptionKeypair;
use crate::theme;
use crate::widgets::peer_popup::status_colors;
use crate::backend::{DeliveryState, TrustCmd};
use crate::dm_access::DmAccess;

/// Цвет папки «Запросы».
const REQUEST_COLOR: egui::Color32 = theme::WARN;

/// Где беседа: во «Входящих», в «Запросах» или узел заблокирован мной.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Folder {
    Inbox,
    Request,
    Blocked,
}

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
    pub my_name:    String,
    /// Свой аватар (base64-PNG) — для строк собственных сообщений.
    pub my_avatar:  Option<String>,

    // Актуальные данные о пирах (обновляется каждый кадр из app.rs)
    pub peers:         Vec<PeerInfo>,
    pub peer_profiles: HashMap<NodeId, PeerProfile>,

    /// Доступ к личке (разрешённые / заблокированные / запросы) из backend.
    pub access:   Option<Arc<Mutex<DmAccess>>>,
    /// Команды «принять запрос / заблокировать / разблокировать».
    pub trust_tx: Option<tokio::sync::mpsc::UnboundedSender<TrustCmd>>,
}

impl Default for PrivatePage {
    fn default() -> Self {
        Self {
            conversations: Vec::new(),
            selected:      0,
            input:         String::new(),
            dm_sender:     None,
            my_enc_kp:     None,
            my_name:       "Вы".into(),
            my_avatar:     None,
            peers:         Vec::new(),
            peer_profiles: HashMap::new(),
            access:        None,
            trust_tx:      None,
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

    fn folder(&self, id: &NodeId) -> Folder {
        let Some(access) = &self.access else { return Folder::Inbox };
        let access = access.lock().unwrap();
        if access.blocked.contains(id.as_str()) {
            Folder::Blocked
        } else if access.is_request(id.as_str()) {
            Folder::Request
        } else {
            Folder::Inbox
        }
    }

    fn send_trust(&self, cmd: TrustCmd) {
        if let Some(tx) = &self.trust_tx {
            let _ = tx.send(cmd);
        }
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
        let input_scroll_height  = line_height * max_input_lines as f32 + 16.0;

        egui::SidePanel::left("private_sidebar")
            .resizable(false)
            .exact_width(210.0)
            .frame(Frame::none().inner_margin(egui::Margin { left: 0.0, right: 12.0, top: 0.0, bottom: 0.0 }))
            .show_inside(ui, |ui| {
                self.show_sidebar(ui);
            });

        egui::CentralPanel::default()
            .frame(Frame::none().inner_margin(egui::Margin { left: 16.0, right: 0.0, top: 0.0, bottom: 0.0 }))
            .show_inside(ui, |ui| {
                self.show_chat(ui, input_scroll_height);
            });
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        theme::page_header(ui, "\u{F033E}", "Диалоги", None);

        // Заблокированные мной в списке не показываем.
        let folders: Vec<Folder> = self.conversations.iter().map(|c| self.folder(&c.peer_id)).collect();
        if folders.iter().all(|f| *f == Folder::Blocked) {
            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Нет диалогов.\nОткройте профиль узла\nи нажмите «Начать беседу».")
                        .small()
                        .color(theme::TEXT_DIM),
                );
            });
            return;
        }

        ScrollArea::vertical()
            .id_source("private_sidebar_scroll")
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for i in (0..folders.len()).filter(|i| folders[*i] == Folder::Inbox) {
                    self.conv_row(ui, i);
                }
                let requests: Vec<usize> =
                    (0..folders.len()).filter(|i| folders[*i] == Folder::Request).collect();
                if !requests.is_empty() {
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(format!("\u{F02FC}  Запросы ({})", requests.len()))
                            .strong()
                            .color(REQUEST_COLOR),
                    );
                    ui.label(
                        egui::RichText::new("От тех, кто не в вашей сети доверия.")
                            .small()
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(4.0);
                    for i in requests {
                        self.conv_row(ui, i);
                    }
                }
            });
    }

    /// Строка беседы в списке слева.
    fn conv_row(&mut self, ui: &mut egui::Ui, i: usize) {
        let is_selected  = self.selected == i;
        let peer_name    = self.conversations[i].peer_name.clone();
        let last_msg     = self.conversations[i].last_message.clone();
        let unread       = self.conversations[i].unread;
        let peer_id      = self.conversations[i].peer_id.clone();
        let avatar_b64   = self.peer_profiles.get(&peer_id)
            .and_then(|p| p.avatar_png.clone());
        let status       = self.peer_profiles.get(&peer_id)
            .map(|p| p.status.clone());

        // Наведение берём из прошлого кадра: размер строки к этому моменту неизвестен.
        let hover_id = ui.id().with(("conv_click", i));
        let hovered = ui.ctx().read_response(hover_id).is_some_and(|r| r.hovered());
        let frame_fill = if is_selected {
            theme::SURFACE_3
        } else if hovered {
            theme::SURFACE_2
        } else {
            egui::Color32::TRANSPARENT
        };

        let frame = Frame::none()
            .inner_margin(egui::Margin::symmetric(10.0, 7.0))
            .rounding(egui::Rounding::same(theme::R_WIDGET))
            .fill(frame_fill);

        let resp = frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                // Аватар пира (или цветной кружок с буквой, как запасной).
                let corner = ui.cursor().min + egui::vec2(28.0, 28.0);
                crate::avatar::show_avatar(ui, avatar_b64.as_deref(), &peer_name, theme::SURFACE_3, 32.0);
                ui.painter().circle(
                    corner, 4.5, status_colors(status.as_deref()).1,
                    egui::Stroke::new(2.0_f32, if is_selected { theme::SURFACE_3 } else { theme::BG }),
                );

                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.set_min_width(0.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(&peer_name)
                                .font(egui::FontId::new(13.5, theme::semibold()))
                                .color(theme::TEXT_STRONG),
                        );
                        if unread > 0 {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                // Счётчик непрочитанных — белая «таблетка».
                                egui::Frame::none()
                                    .fill(theme::ACCENT)
                                    .rounding(egui::Rounding::same(9.0))
                                    .inner_margin(egui::Margin::symmetric(6.0, 1.0))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new(unread.to_string()).size(11.0).color(theme::BG));
                                    });
                            });
                        }
                    });
                    ui.add(
                        egui::Label::new(egui::RichText::new(&last_msg).size(12.0).color(theme::TEXT_DIM))
                            .truncate(true),
                    );
                });
            });
        });

        let clicked = ui.interact(resp.response.rect, hover_id, egui::Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked();

        if clicked {
            self.selected = i;
            self.conversations[i].unread = 0;
            self.input.clear();
        }

        ui.add_space(2.0);
    }

    fn show_chat(&mut self, ui: &mut egui::Ui, input_scroll_height: f32) {
        if self.conversations.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() / 2.0 - 60.0).max(20.0));
                ui.label(egui::RichText::new("\u{F033E}").size(34.0).color(theme::TEXT_FAINT));
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new("Нет активных диалогов")
                        .font(egui::FontId::new(16.0, theme::semibold()))
                        .color(theme::TEXT_DIM),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("Нажмите на узел в «Общем чате» или «Графе сети»\nи выберите «Начать беседу».")
                        .small()
                        .color(theme::TEXT_FAINT),
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
        let my_avatar   = self.my_avatar.clone();
        let folder      = self.folder(&peer_id);
        let has_incoming = self.conversations[selected].messages.iter().any(|m| !m.is_me);

        // Заголовок: аватар, имя, признак шифрования.
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            crate::avatar::show_avatar(ui, peer_avatar.as_deref(), &peer_name, theme::SURFACE_3, 30.0);
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(&peer_name)
                    .font(egui::FontId::new(18.0, theme::semibold()))
                    .color(theme::TEXT_STRONG),
            );
            ui.add_space(6.0);
            let has_key = self.peer_profiles.get(&peer_id)
                .and_then(|p| p.enc_pubkey.as_ref())
                .is_some();
            if has_key {
                theme::status_pill(ui, theme::OK, "\u{F033E} E2E")
                    .on_hover_text("Сообщения шифруются сквозным шифрованием: прочитать их может только собеседник");
            } else {
                theme::status_pill(ui, theme::TEXT_FAINT, "ожидание ключа…");
            }
        });
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // Запрос от незнакомца или заблокированный узел: решение — над перепиской.
        match folder {
            Folder::Request => {
                theme::notice(
                    ui, REQUEST_COLOR, "\u{F02FC}",
                    "Запрос от узла вне вашей сети доверия. Примите — его сообщения пойдут во \
                     «Входящие» и вы сможете ответить. Отклоните — узел будет заблокирован.",
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary_button("\u{F012C}  Принять")).clicked() {
                        self.send_trust(TrustCmd::Allow(peer_id.clone()));
                    }
                    if ui.button("\u{F0156}  Отклонить").clicked() {
                        self.send_trust(TrustCmd::Block(peer_id.clone()));
                    }
                });
                ui.add_space(8.0);
            }
            Folder::Blocked => {
                theme::notice(
                    ui, theme::ERR, "\u{F00AD}",
                    "Вы заблокировали этот узел: его личные сообщения и сообщения в общем чате \
                     не показываются.",
                );
                ui.add_space(6.0);
                if ui.button("Разблокировать").clicked() {
                    self.send_trust(TrustCmd::Unblock(peer_id.clone()));
                }
                ui.add_space(8.0);
            }
            Folder::Inbox if !has_incoming => {
                theme::notice(
                    ui, REQUEST_COLOR, "\u{F02FC}",
                    "Собеседник вам ещё не писал. Если вы для него незнакомец, сообщения лягут к \
                     нему в «Запросы»: он увидит первые 5 и решит, принять ли. Пока он не ответил, \
                     к сообщениям прикладывается «марка работы» — первое за день уходит на \
                     несколько секунд дольше.",
                );
                ui.add_space(8.0);
            }
            Folder::Inbox => {}
        }

        // Проверяем доступность отправки
        let can_send = self.peer_profiles.get(&peer_id)
            .and_then(|p| p.enc_pubkey.as_ref())
            .is_some()
            && self.peers.iter().any(|p| p.id == peer_id)
            && self.dm_sender.is_some()
            && folder == Folder::Inbox;

        // Поле ввода закреплено внизу; высоту переписки ограничиваем до него сами
        // (виджеты сверху-вниз панель внизу не учитывают).
        let mut should_send = false;
        let input_panel = egui::TopBottomPanel::bottom("private_input_panel")
            .frame(Frame::none())
            .show_separator_line(false)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.add_space(10.0);
                self.input_row(ui, input_scroll_height, folder, can_send, &mut should_send);
                ui.add_space(2.0);
            });
        let messages_height = (input_panel.response.rect.min.y - ui.cursor().min.y).max(0.0);

        // Область сообщений
        if self.conversations[selected].messages.is_empty() {
            ui.allocate_ui(egui::vec2(ui.available_width(), messages_height), |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Нет сообщений. Начните диалог!")
                            .color(theme::TEXT_DIM),
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
                    let mut own = 0u32;
                    for idx in 0..len {
                        let (text, time, is_me, delivery) = {
                            let m = &self.conversations[selected].messages[idx];
                            (m.text.clone(), m.time.clone(), m.is_me, m.delivery)
                        };
                        // Без ответа собеседника мы, возможно, у него в «Запросах»:
                        // сверх их лимита сообщения отбрасываются.
                        own += u32::from(is_me);
                        let status = MsgStatus {
                            delivery,
                            may_drop: is_me && !has_incoming && own > crate::dm_access::MAX_REQUEST_MSGS,
                        };
                        let sender = if is_me { self.my_name.clone() } else { peer_name.clone() };
                        let avatar = if is_me { my_avatar.as_deref() } else { peer_avatar.as_deref() };
                        let fill = theme::SURFACE_3;
                        render_message(ui, &text, &time, is_me, &sender, avatar, fill, status);
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

        if should_send {
            self.send_message();
        }
    }

    /// Строка ввода: поле (растёт до 4 строк) и главная кнопка «Отправить».
    fn input_row(&mut self, ui: &mut egui::Ui, max_h: f32, folder: Folder, can_send: bool, should_send: &mut bool) {
        let line_count = self.input.lines().count().clamp(1, 4);
        ui.horizontal(|ui| {
            let btn_w = 118.0;
            let field_w = ui.available_width() - btn_w - ui.spacing().item_spacing.x;
            ScrollArea::vertical()
                .id_source("private_input_scroll")
                .max_height(max_h)
                .max_width(field_w)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    let hint = match folder {
                        Folder::Request => "Примите запрос, чтобы ответить",
                        Folder::Blocked => "Узел заблокирован",
                        Folder::Inbox if can_send => "Сообщение…",
                        Folder::Inbox => "Собеседник не в сети…",
                    };
                    let te = TextEdit::multiline(&mut self.input)
                        .hint_text(hint)
                        .desired_width(field_w)
                        .desired_rows(line_count)
                        .margin(egui::vec2(10.0, 8.0));
                    let resp = ui.add_enabled(can_send, te);
                    if resp.has_focus() {
                        let (enter, shift) = ui.input(|i| (i.key_pressed(egui::Key::Enter), i.modifiers.shift));
                        if enter && !shift {
                            if self.input.ends_with('\n') { self.input.pop(); }
                            *should_send = true;
                        }
                    }
                });
            let send = theme::primary_button("\u{F048A}  Отправить").min_size(egui::vec2(btn_w, 36.0));
            if ui.add_enabled(can_send && !self.input.trim().is_empty(), send).clicked() {
                *should_send = true;
            }
        });
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

        // Пока собеседник нам не писал, он может нас не знать: прикладываем марку
        // работы (без неё незнакомец отбросит сообщение).
        let stamp = !self.conversations[selected].messages.iter().any(|m| !m.is_me);

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
                stamp,
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

/// Статус своего сообщения.
#[derive(Clone, Copy)]
struct MsgStatus {
    /// Доставка до узла собеседника (`None` — входящее или из истории).
    delivery: Option<DeliveryState>,
    /// Сверх лимита запроса у собеседника — скорее всего, отброшено.
    may_drop: bool,
}

#[allow(clippy::too_many_arguments)]
fn render_message(
    ui: &mut egui::Ui,
    text: &str,
    time: &str,
    is_me: bool,
    sender: &str,
    avatar: Option<&str>,
    avatar_fill: egui::Color32,
    status: MsgStatus,
) {
    let MsgStatus { delivery, may_drop } = status;
    let bubble = Frame::none()
        .fill(if is_me { theme::SURFACE_3 } else { theme::SURFACE })
        .stroke(if is_me { egui::Stroke::NONE } else { egui::Stroke::new(1.0_f32, theme::BORDER) })
        .rounding(egui::Rounding::same(theme::R_CARD))
        .inner_margin(egui::Margin::symmetric(12.0, 8.0));

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
                        egui::RichText::new(sender)
                            .font(egui::FontId::new(13.5, theme::semibold()))
                            .color(theme::TEXT_STRONG),
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
                                ("󰄬", theme::OK, "Доставлено на узел собеседника"),
                            DeliveryState::Failed =>
                                ("󰀪", theme::ERR, "Не доставлено"),
                        };
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new(glyph).small().color(color))
                            .on_hover_text(hint);
                    }
                    if may_drop {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("\u{F0026}").small().color(REQUEST_COLOR))
                            .on_hover_text("Скорее всего, не дошло: если вы у собеседника в «Запросах», \
                                            он увидит только первые 5 сообщений, пока не примет запрос.");
                    }
                });
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
