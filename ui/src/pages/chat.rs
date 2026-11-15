use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use eframe::egui;
use egui::{Frame, ScrollArea, TextEdit};
use void_chat::trust_limits::NEWCOMERS_CHANNEL;
use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use void_trust::TrustLevel;
use crate::theme;
use crate::widgets::peer_popup::{status_colors, show_peer_profile};

/// Каналы («доски») общего чата: (id, иконка Nerd Font, название).
/// `id` хранится в каждом сообщении и в БД; глобальный канал — "global".
pub const CHANNELS: &[(&str, &str, &str)] = &[
    ("global", "\u{F01E7}", "Глобальный"),
    (NEWCOMERS_CHANNEL, "\u{F0014}", "Новички"),
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
    /// Номер сообщения у автора (вместе с `from_id` — ключ сообщения).
    pub seq:     u64,
    /// Своё сообщение сверх лимита новичка: узлы, которые нас не знают, его,
    /// скорее всего, отбросили.
    pub may_drop: bool,
}

/// Свой темп в канале глазами узлов, которые нас не знают: зеркало их лимита
/// для незнакомцев (запас и момент последнего пересчёта).
struct OwnPace {
    tokens: f64,
    last:   std::time::Instant,
}

/// Метка сообщения незнакомца.
const NEWCOMER_COLOR: egui::Color32 = theme::WARN;
/// Метка сообщения узла под жалобами.
const REPORTED_COLOR: egui::Color32 = egui::Color32::from_rgb(0xE0, 0x86, 0x4E);

/// Как показать сообщение (по доверию к автору).
#[derive(Default, Clone, Copy)]
struct MsgMarks {
    /// Автор незнакомец — метка «новичок».
    newcomer: bool,
    /// Под жалобами моей сети — метка и сворачивание.
    reported: bool,
    /// Показать «поприветствовать» (я встречающий, канал «Новички»).
    greet: bool,
    /// Можно свернуть: `Some(true)` свёрнуто, `Some(false)` развёрнуто.
    fold: Option<bool>,
}

/// Что нажато в строке сообщения.
#[derive(Default)]
struct MsgClick {
    /// Имя автора → профиль.
    author: Option<NodeId>,
    /// «Показать» / «Свернуть» сообщение незнакомца.
    toggle_fold: bool,
    /// «Поприветствовать» автора.
    greet: bool,
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
    /// Снимок жалоб на узлы из backend (для показа в профиле).
    pub reports: Option<Arc<Mutex<crate::backend::ReportsMap>>>,
    /// Снимок блок-листа (забаненные голосованием): NodeId → ts истечения.
    pub blocklist: Option<Arc<Mutex<HashMap<NodeId, i64>>>>,
    /// Каналы, добавленные голосованием (мерджатся со встроенными `CHANNELS`).
    pub voted_channels: Option<Arc<Mutex<Vec<crate::vote_service::ChannelDef>>>>,
    /// Сигнал в VoidApp: пожаловаться на узел (target, причина).
    pub pending_report: Option<(NodeId, void_reputation::ReportReason)>,
    /// Сеть доверия: уровни узлов и команды «поручиться/отозвать».
    pub trust: Option<crate::trust_ui::TrustUi>,
    /// Наш NodeId (hex) — для расчёта кода безопасности (safety number).
    pub my_id_hex: String,
    /// Сворачивать сообщения незнакомцев (настройка).
    pub fold_strangers: bool,
    /// Развёрнутые вручную сообщения незнакомцев: (автор, seq).
    expanded: HashSet<(NodeId, u64)>,
    /// Сколько узлов поручились за нас (0 — показываем подсказку новичку).
    pub my_vouchers: Option<Arc<AtomicUsize>>,
    /// Сколько живых связей у чата (0 — сообщения пока никуда не уходят).
    pub chat_links: Option<Arc<AtomicUsize>>,
    /// Свой темп для лимита новичка: ключ — канал «Новички» или остальные.
    pace: HashMap<bool, OwnPace>,
    /// Почему сообщение не отправлено (слишком длинное).
    send_error: Option<String>,
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
            reports:          None,
            blocklist:        None,
            voted_channels:   None,
            pending_report:   None,
            trust:            None,
            my_id_hex:        String::new(),
            fold_strangers:   false,
            expanded:         HashSet::new(),
            my_vouchers:      None,
            chat_links:       None,
            pace:             HashMap::new(),
            send_error:       None,
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

    /// Жалобы на узел из снимка backend.
    fn peer_reports(&self, id: &NodeId) -> Vec<void_db::peers::ReportRow> {
        self.reports.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).cloned()))
            .unwrap_or_default()
    }

    /// Забанен ли узел голосованием (бан не истёк).
    fn is_banned(&self, id: &NodeId) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.blocklist.as_ref()
            .and_then(|m| m.lock().ok().and_then(|m| m.get(id).copied()))
            .is_some_and(|until| until > now)
    }

    /// За нас никто не поручился — для других узлов мы незнакомец.
    fn is_newcomer(&self) -> bool {
        self.my_vouchers.as_ref().is_some_and(|n| n.load(Ordering::Relaxed) == 0)
    }

    /// Запас нашего лимита новичка в канале на этот момент.
    fn pace_tokens(&self, channel: &str) -> f64 {
        let (rate, burst) = void_chat::trust_limits::stranger_message_rate(channel);
        self.pace
            .get(&(channel == NEWCOMERS_CHANNEL))
            .map_or(burst, |p| (p.tokens + p.last.elapsed().as_secs_f64() * rate).min(burst))
    }

    /// Через сколько секунд следующее сообщение пройдёт лимит новичка.
    fn pace_wait_secs(&self, channel: &str) -> u64 {
        let (rate, _) = void_chat::trust_limits::stranger_message_rate(channel);
        let tokens = self.pace_tokens(channel);
        if tokens >= 1.0 { 0 } else { ((1.0 - tokens) / rate).ceil() as u64 }
    }

    /// Списывает сообщение с лимита новичка; `false` — его, скорее всего, отбросят.
    fn take_pace(&mut self, channel: &str) -> bool {
        let tokens = self.pace_tokens(channel);
        let ok = tokens >= 1.0;
        self.pace.insert(
            channel == NEWCOMERS_CHANNEL,
            OwnPace { tokens: if ok { tokens - 1.0 } else { tokens }, last: std::time::Instant::now() },
        );
        ok
    }

    /// Подсказка под полем ввода: почему сообщение может не дойти.
    fn input_note(&self) -> Option<(String, egui::Color32)> {
        if let Some(e) = &self.send_error {
            return Some((e.clone(), theme::ERR));
        }
        if self.chat_links.as_ref().is_some_and(|n| n.load(Ordering::Relaxed) == 0) {
            return Some((
                "\u{F0026}  Нет связи с другими узлами — сообщения увидят, когда связь появится.".into(),
                NEWCOMER_COLOR,
            ));
        }
        if self.is_newcomer() {
            let wait = self.pace_wait_secs(&self.current_channel);
            if wait > 0 {
                return Some((
                    format!("\u{F0026}  Следующее сообщение дойдёт до узлов, которые вас не знают, через {wait} с."),
                    NEWCOMER_COLOR,
                ));
            }
        }
        None
    }

    /// Полный список каналов: встроенные + добавленные голосованием (дедуп по id).
    fn all_channels(&self) -> Vec<(String, String, String)> {
        let mut out: Vec<(String, String, String)> = CHANNELS
            .iter()
            .map(|(id, icon, name)| (id.to_string(), icon.to_string(), name.to_string()))
            .collect();
        if let Some(shared) = &self.voted_channels {
            if let Ok(list) = shared.lock() {
                for c in list.iter() {
                    if !out.iter().any(|(id, _, _)| *id == c.id) {
                        out.push((c.id.clone(), c.icon.clone(), c.name.clone()));
                    }
                }
            }
        }
        out
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
            reports:          None,
            blocklist:        None,
            voted_channels:   None,
            pending_report:   None,
            trust:            None,
            my_id_hex:        String::new(),
            fold_strangers:   false,
            expanded:         HashSet::new(),
            my_vouchers:      None,
            chat_links:       None,
            pace:             HashMap::new(),
            send_error:       None,
        }
    }
}

impl ChatPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        // Profile popup — shown from cache even if peer is offline
        let mut close_popup = false;
        let mut start_dm_id: Option<NodeId> = None;
        let mut report_reason: Option<void_reputation::ReportReason> = None;
        let mut vouch_action: Option<crate::widgets::peer_popup::VouchAction> = None;
        let mut block_action: Option<bool> = None;
        if let Some(sel_id) = self.selected.clone() {
            let peer    = self.peers.iter().find(|p| p.id == sel_id).cloned();
            let profile = self.profiles.get(&sel_id).cloned();

            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                close_popup = true;
            }
            if peer.is_some() || profile.is_some() {
                egui::Window::new("Профиль участника")
                    .id(egui::Id::new("chat_peer_profile_popup"))
                    .collapsible(false)
                    .resizable(false)
                    .vscroll(true) // профиль выше окна приложения — иначе кнопки внизу недоступны
                    .max_height(crate::theme::max_window_height(ui.ctx()))
                    .default_width(320.0)
                    .show(ui.ctx(), |ui| {
                        let rep = self.peer_score(&sel_id);
                        let reports = self.peer_reports(&sel_id);
                        let banned = self.is_banned(&sel_id);
                        let trust = self.trust.as_ref().map(|t| t.view(&sel_id, &self.profiles));
                        let action = show_peer_profile(
                            ui, peer.as_ref(), profile.as_ref(), rep, &reports, banned,
                            &self.my_id_hex, trust.as_ref(),
                        );
                        ui.add_space(6.0);
                        if action.start_dm {
                            start_dm_id = Some(sel_id.clone());
                            close_popup = true;
                        }
                        if let Some(reason) = action.report {
                            report_reason = Some(reason);
                            close_popup = true;
                        }
                        if action.vouch.is_some() {
                            vouch_action = action.vouch; // не закрываем попап — видно смену бейджа
                        }
                        if action.block.is_some() {
                            block_action = action.block;
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
            if let (Some(action), Some(trust)) = (vouch_action, &self.trust) {
                use crate::widgets::peer_popup::VouchAction;
                trust.send(match action {
                    VouchAction::Vouch  => crate::backend::TrustCmd::Vouch(sel_id.clone()),
                    VouchAction::Revoke => crate::backend::TrustCmd::Revoke(sel_id.clone()),
                    VouchAction::Greet  => crate::backend::TrustCmd::Greet(sel_id.clone()),
                });
            }
            if let (Some(block), Some(trust)) = (block_action, &self.trust) {
                trust.send(if block {
                    crate::backend::TrustCmd::Block(sel_id.clone())
                } else {
                    crate::backend::TrustCmd::Unblock(sel_id.clone())
                });
            }
        }
        if close_popup { self.selected = None; }
        if let Some(id) = start_dm_id {
            self.pending_dm = Some(id);
        }

        let line_height        = ui.text_style_height(&egui::TextStyle::Body);
        let max_input_lines    = 4;
        let input_scroll_h     = line_height * max_input_lines as f32 + 16.0;
        // Заголовок = текущий канал («доска»). Имя ищем и среди проголосованных.
        let (ch_icon, ch_name) = self
            .all_channels()
            .into_iter()
            .find(|(id, _, _)| *id == self.current_channel)
            .map(|(_, icon, name)| (icon, name))
            .unwrap_or_else(|| {
                let (i, n) = channel_meta(&self.current_channel);
                (i.to_string(), n)
            });
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&ch_icon).size(20.0).color(theme::TEXT_DIM));
            ui.label(
                egui::RichText::new(&ch_name)
                    .font(egui::FontId::new(20.0, theme::semibold()))
                    .color(theme::TEXT_STRONG),
            );
            ui.label(egui::RichText::new("· общий чат").color(theme::TEXT_DIM));
        });
        ui.add_space(8.0);

        // Панель каналов («доски» в духе форчана): встроенные + добавленные
        // голосованием.
        let channels = self.all_channels();
        ui.horizontal_wrapped(|ui| {
            for (id, icon, name) in &channels {
                let selected = self.current_channel == *id;
                if ui
                    .selectable_label(selected, format!("{} {}", icon, name))
                    .clicked()
                {
                    self.current_channel = id.clone();
                    self.scroll_to_bottom = true;
                }
            }
        });
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);

        if self.current_channel == NEWCOMERS_CHANNEL {
            ui.label(
                egui::RichText::new(
                    "Канал для знакомства: здесь пишут и те, за кого ещё никто не поручился.")
                    .small().color(theme::TEXT_DIM),
            );
            ui.add_space(4.0);
        } else if self.my_vouchers.as_ref().is_some_and(|n| n.load(Ordering::Relaxed) == 0) {
            theme::notice(
                ui,
                NEWCOMER_COLOR,
                "\u{F02FC}",
                "За вас ещё никто не поручился, поэтому другие узлы пропускают ваши сообщения \
                 в этот канал не чаще раза в 30 секунд. В канале «Новички» такого лимита нет. \
                 Чтобы его снять, сверьте код безопасности со знакомым и попросите его \
                 поручиться за вас.",
            );
            ui.add_space(6.0);
        }

        // Высоту области сообщений считаем здесь — после панели каналов, чтобы
        // учесть её фактическую высоту (она может переноситься на пару строк).
        let input_note = self.input_note();
        if input_note.is_some() {
            // Обратный отсчёт до следующего сообщения — обновляем раз в секунду.
            ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
        }
        // Поле ввода закреплено внизу, сообщения занимают остальное место — при
        // любой высоте окна ничего не вылезает за край страницы.
        let mut should_send = false;
        let input_panel = egui::TopBottomPanel::bottom("chat_input_panel")
            .frame(Frame::none())
            .show_separator_line(false)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.add_space(10.0);
                if let Some((note, color)) = &input_note {
                    ui.label(egui::RichText::new(note).small().color(*color));
                    ui.add_space(6.0);
                }
                self.input_row(ui, input_scroll_h, &mut should_send);
                ui.add_space(2.0);
            });
        // Панель сдвигает только курсор, а виджеты сверху-вниз смотрят на нижний
        // край всей области — высоту сообщений ограничиваем сами.
        let messages_h = (input_panel.response.rect.min.y - ui.cursor().min.y).max(0.0);

        // Есть ли сообщения в текущем канале (для заглушки пустого состояния).
        let channel_has_msgs = self.messages.iter().any(|m| m.channel == self.current_channel);

        // Collect click result outside scroll closure to avoid borrow conflict
        let mut clicked_id: Option<NodeId> = None;
        let mut toggled: Option<(NodeId, u64)> = None;
        let mut greet: Option<NodeId> = None;
        let greeter = self.current_channel == NEWCOMERS_CHANNEL
            && self.trust.as_ref().is_some_and(|t| t.is_greeter());
        // Уровни авторов канала: незнакомцы — с меткой «новичок», заблокированные
        // (мной или голосованием) не показываются. Снимок доверия блокируем
        // коротко: его же читает чат, решая о лимитах.
        // Под жалобами моей сети — свёрнуты всегда, независимо от настройки.
        let levels: HashMap<NodeId, (TrustLevel, bool)> = self.trust.as_ref()
            .and_then(|t| t.map.lock().ok())
            .map(|map| {
                self.messages.iter()
                    .filter(|m| m.channel == self.current_channel && !m.is_me)
                    .filter_map(|m| m.from_id.as_ref())
                    .map(|id| {
                        let info = map.get(id);
                        (id.clone(), (info.level, info.reported))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let level_of = |m: &ChatMessage| m.from_id.as_ref().and_then(|id| levels.get(id)).map(|l| l.0);
        let reported = |m: &ChatMessage| m.from_id.as_ref().and_then(|id| levels.get(id)).is_some_and(|l| l.1);

        // Отступ заглушки пустого канала — до середины области сообщений.
        let empty_pad = (messages_h / 2.0 - 30.0).max(0.0);
        let scroll_out = ScrollArea::vertical()
            .id_source("chat_messages_scroll")
            .max_height(messages_h)
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if !channel_has_msgs {
                    ui.add_space(empty_pad);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "В канале «{}» пока нет сообщений.", ch_name))
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                }

                for msg in self.messages.iter().filter(|m| m.channel == self.current_channel) {
                    if level_of(msg) == Some(TrustLevel::Blocked) {
                        continue;
                    }
                    let newcomer = level_of(msg) == Some(TrustLevel::Stranger);
                    let key = msg.from_id.clone().map(|id| (id, msg.seq));
                    let marks = MsgMarks {
                        newcomer,
                        reported: reported(msg),
                        greet: greeter && newcomer && !reported(msg),
                        fold: ((newcomer && self.fold_strangers) || reported(msg))
                            .then(|| !key.as_ref().is_some_and(|k| self.expanded.contains(k))),
                    };
                    let click = Self::render_message(ui, msg, &self.profiles, self.my_avatar.as_deref(), marks);
                    if click.greet {
                        greet = msg.from_id.clone();
                    }
                    if click.author.is_some() {
                        clicked_id = click.author;
                    }
                    if click.toggle_fold {
                        toggled = key;
                    }
                    ui.add_space(8.0);
                }

                if self.scroll_to_bottom {
                    let r = ui.allocate_response(egui::vec2(0.0, 0.0), egui::Sense::hover());
                    r.scroll_to_me(Some(egui::Align::BOTTOM));
                    self.scroll_to_bottom = false;
                }
            });

        if let (Some(id), Some(trust)) = (greet, &self.trust) {
            trust.send(crate::backend::TrustCmd::Greet(id));
        }
        if let Some(key) = toggled {
            if !self.expanded.remove(&key) {
                self.expanded.insert(key);
            }
        }
        // Apply click after scroll area finishes (avoids borrow conflict)
        if let Some(id) = clicked_id {
            self.selected = if self.selected.as_ref() == Some(&id) { None } else { Some(id) };
        }

        let scroll_offset  = scroll_out.state.offset.y;
        let viewport_h     = scroll_out.inner_rect.height();
        let content_h      = scroll_out.content_size.y;
        self.was_at_bottom = (scroll_offset + viewport_h) >= (content_h - 50.0);

        if should_send { self.send_message(); }
    }

    /// Строка ввода: многострочное поле (растёт до 4 строк, дальше прокрутка)
    /// и главная кнопка «Отправить». Enter отправляет, Shift+Enter — перенос.
    fn input_row(&mut self, ui: &mut egui::Ui, max_h: f32, should_send: &mut bool) {
        let line_count = self.input.lines().count().clamp(1, 4);
        ui.horizontal(|ui| {
            let btn_w = 118.0;
            let field_w = ui.available_width() - btn_w - ui.spacing().item_spacing.x;
            ScrollArea::vertical()
                .id_source("input_scroll")
                .max_height(max_h)
                .max_width(field_w)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    let resp = ui.add(
                        TextEdit::multiline(&mut self.input)
                            .hint_text("Сообщение…")
                            .desired_width(field_w)
                            .desired_rows(line_count)
                            .margin(egui::vec2(10.0, 8.0)),
                    );
                    if resp.has_focus() {
                        let (enter, shift) = ui.input(|i| (i.key_pressed(egui::Key::Enter), i.modifiers.shift));
                        if enter && !shift {
                            if self.input.ends_with('\n') { self.input.pop(); }
                            *should_send = true;
                        }
                    }
                });
            let send = theme::primary_button("\u{F048A}  Отправить").min_size(egui::vec2(btn_w, 36.0));
            if ui.add_enabled(!self.input.trim().is_empty(), send).clicked() {
                *should_send = true;
            }
        });
    }

    fn render_message(
        ui: &mut egui::Ui,
        msg: &ChatMessage,
        profiles: &HashMap<NodeId, PeerProfile>,
        my_avatar: Option<&str>,
        marks: MsgMarks,
    ) -> MsgClick {
        let MsgMarks { newcomer, reported, greet, fold } = marks;
        let mut click = MsgClick::default();

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
        // Монохром: имена и аватары нейтральные, статус автора — точка у аватара.
        let name_color = theme::TEXT_STRONG;
        let bubble = Frame::none()
            .fill(if msg.is_me { theme::SURFACE_3 } else { theme::SURFACE })
            .stroke(if msg.is_me { egui::Stroke::NONE } else { egui::Stroke::new(1.0_f32, theme::BORDER) })
            .rounding(egui::Rounding::same(theme::R_CARD))
            .inner_margin(egui::Margin::symmetric(12.0, 8.0));

        ui.horizontal_top(|ui| {
            const AVATAR: f32 = 30.0;
            let corner = ui.cursor().min + egui::vec2(AVATAR - 4.0, AVATAR - 4.0);
            crate::avatar::show_avatar(ui, avatar_b64, &display_name, theme::SURFACE_3, AVATAR);
            if !msg.is_me {
                ui.painter().circle(corner, 4.5, status_colors(status).1, egui::Stroke::new(2.0_f32, theme::BG));
            }
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.set_max_width(ui.available_width() * 0.88);
                bubble.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if !msg.is_me {
                            // Clickable author name → triggers profile popup
                            let resp = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&display_name)
                                        .font(egui::FontId::new(13.5, theme::semibold()))
                                        .color(name_color)
                                )
                                .sense(egui::Sense::click())
                            );
                            if resp.clicked() {
                                click.author = msg.from_id.clone();
                            }
                            if resp.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                            }
                            resp.on_hover_text("Нажмите, чтобы посмотреть профиль");
                        } else {
                            ui.label(
                                egui::RichText::new(&display_name)
                                    .font(egui::FontId::new(13.5, theme::semibold()))
                                    .color(name_color)
                            );
                        }

                        if reported {
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("под жалобами").small().color(REPORTED_COLOR))
                                .on_hover_text("На этот узел пожаловались вы или те, кому вы доверяете");
                        } else if newcomer {
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("новичок").small().color(NEWCOMER_COLOR))
                                .on_hover_text("Никто из вашей сети доверия не поручился за этот узел");
                        }

                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(&msg.time)
                                .small()
                                .color(ui.visuals().weak_text_color()),
                        );
                        if msg.may_drop {
                            ui.label(egui::RichText::new("\u{F0026}").small().color(NEWCOMER_COLOR))
                                .on_hover_text("Скорее всего, не дошло до узлов, которые вас не знают: \
                                                от новичка они пропускают одно сообщение в 30 секунд \
                                                (в «Новичках» — раз в 2 секунды). Узлы, которые вам \
                                                доверяют, его получили.");
                        }
                        if greet {
                            ui.add_space(8.0);
                            let hi = egui::RichText::new("\u{F1821} поприветствовать")
                                .small()
                                .color(ui.visuals().hyperlink_color);
                            let resp = ui.add(egui::Label::new(hi).sense(egui::Sense::click()))
                                .on_hover_text("Слабое публичное поручительство: «похож на живого \
                                                человека». Для вас он станет освоившимся.");
                            if resp.clicked() {
                                click.greet = true;
                            }
                        }
                        if fold == Some(false) {
                            ui.add_space(8.0);
                            let hide = egui::RichText::new("свернуть")
                                .small()
                                .color(ui.visuals().weak_text_color());
                            if ui.add(egui::Label::new(hide).sense(egui::Sense::click())).clicked() {
                                click.toggle_fold = true;
                            }
                        }
                    });
                    if fold == Some(true) {
                        let what = if reported { "Сообщение узла под жалобами" } else { "Сообщение незнакомца" };
                        let show = egui::RichText::new(format!("{what} свёрнуто — показать"))
                            .italics()
                            .color(ui.visuals().weak_text_color());
                        let resp = ui.add(egui::Label::new(show).sense(egui::Sense::click()));
                        if resp.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        if resp.clicked() {
                            click.toggle_fold = true;
                        }
                    } else {
                        ui.label(&msg.text);
                    }
                });
            });
            if !msg.is_me { ui.add_space(40.0); }
        });

        click
    }

    fn send_message(&mut self) {
        let text = self.input.trim_end_matches('\n').trim().to_string();
        if text.is_empty() {
            self.input.clear();
            return;
        }
        let max = void_chat::public_chat::MAX_CHAT_TEXT_BYTES;
        if text.len() > max {
            self.send_error = Some(format!(
                "\u{F0026}  Сообщение длиннее {} КБ — другие узлы его не примут. Сократите его.",
                max / 1024,
            ));
            return;
        }
        self.send_error = None;
        let channel = self.current_channel.clone();
        let may_drop = self.is_newcomer() && !self.take_pace(&channel);

        self.messages.push(ChatMessage {
            author:  self.my_name.clone(),
            text:    text.clone(),
            time:    chrono::Local::now().format("%H:%M").to_string(),
            is_me:   true,
            from_id: None,
            channel: self.current_channel.clone(),
            seq:     0,
            may_drop,
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
