use eframe::egui;
use egui::menu;

use void_core::identity::NodeId;

use crate::backend::BackendHandle;
use crate::theme;
use crate::pages::{
    chat::ChatPage,
    private::PrivatePage,
    storage::StoragePage,
    sites::SitesPage,
    profile::ProfilePage,
    graph::Graph,
    votes::VotesPage,
};

#[derive(PartialEq, Clone, Copy)]
pub enum Page {
    Chat,
    Private,
    Storage,
    Sites,
    Votes,
    Profile,
    Graph,
}

impl Page {
    fn icon(&self) -> &'static str {
        match self {
            Page::Chat    => " \u{F0B79}", // nf-md-message
            Page::Private => " \u{F033E}", // nf-md-lock
            Page::Storage => " \u{F02CA}", // nf-md-harddisk
            Page::Sites   => " \u{F059F}", // nf-md-web
            Page::Votes   => " \u{F0C30}", // nf-md-vote
            Page::Profile => " \u{F0009}", // nf-md-account_circle
            Page::Graph   => " \u{F1049}", // nf-md-graph
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Page::Chat    => "Общий чат",
            Page::Private => "Личные сообщения",
            Page::Storage => "Хранилище",
            Page::Sites   => "Сайты",
            Page::Votes   => "Голосования",
            Page::Profile => "Профиль",
            Page::Graph   => "Граф сети",
        }
    }
}

pub struct VoidApp {
    pub current_page: Page,
    pub chat:         ChatPage,
    pub private:      PrivatePage,
    pub storage:      StoragePage,
    pub sites:        SitesPage,
    pub votes:        VotesPage,
    pub profile:      ProfilePage,
    pub graph:        Graph,
    pub backend:      BackendHandle,
    peer_count:       usize,
    /// Подгружена ли уже история общего чата из БД (делается один раз).
    history_loaded:   bool,
    /// Номер снимка пиров/профилей, уже переданного во вкладки.
    snapshot_seen:    Option<u64>,
    // ── Окна меню (настройки / о программе / документация) ────────────────
    show_settings:    bool,
    show_about:       bool,
    show_docs:        bool,
    /// Редактируемая копия настроек; применяется после перезапуска.
    settings:         crate::settings_store::Settings,
    /// Буфер ввода bootstrap-узлов (по одному адресу на строку).
    settings_bootstrap_input: String,
    /// Показать отметку «сохранено» после записи настроек.
    settings_saved:   bool,
    // ── Пароль аккаунта (в окне настроек) ─────────────────────────────────
    pw_current:       String,
    pw_new:           String,
    pw_confirm:       String,
    /// Результат последней операции с паролем: (это_ошибка, текст).
    pw_msg:           Option<(bool, String)>,
    /// Смена пароля в фоне (PBKDF2 — сотни миллисекунд в release, секунды в debug).
    pw_job:           crate::bg::Job<Result<&'static str, String>>,
    /// Один раз спросить, публиковать ли старые локальные отметки «проверен».
    trust_prompt:     bool,
    /// Вопросы сайтов (JS API) к пользователю.
    consent_ui:       crate::site_consent::ConsentUi,
}

impl VoidApp {
    pub fn new(backend: BackendHandle) -> Self {
        let mut chat = ChatPage::new(
            backend.chat_sender.clone(),
            backend.my_name.clone(),
        );
        chat.messages.clear();
        chat.reputation = Some(std::sync::Arc::clone(&backend.peer_reputation));
        chat.reports = Some(std::sync::Arc::clone(&backend.reports));
        chat.blocklist = Some(std::sync::Arc::clone(&backend.blocklist));
        chat.voted_channels = Some(std::sync::Arc::clone(&backend.voted_channels));
        // Сеть доверия (общая для chat и graph).
        let trust = crate::trust_ui::TrustUi {
            map:     std::sync::Arc::clone(&backend.trust),
            private: std::sync::Arc::clone(&backend.private_verified),
            access:  std::sync::Arc::clone(&backend.dm_access),
            details: std::sync::Arc::clone(&backend.trust_details),
            greeter: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                crate::settings_store::load().greeter,
            )),
            my_vouchers: std::sync::Arc::clone(&backend.my_vouchers),
            tx:      backend.trust_tx.clone(),
        };
        chat.trust = Some(trust.clone());
        let trust_prompt = !backend.private_verified.lock().unwrap().is_empty()
            && !crate::verify_store::migration_asked();
        chat.my_id_hex = backend.my_id_full.clone();
        chat.my_vouchers = Some(std::sync::Arc::clone(&backend.my_vouchers));
        chat.chat_links = Some(std::sync::Arc::clone(&backend.chat_links));

        // Load saved profile values (description, status) for the profile page
        let saved = crate::profile_store::load_or_create();

        let mut profile = ProfilePage::default();
        profile.name            = backend.my_name.clone();
        profile.description     = if saved.description.is_empty() { profile.description } else { saved.description };
        profile.status          = if saved.status.is_empty()      { profile.status }      else { saved.status };
        profile.pub_key_display = backend.my_id_short.clone();
        profile.my_ip           = backend.my_ip.clone();
        profile.base_port       = backend.base_port;
        profile.bootstrap       = backend.bootstrap;
        profile.avatar_png      = saved.avatar_png.clone();
        profile.connect_tx      = Some(backend.connect_tx.clone());
        profile.profile_tx      = Some(backend.profile_tx.clone());
        profile.my_node_id      = Some(backend.my_id_node.clone());
        // Рассылаем профиль (с аватаром/описанием) один раз при старте, чтобы
        // пиры сразу получили актуальные данные, а не только после «Сохранить».
        profile.send_profile();

        let mut graph = Graph::new(backend.my_name.clone(), backend.my_id_node.clone());
        graph.reputation = Some(std::sync::Arc::clone(&backend.peer_reputation));
        graph.reports = Some(std::sync::Arc::clone(&backend.reports));
        graph.blocklist = Some(std::sync::Arc::clone(&backend.blocklist));
        graph.trust = Some(trust);
        graph.topology = Some(std::sync::Arc::clone(&backend.topology));

        // Инициализируем страницу личных сообщений
        let mut private = PrivatePage {
            my_enc_kp:  Some(std::sync::Arc::clone(&backend.my_enc_kp)),
            dm_sender:  Some(backend.dm_sender.clone()),
            my_name:    backend.my_name.clone(),
            access:     Some(std::sync::Arc::clone(&backend.dm_access)),
            trust_tx:   Some(backend.trust_tx.clone()),
            ..PrivatePage::default()
        };
        // Загружаем историю с диска
        private.load_history_from_disk();

        // Страница хранилища: подключаем канал публикации и список файлов.
        let mut storage = StoragePage::default();
        storage.publish_tx    = Some(backend.publish_tx.clone());
        storage.download_tx   = Some(backend.download_tx.clone());
        storage.storage_files = Some(std::sync::Arc::clone(&backend.storage_files));
        storage.downloads_dir = Some(backend.downloads_dir.clone());
        storage.peer_profiles = Some(std::sync::Arc::clone(&backend.peer_profiles));
        storage.my_id         = Some(backend.my_id_node.clone());
        storage.my_vouchers   = Some(std::sync::Arc::clone(&backend.my_vouchers));
        storage.my_name       = backend.my_name.clone();

        // Страница сайтов: канал публикации + список сайтов + имена .void.
        let mut sites = SitesPage::default();
        sites.publish_tx     = Some(backend.publish_site_tx.clone());
        sites.mirror_tx      = Some(backend.mirror_tx.clone());
        sites.my_vouchers    = Some(std::sync::Arc::clone(&backend.my_vouchers));
        sites.sites          = Some(std::sync::Arc::clone(&backend.sites));
        sites.site_http_port = backend.site_http_port;
        sites.dns_names      = Some(std::sync::Arc::clone(&backend.dns_names));
        sites.permissions    = Some(backend.site_access.permissions.clone());

        // Страница голосований: снимок предложений + каналы создания/голоса.
        let mut votes = VotesPage::default();
        votes.proposals     = Some(std::sync::Arc::clone(&backend.proposals));
        votes.propose_tx    = Some(backend.propose_tx.clone());
        votes.vote_cast_tx  = Some(backend.vote_cast_tx.clone());
        votes.my_vouchers   = Some(std::sync::Arc::clone(&backend.my_vouchers));
        votes.peers         = Some(std::sync::Arc::clone(&backend.peers));
        votes.profiles      = Some(std::sync::Arc::clone(&backend.peer_profiles));
        votes.storage_files = Some(std::sync::Arc::clone(&backend.storage_files));

        let settings = crate::settings_store::load();
        let settings_bootstrap_input = settings.bootstrap_nodes.join("\n");
        chat.fold_strangers = settings.fold_strangers;

        Self {
            current_page: Page::Chat,
            chat,
            private,
            storage,
            sites,
            votes,
            profile,
            graph,
            backend,
            peer_count: 0,
            history_loaded: false,
            snapshot_seen: None,
            pw_current: String::new(),
            pw_new: String::new(),
            pw_confirm: String::new(),
            pw_msg: None,
            pw_job: crate::bg::Job::default(),
            trust_prompt,
            consent_ui: Default::default(),
            show_settings: false,
            show_about: false,
            show_docs: false,
            settings,
            settings_bootstrap_input,
            settings_saved: false,
        }
    }
}

impl eframe::App for VoidApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let frame_start = std::time::Instant::now();
        self.load_chat_history_once();
        self.poll_chat();
        self.poll_private_chat();
        self.poll_dm_status();
        self.refresh_peers();

        let bar_frame = |m: egui::Margin| egui::Frame::none().fill(theme::BG_SIDE).inner_margin(m);

        egui::TopBottomPanel::top("menu")
            .frame(bar_frame(egui::Margin::symmetric(10.0, 5.0)))
            .show(ctx, |ui| {
                menu::bar(ui, |ui| { self.show_top_bar(ui); });
            });

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(216.0)
            .frame(bar_frame(egui::Margin::symmetric(12.0, 14.0)))
            .show(ctx, |ui| { self.show_sidebar(ui); });

        let peer_count = self.peer_count;
        let local_mode = self.backend.local_mode;
        let public_mode = self.backend.bootstrap;
        let has_bootstrap = self.backend.has_bootstrap;
        let reachable  = self.profile.port_reachable;
        let my_addr    = format!("{} ({}:{})",
            self.profile.name, self.backend.my_ip, self.backend.base_port);
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(28.0)
            .frame(bar_frame(egui::Margin::symmetric(10.0, 0.0)))
            .show(ctx, |ui| {
                crate::widgets::status_bar::show_status_bar(
                    ui, peer_count, &my_addr, local_mode, public_mode, has_bootstrap, reachable,
                );
            });

        let central = egui::Frame::none()
            .fill(theme::BG)
            .inner_margin(egui::Margin { left: 22.0, right: 22.0, top: 14.0, bottom: 12.0 });
        egui::CentralPanel::default().frame(central).show(ctx, |ui| {
            match self.current_page {
                Page::Chat    => {
                    self.chat.show(ui);
                    if let Some(peer_id) = self.chat.pending_dm.take() {
                        self.open_dm(peer_id);
                    }
                    if let Some((target, reason)) = self.chat.pending_report.take() {
                        let _ = self.backend.report_tx.send((target, reason));
                    }
                }
                Page::Private => self.private.show(ui),
                Page::Storage => {
                    self.storage.show(ui);
                    if let Some((target, reason)) = self.storage.pending_report.take() {
                        let _ = self.backend.report_tx.send((target, reason));
                    }
                }
                Page::Sites   => self.sites.show(ui),
                Page::Votes   => self.votes.show(ui),
                Page::Profile => self.profile.show(ui),
                Page::Graph   => {
                    self.graph.show(ui);
                    if let Some(peer_id) = self.graph.pending_dm.take() {
                        self.open_dm(peer_id);
                    }
                    if let Some((target, reason)) = self.graph.pending_report.take() {
                        let _ = self.backend.report_tx.send((target, reason));
                    }
                }
            }
        });

        self.show_dialogs(ctx);
        self.show_site_consent(ctx);

        ctx.request_repaint_after(std::time::Duration::from_millis(50));

        // Долгий кадр — это подвисание окна; пишем в лог, чтобы по жалобе
        // «тормозит» было видно, на какой вкладке и насколько.
        let took = frame_start.elapsed();
        if took > std::time::Duration::from_millis(200) {
            tracing::warn!("Медленный кадр: {} мс (вкладка «{}»)", took.as_millis(), self.current_page.label());
        }
    }
}

impl VoidApp {
    /// Открыть личный чат с указанным пиром (из popup профиля).
    fn open_dm(&mut self, peer_id: NodeId) {
        // Определяем имя пира из профиля или peer_list
        let peer_name = {
            let profiles = self.backend.peer_profiles.lock().unwrap();
            profiles.get(&peer_id)
                .map(|p| p.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| {
                    let peers = self.backend.peers.lock().unwrap();
                    peers.iter().find(|p| p.id == peer_id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| peer_id.as_str()[..8.min(peer_id.as_str().len())].to_string())
                })
        };
        self.private.open_conversation(peer_id, peer_name);
        self.current_page = Page::Private;
    }

    /// Один раз подгружает историю общего чата из БД, как только бэкенд её
    /// загрузил. В отличие от poll_chat, показывает и наши собственные прошлые
    /// сообщения (is_me) — оптимистичного дублирования здесь нет.
    fn load_chat_history_once(&mut self) {
        if self.history_loaded {
            return;
        }
        let history = self.backend.chat_history.lock().unwrap().take();
        if let Some(history) = history {
            for msg in history {
                let is_me = msg.from.as_str() == self.backend.my_id_full;
                let time = chrono::DateTime::from_timestamp(msg.timestamp, 0)
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.with_timezone(&chrono::Local).format("%H:%M").to_string())
                    .unwrap_or_default();
                self.chat.receive_message(crate::pages::chat::ChatMessage {
                    author:  msg.from_name.clone(),
                    text:    msg.text.clone(),
                    time,
                    is_me,
                    from_id: Some(msg.from.clone()),
                    channel: msg.channel.clone(),
                    seq:     msg.seq,
                    may_drop: false,
                });
            }
            self.history_loaded = true;
        }
    }

    fn poll_chat(&mut self) {
        let messages = {
            let mut inbox = self.backend.chat_inbox.lock().unwrap();
            std::mem::take(&mut *inbox)
        };

        for msg in messages {
            if msg.from.as_str() == self.backend.my_id_full {
                continue;
            }

            let time = chrono::DateTime::from_timestamp(msg.timestamp, 0)
                .map(|dt: chrono::DateTime<chrono::Utc>| dt.with_timezone(&chrono::Local).format("%H:%M").to_string())
                .unwrap_or_default();

            self.chat.receive_message(crate::pages::chat::ChatMessage {
                author:  msg.from_name.clone(),
                text:    msg.text.clone(),
                time,
                is_me:   false,
                from_id: Some(msg.from.clone()),
                channel: msg.channel.clone(),
                seq:     msg.seq,
                may_drop: false,
            });
        }
    }

    /// Опрашиваем входящие DM и передаём в PrivatePage.
    fn poll_private_chat(&mut self) {
        let messages = {
            let mut inbox = self.backend.dm_inbox.lock().unwrap();
            std::mem::take(&mut *inbox)
        };

        for dm in messages {
            self.private.receive_dm(dm);
        }
    }

    /// Применяем статусы доставки исходящих DM и убираем терминальные записи,
    /// чтобы карта статусов не росла бесконечно.
    fn poll_dm_status(&mut self) {
        let updates: Vec<(String, crate::backend::DeliveryState)> = {
            let map = self.backend.dm_status.lock().unwrap();
            if map.is_empty() { return; }
            map.iter().map(|(k, v)| (k.clone(), *v)).collect()
        };
        let mut terminal: Vec<String> = Vec::new();
        for (mid, state) in updates {
            self.private.apply_delivery(&mid, state);
            if matches!(
                state,
                crate::backend::DeliveryState::Delivered | crate::backend::DeliveryState::Failed
            ) {
                terminal.push(mid);
            }
        }
        if !terminal.is_empty() {
            let mut map = self.backend.dm_status.lock().unwrap();
            for mid in terminal {
                map.remove(&mid);
            }
        }
    }

    /// Обновляем пиры и профили — дедупликация по IP (или IP:порт в local mode).
    fn refresh_peers(&mut self) {
        // Свой аватар может меняться в рантайме — обновляем его во всех вкладках.
        if self.chat.my_avatar != self.profile.avatar_png {
            self.chat.my_avatar    = self.profile.avatar_png.clone();
            self.private.my_avatar = self.profile.avatar_png.clone();
        }
        self.graph.update_me(&self.profile.name, self.profile.avatar_png.as_deref());
        self.refresh_status();

        // Пиры и профили (с аватарами по ~24 КБ) бэкенд обновляет раз в 2 с —
        // копируем их только при новом снимке, а не 20 раз в секунду.
        let gen = self.backend.snapshot_gen.load(std::sync::atomic::Ordering::Acquire);
        if self.snapshot_seen == Some(gen) {
            return;
        }
        self.snapshot_seen = Some(gen);

        let peers    = self.backend.peers.lock().unwrap().clone();
        let profiles = self.backend.peer_profiles.lock().unwrap().clone();
        let local    = self.backend.local_mode;

        let mut seen = std::collections::HashSet::new();
        let mut unique: Vec<_> = Vec::new();
        for p in peers.iter().filter(|p| !p.id.as_str().starts_with("stub-")) {
            let key = if local { (p.ip, p.port) } else { (p.ip, 0) };
            if seen.insert(key) { unique.push(p); }
        }
        for p in peers.iter().filter(|p| p.id.as_str().starts_with("stub-")) {
            let key = if local { (p.ip, p.port) } else { (p.ip, 0) };
            if seen.insert(key) { unique.push(p); }
        }

        self.peer_count = unique.len();
        let peer_vec: Vec<_> = unique.iter().map(|p| (*p).clone()).collect();
        self.chat.update_context(peer_vec.clone(), profiles.clone());
        self.private.update_context(peer_vec.clone(), profiles.clone());
        self.graph.update_peers(peer_vec, profiles);
    }

    /// Дешёвые поля статуса — каждый кадр.
    fn refresh_status(&mut self) {
        // Доступность наших портов извне (по обратной пробе bootstrap-узла).
        use void_discovery::bootstrap::Reachability;
        self.profile.port_reachable = match *self.backend.reachability.lock().unwrap() {
            Reachability::Reachable => Some(true),
            Reachability::Blocked   => Some(false),
            Reachability::Unknown   => None,
        };

        // Реальная статистика сессии для профиля (аптайм + трафик).
        self.profile.uptime         = self.backend.start_time.elapsed();
        self.profile.upload_bytes   = self.backend.bytes_uploaded.load(std::sync::atomic::Ordering::Relaxed);
        self.profile.download_bytes = self.backend.bytes_downloaded.load(std::sync::atomic::Ordering::Relaxed);

        // Своя репутация глазами пиров (из периодического gossip) + есть ли пиры.
        self.profile.my_vouchers = self.backend.my_vouchers.load(std::sync::atomic::Ordering::Relaxed);
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        // ── Логотип ──────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("\u{F02D9}").size(22.0).color(theme::ACCENT));
            ui.label(
                egui::RichText::new("Void Connect")
                    .font(egui::FontId::new(17.0, theme::semibold()))
                    .color(theme::TEXT_STRONG),
            );
        });
        ui.add_space(14.0);

        // ── Карточка профиля: аватар + имя (щелчок → страница профиля) ──────
        let avatar = self.profile.avatar_png.clone();
        let my_name = self.profile.name.clone();
        let id_short = self.backend.my_id_short.clone();
        let (rect, card) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 58.0), egui::Sense::click());
        let fill = if card.hovered() { theme::SURFACE_2 } else { theme::SURFACE };
        ui.painter().rect(rect, egui::Rounding::same(theme::R_CARD), fill, egui::Stroke::new(1.0_f32, theme::BORDER));
        ui.allocate_ui_at_rect(rect.shrink2(egui::vec2(10.0, 9.0)), |ui| {
            ui.horizontal_centered(|ui| {
                crate::avatar::show_avatar(ui, avatar.as_deref(), &my_name, theme::SURFACE_3, 38.0);
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.add_space(1.0);
                    ui.label(
                        egui::RichText::new(&my_name)
                            .font(egui::FontId::new(14.0, theme::semibold()))
                            .color(theme::TEXT_STRONG),
                    );
                    ui.label(egui::RichText::new(&id_short).size(11.0).monospace().color(theme::TEXT_FAINT));
                });
            });
        });
        if card.on_hover_text("Открыть профиль").on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            self.current_page = Page::Profile;
        }

        ui.add_space(18.0);
        ui.label(egui::RichText::new("РАЗДЕЛЫ").size(10.5).color(theme::TEXT_FAINT));
        ui.add_space(2.0);
        for page in [Page::Chat, Page::Private, Page::Storage, Page::Sites, Page::Votes, Page::Graph] {
            if theme::nav_item(ui, page.icon().trim(), page.label(), self.current_page == page).clicked() {
                self.current_page = page;
            }
            ui.add_space(1.0);
        }

        // Профиль и настройки — внизу панели.
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            if theme::nav_item(ui, "\u{F0493}", "Настройки", self.show_settings).clicked() {
                self.show_settings = true;
                self.settings_saved = false;
            }
            ui.add_space(1.0);
            let page = Page::Profile;
            if theme::nav_item(ui, page.icon().trim(), page.label(), self.current_page == page).clicked() {
                self.current_page = page;
            }
            ui.add_space(6.0);
            ui.separator();
        });
    }

    fn show_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("󰋙", |ui| {
            ui.set_min_width(220.0);

            if ui.button(" \u{F0493} Настройки").clicked() {
                self.show_settings = true;
                self.settings_saved = false;
                ui.close_menu();
            }
            ui.separator();
            ui.label("Навигация:");
            for page in [
                Page::Chat, Page::Private, Page::Storage,
                Page::Sites, Page::Votes, Page::Graph, Page::Profile,
            ] {
                if ui.button(format!("{} {}", page.icon(), page.label())).clicked() {
                    self.current_page = page;
                    ui.close_menu();
                }
            }
            ui.separator();
            if ui.button(" \u{F0343} Выход").clicked() { std::process::exit(0); }
        });

        ui.menu_button("Справка", |ui| {
            if ui.button(" \u{F02FC} О программе").clicked()  { self.show_about = true; ui.close_menu(); }
            if ui.button(" \u{F0BC8} Документация").clicked() { self.show_docs = true;  ui.close_menu(); }
        });

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Индикатор должен отражать реальное наличие связи, а не быть зашитым.
            let (label, color, hint) = if self.peer_count > 0 {
                ("В сети", theme::OK, format!("Известно узлов: {}", self.peer_count))
            } else {
                ("Нет связи", theme::WARN, "Ни одного узла не обнаружено.".to_string())
            };
            theme::status_pill(ui, color, label).on_hover_text(hint);
        });
    }

    /// Вопрос сайта к пользователю (разрешение, публикация файла) — поверх
    /// всего окна. Снимки копируем только пока вопрос открыт.
    fn show_site_consent(&mut self, ctx: &egui::Context) {
        let broker = self.backend.site_access.consent.clone();
        self.consent_ui.attach(ctx, &broker);
        if broker.pending().is_empty() {
            return;
        }
        let sites = self.backend.sites.lock().unwrap().clone();
        let profiles = self.backend.peer_profiles.lock().unwrap().clone();
        let trust = self.backend.trust.lock().unwrap().clone();
        self.consent_ui.show(ctx, &broker, &sites, &profiles, &trust, &self.backend.my_id_node);
    }

    // ── Окна из меню ──────────────────────────────────────────────────────────

    fn show_dialogs(&mut self, ctx: &egui::Context) {
        self.show_trust_prompt(ctx);
        self.show_settings_window(ctx);
        self.show_about_window(ctx);
        self.show_docs_window(ctx);
    }

    /// Окно настроек: публичный режим, bootstrap-узлы, базовый порт.
    /// Значения сохраняются в settings.json и применяются при следующем запуске.
    /// Один раз после обновления: раньше отметки «проверен» были только
    /// локальными, теперь «проверен» — публичное поручительство. Спрашиваем,
    /// публиковать ли старые отметки; если нет — они остаются только у нас.
    fn show_trust_prompt(&mut self, ctx: &egui::Context) {
        if !self.trust_prompt {
            return;
        }
        let count = self.backend.private_verified.lock().unwrap().len();
        let mut answer: Option<bool> = None;
        egui::Window::new("Проверенные контакты")
            .collapsible(false)
            .resizable(false)
            .fixed_size([400.0, 0.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("У вас {count} контакт(ов), отмеченных проверенными."));
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(
                        "Теперь отметка «проверен» — это публичное поручительство: его видят \
                         другие узлы, и ваше доверие к контакту помогает доверию к нему у ваших \
                         знакомых (сеть доверия). Раньше отметки были видны только вам.",
                    )
                    .small()
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Если не публиковать, отметки продолжат работать только для вас; \
                         опубликовать любую можно позже в профиле контакта.",
                    )
                    .small()
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Оставить только у меня").clicked() {
                        answer = Some(false);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Опубликовать").clicked() {
                            answer = Some(true);
                        }
                    });
                });
            });
        if let Some(publish) = answer {
            if publish {
                let _ = self.backend.trust_tx.send(crate::backend::TrustCmd::PublishPrivate);
            }
            crate::verify_store::mark_migration_asked();
            self.trust_prompt = false;
        }
    }

    fn show_settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_settings;
        theme::dialog(ctx, "\u{F0493}  Настройки", &mut open)
            .default_width(440.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Чат").strong().size(15.0));
                ui.add_space(8.0);
                if ui
                    .checkbox(&mut self.chat.fold_strangers, "Сворачивать сообщения незнакомцев")
                    .changed()
                {
                    // Применяется сразу; сохраняем только это поле — несохранённые
                    // правки сетевых настроек ниже на диск не попадают.
                    self.settings.fold_strangers = self.chat.fold_strangers;
                    let mut on_disk = crate::settings_store::load();
                    on_disk.fold_strangers = self.chat.fold_strangers;
                    let _ = crate::settings_store::save(&on_disk);
                }
                ui.label(
                    egui::RichText::new(
                        "Сообщения тех, за кого никто из вашей сети доверия не поручился, \
                         показываются свёрнутыми — их можно раскрыть по щелчку.")
                        .small().color(ui.visuals().weak_text_color()),
                );
                ui.add_space(6.0);
                if ui.checkbox(&mut self.settings.greeter, "Я встречающий").changed() {
                    if let Some(trust) = &self.chat.trust {
                        trust.greeter.store(self.settings.greeter, std::sync::atomic::Ordering::Relaxed);
                    }
                    let mut on_disk = crate::settings_store::load();
                    on_disk.greeter = self.settings.greeter;
                    let _ = crate::settings_store::save(&on_disk);
                }
                ui.label(
                    egui::RichText::new(
                        "У новичков в канале «Новички» и в их профиле появится кнопка \
                         «Поприветствовать». Это слабое публичное поручительство: «похож на \
                         живого человека». Для вас и ваших знакомых новичок станет освоившимся. \
                         Если он окажется ботом, ваши поручительства потеряют вес.")
                        .small().color(ui.visuals().weak_text_color()),
                );
                if self.settings.greeter && self.backend.my_vouchers.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                    crate::trust_ui::newcomer_hint(
                        ui,
                        "За вас ещё никто не поручился — у других узлов ваше приветствие пока ничего не весит.",
                    );
                }

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Глобальная сеть").strong().size(15.0));
                ui.add_space(8.0);

                ui.checkbox(
                    &mut self.settings.public_mode,
                    "Публичный режим — стать точкой входа в сеть",
                );
                ui.label(
                    egui::RichText::new(
                        "Поднимает bootstrap- и relay-сервер, пробрасывает порты через UPnP и \
                         помогает другим узлам войти в сеть. Нужен «белый» IP или проброшенный порт.")
                        .small().color(ui.visuals().weak_text_color()),
                );

                ui.add_space(12.0);
                ui.label(egui::RichText::new("Bootstrap-узлы для подключения к глобальной сети").strong());
                ui.label(
                    egui::RichText::new("По одному адресу host:порт на строку.")
                        .small().color(ui.visuals().weak_text_color()),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.settings_bootstrap_input)
                        .desired_rows(3)
                        .hint_text("203.0.113.5:7700")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Базовый порт:").strong());
                    ui.add(egui::DragValue::new(&mut self.settings.base_port).clamp_range(1024..=65500));
                    ui.label(
                        egui::RichText::new("(чат +2, ЛС +3, сайты +4, bootstrap +5, relay +6)")
                            .small().color(ui.visuals().weak_text_color()),
                    );
                });

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    if ui.add(theme::primary_button("\u{F0193}  Сохранить")).clicked() {
                        self.settings.bootstrap_nodes = self.settings_bootstrap_input
                            .lines()
                            .flat_map(|l| l.split(','))
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        self.settings_saved = crate::settings_store::save(&self.settings).is_ok();
                    }
                    if self.settings_saved {
                        ui.label(
                            egui::RichText::new("\u{F012C}  сохранено")
                                .color(egui::Color32::from_rgb(80, 200, 80)),
                        );
                    }
                });

                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(
                        "\u{F0709}  Изменения вступят в силу после перезапуска программы.")
                        .small().color(egui::Color32::from_rgb(220, 180, 60)),
                );
                let live = if self.backend.bootstrap {
                    "Сейчас активен: публичный режим"
                } else {
                    "Сейчас активен: обычный режим"
                };
                ui.label(egui::RichText::new(live).small().color(ui.visuals().weak_text_color()));

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(8.0);
                self.show_password_section(ui);
            });
        self.show_settings = open;
    }

    /// Раздел «Безопасность аккаунта»: установка/смена/снятие пароля.
    ///
    /// Пароль шифрует ключи на диске (KEK = KDF(machine-id + пароль)). NodeId при
    /// этом не меняется — пароль можно включать и снимать, не теряя личность.
    fn show_password_section(&mut self, ui: &mut egui::Ui) {
        use void_crypto::identity::KeystoreState;

        let data_dir = crate::profile_store::profile_dir();
        let has_pw = matches!(
            void_crypto::Identity::keystore_status(&data_dir),
            KeystoreState::PasswordRequired,
        );

        ui.label(egui::RichText::new("\u{F0BC4}  Безопасность аккаунта").strong().size(15.0));
        ui.add_space(6.0);

        if has_pw {
            ui.label(
                egui::RichText::new("\u{F0BC5}  Аккаунт защищён паролем — он спрашивается при запуске.")
                    .color(egui::Color32::from_rgb(80, 190, 110)),
            );
        } else {
            ui.label("Пароль не задан: на этом устройстве ключи расшифровываются автоматически.");
        }
        ui.label(
            egui::RichText::new(
                "Пароль шифрует ключи на диске — с ним изъятие компьютера не даёт доступ к \
                 аккаунту. Внимание: если забыть пароль, личность на этом ПК восстановить нельзя.",
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );

        ui.add_space(8.0);
        egui::Grid::new("pw_grid").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            if has_pw {
                ui.label("Текущий пароль:");
                ui.add(egui::TextEdit::singleline(&mut self.pw_current).password(true).desired_width(220.0));
                ui.end_row();
            }
            ui.label(if has_pw { "Новый пароль:" } else { "Пароль:" });
            ui.add(
                egui::TextEdit::singleline(&mut self.pw_new)
                    .password(true)
                    .hint_text(if has_pw { "пусто = снять пароль" } else { "" })
                    .desired_width(220.0),
            );
            ui.end_row();

            ui.label("Повтор:");
            ui.add(egui::TextEdit::singleline(&mut self.pw_confirm).password(true).desired_width(220.0));
            ui.end_row();
        });

        ui.add_space(8.0);
        let btn_label = if has_pw {
            if self.pw_new.is_empty() { "\u{F0BC5}  Снять пароль" } else { "\u{F0193}  Сменить пароль" }
        } else {
            "\u{F0BC4}  Установить пароль"
        };
        if let Some(res) = self.pw_job.poll() {
            self.pw_msg = Some(match res {
                Ok(what) => {
                    self.pw_current.clear();
                    self.pw_new.clear();
                    self.pw_confirm.clear();
                    (false, what.into())
                }
                Err(e) => (true, e),
            });
        }
        let busy = self.pw_job.running();
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new(btn_label)).clicked() {
                self.apply_password_change(ui.ctx(), &data_dir, has_pw);
            }
            if busy {
                ui.spinner();
                ui.label(egui::RichText::new("Шифрую ключи…").color(theme::TEXT_DIM));
            }
        });

        if let Some((is_err, msg)) = &self.pw_msg {
            ui.add_space(6.0);
            let color = if *is_err {
                egui::Color32::from_rgb(220, 80, 60)
            } else {
                egui::Color32::from_rgb(80, 200, 80)
            };
            ui.label(egui::RichText::new(msg).color(color));
        }
    }

    /// Валидирует поля и запускает смену пароля в фоне (PBKDF2 — см. `pw_job`).
    fn apply_password_change(&mut self, ctx: &egui::Context, data_dir: &std::path::Path, has_pw: bool) {
        if self.pw_new != self.pw_confirm {
            self.pw_msg = Some((true, "Пароли не совпадают".into()));
            return;
        }
        let new = if self.pw_new.is_empty() { None } else { Some(self.pw_new.clone()) };
        if !has_pw && new.is_none() {
            self.pw_msg = Some((true, "Введите новый пароль".into()));
            return;
        }
        let current = if has_pw { Some(self.pw_current.clone()) } else { None };
        let data_dir = data_dir.to_path_buf();
        self.pw_msg = None;
        self.pw_job.start(ctx, move || {
            match void_crypto::Identity::set_password(&data_dir, current.as_deref(), new.as_deref()) {
                Ok(()) => Ok(match (has_pw, new.is_some()) {
                    (false, _)    => "Пароль установлен",
                    (true, true)  => "Пароль изменён",
                    (true, false) => "Пароль снят",
                }),
                Err(void_crypto::CryptoError::WrongPassword) => Err("Неверный текущий пароль".into()),
                Err(e) => Err(format!("Ошибка: {e}")),
            }
        });
    }

    fn show_about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_about;
        theme::dialog(ctx, "\u{F02FC}  О программе", &mut open)
            .default_width(380.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.vertical_centered(|ui| {
                    ui.heading("Void Connect");
                    ui.label(
                        egui::RichText::new(format!("версия {}", env!("CARGO_PKG_VERSION"))).weak(),
                    );
                });
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                ui.label(
                    "Децентрализованная P2P-сеть — мини-интернет внутри локальной сети. \
                     Общий и личный чат, обмен файлами, хостинг сайтов и внутренний DNS \
                     (.void) — без центрального сервера.",
                );
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("Технологии:").strong());
                    ui.label("Rust · Tokio · egui · ChaCha20/X25519 · SQLite");
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new("\u{F02D1}").color(theme::ERR),
                    );
                    ui.label(
                        egui::RichText::new("Сделано с любовью к децентрализации.")
                            .small().color(ui.visuals().weak_text_color()),
                    );
                });
            });
        self.show_about = open;
    }

    fn show_docs_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_docs;
        let docs_h = theme::max_window_height(ctx) - 60.0;
        theme::dialog(ctx, "\u{F0BC8}  Документация — быстрый старт", &mut open)
            .vscroll(false) // своя прокрутка внутри
            .resizable(true)
            .default_width(470.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().max_height(docs_h.min(440.0)).show(ui, |ui| {
                    ui.add_space(4.0);

                    ui.label(egui::RichText::new("В одной локальной сети").strong().size(14.0));
                    ui.label(
                        "Запустите программу на каждом ПК — узлы найдут друг друга сами \
                         (mDNS + broadcast). Соседи появятся на странице «Граф сети».",
                    );
                    ui.add_space(8.0);

                    ui.label(
                        egui::RichText::new("Своя сеть через интернет (Hamachi / Radmin VPN)")
                            .strong().size(14.0),
                    );
                    ui.label(
                        "1. Установите Hamachi или Radmin VPN на всех ПК.\n\
                         2. Один создаёт сеть, остальные присоединяются по имени и паролю.\n\
                         3. Запустите Void Connect обычно (без --local).\n\
                         4. Если узлы не нашлись — подключитесь вручную к VPN-адресу друга \
                            (25.x.x.x или 26.x.x.x) на странице «Профиль».",
                    );
                    ui.add_space(8.0);

                    ui.label(egui::RichText::new("Глобальная сеть").strong().size(14.0));
                    ui.label(
                        "Меню → Настройки: укажите bootstrap-узлы, чтобы подключиться к сети \
                         через интернет, либо включите «Публичный режим», чтобы самому стать \
                         точкой входа.",
                    );
                    ui.add_space(8.0);

                    ui.label(egui::RichText::new("Если соединение не идёт — порты").strong().size(14.0));
                    ui.label(
                        egui::RichText::new(
                            "TCP 7700 (файлы), 7702 (чат), 7703 (ЛС), 7704 (сайты)\n\
                             UDP 7701 (обнаружение)\n\
                             публичный узел дополнительно: TCP 7705, 7706")
                            .monospace().small(),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Подробные инструкции по файрволу — на странице «Профиль».")
                            .small().color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("Полная документация — в файле README.md и папке Obsidian/.")
                            .small().color(ui.visuals().weak_text_color()),
                    );
                });
            });
        self.show_docs = open;
    }
}
