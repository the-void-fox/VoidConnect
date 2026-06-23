use eframe::egui;
use egui::menu;

use void_core::identity::NodeId;

use crate::backend::BackendHandle;
use crate::pages::{
    chat::ChatPage,
    private::PrivatePage,
    storage::StoragePage,
    sites::SitesPage,
    profile::ProfilePage,
    graph::Graph,
};

#[derive(PartialEq, Clone, Copy)]
pub enum Page {
    Chat,
    Private,
    Storage,
    Sites,
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
    pub profile:      ProfilePage,
    pub graph:        Graph,
    pub backend:      BackendHandle,
    peer_count:       usize,
    /// Подгружена ли уже история общего чата из БД (делается один раз).
    history_loaded:   bool,
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
}

impl VoidApp {
    pub fn new(backend: BackendHandle) -> Self {
        let mut chat = ChatPage::new(
            backend.chat_sender.clone(),
            backend.my_name.clone(),
        );
        chat.messages.clear();
        chat.reputation = Some(std::sync::Arc::clone(&backend.peer_reputation));

        // Load saved profile values (description, status) for the profile page
        let saved = crate::profile_store::load_or_create();

        let mut profile = ProfilePage::default();
        profile.name            = backend.my_name.clone();
        profile.description     = if saved.description.is_empty() { profile.description } else { saved.description };
        profile.status          = if saved.status.is_empty()      { profile.status }      else { saved.status };
        profile.pub_key_display = backend.my_id_short.clone();
        profile.dns_name        = format!("{}.void", backend.my_name);
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

        // Инициализируем страницу личных сообщений
        let mut private = PrivatePage::default();
        private.my_enc_kp  = Some(std::sync::Arc::clone(&backend.my_enc_kp));
        private.my_enc_pub = backend.my_enc_kp.public_bytes();
        private.dm_sender  = Some(backend.dm_sender.clone());
        private.my_node_id = Some(backend.my_id_node.clone());
        private.my_name    = backend.my_name.clone();
        private.base_port  = backend.base_port;
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
        storage.my_name       = backend.my_name.clone();

        // Страница сайтов: канал публикации + список сайтов + имена .void.
        let mut sites = SitesPage::default();
        sites.publish_tx     = Some(backend.publish_site_tx.clone());
        sites.mirror_tx      = Some(backend.mirror_tx.clone());
        sites.sites          = Some(std::sync::Arc::clone(&backend.sites));
        sites.site_http_port = backend.site_http_port;
        sites.dns_names      = Some(std::sync::Arc::clone(&backend.dns_names));

        let settings = crate::settings_store::load();
        let settings_bootstrap_input = settings.bootstrap_nodes.join("\n");

        Self {
            current_page: Page::Chat,
            chat,
            private,
            storage,
            sites,
            profile,
            graph,
            backend,
            peer_count: 0,
            history_loaded: false,
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
        self.load_chat_history_once();
        self.poll_chat();
        self.poll_private_chat();
        self.poll_dm_status();
        self.refresh_peers();

        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            menu::bar(ui, |ui| { self.show_top_bar(ui); });
        });

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show(ctx, |ui| { self.show_sidebar(ui); });

        let peer_count = self.peer_count;
        let local_mode = self.backend.local_mode;
        let public_mode = self.backend.bootstrap;
        let has_bootstrap = self.backend.has_bootstrap;
        let reachable  = self.profile.port_reachable;
        let my_addr    = format!("{} ({}:{})",
            self.profile.name, self.backend.my_ip, self.backend.base_port);
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(26.0)
            .show(ctx, |ui| {
                crate::widgets::status_bar::show_status_bar(
                    ui, peer_count, &my_addr, local_mode, public_mode, has_bootstrap, reachable,
                );
            });

        egui::CentralPanel::default().show(ctx, |ui| {
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

        ctx.request_repaint_after(std::time::Duration::from_millis(50));
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
                    .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%H:%M").to_string())
                    .unwrap_or_default();
                self.chat.receive_message(crate::pages::chat::ChatMessage {
                    author:  msg.from_name.clone(),
                    text:    msg.text.clone(),
                    time,
                    is_me,
                    from_id: Some(msg.from.clone()),
                    channel: msg.channel.clone(),
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
                .map(|dt: chrono::DateTime<chrono::Utc>| dt.format("%H:%M").to_string())
                .unwrap_or_default();

            self.chat.receive_message(crate::pages::chat::ChatMessage {
                author:  msg.from_name.clone(),
                text:    msg.text.clone(),
                time,
                is_me:   false,
                from_id: Some(msg.from.clone()),
                channel: msg.channel.clone(),
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
        // Свой аватар может меняться в рантайме — обновляем его во всех вкладках.
        self.chat.my_avatar    = self.profile.avatar_png.clone();
        self.private.my_avatar = self.profile.avatar_png.clone();
        self.chat.update_context(peer_vec.clone(), profiles.clone());
        self.private.update_context(peer_vec.clone(), profiles.clone());
        self.graph.update_me(&self.profile.name, self.profile.avatar_png.as_deref());
        self.graph.update_peers(peer_vec, profiles);

        // Доступность наших портов извне (по обратной пробе bootstrap-узла).
        use void_discovery::bootstrap::Reachability;
        self.profile.port_reachable = match *self.backend.reachability.lock().unwrap() {
            Reachability::Reachable => Some(true),
            Reachability::Blocked   => Some(false),
            Reachability::Unknown   => None,
        };
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        let pad = 12.0;
        ui.add_space(pad);

        ui.vertical_centered(|ui| {
            ui.heading("󰋙 Void Connect");
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(10.0);

        // ── Карточка профиля: аватар + имя (клик → страница профиля) ──────────
        let avatar = self.profile.avatar_png.clone();
        let my_name = self.profile.name.clone();
        let id_short = self.backend.my_id_short.clone();
        let card = ui.horizontal(|ui| {
            ui.add_space(pad);
            crate::avatar::show_avatar(ui, avatar.as_deref(), &my_name, ui.visuals().hyperlink_color, 40.0);
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.add_space(3.0);
                ui.label(egui::RichText::new(&my_name).strong());
                ui.label(egui::RichText::new(&id_short).small().weak().monospace());
            });
        }).response.interact(egui::Sense::click());
        if card.clicked() {
            self.current_page = Page::Profile;
        }
        card.on_hover_text("Открыть профиль");

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(12.0);

        let btn_w = ui.available_width() - pad * 2.0;
        ui.horizontal(|ui| {
            ui.add_space(pad);
            ui.vertical(|ui| {
                self.nav_button(ui, Page::Chat,    btn_w);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Private, btn_w);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Storage, btn_w);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Sites,   btn_w);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Graph,   btn_w);

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                self.nav_button(ui, Page::Profile, btn_w);
            });
        });
    }

    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page, width: f32) {
        let is_selected = self.current_page == page;
        let text = format!("{} {}", page.icon(), page.label());
        let btn  = egui::Button::new(text)
            .min_size(egui::vec2(width, 32.0))
            .selected(is_selected);
        if ui.add(btn).clicked() {
            self.current_page = page;
        }
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
                Page::Sites, Page::Graph, Page::Profile,
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
            let (dot, label, color, hint) = if self.peer_count > 0 {
                (
                    "●",
                    "В сети",
                    egui::Color32::from_rgb(80, 200, 80),
                    format!("Известно узлов: {}", self.peer_count),
                )
            } else {
                (
                    "○",
                    "Нет связи",
                    egui::Color32::from_rgb(180, 130, 60),
                    "Ни одного узла не обнаружено.".to_string(),
                )
            };
            ui.label(egui::RichText::new(format!("{} {}", dot, label)).color(color))
                .on_hover_text(hint);
            ui.add_space(8.0);
        });
    }

    // ── Окна из меню ──────────────────────────────────────────────────────────

    fn show_dialogs(&mut self, ctx: &egui::Context) {
        self.show_settings_window(ctx);
        self.show_about_window(ctx);
        self.show_docs_window(ctx);
    }

    /// Окно настроек: публичный режим, bootstrap-узлы, базовый порт.
    /// Значения сохраняются в settings.json и применяются при следующем запуске.
    fn show_settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_settings;
        egui::Window::new("\u{F0493}  Настройки")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(440.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.add_space(4.0);
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
                    if ui.button("\u{F0193}  Сохранить").clicked() {
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
            });
        self.show_settings = open;
    }

    fn show_about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_about;
        egui::Window::new("\u{F02FC}  О программе")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(380.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
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
                        egui::RichText::new("\u{F02D1}").color(egui::Color32::from_rgb(220, 90, 90)),
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
        egui::Window::new("\u{F0BC8}  Документация — быстрый старт")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(470.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().max_height(440.0).show(ui, |ui| {
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
