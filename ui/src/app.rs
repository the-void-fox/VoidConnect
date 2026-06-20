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
            Page::Chat    => " 󰭹",
            Page::Private => " 󰌾",
            Page::Storage => " ",
            Page::Sites   => " ",
            Page::Profile => " ",
            Page::Graph   => " ",
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
}

impl VoidApp {
    pub fn new(backend: BackendHandle) -> Self {
        let mut chat = ChatPage::new(
            backend.chat_sender.clone(),
            backend.my_name.clone(),
            backend.my_id_full.clone(),
        );
        chat.messages.clear();

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
        profile.connect_tx      = Some(backend.connect_tx.clone());
        profile.profile_tx      = Some(backend.profile_tx.clone());
        profile.my_node_id      = Some(backend.my_id_node.clone());

        let graph = Graph::new(backend.my_name.clone(), backend.my_id_node.clone());

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

        Self {
            current_page: Page::Chat,
            chat,
            private,
            storage,
            sites:   SitesPage::default(),
            profile,
            graph,
            backend,
            peer_count: 0,
            history_loaded: false,
        }
    }
}

impl eframe::App for VoidApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.load_chat_history_once();
        self.poll_chat();
        self.poll_private_chat();
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
        let my_addr    = format!("{} ({}:{})",
            self.profile.name, self.backend.my_ip, self.backend.base_port);
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(26.0)
            .show(ctx, |ui| {
                crate::widgets::status_bar::show_status_bar(ui, peer_count, &my_addr, local_mode);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_page {
                Page::Chat    => {
                    self.chat.show(ui);
                    if let Some(peer_id) = self.chat.pending_dm.take() {
                        self.open_dm(peer_id);
                    }
                }
                Page::Private => self.private.show(ui),
                Page::Storage => self.storage.show(ui),
                Page::Sites   => self.sites.show(ui),
                Page::Profile => self.profile.show(ui),
                Page::Graph   => {
                    self.graph.show(ui);
                    if let Some(peer_id) = self.graph.pending_dm.take() {
                        self.open_dm(peer_id);
                    }
                }
            }
        });

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
        self.chat.update_context(peer_vec.clone(), profiles.clone());
        self.private.update_context(peer_vec.clone(), profiles.clone());
        self.graph.update_my_name(&self.profile.name);
        self.graph.update_peers(peer_vec, profiles);
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        let pad = 12.0;
        ui.add_space(pad);

        ui.vertical_centered(|ui| {
            ui.heading("󰋙 Void Connect");
        });

        ui.add_space(8.0);
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

            if ui.button("  Настройки").clicked() { ui.close_menu(); }
            ui.separator();
            ui.label("Навигация:");
            for (label, page) in [
                (" 󰭹 Общий чат",         Page::Chat),
                (" 󰌾 Личные сообщения",   Page::Private),
                ("  Хранилище",          Page::Storage),
                ("  Сайты",             Page::Sites),
                ("  Граф сети",         Page::Graph),
                ("  Профиль",           Page::Profile),
            ] {
                if ui.button(label).clicked() {
                    self.current_page = page;
                    ui.close_menu();
                }
            }
            ui.separator();
            if ui.button(" 󰿅 Выход").clicked() { std::process::exit(0); }
        });

        ui.menu_button("Справка", |ui| {
            if ui.button("  О программе").clicked()  { ui.close_menu(); }
            if ui.button("  Документация").clicked() { ui.close_menu(); }
        });

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let online_color = egui::Color32::from_rgb(80, 200, 80);
            ui.label(egui::RichText::new("● Online").color(online_color));
            ui.add_space(8.0);
        });
    }
}
