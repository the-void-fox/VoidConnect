use eframe::egui;
use crate::egui::menu;

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
            Page::Chat => " 󰭹",
            Page::Private => " 󰌾",
            Page::Storage => " ",
            Page::Sites => " ",
            Page::Profile => " ",
            Page::Graph => " "
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Page::Chat => "Общий чат",
            Page::Private => "Личные сообщения",
            Page::Storage => "Хранилище",
            Page::Sites => "Сайты",
            Page::Profile => "Профиль",
            Page::Graph => "Граф",
        }
    }
}

pub struct VoidApp {
    pub current_page: Page,
    pub chat: ChatPage,
    pub private: PrivatePage,
    pub storage: StoragePage,
    pub sites: SitesPage,
    pub profile: ProfilePage,
    pub graph: Graph,
}

impl Default for VoidApp {
    fn default() -> Self {
        Self {
            current_page: Page::Chat,
            chat: ChatPage::default(),
            private: PrivatePage::default(),
            storage: StoragePage::default(),
            sites: SitesPage::default(),
            profile: ProfilePage::default(),
            graph: Graph::default(),
        }
    }
}

impl eframe::App for VoidApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top menu bar
        egui::TopBottomPanel::top("menu")
            .show(ctx, |ui| {
                menu::bar(ui, |ui| { self.show_top_bar(ui) });
            });

        // Left sidebar
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show(ctx, |ui| {
                self.show_sidebar(ui);
            });

        // Status bar at the bottom
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(26.0)
            .show(ctx, |ui| {
                crate::widgets::status_bar::show_status_bar(ui);
            });

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_page {
                Page::Chat    => self.chat.show(ui),
                Page::Private => self.private.show(ui),
                Page::Storage => self.storage.show(ui),
                Page::Sites   => self.sites.show(ui),
                Page::Profile => self.profile.show(ui),
                Page::Graph => self.graph.show(ui),
            }
        });
    }
}

impl VoidApp {
    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        let sidebar_padding = 12.0;
        
        ui.add_space(sidebar_padding);

        // Logo / title - центрировано
        ui.vertical_centered(|ui| {
            ui.heading("󰋙 Void Connect");
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(12.0);

        // Навигационные кнопки одинаковой ширины
        let button_width = ui.available_width() - sidebar_padding * 2.0;
        
        ui.horizontal(|ui| {
            ui.add_space(sidebar_padding);
            ui.vertical(|ui| {
                // Основные страницы
                self.nav_button(ui, Page::Chat, button_width);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Private, button_width);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Storage, button_width);
                ui.add_space(4.0);
                self.nav_button(ui, Page::Sites, button_width);
                
                // Разделитель перед профилем
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);
                
                // Профиль внизу секции
                self.nav_button(ui, Page::Profile, button_width);
            });
        });
    }

    /// Кнопка навигации с фиксированной шириной и подсветкой активной страницы
    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page, width: f32) {
        let is_selected = self.current_page == page;
        let text = format!("{} {}", page.icon(), page.label());
        
        // Стилизация кнопки
        let button = egui::Button::new(text)
            .min_size(egui::vec2(width, 32.0))
            .selected(is_selected);
        
        // Выравнивание текста влево через frame
        let response = ui.add(button);
        
        if response.clicked() {
            self.current_page = page;
        }
    }

    fn show_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.menu_button("󰋙", |ui| {
            ui.set_min_width(220.0); 

            if ui.button("  Настройки").clicked() {
                ui.close_menu();
            }
            
            ui.separator();
            
            // Быстрая навигация
            ui.label("Навигация:");
            if ui.button(" 󰭹 Общий чат").clicked() {
                self.current_page = Page::Chat;
                ui.close_menu();
            }
            if ui.button(" 󰌾 Личные сообщения").clicked() {
                self.current_page = Page::Private;
                ui.close_menu();
            }
            if ui.button("  Хранилище").clicked() {
                self.current_page = Page::Storage;
                ui.close_menu();
            }
            if ui.button("  Сайты").clicked() {
                self.current_page = Page::Sites;
                ui.close_menu();
            }
            if ui.button("  Профиль").clicked() {
                self.current_page = Page::Profile;
                ui.close_menu();
            }
            if ui.button("  Граф").clicked() {
                self.current_page = Page::Profile;
                ui.close_menu();
            }
            
            ui.separator();
            
            if ui.button(" 󰿅 Выход").clicked() {
                std::process::exit(0);
            }
        });

        ui.menu_button("Справка", |ui| {
            if ui.button("  О программе").clicked() {
                ui.close_menu();
            }
            if ui.button("  Документация").clicked() {
                ui.close_menu();
            }
        });
        
        // Spacer - отталкиваем статус вправо
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label("● Online");
            ui.add_space(8.0);
        });
    }
}