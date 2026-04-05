use eframe::egui;

pub struct SiteEntry {
    pub name: String,
    pub address: String,
    pub owner: String,
    pub hosters: u32,
    pub online: bool,
    pub description: String,
}

pub struct SitesPage {
    pub sites: Vec<SiteEntry>,
    pub search: String,
    pub show_publish: bool,
    pub new_site_name: String,
    pub new_site_desc: String,
}

impl Default for SitesPage {
    fn default() -> Self {
        Self {
            sites: vec![
                SiteEntry {
                    name: "Vasya's Blog".into(),
                    address: "vasya.void".into(),
                    owner: "vasya".into(),
                    hosters: 3,
                    online: true,
                    description: "Личный блог о сетях и Rust".into(),
                },
                SiteEntry {
                    name: "Node Status Dashboard".into(),
                    address: "status.void".into(),
                    owner: "alex".into(),
                    hosters: 5,
                    online: true,
                    description: "Мониторинг узлов сети в реальном времени".into(),
                },
                SiteEntry {
                    name: "Void Wiki".into(),
                    address: "wiki.void".into(),
                    owner: "mira".into(),
                    hosters: 7,
                    online: true,
                    description: "Документация и гайды по Void Connect".into(),
                },
                SiteEntry {
                    name: "Music Archive".into(),
                    address: "music.void".into(),
                    owner: "node_7f4a".into(),
                    hosters: 1,
                    online: false,
                    description: "Архив независимой музыки".into(),
                },
            ],
            search: String::new(),
            show_publish: false,
            new_site_name: String::new(),
            new_site_desc: String::new(),
        }
    }
}

impl SitesPage {
    pub fn show(&mut self, ui: &mut egui::Ui) {

    }
}

