use eframe::egui;

pub struct ProfilePage {
    pub name: String,
    pub description: String,
    pub dns_name: String,
    pub status: String,
    pub pub_key_display: String,
    pub reputation: f32,
    pub uptime_hours: u32,
    pub upload_gb: f32,
    pub download_gb: f32,
    pub report_reason: String,
    pub report_target: String,
    pub show_report: bool,
}

impl Default for ProfilePage {
    fn default() -> Self {
        Self {
            name: "vasya".to_string(),
            description: "Просто человек в локальной сети".to_string(),
            dns_name: "vasya.void".to_string(),
            status: "online".to_string(),
            pub_key_display: "4a3f...e91c".to_string(),
            reputation: 0.72,
            uptime_hours: 148,
            upload_gb: 12.4,
            download_gb: 8.1,
            report_reason: String::new(),
            report_target: String::new(),
            show_report: false,
        }
    }
}

impl ProfilePage {
    pub fn show(&mut self, ui: &mut egui::Ui) {

    }
}