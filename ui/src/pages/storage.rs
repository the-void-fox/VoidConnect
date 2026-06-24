use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::{Align, Button, Frame, Label, ProgressBar, RichText, ScrollArea, TextEdit};
use tokio::sync::mpsc::UnboundedSender;

use void_core::identity::NodeId;
use void_core::peer::PeerProfile;
use void_reputation::ReportReason;

use crate::backend::{DownloadCmd, StorageFileInfo};

pub struct FileEntry {
    pub file_id: String,
    pub name: String,
    pub size: String,
    pub size_bytes: i64,
    pub chunks: u32,
    pub chunks_total: u32,
    pub seeders: u32,
    pub status: FileStatus,
    /// Исходный публикатор (его публичный ключ = ID).
    pub owner_key: String,
    /// Имя публикатора для отображения («Ваши файлы» / имя / короткий ID).
    pub owner_name: String,
    /// Файл опубликован нами (мы — исходный публикатор).
    pub is_mine: bool,
    /// Мы раздаём этот файл (опубликован нами либо полностью скачан).
    pub seeding_by_me: bool,
}

#[derive(PartialEq, Clone)]
pub enum FileStatus {
    NotStarted,
    Downloading(f32), // 0.0..1.0
    Paused(f32),      // частично скачан, на паузе — 0.0..1.0
    Seeding,
    Complete,
}

impl FileStatus {
    fn color(&self, ui: &egui::Ui) -> egui::Color32 {
        match self {
            FileStatus::NotStarted => ui.visuals().weak_text_color(),
            FileStatus::Downloading(_) => ui.visuals().hyperlink_color,
            FileStatus::Paused(_) => egui::Color32::from_rgb(200, 160, 70),
            FileStatus::Seeding => egui::Color32::from_rgb(180, 130, 60),
            FileStatus::Complete => egui::Color32::from_rgb(80, 180, 100),
        }
    }

    fn label_text(&self) -> String {
        match self {
            FileStatus::NotStarted => "  Ожидание".into(),
            FileStatus::Downloading(p) => format!("󰇚  Загрузка ({:.0}%)", p * 100.0),
            FileStatus::Paused(p) => format!("󰏤  Пауза ({:.0}%)", p * 100.0),
            FileStatus::Seeding => "󰕒  Раздача".into(),
            FileStatus::Complete => "󰄬  Готово".into(),
        }
    }
}

pub struct StoragePage {
    pub files: Vec<FileEntry>,
    pub search: String,
    pub report_target: Option<usize>,
    /// Канал GUI → backend: опубликовать файл по пути.
    pub publish_tx: Option<UnboundedSender<PathBuf>>,
    /// Канал GUI → backend: управление скачиванием (старт/пауза).
    pub download_tx: Option<UnboundedSender<DownloadCmd>>,
    /// Реальный список файлов из backend (снимок обновляется бэкендом).
    pub storage_files: Option<Arc<Mutex<Vec<StorageFileInfo>>>>,
    /// Поле ввода пути к публикуемому файлу.
    pub publish_path: String,
    /// file_id файлов, для которых мы запросили скачивание (пока не завершено).
    pub downloading: HashSet<String>,
    /// Папка скачанных файлов (для действия «Открыть»).
    pub downloads_dir: Option<PathBuf>,
    /// Файл, ожидающий подтверждения удаления (индекс + вид удаления).
    pending_delete: Option<(usize, DeleteKind)>,
    /// Профили узлов — для перевода ключа публикатора в читаемое имя.
    pub peer_profiles: Option<Arc<Mutex<HashMap<NodeId, PeerProfile>>>>,
    /// Наш ID — чтобы пометить свою «папку».
    pub my_id: Option<NodeId>,
    /// Наше имя — для подписи своей «папки».
    pub my_name: String,
    /// Жалоба на публикатора, ожидающая отправки в backend (target, причина).
    pub pending_report: Option<(NodeId, ReportReason)>,
}

impl Default for StoragePage {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            search: String::new(),
            report_target: None,
            publish_tx: None,
            download_tx: None,
            storage_files: None,
            publish_path: String::new(),
            downloading: HashSet::new(),
            downloads_dir: None,
            pending_delete: None,
            peer_profiles: None,
            my_id: None,
            my_name: String::new(),
            pending_report: None,
        }
    }
}

/// Группа файлов одного публикатора — «папка» пользователя.
struct OwnerGroup {
    key: String,
    name: String,
    is_mine: bool,
    total_size: i64,
    indices: Vec<usize>,
}

// Ширины колонок — одинаковые для шапки и строк
const COL_ICON: f32 = 30.0;
//const COL_NAME: f32 = 240.0;
const COL_SIZE: f32 = 80.0;
const COL_CHUNKS: f32 = 130.0;
const COL_SEEDS: f32 = 60.0;
const COL_STATUS: f32 = 150.0;
const COL_ACTION: f32 = 120.0;
const COL_REPORT: f32 = 32.0;

const ROW_H: f32 = 32.0;
const HEADER_H: f32 = 22.0;

/// Человекочитаемый размер файла.
fn human_size(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1e9      { format!("{:.1} GB", b / 1e9) }
    else if b >= 1e6 { format!("{:.1} MB", b / 1e6) }
    else if b >= 1e3 { format!("{:.1} KB", b / 1e3) }
    else             { format!("{} B", bytes) }
}

impl StoragePage {
    /// Обновляет отображаемый список из снимка backend.
    fn sync_from_backend(&mut self) {
        let Some(shared) = &self.storage_files else { return };
        let snapshot = shared.lock().unwrap().clone();
        let mut entries = Vec::with_capacity(snapshot.len());
        for f in snapshot {
            // Файл докачан — снимаем флаг "скачивается".
            if f.progress >= 1.0 {
                self.downloading.remove(&f.file_id);
            }
            let done = (f.progress * f.total_chunks as f64).round() as u32;
            let status = if f.is_mine {
                FileStatus::Seeding
            } else if f.progress >= 1.0 {
                FileStatus::Complete
            } else if self.downloading.contains(&f.file_id) {
                FileStatus::Downloading(f.progress as f32)
            } else if f.progress > 0.0 {
                // частично скачан, но не в активной загрузке → на паузе (resume)
                FileStatus::Paused(f.progress as f32)
            } else {
                FileStatus::NotStarted
            };
            let owner_name = self.owner_display(&f.owner_key);
            // Мы раздаём файл, если опубликовали его сами или полностью скачали.
            let seeding_by_me = f.is_mine || f.progress >= 1.0;
            entries.push(FileEntry {
                file_id:      f.file_id,
                name:         f.name,
                size:         human_size(f.size_bytes),
                size_bytes:   f.size_bytes,
                chunks:       done,
                chunks_total: f.total_chunks.max(0) as u32,
                seeders:      f.seeders.max(0) as u32,
                status,
                owner_key:    f.owner_key,
                owner_name,
                is_mine:      f.is_mine,
                seeding_by_me,
            });
        }
        self.files = entries;
    }

    /// Переводит публичный ключ публикатора в читаемое имя: «Ваши файлы» для
    /// своих, имя из профиля для известных узлов, иначе короткий ID.
    fn owner_display(&self, owner_key: &str) -> String {
        if let Some(my) = &self.my_id {
            if my.as_str() == owner_key {
                return if self.my_name.trim().is_empty() {
                    "Ваши файлы".to_string()
                } else {
                    self.my_name.clone()
                };
            }
        }
        if let Some(profiles) = &self.peer_profiles {
            if let Ok(map) = profiles.lock() {
                if let Some(p) = map.get(&NodeId(owner_key.to_string())) {
                    if !p.name.trim().is_empty() {
                        return p.name.clone();
                    }
                }
            }
        }
        if owner_key.is_empty() {
            "неизвестный публикатор".to_string()
        } else {
            format!("{}…", &owner_key[..8.min(owner_key.len())])
        }
    }

    /// Группирует файлы по публикатору в «папки», применяя поиск (по имени файла
    /// и имени публикатора). Своя папка идёт первой, остальные — по имени.
    fn build_groups(&self, search_lower: &str) -> Vec<OwnerGroup> {
        let mut map: HashMap<String, OwnerGroup> = HashMap::new();
        for (idx, f) in self.files.iter().enumerate() {
            if !search_lower.is_empty()
                && !f.name.to_lowercase().contains(search_lower)
                && !f.owner_name.to_lowercase().contains(search_lower)
            {
                continue;
            }
            let g = map.entry(f.owner_key.clone()).or_insert_with(|| OwnerGroup {
                key:        f.owner_key.clone(),
                name:       f.owner_name.clone(),
                is_mine:    f.is_mine,
                total_size: 0,
                indices:    Vec::new(),
            });
            g.total_size += f.size_bytes;
            g.indices.push(idx);
        }
        let mut groups: Vec<OwnerGroup> = map.into_values().collect();
        groups.sort_by(|a, b| {
            b.is_mine
                .cmp(&a.is_mine)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.key.cmp(&b.key))
        });
        groups
    }

    /// Отправляет путь из поля ввода в backend на публикацию.
    fn publish_current(&mut self) {
        let path = self.publish_path.trim().to_string();
        if path.is_empty() { return; }
        if let Some(tx) = &self.publish_tx {
            let _ = tx.send(PathBuf::from(path));
        }
        self.publish_path.clear();
    }

    /// Запрашивает у backend скачивание (или возобновление) файла по индексу.
    fn start_download(&mut self, idx: usize) {
        let Some(file) = self.files.get(idx) else { return };
        let file_id = file.file_id.clone();
        if file_id.is_empty() { return; }
        if let Some(tx) = &self.download_tx {
            let _ = tx.send(DownloadCmd::Start(file_id.clone()));
        }
        self.downloading.insert(file_id);
        if let Some(f) = self.files.get_mut(idx) {
            f.status = FileStatus::Downloading(0.0);
        }
    }

    /// Ставит скачивание на паузу. Уже полученные чанки сохранены, поэтому
    /// кнопка «Загрузить» затем продолжит с места остановки (resume).
    fn pause_download(&mut self, idx: usize) {
        let Some(file) = self.files.get(idx) else { return };
        let file_id = file.file_id.clone();
        if let Some(tx) = &self.download_tx {
            let _ = tx.send(DownloadCmd::Pause(file_id.clone()));
        }
        self.downloading.remove(&file_id);
        if let Some(f) = self.files.get_mut(idx) {
            f.status = FileStatus::NotStarted;
        }
    }

    /// Открывает скачанный файл системным приложением (кросс-платформенно).
    fn open_file(&self, idx: usize) {
        let Some(file) = self.files.get(idx) else { return };
        let Some(dir) = &self.downloads_dir else { return };
        let path = dir.join(&file.name);
        // Скачанные файлы лежат в <data_dir>/downloads/<name>. Свой раздаваемый
        // файл там может отсутствовать (раздаётся из чанк-стора) — тогда не пытаемся.
        if path.exists() {
            crate::sys_open::open_external(&path);
        }
    }

    /// Удаляет файл: «из сети» (только владелец, нет других сидеров) или «свою
    /// копию» (перестать раздавать). Сразу убирает из списка — снимок backend
    /// подтвердит на следующем тике.
    fn remove_file(&mut self, idx: usize, kind: DeleteKind) {
        let Some(file) = self.files.get(idx) else { return };
        let file_id = file.file_id.clone();
        if file_id.is_empty() { return; }
        if let Some(tx) = &self.download_tx {
            let cmd = match kind {
                DeleteKind::Network => DownloadCmd::Remove(file_id.clone()),
                DeleteKind::Local   => DownloadCmd::RemoveLocal(file_id.clone()),
            };
            let _ = tx.send(cmd);
        }
        self.downloading.remove(&file_id);
        self.files.retain(|f| f.file_id != file_id);
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        // Подтягиваем актуальный список файлов из backend.
        self.sync_from_backend();

        // === Заголовок ===
        ui.add_space(8.0);
        ui.heading("\u{F02CA} Хранилище");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // === Поиск ===
        ui.add(
            TextEdit::singleline(&mut self.search)
                .hint_text("󰍉  Поиск по файлам и пользователям…")
                .desired_width(f32::INFINITY),
        );

        ui.add_space(6.0);

        // === Публикация файла ===
        let mut do_publish = false;
        ui.horizontal(|ui| {
            let pub_w = 130.0;
            let browse_w = 96.0;
            let gap = ui.spacing().item_spacing.x;
            let path_w = (ui.available_width() - pub_w - browse_w - gap * 2.0).max(120.0);
            let resp = ui.add(
                TextEdit::singleline(&mut self.publish_path)
                    .hint_text("󰉓  Путь к файлу…")
                    .desired_width(path_w - 4.0),
            );
            // Enter в поле = опубликовать
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                do_publish = true;
            }
            // Нативный выбор файла
            if ui.add_sized([browse_w, 28.0], Button::new("󰉕  Обзор")).clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Файл для публикации")
                    .pick_file()
                {
                    self.publish_path = path.display().to_string();
                }
            }
            let enabled = self.publish_tx.is_some() && !self.publish_path.trim().is_empty();
            if ui.add_enabled(enabled, Button::new("󰐕  Опубликовать").min_size(egui::vec2(pub_w, 28.0))).clicked() {
                do_publish = true;
            }
        });
        if do_publish {
            self.publish_current();
        }

        ui.add_space(8.0);

        // === Шапка таблицы ===
        let spacing_x = ui.spacing().item_spacing.x;
        let total_spacing = spacing_x * 7.0; // 7 промежутков между 8 колонками
        let fixed_width = COL_ICON + COL_SIZE + COL_CHUNKS + COL_SEEDS + COL_STATUS + COL_ACTION + COL_REPORT;
        
        // === Группировка по публикаторам («папки» пользователей) ===
        let search_lower = self.search.trim().to_lowercase();
        let groups = self.build_groups(&search_lower);

        let avail_h = ui.available_height() - 40.0;
        let mut action: Option<(usize, RowAction)> = None;

        if groups.is_empty() {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                let msg = if self.files.is_empty() {
                    "Хранилище пусто. Опубликуйте файл или дождитесь появления файлов в сети."
                } else {
                    "Ничего не найдено по запросу."
                };
                ui.label(RichText::new(msg).color(ui.visuals().weak_text_color()));
            });
        } else {
            ScrollArea::vertical()
                .id_source("storage_scroll")
                .max_height(avail_h)
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    for g in &groups {
                        // Заголовок «папки» = публикатор + число файлов + объём.
                        let icon = if g.is_mine { "\u{F0004}" } else { "\u{F024B}" };
                        let title = format!(
                            "{}  {}   —   {} файл. · {}",
                            icon, g.name, g.indices.len(), human_size(g.total_size),
                        );
                        let title_rt = if g.is_mine {
                            RichText::new(title).strong().color(egui::Color32::from_rgb(110, 175, 235))
                        } else {
                            RichText::new(title).strong()
                        };
                        egui::CollapsingHeader::new(title_rt)
                            .id_source(format!("owner_folder_{}", g.key))
                            .default_open(g.is_mine || !search_lower.is_empty())
                            .show(ui, |ui| {
                                let inner_w = ui.available_width();
                                let col_name_w =
                                    (inner_w - fixed_width - total_spacing - 24.0).max(120.0);
                                Frame::none()
                                    .inner_margin(egui::Margin::symmetric(6.0, 4.0))
                                    .fill(ui.visuals().widgets.noninteractive.bg_fill)
                                    .show(ui, |ui| { Self::table_header(ui, col_name_w); });
                                ui.add_space(2.0);
                                for (row_i, &idx) in g.indices.iter().enumerate() {
                                    let file = &self.files[idx];
                                    let frame_fill = if row_i % 2 == 0 {
                                        ui.visuals().extreme_bg_color
                                    } else {
                                        egui::Color32::TRANSPARENT
                                    };
                                    Frame::none()
                                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                        .fill(frame_fill)
                                        .show(ui, |ui| {
                                            ui.set_min_height(ROW_H);
                                            Self::table_row(ui, idx, file, &mut action, col_name_w);
                                        });
                                }
                            });
                        ui.add_space(6.0);
                    }
                });
        }

        // === Обработка действий ===
        if let Some((idx, act)) = action {
            match act {
                RowAction::Download => self.start_download(idx),
                RowAction::Pause    => self.pause_download(idx),
                RowAction::Open     => self.open_file(idx),
                RowAction::Report   => self.report_target = Some(idx),
                RowAction::Delete      => self.pending_delete = Some((idx, DeleteKind::Network)),
                RowAction::RemoveLocal => self.pending_delete = Some((idx, DeleteKind::Local)),
            }
        }

        // === Диалог подтверждения удаления ===
        if let Some((idx, kind)) = self.pending_delete {
            let Some(file) = self.files.get(idx) else {
                self.pending_delete = None;
                return;
            };
            let name = file.name.clone();
            let mut close = false;
            let mut confirm = false;
            let (title, msg, btn_label) = match kind {
                DeleteKind::Network => (
                    "󰩺  Удалить из сети",
                    "Файл будет убран из вашей раздачи и стёрт с диска. Других сидеров нет — \
                     файл станет недоступен в сети, и его манифест больше не будет приниматься. \
                     Действие необратимо.",
                    "󰩺  Удалить из сети",
                ),
                DeleteKind::Local => (
                    "󰮞  Убрать мою копию",
                    "Ваша локальная копия будет удалена, вы перестанете раздавать файл. Сам файл \
                     останется доступен в сети у других сидеров — его можно будет скачать снова.",
                    "󰮞  Убрать копию",
                ),
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .fixed_size([380.0, 0.0])
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.add_space(6.0);
                    ui.label(RichText::new(&name).strong());
                    ui.add_space(6.0);
                    ui.label(RichText::new(msg).small().color(ui.visuals().weak_text_color()));
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Отмена").clicked() {
                            close = true;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let del = Button::new(RichText::new(btn_label).color(egui::Color32::WHITE))
                                .fill(egui::Color32::from_rgb(180, 60, 50));
                            if ui.add(del).clicked() {
                                confirm = true;
                            }
                        });
                    });
                });
            if confirm {
                self.remove_file(idx, kind);
                close = true;
            }
            if close {
                self.pending_delete = None;
            }
        }

        // === Диалог жалобы на публикатора ===
        if let Some(idx) = self.report_target {
            let (file_name, owner_name, owner_key, is_mine) = match self.files.get(idx) {
                Some(f) => (f.name.clone(), f.owner_name.clone(), f.owner_key.clone(), f.is_mine),
                None => { self.report_target = None; return; }
            };
            let mut chosen: Option<ReportReason> = None;
            let mut close = false;

            egui::Window::new("󰀦  Жалоба на публикатора")
                .collapsible(false)
                .resizable(false)
                .fixed_size([390.0, 0.0])
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ui.ctx(), |ui| {
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Файл:").strong());
                        ui.label(RichText::new(&file_name).monospace());
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Публикатор:").strong());
                        ui.label(RichText::new(&owner_name).color(ui.visuals().hyperlink_color));
                    });
                    ui.add_space(10.0);

                    if is_mine {
                        ui.label(
                            RichText::new("Это ваш файл — пожаловаться на себя нельзя.")
                                .color(egui::Color32::from_rgb(220, 160, 60)),
                        );
                        ui.add_space(10.0);
                        ui.separator();
                        ui.add_space(6.0);
                        if ui.button("Закрыть").clicked() {
                            close = true;
                        }
                        return;
                    }

                    ui.label(RichText::new("Выберите причину:").size(14.0).strong());
                    ui.add_space(10.0);

                    let reasons: [(&str, &str, ReportReason); 4] = [
                        (" 󱃈  Вредоносный контент",   "Вирус, троян, майнер и т.д.",            ReportReason::MaliciousContent),
                        (" 󰶍  Мошенничество / обман", "Ложное описание файла",                  ReportReason::MaliciousContent),
                        (" 󰇮  Неверные / битые данные","Неверный размер, формат или битые чанки", ReportReason::BadChunks),
                        (" 󰶐  Другое",                "Иная причина",                           ReportReason::MaliciousContent),
                    ];
                    for (label, tooltip, reason) in reasons {
                        let resp = ui.selectable_label(false, label).on_hover_text(tooltip);
                        if resp.clicked() {
                            chosen = Some(reason);
                        }
                    }

                    ui.add_space(14.0);
                    ui.separator();
                    ui.add_space(8.0);
                    if ui.button("Отмена").clicked() {
                        close = true;
                    }
                });

            if let Some(reason) = chosen {
                if !owner_key.is_empty() {
                    self.pending_report = Some((NodeId(owner_key), reason));
                }
                close = true;
            }
            if close {
                self.report_target = None;
            }
        }

        // === Статус-строка ===
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let total = self.files.len();
            let seeding = self.files.iter().filter(|f| f.seeding_by_me).count();
            let loading = self
                .files
                .iter()
                .filter(|f| matches!(f.status, FileStatus::Downloading(_)))
                .count();
            let pending = self
                .files
                .iter()
                .filter(|f| matches!(f.status, FileStatus::NotStarted | FileStatus::Paused(_)))
                .count();

            ui.label(
                RichText::new(format!(
                    "Файлов: {total}   |   Раздаёте: {seeding}   |   Загружается: {loading}   |   Ожидает: {pending}"
                ))
                .size(12.0)
                .color(ui.visuals().weak_text_color()),
            );
        });
    }

    fn table_header(ui: &mut egui::Ui, col_name_w: f32) {
        ui.horizontal(|ui| {
            // Иконка
            ui.allocate_ui(egui::vec2(COL_ICON, HEADER_H), |ui| {
                ui.set_width(COL_ICON); // Жесткая фиксация
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new(" ").size(12.0).color(ui.visuals().weak_text_color()));
                });
            });
            // Имя файла
            ui.allocate_ui(egui::vec2(col_name_w, HEADER_H), |ui| {
                ui.set_width(col_name_w); // Жесткая фиксация
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add(Label::new(RichText::new("Имя файла").strong().size(12.0)).wrap(false));
                });
            });
            // Размер
            ui.allocate_ui(egui::vec2(COL_SIZE, HEADER_H), |ui| {
                ui.set_width(COL_SIZE);
                ui.centered_and_justified(|ui| {
                    ui.add(Label::new(RichText::new("Размер").strong().size(12.0)).wrap(false));
                });
            });
            // Чанки
            ui.allocate_ui(egui::vec2(COL_CHUNKS, HEADER_H), |ui| {
                ui.set_width(COL_CHUNKS);
                ui.centered_and_justified(|ui| {
                    ui.add(Label::new(RichText::new("Чанки").strong().size(12.0)).wrap(false));
                });
            });
            // Сиды
            ui.allocate_ui(egui::vec2(COL_SEEDS, HEADER_H), |ui| {
                ui.set_width(COL_SEEDS);
                ui.centered_and_justified(|ui| {
                    ui.add(Label::new(RichText::new("Сиды").strong().size(12.0)).wrap(false));
                });
            });
            // Статус
            ui.allocate_ui(egui::vec2(COL_STATUS, HEADER_H), |ui| {
                ui.set_width(COL_STATUS);
                ui.centered_and_justified(|ui| {
                    ui.add(Label::new(RichText::new("Статус").strong().size(12.0)).wrap(false));
                });
            });
            // Действие
            ui.allocate_ui(egui::vec2(COL_ACTION, HEADER_H), |ui| {
                ui.set_width(COL_ACTION);
                ui.centered_and_justified(|ui| {
                    ui.add(Label::new(RichText::new("Действие").strong().size(12.0)).wrap(false));
                });
            });
            // Колонка меню действий — без подписи в шапке
            ui.allocate_ui(egui::vec2(COL_REPORT, HEADER_H), |ui| {
                ui.set_width(COL_REPORT);
            });
        });
    }

fn table_row(
        ui: &mut egui::Ui,
        idx: usize,
        file: &FileEntry,
        action: &mut Option<(usize, RowAction)>,
        col_name_w: f32,
    ) {
        let icon = file_icon(&file.name);

        ui.horizontal(|ui| {
            // Иконка
            ui.allocate_ui(egui::vec2(COL_ICON, ROW_H), |ui| {
                ui.set_width(COL_ICON);
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new(icon).size(16.0).color(ui.visuals().weak_text_color()));
                });
            });
            
            // Имя файла + маркер «вы раздаёте» (Скролл + жесткая фиксация)
            ui.allocate_ui(egui::vec2(col_name_w, ROW_H), |ui| {
                ui.set_width(col_name_w); // <--- Запрещаем ячейке расширяться
                ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                    let mut name_w = col_name_w;
                    if file.seeding_by_me {
                        ui.label(
                            RichText::new("⬆")
                                .size(12.0)
                                .color(egui::Color32::from_rgb(90, 190, 120)),
                        )
                        .on_hover_text("Вы раздаёте этот файл");
                        name_w -= 16.0;
                    }
                    ScrollArea::horizontal()
                        .id_source(format!("name_scroll_{}", idx))
                        .max_width(name_w.max(40.0)) // <--- Запрещаем скроллу распирать ячейку
                        .show(ui, |ui| {
                            ui.add(Label::new(RichText::new(&file.name).size(13.0)).wrap(false));
                        });
                });
            });
            
            // Размер
            ui.allocate_ui(egui::vec2(COL_SIZE, ROW_H), |ui| {
                ui.set_width(COL_SIZE);
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new(&file.size).size(12.0).color(ui.visuals().weak_text_color()));
                });
            });
            // Чанки + прогресс
            ui.allocate_ui(egui::vec2(COL_CHUNKS, ROW_H), |ui| {
                ui.set_width(COL_CHUNKS);
                ui.with_layout(egui::Layout::top_down(egui::Align::LEFT).with_cross_justify(true), |ui| {
                    ui.add_space(2.0);
                    ui.label(RichText::new(format!("{}/{}", file.chunks, file.chunks_total)).size(11.0).color(ui.visuals().weak_text_color()));
                    let progress = if file.chunks_total > 0 {
                        file.chunks as f32 / file.chunks_total as f32
                    } else {
                        0.0
                    };
                    ui.add(ProgressBar::new(progress).desired_width(COL_CHUNKS - 8.0).desired_height(3.0));
                });
            });
            // Сиды
            ui.allocate_ui(egui::vec2(COL_SEEDS, ROW_H), |ui| {
                ui.set_width(COL_SEEDS);
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new(format!("{}", file.seeders)).size(12.0).color(ui.visuals().weak_text_color()));
                });
            });
            // Статус
            ui.allocate_ui(egui::vec2(COL_STATUS, ROW_H), |ui| {
                ui.set_width(COL_STATUS);
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new(file.status.label_text()).size(12.0).color(file.status.color(ui)));
                });
            });
            // Действие
            ui.allocate_ui(egui::vec2(COL_ACTION, ROW_H), |ui| {
                ui.set_width(COL_ACTION);
                ui.centered_and_justified(|ui| {
                    let (label, act) = match &file.status {
                        FileStatus::NotStarted => ("󰇚  Загрузить", RowAction::Download),
                        FileStatus::Downloading(_) => ("  Пауза", RowAction::Pause),
                        FileStatus::Paused(_) => ("󰐊  Продолжить", RowAction::Download),
                        FileStatus::Complete | FileStatus::Seeding => ("󰈔  Открыть", RowAction::Open),
                    };
                    let btn = ui.add_sized([COL_ACTION - 4.0, 24.0], Button::new(label).wrap(false));
                    if btn.clicked() {
                        *action = Some((idx, act));
                    }
                });
            });
            // Меню действий (кебаб): пожаловаться / удалить из раздачи
            ui.allocate_ui(egui::vec2(COL_REPORT, ROW_H), |ui| {
                ui.set_width(COL_REPORT);
                ui.centered_and_justified(|ui| {
                    // Удаление из сети — только владельцу и только если файл больше
                    // никто не раздаёт (seeders ≤ 1 = только мы). Иначе доступно лишь
                    // «убрать мою копию», и только когда копия реально есть локально.
                    let can_network_delete = file.is_mine && file.seeders <= 1;
                    let has_local_copy = !matches!(file.status, FileStatus::NotStarted);
                    let can_remove_local = !can_network_delete && (file.is_mine || has_local_copy);
                    ui.menu_button(RichText::new("\u{F01D9}").size(15.0).color(ui.visuals().weak_text_color()), |ui| {
                        if !file.is_mine && ui.button("\u{F0026}  Пожаловаться").clicked() {
                            *action = Some((idx, RowAction::Report));
                            ui.close_menu();
                        }
                        if can_network_delete {
                            if ui.button(RichText::new("\u{F0A7A}  Удалить из сети")
                                .color(egui::Color32::from_rgb(220, 90, 70))).clicked()
                            {
                                *action = Some((idx, RowAction::Delete));
                                ui.close_menu();
                            }
                        } else if can_remove_local {
                            if ui.button(RichText::new("\u{F0A7A}  Убрать мою копию")
                                .color(egui::Color32::from_rgb(220, 160, 80))).clicked()
                            {
                                *action = Some((idx, RowAction::RemoveLocal));
                                ui.close_menu();
                            }
                        }
                    });
                });
            });
        });
    }
}

/// Иконки Nerd Font по расширению файла
fn file_icon(name: &str) -> &'static str {
    let n = name.to_lowercase();

    // Архивы
    if n.ends_with(".zip")
        || n.ends_with(".tar")
        || n.ends_with(".tar.gz")
        || n.ends_with(".gz")
        || n.ends_with(".xz")
        || n.ends_with(".bz2")
        || n.ends_with(".7z")
        || n.ends_with(".rar")
    {
        return "  󰗄";
    }
    // Видео
    if n.ends_with(".mp4")
        || n.ends_with(".mkv")
        || n.ends_with(".avi")
        || n.ends_with(".mov")
        || n.ends_with(".webm")
        || n.ends_with(".flv")
        || n.ends_with(".wmv")
        || n.ends_with(".m4v")
    {
        return "  󰎁";
    }
    // Аудио
    if n.ends_with(".mp3")
        || n.ends_with(".flac")
        || n.ends_with(".ogg")
        || n.ends_with(".wav")
        || n.ends_with(".aac")
        || n.ends_with(".opus")
        || n.ends_with(".m4a")
        || n.ends_with(".wma")
    {
        return "  󰎄";
    }
    // Изображения
    if n.ends_with(".png")
        || n.ends_with(".jpg")
        || n.ends_with(".jpeg")
        || n.ends_with(".gif")
        || n.ends_with(".webp")
        || n.ends_with(".svg")
        || n.ends_with(".bmp")
        || n.ends_with(".ico")
        || n.ends_with(".tiff")
    {
        return "  󰋩";
    }
    // PDF документы
    if n.ends_with(".pdf") {
        return "  󰈦";
    }
    // Таблицы / данные
    if n.ends_with(".csv")
        || n.ends_with(".xlsx")
        || n.ends_with(".xls")
        || n.ends_with(".ods")
        || n.ends_with(".tsv")
    {
        return "  󰈛";
    }
    // Документы текстовые
    if n.ends_with(".doc")
        || n.ends_with(".docx")
        || n.ends_with(".odt")
        || n.ends_with(".txt")
        || n.ends_with(".md")
        || n.ends_with(".rtf")
    {
        return "  󰈙";
    }
    // Код — Rust
    if n.ends_with(".rs") {
        return "  󱘗";
    }
    // Код — Python
    if n.ends_with(".py") || n.ends_with(".pyw") {
        return "  󰌠";
    }
    // Код — JavaScript / TypeScript
    if n.ends_with(".js") || n.ends_with(".mjs") || n.ends_with(".cjs") {
        return "  󰌞";
    }
    if n.ends_with(".ts") || n.ends_with(".tsx") || n.ends_with(".jsx") {
        return "  󰛦";
    }
    // Код — C / C++
    if n.ends_with(".c") || n.ends_with(".h") {
        return "  󰙨";
    }
    if n.ends_with(".cpp") || n.ends_with(".hpp") || n.ends_with(".cc") {
        return "  󰙨";
    }
    // Код — Go
    if n.ends_with(".go") {
        return "  󰟓";
    }
    // Код — Java
    if n.ends_with(".java") || n.ends_with(".class") || n.ends_with(".jar") {
        return "  󰬷";
    }
    // Код — C#
    if n.ends_with(".cs") {
        return "  󰌛";
    }
    // Код — HTML
    if n.ends_with(".html") || n.ends_with(".htm") {
        return "  󰌝";
    }
    // Код — CSS / SCSS / SASS
    if n.ends_with(".css") || n.ends_with(".scss") || n.ends_with(".sass") || n.ends_with(".less")
    {
        return "  󰌜";
    }
    // Код — PHP
    if n.ends_with(".php") {
        return "  󰌟";
    }
    // Код — Ruby
    if n.ends_with(".rb") || n.ends_with(".rake") {
        return "  󰴭";
    }
    // Код — Swift
    if n.ends_with(".swift") {
        return "  󰛦";
    }
    // Код — Kotlin
    if n.ends_with(".kt") || n.ends_with(".kts") {
        return "  󱘗";
    }
    // Shell скрипты
    if n.ends_with(".sh") || n.ends_with(".bash") || n.ends_with(".zsh") || n.ends_with(".fish")
    {
        return "  󰆍";
    }
    // PowerShell
    if n.ends_with(".ps1") || n.ends_with(".psm1") || n.ends_with(".psd1") {
        return "  󰏊";
    }
    // Конфиги
    if n.ends_with(".json")
        || n.ends_with(".toml")
        || n.ends_with(".yaml")
        || n.ends_with(".yml")
        || n.ends_with(".ini")
        || n.ends_with(".cfg")
        || n.ends_with(".conf")
    {
        return "  󰘦";
    }
    // XML
    if n.ends_with(".xml") || n.ends_with(".xsl") || n.ends_with(".xslt") {
        return "  󰗀";
    }
    // SQL
    if n.ends_with(".sql") {
        return "  󰎁";
    }
    // Образы дисков
    if n.ends_with(".iso") || n.ends_with(".img") || n.ends_with(".dmg") {
        return "  󰋊";
    }
    // Torrent файлы
    if n.ends_with(".torrent") {
        return "  󰶦";
    }
    // Магнитные ссылки (виртуально)
    if n.ends_with(".magnet") {
        return "  󰶦";
    }
    // Исполняемые файлы
    if n.ends_with(".exe")
        || n.ends_with(".msi")
        || n.ends_with(".bin")
        || n.ends_with(".appimage")
        || n.ends_with(".deb")
        || n.ends_with(".rpm")
        || n.ends_with(".apk")
    {
        return "  󰆧";
    }
    // macOS приложения
    if n.ends_with(".app") {
        return "  \u{f0035}";
    }
    // Шрифты
    if n.ends_with(".ttf")
        || n.ends_with(".otf")
        || n.ends_with(".woff")
        || n.ends_with(".woff2")
        || n.ends_with(".eot")
    {
        return "  󰛖";
    }
    // Динамические библиотеки
    if n.ends_with(".dll") || n.ends_with(".so") || n.ends_with(".dylib") {
        return "  󰌲";
    }
    // Базы данных
    if n.ends_with(".db")
        || n.ends_with(".sqlite")
        || n.ends_with(".sqlite3")
        || n.ends_with(".mdb")
    {
        return "  󰄭";
    }
    // Логи
    if n.ends_with(".log") || n.ends_with(".lg") {
        return "  󰚌";
    }
    // Сертификаты и ключи
    if n.ends_with(".pem")
        || n.ends_with(".crt")
        || n.ends_with(".cer")
        || n.ends_with(".key")
        || n.ends_with(".pub")
    {
        return "  󰌆";
    }
    // Стоковые изображения
    if n.ends_with(".psd") || n.ends_with(".ai") || n.ends_with(".sketch") || n.ends_with(".fig")
    {
        return "  󰣪";
    }
    // 3D модели
    if n.ends_with(".obj")
        || n.ends_with(".fbx")
        || n.ends_with(".stl")
        || n.ends_with(".blend")
        || n.ends_with(".3ds")
    {
        return "  󰔏";
    }
    // Проекты IDE
    if n.ends_with(".code-workspace") || n.ends_with(".sublime-project") {
        return "  󰨞";
    }
    // Git файлы
    if n.ends_with(".gitignore")
        || n.ends_with(".gitattributes")
        || n.ends_with(".gitmodules")
    {
        return "  󰊢";
    }
    // Markdown файлы
    if n.ends_with(".md") || n.ends_with(".mdx") {
        return "  󰍔";
    }
    // По умолчанию
    "  󰈔"
}

enum RowAction {
    Download,
    Pause,
    Open,
    Report,
    /// Удалить файл из сети (владелец, других сидеров нет).
    Delete,
    /// Убрать только свою локальную копию (перестать раздавать).
    RemoveLocal,
}

/// Какой вид удаления подтверждается в диалоге.
#[derive(Clone, Copy, PartialEq)]
enum DeleteKind {
    /// Удалить файл из сети целиком (владелец, других сидеров нет).
    Network,
    /// Убрать только свою локальную копию.
    Local,
}