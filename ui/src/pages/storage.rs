use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::{Align, Button, Frame, Label, ProgressBar, RichText, ScrollArea, TextEdit};
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::{DownloadCmd, StorageFileInfo};

pub struct FileEntry {
    pub file_id: String,
    pub name: String,
    pub size: String,
    pub chunks: u32,
    pub chunks_total: u32,
    pub seeders: u32,
    pub status: FileStatus,
}

#[derive(PartialEq, Clone)]
pub enum FileStatus {
    NotStarted,
    Downloading(f32), // 0.0..1.0
    Seeding,
    Complete,
}

impl FileStatus {
    fn color(&self, ui: &egui::Ui) -> egui::Color32 {
        match self {
            FileStatus::NotStarted => ui.visuals().weak_text_color(),
            FileStatus::Downloading(_) => ui.visuals().hyperlink_color,
            FileStatus::Seeding => egui::Color32::from_rgb(180, 130, 60),
            FileStatus::Complete => egui::Color32::from_rgb(80, 180, 100),
        }
    }

    fn label_text(&self) -> String {
        match self {
            FileStatus::NotStarted => "  Ожидание".into(),
            FileStatus::Downloading(p) => format!("󰇚  Загрузка ({:.0}%)", p * 100.0),
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
        }
    }
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
            } else {
                FileStatus::NotStarted
            };
            entries.push(FileEntry {
                file_id:      f.file_id,
                name:         f.name,
                size:         human_size(f.size_bytes),
                chunks:       done,
                chunks_total: f.total_chunks.max(0) as u32,
                seeders:      f.seeders.max(0) as u32,
                status,
            });
        }
        self.files = entries;
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

    /// Открывает скачанный файл системным приложением (xdg-open).
    fn open_file(&self, idx: usize) {
        let Some(file) = self.files.get(idx) else { return };
        let Some(dir) = &self.downloads_dir else { return };
        let path = dir.join(&file.name);
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        // Подтягиваем актуальный список файлов из backend.
        self.sync_from_backend();

        // === Заголовок ===
        ui.add_space(8.0);
        ui.heading("Хранилище");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        // === Панель инструментов ===
        ui.horizontal(|ui| {
            let toolbar_h = 28.0;
            let btn_w = 110.0;
            let gap = ui.spacing().item_spacing.x;
            let search_w = ui.available_width() - (btn_w + gap) * 2.0 - gap;

            ui.allocate_ui(egui::vec2(search_w, toolbar_h), |ui| {
                ui.with_layout(
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.add(
                            TextEdit::singleline(&mut self.search)
                                .hint_text("󰍉  Поиск файлов...")
                                .desired_width(search_w - 4.0),
                        );
                    },
                );
            });

            if ui.add_sized([btn_w, toolbar_h], Button::new("Добавить")).clicked() {
                // TODO
            }

            if ui.add_sized([btn_w, toolbar_h], Button::new("Моя раздача")).clicked() {
                // TODO
            }
        });

        ui.add_space(6.0);

        // === Публикация файла ===
        let mut do_publish = false;
        ui.horizontal(|ui| {
            let btn_w = 130.0;
            let gap = ui.spacing().item_spacing.x;
            let path_w = (ui.available_width() - btn_w - gap).max(120.0);
            let resp = ui.add(
                TextEdit::singleline(&mut self.publish_path)
                    .hint_text("󰉓  Путь к файлу для публикации…")
                    .desired_width(path_w - 4.0),
            );
            // Enter в поле = опубликовать
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                do_publish = true;
            }
            let enabled = self.publish_tx.is_some() && !self.publish_path.trim().is_empty();
            if ui.add_enabled(enabled, Button::new("󰐕  Опубликовать").min_size(egui::vec2(btn_w, 28.0))).clicked() {
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
        
        // Занимаем все оставшееся место, но задаем минимальную ширину (например, 150.0)
        let col_name_w = (ui.available_width() - fixed_width - total_spacing - 15.0).max(150.0);

        Frame::none()
            .inner_margin(egui::Margin::symmetric(6.0, 4.0))
            .fill(ui.visuals().widgets.noninteractive.bg_fill)
            .show(ui, |ui| {
                Self::table_header(ui, col_name_w); // Передаем ширину
            });

        ui.add_space(2.0);

        // === Тело таблицы ===
        let avail_h = ui.available_height() - 40.0;
        let search_lower = self.search.to_lowercase();
        let mut action: Option<(usize, RowAction)> = None;

        ScrollArea::vertical()
            .id_source("storage_scroll")
            .max_height(avail_h)
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for (i, file) in self.files.iter().enumerate() {
                    if !search_lower.is_empty()
                        && !file.name.to_lowercase().contains(&search_lower)
                    {
                        continue;
                    }

                    let frame_fill = if i % 2 == 0 {
                        ui.visuals().extreme_bg_color
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    Frame::none()
                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                        .fill(frame_fill)
                        .show(ui, |ui| {
                            ui.set_min_height(ROW_H);
                            Self::table_row(ui, i, file, &mut action, col_name_w); // Передаем ширину
                        });
                }
            });

        // === Обработка действий ===
        if let Some((idx, act)) = action {
            match act {
                RowAction::Download => self.start_download(idx),
                RowAction::Pause    => self.pause_download(idx),
                RowAction::Open     => self.open_file(idx),
                RowAction::Report   => self.report_target = Some(idx),
            }
        }

        // === Диалог репорта ===
        if let Some(idx) = self.report_target {
            let file_name = self.files[idx].name.clone();
            let mut submitted = false;

            egui::Window::new(format!("  󰀦  Жалоба: {}", file_name))
                .collapsible(false)
                .resizable(false)
                .fixed_size([360.0, 240.0])
                .show(ui.ctx(), |ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Выберите причину жалобы:")
                            .size(14.0)
                            .strong(),
                    );
                    ui.add_space(12.0);

                    let reasons = [
                        (" 󱃈  Вредоносный контент", "Вирус, троян, майнер и т.д."),
                        (" 󰶍  Мошенничество / обман", "Ложное описание файла"),
                        (" 󰇮  Неверные метаданные", "Неправильный размер или формат"),
                        (" 󰶐  Другое", "Иная причина"),
                    ];

                    for (reason, tooltip) in reasons {
                        let resp = ui.selectable_label(false, reason);
                        resp.clone().on_hover_text(tooltip);
                        if resp.clicked() {
                            submitted = true;
                        }
                    }

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        if ui.button("Отмена").clicked() {
                            self.report_target = None;
                        }
                        if ui.button("Отправить").clicked() {
                            submitted = true;
                        }
                    });
                });

            if submitted {
                self.report_target = None;
            }
        }

        // === Статус-строка ===
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let total = self.files.len();
            let complete = self
                .files
                .iter()
                .filter(|f| matches!(f.status, FileStatus::Complete | FileStatus::Seeding))
                .count();
            let loading = self
                .files
                .iter()
                .filter(|f| matches!(f.status, FileStatus::Downloading(_)))
                .count();
            let pending = self
                .files
                .iter()
                .filter(|f| matches!(f.status, FileStatus::NotStarted))
                .count();

            ui.label(
                RichText::new(format!(
                    "Файлов: {total}   |   Готово: {complete}   |   Загружается: {loading}   |   Ожидает: {pending}"
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
            // Репорт
            ui.allocate_ui(egui::vec2(COL_REPORT, HEADER_H), |ui| {
                ui.set_width(COL_REPORT);
                ui.centered_and_justified(|ui| {
                    ui.add(Label::new(RichText::new(" ").size(12.0).color(ui.visuals().weak_text_color())).wrap(false));
                });
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
            
            // Имя (Скролл + жесткая фиксация)
            ui.allocate_ui(egui::vec2(col_name_w, ROW_H), |ui| {
                ui.set_width(col_name_w); // <--- Запрещаем ячейке расширяться
                ui.with_layout(egui::Layout::left_to_right(Align::Center), |ui| {
                    ScrollArea::horizontal()
                        .id_source(format!("name_scroll_{}", idx))
                        .max_width(col_name_w) // <--- Запрещаем скроллу распирать ячейку
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
                        FileStatus::Complete | FileStatus::Seeding => ("󰈔  Открыть", RowAction::Open),
                    };
                    let btn = ui.add_sized([COL_ACTION - 4.0, 24.0], Button::new(label).wrap(false));
                    if btn.clicked() {
                        *action = Some((idx, act));
                    }
                });
            });
            // Репорт
            ui.allocate_ui(egui::vec2(COL_REPORT, ROW_H), |ui| {
                ui.set_width(COL_REPORT);
                ui.centered_and_justified(|ui| {
                    let resp = ui.add(Button::new(RichText::new("").size(14.0).color(ui.visuals().weak_text_color())).frame(false).wrap(false));
                    resp.clone().on_hover_text("Пожаловаться на файл");
                    if resp.clicked() {
                        *action = Some((idx, RowAction::Report));
                    }
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
        return "  � Yates";
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
    // Сublic библиотеки
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
}