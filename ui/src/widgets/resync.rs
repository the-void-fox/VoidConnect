//! Кнопка «Переспросить соседей»: соседи присылают заново списки файлов,
//! сайтов, имён `.void` и данные сайтов — если что-то не дошло (сайт
//! открывается не полностью, файла не видно в хранилище).

use std::sync::{Arc, Mutex};

use eframe::egui;
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::ResyncStatus;
use crate::theme;

/// Сколько секунд показывать итог последнего запроса.
const SHOW_RESULT_SECS: u64 = 20;

/// Связь кнопки с backend.
#[derive(Clone)]
pub struct Resync {
    pub tx: UnboundedSender<()>,
    pub status: Arc<Mutex<ResyncStatus>>,
}

/// «1 файл», «2 файла», «5 файлов».
fn plural(n: i64, one: &str, few: &str, many: &str) -> String {
    let (m10, m100) = (n.abs() % 10, n.abs() % 100);
    let word = if m10 == 1 && m100 != 11 {
        one
    } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
        few
    } else {
        many
    };
    format!("{n} {word}")
}

/// Текст итога и его цвет (`None` — показывать нечего).
fn summary(status: &ResyncStatus) -> Option<(String, egui::Color32)> {
    match status {
        ResyncStatus::Idle | ResyncStatus::Running => None,
        ResyncStatus::NoNeighbors => Some((
            "\u{F0026}  Нет связи с соседями — спросить некого.".into(),
            theme::WARN,
        )),
        ResyncStatus::Done { at, .. } if at.elapsed().as_secs() > SHOW_RESULT_SECS => None,
        ResyncStatus::Done { neighbors, new_files, new_sites, .. } => {
            // «Спросили 1 соседа / 3 соседей» — винительный падеж.
            let asked = plural(*neighbors as i64, "соседа", "соседей", "соседей");
            let mut got = Vec::new();
            if *new_files > 0 {
                got.push(format!("+{}", plural(*new_files, "файл", "файла", "файлов")));
            }
            if *new_sites > 0 {
                got.push(format!("+{}", plural(*new_sites, "сайт", "сайта", "сайтов")));
            }
            Some(if got.is_empty() {
                (format!("\u{F012C}  Спросили {asked} — нового нет, у вас всё актуально."), theme::TEXT_DIM)
            } else {
                (format!("\u{F012C}  Спросили {asked}, пришло: {}.", got.join(", ")), theme::OK)
            })
        }
    }
}

/// Ширина кнопки (чтобы соседние поля могли занять остальное).
pub const BUTTON_WIDTH: f32 = 252.0;

/// Кнопка. Возвращает текст итога, если его стоит показать под строкой.
pub fn button(ui: &mut egui::Ui, r: &Resync) -> Option<(String, egui::Color32)> {
    let status = r.status.lock().map(|s| s.clone()).unwrap_or_default();
    let running = status == ResyncStatus::Running;
    let label = if running { "\u{F0450}  Спрашиваю…" } else { "\u{F0450}  Переспросить соседей" };
    let resp = ui
        .add_enabled(!running, egui::Button::new(label).min_size(egui::vec2(BUTTON_WIDTH, 28.0)))
        .on_hover_text(
            "Попросить соседей прислать заново списки файлов, сайтов, имён .void и данные \
             сайтов. Помогает, если чего-то не видно или сайт открывается не полностью.",
        );
    if resp.clicked() {
        if let Ok(mut s) = r.status.lock() {
            *s = ResyncStatus::Running;
        }
        let _ = r.tx.send(());
    }
    summary(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_plurals() {
        assert_eq!(plural(1, "файл", "файла", "файлов"), "1 файл");
        assert_eq!(plural(3, "файл", "файла", "файлов"), "3 файла");
        assert_eq!(plural(5, "файл", "файла", "файлов"), "5 файлов");
        assert_eq!(plural(11, "файл", "файла", "файлов"), "11 файлов");
        assert_eq!(plural(21, "файл", "файла", "файлов"), "21 файл");
        assert_eq!(plural(112, "файл", "файла", "файлов"), "112 файлов");
    }

    #[test]
    fn summary_texts() {
        let at = std::time::Instant::now();
        let done = |f, s| ResyncStatus::Done { neighbors: 2, new_files: f, new_sites: s, at };
        assert!(summary(&done(0, 0)).unwrap().0.contains("нового нет"));
        assert!(summary(&done(3, 1)).unwrap().0.contains("+3 файла, +1 сайт"));
        assert!(summary(&done(0, 0)).unwrap().0.contains("Спросили 2 соседей"));
        let one = ResyncStatus::Done { neighbors: 1, new_files: 0, new_sites: 0, at };
        assert!(summary(&one).unwrap().0.contains("Спросили 1 соседа"));
        assert!(summary(&ResyncStatus::Running).is_none());
        assert!(summary(&ResyncStatus::NoNeighbors).unwrap().0.contains("Нет связи"));
    }
}
