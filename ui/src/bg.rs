//! Фоновые задачи интерфейса.
//!
//! Долгие блокирующие операции (системный диалог выбора файла, PBKDF2 при
//! смене пароля, обработка картинки аватара) нельзя выполнять в UI-потоке:
//! пока он занят, окно не отвечает на ping композитора, и система помечает его
//! «не отвечает» (Hyprland/GNOME/KDE — через несколько секунд). [`Job`]
//! запускает такую операцию в отдельном потоке и будит интерфейс, когда
//! результат готов.

use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;

/// Одна фоновая операция с результатом `T`.
pub struct Job<T> {
    rx: Option<Receiver<T>>,
}

impl<T> Default for Job<T> {
    fn default() -> Self {
        Self { rx: None }
    }
}

impl<T: Send + 'static> Job<T> {
    /// Запускает `f` в отдельном потоке. Если предыдущая операция ещё идёт,
    /// её результат будет отброшен.
    pub fn start(&mut self, ctx: &egui::Context, f: impl FnOnce() -> T + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let out = f();
            let _ = tx.send(out);
            ctx.request_repaint();
        });
        self.rx = Some(rx);
    }

    /// Идёт ли операция.
    pub fn running(&self) -> bool {
        self.rx.is_some()
    }

    /// Забирает результат, если он готов (вызывать каждый кадр).
    pub fn poll(&mut self) -> Option<T> {
        let rx = self.rx.as_ref()?;
        match rx.try_recv() {
            Ok(v) => {
                self.rx = None;
                Some(v)
            }
            Err(TryRecvError::Empty) => None,
            // Поток упал, не прислав результат: операция окончена без него.
            Err(TryRecvError::Disconnected) => {
                self.rx = None;
                None
            }
        }
    }
}

/// Системный диалог выбора файла/каталога в фоновом потоке. Синхронный
/// `rfd::FileDialog` блокирует вызывающий поток, пока диалог открыт: в
/// UI-потоке это «не отвечает» уже через несколько секунд раздумий.
///
/// На macOS диалоги обязаны жить в главном потоке — там вызываем напрямую.
pub fn pick_in_background<T: Send + 'static>(
    job: &mut Job<T>,
    ctx: &egui::Context,
    f: impl FnOnce() -> T + Send + 'static,
) {
    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(f());
        job.rx = Some(rx);
        let _ = ctx;
    }
    #[cfg(not(target_os = "macos"))]
    job.start(ctx, f);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_delivers_result_once() {
        let ctx = egui::Context::default();
        let mut job: Job<u32> = Job::default();
        assert!(!job.running());
        job.start(&ctx, || 7);
        assert!(job.running());
        let mut got = None;
        for _ in 0..200 {
            if let Some(v) = job.poll() {
                got = Some(v);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(got, Some(7));
        assert!(!job.running());
        assert_eq!(job.poll(), None);
    }

    #[test]
    fn panicked_job_stops_running() {
        let ctx = egui::Context::default();
        let mut job: Job<u32> = Job::default();
        job.start(&ctx, || panic!("тестовая паника"));
        for _ in 0..200 {
            let _ = job.poll();
            if !job.running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!job.running());
    }
}
