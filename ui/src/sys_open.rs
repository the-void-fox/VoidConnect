//! Кросс-платформенное открытие URL/файла системным приложением по умолчанию.
//!
//! Раньше в UI был жёстко зашит `xdg-open` — он существует только в Linux, поэтому
//! на сборке под Windows/macOS кнопки «Открыть» (сайты, скачанные файлы) молча не
//! срабатывали. Здесь выбор обработчика по целевой ОС, без внешних зависимостей.

use std::ffi::OsStr;

/// Открывает `target` (URL или путь к файлу) в системном приложении по умолчанию.
/// Возвращает `false`, если запустить обработчик не удалось.
pub fn open_external<S: AsRef<OsStr>>(target: S) -> bool {
    let target = target.as_ref();

    #[cfg(target_os = "windows")]
    {
        // `cmd /C start "" <target>`: пустые кавычки — это заголовок окна, иначе
        // `start` трактует первый аргумент в кавычках как заголовок, а не как цель.
        std::process::Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(target)
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(target).spawn().is_ok()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(target).spawn().is_ok()
    }
}
