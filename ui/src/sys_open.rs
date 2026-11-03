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
        // НЕ через `cmd /C start`: cmd заново разбирает командную строку, и `&`,
        // `|`, `^` в имени файла или сайта (оно приходит из сети) выполнились бы
        // как команды. explorer.exe получает цель одним аргументом, без shell.
        use std::os::windows::process::CommandExt;
        let target = target.to_string_lossy();
        // Кавычка внутри цели сломала бы границы аргумента. В путях Windows она
        // запрещена, в наших URL её нет — такую цель просто не открываем.
        if target.contains('"') {
            return false;
        }
        std::process::Command::new("explorer")
            .raw_arg(format!("\"{}\"", target))
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
