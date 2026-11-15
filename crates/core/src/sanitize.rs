//! Очистка данных, пришедших из сети, перед использованием в путях, UI и логике.
//!
//! Всё, что прислал другой узел (имя файла из манифеста, имя в профиле, хэш в
//! запросе чанка), считается враждебным: оно может содержать `../`, абсолютный
//! путь, управляющие символы или символы направления текста, маскирующие
//! расширение (`photo<U+202E>gpj.exe` выглядит как `photoexe.jpg`).

/// Максимальная длина имени файла (в символах) после очистки.
const MAX_FILE_NAME_CHARS: usize = 200;

/// Имя, которое получает файл, если от присланного ничего не осталось.
const FALLBACK_FILE_NAME: &str = "file";

/// Зарезервированные имена устройств Windows (с любым расширением).
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Расширения, открытие которых запускает код (программы, скрипты, ярлыки,
/// документы с макросами, образы дисков, которые Windows монтирует сама).
const RISKY_EXTENSIONS: &[&str] = &[
    // Windows
    "exe", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "msi", "msp", "scr", "pif", "lnk", "hta", "cpl", "reg", "url", "inf",
    "scf", "appref-ms", "library-ms", "search-ms", "settingcontent-ms",
    "docm", "xlsm", "pptm", "iso", "img", "vhd", "vhdx",
    // Unix
    "desktop", "sh", "bash", "zsh", "fish", "run", "appimage", "deb", "rpm",
    "command", "app", "dmg", "pkg",
    // Кросс-платформенные интерпретаторы
    "jar", "py", "pyw", "pl", "rb", "php",
];

/// Символ управления направлением текста (bidi) или невидимый разделитель,
/// которым маскируют расширение файла или подменяют отображаемое имя.
fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'   // zero-width + LRM/RLM
            | '\u{202A}'..='\u{202E}' // LRE/RLE/PDF/LRO/RLO
            | '\u{2060}'..='\u{2064}' // word joiner и невидимые операторы
            | '\u{2066}'..='\u{2069}' // изоляты направления
            | '\u{FEFF}'              // BOM
    )
}

/// Убирает управляющие символы и bidi-символы. Подходит для имён и коротких
/// подписей, которые показываются в интерфейсе.
pub fn strip_unsafe_chars(s: &str) -> String {
    s.chars()
        .filter(|&c| !c.is_control() && !is_bidi_or_invisible(c))
        .collect()
}

/// Обрезает строку до `max` символов (не байт — не режет UTF-8 посередине).
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

/// Очищенное имя для показа в UI: без управляющих/bidi-символов, не длиннее `max`.
pub fn display_text(s: &str, max: usize) -> String {
    truncate_chars(strip_unsafe_chars(s).trim(), max)
}

/// Превращает присланное по сети имя файла в безопасное ИМЯ (не путь).
///
/// Гарантии результата:
/// - один компонент пути: нет `/`, `\`, нет `..`, не абсолютный (на любой ОС);
/// - нет управляющих, bidi- и запрещённых в Windows символов (`<>:"|?*`);
/// - не начинается с точки (скрытые файлы вроде `.bashrc`) и не кончается
///   точкой/пробелом (Windows молча их отрезает);
/// - не совпадает с именем устройства Windows (`CON`, `NUL.txt`, …);
/// - не пустое и не длиннее [`MAX_FILE_NAME_CHARS`] символов.
pub fn safe_file_name(name: &str) -> String {
    // Берём только последний компонент — с учётом обоих разделителей.
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");

    let cleaned: String = strip_unsafe_chars(last)
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c => c,
        })
        .collect();

    let trimmed = cleaned
        .trim_start_matches(|c: char| c == '.' || c.is_whitespace())
        .trim_end_matches(|c: char| c == '.' || c.is_whitespace());

    let mut out = truncate_chars(trimmed, MAX_FILE_NAME_CHARS);
    // Обрезка могла оставить точку/пробел в конце.
    while out.ends_with(['.', ' ']) {
        out.pop();
    }

    if out.is_empty() {
        return FALLBACK_FILE_NAME.to_string();
    }

    let stem = out.split('.').next().unwrap_or("").trim_end().to_ascii_lowercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    out
}

/// `true`, если открытие файла с таким именем может запустить код. Перед
/// открытием такого файла UI должен явно спросить пользователя.
pub fn is_risky_to_open(name: &str) -> bool {
    let name = safe_file_name(name).to_ascii_lowercase();
    match name.rsplit_once('.') {
        Some((_, ext)) => RISKY_EXTENSIONS.contains(&ext),
        // Без расширения на Unix это может быть исполняемый файл.
        None => true,
    }
}

/// `true`, если строка — 64 hex-символа в нижнем регистре (SHA-256 хэш,
/// NodeId, X25519-ключ). Проверка формата на границе протокола, до того как
/// строка попадёт в путь на диске или в БД.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_and_absolute_paths_become_plain_names() {
        assert_eq!(safe_file_name("../../.bashrc"), "bashrc");
        assert_eq!(safe_file_name("/home/user/.config/autostart/x.desktop"), "x.desktop");
        assert_eq!(safe_file_name("..\\..\\Startup\\evil.bat"), "evil.bat");
        assert_eq!(safe_file_name("C:\\Windows\\win.ini"), "win.ini");
        assert_eq!(safe_file_name(".."), "file");
        assert_eq!(safe_file_name(""), "file");
        assert_eq!(safe_file_name("/"), "file");
    }

    #[test]
    fn ordinary_names_survive() {
        assert_eq!(safe_file_name("photo.jpg"), "photo.jpg");
        assert_eq!(safe_file_name("Отчёт 2026.pdf"), "Отчёт 2026.pdf");
        assert_eq!(safe_file_name("Tom & Jerry.mkv"), "Tom & Jerry.mkv");
    }

    #[test]
    fn hostile_characters_removed() {
        // RLO маскирует .exe под .jpg
        assert_eq!(safe_file_name("photo\u{202E}gpj.exe"), "photogpj.exe");
        assert_eq!(safe_file_name("a\u{0}b\nc.txt"), "abc.txt");
        assert_eq!(safe_file_name("what?.txt"), "what_.txt");
        assert_eq!(safe_file_name("name. . ."), "name");
    }

    #[test]
    fn windows_reserved_names_prefixed() {
        assert_eq!(safe_file_name("CON"), "_CON");
        assert_eq!(safe_file_name("nul.txt"), "_nul.txt");
        assert_eq!(safe_file_name("console.txt"), "console.txt");
    }

    #[test]
    fn long_names_truncated_on_char_boundary() {
        let long = "я".repeat(500);
        let out = safe_file_name(&long);
        assert_eq!(out.chars().count(), MAX_FILE_NAME_CHARS);
    }

    #[test]
    fn risky_extensions_detected() {
        assert!(is_risky_to_open("setup.exe"));
        assert!(is_risky_to_open("run.SH"));
        assert!(is_risky_to_open("x.desktop"));
        assert!(is_risky_to_open("noext"));
        assert!(is_risky_to_open("photo\u{202E}gpj.exe"));
        assert!(!is_risky_to_open("photo.jpg"));
        assert!(!is_risky_to_open("doc.pdf"));
    }

    #[test]
    fn hex64_format() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(!is_hex64(&"A".repeat(64)));
        assert!(!is_hex64(&"a".repeat(63)));
        assert!(!is_hex64("../../../../etc/passwd"));
        assert!(!is_hex64(&format!("é{}", "a".repeat(62))));
    }

    #[test]
    fn display_text_strips_and_truncates() {
        assert_eq!(display_text("  Alice\u{202E}  ", 10), "Alice");
        assert_eq!(display_text("abcdef", 3), "abc");
    }
}
