//! Аватарки: обработка выбранного изображения и отрисовка из base64-PNG.
//!
//! Аватар хранится и рассылается как маленький PNG (64×64) в base64 внутри
//! профиля, поэтому при выборе картинку масштабируем и проверяем лимит размера.

use base64::Engine;
use eframe::egui;

/// Сторона квадратного аватара (в пикселях исходного PNG).
const AVATAR_SIZE: u32 = 64;
/// Лимит base64-строки аватара (~24 КБ) — чтобы профиль оставался лёгким для
/// рассылки по relay чата.
pub use void_core::peer::MAX_AVATAR_B64;
/// Максимальная сторона ЧУЖОГО аватара (свой всегда 64×64). Больше — отбрасываем
/// по заголовку, не декодируя пиксели: «PNG-бомба» весит килобайты, а
/// распаковывается в гигабайты.
const MAX_AVATAR_SIDE: u32 = 256;

/// Декодирует изображение из файла, масштабирует/обрезает до 64×64 и кодирует
/// в base64-PNG. `None` — не удалось прочитать/слишком большой результат.
pub fn process_image_file(path: &std::path::Path) -> Option<String> {
    let img = image::open(path).ok()?;
    let resized = img.resize_to_fill(
        AVATAR_SIZE,
        AVATAR_SIZE,
        image::imageops::FilterType::Lanczos3,
    );
    let mut png = Vec::new();
    resized
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .ok()?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
    if b64.len() > MAX_AVATAR_B64 {
        return None;
    }
    Some(b64)
}

/// FNV-1a хэш строки base64 — используется как ключ инвалидации кэшей текстур.
pub fn avatar_hash(b64: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in b64.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Аватар из сети безопасен для показа (размер и стороны в пределах).
pub fn is_safe_avatar(b64: &str) -> bool {
    checked_avatar_bytes(b64).is_some()
}

/// Декодирует base64 аватара из сети и проверяет размер файла и размеры
/// картинки по заголовку (без распаковки пикселей). `None` — отбросить.
fn checked_avatar_bytes(b64: &str) -> Option<Vec<u8>> {
    if b64.len() > MAX_AVATAR_B64 {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let (w, h) = image::ImageReader::new(std::io::Cursor::new(&bytes))
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()?;
    if w == 0 || h == 0 || w > MAX_AVATAR_SIDE || h > MAX_AVATAR_SIDE {
        return None;
    }
    Some(bytes)
}

/// Декодирует base64-PNG в [`egui::ColorImage`] (RGBA). Нужен для отрисовки
/// аватара в произвольном `Painter` (например, узлы графа), где виджет
/// [`egui::Image`] неприменим. `None` — битые данные.
pub fn color_image_from_b64(b64: &str) -> Option<egui::ColorImage> {
    let bytes = checked_avatar_bytes(b64)?;
    let rgba = image::load_from_memory(&bytes).ok()?.to_rgba8();
    let (w, h) = rgba.dimensions();
    Some(egui::ColorImage::from_rgba_unmultiplied(
        [w as usize, h as usize],
        rgba.as_raw(),
    ))
}

/// Рисует круглый аватар текстурой `tex_id` в произвольном painter'е.
/// Использует треугольный веер с UV, отображённым на вписанный в круг квадрат
/// картинки — даёт настоящий круглый аватар без прямоугольных углов.
pub fn paint_circle_avatar(
    painter: &egui::Painter,
    tex_id: egui::TextureId,
    center: egui::Pos2,
    radius: f32,
) {
    use egui::epaint::{Mesh, Vertex};
    const SEGMENTS: usize = 36;
    let mut mesh = Mesh::with_texture(tex_id);
    // Центр (UV в середине картинки).
    mesh.vertices.push(Vertex {
        pos: center,
        uv: egui::pos2(0.5, 0.5),
        color: egui::Color32::WHITE,
    });
    for i in 0..=SEGMENTS {
        let a = i as f32 / SEGMENTS as f32 * std::f32::consts::TAU;
        let (s, c) = a.sin_cos();
        mesh.vertices.push(Vertex {
            pos: center + egui::vec2(c * radius, s * radius),
            uv: egui::pos2(0.5 + 0.5 * c, 0.5 + 0.5 * s),
            color: egui::Color32::WHITE,
        });
    }
    for i in 1..=SEGMENTS as u32 {
        mesh.indices.extend_from_slice(&[0, i, i + 1]);
    }
    painter.add(egui::Shape::mesh(mesh));
}

/// Сколько разных аватаров держим декодированными; больше — кэш сбрасывается
/// целиком (так проще, а пересчитать десяток видимых аватаров дёшево).
const CACHE_CAP: usize = 512;

/// Проверенный и декодированный из base64 аватар: URI для egui + байты PNG.
type Decoded = Option<(String, std::sync::Arc<[u8]>)>;

/// Корзины кэша: отпечаток → (исходная строка, результат).
type Buckets = std::collections::HashMap<u64, Vec<(Box<str>, Decoded)>>;

thread_local! {
    /// Кэш аватаров UI-потока. Ключ — дешёвый отпечаток (длина + края строки),
    /// внутри корзины строка сравнивается целиком (memcmp), так что совпадение
    /// отпечатков не подменит чужой аватар.
    static CACHE: std::cell::RefCell<Buckets> = Default::default();
}

/// Отпечаток для корзины кэша: длина + первые и последние 64 байта.
fn quick_key(b64: &str) -> u64 {
    let b = b64.as_bytes();
    let mut h: u64 = 0xcbf29ce484222325 ^ b.len() as u64;
    let head = &b[..b.len().min(64)];
    let tail = &b[b.len().saturating_sub(64)..];
    for &x in head.iter().chain(tail) {
        h ^= x as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Строит egui-картинку из base64-PNG. URI содержит хэш содержимого, поэтому
/// смена аватара инвалидирует кэш текстур egui.
///
/// Результат кэшируется: без кэша каждая строка чата каждый кадр
/// заново декодировала base64 и разбирала заголовок PNG (в debug-сборке — до
/// миллисекунды на аватар, что на длинной переписке тормозило весь интерфейс).
pub fn cached_image(b64: &str) -> Option<egui::Image<'static>> {
    let key = quick_key(b64);
    let decoded = CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(hit) = cache.get(&key).and_then(|bucket| bucket.iter().find(|(src, _)| &**src == b64)) {
            return hit.1.clone();
        }
        if cache.values().map(Vec::len).sum::<usize>() >= CACHE_CAP {
            cache.clear();
        }
        let decoded: Decoded = checked_avatar_bytes(b64).map(|bytes| {
            (format!("bytes://avatar/{:016x}.png", avatar_hash(b64)), bytes.into())
        });
        cache.entry(key).or_default().push((b64.into(), decoded.clone()));
        decoded
    });
    decoded.map(|(uri, bytes)| egui::Image::from_bytes(uri, bytes))
}

/// Рисует круглый аватар размера `size`. Если PNG нет или он битый — рисует
/// цветной кружок с первой буквой имени (как было до аватарок).
pub fn show_avatar(
    ui: &mut egui::Ui,
    b64: Option<&str>,
    name: &str,
    fill: egui::Color32,
    size: f32,
) {
    if let Some(img) = b64.and_then(cached_image) {
        ui.add(img.fit_to_exact_size(egui::vec2(size, size)).rounding(size / 2.0));
        return;
    }
    let initial = name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".into());
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), size / 2.0, fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        &initial,
        egui::FontId::proportional(size * 0.45),
        egui::Color32::WHITE,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Однотонный PNG с максимальным сжатием (так собирают «PNG-бомбу»).
    fn png_b64(w: u32, h: u32) -> String {
        use image::codecs::png::{CompressionType, FilterType, PngEncoder};
        use image::ImageEncoder;
        let raw = vec![0u8; (w * h * 4) as usize];
        let mut png = Vec::new();
        PngEncoder::new_with_quality(&mut png, CompressionType::Best, FilterType::NoFilter)
            .write_image(&raw, w, h, image::ExtendedColorType::Rgba8)
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(&png)
    }

    #[test]
    fn normal_avatar_decodes() {
        let img = color_image_from_b64(&png_b64(64, 64)).expect("64×64 должен декодироваться");
        assert_eq!(img.size, [64, 64]);
    }

    #[test]
    fn oversized_dimensions_rejected_before_decoding() {
        // Однотонная 1024×1024 сжимается в PNG до килобайт (проходит лимит по
        // байтам), но в памяти — 4 МБ; при 16k×16k было бы уже 1 ГБ.
        let bomb = png_b64(1024, 1024);
        assert!(bomb.len() <= MAX_AVATAR_B64, "бомба должна пролезать в лимит по байтам");
        assert!(color_image_from_b64(&bomb).is_none());
        assert!(cached_image(&bomb).is_none());
    }

    #[test]
    fn cache_distinguishes_same_fingerprint() {
        // Одинаковые длина и края, разная середина — отпечаток совпадает,
        // но кэш обязан различить строки.
        use image::ImageEncoder;
        // Шумная картинка: base64 длиннее 128 символов, середина вне краёв.
        let raw: Vec<u8> = (0..64u32 * 64 * 4).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let mut png = Vec::new();
        image::codecs::png::PngEncoder::new(&mut png)
            .write_image(&raw, 64, 64, image::ExtendedColorType::Rgba8)
            .unwrap();
        let a = base64::engine::general_purpose::STANDARD.encode(&png);
        assert!(a.len() > 1000);
        let mut b = a.clone().into_bytes();
        let mid = b.len() / 2;
        b[mid] = if b[mid] == b'A' { b'B' } else { b'A' };
        let b = String::from_utf8(b).unwrap();
        assert_eq!(quick_key(&a), quick_key(&b));
        let ia = cached_image(&a);
        let ib = cached_image(&b);
        assert!(ia.is_some());
        // Испорченная середина либо не декодируется, либо даёт другой URI.
        if let (Some(ia), Some(ib)) = (ia, ib) {
            assert_ne!(ia.source().uri(), ib.source().uri());
        }
        // Повторный запрос берётся из кэша и указывает на тот же PNG.
        let uri = format!("bytes://avatar/{:016x}.png", avatar_hash(&a));
        assert_eq!(cached_image(&a).unwrap().source().uri(), Some(uri.as_str()));
    }

    #[test]
    fn garbage_rejected() {
        assert!(color_image_from_b64("not base64 !!!").is_none());
        assert!(color_image_from_b64(&"A".repeat(MAX_AVATAR_B64 + 4)).is_none());
    }
}
