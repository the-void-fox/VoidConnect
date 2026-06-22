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
pub const MAX_AVATAR_B64: usize = 24 * 1024;

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

/// Строит egui-картинку из base64-PNG. URI содержит хэш содержимого, поэтому
/// смена аватара инвалидирует кэш текстур egui.
pub fn image_from_b64(b64: &str) -> Option<egui::Image<'static>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let uri = format!("bytes://avatar/{:016x}.png", avatar_hash(b64));
    Some(egui::Image::from_bytes(uri, bytes))
}

/// Декодирует base64-PNG в [`egui::ColorImage`] (RGBA). Нужен для отрисовки
/// аватара в произвольном `Painter` (например, узлы графа), где виджет
/// [`egui::Image`] неприменим. `None` — битые данные.
pub fn color_image_from_b64(b64: &str) -> Option<egui::ColorImage> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
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

/// Рисует круглый аватар размера `size`. Если PNG нет или он битый — рисует
/// цветной кружок с первой буквой имени (как было до аватарок).
pub fn show_avatar(
    ui: &mut egui::Ui,
    b64: Option<&str>,
    name: &str,
    fill: egui::Color32,
    size: f32,
) {
    if let Some(img) = b64.and_then(image_from_b64) {
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
