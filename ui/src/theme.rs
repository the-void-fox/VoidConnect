//! Тема «Void»: монохром как у логотипа — почти чёрный фон, белые и серые
//! акценты; цвет только у смысла (статусы, доверие, ошибки).
//!
//! Здесь всё оформление в одном месте: палитра, шрифты (Inter для текста,
//! FiraCode Nerd Font для иконок, ID и кодов), стиль виджетов egui и
//! несколько общих элементов — заголовок страницы, карточка, главная кнопка,
//! пункт бокового меню.

use eframe::egui::{
    self, Color32, FontData, FontDefinitions, FontFamily, FontId, FontTweak, Margin, Rounding,
    Stroke, TextStyle, Vec2,
};

// ── Палитра ──────────────────────────────────────────────────────────────────

/// Фон центральной области.
pub const BG: Color32 = Color32::from_rgb(0x0D, 0x0E, 0x11);
/// Боковая панель, верхняя и нижняя полосы.
pub const BG_SIDE: Color32 = Color32::from_rgb(0x11, 0x12, 0x16);
/// Карточки и панели поверх фона.
pub const SURFACE: Color32 = Color32::from_rgb(0x16, 0x18, 0x1D);
/// Окна, всплывающие меню, кнопки в покое.
pub const SURFACE_2: Color32 = Color32::from_rgb(0x1C, 0x1F, 0x25);
/// Наведение.
pub const SURFACE_3: Color32 = Color32::from_rgb(0x25, 0x29, 0x31);
/// Рамки и разделители.
pub const BORDER: Color32 = Color32::from_rgb(0x26, 0x2A, 0x31);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(0x35, 0x3A, 0x43);

/// Основной текст, яркий текст (заголовки, выбранное), приглушённый, едва видный.
pub const TEXT: Color32 = Color32::from_rgb(0xD4, 0xD7, 0xDC);
pub const TEXT_STRONG: Color32 = Color32::from_rgb(0xF4, 0xF5, 0xF7);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x8E, 0x94, 0x9E);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x5C, 0x62, 0x6C);

/// Акцент — белый, как логотип.
pub const ACCENT: Color32 = Color32::WHITE;

/// Смысловые цвета: в сети / успех, внимание, ошибка, сведения.
pub const OK: Color32 = Color32::from_rgb(0x5B, 0xC2, 0x7E);
pub const WARN: Color32 = Color32::from_rgb(0xE2, 0xB0, 0x4A);
pub const ERR: Color32 = Color32::from_rgb(0xE5, 0x6B, 0x5D);
pub const INFO: Color32 = Color32::from_rgb(0x8F, 0xB4, 0xE8);

/// Скругления.
pub const R_WIDGET: f32 = 7.0;
pub const R_CARD: f32 = 10.0;
pub const R_WINDOW: f32 = 12.0;

/// Обводка с толщиной `f32` (литералы без суффикса иначе выводятся как f64).
fn stroke(width: f32, color: Color32) -> Stroke {
    Stroke::new(width, color)
}

/// Семейство полужирного Inter (заголовки, акценты).
pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

// ── Установка ────────────────────────────────────────────────────────────────

/// Шрифты, стиль и цвета. Вызывается один раз при создании окна.
pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_style(style());
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".into(),
        FontData::from_static(include_bytes!("assets/fonts/Inter-Regular.ttf")),
    );
    fonts.font_data.insert(
        "Inter-SemiBold".into(),
        FontData::from_static(include_bytes!("assets/fonts/Inter-SemiBold.ttf")),
    );
    let fira: &'static [u8] = include_bytes!("assets/fonts/FiraCode.ttf");
    fonts.font_data.insert("FiraCode".into(), FontData::from_static(fira));
    // Тот же FiraCode как запасной для иконок внутри текста Inter: у него другая
    // высота строки, без поправки значки «проваливаются» ниже букв.
    fonts.font_data.insert(
        "FiraCode-Icons".into(),
        FontData::from_static(fira).tweak(FontTweak {
            scale: 1.0,
            y_offset_factor: -0.04,
            y_offset: 0.0,
            baseline_offset_factor: 0.0,
        }),
    );

    let defaults = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let chain = |first: &str| -> Vec<String> {
        let mut v = vec![first.to_owned(), "FiraCode-Icons".to_owned()];
        v.extend(defaults.iter().cloned()); // эмодзи и прочее из встроенных egui
        v
    };
    fonts.families.insert(FontFamily::Proportional, chain("Inter"));
    fonts.families.insert(semibold(), chain("Inter-SemiBold"));
    fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "FiraCode".into());
    ctx.set_fonts(fonts);
}

fn style() -> egui::Style {
    let mut style = egui::Style {
        text_styles: [
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Heading, FontId::new(20.0, semibold())),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into(),
        visuals: visuals(),
        ..Default::default()
    };

    let s = &mut style.spacing;
    s.item_spacing = Vec2::new(8.0, 7.0);
    s.button_padding = Vec2::new(12.0, 5.0);
    s.interact_size = Vec2::new(36.0, 26.0);
    s.window_margin = Margin::same(16.0);
    s.menu_margin = Margin::same(6.0);
    s.indent = 16.0;
    s.icon_width = 16.0;
    s.icon_width_inner = 9.0;
    s.icon_spacing = 6.0;
    s.scroll.bar_width = 8.0;
    s.scroll.floating = true;

    style
}

fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    let round = Rounding::same(R_WIDGET);

    v.override_text_color = None;
    v.panel_fill = BG;
    v.window_fill = SURFACE_2;
    v.window_stroke = stroke(1.0, BORDER_STRONG);
    v.window_rounding = Rounding::same(R_WINDOW);
    v.window_shadow = egui::epaint::Shadow {
        offset: Vec2::new(0.0, 8.0),
        blur: 24.0,
        spread: 0.0,
        color: Color32::from_black_alpha(140),
    };
    v.popup_shadow = egui::epaint::Shadow {
        offset: Vec2::new(0.0, 4.0),
        blur: 14.0,
        spread: 0.0,
        color: Color32::from_black_alpha(120),
    };
    v.menu_rounding = Rounding::same(R_WIDGET + 1.0);
    v.extreme_bg_color = Color32::from_rgb(0x09, 0x0A, 0x0C); // поля ввода
    v.faint_bg_color = Color32::from_rgb(0x13, 0x15, 0x19);
    v.code_bg_color = SURFACE_2;
    v.hyperlink_color = Color32::from_rgb(0xC6, 0xCF, 0xDC);
    v.warn_fg_color = WARN;
    v.error_fg_color = ERR;
    v.text_cursor = stroke(2.0, ACCENT);

    // Выделение: серое поле и белый текст (белое поле спрятало бы белый текст
    // при выделении в полях ввода).
    v.selection.bg_fill = Color32::from_rgb(0x3A, 0x40, 0x4A);
    v.selection.stroke = stroke(1.0, ACCENT);

    let w = &mut v.widgets;
    // Надписи, рамки, разделители.
    w.noninteractive.bg_fill = SURFACE;
    w.noninteractive.weak_bg_fill = SURFACE;
    w.noninteractive.bg_stroke = stroke(1.0, BORDER);
    w.noninteractive.fg_stroke = stroke(1.0, TEXT);
    w.noninteractive.rounding = round;
    // Кнопки и поля в покое.
    w.inactive.bg_fill = SURFACE_2;
    w.inactive.weak_bg_fill = SURFACE_2;
    w.inactive.bg_stroke = stroke(1.0, BORDER);
    w.inactive.fg_stroke = stroke(1.0, TEXT);
    w.inactive.rounding = round;
    w.inactive.expansion = 0.0;
    // Наведение.
    w.hovered.bg_fill = SURFACE_3;
    w.hovered.weak_bg_fill = SURFACE_3;
    w.hovered.bg_stroke = stroke(1.0, BORDER_STRONG);
    w.hovered.fg_stroke = stroke(1.5, TEXT_STRONG);
    w.hovered.rounding = round;
    w.hovered.expansion = 0.0;
    // Нажатие.
    w.active.bg_fill = Color32::from_rgb(0x2E, 0x33, 0x3C);
    w.active.weak_bg_fill = Color32::from_rgb(0x2E, 0x33, 0x3C);
    w.active.bg_stroke = stroke(1.0, TEXT_DIM);
    w.active.fg_stroke = stroke(1.5, TEXT_STRONG);
    w.active.rounding = round;
    w.active.expansion = 0.0;
    // Открытое меню / раскрытый комбобокс.
    w.open.bg_fill = SURFACE_2;
    w.open.weak_bg_fill = SURFACE_2;
    w.open.bg_stroke = stroke(1.0, BORDER_STRONG);
    w.open.fg_stroke = stroke(1.0, TEXT_STRONG);
    w.open.rounding = round;

    v
}

// ── Общие элементы ───────────────────────────────────────────────────────────

/// Высота, выше которой окно не растёт (дальше — прокрутка внутри).
pub fn max_window_height(ctx: &egui::Context) -> f32 {
    (ctx.screen_rect().height() - 64.0).max(160.0)
}

/// Окно-диалог по центру: не выше экрана (дальше — прокрутка), закрывается Esc.
pub fn dialog<'a>(
    ctx: &egui::Context,
    title: impl Into<egui::WidgetText>,
    open: &'a mut bool,
) -> egui::Window<'a> {
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        *open = false;
    }
    egui::Window::new(title)
        .open(open)
        .collapsible(false)
        .resizable(false)
        .vscroll(true)
        .max_height(max_window_height(ctx))
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
}

/// Заголовок страницы: иконка, название, необязательная подпись под ним.
pub fn page_header(ui: &mut egui::Ui, icon: &str, title: &str, subtitle: Option<&str>) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(icon).size(20.0).color(TEXT_DIM));
        ui.add_space(2.0);
        ui.label(egui::RichText::new(title).font(FontId::new(20.0, semibold())).color(TEXT_STRONG));
    });
    if let Some(sub) = subtitle {
        ui.label(egui::RichText::new(sub).color(TEXT_DIM));
    }
    ui.add_space(8.0);
}

/// Рамка карточки: чуть светлее фона, тонкая граница, скругление.
pub fn card_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(SURFACE)
        .stroke(stroke(1.0, BORDER))
        .rounding(Rounding::same(R_CARD))
        .inner_margin(Margin::same(14.0))
}

/// Главная кнопка: белая с тёмным текстом — одна на экран, для основного действия.
pub fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.into()).color(BG).font(FontId::new(14.0, semibold())))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
}

/// Пункт бокового меню: иконка и подпись, выбранный — светлый фон и белая
/// полоска слева.
pub fn nav_item(ui: &mut egui::Ui, icon: &str, label: &str, selected: bool) -> egui::Response {
    let size = Vec2::new(ui.available_width(), 34.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let p = ui.painter();
        let hovered = resp.hovered();
        if selected {
            p.rect_filled(rect, Rounding::same(R_WIDGET), SURFACE_3);
            let bar = egui::Rect::from_min_size(
                rect.left_top() + Vec2::new(0.0, 8.0),
                Vec2::new(3.0, rect.height() - 16.0),
            );
            p.rect_filled(bar, Rounding::same(1.5), ACCENT);
        } else if hovered {
            p.rect_filled(rect, Rounding::same(R_WIDGET), SURFACE_2);
        }
        let color = if selected || hovered { TEXT_STRONG } else { TEXT_DIM };
        let y = rect.center().y;
        p.text(
            egui::pos2(rect.left() + 16.0, y),
            egui::Align2::LEFT_CENTER,
            icon,
            FontId::new(16.0, FontFamily::Proportional),
            color,
        );
        let font = if selected { FontId::new(14.0, semibold()) } else { FontId::new(14.0, FontFamily::Proportional) };
        p.text(egui::pos2(rect.left() + 42.0, y), egui::Align2::LEFT_CENTER, label, font, color);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Плашка-пояснение: иконка и текст на чуть подкрашенном фоне цвета `color`
/// (обычно [`WARN`] — «вы пока новичок», [`ERR`] — ошибка).
pub fn notice(ui: &mut egui::Ui, color: Color32, icon: &str, text: &str) {
    egui::Frame::none()
        .fill(color.gamma_multiply(0.07))
        .stroke(stroke(1.0, color.gamma_multiply(0.28)))
        .rounding(Rounding::same(R_WIDGET))
        .inner_margin(Margin::symmetric(10.0, 7.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(egui::RichText::new(icon).color(color));
                ui.add(egui::Label::new(egui::RichText::new(text).size(12.5).color(TEXT)).wrap(true));
            });
        });
}

/// Маленькая «таблетка» со статусом: точка и подпись.
pub fn status_pill(ui: &mut egui::Ui, color: Color32, text: &str) -> egui::Response {
    egui::Frame::none()
        .fill(color.gamma_multiply(0.12))
        .stroke(stroke(1.0, color.gamma_multiply(0.35)))
        .rounding(Rounding::same(20.0))
        .inner_margin(Margin::symmetric(10.0, 3.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(egui::RichText::new("●").size(10.0).color(color));
                ui.label(egui::RichText::new(text).size(12.5).color(TEXT_STRONG));
            });
        })
        .response
}
