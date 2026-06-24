mod app;
mod avatar;
mod backend;
mod boot;
mod device_lock;
mod pages;
mod profile_store;
mod private_store;
mod settings_store;
mod sys_open;
mod verify_store;
mod vote_service;
mod widgets;

use eframe::egui;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("warn".parse().unwrap())
                .add_directive("void_discovery=info".parse().unwrap())
                .add_directive("void_chat=info".parse().unwrap())
                .add_directive("void_ui=info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    // Parse flags: --local / -l can appear anywhere in args
    let local_mode = args.iter().any(|a| a == "--local" || a == "-l");

    // --public: запуск в bootstrap-режиме (точка входа в сеть). Включает
    // bootstrap-сервер (peer-exchange) + попытку UPnP-проброса портов + бейдж.
    // Может быть включён и из настроек (settings.json) — см. ниже.
    let cli_public = args.iter().any(|a| a == "--public");

    // --bootstrap=host:port,host:port — адреса bootstrap-узлов (base_port).
    // При старте к ним подключаемся для первого знакомства с сетью (cross-LAN).
    let cli_bootstrap_addrs: Vec<String> = args.iter()
        .find_map(|a| a.strip_prefix("--bootstrap="))
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Папка данных: --data-dir=PATH или env VOID_DATA_DIR (по умолчанию ~/.config/void-connect).
    // Удобно для запуска нескольких инстансов на одной машине — у каждого свои
    // ключи, профиль, void.db и история DM. Должно быть задано ДО profile_dir().
    let data_dir_override = args.iter()
        .find_map(|a| a.strip_prefix("--data-dir="))
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("VOID_DATA_DIR").ok().map(std::path::PathBuf::from));
    if let Some(dir) = data_dir_override {
        profile_store::set_data_dir(dir);
    }

    // Сохранённые настройки (settings.json в папке данных). Их можно менять из
    // интерфейса (меню → Настройки), чтобы не запускать программу с аргументами.
    // CLI имеет приоритет: --public форсит публичный режим, --bootstrap=
    // перекрывает список узлов, второй позиционный аргумент — базовый порт.
    let settings = settings_store::load();
    let public_mode = cli_public || settings.public_mode;
    let bootstrap_addrs: Vec<String> = if cli_bootstrap_addrs.is_empty() {
        settings.bootstrap_nodes.clone()
    } else {
        cli_bootstrap_addrs
    };

    // Positional args (skip flags)
    let positional: Vec<&str> = args.iter().skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(|a| a.as_str())
        .collect();

    let base_port = positional.get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(settings.base_port);

    // Load (or create) persistent identity + profile from disk
    let mut saved = profile_store::load_or_create();

    // CLI name (first positional arg) overrides saved name
    if let Some(cli_name) = positional.first().filter(|n| !n.is_empty() && **n != "Anonymous") {
        saved.name = cli_name.to_string();
    }

    let name = if saved.name.is_empty() {
        "Anonymous".to_string()
    } else {
        saved.name.clone()
    };

    let data_dir = profile_store::profile_dir();

    // Привязка аккаунта к устройству: если папка аккаунта скопирована с другого
    // ПК — блокируем доступ ко всем функциям (бэкенд не запускаем) и показываем
    // экран с пояснением. machine-id стабилен, ложных блокировок не будет.
    if let device_lock::DeviceStatus::Locked { recorded, current } =
        device_lock::check_or_bind(&data_dir)
    {
        tracing::warn!("Аккаунт привязан к другому устройству — доступ заблокирован");
        return run_locked_ui(data_dir, recorded, current);
    }

    // Идентичность загружается отложенно в `BootApp`: если кейстор защищён
    // паролем, бэкенд не стартует, пока пользователь не введёт верный пароль.
    let params = boot::LaunchParams {
        name,
        base_port,
        local_mode,
        public_mode,
        bootstrap_addrs,
        data_dir,
        saved,
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("Void Connect"),
        ..Default::default()
    };

    eframe::run_native(
        "Void Connect",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            // Загрузчики изображений (для аватарок из PNG-байтов).
            egui_extras::install_image_loaders(&cc.egui_ctx);
            install_fonts(&cc.egui_ctx);
            cc.egui_ctx.set_pixels_per_point(1.5);

            Box::new(boot::BootApp::new(params))
        }),
    )
}

/// Устанавливает встроенный FiraCode Nerd Font (иконки nf-md/nf-fa) как первый
/// в обоих семействах. Общая настройка для рабочего и заблокированного окна.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let font_bytes = include_bytes!("assets/fonts/FiraCode.ttf").to_vec();
    fonts.font_data.insert(
        "FiraCode".to_owned(),
        egui::FontData::from_owned(font_bytes).into(),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts.families.entry(family).or_default().insert(0, "FiraCode".to_owned());
    }
    ctx.set_fonts(fonts);
}

/// Окно «доступ заблокирован»: бэкенд НЕ запускается (никаких сетевых/файловых
/// функций) — только сообщение о привязке аккаунта к другому устройству.
fn run_locked_ui(
    data_dir: std::path::PathBuf,
    recorded: String,
    current: String,
) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([580.0, 380.0])
            .with_min_inner_size([460.0, 300.0])
            .with_title("Void Connect — доступ заблокирован"),
        ..Default::default()
    };
    eframe::run_native(
        "Void Connect",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            install_fonts(&cc.egui_ctx);
            cc.egui_ctx.set_pixels_per_point(1.4);
            Box::new(LockedApp {
                data_dir: data_dir.display().to_string(),
                recorded,
                current,
            })
        }),
    )
}

struct LockedApp {
    data_dir: String,
    recorded: String,
    current:  String,
}

impl eframe::App for LockedApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let short = |s: &str| -> String {
            if s.chars().count() > 16 {
                let v: Vec<char> = s.chars().collect();
                format!("{}…{}", v[..8].iter().collect::<String>(), v[v.len()-4..].iter().collect::<String>())
            } else {
                s.to_string()
            }
        };
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(28.0);
                ui.label(
                    egui::RichText::new("\u{F0026}")
                        .size(46.0)
                        .color(egui::Color32::from_rgb(220, 150, 60)),
                );
                ui.add_space(6.0);
                ui.heading("Доступ заблокирован");
            });
            ui.add_space(14.0);
            ui.label(
                egui::RichText::new(
                    "Извините, этот аккаунт принадлежит другому устройству и не может быть \
                     перенесён. Похоже, файлы аккаунта скопированы с другого компьютера.")
                    .size(15.0),
            );
            ui.add_space(8.0);
            ui.label(
                "Удалите чужие файлы аккаунта из папки ниже и перезапустите программу — \
                 будет создан новый аккаунт. Либо запустите программу на исходном устройстве.",
            );
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Папка аккаунта:").strong());
                ui.label(egui::RichText::new(&self.data_dir).monospace());
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!(
                    "привязка: {}   |   это устройство: {}",
                    short(&self.recorded), short(&self.current)))
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(18.0);
            ui.vertical_centered(|ui| {
                if ui.add_sized([140.0, 32.0], egui::Button::new("Выход")).clicked() {
                    std::process::exit(0);
                }
            });
        });
    }
}
