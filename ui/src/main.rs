mod app;
mod backend;
mod pages;
mod profile_store;
mod private_store;
mod widgets;

use eframe::egui;
use void_core::identity::NodeId;

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
    let public_mode = args.iter().any(|a| a == "--public");

    // --bootstrap=host:port,host:port — адреса bootstrap-узлов (base_port).
    // При старте к ним подключаемся для первого знакомства с сетью (cross-LAN).
    let bootstrap_addrs: Vec<String> = args.iter()
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

    // Positional args (skip flags)
    let positional: Vec<&str> = args.iter().skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(|a| a.as_str())
        .collect();

    let base_port = positional.get(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(7700u16);

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
    let identity = void_crypto::Identity::load_or_create(&data_dir)
        .expect("Failed to load or create crypto identity");
    let node_id = NodeId(identity.id.as_str().to_string());
    // Keep profile.json node_id in sync with the real crypto-derived ID
    saved.node_id = identity.id.as_str().to_string();
    profile_store::save_profile(&saved).ok();

    // Оборачиваем keypair'ы в Arc, чтобы шарить между backend и GUI.
    let enc_kp = std::sync::Arc::new(identity.encryption);
    // Ключ подписи сообщений общего чата (его pubkey == node_id).
    let sign_kp = std::sync::Arc::new(identity.signing);

    let backend = backend::start_backend(name, base_port, node_id, local_mode, public_mode, bootstrap_addrs, enc_kp, sign_kp, data_dir);

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

            let mut fonts = egui::FontDefinitions::default();
            let font_bytes = include_bytes!("assets/fonts/FiraCode.ttf").to_vec();
            fonts.font_data.insert(
                "FiraCode".to_owned(),
                egui::FontData::from_owned(font_bytes).into(),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "FiraCode".to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "FiraCode".to_owned());
            cc.egui_ctx.set_fonts(fonts);
            cc.egui_ctx.set_pixels_per_point(1.5);

            Box::new(app::VoidApp::new(backend))
        }),
    )
}
