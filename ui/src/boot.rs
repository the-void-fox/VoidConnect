//! Загрузочная обёртка: пароль-гейт перед запуском приложения.
//!
//! Если кейстор защищён паролем ([`void_crypto::Identity::keystore_status`]),
//! бэкенд НЕ стартует, пока пользователь не введёт верный пароль (по аналогии с
//! экраном «устройство заблокировано»). Без пароля — мгновенная
//! авто-разблокировка, поведение как раньше.
//!
//! Сделано одной обёрткой `BootApp` внутри ОДНОГО `eframe::run_native`: создать
//! второй event-loop в процессе нельзя, поэтому экран ввода пароля и основное
//! приложение живут в одном `App`, переключаясь по состоянию.

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;
use void_core::identity::NodeId;
use void_crypto::identity::KeystoreState;

use crate::app::VoidApp;
use crate::backend;
use crate::profile_store::{self, SavedProfile};

/// Всё, что нужно для отложенного запуска бэкенда после разблокировки.
pub struct LaunchParams {
    pub name: String,
    pub base_port: u16,
    pub local_mode: bool,
    pub public_mode: bool,
    pub bootstrap_addrs: Vec<String>,
    pub data_dir: PathBuf,
    pub saved: SavedProfile,
}

enum Phase {
    /// Ждём пароль для расшифровки ключей.
    Unlock { password: String, error: Option<String> },
    /// Разблокировано — основное приложение.
    Running(Box<VoidApp>),
}

pub struct BootApp {
    params: LaunchParams,
    phase: Phase,
}

impl BootApp {
    /// Создаёт загрузчик. Если пароль не требуется — сразу запускает приложение.
    pub fn new(mut params: LaunchParams) -> Self {
        let needs_pw = matches!(
            void_crypto::Identity::keystore_status(&params.data_dir),
            KeystoreState::PasswordRequired
        );

        if !needs_pw {
            match Self::launch(&mut params, None) {
                Ok(app) => return Self { params, phase: Phase::Running(Box::new(app)) },
                // Маловероятно (кейстор без пароля, но не открылся) — покажем ввод.
                Err(e) => return Self {
                    params,
                    phase: Phase::Unlock { password: String::new(), error: Some(e) },
                },
            }
        }

        Self { params, phase: Phase::Unlock { password: String::new(), error: None } }
    }

    /// Загружает личность (с паролем при необходимости), стартует бэкенд, строит
    /// `VoidApp`. Возвращает понятный текст ошибки для экрана ввода.
    fn launch(params: &mut LaunchParams, password: Option<&str>) -> Result<VoidApp, String> {
        let identity = void_crypto::Identity::load_or_create_with_password(
            &params.data_dir,
            password,
        )
        .map_err(|e| match e {
            void_crypto::CryptoError::WrongPassword => "Неверный пароль".to_string(),
            other => format!("Не удалось загрузить ключи: {other}"),
        })?;

        let node_id = NodeId(identity.id.as_str().to_string());
        // Держим node_id в profile.json в синхроне с криптографическим ID.
        params.saved.node_id = identity.id.as_str().to_string();
        profile_store::save_profile(&params.saved).ok();

        let enc_kp = Arc::new(identity.encryption);
        let sign_kp = Arc::new(identity.signing);

        let backend = backend::start_backend(
            params.name.clone(),
            params.base_port,
            node_id,
            params.local_mode,
            params.public_mode,
            params.bootstrap_addrs.clone(),
            enc_kp,
            sign_kp,
            params.data_dir.clone(),
        );

        Ok(VoidApp::new(backend))
    }

    fn show_unlock(ctx: &egui::Context, password: &mut String, error: &Option<String>) -> bool {
        let mut submit = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(120.0);
                ui.heading("\u{F033E}  Void Connect");
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("Аккаунт защищён паролем")
                        .size(16.0)
                        .strong(),
                );
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(
                        "Введите пароль, чтобы расшифровать ключи и войти.",
                    )
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(16.0);

                let resp = ui.add(
                    egui::TextEdit::singleline(password)
                        .password(true)
                        .hint_text("Пароль")
                        .desired_width(260.0),
                );
                // Enter в поле = отправка.
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }

                ui.add_space(10.0);
                if ui
                    .add_sized([260.0, 32.0], egui::Button::new("\u{F0FC6}  Разблокировать"))
                    .clicked()
                {
                    submit = true;
                }

                if let Some(err) = error {
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new(format!("\u{F0026}  {err}"))
                            .color(egui::Color32::from_rgb(220, 80, 60)),
                    );
                }
            });
        });
        submit
    }
}

impl eframe::App for BootApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Уже запущено — делегируем основному приложению.
        if let Phase::Running(app) = &mut self.phase {
            app.update(ctx, frame);
            return;
        }

        // Экран ввода пароля. Намерение собираем без удержания заимствования
        // self.phase на время launch (который трогает self.params).
        let mut submit = false;
        let mut pw = String::new();
        if let Phase::Unlock { password, error } = &mut self.phase {
            submit = Self::show_unlock(ctx, password, error);
            if submit {
                pw = password.clone();
            }
        }

        if submit {
            match Self::launch(&mut self.params, Some(&pw)) {
                Ok(app) => self.phase = Phase::Running(Box::new(app)),
                Err(e) => {
                    if let Phase::Unlock { password, error } = &mut self.phase {
                        password.clear();
                        *error = Some(e);
                    }
                }
            }
        }
    }
}
