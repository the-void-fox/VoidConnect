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
    /// Ждём пароль для расшифровки ключей. `job` — идущая проверка пароля
    /// (PBKDF2 считается в фоне, чтобы окно не «зависало»).
    Unlock {
        password: String,
        error: Option<String>,
        job: crate::bg::Job<Result<void_crypto::Identity, String>>,
    },
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
                    phase: Phase::Unlock { password: String::new(), error: Some(e), job: Default::default() },
                },
            }
        }

        Self { params, phase: Phase::Unlock { password: String::new(), error: None, job: Default::default() } }
    }

    /// Загружает личность (с паролем при необходимости), стартует бэкенд, строит
    /// `VoidApp`. Возвращает понятный текст ошибки для экрана ввода.
    fn launch(params: &mut LaunchParams, password: Option<&str>) -> Result<VoidApp, String> {
        let identity = Self::load_identity(&params.data_dir, password)?;
        Ok(Self::start(params, identity))
    }

    /// Расшифровывает ключи. С паролем это PBKDF2 на 600 тыс. итераций —
    /// поэтому при вводе пароля вызывается из фонового потока.
    fn load_identity(data_dir: &std::path::Path, password: Option<&str>) -> Result<void_crypto::Identity, String> {
        void_crypto::Identity::load_or_create_with_password(data_dir, password)
            .map_err(|e| match e {
                void_crypto::CryptoError::WrongPassword => "Неверный пароль".to_string(),
                other => format!("Не удалось загрузить ключи: {other}"),
            })
    }

    /// Стартует бэкенд с уже расшифрованной личностью и строит `VoidApp`.
    fn start(params: &mut LaunchParams, identity: void_crypto::Identity) -> VoidApp {
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

        VoidApp::new(backend)
    }

    fn show_unlock(ctx: &egui::Context, password: &mut String, error: &Option<String>, busy: bool) -> bool {
        use crate::theme;
        let mut submit = false;
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(theme::BG))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space((ui.available_height() / 2.0 - 190.0).max(24.0));
                    ui.label(egui::RichText::new("\u{F02D9}").size(56.0).color(theme::ACCENT));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Void Connect")
                            .font(egui::FontId::new(24.0, theme::semibold()))
                            .color(theme::TEXT_STRONG),
                    );
                    ui.add_space(20.0);

                    theme::card_frame().inner_margin(egui::Margin::same(20.0)).show(ui, |ui| {
                        ui.set_width(300.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{F033E}  Аккаунт защищён паролем")
                                    .font(egui::FontId::new(15.0, theme::semibold()))
                                    .color(theme::TEXT_STRONG),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("Введите пароль, чтобы расшифровать ключи и войти.")
                                    .size(12.5)
                                    .color(theme::TEXT_DIM),
                            );
                            ui.add_space(14.0);

                            let resp = ui.add(
                                egui::TextEdit::singleline(password)
                                    .password(true)
                                    .hint_text("Пароль")
                                    .margin(egui::vec2(10.0, 8.0))
                                    .desired_width(f32::INFINITY),
                            );
                            // Курсор сразу в поле пароля (если фокус ни на чём другом).
                            ui.memory_mut(|m| if m.focused().is_none() { m.request_focus(resp.id) });
                            // Enter в поле = отправка.
                            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                submit = true;
                            }

                            ui.add_space(10.0);
                            let label = if busy { "Проверяю пароль…" } else { "\u{F0FC6}  Разблокировать" };
                            let unlock = theme::primary_button(label)
                                .min_size(egui::vec2(ui.available_width(), 36.0));
                            if ui.add_enabled(!busy, unlock).clicked() {
                                submit = true;
                            }

                            if let Some(err) = error {
                                ui.add_space(10.0);
                                ui.label(egui::RichText::new(format!("\u{F0026}  {err}")).color(theme::ERR));
                            }
                        });
                    });
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

        // Экран ввода пароля. Проверка пароля идёт в фоне; бэкенд стартуем
        // здесь же, в UI-потоке, когда личность расшифрована.
        let mut unlocked = None;
        if let Phase::Unlock { password, error, job } = &mut self.phase {
            match job.poll() {
                Some(Ok(identity)) => unlocked = Some(identity),
                Some(Err(e)) => {
                    password.clear();
                    *error = Some(e);
                }
                None => {}
            }
            let busy = job.running();
            if Self::show_unlock(ctx, password, error, busy) && !busy && !password.is_empty() {
                let pw = password.clone();
                let dir = self.params.data_dir.clone();
                *error = None;
                job.start(ctx, move || Self::load_identity(&dir, Some(&pw)));
            }
        }
        if let Some(identity) = unlocked {
            self.phase = Phase::Running(Box::new(Self::start(&mut self.params, identity)));
        }
    }
}
