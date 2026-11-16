//! Диалог согласия для JS API сайтов.
//!
//! Сайт просит разрешение или хочет опубликовать файл — HTTP-запрос ждёт, а
//! здесь, в окне приложения (не в браузере: подделать нельзя), пользователь
//! видит, какой сайт, чей он и что именно просит, и отвечает. Окно перекрывает
//! интерфейс, пока есть вопросы; приложение мигает в панели задач.

use std::collections::HashMap;

use eframe::egui;
use void_core::identity::NodeId;
use void_core::peer::PeerProfile;
use void_trust::{TrustLevel, TrustMap};
use void_web::{ConsentBroker, ConsentKind, ConsentRequest, Permission};

use crate::backend::SiteInfo;
use crate::theme;

/// Через сколько после появления вопроса можно нажать «Разрешить».
const ARM_DELAY: std::time::Duration = std::time::Duration::from_millis(800);

#[derive(Default)]
pub struct ConsentUi {
    /// Больший ID уже показанного вопроса — новый вопрос привлекает внимание.
    last_seen: u64,
    waker_set: bool,
}

/// Что показать о владельце сайта.
struct Owner {
    name: String,
    short: String,
    trust: (String, egui::Color32),
}

fn trust_label(level: TrustLevel) -> (String, egui::Color32) {
    match level {
        TrustLevel::Verified => ("проверен вами лично".into(), theme::OK),
        TrustLevel::Trusted => ("через ваших знакомых".into(), theme::INFO),
        TrustLevel::Settled => ("освоившийся".into(), theme::TEXT_DIM),
        TrustLevel::Stranger => ("незнакомец".into(), theme::WARN),
        TrustLevel::Blocked => ("заблокирован вами".into(), theme::ERR),
    }
}

fn human_size(bytes: u64) -> String {
    const K: f64 = 1024.0;
    let b = bytes as f64;
    if b >= K * K * K {
        format!("{:.1} ГБ", b / (K * K * K))
    } else if b >= K * K {
        format!("{:.1} МБ", b / (K * K))
    } else if b >= K {
        format!("{:.0} КБ", b / K)
    } else {
        format!("{bytes} Б")
    }
}

impl ConsentUi {
    /// Новый вопрос сайта будит интерфейс (вызывать каждый кадр — дёшево).
    pub fn attach(&mut self, ctx: &egui::Context, broker: &ConsentBroker) {
        if !self.waker_set {
            let c = ctx.clone();
            broker.set_waker(move || c.request_repaint());
            self.waker_set = true;
        }
    }

    /// Рисует диалог для самого старого вопроса (если есть).
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        broker: &ConsentBroker,
        sites: &[SiteInfo],
        profiles: &HashMap<NodeId, PeerProfile>,
        trust: &TrustMap,
        my_id: &NodeId,
    ) {
        self.attach(ctx, broker);
        let pending = broker.pending();
        let Some(req) = pending.first().cloned() else { return };
        if req.id > self.last_seen {
            self.last_seen = pending.iter().map(|r| r.id).max().unwrap_or(req.id);
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }
        // Пока вопрос открыт — следим за сроком ответа.
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        let owner = sites.iter().find(|s| s.name == req.site).map(|s| {
            let id = &s.owner;
            let short = format!("{}…{}", &id.0[..8.min(id.0.len())], &id.0[id.0.len().saturating_sub(4)..]);
            if id == my_id {
                return Owner { name: "вы".into(), short, trust: ("ваш сайт".into(), theme::OK) };
            }
            let name = profiles
                .get(id)
                .map(|p| void_core::sanitize::display_text(&p.name, 32))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "неизвестный узел".into());
            Owner { name, short, trust: trust_label(trust.level(id)) }
        });

        // Затемнение и блок кликов по остальному интерфейсу.
        let screen = ctx.screen_rect();
        egui::Area::new(egui::Id::new("site_consent_dim"))
            .order(egui::Order::Middle)
            .fixed_pos(screen.min)
            .show(ctx, |ui| {
                ui.painter().rect_filled(screen, 0.0, egui::Color32::from_black_alpha(150));
                ui.allocate_rect(screen, egui::Sense::click());
            });

        // Кнопка «Разрешить» оживает не сразу: диалог появляется внезапно, и
        // клик, начатый по другому месту окна, не должен попасть в согласие.
        let armed = req.created.elapsed() >= ARM_DELAY;
        let mut answer: Option<bool> = None;
        egui::Area::new(egui::Id::new("site_consent"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                theme::card_frame().inner_margin(egui::Margin::same(20.0)).show(ui, |ui| {
                    ui.set_width(440.0);
                    Self::body(ui, &req, owner.as_ref(), pending.len());
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new("Отклонить").min_size(egui::vec2(120.0, 32.0))).clicked() {
                            answer = Some(false);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let label = match req.kind {
                                ConsentKind::Upload { .. } => "\u{F0552}  Опубликовать",
                                ConsentKind::Permissions(_) => "\u{F012C}  Разрешить",
                            };
                            let btn = theme::primary_button(label).min_size(egui::vec2(150.0, 32.0));
                            if ui.add_enabled(armed, btn).clicked() {
                                answer = Some(true);
                            }
                        });
                    });
                });
            });
        if !armed {
            ctx.request_repaint_after(ARM_DELAY.saturating_sub(req.created.elapsed()));
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            answer = Some(false);
        }
        if let Some(allow) = answer {
            broker.answer(req.id, allow);
        }
    }

    fn body(ui: &mut egui::Ui, req: &ConsentRequest, owner: Option<&Owner>, total: usize) {
        let weak = theme::TEXT_DIM;
        ui.label(egui::RichText::new("\u{F059F}  Запрос сайта").size(12.5).color(weak));
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new(format!("{}.void", req.site))
                .font(egui::FontId::new(19.0, theme::semibold()))
                .color(theme::TEXT_STRONG),
        );
        match owner {
            Some(o) => {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(egui::RichText::new("Владелец:").color(weak));
                    ui.label(egui::RichText::new(&o.name).strong());
                    ui.label(egui::RichText::new(&o.short).monospace().size(11.0).color(theme::TEXT_FAINT));
                    ui.label(egui::RichText::new(format!("· {}", o.trust.0)).color(o.trust.1));
                });
            }
            None => {
                ui.label(egui::RichText::new("Владелец неизвестен").color(theme::WARN));
            }
        }
        ui.add_space(12.0);

        match &req.kind {
            ConsentKind::Permissions(perms) => {
                ui.label("Сайт просит разрешение:");
                ui.add_space(4.0);
                for p in perms {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new("  \u{F012C}").color(theme::ACCENT));
                        ui.label(p.describe());
                    });
                }
                ui.add_space(8.0);
                if perms.contains(&Permission::Publish) {
                    ui.label(
                        egui::RichText::new(
                            "Записи подписываются вашим ключом, их видят все, кто открывает этот \
                             сайт. Изменить или удалить их можете только вы.",
                        )
                        .small()
                        .color(weak),
                    );
                }
                ui.label(
                    egui::RichText::new(
                        "Разрешение действует только для этого сайта, пока вы его не отзовёте \
                         (вкладка «Сайты», карточка сайта). Ключи, личные сообщения и файлы на \
                         диске сайтам недоступны никогда.",
                    )
                    .small()
                    .color(weak),
                );
            }
            ConsentKind::Upload { name, size } => {
                ui.label("Сайт хочет опубликовать в сеть файл:");
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(format!("  «{}»", void_core::sanitize::display_text(name, 80))).strong());
                    ui.label(egui::RichText::new(human_size(*size)).color(weak));
                });
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(
                        "Файл станет доступен всем узлам сети от вашего имени. Публикуйте, только \
                         если сами выбрали этот файл на странице сайта.",
                    )
                    .small()
                    .color(weak),
                );
            }
        }

        let left = void_web::consent::REQUEST_TTL.saturating_sub(req.created.elapsed()).as_secs();
        ui.add_space(8.0);
        let mut tail = format!("Без ответа через {}:{:02} — отказ.", left / 60, left % 60);
        if total > 1 {
            tail.push_str(&format!("  Ещё запросов: {}.", total - 1));
        }
        ui.label(egui::RichText::new(tail).small().color(theme::TEXT_FAINT));
    }
}
