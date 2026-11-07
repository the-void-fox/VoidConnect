use eframe::egui;
use void_core::peer::{PeerInfo, PeerProfile};
use void_db::peers::ReportRow;
use void_reputation::ReportReason;
use void_trust::TrustLevel;

use crate::trust_ui::TrustView;

/// Поручительство, выбранное в попапе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VouchAction {
    /// Поручиться лично (код безопасности совпал) — или опубликовать старую отметку.
    Vouch,
    /// Отозвать поручительство (или снять локальную отметку).
    Revoke,
}

/// Действие, выбранное пользователем в попапе профиля узла.
#[derive(Default)]
pub struct PeerPopupAction {
    /// Нажата «Начать беседу».
    pub start_dm: bool,
    /// Выбрана причина жалобы на узел.
    pub report: Option<ReportReason>,
    /// Поручиться / отозвать.
    pub vouch: Option<VouchAction>,
    /// `Some(true)` — заблокировать, `Some(false)` — разблокировать.
    pub block: Option<bool>,
}

/// Подпись и цвет уровня доверия.
fn trust_badge(view: &TrustView) -> (String, egui::Color32) {
    match view.info.level {
        TrustLevel::Verified if view.private_mark => (
            "󰄬  Проверен лично (не опубликовано)".into(),
            egui::Color32::from_rgb(80, 190, 110),
        ),
        TrustLevel::Verified => ("󰄬  Проверен лично".into(), egui::Color32::from_rgb(80, 190, 110)),
        TrustLevel::Trusted => {
            let mut names = view.via_names.join(", ");
            if names.is_empty() {
                names = "общие контакты".into();
            }
            (format!("󰡉  Через знакомых: {names}"), egui::Color32::from_rgb(120, 170, 220))
        }
        TrustLevel::Settled => ("Освоившийся".into(), egui::Color32::from_rgb(170, 160, 120)),
        TrustLevel::Stranger if view.info.reported => {
            ("󰀦  Незнакомец · под жалобами".into(), egui::Color32::from_rgb(220, 140, 60))
        }
        TrustLevel::Stranger => ("Незнакомец".into(), egui::Color32::from_gray(140)),
        TrustLevel::Blocked => ("󰂭  Заблокирован".into(), egui::Color32::from_rgb(220, 80, 60)),
    }
}

pub fn status_colors(status: Option<&str>) -> (egui::Color32, egui::Color32) {
    match status {
        Some("online")  => (egui::Color32::from_rgb(35, 130, 70),  egui::Color32::from_rgb(80, 200, 80)),
        Some("away")    => (egui::Color32::from_rgb(130, 110, 20), egui::Color32::from_rgb(220, 180, 40)),
        Some("busy")    => (egui::Color32::from_rgb(130, 40, 40),  egui::Color32::from_rgb(220, 80, 60)),
        Some("offline") => (egui::Color32::from_rgb(60, 60, 60),   egui::Color32::from_gray(120)),
        _               => (egui::Color32::from_rgb(35, 130, 70),  egui::Color32::from_rgb(80, 200, 80)),
    }
}

/// Показывает профиль пира. Возвращает выбранное действие (начать беседу /
/// пожаловаться).
pub fn show_peer_profile(
    ui:         &mut egui::Ui,
    peer:       Option<&PeerInfo>,
    profile:    Option<&PeerProfile>,
    reputation: Option<f64>,
    reports:    &[ReportRow],
    banned:     bool,
    my_id:      &str,
    trust:      Option<&TrustView>,
) -> PeerPopupAction {
    let name        = profile.map(|p| p.name.as_str())
        .or_else(|| peer.map(|p| p.name.as_str()))
        .unwrap_or("?");
    let description = profile.map(|p| p.description.as_str()).unwrap_or("");
    let status      = profile.map(|p| p.status.as_str()).unwrap_or("online");
    let has_dm_key  = profile.and_then(|p| p.enc_pubkey.as_ref()).is_some();
    let is_bootstrap = profile.map(|p| p.is_bootstrap).unwrap_or(false);
    let mut vouch = None;

    // Avatar + name/status row
    ui.horizontal(|ui| {
        let (fill, _) = status_colors(Some(status));
        let avatar = profile.and_then(|p| p.avatar_png.as_deref());
        crate::avatar::show_avatar(ui, avatar, name, fill, 56.0);

        ui.add_space(12.0);
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(name).strong().size(16.0));
            ui.add_space(2.0);
            let status_label = match status {
                "online"  => "Online",
                "away"    => "Away",
                "busy"    => "Busy",
                "offline" => "Offline",
                _         => "Online",
            };
            let (_, stroke) = status_colors(Some(status));
            ui.label(egui::RichText::new(format!("● {}", status_label)).color(stroke).small());

            if has_dm_key {
                ui.label(
                    egui::RichText::new("󰌾 E2E шифрование доступно")
                        .small()
                        .color(egui::Color32::from_rgb(80, 200, 80)),
                );
            }
            if is_bootstrap {
                ui.label(
                    egui::RichText::new("󰒋  Bootstrap-узел")
                        .small()
                        .strong()
                        .color(egui::Color32::from_rgb(150, 130, 230)),
                );
            }
            if banned {
                ui.label(
                    egui::RichText::new("󰂭  Забанен голосованием")
                        .small()
                        .strong()
                        .color(egui::Color32::from_rgb(220, 80, 60)),
                );
            }
            if let Some(view) = trust {
                let (label, color) = trust_badge(view);
                ui.label(egui::RichText::new(label).small().strong().color(color));
            }
        });
    });

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(6.0);

    // Network info
    if let Some(peer) = peer {
        egui::Grid::new("peer_info_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.label(egui::RichText::new("IP:").strong());
            ui.label(egui::RichText::new(peer.ip.to_string()).monospace());
            ui.end_row();

            ui.label(egui::RichText::new("Порт:").strong());
            ui.label(egui::RichText::new(peer.port.to_string()).monospace());
            ui.end_row();

            let id_str = peer.id.as_str();
            let id_short = if id_str.len() >= 12 {
                format!("{}...{}", &id_str[..8], &id_str[id_str.len()-4..])
            } else {
                id_str.to_string()
            };
            ui.label(egui::RichText::new("ID:").strong());
            ui.label(egui::RichText::new(id_short).monospace().color(ui.visuals().weak_text_color()));
            ui.end_row();
        });
    } else {
        ui.label(
            egui::RichText::new("Узел не в сети")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
    }

    // ── Проверка контакта (safety number) ────────────────────────────────────
    let peer_id = peer.map(|p| p.id.as_str())
        .or_else(|| profile.map(|p| p.node_id.as_str()));
    let verified = trust.is_some_and(|t| t.info.level == TrustLevel::Verified);
    let private_mark = trust.is_some_and(|t| t.private_mark);
    if let (Some(pid), Some(_)) = (peer_id, trust) {
        if !my_id.is_empty() && pid != my_id {
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);
            let header = if verified {
                egui::RichText::new("󰄬  Проверка контакта: подтверждён")
                    .color(egui::Color32::from_rgb(80, 190, 110))
            } else {
                egui::RichText::new("󰀦  Проверка контакта: не подтверждён")
                    .color(egui::Color32::from_rgb(220, 170, 70))
            };
            egui::CollapsingHeader::new(header).id_source("peer_verify").show(ui, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Имена не удостоверены — кто угодно может назваться так же. Сверьте эти \
                         цифры с собеседником по другому каналу (звонок, личная встреча). \
                         Совпали — поручитесь за контакт. Если код вдруг изменился — \
                         возможна подмена личности.",
                    )
                    .small()
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(4.0);
                let code = void_crypto::verify::safety_number(my_id, pid);
                ui.label(egui::RichText::new(&code).monospace().size(15.0));
                ui.add_space(6.0);
                if private_mark {
                    ui.label(
                        egui::RichText::new(
                            "Отметка стоит только у вас. Опубликуйте её, чтобы она стала \
                             поручительством и помогала доверию к контакту у ваших знакомых.",
                        )
                        .small()
                        .color(ui.visuals().weak_text_color()),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Опубликовать поручительство").clicked() {
                            vouch = Some(VouchAction::Vouch);
                        }
                        if ui.button("Снять отметку").clicked() {
                            vouch = Some(VouchAction::Revoke);
                        }
                    });
                } else if verified {
                    if ui.button("Отозвать поручительство").clicked() {
                        vouch = Some(VouchAction::Revoke);
                    }
                } else {
                    ui.label(
                        egui::RichText::new(
                            "Поручительство публично: его увидят другие узлы, и ваше доверие \
                             к контакту войдёт в их расчёт. Ручайтесь только за тех, с кем \
                             сверили код.",
                        )
                        .small()
                        .color(ui.visuals().weak_text_color()),
                    );
                    if ui.button("󰄬  Поручиться: код совпал").clicked() {
                        vouch = Some(VouchAction::Vouch);
                    }
                }
            });
        }
    }

    // Качество раздачи (локальная репутация: валидные/битые чанки, отдача).
    if let Some(score) = reputation {
        use void_reputation::ReputationLevel;
        let (label, color) = match ReputationLevel::from_score(score) {
            ReputationLevel::High     => ("Высокая",       egui::Color32::from_rgb(80, 180, 100)),
            ReputationLevel::Normal   => ("Обычная",       egui::Color32::from_rgb(120, 170, 220)),
            ReputationLevel::Low      => ("Низкая",        egui::Color32::from_rgb(200, 160, 70)),
            ReputationLevel::Negative => ("Отрицательная", egui::Color32::from_rgb(220, 80, 60)),
        };
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Качество раздачи:").strong());
            ui.label(egui::RichText::new(format!("{label}  ({score:.1})")).color(color));
        })
        .response
        .on_hover_text("Как этот узел отдаёт вам файлы: проверенные и битые части. \
                        На доверие и голосования не влияет.");
    }

    if !description.is_empty() {
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(egui::RichText::new("О себе:").strong());
        ui.add_space(2.0);
        ui.label(description);
    }

    // Жалобы на узел (дошедшие до нас по gossip). Сворачиваемый список.
    ui.add_space(6.0);
    ui.separator();
    ui.add_space(4.0);
    let reports_header = if reports.is_empty() {
        "󰀦  Жалобы: нет".to_string()
    } else {
        format!("󰀦  Жалобы: {}", reports.len())
    };
    egui::CollapsingHeader::new(reports_header)
        .enabled(!reports.is_empty())
        .id_source("peer_reports")
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Показаны только жалобы, дошедшие до вашего узла.")
                    .small()
                    .italics()
                    .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(2.0);
            for r in reports {
                let reason = match r.reason.as_str() {
                    "spam" => "спам",
                    "malicious_content" => "вредоносный контент",
                    "bad_chunks" => "битые файлы",
                    other => other,
                };
                let who = &r.reporter_key[..8.min(r.reporter_key.len())];
                let when = r.created_at.get(..10).unwrap_or(&r.created_at);
                ui.label(
                    egui::RichText::new(format!("• {} — {} ({}…)", when, reason, who)).small(),
                );
            }
        });

    // Кнопка "Начать беседу"
    ui.add_space(10.0);
    ui.separator();
    ui.add_space(6.0);

    let btn = egui::Button::new("󰭹  Начать беседу")
        .min_size(egui::vec2(ui.available_width(), 32.0));
    let resp = ui.add_enabled(peer.is_some() || profile.is_some(), btn);
    let clicked = resp.clicked();
    if resp.hovered() && !has_dm_key {
        resp.on_hover_text("Ключ шифрования ещё не получен. Подожди немного.");
    }

    // Жалоба на узел
    ui.add_space(4.0);
    let mut report = None;
    ui.menu_button("  󰀦  Пожаловаться", |ui| {
        if ui.button(" 󱃈  Спам").clicked() {
            report = Some(ReportReason::Spam);
            ui.close_menu();
        }
        if ui.button(" 󰶍  Вредоносный контент").clicked() {
            report = Some(ReportReason::MaliciousContent);
            ui.close_menu();
        }
        if ui.button(" 󰇮  Битые файлы").clicked() {
            report = Some(ReportReason::BadChunks);
            ui.close_menu();
        }
    });

    // Блокировка: личка и сообщения в чате от узла не показываются (локально).
    let mut block = None;
    if let (Some(view), Some(pid)) = (trust, peer_id) {
        if !my_id.is_empty() && pid != my_id {
            ui.add_space(4.0);
            if view.blocked_by_me {
                if ui.button("Разблокировать").clicked() {
                    block = Some(false);
                }
            } else if ui.button("  \u{F00AD}  Заблокировать")
                .on_hover_text("Его личные сообщения и сообщения в чате перестанут показываться. \
                                Решение только ваше — в сеть оно не уходит.")
                .clicked()
            {
                block = Some(true);
            }
        }
    }

    PeerPopupAction { start_dm: clicked, report, vouch, block }
}
