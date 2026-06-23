use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::{Button, Frame, RichText, ScrollArea};
use tokio::sync::mpsc::UnboundedSender;

use void_core::identity::NodeId;
use void_core::peer::{PeerInfo, PeerProfile};
use void_vote::{Outcome, ProposalKind};

use crate::backend::StorageFileInfo;
use crate::vote_service::ProposalView;

/// Тип создаваемого предложения (выбор в диалоге).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum NewKind {
    #[default]
    Ban,
    Unban,
    AddChannel,
    RemoveFile,
}

impl NewKind {
    fn label(&self) -> &'static str {
        match self {
            NewKind::Ban => "Бан узла",
            NewKind::Unban => "Разбан узла",
            NewKind::AddChannel => "Добавить канал",
            NewKind::RemoveFile => "Удалить файл из хранилища",
        }
    }
}

pub struct VotesPage {
    // Данные из backend.
    pub proposals:     Option<Arc<Mutex<Vec<ProposalView>>>>,
    pub propose_tx:    Option<UnboundedSender<ProposalKind>>,
    pub vote_cast_tx:  Option<UnboundedSender<(String, bool)>>,
    pub my_score:      Option<Arc<Mutex<f64>>>,
    pub peers:         Option<Arc<Mutex<Vec<PeerInfo>>>>,
    pub profiles:      Option<Arc<Mutex<HashMap<NodeId, PeerProfile>>>>,
    pub storage_files: Option<Arc<Mutex<Vec<StorageFileInfo>>>>,

    // Локальное состояние UI.
    snapshot:     Vec<ProposalView>,
    score:        f64,
    show_create:  bool,
    new_kind:     NewKind,
    target_node:  String,
    target_file:  String,
    channel_id:   String,
    channel_name: String,
}

impl Default for VotesPage {
    fn default() -> Self {
        Self {
            proposals:     None,
            propose_tx:    None,
            vote_cast_tx:  None,
            my_score:      None,
            peers:         None,
            profiles:      None,
            storage_files: None,
            snapshot:      Vec::new(),
            score:         0.0,
            show_create:   false,
            new_kind:      NewKind::default(),
            target_node:   String::new(),
            target_file:   String::new(),
            channel_id:    String::new(),
            channel_name:  String::new(),
        }
    }
}

impl VotesPage {
    fn sync(&mut self) {
        if let Some(shared) = &self.proposals {
            self.snapshot = shared.lock().unwrap().clone();
        }
        if let Some(shared) = &self.my_score {
            self.score = *shared.lock().unwrap();
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui) {
        self.sync();
        let can_propose = void_vote::can_propose(self.score);
        let can_vote = void_vote::can_vote(self.score);

        ui.horizontal(|ui| {
            ui.heading("\u{F0C30} Голосования");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(can_propose, Button::new(" \u{F0415} Создать"))
                    .on_disabled_hover_text("Нужна высокая репутация (≥ 50)")
                    .clicked()
                {
                    self.show_create = true;
                }
            });
        });

        if !can_propose {
            ui.label(
                RichText::new(format!(
                    "Создавать голосования может узел с высокой репутацией (≥ 50). Ваша: {:.0}",
                    self.score
                ))
                .small()
                .weak(),
            );
        }
        if !can_vote {
            ui.label(
                RichText::new(format!(
                    "\u{F0026} Голосовать может узел с положительной репутацией. Ваша: {:.0}",
                    self.score
                ))
                .small()
                .color(egui::Color32::from_rgb(210, 150, 60)),
            );
        }
        ui.separator();
        ui.add_space(4.0);

        let ctx = ui.ctx().clone();
        self.show_create_dialog(&ctx);

        if self.snapshot.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Пока нет голосований").weak());
            });
            return;
        }

        let now = chrono::Utc::now().timestamp();
        let votes_tx = self.vote_cast_tx.clone();
        ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            for v in &self.snapshot {
                show_proposal(ui, v, can_vote, now, &votes_tx);
                ui.add_space(8.0);
            }
        });
    }

    fn show_create_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_create {
            return;
        }
        let mut open = true;
        egui::Window::new("Создать голосование")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ctx, |ui| {
                egui::ComboBox::from_label("Тип")
                    .selected_text(self.new_kind.label())
                    .show_ui(ui, |ui| {
                        for k in [NewKind::Ban, NewKind::Unban, NewKind::AddChannel, NewKind::RemoveFile] {
                            ui.selectable_value(&mut self.new_kind, k, k.label());
                        }
                    });
                ui.add_space(6.0);

                match self.new_kind {
                    NewKind::Ban | NewKind::Unban => self.pick_node(ui),
                    NewKind::RemoveFile => self.pick_file(ui),
                    NewKind::AddChannel => {
                        ui.horizontal(|ui| {
                            ui.label("id:");
                            ui.text_edit_singleline(&mut self.channel_id);
                        });
                        ui.horizontal(|ui| {
                            ui.label("название:");
                            ui.text_edit_singleline(&mut self.channel_name);
                        });
                    }
                }

                ui.add_space(8.0);
                ui.separator();
                let ready = self.create_ready();
                ui.horizontal(|ui| {
                    if ui.add_enabled(ready, Button::new("Создать")).clicked() {
                        if let Some(kind) = self.build_kind() {
                            if let Some(tx) = &self.propose_tx {
                                let _ = tx.send(kind);
                            }
                        }
                        self.reset_form();
                        self.show_create = false;
                    }
                    if ui.button("Отмена").clicked() {
                        self.reset_form();
                        self.show_create = false;
                    }
                });
            });
        if !open {
            self.reset_form();
            self.show_create = false;
        }
    }

    fn pick_node(&mut self, ui: &mut egui::Ui) {
        let peers = self.peers.as_ref().map(|p| p.lock().unwrap().clone()).unwrap_or_default();
        let profiles = self.profiles.as_ref().map(|p| p.lock().unwrap().clone()).unwrap_or_default();
        let selected = if self.target_node.is_empty() {
            "— выберите узел —".to_string()
        } else {
            short_node(&self.target_node)
        };
        egui::ComboBox::from_label("Узел")
            .selected_text(selected)
            .show_ui(ui, |ui| {
                for p in peers.iter().filter(|p| p.id.as_str().len() == 64) {
                    let name = profiles
                        .get(&p.id)
                        .map(|pr| pr.name.clone())
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| p.name.clone());
                    let label = format!("{} ({})", name, short_node(p.id.as_str()));
                    ui.selectable_value(&mut self.target_node, p.id.as_str().to_string(), label);
                }
            });
    }

    fn pick_file(&mut self, ui: &mut egui::Ui) {
        let files = self.storage_files.as_ref().map(|f| f.lock().unwrap().clone()).unwrap_or_default();
        let selected = if self.target_file.is_empty() {
            "— выберите файл —".to_string()
        } else {
            files
                .iter()
                .find(|f| f.file_id == self.target_file)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| short_node(&self.target_file))
        };
        egui::ComboBox::from_label("Файл")
            .selected_text(selected)
            .show_ui(ui, |ui| {
                for f in &files {
                    ui.selectable_value(&mut self.target_file, f.file_id.clone(), f.name.clone());
                }
            });
    }

    fn create_ready(&self) -> bool {
        match self.new_kind {
            NewKind::Ban | NewKind::Unban => !self.target_node.is_empty(),
            NewKind::RemoveFile => !self.target_file.is_empty(),
            NewKind::AddChannel => {
                !self.channel_id.trim().is_empty() && !self.channel_name.trim().is_empty()
            }
        }
    }

    fn build_kind(&self) -> Option<ProposalKind> {
        Some(match self.new_kind {
            NewKind::Ban => ProposalKind::BanUser { target: self.target_node.clone() },
            NewKind::Unban => ProposalKind::UnbanUser { target: self.target_node.clone() },
            NewKind::RemoveFile => ProposalKind::RemoveFile { file_id: self.target_file.clone() },
            NewKind::AddChannel => ProposalKind::AddChannel {
                id: self.channel_id.trim().to_string(),
                name: self.channel_name.trim().to_string(),
                icon: "\u{F04C2}".to_string(),
            },
        })
    }

    fn reset_form(&mut self) {
        self.target_node.clear();
        self.target_file.clear();
        self.channel_id.clear();
        self.channel_name.clear();
    }
}

fn show_proposal(
    ui: &mut egui::Ui,
    v: &ProposalView,
    can_vote: bool,
    now: i64,
    votes_tx: &Option<UnboundedSender<(String, bool)>>,
) {
    Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&v.label).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (txt, color) = outcome_badge(v);
                ui.label(RichText::new(txt).small().strong().color(color));
            });
        });

        let status = if v.open {
            format!("осталось {}", time_left(v.closes_at, now))
        } else if v.finalized {
            "завершено".to_string()
        } else {
            "подсчёт…".to_string()
        };
        ui.label(
            RichText::new(format!("автор {} · {}", v.proposer_short, status))
                .small()
                .weak(),
        );

        ui.add_space(2.0);
        let total = v.eligible.max(1);
        let frac = v.yes as f32 / total as f32;
        ui.add(egui::ProgressBar::new(frac).text(format!("За {} / Против {}", v.yes, v.no)));

        let p = void_vote::params(&v.kind);
        ui.label(
            RichText::new(format!(
                "участников: {} (нужно {}) · высокореп.: {} (нужно {}) · порог: {}",
                v.eligible,
                p.min_voters,
                v.high,
                p.min_high,
                if p.supermajority { "⅔" } else { ">½" },
            ))
            .small()
            .weak(),
        );

        if v.open {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let yes_sel = v.my_vote == Some(true);
                let no_sel = v.my_vote == Some(false);
                if ui
                    .add_enabled(can_vote, egui::SelectableLabel::new(yes_sel, " \u{F012C} За "))
                    .clicked()
                {
                    if let Some(tx) = votes_tx {
                        let _ = tx.send((v.id.clone(), true));
                    }
                }
                if ui
                    .add_enabled(can_vote, egui::SelectableLabel::new(no_sel, " \u{F0156} Против "))
                    .clicked()
                {
                    if let Some(tx) = votes_tx {
                        let _ = tx.send((v.id.clone(), false));
                    }
                }
                if let Some(c) = v.my_vote {
                    ui.label(
                        RichText::new(format!("ваш голос: {}", if c { "за" } else { "против" }))
                            .small()
                            .weak(),
                    );
                }
            });
        }
    });
}

fn outcome_badge(v: &ProposalView) -> (&'static str, egui::Color32) {
    if v.open {
        return ("идёт", egui::Color32::from_rgb(90, 150, 220));
    }
    match v.outcome {
        Outcome::Passed => ("принято", egui::Color32::from_rgb(80, 180, 80)),
        Outcome::Rejected => ("отклонено", egui::Color32::from_rgb(210, 140, 60)),
        Outcome::NoQuorum => ("нет кворума", egui::Color32::from_rgb(150, 150, 150)),
    }
}

fn short_node(s: &str) -> String {
    format!("{}…", &s[..8.min(s.len())])
}

fn time_left(closes_at: i64, now: i64) -> String {
    let secs = (closes_at - now).max(0);
    if secs >= 86_400 {
        format!("{} д {} ч", secs / 86_400, (secs % 86_400) / 3600)
    } else if secs >= 3600 {
        format!("{} ч {} мин", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{} мин", secs / 60)
    }
}
