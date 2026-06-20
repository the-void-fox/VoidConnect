use eframe::egui;
use void_core::identity::NodeId;
use void_core::peer::PeerProfile;
use crate::profile_store;

pub struct ProfilePage {
    pub name:            String,
    pub description:     String,
    pub dns_name:        String,
    pub status:          String,
    pub pub_key_display: String,
    pub my_node_id:      Option<NodeId>,
    pub reputation:      f32,
    pub uptime_hours:    u32,
    pub upload_gb:       f32,
    pub download_gb:     f32,
    pub my_ip:           String,
    pub base_port:       u16,
    /// Запущены ли мы в публичном (bootstrap) режиме.
    pub bootstrap:       bool,
    connect_input:       String,
    connect_error:       Option<String>,
    connect_ok:          bool,
    pub connect_tx:      Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// Канал → backend для рассылки обновлений профиля
    pub profile_tx:      Option<tokio::sync::mpsc::UnboundedSender<PeerProfile>>,
    /// Снапшот последнего отправленного профиля (для определения изменений)
    last_sent_profile:   Option<(String, String, String)>,
    tcp_test_result:     Option<Result<String, String>>,
    tcp_test_running:    bool,
    tcp_test_rx:         Option<std::sync::mpsc::Receiver<Result<String, String>>>,
}

impl Default for ProfilePage {
    fn default() -> Self {
        Self {
            name:            "Anonymous".to_string(),
            description:     "Узел в Void Connect".to_string(),
            dns_name:        "anonymous.void".to_string(),
            status:          "online".to_string(),
            pub_key_display: "--------".to_string(),
            reputation:      0.0,
            uptime_hours:    0,
            upload_gb:       0.0,
            download_gb:     0.0,
            my_ip:           "?".to_string(),
            base_port:       7700,
            bootstrap:         false,
            my_node_id:        None,
            connect_input:     String::new(),
            connect_error:     None,
            connect_ok:        false,
            connect_tx:        None,
            profile_tx:        None,
            last_sent_profile: None,
            tcp_test_result:   None,
            tcp_test_running:  false,
            tcp_test_rx:       None,
        }
    }
}

impl ProfilePage {
    pub fn show(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                self.show_inner(ui);
            });
    }

    fn show_inner(&mut self, ui: &mut egui::Ui) {
        // Авто-отправка профиля если изменилось имя/описание/статус
        self.maybe_send_profile();

        ui.add_space(8.0);
        ui.heading("  Профиль");
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(16.0);

        if self.bootstrap {
            ui.label(
                egui::RichText::new("󰒋  Вы — Bootstrap-узел (точка входа в сеть)")
                    .strong()
                    .color(egui::Color32::from_rgb(150, 130, 230)),
            );
            ui.add_space(12.0);
        }

        // ── Аватар + основная инфо ──────────────────────────────────────────
        ui.horizontal(|ui| {
            let initials = self.name.chars().next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "?".into());
            let size = 72.0;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), size / 2.0, ui.visuals().hyperlink_color);
            ui.painter().text(
                rect.center(), egui::Align2::CENTER_CENTER, &initials,
                egui::FontId::proportional(32.0), egui::Color32::WHITE,
            );

            ui.add_space(16.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Имя:").strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.name)
                            .desired_width(200.0)
                            .char_limit(32),
                    );
                    let len = self.name.chars().count();
                    ui.label(
                        egui::RichText::new(format!("{}/32", len))
                            .small()
                            .color(if len >= 32 {
                                egui::Color32::from_rgb(220, 80, 60)
                            } else {
                                ui.visuals().weak_text_color()
                            }),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Статус:").strong());
                    egui::ComboBox::from_id_source("status_combo")
                        .selected_text(&self.status)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.status, "online".into(),  "● Online");
                            ui.selectable_value(&mut self.status, "away".into(),    "● Away");
                            ui.selectable_value(&mut self.status, "busy".into(),    "● Busy");
                            ui.selectable_value(&mut self.status, "offline".into(), "● Offline");
                        });
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(".void адрес:").strong());
                    ui.label(egui::RichText::new(&self.dns_name).monospace());
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("ID (pubkey):").strong());
                    ui.label(
                        egui::RichText::new(&self.pub_key_display)
                            .monospace()
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            });
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // ── Описание ────────────────────────────────────────────────────────
        ui.label(egui::RichText::new("О себе:").strong());
        ui.add_space(4.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.description)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("💾 Сохранить и поделиться").clicked() {
                self.send_profile();
            }
            ui.label(
                egui::RichText::new("Профиль будет разослан всем подключённым узлам")
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // ── Репутация ───────────────────────────────────────────────────────
        ui.label(egui::RichText::new("Репутация").strong());
        ui.add_space(6.0);
        let rep_color = if self.reputation > 0.7 {
            egui::Color32::from_rgb(80, 200, 80)
        } else if self.reputation > 0.4 {
            egui::Color32::from_rgb(220, 180, 40)
        } else {
            egui::Color32::from_rgb(220, 80, 60)
        };
        ui.add(
            egui::ProgressBar::new(self.reputation)
                .desired_width(300.0)
                .fill(rep_color)
                .text(format!("{:.0}%", self.reputation * 100.0)),
        );

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // ── Статистика ──────────────────────────────────────────────────────
        ui.label(egui::RichText::new("Статистика").strong());
        ui.add_space(8.0);
        egui::Grid::new("stats_grid").num_columns(2).spacing([40.0, 8.0]).show(ui, |ui| {
            ui.label("⏱ Аптайм:");
            ui.label(format!("{} ч", self.uptime_hours));
            ui.end_row();
            ui.label("⬆ Отдано:");
            ui.label(format!("{:.1} ГБ", self.upload_gb));
            ui.end_row();
            ui.label("⬇ Получено:");
            ui.label(format!("{:.1} ГБ", self.download_gb));
            ui.end_row();
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        // ── Подключение к пиру вручную ──────────────────────────────────────
        ui.label(egui::RichText::new("Подключение к пиру вручную").strong());
        ui.add_space(4.0);

        // Мой адрес — чтобы его было удобно передать другому
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Мой адрес:").color(ui.visuals().weak_text_color()));
            let my_addr = format!("{}:{}", self.my_ip, self.base_port);
            ui.label(
                egui::RichText::new(&my_addr)
                    .monospace()
                    .color(ui.visuals().hyperlink_color),
            );
            if ui.small_button("📋 Копировать").clicked() {
                ui.output_mut(|o| o.copied_text = my_addr);
            }
        });

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Если автообнаружение не сработало (Wi-Fi AP isolation, другая подсеть),\n\
                 введи адрес другого узла и нажми «Подключиться»."
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(6.0);

        // Проверяем результат фонового TCP-теста
        if let Some(rx) = &self.tcp_test_rx {
            if let Ok(result) = rx.try_recv() {
                self.tcp_test_result  = Some(result);
                self.tcp_test_running = false;
                self.tcp_test_rx      = None;
            }
        }

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.connect_input)
                    .hint_text("192.168.1.X:7700")
                    .desired_width(200.0),
            );

            let can_connect = !self.connect_input.trim().is_empty()
                && self.connect_tx.is_some();

            // Enter в поле ввода тоже подключает
            let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));

            let clicked = ui.add_enabled(can_connect, egui::Button::new("Подключиться")).clicked();
            if clicked || (enter_pressed && can_connect) {
                self.try_connect();
            }

            let can_test = !self.connect_input.trim().is_empty() && !self.tcp_test_running;
            if ui.add_enabled(can_test, egui::Button::new("🔍 Тест TCP")).clicked() {
                self.start_tcp_test();
            }
        });

        // Сообщение об ошибке / успехе подключения
        if let Some(err) = &self.connect_error {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("⚠  {}", err))
                    .color(egui::Color32::from_rgb(220, 80, 60))
                    .small(),
            );
        }
        if self.connect_ok {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("✓  Пир добавлен. Соединение устанавливается...")
                    .color(egui::Color32::from_rgb(80, 200, 80))
                    .small(),
            );
        }

        // Результат TCP-теста
        if self.tcp_test_running {
            ui.add_space(4.0);
            ui.label(egui::RichText::new("⏳ Проверяем TCP соединение...").small());
        }
        if let Some(ref result) = self.tcp_test_result {
            ui.add_space(4.0);
            match result {
                Ok(msg) => {
                    ui.label(
                        egui::RichText::new(format!("✓  {}", msg))
                            .color(egui::Color32::from_rgb(80, 200, 80))
                            .small(),
                    );
                }
                Err(msg) => {
                    ui.label(
                        egui::RichText::new(format!("✗  {}", msg))
                            .color(egui::Color32::from_rgb(220, 80, 60))
                            .small(),
                    );
                }
            }
        }

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Порты которые должны быть открыты в файрволе:\n\
                 UDP 7701  — обнаружение (broadcast)\n\
                 TCP 7702  — публичный чат"
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );

        ui.add_space(8.0);
        egui::CollapsingHeader::new(
            egui::RichText::new("▶ Инструкции по настройке файрвола").small()
        )
        .default_open(false)
        .show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(egui::RichText::new("NixOS  (/etc/nixos/modules/networking.nix):").small().strong());
            ui.add_space(2.0);
            let nixos_snippet = "networking.firewall.interfaces.\"wlan0\" = {\n  allowedTCPPorts = [ 7702 ];\n  allowedUDPPorts = [ 7701 ];\n};";
            ui.add(
                egui::TextEdit::multiline(&mut nixos_snippet.to_string())
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
            ui.add_space(4.0);
            ui.label(egui::RichText::new("После изменения: sudo nixos-rebuild switch").small().monospace());
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Ubuntu/Debian:").small().strong());
            ui.label(egui::RichText::new("sudo ufw allow 7701/udp\nsudo ufw allow 7702/tcp").small().monospace());
        });
    }

    /// Отправляет профиль, если он изменился с момента последней отправки.
    fn maybe_send_profile(&mut self) {
        let current = (self.name.clone(), self.description.clone(), self.status.clone());
        if self.last_sent_profile.as_ref() != Some(&current) {
            self.send_profile();
        }
    }

    fn send_profile(&mut self) {
        let Some(tx) = &self.profile_tx else { return };
        let Some(id) = &self.my_node_id else { return };

        // Enforce char limit before sending
        if self.name.chars().count() > 32 {
            self.name = self.name.chars().take(32).collect();
        }

        let profile = PeerProfile {
            node_id:      id.clone(),
            name:         self.name.clone(),
            description:  self.description.clone(),
            status:       self.status.clone(),
            enc_pubkey:   None,  // backend добавит enc_pubkey перед рассылкой
            is_bootstrap: false, // backend проставит флаг перед рассылкой
        };
        let _ = tx.send(profile);
        self.last_sent_profile = Some((self.name.clone(), self.description.clone(), self.status.clone()));

        // Persist to disk
        let _ = profile_store::save_profile(&profile_store::SavedProfile {
            node_id:     id.as_str().to_string(),
            name:        self.name.clone(),
            description: self.description.clone(),
            status:      self.status.clone(),
        });
    }

    fn try_connect(&mut self) {
        let input = self.connect_input.trim().to_string();
        self.connect_error = None;
        self.connect_ok    = false;

        if input.parse::<std::net::SocketAddr>().is_err() {
            self.connect_error = Some(
                "Неверный формат. Ожидается IP:порт, например 192.168.1.5:7700".into()
            );
            return;
        }

        if let Some(tx) = &self.connect_tx {
            let _ = tx.send(input.clone());
            self.connect_ok    = true;
            self.connect_input.clear();
        }
    }

    /// Запускает TCP-тест в фоновом потоке: пробует подключиться к base+2 (чат-порт)
    fn start_tcp_test(&mut self) {
        let input = self.connect_input.trim().to_string();

        // Разбираем введённый адрес: ожидаем IP:base_port
        let base_addr = match input.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(_) => {
                // Попробуем воспринять как просто IP без порта
                match input.parse::<std::net::IpAddr>() {
                    Ok(ip) => std::net::SocketAddr::new(ip, 7700),
                    Err(_) => {
                        self.tcp_test_result = Some(Err(
                            "Неверный формат адреса (ожидается IP:порт)".into()
                        ));
                        return;
                    }
                }
            }
        };

        let chat_addr = std::net::SocketAddr::new(base_addr.ip(), base_addr.port() + 2);
        let (tx, rx) = std::sync::mpsc::channel();
        self.tcp_test_rx      = Some(rx);
        self.tcp_test_running = true;
        self.tcp_test_result  = None;

        std::thread::spawn(move || {
            use std::net::TcpStream;
            use std::time::Duration;
            let timeout = Duration::from_secs(3);
            match TcpStream::connect_timeout(&chat_addr, timeout) {
                Ok(_) => {
                    let _ = tx.send(Ok(format!("TCP {}  — порт открыт!", chat_addr)));
                }
                Err(e) => {
                    let hint = if e.raw_os_error() == Some(111) {
                        " (Connection refused — порт закрыт или сервис не запущен)"
                    } else if e.raw_os_error() == Some(113) {
                        " (No route to host — файрвол блокирует. Открой TCP 7702 в файрволе)"
                    } else if e.kind() == std::io::ErrorKind::TimedOut {
                        " (Таймаут — пакеты отбрасываются, проверь файрвол)"
                    } else {
                        ""
                    };
                    let _ = tx.send(Err(format!("TCP {} — {}{}", chat_addr, e, hint)));
                }
            }
        });
    }
}
