//! Сеть доверия для страниц GUI (чат, граф): уровень узла, имена поручителей,
//! команды «поручиться / отозвать / заблокировать».

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;
use void_core::identity::NodeId;
use void_core::peer::PeerProfile;
use void_trust::store::Activity;
use void_trust::{TrustInfo, TrustMap};

use crate::backend::{TrustCmd, TrustDetails};

/// Цвет подсказок «вы пока новичок».
pub const NEWCOMER_HINT: eframe::egui::Color32 = eframe::egui::Color32::from_rgb(200, 160, 70);

/// За нас никто не поручился — для других узлов мы незнакомец.
pub fn is_newcomer(my_vouchers: &Option<Arc<AtomicUsize>>) -> bool {
    my_vouchers.as_ref().is_some_and(|n| n.load(Ordering::Relaxed) == 0)
}

/// Подсказка новичку: почему другие узлы могут не принять действие.
pub fn newcomer_hint(ui: &mut eframe::egui::Ui, text: &str) {
    ui.label(eframe::egui::RichText::new(format!("\u{F0026}  {text}")).small().color(NEWCOMER_HINT));
}

/// Доступ к снимку доверия backend (общий для страниц).
#[derive(Clone)]
pub struct TrustUi {
    pub map: Arc<Mutex<TrustMap>>,
    /// Неопубликованные отметки «проверен».
    pub private: Arc<Mutex<HashSet<NodeId>>>,
    /// Доступ к личке (в нём — заблокированные мной).
    pub access: Arc<Mutex<crate::dm_access::DmAccess>>,
    /// Мои приветствия и наблюдения за узлами.
    pub details: Arc<Mutex<TrustDetails>>,
    /// Включена роль встречающего (настройка).
    pub greeter: Arc<AtomicBool>,
    /// Сколько узлов поручились за нас (0 — мы новичок для других).
    pub my_vouchers: Arc<AtomicUsize>,
    pub tx: UnboundedSender<TrustCmd>,
}

/// Что показать о доверии к узлу.
pub struct TrustView {
    pub info: TrustInfo,
    /// Имена самых весомых поручителей («через знакомых: Аня, Вика»).
    pub via_names: Vec<String>,
    /// Отметка «проверен» есть, но только у нас (не опубликована).
    pub private_mark: bool,
    /// Заблокирован мной.
    pub blocked_by_me: bool,
    /// Я его поприветствовал (как встречающий).
    pub greeted_by_me: bool,
    /// Что мой узел видел за ним (для «когда освоится»).
    pub activity: Option<Activity>,
    /// Включена роль встречающего — показывать «Поприветствовать».
    pub greeter_mode: bool,
    /// Мы сами новичок: наши жалобы другие узлы не учтут.
    pub i_am_newcomer: bool,
}

impl TrustUi {
    pub fn view(&self, id: &NodeId, profiles: &HashMap<NodeId, PeerProfile>) -> TrustView {
        let info = match self.map.lock() {
            Ok(map) => map.get(id),
            Err(_) => TrustMap::default().get(id),
        };
        let private_mark = self.private.lock().map(|p| p.contains(id)).unwrap_or(false);
        let blocked_by_me = self.access.lock().map(|a| a.blocked.contains(id.as_str())).unwrap_or(false);
        let via_names = info
            .via
            .iter()
            .map(|v| {
                profiles
                    .get(v)
                    .map(|p| p.name.clone())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| format!("{}…", &v.as_str()[..8.min(v.as_str().len())]))
            })
            .collect();
        let (greeted_by_me, activity) = self.details.lock()
            .map(|d| (d.greeted.contains(id), d.activity.get(id).copied()))
            .unwrap_or_default();
        TrustView {
            info, via_names, private_mark, blocked_by_me, greeted_by_me, activity,
            greeter_mode: self.is_greeter(),
            i_am_newcomer: self.my_vouchers.load(Ordering::Relaxed) == 0,
        }
    }

    pub fn is_greeter(&self) -> bool {
        self.greeter.load(Ordering::Relaxed)
    }

    pub fn send(&self, cmd: TrustCmd) {
        let _ = self.tx.send(cmd);
    }
}
