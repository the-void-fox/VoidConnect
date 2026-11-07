//! Сеть доверия для страниц GUI (чат, граф): уровень узла, имена поручителей,
//! команды «поручиться / отозвать».

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;
use void_core::identity::NodeId;
use void_core::peer::PeerProfile;
use void_trust::{TrustInfo, TrustMap};

use crate::backend::TrustCmd;

/// Доступ к снимку доверия backend (общий для страниц).
#[derive(Clone)]
pub struct TrustUi {
    pub map: Arc<Mutex<TrustMap>>,
    /// Неопубликованные отметки «проверен».
    pub private: Arc<Mutex<HashSet<NodeId>>>,
    pub tx: UnboundedSender<TrustCmd>,
}

/// Что показать о доверии к узлу.
pub struct TrustView {
    pub info: TrustInfo,
    /// Имена самых весомых поручителей («через знакомых: Аня, Вика»).
    pub via_names: Vec<String>,
    /// Отметка «проверен» есть, но только у нас (не опубликована).
    pub private_mark: bool,
}

impl TrustUi {
    pub fn view(&self, id: &NodeId, profiles: &HashMap<NodeId, PeerProfile>) -> TrustView {
        let info = match self.map.lock() {
            Ok(map) => map.get(id),
            Err(_) => TrustMap::default().get(id),
        };
        let private_mark = self.private.lock().map(|p| p.contains(id)).unwrap_or(false);
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
        TrustView { info, via_names, private_mark }
    }

    pub fn send(&self, cmd: TrustCmd) {
        let _ = self.tx.send(cmd);
    }
}
