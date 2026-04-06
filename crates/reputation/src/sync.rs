/// sync.rs — синхронизация репутации между узлами.
///
/// При подключении нового пира обмениваемся нашими локальными оценками.
/// Все оценки подписаны ключом оценивающего — нельзя анонимно накрутить.
/// Применяется взвешенное усреднение: вес голоса = score оценивающего.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use void_core::identity::NodeId;
use void_core::message::NetworkMessage;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;
use void_db::{peers as db_peers, DbPool};
use void_network::router::{MessageKind, Router, RouterEvent};

use crate::error::ReputationError;
use crate::events::{EventProcessor, ReputationEvent};
use crate::score::ScoreManager;

// ─── Константы ───────────────────────────────────────────────────────────────

/// Максимальное число записей репутации в одном sync-пакете.
const MAX_SYNC_ENTRIES: usize = 200;

/// Минимальный вес голоса нового узла (score = 0).
const MIN_VOTE_WEIGHT: f64 = 0.1;

// ─── Структуры синхронизации ──────────────────────────────────────────────────

/// Одна запись в sync-пакете: оценка конкретного узла.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEntry {
    /// Чей score передаём
    pub target_key: String,
    /// Значение score по мнению отправляющего узла
    pub score: f64,
}

/// Payload пакета синхронизации (подписывается целиком).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    /// Оценки отправителя
    pub entries: Vec<ReputationEntry>,
    /// Метка времени (unix timestamp)
    pub timestamp: i64,
}

impl SyncPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("SyncPayload serialization failed")
    }
}

/// Payload одной оценки репутации (входит в SignedMessage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationVote {
    /// Чью репутацию оцениваем
    pub target_key: String,
    /// Оценка score
    pub score: f64,
    /// Метка времени
    pub timestamp: i64,
}

impl ReputationVote {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("ReputationVote serialization failed")
    }
}

// ─── SyncManager ──────────────────────────────────────────────────────────────

/// Управляет синхронизацией репутации через Router.
pub struct SyncManager {
    pool: DbPool,
    score_manager: ScoreManager,
    event_processor: EventProcessor,
    my_keypair: Arc<SigningKeypair>,
    my_id: NodeId,
}

impl SyncManager {
    pub fn new(
        pool: DbPool,
        score_manager: ScoreManager,
        event_processor: EventProcessor,
        my_keypair: Arc<SigningKeypair>,
        my_id: NodeId,
    ) -> Self {
        Self {
            pool,
            score_manager,
            event_processor,
            my_keypair,
            my_id,
        }
    }

    // ─── Запуск фонового цикла ────────────────────────────────────────────────

    /// Подписывается на Router и обрабатывает события репутации.
    ///
    /// Слушает:
    /// - `MessageKind::Reputation` — входящие sync-пакеты
    /// - `MessageKind::All` с фильтром — Connect/Disconnect для аптайма
    pub async fn start(self: Arc<Self>, router: Arc<Router>) {
        // Подписка на сообщения репутации
        let mut rep_rx = router.subscribe(MessageKind::Reputation, 256).await;

        // Подписка на Discovery (чтобы реагировать на Connect/Disconnect через Router events)
        let mut discovery_rx = router.subscribe(MessageKind::Discovery, 256).await;

        let manager = self.clone();
        let router_for_rep = router.clone();

        // Задача: обработка Reputation сообщений
        tokio::spawn(async move {
            while let Some(event) = rep_rx.recv().await {
                if let Err(e) = manager.handle_reputation_message(event).await {
                    warn!("Reputation sync error: {}", e);
                }
            }
        });

        // Задача: реагирование на подключение новых пиров (отправляем им наши данные)
        let manager2 = self.clone();
        tokio::spawn(async move {
            while let Some(event) = discovery_rx.recv().await {
                // Announce — значит новый пир подключился, отправляем ему наш sync-пакет
                if let NetworkMessage::Announce { peer } = &event.message {
                    let peer_id = peer.id.clone();
                    debug!("New peer {}, sending reputation sync", peer_id);

                    // Событие подключения → аптайм
                    manager2
                        .event_processor
                        .process(ReputationEvent::PeerConnected {
                            peer_id: peer_id.clone(),
                        })
                        .await;

                    // Отправляем наш sync-пакет
                    if let Ok(msg) = manager2.build_sync_message().await {
                        let _ = router_for_rep.send_to(&peer_id, msg).await;
                    }
                }
            }
        });
    }

    // ─── Построение sync-пакета ───────────────────────────────────────────────

    /// Строит подписанный NetworkMessage::ReputationSync из наших локальных данных.
    async fn build_sync_message(&self) -> Result<NetworkMessage, ReputationError> {
        let all_peers = db_peers::list_peers(&self.pool)
            .await
            .map_err(ReputationError::from)?;

        let entries: Vec<ReputationEntry> = {
            let mut result = Vec::new();
            for peer in all_peers.iter().take(MAX_SYNC_ENTRIES) {
                if let Ok(Some(rep)) =
                    db_peers::get_reputation(&self.pool, &peer.public_key).await
                {
                    result.push(ReputationEntry {
                        target_key: peer.public_key.clone(),
                        score: rep.score,
                    });
                }
            }
            result
        };

        let payload = SyncPayload {
            entries,
            timestamp: chrono::Utc::now().timestamp(),
        };

        let signed =
            SignedMessage::sign(payload.to_bytes(), &self.my_keypair).map_err(ReputationError::from)?;

        Ok(NetworkMessage::ReputationSync {
            from: self.my_id.clone(),
            signed_payload: signed.payload,
            signature: signed.signature,
            signer: signed.signer,
        })
    }

    // ─── Приём sync-пакета ────────────────────────────────────────────────────

    async fn handle_reputation_message(
        &self,
        event: RouterEvent,
    ) -> Result<(), ReputationError> {
        match event.message {
            NetworkMessage::ReputationSync {
                from,
                signed_payload,
                signature,
                signer,
            } => {
                // Проверяем что signer совпадает с from
                if signer != from.as_str() {
                    warn!("ReputationSync: signer mismatch from {}", from);
                    return Err(ReputationError::SignerMismatch);
                }

                // Верифицируем подпись
                let signed = SignedMessage {
                    payload: signed_payload,
                    signature,
                    signer: signer.clone(),
                };
                signed.verify().map_err(ReputationError::from)?;

                // Десериализуем payload
                let sync: SyncPayload = serde_json::from_slice(&signed.payload)
                    .map_err(|e| ReputationError::Deserialize(e.to_string()))?;

                // Узнаём вес голоса отправителя
                let sender_score = self.score_manager.score(&from).await;
                let vote_weight = (sender_score / 100.0).clamp(MIN_VOTE_WEIGHT, 1.0);

                debug!(
                    "Applying reputation sync from {} (weight={:.2}, entries={})",
                    from,
                    vote_weight,
                    sync.entries.len()
                );

                self.apply_sync(sync, vote_weight, &from).await?;
                Ok(())
            }

            NetworkMessage::ReputationReport {
                target,
                signed_payload,
                signature,
                signer,
            } => {
                // Пересобираем SignedMessage для передачи в ReportManager
                let signed = SignedMessage {
                    payload: signed_payload,
                    signature,
                    signer,
                };
                // ReportManager подключается отдельно — здесь только логируем
                info!("Reputation report received targeting {}", target);
                let _ = (signed, target); // обрабатывается через ReportManager
                Ok(())
            }

            _ => Ok(()),
        }
    }

    // ─── Применение входящих данных ───────────────────────────────────────────

    /// Применяет взвешенное среднее от sync-пакета к локальным данным.
    ///
    /// Формула: new_score = current * (1 - w) + received * w
    /// где w = vote_weight (от 0.1 до 1.0)
    async fn apply_sync(
        &self,
        sync: SyncPayload,
        vote_weight: f64,
        from: &NodeId,
    ) -> Result<(), ReputationError> {
        for entry in sync.entries.iter().take(MAX_SYNC_ENTRIES) {
            // Не принимаем оценки себя самого
            if entry.target_key == self.my_id.as_str() {
                continue;
            }

            // Не принимаем оценки от того, кого оцениваем (круговые)
            if entry.target_key == from.as_str() {
                continue;
            }

            let target_id = NodeId(entry.target_key.clone());

            // Гарантируем существование записи
            let _ = db_peers::init_reputation(&self.pool, &entry.target_key).await;

            // Получаем текущий score
            let current = self.score_manager.score(&target_id).await;

            // Взвешенное среднее
            let blended = current * (1.0 - vote_weight) + entry.score * vote_weight;
            let delta = blended - current;

            if delta.abs() < 0.01 {
                // Изменение слишком мало — пропускаем
                continue;
            }

            // Применяем дельту через bootstrap_bonus (прямое сложение со score)
            db_peers::apply_reputation_delta(
                &self.pool,
                &entry.target_key,
                void_db::peers::ReputationDelta {
                    bootstrap_bonus: delta,
                    ..Default::default()
                },
            )
            .await
            .map_err(ReputationError::from)?;
        }

        Ok(())
    }
}