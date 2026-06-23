//! Хранение предложений и голосов (рантайм-запросы sqlx, без `query!`-макросов,
//! чтобы не требовался offline-кэш `.sqlx`).
//!
//! Голоса дедуплицированы на уровне БД: PK `(proposal_id, voter_key)` +
//! latest-wins по `created_at`. Так синхронизация объединением множеств
//! детерминированно сходится у всех узлов.

use sqlx::Row;

use void_crypto::sign::SignedMessage;
use void_db::DbPool;

use crate::error::VoteError;
use crate::tally::VoteRecord;
use crate::types::{Proposal, ProposalKind, ProposalPayload, Vote, VotePayload, VOTING_WINDOW_SECS};

/// Предложение, прочитанное из БД.
#[derive(Debug, Clone)]
pub struct StoredProposal {
    pub id: String,
    pub kind: ProposalKind,
    pub created_at: i64,
    pub proposer_key: String,
    /// Момент заморозки результата (`None` = ещё открыто/не финализировано).
    pub closed_at: Option<i64>,
    /// Восстановленный `SignedMessage` (для рассылки/синхронизации и проверки).
    pub signed: SignedMessage,
}

/// Сохраняет предложение (идемпотентно — повтор по тому же id игнорируется).
pub async fn insert_proposal(pool: &DbPool, p: &Proposal) -> Result<(), VoteError> {
    let payload_json = std::str::from_utf8(&p.signed.payload)
        .map_err(|e| VoteError::Serde(e.to_string()))?;
    sqlx::query(
        "INSERT OR IGNORE INTO proposals
            (proposal_id, kind, target, payload_json, proposer_key, signature, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&p.id)
    .bind(p.payload.kind.tag())
    .bind(p.payload.kind.target())
    .bind(payload_json)
    .bind(&p.signed.signer)
    .bind(&p.signed.signature)
    .bind(p.payload.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Предложение по id.
pub async fn get_proposal(pool: &DbPool, id: &str) -> Result<Option<StoredProposal>, VoteError> {
    let row = sqlx::query(
        "SELECT proposal_id, payload_json, proposer_key, signature, created_at, closed_at
         FROM proposals WHERE proposal_id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(row_to_proposal).transpose()
}

/// Все известные предложения, новые сверху.
pub async fn list_proposals(pool: &DbPool) -> Result<Vec<StoredProposal>, VoteError> {
    let rows = sqlx::query(
        "SELECT proposal_id, payload_json, proposer_key, signature, created_at, closed_at
         FROM proposals ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(row_to_proposal).collect()
}

/// Предложения с ещё открытым окном на момент `now` (для anti-entropy sync).
pub async fn list_open_proposals(pool: &DbPool, now: i64) -> Result<Vec<StoredProposal>, VoteError> {
    let rows = sqlx::query(
        "SELECT proposal_id, payload_json, proposer_key, signature, created_at, closed_at
         FROM proposals WHERE created_at + ? > ? ORDER BY created_at DESC",
    )
    .bind(VOTING_WINDOW_SECS)
    .bind(now)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(row_to_proposal).collect()
}

/// Помечает предложение финализированным (результат заморожен).
pub async fn mark_closed(pool: &DbPool, id: &str, closed_at: i64) -> Result<(), VoteError> {
    sqlx::query("UPDATE proposals SET closed_at = ? WHERE proposal_id = ?")
        .bind(closed_at)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Сохраняет/обновляет голос. Один на (proposal_id, voter_key); при конфликте
/// побеждает запись с бóльшим `created_at` (latest-wins, детерминированно).
pub async fn upsert_vote(pool: &DbPool, vote: &Vote) -> Result<(), VoteError> {
    sqlx::query(
        "INSERT INTO votes (proposal_id, voter_key, choice, signature, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(proposal_id, voter_key) DO UPDATE SET
             choice     = excluded.choice,
             signature  = excluded.signature,
             created_at = excluded.created_at
         WHERE excluded.created_at > votes.created_at",
    )
    .bind(&vote.payload.proposal_id)
    .bind(&vote.signed.signer)
    .bind(vote.payload.choice as i64)
    .bind(&vote.signed.signature)
    .bind(vote.payload.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Восстанавливает голоса предложения как `SignedMessage` — для re-announce при
/// anti-entropy sync. Payload пересобирается из (proposal_id, choice, created_at)
/// детерминированно (тем же serde_json), так что подпись остаётся валидной.
pub async fn list_vote_messages(
    pool: &DbPool,
    proposal_id: &str,
) -> Result<Vec<SignedMessage>, VoteError> {
    let rows = sqlx::query(
        "SELECT voter_key, choice, signature, created_at FROM votes WHERE proposal_id = ?",
    )
    .bind(proposal_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let payload = VotePayload {
                proposal_id: proposal_id.to_string(),
                choice: r.get::<i64, _>("choice") != 0,
                created_at: r.get::<i64, _>("created_at"),
            };
            SignedMessage {
                payload: payload.to_bytes(),
                signature: r.get::<String, _>("signature"),
                signer: r.get::<String, _>("voter_key"),
            }
        })
        .collect())
}

/// Голоса по предложению (по одному на узел, уже дедуплицированные).
pub async fn list_votes(pool: &DbPool, proposal_id: &str) -> Result<Vec<VoteRecord>, VoteError> {
    let rows = sqlx::query(
        "SELECT voter_key, choice, created_at FROM votes WHERE proposal_id = ?",
    )
    .bind(proposal_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| VoteRecord {
            voter_key: r.get::<String, _>("voter_key"),
            choice: r.get::<i64, _>("choice") != 0,
            created_at: r.get::<i64, _>("created_at"),
        })
        .collect())
}

fn row_to_proposal(row: sqlx::sqlite::SqliteRow) -> Result<StoredProposal, VoteError> {
    let id: String = row.get("proposal_id");
    let payload_json: String = row.get("payload_json");
    let proposer_key: String = row.get("proposer_key");
    let signature: String = row.get("signature");
    let created_at: i64 = row.get("created_at");
    let closed_at: Option<i64> = row.get("closed_at");

    let payload: ProposalPayload =
        serde_json::from_str(&payload_json).map_err(|e| VoteError::Serde(e.to_string()))?;
    let signed = SignedMessage {
        payload: payload_json.into_bytes(),
        signature,
        signer: proposer_key.clone(),
    };
    Ok(StoredProposal {
        id,
        kind: payload.kind,
        created_at,
        proposer_key,
        closed_at,
        signed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Vote;
    use void_crypto::keys::SigningKeypair;

    async fn pool() -> (tempfile::TempDir, DbPool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = void_db::open(&dir.path().join("db.sqlite")).await.unwrap();
        (dir, pool)
    }

    fn kp(seed: u8) -> SigningKeypair {
        SigningKeypair::from_seed(&[seed; 32]).unwrap()
    }

    #[tokio::test]
    async fn proposal_round_trips_and_verifies() {
        let (_d, pool) = pool().await;
        let p = Proposal::create(
            ProposalKind::AddChannel {
                id: "tech2".into(),
                name: "Tech2".into(),
                icon: "#".into(),
            },
            &kp(1),
        )
        .unwrap();
        insert_proposal(&pool, &p).await.unwrap();

        let got = get_proposal(&pool, &p.id).await.unwrap().unwrap();
        assert_eq!(got.id, p.id);
        assert_eq!(got.kind, p.payload.kind);
        // Восстановленная подпись валидна, а id пересчитывается тем же.
        got.signed.verify().unwrap();
        let restored = Proposal::from_signed(got.signed).unwrap();
        assert_eq!(restored.id, p.id);
    }

    #[tokio::test]
    async fn vote_latest_wins() {
        let (_d, pool) = pool().await;
        let voter = kp(2);

        // Голос v1: created_at=10, «за».
        let mut v1 = Vote::create("prop1".into(), true, &voter).unwrap();
        v1.payload.created_at = 10;
        v1.payload.proposal_id = "prop1".into();
        // пересоздаём подпись под изменённое тело, чтобы verify проходил
        let v1 = resign(v1, &voter);
        upsert_vote(&pool, &v1).await.unwrap();

        // Более старый голос (created_at=5) НЕ должен перезаписать.
        let mut v_old = Vote::create("prop1".into(), false, &voter).unwrap();
        v_old.payload.created_at = 5;
        let v_old = resign(v_old, &voter);
        upsert_vote(&pool, &v_old).await.unwrap();

        let votes = list_votes(&pool, "prop1").await.unwrap();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].choice, true, "старый голос не должен перезаписать новый");
        assert_eq!(votes[0].created_at, 10);

        // Более новый голос (created_at=20, «против») перезаписывает.
        let mut v_new = Vote::create("prop1".into(), false, &voter).unwrap();
        v_new.payload.created_at = 20;
        let v_new = resign(v_new, &voter);
        upsert_vote(&pool, &v_new).await.unwrap();

        let votes = list_votes(&pool, "prop1").await.unwrap();
        assert_eq!(votes.len(), 1);
        assert_eq!(votes[0].choice, false);
        assert_eq!(votes[0].created_at, 20);
    }

    /// Пересобирает подпись голоса под текущее тело (тесты меняют created_at).
    fn resign(mut v: Vote, keypair: &SigningKeypair) -> Vote {
        v.signed = SignedMessage::sign(v.payload.to_bytes(), keypair).unwrap();
        v
    }
}
