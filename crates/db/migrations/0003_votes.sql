-- ─────────────────────────────────────────────
-- Голосования (void-vote)
-- ─────────────────────────────────────────────
-- Децентрализованная система предложений и голосов. Записи подписаны авторами
-- и неизменяемы; синхронизируются между узлами объединением множеств
-- (anti-entropy). Подсчёт детерминированный и локальный.

-- Предложение. proposal_id = hex(sha256(proposer_key || payload_json)).
-- target денормализован из payload для дедупа/индексации (NodeId | file_id | channel id).
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id   TEXT    PRIMARY KEY,
    kind          TEXT    NOT NULL,   -- "ban_user" | "unban_user" | "add_channel" | "remove_file"
    target        TEXT    NOT NULL,
    payload_json  TEXT    NOT NULL,   -- сериализованный ProposalPayload (для re-derive + verify)
    proposer_key  TEXT    NOT NULL,   -- автор (= signed.signer)
    signature     TEXT    NOT NULL,   -- подпись proposer_key
    created_at    INTEGER NOT NULL,   -- unix ts из payload (начало окна голосования)
    closed_at     INTEGER,            -- момент заморозки результата (NULL = ещё не финализировано)
    received_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_proposals_kind_target ON proposals (kind, target);
CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals (created_at);

-- Голос. Один на (proposal_id, voter_key); переголосование — побеждает больший
-- created_at (latest-wins). FK на proposals НЕТ намеренно: голос может прийти
-- раньше самого предложения (out-of-order gossip).
CREATE TABLE IF NOT EXISTS votes (
    proposal_id  TEXT    NOT NULL,
    voter_key    TEXT    NOT NULL,   -- голосующий (= signed.signer)
    choice       INTEGER NOT NULL,   -- 0 = против, 1 = за
    signature    TEXT    NOT NULL,   -- подпись voter_key
    created_at   INTEGER NOT NULL,   -- unix ts из payload (для latest-wins)
    PRIMARY KEY (proposal_id, voter_key)
);

CREATE INDEX IF NOT EXISTS idx_votes_proposal ON votes (proposal_id);
