-- Сеть доверия (см. Obsidian/Сеть доверия.md).

-- Поручительства: последняя версия на пару (поручитель, подопечный).
-- Подпись хранится целиком (signed_json) — для пересылки новым связям.
CREATE TABLE IF NOT EXISTS vouches (
    voucher     TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    kind        TEXT    NOT NULL,              -- "personal" | "greeter"
    updated_at  INTEGER NOT NULL,              -- unix-мс, растёт с каждой версией
    revoked     INTEGER NOT NULL DEFAULT 0,
    signed_json TEXT    NOT NULL,
    PRIMARY KEY (voucher, subject)
);

CREATE INDEX IF NOT EXISTS idx_vouches_subject ON vouches (subject);

-- Наблюдения за узлами, которых МЫ видели в сети (для уровня «освоившийся»).
-- Отдельно от peers: строки peers создаются и для узлов, о которых мы только
-- слышали из чужих данных, — их first_seen_at ничего не говорит.
CREATE TABLE IF NOT EXISTS peer_activity (
    node_id         TEXT    PRIMARY KEY,
    first_seen      INTEGER NOT NULL,          -- unix-секунды
    last_seen       INTEGER NOT NULL,
    active_days     INTEGER NOT NULL DEFAULT 0, -- дней с «живыми» сообщениями
    live_messages   INTEGER NOT NULL DEFAULT 0,
    last_active_day INTEGER NOT NULL DEFAULT -1 -- номер дня (unix / 86400)
);
