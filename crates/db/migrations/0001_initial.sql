-- migrations/0001_initial.sql
-- Void Connect — начальная схема базы данных

PRAGMA journal_mode = WAL;   -- включаем WAL для конкурентного доступа
PRAGMA foreign_keys = ON;

-- ─────────────────────────────────────────────
-- Профиль локального пользователя
-- (одна строка — свой аккаунт)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS local_profile (
    id          INTEGER PRIMARY KEY CHECK (id = 1),  -- синглтон
    public_key  TEXT    NOT NULL UNIQUE,             -- hex(Ed25519 pubkey) — глобальный ID узла
    username    TEXT    NOT NULL,
    avatar_url  TEXT,                                -- путь к файлу или data-URI
    status_text TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─────────────────────────────────────────────
-- Известные узлы (peers)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS peers (
    public_key      TEXT    PRIMARY KEY,             -- hex(Ed25519 pubkey)
    username        TEXT,
    avatar_url      TEXT,
    status_text     TEXT,
    ip_address      TEXT,                            -- последний известный IP
    port            INTEGER,
    is_bootstrap    INTEGER NOT NULL DEFAULT 0,      -- 1 если bootstrap-узел
    last_seen_at    TEXT,
    first_seen_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers (last_seen_at DESC);

-- ─────────────────────────────────────────────
-- Репутация узлов
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reputation (
    public_key          TEXT    PRIMARY KEY REFERENCES peers (public_key) ON DELETE CASCADE,
    score               REAL    NOT NULL DEFAULT 0.0,
    upload_bytes        INTEGER NOT NULL DEFAULT 0,
    download_bytes      INTEGER NOT NULL DEFAULT 0,
    valid_chunks_sent   INTEGER NOT NULL DEFAULT 0,
    bad_chunks_sent     INTEGER NOT NULL DEFAULT 0,
    spam_strikes        INTEGER NOT NULL DEFAULT 0,
    uptime_seconds      INTEGER NOT NULL DEFAULT 0,
    bootstrap_bonus     REAL    NOT NULL DEFAULT 0.0,
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Жалобы
CREATE TABLE IF NOT EXISTS reputation_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_key      TEXT    NOT NULL REFERENCES peers (public_key) ON DELETE CASCADE,
    reporter_key    TEXT    NOT NULL,                -- кто пожаловался
    reason          TEXT    NOT NULL,                -- "spam" | "bad_chunks" | "malicious_content"
    signature       TEXT    NOT NULL,                -- подпись репорта ключом reporter_key
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_reports_target ON reputation_reports (target_key);

-- ─────────────────────────────────────────────
-- Сообщения общего чата
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public_messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT    NOT NULL UNIQUE,         -- UUID от отправителя (дедупликация)
    sender_key      TEXT    NOT NULL,                -- public key отправителя
    content         TEXT    NOT NULL,
    signature       TEXT    NOT NULL,                -- подпись сообщения
    sent_at         TEXT    NOT NULL,                -- время по часам отправителя
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_pub_messages_sent ON public_messages (sent_at DESC);

-- ─────────────────────────────────────────────
-- Личные сообщения (E2E)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS private_messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT    NOT NULL UNIQUE,
    peer_key        TEXT    NOT NULL,                -- собеседник (его pubkey)
    direction       TEXT    NOT NULL CHECK (direction IN ('in', 'out')),
    encrypted_blob  BLOB    NOT NULL,                -- зашифрованный контент
    sent_at         TEXT    NOT NULL,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_read         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_priv_messages_peer ON private_messages (peer_key, sent_at DESC);

-- ─────────────────────────────────────────────
-- Индекс файловых чанков
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chunks (
    hash            TEXT    PRIMARY KEY,             -- SHA-256 hex — уникальный ID чанка
    file_id         TEXT    NOT NULL,                -- к какому файлу относится
    chunk_index     INTEGER NOT NULL,
    size_bytes      INTEGER NOT NULL,
    is_local        INTEGER NOT NULL DEFAULT 0,      -- 1 если чанк хранится локально
    local_path      TEXT,                            -- путь на диске (если is_local = 1)
    UNIQUE (file_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks (file_id, chunk_index);

-- Какие узлы владеют каким чанком
CREATE TABLE IF NOT EXISTS chunk_owners (
    chunk_hash  TEXT    NOT NULL REFERENCES chunks (hash) ON DELETE CASCADE,
    peer_key    TEXT    NOT NULL,
    verified_at TEXT,
    PRIMARY KEY (chunk_hash, peer_key)
);

-- Метаданные файлов
CREATE TABLE IF NOT EXISTS files (
    file_id         TEXT    PRIMARY KEY,             -- SHA-256 от манифеста
    name            TEXT    NOT NULL,
    size_bytes      INTEGER NOT NULL,
    total_chunks    INTEGER NOT NULL,
    owner_key       TEXT    NOT NULL,                -- кто опубликовал
    mime_type       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);