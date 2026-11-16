-- Общие данные сайтов (JS API, `void-web::records`): подписанные записи
-- пользователей. Каждый автор владеет своими ключами — чужую запись нельзя ни
-- перезаписать, ни удалить. Последняя версия на (сайт, коллекция, автор, ключ).
CREATE TABLE IF NOT EXISTS site_records (
    site        TEXT    NOT NULL,
    collection  TEXT    NOT NULL,
    author      TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    updated_at  INTEGER NOT NULL,              -- unix-мс, версия записи
    link        TEXT,                          -- ссылка для выборок (напр. ключ видео)
    deleted     INTEGER NOT NULL DEFAULT 0,    -- 1 — надгробие (data = NULL)
    data        TEXT,                          -- JSON
    signed_json TEXT    NOT NULL,              -- подпись целиком — для пересылки
    received_at INTEGER NOT NULL,              -- unix-мс, когда узнали
    PRIMARY KEY (site, collection, author, key)
);

CREATE INDEX IF NOT EXISTS idx_site_records_coll   ON site_records (site, collection, updated_at);
CREATE INDEX IF NOT EXISTS idx_site_records_link   ON site_records (site, collection, link, updated_at);
CREATE INDEX IF NOT EXISTS idx_site_records_author ON site_records (site, author, updated_at);
