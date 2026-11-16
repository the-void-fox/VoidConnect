-- Чанк в таблице `chunks` раньше хранился по хэшу (PRIMARY KEY hash). Если у
-- двух файлов совпадал хоть один блок (одинаковое начало видео, обрезанная
-- копия, повтор внутри файла), второй файл терял строку этого чанка, и собрать
-- его было уже нельзя. Теперь строка — это место чанка в файле
-- (file_id, chunk_index); один и тот же хэш может стоять в нескольких файлах,
-- блоб на диске при этом общий.

-- 1. Владельцы чанков ссылались на chunks(hash) внешним ключом — хэш больше не
--    уникален, ключ убираем. Пересобираем таблицу ДО пересборки chunks, иначе
--    DROP TABLE chunks каскадом стёр бы всех владельцев.
CREATE TABLE chunk_owners_new (
    chunk_hash  TEXT    NOT NULL,
    peer_key    TEXT    NOT NULL,
    verified_at TEXT,
    PRIMARY KEY (chunk_hash, peer_key)
);
INSERT OR IGNORE INTO chunk_owners_new (chunk_hash, peer_key, verified_at)
    SELECT chunk_hash, peer_key, verified_at FROM chunk_owners;
DROP TABLE chunk_owners;
ALTER TABLE chunk_owners_new RENAME TO chunk_owners;

-- 2. Чанки: ключ — место в файле.
CREATE TABLE chunks_new (
    file_id         TEXT    NOT NULL,
    chunk_index     INTEGER NOT NULL,
    hash            TEXT    NOT NULL,
    size_bytes      INTEGER NOT NULL,
    is_local        INTEGER NOT NULL DEFAULT 0,
    local_path      TEXT,
    PRIMARY KEY (file_id, chunk_index)
);
INSERT OR IGNORE INTO chunks_new (file_id, chunk_index, hash, size_bytes, is_local, local_path)
    SELECT file_id, chunk_index, hash, size_bytes, is_local, local_path FROM chunks
    WHERE file_id <> '';
DROP TABLE chunks;
ALTER TABLE chunks_new RENAME TO chunks;
CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks (hash);
