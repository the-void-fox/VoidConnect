-- Подпись публикатора для манифеста файла (FileManifest::signature).
-- Хранится, чтобы сидеры могли переслать подписанный манифест и после
-- перезапуска: без подписи узлы манифест не принимают.
-- Одна подпись на file_id: первая принятая («кто первым известен»).
CREATE TABLE IF NOT EXISTS file_signatures (
    file_id    TEXT PRIMARY KEY,
    publisher  TEXT NOT NULL,
    signature  TEXT NOT NULL
);
