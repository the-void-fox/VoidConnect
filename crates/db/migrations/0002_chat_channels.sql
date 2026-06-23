-- ─────────────────────────────────────────────
-- Каналы («доски») общего чата
-- ─────────────────────────────────────────────
-- Каждое сообщение общего чата относится к каналу. Существующие строки
-- получают канал по умолчанию — глобальный ('global').

ALTER TABLE public_messages ADD COLUMN channel TEXT NOT NULL DEFAULT 'global';

CREATE INDEX IF NOT EXISTS idx_pub_messages_channel
    ON public_messages (channel, sent_at DESC);
