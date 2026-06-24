//! # void-network
//!
//! Сетевые примитивы безопасности, общие для остальных крейтов:
//!   - [`rate_limit::RateLimiter`] — лимитер частоты сообщений от узла (его
//!     применяют `void-chat` и `void-reputation`);
//!   - [`conn_guard::ConnLimiter`] — ограничитель числа одновременных входящих
//!     соединений (глобальный + на один IP); защита от connection-flood, его
//!     применяют accept-циклы серверов чата/DM/чанков/bootstrap/relay.
//!
//! Реальная сеть реализована напрямую в других крейтах:
//!   - чат и личные сообщения — `void-chat` (свой length-prefixed JSON поверх TCP);
//!   - bootstrap и relay — `void-discovery` (свой протокол).
//!
//! Прежний экспериментальный слой (`start`/`ConnectionManager`/`Transport`/
//! `Router`) был не подключён ни к одной точке входа и удалён.

pub mod conn_guard;
pub mod rate_limit;
