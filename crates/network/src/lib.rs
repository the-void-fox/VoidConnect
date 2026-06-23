//! # void-network
//!
//! От этого крейта в работающем приложении используется только
//! [`rate_limit::RateLimiter`] — общий лимитер запросов (его применяют
//! `void-chat` и `void-reputation`).
//!
//! Реальная сеть реализована напрямую в других крейтах:
//!   - чат и личные сообщения — `void-chat` (свой length-prefixed JSON поверх TCP);
//!   - bootstrap и relay — `void-discovery` (свой протокол).
//!
//! Прежний экспериментальный слой (`start`/`ConnectionManager`/`Transport`/
//! `Router`) был не подключён ни к одной точке входа и удалён.

pub mod rate_limit;
