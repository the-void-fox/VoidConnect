//! `void-storage` — P2P файловое хранилище для Void Connect.
//!
//! ## Быстрый старт
//!
//! ```ignore
//! use void_storage::{StorageManager, ChunkStore};
//! use std::path::PathBuf;
//!
//! // Открываем хранилище чанков на диске
//! let store = ChunkStore::new(PathBuf::from("./data/chunks")).await?;
//!
//! // Создаём менеджер (загружает индекс из БД)
//! let manager = StorageManager::new(pool, store, my_node_id).await?;
//!
//! // Запускаем TCP-сервер для раздачи чанков
//! let mgr = manager.clone();
//! tokio::spawn(async move { mgr.start_server(7702).await });
//!
//! // Публикуем файл
//! let file_id = manager.publish_file(Path::new("/home/user/photo.jpg")).await?;
//!
//! // Скачиваем файл
//! manager.download_file(&file_id, Path::new("/tmp/photo.jpg"), &peers).await?;
//! ```

pub mod chunk_store;
pub mod chunker;
pub mod error;
pub mod index;
pub mod integrity;
pub mod manager;
pub mod transfer;

pub use chunk_store::ChunkStore;
pub use error::StorageError;
pub use manager::StorageManager;
pub use transfer::{ChunkRequest, ChunkResponse, ChunkResponseStatus};