use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

use crate::error::NetworkError;

/// Тип транспорта — TCP или WebSocket.
/// Оба поддерживаются одновременно: TCP для p2p в LAN, WS для bootstrap-узлов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    WebSocket,
}

/// Фрейм — единица передачи данных между узлами.
/// JSON-сериализуется перед отправкой.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// Версия протокола
    pub version: u8,
    /// Сырой payload (сериализованный NetworkMessage)
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(payload: Vec<u8>) -> Self {
        Self {
            version: 1,
            payload,
        }
    }

    /// Сериализует фрейм в байты для отправки по TCP (4-байтовый length-prefix).
    pub fn to_tcp_bytes(&self) -> Result<Vec<u8>, NetworkError> {
        let data = serde_json::to_vec(self)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;
        let len = data.len() as u32;
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&data);
        Ok(buf)
    }

    /// Десериализует фрейм из JSON-байт.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetworkError> {
        serde_json::from_slice(bytes)
            .map_err(|e| NetworkError::Serialization(e.to_string()))
    }
}

// ─── TCP transport ────────────────────────────────────────────────────────────

/// Обёртка над TCP-соединением с length-prefixed framing.
pub struct TcpTransport {
    stream: TcpStream,
    pub peer_addr: SocketAddr,
}

impl TcpTransport {
    pub fn new(stream: TcpStream, peer_addr: SocketAddr) -> Self {
        Self { stream, peer_addr }
    }

    /// Отправляет фрейм: [u32 len][json bytes]
    pub async fn send(&mut self, frame: Frame) -> Result<(), NetworkError> {
        let bytes = frame.to_tcp_bytes()?;
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| NetworkError::Io(e.to_string()))
    }

    /// Читает следующий фрейм. Блокирует до получения данных.
    pub async fn recv(&mut self) -> Result<Frame, NetworkError> {
        // Читаем 4 байта длины
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetworkError::Io(e.to_string()))?;

        let len = u32::from_be_bytes(len_buf) as usize;

        // Защита от слишком больших сообщений (max 16 MB)
        if len > 16 * 1024 * 1024 {
            return Err(NetworkError::Protocol(format!(
                "Frame too large: {} bytes",
                len
            )));
        }

        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| NetworkError::Io(e.to_string()))?;

        Frame::from_bytes(&buf)
    }
}

// ─── WebSocket transport ──────────────────────────────────────────────────────

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Обёртка над WebSocket-соединением.
pub struct WsTransport {
    stream: WsStream,
    pub peer_addr: SocketAddr,
}

impl WsTransport {
    pub fn new(stream: WsStream, peer_addr: SocketAddr) -> Self {
        Self { stream, peer_addr }
    }

    /// Подключается к ws://addr как клиент.
    pub async fn connect(addr: SocketAddr) -> Result<Self, NetworkError> {
        let url = format!("ws://{}", addr);
        let (stream, _) = connect_async(&url)
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;
        Ok(Self::new(stream, addr))
    }

    pub async fn send(&mut self, frame: Frame) -> Result<(), NetworkError> {
        let data = serde_json::to_vec(&frame)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;
        self.stream
            .send(WsMessage::Binary(data))
            .await
            .map_err(|e| NetworkError::Io(e.to_string()))
    }

    pub async fn recv(&mut self) -> Result<Frame, NetworkError> {
        loop {
            match self.stream.next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return Frame::from_bytes(&data);
                }
                Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => {
                    // игнорируем служебные фреймы
                    continue;
                }
                Some(Ok(WsMessage::Close(_))) | None => {
                    return Err(NetworkError::Disconnected);
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(NetworkError::Io(e.to_string())),
            }
        }
    }
}

// ─── Unified transport ────────────────────────────────────────────────────────

/// Единый тип транспорта — скрывает разницу между TCP и WS.
/// Используется в Connection для единообразной работы с обоими протоколами.
pub enum Transport {
    Tcp(TcpTransport),
    WebSocket(WsTransport),
}

impl Transport {
    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Tcp(_) => TransportKind::Tcp,
            Transport::WebSocket(_) => TransportKind::WebSocket,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            Transport::Tcp(t) => t.peer_addr,
            Transport::WebSocket(t) => t.peer_addr,
        }
    }

    pub async fn send(&mut self, frame: Frame) -> Result<(), NetworkError> {
        match self {
            Transport::Tcp(t) => t.send(frame).await,
            Transport::WebSocket(t) => t.send(frame).await,
        }
    }

    pub async fn recv(&mut self) -> Result<Frame, NetworkError> {
        match self {
            Transport::Tcp(t) => t.recv().await,
            Transport::WebSocket(t) => t.recv().await,
        }
    }
}