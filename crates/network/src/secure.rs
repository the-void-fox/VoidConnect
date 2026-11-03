//! Аутентифицированное шифрование TCP-каналов — Noise XX.
//!
//! Любое соединение между узлами (чат, личные сообщения, чанки, bootstrap,
//! relay) начинается с рукопожатия `Noise_XX_25519_ChaChaPoly_BLAKE2s`. После
//! него обе стороны точно знают NodeId друг друга, а весь трафик зашифрован и
//! защищён от подмены: провайдер, сосед по LAN или ретранслятор видят только
//! шифротекст и не могут выдать себя за другой узел.
//!
//! Привязка к личности. NodeId — это Ed25519-ключ, а Noise работает с X25519.
//! Поэтому у процесса есть отдельный X25519-ключ для Noise, а в рукопожатии
//! каждая сторона передаёт (уже под шифрованием) `binding` = Ed25519-ключ +
//! подпись им строки `BINDING_CONTEXT || noise_static_pub`. Noise доказывает
//! владение X25519-ключом, подпись — что этот ключ выпущен владельцем NodeId.
//! Подделать NodeId можно только украв Ed25519-ключ.
//!
//! Пролог Noise содержит имя канала ([`Channel`]): рукопожатие одного канала
//! нельзя «переиграть» в другом (например, соединение чанков выдать за DM).
//!
//! Поток после рукопожатия — [`SecureStream`]: обычные `AsyncRead`/`AsyncWrite`,
//! поверх которых прикладные протоколы работают без изменений. Данные режутся
//! на Noise-кадры `[u16 BE длина][шифротекст]` (до 64 КиБ каждый). Как и у TLS,
//! записанное может оставаться в буфере до `flush()` — прикладные функции
//! записи сообщений вызывают `flush()` в конце.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;
use zeroize::Zeroizing;

use void_core::identity::NodeId;
use void_crypto::keys::SigningKeypair;
use void_crypto::sign::SignedMessage;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Контекст подписи привязки Noise-ключа к NodeId.
const BINDING_CONTEXT: &[u8] = b"void-connect/noise-static/v1";
/// `binding` = Ed25519 public (32) || подпись (64).
const BINDING_LEN: usize = 32 + 64;
/// Максимальный Noise-кадр (ограничение спецификации).
const MAX_FRAME: usize = 65535;
const TAG_LEN: usize = 16;
/// Максимум открытого текста в одном кадре.
const MAX_PLAINTEXT: usize = MAX_FRAME - TAG_LEN;

/// Таймаут всего рукопожатия — защита от узла, который подключился и молчит.
#[cfg(not(test))]
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);

/// Канал (сервис), для которого открывается соединение. Входит в пролог Noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Chat,
    Dm,
    Chunks,
    Bootstrap,
    Relay,
}

impl Channel {
    fn prologue(self) -> &'static [u8] {
        match self {
            Channel::Chat => b"void-connect/v1/chat",
            Channel::Dm => b"void-connect/v1/dm",
            Channel::Chunks => b"void-connect/v1/chunks",
            Channel::Bootstrap => b"void-connect/v1/bootstrap",
            Channel::Relay => b"void-connect/v1/relay",
        }
    }
}

/// Любой двунаправленный поток (TCP, relay-туннель, вложенный SecureStream).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Поток с стёртым типом — когда соединение может прийти и напрямую, и через relay.
pub type BoxStream = Box<dyn AsyncStream>;

// ─── Личность узла для Noise ─────────────────────────────────────────────────────

/// Noise-ключ процесса, привязанный подписью к NodeId. Дешёвый `Clone`.
#[derive(Clone)]
pub struct NoiseIdentity {
    inner: Arc<IdentityInner>,
}

struct IdentityInner {
    node_id: NodeId,
    static_private: Zeroizing<Vec<u8>>,
    binding: [u8; BINDING_LEN],
}

impl NoiseIdentity {
    /// Создаёт свежий X25519-ключ для Noise (на время работы процесса) и
    /// подписывает его Ed25519-ключом узла.
    pub fn new(signing: &SigningKeypair) -> Self {
        let keypair = snow::Builder::new(noise_params())
            .generate_keypair()
            .expect("генерация X25519-ключа не может завершиться ошибкой");

        let mut msg = BINDING_CONTEXT.to_vec();
        msg.extend_from_slice(&keypair.public);
        let signed = SignedMessage::sign(msg, signing).expect("подпись Ed25519 не может завершиться ошибкой");
        let sig = hex::decode(&signed.signature).expect("подпись в hex");

        let mut binding = [0u8; BINDING_LEN];
        binding[..32].copy_from_slice(&signing.public_bytes());
        binding[32..].copy_from_slice(&sig);

        Self {
            inner: Arc::new(IdentityInner {
                node_id: NodeId::from_public_key_bytes(&signing.public_bytes()),
                static_private: Zeroizing::new(keypair.private),
                binding,
            }),
        }
    }

    /// NodeId, который увидят собеседники.
    pub fn node_id(&self) -> &NodeId {
        &self.inner.node_id
    }
}

fn noise_params() -> snow::params::NoiseParams {
    NOISE_PARAMS.parse().expect("корректная строка параметров Noise")
}

/// Проверяет `binding` собеседника против его Noise-ключа, возвращает NodeId.
fn verify_binding(binding: &[u8], remote_static: &[u8]) -> io::Result<NodeId> {
    if binding.len() != BINDING_LEN {
        return Err(denied("неверная длина привязки ключа"));
    }
    let mut payload = BINDING_CONTEXT.to_vec();
    payload.extend_from_slice(remote_static);
    let signed = SignedMessage {
        payload,
        signature: hex::encode(&binding[32..]),
        signer: hex::encode(&binding[..32]),
    };
    signed
        .verify()
        .map_err(|_| denied("подпись привязки Noise-ключа неверна"))?;
    Ok(NodeId::from_public_key_bytes(&binding[..32]))
}

fn denied(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, msg.to_string())
}

fn noise_err(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {}", e))
}

// ─── Рукопожатие ─────────────────────────────────────────────────────────────────

/// Исходящее соединение. `expected` — NodeId, к которому мы подключаемся: если
/// на том конце другой узел, соединение разрывается ДО того, как мы раскроем
/// ему свою личность.
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    me: &NoiseIdentity,
    channel: Channel,
    expected: Option<&NodeId>,
) -> io::Result<SecureStream<S>> {
    timeout(HANDSHAKE_TIMEOUT, handshake(io, me, channel, true, expected))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "noise handshake timed out"))?
}

/// Входящее соединение: принимаем любой узел, сумевший доказать свой NodeId
/// (его можно узнать через [`SecureStream::peer`]).
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    me: &NoiseIdentity,
    channel: Channel,
) -> io::Result<SecureStream<S>> {
    timeout(HANDSHAKE_TIMEOUT, handshake(io, me, channel, false, None))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "noise handshake timed out"))?
}

async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    me: &NoiseIdentity,
    channel: Channel,
    initiator: bool,
    expected: Option<&NodeId>,
) -> io::Result<SecureStream<S>> {
    let builder = snow::Builder::new(noise_params())
        .local_private_key(&me.inner.static_private)
        .map_err(noise_err)?
        .prologue(channel.prologue())
        .map_err(noise_err)?;
    let mut hs = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(noise_err)?;

    let mut out = vec![0u8; MAX_FRAME];
    let mut payload = vec![0u8; MAX_FRAME];

    let peer = if initiator {
        // -> e
        let n = hs.write_message(&[], &mut out).map_err(noise_err)?;
        write_handshake_frame(&mut io, &out[..n]).await?;
        // <- e, ee, s, es + binding ответчика
        let msg = read_handshake_frame(&mut io).await?;
        let n = hs.read_message(&msg, &mut payload).map_err(noise_err)?;
        let remote = hs.get_remote_static().ok_or_else(|| denied("нет ключа собеседника"))?;
        let peer = verify_binding(&payload[..n], remote)?;
        if let Some(exp) = expected {
            if *exp != peer {
                return Err(denied(&format!(
                    "на том конце узел {}, ожидался {}",
                    short(&peer),
                    short(exp)
                )));
            }
        }
        // -> s, se + наш binding (только после проверки собеседника)
        let n = hs.write_message(&me.inner.binding, &mut out).map_err(noise_err)?;
        write_handshake_frame(&mut io, &out[..n]).await?;
        peer
    } else {
        // <- e
        let msg = read_handshake_frame(&mut io).await?;
        hs.read_message(&msg, &mut payload).map_err(noise_err)?;
        // -> e, ee, s, es + наш binding
        let n = hs.write_message(&me.inner.binding, &mut out).map_err(noise_err)?;
        write_handshake_frame(&mut io, &out[..n]).await?;
        // <- s, se + binding инициатора
        let msg = read_handshake_frame(&mut io).await?;
        let n = hs.read_message(&msg, &mut payload).map_err(noise_err)?;
        let remote = hs.get_remote_static().ok_or_else(|| denied("нет ключа собеседника"))?;
        verify_binding(&payload[..n], remote)?
    };

    let noise = hs.into_transport_mode().map_err(noise_err)?;
    Ok(SecureStream::new(io, noise, peer))
}

fn short(id: &NodeId) -> &str {
    &id.as_str()[..8.min(id.as_str().len())]
}

async fn write_handshake_frame<S: AsyncWrite + Unpin>(io: &mut S, msg: &[u8]) -> io::Result<()> {
    io.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    io.write_all(msg).await?;
    io.flush().await
}

async fn read_handshake_frame<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Vec<u8>> {
    let len = io.read_u16().await? as usize;
    let mut msg = vec![0u8; len];
    io.read_exact(&mut msg).await?;
    Ok(msg)
}

// ─── Зашифрованный поток ─────────────────────────────────────────────────────────

/// Поток после рукопожатия: прозрачно шифрует запись и расшифровывает чтение.
pub struct SecureStream<S> {
    io: S,
    noise: snow::TransportState,
    peer: NodeId,
    /// Принятые, ещё не разобранные байты кадров.
    rbuf: Vec<u8>,
    /// Расшифрованный текст текущего кадра и позиция чтения в нём.
    plain: Vec<u8>,
    plain_pos: usize,
    /// Буфер для чтения из `io`.
    scratch: Box<[u8]>,
    /// Зашифрованный кадр, ещё не полностью записанный в `io`.
    wbuf: Vec<u8>,
    wpos: usize,
    /// Кадр не расшифровался — поток испорчен, дальше только ошибки.
    broken: bool,
}

impl<S> std::fmt::Debug for SecureStream<S> {
    /// Только собеседник — без ключей и буферов.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureStream").field("peer", &self.peer).finish_non_exhaustive()
    }
}

impl<S> SecureStream<S> {
    fn new(io: S, noise: snow::TransportState, peer: NodeId) -> Self {
        Self {
            io,
            noise,
            peer,
            rbuf: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
            scratch: vec![0u8; 16 * 1024].into_boxed_slice(),
            wbuf: Vec::new(),
            wpos: 0,
            broken: false,
        }
    }

    /// NodeId собеседника, доказанный рукопожатием.
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }
}

impl<S: AsyncWrite + Unpin> SecureStream<S> {
    /// Дописывает в `io` отложенный зашифрованный кадр.
    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SecureStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.broken {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "noise: поток повреждён")));
            }
            if this.plain_pos < this.plain.len() {
                let n = buf.remaining().min(this.plain.len() - this.plain_pos);
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }

            // Целый кадр уже в буфере — расшифровываем.
            if this.rbuf.len() >= 2 {
                let len = u16::from_be_bytes([this.rbuf[0], this.rbuf[1]]) as usize;
                if this.rbuf.len() >= 2 + len {
                    this.plain.resize(len, 0);
                    match this.noise.read_message(&this.rbuf[2..2 + len], &mut this.plain) {
                        Ok(n) => this.plain.truncate(n),
                        Err(_) => {
                            this.broken = true;
                            continue;
                        }
                    }
                    this.plain_pos = 0;
                    this.rbuf.drain(..2 + len);
                    continue;
                }
            }

            // Нужны ещё байты из сети.
            let mut rb = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                return if this.rbuf.is_empty() {
                    Poll::Ready(Ok(())) // чистый EOF на границе кадра
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            this.rbuf.extend_from_slice(&this.scratch[..n]);
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SecureStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Не держим больше одного кадра: сначала дописываем предыдущий.
        ready!(this.poll_write_pending(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let n = buf.len().min(MAX_PLAINTEXT);
        this.wbuf.resize(2 + n + TAG_LEN, 0);
        let len = this
            .noise
            .write_message(&buf[..n], &mut this.wbuf[2..])
            .map_err(noise_err)?;
        this.wbuf[..2].copy_from_slice(&(len as u16).to_be_bytes());
        this.wbuf.truncate(2 + len);
        this.wpos = 0;

        // Пробуем отправить сразу; если сокет занят — кадр уйдёт при flush/следующей записи.
        if let Poll::Ready(Err(e)) = this.poll_write_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_pending(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_write_pending(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

// ─── Тесты ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn identity(seed: u8) -> NoiseIdentity {
        NoiseIdentity::new(&SigningKeypair::from_seed(&[seed; 32]).unwrap())
    }

    /// Рукопожатие поверх in-memory пары; возвращает обе стороны.
    async fn pair(
        a: &NoiseIdentity,
        b: &NoiseIdentity,
        channel_a: Channel,
        channel_b: Channel,
        expected: Option<NodeId>,
    ) -> (io::Result<SecureStream<tokio::io::DuplexStream>>, io::Result<SecureStream<tokio::io::DuplexStream>>) {
        let (ia, ib) = duplex(256 * 1024);
        let b = b.clone();
        let server = tokio::spawn(async move { accept(ib, &b, channel_b).await });
        let client = connect(ia, a, channel_a, expected.as_ref()).await;
        let server = server.await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn mutual_authentication_and_large_transfer() {
        let (a, b) = (identity(1), identity(2));
        let (client, server) = pair(&a, &b, Channel::Dm, Channel::Dm, Some(b.node_id().clone())).await;
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.peer(), b.node_id(), "клиент знает, с кем говорит");
        assert_eq!(server.peer(), a.node_id(), "сервер знает, кто подключился");

        // Больше одного Noise-кадра в обе стороны.
        let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let expected = big.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&big).await.unwrap();
            client.flush().await.unwrap();
            let mut back = vec![0u8; 5];
            client.read_exact(&mut back).await.unwrap();
            back
        });
        let mut got = vec![0u8; expected.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        server.write_all(b"thanks").await.unwrap();
        server.flush().await.unwrap();
        assert_eq!(&writer.await.unwrap(), b"thank");
    }

    #[tokio::test]
    async fn unexpected_peer_rejected() {
        // Подключаемся к «Алисе», а отвечает другой узел (подменённый IP).
        let (me, impostor, alice) = (identity(1), identity(2), identity(3));
        let (client, _server) =
            pair(&me, &impostor, Channel::Dm, Channel::Dm, Some(alice.node_id().clone())).await;
        let err = client.err().expect("подмена собеседника должна быть обнаружена");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn channel_mismatch_fails() {
        let (a, b) = (identity(1), identity(2));
        let (client, server) = pair(&a, &b, Channel::Chunks, Channel::Dm, None).await;
        assert!(client.is_err() || server.is_err(), "рукопожатие чужого канала не проходит");
        assert!(client.is_err());
    }

    /// Чужая (перехваченная) привязка с собственным Noise-ключом не проходит:
    /// подпись привязывает NodeId к конкретному Noise-ключу.
    #[tokio::test]
    async fn stolen_binding_rejected() {
        let (victim, attacker, server_id) = (identity(1), identity(2), identity(3));
        let forged = NoiseIdentity {
            inner: Arc::new(IdentityInner {
                node_id: victim.node_id().clone(),
                static_private: attacker.inner.static_private.clone(),
                binding: victim.inner.binding,
            }),
        };
        let (client, server) = pair(&forged, &server_id, Channel::Dm, Channel::Dm, None).await;
        let _ = client;
        let err = server.err().expect("сервер должен отклонить чужую привязку");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn tampered_frame_is_rejected() {
        let (a, b) = (identity(1), identity(2));
        let (client, server) = pair(&a, &b, Channel::Chat, Channel::Chat, None).await;
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        // Подмешиваем «кадр» мимо шифрования — как это сделал бы посредник.
        client.io.write_all(&[0, 20]).await.unwrap();
        client.io.write_all(&[0xAB; 20]).await.unwrap();
        let mut buf = [0u8; 8];
        let err = server.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn clean_eof_after_peer_closes() {
        let (a, b) = (identity(1), identity(2));
        let (client, server) = pair(&a, &b, Channel::Chat, Channel::Chat, None).await;
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        client.write_all(b"bye").await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);
        let mut all = Vec::new();
        server.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"bye");
    }

    #[tokio::test]
    async fn silent_peer_times_out() {
        let me = identity(1);
        let (ia, _ib) = duplex(1024); // другая сторона молчит
        let res = connect(ia, &me, Channel::Chat, None).await;
        assert_eq!(res.err().unwrap().kind(), io::ErrorKind::TimedOut);
    }
}
