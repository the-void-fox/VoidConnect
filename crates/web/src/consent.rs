//! Запросы согласия пользователя (JS API).
//!
//! Когда сайт просит разрешение или хочет загрузить файл в сеть, HTTP-запрос
//! ждёт, пока пользователь ответит в окне Void Connect. Страница сайта видит
//! только итог «да/нет»: подделать диалог она не может — он рисуется не в
//! браузере. Защита от назойливости: не больше [`MAX_PENDING_PER_SITE`]
//! вопросов от сайта одновременно, после отказа в разрешениях сайт
//! [`DENY_COOLDOWN`] не может спросить снова, без ответа вопрос снимается через
//! [`REQUEST_TTL`] (= отказ).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::permissions::Permission;

/// Сколько вопросов одного сайта может ждать ответа одновременно.
pub const MAX_PENDING_PER_SITE: usize = 3;
/// Сколько сайт не может снова спрашивать разрешения после отказа.
pub const DENY_COOLDOWN: Duration = Duration::from_secs(120);
/// Пауза после отказа в публикации файла: короче — пользователь мог просто
/// выбрать не тот файл, — но не даёт сайту засыпать его диалогами.
pub const UPLOAD_DENY_COOLDOWN: Duration = Duration::from_secs(15);
/// Сколько вопрос ждёт ответа (дальше — отказ).
pub const REQUEST_TTL: Duration = Duration::from_secs(120);

/// О чём спрашивают.
#[derive(Debug, Clone, PartialEq)]
pub enum ConsentKind {
    /// Выдать сайту разрешения.
    Permissions(Vec<Permission>),
    /// Опубликовать в сеть файл, выбранный на странице.
    Upload { name: String, size: u64 },
}

/// Вопрос, ожидающий ответа пользователя.
#[derive(Debug, Clone)]
pub struct ConsentRequest {
    pub id: u64,
    /// Имя сайта (нормализованное, без зоны).
    pub site: String,
    pub kind: ConsentKind,
    pub created: Instant,
}

/// Почему вопрос не задан.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Сайт уже ждёт ответа на несколько вопросов.
    TooMany,
    /// Сайту недавно отказали — пусть подождёт.
    Cooldown,
}

struct Pending {
    req: ConsentRequest,
    reply: oneshot::Sender<bool>,
}

/// Вид вопроса для пауз после отказа.
fn kind_tag(kind: &ConsentKind) -> u8 {
    match kind {
        ConsentKind::Permissions(_) => 0,
        ConsentKind::Upload { .. } => 1,
    }
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    pending: Vec<Pending>,
    /// (сайт, вид вопроса) → до какого момента не спрашивать.
    cooldown: HashMap<(String, u8), Instant>,
}

type Waker = Arc<dyn Fn() + Send + Sync>;

/// Очередь вопросов к пользователю. Клонируется дёшево.
#[derive(Clone, Default)]
pub struct ConsentBroker {
    inner: Arc<Mutex<Inner>>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl ConsentBroker {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Функция, которую вызываем при новом вопросе (интерфейс перерисуется и
    /// привлечёт внимание пользователя).
    pub fn set_waker(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(f));
    }

    /// Задаёт вопрос. Ответ придёт в канал (`false` — отказ или истёк срок).
    pub fn ask(&self, site: &str, kind: ConsentKind) -> Result<oneshot::Receiver<bool>, Refused> {
        let now = Instant::now();
        let rx = {
            let mut inner = self.lock();
            Self::expire(&mut inner, now);
            if inner.cooldown.get(&(site.to_string(), kind_tag(&kind))).is_some_and(|until| *until > now) {
                return Err(Refused::Cooldown);
            }
            if inner.pending.iter().filter(|p| p.req.site == site).count() >= MAX_PENDING_PER_SITE {
                return Err(Refused::TooMany);
            }
            inner.next_id += 1;
            let (tx, rx) = oneshot::channel();
            let req = ConsentRequest { id: inner.next_id, site: site.to_string(), kind, created: now };
            inner.pending.push(Pending { req, reply: tx });
            rx
        };
        let waker = self.waker.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(w) = waker {
            w();
        }
        Ok(rx)
    }

    /// Снимает истёкшие вопросы и те, чей HTTP-запрос уже закрыт (вкладку
    /// закрыли) — отвечать на них незачем.
    fn expire(inner: &mut Inner, now: Instant) {
        let mut i = 0;
        while i < inner.pending.len() {
            let p = &inner.pending[i];
            if now.duration_since(p.req.created) > REQUEST_TTL || p.reply.is_closed() {
                let p = inner.pending.remove(i);
                let _ = p.reply.send(false);
            } else {
                i += 1;
            }
        }
        inner.cooldown.retain(|_, until| *until > now);
    }

    /// Вопросы, ждущие ответа (старые первыми).
    pub fn pending(&self) -> Vec<ConsentRequest> {
        let mut inner = self.lock();
        Self::expire(&mut inner, Instant::now());
        inner.pending.iter().map(|p| p.req.clone()).collect()
    }

    /// Ответ пользователя. Отказ включает паузу для сайта (на этот вид вопроса).
    pub fn answer(&self, id: u64, allow: bool) {
        let mut inner = self.lock();
        let Some(pos) = inner.pending.iter().position(|p| p.req.id == id) else { return };
        let p = inner.pending.remove(pos);
        if !allow {
            let pause = match p.req.kind {
                ConsentKind::Permissions(_) => DENY_COOLDOWN,
                ConsentKind::Upload { .. } => UPLOAD_DENY_COOLDOWN,
            };
            inner.cooldown.insert((p.req.site.clone(), kind_tag(&p.req.kind)), Instant::now() + pause);
        }
        let _ = p.reply.send(allow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perms() -> ConsentKind {
        ConsentKind::Permissions(vec![Permission::Identity])
    }

    #[tokio::test]
    async fn answer_reaches_waiting_request() {
        let b = ConsentBroker::new();
        let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w = Arc::clone(&woken);
        b.set_waker(move || {
            w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let rx = b.ask("tube", perms()).unwrap();
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 1);
        let pending = b.pending();
        assert_eq!(pending.len(), 1);
        b.answer(pending[0].id, true);
        assert!(rx.await.unwrap());
        assert!(b.pending().is_empty());
    }

    #[tokio::test]
    async fn denial_starts_cooldown_per_kind() {
        let b = ConsentBroker::new();
        let rx = b.ask("tube", perms()).unwrap();
        b.answer(b.pending()[0].id, false);
        assert!(!rx.await.unwrap());
        assert_eq!(b.ask("tube", perms()).unwrap_err(), Refused::Cooldown);
        // Другой сайт и другой вид вопроса паузой не задеты.
        assert!(b.ask("blog", perms()).is_ok());
        let upload = || ConsentKind::Upload { name: "a.webm".into(), size: 1 };
        let rx = b.ask("tube", upload()).unwrap();
        let id = b.pending().iter().find(|r| r.site == "tube").unwrap().id;
        b.answer(id, false);
        assert!(!rx.await.unwrap());
        assert_eq!(b.ask("tube", upload()).unwrap_err(), Refused::Cooldown, "после отказа в загрузке — тоже пауза");
    }

    #[test]
    fn site_cannot_flood_questions() {
        let b = ConsentBroker::new();
        let _keep: Vec<_> = (0..MAX_PENDING_PER_SITE)
            .map(|i| b.ask("tube", ConsentKind::Upload { name: format!("{i}"), size: 1 }).unwrap())
            .collect();
        assert_eq!(
            b.ask("tube", ConsentKind::Upload { name: "x".into(), size: 1 }).unwrap_err(),
            Refused::TooMany
        );
        assert!(b.ask("blog", perms()).is_ok());
    }

    #[test]
    fn closed_request_is_dropped() {
        let b = ConsentBroker::new();
        let rx = b.ask("tube", perms()).unwrap();
        drop(rx); // вкладку закрыли
        assert!(b.pending().is_empty());
    }
}
