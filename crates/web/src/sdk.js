/*
 * Void Connect — SDK для сайтов сети.
 *
 * Подключение:  <script src="/.void/sdk.js"></script>   → window.Void
 *
 * Документация: docs/site-api.md в репозитории Void Connect.
 *
 * Все вызовы идут к узлу пользователя на адрес самого сайта. Разрешения
 * пользователь подтверждает в окне Void Connect, не на странице: подделать
 * согласие сайт не может.
 *
 * Важно для безопасности вашего сайта: данные записей пишут другие люди.
 * Показывайте их через textContent, а не innerHTML. Inline-скрипты и eval на
 * сайтах сети запрещены политикой CSP — весь код держите в .js-файлах.
 */
(() => {
  'use strict';

  const API = '/.void/api';

  /** Ошибка вызова API: `code` — машинный код, `permission` — какое разрешение нужно. */
  class VoidError extends Error {
    constructor(message, code, status, permission) {
      super(message);
      this.name = 'VoidError';
      this.code = code;
      this.status = status;
      this.permission = permission || null;
    }
  }

  const config = {
    /** Показывать подсказку «подтвердите в окне Void Connect» на время вопроса. */
    consentHint: true,
  };

  function buildUrl(path, query) {
    let url = API + path;
    if (query) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) q.set(k, String(v));
      }
      const s = q.toString();
      if (s) url += '?' + s;
    }
    return url;
  }

  async function call(method, path, { query, body } = {}) {
    const init = {
      method,
      headers: { 'X-Void-Api': '1' },
      credentials: 'omit',
      cache: 'no-store',
    };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
      init.headers['Content-Type'] = 'application/json';
    }
    const res = await fetch(buildUrl(path, query), init);
    let data = null;
    try { data = await res.json(); } catch (_) { /* не JSON */ }
    if (!res.ok) {
      throw new VoidError(
        (data && data.error) || res.statusText,
        (data && data.code) || 'http_' + res.status,
        res.status,
        res.headers.get('X-Void-Permission'),
      );
    }
    return data;
  }

  // ── Подсказка на время вопроса пользователю ─────────────────────────────
  let hintDepth = 0;
  let hintEl = null;
  function showHint(text) {
    if (!config.consentHint || !document.body) return () => {};
    hintDepth += 1;
    if (!hintEl) {
      hintEl = document.createElement('div');
      Object.assign(hintEl.style, {
        position: 'fixed', left: '50%', bottom: '24px', transform: 'translateX(-50%)',
        zIndex: '2147483647', padding: '10px 16px', borderRadius: '10px',
        background: 'rgba(20,20,22,0.94)', color: '#fff', font: '14px/1.4 system-ui, sans-serif',
        boxShadow: '0 6px 24px rgba(0,0,0,0.35)', pointerEvents: 'none',
      });
      document.body.appendChild(hintEl);
    }
    hintEl.textContent = text;
    return () => {
      hintDepth -= 1;
      if (hintDepth <= 0 && hintEl) { hintEl.remove(); hintEl = null; hintDepth = 0; }
    };
  }

  // ── Живые обновления: один WebSocket на страницу ───────────────────────
  // Браузер держит не больше 6 HTTP-соединений на адрес; поток на каждую
  // подписку быстро занял бы их все. Поэтому все подписки страницы делят одно
  // WebSocket-соединение, а записи раздаются подписчикам здесь.
  const hub = { ws: null, subs: new Set(), backoff: 1000, timer: null, everOpened: false };

  function hubConnect() {
    if (hub.ws || hub.timer || hub.subs.size === 0) return;
    const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
    const ws = new WebSocket(proto + location.host + API + '/events');
    hub.ws = ws;
    ws.onopen = () => {
      // Пока соединения не было, изменения могли пройти мимо — перечитать.
      if (hub.everOpened) for (const s of hub.subs) s.resync();
      hub.everOpened = true;
      hub.backoff = 1000;
    };
    ws.onmessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch (_) { return; }
      if (m.type === 'record') for (const s of hub.subs) s.deliver(m.record);
      else if (m.type === 'resync') for (const s of hub.subs) s.resync();
    };
    ws.onclose = () => {
      if (hub.ws !== ws) return;
      hub.ws = null;
      if (hub.subs.size === 0) return;
      hub.timer = setTimeout(() => { hub.timer = null; hubConnect(); }, hub.backoff);
      hub.backoff = Math.min(hub.backoff * 2, 15000);
    };
  }

  function subscribe(opts, onRecord) {
    const sub = {
      deliver(r) {
        if (opts.collection && r.collection !== opts.collection) return;
        if (opts.link && r.link !== opts.link) return;
        try { onRecord(r); } catch (e) { console.error(e); }
      },
      resync() {
        if (opts.onResync) { try { opts.onResync(); } catch (e) { console.error(e); } }
      },
    };
    hub.subs.add(sub);
    hubConnect();
    return {
      close() {
        hub.subs.delete(sub);
        if (hub.subs.size === 0 && hub.ws) {
          const ws = hub.ws;
          hub.ws = null;
          ws.close();
        }
      },
    };
  }

  // ── Загрузка файла (XHR — ради прогресса) ───────────────────────────────
  function upload(file, opts = {}) {
    return new Promise((resolve, reject) => {
      const done = showHint('Подтвердите загрузку «' + (opts.name || file.name) + '» в окне Void Connect');
      const xhr = new XMLHttpRequest();
      xhr.open('POST', buildUrl('/files', { name: opts.name || file.name }));
      xhr.setRequestHeader('X-Void-Api', '1');
      xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
      xhr.responseType = 'json';
      let started = false;
      xhr.upload.onprogress = (e) => {
        if (!started) { started = true; done(); }
        if (opts.onProgress && e.lengthComputable) opts.onProgress(e.loaded / e.total);
      };
      xhr.onload = () => {
        done();
        const data = xhr.response;
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new VoidError((data && data.error) || 'HTTP ' + xhr.status,
          (data && data.code) || 'http_' + xhr.status, xhr.status, null));
      };
      xhr.onerror = () => { done(); reject(new VoidError('сеть недоступна', 'network', 0, null)); };
      xhr.onabort = () => { done(); reject(new VoidError('загрузка отменена', 'aborted', 0, null)); };
      if (opts.signal) opts.signal.addEventListener('abort', () => xhr.abort());
      xhr.send(file);
    });
  }

  function newKey() {
    const b = new Uint8Array(12);
    crypto.getRandomValues(b);
    return Date.now().toString(36) + '-' + Array.from(b, (x) => x.toString(36).padStart(2, '0')).join('').slice(0, 16);
  }

  const Void = {
    version: 1,
    VoidError,
    config,

    /** Сведения о сайте: имя, владелец. */
    site: () => call('GET', '/site'),

    /** Пользователь: {id, name, avatar}. Нужно разрешение identity. */
    me: () => call('GET', '/me'),

    /** Разрешения, уже выданные сайту: ['identity', 'publish']. */
    permissions: async () => (await call('GET', '/permissions')).granted,

    /**
     * Попросить разрешения. Пользователь ответит в окне Void Connect (до 2 мин).
     * Возвращает выданные разрешения; при отказе — VoidError с code 'denied'.
     */
    async requestPermissions(perms) {
      const granted = await this.permissions();
      if (perms.every((p) => granted.includes(p))) return granted;
      const done = showHint('Подтвердите доступ для этого сайта в окне Void Connect');
      try {
        return (await call('POST', '/permissions', { body: { permissions: perms } })).granted;
      } finally {
        done();
      }
    },

    /** Публичный профиль узла по ID или null. */
    async profile(id) {
      try {
        return await call('GET', '/profiles/' + encodeURIComponent(id));
      } catch (e) {
        if (e.code === 'not_found') return null;
        throw e;
      }
    },

    records: {
      /**
       * Записи коллекции, свежие первыми.
       * opts: {author, key, link, since, before, limit (≤500)}
       */
      query: async (collection, opts = {}) =>
        (await call('GET', '/records', { query: { collection, ...opts } })).records,

      /** Одна запись автора по ключу или null. */
      get: async (collection, author, key) =>
        (await call('GET', '/records', { query: { collection, author, key, limit: 1 } })).records[0] || null,

      /** Создать или изменить свою запись. data — JSON до 8 КБ. opts: {link}. Нужно publish. */
      put: (collection, key, data, opts = {}) =>
        call('PUT', '/records', { body: { collection, key, data, link: opts.link } }),

      /** Удалить свою запись. Нужно publish. */
      delete: (collection, key) => call('DELETE', '/records', { query: { collection, key } }),

      /**
       * Живые изменения: onRecord(record) на каждую новую/изменённую/удалённую
       * (record.deleted) запись. opts: {collection, link, onResync}.
       * Возвращает {close()}.
       */
      subscribe: (opts, onRecord) => subscribe(opts || {}, onRecord),
    },

    files: {
      /**
       * Опубликовать файл в сеть (File/Blob). Пользователь подтверждает в окне
       * Void Connect. opts: {name, onProgress(0..1), signal}.
       * Возвращает {fileId, name, size, type}.
       */
      upload,

      /** Сведения о файле: {id, name, size, type, playable, publisher, local}. */
      info: (id) => call('GET', '/files/' + encodeURIComponent(id)),

      /** Адрес содержимого файла для <video>, <img>, <a download>. */
      url: (id) => '/.void/files/' + encodeURIComponent(id),
    },

    /** Уникальный ключ для новой записи. */
    newKey,
  };

  Object.freeze(Void.records);
  Object.freeze(Void.files);
  window.Void = Object.freeze(Void);
})();
