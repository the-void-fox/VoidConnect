// VoidTube — пример сайта на JS API Void Connect.
//
// Данные сайта — записи пользователей (каждую подписывает автор):
//   videos   ключ — случайный, data {title, description, fileId, size, type, thumb}
//   likes    ключ — "l-<ключ видео>-<начало ID автора>", link = "<автор>:<ключ видео>"
//   comments ключ — случайный, link = "<автор>:<ключ видео>", data {text}
//   hidden   (только владелец сайта) ключ "h-…", link = "<автор>:<ключ видео>" — скрыть видео
//
// Всё, что пришло от других людей, выводится через textContent (функция h),
// никакого innerHTML: иначе комментарий мог бы выполнить код от имени зрителя.

'use strict';

const view = document.getElementById('view');
const accountBox = document.getElementById('account');

const state = {
  me: null,          // {id, name, avatar} после входа
  canPublish: false,
  site: null,        // {name, owner: {id, name}}
  profiles: new Map(),
  subs: [],          // открытые подписки текущей страницы
};

// ── DOM без innerHTML ──────────────────────────────────────────────────────
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function clear(el, ...children) {
  el.replaceChildren(...children.flat().filter(Boolean));
}

function ago(ms) {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return 'только что';
  if (s < 3600) return Math.floor(s / 60) + ' мин назад';
  if (s < 86400) return Math.floor(s / 3600) + ' ч назад';
  return new Date(ms).toLocaleDateString('ru-RU');
}

function size(bytes) {
  if (bytes >= 1 << 30) return (bytes / (1 << 30)).toFixed(1) + ' ГБ';
  if (bytes >= 1 << 20) return (bytes / (1 << 20)).toFixed(1) + ' МБ';
  return Math.max(1, Math.round(bytes / 1024)) + ' КБ';
}

const TRUST = {
  verified: 'проверен вами',
  trusted: 'знакомый',
  settled: 'освоившийся',
  stranger: 'новичок',
};

// Аватар: картинка из профиля (data:URI) или первая буква имени.
function avatar(profile, small) {
  const cls = 'avatar' + (small ? ' small' : '');
  if (profile && profile.avatar && profile.avatar.startsWith('data:image/png;base64,')) {
    return h('img', { class: cls, src: profile.avatar, alt: '' });
  }
  const letter = ((profile && profile.name) || '?').trim().charAt(0).toUpperCase() || '?';
  return h('span', { class: cls }, letter);
}

async function profileOf(id) {
  if (!state.profiles.has(id)) {
    state.profiles.set(id, Void.profile(id).catch(() => null));
  }
  return state.profiles.get(id);
}

function authorLine(id, trust, small) {
  const box = h('span', { class: 'row' });
  const isMe = state.me && state.me.id === id;
  profileOf(id).then((p) => {
    const name = (p && p.name) || id.slice(0, 8);
    const badge = isMe ? h('span', { class: 'badge verified' }, 'вы')
      : trust && TRUST[trust] ? h('span', { class: 'badge ' + trust }, TRUST[trust]) : null;
    clear(box, avatar(p, small), h('span', {}, name), badge);
  });
  return box;
}

// ── Вход: разрешения у пользователя (он отвечает в окне Void Connect) ──────
async function refreshAccount() {
  const granted = await Void.permissions().catch(() => []);
  state.canPublish = granted.includes('publish');
  state.me = granted.includes('identity') ? await Void.me().catch(() => null) : null;
  if (state.me) {
    clear(accountBox, avatar(state.me), h('span', {}, state.me.name));
  } else {
    clear(accountBox, h('button', { class: 'primary', onclick: login }, 'Войти'));
  }
}

async function login() {
  try {
    await Void.requestPermissions(['identity', 'publish']);
  } catch (e) {
    if (e.code === 'denied' || e.code === 'cooldown') alert('Без разрешения можно только смотреть.');
    else alert('Не получилось: ' + e.message);
  }
  await refreshAccount();
  route();
}

async function needLogin() {
  if (state.canPublish && state.me) return true;
  await login();
  return state.canPublish && state.me;
}

// ── Модерация владельцем сайта ─────────────────────────────────────────────
async function hiddenSet() {
  if (!state.site) return new Set();
  const recs = await Void.records.query('hidden', { author: state.site.owner.id, limit: 500 }).catch(() => []);
  return new Set(recs.map((r) => r.link));
}

// ── Лента ──────────────────────────────────────────────────────────────────
async function showFeed() {
  clear(view, h('p', { class: 'muted' }, 'Загружаю…'));
  const [videos, hidden] = await Promise.all([
    Void.records.query('videos', { limit: 200 }),
    hiddenSet(),
  ]);
  const visible = videos.filter((v) => !hidden.has(v.author + ':' + v.key) && v.data && v.data.fileId);
  if (!visible.length) {
    clear(view, h('div', { class: 'empty' },
      h('p', {}, 'Пока ни одного видео.'),
      h('a', { href: '#/upload' }, h('button', { class: 'primary' }, 'Загрузить первое'))));
    return;
  }
  clear(view, h('div', { class: 'grid' }, visible.map(videoCard)));
  // Новые видео появляются сами.
  state.subs.push(Void.records.subscribe({ collection: 'videos', onResync: showFeed }, () => showFeed()));
}

function videoCard(v) {
  const d = v.data || {};
  const thumb = h('div', { class: 'thumb' });
  if (typeof d.thumb === 'string' && d.thumb.startsWith('data:image/jpeg;base64,')) {
    thumb.append(h('img', { src: d.thumb, alt: '' }));
  } else {
    thumb.textContent = '▶';
  }
  return h('a', { class: 'card', href: '#/watch/' + v.author + '/' + encodeURIComponent(v.key) },
    thumb,
    h('div', { class: 'card-meta' },
      h('div', {},
        h('div', { class: 'card-title' }, String(d.title || 'Без названия')),
        h('div', { class: 'faint' }, ago(v.updatedAt) + (d.size ? ' · ' + size(d.size) : '')),
        authorLine(v.author, v.trust, true))));
}

// ── Просмотр ───────────────────────────────────────────────────────────────
async function showWatch(author, key) {
  clear(view, h('p', { class: 'muted' }, 'Загружаю…'));
  const v = await Void.records.get('videos', author, key);
  if (!v || !v.data || !v.data.fileId) {
    clear(view, h('div', { class: 'empty' }, 'Видео не найдено (или автор его удалил).'));
    return;
  }
  const d = v.data;
  const ref = author + ':' + key;
  const player = h('video', { class: 'player', controls: true, preload: 'metadata', src: Void.files.url(d.fileId) });
  player.addEventListener('error', () => {
    status.textContent = 'Видео пока недоступно: никто из раздающих не в сети.';
  });
  const status = h('p', { class: 'error' });
  const likeBtn = h('button', { onclick: () => toggleLike(ref, key, likeBtn) }, '♥ …');
  const actions = h('div', { class: 'row' }, authorLine(author, v.trust), h('span', { class: 'spacer' }), likeBtn);

  if (state.me && author === state.me.id) {
    actions.append(h('button', {
      onclick: async () => {
        if (!confirm('Удалить видео из ленты?')) return;
        await Void.records.delete('videos', key).catch((e) => alert(e.message));
        location.hash = '#/';
      },
    }, 'Удалить'));
  } else if (state.me && state.site && state.me.id === state.site.owner.id) {
    actions.append(h('button', {
      onclick: async () => {
        const hk = 'h-' + key + '-' + author.slice(0, 16);
        await Void.records.put('hidden', hk, { at: Date.now() }, { link: ref }).catch((e) => alert(e.message));
        location.hash = '#/';
      },
    }, 'Скрыть (модерация)'));
  }

  const comments = h('div', {});
  const form = commentForm(ref);
  clear(view, h('div', { class: 'watch' },
    h('div', {},
      player, status,
      h('h1', {}, String(d.title || 'Без названия')),
      actions,
      h('div', { class: 'desc' },
        h('div', { class: 'faint' }, ago(v.updatedAt) + (d.size ? ' · ' + size(d.size) : '')),
        String(d.description || ''))),
    h('aside', { class: 'side' }, h('h2', {}, 'Комментарии'), form, comments)));

  const loadComments = async () => {
    const list = await Void.records.query('comments', { link: ref, limit: 300 });
    clear(comments, list.length ? list.map(commentEl) : h('p', { class: 'faint' }, 'Пока никто не написал.'));
  };
  const loadLikes = async () => {
    const likes = await Void.records.query('likes', { link: ref, limit: 500 });
    const myKey = state.me ? likeKey(key) : null;
    const mine = likes.some((l) => l.mine && l.key === myKey);
    likeBtn.textContent = '♥ ' + likes.length;
    likeBtn.classList.toggle('liked', mine);
    likeBtn.dataset.mine = mine ? '1' : '';
  };
  await Promise.all([loadComments(), loadLikes()]);
  state.subs.push(Void.records.subscribe({ collection: 'comments', link: ref, onResync: loadComments }, loadComments));
  state.subs.push(Void.records.subscribe({ collection: 'likes', link: ref, onResync: loadLikes }, loadLikes));
}

function commentEl(c) {
  return h('div', { class: 'comment' },
    h('div', { class: 'comment-body' },
      h('div', { class: 'row faint' }, authorLine(c.author, c.trust, true), ago(c.updatedAt)),
      h('div', { class: 'comment-text' }, String((c.data && c.data.text) || ''))));
}

function commentForm(ref) {
  const input = h('textarea', { maxlength: 2000, placeholder: 'Написать комментарий…' });
  const send = h('button', { class: 'primary' }, 'Отправить');
  send.addEventListener('click', async () => {
    const text = input.value.trim();
    if (!text || !(await needLogin())) return;
    send.disabled = true;
    try {
      await Void.records.put('comments', Void.newKey(), { text }, { link: ref });
      input.value = '';
    } catch (e) {
      alert(e.code === 'rate_limited' ? 'Слишком часто — подождите немного.' : e.message);
    } finally {
      send.disabled = false;
    }
  });
  return h('div', { class: 'comment-form' }, input, send);
}

// Ключ лайка зависит от видео и автора: повторный лайк не создаст второй записи.
function likeKey(videoKey) {
  return 'l-' + videoKey + '-' + state.me.id.slice(0, 16);
}

async function toggleLike(ref, videoKey, btn) {
  if (!(await needLogin())) return;
  const key = likeKey(videoKey);
  btn.disabled = true;
  try {
    if (btn.dataset.mine) await Void.records.delete('likes', key);
    else await Void.records.put('likes', key, { at: Date.now() }, { link: ref });
  } catch (e) {
    alert(e.message);
  } finally {
    btn.disabled = false;
  }
}

// ── Загрузка ───────────────────────────────────────────────────────────────

// Кадр видео на 1-й секунде → JPEG до ~6 КБ (миниатюра живёт прямо в записи).
function makeThumb(file) {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const v = document.createElement('video');
    v.muted = true;
    v.preload = 'auto';
    v.src = url;
    const done = (res) => { URL.revokeObjectURL(url); resolve(res); };
    v.addEventListener('error', () => done(null));
    v.addEventListener('loadeddata', () => { v.currentTime = Math.min(1, (v.duration || 2) / 2); });
    v.addEventListener('seeked', () => {
      const c = document.createElement('canvas');
      c.width = 192;
      c.height = 108;
      c.getContext('2d').drawImage(v, 0, 0, c.width, c.height);
      for (const q of [0.6, 0.45, 0.3]) {
        const data = c.toDataURL('image/jpeg', q);
        if (data.length <= 6000) return done(data);
      }
      done(null);
    }, { once: true });
  });
}

function showUpload() {
  let file = null;
  let thumb = null;
  const fileInput = h('input', { type: 'file', accept: 'video/*' });
  const dropLabel = h('div', {}, 'Выберите видео (mp4, webm…)');
  const preview = h('div', {});
  const title = h('input', { type: 'text', maxlength: 120, placeholder: 'Название' });
  const desc = h('textarea', { maxlength: 3000, placeholder: 'Описание (необязательно)' });
  const progress = h('progress', { max: 1, value: 0, hidden: true });
  const status = h('p', { class: 'muted' });
  const go = h('button', { class: 'primary', disabled: true }, 'Опубликовать');

  fileInput.addEventListener('change', async () => {
    file = fileInput.files[0] || null;
    go.disabled = !file;
    if (!file) return;
    dropLabel.textContent = file.name + ' · ' + size(file.size);
    if (!title.value) title.value = file.name.replace(/\.[^.]+$/, '');
    thumb = await makeThumb(file);
    clear(preview, thumb ? h('img', { class: 'preview', src: thumb, alt: '' }) : null);
  });

  go.addEventListener('click', async () => {
    if (!file || !(await needLogin())) return;
    go.disabled = true;
    progress.hidden = false;
    status.textContent = 'Подтвердите публикацию в окне Void Connect…';
    try {
      const up = await Void.files.upload(file, {
        onProgress: (p) => { progress.value = p; status.textContent = 'Загрузка: ' + Math.round(p * 100) + '%'; },
      });
      status.textContent = 'Сохраняю…';
      const key = Void.newKey();
      await Void.records.put('videos', key, {
        title: title.value.trim().slice(0, 120) || up.name,
        description: desc.value.trim().slice(0, 3000),
        fileId: up.fileId,
        size: up.size,
        type: up.type,
        thumb,
      });
      location.hash = '#/watch/' + state.me.id + '/' + encodeURIComponent(key);
    } catch (e) {
      status.textContent = e.code === 'denied' ? 'Публикация отменена.' : 'Ошибка: ' + e.message;
      status.className = 'error';
      go.disabled = false;
    }
  });

  clear(view, h('div', { class: 'panel' },
    h('h1', {}, 'Новое видео'),
    h('label', { class: 'drop' }, fileInput, dropLabel),
    preview, title, desc, progress, status,
    h('div', { class: 'row' }, h('span', { class: 'spacer' }), go),
    h('p', { class: 'faint' },
      'Видео станет доступно всем в сети и будет раздаваться с вашего компьютера, ' +
      'пока его не скачают другие.')));
}

// ── Маршруты ───────────────────────────────────────────────────────────────
function route() {
  for (const s of state.subs) s.close();
  state.subs = [];
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  for (const a of document.querySelectorAll('[data-nav]')) {
    a.classList.toggle('active', a.dataset.nav === (parts[0] || 'feed'));
  }
  const fail = (e) => clear(view, h('p', { class: 'error' }, 'Ошибка: ' + e.message));
  if (parts[0] === 'watch' && parts[1] && parts[2]) showWatch(parts[1], decodeURIComponent(parts[2])).catch(fail);
  else if (parts[0] === 'upload') showUpload();
  else showFeed().catch(fail);
}

window.addEventListener('hashchange', route);

(async () => {
  if (!window.Void) {
    clear(view, h('p', { class: 'error' }, 'Сайт работает только внутри Void Connect.'));
    return;
  }
  state.site = await Void.site().catch(() => null);
  if (state.site) {
    document.getElementById('site-owner').textContent = '· сайт ' + state.site.name + '.void';
  }
  await refreshAccount();
  route();
})();
