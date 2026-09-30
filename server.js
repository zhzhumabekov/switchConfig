// Локальный сервер для просмотра конфигураций коммутаторов.
//   node server.js           — http://127.0.0.1:8080
//   set PORT=9000 && node server.js
//
// Слушает только 127.0.0.1: с других компьютеров он недоступен.
const http = require('http');
const fs = require('fs');
const path = require('path');
const store = require('./store');
const { runCommands, fetchConfig, extract, humanError } = require('./fetch-config');
const live = require('./live-state');
const { redact } = require('./update-config');

const PORT = +process.env.PORT || 8080;
const HOST = '127.0.0.1';

// Отдаём только эти файлы — конфиги с секретами и data/ наружу не попадают
const STATIC = {
  '/': 'index.html', '/index.html': 'index.html', '/settings.html': 'settings.html',
  '/style.css': 'style.css', '/app.js': 'app.js', '/settings.js': 'settings.js', '/config.js': 'config.js',
};
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

const busy = new Set(); // id коммутаторов, с которых сейчас забираются данные

/* ---------- вспомогательное ---------- */
function send(res, status, data) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': typeof data === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 1e5) { reject(new HttpError(413, 'Слишком большой запрос')); req.destroy(); } });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new HttpError(400, 'Некорректный JSON')); } });
  });
}

// Открытый вид записи: без пароля
function publicView(s) {
  return {
    id: s.id, name: s.name, host: s.host, port: s.port, user: s.user,
    hasPassword: !!s.secret, sysname: s.sysname || '', lastFetch: s.lastFetch || null,
    lastError: s.lastError || null, lastChange: s.lastChange || null, source: s.source || '',
    hasConfig: !!store.readConfig(s.id), stateAt: s.stateAt || null, busy: busy.has(s.id),
  };
}

function validate(b, partial) {
  const out = {};
  if (!partial || b.name !== undefined) {
    out.name = String(b.name || '').trim();
    if (!out.name) throw new HttpError(400, 'Укажите название');
  }
  if (!partial || b.host !== undefined) {
    out.host = String(b.host || '').trim();
    if (!/^[A-Za-z0-9.\-:]{1,253}$/.test(out.host)) throw new HttpError(400, 'Некорректный IP-адрес или имя');
  }
  if (!partial || b.port !== undefined) {
    out.port = +(b.port || 22);
    if (!Number.isInteger(out.port) || out.port < 1 || out.port > 65535) throw new HttpError(400, 'Порт SSH должен быть от 1 до 65535');
  }
  if (!partial || b.user !== undefined) {
    out.user = String(b.user || '').trim();
    if (!out.user) throw new HttpError(400, 'Укажите логин');
  }
  return out;
}

async function passwordFor(sw, given) {
  if (given) return given;
  const p = await store.decrypt(sw && sw.secret);
  if (!p) throw new HttpError(400, 'Пароль не сохранён — укажите его в настройках');
  return p;
}

async function doFetch(id) {
  if (busy.has(id)) throw new HttpError(409, 'Конфигурация уже забирается');
  const list = store.load();
  const sw = list.find(s => s.id === id);
  if (!sw) throw new HttpError(404, 'Коммутатор не найден');
  busy.add(id);
  try {
    const password = await passwordFor(sw);
    // Конфигурация и состояние портов — за одно подключение
    const stateKeys = Object.keys(live.COMMANDS);
    const outputs = await runCommands({ host: sw.host, port: sw.port, user: sw.user },
      password, ['display current-configuration', ...stateKeys.map(k => live.COMMANDS[k])]);
    const text = extract(outputs[0]);
    if (!/^sysname /m.test(text)) throw new Error('Получен неполный вывод — конфигурация не сохранена');
    const changed = store.writeConfig(id, text);
    const raw = Object.fromEntries(stateKeys.map((k, i) => [k, outputs[i + 1]]));
    const state = live.parseAll(raw);
    store.writeState(id, state, raw);
    const fresh = store.load();
    const cur = fresh.find(s => s.id === id);
    if (cur) {
      cur.lastFetch = new Date().toISOString();
      cur.lastError = null;
      cur.sysname = (text.match(/^sysname\s+(\S+)/m) || [])[1] || cur.sysname;
      if (changed) cur.lastChange = cur.lastFetch;
      cur.stateAt = state.at;
      store.save(fresh);
    }
    return { ok: true, changed, lines: text.split('\n').length - 1, stateErrors: state.errors };
  } catch (err) {
    const msg = err instanceof HttpError ? err.message : humanError(err);
    const fresh = store.load();
    const cur = fresh.find(s => s.id === id);
    if (cur) { cur.lastError = { at: new Date().toISOString(), message: msg }; store.save(fresh); }
    return { ok: false, error: msg };
  } finally {
    busy.delete(id);
  }
}

/* ---------- API ---------- */
async function api(req, res, parts) {
  const method = req.method;
  const [, res1, id, action] = parts; // ['api', 'switches', id, action]

  if (res1 === 'switches' && !id && method === 'GET') return send(res, 200, store.load().map(publicView));

  if (res1 === 'switches' && !id && method === 'POST') {
    const b = await readBody(req);
    const v = validate(b);
    const list = store.load();
    const sw = { id: store.makeId(v.name, list), ...v, secret: b.password ? await store.encrypt(String(b.password)) : null, createdAt: new Date().toISOString() };
    list.push(sw);
    store.save(list);
    return send(res, 201, publicView(sw));
  }

  if (res1 === 'switches' && id && !action) {
    const list = store.load();
    const sw = list.find(s => s.id === id);
    if (!sw) throw new HttpError(404, 'Коммутатор не найден');
    if (method === 'PUT') {
      const b = await readBody(req);
      const v = validate(b, true);
      Object.assign(sw, v);
      if (b.password) sw.secret = await store.encrypt(String(b.password));
      if (b.clearPassword) sw.secret = null;
      store.save(list);
      return send(res, 200, publicView(sw));
    }
    if (method === 'DELETE') {
      store.save(list.filter(s => s.id !== id));
      store.removeConfig(id);
      return send(res, 200, { ok: true });
    }
  }

  if (res1 === 'switches' && id && action === 'config' && method === 'GET') {
    const text = store.readConfig(id);
    if (text == null) throw new HttpError(404, 'Конфигурация ещё не загружена');
    return send(res, 200, redact(text));
  }

  if (res1 === 'switches' && id && action === 'state' && method === 'GET') {
    const st = store.readState(id);
    if (!st) throw new HttpError(404, 'Состояние ещё не загружено');
    return send(res, 200, st);
  }

  if (res1 === 'switches' && id && action === 'fetch' && method === 'POST') {
    return send(res, 200, await doFetch(id));
  }

  if (res1 === 'fetch-all' && method === 'POST') {
    const ids = store.load().filter(s => s.secret).map(s => s.id);
    const results = {};
    // Не больше 4 подключений одновременно
    const queue = [...ids];
    await Promise.all(Array.from({ length: Math.min(4, queue.length) }, async () => {
      while (queue.length) { const i = queue.shift(); results[i] = await doFetch(i).catch(e => ({ ok: false, error: e.message })); }
    }));
    return send(res, 200, results);
  }

  if (res1 === 'test' && method === 'POST') {
    const b = await readBody(req);
    const list = store.load();
    const sw = b.id ? list.find(s => s.id === b.id) : null;
    const v = validate({ name: 'test', host: b.host ?? sw?.host, port: b.port ?? sw?.port, user: b.user ?? sw?.user });
    try {
      const password = await passwordFor(sw, b.password);
      const prompt = await fetchConfig({ host: v.host, port: v.port, user: v.user, testOnly: true, timeout: 25 }, password);
      return send(res, 200, { ok: true, prompt });
    } catch (err) {
      return send(res, 200, { ok: false, error: err instanceof HttpError ? err.message : humanError(err) });
    }
  }

  throw new HttpError(404, 'Неизвестный запрос');
}

/* ---------- сервер ---------- */
const allowedHosts = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);

const server = http.createServer(async (req, res) => {
  try {
    // Защита от обращений со сторонних сайтов (DNS rebinding, CSRF)
    if (!allowedHosts.has(req.headers.host)) throw new HttpError(403, 'Запрещено');
    const origin = req.headers.origin;
    if (origin && !allowedHosts.has(origin.replace(/^https?:\/\//, ''))) throw new HttpError(403, 'Запрещено');

    const url = new URL(req.url, `http://${req.headers.host}`);
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);

    if (parts[0] === 'api') {
      if (req.method !== 'GET' && !/^application\/json/.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Ожидается JSON');
      return await api(req, res, parts);
    }

    const file = STATIC[url.pathname];
    if (!file || req.method !== 'GET') throw new HttpError(404, 'Не найдено');
    const full = path.join(__dirname, file);
    if (!fs.existsSync(full)) throw new HttpError(404, 'Не найдено');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)], 'Cache-Control': 'no-cache' });
    fs.createReadStream(full).pipe(res);
  } catch (err) {
    if (!(err instanceof HttpError)) console.error(err);
    send(res, err.status || 500, { error: err.message });
  }
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') console.error(`Порт ${PORT} занят. Возможно, сервер уже запущен — откройте http://${HOST}:${PORT}/`);
  else console.error(err);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`Сервер запущен: http://${HOST}:${PORT}/`);
  console.log(`Настройки коммутаторов: http://${HOST}:${PORT}/settings.html`);
  console.log('Ctrl+C — остановить.');
});
