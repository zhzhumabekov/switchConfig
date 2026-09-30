// Сбор по расписанию, пока запущен сервер. Настройки — data/schedule.json.
const fs = require('fs');
const path = require('path');
const store = require('./store');
const collector = require('./collector');
const directory = require('./directory');

const FILE = path.join(__dirname, 'data', 'schedule.json');
const DEFAULTS = { enabled: true, stateMinutes: 30, configHours: 24, directoryMinutes: 60 };
const LIMITS = { stateMinutes: [5, 1440], configHours: [1, 168], directoryMinutes: [10, 1440] };

let running = false;
let lastTick = null;
let lastRun = null; // { at, results }
let timer = null;

function load() {
  try { return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; } catch { return { ...DEFAULTS }; }
}

function save(input) {
  const s = { ...load() };
  if (input.enabled !== undefined) s.enabled = !!input.enabled;
  for (const [k, [min, max]] of Object.entries(LIMITS)) {
    if (input[k] === undefined) continue;
    const v = Math.round(+input[k]);
    if (!Number.isFinite(v) || v < min || v > max) throw Object.assign(new Error(`Значение «${k}» должно быть от ${min} до ${max}`), { status: 400, user: true });
    s[k] = v;
  }
  fs.writeFileSync(FILE, JSON.stringify(s, null, 2));
  return s;
}

const age = iso => (iso ? Date.now() - new Date(iso).getTime() : Infinity);

// Что пора собрать: { id: { config: bool } }
function due(s = load()) {
  const out = {};
  for (const sw of store.load()) {
    if (!sw.secret || collector.busy.has(sw.id)) continue;
    const needConfig = age(sw.lastFetch) >= s.configHours * 3600e3;
    // После ошибки ждём тот же интервал, а не пробуем каждую минуту
    const needState = age(sw.lastAttempt || sw.stateAt) >= s.stateMinutes * 60e3;
    if (needState || (needConfig && age(sw.lastAttempt) >= s.stateMinutes * 60e3)) out[sw.id] = { config: needConfig, reason: 'schedule' };
  }
  return out;
}

async function tick() {
  lastTick = new Date().toISOString();
  const s = load();
  if (!s.enabled || running) return;
  const plan = due(s);
  const ids = Object.keys(plan);
  if (!ids.length) return;
  running = true;
  try {
    const results = await collector.collectMany(ids, id => plan[id]);
    lastRun = { at: new Date().toISOString(), results };
    const bad = Object.entries(results).filter(([, r]) => !r.ok);
    console.log(`[${new Date().toLocaleTimeString('ru-RU')}] По расписанию: ${ids.length - bad.length} из ${ids.length} успешно` +
      (bad.length ? ` (ошибки: ${bad.map(([k, r]) => `${k}: ${r.error}`).join('; ')})` : ''));
    await directory.refreshIfStale(s.directoryMinutes * 60e3);
  } catch (e) {
    console.error('Ошибка расписания:', e.message);
  } finally {
    running = false;
  }
}

function start() {
  if (timer) return;
  setTimeout(tick, 15000); // первая проверка вскоре после запуска
  timer = setInterval(tick, 60000);
}

function status() {
  const s = load();
  // Когда ближайший сбор
  let next = null;
  if (s.enabled) {
    for (const sw of store.load()) {
      if (!sw.secret) continue;
      const base = sw.lastAttempt || sw.stateAt;
      const t = base ? new Date(base).getTime() + s.stateMinutes * 60e3 : Date.now();
      if (next == null || t < next) next = t;
    }
  }
  return { ...s, running, lastTick, lastRun, next: next ? new Date(Math.max(next, Date.now())).toISOString() : null };
}

module.exports = { start, load, save, status, tick };
