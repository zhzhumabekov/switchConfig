// История: версии конфигурации, журнал событий, где и когда было видно каждое устройство.
//   data/history/<id>/config/<время>.txt  — версии конфигурации
//   data/history/<id>/index.json          — список версий с числом изменённых строк
//   data/history/events.jsonl             — журнал событий (по строке JSON на событие)
//   data/history/devices.json             — MAC → где виден сейчас, когда появился, куда переезжал
const fs = require('fs');
const path = require('path');
const LineDiff = require('./diff');

const ROOT = path.join(__dirname, 'data', 'history');
const EVENTS = path.join(ROOT, 'events.jsonl');
const DEVICES = path.join(ROOT, 'devices.json');
const MAX_VERSIONS = 300;
const MAX_EVENTS = 20000;
const MAX_MOVES = 30;

fs.mkdirSync(ROOT, { recursive: true });

const swDir = id => path.join(ROOT, id);
const cfgDir = id => path.join(swDir(id), 'config');
const indexPath = id => path.join(swDir(id), 'index.json');
const tsFile = ts => ts.replace(/[:.]/g, '-') + '.txt';

function readJson(f, def) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return def; } }
function writeJson(f, data) { const tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(data)); fs.renameSync(tmp, f); }

/* ---------- версии конфигурации ---------- */
function listVersions(id) { return readJson(indexPath(id), []); }

function readVersion(id, ts) {
  const v = listVersions(id).find(x => x.ts === ts);
  if (!v) return null;
  try { return fs.readFileSync(path.join(cfgDir(id), v.file), 'utf8'); } catch { return null; }
}

// Сохраняет версию, если она отличается от последней. Возвращает {added, removed} или null.
function addConfigVersion(id, text, ts = new Date().toISOString()) {
  fs.mkdirSync(cfgDir(id), { recursive: true });
  const index = listVersions(id);
  const last = index[0];
  const prevText = last ? readVersion(id, last.ts) : null;
  if (prevText === text) return null;
  const st = prevText != null ? LineDiff.stats(LineDiff.diffLines(prevText.split('\n'), text.split('\n'))) : null;
  const file = tsFile(ts);
  fs.writeFileSync(path.join(cfgDir(id), file), text);
  index.unshift({ ts, file, lines: text.split('\n').length - 1, added: st ? st.added : null, removed: st ? st.removed : null });
  // Удаляем самые старые версии сверх лимита, кроме закреплённых резервных копий
  let excess = index.length - MAX_VERSIONS;
  for (let i = index.length - 1; i >= 0 && excess > 0; i--) {
    if (index[i].pinned) continue;
    fs.rm(path.join(cfgDir(id), index[i].file), { force: true }, () => {});
    index.splice(i, 1);
    excess--;
  }
  writeJson(indexPath(id), index);
  return st;
}

// Отметить версию как резервную копию (не удаляется автоматически)
function pinVersion(id, ts, note) {
  const index = listVersions(id);
  const v = index.find(x => x.ts === ts);
  if (!v) return null;
  // Уже закреплённая версия сохраняет свою отметку
  if (!v.pinned) {
    v.pinned = true;
    v.note = note || 'Резервная копия';
    v.pinnedAt = new Date().toISOString();
  }
  writeJson(indexPath(id), index);
  return v;
}

function unpinVersion(id, ts) {
  const index = listVersions(id);
  const v = index.find(x => x.ts === ts);
  if (!v) return null;
  delete v.pinned; delete v.note; delete v.pinnedAt;
  writeJson(indexPath(id), index);
  return v;
}

// Первая версия из уже имеющегося конфига (до появления истории)
function seedConfig(id, text, ts) {
  if (text && !listVersions(id).length) addConfigVersion(id, text, ts || new Date().toISOString());
}

function removeSwitch(id) { fs.rmSync(swDir(id), { recursive: true, force: true }); }

/* ---------- события ---------- */
function addEvent(e) {
  const ev = { ts: new Date().toISOString(), ...e };
  fs.appendFileSync(EVENTS, JSON.stringify(ev) + '\n');
  return ev;
}

function readEvents({ sw, limit = 200, before } = {}) {
  let lines;
  try { lines = fs.readFileSync(EVENTS, 'utf8').split('\n'); } catch { return []; }
  if (lines.length > MAX_EVENTS * 1.2) {
    // Обрезаем журнал, чтобы не рос бесконечно
    lines = lines.slice(-MAX_EVENTS);
    fs.writeFileSync(EVENTS, lines.filter(Boolean).join('\n') + '\n');
  }
  const out = [];
  for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
    if (!lines[i]) continue;
    let e;
    try { e = JSON.parse(lines[i]); } catch { continue; }
    if (sw && e.sw !== sw) continue;
    if (before && e.ts >= before) continue;
    out.push(e);
  }
  return out;
}

/* ---------- устройства и состояние портов ---------- */
function loadDevices() { return readJson(DEVICES, { baselined: {}, macs: {} }); }
function saveDevices(db) { writeJson(DEVICES, db); }

// Описания портов из конфигурации (для определения аплинков на сервере)
function portDescriptions(configText) {
  const out = {};
  const re = /^interface (\S+)\n((?: .*\n)*)/gm;
  let m;
  while ((m = re.exec(configText || ''))) {
    const d = m[2].match(/^ description (.+)$/m);
    if (d) out[m[1]] = d[1];
  }
  return out;
}
const isUplinkDesc = d => /uplink|link_to|link-to|downlink|trunk_to/i.test(d || '');

const short = n => String(n || '').replace(/^XGigabitEthernet/, 'XGE').replace(/^GigabitEthernet/, 'GE');

// Сравнивает новое состояние с предыдущим и записывает события. Возвращает список событий.
function onState(sw, prev, cur, configText, directory) {
  const events = [];
  const add = e => events.push(addEvent({ sw: sw.id, swName: sw.name, ...e }));
  const desc = portDescriptions(configText);
  const now = cur.at;

  // 1. Изменения состояния портов
  if (prev && prev.interfaces) {
    for (const [name, st] of Object.entries(cur.interfaces || {})) {
      const p = prev.interfaces[name];
      if (!p || !/Ethernet|Eth-Trunk/i.test(name)) continue;
      const up = isUplinkDesc(desc[name]);
      const label = `${short(name)}${desc[name] ? ` (${desc[name]})` : ''}`;
      if (st.status === 'lbdt' && p.status !== 'lbdt') add({ type: 'loop', sev: 'high', port: name, text: `Порт ${label} заблокирован: обнаружена петля` });
      if (st.status !== 'lbdt' && p.status === 'lbdt') add({ type: 'loop-cleared', sev: 'info', port: name, text: `Порт ${label} разблокирован после петли` });
      if (up && p.status === 'up' && st.status !== 'up') add({ type: 'uplink-down', sev: 'high', port: name, text: `Аплинк ${label} упал (${st.phy})` });
      if (up && p.status !== 'up' && st.status === 'up') add({ type: 'uplink-up', sev: 'info', port: name, text: `Аплинк ${label} снова работает` });
      const e0 = p.inErr + p.outErr, e1 = st.inErr + st.outErr;
      if (e1 > e0 && (e0 === 0 || e1 - e0 >= 100)) add({ type: 'errors', sev: 'med', port: name, text: `Ошибки на порту ${label}: +${e1 - e0} (всего ${e1})` });
    }
  }

  // 1б. Оборудование: новые и устранённые проблемы (температура, питание, SFP…)
  if (prev && prev.hw && cur.hw) {
    const before = new Map((prev.hw.problems || []).map(p => [p.key, p]));
    const now = new Map((cur.hw.problems || []).map(p => [p.key, p]));
    for (const [k, p] of now) if (!before.has(k)) add({ type: 'hw', sev: p.sev, port: p.port, text: p.text });
    for (const [k, p] of before) if (!now.has(k)) add({ type: 'hw-ok', sev: 'info', port: p.port, text: `Устранено: ${p.text}` });
  }

  // 2. Устройства: где видно каждый MAC на конечных портах
  const db = loadDevices();
  const firstRun = !db.baselined[sw.id];
  const byPort = {};
  for (const m of cur.mac || []) (byPort[m.port] ||= []).push(m);
  const known = mac => directory && (directory.dhcp || []).some(l => l.mac === mac);
  const nameOf = mac => { const l = directory && (directory.dhcp || []).find(x => x.mac === mac); return l && l.host ? l.host.split('.')[0] : ''; };

  for (const [port, list] of Object.entries(byPort)) {
    // Аплинк или порт с множеством MAC — транзит, устройства за ним не записываем
    if (isUplinkDesc(desc[port]) || list.length > 5) continue;
    for (const m of list) {
      const d = db.macs[m.mac];
      const who = nameOf(m.mac);
      const whoText = who ? `${who} (${m.mac})` : m.mac;
      if (!d) {
        db.macs[m.mac] = { firstSeen: now, lastSeen: now, sw: sw.id, swName: sw.name, port, vlan: m.vlan, since: now, moves: [] };
        if (!firstRun) {
          const unknown = directory && !known(m.mac);
          add({ type: unknown ? 'unknown-device' : 'new-device', sev: unknown ? 'med' : 'info', port, mac: m.mac,
            text: unknown ? `Новое неизвестное устройство ${m.mac} на ${short(port)}, VLAN ${m.vlan ?? '—'}` : `Новое устройство ${whoText} на ${short(port)}` });
        }
        continue;
      }
      if (d.sw !== sw.id || d.port !== port) {
        const fromSw = d.sw === sw.id ? '' : `${d.swName || d.sw} `;
        d.moves.unshift({ sw: d.sw, swName: d.swName, port: d.port, from: d.since || d.firstSeen, to: now });
        d.moves.length = Math.min(d.moves.length, MAX_MOVES);
        add({ type: 'moved', sev: 'info', port, mac: m.mac, text: `${whoText} переехал: ${fromSw}${short(d.port)} → ${short(port)}` });
        d.sw = sw.id; d.port = port; d.since = now;
      }
      d.swName = sw.name;
      d.lastSeen = now;
      d.vlan = m.vlan;
    }
  }
  db.baselined[sw.id] = true;
  saveDevices(db);
  return events;
}

module.exports = {
  listVersions, readVersion, addConfigVersion, seedConfig, removeSwitch, pinVersion, unpinVersion,
  addEvent, readEvents, loadDevices, onState,
};
