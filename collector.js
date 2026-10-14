// Сбор данных с коммутаторов: конфигурация и/или состояние портов за одно SSH-подключение,
// запись истории и событий. Используется кнопками «Обновить» и расписанием.
const store = require('./store');
const live = require('./live-state');
const history = require('./history');
const directory = require('./directory');
const cme = require('./cme');
const wlan = require('./wlan');
const ciscoState = require('./cisco-state');
const { runCommands, extract, humanError } = require('./fetch-config');

const busy = new Set(); // id коммутаторов, с которых сейчас забираются данные

// Ошибка с понятным текстом, который показывается как есть
class UserError extends Error { constructor(status, msg) { super(msg); this.status = status; this.user = true; } }

async function passwordFor(sw, given) {
  if (given) return given;
  const p = await store.decrypt(sw && sw.secret);
  if (!p) throw new UserError(400, 'Пароль не сохранён — укажите его в настройках');
  return p;
}

function update(id, fn) {
  const list = store.load();
  const cur = list.find(s => s.id === id);
  if (cur) { fn(cur); store.save(list); }
  return cur;
}

// Cisco CME: список телефонов (MAC, номера, подписи, регистрация)
async function collectCme(sw) {
  const password = await passwordFor(sw);
  const enablePassword = sw.enableSecret ? await store.decrypt(sw.enableSecret) : null;
  const keys = Object.keys(cme.COMMANDS);
  const outputs = await runCommands({ host: sw.host, port: sw.port, user: sw.user, vendor: 'cisco', enablePassword, timeout: 90 },
    password, keys.map(k => cme.COMMANDS[k]));
  const raw = Object.fromEntries(keys.map((k, i) => [k, cme.redact(outputs[i])]));
  const state = cme.parseAll(raw);
  if (!state.phones.length && Object.keys(state.errors).length === keys.length) {
    throw new Error('Команды CME не выполнились: ' + Object.values(state.errors)[0] + (enablePassword ? '' : ' (возможно, нужен пароль enable)'));
  }
  // События: телефон перестал или снова начал регистрироваться
  const prev = store.readState(sw.id);
  if (prev && prev.phones) {
    const before = new Map(prev.phones.map(p => [p.mac, p]));
    const label = p => [p.numbers.join(', '), p.names[0]].filter(Boolean).join(' · ') || p.mac;
    for (const p of state.phones) {
      const b = before.get(p.mac);
      if (!b) continue;
      if (b.status === 'registered' && p.status !== 'registered') history.addEvent({ sw: sw.id, swName: sw.name, type: 'phone-unreg', sev: 'med', mac: p.mac, text: `Телефон ${label(p)} перестал регистрироваться (${p.status})` });
      if (b.status !== 'registered' && p.status === 'registered') history.addEvent({ sw: sw.id, swName: sw.name, type: 'phone-reg', sev: 'info', mac: p.mac, text: `Телефон ${label(p)} снова зарегистрирован` });
    }
  }
  store.writeState(sw.id, state, raw);
  return { ok: true, phones: state.phones.length, registered: state.phones.filter(p => p.status === 'registered').length, stateErrors: state.errors };
}

const upText = sec => { const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60); return d ? `${d} дн ${h} ч` : h ? `${h} ч ${m} мин` : `${m} мин`; };

// Контроллер Wi‑Fi: точка доступа пропала или вернулась
function apEvents(sw, prev, cur) {
  if (!prev || !prev.wlan || !cur.wlan) return;
  const before = new Map(prev.wlan.aps.map(a => [a.mac, a]));
  const ok = a => a.state === 'nor' || a.state === 'normal';
  for (const a of cur.wlan.aps) {
    const b = before.get(a.mac);
    if (!b) { history.addEvent({ sw: sw.id, swName: sw.name, type: 'ap-new', sev: 'info', mac: a.mac, text: `Новая точка доступа ${a.name} (${a.mac}${a.ip ? ', ' + a.ip : ''})` }); continue; }
    if (ok(b) && !ok(a)) history.addEvent({ sw: sw.id, swName: sw.name, type: 'ap-down', sev: 'high', mac: a.mac, text: `Точка доступа ${a.name}: ${a.stateText}` });
    if (!ok(b) && ok(a)) history.addEvent({ sw: sw.id, swName: sw.name, type: 'ap-up', sev: 'info', mac: a.mac, text: `Точка доступа ${a.name} снова работает` });
    else if (ok(b) && ok(a) && a.uptimeSec != null && b.uptimeSec != null && a.uptimeSec < b.uptimeSec) history.addEvent({ sw: sw.id, swName: sw.name, type: 'ap-reboot', sev: 'med', mac: a.mac, text: `Точка доступа ${a.name} перезагрузилась (работает ${upText(a.uptimeSec)})` });
  }
  const now = new Set(cur.wlan.aps.map(a => a.mac));
  for (const b of prev.wlan.aps) if (!now.has(b.mac)) history.addEvent({ sw: sw.id, swName: sw.name, type: 'ap-gone', sev: 'med', mac: b.mac, text: `Точка доступа ${b.name} исчезла из списка контроллера` });
}

// opts.config — забирать ли конфигурацию (иначе только состояние портов)
async function collect(id, { config = true, reason = 'manual' } = {}) {
  if (busy.has(id)) throw new UserError(409, 'Данные с этого коммутатора уже забираются');
  const sw = store.load().find(s => s.id === id);
  if (!sw) throw new UserError(404, 'Коммутатор не найден');
  if (sw.type === 'cisco-cme') {
    busy.add(id);
    const attemptAt = new Date().toISOString();
    try {
      const r = await collectCme(sw);
      if (sw.lastError) history.addEvent({ sw: id, swName: sw.name, type: 'recovered', sev: 'info', text: 'Роутер снова отвечает' });
      update(id, cur => { cur.stateAt = new Date().toISOString(); cur.lastFetch = cur.stateAt; cur.lastAttempt = attemptAt; cur.lastError = null; });
      return r;
    } catch (err) {
      const msg = err.user ? err.message : humanError(err);
      if (!sw.lastError) history.addEvent({ sw: id, swName: sw.name, type: 'unreachable', sev: 'high', text: `Не удалось подключиться: ${msg}` });
      update(id, cur => { cur.lastError = { at: new Date().toISOString(), message: msg }; cur.lastAttempt = attemptAt; });
      return { ok: false, error: msg };
    } finally {
      busy.delete(id);
    }
  }
  busy.add(id);
  const attemptAt = new Date().toISOString();
  try {
    const password = await passwordFor(sw);
    // Набор команд зависит от типа устройства
    const isCisco = sw.type === 'cisco-ios', isAc = sw.type === 'huawei-ac';
    const STATE_CMDS = isCisco ? ciscoState.COMMANDS : isAc ? { ...live.COMMANDS, ...wlan.COMMANDS } : live.COMMANDS;
    const stateKeys = Object.keys(STATE_CMDS);
    const configCmd = isCisco ? 'show running-config' : 'display current-configuration';
    const commands = [...(config ? [configCmd] : []), ...stateKeys.map(k => STATE_CMDS[k])];
    const enablePassword = isCisco && sw.enableSecret ? await store.decrypt(sw.enableSecret) : null;
    const outputs = await runCommands({ host: sw.host, port: sw.port, user: sw.user, vendor: isCisco ? 'cisco' : 'huawei', enablePassword, timeout: isAc || isCisco ? 120 : 60 }, password, commands);

    let text = store.readConfig(id);
    let changed = false, diff = null;
    if (config) {
      text = isCisco ? ciscoState.extractConfig(outputs.shift()) : extract(outputs.shift());
      if (!(isCisco ? /^hostname /m : /^ ?sysname /m).test(text)) throw new Error('Получен неполный вывод — конфигурация не сохранена');
      // Первая версия истории — из того, что уже было сохранено раньше
      history.seedConfig(id, store.readConfig(id), sw.lastFetch);
      changed = store.writeConfig(id, text);
      diff = history.addConfigVersion(id, text);
      if (diff && (diff.added || diff.removed)) {
        history.addEvent({ sw: id, swName: sw.name, type: 'config-changed', sev: 'med', text: `Конфигурация изменилась: +${diff.added} / −${diff.removed} строк` });
      }
    }

    const raw = Object.fromEntries(stateKeys.map((k, i) => [k, outputs[i]]));
    const state = isCisco ? ciscoState.parseAll(raw) : live.parseAll(raw);
    if (isCisco) state.vendor = 'cisco';
    if (isAc) {
      state.wlan = wlan.parseAll(raw);
      Object.assign(state.errors, state.wlan.errors);
    }
    const prevState = store.readState(id);
    if (isAc) apEvents(sw, prevState, state);
    store.writeState(id, state, raw);
    history.onState(sw, prevState, state, text, directory.readResult());

    if (sw.lastError) history.addEvent({ sw: id, swName: sw.name, type: 'recovered', sev: 'info', text: 'Коммутатор снова отвечает' });
    update(id, cur => {
      const now = new Date().toISOString();
      if (config) {
        cur.lastFetch = now;
        cur.sysname = (text.match(/^ ?(?:sysname|hostname)\s+(\S+)/m) || [])[1] || cur.sysname;
        if (changed) cur.lastChange = now;
      }
      cur.stateAt = state.at;
      cur.lastAttempt = attemptAt;
      cur.lastError = null;
    });
    return { ok: true, changed, config, lines: text ? text.split('\n').length - 1 : 0, stateErrors: state.errors };
  } catch (err) {
    const msg = err.user ? err.message : humanError(err);
    if (!sw.lastError) history.addEvent({ sw: id, swName: sw.name, type: 'unreachable', sev: 'high', text: `Не удалось подключиться: ${msg}` });
    update(id, cur => { cur.lastError = { at: new Date().toISOString(), message: msg }; cur.lastAttempt = attemptAt; });
    return { ok: false, error: msg };
  } finally {
    busy.delete(id);
  }
}

// Несколько коммутаторов, не больше 4 подключений одновременно
async function collectMany(ids, opts) {
  const results = {};
  const queue = [...ids];
  await Promise.all(Array.from({ length: Math.min(4, queue.length) }, async () => {
    while (queue.length) {
      const i = queue.shift();
      const o = typeof opts === 'function' ? opts(i) : opts;
      results[i] = await collect(i, o).catch(e => ({ ok: false, error: e.message }));
    }
  }));
  return results;
}

module.exports = { collect, collectMany, passwordFor, busy, UserError };
