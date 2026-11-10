// Изменение порта коммутатора Huawei из приложения:
//   applyPortEdit     — PVID, VLAN транка, телефон (LLDP-MED voice VLAN);
//   applyPortTemplate — привести порт к шаблону эталона (рабочее место, принтер, точка доступа).
//
// Команды сервер собирает сам (Fixes) — со страницы приходит только, что поменять.
// Перед изменением настройки порта читаются с коммутатора и сверяются с тем, что видел
// пользователь: если порт за это время поменяли, ничего не выполняется.
const fs = require('fs');
const path = require('path');
const store = require('./store');
const history = require('./history');
const collector = require('./collector');
const Fixes = require('./fixes');
const Standard = require('./standard');
const { runCommands, humanError } = require('./fetch-config');
const { redact } = require('./update-config');
const { DATA } = require('./paths');

class UserError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; this.user = true; } }

const STANDARD = path.join(DATA, 'standard.json');
const PORT_RE = /^(XGigabitEthernet|GigabitEthernet|40GE|100GE|Eth-Trunk)[\d/]{1,16}$/;
// Магистральные порты (как в classify на странице) — шаблон рабочего места к ним не применяется
const LINK_DESC_RE = /uplink|link_to|downlink|link-to/i;
const errorsIn = text => (String(text || '').match(/^\s*Error\s*:.+$/gim) || []).map(s => s.trim());

// Строки interface <name> из конфигурации (без отступа), null — такого интерфейса нет
function ifaceLines(text, name) {
  const lines = String(text || '').replace(/\r/g, '').split('\n');
  const i = lines.findIndex(l => l.trim() === `interface ${name}`);
  if (i < 0) return null;
  const out = [];
  for (let j = i + 1; j < lines.length && /^ /.test(lines[j]); j++) out.push(lines[j].trim());
  return out;
}

function vlanList(v) {
  if (!Array.isArray(v)) return [];
  return v.slice(0, 4094).map(Number);
}

function parseChange(b) {
  const change = { add: vlanList(b.add), remove: vlanList(b.remove) };
  if (b.pvid !== undefined && b.pvid !== null) change.pvid = Number(b.pvid);
  if (b.voice === false) change.voice = false;
  else if (b.voice !== undefined && b.voice !== null) change.voice = Number(b.voice);
  const desc = parseDesc(b.desc);
  if (desc !== undefined) change.desc = desc;
  return change;
}

// Описание порта: одна строка, без «?» — в CLI он сразу вызывает подсказку вместо ввода
function parseDesc(v) {
  if (v === undefined || v === null) return undefined;
  const desc = String(v).trim().replace(/\s+/g, ' ');
  if (desc.length > 200) throw new UserError('Описание длиннее 200 символов');
  if (/[\x00-\x1f\x7f?]/.test(desc)) throw new UserError('В описании недопустимые символы (например, «?»)');
  return desc;
}

function readStandard() {
  try { return JSON.parse(fs.readFileSync(STANDARD, 'utf8')); } catch { return null; }
}

// Порт в том виде, в каком его понимает Fixes.portChange
function portFromLines(name, lines) {
  const d = lines.find(l => /^description /.test(l));
  return { name, lines, desc: d ? d.replace(/^description /, '') : '', shutdown: lines.includes('shutdown') };
}

/* Общий сценарий изменения порта.
   buildCmds(now) — команды режима interface по текущим строкам порта (ошибка — UserError).
   text — подписи для журнала событий: { done, failed }. */
async function changePort(id, b, buildCmds, text) {
  const sw = store.load().find(s => s.id === id);
  if (!sw) throw new UserError('Коммутатор не найден', 404);
  if (sw.type && sw.type !== 'huawei') throw new UserError('Изменение портов доступно только для коммутаторов Huawei');
  if (!sw.secret) throw new UserError('Пароль не сохранён — укажите его в настройках');
  const name = String(b.port || '');
  if (!PORT_RE.test(name)) throw new UserError('Некорректное имя порта');
  if (!Array.isArray(b.seen)) throw new UserError('Не переданы текущие настройки порта');
  if (collector.busy.has(id)) throw new UserError('С коммутатора сейчас забираются данные — повторите через минуту', 409);

  const log = [];
  const step = (ok, msg) => log.push({ ok, msg });
  const opt = { host: sw.host, port: sw.port, user: sw.user };
  const password = await store.decrypt(sw.secret);
  let applied = false, cmds = [];

  collector.busy.add(id);
  try {
    // 1. Настройки порта прямо сейчас — сверяем с тем, что видел пользователь
    const [cur] = await runCommands({ ...opt, timeout: 60 }, password, [`display current-configuration interface ${name}`]);
    const now = ifaceLines(redact(cur), name);
    if (!now) throw new UserError(`Порт ${name} не найден на коммутаторе`);
    const seen = b.seen.map(l => String(l).trim());
    if (now.join('\n') !== seen.join('\n')) {
      throw new UserError('Настройки порта на коммутаторе отличаются от показанных — их изменили. Данные обновлены, проверьте порт и повторите', 409);
    }
    step(true, 'Настройки порта на коммутаторе совпадают с показанными');

    // 2. Команды
    try { cmds = buildCmds(now); } catch (e) { throw e.user ? e : new UserError(e.message); }
    if (!cmds.length) throw new UserError('Порт уже настроен так — менять нечего');
    const out = await runCommands({ ...opt, configMode: true, timeout: 60 }, password, ['system-view', `interface ${name}`, ...cmds, 'return']);
    applied = true;
    const errs = [];
    cmds.forEach((c, i) => {
      const e = errorsIn(out[i + 2]);
      step(!e.length, e.length ? `${c} — ${e.join('; ')}` : c);
      errs.push(...e);
    });
    const enterErrs = [...errorsIn(out[0]), ...errorsIn(out[1])]; // system-view, interface …
    if (enterErrs.length) throw new UserError(`Не удалось войти в настройки порта: ${enterErrs.join('; ')}`);
    if (errs.length) throw new UserError('Коммутатор не принял часть команд — конфигурация не сохранена (save не выполнялся)');

    // 3. Сохранение
    let saved = false;
    if (b.save) {
      const [s] = await runCommands({ ...opt, answerYes: true, timeout: 120 }, password, ['save']);
      const e = errorsIn(s);
      if (e.length) step(false, `save — ${e.join('; ')}`);
      else { saved = true; step(true, 'Конфигурация сохранена (save)'); }
    }

    history.addEvent({ sw: id, swName: sw.name, port: name, type: 'port-edit', sev: 'info',
      text: `${text.done}: ${cmds.join('; ')}${saved ? '' : ' (не сохранено)'}` });
    return { ok: true, log, commands: cmds, saved };
  } catch (e) {
    const msg = e.user ? e.message : humanError(e);
    step(false, msg);
    if (applied) history.addEvent({ sw: id, swName: sw.name, port: name, type: 'port-edit', sev: 'med', text: `${text.failed}: ${msg}` });
    return { ok: false, error: msg, log, applied };
  } finally {
    collector.busy.delete(id);
    // Забираем свежую конфигурацию, чтобы страница показала то, что на коммутаторе на самом деле
    await collector.collect(id, { config: true, reason: 'port-edit' }).catch(() => {});
  }
}

function applyPortEdit(id, b) {
  const change = parseChange(b);
  const name = String(b.port || '');
  return changePort(id, b, now => Fixes.portEdit(now, change),
    { done: `Изменён порт ${name}`, failed: `Изменение порта ${name} с ошибкой` });
}

// b.tpl — id шаблона эталона (workstation, printer, ap) или пусто — только описание; b.desc — новое описание
function applyPortTemplate(id, b) {
  const tplId = b.tpl ? String(b.tpl) : '';
  const desc = parseDesc(b.desc);
  let tpl = null;
  if (tplId) {
    if (!Standard.TPL_LABEL[tplId]) throw new UserError('Неизвестный шаблон');
    const std = readStandard();
    tpl = std && std.ports && std.ports[tplId];
    if (!tpl || !tpl.enabled || !Array.isArray(tpl.lines) || !tpl.lines.length) throw new UserError(`Шаблон «${Standard.TPL_LABEL[tplId]}» не задан в эталоне`);
  } else if (desc === undefined) {
    throw new UserError('Не выбран шаблон');
  }
  const name = String(b.port || '');
  const label = tpl ? `шаблону «${Standard.TPL_LABEL[tplId]}»` : 'новому описанию';

  return changePort(id, b, now => {
    const p = portFromLines(name, now);
    if (tpl) {
      if (/^Eth-Trunk/.test(name) || now.some(l => /^eth-trunk \d+/.test(l))) throw new UserError('Порт агрегирован (Eth-Trunk) — шаблон к нему не применяется');
      if (LINK_DESC_RE.test(p.desc)) throw new UserError(`Порт подписан как магистральный («${p.desc}») — шаблон к нему не применяется`);
    }
    return tpl ? Fixes.templateChange(p, tpl.lines, desc) : Fixes.portChange(p, { special: 'desc' }, desc);
  }, { done: `Порт ${name} приведён к ${label}`, failed: `Порт ${name}: не удалось привести к ${label}` });
}

module.exports = { applyPortEdit, applyPortTemplate, ifaceLines };
