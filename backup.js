// Резервные копии и восстановление конфигурации коммутатора Huawei.
//
// Резервная копия — снимок display current-configuration, закреплённый в истории.
// Восстановление НЕ меняет работающую конфигурацию: выбранная версия загружается на flash
// отдельным файлом и назначается конфигурацией для следующей загрузки
// (startup saved-configuration). Перезагрузку выполняет администратор сам.
const store = require('./store');
const history = require('./history');
const collector = require('./collector');
const { runCommands, uploadFile, humanError } = require('./fetch-config');

class UserError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; this.user = true; } }

function update(id, fn) {
  const list = store.load();
  const cur = list.find(s => s.id === id);
  if (cur) { fn(cur); store.save(list); }
  return cur;
}

function getSwitch(id) {
  const sw = store.load().find(s => s.id === id);
  if (!sw) throw new UserError('Коммутатор не найден', 404);
  if (sw.type === 'cisco-cme') throw new UserError('Резервные копии и восстановление доступны только для коммутаторов Huawei');
  return sw;
}

/* ---------- резервная копия ---------- */
async function backupNow(id, note) {
  const sw = getSwitch(id);
  const r = await collector.collect(id, { config: true, reason: 'backup' });
  if (!r.ok) throw new UserError(`Не удалось получить конфигурацию: ${r.error}`);
  const v = history.listVersions(id)[0];
  if (!v) throw new UserError('Конфигурация не сохранилась');
  history.pinVersion(id, v.ts, note || 'Резервная копия');
  history.addEvent({ sw: id, swName: sw.name, type: 'backup', sev: 'info', text: `Сделана резервная копия конфигурации (${v.lines} строк)` });
  return { ok: true, version: history.listVersions(id).find(x => x.ts === v.ts), changed: r.changed };
}

/* ---------- display startup ----------
  Startup saved-configuration file:          flash:/vrpcfg.zip
  Next startup saved-configuration file:     flash:/vrpcfg.zip
*/
function parseStartup(text) {
  const t = String(text || '');
  return {
    current: (t.match(/^\s*Startup saved-configuration file\s*:\s*(\S+)/im) || [])[1] || '',
    next: (t.match(/Next startup saved-configuration file\s*:\s*(\S+)/i) || [])[1] || '',
  };
}
const baseName = f => String(f || '').replace(/^.*[\/:]/, '');
const errorIn = text => (String(text || '').match(/^\s*Error\s*:\s*(.+)$/im) || [])[1] || '';

function stamp(d = new Date()) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}`;
}

// Слоты стека, кроме главного — на них нужно скопировать файл
function memberSlots(id) {
  const st = store.readState(id);
  const members = (st && st.hw && st.hw.stack && st.hw.stack.members) || [];
  const master = members.find(m => /master/i.test(m.role));
  return members.filter(m => m !== master).map(m => m.slot);
}

/* ---------- восстановление ---------- */
async function restore(id, ts, confirmName) {
  const sw = getSwitch(id);
  if (String(confirmName || '').trim() !== sw.name) throw new UserError(`Для подтверждения введите название коммутатора точно: «${sw.name}»`);
  if (!sw.secret) throw new UserError('Пароль не сохранён — укажите его в настройках');
  const text = history.readVersion(id, ts);
  if (text == null) throw new UserError('Версия не найдена', 404);
  if (!/^sysname /m.test(text) || !/^return\s*$/m.test(text)) throw new UserError('Версия неполная (нет sysname или return) — восстанавливать её нельзя');

  const log = [];
  const step = (ok, msg) => { log.push({ ok, msg }); };
  const opt = { host: sw.host, port: sw.port, user: sw.user, timeout: 120 };
  const password = await store.decrypt(sw.secret);

  // 1. Свежая копия текущей конфигурации — чтобы было куда вернуться
  try {
    const b = await backupNow(id, 'Автоматически перед восстановлением');
    step(true, `Сделана резервная копия текущей конфигурации (${b.version.lines} строк)`);
  } catch (e) {
    throw new UserError(`Восстановление остановлено: не удалось сделать копию текущей конфигурации (${e.message})`);
  }

  try {
    // 2. Какой файл загружается сейчас
    const [st0] = await runCommands(opt, password, ['display startup']);
    const before = parseStartup(st0);
    if (!before.next) throw new UserError('Не удалось прочитать display startup — восстановление остановлено');
    step(true, `Сейчас при загрузке используется: ${before.next}`);

    // 3. Загрузка версии на flash отдельным файлом
    const file = `restore_${stamp()}.cfg`;
    const size = await uploadFile(opt, password, file, text.replace(/\r?\n/g, '\r\n'));
    step(true, `Файл ${file} загружен на flash (${size} байт)`);

    // 4. Назначение конфигурацией для следующей загрузки
    let out = await runCommands({ ...opt, answerYes: true }, password, [`startup saved-configuration ${file}`, 'display startup']);
    let err = errorIn(out[0]);
    if (err && /slot|exist|stack|member|not found/i.test(err)) {
      // В стеке файл должен быть на каждом члене стека
      const slots = memberSlots(id);
      if (slots.length) {
        await runCommands({ ...opt, answerYes: true }, password, slots.map(n => `copy flash:/${file} slot${n}#flash:/${file}`));
        step(true, `Файл скопирован на члены стека: ${slots.map(n => 'slot ' + n).join(', ')}`);
        out = await runCommands({ ...opt, answerYes: true }, password, [`startup saved-configuration ${file}`, 'display startup']);
        err = errorIn(out[0]);
      }
    }
    if (err) throw new UserError(`Коммутатор не принял файл: ${err}`);
    const after = parseStartup(out[1]);
    const ok = baseName(after.next) === file;
    if (!ok) throw new UserError(`После команды для следующей загрузки указан «${after.next || '?'}», а не ${file}`);
    step(true, `Для следующей загрузки назначен ${after.next}`);

    update(id, cur => { cur.lastRestore = { at: new Date().toISOString(), ts, file, previous: before.next, undone: false }; });
    history.addEvent({ sw: id, swName: sw.name, type: 'restore', sev: 'high',
      text: `Назначено восстановление: версия от ${new Date(ts).toLocaleString('ru-RU')} (${file}). Применится после перезагрузки` });
    return { ok: true, log, file, previous: before.next };
  } catch (e) {
    const msg = e.user ? e.message : humanError(e);
    step(false, msg);
    return { ok: false, error: msg, log };
  }
}

// Вернуть прежний файл конфигурации для следующей загрузки
async function undoRestore(id) {
  const sw = getSwitch(id);
  const lr = sw.lastRestore;
  if (!lr || lr.undone) throw new UserError('Нет назначенного восстановления, которое можно отменить');
  const password = await store.decrypt(sw.secret);
  const prev = baseName(lr.previous);
  const out = await runCommands({ host: sw.host, port: sw.port, user: sw.user, answerYes: true, timeout: 60 }, password, [`startup saved-configuration ${prev}`, 'display startup']);
  const err = errorIn(out[0]);
  if (err) throw new UserError(`Коммутатор не принял команду: ${err}`);
  const after = parseStartup(out[1]);
  if (baseName(after.next) !== prev) throw new UserError(`Для следующей загрузки указан «${after.next || '?'}», а не ${prev}`);
  update(id, cur => { cur.lastRestore = { ...lr, undone: true, undoneAt: new Date().toISOString() }; });
  history.addEvent({ sw: id, swName: sw.name, type: 'restore-undo', sev: 'info', text: `Восстановление отменено: при загрузке снова используется ${after.next}` });
  return { ok: true, next: after.next };
}

module.exports = { backupNow, restore, undoRestore, parseStartup };
