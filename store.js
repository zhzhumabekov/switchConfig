// Хранилище списка коммутаторов и их конфигураций.
//   data/switches.json      — список коммутаторов (пароли зашифрованы)
//   data/configs/<id>.txt   — последняя полученная конфигурация
//   data/configs/<id>.prev.txt — предыдущая версия
//
// Пароли шифруются через Windows DPAPI (ConvertFrom-SecureString): расшифровать их
// может только та же учётная запись Windows на этом же компьютере.
// На других ОС — AES-256-GCM с ключом в data/.key.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const DATA = path.join(__dirname, 'data');
const CONFIGS = path.join(DATA, 'configs');
const STATES = path.join(DATA, 'state');
const LIST = path.join(DATA, 'switches.json');

fs.mkdirSync(CONFIGS, { recursive: true });
fs.mkdirSync(STATES, { recursive: true });

/* ---------- шифрование ---------- */
function powershell(script, input) {
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      '[Console]::OutputEncoding=[Text.Encoding]::UTF8; ' + script],
    { env: { ...process.env, SWCFG_IN: input }, windowsHide: true, timeout: 20000 },
    (err, stdout, stderr) => err ? reject(new Error(stderr.trim() || err.message)) : resolve(stdout.replace(/\r?\n$/, '')));
  });
}

function aesKey() {
  const f = path.join(DATA, '.key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
}

async function encrypt(plain) {
  if (process.platform === 'win32') {
    const value = await powershell('ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $env:SWCFG_IN -AsPlainText -Force)', plain);
    return { type: 'dpapi', value };
  }
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', aesKey(), iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return { type: 'aes', value: [iv, c.getAuthTag(), enc].map(b => b.toString('base64')).join('.') };
}

async function decrypt(secret) {
  if (!secret) return null;
  if (secret.type === 'dpapi') {
    return powershell('$s = ConvertTo-SecureString -String $env:SWCFG_IN; ' +
      '[Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))', secret.value);
  }
  const [iv, tag, enc] = secret.value.split('.').map(s => Buffer.from(s, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', aesKey(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
}

/* ---------- список коммутаторов ---------- */
function load() {
  if (!fs.existsSync(LIST)) return seed();
  return JSON.parse(fs.readFileSync(LIST, 'utf8'));
}
function save(list) {
  const tmp = LIST + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2));
  fs.renameSync(tmp, LIST);
}

// При первом запуске переносим уже имеющийся 3floor.txt, чтобы страница не была пустой
function seed() {
  const list = [];
  const old = path.join(__dirname, '3floor.txt');
  if (fs.existsSync(old)) {
    const text = fs.readFileSync(old, 'utf8').replace(/\r/g, '');
    const sysname = (text.match(/^sysname\s+(\S+)/m) || [])[1] || '';
    // Адрес берём из первого IP-интерфейса в самом конфиге; логин пользователь укажет в настройках
    const host = (text.match(/^interface Vlanif\d+\n(?: .*\n)*? ip address (\S+)/m) || [])[1] || '';
    const id = makeId(sysname || 'switch', list);
    fs.writeFileSync(configPath(id), text);
    list.push({
      id, name: sysname || 'Коммутатор', host, port: 22, user: '',
      secret: null, sysname,
      lastFetch: fs.statSync(old).mtime.toISOString(), lastError: null, source: 'импорт из 3floor.txt',
    });
  }
  save(list);
  return list;
}

function makeId(name, list) {
  const base = (name || 'switch').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'switch';
  let id = base, i = 2;
  while (list.some(s => s.id === id)) id = `${base}-${i++}`;
  return id;
}

const configPath = id => path.join(CONFIGS, `${id}.txt`);
const prevPath = id => path.join(CONFIGS, `${id}.prev.txt`);

function readConfig(id) {
  const f = configPath(id);
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
}

// Возвращает true, если конфигурация изменилась
function writeConfig(id, text) {
  const f = configPath(id);
  const old = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
  if (old === text) return false;
  if (old != null) fs.writeFileSync(prevPath(id), old);
  fs.writeFileSync(f, text);
  return true;
}

// Состояние портов (JSON) и сырой вывод команд — для проверки, если разбор что-то не распознал
const statePath = id => path.join(STATES, `${id}.json`);
const rawStatePath = id => path.join(STATES, `${id}.raw.txt`);

function writeState(id, state, raw) {
  fs.writeFileSync(statePath(id), JSON.stringify(state));
  fs.writeFileSync(rawStatePath(id), Object.entries(raw).map(([k, v]) => `===== ${k} =====\n${v ?? ''}`).join('\n\n'));
}
function readState(id) {
  const f = statePath(id);
  return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null;
}

function removeConfig(id) {
  for (const f of [configPath(id), prevPath(id), statePath(id), rawStatePath(id)]) if (fs.existsSync(f)) fs.unlinkSync(f);
}

module.exports = { load, save, encrypt, decrypt, makeId, readConfig, writeConfig, removeConfig, configPath, writeState, readState };
