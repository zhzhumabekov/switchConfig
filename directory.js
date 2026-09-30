// Данные из Windows-инфраструктуры: DHCP (MAC → IP, имя), компьютеры AD, обратный DNS.
// Всё только читается. Настройки — data/directory-settings.json, результат — data/directory.json.
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const { execFile } = require('child_process');
const store = require('./store');

const DATA = path.join(__dirname, 'data');
const SETTINGS = path.join(DATA, 'directory-settings.json');
const RESULT = path.join(DATA, 'directory.json');
const SCRIPT = path.join(__dirname, 'directory.ps1');

const DEFAULTS = { enabled: process.platform === 'win32', dhcpServers: '', ad: true, dhcp: true, dns: true, user: '', secret: null };

function loadSettings() {
  try { return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(SETTINGS, 'utf8')) }; }
  catch { return { ...DEFAULTS }; }
}
function saveSettings(s) { fs.writeFileSync(SETTINGS, JSON.stringify(s, null, 2)); }

function publicSettings(s = loadSettings()) {
  return {
    enabled: s.enabled, dhcpServers: s.dhcpServers, ad: s.ad, dhcp: s.dhcp, dns: s.dns,
    user: s.user, hasPassword: !!s.secret,
    currentUser: process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}` : (process.env.USERNAME || ''),
    domain: process.env.USERDNSDOMAIN || '',
  };
}

function readResult() {
  try { return JSON.parse(fs.readFileSync(RESULT, 'utf8')); } catch { return null; }
}

function runScript(s, password) {
  const tmp = path.join(DATA, `directory.${process.pid}.tmp.json`);
  const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', SCRIPT, '-OutFile', tmp];
  if (s.dhcpServers) args.push('-DhcpServers', s.dhcpServers);
  if (!s.dhcp) args.push('-NoDhcp');
  if (!s.ad) args.push('-NoAD');
  const env = { ...process.env };
  if (s.user && password) { env.SWCFG_USER = s.user; env.SWCFG_PASS = password; }
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', args, { env, windowsHide: true, timeout: 180000, maxBuffer: 1 << 20 }, (err, stdout, stderr) => {
      try {
        if (!fs.existsSync(tmp)) return reject(new Error((stderr || stdout || (err && err.message) || 'скрипт не вернул данные').trim()));
        const data = JSON.parse(fs.readFileSync(tmp, 'utf8').replace(/^\uFEFF/, ''));
        resolve(data);
      } catch (e) { reject(e); } finally { fs.rm(tmp, { force: true }, () => {}); }
    });
  });
}

function withTimeout(p, ms) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);
}

// Обратный DNS для IP из ARP коммутаторов, которых нет в DHCP (статические адреса)
async function reverseLookups(knownIps) {
  const ips = new Set();
  for (const sw of store.load()) {
    const st = store.readState(sw.id);
    for (const a of (st && st.arp) || []) if (!knownIps.has(a.ip)) ips.add(a.ip);
  }
  const out = {};
  const list = [...ips].slice(0, 1000);
  for (let i = 0; i < list.length; i += 20) {
    await Promise.all(list.slice(i, i + 20).map(async ip => {
      try { const names = await withTimeout(dns.reverse(ip), 2000); if (names.length) out[ip] = names[0]; } catch { /* нет PTR-записи */ }
    }));
  }
  return out;
}

let running = null;

async function refresh() {
  if (running) return running;
  running = (async () => {
    const s = loadSettings();
    if (!s.enabled) throw new Error('Источник AD / DHCP / DNS выключен в настройках');
    if (process.platform !== 'win32') throw new Error('Чтение AD и DHCP работает только на Windows');
    const password = s.user ? await store.decrypt(s.secret) : null;
    const data = (s.dhcp || s.ad) ? await runScript(s, password) : { at: new Date().toISOString(), servers: [], dhcp: [], ad: [], errors: {} };
    data.dhcp = data.dhcp || [];
    data.ad = data.ad || [];
    data.errors = data.errors || {};
    data.dns = {};
    if (s.dns) {
      try { data.dns = await reverseLookups(new Set(data.dhcp.map(l => l.ip))); }
      catch (e) { data.errors.DNS = e.message; }
    }
    fs.writeFileSync(RESULT, JSON.stringify(data));
    return summary(data);
  })();
  try { return await running; } finally { running = null; }
}

function summary(d = readResult()) {
  if (!d) return null;
  return {
    at: d.at, servers: d.servers || [], errors: d.errors || {},
    counts: { dhcp: (d.dhcp || []).length, reserved: (d.dhcp || []).filter(l => l.reserved).length, ad: (d.ad || []).length, dns: Object.keys(d.dns || {}).length },
  };
}

// Обновить, если данные старше maxAgeMs (вызывается после сбора с коммутаторов)
async function refreshIfStale(maxAgeMs) {
  const s = loadSettings();
  if (!s.enabled || process.platform !== 'win32') return null;
  const d = readResult();
  if (d && Date.now() - new Date(d.at) < maxAgeMs) return null;
  return refresh().catch(e => ({ error: e.message }));
}

module.exports = { loadSettings, saveSettings, publicSettings, readResult, refresh, refreshIfStale, summary };
