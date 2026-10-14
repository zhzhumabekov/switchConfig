// Контроллер беспроводной сети Huawei AC (AC6508 и т. п.): точки доступа, клиенты, SSID.
// Все команды только читают данные. Результат кладётся в состояние контроллера (state.wlan).
const COMMANDS = {
  aps: 'display ap all',
  stations: 'display station all',
  vaps: 'display vap all',
};

const lines = t => String(t || '').replace(/\r/g, '').split('\n');
const MAC = /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/i;
const pl = (n, one, few, many) => { const m10 = n % 10, m100 = n % 100; return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? few : many; };
const dash = v => (v == null || v === '-' ? '' : v);

// Состояния точки в display ap all
const AP_STATE = {
  nor: 'работает', normal: 'работает', idle: 'не на связи', fault: 'авария', config: 'настраивается', 'config-failed': 'ошибка настройки',
  'commit-failed': 'ошибка применения', download: 'обновляет ПО', standby: 'резерв', verunmatch: 'версия ПО не подходит', 'name-conflicted': 'конфликт имени',
  unauthorized: 'не авторизована', initial: 'подключается', upgrading: 'обновляет ПО',
};
const STATE_RE = new RegExp(`^(${Object.keys(AP_STATE).join('|')})$`, 'i');

// 10D:2H:3M:4S → секунды
function uptimeSec(s) {
  if (!s || s === '-') return null;
  let sec = 0, ok = false;
  for (const [, n, u] of String(s).matchAll(/(\d+)\s*([DHMS])/gi)) { ok = true; sec += +n * { d: 86400, h: 3600, m: 60, s: 1 }[u.toLowerCase()]; }
  return ok ? sec : null;
}

/* ---------- display ap all ----------
ID   MAC            Name          Group   IP            Type              State STA Uptime        ExtraInfo
0    00e0-fc12-3456 3floor-ap1    default 10.20.50.101  AirEngine5760-10  nor   12  10D:2H:3M:4S  -
*/
function parseAps(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    if (t.length < 7 || !/^\d+$/.test(t[0]) || !MAC.test(t[1])) continue;
    const si = t.findIndex((x, i) => i >= 5 && STATE_RE.test(x));
    if (si < 0) continue;
    out.push({
      id: +t[0], mac: t[1].toLowerCase(), name: t.slice(2, si - 3).join(' ') || t[1], group: dash(t[si - 3]),
      ip: dash(t[si - 2]), type: dash(t[si - 1]), state: t[si].toLowerCase(), stateText: AP_STATE[t[si].toLowerCase()] || t[si],
      sta: /^\d+$/.test(t[si + 1] || '') ? +t[si + 1] : 0, uptime: dash(t[si + 2]), uptimeSec: uptimeSec(t[si + 2]), extra: dash(t.slice(si + 3).join(' ')),
    });
  }
  return out;
}

/* ---------- display station all ----------
STA MAC          AP ID Ap name     Rf/WLAN  Band  Type  Rx/Tx      RSSI  VLAN  IP address      SSID
14d1-1234-5678   0     3floor-ap1  1/1      5G    11ac  866/866    -45   51    10.20.51.23     PSA
*/
function parseStations(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    if (t.length < 8 || !MAC.test(t[0]) || !/^\d+$/.test(t[1])) continue;
    const ri = t.findIndex((x, i) => i >= 2 && /^\d+\/\d+$/.test(x) && /^(2\.4G|5G|6G|-)$/i.test(t[i + 1] || ''));
    if (ri < 0) continue;
    const [rx, tx] = String(t[ri + 3] || '').split('/').map(Number);
    out.push({
      mac: t[0].toLowerCase(), apId: +t[1], apName: t.slice(2, ri).join(' '), radio: t[ri], band: dash(t[ri + 1]), phy: dash(t[ri + 2]),
      rx: Number.isFinite(rx) ? rx : null, tx: Number.isFinite(tx) ? tx : null,
      rssi: /^-?\d+$/.test(t[ri + 4] || '') ? +t[ri + 4] : null, vlan: /^\d+$/.test(t[ri + 5] || '') ? +t[ri + 5] : null,
      ip: /^\d+\.\d+\.\d+\.\d+$/.test(t[ri + 6] || '') ? t[ri + 6] : '', ssid: t.slice(ri + 7).join(' '),
    });
  }
  return out;
}

/* ---------- display vap all ----------
AP ID AP name   RfID WID  BSSID          Status  Auth type     STA   SSID
0     ap1       0    1    00e0-fc12-3450 ON      WPA/WPA2-PSK  0     PSA
*/
function parseVaps(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    const bi = t.findIndex(x => MAC.test(x));
    if (bi < 4 || !/^\d+$/.test(t[0])) continue;
    const st = t[bi + 1] || '';
    const staIdx = t.findIndex((x, i) => i > bi + 1 && /^\d+$/.test(x));
    out.push({
      apId: +t[0], apName: t.slice(1, bi - 2).join(' '), radio: +t[bi - 2], wlan: +t[bi - 1], bssid: t[bi].toLowerCase(), status: st,
      auth: staIdx > 0 ? t.slice(bi + 2, staIdx).join(' ') : '', sta: staIdx > 0 ? +t[staIdx] : 0, ssid: staIdx > 0 ? t.slice(staIdx + 1).join(' ') : '',
    });
  }
  return out;
}

function commandError(text) {
  const m = String(text || '').match(/^\s*Error:\s*(.*)$/m);
  return m ? m[1].trim() || 'команда не поддерживается' : null;
}

// Сводка и проблемы
function problems(aps, stations) {
  const out = [];
  const add = (key, sev, text, extra = {}) => out.push({ key, sev, text, ...extra });
  for (const a of aps) {
    if (a.state === 'nor' || a.state === 'normal') continue;
    const sev = ['fault', 'idle', 'config-failed', 'commit-failed', 'verunmatch', 'name-conflicted'].includes(a.state) ? 'high' : 'med';
    add(`ap:${a.mac}`, sev, `Точка доступа ${a.name}: ${a.stateText}${a.extra ? ' (' + a.extra + ')' : ''}`, { mac: a.mac, cmd: `display ap all\ndisplay ap online-fail-record ap-mac ${a.mac}` });
  }
  const weak = stations.filter(s => s.rssi != null && s.rssi < -75);
  if (weak.length >= 3) add('weak', 'info', `${weak.length} ${pl(weak.length, 'клиент', 'клиента', 'клиентов')} со слабым сигналом (RSSI ниже −75 дБм)`, { cmd: 'display station all' });
  const loaded = aps.filter(a => a.sta >= 40);
  for (const a of loaded) add(`load:${a.mac}`, 'med', `Точка ${a.name} перегружена: ${a.sta} клиентов`, { mac: a.mac, cmd: `display station ap-name ${a.name}` });
  return out;
}

function parseAll(raw) {
  const errors = {};
  for (const [k, cmd] of Object.entries(COMMANDS)) {
    const e = raw[k] == null ? 'не выполнялась' : commandError(raw[k]);
    if (e) errors[cmd] = e;
  }
  const aps = parseAps(raw.aps);
  const stations = parseStations(raw.stations);
  const vaps = parseVaps(raw.vaps);
  // SSID: сколько клиентов и на каких VLAN
  const ssids = {};
  for (const v of vaps) {
    const s = ssids[v.ssid] ||= { ssid: v.ssid, auth: v.auth, wlan: v.wlan, vaps: 0, on: 0, clients: 0, vlans: [] };
    s.vaps++; if (/^on$/i.test(v.status)) s.on++;
  }
  for (const st of stations) {
    const s = ssids[st.ssid] ||= { ssid: st.ssid, auth: '', wlan: null, vaps: 0, on: 0, clients: 0, vlans: [] };
    s.clients++;
    if (st.vlan != null && !s.vlans.includes(st.vlan)) s.vlans.push(st.vlan);
  }
  return { aps, stations, ssids: Object.values(ssids), problems: problems(aps, stations), errors };
}

module.exports = { COMMANDS, parseAll, parseAps, parseStations, parseVaps, uptimeSec, AP_STATE };
