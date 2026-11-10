// Состояние коммутатора Cisco IOS: порты, ошибки, LLDP/CDP, MAC, ARP, версия, среда, STP, журнал.
// Всё приводится к тому же виду, что и у Huawei (live-state.js), чтобы страница показывала одинаково.
// Все команды только читают данные.
const hardware = require('./hardware');
const log = require('./log');

const COMMANDS = {
  interfaces: 'show interfaces status',
  errors: 'show interfaces counters errors',
  lldp: 'show lldp neighbors',
  cdp: 'show cdp neighbors',
  mac: 'show mac address-table',
  arp: 'show ip arp',
  version: 'show version',
  env: 'show environment all',
  cpu: 'show processes cpu | include CPU utilization',
  stproot: 'show spanning-tree root',
  logbuffer: 'show logging',
};

const lines = t => String(t || '').replace(/\r/g, '').split('\n');

// Gi1/0/1, Gig 1/0/1, GigabitEthernet1/0/1 → GigabitEthernet1/0/1
const PREFIX = [
  [/^(?:Hu|HundredGig\w*)/i, 'HundredGigE'], [/^(?:Fo|FortyGig\w*)/i, 'FortyGigabitEthernet'],
  [/^(?:Twe|TwentyFiveGig\w*)/i, 'TwentyFiveGigE'], [/^(?:Tw|TwoGig\w*)/i, 'TwoGigabitEthernet'],
  [/^(?:Te|Ten|TenGig\w*)/i, 'TenGigabitEthernet'], [/^(?:Gi|Gig|GigabitEthernet)/i, 'GigabitEthernet'],
  [/^(?:Fa|Fas|FastEthernet)/i, 'FastEthernet'], [/^(?:Po|Port-channel)/i, 'Port-channel'], [/^(?:Vl|Vlan)/i, 'Vlan'],
];
function normPort(name) {
  const s = String(name || '').replace(/\s+/g, '');
  const m = s.match(/^([A-Za-z-]+)(\d[\d/.:]*)$/);
  if (!m) return s;
  for (const [re, full] of PREFIX) if (re.test(m[1])) return full + m[2];
  return s;
}
const isPortToken = t => /^(Gi|Gig|Fa|Fas|Te|Ten|Tw|Twe|Fo|Hu|Po|GigabitEthernet|FastEthernet|TenGigabitEthernet|TwoGigabitEthernet|Port-channel)\d/i.test(t);

// 0011.2233.4455 → 0011-2233-4455
const huMac = m => { const h = String(m || '').replace(/[^0-9a-f]/gi, '').toLowerCase(); return h.length === 12 ? `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8)}` : null; };

/* ---------- show interfaces status ----------
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   PC-1               connected    20         a-full a-1000 10/100/1000BaseTX
*/
const ST_MAP = { connected: 'up', notconnect: 'down', disabled: 'admin', 'err-disabled': 'errdis', inactive: 'down', sfpabsent: 'down', xcvrabsen: 'down', monitoring: 'up', suspended: 'down', notpresent: 'down' };
function parseInterfaces(text) {
  const out = {};
  for (const l of lines(text)) {
    const m = l.match(/^(\S+)\s+(.*?)\s*\b(connected|notconnect|disabled|err-disabled|inactive|sfpAbsent|xcvrAbsen|monitoring|suspended|notpresent)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$/i);
    if (!m || !isPortToken(m[1])) continue;
    out[normPort(m[1])] = {
      phy: m[3], proto: m[3], status: ST_MAP[m[3].toLowerCase()] || 'down',
      vlan: m[4], duplex: m[5], speed: m[6], media: m[7].trim(), name: m[2].trim(),
      inUti: '', outUti: '', inErr: 0, outErr: 0,
    };
  }
  return out;
}

/* ---------- show interfaces counters errors (первая таблица) ----------
Port        Align-Err     FCS-Err    Xmit-Err     Rcv-Err  UnderSize  OutDiscards
Gi1/0/1             0           0           0           0          0            0
*/
function applyErrors(ifs, text) {
  for (const l of lines(text)) {
    const m = l.match(/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/);
    if (!m || !isPortToken(m[1])) continue;
    const p = ifs[normPort(m[1])];
    if (!p) continue;
    p.inErr = +m[2] + +m[3] + +m[5] + +m[6];
    p.outErr = +m[4];
  }
}

/* ---------- show lldp neighbors ----------
Device ID           Local Intf     Hold-time  Capability      Port ID
psa_4_floor         Gi1/0/48       120        B,R             XGigabitEthernet3/0/48
*/
function parseLldp(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    const li = t.findIndex((x, i) => i > 0 && isPortToken(x));
    if (li < 1 || !/^\d+$/.test(t[li + 1] || '')) continue;
    out.push({ port: normPort(t[li]), device: t.slice(0, li).join(' '), remotePort: t[t.length - 1], expires: +t[li + 1] });
  }
  return out;
}

/* ---------- show cdp neighbors (длинные имена переносятся на следующую строку) ----------
Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
SEP001122334455  Gig 1/0/5         150             H P M   IP Phone  Port 1
psa_4_floor
                 Gig 1/0/48        170              R S I  S5720     XGE 3/0/48
*/
function parseCdp(text) {
  const out = [];
  let pendingName = '';
  let started = false;
  for (const l of lines(text)) {
    if (/^Device ID/i.test(l)) { started = true; continue; }
    if (!started || !l.trim() || /^Total cdp entries/i.test(l)) continue;
    const m = l.match(/^(\S*)\s+((?:Gig|Fas|Ten|Two|Twe|For|Hun|Po|Gi|Fa|Te)\w*\s*\d+(?:\/\d+)+)\s+(\d+)\s+(.*)$/i);
    if (!m) { if (/^\S/.test(l) && !/\s{2,}\S/.test(l.trim())) pendingName = l.trim(); continue; }
    const device = m[1] || pendingName;
    pendingName = '';
    const rest = m[4].trim().split(/\s+/);
    const remote = rest.length >= 2 && /^[A-Za-z-]+$/.test(rest[rest.length - 2]) && /\d/.test(rest[rest.length - 1]) ? rest.slice(-2).join(' ') : rest[rest.length - 1];
    out.push({ port: normPort(m[2]), device, remotePort: remote, expires: +m[3], cdp: true });
  }
  return out;
}

/* ---------- show mac address-table ----------
  20    0011.2233.4455    DYNAMIC     Gi1/0/1
*/
function parseMac(text) {
  const out = [];
  for (const l of lines(text)) {
    const m = l.match(/^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)/i);
    if (!m || !isPortToken(m[4])) continue;
    out.push({ mac: huMac(m[2]), vlan: +m[1], port: normPort(m[4]), type: m[3].toLowerCase() });
  }
  return out;
}

/* ---------- show ip arp ----------
Internet  10.20.20.20             3   b4b2.e9f2.f00b  ARPA   Vlan20
*/
function parseArp(text) {
  const out = [];
  for (const l of lines(text)) {
    const m = l.match(/^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)/i);
    if (!m) continue;
    const vl = m[4].match(/^Vlan(\d+)$/i);
    out.push({ ip: m[1], mac: huMac(m[3]), type: m[2] === '-' ? 'interface' : 'dynamic', iface: normPort(m[4]), vlan: vl ? +vl[1] : null });
  }
  return out;
}

/* ---------- show version ---------- */
function parseVersion(text) {
  const t = String(text || '');
  const sw = (t.match(/Cisco IOS(?: XE)? Software.*?Version\s+([^\s,]+)/i) || [])[1] || '';
  const platform = (t.match(/Cisco IOS(?: XE)? Software,?\s*([^\s,]+)\s+Software/i) || [])[1] || '';
  const model = (t.match(/^Model [Nn]umber\s*:\s*(\S+)/m) || t.match(/^cisco\s+(\S+)\s+\(/m) || [])[1] || '';
  const upLine = (t.match(/^\S+ uptime is (.+)$/m) || [])[1] || '';
  const part = re => +((upLine.match(re) || [])[1] || 0);
  const uptimeSec = upLine ? part(/(\d+)\s*year/) * 31536000 + part(/(\d+)\s*week/) * 604800 + part(/(\d+)\s*day/) * 86400 + part(/(\d+)\s*hour/) * 3600 + part(/(\d+)\s*minute/) * 60 : null;
  // Таблица стека: *    1 52    WS-C2960X-48FPD-L  15.2(7)E7  C2960X-UNIVERSALK9-M
  const members = [];
  for (const l of lines(t)) {
    const m = l.match(/^(\*?)\s*(\d+)\s+(\d+)\s+(WS-\S+|C\d\S+|IE-\S+|ISR\S+)\s+(\S+)\s+(\S+)/);
    if (m) members.push({ slot: +m[2], role: m[1] ? 'Master' : 'Member', type: m[4], ports: +m[3], software: m[5] });
  }
  return { version: { software: [platform, sw].filter(Boolean).join(' '), vrp: '', model, uptime: upLine.trim(), uptimeSec, patch: '' }, members };
}

/* ---------- show environment all ---------- */
function parseEnv(text) {
  const t = String(text || '');
  const fan = [], power = [], temperature = [];
  for (const l of lines(t)) {
    let m;
    if ((m = l.match(/^\s*(?:Switch\s+(\d+)\s+)?FAN(?:\s+(\S+))?\s+is\s+(.+)$/i))) fan.push({ slot: +(m[1] || 1), id: m[2] || '1', status: /^OK/i.test(m[3]) ? 'Normal' : m[3].trim(), speed: null });
    else if ((m = l.match(/^\s*(\d+)\s*([AB]?)\s+(\S+)\s+(\S+)\s+(Good|Bad|OK|Faulty|Not Present|No Input Power)\b/i))) {
      power.push({ slot: +m[1], id: 'PS' + (m[2] || m[3]), online: /not present/i.test(m[5]) ? 'Absent' : 'Present', state: /good|ok/i.test(m[5]) ? 'Supply' : m[5], watts: null });
    }
  }
  const cur = t.match(/Temperature Value:\s*(\d+)/i), red = t.match(/Red Threshold\s*:\s*(\d+)/i), state = t.match(/Temperature State:\s*(\w+)/i);
  if (cur) temperature.push({ slot: 1, sensor: 'system', status: state && !/green|ok/i.test(state[1]) ? state[1].toUpperCase() : 'NORMAL', current: +cur[1], upper: red ? +red[1] : null });
  else if (/SYSTEM TEMPERATURE is (\w+)/i.test(t)) {
    const st = t.match(/SYSTEM TEMPERATURE is (\w+)/i)[1];
    if (!/^OK$/i.test(st)) temperature.push({ slot: 1, sensor: 'system', status: st.toUpperCase(), current: null, upper: null });
  }
  return { fan, power, temperature };
}

/* ---------- show spanning-tree root ----------
Vlan                   Root ID          Cost    Time  Age Dly  Root Port
---------------- -------------------- --------- ----- --- ---  ------------
VLAN0001         32769 0011.2233.4455         4    2   20  15  Gi1/0/48
VLAN0020         32788 4c1f.cc12.3456         0    2   20  15
*/
function parseStpRoot(text) {
  const vlans = [];
  for (const l of lines(text)) {
    const m = l.match(/^VLAN0*(\d+)\s+(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\d+)\s+\d+\s+\d+\s+\d+\s*(\S*)/i);
    if (m) vlans.push({ vlan: +m[1], priority: +m[2], rootMac: huMac(m[3]), cost: +m[4], rootPort: m[5] ? normPort(m[5]) : '' });
  }
  const main = vlans.find(v => v.vlan === 20) || vlans.find(v => v.vlan === 1) || vlans[0];
  return {
    mode: vlans.length ? 'PVST (по VLAN)' : '', vlans,
    bridge: '', root: main ? `${main.priority}.${main.rootMac}` : '', rootCost: main ? main.cost : null,
    rootPort: main ? main.rootPort : '', isRoot: !!main && !main.rootPort && main.cost === 0,
    ports: {}, bpduProtection: false, tcCount: 0, tcReceived: 0, lastTcSec: null, lastTcPort: '', disabled: !vlans.length && /Spanning tree.*not|No spanning tree/i.test(text || ''),
  };
}

function commandError(text) {
  const m = String(text || '').match(/^\s*%\s*(Invalid input.*|Incomplete command.*|Ambiguous command.*|Authorization failed.*)$/m);
  return m ? m[1].trim() : null;
}

function parseAll(raw, at = new Date().toISOString()) {
  const errors = {};
  for (const [k, cmd] of Object.entries(COMMANDS)) {
    const e = raw[k] == null ? 'не выполнялась' : commandError(raw[k]);
    if (e) errors[cmd] = e;
  }
  const interfaces = parseInterfaces(raw.interfaces);
  applyErrors(interfaces, raw.errors);
  // LLDP и CDP в один список (CDP добавляем только для портов без LLDP-соседа)
  const lldp = parseLldp(raw.lldp);
  for (const c of parseCdp(raw.cdp)) if (!lldp.some(x => x.port === c.port)) lldp.push(c);
  const ver = parseVersion(raw.version);
  const env = parseEnv(raw.env);
  const cpu = (String(raw.cpu || '').match(/five seconds:\s*(\d+)%/i) || [])[1];
  const hw = {
    version: ver.version, device: [], stack: { topology: '', members: ver.members },
    cpu: { now: cpu != null ? +cpu : null, max: null, min5: +((String(raw.cpu || '').match(/five minutes:\s*(\d+)%/i) || [])[1] || 0) || null },
    memory: { percent: null }, temperature: env.temperature, power: env.power, fan: env.fan, transceiver: {},
  };
  // Проблемы те же, что у Huawei, но с командами Cisco
  const CMD = { 'display cpu-usage': 'show processes cpu sorted', 'display memory-usage': 'show processes memory sorted', 'display temperature all': 'show environment temperature', 'display power': 'show environment power', 'display fan': 'show environment fan', 'display device': 'show inventory', 'display stack': 'show switch' };
  hw.problems = hardware.problems(hw, interfaces).map(p => ({ ...p, cmd: CMD[p.cmd] || (p.cmd && p.cmd.startsWith('display') ? '' : p.cmd) }));
  // Порты, выключенные защитой (err-disabled)
  for (const [port, st] of Object.entries(interfaces)) {
    if (st.status === 'errdis') hw.problems.push({ key: `errdis:${port}`, sev: 'high', port, text: `Порт ${port.replace(/^GigabitEthernet/, 'GE')} выключен защитой (err-disabled)`, cmd: `show interfaces status err-disabled\nshow errdisable recovery` });
  }
  return {
    at, vendor: 'cisco', interfaces, lldp, mac: parseMac(raw.mac), arp: parseArp(raw.arp),
    hw, stp: parseStpRoot(raw.stproot), log: log.analyze(raw.logbuffer), errors,
  };
}

// Конфигурация из вывода show running-config: от «Current configuration» до «end»
function extractConfig(text) {
  const ls = String(text || '').replace(/\r/g, '').split('\n');
  let start = ls.findIndex(l => /^Current configuration\s*:/i.test(l));
  if (start < 0) start = ls.findIndex(l => /show running-config/.test(l));
  const end = ls.findIndex((l, i) => i > start && l.trim() === 'end');
  if (start < 0 || end < 0) throw new Error('В выводе не найдена конфигурация (нет «Current configuration» или «end»). Нужен привилегированный режим (enable).');
  return ls.slice(start + 1, end + 1).map(l => l.replace(/\s+$/, '')).join('\n').replace(/^\n+/, '') + '\n';
}

module.exports = { COMMANDS, parseAll, extractConfig, parseInterfaces, parseLldp, parseCdp, parseMac, parseArp, parseVersion, parseEnv, parseStpRoot, normPort, huMac };
