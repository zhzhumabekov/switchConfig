// Состояние «железа» коммутатора Huawei VRP: модель, прошивка, время работы, стек,
// CPU, память, температура, питание, вентиляторы, SFP-модули. Все команды только читают данные.
const COMMANDS = {
  version: 'display version',
  device: 'display device',
  stack: 'display stack',
  cpu: 'display cpu-usage',
  memory: 'display memory-usage',
  temperature: 'display temperature all',
  power: 'display power',
  fan: 'display fan',
  transceiver: 'display transceiver verbose',
};

const lines = t => String(t || '').replace(/\r/g, '').split('\n');
const num = v => { const n = parseFloat(String(v).replace(',', '.')); return Number.isFinite(n) ? n : null; };

/* ---------- display version ----------
VRP (R) software, Version 5.170 (S5720 V200R010C00SPC600)
HUAWEI S5720-52X-LI-AC Routing Switch uptime is 125 weeks, 3 days, 2 hours, 11 minutes
*/
function parseVersion(text) {
  const t = String(text || '');
  const ver = (t.match(/VRP \(R\) software,\s*Version\s+([^\n]+)/i) || [])[1] || '';
  const inner = (ver.match(/\(([^)]+)\)/) || [])[1] || ver.trim();
  const upLine = (t.match(/^.*uptime is .+$/im) || [])[0] || '';
  const model = (upLine.match(/\b(S\d{4}[\w-]*|CE\d{4}[\w-]*|AR\d+[\w-]*)/) || [])[1] || '';
  const upText = (upLine.match(/uptime is (.+)$/i) || [])[1] || '';
  const part = re => +((upText.match(re) || [])[1] || 0);
  const uptimeSec = upText ? part(/(\d+)\s*week/) * 604800 + part(/(\d+)\s*day/) * 86400 + part(/(\d+)\s*hour/) * 3600 + part(/(\d+)\s*minute/) * 60 : null;
  const patch = (t.match(/Patch Version\s*:\s*(\S+)/i) || [])[1] || '';
  return { software: inner.trim(), vrp: ver.trim(), model, uptime: upText.trim(), uptimeSec, patch };
}

/* ---------- display device ----------
Slot Sub  Type                   Online    Power    Register     Status   Role
0    -    S5720-52X-LI-AC        Present   PowerOn  Registered   Normal   Master
*/
function parseDevice(text) {
  const out = [];
  for (const l of lines(text)) {
    const m = l.match(/^\s*(\d+)\s+(\S+)\s+(\S+)\s+(Present|Absent)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?/i);
    if (m) out.push({ slot: +m[1], type: m[3], online: m[4], power: m[5], register: m[6], status: m[7], role: m[8] || '' });
  }
  return out;
}

/* ---------- display stack ----------
Stack topology type: Ring
Slot      Role        MAC address       Priority   Device type
0         Master      0011-2233-4455    200        S5720-52X-LI-AC
*/
function parseStack(text) {
  const t = String(text || '');
  const topology = (t.match(/Stack topology type\s*:\s*(\S+)/i) || [])[1] || '';
  const members = [];
  for (const l of lines(t)) {
    const m = l.match(/^\s*(\d+)\s+(Master|Standby|Slave|Backup)\s+([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(\d+)\s+(\S+)/i);
    if (m) members.push({ slot: +m[1], role: m[2], mac: m[3].toLowerCase(), priority: +m[4], type: m[5] });
  }
  return { topology, members };
}

/* ---------- display cpu-usage / display memory-usage ---------- */
function parseCpu(text) {
  const t = String(text || '');
  const now = num((t.match(/CPU Usage\s*:\s*([\d.]+)%/i) || t.match(/five seconds:\s*([\d.]+)%/i) || [])[1]);
  const max = num((t.match(/CPU Usage\s*:\s*[\d.]+%\s*Max\s*:\s*([\d.]+)%/i) || [])[1]);
  const min5 = num((t.match(/five minutes:\s*([\d.]+)%/i) || [])[1]);
  return { now, max, min5 };
}
function parseMemory(text) {
  const t = String(text || '');
  return {
    percent: num((t.match(/Memory Using Percentage(?: Is)?\s*:\s*([\d.]+)%/i) || [])[1]),
    total: num((t.match(/System Total Memory Is\s*:\s*(\d+)/i) || [])[1]),
    used: num((t.match(/Total Memory Used Is\s*:\s*(\d+)/i) || [])[1]),
  };
}

/* ---------- display temperature all ----------
Slot  Card   Sensor Status   Current(C) Lower(C) Lower-Resume(C) Upper(C) Upper-Resume(C)
0     NA     NA     NORMAL   39         0        4               68       64
*/
function parseTemperature(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    if (!/^\d+$/.test(t[0] || '')) continue;
    const si = t.findIndex(x => /^(NORMAL|ABNORMAL|HIGH|LOW|MINOR|MAJOR|FATAL|WARNING|ALARM)$/i.test(x));
    if (si < 0) continue;
    const vals = t.slice(si + 1).map(num).filter(v => v != null);
    if (!vals.length) continue;
    const upper = vals.length >= 5 ? vals[3] : vals.length >= 3 ? vals[2] : null;
    out.push({ slot: +t[0], sensor: t.slice(1, si).join(' '), status: t[si].toUpperCase(), current: vals[0], upper });
  }
  return out;
}

/* ---------- display power ----------
Slot    PowerID  Online   Mode   State      Power(W)
0       PWR1     Present  AC     Supply     150.00
*/
function parsePower(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    if (!/^\d+$/.test(t[0] || '') || !/^(Present|Absent)$/i.test(t[2] || '')) continue;
    out.push({ slot: +t[0], id: t[1], online: t[2], mode: t[3] || '', state: t[4] || '', watts: num(t[5]) });
  }
  return out;
}

/* ---------- display fan ----------
Slot  FanID   FanNum   Status      Speed(%)   Mode     Airflow
0     1       [1-2]    Normal      40         Auto     Side-to-Side
*/
function parseFan(text) {
  const out = [];
  for (const l of lines(text)) {
    const t = l.trim().split(/\s+/);
    if (!/^\d+$/.test(t[0] || '')) continue;
    const si = t.findIndex((x, i) => i > 0 && /^(Normal|Abnormal|Fault|Absent|Present|Failed|Block)$/i.test(x));
    if (si < 0) continue;
    out.push({ slot: +t[0], id: t[1], status: t[si], speed: num(t[si + 1]) });
  }
  return out;
}

/* ---------- display transceiver verbose ----------
XGigabitEthernet0/0/3 transceiver information:
  Transceiver Type      :10GBASE_SR
  RX Power(dBm)         :-2.94
  RX Power Low Threshold(dBm) :-13.90
*/
function parseTransceiver(text) {
  const out = {};
  const parts = String(text || '').replace(/\r/g, '').split(/^\s*(\S+) transceiver information:\s*$/m);
  for (let i = 1; i < parts.length; i += 2) {
    const kv = {};
    for (const l of lines(parts[i + 1])) {
      const m = l.match(/^\s*([^:]+?)\s*:\s*(.*)$/);
      if (m && !kv[m[1].toLowerCase()]) kv[m[1].toLowerCase()] = m[2].trim();
    }
    const get = (...keys) => { for (const k of keys) for (const [kk, v] of Object.entries(kv)) if (kk.startsWith(k)) return v; return ''; };
    // Для многоканальных модулей (40G) значения через «|» — берём худший канал
    const minOf = v => { const ns = String(v).split(/[|,]/).map(num).filter(x => x != null); return ns.length ? Math.min(...ns) : null; };
    const name = normPort(parts[i]);
    out[name] = {
      type: get('transceiver type'), wavelength: get('wavelength'), distance: get('transfer distance'),
      vendor: get('vendor name'), part: get('vendor part number'), serial: get('manu. serial number', 'serial number'),
      temp: minOf(get('temperature(')), bias: minOf(get('bias current(')), voltage: minOf(get('voltage(')),
      rx: minOf(get('rx power(dbm)', 'rx power (dbm)', 'current rx power')), rxLow: num(get('rx power low threshold', 'rx power low warning')), rxHigh: num(get('rx power high threshold', 'rx power high warning')),
      tx: minOf(get('tx power(dbm)', 'tx power (dbm)', 'current tx power')), txLow: num(get('tx power low threshold', 'tx power low warning')), txHigh: num(get('tx power high threshold', 'tx power high warning')),
    };
  }
  return out;
}
function normPort(n) {
  return String(n || '').replace(/^XGE(?=\d)/i, 'XGigabitEthernet').replace(/^GE(?=\d)/i, 'GigabitEthernet');
}

/* ---------- проблемы ---------- */
function problems(hw, interfaces = {}) {
  const out = [];
  const add = (key, sev, text, extra = {}) => out.push({ key, sev, text, ...extra });
  if (hw.cpu && hw.cpu.now != null) {
    if (hw.cpu.now >= 95) add('cpu', 'high', `Загрузка CPU ${hw.cpu.now}%`, { cmd: 'display cpu-usage' });
    else if (hw.cpu.now >= 80) add('cpu', 'med', `Высокая загрузка CPU: ${hw.cpu.now}%`, { cmd: 'display cpu-usage' });
  }
  if (hw.memory && hw.memory.percent != null) {
    if (hw.memory.percent >= 95) add('mem', 'high', `Память занята на ${hw.memory.percent}%`, { cmd: 'display memory-usage' });
    else if (hw.memory.percent >= 85) add('mem', 'med', `Высокое использование памяти: ${hw.memory.percent}%`, { cmd: 'display memory-usage' });
  }
  for (const t of hw.temperature || []) {
    if (t.status !== 'NORMAL') add(`temp:${t.slot}:${t.sensor}`, 'high', `Температура в слоте ${t.slot}: ${t.current}°C (${t.status})`, { cmd: 'display temperature all' });
    else if (t.upper != null && t.current >= t.upper - 5) add(`temp:${t.slot}:${t.sensor}`, 'med', `Температура в слоте ${t.slot} близка к порогу: ${t.current}°C из ${t.upper}°C`, { cmd: 'display temperature all' });
  }
  for (const p of hw.power || []) {
    if (/^present$/i.test(p.online) && !/^(supply|normal|ok|on)$/i.test(p.state)) add(`pwr:${p.slot}:${p.id}`, 'high', `Блок питания ${p.id} в слоте ${p.slot}: ${p.state}`, { cmd: 'display power' });
  }
  for (const f of hw.fan || []) {
    if (!/^normal$/i.test(f.status)) add(`fan:${f.slot}:${f.id}`, 'high', `Вентилятор ${f.id} в слоте ${f.slot}: ${f.status}`, { cmd: 'display fan' });
  }
  for (const d of hw.device || []) {
    if (/^present$/i.test(d.online) && !/^normal$/i.test(d.status)) add(`dev:${d.slot}`, 'high', `Слот ${d.slot} (${d.type}): состояние ${d.status}`, { cmd: 'display device' });
  }
  if (hw.stack && /chain|link/i.test(hw.stack.topology) && hw.stack.members.length >= 3) {
    add('stack-chain', 'info', `Стек из ${hw.stack.members.length} коммутаторов собран цепочкой, а не кольцом: обрыв одного кабеля разделит стек`, { cmd: 'display stack' });
  }
  for (const [port, x] of Object.entries(hw.transceiver || {})) {
    const st = interfaces[port];
    if (!st || st.status !== 'up' || x.rx == null) continue; // для выключенного порта сигнал не оцениваем
    const sp = port.replace(/^XGigabitEthernet/, 'XGE').replace(/^GigabitEthernet/, 'GE');
    const cmd = `display transceiver interface ${port} verbose`;
    if (x.rxLow != null && x.rx < x.rxLow) add(`sfp-rx:${port}`, 'high', `Слабый сигнал на ${sp}: приём ${x.rx} дБм, порог ${x.rxLow}`, { port, cmd });
    else if (x.rxLow != null && x.rx < x.rxLow + 2) add(`sfp-rx:${port}`, 'med', `Сигнал на ${sp} близок к порогу: приём ${x.rx} дБм, порог ${x.rxLow}`, { port, cmd });
    else if (x.rxHigh != null && x.rx > x.rxHigh) add(`sfp-rx:${port}`, 'high', `Слишком сильный сигнал на ${sp}: приём ${x.rx} дБм, порог ${x.rxHigh}`, { port, cmd });
    if (x.txLow != null && x.tx != null && x.tx < x.txLow) add(`sfp-tx:${port}`, 'high', `Низкая мощность передатчика на ${sp}: ${x.tx} дБм, порог ${x.txLow}`, { port, cmd });
  }
  return out;
}

function parseHardware(raw, interfaces) {
  const hw = {
    version: parseVersion(raw.version), device: parseDevice(raw.device), stack: parseStack(raw.stack),
    cpu: parseCpu(raw.cpu), memory: parseMemory(raw.memory), temperature: parseTemperature(raw.temperature),
    power: parsePower(raw.power), fan: parseFan(raw.fan), transceiver: parseTransceiver(raw.transceiver),
  };
  hw.problems = problems(hw, interfaces);
  return hw;
}

module.exports = { COMMANDS, parseHardware, parseVersion, parseDevice, parseStack, parseCpu, parseMemory, parseTemperature, parsePower, parseFan, parseTransceiver, problems };
