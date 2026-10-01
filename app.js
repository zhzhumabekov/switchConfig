(() => {
'use strict';

/* =====================================================================
   Справочники
   ===================================================================== */
const ROLES = {
  uplink:  { label: 'Аплинк',                     color: '--r-uplink' },
  link:    { label: 'Связь с другим коммутатором', color: '--r-link' },
  ap:      { label: 'Wi‑Fi (AP / контроллер)',     color: '--r-ap' },
  printer: { label: 'Принтер',                     color: '--r-printer' },
  test:    { label: 'Тестовый',                    color: '--r-test' },
  trunk:   { label: 'Расширенный транк',           color: '--r-trunk' },
  access:  { label: 'Рабочее место (ПК + телефон)', color: '--r-access' },
  empty:   { label: 'Не настроен',                 color: '--r-empty' },
};
const ROLE_ORDER = ['uplink', 'link', 'ap', 'printer', 'test', 'trunk', 'access', 'empty'];
const VLAN_COLORS = ['#4a7fe0', '#1f9e8f', '#8a5cd6', '#e0701f', '#d4508a', '#c99a0e', '#3a9d4a', '#7c8594', '#c83a32'];

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* =====================================================================
   Парсер конфигурации Huawei VRP
   ===================================================================== */
function parseTree(text) {
  // Возвращает список секций (разделённых '#'), каждая — массив узлов {cmd, children, lines}
  const sections = [];
  let cur = [];
  const stack = [];
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.replace(/\s+$/, '');
    if (line.trim() === '#') { if (cur.length) sections.push(cur); cur = []; stack.length = 0; continue; }
    if (!line.trim()) continue;
    const depth = line.match(/^ */)[0].length;
    const node = { cmd: line.trim(), depth, children: [] };
    while (stack.length && stack[stack.length - 1].depth >= depth) stack.pop();
    if (stack.length) stack[stack.length - 1].children.push(node);
    else cur.push(node);
    stack.push(node);
  }
  if (cur.length) sections.push(cur);
  return sections;
}

function nodeText(n, indent = '') {
  return [indent + n.cmd, ...n.children.map(c => nodeText(c, indent + ' '))].join('\n');
}

// "20 25 to 26 50 to 52 200" → [{from:20,to:20},{from:25,to:26},...]
function parseVlanList(s) {
  const tok = s.trim().split(/\s+/);
  const out = [];
  for (let i = 0; i < tok.length; i++) {
    const a = +tok[i];
    if (Number.isNaN(a)) continue;
    if (tok[i + 1] === 'to') { out.push({ from: a, to: +tok[i + 2] }); i += 2; }
    else out.push({ from: a, to: a });
  }
  return out;
}
const inRanges = (ranges, v) => ranges.some(r => v >= r.from && v <= r.to);
const rangesText = ranges => ranges.map(r => r.from === r.to ? `${r.from}` : `${r.from}–${r.to}`);
const rangesSize = ranges => ranges.reduce((a, r) => a + r.to - r.from + 1, 0);

function ipToInt(ip) { return ip.split('.').reduce((a, o) => (a * 256) + (+o), 0); }
function maskLen(mask) { return mask.split('.').reduce((a, o) => a + ((+o).toString(2).match(/1/g) || []).length, 0); }
function sameNet(ip, net, mask) { const m = ipToInt(mask); return ((ipToInt(ip) & m) >>> 0) === ((ipToInt(net) & m) >>> 0); }
function netOf(ip, mask) { const n = (ipToInt(ip) & ipToInt(mask)) >>> 0; return [n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255].join('.'); }

function shortName(name) {
  return name.replace(/^XGigabitEthernet/, 'XGE').replace(/^GigabitEthernet/, 'GE').replace(/^MEth/, 'MEth');
}

function classify(p) {
  // Порт без настроек (или только выключен) — не настроен
  if (!p.lines.length || p.lines.every(l => l === 'shutdown')) return 'empty';
  const d = (p.desc || '').toLowerCase();
  if (/uplink|link_to_floor/.test(d)) return 'uplink';
  if (/link_to|downlink|link-to/.test(d)) return 'link';
  if (/connected_to_ap|connected_to_ac|wifi|_ap\b|\bap_/.test(d)) return 'ap';
  if (/printer|принтер/.test(d)) return 'printer';
  if (/test/.test(d)) return 'test';
  const extra = p.allowed.some(r => r.from !== r.to || ![20, 200, p.pvid].includes(r.from));
  if (p.linkType === 'trunk' && extra) return 'trunk';
  return 'access';
}

function parseConfig(text) {
  const sections = parseTree(text);
  const nodes = sections.flat();
  const cfg = {
    text, sections,
    version: '', sysname: '', vlansDeclared: [], vlanNames: {},
    ports: [], vlanifs: [], routes: [], others: [],
    aaa: { schemes: [], domains: [], users: {} },
    radius: [], ntp: { servers: [], flags: [] }, snmp: { lines: [], communities: 0 },
    ssh: { users: {}, flags: [] }, ui: [], log: [], misc: {},
    authProfiles: [], dot1x: [], stpLines: [],
  };

  const vText = text.match(/^!Software Version\s+(.+)$/m);
  cfg.version = vText ? vText[1].trim() : '';

  for (const n of nodes) {
    const c = n.cmd;
    let m;
    if ((m = c.match(/^sysname\s+(.+)/))) cfg.sysname = m[1];
    else if ((m = c.match(/^vlan batch\s+(.+)/))) cfg.vlansDeclared.push(...parseVlanList(m[1]));
    else if ((m = c.match(/^vlan\s+(\d+)$/))) {
      const d = n.children.find(x => x.cmd.startsWith('description '));
      if (d) cfg.vlanNames[+m[1]] = d.cmd.slice(12);
      if (!inRanges(cfg.vlansDeclared, +m[1])) cfg.vlansDeclared.push({ from: +m[1], to: +m[1] });
    }
    else if ((m = c.match(/^interface\s+(\S+)/))) parseInterface(cfg, m[1], n);
    else if ((m = c.match(/^ip route-static\s+(\S+)\s+(\S+)\s+(\S+)(.*)/))) cfg.routes.push({ net: m[1], mask: m[2], nh: m[3], extra: m[4].trim() });
    else if (c === 'aaa') parseAaa(cfg, n);
    else if ((m = c.match(/^radius-server template\s+(\S+)/))) {
      const t = { name: m[1], servers: [], opts: [] };
      for (const ch of n.children) {
        const s = ch.cmd.match(/^radius-server (authentication|accounting)\s+(\S+)\s+(\d+)(?:.*weight\s+(\d+))?/);
        if (s) t.servers.push({ kind: s[1], ip: s[2], port: s[3], weight: s[4] || '' });
        else if (/shared-key/.test(ch.cmd)) t.opts.push('shared-key задан (скрыт)');
        else t.opts.push(ch.cmd.replace(/^radius-server\s+/, ''));
      }
      cfg.radius.push(t);
    }
    else if ((m = c.match(/^ntp-service unicast-server\s+(\S+)/))) cfg.ntp.servers.push(m[1]);
    else if (c.startsWith('ntp-service')) cfg.ntp.flags.push(c.replace(/^ntp-service\s+/, ''));
    else if (c.startsWith('snmp-agent')) {
      if (/community/.test(c)) cfg.snmp.communities++;
      cfg.snmp.lines.push(c);
    }
    else if ((m = c.match(/^ssh user\s+(\S+)(?:\s+(.+))?/))) {
      const u = cfg.ssh.users[m[1]] ||= { name: m[1], auth: '', service: '' };
      const rest = m[2] || '';
      let r;
      if ((r = rest.match(/authentication-type\s+(\S+)/))) u.auth = r[1];
      if ((r = rest.match(/service-type\s+(.+)/))) u.service = r[1];
    }
    else if (/^(sftp|stelnet|telnet|ssh)\b/.test(c)) cfg.ssh.flags.push(c);
    else if ((m = c.match(/^user-interface\s+(.+)/))) cfg.ui.push({ name: m[1], opts: n.children.map(x => x.cmd) });
    else if (c.startsWith('info-center')) cfg.log.push(c);
    else if ((m = c.match(/^clock timezone\s+(\S+)\s+(add|minus)\s+(\S+)/))) cfg.misc.tz = `${m[1]} (UTC${m[2] === 'add' ? '+' : '−'}${m[3].replace(/:00$/, '')})`;
    else if ((m = c.match(/^set save-configuration interval\s+(\d+)/))) cfg.misc.autosave = +m[1];
    else if (c === 'lldp enable') cfg.misc.lldp = true;
    else if ((m = c.match(/^authentication-profile name\s+(\S+)/))) cfg.authProfiles.push({ name: m[1], opts: n.children.map(x => x.cmd) });
    else if ((m = c.match(/^dot1x-access-profile name\s+(\S+)/))) cfg.dot1x.push({ name: m[1], opts: n.children.map(x => x.cmd) });
    else if (/^(undo )?stp\b/.test(c)) cfg.stpLines.push(nodeText(n));
    else cfg.others.push(nodeText(n));
  }

  for (const p of cfg.ports) p.role = classify(p);
  return cfg;
}

function parseInterface(cfg, name, n) {
  const lines = n.children.map(x => x.cmd);
  if (/^Vlanif/.test(name)) {
    const ip = lines.map(l => l.match(/^ip address\s+(\S+)\s+(\S+)(\s+sub)?/)).filter(Boolean);
    cfg.vlanifs.push({
      name, vlan: +name.slice(6), lines,
      ips: ip.map(m => ({ ip: m[1], mask: m[2], sub: !!m[3] })),
      shutdown: lines.includes('shutdown'),
    });
    return;
  }
  const m = name.match(/^(XGigabitEthernet|GigabitEthernet|MEth|Eth-Trunk|NULL)(.*)$/);
  if (!m || !/Ethernet/.test(m[1])) { if (!/^NULL/.test(name)) cfg.others.push(nodeText(n)); return; }
  const [slot, sub, idx] = m[2].split('/').map(Number);
  const p = {
    name, short: shortName(name), type: m[1] === 'XGigabitEthernet' ? 'xge' : 'ge',
    slot, sub, idx, lines,
    desc: '', portDesc: '', linkType: '', pvid: null, allowed: [], untagged: [],
    lbd: false, voiceVlan: null, lldpOff: false, negOff: false, stpEdgeOff: false, shutdown: false,
    stpLines: [], edged: null, stpOff: false, rootProt: false, loopProt: false, bpduFilter: false,
  };
  for (const l of lines) {
    let r;
    if ((r = l.match(/^description\s+(.+)/))) p.desc = r[1];
    else if ((r = l.match(/^port description\s+(.+)/))) p.portDesc = r[1];
    else if ((r = l.match(/^port link-type\s+(\S+)/))) p.linkType = r[1];
    else if ((r = l.match(/^port trunk pvid vlan\s+(\d+)/))) p.pvid = +r[1];
    else if ((r = l.match(/^port default vlan\s+(\d+)/))) p.pvid = +r[1];
    else if ((r = l.match(/^port (?:trunk|hybrid tagged) allow-pass vlan\s+(.+)/))) p.allowed.push(...parseVlanList(r[1]));
    else if ((r = l.match(/^port hybrid tagged vlan\s+(.+)/))) p.allowed.push(...parseVlanList(r[1]));
    else if ((r = l.match(/^port hybrid untagged vlan\s+(.+)/))) p.untagged.push(...parseVlanList(r[1]));
    else if (l === 'loopback-detect enable') p.lbd = true;
    else if ((r = l.match(/voice-vlan vlan\s+(\d+)/))) p.voiceVlan = +r[1];
    else if (l === 'undo lldp enable') p.lldpOff = true;
    else if (l === 'undo negotiation auto') p.negOff = true;
    else if (l === 'stp edged-port disable') { p.stpEdgeOff = true; p.edged = false; }
    else if (l === 'shutdown') p.shutdown = true;
    // Настройки STP порта
    if (/^(undo )?stp\b/.test(l)) {
      p.stpLines.push(l);
      if (l === 'stp edged-port enable') p.edged = true;
      if (l === 'stp disable' || l === 'undo stp enable') p.stpOff = true;
      if (l === 'stp root-protection') p.rootProt = true;
      if (l === 'stp loop-protection') p.loopProt = true;
      if (/^stp bpdu-filter enable/.test(l)) p.bpduFilter = true;
    }
  }
  if (p.linkType === 'access' && p.pvid != null) p.allowed = [{ from: p.pvid, to: p.pvid }];
  p.effPvid = p.pvid ?? (p.lines.length ? 1 : null);
  cfg.ports.push(p);
}

function parseAaa(cfg, n) {
  for (const ch of n.children) {
    let m;
    if ((m = ch.cmd.match(/^(authentication|authorization|accounting)-scheme\s+(\S+)/))) {
      cfg.aaa.schemes.push({ kind: m[1], name: m[2], opts: ch.children.map(x => x.cmd) });
    } else if ((m = ch.cmd.match(/^domain\s+(\S+)/))) {
      cfg.aaa.domains.push({ name: m[1], opts: ch.children.map(x => x.cmd) });
    } else if ((m = ch.cmd.match(/^local-user\s+(\S+)\s+(.+)/))) {
      const u = cfg.aaa.users[m[1]] ||= { name: m[1], level: '', services: [], password: false };
      let r;
      if ((r = m[2].match(/^privilege level\s+(\d+)/))) u.level = +r[1];
      else if ((r = m[2].match(/^service-type\s+(.+)/))) u.services = r[1].split(/\s+/);
      else if (/^password/.test(m[2])) u.password = true;
    }
  }
}

/* =====================================================================
   Утилиты представления
   ===================================================================== */
function portSort(a, b) {
  return (a.type === b.type ? 0 : a.type === 'ge' ? -1 : 1) || a.slot - b.slot || a.sub - b.sub || a.idx - b.idx;
}

// Сжимает список портов в диапазоны: GE0/0/4–6, 0/0/8, XGE0/0/3
function compressPorts(ports) {
  const sorted = [...ports].sort(portSort);
  const groups = [];
  for (const p of sorted) {
    const g = groups[groups.length - 1];
    if (g && g.type === p.type && g.slot === p.slot && g.sub === p.sub && g.to + 1 === p.idx) g.to = p.idx;
    else groups.push({ type: p.type, slot: p.slot, sub: p.sub, from: p.idx, to: p.idx });
  }
  let lastType = null;
  return groups.map(g => {
    const pre = g.type !== lastType ? (g.type === 'xge' ? 'XGE' : 'GE') : '';
    lastType = g.type;
    const base = `${g.slot}/${g.sub}/`;
    return pre + base + g.from + (g.to !== g.from ? `–${g.to}` : '');
  }).join(', ');
}

function vlanChip(v, cfg, extraClass = '') {
  const known = inRanges(cfg.vlansDeclared, v);
  const nm = cfg.vlanNames[v];
  return `<span class="vl ${known ? '' : 'unknown'} ${extraClass}" title="${esc(known ? (nm || 'VLAN ' + v) : 'VLAN не создан на коммутаторе')}">${v}${nm ? ' · ' + esc(nm) : ''}</span>`;
}
function vlanChipsFromRanges(ranges, cfg) {
  return ranges.map(r => r.from === r.to ? vlanChip(r.from, cfg) : `<span class="vl" title="${rangesSize([r])} VLAN">${r.from}–${r.to}</span>`).join('');
}
function roleChip(role) {
  const r = ROLES[role];
  return `<span class="role"><span class="sw ${role === 'empty' ? 'empty' : ''}" style="--c:var(${r.color})"></span>${esc(r.label)}</span>`;
}
function portFlags(p) {
  const f = [];
  if (p.voiceVlan) f.push(`<span class="flag" title="LLDP-MED сообщает телефону Voice VLAN ${p.voiceVlan}">Voice ${p.voiceVlan}</span>`);
  if (p.lbd) f.push(`<span class="flag" title="Обнаружение петель">LBD</span>`);
  if (p.lldpOff) f.push(`<span class="flag warn">LLDP выкл.</span>`);
  if (p.negOff) f.push(`<span class="flag warn" title="undo negotiation auto">Автосогл. выкл.</span>`);
  if (p.stpEdgeOff) f.push(`<span class="flag warn" title="stp edged-port disable">STP edge выкл.</span>`);
  if (p.shutdown) f.push(`<span class="flag warn">shutdown</span>`);
  return f.join('');
}
const portLink = p => `<button class="plink" data-port="${esc(p.name)}">${esc(p.short)}</button>`;
const carries = (p, v) => inRanges(p.allowed, v) || inRanges(p.untagged, v) || p.effPvid === v;
const untaggedIn = (p, v) => p.effPvid === v || inRanges(p.untagged, v);

/* =====================================================================
   Анализ: замечания
   ===================================================================== */
function analyze(cfg) {
  const issues = [];
  const active = cfg.ports.filter(p => p.lines.length);

  // 1. VLAN используются на портах, но не созданы
  const undeclared = new Map();
  for (const p of active) {
    const ranges = [...p.allowed, ...p.untagged];
    if (p.pvid != null) ranges.push({ from: p.pvid, to: p.pvid });
    for (const r of ranges) {
      if (r.to - r.from > 64) continue; // широкие диапазоны (2–4094) не учитываем
      for (let v = r.from; v <= r.to; v++) {
        if (v === 1 || inRanges(cfg.vlansDeclared, v)) continue;
        if (!undeclared.has(v)) undeclared.set(v, new Set());
        undeclared.get(v).add(p);
      }
    }
  }
  if (undeclared.size) {
    issues.push({
      kind: 'vlan-undeclared', data: { vlans: [...undeclared.entries()].sort((a, b) => a[0] - b[0]).map(([v, ps]) => [v, [...ps].map(p => p.name)]) },
      sev: 'med', title: `VLAN разрешены на портах, но не созданы: ${[...undeclared.keys()].sort((a, b) => a - b).join(', ')}`,
      body: 'Трафик этих VLAN через коммутатор не пойдёт, пока VLAN не создан (vlan batch). Либо создайте VLAN, либо уберите его из allow-pass.',
      extra: [...undeclared.entries()].sort((a, b) => a[0] - b[0]).map(([v, ps]) =>
        `<div><span class="vl unknown">${v}</span> <span class="muted">на портах:</span> <span class="mono">${esc(compressPorts([...ps]))}</span></div>`).join(''),
    });
  }

  // 2. Vlanif без VLAN
  for (const vi of cfg.vlanifs) {
    if (vi.vlan !== 1 && !inRanges(cfg.vlansDeclared, vi.vlan) && !vi.shutdown) {
      issues.push({ kind: 'vlanif-novlan', data: { name: vi.name, vlan: vi.vlan, ips: vi.ips.map(i => i.ip) }, sev: 'high', title: `${vi.name} настроен, но VLAN ${vi.vlan} не создан`, body: `Интерфейс ${vi.ips.map(i => i.ip).join(', ')} не поднимется (down), пока нет VLAN ${vi.vlan} и порта, где он проходит.` });
    }
  }

  // 3. Маршруты с недостижимым next-hop
  const connected = cfg.vlanifs.flatMap(v => v.ips.map(i => ({ ...i, ifname: v.name })));
  const badNh = {}, badRoutes = {};
  for (const r of cfg.routes) {
    if (!connected.some(c => sameNet(r.nh, c.ip, c.mask))) { (badNh[r.nh] ||= []).push(`${r.net}/${maskLen(r.mask)}`); (badRoutes[r.nh] ||= []).push(r); }
  }
  for (const [nh, nets] of Object.entries(badNh)) {
    issues.push({ kind: 'route-nh', data: { routes: badRoutes[nh] }, sev: 'high', title: `Next-hop ${nh} не входит ни в одну подключённую подсеть`, body: `Маршруты ${nets.join(', ')} неактивны: на коммутаторе нет Vlanif в сети ${nh}. Скорее всего, это остаток прежней схемы.` });
  }

  // 4. Loopback-detect на аплинках
  const lbdUp = active.filter(p => (p.role === 'uplink' || p.role === 'link') && p.lbd);
  if (lbdUp.length) issues.push({ kind: 'lbd-uplink', sev: 'med', title: 'Loopback-detect включён на аплинке', body: 'На магистральных портах обнаружение петель может заблокировать порт и отрезать этаж. Обычно его включают только на пользовательских портах.', ports: lbdUp });

  // 5. Порт конечного устройства без PVID
  const noPvid = active.filter(p => p.linkType === 'trunk' && p.pvid == null && ['printer', 'test', 'access'].includes(p.role));
  if (noPvid.length) issues.push({ kind: 'no-pvid', sev: 'med', title: 'Порты для устройств без PVID', body: 'Для транка без «port trunk pvid» PVID = 1. Нетегированный трафик принтера или ПК попадёт в VLAN 1, а не в нужный VLAN. Задайте pvid или переведите порт в режим access.', ports: noPvid });

  // 6. Шаблон «port description desktop» на непользовательских портах
  const wrongDesc = active.filter(p => p.portDesc === 'desktop' && !['access'].includes(p.role));
  if (wrongDesc.length) issues.push({ kind: 'desc-desktop', sev: 'info', title: '«port description desktop» на непользовательских портах', body: 'Похоже на массовую настройку по шаблону: описание не соответствует назначению порта.', ports: wrongDesc });

  // 7. Непоследовательный loopback-detect на пользовательских портах
  const acc = active.filter(p => p.role === 'access' && !p.shutdown);
  const accNoLbd = acc.filter(p => !p.lbd);
  if (acc.length && accNoLbd.length && accNoLbd.length < acc.length) issues.push({ kind: 'lbd-missing', sev: 'info', title: `Loopback-detect включён не на всех пользовательских портах (${acc.length - accNoLbd.length} из ${acc.length})`, body: 'На остальных рабочих местах петля (например, кабель, воткнутый в два порта) не будет обнаружена.', ports: accNoLbd, collapse: true });

  // 8. Безопасность
  const con = cfg.ui.find(u => /^con/.test(u.name));
  if (con && con.opts.includes('authentication-mode none')) issues.push({ kind: 'console-noauth', data: { terminalUsers: Object.values(cfg.aaa.users).filter(u => u.services.includes('terminal')).map(u => u.name) }, sev: 'high', title: 'Консольный порт без аутентификации', body: 'user-interface con 0 → authentication-mode none. Любой человек с физическим доступом получает полный доступ к CLI.' });
  const vtyNoTo = cfg.ui.filter(u => u.opts.some(o => o === 'idle-timeout 0 0'));
  if (vtyNoTo.length) issues.push({ kind: 'vty-timeout', data: { lines: vtyNoTo.map(u => u.name) }, sev: 'med', title: 'Сессии VTY никогда не закрываются по бездействию', body: `idle-timeout 0 0 на ${vtyNoTo.map(u => u.name).join(', ')}. Забытая сессия остаётся открытой бесконечно.` });
  const telnetUsers = Object.values(cfg.aaa.users).filter(u => u.services.some(s => ['telnet', 'ftp', 'http'].includes(s)));
  if (telnetUsers.length) issues.push({ kind: 'plain-proto', data: { users: telnetUsers.map(u => ({ name: u.name, services: u.services })) }, sev: 'med', title: 'Разрешены незашифрованные протоколы управления', body: telnetUsers.map(u => `${u.name}: ${u.services.filter(s => ['telnet', 'ftp', 'http'].includes(s)).join(', ')}`).join('; ') + '. Логины и пароли передаются открытым текстом. Лучше оставить только ssh.' });
  if (cfg.snmp.lines.some(l => /sys-info version.*\bv(1|2c)\b/.test(l))) issues.push({ kind: 'snmp-v2', sev: 'med', title: 'SNMP v1/v2c без шифрования', body: `Включены SNMP v1/v2c, v3 отключён. Настроено community: ${cfg.snmp.communities}. Community передаются открытым текстом, стоит ограничить доступ ACL или перейти на v3.` });

  // 9. Созданные, но неиспользуемые VLAN
  const declaredList = [];
  for (const r of cfg.vlansDeclared) for (let v = r.from; v <= r.to && declaredList.length < 500; v++) declaredList.push(v);
  const narrow = active.filter(p => rangesSize(p.allowed) < 64);
  const unused = declaredList.filter(v => !narrow.some(p => carries(p, v)) && !cfg.vlanifs.some(vi => vi.vlan === v));
  if (unused.length) issues.push({ kind: 'vlan-unused', data: { vlans: unused }, sev: 'info', title: `VLAN созданы, но не назначены ни одному порту доступа: ${unused.join(', ')}`, body: 'Эти VLAN проходят только через широкий транк (например, 2–4094) или не используются вовсе.', extra: unused.map(v => vlanChip(v, cfg)).join(' ') });

  // 10. STP по конфигурации
  const sc = stpConfig(cfg);
  if (sc.disabled) issues.push({ kind: 'stp-disabled', sev: 'high', title: 'STP выключен', body: 'Без STP петля в сети (например, кабель, замкнутый между двумя портами или коммутаторами) остановит работу всего сегмента.' });
  else {
    const userPorts = active.filter(p => ['access', 'ap', 'printer', 'test'].includes(p.role) && !p.shutdown && !p.stpOff);
    const noEdge = userPorts.filter(p => !stpEdged(p, sc));
    const edged = active.filter(p => stpEdged(p, sc));
    if (noEdge.length) issues.push({ kind: 'stp-noedge', data: { noBpdu: !sc.bpduProtection }, sev: 'med', title: `Пользовательские порты не настроены как edged (${noEdge.length})`, body: 'Порт без edged после подключения ждёт ~30 с, прежде чем начать передавать трафик, и каждое включение ПК вызывает изменение топологии STP (сброс таблиц MAC на всех коммутаторах).', ports: noEdge, collapse: true });
    if (!sc.bpduProtection && (edged.length || noEdge.length)) {
      const uplinkEdged = edged.filter(p => ['uplink', 'link'].includes(p.role)).map(p => p.short);
      issues.push({ kind: 'stp-nobpdu', data: { uplinkEdged }, sev: 'med', title: 'Нет защиты от чужих коммутаторов (bpdu-protection)', body: 'Если к пользовательскому порту подключат коммутатор, он может стать корнем STP или вызвать перестроение всей сети. stp bpdu-protection отключает edged-порт, на который пришёл BPDU.' });
    }
    const offUp = active.filter(p => p.stpOff && ['uplink', 'link', 'trunk'].includes(p.role));
    if (offUp.length) issues.push({ kind: 'stp-port-off', sev: 'high', title: 'STP выключен на магистральных портах', body: 'На этих портах петля не будет обнаружена.', ports: offUp });
  }

  const order = { high: 0, med: 1, info: 2 };
  return issues.sort((a, b) => order[a.sev] - order[b.sev]);
}

/* ---------- STP: настройки из конфигурации ---------- */
function stpConfig(cfg) {
  const ls = (cfg.stpLines || []).map(x => x.split('\n')[0].trim());
  const has = re => ls.some(l => re.test(l));
  const pr = ls.map(l => l.match(/^stp (?:instance 0 )?priority (\d+)/)).find(Boolean);
  return {
    lines: cfg.stpLines || [],
    mode: (ls.map(l => l.match(/^stp mode (\S+)/)).find(Boolean) || [])[1] || '',
    priority: pr ? +pr[1] : has(/^stp (instance 0 )?root primary/) ? 0 : has(/^stp (instance 0 )?root secondary/) ? 4096 : null,
    bpduProtection: has(/^stp bpdu-protection$/),
    edgedDefault: has(/^stp edged-port default$/),
    disabled: has(/^stp disable$/) || has(/^undo stp enable$/),
  };
}
const stpEdged = (p, sc) => p.edged === true || (sc.edgedDefault && p.edged !== false);

/* =====================================================================
   Рендер
   ===================================================================== */
let CFG = null;
const state = { panelVlan: '', hiddenRoles: new Set(), profile: null, tab: 'overview', current: null };

// Вычисления, которые нужны и для одного коммутатора, и для общего обзора
function prepare(cfg) {
  cfg.issues = analyze(cfg);
  cfg.members = [...new Set(cfg.ports.map(p => p.slot))].sort((a, b) => a - b);
  cfg.usedVlans = collectVlans(cfg);
  return cfg;
}

/* ---------- живое состояние (display interface brief / lldp / mac / arp) ---------- */
const ST_LABEL = { up: 'up', down: 'down', admin: 'shutdown', lbdt: 'петля', standby: 'резерв' };

function groupBy(arr, key) {
  const o = {};
  for (const x of arr || []) (o[x[key]] ||= []).push(x);
  return o;
}

function attachState(cfg, st) {
  cfg.state = st;
  const lldpBy = groupBy(st.lldp, 'port'), macBy = groupBy(st.mac, 'port');
  for (const p of cfg.ports) {
    p.st = st.interfaces[p.name] || null;
    p.lldp = lldpBy[p.name] || [];
    p.macs = macBy[p.name] || [];
  }
  // Замечания по текущему состоянию
  const ports = cfg.ports.filter(p => p.st);
  const loop = ports.filter(p => p.st.status === 'lbdt');
  if (loop.length) cfg.issues.push({ kind: 'loop', sev: 'high', live: true, title: 'Порт заблокирован из-за петли', body: 'Loopback-detect обнаружил петлю и выключил порт (#down). Найдите кабель, который замыкает сеть (например, воткнут в два порта), и уберите его.', ports: loop });
  const upDown = ports.filter(p => ['uplink', 'link'].includes(p.role) && p.st.status !== 'up');
  if (upDown.length) cfg.issues.push({ kind: 'uplink-down', sev: 'high', live: true, title: 'Магистральный порт не работает', body: 'Порт аплинка или связи с другим коммутатором сейчас не в состоянии up.', ports: upDown });
  const errs = ports.filter(p => p.st.inErr + p.st.outErr > 0);
  const stp = st.stp;
  if (stp && stp.bridge) {
    const sc = stpConfig(cfg);
    const hasUplink = cfg.ports.some(p => p.role === 'uplink');
    if (stp.isRoot && hasUplink) cfg.issues.push({ kind: 'stp-root-self', sev: sc.priority != null ? 'info' : 'high', live: true,
      title: 'Этот коммутатор — корневой мост STP', body: sc.priority != null ? `Приоритет задан вручную (${sc.priority}). Если это не ядро сети — проверьте, что так задумано.` : 'У коммутатора есть аплинк, значит это не ядро. Корнем стал из-за приоритета по умолчанию (32768) — путь трафика может быть неоптимальным, а перестроения затронут всю сеть.' });
    const rp = stp.rootPort && cfg.ports.find(p => p.name === stp.rootPort);
    if (rp && ['access', 'ap', 'printer', 'test'].includes(rp.role)) cfg.issues.push({ kind: 'stp-rootport-user', sev: 'high', live: true,
      title: `Корневой порт STP — пользовательский порт ${rp.short}`, body: 'Путь к корневому мосту идёт через пользовательский порт. Похоже, к нему подключён коммутатор, который стал корнем или лучшим путём к нему.', ports: [rp] });
    const bpduDown = Object.entries(stp.ports).filter(([, x]) => x.protection === 'BPDU').map(([n]) => cfg.ports.find(p => p.name === n)).filter(Boolean);
    if (bpduDown.length) cfg.issues.push({ kind: 'stp-bpdu-down', sev: 'high', live: true, title: 'Порты отключены защитой BPDU', body: 'На эти пользовательские порты пришёл BPDU — к ним подключили коммутатор. Порт выключен защитой.', ports: bpduDown });
    const up = st.hw && st.hw.version && st.hw.version.uptimeSec;
    const perDay = up ? stp.tcCount / Math.max(1, up / 86400) : null;
    if (stp.lastTcSec != null && (stp.lastTcSec < 900 || (perDay != null && perDay > 20))) {
      const tp = stp.lastTcPort && cfg.ports.find(p => p.name === stp.lastTcPort);
      cfg.issues.push({ kind: 'stp-tc', data: { port: stp.lastTcPort }, sev: perDay != null && perDay > 20 ? 'med' : 'info', live: true,
        title: perDay != null && perDay > 20 ? `Частые изменения топологии STP: ~${Math.round(perDay)} в сутки` : `Недавнее изменение топологии STP (${Math.round(stp.lastTcSec / 60)} мин назад)`,
        body: `Всего изменений: ${stp.tcCount}. Последнее пришло через ${tp ? tp.short + (tp.desc ? ' (' + tp.desc + ')' : '') : (stp.lastTcPort || '—')}.`, ports: tp ? [tp] : undefined });
    }
  }
  for (const pr of (st.hw && st.hw.problems) || []) {
    const port = pr.port && cfg.ports.find(x => x.name === pr.port);
    cfg.issues.push({ kind: 'hw', data: { key: pr.key, cmd: pr.cmd }, sev: pr.sev, live: true, title: pr.text,
      body: 'Обнаружено по данным оборудования (display device / power / fan / temperature / transceiver).', ports: port ? [port] : undefined });
  }
  if (errs.length) cfg.issues.push({ kind: 'port-errors', sev: 'med', live: true, title: 'Ошибки на портах', body: 'Счётчики inErrors/outErrors не нулевые: возможна плохая линия, кабель или несогласованная скорость/дуплекс.', ports: errs });
  const order = { high: 0, med: 1, info: 2 };
  cfg.issues.sort((a, b) => order[a.sev] - order[b.sev]);
  return cfg;
}

function stClass(p) {
  if (!p.st) return '';
  return ` st-${p.st.status}${p.st.inErr + p.st.outErr > 0 ? ' st-err' : ''}`;
}
function liveBadge(p) {
  if (!p.st) return '<span class="muted">—</span>';
  const errs = p.st.inErr + p.st.outErr;
  return `<span class="live live-${p.st.status}">${ST_LABEL[p.st.status] || esc(p.st.phy)}</span>${errs ? ` <span class="flag warn" title="inErrors ${p.st.inErr}, outErrors ${p.st.outErr}">ошибки</span>` : ''}`;
}

// Источники живых данных: все коммутаторы (сервер) или текущий конфиг
function liveSources() {
  if (SERVER) return SWITCHES.filter(s => s.cfg && s.cfg.state).map(s => ({ sw: s, cfg: s.cfg }));
  return CFG && CFG.state ? [{ sw: null, cfg: CFG }] : [];
}
function ipsForMac(mac) {
  const ips = new Set();
  const lease = DIR && DIR.byMac.get(mac);
  if (lease) ips.add(lease.ip);
  for (const { cfg } of liveSources()) for (const a of cfg.state.arp) if (a.mac === mac) ips.add(a.ip);
  return [...ips];
}

/* ---------- AD / DHCP / DNS ---------- */
let DIR = null; // { at, byMac, byIp, adByName, dns, errors }

function buildDirectory(d) {
  if (!d || !d.at) return null;
  const byMac = new Map(), byIp = new Map(), adByName = new Map();
  // Активная аренда важнее резервирования без аренды
  const rank = l => (l.state === 'ReservationOnly' ? 1 : 0);
  for (const l of d.dhcp || []) {
    const cur = byMac.get(l.mac);
    if (!cur || rank(l) < rank(cur)) byMac.set(l.mac, l);
    byIp.set(l.ip, l);
  }
  for (const c of d.ad || []) adByName.set(c.name.toUpperCase(), c);
  return { at: d.at, byMac, byIp, adByName, dns: d.dns || {}, errors: d.errors || {}, counts: { dhcp: (d.dhcp || []).length, ad: (d.ad || []).length } };
}

const shortHost = h => String(h || '').split('.')[0];
function ouPath(dn) {
  return String(dn || '').split(',').filter(x => /^OU=/i.test(x)).map(x => x.slice(3)).reverse().join(' / ');
}

// Всё, что известно об устройстве по MAC
function deviceInfo(mac) {
  const lease = DIR && DIR.byMac.get(mac);
  const ips = ipsForMac(mac);
  let name = lease ? shortHost(lease.host) : '';
  let source = lease ? (lease.reserved ? 'dhcp-res' : 'dhcp') : '';
  if (!name && DIR) {
    const ip = ips.find(i => DIR.dns[i]);
    if (ip) { name = shortHost(DIR.dns[ip]); source = 'dns'; }
  }
  const ad = name && DIR ? DIR.adByName.get(name.toUpperCase()) : null;
  const phone = PHONES ? PHONES.get(mac) : null;
  if (phone && phone.ip && !ips.includes(phone.ip)) ips.push(phone.ip);
  return {
    mac, ips, name, source, lease, ad, phone,
    os: ad ? ad.os : '', ou: ad ? ouPath(ad.dn) : '', description: (ad && ad.description) || (lease && lease.description) || '',
    known: !!(lease || ad || phone || source === 'dns'),
  };
}

function phoneLabel(ph) {
  const t = [ph.model && 'CP-' + ph.model.replace(/^CP-/i, ''), ph.description, ph.status !== 'registered' ? 'не зарегистрирован' : ''].filter(Boolean).join(' · ');
  return `<span class="dev" title="${esc(t)}">☎ <b>${esc(ph.numbers.join(', ') || '—')}</b>${ph.names[0] ? ' ' + esc(ph.names[0]) : ''}</span>${ph.status !== 'registered' ? ' <span class="flag warn">не зарег.</span>' : ''}`;
}

function deviceLabel(d, withIp = true) {
  if (d.phone && !d.name) return phoneLabel(d.phone) + (withIp && d.ips.length ? ` <span class="mono muted">${esc(d.ips[0])}</span>` : '');
  if (!d.name) return withIp && d.ips.length ? `<span class="mono">${esc(d.ips.join(', '))}</span>` : '';
  const title = [d.os, d.ou, d.description].filter(Boolean).join(' · ');
  const off = d.ad && !d.ad.enabled ? ' <span class="flag warn" title="Учётная запись компьютера отключена в AD">откл. в AD</span>' : '';
  return `<span class="dev" title="${esc(title)}">🖥 <b>${esc(d.name)}</b></span>${withIp && d.ips.length ? ` <span class="mono muted">${esc(d.ips[0])}</span>` : ''}${off}`;
}

function connectedText(p) {
  if (p.lldp && p.lldp.length) return p.lldp.map(n => `🔗 ${esc(n.device || '?')}${n.remotePort ? ` <span class="muted">(${esc(n.remotePort)})</span>` : ''}`).join('<br>');
  if (p.macs && p.macs.length) {
    if (p.macs.length <= 3) {
      const parts = p.macs.map(m => deviceInfo(m.mac)).map(d => deviceLabel(d) || `<span class="mono muted" title="Нет в DHCP / AD / DNS">${esc(d.mac)}</span>`);
      return parts.join('<br>');
    }
    return `${p.macs.length} MAC`;
  }
  return p.st && p.st.status === 'up' ? '<span class="muted">нет MAC</span>' : '<span class="muted">—</span>';
}

// Порт «конечный»: к нему подключено устройство, а не другой коммутатор
function isEdgePort(p) {
  return p && !['uplink', 'link'].includes(p.role) && !(p.lldp.length > 0 && p.macs.length > 3) && p.macs.length <= 20;
}

// MAC на конечных портах, о которых ничего нет в DHCP / AD / DNS
function unknownDevices(sources) {
  const out = [];
  for (const { sw, cfg } of sources) {
    for (const p of cfg.ports) {
      if (!p.macs || !isEdgePort(p)) continue;
      for (const m of p.macs) {
        const d = deviceInfo(m.mac);
        if (!d.known) out.push({ sw, cfg, p, m, d });
        else if (d.ad && !d.ad.enabled) out.push({ sw, cfg, p, m, d, disabled: true });
      }
    }
  }
  return out;
}

function unknownHtml(list, withSwitch) {
  if (!DIR) return '<p class="hint" style="margin:0">Подключите AD / DHCP / DNS в <a href="settings.html">настройках</a>, чтобы видеть неизвестные устройства.</p>';
  if (!list.length) return '<p class="muted" style="margin:0">Все устройства на портах известны DHCP, AD или DNS.</p>';
  return `<div class="table-scroll"><table class="tbl"><thead><tr>${withSwitch ? '<th>Коммутатор</th>' : ''}<th>Порт</th><th>MAC</th><th>VLAN</th><th>IP (ARP)</th><th>Причина</th></tr></thead><tbody>
    ${list.slice(0, 300).map(u => `<tr data-goto-sw="${esc(u.sw ? u.sw.id : '')}" data-goto-port="${esc(u.p.name)}">
      ${withSwitch ? `<td><b>${esc(u.sw ? u.sw.name : '')}</b></td>` : ''}
      <td class="mono">${esc(u.p.short)}${u.p.desc ? ` <span class="muted">${esc(u.p.desc)}</span>` : ''}</td>
      <td class="mono">${esc(u.m.mac)}</td>
      <td>${u.m.vlan != null ? vlanChip(u.m.vlan, u.cfg || CFG || { vlansDeclared: [], vlanNames: {} }) : '—'}</td>
      <td class="mono">${esc(u.d.ips.join(', ')) || '<span class="muted">—</span>'}</td>
      <td>${u.disabled ? `<span class="flag warn">${esc(u.d.name)} отключён в AD</span>` : '<span class="flag warn">нет в DHCP / AD / DNS</span>'}</td>
    </tr>`).join('')}
  </tbody></table></div>${list.length > 300 ? `<div class="foot">Показано 300 из ${list.length}</div>` : ''}`;
}

function render(cfg, sw = null) {
  CFG = cfg;
  $('#tab-cme').hidden = true;
  $('#eyebrow').textContent = 'Huawei · стек коммутаторов';
  if (!cfg.issues) prepare(cfg);
  $('#tab-all').hidden = true;
  $('#tabs').hidden = false;

  $('#sysname').textContent = sw ? sw.name : (cfg.sysname || 'Без имени');
  document.title = `${sw ? sw.name : cfg.sysname || 'Коммутатор'} — конфигурация`;
  $('#meta').innerHTML = [
    sw && sw.sysname && sw.sysname !== sw.name && `<b>${esc(sw.sysname)}</b>`,
    sw && `IP <b>${esc(sw.host)}</b>`,
    sw && sw.lastFetch && `Обновлено <b>${esc(ago(sw.lastFetch))}</b>`,
    sw && sw.lastError && `<span style="color:var(--sev-high)">Последнее обновление не удалось: ${esc(sw.lastError.message)}</span>`,
    cfg.version && `ПО <b>${esc(cfg.version)}</b>`,
    `Стек: <b>${cfg.members.length}</b> ${plural(cfg.members.length, 'член', 'члена', 'членов')}`,
    cfg.misc.tz && `Часовой пояс <b>${esc(cfg.misc.tz)}</b>`,
    cfg.misc.autosave && `Автосохранение <b>каждые ${cfg.misc.autosave / 1440 >= 1 && cfg.misc.autosave % 1440 === 0 ? cfg.misc.autosave / 1440 + ' дн.' : cfg.misc.autosave + ' мин'}</b>`,
  ].filter(Boolean).map(s => `<span>${s}</span>`).join('');

  const n = cfg.issues.filter(i => i.sev !== 'info').length;
  $('#issuesCount').textContent = n || '';

  renderStats(cfg);
  renderLegend();
  renderPanel(cfg);
  renderKeyLinks(cfg);
  renderUnknown(cfg, sw);
  renderMgmt(cfg);
  renderProfiles(cfg);
  fillPortFilters(cfg);
  renderPortTable();
  renderVlans(cfg);
  renderL3(cfg);
  renderServices(cfg);
  renderIssues(cfg);
  renderRaw(cfg);
  renderHistory(sw);
  renderStandard(cfg, sw);
  renderHardware(cfg, sw);
  renderStp(cfg, sw);
  showTab(state.tab === 'all' || (['history', 'standard'].includes(state.tab) && !sw) || (state.tab === 'hw' && $('#hwTabBtn').hidden) ? 'overview' : state.tab);
}

function ago(iso) {
  if (!iso) return '';
  const d = new Date(iso), s = (Date.now() - d) / 1000;
  if (s < 60) return 'только что';
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
  return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}

function collectVlans(cfg) {
  const s = new Set();
  for (const r of cfg.vlansDeclared) for (let v = r.from; v <= r.to; v++) s.add(v);
  for (const p of cfg.ports) {
    if (p.pvid != null) s.add(p.pvid);
    for (const r of p.allowed) if (r.to - r.from <= 64) for (let v = r.from; v <= r.to; v++) s.add(v);
  }
  for (const vi of cfg.vlanifs) if (vi.vlan !== 1) s.add(vi.vlan);
  return [...s].sort((a, b) => a - b);
}

function renderStats(cfg) {
  const byRole = r => cfg.ports.filter(p => p.role === r).length;
  const ge = cfg.ports.filter(p => p.type === 'ge').length, xge = cfg.ports.filter(p => p.type === 'xge').length;
  const cfgd = cfg.ports.filter(p => p.lines.length).length;
  const items = [
    { v: cfg.ports.length, l: 'Физических портов', s: `${ge} × 1G, ${xge} × 10G` },
    { v: cfgd, l: 'Настроено', s: `${cfg.ports.length - cfgd} без настроек` },
    cfg.state && { v: cfg.ports.filter(p => p.st && p.st.status === 'up').length, l: 'Подключено сейчас (up)', s: `данные ${ago(cfg.state.at)}` },
    { v: byRole('access'), l: 'Рабочих мест', s: 'ПК + IP-телефон' },
    { v: byRole('ap'), l: 'Wi‑Fi (AP / AC)', s: '' },
    { v: byRole('uplink') + byRole('link'), l: 'Магистральных линков', s: `${byRole('trunk')} расширенных транков` },
    { v: rangesSize(cfg.vlansDeclared), l: 'VLAN создано', s: `${cfg.vlanifs.filter(v => !v.shutdown).length} L3-интерфейса` },
    { v: cfg.issues.length, l: 'Замечаний', s: `${cfg.issues.filter(i => i.sev === 'high').length} важных` },
  ].filter(Boolean);
  $('#stats').innerHTML = items.map(i => `<div class="stat"><div class="v">${i.v}</div><div class="l">${i.l}</div>${i.s ? `<div class="s">${i.s}</div>` : ''}</div>`).join('');
}

function renderLegend() {
  const counts = {};
  for (const p of CFG.ports) counts[p.role] = (counts[p.role] || 0) + 1;
  $('#legend').innerHTML = ROLE_ORDER.filter(r => counts[r]).map(r =>
    `<span class="legend-item ${state.hiddenRoles.has(r) ? 'off' : ''}" data-role="${r}" title="Нажмите, чтобы скрыть или показать">
      <span class="sw ${r === 'empty' ? 'empty' : ''}" style="--c:var(${ROLES[r].color})"></span>${ROLES[r].label} <b>${counts[r]}</b></span>`).join('') + liveLegend(CFG);
}

function liveLegend(cfg) {
  if (!cfg.state) return '';
  const n = f => cfg.ports.filter(p => p.st && f(p.st)).length;
  const items = [
    ['up', 'up', n(s => s.status === 'up')],
    ['down', 'down', n(s => s.status === 'down')],
    ['admin', 'shutdown', n(s => s.status === 'admin')],
    ['lbdt', 'петля', n(s => s.status === 'lbdt')],
    ['err', 'ошибки', n(s => s.inErr + s.outErr > 0)],
  ].filter(([k, , c]) => c || k === 'up' || k === 'down');
  return `<span class="legend-sep"></span><span class="legend-st">Сейчас (${esc(ago(cfg.state.at))}):</span>` +
    items.map(([k, label, c]) => `<span class="legend-st"><span class="led led-${k}"></span>${label} <b>${c}</b></span>`).join('');
}

function renderPanel(cfg) {
  const sel = $('#panelVlan');
  sel.innerHTML = '<option value="">— все —</option>' + cfg.usedVlans.map(v => `<option value="${v}">${v}${cfg.vlanNames[v] ? ' · ' + esc(cfg.vlanNames[v]) : ''}</option>`).join('');
  sel.value = state.panelVlan;
  $('#panel').innerHTML = panelHtml(cfg, false);
}

function panelHtml(cfg, mini) {
  return cfg.members.map(slot => {
    const ge = cfg.ports.filter(p => p.slot === slot && p.type === 'ge').sort(portSort);
    const xge = cfg.ports.filter(p => p.slot === slot && p.type === 'xge').sort(portSort);
    // банки по 12 портов, нечётные сверху, чётные снизу
    const banks = [];
    for (let i = 0; i < ge.length; i += 12) banks.push(ge.slice(i, i + 12));
    const bankHtml = ports => {
      const top = ports.filter(p => p.idx % 2 === 1), bot = ports.filter(p => p.idx % 2 === 0);
      const cells = [];
      for (let i = 0; i < Math.max(top.length, bot.length); i++) { cells.push(top[i]); cells.push(bot[i]); }
      return cells.map(p => p ? portCell(p, mini) : '<span></span>').join('');
    };
    return `<div class="member">
      <div class="member-label"><b>Slot ${slot}</b>${mini ? '' : `${ge.length}×GE<br>${xge.length}×10GE`}</div>
      <div class="chassis">
        ${banks.map(b => `<div class="bank">${bankHtml(b)}</div>`).join('')}
        ${xge.length ? `<div class="bank sfp">${bankHtml(xge)}</div>` : ''}
      </div></div>`;
  }).join('');
}

function portCell(p, mini) {
  const v = !mini && state.panelVlan ? +state.panelVlan : null;
  let cls = `port ${p.type} ${p.role === 'empty' ? 'empty' : ''} ${p.desc ? 'has-desc' : ''}${stClass(p)}`;
  if (!mini && state.hiddenRoles.has(p.role)) cls += ' dim';
  else if (v != null) {
    if (!carries(p, v)) cls += ' dim';
    else if (!untaggedIn(p, v)) cls += ' tagged';
  }
  return `<div class="${cls}" style="--c:var(${ROLES[p.role].color})" data-port="${esc(p.name)}">${p.idx}</div>`;
}

function renderKeyLinks(cfg) {
  const key = cfg.ports.filter(p => ['uplink', 'link', 'ap', 'printer', 'test'].includes(p.role) || (p.desc && p.role !== 'access')).sort((a, b) => ROLE_ORDER.indexOf(a.role) - ROLE_ORDER.indexOf(b.role) || portSort(a, b));
  const named = cfg.ports.filter(p => p.role === 'access' && p.desc);
  $('#keyLinks').innerHTML = `<ul class="list">${[...key, ...named].map(p => `
    <li>${portLink(p)}${cfg.state ? liveBadge(p) : ''}<span class="grow">${esc(p.desc || '—')}${p.lldp && p.lldp.length ? `<div class="muted" style="font-size:12px">${connectedText(p)}</div>` : ''}</span>${roleChip(p.role)}</li>`).join('')}</ul>`;
}

function renderUnknown(cfg, sw) {
  const card = $('#unknownCard');
  card.hidden = !cfg.state;
  if (!cfg.state) return;
  const list = unknownDevices([{ sw, cfg }]);
  $('#unknownCount').textContent = DIR ? list.length : '';
  $('#unknownList').innerHTML = unknownHtml(list, false);
}

function renderMgmt(cfg) {
  const vi = cfg.vlanifs.filter(v => !v.shutdown && v.ips.length);
  const users = Object.values(cfg.aaa.users);
  $('#mgmtSummary').innerHTML = `<dl class="kv">
    <dt>IP-адреса</dt><dd>${vi.map(v => `<div><code>${esc(v.ips[0].ip)}/${maskLen(v.ips[0].mask)}</code> <span class="muted">${esc(v.name)}${cfg.vlanNames[v.vlan] ? ' · ' + esc(cfg.vlanNames[v.vlan]) : ''}</span></div>`).join('') || '—'}</dd>
    <dt>Доступ</dt><dd>${[cfg.ssh.flags.some(f => /stelnet server enable/.test(f)) && 'SSH', cfg.ssh.flags.some(f => /sftp server enable/.test(f)) && 'SFTP', cfg.ui.some(u => /vty/.test(u.name)) && 'VTY (AAA)'].filter(Boolean).join(', ') || '—'}</dd>
    <dt>Локальные учётки</dt><dd>${users.map(u => `<code>${esc(u.name)}</code> <span class="muted">ур. ${u.level}</span>`).join(', ') || '—'}</dd>
    <dt>RADIUS</dt><dd>${cfg.radius.flatMap(t => t.servers.map(s => `<code>${esc(s.ip)}</code>`)).join(', ') || '—'}</dd>
    <dt>NTP</dt><dd>${cfg.ntp.servers.map(s => `<code>${esc(s)}</code>`).join(', ') || '—'}</dd>
    <dt>Syslog</dt><dd>${cfg.log.map(l => l.match(/loghost\s+(\S+)/)).filter(Boolean).map(m => `<code>${esc(m[1])}</code>`).join(', ') || '—'}</dd>
    <dt>Мониторинг</dt><dd>SNMP ${esc((cfg.snmp.lines.find(l => /sys-info version/.test(l)) || '').replace(/.*version\s+/, '') || '—')}${cfg.snmp.lines.find(l => /location/.test(l)) ? ' · location ' + esc(cfg.snmp.lines.find(l => /location/.test(l)).replace(/.*location\s+/, '')) : ''}</dd>
  </dl>`;
}

/* ---------- профили ---------- */
function profileKey(p) {
  if (!p.lines.length) return 'empty';
  return JSON.stringify([p.role, p.linkType, p.effPvid, rangesText(p.allowed).join(','), p.lbd, p.voiceVlan, p.lldpOff, p.negOff, p.stpEdgeOff]);
}
function renderProfiles(cfg) {
  const map = new Map();
  for (const p of cfg.ports) {
    const k = profileKey(p);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(p);
  }
  cfg.profiles = [...map.entries()].map(([k, ports]) => ({ key: k, ports, sample: ports[0] }))
    .sort((a, b) => b.ports.length - a.ports.length);
  const cards = cfg.profiles.map((g, i) => {
    const p = g.sample;
    const body = p.role === 'empty'
      ? '<span class="muted">без конфигурации</span>'
      : `${roleChip(p.role)} <span class="muted">${esc(p.linkType || '—')}</span> · PVID <b>${p.effPvid}${p.pvid == null ? ' <span class="muted">(по умолч.)</span>' : ''}</b> · ${vlanChipsFromRanges(p.allowed, cfg)} ${portFlags(p)}`;
    return `<div class="profile ${state.profile === i ? 'active' : ''}" data-profile="${i}">
      <div class="n">${g.ports.length}<small>${plural(g.ports.length, 'порт', 'порта', 'портов')}</small></div>
      <div class="h">${body}</div>
      <div class="r">${esc(compressPorts(g.ports))}</div>
    </div>`;
  });
  const multi = cfg.profiles.filter(g => g.ports.length > 1).length;
  const singles = cards.slice(multi);
  const openSingles = state.profile != null && state.profile >= multi;
  $('#profiles').innerHTML = cards.slice(0, multi).join('') + (singles.length
    ? `<details class="singles" ${openSingles ? 'open' : ''}><summary>Уникальные настройки: ещё ${singles.length} ${plural(singles.length, 'порт', 'порта', 'портов')}</summary>${singles.join('')}</details>`
    : '');
}

/* ---------- таблица портов ---------- */
function fillPortFilters(cfg) {
  const keep = ['#portMember', '#portRole', '#portVlan', '#portLive'].map(id => [id, $(id).value]);
  fillPortFilterOptions(cfg);
  for (const [id, v] of keep) if ([...$(id).options].some(o => o.value === v)) $(id).value = v;
}

function fillPortFilterOptions(cfg) {
  $('#portMember').innerHTML = '<option value="">Все члены стека</option>' + cfg.members.map(s => `<option value="${s}">Slot ${s}</option>`).join('');
  $('#portRole').innerHTML = '<option value="">Все роли</option>' + ROLE_ORDER.filter(r => cfg.ports.some(p => p.role === r)).map(r => `<option value="${r}">${ROLES[r].label}</option>`).join('');
  $('#portVlan').innerHTML = '<option value="">Любой VLAN</option>' + cfg.usedVlans.map(v => `<option value="${v}">${v}${cfg.vlanNames[v] ? ' · ' + esc(cfg.vlanNames[v]) : ''}</option>`).join('');
  $('#portLive').hidden = !cfg.state;
  $('#portLive').value = '';
  $('#portTable').classList.toggle('no-live', !cfg.state);
}

const LIVE_FILTERS = {
  up: p => p.st && p.st.status === 'up',
  down: p => p.st && p.st.status !== 'up',
  lbdt: p => p.st && p.st.status === 'lbdt',
  err: p => p.st && p.st.inErr + p.st.outErr > 0,
  lldp: p => p.lldp && p.lldp.length > 0,
};

function filteredPorts() {
  const q = $('#portSearch').value.trim().toLowerCase();
  const mem = $('#portMember').value, role = $('#portRole').value, vlan = $('#portVlan').value;
  const hideEmpty = $('#portHideEmpty').checked;
  const live = CFG.state ? $('#portLive').value : '';
  const prof = state.profile != null ? new Set(CFG.profiles[state.profile].ports) : null;
  return CFG.ports.filter(p => {
    if (prof && !prof.has(p)) return false;
    if (hideEmpty && !p.lines.length && !prof) return false;
    if (mem !== '' && p.slot !== +mem) return false;
    if (role && p.role !== role) return false;
    if (vlan && !carries(p, +vlan)) return false;
    if (live && !LIVE_FILTERS[live](p)) return false;
    if (q) {
      const hay = [p.name, p.short, p.desc, p.portDesc, ROLES[p.role].label, rangesText(p.allowed).join(' '), p.lines.join(' '),
        ...(p.lldp || []).map(n => n.device), ...(p.macs || []).flatMap(m => [m.mac, m.mac.replace(/-/g, ''), ...ipsForMac(m.mac)])].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort(portSort);
}

function renderPortTable() {
  const rows = filteredPorts();
  $('#portTable tbody').innerHTML = rows.map(p => `<tr data-port="${esc(p.name)}">
    <td><span class="mono"><b>${esc(p.short)}</b></span></td>
    <td class="live-col">${liveBadge(p)}</td>
    <td>${roleChip(p.role)}</td>
    <td>${p.desc ? esc(p.desc) : '<span class="muted">—</span>'}${p.portDesc && p.portDesc !== p.desc ? ` <span class="muted" title="port description">(${esc(p.portDesc)})</span>` : ''}</td>
    <td class="live-col">${connectedText(p)}</td>
    <td>${p.effPvid != null ? vlanChip(p.effPvid, CFG) + (p.pvid == null ? ' <span class="muted" title="PVID не задан явно">по умолч.</span>' : '') : '<span class="muted">—</span>'}</td>
    <td>${p.allowed.length ? vlanChipsFromRanges(p.allowed, CFG) : '<span class="muted">—</span>'}</td>
    <td>${portFlags(p) || '<span class="muted">—</span>'}</td>
  </tr>`).join('') || `<tr><td colspan="8" class="muted">Нет портов, подходящих под фильтр</td></tr>`;
  const prof = state.profile != null ? ` · фильтр по профилю <button class="plink" id="clearProfile">сбросить</button>` : '';
  $('#portFoot').innerHTML = `Показано ${rows.length} из ${CFG.ports.length}${prof}`;
}

/* ---------- VLAN ---------- */
function renderVlans(cfg) {
  const narrow = p => rangesSize(p.allowed) < 64;
  $('#vlanGrid').innerHTML = cfg.usedVlans.map((v, i) => {
    const declared = inRanges(cfg.vlansDeclared, v);
    const untag = cfg.ports.filter(p => p.lines.length && untaggedIn(p, v) && p.pvid != null);
    const tag = cfg.ports.filter(p => p.lines.length && carries(p, v) && !untaggedIn(p, v) && narrow(p));
    const wide = cfg.ports.filter(p => p.lines.length && carries(p, v) && !narrow(p));
    const vi = cfg.vlanifs.find(x => x.vlan === v);
    const byRole = {};
    for (const p of untag) byRole[p.role] = (byRole[p.role] || 0) + 1;
    return `<div class="vlan-card ${declared ? '' : 'unknown'}" style="--vc:${declared ? VLAN_COLORS[i % VLAN_COLORS.length] : 'var(--sev-med)'}">
      <div class="top-row"><span class="id">${v}</span><span class="nm">${esc(cfg.vlanNames[v] || (declared ? 'без описания' : ''))}</span>${declared ? '' : '<span class="badge">не создан</span>'}</div>
      ${vi ? `<div class="row"><span class="k">L3:</span> ${vi.ips.map(x => `<code>${esc(x.ip)}/${maskLen(x.mask)}</code>`).join(', ') || '—'} <span class="muted">(${esc(vi.name)}${vi.shutdown ? ', shutdown' : ''})</span></div>` : ''}
      ${v === 200 && cfg.ports.some(p => p.voiceVlan === 200) ? `<div class="row"><span class="k">Voice VLAN через LLDP-MED на</span> ${cfg.ports.filter(p => p.voiceVlan === 200).length} портах</div>` : ''}
      <div class="row"><span class="k">Untagged (PVID):</span> <b>${untag.length}</b> ${Object.entries(byRole).map(([r, n]) => `<span class="muted">· ${ROLES[r].label.toLowerCase()} ${n}</span>`).join(' ')}</div>
      ${untag.length ? `<div class="ports">${esc(compressPorts(untag))}</div>` : ''}
      <div class="row"><span class="k">Tagged:</span> <b>${tag.length}</b></div>
      ${tag.length && tag.length <= 30 ? `<div class="ports">${esc(compressPorts(tag))}</div>` : tag.length ? `<div class="ports muted">${esc(compressPorts(tag))}</div>` : ''}
      ${wide.length ? `<div class="row"><span class="k">Через широкий транк:</span> <span class="mono">${esc(compressPorts(wide))}</span></div>` : ''}
      <button class="btn ghost" data-vlan-show="${v}">Показать на панели</button>
    </div>`;
  }).join('');
}

/* ---------- L3 ---------- */
function renderL3(cfg) {
  $('#l3Table').className = 'tbl static';
  $('#l3Table').innerHTML = `<thead><tr><th>Интерфейс</th><th>VLAN</th><th>IP-адрес</th><th>Сеть</th><th>Статус</th><th>Опции</th></tr></thead><tbody>` +
    cfg.vlanifs.map(v => `<tr>
      <td class="mono"><b>${esc(v.name)}</b></td>
      <td>${v.vlan === 1 ? '<span class="vl">1</span>' : vlanChip(v.vlan, cfg)}</td>
      <td>${v.ips.map(x => `<code>${esc(x.ip)}/${maskLen(x.mask)}</code>`).join('<br>') || '<span class="muted">—</span>'}</td>
      <td>${v.ips.map(x => `<code>${netOf(x.ip, x.mask)}/${maskLen(x.mask)}</code>`).join('<br>') || '<span class="muted">—</span>'}</td>
      <td>${v.shutdown ? '<span class="flag warn">shutdown</span>' : (v.vlan !== 1 && !inRanges(cfg.vlansDeclared, v.vlan) ? '<span class="flag warn">VLAN не создан</span>' : '<span class="flag">включён</span>')}</td>
      <td class="muted">${esc(v.lines.filter(l => !/^ip address|^shutdown/.test(l)).join('; ')) || '—'}</td>
    </tr>`).join('') + '</tbody>';

  const connected = cfg.vlanifs.flatMap(v => v.ips.map(i => ({ ...i, ifname: v.name })));
  $('#routeTable').className = 'tbl static';
  $('#routeTable').innerHTML = `<thead><tr><th>Назначение</th><th>Next-hop</th><th>Через интерфейс</th><th>Статус</th></tr></thead><tbody>` +
    cfg.routes.map(r => {
      const via = connected.find(c => sameNet(r.nh, c.ip, c.mask));
      return `<tr>
        <td><code>${esc(r.net)}/${maskLen(r.mask)}</code></td>
        <td><code>${esc(r.nh)}</code></td>
        <td>${via ? `<span class="mono">${esc(via.ifname)}</span>` : '<span class="muted">нет подключённой сети</span>'}</td>
        <td>${via ? '<span class="flag">активен</span>' : '<span class="flag warn">next-hop недостижим</span>'}</td>
      </tr>`;
    }).join('') + '</tbody>';
}

/* ---------- сервисы ---------- */
function renderServices(cfg) {
  const cards = [];
  const kv = rows => `<dl class="kv">${rows.filter(Boolean).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const codeList = arr => arr.length ? arr.map(x => `<code>${esc(x)}</code>`).join('<br>') : '<span class="muted">—</span>';

  // AAA
  const users = Object.values(cfg.aaa.users);
  cards.push(`<div class="card"><h2>AAA <span class="tag">аутентификация</span></h2>
    <div class="sub">Домены</div>
    <ul class="list">${cfg.aaa.domains.map(d => `<li><code>${esc(d.name)}</code><span class="grow muted">${esc(d.opts.join(' · ') || '—')}</span></li>`).join('')}</ul>
    <div class="sub">Схемы</div>
    <ul class="list">${cfg.aaa.schemes.map(s => `<li><code>${esc(s.name)}</code><span class="muted">${s.kind}</span><span class="grow muted">${esc(s.opts.join(' · ') || 'по умолчанию')}</span></li>`).join('')}</ul>
    <div class="sub">Локальные пользователи</div>
    <table class="tbl static"><thead><tr><th>Логин</th><th>Уровень</th><th>Сервисы</th></tr></thead><tbody>
    ${users.map(u => `<tr><td><code>${esc(u.name)}</code></td><td>${u.level}</td><td>${u.services.map(s => `<span class="flag ${['telnet', 'ftp', 'http', 'x25-pad'].includes(s) ? 'warn' : ''}">${esc(s)}</span>`).join('')}</td></tr>`).join('')}
    </tbody></table></div>`);

  // RADIUS + 802.1X
  cards.push(`<div class="card"><h2>RADIUS и 802.1X</h2>
    ${cfg.radius.map(t => `<div class="sub">Шаблон ${esc(t.name)}</div>
      ${t.servers.length ? `<table class="tbl static"><thead><tr><th>Сервер</th><th>Порт</th><th>Тип</th><th>Вес</th></tr></thead><tbody>
      ${t.servers.map(s => `<tr><td><code>${esc(s.ip)}</code></td><td>${s.port}</td><td>${s.kind}</td><td>${s.weight || '—'}</td></tr>`).join('')}</tbody></table>` : '<div class="muted">серверы не заданы</div>'}
      ${t.opts.length ? `<div class="muted" style="margin-top:6px">${esc(t.opts.join(' · '))}</div>` : ''}`).join('')}
    <div class="sub">Профили аутентификации</div>
    <ul class="list">${cfg.authProfiles.map(a => `<li><code>${esc(a.name)}</code><span class="grow muted">${esc(a.opts.join(' · ') || '—')}</span></li>`).join('')}</ul>
    <div class="sub">Профили 802.1X</div>
    <ul class="list">${cfg.dot1x.map(a => `<li><code>${esc(a.name)}</code><span class="grow muted">${esc(a.opts.join(' · ') || '—')}</span></li>`).join('')}</ul>
    <p class="hint" style="margin-top:10px">Профили описаны, но ни к одному порту не применены (нет authentication-profile на интерфейсах).</p>
  </div>`);

  // Удалённый доступ
  cards.push(`<div class="card"><h2>Удалённый доступ</h2>
    <div class="sub">Сервисы</div>${codeList(cfg.ssh.flags)}
    <div class="sub">SSH-пользователи</div>
    <table class="tbl static"><thead><tr><th>Логин</th><th>Аутентификация</th><th>Сервис</th></tr></thead><tbody>
    ${Object.values(cfg.ssh.users).map(u => `<tr><td><code>${esc(u.name)}</code></td><td>${esc(u.auth || '—')}</td><td>${esc(u.service || '—')}</td></tr>`).join('')}</tbody></table>
    <div class="sub">Линии (user-interface)</div>
    <ul class="list">${cfg.ui.map(u => `<li><code>${esc(u.name)}</code><span class="grow">${u.opts.map(o => `<span class="flag ${/none|idle-timeout 0 0/.test(o) ? 'warn' : ''}">${esc(o)}</span>`).join('') || '<span class="muted">по умолчанию</span>'}</span></li>`).join('')}</ul>
  </div>`);

  // Время
  cards.push(`<div class="card"><h2>Время (NTP)</h2>${kv([
    ['Часовой пояс', esc(cfg.misc.tz || '—')],
    ['NTP-серверы', codeList(cfg.ntp.servers)],
    ['Прочее', codeList(cfg.ntp.flags)],
  ])}</div>`);

  // SNMP
  const snmpVal = re => { const l = cfg.snmp.lines.find(x => re.test(x)); return l ? l.replace(re, '').trim() : ''; };
  cards.push(`<div class="card"><h2>SNMP <span class="tag">мониторинг</span></h2>${kv([
    ['Версии', esc(snmpVal(/^snmp-agent sys-info version/) || '—') + (cfg.snmp.lines.some(l => /undo snmp-agent sys-info version v3/.test(l)) ? ' <span class="flag warn">v3 выкл.</span>' : '')],
    ['Community', `${cfg.snmp.communities} (read, значения скрыты)`],
    ['Location', esc(snmpVal(/^snmp-agent sys-info location/) || '—')],
    ['MIB view', esc(snmpVal(/^snmp-agent mib-view/) || '—')],
    ['Трапы', cfg.snmp.lines.includes('snmp-agent trap enable') ? 'включены' : 'выключены'],
  ])}</div>`);

  // Журналы и прочее
  cards.push(`<div class="card"><h2>Журналы и прочее</h2>${kv([
    ['Syslog', codeList(cfg.log)],
    ['LLDP', cfg.misc.lldp ? 'включён глобально' : '—'],
    ['Автосохранение', cfg.misc.autosave ? `каждые ${cfg.misc.autosave} мин (${(cfg.misc.autosave / 1440).toFixed(0)} дн.)` : '—'],
  ])}
  ${cfg.others.length ? `<div class="sub">Остальные команды</div><pre class="mono" style="margin:0;white-space:pre-wrap;font-size:12px">${esc(cfg.others.join('\n'))}</pre>` : ''}
  </div>`);

  $('#servicesGrid').innerHTML = cards.join('');
}

/* ---------- замечания ---------- */
function renderIssues(cfg) {
  const SEV = { high: 'Важно', med: 'Внимание', info: 'Инфо' };
  $('#issuesList').innerHTML = cfg.issues.map(i => `<div class="issue sev-${i.sev}">
    <div class="ih"><span class="sev">${SEV[i.sev]}</span><span class="it">${esc(i.title)}</span></div>
    <div class="ib">${esc(i.body)}</div>
    ${i.ports ? `<div class="ip">${i.collapse && i.ports.length > 12 ? `<span class="mono muted">${esc(compressPorts(i.ports))}</span>` : i.ports.map(p => `${portLink(p)}${p.desc ? ` <span class="muted">${esc(p.desc)}</span>` : ''}`).join('<span class="muted">·</span>')}</div>` : ''}
    ${i.extra ? `<div class="ip" style="flex-direction:column">${i.extra}</div>` : ''}
    ${fixHtml(i, cfg)}
  </div>`).join('') || '<div class="card">Замечаний нет.</div>';
}

/* ---------- исходник ---------- */
function renderRaw(cfg) {
  const q = $('#rawSearch').value.trim().toLowerCase();
  const html = [];
  for (const sec of cfg.sections) {
    const txt = sec.map(n => nodeText(n)).join('\n');
    if (q && !txt.toLowerCase().includes(q)) continue;
    const first = sec[0].cmd;
    const title = sec.length > 1 && /^vlan \d+$/.test(first) ? `vlan ${sec[0].cmd.slice(5)} … ${sec[sec.length - 1].cmd.slice(5)}` : first;
    const lines = txt.split('\n').length;
    let body = esc(txt);
    if (q) body = body.replace(new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/[&<>"']/g, c => esc(c)), 'gi'), m => `<mark>${m}</mark>`);
    html.push(`<details class="raw-block" ${q ? 'open' : ''}><summary><span>${esc(title)}</span><span class="n">${lines} ${plural(lines, 'строка', 'строки', 'строк')}</span></summary><pre>${body}</pre></details>`);
  }
  $('#rawList').innerHTML = html.join('') || '<div class="muted">Ничего не найдено</div>';
}

/* =====================================================================
   Детали порта (боковая панель)
   ===================================================================== */
function openPort(name) {
  if (!CFG) return;
  const p = CFG.ports.find(x => x.name === name);
  if (!p) return;
  const prof = CFG.profiles.find(g => g.ports.includes(p));
  const same = prof ? prof.ports.filter(x => x !== p) : [];
  const issues = CFG.issues.filter(i => i.ports && i.ports.includes(p));
  $('#drawerTitle').textContent = p.name;
  $('#drawerBody').innerHTML = `
    <dl class="kv">
      <dt>Роль</dt><dd>${roleChip(p.role)}</dd>
      <dt>Член стека</dt><dd>Slot ${p.slot}, порт ${p.idx} (${p.type === 'xge' ? '10G SFP+' : '1G'})</dd>
      <dt>Описание</dt><dd>${esc(p.desc || '—')}</dd>
      ${p.portDesc ? `<dt>port description</dt><dd>${esc(p.portDesc)}</dd>` : ''}
      <dt>Режим</dt><dd>${esc(p.linkType || '—')}</dd>
      <dt>PVID</dt><dd>${p.effPvid != null ? vlanChip(p.effPvid, CFG) + (p.pvid == null ? ' <span class="muted">(не задан, по умолчанию 1)</span>' : '') : '—'}</dd>
      <dt>Разрешённые VLAN</dt><dd>${p.allowed.length ? vlanChipsFromRanges(p.allowed, CFG) : '—'}</dd>
      <dt>Опции</dt><dd>${portFlags(p) || '—'}</dd>
    </dl>
    ${CFG.state ? livePortHtml(p) : ''}
    ${SERVER && state.current && state.current !== 'all' ? portHistoryHtml(state.current, p.name) : ''}
    ${issues.length ? `<div class="sub">Замечания</div>${issues.map(i => `<div class="issue sev-${i.sev}" style="padding:8px 12px"><div class="it">${esc(i.title)}</div></div>`).join('')}` : ''}
    ${portToolHtml(p)}
    <div class="sub">Конфигурация</div>
    <pre>interface ${esc(p.name)}${p.lines.length ? '\n' + esc(p.lines.map(l => ' ' + l).join('\n')) : '\n <span class="muted"># нет настроек</span>'}</pre>
    ${same.length ? `<div class="sub">Такие же настройки ещё у ${same.length} ${plural(same.length, 'порта', 'портов', 'портов')}</div><div class="mono muted" style="font-size:12px">${esc(compressPorts(same))}</div>` : '<div class="sub">Уникальная конфигурация</div>'}
  `;
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#scrim').hidden = false;
  updatePortTool();
}
function livePortHtml(p) {
  const st = p.st;
  const macs = p.macs || [];
  const MAX = 50;
  return `<div class="sub">Сейчас <span class="muted" style="text-transform:none;letter-spacing:0">· данные ${esc(ago(CFG.state.at))}</span></div>
    ${st ? `<dl class="kv">
      <dt>Состояние</dt><dd>${liveBadge(p)} <span class="muted mono">PHY ${esc(st.phy)} / Protocol ${esc(st.proto)}</span></dd>
      <dt>Загрузка</dt><dd>вход ${esc(st.inUti || '—')} · выход ${esc(st.outUti || '—')}</dd>
      <dt>Ошибки</dt><dd>${st.inErr + st.outErr ? `<span style="color:var(--sev-high)">вход ${st.inErr}, выход ${st.outErr}</span>` : 'нет'}</dd>
    </dl>` : '<div class="muted">Порт не найден в выводе display interface brief.</div>'}
    ${p.lldp.length ? `<div class="sub">LLDP-сосед</div><ul class="list">${p.lldp.map(n => `<li><span class="grow"><b>${esc(n.device || '?')}</b></span><span class="muted">порт</span> <span class="mono">${esc(n.remotePort || '—')}</span></li>`).join('')}</ul>` : ''}
    <div class="sub">MAC-адреса на порту (${macs.length})</div>
    ${macs.length ? `<table class="tbl static"><thead><tr><th>MAC</th><th>VLAN</th><th>IP</th>${DIR || (PHONES && PHONES.size) ? '<th>Устройство</th>' : ''}</tr></thead><tbody>
      ${macs.slice(0, MAX).map(m => { const d = deviceInfo(m.mac); return `<tr><td class="mono">${esc(m.mac)}</td><td>${m.vlan ?? '—'}</td><td class="mono">${esc(d.ips.join(', ')) || '<span class="muted">—</span>'}</td>${DIR || (PHONES && PHONES.size) ? `<td>${d.name || d.phone ? deviceLabel(d, false) + (d.os || d.ou ? `<div class="muted" style="font-size:12px">${esc([d.os, d.ou].filter(Boolean).join(' · '))}</div>` : '') + (d.description ? `<div class="muted" style="font-size:12px">${esc(d.description)}</div>` : '') : '<span class="flag warn">неизвестно</span>'}</td>` : ''}</tr>`; }).join('')}
    </tbody></table>${macs.length > MAX ? `<div class="muted" style="margin-top:6px">…и ещё ${macs.length - MAX}. Много MAC — обычно это аплинк или неуправляемый свитч за портом.</div>` : ''}`
    : '<div class="muted">Нет выученных MAC-адресов.</div>'}`;
}

/* ---------- готовые команды (этап 3) ---------- */
function cmdBox(text) {
  return `<div class="cmd-box"><pre class="cmd">${esc(text)}</pre><button class="btn small copy-btn" data-copy>Копировать</button></div>`;
}

function fixHtml(issue, cfg) {
  if (typeof Fixes === 'undefined') return '';
  const vs = Fixes.forIssue(issue, cfg);
  if (!vs || !vs.length) return '';
  return `<details class="fix"><summary>Как исправить</summary>${vs.map(v => `<div class="fix-v">
      <div class="fix-t">${esc(v.title)}</div>
      ${v.note ? `<p class="fix-n">${esc(v.note)}</p>` : ''}
      ${v.warn ? `<p class="fix-w">⚠ ${esc(v.warn)}</p>` : ''}
      ${v.commands ? cmdBox(v.commands) : '<p class="muted">Команды не нужны.</p>'}
    </div>`).join('')}</details>`;
}

let PORT_TOOL = null; // { p, templates }
function portToolHtml(p) {
  if (typeof Fixes === 'undefined' || !CFG.profiles) return '';
  const templates = Fixes.portTemplates(CFG);
  PORT_TOOL = { p, templates };
  return `<div class="sub">Команды для порта</div>
    <div class="port-tool">
      <label class="field">Сделать порт
        <select id="tplSelect"><option value="">— только изменить описание —</option>${templates.map(t => `<option value="${t.id}">${esc(t.label)}</option>`).join('')}</select>
      </label>
      <label class="field">Описание (description)
        <input id="tplDesc" value="${esc(p.desc || '')}" placeholder="например, PC-BUH-012 room-305" maxlength="200">
      </label>
      <div id="tplBasis" class="muted" style="font-size:12px"></div>
      <div id="tplOut"></div>
    </div>`;
}

function updatePortTool() {
  if (!PORT_TOOL || !$('#tplOut')) return;
  const { p, templates } = PORT_TOOL;
  const tpl = templates.find(t => t.id === $('#tplSelect').value) || { special: 'none' };
  const desc = $('#tplDesc').value.trim().replace(/\s+/g, ' ');
  $('#tplBasis').textContent = tpl.basis ? `Шаблон: ${tpl.basis} на этом коммутаторе.` : '';
  const cmds = tpl.special === 'none' ? (desc !== (p.desc || '') ? Fixes.portCommands(p, { special: 'desc' }, desc) : '') : Fixes.portCommands(p, tpl, desc);
  const nonAscii = /[^\x20-\x7e]/.test(desc) ? '<p class="fix-w">⚠ В описании есть символы не латиницей — многие коммутаторы Huawei их не принимают или показывают неверно. Лучше использовать латиницу.</p>' : '';
  $('#tplOut').innerHTML = cmds
    ? cmdBox(cmds) + nonAscii + '<p class="fix-n">Команды только показываются — выполните их на коммутаторе сами, проверьте результат и сохраните командой <code>save</code>.</p>'
    : '<p class="muted" style="margin:6px 0 0">Порт уже настроен так — команды не нужны.</p>';
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy'); ta.remove(); return ok;
  }
}

function closeDrawer() {
  $('#drawer').classList.remove('open');
  $('#drawer').setAttribute('aria-hidden', 'true');
  $('#scrim').hidden = true;
}

/* =====================================================================
   Несколько коммутаторов (режим сервера)
   ===================================================================== */
let SERVER = false;
let SWITCHES = []; // [{id, name, host, ..., cfg}]

async function apiCall(method, url, body) {
  const r = await fetch(url, {
    method, cache: 'no-store',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || `Ошибка ${r.status}`);
  return data;
}

function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + kind;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 5000);
}

async function loadSwitches() {
  const all = await apiCall('GET', 'api/switches');
  const list = all.filter(x => x.type !== 'cisco-cme');
  CMES = await Promise.all(all.filter(x => x.type === 'cisco-cme').map(async x => {
    let st = null;
    if (x.stateAt) { try { st = await apiCall('GET', `api/switches/${encodeURIComponent(x.id)}/state`); } catch (e) { /* нет данных */ } }
    return { ...x, state: st, phones: (st && st.phones) || [], cmeErrors: (st && st.errors) || {}, cmeAt: st && st.at };
  }));
  PHONES = new Map();
  for (const c of CMES) for (const p of c.phones) PHONES.set(p.mac, { ...p, cme: c });
  try { DIR = buildDirectory(await apiCall('GET', 'api/directory')); } catch (e) { DIR = null; }
  try { EVENTS = await apiCall('GET', 'api/events?limit=300'); } catch (e) { EVENTS = []; }
  try { DEVICES = await apiCall('GET', 'api/devices'); } catch (e) { DEVICES = null; }
  try { const st = await apiCall('GET', 'api/standard'); STD = st && st.ports ? st : null; } catch (e) { STD = null; }
  pollSig = sigOf(all);
  const old = new Map(SWITCHES.map(s => [s.id, s]));
  SWITCHES = await Promise.all(list.map(async s => {
    if (!s.hasConfig) return { ...s, cfg: null };
    const prev = old.get(s.id);
    // Не перечитываем данные, если они не обновлялись
    if (prev && prev.cfg && prev.lastFetch === s.lastFetch && prev.stateAt === s.stateAt) return { ...s, cfg: prev.cfg };
    const base = `api/switches/${encodeURIComponent(s.id)}`;
    let cfg;
    try { cfg = prepare(parseConfig(await apiCall('GET', `${base}/config`))); }
    catch (e) { return { ...s, cfg: null, loadError: e.message }; }
    if (s.stateAt) {
      try { attachState(cfg, await apiCall('GET', `${base}/state`)); } catch (e) { /* состояние необязательно */ }
    }
    return { ...s, cfg };
  }));
  fillSwitchSelect();
}

function fillSwitchSelect() {
  const sel = $('#swSelect');
  sel.innerHTML = `<option value="all">Все коммутаторы (${SWITCHES.length})</option>` +
    SWITCHES.map(s => `<option value="${esc(s.id)}" ${s.cfg ? '' : 'disabled'}>${esc(s.name)}${s.cfg ? '' : ' — нет данных'}</option>`).join('') +
    (CMES.length ? `<optgroup label="Телефония">${CMES.map(c => `<option value="cme:${esc(c.id)}">☎ ${esc(c.name)}</option>`).join('')}</optgroup>` : '');
  sel.value = state.current || 'all';
}

function selectSwitch(id, tab) {
  if (String(id || '').startsWith('cme:') && CMES.some(c => 'cme:' + c.id === id)) {
    if (id !== state.current) closeDrawer();
    state.current = id;
    try { localStorage.setItem('swcfg-current', id); } catch (e) { /* нет доступа */ }
    $('#swSelect').value = id;
    $('#refreshBtn').textContent = 'Обновить с роутера';
    renderCme(CMES.find(c => 'cme:' + c.id === id));
    return;
  }
  const sw = SWITCHES.find(s => s.id === id);
  if (!sw || !sw.cfg) id = 'all';
  if (id !== state.current) { state.profile = null; state.panelVlan = ''; closeDrawer(); }
  state.current = id;
  if (tab) state.tab = tab;
  try { localStorage.setItem('swcfg-current', id); } catch (e) { /* нет доступа */ }
  $('#swSelect').value = id;
  $('#refreshBtn').textContent = id === 'all' ? 'Обновить все' : 'Обновить с коммутатора';
  if (id === 'all') renderAll();
  else render(sw.cfg, sw);
}

function renderAll() {
  CFG = null;
  $('#tab-cme').hidden = true;
  $('#eyebrow').textContent = 'Huawei · стек коммутаторов';
  $('#tabs').hidden = true;
  $$('.tab').forEach(s => { s.hidden = s.id !== 'tab-all'; });
  setHash();
  $('#sysname').textContent = 'Все коммутаторы';
  document.title = 'Коммутаторы — общий обзор';
  const withCfg = SWITCHES.filter(s => s.cfg);
  const errs = SWITCHES.filter(s => s.lastError);
  $('#meta').innerHTML = [
    `<span><b>${SWITCHES.length}</b> ${plural(SWITCHES.length, 'коммутатор', 'коммутатора', 'коммутаторов')}</span>`,
    `<span><b>${withCfg.length}</b> с загруженной конфигурацией</span>`,
    errs.length ? `<span style="color:var(--sev-high)"><b>${errs.length}</b> с ошибкой обновления</span>` : '',
  ].join('');

  if (!SWITCHES.length) {
    $('#allStats').innerHTML = '';
    $('#swGrid').innerHTML = `<div class="card"><h2>Коммутаторов пока нет</h2><p class="hint" style="margin:0">Добавьте их на странице <a href="settings.html">Настройки</a>: IP-адрес, логин и пароль.</p></div>`;
    $('#allIssuesCard').hidden = $('#matrixCard').hidden = true;
    return;
  }

  // Общие цифры
  const sum = f => withCfg.reduce((a, s) => a + f(s.cfg), 0);
  const cnt = (cfg, r) => cfg.ports.filter(p => p.role === r).length;
  $('#allStats').innerHTML = [
    { v: SWITCHES.length, l: 'Коммутаторов', s: `${sum(c => c.members.length)} членов стека` },
    { v: sum(c => c.ports.length), l: 'Портов всего', s: `${sum(c => c.ports.filter(p => p.lines.length).length)} настроено` },
    { v: sum(c => cnt(c, 'access')), l: 'Рабочих мест', s: '' },
    { v: sum(c => cnt(c, 'ap')), l: 'Wi‑Fi (AP / AC)', s: '' },
    { v: sum(c => c.issues.filter(i => i.sev === 'high').length), l: 'Важных замечаний', s: `${sum(c => c.issues.filter(i => i.sev === 'med').length)} требуют внимания` },
  ].map(i => `<div class="stat"><div class="v">${i.v}</div><div class="l">${i.l}</div>${i.s ? `<div class="s">${i.s}</div>` : ''}</div>`).join('');

  // Карточки коммутаторов
  $('#swGrid').innerHTML = SWITCHES.map(s => {
    const c = s.cfg;
    const status = s.busy ? '<span class="flag">обновляется…</span>'
      : s.lastError ? `<div class="err">Не удалось обновить (${esc(ago(s.lastError.at))}): ${esc(s.lastError.message)}</div>`
      : '';
    const head = `<div class="h">
        <span class="t" data-open-sw="${esc(s.id)}">${esc(s.name)}</span>
        <span class="s mono">${esc(s.host)}</span>
        ${s.lastFetch ? `<span class="s">· ${esc(ago(s.lastFetch))}</span>` : ''}
        <span class="acts">
          ${s.hasPassword ? `<button class="btn small" data-refresh-sw="${esc(s.id)}">Обновить</button>` : `<a class="btn small" href="settings.html">Указать пароль</a>`}
          ${c ? `<button class="btn small" data-open-sw="${esc(s.id)}">Открыть →</button>` : ''}
        </span>
      </div>`;
    if (!c) return `<div class="sw-card">${head}${status}<div class="none">Конфигурация ещё не загружена${s.loadError ? ': ' + esc(s.loadError) : ''}.</div></div>`;
    const hi = c.issues.filter(i => i.sev === 'high').length, med = c.issues.filter(i => i.sev === 'med').length;
    return `<div class="sw-card" data-sw="${esc(s.id)}">${head}${status}
      <div class="nums">
        ${c.sysname && c.sysname !== s.name ? `<span class="mono">${esc(c.sysname)}</span>` : ''}
        <span><b>${c.members.length}</b>${plural(c.members.length, 'член', 'члена', 'членов')} стека</span>
        <span><b>${c.ports.filter(p => p.lines.length).length}</b>/ ${c.ports.length} портов</span>
        <span><b>${cnt(c, 'access')}</b>рабочих мест</span>
        <span><b>${cnt(c, 'ap')}</b>Wi‑Fi</span>
        <span><b>${rangesSize(c.vlansDeclared)}</b>VLAN</span>
        ${c.state ? `<span title="данные ${esc(ago(c.state.at))}"><b style="color:#2e8b57">${c.ports.filter(p => p.st && p.st.status === 'up').length}</b>up</span>` : ''}
        <span class="${hi ? 'sev-high' : ''}"><b>${hi}</b>важных</span>
        <span class="${med ? 'sev-med' : ''}"><b>${med}</b>внимание</span>
      </div>
      <div class="panel-scroll mini">${panelHtml(c, true)}</div>
    </div>`;
  }).join('');

  // Телефония
  renderPhones();

  // Схема сети и оборудование
  renderMap(withCfg);
  renderHwTable(withCfg);
  renderStpAll(withCfg);

  // Соответствие эталону
  renderStdMatrix(withCfg);

  // Последние события
  const evShown = EVENTS.slice(0, 30);
  $('#allEventsCard').hidden = !EVENTS.length;
  $('#allEventsNote').textContent = EVENTS.length > 30 ? 'показаны последние 30' : '';
  $('#allEvents').innerHTML = eventsHtml(evShown, true);

  // Неизвестные устройства на всех коммутаторах
  const unk = unknownDevices(liveSources());
  $('#allUnknownCard').hidden = !liveSources().length;
  $('#allUnknownCount').textContent = DIR ? unk.length : '';
  $('#allUnknownList').innerHTML = unknownHtml(unk, true);

  // Сводная таблица замечаний
  const SEV = { high: 'Важно', med: 'Внимание' };
  const rows = withCfg.flatMap(s => s.cfg.issues.filter(i => i.sev !== 'info').map(i => ({ s, i })))
    .sort((a, b) => (a.i.sev === 'high' ? 0 : 1) - (b.i.sev === 'high' ? 0 : 1));
  $('#allIssuesCard').hidden = !rows.length;
  $('#allIssues').innerHTML = `<thead><tr><th>Коммутатор</th><th>Уровень</th><th>Замечание</th></tr></thead><tbody>` +
    rows.map(({ s, i }) => `<tr data-open-sw="${esc(s.id)}" data-open-tab="issues">
      <td><b>${esc(s.name)}</b></td>
      <td class="sev-${i.sev}"><span class="flag" style="background:var(--sb);color:var(--sc)">${SEV[i.sev]}</span></td>
      <td>${esc(i.title)}</td></tr>`).join('') + '</tbody>';

  // Матрица VLAN × коммутатор
  $('#matrixCard').hidden = !withCfg.length;
  const vlans = [...new Set(withCfg.flatMap(s => s.cfg.usedVlans))].sort((a, b) => a - b);
  const name = v => { for (const s of withCfg) if (s.cfg.vlanNames[v]) return s.cfg.vlanNames[v]; return ''; };
  $('#vlanMatrix').innerHTML = `<thead><tr><th>VLAN</th>${withCfg.map(s => `<th>${esc(s.name)}</th>`).join('')}</tr></thead><tbody>` +
    vlans.map(v => `<tr><td><span class="mono"><b>${v}</b></span> <span class="muted">${esc(name(v))}</span></td>${withCfg.map(s => {
      const c = s.cfg;
      const declared = inRanges(c.vlansDeclared, v);
      const used = c.ports.filter(p => p.lines.length && rangesSize(p.allowed) < 64 && carries(p, v));
      const untag = used.filter(p => p.pvid != null && untaggedIn(p, v)).length;
      if (!declared && used.length) return `<td class="bad" title="Разрешён на ${used.length} портах, но не создан">⚠ ${used.length}</td>`;
      if (!declared) return '<td class="no">—</td>';
      return `<td class="yes" title="untagged: ${untag}, всего портов: ${used.length}">${untag || (used.length ? `<span class="muted">tag ${used.length}</span>` : '✓')}</td>`;
    }).join('')}</tr>`).join('') + '</tbody>';
}

async function refresh(id) {
  const btn = $('#refreshBtn');
  const all = id === 'all';
  const cmeId = String(id).startsWith('cme:') ? id.slice(4) : null;
  if (cmeId) id = cmeId;
  const targets = all ? SWITCHES.filter(s => s.hasPassword) : [...SWITCHES, ...CMES].filter(s => s.id === id);
  if (!targets.length || targets.some(s => !s.hasPassword)) { toast('Пароль не сохранён — укажите его в настройках', 'err'); return; }
  btn.disabled = true; btn.classList.add('spin');
  targets.forEach(s => { s.busy = true; });
  if (state.current === 'all') renderAll();
  toast(all ? `Обновляю ${targets.length} ${plural(targets.length, 'коммутатор', 'коммутатора', 'коммутаторов')}…` : `Подключаюсь к ${targets[0].host}…`);
  try {
    const res = all ? await apiCall('POST', 'api/fetch-all', {}) : { [id]: await apiCall('POST', `api/switches/${encodeURIComponent(id)}/fetch`, {}) };
    const vals = Object.entries(res);
    const bad = vals.filter(([, r]) => !r.ok);
    if (!bad.length) toast(all ? `Обновлено: ${vals.length}` : vals[0][1].phones != null ? `Телефонов: ${vals[0][1].phones}, зарегистрировано ${vals[0][1].registered}` : (vals[0][1].changed ? 'Конфигурация обновлена' : 'Конфигурация не изменилась'), 'ok');
    else toast(bad.map(([k, r]) => `${(SWITCHES.find(s => s.id === k) || {}).name || k}: ${r.error}`).join('; '), 'err');
  } catch (e) { toast(e.message, 'err'); }
  await loadSwitches().catch(e => toast(e.message, 'err'));
  btn.disabled = false; btn.classList.remove('spin');
  selectSwitch(state.current);
  if (cmeId) toast('Данные о телефонах обновлены', 'ok');
}

/* ---------- поиск «где подключено устройство» ---------- */
function findDevice(q) {
  q = q.trim();
  const sources = liveSources();
  const isIp = /^\d{1,3}(\.\d{1,3}){1,3}\.?$/.test(q);
  const hex = q.toLowerCase().replace(/[^0-9a-f]/g, '');
  const isMac = !isIp && /^[0-9a-f.:\- ]+$/i.test(q) && hex.length >= 4;
  const macHex = m => m.replace(/-/g, '');

  const macs = new Set();
  if (isIp) {
    const full = /^\d+\.\d+\.\d+\.\d+$/.test(q);
    for (const { cfg } of sources) for (const a of cfg.state.arp) if (full ? a.ip === q : a.ip.startsWith(q)) macs.add(a.mac);
  } else if (PHONES && PHONES.size && /^\d{2,}$/.test(q)) {
    // Внутренний номер
    for (const p of PHONES.values()) if (p.numbers.some(n => n === q || n.startsWith(q))) macs.add(p.mac);
  }
  if (!isIp && PHONES && q.length >= 2) {
    const ql = q.toLowerCase();
    for (const p of PHONES.values()) if (p.names.some(n => n.toLowerCase().includes(ql)) || (p.description || '').toLowerCase().includes(ql)) macs.add(p.mac);
  }
  if (!isIp && DIR && q.length >= 2 && !/^\d+$/.test(q)) {
    const ql = q.toLowerCase();
    for (const l of DIR.byMac.values()) if ((l.host || '').toLowerCase().includes(ql) || (l.description || '').toLowerCase().includes(ql)) macs.add(l.mac);
    for (const c of DIR.adByName.values()) {
      if (!(c.description || '').toLowerCase().includes(ql)) continue;
      for (const l of DIR.byMac.values()) if (shortHost(l.host).toUpperCase() === c.name.toUpperCase()) macs.add(l.mac);
    }
  }
  if (isMac) {
    if (DEVICES) for (const mac of Object.keys(DEVICES.macs)) if (macHex(mac).includes(hex)) macs.add(mac);
    for (const { cfg } of sources) {
      for (const m of cfg.state.mac) if (macHex(m.mac).includes(hex)) macs.add(m.mac);
      for (const a of cfg.state.arp) if (macHex(a.mac).includes(hex)) macs.add(a.mac);
    }
  }

  const devices = [...macs].slice(0, 30).map(mac => {
    const seen = [];
    for (const { sw, cfg } of sources) for (const m of cfg.state.mac) {
      if (m.mac !== mac) continue;
      const p = cfg.ports.find(x => x.name === m.port);
      // Порт, где MAC виден «транзитом»: аплинк, связь со свитчем или порт с множеством MAC
      const transit = !p || ['uplink', 'link'].includes(p.role) || (p.lldp.length > 0 && p.macs.length > 3) || p.macs.length > 20;
      seen.push({ sw, cfg, p, m, transit, count: p ? p.macs.length : 999 });
    }
    seen.sort((a, b) => a.transit - b.transit || a.count - b.count);
    const info = deviceInfo(mac);
    return { mac, ips: info.ips, info, best: seen[0] && !seen[0].transit ? seen[0] : null, seen };
  });

  // Текстовый поиск: LLDP-соседи и описания портов
  const text = [];
  if (!isIp && !isMac && q.length >= 2) {
    const ql = q.toLowerCase();
    for (const { sw, cfg } of sources.length ? sources : (SERVER ? SWITCHES.filter(s => s.cfg).map(s => ({ sw: s, cfg: s.cfg })) : [{ sw: null, cfg: CFG }])) {
      for (const p of cfg.ports) {
        const n = (p.lldp || []).find(x => x.device.toLowerCase().includes(ql));
        if (n) text.push({ sw, p, what: `LLDP: ${n.device}` });
        else if ((p.desc || '').toLowerCase().includes(ql)) text.push({ sw, p, what: `описание: ${p.desc}` });
      }
    }
  }
  return { q, isIp, isMac, devices, text: text.slice(0, 50), sources };
}

function gotoLink(sw, p, label) {
  return `<button class="plink" data-goto-sw="${esc(sw ? sw.id : '')}" data-goto-port="${esc(p.name)}">${esc(label || p.short)}</button>`;
}

function showFind(q) {
  if (!q.trim()) return;
  const r = findDevice(q);
  const swName = sw => sw ? esc(sw.name) : '';
  const loc = s => `${s.sw ? `<b>${swName(s.sw)}</b> · ` : ''}${s.p ? gotoLink(s.sw, s.p) : esc(s.m.port)} · VLAN ${s.m.vlan ?? '—'}${s.p && s.p.desc ? ` · <span class="muted">${esc(s.p.desc)}</span>` : ''}`;
  const times = r.sources.map(s => `${s.sw ? s.sw.name + ': ' : ''}${ago(s.cfg.state.at)}`).join(', ');

  let html = '';
  if (!r.sources.length && !r.devices.length) {
    html = '<p class="muted">Нет данных о состоянии портов. Нажмите «Обновить», чтобы забрать их с коммутаторов.</p>';
  } else if (r.devices.length) {
    html = r.devices.map(d => `<div class="find-item">
      <div class="h">${d.info.phone ? phoneLabel(d.info.phone) : ''}${d.info.name ? deviceLabel(d.info, false) : ''}<span class="mono"><b>${esc(d.mac)}</b></span>${d.ips.length ? `<span class="mono">${esc(d.ips.join(', '))}</span>` : ''}</div>
      ${d.info.os || d.info.ou || d.info.description ? `<div class="muted" style="font-size:12.5px">${esc([d.info.os, d.info.ou, d.info.description].filter(Boolean).join(' · '))}</div>` : ''}
      ${d.best ? `<div class="where">📍 Подключено: ${loc(d.best)}</div>` : `<div class="where muted">${d.seen.length ? 'Конечный порт не найден — MAC виден только через аплинки.' : 'Сейчас не виден ни на одном коммутаторе (выключен или подключён к коммутатору, которого нет в списке).' + lastSeenText(d.mac)}</div>`}
      ${d.seen.filter(s => s !== d.best).length ? `<details><summary class="muted">Также виден через ${d.seen.filter(s => s !== d.best).length}</summary>
        ${d.seen.filter(s => s !== d.best).map(s => `<div class="muted" style="font-size:12.5px">${loc(s)}${s.p ? ' · ' + esc(ROLES[s.p.role].label.toLowerCase()) : ''}</div>`).join('')}</details>` : ''}
    </div>`).join('');
  } else if (r.text.length) {
    html = r.text.map(t => `<div class="find-item"><div>${t.sw ? `<b>${swName(t.sw)}</b> · ` : ''}${gotoLink(t.sw, t.p)} ${liveBadge(t.p)}</div><div class="muted">${esc(t.what)}</div></div>`).join('');
  } else {
    html = `<p>Ничего не найдено по «${esc(q)}».</p>`;
  }
  html += `<p class="hint" style="margin-top:14px">Ищется по MAC (в любом формате, можно часть), IP, имени компьютера (DHCP / AD), имени LLDP-соседа или описанию порта.
    IP находится по таблице ARP — полнее всего, если в список добавлен коммутатор ядра (шлюз сети).${times ? ` Данные: ${esc(times)}.` : ''}</p>`;

  $('#drawerTitle').textContent = `Поиск: ${q}`;
  $('#drawerBody').innerHTML = html;
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#scrim').hidden = false;
}

/* ---------- история, события, устройства ---------- */
let EVENTS = [];
let DEVICES = null;
let HIST = null; // { sw, versions, events, cache }
let pollSig = '';

const EV_ICON = {
  unreachable: '⛔', recovered: '✅', 'config-changed': '📝', loop: '🔁', 'loop-cleared': '✅',
  'uplink-down': '🔻', 'uplink-up': '🔺', errors: '⚠️', 'new-device': '➕', 'unknown-device': '❓', moved: '↔️', hw: '🛠', 'hw-ok': '✅', 'phone-unreg': '📵', 'phone-reg': '☎️', backup: '💾', restore: '♻️', 'restore-undo': '↩️', 'stp-root': '🌳', 'stp-rootport': '🌿',
};
const EV_GROUPS = {
  important: e => e.sev === 'high' || e.sev === 'med',
  devices: e => ['new-device', 'unknown-device', 'moved', 'phone-unreg', 'phone-reg'].includes(e.type),
  ports: e => ['loop', 'loop-cleared', 'uplink-down', 'uplink-up', 'errors'].includes(e.type),
  config: e => ['config-changed', 'backup', 'restore', 'restore-undo'].includes(e.type),
  reach: e => ['unreachable', 'recovered'].includes(e.type),
  hardware: e => ['hw', 'hw-ok'].includes(e.type),
  backup: e => ['backup', 'restore', 'restore-undo'].includes(e.type),
  stp: e => ['stp-root', 'stp-rootport'].includes(e.type),
};

function fmtTime(iso) {
  return new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function eventsHtml(list, withSwitch) {
  if (!list.length) return '<p class="muted" style="margin:0">Событий пока нет. Они появляются, когда при очередном сборе что-то меняется: порт упал, появилось новое устройство, изменился конфиг.</p>';
  return `<ul class="events">${list.map(e => `<li class="ev sev-${esc(e.sev)}">
    <span class="ev-t" title="${esc(new Date(e.ts).toLocaleString('ru-RU'))}">${esc(fmtTime(e.ts))}</span>
    <span class="ev-i">${EV_ICON[e.type] || '•'}</span>
    <span class="ev-x">${withSwitch ? `<b>${esc(e.swName || e.sw)}</b> · ` : ''}${esc(e.text)}${e.port ? ` <button class="plink" data-goto-sw="${esc(e.sw)}" data-goto-port="${esc(e.port)}">открыть порт</button>` : ''}${e.type === 'config-changed' ? ` <button class="plink" data-open-sw="${esc(e.sw)}" data-open-tab="history">что изменилось</button>` : ''}</span>
  </li>`).join('')}</ul>`;
}

function lastSeenText(mac) {
  const d = DEVICES && DEVICES.macs[mac];
  if (!d) return '';
  return ` Последний раз: ${d.swName || d.sw} · ${shortName(d.port)} · ${fmtTime(d.lastSeen)}.`;
}

// Какие устройства были на порту (по истории сборов)
function portHistoryHtml(swId, portName) {
  if (!DEVICES) return '';
  const rows = [];
  for (const [mac, d] of Object.entries(DEVICES.macs)) {
    if (d.sw === swId && d.port === portName) rows.push({ mac, from: d.since || d.firstSeen, to: d.lastSeen, current: true });
    for (const mv of d.moves || []) if (mv.sw === swId && mv.port === portName) rows.push({ mac, from: mv.from, to: mv.to });
  }
  if (!rows.length) return '';
  rows.sort((a, b) => String(b.to).localeCompare(String(a.to)));
  return `<div class="sub">История порта</div>
    <table class="tbl static"><thead><tr><th>Устройство</th><th>Был на порту</th></tr></thead><tbody>
    ${rows.slice(0, 20).map(r => {
      const info = deviceInfo(r.mac);
      return `<tr><td>${info.name ? deviceLabel(info, false) + ` <span class="mono muted">${esc(r.mac)}</span>` : `<span class="mono">${esc(r.mac)}</span>`}</td>
        <td>${esc(fmtTime(r.from))} — ${r.current ? `последний раз ${esc(fmtTime(r.to))}` : `${esc(fmtTime(r.to))} <span class="muted">(переехал)</span>`}</td></tr>`;
    }).join('')}
    </tbody></table>`;
}

async function renderHistory(sw) {
  $('#historyTabBtn').hidden = !SERVER || !sw;
  if (!SERVER || !sw) return;
  const id = sw.id;
  let versions = [], events = [];
  try { versions = await apiCall('GET', `api/switches/${encodeURIComponent(id)}/history`); } catch (e) { /* нет истории */ }
  try { events = await apiCall('GET', `api/events?sw=${encodeURIComponent(id)}&limit=500`); } catch (e) { /* нет событий */ }
  if (state.current !== id) return; // пока грузилось, выбрали другой коммутатор
  const keepA = HIST && HIST.sw === id ? $('#verA').value : '', keepB = HIST && HIST.sw === id ? $('#verB').value : '';
  HIST = { sw: id, versions, events, cache: HIST && HIST.sw === id ? HIST.cache : {} };
  renderSwEvents();
  renderBackups(sw);

  const label = v => `${fmtTime(v.ts)}${v.added != null ? ` · +${v.added} / −${v.removed}` : ' · первая'}`;
  const opts = versions.map(v => `<option value="${esc(v.ts)}">${esc(label(v))}</option>`).join('');
  $('#verA').innerHTML = opts; $('#verB').innerHTML = opts;
  const hasTwo = versions.length >= 2;
  $('#verA').disabled = $('#verB').disabled = !hasTwo;
  if (!versions.length) {
    $('#verList').innerHTML = '<p class="muted" style="margin:0">История версий появится после следующего сбора конфигурации.</p>';
    $('#cfgDiff').innerHTML = '';
    return;
  }
  if (!hasTwo) {
    $('#verList').innerHTML = `<p class="muted" style="margin:0">Пока одна версия — от ${esc(fmtTime(versions[0].ts))}. Различия появятся, когда конфигурация изменится.</p>`;
    $('#cfgDiff').innerHTML = '';
    return;
  }
  $('#verA').value = versions.some(v => v.ts === keepA) ? keepA : versions[1].ts;
  $('#verB').value = versions.some(v => v.ts === keepB) ? keepB : versions[0].ts;
  $('#verList').innerHTML = `<details class="ver-list"><summary class="muted">Все версии (${versions.length})</summary>
    <table class="tbl static"><thead><tr><th>Дата</th><th>Строк</th><th>Изменения</th><th></th></tr></thead><tbody>
    ${versions.slice(0, 50).map((v, i) => `<tr><td>${esc(new Date(v.ts).toLocaleString('ru-RU'))}</td><td>${v.lines}</td>
      <td>${v.added != null ? `<span class="d-add">+${v.added}</span> <span class="d-del">−${v.removed}</span>` : '<span class="muted">первая версия</span>'}</td>
      <td>${versions[i + 1] ? `<button class="plink" data-ver-a="${esc(versions[i + 1].ts)}" data-ver-b="${esc(v.ts)}">сравнить с предыдущей</button>` : ''}</td></tr>`).join('')}
    </tbody></table></details>`;
  showDiff();
}

/* ---------- резервные копии и восстановление ---------- */
function renderBackups(sw) {
  const lr = sw && sw.lastRestore;
  $('#restoreBanner').innerHTML = lr && !lr.undone ? `<div class="issue sev-high" style="margin-bottom:12px">
      <div class="ih"><span class="sev">Ожидает перезагрузки</span><span class="it">Назначено восстановление версии от ${esc(new Date(lr.ts).toLocaleString('ru-RU'))}</span></div>
      <div class="ib">Файл <code>${esc(lr.file)}</code> назначен конфигурацией для следующей загрузки (${esc(fmtTime(lr.at))}). Чтобы применить — перезагрузите коммутатор в окно обслуживания командой <code>reboot</code> (в стеке перезагрузятся все члены). Прежний файл: <code>${esc(lr.previous)}</code>.</div>
      <div class="ip"><button class="btn small" data-restore-undo>Отменить восстановление (вернуть ${esc(lr.previous.replace(/^.*[\/:]/, ''))})</button></div>
    </div>` : '';
  const vs = (HIST && HIST.versions) || [];
  if (!vs.length) { $('#backupList').innerHTML = '<p class="muted" style="margin:0">Версий пока нет. Нажмите «Сделать резервную копию».</p>'; return; }
  const pinned = vs.filter(v => v.pinned);
  const rows = [...pinned, ...vs.filter(v => !v.pinned).slice(0, 10)];
  const base = `api/switches/${encodeURIComponent(sw.id)}/history/`;
  $('#backupList').innerHTML = `<div class="table-scroll"><table class="tbl static"><thead><tr><th>Дата</th><th>Строк</th><th>Отметка</th><th>Скачать</th><th></th></tr></thead><tbody>
    ${rows.map((v, i) => `<tr>
      <td>${esc(new Date(v.ts).toLocaleString('ru-RU'))}${v.ts === vs[0].ts ? ' <span class="flag">текущая</span>' : ''}</td>
      <td>${v.lines}</td>
      <td>${v.pinned ? `📌 ${esc(v.note || 'Резервная копия')} <button class="plink" data-unpin="${esc(v.ts)}" title="Снять закрепление: версия сможет удалиться при очистке">открепить</button>` : '<span class="muted">версия из истории</span>'}</td>
      <td><a class="plink" href="${base}${encodeURIComponent(v.ts)}?download=1" title="Пароли и ключи скрыты">.cfg</a> · <a class="plink" href="${base}${encodeURIComponent(v.ts)}?download=1&raw=1" title="Полная копия с зашифрованными паролями — для восстановления вручную">с паролями</a></td>
      <td>${v.ts === vs[0].ts ? '' : `<button class="btn small" data-restore="${esc(v.ts)}">Восстановить…</button>`}</td>
    </tr>`).join('')}
  </tbody></table></div>${vs.length > rows.length ? `<p class="hint" style="margin:8px 0 0">Показаны закреплённые копии и 10 последних версий. Все версии — в блоке «Что изменилось» ниже.</p>` : ''}`;
}

async function makeBackup() {
  const btn = $('#backupBtn');
  const id = HIST && HIST.sw;
  if (!id) return;
  btn.disabled = true; btn.classList.add('spin');
  toast('Забираю конфигурацию…');
  try {
    const r = await apiCall('POST', `api/switches/${encodeURIComponent(id)}/backup`, {});
    toast(`Резервная копия сохранена: ${r.version.lines} строк${r.changed ? '' : ' (конфигурация не менялась)'}`, 'ok');
    await loadSwitches();
    selectSwitch(state.current, 'history');
  } catch (e) { toast(e.message, 'err'); }
  btn.disabled = false; btn.classList.remove('spin');
}

let RESTORE = null; // { sw, ts }
async function openRestore(ts) {
  const sw = SWITCHES.find(x => x.id === HIST.sw);
  if (!sw) return;
  RESTORE = { sw, ts };
  const cur = HIST.versions[0];
  openDrawer('Восстановление конфигурации', '<p class="muted">Сравниваю с текущей конфигурацией…</p>');
  let st = null, preview = '';
  try {
    const [a, b] = await Promise.all([versionText(cur.ts), versionText(ts)]);
    const ops = LineDiff.diffLines(a.replace(/\n$/, '').split('\n'), b.replace(/\n$/, '').split('\n'));
    st = LineDiff.stats(ops);
    preview = LineDiff.hunks(ops).slice(0, 8).map(h => h.lines.filter(l => l.op !== ' ').slice(0, 12).map(l => `<div class="dl dl-${l.op === '+' ? 'add' : 'del'}"><span class="ln"></span><span class="ln"></span><span class="dt">${l.op} ${esc(l.line)}</span></div>`).join('')).join('<div class="hunk-h">…</div>');
  } catch (e) { preview = `<p class="muted">Не удалось сравнить: ${esc(e.message)}</p>`; }
  $('#drawerBody').innerHTML = `
    <dl class="kv">
      <dt>Коммутатор</dt><dd><b>${esc(sw.name)}</b> <span class="mono muted">${esc(sw.host)}</span></dd>
      <dt>Версия</dt><dd>${esc(new Date(ts).toLocaleString('ru-RU'))}</dd>
      <dt>Текущая</dt><dd>${esc(new Date(cur.ts).toLocaleString('ru-RU'))}</dd>
      ${st ? `<dt>Отличия</dt><dd>относительно текущей: <span class="d-add">+${st.added}</span> <span class="d-del">−${st.removed}</span> строк</dd>` : ''}
    </dl>
    ${preview ? `<div class="sub">Что изменится после перезагрузки</div><div class="diff" style="max-height:260px;overflow:auto">${preview}</div>` : ''}
    <div class="sub">Что будет сделано</div>
    <ol class="steps">
      <li>Сделается свежая резервная копия текущей конфигурации.</li>
      <li>Выбранная версия загрузится на flash коммутатора по SFTP отдельным файлом <code>restore_…cfg</code>. Текущий файл конфигурации не изменится.</li>
      <li>Файл назначится конфигурацией для следующей загрузки: <code>startup saved-configuration restore_…cfg</code>, результат проверится через <code>display startup</code>.</li>
      <li><b>Работающая конфигурация не меняется.</b> Новая применится только после перезагрузки, которую вы делаете сами (<code>reboot</code>) в окно обслуживания.</li>
    </ol>
    <p class="fix-w">⚠ После перезагрузки коммутатор будет недоступен несколько минут, все порты отключатся. Если в выбранной версии другой IP управления или учётные записи, связь с коммутатором может пропасть. До перезагрузки всё можно отменить кнопкой «Отменить восстановление».</p>
    <label class="field">Для подтверждения введите название коммутатора: <b>${esc(sw.name)}</b>
      <input id="restoreConfirm" data-name="${esc(sw.name)}" autocomplete="off" spellcheck="false">
    </label>
    <div class="form-actions"><button class="btn primary" id="restoreGo" disabled>Назначить восстановление</button><button class="btn ghost" data-std-cancel>Отмена</button></div>
    <div id="restoreLog"></div>`;
}

async function doRestore() {
  if (!RESTORE) return;
  const btn = $('#restoreGo');
  btn.disabled = true; btn.classList.add('spin');
  $('#restoreLog').innerHTML = '<p class="muted">Выполняется — это займёт до минуты…</p>';
  try {
    const r = await apiCall('POST', `api/switches/${encodeURIComponent(RESTORE.sw.id)}/restore`, { ts: RESTORE.ts, confirm: $('#restoreConfirm').value });
    $('#restoreLog').innerHTML = `<ul class="std-rules">${(r.log || []).map(l => `<li class="${l.ok ? 'ok' : 'bad'}"><span class="mark">${l.ok ? '✓' : '✗'}</span><div class="grow">${esc(l.msg)}</div></li>`).join('')}</ul>` +
      (r.ok ? `<p class="fix-n" style="color:var(--text)"><b>Готово.</b> Перезагрузите коммутатор в окно обслуживания: <code>reboot</code>. После загрузки проверьте <code>display startup</code> и нажмите «Обновить с коммутатора».</p>`
        : `<p class="fix-w">Восстановление не назначено: ${esc(r.error || '')}. Работающая конфигурация не изменялась.</p>`);
    await loadSwitches();
    renderHistory(SWITCHES.find(x => x.id === RESTORE.sw.id));
  } catch (e) {
    $('#restoreLog').innerHTML = `<p class="fix-w">✗ ${esc(e.message)}</p>`;
    btn.disabled = false;
  }
  btn.classList.remove('spin');
}

async function undoRestore() {
  const sw = SWITCHES.find(x => x.id === (HIST && HIST.sw));
  if (!sw) return;
  toast('Возвращаю прежний файл конфигурации…');
  try {
    const r = await apiCall('POST', `api/switches/${encodeURIComponent(sw.id)}/restore/undo`, {});
    toast(`Отменено: при загрузке будет ${r.next}`, 'ok');
    await loadSwitches();
    renderHistory(SWITCHES.find(x => x.id === sw.id));
  } catch (e) { toast(e.message, 'err'); }
}

function renderSwEvents() {
  if (!HIST) return;
  const f = EV_GROUPS[$('#evFilter').value];
  $('#swEvents').innerHTML = eventsHtml(f ? HIST.events.filter(f) : HIST.events, false);
}

async function versionText(ts) {
  if (!HIST.cache[ts]) HIST.cache[ts] = await apiCall('GET', `api/switches/${encodeURIComponent(HIST.sw)}/history/${encodeURIComponent(ts)}`);
  return HIST.cache[ts];
}

async function showDiff() {
  if (!HIST || HIST.versions.length < 2) return;
  const a = $('#verA').value, b = $('#verB').value;
  const box = $('#cfgDiff');
  if (a === b) { box.innerHTML = '<p class="muted">Выберите две разные версии.</p>'; return; }
  box.innerHTML = '<p class="muted">Сравниваю…</p>';
  let ta, tb;
  try { [ta, tb] = await Promise.all([versionText(a), versionText(b)]); }
  catch (e) { box.innerHTML = `<p class="muted">Не удалось загрузить версию: ${esc(e.message)}</p>`; return; }
  const [older, newer] = a < b ? [ta, tb] : [tb, ta];
  const ops = LineDiff.diffLines(older.replace(/\n$/, '').split('\n'), newer.replace(/\n$/, '').split('\n'));
  const st = LineDiff.stats(ops);
  if (!st.added && !st.removed) { box.innerHTML = '<p class="muted">Версии одинаковые.</p>'; return; }
  const line = l => `<div class="dl dl-${l.op === '+' ? 'add' : l.op === '-' ? 'del' : 'ctx'}"><span class="ln">${l.aNo ?? ''}</span><span class="ln">${l.bNo ?? ''}</span><span class="dt">${l.op === ' ' ? ' ' : l.op} ${esc(l.line)}</span></div>`;
  // Ближайшая команда верхнего уровня над изменением (например, interface GigabitEthernet0/0/5)
  const ctxOf = i => { for (let j = i; j >= 0; j--) { const t = ops[j].line; if (t && !/^\s/.test(t) && t !== '#') return t; } return ''; };
  let body;
  if ($('#diffFull').checked) {
    let an = 0, bn = 0;
    body = ops.map(o => { if (o.op !== '+') an++; if (o.op !== '-') bn++; return line({ ...o, aNo: o.op === '+' ? null : an, bNo: o.op === '-' ? null : bn }); }).join('');
  } else {
    body = LineDiff.hunks(ops).map(h => `<div class="hunk-h">${esc(ctxOf(h.lines.find(l => l.op !== ' ').i) || 'начало')}</div>${h.lines.map(line).join('')}`).join('');
  }
  box.innerHTML = `<div class="diff-sum"><span class="d-add">+${st.added}</span> <span class="d-del">−${st.removed}</span> строк</div><div class="diff">${body}</div>`;
}

// Фоновое обновление: сервер собирает данные по расписанию, страница подхватывает их сама
function sigOf(list) { return list.map(x => [x.id, x.lastFetch, x.stateAt, x.lastError && x.lastError.at].join('|')).join(';'); }
async function poll() {
  if (document.hidden) return;
  try {
    const list = await apiCall('GET', 'api/switches');
    const sig = sigOf(list);
    if (pollSig && sig !== pollSig && !$('#refreshBtn').disabled) {
      await loadSwitches();
      selectSwitch(state.current);
      toast('Данные обновлены');
    }
    pollSig = sig;
  } catch (e) { /* сервер недоступен — попробуем позже */ }
}

/* ---------- телефония: Cisco CME ---------- */
let CMES = [];
let PHONES = null; // MAC → телефон

// Где подключён MAC сейчас: конечный порт (не аплинк)
function locateMac(mac) {
  const seen = [];
  for (const { sw, cfg } of liveSources()) for (const m of cfg.state.mac) {
    if (m.mac !== mac) continue;
    const p = cfg.ports.find(x => x.name === m.port);
    const transit = !p || ['uplink', 'link'].includes(p.role) || (p.lldp.length > 0 && p.macs.length > 3) || p.macs.length > 20;
    seen.push({ sw, cfg, p, m, transit, count: p ? p.macs.length : 999 });
  }
  seen.sort((a, b) => a.transit - b.transit || a.count - b.count);
  return seen[0] && !seen[0].transit ? seen[0] : null;
}

function renderPhones() {
  $('#phonesCard').hidden = !CMES.length;
  if (!CMES.length) return;
  $('#cmeSources').innerHTML = CMES.map(c => `<b>${esc(c.name)}</b> ${esc(c.host)} · ${c.lastError ? `<span style="color:var(--sev-high)">ошибка: ${esc(c.lastError.message)}</span>` : c.cmeAt ? `обновлено ${esc(ago(c.cmeAt))}` : 'данные ещё не загружены'}
    ${Object.keys(c.cmeErrors).length ? ` · не выполнились: ${esc(Object.keys(c.cmeErrors).join(', '))}` : ''}
    ${c.hasPassword ? ` <button class="btn small" data-refresh-sw="${esc(c.id)}">Обновить</button>` : ' <a href="settings.html">указать пароль</a>'}`).join('<br>');
  renderPhoneTable();
}

function renderPhoneTable() {
  const q = $('#phoneSearch').value.trim().toLowerCase();
  const f = $('#phoneFilter').value;
  const rows = [];
  for (const c of CMES) for (const ph of c.phones) {
    const loc = locateMac(ph.mac);
    const last = !loc && DEVICES && DEVICES.macs[ph.mac];
    if (f === 'unreg' && ph.status === 'registered') continue;
    if (f === 'nowhere' && loc) continue;
    if (q) {
      const hay = [ph.numbers.join(' '), ph.names.join(' '), ph.description, ph.mac, ph.mac.replace(/-/g, ''), ph.ip, ph.model, loc && loc.p.short, loc && loc.sw && loc.sw.name].join(' ').toLowerCase();
      if (!hay.includes(q)) continue;
    }
    rows.push({ c, ph, loc, last });
  }
  rows.sort((a, b) => String(a.ph.numbers[0] || '~').localeCompare(String(b.ph.numbers[0] || '~'), 'ru', { numeric: true }));
  const total = CMES.reduce((n, c) => n + c.phones.length, 0);
  const reg = CMES.reduce((n, c) => n + c.phones.filter(p => p.status === 'registered').length, 0);
  $('#phoneTable').innerHTML = `<thead><tr><th>Номер</th><th>Имя / подпись</th><th>Модель</th><th>Статус</th><th>IP</th><th>MAC</th><th>Подключён</th></tr></thead><tbody>` +
    rows.slice(0, 500).map(({ c, ph, loc, last }) => `<tr data-open-phone="${esc(c.id)}|${esc(ph.mac)}">
      <td class="mono"><b>${esc(ph.numbers.join(', ') || '—')}</b></td>
      <td>${esc(ph.names.join(' · ') || '—')}${ph.description ? `<div class="muted" style="font-size:12px">${esc(ph.description)}</div>` : ''}</td>
      <td>${esc(ph.model || '—')} <span class="muted">${ph.proto.toUpperCase()}</span></td>
      <td>${ph.status === 'registered' ? '<span class="live live-up">зарегистрирован</span>' : `<span class="flag warn">${esc(ph.status === 'unregistered' ? 'не зарегистрирован' : ph.status === 'deceased' ? 'пропал (deceased)' : 'неизвестно')}</span>`}</td>
      <td class="mono">${esc(ph.ip || '—')}</td>
      <td class="mono muted">${esc(ph.mac)}</td>
      <td>${loc ? `<b>${esc(loc.sw ? loc.sw.name : '')}</b> · <span class="mono">${esc(loc.p.short)}</span>${loc.p.desc ? ` <span class="muted">${esc(loc.p.desc)}</span>` : ''}`
        : last ? `<span class="muted">последний раз: ${esc(last.swName || last.sw)} · ${esc(shortName(last.port))} · ${esc(fmtTime(last.lastSeen))}</span>`
        : '<span class="muted">не найден на коммутаторах</span>'}</td>
    </tr>`).join('') + '</tbody>';
  const found = rows.filter(r => r.loc).length;
  $('#phoneFoot').textContent = `Всего ${total}, зарегистрировано ${reg}. Показано ${Math.min(rows.length, 500)}, из них найдено на портах ${found}.`;
}

/* ---------- раздел «Телефоны» одного роутера CME ---------- */
let CME = null; // выбранный роутер

function openDrawer(title, html) {
  $('#drawerTitle').textContent = title;
  $('#drawerBody').innerHTML = html;
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#scrim').hidden = false;
}

function renderCme(c) {
  CME = c;
  CFG = null;
  $('#tabs').hidden = true;
  $$('.tab').forEach(s => { s.hidden = s.id !== 'tab-cme'; });
  $('#eyebrow').textContent = 'Cisco CME · телефония';
  setHash();
  $('#sysname').textContent = c.name;
  document.title = `${c.name} — телефоны`;
  const reg = c.phones.filter(p => p.status === 'registered').length;
  $('#meta').innerHTML = [
    `<span>Cisco CME · IP <b>${esc(c.host)}</b></span>`,
    c.cmeAt ? `<span>Обновлено <b>${esc(ago(c.cmeAt))}</b></span>` : '<span>данные ещё не загружены</span>',
    `<span><b>${c.phones.length}</b> ${plural(c.phones.length, 'телефон', 'телефона', 'телефонов')}, зарегистрировано <b>${reg}</b></span>`,
    c.lastError ? `<span style="color:var(--sev-high)">Ошибка: ${esc(c.lastError.message)}</span>` : '',
  ].join('');
  renderCmeTable();

  const st = c.state || {};
  const free = st.freeDns || [];
  $('#freeDnCount').textContent = free.length || '';
  $('#freeDns').innerHTML = free.length ? `<ul class="list">${free.slice(0, 100).map(d => `<li><span class="mono"><b>${esc(d.numbers.join(', ') || '—')}</b></span>
      <span class="grow">${esc([d.name, d.label].filter(Boolean).join(' · '))} <span class="muted">ephone-dn ${d.id}</span></span></li>`).join('')}</ul>`
    : '<p class="muted" style="margin:0">Свободных номеров нет.</p>';

  const cands = phoneCandidates();
  $('#candCount').textContent = cands.length || '';
  $('#phoneCands').innerHTML = cands.length ? `<ul class="list">${cands.slice(0, 100).map(x => `<li>
      <span class="mono">${esc(x.m.mac)}</span>
      <span class="grow"><b>${esc(x.sw.name)}</b> · <button class="plink" data-goto-sw="${esc(x.sw.id)}" data-goto-port="${esc(x.p.name)}">${esc(x.p.short)}</button> <span class="muted">VLAN ${x.m.vlan}${x.p.desc ? ' · ' + esc(x.p.desc) : ''}</span></span>
      <button class="btn small" data-new-phone="${esc(x.m.mac)}">Добавить</button></li>`).join('')}</ul>`
    : `<p class="muted" style="margin:0">${liveSources().length ? 'Таких нет — все MAC в голосовом VLAN известны CME.' : 'Нет данных о портах коммутаторов.'}</p>`;

  const errs = Object.keys(c.cmeErrors || {});
  $('#cmeNote').textContent = errs.length ? `Не выполнились команды: ${errs.join(', ')}.${errs.some(x => /running-config/.test(x)) ? ' Без show running-config нет подписей и имён — укажите пароль enable в настройках.' : ''}` : '';
}

// MAC на конечных портах в голосовом VLAN, которых нет в CME
function phoneCandidates() {
  const out = [];
  for (const { sw, cfg } of liveSources()) {
    for (const p of cfg.ports) {
      if (!p.macs || !p.voiceVlan || !isEdgePort(p)) continue;
      for (const m of p.macs) if (m.vlan === p.voiceVlan && !(PHONES && PHONES.has(m.mac))) out.push({ sw, cfg, p, m });
    }
  }
  return out;
}

function renderCmeTable() {
  const c = CME;
  if (!c) return;
  const q = $('#cmeSearch').value.trim().toLowerCase();
  const f = $('#cmeFilter').value;
  const rows = [];
  for (const ph of c.phones) {
    const loc = locateMac(ph.mac);
    if (f === 'unreg' && ph.status === 'registered') continue;
    if (f === 'nowhere' && loc) continue;
    if (f === 'sip' && ph.proto !== 'sip') continue;
    if (q) {
      const hay = [ph.numbers.join(' '), ph.names.join(' '), ph.description, ph.mac, ph.mac.replace(/-/g, ''), ph.ip, ph.model, ph.id, loc && loc.p.short, loc && loc.sw && loc.sw.name].join(' ').toLowerCase();
      if (!hay.includes(q)) continue;
    }
    rows.push({ ph, loc });
  }
  rows.sort((a, b) => String(a.ph.numbers[0] || '~').localeCompare(String(b.ph.numbers[0] || '~'), 'ru', { numeric: true }));
  $('#cmeTable').innerHTML = `<thead><tr><th>Номер</th><th>Имя / подпись</th><th>Описание</th><th>Модель</th><th>Статус</th><th>IP</th><th>Подключён</th><th></th></tr></thead><tbody>` +
    rows.map(({ ph, loc }) => `<tr data-open-phone="${esc(c.id)}|${esc(ph.mac)}">
      <td class="mono"><b>${esc(ph.numbers.join(', ') || '—')}</b></td>
      <td>${esc(ph.names.join(' · ') || '—')}</td>
      <td class="muted">${esc(ph.description || '')}</td>
      <td>${esc(ph.model || '—')} <span class="muted">${ph.proto.toUpperCase()}</span></td>
      <td>${phoneStatus(ph)}</td>
      <td class="mono">${esc(ph.ip || '—')}</td>
      <td>${loc ? `<b>${esc(loc.sw ? loc.sw.name : '')}</b> · <span class="mono">${esc(loc.p.short)}</span>` : '<span class="muted">—</span>'}</td>
      <td class="muted mono">${esc(ph.id)}</td>
    </tr>`).join('') + '</tbody>';
  $('#cmeFoot').textContent = `Показано ${rows.length} из ${c.phones.length}`;
}

function phoneStatus(ph) {
  return ph.status === 'registered' ? '<span class="live live-up">зарегистрирован</span>'
    : `<span class="flag warn">${esc(ph.status === 'unregistered' ? 'не зарегистрирован' : ph.status === 'deceased' ? 'пропал (deceased)' : 'неизвестно')}</span>`;
}

let PHONE_EDIT = null; // { c, ph }

function phoneField(label, name, value, extra = '') {
  return `<label class="field">${label}<input name="${name}" value="${esc(value || '')}" spellcheck="false" ${extra}></label>`;
}
function modelField(value) {
  return `<label class="field">Модель (type)<input name="model" list="phoneModels" value="${esc(value || '')}" spellcheck="false">
    <datalist id="phoneModels">${CmeCmd.MODELS.map(m => `<option value="${m}">`).join('')}</datalist></label>`;
}

function openPhone(mac) {
  const c = CME;
  const ph = c && c.phones.find(p => p.mac === mac);
  if (!ph) return;
  PHONE_EDIT = { c, ph };
  const loc = locateMac(ph.mac);
  const last = !loc && DEVICES && DEVICES.macs[ph.mac];
  const dn = ph.dns[0];
  const cfgText = [
    ph.proto === 'sip' ? `voice register pool ${ph.ref}` : `ephone ${ph.ref}`, ...ph.lines.map(l => ' ' + l),
    ...ph.dns.flatMap(d => ['!', d.head || (ph.proto === 'sip' ? `voice register dn ${d.id}` : `ephone-dn ${d.id}`), ...d.lines.map(l => ' ' + l)]),
  ].join('\n');
  openDrawer(`☎ ${ph.numbers.join(', ') || ph.id}${ph.names[0] ? ' · ' + ph.names[0] : ''}`, `
    <dl class="kv">
      <dt>Статус</dt><dd>${phoneStatus(ph)}</dd>
      <dt>Телефон</dt><dd class="mono">${esc(ph.id)} · ${ph.proto.toUpperCase()}</dd>
      <dt>Модель</dt><dd>${esc(ph.model || '—')}</dd>
      <dt>MAC</dt><dd class="mono">${esc(CmeCmd.ciscoMac(ph.mac) || ph.mac)}</dd>
      <dt>IP</dt><dd class="mono">${esc(ph.ip || '—')}</dd>
      <dt>Подключён</dt><dd>${loc ? `<b>${esc(loc.sw ? loc.sw.name : '')}</b> · <button class="plink" data-goto-sw="${esc(loc.sw ? loc.sw.id : '')}" data-goto-port="${esc(loc.p.name)}">${esc(loc.p.short)}</button> <span class="muted">VLAN ${loc.m.vlan}${loc.p.desc ? ' · ' + esc(loc.p.desc) : ''}</span>`
        : last ? `<span class="muted">последний раз: ${esc(last.swName || last.sw)} · ${esc(shortName(last.port))} · ${esc(fmtTime(last.lastSeen))}</span>` : '<span class="muted">не найден на коммутаторах</span>'}</dd>
      <dt>Описание</dt><dd>${esc(ph.description || '—')}</dd>
    </dl>
    <div class="sub">Номера на кнопках</div>
    ${ph.dns.length ? `<table class="tbl static"><thead><tr><th>Кнопка</th><th>Номер</th><th>Имя</th><th>Подпись</th><th>DN</th></tr></thead><tbody>
      ${ph.dns.map((d, i) => `<tr><td>${i + 1}</td><td class="mono"><b>${esc(d.numbers.join(', '))}</b></td><td>${esc(d.name || '—')}</td><td>${esc(d.label || '—')}</td><td class="muted mono">${d.id}</td></tr>`).join('')}
    </tbody></table>` : '<p class="muted">Нет данных о номерах (нужна show running-config — укажите пароль enable).</p>'}
    <div class="sub">Конфигурация</div>
    <pre>${esc(cfgText)}</pre>
    <div class="sub">Изменить</div>
    ${dn || ph.lines.length ? `<form id="phForm" class="std-form" autocomplete="off" onsubmit="return false">
      ${dn ? phoneField('Номер (первая линия)', 'number', dn.numbers[0] || '', 'inputmode="numeric"') + phoneField('Имя (name — видно на экране вызываемого)', 'name', dn.name) + phoneField('Подпись кнопки (label)', 'label', dn.label) : ''}
      ${phoneField('Описание телефона (description)', 'description', ph.description)}
      ${modelField(ph.model)}
      ${phoneField('MAC-адрес (при замене аппарата)', 'mac', CmeCmd.ciscoMac(ph.mac) || '')}
      <div id="phOut"></div>
    </form>` : '<p class="muted">Изменение недоступно: нет конфигурации телефона.</p>'}
    <details class="fix"><summary>Перезагрузить телефон</summary>${cmdBox(CmeCmd.restart(ph))}</details>
    <details class="fix"><summary>Удалить телефон</summary>
      <p class="fix-w">⚠ Телефон перестанет работать. Вариант 2 удалит и его номера, если они не используются на других телефонах.</p>
      <div class="fix-v"><div class="fix-t">Вариант 1. Только телефон (номер останется свободным)</div>${cmdBox(CmeCmd.remove(ph, false, c.phones))}</div>
      <div class="fix-v"><div class="fix-t">Вариант 2. Телефон и его номера</div>${cmdBox(CmeCmd.remove(ph, true, c.phones))}</div>
    </details>`);
  updatePhoneCmds();
}

function formVals(form) {
  const o = {};
  for (const el of form.elements) if (el.name) o[el.name] = CmeCmd.clean(el.value);
  return o;
}

function updatePhoneCmds() {
  const form = $('#phForm');
  if (!form || !PHONE_EDIT) return;
  const { c, ph } = PHONE_EDIT;
  const f = formVals(form);
  const v = CmeCmd.validate(f, (c.state && c.state.used) || {}, ph);
  const cmds = v.errors.length ? '' : CmeCmd.edit(ph, f);
  $('#phOut').innerHTML = (v.errors.length ? `<p class="fix-w">✗ ${v.errors.map(esc).join('<br>✗ ')}</p>` : '') +
    v.warnings.map(w => `<p class="fix-w">⚠ ${esc(w)}</p>`).join('') +
    (cmds ? cmdBox(cmds) + `<p class="fix-n">Выполните на роутере и сохраните: <code>write memory</code>.${ph.proto === 'sccp' ? ' Команда restart перезапустит телефон, чтобы он получил новые настройки.' : ' Для SIP после изменений создаётся профиль (create profile); телефон может потребовать перезагрузки.'}</p>`
      : (v.errors.length ? '' : '<p class="muted" style="margin:0">Измените поля выше — здесь появятся команды.</p>'));
}

function openNewPhone(mac) {
  const c = CME || CMES[0];
  if (!c) return;
  if (!CME) selectSwitch('cme:' + c.id);
  const used = (c.state && c.state.used) || {};
  const free = (c.state && c.state.freeDns) || [];
  const where = mac ? locateMac(mac) : null;
  openDrawer('Новый телефон', `<form id="newPhForm" class="std-form" autocomplete="off" onsubmit="return false">
    <p class="hint">Для SCCP-телефона (ephone). Номера ephone и ephone-dn подобраны свободные.</p>
    ${phoneField('MAC-адрес телефона', 'mac', mac ? CmeCmd.ciscoMac(mac) : '', 'placeholder="0019.AA7B.1234"')}
    ${where ? `<p class="fix-n">Этот MAC сейчас на ${esc(where.sw ? where.sw.name : '')} · ${esc(where.p.short)}${where.p.desc ? ' (' + esc(where.p.desc) + ')' : ''}.</p>` : ''}
    ${modelField('')}
    <label class="field">Номер
      <select name="dnId"><option value="">Новый номер</option>${free.map(d => `<option value="${d.id}">Свободный: ${esc(d.numbers.join(', '))}${d.name ? ' · ' + esc(d.name) : ''} (ephone-dn ${d.id})</option>`).join('')}</select>
    </label>
    <div id="newDnFields">
      ${phoneField('Внутренний номер', 'number', '', 'inputmode="numeric" placeholder="например, 2400"')}
      ${phoneField('Имя (name)', 'name', '', 'placeholder="Ivanova Anna"')}
      ${phoneField('Подпись кнопки (label)', 'label', '')}
    </div>
    ${phoneField('Описание телефона (description)', 'description', '', 'placeholder="kab 305"')}
    <div class="row-chk muted" style="font-size:12.5px">ephone <input name="ephoneId" type="number" min="1" value="${CmeCmd.nextFree(used.ephone)}" style="width:80px">
      ephone-dn <input name="newDnId" type="number" min="1" value="${CmeCmd.nextFree(used.ephoneDn)}" style="width:80px"></div>
    <div id="newPhOut"></div>
  </form>`);
  PHONE_EDIT = { c, ph: null };
  updateNewPhoneCmds();
}

function updateNewPhoneCmds() {
  const form = $('#newPhForm');
  if (!form || !PHONE_EDIT) return;
  const { c } = PHONE_EDIT;
  const used = (c.state && c.state.used) || {};
  const f = formVals(form);
  const existingDn = !!f.dnId;
  $('#newDnFields').hidden = existingDn;
  const check = { mac: f.mac, model: f.model, description: f.description, name: existingDn ? '' : f.name, label: existingDn ? '' : f.label };
  if (!existingDn) check.number = f.number;
  const v = CmeCmd.validate(check, used, null);
  const errors = [...v.errors];
  if (!f.mac) errors.push('Укажите MAC-адрес');
  if ((used.ephone || []).includes(+f.ephoneId)) errors.push(`ephone ${f.ephoneId} уже занят`);
  if (!existingDn && (used.ephoneDn || []).includes(+f.newDnId)) errors.push(`ephone-dn ${f.newDnId} уже занят`);
  if (PHONES && f.mac && CmeCmd.ciscoMac(f.mac)) {
    const h = f.mac.replace(/[^0-9a-f]/gi, '').toLowerCase();
    const dup = [...PHONES.values()].find(p => p.mac.replace(/-/g, '') === h);
    if (dup) errors.push(`Телефон с этим MAC уже есть: ${dup.id} (${dup.numbers.join(', ')})`);
  }
  const r = errors.length ? null : CmeCmd.create({ ...f, ephoneId: +f.ephoneId, newDnId: +f.newDnId, dnId: f.dnId ? +f.dnId : null }, used);
  $('#newPhOut').innerHTML = (errors.length ? `<p class="fix-w">✗ ${errors.map(esc).join('<br>✗ ')}</p>` : '') +
    v.warnings.map(w => `<p class="fix-w">⚠ ${esc(w)}</p>`).join('') +
    (r ? cmdBox(r.commands) + '<p class="fix-n">Выполните на роутере и сохраните: <code>write memory</code>. Телефон зарегистрируется после подключения к сети (для 79xx может понадобиться прошивка на TFTP).</p>' : '');
}

/* ---------- STP ---------- */
const STP_ROLE = { ROOT: 'корневой', DESI: 'назначенный', ALTE: 'резервный', BACK: 'запасной', MAST: 'master', DISA: 'выключен', NONE: '—' };

// Имя коммутатора по идентификатору моста (MAC после точки)
function bridgeName(id) {
  const mac = String(id || '').split('.').pop().toLowerCase();
  for (const s of SWITCHES) if (s.cfg && s.cfg.state && s.cfg.state.stp && String(s.cfg.state.stp.bridge).split('.').pop().toLowerCase() === mac) return s.name;
  return '';
}
function stpRoleBadge(x) {
  if (!x) return '<span class="muted">—</span>';
  const cls = x.role === 'ROOT' ? 'stp-root' : (x.role === 'ALTE' || x.role === 'BACK') ? 'stp-alt' : x.role === 'DESI' ? 'stp-desi' : 'stp-other';
  return `<span class="stp-role ${cls}" title="${esc(STP_ROLE[x.role] || x.role)}">${esc(x.role)}</span>`;
}

function renderStp(cfg, sw) {
  const sc = stpConfig(cfg);
  const stp = cfg.state && cfg.state.stp && cfg.state.stp.bridge ? cfg.state.stp : null;
  const issues = cfg.issues.filter(i => /^stp-/.test(i.kind || ''));
  $('#stpCount').textContent = issues.filter(i => i.sev !== 'info').length || '';
  const rp = stp && stp.rootPort ? cfg.ports.find(p => p.name === stp.rootPort) : null;
  const rootName = stp ? (stp.isRoot ? 'этот коммутатор' : bridgeName(stp.root) || (rp && rp.lldp && rp.lldp[0] ? `за портом — сосед ${rp.lldp[0].device}` : '')) : '';
  $('#stpSummary').innerHTML = `<dl class="kv">
      <dt>Состояние</dt><dd>${sc.disabled || (stp && stp.disabled) ? '<span class="flag warn">выключен</span>' : '<span class="flag">включён</span>'}</dd>
      <dt>Режим</dt><dd>${esc((stp && stp.mode) || sc.mode.toUpperCase() || 'MSTP (по умолчанию)')}</dd>
      <dt>Приоритет моста</dt><dd>${sc.priority != null ? `<b>${sc.priority}</b> (задан в конфигурации)` : '32768 (по умолчанию)'}</dd>
      ${stp ? `<dt>Этот мост</dt><dd class="mono">${esc(stp.bridge)}</dd>
      <dt>Корневой мост</dt><dd><span class="mono">${esc(stp.root)}</span>${rootName ? ` <span class="muted">— ${esc(rootName)}</span>` : ''}</dd>
      <dt>Корневой порт</dt><dd>${rp ? `${portLink(rp)}${rp.desc ? ` <span class="muted">${esc(rp.desc)}</span>` : ''}` : stp.isRoot ? '<span class="muted">нет (коммутатор сам корень)</span>' : esc(stp.rootPort || '—')}</dd>
      <dt>Стоимость до корня</dt><dd>${stp.rootCost ?? '—'}</dd>
      <dt>Таймеры</dt><dd class="muted">${esc(stp.times || '—')}</dd>` : ''}
    </dl>
    ${sc.lines.length ? `<div class="sub">Глобальные настройки STP</div><pre>${esc(sc.lines.join('\n'))}</pre>` : '<p class="hint" style="margin:10px 0 0">Глобальных настроек STP в конфигурации нет — используются значения по умолчанию.</p>'}`;

  const tcPort = stp && stp.lastTcPort ? cfg.ports.find(p => p.name === stp.lastTcPort) : null;
  $('#stpTc').innerHTML = stp ? `<dl class="kv">
      <dt>Изменений топологии</dt><dd><b>${stp.tcCount}</b> <span class="muted">(получено TC/TCN: ${stp.tcReceived})</span></dd>
      <dt>Последнее</dt><dd>${stp.lastTcSec != null ? esc(fmtUptime(stp.lastTcSec)) + ' назад' : '—'}</dd>
      <dt>Через порт</dt><dd>${tcPort ? portLink(tcPort) + (tcPort.desc ? ` <span class="muted">${esc(tcPort.desc)}</span>` : '') : esc(stp.lastTcPort || '—')}</dd>
      <dt>BPDU-protection</dt><dd>${stp.bpduProtection || sc.bpduProtection ? '<span class="flag">включена</span>' : '<span class="flag warn">выключена</span>'}</dd>
      <dt>Edged по умолчанию</dt><dd>${sc.edgedDefault ? 'да (stp edged-port default)' : 'нет'}</dd>
      <dt>Заблокировано резервных</dt><dd>${Object.values(stp.ports).filter(x => (x.role === 'ALTE' || x.role === 'BACK') && x.state === 'DISCARDING').length}</dd>
    </dl>` : '<p class="muted" style="margin:0">Нет данных о текущем состоянии STP — нажмите «Обновить с коммутатора».</p>';

  $('#stpIssuesCard').hidden = !issues.length;
  const SEV = { high: 'Важно', med: 'Внимание', info: 'Инфо' };
  $('#stpIssues').innerHTML = issues.map(i => `<div class="issue sev-${i.sev}" style="padding:10px 14px">
      <div class="ih"><span class="sev">${SEV[i.sev]}</span><span class="it">${esc(i.title)}</span></div>
      <div class="ib">${esc(i.body)}</div>
      ${i.ports ? `<div class="ip"><span class="mono muted">${esc(compressPorts(i.ports))}</span></div>` : ''}
      ${fixHtml(i, cfg)}</div>`).join('');
  renderStpPorts(cfg);
  $('#stpNote').textContent = stp ? `Данные ${ago(cfg.state.at)}. Учитывается экземпляр 0 (CIST).` : '';
}

function renderStpPorts(cfg) {
  const sc = stpConfig(cfg);
  const live = cfg.state && cfg.state.stp ? cfg.state.stp.ports : {};
  const f = $('#stpFilter').value;
  const user = p => ['access', 'ap', 'printer', 'test'].includes(p.role);
  const rows = cfg.ports.filter(p => {
    const x = live[p.name];
    if (!x && !p.stpLines.length && !(user(p) && p.lines.length)) return false;
    if (f === 'nondesi') return x && x.role !== 'DESI';
    if (f === 'blocked') return x && x.state === 'DISCARDING';
    if (f === 'edged') return stpEdged(p, sc);
    if (f === 'noedge') return user(p) && p.lines.length && !p.shutdown && !stpEdged(p, sc);
    if (f === 'cfg') return p.stpLines.length > 0;
    return !!x || p.stpLines.length > 0;
  }).sort((a, b) => {
    const r = x => ({ ROOT: 0, ALTE: 1, BACK: 2 }[(live[x.name] || {}).role] ?? 3);
    return r(a) - r(b) || portSort(a, b);
  });
  $('#stpPorts').innerHTML = `<thead><tr><th>Порт</th><th>Роль STP</th><th>Состояние</th><th>Защита</th><th>Edged</th><th>Назначение</th><th>Сосед / описание</th><th>Настройки STP</th></tr></thead><tbody>` +
    rows.slice(0, 400).map(p => { const x = live[p.name]; return `<tr data-port="${esc(p.name)}">
      <td class="mono"><b>${esc(p.short)}</b></td>
      <td>${stpRoleBadge(x)}</td>
      <td>${x ? `<span class="${x.state === 'FORWARDING' ? 'live live-up' : 'flag warn'}">${esc(x.state.toLowerCase())}</span>` : '<span class="muted">—</span>'}</td>
      <td>${x && x.protection !== 'NONE' ? `<span class="flag warn">${esc(x.protection)}</span>` : '<span class="muted">—</span>'}</td>
      <td>${stpEdged(p, sc) ? '<span class="flag">да</span>' : '<span class="muted">нет</span>'}</td>
      <td>${roleChip(p.role)}</td>
      <td>${p.lldp && p.lldp.length ? connectedText(p) : esc(p.desc || '')}</td>
      <td class="mono" style="font-size:12px">${esc(p.stpLines.join('; ')) || '<span class="muted">—</span>'}</td>
    </tr>`; }).join('') + '</tbody>' + (rows.length ? '' : '<tbody><tr><td colspan="8" class="muted">Нет портов под этот фильтр</td></tr></tbody>');
}

function renderStpAll(withCfg) {
  const rows = withCfg.filter(s => s.cfg.state && s.cfg.state.stp && s.cfg.state.stp.bridge);
  $('#stpAllCard').hidden = !rows.length;
  if (!rows.length) return;
  const roots = [...new Set(rows.map(s => s.cfg.state.stp.root))];
  $('#stpAllWarn').innerHTML = roots.length > 1 ? `<div class="issue sev-high" style="padding:8px 12px;margin-bottom:10px"><div class="ih"><span class="sev">Важно</span>
      <span class="it">У коммутаторов разные корневые мосты: ${roots.map(r => esc(bridgeName(r) || r)).join(', ')}</span></div>
      <div class="ib">В одной сети корень должен быть один. Возможно, сеть разделена на несвязанные части, или где-то STP выключен на линке.</div></div>`
    : `<p class="hint">Все коммутаторы видят один корневой мост: <b>${esc(bridgeName(roots[0]) || roots[0])}</b>.</p>`;
  $('#stpAll').innerHTML = `<thead><tr><th>Коммутатор</th><th>Режим</th><th>Корневой мост</th><th>Корневой порт</th><th>Стоимость</th><th>Последнее TC</th><th>BPDU-protection</th><th>Замечания</th></tr></thead><tbody>` +
    rows.map(s => {
      const stp = s.cfg.state.stp, sc = stpConfig(s.cfg);
      const rp = s.cfg.ports.find(p => p.name === stp.rootPort);
      const iss = s.cfg.issues.filter(i => /^stp-/.test(i.kind || '') && i.sev !== 'info');
      return `<tr data-open-sw="${esc(s.id)}" data-open-tab="stp">
        <td><b>${esc(s.name)}</b></td>
        <td>${esc(stp.mode || sc.mode || '—')}</td>
        <td>${stp.isRoot ? '<b>этот коммутатор</b>' : esc(bridgeName(stp.root) || stp.root)}</td>
        <td class="mono">${rp ? esc(rp.short) + (rp.desc ? ` <span class="muted">${esc(rp.desc)}</span>` : '') : '—'}</td>
        <td>${stp.rootCost ?? '—'}</td>
        <td>${stp.lastTcSec != null ? esc(fmtUptime(stp.lastTcSec)) + ' назад' : '—'}</td>
        <td>${stp.bpduProtection || sc.bpduProtection ? '<span class="flag">да</span>' : '<span class="flag warn">нет</span>'}</td>
        <td>${iss.length ? iss.map(i => `<span class="flag warn" title="${esc(i.title)}">${esc(i.title.length > 38 ? i.title.slice(0, 37) + '…' : i.title)}</span>`).join(' ') : '<span class="flag">норма</span>'}</td>
      </tr>`;
    }).join('') + '</tbody>';
}

/* ---------- оборудование и схема сети (этап 5) ---------- */
const HW_CMDS = ['display version', 'display device', 'display stack', 'display cpu-usage', 'display memory-usage', 'display temperature all', 'display power', 'display fan', 'display transceiver verbose'];

function fmtUptime(sec) {
  if (sec == null) return '—';
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600);
  const mm = Math.floor((sec % 3600) / 60);
  return d ? `${d} ${plural(d, 'день', 'дня', 'дней')}${hh ? ` ${hh} ч` : ''}` : hh ? `${hh} ч ${mm} мин` : `${mm} мин`;
}
function bar(pct, warn = 80, bad = 95) {
  if (pct == null) return '<span class="muted">—</span>';
  const cls = pct >= bad ? 'bad' : pct >= warn ? 'mid' : 'ok';
  return `<span class="bar ${cls}"><span style="width:${Math.min(100, pct)}%"></span></span> <b>${pct}%</b>`;
}
const stateOk = v => /^(normal|supply|ok|on)$/i.test(v || '');

function renderHardware(cfg, sw) {
  const hw = cfg.state && cfg.state.hw;
  const on = !!hw;
  $('#hwTabBtn').hidden = !on;
  if (!on) return;
  const probs = hw.problems || [];
  $('#hwCount').textContent = probs.filter(p => p.sev !== 'info').length || '';
  const SEV = { high: 'Важно', med: 'Внимание', info: 'Инфо' };
  $('#hwProblemsCard').hidden = !probs.length;
  $('#hwProblems').innerHTML = probs.map(p => `<div class="issue sev-${p.sev}" style="padding:8px 12px">
      <div class="ih"><span class="sev">${SEV[p.sev]}</span><span class="it">${esc(p.text)}</span>
      ${p.port ? `<button class="plink" data-port="${esc(p.port)}">открыть порт</button>` : ''}</div>
      ${fixHtml({ kind: 'hw', data: { key: p.key, cmd: p.cmd } }, cfg)}</div>`).join('');

  const v = hw.version || {};
  const dev = hw.device || [];
  const members = (hw.stack && hw.stack.members) || [];
  const slots = [...new Set([...dev.map(d => d.slot), ...members.map(m => m.slot)])].sort((a, b) => a - b);
  $('#hwDevice').innerHTML = `<dl class="kv">
      <dt>Модель</dt><dd>${esc(v.model || (dev[0] && dev[0].type) || '—')}</dd>
      <dt>ПО</dt><dd>${esc(v.software || cfg.version || '—')}${v.patch ? ` · патч ${esc(v.patch)}` : ''}</dd>
      <dt>Работает без перезагрузки</dt><dd>${esc(fmtUptime(v.uptimeSec))}</dd>
      <dt>Стек</dt><dd>${hw.stack && hw.stack.topology ? `${esc(hw.stack.topology)}${/ring/i.test(hw.stack.topology) ? ' (кольцо)' : /chain|link/i.test(hw.stack.topology) ? ' (цепочка)' : ''}` : '—'}</dd>
    </dl>
    ${slots.length ? `<table class="tbl static" style="margin-top:10px"><thead><tr><th>Слот</th><th>Роль</th><th>Модель</th><th>Состояние</th></tr></thead><tbody>
      ${slots.map(sl => { const d = dev.find(x => x.slot === sl) || {}, m = members.find(x => x.slot === sl) || {};
        return `<tr><td>${sl}</td><td>${esc(m.role || d.role || '—')}</td><td class="mono">${esc(d.type || m.type || '—')}</td>
          <td>${d.status ? `<span class="flag ${/^normal$/i.test(d.status) ? '' : 'warn'}">${esc(d.status)}</span>` : '—'}</td></tr>`; }).join('')}
    </tbody></table>` : ''}`;

  const temps = hw.temperature || [];
  $('#hwEnv').innerHTML = `<dl class="kv">
      <dt>CPU</dt><dd>${bar(hw.cpu && hw.cpu.now)}${hw.cpu && hw.cpu.max != null ? ` <span class="muted">макс. ${hw.cpu.max}%</span>` : ''}</dd>
      <dt>Память</dt><dd>${bar(hw.memory && hw.memory.percent, 85, 95)}</dd>
    </dl>
    ${temps.length ? `<div class="sub">Температура</div><table class="tbl static"><thead><tr><th>Слот</th><th>Сейчас</th><th>Порог</th><th>Состояние</th></tr></thead><tbody>
      ${temps.map(t => `<tr><td>${t.slot}</td><td><b>${t.current}°C</b></td><td>${t.upper != null ? t.upper + '°C' : '—'}</td>
        <td><span class="flag ${t.status === 'NORMAL' && !(t.upper != null && t.current >= t.upper - 5) ? '' : 'warn'}">${esc(t.status)}</span></td></tr>`).join('')}</tbody></table>` : ''}
    ${(hw.power || []).length ? `<div class="sub">Питание</div><table class="tbl static"><thead><tr><th>Слот</th><th>Блок</th><th>Установлен</th><th>Состояние</th><th>Вт</th></tr></thead><tbody>
      ${hw.power.map(p => `<tr><td>${p.slot}</td><td>${esc(p.id)}</td><td>${esc(p.online)}</td>
        <td>${/^absent$/i.test(p.online) ? '<span class="muted">—</span>' : `<span class="flag ${stateOk(p.state) ? '' : 'warn'}">${esc(p.state)}</span>`}</td><td>${p.watts ?? '—'}</td></tr>`).join('')}</tbody></table>` : ''}
    ${(hw.fan || []).length ? `<div class="sub">Вентиляторы</div><table class="tbl static"><thead><tr><th>Слот</th><th>Модуль</th><th>Состояние</th><th>Скорость</th></tr></thead><tbody>
      ${hw.fan.map(f => `<tr><td>${f.slot}</td><td>${esc(f.id)}</td><td><span class="flag ${stateOk(f.status) ? '' : 'warn'}">${esc(f.status)}</span></td><td>${f.speed != null ? f.speed + '%' : '—'}</td></tr>`).join('')}</tbody></table>` : ''}`;

  const sfp = Object.entries(hw.transceiver || {});
  const probKeys = new Map(probs.map(p => [p.key, p]));
  const dbm = (v, lo, hi) => v == null ? '<span class="muted">—</span>'
    : `<b>${v}</b>${lo != null || hi != null ? ` <span class="muted">(${lo ?? '…'} … ${hi ?? '…'})</span>` : ''}`;
  $('#hwSfp').innerHTML = sfp.length ? `<div class="table-scroll"><table class="tbl"><thead><tr><th>Порт</th><th>Сейчас</th><th>Модуль</th><th>λ, нм</th><th>Rx, дБм (пороги)</th><th>Tx, дБм (пороги)</th><th>t°C</th><th>Оценка</th></tr></thead><tbody>
    ${sfp.sort((a, b) => a[0].localeCompare(b[0], 'en', { numeric: true })).map(([port, x]) => {
      const p = cfg.ports.find(y => y.name === port);
      const pr = probKeys.get('sfp-rx:' + port) || probKeys.get('sfp-tx:' + port);
      return `<tr data-port="${esc(port)}">
        <td class="mono"><b>${esc(shortName(port))}</b>${p && p.desc ? ` <span class="muted">${esc(p.desc)}</span>` : ''}</td>
        <td>${p ? liveBadge(p) : '—'}</td>
        <td>${esc(x.type || '—')}<div class="muted" style="font-size:12px">${esc([x.vendor, x.part].filter(Boolean).join(' · '))}</div></td>
        <td>${esc(x.wavelength || '—')}</td>
        <td>${dbm(x.rx, x.rxLow, x.rxHigh)}</td>
        <td>${dbm(x.tx, x.txLow, x.txHigh)}</td>
        <td>${x.temp ?? '—'}</td>
        <td>${pr ? `<span class="flag warn">${pr.sev === 'high' ? 'плохо' : 'на грани'}</span>` : (p && p.st && p.st.status === 'up' && x.rx != null ? '<span class="flag">норма</span>' : '<span class="muted">—</span>')}</td>
      </tr>`; }).join('')}
    </tbody></table></div>` : '<p class="muted" style="margin:0">SFP-модули не найдены (или команда не поддерживается).</p>';

  const failed = HW_CMDS.filter(c => cfg.state.errors && cfg.state.errors[c]);
  $('#hwNote').textContent = `Данные ${ago(cfg.state.at)}.` + (failed.length ? ` Не поддерживаются этим коммутатором: ${failed.join(', ')}.` : '');
}

// Граф связей по LLDP: коммутаторы из списка и соседние коммутаторы, которых в списке нет
function topology(list) {
  const key = n => String(n || '').trim().toUpperCase();
  const nodes = new Map();
  for (const { sw, cfg } of list) nodes.set(key(cfg.sysname || sw.name), { id: key(cfg.sysname || sw.name), name: sw.name, sw, cfg, managed: true });
  const edges = new Map();
  for (const { sw, cfg } of list) {
    const a = key(cfg.sysname || sw.name);
    for (const p of cfg.ports) for (const n of p.lldp || []) {
      const b = key(n.device);
      if (!b || b === a) continue;
      const known = nodes.has(b) && nodes.get(b).managed;
      // Телефоны и точки доступа на пользовательских портах на схему не выносим
      if (!known && !['uplink', 'link', 'trunk'].includes(p.role) && (p.macs || []).length <= 5) continue;
      if (!nodes.has(b)) nodes.set(b, { id: b, name: n.device, managed: false });
      const [x, y] = [a, b].sort();
      const ek = x + '||' + y;
      if (!edges.has(ek)) edges.set(ek, { a: x, b: y, links: [] });
      const e = edges.get(ek);
      const mine = p.short, theirs = shortName(n.remotePort || '');
      const rec = a === x ? { pa: mine, pb: theirs } : { pa: theirs, pb: mine };
      const up = p.st ? p.st.status === 'up' : null;
      const same = e.links.find(l => l.pa === rec.pa && l.pb === rec.pb);
      if (same) { if (up === false) same.up = false; } else e.links.push({ ...rec, up });
    }
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

function renderMap(withCfg) {
  const withLive = withCfg.filter(s => s.cfg.state).map(s => ({ sw: s, cfg: s.cfg }));
  const { nodes, edges } = topology(withLive);
  $('#mapCard').hidden = !withLive.length;
  if (!withLive.length) return;
  if (!edges.length) {
    $('#netMap').innerHTML = '<p class="muted" style="margin:0">Связи между коммутаторами по LLDP не найдены. Проверьте, что LLDP включён на коммутаторах и на аплинках.</p>';
    $('#mapLegend').innerHTML = '';
    return;
  }
  // Уровни: обход в ширину от узла с наибольшим числом связей
  const deg = new Map(nodes.map(n => [n.id, 0]));
  for (const e of edges) { deg.set(e.a, deg.get(e.a) + 1); deg.set(e.b, deg.get(e.b) + 1); }
  const adj = new Map(nodes.map(n => [n.id, []]));
  for (const e of edges) { adj.get(e.a).push(e.b); adj.get(e.b).push(e.a); }
  const level = new Map();
  const order = [...nodes].sort((a, b) => deg.get(b.id) - deg.get(a.id) || (b.managed - a.managed));
  for (const start of order) {
    if (level.has(start.id)) continue;
    const base = level.size ? Math.max(...level.values()) + 1 : 0;
    level.set(start.id, base);
    const q = [start.id];
    while (q.length) { const c = q.shift(); for (const nb of adj.get(c)) if (!level.has(nb)) { level.set(nb, level.get(c) + 1); q.push(nb); } }
  }
  const rows = [];
  for (const n of nodes) (rows[level.get(n.id)] ||= []).push(n);
  const W = 170, H = 50, colW = 200, rowH = 130;
  const width = Math.max(640, Math.max(...rows.map(r => (r || []).length)) * colW);
  const height = rows.length * rowH + 20;
  const pos = new Map();
  rows.forEach((r, li) => (r || []).forEach((n, i) => pos.set(n.id, { x: (i + 0.5) * width / r.length, y: 40 + li * rowH })));

  const lines = edges.map(e => {
    const A = pos.get(e.a), B = pos.get(e.b);
    const down = e.links.some(l => l.up === false), up = e.links.every(l => l.up === true);
    const cls = down ? 'down' : up ? 'up' : 'unk';
    // Подпись порта — сразу за краем прямоугольника узла, на линии связи
    const lab = (t, from, to) => {
      const dx = to.x - from.x, dy = to.y - from.y;
      const k = Math.min(0.45, Math.min(dy ? (H / 2 + 14) / Math.abs(dy) : Infinity, dx ? (W / 2 + 22) / Math.abs(dx) : Infinity));
      return `<text class="m-port" x="${from.x + dx * k}" y="${from.y + dy * k + 4}" text-anchor="middle">${esc(t)}</text>`;
    };
    const pa = e.links.map(l => l.pa).filter(Boolean).join(', '), pb = e.links.map(l => l.pb).filter(Boolean).join(', ');
    const title = e.links.map(l => `${l.pa || '?'} ↔ ${l.pb || '?'}${l.up === false ? ' (не работает)' : ''}`).join('\n');
    return `<g class="m-edge ${cls}"><title>${esc(title)}</title><line x1="${A.x}" y1="${A.y}" x2="${B.x}" y2="${B.y}"/>${e.links.length > 1 ? `<text class="m-count" x="${(A.x + B.x) / 2}" y="${(A.y + B.y) / 2 - 4}" text-anchor="middle">${e.links.length}×</text>` : ''}${lab(pa, A, B)}${lab(pb, B, A)}</g>`;
  }).join('');
  const boxes = nodes.map(n => {
    const { x, y } = pos.get(n.id);
    const hwp = n.managed && n.cfg.state && n.cfg.state.hw ? n.cfg.state.hw.problems.filter(p => p.sev === 'high').length : 0;
    const high = n.managed ? n.cfg.issues.filter(i => i.sev === 'high').length : 0;
    const cls = !n.managed ? 'ext' : n.sw.lastError ? 'err' : (hwp || high) ? 'warn' : 'ok';
    const sub = n.managed ? ((n.cfg.state.hw && n.cfg.state.hw.version.model) || n.sw.host) : 'нет в списке';
    const nm = n.name.length > 22 ? n.name.slice(0, 21) + '…' : n.name;
    return `<g class="m-node ${cls}" ${n.managed ? `data-open-sw="${esc(n.sw.id)}"` : ''} transform="translate(${x - W / 2},${y - H / 2})">
      <title>${esc(n.name)}${n.managed ? '' : ' — этого коммутатора нет в списке'}</title>
      <rect width="${W}" height="${H}" rx="8"/><text class="m-name" x="${W / 2}" y="21" text-anchor="middle">${esc(nm)}</text>
      <text class="m-sub" x="${W / 2}" y="38" text-anchor="middle">${esc(sub)}</text></g>`;
  }).join('');
  $('#netMap').innerHTML = `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="Схема сети">${lines}${boxes}</svg>`;
  $('#mapLegend').innerHTML = [
    ['ok', 'коммутатор из списка'], ['warn', 'есть важные замечания'], ['err', 'не отвечает'], ['ext', 'сосед, которого нет в списке'],
  ].map(([c, t]) => `<span class="legend-st"><span class="m-sw ${c}"></span>${t}</span>`).join('') +
    '<span class="legend-st"><span class="m-ln up"></span>линк работает</span><span class="legend-st"><span class="m-ln down"></span>не работает</span>';
}

function renderHwTable(withCfg) {
  const rows = withCfg.filter(s => s.cfg.state && s.cfg.state.hw);
  $('#hwTableCard').hidden = !rows.length;
  if (!rows.length) return;
  $('#hwTable').innerHTML = `<thead><tr><th>Коммутатор</th><th>Модель</th><th>ПО</th><th>Без перезагрузки</th><th>CPU</th><th>Память</th><th>Макс. t°</th><th>Проблемы</th></tr></thead><tbody>` +
    rows.map(s => {
      const hw = s.cfg.state.hw, v = hw.version || {};
      const maxT = (hw.temperature || []).reduce((m, t) => Math.max(m, t.current), -Infinity);
      const pr = hw.problems || [];
      return `<tr data-open-sw="${esc(s.id)}" data-open-tab="hw">
        <td><b>${esc(s.name)}</b></td>
        <td class="mono">${esc(v.model || '—')}${s.cfg.members.length > 1 ? ` <span class="muted">× ${s.cfg.members.length}</span>` : ''}</td>
        <td class="mono">${esc(v.software || s.cfg.version || '—')}</td>
        <td>${esc(fmtUptime(v.uptimeSec))}</td>
        <td>${hw.cpu && hw.cpu.now != null ? hw.cpu.now + '%' : '—'}</td>
        <td>${hw.memory && hw.memory.percent != null ? hw.memory.percent + '%' : '—'}</td>
        <td>${Number.isFinite(maxT) ? maxT + '°C' : '—'}</td>
        <td>${pr.length ? pr.map(p => `<span class="flag ${p.sev === 'info' ? '' : 'warn'}" title="${esc(p.text)}">${esc(p.text.length > 40 ? p.text.slice(0, 39) + '…' : p.text)}</span>`).join(' ') : '<span class="flag">норма</span>'}</td>
      </tr>`;
    }).join('') + '</tbody>';
}

/* ---------- эталон (этап 4) ---------- */
let STD = null;

const splitLines = v => String(v || '').split(/[\n,;]+/).map(x => x.trim()).filter(Boolean);

function changeChips(lines) {
  return lines.slice(0, 6).map(l => /^undo /.test(l)
    ? `<span class="chg chg-del">− ${esc(l.slice(5))}</span>`
    : `<span class="chg chg-add">+ ${esc(l)}</span>`).join('') + (lines.length > 6 ? ` <span class="muted">и ещё ${lines.length - 6}</span>` : '');
}

function renderStandard(cfg, sw) {
  const on = SERVER && !!sw && typeof Standard !== 'undefined';
  $('#standardTabBtn').hidden = !on;
  if (!on) return;
  if (!STD) {
    $('#stdCount').textContent = '';
    $('#stdSummary').innerHTML = `<h2>Эталон ещё не задан</h2>
      <p class="hint">Эталон — это то, как должны быть настроены порты каждого типа и общие параметры (NTP, syslog, SNMP, SSH, доступ к консоли). Он один для всех коммутаторов.
      Проще всего взять за основу этот коммутатор: порты — по самой частой настройке, общие параметры — как сейчас, плюс рекомендуемые правила безопасности. Потом его можно поправить.</p>
      <button class="btn primary" data-std-create>Создать эталон на основе ${esc(sw.name)}</button>`;
    $('#stdRulesCard').hidden = $('#stdPortsCard').hidden = true;
    return;
  }
  const rep = Standard.check(cfg, STD);
  const pct = Standard.score(rep);
  const bad = rep.rules.filter(r => !r.ok).length + rep.portGroups.reduce((n, g) => n + g.ports.length, 0);
  $('#stdCount').textContent = bad || '';
  $('#stdSummary').innerHTML = `<div class="std-sum">
      <div class="std-pct ${pct === 100 ? 'ok' : pct >= 80 ? 'mid' : 'bad'}">${pct}%</div>
      <div class="grow">
        <div><b>Соответствие эталону</b> <span class="muted">· эталон от ${esc(fmtTime(STD.updatedAt))}${STD.createdFrom ? `, основа — ${esc(STD.createdFrom)}` : ''}</span></div>
        <div class="muted">Общие настройки: ${rep.totals.rulesOk} из ${rep.totals.rules} · порты: ${rep.totals.portsOk} из ${rep.totals.ports} по эталону</div>
      </div>
      <button class="btn small" data-std-edit>Изменить эталон</button>
    </div>
    ${rep.allCommands ? `<details class="fix"><summary>Все исправления одним блоком</summary><p class="fix-n">Сначала просмотрите отдельные пункты ниже — особенно предупреждения.</p>${cmdBox(rep.allCommands)}</details>` : '<p class="muted" style="margin:10px 0 0">Коммутатор полностью соответствует эталону.</p>'}`;

  $('#stdRulesCard').hidden = !rep.rules.length;
  $('#stdRules').innerHTML = `<ul class="std-rules">${rep.rules.map(r => `<li class="${r.ok ? 'ok' : 'bad'}">
      <span class="mark">${r.ok ? '✓' : '✗'}</span>
      <div class="grow"><b>${esc(r.label)}</b>${r.detail ? ` <span class="muted">— ${esc(r.detail)}</span>` : ''}
        ${!r.ok && r.commands ? `<details class="fix"><summary>Как исправить</summary>${r.warn ? `<p class="fix-w">⚠ ${esc(r.warn)}</p>` : ''}${cmdBox(r.commands)}</details>` : ''}
      </div></li>`).join('')}</ul>`;

  $('#stdPortsCard').hidden = !rep.totals.ports;
  $('#stdPorts').innerHTML = rep.portGroups.length ? rep.portGroups.map(g => `<div class="std-group">
      <div><b>${g.ports.length} ${plural(g.ports.length, 'порт', 'порта', 'портов')}</b> · ${esc(g.label)}</div>
      <div class="mono muted" style="font-size:12px;margin:2px 0 6px">${esc(compressPorts(g.ports))}</div>
      <div>${changeChips(g.change)}</div>
      <details class="fix"><summary>Команды</summary>${cmdBox(g.commands)}</details>
    </div>`).join('') : `<p class="muted" style="margin:0">Все ${rep.totals.ports} проверенных портов настроены по эталону.</p>`;
}

function renderStdMatrix(withCfg) {
  const on = typeof Standard !== 'undefined' && withCfg.length;
  $('#allStdCard').hidden = !on;
  if (!on) return;
  if (!STD) {
    $('#stdMatrix').innerHTML = '<tbody><tr><td class="muted">Эталон ещё не задан. Откройте коммутатор, который считаете образцовым, вкладка «Эталон» → «Создать эталон».</td></tr></tbody>';
    return;
  }
  $('#stdMatrix').innerHTML = `<thead><tr><th>Коммутатор</th><th>Соответствие</th><th>Общие настройки</th><th>Порты</th><th>Главное</th></tr></thead><tbody>` +
    withCfg.map(s => {
      const rep = Standard.check(s.cfg, STD), pct = Standard.score(rep);
      const main = [...rep.rules.filter(r => !r.ok).map(r => r.label), ...rep.portGroups.slice(0, 1).map(g => `${g.ports.length} портов «${g.label}»`)].slice(0, 3);
      return `<tr data-open-sw="${esc(s.id)}" data-open-tab="standard">
        <td><b>${esc(s.name)}</b></td>
        <td><span class="std-pct small ${pct === 100 ? 'ok' : pct >= 80 ? 'mid' : 'bad'}">${pct}%</span></td>
        <td>${rep.totals.rulesOk} / ${rep.totals.rules}</td>
        <td>${rep.totals.portsOk} / ${rep.totals.ports}</td>
        <td class="muted">${esc(main.join(' · ')) || '—'}</td></tr>`;
    }).join('') + '</tbody>';
}

function openStdEditor(std) {
  if (!std) {
    if (!CFG) { toast('Откройте коммутатор, чтобы создать эталон на его основе', 'err'); return; }
    std = Standard.derive(CFG, (SWITCHES.find(x => x.id === state.current) || {}).name);
  }
  const tplBlock = id => `<label class="chk"><input type="checkbox" name="p_${id}_on"> <b>${esc(Standard.TPL_LABEL[id])}</b></label>
    <textarea name="p_${id}" rows="6" spellcheck="false" placeholder="команды интерфейса, по одной в строке"></textarea>`;
  $('#drawerTitle').textContent = 'Эталон';
  $('#drawerBody').innerHTML = `<form id="stdForm" class="std-form">
    <p class="hint">Один эталон для всех коммутаторов. Пустое поле или снятая галочка — правило не проверяется.</p>
    <div class="sub">Шаблоны портов</div>
    <p class="hint">Команды внутри interface, без description. Порт сравнивается с шаблоном своей роли.</p>
    ${['workstation', 'printer', 'ap'].map(tplBlock).join('')}
    <div class="sub">Общие настройки</div>
    <label class="field">NTP-серверы (все должны быть настроены)<textarea name="ntpServers" rows="3" spellcheck="false"></textarea></label>
    <label class="field">Серверы журналов (info-center loghost)<textarea name="syslogHosts" rows="2" spellcheck="false"></textarea></label>
    <div class="field">Разрешённые версии SNMP
      <span class="row-chk"><label class="chk"><input type="checkbox" name="snmp_v1"> v1</label><label class="chk"><input type="checkbox" name="snmp_v2c"> v2c</label><label class="chk"><input type="checkbox" name="snmp_v3"> v3</label></span>
    </div>
    <label class="chk"><input type="checkbox" name="snmpTrap"> SNMP-трапы включены</label>
    <label class="chk"><input type="checkbox" name="sshRequired"> SSH-сервер включён</label>
    <label class="chk"><input type="checkbox" name="telnetForbidden"> Telnet запрещён (сервер и service-type)</label>
    <label class="chk"><input type="checkbox" name="vtyAaa"> Вход по VTY через AAA</label>
    <label class="field">Таймаут VTY-сессии не больше (мин)<input name="vtyIdleMax" type="number" min="1" max="600" placeholder="пусто — не проверять"></label>
    <label class="chk"><input type="checkbox" name="consoleAuth"> Пароль на консольном порту</label>
    <label class="chk"><input type="checkbox" name="lldp"> LLDP включён</label>
    <label class="field">Часовой пояс (строка конфигурации)<input name="timezone" spellcheck="false" placeholder="clock timezone ..."></label>
    <label class="field">Обязательные строки (верхнего уровня, по одной в строке)<textarea name="requiredLines" rows="3" spellcheck="false"></textarea></label>
    <label class="field">Запрещённые строки (начало строки, по одной в строке)<textarea name="forbiddenLines" rows="3" spellcheck="false"></textarea></label>
    <div class="form-actions">
      <button type="submit" class="btn primary">Сохранить эталон</button>
      ${CFG ? '<button type="button" class="btn" data-std-fill>Заполнить из текущего коммутатора</button>' : ''}
      <button type="button" class="btn ghost" data-std-cancel>Отмена</button>
      <span class="form-status" id="stdStatus"></span>
    </div>
  </form>`;
  fillStdForm(std);
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#scrim').hidden = false;
}

function fillStdForm(std) {
  const f = $('#stdForm').elements;
  $('#stdForm').dataset.source = std.createdFrom || '';
  for (const id of ['workstation', 'printer', 'ap']) {
    const t = (std.ports || {})[id] || { enabled: false, lines: [] };
    f['p_' + id + '_on'].checked = !!t.enabled;
    f['p_' + id].value = (t.lines || []).join('\n');
  }
  const g = std.global || {};
  f.ntpServers.value = (g.ntpServers || []).join('\n');
  f.syslogHosts.value = (g.syslogHosts || []).join('\n');
  for (const v of ['v1', 'v2c', 'v3']) f['snmp_' + v].checked = (g.snmpAllowed || []).includes(v);
  for (const k of ['snmpTrap', 'sshRequired', 'telnetForbidden', 'vtyAaa', 'consoleAuth', 'lldp']) f[k].checked = !!g[k];
  f.vtyIdleMax.value = g.vtyIdleMax || '';
  f.timezone.value = g.timezone || '';
  f.requiredLines.value = (g.requiredLines || []).join('\n');
  f.forbiddenLines.value = (g.forbiddenLines || []).join('\n');
}

async function saveStdForm() {
  const form = $('#stdForm'), f = form.elements;
  const lines = v => String(v || '').split('\n').map(x => x.trim()).filter(Boolean);
  const std = {
    version: 1,
    createdFrom: form.dataset.source || (STD && STD.createdFrom) || '',
    ports: Object.fromEntries(['workstation', 'printer', 'ap'].map(id => [id, { enabled: f['p_' + id + '_on'].checked, lines: lines(f['p_' + id].value).filter(l => !/^description /.test(l)) }])),
    global: {
      ntpServers: splitLines(f.ntpServers.value), syslogHosts: splitLines(f.syslogHosts.value),
      snmpAllowed: ['v1', 'v2c', 'v3'].filter(v => f['snmp_' + v].checked),
      snmpTrap: f.snmpTrap.checked, sshRequired: f.sshRequired.checked, telnetForbidden: f.telnetForbidden.checked,
      vtyAaa: f.vtyAaa.checked, vtyIdleMax: f.vtyIdleMax.value ? Math.max(1, Math.round(+f.vtyIdleMax.value)) : null,
      consoleAuth: f.consoleAuth.checked, lldp: f.lldp.checked, timezone: f.timezone.value.trim(),
      requiredLines: lines(f.requiredLines.value), forbiddenLines: lines(f.forbiddenLines.value),
    },
  };
  $('#stdStatus').textContent = 'Сохраняю…';
  try {
    STD = await apiCall('PUT', 'api/standard', std);
    closeDrawer();
    toast('Эталон сохранён', 'ok');
    selectSwitch(state.current, state.current === 'all' ? undefined : 'standard');
  } catch (e) {
    $('#stdStatus').textContent = e.message;
    $('#stdStatus').className = 'form-status err';
  }
}

function setHash() {
  const h = SERVER ? (state.current === 'all' || String(state.current).startsWith('cme:') ? state.current : `${state.current}/${state.tab}`) : state.tab;
  try { history.replaceState(null, '', '#' + h); } catch (e) { /* file:// в некоторых браузерах */ }
}

/* =====================================================================
   События
   ===================================================================== */
function showTab(id) {
  state.tab = id;
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
  $$('.tab').forEach(s => { s.hidden = s.id !== 'tab-' + id; });
  setHash();
}

function cfgFor(el) {
  const sw = el.closest('[data-sw]');
  if (!sw) return CFG;
  const s = SWITCHES.find(x => x.id === sw.dataset.sw);
  return s && s.cfg;
}

function bind() {
  $('#tabs').addEventListener('click', e => { const b = e.target.closest('button[data-tab]'); if (b) showTab(b.dataset.tab); });

  $('#drawerBody').addEventListener('change', e => { if (e.target.id === 'tplSelect') updatePortTool(); });
  $('#drawerBody').addEventListener('submit', e => { if (e.target.id === 'stdForm') { e.preventDefault(); saveStdForm(); } });
  $('#drawerBody').addEventListener('input', e => { if (e.target.id === 'tplDesc') updatePortTool(); });

  document.addEventListener('click', e => {
    const op = e.target.closest('[data-open-phone]');
    if (op && !e.target.closest('[data-goto-port]')) {
      const [cid, mac] = op.dataset.openPhone.split('|');
      if (state.current !== 'cme:' + cid) { selectSwitch('cme:' + cid); window.scrollTo(0, 0); }
      openPhone(mac);
      return;
    }
    const np = e.target.closest('[data-new-phone]');
    if (np) { openNewPhone(np.dataset.newPhone && np.dataset.newPhone !== 'true' ? np.dataset.newPhone : ''); return; }
    if (e.target.closest('[data-std-edit]')) { openStdEditor(STD); return; }
    if (e.target.closest('[data-std-create]')) { openStdEditor(Standard.derive(CFG, (SWITCHES.find(x => x.id === state.current) || {}).name)); return; }
    if (e.target.closest('[data-std-fill]')) { if (CFG) fillStdForm(Standard.derive(CFG, (SWITCHES.find(x => x.id === state.current) || {}).name)); return; }
    if (e.target.closest('[data-std-cancel]')) { closeDrawer(); return; }
    const cp = e.target.closest('[data-copy]');
    if (cp) {
      const text = cp.closest('.cmd-box').querySelector('pre').textContent;
      copyText(text).then(ok => toast(ok ? 'Команды скопированы' : 'Не удалось скопировать — выделите текст вручную', ok ? 'ok' : 'err'));
      return;
    }
    const gt = e.target.closest('[data-goto-port]');
    if (gt) {
      // Переход из результатов поиска: открыть коммутатор и порт
      if (gt.dataset.gotoSw && gt.dataset.gotoSw !== state.current) selectSwitch(gt.dataset.gotoSw, 'overview');
      openPort(gt.dataset.gotoPort);
      return;
    }
    const rb = e.target.closest('[data-restore]');
    if (rb) { openRestore(rb.dataset.restore); return; }
    if (e.target.closest('#restoreGo')) { doRestore(); return; }
    if (e.target.closest('[data-restore-undo]')) { undoRestore(); return; }
    const up = e.target.closest('[data-unpin]');
    if (up) { apiCall('POST', `api/switches/${encodeURIComponent(HIST.sw)}/history/${encodeURIComponent(up.dataset.unpin)}/unpin`, {}).then(() => renderHistory(SWITCHES.find(x => x.id === HIST.sw))).catch(err => toast(err.message, 'err')); return; }
    const vb = e.target.closest('[data-ver-a]');
    if (vb) { $('#verA').value = vb.dataset.verA; $('#verB').value = vb.dataset.verB; showDiff(); $('#cfgDiff').scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    const rs = e.target.closest('[data-refresh-sw]');
    if (rs) { refresh(rs.dataset.refreshSw); return; }
    const pl = e.target.closest('[data-port]');
    if (pl) {
      // Клик по порту на мини-панели общего обзора — открываем этот коммутатор
      const swEl = pl.closest('[data-sw]');
      if (swEl && swEl.dataset.sw !== state.current) selectSwitch(swEl.dataset.sw, 'overview');
      openPort(pl.dataset.port);
      return;
    }
    const os = e.target.closest('[data-open-sw]');
    if (os) { selectSwitch(os.dataset.openSw, os.dataset.openTab || 'overview'); window.scrollTo(0, 0); return; }
    const lg = e.target.closest('.legend-item');
    if (lg) {
      const r = lg.dataset.role;
      state.hiddenRoles.has(r) ? state.hiddenRoles.delete(r) : state.hiddenRoles.add(r);
      renderLegend(); renderPanel(CFG); return;
    }
    const pr = e.target.closest('[data-profile]');
    if (pr) {
      const i = +pr.dataset.profile;
      state.profile = state.profile === i ? null : i;
      renderProfiles(CFG); renderPortTable();
      if (state.profile != null) $('#portTable').scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    if (e.target.id === 'clearProfile') { state.profile = null; renderProfiles(CFG); renderPortTable(); return; }
    const vs = e.target.closest('[data-vlan-show]');
    if (vs) { state.panelVlan = vs.dataset.vlanShow; renderPanel(CFG); showTab('overview'); $('#panel').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  });

  $('#swSelect').addEventListener('change', e => { selectSwitch(e.target.value); window.scrollTo(0, 0); });
  $('#evFilter').addEventListener('change', renderSwEvents);
  $('#backupBtn').addEventListener('click', makeBackup);
  $('#drawerBody').addEventListener('input', e => { if (e.target.id === 'restoreConfirm') $('#restoreGo').disabled = e.target.value.trim() !== e.target.dataset.name; });
  $('#phoneSearch').addEventListener('input', renderPhoneTable);
  $('#cmeSearch').addEventListener('input', renderCmeTable);
  $('#stpFilter').addEventListener('change', () => CFG && renderStpPorts(CFG));
  $('#cmeFilter').addEventListener('change', renderCmeTable);
  $('#drawerBody').addEventListener('input', e => { if (e.target.closest('#phForm')) updatePhoneCmds(); if (e.target.closest('#newPhForm')) updateNewPhoneCmds(); });
  $('#drawerBody').addEventListener('change', e => { if (e.target.closest('#phForm')) updatePhoneCmds(); if (e.target.closest('#newPhForm')) updateNewPhoneCmds(); });
  $('#phoneFilter').addEventListener('change', renderPhoneTable);
  ['#verA', '#verB', '#diffFull'].forEach(id => $(id).addEventListener('change', showDiff));
  $('#refreshBtn').addEventListener('click', () => refresh(state.current));
  $('#findInput').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); showFind(e.target.value); } });

  $('#panelVlan').addEventListener('change', e => { state.panelVlan = e.target.value; renderPanel(CFG); });
  ['#portSearch', '#portMember', '#portRole', '#portVlan', '#portLive', '#portHideEmpty'].forEach(s => $(s).addEventListener('input', renderPortTable));
  $('#portReset').addEventListener('click', () => {
    $('#portSearch').value = ''; $('#portMember').value = ''; $('#portRole').value = ''; $('#portVlan').value = ''; $('#portLive').value = ''; $('#portHideEmpty').checked = true;
    state.profile = null; renderProfiles(CFG); renderPortTable();
  });

  $('#rawSearch').addEventListener('input', () => renderRaw(CFG));
  $('#rawExpand').addEventListener('click', () => $$('#rawList details').forEach(d => { d.open = true; }));
  $('#rawCollapse').addEventListener('click', () => $$('#rawList details').forEach(d => { d.open = false; }));

  $('#drawerClose').addEventListener('click', closeDrawer);
  $('#scrim').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  // Подсказка при наведении на порт (основная панель и мини-панели общего обзора)
  const tip = $('#tip');
  document.addEventListener('mousemove', e => {
    const el = e.target.closest && e.target.closest('.port');
    if (!el) { tip.hidden = true; return; }
    const cfg = cfgFor(el);
    const p = cfg && cfg.ports.find(x => x.name === el.dataset.port);
    if (!p) { tip.hidden = true; return; }
    tip.innerHTML = `<b>${esc(p.short)}</b> · ${esc(ROLES[p.role].label)}${p.desc ? '<br>' + esc(p.desc) : ''}${p.lines.length ? `<br>PVID ${p.effPvid} · VLAN ${esc(rangesText(p.allowed).join(', ') || '—')}` : ''}`;
    tip.hidden = false;
    const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
    const y = e.clientY + 18 + tip.offsetHeight > window.innerHeight ? e.clientY - tip.offsetHeight - 10 : e.clientY + 18;
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
  });

  // Тема
  const root = document.documentElement;
  try { const t = localStorage.getItem('swcfg-theme'); if (t) root.dataset.theme = t; } catch (e) { /* нет доступа */ }
  $('#themeBtn').addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('swcfg-theme', root.dataset.theme); } catch (e) { /* нет доступа */ }
  });

  // Загрузка конфига из файла (без сервера)
  $('#fileInput').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      const text = String(rd.result).replace(/%\^%#[\s\S]*?%\^%#/g, '******').replace(/(irreversible-cipher|cipher)\s+(?!\*{6})\S+/g, '$1 ******');
      state.profile = null; state.panelVlan = ''; state.hiddenRoles.clear();
      render(parseConfig(text));
    };
    rd.readAsText(f);
    e.target.value = '';
  });
}

/* ===================================================================== */
async function boot() {
  bind();
  const hash = decodeURIComponent(location.hash.slice(1));
  let ok = false;
  if (location.protocol.startsWith('http')) {
    try { await loadSwitches(); ok = true; } catch (e) { /* сервер недоступен */ }
  }

  if (!ok) {
    // Страница открыта как файл — показываем встроенный config.js
    render(parseConfig(window.RAW_CONFIG || ''));
    if (hash && $('#tab-' + hash)) showTab(hash);
    return;
  }

  SERVER = true;
  ['#swSelect', '#refreshBtn', '#settingsLink', '#findInput'].forEach(s => { $(s).hidden = false; });
  setInterval(poll, 60000);
  $('#fileBtn').hidden = true;

  let [id, tab] = hash.split('/');
  if (!id) { try { id = localStorage.getItem('swcfg-current'); } catch (e) { /* нет доступа */ } }
  // Если коммутатор всего один — сразу открываем его
  if (!id && SWITCHES.length === 1) id = SWITCHES[0].id;
  selectSwitch(id || 'all', tab && $('#tab-' + tab) ? tab : 'overview');
}

boot();
})();
