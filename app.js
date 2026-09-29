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
  if (!p.lines.length) return 'empty';
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
    authProfiles: [], dot1x: [],
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
    else if (l === 'stp edged-port disable') p.stpEdgeOff = true;
    else if (l === 'shutdown') p.shutdown = true;
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
      sev: 'med', title: `VLAN разрешены на портах, но не созданы: ${[...undeclared.keys()].sort((a, b) => a - b).join(', ')}`,
      body: 'Трафик этих VLAN через коммутатор не пойдёт, пока VLAN не создан (vlan batch). Либо создайте VLAN, либо уберите его из allow-pass.',
      extra: [...undeclared.entries()].sort((a, b) => a[0] - b[0]).map(([v, ps]) =>
        `<div><span class="vl unknown">${v}</span> <span class="muted">на портах:</span> <span class="mono">${esc(compressPorts([...ps]))}</span></div>`).join(''),
    });
  }

  // 2. Vlanif без VLAN
  for (const vi of cfg.vlanifs) {
    if (vi.vlan !== 1 && !inRanges(cfg.vlansDeclared, vi.vlan) && !vi.shutdown) {
      issues.push({ sev: 'high', title: `${vi.name} настроен, но VLAN ${vi.vlan} не создан`, body: `Интерфейс ${vi.ips.map(i => i.ip).join(', ')} не поднимется (down), пока нет VLAN ${vi.vlan} и порта, где он проходит.` });
    }
  }

  // 3. Маршруты с недостижимым next-hop
  const connected = cfg.vlanifs.flatMap(v => v.ips.map(i => ({ ...i, ifname: v.name })));
  const badNh = {};
  for (const r of cfg.routes) {
    if (!connected.some(c => sameNet(r.nh, c.ip, c.mask))) (badNh[r.nh] ||= []).push(`${r.net}/${maskLen(r.mask)}`);
  }
  for (const [nh, nets] of Object.entries(badNh)) {
    issues.push({ sev: 'high', title: `Next-hop ${nh} не входит ни в одну подключённую подсеть`, body: `Маршруты ${nets.join(', ')} неактивны: на коммутаторе нет Vlanif в сети ${nh}. Скорее всего, это остаток прежней схемы.` });
  }

  // 4. Loopback-detect на аплинках
  const lbdUp = active.filter(p => (p.role === 'uplink' || p.role === 'link') && p.lbd);
  if (lbdUp.length) issues.push({ sev: 'med', title: 'Loopback-detect включён на аплинке', body: 'На магистральных портах обнаружение петель может заблокировать порт и отрезать этаж. Обычно его включают только на пользовательских портах.', ports: lbdUp });

  // 5. Порт конечного устройства без PVID
  const noPvid = active.filter(p => p.linkType === 'trunk' && p.pvid == null && ['printer', 'test', 'access'].includes(p.role));
  if (noPvid.length) issues.push({ sev: 'med', title: 'Порты для устройств без PVID', body: 'Для транка без «port trunk pvid» PVID = 1. Нетегированный трафик принтера или ПК попадёт в VLAN 1, а не в нужный VLAN. Задайте pvid или переведите порт в режим access.', ports: noPvid });

  // 6. Шаблон «port description desktop» на непользовательских портах
  const wrongDesc = active.filter(p => p.portDesc === 'desktop' && !['access'].includes(p.role));
  if (wrongDesc.length) issues.push({ sev: 'info', title: '«port description desktop» на непользовательских портах', body: 'Похоже на массовую настройку по шаблону: описание не соответствует назначению порта.', ports: wrongDesc });

  // 7. Непоследовательный loopback-detect на пользовательских портах
  const acc = active.filter(p => p.role === 'access');
  const accNoLbd = acc.filter(p => !p.lbd);
  if (acc.length && accNoLbd.length && accNoLbd.length < acc.length) issues.push({ sev: 'info', title: `Loopback-detect включён не на всех пользовательских портах (${acc.length - accNoLbd.length} из ${acc.length})`, body: 'На остальных рабочих местах петля (например, кабель, воткнутый в два порта) не будет обнаружена.', ports: accNoLbd, collapse: true });

  // 8. Безопасность
  const con = cfg.ui.find(u => /^con/.test(u.name));
  if (con && con.opts.includes('authentication-mode none')) issues.push({ sev: 'high', title: 'Консольный порт без аутентификации', body: 'user-interface con 0 → authentication-mode none. Любой человек с физическим доступом получает полный доступ к CLI.' });
  const vtyNoTo = cfg.ui.filter(u => u.opts.some(o => o === 'idle-timeout 0 0'));
  if (vtyNoTo.length) issues.push({ sev: 'med', title: 'Сессии VTY никогда не закрываются по бездействию', body: `idle-timeout 0 0 на ${vtyNoTo.map(u => u.name).join(', ')}. Забытая сессия остаётся открытой бесконечно.` });
  const telnetUsers = Object.values(cfg.aaa.users).filter(u => u.services.some(s => ['telnet', 'ftp', 'http'].includes(s)));
  if (telnetUsers.length) issues.push({ sev: 'med', title: 'Разрешены незашифрованные протоколы управления', body: telnetUsers.map(u => `${u.name}: ${u.services.filter(s => ['telnet', 'ftp', 'http'].includes(s)).join(', ')}`).join('; ') + '. Логины и пароли передаются открытым текстом. Лучше оставить только ssh.' });
  if (cfg.snmp.lines.some(l => /sys-info version.*\bv(1|2c)\b/.test(l))) issues.push({ sev: 'med', title: 'SNMP v1/v2c без шифрования', body: `Включены SNMP v1/v2c, v3 отключён. Настроено community: ${cfg.snmp.communities}. Community передаются открытым текстом, стоит ограничить доступ ACL или перейти на v3.` });

  // 9. Созданные, но неиспользуемые VLAN
  const declaredList = [];
  for (const r of cfg.vlansDeclared) for (let v = r.from; v <= r.to && declaredList.length < 500; v++) declaredList.push(v);
  const narrow = active.filter(p => rangesSize(p.allowed) < 64);
  const unused = declaredList.filter(v => !narrow.some(p => carries(p, v)) && !cfg.vlanifs.some(vi => vi.vlan === v));
  if (unused.length) issues.push({ sev: 'info', title: `VLAN созданы, но не назначены ни одному порту доступа: ${unused.join(', ')}`, body: 'Эти VLAN проходят только через широкий транк (например, 2–4094) или не используются вовсе.', extra: unused.map(v => vlanChip(v, cfg)).join(' ') });

  const order = { high: 0, med: 1, info: 2 };
  return issues.sort((a, b) => order[a.sev] - order[b.sev]);
}

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

function render(cfg, sw = null) {
  CFG = cfg;
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
  renderMgmt(cfg);
  renderProfiles(cfg);
  fillPortFilters(cfg);
  renderPortTable();
  renderVlans(cfg);
  renderL3(cfg);
  renderServices(cfg);
  renderIssues(cfg);
  renderRaw(cfg);
  showTab(state.tab === 'all' ? 'overview' : state.tab);
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
    { v: byRole('access'), l: 'Рабочих мест', s: 'ПК + IP-телефон' },
    { v: byRole('ap'), l: 'Wi‑Fi (AP / AC)', s: '' },
    { v: byRole('uplink') + byRole('link'), l: 'Магистральных линков', s: `${byRole('trunk')} расширенных транков` },
    { v: rangesSize(cfg.vlansDeclared), l: 'VLAN создано', s: `${cfg.vlanifs.filter(v => !v.shutdown).length} L3-интерфейса` },
    { v: cfg.issues.length, l: 'Замечаний', s: `${cfg.issues.filter(i => i.sev === 'high').length} важных` },
  ];
  $('#stats').innerHTML = items.map(i => `<div class="stat"><div class="v">${i.v}</div><div class="l">${i.l}</div>${i.s ? `<div class="s">${i.s}</div>` : ''}</div>`).join('');
}

function renderLegend() {
  const counts = {};
  for (const p of CFG.ports) counts[p.role] = (counts[p.role] || 0) + 1;
  $('#legend').innerHTML = ROLE_ORDER.filter(r => counts[r]).map(r =>
    `<span class="legend-item ${state.hiddenRoles.has(r) ? 'off' : ''}" data-role="${r}" title="Нажмите, чтобы скрыть или показать">
      <span class="sw ${r === 'empty' ? 'empty' : ''}" style="--c:var(${ROLES[r].color})"></span>${ROLES[r].label} <b>${counts[r]}</b></span>`).join('');
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
  let cls = `port ${p.type} ${p.role === 'empty' ? 'empty' : ''} ${p.desc ? 'has-desc' : ''}`;
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
    <li>${portLink(p)}<span class="grow">${esc(p.desc || '—')}</span>${roleChip(p.role)}</li>`).join('')}</ul>`;
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
  $('#portMember').innerHTML = '<option value="">Все члены стека</option>' + cfg.members.map(s => `<option value="${s}">Slot ${s}</option>`).join('');
  $('#portRole').innerHTML = '<option value="">Все роли</option>' + ROLE_ORDER.filter(r => cfg.ports.some(p => p.role === r)).map(r => `<option value="${r}">${ROLES[r].label}</option>`).join('');
  $('#portVlan').innerHTML = '<option value="">Любой VLAN</option>' + cfg.usedVlans.map(v => `<option value="${v}">${v}${cfg.vlanNames[v] ? ' · ' + esc(cfg.vlanNames[v]) : ''}</option>`).join('');
}

function filteredPorts() {
  const q = $('#portSearch').value.trim().toLowerCase();
  const mem = $('#portMember').value, role = $('#portRole').value, vlan = $('#portVlan').value;
  const hideEmpty = $('#portHideEmpty').checked;
  const prof = state.profile != null ? new Set(CFG.profiles[state.profile].ports) : null;
  return CFG.ports.filter(p => {
    if (prof && !prof.has(p)) return false;
    if (hideEmpty && !p.lines.length && !prof) return false;
    if (mem !== '' && p.slot !== +mem) return false;
    if (role && p.role !== role) return false;
    if (vlan && !carries(p, +vlan)) return false;
    if (q) {
      const hay = [p.name, p.short, p.desc, p.portDesc, ROLES[p.role].label, rangesText(p.allowed).join(' '), p.lines.join(' ')].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }).sort(portSort);
}

function renderPortTable() {
  const rows = filteredPorts();
  $('#portTable tbody').innerHTML = rows.map(p => `<tr data-port="${esc(p.name)}">
    <td><span class="mono"><b>${esc(p.short)}</b></span></td>
    <td>${roleChip(p.role)}</td>
    <td>${p.desc ? esc(p.desc) : '<span class="muted">—</span>'}${p.portDesc && p.portDesc !== p.desc ? ` <span class="muted" title="port description">(${esc(p.portDesc)})</span>` : ''}</td>
    <td>${p.effPvid != null ? vlanChip(p.effPvid, CFG) + (p.pvid == null ? ' <span class="muted" title="PVID не задан явно">по умолч.</span>' : '') : '<span class="muted">—</span>'}</td>
    <td>${p.allowed.length ? vlanChipsFromRanges(p.allowed, CFG) : '<span class="muted">—</span>'}</td>
    <td>${portFlags(p) || '<span class="muted">—</span>'}</td>
  </tr>`).join('') || `<tr><td colspan="6" class="muted">Нет портов, подходящих под фильтр</td></tr>`;
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
    ${issues.length ? `<div class="sub">Замечания</div>${issues.map(i => `<div class="issue sev-${i.sev}" style="padding:8px 12px"><div class="it">${esc(i.title)}</div></div>`).join('')}` : ''}
    <div class="sub">Конфигурация</div>
    <pre>interface ${esc(p.name)}${p.lines.length ? '\n' + esc(p.lines.map(l => ' ' + l).join('\n')) : '\n <span class="muted"># нет настроек</span>'}</pre>
    ${same.length ? `<div class="sub">Такие же настройки ещё у ${same.length} ${plural(same.length, 'порта', 'портов', 'портов')}</div><div class="mono muted" style="font-size:12px">${esc(compressPorts(same))}</div>` : '<div class="sub">Уникальная конфигурация</div>'}
  `;
  $('#drawer').classList.add('open');
  $('#drawer').setAttribute('aria-hidden', 'false');
  $('#scrim').hidden = false;
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
  const list = await apiCall('GET', 'api/switches');
  const old = new Map(SWITCHES.map(s => [s.id, s]));
  SWITCHES = await Promise.all(list.map(async s => {
    if (!s.hasConfig) return { ...s, cfg: null };
    const prev = old.get(s.id);
    // Не перечитываем конфиг, если он не обновлялся
    if (prev && prev.cfg && prev.lastFetch === s.lastFetch) return { ...s, cfg: prev.cfg };
    try { return { ...s, cfg: prepare(parseConfig(await apiCall('GET', `api/switches/${encodeURIComponent(s.id)}/config`))) }; }
    catch (e) { return { ...s, cfg: null, loadError: e.message }; }
  }));
  fillSwitchSelect();
}

function fillSwitchSelect() {
  const sel = $('#swSelect');
  sel.innerHTML = `<option value="all">Все коммутаторы (${SWITCHES.length})</option>` +
    SWITCHES.map(s => `<option value="${esc(s.id)}" ${s.cfg ? '' : 'disabled'}>${esc(s.name)}${s.cfg ? '' : ' — нет данных'}</option>`).join('');
  sel.value = state.current || 'all';
}

function selectSwitch(id, tab) {
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
        <span class="${hi ? 'sev-high' : ''}"><b>${hi}</b>важных</span>
        <span class="${med ? 'sev-med' : ''}"><b>${med}</b>внимание</span>
      </div>
      <div class="panel-scroll mini">${panelHtml(c, true)}</div>
    </div>`;
  }).join('');

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
  const targets = all ? SWITCHES.filter(s => s.hasPassword) : SWITCHES.filter(s => s.id === id);
  if (!targets.length || targets.some(s => !s.hasPassword)) { toast('Пароль не сохранён — укажите его в настройках', 'err'); return; }
  btn.disabled = true; btn.classList.add('spin');
  targets.forEach(s => { s.busy = true; });
  if (state.current === 'all') renderAll();
  toast(all ? `Обновляю ${targets.length} ${plural(targets.length, 'коммутатор', 'коммутатора', 'коммутаторов')}…` : `Подключаюсь к ${targets[0].host}…`);
  try {
    const res = all ? await apiCall('POST', 'api/fetch-all', {}) : { [id]: await apiCall('POST', `api/switches/${encodeURIComponent(id)}/fetch`, {}) };
    const vals = Object.entries(res);
    const bad = vals.filter(([, r]) => !r.ok);
    if (!bad.length) toast(all ? `Обновлено: ${vals.length}` : (vals[0][1].changed ? 'Конфигурация обновлена' : 'Конфигурация не изменилась'), 'ok');
    else toast(bad.map(([k, r]) => `${(SWITCHES.find(s => s.id === k) || {}).name || k}: ${r.error}`).join('; '), 'err');
  } catch (e) { toast(e.message, 'err'); }
  await loadSwitches().catch(e => toast(e.message, 'err'));
  btn.disabled = false; btn.classList.remove('spin');
  selectSwitch(state.current);
}

function setHash() {
  const h = SERVER ? (state.current === 'all' ? 'all' : `${state.current}/${state.tab}`) : state.tab;
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

  document.addEventListener('click', e => {
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
  $('#refreshBtn').addEventListener('click', () => refresh(state.current));

  $('#panelVlan').addEventListener('change', e => { state.panelVlan = e.target.value; renderPanel(CFG); });
  ['#portSearch', '#portMember', '#portRole', '#portVlan', '#portHideEmpty'].forEach(s => $(s).addEventListener('input', renderPortTable));
  $('#portReset').addEventListener('click', () => {
    $('#portSearch').value = ''; $('#portMember').value = ''; $('#portRole').value = ''; $('#portVlan').value = ''; $('#portHideEmpty').checked = true;
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
  ['#swSelect', '#refreshBtn', '#settingsLink'].forEach(s => { $(s).hidden = false; });
  $('#fileBtn').hidden = true;

  let [id, tab] = hash.split('/');
  if (!id) { try { id = localStorage.getItem('swcfg-current'); } catch (e) { /* нет доступа */ } }
  // Если коммутатор всего один — сразу открываем его
  if (!id && SWITCHES.length === 1) id = SWITCHES[0].id;
  selectSwitch(id || 'all', tab && $('#tab-' + tab) ? tab : 'overview');
}

boot();
})();
