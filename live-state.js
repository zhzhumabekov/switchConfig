// Разбор «живого» состояния коммутатора Huawei VRP: статус портов, LLDP-соседи,
// таблица MAC-адресов и ARP. Все команды только читают данные.
const hardware = require('./hardware');

const COMMANDS = {
  interfaces: 'display interface brief',
  lldp: 'display lldp neighbor brief',
  mac: 'display mac-address',
  arp: 'display arp',
  ...hardware.COMMANDS,
};

const MAC_RE = /^([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})$/i;
const IFACE_RE = /^(XGigabitEthernet|GigabitEthernet|MultiGE|25GE|40GE|100GE|10GE|XGE|GE|Eth-Trunk|Ethernet|Eth|Vlanif|MEth)(\d[\d/.:]*)$/i;

// GE0/0/1 → GigabitEthernet0/0/1, XGE0/0/3 → XGigabitEthernet0/0/3 (как в конфигурации)
function normPort(name) {
  const m = String(name || '').match(IFACE_RE);
  if (!m) return name;
  const full = { xge: 'XGigabitEthernet', ge: 'GigabitEthernet', eth: 'Ethernet' }[m[1].toLowerCase()];
  return (full || m[1]) + m[2];
}
const isIface = t => IFACE_RE.test(t);

// Ответ коммутатора «команда не поддерживается / нет прав»
function commandError(text) {
  const m = String(text || '').match(/^\s*Error:\s*(.*)$/m);
  return m ? m[1].trim() || 'команда не поддерживается' : null;
}

/* ---------- display interface brief ----------
Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
GigabitEthernet0/0/1        up    up        0.01%  0.13%          0          0
GigabitEthernet0/0/2        *down down         0%     0%          0          0
*/
function parseInterfaces(text) {
  const out = {};
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 3 || !isIface(t[0])) continue;
    const [name, phy, proto] = t;
    const nums = t.slice(3);
    const inErr = +nums[2], outErr = +nums[3];
    let status = 'down';
    if (/^up/i.test(phy)) status = 'up';
    else if (phy.startsWith('*')) status = 'admin';  // shutdown
    else if (phy.startsWith('#')) status = 'lbdt';   // заблокирован loopback-detect
    else if (phy.startsWith('^')) status = 'standby';
    out[normPort(name)] = {
      phy, proto, status,
      inUti: nums[0] || '', outUti: nums[1] || '',
      inErr: Number.isFinite(inErr) ? inErr : 0, outErr: Number.isFinite(outErr) ? outErr : 0,
    };
  }
  return out;
}

/* ---------- display lldp neighbor brief ----------
Local Intf       Neighbor Dev             Neighbor Intf             Exptime(s)
GE0/0/48         SW-FLOOR-4               GE0/0/1                   104
*/
function parseLldp(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 3 || !isIface(t[0])) continue;
    let end = t.length;
    const exp = /^\d+$/.test(t[end - 1]) ? +t[--end] : null;
    const intf = t[end - 1];
    const dev = t.slice(1, end - 1).join(' ');
    out.push({ port: normPort(t[0]), device: dev || '', remotePort: intf || '', expires: exp });
  }
  return out;
}

/* ---------- display mac-address ----------
MAC Address    VLAN/       PEVLAN CEVLAN Port            Type      LSP/LSR-ID
0011-2233-4455 20          -      -      GE0/0/4         dynamic   0/-
или (новые версии)
MAC Address    VLAN/VSI/BD                       Learned-From        Type
0011-2233-4455 20/-/-                            GE0/0/4             dynamic
*/
const MAC_TYPES = /^(dynamic|static|sticky|security|sec-config|blackhole|authen|mux|snooping|pseudo|evpn)$/i;
function parseMac(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length < 3 || !MAC_RE.test(t[0])) continue;
    const vlan = parseInt(t[1], 10);
    const port = t.slice(2).find(isIface);
    if (!port) continue;
    const type = t.slice(2).find(x => MAC_TYPES.test(x)) || '';
    out.push({ mac: t[0].toLowerCase(), vlan: Number.isFinite(vlan) ? vlan : null, port: normPort(port), type: type.toLowerCase() });
  }
  return out;
}

/* ---------- display arp ----------
IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE        INTERFACE   VPN-INSTANCE
                                          VLAN/CEVLAN(SIP/DIP)
10.0.0.1        4c1f-cc12-3456            I -         Vlanif20
10.0.0.15       0011-2233-4455  20        D-0         GE0/0/4
                                          20/-
*/
function parseArp(text) {
  const out = [];
  let last = null;
  for (const line of String(text || '').split('\n')) {
    const t = line.trim().split(/\s+/);
    if (t.length >= 3 && /^\d+\.\d+\.\d+\.\d+$/.test(t[0]) && MAC_RE.test(t[1])) {
      const rest = t.slice(2);
      const typeTok = rest.find(x => /^[IDS](-\d*)?$/.test(x)) || '';
      const iface = rest.find(isIface) || '';
      const vlanIf = iface.match(/^Vlanif(\d+)$/i);
      last = {
        ip: t[0], mac: t[1].toLowerCase(),
        type: { I: 'interface', D: 'dynamic', S: 'static' }[typeTok[0]] || '',
        iface: normPort(iface), vlan: vlanIf ? +vlanIf[1] : null,
      };
      out.push(last);
    } else if (last && /^\d+\/\S*$/.test(line.trim())) {
      // Вторая строка записи: VLAN/CEVLAN
      last.vlan = last.vlan ?? parseInt(line.trim(), 10);
      last = null;
    } else {
      last = null;
    }
  }
  return out;
}

function parseAll(raw, at = new Date().toISOString()) {
  const errors = {};
  for (const [k, cmd] of Object.entries(COMMANDS)) {
    const e = raw[k] == null ? 'не выполнялась' : commandError(raw[k]);
    if (e) errors[cmd] = e;
  }
  const interfaces = parseInterfaces(raw.interfaces);
  return {
    at,
    interfaces,
    hw: hardware.parseHardware(raw, interfaces),
    lldp: parseLldp(raw.lldp),
    mac: parseMac(raw.mac),
    arp: parseArp(raw.arp),
    errors,
  };
}

module.exports = { COMMANDS, parseAll, parseInterfaces, parseLldp, parseMac, parseArp, normPort };
