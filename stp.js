// Разбор STP коммутатора Huawei VRP: display stp brief и общий раздел display stp.
// Работает на сервере (require('./stp')) — результат кладётся в состояние коммутатора.
const COMMANDS = {
  stpBrief: 'display stp brief',
  stp: 'display stp',
};

const lines = t => String(t || '').replace(/\r/g, '').split('\n');
const normPort = n => String(n || '').replace(/^XGE(?=\d)/i, 'XGigabitEthernet').replace(/^GE(?=\d)/i, 'GigabitEthernet');

/* ---------- display stp brief ----------
 MSTID  Port                        Role  STP State     Protection
   0    GigabitEthernet0/0/1        DESI  FORWARDING      NONE
   0    GigabitEthernet0/0/48       ROOT  FORWARDING      NONE
*/
function parseBrief(text) {
  const out = {};
  for (const l of lines(text)) {
    const m = l.match(/^\s*(\d+)\s+(\S+)\s+(ROOT|DESI|ALTE|BACK|MAST|DISA|NONE)\s+(\S+)\s+(\S+)/i);
    if (!m || +m[1] !== 0) continue; // только CIST (экземпляр 0)
    out[normPort(m[2])] = { role: m[3].toUpperCase(), state: m[4].toUpperCase(), protection: m[5].toUpperCase() };
  }
  return out;
}

/* ---------- display stp (общий раздел CIST) ----------
-------[CIST Global Info][Mode MSTP]-------
CIST Bridge         :32768.4c1f-cc12-3456
CIST Root/ERPC      :4096.0011-2233-4455 / 20000
CIST RootPortId     :128.48
BPDU-Protection     :Disabled
Time since last TC  :0 days 2h:13m:24s
Number of TC        :45
Last TC occurred    :GigabitEthernet0/0/48
*/
function parseGlobal(text) {
  const t = String(text || '').replace(/\r/g, '');
  // Только общий раздел — до первого блока порта
  const g = t.split(/^-+\[Port/m)[0];
  const val = re => ((g.match(re) || [])[1] || '').trim();
  const bridge = val(/CIST Bridge\s*:\s*(\S+)/i);
  const rootLine = val(/CIST Root\/ERPC\s*:\s*([^\n]+)/i);
  const [root, cost] = rootLine.split('/').map(x => x.trim());
  const since = val(/Time since last TC\s*:\s*([^\n]+)/i);
  const sinceSec = (() => {
    const m = since.match(/(\d+)\s*days?\s*(\d+)h:(\d+)m:(\d+)s/i);
    return m ? +m[1] * 86400 + +m[2] * 3600 + +m[3] * 60 + +m[4] : null;
  })();
  const disabled = /Protocol Status\s*:\s*Disabled/i.test(g) || /STP is not enabled|stp is disabled/i.test(g);
  return {
    mode: val(/\[Mode\s+(\w+)\]/i) || val(/Mode\s*:\s*(\w+)/i),
    bridge, root: root || '', rootCost: cost != null && cost !== '' ? +cost : null,
    regRoot: val(/CIST RegRoot\/IRPC\s*:\s*(\S+)/i),
    rootPortId: val(/CIST RootPortId\s*:\s*(\S+)/i),
    bpduProtection: /BPDU-Protection\s*:\s*Enabled/i.test(g),
    times: val(/Active Times\s*:\s*([^\n]+)/i),
    tcReceived: +(val(/TC or TCN received\s*:\s*(\d+)/i) || 0),
    tcCount: +(val(/Number of TC\s*:\s*(\d+)/i) || 0),
    lastTcSec: sinceSec, lastTcText: since,
    lastTcPort: normPort(val(/Last TC occurred\s*:\s*(\S+)/i)),
    disabled,
    isRoot: !!bridge && !!root && bridge.toLowerCase() === root.toLowerCase(),
  };
}

function parseStp(raw) {
  const global = parseGlobal(raw.stp);
  const ports = parseBrief(raw.stpBrief);
  const rootPort = Object.keys(ports).find(p => ports[p].role === 'ROOT') || '';
  return { ...global, ports, rootPort };
}

module.exports = { COMMANDS, parseStp, parseBrief, parseGlobal };
