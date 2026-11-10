// Cisco CME (Call Manager Express): телефоны, их MAC-адреса, номера и подписи.
// Все команды только читают данные.
const COMMANDS = {
  config: 'show running-config | section ephone|voice register',
  ephone: 'show ephone',
  sip: 'show voice register pool all',
};

const lines = t => String(t || '').replace(/\r/g, '').split('\n');
// 0019.AA7B.1234 → 0019-aa7b-1234 (как в таблицах MAC Huawei)
function normMac(m) {
  const h = String(m || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  return h.length === 12 ? `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8)}` : null;
}

// Пароли в разделах ephone (username … password …) не сохраняем
function redact(text) {
  return String(text || '').replace(/(password|secret)\s+\S+/gi, '$1 ******');
}

function commandError(text) {
  const m = String(text || '').match(/^\s*%\s*(Invalid input.*|Incomplete command.*|Authorization failed.*|Unknown command.*|Ambiguous command.*)$/m);
  return m ? m[1].trim() : null;
}

/* ---------- show running-config | section ephone|voice register ---------- */
function parseConfig(text) {
  const dn = {}, ephones = {}, sipDn = {}, sipPools = {};
  let cur = null;
  for (const raw of lines(text)) {
    const l = raw.replace(/\s+$/, '');
    let m;
    if ((m = l.match(/^ephone-dn\s+(\d+)/))) { cur = dn[m[1]] = { id: +m[1], numbers: [], lines: [], head: l.trim() }; continue; }
    if ((m = l.match(/^ephone\s+(\d+)/))) { cur = ephones[m[1]] = { id: +m[1], buttons: [], lines: [] }; continue; }
    if ((m = l.match(/^voice register dn\s+(\d+)/))) { cur = sipDn[m[1]] = { id: +m[1], numbers: [], lines: [] }; continue; }
    if ((m = l.match(/^voice register pool\s+(\d+)/))) { cur = sipPools[m[1]] = { id: +m[1], dns: [], lines: [] }; continue; }
    if (/^\S/.test(l)) { cur = null; continue; }
    if (!cur) continue;
    const t = l.trim();
    if (t && t !== '!') cur.lines.push(t);
    if ((m = t.match(/^number\s+(\S+)(?:\s+secondary\s+(\S+))?/)) && cur.numbers) { cur.numbers.push(m[1]); if (m[2]) cur.numbers.push(m[2]); }
    else if ((m = t.match(/^number\s+\d+\s+dn\s+(\d+)/)) && cur.dns) cur.dns.push(+m[1]);
    else if ((m = t.match(/^name\s+(.+)/))) cur.name = m[1].replace(/^"|"$/g, '');
    else if ((m = t.match(/^label\s+(.+)/))) cur.label = m[1].replace(/^"|"$/g, '');
    else if ((m = t.match(/^description\s+(.+)/))) cur.description = m[1].replace(/^"|"$/g, '');
    else if ((m = t.match(/^mac-address\s+(\S+)/))) cur.mac = normMac(m[1]);
    else if ((m = t.match(/^id mac\s+(\S+)/))) cur.mac = normMac(m[1]);
    else if ((m = t.match(/^type\s+(\S+)/))) cur.model = m[1];
    else if ((m = t.match(/^button\s+(.+)/)) && cur.buttons) {
      // button 1:5 2:6  или  1o5  1c7 — номер кнопки, тип, номер ephone-dn
      for (const b of m[1].trim().split(/\s+/)) { const x = b.match(/^\d+[:a-z](\d+)/i); if (x) cur.buttons.push(+x[1]); }
    }
  }
  return { dn, ephones, sipDn, sipPools };
}

/* ---------- show ephone ----------
ephone-1[0] Mac:0019.AA7B.1234 TCP socket:[2] activeLine:0 ... REGISTERED in SCCP ver 20/17 max_streams=5
IP:10.20.200.15 * 7965  keepalive 1234 max_line 6 available_line 6
button 1: cw:1 ccw:(0 0)
 dn 5  number 2345 CH1   IDLE         CH2   IDLE
*/
function parseEphone(text) {
  const out = {};
  let cur = null;
  for (const l of lines(text)) {
    let m;
    if ((m = l.match(/^ephone-(\d+)\[\d+\]\s+Mac:\s*([0-9A-Fa-f.]+)/))) {
      const st = (l.match(/\b(UNREGISTERED|REGISTERED|DECEASED)\b/) || [])[1] || '';
      cur = out[m[1]] = { id: +m[1], mac: normMac(m[2]), status: st.toLowerCase() || 'unknown', numbers: [] };
      continue;
    }
    if (!cur) continue;
    if ((m = l.match(/\bIP:\s*(\d+\.\d+\.\d+\.\d+)(?:\s*\*)?\s+(\S[^\s]*(?:\s+\d{4})?)?/))) {
      cur.ip = m[1];
      const model = (l.match(/IP:\s*\S+\s*\*?\s*(.+?)\s+keepalive/i) || [])[1];
      if (model) cur.model = model.trim();
    }
    if ((m = l.match(/^\s*dn\s+(\d+)\s+number\s+(\S+)/))) cur.numbers.push(m[2]);
    if (!cur.status || cur.status === 'unknown') {
      const st = (l.match(/\b(UNREGISTERED|REGISTERED|DECEASED)\b/) || [])[1];
      if (st) cur.status = st.toLowerCase();
    }
  }
  return out;
}

/* ---------- show voice register pool all (SIP) ----------
Pool Tag 1
Config:
  Mac address is 0011.2233.4455
  Type is 7965
  Number list 1 : DN 1
Dialpeers created:
...
  Registration method: ...  / IP address : 10.20.200.20 / Registered
*/
function parseSip(text) {
  const out = {};
  const parts = String(text || '').replace(/\r/g, '').split(/^Pool Tag\s+(\d+)\s*$/m);
  for (let i = 1; i < parts.length; i += 2) {
    const b = parts[i + 1] || '';
    const mac = normMac((b.match(/Mac address is\s+(\S+)/i) || [])[1]);
    const ip = (b.match(/(?:IP address|Contact IP|ip address is)\s*:?\s*(\d+\.\d+\.\d+\.\d+)/i) || [])[1] || '';
    let status = 'unknown';
    if (/\b(unregistered|not registered)\b/i.test(b)) status = 'unregistered';
    else if (/\bregistered\b/i.test(b) || /Active Call/i.test(b)) status = 'registered';
    out[parts[i]] = { id: +parts[i], mac, ip, status };
  }
  return out;
}

// Один список телефонов: MAC, модель, номера, подписи, статус регистрации, IP
function parseAll(raw, at = new Date().toISOString()) {
  const errors = {};
  for (const [k, cmd] of Object.entries(COMMANDS)) {
    const e = raw[k] == null ? 'не выполнялась' : commandError(raw[k]);
    if (e) errors[cmd] = e;
  }
  const cfg = parseConfig(raw.config);
  const eph = parseEphone(raw.ephone);
  const sip = parseSip(raw.sip);
  const phones = [];
  const dnInfo = (map, ids) => {
    const list = ids.map(id => map[id]).filter(Boolean);
    return {
      numbers: [...new Set(list.flatMap(d => d.numbers))],
      names: [...new Set(list.flatMap(d => [d.name, d.label]).filter(Boolean))],
      dns: list.map(d => ({ id: d.id, numbers: d.numbers, name: d.name || '', label: d.label || '', description: d.description || '', head: d.head || '', lines: d.lines || [] })),
    };
  };

  // SCCP (ephone): из конфигурации и из show ephone
  const ids = new Set([...Object.keys(cfg.ephones), ...Object.keys(eph)]);
  for (const id of ids) {
    const c = cfg.ephones[id] || { buttons: [] }, s = eph[id] || {};
    const d = dnInfo(cfg.dn, c.buttons || []);
    const mac = c.mac || s.mac;
    if (!mac) continue;
    phones.push({
      proto: 'sccp', id: `ephone ${id}`, ref: +id, mac, model: c.model || s.model || '', ip: s.ip || '',
      status: s.status || 'unknown', numbers: d.numbers.length ? d.numbers : (s.numbers || []), names: d.names, description: c.description || '',
      buttons: c.buttons || [], dns: d.dns, lines: c.lines || [],
    });
  }
  // SIP (voice register pool)
  for (const [id, c] of Object.entries(cfg.sipPools)) {
    const s = sip[id] || {};
    const d = dnInfo(cfg.sipDn, c.dns || []);
    const mac = c.mac || s.mac;
    if (!mac) continue;
    phones.push({
      proto: 'sip', id: `pool ${id}`, ref: +id, mac, model: c.model || '', ip: s.ip || '',
      status: s.status || 'unknown', numbers: d.numbers, names: d.names, description: c.description || '',
      buttons: c.dns || [], dns: d.dns, lines: c.lines || [],
    });
  }
  // Занятые идентификаторы и номера — чтобы предложить свободные для нового телефона
  const used = {
    ephone: [...new Set(Object.keys(cfg.ephones).map(Number).concat(Object.keys(eph).map(Number)))],
    ephoneDn: Object.keys(cfg.dn).map(Number),
    pool: Object.keys(cfg.sipPools).map(Number),
    sipDn: Object.keys(cfg.sipDn).map(Number),
    numbers: [...new Set([...Object.values(cfg.dn), ...Object.values(cfg.sipDn)].flatMap(d => d.numbers))],
  };
  // Номера без телефона (ephone-dn, не назначенные ни на одну кнопку)
  const assigned = new Set(Object.values(cfg.ephones).flatMap(e => e.buttons));
  const freeDns = Object.values(cfg.dn).filter(d => !assigned.has(d.id)).map(d => ({ id: d.id, numbers: d.numbers, name: d.name || '', label: d.label || '' }));
  return { at, kind: 'cme', phones, used, freeDns, errors };
}

module.exports = { COMMANDS, parseAll, parseConfig, parseEphone, parseSip, normMac, redact };
