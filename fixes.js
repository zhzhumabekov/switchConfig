// Готовые команды Huawei VRP для исправления замечаний и шаблоны настройки портов.
// Команды только формируются для копирования — на коммутатор ничего не отправляется.
(function (root) {
  'use strict';

  /* ---------- вспомогательное ---------- */
  // [20, 21, 22, 200] → "20 to 22 200" (синтаксис VRP)
  function vrpList(nums) {
    const s = [...new Set(nums)].sort((a, b) => a - b);
    const out = [];
    for (let i = 0; i < s.length; i++) {
      let j = i;
      while (j + 1 < s.length && s[j + 1] === s[j] + 1) j++;
      out.push(j > i ? `${s[i]} to ${s[j]}` : `${s[i]}`);
      i = j;
    }
    return out.join(' ');
  }
  const expand = ranges => { const o = []; for (const r of ranges) for (let v = r.from; v <= r.to && o.length < 5000; v++) o.push(v); return o; };

  // Команды в системном режиме: system-view … return
  function sys(lines) { return ['system-view', ...lines, 'return'].join('\n'); }
  function iface(name, lines) { return lines.length ? [`interface ${name}`, ...lines.map(l => ' ' + l), ' quit'] : []; }
  const perPort = (ports, fn) => ports.flatMap(p => iface(p.name, fn(p)));

  const variant = (title, commands, note, warn) => ({ title, commands, note: note || '', warn: warn || '' });

  /* ---------- исправления замечаний ---------- */
  function forIssue(issue, cfg) {
    const d = issue.data || {};
    const ports = issue.ports || [];
    switch (issue.kind) {
      case 'vlan-undeclared': {
        const vlans = d.vlans.map(([v]) => v);
        const byPort = new Map();
        for (const [v, names] of d.vlans) for (const n of names) (byPort.get(n) || byPort.set(n, []).get(n)).push(v);
        const portLines = [...byPort.entries()].flatMap(([name, vs]) => {
          const p = cfg.ports.find(x => x.name === name);
          const allowedOnly = vs.filter(v => p && p.allowed.some(r => v >= r.from && v <= r.to));
          const pvidBad = p && vs.includes(p.pvid);
          return iface(name, [
            ...(allowedOnly.length ? [`undo port trunk allow-pass vlan ${vrpList(allowedOnly)}`] : []),
            ...(pvidBad ? ['undo port trunk pvid vlan'] : []),
          ]);
        });
        return [
          variant('Вариант 1. Создать VLAN', sys([`vlan batch ${vrpList(vlans)}`]),
            'Если эти VLAN должны проходить через коммутатор (например, они есть на ядре и нужны дальше по сети).'),
          variant('Вариант 2. Убрать эти VLAN с портов', sys(portLines),
            'Если VLAN не нужны. Проверьте по списку портов выше, что трафик этих VLAN там действительно не ожидается.'),
        ];
      }
      case 'vlanif-novlan':
        return [
          variant('Вариант 1. Создать VLAN', sys([`vlan batch ${d.vlan}`]),
            `Если адрес ${d.ips.join(', ')} нужен — после этого VLAN ${d.vlan} должен ещё проходить через аплинк.`),
          variant(`Вариант 2. Удалить ${d.name}`, sys([`undo interface ${d.name}`]), '',
            `Удалит IP-адрес ${d.ips.join(', ')}. Убедитесь, что по нему никто не подключается к коммутатору.`),
        ];
      case 'route-nh':
        return [variant('Удалить неработающие маршруты', sys(d.routes.map(r => `undo ip route-static ${r.net} ${r.mask} ${r.nh}`)),
          'Если маршруты нужны, вместо удаления нужен интерфейс (Vlanif) в сети next-hop.')];
      case 'lbd-uplink':
        return [variant('Выключить loopback-detect на аплинках', sys(perPort(ports, () => ['undo loopback-detect enable'])))];
      case 'no-pvid':
        return [variant('Задать PVID', sys(perPort(ports, p => [`port trunk pvid vlan ${guessPvid(p, cfg)}`])),
          'PVID — VLAN, в который попадает нетегированный трафик устройства. Подставлен единственный или основной разрешённый VLAN порта — проверьте.')];
      case 'desc-desktop':
        return [variant('Убрать «port description desktop»', sys(perPort(ports, () => ['undo port description'])),
          'Своё описание порта можно задать командой description в панели порта.')];
      case 'lbd-missing':
        return [variant('Включить loopback-detect', sys(perPort(ports, () => ['loopback-detect enable'])))];
      case 'console-noauth':
        return [variant('Включить пароль на консоли', sys(['user-interface con 0', ' authentication-mode aaa', ' quit']), '',
          d.terminalUsers.length
            ? `Вход с консоли будет по локальным учёткам с service-type terminal: ${d.terminalUsers.join(', ')}. Убедитесь, что пароль от одной из них известен — иначе консольный доступ будет потерян.`
            : 'Сейчас нет локальных пользователей с service-type terminal — сначала создайте такого, иначе консольный доступ будет потерян.')];
      case 'vty-timeout':
        return [variant('Закрывать сессию после 15 минут бездействия', sys(d.lines.flatMap(l => [`user-interface ${l}`, ' idle-timeout 15 0', ' quit'])))];
      case 'plain-proto': {
        const lines = d.users.map(u => {
          const keep = u.services.filter(s => !['telnet', 'ftp', 'http', 'x25-pad'].includes(s));
          if (!keep.includes('ssh')) keep.push('ssh');
          return ` local-user ${u.name} service-type ${keep.join(' ')}`;
        });
        return [variant('Оставить только защищённые протоколы', sys(['aaa', ...lines, ' quit']), '',
          'service-type задаётся целиком: команда заменяет весь список. Перед этим проверьте, что вход по SSH под этими учётками работает.')];
      }
      case 'snmp-v2':
        return [variant('Разрешить SNMP только с сервера мониторинга', sys([
          'acl number 2000', ' rule 5 permit source <IP-сервера-мониторинга> 0', ' rule 100 deny', ' quit', 'snmp-agent acl 2000',
        ]), 'Подставьте IP сервера мониторинга (Zabbix). Надёжнее перейти на SNMPv3, но это требует настройки и на стороне Zabbix.',
        'Если адрес указать неверно, мониторинг перестанет получать данные с коммутатора.')];
      case 'vlan-unused':
        return [variant('Удалить неиспользуемые VLAN', sys(d.vlans.map(v => `undo vlan ${v}`)), '',
          'Удаляйте, только если VLAN не нужен дальше по сети: он может проходить через аплинк к другим коммутаторам.')];
      case 'loop':
        return [variant('Диагностика', ['display loopback-detect', ...ports.map(p => `display mac-address interface ${p.name}`)].join('\n'),
          'Найдите кабель, который замыкает сеть, и уберите его. Порт восстановится сам; чтобы включить сразу — выключите и включите его:'),
        variant('Включить порт после устранения петли', sys(perPort(ports, () => ['shutdown', 'undo shutdown'])))];
      case 'uplink-down':
        return [variant('Диагностика', ports.flatMap(p => [`display interface ${p.name}`, `display lldp neighbor interface ${p.name}`,
          ...(p.type === 'xge' ? [`display transceiver interface ${p.name} verbose`] : [])]).join('\n'),
          'Проверьте кабель или модуль и состояние порта на соседнем коммутаторе.')];
      case 'port-errors':
        return [variant('Диагностика', ports.map(p => `display interface ${p.name}`).join('\n'),
          'Посмотрите тип ошибок (CRC — обычно кабель или разъём). После замены кабеля сбросьте счётчики и понаблюдайте:'),
        variant('Сбросить счётчики', ports.map(p => `reset counters interface ${p.name}`).join('\n'))];
      default:
        return null;
    }
  }

  function guessPvid(p, cfg) {
    const vs = expand(p.allowed).filter(v => v !== 1 && v !== p.voiceVlan);
    if (vs.length === 1) return vs[0];
    // Основной VLAN рабочих мест на этом коммутаторе
    const counts = {};
    for (const x of cfg.ports) if (x.pvid != null && x.role === 'access') counts[x.pvid] = (counts[x.pvid] || 0) + 1;
    const main = +Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
    return vs.includes(main) ? main : (vs[0] || '<VLAN>');
  }

  /* ---------- шаблоны портов ---------- */
  function modelOf(lines) {
    const m = { linkType: '', pvid: null, allowed: [], other: [] };
    for (const l of lines) {
      let r;
      if ((r = l.match(/^port link-type (\S+)/))) m.linkType = r[1];
      else if ((r = l.match(/^port trunk pvid vlan (\d+)/))) m.pvid = +r[1];
      else if ((r = l.match(/^port default vlan (\d+)/))) m.pvid = +r[1];
      else if ((r = l.match(/^port trunk allow-pass vlan (.+)/))) m.allowed.push(...parseList(r[1]));
      else if (!/^description /.test(l)) m.other.push(l);
    }
    return m;
  }
  function parseList(s) {
    const t = s.trim().split(/\s+/), out = [];
    for (let i = 0; i < t.length; i++) {
      const a = +t[i];
      if (Number.isNaN(a)) continue;
      if (t[i + 1] === 'to') { for (let v = a; v <= +t[i + 2] && out.length < 5000; v++) out.push(v); i += 2; } else out.push(a);
    }
    return out;
  }

  function undoOf(l) {
    let r;
    if ((r = l.match(/^undo (.+)/))) return r[1];
    if (/^port description /.test(l)) return 'undo port description';
    if (/^lldp tlv-enable med-tlv network-policy/.test(l)) return 'undo lldp tlv-enable med-tlv network-policy';
    if (/^stp edged-port /.test(l)) return 'undo stp edged-port';
    if (/^storm-control (broadcast|multicast|unicast) /.test(l)) return `undo ${l.split(' ').slice(0, 2).join(' ')}`;
    return 'undo ' + l;
  }

  // Самый частый набор настроек для роли на этом коммутаторе
  function pickProfile(cfg, role) {
    const groups = (cfg.profiles || []).filter(g => g.sample.role === role && g.sample.lines.length).sort((a, b) => b.ports.length - a.ports.length);
    return groups[0] || null;
  }

  function portTemplates(cfg) {
    const out = [];
    const ws = pickProfile(cfg, 'access');
    if (ws) {
      out.push({ id: 'workstation', label: 'Рабочее место (ПК + телефон)', lines: ws.sample.lines.filter(l => !/^description /.test(l)), basis: `как на ${ws.ports.length} портах` });
      // Принтер: как рабочее место, но только данные, без голосового VLAN
      const m = modelOf(ws.sample.lines);
      if (m.pvid != null) {
        const lines = ws.sample.lines.filter(l => !/^description |^port trunk allow-pass|^lldp tlv-enable med-tlv network-policy|^port description /.test(l));
        const i = lines.findIndex(l => /^port trunk pvid/.test(l));
        lines.splice(i + 1, 0, `port trunk allow-pass vlan ${m.pvid}`);
        out.push({ id: 'printer', label: 'Принтер / устройство без телефона', lines, basis: `рабочее место без голосового VLAN, только VLAN ${m.pvid}` });
      }
    }
    const ap = pickProfile(cfg, 'ap');
    if (ap) out.push({ id: 'ap', label: 'Точка доступа Wi‑Fi', lines: ap.sample.lines.filter(l => !/^description /.test(l)), basis: `как на ${ap.ports.length} портах` });
    out.push({ id: 'off', label: 'Выключить порт (shutdown)', special: 'off' });
    out.push({ id: 'on', label: 'Включить порт', special: 'on' });
    return out;
  }

  // Команды, которые приводят порт к шаблону. desc — новое описание (undefined — не менять)
  function portChange(p, tpl, desc) {
    const out = [];
    if (desc !== undefined && desc !== (p.desc || '')) out.push(desc ? `description ${desc}` : 'undo description');
    if (tpl.special === 'desc') return out;
    if (tpl.special === 'off') { if (!p.shutdown) out.push('shutdown'); return out; }
    if (tpl.special === 'on') { if (p.shutdown) out.push('undo shutdown'); return out; }

    const c = modelOf(p.lines), t = modelOf(tpl.lines);
    if ((t.linkType || 'hybrid') !== (c.linkType || 'hybrid')) {
      // Смена типа порта: сначала убираем настройки VLAN старого типа
      if (c.linkType === 'trunk') {
        if (c.pvid != null) out.push('undo port trunk pvid vlan');
        if (c.allowed.length) out.push(`undo port trunk allow-pass vlan ${vrpList(c.allowed)}`);
      }
      if (c.linkType === 'access' && c.pvid != null) out.push('undo port default vlan');
      if (t.linkType) out.push(`port link-type ${t.linkType}`);
      c.pvid = null; c.allowed = [];
    }
    if (t.linkType === 'access') {
      if (t.pvid !== c.pvid) out.push(t.pvid != null ? `port default vlan ${t.pvid}` : 'undo port default vlan');
    } else {
      if (t.pvid !== c.pvid) out.push(t.pvid != null ? `port trunk pvid vlan ${t.pvid}` : 'undo port trunk pvid vlan');
      const remove = c.allowed.filter(v => !t.allowed.includes(v));
      const add = t.allowed.filter(v => !c.allowed.includes(v));
      if (remove.length) out.push(`undo port trunk allow-pass vlan ${vrpList(remove)}`);
      if (add.length) out.push(`port trunk allow-pass vlan ${vrpList(add)}`);
    }
    for (const l of c.other) if (!t.other.includes(l)) out.push(undoOf(l));
    for (const l of t.other) if (!c.other.includes(l)) out.push(l);
    return out;
  }

  function portCommands(p, tpl, desc) {
    const lines = portChange(p, tpl, desc);
    return lines.length ? sys(iface(p.name, lines)) : '';
  }

  const api = { forIssue, portTemplates, portChange, portCommands, vrpList, undoOf, modelOf, sys, iface };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Fixes = api;
})(typeof window !== 'undefined' ? window : globalThis);
