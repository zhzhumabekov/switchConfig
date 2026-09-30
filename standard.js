// Эталонные настройки: создание эталона из коммутатора и проверка коммутатора на соответствие.
// Работает в браузере (window.Standard, нужен Fixes) и в Node (require('./standard')).
(function (root) {
  'use strict';
  const Fixes = root.Fixes || (typeof require === 'function' ? require('./fixes') : null);

  // Роль порта → шаблон эталона
  const ROLE_TPL = { access: 'workstation', printer: 'printer', ap: 'ap' };
  const PHYS = /^(undo )?(negotiation auto|speed \S+|duplex \S+)$/;
  const TPL_LABEL = { workstation: 'Рабочее место (ПК + телефон)', printer: 'Принтер / устройство без телефона', ap: 'Точка доступа Wi‑Fi' };

  const loghosts = cfg => cfg.log.map(l => (l.match(/loghost\s+(\S+)/) || [])[1]).filter(Boolean);
  const snmpVersions = cfg => {
    const l = cfg.snmp.lines.find(x => /^snmp-agent sys-info version /.test(x));
    return l ? l.replace(/^snmp-agent sys-info version /, '').split(/\s+/).filter(v => /^v(1|2c|3)$/.test(v)) : [];
  };
  const trimmedLines = cfg => new Set(cfg.text.replace(/\r/g, '').split('\n').map(l => l.trim()).filter(Boolean));

  /* ---------- эталон из коммутатора ---------- */
  function derive(cfg, source) {
    const tpls = Fixes.portTemplates(cfg);
    const ports = {};
    for (const id of ['workstation', 'printer', 'ap']) {
      const t = tpls.find(x => x.id === id);
      ports[id] = { enabled: !!t, lines: t ? t.lines : [] };
    }
    const tz = (cfg.text.match(/^clock timezone .+$/m) || [])[0] || '';
    return {
      version: 1,
      createdFrom: source || cfg.sysname || '',
      updatedAt: new Date().toISOString(),
      ports,
      global: {
        ntpServers: [...cfg.ntp.servers],
        syslogHosts: loghosts(cfg),
        // Рекомендуемые значения, даже если на коммутаторе сейчас иначе
        snmpAllowed: ['v2c', 'v3'],
        snmpTrap: cfg.snmp.lines.includes('snmp-agent trap enable'),
        sshRequired: true,
        telnetForbidden: true,
        vtyAaa: true,
        vtyIdleMax: 15,
        consoleAuth: true,
        lldp: true,
        timezone: tz.trim(),
        requiredLines: [],
        forbiddenLines: [],
      },
    };
  }

  /* ---------- проверка ---------- */
  function check(cfg, std) {
    const g = (std && std.global) || {};
    const rules = [];
    const rule = (id, label, ok, detail, commands, warn) => rules.push({ id, label, ok, detail: detail || '', commands: commands || '', warn: warn || '' });
    const sys = Fixes.sys;

    if (g.ntpServers && g.ntpServers.length) {
      const missing = g.ntpServers.filter(s => !cfg.ntp.servers.includes(s));
      const extra = cfg.ntp.servers.filter(s => !g.ntpServers.includes(s));
      rule('ntp', 'NTP-серверы', !missing.length,
        missing.length ? `Не настроены: ${missing.join(', ')}` : `Все ${g.ntpServers.length} настроены${extra.length ? `; дополнительно: ${extra.join(', ')}` : ''}`,
        missing.length ? sys(missing.map(s => `ntp-service unicast-server ${s}`)) : '');
    }
    if (g.syslogHosts && g.syslogHosts.length) {
      const have = loghosts(cfg);
      const missing = g.syslogHosts.filter(s => !have.includes(s));
      rule('syslog', 'Сервер журналов (syslog)', !missing.length,
        missing.length ? `Не настроены: ${missing.join(', ')}` : `Настроено: ${g.syslogHosts.join(', ')}`,
        missing.length ? sys(missing.map(s => `info-center loghost ${s}`)) : '');
    }
    if (g.snmpAllowed && g.snmpAllowed.length) {
      const on = snmpVersions(cfg);
      const bad = on.filter(v => !g.snmpAllowed.includes(v));
      rule('snmp-ver', `SNMP: разрешены только ${g.snmpAllowed.join(', ')}`, !bad.length,
        bad.length ? `Включены недопустимые версии: ${bad.join(', ')}` : (on.length ? `Включены: ${on.join(', ')}` : 'SNMP не включён'),
        bad.length ? sys(bad.map(v => `undo snmp-agent sys-info version ${v}`)) : '',
        bad.length ? 'Проверьте, что мониторинг (Zabbix) не опрашивает коммутатор по этой версии.' : '');
    }
    if (g.snmpTrap) {
      const ok = cfg.snmp.lines.includes('snmp-agent trap enable');
      rule('snmp-trap', 'SNMP-трапы включены', ok, ok ? '' : 'Трапы выключены', ok ? '' : sys(['snmp-agent trap enable']));
    }
    if (g.sshRequired) {
      const ok = cfg.ssh.flags.includes('stelnet server enable');
      rule('ssh', 'SSH-сервер включён', ok, ok ? '' : 'Нет «stelnet server enable»', ok ? '' : sys(['stelnet server enable']));
    }
    if (g.telnetForbidden) {
      const srv = cfg.ssh.flags.includes('telnet server enable');
      const users = Object.values(cfg.aaa.users).filter(u => u.services.includes('telnet'));
      const lines = [];
      if (srv) lines.push('undo telnet server enable');
      if (users.length) lines.push('aaa', ...users.map(u => ` local-user ${u.name} service-type ${u.services.filter(s => s !== 'telnet').join(' ') || 'ssh'}`), ' quit');
      rule('telnet', 'Telnet запрещён', !srv && !users.length,
        [srv && 'включён telnet-сервер', users.length && `telnet разрешён пользователям: ${users.map(u => u.name).join(', ')}`].filter(Boolean).join('; '),
        lines.length ? sys(lines) : '', users.length ? 'service-type задаётся целиком: проверьте, что вход по SSH работает.' : '');
    }
    const vtys = cfg.ui.filter(u => /^vty/.test(u.name) && u.opts.length);
    if (g.vtyAaa) {
      const bad = vtys.filter(u => !u.opts.includes('authentication-mode aaa'));
      rule('vty-aaa', 'Вход по VTY через AAA (логин и пароль)', !bad.length,
        bad.length ? `Не AAA: ${bad.map(u => u.name).join(', ')}` : '',
        bad.length ? sys(bad.flatMap(u => [`user-interface ${u.name}`, ' authentication-mode aaa', ' quit'])) : '');
    }
    if (g.vtyIdleMax) {
      const bad = cfg.ui.filter(u => /^vty/.test(u.name)).filter(u => {
        const m = u.opts.map(o => o.match(/^idle-timeout (\d+)(?: (\d+))?/)).find(Boolean);
        if (!m) return false; // по умолчанию 10 минут
        const min = +m[1] + (+m[2] || 0) / 60;
        return min === 0 || min > g.vtyIdleMax;
      });
      rule('vty-idle', `Таймаут VTY-сессии не больше ${g.vtyIdleMax} мин`, !bad.length,
        bad.length ? `Превышен или отключён: ${bad.map(u => u.name).join(', ')}` : '',
        bad.length ? sys(bad.flatMap(u => [`user-interface ${u.name}`, ` idle-timeout ${g.vtyIdleMax} 0`, ' quit'])) : '');
    }
    if (g.consoleAuth) {
      const con = cfg.ui.find(u => /^con/.test(u.name));
      const bad = con && con.opts.includes('authentication-mode none');
      rule('console', 'Пароль на консольном порту', !bad, bad ? 'authentication-mode none' : '',
        bad ? sys(['user-interface con 0', ' authentication-mode aaa', ' quit']) : '',
        bad ? 'Убедитесь, что есть локальная учётка с service-type terminal и известным паролем — иначе консольный доступ будет потерян.' : '');
    }
    if (g.lldp) rule('lldp', 'LLDP включён', !!cfg.misc.lldp, cfg.misc.lldp ? '' : 'Нет «lldp enable»', cfg.misc.lldp ? '' : sys(['lldp enable']));
    if (g.timezone) {
      const ok = trimmedLines(cfg).has(g.timezone.trim());
      rule('tz', 'Часовой пояс', ok, ok ? g.timezone : `Ожидается «${g.timezone}»`, ok ? '' : sys([g.timezone.trim()]));
    }
    const lines = trimmedLines(cfg);
    for (const l of (g.requiredLines || []).map(x => x.trim()).filter(Boolean)) {
      const ok = lines.has(l);
      rule('req:' + l, `Есть строка «${l}»`, ok, '', ok ? '' : sys([l]), ok ? '' : 'Команда добавляется в системном режиме. Если это настройка интерфейса или раздела — выполните её внутри него.');
    }
    for (const l of (g.forbiddenLines || []).map(x => x.trim()).filter(Boolean)) {
      const found = [...lines].filter(x => x === l || x.startsWith(l + ' '));
      rule('forb:' + l, `Нет строки «${l}»`, !found.length, found.length ? `Найдено: ${found.slice(0, 3).join('; ')}` : '',
        found.length ? sys(found.map(x => Fixes.undoOf(x))) : '',
        found.length ? 'Команда undo сформирована автоматически и убирает строку целиком — проверьте, что вместе с ней не отключится нужное (например, другие версии или параметры в той же строке).' : '');
    }

    // Порты: сравнение с шаблоном своей роли
    const groups = new Map();
    let portsChecked = 0;
    for (const p of cfg.ports) {
      const tplId = ROLE_TPL[p.role];
      const t = tplId && std && std.ports && std.ports[tplId];
      if (!t || !t.enabled || !t.lines.length || p.shutdown || !p.lines.length) continue;
      portsChecked++;
      // Скорость, дуплекс и автосогласование — свойства конкретного устройства, с эталоном не сравниваются
      const change = Fixes.portChange(p, { lines: t.lines }).filter(l => !PHYS.test(l));
      if (!change.length) continue;
      const key = tplId + '|' + change.join('|');
      if (!groups.has(key)) groups.set(key, { tpl: tplId, label: TPL_LABEL[tplId], change, ports: [] });
      groups.get(key).ports.push(p);
    }
    const portGroups = [...groups.values()].sort((a, b) => b.ports.length - a.ports.length)
      .map(gr => ({ ...gr, commands: sys(gr.ports.flatMap(p => Fixes.iface(p.name, gr.change))) }));
    const portsBad = portGroups.reduce((n, gr) => n + gr.ports.length, 0);

    // Все исправления одним блоком
    const allLines = [];
    for (const r of rules) if (!r.ok && r.commands) allLines.push(...r.commands.split('\n').filter(l => l !== 'system-view' && l !== 'return'));
    for (const gr of portGroups) for (const p of gr.ports) allLines.push(...Fixes.iface(p.name, gr.change));

    return {
      rules, portGroups,
      totals: {
        rules: rules.length, rulesOk: rules.filter(r => r.ok).length,
        ports: portsChecked, portsOk: portsChecked - portsBad,
      },
      allCommands: allLines.length ? sys(allLines) : '',
    };
  }

  function score(rep) {
    const total = rep.totals.rules + rep.totals.ports;
    return total ? Math.round(100 * (rep.totals.rulesOk + rep.totals.portsOk) / total) : 100;
  }

  const api = { derive, check, score, ROLE_TPL, TPL_LABEL };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Standard = api;
})(typeof window !== 'undefined' ? window : globalThis);
