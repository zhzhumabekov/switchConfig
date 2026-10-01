// Журнал коммутатора Huawei VRP (display logbuffer): разбор записей, рекомендации, аудит.
// Только чтение. Результат кладётся в состояние коммутатора (state.log).
const COMMANDS = { logbuffer: 'display logbuffer' };

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
const LEVELS = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];
const times = n => { const m10 = n % 10, m100 = n % 100; return `${n} ${m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? 'раза' : 'раз'}`; };
const short = n => String(n || '').replace(/^XGigabitEthernet/, 'XGE').replace(/^GigabitEthernet/, 'GE');
const normPortName = n => String(n || '').replace(/^XGE(?=\d)/i, 'XGigabitEthernet').replace(/^GE(?=\d)/i, 'GigabitEthernet');
const PORT_RE = /\b((?:X?GigabitEthernet|Eth-Trunk|XGE|GE)\d+(?:\/\d+){0,2})\b/;

/* ---------- разбор ----------
Oct  1 2026 10:21:03+06:00 SW %%01IFNET/4/IF_STATE(l)[12]:Interface GigabitEthernet0/0/4 has turned into DOWN state.
*/
const LINE_RE = /^(\w{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\S*\s+(\S+)\s+%%(\d{2})([\w-]+)\/(\d)\/([\w-]+)(?:\([a-z]+\))?(?:\[\d+\])?\s*:\s*(.*)$/i;

function parseBuffer(text) {
  const t = String(text || '').replace(/\r/g, '');
  const meta = {
    enabled: /contents\s*:\s*enabled/i.test(t),
    maxSize: +((t.match(/Allowed max buffer size\s*:\s*(\d+)/i) || [])[1] || 0),
    size: +((t.match(/Actual buffer size\s*:\s*(\d+)/i) || [])[1] || 0),
    overwritten: +((t.match(/Overwritten messages\s*:\s*(\d+)/i) || [])[1] || 0),
    current: +((t.match(/Current messages\s*:\s*(\d+)/i) || [])[1] || 0),
  };
  const entries = [];
  for (const raw of t.split('\n')) {
    const l = raw.replace(/\s+$/, '');
    const m = l.match(LINE_RE);
    if (m) {
      const mon = MONTHS[m[1].toLowerCase()];
      const d = new Date(+m[3], mon == null ? 0 : mon, +m[2], +m[4], +m[5], +m[6]);
      entries.push({ ts: d.getTime(), time: `${m[3]}-${String((mon ?? 0) + 1).padStart(2, '0')}-${String(m[2]).padStart(2, '0')} ${m[4]}:${m[5]}:${m[6]}`,
        host: m[7], module: m[9].toUpperCase(), level: +m[10], brief: m[11], text: m[12].trim() });
    } else if (entries.length && /^\s+\S/.test(l) && !/:\s*\S/.test(l.slice(0, 5))) {
      entries[entries.length - 1].text += ' ' + l.trim(); // продолжение длинной записи
    }
  }
  entries.sort((a, b) => a.ts - b.ts);
  return { meta, entries };
}

const field = (text, name) => ((text.match(new RegExp(`${name}\\s*=\\s*"?([^,)"]+)`, 'i')) || [])[1] || '').trim();
const sys = lines => ['system-view', ...lines, 'return'].join('\n');

// IP-адреса этого компьютера — чтобы узнать в журнале собственные SSH-сессии сбора
const LOCAL_IPS = new Set(Object.values(require('os').networkInterfaces()).flat().filter(a => a && a.family === 'IPv4').map(a => a.address));
const maxPps = items => Math.max(0, ...items.map(e => +(e.text.match(/AttackPackets\s*=\s*(\d+)/i) || [])[1] || 0));

/* ---------- правила ----------
   Каждое правило: test(e) → подходит ли запись; key(e) → объект проблемы (порт, IP…);
   build(group) → { sev, title, detail, advice, commands } или null, если порога нет. */
const RULES = [
  {
    id: 'flap', cat: 'Порты',
    test: e => /IF_STATE|PHY_STATUS|LINK_STATE|IFNET/i.test(e.module + e.brief) && /(DOWN|UP)\b/i.test(e.text) && PORT_RE.test(e.text) && !/Vlanif|LoopBack|NULL/i.test(e.text),
    key: e => (e.text.match(PORT_RE) || [])[1],
    build: g => {
      const downs = g.items.filter(e => /DOWN/i.test(e.text)).length;
      if (downs < 3) return null;
      return {
        sev: downs >= 10 ? 'high' : 'med',
        title: `Порт ${short(g.key)} «мигает»: падал ${times(downs)}`,
        detail: `Переходы up/down с ${g.first} по ${g.last}.`,
        advice: 'Частые падения порта — обычно плохой патч-корд или розетка, неисправная сетевая карта или энергосбережение на ПК (Green Ethernet / EEE). Замените патч-корд, проверьте ошибки на порту. Если к порту подключён коммутатор или точка доступа — проверьте их питание.',
        commands: [`display interface ${g.key}`, `display interface ${g.key} | include error|CRC`].join('\n'),
        port: g.key,
      };
    },
  },
  {
    id: 'loop', cat: 'Петли',
    test: e => /LDT|LOOP|LBDT/i.test(e.module + e.brief) || /loop(back)? (exists|detected|occurred)|loopback.*detect/i.test(e.text),
    key: e => (e.text.match(PORT_RE) || [])[1] || 'общее',
    build: g => ({
      sev: 'high', title: `Обнаружена петля${g.key !== 'общее' ? ` на ${short(g.key)}` : ''} (${times(g.count)})`,
      detail: `Последний раз — ${g.last}.`,
      advice: 'Где-то кабель замыкает сеть сам на себя: воткнут в два порта, или пользователь подключил свой коммутатор двумя проводами. Найдите и уберите лишний кабель. Порт с петлёй блокируется loopback-detect и восстанавливается сам.',
      commands: ['display loopback-detect', ...(g.key !== 'общее' ? [`display mac-address interface ${g.key}`] : [])].join('\n'),
      port: g.key !== 'общее' ? g.key : undefined,
    }),
  },
  {
    id: 'macflap', cat: 'Петли',
    test: e => /MFLP|MAC_?FLAP|MACFLAP/i.test(e.module + e.brief) || /mac[- ]?address(es)? (flapping|flap)|flapping/i.test(e.text) && /mac/i.test(e.text),
    key: e => field(e.text, 'MacAddress') || field(e.text, 'MAC') || 'общее',
    build: g => ({
      sev: 'high', title: `MAC-адрес «прыгает» между портами${g.key !== 'общее' ? `: ${g.key}` : ''} (${times(g.count)})`,
      detail: `Последний раз — ${g.last}. ${g.items[g.items.length - 1].text.slice(0, 200)}`,
      advice: 'Один и тот же MAC появляется то на одном порту, то на другом — почти всегда это петля через посторонний коммутатор или неправильно подключённую точку доступа. Найдите порты из сообщения и отключите лишнее подключение.',
      commands: g.key !== 'общее' ? `display mac-address ${g.key}` : 'display mac-address flapping record',
    }),
  },
  {
    id: 'bpdu', cat: 'STP',
    test: e => /BPDU.?PROTECT/i.test(e.brief + e.text),
    key: e => (e.text.match(PORT_RE) || [])[1] || 'общее',
    build: g => ({
      sev: 'high', title: `BPDU-protection отключила порт ${short(g.key)} (${times(g.count)})`,
      detail: `Последний раз — ${g.last}.`,
      advice: 'К пользовательскому порту подключили коммутатор (или точку доступа в режиме моста). Уберите устройство, затем включите порт: shutdown / undo shutdown, либо настройте автоматическое восстановление.',
      commands: g.key !== 'общее' ? sys([`interface ${g.key}`, ' shutdown', ' undo shutdown', ' quit']) : 'display stp brief',
      port: g.key !== 'общее' ? g.key : undefined,
    }),
  },
  {
    id: 'stp-tc', cat: 'STP',
    test: e => /MSTP|STP/i.test(e.module) && /TC|TOPOLOGY|ROOT/i.test(e.brief + e.text),
    key: e => /ROOT/i.test(e.brief) || /root bridge/i.test(e.text) ? 'root' : 'tc',
    build: g => {
      if (g.key === 'root') return { sev: 'high', title: `Сменялся корневой мост STP (${times(g.count)})`, detail: `Последний раз — ${g.last}.`,
        advice: 'Смена корня перестраивает всю сеть. Корнем должно быть ядро с явным приоритетом (stp root primary), а на коммутаторах доступа — stp bpdu-protection, чтобы посторонний коммутатор не стал корнем.', commands: 'display stp | include Root' };
      if (g.count < 5) return null;
      return { sev: 'med', title: `Частые изменения топологии STP: ${g.count} записей`, detail: `С ${g.first} по ${g.last}.`,
        advice: 'Каждое изменение топологии сбрасывает таблицы MAC — трафик кратко рассылается во все порты. Основная причина — пользовательские порты без stp edged-port (вкладка «STP» покажет, какие).', commands: 'display stp tc-bpdu statistics' };
    },
  },
  {
    id: 'loginfail', cat: 'Безопасность',
    test: e => /LOGIN_?FAIL|AUTHEN.*FAIL|LOGINFAIL/i.test(e.brief) || /(failed to (log ?in|login)|authentication fail|password authentication failed)/i.test(e.text) && !/SNMP/i.test(e.module + e.text),
    key: e => field(e.text, 'Ip(?:Address)?') || field(e.text, 'IpAddress') || (e.text.match(/(\d+\.\d+\.\d+\.\d+)/) || [])[1] || 'неизвестно',
    build: g => {
      const users = [...new Set(g.items.map(e => field(e.text, 'User(?:Name)?')).filter(Boolean))];
      return {
        sev: g.count >= 10 ? 'high' : g.count >= 3 ? 'med' : 'info',
        title: `Неудачные входы с ${g.key}: ${g.count}`,
        detail: `${users.length ? `Логины: ${users.slice(0, 5).join(', ')}. ` : ''}С ${g.first} по ${g.last}.`,
        advice: g.count >= 10 ? 'Похоже на перебор паролей. Ограничьте доступ к управлению по SSH только с адресов администраторов (ACL на VTY) и проверьте, чей это адрес.'
          : 'Кто-то ошибается с паролем. Если адрес незнакомый — проверьте, чей он (поиск по IP вверху страницы).',
        commands: sys(['acl number 2001', ` rule 5 permit source <сеть-администраторов> <wildcard>`, ' rule 100 deny', ' quit', 'user-interface vty 0 4', ' acl 2001 inbound', ' quit']),
        ip: g.key,
        warn: 'Перед применением ACL убедитесь, что ваш адрес входит в разрешённую сеть, иначе потеряете доступ по SSH.',
      };
    },
  },
  {
    id: 'snmpfail', cat: 'Безопасность',
    test: e => /SNMP/i.test(e.module) && /auth|fail|community/i.test(e.brief + e.text),
    key: e => field(e.text, 'SourceIP') || field(e.text, 'Ip(?:Address)?') || (e.text.match(/(\d+\.\d+\.\d+\.\d+)/) || [])[1] || 'неизвестно',
    build: g => ({
      sev: 'med', title: `Ошибки SNMP-аутентификации с ${g.key}: ${g.count}`, detail: `Последний раз — ${g.last}.`,
      advice: 'С этого адреса опрашивают коммутатор с неверным community. Если это сервер мониторинга — исправьте community в его настройках; если адрес чужой — это сканирование сети, ограничьте SNMP списком доступа (snmp-agent acl).',
      commands: sys(['acl number 2000', ' rule 5 permit source <IP-сервера-мониторинга> 0', ' rule 100 deny', ' quit', 'snmp-agent acl 2000']),
      ip: g.key,
    }),
  },
  {
    id: 'dupip', cat: 'Сеть',
    test: e => /DUPLICATE|IPCONFLICT|IP_?CONFLICT|ARP_?DUP/i.test(e.brief) || /duplicate ip|ip address conflict|conflict.*ip/i.test(e.text),
    key: e => field(e.text, 'IpAddress') || field(e.text, 'Ip') || (e.text.match(/(\d+\.\d+\.\d+\.\d+)/) || [])[1] || 'неизвестно',
    build: g => {
      const macs = [...new Set(g.items.map(e => field(e.text, 'MacAddress') || field(e.text, 'Mac')).filter(Boolean))];
      return {
        sev: 'high', title: `Конфликт IP-адреса ${g.key}`, detail: `${macs.length ? `MAC: ${macs.join(', ')}. ` : ''}${times(g.count)}, последний — ${g.last}.`,
        advice: 'Два устройства используют один IP. Если это адрес самого коммутатора или шлюза — связь будет пропадать. Найдите устройство по MAC (поиск вверху страницы) и измените ему адрес или выдайте адрес по DHCP.',
        commands: `display arp | include ${g.key}`, ip: g.key, macs,
      };
    },
  },
  {
    id: 'hw', cat: 'Оборудование',
    test: e => /DEVM|ENTITY|ENTITYTRAP|POWER|FAN|TEMPERATURE/i.test(e.module) || /hwPower|hwFan|hwTemperature|hwEntity|power supply|fan (fault|failure|abnormal)|temperature (rise|exceed)/i.test(e.brief + e.text),
    key: e => /power/i.test(e.brief + e.text) ? 'питание' : /fan/i.test(e.brief + e.text) ? 'вентилятор' : /temperat/i.test(e.brief + e.text) ? 'температура' : 'устройство',
    build: g => {
      const bad = g.items.filter(e => e.level <= 4);
      if (!bad.length) return null;
      return {
        sev: bad.some(e => e.level <= 2) ? 'high' : 'med', title: `Сообщения об оборудовании: ${g.key} (${bad.length})`,
        detail: `Последнее: ${bad[bad.length - 1].text.slice(0, 200)}`,
        advice: { питание: 'Проверьте кабель питания и блок питания. Если блок питания один — его отказ остановит коммутатор.', вентилятор: 'Проверьте вентиляторный модуль, он мог засориться или выйти из строя — коммутатор начнёт перегреваться.', температура: 'Проверьте охлаждение в шкафу и вентиляторы коммутатора.' }[g.key] || 'Проверьте состояние модулей коммутатора.',
        commands: { питание: 'display power', вентилятор: 'display fan', температура: 'display temperature all' }[g.key] || 'display device',
      };
    },
  },
  {
    id: 'stack', cat: 'Оборудование',
    test: e => /STACK|CSS/i.test(e.module) && /leave|split|down|remove|fail|lost/i.test(e.brief + e.text),
    key: () => 'стек',
    build: g => ({
      sev: 'high', title: `События стека: член стека выходил / стек разделялся (${g.count})`, detail: `Последнее: ${g.items[g.items.length - 1].text.slice(0, 200)}`,
      advice: 'Проверьте стековые кабели и порты, а также питание членов стека. Стек, собранный кольцом, переживает обрыв одного кабеля.',
      commands: 'display stack\ndisplay stack port',
    }),
  },
  {
    // Auto port-defend: через порт приходит слишком много пакетов протокола на CPU
    id: 'portdefend', cat: 'Безопасность',
    test: e => /PORT_ATTACK|PORT_?DEFEND/i.test(e.brief) || /auto port-defend/i.test(e.text),
    key: e => `${normPortName(field(e.text, 'SourceAttackInterface')) || (e.text.match(PORT_RE) || [])[1] || '?'}|${field(e.text, 'AttackProtocol') || '?'}`,
    build: g => {
      const [port, proto] = g.key.split('|');
      const perHour = g.items.length > 1 ? g.items.length / Math.max(1, (g.items[g.items.length - 1].ts - g.items[0].ts) / 3600e3) : null;
      return {
        sev: g.count >= 20 ? 'med' : 'info',
        title: `Auto port-defend на ${short(port)}: слишком много ${proto} на CPU (${times(g.count)})`,
        detail: `С ${g.first} по ${g.last}${perHour == null ? '' : perHour >= 1 ? `, в среднем ${perHour.toFixed(1)} в час` : `, в среднем ${(perHour * 24).toFixed(1)} в сутки`}.`,
        advice: `Через этот порт на процессор коммутатора приходит больше пакетов ${proto}, чем порог защиты, и коммутатор временно понижает им приоритет. ` +
          'Транзитный трафик пользователей это не затрагивает — замедляется только трафик к самому коммутатору (управление, ARP к его IP). ' +
          'Если порт — связь с другим коммутатором (см. LLDP-соседа и описание порта), это обычно ложное срабатывание: через него приходят ARP всех устройств соседнего коммутатора, особенно если в этом VLAN у обоих коммутаторов есть IP (Vlanif). Тогда порт добавляют в белый список. ' +
          'Если срабатывания идут круглосуточно с равными промежутками — кто-то регулярно сканирует сеть (сканер, мониторинг, антивирус): найдите его по ARP-запросам. Если порт пользовательский — ищите источник за ним: сканер, вирус или петля.',
        commands: ['display auto-port-defend attack-source', `display cpu-defend statistics packet-type ${String(proto).toLowerCase()} all`, '',
          '# Только для порта между коммутаторами:', sys([`auto-port-defend whitelist 1 interface ${port}`])].join('\n'),
        port: port !== '?' ? port : undefined,
        warn: 'Белый список отключает защиту CPU для этого порта — добавляйте только порты между своими коммутаторами. Номер списка (1) должен быть свободен: проверьте «display auto-port-defend configuration».',
      };
    },
  },
  {
    // CPU-defend: много пакетов на CPU с одного IP
    id: 'sipattack', cat: 'Безопасность',
    test: e => /SIP_ATTACK/i.test(e.brief),
    key: e => `${field(e.text, 'SourceAttackIP') || '?'}|${field(e.text, 'AttackProtocol') || '?'}`,
    build: g => {
      const [ip, proto] = g.key.split('|');
      const self = LOCAL_IPS.has(ip);
      return {
        sev: self ? 'info' : g.count >= 10 ? 'med' : 'info',
        title: `Много пакетов ${proto} на CPU с ${ip}${self ? ' — это этот компьютер' : ''} (${times(g.count)}, до ${maxPps(g.items)} пак/с)`,
        detail: `С ${g.first} по ${g.last}.`,
        advice: self
          ? 'Это компьютер, на котором работает приложение: коммутатор так отмечает SSH-сессии сбора данных (во время выгрузки конфигурации и таблиц — сотни пакетов в секунду). Это не атака и на работу сети не влияет. Если сообщения мешают — увеличьте интервал сбора в «Настройках».'
          : `С адреса ${ip} на процессор коммутатора приходит много пакетов ${proto}. Если это сервер мониторинга или администратор — норма при интенсивном опросе. Если адрес незнакомый — проверьте, чей он: возможно сканирование портов или атака на управление коммутатором.`,
        commands: 'display cpu-defend statistics all\ndisplay auto-defend attack-source',
        ip,
      };
    },
  },
  {
    id: 'cpu', cat: 'Сеть',
    test: e => /CPUDEFEND|CPCAR|CPU/i.test(e.module) || /cpcar|dropped by cpu|cpu.*(usage|utilization).*(high|exceed|over)/i.test(e.text),
    key: () => 'cpu',
    build: g => ({
      sev: 'med', title: `Перегрузка CPU или отброс пакетов на CPU (${g.count})`, detail: `Последнее: ${g.items[g.items.length - 1].text.slice(0, 200)}`,
      advice: 'На процессор коммутатора приходит слишком много пакетов: шторм, петля, ARP-сканирование или атака. Проверьте, какой тип пакетов отбрасывается, и есть ли петли.',
      commands: 'display cpu-usage\ndisplay cpu-defend statistics all',
    }),
  },
  {
    id: 'storm', cat: 'Сеть',
    test: e => /storm/i.test(e.brief + e.text),
    key: e => (e.text.match(PORT_RE) || [])[1] || 'общее',
    build: g => ({
      sev: 'med', title: `Шторм трафика${g.key !== 'общее' ? ` на ${short(g.key)}` : ''} (${g.count})`, detail: `Последний раз — ${g.last}.`,
      advice: 'На порт приходит лавина широковещательного или многоадресного трафика — чаще всего из-за петли за этим портом или неисправной сетевой карты.',
      commands: g.key !== 'общее' ? `display interface ${g.key}` : 'display storm-control', port: g.key !== 'общее' ? g.key : undefined,
    }),
  },
  {
    id: 'ntp', cat: 'Сервисы',
    test: e => /NTP/i.test(e.module) && /lost|fail|unsynchron|not synchron|STRATUM|change/i.test(e.brief + e.text),
    key: () => 'ntp',
    build: g => ({
      sev: 'med', title: `Проблемы синхронизации времени NTP (${g.count})`, detail: `Последнее: ${g.items[g.items.length - 1].text.slice(0, 160)}`,
      advice: 'Без точного времени журналы разных устройств не совпадают, а некоторые проверки (сертификаты, Kerberos) могут не работать. Проверьте доступность NTP-серверов с коммутатора.',
      commands: 'display ntp-service status\ndisplay ntp-service sessions',
    }),
  },
  {
    id: 'optic', cat: 'Порты',
    test: e => /OPTICAL|TRANSCEIVER|SFP/i.test(e.module + e.brief) || /optical (module|power)|rx power|tx power|transceiver/i.test(e.text),
    key: e => (e.text.match(PORT_RE) || [])[1] || 'общее',
    build: g => ({
      sev: 'med', title: `Сообщения о SFP-модуле${g.key !== 'общее' ? ` на ${short(g.key)}` : ''} (${g.count})`, detail: `Последнее: ${g.items[g.items.length - 1].text.slice(0, 160)}`,
      advice: 'Модуль сообщает о проблеме с уровнем сигнала или о несовместимости. Почистите оптические разъёмы, проверьте модуль на другой стороне линии (вкладка «Оборудование» покажет уровни сигнала).',
      commands: g.key !== 'общее' ? `display transceiver interface ${g.key} verbose` : 'display transceiver verbose', port: g.key !== 'общее' ? g.key : undefined,
    }),
  },
  {
    id: 'reboot', cat: 'Оборудование',
    test: e => /reboot|cold start|warm start|system (is )?restart/i.test(e.brief + ' ' + e.text),
    key: () => 'reboot',
    build: g => ({
      sev: 'info', title: `Коммутатор перезагружался (${g.count})`, detail: `Последний раз — ${g.last}.`,
      advice: 'Если перезагрузку никто не планировал — проверьте питание (ИБП) и журнал перед перезагрузкой.', commands: 'display reboot-info',
    }),
  },
];

// Аудит: кто и какие команды выполнял, входы и выходы
function audit(entries) {
  const commands = [], logins = [];
  for (const e of entries) {
    if (/CMDRECORD/i.test(e.brief)) {
      const cmd = (e.text.match(/Command="([^"]*)"/i) || [])[1] || field(e.text, 'Command');
      if (!cmd || /^(display|dis |screen-length|quit|return|system-view|sys$|ping|tracert|undo terminal|terminal)/i.test(cmd.trim())) continue;
      commands.push({ time: e.time, ts: e.ts, user: field(e.text, 'User'), ip: field(e.text, 'Ip'), command: cmd });
    } else if (/LOGIN|LOGOUT|USERLOG/i.test(e.brief) && !/FAIL/i.test(e.brief)) {
      logins.push({ time: e.time, ts: e.ts, kind: /OUT/i.test(e.brief) ? 'выход' : 'вход', user: field(e.text, 'User(?:Name)?') || (e.text.match(/user\s+(\S+)/i) || [])[1] || '', ip: field(e.text, 'Ip(?:Address)?') || (e.text.match(/(\d+\.\d+\.\d+\.\d+)/) || [])[1] || '', text: e.text.slice(0, 160) });
    }
  }
  return { commands: commands.slice(-200).reverse(), logins: logins.slice(-200).reverse() };
}

function analyze(text) {
  const { meta, entries } = parseBuffer(text);
  const findings = [];
  const unmatched = new Map();
  const groups = new Map(); // ruleId|key → группа
  for (const e of entries) {
    const rule = RULES.find(r => r.test(e));
    if (!rule) {
      if (e.level <= 4) { const k = `${e.module}/${e.brief}`; const u = unmatched.get(k) || { module: e.module, brief: e.brief, level: e.level, count: 0, last: '', sample: '' }; u.count++; u.last = e.time; u.sample = e.text.slice(0, 200); unmatched.set(k, u); }
      continue;
    }
    const key = rule.key(e) || 'общее';
    const gk = rule.id + '|' + key;
    if (!groups.has(gk)) groups.set(gk, { rule, key, items: [] });
    groups.get(gk).items.push(e);
  }
  for (const [gk, g] of groups) {
    const grp = { key: g.key, items: g.items, count: g.items.length, first: g.items[0].time, last: g.items[g.items.length - 1].time };
    const f = g.rule.build(grp);
    if (f) findings.push({ id: gk, rule: g.rule.id, cat: g.rule.cat, count: grp.count, first: grp.first, last: grp.last, lastTs: g.items[g.items.length - 1].ts, ...f });
  }
  const order = { high: 0, med: 1, info: 2 };
  findings.sort((a, b) => order[a.sev] - order[b.sev] || b.lastTs - a.lastTs);
  const byLevel = Array(8).fill(0);
  for (const e of entries) if (e.level >= 0 && e.level <= 7) byLevel[e.level]++;
  return {
    meta, count: entries.length, first: entries[0] ? entries[0].time : null, last: entries.length ? entries[entries.length - 1].time : null,
    byLevel, findings, audit: audit(entries),
    other: [...unmatched.values()].sort((a, b) => a.level - b.level || b.count - a.count).slice(0, 30),
    recent: entries.slice(-500).reverse().map(e => ({ time: e.time, module: e.module, level: e.level, brief: e.brief, text: e.text.slice(0, 400) })),
  };
}

module.exports = { COMMANDS, analyze, parseBuffer, LEVELS };
