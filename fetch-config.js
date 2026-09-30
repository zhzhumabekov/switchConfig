// Подключается к коммутатору Huawei по SSH, забирает текущую конфигурацию,
// сохраняет её в 3floor.txt и пересобирает config.js для страницы.
//
//   node fetch-config.js --host 192.168.1.1 --user admin [--port 22] [--out 3floor.txt]
//
// Адрес и логин можно задать переменными окружения SWITCH_HOST и SWITCH_USER.
//
// Пароль спрашивается при запуске (ввод скрыт) или берётся из переменной окружения SWITCH_PASSWORD.
// В файлах пароль не сохраняется.
const fs = require('fs');
const path = require('path');
const { Client } = require('ssh2');
const { build } = require('./update-config');

const DEFAULTS = { host: process.env.SWITCH_HOST || '', port: 22, user: process.env.SWITCH_USER || '', out: '3floor.txt', timeout: 60 };

function parseArgs(argv) {
  const opt = { ...DEFAULTS };
  for (let i = 0; i < argv.length; i++) {
    const m = argv[i].match(/^--(host|port|user|out|timeout)$/);
    if (m && argv[i + 1] != null) opt[m[1]] = argv[++i];
    else if (argv[i] === '-h' || argv[i] === '--help') opt.help = true;
  }
  opt.port = +opt.port;
  opt.timeout = +opt.timeout;
  return opt;
}

function askHidden(question) {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stdout.write(question);
    if (!stdin.isTTY) {
      // Ввод из пайпа: просто читаем первую строку
      let buf = '';
      stdin.setEncoding('utf8');
      stdin.on('data', d => { buf += d; if (buf.includes('\n')) { stdin.pause(); resolve(buf.split(/\r?\n/)[0]); } });
      stdin.on('end', () => resolve(buf.trim()));
      return;
    }
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = ch => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData);
          process.stdout.write('\n');
          return resolve(value);
        }
        if (c === '\u0003') { process.stdout.write('\n'); return reject(new Error('Отменено')); }
        if (c === '\u0008' || c === '\u007f') value = value.slice(0, -1);
        else value += c;
      }
    };
    stdin.on('data', onData);
  });
}

// Убирает управляющие последовательности терминала и пагинацию («---- More ----» Huawei, «--More--» Cisco)
function clean(text) {
  return text
    .replace(/ *---- More ----/g, '')
    .replace(/\x1b\[\d+D *\x1b\[\d+D/g, '')   // стирание строки «More» курсором (Huawei)
    .replace(/ ?--More-- ?/g, '')
    .replace(/\x08+ *\x08+/g, '')              // стирание «--More--» возвратом каретки (Cisco)
    .replace(/\x08/g, '')
    .replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')
    .replace(/\r+\n/g, '\n')
    .replace(/\r/g, '');
}

// Особенности CLI разных производителей
const VENDORS = {
  huawei: { prompt: /(?:^|\n)([<\[][^<>\[\]\r\n]{1,64}[>\]])\s*$/, more: /---- More ----\s*$/, pager: 'screen-length 0 temporary', quit: 'quit', name: p => p.slice(1, -1) },
  cisco: { prompt: /(?:^|\n)([A-Za-z0-9._\-()\/]{1,64}[#>])\s*$/, more: /--More--\s*$/, pager: 'terminal length 0', quit: 'exit', name: p => p.slice(0, -1) },
};
const PROMPT = VENDORS.huawei.prompt;

// Выполняет команды в одной SSH-сессии и возвращает их вывод (по элементу на команду).
// opt.testOnly — только войти и вернуть имя из приглашения (<SWITCH-NAME>), без команд.
// opt.vendor — 'huawei' (по умолчанию) или 'cisco'; opt.enablePassword — пароль enable для Cisco.
function runCommands(opt, password, commands) {
  const timeout = opt.timeout || 60;
  const V = VENDORS[opt.vendor] || VENDORS.huawei;
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const queue = [V.pager, ...commands];
    let enabling = false;
    const outputs = [];
    let buf = '';
    let idx = -1;       // -1 — ждём приглашение после входа
    let prompt = null;  // приглашение, например <SWITCH-NAME>
    let settled = false;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      err ? reject(err) : resolve(value);
      setTimeout(() => conn.end(), 300);
    };
    const timer = setTimeout(() => finish(new Error(`Таймаут ${timeout} с — коммутатор не ответил`)), timeout * 1000);

    conn.on('ready', () => {
      conn.shell({ term: 'vt100', cols: 512, rows: 200 }, (err, stream) => {
        if (err) return finish(err);
        const send = cmd => stream.write(cmd + '\n');

        stream.on('data', d => {
          if (settled) return;
          buf += d.toString('utf8');
          // Если пагинация не отключилась — отвечаем пробелом
          if (V.more.test(buf)) { stream.write(' '); return; }
          if (/\[Y\/N\]:?\s*$/i.test(buf)) { stream.write('N\n'); return; }  // напр. «сменить пароль?»

          // Cisco: переход в привилегированный режим (enable)
          if (enabling) {
            if (/Password:\s*$/i.test(buf)) { buf = ''; send(opt.enablePassword); return; }
            if (/% ?(Access denied|Bad secrets|Error in authentication)/i.test(buf)) return finish(new Error('Неверный пароль enable'));
            const m = clean(buf).match(V.prompt);
            if (!m) return;
            enabling = false;
            if (!m[1].endsWith('#')) return finish(new Error('Не удалось войти в режим enable'));
            prompt = m[1];
            buf = '';
            idx = 0;
            send(queue[0]);
            return;
          }

          if (!prompt) {
            const m = clean(buf).match(V.prompt);
            if (!m) return;
            prompt = m[1];
            if (opt.testOnly) { send(V.quit); return finish(null, V.name(prompt)); }
            if (opt.vendor === 'cisco' && prompt.endsWith('>') && opt.enablePassword) {
              enabling = true; buf = ''; send('enable'); return;
            }
          } else if (!clean(buf).replace(/\s+$/, '').endsWith(prompt)) {
            return; // команда ещё выводит данные
          } else if (idx >= 1) {
            outputs[idx - 1] = clean(buf); // idx 0 — screen-length, его вывод не нужен
          }

          idx++;
          buf = '';
          if (idx < queue.length) send(queue[idx]);
          else { send(V.quit); finish(null, outputs); }
        });
        stream.on('close', () => finish(new Error('Сессия закрылась до получения данных')));
      });
    });

    conn.on('keyboard-interactive', (name, instr, lang, prompts, done) => done(prompts.map(() => password)));
    conn.on('error', err => finish(err));

    conn.connect({
      host: opt.host,
      port: opt.port,
      username: opt.user,
      password,
      tryKeyboard: true,
      readyTimeout: 20000,
      // Коммутаторы на V200R0xx поддерживают только старые алгоритмы. Ключ хоста
      // ecdsa-sha2-nistp521 исключён: VRP подписывает им некорректно
      // («signature verification failed»), поэтому используем ssh-rsa.
      algorithms: {
        kex: { append: ['diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1'] },
        cipher: { append: ['aes128-cbc', 'aes256-cbc', '3des-cbc'] },
        serverHostKey: ['ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-dss'],
        hmac: { append: ['hmac-sha1'] },
      },
    });
  });
}

function fetchConfig(opt, password) {
  if (opt.testOnly) return runCommands(opt, password, []);
  if (opt.vendor === 'cisco') throw new Error('Для Cisco используйте runCommands');
  return runCommands(opt, password, ['display current-configuration']).then(([out]) => extract(out));
}

// Оставляет только конфигурацию: от первой строки после команды до «return»
function extract(text) {
  const lines = text.split('\n');
  let start = lines.findIndex(l => /display current-configuration/.test(l)) + 1;
  let end = lines.findIndex((l, i) => i >= start && l.trim() === 'return');
  if (end === -1) throw new Error('В выводе не найден конец конфигурации («return»). Проверьте права пользователя.');
  while (start < end && !lines[start].trim()) start++;
  return lines.slice(start, end + 1).map(l => l.replace(/\s+$/, '')).join('\n') + '\n';
}

async function main() {
  const opt = parseArgs(process.argv.slice(2));
  if (opt.help) {
    console.log('node fetch-config.js [--host IP] [--port 22] [--user имя] [--out файл.txt] [--timeout сек]');
    return;
  }
  if (!opt.host || !opt.user) throw new Error('Укажите адрес и логин: --host IP --user имя (или SWITCH_HOST / SWITCH_USER)');
  const out = path.resolve(__dirname, opt.out);
  const password = process.env.SWITCH_PASSWORD || await askHidden(`Пароль для ${opt.user}@${opt.host}: `);

  console.log(`Подключаюсь к ${opt.host}:${opt.port}…`);
  const config = await fetchConfig(opt, password);
  const lineCount = config.split('\n').length - 1;
  if (lineCount < 10 || !/^sysname /m.test(config)) throw new Error('Получен подозрительно короткий вывод — файл не перезаписан.');

  // Предыдущую версию сохраняем рядом, чтобы можно было сравнить или откатиться
  if (fs.existsSync(out)) {
    const old = fs.readFileSync(out, 'utf8').replace(/\r/g, '');
    if (old === config) {
      console.log('Конфигурация не изменилась с прошлого раза.');
    } else {
      const prev = out.replace(/\.txt$/i, '') + '.prev.txt';
      fs.writeFileSync(prev, old);
      console.log(`Старая версия сохранена в ${path.basename(prev)}`);
    }
  }
  fs.writeFileSync(out, config);
  console.log(`Сохранено ${lineCount} строк в ${path.basename(out)}`);
  build(out);
  console.log('Готово. Обновите страницу index.html в браузере (F5).');
}

// Понятный текст ошибки для людей
function humanError(err) {
  const m = err.message || String(err);
  if (/authentication/i.test(m)) return 'Неверный логин или пароль';
  if (/ECONNREFUSED/.test(m)) return 'Подключение отклонено: SSH на коммутаторе выключен или порт указан неверно';
  if (/ETIMEDOUT|Timed out while waiting for handshake/i.test(m)) return 'Коммутатор не отвечает (нет сети до адреса или SSH закрыт)';
  if (/EHOSTUNREACH|ENETUNREACH/.test(m)) return 'Адрес недоступен из этой сети';
  if (/ENOTFOUND|EAI_AGAIN/.test(m)) return 'Не удалось найти адрес';
  return m;
}

module.exports = { runCommands, fetchConfig, extract, clean, humanError, VENDORS };

if (require.main === module) {
  main().catch(err => {
    console.error('Ошибка: ' + humanError(err));
    process.exitCode = 1;
  });
}
