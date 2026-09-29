// Пересобирает config.js из 3floor.txt (секреты скрываются).
//   node update-config.js            — обновить один раз
//   node update-config.js --watch    — следить за файлом и обновлять при каждом сохранении
//   node update-config.js other.txt  — взять другой файл конфига
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const watch = args.includes('--watch') || args.includes('-w');
const defaultSrc = path.resolve(__dirname, args.find(a => !a.startsWith('-')) || '3floor.txt');
const out = path.join(__dirname, 'config.js');

function redact(text) {
  return text
    .replace(/\r/g, '')
    .replace(/%\^%#[\s\S]*?%\^%#/g, '******')
    .replace(/(irreversible-cipher|cipher|simple)\s+(?!\*{6})\S+/g, '$1 ******');
}

function build(src = defaultSrc) {
  let text;
  try {
    text = fs.readFileSync(src, 'utf8');
  } catch (e) {
    console.error(`[${time()}] Не удалось прочитать ${src}: ${e.message}`);
    return;
  }
  const js = `// Сгенерировано из ${path.basename(src)} скриптом update-config.js. Секреты (пароли, ключи, community) скрыты.\n` +
    `window.RAW_CONFIG = ${JSON.stringify(redact(text))};\n`;
  fs.writeFileSync(out, js);
  const ports = (text.match(/^interface (X?GigabitEthernet)/gm) || []).length;
  console.log(`[${time()}] config.js обновлён: ${text.split('\n').length} строк, ${ports} портов`);
}

const time = () => new Date().toLocaleTimeString('ru-RU');

module.exports = { build, redact };

if (require.main === module) {
  build();
}

if (require.main === module && watch) {
  console.log(`Слежу за ${path.basename(defaultSrc)}. После сохранения обновите страницу в браузере (F5). Ctrl+C — выход.`);
  let timer = null;
  // watchFile надёжнее fs.watch на Windows: редакторы часто пересоздают файл при сохранении
  fs.watchFile(defaultSrc, { interval: 500 }, (cur, prev) => {
    if (cur.mtimeMs === prev.mtimeMs) return;
    clearTimeout(timer);
    timer = setTimeout(build, 200);
  });
}
