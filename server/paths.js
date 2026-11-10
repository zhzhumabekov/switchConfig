// Пути проекта.
//   ROOT — корень проекта (папка над server/): там лежат public/, shared/ и 3floor.txt.
//   DATA — данные приложения (список коммутаторов, конфигурации, история). По умолчанию — data/
//          в корне проекта. Приложение Electron передаёт свою папку через SWCFG_DATA: внутри
//          собранного exe код лежит в архиве, куда писать нельзя.
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DATA = process.env.SWCFG_DATA ? path.resolve(process.env.SWCFG_DATA) : path.join(ROOT, 'data');

// Файлы, которые запускаются внешними программами (powershell), в exe распаковываются рядом с архивом
const unpacked = file => path.join(__dirname, file).replace(/app\.asar([\\/])/, 'app.asar.unpacked$1');

module.exports = { ROOT, DATA, unpacked };
