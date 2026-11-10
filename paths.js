// Где лежат данные приложения (список коммутаторов, конфигурации, история).
// По умолчанию — папка data рядом с кодом. Приложение Electron передаёт свою папку
// через SWCFG_DATA: внутри собранного exe код лежит в архиве, куда писать нельзя.
const path = require('path');

const DATA = process.env.SWCFG_DATA ? path.resolve(process.env.SWCFG_DATA) : path.join(__dirname, 'data');

// Файлы, которые запускаются внешними программами (powershell), в exe распаковываются рядом с архивом
const unpacked = file => path.join(__dirname, file).replace(/app\.asar([\\/])/, 'app.asar.unpacked$1');

module.exports = { DATA, unpacked };
