// Рисует иконку приложения build/icon.png (256×256): передняя панель коммутатора с портами.
//   node build/make-icon.js
// electron-builder сам делает из неё icon.ico для exe и установщика.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const N = 256, SS = 4; // размер и сглаживание (точек на пиксель по каждой оси)

// Скруглённый прямоугольник: точка внутри?
const rrect = (x0, y0, x1, y1, r) => (x, y) => {
  if (x < x0 || x > x1 || y < y0 || y > y1) return false;
  const cx = Math.min(Math.max(x, x0 + r), x1 - r), cy = Math.min(Math.max(y, y0 + r), y1 - r);
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
};
const circle = (cx, cy, r) => (x, y) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r;

// Слои снизу вверх: [фигура, цвет(x, y)]
const layers = [];
const solid = c => () => c;
const add = (shape, color) => layers.push([shape, typeof color === 'function' ? color : solid(color)]);

// Фон — синий градиент сверху вниз
add(rrect(8, 8, 248, 248, 52), (x, y) => {
  const t = (y - 8) / 240;
  return [Math.round(37 + (29 - 37) * t), Math.round(117 + (78 - 117) * t), Math.round(252 + (216 - 252) * t)];
});

// Корпус коммутатора
add(rrect(28, 82, 228, 182, 14), [15, 23, 42]);
add(rrect(34, 88, 222, 176, 10), [30, 41, 59]);

// Два ряда портов по 6, у каждого — индикатор
const portW = 22, gap = 7, startX = 46;
const led = [[34, 197, 94], [34, 197, 94], [250, 204, 21], [34, 197, 94], [100, 116, 139], [34, 197, 94]];
for (let row = 0; row < 2; row++) {
  const y = 98 + row * 38;
  for (let i = 0; i < 6; i++) {
    const x = startX + i * (portW + gap);
    add(rrect(x, y, x + portW, y + 24, 3), [226, 232, 240]);
    add(rrect(x + 5, y + 5, x + portW - 5, y + 19, 2), [51, 65, 85]);
    add(rrect(x + 8, y + 19, x + portW - 8, y + 24, 1), [51, 65, 85]); // защёлка RJ45
  }
}
// Индикаторы портов — строка внизу корпуса
for (let i = 0; i < 6; i++) add(circle(startX + i * (portW + gap) + portW / 2, 169, 3.2), led[i]);

// Сеть: три линии от коммутатора вверх, к «облаку» узлов
add(rrect(125, 50, 131, 82, 2), [219, 234, 254]);
add(rrect(66, 50, 190, 56, 3), [219, 234, 254]);
add(rrect(66, 50, 72, 82, 2), [219, 234, 254]);
add(rrect(184, 50, 190, 82, 2), [219, 234, 254]);
add(circle(128, 46, 14), [255, 255, 255]);
add(circle(128, 46, 7), [37, 99, 235]);

// Линия снизу — к компьютерам
add(rrect(125, 182, 131, 206, 2), [219, 234, 254]);
add(rrect(98, 204, 158, 222, 5), [255, 255, 255]);
add(rrect(104, 209, 152, 217, 2), [37, 99, 235]);

// Растеризация с суперсэмплингом
const px = Buffer.alloc(N * N * 4);
for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
  let r = 0, g = 0, b = 0, a = 0;
  for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
    const fx = x + (sx + 0.5) / SS, fy = y + (sy + 0.5) / SS;
    let c = null;
    for (const [shape, color] of layers) if (shape(fx, fy)) c = color(fx, fy);
    if (c) { r += c[0]; g += c[1]; b += c[2]; a++; }
  }
  const o = (y * N + x) * 4;
  if (a) { px[o] = r / a; px[o + 1] = g / a; px[o + 2] = b / a; }
  px[o + 3] = Math.round(255 * a / (SS * SS));
}

// Кодирование PNG
const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc = buf => { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
  return Buffer.concat([len, td, c]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(N, 0); ihdr.writeUInt32BE(N, 4); ihdr[8] = 8; ihdr[9] = 6; // 8 бит, RGBA
const raw = Buffer.alloc(N * (N * 4 + 1));
for (let y = 0; y < N; y++) px.copy(raw, y * (N * 4 + 1) + 1, y * N * 4, (y + 1) * N * 4);
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0)),
]);
fs.writeFileSync(path.join(__dirname, 'icon.png'), png);
console.log('build/icon.png готов');
