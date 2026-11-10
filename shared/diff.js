// Построчное сравнение текстов (алгоритм Майерса). Работает и в браузере (window.LineDiff),
// и в Node (require('./diff')).
(function (root) {
  'use strict';

  // Возвращает список строк с пометкой: ' ' — без изменений, '-' — удалена, '+' — добавлена
  function diffLines(a, b) {
    let start = 0;
    while (start < a.length && start < b.length && a[start] === b[start]) start++;
    let endA = a.length, endB = b.length;
    while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }

    const A = a.slice(start, endA), B = b.slice(start, endB);
    const mid = myers(A, B) || [...A.map(line => ({ op: '-', line })), ...B.map(line => ({ op: '+', line }))];

    const out = [];
    for (let i = 0; i < start; i++) out.push({ op: ' ', line: a[i] });
    for (const x of mid) out.push(x);
    for (let i = endA; i < a.length; i++) out.push({ op: ' ', line: a[i] });
    return out;
  }

  function myers(a, b, maxD = 1000) {
    const n = a.length, m = b.length, max = n + m;
    if (!max) return [];
    if (max > 40000) return null; // слишком большой объём изменений — показываем целиком
    const off = max + 1;
    const v = new Int32Array(2 * max + 3);
    const trace = [];
    for (let d = 0; d <= Math.min(max, maxD); d++) {
      trace.push(v.slice());
      for (let k = -d; k <= d; k += 2) {
        let x = (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) ? v[off + k + 1] : v[off + k - 1] + 1;
        let y = x - k;
        while (x < n && y < m && a[x] === b[y]) { x++; y++; }
        v[off + k] = x;
        if (x >= n && y >= m) return backtrack(trace, a, b, off);
      }
    }
    return null;
  }

  function backtrack(trace, a, b, off) {
    let x = a.length, y = b.length;
    const ops = [];
    for (let d = trace.length - 1; d >= 0; d--) {
      const v = trace[d];
      const k = x - y;
      const prevK = (k === -d || (k !== d && v[off + k - 1] < v[off + k + 1])) ? k + 1 : k - 1;
      const prevX = v[off + prevK], prevY = prevX - prevK;
      while (x > prevX && y > prevY) { ops.push({ op: ' ', line: a[x - 1] }); x--; y--; }
      if (d > 0) {
        if (x === prevX) { ops.push({ op: '+', line: b[y - 1] }); y--; }
        else { ops.push({ op: '-', line: a[x - 1] }); x--; }
      }
    }
    return ops.reverse();
  }

  // Группирует изменения в блоки с `context` строками вокруг
  function hunks(ops, context = 3) {
    const out = [];
    let cur = null, lastChange = -Infinity;
    let aLine = 0, bLine = 0;
    ops.forEach((o, i) => {
      if (o.op !== ' ') {
        if (!cur || i - lastChange > context * 2) {
          cur = { lines: [], aStart: null, bStart: null };
          out.push(cur);
          for (let j = Math.max(0, i - context); j < i; j++) cur.lines.push({ ...ops[j], i: j });
        } else {
          for (let j = lastChange + 1; j < i; j++) cur.lines.push({ ...ops[j], i: j });
        }
        cur.lines.push({ ...o, i });
        lastChange = i;
      } else if (cur && i - lastChange <= context) {
        // хвост контекста добавляется при закрытии блока
      }
    });
    // хвосты контекста
    for (const h of out) {
      const last = h.lines[h.lines.length - 1].i;
      for (let j = last + 1; j < Math.min(ops.length, last + 1 + context); j++) {
        if (ops[j].op !== ' ') break;
        h.lines.push({ ...ops[j], i: j });
      }
    }
    // номера строк в старой и новой версии
    const pos = [];
    for (const o of ops) { pos.push({ a: aLine + 1, b: bLine + 1 }); if (o.op !== '+') aLine++; if (o.op !== '-') bLine++; }
    for (const h of out) for (const l of h.lines) { l.aNo = l.op === '+' ? null : pos[l.i].a; l.bNo = l.op === '-' ? null : pos[l.i].b; }
    return out;
  }

  function stats(ops) {
    let added = 0, removed = 0;
    for (const o of ops) { if (o.op === '+') added++; else if (o.op === '-') removed++; }
    return { added, removed };
  }

  const api = { diffLines, hunks, stats };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.LineDiff = api;
})(typeof window !== 'undefined' ? window : globalThis);
