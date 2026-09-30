(() => {
'use strict';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let list = [];
let editing = null; // id редактируемого коммутатора или null для нового

/* ---------- API ---------- */
async function api(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: method !== 'GET' ? { 'Content-Type': 'application/json' } : {},
    body: method !== 'GET' ? JSON.stringify(body ?? {}) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `Ошибка ${r.status}`);
  return data;
}

function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + kind;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 5000);
}

function ago(iso) {
  if (!iso) return '';
  const d = new Date(iso), s = (Date.now() - d) / 1000;
  if (s < 60) return 'только что';
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
  return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/* ---------- список ---------- */
async function load() {
  try {
    list = await api('GET', 'api/switches');
  } catch (e) {
    $('#noServer').hidden = false;
    $('#listCard').hidden = true;
    $('#addBtn').disabled = $('#fetchAll').disabled = true;
    return;
  }
  renderList();
  if (!list.length) openForm(null);
}

function renderList() {
  $('#emptyState').hidden = list.length > 0;
  $('#swTable').hidden = !list.length;
  $('#fetchAll').disabled = !list.some(s => s.hasPassword);
  $('#swTable tbody').innerHTML = list.map(s => {
    let cfg;
    if (s.busy) cfg = '<span class="flag">забирается…</span>';
    else if (s.lastError) cfg = `<span class="flag warn" title="${esc(ago(s.lastError.at))}">Ошибка</span> <span class="muted">${esc(s.lastError.message)}</span>`;
    else if (s.hasConfig) cfg = `<span class="flag">загружена</span> <span class="muted">${esc(ago(s.lastFetch))}${s.source && !s.hasPassword ? ' · ' + esc(s.source) : ''}</span>`;
    else cfg = '<span class="muted">ещё не загружена</span>';
    return `<tr data-id="${esc(s.id)}">
      <td><b>${esc(s.name)}</b>${s.sysname && s.sysname !== s.name ? `<div class="muted mono">${esc(s.sysname)}</div>` : ''}</td>
      <td class="mono">${esc(s.host)}${s.port !== 22 ? ':' + s.port : ''}</td>
      <td class="mono">${esc(s.user)}</td>
      <td>${s.hasPassword ? '<span class="flag">сохранён</span>' : '<span class="flag warn">не задан</span>'}</td>
      <td>${cfg}</td>
      <td class="row-actions">
        <button class="btn small" data-act="fetch" ${s.hasPassword && !s.busy ? '' : 'disabled'} title="${s.hasPassword ? '' : 'Сначала сохраните пароль'}">Забрать</button>
        <button class="btn small" data-act="test" ${s.hasPassword ? '' : 'disabled'}>Проверить</button>
        <button class="btn small" data-act="edit">Изменить</button>
        <button class="btn small danger" data-act="delete">Удалить</button>
      </td>
    </tr>`;
  }).join('');
}

/* ---------- форма ---------- */
function openForm(id) {
  editing = id;
  const s = list.find(x => x.id === id);
  const f = $('#swForm');
  f.reset();
  f.elements.name.value = s ? s.name : '';
  f.elements.host.value = s ? s.host : '';
  f.elements.port.value = s ? s.port : 22;
  f.elements.user.value = s ? s.user : '';
  f.elements.password.type = 'password';
  f.elements.password.placeholder = s && s.hasPassword ? '•••••••• (сохранён)' : '';
  $('#pwHint').textContent = s && s.hasPassword ? 'Оставьте пустым, чтобы не менять' : '';
  $('#clearPwRow').hidden = !(s && s.hasPassword);
  $('#formTitle').textContent = s ? `Изменить: ${s.name}` : 'Новый коммутатор';
  $('#formStatus').textContent = '';
  $('#formStatus').className = 'form-status';
  $('#formCard').hidden = false;
  $('#formCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
  (s ? f.elements.password : f.elements.name).focus();
}
function closeForm() { $('#formCard').hidden = true; editing = null; }

function formData() {
  const f = $('#swForm');
  return {
    name: f.elements.name.value.trim(), host: f.elements.host.value.trim(), port: +f.elements.port.value || 22,
    user: f.elements.user.value.trim(), password: f.elements.password.value, clearPassword: f.elements.clearPassword.checked,
  };
}

function status(msg, kind = '') {
  $('#formStatus').textContent = msg;
  $('#formStatus').className = 'form-status ' + kind;
}

async function saveForm() {
  const d = formData();
  if (!d.name || !d.host || !d.user) { status('Заполните название, адрес и логин', 'err'); return null; }
  if (!editing && !d.password) { status('Укажите пароль', 'err'); return null; }
  const body = { name: d.name, host: d.host, port: d.port, user: d.user };
  if (d.password) body.password = d.password;
  if (d.clearPassword) body.clearPassword = true;
  status('Сохраняю…');
  try {
    const saved = editing ? await api('PUT', `api/switches/${encodeURIComponent(editing)}`, body) : await api('POST', 'api/switches', body);
    list = await api('GET', 'api/switches');
    renderList();
    return saved;
  } catch (e) {
    status(e.message, 'err');
    return null;
  }
}

async function fetchOne(id) {
  const s = list.find(x => x.id === id);
  toast(`Забираю конфигурацию с ${s ? s.name : id}…`);
  list = list.map(x => x.id === id ? { ...x, busy: true } : x);
  renderList();
  try {
    const r = await api('POST', `api/switches/${encodeURIComponent(id)}/fetch`, {});
    toast(r.ok ? `${s.name}: получено ${r.lines} строк${r.changed ? '' : ' (без изменений)'}` : `${s.name}: ${r.error}`, r.ok ? 'ok' : 'err');
  } catch (e) { toast(e.message, 'err'); }
  list = await api('GET', 'api/switches');
  renderList();
}

async function testConn(body, report) {
  report('Подключаюсь…', '');
  try {
    const r = await api('POST', 'api/test', body);
    report(r.ok ? `✓ Подключение успешно${r.prompt ? ': ' + r.prompt : ''}` : `✗ ${r.error}`, r.ok ? 'ok' : 'err');
  } catch (e) { report(`✗ ${e.message}`, 'err'); }
}

/* ---------- события ---------- */
$('#addBtn').addEventListener('click', () => openForm(null));
$('#cancelBtn').addEventListener('click', closeForm);
$('#pwToggle').addEventListener('click', () => {
  const p = $('#swForm').elements.password;
  p.type = p.type === 'password' ? 'text' : 'password';
});

$('#swForm').addEventListener('submit', async e => {
  e.preventDefault();
  const saved = await saveForm();
  if (saved) { closeForm(); toast(`Сохранено: ${saved.name}`, 'ok'); }
});

$('#saveFetch').addEventListener('click', async () => {
  const saved = await saveForm();
  if (!saved) return;
  closeForm();
  await fetchOne(saved.id);
});

$('#testBtn').addEventListener('click', () => {
  const d = formData();
  if (!d.host || !d.user) { status('Укажите адрес и логин', 'err'); return; }
  if (!d.password && !(editing && list.find(x => x.id === editing)?.hasPassword)) { status('Укажите пароль', 'err'); return; }
  const body = { host: d.host, port: d.port, user: d.user };
  if (d.password) body.password = d.password;
  if (editing) body.id = editing;
  testConn(body, status);
});

$('#swTable').addEventListener('click', async e => {
  const b = e.target.closest('button[data-act]');
  if (!b) return;
  const id = b.closest('tr').dataset.id;
  const s = list.find(x => x.id === id);
  if (b.dataset.act === 'edit') openForm(id);
  else if (b.dataset.act === 'fetch') fetchOne(id);
  else if (b.dataset.act === 'test') testConn({ id }, (msg, kind) => toast(`${s.name}: ${msg}`, kind));
  else if (b.dataset.act === 'delete') {
    if (b.dataset.confirm !== '1') {
      // Подтверждение прямо на кнопке: второй клик в течение 4 секунд удаляет
      b.dataset.confirm = '1';
      b.textContent = 'Точно удалить?';
      setTimeout(() => { if (b.isConnected) { b.dataset.confirm = ''; b.textContent = 'Удалить'; } }, 4000);
      return;
    }
    try {
      await api('DELETE', `api/switches/${encodeURIComponent(id)}`);
      toast(`Удалён: ${s.name}`, 'ok');
      if (editing === id) closeForm();
      list = await api('GET', 'api/switches');
      renderList();
    } catch (err) { toast(err.message, 'err'); }
  }
});

$('#fetchAll').addEventListener('click', async () => {
  const btn = $('#fetchAll');
  btn.disabled = true;
  toast('Забираю конфигурации со всех коммутаторов…');
  list = list.map(x => x.hasPassword ? { ...x, busy: true } : x);
  renderList();
  try {
    const r = await api('POST', 'api/fetch-all', {});
    const vals = Object.values(r);
    const ok = vals.filter(x => x.ok).length;
    toast(`Готово: ${ok} из ${vals.length} успешно`, ok === vals.length ? 'ok' : 'err');
  } catch (e) { toast(e.message, 'err'); }
  list = await api('GET', 'api/switches');
  renderList();
});

/* ---------- AD / DHCP / DNS ---------- */
function dirSummary(last) {
  if (!last) return 'данные ещё не загружались';
  const c = last.counts;
  const errs = Object.entries(last.errors || {});
  return `загружено ${ago(last.at)}: DHCP ${c.dhcp} (резерв. ${c.reserved}), AD ${c.ad} компьютеров, DNS ${c.dns} имён` +
    (errs.length ? ` · ошибки: ${errs.map(([k, v]) => `${k}: ${v}`).join('; ')}` : '');
}

function fillDir(s) {
  const f = $('#dirForm').elements;
  f.enabled.checked = s.enabled;
  f.dhcpServers.value = s.dhcpServers || '';
  f.dhcp.checked = s.dhcp; f.ad.checked = s.ad; f.dns.checked = s.dns;
  f.user.value = s.user || '';
  f.user.placeholder = s.currentUser ? `пусто — текущая: ${s.currentUser}` : 'DOMAIN\\user';
  f.password.value = '';
  f.password.placeholder = s.hasPassword ? '•••••••• (сохранён)' : '';
  $('#dirUserHint').textContent = 'Пусто — используется ваша учётная запись Windows. Нужны права на чтение DHCP (группа «DHCP Users»).';
  $('#dirPwHint').textContent = s.hasPassword ? 'Оставьте пустым, чтобы не менять' : 'Только если указана другая учётная запись';
  const last = s.last;
  $('#dirLast').textContent = dirSummary(last);
  $('#dirLast').className = 'form-status' + (last && Object.keys(last.errors || {}).length ? ' err' : '');
}

async function loadDir() {
  try { fillDir(await api('GET', 'api/directory/settings')); $('#dirCard').hidden = false; }
  catch (e) { /* сервер старой версии или недоступен */ }
}

async function saveDir() {
  const f = $('#dirForm').elements;
  const body = {
    enabled: f.enabled.checked, dhcp: f.dhcp.checked, ad: f.ad.checked, dns: f.dns.checked,
    dhcpServers: f.dhcpServers.value, user: f.user.value,
  };
  if (f.password.value) body.password = f.password.value;
  const s = await api('PUT', 'api/directory/settings', body);
  fillDir(s);
  return s;
}

function dirStatus(msg, kind = '') {
  $('#dirStatus').textContent = msg;
  $('#dirStatus').className = 'form-status ' + kind;
}

$('#dirForm').addEventListener('submit', async e => {
  e.preventDefault();
  try { await saveDir(); dirStatus('Сохранено', 'ok'); } catch (err) { dirStatus(err.message, 'err'); }
});

$('#dirRefresh').addEventListener('click', async () => {
  const btn = $('#dirRefresh');
  try {
    const s = await saveDir();
    if (!s.enabled) { dirStatus('Сначала включите «Использовать данные AD / DHCP / DNS»', 'err'); return; }
    btn.disabled = true;
    dirStatus('Загружаю данные из AD и DHCP…');
    const r = await api('POST', 'api/directory/refresh', {});
    if (!r.ok) dirStatus(r.error, 'err');
    else {
      const errs = Object.keys(r.errors || {}).length;
      dirStatus(`✓ DHCP: ${r.counts.dhcp}, AD: ${r.counts.ad}, DNS: ${r.counts.dns}${errs ? ` · есть ошибки (${errs})` : ''}`, errs ? 'err' : 'ok');
      loadDir();
    }
  } catch (err) { dirStatus(err.message, 'err'); }
  btn.disabled = false;
});

load();
loadDir();
})();
