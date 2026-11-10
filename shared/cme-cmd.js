// Команды Cisco CME для изменения телефонов. Только формируются для копирования —
// на роутер приложение ничего не отправляет. Работает в браузере (window.CmeCmd) и в Node.
(function (root) {
  'use strict';

  const MODELS = ['7911', '7942', '7945', '7960', '7962', '7965', '7975', '8941', '8945', '6921', '6941', '6961', '7937'];

  // 0019-aa7b-1234 → 0019.AA7B.1234 (формат Cisco)
  function ciscoMac(mac) {
    const h = String(mac || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
    return h.length === 12 ? `${h.slice(0, 4)}.${h.slice(4, 8)}.${h.slice(8)}` : null;
  }
  const hex12 = mac => String(mac || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  const nextFree = used => { const s = new Set(used || []); let i = 1; while (s.has(i)) i++; return i; };
  const clean = v => String(v == null ? '' : v).trim().replace(/\s+/g, ' ');

  function wrap(lines) { return ['configure terminal', ...lines, 'end'].join('\n'); }

  // Проверка полей формы. Возвращает { errors: [], warnings: [] }
  function validate(f, used, phone) {
    const errors = [], warnings = [];
    if (f.number !== undefined) {
      if (!/^\d{2,15}$/.test(f.number)) errors.push('Номер — только цифры (от 2 до 15)');
      else if ((used.numbers || []).includes(f.number) && !(phone && phone.numbers.includes(f.number))) errors.push(`Номер ${f.number} уже занят`);
    }
    if (f.mac !== undefined && f.mac !== '' && !ciscoMac(f.mac)) errors.push('MAC-адрес должен состоять из 12 шестнадцатеричных цифр');
    for (const k of ['name', 'label', 'description']) {
      if (f[k] && /[^\x20-\x7e]/.test(f[k])) { warnings.push('Старые телефоны Cisco не показывают кириллицу — лучше писать латиницей'); break; }
    }
    if (f.model && !/^[\w-]{3,12}$/.test(f.model)) errors.push('Модель — например 7965');
    return { errors, warnings: [...new Set(warnings)] };
  }

  // Изменение существующего телефона: только то, что отличается
  function edit(phone, f) {
    const sip = phone.proto === 'sip';
    const dn = phone.dns[0] || null;
    const dnLines = [], phLines = [];
    if (dn) {
      if (f.number !== undefined && f.number !== (dn.numbers[0] || '')) dnLines.push(`number ${f.number}`);
      if (f.name !== undefined && f.name !== dn.name) dnLines.push(f.name ? `name ${f.name}` : 'no name');
      if (f.label !== undefined && f.label !== dn.label) dnLines.push(f.label ? `label ${f.label}` : 'no label');
    }
    if (f.description !== undefined && f.description !== (phone.description || '')) phLines.push(f.description ? `description ${f.description}` : 'no description');
    if (f.model !== undefined && f.model && f.model !== phone.model) phLines.push(`type ${f.model}`);
    if (f.mac !== undefined && f.mac && hex12(f.mac) !== hex12(phone.mac)) phLines.push(sip ? `id mac ${ciscoMac(f.mac)}` : `mac-address ${ciscoMac(f.mac)}`);
    if (!dnLines.length && !phLines.length) return '';
    const lines = [];
    if (dnLines.length) lines.push(sip ? `voice register dn ${dn.id}` : `ephone-dn ${dn.id}`, ...dnLines.map(l => ' ' + l), ' exit');
    if (sip) {
      if (phLines.length) lines.push(`voice register pool ${phone.ref}`, ...phLines.map(l => ' ' + l), ' exit');
      lines.push('voice register global', ' create profile', ' exit');
    } else {
      // Телефон перечитывает настройки после перезапуска
      lines.push(`ephone ${phone.ref}`, ...phLines.map(l => ' ' + l), ' restart', ' exit');
    }
    return wrap(lines);
  }

  function restart(phone) {
    return phone.proto === 'sip'
      ? wrap([`voice register pool ${phone.ref}`, ' restart', ' exit'])
      : wrap([`ephone ${phone.ref}`, ' restart', ' exit']);
  }

  // Удаление телефона; withDns — удалить и его номера, если они больше ни на чём не используются
  function remove(phone, withDns, otherPhones) {
    const sip = phone.proto === 'sip';
    const lines = [sip ? `no voice register pool ${phone.ref}` : `no ephone ${phone.ref}`];
    if (withDns) {
      const usedElsewhere = new Set((otherPhones || []).filter(p => p !== phone && p.proto === phone.proto).flatMap(p => p.dns.map(d => d.id)));
      for (const d of phone.dns) if (!usedElsewhere.has(d.id)) lines.push(sip ? `no voice register dn ${d.id}` : `no ephone-dn ${d.id}`);
    }
    if (sip) lines.push('voice register global', ' create profile', ' exit');
    return wrap(lines);
  }

  // Новый SCCP-телефон. f.dnId — существующий свободный номер (ephone-dn) или пусто для нового
  function create(f, used) {
    const ephoneId = f.ephoneId || nextFree(used.ephone);
    const lines = [];
    let dnId = f.dnId ? +f.dnId : null;
    if (!dnId) {
      dnId = f.newDnId || nextFree(used.ephoneDn);
      lines.push(`ephone-dn ${dnId} dual-line`, ` number ${f.number}`);
      if (f.name) lines.push(` name ${f.name}`);
      if (f.label) lines.push(` label ${f.label}`);
      lines.push(' exit');
    }
    lines.push(`ephone ${ephoneId}`);
    if (f.description) lines.push(` description ${f.description}`);
    lines.push(` mac-address ${ciscoMac(f.mac)}`);
    if (f.model) lines.push(` type ${f.model}`);
    lines.push(` button 1:${dnId}`, ' restart', ' exit');
    return { ephoneId, dnId, commands: wrap(lines) };
  }

  const api = { MODELS, ciscoMac, nextFree, clean, validate, edit, restart, remove, create };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.CmeCmd = api;
})(typeof window !== 'undefined' ? window : globalThis);
