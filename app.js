'use strict';
/*
 * Bóveda — gestor de contraseñas personal.
 * Todo se cifra en el celular con AES-256-GCM. La clave sale de tus DOS
 * contraseñas (PBKDF2-SHA256, 600.000 iteraciones). Las contraseñas maestras
 * no se guardan en ningún lado. Nada se envía a ningún servidor.
 */
(() => {
  const ITER = 600000;
  const IDLE_MS = 5 * 60 * 1000;   // bloqueo por inactividad
  const HIDDEN_MS = 30 * 1000;     // bloqueo al salir de la app
  const CLIP_MS = 30 * 1000;       // se borra el portapapeles
  const MIN_LEN = 8;
  const BACKUP_NAG_DAYS = 7;

  const app = document.getElementById('app');
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const S = { key: null, salt: null, iter: ITER, data: null, query: '' };

  // ---------- utilidades ----------
  function toB64(buf) {
    const u = new Uint8Array(buf); let s = '';
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function fromB64(s) {
    const bin = atob(s); const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return toB64(crypto.getRandomValues(new Uint8Array(16))).replace(/[^a-z0-9]/gi, '');
  }

  // Crea elementos sin innerHTML (evita inyección de código desde los datos).
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  // ---------- almacenamiento local ----------
  let dbp;
  function idb() {
    return dbp ||= new Promise((res, rej) => {
      const r = indexedDB.open('boveda', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  async function dbGet(k) {
    const db = await idb();
    return new Promise((res, rej) => {
      const q = db.transaction('kv', 'readonly').objectStore('kv').get(k);
      q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
    });
  }
  async function dbPut(k, v) {
    const db = await idb();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', 'readwrite');
      tx.objectStore('kv').put(v, k);
      tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
    });
  }

  // ---------- cifrado ----------
  async function deriveKey(p1, p2, salt, iter) {
    const material = enc.encode(p1.normalize('NFC') + '\u0000' + p2.normalize('NFC'));
    const base = await crypto.subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function encryptVault(key, salt, iter, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data)));
    return { app: 'boveda', v: 1, kdf: 'PBKDF2-SHA256', iter, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) };
  }
  // Si alguna contraseña es incorrecta, AES-GCM falla y esto tira error.
  async function decryptVault(rec, p1, p2) {
    const salt = fromB64(rec.salt);
    const key = await deriveKey(p1, p2, salt, rec.iter);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(rec.iv) }, key, fromB64(rec.ct));
    return { key, salt, iter: rec.iter, data: JSON.parse(dec.decode(pt)) };
  }
  function validRecord(r) {
    return r && typeof r === 'object' && r.app === 'boveda' && r.v === 1 &&
      Number.isInteger(r.iter) && r.iter >= 100000 && r.iter <= 10000000 &&
      ['salt', 'iv', 'ct'].every(k => typeof r[k] === 'string' && r[k].length > 0);
  }
  async function save() {
    S.data.updated = Date.now();
    await dbPut('vault', await encryptVault(S.key, S.salt, S.iter, S.data));
  }
  function genPassword(len = 20) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@_';
    const max = 256 - (256 % chars.length); const out = [];
    while (out.length < len) {
      for (const x of crypto.getRandomValues(new Uint8Array(len * 2))) {
        if (x < max && out.length < len) out.push(chars[x % chars.length]);
      }
    }
    return out.join('');
  }

  // ---------- sesión y bloqueo automático ----------
  let idleTimer, hideTimer, clipTimer, hiddenAt = null;
  function bump() {
    if (!S.key) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(lock, IDLE_MS);
  }
  function lock() {
    S.key = null; S.salt = null; S.data = null; S.query = '';
    clearTimeout(idleTimer); clearTimeout(hideTimer);
    viewUnlock();
  }
  ['pointerdown', 'keydown', 'scroll'].forEach(ev => addEventListener(ev, bump, { passive: true, capture: true }));
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      document.body.classList.add('veil');   // oculta el contenido en el selector de apps
      hiddenAt = Date.now();
      if (S.key) hideTimer = setTimeout(lock, HIDDEN_MS);
    } else {
      document.body.classList.remove('veil');
      clearTimeout(hideTimer);
      if (S.key && hiddenAt && Date.now() - hiddenAt >= HIDDEN_MS) lock();
      hiddenAt = null;
    }
  });

  // ---------- piezas de interfaz ----------
  function show(...nodes) { app.replaceChildren(...nodes); window.scrollTo(0, 0); }
  function topbar(title, left, right) {
    return h('header', { class: 'top' }, h('div', { class: 'slot' }, left || ''), h('h1', {}, title), h('div', { class: 'slot right' }, right || ''));
  }
  function back(fn) { return h('button', { class: 'small', onclick: fn }, '‹ Volver'); }
  function toast(msg) { const t = h('div', { class: 'toast' }, msg); document.body.append(t); setTimeout(() => t.remove(), 2200); }
  function errorBox() { return h('p', { class: 'error', role: 'alert' }); }
  async function busy(btn, label, fn) {
    const old = btn.textContent; btn.disabled = true; btn.textContent = label;
    try { return await fn(); } finally { btn.disabled = false; btn.textContent = old; }
  }
  const noAuto = { autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false' };
  function toggleBtn(input) {
    const b = h('button', { type: 'button', class: 'small', onclick: () => {
      input.type = input.type === 'password' ? 'text' : 'password';
      b.textContent = input.type === 'password' ? 'Ver' : 'Ocultar';
    } }, 'Ver');
    return b;
  }
  function pwField(id, label) {
    const input = h('input', { type: 'password', id, ...noAuto });
    return h('label', { class: 'field' }, h('span', {}, label), h('div', { class: 'row' }, input, toggleBtn(input)));
  }
  function avatar(title, big) {
    let n = 0; for (const ch of title) n = (n * 31 + ch.codePointAt(0)) >>> 0;
    const letter = ([...title.trim()][0] || '?').toUpperCase();
    return h('span', { class: `av c${n % 6}${big ? ' big' : ''}`, 'aria-hidden': 'true' }, letter);
  }
  function hero(sub) {
    return h('div', { class: 'hero' }, h('img', { src: 'icon-192.png', alt: '' }), h('h1', {}, 'Bóveda'), h('p', {}, sub));
  }
  const val = (form, id) => form.querySelector('#' + id).value;

  async function copy(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast(label + ' copiado');
      clearTimeout(clipTimer);
      clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIP_MS);
    } catch { toast('No se pudo copiar'); }
  }

  function checkNew(a, a2, b, b2) {
    if (a.length < MIN_LEN || b.length < MIN_LEN) return `Cada contraseña tiene que tener al menos ${MIN_LEN} caracteres.`;
    if (a !== a2) return 'La contraseña 1 no coincide con su confirmación.';
    if (b !== b2) return 'La contraseña 2 no coincide con su confirmación.';
    if (a === b) return 'Las dos contraseñas tienen que ser distintas.';
    return '';
  }

  // ---------- pantallas ----------
  async function home() {
    if (S.key) return viewList();
    (await dbGet('vault')) ? viewUnlock() : viewSetup();
  }

  function viewSetup() {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Crear bóveda');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const a = val(f, 'p1'), b = val(f, 'p2');
      const problem = checkNew(a, val(f, 'p1b'), b, val(f, 'p2b'));
      if (problem) { err.textContent = problem; return; }
      await busy(btn, 'Creando…', async () => {
        S.salt = crypto.getRandomValues(new Uint8Array(16)); S.iter = ITER;
        S.key = await deriveKey(a, b, S.salt, S.iter);
        S.data = { entries: [], created: Date.now() };
        await save();
        try { await navigator.storage?.persist?.(); } catch {}
      });
      bump(); viewList();
    } },
      h('p', { class: 'muted' }, 'Elegí dos contraseñas distintas. Vas a necesitar las dos cada vez que abras la bóveda.'),
      h('p', { class: 'note' }, 'Si olvidás cualquiera de las dos, no hay forma de recuperar los datos. Mejor frases largas que puedas recordar.'),
      pwField('p1', 'Contraseña 1'), pwField('p1b', 'Repetir contraseña 1'),
      pwField('p2', 'Contraseña 2'), pwField('p2b', 'Repetir contraseña 2'),
      err, btn,
      h('button', { type: 'button', class: 'link', onclick: pickBackup }, 'Ya tengo un respaldo')
    );
    show(hero('Creá tu bóveda'), f);
  }

  function viewUnlock() {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Abrir');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const rec = await dbGet('vault');
      try {
        await busy(btn, 'Abriendo…', async () => {
          const r = await decryptVault(rec, val(f, 'p1'), val(f, 'p2'));
          Object.assign(S, { key: r.key, salt: r.salt, iter: r.iter, data: r.data });
        });
      } catch {
        err.textContent = 'Alguna de las dos contraseñas es incorrecta.';
        f.querySelector('#p1').value = ''; f.querySelector('#p2').value = '';
        f.querySelector('#p1').focus();
        return;
      }
      bump(); viewList();
    } },
      pwField('p1', 'Contraseña 1'), pwField('p2', 'Contraseña 2'), err, btn,
      h('button', { type: 'button', class: 'link', onclick: pickBackup }, 'Restaurar desde un respaldo')
    );
    show(hero('Tus contraseñas, solo en este celular'), f);
  }

  function backupBanner() {
    const slot = h('div');
    dbGet('lastBackup').then(t => {
      if (!S.data || !S.data.entries.length) return;
      const never = !t;
      const stale = t && S.data.updated > t && (Date.now() - t) > BACKUP_NAG_DAYS * 864e5;
      if (never || stale) {
        slot.append(h('button', { class: 'banner', onclick: async () => { if (await exportBackup()) viewList(); } },
          never ? 'Todavía no hiciste un respaldo. Tocá para exportarlo.' : 'Tenés cambios sin respaldar. Tocá para exportar un respaldo.'));
      }
    });
    return slot;
  }

  function viewList() {
    const list = h('ul', { class: 'list' });
    const search = h('input', { type: 'search', placeholder: 'Buscar…', value: S.query, ...noAuto,
      oninput: () => { S.query = search.value; fill(); } });
    function fill() {
      const q = S.query.trim().toLowerCase();
      const items = S.data.entries
        .filter(x => !q || [x.title, x.username, x.url].some(s => (s || '').toLowerCase().includes(q)))
        .sort((a, b) => a.title.localeCompare(b.title, 'es', { sensitivity: 'base' }));
      list.replaceChildren(...(items.length
        ? items.map(x => h('li', {}, h('button', { class: 'item', onclick: () => viewDetail(x.id) }, avatar(x.title),
            h('span', { class: 'txt' }, h('span', { class: 't' }, x.title), h('span', { class: 's' }, x.username || x.url || '')),
            h('span', { class: 'chev' }, '›'))))
        : [h('li', { class: 'empty' }, S.data.entries.length ? 'Sin resultados.' : 'Todavía no guardaste nada. Tocá + para agregar.')]));
    }
    fill();
    show(
      topbar('Bóveda', h('button', { class: 'small', onclick: lock }, 'Bloquear'), h('button', { class: 'small', onclick: viewSettings }, 'Ajustes')),
      backupBanner(), h('div', { class: 'pad' }, search), list,
      h('button', { class: 'fab', onclick: () => viewEdit(null), 'aria-label': 'Agregar' }, '+')
    );
  }

  function viewDetail(id) {
    const x = S.data.entries.find(e => e.id === id);
    if (!x) return viewList();
    const MASK = '••••••••••';
    const row = (label, value, acts) => h('div', { class: 'drow' }, h('span', { class: 'lbl' }, label),
      h('div', { class: 'val' }, value), acts ? h('div', { class: 'acts' }, ...acts) : null);
    const rows = [];
    if (x.username) rows.push(row('Usuario', x.username, [h('button', { class: 'small', onclick: () => copy(x.username, 'Usuario') }, 'Copiar')]));
    if (x.password) {
      const pw = h('code', { class: 'pw' }, MASK); let shown = false;
      rows.push(row('Contraseña', pw, [
        h('button', { class: 'small', onclick: e => { shown = !shown; pw.textContent = shown ? x.password : MASK; e.currentTarget.textContent = shown ? 'Ocultar' : 'Ver'; } }, 'Ver'),
        h('button', { class: 'small', onclick: () => copy(x.password, 'Contraseña') }, 'Copiar'),
      ]));
    }
    if (x.url) {
      const acts = [h('button', { class: 'small', onclick: () => copy(x.url, 'Sitio') }, 'Copiar')];
      if (/^https?:\/\//i.test(x.url)) acts.push(h('a', { class: 'btn small', href: x.url, target: '_blank', rel: 'noopener noreferrer' }, 'Abrir'));
      rows.push(row('Sitio', x.url, acts));
    }
    if (x.notes) rows.push(h('div', { class: 'drow' }, h('span', { class: 'lbl' }, 'Notas'), h('p', { class: 'notes' }, x.notes)));
    show(
      topbar('', back(viewList), h('button', { class: 'small', onclick: () => viewEdit(x.id) }, 'Editar')),
      h('div', { class: 'card' }, h('div', { class: 'dhead' }, avatar(x.title, true), h('div', { class: 'dt' }, x.title)), ...rows, h('p', { class: 'note' }, 'Modificado: ' + new Date(x.updated).toLocaleString('es-AR')))
    );
  }

  function viewEdit(id) {
    const x = id ? S.data.entries.find(e => e.id === id) : null;
    const err = errorBox();
    const field = (name, label, value, extra = {}) => h('label', { class: 'field' }, h('span', {}, label),
      h('input', { name, type: 'text', value: value || '', ...noAuto, ...extra }));
    const pwInput = h('input', { name: 'password', type: 'password', value: x?.password || '', ...noAuto });
    const tog = toggleBtn(pwInput);
    const gen = h('button', { type: 'button', class: 'small', onclick: () => {
      pwInput.value = genPassword(); pwInput.type = 'text'; tog.textContent = 'Ocultar';
    } }, 'Generar');
    const notes = h('textarea', { name: 'notes', rows: '4' }); notes.value = x?.notes || '';

    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const fd = new FormData(f);
      const title = String(fd.get('title') || '').trim();
      if (!title) { err.textContent = 'Poné un nombre.'; return; }
      const now = Date.now();
      const rec = { id: x?.id || uuid(), title, username: String(fd.get('username')).trim(), password: String(fd.get('password')),
        url: String(fd.get('url')).trim(), notes: String(fd.get('notes')), created: x?.created || now, updated: now };
      const prev = S.data.entries;
      S.data.entries = x ? prev.map(e => e.id === x.id ? rec : e) : [...prev, rec];
      try { await save(); } catch (ex) { S.data.entries = prev; err.textContent = 'No se pudo guardar: ' + ex.message; return; }
      toast('Guardado'); viewDetail(rec.id);
    } },
      field('title', 'Nombre (ej: Banco, Gmail)', x?.title, { autocapitalize: 'sentences' }),
      field('username', 'Usuario o email', x?.username, { inputmode: 'email' }),
      h('label', { class: 'field' }, h('span', {}, 'Contraseña'), h('div', { class: 'row' }, pwInput, tog, gen)),
      field('url', 'Sitio web', x?.url, { inputmode: 'url' }),
      h('label', { class: 'field' }, h('span', {}, 'Notas'), notes),
      err,
      h('button', { type: 'submit', class: 'primary' }, 'Guardar'),
      x ? h('button', { type: 'button', class: 'danger', onclick: async () => {
        if (!confirm(`¿Borrar "${x.title}"? No se puede deshacer.`)) return;
        const prev = S.data.entries;
        S.data.entries = prev.filter(e => e.id !== x.id);
        try { await save(); } catch (ex) { S.data.entries = prev; err.textContent = 'No se pudo borrar: ' + ex.message; return; }
        toast('Borrado'); viewList();
      } }, 'Borrar') : null
    );
    show(topbar(x ? 'Editar' : 'Nueva', back(() => x ? viewDetail(x.id) : viewList())), f);
  }

  async function viewSettings() {
    const last = await dbGet('lastBackup');
    show(
      topbar('Ajustes', back(viewList)),
      h('div', { class: 'card' },
        h('h2', {}, 'Respaldo'),
        h('p', { class: 'muted' }, last ? 'Último respaldo: ' + new Date(last).toLocaleString('es-AR') : 'Nunca hiciste un respaldo.'),
        h('p', { class: 'note' }, 'El archivo queda cifrado con tus dos contraseñas. Podés guardarlo en Drive o mandártelo por mail: sin las contraseñas no sirve.'),
        h('button', { class: 'primary', onclick: async () => { if (await exportBackup()) viewSettings(); } }, 'Exportar respaldo'),
        h('button', { onclick: pickBackup }, 'Restaurar un respaldo')),
      h('div', { class: 'card' },
        h('h2', {}, 'Seguridad'),
        h('button', { onclick: viewChange }, 'Cambiar las contraseñas'),
        h('p', { class: 'note' }, `Se bloquea sola a los 5 minutos sin uso o a los 30 segundos de salir de la app. Entradas guardadas: ${S.data.entries.length}.`))
    );
  }

  function viewChange() {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Cambiar');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const a = val(f, 'n1'), b = val(f, 'n2');
      const problem = checkNew(a, val(f, 'n1b'), b, val(f, 'n2b'));
      if (problem) { err.textContent = problem; return; }
      try {
        await busy(btn, 'Cambiando…', async () => {
          await decryptVault(await dbGet('vault'), val(f, 'c1'), val(f, 'c2'));  // verifica las actuales
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const key = await deriveKey(a, b, salt, ITER);
          const old = { key: S.key, salt: S.salt, iter: S.iter };
          Object.assign(S, { key, salt, iter: ITER });
          try { await save(); } catch (ex) { Object.assign(S, old); throw ex; }
        });
      } catch (ex) {
        err.textContent = ex.name === 'OperationError' ? 'Las contraseñas actuales no son correctas.' : 'No se pudo cambiar: ' + ex.message;
        return;
      }
      toast('Contraseñas cambiadas'); viewSettings();
    } },
      pwField('c1', 'Contraseña 1 actual'), pwField('c2', 'Contraseña 2 actual'),
      pwField('n1', 'Nueva contraseña 1'), pwField('n1b', 'Repetir nueva contraseña 1'),
      pwField('n2', 'Nueva contraseña 2'), pwField('n2b', 'Repetir nueva contraseña 2'),
      h('p', { class: 'note' }, 'Los respaldos que ya exportaste siguen abriéndose con las contraseñas viejas. Exportá uno nuevo después de cambiarlas.'),
      err, btn
    );
    show(topbar('Cambiar contraseñas', back(viewSettings)), f);
  }

  async function exportBackup() {
    const rec = await dbGet('vault');
    const name = `boveda-respaldo-${new Date().toISOString().slice(0, 10)}.json`;
    const file = new File([JSON.stringify(rec)], name, { type: 'application/json' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      try { await navigator.share({ files: [file], title: 'Respaldo Bóveda' }); }
      catch (e) { if (e.name === 'AbortError') return false; return downloadFile(file); }
    } else {
      downloadFile(file);
    }
    await dbPut('lastBackup', Date.now());
    toast('Respaldo exportado');
    return true;
  }
  async function downloadFile(file) {
    const url = URL.createObjectURL(file);
    const a = h('a', { href: url, download: file.name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    await dbPut('lastBackup', Date.now());
    toast('Respaldo exportado');
    return true;
  }

  function pickBackup() {
    const inp = h('input', { type: 'file', accept: 'application/json,.json', hidden: true });
    inp.addEventListener('change', async () => {
      const file = inp.files[0]; inp.remove();
      if (!file) return;
      let rec;
      try { rec = JSON.parse(await file.text()); } catch { toast('Ese archivo no es un respaldo válido'); return; }
      if (!validRecord(rec)) { toast('Ese archivo no es un respaldo de Bóveda'); return; }
      viewRestore(rec, file.name);
    });
    document.body.append(inp); inp.click();
  }

  function viewRestore(rec, fileName) {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Restaurar');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      let r;
      try { r = await busy(btn, 'Verificando…', () => decryptVault(rec, val(f, 'p1'), val(f, 'p2'))); }
      catch { err.textContent = 'Esas contraseñas no abren este respaldo.'; return; }
      if (await dbGet('vault') && !confirm('Esto reemplaza la bóveda que tenés ahora en este celular por la del respaldo. ¿Seguir?')) return;
      await dbPut('vault', rec);
      await dbPut('lastBackup', Date.now());
      Object.assign(S, { key: r.key, salt: r.salt, iter: r.iter, data: r.data });
      try { await navigator.storage?.persist?.(); } catch {}
      bump(); toast('Respaldo restaurado'); viewList();
    } },
      h('p', { class: 'muted' }, 'Archivo: ' + fileName),
      h('p', { class: 'note' }, 'Ingresá las dos contraseñas que tenía la bóveda cuando hiciste este respaldo.'),
      pwField('p1', 'Contraseña 1'), pwField('p2', 'Contraseña 2'), err, btn
    );
    show(topbar('Restaurar', back(() => S.key ? viewSettings() : home())), f);
  }

  // ---------- arranque ----------
  if (!window.isSecureContext || !window.crypto?.subtle) {
    show(h('div', { class: 'card' }, h('p', {}, 'Esta app tiene que abrirse desde una dirección https.')));
    return;
  }
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  home();
})();
