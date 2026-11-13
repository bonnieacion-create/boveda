'use strict';
/*
 * Bóveda — gestor de contraseñas personal.
 *
 * Cifrado (versión 2):
 *  - Los datos se cifran con una clave aleatoria (AES-256-GCM).
 *  - Esa clave se guarda "envuelta" dos veces:
 *      1) con una clave que sale de tus DOS contraseñas, y
 *      2) con una clave que sale de tu CÓDIGO DE RECUPERACIÓN.
 *    Cualquiera de las dos abre la bóveda. Ninguna se guarda en ningún lado.
 *  - Derivación: PBKDF2-SHA256, 600.000 iteraciones.
 *  - Nada se envía a ningún servidor.
 */
(() => {
  const ITER = 600000;
  const IDLE_MS = 5 * 60 * 1000;   // bloqueo por inactividad
  const HIDDEN_MS = 30 * 1000;     // bloqueo al salir de la app
  const CLIP_MS = 30 * 1000;       // se borra el portapapeles
  const MIN_LEN = 8;
  const GATE_CHANGES = 5;          // cambios sin respaldar que bloquean agregar
  const GATE_FIRST = 3;            // entradas sin ningún respaldo que bloquean agregar
  const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  const app = document.getElementById('app');
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const S = { dk: null, key: null, rec: null, data: null, query: '', hold: false };

  // ---------- utilidades ----------
  const rand = n => crypto.getRandomValues(new Uint8Array(n));
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
    return toB64(rand(16)).replace(/[^a-z0-9]/gi, '');
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
  const pwSecret = (p1, p2) => p1.normalize('NFC') + '\u0000' + p2.normalize('NFC');

  function newRecoveryCode() {
    let val = 0, bits = 0, out = '';
    for (const x of rand(20)) {             // 160 bits → 32 caracteres
      val = (val << 8) | x; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
      val &= (1 << bits) - 1;
    }
    return out.match(/.{4}/g).join('-');
  }
  const normCode = s => s.toUpperCase().replace(/[IL]/g, '1').replace(/O/g, '0').replace(/[^0-9A-Z]/g, '');
  const codeLooksValid = s => s.length === 32 && [...s].every(c => B32.includes(c));

  async function kek(secret, salt, iter) {
    const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function seal(key, bytes) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { iv: toB64(iv), ct: toB64(ct) };
  }
  // Si la clave es incorrecta, AES-GCM falla y esto tira error.
  async function open(key, box) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv) }, key, fromB64(box.ct)));
  }
  async function makeSlot(secret, dk) {
    const salt = rand(16);
    return { salt: toB64(salt), iter: ITER, ...(await seal(await kek(secret, salt, ITER), dk)) };
  }
  async function openSlot(secret, slot) {
    return open(await kek(secret, fromB64(slot.salt), slot.iter), slot);
  }
  const dataKey = dk => crypto.subtle.importKey('raw', dk, 'AES-GCM', false, ['encrypt', 'decrypt']);

  async function loadData(rec, dk) {
    const key = await dataKey(dk);
    const data = JSON.parse(dec.decode(await open(key, rec.data)));
    return { dk, key, data, rec };
  }
  // Abre con las dos contraseñas. Las bóvedas de la versión 1 devuelven { legacy: datos }.
  async function openWithPasswords(rec, p1, p2) {
    if (rec.v === 1) {
      const k = await kek(pwSecret(p1, p2), fromB64(rec.salt), rec.iter);
      return { legacy: JSON.parse(dec.decode(await open(k, rec))) };
    }
    return loadData(rec, await openSlot(pwSecret(p1, p2), rec.pw));
  }

  const isStr = x => typeof x === 'string' && x.length > 0;
  const okIter = n => Number.isInteger(n) && n >= 100000 && n <= 10000000;
  const okBox = b => !!b && isStr(b.iv) && isStr(b.ct);
  const okSlot = s => okBox(s) && isStr(s.salt) && okIter(s.iter);
  function validRecord(r) {
    if (!r || typeof r !== 'object' || r.app !== 'boveda') return false;
    if (r.v === 1) return okIter(r.iter) && isStr(r.salt) && okBox(r);
    if (r.v === 2) return okSlot(r.pw) && okSlot(r.rc) && okBox(r.data);
    return false;
  }

  function setSession(o) {
    Object.assign(S, { dk: o.dk, key: o.key, rec: o.rec, data: o.data });
    bump();
  }
  async function save() {
    S.data.updated = Date.now();
    const rec = { ...S.rec, data: await seal(S.key, enc.encode(JSON.stringify(S.data))) };
    await dbPut('vault', rec);
    S.rec = rec;
  }
  // Crea una bóveda nueva (o migra una vieja) y devuelve el código de recuperación.
  async function createVault(p1, p2, data) {
    const dk = rand(32);
    const code = newRecoveryCode();
    const rec = { app: 'boveda', v: 2, pw: await makeSlot(pwSecret(p1, p2), dk), rc: await makeSlot(normCode(code), dk) };
    setSession({ dk, key: await dataKey(dk), rec, data });
    await save();
    return code;
  }
  async function markChanged() { await dbPut('changes', ((await dbGet('changes')) || 0) + 1); }

  function genPassword(len = 20) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@_';
    const max = 256 - (256 % chars.length); const out = [];
    while (out.length < len) {
      for (const x of rand(len * 2)) if (x < max && out.length < len) out.push(chars[x % chars.length]);
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
    if (S.hold) return;   // no bloquear mientras se anota el código de recuperación
    if (S.dk) S.dk.fill(0);
    Object.assign(S, { dk: null, key: null, rec: null, data: null, query: '' });
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
    return h('div', { class: 'hero' }, h('img', { src: 'icon-192.png', alt: '' }), h('h1', {}, 'Bóveda'), sub ? h('p', {}, sub) : null);
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
  const newPwFields = (pre = 'n', label = 'Nueva contraseña') => [
    pwField(pre + '1', label + ' 1'), pwField(pre + '1b', 'Repetir ' + label.toLowerCase() + ' 1'),
    pwField(pre + '2', label + ' 2'), pwField(pre + '2b', 'Repetir ' + label.toLowerCase() + ' 2'),
  ];
  const readNew = (f, pre = 'n') => {
    const a = val(f, pre + '1'), b = val(f, pre + '2');
    return { a, b, problem: checkNew(a, val(f, pre + '1b'), b, val(f, pre + '2b')) };
  };
  const confirmReplace = async () => !(await dbGet('vault')) ||
    confirm('Esto reemplaza la bóveda que tenés ahora en este celular por la del respaldo. ¿Seguir?');

  // ---------- pantallas ----------
  async function home() {
    if (S.key) return viewList();
    (await dbGet('vault')) ? viewUnlock() : viewWelcome(0);
  }

  // Bienvenida (3 pasos)
  const SLIDES = [
    ['Tus contraseñas, solo acá', 'Todo se guarda cifrado en este celular. No se manda nada a internet: ni siquiera quien hizo la app puede ver tus datos.'],
    ['Dos contraseñas y un código', 'Para abrir la bóveda usás dos contraseñas. Además vas a recibir un código de recuperación para anotar en papel, por si alguna vez olvidás una.'],
    ['Hacé respaldos', 'Si perdés el celular o se borran los datos del navegador, el respaldo es la única forma de recuperar todo. La app te lo va a pedir seguido.'],
  ];
  function viewWelcome(i, done) {
    const [title, text] = SLIDES[i];
    const last = i === SLIDES.length - 1;
    show(
      hero(),
      h('div', { class: 'card welcome' },
        h('div', { class: 'dots' }, SLIDES.map((_, j) => h('span', { class: j === i ? 'on' : '' }))),
        h('span', { class: 'step' }, `${i + 1} de ${SLIDES.length}`),
        h('h2', { class: 'wt' }, title),
        h('p', { class: 'muted' }, text),
        h('button', { class: 'primary', onclick: () => last ? (done ? done() : viewSetup()) : viewWelcome(i + 1, done) },
          last ? (done ? 'Listo' : 'Empezar') : 'Siguiente'),
        i > 0 ? h('button', { class: 'link', onclick: () => viewWelcome(i - 1, done) }, 'Atrás')
          : (!done ? h('button', { class: 'link', onclick: pickBackup }, 'Ya tengo un respaldo') : null)
      )
    );
  }

  function viewSetup() {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Crear bóveda');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const { a, b, problem } = readNew(f, 'p');
      if (problem) { err.textContent = problem; return; }
      let code;
      await busy(btn, 'Creando…', async () => {
        code = await createVault(a, b, { entries: [], created: Date.now() });
        await dbPut('changes', 0);
        try { await navigator.storage?.persist?.(); } catch {}
      });
      showNewCode(code, viewList);
    } },
      h('p', { class: 'muted' }, 'Elegí dos contraseñas distintas. Vas a necesitar las dos cada vez que abras la bóveda.'),
      h('p', { class: 'note' }, 'Mejor frases largas que puedas recordar, que no uses en ningún otro lado.'),
      ...newPwFields('p', 'Contraseña'),
      err, btn,
      h('button', { type: 'button', class: 'link', onclick: () => viewWelcome(0) }, '‹ Volver a la introducción')
    );
    show(hero('Creá tu bóveda'), f);
  }

  // Código de recuperación: se muestra una sola vez y hay que confirmarlo.
  async function showNewCode(code, next) {
    await dbPut('rcPending', true);
    viewCode(code, next);
  }
  function viewCode(code, next) {
    S.hold = true;
    const groups = code.split('-');
    const tail = groups[groups.length - 1];
    const btn = h('button', { class: 'primary', disabled: true, onclick: async () => {
      S.hold = false; bump();
      await dbPut('rcPending', false);
      toast('Código guardado');
      next();
    } }, 'Ya lo anoté');
    const check = h('input', { type: 'text', placeholder: 'Últimos 4 caracteres', maxlength: '4', ...noAuto,
      oninput: () => { btn.disabled = normCode(check.value) !== tail; } });
    show(
      topbar('Tu código'),
      h('div', { class: 'card' },
        h('p', { class: 'muted' }, 'Si olvidás alguna de tus dos contraseñas, con este código recuperás la bóveda.'),
        h('div', { class: 'code' }, h('span', {}, groups.slice(0, 4).join('-')), h('span', {}, groups.slice(4).join('-'))),
        h('ul', { class: 'tips' },
          h('li', {}, 'Anotalo en papel y guardalo en un lugar seguro.'),
          h('li', {}, 'No lo guardes en este mismo celular ni le saques foto.'),
          h('li', {}, 'Se muestra una sola vez.')),
        h('label', { class: 'field' }, h('span', {}, 'Para confirmar, escribí los últimos 4 caracteres'), check),
        btn
      )
    );
  }

  function viewUnlock() {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Abrir');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const rec = await dbGet('vault');
      const p1 = val(f, 'p1'), p2 = val(f, 'p2');
      let r;
      try { r = await busy(btn, 'Abriendo…', () => openWithPasswords(rec, p1, p2)); }
      catch {
        err.textContent = 'Alguna de las dos contraseñas es incorrecta.';
        f.querySelector('#p1').value = ''; f.querySelector('#p2').value = '';
        f.querySelector('#p1').focus();
        return;
      }
      if (r.legacy) {   // bóveda de la versión anterior: se pasa a la nueva con código de recuperación
        const code = await createVault(p1, p2, r.legacy);
        await markChanged();
        return showNewCode(code, viewList);
      }
      setSession(r);
      if (await dbGet('rcPending')) {   // el código anterior no llegó a confirmarse: se genera otro
        const code = newRecoveryCode();
        S.rec = { ...S.rec, rc: await makeSlot(normCode(code), S.dk) };
        await save();
        return showNewCode(code, viewList);
      }
      viewList();
    } },
      pwField('p1', 'Contraseña 1'), pwField('p2', 'Contraseña 2'), err, btn,
      h('button', { type: 'button', class: 'link', onclick: async () => {
        const rec = await dbGet('vault');
        if (rec.v !== 2) { toast('Esta bóveda todavía no tiene código de recuperación'); return; }
        viewRecover(rec, {});
      } }, 'Olvidé una contraseña'),
      h('button', { type: 'button', class: 'link', onclick: pickBackup }, 'Restaurar desde un respaldo')
    );
    show(hero('Tus contraseñas, solo en este celular'), f);
  }

  // Recuperar con el código: abre la bóveda y obliga a elegir dos contraseñas nuevas.
  function viewRecover(rec, { fromBackup }) {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Continuar');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const code = normCode(val(f, 'rc'));
      if (!codeLooksValid(code)) { err.textContent = 'El código tiene 32 caracteres (letras y números).'; return; }
      let r;
      try { r = await busy(btn, 'Verificando…', async () => loadData(rec, await openSlot(code, rec.rc))); }
      catch { err.textContent = 'Ese código no abre esta bóveda.'; return; }
      viewRecoverNew(r, fromBackup);
    } },
      h('p', { class: 'muted' }, 'Ingresá el código de recuperación que anotaste cuando creaste la bóveda.'),
      h('label', { class: 'field' }, h('span', {}, 'Código de recuperación'),
        h('input', { id: 'rc', type: 'text', placeholder: 'XXXX-XXXX-XXXX-…', class: 'mono', ...noAuto })),
      err, btn
    );
    show(topbar('Recuperar', back(home)), f);
  }
  function viewRecoverNew(r, fromBackup) {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Guardar y abrir');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const { a, b, problem } = readNew(f);
      if (problem) { err.textContent = problem; return; }
      if (fromBackup && !(await confirmReplace())) return;
      await busy(btn, 'Guardando…', async () => {
        setSession(r);
        S.rec = { ...S.rec, pw: await makeSlot(pwSecret(a, b), S.dk) };
        await save();
        await markChanged();
      });
      toast('Listo, ya tenés contraseñas nuevas'); viewList();
    } },
      h('p', { class: 'muted' }, 'El código es correcto. Elegí tus dos contraseñas nuevas.'),
      h('p', { class: 'note' }, 'Tu código de recuperación sigue siendo el mismo.'),
      ...newPwFields(), err, btn
    );
    show(topbar('Contraseñas nuevas'), f);
  }

  async function needsBackup() {
    const [last, ch] = await Promise.all([dbGet('lastBackup'), dbGet('changes')]);
    return (ch || 0) >= GATE_CHANGES || (!last && S.data.entries.length >= GATE_FIRST);
  }
  async function addEntry() { (await needsBackup()) ? viewGate() : viewEdit(null); }

  async function viewGate() {
    const [last, ch] = await Promise.all([dbGet('lastBackup'), dbGet('changes')]);
    show(
      topbar('Respaldo', back(viewList)),
      h('div', { class: 'card gate' },
        h('div', { class: 'gate-ico' }, '!'),
        h('h2', { class: 'wt' }, 'Antes de seguir, hacé un respaldo'),
        h('p', { class: 'muted' }, last
          ? `Tenés ${ch} cambios que solo existen en este celular. Si lo perdés hoy, se pierden.`
          : 'Todavía no hiciste ningún respaldo. Si perdés el celular hoy, perdés todo lo que cargaste.'),
        h('p', { class: 'note' }, 'El archivo queda cifrado. Guardalo en Drive o mandátelo por mail.'),
        h('button', { class: 'primary', onclick: async () => { if (await exportBackup()) viewEdit(null); } }, 'Exportar respaldo ahora')
      )
    );
  }

  function backupBanner() {
    const slot = h('div');
    Promise.all([dbGet('lastBackup'), dbGet('changes')]).then(([last, ch]) => {
      if (!S.data || !S.data.entries.length) return;
      let msg = '';
      if (!last) msg = 'Todavía no hiciste un respaldo. Tocá para exportarlo.';
      else if (ch > 0) msg = `${ch} ${ch === 1 ? 'cambio' : 'cambios'} sin respaldar. Tocá para exportar.`;
      if (msg) slot.append(h('button', { class: 'banner', onclick: async () => { if (await exportBackup()) viewList(); } }, msg));
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
      h('button', { class: 'fab', onclick: addEntry, 'aria-label': 'Agregar' }, '+')
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
      h('div', { class: 'card' }, h('div', { class: 'dhead' }, avatar(x.title, true), h('div', { class: 'dt' }, x.title)), ...rows,
        h('p', { class: 'note' }, 'Modificado: ' + new Date(x.updated).toLocaleString('es-AR')))
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
      try { await save(); await markChanged(); } catch (ex) { S.data.entries = prev; err.textContent = 'No se pudo guardar: ' + ex.message; return; }
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
        try { await save(); await markChanged(); } catch (ex) { S.data.entries = prev; err.textContent = 'No se pudo borrar: ' + ex.message; return; }
        toast('Borrado'); viewList();
      } }, 'Borrar') : null
    );
    show(topbar(x ? 'Editar' : 'Nueva', back(() => x ? viewDetail(x.id) : viewList())), f);
  }

  async function viewSettings() {
    const [last, ch] = await Promise.all([dbGet('lastBackup'), dbGet('changes')]);
    show(
      topbar('Ajustes', back(viewList)),
      h('div', { class: 'card' },
        h('h2', {}, 'Respaldo'),
        h('p', { class: 'muted' }, last
          ? 'Último respaldo: ' + new Date(last).toLocaleString('es-AR') + (ch ? ` · ${ch} ${ch === 1 ? 'cambio' : 'cambios'} después` : ' · al día')
          : 'Nunca hiciste un respaldo.'),
        h('p', { class: 'note' }, 'El archivo queda cifrado: se abre con tus dos contraseñas o con tu código de recuperación. Podés guardarlo en Drive o mandártelo por mail.'),
        h('button', { class: 'primary', onclick: async () => { if (await exportBackup()) viewSettings(); } }, 'Exportar respaldo'),
        h('button', { onclick: pickBackup }, 'Restaurar un respaldo')),
      h('div', { class: 'card' },
        h('h2', {}, 'Seguridad'),
        h('button', { onclick: viewChange }, 'Cambiar las contraseñas'),
        h('button', { onclick: async () => {
          if (!confirm('Se va a generar un código nuevo y el anterior deja de servir para esta bóveda. ¿Seguir?')) return;
          const code = newRecoveryCode();
          S.rec = { ...S.rec, rc: await makeSlot(normCode(code), S.dk) };
          await save(); await markChanged();
          showNewCode(code, viewSettings);
        } }, 'Nuevo código de recuperación'),
        h('p', { class: 'note' }, `Se bloquea sola a los 5 minutos sin uso o a los 30 segundos de salir de la app. Entradas guardadas: ${S.data.entries.length}.`)),
      h('div', { class: 'card' },
        h('h2', {}, 'Ayuda'),
        h('button', { onclick: () => viewWelcome(0, viewSettings) }, 'Cómo funciona'))
    );
  }

  function viewChange() {
    const err = errorBox();
    const btn = h('button', { type: 'submit', class: 'primary' }, 'Cambiar');
    const f = h('form', { class: 'card', onsubmit: async e => {
      e.preventDefault(); err.textContent = '';
      const { a, b, problem } = readNew(f);
      if (problem) { err.textContent = problem; return; }
      try {
        await busy(btn, 'Cambiando…', async () => {
          await openSlot(pwSecret(val(f, 'c1'), val(f, 'c2')), S.rec.pw);   // verifica las actuales
          const old = S.rec;
          S.rec = { ...S.rec, pw: await makeSlot(pwSecret(a, b), S.dk) };
          try { await save(); } catch (ex) { S.rec = old; throw ex; }
          await markChanged();
        });
      } catch (ex) {
        err.textContent = ex.name === 'OperationError' ? 'Las contraseñas actuales no son correctas.' : 'No se pudo cambiar: ' + ex.message;
        return;
      }
      toast('Contraseñas cambiadas'); viewSettings();
    } },
      pwField('c1', 'Contraseña 1 actual'), pwField('c2', 'Contraseña 2 actual'),
      ...newPwFields(),
      h('p', { class: 'note' }, 'Los respaldos que ya exportaste siguen abriéndose con las contraseñas viejas. Exportá uno nuevo después de cambiarlas.'),
      err, btn
    );
    show(topbar('Cambiar contraseñas', back(viewSettings)), f);
  }

  async function backupDone() {
    await dbPut('lastBackup', Date.now());
    await dbPut('changes', 0);
    toast('Respaldo exportado');
    return true;
  }
  async function exportBackup() {
    const rec = await dbGet('vault');
    const name = `boveda-respaldo-${new Date().toISOString().slice(0, 10)}.json`;
    const file = new File([JSON.stringify(rec)], name, { type: 'application/json' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      try { await navigator.share({ files: [file], title: 'Respaldo Bóveda' }); }
      catch (e) { if (e.name === 'AbortError') return false; downloadFile(file); }
    } else {
      downloadFile(file);
    }
    return backupDone();
  }
  function downloadFile(file) {
    const url = URL.createObjectURL(file);
    const a = h('a', { href: url, download: file.name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
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
      const p1 = val(f, 'p1'), p2 = val(f, 'p2');
      let r;
      try { r = await busy(btn, 'Verificando…', () => openWithPasswords(rec, p1, p2)); }
      catch { err.textContent = 'Esas contraseñas no abren este respaldo.'; return; }
      if (!(await confirmReplace())) return;
      try { await navigator.storage?.persist?.(); } catch {}
      if (r.legacy) {
        const code = await createVault(p1, p2, r.legacy);
        await markChanged();
        toast('Respaldo restaurado');
        return showNewCode(code, viewList);
      }
      await dbPut('vault', rec);
      await dbPut('lastBackup', Date.now());
      await dbPut('changes', 0);
      setSession(r);
      toast('Respaldo restaurado'); viewList();
    } },
      h('p', { class: 'muted' }, 'Archivo: ' + fileName),
      h('p', { class: 'note' }, 'Ingresá las dos contraseñas que tenía la bóveda cuando hiciste este respaldo.'),
      pwField('p1', 'Contraseña 1'), pwField('p2', 'Contraseña 2'), err, btn,
      rec.v === 2 ? h('button', { type: 'button', class: 'link', onclick: () => viewRecover(rec, { fromBackup: true }) }, 'Olvidé una contraseña: usar el código') : null
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
