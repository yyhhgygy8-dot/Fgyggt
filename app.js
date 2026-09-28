'use strict';
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const view = $('#view');
  let page = 'dashboard';
  let timer = null;
  let dash = null;
  let modalOpen = false;

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const GB = 1024 * 1024 * 1024;
  function fmtBytes(n) {
    n = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n.toFixed(0) : n.toFixed(2)) + ' ' + u[i];
  }
  function fmtDate(ts) { return ts ? new Date(ts).toLocaleDateString('fa-IR') : 'نامحدود'; }
  function fmtDateTime(ts) { return ts ? new Date(ts).toLocaleString('fa-IR') : '—'; }
  function fmtUptime(s) {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? d + ' روز ' : '') + (h ? h + ' ساعت ' : '') + m + ' دقیقه';
  }
  function ago(ts) {
    if (!ts) return 'هرگز';
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60) return 'چند ثانیه پیش';
    if (s < 3600) return Math.floor(s / 60) + ' دقیقه پیش';
    if (s < 86400) return Math.floor(s / 3600) + ' ساعت پیش';
    return Math.floor(s / 86400) + ' روز پیش';
  }

  function toast(msg, kind) {
    const el = document.createElement('div');
    el.className = kind || '';
    el.textContent = msg;
    $('#toast').appendChild(el);
    setTimeout(() => el.remove(), 3500);
  }

  async function api(method, url, body) {
    const opt = { method, credentials: 'same-origin', headers: { 'X-Requested-With': 'panel' } };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let r;
    try { r = await fetch(url, opt); } catch (e) { throw new Error('ارتباط با سرور برقرار نشد.'); }
    const ct = r.headers.get('content-type') || '';
    const data = ct.includes('json') ? await r.json() : await r.text();
    if (r.status === 401 && url !== '/api/login') { showLogin(); throw new Error('لطفاً دوباره وارد شوید.'); }
    if (!r.ok) throw new Error((data && data.error) || 'خطا در انجام عملیات');
    return data;
  }
  async function act(fn, okMsg) {
    try { const r = await fn(); if (okMsg) toast(okMsg, 'ok'); return r; } catch (e) { toast(e.message, 'bad'); return null; }
  }

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(() => toast('کپی شد', 'ok'));
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast('کپی شد', 'ok'); } catch (e) { toast('کپی ممکن نشد', 'bad'); }
    ta.remove();
  }

  function modal(html) {
    modalOpen = true;
    const bg = document.createElement('div');
    bg.className = 'modal-bg';
    bg.innerHTML = '<div class="modal">' + html + '</div>';
    const close = () => { bg.remove(); modalOpen = false; };
    bg.addEventListener('mousedown', (e) => { if (e.target === bg) close(); });
    document.body.appendChild(bg);
    bg.close = close;
    bg.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
    return bg;
  }

  /* ---------------------------------------------------------- login */
  function showLogin() {
    stopTimer();
    $('#app').classList.add('hidden');
    $('#login').classList.remove('hidden');
  }
  function showApp() {
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    go(page);
  }
  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('#loginErr').textContent = '';
    try {
      await api('POST', '/api/login', { username: $('#lu').value.trim(), password: $('#lp').value });
      $('#lp').value = '';
      showApp();
    } catch (err) { $('#loginErr').textContent = err.message; }
  });
  $('#logoutBtn').addEventListener('click', async () => { try { await api('POST', '/api/logout', {}); } catch (e) { /* */ } showLogin(); });
  $('#nav').addEventListener('click', (e) => { const b = e.target.closest('button[data-p]'); if (b) go(b.dataset.p); });

  function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }
  function go(p) {
    page = p;
    document.querySelectorAll('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.p === p));
    stopTimer();
    const pages = { dashboard: pDashboard, clients: pClients, settings: pSettings, backup: pBackup, logs: pLogs, account: pAccount };
    const fn = pages[p];
    fn();
    if (p === 'dashboard' || p === 'clients') timer = setInterval(() => { if (!modalOpen) fn(true); }, 10000);
  }

  /* ------------------------------------------------------ dashboard */
  async function pDashboard() {
    try {
      const d = dash = await api('GET', '/api/dashboard');
      let alerts = '';
      if (!d.hasWg) alerts += '<div class="alert">حالت آزمایشی (Dry-Run): ابزار wg نصب نیست یا پنل با دسترسی root اجرا نشده؛ تغییری روی سیستم اعمال نمی‌شود. برای اجرای واقعی از install.sh استفاده کنید.</div>';
      if (d.hasWg && !d.wgUp) alerts += '<div class="alert bad">اینترفیس وایرگارد بالا نیست. ' + esc(d.lastError || '') + ' از بخش تنظیمات «ری‌استارت وایرگارد» را بزنید.</div>';
      if (!d.endpoint) alerts += '<div class="alert">آدرس سرور (Endpoint) هنوز تنظیم نشده. از بخش تنظیمات آن را وارد کنید.</div>';
      view.innerHTML = alerts +
        '<div class="grid stats">' +
        stat(d.total, 'کل کاربران') + stat(d.online, 'آنلاین') + stat(d.active, 'فعال') + stat(d.disabled, 'غیرفعال') + stat(fmtBytes(d.traffic), 'کل ترافیک مصرفی') +
        '</div><h2>وضعیت سرور</h2><div class="card"><table>' +
        tr('وضعیت اینترفیس', d.hasWg ? (d.wgUp ? '<span class="badge ok">بالا (' + esc(d.iface) + ')</span>' : '<span class="badge bad">پایین</span>') : '<span class="badge warn">Dry-Run</span>') +
        tr('آدرس پنل', '<span class="ltr">' + esc(d.panelUrl) + '</span>') +
        tr('Endpoint', '<span class="ltr">' + esc(d.endpoint || '—') + ':' + esc(d.port) + '</span>') +
        tr('کلید عمومی سرور', '<span class="ltr" style="word-break:break-all">' + esc(d.serverPublicKey) + '</span>') +
        tr('مدت اجرای پنل', fmtUptime(d.uptime)) + tr('نسخه', esc(d.version)) +
        '</table></div>';
    } catch (e) { if (!timer) toast(e.message, 'bad'); }
  }
  const stat = (v, l) => '<div class="card stat"><b>' + esc(v) + '</b><span>' + l + '</span></div>';
  const tr = (a, b) => '<tr><td>' + a + '</td><td>' + b + '</td></tr>';

  /* -------------------------------------------------------- clients */
  let clients = [];
  let filter = '';
  async function pClients(silent) {
    try { clients = await api('GET', '/api/clients'); } catch (e) { if (!silent) toast(e.message, 'bad'); return; }
    if (!silent || !$('#clist')) {
      view.innerHTML = '<div class="row between"><h2>کاربران / کانفیگ‌ها</h2><div class="row">' +
        '<input id="q" placeholder="جستجو..." style="width:170px" value="' + esc(filter) + '">' +
        '<button id="addBtn" class="btn primary">+ کاربر جدید</button></div></div><div id="clist" class="clist"></div>';
      $('#addBtn').onclick = openCreate;
      $('#q').oninput = (e) => { filter = e.target.value; renderClients(); };
      $('#clist').addEventListener('click', onClientAction);
    }
    renderClients();
  }

  function renderClients() {
    const list = clients.filter((c) => !filter || (c.name + ' ' + c.address + ' ' + (c.note || '')).toLowerCase().includes(filter.toLowerCase()));
    if (!list.length) { $('#clist').innerHTML = '<div class="card muted">' + (clients.length ? 'موردی پیدا نشد.' : 'هنوز کاربری ساخته نشده. با دکمهٔ «کاربر جدید» شروع کنید.') + '</div>'; return; }
    $('#clist').innerHTML = list.map(clientCard).join('');
  }

  function clientCard(c) {
    const pct = c.quotaBytes > 0 ? Math.min(100, (c.used / c.quotaBytes) * 100) : 0;
    let badge = '<span class="badge ok">فعال</span>';
    if (!c.enabled) {
      const t = c.disabledReason === 'quota' ? 'اتمام حجم' : c.disabledReason === 'expired' ? 'منقضی' : 'غیرفعال';
      badge = '<span class="badge bad">' + t + '</span>';
    }
    const exp = c.expiresAt ? Math.ceil((c.expiresAt - Date.now()) / 86400000) : null;
    const expTxt = c.expiresAt ? fmtDate(c.expiresAt) + (exp > 0 ? ' (' + exp + ' روز مانده)' : '') : 'نامحدود';
    return '<div class="card client" data-id="' + c.id + '">' +
      '<div class="head"><div class="name"><span class="dot ' + (c.online ? 'on' : '') + '"></span>' + esc(c.name) + '</div><div>' + badge + '</div></div>' +
      '<div class="muted ltr">' + esc(c.address) + (c.note ? ' &nbsp;·&nbsp; <span style="unicode-bidi:plaintext">' + esc(c.note) + '</span>' : '') + '</div>' +
      '<div class="bar"><i class="' + (pct > 90 ? 'hot' : '') + '" style="width:' + pct + '%"></i></div>' +
      '<div class="row between muted" style="font-size:13px"><span>مصرف: ' + fmtBytes(c.used) + ' / ' + (c.quotaBytes > 0 ? fmtBytes(c.quotaBytes) : 'نامحدود') + '</span>' +
      '<span>↑ ' + fmtBytes(c.usedRx) + ' ↓ ' + fmtBytes(c.usedTx) + '</span></div>' +
      '<div class="muted" style="font-size:13px">انقضا: ' + expTxt + ' · آخرین اتصال: ' + ago(c.lastHandshake) + '</div>' +
      '<div class="acts">' +
      '<button class="btn small primary" data-a="qr">QR / کانفیگ</button>' +
      '<button class="btn small" data-a="link">لینک اشتراک</button>' +
      '<button class="btn small" data-a="edit">ویرایش</button>' +
      '<button class="btn small" data-a="toggle">' + (c.enabled ? 'غیرفعال‌سازی' : 'فعال‌سازی') + '</button>' +
      '<button class="btn small" data-a="reset">ریست حجم</button>' +
      '<button class="btn small danger" data-a="del">حذف</button></div></div>';
  }

  async function onClientAction(e) {
    const b = e.target.closest('button[data-a]');
    if (!b) return;
    const id = b.closest('.client').dataset.id;
    const c = clients.find((x) => x.id === id);
    const a = b.dataset.a;
    if (a === 'qr') return openQr(c);
    if (a === 'link') {
      const base = (dash && dash.panelUrl) || location.origin;
      return copy((base || location.origin) + '/c/' + c.token);
    }
    if (a === 'edit') return openEdit(c);
    if (a === 'toggle') { if (await act(() => api('PATCH', '/api/clients/' + id, { enabled: !c.enabled }), c.enabled ? 'غیرفعال شد' : 'فعال شد')) pClients(true); return; }
    if (a === 'reset') { if (!confirm('مصرف «' + c.name + '» صفر شود؟')) return; if (await act(() => api('POST', '/api/clients/' + id + '/reset', {}), 'مصرف ریست شد')) pClients(true); return; }
    if (a === 'del') { if (!confirm('کاربر «' + c.name + '» برای همیشه حذف شود؟')) return; if (await act(() => api('DELETE', '/api/clients/' + id), 'حذف شد')) pClients(true); }
  }

  async function ensureDash() { if (!dash) { try { dash = await api('GET', '/api/dashboard'); } catch (e) { /* */ } } }

  async function openCreate() {
    let s = {};
    try { s = await api('GET', '/api/settings'); } catch (e) { /* */ }
    const m = modal('<h3>کاربر جدید</h3>' +
      '<label>نام</label><input id="cn" maxlength="40" placeholder="مثلاً ali">' +
      '<div class="two"><div><label>حجم (گیگابایت، ۰ = نامحدود)</label><input id="cq" type="number" min="0" step="any" value="' + (s.defaultQuotaGB || 0) + '"></div>' +
      '<div><label>مدت اعتبار (روز، ۰ = نامحدود)</label><input id="cd" type="number" min="0" step="1" value="' + (s.defaultExpiryDays || 0) + '"></div></div>' +
      '<div class="two"><div><label>تعداد (ساخت گروهی)</label><input id="cc" type="number" min="1" max="100" value="1"></div>' +
      '<div><label>یادداشت</label><input id="cnote" maxlength="200"></div></div>' +
      '<p id="cerr" class="err"></p><div class="row"><button id="csave" class="btn primary">ساخت</button><button class="btn" data-close>انصراف</button></div>');
    $('#cn', m).focus();
    $('#csave', m).onclick = async () => {
      try {
        await api('POST', '/api/clients', { name: $('#cn', m).value, quotaGB: $('#cq', m).value, expiryDays: $('#cd', m).value, count: $('#cc', m).value, note: $('#cnote', m).value });
        m.close(); toast('ساخته شد', 'ok'); pClients(true);
      } catch (e) { $('#cerr', m).textContent = e.message; }
    };
  }

  function openEdit(c) {
    const expVal = c.expiresAt ? new Date(c.expiresAt).toISOString().slice(0, 10) : '';
    const m = modal('<h3>ویرایش «' + esc(c.name) + '»</h3>' +
      '<label>نام</label><input id="en" maxlength="40" value="' + esc(c.name) + '">' +
      '<div class="two"><div><label>حجم (گیگابایت، ۰ = نامحدود)</label><input id="eq" type="number" min="0" step="any" value="' + (c.quotaBytes / GB) + '"></div>' +
      '<div><label>تاریخ انقضا (خالی = نامحدود)</label><input id="ee" type="date" value="' + expVal + '"></div></div>' +
      '<div class="row" style="margin-top:6px"><button class="btn small" data-x="7">+۷ روز</button><button class="btn small" data-x="30">+۳۰ روز</button><button class="btn small" data-g="10">+۱۰ گیگ</button><button class="btn small" data-g="50">+۵۰ گیگ</button></div>' +
      '<label>یادداشت</label><input id="eno" maxlength="200" value="' + esc(c.note || '') + '">' +
      '<p id="eerr" class="err"></p><div class="row"><button id="esave" class="btn primary">ذخیره</button><button id="eregen" class="btn danger">ساخت کلید جدید</button><button class="btn" data-close>انصراف</button></div>');
    m.querySelectorAll('[data-x]').forEach((b) => b.onclick = () => {
      const cur = $('#ee', m).value ? new Date($('#ee', m).value + 'T23:59:59').getTime() : Date.now();
      const base = Math.max(cur, Date.now());
      $('#ee', m).value = new Date(base + Number(b.dataset.x) * 86400000).toISOString().slice(0, 10);
    });
    m.querySelectorAll('[data-g]').forEach((b) => b.onclick = () => { $('#eq', m).value = (Number($('#eq', m).value || 0) + Number(b.dataset.g)).toString(); });
    $('#esave', m).onclick = async () => {
      const ev = $('#ee', m).value;
      try {
        await api('PATCH', '/api/clients/' + c.id, {
          name: $('#en', m).value, note: $('#eno', m).value, quotaGB: $('#eq', m).value || 0,
          expiresAt: ev ? new Date(ev + 'T23:59:59').getTime() : null,
        });
        m.close(); toast('ذخیره شد', 'ok'); pClients(true);
      } catch (e) { $('#eerr', m).textContent = e.message; }
    };
    $('#eregen', m).onclick = async () => {
      if (!confirm('کلیدها عوض می‌شود و کانفیگ قبلی از کار می‌افتد. ادامه می‌دهید؟')) return;
      if (await act(() => api('POST', '/api/clients/' + c.id + '/regenerate', {}), 'کلید جدید ساخته شد')) { m.close(); pClients(true); }
    };
  }

  async function openQr(c) {
    await ensureDash();
    let conf = '';
    try { conf = (await api('GET', '/api/clients/' + c.id + '/text')).config; } catch (e) { return toast(e.message, 'bad'); }
    const hasQr = dash && dash.hasQr;
    const m = modal('<h3>' + esc(c.name) + '</h3>' +
      (hasQr ? '<div class="qr"><img alt="QR" src="/api/clients/' + c.id + '/qr?t=' + Date.now() + '"></div>' : '<p class="muted">برای نمایش QR، ماژول qrcode لازم است (npm install).</p>') +
      '<pre class="conf">' + esc(conf) + '</pre>' +
      '<div class="row"><a class="btn primary" href="/api/clients/' + c.id + '/config">دانلود .conf</a><button id="qcopy" class="btn">کپی</button><button class="btn" data-close>بستن</button></div>');
    $('#qcopy', m).onclick = () => copy(conf);
  }

  /* ------------------------------------------------------- settings */
  async function pSettings() {
    let s;
    try { s = await api('GET', '/api/settings'); } catch (e) { return toast(e.message, 'bad'); }
    const f = (id, label, val, extra) => '<div><label>' + label + '</label><input id="' + id + '" value="' + esc(val) + '" ' + (extra || '') + '></div>';
    view.innerHTML = '<h2>تنظیمات</h2><div class="card">' +
      '<h3>آدرس‌ها</h3><div class="two">' +
      f('s_panelUrl', 'آدرس پنل', s.panelUrl, 'class="ltr" placeholder="https://cloud.stackdome.com"') +
      '<div><label>آدرس سرور برای کانفیگ‌ها (Endpoint: IP یا دامنه)</label><div class="row" style="flex-wrap:nowrap"><input id="s_endpoint" class="ltr" value="' + esc(s.endpoint) + '"><button id="detect" class="btn small" type="button">تشخیص IP</button></div></div>' +
      f('s_listenPort', 'پورت UDP وایرگارد', s.listenPort, 'type="number" min="1" max="65535"') +
      f('s_interface', 'نام اینترفیس', s.interface, 'class="ltr"') +
      f('s_subnet', 'زیرشبکهٔ کاربران', s.subnet, 'class="ltr"') +
      f('s_extIface', 'کارت شبکهٔ خروجی برای NAT (خالی = خودکار' + (s.detectedExt ? ': ' + esc(s.detectedExt) : '') + ')', s.extIface, 'class="ltr"') +
      '</div><h3 style="margin-top:18px">کانفیگ کاربران</h3><div class="two">' +
      f('s_dns', 'DNS', s.dns, 'class="ltr"') +
      f('s_allowedIps', 'AllowedIPs', s.allowedIps, 'class="ltr"') +
      f('s_mtu', 'MTU', s.mtu, 'type="number"') +
      f('s_keepalive', 'PersistentKeepalive (ثانیه)', s.keepalive, 'type="number"') +
      '</div><h3 style="margin-top:18px">پیش‌فرض کاربر جدید</h3><div class="two">' +
      f('s_defaultQuotaGB', 'حجم پیش‌فرض (گیگابایت، ۰ = نامحدود)', s.defaultQuotaGB, 'type="number" min="0" step="any"') +
      f('s_defaultExpiryDays', 'اعتبار پیش‌فرض (روز، ۰ = نامحدود)', s.defaultExpiryDays, 'type="number" min="0"') +
      '</div>' +
      '<div class="toggle"><input type="checkbox" id="s_usePsk"' + (s.usePsk ? ' checked' : '') + '><label for="s_usePsk">استفاده از PresharedKey برای کاربران جدید (امنیت بیشتر)</label></div>' +
      '<div class="toggle"><input type="checkbox" id="s_monthlyReset"' + (s.monthlyReset ? ' checked' : '') + '><label for="s_monthlyReset">ریست خودکار مصرف حجم در ابتدای هر ماه میلادی</label></div>' +
      '<p id="serr" class="err"></p><div class="row"><button id="ssave" class="btn primary">ذخیره و اعمال</button><button id="srestart" class="btn">ری‌استارت وایرگارد</button></div>' +
      '<p class="muted" style="font-size:13px">تغییر پورت، اینترفیس، زیرشبکه، MTU و کارت شبکه باعث ری‌استارت کوتاه اینترفیس می‌شود. تغییر زیرشبکه آدرس همهٔ کاربران را عوض می‌کند و باید کانفیگ‌ها را دوباره بگیرند.</p></div>';
    $('#detect').onclick = async () => { const r = await act(() => api('POST', '/api/server/detect-ip', {})); if (r) $('#s_endpoint').value = r.ip; };
    $('#srestart').onclick = () => act(() => api('POST', '/api/server/restart', {}), 'وایرگارد ری‌استارت شد');
    $('#ssave').onclick = async () => {
      $('#serr').textContent = '';
      const g = (k) => $('#s_' + k).value;
      const body = {
        panelUrl: g('panelUrl'), endpoint: g('endpoint'), listenPort: g('listenPort'), interface: g('interface'), subnet: g('subnet'),
        extIface: g('extIface'), dns: g('dns'), allowedIps: g('allowedIps'), mtu: g('mtu'), keepalive: g('keepalive'),
        defaultQuotaGB: g('defaultQuotaGB'), defaultExpiryDays: g('defaultExpiryDays'),
        usePsk: $('#s_usePsk').checked, monthlyReset: $('#s_monthlyReset').checked,
      };
      try {
        const r = await api('PUT', '/api/settings', body);
        dash = null;
        toast(r.reassigned ? 'ذخیره شد؛ آدرس کاربران تغییر کرد' : 'ذخیره و اعمال شد', 'ok');
      } catch (e) { $('#serr').textContent = e.message; }
    };
  }

  /* --------------------------------------------------------- backup */
  function pBackup() {
    view.innerHTML = '<h2>پشتیبان‌گیری</h2><div class="card"><p>فایل پشتیبان شامل کلیدهای خصوصی سرور و کاربران است؛ آن را امن نگه دارید.</p>' +
      '<div class="row"><a class="btn primary" href="/api/backup">دانلود پشتیبان</a>' +
      '<button id="rbtn" class="btn">بازیابی از فایل...</button><input id="rfile" type="file" accept="application/json,.json" class="hidden"></div>' +
      '<p class="muted" style="font-size:13px">بازیابی، اطلاعات فعلی را جایگزین می‌کند و وایرگارد ری‌استارت می‌شود.</p></div>';
    $('#rbtn').onclick = () => $('#rfile').click();
    $('#rfile').onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (!confirm('اطلاعات فعلی با فایل پشتیبان جایگزین شود؟')) return;
      try {
        const data = JSON.parse(await file.text());
        const r = await api('POST', '/api/restore', data);
        toast('بازیابی شد (' + r.count + ' کاربر)', 'ok');
      } catch (err) { toast(err.message || 'فایل نامعتبر', 'bad'); }
      e.target.value = '';
    };
  }

  /* ----------------------------------------------------------- logs */
  async function pLogs() {
    let logs;
    try { logs = await api('GET', '/api/logs'); } catch (e) { return toast(e.message, 'bad'); }
    view.innerHTML = '<div class="row between"><h2>گزارش‌ها</h2><button id="clr" class="btn small">پاک کردن</button></div><div class="card"><table>' +
      (logs.length ? logs.map((l) => '<tr><td>' + fmtDateTime(l.t) + '</td><td>' + esc(l.m) + '</td></tr>').join('') : '<tr><td colspan="2" class="muted">گزارشی وجود ندارد.</td></tr>') + '</table></div>';
    $('#clr').onclick = async () => { if (await act(() => api('DELETE', '/api/logs'))) pLogs(); };
  }

  /* -------------------------------------------------------- account */
  async function pAccount() {
    let me;
    try { me = await api('GET', '/api/me'); } catch (e) { return; }
    view.innerHTML = '<h2>حساب مدیر</h2><div class="card" style="max-width:420px">' +
      '<label>نام کاربری</label><input id="a_u" class="ltr" value="' + esc(me.username) + '" autocomplete="username">' +
      '<label>رمز فعلی</label><input id="a_o" type="password" autocomplete="current-password">' +
      '<label>رمز جدید (حداقل ۸ نویسه؛ خالی = بدون تغییر)</label><input id="a_n" type="password" autocomplete="new-password">' +
      '<p id="aerr" class="err"></p><button id="asave" class="btn primary">ذخیره</button></div>';
    $('#asave').onclick = async () => {
      try {
        await api('POST', '/api/account', { newUsername: $('#a_u').value, oldPassword: $('#a_o').value, newPassword: $('#a_n').value });
        toast('ذخیره شد؛ دوباره وارد شوید', 'ok');
        showLogin();
      } catch (e) { $('#aerr').textContent = e.message; }
    };
  }

  /* ----------------------------------------------------------- boot */
  (async function init() {
    try { await api('GET', '/api/me'); showApp(); } catch (e) { showLogin(); }
  })();
})();
