'use strict';
/*
 * WG Panel - پنل مدیریت وایرگارد
 * Zero-dependency Node.js backend (only optional dependency: "qrcode" for QR images)
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

let QRCode = null;
try { QRCode = require('qrcode'); } catch (e) { /* optional */ }

const VERSION = '1.0.0';
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const WG_DIR = process.env.WG_DIR || '/etc/wireguard';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DB_FILE = path.join(DATA_DIR, 'db.json');
const STARTED_AT = Date.now();

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

/* ------------------------------------------------------------------ utils */
class ApiError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

function run(cmd, args, opts) {
  return new Promise((resolve) => {
    execFile(cmd, args, Object.assign({ timeout: 25000 }, opts || {}), (err, stdout, stderr) => {
      resolve({ ok: !err, stdout: String(stdout || ''), stderr: String(stderr || ''), err });
    });
  });
}

function genKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey: priv.toString('base64'), publicKey: pub.toString('base64') };
}
function genPsk() { return crypto.randomBytes(32).toString('base64'); }

function ip2int(ip) {
  const p = ip.split('.').map(Number);
  return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}
function int2ip(n) { return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }
function parseCidr(c) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(String(c || '').trim());
  if (!m) return null;
  const oct = m.slice(1, 5).map(Number);
  if (oct.some((o) => o > 255)) return null;
  const bits = +m[5];
  if (bits < 16 || bits > 29) return null;
  const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
  const base = (ip2int(oct.join('.')) & mask) >>> 0;
  return { base, bits, mask, size: Math.pow(2, 32 - bits) };
}

function fmtEndpoint(h) { return h.includes(':') && !h.startsWith('[') ? '[' + h + ']' : h; }
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n.toFixed(0) : n.toFixed(2)) + ' ' + u[i];
}
function fmtDate(ts) {
  try { return new Date(ts).toLocaleDateString('fa-IR', { timeZone: 'Asia/Tehran' }); } catch (e) { return new Date(ts).toISOString().slice(0, 10); }
}

/* --------------------------------------------------------------- database */
const NAT_KEYS = ['listenPort', 'subnet', 'interface', 'extIface', 'mtu'];

function defaultSettings() {
  return {
    panelUrl: process.env.PANEL_URL || 'https://cloud.stackdome.com',
    endpoint: process.env.ENDPOINT || '',
    listenPort: 51820,
    interface: 'wg0',
    subnet: '10.66.66.0/24',
    dns: '1.1.1.1, 8.8.8.8',
    mtu: 1420,
    keepalive: 25,
    allowedIps: '0.0.0.0/0, ::/0',
    usePsk: true,
    extIface: '',
    defaultQuotaGB: 0,
    defaultExpiryDays: 0,
    monthlyReset: false,
  };
}

let db = null;
function loadDb() {
  let raw = null;
  for (const f of [DB_FILE, DB_FILE + '.bak']) {
    if (fs.existsSync(f)) {
      try { raw = JSON.parse(fs.readFileSync(f, 'utf8')); break; } catch (e) {
        console.error('[db] cannot parse ' + f + ': ' + e.message);
      }
    }
  }
  if (!raw && fs.existsSync(DB_FILE)) {
    console.error('[db] database is corrupted and no valid backup found. Refusing to start to avoid data loss.');
    process.exit(1);
  }
  db = raw || {};
  db.settings = Object.assign(defaultSettings(), db.settings || {});
  db.clients = Array.isArray(db.clients) ? db.clients : [];
  db.logs = Array.isArray(db.logs) ? db.logs : [];
  db.runtime = db.runtime || {};
  if (!db.secret) db.secret = crypto.randomBytes(32).toString('hex');
  if (!db.server) db.server = genKeyPair();
  if (!db.admin) {
    const pass = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
    db.admin = makeAdmin(process.env.ADMIN_USER || 'admin', pass);
    try {
      fs.writeFileSync(path.join(DATA_DIR, 'initial-admin.txt'),
        'username: ' + db.admin.username + '\npassword: ' + pass + '\n', { mode: 0o600 });
    } catch (e) { /* ignore */ }
    console.log('[panel] Admin created -> username: ' + db.admin.username + '  password: ' + pass);
  }
  saveNow();
}
function makeAdmin(username, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { username, salt, hash, pv: Date.now() };
}
function checkPassword(password) {
  const h = crypto.scryptSync(String(password), db.admin.salt, 64);
  const e = Buffer.from(db.admin.hash, 'hex');
  return h.length === e.length && crypto.timingSafeEqual(h, e);
}

let saveTimer = null;
let lastBackup = 0;
function saveNow() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  const tmp = DB_FILE + '.tmp';
  try {
    if (fs.existsSync(DB_FILE) && Date.now() - lastBackup > 10 * 60 * 1000) {
      fs.copyFileSync(DB_FILE, DB_FILE + '.bak');
      lastBackup = Date.now();
    }
    fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 });
    fs.renameSync(tmp, DB_FILE);
  } catch (e) { console.error('[db] save failed: ' + e.message); }
}
function save() { if (!saveTimer) saveTimer = setTimeout(saveNow, 400); }

function log(msg) {
  console.log('[panel] ' + msg);
  db.logs.unshift({ t: Date.now(), m: msg });
  if (db.logs.length > 300) db.logs.length = 300;
  save();
}

/* ------------------------------------------------------------- wireguard */
let HAS_WG = false;
const state = { wgUp: false, publicIpTried: false, lastError: '' };

async function detectSystem() {
  if (process.env.DRY_RUN === '1') { HAS_WG = false; return; }
  const r = await run('bash', ['-c', 'command -v wg && command -v wg-quick']);
  const root = typeof process.getuid === 'function' ? process.getuid() === 0 : false;
  HAS_WG = r.ok && root;
  if (!HAS_WG) console.warn('[panel] WireGuard tools not available or not root -> DRY-RUN mode (no system changes).');
}

async function detectExtIface() {
  if (!HAS_WG) return '';
  const r = await run('ip', ['-o', '-4', 'route', 'show', 'to', 'default']);
  const m = /dev\s+(\S+)/.exec(r.stdout);
  return m ? m[1] : '';
}

function fetchPublicIp() {
  return new Promise((resolve) => {
    const req = https.get('https://api.ipify.org', { timeout: 6000 }, (res) => {
      let d = '';
      res.on('data', (c) => { d += c; if (d.length > 100) req.destroy(); });
      res.on('end', () => resolve(/^[0-9.]{7,15}$/.test(d.trim()) ? d.trim() : ''));
    });
    req.on('timeout', () => { req.destroy(); resolve(''); });
    req.on('error', () => resolve(''));
  });
}

function confPath() { return path.join(WG_DIR, db.settings.interface + '.conf'); }

function buildServerConf() {
  const s = db.settings;
  const net = parseCidr(s.subnet);
  const lines = [
    '# Generated by WG Panel - do not edit by hand',
    '[Interface]',
    'Address = ' + int2ip(net.base + 1) + '/' + net.bits,
    'ListenPort = ' + s.listenPort,
    'PrivateKey = ' + db.server.privateKey,
  ];
  if (s.mtu) lines.push('MTU = ' + s.mtu);
  const ext = s.extIface || db.runtime.detectedExt || '';
  if (ext && /^[a-zA-Z0-9_.:-]{1,15}$/.test(ext)) {
    lines.push('PostUp = iptables -A FORWARD -i %i -j ACCEPT || true; iptables -A FORWARD -o %i -j ACCEPT || true; iptables -t nat -A POSTROUTING -o ' + ext + ' -j MASQUERADE || true');
    lines.push('PostDown = iptables -D FORWARD -i %i -j ACCEPT || true; iptables -D FORWARD -o %i -j ACCEPT || true; iptables -t nat -D POSTROUTING -o ' + ext + ' -j MASQUERADE || true');
  }
  for (const c of db.clients) {
    if (!c.enabled) continue;
    lines.push('', '# ' + String(c.name).replace(/[\r\n]/g, ' '), '[Peer]', 'PublicKey = ' + c.publicKey);
    if (c.presharedKey) lines.push('PresharedKey = ' + c.presharedKey);
    lines.push('AllowedIPs = ' + c.address + '/32');
  }
  return lines.join('\n') + '\n';
}

function writeServerConf() {
  if (!HAS_WG) return;
  fs.mkdirSync(WG_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(confPath(), buildServerConf(), { mode: 0o600 });
}

let applyQueue = Promise.resolve();
function applyConfig(full) {
  applyQueue = applyQueue.then(() => doApply(full)).catch((e) => {
    state.lastError = e.message;
    log('خطا در اعمال تنظیمات وایرگارد: ' + e.message);
  });
  return applyQueue;
}
async function doApply(full) {
  if (!HAS_WG) return;
  const ifc = db.settings.interface;
  const prev = db.runtime.appliedIface;
  const up = (await run('wg', ['show', ifc])).ok;
  if (full && up) await tick(true);               // capture counters before restart
  writeServerConf();
  if (full || !up) {
    if (prev && prev !== ifc) await run('wg-quick', ['down', prev]);
    if (up) await run('wg-quick', ['down', confPath()]);
    const r = await run('wg-quick', ['up', confPath()]);
    if (!r.ok) throw new Error((r.stderr || 'wg-quick up failed').trim().slice(0, 500));
    state.lastError = '';
    log('اینترفیس ' + ifc + ' بالا آمد');
  } else {
    const r = await run('bash', ['-c', 'wg syncconf "$0" <(wg-quick strip "$1")', ifc, confPath()]);
    if (!r.ok) throw new Error((r.stderr || 'wg syncconf failed').trim().slice(0, 500));
    state.lastError = '';
  }
  db.runtime.appliedIface = ifc;
  save();
}

/* --------------------------------------------------------------- clients */
function allocIp() {
  const net = parseCidr(db.settings.subnet);
  const used = new Set(db.clients.map((c) => c.address));
  for (let i = 2; i < net.size - 1; i++) {
    const ip = int2ip(net.base + i);
    if (!used.has(ip)) return ip;
  }
  return null;
}

function limitReason(c) {
  if (c.quotaBytes > 0 && c.usedRx + c.usedTx >= c.quotaBytes) return 'quota';
  if (c.expiresAt && Date.now() >= c.expiresAt) return 'expired';
  return null;
}

function makeClient(name, quotaGB, expiryDays, note) {
  const address = allocIp();
  if (!address) throw new ApiError(400, 'ظرفیت آدرس‌های شبکه پر شده است. زیرشبکه را بزرگ‌تر کنید.');
  const kp = genKeyPair();
  return {
    id: crypto.randomUUID(),
    name, note: note || '',
    privateKey: kp.privateKey, publicKey: kp.publicKey,
    presharedKey: db.settings.usePsk ? genPsk() : '',
    address, enabled: true, disabledReason: null,
    quotaBytes: Math.round(quotaGB * 1024 * 1024 * 1024),
    usedRx: 0, usedTx: 0, lastRx: 0, lastTx: 0,
    expiresAt: expiryDays > 0 ? Date.now() + expiryDays * 86400000 : null,
    createdAt: Date.now(), lastHandshake: 0, lastEndpoint: '',
    token: crypto.randomBytes(18).toString('base64url'),
  };
}

function clientConfig(c) {
  const s = db.settings;
  let ep = s.endpoint;
  if (!ep) { try { ep = new URL(s.panelUrl).hostname; } catch (e) { ep = ''; } }
  if (!ep) throw new ApiError(400, 'آدرس سرور (Endpoint) در تنظیمات مشخص نشده است.');
  const l = ['[Interface]', 'PrivateKey = ' + c.privateKey, 'Address = ' + c.address + '/32'];
  if (s.dns) l.push('DNS = ' + s.dns);
  if (s.mtu) l.push('MTU = ' + s.mtu);
  l.push('', '[Peer]', 'PublicKey = ' + db.server.publicKey);
  if (c.presharedKey) l.push('PresharedKey = ' + c.presharedKey);
  l.push('Endpoint = ' + fmtEndpoint(ep) + ':' + s.listenPort, 'AllowedIPs = ' + s.allowedIps);
  if (s.keepalive) l.push('PersistentKeepalive = ' + s.keepalive);
  return l.join('\n') + '\n';
}

function fileSlug(c) {
  let s = String(c.name).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 15);
  if (!s) s = 'wg-' + c.address.split('.').pop();
  return s;
}

function isOnline(c) { return c.lastHandshake && Date.now() - c.lastHandshake < 180000; }

function clientView(c) {
  const used = c.usedRx + c.usedTx;
  return {
    id: c.id, name: c.name, note: c.note, address: c.address,
    enabled: c.enabled, disabledReason: c.disabledReason,
    quotaBytes: c.quotaBytes, usedRx: c.usedRx, usedTx: c.usedTx, used,
    expiresAt: c.expiresAt, createdAt: c.createdAt,
    lastHandshake: c.lastHandshake, lastEndpoint: c.lastEndpoint,
    online: !!isOnline(c), token: c.token,
  };
}

async function tick(noApply) {
  const now = Date.now();
  let changed = false;

  // monthly reset
  if (db.settings.monthlyReset) {
    const d = new Date();
    const key = d.getUTCFullYear() * 100 + d.getUTCMonth() + 1;
    if (db.runtime.lastResetMonth && db.runtime.lastResetMonth !== key) {
      for (const c of db.clients) {
        c.usedRx = 0; c.usedTx = 0;
        if (!c.enabled && c.disabledReason === 'quota' && !limitReason(c)) { c.enabled = true; c.disabledReason = null; }
      }
      log('ریست ماهانهٔ مصرف حجم انجام شد');
      changed = true;
    }
    if (db.runtime.lastResetMonth !== key) { db.runtime.lastResetMonth = key; changed = true; }
  }

  if (HAS_WG) {
    const r = await run('wg', ['show', db.settings.interface, 'dump']);
    state.wgUp = r.ok;
    if (r.ok) {
      const seen = new Set();
      const lines = r.stdout.trim().split('\n').slice(1);
      const byPub = new Map(db.clients.map((c) => [c.publicKey, c]));
      for (const ln of lines) {
        const f = ln.split('\t');
        if (f.length < 8) continue;
        const c = byPub.get(f[0]);
        if (!c) continue;
        seen.add(c.id);
        const rx = Number(f[5]) || 0, tx = Number(f[6]) || 0;
        c.usedRx += rx >= c.lastRx ? rx - c.lastRx : rx;
        c.usedTx += tx >= c.lastTx ? tx - c.lastTx : tx;
        c.lastRx = rx; c.lastTx = tx;
        const hs = (Number(f[4]) || 0) * 1000;
        if (hs) c.lastHandshake = hs;
        if (f[2] && f[2] !== '(none)') c.lastEndpoint = f[2];
      }
      for (const c of db.clients) if (!seen.has(c.id)) { c.lastRx = 0; c.lastTx = 0; }
      changed = true;
    }
  }

  // enforce limits
  let needApply = false;
  for (const c of db.clients) {
    if (!c.enabled) continue;
    const why = limitReason(c);
    if (why) {
      c.enabled = false; c.disabledReason = why; needApply = true; changed = true;
      log('کاربر «' + c.name + '» غیرفعال شد (' + (why === 'quota' ? 'اتمام حجم' : 'پایان اعتبار') + ')');
    }
  }
  if (changed) save();
  if (needApply && !noApply) await applyConfig(false);
  return now;
}

/* ------------------------------------------------------------------ auth */
function signToken(p) {
  const b = Buffer.from(JSON.stringify(p)).toString('base64url');
  const s = crypto.createHmac('sha256', db.secret).update(b).digest('base64url');
  return b + '.' + s;
}
function verifyToken(t) {
  if (!t || typeof t !== 'string') return null;
  const [b, s] = t.split('.');
  if (!b || !s) return null;
  const e = crypto.createHmac('sha256', db.secret).update(b).digest('base64url');
  const x = Buffer.from(s), y = Buffer.from(e);
  if (x.length !== y.length || !crypto.timingSafeEqual(x, y)) return null;
  try {
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (!p.exp || p.exp < Date.now() || p.pv !== db.admin.pv) return null;
    return p;
  } catch (e2) { return null; }
}
function getCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}
function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  return req.socket.remoteAddress || '';
}
const attempts = new Map();
function checkRate(ip) {
  const a = attempts.get(ip);
  if (a && a.until > Date.now()) throw new ApiError(429, 'تلاش‌های ناموفق زیاد بود. چند دقیقه بعد دوباره امتحان کنید.');
}
function failAttempt(ip) {
  const a = attempts.get(ip) || { n: 0, until: 0 };
  a.n++;
  if (a.n >= 8) { a.until = Date.now() + 10 * 60 * 1000; a.n = 0; }
  attempts.set(ip, a);
}

/* --------------------------------------------------------------- routing */
const routes = [];
function route(method, pattern, handler, opts) {
  routes.push({ method, re: new RegExp('^' + pattern + '$'), handler, auth: !(opts && opts.auth === false) });
}

function findClient(id) {
  const c = db.clients.find((x) => x.id === id);
  if (!c) throw new ApiError(404, 'کاربر پیدا نشد.');
  return c;
}

function num(v, def, min, max, label) {
  if (v === undefined || v === null || v === '') return def;
  const n = Number(v);
  if (!isFinite(n) || n < min || n > max) throw new ApiError(400, 'مقدار نامعتبر: ' + label);
  return n;
}
function cleanName(v) {
  const s = String(v || '').replace(/[\r\n\t]/g, ' ').trim();
  if (!s || s.length > 40) throw new ApiError(400, 'نام باید بین ۱ تا ۴۰ نویسه باشد.');
  return s;
}

route('POST', '/api/login', async (ctx) => {
  checkRate(ctx.ip);
  const { username, password } = ctx.body || {};
  const okUser = typeof username === 'string' && username === db.admin.username;
  const okPass = typeof password === 'string' && checkPassword(password);
  if (!okUser || !okPass) { failAttempt(ctx.ip); throw new ApiError(401, 'نام کاربری یا رمز عبور اشتباه است.'); }
  attempts.delete(ctx.ip);
  const maxAge = 7 * 24 * 3600;
  const tok = signToken({ u: db.admin.username, pv: db.admin.pv, exp: Date.now() + maxAge * 1000 });
  const secure = ctx.req.headers['x-forwarded-proto'] === 'https' || ctx.req.socket.encrypted ? '; Secure' : '';
  ctx.res.setHeader('Set-Cookie', 'session=' + encodeURIComponent(tok) + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + maxAge + secure);
  return { ok: true };
}, { auth: false });

route('POST', '/api/logout', async (ctx) => {
  ctx.res.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  return { ok: true };
}, { auth: false });

route('GET', '/api/me', async (ctx) => ({ username: db.admin.username, version: VERSION }));

route('POST', '/api/account', async (ctx) => {
  const { oldPassword, newPassword, newUsername } = ctx.body || {};
  if (!checkPassword(oldPassword || '')) throw new ApiError(400, 'رمز فعلی اشتباه است.');
  const uname = String(newUsername || db.admin.username).trim();
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(uname)) throw new ApiError(400, 'نام کاربری فقط حروف انگلیسی/عدد و ۳ تا ۳۲ نویسه باشد.');
  const pass = newPassword ? String(newPassword) : String(oldPassword);
  if (newPassword && pass.length < 8) throw new ApiError(400, 'رمز جدید حداقل ۸ نویسه باشد.');
  db.admin = makeAdmin(uname, pass);
  try { fs.unlinkSync(path.join(DATA_DIR, 'initial-admin.txt')); } catch (e) { /* ignore */ }
  log('اطلاعات ورود مدیر تغییر کرد');
  saveNow();
  ctx.res.setHeader('Set-Cookie', 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  return { ok: true };
});

route('GET', '/api/dashboard', async () => {
  const total = db.clients.length;
  const active = db.clients.filter((c) => c.enabled).length;
  const online = db.clients.filter(isOnline).length;
  const traffic = db.clients.reduce((a, c) => a + c.usedRx + c.usedTx, 0);
  return {
    total, active, disabled: total - active, online, traffic,
    hasWg: HAS_WG, wgUp: state.wgUp, lastError: state.lastError, hasQr: !!QRCode,
    serverPublicKey: db.server.publicKey, endpoint: db.settings.endpoint,
    port: db.settings.listenPort, iface: db.settings.interface,
    uptime: Math.floor((Date.now() - STARTED_AT) / 1000), version: VERSION,
    panelUrl: db.settings.panelUrl,
  };
});

route('GET', '/api/clients', async () => db.clients.map(clientView));

route('POST', '/api/clients', async (ctx) => {
  const b = ctx.body || {};
  const s = db.settings;
  const count = Math.floor(num(b.count, 1, 1, 100, 'تعداد'));
  const quotaGB = num(b.quotaGB, s.defaultQuotaGB, 0, 100000, 'حجم');
  const days = Math.floor(num(b.expiryDays, s.defaultExpiryDays, 0, 3650, 'مدت اعتبار'));
  const note = String(b.note || '').slice(0, 200);
  const base = cleanName(b.name);
  const created = [];
  for (let i = 0; i < count; i++) {
    const name = count > 1 ? base + '-' + (i + 1) : base;
    const c = makeClient(name, quotaGB, days, note);
    db.clients.push(c);
    created.push(c);
  }
  log(created.length + ' کاربر جدید ساخته شد: ' + base);
  saveNow();
  await applyConfig(false);
  return created.map(clientView);
});

route('PATCH', '/api/clients/([0-9a-f-]{36})', async (ctx) => {
  const c = findClient(ctx.params[0]);
  const b = ctx.body || {};
  if (b.name !== undefined) c.name = cleanName(b.name);
  if (b.note !== undefined) c.note = String(b.note).slice(0, 200);
  if (b.quotaGB !== undefined) c.quotaBytes = Math.round(num(b.quotaGB, 0, 0, 100000, 'حجم') * 1024 * 1024 * 1024);
  if (b.expiresAt !== undefined) {
    if (b.expiresAt === null || b.expiresAt === '') c.expiresAt = null;
    else {
      const t = Number(b.expiresAt);
      if (!isFinite(t) || t < 0) throw new ApiError(400, 'تاریخ نامعتبر است.');
      c.expiresAt = t;
    }
  }
  if (b.enabled !== undefined) {
    if (b.enabled) {
      const why = limitReason(c);
      if (why) throw new ApiError(400, why === 'quota' ? 'حجم این کاربر تمام شده؛ ابتدا حجم را افزایش دهید یا مصرف را ریست کنید.' : 'اعتبار این کاربر تمام شده؛ ابتدا تاریخ انقضا را تمدید کنید.');
      c.enabled = true; c.disabledReason = null;
    } else { c.enabled = false; c.disabledReason = 'manual'; }
  } else if (!c.enabled && (c.disabledReason === 'quota' || c.disabledReason === 'expired') && !limitReason(c)) {
    c.enabled = true; c.disabledReason = null;   // limit raised -> auto re-enable
  }
  saveNow();
  await applyConfig(false);
  return clientView(c);
});

route('POST', '/api/clients/([0-9a-f-]{36})/reset', async (ctx) => {
  const c = findClient(ctx.params[0]);
  c.usedRx = 0; c.usedTx = 0;
  if (!c.enabled && c.disabledReason === 'quota' && !limitReason(c)) { c.enabled = true; c.disabledReason = null; }
  log('مصرف «' + c.name + '» ریست شد');
  saveNow();
  await applyConfig(false);
  return clientView(c);
});

route('POST', '/api/clients/([0-9a-f-]{36})/regenerate', async (ctx) => {
  const c = findClient(ctx.params[0]);
  const kp = genKeyPair();
  c.privateKey = kp.privateKey; c.publicKey = kp.publicKey;
  c.presharedKey = db.settings.usePsk ? genPsk() : '';
  c.lastRx = 0; c.lastTx = 0; c.lastHandshake = 0;
  c.token = crypto.randomBytes(18).toString('base64url');
  log('کلیدهای «' + c.name + '» دوباره ساخته شد');
  saveNow();
  await applyConfig(false);
  return clientView(c);
});

route('DELETE', '/api/clients/([0-9a-f-]{36})', async (ctx) => {
  const c = findClient(ctx.params[0]);
  db.clients = db.clients.filter((x) => x !== c);
  log('کاربر «' + c.name + '» حذف شد');
  saveNow();
  await applyConfig(false);
  return { ok: true };
});

route('GET', '/api/clients/([0-9a-f-]{36})/config', async (ctx) => {
  const c = findClient(ctx.params[0]);
  sendConfig(ctx.res, c);
});
route('GET', '/api/clients/([0-9a-f-]{36})/text', async (ctx) => ({ config: clientConfig(findClient(ctx.params[0])) }));
route('GET', '/api/clients/([0-9a-f-]{36})/qr', async (ctx) => {
  const c = findClient(ctx.params[0]);
  const svg = await qrSvg(clientConfig(c));
  if (!svg) throw new ApiError(404, 'ماژول QR نصب نیست.');
  ctx.res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
  ctx.res.end(svg);
});

async function qrSvg(text) {
  if (!QRCode) return null;
  try { return await QRCode.toString(text, { type: 'svg', margin: 2, errorCorrectionLevel: 'L' }); } catch (e) { return null; }
}
function sendConfig(res, c) {
  const conf = clientConfig(c);
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Disposition': 'attachment; filename="' + fileSlug(c) + '.conf"',
    'Cache-Control': 'no-store',
  });
  res.end(conf);
}

/* settings */
route('GET', '/api/settings', async () => Object.assign({}, db.settings, { detectedExt: db.runtime.detectedExt || '' }));

route('PUT', '/api/settings', async (ctx) => {
  const b = ctx.body || {};
  const cur = db.settings;
  const n = Object.assign({}, cur);

  if (b.panelUrl !== undefined) {
    const u = String(b.panelUrl).trim().replace(/\/+$/, '');
    if (u && !/^https?:\/\/[A-Za-z0-9.\-:\[\]]+(\/[^\s]*)?$/.test(u)) throw new ApiError(400, 'آدرس پنل نامعتبر است (مثال: https://cloud.stackdome.com).');
    n.panelUrl = u;
  }
  if (b.endpoint !== undefined) {
    const e = String(b.endpoint).trim();
    if (e && !/^[A-Za-z0-9.\-:\[\]]{1,255}$/.test(e)) throw new ApiError(400, 'آدرس سرور (Endpoint) نامعتبر است.');
    n.endpoint = e;
  }
  if (b.listenPort !== undefined) n.listenPort = Math.floor(num(b.listenPort, cur.listenPort, 1, 65535, 'پورت'));
  if (b.interface !== undefined) {
    if (!/^[A-Za-z0-9_-]{1,15}$/.test(String(b.interface))) throw new ApiError(400, 'نام اینترفیس نامعتبر است.');
    n.interface = String(b.interface);
  }
  if (b.subnet !== undefined) {
    if (!parseCidr(b.subnet)) throw new ApiError(400, 'زیرشبکه نامعتبر است (مثال: 10.66.66.0/24، پیشوند بین ۱۶ تا ۲۹).');
    n.subnet = String(b.subnet).trim();
  }
  if (b.dns !== undefined) {
    const d = String(b.dns).trim();
    if (d && !/^[0-9a-fA-F:., ]{1,100}$/.test(d)) throw new ApiError(400, 'DNS نامعتبر است.');
    n.dns = d;
  }
  if (b.mtu !== undefined) n.mtu = Math.floor(num(b.mtu, cur.mtu, 576, 1500, 'MTU'));
  if (b.keepalive !== undefined) n.keepalive = Math.floor(num(b.keepalive, cur.keepalive, 0, 600, 'Keepalive'));
  if (b.allowedIps !== undefined) {
    const a = String(b.allowedIps).trim();
    if (!/^[0-9a-fA-F:./, ]{1,300}$/.test(a) || !a) throw new ApiError(400, 'AllowedIPs نامعتبر است.');
    n.allowedIps = a;
  }
  if (b.extIface !== undefined) {
    const x = String(b.extIface).trim();
    if (x && !/^[a-zA-Z0-9_.:-]{1,15}$/.test(x)) throw new ApiError(400, 'نام کارت شبکهٔ خروجی نامعتبر است.');
    n.extIface = x;
  }
  if (b.usePsk !== undefined) n.usePsk = !!b.usePsk;
  if (b.defaultQuotaGB !== undefined) n.defaultQuotaGB = num(b.defaultQuotaGB, 0, 0, 100000, 'حجم پیش‌فرض');
  if (b.defaultExpiryDays !== undefined) n.defaultExpiryDays = Math.floor(num(b.defaultExpiryDays, 0, 0, 3650, 'اعتبار پیش‌فرض'));
  if (b.monthlyReset !== undefined) n.monthlyReset = !!b.monthlyReset;

  let reassigned = false;
  if (n.subnet !== cur.subnet) {
    const net = parseCidr(n.subnet);
    if (db.clients.length > net.size - 3) throw new ApiError(400, 'زیرشبکهٔ جدید برای تعداد کاربران فعلی کوچک است.');
    db.settings = n;
    db.clients.forEach((c, i) => { c.address = int2ip(net.base + 2 + i); });
    reassigned = true;
  }
  const needsRestart = NAT_KEYS.some((k) => n[k] !== cur[k]);
  db.settings = n;
  log('تنظیمات ذخیره شد' + (reassigned ? ' (آدرس‌های کاربران بازتخصیص شد؛ کانفیگ‌ها را دوباره بگیرید)' : ''));
  saveNow();
  await applyConfig(needsRestart);
  return { ok: true, needsRestart, reassigned };
});

route('POST', '/api/server/restart', async () => {
  await applyConfig(true);
  if (state.lastError) throw new ApiError(500, state.lastError);
  return { ok: true };
});

route('POST', '/api/server/detect-ip', async () => {
  const ip = await fetchPublicIp();
  if (!ip) throw new ApiError(502, 'تشخیص IP عمومی ممکن نشد.');
  return { ip };
});

/* logs + backup */
route('GET', '/api/logs', async () => db.logs);
route('DELETE', '/api/logs', async () => { db.logs = []; save(); return { ok: true }; });

route('GET', '/api/backup', async (ctx) => {
  ctx.res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Disposition': 'attachment; filename="wg-panel-backup-' + new Date().toISOString().slice(0, 10) + '.json"',
    'Cache-Control': 'no-store',
  });
  ctx.res.end(JSON.stringify({ format: 'wg-panel-backup', version: 1, settings: db.settings, server: db.server, clients: db.clients }, null, 2));
});

route('POST', '/api/restore', async (ctx) => {
  const b = ctx.body || {};
  if (b.format !== 'wg-panel-backup' || !b.server || !b.server.privateKey || !b.server.publicKey || !Array.isArray(b.clients)) {
    throw new ApiError(400, 'فایل پشتیبان معتبر نیست.');
  }
  const settings = Object.assign(defaultSettings(), b.settings || {});
  if (!parseCidr(settings.subnet)) throw new ApiError(400, 'زیرشبکهٔ فایل پشتیبان نامعتبر است.');
  for (const c of b.clients) {
    if (!c || typeof c.publicKey !== 'string' || typeof c.privateKey !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(c.address || '')) {
      throw new ApiError(400, 'اطلاعات کاربران در فایل پشتیبان معتبر نیست.');
    }
  }
  db.settings = settings;
  db.server = { privateKey: b.server.privateKey, publicKey: b.server.publicKey };
  db.clients = b.clients.map((c) => Object.assign({
    id: crypto.randomUUID(), name: 'client', note: '', presharedKey: '', enabled: true, disabledReason: null,
    quotaBytes: 0, usedRx: 0, usedTx: 0, lastRx: 0, lastTx: 0, expiresAt: null, createdAt: Date.now(),
    lastHandshake: 0, lastEndpoint: '', token: crypto.randomBytes(18).toString('base64url'),
  }, c, { lastRx: 0, lastTx: 0 }));
  log('پشتیبان بازیابی شد (' + db.clients.length + ' کاربر)');
  saveNow();
  await applyConfig(true);
  return { ok: true, count: db.clients.length };
});

/* public user page */
function findByToken(t) { return db.clients.find((c) => c.token === t); }

route('GET', '/c/([A-Za-z0-9_-]{20,40})', async (ctx) => {
  const c = findByToken(ctx.params[0]);
  if (!c) throw new ApiError(404, 'لینک نامعتبر است.');
  let conf = '';
  try { conf = clientConfig(c); } catch (e) { conf = ''; }
  const svg = conf ? await qrSvg(conf) : null;
  const used = c.usedRx + c.usedTx;
  const pct = c.quotaBytes > 0 ? Math.min(100, Math.round((used / c.quotaBytes) * 100)) : 0;
  let status = 'فعال', cls = 'ok';
  if (!c.enabled) { status = c.disabledReason === 'quota' ? 'اتمام حجم' : c.disabledReason === 'expired' ? 'منقضی شده' : 'غیرفعال'; cls = 'bad'; }
  const html = '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">' +
    '<title>' + esc(c.name) + '</title><link rel="stylesheet" href="/style.css"></head><body class="userpage">' +
    '<main class="ucard"><h1>' + esc(c.name) + '</h1>' +
    '<p><span class="badge ' + cls + '">' + status + '</span></p>' +
    '<div class="bar"><i style="width:' + pct + '%"></i></div>' +
    '<p class="muted">مصرف: <b>' + fmtBytes(used) + '</b> از <b>' + (c.quotaBytes > 0 ? fmtBytes(c.quotaBytes) : 'نامحدود') + '</b></p>' +
    '<p class="muted">انقضا: <b>' + (c.expiresAt ? fmtDate(c.expiresAt) : 'نامحدود') + '</b></p>' +
    (svg ? '<div class="qr">' + svg + '</div>' : '') +
    (conf ? '<p><a class="btn primary" href="/c/' + esc(c.token) + '/config">دانلود فایل کانفیگ</a> ' +
      '<button class="btn" id="copybtn" type="button">کپی کانفیگ</button></p>' +
      '<pre id="conf" class="conf">' + esc(conf) + '</pre><script src="/user.js"></script>' : '<p class="muted">کانفیگ در دسترس نیست.</p>') +
    '</main></body></html>';
  ctx.res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  ctx.res.end(html);
}, { auth: false });

route('GET', '/c/([A-Za-z0-9_-]{20,40})/config', async (ctx) => {
  const c = findByToken(ctx.params[0]);
  if (!c) throw new ApiError(404, 'لینک نامعتبر است.');
  sendConfig(ctx.res, c);
}, { auth: false });

/* ----------------------------------------------------------- http server */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 5 * 1024 * 1024) { reject(new ApiError(413, 'حجم درخواست زیاد است.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(new ApiError(400, 'JSON نامعتبر است.')); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  if (res.headersSent || res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

const EMBED = {"/user.js": "(function () {\n  var b = document.getElementById('copybtn'), p = document.getElementById('conf');\n  if (!b || !p) return;\n  b.addEventListener('click', function () {\n    var t = p.textContent;\n    function done() { b.textContent = '\u06a9\u067e\u06cc \u0634\u062f \u2713'; setTimeout(function () { b.textContent = '\u06a9\u067e\u06cc \u06a9\u0627\u0646\u0641\u06cc\u06af'; }, 2000); }\n    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(t).then(done); return; }\n    var ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select();\n    try { document.execCommand('copy'); done(); } catch (e) {}\n    ta.remove();\n  });\n})();\n", "/app.js": "'use strict';\n(function () {\n  const $ = (s, r) => (r || document).querySelector(s);\n  const view = $('#view');\n  let page = 'dashboard';\n  let timer = null;\n  let dash = null;\n  let modalOpen = false;\n\n  const esc = (s) => String(s == null ? '' : s).replace(/[&<>\"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]));\n  const GB = 1024 * 1024 * 1024;\n  function fmtBytes(n) {\n    n = Number(n) || 0;\n    const u = ['B', 'KB', 'MB', 'GB', 'TB'];\n    let i = 0;\n    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }\n    return (i === 0 ? n.toFixed(0) : n.toFixed(2)) + ' ' + u[i];\n  }\n  function fmtDate(ts) { return ts ? new Date(ts).toLocaleDateString('fa-IR') : '\u0646\u0627\u0645\u062d\u062f\u0648\u062f'; }\n  function fmtDateTime(ts) { return ts ? new Date(ts).toLocaleString('fa-IR') : '\u2014'; }\n  function fmtUptime(s) {\n    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);\n    return (d ? d + ' \u0631\u0648\u0632 ' : '') + (h ? h + ' \u0633\u0627\u0639\u062a ' : '') + m + ' \u062f\u0642\u06cc\u0642\u0647';\n  }\n  function ago(ts) {\n    if (!ts) return '\u0647\u0631\u06af\u0632';\n    const s = Math.floor((Date.now() - ts) / 1000);\n    if (s < 60) return '\u0686\u0646\u062f \u062b\u0627\u0646\u06cc\u0647 \u067e\u06cc\u0634';\n    if (s < 3600) return Math.floor(s / 60) + ' \u062f\u0642\u06cc\u0642\u0647 \u067e\u06cc\u0634';\n    if (s < 86400) return Math.floor(s / 3600) + ' \u0633\u0627\u0639\u062a \u067e\u06cc\u0634';\n    return Math.floor(s / 86400) + ' \u0631\u0648\u0632 \u067e\u06cc\u0634';\n  }\n\n  function toast(msg, kind) {\n    const el = document.createElement('div');\n    el.className = kind || '';\n    el.textContent = msg;\n    $('#toast').appendChild(el);\n    setTimeout(() => el.remove(), 3500);\n  }\n\n  async function api(method, url, body) {\n    const opt = { method, credentials: 'same-origin', headers: { 'X-Requested-With': 'panel' } };\n    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }\n    let r;\n    try { r = await fetch(url, opt); } catch (e) { throw new Error('\u0627\u0631\u062a\u0628\u0627\u0637 \u0628\u0627 \u0633\u0631\u0648\u0631 \u0628\u0631\u0642\u0631\u0627\u0631 \u0646\u0634\u062f.'); }\n    const ct = r.headers.get('content-type') || '';\n    const data = ct.includes('json') ? await r.json() : await r.text();\n    if (r.status === 401 && url !== '/api/login') { showLogin(); throw new Error('\u0644\u0637\u0641\u0627\u064b \u062f\u0648\u0628\u0627\u0631\u0647 \u0648\u0627\u0631\u062f \u0634\u0648\u06cc\u062f.'); }\n    if (!r.ok) throw new Error((data && data.error) || '\u062e\u0637\u0627 \u062f\u0631 \u0627\u0646\u062c\u0627\u0645 \u0639\u0645\u0644\u06cc\u0627\u062a');\n    return data;\n  }\n  async function act(fn, okMsg) {\n    try { const r = await fn(); if (okMsg) toast(okMsg, 'ok'); return r; } catch (e) { toast(e.message, 'bad'); return null; }\n  }\n\n  function copy(text) {\n    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text).then(() => toast('\u06a9\u067e\u06cc \u0634\u062f', 'ok'));\n    const ta = document.createElement('textarea');\n    ta.value = text; document.body.appendChild(ta); ta.select();\n    try { document.execCommand('copy'); toast('\u06a9\u067e\u06cc \u0634\u062f', 'ok'); } catch (e) { toast('\u06a9\u067e\u06cc \u0645\u0645\u06a9\u0646 \u0646\u0634\u062f', 'bad'); }\n    ta.remove();\n  }\n\n  function modal(html) {\n    modalOpen = true;\n    const bg = document.createElement('div');\n    bg.className = 'modal-bg';\n    bg.innerHTML = '<div class=\"modal\">' + html + '</div>';\n    const close = () => { bg.remove(); modalOpen = false; };\n    bg.addEventListener('mousedown', (e) => { if (e.target === bg) close(); });\n    document.body.appendChild(bg);\n    bg.close = close;\n    bg.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));\n    return bg;\n  }\n\n  /* ---------------------------------------------------------- login */\n  function showLogin() {\n    stopTimer();\n    $('#app').classList.add('hidden');\n    $('#login').classList.remove('hidden');\n  }\n  function showApp() {\n    $('#login').classList.add('hidden');\n    $('#app').classList.remove('hidden');\n    go(page);\n  }\n  $('#loginForm').addEventListener('submit', async (e) => {\n    e.preventDefault();\n    $('#loginErr').textContent = '';\n    try {\n      await api('POST', '/api/login', { username: $('#lu').value.trim(), password: $('#lp').value });\n      $('#lp').value = '';\n      showApp();\n    } catch (err) { $('#loginErr').textContent = err.message; }\n  });\n  $('#logoutBtn').addEventListener('click', async () => { try { await api('POST', '/api/logout', {}); } catch (e) { /* */ } showLogin(); });\n  $('#nav').addEventListener('click', (e) => { const b = e.target.closest('button[data-p]'); if (b) go(b.dataset.p); });\n\n  function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }\n  function go(p) {\n    page = p;\n    document.querySelectorAll('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.p === p));\n    stopTimer();\n    const pages = { dashboard: pDashboard, clients: pClients, settings: pSettings, backup: pBackup, logs: pLogs, account: pAccount };\n    const fn = pages[p];\n    fn();\n    if (p === 'dashboard' || p === 'clients') timer = setInterval(() => { if (!modalOpen) fn(true); }, 10000);\n  }\n\n  /* ------------------------------------------------------ dashboard */\n  async function pDashboard() {\n    try {\n      const d = dash = await api('GET', '/api/dashboard');\n      let alerts = '';\n      if (!d.hasWg) alerts += '<div class=\"alert\">\u062d\u0627\u0644\u062a \u0622\u0632\u0645\u0627\u06cc\u0634\u06cc (Dry-Run): \u0627\u0628\u0632\u0627\u0631 wg \u0646\u0635\u0628 \u0646\u06cc\u0633\u062a \u06cc\u0627 \u067e\u0646\u0644 \u0628\u0627 \u062f\u0633\u062a\u0631\u0633\u06cc root \u0627\u062c\u0631\u0627 \u0646\u0634\u062f\u0647\u061b \u062a\u063a\u06cc\u06cc\u0631\u06cc \u0631\u0648\u06cc \u0633\u06cc\u0633\u062a\u0645 \u0627\u0639\u0645\u0627\u0644 \u0646\u0645\u06cc\u200c\u0634\u0648\u062f. \u0628\u0631\u0627\u06cc \u0627\u062c\u0631\u0627\u06cc \u0648\u0627\u0642\u0639\u06cc \u0627\u0632 install.sh \u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u06a9\u0646\u06cc\u062f.</div>';\n      if (d.hasWg && !d.wgUp) alerts += '<div class=\"alert bad\">\u0627\u06cc\u0646\u062a\u0631\u0641\u06cc\u0633 \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f \u0628\u0627\u0644\u0627 \u0646\u06cc\u0633\u062a. ' + esc(d.lastError || '') + ' \u0627\u0632 \u0628\u062e\u0634 \u062a\u0646\u0638\u06cc\u0645\u0627\u062a \u00ab\u0631\u06cc\u200c\u0627\u0633\u062a\u0627\u0631\u062a \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f\u00bb \u0631\u0627 \u0628\u0632\u0646\u06cc\u062f.</div>';\n      if (!d.endpoint) alerts += '<div class=\"alert\">\u0622\u062f\u0631\u0633 \u0633\u0631\u0648\u0631 (Endpoint) \u0647\u0646\u0648\u0632 \u062a\u0646\u0638\u06cc\u0645 \u0646\u0634\u062f\u0647. \u0627\u0632 \u0628\u062e\u0634 \u062a\u0646\u0638\u06cc\u0645\u0627\u062a \u0622\u0646 \u0631\u0627 \u0648\u0627\u0631\u062f \u06a9\u0646\u06cc\u062f.</div>';\n      view.innerHTML = alerts +\n        '<div class=\"grid stats\">' +\n        stat(d.total, '\u06a9\u0644 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646') + stat(d.online, '\u0622\u0646\u0644\u0627\u06cc\u0646') + stat(d.active, '\u0641\u0639\u0627\u0644') + stat(d.disabled, '\u063a\u06cc\u0631\u0641\u0639\u0627\u0644') + stat(fmtBytes(d.traffic), '\u06a9\u0644 \u062a\u0631\u0627\u0641\u06cc\u06a9 \u0645\u0635\u0631\u0641\u06cc') +\n        '</div><h2>\u0648\u0636\u0639\u06cc\u062a \u0633\u0631\u0648\u0631</h2><div class=\"card\"><table>' +\n        tr('\u0648\u0636\u0639\u06cc\u062a \u0627\u06cc\u0646\u062a\u0631\u0641\u06cc\u0633', d.hasWg ? (d.wgUp ? '<span class=\"badge ok\">\u0628\u0627\u0644\u0627 (' + esc(d.iface) + ')</span>' : '<span class=\"badge bad\">\u067e\u0627\u06cc\u06cc\u0646</span>') : '<span class=\"badge warn\">Dry-Run</span>') +\n        tr('\u0622\u062f\u0631\u0633 \u067e\u0646\u0644', '<span class=\"ltr\">' + esc(d.panelUrl) + '</span>') +\n        tr('Endpoint', '<span class=\"ltr\">' + esc(d.endpoint || '\u2014') + ':' + esc(d.port) + '</span>') +\n        tr('\u06a9\u0644\u06cc\u062f \u0639\u0645\u0648\u0645\u06cc \u0633\u0631\u0648\u0631', '<span class=\"ltr\" style=\"word-break:break-all\">' + esc(d.serverPublicKey) + '</span>') +\n        tr('\u0645\u062f\u062a \u0627\u062c\u0631\u0627\u06cc \u067e\u0646\u0644', fmtUptime(d.uptime)) + tr('\u0646\u0633\u062e\u0647', esc(d.version)) +\n        '</table></div>';\n    } catch (e) { if (!timer) toast(e.message, 'bad'); }\n  }\n  const stat = (v, l) => '<div class=\"card stat\"><b>' + esc(v) + '</b><span>' + l + '</span></div>';\n  const tr = (a, b) => '<tr><td>' + a + '</td><td>' + b + '</td></tr>';\n\n  /* -------------------------------------------------------- clients */\n  let clients = [];\n  let filter = '';\n  async function pClients(silent) {\n    try { clients = await api('GET', '/api/clients'); } catch (e) { if (!silent) toast(e.message, 'bad'); return; }\n    if (!silent || !$('#clist')) {\n      view.innerHTML = '<div class=\"row between\"><h2>\u06a9\u0627\u0631\u0628\u0631\u0627\u0646 / \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627</h2><div class=\"row\">' +\n        '<input id=\"q\" placeholder=\"\u062c\u0633\u062a\u062c\u0648...\" style=\"width:170px\" value=\"' + esc(filter) + '\">' +\n        '<button id=\"addBtn\" class=\"btn primary\">+ \u06a9\u0627\u0631\u0628\u0631 \u062c\u062f\u06cc\u062f</button></div></div><div id=\"clist\" class=\"clist\"></div>';\n      $('#addBtn').onclick = openCreate;\n      $('#q').oninput = (e) => { filter = e.target.value; renderClients(); };\n      $('#clist').addEventListener('click', onClientAction);\n    }\n    renderClients();\n  }\n\n  function renderClients() {\n    const list = clients.filter((c) => !filter || (c.name + ' ' + c.address + ' ' + (c.note || '')).toLowerCase().includes(filter.toLowerCase()));\n    if (!list.length) { $('#clist').innerHTML = '<div class=\"card muted\">' + (clients.length ? '\u0645\u0648\u0631\u062f\u06cc \u067e\u06cc\u062f\u0627 \u0646\u0634\u062f.' : '\u0647\u0646\u0648\u0632 \u06a9\u0627\u0631\u0628\u0631\u06cc \u0633\u0627\u062e\u062a\u0647 \u0646\u0634\u062f\u0647. \u0628\u0627 \u062f\u06a9\u0645\u0647\u0654 \u00ab\u06a9\u0627\u0631\u0628\u0631 \u062c\u062f\u06cc\u062f\u00bb \u0634\u0631\u0648\u0639 \u06a9\u0646\u06cc\u062f.') + '</div>'; return; }\n    $('#clist').innerHTML = list.map(clientCard).join('');\n  }\n\n  function clientCard(c) {\n    const pct = c.quotaBytes > 0 ? Math.min(100, (c.used / c.quotaBytes) * 100) : 0;\n    let badge = '<span class=\"badge ok\">\u0641\u0639\u0627\u0644</span>';\n    if (!c.enabled) {\n      const t = c.disabledReason === 'quota' ? '\u0627\u062a\u0645\u0627\u0645 \u062d\u062c\u0645' : c.disabledReason === 'expired' ? '\u0645\u0646\u0642\u0636\u06cc' : '\u063a\u06cc\u0631\u0641\u0639\u0627\u0644';\n      badge = '<span class=\"badge bad\">' + t + '</span>';\n    }\n    const exp = c.expiresAt ? Math.ceil((c.expiresAt - Date.now()) / 86400000) : null;\n    const expTxt = c.expiresAt ? fmtDate(c.expiresAt) + (exp > 0 ? ' (' + exp + ' \u0631\u0648\u0632 \u0645\u0627\u0646\u062f\u0647)' : '') : '\u0646\u0627\u0645\u062d\u062f\u0648\u062f';\n    return '<div class=\"card client\" data-id=\"' + c.id + '\">' +\n      '<div class=\"head\"><div class=\"name\"><span class=\"dot ' + (c.online ? 'on' : '') + '\"></span>' + esc(c.name) + '</div><div>' + badge + '</div></div>' +\n      '<div class=\"muted ltr\">' + esc(c.address) + (c.note ? ' &nbsp;\u00b7&nbsp; <span style=\"unicode-bidi:plaintext\">' + esc(c.note) + '</span>' : '') + '</div>' +\n      '<div class=\"bar\"><i class=\"' + (pct > 90 ? 'hot' : '') + '\" style=\"width:' + pct + '%\"></i></div>' +\n      '<div class=\"row between muted\" style=\"font-size:13px\"><span>\u0645\u0635\u0631\u0641: ' + fmtBytes(c.used) + ' / ' + (c.quotaBytes > 0 ? fmtBytes(c.quotaBytes) : '\u0646\u0627\u0645\u062d\u062f\u0648\u062f') + '</span>' +\n      '<span>\u2191 ' + fmtBytes(c.usedRx) + ' \u2193 ' + fmtBytes(c.usedTx) + '</span></div>' +\n      '<div class=\"muted\" style=\"font-size:13px\">\u0627\u0646\u0642\u0636\u0627: ' + expTxt + ' \u00b7 \u0622\u062e\u0631\u06cc\u0646 \u0627\u062a\u0635\u0627\u0644: ' + ago(c.lastHandshake) + '</div>' +\n      '<div class=\"acts\">' +\n      '<button class=\"btn small primary\" data-a=\"qr\">QR / \u06a9\u0627\u0646\u0641\u06cc\u06af</button>' +\n      '<button class=\"btn small\" data-a=\"link\">\u0644\u06cc\u0646\u06a9 \u0627\u0634\u062a\u0631\u0627\u06a9</button>' +\n      '<button class=\"btn small\" data-a=\"edit\">\u0648\u06cc\u0631\u0627\u06cc\u0634</button>' +\n      '<button class=\"btn small\" data-a=\"toggle\">' + (c.enabled ? '\u063a\u06cc\u0631\u0641\u0639\u0627\u0644\u200c\u0633\u0627\u0632\u06cc' : '\u0641\u0639\u0627\u0644\u200c\u0633\u0627\u0632\u06cc') + '</button>' +\n      '<button class=\"btn small\" data-a=\"reset\">\u0631\u06cc\u0633\u062a \u062d\u062c\u0645</button>' +\n      '<button class=\"btn small danger\" data-a=\"del\">\u062d\u0630\u0641</button></div></div>';\n  }\n\n  async function onClientAction(e) {\n    const b = e.target.closest('button[data-a]');\n    if (!b) return;\n    const id = b.closest('.client').dataset.id;\n    const c = clients.find((x) => x.id === id);\n    const a = b.dataset.a;\n    if (a === 'qr') return openQr(c);\n    if (a === 'link') {\n      const base = (dash && dash.panelUrl) || location.origin;\n      return copy((base || location.origin) + '/c/' + c.token);\n    }\n    if (a === 'edit') return openEdit(c);\n    if (a === 'toggle') { if (await act(() => api('PATCH', '/api/clients/' + id, { enabled: !c.enabled }), c.enabled ? '\u063a\u06cc\u0631\u0641\u0639\u0627\u0644 \u0634\u062f' : '\u0641\u0639\u0627\u0644 \u0634\u062f')) pClients(true); return; }\n    if (a === 'reset') { if (!confirm('\u0645\u0635\u0631\u0641 \u00ab' + c.name + '\u00bb \u0635\u0641\u0631 \u0634\u0648\u062f\u061f')) return; if (await act(() => api('POST', '/api/clients/' + id + '/reset', {}), '\u0645\u0635\u0631\u0641 \u0631\u06cc\u0633\u062a \u0634\u062f')) pClients(true); return; }\n    if (a === 'del') { if (!confirm('\u06a9\u0627\u0631\u0628\u0631 \u00ab' + c.name + '\u00bb \u0628\u0631\u0627\u06cc \u0647\u0645\u06cc\u0634\u0647 \u062d\u0630\u0641 \u0634\u0648\u062f\u061f')) return; if (await act(() => api('DELETE', '/api/clients/' + id), '\u062d\u0630\u0641 \u0634\u062f')) pClients(true); }\n  }\n\n  async function ensureDash() { if (!dash) { try { dash = await api('GET', '/api/dashboard'); } catch (e) { /* */ } } }\n\n  async function openCreate() {\n    let s = {};\n    try { s = await api('GET', '/api/settings'); } catch (e) { /* */ }\n    const m = modal('<h3>\u06a9\u0627\u0631\u0628\u0631 \u062c\u062f\u06cc\u062f</h3>' +\n      '<label>\u0646\u0627\u0645</label><input id=\"cn\" maxlength=\"40\" placeholder=\"\u0645\u062b\u0644\u0627\u064b ali\">' +\n      '<div class=\"two\"><div><label>\u062d\u062c\u0645 (\u06af\u06cc\u06af\u0627\u0628\u0627\u06cc\u062a\u060c \u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f)</label><input id=\"cq\" type=\"number\" min=\"0\" step=\"any\" value=\"' + (s.defaultQuotaGB || 0) + '\"></div>' +\n      '<div><label>\u0645\u062f\u062a \u0627\u0639\u062a\u0628\u0627\u0631 (\u0631\u0648\u0632\u060c \u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f)</label><input id=\"cd\" type=\"number\" min=\"0\" step=\"1\" value=\"' + (s.defaultExpiryDays || 0) + '\"></div></div>' +\n      '<div class=\"two\"><div><label>\u062a\u0639\u062f\u0627\u062f (\u0633\u0627\u062e\u062a \u06af\u0631\u0648\u0647\u06cc)</label><input id=\"cc\" type=\"number\" min=\"1\" max=\"100\" value=\"1\"></div>' +\n      '<div><label>\u06cc\u0627\u062f\u062f\u0627\u0634\u062a</label><input id=\"cnote\" maxlength=\"200\"></div></div>' +\n      '<p id=\"cerr\" class=\"err\"></p><div class=\"row\"><button id=\"csave\" class=\"btn primary\">\u0633\u0627\u062e\u062a</button><button class=\"btn\" data-close>\u0627\u0646\u0635\u0631\u0627\u0641</button></div>');\n    $('#cn', m).focus();\n    $('#csave', m).onclick = async () => {\n      try {\n        await api('POST', '/api/clients', { name: $('#cn', m).value, quotaGB: $('#cq', m).value, expiryDays: $('#cd', m).value, count: $('#cc', m).value, note: $('#cnote', m).value });\n        m.close(); toast('\u0633\u0627\u062e\u062a\u0647 \u0634\u062f', 'ok'); pClients(true);\n      } catch (e) { $('#cerr', m).textContent = e.message; }\n    };\n  }\n\n  function openEdit(c) {\n    const expVal = c.expiresAt ? new Date(c.expiresAt).toISOString().slice(0, 10) : '';\n    const m = modal('<h3>\u0648\u06cc\u0631\u0627\u06cc\u0634 \u00ab' + esc(c.name) + '\u00bb</h3>' +\n      '<label>\u0646\u0627\u0645</label><input id=\"en\" maxlength=\"40\" value=\"' + esc(c.name) + '\">' +\n      '<div class=\"two\"><div><label>\u062d\u062c\u0645 (\u06af\u06cc\u06af\u0627\u0628\u0627\u06cc\u062a\u060c \u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f)</label><input id=\"eq\" type=\"number\" min=\"0\" step=\"any\" value=\"' + (c.quotaBytes / GB) + '\"></div>' +\n      '<div><label>\u062a\u0627\u0631\u06cc\u062e \u0627\u0646\u0642\u0636\u0627 (\u062e\u0627\u0644\u06cc = \u0646\u0627\u0645\u062d\u062f\u0648\u062f)</label><input id=\"ee\" type=\"date\" value=\"' + expVal + '\"></div></div>' +\n      '<div class=\"row\" style=\"margin-top:6px\"><button class=\"btn small\" data-x=\"7\">+\u06f7 \u0631\u0648\u0632</button><button class=\"btn small\" data-x=\"30\">+\u06f3\u06f0 \u0631\u0648\u0632</button><button class=\"btn small\" data-g=\"10\">+\u06f1\u06f0 \u06af\u06cc\u06af</button><button class=\"btn small\" data-g=\"50\">+\u06f5\u06f0 \u06af\u06cc\u06af</button></div>' +\n      '<label>\u06cc\u0627\u062f\u062f\u0627\u0634\u062a</label><input id=\"eno\" maxlength=\"200\" value=\"' + esc(c.note || '') + '\">' +\n      '<p id=\"eerr\" class=\"err\"></p><div class=\"row\"><button id=\"esave\" class=\"btn primary\">\u0630\u062e\u06cc\u0631\u0647</button><button id=\"eregen\" class=\"btn danger\">\u0633\u0627\u062e\u062a \u06a9\u0644\u06cc\u062f \u062c\u062f\u06cc\u062f</button><button class=\"btn\" data-close>\u0627\u0646\u0635\u0631\u0627\u0641</button></div>');\n    m.querySelectorAll('[data-x]').forEach((b) => b.onclick = () => {\n      const cur = $('#ee', m).value ? new Date($('#ee', m).value + 'T23:59:59').getTime() : Date.now();\n      const base = Math.max(cur, Date.now());\n      $('#ee', m).value = new Date(base + Number(b.dataset.x) * 86400000).toISOString().slice(0, 10);\n    });\n    m.querySelectorAll('[data-g]').forEach((b) => b.onclick = () => { $('#eq', m).value = (Number($('#eq', m).value || 0) + Number(b.dataset.g)).toString(); });\n    $('#esave', m).onclick = async () => {\n      const ev = $('#ee', m).value;\n      try {\n        await api('PATCH', '/api/clients/' + c.id, {\n          name: $('#en', m).value, note: $('#eno', m).value, quotaGB: $('#eq', m).value || 0,\n          expiresAt: ev ? new Date(ev + 'T23:59:59').getTime() : null,\n        });\n        m.close(); toast('\u0630\u062e\u06cc\u0631\u0647 \u0634\u062f', 'ok'); pClients(true);\n      } catch (e) { $('#eerr', m).textContent = e.message; }\n    };\n    $('#eregen', m).onclick = async () => {\n      if (!confirm('\u06a9\u0644\u06cc\u062f\u0647\u0627 \u0639\u0648\u0636 \u0645\u06cc\u200c\u0634\u0648\u062f \u0648 \u06a9\u0627\u0646\u0641\u06cc\u06af \u0642\u0628\u0644\u06cc \u0627\u0632 \u06a9\u0627\u0631 \u0645\u06cc\u200c\u0627\u0641\u062a\u062f. \u0627\u062f\u0627\u0645\u0647 \u0645\u06cc\u200c\u062f\u0647\u06cc\u062f\u061f')) return;\n      if (await act(() => api('POST', '/api/clients/' + c.id + '/regenerate', {}), '\u06a9\u0644\u06cc\u062f \u062c\u062f\u06cc\u062f \u0633\u0627\u062e\u062a\u0647 \u0634\u062f')) { m.close(); pClients(true); }\n    };\n  }\n\n  async function openQr(c) {\n    await ensureDash();\n    let conf = '';\n    try { conf = (await api('GET', '/api/clients/' + c.id + '/text')).config; } catch (e) { return toast(e.message, 'bad'); }\n    const hasQr = dash && dash.hasQr;\n    const m = modal('<h3>' + esc(c.name) + '</h3>' +\n      (hasQr ? '<div class=\"qr\"><img alt=\"QR\" src=\"/api/clients/' + c.id + '/qr?t=' + Date.now() + '\"></div>' : '<p class=\"muted\">\u0628\u0631\u0627\u06cc \u0646\u0645\u0627\u06cc\u0634 QR\u060c \u0645\u0627\u0698\u0648\u0644 qrcode \u0644\u0627\u0632\u0645 \u0627\u0633\u062a (npm install).</p>') +\n      '<pre class=\"conf\">' + esc(conf) + '</pre>' +\n      '<div class=\"row\"><a class=\"btn primary\" href=\"/api/clients/' + c.id + '/config\">\u062f\u0627\u0646\u0644\u0648\u062f .conf</a><button id=\"qcopy\" class=\"btn\">\u06a9\u067e\u06cc</button><button class=\"btn\" data-close>\u0628\u0633\u062a\u0646</button></div>');\n    $('#qcopy', m).onclick = () => copy(conf);\n  }\n\n  /* ------------------------------------------------------- settings */\n  async function pSettings() {\n    let s;\n    try { s = await api('GET', '/api/settings'); } catch (e) { return toast(e.message, 'bad'); }\n    const f = (id, label, val, extra) => '<div><label>' + label + '</label><input id=\"' + id + '\" value=\"' + esc(val) + '\" ' + (extra || '') + '></div>';\n    view.innerHTML = '<h2>\u062a\u0646\u0638\u06cc\u0645\u0627\u062a</h2><div class=\"card\">' +\n      '<h3>\u0622\u062f\u0631\u0633\u200c\u0647\u0627</h3><div class=\"two\">' +\n      f('s_panelUrl', '\u0622\u062f\u0631\u0633 \u067e\u0646\u0644', s.panelUrl, 'class=\"ltr\" placeholder=\"https://cloud.stackdome.com\"') +\n      '<div><label>\u0622\u062f\u0631\u0633 \u0633\u0631\u0648\u0631 \u0628\u0631\u0627\u06cc \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627 (Endpoint: IP \u06cc\u0627 \u062f\u0627\u0645\u0646\u0647)</label><div class=\"row\" style=\"flex-wrap:nowrap\"><input id=\"s_endpoint\" class=\"ltr\" value=\"' + esc(s.endpoint) + '\"><button id=\"detect\" class=\"btn small\" type=\"button\">\u062a\u0634\u062e\u06cc\u0635 IP</button></div></div>' +\n      f('s_listenPort', '\u067e\u0648\u0631\u062a UDP \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f', s.listenPort, 'type=\"number\" min=\"1\" max=\"65535\"') +\n      f('s_interface', '\u0646\u0627\u0645 \u0627\u06cc\u0646\u062a\u0631\u0641\u06cc\u0633', s.interface, 'class=\"ltr\"') +\n      f('s_subnet', '\u0632\u06cc\u0631\u0634\u0628\u06a9\u0647\u0654 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646', s.subnet, 'class=\"ltr\"') +\n      f('s_extIface', '\u06a9\u0627\u0631\u062a \u0634\u0628\u06a9\u0647\u0654 \u062e\u0631\u0648\u062c\u06cc \u0628\u0631\u0627\u06cc NAT (\u062e\u0627\u0644\u06cc = \u062e\u0648\u062f\u06a9\u0627\u0631' + (s.detectedExt ? ': ' + esc(s.detectedExt) : '') + ')', s.extIface, 'class=\"ltr\"') +\n      '</div><h3 style=\"margin-top:18px\">\u06a9\u0627\u0646\u0641\u06cc\u06af \u06a9\u0627\u0631\u0628\u0631\u0627\u0646</h3><div class=\"two\">' +\n      f('s_dns', 'DNS', s.dns, 'class=\"ltr\"') +\n      f('s_allowedIps', 'AllowedIPs', s.allowedIps, 'class=\"ltr\"') +\n      f('s_mtu', 'MTU', s.mtu, 'type=\"number\"') +\n      f('s_keepalive', 'PersistentKeepalive (\u062b\u0627\u0646\u06cc\u0647)', s.keepalive, 'type=\"number\"') +\n      '</div><h3 style=\"margin-top:18px\">\u067e\u06cc\u0634\u200c\u0641\u0631\u0636 \u06a9\u0627\u0631\u0628\u0631 \u062c\u062f\u06cc\u062f</h3><div class=\"two\">' +\n      f('s_defaultQuotaGB', '\u062d\u062c\u0645 \u067e\u06cc\u0634\u200c\u0641\u0631\u0636 (\u06af\u06cc\u06af\u0627\u0628\u0627\u06cc\u062a\u060c \u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f)', s.defaultQuotaGB, 'type=\"number\" min=\"0\" step=\"any\"') +\n      f('s_defaultExpiryDays', '\u0627\u0639\u062a\u0628\u0627\u0631 \u067e\u06cc\u0634\u200c\u0641\u0631\u0636 (\u0631\u0648\u0632\u060c \u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f)', s.defaultExpiryDays, 'type=\"number\" min=\"0\"') +\n      '</div>' +\n      '<div class=\"toggle\"><input type=\"checkbox\" id=\"s_usePsk\"' + (s.usePsk ? ' checked' : '') + '><label for=\"s_usePsk\">\u0627\u0633\u062a\u0641\u0627\u062f\u0647 \u0627\u0632 PresharedKey \u0628\u0631\u0627\u06cc \u06a9\u0627\u0631\u0628\u0631\u0627\u0646 \u062c\u062f\u06cc\u062f (\u0627\u0645\u0646\u06cc\u062a \u0628\u06cc\u0634\u062a\u0631)</label></div>' +\n      '<div class=\"toggle\"><input type=\"checkbox\" id=\"s_monthlyReset\"' + (s.monthlyReset ? ' checked' : '') + '><label for=\"s_monthlyReset\">\u0631\u06cc\u0633\u062a \u062e\u0648\u062f\u06a9\u0627\u0631 \u0645\u0635\u0631\u0641 \u062d\u062c\u0645 \u062f\u0631 \u0627\u0628\u062a\u062f\u0627\u06cc \u0647\u0631 \u0645\u0627\u0647 \u0645\u06cc\u0644\u0627\u062f\u06cc</label></div>' +\n      '<p id=\"serr\" class=\"err\"></p><div class=\"row\"><button id=\"ssave\" class=\"btn primary\">\u0630\u062e\u06cc\u0631\u0647 \u0648 \u0627\u0639\u0645\u0627\u0644</button><button id=\"srestart\" class=\"btn\">\u0631\u06cc\u200c\u0627\u0633\u062a\u0627\u0631\u062a \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f</button></div>' +\n      '<p class=\"muted\" style=\"font-size:13px\">\u062a\u063a\u06cc\u06cc\u0631 \u067e\u0648\u0631\u062a\u060c \u0627\u06cc\u0646\u062a\u0631\u0641\u06cc\u0633\u060c \u0632\u06cc\u0631\u0634\u0628\u06a9\u0647\u060c MTU \u0648 \u06a9\u0627\u0631\u062a \u0634\u0628\u06a9\u0647 \u0628\u0627\u0639\u062b \u0631\u06cc\u200c\u0627\u0633\u062a\u0627\u0631\u062a \u06a9\u0648\u062a\u0627\u0647 \u0627\u06cc\u0646\u062a\u0631\u0641\u06cc\u0633 \u0645\u06cc\u200c\u0634\u0648\u062f. \u062a\u063a\u06cc\u06cc\u0631 \u0632\u06cc\u0631\u0634\u0628\u06a9\u0647 \u0622\u062f\u0631\u0633 \u0647\u0645\u0647\u0654 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646 \u0631\u0627 \u0639\u0648\u0636 \u0645\u06cc\u200c\u06a9\u0646\u062f \u0648 \u0628\u0627\u06cc\u062f \u06a9\u0627\u0646\u0641\u06cc\u06af\u200c\u0647\u0627 \u0631\u0627 \u062f\u0648\u0628\u0627\u0631\u0647 \u0628\u06af\u06cc\u0631\u0646\u062f.</p></div>';\n    $('#detect').onclick = async () => { const r = await act(() => api('POST', '/api/server/detect-ip', {})); if (r) $('#s_endpoint').value = r.ip; };\n    $('#srestart').onclick = () => act(() => api('POST', '/api/server/restart', {}), '\u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f \u0631\u06cc\u200c\u0627\u0633\u062a\u0627\u0631\u062a \u0634\u062f');\n    $('#ssave').onclick = async () => {\n      $('#serr').textContent = '';\n      const g = (k) => $('#s_' + k).value;\n      const body = {\n        panelUrl: g('panelUrl'), endpoint: g('endpoint'), listenPort: g('listenPort'), interface: g('interface'), subnet: g('subnet'),\n        extIface: g('extIface'), dns: g('dns'), allowedIps: g('allowedIps'), mtu: g('mtu'), keepalive: g('keepalive'),\n        defaultQuotaGB: g('defaultQuotaGB'), defaultExpiryDays: g('defaultExpiryDays'),\n        usePsk: $('#s_usePsk').checked, monthlyReset: $('#s_monthlyReset').checked,\n      };\n      try {\n        const r = await api('PUT', '/api/settings', body);\n        dash = null;\n        toast(r.reassigned ? '\u0630\u062e\u06cc\u0631\u0647 \u0634\u062f\u061b \u0622\u062f\u0631\u0633 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646 \u062a\u063a\u06cc\u06cc\u0631 \u06a9\u0631\u062f' : '\u0630\u062e\u06cc\u0631\u0647 \u0648 \u0627\u0639\u0645\u0627\u0644 \u0634\u062f', 'ok');\n      } catch (e) { $('#serr').textContent = e.message; }\n    };\n  }\n\n  /* --------------------------------------------------------- backup */\n  function pBackup() {\n    view.innerHTML = '<h2>\u067e\u0634\u062a\u06cc\u0628\u0627\u0646\u200c\u06af\u06cc\u0631\u06cc</h2><div class=\"card\"><p>\u0641\u0627\u06cc\u0644 \u067e\u0634\u062a\u06cc\u0628\u0627\u0646 \u0634\u0627\u0645\u0644 \u06a9\u0644\u06cc\u062f\u0647\u0627\u06cc \u062e\u0635\u0648\u0635\u06cc \u0633\u0631\u0648\u0631 \u0648 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646 \u0627\u0633\u062a\u061b \u0622\u0646 \u0631\u0627 \u0627\u0645\u0646 \u0646\u06af\u0647 \u062f\u0627\u0631\u06cc\u062f.</p>' +\n      '<div class=\"row\"><a class=\"btn primary\" href=\"/api/backup\">\u062f\u0627\u0646\u0644\u0648\u062f \u067e\u0634\u062a\u06cc\u0628\u0627\u0646</a>' +\n      '<button id=\"rbtn\" class=\"btn\">\u0628\u0627\u0632\u06cc\u0627\u0628\u06cc \u0627\u0632 \u0641\u0627\u06cc\u0644...</button><input id=\"rfile\" type=\"file\" accept=\"application/json,.json\" class=\"hidden\"></div>' +\n      '<p class=\"muted\" style=\"font-size:13px\">\u0628\u0627\u0632\u06cc\u0627\u0628\u06cc\u060c \u0627\u0637\u0644\u0627\u0639\u0627\u062a \u0641\u0639\u0644\u06cc \u0631\u0627 \u062c\u0627\u06cc\u06af\u0632\u06cc\u0646 \u0645\u06cc\u200c\u06a9\u0646\u062f \u0648 \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f \u0631\u06cc\u200c\u0627\u0633\u062a\u0627\u0631\u062a \u0645\u06cc\u200c\u0634\u0648\u062f.</p></div>';\n    $('#rbtn').onclick = () => $('#rfile').click();\n    $('#rfile').onchange = async (e) => {\n      const file = e.target.files[0];\n      if (!file) return;\n      if (!confirm('\u0627\u0637\u0644\u0627\u0639\u0627\u062a \u0641\u0639\u0644\u06cc \u0628\u0627 \u0641\u0627\u06cc\u0644 \u067e\u0634\u062a\u06cc\u0628\u0627\u0646 \u062c\u0627\u06cc\u06af\u0632\u06cc\u0646 \u0634\u0648\u062f\u061f')) return;\n      try {\n        const data = JSON.parse(await file.text());\n        const r = await api('POST', '/api/restore', data);\n        toast('\u0628\u0627\u0632\u06cc\u0627\u0628\u06cc \u0634\u062f (' + r.count + ' \u06a9\u0627\u0631\u0628\u0631)', 'ok');\n      } catch (err) { toast(err.message || '\u0641\u0627\u06cc\u0644 \u0646\u0627\u0645\u0639\u062a\u0628\u0631', 'bad'); }\n      e.target.value = '';\n    };\n  }\n\n  /* ----------------------------------------------------------- logs */\n  async function pLogs() {\n    let logs;\n    try { logs = await api('GET', '/api/logs'); } catch (e) { return toast(e.message, 'bad'); }\n    view.innerHTML = '<div class=\"row between\"><h2>\u06af\u0632\u0627\u0631\u0634\u200c\u0647\u0627</h2><button id=\"clr\" class=\"btn small\">\u067e\u0627\u06a9 \u06a9\u0631\u062f\u0646</button></div><div class=\"card\"><table>' +\n      (logs.length ? logs.map((l) => '<tr><td>' + fmtDateTime(l.t) + '</td><td>' + esc(l.m) + '</td></tr>').join('') : '<tr><td colspan=\"2\" class=\"muted\">\u06af\u0632\u0627\u0631\u0634\u06cc \u0648\u062c\u0648\u062f \u0646\u062f\u0627\u0631\u062f.</td></tr>') + '</table></div>';\n    $('#clr').onclick = async () => { if (await act(() => api('DELETE', '/api/logs'))) pLogs(); };\n  }\n\n  /* -------------------------------------------------------- account */\n  async function pAccount() {\n    let me;\n    try { me = await api('GET', '/api/me'); } catch (e) { return; }\n    view.innerHTML = '<h2>\u062d\u0633\u0627\u0628 \u0645\u062f\u06cc\u0631</h2><div class=\"card\" style=\"max-width:420px\">' +\n      '<label>\u0646\u0627\u0645 \u06a9\u0627\u0631\u0628\u0631\u06cc</label><input id=\"a_u\" class=\"ltr\" value=\"' + esc(me.username) + '\" autocomplete=\"username\">' +\n      '<label>\u0631\u0645\u0632 \u0641\u0639\u0644\u06cc</label><input id=\"a_o\" type=\"password\" autocomplete=\"current-password\">' +\n      '<label>\u0631\u0645\u0632 \u062c\u062f\u06cc\u062f (\u062d\u062f\u0627\u0642\u0644 \u06f8 \u0646\u0648\u06cc\u0633\u0647\u061b \u062e\u0627\u0644\u06cc = \u0628\u062f\u0648\u0646 \u062a\u063a\u06cc\u06cc\u0631)</label><input id=\"a_n\" type=\"password\" autocomplete=\"new-password\">' +\n      '<p id=\"aerr\" class=\"err\"></p><button id=\"asave\" class=\"btn primary\">\u0630\u062e\u06cc\u0631\u0647</button></div>';\n    $('#asave').onclick = async () => {\n      try {\n        await api('POST', '/api/account', { newUsername: $('#a_u').value, oldPassword: $('#a_o').value, newPassword: $('#a_n').value });\n        toast('\u0630\u062e\u06cc\u0631\u0647 \u0634\u062f\u061b \u062f\u0648\u0628\u0627\u0631\u0647 \u0648\u0627\u0631\u062f \u0634\u0648\u06cc\u062f', 'ok');\n        showLogin();\n      } catch (e) { $('#aerr').textContent = e.message; }\n    };\n  }\n\n  /* ----------------------------------------------------------- boot */\n  (async function init() {\n    try { await api('GET', '/api/me'); showApp(); } catch (e) { showLogin(); }\n  })();\n})();\n", "/style.css": ":root{--bg:#0f1420;--card:#171e2e;--card2:#1e2740;--line:#2a3550;--text:#e7ecf7;--muted:#8d9ab8;--pri:#4f8cff;--ok:#2ecc8f;--bad:#ff5d6c;--warn:#f5b942}\n*{box-sizing:border-box}\nhtml,body{margin:0;background:var(--bg);color:var(--text);font-family:Vazirmatn,Tahoma,\"Segoe UI\",system-ui,sans-serif;font-size:15px;line-height:1.7}\n.hidden{display:none!important}\na{color:var(--pri)}\nbutton,input,select,textarea{font:inherit;color:inherit}\ninput,select,textarea{width:100%;background:#0f1626;border:1px solid var(--line);border-radius:10px;padding:9px 12px;outline:none}\ninput:focus,select:focus,textarea:focus{border-color:var(--pri)}\ninput[type=checkbox]{width:auto;accent-color:var(--pri);transform:scale(1.2)}\nlabel{display:block;color:var(--muted);font-size:13px;margin:10px 0 4px}\n.btn{background:var(--card2);border:1px solid var(--line);border-radius:10px;padding:8px 14px;cursor:pointer;text-decoration:none;display:inline-block;transition:.15s}\n.btn:hover{border-color:var(--pri)}\n.btn.primary{background:var(--pri);border-color:var(--pri);color:#fff}\n.btn.danger{color:var(--bad);border-color:#5a2a35}\n.btn.small{padding:4px 10px;font-size:13px}\n.err{color:var(--bad);min-height:1.4em;margin:6px 0 0}\n.muted{color:var(--muted)}\n.ltr{direction:ltr;unicode-bidi:plaintext;text-align:left}\n\n#login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}\n.login-box{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:28px;width:100%;max-width:360px;display:flex;flex-direction:column;gap:12px;text-align:center}\n.login-box .logo{font-size:44px}\n.login-box h1{margin:0 0 6px;font-size:22px}\n\n.top{display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;flex-wrap:wrap}\n.brand{font-weight:700;font-size:17px;white-space:nowrap}\n#nav{display:flex;gap:4px;flex:1;overflow-x:auto}\n#nav button{background:none;border:0;padding:7px 12px;border-radius:9px;cursor:pointer;color:var(--muted);white-space:nowrap}\n#nav button.active{background:var(--card2);color:var(--text)}\nmain{max-width:1100px;margin:0 auto;padding:16px}\n\n.grid{display:grid;gap:12px}\n.stats{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}\n.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}\n.stat b{display:block;font-size:26px}\n.stat span{color:var(--muted);font-size:13px}\nh2{margin:6px 0 12px;font-size:18px}\nh3{margin:0 0 8px;font-size:16px}\n.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\n.row.between{justify-content:space-between}\n.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}\n@media(max-width:600px){.two{grid-template-columns:1fr}}\n\n.badge{display:inline-block;padding:1px 10px;border-radius:99px;font-size:12px;border:1px solid var(--line)}\n.badge.ok{color:var(--ok);border-color:#1e6b50}\n.badge.bad{color:var(--bad);border-color:#6b2a35}\n.badge.warn{color:var(--warn);border-color:#6b5420}\n.badge.on{background:#123b2d;color:var(--ok);border-color:#1e6b50}\n\n.bar{height:8px;background:#0f1626;border-radius:99px;overflow:hidden;margin:6px 0}\n.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--pri),var(--ok));border-radius:99px}\n.bar i.hot{background:linear-gradient(90deg,var(--warn),var(--bad))}\n\n.clist{display:grid;gap:10px}\n.client{display:grid;gap:6px}\n.client .head{display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap}\n.client .name{font-weight:700;font-size:16px}\n.client .acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}\n.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:#4a5470;margin-inline-end:6px}\n.dot.on{background:var(--ok);box-shadow:0 0 6px var(--ok)}\n\n.modal-bg{position:fixed;inset:0;background:#000a;display:flex;align-items:center;justify-content:center;padding:14px;z-index:20}\n.modal{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;width:100%;max-width:480px;max-height:92vh;overflow:auto}\n.modal .qr img,.qr svg{width:100%;max-width:280px;height:auto;background:#fff;border-radius:10px;display:block;margin:8px auto}\npre.conf{direction:ltr;text-align:left;background:#0b1120;border:1px solid var(--line);border-radius:10px;padding:10px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}\n.toggle{display:flex;align-items:center;gap:8px;margin:12px 0}\n.toggle label{margin:0;color:var(--text)}\ntable{width:100%;border-collapse:collapse}\ntd{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}\ntd:first-child{color:var(--muted);white-space:nowrap;width:1%}\n.alert{padding:10px 14px;border-radius:10px;border:1px solid #6b5420;background:#2a2412;color:var(--warn);margin-bottom:12px}\n.alert.bad{border-color:#6b2a35;background:#2a1218;color:var(--bad)}\n\n#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);z-index:50;display:flex;flex-direction:column;gap:8px;align-items:center}\n#toast div{background:#0b1120;border:1px solid var(--line);padding:9px 16px;border-radius:10px;box-shadow:0 4px 20px #0008}\n#toast div.bad{border-color:var(--bad);color:var(--bad)}\n#toast div.ok{border-color:var(--ok)}\n\n/* public user page */\n.userpage{display:flex;justify-content:center;padding:16px}\n.ucard{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px;width:100%;max-width:460px;text-align:center}\n.ucard h1{margin:0 0 6px;font-size:22px}\n.ucard .qr svg{max-width:260px}\n.ucard pre.conf{text-align:left}\n", "/favicon.svg": "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\"><rect width=\"64\" height=\"64\" rx=\"14\" fill=\"#0f1420\"/><path d=\"M32 8l20 7v15c0 13-9 22-20 26C21 52 12 43 12 30V15z\" fill=\"#4f8cff\"/><path d=\"M24 31l6 6 11-13\" fill=\"none\" stroke=\"#fff\" stroke-width=\"5\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>\n", "/index.html": "<!doctype html>\n<html lang=\"fa\" dir=\"rtl\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n  <meta name=\"robots\" content=\"noindex,nofollow\">\n  <meta name=\"theme-color\" content=\"#0f1420\">\n  <title>\u067e\u0646\u0644 \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f</title>\n  <link rel=\"icon\" href=\"/favicon.svg\" type=\"image/svg+xml\">\n  <link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n<body>\n  <div id=\"login\" class=\"hidden\">\n    <form id=\"loginForm\" class=\"login-box\" autocomplete=\"on\">\n      <div class=\"logo\">\ud83d\udee1\ufe0f</div>\n      <h1>\u067e\u0646\u0644 \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f</h1>\n      <input id=\"lu\" name=\"username\" placeholder=\"\u0646\u0627\u0645 \u06a9\u0627\u0631\u0628\u0631\u06cc\" autocomplete=\"username\" required>\n      <input id=\"lp\" name=\"password\" type=\"password\" placeholder=\"\u0631\u0645\u0632 \u0639\u0628\u0648\u0631\" autocomplete=\"current-password\" required>\n      <button class=\"btn primary\" type=\"submit\">\u0648\u0631\u0648\u062f</button>\n      <p id=\"loginErr\" class=\"err\"></p>\n    </form>\n  </div>\n\n  <div id=\"app\" class=\"hidden\">\n    <header class=\"top\">\n      <div class=\"brand\">\ud83d\udee1\ufe0f <span>\u067e\u0646\u0644 \u0648\u0627\u06cc\u0631\u06af\u0627\u0631\u062f</span></div>\n      <nav id=\"nav\">\n        <button data-p=\"dashboard\" class=\"active\">\u062f\u0627\u0634\u0628\u0648\u0631\u062f</button>\n        <button data-p=\"clients\">\u06a9\u0627\u0631\u0628\u0631\u0627\u0646</button>\n        <button data-p=\"settings\">\u062a\u0646\u0638\u06cc\u0645\u0627\u062a</button>\n        <button data-p=\"backup\">\u067e\u0634\u062a\u06cc\u0628\u0627\u0646</button>\n        <button data-p=\"logs\">\u06af\u0632\u0627\u0631\u0634\u200c\u0647\u0627</button>\n        <button data-p=\"account\">\u062d\u0633\u0627\u0628</button>\n      </nav>\n      <button id=\"logoutBtn\" class=\"btn small\">\u062e\u0631\u0648\u062c</button>\n    </header>\n    <main id=\"view\"></main>\n  </div>\n\n  <div id=\"toast\"></div>\n  <script src=\"/app.js\"></script>\n</body>\n</html>\n"};

function serveStatic(req, res, pathname) {
  let p = pathname === '/' ? '/index.html' : pathname;
  if (Object.prototype.hasOwnProperty.call(EMBED, p)) {
    res.writeHead(200, { 'Content-Type': MIME[path.extname(p).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(EMBED[p]);
    return true;
  }
  const full = path.normalize(path.join(PUBLIC_DIR, p));
  if (!full.startsWith(PUBLIC_DIR + path.sep) && full !== PUBLIC_DIR) return false;
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) return false;
  const ext = path.extname(full).toLowerCase();
  res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  fs.createReadStream(full).pipe(res);
  return true;
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; frame-ancestors 'none'");
  try {
    const url = new URL(req.url, 'http://localhost');
    const pathname = decodeURIComponent(url.pathname);
    const method = req.method;

    if (method === 'GET' || method === 'HEAD') {
      const isApi = pathname.startsWith('/api/') || pathname.startsWith('/c/');
      if (!isApi && serveStatic(req, res, pathname)) return;
    }

    let matched = null, params = [];
    for (const r of routes) {
      if (r.method !== method) continue;
      const m = r.re.exec(pathname);
      if (m) { matched = r; params = m.slice(1); break; }
    }
    if (!matched) {
      if (pathname.startsWith('/api/')) throw new ApiError(404, 'مسیر پیدا نشد.');
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not found');
    }

    if (method !== 'GET' && req.headers['x-requested-with'] !== 'panel') throw new ApiError(403, 'درخواست نامعتبر.');
    let user = null;
    if (matched.auth) {
      user = verifyToken(getCookie(req, 'session'));
      if (!user) throw new ApiError(401, 'نیاز به ورود دارید.');
    }
    const body = method === 'GET' || method === 'HEAD' ? {} : await readBody(req);
    const ctx = { req, res, url, params, body, ip: clientIp(req), user };
    const result = await matched.handler(ctx);
    if (!res.headersSent && !res.writableEnded) sendJson(res, 200, result === undefined ? { ok: true } : result);
  } catch (e) {
    const status = e instanceof ApiError ? e.status : 500;
    if (!(e instanceof ApiError)) console.error('[error]', e);
    const wantsHtml = /^\/c\//.test(req.url) && req.method === 'GET';
    if (wantsHtml && !res.headersSent) {
      res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;text-align:center;padding:3rem" dir="rtl">' + esc(e.message) + '</body>');
    }
    sendJson(res, status, { error: e instanceof ApiError ? e.message : 'خطای داخلی سرور' });
  }
});

/* ------------------------------------------------------------------ boot */
async function main() {
  loadDb();
  await detectSystem();
  if (HAS_WG) db.runtime.detectedExt = await detectExtIface();
  if (!db.settings.endpoint) {
    const ip = await fetchPublicIp();
    if (ip) { db.settings.endpoint = ip; log('آدرس سرور به‌صورت خودکار تنظیم شد: ' + ip); }
  }
  saveNow();
  await applyConfig(false);
  await tick();
  setInterval(() => { tick().catch((e) => console.error('[tick]', e.message)); }, 10000);

  server.listen(PORT, HOST, () => console.log('[panel] WG Panel v' + VERSION + ' listening on http://' + HOST + ':' + PORT + (HAS_WG ? '' : '  (DRY-RUN)')));
  const stop = () => { saveNow(); server.close(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

process.on('unhandledRejection', (e) => console.error('[unhandled]', e));
main().catch((e) => { console.error(e); process.exit(1); });
