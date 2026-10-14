'use strict';
const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const zlib   = require('zlib');
const { URL } = require('url');
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
const logger  = require('./logger');
const tillKit = require('./till-kit');   // shop network: what a till needs to trust this relay  // daily error/activity log for troubleshooting
const consoleUi = require('./console-ui');  // timestamps, colours, status block, hotkeys
const activity = require('./activity');     // console lines kept (masked) for Settings > Logs
const logTools = require('./log-tools');    // log retention, date-range export, support bundle zip
if (require.main === module) consoleUi.install(logger.LOG_DIR, { context: activityContext });
else { activity.setDir(logger.LOG_DIR); activity.setContextGetter(activityContext); }
logger.setContextGetter(activityContext);   // error-log entries name their business too
const vault   = require('./vault');   // encrypted per-tenant credential store
const mailer  = require('./mailer');  // outgoing email: password-reset codes and security alerts (Settings > Email)
// Mask the exact vault secrets in the activity log whenever a business is read.
try { vault.setSecretSink(t => activity.noteSecrets([t.efrisPassword, t.efrisPassphrase, t.managerToken])); } catch (_) {}
try { vault.warm(); } catch (_) {}     // unlock the vault key in the background, not on the first request
// Once the vault is unlocked, read every business once so all saved secrets are
// known to the activity masker before anything about them can be logged (not only
// the businesses a request has touched). Retried every few seconds until unlocked.
function learnVaultSecrets() {
  if (!vault.isUnlocked()) return false;
  try { for (const t of vault.listTenants()) { try { vault.getTenant(t.id); } catch (_) { return false; } } } catch (_) { return false; }
  mailer.learn();   // the saved email (SMTP) password too
  return true;
}
if (!learnVaultSecrets()) {
  const _learnTimer = setInterval(() => { if (learnVaultSecrets()) clearInterval(_learnTimer); }, 5000);
  _learnTimer.unref();
}

// ── Redact secrets before anything gets logged ──────────────────
// Scans a request body for known-sensitive field names (wherever they are
// nested - config.efrisPassword, config.efrisKeyPassphrase, a bare
// accessToken, etc.) and strips those exact values out of a string. This
// way logging code never has to know which variable holds a given route's
// secret - it just redacts whatever the request actually contained.
const SECRET_FIELD_NAMES = new Set(['efrispassword','accesstoken','token','apiaccesstoken','efriskeypassphrase','efriskeypassword','password','efriskeypem']);
function collectSecrets(obj, acc, depth) {
  if (!obj || typeof obj !== 'object' || depth > 4) return acc;
  if (!depth) for (const v of activity.secretsIn(obj)) acc.push(v);   // managerToken, aesKey, pwd, ...
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (typeof v === 'string' && v && SECRET_FIELD_NAMES.has(k.toLowerCase())) acc.push(v);
    else if (v && typeof v === 'object') collectSecrets(v, acc, depth + 1);
  }
  return acc;
}
function redactSecrets(str, req) {
  if (!str) return str;
  let out = String(str);
  for (const s of collectSecrets(req && req.body, [], 0)) { if (s && s.length >= 4) out = out.split(s).join('***'); }
  return out;
}

// Log crashes before exiting instead of exiting silently (e.g. a missing
// module can crash the process before any application code runs). Node's
// default for both events is to crash the process - these handlers preserve
// that behavior (so process managers can still restart it) but write a log
// line first, to both today's log file and stderr, before exiting.
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception - process exiting', { message: err && err.message, stack: err && err.stack });
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection - process exiting', { message: reason && reason.message || String(reason), stack: reason && reason.stack });
  process.exit(1);
});

const app  = express();
app.disable('x-powered-by');   // do not announce the server software
// A failing async route (a bad Manager URL, Manager closed mid-request) must answer
// that request with an error, not reach the unhandledRejection handler above and
// stop the relay with its queue timers. Route every handler's rejection to the
// error middleware at the end of this file.
for (const m of ['get', 'post', 'put', 'delete', 'patch']) {
  const orig = app[m].bind(app);
  app[m] = function (route, ...handlers) {
    if (!handlers.length) return orig(route);   // app.get('setting')
    return orig(route, ...handlers.map(h => (typeof h === 'function' && h.length < 4)
      ? function (req, res, next) { try { const r = h(req, res, next); if (r && typeof r.catch === 'function') r.catch(next); } catch (e) { next(e); } }
      : h));
  };
}
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT, 10) || 5443;   // override for a second copy (tests, scans)
// Which interface to bind. Default 127.0.0.1 (loopback ONLY): the common case is a
// single-machine install where Manager, the relay, and the
// browser are all local - binding loopback avoids the Windows Firewall prompt and
// never exposes the relay (or the API key it serves) on the network.
// Server/LAN/cloud installs that must be reachable from OTHER machines set
// BIND_HOST=0.0.0.0 (the cloud/container-host workflow does this; LAN admins set it too).
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';

// Set true once the HTTPS listener (5443) is up. When it is, there is ONE canonical
// URL - https://<host>:5443 - and any human who opens the old http://<host>:3000 in
// a browser is redirected there. Programmatic/API callers on 3000 keep working, and
// when there is no cert yet 3000 still serves the full app so first-run isn't broken.
let httpsUp = false;

// Only trust X-Forwarded-For from a reverse proxy on this machine (e.g. a local
// tunnel). Trusting every hop lets any caller fake its IP past the rate limiter.
// A proxy on another host can be named with TRUST_PROXY (Express syntax).
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');

// Which browser origins may call the relay and frame the extension. Manager
// Desktop and the relay itself run on loopback, so loopback origins (any port)
// are always allowed. Add others (e.g. a cloud Manager) with ALLOWED_ORIGINS,
// comma separated: ALLOWED_ORIGINS=https://manager.example.com
const LOOPBACK_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|::1)$/i;
const EXTRA_HOSTS = String(process.env.ALLOWED_HOSTS || '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
// Shop network (LAN) mode (LAN_MODE=1, set by the launcher): tills open Manager
// Server Edition in a browser at http(s)://<server name or IP>:<Manager port>, so
// those origins may frame the extension and talk to the relay. The names are the
// ALLOWED_HOSTS the launcher built (hostname, hostname.local, private IPv4s); the
// ports are MANAGER_PORTS (default 5000, Manager Server's default). MANAGER_ORIGINS
// adds any other Manager origin (comma separated), in or out of LAN mode.
const LAN_MODE = /^(1|true|yes|on)$/i.test(String(process.env.LAN_MODE || ''));
const bracketHost = h => (h.includes(':') ? '[' + h + ']' : h);
const remoteHost = h => !!h && !LOOPBACK_HOST.test(h) && h !== '0.0.0.0';
function lanManagerOrigins(hosts, ports) {
  const out = [];
  for (const h of (hosts || []).filter(remoteHost)) for (const p of ports || []) for (const proto of ['http', 'https']) out.push(proto + '://' + bracketHost(h) + ':' + p);
  return out;
}
function managerPorts(v) { return String(v || '5000').split(',').map(p => p.trim()).filter(p => /^\d{1,5}$/.test(p) && +p > 0 && +p < 65536); }
// The relay addresses tills use in LAN mode (first = the PC name: the Manager button URL).
function lanRelayUrls(hosts, httpsPort) {
  return (hosts || []).filter(remoteHost).map(h => 'https://' + bracketHost(h) + ':' + httpsPort + '/extension');
}
const MANAGER_PORTS = managerPorts(process.env.MANAGER_PORTS);
// LAN mode: the relay also serves Manager Server over HTTPS (manager-proxy.js) on
// MANAGER_HTTPS_PORT, default Manager's port + 1 (5001). MANAGER_HTTPS_PORT=0 turns it off.
const MANAGER_HTTPS_PORT = (() => {
  if (!LAN_MODE || !MANAGER_PORTS.length) return 0;
  const v = String(process.env.MANAGER_HTTPS_PORT || '').trim();
  if (v === '0') return 0;
  const n = parseInt(v, 10);
  return (n > 0 && n < 65536) ? n : (+MANAGER_PORTS[0] + 1);
})();
const EXTRA_ORIGINS = [...new Set(String(process.env.ALLOWED_ORIGINS || '').split(',')
  .concat(String(process.env.MANAGER_ORIGINS || '').split(','))
  .map(o => o.trim().replace(/\/+$/, '')).filter(Boolean)
  .concat(LAN_MODE ? lanManagerOrigins(EXTRA_HOSTS, MANAGER_HTTPS_PORT ? MANAGER_PORTS.concat(String(MANAGER_HTTPS_PORT)) : MANAGER_PORTS) : []))];
const LAN_URLS = LAN_MODE ? lanRelayUrls(EXTRA_HOSTS, HTTPS_PORT) : [];
function isAllowedOrigin(origin) {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    if ((u.protocol === 'http:' || u.protocol === 'https:') && LOOPBACK_HOST.test(u.hostname)) return true;
  } catch (_) { return false; }
  return EXTRA_ORIGINS.includes(String(origin).replace(/\/+$/, ''));
}
// No [::1] entries: browsers reject them in frame-ancestors.
const FRAME_ANCESTORS = ["'self'", 'http://localhost:*', 'https://localhost:*', 'http://127.0.0.1:*', 'https://127.0.0.1:*'].concat(EXTRA_ORIGINS).join(' ');

// Host-header allowlist: stops DNS-rebinding pages from reaching the relay under
// their own hostname. Enforced when bound to loopback (the default) or when
// ALLOWED_HOSTS is set; a network/container bind without ALLOWED_HOSTS skips it.
const BIND_IS_LOOPBACK = LOOPBACK_HOST.test(BIND_HOST);
const ENFORCE_HOST = BIND_IS_LOOPBACK || EXTRA_HOSTS.length > 0;
if (!ENFORCE_HOST) console.log('Note: BIND_HOST=' + BIND_HOST + ' without ALLOWED_HOSTS - Host header check is off. Set ALLOWED_HOSTS=<your hostname>.');
app.use((req, res, next) => {
  if (!ENFORCE_HOST) return next();
  const h = String(req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
  if (LOOPBACK_HOST.test(h) || EXTRA_HOSTS.includes(h)) return next();
  res.status(421).type('text/plain').send('Host not allowed');
});

app.use(cors({
  origin: (origin, cb) => cb(null, isAllowedOrigin(origin)),
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-API-KEY','X-Manager-Token','X-Manager-Endpoint','X-Tenant-Id','X-Fx-Key'],
}));
// Only Manager (loopback, or ALLOWED_ORIGINS) and the relay itself may frame our pages.
app.use((req, res, next) => {
  // Everything the pages use comes from the relay itself (scripts, styles, the PDF
  // library) or is inline / data: (QR codes, logos). 'unsafe-inline' stays because
  // the extension uses inline scripts and handlers.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:", "font-src 'self' data:", "connect-src 'self'", "frame-src 'self' blob:",
    "worker-src 'self' blob:", "object-src 'none'", "base-uri 'self'", "form-action 'self'",
    'frame-ancestors ' + FRAME_ANCESTORS,
  ].join('; '));
  // HSTS covers every port of a host name, so on a shop PC it would force the browser
  // onto https for Manager Server (http://PCNAME:5000) too. Send it only behind a
  // proxy with a real domain (TRUST_PROXY), never on a local or shop-network name; max-age=0 clears an earlier one.
  if (req.secure) res.setHeader('Strict-Transport-Security', process.env.TRUST_PROXY ? 'max-age=31536000' : 'max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');   // page URLs can carry the Manager token
  next();
});
app.use(express.json({ limit: '5mb' }));   // cap request bodies to guard against oversized-payload DoS
// Learn the secrets a request carries (body fields named like a password, token or
// key, and the credential headers) before any route can log them, so the activity
// log masks their exact values wherever they show up.
app.use((req, res, next) => {
  try {
    activity.noteBody(req.body);
    activity.noteBody(req.query);
    const h = req.headers || {};
    const hv = [h['x-manager-token'], h['x-api-key'], h['x-fx-key']];
    const m = /^\s*\S+\s+(\S{6,})\s*$/.exec(String(h.authorization || ''));
    if (m) hv.push(m[1]);
    activity.noteSecrets(hv.filter(v => typeof v === 'string'));
  } catch (_) {}
  next();
});

// Published release version, so a user can see which version is running and match
// it against the public repo's tag. Read from the VERSION file, fall back to
// package.json, then 'dev'.
const APP_VERSION = (() => {
  // Try the VERSION file both where it sits in the container (/app/VERSION, copied
  // by the Dockerfile) and where it sits in a source checkout (repo-root/VERSION,
  // one level above backend/). Fall back to package.json, then 'dev'.
  for (const p of [path.join(__dirname, 'VERSION'), path.join(__dirname, '..', 'VERSION')]) {
    try { const v = fs.readFileSync(p, 'utf8').trim(); if (v) return v; } catch (_) {}
  }
  try { return require('./package.json').version || 'dev'; } catch (_) {}
  try { return require('../package.json').version || 'dev'; } catch (_) { return 'dev'; }
})();
app.get('/api/version', (req, res) => res.json({ version: APP_VERSION }));

// Single-URL redirect: once HTTPS is live, bounce plain-HTTP *browser page* loads
// (GET for HTML) from :3000 to https://<host>:5443. Only page navigations are
// redirected - XHR/fetch API calls and non-GET requests are left alone so nothing
// programmatic breaks.
app.use((req, res, next) => {
  if (httpsUp && !req.secure && req.method === 'GET' &&
      String(req.headers.accept || '').includes('text/html')) {
    const host = String(req.headers.host || 'localhost').split(':')[0];
    return res.redirect(302, 'https://' + host + ':' + HTTPS_PORT + req.originalUrl);
  }
  next();
});

// ── Sign-in, roles and business isolation ──
// Every /api request is made by a principal: a signed-in user (Authorization:
// Bearer <session token>, see auth.js) or, only when INTERNAL_API_KEY is set in
// the environment, the "service" principal (X-API-KEY header, for automation:
// tests, scanners, scripts). The pages never carry a key.
const auth = require('./auth');
const { AsyncLocalStorage } = require('async_hooks');
// The principal of the request being handled, so deep helpers (the submission
// log writer) can record who did what without every route passing it down.
const reqCtx = new AsyncLocalStorage();
const SERVICE_KEY = process.env.INTERNAL_API_KEY || '';
const SERVICE_KEY_BUF = Buffer.from(SERVICE_KEY);
activity.noteSecrets(SERVICE_KEY);
// Business and person behind the console line being printed (activity log).
function activityContext() {
  const s = reqCtx.getStore();
  if (!s) return null;
  const u = s.user;
  return { tenantId: s.tenantId || '', user: u ? (u.displayName || u.name || u.id || '') : '' };
}
function serviceKeyOk(v) {
  if (!SERVICE_KEY) return false;
  const b = Buffer.from(String(v || ''));
  return b.length === SERVICE_KEY_BUF.length && crypto.timingSafeEqual(b, SERVICE_KEY_BUF);
}
const SERVICE_PRINCIPAL = Object.freeze({ id: 'service', name: 'service', displayName: 'Service', service: true, owner: true, roles: {} });

// A request made on the relay's own computer: loopback socket, loopback Host, and
// not forwarded by a proxy on this machine (a local tunnel or reverse proxy makes
// remote requests arrive on loopback; they carry X-Forwarded-For). Tests simulate
// another computer by sending X-Forwarded-For.
function isLocalRequest(req) {
  const ra = String((req.socket && req.socket.remoteAddress) || '');
  const sockLocal = ra === '::1' || /^(::ffff:)?127\./.test(ra);
  const host = String(req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
  const hostLocal = LOOPBACK_HOST.test(host);
  const proxied = !!(req.headers['x-forwarded-for'] || req.headers.forwarded || req.headers['x-real-ip'] || req.headers['cf-connecting-ip']);
  return sockLocal && hostLocal && !proxied;
}

// Businesses (vault tenants) a principal may use. Owners and the service: all.
function tenantIdsFor(user) {
  let all = [];
  try { all = vault.listTenants().map(t => t.id); } catch (_) {}
  if (!user) return [];
  if (user.owner || user.service) return all;
  return Object.keys(user.roles || {});
}
// Owners and the service may also name a business not saved yet (the extension
// sends its id while the owner is still filling in its settings); nothing is
// stored for such an id, so there is nothing to reach.
function canUseTenant(user, tid) {
  if (!user || !tid) return false;
  if (user.owner || user.service) return true;
  return !!(user.roles && user.roles[tid]);
}

// ── Route permissions ──
// One line per /api route: [method, path below /api, permission]. 'public' needs
// no sign-in; '' needs any signed-in user (the route checks scope itself); other
// values are permissions from auth.js ROLE_PERMS. A route missing here is
// ADMIN ONLY (deny by default): a new route stays locked until it is listed.
const ROUTE_PERMS = [
  // No sign-in
  ['GET', '/health', 'public'], ['GET', '/version', 'public'],
  ['GET', '/auth/status', 'public'], ['POST', '/auth/setup', 'public'], ['POST', '/auth/login', 'public'], ['POST', '/auth/recover', 'public'],
  ['POST', '/auth/email-code', 'public'],   // answers the same whether or not the account exists
  // Any signed-in user; the route itself limits what each one can do
  ['POST', '/auth/logout', ''], ['POST', '/auth/change-password', ''], ['POST', '/client-log', ''],
  ['GET', '/auth/users', ''], ['POST', '/auth/users', ''], ['POST', '/auth/users/:id', ''], ['POST', '/auth/users/:id/email-code', ''],
  ['POST', '/auth/me', ''],
  ['GET', '/tenant', ''], ['POST', '/tenant', ''], ['DELETE', '/tenant/:id', ''],
  ['GET', '/tenant/:id/profile', ''],   // any role in that business (checked in the route)
  // Cashier: view documents, rates, units
  ['GET', '/manager/invoice', 'view'], ['GET', '/manager/find-doc', 'view'], ['GET', '/manager/invoices', 'view'],
  ['GET', '/receipt-snapshot', 'view'], ['GET', '/connectivity', 'view'], ['GET', '/fx-rates', 'view'], ['GET', '/fx-rate', 'view'],
  ['POST', '/efris/exchange-rate', 'view'], ['POST', '/efris/my-details', 'view'], ['GET', '/units', 'view'], ['GET', '/units/sync-status', 'view'],
  // Cashier: fiscalise and record a sale (the receipt wizard also takes the next
  // number from a series, logs Manager-only receipts and sets the day's FX rate)
  ['POST', '/efris/submit-invoice', 'sell'], ['POST', '/efris/preview-invoice', 'sell'], ['POST', '/manager/create-receipt', 'sell'],
  ['POST', '/efris/save-to-manager', 'sell'], ['POST', '/receipt-snapshot', 'sell'], ['POST', '/manager-only-log', 'sell'],
  ['GET', '/print-count', 'sell'], ['POST', '/print-count', 'sell'],
  ['POST', '/manager/set-exchange-rate', 'sell'], ['GET', '/manager/bank-accounts', 'sell'],
  ['POST', '/receipt-number/next', 'sell'],
  // Goods > My Items, shared by every computer: everyone reads, admins change it.
  ['GET', '/goods-catalog', 'goods-read'], ['PUT', '/goods-catalog', 'admin'],
  ['GET', '/number-series', 'sell'], ['POST', '/number-series/:id/next', 'sell'], ['POST', '/number-series/:id/preview', 'sell'],
  // Cashier: customers
  ['POST', '/manager/customers', 'customers'], ['POST', '/manager/customer-detail', 'customers'],
  ['POST', '/manager/create-customer', 'customers'], ['POST', '/efris/verify-tin', 'customers'],
  // Cashier: read goods, units and the commodity tree
  ['POST', '/efris/search-goods', 'goods-read'], ['GET', '/goods/manager-items', 'goods-read'], ['GET', '/goods/manager-item-detail', 'goods-read'],
  ['GET', '/manager/items-list', 'goods-read'], ['POST', '/efris/measure-units', 'goods-read'],
  ['GET', '/segments', 'goods-read'], ['GET', '/segments/:segCode/families', 'goods-read'], ['GET', '/segments/:segCode/families/:famCode/classes', 'goods-read'],
  ['GET', '/segments/:segCode/families/:famCode/classes/:clsCode/commodities', 'goods-read'],
  ['GET', '/commodity/search', 'goods-read'], ['GET', '/commodity/:code', 'goods-read'], ['POST', '/efris/commodity-tax', 'goods-read'],
  // Cashier: offline queue (see it, Try now, link the Manager document)
  ['GET', '/offline-queue', 'queue'], ['POST', '/offline-queue/:id/link', 'queue'], ['POST', '/offline-queue/retry-now', 'queue'], ['POST', '/offline-queue/flush', 'queue'],
  // Cashier: own submission-log entries (accountants and admins see all)
  ['GET', '/submission-log', 'log-own'], ['GET', '/submission-log/by-fdn/:fdn', 'log-own'],
  // Accountant: credit and debit notes
  ['POST', '/efris/credit-note', 'credit'], ['POST', '/efris/credit-notes/status', 'credit'], ['POST', '/efris/credit-notes/void', 'credit'],
  ['POST', '/efris/credit-notes/cancel', 'credit'], ['POST', '/efris/debit-note', 'credit'], ['POST', '/manager/create-credit-note', 'credit'],
  // Accountant: reports and reconcile
  ['POST', '/efris/invoices-report', 'reports'], ['GET', '/z-report', 'reports'],
  ['POST', '/reconcile/documents', 'reconcile'], ['POST', '/reconcile/stock', 'reconcile'],
  // Accountant: stock (T131/T132 and the Manager inventory mirror)
  ['POST', '/efris/stock-in', 'stock'], ['POST', '/efris/stock-adjust', 'stock'], ['POST', '/manager/inventory-adjust', 'stock'],
  ['GET', '/manager/accounts', 'stock'], ['GET', '/manager/divisions', 'stock'],
  // Accountant: number series set-up
  ['POST', '/number-series', 'series'], ['PUT', '/number-series/:id', 'series'], ['DELETE', '/number-series/:id', 'series'],
  // Accountant: the whole submission log and queue housekeeping
  ['POST', '/submission-log/import', 'log-all'], ['POST', '/submission-log/:id/link', 'log-all'], ['DELETE', '/submission-log/:id', 'log-all'],
  ['DELETE', '/offline-queue/:id', 'log-all'],
  // Admin: the relay's activity log (Settings > Logs). Listed explicitly; the route
  // further limits a non-owner admin to the businesses they administer.
  ['GET', '/admin/activity', 'admin'], ['GET', '/admin/activity/export', 'admin'], ['GET', '/admin/support-bundle', 'admin'],
  // Owner only: the relay's outgoing email server (Settings > Email). 'owner' is not
  // a role permission: an owner or the service passes, every other user (even a
  // business admin) is refused, because the mail account serves the whole relay.
  ['GET', '/admin/email', 'owner'], ['POST', '/admin/email', 'owner'], ['POST', '/admin/email/test', 'owner'],
  // Owner only: single-user mode (no sign-in on the relay's own computer).
  ['GET', '/admin/single-user', 'owner'], ['POST', '/admin/single-user', 'owner'],
  // Everything else (tenant credentials, users, goods registration T130, custom
  // fields, theme install, Enabler test, manager/detect, rotate-key, logs, debug
  // routes, unit sync, currencies) is admin only.
].map(([method, p, perm]) => ({ method, path: p, perm, re: new RegExp('^' + p.replace(/:[A-Za-z]+/g, '[^/]+') + '/?$') }));
function routePerm(method, p) {
  const m = method === 'HEAD' ? 'GET' : method;
  const hit = ROUTE_PERMS.find(r => r.method === m && r.re.test(p));
  return hit ? hit.perm : '*';
}

function denyAuth(res) { return res.status(401).json({ success: false, error: 'Sign in required', auth: true }); }
app.use('/api', (req, res, next) => {
  // Who is calling
  let user = null;
  if (req.headers['x-api-key'] && serviceKeyOk(req.headers['x-api-key'])) user = SERVICE_PRINCIPAL;
  else {
    const m = /^Bearer\s+([A-Za-z0-9_-]{20,100})\s*$/i.exec(String(req.headers.authorization || ''));
    if (m) {
      const s = auth.sessionFromToken(m[1]);
      // A single-user (automatic) session only counts on the relay's own computer,
      // and only while single-user mode is on.
      if (s && !(s.session && s.session.localAuto && !(isLocalRequest(req) && singleUserOn()))) { user = s.user; req.sessionHash = s.hash; req.sessionToken = m[1]; req.localAuto = !!(s.session && s.session.localAuto); }
    }
  }
  req.auth = user;
  const perm = routePerm(req.method, req.path);
  if (perm === 'public') return reqCtx.run({ user }, next);
  if (!user) return denyAuth(res);
  // Which business: X-Tenant-Id must be one the user holds a role in. The tenant
  // routes name their business in the body or path and check it themselves.
  const tid = String(req.headers['x-tenant-id'] || '').trim();
  const tenantRoute = /^\/tenant(\/|$)/.test(req.path);
  if (tid && !tenantRoute && !canUseTenant(user, tid)) return res.status(403).json({ success: false, error: 'You do not have access to this business' });
  req.tenantId = tid && !tenantRoute ? tid : '';
  // Owner-only routes: no role grants them, whatever the business.
  if (perm === 'owner' && !(user.owner || user.service)) return res.status(403).json({ success: false, error: 'Only an owner can do this', permission: 'owner' });
  // What they may do there (no business named: what they may do in any of theirs)
  if (perm !== '' && perm !== 'owner') {
    const perms = auth.permissionsFor(user, req.tenantId || undefined);
    if (!auth.can(perms, perm)) return res.status(403).json({ success: false, error: 'Your role cannot do this', permission: perm === '*' ? 'admin' : perm });
  }
  reqCtx.run({ user, tenantId: req.tenantId }, next);
});
function currentUser() { const s = reqCtx.getStore(); return (s && s.user) || null; }
// Who to record on a log entry.
function actor(req) {
  const u = (req && req.auth) || currentUser();
  if (!u) return {};
  return { userId: u.id, userName: u.displayName || u.name };
}

// ── Vault placeholders ──
// The browser keeps no secrets: where it would send the EFRIS password, private
// key, key passphrase or Manager token it sends VAULT_PLACEHOLDER plus an
// X-Tenant-Id header. Swap each placeholder for the decrypted vault value here,
// before any route sees the request, so the routes themselves are unchanged.
// Only the business checked above is ever filled.
const VAULT_PLACEHOLDER = '__vault__';
const VAULT_FIELD = {
  efrispassword: 'efrisPassword', password: 'efrisPassword',
  efriskeypem: 'efrisPrivateKeyPem',
  efriskeypassphrase: 'efrisPassphrase', efriskeypassword: 'efrisPassphrase',
  accesstoken: 'managerToken', apiaccesstoken: 'managerToken', token: 'managerToken', tk: 'managerToken',
};
// Returns how many placeholders were filled with a real (non-empty) vault value.
function fillFromVault(obj, tenant, depth) {
  if (!obj || typeof obj !== 'object' || depth > 5) return 0;
  let n = 0;
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v === VAULT_PLACEHOLDER) { const f = VAULT_FIELD[k.toLowerCase()]; obj[k] = (f && tenant && tenant[f]) || ''; if (obj[k]) n++; }
    else if (v && typeof v === 'object') n += fillFromVault(v, tenant, depth + 1);
  }
  return n;
}
// Field names that say where a Manager call goes (body, nested config, query).
const MGR_EP_FIELD = /^(managerendpoint|mgrendpoint|managerurl|ep)$/i;
// Sets every Manager-endpoint field in obj to ep. Returns how many it found.
function forceEndpoint(obj, ep, depth) {
  if (!obj || typeof obj !== 'object' || depth > 5) return 0;
  let n = 0;
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (MGR_EP_FIELD.test(k) && (typeof v === 'string' || v == null)) { if (v) n++; obj[k] = ep; }
    else if (v && typeof v === 'object') n += forceEndpoint(v, ep, depth + 1);
  }
  return n;
}
app.use('/api', (req, res, next) => {
  if (/^\/auth(\/|$)/.test(req.path)) return next();   // passwords there are the user's own
  if (/^\/admin\/email(\/|$)/.test(req.path)) return next();   // the email password is the relay's, not a business's
  if (/^\/tenant(\/|$)/.test(req.path)) return next();   // saving a business never needs saved secrets filled in (a profile must keep its placeholders)
  const raw = JSON.stringify(req.body || {}) + JSON.stringify(req.query || {}) + (req.headers['x-manager-token'] || '');
  if (!raw.includes(VAULT_PLACEHOLDER)) return next();
  const tid = req.tenantId || '';
  if (!tid) return res.status(400).json({ success: false, error: 'Select a business first (saved credentials belong to a business).' });
  let tenant = null;
  // While the vault key is still unlocking in the background, answer "try again
  // shortly" rather than filling the request with blank secrets.
  try { tenant = vault.getTenant(tid); }
  catch (e) { if (e.code === 'VAULT_LOCKED') return res.status(503).json({ success: false, error: e.message, vaultLocked: true }); throw e; }
  if (!tenant) console.log('   ⚠ Request used vault placeholders but tenant "' + tid + '" is not in the vault');
  let filled = fillFromVault(req.body, tenant, 0) + fillFromVault(req.query, tenant, 0);
  const hdrTok = req.headers['x-manager-token'] === VAULT_PLACEHOLDER;
  if (hdrTok) { req.headers['x-manager-token'] = (tenant && tenant.managerToken) || ''; if (req.headers['x-manager-token']) filled++; }
  // The filled-in values are masked in the logs from here on.
  activity.noteBody(req.body); activity.noteBody(req.query); activity.noteSecrets(req.headers['x-manager-token'] || '');
  if (filled) {
    // A saved secret only ever goes to this business's own Manager: whatever
    // endpoint the caller named is replaced by the one saved with the business.
    // Without a saved endpoint the request is refused rather than sent anywhere
    // the caller chose.
    const ep = String((tenant && tenant.managerEndpoint) || '').trim();
    const named = forceEndpoint(req.body, ep, 0) + forceEndpoint(req.query, ep, 0) + (req.headers['x-manager-endpoint'] ? 1 : 0);
    const mgrTokenUsed = hdrTok || /"(accesstoken|apiaccesstoken|token|tk)":"__vault__"/i.test(raw);
    if (!ep && (named || mgrTokenUsed)) return res.status(400).json({ success: false, error: 'Save the Manager endpoint for this business in Settings first: saved credentials are only sent to the Manager saved with the business.' });
    if (ep) req.headers['x-manager-endpoint'] = ep;
    req.vaultFilled = true;
    req.vaultEndpoint = ep;
  }
  next();
});

// Simple rate limiter - max 30 EFRIS submissions per minute per IP
const _rateMap = new Map();
function rateLimit(maxPerMin) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const window = 60000;
    if (!_rateMap.has(ip)) _rateMap.set(ip, []);
    const hits = _rateMap.get(ip).filter(t => now - t < window);
    hits.push(now);
    _rateMap.set(ip, hits);
    if (hits.length > maxPerMin) return res.status(429).json({ error: 'Too many requests - slow down' });
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, hits] of _rateMap) if (!hits.some(t => now - t < 60000)) _rateMap.delete(ip);
}, 5 * 60000).unref();

// ══════════════════════════════════════════════════════════════
//  Sign-in routes (/api/auth/*)
// ══════════════════════════════════════════════════════════════
// Permission names a role grants, for the extension to show or hide controls.
// Admins get '*' plus every name, so a check for any one name succeeds.
const ALL_PERM_NAMES = ['admin'].concat(auth.ROLE_PERMS.accountant);
function permList(user, tid) {
  const p = auth.permissionsFor(user, tid);
  return p.has('*') ? ['*'].concat(ALL_PERM_NAMES) : [...p];
}
function tenantMetaMap() { const m = {}; try { for (const t of vault.listTenants()) m[t.id] = t; } catch (_) {} return m; }
// The businesses a user may use, with their role in each.
function tenantsOf(user) {
  const metas = tenantMetaMap();
  const ids = new Set(tenantIdsFor(user));
  return [...ids].map(id => {
    const t = metas[id] || {};
    return { id, businessName: t.businessName || '', tradeName: t.tradeName || '', tin: t.tin || '', mode: t.mode || 'sandbox', role: auth.roleIn(user, id) };
  });
}
// Businesses where the user is an administrator (owners: all of them).
function adminTenantIds(user) { return tenantIdsFor(user).filter(id => auth.roleIn(user, id) === 'admin'); }
function shortUser(u) { return u ? { id: u.id, name: u.name, displayName: u.displayName || u.name, email: u.email || '', owner: !!u.owner } : null; }

// ── Security alerts (email) ──
// Where a request came from, for the alert text.
function reqWhere(req) {
  const local = isLocalRequest(req);
  const ip = String((req && (req.ip || (req.socket && req.socket.remoteAddress))) || '').replace(/^::ffff:/, '');
  return { local, ip };
}
function bizNames(ids) {
  const m = tenantMetaMap();
  return ids.map(id => { const t = m[id] || {}; return t.tradeName || t.businessName || id; }).join(', ');
}
function actorText(req) {
  const u = req && req.auth;
  if (!u) return '';
  if (u.service) return 'An automated service (API key)';
  return '"' + u.name + '"' + (u.displayName && u.displayName !== u.name ? ' (' + u.displayName + ')' : '');
}
function roleText(roles) {
  const m = tenantMetaMap();
  return Object.entries(roles || {}).map(([t, r]) => (auth.ROLES.includes(r) ? r[0].toUpperCase() + r.slice(1) : r) + ' at ' + ((m[t] && (m[t].tradeName || m[t].businessName)) || t)).join(', ');
}
// Queue a security alert to the owners with an email and to the affected user.
// Never throws and never waits: a failed email does not affect the request.
function securityAlert(event, req, ctx) {
  try {
    const biz = req && req.tenantId ? bizNames([req.tenantId]) : '';
    return mailer.alert(event, Object.assign({ owners: auth.listOwners(), business: biz }, reqWhere(req), ctx || {}));
  } catch (_) { return []; }
}

app.get('/api/auth/status', (req, res) => {
  let user = req.auth;
  const local = isLocalRequest(req);
  // Single-user mode: on the relay's own computer, nobody signed in yet means the
  // owner is signed in automatically (a normal session, marked local-auto).
  let auto = null;
  if (!user && local && singleUserOn() && auth.hasUsers()) {
    const o = singleUserOwner();
    if (o) {
      const s = auth.createSession(o.id, false, { localAuto: true });
      user = auth.getUser(o.id);
      auto = { autoToken: s.token, autoExpiresAt: s.expiresAt };
      console.log('   Sign-in: single-user mode opened EFRIS Connect as "' + o.name + '" on this computer');
    }
  }
  const tenants = user ? tenantsOf(user) : [];
  const permissions = {};
  for (const t of tenants) permissions[t.id] = permList(user, t.id);
  res.json(Object.assign({ success: true, setupNeeded: !auth.hasUsers(), local, emailRecovery: mailer.isConfigured(), user: shortUser(user), tenants, permissions,
    singleUser: local && singleUserOn(), localAuto: !!(auto || req.localAuto) }, auto || {}));
});

// Create the owner account. Only while no account exists. On the relay's own
// computer no code is needed; from anywhere else the setup code shown in the
// relay console (and saved in the data folder) is required.
app.post('/api/auth/setup', rateLimit(10), (req, res) => {
  const b = req.body || {};
  if (auth.hasUsers()) return res.status(409).json({ success: false, error: 'The owner account already exists. Sign in instead.' });
  if (!isLocalRequest(req) && !auth.checkSetupCode(b.setupCode)) {
    return res.status(403).json({ success: false, error: 'The setup code is wrong or has expired. It is shown in the EFRIS Connect window on the server.', setupCodeRequired: true });
  }
  let out;
  try { out = auth.createOwner({ name: b.name, displayName: b.displayName, password: b.password }); }
  catch (e) { return res.status(e.status || 500).json({ success: false, error: e.expose ? e.message : 'Could not create the account' }); }
  const s = auth.createSession(out.user.id, !!b.remember);
  console.log('   Sign-in: owner account "' + out.user.name + '" created' + (isLocalRequest(req) ? ' on this computer' : ' with the setup code'));
  securityAlert('owner-created', req, { user: out.user });
  res.json({ success: true, token: s.token, expiresAt: s.expiresAt, recoveryCode: out.recoveryCode, user: shortUser(out.user) });
});

app.post('/api/auth/login', rateLimit(10), (req, res) => {
  const b = req.body || {};
  if (!auth.hasUsers()) return res.json({ success: false, error: 'No account exists yet. Create the owner account first.', setupNeeded: true });
  const r = auth.login(b.name, b.password, !!b.remember);
  if (!r.success) {
    if (r.justLocked) securityAlert('locked', req, { user: r.justLocked });
    const { justLocked, ...out } = r;
    return res.json(out);
  }
  res.json({ success: true, token: r.token, expiresAt: r.expiresAt, user: shortUser(r.user) });
});

app.post('/api/auth/logout', (req, res) => {
  if (req.sessionToken) auth.logout(req.sessionToken);
  res.json({ success: true });
});

// Forgotten password: the user's recovery code, or (owner, on the relay's own
// computer only) a reset code written by reset-owner.js.
app.post('/api/auth/recover', rateLimit(10), (req, res) => {
  const b = req.body || {};
  const r = auth.recover(b.name, b.code, b.newPassword, { allowReset: isLocalRequest(req) });
  if (!r.success) return res.json(r);
  securityAlert(r.method === 'reset' ? 'reset-owner-code' : r.method === 'email' ? 'reset-email-code' : 'reset-recovery', req, { user: r.user });
  res.json({ success: true, token: r.token, expiresAt: r.expiresAt, recoveryCode: r.recoveryCode, user: shortUser(r.user) });
});

// Forgot password > Email me a code. The answer is the same whether or not the
// name exists, has an email address or has hit the hourly limit, so it cannot be
// used to find accounts. The code is emailed in the background.
const EMAIL_CODE_SENT = 'If that sign-in name has an email address, a code is on its way. It works once and is valid for 30 minutes. Check your inbox (and the spam folder), then type the code below.';
app.post('/api/auth/email-code', rateLimit(5), (req, res) => {
  const b = req.body || {};
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name) return res.json({ success: false, error: 'Enter your sign-in name first.' });
  if (!mailer.isConfigured()) return res.json({ success: true, message: EMAIL_CODE_SENT });
  try {
    const r = auth.issueEmailCode({ name });
    if (r.code) mailer.sendCode(r.user, r.code, reqWhere(req));
    else if (r.limited) console.log('   ⚠ Sign-in: no password code emailed for "' + name.slice(0, 64) + '": ' + auth.EMAIL_CODE_MAX_PER_HOUR + ' already sent in the last hour');
  } catch (e) { console.log('   ⚠ Sign-in: password code not sent: ' + e.message); }
  res.json({ success: true, message: EMAIL_CODE_SENT });
});

// My account: the signed-in user's own email address (needs the current password).
app.post('/api/auth/me', (req, res) => {
  if (!req.auth || req.auth.service) return res.status(400).json({ success: false, error: 'Sign in as a user to change your account.' });
  const b = req.body || {};
  if (b.email === undefined) return res.status(400).json({ success: false, error: 'Nothing to change.' });
  const r = auth.setOwnEmail(req.auth.id, b.currentPassword, b.email);
  if (!r.success) return res.json(r);
  if (r.changed) securityAlert('email-changed', req, { user: r.user, alsoTo: r.previous });
  res.json({ success: true, user: shortUser(r.user) });
});

app.post('/api/auth/change-password', (req, res) => {
  if (!req.auth || req.auth.service) return res.status(400).json({ success: false, error: 'Sign in as a user to change a password.' });
  const b = req.body || {};
  const r = auth.changeOwnPassword(req.auth.id, b.currentPassword, b.newPassword, req.sessionHash);
  if (r.success) securityAlert('password-changed', req, { user: auth.publicUser(auth.getUser(req.auth.id)) });
  res.json(r);
});

// ── User administration ──
// An administrator manages the users of the businesses they administer, and only
// the roles in those businesses. Owners manage everyone.
function userAdminScope(req, res) {
  const user = req.auth;
  if (user.owner || user.service) return { all: true, tenants: new Set(tenantIdsFor(user)) };
  const t = new Set(adminTenantIds(user));
  if (!t.size) { res.status(403).json({ success: false, error: 'Your role cannot do this', permission: 'admin' }); return null; }
  return { all: false, tenants: t };
}
function viewUserFor(scope, u) {
  if (scope.all) return u;
  const roles = {};
  for (const [t, r] of Object.entries(u.roles || {})) if (scope.tenants.has(t)) roles[t] = r;
  return { ...u, roles };
}
const inScope = (scope, u) => scope.all || (!u.owner && Object.keys(u.roles || {}).some(t => scope.tenants.has(t)));
// The user's roles are all in businesses this admin runs (so disabling or resetting
// them cannot lock someone out of a business the admin has no say in).
const whollyInScope = (scope, u) => scope.all || (!u.owner && Object.keys(u.roles || {}).every(t => scope.tenants.has(t)));

app.get('/api/auth/users', (req, res) => {
  const scope = userAdminScope(req, res); if (!scope) return;
  res.json({ success: true, users: auth.listUsers().filter(u => inScope(scope, u)).map(u => viewUserFor(scope, u)) });
});

app.post('/api/auth/users', (req, res) => {
  const scope = userAdminScope(req, res); if (!scope) return;
  const b = req.body || {};
  const roles = (b.roles && typeof b.roles === 'object') ? b.roles : {};
  for (const t of Object.keys(roles)) if (!scope.all && !scope.tenants.has(t)) return res.status(403).json({ success: false, error: 'You do not have access to this business' });
  if (!scope.all && !Object.keys(roles).length) return res.status(400).json({ success: false, error: 'Give the user a role in at least one business.' });
  if (b.owner && !(req.auth.owner || req.auth.service)) return res.status(403).json({ success: false, error: 'Only an owner can make another owner.' });
  try {
    const u = auth.addUser({ name: b.name, displayName: b.displayName, password: b.password, roles, owner: !!b.owner, email: b.email });
    console.log('   Sign-in: user "' + u.name + '" added by ' + (req.auth.name || 'service'));
    securityAlert(u.owner ? 'owner-created' : 'user-added', req, { user: u, actor: actorText(req), detail: u.owner ? '' : roleText(u.roles) });
    res.json({ success: true, user: viewUserFor(scope, u) });
  } catch (e) { res.status(e.status || 500).json({ success: false, error: e.expose ? e.message : 'Could not add the user' }); }
});

app.post('/api/auth/users/:id', (req, res) => {
  const scope = userAdminScope(req, res); if (!scope) return;
  const b = req.body || {};
  const target = auth.listUsers().find(u => u.id === req.params.id);
  if (!target || !inScope(scope, target)) return res.status(404).json({ success: false, error: 'User not found.' });
  const fields = {};
  if (b.displayName !== undefined) fields.displayName = b.displayName;
  if (b.roles !== undefined) {
    const want = (b.roles && typeof b.roles === 'object') ? b.roles : {};
    for (const t of Object.keys(want)) if (!scope.all && !scope.tenants.has(t)) return res.status(403).json({ success: false, error: 'You do not have access to this business' });
    // Roles in businesses the caller does not run are kept as they are.
    const keep = {};
    for (const [t, r] of Object.entries(target.roles || {})) if (!scope.tenants.has(t)) keep[t] = r;
    fields.roles = { ...keep, ...want };
  }
  // The email address can reset the password, so it needs the same reach as a password reset.
  if (b.disabled !== undefined || (b.password !== undefined && b.password !== '') || b.email !== undefined) {
    if (!whollyInScope(scope, target)) return res.status(403).json({ success: false, error: 'This user also works for a business you do not administer. Ask an owner.' });
    if (b.disabled !== undefined) fields.disabled = !!b.disabled;
    if (b.password !== undefined && b.password !== '') fields.password = b.password;
    if (b.email !== undefined) fields.email = b.email;
  }
  if (b.owner !== undefined) {
    if (!(req.auth.owner || req.auth.service)) return res.status(403).json({ success: false, error: 'Only an owner can grant or remove owner rights.' });
    fields.owner = !!b.owner;
  }
  if (target.id === (req.auth && req.auth.id) && fields.disabled) return res.status(400).json({ success: false, error: 'You cannot disable your own account.' });
  try {
    const u = auth.updateUser(target.id, fields);
    const actor = actorText(req);
    if (fields.password) securityAlert('password-reset-admin', req, { user: u, actor });
    if (!target.disabled && u.disabled) securityAlert('user-disabled', req, { user: u, actor });
    const newAdmin = Object.keys(u.roles || {}).filter(t => u.roles[t] === 'admin' && (target.roles || {})[t] !== 'admin');
    if (newAdmin.length) securityAlert('role-admin', req, { user: u, actor, detail: bizNames(newAdmin) });
    if (!target.owner && u.owner) securityAlert('owner-created', req, { user: u, actor });
    if ((target.email || '') !== (u.email || '')) securityAlert('email-changed', req, { user: u, actor, alsoTo: target.email });
    res.json({ success: true, user: viewUserFor(scope, u) });
  } catch (e) { res.status(e.status || 500).json({ success: false, error: e.expose ? e.message : 'Could not update the user' }); }
});

// Reset password > Email a code to the user: the user sets their own new password
// with the emailed code (Forgot password). Same reach as a password reset.
app.post('/api/auth/users/:id/email-code', (req, res) => {
  const scope = userAdminScope(req, res); if (!scope) return;
  const target = auth.listUsers().find(u => u.id === req.params.id);
  if (!target || !inScope(scope, target)) return res.status(404).json({ success: false, error: 'User not found.' });
  if (!whollyInScope(scope, target)) return res.status(403).json({ success: false, error: 'This user also works for a business you do not administer. Ask an owner.' });
  if (!mailer.isConfigured()) return res.status(400).json({ success: false, error: 'Email is not set up. An owner can set it up in Settings > Email.' });
  if (!target.email) return res.status(400).json({ success: false, error: 'This user has no email address. Add one first, or set a new password by hand.' });
  if (target.disabled) return res.status(400).json({ success: false, error: 'This user is disabled. Enable the account first.' });
  const r = auth.issueEmailCode({ id: target.id });
  if (!r.code) return res.status(r.limited ? 429 : 400).json({ success: false, error: r.error });
  mailer.sendCode(r.user, r.code, Object.assign(reqWhere(req), { byAdmin: actorText(req) }));
  console.log('   Sign-in: ' + actorText(req) + ' asked for a password code to be emailed to "' + target.name + '"');
  res.json({ success: true, message: 'A code is being emailed to ' + (target.displayName || target.name) + '. It works once and is valid for 30 minutes. They type it under "Forgot password?" with a new password.' });
});

// ── Settings > Email (owner only, see ROUTE_PERMS) ──
function emailView(req) {
  const owners = auth.listOwners().filter(o => !o.disabled);
  const me = req.auth && !req.auth.service ? auth.getUser(req.auth.id) : null;
  return { success: true, settings: mailer.getSettings(), configured: mailer.isConfigured(),
    ownerHasEmail: !!(me && me.email), myEmail: (me && me.email) || '', ownersWithEmail: owners.filter(o => o.email).length };
}
app.get('/api/admin/email', (req, res) => res.json(emailView(req)));
app.post('/api/admin/email', (req, res) => {
  let r;
  try { r = mailer.saveSettings(req.body || {}); }
  catch (e) { return res.status(500).json({ success: false, error: 'The email settings could not be saved: ' + e.message }); }
  if (r.error) return res.status(400).json({ success: false, error: r.error });
  console.log('   Email: settings ' + (r.settings.host ? 'saved (' + r.settings.host + ':' + r.settings.port + ')' : 'cleared, email is off') + ' by ' + actorText(req));
  res.json(emailView(req));
});
// Sends a test message now and reports the mail server's own error on failure.
app.post('/api/admin/email/test', async (req, res) => {
  const b = req.body || {};
  const me = req.auth && !req.auth.service ? auth.getUser(req.auth.id) : null;
  const to = String(b.to || (me && me.email) || '').trim();
  if (!mailer.isConfigured()) return res.status(400).json({ success: false, error: 'Save the email settings first.' });
  if (!mailer.validEmail(to)) return res.status(400).json({ success: false, error: 'Enter the email address to send the test to.' });
  const r = await mailer.send(mailer.testMessage(to));
  console.log(r.success ? '   Email: test email sent by ' + actorText(req) : '   ⚠ Email: test email failed: ' + r.error);
  res.json(r.success ? { success: true, message: 'Test email sent. Check the inbox (and the spam folder).' } : { success: false, error: r.error });
});

// ── Single-user mode (Settings > Users, owner only) ──
// For Manager Desktop on one PC: EFRIS Connect opens without sign-in on the
// computer that runs it. Requests from any other computer still sign in. It is
// refused while the relay can be reached from other computers (LAN mode or a
// non-loopback bind) and turned off at start if that has changed since.
function singleUserBlockReason() {
  if (LAN_MODE) return 'shop network (LAN) mode is on';
  if (!BIND_IS_LOOPBACK) return 'EFRIS Connect is reachable from other computers (BIND_HOST=' + BIND_HOST + ')';
  return '';
}
function singleUserRec() { try { return vault.getRelay('singleUser', []) || {}; } catch (_) { return {}; } }
function singleUserOn() { return !singleUserBlockReason() && !!singleUserRec().enabled; }
// The owner it signs in as: the one who turned it on, else the first active owner.
function singleUserOwner() {
  const owners = auth.listOwners().filter(o => !o.disabled);
  const id = singleUserRec().ownerId;
  return owners.find(o => o.id === id) || owners[0] || null;
}
function singleUserView() {
  const r = singleUserRec(); const o = singleUserOwner(); const blocked = singleUserBlockReason();
  return { success: true, enabled: !!r.enabled && !blocked, allowed: !blocked, blockedReason: blocked, lanMode: LAN_MODE,
    owner: o ? (o.displayName || o.name) : '', changedAt: r.changedAt || '', changedBy: r.changedBy || '',
    autoDisabledAt: r.autoDisabledAt || '', autoDisabledReason: r.autoDisabledReason || '' };
}
app.get('/api/admin/single-user', (req, res) => res.json(singleUserView()));
app.post('/api/admin/single-user', (req, res) => {
  const b = req.body || {};
  if (typeof b.enabled !== 'boolean') return res.status(400).json({ success: false, error: 'Say whether single-user mode is on or off.' });
  const blocked = singleUserBlockReason();
  if (b.enabled && blocked) return res.status(409).json(Object.assign(singleUserView(), { success: false, error: 'Single-user mode cannot be turned on while ' + blocked + ': people on other computers would still sign in, but it is only meant for one PC. Leave it off when tills or other computers use EFRIS Connect.' }));
  const was = !!singleUserRec().enabled;
  const me = req.auth && !req.auth.service ? auth.getUser(req.auth.id) : null;
  try {
    vault.putRelay('singleUser', { enabled: b.enabled, ownerId: b.enabled ? (me && me.owner ? me.id : (singleUserOwner() || {}).id || '') : (singleUserRec().ownerId || ''),
      changedAt: new Date().toISOString(), changedBy: actorText(req), autoDisabledAt: '', autoDisabledReason: '' }, []);
  } catch (e) { return res.status(500).json({ success: false, error: 'The setting could not be saved: ' + e.message }); }
  if (!b.enabled) auth.revokeLocalAutoSessions();
  if (was !== b.enabled) {
    const o = singleUserOwner();
    console.log('   Security: single-user mode turned ' + (b.enabled ? 'ON' : 'OFF') + ' by ' + actorText(req) + (b.enabled ? ': EFRIS Connect opens without sign-in as "' + (o ? o.name : '?') + '" on this computer; other computers still sign in' : ': everyone signs in again'));
    securityAlert(b.enabled ? 'single-user-on' : 'single-user-off', req, { user: o, actor: actorText(req) });
  }
  res.json(singleUserView());
});
// At start: a relay that is now reachable from other computers turns the mode off.
(function singleUserStartCheck() {
  const r = singleUserRec(); const blocked = singleUserBlockReason();
  if (!r.enabled || !blocked) return;
  try {
    vault.putRelay('singleUser', { enabled: false, autoDisabledAt: new Date().toISOString(), autoDisabledReason: blocked }, []);
    auth.revokeLocalAutoSessions();
    console.log('   ⚠ Single-user mode was turned OFF because ' + blocked + '. Everyone signs in, also on this computer.');
    mailer.alert('single-user-off', { owners: auth.listOwners(), user: singleUserOwner(), detail: 'turned off at start because ' + blocked, computer: 'the computer that runs EFRIS Connect (at start)' });
  } catch (e) { console.log('   ⚠ Single-user mode could not be turned off: ' + e.message); }
})();

// Expired sessions are dropped once an hour.
setInterval(() => { try { auth.purgeSessions(); } catch (_) {} }, 3600000).unref();

// Load frontend HTML at startup - used as /extension and SPA
let EXTENSION_HTML = '';
try {
  EXTENSION_HTML = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
  console.log('Loaded frontend/index.html as EXTENSION_HTML');
} catch(e) {
  console.warn('Could not load frontend/index.html:', e.message);
}

// Runtime files (vault, logs, certs, submission log, queue) live in DATA_DIR;
// the commodity tree and bundled unit lists ship with the code in SHIPPED_DIR.
const { DATA_DIR, SHIPPED_DIR } = require('./paths');
let TREE = null;
let UNITS = null;

function getTree() {
  if (!TREE) {
    console.log('Loading goods_tree.json...');
    TREE = JSON.parse(fs.readFileSync(path.join(SHIPPED_DIR, 'goods_tree.json'), 'utf8'));
    console.log('Loaded: ' + Object.keys(TREE).length + ' segments');
  }
  return TREE;
}

// Prefer the EFRIS-synced unit list (uom_synced.json) when present - it's the
// authoritative list pulled from the taxpayer's own EFRIS account and cached to
// disk so it also works offline. Falls back to the bundled static list.
function getUnits() {
  if (!UNITS) {
    for (const [dir, f] of [[DATA_DIR, 'uom_synced.json'], [SHIPPED_DIR, 'uom.json'], [SHIPPED_DIR, 'units.json']]) {
      try { const u = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); if (Array.isArray(u) && u.length) { UNITS = u; break; } } catch(e) {}
    }
    if (!UNITS) UNITS = [];
  }
  return UNITS;
}
// Metadata about the last EFRIS unit sync (for the UI to show "last synced").
function unitsSyncMeta() {
  try {
    const st = fs.statSync(path.join(DATA_DIR, 'uom_synced.json'));
    const arr = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'uom_synced.json'), 'utf8'));
    return { synced: true, count: Array.isArray(arr) ? arr.length : 0, at: st.mtime.toISOString() };
  } catch(e) { return { synced: false }; }
}

// ── URA EFRIS addresses ───────────────────────────────────────
// Every place that talks to URA takes its address from here. EFRIS_URL_OVERRIDE
// is a TEST HOOK ONLY: when set (the automated tests point it at a local fake
// URA), it replaces the URA getInformation URL for both sandbox and production,
// and its origin replaces the URA host used by the reachability pings. Unset
// (normal use) it has no effect.
function uraUrl(mode) {
  if (process.env.EFRIS_URL_OVERRIDE) return process.env.EFRIS_URL_OVERRIDE;
  return mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
}
function uraHost(mode) {
  if (process.env.EFRIS_URL_OVERRIDE) return new URL(process.env.EFRIS_URL_OVERRIDE).origin + '/';
  return mode === 'production' ? 'https://efrisws.ura.go.ug/' : 'https://efristest.ura.go.ug/';
}

// ── HTTPS call to EFRIS ───────────────────────────────────────
function efrisCall(baseUrl, payload) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(payload);
    let parsed;
    try { parsed = new URL(baseUrl); } catch(e) { return reject(new Error('Bad EFRIS URL: ' + baseUrl)); }
    const opts = {
      hostname: parsed.hostname, port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
      path: parsed.pathname + (parsed.search || ''), method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bodyStr) },
      timeout: 30000
    };
    // EFRIS is HTTPS, but the local Offline Mode Enabler is plain HTTP - pick the
    // library by protocol, else we TLS-handshake a plaintext server and get
    // "EPROTO … wrong version number".
    const lib = parsed.protocol === 'http:' ? http : https;
    // Did the request reach the server? A timeout after connecting means EFRIS may
    // have processed it (outcome unknown, flagged afterSend); a timeout before that
    // is a plain network failure.
    let connected = false;
    const req = lib.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e) { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', (e) => { logger.error('EFRIS network call failed', { url: baseUrl, message: e.message }); reject(e); });
    req.on('socket', s => { if (!s.connecting) connected = true; else s.once('connect', () => { connected = true; }); });
    req.on('timeout', () => { req.destroy(); logger.error('EFRIS network call timed out', { url: baseUrl }); const e = new Error('EFRIS timed out after 30s'); e.afterSend = connected; reject(e); });
    req.write(bodyStr); req.end();
  });
}

// ── Call Manager.io ───────────────────────────────────────────
// Follows same-method redirects (301/302/307/308) - Manager installs are
// commonly parked behind a reverse proxy that redirects http:// to https://,
// and Node's http/https client (unlike a browser or axios) never follows
// redirects on its own. Left unhandled, every request comes back as a bare
// 301 with no body, which is easily misreported as "invalid access token"
// further up the stack.
function _managerCallOnce(endpoint, token, method, docPath, body, _redirectsLeft, extraHeaders) {
  if (_redirectsLeft === undefined) _redirectsLeft = 5;
  return new Promise((resolve, reject) => {
    const base = (endpoint || '').replace(/\/+$/, '');
    const cleanPath = docPath ? (docPath.startsWith('/') ? docPath : '/' + docPath) : '';
    const fullUrl = base + cleanPath;
    let parsed;
    try { parsed = new URL(fullUrl); } catch(e) { return reject(new Error('Bad Manager URL: ' + fullUrl)); }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return reject(new Error('Manager URL must start with http:// or https://'));
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const bodyStr = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: parsed.hostname, port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + (parsed.search || ''), method,
      // A missing or non-browser User-Agent is a common trigger for proxy/WAF
      // bot protection to block legitimate server-to-server API calls with a 403.
      headers: { 'X-API-KEY': token, 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36', 'Accept': 'application/json' },
      timeout: 20000,
      // Verify Manager's TLS certificate by default (prevents MITM). Only skip
      // verification when the operator explicitly opts in for a self-signed
      // Manager (MANAGER_INSECURE_TLS=1) - never silently.
      ...(isHttps && process.env.MANAGER_INSECURE_TLS === '1' ? { rejectUnauthorized: false } : {})
    };
    if (extraHeaders) Object.assign(opts.headers, extraHeaders);
    if (bodyStr) opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    const req = lib.request(opts, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && _redirectsLeft > 0) {
        res.resume(); // discard body, we're not using this response
        const next = new URL(res.headers.location, parsed);
        // The Manager token travels with every hop, so only follow a redirect to
        // the same origin (scheme, host and port), or the same host's http -> https
        // upgrade. Anything else is an error and the token is not sent there.
        const sameOrigin = next.origin === parsed.origin;
        const upgrade = !isHttps && next.protocol === 'https:' && next.hostname === parsed.hostname;
        if (!sameOrigin && !upgrade) {
          return reject(new Error('Manager redirected to ' + next.protocol + '//' + next.host + ' - not followed so your Manager token is not sent there. If that is your Manager, use it as the endpoint.'));
        }
        const nextUrl = next.toString();
        console.log(`   Manager redirect ${res.statusCode}: ${fullUrl} → ${nextUrl}`);
        return resolve(_managerCallOnce(nextUrl, token, method, '', body, _redirectsLeft - 1));
      }
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (data) {
          // Detect HTML responses (e.g. Manager login redirect) before JSON.parse
          const trimmed = data.trimStart();
          if (trimmed.startsWith('<')) {
            // Strip tags for a readable snippet (e.g. a WAF block page's
            // title/reason) instead of discarding the body - often the only clue
            // that a 403/404 came from a proxy in front of Manager, not Manager.
            const textSnippet = trimmed.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 200);
            // A JS-challenge interstitial ("Just a moment...") has a recognizable
            // signature. When present it is not a Manager error or a bad token - no
            // server-to-server call can solve a JS challenge - so callers can report
            // it directly.
            const isCfChallenge = /just a moment|cf-browser-verification|cf-chl-|checking your browser|enable javascript and cookies/i.test(data);
            return resolve({ status: res.statusCode, data: null, _html: true, _htmlSnippet: textSnippet, _cfChallenge: isCfChallenge });
          }
          try { resolve({ status: res.statusCode, data: JSON.parse(data), headers: res.headers }); }
          catch(e) { resolve({ status: res.statusCode, data, headers: res.headers }); }
        } else { resolve({ status: res.statusCode, data: null, headers: res.headers }); }
      });
    });
    req.on('error', (e) => { logger.error('Manager.io network call failed', { url: fullUrl, message: e.message }); reject(e); });
    req.on('timeout', () => { req.destroy(); logger.error('Manager.io network call timed out', { url: fullUrl }); reject(new Error('Manager timed out')); });
    if (bodyStr) req.write(bodyStr); req.end();
  });
}

// Manager is single-threaded and hangs up under concurrent load (it also
// picks a random port each launch). Retry ONLY idempotent reads (GET/HEAD) on a
// transient network failure so flaky loads self-heal. Writes (POST/PUT/DELETE)
// are never retried here - a lost response could otherwise double-create a
// receipt/stock movement. HTTP error statuses resolve (not reject), so 4xx/5xx
// are returned to the caller untouched; only true socket failures are retried.
async function managerCall(endpoint, token, method, docPath, body, _redirectsLeft) {
  const m = String(method || 'GET').toUpperCase();
  const idempotent = m === 'GET' || m === 'HEAD';
  const maxAttempts = idempotent ? 3 : 1;
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await _managerCallOnce(endpoint, token, method, docPath, body, _redirectsLeft);
    } catch (e) {
      lastErr = e;
      const em = String((e && e.message) || '').toLowerCase();
      const transient = /timed out|socket hang up|econnreset|econnaborted|eai_again|etimedout|econnrefused/.test(em);
      if (!transient || attempt === maxAttempts) throw e;
      const wait = 400 * attempt;
      console.log(`   Manager ${m} transient error (${e.message}) - retry ${attempt}/${maxAttempts - 1} in ${wait}ms`);
      await new Promise(r => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

function normEp(ep) {
  ep = (ep || '').trim().replace(/\/+$/, '');
  // api4 is a different protocol - don't silently rewrite it; surface the issue
  if (ep.endsWith('/api4')) throw Object.assign(new Error('Manager API v4 endpoints (/api4) are not yet supported. Please use your /api2 endpoint URL instead.'), { status: 400, expose: true });
  else if (ep.endsWith('/api')) ep = ep + '2';
  else if (!ep.endsWith('/api2')) ep = ep + '/api2';
  return ep;
}

function bareKey(k) { return String(k || '').split('?')[0].replace(/\/+$/, '').split('/').pop(); }

function mgrCreds(req) {
  // A request filled from the vault always goes to the business's saved endpoint.
  const ep = (req.vaultFilled ? req.vaultEndpoint : '') || req.headers['x-manager-endpoint'] || req.query.ep || '';
  // The token is accepted only as a header: URLs end up in logs and history.
  const tk = req.headers['x-manager-token'] || '';
  return { ep: normEp(ep), tk };
}

async function mgrTextCustomFields(ep, tk) {
  const byName = {}, byKey = {};
  try {
    const r = await managerCall(ep, tk, 'GET', '/text-custom-fields');
    const arr = (r.data && r.data.textCustomFields) || [];
    arr.forEach(f => { byName[f.name] = f.key; byKey[f.key] = f.name; });
  } catch (e) {}
  return { byName, byKey };
}

// Cache tax code list per endpoint to avoid repeated fetches
const _taxCodeCache = {};
async function mgrTaxCodeGuid(ep, tk, vatType) {
  const cacheKey = ep + '_taxcodes';
  const load = async () => {
    try { const r = await managerCall(ep, tk, 'GET', '/tax-codes'); _taxCodeCache[cacheKey] = (r.data && r.data.taxCodes) || []; }
    catch (e) { _taxCodeCache[cacheKey] = []; }
  };
  // Match by the EFRIS tax designation. Standard must not pick "Deemed VAT 18%".
  const t = String(vatType || 'Standard').toLowerCase();
  const pick = () => (_taxCodeCache[cacheKey] || []).find(c => {
    const nm = String(c.name || c.Name || '').toLowerCase();
    if (/exempt/.test(t)) return /exempt/.test(nm);
    if (/zero/.test(t)) return /zero/.test(nm);
    if (/deemed/.test(t)) return /deemed/.test(nm);
    return /18|standard|vat/.test(nm) && !/deemed|zero|exempt/.test(nm);
  });
  if (!_taxCodeCache[cacheKey]) await load();
  let match = pick();
  if (!match) { await load(); match = pick(); }   // tax codes may have been created since
  return match ? (match.key || match.Key) : null;
}

async function normalizeInvoice(ep, tk, key) {
  // A document key belongs to either a sales invoice or a receipt. Probe invoice
  // first, fall back to receipt. (Non-VAT businesses often record cash sales as
  // Manager "Receipts".)
  let form = null, docType = 'invoice', formBase = '/sales-invoice-form', listBase = '/sales-invoices', listProp = 'salesInvoices';
  let formR = await managerCall(ep, tk, 'GET', '/sales-invoice-form/' + key);
  if (formR.status === 200 && formR.data && !formR.data.error && (formR.data.Lines || formR.data.Reference || formR.data.IssueDate)) {
    form = formR.data;
  } else {
    // Try receipt
    const rcptR = await managerCall(ep, tk, 'GET', '/receipt-form/' + key);
    if (rcptR.status === 200 && rcptR.data && !rcptR.data.error) {
      form = rcptR.data; docType = 'receipt'; formBase = '/receipt-form'; listBase = '/receipts'; listProp = 'receipts';
      // A receipt that only pays a sales invoice is a payment, not a sale: the invoice
      // is the fiscal document. Fiscalising the payment too would report the sale twice.
      const ls = Array.isArray(form.Lines) ? form.Lines : [];
      if (ls.length && ls.every(l => l && l.AccountsReceivableSalesInvoice && !l.Item)) {
        throw Object.assign(new Error('This receipt is a payment against a sales invoice. The invoice is the fiscal document (submit the invoice to EFRIS, if not done yet); payments are not submitted to URA.'), { status: 400, expose: true, notASale: true });
      }
      console.log(`   Loaded Manager RECEIPT ${key} - fields: ${Object.keys(form).join(', ')}`);
    }
  }
  if (!form) return { _error: 'Manager returned HTTP ' + formR.status + ' (not found as invoice or receipt)', _status: formR.status };
  if (docType === 'invoice') console.log(`   Loaded Manager SALES INVOICE ${key} - fields: ${Object.keys(form).join(', ')}`);
  // "Amounts are tax inclusive" (Manager omits the flag when it is unticked).
  const inclKey = Object.keys(form).find(k => /include|inclusive/i.test(k) && /tax|amount/i.test(k));
  const taxInclusive = inclKey ? !!form[inclKey] : false;
  console.log(`   Amounts are tax inclusive: ${taxInclusive ? 'yes' : 'no'}${inclKey ? ' (' + inclKey + ')' : ''}`);
  let disp = {};
  try {
    const l = (await managerCall(ep, tk, 'GET', listBase + '/' + key)).data;
    disp = (l && l[listProp] && l[listProp][0]) || {};
  } catch (e) {}
  const cf = await mgrTextCustomFields(ep, tk);
  const strs = (form.CustomFields2 && form.CustomFields2.Strings) || {};
  const cfVals = {};
  Object.keys(strs).forEach(k => { cfVals[cf.byKey[k] || k] = strs[k]; });
  // List item carries the payer/customer as a display value under varying names
  // (receipts use paidBy). Unwrap {name} objects too.
  let custName = disp.customer || disp.payer || disp.paidBy || disp.contact || '';
  if (custName && typeof custName === 'object') custName = custName.name || custName.Name || '';
  // NOTE: on a receipt form, PaidBy is a TYPE flag (1 = Customer), NOT a key -
  // using it as a contact key looked up "/customer-form/1" and failed. Resolve
  // from the actual contact key fields instead, and only when it's a real UUID.
  const _UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  let custTIN = strs && (cf.byName && (strs[cf.byName['Buyer TIN']] || strs[cf.byName['Customer TIN']])) || '';
  const contactKey = form.Customer || form.Contact || form.Payer || '';
  if (contactKey && _UUID.test(String(contactKey))) {
    try {
      const c = (await managerCall(ep, tk, 'GET', '/customer-form/' + contactKey)).data;
      if (c) {
        if (c.Name || c.name) custName = c.Name || c.name;
        // Pull the customer's stored TIN from its own custom fields (so B2B/B2G loads it).
        const cstr = (c.CustomFields2 && c.CustomFields2.Strings) || {};
        const tinKey = cf.byName['Buyer TIN'] || cf.byName['Customer TIN'];
        if (!custTIN && tinKey && cstr[tinKey]) custTIN = cstr[tinKey];
        if (!custTIN && (c.TIN || c.Tin)) custTIN = c.TIN || c.Tin;
      }
    } catch (e) {}
  }
  const lines = [];
  for (const l of (form.Lines || [])) {
    let itemName = (l.LineDescription || l.Description || '').split('\n')[0] || 'Service', code = '', unit = 'Each';
    if (l.Item) {
      let it = null;
      try { it = (await managerCall(ep, tk, 'GET', '/non-inventory-item-form/' + l.Item)).data; } catch (e) {}
      if (!it || it.error) { try { it = (await managerCall(ep, tk, 'GET', '/inventory-item-form/' + l.Item)).data; } catch (e) {} }
      if (it && !it.error) {
        itemName = it.Name || it.ItemName || itemName;
        // Inventory items expose the code as ItemCode; non-inventory as Code.
        code = it.ItemCode || it.itemCode || it.Code || it.code || '';
        unit = it.UnitName || unit;
        console.log(`   Line item resolved: name="${itemName}" code="${code}" (EFRIS goodsCode)`);
      } else {
        console.log(`   Line item ${l.Item}: could not resolve from Manager (no code)`);
      }
    }
    let rate = 0, taxName = '';
    if (l.TaxCode) {
      try { const tc = (await managerCall(ep, tk, 'GET', '/tax-code-form/' + l.TaxCode)).data; if (tc) { rate = (tc.Rates && tc.Rates[0]) || 0; taxName = tc.Name || ''; } } catch (e) {}
    }
    const qty = parseFloat(l.Qty || l.Quantity || 1) || 1;
    let price = parseFloat(l.SalesUnitPrice || l.UnitPrice || l.Amount || 0) || 0;
    // EFRIS (and the extension) work in tax-INCLUSIVE prices. Manager's default is
    // tax-exclusive ("Amounts are tax inclusive" unticked: AmountsIncludeTax absent),
    // where VAT is added on top, so convert to the inclusive unit price.
    if (rate && !taxInclusive) price = Math.round(price * (1 + rate / 100) * 100) / 100;
    // Manager line discount (exact amount or percentage), in the same inclusive money
    // as the price. buildT109 sends it to URA as a discount line (discountFlag 0).
    let discount = 0;
    const dAmt = parseFloat(l.DiscountAmount || 0) || 0, dPct = parseFloat(l.DiscountPercentage || 0) || 0;
    if (dAmt > 0) discount = (rate && !taxInclusive) ? dAmt * (1 + rate / 100) : dAmt;
    else if (dPct > 0) discount = qty * price * dPct / 100;
    discount = Math.round(Math.min(discount, qty * price) * 100) / 100;
    const lineTotal = qty * price - discount, taxAmount = rate ? lineTotal * rate / (100 + rate) : 0;
    lines.push({ ItemName: itemName, ItemCode: code, Qty: qty, UnitPrice: price, LineTotal: lineTotal, Discount: discount,
      TaxAmount: taxAmount, TaxRate: rate, TaxName: taxName, Unit: unit,
      EFRISCategoryId: '', EFRISCategoryName: '' });
  }
  const totalTax = lines.reduce((s, l) => s + l.TaxAmount, 0);
  // Always compute total from line items when we have them - Manager's stored display total can be stale
  const computedFromLines = lines.length > 0 ? lines.reduce((s, l) => s + l.LineTotal, 0) : 0;
  const total = computedFromLines || (disp.invoiceAmount && disp.invoiceAmount.value) || (disp.amount && disp.amount.value) || 0;
  const currency = (disp.invoiceAmount && disp.invoiceAmount.currency) || (disp.amount && disp.amount.currency) || 'UGX';
  return {
    DocType: docType,
    Reference: form.Reference || disp.reference || '',
    IssueDate: (form.IssueDate || form.Date || '').slice(0, 10) || disp.issueDate || disp.date || '',
    Customer: { Name: custName, Address: '', TIN: custTIN || '' },
    CustomerName: custName, CustomerTIN: custTIN || '', Currency: currency,
    ExchangeRate: form.ExchangeRate || 1, Total: total,
    AmountExcludingTax: total - totalTax, TaxAmount: totalTax,
    Notes: form.Description || '', Lines: lines, CustomFields: cfVals, Key: key,
    AmountsIncludeTax: taxInclusive, HasTaxCodes: (form.Lines || []).some(l => !!l.TaxCode)
  };
}

// ── RSA/AES crypto ────────────────────────────────────────────
// Key resolution order:
//   1. EFRIS_PRIVATE_KEY_B64 - base64-encoded key file (PEM or DER - detected automatically)
//   2. EFRIS_PRIVATE_KEY     - raw PEM content or file path
//   3. /app/keys/efris_private.pem - file baked into image (legacy)
let _pemContentFromEnv = null;
let _derKeyFromEnv = null;
const _pkB64 = process.env.EFRIS_PRIVATE_KEY_B64 || '';
if (_pkB64) {
  const decoded = Buffer.from(_pkB64, 'base64');
  // If the decoded bytes look like PEM text, use as PEM; otherwise treat as binary DER
  const asText = decoded.toString('utf8').replace(/\r/g, '');
  if (asText.trimStart().startsWith('-----BEGIN')) {
    _pemContentFromEnv = asText;
  } else {
    _derKeyFromEnv = decoded;
  }
} else {
  const _pkEnv = process.env.EFRIS_PRIVATE_KEY || '';
  if (_pkEnv.trim().startsWith('-----BEGIN')) { _pemContentFromEnv = _pkEnv.replace(/\\n/g, '\n'); }
}
const EFRIS_PRIVATE_KEY_PATHS = (!_pemContentFromEnv && !_derKeyFromEnv && process.env.EFRIS_PRIVATE_KEY && !process.env.EFRIS_PRIVATE_KEY.trim().startsWith('-----BEGIN'))
  ? [process.env.EFRIS_PRIVATE_KEY]
  // Local/Desktop editions have no env secret - drop the key at one of these paths
  // (all gitignored) and it's picked up with zero config. Cloud uses the B64 secret.
  : [
      path.join(__dirname, 'keys', 'efris_private.pem'),
      path.join(DATA_DIR, 'private_key.pem'),
      path.join(__dirname, 'data', 'private_key.pem'),
      '/app/keys/efris_private.pem',
    ];

// A key path from Settings must be a local .pem/.key file. UNC paths
// (\\host\share) are refused: opening one makes Windows send its credentials
// to that host.
function safeKeyPath(p) {
  const s = String(p || '').trim();
  if (!s || /^(\\\\|\/\/)/.test(s)) return false;
  return /\.(pem|key)$/i.test(s);
}

function loadPem(p) {
  if (_pemContentFromEnv) return _pemContentFromEnv;
  try {
    let content = fs.readFileSync(p, 'utf8');
    // A container-build `echo` can write literal \n instead of real newlines - fix it
    if (content.includes('\\n')) content = content.replace(/\\n/g, '\n');
    return content;
  } catch(e) { return null; }
}

// Node.js 20 + OpenSSL 3 removed RSA_PKCS1_PADDING. EFRIS uses PKCS1 v1.5, so
// we use RSA_NO_PADDING and strip the padding manually.
function pkcs1v15Decrypt(keyObj, encBuf) {
  const raw = crypto.privateDecrypt({ key: keyObj, padding: crypto.constants.RSA_NO_PADDING }, encBuf);
  if (raw[0] !== 0x00 || raw[1] !== 0x02) throw new Error('not PKCS1v15: bad header');
  let i = 2;
  while (i < raw.length && raw[i] !== 0x00) i++;
  if (i >= raw.length) throw new Error('not PKCS1v15: no zero separator');
  return raw.slice(i + 1);
}

function resolveAesKey(passwordDes, keyOverride) {
  const enc = Buffer.from(passwordDes, 'base64');
  const C = crypto.constants;
  const tried = [];

  const keyEntries = [];
  // Per-request key from Settings (file path or pasted PEM, optional passphrase).
  // Tried FIRST so a business's own configured key wins over env/baked-in keys.
  if (keyOverride && (keyOverride.pem || keyOverride.path)) {
    let pem = keyOverride.pem || null;
    if (!pem && keyOverride.path) {
      if (!safeKeyPath(keyOverride.path)) tried.push('config-key path refused (must be a local .pem or .key file, not a network path)');
      else { try { pem = fs.readFileSync(keyOverride.path, 'utf8'); } catch (e) { tried.push('config-key path not found: ' + keyOverride.path); } }
    }
    if (pem) {
      if (pem.includes('\\n')) pem = pem.replace(/\\n/g, '\n');
      const opt = { key: pem, format: 'pem' };
      if (keyOverride.passphrase) opt.passphrase = keyOverride.passphrase;
      try { keyEntries.push({ keyObj: crypto.createPrivateKey(opt), label: 'config-key' }); }
      catch (e) { tried.push('config-key: ' + (e.message || '').slice(0, 60)); }
    }
  }
  if (_derKeyFromEnv) {
    try {
      for (const type of ['pkcs8', 'pkcs1']) {
        try { keyEntries.push({ keyObj: crypto.createPrivateKey({ key: _derKeyFromEnv, format: 'der', type }), label: 'der-env-' + type }); break; } catch(e) {}
      }
    } catch(e) {}
  }
  if (_pemContentFromEnv) {
    try { keyEntries.push({ keyObj: crypto.createPrivateKey({ key: _pemContentFromEnv, format: 'pem' }), label: 'pem-env' }); } catch(e) { tried.push('pem-env: parse failed: ' + (e.message||'').slice(0,40)); }
  }
  for (const p of EFRIS_PRIVATE_KEY_PATHS) {
    const pem = loadPem(p);
    if (!pem) { tried.push(path.basename(p) + ': file not found'); continue; }
    try { keyEntries.push({ keyObj: crypto.createPrivateKey({ key: pem, format: 'pem' }), label: path.basename(p) }); } catch(e) { tried.push(path.basename(p) + ': parse failed: ' + (e.message||'').slice(0,40)); }
  }

  for (const { keyObj, label } of keyEntries) {
    // Try PKCS1 v1.5 first (EFRIS standard), then OAEP variants as fallback
    const attempts = [
      { name: 'PKCS1v15-manual', fn: () => pkcs1v15Decrypt(keyObj, enc) },
      { name: 'OAEP-SHA1',       fn: () => crypto.privateDecrypt({ key: keyObj, padding: C.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, enc) },
      { name: 'OAEP-SHA256',     fn: () => crypto.privateDecrypt({ key: keyObj, padding: C.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, enc) },
    ];
    for (const { name, fn } of attempts) {
      try {
        const dec = fn();
        const b64 = Buffer.from(dec.toString('utf8').trim(), 'base64');
        if ([16,24,32].includes(b64.length)) return { key: b64, keyObj, pem: keyObj, path: label, variant: name + '+base64' };
        if ([16,24,32].includes(dec.length)) return { key: dec, keyObj, pem: keyObj, path: label, variant: name + '+raw' };
        tried.push(label + '/' + name + ': raw ' + dec.length + 'b b64 ' + b64.length + 'b');
      } catch(e) { tried.push(label + '/' + name + ': ' + (e.message||'').slice(0,40)); }
    }
  }
  throw new Error('Could not derive a valid AES key from T104. Tried - ' + tried.join('  |  '));
}

function aesAlgo(keyBytes) {
  return keyBytes.length === 32 ? 'aes-256-ecb' : keyBytes.length === 24 ? 'aes-192-ecb' : 'aes-128-ecb';
}
// The Offline Enabler (TCS) talks plain base64 JSON to local clients: it has no
// T104 key exchange and does the encryption with URA itself. A session on the
// Enabler carries this empty key, and the AES helpers below then just base64.
const PLAIN_KEY = Buffer.alloc(0);
const isPlainKey = k => !k || k.length === 0;
function aesEncryptB64(plain, keyBytes) {
  if (isPlainKey(keyBytes)) return Buffer.from(plain, 'utf8').toString('base64');
  // Encrypt to a Buffer and base64-encode the WHOLE ciphertext once. Encoding
  // update() and final() separately and concatenating the two base64 strings
  // corrupts the output whenever update() emits a non-multiple-of-3 byte count
  // (mid-string '=' padding) - which only happens for larger multi-block
  // payloads like T131 stock-in, causing EFRIS rc 15 "Data decryption error".
  const c = crypto.createCipheriv(aesAlgo(keyBytes), keyBytes, null);
  const buf = Buffer.concat([c.update(Buffer.from(plain, 'utf8')), c.final()]);
  return buf.toString('base64');
}
function aesDecryptStr(b64, keyBytes) {
  if (isPlainKey(keyBytes)) { const b = Buffer.from(b64, 'base64'); return (b[0] === 0x1f && b[1] === 0x8b) ? zlib.gunzipSync(b, { finishFlush: zlib.constants.Z_SYNC_FLUSH }).toString('utf8') : b.toString('utf8'); }
  const d = crypto.createDecipheriv(aesAlgo(keyBytes), keyBytes, null);
  return d.update(b64, 'base64', 'utf8') + d.final('utf8');
}
// AES-decrypt to raw bytes, then gunzip if the payload is gzip-compressed.
// NOTE: some EFRIS responses (e.g. the T115 dictionary) are gzip+base64 with
// NO AES layer at all, so check for the gzip magic on the raw base64-decoded
// buffer BEFORE attempting AES (which would throw "wrong final block length").
function aesDecryptMaybeGzip(b64, keyBytes) {
  const rawBuf = Buffer.from(b64, 'base64');
  const isGzip = b => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
  if (isGzip(rawBuf)) return zlib.gunzipSync(rawBuf).toString('utf8');
  if (isPlainKey(keyBytes)) return rawBuf.toString('utf8');
  const d = crypto.createDecipheriv(aesAlgo(keyBytes), keyBytes, null);
  const buf = Buffer.concat([d.update(rawBuf), d.final()]);
  if (isGzip(buf)) return zlib.gunzipSync(buf).toString('utf8');
  return buf.toString('utf8');
}
function signSha1(content, privatePem) {
  return crypto.createSign('RSA-SHA1').update(content, 'utf8').sign(privatePem, 'base64');
}

function efrisEnvEnc(code, payloadObj, tin, deviceNo, aesKeyBytes, privatePem) {
  const json = typeof payloadObj === 'string' ? payloadObj : JSON.stringify(payloadObj);
  if (isPlainKey(aesKeyBytes)) return efrisEnv(code, json, tin, deviceNo);   // Offline Enabler: plain
  const contentB64 = aesEncryptB64(json, aesKeyBytes);
  const signature = signSha1(contentB64, privatePem);
  const env = efrisEnv(code, '', tin, deviceNo);
  env.data.content = contentB64;
  env.data.signature = signature;
  env.data.dataDescription = { codeType: '1', encryptCode: '2', zipCode: '0' };
  return env;
}

// Today in East Africa Time (UTC+3), whatever the server's own time zone.
function eatToday() { return new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10); }
// Uganda time (EAT, UTC+3) for a timestamp, whatever the server's time zone:
// { date: 'yyyy-MM-dd', time: 'HH:mm:ss', year: 'yyyy', month: 'MM' }.
function eatParts(ms) {
  const s = new Date((ms == null ? Date.now() : ms) + 3 * 3600000).toISOString();
  return { date: s.slice(0, 10), time: s.slice(11, 19), year: s.slice(0, 4), month: s.slice(5, 7) };
}
function eatStamp(ms) { const p = eatParts(ms); return p.date + ' ' + p.time; }

function efrisEnv(code, content, tin, deviceNo) {
  const cs = typeof content === 'string' ? content : JSON.stringify(content);
  return {
    data: { content: Buffer.from(cs).toString('base64'), signature: null, dataDescription: { codeType:'0', encryptCode:'1', zipCode:'0' } },
    globalInfo: {
      appId:'AP04', version:'1.1.20191201', dataExchangeId: Date.now().toString(),
      interfaceCode: code, requestCode:'TP',
      // East Africa Time (UTC+3). URA's online server tolerated UTC, but the Offline
      // Enabler rejects a requestTime more than 10 minutes off its clock (rc 28).
      requestTime: new Date(Date.now() + 3 * 3600000).toISOString().replace('T',' ').slice(0,19),
      responseCode:'TA', userName: tin, deviceMAC:'B47720524540',
      deviceNo, tin, brn:'', taxpayerID:'1',
      longitude:'32.6290', latitude:'0.3476', agentType:'0',
      extendField: { responsePaddingInfo:'0' }
    },
    returnStateInfo: { returnCode:'', returnMessage:'' }
  };
}

// ── Session cache ─────────────────────────────────────────────
const sessions = {};

// A cached session holds the AES key, so it is keyed on everything that produced
// it: TIN, device, endpoint (sandbox / production / Enabler) and a fingerprint of
// the private key used. A caller with only a TIN and device number cannot reuse
// someone else's session.
function sessionKey(tin, deviceNo, efrisBaseUrl, keyOverride) {
  const kh = keyOverride
    ? crypto.createHash('sha256').update(String(keyOverride.pem || '') + '\0' + String(keyOverride.path || '') + '\0' + String(keyOverride.passphrase || '')).digest('hex').slice(0, 16)
    : 'server-key';
  return tin + '_' + deviceNo + '|' + String(efrisBaseUrl || '') + '|' + kh;
}

async function getSession(tin, deviceNo, password, efrisBaseUrl, keyOverride) {
  const key = sessionKey(tin, deviceNo, efrisBaseUrl, keyOverride);
  const now = Date.now();
  if (sessions[key] && (now - sessions[key].ts) < 1800000) {
    console.log('   Reusing cached session');
    return sessions[key];
  }
  const snip = d => (typeof d === 'string' ? d : JSON.stringify(d) || '').slice(0, 400);
  const rcOf = r => r && r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnCode : undefined;
  const rmOf = r => r && r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnMessage : '';
  console.log('   New session for TIN: ' + tin);
  const t101 = await efrisCall(efrisBaseUrl, efrisEnv('T101', '', tin, deviceNo));
  // URA's gateway sometimes answers HTTP 200 with an HTML "Server Unreachable" page
  // while EFRIS itself is down: treat that as URA unreachable (network), so sales
  // are queued offline and sent later instead of failing.
  {
    const raw = typeof t101.data === 'string' ? t101.data : '';
    if (t101.status === 200 && /^\s*<(?:!doctype|html)/i.test(raw) && !/^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(efrisBaseUrl || '')) {
      const t = (raw.match(/<title>([^<]{1,80})<\/title>/i) || [])[1] || 'an HTML page';
      throw new Error('URA EFRIS network unreachable: the URA server answered with "' + t.trim() + '" instead of EFRIS. URA is down; sales are kept offline until it is back.');
    }
  }
  if (t101.status !== 200) {
    const bodyStr = (typeof t101.data === 'string' ? t101.data : JSON.stringify(t101.data) || '');
    const isHtml = /^\s*<(?:!doctype|html)/i.test(bodyStr) || /HTTP Status \d+/.test(bodyStr);
    const isLocal = /^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(efrisBaseUrl || '');
    let msg;
    if (isHtml && isLocal) {
      msg = 'The Offline Enabler at ' + efrisBaseUrl + ' returned HTTP ' + t101.status + ' (a web-server "Not Found" page, not an EFRIS response). '
          + 'The server is reachable but the EFRIS interface is not at that path. Check the Enabler URL ends in /efristcs/ws/tcsapp/getInformation and the TCS app is deployed and running, '
          + 'or set Enabler mode to "Fallback" (Settings) so URA is used when the Enabler is unavailable.';
    } else if (isHtml) {
      msg = 'EFRIS endpoint ' + efrisBaseUrl + ' returned HTTP ' + t101.status + ' (an HTML page, not an EFRIS response) - check the URL/path.';
    } else {
      msg = 'EFRIS T101 (session) failed at ' + efrisBaseUrl + ': HTTP ' + t101.status + '. ' + snip(t101.data).slice(0, 160);
    }
    const err = new Error(msg);
    err.endpointFailure = true;   // reachable-but-wrong: let fallback try the next target
    throw err;
  }
  let symKeyEnc = null, aesKey = null, privatePem = null;
  let _aesErr = null;
  const viaEnabler = /^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(efrisBaseUrl || '');
  if (viaEnabler) {
    aesKey = PLAIN_KEY;   // the Enabler has no T104 (rc 998) and expects plain JSON
  } else {
    // T104 now and then comes back without a key (URA side); ask once more before giving up.
    let t104 = null;
    for (let attempt = 0; attempt < 2 && !symKeyEnc; attempt++) {
      if (attempt) await new Promise(r => setTimeout(r, 1500));
      t104 = await efrisCall(efrisBaseUrl, efrisEnv('T104', '', tin, deviceNo));
      try { const c = JSON.parse(Buffer.from(t104.data.data.content, 'base64').toString()); symKeyEnc = c.passowrdDes || c.passwordDes; } catch(e) {}
    }
    if (!symKeyEnc) _aesErr = 'URA did not send a session key (T104' + (rcOf(t104) ? ' rc ' + rcOf(t104) + ' ' + rmOf(t104) : ', HTTP ' + (t104 && t104.status)) + '). URA may be busy; try again in a minute.';
    try { if (symKeyEnc) { const r = resolveAesKey(symKeyEnc, keyOverride); aesKey = r.key; privatePem = r.pem; } } catch(e) { _aesErr = e.message; console.log('   AES key error: ' + e.message); }
  }
  const t103 = await efrisCall(efrisBaseUrl, efrisEnv('T103', '', tin, deviceNo));
  if (rcOf(t103) && rcOf(t103) !== '00') {
    const code = rcOf(t103), rm = rmOf(t103);
    const isLocal = /^https?:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(efrisBaseUrl || '');
    const who = isLocal ? 'the Offline Enabler device (device no ' + deviceNo + ')' : 'this device (device no ' + deviceNo + ')';
    let hint = '';
    if (code === '402' || /key expired|device.*expired/i.test(rm || '')) {
      hint = ' - the device key for ' + who + ' has expired. Renew/re-initialise this device in the URA EFRIS portal (Device Management) to get a fresh key.'
           + (isLocal ? ' Meanwhile, set Enabler mode to "Fallback" (Settings) so receipts go to URA directly using your (valid) main device.' : '');
    }
    throw new Error('EFRIS login (T103) failed (' + code + '): ' + rm + hint);
  }
  if (!aesKey) throw new Error('No AES key - ' + (_aesErr || 'private key not found or could not decrypt the EFRIS session key.'));
  // T103 (login) also returns the taxpayer record and its registered tax types -
  // the only place VAT registration appears (T119 carries no VAT field). Keep it.
  let login = null;
  try {
    const c = t103.data && t103.data.data && t103.data.data.content;
    if (c) { const raw = efrisDecodeJson(c, aesKey); if (raw) login = JSON.parse(raw); }
  } catch (_) {}
  try {
    if (login) {
      const tt = login.taxType || (login.taxpayer && login.taxpayer.taxType) || [];
      const names = Array.isArray(tt) ? tt.map(t => t && (t.taxTypeName || t.name || t.taxTypeCode || JSON.stringify(t))).join(', ') : JSON.stringify(tt).slice(0, 200);
      console.log('   [T103 login] fields: ' + Object.keys(login).join(', ') + (names ? ' | tax types: ' + names : ''));
    } else console.log('   [T103 login] no readable content');
  } catch (_) {}
  const session = { symKeyEnc, aesKey, privatePem, login, ts: now, _args: [tin, deviceNo, password, efrisBaseUrl, keyOverride] };
  sessions[key] = session;
  return session;
}

// Discard the cached session so the next getSession() re-runs T101/T104/T103 and
// obtains a FRESH AES key. This is the recovery for rc:15 "Data decryption error":
// EFRIS returns rc:15 when the AES key it issued has rotated on its side but our
// 30-minute cache is still serving the old one. The write interfaces (T130/T109/
// T131) all used to "retry" rc:15 with the SAME cached key, which can never work -
// the key must be renewed first. Callers should invalidate, re-fetch the session,
// then retry once with the new key. The failed request never reached processing
// (it failed at the decryption stage), so retrying carries no duplicate-write risk.
function invalidateSession(tin, deviceNo) {
  const prefix = tin + '_' + deviceNo + '|';
  for (const k of Object.keys(sessions)) if (k.startsWith(prefix)) delete sessions[k];
}

// An encrypted EFRIS call that recovers from rc:15 ("Data decryption error": URA
// replaced the session key, e.g. the device logged in elsewhere). It renews the
// session, copies the fresh key INTO the caller's session object (so the caller's
// later calls use it too) and retries once. A request rejected at decryption was
// never processed, so the retry cannot create a duplicate.
async function efrisSecure(eu, code, payload, tin, deviceNo, session) {
  let r = await efrisCall(eu, efrisEnvEnc(code, payload, tin, deviceNo, session.aesKey, session.privatePem));
  const rc = r && r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnCode : null;
  if (rc !== '15' || !session._args) return r;
  console.log('   ' + code + ' rc 15 (stale session key) - renewing session and retrying once');
  invalidateSession(tin, deviceNo);
  const fresh = await getSession(...session._args);
  Object.assign(session, fresh);
  return efrisCall(eu, efrisEnvEnc(code, payload, tin, deviceNo, session.aesKey, session.privatePem));
}

// Build a per-request key override from a config/body object (Settings fields).
function keyOverrideFrom(c) {
  if (!c) return null;
  const path = (c.efrisKeyPath || '').trim();
  const pem = c.efrisKeyPem || '';
  const passphrase = c.efrisKeyPassphrase || c.efrisKeyPassword || '';
  if (!path && !pem) return null;
  return { path, pem, passphrase };
}

// ── EFRIS data dictionary (T115) - used to resolve currency codes ──
// T130's `currency` field wants the EFRIS internal currency code, NOT the ISO
// string ("UGX" is rejected with rc:680). We fetch the dictionary once, cache it
// on the session, and map ISO → EFRIS code.
// Brute-force decoder: EFRIS signals encryption/compression in the response's
// dataDescription, but it varies by interface. Try every combination and keep
// whichever yields valid JSON.
function efrisDecodeJson(b64, keyBytes) {
  const rawBuf = Buffer.from(b64, 'base64');
  const okJson = s => {
    if (!s || s.length < 2) return null;
    try { JSON.parse(s); return s; } catch(_) {}
    // Tolerate trailing bytes: trim to the last closing brace/bracket and retry.
    const cut = Math.max(s.lastIndexOf('}'), s.lastIndexOf(']'));
    if (cut > 0) { const t = s.slice(0, cut + 1); try { JSON.parse(t); return t; } catch(_) {} }
    return null;
  };
  // EFRIS gzip streams (Java GZIPOutputStream) are often not cleanly terminated,
  // so Node's gunzip needs Z_SYNC_FLUSH to avoid "unexpected end of file".
  const Z = { finishFlush: zlib.constants.Z_SYNC_FLUSH };
  const aesDec = buf => {
    const d = crypto.createDecipheriv(aesAlgo(keyBytes), keyBytes, null);
    return Buffer.concat([d.update(buf), d.final()]);
  };
  const attempts = [];
  attempts.push(() => zlib.gunzipSync(rawBuf, Z).toString('utf8'));              // gzip(json)
  attempts.push(() => aesDec(zlib.gunzipSync(rawBuf, Z)).toString('utf8'));      // gzip(AES(json)) ← EFRIS dictionary
  attempts.push(() => zlib.inflateSync(rawBuf, Z).toString('utf8'));            // zlib deflate
  attempts.push(() => zlib.inflateRawSync(rawBuf, Z).toString('utf8'));         // raw deflate
  attempts.push(() => rawBuf.toString('utf8'));                                  // plain
  attempts.push(() => aesDec(rawBuf).toString('utf8'));                          // AES(json)
  attempts.push(() => zlib.gunzipSync(aesDec(rawBuf), Z).toString('utf8'));      // AES(gzip(json))
  for (const fn of attempts) {
    try { const s = okJson(fn()); if (s) return s; } catch(_) {}
  }
  return null;
}

const _dictCache = {};
// The last dictionary that decoded, per TIN, so a bad response (e.g. a stale session
// key) does not leave goods registration without the currency codes.
const dictFile = tin => path.join(DATA_DIR, 'efris_dictionary_' + String(tin).replace(/[^0-9A-Za-z]/g, '') + '.json');
function savedDictionary(tin) { try { return JSON.parse(fs.readFileSync(dictFile(tin), 'utf8')); } catch (_) { return null; } }
async function getEfrisDictionary(tin, deviceNo, session, eu) {
  const key = tin + '_' + deviceNo;
  if (_dictCache[key]) return _dictCache[key];
  try {
    const t115 = await efrisSecure(eu, 'T115', {}, tin, deviceNo, session);
    const rc = t115.data && t115.data.returnStateInfo ? t115.data.returnStateInfo.returnCode : null;
    const rm = t115.data && t115.data.returnStateInfo ? t115.data.returnStateInfo.returnMessage : '';
    console.log(`   T115 outer rc: ${rc} - ${rm}`);
    if (t115.data && t115.data.data) {
      // Log how EFRIS says the response is encoded + the raw byte signature
      console.log(`   T115 dataDescription: ${JSON.stringify(t115.data.data.dataDescription || {})}`);
      if (t115.data.data.content) {
        const sig = Buffer.from(t115.data.data.content, 'base64').slice(0, 6).toString('hex');
        console.log(`   T115 content byte signature (hex): ${sig}`);
        const raw = efrisDecodeJson(t115.data.data.content, session.aesKey);
        if (raw) {
          const dict = JSON.parse(raw);
          console.log(`   T115 dictionary loaded - top-level keys: ${Object.keys(dict).join(', ')}`);
          _dictCache[key] = dict;
          try { writeFileAtomic(dictFile(tin), JSON.stringify(dict)); } catch (_) {}
          return dict;
        }
        console.log(`   (T115 content could not be decoded to JSON by any method)`);
      }
    }
  } catch(e) { console.log(`   (T115 dictionary fetch failed: ${e.message})`); }
  const saved = savedDictionary(tin);
  if (saved) { console.log('   Using the last saved EFRIS dictionary for this TIN'); return saved; }
  return null;
}

// Resolve an ISO currency (e.g. "UGX") to the EFRIS currency code expected by T130.
async function resolveEfrisCurrency(isoCode, tin, deviceNo, session, eu) {
  const iso = (isoCode || 'UGX').trim().toUpperCase();
  const dict = await getEfrisDictionary(tin, deviceNo, session, eu);
  if (!dict) return iso === 'UGX' ? '101' : iso; // no dictionary: UGX is EFRIS currency 101
  // Log currency-like sections so the exact format is visible in server logs.
  for (const [section, val] of Object.entries(dict)) {
    if (Array.isArray(val) && /rate|curr/i.test(section)) {
      console.log(`   T115 section "${section}" sample: ${JSON.stringify(val.slice(0, 2))}`);
    }
  }
  // Search every array for an entry matching this ISO code (exact value match first,
  // then substring within any field), and return its internal code.
  const pickCode = row => row.currencyCode || row.code || row.value || row.id || row.key;
  let exact = null, partial = null;
  for (const [section, val] of Object.entries(dict)) {
    if (!Array.isArray(val)) continue;
    for (const row of val) {
      if (!row || typeof row !== 'object') continue;
      const vals = Object.values(row).map(x => String(x).toUpperCase());
      if (vals.includes(iso)) { exact = exact || { section, code: pickCode(row), row }; }
      else if (!partial && vals.some(v => v.includes(iso))) { partial = { section, code: pickCode(row), row }; }
    }
  }
  const hit = exact || partial;
  if (hit) {
    console.log(`   Currency "${iso}" → EFRIS code "${hit.code}" (section: ${hit.section}, ${exact?'exact':'partial'} match)`);
    return String(hit.code);
  }
  console.log(`   Currency "${iso}" not found in T115 dictionary - sending ISO as-is`);
  return iso;
}

// Reverse of resolveEfrisCurrency: map an EFRIS currency CODE (e.g. "102") back to
// its ISO code (e.g. "USD") using the T115 currencyType dictionary (name=ISO,
// value=code). Returns '' if it can't be resolved. UGX is code "101".
async function efrisCurrencyIsoFromCode(code, tin, deviceNo, session, eu) {
  const c = String(code || '').trim();
  if (!c || c === '101') return 'UGX';
  const dict = await getEfrisDictionary(tin, deviceNo, session, eu);
  if (!dict) return '';
  for (const val of Object.values(dict)) {
    if (!Array.isArray(val)) continue;
    for (const row of val) {
      if (row && typeof row === 'object' && String(row.value) === c && /^[A-Z]{3}$/.test(String(row.name || ''))) return row.name;
    }
  }
  return '';
}

// Return the list of valid EFRIS measure units from the T115 dictionary.
// The authoritative source is the "rateUnit" section (value=code, name=label) -
// we do NOT hardcode this so it always matches what the taxpayer's EFRIS accepts.
async function getEfrisMeasureUnits(tin, deviceNo, session, eu) {
  const dict = await getEfrisDictionary(tin, deviceNo, session, eu);
  if (!dict) return [];
  // The units live in a section keyed by something like "rateUnit". Be tolerant:
  // pick the array whose rows have short {value} codes and a descriptive name.
  const candidates = ['rateUnit', 'measureUnit', 'unit', 'goodsUnit'];
  let list = null;
  for (const k of candidates) { if (Array.isArray(dict[k])) { list = dict[k]; break; } }
  if (!list) {
    // Fallback: any section whose rows look like {value, name} unit entries
    for (const v of Object.values(dict)) {
      if (Array.isArray(v) && v.length && v[0] && v[0].value && v[0].name && String(v[0].value).length <= 4) { list = v; break; }
    }
  }
  if (!list) return [];
  return list.map(r => ({ code: String(r.value || r.code || ''), name: String(r.name || r.description || '') }))
             .filter(u => u.code);
}

// Is a given unit code valid per the EFRIS dictionary?
async function isValidEfrisUnit(code, tin, deviceNo, session, eu) {
  if (!code) return false;
  const units = await getEfrisMeasureUnits(tin, deviceNo, session, eu);
  if (!units.length) return null; // unknown - dictionary unavailable
  const c = String(code).trim().toUpperCase();
  return units.some(u => u.code.toUpperCase() === c);
}

// ── Registered-goods map (T127) ──────────────────────────────────────────────
// Returns { GOODSCODE -> { measureUnit, commodityCategoryId, commodityCategoryName,
// unitPrice, goodsName } } for goods registered under this taxpayer. This is the
// authoritative source for a line's unit of measure: invoice/credit-note lines MUST
// echo the SAME measureUnit the item was registered with, otherwise EFRIS renders the
// wrong unit (e.g. "Stick" when we default to 101) and credit notes are rejected with
// "unit of measure does not match goods maintenance". Cached briefly per TIN.
const _goodsMapCache = {};
async function getRegisteredGoodsMap(tin, deviceNo, session, eu) {
  const cacheKey = String(tin || '');
  const now = Date.now();
  const cached = _goodsMapCache[cacheKey];
  if (cached && (now - cached.ts) < 120000) return cached.map;
  const map = {};
  try {
    let pageNo = 1;
    for (let guard = 0; guard < 25; guard++) {
      const payload = { goodsCode: '', goodsName: '', commodityCategoryCode: '', pageNo: String(pageNo), pageSize: '99' };
      const r = await efrisSecure(eu, 'T127', payload, tin, deviceNo, session);
      const rc = r.data?.returnStateInfo?.returnCode;
      if (rc !== '00' && rc !== '45') break;
      let items = [];
      if (r.data?.data?.content) {
        try {
          const parsed = JSON.parse(aesDecryptStr(r.data.data.content, session.aesKey));
          items = parsed.records || parsed.goodsList || parsed.list || (Array.isArray(parsed) ? parsed : []);
        } catch (e) { break; }
      }
      if (!items.length) break;
      for (const it of items) {
        const code = String(it.goodsCode || it.itemCode || it.code || '').trim();
        if (!code) continue;
        map[code.toUpperCase()] = {
          measureUnit: String(it.measureUnit || it.unitOfMeasure || it.unit || '').trim(),
          commodityCategoryId: String(it.commodityCategoryId || it.commodityCategoryCode || '').trim(),
          commodityCategoryName: String(it.commodityCategoryName || '').trim(),
          unitPrice: it.unitPrice != null ? String(it.unitPrice) : '',
          goodsName: String(it.goodsName || it.name || '').trim(),
          // Tax fields, so a credit note re-uses the SAME tax rate as the original
          // invoice (URA 1443 rejects a mismatch).
          taxRate: it.taxRate != null ? String(it.taxRate) : '',
          isExempt: it.isExempt != null ? String(it.isExempt) : '',
          isZeroRate: it.isZeroRate != null ? String(it.isZeroRate) : '',
        };
      }
      if (items.length < 99) break;
      pageNo++;
    }
  } catch (e) { console.log(`   getRegisteredGoodsMap error: ${e.message}`); }
  // Persist to disk on success so OFFLINE submissions (via the Enabler) can still
  // resolve each line's registered unit without a live T127 call. If the live fetch
  // came back empty (e.g. URA/Enabler unreachable), fall back to the disk cache.
  const cacheFile = path.join(DATA_DIR, 'goods_cache_' + cacheKey.replace(/[^0-9A-Za-z]/g, '') + '.json');
  if (Object.keys(map).length) {
    try { fs.writeFileSync(cacheFile, JSON.stringify(map)); } catch (_) {}
    _goodsMapCache[cacheKey] = { ts: now, map };
    return map;
  }
  try {
    const disk = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    if (disk && Object.keys(disk).length) { console.log('   getRegisteredGoodsMap: using on-disk cache (offline)'); _goodsMapCache[cacheKey] = { ts: now, map: disk }; return disk; }
  } catch (_) {}
  _goodsMapCache[cacheKey] = { ts: now, map };
  return map;
}

// Annotate invoice/credit-note lines with the EFRIS-registered unit + commodity so
// buildT109 stops defaulting unitOfMeasure to '101' (Stick). Mutates lines in place.
function annotateLinesWithRegisteredGoods(invoice, goodsMap) {
  if (!invoice || !Array.isArray(invoice.Lines) || !goodsMap) return;
  for (const l of invoice.Lines) {
    const code = String(l.ItemCode || l.Code || l.itemCode || '').trim().toUpperCase();
    const g = code && goodsMap[code];
    if (!g) continue;
    if (g.measureUnit && !l.EFRISUnitOfMeasure) l.EFRISUnitOfMeasure = g.measureUnit;
    if (g.commodityCategoryId && !l.EFRISCommodityCode) l.EFRISCommodityCode = g.commodityCategoryId;
    if (g.commodityCategoryName && !l.EFRISCommodityName) l.EFRISCommodityName = g.commodityCategoryName;
    // Tax category from the registered good, so buildT109/T108 emits the SAME tax
    // rate the good was registered (and originally invoiced) with. Only set it when
    // the line carries none, so an explicit caller choice is never overridden.
    if (!l.TaxName && !l.TaxCode) {
      const tn = taxNameFromRegisteredGood(g);
      if (tn) l.TaxName = tn;
    }
  }
}
// Map a registered good's tax fields to a TaxName that buildT109 classifies.
function taxNameFromRegisteredGood(g) {
  const truthy = v => /^(1|101|yes|true|y)$/i.test(String(v == null ? '' : v).trim());
  if (truthy(g.isZeroRate)) return 'Zero Rated';
  if (truthy(g.isExempt))   return 'Exempt';
  const tr = String(g.taxRate == null ? '' : g.taxRate).trim();
  if (tr === '-' ) return 'Exempt';
  const n = parseFloat(tr);
  if (n > 0) return 'Standard VAT 18%';
  if (n === 0) return 'Zero Rated';
  return '';
}

// Resolve a line's EFRIS unit-of-measure code. Priority:
//   1. EFRISUnitOfMeasure - set from the registered goods record (authoritative).
//   2. cfg.defaultUnitOfMeasure - taxpayer default (ignored if it's the bad '101').
//   3. The line's Manager unit name resolved against uom.json (e.g. "Piece" -> PCE).
//   4. 'PCE' (Piece) - a safe default. NEVER '101' (that renders as "Stick").
function resolveLineUom(l, cfg) {
  const reg = String(l.EFRISUnitOfMeasure || '').trim();
  if (reg) return reg;
  const def = String((cfg && cfg.defaultUnitOfMeasure) || '').trim();
  if (def && def !== '101') return def;
  const unitName = String(l.Unit || l.UnitName || '').trim().toLowerCase();
  if (unitName) {
    try {
      const u = getUnits().find(x => String(x.name || x.desc || '').trim().toLowerCase() === unitName);
      if (u && u.code) return u.code;
    } catch (e) {}
  }
  return 'PCE';
}

// The discount on a line, in the same (VAT-inclusive) money as UnitPrice. The
// extension sends _discount; a Manager document carries Discount. When LineTotal is
// below qty x unitPrice, the difference is the discount actually applied (this also
// covers a discount entered on a VAT-exclusive price). 0 = no discount.
function lineDiscount(l, qty, unitPrice) {
  const given = parseFloat(l._discount != null ? l._discount : (l.Discount != null ? l.Discount : l.DiscountAmount)) || 0;
  if (!(given > 0)) return 0;
  const full = qty * unitPrice;
  const lt = parseFloat(l.LineTotal);
  let d = (isFinite(lt) && lt >= 0 && lt < full - 0.005) ? full - lt : given;
  d = Math.round(Math.min(d, full) * 100) / 100;
  return d > 0 ? d : 0;
}

// buyerType for a government buyer. URA's API doc v1.1 (2020) listed "0: B2B or
// B2G"; the EFRIS v23 field list used by current integrators defines 3 = B2G
// (paybillug ura-efris-php-sdk CustomTypes::buyerType: 0 B2B, 1 B2C, 2 Foreigner,
// 3 B2G; Ernestbent URA-EFRIS sends "B2G": "3"). No T115 dictionary dump with a
// buyerType list was available to confirm it. A business whose EFRIS build
// rejects 3 can set config b2gBuyerType '0' to go back to the old value.
const BUYER_TYPE_B2G = '3';
function b2gBuyerType(cfg) {
  const o = String((cfg && cfg.b2gBuyerType) || '').trim();
  return (o === '0' || o === '3') ? o : BUYER_TYPE_B2G;
}

function buildT109(invoice, cfg) {
  const vat = !!cfg.vatRegistered;
  const isRefund = !!(invoice.IsRefund || invoice.isRefund);
  // Debit note: a T109 of invoiceType 4 pointing at the ORIGINAL invoice's EFRIS id.
  const debitOf = invoice._debitOf && invoice._debitOf.oriInvoiceId ? invoice._debitOf : null;
  const r2 = n => (Math.round((parseFloat(n) || 0) * 100) / 100).toFixed(2);
  const lines = invoice.Lines || [];
  const goodsDetails = [];
  lines.forEach((l, i) => {
    const qty = parseFloat(l.Qty || 1) || 1;
    const unitPrice = parseFloat(l.UnitPrice || 0) || 0;
    // A discounted line goes to URA as the item at its FULL amount (discountFlag 1)
    // followed by a discount line (discountFlag 0) carrying the negative discount,
    // so unitPrice x qty == total on the item line. See lineDiscount().
    const discount = lineDiscount(l, qty, unitPrice);
    const total = discount > 0 ? qty * unitPrice : (parseFloat(l.LineTotal || (unitPrice * qty)) || 0);
    const taxName = String(l.TaxName || l.TaxCode || invoice.TaxName || '').toLowerCase();
    const lineTax = parseFloat(l.TaxAmount || 0) || 0;
    let taxRate, tax, vatFlag, catCode;
    // Excise: a line is excisable if its item config carries excise data or the tax
    // name mentions excise. Per v24.0.1: exciseFlag '1' needs exciseRate, exciseRule
    // and exciseTax; exciseRule '2' (specific/quantity duty) also needs exciseUnit
    // and exciseCurrency ('1' = ad valorem). Values come from the item config so we
    // never guess a rate.
    const isExcise = /excise/.test(taxName) || l.ExciseFlag === '1' || !!(l.ExciseRate || l.ExciseTax);
    const vat18 = amt => r2(amt - amt / 1.18);   // VAT inside a VAT-inclusive 18% amount
    if (vat && /deemed/.test(taxName)) { taxRate = '0.18'; tax = vat18(total); vatFlag = '1'; catCode = '04'; }  // D - Deemed 18%
    else if (vat && /exempt/.test(taxName)) { taxRate = '-'; tax = '0'; vatFlag = '1'; catCode = '03'; }
    else if (vat && /zero/.test(taxName)) { taxRate = '0'; tax = '0'; vatFlag = '1'; catCode = '02'; }
    else if (vat && (/standard/.test(taxName) || lineTax > 0)) { taxRate = '0.18'; tax = vat18(total); vatFlag = '1'; catCode = '01'; }
    else if (vat) { taxRate = '-'; tax = '0'; vatFlag = '1'; catCode = '03'; }
    // Non-VAT-registered taxpayer: issues e-receipts (invoiceKind=2).
    // Per EFRIS developer docs taxRule field: OOS = Out of Scope (correct for
    // non-VAT businesses). catCode '05' = OOS in taxCategoryCode (01=Standard,
    // 02=Zero, 03=Exempt, 04=Deemed, 05=OOS). Codes 03/04 are rejected on
    // e-receipts with URA 3087 "Exempt/Deemed not allowed for receipt".
    else { taxRate = '-'; tax = '0'; vatFlag = '2'; catCode = '05'; }
    // taxRule per developer.efris.dev: STANDARD | EXEMPT | ZERORATED | OOS | DIM
    let taxRule;
    if (!vat) taxRule = 'OOS';
    else if (catCode === '01') taxRule = 'STANDARD';
    else if (catCode === '02') taxRule = 'ZERORATED';
    else if (catCode === '04') taxRule = 'DEEMED';
    else taxRule = 'EXEMPT';
    const g = {
      item: String(l.ItemName || l.Description || 'Service').slice(0, 100),
      itemCode: String(l.ItemCode || l.Code || ('ITEM' + (i + 1))).slice(0, 50),
      qty: String(qty), unitOfMeasure: resolveLineUom(l, cfg),
      unitPrice: r2(unitPrice), total: r2(total), taxRate, taxRule, tax: String(tax),
      discountTotal: discount > 0 ? r2(-discount) : '', discountTaxRate: discount > 0 ? taxRate : '', orderNumber: '',
      discountFlag: discount > 0 ? '1' : '2', deemedFlag: (catCode === '04' ? '1' : '2'), exciseFlag: (isExcise ? '1' : '2'),
      categoryId: '', categoryName: '',
      goodsCategoryId: l.EFRISCommodityCode || cfg.defaultCommodityCode || '',
      goodsCategoryName: l.EFRISCommodityName || cfg.defaultCommodityName || '',
      vatApplicableFlag: vatFlag, _catCode: catCode
    };
    // Excise duty fields (only when the line is excisable) - structure per v24.0.1
    // goodsDetails validation (codes 1231-1259). Values sourced from item config.
    if (isExcise) {
      const exRule = String(l.ExciseRule || '1');   // '1' ad valorem, '2' specific
      const exRate = parseFloat(l.ExciseRate || 0) || 0;
      g.exciseRate = String(l.ExciseRate != null && l.ExciseRate !== '' ? l.ExciseRate : '');
      g.exciseRule = exRule;
      // Compute the excise amount when not supplied: ad valorem (rule 1) = rate x
      // line total; specific (rule 2) = rate x quantity.
      let exTax = (l.ExciseTax != null && l.ExciseTax !== '') ? parseFloat(l.ExciseTax) || 0
                : (exRule === '2' ? exRate * qty : exRate * total);
      g.exciseTax = r2(exTax);
      if (exRule === '2') {
        g.exciseUnit = String(l.ExciseUnit || '');
        g.exciseCurrency = String(l.ExciseCurrency || invoice.Currency || 'UGX');
      }
    }
    // Deemed VAT / VAT Exemption PROJECT fields (only when the line is on a project)
    // - v24.0.1 codes 3038-3046. deemedExemptCode <=3, vatProjectId <=18,
    // vatProjectName <=100. Provided per line by the goods/customer config.
    if (l.VatProjectId || l.DeemedExemptCode) {
      g.deemedExemptCode = String(l.DeemedExemptCode || '');
      g.vatProjectId     = String(l.VatProjectId || '').slice(0, 18);
      g.vatProjectName   = String(l.VatProjectName || '').slice(0, 100);
    }
    goodsDetails.push(g);
    if (discount > 0) {
      // The discount line: same item and code, no qty/unitPrice, total = -discount.
      // Its tax is the difference between the tax on the discounted amount and the
      // tax on the full amount, so the pair carries exactly the VAT on what was paid.
      const after = total - discount;
      const dTax = taxRate === '0.18' ? r2(parseFloat(vat18(after)) - parseFloat(tax)) : '0';
      goodsDetails.push({
        // URA 1178: the discount line's item is the item name plus " (Discount)", or
        // plus " (deemed) (Discount)" on a deemed line.
        ...g, item: String(g.item || '') + (g.deemedFlag === '1' ? ' (deemed)' : '') + ' (Discount)',
        qty: '', unitPrice: '', total: r2(-discount), tax: String(dTax),
        discountTotal: '', discountTaxRate: taxRate, discountFlag: '0',
        ...(g.exciseTax !== undefined ? { exciseTax: '0' } : {}),
      });
    }
  });
  // orderNumber is the position in goodsDetails (discount lines included).
  goodsDetails.forEach((g, i) => { g.orderNumber = String(i); });
  const gross = goodsDetails.reduce((s, g) => s + parseFloat(g.total), 0);
  const taxAmount = goodsDetails.reduce((s, g) => s + (parseFloat(g.tax) || 0), 0);
  const net = gross - taxAmount;
  // One taxDetails row per tax category (a sale mixing standard-rated and exempt
  // lines must report each category's own net/tax/gross).
  const taxGroups = [];
  for (const g of goodsDetails) {
    let t = taxGroups.find(x => x.catCode === g._catCode);
    if (!t) taxGroups.push(t = { catCode: g._catCode, taxRate: g.taxRate, gross: 0, tax: 0 });
    t.gross += parseFloat(g.total) || 0; t.tax += parseFloat(g.tax) || 0;
  }
  goodsDetails.forEach(g => delete g._catCode);
  // URA's documented format (yyyy-MM-dd HH:mm:ss). URA online also took dd/MM/yyyy,
  // but the Offline Enabler validates it itself and rejects anything else (rc 1130).
  // Always Uganda time, whatever the server's time zone. A sale queued offline
  // carries _saleAt (when it was made) and is dated then, not when it was sent.
  const saleMs = invoice._saleAt ? Date.parse(invoice._saleAt) : NaN;
  const at = eatParts(isNaN(saleMs) ? Date.now() : saleMs);
  const issueRaw = String(invoice.IssueDate || '');
  const issueDay = /^\d{4}-\d{2}-\d{2}/.test(issueRaw) ? issueRaw.slice(0, 10)
    : (issueRaw && !isNaN(Date.parse(issueRaw))) ? eatParts(Date.parse(issueRaw)).date : at.date;
  const issuedDate = issueDay + ' ' + at.time;

  // ── Buyer details - supports B2C, B2B, B2G, Foreign ──────────────────────
  // buyerType: '0'=B2B (taxpayer with TIN), '1'=B2C, '2'=Foreigner, '3'=B2G (see BUYER_TYPE_B2G)
  const custType = String(invoice.CustomerType || 'b2c').toLowerCase();
  const hasTin = !!(invoice.CustomerTIN && String(invoice.CustomerTIN).trim());
  let buyerType, buyerTin, buyerPassportNum, buyerCitizenship, buyerLegalName, buyerBusinessName, buyerAddress;
  if (custType === 'b2b') {
    buyerType = '0'; buyerTin = String(invoice.CustomerTIN || ''); buyerPassportNum = '';
    buyerCitizenship = ''; buyerLegalName = invoice.CustomerName || '';
    buyerBusinessName = invoice.CustomerName || ''; buyerAddress = invoice.CustomerAddress || '';
  } else if (custType === 'b2g') {
    buyerType = b2gBuyerType(cfg); buyerTin = String(invoice.CustomerTIN || ''); buyerPassportNum = '';
    buyerCitizenship = ''; buyerLegalName = invoice.CustomerName || 'Government Entity';
    buyerBusinessName = invoice.CustomerDept || invoice.CustomerName || 'Government';
    buyerAddress = invoice.CustomerAddress || '';
  } else if (custType === 'foreign') {
    buyerType = '2'; buyerTin = ''; buyerPassportNum = String(invoice.PassportNum || '');
    buyerCitizenship = String(invoice.Nationality || '');
    buyerLegalName = invoice.CustomerName || 'Foreign Visitor';
    buyerBusinessName = invoice.CustomerName || ''; buyerAddress = invoice.CustomerAddress || '';
  } else {
    // B2C default - walk-in local customer. Some consumers do have a TIN; when one
    // is supplied, treat as a taxpayer (buyerType 0) so EFRIS records it.
    if (hasTin) { buyerType = '0'; buyerTin = String(invoice.CustomerTIN || ''); }
    else { buyerType = '1'; buyerTin = ''; }
    buyerPassportNum = '';
    buyerCitizenship = ''; buyerLegalName = invoice.CustomerName || 'Walk-in Customer';
    buyerBusinessName = invoice.CustomerName || ''; buyerAddress = '';
  }

  // Non-VAT e-receipts (invoiceKind=2): no tax categories apply - omit taxDetails
  // entirely. The taxRule='OOS' on each goodsDetails line carries the designation.
  const taxDetails = vat
    ? taxGroups.map(t => ({ taxCategoryCode: t.catCode, netAmount: r2(t.gross - t.tax), taxRate: t.taxRate, taxAmount: r2(t.tax), grossAmount: r2(t.gross) }))
    : [];
  return {
    sellerDetails: { tin: cfg.tin, ninBrn: cfg.brn || '', legalName: cfg.businessName || cfg.tradeName || '', businessName: cfg.tradeName || cfg.businessName || '', address: cfg.businessAddress || 'Uganda', mobilePhone: cfg.phone || '', linePhone: '', emailAddress: cfg.email || '', placeOfBusiness: cfg.businessAddress || 'Uganda', referenceNo: (isRefund ? 'CN-' : '') + (invoice.Reference || '') },
    basicInformation: { invoiceNo: '', antifakeCode: '', deviceNo: cfg.deviceNo, issuedDate, operator: invoice.Operator || cfg.issuedBy || cfg.operator || 'Cashier', currency: invoice.Currency || 'UGX', oriInvoiceId: debitOf ? String(debitOf.oriInvoiceId) : (invoice.OriginalFDN || ''), invoiceType: debitOf ? '4' : '1', invoiceKind: vat ? '1' : '2', dataSource: '103', invoiceIndustryCode: '101', isBatch: '0', isRefund: isRefund && !debitOf ? '1' : '0' },
    buyerDetails: { buyerTin, buyerNinBrn: '', buyerPassportNum, buyerLegalName, buyerBusinessName, buyerAddress, buyerEmail: invoice.CustomerEmail || '', buyerMobilePhone: invoice.CustomerPhone || '', buyerLinePhone: '', buyerPlaceOfBusi: invoice.CustomerDept || '', buyerType, buyerCitizenship, buyerSector: '', buyerReferenceNo: '' },
    goodsDetails,
    taxDetails,
    summary: { netAmount: r2(net), taxAmount: r2(taxAmount), grossAmount: r2(gross), itemCount: String(goodsDetails.filter(g => g.discountFlag !== '0').length) /* URA 1304: goods lines minus discount lines */, modeCode: '1', remarks: (isRefund && invoice.CreditNoteReason ? invoice.CreditNoteReason + (invoice.Notes ? '. ' + invoice.Notes : '') : invoice.Notes || ''), qrCode: '' },
    payWay: (invoice.PayWays && invoice.PayWays.length)
      ? invoice.PayWays.map((pw, i) => ({ paymentMode: String(pw.mode || '101'), paymentAmount: r2(pw.amount || 0), orderNumber: String(i + 1) }))
      : [{ paymentMode: String(invoice.PaymentMode || '101'), paymentAmount: r2(gross), orderNumber: '1' }],
    extend: {},
    // Deemed VAT / VAT-Exemption summary list (v24.0.1 T190, codes 3371+). Only
    // emitted when the caller supplies it, so we never send a malformed collection.
    ...(invoice.VatDeemedExemptDtlList && invoice.VatDeemedExemptDtlList.length
        ? { vatDeemedExemptDtlList: invoice.VatDeemedExemptDtlList } : {})
  };
}

// ── Build a T108 credit-note application ─────────────────────────────────────
// EFRIS credit notes reuse the T109 line/buyer/tax structure but: (1) amounts are
// NEGATIVE (qty, total, tax, summary), (2) lines MUST carry the registered unit of
// measure (annotate the invoice first), and (3) they add credit-note fields keyed on
// the ORIGINAL invoice (oriInvoiceId/oriInvoiceNo) plus a reasonCode. Lands in the
// URA Credit Notes register (status Pending until URA approves).
//   opts: { oriInvoiceId, oriInvoiceNo, reasonCode, reason, sellersReferenceNo }
function buildT108(invoice, cfg, opts) {
  const o = opts || {};
  const base = buildT109({ ...invoice, IsRefund: true }, cfg);
  const neg = s => { const n = parseFloat(s) || 0; return (n === 0 ? 0 : -Math.abs(n)).toFixed(2); };
  const negQty = q => { const n = parseFloat(q) || 0; return String(n === 0 ? 0 : -Math.abs(n)); };
  // A discounted item and its discount line keep their relationship with the signs
  // reversed: the item line is negative and the discount line (and the item's
  // discountTotal) positive, so each pair still nets to the discounted amount.
  const flip = s => { const n = parseFloat(s) || 0; return (n === 0 ? 0 : -n).toFixed(2); };
  const goodsDetails = base.goodsDetails.map(g => String(g.discountFlag) === '0'
    ? { ...g, total: flip(g.total), tax: String(flip(g.tax)) }
    : {
      ...g,
      qty: negQty(g.qty),
      total: neg(g.total),
      tax: String(neg(g.tax)),
      ...(String(g.discountFlag) === '1' ? { discountTotal: flip(g.discountTotal) } : {}),
    });
  const taxDetails = (base.taxDetails || []).map(t => ({
    ...t,
    netAmount: neg(t.netAmount),
    taxAmount: neg(t.taxAmount),
    grossAmount: neg(t.grossAmount),
  }));
  const summary = {
    ...base.summary,
    netAmount: neg(base.summary.netAmount),
    taxAmount: neg(base.summary.taxAmount),
    grossAmount: neg(base.summary.grossAmount),
    remarks: o.remarks || base.summary.remarks || '',
  };
  const payWay = (base.payWay || []).map(p => ({ ...p, paymentAmount: neg(p.paymentAmount) }));
  const applicationTime = eatStamp();   // Uganda time, whatever the server's zone
  return {
    oriInvoiceId: String(o.oriInvoiceId || ''),
    oriInvoiceNo: String(o.oriInvoiceNo || ''),
    reasonCode: String(o.reasonCode || '102'),
    reason: String(o.reason || ''),
    applicationTime,
    invoiceApplyCategoryCode: '101',         // 101 = credit note against an original invoice
    currency: invoice.Currency || 'UGX',
    contactName: '', contactMobileNum: '', source: '103', remarks: o.remarks || '',
    sellersReferenceNo: String(o.sellersReferenceNo || invoice.Reference || ''),
    basicInformation: base.basicInformation,
    sellerDetails: base.sellerDetails,
    buyerDetails: base.buyerDetails,
    goodsDetails,
    taxDetails,
    summary,
    payWay,
    importServicesSeller: {},
    extend: {},
  };
}

// ══════════════════════════════════════════════════════════════
//  GOODS TREE ROUTES (existing)
// ══════════════════════════════════════════════════════════════

const RELAY_STARTED_AT = new Date().toISOString();   // lets open pages notice a restart
app.get('/api/health', (req, res) => {
  const b64 = process.env.EFRIS_PRIVATE_KEY_B64 || '';
  const raw = process.env.EFRIS_PRIVATE_KEY || '';
  let keyParseError = null, keyOk = false, keyFormat = 'none';
  if (_derKeyFromEnv) {
    keyFormat = 'der';
    for (const type of ['pkcs8', 'pkcs1']) {
      try { crypto.createPrivateKey({ key: _derKeyFromEnv, format: 'der', type }); keyOk = true; keyFormat = 'der-' + type; break; } catch(e) { keyParseError = e.message; }
    }
  } else if (_pemContentFromEnv) {
    keyFormat = 'pem';
    try { crypto.createPrivateKey({ key: _pemContentFromEnv, format: 'pem' }); keyOk = true; } catch(e) { keyParseError = e.message; }
  } else {
    // Key supplied as a file path (e.g. local dev: EFRIS_PRIVATE_KEY=C:\...\key.pem).
    // Actually load and parse it so the health report reflects file-based keys too.
    for (const p of EFRIS_PRIVATE_KEY_PATHS) {
      const pem = loadPem(p);
      if (!pem) { keyParseError = path.basename(p) + ': file not found'; continue; }
      keyFormat = 'pem-file';
      try { crypto.createPrivateKey({ key: pem, format: 'pem' }); keyOk = true; keyParseError = null; break; }
      catch(e) { keyParseError = path.basename(p) + ': ' + e.message; }
    }
  }
  // Public callers only learn that the relay is up and whether a key loads;
  // the format and error details need an admin (or the service key).
  if (!auth.can(auth.permissionsFor(req.auth), '*')) return res.json({ status: 'ok', startedAt: RELAY_STARTED_AT, key: { key_parse_ok: keyOk } });
  res.json({ startedAt: RELAY_STARTED_AT,
    status: 'ok',
    uptime: process.uptime(),
    key: {
      b64_length: b64.length,
      raw_length: raw.length,
      key_format: keyFormat,
      key_parse_ok: keyOk,
      key_parse_error: keyParseError,
    }
  });
});

// ── Daily error/activity logs - for the team or support to troubleshoot ──
// The raw day files hold every business's entries, so only owners and the
// service principal may read them (business admins use the scoped activity
// view, export and support bundle). The output is masked line by line, also
// for files written before the logger masked its entries.
function ownerOnly(req, res) {
  const u = req.auth;
  if (u && (u.owner || u.service)) return true;
  res.status(403).json({ success: false, error: 'Only an owner can read the raw relay logs', permission: 'owner' });
  return false;
}
app.get('/api/admin/logs', (req, res) => {
  if (!ownerOnly(req, res)) return;
  res.json({ days: logger.listDays() });
});
app.get('/api/admin/logs/:day', (req, res) => {
  if (!ownerOnly(req, res)) return;
  const content = logger.readDay(req.params.day);
  if (content === null) return res.status(404).json({ error: 'No log for that day' });
  const m = s => activity.mask(s);
  const out = content.split('\n').map(l => {
    if (!l.trim()) return l;
    let e = null; try { e = JSON.parse(l); } catch (_) {}
    return e && typeof e === 'object' ? JSON.stringify(maskDeep(e, m, 0)) : m(l);
  }).join('\n');
  res.setHeader('Cache-Control', 'no-store');
  res.type('text/plain').send(out);
});

// ── Activity log (Settings > Logs): the relay console's lines, masked ──
// GET /api/admin/activity?day=&level=all|warn|error&tenant=<id>|system|all&q=&debug=0|1&after=<seq>&limit=
// Owners and the service see every line; any other admin sees only lines tagged
// with a business they administer (untagged "system" lines are for owners).
const ACTIVITY_LIMIT_MAX = 2000;
// Which lines a caller may see, for the activity routes. Returns { status, error }
// or { all, mine, keep(entry) } where keep applies the business filter.
function activityScope(user, tenant) {
  const all = !!(user && (user.owner || user.service));
  const mine = new Set(all ? [] : Object.keys((user && user.roles) || {}).filter(t => user.roles[t] === 'admin'));
  if (!all && tenant !== 'all' && tenant !== 'system' && !mine.has(tenant)) return { status: 403, error: 'You do not administer this business' };
  const keep = e => {
    if (all) return !(tenant === 'system' ? e.tenantId : (tenant !== 'all' && e.tenantId !== tenant));
    if (!e.tenantId || !mine.has(e.tenantId)) return false;
    return !(tenant === 'system' || (tenant !== 'all' && e.tenantId !== tenant));
  };
  return { all, mine, tenant, keep };
}
// level / debug / text filters shared by the activity routes. Returns { error } or { test(entry) }.
function activityFilters(q) {
  const str = v => (typeof v === 'string' ? v : '');
  const level = str(q.level) || 'all';
  if (!['all', 'warn', 'error'].includes(level)) return { error: 'level must be all, warn or error' };
  const debug = str(q.debug) === '1';
  const needle = str(q.q).trim().toLowerCase().slice(0, 200);
  return { test: e => {
    if (!debug && e.debug) return false;
    if (level === 'error' && e.level !== 'error') return false;
    if (level === 'warn' && e.level === 'info') return false;
    if (needle && (String(e.text) + ' ' + (e.user || '')).toLowerCase().indexOf(needle) < 0) return false;
    return true;
  } };
}
app.get('/api/admin/activity', (req, res) => {
  const user = req.auth;
  const q = req.query || {};
  const str = v => (typeof v === 'string' ? v : '');
  const day = str(q.day).trim();
  if (day && !activity.validDay(day)) return res.status(400).json({ success: false, error: 'day must be a date like 2026-10-09' });
  const f = activityFilters(q);
  if (f.error) return res.status(400).json({ success: false, error: f.error });
  const scope = activityScope(user, str(q.tenant) || 'all');
  if (scope.error) return res.status(scope.status).json({ success: false, error: scope.error });
  let after = null;
  if (str(q.after) !== '') { after = Number(q.after); if (!Number.isFinite(after)) return res.status(400).json({ success: false, error: 'after must be a number' }); }
  let limit = parseInt(str(q.limit), 10);
  if (!Number.isFinite(limit) || limit <= 0) limit = 500;
  limit = Math.min(limit, ACTIVITY_LIMIT_MAX);
  const today = activity.eatDay();
  const src = activity.entries({ day: day || today, after: (!day || day === today) ? after : null });
  const out = src.filter(e => scope.keep(e) && f.test(e));
  // A non-owner admin does not see other businesses' TINs, as in the export.
  const hideTins = otherTinHider(scope);
  const entries = out.slice(-limit).map(e => (scope.all ? e : { ...e, text: hideTins(e.text) }));
  const lastSeq = src.length ? src[src.length - 1].seq : (after != null ? after : activity.lastSeq());
  res.json({ success: true, day: day || today, today, entries, lastSeq, truncated: out.length > entries.length, days: activity.listDays() });
});

// ── Activity export and support bundle (Settings > Logs > Export) ──
// Same scoping and masking as /api/admin/activity, over a range of Uganda days.
const EXPORT_MAX_DAYS = 92;
const EXPORT_MAX_LINES = 200000;
const LOG_OK = /FDN:|fiscalised|✅|✔|Created |recorded |unlocked|running at|Theme updated/;
function logLevelLabel(e) { return e.level === 'error' ? 'Error' : e.level === 'warn' ? 'Warning' : LOG_OK.test(e.text) ? 'OK' : 'Info'; }
function logBizName(id, metas) { if (!id) return 'System'; const t = metas[id]; return (t && (t.tradeName || t.businessName)) || id; }
function eatDayTime(iso) { const t = Date.parse(iso); const d = new Date((isNaN(t) ? 0 : t) + 3 * 3600000).toISOString(); return { date: d.slice(0, 10), time: d.slice(11, 19) }; }
// Masks a text for anything leaving the relay: the activity rules (including the
// exact vault secrets), plus for a non-owner admin the TINs of businesses they do
// not administer.
// The TINs of businesses a non-owner admin does not administer, hidden from them.
function otherTinHider(scope) {
  const hide = [];
  if (!scope.all) { try { for (const t of vault.listTenants()) if (!scope.mine.has(t.id) && t.tin && String(t.tin).length >= 6) hide.push(String(t.tin)); } catch (_) {} }
  return s => { let out = String(s); for (const v of hide) if (out.indexOf(v) >= 0) out = out.split(v).join('***'); return out; };
}
function exportMasker(scope) {
  // Read every business once so its exact secret values are known to the masker.
  try { for (const t of vault.listTenants()) { try { vault.getTenant(t.id); } catch (_) {} } } catch (_) {}
  const hideTins = otherTinHider(scope);
  return s => hideTins(activity.mask(s));
}
function csvSafe(s) { return /^[=+\-@\t\r]/.test(s) ? "'" + s : s; }
function exportLine(e, kind, metas, m) {
  const t = eatDayTime(e.time), lv = logLevelLabel(e), biz = logBizName(e.tenantId, metas), user = e.user || '';
  // CSV cells are quoted, and a cell a spreadsheet would read as a formula (=, +,
  // -, @, tab, CR) gets a leading apostrophe so it opens as text.
  if (kind === 'csv') { const q = v => '"' + csvSafe(m(String(v))).replace(/"/g, '""') + '"'; return [t.date, t.time, lv, biz, user, e.debug ? 'yes' : 'no', e.text].map(q).join(','); }
  return m(t.date + ' ' + t.time + '  ' + (lv + '       ').slice(0, 7) + '  [' + biz + ']' + (user ? ' ' + user : '') + '  ' + e.text);
}
function exportRange(req, res) {
  const q = req.query || {};
  const str = v => (typeof v === 'string' ? v.trim() : '');
  const r = logTools.dayRange(str(q.from), str(q.to), EXPORT_MAX_DAYS);
  if (r.error) { res.status(400).json({ success: false, error: r.error }); return null; }
  return r;
}
const queryTenant = q => (typeof q.tenant === 'string' && q.tenant) || 'all';
// GET /api/admin/activity/export?from=&to=&level=&tenant=&q=&debug=&format=txt|csv
app.get('/api/admin/activity/export', (req, res) => {
  const q = req.query || {};
  const range = exportRange(req, res); if (!range) return;
  const format = typeof q.format === 'string' && q.format ? q.format : 'txt';
  if (format !== 'txt' && format !== 'csv') return res.status(400).json({ success: false, error: 'format must be txt or csv' });
  const f = activityFilters(q);
  if (f.error) return res.status(400).json({ success: false, error: f.error });
  const scope = activityScope(req.auth, queryTenant(q));
  if (scope.error) return res.status(scope.status).json({ success: false, error: scope.error });
  const metas = tenantMetaMap(), m = exportMasker(scope);
  const from = range.days[0], to = range.days[range.days.length - 1];
  res.setHeader('Content-Type', format === 'csv' ? 'text/csv; charset=utf-8' : 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="EFRISConnect-log-' + from + '_to_' + to + '.' + format + '"');
  res.setHeader('Cache-Control', 'no-store');
  res.write(format === 'csv' ? '﻿Date,Time,Level,Business,User,Technical,Text\r\n' : 'EFRISConnect activity log, ' + from + ' to ' + to + ' (Uganda time). Passwords, tokens and keys are removed.\r\n');
  let n = 0, stopped = false;
  for (const day of range.days) {
    const lines = [];
    for (const e of activity.entries({ day })) {
      if (!scope.keep(e) || !f.test(e)) continue;
      if (n >= EXPORT_MAX_LINES) { stopped = true; break; }
      lines.push(exportLine(e, format, metas, m)); n++;
    }
    if (lines.length) res.write(lines.join('\r\n') + '\r\n');
    if (stopped) break;
  }
  if (stopped) res.write(format === 'csv' ? ',,,,,,"Stopped at ' + EXPORT_MAX_LINES + ' lines: choose fewer days or add a filter"\r\n' : 'Stopped at ' + EXPORT_MAX_LINES + ' lines: choose fewer days or add a filter.\r\n');
  else if (!n && format === 'txt') res.write('No lines match these filters in this period.\r\n');
  res.end();
});

// Masks every string in a logger entry; values under secret-looking keys go entirely.
const SECRET_KEY_RE = /pass(word|phrase|wd|code)?|pwd|secret|token|api[_-]?key|aes[_-]?key|access[_-]?key|authorization|pem|private[_-]?key|cookie|credential/i;
function maskDeep(v, m, depth) {
  if (typeof v === 'string') return m(v);
  if (!v || typeof v !== 'object' || depth > 6) return v;
  if (Array.isArray(v)) return v.map(x => maskDeep(x, m, depth + 1));
  const out = {};
  for (const k of Object.keys(v)) out[k] = SECRET_KEY_RE.test(k) ? '***' : maskDeep(v[k], m, depth + 1);
  return out;
}
// system-info.txt: versions and state only. No secrets, no names, no settings
// beyond the ones listed here.
function systemInfo(scope, range) {
  const os = require('os');
  const metas = tenantMetaMap();
  const ids = Object.keys(metas).filter(id => scope.all || scope.mine.has(id));
  const conn = (_connCache && _connCache.data) || {};
  const iso = ms => new Date(ms).toISOString();
  const reach = v => (v === true ? 'reachable' : v === false ? 'unreachable' : 'not checked yet');
  let queue = []; try { queue = loadQueue(); } catch (_) {}
  let users = []; try { users = auth.listUsers(); } catch (_) {}
  const userCount = scope.all ? users.length : users.filter(u => Object.keys(u.roles || {}).some(t => scope.mine.has(t))).length;
  const up = Math.floor(process.uptime());
  const L = [
    'EFRISConnect support bundle',
    'Made: ' + new Date().toISOString() + ' (UTC)',
    'Period: ' + range.days[0] + ' to ' + range.days[range.days.length - 1] + ' (Uganda time)',
    'Made by: ' + (scope.all ? 'an owner (all businesses)' : 'an admin (their businesses only)'),
    '',
    'EFRISConnect version: ' + APP_VERSION,
    'Operating system: ' + os.type() + ' ' + os.release() + ' (' + process.platform + ', ' + process.arch + ')',
    'Node.js: ' + process.version,
    'Relay running for: ' + Math.floor(up / 86400) + 'd ' + Math.floor(up % 86400 / 3600) + 'h ' + Math.floor(up % 3600 / 60) + 'm',
    'Vault: ' + (vault.isUnlocked() ? 'unlocked' : 'locked'),
    'URA: ' + reach(_retry.online !== null ? _retry.online : conn.ura) + (_retry.lastAt ? ', last queue attempt ' + iso(_retry.lastAt) : '') + (_connCache && _connCache.ts ? ', last connection check ' + iso(_connCache.ts) : ''),
    'Offline Enabler last status: ' + (conn.enabler === true ? 'answering' : conn.enabler === false ? 'not answering' : 'not checked'),
    'Users: ' + userCount,
    'Data folder: ' + DATA_DIR,
    'Log retention: ' + logTools.retentionDays() + ' days',
    '',
    'Businesses (' + ids.length + '):',
  ];
  for (const id of ids) {
    const t = metas[id] || {};
    const pend = queue.filter(e => e.tenantId === id && e.status === 'pending').length;
    const failed = queue.filter(e => e.tenantId === id && e.status === 'failed').length;
    L.push('  ' + logBizName(id, metas) + ' [' + id + ']: ' + (t.mode === 'production' ? 'production' : 'sandbox')
      + ', Offline Enabler configured: ' + (t.hasEnabler ? 'yes' : 'no') + ', offline queue: ' + pend + ' pending, ' + failed + ' failed');
  }
  return L.join('\r\n') + '\r\n';
}
// GET /api/admin/support-bundle?from=&to=&tenant=  -> EFRISConnect-support-<from>_to_<to>.zip
app.get('/api/admin/support-bundle', (req, res) => {
  const q = req.query || {};
  const range = exportRange(req, res); if (!range) return;
  const scope = activityScope(req.auth, queryTenant(q));
  if (scope.error) return res.status(scope.status).json({ success: false, error: scope.error });
  const metas = tenantMetaMap(), m = exportMasker(scope);
  const files = [];
  let n = 0;
  for (const day of range.days) {
    const lines = [];
    for (const e of activity.entries({ day })) {
      if (!scope.keep(e)) continue;
      if (n >= EXPORT_MAX_LINES) break;
      lines.push(exportLine(e, 'txt', metas, m)); n++;
    }
    if (lines.length) files.push({ name: 'activity-' + day + '.txt', data: lines.join('\r\n') + '\r\n' });
  }
  // The structured error log (logger.js day files): owners see every entry, other
  // admins only entries tagged with a business they administer.
  for (const day of range.days) {
    const raw = logger.readDay(day);
    if (!raw) continue;
    const out = [];
    for (const l of raw.split('\n')) {
      if (!l.trim()) continue;
      let e = null; try { e = JSON.parse(l); } catch (_) {}
      if (!e || typeof e !== 'object' || Array.isArray(e)) { if (scope.all && scope.tenant === 'all') out.push(m(l)); continue; }
      if (!scope.keep({ tenantId: typeof e.tenantId === 'string' ? e.tenantId : '' })) continue;
      out.push(m(JSON.stringify(maskDeep(e, m, 0))));
    }
    if (out.length) files.push({ name: 'errors-' + day + '.jsonl', data: out.join('\n') + '\n' });
  }
  files.push({ name: 'system-info.txt', data: m(systemInfo(scope, range)) });
  const from = range.days[0], to = range.days[range.days.length - 1];
  const body = logTools.zip(files);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="EFRISConnect-support-' + from + '_to_' + to + '.zip"');
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
});

// ── Client-side error reports - what the frontend saw + what the user was
// doing (tab/breadcrumbs only, never form values), so support can reproduce
// a bug from the daily logs without asking the user to screenshot a console.
const _clientLogHits = [];
app.post('/api/client-log', (req, res) => {
  const now = Date.now();
  while (_clientLogHits.length && now - _clientLogHits[0] > 60000) _clientLogHits.shift();
  if (_clientLogHits.length >= 30) return res.status(429).end(); // don't let a crash loop flood the log
  _clientLogHits.push(now);

  const b = req.body || {};
  const trunc = (s, n) => (typeof s === 'string' ? s.slice(0, n) : s);
  // Page URLs and messages can carry the Manager token (?apiAccessToken=, tk=) or
  // an API key: drop the URL's query/hash and mask any such value left anywhere.
  const scrub = s => String(s == null ? '' : s).replace(/\b(apiAccessToken|accessToken|tk|key)=[^&\s#'"]*/gi, '$1=[redacted]');
  logger.error('client: ' + trunc(scrub(redactSecrets(String(b.message || 'unknown error'), req)), 500), {
    tab: trunc(b.tab, 40),
    breadcrumbs: Array.isArray(b.breadcrumbs) ? b.breadcrumbs.slice(-8).map(x => trunc(scrub(x), 60)) : undefined,
    stack: trunc(scrub(redactSecrets(String(b.stack || ''), req)), 1500),
    url: b.url ? trunc(scrub(String(b.url).split(/[?#]/)[0]), 200) : undefined,
  });
  res.status(204).end();
});

app.get('/api/segments', (req, res) => {
  try {
    const { q } = req.query;
    let segs = Object.entries(getTree()).map(([code, seg]) => ({ code, name: seg.n }));
    if (q && q.length >= 2) {
      const ql = q.toLowerCase();
      segs = segs.filter(s => s.name.toLowerCase().includes(ql) || s.code.includes(ql));
    }
    res.json(segs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/segments/:segCode/families', (req, res) => {
  try {
    const seg = getTree()[req.params.segCode];
    if (!seg) return res.status(404).json({ error: 'Segment not found' });
    res.json(Object.entries(seg.f).map(([code, fam]) => ({ code, name: fam.n })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/segments/:segCode/families/:famCode/classes', (req, res) => {
  try {
    const seg = getTree()[req.params.segCode];
    if (!seg) return res.status(404).json({ error: 'Segment not found' });
    const fam = seg.f[req.params.famCode];
    if (!fam) return res.status(404).json({ error: 'Family not found' });
    res.json(Object.entries(fam.c).map(([code, cls]) => ({ code, name: cls.n })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/segments/:segCode/families/:famCode/classes/:clsCode/commodities', (req, res) => {
  try {
    const seg = getTree()[req.params.segCode];
    if (!seg) return res.status(404).json({ error: 'Segment not found' });
    const fam = seg.f[req.params.famCode];
    if (!fam) return res.status(404).json({ error: 'Family not found' });
    const cls = fam.c[req.params.clsCode];
    if (!cls) return res.status(404).json({ error: 'Class not found' });
    res.json(Object.entries(cls.d).map(([code, com]) => {
      if (typeof com === 'string') return { code, name: com };
      return { code, name: com.n, isService: com.s };
    }));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/units', (req, res) => {
  try { res.json(getUnits()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// When was the unit list last synced from EFRIS (and how many units)?
app.get('/api/units/sync-status', (req, res) => {
  const m = unitsSyncMeta();
  res.json({ ...m, activeCount: getUnits().length });
});

// Pull the AUTHORITATIVE measure-unit list from the taxpayer's own EFRIS account
// (T115 dictionary), merge it with the bundled static list (EFRIS wins on any shared
// code; our known-good extras are kept), and cache it to uom_synced.json so it's
// used everywhere AND available offline. Run this once online; the picker/validation
// then reflect exactly what this EFRIS account accepts.
app.post('/api/efris/sync-units', async (req, res) => {
  const { tin, deviceNo, efrisPassword, mode } = req.body || {};
  if (!tin || !deviceNo || !efrisPassword) return res.json({ success: false, error: 'Missing EFRIS credentials' });
  try {
    const eu = uraUrl(mode);
    const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
    const efrisUnits = await getEfrisMeasureUnits(tin, deviceNo, session, eu);
    if (!efrisUnits.length) return res.json({ success: false, error: 'EFRIS returned no measure units (T115 dictionary unavailable or empty). Kept the existing list.' });

    // Merge: start from static bundled units, then let EFRIS overwrite by code.
    let staticUnits = [];
    try { staticUnits = JSON.parse(fs.readFileSync(path.join(SHIPPED_DIR, 'uom.json'), 'utf8')); } catch(_) {}
    const byCode = new Map();
    for (const u of staticUnits) { const c = String(u.code || '').toUpperCase(); if (c) byCode.set(c, { code: u.code, name: u.name || u.desc || '' }); }
    let added = 0, updated = 0;
    for (const u of efrisUnits) {
      const c = String(u.code || '').toUpperCase(); if (!c) continue;
      if (byCode.has(c)) updated++; else added++;
      byCode.set(c, { code: u.code, name: u.name || '' });   // EFRIS is authoritative
    }
    const merged = [...byCode.values()].sort((a, b) => String(a.name).localeCompare(String(b.name)));
    fs.writeFileSync(path.join(DATA_DIR, 'uom_synced.json'), JSON.stringify(merged));
    UNITS = null;  // invalidate cache so getUnits() reloads the synced list
    console.log(`   ✅ Synced ${efrisUnits.length} EFRIS units (${added} new, ${updated} updated); total ${merged.length} → uom_synced.json`);
    res.json({ success: true, efrisCount: efrisUnits.length, added, updated, total: merged.length,
      sample: efrisUnits.slice(0, 10), syncedAt: new Date().toISOString() });
  } catch (e) {
    const safe = redactSecrets(String(e.message || e), req);
    logger.error('sync-units failed', { message: safe });
    res.json({ success: false, error: safe });
  }
});

app.get('/api/commodity/search', (req, res) => {
  try {
    const q = (req.query.q || '').toLowerCase().trim();
    if (q.length < 2) return res.json([]);
    const tree = getTree();
    const results = [];
    for (const [sc, seg] of Object.entries(tree)) {
      for (const [fc, fam] of Object.entries(seg.f)) {
        for (const [cc, cls] of Object.entries(fam.c)) {
          if (!cls.d) continue;
          for (const [dc, com] of Object.entries(cls.d)) {
            const comName = typeof com === 'string' ? com : com.n;
            if (comName.toLowerCase().includes(q) || dc.includes(q)) {
              results.push({ commodityCode: dc, commodityName: comName,
                classCode: cc, className: cls.n, familyCode: fc, familyName: fam.n,
                segmentCode: sc, segmentName: seg.n });
              if (results.length >= 20) break;
            }
          }
          if (results.length >= 20) break;
        }
        if (results.length >= 20) break;
      }
      if (results.length >= 20) break;
    }
    res.json(results);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/commodity/:code', (req, res) => {
  try {
    const target = req.params.code.padStart(8, '0');
    const tree = getTree();
    for (const [sc, seg] of Object.entries(tree)) {
      for (const [fc, fam] of Object.entries(seg.f)) {
        for (const [cc, cls] of Object.entries(fam.c)) {
          if (cls.d && cls.d[target]) {
            const com = cls.d[target];
            return res.json({ commodityCode: target, commodityName: typeof com === 'string' ? com : com.n,
              classCode: cc, className: cls.n, familyCode: fc, familyName: fam.n, segmentCode: sc, segmentName: seg.n });
          }
        }
      }
    }
    res.status(404).json({ error: 'Commodity not found' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  URA tax rule for a commodity code (T124, T146 fallback)
// ══════════════════════════════════════════════════════════════
// URA keeps, per commodity category, whether sales are standard-rated, zero-rated
// or exempt (with the dates each rule applies), and whether the category is
// excisable. T124 is the paged commodity-category query (pageNo/pageSize, and on
// current builds an optional commodityCategoryCode filter). Builds that ignore the
// filter return the first page of the whole list instead, so a reply without the
// asked code falls back to T146 (category by code and issue date). Results are
// cached for 24 h per environment; the rules change rarely.
const COMMODITY_TAX_TTL = 24 * 3600000;
const _commodityTax = new Map();   // mode|code -> { ts, rec }
let _commodityShapeLogged = false;

// URA's yes/no fields are '101' (yes) / '102' (no); accept the usual spellings too.
function uraYes(v) {
  const s = String(v == null ? '' : v).trim().toLowerCase();
  return s === '101' || s === '1' || s === 'y' || s === 'yes' || s === 'true';
}
// URA dates: dd/MM/yyyy (with or without a time) or yyyy-MM-dd. Returns ms or null.
function uraDateMs(v) {
  const s = String(v || '').trim();
  let m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})/.exec(s);
  if (m) return Date.UTC(+m[3], +m[2] - 1, +m[1]);
  m = /^(\d{4})-(\d{1,2})-(\d{1,2})/.exec(s);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]);
  return null;
}
// A rule flagged on URA applies today unless its dates say otherwise.
function ruleActive(start, end, now) {
  const a = uraDateMs(start), b = uraDateMs(end);
  if (a != null && now < a) return false;
  if (b != null && now > b + 86400000 - 1) return false;
  return true;
}
function commodityNameFromTree(code) {
  try {
    const target = String(code).padStart(8, '0');
    for (const seg of Object.values(getTree())) for (const fam of Object.values(seg.f || {})) for (const cls of Object.values(fam.c || {})) {
      if (cls.d && cls.d[target]) { const c = cls.d[target]; return typeof c === 'string' ? c : c.n; }
    }
  } catch (_) {}
  return '';
}
// One URA commodity-category record -> the VAT rule EFRISConnect works with.
function commodityTaxRule(rec, now) {
  now = now || Date.now();
  const r = rec || {};
  const rateNum = parseFloat(r.rate);
  const ratePct = isNaN(rateNum) ? null : Math.round((rateNum <= 1 ? rateNum * 100 : rateNum) * 100) / 100;
  const exempt = uraYes(r.isExempt) && ruleActive(r.exemptRateStartDate, r.exemptRateEndDate, now);
  const zero = !exempt && uraYes(r.isZeroRate) && ruleActive(r.zeroRateStartDate, r.zeroRateEndDate, now);
  const deemedKey = Object.keys(r).find(k => /deemed/i.test(k) && !/date/i.test(k));
  const deemed = !exempt && !zero && !!deemedKey && uraYes(r[deemedKey]);
  const exciseKey = Object.keys(r).find(k => /^(is)?excis(able|e)?(flag)?$/i.test(k));
  const excisable = !!exciseKey && uraYes(r[exciseKey]);
  let rule, label;
  if (exempt) { rule = 'exempt'; label = 'Exempt'; }
  else if (zero) { rule = 'zero'; label = 'Zero-rated 0%'; }
  else if (deemed) { rule = 'deemed'; label = 'Deemed VAT ' + (ratePct || 18) + '%'; }
  else if (ratePct != null && ratePct > 0) { rule = 'standard'; label = 'Standard ' + ratePct + '%'; }
  else if (ratePct === 0) { rule = 'zero'; label = 'Zero-rated 0%'; }
  else { rule = 'unknown'; label = 'Unknown'; }
  return {
    code: String(r.commodityCategoryCode || ''), name: String(r.commodityCategoryName || ''),
    rule, label: label + (excisable ? ' + excise' : ''), rate: ratePct, excisable,
    isZeroRate: uraYes(r.isZeroRate), zeroRateStartDate: r.zeroRateStartDate || '', zeroRateEndDate: r.zeroRateEndDate || '',
    isExempt: uraYes(r.isExempt), exemptRateStartDate: r.exemptRateStartDate || '', exemptRateEndDate: r.exemptRateEndDate || '',
    isLeafNode: r.isLeafNode === undefined ? null : uraYes(r.isLeafNode),
    serviceMark: r.serviceMark === undefined ? null : uraYes(r.serviceMark),
  };
}
// Every object in a decoded reply that looks like a commodity-category record.
function commodityRecords(parsed) {
  const out = [];
  const walk = (v, d) => {
    if (!v || typeof v !== 'object' || d > 4) return;
    if (Array.isArray(v)) { v.forEach(x => walk(x, d + 1)); return; }
    if (v.commodityCategoryCode !== undefined) { out.push(v); return; }
    for (const k of Object.keys(v)) if (k !== 'page') walk(v[k], d + 1);
  };
  walk(parsed, 0);
  return out;
}
async function commodityQuery(eu, iface, payload, cfg, session) {
  const r = await efrisSecure(eu, iface, payload, cfg.tin, cfg.deviceNo, session);
  const rc = r && r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnCode : null;
  const rm = r && r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnMessage : '';
  let parsed = null;
  const c = r && r.data && r.data.data && r.data.data.content;
  if (c) { try { const raw = efrisDecodeJson(c, session.aesKey); if (raw) parsed = JSON.parse(raw); } catch (_) {} }
  if (parsed && !_commodityShapeLogged) {
    _commodityShapeLogged = true;
    const recs = commodityRecords(parsed);
    console.log('   [debug] ' + iface + ' reply shape: top-level ' + Object.keys(parsed).join(', ') + (recs[0] ? ' | record fields: ' + Object.keys(recs[0]).join(', ') : ' | no records'));
  }
  return { rc, rm, parsed };
}
// Looks up the URA tax rule of each code. cfg: { tin, deviceNo, efrisPassword,
// mode, efrisKeyPem/efrisKeyPath/efrisKeyPassphrase }. Never throws for one bad
// code: that code comes back with an error.
async function lookupCommodityTax(codes, cfg) {
  const mode = cfg.mode === 'production' ? 'production' : 'sandbox';
  const eu = uraUrl(mode);
  const list = [...new Set((codes || []).map(c => String(c || '').trim()).filter(c => /^\d{1,10}$/.test(c)))].slice(0, 50);
  const out = {};
  const todo = [];
  const now = Date.now();
  for (const code of list) {
    const hit = _commodityTax.get(mode + '|' + code);
    if (hit && now - hit.ts < COMMODITY_TAX_TTL) out[code] = Object.assign({}, hit.rec, { cached: true });
    else todo.push(code);
  }
  if (!todo.length) return out;
  const session = await getSession(cfg.tin, cfg.deviceNo, cfg.efrisPassword, eu, keyOverrideFrom(cfg));
  if (!session.aesKey) throw new Error('No AES key');
  const pad = c => String(c).padStart(8, '0');
  const issueDate = new Date(Date.now() + 3 * 3600000).toISOString().replace('T', ' ').slice(0, 19);
  for (const code of todo) {
    try {
      let rec = null, source = '', err = '';
      const q1 = await commodityQuery(eu, 'T124', { commodityCategoryCode: code, pageNo: '1', pageSize: '10' }, cfg, session);
      if (q1.rc === '00' || q1.rc === null) rec = commodityRecords(q1.parsed).find(x => pad(x.commodityCategoryCode) === pad(code)) || null;
      if (rec) source = 'T124';
      else {
        if (q1.rc && q1.rc !== '00') err = 'T124 ' + q1.rc + ' ' + q1.rm;
        const q2 = await commodityQuery(eu, 'T146', { categoryCode: code, type: '1', issueDate }, cfg, session);
        if (q2.rc === '00') rec = commodityRecords(q2.parsed).find(x => pad(x.commodityCategoryCode) === pad(code)) || commodityRecords(q2.parsed)[0] || null;
        if (rec) source = 'T146';
        else if (q2.rc && q2.rc !== '00') err = (err ? err + '; ' : '') + 'T146 ' + q2.rc + ' ' + q2.rm;
      }
      if (!rec) { out[code] = { code, name: commodityNameFromTree(code), rule: 'unknown', label: 'Not found at URA', error: err || 'URA returned no record for this code' }; continue; }
      const v = commodityTaxRule(rec, now);
      v.code = code;
      if (!v.name) v.name = commodityNameFromTree(code);
      v.source = source;
      _commodityTax.set(mode + '|' + code, { ts: now, rec: v });
      out[code] = v;
    } catch (e) {
      out[code] = { code, name: commodityNameFromTree(code), rule: 'unknown', label: 'Lookup failed', error: e.message };
    }
  }
  return out;
}

app.post('/api/efris/commodity-tax', async (req, res) => {
  const b = req.body || {};
  const cfg = b.config || b;
  const codes = Array.isArray(b.codes) ? b.codes : (b.code ? [b.code] : []);
  if (!codes.length) return res.status(400).json({ success: false, error: 'codes required' });
  if (!cfg.tin || !cfg.deviceNo) return res.status(400).json({ success: false, error: 'EFRIS credentials required (config.tin, config.deviceNo)' });
  try {
    const results = await lookupCommodityTax(codes, cfg);
    res.json({ success: true, results });
  } catch (e) {
    const safe = redactSecrets(String(e.message || e), req);
    logger.error('commodity-tax failed', { message: safe });
    res.json({ success: false, error: safe });
  }
});

// ══════════════════════════════════════════════════════════════
//  GOODS SYNC ROUTES (new)
// ══════════════════════════════════════════════════════════════

app.post('/api/goods/sync-to-manager', async (req, res) => {
  const { managerEndpoint, accessToken, item } = req.body || {};
  if (!managerEndpoint || !accessToken || !item) {
    return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and item are required' });
  }
  const ep = normEp(managerEndpoint);
  // Goods keep their ORIGINAL (possibly foreign) price - we convert to UGX only at
  // receipt time (see /api/efris/search-goods, which returns unitPriceUGX). So the
  // item is stored as-registered here.
  // Classify service vs good the same way EFRIS/the portal does: by the UNSPSC commodity
  // category segment (70-94 = services). This overrides a mis-set item.type so a tour
  // (90…) or transport (78…) lands as a Manager NON-inventory item even if the form said
  // "Goods". Falls back to item.type when no category is present.
  const _catSeg = parseInt(String(item.comCode || item.commodityCategoryCode || '').slice(0, 2), 10);
  const isService = (_catSeg >= 70 && _catSeg <= 94) ? true
                  : (_catSeg >= 1) ? false
                  : (item.type || 'Service') !== 'Goods';
  const listPath = isService ? '/non-inventory-items' : '/inventory-items';
  const listKey  = isService ? 'nonInventoryItems' : 'inventoryItems';
  const formBase = isService ? '/non-inventory-item-form' : '/inventory-item-form';

  try {
    // Look up custom field GUIDs. Accept several common names so renaming the
    // Manager custom fields (e.g. to "Commodity Code") keeps working.
    let comCodeFieldKey = null, catPathFieldKey = null, priceCurFieldKey = null;
    try {
      const cf = await mgrTextCustomFields(ep, accessToken);
      const find = (...names) => { for (const n of names) { if (cf.byName[n]) return cf.byName[n]; } return null; };
      comCodeFieldKey = find('EFRIS Commodity Code', 'Commodity Code', 'EFRIS Commodity', 'Commodity');
      catPathFieldKey = find('EFRIS Category Path', 'Segment / Class Grouping', 'EFRIS Segment / Class Grouping', 'EFRIS Segment', 'Category Path', 'Class Grouping');
      priceCurFieldKey = find('Price Currency', 'EFRIS Price Currency', 'Sales Currency', 'Item Currency');
    } catch(_) {}
    // The good's listing currency (e.g. USD) - tagged on the Manager item so the
    // stored price number isn't mistaken for UGX; the extension converts at receipt.
    const priceCur = String(item.cur || 'UGX').trim().toUpperCase();

    const catPath = [item.segment, item.family, item.cls].filter(Boolean).join(' >> ');
    const codeLower = (item.code || '').toLowerCase();
    const nameLower = (item.name || '').toLowerCase();

    // Step 1: Find existing item key by fetching the list
    console.log(`\n🔗 Syncing to Manager.io: ${ep} - ${item.code} ${item.name}`);
    const listR = await managerCall(ep, accessToken, 'GET', listPath, null);
    const existingList = (listR.status === 200 && listR.data && listR.data[listKey]) || [];
    // Inventory (Goods) items come back from Manager's list endpoint keyed
    // ItemCode/ItemName - NOT code/Code or name/Name (those are the
    // non-inventory/Service shape). Checking only the Service-shaped field
    // names meant a Goods item's code+name both silently failed to match its
    // own existing record here, so every re-sync created a duplicate instead
    // of updating it.
    const match = existingList.find(i => {
      const cd = (i.code || i.Code || i.itemCode || i.ItemCode || '').toLowerCase();
      return codeLower && cd && cd === codeLower;
    }) || existingList.find(i => {
      const nm = (i.itemName || i.name || i.Name || i.ItemName || '').toLowerCase();
      return nm === nameLower;
    });

    let r, action, existingKey = null;

    if (match) {
      // Step 2a: UPDATE - GET the full form, merge our fields, POST back to form endpoint
      existingKey = match.key || match.Key;
      console.log(`   Existing item (key ${existingKey}) - GET form → mutate → POST form`);
      const formR = await managerCall(ep, accessToken, 'GET', `${formBase}/${existingKey}`, null);
      if (formR.status !== 200) {
        return res.json({ success: false, error: `Could not fetch item form: HTTP ${formR.status}` });
      }
      // Merge our fields into the form (preserving all other Manager fields).
      // Non-inventory and inventory items use different field names in Manager API.
      const form = Object.assign({}, formR.data || {});
      console.log(`   Form fields available: ${Object.keys(form).join(', ')}`);
      const price = parseFloat(item.price) || 0;
      form.Code     = item.code;
      form.UnitName = item.uom;
      if (item.remarks) form.DefaultLineDescription = item.remarks;
      if (isService) {
        // Non-inventory items
        form.Name              = item.name;
        form.HasSalesUnitPrice = price > 0;
        form.SalesUnitPrice    = price;
      } else {
        // Inventory items - confirmed field names from GET form response
        form.ItemName                 = item.name;
        form.ItemCode                 = item.code;   // inventory uses ItemCode, not Code
        form.DefaultSalesUnitPrice    = price;
        form.HasDefaultSalesUnitPrice = price > 0;
      }
      // Tax code - look up Manager tax code GUID matching the VAT designation
      if (item.vat) {
        try {
          const taxGuid = await mgrTaxCodeGuid(ep, accessToken, item.vat);
          if (taxGuid) { form.TaxCode = taxGuid; form.HasDefaultTaxCode = true; form.DefaultTaxCode = taxGuid; console.log(`   Tax code GUID → ${taxGuid} (${item.vat})`); }
          else { console.log(`   ⚠ No matching tax code found for VAT type: ${item.vat}`); }
        } catch(_) {}
      }
      // Merge custom fields - preserve existing, add/overwrite ours
      const cfStrings = Object.assign({}, (form.CustomFields2 && form.CustomFields2.Strings) || {});
      if (comCodeFieldKey && item.comCode) cfStrings[comCodeFieldKey] = item.comCode;
      if (catPathFieldKey && catPath)      cfStrings[catPathFieldKey] = catPath;
      if (priceCurFieldKey && priceCur)    cfStrings[priceCurFieldKey] = priceCur;
      if (Object.keys(cfStrings).length)   form.CustomFields2 = { Strings: cfStrings };
      // Inventory items use SaleItemAccount/PurchaseItemAccount; non-inventory
      // use WhenSold/WhenPurchased. Set both - Manager ignores the irrelevant one.
      if (item.whenSold) { form.SaleItemAccount = item.whenSold; form.WhenSold = item.whenSold; }
      if (item.whenPurchased) { form.PurchaseItemAccount = item.whenPurchased; form.WhenPurchased = item.whenPurchased; }
      if (item.division) form.Division = item.division;
      if (item.salesDivision) form.SalesDivision = item.salesDivision;
      if (!isService && item.costMethod != null && item.costMethod !== '') form.CostMethod = item.costMethod;
      r = await managerCall(ep, accessToken, 'POST', `${formBase}/${existingKey}`, form);
      action = 'updated';
      const written = Object.keys(cfStrings).length;
      console.log(`   Manager form POST: HTTP ${r.status}`);
      if (comCodeFieldKey) console.log(`   EFRIS Commodity Code → ${item.comCode}`);
      if (catPathFieldKey) console.log(`   EFRIS Category Path  → ${catPath}`);
      const ok = r.status >= 200 && r.status < 300;
      return res.json(ok
        ? { success: true, action, managerId: existingKey, comCodeWritten: !!(comCodeFieldKey && item.comCode), fieldsWritten: written }
        : { success: false, error: `Manager form POST returned HTTP ${r.status}: ${JSON.stringify(r.data||'').slice(0,200)}` });

    } else {
      // Step 2b: CREATE - use the form endpoint (POST without a key) for both
      // inventory and non-inventory items. POST to the list endpoint works for
      // non-inventory items but silently fails for inventory items in Manager v2.
      const createPath = isService ? '/non-inventory-item-form' : '/inventory-item-form';
      console.log(`   No existing item found - creating via POST ${createPath}`);
      const cfStrings = {};
      if (comCodeFieldKey && item.comCode) cfStrings[comCodeFieldKey] = item.comCode;
      if (catPathFieldKey && catPath)      cfStrings[catPathFieldKey] = catPath;
      if (priceCurFieldKey && priceCur)    cfStrings[priceCurFieldKey] = priceCur;
      const price = parseFloat(item.price) || 0;
      const payload = { Code: item.code, Name: item.name, UnitName: item.uom, DefaultLineDescription: item.remarks || '' };
      if (isService) {
        payload.HasDefaultLineDescription = !!(item.remarks);
        payload.HasSalesUnitPrice = price > 0;
        payload.HasDefaultSalesUnitPrice = price > 0;
        payload.SalesUnitPrice    = price;
        payload.DefaultSalesUnitPrice = price;
      } else {
        payload.ItemName                 = item.name;
        payload.ItemCode                 = item.code;   // inventory uses ItemCode, not Code
        payload.DefaultSalesUnitPrice    = price;
        payload.HasDefaultSalesUnitPrice = price > 0;
      }
      // Tax code for create
      if (item.vat) {
        try { const tg = await mgrTaxCodeGuid(ep, accessToken, item.vat); if (tg) { payload.TaxCode = tg; payload.HasDefaultTaxCode = true; payload.DefaultTaxCode = tg; } } catch(_) {}
      }
      if (item.whenSold) { payload.SaleItemAccount = item.whenSold; payload.WhenSold = item.whenSold; }
      if (item.whenPurchased) { payload.PurchaseItemAccount = item.whenPurchased; payload.WhenPurchased = item.whenPurchased; }
      if (item.division) payload.Division = item.division;
      if (item.salesDivision) payload.SalesDivision = item.salesDivision;
      if (!isService && item.costMethod != null && item.costMethod !== '') payload.CostMethod = item.costMethod;
      if (Object.keys(cfStrings).length) payload.CustomFields2 = { Strings: cfStrings };
      r = await managerCall(ep, accessToken, 'POST', createPath, payload);
      action = 'created';
      // Form endpoint on success redirects (302) or returns 200/201; fetch new key
      // by looking up the item by code in the list
      if ((r.status >= 200 && r.status < 400)) {
        try {
          const listR = await managerCall(ep, accessToken, 'GET', listPath, null);
          const arr = listR.data && listR.data[listKey];
          if (Array.isArray(arr)) {
            const created = arr.find(i => {
              const cd = (i.code || i.Code || '').toLowerCase();
              const nm = (i.itemName || i.name || i.Name || '').toLowerCase();
              return (codeLower && cd === codeLower) || nm === nameLower;
            });
            if (created) existingKey = created.key || created.Key;
          }
        } catch(_) {}
      }
      console.log(`   Manager POST: HTTP ${r.status} → key: ${existingKey||'unknown'}`);
      const ok = r.status >= 200 && r.status < 400;
      const written = Object.keys(cfStrings).length;
      // Seed the Manager opening balance from the good's current EFRIS stock, when
      // an import supplied one (inventory items only - services carry no stock).
      // Create-only path, so a re-sync never re-applies it. Best-effort.
      let openingStock = null;
      if (ok && !isService && existingKey && parseFloat(item.openingStock) > 0) {
        try {
          const qty = parseFloat(item.openingStock);
          const cost = parseFloat(item.price) || 0;
          const sb = { InventoryItem: existingKey, HasQtyToOnHand: true, QtyOnHandLines: [{ QtyOnHand: qty }], AverageCost: cost };
          const sbr = await managerCall(ep, accessToken, 'POST', '/inventory-item-starting-balance-form', sb);
          console.log(`   opening-stock POST: HTTP ${sbr.status} item=${existingKey} qty=${qty}`);
          if (sbr.status >= 200 && sbr.status < 400) {
            openingStock = qty;
            if (cost > 0) { try { await recordInventoryUnitCost(ep, accessToken, existingKey, cost, eatToday()); } catch(_) {} }
          }
        } catch (e) { console.log(`   opening-stock skipped: ${e.message}`); }
      }
      return res.json(ok
        ? { success: true, action, managerId: existingKey || null, comCodeWritten: !!(comCodeFieldKey && item.comCode), fieldsWritten: written, openingStock }
        : { success: false, error: `Manager returned HTTP ${r.status}: ${JSON.stringify(r.data||'').slice(0,200)}` });
    }
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/goods/manager-items', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  try {
    // No ?fields filter - in this Manager build that filter omits key/code, which
    // breaks the import picker (needs key) and item matching (needs code).
    const [niR, invR] = await Promise.all([
      managerCall(ep, tk, 'GET', '/non-inventory-items', null),
      managerCall(ep, tk, 'GET', '/inventory-items', null)
    ]);
    const services = (niR.status === 200 && niR.data && (niR.data.nonInventoryItems || niR.data.NonInventoryItems)) || [];
    const goods    = (invR.status === 200 && invR.data && (invR.data.inventoryItems || invR.data.InventoryItems)) || [];
    const num = v => { if (v == null) return 0; if (typeof v === 'object') v = v.value != null ? v.value : (v.amount != null ? v.amount : 0); return parseFloat(v) || 0; };
    const normalize = (arr, type) => arr.map(i => {
      const price = num(i.SalePrice || i.salePrice || i.salesUnitPrice || i.SalesUnitPrice || i.salesPrice || i.price || i.Price);
      return {
        key:            i.key || i.Key,
        code:           i.ItemCode || i.itemCode || i.code || i.Code || '',
        name:           i.ItemName || i.itemName || i.name || i.Name || '',
        unitName:       i.UnitName || i.unitName || '',
        price:          price,           // frontend (walk-in autofill) reads .price
        salesUnitPrice: price,
        description:    i.description || i.Description || '',
        type
      };
    });
    res.json({ success: true, items: [...normalize(services,'Service'), ...normalize(goods,'Goods')] });
  } catch(e) {
    res.json({ success: false, error: e.message });
  }
});

const _acctPath = {};
app.get('/api/manager/accounts', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  // Try several common Manager account-list endpoints. Manager API2 uses kebab-case
  // plural paths (cf. /inventory-items). Different editions expose different names.
  // The one that answers is remembered per Manager, so later calls go straight to it.
  let paths = ['/chart-of-accounts', '/profit-and-loss-statement-accounts', '/profit-and-loss-accounts', '/income-statement-accounts', '/balance-sheet-accounts', '/accounts'];
  if (_acctPath[ep]) paths = [_acctPath[ep], ...paths.filter(p => p !== _acctPath[ep])];
  for (const path of paths) {
    try {
      const r = await managerCall(ep, tk, 'GET', path, null);
      if (r.status === 200) _acctPath[ep] = path;
      else if (!_acctPath[ep]) console.log(`   accounts probe ${path} → HTTP ${r.status}`);
      if (r.status === 200 && r.data) {
        // Find the array inside the response object (Manager wraps lists under a key)
        const arr = Array.isArray(r.data)
          ? r.data
          : Object.values(r.data).find(v => Array.isArray(v) && v.length && (v[0].key || v[0].Key));
        if (arr && arr.length) {
          const accounts = arr.map(a => ({ key: a.key || a.Key, name: a.name || a.Name || a.accountName || a.AccountName || '' })).filter(a => a.key);
          console.log(`   Manager accounts from ${path}: ${accounts.length} items`);
          if (accounts.length) return res.json({ success: true, accounts });
        }
      }
    } catch(e) { console.log(`   accounts probe ${path} error: ${e.message}`); }
  }
  console.log('   Manager accounts: none of the candidate paths returned a list');
  res.json({ success: true, accounts: [] });
});

// Bank & cash accounts (the "Received in" targets) - distinct from the chart of
// accounts above. Used by the payment-method → account mapping in Settings.
app.get('/api/manager/bank-accounts', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  try {
    const r = await managerCall(ep, tk, 'GET', '/bank-and-cash-accounts', null);
    const arr = (r.data && (r.data.bankAndCashAccounts || r.data.BankAndCashAccounts)) || [];
    const accounts = arr.map(a => ({ key: a.key || a.Key, name: a.name || a.Name || '', currency: a.currency || a.Currency || a.foreignCurrency || a.ForeignCurrency || '' })).filter(a => a.key);
    res.json({ success: true, accounts });
  } catch (e) { res.json({ success: false, error: e.message, accounts: [] }); }
});

// ── EFRIS custom-field provisioning ───────────────────────────
// Manager placement GUIDs identify built-in document types. These are default
// values; they are overridable per request because they can vary between
// company files (verify via /custom-field-sample).
const MGR_PLACEMENTS = {
  salesInvoice:   'ad12b60b-23bf-4421-94df-8be79cef533e',
  receipt:        '7662b887-c8d8-486e-98fd-f9dbcd41c6dc',
  creditNote:     '245e5943-0092-409d-96ae-e2ee10eac75b',   // Credit Note (read from a field placed there by hand)
  inventoryItem:  '0dbdbf8a-d80c-48e6-b453-bb7862445b7c',
  nonInventoryItem:'7affe9ee-731f-4936-8acf-15cae7bcacee',
  customer:       'ec37c11e-2b67-49c6-8a58-6eccb7dd75ee',
  business:       '38cf4712-6e95-4ce1-b53a-bff03edad273',   // Business Details (shown on that page in Manager)
};
// Each EFRIS field: the name to create, every name that counts as "already
// present" (so we never duplicate), and which placement group it belongs to.
// P.customer may be empty when the Customer placement GUID is unavailable;
// customer-object specs are dropped in that case (see ensure-efris-fields).
function efrisFieldSpecs(P) {
  // The buyer fields (Customer Type, Buyer TIN, Nationality, Passport/ID) also get
  // the Customer placement so ONE field serves both documents and customers - this
  // happens on customer creation (see create-customer), not as separate fields here.
  const CUST_FIELD = P.customer ? [P.customer] : [];
  const DOC  = [P.salesInvoice, P.receipt];
  // Fiscal results also go on credit notes, so an approved credit note shows its FDN.
  const FISC = P.creditNote ? DOC.concat(P.creditNote) : DOC;
  const BUYER = P.customer ? [P.salesInvoice, P.receipt, P.customer] : DOC;
  const ITEM = [P.inventoryItem, P.nonInventoryItem];
  // fiscal: system-written result field - locked, excluded from copy/clone.
  // show:   appears on the printed/saved document (Manager's DisplayOnView).
  const specs = [
    { create: 'FDN',              match: ['fdn', 'fiscal document number'],            placement: FISC, fiscal: true, show: true },
    { create: 'Verification Code',match: ['verification code', 'antifake code'],       placement: FISC, fiscal: true, show: true },
    { create: 'QR Code',          match: ['qr code'],                                  placement: FISC, type: 3, fiscal: true, show: true }, // Type 3 = Manager's native QR Code field (renders a scannable code)
    { create: 'Device Number',    match: ['device number'],                            placement: FISC, fiscal: true, show: true },
    { create: 'Issued Time',      match: ['issued time'],                              placement: FISC, fiscal: true, show: true },
    { create: 'Invoice ID',       match: ['invoice id'],                               placement: DOC, fiscal: true },
    { create: 'Status',           match: ['status'],                                   placement: FISC, fiscal: true },
    { create: 'Submission Date',  match: ['submission date'],                          placement: FISC, fiscal: true },
    { create: 'Issued By',        match: ['issued by', 'served by', 'operator'],       placement: FISC, show: true },
    // Buyer fields - let the user tag a document before submission so the right
    // buyer type/TIN/payment mode flow into EFRIS (T109/T108). Never locked (the
    // user fills these); buyer-identity fields print, Customer Type stays internal.
    { create: 'Customer Type',    match: ['customer type', 'buyer type'],              placement: BUYER },
    { create: 'Buyer TIN',        match: ['buyer tin', 'customer tin'],                placement: BUYER, show: true },
    { create: 'Payment Method',   match: ['payment method', 'payment mode'],           placement: DOC, show: true },
    // Foreign-buyer fields (EFRIS requires these for non-Ugandan customers).
    { create: 'Passport / ID No', match: ['passport / id no', 'passport', 'passport no', 'id no'], placement: BUYER, show: true },
    { create: 'Nationality',      match: ['nationality', 'country'],                   placement: BUYER, show: true },
    { create: 'Commodity Code',   match: ['commodity code'],                           placement: ITEM },
    { create: 'Category Path',    match: ['category path', 'segment / class grouping'],placement: ITEM },
    { create: 'Price Currency',   match: ['price currency', 'sales currency', 'item currency'], placement: ITEM },
  ];
  // Business Details fields (seller identity and how customers pay). Only when the
  // Business Details placement is known: Manager does not publish its ID, so it is
  // learned from a "Trading As" field the user creates there (see ensure-efris-fields).
  // The customer-field linking matches only "Buyer TIN" / "Customer TIN", so this
  // TIN stays on Business Details.
  if (P.business) {
    const BIZ = [P.business];
    specs.push(
      { create: 'Trading As',     match: ['trading as', 'trade name'],         placement: BIZ, show: true },
      { create: 'TIN',            match: ['tin', 'seller tin'],                placement: BIZ, show: true },
      { create: 'BRN',            match: ['brn', 'seller brn'],                placement: BIZ, show: true },
      );
  }
  // How to pay: on SALES INVOICES only (receipts are already paid, and Business
  // Details would print them on every document). Set the values once in Manager's
  // Sales Invoices Form Defaults and every new invoice carries them.
  const INV = [P.salesInvoice];
  specs.push(
    { create: 'Bank',           match: ['bank', 'bank name'],                placement: INV, show: true },
    { create: 'Account name',   match: ['account name'],                     placement: INV, show: true },
    { create: 'Account number', match: ['account number', 'account no'],    placement: INV, show: true },
    { create: 'Mobile money',   match: ['mobile money', 'momo'],             placement: INV, show: true },
    { create: 'Payment terms',  match: ['payment terms'],                    placement: INV, show: true });
  void CUST_FIELD;
  return specs;
}

// Resolve Manager's "Customer" custom-field placement GUID. Manager's
// text-custom-field form exposes the available placements (name -> GUID); this
// looks for the Customer one. Returns the GUID or '' if not found.
const _isGuid = s => /^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(String(s || ''));
async function discoverCustomerPlacement(ep, tk) {
  const wantsCustomer = s => { const n = String(s || '').toLowerCase(); return n === 'customer' || n === 'customers'; };
  const scan = (obj) => {
    let found = '';
    const visit = (v) => {
      if (found || !v || typeof v !== 'object') return;
      if (Array.isArray(v)) { for (const x of v) visit(x); return; }
      // Shape A: a GUID→name string map (e.g. {"<guid>":"Customers", ...}).
      for (const k in v) {
        if (_isGuid(k) && typeof v[k] === 'string' && wantsCustomer(v[k])) { found = k; return; }
      }
      // Shape B: an object with a name and a guid-bearing field.
      const name = v.name || v.Name || v.label || v.text;
      const guid = v.value || v.key || v.Key || v.guid || v.id;
      if (wantsCustomer(name) && _isGuid(guid)) { found = String(guid); return; }
      for (const k in v) visit(v[k]);
    };
    visit(obj);
    return found;
  };
  let dump = null;
  for (const p of ['/text-custom-field-form', '/custom-field-form', '/custom-fields', '/text-custom-fields']) {
    try { const r = await managerCall(ep, tk, 'GET', p, null); if (!dump && r.data) dump = { p, data: r.data }; const g = scan(r.data); if (g) { console.log(`   Customer placement discovered via ${p}: ${g}`); return g; } } catch(_) {}
  }
  // Fallback: if the user created ONE custom field by hand on the Customers form,
  // its Placement GUID won't be one of our four known doc/item placements - so any
  // unknown placement GUID found on an existing field is the Customer form.
  try {
    const known = new Set(Object.values(MGR_PLACEMENTS).filter(_isGuid).map(s => s.toLowerCase()));
    const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
    const fields = (list.data && list.data.textCustomFields) || [];
    for (const f of fields.slice(0, 30)) {
      const k = f.key || f.Key; if (!k) continue;
      try {
        const tf = await managerCall(ep, tk, 'GET', '/text-custom-field-form/' + bareKey(k), null);
        const pl = (tf.data && (tf.data.Placement || tf.data.Placements)) || [];
        const arr = Array.isArray(pl) ? pl : [pl];
        for (const g of arr) { const gs = String(g || '').toLowerCase(); if (_isGuid(gs) && !known.has(gs)) { console.log(`   Customer placement inferred from field "${f.name}": ${g}`); return String(g); } }
      } catch(_) {}
    }
  } catch(_) {}
  // Not found - log what Manager returned so the Customer placement GUID can be
  // identified from the entry naming "Customer"/"Customers".
  if (dump) {
    console.log(`   ⚠ Customer placement NOT auto-detected. Raw ${dump.p} (find the "Customer(s)" entry + its GUID and send it):`);
    try { console.log('   ' + JSON.stringify(dump.data).slice(0, 2500)); } catch(_) {}
  }
  return '';
}

// List Manager customers for the Customers tab. Manager's own list endpoint
// only carries name/code - the EFRIS Type and TIN live in per-customer custom
// fields, so enrich each entry from its form (capped: huge customer lists get
// name-only rows past the cap rather than hundreds of extra round trips).
// Enriched rows are kept for a minute per business, and the per-customer forms are
// read 4 at a time: 60 parallel requests made Manager time out and drop them.
const _custCache = {};
function custCacheKey(ep, tk) { return crypto.createHash('sha256').update(String(ep) + '|' + String(tk)).digest('hex').slice(0, 24); }
function clearCustCache(ep, tk) { delete _custCache[custCacheKey(ep, tk)]; }
async function inPool(items, size, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, async () => { while (i < items.length) { const it = items[i++]; await fn(it); } }));
}
app.post('/api/manager/customers', async (req, res) => {
  const { managerEndpoint, accessToken } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  const ck = custCacheKey(ep, tk), hit = _custCache[ck];
  if (hit && Date.now() - hit.at < 60000 && !(req.body && req.body.refresh)) return res.json({ success: true, customers: hit.customers, cached: true });
  try {
    const r = await managerCall(ep, tk, 'GET', '/customers', null);
    const arr = (r.data && (r.data.customers || r.data.Customers)) || [];
    const customers = arr.map(c => ({ name: c.name || c.Name || '', code: c.code || c.Code || '', key: c.key || c.Key || '', type: '', tin: '' }));
    if (customers.length) {
      const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
      const nameByKey = {};
      for (const cf of ((list.data && list.data.textCustomFields) || [])) nameByKey[String(cf.key || cf.Key || '').toLowerCase()] = String(cf.name || '').trim().toLowerCase();
      const ENRICH_CAP = 60;
      await inPool(customers.slice(0, ENRICH_CAP), 2, async c => {
        if (!c.key) return;
        try {
          const f = await managerCall(ep, tk, 'GET', '/customer-form/' + bareKey(c.key), null);
          const strings = (f.data && f.data.CustomFields2 && f.data.CustomFields2.Strings) || {};
          const pick = (names) => { for (const k of Object.keys(strings)) { const nm = nameByKey[String(k).toLowerCase()]; if (nm && names.includes(nm)) { const v = strings[k]; if (v != null && String(v).trim() !== '') return String(v).trim(); } } return ''; };
          c.type = pick(['efris customer type', 'customer type', 'buyer type']);
          c.tin = pick(['efris tin', 'buyer tin', 'customer tin', 'tin']);
          c.passport = pick(['efris passport / id', 'passport / id no', 'passport / id', 'passport', 'id no']);
          c.nationality = pick(['efris nationality', 'nationality', 'country']);
        } catch (_) {}
      });
      if (customers.length > ENRICH_CAP) console.log(`   customers list: enriched first ${ENRICH_CAP} of ${customers.length} with type/TIN`);
    }
    _custCache[ck] = { at: Date.now(), customers };
    res.json({ success: true, customers });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Delete a Manager customer. DELETE alone isn't trusted (this session's rule:
// HTTP status codes lie) - read the record back and require it actually gone.
app.post('/api/manager/delete-customer', async (req, res) => {
  const { managerEndpoint, accessToken, key } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk || !key) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and key required' });
  clearCustCache(ep, tk);   // the customer list changes
  try {
    const k = bareKey(key);
    const r = await managerCall(ep, tk, 'DELETE', '/customer-form/' + k, null);
    const chk = await managerCall(ep, tk, 'GET', '/customer-form/' + k, null);
    const gone = !(chk.status === 200 && chk.data && (chk.data.Name || chk.data.name));
    console.log(`   delete-customer ${k}: DELETE HTTP ${r.status}, readback ${chk.status} → ${gone ? 'gone' : 'STILL THERE'}`);
    if (gone) return res.json({ success: true });
    res.json({ success: false, error: `Manager did not delete the customer (DELETE HTTP ${r.status}). It may be referenced by invoices/receipts - Manager refuses to delete customers with transactions.` });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// One customer's details + EFRIS buyer fields (for the receipt/submit buyer picker).
app.post('/api/manager/customer-detail', async (req, res) => {
  const { managerEndpoint, accessToken, key } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk || !key) return res.status(400).json({ success: false, error: 'key required' });
  try {
    const f = await managerCall(ep, tk, 'GET', '/customer-form/' + bareKey(key), null);
    const d = f.data || {};
    const strings = (d.CustomFields2 && d.CustomFields2.Strings) || {};
    const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
    const nameByKey = {};
    for (const cf of ((list.data && list.data.textCustomFields) || [])) nameByKey[String(cf.key || cf.Key || '').toLowerCase()] = String(cf.name || '').trim().toLowerCase();
    const pick = (names) => { for (const k of Object.keys(strings)) { const nm = nameByKey[String(k).toLowerCase()]; if (nm && names.includes(nm)) { const v = strings[k]; if (v != null && String(v).trim() !== '') return String(v).trim(); } } return ''; };
    res.json({ success: true, customer: {
      name: d.Name || d.name || '',
      type: pick(['efris customer type', 'customer type', 'buyer type']),
      tin: pick(['buyer tin', 'efris tin', 'tin', 'customer tin']),
      passport: pick(['efris passport / id', 'passport / id', 'passport', 'passport / id no', 'id no']),
      nationality: pick(['efris nationality', 'nationality', 'country']),
      billing: d.BillingAddress || '',
    } });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Create a customer in Manager from the extension, populating the EFRIS buyer
// custom fields. Ensures the customer-object fields exist first (resolving the
// Customer placement); if the placement can't be found, still creates the customer
// (name only) and reports which fields were skipped.
app.post('/api/manager/create-customer', async (req, res) => {
  const { managerEndpoint, accessToken, customer } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk || !customer || !customer.name) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and customer.name required' });
  clearCustCache(ep, tk);   // the customer list changes
  try {
    const placement = customer.placement || MGR_PLACEMENTS.customer || await discoverCustomerPlacement(ep, tk);
    // Reuse the SAME custom fields already created for documents - just ADD the
    // Customer placement to them (a Manager field can live on many forms). No
    // duplicate "EFRIS *" fields. Each concept maps to its existing field name.
    const specs = [
      { field: 'Customer Type',    aliases: ['customer type', 'buyer type'],                 val: customer.type },
      { field: 'Buyer TIN',        aliases: ['buyer tin', 'customer tin'],                   val: customer.tin, show: true },
      { field: 'Nationality',      aliases: ['nationality', 'country'],                      val: customer.nationality, show: true },
      { field: 'Passport / ID No', aliases: ['passport / id no', 'passport / id', 'passport', 'id no'], val: customer.passport, show: true },
    ];
    const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
    const existing = (list.data && list.data.textCustomFields) || [];
    const findField = (names) => existing.find(f => names.includes(String(f.name || '').trim().toLowerCase()));
    // Ensure `placement` is in a field's Placement array, preserving everything else.
    const ensurePlacement = async (key) => {
      try {
        const tf = await managerCall(ep, tk, 'GET', '/text-custom-field-form/' + bareKey(key), null);
        const form = tf.data || {};
        let pl = form.Placement || form.Placements || [];
        pl = Array.isArray(pl) ? pl.slice() : (pl ? [pl] : []);
        if (pl.map(x => String(x).toLowerCase()).includes(String(placement).toLowerCase())) return true; // already there
        pl.push(placement);
        form.Placement = pl;
        const pr = await managerCall(ep, tk, 'POST', '/text-custom-field-form/' + bareKey(key), form);
        return pr.status >= 200 && pr.status < 400;
      } catch (_) { return false; }
    };
    const fieldKey = {}; let extended = [];
    if (placement) {
      for (const s of specs) {
        const names = [s.field.toLowerCase(), ...s.aliases];
        let f = findField(names);
        if (f) {
          const k = f.key || f.Key;
          if (await ensurePlacement(k)) extended.push(f.name);
          fieldKey[s.field] = k;
        } else {
          // Field doesn't exist at all - create it on documents + the customer form.
          try {
            await managerCall(ep, tk, 'POST', '/text-custom-field-form', Object.assign({ Name: s.field, Placement: [MGR_PLACEMENTS.salesInvoice, MGR_PLACEMENTS.receipt, placement] }, s.show ? { DisplayOnView: true } : {}));
            const l2 = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
            const nf = ((l2.data && l2.data.textCustomFields) || []).find(x => String(x.name || '').trim().toLowerCase() === s.field.toLowerCase());
            if (nf) fieldKey[s.field] = nf.key || nf.Key;
          } catch (_) {}
        }
      }
      if (extended.length) console.log(`   ↳ added Customer placement to: ${extended.join(', ')}`);
    }
    // Build the customer form: Name + CustomFields2.Strings{ fieldKey: value }.
    const strings = {};
    for (const s of specs) { const k = fieldKey[s.field]; if (k && s.val != null && String(s.val).trim() !== '') strings[k] = String(s.val).trim(); }
    // Editing an existing customer: GET → merge → POST back to its key, so
    // fields we don't manage (email, credit limit, etc.) are preserved.
    if (customer.key) {
      const k = bareKey(customer.key);
      const gf = await managerCall(ep, tk, 'GET', '/customer-form/' + k, null);
      if (gf.status !== 200 || !gf.data) return res.json({ success: false, error: `Could not fetch the existing customer (HTTP ${gf.status})` });
      const form = Object.assign({}, gf.data);
      form.Name = customer.name;
      form.BillingAddress = String(customer.billing || '').trim();
      form.DeliveryAddress = String(customer.delivery || '').trim();
      const cf2 = form.CustomFields2 || {};
      form.CustomFields2 = Object.assign({}, cf2, { Strings: Object.assign({}, cf2.Strings || {}, strings) });
      const ur = await managerCall(ep, tk, 'POST', '/customer-form/' + k, form);
      if (ur.status >= 200 && ur.status < 300) {
        console.log(`   ✅ Updated Manager customer "${customer.name}" (key ${k}); ${Object.keys(strings).length} EFRIS field(s) set`);
        return res.json({ success: true, key: k, action: 'updated', fieldsSet: Object.keys(strings).length });
      }
      return res.json({ success: false, error: 'Manager rejected the update (HTTP ' + ur.status + ')', detail: ur.data });
    }
    const body = { Name: customer.name };
    if (customer.billing && String(customer.billing).trim())   body.BillingAddress = String(customer.billing).trim();
    if (customer.delivery && String(customer.delivery).trim()) body.DeliveryAddress = String(customer.delivery).trim();
    if (Object.keys(strings).length) body.CustomFields2 = { Strings: strings };
    const r = await managerCall(ep, tk, 'POST', '/customer-form', body);
    if (r.status >= 200 && r.status < 300) {
      const key = (r.data && (r.data.key || r.data.Key)) || null;
      console.log(`   ✅ Created Manager customer "${customer.name}" (key ${key}); ${Object.keys(strings).length} EFRIS field(s) set${placement ? '' : ' - customer fields skipped (no placement)'}`);
      return res.json({ success: true, key, placement: placement || null, fieldsSet: Object.keys(strings).length,
        note: placement ? undefined : 'Customer created, but the EFRIS buyer fields could not be attached (Manager Customer placement not found). Create one customer custom field by hand once, then re-run.' });
    }
    res.json({ success: false, error: 'Manager rejected the customer (HTTP ' + r.status + ')', detail: r.data });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Report which EFRIS fields exist vs are missing (no writes).
app.get('/api/manager/efris-fields-status', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  try {
    const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
    const have = new Set(((list.data && list.data.textCustomFields) || []).map(f => (f.name || '').trim().toLowerCase()));
    const specs = efrisFieldSpecs(MGR_PLACEMENTS);
    const existing = [], missing = [];
    for (const s of specs) (s.match.some(n => have.has(n)) ? existing : missing).push(s.create);
    res.json({ success: true, existing, missing });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Create any missing EFRIS custom fields. Placement GUIDs may be overridden in
// the body (placements:{salesInvoice,receipt,inventoryItem,nonInventoryItem}).
// Serialize ensure-efris-fields calls per Manager endpoint. Two overlapping calls
// each take their "what already exists" snapshot before the other's creates are
// visible, which duplicates the item-level fields (Commodity Code, Category Path,
// Price Currency). Chaining per endpoint makes the second call see the first's
// fields and skip them.
// ── Manager tax codes for the EFRIS VAT categories ──
// buildT109 picks a line's EFRIS tax category from the Manager tax-code NAME
// (deemed / exempt / zero / standard, else any VAT amount -> standard). A
// VAT-registered business needs one code per category. Each wanted code is
// matched against the existing codes by name and created only when missing;
// new codes copy the shape of an existing tax-code form (GET /tax-code-form/{key})
// with the name and rate replaced, so Manager's own field set is kept.
const EFRIS_TAX_CODES = [
  { cat: 'standard', name: 'VAT 18%', rate: 18 },
  { cat: 'zero', name: 'Zero rated 0%', rate: 0 },
  { cat: 'exempt', name: 'Exempt', rate: 0 },
  { cat: 'deemed', name: 'Deemed VAT 18%', rate: 18 },
];
// The EFRIS category buildT109 gives a tax code with this name ('' = none: no VAT
// word, so only a line with a VAT amount would count as standard).
function taxCodeCategory(name) {
  const n = String(name || '').toLowerCase();
  if (/deemed/.test(n)) return 'deemed';
  if (/exempt/.test(n)) return 'exempt';
  if (/zero/.test(n)) return 'zero';
  if (/(^|[^\d.])0(\.0+)?\s*%/.test(n)) return 'zero';
  if (/standard|\bvat\b|18\s*%|\b18\b/.test(n)) return 'standard';
  return '';
}
// Copy a tax-code form and set its name and rate. Rates is Manager's rate list
// (one entry for a single-rate code); any other numeric *Rate* key follows too.
function taxCodeFormFrom(template, name, rate) {
  const out = {};
  for (const k of Object.keys(template || {})) if (!['Key', 'key', 'Name', 'name', 'Code', 'code'].includes(k)) out[k] = template[k];
  out.Name = name;
  let set = false;
  for (const k of Object.keys(out)) {
    if (k === 'Rates' && Array.isArray(out[k])) { out[k] = [rate]; set = true; }
    else if (/rate$/i.test(k) && typeof out[k] === 'number') { out[k] = rate; set = true; }
  }
  if (!set) out.Rates = [rate];
  return out;
}
async function ensureEfrisTaxCodes(ep, tk) {
  const created = [], existing = [], failed = [];
  const list = await managerCall(ep, tk, 'GET', '/tax-codes', null);
  if (list.status && list.status >= 400) throw new Error('Manager /tax-codes: HTTP ' + list.status);
  const codes = ((list.data && (list.data.taxCodes || list.data.TaxCodes)) || []).map(c => ({ key: c.key || c.Key, name: String(c.name || c.Name || '') }));
  let template = null;
  const tplCode = codes.find(c => taxCodeCategory(c.name) === 'standard') || codes[0];
  if (tplCode && tplCode.key) {
    try { const f = await managerCall(ep, tk, 'GET', '/tax-code-form/' + bareKey(tplCode.key), null); if (f.status === 200 && f.data && typeof f.data === 'object') template = f.data; } catch (_) {}
  }
  for (const w of EFRIS_TAX_CODES) {
    const have = codes.find(c => taxCodeCategory(c.name) === w.cat);
    if (have) { existing.push({ category: w.cat, name: have.name }); continue; }
    const form = taxCodeFormFrom(template || {}, w.name, w.rate);
    try {
      const r = await managerCall(ep, tk, 'POST', '/tax-code-form', form);
      if (r.status === 200 || r.status === 201) { created.push({ category: w.cat, name: w.name }); codes.push({ key: '', name: w.name }); console.log('   ✓ created tax code: ' + w.name); }
      else failed.push({ category: w.cat, name: w.name, error: (r.data && (r.data.error || JSON.stringify(r.data))) || ('HTTP ' + r.status) });
    } catch (e) { failed.push({ category: w.cat, name: w.name, error: e.message }); }
  }
  return { created, existing, failed, templateUsed: template ? tplCode.name : null };
}
// VAT registration for the tax codes: the caller's flag, else URA's T103 tax types.
async function vatRegisteredFor(body) {
  const b = body || {};
  if (typeof b.vatRegistered === 'boolean') return { vat: b.vatRegistered, source: 'settings' };
  const c = b.config;
  if (c && typeof c.vatRegistered === 'boolean') return { vat: c.vatRegistered, source: 'settings' };
  if (c && c.tin && c.deviceNo) {
    try {
      const s = await getSession(c.tin, c.deviceNo, c.efrisPassword, uraUrl(c.mode), keyOverrideFrom(c));
      const tt = s.login && (s.login.taxType || (s.login.taxpayer && s.login.taxpayer.taxType));
      if (Array.isArray(tt) && tt.length) return { vat: tt.some(t => /value.?added|\bvat\b/i.test(String((t && (t.taxTypeName || t.name)) || ''))), source: 'URA T103' };
    } catch (_) {}
  }
  return { vat: null, source: '' };
}

const _ensureFieldChains = new Map();
function _ensureSerialize(key, fn) {
  const prev = _ensureFieldChains.get(key) || Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  _ensureFieldChains.set(key, next.catch(() => {}));
  return next;
}

app.post('/api/manager/ensure-efris-fields', async (req, res) => {
  const { managerEndpoint, accessToken, placements } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  return _ensureSerialize(ep, async () => {
  const P = Object.assign({}, MGR_PLACEMENTS, placements || {});
  // Resolve the Customer placement GUID (override, else auto-resolve). If
  // unknown, the customer-object fields are skipped and reported as such.
  if (!P.customer) { try { P.customer = await discoverCustomerPlacement(ep, tk); } catch(_) {} }
  // Optional: name of an existing field to copy Type/Size/flags from. Manager's
  // API doesn't document the field shape (OpenAPI says only "object"), so the
  // reliable way to match a user's preferred Type/Size/printed-doc flags is to
  // replicate an example field they configured by hand.
  const templateName = ((req.body || {}).templateField || '').trim().toLowerCase();
  try {
    const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
    const allFields = (list.data && list.data.textCustomFields) || [];
    const have = new Set(allFields.map(f => (f.name || '').trim().toLowerCase()));
    // Learn the Business Details placement from a "Trading As" field created there by
    // hand: its placement that is not one of the known document/item/customer forms.
    let businessNote;
    if (!P.business) {
      const ta = allFields.find(f => ['trading as', 'trade name'].includes((f.name || '').trim().toLowerCase()));
      if (ta) {
        try {
          const tf = await managerCall(ep, tk, 'GET', '/text-custom-field-form/' + bareKey(ta.key || ta.Key), null);
          const pl = (tf.data && (tf.data.Placement || tf.data.Placements)) || [];
          const known = Object.values(MGR_PLACEMENTS).map(x => String(x).toLowerCase()).concat(P.customer ? [String(P.customer).toLowerCase()] : []);
          const biz = (Array.isArray(pl) ? pl : [pl]).find(x => x && !known.includes(String(x).toLowerCase()));
          if (biz) { P.business = biz; console.log('   Business Details placement learned from "' + ta.name + '": ' + biz); }
          else businessNote = 'The "' + ta.name + '" field is not placed on Business Details. Edit it in Manager and tick Business Details, then run this again.';
        } catch (_) {}
      } else {
        businessNote = 'To add seller and payment fields to Manager Business Details (TIN, BRN, Bank, Account name, Account number, Mobile money, Payment terms): in Manager open Settings, Custom Fields, New Text Field, name it "Trading As", tick Business Details and Display on printed documents, Create, then run this again.';
      }
    }
    // Build a template of non-identity attributes (everything except Name/Key/
    // Placement) from a chosen field, else the first existing field.
    let template = {};
    const tplField = allFields.find(f => (f.name || '').trim().toLowerCase() === templateName) || allFields[0];
    if (tplField) {
      const k = tplField.key || tplField.Key;
      try {
        const tf = await managerCall(ep, tk, 'GET', `/text-custom-field-form/${k}`, null);
        const src = tf.data || {};
        for (const key in src) {
          if (['Name','Key','key','Placement','Placements','name'].includes(key)) continue;
          template[key] = src[key];
        }
        console.log(`   ℹ ensure-fields: copying attributes from template "${tplField.name}": ${Object.keys(template).join(', ') || '(none)'}`);
      } catch(_) {}
    }
    const specs = efrisFieldSpecs(P);
    const created = [], skipped = [], failed = [];
    const extended = [];
    for (const s of specs) {
      if (s.match.some(n => have.has(n))) {
        skipped.push(s.create);
        // Existing field: add any placement it is missing (e.g. Credit Note on older set-ups).
        const ex = allFields.find(f => s.match.includes((f.name || '').trim().toLowerCase()));
        if (ex && Array.isArray(s.placement)) {
          try {
            const tf = await managerCall(ep, tk, 'GET', '/text-custom-field-form/' + bareKey(ex.key || ex.Key), null);
            const form = tf.data || {};
            const pl = [].concat(form.Placement || form.Placements || []);
            const have2 = new Set(pl.map(x => String(x).toLowerCase()));
            const add = s.placement.filter(g => g && !have2.has(String(g).toLowerCase()));
            if (add.length && tf.status === 200) {
              form.Placement = pl.concat(add);
              const pr = await managerCall(ep, tk, 'POST', '/text-custom-field-form/' + bareKey(ex.key || ex.Key), form);
              if (pr.status >= 200 && pr.status < 400) extended.push(ex.name);
            }
          } catch (_) {}
        }
        continue;
      }
      // Force the field Type explicitly (Manager: 0=single line, 1=paragraph,
      // 2=drop-down, 3=QR Code) so QR Code renders as a scannable code and the
      // rest stay single-line text - never inheriting a wrong Type from the template.
      // Also force Manager's display/lock flags (keys read from a real field form):
      // fiscal result fields are locked and excluded from copy/clone so a cloned
      // invoice never carries a stale FDN; `show` fields appear on the printed/saved
      // document (DisplayOnView). These are forced, not inherited from the template.
      const flags = {};
      if (s.fiscal) { flags.LockedForManualEditing = true; flags.ExcludeFromCopyingOrCloning = true; }
      if (s.show) flags.DisplayOnView = true;
      const base = { Name: s.create, Placement: s.placement, Type: (s.type !== undefined ? s.type : 0) };
      const full = Object.assign({}, template, flags, base);
      try {
        let r = await managerCall(ep, tk, 'POST', '/text-custom-field-form', full);
        // If the richer payload is rejected, retry with the minimal shape so the
        // field is still created (richness is best-effort, never a blocker). The
        // learned flags are valid Manager keys, so they stay on the retry.
        if (!(r.status === 200 || r.status === 201) && Object.keys(template).length) {
          console.log(`   ⚠ rich create for "${s.create}" failed (HTTP ${r.status}) - retrying minimal`);
          r = await managerCall(ep, tk, 'POST', '/text-custom-field-form', Object.assign({}, flags, base));
        }
        if (r.status === 200 || r.status === 201) { created.push(s.create); have.add(s.create.trim().toLowerCase()); s.match.forEach(n => have.add(n)); console.log(`   ✓ created custom field: ${s.create}`); }
        else { failed.push({ field: s.create, status: r.status, error: r._cfChallenge ? 'Blocked by Cloudflare\'s browser-challenge page (not a Manager error) - add a WAF/Bot Fight Mode exception for this path' : ((r.data && (r.data.error || JSON.stringify(r.data))) || (r._htmlSnippet ? `HTTP ${r.status} - ${r._htmlSnippet}` : ('HTTP ' + r.status))) }); }
      } catch (e) { failed.push({ field: s.create, error: e.message }); }
    }
    if (extended.length) console.log(`   ↳ added missing placements (e.g. Credit Note) to: ${extended.join(', ')}`);
    // Tax codes for the EFRIS VAT categories (VAT-registered businesses only).
    let taxCodes;
    const vr = await vatRegisteredFor(req.body);
    if (vr.vat === true) {
      try { taxCodes = Object.assign({ vatRegistered: true, source: vr.source }, await ensureEfrisTaxCodes(ep, tk)); }
      catch (e) { taxCodes = { vatRegistered: true, created: [], existing: [], failed: [{ name: 'tax codes', error: e.message }] }; }
    } else {
      taxCodes = { vatRegistered: vr.vat, created: [], existing: [], failed: [],
        note: vr.vat === false ? 'Not VAT-registered: no VAT tax codes are needed in Manager.' : 'VAT registration unknown (set it in Settings or check My details), so no tax codes were created.' };
    }
    res.json({ success: failed.length === 0 && !taxCodes.failed.length, taxCodes, created, skipped, extended, failed, templateUsed: tplField ? tplField.name : null,
      customerPlacement: P.customer || null, businessPlacement: P.business || null, businessNote,
      customerNote: P.customer ? undefined : 'Could not auto-detect Manager\'s Customer form placement, so the customer-object fields were skipped. The document-level buyer fields (Customer Type, Buyer TIN, Passport/ID, Nationality) were still created and are what EFRIS uses.' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
  });
});

app.get('/api/manager/divisions', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  try {
    const r = await managerCall(ep, tk, 'GET', '/divisions', null);
    if (r.status === 200 && r.data) {
      const arr = Array.isArray(r.data) ? r.data : (r.data.divisions || []);
      const divisions = arr.map(d => ({ key: d.key || d.Key, name: d.name || d.Name || '' })).filter(d => d.key);
      return res.json({ success: true, divisions });
    }
    res.json({ success: true, divisions: [] });
  } catch(e) {
    res.json({ success: false, error: e.message });
  }
});

// List all Manager items (inventory + non-inventory) for the create-receipt picker
app.get('/api/manager/items-list', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  try {
    // Explicitly request the columns we need (incl. SalePrice) - Manager list
    // endpoints otherwise return only a default subset.
    const cols = '?fields=ItemCode&fields=ItemName&fields=SalePrice&fields=UnitName';
    const [invR, niR] = await Promise.all([
      managerCall(ep, tk, 'GET', '/inventory-items' + cols, null),
      managerCall(ep, tk, 'GET', '/non-inventory-items' + cols, null)
    ]);
    const num = v => { if (v == null) return 0; if (typeof v === 'object') v = v.value != null ? v.value : (v.amount != null ? v.amount : 0); return parseFloat(v) || 0; };
    const cur = v => (v && typeof v === 'object' && v.currency) ? String(v.currency) : '';
    const mapItem = (i, type) => {
      const sp = i.SalePrice || i.salePrice || i.salesPrice || i.SalesPrice || i.unitPrice || i.UnitPrice || i.price || i.Price;
      return {
        key:   i.key  || i.Key  || '',
        code:  i.code || i.Code || i.ItemCode || i.itemCode || '',
        name:  i.itemName || i.ItemName || i.name || i.Name || '',
        // The list returns the price as "SalePrice" (not Sales-); may be a {value,currency} object.
        price: num(sp),
        currency: cur(sp),
        type
      };
    };
    const inv = (invR.data && (invR.data.inventoryItems  || invR.data.InventoryItems  || [])).map(i => mapItem(i, 'inventory'));
    const ni  = (niR.data  && (niR.data.nonInventoryItems || niR.data.NonInventoryItems || [])).map(i => mapItem(i, 'service'));
    // The ?fields filter can leave out the item code. Fill missing codes from the
    // unfiltered list (which has key and code), matched by key.
    for (const [list, path, prop] of [[inv, '/inventory-items', 'inventoryItems'], [ni, '/non-inventory-items', 'nonInventoryItems']]) {
      if (!list.some(x => !x.code)) continue;
      try {
        const full = await managerCall(ep, tk, 'GET', path, null);
        const rows = (full.data && (full.data[prop] || full.data[prop[0].toUpperCase() + prop.slice(1)])) || [];
        const codeByKey = {};
        for (const r of rows) { const k = r.key || r.Key; const c = r.ItemCode || r.itemCode || r.code || r.Code; if (k && c) codeByKey[k] = c; }
        for (const x of list) if (!x.code && codeByKey[x.key]) x.code = codeByKey[x.key];
      } catch (_) {}
    }
    console.log(`[items-list] inventory=${inv.length} non-inventory=${ni.length} first=${JSON.stringify((inv[0]||ni[0])||{})} rawKeys=${Object.keys(((invR.data&&(invR.data.inventoryItems||invR.data.InventoryItems))||[])[0]||{}).join(',')}`);
    res.json({ success: true, items: [...inv, ...ni] });
  } catch(e) { res.status(502).json({ success: false, error: 'Could not read items from Manager: ' + String(e.message || '').slice(0, 160) }); }
});

// Create a new receipt in Manager (then the frontend submits to EFRIS separately)
app.post('/api/manager/create-receipt', async (req, res) => {
  const { managerEndpoint, accessToken, receipt } = req.body || {};
  if (!managerEndpoint || !accessToken) return res.status(400).json({ success: false, error: 'Missing Manager credentials' });
  const ep = normEp(managerEndpoint);
  try {
    // Manager has NO "blank form" GET (GET /receipt-form/{key} needs a key), so we
    // build the payload and POST it directly. A receipt requires a "Received in"
    // bank/cash account - use the one supplied, else default to the first account.
    // Deposit account per payment method: the one supplied (Settings map or the
    // per-receipt picker), else the bank/cash account whose name matches the method
    // in the receipt currency.
    let accts = [];
    try { const bankR = await managerCall(ep, accessToken, 'GET', '/bank-and-cash-accounts', null); accts = (bankR.data && (bankR.data.bankAndCashAccounts || bankR.data.BankAndCashAccounts)) || []; } catch (_) {}
    const want = String(receipt.currency || 'UGX').toUpperCase();
    const accCur = a => String(a.currency || a.Currency || a.foreignCurrency || a.ForeignCurrency || (a.actualBalance && a.actualBalance.currency) || '').toUpperCase();
    const nm = a => String(a.name || a.Name || '');
    const accKey = a => a ? (a.key || a.Key || '') : '';
    const FX = /eur|usd|gbp|kes|tzs|rwf|euro|dollar|pound/i;
    const curOk = a => accCur(a) === want || (want === 'UGX' && !accCur(a) && !FX.test(nm(a)));
    const accountFor = (method) => {
      const pm = String(method || '').toLowerCase();
      let pmKey = null;
      if (/cash/.test(pm)) pmKey = /cash/i;
      else if (/mobile|momo|mtn|airtel/.test(pm)) pmKey = /mobile|momo|mtn|airtel/i;
      else if (/bank|transfer|eft|cheque|card|pos|credit|debit|visa|master|rtgs|swift|draft/.test(pm)) pmKey = /bank|transfer|eft/i;
      return (pmKey ? accts.find(a => curOk(a) && pmKey.test(nm(a))) : null) ||
        (pmKey ? accts.find(a => pmKey.test(nm(a))) : null) ||
        accts.find(a => accCur(a) === want) ||
        (want === 'UGX' ? accts.find(a => !accCur(a) && !FX.test(nm(a))) : null) ||
        (want === 'UGX' ? accts.find(a => !accCur(a)) : null) ||
        accts.find(a => !FX.test(nm(a))) || accts[0] || null;
    };
    const accName = k => { const a = accts.find(x => bareKey(accKey(x)) === bareKey(k)); return a ? nm(a) : k; };
    // Split payment parts, each with its account. The receipt goes into the first
    // part's account (Manager receipts have one "Received in"); each other part is
    // moved to its own account with an Inter Account Transfer after the receipt.
    const parts = (Array.isArray(receipt.payments) ? receipt.payments : []).filter(p => parseFloat(p.amount) > 0)
      .map(p => ({ method: String(p.method || ''), amount: parseFloat(p.amount), txn: String(p.txn || '').trim().slice(0, 60), account: p.account || accKey(accountFor(p.method)) }));
    let receivedIn = receipt.receivedIn || (parts[0] && parts[0].account) || accKey(accountFor(receipt.paymentMethod));
    if (parts[0]) parts[0].account = receivedIn;
    if (receivedIn) console.log(`   Received-in account: "${accName(receivedIn)}" (payment: ${receipt.paymentMethod || 'n/a'})`);
    // A foreign-currency sale going into an account kept in another currency (no
    // USD account, say): Manager would book the USD figures as shillings. Record it
    // in the account's currency at the receipt's exchange rate instead.
    // A sale in a foreign currency goes to an account kept in that currency when
    // the business has one (e.g. "Cash on Hand USD"), even if the payment-method
    // mapping in Settings points at the UGX account.
    if (want !== 'UGX') {
      const cur0 = accts.find(a => bareKey(accKey(a)) === bareKey(receivedIn));
      if (!cur0 || accCur(cur0) !== want) {
        const pmFor = m => { const x = String(m || '').toLowerCase(); return /cash/.test(x) ? /cash/i : /mobile|momo|mtn|airtel/.test(x) ? /mobile|momo|mtn|airtel/i : /bank|transfer|eft|cheque|card|pos|visa|master|rtgs|swift|draft/.test(x) ? /bank|transfer|eft/i : null; };
        const inCur = accts.filter(a => accCur(a) === want);
        const re = pmFor((parts[0] && parts[0].method) || receipt.paymentMethod);
        const pick = (re && inCur.find(a => re.test(nm(a)))) || inCur[0];
        if (pick) { receivedIn = accKey(pick); if (parts[0]) parts[0].account = receivedIn; console.log(`   ${want} sale: using the ${want} account "${nm(pick)}"`); }
      }
    }
    {
      const acct = accts.find(a => bareKey(accKey(a)) === bareKey(receivedIn));
      const acctCur = (acct && accCur(acct)) || 'UGX';
      const fx = parseFloat(receipt.exchangeRate) || 0;
      if (want !== acctCur && acctCur === 'UGX') {
        if (fx > 0) {
          const total = (receipt.lines || []).reduce((t, l) => t + (parseFloat(l.qty) || 1) * (parseFloat(l.unitPrice) || 0), 0);
          receipt.lines = (receipt.lines || []).map(l => ({ ...l, unitPrice: Math.round((parseFloat(l.unitPrice) || 0) * fx * 100) / 100 }));
          parts.forEach(pt => { pt.amount = Math.round(pt.amount * fx * 100) / 100; });
          receipt.description = (receipt.description || '') + ` (${want} ${total.toFixed(2)} at ${fx} UGX/${want})`;
          console.log(`   ${want} receipt into a UGX account: recorded in UGX at ${fx} (${want} ${total.toFixed(2)} = UGX ${Math.round(total * fx).toLocaleString()})`);
        } else console.log(`   ⚠ ${want} receipt into a UGX account with no exchange rate - amounts recorded as they are`);
      }
    }
    const form = {};
    form.Date = receipt.date || eatToday();
    if (receipt.reference) form.Reference = receipt.reference;
    // "Paid by" needs a Customer KEY (a bare name shows as "Other"). Resolve the
    // name to an existing customer, else create one, then link it.
    if (receipt.customer) {
      const custName = String(receipt.customer).trim();
      let custKey = '';
      try {
        const cr = await managerCall(ep, accessToken, 'GET', '/customers', null);
        const arr = (cr.data && (cr.data.customers || cr.data.Customers || [])) || [];
        const hit = arr.find(c => String(c.name || c.Name || '').trim().toLowerCase() === custName.toLowerCase());
        if (hit) custKey = hit.key || hit.Key || '';
        if (!custKey) {
          const nc = await managerCall(ep, accessToken, 'POST', '/customer-form', { Name: custName });
          if (nc.status >= 200 && nc.status < 400) {
            custKey = (nc.data && (nc.data.key || nc.data.Key)) || '';
            if (!custKey) { // re-list to find the new key
              try { const cr2 = await managerCall(ep, accessToken, 'GET', '/customers', null); const a2 = (cr2.data && (cr2.data.customers || cr2.data.Customers || [])) || []; const h2 = a2.find(c => String(c.name || c.Name || '').trim().toLowerCase() === custName.toLowerCase()); if (h2) custKey = h2.key || h2.Key || ''; } catch (_) {}
            }
            console.log(`   Created Manager customer "${custName}" → ${custKey || 'unknown'}`);
            clearCustCache(ep, accessToken);
          }
        }
      } catch (_) {}
      // Link as a Customer payer. Manager needs PaidBy=1 (contact type Customer)
      // AND the Customer key; setting Contact alone defaults PaidBy to 0 (Other),
      // which is why the receipt showed "Other → <GUID>" instead of the name.
      if (custKey) { form.PaidBy = 1; form.Customer = custKey; form.Contact = custKey; }
    }
    if (receivedIn)         form.ReceivedIn  = receivedIn;
    if (receipt.description) form.Description = receipt.description;
    form.QuantityColumn = true;
    form.UnitPriceColumn = true;
    form.HasLineDescription = true;
    // Theme: Manager applies Form Defaults only in its own screens, and its API has
    // no Form Defaults endpoint, so set the theme on the receipt itself. Manager
    // needs both the "Custom theme" tick and WHICH theme (CustomThemeId). Use the
    // installed EFRISConnect theme; else the theme of the latest receipt.
    try {
      let themeId = bareKey(receipt.themeKey || '');
      if (themeId) { const tg = await managerCall(ep, accessToken, 'GET', '/custom-theme-form/' + themeId, null); if (tg.status !== 200) { console.log('   Receipt theme ' + themeId + ' not found in Manager (reinstall the theme)'); themeId = ''; } }
      if (!themeId) {
        const rl = await managerCall(ep, accessToken, 'GET', '/receipts?pageSize=5', null);
        for (const r0 of ((rl.data && (rl.data.receipts || rl.data.receiptsAndPayments)) || [])) {
          const rf = await managerCall(ep, accessToken, 'GET', '/receipt-form/' + (r0.key || r0.Key), null);
          if (rf.data && rf.data.CustomThemeId) { themeId = rf.data.CustomThemeId; break; }
        }
      }
      if (themeId) { form.CustomTheme = true; form.CustomThemeId = themeId; console.log('   Receipt theme: ' + themeId); }
      else console.log('   Receipt theme: none installed - Manager default theme used');
    } catch (e) { console.log(`   Receipt theme skipped: ${e.message}`); }
    // Buyer + payment custom fields, so the Manager receipt (and its printed theme)
    // carry the same buyer TIN / type / payment method that EFRIS received - not
    // just the fiscal-result fields (FDN/QR) written later by saveEfrisToManager.
    try {
      const cf = await mgrTextCustomFields(ep, accessToken);
      const cfStr = (form.CustomFields2 && form.CustomFields2.Strings) || {};
      const setCF = (names, val) => { if (val == null || val === '') return; for (const n of names) { const k = cf.byName[n]; if (k) { cfStr[k] = String(val); return; } } };
      setCF(['Buyer TIN', 'Customer TIN'], receipt.buyerTin);
      setCF(['Customer Type', 'Buyer Type'], receipt.customerType);
      setCF(['Payment Method', 'Payment Mode'], receipt.paymentMethod);
      setCF(['Nationality'], receipt.nationality);
      setCF(['Passport / ID No', 'Passport/ID No', 'Passport', 'Passport Number'], receipt.passport);
      if (Object.keys(cfStr).length) form.CustomFields2 = { ...(form.CustomFields2 || {}), Strings: cfStr };
    } catch (e) { console.log(`   Buyer/payment custom fields skipped: ${e.message}`); }
    form.Lines = await Promise.all((receipt.lines || []).map(async l => {
      const price = parseFloat(l.unitPrice) || 0;
      const line = { Qty: parseFloat(l.qty) || 1, UnitPrice: price, SalesUnitPrice: price };
      let key = l.itemKey;
      // Link the line to the Manager inventory/service item (so stock/books update)
      // by resolving from the code or name when no key was supplied.
      if (!key && (l.itemCode || l.itemName)) {
        try { const rk = await resolveManagerItemKey(ep, accessToken, l.itemCode, l.itemName); key = rk.key; } catch (_) {}
      }
      if (key) { line.Item = key; console.log(`   Receipt line linked: "${l.itemName || l.itemCode}" → item ${key}`); }
      else console.log(`   ⚠ Receipt line NOT linked (posts to Suspense): code="${l.itemCode || ''}" name="${l.itemName || ''}" - no matching Manager item`);
      if (l.description) line.LineDescription = l.description;
      if (l.taxCat) { try { const tc = await mgrTaxCodeGuid(ep, accessToken, l.taxCat === 'Deemed' ? 'Standard' : l.taxCat); if (tc) line.TaxCode = tc; else console.log(`   ⚠ No Manager tax code for ${l.taxCat} - line has no VAT in Manager`); } catch (_) {} }
      return line;
    }));
    // Credit sale (part or none of it paid now): a Receipt always means paid in full,
    // so record a Sales Invoice for the whole sale and a payment receipt against it
    // for each part paid now. The rest stays owed by the customer.
    if (receipt.creditSale) {
      if (!form.Customer) return res.status(400).json({ success: false, error: 'A credit sale needs a named customer (the one who owes the balance).' });
      let arKey = '';
      try {
        const coa = await managerCall(ep, accessToken, 'GET', '/chart-of-accounts', null);
        const all = Object.values(coa.data || {}).find(Array.isArray) || [];
        const ar = all.find(a => /^accounts receivable$/i.test(String(a.name || a.Name || '').trim()));
        arKey = ar ? (ar.key || ar.Key) : '';
      } catch (_) {}
      if (!arKey) return res.status(502).json({ success: false, error: 'Could not find the Accounts receivable account in Manager.' });
      // Due date: the customer's own terms in Manager when set, else 14 days.
      let dueDays = 14;
      try { const cf = await managerCall(ep, accessToken, 'GET', '/customer-form/' + bareKey(form.Customer), null); const dd = cf.data && (cf.data.DueDateDays || cf.data.DefaultDueDateDays); if (parseInt(dd, 10) > 0) dueDays = parseInt(dd, 10); } catch (_) {}
      const inv = { IssueDate: form.Date, DueDateDays: dueDays, Customer: form.Customer, Lines: form.Lines, AmountsIncludeTax: true };
      ['Reference', 'Description', 'CustomTheme', 'CustomThemeId', 'CustomFields2', 'HasLineDescription', 'QuantityColumn', 'UnitPriceColumn'].forEach(k => { if (form[k] !== undefined) inv[k] = form[k]; });
      const ir = await managerCall(ep, accessToken, 'POST', '/sales-invoice-form', inv);
      if (ir.status < 200 || ir.status >= 300) return res.status(502).json({ success: false, error: `Manager sales invoice creation failed: HTTP ${ir.status}`, detail: JSON.stringify(ir.data || '').slice(0, 500) });
      let invKey = (ir.data && (ir.data.key || ir.data.Key)) || '';
      if (!invKey && ir.headers) { const loc = ir.headers.location || ir.headers.Location || ''; invKey = String(loc).split('?')[0].split('/').filter(Boolean).pop() || ''; }
      console.log(`   Credit sale: created Manager sales invoice → key: ${invKey || 'unknown'} ref: ${receipt.reference || ''}`);
      const payments = [];
      for (const pt of parts.filter(x => !/credit/i.test(x.method))) {
        const amt = Math.round(pt.amount * 100) / 100;
        const pr = { Date: form.Date, Reference: pt.txn || receipt.reference || '', PaidBy: 1, Customer: form.Customer, ReceivedIn: pt.account || receivedIn,
          Description: `Payment for ${receipt.reference || 'invoice'} (${pt.method}${pt.txn ? ', Txn ' + pt.txn : ''})`,
          // Manager only multiplies Qty x price when these column flags are set;
          // without them the payment is stored as 0.00.
          HasLineDescription: true, QuantityColumn: true, UnitPriceColumn: true,
          Lines: [{ Account: arKey, AccountsReceivableSalesInvoice: invKey, Qty: 1, SalesUnitPrice: amt }] };
        if (form.CustomThemeId) { pr.CustomTheme = true; pr.CustomThemeId = form.CustomThemeId; }
        try {
          const rr = await managerCall(ep, accessToken, 'POST', '/receipt-form', pr);
          const ok = rr.status >= 200 && rr.status < 300;
          if (ok) { try { let pk = (rr.data && (rr.data.key || rr.data.Key)) || ''; if (!pk && rr.headers) pk = String(rr.headers.location || '').split('?')[0].split('/').filter(Boolean).pop() || '';
            if (pk) { const chk = await managerCall(ep, accessToken, 'GET', '/receipt-form/' + pk, null); const ln = ((chk.data && chk.data.Lines) || [])[0] || {};
              if (!((parseFloat(ln.Qty) || 0) * (parseFloat(ln.SalesUnitPrice) || 0) > 0)) console.log('   ⚠ Credit sale: Manager stored the payment as 0 - check receipt ' + (pr.Reference || pk)); } } catch (_) {} }
          console.log(`   Credit sale: ${ok ? 'recorded' : 'could NOT record'} payment ${amt} (${pt.method}) into "${accName(pr.ReceivedIn)}" against ${receipt.reference || invKey}` + (ok ? '' : ` - HTTP ${rr.status}`));
          payments.push({ method: pt.method, amount: amt, ok });
        } catch (e) { console.log('   Credit sale payment error: ' + e.message); payments.push({ method: pt.method, amount: amt, ok: false }); }
      }
      return res.json({ success: true, key: invKey, kind: 'invoice', reference: receipt.reference, payments });
    }
    const createR = await managerCall(ep, accessToken, 'POST', '/receipt-form', form);
    if (createR.status < 200 || createR.status >= 300) {
      return res.status(502).json({
        success: false,
        error: `Manager receipt creation failed: HTTP ${createR.status}`,
        detail: JSON.stringify(createR.data || '').slice(0, 500),
        formFields: Object.keys(form)
      });
    }
    // Extract new key
    let newKey = null;
    const rd = createR.data;
    if (rd && rd.key) newKey = rd.key;
    else if (rd && rd.Key) newKey = rd.Key;
    else if (Array.isArray(rd) && rd.length) {
      const found = rd.find(r => (r.reference || r.Reference) === receipt.reference);
      newKey = ((found || rd[rd.length - 1]).key);
    }
    if (!newKey && createR.headers) {
      const loc = createR.headers['location'] || createR.headers['Location'] || '';
      if (loc) { const parts = loc.split('/').filter(Boolean); newKey = parts[parts.length - 1]; }
    }
    console.log(`   Created Manager receipt → key: ${newKey || 'unknown'} ref: ${receipt.reference || ''}`);
    const transfers = [];
    for (const p of parts.slice(1)) {
      if (!p.account || bareKey(p.account) === bareKey(receivedIn)) continue;
      const amt = Math.round(p.amount * 100) / 100;
      // Accounts in different currencies (a USD sale's part moved to a UGX mobile
      // money account, say): CreditAmount leaves the source in ITS currency and
      // DebitAmount enters the destination in ITS currency, converted at the
      // receipt's exchange rate (UGX per unit of the sale currency).
      const curOf = k => { const a = accts.find(x => bareKey(accKey(x)) === bareKey(k)); return (a && accCur(a)) || 'UGX'; };
      const srcCur = curOf(receivedIn), dstCur = curOf(p.account), fxr = parseFloat(receipt.exchangeRate) || 0;
      let dstAmt = amt;
      if (srcCur !== dstCur) {
        if (fxr > 0 && srcCur === want && dstCur === 'UGX') dstAmt = Math.round(amt * fxr * 100) / 100;
        else if (fxr > 0 && srcCur === 'UGX' && dstCur === want) dstAmt = Math.round(amt / fxr * 100) / 100;
        else console.log(`   ⚠ Split payment from a ${srcCur} account to a ${dstCur} account with no usable exchange rate - same amount recorded on both sides`);
      }
      // The payment's transaction ID (MoMo / bank ref) is the transfer's reference, so
      // it matches the bank or mobile money statement; the receipt number is in the description.
      const iat = { Date: form.Date, Reference: p.txn || receipt.reference || '', Description: `Split payment ${receipt.reference || ''}: ${p.method} part` + (p.txn ? ` (Txn ${p.txn})` : ''),
        PaidFrom: receivedIn, ReceivedIn: p.account, Amount: amt, CreditAmount: amt, DebitAmount: dstAmt };  // amount field name differs across builds; the unknown ones are ignored
      try {
        const tr = await managerCall(ep, accessToken, 'POST', '/inter-account-transfer-form', iat);
        const ok = tr.status >= 200 && tr.status < 300;
        if (ok) { try { const chk = await managerCall(ep, accessToken, 'GET', '/inter-account-transfers?pageSize=5&term=' + encodeURIComponent(iat.Reference), null);
          const row = ((chk.data && chk.data.interAccountTransfers) || [])[0]; const got = row && (row.amount != null ? row.amount : row.Amount);
          const v = got && typeof got === 'object' ? (got.value != null ? got.value : got.Value) : got;
          if (row && Math.abs((parseFloat(v) || 0) - amt) > 0.01) console.log('   ⚠ Split payment transfer recorded with amount ' + JSON.stringify(got) + ' - check it in Manager'); } catch (_) {} }
        console.log(`   Split payment: ${ok ? 'moved' : 'could NOT move'} ${amt} (${p.method}) "${accName(receivedIn)}" → "${accName(p.account)}"` + (ok ? '' : ` - HTTP ${tr.status} ${JSON.stringify(tr.data || '').slice(0, 200)}`));
        transfers.push({ method: p.method, amount: amt, ok });
      } catch (e) { console.log('   Split payment transfer error: ' + e.message); transfers.push({ method: p.method, amount: amt, ok: false }); }
    }
    res.json({ success: true, key: newKey, reference: receipt.reference, transfers });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Return a receipt's form JSON for inspection - used to read the real
// Contact/Customer field names from an existing document.
app.post('/api/manager/debug-receipt-form', async (req, res) => {
  const { managerEndpoint, accessToken, reference } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  try {
    const list = await managerCall(ep, tk, 'GET', '/receipts', null);
    const arr = (list.data && (list.data.receipts || list.data.receiptsAndPayments)) || [];
    const hit = reference ? arr.find(r => String(r.reference || r.Reference || '') === String(reference)) : arr[0];
    if (!hit) return res.json({ success: false, error: 'no matching receipt found', available: arr.map(r => r.reference || r.Reference) });
    const key = hit.key || hit.Key;
    const f = await managerCall(ep, tk, 'GET', '/receipt-form/' + key, null);
    const bc = await managerCall(ep, tk, 'GET', '/bank-and-cash-accounts', null);
    res.json({ success: true, key, form: f.data, bankAndCashAccountsRaw: bc.data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Inspection endpoint: GET any Manager API path and return the raw JSON. Behind the
// relay's API key (operator-only), so the in-app panel can inspect any
// object/form (e.g. /sales-invoice-form/<key>, /customer-form/<key>,
// /inventory-items, /receipt-form/<key>) without the browser console.
app.post('/api/manager/debug-get', async (req, res) => {
  const { managerEndpoint, accessToken, path } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  let p = String(path || '').trim();
  if (!ep || !tk || !p) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and path required' });
  if (!p.startsWith('/')) p = '/' + p;
  try {
    const r = await managerCall(ep, tk, 'GET', p, null);
    res.json({ success: r.status >= 200 && r.status < 300, status: r.status, path: p, data: r.data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Return a text-custom-field's form JSON by name, for inspecting Manager's
// enum value for the "QR code" field type.
app.post('/api/manager/debug-custom-field', async (req, res) => {
  const { managerEndpoint, accessToken, name } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk || !name) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and name required' });
  try {
    const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
    const arr = (list.data && list.data.textCustomFields) || [];
    const hit = arr.find(f => String(f.name || '').trim().toLowerCase() === String(name).trim().toLowerCase());
    if (!hit) return res.json({ success: false, error: 'no field named "' + name + '" found', available: arr.map(f => f.name) });
    const key = hit.key || hit.Key;
    const f = await managerCall(ep, tk, 'GET', '/text-custom-field-form/' + key, null);
    res.json({ success: true, key, form: f.data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Resolve a Manager inventory-item key from its ItemCode (the code we keep in
// sync with the EFRIS goodsCode). Returns null if not found.
async function resolveManagerItemKey(ep, tk, code, name) {
  if (!code && !name) return { key: null, reason: 'no code' };
  const want = String(code || '').trim().toLowerCase();
  const wantName = String(name || '').trim().toLowerCase();
  const codeOf = i => String(i.code || i.Code || i.ItemCode || i.itemCode || '').trim().toLowerCase();
  const nameOf = i => String(i.ItemName || i.itemName || i.name || i.Name || '').trim().toLowerCase();
  const match = arr => {
    let hit = want && arr.find(i => codeOf(i) === want);
    if (!hit && wantName) hit = arr.find(i => nameOf(i) === wantName);
    return hit;
  };
  try {
    // The inventory list doesn't reliably expose the code column, so request it
    // explicitly AND match by name as a fallback.
    let arr = [];
    for (const q of ['?fields=ItemCode', '']) {
      const r = await managerCall(ep, tk, 'GET', '/inventory-items' + q, null);
      arr = (r.data && (r.data.inventoryItems || r.data.InventoryItems || [])) || [];
      const hit = match(arr);
      if (hit) return { key: hit.key || hit.Key || null };
    }
    // Not an inventory item - is it a non-inventory (service) item? Return its KEY
    // (so receipt/invoice lines link to it and don't post to Suspense) AND flag it
    // as non-inventory, so stock callers can still reject it (services hold no stock).
    try {
      const nr = await managerCall(ep, tk, 'GET', '/non-inventory-items', null);
      const narr = (nr.data && (nr.data.nonInventoryItems || nr.data.NonInventoryItems || [])) || [];
      const hit = match(narr);
      if (hit) return { key: hit.key || hit.Key || null, reason: 'non-inventory' };
    } catch (_) {}
    return { key: null, reason: 'not found' };
  } catch (_) { return { key: null, reason: 'lookup failed' }; }
}

// Mirror EFRIS stock movements into Manager's inventory ledger.
//  direction 'in'  → Inventory Write-on  (increase qty)
//  direction 'out' → Inventory Write-off (decrease qty)
// Accepts items:[{itemCode, quantity}] (codes resolved to keys) or a single
// {itemKey, qty}. Reports Manager's exact error per item so the payload shape
// can be tuned if a build rejects it.
// Scan existing inventory write-offs for one with a real (non-empty) lines
// array - i.e. one a human created in Manager's UI - and return its structure:
// which property holds the lines, and which field names its line uses for the
// item reference and quantity. Cached per endpoint after the first hit, since
// the schema doesn't change within a Manager version.
const _writeOffTemplateCache = {};
async function findWriteOffLineTemplate(ep, accessToken) {
  if (_writeOffTemplateCache[ep]) return _writeOffTemplateCache[ep];
  const listR = await managerCall(ep, accessToken, 'GET', '/inventory-write-offs', null);
  if (listR.status !== 200 || !listR.data) return null;
  const listArr = Array.isArray(listR.data) ? listR.data
    : Object.values(listR.data).find(v => Array.isArray(v)) || [];
  // Newest first, but don't scan forever - a template either exists in the
  // recent docs or the user hasn't made one manually yet.
  const candidates = listArr.slice(-12).reverse();
  for (const entry of candidates) {
    const k = entry.key || entry.Key || entry.id;
    if (!k) continue;
    try {
      const formR = await managerCall(ep, accessToken, 'GET', `/inventory-write-off-form/${k}`, null);
      if (formR.status !== 200 || !formR.data) continue;
      for (const [prop, val] of Object.entries(formR.data)) {
        if (!Array.isArray(val) || !val.length || typeof val[0] !== 'object') continue;
        const lineKeys = Object.keys(val[0]);
        const itemField = lineKeys.find(f => /inventoryitem/i.test(f)) || lineKeys.find(f => /item/i.test(f) && !/name|code/i.test(f));
        const qtyField = lineKeys.find(f => /^qty$/i.test(f)) || lineKeys.find(f => /qty|quantity/i.test(f));
        if (itemField && qtyField) {
          console.log(`   write-off template source doc ${k}: ${JSON.stringify(formR.data).slice(0, 500)}`);
          // Keep the whole form, not just the line shape: document-level settings
          // like the Allocation expense account ride along into automated
          // write-offs (otherwise their cost lands in Suspense).
          const form = Object.assign({}, formR.data);
          delete form.Key; delete form.key; delete form.id;
          const tpl = { linesProp: prop, itemField, qtyField, line: val[0], form, sourceKey: k };
          _writeOffTemplateCache[ep] = tpl;
          return tpl;
        }
      }
    } catch (_) {}
  }
  return null;
}

// Record a per-date "Inventory Unit Cost" for an item - the record this
// Manager version actually uses to value write-offs and COGS (AverageCost on
// the starting balance is NOT used for that). Field names are read from an
// existing record when one exists and verified by readback, rather than
// assuming a 201 response means the write succeeded.
const _unitCostTemplateCache = {};
async function recordInventoryUnitCost(ep, accessToken, itemKey, unitCost, date) {
  try {
    let tpl = _unitCostTemplateCache[ep];
    if (!tpl) {
      const listR = await managerCall(ep, accessToken, 'GET', '/inventory-unit-costs', null);
      const listArr = (listR.status === 200 && listR.data)
        ? (Array.isArray(listR.data) ? listR.data : Object.values(listR.data).find(v => Array.isArray(v)) || [])
        : [];
      for (const entry of listArr.slice(-8).reverse()) {
        const k = entry.key || entry.Key || entry.id;
        if (!k) continue;
        const formR = await managerCall(ep, accessToken, 'GET', `/inventory-unit-cost-form/${k}`, null);
        if (formR.status !== 200 || !formR.data) continue;
        const keys = Object.keys(formR.data);
        const itemField = keys.find(f => /inventoryitem/i.test(f)) || keys.find(f => /item/i.test(f) && !/name|code/i.test(f));
        const dateField = keys.find(f => /^date$/i.test(f)) || keys.find(f => /date/i.test(f));
        // Claim item + date first, then keep them out of the cost candidates -
        // /cost/i alone happily matches names like "CostDate"/"CostInventoryItem".
        const claimed = new Set([itemField, dateField, 'Key', 'key', 'id']);
        const costCandidates = keys.filter(f => !claimed.has(f));
        const costField = costCandidates.find(f => /unitcost/i.test(f))
          || costCandidates.find(f => /cost|price|amount/i.test(f) && typeof formR.data[f] === 'number')
          || costCandidates.find(f => /cost|price|amount/i.test(f));
        if (itemField && costField && dateField) {
          const form = Object.assign({}, formR.data);
          delete form.Key; delete form.key; delete form.id;
          tpl = { itemField, costField, dateField, form };
          _unitCostTemplateCache[ep] = tpl;
          console.log(`   unit-cost learned template: item="${itemField}" cost="${costField}" date="${dateField}"`);
          break;
        }
      }
      // No record to learn from yet - use the form's visible labels as the guess
      // (Date / Inventory Item / Unit cost); the readback below is the safety net.
      if (!tpl) tpl = { itemField: 'InventoryItem', costField: 'UnitCost', dateField: 'Date', form: {} };
    }
    const payload = Object.assign({}, tpl.form);
    payload[tpl.dateField] = (String(date).slice(0, 10)) + 'T00:00:00';
    payload[tpl.itemField] = itemKey;
    payload[tpl.costField] = unitCost;
    const r = await managerCall(ep, accessToken, 'POST', '/inventory-unit-cost-form', payload);
    const newKey = r.data && (r.data.Key || r.data.key || r.data.id);
    let took = false;
    if (r.status >= 200 && r.status < 400 && newKey) {
      const chk = await managerCall(ep, accessToken, 'GET', `/inventory-unit-cost-form/${newKey}`, null);
      took = !!(chk.data && chk.data[tpl.itemField] === itemKey && parseFloat(chk.data[tpl.costField]) === unitCost);
      if (!took) delete _unitCostTemplateCache[ep]; // guessed names were dropped - relearn next time
    }
    console.log(`   unit-cost record POST: HTTP ${r.status} item=${itemKey} cost=${unitCost} → ${took ? 'verified' : 'NOT verified'}`);
    return took ? 'recorded' : 'not recorded (set it once manually under Inventory Unit Costs so the format can be learned)';
  } catch (e) { console.log(`   unit-cost record error: ${e.message}`); return 'error: ' + e.message; }
}

// The Manager supplier for a stock-in purchase invoice: found by name, else created.
// A purchase invoice without a supplier lands in Manager's Suspense account.
async function mgrSupplierKey(ep, tk, name) {
  const want = String(name || '').trim() || 'Stock-in Supplier';
  const l = await managerCall(ep, tk, 'GET', '/suppliers?pageSize=1000', null);
  const arr = (l.data && (l.data.suppliers || l.data.Suppliers)) || [];
  const hit = arr.find(s => String(s.name || s.Name || '').trim().toLowerCase() === want.toLowerCase());
  if (hit) return bareKey(hit.key || hit.Key);
  const cr = await managerCall(ep, tk, 'POST', '/supplier-form', { Name: want });
  const k = bareKey((cr.data && (cr.data.Key || cr.data.key || cr.data.id)) || cr.location || '');
  if (k) console.log('   Created supplier "' + want + '" in Manager for the stock-in');
  return k;
}

app.post('/api/manager/inventory-adjust', async (req, res) => {
  const b = req.body || {};
  const { managerEndpoint, accessToken } = b;
  if (!managerEndpoint || !accessToken) {
    return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken are required' });
  }
  const ep = normEp(managerEndpoint);
  const direction = (b.direction === 'out') ? 'out' : 'in';
  const date = b.date || eatToday();
  const description = b.description || (direction === 'in' ? 'Stock-in via EFRISConnect' : 'Stock adjustment via EFRISConnect');
  // Normalise to a list of {itemKey?, itemCode?, qty}
  let items = Array.isArray(b.items) ? b.items.slice()
            : (b.itemKey || b.itemCode) ? [{ itemKey: b.itemKey, itemCode: b.itemCode, qty: b.qty }] : [];
  items = items.map(i => ({ itemKey: i.itemKey || '', itemCode: i.itemCode || i.code || '', itemName: i.itemName || i.name || '', qty: parseFloat(i.qty != null ? i.qty : i.quantity) || 0, unitPrice: parseFloat(i.unitPrice != null ? i.unitPrice : i.unitCost) || 0 }))
               .filter(i => i.qty > 0 && (i.itemKey || i.itemCode || i.itemName));
  if (!items.length) return res.json({ success: false, error: 'No items with a positive quantity to mirror.' });
  let supplierKey;   // looked up once, on the first purchase invoice

  const results = [];
  for (const it of items) {
    let key = it.itemKey;
    if (!key && (it.itemCode || it.itemName)) {
      const resolved = await resolveManagerItemKey(ep, accessToken, it.itemCode, it.itemName);
      key = resolved.key;
      // A non-inventory (service) item now resolves to a key, but it still cannot
      // take stock - reject it by reason, not by a missing key.
      if (!key || resolved.reason === 'non-inventory') {
        const msg = resolved.reason === 'non-inventory'
          ? 'This item is a Non-inventory (Service) item in Manager - Manager only tracks stock for Inventory items. Re-create it as a Goods (Inventory item).'
          : 'Item not found among Manager inventory items (by ItemCode). Re-Sync it to Manager first.';
        results.push({ item: it.itemCode || it.itemKey, ok: false, error: msg });
        continue;
      }
    }
    if (!key) { results.push({ item: it.itemCode || it.itemKey, ok: false, error: 'No item key' }); continue; }
    try {
      if (direction === 'in') {
        // Route by EFRIS stock-in type to the matching Manager document.
        //   101 Import, 102 Local Purchase → Purchase Invoice
        //   103 Manufacture/Assembly      → Production Order
        //   104 Opening Stock             → Starting Balance
        const sit = String(b.stockInType || '').trim();
        if (sit === '103') {
          // Manufacture/Assembly → Production Order (finished item + qty). Bill of
          // materials / labour live in Manager, so we create a minimal order that
          // adds the produced quantity; the user can add the recipe in Manager.
          const po = { Date: (String(date).slice(0, 10)) + 'T00:00:00', FinishedInventoryItem: key, Qty: it.qty, BillOfMaterials: [] };
          const r = await managerCall(ep, accessToken, 'POST', '/production-order-form', po);
          console.log(`   production-order POST: HTTP ${r.status} item=${key} qty=${it.qty} body=${JSON.stringify(r.data||'').slice(0,120)}`);
          if (r.status >= 200 && r.status < 400) results.push({ item: it.itemCode || key, ok: true, path: 'production-order' });
          else results.push({ item: it.itemCode || key, ok: false, error: `Production order HTTP ${r.status}: ${JSON.stringify(r.data||'').slice(0,160)}` });
          continue;
        }
        if (sit === '104') {
          // Opening Stock → Starting Balance (confirmed shape). One per item.
          const sb = {
            InventoryItem: key,
            HasQtyToOnHand: true,
            QtyOnHandLines: [{ QtyOnHand: it.qty }],
            AverageCost: parseFloat(it.unitPrice) || 0
          };
          const r = await managerCall(ep, accessToken, 'POST', '/inventory-item-starting-balance-form', sb);
          console.log(`   starting-balance POST: HTTP ${r.status} item=${key} qty=${it.qty} body=${JSON.stringify(r.data||'').slice(0,120)}`);
          if (r.status >= 200 && r.status < 400) {
            const res = { item: it.itemCode || key, ok: true, path: 'starting-balance' };
            // Manager values write-offs (and COGS) from per-date "Inventory
            // Unit Cost" records, NOT the starting balance's AverageCost -
            // without one, a later write-off posts at zero and its expense
            // account shows nothing. Record the unit cost alongside the opening
            // stock so this step is handled automatically.
            if (parseFloat(it.unitPrice) > 0) res.unitCost = await recordInventoryUnitCost(ep, accessToken, key, parseFloat(it.unitPrice), date);
            results.push(res);
          }
          else results.push({ item: it.itemCode || key, ok: false, error: `Starting balance HTTP ${r.status}: ${JSON.stringify(r.data||'').slice(0,160)}` });
          continue;
        }
        // Purchase Invoice - standard, non-corrupting way to receive inventory.
        const payload = {
          IssueDate: (String(date).slice(0, 10)) + 'T00:00:00',
          Description: description,
          Lines: [{ Item: key, Qty: it.qty, PurchaseUnitPrice: parseFloat(it.unitPrice) || 0 }]
        };
        try { if (supplierKey === undefined) supplierKey = await mgrSupplierKey(ep, accessToken, b.supplierName); } catch (e) { supplierKey = ''; console.log('   Could not set the supplier: ' + e.message); }
        if (supplierKey) payload.Supplier = supplierKey;
        const r = await managerCall(ep, accessToken, 'POST', '/purchase-invoice-form', payload);
        console.log(`   purchase-invoice POST (type ${sit}): HTTP ${r.status} item=${key} qty=${it.qty} body=${JSON.stringify(r.data||'').slice(0,120)}`);
        if (r.status >= 200 && r.status < 400) results.push({ item: it.itemCode || key, ok: true, path: 'purchase-invoice' });
        else results.push({ item: it.itemCode || key, ok: false, error: `Purchase invoice HTTP ${r.status}: ${JSON.stringify(r.data||'').slice(0,160)}` });
      } else {
        // decrease -> write-off document. Manager silently drops unknown line
        // field names, so a guessed line shape returns HTTP 201 but leaves an
        // empty line (blank Inventory Item, Qty 0). Empty documents also read
        // back with no lines property, so a created-then-readback template is
        // unreliable. The reliable schema source is a write-off created in
        // Manager's UI: copy its line structure verbatim, swap in the item +
        // qty, and create the new document with those exact field names.
        const template = await findWriteOffLineTemplate(ep, accessToken);
        if (!template) {
          results.push({ item: it.itemCode || key, ok: false, error: 'To enable automatic Manager adjustments, first create ONE inventory write-off manually in Manager (Inventory Write-offs → New Write-off, any item/qty). The extension copies its exact line format for all future automated ones.' });
          continue;
        }
        console.log(`   write-off learned template: linesProp="${template.linesProp}" item="${template.itemField}" qty="${template.qtyField}" from doc ${template.sourceKey}`);
        const line = Object.assign({}, template.line);
        line[template.itemField] = key;
        line[template.qtyField] = it.qty;
        // Clone the full template form so document-level settings (Allocation
        // account etc.) carry over, then override the parts that are ours.
        const payload = Object.assign({}, template.form || {}, { Date: date, Description: description });
        payload[template.linesProp] = [line];
        // Explicit allocation from the UI overrides whatever the template had.
        // The field's real name is only knowable from a form where it's set, so
        // prefer a matching key from the template; fall back to "Account" (and
        // the verify readback below will tell us if that guess was dropped).
        if (b.allocationAccount) {
          const allocField = Object.keys(template.form || {}).find(f => /alloc|account/i.test(f) && !/enabled/i.test(f) && !Array.isArray((template.form || {})[f])) || 'Account';
          payload[allocField] = b.allocationAccount;
          console.log(`   write-off allocation: ${allocField}=${b.allocationAccount}`);
        }
        const r = await managerCall(ep, accessToken, 'POST', '/inventory-write-off-form', payload);
        console.log(`   write-off create POST: HTTP ${r.status} body=${JSON.stringify(r.data || '').slice(0, 300)}`);
        // Verify the line actually took: read the new doc back and require a
        // non-empty lines array. A 201 response alone is not sufficient here.
        let verified = false;
        const newKey = r.data && (r.data.Key || r.data.key || r.data.id);
        if (r.status >= 200 && r.status < 400 && newKey) {
          try {
            const chk = await managerCall(ep, accessToken, 'GET', `/inventory-write-off-form/${newKey}`, null);
            const arr = chk.data && chk.data[template.linesProp];
            verified = Array.isArray(arr) && arr.length > 0;
            const allocInfo = b.allocationAccount
              ? ' alloc=' + (Object.entries(chk.data || {}).some(([f, v]) => v === b.allocationAccount) ? 'took' : 'DROPPED (field name guess was wrong - report the "template source doc" log line)')
              : '';
            console.log(`   write-off verify readback: lines=${Array.isArray(arr) ? arr.length : 'missing'} → ${verified ? 'OK' : 'STILL EMPTY'}${allocInfo}`);
          } catch (_) {}
        }
        if (verified) results.push({ item: it.itemCode || key, ok: true, path: 'write-off' });
        else results.push({ item: it.itemCode || key, ok: false, error: `Write-off document was created but its line did not take (HTTP ${r.status}). Check the server log's "learned template" line and report it.` });
      }
    } catch (e) { results.push({ item: it.itemCode || key, ok: false, error: e.message }); }
  }
  const okCount = results.filter(r => r.ok).length;
  res.json({ success: okCount > 0, mirrored: okCount, total: results.length, results });
});

// ── Readiness audit ─────────────────────────────────────────────
// Audit for "hidden step" failures: cases where Manager accepts an API call
// (HTTP 201) but the business outcome needs prior manual setup. Each check
// reports ok/warn/fail plus the fix, so the gap surfaces before a stock
// movement or submission hits it.
app.post('/api/manager/readiness-audit', async (req, res) => {
  const { managerEndpoint, accessToken } = req.body || {};
  if (!managerEndpoint || !accessToken) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  const ep = normEp(managerEndpoint);
  const tk = accessToken;
  const checks = [];
  const add = (id, title, status, detail, fix) => checks.push({ id, title, status, detail, fix: fix || '' });

  // 1. Manager connection + inventory items visible
  let invItems = [];
  try {
    const r = await managerCall(ep, tk, 'GET', '/inventory-items', null);
    if (r.status === 200 && r.data) {
      invItems = Object.values(r.data).find(v => Array.isArray(v)) || [];
      add('manager', 'Manager connection', 'ok', `Connected - ${invItems.length} inventory item(s) visible.`);
    } else if (r._cfChallenge) {
      add('manager', 'Manager connection', 'fail', 'Cloudflare showed its own browser-challenge page instead of forwarding to Manager - not a token problem.', 'In Cloudflare: Security → Bots (or WAF → Custom rules), add a rule skipping Bot Fight Mode / Super Bot Fight Mode for this Manager endpoint\'s path or this server\'s outbound IP.');
    } else add('manager', 'Manager connection', 'fail', `Inventory list returned HTTP ${r.status}.${r._htmlSnippet ? ' Response: ' + r._htmlSnippet : ''}`, r._html ? 'Manager returned a non-JSON (HTML/proxy) page rather than a Manager-level error - this usually means a reverse proxy or firewall (e.g. Cloudflare) in front of Manager is blocking the request, not that Manager itself rejected it. Check that service\'s security/WAF logs for a blocked request to this path.' : 'Check the Manager endpoint URL and access token in Settings → System.');
  } catch (e) { add('manager', 'Manager connection', 'fail', e.message, 'Check the Manager endpoint URL and access token in Settings → System.'); }

  // 2. Write-off template - only relevant once inventory items exist AND the
  // user adjusts stock quantities. A brand-new business has nothing to adjust,
  // so don't nag them to hand-create a write-off (mirrors the unit-cost check).
  try {
    if (!invItems.length) {
      add('writeoff', 'Stock adjustment format', 'ok', 'No inventory items yet - stock adjustments are set up automatically the first time you adjust stock.');
    } else {
      const tpl = await findWriteOffLineTemplate(ep, tk);
      if (tpl) add('writeoff', 'Stock adjustment format', 'ok', `Write-off line format learned (fields: ${tpl.itemField}/${tpl.qtyField}).`);
      else add('writeoff', 'Stock adjustment format', 'warn', 'No manually created inventory write-off found to learn Manager\'s line format from.', 'Only needed if you adjust stock quantities: create ONE write-off manually in Manager (Inventory Write-offs → New Write-off, any item/qty) so automated adjustments can copy its format.');
    }
  } catch (e) { add('writeoff', 'Stock adjustment format', 'warn', e.message, 'Only needed if you adjust stock quantities: enable the Inventory Write-offs tab in Manager (Customize), then create one write-off manually.'); }

  // 3. Inventory Unit Cost coverage (write-offs/COGS value at ZERO without one)
  try {
    const ucR = await managerCall(ep, tk, 'GET', '/inventory-unit-costs', null);
    const ucList = (ucR.status === 200 && ucR.data) ? (Object.values(ucR.data).find(v => Array.isArray(v)) || []) : [];
    const covered = new Set();
    for (const entry of ucList.slice(-25)) {
      const k = entry.key || entry.Key || entry.id; if (!k) continue;
      try {
        const f = await managerCall(ep, tk, 'GET', `/inventory-unit-cost-form/${k}`, null);
        if (f.status === 200 && f.data) { const itf = Object.keys(f.data).find(x => /inventoryitem/i.test(x)); if (itf && f.data[itf]) covered.add(f.data[itf]); }
      } catch (_) {}
    }
    const missing = invItems.filter(i => !covered.has(i.key || i.Key)).map(i => i.itemCode || i.ItemCode || i.itemName || i.ItemName || i.name || (i.key || i.Key));
    if (!invItems.length) add('unitcost', 'Inventory unit costs', 'ok', 'No inventory items yet - nothing to cover.');
    else if (!missing.length) add('unitcost', 'Inventory unit costs', 'ok', 'Every inventory item has a unit cost record.');
    else add('unitcost', 'Inventory unit costs', 'warn', `No unit cost record for: ${missing.join(', ')}. Write-offs/COGS for these value at ZERO.`, 'Do a Stock In with a Unit Cost (recorded automatically), or add records under Manager → Inventory Unit Costs.');
  } catch (e) { add('unitcost', 'Inventory unit costs', 'warn', e.message); }

  // 4. EFRIS custom fields on Manager documents. Match the SAME names the
  // app's own Check/Create uses (efrisFieldSpecs creates a field named plain
  // "FDN") - checking different names here produced a false "missing" warning.
  try {
    const cf = await mgrTextCustomFields(ep, tk);
    const haveLower = new Set(Object.keys(cf.byName).map(n => n.toLowerCase()));
    const hasFdn = ['fdn', 'fiscal document number', 'efris fdn'].some(n => haveLower.has(n));
    const hasCom = ['efris commodity code', 'commodity code', 'efris commodity', 'commodity'].some(n => haveLower.has(n));
    if (hasFdn && hasCom) add('customfields', 'EFRIS custom fields', 'ok', 'FDN and commodity-code fields exist.');
    else checks.push({ id: 'customfields', title: 'EFRIS custom fields', status: 'warn',
      detail: `Missing: ${[!hasFdn && 'FDN field', !hasCom && 'commodity-code field'].filter(Boolean).join(', ')}.`,
      fix: 'Use the button here, or run Check / Create EFRIS Custom Fields in Settings, Custom Fields.',
      action: 'create-custom-fields' });
  } catch (e) { add('customfields', 'EFRIS custom fields', 'warn', e.message, 'Run "Check / Create EFRIS Custom Fields" in Settings, Custom Fields.'); }

  // 5. Currencies - the base currency must be set before goods. If we can read a
  // base, report it; if not, flag it and let the user set it inline (the connect
  // screen renders a "Set base currency" button for the action below) so they do
  // not have to leave the flow. Same read the Settings, Currencies tab uses.
  try {
    const { base, foreign } = await readMgrCurrencies(ep, tk);
    const fc = foreign.map(c => c.code).filter(Boolean);
    if (base && base.code) {
      const src = base.source === 'efrisconnect' ? ' (set from EFRISConnect; Manager does not report it back through its API)' : '';
      add('currency', 'Currencies', 'ok', `Base currency ${base.code}${src}${fc.length ? '; foreign: ' + fc.join(', ') : ' - no foreign currencies added yet'}.`, fc.length ? '' : 'Add any foreign currency you price goods in under Settings, Currencies.');
    } else {
      checks.push({ id: 'currency', title: 'Currencies', status: 'warn',
        detail: 'Base currency not confirmed. Manager does not report it through its API, so EFRISConnect only knows it once it has been set from here.',
        fix: 'Click the button to set it to UGX (also fine if it is already set in Manager - this records it). Foreign currencies you price goods in go under Settings, Currencies.',
        action: 'set-base-currency' });
    }
  } catch (e) { add('currency', 'Currencies', 'warn', 'Could not read currencies now.', 'Set base and foreign currencies under Settings, Currencies before creating goods.'); }

  // 6. Chart of accounts reachable (needed by allocation picker + item sync)
  try {
    const r = await managerCall(ep, tk, 'GET', '/chart-of-accounts', null);
    const arr = (r.status === 200 && r.data) ? (Object.values(r.data).find(v => Array.isArray(v)) || []) : [];
    if (arr.length) add('accounts', 'Chart of accounts', 'ok', `${arr.length} accounts visible.`);
    else add('accounts', 'Chart of accounts', 'warn', `Chart of accounts returned HTTP ${r.status} / empty.`);
  } catch (e) { add('accounts', 'Chart of accounts', 'warn', e.message); }

  const worst = checks.some(c => c.status === 'fail') ? 'fail' : checks.some(c => c.status === 'warn') ? 'warn' : 'ok';
  res.json({ success: true, overall: worst, checks });
});

// Full details for a single Manager.io item (for import prefill)
app.get('/api/goods/manager-item-detail', async (req, res) => {
  const ep = normEp(req.headers['x-manager-endpoint'] || req.query.ep || '');
  const tk = req.headers['x-manager-token'] || '';
  const key = req.query.key || '';
  const type = req.query.type || 'Service';
  if (!ep || !tk || !key) return res.status(400).json({ success: false, error: 'ep, tk and key are required' });
  const itemPath = type === 'Goods' ? `/inventory-item-form/${key}` : `/non-inventory-item-form/${key}`;
  try {
    const r = await managerCall(ep, tk, 'GET', itemPath, null);
    if (r.status !== 200) return res.json({ success: false, error: `Manager returned HTTP ${r.status}` });
    const d = r.data || {};
    // Return the raw form for inspecting the exact account field names.
    if (req.query.raw) return res.json({ success: true, raw: d, keys: Object.keys(d) });
    // Manager returns camelCase on GET; normalize both cases
    const cf2 = d.customFields2 || d.CustomFields2 || {};
    const cfStrings = cf2.strings || cf2.Strings || {};
    console.log(`   Detail for ${key}:`, JSON.stringify(d).slice(0, 300));
    // Pull the stored EFRIS Commodity Code + Category Path (written at sync time)
    // so an already-configured item imports without re-picking the category.
    let comCode = '', catPath = '';
    try {
      const cf = await mgrTextCustomFields(ep, tk);
      const find = (...names) => { for (const n of names) { const k = cf.byName && cf.byName[n]; if (k) return k; } return null; };
      const comKey = find('EFRIS Commodity Code', 'Commodity Code', 'EFRIS Commodity', 'Commodity');
      const catKey = find('EFRIS Category Path', 'Category Path', 'Segment / Class Grouping', 'Class Grouping', 'EFRIS Segment / Class Grouping');
      if (comKey && cfStrings[comKey]) comCode = String(cfStrings[comKey]);
      if (catKey && cfStrings[catKey]) catPath = String(cfStrings[catKey]);
    } catch (_) {}
    // Field names differ between inventory items (ItemName, DefaultSalesUnitPrice,
    // HasDefaultSalesUnitPrice, no Code) and non-inventory items (Name, SalesUnitPrice,
    // HasSalesUnitPrice). Read every variant so both populate the form correctly.
    const pick = (...keys) => { for (const k of keys) { if (d[k] !== undefined && d[k] !== null && d[k] !== '') return d[k]; } return undefined; };
    res.json({ success: true, item: {
      key,
      code:                   pick('ItemCode','itemCode','Code','code') || '',
      name:                   pick('ItemName','itemName','Name','name') || '',
      unitName:               pick('UnitName','unitName') || '',
      salesUnitPrice:         pick('DefaultSalesUnitPrice','SalesUnitPrice','salesUnitPrice','DefaultSalesPrice') || 0,
      hasSalesUnitPrice:      !!(d.HasDefaultSalesUnitPrice || d.hasDefaultSalesUnitPrice || d.HasSalesUnitPrice || d.hasSalesUnitPrice),
      description:            pick('Description','description') || '',
      defaultLineDescription: pick('DefaultLineDescription','defaultLineDescription') || '',
      customFieldStrings:     cfStrings,
      division:               d.division || d.Division || '',
      salesDivision:          d.salesDivision || d.SalesDivision || '',
      costMethod:             d.costMethod != null ? d.costMethod : (d.CostMethod != null ? d.CostMethod : ''),
      whenSold:               d.SaleItemAccount || d.saleItemAccount || d.WhenSold || d.whenSold || '',
      whenPurchased:          d.PurchaseItemAccount || d.purchaseItemAccount || d.WhenPurchased || d.whenPurchased || '',
      comCode, catPath,
    }});
  } catch(e) {
    res.json({ success: false, error: e.message });
  }
});

// Live, valid EFRIS measure units for the taxpayer (from T115 dictionary).
// The frontend uses this to let the user pick a guaranteed-valid unit code.
app.post('/api/efris/measure-units', async (req, res) => {
  const { tin, deviceNo, efrisPassword, mode } = req.body || {};
  if (!tin || !deviceNo) return res.status(400).json({ success: false, error: 'tin and deviceNo are required' });
  const eu = uraUrl(mode);
  try {
    const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
    const units = await getEfrisMeasureUnits(tin, deviceNo, session, eu);
    res.json({ success: true, units });
  } catch(e) {
    logger.error('measure-units failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: e.message });
  }
});

app.post('/api/efris/register-goods', async (req, res) => {
  const { tin, deviceNo, efrisPassword, mode, item } = req.body || {};
  if (!tin || !deviceNo || !item) {
    return res.status(400).json({ success: false, error: 'tin, deviceNo and item are required' });
  }
  const eu = uraUrl(mode);
  try {
    let session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
    if (!session.aesKey) throw new Error('No AES key available - check private key path');

    // Resolve the EFRIS measure-unit CODE. The frontend may pass a pre-resolved
    // code (item.efrisUom) and/or a unit name (item.uom). We must only ever send
    // a code that actually exists in uom.json - otherwise EFRIS rejects it (e.g.
    // the literal word "PIECE" instead of the code "PCE").
    const units = getUnits();
    const byCode = new Map(units.map(u => [String(u.code).toUpperCase(), u.code]));
    const byName = new Map(units.map(u => [String(u.name || u.desc || '').toLowerCase(), u.code]));
    const rawEfrisUom = (item.efrisUom || '').trim().toUpperCase();
    const rawName = (item.uom || '').trim().toLowerCase();
    let uomCode = '';
    if (rawEfrisUom && byCode.has(rawEfrisUom)) {
      uomCode = byCode.get(rawEfrisUom);                         // valid code passed
    } else if (byName.has(rawName)) {
      uomCode = byName.get(rawName);                             // resolve "Piece" -> PCE
    } else if (rawEfrisUom && byName.has(rawEfrisUom.toLowerCase())) {
      uomCode = byName.get(rawEfrisUom.toLowerCase());           // efrisUom held a name
    }
    if (!uomCode) {
      // Unknown unit - report it as a unit problem rather than sending garbage.
      const sent = rawEfrisUom || (item.uom || '');
      console.log(`   ⚠ UOM "${sent}" is not a known EFRIS measure unit - asking user to pick.`);
      return res.json({ success: false, unitProblem: true, sentUnit: sent,
        validUnits: units.map(u => ({ code: u.code, name: u.name || u.desc || '' })),
        error: `"${sent}" is not a valid EFRIS measure unit.` });
    }
    console.log(`   UOM resolved: uom="${item.uom}" efrisUom="${item.efrisUom}" → code "${uomCode}"`);

    // VAT tax item - taxCategoryCode: '01'=standard(18%), '02'=zero-rated, '03'=exempt
    const vatCat = item.vat === 'Exempt' ? '03' : item.vat === 'Zero' ? '02' : '01';
    const taxRate = vatCat === '01' ? '0.18' : '0.00';

    // goodsTypeCode is ALWAYS '101' in T130 - EFRIS decides "Is it a Service?" from the
    // COMMODITY CATEGORY (e.g. 90121501 Tour arrangement → shown as a service), not from
    // this field. Every item that successfully persists (goods AND services, incl. the
    // Ngamba tour) is goodsTypeCode=101 with a real measure unit. Sending '102' returns a
    // hollow rc:00 that never persists (and a real unit under '102' gives rc:2981), so the
    // item.type (Goods/Service) is used ONLY for the Manager inventory/non-inventory split.
    const goodsTypeCode = '101';

    // T130 = Goods Registration (Add Product Code).
    // currency: EFRIS accepts ISO codes (USD, EUR, GBP…) for foreign-currency items.
    // UGX is the default base currency - omit the field entirely when pricing in UGX.
    // taxItems are for invoices (T109), not goods registration - exclude here.
    // currency is required by T130, but it wants the EFRIS dictionary code (not "UGX").
    // Resolve via the T115 data dictionary.
    const t130Currency = await resolveEfrisCurrency(item.cur || 'UGX', tin, deviceNo, session, eu);
    const measureUnit = uomCode;   // real EFRIS unit (PCE/PP/MTK…) for goods and services alike
    const t130Payload = {
      goodsCode:             item.code,
      goodsName:             item.name,
      goodsTypeCode,
      measureUnit,
      unitPrice:             String(parseFloat(item.price) || 0),
      currency:              t130Currency,
      commodityCategoryId:   item.comCode || '',
      commodityCategoryName: item.comName || '',
      haveExciseTax:         item.excise === 'Yes' ? '101' : '102',
      description:           item.remarks || '',
      stockPrewarning:       '0',
      pricingMode:           '1',
      havePieceUnit:         '102',
      pieceUnit:             '',
      packageScaledValue:    '',
      scaledValue:           '',
      discountTaxRate:       '',
    };

    console.log(`\n📦 Registering goods with EFRIS T130: ${item.code} - ${item.name}`);
    console.log(`   Payload: goodsCode=${t130Payload.goodsCode}, categoryId=${t130Payload.commodityCategoryId}, measureUnit=${measureUnit}, price=${t130Payload.unitPrice}, currency=${t130Currency}, vatCat=${vatCat}, type=${goodsTypeCode}`);

    // T130 is a BATCH interface - payload must be an array even for a single item
    let t130 = await efrisCall(eu, efrisEnvEnc('T130', [t130Payload], tin, deviceNo, session.aesKey, session.privatePem));
    let outerRc = t130.data && t130.data.returnStateInfo ? t130.data.returnStateInfo.returnCode : null;
    let outerRm = t130.data && t130.data.returnStateInfo ? t130.data.returnStateInfo.returnMessage : '';
    // rc:15 = "Data decryption error" - the cached AES key rotated on EFRIS's side.
    // Renew the session (fresh T104 key) and retry ONCE with the new key. The failed
    // request never reached processing, so there is no duplicate-registration risk.
    if (outerRc === '15') {
      console.log('   ⚠ T130 rc:15 (decryption) - renewing session and retrying once');
      invalidateSession(tin, deviceNo);
      session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
      t130 = await efrisCall(eu, efrisEnvEnc('T130', [t130Payload], tin, deviceNo, session.aesKey, session.privatePem));
      outerRc = t130.data && t130.data.returnStateInfo ? t130.data.returnStateInfo.returnCode : null;
      outerRm = t130.data && t130.data.returnStateInfo ? t130.data.returnStateInfo.returnMessage : '';
    }
    console.log(`   T130 outer rc: ${outerRc} (${outerRm})`);

    // Decrypt per-item results from response content
    let itemRc = outerRc, itemRm = outerRm;
    if (t130.data && t130.data.data && t130.data.data.content) {
      try {
        const raw = aesDecryptStr(t130.data.data.content, session.aesKey);
        const results = JSON.parse(raw);
        const r0 = Array.isArray(results) ? results[0] : results;
        if (r0) {
          itemRc = r0.returnCode || r0.returnStateInfo?.returnCode || outerRc;
          itemRm = r0.returnMessage || r0.returnStateInfo?.returnMessage || outerRm;
          console.log(`   T130 item rc: ${itemRc} - ${itemRm}`);
        }
      } catch(e) { console.log(`   (could not decrypt T130 item response: ${e.message})`); }
    }

    // rc:00 = success; rc:602 = already exists
    let ok = itemRc === '00' || itemRc === '602';
    let alreadyExists = itemRc === '602';
    let ghost = false;

    // VERIFY the item actually persisted - for BOTH rc:00 and rc:602. EFRIS can:
    //  • return a hollow rc:00 for an invalid field combo yet never write the record;
    //  • return rc:602 "already exists" for a goodsCode that an earlier failed/partial
    //    attempt RESERVED but which isn't a usable record (not in T127, not on portal) -
    //    a "ghost" code. Read it back with T127 by goodsCode and require a real match.
    let persisted = null;
    if (ok) {
      try {
        const vp = { goodsCode: item.code, goodsName: '', commodityCategoryCode: '', pageNo: '1', pageSize: '20' };
        const vr = await efrisSecure(eu, 'T127', vp, tin, deviceNo, session);
        if (vr.data?.data?.content) {
          const raw = aesDecryptStr(vr.data.data.content, session.aesKey);
          const parsed = JSON.parse(raw);
          const recs = parsed.records || parsed.goodsList || parsed.list || [];
          persisted = recs.some(r => String(r.goodsCode || '').toUpperCase() === String(item.code).toUpperCase());
        } else { persisted = false; }
        console.log(`   Verify T127 (${item.code}): ${persisted ? 'FOUND - usable record ✅' : 'NOT FOUND in registry ⚠'}`);
      } catch (e) { persisted = null; console.log(`   Verify T127 error (trusting rc): ${e.message}`); }
    }
    // A confirmed non-persist turns "success" into a clear, actionable failure.
    if (persisted === false) {
      ok = false;
      if (alreadyExists) {
        ghost = true; alreadyExists = false;
        itemRc = 'GHOST';
        itemRm = `EFRIS says goodsCode "${item.code}" already exists (rc:602) but it is NOT in the registry or on the portal - an earlier failed attempt reserved the code in a broken state. This code is unusable. Register this product under a NEW unique code (e.g. "${item.code}-1"), or ask URA to clear the code.`;
      } else {
        itemRc = 'NOPERSIST';
        itemRm = 'EFRIS accepted the request (rc:00) but the item did not appear in the registry afterwards - usually an invalid measure unit or commodity category. Check the unit/category and try again.';
      }
    }

    if (ok) {
      console.log(alreadyExists ? `   ✓ Item already registered in EFRIS (verified)` : `   ✅ Registered successfully (verified)`);
    } else {
      console.log(`   ${ghost ? '👻 Ghost code' : '❌ T130 failed'}: ${itemRc} - ${itemRm}`);
    }
    // For an invalid measure unit, attach a few valid options to guide the user.
    let unitProblem = false, validUnits = [];
    if (!ok && (itemRc === '2235' || itemRc === '2234' || itemRc === 'NOPERSIST' || /measure ?unit/i.test(itemRm || ''))) {
      unitProblem = true;
      // Offer the goods measure-unit list from uom.json (what EFRIS validates
      // T130 against) - NOT the live T115 packaging-unit section.
      try { validUnits = getUnits().map(u => ({ code: u.code, name: u.name || u.desc || '' })); } catch(_) {}
    }
    // rc:681 - the item is flagged excisable but this TIN has no Local Excise Duty
    // registration in EFRIS, so EFRIS forbids haveExciseTax='101'. This is a URA
    // registration fact, not a fixable payload error. Give a clear, actionable
    // message and flag it so the frontend can offer "register without excise".
    let exciseProblem = false;
    if (!ok && (itemRc === '681' || /excise/i.test(itemRm || ''))) {
      exciseProblem = true;
      itemRm = `This item is marked as excisable, but TIN ${tin} is not registered for Local Excise Duty in EFRIS, so URA will not accept it as an excise good. Either add Excise Duty to your URA registration, or turn off the excise flag on this item and register it as a normal VAT good.`;
    }
    res.json({ success: ok, returnCode: itemRc, returnMessage: itemRm, alreadyExists,
      ghost, suggestedCode: ghost ? item.code + '-1' : undefined,
      unitProblem, sentUnit: uomCode, validUnits, exciseProblem,
      error: ok ? undefined : (ghost || exciseProblem ? itemRm : `EFRIS T130: ${itemRc} - ${itemRm}`) });
  } catch(e) {
    console.log(`   ❌ register-goods error: ${e.message}`);
    logger.error('register-goods failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  EFRIS API ROUTES
// ══════════════════════════════════════════════════════════════

app.post('/api/efris/test-connection', async (req, res) => {
  const b = req.body || {};
  const url = uraUrl(b.mode);
  try {
    invalidateSession(b.tin || '', b.deviceNo || '');
    await getSession(b.tin, b.deviceNo, b.password, url, keyOverrideFrom(b));
    res.json({ success: true, message: 'Connected to URA EFRIS ' + (b.mode === 'production' ? 'Production' : 'Sandbox') });
  } catch(e) {
    logger.error('test-connection failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: e.message });
  }
});

// Resolve the EFRIS endpoints to try, in order, for a submission.
//   config.enablerUrl  - local URA Offline Mode Enabler base URL (getInformation)
//   config.enablerMode - 'off' | 'fallback' (URA first, Enabler on failure) | 'always'
// The Enabler speaks the same EFRIS protocol (same AES/RSA envelope), so our
// existing efrisCall/efrisEnvEnc work unchanged - only the base URL differs.
// The URA Offline Enabler runs on this machine or the office LAN. Only such
// addresses are accepted, so the relay cannot be pointed at internet hosts
// (it would post signed invoices there). Extra LAN names: ALLOWED_ENABLER_HOSTS.
const ENABLER_EXTRA_HOSTS = String(process.env.ALLOWED_ENABLER_HOSTS || '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
function enablerUrlOk(u) {
  let p; try { p = new URL(String(u || '').trim()); } catch (_) { return false; }
  if (p.protocol !== 'http:' && p.protocol !== 'https:') return false;
  const h = p.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (ENABLER_EXTRA_HOSTS.includes(h)) return true;
  if (h === 'localhost' || h === '::1' || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^169\.254\./.test(h) || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe80:/.test(h)) return true;
  // Single-label or .local/.lan/.home names resolve on the LAN, not the internet.
  return !h.includes('.') || /\.(local|lan|home|internal)$/.test(h);
}

function efrisEndpoints(config) {
  const ura = uraUrl(config.mode);
  let enabler = (config.enablerUrl || '').trim();
  if (enabler && !enablerUrlOk(enabler)) { console.log('   Enabler URL ignored (not a local/LAN address): ' + enabler); enabler = ''; }
  const mode = enabler ? (config.enablerMode || 'fallback') : 'off';
  if (mode === 'always') return [{ url: enabler, kind: 'enabler' }];
  if (mode === 'fallback') return [{ url: ura, kind: 'ura' }, { url: enabler, kind: 'enabler' }];
  return [{ url: ura, kind: 'ura' }];
}

// The Offline Mode Enabler is its OWN registered device (its own device number)
// sharing the taxpayer's private key. When routing to it, identify as the Enabler's
// device number (config.enablerDeviceNo) so its T104/T109 succeed; for URA keep the
// extension's own device number.
function cfgForTarget(config, target) {
  if (target && target.kind === 'enabler' && config.enablerDeviceNo) {
    return { ...config, deviceNo: config.enablerDeviceNo };
  }
  return config;
}

// Is this error a connectivity/network failure (→ queue offline) rather than a
// URA business rejection (which comes back as a resolved rc, not a throw)?
function isNetworkError(e) {
  const m = String((e && e.message) || e || '').toLowerCase();
  return /econnrefused|enotfound|etimedout|eai_again|ehostunreach|enetunreach|econnreset|socket hang up|timed out|network|getaddrinfo|request to .* failed/.test(m);
}

// Core invoice/receipt submission (T109). Returns a result object; THROWS on a
// network failure so callers can decide to queue offline. Does not touch res.
let _inflight = 0;
async function performInvoiceSubmission(invoice, config, eu) {
  _inflight++;
  try { return await performInvoiceSubmissionInner(invoice, config, eu); } finally { _inflight--; }
}
async function performInvoiceSubmissionInner(invoice, config, eu) {
  let session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
  if (!session.aesKey) throw new Error('No AES key available to encrypt T109');
  try {
    const goodsMap = await getRegisteredGoodsMap(config.tin, config.deviceNo, session, eu);
    annotateLinesWithRegisteredGoods(invoice, goodsMap);
  } catch (e) { console.log(`   goods-map annotate skipped: ${e.message}`); }
  // Seller details missing from this business's settings (URA rejects an empty email,
  // rc 1115): fill them from the taxpayer record URA returned at login.
  const tpRec = (session.login && (session.login.taxpayer || session.login)) || {};
  config = { ...config,
    email: config.email || tpRec.contactEmail || tpRec.email || '',
    phone: config.phone || tpRec.contactMobile || tpRec.contactNumber || '',
    businessAddress: config.businessAddress || tpRec.address || '',
    businessName: config.businessName || tpRec.legalName || '',
    tradeName: config.tradeName || tpRec.businessName || '',
  };
  const t109data = buildT109(invoice, config);
  t109data.goodsDetails.forEach(g => console.log(`   T109 line: item="${g.item}" itemCode="${g.itemCode}" uom="${g.unitOfMeasure}" taxRule="${g.taxRule}"`));
  let t109, rc, rm;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try { t109 = await efrisCall(eu, efrisEnvEnc('T109', t109data, config.tin, config.deviceNo, session.aesKey, session.privatePem)); }
    catch (e) {
      // Sent, then no answer: EFRIS may have fiscalised it. Flag it so callers do
      // not resend it blindly (a second FDN for one sale).
      if (e.afterSend) e.uncertain = true;
      throw e;
    }
    rc = t109.data && t109.data.returnStateInfo ? t109.data.returnStateInfo.returnCode : null;
    rm = t109.data && t109.data.returnStateInfo ? t109.data.returnStateInfo.returnMessage : '';
    if (rc !== '15') break;
    // rc:15 means the cached AES key rotated on EFRIS's side - renew it before the
    // next attempt (retrying with the same stale key can never succeed).
    console.log(`   T109 rc 15 (stale session key) - renewing session, retry ${attempt}/3`);
    invalidateSession(config.tin, config.deviceNo);
    session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
  }
  let contentStr = null;
  if (t109.data && t109.data.data && t109.data.data.content) {
    try { contentStr = aesDecryptStr(t109.data.data.content, session.aesKey); }
    catch(e) { try { contentStr = Buffer.from(t109.data.data.content, 'base64').toString('utf8'); } catch(_) {} }
  }
  let fdn = null, qrCode = null, antifakeCode = null, invoiceId = '', validationUrl = null;
  try {
    if (contentStr) {
      const d = JSON.parse(contentStr);
      const bi = d.basicInformation || {};
      fdn = d.fdn || d.fiscalDocumentNumber || bi.invoiceNo || bi.fdn;
      antifakeCode = d.antiFakeCode || d.antifakeCode || bi.antifakeCode || bi.antiFakeCode;
      invoiceId = bi.invoiceId || bi.invoiceID || d.invoiceId || '';
      const efrisPortal = config.mode === 'production'
        ? 'https://efris.ura.go.ug/site_mobile/#/invoiceValidation'
        : 'https://efristest.ura.go.ug/site_new/#/invoiceValidation';
      validationUrl = (fdn && antifakeCode)
        ? `${efrisPortal}?invoiceNo=${encodeURIComponent(fdn)}&antiFakeCode=${encodeURIComponent(antifakeCode)}` : null;
      qrCode = d.qrCode || d.qrCodeBase64 || bi.qrCode || validationUrl || antifakeCode;
      console.log(`   T109 result - FDN: ${fdn}, antifakeCode: ${antifakeCode}`);
    }
  } catch(e) { console.log(`   T109 content parse error: ${e.message}`); }
  const ok = rc === '00' || !!fdn;
  const issuedDate = new Date().toISOString();
  if (ok) {
    try {
      appendSubmissionLog({
        id: crypto.randomUUID(), submittedAt: issuedDate, fdn, antifakeCode, validationUrl, tenantId: config._tenantId || undefined,
        userId: config._userId || undefined, userName: config._userName || undefined,
        ...(invoice._debitOf ? { kind: 'debit-note', docType: 'Debit note', originalFdn: invoice._debitOf.oriInvoiceNo || '' } : {}),
        deviceNo: config.deviceNo, invoiceId, reference: invoice.Reference || invoice.reference || '',
        returnCode: rc, status: 'success', tin: config.tin,
        customerName: t109data.buyerDetails ? (t109data.buyerDetails.buyerLegalName || t109data.buyerDetails.buyerTin || '') : '',
        totalAmount: t109data.summary ? parseFloat(t109data.summary.grossAmount) || 0 : 0,
        currency: t109data.basicInformation ? t109data.basicInformation.currency || 'UGX' : 'UGX',
        invoiceKind: t109data.basicInformation ? t109data.basicInformation.invoiceKind || '' : '',
        mode: config.mode || 'sandbox',
        // Kept so a later credit note can be prefilled (lines) and keep the buyer.
        buyerTin: t109data.buyerDetails ? t109data.buyerDetails.buyerTin || '' : '',
        buyerType: t109data.buyerDetails ? t109data.buyerDetails.buyerType || '' : '',
        lines: (t109data.goodsDetails || []).filter(g => String(g.discountFlag) !== '0').map(g => ({
          name: g.item || '', code: g.itemCode || '', qty: parseFloat(g.qty) || 0, unitPrice: parseFloat(g.unitPrice) || 0, orderNumber: parseInt(g.orderNumber, 10) })),
      });
    } catch(le) { console.log('Submission log write error:', le.message); }
  }
  return { ok, fdn, qrCode, antifakeCode, validationUrl, deviceNo: config.deviceNo, issuedDate, invoiceId, returnCode: rc, returnMessage: rm };
}

app.post('/api/efris/submit-invoice', rateLimit(30), async (req, res) => {
  const { invoice, config, documentKey, managerEndpoint } = req.body || {};
  if (!invoice || !config || !config.tin) {
    return res.status(400).json({ success: false, error: 'Missing invoice or config.tin' });
  }
  // Business that is submitting: carried on the config so the submission log
  // entry is tagged even when it is written later from the offline queue.
  config._tenantId = reqTenant(req);
  { const a = actor(req); config._userId = a.userId || ''; config._userName = a.userName || ''; }
  delete invoice._debitOf;   // debit notes go through /api/efris/debit-note only
  const saleAt = new Date().toISOString();   // when the sale was made (an offline sale is dated by this)
  try {
    // Guard: a receipt that clears an invoice has no goods lines - EFRIS can't
    // process it. The original invoice should be submitted instead.
    const lines = invoice.Lines || [];
    if (lines.length === 0) {
      return res.json({ success: false, error: 'This document has no line items. If this is a payment receipt that clears an invoice, submit the original sales invoice to EFRIS instead.' });
    }
    // URS §9.18: receipt/invoice reference must be UNIQUE per transaction for
    // system-to-system users. Block a re-used reference that already fiscalised
    // successfully (unless the caller explicitly allows a resubmit).
    const ref = String(invoice.Reference || '').trim();
    if (ref && !req.body.allowDuplicateRef) {
      try {
        let log = []; try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(_) {}
        const dup = log.find(e => e.status === 'success' && e.kind !== 'credit-note' && String(e.reference || '').trim().toLowerCase() === ref.toLowerCase() && String(e.tin || config.tin) === String(config.tin));
        if (dup) return res.json({ success: false, duplicateRef: true, existingFdn: dup.fdn || '',
          error: `Reference "${ref}" was already fiscalised (FDN ${dup.fdn || '?'}). URA requires a unique reference per transaction. Use a new receipt number, or resubmit only if you are correcting a failed attempt.` });
        // Same reference already waiting in the offline queue: it will be sent from there.
        const q = loadQueue().find(e => e.status === 'pending' && String(e.reference || '').trim().toLowerCase() === ref.toLowerCase() && String((e.cfgPublic || {}).tin || '') === String(config.tin));
        if (q) return res.json({ success: false, duplicateRef: true, queued: true, offlineId: q.id,
          error: `Reference "${ref}" is already saved offline and will be submitted automatically when EFRIS is reachable. Use a new receipt number for a different sale.` });
      } catch(_) {}
    }
    // Try each endpoint (URA, then the local Offline Mode Enabler if configured).
    // A network failure moves to the next target; a URA business rejection is a
    // real result and stops here. If every target is unreachable → queue offline.
    const targets = efrisEndpoints(config);
    let result = null, lastNetErr = null, lastEndpointErr = null, uncertain = null;
    for (const t of targets) {
      try {
        result = await performInvoiceSubmission(invoice, cfgForTarget(config, t), t.url);
        if (t.kind === 'enabler' && result) result.viaEnabler = true;
        lastNetErr = null; lastEndpointErr = null;
        break;
      } catch (subErr) {
        // Sent but timed out: outcome unknown. Never fail over to the next target
        // (that could fiscalise the sale twice); queue it to be checked first.
        if (subErr.uncertain) { lastNetErr = subErr; uncertain = t.kind; console.log(`   ${t.kind} did not answer after the sale was sent: ${subErr.message}`); break; }
        if (isNetworkError(subErr)) { lastNetErr = subErr; console.log(`   ${t.kind} unreachable: ${subErr.message}`); continue; }
        // Reachable but wrong (HTTP 404 / HTML page): don't queue - it's a config
        // problem. Try the next target (e.g. fall through to URA), else surface it.
        if (subErr.endpointFailure) { lastEndpointErr = subErr; console.log(`   ${t.kind} endpoint error: ${subErr.message}`); continue; }
        throw subErr;
      }
    }
    // Every target was reachable-but-misconfigured (no transient network error):
    // return the actionable message rather than a raw 500 or a misleading queue.
    if (!result && lastEndpointErr && !lastNetErr) {
      return res.json({ success: false, endpointError: true, error: lastEndpointErr.message });
    }
    if (!result && lastNetErr) {
      const offlineId = offlineEnqueue({ kind: 'invoice', invoice, cfgPublic: publicCfg(config), tenantId: config._tenantId || '', managerEndpoint: managerEndpoint || '', documentKey: documentKey || '', reference: invoice.Reference || '', saleAt,
        ...(uncertain ? { uncertain: true, uncertainVia: uncertain } : {}) });
      if (uncertain) {
        console.log(`   ⚠ EFRIS did not answer in time - outcome unknown, queued to check by reference (${offlineId})`);
        return res.json({ success: true, queued: true, offline: true, uncertain: true, offlineId, reference: invoice.Reference || '',
          message: 'EFRIS did not answer in time, so it may already have this sale. It is saved and will be checked with EFRIS (by reference) before it is sent again.' });
      }
      console.log(`   ⚠ EFRIS unreachable (URA${config.enablerUrl ? ' + Enabler' : ''}) - queued offline (${offlineId})`);
      return res.json({ success: true, queued: true, offline: true, offlineId, reference: invoice.Reference || '',
        message: 'Saved offline - EFRIS is unreachable. It will be submitted automatically when the connection returns.' });
    }
    return res.json(result.ok
      ? { success: true, fdn: result.fdn, qrCode: result.qrCode, antifakeCode: result.antifakeCode, validationUrl: result.validationUrl, deviceNo: result.deviceNo, issuedDate: result.issuedDate, invoiceId: result.invoiceId, viaEnabler: !!result.viaEnabler, returnCode: result.returnCode, returnMessage: result.returnMessage }
      : { success: false, error: 'URA ' + result.returnCode + ': ' + result.returnMessage, returnCode: result.returnCode });
  } catch(e) {
    logger.error('submit-invoice failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});


// Test whether the Offline Enabler is installed and answering at the given URL, so
// the operator doesn't set "Always" mode against an Enabler that isn't running.
app.post('/api/efris/test-enabler', async (req, res) => {
  const url = String((req.body || {}).enablerUrl || '').trim();
  if (!url) return res.status(400).json({ ok: false, error: 'Enabler URL required' });
  try { new URL(url); } catch(_) { return res.json({ ok: false, error: 'That is not a valid URL.' }); }
  if (!enablerUrlOk(url)) return res.json({ ok: false, error: 'The Offline Enabler must be on this computer or your local network (e.g. http://localhost:9880/...). Internet addresses are not allowed.' });
  try {
    // A reachable Enabler answers a posted EFRIS envelope with HTTP 200 (even a
    // business-level error rc means it's up and processing).
    const r = await efrisCall(url, efrisEnv('T101', '', '', ''));
    if (r.status === 200) return res.json({ ok: true, detail: 'HTTP 200' });
    const body = (typeof r.data === 'string' ? r.data : JSON.stringify(r.data) || '');
    const isHtml = /^\s*<(?:!doctype|html)/i.test(body) || /HTTP Status \d+/.test(body);
    return res.json({ ok: false,
      error: 'Enabler returned HTTP ' + r.status + (isHtml ? ' (a web-server page, not an EFRIS response)' : ''),
      hint: 'Check the URL ends in /efristcs/ws/tcsapp/getInformation and the Enabler (Tomcat) is running.' });
  } catch (e) {
    const m = String((e && e.message) || '').toLowerCase();
    const down = /econnrefused|enotfound|etimedout|timed out|ehostunreach|enetunreach|network|getaddrinfo/.test(m);
    return res.json({ ok: false,
      error: down ? 'Enabler not reachable at ' + url : e.message,
      hint: down ? 'Is the Offline Enabler installed and running on this machine/LAN? Start its Tomcat service, then test again. Until it responds here, do NOT set "When to use the Enabler" to "Always" - submissions would fail.' : '' });
  }
});

app.post('/api/efris/verify-tin', async (req, res) => {
  const { buyerTin, config } = req.body || {};
  if (!buyerTin || !config || !config.tin) return res.status(400).json({ success: false, error: 'buyerTin and config required' });
  const eu = uraUrl(config.mode);
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    // T119: taxpayer query - look up a TIN to verify it exists and get details
    const t119 = await efrisSecure(eu, 'T119', { tin: buyerTin, ninBrn: '', queryType: '1' }, config.tin, config.deviceNo, session);
    const rc = t119.data && t119.data.returnStateInfo ? t119.data.returnStateInfo.returnCode : null;
    const rm = t119.data && t119.data.returnStateInfo ? t119.data.returnStateInfo.returnMessage : '';
    let info = null;
    if (t119.data && t119.data.data && t119.data.data.content) {
      try {
        const s = aesDecryptStr(t119.data.data.content, session.aesKey);
        info = JSON.parse(s);
        console.log('[T119 taxpayer fields]', JSON.stringify(info));
      } catch(e) {}
    }
    const ok = rc === '00';
    // Extract taxpayer name from whichever field EFRIS returns (varies by API version)
    let taxpayerName = '';
    if (info) {
      const tp = info.taxpayer || info;
      taxpayerName = tp.taxpayerName || tp.taxpayerLegalName || tp.legalName
        || tp.entityName || tp.taxPayerName || tp.businessName || tp.name || '';
    }
    res.json(ok
      ? { success: true, tin: buyerTin, taxpayer: info, taxpayerName, returnCode: rc }
      : { success: false, error: 'URA ' + rc + ': ' + rm, returnCode: rc });
  } catch(e) {
    logger.error('verify-tin failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// Detect VAT registration from a T119 taxpayer record without hardcoding a
// single field name (URA records vary). Returns { status, detail } where status
// is true (registered), false (not), or null (could not determine).
function detectVatRegistration(tp, info) {
  const truthy = (v) => {
    if (v === null || v === undefined) return false;
    const s = String(v).trim().toLowerCase();
    return !(s === '' || s === '0' || s === 'false' || s === 'no' || s === 'n' || s === 'null' || s === 'none');
  };
  const scan = (obj) => {
    if (!obj || typeof obj !== 'object') return null;
    // 1. A field that means VAT registration - its own value decides yes/no.
    //    (Other VAT flags, e.g. isAllowOutOfScopeVAT, describe different rules.)
    for (const k of Object.keys(obj)) {
      if (/^(is)?vat(reg(istered|istration)?|flag|status|payer)?$/i.test(k) && (typeof obj[k] !== 'object' || obj[k] === null)) {
        const v = obj[k];
        return { status: truthy(v), detail: k + '=' + (v === '' || v === null ? '(empty)' : String(v)) };
      }
    }
    // 2. A registered-tax-type field that lists VAT (name or code 01).
    for (const k of Object.keys(obj)) {
      if (/tax.?type|registeredtax|taxregist/i.test(k)) {
        const s = JSON.stringify(obj[k] || '').toLowerCase();
        if (/vat|value.?added/.test(s) || /"0?1"/.test(s)) return { status: true, detail: k + ' lists VAT' };
      }
    }
    return null;
  };
  return scan(tp) || scan(info) || { status: null, detail: '' };
}

// ── My details (T119 with own TIN) ────────────────────────────
app.post('/api/efris/my-details', async (req, res) => {
  const { config } = req.body || {};
  if (!config || !config.tin) return res.status(400).json({ success: false, error: 'config.tin required' });
  const eu = uraUrl(config.mode);
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    if (!session.aesKey) throw new Error('No AES key');
    const t119 = await efrisSecure(eu, 'T119', { tin: config.tin, ninBrn: '', queryType: '1' }, config.tin, config.deviceNo, session);
    const rc = t119.data && t119.data.returnStateInfo ? t119.data.returnStateInfo.returnCode : null;
    const rm = t119.data && t119.data.returnStateInfo ? t119.data.returnStateInfo.returnMessage : '';
    let info = null;
    if (t119.data && t119.data.data && t119.data.data.content) {
      try { const s = aesDecryptStr(t119.data.data.content, session.aesKey); info = JSON.parse(s); } catch(e) {}
    }
    if (rc !== '00') return res.json({ success: false, error: 'URA ' + rc + ': ' + rm });
    const tp = (info && (info.taxpayer || info)) || {};
    // URA sends "NIN/BRN" in one field ("/8002001593213" when there is no NIN): keep the BRN.
    const nb = String((tp.ninBrn && !/non/i.test(tp.ninBrn)) ? tp.ninBrn : (tp.brn || '')).split('/').map(x => x.trim()).filter(Boolean);
    const brn = nb.length ? nb[nb.length - 1] : '';
    const addr = String(tp.address || tp.placeOfBusiness || '').replace(/\s{2,}/g, ' ').trim();
    // VAT registration readout. The exact field URA returns is not fixed across
    // taxpayer records, so detect generically: any key mentioning VAT decides
    // yes/no by its value; otherwise a registered-tax-type list mentioning VAT.
    // VAT registration comes from the registered tax types in the T103 login reply
    // (T119 has no VAT field on current EFRIS). Only without that list fall back
    // to scanning the T119 / login fields.
    let vat = { status: null, detail: '' };
    const tt = session.login && (session.login.taxType || (session.login.taxpayer && session.login.taxpayer.taxType));
    if (Array.isArray(tt) && tt.length) {
      const names = tt.map(t => String((t && (t.taxTypeName || t.name)) || '')).filter(Boolean);
      const hasVat = names.some(n => /value.?added|\bvat\b/i.test(n));
      vat = { status: hasVat, detail: 'T103 tax types: ' + names.join(', ') };
    } else {
      vat = detectVatRegistration(tp, info);
      if (vat.status === null && session.login) {
        const lv = detectVatRegistration(session.login.taxpayer || {}, session.login);
        if (lv.status !== null) vat = { status: lv.status, detail: 'T103 ' + lv.detail };
      }
    }
    try { console.log('[T119 taxpayer fields] ' + Object.keys(tp).join(', ') + (vat.detail ? ' | vat: ' + vat.detail : ' | vat: not found')); } catch(_) {}
    // Diagnostics so the VAT field can be pinned without reading server logs:
    // the list of keys URA returned, plus any tax/VAT/registration-related pairs.
    const taxpayerFields = Object.keys(tp);
    const taxInfo = {};
    for (const k of taxpayerFields) { if (/vat|tax|regist/i.test(k) && (typeof tp[k] !== 'object' || tp[k] === null)) taxInfo[k] = tp[k]; }
    res.json({ success: true, legalName: tp.taxpayerLegalName || tp.legalName || tp.taxpayerName || '', businessName: tp.taxpayerName || tp.businessName || tp.legalName || '', address: addr, email: tp.contactEmail || '', phone: tp.contactMobile || tp.contactNumber || '', brn, tin: config.tin, vatRegistered: vat.status, vatDetail: vat.detail, taxpayerFields, taxInfo });
  } catch(e) {
    logger.error('my-details failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Sandbox test: make URA issue a new session key behind the relay's back ──
// A fresh T104 for the same device makes URA replace the key the relay has cached,
// so the next write (T109/T130/T131) gets rc:15 and must renew its session and
// retry. Sandbox only, and the cache is deliberately left untouched.
app.post('/api/efris/test/rotate-key', rateLimit(6), async (req, res) => {
  const { config } = req.body || {};
  if (!config || !config.tin || !config.deviceNo) return res.status(400).json({ success: false, error: 'config with tin and deviceNo required' });
  if (config.mode !== 'sandbox') return res.status(403).json({ success: false, error: 'Only available in sandbox mode.' });
  const eu = uraUrl('sandbox');
  try {
    const t101 = await efrisCall(eu, efrisEnv('T101', '', config.tin, config.deviceNo));
    const t104 = await efrisCall(eu, efrisEnv('T104', '', config.tin, config.deviceNo));
    const rc = t104.data && t104.data.returnStateInfo ? t104.data.returnStateInfo.returnCode : null;
    console.log('   TEST: URA issued a new session key for device ' + config.deviceNo + ' (T104 rc=' + rc + '); the relay still holds the old one');
    res.json({ success: t101.status === 200 && t104.status === 200, rc });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ── Credit Note (T108) ────────────────────────────────────────
app.post('/api/efris/credit-note', rateLimit(30), async (req, res) => {
  const { originalFDN, originalInvoiceId, reasonCode, reason, remarks, referenceNo, items, invoice, config } = req.body || {};
  if (!originalFDN || !config || !config.tin) return res.status(400).json({ success: false, error: 'originalFDN and config required' });
  if (!originalInvoiceId) return res.status(400).json({ success: false, error: 'Credit note requires the original invoice ID (oriInvoiceId). Enter the original FDN in the "Fiscal Document Number" custom field on the original invoice before raising a credit note.' });
  const _cnTarget = efrisEndpoints(config)[0];   // Enabler when in 'always' mode, else URA
  const eu = _cnTarget.url;
  const cnCfg = cfgForTarget(config, _cnTarget); // Enabler device number if routing there
  try {
    const session = await getSession(cnCfg.tin, cnCfg.deviceNo, cnCfg.efrisPassword, eu, keyOverrideFrom(cnCfg));
    if (!session.aesKey) throw new Error('No AES key for T108');
    // Prefer a full invoice object (carries item names, tax, buyer details). Fall back
    // to the legacy `items` array, reconstructing a minimal invoice from it.
    const cnInvoice = invoice && invoice.Lines
      ? { ...invoice }
      : {
          Currency: (config && config.currency) || 'UGX',
          Reference: referenceNo || '',
          CustomerType: (req.body && req.body.customerType) || 'b2c',
          Lines: (items || []).map((item) => ({
            ItemName: item.itemName || item.name || '',
            ItemCode: String(item.itemCode || ''),
            Qty: parseFloat(item.quantity || 1) || 1,
            UnitPrice: parseFloat(item.unitPrice || 0) || 0,
          })),
        };
    // Echo the registered unit of measure onto each line so EFRIS doesn't reject the
    // credit note with "unit of measure does not match goods maintenance".
    try {
      const goodsMap = await getRegisteredGoodsMap(cnCfg.tin, cnCfg.deviceNo, session, eu);
      annotateLinesWithRegisteredGoods(cnInvoice, goodsMap);
    } catch (e) { console.log(`   CN goods-map annotate skipped: ${e.message}`); }
    const t108data = buildT108(cnInvoice, cnCfg, {
      oriInvoiceId: originalInvoiceId,
      oriInvoiceNo: originalFDN,
      reasonCode: reasonCode || '102',
      reason: reason || '',
      remarks: remarks || '',
      sellersReferenceNo: referenceNo || cnInvoice.Reference || ('CN-' + Date.now()),
    });
    // URA matches each credit-note line to the ORIGINAL invoice line with the same
    // orderNumber (1427 "item must be the same as the original invoice" otherwise),
    // so keep the original line positions when only some lines are credited.
    if (Array.isArray(items) && items.length === t108data.goodsDetails.length && items.every(it => Number.isInteger(+it.orderNumber) && +it.orderNumber >= 0)) {
      t108data.goodsDetails.forEach((g, j) => { g.orderNumber = String(+items[j].orderNumber); });
    }
    t108data.goodsDetails.forEach(g => console.log(`   CN line: #${g.orderNumber} item="${g.item}" itemCode="${g.itemCode}" uom="${g.unitOfMeasure}" qty=${g.qty} total=${g.total}`));
    // Per Interface Design v24.0.1, the Credit-Note Application interface is T110
    // (T108 is a query). Our payload is already a T110 application (reasonCode,
    // applicationTime, invoiceApplyCategoryCode). Send T110; if this EFRIS build
    // doesn't recognise it (older sandbox), fall back to T108 which worked before.
    const cnSubmit = async (code) => {
      const r = await efrisSecure(eu, code, t108data, cnCfg.tin, cnCfg.deviceNo, session);
      const c = r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnCode : null;
      const m = r.data && r.data.returnStateInfo ? r.data.returnStateInfo.returnMessage : '';
      return { r, c, m };
    };
    let iface = 'T110';
    let { r: t108, c: rc, m: rm } = await cnSubmit('T110');
    // "interface not found / illegal" style failures → retry as T108.
    if (rc !== '00' && /interface|not\s*exist|not\s*found|illegal|no such|不存在/i.test(rm || '')) {
      console.log(`   T110 rejected (${rc} ${rm}) - falling back to T108`);
      const fb = await cnSubmit('T108'); t108 = fb.r; rc = fb.c; rm = fb.m; iface = 'T108';
    }
    console.log(`   Credit note submitted via ${iface}: rc=${rc} ${rm}`);
    let fdn = null, cnRef = null, antifakeCode = null, invoiceId = '', validationUrl = null;
    if (t108.data && t108.data.data && t108.data.data.content) {
      try {
        const s = aesDecryptStr(t108.data.data.content, session.aesKey);
        const d = JSON.parse(s);
        const bi = d.basicInformation || {};
        fdn = d.invoiceNo || d.fdn || d.fiscalDocumentNumber || bi.invoiceNo || null;
        antifakeCode = d.antiFakeCode || d.antifakeCode || bi.antifakeCode || bi.antiFakeCode || null;
        invoiceId = d.invoiceId || d.invoiceID || bi.invoiceId || '';
        cnRef = d.referenceNo || referenceNo || null;
        const efrisPortal = config.mode === 'production'
          ? 'https://efris.ura.go.ug/site_mobile/#/invoiceValidation'
          : 'https://efristest.ura.go.ug/site_new/#/invoiceValidation';
        validationUrl = (fdn && antifakeCode)
          ? `${efrisPortal}?invoiceNo=${encodeURIComponent(fdn)}&antiFakeCode=${encodeURIComponent(antifakeCode)}`
          : null;
        console.log('   T108 credit note:', JSON.stringify(d));
      } catch(e) { console.log('   T108 parse error:', e.message); }
    }
    const ok = rc === '00' || !!fdn;
    // Record the credit note (negative amount) so Documents and the Z report net it
    // off the day's sales.
    if (ok) {
      try {
        appendSubmissionLog({
          id: crypto.randomUUID(), kind: 'credit-note', docType: 'Credit note', submittedAt: new Date().toISOString(), fdn: fdn || '', antifakeCode: antifakeCode || '', validationUrl,
          tenantId: reqTenant(req) || undefined, deviceNo: cnCfg.deviceNo, invoiceId, reference: cnRef || t108data.sellersReferenceNo || '',
          originalFdn: originalFDN, returnCode: rc, status: 'success', tin: config.tin,
          customerName: t108data.buyerDetails ? (t108data.buyerDetails.buyerLegalName || t108data.buyerDetails.buyerTin || '') : '',
          totalAmount: -Math.abs(parseFloat(t108data.summary && t108data.summary.grossAmount) || 0),
          currency: t108data.currency || 'UGX', invoiceKind: t108data.basicInformation ? t108data.basicInformation.invoiceKind || '' : '', mode: config.mode || 'sandbox',
        });
      } catch (le) { console.log('Submission log write error:', le.message); }
    }
    res.json(ok
      ? { success: true, fdn, referenceNo: cnRef, antifakeCode, invoiceId, validationUrl, qrCode: validationUrl, deviceNo: config.deviceNo, returnCode: rc, returnMessage: rm }
      : { success: false, error: 'URA ' + rc + ': ' + rm, returnCode: rc });
  } catch(e) {
    logger.error('credit-note failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Invoice Report (T144) ─────────────────────────────────────
app.post('/api/efris/invoices-report', async (req, res) => {
  const { startDate, endDate, pageNo, pageSize, buyerTin, referenceNo, config } = req.body || {};
  if (!startDate || !endDate || !config || !config.tin) return res.status(400).json({ success: false, error: 'startDate, endDate and config required' });
  const eu = uraUrl(config.mode);
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    if (!session.aesKey) throw new Error('No AES key - private key not found or could not decrypt T104 session. Check that private_key.pem exists in the data folder (' + DATA_DIR + ') and matches your EFRIS device.');
    // T106 = Invoice/Receipt query (by conditions). T144 was being validated as a
    // GOODS interface by URA (hence "2194 goodsCode cannot be empty"). T106 lists the
    // taxpayer's issued invoices/receipts in a date range.
    const t106data = {
      oriInvoiceNo: '', invoiceNo: '', deviceNo: config.deviceNo || '',
      buyerTin: buyerTin || '', buyerLegalName: '', buyerNinBrn: '',
      combineKeywords: '', invoiceType: '', invoiceKind: '', isInvalid: '', isRefund: '',
      startDate, endDate,
      pageNo: String(pageNo || '1'),
      pageSize: String(Math.min(parseInt(pageSize) || 20, 99)),
      referenceNo: referenceNo || '', branchName: '', queryType: '1',
      dataSource: '', sellerTinOrNin: config.tin, currencyType: '', invoiceIndustryCode: '',
    };
    const t106 = await efrisSecure(eu, 'T106', t106data, config.tin, config.deviceNo, session);
    const rc = t106.data && t106.data.returnStateInfo ? t106.data.returnStateInfo.returnCode : null;
    const rm = t106.data && t106.data.returnStateInfo ? t106.data.returnStateInfo.returnMessage : '';
    let records = [], page = {};
    if (t106.data && t106.data.data && t106.data.data.content) {
      try {
        const s = efrisDecodeJson(t106.data.data.content, session.aesKey) || aesDecryptStr(t106.data.data.content, session.aesKey);
        const d = JSON.parse(s);
        records = d.records || d.invoiceList || d.list || (Array.isArray(d) ? d : []);
        page = d.page || { pageNo: 1, pageCount: 1, totalSize: records.length };
        console.log('   T106 report: ' + records.length + ' records');
      } catch(e) { console.log('   T106 parse error:', e.message); }
    }
    const ok = rc === '00' || records.length > 0;
    res.json(ok
      ? { success: true, records, page, returnCode: rc }
      : { success: false, error: 'URA ' + rc + ': ' + rm, returnCode: rc });
  } catch(e) {
    logger.error('invoices-report failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Credit-note follow-up: status (T111), withdraw (T120), cancel (T114) ──
// A T110 credit note is only an APPLICATION: URA approves it later and only then
// gives it an FDN. T111 lists our applications with their approval status.
const CN_STATUS_TEXT = { '101': 'Approved', '102': 'Pending approval', '103': 'Rejected', '104': 'Withdrawn' };
function efrisRcOf(r) {
  const s = (r && r.data && r.data.returnStateInfo) || {};
  return { rc: s.returnCode != null ? String(s.returnCode) : null, rm: s.returnMessage || '' };
}
// Decoded JSON content of an EFRIS answer (encrypted/zipped or plain), or null.
function efrisContentJson(r, session) {
  const c = r && r.data && r.data.data && r.data.data.content;
  if (!c) return null;
  try { return JSON.parse(efrisDecodeJson(c, session.aesKey) || aesDecryptStr(c, session.aesKey)); } catch (_) { return null; }
}
// Session on the first EFRIS target (the Enabler only in 'always' mode).
async function efrisQuerySession(config) {
  const t = efrisEndpoints(config)[0];
  const cfg = cfgForTarget(config, t);
  const session = await getSession(cfg.tin, cfg.deviceNo, cfg.efrisPassword, t.url, keyOverrideFrom(cfg));
  if (!session.aesKey) throw new Error('No AES key - check the EFRIS private key in Settings.');
  return { eu: t.url, cfg, session };
}
function efrisFriendly(e, what) {
  return isNetworkError(e) ? 'EFRIS is unreachable right now, so ' + what + '. Try again when the connection is back.' : (e && e.message) || String(e);
}
function cnItem(r) {
  const st = String(r.approveStatus || '');
  return { id: String(r.id || ''), referenceNo: r.referenceNo || '', oriInvoiceNo: r.oriInvoiceNo || '', invoiceNo: r.invoiceNo || '',
    approveStatus: st, statusText: CN_STATUS_TEXT[st] || st, grossAmount: r.grossAmount, currency: r.currency || '',
    applicationTime: r.applicationTime || '', taskId: r.taskId || '', categoryCode: String(r.invoiceApplyCategoryCode || ''),
    buyerName: r.buyerLegalName || r.buyerBusinessName || r.buyerName || undefined };
}
// T111 (my own credit/debit-note applications), up to 5 pages of 100.
async function t111Query(config, f) {
  const { eu, cfg, session } = await efrisQuerySession(config);
  const out = [];
  for (let p = 1; p <= 5; p++) {
    const body = { referenceNo: f.referenceNo || '', oriInvoiceNo: f.oriInvoiceNo || '', invoiceNo: '', combineKeywords: '', approveStatus: '',
      startDate: f.startDate || '', endDate: f.endDate || '', pageNo: String(p), pageSize: '99', queryType: '1',   // URA rejects 100 despite "max 100"
      invoiceApplyCategoryCode: '101,103', creditNoteType: '1' };
    const r = await efrisSecure(eu, 'T111', body, cfg.tin, cfg.deviceNo, session);
    const { rc, rm } = efrisRcOf(r);
    if (rc !== '00') { if (p === 1) throw new Error('URA ' + rc + ': ' + rm); break; }
    const d = efrisContentJson(r, session) || {};
    const recs = d.records || d.list || (Array.isArray(d) ? d : []);
    out.push(...recs);
    if (p >= (Number(d.page && d.page.pageCount) || 1) || recs.length < 100) break;
  }
  return out.map(cnItem);
}
// URA's portal link for a fiscal document (what receipts print as their QR code).
function efrisValidationUrl(mode, fdn, antifakeCode) {
  if (!fdn || !antifakeCode) return null;
  const portal = mode === 'production'
    ? 'https://efris.ura.go.ug/site_mobile/#/invoiceValidation'
    : 'https://efristest.ura.go.ug/site_new/#/invoiceValidation';
  return `${portal}?invoiceNo=${encodeURIComponent(fdn)}&antiFakeCode=${encodeURIComponent(antifakeCode)}`;
}
// URA T111 times are dd/MM/yyyy HH:mm:ss in Uganda time; ISO, or '' when unreadable.
function uraTimeIso(v) {
  const m = String(v || '').match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?/);
  if (!m) return '';
  const t = Date.parse(`${m[3]}-${m[2]}-${m[1]}T${m[4] || '00'}:${m[5] || '00'}:${m[6] || '00'}+03:00`);
  return isNaN(t) ? '' : new Date(t).toISOString();
}
// T108 (invoice details) for an issued document: its verification (antifake)
// code and URA's QR data. null when URA does not give them.
async function t108Details(config, fdn) {
  const { eu, cfg, session } = await efrisQuerySession(config);
  const r = await efrisSecure(eu, 'T108', { invoiceNo: String(fdn) }, cfg.tin, cfg.deviceNo, session);
  const { rc, rm } = efrisRcOf(r);
  if (rc !== '00') { console.log(`   T108 details for ${fdn}: URA ${rc} ${rm}`); return null; }
  const d = efrisContentJson(r, session) || {};
  const bi = d.basicInformation || {}, sm = d.summary || {};
  const antifakeCode = bi.antifakeCode || bi.antiFakeCode || d.antifakeCode || d.antiFakeCode || '';
  const qrCode = sm.qrCode || d.qrCode || '';
  if (!antifakeCode && !qrCode) return null;
  return { antifakeCode, qrCode, issuedDate: bi.issuedDate || '' };
}
// Approved credit notes about to be written to Manager: fetch the verification
// code + QR (T108) for those that only have the FDN, and keep them in the log.
// Failures are logged and skipped: the FDN is still written.
async function cnEnrich(config, entries) {
  for (const e of entries) {
    if (!e.fdn || e.antifakeCode) continue;
    try {
      const d = await t108Details(config, e.fdn);
      if (!d) continue;
      e.antifakeCode = d.antifakeCode || '';
      e.validationUrl = efrisValidationUrl(e.mode || config.mode, e.fdn, d.antifakeCode) || e.validationUrl || null;
      e.qrCode = d.qrCode || e.validationUrl || '';
      updateSubmissionLog(log => {
        const x = log.find(y => y.id === e.id); if (!x) return false;
        x.antifakeCode = e.antifakeCode; x.validationUrl = e.validationUrl; x.qrCode = e.qrCode;
      });
    } catch (err) { console.log(`   Credit note ${e.reference}: verification code lookup failed: ${err.message}`); }
  }
}
// Store URA's verdict on our credit-note log entries. Only entries of the same
// TIN, the same business (adopt.tenantId; untagged older entries too) and the same
// mode (sandbox / production; entries without one too) are candidates, so a
// sandbox and a production note, or two businesses, sharing a TIN and reference
// stay apart. URA's application id is matched first, then the reference (only on
// entries not bound to another application); an exact business and mode match
// wins over an untagged entry. With `adopt` ({ tenantId, mode, deviceNo }), a
// credit note URA has but the log does not (e.g. one issued before credit notes
// were logged) is added to the log. Returns the approved entries whose FDN is not
// in Manager yet.
function applyCnStatus(items, tin, adopt) {
  const refKey = v => String(v || '').trim().toLowerCase();
  const tid = (adopt && adopt.tenantId) || '';
  const mode = (adopt && adopt.mode) || '';
  const pending = [];
  updateSubmissionLog(log => {
    let changed = false;
    const fits = e => e.kind === 'credit-note' && String(e.tin || '') === String(tin)
      && (!tid || !e.tenantId || e.tenantId === tid) && (!mode || !e.mode || e.mode === mode);
    const score = e => (tid && e.tenantId === tid ? 2 : 0) + (mode && e.mode === mode ? 1 : 0);
    const best = list => list.reduce((a, e) => (!a || score(e) > score(a) ? e : a), null);
    const cands = log.filter(fits);
    const find = it => {
      const k = refKey(it.referenceNo);
      const byApp = it.id ? cands.filter(e => e.applicationId && String(e.applicationId) === String(it.id)) : [];
      if (byApp.length) return best(byApp);
      if (!k) return null;
      return best(cands.filter(e => refKey(e.reference) === k && (!e.applicationId || !it.id || String(e.applicationId) === String(it.id))));
    };
    const seen = new Set();
    for (const it of items) {
      const k = refKey(it.referenceNo);
      let e = find(it);
      if (!e) {
        // Adopt only credit-note applications (not cancellations of other notes).
        if (!adopt || !(k || it.id) || (it.categoryCode && it.categoryCode !== '101')) continue;
        const gross = Math.abs(parseFloat(it.grossAmount) || 0);
        e = {
          id: crypto.randomUUID(), kind: 'credit-note', docType: 'Credit note', adopted: true,
          submittedAt: uraTimeIso(it.applicationTime) || new Date().toISOString(),
          fdn: '', reference: it.referenceNo || '', originalFdn: it.oriInvoiceNo || '', oriInvoiceNo: it.oriInvoiceNo || '',
          grossAmount: it.grossAmount != null ? String(it.grossAmount) : '', totalAmount: -gross, currency: it.currency || 'UGX',
          customerName: it.buyerName || '', approveStatus: '', statusText: '', applicationId: it.id || '',
          tenantId: adopt.tenantId || undefined, tin: String(tin), deviceNo: adopt.deviceNo || '', mode: adopt.mode || 'sandbox',
          returnCode: '00', status: 'success', userName: 'URA check',
        };
        // Buyer and Manager reference come from the original invoice we fiscalised.
        const orig = it.oriInvoiceNo ? log.find(x => x.kind !== 'credit-note' && String(x.fdn || '') === String(it.oriInvoiceNo)) : null;
        if (orig) {
          e.originalReference = orig.reference || '';
          if (!e.customerName) e.customerName = orig.customerName || '';
          if (orig.buyerTin) e.buyerTin = orig.buyerTin;
          if (orig.buyerType) e.buyerType = orig.buyerType;
        }
        log.unshift(e);
        cands.push(e);
        changed = true;
        console.log(`   Credit note ${e.reference || it.id} found at URA (${it.statusText || 'status ' + it.approveStatus}), added to the history`);
      }
      if (seen.has(e.id)) continue;
      seen.add(e.id);
      const was = e.approveStatus || '';
      if (was !== it.approveStatus || (it.id && e.applicationId !== it.id) || (it.approveStatus === '101' && it.invoiceNo && !e.fdn)) {
        e.approveStatus = it.approveStatus; e.statusText = it.statusText;
        if (it.id) e.applicationId = it.id;
        if (it.approveStatus === '101' && it.invoiceNo && !e.fdn) e.fdn = it.invoiceNo;
        changed = true;
        if (was !== it.approveStatus) {
          if (it.approveStatus === '101') console.log(`   Credit note ${e.reference} approved by URA: FDN ${e.fdn || '?'}`);
          else console.log(`   Credit note ${e.reference} is now ${it.statusText} at URA`);
        }
      }
      if (e.approveStatus === '101' && e.fdn && !e.mgrWritten && !e.cancelled) pending.push({ ...e });
    }
    return changed ? undefined : false;
  });
  return pending;
}
// The Manager credit note whose Reference is one of `refs`: { key, formBase } or null.
// Manager's credit-note list has no Reference column (its search does not match it
// either), so candidates are read through the form: first the search hits for each
// ref (the extension puts URA's ref in the description), then the whole list.
// Matching is exact: the form's Reference equals a ref (case and surrounding spaces
// ignored), or the list description holds a ref of 8+ characters as a whole word
// (so CN-INV-1 never matches CN-INV-12, and a short ref never matches by description).
// Each Manager's key -> Reference is cached for the life of the process, and the
// whole-list walk reads at most CN_SCAN_MAX forms per call.
const CN_SCAN_MAX = 300;
const _cnRefCache = new Map();   // normalised endpoint -> Map(key -> Reference)
const escRe = v => String(v).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function descHasRef(desc, ref) {
  if (!desc || String(ref).length < 8) return false;
  const edge = '[\\s|.,;:!?()\\[\\]{}"\'/\\\\#]';
  return new RegExp('(?:^|' + edge + ')' + escRe(ref) + '(?:$|' + edge + ')', 'i').test(String(desc));
}
async function findMgrCreditNoteByReference(ep, tk, refs, exclude) {
  refs = (Array.isArray(refs) ? refs : [refs]).map(r => String(r || '').trim()).filter(Boolean);
  const skipKey = k => !!(exclude && exclude.has(k));
  if (!refs.length) return null;
  const want = new Set(refs.map(r => r.toLowerCase()));
  const formBase = '/credit-note-form';
  const cache = _cnRefCache.get(ep) || new Map();
  _cnRefCache.set(ep, cache);
  const checked = new Set();
  let reads = 0;
  const matchKey = async (key, capped) => {
    if (!key || checked.has(key) || skipKey(key)) return null;
    checked.add(key);
    if (!cache.has(key)) {
      if (capped && reads >= CN_SCAN_MAX) return null;
      reads++;
      try {
        const f = await managerCall(ep, tk, 'GET', `${formBase}/${key}`, null);
        if (f.status === 200 && f.data) cache.set(key, String(f.data.Reference || ''));
      } catch (_) {}
    }
    return cache.has(key) && want.has(cache.get(key).trim().toLowerCase()) ? { key, formBase } : null;
  };
  const list = async q => {
    try {
      const r = await managerCall(ep, tk, 'GET', '/credit-notes' + q, null);
      return (r.status === 200 && r.data && (r.data.creditNotes || r.data.CreditNotes)) || [];
    } catch (_) { return []; }
  };
  for (const ref of refs) {
    for (const x of await list('?term=' + encodeURIComponent(ref))) {
      const key = bareKey(x.key || x.Key);
      if (!key || skipKey(key)) continue;
      const hit = await matchKey(key, false); if (hit) return hit;
      if (refs.some(r => descHasRef(x.description || x.Description, r))) return { key, formBase };
    }
  }
  for (let skip = 0; skip < 1000 && reads < CN_SCAN_MAX; skip += 100) {
    const page = await list('?pageSize=100&skip=' + skip);
    for (const x of page) { const hit = await matchKey(bareKey(x.key || x.Key), true); if (hit) return hit; }
    if (page.length < 100) break;
  }
  return null;
}
// Write an approved credit note's FDN (and, when known, its verification code and
// QR) onto its Manager credit note with Status 'Approved'. The branded theme then
// prints it as issued instead of "Awaiting URA approval" (it keys on the FDN
// field). Not found in Manager: skipped quietly (counts as an attempt).
// References the Manager credit note may carry: ours, "CN-" + the original invoice's
// reference (the extension's default), or "CN-" + the original FDN (URA's seller
// reference). Several credit notes can share one original, so the "CN-" fallbacks
// are used only while no other credit note for that original has been written to
// a Manager document.
function cnMgrRefs(e, log) {
  log = log || readSubmissionLog();
  let origRef = e.originalReference || '';
  const ori = String(e.oriInvoiceNo || e.originalFdn || '');
  if (!origRef && ori) {
    const o = log.find(x => x.kind !== 'credit-note' && String(x.fdn || '') === ori);
    if (o) origRef = o.reference || '';
  }
  const sibling = !!ori && log.some(x => x.kind === 'credit-note' && x.id !== e.id && x.mgrKey
    && String(x.oriInvoiceNo || x.originalFdn || '') === ori);
  const refs = [e.reference];
  if (!sibling) refs.push(origRef && 'CN-' + origRef, e.oriInvoiceNo && 'CN-' + e.oriInvoiceNo);
  return [...new Set(refs.filter(Boolean))];
}
// Manager documents already holding another credit note (never written twice).
function cnUsedKeys(e, log) {
  return new Set((log || readSubmissionLog()).filter(x => x.kind === 'credit-note' && x.id !== e.id && x.mgrKey).map(x => String(x.mgrKey)));
}
async function cnWriteBack(ep, tk, e) {
  let ok = false, key = '';
  try {
    const log = readSubmissionLog();
    const refs = cnMgrRefs(e, log);
    const hit = await findMgrCreditNoteByReference(ep, tk, refs, cnUsedKeys(e, log));
    if (!hit) console.log(`   Credit note ${e.reference}: no Manager credit note with reference ${refs.join(' or ')}; not written`);
    if (hit) {
      const fiscal = { fdn: e.fdn, antifakeCode: e.antifakeCode || '', validationUrl: e.validationUrl || e.qrCode || '', deviceNo: e.deviceNo || '' };
      const w = await saveEfrisToManager(ep, tk, hit.key, fiscal, null, { formBase: hit.formBase, status: 'Approved', note: 'Credit Note FDN: ' + e.fdn });
      ok = !!(w && w.success);
      if (ok) { key = hit.key; console.log(`   Credit note ${e.reference}: FDN ${e.fdn}${e.antifakeCode ? ' and verification code' : ''} written to Manager`); }
      else console.log(`   Credit note ${e.reference}: Manager write-back failed (${(w && w.error) || 'not accepted'})`);
    }
  } catch (err) { console.log(`   Credit note ${e.reference}: Manager write-back error: ${err.message}`); }
  updateSubmissionLog(log => {
    const x = log.find(y => y.id === e.id); if (!x) return false;
    x.mgrAttempts = (x.mgrAttempts || 0) + 1;
    if (ok) { x.mgrWritten = true; x.mgrKey = key; }
  });
  return ok;
}

app.post('/api/efris/credit-notes/status', async (req, res) => {
  const { referenceNo, oriInvoiceNo, startDate, endDate, managerEndpoint, accessToken } = req.body || {};
  let config = (req.body || {}).config;
  if (!config || !config.tin) return res.status(400).json({ success: false, error: 'config.tin required' });
  // The business's own TIN and mode come from its saved settings when it has
  // them, not from the request, so URA's answer is filed under the right business.
  const tid = reqTenant(req);
  let saved = null;
  if (tid) { try { saved = vault.getTenant(tid); } catch (_) {} }
  if (saved) config = { ...config, tin: saved.tin || config.tin, mode: saved.mode || config.mode };
  try {
    const items = await t111Query(config, { referenceNo, oriInvoiceNo, startDate, endDate });
    const view = scopedView(req, 'credit');
    const toWrite = applyCnStatus(items, config.tin, { tenantId: tid, mode: config.mode || 'sandbox', deviceNo: config.deviceNo }).filter(view.sees);
    let managerUpdated = 0;
    if (managerEndpoint && accessToken && toWrite.length) {
      const ep = normEp(managerEndpoint);
      await cnEnrich(config, toWrite);
      // Stop retrying (and logging) notes with no Manager credit note after 3 tries.
      for (const e of toWrite) if ((e.mgrAttempts || 0) < 3 && await cnWriteBack(ep, accessToken, e)) managerUpdated++;
    }
    res.json({ success: true, items, managerUpdated });
  } catch (e) {
    logger.error('credit-notes/status failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: efrisFriendly(e, 'credit-note status could not be checked') });
  }
});

// Background: every 15 minutes, ask URA about credit notes still pending, for
// businesses whose credentials are in the vault, and write approved FDNs into
// Manager. Skipped while the vault is locked.
let _cnPolling = false;
async function pollPendingCreditNotes() {
  if (_cnPolling || !vault.isUnlocked()) return;
  _cnPolling = true;
  try {
    const cutoff = Date.now() - 90 * 86400000;
    const isCn = e => e.kind === 'credit-note' && e.status === 'success' && e.tenantId && !e.cancelled && e.reference;
    const needsMgr = e => e.approveStatus === '101' && e.fdn && !e.mgrWritten && (e.mgrAttempts || 0) < 5;
    const log = readSubmissionLog().filter(isCn);
    const pend = log.filter(e => (e.approveStatus === '102' || (!e.approveStatus && !e.fdn)) && Date.parse(e.submittedAt || 0) > cutoff);
    const tids = [...new Set(pend.concat(log.filter(needsMgr)).map(e => e.tenantId))];
    // Each business is checked under its own context, so its lines in the
    // activity log are tagged with it. Returns 'stop' when the run should end.
    const one = async tid => {
      let t = null; try { t = vault.getTenant(tid); } catch (_) { return 'stop'; }   // locked meanwhile
      const creds = t && offlineCredsFromVault({ tenantId: tid });
      if (!creds) return '';
      // Only this business's own TIN and its saved mode (its credentials are for that mode).
      const sameMode = x => !x.mode || !t.mode || x.mode === t.mode;
      for (const e of pend.filter(x => x.tenantId === tid && (!t.tin || String(x.tin) === String(t.tin)) && sameMode(x))) {
        const cfg = { tin: e.tin, deviceNo: t.deviceNo || e.deviceNo, mode: t.mode || e.mode, ...creds.cfg };
        try { applyCnStatus(await t111Query(cfg, { referenceNo: e.reference }), e.tin, { tenantId: tid, mode: cfg.mode, deviceNo: cfg.deviceNo }); }
        catch (err) {
          if (isNetworkError(err)) { reqCtx.run({ user: null, tenantId: '' }, () => console.log('   Credit-note status check: URA unreachable, will retry in 15 minutes')); return 'stop'; }
          console.log(`   Credit-note status check for ${e.reference} failed: ${err.message}`);
        }
      }
      if (!t.managerEndpoint || !t.managerToken) return '';
      const ep = normEp(t.managerEndpoint);
      const due = readSubmissionLog().filter(x => isCn(x) && x.tenantId === tid && needsMgr(x) && sameMode(x));
      if (due.some(x => !x.antifakeCode)) await cnEnrich({ tin: due[0].tin, deviceNo: t.deviceNo || due[0].deviceNo, mode: t.mode || due[0].mode, ...creds.cfg }, due);
      for (const e of due) await cnWriteBack(ep, t.managerToken, e);
      return '';
    };
    for (const tid of tids) {
      if (await reqCtx.run({ user: null, tenantId: tid }, () => one(tid)) === 'stop') return;
    }
  } finally { _cnPolling = false; }
}
setInterval(() => { pollPendingCreditNotes().catch(e => console.log('   Credit-note status check error: ' + e.message)); }, 15 * 60000).unref();

// Withdraw a credit-note application still pending at URA (T120). businessKey is
// taken to be the T111 record id (unconfirmed; URA's answer is logged).
app.post('/api/efris/credit-notes/void', rateLimit(30), async (req, res) => {
  const { config, id, referenceNo } = req.body || {};
  if (!config || !config.tin || !id) return res.status(400).json({ success: false, error: 'config and the application id (from the status list) are required' });
  try {
    const { eu, cfg, session } = await efrisQuerySession(config);
    const r = await efrisSecure(eu, 'T120', { businessKey: String(id), referenceNo: String(referenceNo || '') }, cfg.tin, cfg.deviceNo, session);
    const { rc, rm } = efrisRcOf(r);
    console.log(`   T120 withdraw credit-note application id=${id} ref=${referenceNo || '-'}: rc=${rc} ${rm}`);
    if (rc === '00') {
      const ref = String(referenceNo || '').trim().toLowerCase();
      updateSubmissionLog(log => {
        const e = log.find(x => x.kind === 'credit-note' && String(x.tin || '') === String(config.tin) && (x.applicationId === String(id) || (ref && String(x.reference || '').trim().toLowerCase() === ref)));
        if (!e) return false;
        e.approveStatus = '104'; e.statusText = CN_STATUS_TEXT['104'];
      });
    }
    res.json(rc === '00' ? { success: true, returnCode: rc, returnMessage: rm } : { success: false, returnCode: rc, returnMessage: rm, error: 'URA ' + rc + ': ' + rm });
  } catch (e) {
    logger.error('credit-notes/void failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: efrisFriendly(e, 'the credit note was not withdrawn') });
  }
});

// Cancel an ISSUED (approved) credit note (T114, category 104).
app.post('/api/efris/credit-notes/cancel', rateLimit(30), async (req, res) => {
  const { config, oriInvoiceId, invoiceNo, reasonCode, reason } = req.body || {};
  if (!config || !config.tin || !oriInvoiceId || !invoiceNo) return res.status(400).json({ success: false, error: 'config, oriInvoiceId (the original invoice\'s EFRIS id) and invoiceNo (the credit note FDN) are required' });
  const code = String(reasonCode || '');
  if (!['101', '102', '103'].includes(code)) return res.status(400).json({ success: false, error: 'reasonCode must be 101 (buyer refused), 102 (not delivered) or 103 (other)' });
  if (code === '103' && !String(reason || '').trim()) return res.status(400).json({ success: false, error: 'Give a reason when the reason is "Other"' });
  try {
    const { eu, cfg, session } = await efrisQuerySession(config);
    const body = { oriInvoiceId: String(oriInvoiceId), invoiceNo: String(invoiceNo), reason: String(reason || ''), reasonCode: code, invoiceApplyCategoryCode: '104', attachmentList: [] };
    const r = await efrisSecure(eu, 'T114', body, cfg.tin, cfg.deviceNo, session);
    const { rc, rm } = efrisRcOf(r);
    console.log(`   T114 cancel credit note ${invoiceNo}: rc=${rc} ${rm}`);
    if (rc === '00') {
      updateSubmissionLog(log => {
        const e = log.find(x => x.kind === 'credit-note' && String(x.tin || '') === String(config.tin) && String(x.fdn || '') === String(invoiceNo));
        if (!e) return false;
        e.cancelled = true; e.cancelledAt = new Date().toISOString();
      });
    }
    res.json(rc === '00' ? { success: true, returnCode: rc, returnMessage: rm } : { success: false, returnCode: rc, returnMessage: rm, error: 'URA ' + rc + ': ' + rm });
  } catch (e) {
    logger.error('credit-notes/cancel failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: efrisFriendly(e, 'the credit note was not cancelled') });
  }
});

// ── Debit Note (T109, invoiceType 4) ──────────────────────────
// Same flow as submit-invoice, but the T109 points at the ORIGINAL invoice's EFRIS
// id. Not queued offline: a debit note is raised at the desk and can be resent.
app.post('/api/efris/debit-note', rateLimit(30), async (req, res) => {
  const { invoice, config, originalFDN, originalInvoiceId, reason } = req.body || {};
  if (!invoice || !config || !config.tin) return res.status(400).json({ success: false, error: 'Missing invoice or config.tin' });
  if (!originalInvoiceId) return res.status(400).json({ success: false, error: 'A debit note needs the original invoice\'s EFRIS Invoice ID. Open the original from Documents, or enter its FDN so it can be looked up.' });
  if (!(invoice.Lines || []).length) return res.json({ success: false, error: 'The debit note has no line items. Add the extra goods or charges being billed.' });
  config._tenantId = reqTenant(req);
  { const a = actor(req); config._userId = a.userId || ''; config._userName = a.userName || ''; }
  const dn = { ...invoice, _debitOf: { oriInvoiceId: String(originalInvoiceId), oriInvoiceNo: String(originalFDN || '') } };
  delete dn.IsRefund; delete dn.isRefund;
  if (reason && !dn.Notes) dn.Notes = String(reason);
  try {
    // URA wants a unique reference per document (URS 9.18), debit notes included.
    const ref = String(dn.Reference || '').trim();
    if (ref && !req.body.allowDuplicateRef) {
      const dup = readSubmissionLog().find(e => e.status === 'success' && e.kind !== 'credit-note' && String(e.reference || '').trim().toLowerCase() === ref.toLowerCase() && String(e.tin || config.tin) === String(config.tin));
      if (dup) return res.json({ success: false, duplicateRef: true, existingFdn: dup.fdn || '',
        error: `Reference "${ref}" was already fiscalised (FDN ${dup.fdn || '?'}). Use a new number for this debit note.` });
    }
    const targets = efrisEndpoints(config);
    let result = null, lastNetErr = null, lastEndpointErr = null, uncertain = false;
    for (const t of targets) {
      try {
        result = await performInvoiceSubmission(dn, cfgForTarget(config, t), t.url);
        if (t.kind === 'enabler' && result) result.viaEnabler = true;
        lastNetErr = null; lastEndpointErr = null;
        break;
      } catch (subErr) {
        if (subErr.uncertain) { lastNetErr = subErr; uncertain = true; break; }
        if (isNetworkError(subErr)) { lastNetErr = subErr; console.log(`   ${t.kind} unreachable: ${subErr.message}`); continue; }
        if (subErr.endpointFailure) { lastEndpointErr = subErr; continue; }
        throw subErr;
      }
    }
    if (!result && lastEndpointErr && !lastNetErr) return res.json({ success: false, endpointError: true, error: lastEndpointErr.message });
    if (!result && uncertain) return res.json({ success: false, uncertain: true, error: 'EFRIS did not answer in time, so it may already have this debit note. Check Documents (or EFRIS) for reference "' + ref + '" before sending it again.' });
    if (!result) return res.json({ success: false, offline: true, error: 'EFRIS is unreachable, so the debit note was not issued. Debit notes are not saved offline; try again when the connection is back.' });
    if (result.ok) console.log(`   Debit note ${ref || '?'} on ${originalFDN || originalInvoiceId} issued: FDN ${result.fdn}`);
    return res.json(result.ok
      ? { success: true, fdn: result.fdn, qrCode: result.qrCode, antifakeCode: result.antifakeCode, validationUrl: result.validationUrl, deviceNo: result.deviceNo, issuedDate: result.issuedDate, invoiceId: result.invoiceId, viaEnabler: !!result.viaEnabler, returnCode: result.returnCode, returnMessage: result.returnMessage }
      : { success: false, error: 'URA ' + result.returnCode + ': ' + result.returnMessage, returnCode: result.returnCode });
  } catch (e) {
    logger.error('debit-note failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── URA exchange rate (T121): 1 unit of `currency` = rate UGX, cached 6 hours ──
const _uraRateCache = {};
app.post('/api/efris/exchange-rate', async (req, res) => {
  const { config } = req.body || {};
  const cur = String((req.body || {}).currency || '').trim().toUpperCase();
  if (!config || !config.tin || !/^[A-Z]{3}$/.test(cur)) return res.status(400).json({ success: false, error: 'config and a 3-letter currency code are required' });
  if (cur === 'UGX') return res.json({ success: true, currency: 'UGX', rate: 1, source: 'URA' });
  const ck = (config.mode === 'production' ? 'p|' : 's|') + cur;
  const hit = _uraRateCache[ck];
  if (hit && Date.now() - hit.ts < 6 * 3600000) return res.json({ success: true, currency: cur, rate: hit.rate, source: 'URA', cached: true });
  try {
    const { eu, cfg, session } = await efrisQuerySession(config);
    const r = await efrisSecure(eu, 'T121', { currency: cur }, cfg.tin, cfg.deviceNo, session);
    const { rc, rm } = efrisRcOf(r);
    if (rc !== '00') return res.json({ success: false, error: 'URA ' + rc + ': ' + rm });
    let d = efrisContentJson(r, session) || {};
    if (Array.isArray(d)) d = d.find(x => String(x.currency || '').toUpperCase() === cur) || d[0] || {};
    const rate = parseFloat(d.rate);
    if (!(rate > 0)) return res.json({ success: false, error: 'URA has no exchange rate for ' + cur + '.' });
    _uraRateCache[ck] = { ts: Date.now(), rate };
    res.json({ success: true, currency: cur, rate, source: 'URA' });
  } catch (e) {
    logger.error('exchange-rate failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: efrisFriendly(e, 'the URA rate could not be read') });
  }
});

// ── Reconciliation: URA vs Manager ────────────────────────────
// Every row of a Manager list (pageSize/skip paging). soft: a missing list is empty.
async function mgrListAll(ep, tk, listPath, props, soft) {
  const out = [], size = 500;
  for (let page = 0; page < 40; page++) {
    const r = await managerCall(ep, tk, 'GET', listPath + (listPath.includes('?') ? '&' : '?') + 'pageSize=' + size + '&skip=' + (page * size), null);
    if (r.status !== 200 || !r.data || typeof r.data !== 'object') {
      if (page === 0 && !soft) throw new Error('Manager ' + listPath + ' returned HTTP ' + r.status);
      break;
    }
    let arr = null;
    for (const p of props) if (Array.isArray(r.data[p])) { arr = r.data[p]; break; }
    if (!arr) arr = Object.values(r.data).find(Array.isArray) || [];
    out.push(...arr);
    const total = Number(r.data.totalRecords);
    if (arr.length < size || (total && out.length >= total)) break;
  }
  return out;
}
const mgrNum = v => { if (v == null) return 0; if (typeof v === 'object') v = v.value != null ? v.value : (v.amount != null ? v.amount : 0); return parseFloat(v) || 0; };
// T106 (issued invoices/receipts/notes) for a date range, all pages (max 20).
async function t106All(config, startDate, endDate) {
  const { eu, cfg, session } = await efrisQuerySession(config);
  const out = [];
  for (let p = 1; p <= 20; p++) {
    const body = {
      oriInvoiceNo: '', invoiceNo: '', deviceNo: '', buyerTin: '', buyerLegalName: '', buyerNinBrn: '',
      combineKeywords: '', invoiceType: '', invoiceKind: '', isInvalid: '', isRefund: '',
      startDate, endDate, pageNo: String(p), pageSize: '99',
      referenceNo: '', branchName: '', queryType: '1',
      dataSource: '', sellerTinOrNin: cfg.tin, currencyType: '', invoiceIndustryCode: '',
    };
    const r = await efrisSecure(eu, 'T106', body, cfg.tin, cfg.deviceNo, session);
    const { rc, rm } = efrisRcOf(r);
    if (rc !== '00') { if (p === 1) throw new Error('URA ' + rc + ': ' + rm); break; }
    const d = efrisContentJson(r, session) || {};
    const recs = d.records || d.invoiceList || d.list || (Array.isArray(d) ? d : []);
    out.push(...recs);
    if (p >= (Number(d.page && d.page.pageCount) || 1) || recs.length < 99) break;
  }
  return out;
}
function t106Kind(r) {
  const t = String(r.invoiceType || '');
  if (t === '2') return 'credit-note';
  if (t === '4') return 'debit-note';
  return String(r.invoiceKind || '') === '2' ? 'receipt' : 'invoice';
}

// URA T106 dates come as dd/MM/yyyy[ HH:mm:ss]; return yyyy-MM-dd so the page does not read them as MM/dd.
function uraIsoDate(v) {
  const t = String(v || '');
  const m = t.match(/^(\d{2})\/(\d{2})\/(\d{4})/);
  return m ? `${m[3]}-${m[2]}-${m[1]}` : t.slice(0, 10);
}
app.post('/api/reconcile/documents', async (req, res) => {
  const { config, startDate, endDate, managerEndpoint, accessToken } = req.body || {};
  const dOk = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || ''));
  if (!config || !config.tin || !dOk(startDate) || !dOk(endDate)) return res.status(400).json({ success: false, error: 'config, startDate and endDate (yyyy-MM-dd) are required' });
  if (!managerEndpoint || !accessToken) return res.status(400).json({ success: false, error: 'Manager endpoint and access token are required' });
  try {
    const ura = (await t106All(config, startDate, endDate)).map(r => ({
      fdn: String(r.invoiceNo || '').trim(), reference: String(r.referenceNo || '').trim(), amount: parseFloat(r.grossAmount) || 0,
      currency: r.currency || '', date: uraIsoDate(r.issuedDate || r.issuedDateStr), kind: t106Kind(r) }));
    const ep = normEp(managerEndpoint);
    const [inv, rcp, cn] = await Promise.all([
      mgrListAll(ep, accessToken, '/sales-invoices', ['salesInvoices', 'SalesInvoices'], false),
      mgrListAll(ep, accessToken, '/receipts', ['receipts', 'Receipts'], true),
      mgrListAll(ep, accessToken, '/credit-notes', ['creditNotes', 'CreditNotes'], true),
    ]);
    const mgrDoc = (x, type) => ({
      reference: String(x.reference || x.Reference || '').trim(), type,
      amount: mgrNum(x.invoiceAmount || x.amount || x.creditNoteAmount || x.total || x.Amount),
      date: String(x.issueDate || x.date || x.IssueDate || x.Date || '').slice(0, 10), key: bareKey(x.key || x.Key),
      text: String(x.reference || x.Reference || '') + ' ' + String(x.description || x.Description || '') });
    const mgr = [].concat(inv.map(x => mgrDoc(x, 'invoice')), rcp.map(x => mgrDoc(x, 'receipt')), cn.map(x => mgrDoc(x, 'credit-note')))
      .filter(m => m.date >= startDate && m.date <= endDate);
    const byRef = {}, byFdn = {};
    ura.forEach((u, i) => { if (u.reference) (byRef[u.reference.toLowerCase()] = byRef[u.reference.toLowerCase()] || []).push(i); if (u.fdn) byFdn[u.fdn] = i; });
    const used = new Set(), onlyManager = [], amountMismatch = [];
    let matched = 0;
    for (const m of mgr) {
      let i = (byRef[m.reference.toLowerCase()] || []).find(j => !used.has(j));
      if (i == null) for (const f of (m.text.match(/\d{10,}/g) || [])) { if (byFdn[f] != null && !used.has(byFdn[f])) { i = byFdn[f]; break; } }
      if (i == null) { onlyManager.push({ reference: m.reference, type: m.type, amount: m.amount, date: m.date, key: m.key }); continue; }
      used.add(i); matched++;
      const u = ura[i];
      if (Math.abs(Math.abs(u.amount) - Math.abs(m.amount)) > 1) amountMismatch.push({ reference: m.reference || u.reference, fdn: u.fdn, uraAmount: u.amount, managerAmount: m.amount });
    }
    const onlyUra = ura.filter((u, i) => !used.has(i));
    // A receipt that only pays sales invoices is a payment, not a sale: URA never has
    // it. Read the unmatched receipts' lines and list those separately.
    const payments = [], notAtUra = [];
    for (const m of onlyManager) {
      let isPayment = false;
      if (m.type === 'receipt' && m.key) {
        try {
          const f = await managerCall(ep, accessToken, 'GET', '/receipt-form/' + bareKey(m.key), null);
          const ls = (f.data && Array.isArray(f.data.Lines)) ? f.data.Lines : [];
          isPayment = ls.length > 0 && ls.every(l => l && l.AccountsReceivableSalesInvoice && !l.Item);
        } catch (_) {}
      }
      (isPayment ? payments : notAtUra).push(m);
    }
    console.log(`   Reconcile ${startDate}..${endDate}: URA ${ura.length}, Manager ${mgr.length}, matched ${matched}, mismatched amounts ${amountMismatch.length}, invoice payments ${payments.length}`);
    res.json({ success: true, counts: { ura: ura.length, manager: mgr.length - payments.length, matched, payments: payments.length }, onlyUra, onlyManager: notAtUra, payments, amountMismatch });
  } catch (e) {
    logger.error('reconcile/documents failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: efrisFriendly(e, 'the documents could not be compared') });
  }
});

// Current stock EFRIS holds for a registered good (field name varies by version).
function goodsStockOf(it) {
  for (const c of [it.stockQuantity, it.goodsStock, it.remainingStock, it.currentStock, it.stock, it.stockValue, it.stockQty]) {
    if (c != null && c !== '') { const n = parseFloat(c); if (isFinite(n)) return n; }
  }
  return null;
}
// Every good registered under the TIN (T127), all pages.
async function t127All(config) {
  const { eu, cfg, session } = await efrisQuerySession(config);
  const out = [];
  for (let p = 1; p <= 30; p++) {
    const r = await efrisSecure(eu, 'T127', { goodsCode: '', goodsName: '', commodityCategoryCode: '', pageNo: String(p), pageSize: '99' }, cfg.tin, cfg.deviceNo, session);
    const { rc, rm } = efrisRcOf(r);
    if (rc !== '00' && rc !== '45') { if (p === 1) throw new Error('URA ' + rc + ': ' + rm); break; }
    const d = efrisContentJson(r, session) || {};
    const recs = d.records || d.goodsList || d.list || (Array.isArray(d) ? d : []);
    out.push(...recs);
    if (p >= (Number(d.page && d.page.pageCount) || 1) || recs.length < 99) break;
  }
  return out;
}

app.post('/api/reconcile/stock', async (req, res) => {
  const { config, managerEndpoint, accessToken } = req.body || {};
  if (!config || !config.tin) return res.status(400).json({ success: false, error: 'config.tin required' });
  if (!managerEndpoint || !accessToken) return res.status(400).json({ success: false, error: 'Manager endpoint and access token are required' });
  try {
    // Services (serviceMark 101) carry no stock.
    const goods = (await t127All(config)).filter(g => String(g.serviceMark || '') !== '101').map(g => ({
      name: String(g.goodsName || g.name || '').trim(), code: String(g.goodsCode || g.itemCode || '').trim(), qty: goodsStockOf(g) || 0 }));
    const ep = normEp(managerEndpoint);
    let items = await mgrListAll(ep, accessToken, '/inventory-items', ['inventoryItems', 'InventoryItems'], false);
    const qtyOf = i => { for (const k of ['qtyOnHand', 'QtyOnHand', 'qtyOwned', 'QtyOwned', 'quantityOnHand', 'QuantityOnHand', 'qty', 'Qty']) if (i[k] != null) return mgrNum(i[k]); return null; };
    if (items[0]) console.log('   Reconcile stock: Manager inventory list fields: ' + Object.keys(items[0]).join(', '));
    // The default list columns may leave out the quantity: ask for it by name.
    if (items.length && !items.some(i => qtyOf(i) != null)) {
      try {
        const extra = await mgrListAll(ep, accessToken, '/inventory-items?fields=ItemCode&fields=ItemName&fields=QtyOnHand&fields=QtyOwned', ['inventoryItems', 'InventoryItems'], true);
        const byKey = {}; extra.forEach(x => { byKey[x.key || x.Key] = x; });
        items = items.map(i => { const x = byKey[i.key || i.Key]; return x ? { ...i, ...x, _q: qtyOf(x) } : i; });
      } catch (e) { console.log('   Reconcile stock: quantity column not available: ' + e.message); }
    }
    const mgr = items.map(i => ({
      name: String(i.ItemName || i.itemName || i.name || i.Name || '').trim(), code: String(i.ItemCode || i.itemCode || i.code || i.Code || '').trim(),
      qty: i._q != null ? i._q : (qtyOf(i) || 0), key: bareKey(i.key || i.Key) }));
    const used = new Set(), rows = [], onlyUra = [];
    const r3 = n => Math.round(n * 1000) / 1000;
    for (const g of goods) {
      let j = g.code ? mgr.findIndex((m, k) => !used.has(k) && m.code && m.code.toUpperCase() === g.code.toUpperCase()) : -1;
      if (j < 0 && g.name) j = mgr.findIndex((m, k) => !used.has(k) && m.name.toLowerCase() === g.name.toLowerCase());
      if (j < 0) { onlyUra.push({ name: g.name, code: g.code, uraQty: g.qty }); continue; }
      used.add(j);
      rows.push({ name: g.name || mgr[j].name, code: g.code || mgr[j].code, uraQty: g.qty, managerQty: mgr[j].qty, diff: r3(mgr[j].qty - g.qty) });
    }
    const onlyManager = mgr.filter((m, k) => !used.has(k)).map(m => ({ name: m.name, code: m.code, managerQty: m.qty, key: m.key }));
    console.log(`   Reconcile stock: URA ${goods.length} goods, Manager ${mgr.length} items, matched ${rows.length}, differing ${rows.filter(r => r.diff).length}`);
    res.json({ success: true, rows, onlyUra, onlyManager });
  } catch (e) {
    logger.error('reconcile/stock failed', { message: redactSecrets(e && e.message, req) });
    res.json({ success: false, error: efrisFriendly(e, 'stock could not be compared') });
  }
});

// ── Stock-in (T131) ───────────────────────────────────────────
app.post('/api/efris/stock-in', rateLimit(30), async (req, res) => {
  const { supplierName, supplierTin, stockInDate, stockInType, branchId, remarks, productionBatchNo, productionDate, items, config } = req.body || {};
  if (!items || !items.length || !config || !config.tin) return res.status(400).json({ success: false, error: 'items and config required' });
  // operationType 101 (stock-in) mandates a supplier name (URA 2081). Reject early
  // with a clear message rather than after a round-trip to EFRIS.
  if (!supplierName || !String(supplierName).trim()) {
    return res.status(400).json({ success: false, error: 'Supplier Name is required for a stock-in (URA 2081). Enter the supplier you bought the stock from.' });
  }
  const eu = uraUrl(config.mode);
  try {
    let session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    if (!session.aesKey) throw new Error('No AES key for T131');
    // EFRIS T131 requires the header wrapped in `goodsStockIn` and items in
    // `goodsStockInItem`. operationType lives ONLY in the header (101 = stock-in).
    // A flat operationType at the root is why rc 2076 ("operationType cannot be
    // empty") persisted - EFRIS reads goodsStockIn.operationType, not the root.
    const t131data = {
      goodsStockIn: {
        operationType:     '101',
        supplierTin:       supplierTin || '',
        supplierName:      supplierName || '',
        remarks:           remarks || '',
        stockInDate:       (stockInDate || eatToday()).slice(0,10),
        stockInType:       stockInType || '104',
        productionBatchNo: productionBatchNo || '',
        productionDate:    productionDate || '',
        branchId:          branchId || '',
        invoiceNo:         '',
        isCheckBatchNo:    '',
        rollBackIfError:   '1',
        goodsTypeCode:     '',
      },
      goodsStockInItem: items.map(item => ({
        goodsCode:   String(item.goodsCode || item.itemCode || ''),
        measureUnit: (item.measureUnit || 'PS').toUpperCase(),
        quantity:    String(item.quantity || 1),
        unitPrice:   String(item.unitPrice || 0),
        remarks:     '',
      })),
    };
    console.log('\n📦 T131 stock-in payload:', JSON.stringify(t131data, null, 2));
    const envelope = efrisEnvEnc('T131', t131data, config.tin, config.deviceNo, session.aesKey, session.privatePem);
    const selfCheck = aesDecryptStr(envelope.data.content, session.aesKey);
    console.log(`   Self-decrypt check: ${selfCheck.slice(0, 200)}`);
    // rc 15 = EFRIS "Data decryption error". Our ciphertext is verified correct
    // (self-decrypt passes), so an rc 15 is a transient URA-side fault - retry it.
    let t131, rc, rm;
    for (let attempt = 1; attempt <= 3; attempt++) {
      const env = attempt === 1 ? envelope
        : efrisEnvEnc('T131', t131data, config.tin, config.deviceNo, session.aesKey, session.privatePem);
      t131 = await efrisCall(eu, env);
      rc = t131.data && t131.data.returnStateInfo ? t131.data.returnStateInfo.returnCode : null;
      rm = t131.data && t131.data.returnStateInfo ? t131.data.returnStateInfo.returnMessage : '';
      if (rc !== '15') break;
      // rc:15 means the cached AES key rotated on EFRIS's side - renew it before the
      // next attempt (the following env is rebuilt with the new session key).
      console.log(`   T131 rc 15 (stale session key) - renewing session, retry ${attempt}/3`);
      invalidateSession(config.tin, config.deviceNo);
      session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    }
    let errors = [], rawContent = null;
    if (t131.data && t131.data.data && t131.data.data.content) {
      try {
        const s = (efrisDecodeJson(t131.data.data.content, session.aesKey) || aesDecryptStr(t131.data.data.content, session.aesKey)); rawContent = s;
        const d = JSON.parse(s);
        // T131 returns an ARRAY of per-item results; collect any with a non-00 code.
        if (Array.isArray(d)) errors = d.filter(r => r.returnCode && r.returnCode !== '00')
          .map(r => ({ itemCode: r.goodsCode, returnCode: r.returnCode, returnMessage: r.returnMessage }));
        else errors = d.errors || [];
      } catch(e) { console.log(`   T131 decrypt error: ${e.message}`); }
    }
    console.log(`   T131 rc: ${rc} - ${rm}`);
    if (rawContent) {
      try { const parsed = JSON.parse(rawContent); console.log(`   T131 raw response (parsed):`, JSON.stringify(parsed, null, 2).slice(0, 600)); } catch(e) { console.log(`   T131 raw response (raw): ${rawContent.slice(0, 500)}`); }
    } else if (t131.data && t131.data.data) {
      console.log(`   T131 response content (encrypted): ${JSON.stringify(t131.data.data).slice(0, 200)}`);
    }
    // rc 45 with item errors is NOT a success - surface the item-level reason.
    const ok = rc === '00' || (rc === '45' && errors.length === 0);
    res.json(ok
      ? { success: rc === '00', partialErrors: errors, returnCode: rc, returnMessage: rm }
      : { success: false, error: errors.length ? errors.map(e => e.itemCode + ': ' + e.returnMessage).join('; ') : ('URA ' + rc + ': ' + rm), returnCode: rc, partialErrors: errors, debug: rawContent });
  } catch(e) {
    logger.error('stock-in failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Stock Adjust (T132) ───────────────────────────────────────
app.post('/api/efris/stock-adjust', async (req, res) => {
  const { adjustDate, adjustType, branchId, remarks, items, config } = req.body || {};
  if (!items || !items.length || !config || !config.tin) return res.status(400).json({ success: false, error: 'items and config required' });
  const eu = uraUrl(config.mode);
  try {
    let session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    if (!session.aesKey) throw new Error('No AES key for stock adjust');
    // Stock adjustment is the SAME T131 interface with operationType 102 (decrease)
    // plus an adjustType. Same goodsStockIn/goodsStockInItem wrapper as stock-in -
    // the old flat payload to "T132" caused rc 2066 "Illegal json format".
    const t132data = {
      goodsStockIn: {
        operationType:    '102',
        supplierTin:      '',
        supplierName:     '',
        adjustType:       adjustType || '102',
        remarks:          remarks || '',
        stockInDate:      (adjustDate || eatToday()).slice(0,10),
        branchId:         branchId || '',
        invoiceNo:        '',
        rollBackIfError:  '1',
        goodsTypeCode:    '',
      },
      goodsStockInItem: items.map(item => ({
        goodsCode:   String(item.itemCode || item.goodsCode || ''),
        measureUnit: (item.measureUnit || 'PS').toUpperCase(),
        quantity:    String(item.quantity || 1),
        unitPrice:   String(item.unitPrice || 0),
        remarks:     '',
      })),
    };
    let t132, rc, rm;
    for (let attempt = 1; attempt <= 3; attempt++) {
      t132 = await efrisCall(eu, efrisEnvEnc('T131', t132data, config.tin, config.deviceNo, session.aesKey, session.privatePem));
      rc = t132.data && t132.data.returnStateInfo ? t132.data.returnStateInfo.returnCode : null;
      rm = t132.data && t132.data.returnStateInfo ? t132.data.returnStateInfo.returnMessage : '';
      if (rc !== '15') break;
      // rc:15 = stale AES key; renew the session before retrying.
      console.log(`   T131(adjust) rc 15 (stale session key) - renewing session, retry ${attempt}/3`);
      invalidateSession(config.tin, config.deviceNo);
      session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    }
    let errors = [];
    if (t132.data && t132.data.data && t132.data.data.content) {
      try {
        const s = aesDecryptStr(t132.data.data.content, session.aesKey); const d = JSON.parse(s);
        if (Array.isArray(d)) errors = d.filter(r => r.returnCode && r.returnCode !== '00').map(r => ({ itemCode: r.goodsCode, returnCode: r.returnCode, returnMessage: r.returnMessage }));
        else errors = d.errors || [];
      } catch(e) {}
    }
    console.log(`   T131(adjust) rc: ${rc} - ${rm}`);
    const ok = rc === '00' || (rc === '45' && errors.length === 0);
    res.json(ok
      ? { success: rc === '00', partialErrors: errors, returnCode: rc, returnMessage: rm }
      : { success: false, error: errors.length ? errors.map(e => e.itemCode + ': ' + e.returnMessage).join('; ') : ('URA ' + rc + ': ' + rm), returnCode: rc, partialErrors: errors });
  } catch(e) {
    logger.error('stock-adjust failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/efris/preview-invoice', async (req, res) => {
  const { invoice, config } = req.body || {};
  if (!invoice || !config) return res.status(400).json({ success: false, error: 'invoice and config required' });
  try {
    const t109data = buildT109(invoice, config);
    res.json({ success: true, payload: t109data });
  } catch(e) {
    logger.error('preview-invoice failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// Write EFRIS fiscal data (FDN/QR/etc.) back onto the source Manager document.
// Shared by the save-to-manager endpoint and the offline-queue flush.
// opts (credit notes): { formBase, status, note } - only that form, given status,
// note appended to the description, title left alone.
async function saveEfrisToManager(ep, accessToken, key, efrisData, vatRegistered, opts) {
  opts = opts || {};
  let formBase = opts.formBase || '/sales-invoice-form';
  let getR = await managerCall(ep, accessToken, 'GET', formBase + '/' + key, null);
  if (!opts.formBase && (getR.status !== 200 || (getR.data && getR.data.error))) {
    const rcptR = await managerCall(ep, accessToken, 'GET', '/receipt-form/' + key, null);
    if (rcptR.status === 200 && rcptR.data && !rcptR.data.error) { getR = rcptR; formBase = '/receipt-form'; }
  }
  if (getR.status !== 200) return { success: false, error: 'Manager GET returned ' + getR.status };
  const form = getR.data;
  const cf = await mgrTextCustomFields(ep, accessToken);
  form.CustomFields2 = form.CustomFields2 || {};
  form.CustomFields2.Strings = form.CustomFields2.Strings || {};
  const setCFAny = (names, val) => { for (const n of names) { const k = cf.byName[n]; if (k && val != null && val !== '') { form.CustomFields2.Strings[k] = String(val); break; } } };
  setCFAny(['FDN', 'Fiscal Document Number', 'EFRIS FDN'], efrisData.fdn);
  setCFAny(['Verification Code', 'EFRIS Antifake Code'], efrisData.antifakeCode);
  setCFAny(['QR Code', 'EFRIS QR Code URL', 'EFRIS QR Code'], efrisData.validationUrl || efrisData.antifakeCode);
  setCFAny(['EFRIS Device Number', 'Device Number'], efrisData.deviceNo);
  setCFAny(['EFRIS Issued Time', 'Issued Time'], efrisData.issuedDate ? new Date(efrisData.issuedDate).toLocaleString('en-UG', { timeZone: 'Africa/Kampala' }) : '');
  if (efrisData.invoiceId) setCFAny(['EFRIS Invoice ID', 'Invoice ID'], efrisData.invoiceId);
  setCFAny(['Status', 'EFRIS Status'], opts.status || 'Submitted');
  setCFAny(['Submission Date', 'EFRIS Submission Date'], eatToday());
  if (efrisData.operator) setCFAny(['Issued By', 'Issued by', 'Served By', 'Operator'], efrisData.operator);   // the person URA recorded as operator
  // A document saved in Manager without a reference takes the number sent to URA.
  if (efrisData.reference && !String(form.Reference || '').trim()) form.Reference = String(efrisData.reference);
  if (opts.note && !String(form.Description || '').includes(opts.note)) form.Description = (form.Description ? form.Description + ' | ' : '') + opts.note;
  const docTypeLabel = vatRegistered ? 'Tax Invoice' : 'e-Receipt';
  if (!opts.formBase && ('CustomTitle' in form || form.CustomTitle === undefined)) form.CustomTitle = docTypeLabel;
  const postR = await managerCall(ep, accessToken, 'POST', formBase + '/' + key, form);
  const ok = postR.status === 200 || postR.status === 201 || postR.status === 204;
  return ok ? { success: true } : { success: false, error: 'Manager POST returned ' + postR.status };
}

app.post('/api/efris/save-to-manager', async (req, res) => {
  const { managerEndpoint, accessToken, documentKey, efrisData, vatRegistered } = req.body || {};
  if (!managerEndpoint || !accessToken || !documentKey) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }
  try {
    const r = await saveEfrisToManager(normEp(managerEndpoint), accessToken, bareKey(documentKey), efrisData || {}, vatRegistered);
    res.json(r.success ? { success: true } : { success: false, error: r.error, fdn: (efrisData || {}).fdn });
  } catch(e) {
    logger.error('save-to-manager failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
});

// Create a credit note in Manager linked to the original invoice/receipt
app.post('/api/manager/create-credit-note', async (req, res) => {
  const { managerEndpoint, accessToken, originalDocType, reason, referenceNo, efrisFdn, efrisInvoiceId, efrisAntifake, efrisQr, efrisSubDate, items, originalReference } = req.body || {};
  let originalKey = bareKey((req.body || {}).originalKey || '');
  if (!managerEndpoint || !accessToken || (!originalKey && !originalReference)) return res.status(400).json({ success: false, error: 'Missing required fields' });
  const ep = normEp(managerEndpoint);
  // Opened from the Credit Note tab there is no document key: find the original in
  // Manager by its reference (the number sent to URA).
  if (!originalKey) {
    originalKey = await findMgrDocByReference(ep, accessToken, originalReference);
    if (!originalKey) return res.json({ success: false, error: 'No sales invoice or receipt with reference "' + originalReference + '" was found in Manager, so the credit note was not recorded there. Create it in Manager by hand.' });
  }
  // Overwrite a credit-note form's EFRIS custom fields with the CREDIT NOTE's own
  // values (so it doesn't inherit the original invoice's FDN/QR when cloned).
  const applyCnEfris = (form, cfMeta) => {
    const set = (names, val) => {
      if (val == null || val === '') return;
      const mn = Object.keys(cfMeta.byName || {}).find(n => names.some(l => n.toLowerCase().includes(l.toLowerCase())));
      if (!mn) return;
      const k = cfMeta.byName[mn];
      if (!form.CustomFields2) form.CustomFields2 = { Strings: {} };
      if (!form.CustomFields2.Strings) form.CustomFields2.Strings = {};
      form.CustomFields2.Strings[k] = String(val);
    };
    set(['Fiscal Document', 'FDN'], efrisFdn);
    set(['Verification'], efrisAntifake);
    set(['QR Code', 'QR'], efrisQr);
    set(['Invoice ID', 'UGX Inv'], efrisInvoiceId);
    set(['Submission Date'], efrisSubDate);
    set(['Status'], 'Credit Note');
  };

  // First read the original document to get its lines and details
  let origForm = null, origFormBase = '/sales-invoice-form';
  const invR = await managerCall(ep, accessToken, 'GET', '/sales-invoice-form/' + originalKey, null);
  if (invR.status === 200 && invR.data && !invR.data.error) {
    origForm = invR.data; origFormBase = '/sales-invoice-form';
  } else {
    const rcptR = await managerCall(ep, accessToken, 'GET', '/receipt-form/' + originalKey, null);
    if (rcptR.status === 200 && rcptR.data && !rcptR.data.error) {
      origForm = rcptR.data; origFormBase = '/receipt-form';
    }
  }
  if (!origForm) return res.status(404).json({ success: false, error: 'Original document not found in Manager' });

  // Build a native Credit Note (so it lands in Manager's Credit Notes tab, not as
  // a negative sales invoice). POST directly - Manager form endpoints 500/404 on a
  // bare GET, so we must not GET-probe them.
  let cfMeta = null; try { cfMeta = await mgrTextCustomFields(ep, accessToken); } catch (_) {}
  const today = eatToday();
  // Reference: prefer the caller's clean reference; never fall back to the raw key.
  const cnRef = referenceNo || ('CN-' + (origForm.Reference || origForm.InvoiceNumber || ''));
  const cnForm = {
    Date: today, IssueDate: today,   // Manager's credit-note form uses one of these - set both
    Reference: cnRef,
    Description: reason + (efrisFdn ? ' | Credit Note FDN: ' + efrisFdn : ''),
    HasLineDescription: true, QuantityColumn: true, UnitPriceColumn: true,
  };
  if (origForm.Customer) cnForm.Customer = origForm.Customer;
  else if (origForm.Contact) cnForm.Contact = origForm.Contact;
  else {
    // A walk-in receipt has no customer, and Manager puts a credit note without one
    // into Suspense. Use (or create) a "Walk-in Customer".
    try {
      const cl = await managerCall(ep, accessToken, 'GET', '/customers?pageSize=500', null);
      const arr = (cl.data && (cl.data.customers || cl.data.Customers)) || [];
      const hit = arr.find(c => /^walk-?in customer$/i.test(String(c.name || c.Name || '').trim()));
      let ck = hit ? bareKey(hit.key || hit.Key) : '';
      if (!ck) {
        const cr = await managerCall(ep, accessToken, 'POST', '/customer-form', { Name: 'Walk-in Customer' });
        ck = bareKey((cr.data && (cr.data.Key || cr.data.key || cr.data.id)) || cr.location || '');
        if (ck) console.log('   Created customer "Walk-in Customer" for credit notes on walk-in receipts');
      }
      if (ck) cnForm.Customer = ck;
    } catch (e) { console.log('   Could not set a customer on the credit note: ' + e.message); }
  }
  // Same price basis and tax codes as the original, so VAT is reversed correctly.
  if (origForm.AmountsIncludeTax != null) cnForm.AmountsIncludeTax = origForm.AmountsIncludeTax;
  // Manager receipts have no such flag: their prices include tax. A credit note's
  // prices exclude tax unless told otherwise, which would add VAT on top again
  // (a 1,000 receipt became a 1,180 credit note).
  else if (origFormBase === '/receipt-form') cnForm.AmountsIncludeTax = true;
  if (origForm.TaxCodeEnabled != null) cnForm.TaxCodeEnabled = origForm.TaxCodeEnabled;
  // Print with the same theme as the original (Manager has no form defaults over the API).
  if (origForm.CustomThemeId) { cnForm.CustomTheme = true; cnForm.CustomThemeId = origForm.CustomThemeId; }
  if (origFormBase === '/sales-invoice-form') cnForm.SalesInvoice = originalKey;   // links the credit note to the invoice
  const credLines = await creditLinesFrom(ep, accessToken, origForm.Lines || [], items);
  if (!credLines.length) return res.json({ success: false, error: 'None of the credited items match a line on the original document, so nothing was recorded in Manager.' });
  cnForm.Lines = credLines;
  if (cfMeta) applyCnEfris(cnForm, cfMeta);
  const cnPaths = ['/credit-note-form', '/sales-credit-note-form', '/customer-credit-note-form'];
  let lastCnErr = '';
  for (const path of cnPaths) {
    try {
      const r = await managerCall(ep, accessToken, 'POST', path, cnForm);
      if (r.status >= 200 && r.status < 400) {
        let newKey = (r.data && (r.data.key || r.data.Key)) || null;
        if (!newKey) { // re-list to find it
          try { const lr = await managerCall(ep, accessToken, 'GET', path.replace('-form', 's'), null); const arr = (lr.data && (lr.data.creditNotes || lr.data.salesCreditNotes || [])) || []; const hit = arr.find(x => (x.reference || x.Reference) === cnForm.Reference); if (hit) newKey = hit.key || hit.Key; } catch (_) {}
        }
        console.log(`   Manager credit note created via ${path} → key: ${newKey || 'unknown'}`);
        return res.json({ success: true, key: newKey, method: path });
      }
      // Only "no such form" (404) means try the next path. Any other answer is
      // Manager rejecting this credit note; creating a negative invoice instead
      // would hide that and could book the credit twice.
      if (r.status !== 404) {
        const err = `${path} HTTP ${r.status}: ${JSON.stringify(r.data || '').slice(0, 150)}`;
        console.log('   Manager credit note not created: ' + err);
        return res.json({ success: false, error: 'Manager did not accept the credit note (' + err + ')' });
      }
      lastCnErr = path + ' HTTP 404';
    } catch (e) { return res.json({ success: false, error: 'Manager credit note failed (' + path + ': ' + e.message + ')' }); }
  }
  console.log(`   No native credit-note endpoint worked (${lastCnErr}) - using negative-invoice fallback`);

  // Fallback: no native credit note form - create a negative receipt/invoice
  console.log('   No credit note form found - creating negative receipt as fallback');
  try {
    const fallbackForm = Object.assign({}, origForm);
    delete fallbackForm.Key; delete fallbackForm.key; delete fallbackForm.id; delete fallbackForm.UniqueName;
    fallbackForm.Date = today; fallbackForm.IssueDate = today;
    fallbackForm.Reference = cnRef;
    fallbackForm.Description = reason + (efrisFdn ? ' | Credit Note FDN: ' + efrisFdn : '');
    fallbackForm.Lines = credLines.map(l => ({ ...l, Qty: -(parseFloat(l.Qty) || 1) }));
    // Overwrite the cloned (original's) EFRIS custom fields with the credit note's.
    try { const cfMeta = await mgrTextCustomFields(ep, accessToken); applyCnEfris(fallbackForm, cfMeta); } catch (_) {}
    const fallR = await managerCall(ep, accessToken, 'POST', origFormBase, fallbackForm);
    if (!(fallR.status >= 200 && fallR.status < 300) || (fallR.data && fallR.data.error)) {
      const err = `${origFormBase} HTTP ${fallR.status}: ${JSON.stringify(fallR.data || '').slice(0, 150)}`;
      console.log('   Fallback credit note not created: ' + err);
      return res.json({ success: false, error: 'Manager did not accept the credit note (' + err + ')' });
    }
    let newKey = null;
    if (fallR.data && fallR.data.key) newKey = fallR.data.key;
    else if (Array.isArray(fallR.data) && fallR.data.length) newKey = fallR.data[fallR.data.length - 1].key;
    console.log(`   Fallback negative ${origFormBase} → key: ${newKey || 'unknown'}`);
    return res.json({ success: true, key: newKey, method: origFormBase + ' (negative fallback)' });
  } catch(e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// Key of the Manager sales invoice or receipt whose Reference is `ref`.
async function findMgrDocByReference(ep, tk, ref) {
  ref = String(ref || '').trim(); if (!ref) return '';
  for (const [list, prop] of [['/sales-invoices', 'salesInvoices'], ['/receipts', 'receipts']]) {
    try {
      const r = await managerCall(ep, tk, 'GET', list + '?term=' + encodeURIComponent(ref), null);
      const arr = (r.data && (r.data[prop] || r.data[prop.charAt(0).toUpperCase() + prop.slice(1)])) || [];
      const hit = arr.find(x => String(x.reference || x.Reference || '').trim() === ref);
      if (hit) return bareKey(hit.key || hit.Key);
    } catch (_) {}
  }
  return '';
}
// The credit note's lines: the original's lines (item, account, tax code kept) with
// the CREDITED quantity, matched by item code, else by name. Without `items`, the
// whole document is credited (the old behaviour).
async function creditLinesFrom(ep, tk, origLines, items) {
  const priceOf = l => parseFloat(l.SalesUnitPrice != null ? l.SalesUnitPrice : (l.UnitPrice != null ? l.UnitPrice : l.Amount)) || 0;
  const base = l => { const p = priceOf(l); const o = { ...l, UnitPrice: p, SalesUnitPrice: p }; delete o.Key; delete o.key; return o; };
  if (!Array.isArray(items) || !items.length) return origLines.map(l => ({ ...base(l), Qty: parseFloat(l.Qty) || 1 }));
  const info = [];
  for (const l of origLines) {
    let code = '', name = String(l.LineDescription || '').split('\n')[0];
    if (l.Item) {
      let it = null;
      try { it = (await managerCall(ep, tk, 'GET', '/inventory-item-form/' + l.Item)).data; } catch (_) {}
      if (!it || it.error) { try { it = (await managerCall(ep, tk, 'GET', '/non-inventory-item-form/' + l.Item)).data; } catch (_) {} }
      if (it && !it.error) { code = it.ItemCode || it.Code || ''; name = it.Name || it.ItemName || name; }
    }
    info.push({ l, code: code.toLowerCase(), name: name.toLowerCase(), used: false });
  }
  const out = [];
  for (const it of items) {
    const qty = Math.abs(parseFloat(it.quantity != null ? it.quantity : it.qty) || 0); if (!qty) continue;
    const c = String(it.itemCode || '').trim().toLowerCase(), n = String(it.itemName || '').trim().toLowerCase();
    const m = info.find(x => !x.used && c && x.code === c) || info.find(x => !x.used && n && x.name === n);
    if (!m) continue;
    m.used = true;
    out.push({ ...base(m.l), Qty: qty });
  }
  return out;
}

// Return the live T115 dictionary's structure for inspection - used to identify
// which section holds the goods measure-unit codes EFRIS validates against.
app.post('/api/efris/dictionary-dump', async (req, res) => {
  const { tin, deviceNo, efrisPassword, mode } = req.body || {};
  if (!tin || !deviceNo) return res.status(400).json({ success: false, error: 'tin and deviceNo required' });
  const eu = uraUrl(mode);
  try {
    const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
    const dict = await getEfrisDictionary(tin, deviceNo, session, eu);
    if (!dict) return res.json({ success: false, error: 'No T115 dictionary returned' });
    const summary = {};
    for (const k of Object.keys(dict)) {
      const v = dict[k];
      if (Array.isArray(v)) summary[k] = { count: v.length, sample: v.slice(0, 8) };
      else summary[k] = typeof v;
    }
    res.json({ success: true, keys: Object.keys(dict), summary });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Force-clean a broken inventory item (e.g. one whose form 404s because a bad
// starting-balance write corrupted it). Resolves the key by code, then deletes
// its starting balance and the item itself, reporting each step.
app.post('/api/manager/cleanup-item', async (req, res) => {
  const { managerEndpoint, accessToken, code } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk || !code) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and code are required' });
  const want = String(code).trim().toLowerCase();
  const codeOf = i => String(i.code || i.Code || i.ItemCode || i.itemCode || '').trim().toLowerCase();
  const steps = [];
  try {
    // find the key in inventory + non-inventory lists
    let key = null, base = null;
    for (const [path, prop, fb] of [['/inventory-items', 'inventoryItems', '/inventory-item-form'], ['/non-inventory-items', 'nonInventoryItems', '/non-inventory-item-form']]) {
      try {
        const r = await managerCall(ep, tk, 'GET', path, null);
        const arr = (r.data && (r.data[prop] || [])) || [];
        const hit = arr.find(i => codeOf(i) === want);
        if (hit) { key = hit.key || hit.Key; base = fb; steps.push(`found in ${path} → key ${key}`); break; }
      } catch (e) { steps.push(`${path}: ${e.message}`); }
    }
    if (!key) return res.json({ success: false, error: 'Item not found in any Manager list', steps });
    // 1) delete starting balance (the likely corrupter)
    try { const r = await managerCall(ep, tk, 'DELETE', '/inventory-item-starting-balance-form/' + key, null); steps.push(`DELETE starting-balance → HTTP ${r.status}`); } catch (e) { steps.push('starting-balance del err: ' + e.message); }
    // 2) delete the item itself
    let delStatus = null;
    try { const r = await managerCall(ep, tk, 'DELETE', base + '/' + key, null); delStatus = r.status; steps.push(`DELETE ${base} → HTTP ${r.status}`); } catch (e) { steps.push('item del err: ' + e.message); }
    const ok = delStatus != null && delStatus >= 200 && delStatus < 400;
    res.json({ success: ok, key, steps });
  } catch (e) { res.status(500).json({ success: false, error: e.message, steps }); }
});

app.get('/api/manager/invoice', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  const key = bareKey(req.query.key || '');
  if (!ep || !tk || !key) return res.status(400).json({ success: false, error: 'ep, tk and key are required' });
  try {
    const inv = await normalizeInvoice(ep, tk, key);
    res.json(inv._error
      ? { success: false, error: inv._error, hint: inv._status === 401 ? 'Token rejected' : 'Check endpoint and key' }
      : { success: true, data: inv });
  } catch(e) {
    res.json({ success: false, error: e.message });
  }
});

// Find a sales invoice or receipt in Manager by its reference (credit notes opened by FDN).
app.get('/api/manager/find-doc', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  const ref = String(req.query.ref || '').trim();
  if (!ep || !tk || !ref) return res.status(400).json({ success: false, error: 'ep, tk and ref are required' });
  try { const key = await findMgrDocByReference(ep, tk, ref); res.json(key ? { success: true, key } : { success: false, error: 'not found' }); }
  catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/manager/invoices', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk are required' });
  // Optional server-side search term (matches reference / customer in Manager) and
  // a page size cap so large books don't pull everything.
  const term = (req.query.term || '').trim();
  const qs = (term ? ('?term=' + encodeURIComponent(term) + '&pageSize=100') : '?pageSize=100');
  try {
    const r = await managerCall(ep, tk, 'GET', '/sales-invoices' + qs, null);
    if (r.status !== 200) return res.json({ success: false, error: 'Manager returned HTTP ' + r.status, hint: r.status === 401 ? 'Token rejected' : 'Check endpoint URL' });
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    // Pull a payer/customer value from whatever field Manager used (list shapes
    // differ across builds and between invoices vs receipts).
    const custOf = i => {
      const c = i.customer || i.Customer || i.payer || i.Payer || i.contact || i.Contact || i.payee || i.Payee || i.paidBy || i.PaidBy || i.customerName || i.CustomerName || '';
      if (c && typeof c === 'object') return c.name || c.Name || '';   // Manager sometimes wraps as {key,name}
      return c;
    };
    const nameCache = {};
    const resolveName = async v => {
      if (!v || typeof v !== 'string') return '';
      if (!UUID_RE.test(v)) return v;              // already a name
      if (nameCache[v] !== undefined) return nameCache[v];
      let name = '';
      try { const c = (await managerCall(ep, tk, 'GET', '/customer-form/' + v)).data; if (c && (c.Name || c.name)) name = c.Name || c.name; } catch(_) {}
      nameCache[v] = name; return name;
    };
    const salesInv = (r.data && r.data.salesInvoices) || [];
    if (salesInv[0]) console.log('   [invoices] sample sales-invoice keys:', Object.keys(salesInv[0]).join(','));
    const list = [];
    await Promise.all(salesInv.map(async i => {
      list.push({ key: i.key, reference: i.reference, customer: await resolveName(custOf(i)), amount: (i.invoiceAmount && i.invoiceAmount.value) || 0, currency: (i.invoiceAmount && i.invoiceAmount.currency) || '', date: i.issueDate, status: i.status, docType: 'invoice' });
    }));
    // Also include receipts (non-VAT cash sales). Tolerate absence / different shape.
    try {
      const rr = await managerCall(ep, tk, 'GET', '/receipts' + qs, null);
      const rcpts = (rr.status === 200 && rr.data && (rr.data.receipts || rr.data.receiptsAndPayments)) || [];
      if (rcpts[0]) console.log('   [invoices] sample receipt keys:', Object.keys(rcpts[0]).join(','), '| payer candidates →', JSON.stringify({ payer: rcpts[0].payer, customer: rcpts[0].customer, contact: rcpts[0].contact, payee: rcpts[0].payee, paidBy: rcpts[0].paidBy }));
      await Promise.all(rcpts.map(async i => {
        list.push({ key: i.key, reference: i.reference || i.payee || '(receipt)', customer: await resolveName(custOf(i)), amount: (i.amount && i.amount.value) || i.amount || 0, currency: (i.amount && i.amount.currency) || '', date: i.date || i.issueDate, status: i.status, docType: 'receipt' });
      }));
    } catch(_) {}
    res.json({ success: true, business: (r.data && r.data.business && r.data.business.name) || '', invoices: list });
  } catch(e) {
    res.json({ success: false, error: e.message });
  }
});

app.post('/api/manager/test', async (req, res) => {
  let ep;
  try { ep = normEp((req.body || {}).managerEndpoint || ''); }
  catch(e) { return res.json({ success: false, error: e.message }); }
  const tk = ((req.body || {}).accessToken || '').trim();
  try {
    let r = await managerCall(ep, tk, 'GET', '/sales-invoices', null);
    // Sales Invoices may be a disabled tab on this business (common for
    // receipt-only/non-VAT businesses) - that alone shouldn't read as "token
    // invalid". Fall back to Inventory Items (present on every business) before
    // concluding the token is bad; only both failing the same way is a real signal.
    let usedFallback = false;
    if (r._html || r.status === 404) {
      const r2 = await managerCall(ep, tk, 'GET', '/inventory-items', null);
      if (r2.status === 200) { r = r2; usedFallback = true; }
    }
    if (r._cfChallenge) {
      res.json({ success: false, error: 'Cloudflare is showing its own "Just a moment..." browser-challenge page instead of forwarding this request to Manager. This is not a token problem - no automated request can solve that challenge.', hint: 'In the Cloudflare dashboard for this domain, go to Security → Bots (or WAF → Custom rules) and add a rule that skips Bot Fight Mode / Super Bot Fight Mode for this endpoint\'s path (e.g. host equals your Manager domain AND path starts with /api2/), or for this server\'s outbound IP. Leave protection on for the rest of the site.' });
    } else if (r._html) {
      res.json({ success: false, error: 'Manager returned an HTML page instead of JSON' + (r._htmlSnippet ? ' ("' + r._htmlSnippet + '")' : '') + ' - the access token may be invalid or expired, OR a reverse proxy/firewall in front of Manager (e.g. Cloudflare) is blocking this request before it reaches Manager at all.', hint: 'If the snippet above looks like a proxy/security page rather than a Manager error, check that service\'s security/WAF logs for a blocked request - it may need an exception for API traffic. Otherwise, regenerate the token in Manager → Settings → API Access Tokens, paste it in Settings here, click Save Settings, then test again.' });
    } else if (r.status === 200) {
      const biz = (r.data && r.data.business && r.data.business.name) || '?';
      res.json({ success: true, message: 'Connected · Business: ' + biz, endpoint: ep });
    } else if (r.status === 401) {
      res.json({ success: false, error: 'HTTP 401 - access token rejected by Manager.', hint: 'Regenerate token in Manager → Settings → API Access Tokens, paste it in Settings, click Save Settings, then test again.' });
    } else if (r.status === 403) {
      res.json({ success: false, error: 'HTTP 403 - request blocked before reaching Manager\'s own logic (Manager itself replies with 401 for a bad token, not 403).', hint: 'This points to a reverse proxy or firewall in front of Manager (e.g. Cloudflare\'s bot/WAF protection) blocking server-to-server API calls. Check that service\'s security event log for a blocked request to ' + ep + ' around now, and add an exception for API traffic if found.' });
    } else {
      res.json({ success: false, error: 'Manager returned HTTP ' + r.status, hint: 'Confirm Manager is running and reachable. Endpoint tried: ' + ep });
    }
  } catch(e) {
    res.json({ success: false, error: e.message, hint: e.message.includes('ECONNREFUSED') ? 'Manager is not running.' : 'Check your Manager URL' });
  }
});

// ── Auto-detect the local Manager server ──────────────────────────────
// Manager binds a DIFFERENT random port on every launch, so a fixed list
// of "common ports" almost never finds it. We run on the same machine, so instead
// we fast-scan localhost for OPEN TCP ports, then HTTP-probe each for Manager's
// signature. Closed ports refuse instantly on localhost, so a full scan is quick.
function tcpOpen(port, host, timeout) {
  const net = require('net');
  return new Promise(resolve => {
    const s = new net.Socket(); let done = false;
    const fin = v => { if (done) return; done = true; try { s.destroy(); } catch(_) {} resolve(v); };
    s.setTimeout(timeout || 250);
    s.once('connect', () => fin(true));
    s.once('timeout', () => fin(false));
    s.once('error', () => fin(false));
    try { s.connect(port, host || '127.0.0.1'); } catch(_) { fin(false); }
  });
}
// Is there a Manager server on this open port? Manager's API2 answers /api2/...
// with JSON (200 with data, or 401/403 when a token is needed) - a plain web app
// or other service won't. We probe /api2/sales-invoices and accept a JSON-ish or
// auth response.
function managerSignature(port, host) {
  return new Promise(resolve => {
    const req = http.get({ host: host || '127.0.0.1', port, path: '/api2/sales-invoices', timeout: 1200,
      headers: { 'Accept': 'application/json' } }, r => {
      let body = ''; r.on('data', c => { body += c; if (body.length > 4000) r.destroy(); });
      r.on('end', () => {
        const ct = String(r.headers['content-type'] || '');
        const looksJson = ct.includes('json') || /^[\s]*[[{]/.test(body);
        const authWall = r.statusCode === 401 || r.statusCode === 403
          // Manager Server Edition sends a browser without a session to its login page.
          || (r.statusCode >= 300 && r.statusCode < 400 && /login|sign-?in|access-token/i.test(String(r.headers.location || '')));
        // A Manager server returns JSON on /api2 (200 or auth error). Reject plain
        // HTML unless it explicitly mentions Manager.
        if (looksJson || authWall || /manager/i.test(body)) resolve(true);
        else resolve(false);
      });
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}
async function scanChunk(ports, host, openLimit) {
  const open = [];
  const CONC = 400; let i = 0;
  async function worker() { while (i < ports.length && open.length < openLimit) { const p = ports[i++]; if (await tcpOpen(p, host, 250)) open.push(p); } }
  await Promise.all(Array.from({ length: Math.min(CONC, ports.length) }, worker));
  return open;
}
app.post('/api/manager/detect', rateLimit(6), async (req, res) => {
  const host = '127.0.0.1';
  // Ports people actually see for Manager (fixed installs / container host) - tried first.
  const common = [5000, 8080, 8081, 8082, 8090, 8443, 8888, 8889, 9090, 9091, 9000, 55667, 44300, 3100];
  // Full ephemeral range where Manager's random port lives.
  const full = [];
  for (let p = 1024; p <= 65535; p++) if (!common.includes(p)) full.push(p);
  const order = common.concat(full);
  const started = Date.now();
  const CHUNK = 4000;
  try {
    for (let start = 0; start < order.length; start += CHUNK) {
      if (Date.now() - started > 25000) break;  // safety cap
      const chunk = order.slice(start, start + CHUNK);
      const open = await scanChunk(chunk, host, 60);
      for (const p of open) {
        if (await managerSignature(p, host)) {
          const endpoint = `http://${host}:${p}/api2`;
          console.log(`   🔎 Manager detected at ${endpoint} (scanned ${start + chunk.length} ports in ${Date.now() - started}ms)`);
          return res.json({ success: true, endpoint, port: p, ms: Date.now() - started });
        }
      }
    }
    res.json({ success: false, error: 'No local Manager server found on any port.', ms: Date.now() - started });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  FX RATE - Bank of Uganda mid-rate (cached 1h)
// ══════════════════════════════════════════════════════════════
let _fxCache = { ts: 0, rates: {}, source: '' };
function _httpGet(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'EFRISConnect/1.0' } }, r => {
      // follow one redirect
      if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
        r.resume(); return _httpGet(r.headers.location, timeoutMs).then(resolve, reject);
      }
      let d = ''; r.on('data', c => d += c); r.on('end', () => resolve(d));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 8000, () => { req.destroy(new Error('FX source timed out')); });
  });
}
// Primary: Bank of Uganda mid-rates (XML). Fallback: open.er-api.com (UGX base,
// inverted to "UGX per 1 unit"). Returns whichever succeeds; merges so a currency
// missing from BOU is still filled from the fallback.
// Lightweight reachability probe - resolves true on ANY HTTP response (even
// 404/405), false on a network error/timeout. Used by the connectivity badge.
// TLS verification is intentionally skipped here: this is a read-only HEAD health
// check that sends and reads NO credentials or data - it only reports whether a
// host answers. (Credential-bearing Manager calls verify TLS by default.)
function pingUrl(url, timeoutMs) {
  return new Promise((resolve) => {
    let parsed; try { parsed = new URL(url); } catch (e) { return resolve(false); }
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request({ hostname: parsed.hostname, port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80), path: '/', method: 'HEAD', timeout: timeoutMs || 3500, ...(parsed.protocol === 'https:' ? { rejectUnauthorized: false } : {}) }, r => { r.resume(); resolve(true); });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}
let _connCache = { ts: 0, key: '', data: null };
// Report reachability of URA (and the Enabler if configured) + offline-queue depth.
app.get('/api/connectivity', async (req, res) => {
  const mode = (req.query.mode === 'production') ? 'production' : 'sandbox';
  let enablerUrl = (req.query.enablerUrl || '').trim();
  if (enablerUrl && !enablerUrlOk(enablerUrl)) enablerUrl = '';
  const enablerMode = (req.query.enablerMode || (enablerUrl ? 'fallback' : 'off'));
  const key = mode + '|' + enablerUrl + '|' + enablerMode;
  const now = Date.now();
  if (_connCache.data && _connCache.key === key && (now - _connCache.ts) < 15000) {
    return res.json({ ..._connCache.data, cached: true, pending: loadQueue().filter(e => e.status === 'pending').length });
  }
  const uraPing = uraHost(mode);
  const [ura, enabler] = await Promise.all([
    pingUrl(uraPing, 3500),
    enablerUrl ? pingUrl(enablerUrl, 2500) : Promise.resolve(null),
  ]);
  const data = { success: true, ura, enabler, enablerMode, mode };
  _connCache = { ts: now, key, data };
  res.json({ ...data, pending: loadQueue().filter(e => e.status === 'pending').length });
});

// Fetch UGX exchange rates (1 <CUR> = N UGX), cached 1h. Reusable server-side.
async function getFxRates() {
  if (Date.now() - _fxCache.ts < 3600000 && Object.keys(_fxCache.rates).length) {
    return { rates: _fxCache.rates, source: _fxCache.source, cached: true };
  }
  const rates = {}; const sources = [];
  try {
    const xml = await _httpGet('https://www.bou.or.ug/bou/bouwebsite/bouwebsitecontent/statistics/exchangerates/ExchangeRates.xml');
    const re = /<Currency code="([A-Z]{3})"[^>]*>[\s\S]*?<MidRate>([\d.]+)<\/MidRate>/g;
    let m, n = 0;
    while ((m = re.exec(xml)) !== null) { const v = parseFloat(m[2]); if (v > 0) { rates[m[1]] = v; n++; } }
    if (n) sources.push('Bank of Uganda');
  } catch (e) { console.log('FX: BOU source failed - ' + e.message); }
  if (!Object.keys(rates).length) {
    try {
      const txt = await _httpGet('https://open.er-api.com/v6/latest/UGX');
      const j = JSON.parse(txt);
      if (j && j.rates) {
        for (const code in j.rates) { const per = parseFloat(j.rates[code]); if (per > 0) rates[code] = Math.round((1 / per) * 10000) / 10000; }
        sources.push('open.er-api.com');
      }
    } catch (e) { console.log('FX: er-api fallback failed - ' + e.message); }
  }
  if (!Object.keys(rates).length) {
    if (Object.keys(_fxCache.rates).length) return { rates: _fxCache.rates, source: _fxCache.source || 'last cached', stale: true };
    return { rates: {}, source: '' };
  }
  _fxCache = { ts: Date.now(), rates, source: sources.join(' + ') };
  return { rates, source: _fxCache.source };
}
// Convert an amount in `iso` to UGX using the cached rates. Returns { ugx, rate }
// or null when no rate is available (caller keeps the original amount).
async function convertToUGX(amount, iso) {
  const cur = String(iso || '').trim().toUpperCase();
  if (!amount || !cur || cur === 'UGX') return null;
  const { rates } = await getFxRates();
  const rate = rates[cur];
  if (!(rate > 0)) return null;
  return { ugx: Math.round(amount * rate * 100) / 100, rate };
}
app.get('/api/fx-rates', async (req, res) => {
  try {
    const r = await getFxRates();
    if (!Object.keys(r.rates).length) return res.json({ success: false, error: 'No FX source reachable', rates: {} });
    res.json({ success: true, rates: r.rates, source: r.source, cached: !!r.cached, stale: !!r.stale });
  } catch (e) { res.json({ success: false, error: e.message, rates: {} }); }
});

// Single rate "1 <target> = N UGX", for a specific DATE when possible. With an
// ExchangeRate-API key we read that date's historical rate (needed to value a
// back-dated document correctly for FX gain/loss); otherwise we fall back to the
// latest Bank of Uganda / er-api rate and flag that it is not date-specific.
// Keyless historical rate via fawazahmed0's currency-api (free, no key, CDN-hosted,
// dated history, includes UGX). Returns "1 <target> = N UGX" for the given date, or 0.
async function fxFromCurrencyApi(target, date) {
  const t = String(target || '').toLowerCase();
  const seg = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : 'latest';
  const urls = [
    `https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@${seg}/v1/currencies/${t}.json`,
    `https://${seg}.currency-api.pages.dev/v1/currencies/${t}.json`,
  ];
  for (const u of urls) {
    try { const j = JSON.parse(await _httpGet(u, 8000)); const obj = j && j[t]; if (obj && obj.ugx > 0) return Math.round(obj.ugx * 10000) / 10000; } catch(_) {}
  }
  return 0;
}
app.get('/api/fx-rate', async (req, res) => {
  const target = String(req.query.target || '').trim().toUpperCase();
  const date = String(req.query.date || '').trim();   // YYYY-MM-DD
  // ExchangeRate-API key: X-Fx-Key header, else FX_API_KEY env. ?key= is still
  // accepted from older extensions; never logged.
  const key = String(req.headers['x-fx-key'] || process.env.FX_API_KEY || req.query.key || '').trim();
  if (!target || target === 'UGX') return res.json({ success: true, rate: 1, source: 'UGX base' });
  const today = eatToday();
  const isPast = !!(date && date < today);
  // 0) Manager's own rate service - keyless, historical, matches Manager's books.
  try {
    const r = await fxFromManager(target, date);
    if (r > 0) return res.json({ success: true, rate: r, date: (isPast ? date : today), source: 'forex.manager.io' + (isPast ? ' (' + date + ')' : ''), historical: isPast });
  } catch(_) {}
  // 1) Optional deeper history via ExchangeRate-API when a key is configured.
  if (key && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
    try {
      const [Y, M, D] = date.split('-');
      const j = JSON.parse(await _httpGet(`https://v6.exchangerate-api.com/v6/${encodeURIComponent(key)}/history/${target}/${+Y}/${+M}/${+D}`, 8000));
      if (j && j.result === 'success' && j.conversion_rates && j.conversion_rates.UGX > 0)
        return res.json({ success: true, rate: Math.round(j.conversion_rates.UGX * 10000) / 10000, date, source: 'ExchangeRate-API (' + date + ')', historical: true });
      if (j && j.result === 'error') console.log('FX history (key): ' + (j['error-type'] || 'error'));
    } catch (e) { console.log('FX history (key) failed: ' + String(e.message).split(key).join('[key]')); }
  }
  // 2) Keyless historical/latest via currency-api (default - no key needed).
  try {
    const r = await fxFromCurrencyApi(target, date);
    if (r > 0) return res.json({ success: true, rate: r, date: (isPast ? date : today), source: 'currency-api' + (isPast ? ' (' + date + ')' : ' (latest)'), historical: isPast });
  } catch(_) {}
  // 3) Final fallback: latest UGX rate (Bank of Uganda, then er-api).
  try {
    const { rates, source } = await getFxRates();
    const r = rates[target];
    if (r > 0) return res.json({ success: true, rate: r, source: (source || 'latest') + (isPast ? ' - latest, not ' + date : ''), historical: false, fallback: isPast });
  } catch(_) {}
  res.json({ success: false, error: 'No exchange rate available for ' + target + (isPast ? ' on ' + date : '') });
});

// Manager's exchange-rate service, the same source Manager's "refresh rate"
// uses: POST {BaseCurrency, ExchangeRate:{Date, Currency}} returns {Value} =
// "1 <Currency> = Value <BaseCurrency>". Keyless, and the Date field drives
// historical rates (back to ~2019), so results match Manager's books.
function fxFromManager(target, date) {
  return new Promise(resolve => {
    try {
      const d = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : eatToday();
      const body = JSON.stringify({
        BaseCurrency: { Code: 'UGX', Name: 'Uganda Shillings', Prefix: 'Ugx', Suffix: '/=', DecimalPlaces: null },
        ExchangeRate: { Date: d, Currency: { Code: String(target).toUpperCase() }, ExchangeRateValue: 0, ExchangeRateIsInverse: false },
      });
      const req = https.request({ hostname: 'forex.manager.io', path: '/', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'User-Agent': 'EFRISConnect/1.0' }, timeout: 8000 }, r => {
        let out = ''; r.on('data', c => out += c); r.on('end', () => {
          try { const j = JSON.parse(out); const v = parseFloat(j && j.Value); if (!j.Error && v > 0) return resolve(Math.round(v * 10000) / 10000); } catch(_) {}
          resolve(0);
        });
      });
      req.on('error', () => resolve(0)); req.on('timeout', () => { req.destroy(); resolve(0); });
      req.write(body); req.end();
    } catch (e) { resolve(0); }
  });
}

// Model B (opt-in): push a dated exchange rate into Manager's Foreign Exchange
// Rates so a foreign-currency receipt values correctly on the books. Best-effort
// and NON-FATAL: if the endpoint/shape isn't what this Manager build expects it
// reports the failure verbatim rather than guessing - nothing else depends on it.
// The exact form path/field GUIDs may vary by Manager build.
app.post('/api/manager/set-exchange-rate', async (req, res) => {
  const { managerEndpoint, accessToken, currency, rate, date } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  const cur = String(currency || '').trim().toUpperCase();
  const rt = parseFloat(rate);
  if (!ep || !tk || !cur || !(rt > 0)) {
    return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken, currency and a positive rate are required' });
  }
  const d = date || eatToday();
  // Manager keeps one record per date and currency (/exchange-rate-form) with the
  // currency's own key and the rate in ExchangeRateValue (1 foreign = n base).
  // Update the day's record when it exists instead of adding a duplicate.
  try {
    const fc = await managerCall(ep, tk, 'GET', '/foreign-currencies', null);
    if (fc._html) return res.json({ success: false, error: 'Manager returned a login/HTML page - check the access token', verified: false });
    const curRec = ((fc.data && fc.data.foreignCurrencies) || []).find(c => String(c.code || '').toUpperCase() === cur);
    if (!curRec) return res.json({ success: false, error: cur + ' is not set up in Manager (Settings > Currencies)', verified: false });
    const curKey = curRec.key;
    const body = { Date: d, Currency: curKey, ExchangeRateValue: rt };
    let existing = null;
    try {
      const l = await managerCall(ep, tk, 'GET', '/exchange-rates?pageSize=200', null);
      for (const x of ((l.data && l.data.exchangeRates) || []).filter(x => String(x.date || '').slice(0, 10) === d)) {
        const f = await managerCall(ep, tk, 'GET', '/exchange-rate-form/' + x.key, null);
        if (f.data && bareKey(f.data.Currency || '') === bareKey(curKey)) { existing = x.key; break; }
      }
    } catch (_) {}
    const r = existing ? await managerCall(ep, tk, 'PUT', '/exchange-rate-form/' + existing, body)
                       : await managerCall(ep, tk, 'POST', '/exchange-rate-form', body);
    const ok = r.status >= 200 && r.status < 300;
    console.log(`   Exchange rate ${ok ? (existing ? 'updated' : 'recorded') : 'NOT recorded'} in Manager: 1 ${cur} = ${rt} (${d})` + (ok ? '' : ' - HTTP ' + r.status));
    res.json({ success: ok, verified: ok, status: r.status, currency: cur, rate: rt, date: d, updated: !!existing });
  } catch (e) { res.json({ success: false, error: e.message, verified: false }); }
});

// ── Currency scan: what base + foreign currencies does this Manager business have? ──
// Read Manager's base + foreign currencies. The base currency is a singleton
// form exposed at slightly different paths across builds, so try a few and accept
// any that yields a code. Shared by the Currencies tab endpoint and the readiness
// audit so both report the same thing.
// Manager's Base Currency is a built-in SINGLETON addressed by a fixed GUID (the
// generic /base-currency-form path throws "not a valid GUID"). This is that GUID.
const MGR_BASE_CURRENCY_GUID = '39dde4fc-7af8-44cc-8572-3b1ff4cfb918';
// Manager (26.9) accepts writes to that singleton but its API answers GET on it
// with 404, so a base currency that IS set cannot be read back. Remember each
// successful set per business (keyed by a hash of endpoint + token, never the
// token itself) and report that when Manager cannot.
const BASE_CCY_FILE = path.join(DATA_DIR, 'base_currency.json');
function baseCcyId(ep, tk) { return crypto.createHash('sha256').update(String(ep) + '|' + String(tk)).digest('hex').slice(0, 24); }
function loadBaseCcy() { try { return JSON.parse(fs.readFileSync(BASE_CCY_FILE, 'utf8')); } catch (_) { return {}; } }
function rememberBaseCcy(ep, tk, rec) {
  const all = loadBaseCcy(); all[baseCcyId(ep, tk)] = Object.assign({ setAt: new Date().toISOString() }, rec);
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(BASE_CCY_FILE, JSON.stringify(all, null, 2)); } catch (e) { console.log('base currency record not saved: ' + e.message); }
}
async function readMgrCurrencies(ep, tk) {
  let base = null, foreign = [], baseDebug = {};
  for (const p of ['/base-currency-form/' + MGR_BASE_CURRENCY_GUID, '/base-currency-form', '/base-currency', '/base-currency-settings']) {
    try {
      const b = await managerCall(ep, tk, 'GET', p);
      baseDebug[p] = b.status;
      if (b.status === 200 && b.data && !b.data.error) {
        const d = b.data.baseCurrency || b.data.BaseCurrency || b.data;
        // Handle the code as a nested object OR as a plain string (some builds
        // return just "UGX"), plus a couple of extra key spellings.
        const code = (typeof d === 'string' ? d : '')
          || d.Code || d.code || d.currency || d.Currency || d.currencyCode || d.CurrencyCode
          || (typeof b.data.BaseCurrency === 'string' ? b.data.BaseCurrency : '')
          || '';
        if (code) { base = { code: String(code).toUpperCase(), name: d.Name || d.name || '' }; break; }
        // 200 but nothing parseable - log the raw shape once so the parser can be
        // matched exactly to this Manager build.
        console.log(`   base-currency GET ${p} 200 but no code parsed; raw: ${JSON.stringify(b.data).slice(0, 400)}`);
      }
    } catch(_) {}
  }
  try {
    const f = await managerCall(ep, tk, 'GET', '/foreign-currencies');
    const arr = (f.data && (f.data.foreignCurrencies || f.data.currencies || f.data.foreignCurrency)) || [];
    foreign = (Array.isArray(arr) ? arr : []).map(c => ({ key: c.key || c.Key || '', code: c.code || c.Code || '', name: c.name || c.Name || '' })).filter(c => c.code);
  } catch(_) {}
  if (!base) {
    const rec = loadBaseCcy()[baseCcyId(ep, tk)];
    if (rec && rec.code) base = { code: rec.code, name: rec.name || '', source: 'efrisconnect', setAt: rec.setAt };
  }
  return { base: (base && base.code) ? base : null, foreign, baseDebug };
}
app.get('/api/manager/currencies', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk are required' });
  const { base, foreign, baseDebug } = await readMgrCurrencies(ep, tk);
  res.json({ success: true, base, foreign, baseDebug });
});

// ── Currency create/configure (ISO-4217 driven from the client) ──
// Mirrors Manager's own Foreign Currency form: Code, Name, Prefix (symbol), Suffix,
// DecimalPlaces. Also sets the Base Currency when kind='base'.
app.post('/api/manager/add-currency', async (req, res) => {
  const { managerEndpoint, accessToken, kind, code, name, prefix, suffix, decimalPlaces } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  const cc = String(code || '').trim().toUpperCase();
  if (!ep || !tk || !cc || !name) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken, code and name are required' });
  const isBase = kind === 'base';
  try {
    let r, postedPath;
    if (isBase) {
      // The Base Currency is a SINGLETON updated by its fixed GUID. Posting to the
      // generic /base-currency-form path 201s but sets nothing (and GET on it throws
      // "not a valid GUID"), so update the singleton at /base-currency-form/{guid}.
      // Manager's API spec defines PUT for /{key}; older builds took POST there, so
      // fall back to it. (POST to the bare /base-currency-form creates a separate
      // record that Manager's own Base Currency screen ignores - never use it.)
      postedPath = '/base-currency-form/' + MGR_BASE_CURRENCY_GUID;
      const baseBody = { Code: cc, Name: name, Prefix: prefix || '', Suffix: suffix || '', DecimalPlaces: (decimalPlaces != null ? Number(decimalPlaces) : 2) };
      r = await managerCall(ep, tk, 'PUT', postedPath, baseBody);
      if (!(r.status >= 200 && r.status < 300) && !r._html) r = await managerCall(ep, tk, 'POST', postedPath, baseBody);
      if (r.status >= 200 && r.status < 300 && !r._html) rememberBaseCcy(ep, tk, { code: cc, name, prefix: prefix || '', suffix: suffix || '' });
    } else {
      postedPath = '/foreign-currency-form';
      r = await managerCall(ep, tk, 'POST', postedPath, { Code: cc, Name: name, Prefix: prefix || '', Suffix: suffix || '', DecimalPlaces: (decimalPlaces != null ? Number(decimalPlaces) : 2) });
    }
    if (r._html) return res.json({ success: false, error: 'Manager returned a login/HTML page - check the access token' });
    const ok = r.status >= 200 && r.status < 300;
    // Read the base back so we can confirm it actually took.
    // confirmed: true/false when Manager reports the base back; null when it cannot
    // (this build) - the write status is then the only signal.
    let confirmed = null, readBack;
    if (isBase) {
      try { const c = await readMgrCurrencies(ep, tk); if (c.base && c.base.code && c.base.source !== 'efrisconnect') { readBack = c.base.code; confirmed = (c.base.code === cc); } } catch(_) {}
    }
    console.log(`   add-currency ${kind || 'foreign'} ${cc}: ${isBase ? 'PUT/POST' : 'POST'} ${postedPath} -> HTTP ${r.status}${isBase ? ` (readback: ${readBack || 'none'}, confirmed: ${confirmed === null ? 'n/a - Manager does not report it' : confirmed})` : ''}`);
    res.json({ success: ok, confirmed, readBack, status: r.status, code: cc,
      note: ok
        ? (isBase ? (confirmed === true ? 'Base currency set and confirmed.'
            : confirmed === false ? `Manager reports a different base currency (${readBack}) - check Manager: Settings, Currencies, Base Currency.`
            : 'Base currency set. Manager does not report it back through its API, so EFRISConnect keeps a record of it.') : 'Created in Manager')
        : `Manager did not accept the currency form (HTTP ${r.status}).`,
      data: r.data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  T131 - Search EFRIS registered goods
// ══════════════════════════════════════════════════════════════
app.post('/api/efris/search-goods', async (req, res) => {
  const { tin, deviceNo, efrisPassword, mode, query, goodsCode } = req.body || {};
  if (!tin || !deviceNo || !efrisPassword) return res.json({ success: false, error: 'Missing EFRIS credentials' });
  // Offline cache: the FULL catalog load (empty query) is cached to disk per TIN so
  // the Line-Items picker still lists EFRIS-registered goods when URA is
  // unreachable - kept in sync with URA on every successful online load.
  const isFullLoad = !query && !goodsCode;
  const goodsCacheFile = path.join(DATA_DIR, 'goods_search_cache_' + String(tin).replace(/[^0-9A-Za-z]/g, '') + '.json');
  const serveCached = () => { try { const disk = JSON.parse(fs.readFileSync(goodsCacheFile, 'utf8')); if (Array.isArray(disk) && disk.length) { console.log('   Using cached goods list (offline)'); return disk; } } catch(_) {} return null; };
  try {
    const eu = uraUrl(mode);
    // T127 = Goods/Services Inquiry (query goods registered under this TIN).
    // NOTE: T130 is goods *registration* (upload) and only echoes the request back -
    // it must NOT be used for search. T127 takes a single object (not a batch array).
    // `query` is a NAME substring (goodsName) - it does NOT match against goodsCode,
    // so a caller that already knows the exact code (e.g. Stock Management's
    // item-code lookup) must pass `goodsCode` instead, or EFRIS returns 0 records.
    const GOODS_SEARCH_IFACE = 'T127';
    const payload = { goodsCode: goodsCode || '', goodsName: query || '', commodityCategoryCode: '', pageNo: '1', pageSize: '99' };
    let items = [], outerRc, outerRm, pageInfo = null;
    // One retry with a forced-fresh session: a decrypt failure on a *reused*
    // cached session ("wrong final block length") looks like the server-side
    // session/key had gone stale in a way our 30-min in-memory cache didn't
    // detect - dropping the cache and re-doing the T101/T104/T103 handshake
    // resolves that class of failure without surfacing a confusing 0-results.
    for (let attempt = 1; attempt <= 2; attempt++) {
      const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
      const t131 = await efrisSecure(eu, GOODS_SEARCH_IFACE, payload, tin, deviceNo, session);
      outerRc = t131.data?.returnStateInfo?.returnCode;
      outerRm = t131.data?.returnStateInfo?.returnMessage || '';
      console.log(`\n🔍 ${GOODS_SEARCH_IFACE} search rc: ${outerRc} - ${outerRm}`);
      if (outerRc !== '00' && outerRc !== '45') return res.json({ success: false, error: outerRm || `${GOODS_SEARCH_IFACE} failed` });
      let decryptErr = null;
      if (t131.data?.data?.content) {
        try {
          // Use the brute-force decoder (same one that reliably decodes the T115
          // dictionary): EFRIS compresses larger T127 responses (gzip after AES),
          // and the exact combination varies, so try every gzip/AES combination
          // and keep whichever yields valid JSON. A single fixed path returns
          // garbage when the compression layer is present.
          const raw = efrisDecodeJson(t131.data.data.content, session.aesKey);
          if (!raw) throw new Error('Could not decode T127 response by any known method');
          console.log(`   T127 search raw: ${raw.slice(0,300)}`);
          const parsed = JSON.parse(raw);
          items = parsed.records || parsed.goodsList || parsed.list || (Array.isArray(parsed) ? parsed : []);
          pageInfo = parsed.page || null;
        } catch(e) { decryptErr = e; console.log(`   T127 search decrypt error (attempt ${attempt}): ${e.message}`); }
      }
      if (!decryptErr) break;
      if (attempt === 1) { invalidateSession(tin, deviceNo); console.log('   Dropping cached session, retrying T127 with a fresh one…'); }
      else logger.error('search-goods decrypt failed after session retry', { message: decryptErr.message });
    }
    // Pagination: on a full catalog load, pull the remaining pages so the picker +
    // offline cache hold EVERY registered good, not just the first page.
    if (isFullLoad && pageInfo && Number(pageInfo.pageCount) > 1) {
      try {
        const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
        for (let p = 2; p <= Number(pageInfo.pageCount); p++) {
          const pr = await efrisSecure(eu, GOODS_SEARCH_IFACE, { ...payload, pageNo: String(p) }, tin, deviceNo, session);
          if (pr.data?.data?.content) {
            const raw = efrisDecodeJson(pr.data.data.content, session.aesKey);
            if (raw) { const pd = JSON.parse(raw); items = items.concat(pd.records || pd.goodsList || pd.list || []); }
          }
        }
        console.log(`   T127 paginated: ${pageInfo.pageCount} pages, ${items.length} total`);
      } catch (e) { console.log(`   T127 pagination stopped: ${e.message}`); }
    }
    console.log(`   T127 search found ${items.length} items`);
    // One-time: log the field names EFRIS returns per record, so the current-stock
    // field (if any) can be identified for opening-balance import at sync time.
    if (items[0]) console.log(`   T127 record fields: ${Object.keys(items[0]).join(', ')}`);
    // Normalize whatever EFRIS calls "current stock" into a single `currentStock`
    // field, so an import can seed the Manager opening balance from it. EFRIS
    // naming varies by version; take the first present numeric candidate.
    for (const it of items) { const n = goodsStockOf(it); if (n != null) it.currentStock = n; }
    // Log each record's type/unit so goods-vs-service classification can be verified.
    for (const it of items) { const seg = parseInt(String(it.commodityCategoryCode||'').slice(0,2),10); console.log(`     • ${it.goodsCode||'?'}  cat=${it.commodityCategoryCode} unit=${it.measureUnit} (${seg>=70&&seg<=94?'Service':'Goods'})`); }
    // Receipt-time currency conversion: the good stays priced in its ORIGINAL
    // currency (in EFRIS/Manager); here we add unitPriceUGX (converted with the
    // CURRENT rate) + currencyIso so a UGX receipt line uses the live UGX value
    // instead of carrying e.g. "98" (USD) as if it were UGX.
    if (items.length) {
      try {
        const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
        const { rates } = await getFxRates();
        for (const it of items) {
          const price = parseFloat(it.unitPrice) || 0;
          const iso = await efrisCurrencyIsoFromCode(it.currency, tin, deviceNo, session, eu);
          it.currencyIso = iso || 'UGX';
          if (iso && iso !== 'UGX' && rates[iso] > 0) { it.unitPriceUGX = Math.round(price * rates[iso] * 100) / 100; it.fxRate = rates[iso]; }
          else it.unitPriceUGX = price;
        }
      } catch (e) { console.log('   FX enrich error: ' + e.message); }
    }
    // Refresh the offline cache on a good full load; fall back to it if the live
    // call came back empty (e.g. decrypt failed / URA hiccup) but we have a cache.
    if (isFullLoad && items.length) { try { fs.writeFileSync(goodsCacheFile, JSON.stringify(items)); } catch(_) {} }
    if (isFullLoad && !items.length) { const disk = serveCached(); if (disk) return res.json({ success: true, items: disk, cached: true, offline: true }); }
    res.json({ success: true, items });
  } catch (e) {
    const safe = redactSecrets(e.message, req);
    logger.error('search-goods failed', { message: safe });
    // URA unreachable - serve the last-synced catalog so the picker still works offline.
    if (isFullLoad) { const disk = serveCached(); if (disk) return res.json({ success: true, items: disk, cached: true, offline: true }); }
    res.json({ success: false, error: safe });
  }
});


// ══════════════════════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════
//  Submission Log
// ══════════════════════════════════════════════════════════════
const SUBMISSION_LOG_FILE = path.join(DATA_DIR, 'submission_log.json');

// Keep about a year of a busy till's documents (the Z report and Documents read it).
const SUBMISSION_LOG_MAX = 20000;
// ── Per-business view of the submission log ──
// Several businesses (Manager files) can share one relay and even one TIN, so
// each entry records the business that created it (tenantId, the request's
// checked X-Tenant-Id). A request with a tenant id sees its own entries plus
// older, untagged entries for the same TIN (flagged unlinked). A request without
// one sees the entries of the businesses the user holds a role in (owners and the
// service principal: everything).
function reqTenant(req) { return String((req && req.tenantId) || ''); }
function tenantView(req) {
  const tid = reqTenant(req);
  const user = req && req.auth;
  const metas = tenantMetaMap();
  if (tid) {
    const tin = (metas[tid] && metas[tid].tin) || '';
    return { tid, sees: e => e.tenantId ? e.tenantId === tid : (!!tin && String(e.tin || '') === tin) };
  }
  if (user && (user.owner || user.service)) return { tid: '', sees: () => true };
  const ids = new Set(tenantIdsFor(user));
  const tins = new Set([...ids].map(i => metas[i] && metas[i].tin).filter(Boolean));
  return { tid: '', sees: e => e.tenantId ? ids.has(e.tenantId) : tins.has(String(e.tin || '')) };
}
// What the caller may do with one entry: their permissions in the entry's own
// business. An older untagged entry counts as the requested business's, or, with
// no business named, as any of the caller's businesses with the entry's TIN. Never
// the union of all their roles: a cashier in A and accountant in B is a cashier
// for A's entries whether or not X-Tenant-Id is sent.
function entryPermsFn(req) {
  const user = req && req.auth, tid = reqTenant(req);
  if (!user) { const none = new Set(); return () => none; }
  if (user.owner || user.service) { const all = new Set(['*']); return () => all; }
  const metas = tenantMetaMap();
  const cache = new Map();
  return e => {
    const own = e && e.tenantId ? String(e.tenantId) : tid;
    const key = own ? 't:' + own : 'tin:' + String((e && e.tin) || '');
    if (cache.has(key)) return cache.get(key);
    let p;
    if (own) p = auth.permissionsFor(user, own);
    else {
      p = new Set();
      const tin = String((e && e.tin) || '');
      for (const id of Object.keys(user.roles || {})) {
        if (tin && metas[id] && String(metas[id].tin || '') === tin) for (const x of auth.permissionsFor(user, id)) p.add(x);
      }
    }
    cache.set(key, p);
    return p;
  };
}
// tenantView narrowed entry by entry: `perm` in the entry's business, or (for the
// caller's own entries) `ownPerm` there.
function scopedView(req, perm, ownPerm) {
  const v = tenantView(req);
  const P = entryPermsFn(req);
  const uid = req && req.auth && req.auth.id;
  return { tid: v.tid, perms: P,
    sees: e => v.sees(e) && (auth.can(P(e), perm) || (!!ownPerm && auth.can(P(e), ownPerm) && !!uid && e.userId === uid)) };
}
// Reading the log: a cashier ('log-own' without 'log-all') sees only the entries
// they made, business by business.
function logView(req) { return scopedView(req, 'log-all', 'log-own'); }
function markUnlinked(e) { return e.tenantId ? e : Object.assign({}, e, { unlinked: true }); }

// Atomic write: temp file then rename, so a crash or a reader never sees a half-
// written file. Synchronous on purpose: a read-change-write built on it runs to the
// end before any other request's, so writers cannot overwrite each other.
function writeFileAtomic(file, data) {
  const tmp = file + '.' + process.pid + '.tmp';
  try { fs.writeFileSync(tmp, data); }
  catch (e) { try { fs.rmSync(tmp, { force: true }); } catch (_) {} throw e; }
  try { fs.renameSync(tmp, file); }
  catch (e) {
    // Windows: antivirus/indexer can hold the target open for a moment; write in place.
    try { fs.writeFileSync(file, data); } finally { try { fs.rmSync(tmp, { force: true }); } catch (_) {} }
  }
}
function readSubmissionLog() { try { const l = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); return Array.isArray(l) ? l : []; } catch (_) { return []; } }
// The ONE writer of the submission log: every change (new submission, Manager-only
// row, link, delete, URA import) goes through here. fn changes the array in place
// (or returns a new one); returning false means nothing to save.
function updateSubmissionLog(fn) {
  let log = readSubmissionLog();
  const out = fn(log);
  if (out === false) return false;
  if (Array.isArray(out)) log = out;
  if (log.length > SUBMISSION_LOG_MAX) log = log.slice(0, SUBMISSION_LOG_MAX);
  writeFileAtomic(SUBMISSION_LOG_FILE, JSON.stringify(log, null, 2));
  return true;
}
// Each entry records who made it: the signed-in user of the request, or the user
// who queued a sale that the offline queue sends later.
function appendSubmissionLog(entry) {
  const e = { ...entry };
  if (!e.userId) { delete e.userId; delete e.userName; Object.assign(e, actor()); }
  updateSubmissionLog(log => { log.unshift(e); });
}

// Issued-document retrieval: the extension saves a render snapshot (the receipt.html
// query string) keyed by FDN when a document is issued, so History can re-open the
// ACTUAL rendered document later - not just its reference. Stored server-side so it
// survives browser cache clears and is shared across sessions on the same relay.
const RECEIPT_SNAP_FILE = path.join(DATA_DIR, 'receipt_snapshots.json');
function _readSnaps() { try { return JSON.parse(fs.readFileSync(RECEIPT_SNAP_FILE, 'utf8')); } catch(e) { return {}; } }
// Snapshots carry the business that saved them; a business only reads its own.
// Within it, someone who sees the whole log (log-all) reads any snapshot, others
// only the ones they saved (older ones with no user: anyone who may view there).
// Replacing one (write) needs 'sell' in its business.
// Older snapshots (no tenantId) stay readable by owners, and by an admin of the
// requested business when the snapshot's seller TIN (if it has one) is theirs.
function snapVisible(req, hit, write) {
  const tid = reqTenant(req), user = req.auth;
  if (hit.tenantId) {
    if (tid ? hit.tenantId !== tid : !tenantIdsFor(user).includes(hit.tenantId)) return false;
    const p = auth.permissionsFor(user, hit.tenantId);
    if (write) return auth.can(p, 'sell');
    if (auth.can(p, 'log-all')) return true;
    return hit.userId ? hit.userId === (user && user.id) : auth.can(p, 'view');
  }
  if (user && (user.owner || user.service)) return true;
  if (!tid || auth.roleIn(user, tid) !== 'admin') return false;
  let tin = ''; try { tin = new URLSearchParams(String(hit.query || '')).get('tin') || ''; } catch (_) {}
  const own = (tenantMetaMap()[tid] || {}).tin || '';
  return !tin || tin === own;
}
app.post('/api/receipt-snapshot', (req, res) => {
  const { key, query } = req.body || {};
  if (!key || !query) return res.status(400).json({ success: false, error: 'key and query required' });
  const map = _readSnaps();
  const prev = map[String(key)];
  if (prev && !snapVisible(req, prev, true)) return res.status(403).json({ success: false, error: 'You do not have access to this business' });
  map[String(key)] = { query: String(query), savedAt: Date.now(), tenantId: reqTenant(req) || undefined, ...actor(req) };
  // Keep the most recent 1000 snapshots.
  const keys = Object.keys(map);
  if (keys.length > 1000) keys.sort((a, b) => (map[a].savedAt || 0) - (map[b].savedAt || 0)).slice(0, keys.length - 1000).forEach(k => delete map[k]);
  writeFileAtomic(RECEIPT_SNAP_FILE, JSON.stringify(map));
  res.json({ success: true });
});
app.get('/api/receipt-snapshot', (req, res) => {
  const hit = _readSnaps()[String(req.query.key || '')];
  if (!hit || !snapVisible(req, hit)) return res.json({ success: false, error: 'No saved document for this reference' });
  res.json({ success: true, query: hit.query });
});

// Reprint marking (URS 9.10): how many times each document was printed, kept on
// the relay so a reprint on ANY computer is marked COPY. Keyed by business + FDN
// (or the reference for an unfiscalised document). Only the Print action counts.
const PRINT_COUNT_FILE = path.join(DATA_DIR, 'print_counts.json');
function _readPrints() { try { return JSON.parse(fs.readFileSync(PRINT_COUNT_FILE, 'utf8')) || {}; } catch (e) { return {}; } }
// The business the count belongs to: the one named by X-Tenant-Id, else the
// caller's only business. Owners/service with no business use the shared bucket.
function printTenant(req) {
  const tid = reqTenant(req); if (tid) return { tid };
  const u = req.auth;
  if (u && (u.owner || u.service)) return { tid: '' };
  const ids = tenantIdsFor(u);
  return ids.length === 1 ? { tid: ids[0] } : { error: 'Choose a business first' };
}
function printKey(req, raw) {
  const key = String(raw || '').trim().slice(0, 120);
  if (!key) return { error: 'key required' };
  const t = printTenant(req); if (t.error) return t;
  return { id: t.tid + '|' + key, key, tid: t.tid };
}
function printView(e) {
  return { count: e ? e.count || 0 : 0, firstAt: e ? e.firstAt : null, lastAt: e ? e.lastAt : null, firstBy: e ? e.firstBy || '' : '', lastBy: e ? e.lastBy || '' : '' };
}
app.get('/api/print-count', (req, res) => {
  const k = printKey(req, req.query.key);
  if (k.error) return res.status(400).json({ success: false, error: k.error });
  res.json({ success: true, key: k.key, ...printView(_readPrints()[k.id]) });
});
app.post('/api/print-count', (req, res) => {
  const k = printKey(req, (req.body || {}).key);
  if (k.error) return res.status(400).json({ success: false, error: k.error });
  const map = _readPrints(), now = new Date().toISOString(), who = actor(req).userName || '';
  const e = map[k.id] || { tenantId: k.tid || undefined, key: k.key, count: 0, firstAt: now, firstBy: who };
  e.count = (e.count || 0) + 1; e.lastAt = now; e.lastBy = who;
  if ((req.body || {}).ref) e.ref = String(req.body.ref).slice(0, 80);
  map[k.id] = e;
  // Keep the most recent 5000 documents.
  const ids = Object.keys(map);
  if (ids.length > 5000) ids.sort((a, b) => String(map[a].lastAt).localeCompare(String(map[b].lastAt))).slice(0, ids.length - 5000).forEach(i => delete map[i]);
  writeFileAtomic(PRINT_COUNT_FILE, JSON.stringify(map));
  res.json({ success: true, key: k.key, ...printView(e) });
});

app.get('/api/submission-log', (req, res) => {
  try {
    let log = [];
    try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(e) {}
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 1000);
    const q = (req.query.q || '').toLowerCase();
    const view = logView(req);
    // Credit/debit notes only for users with the credit permission in that
    // entry's business (not cashiers).
    const notes = e => auth.can(view.perms(e), 'credit');
    log = log.filter(e => view.sees(e) && ((e.kind !== 'credit-note' && e.kind !== 'debit-note') || notes(e))).map(markUnlinked);
    const has = v => String(v || '').toLowerCase().includes(q);
    const filtered = q ? log.filter(e =>
      has(e.fdn) || has(e.invoiceId) || has(e.reference) || has(e.customerName) ||
      has(e.originalFdn) || has(e.oriInvoiceNo) || has(e.applicationId)
    ) : log;
    const total = filtered.length;
    const items = filtered.slice((page - 1) * limit, page * limit);
    res.json({ success: true, total, page, limit, items });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Log a Manager-only (non-fiscal) receipt so it shows in Documents tagged
// "Manager only". Kept in the same store with a managerOnly flag + status that
// keeps it out of the Z-report (which counts only fiscalised sales).
app.post('/api/manager-only-log', (req, res) => {
  const b = req.body || {};
  try {
    const ref = String(b.reference || '').trim();
    let deduped = false;
    updateSubmissionLog(log => {
    if (ref && log.some(e => e.managerOnly && String(e.reference || '').trim() === ref)) { deduped = true; return false; }
    log.unshift({
      id: crypto.randomUUID(), managerOnly: true, status: 'manager-only', fdn: '', tenantId: reqTenant(req) || undefined, ...actor(req),
      reference: b.reference || '', customerName: b.customerName || '',
      totalAmount: b.totalAmount || 0, currency: b.currency || 'UGX',
      invoiceKind: '3', mode: b.mode || '', docKey: b.docKey || '',
      submittedAt: b.submittedAt || new Date().toISOString()
    });
    });
    res.json(deduped ? { success: true, deduped: true } : { success: true });
  } catch(e) { res.json({ success: false, error: e.message }); }
});

// Z daily report (URS §9.17) - end-of-day summary of a full day's fiscalised
// sales (00:00:00-23:59:59) built from the submission log: document count, and
// gross/tax/net totals by currency. `date` = YYYY-MM-DD (defaults to today).
app.get('/api/z-report', (req, res) => {
  try {
    const date = (req.query.date || new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10)).slice(0, 10);   // today in Uganda time
    let log = []; try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(_) {}
    const view = scopedView(req, 'reports');
    // The business day is Uganda time (EAT, UTC+3): a document fiscalised at 01:00
    // belongs to that day, not to the previous UTC date.
    const eatDay = iso => { const t = Date.parse(iso || ''); return isNaN(t) ? String(iso || '').slice(0, 10) : new Date(t + 3 * 3600000).toISOString().slice(0, 10); };
    // Cancelled, rejected or withdrawn credit notes never took effect: leave them out.
    const lapsed = e => e.cancelled || (e.kind === 'credit-note' && (e.approveStatus === '103' || e.approveStatus === '104'));
    const day = log.filter(view.sees).filter(e => eatDay(e.submittedAt) === date && (e.status ? e.status === 'success' : true) && !lapsed(e));
    const byCurrency = {};
    let count = 0, credits = 0;
    for (const e of day) {
      const cur = e.currency || 'UGX';
      const amt = parseFloat(e.totalAmount) || 0;
      const isCredit = amt < 0 || e.kind === 'credit-note' || String(e.returnCode) === 'CN' || /credit/i.test(e.docType || '');
      const b = byCurrency[cur] || (byCurrency[cur] = { currency: cur, count: 0, gross: 0 });
      b.count++; b.gross += amt; count++; if (isCredit) credits++;
    }
    Object.values(byCurrency).forEach(b => { b.gross = Math.round(b.gross * 100) / 100; });
    res.json({ success: true, date, count, credits,
      totals: Object.values(byCurrency),
      documents: day.map(e => ({ fdn: e.fdn, reference: e.reference, customer: e.customerName, amount: e.totalAmount, currency: e.currency, at: e.submittedAt, kind: e.invoiceKind })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// Look up a previously-submitted document by FDN (from our local log) so the
// independent Credit Note tab can resolve the original's EFRIS invoiceId + reference.
app.get('/api/submission-log/by-fdn/:fdn', (req, res) => {
  try {
    let log = [];
    try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(e) {}
    const fdn = String(req.params.fdn || '').trim();
    const view = logView(req);
    const hit = log.filter(e => view.sees(e) && ((e.kind !== 'credit-note' && e.kind !== 'debit-note') || auth.can(view.perms(e), 'credit')))
      .find(e => String(e.fdn || '').trim() === fdn);
    if (!hit) return res.json({ success: false, error: 'FDN not found in local submission history. Enter the original invoice ID manually if you have it.' });
    res.json({ success: true, fdn: hit.fdn, invoiceId: hit.invoiceId || '', reference: hit.reference || '', customerName: hit.customerName || '', amount: hit.totalAmount || 0, currency: hit.currency || 'UGX',
      buyerTin: hit.buyerTin || '', buyerType: hit.buyerType || '', lines: Array.isArray(hit.lines) ? hit.lines : [],
      antifakeCode: hit.antifakeCode || '', validationUrl: hit.validationUrl || '', submittedAt: hit.submittedAt || '', deviceNo: hit.deviceNo || '' });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Add documents URA has (from its T106 report) that are missing from the local
// history - e.g. submitted before the history recorded them, or from another PC -
// so Documents and the Z report match URA. Never overwrites an existing FDN.
app.post('/api/submission-log/import', async (req, res) => {
  const recs = Array.isArray((req.body || {}).records) ? req.body.records.slice(0, 200) : [];
  const { tin, deviceNo, mode } = req.body || {};
  if (!recs.length) return res.json({ success: true, added: 0 });
  let added = 0, _refreshed = 0;
  try { updateSubmissionLog(log => {
  const have = new Set(log.map(e => String(e.fdn || '').trim()).filter(Boolean));
  const tid = reqTenant(req);
  // URA dates arrive as dd/MM/yyyy HH:mm:ss (or epoch ms).
  const when = r => {
    // Prefer whichever of URA's date fields carries the time of day.
    const cands = [r.issuedDate, r.issuedDateStr, r.invoiceDate].map(x => String(x == null ? '' : x).trim()).filter(Boolean);
    const v = cands.find(x => /\d{1,2}:\d{2}/.test(x)) || cands.find(x => /^\d{12,}$/.test(x)) || cands[0] || '';
    if (/^\d{12,}$/.test(String(v))) return new Date(+v).toISOString();
    const m = String(v).match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?/);
    if (m) return new Date(Date.UTC(+m[3], +m[2] - 1, +m[1], (+m[4] || 0) - 3, +m[5] || 0, +m[6] || 0)).toISOString();   // EAT is UTC+3
    const d = new Date(v); return isNaN(d) ? new Date().toISOString() : d.toISOString();
  };
  const cur = c => (/^\d+$/.test(String(c || '')) ? (String(c) === '101' ? 'UGX' : String(c)) : (c || 'UGX'));
  recs.forEach((r, i) => {
    const fdn = String(r.invoiceNo || r.fdn || '').trim();
    if (!/^\d{6,}$/.test(fdn)) return;
    // Already there: only an entry that itself came from URA gets its time refreshed.
    if (have.has(fdn)) { const ex = log.find(e => String(e.fdn) === fdn && e.importedFromUra); if (ex) { const t = when(r); if (t !== ex.submittedAt) { ex.submittedAt = t; _refreshed++; } } return; }
    have.add(fdn); added++;
    log.push({ id: crypto.randomUUID(), submittedAt: when(r), fdn, antifakeCode: r.antifakeCode || '', validationUrl: '', tenantId: tid || undefined, ...actor(req),
      deviceNo: r.deviceNo || deviceNo || '', invoiceId: String(r.id || r.invoiceId || ''), reference: r.referenceNo || '',
      returnCode: '00', status: 'success', tin: tin || r.sellerTin || '', customerName: r.buyerLegalName || r.buyerBusinessName || '',
      totalAmount: parseFloat(r.grossAmount) || 0, currency: cur(r.currency), invoiceKind: r.invoiceKind || '', mode: mode || 'sandbox',
      importedFromUra: true });
  });
  if (!added && !_refreshed) return false;
  log.sort((a, b) => String(b.submittedAt || '').localeCompare(String(a.submittedAt || '')));
  }); } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
  if (added || _refreshed) console.log('   Submission history: added ' + added + ' document(s) from URA');
  res.json({ success: true, added });
});

// Link an older, untagged entry to the requesting business, so it stops showing
// in other businesses that share the TIN. Only untagged entries this business
// can already see can be linked.
app.post('/api/submission-log/:id/link', (req, res) => {
  try {
    const view = tenantView(req);
    if (!view.tid) return res.status(400).json({ success: false, error: 'No business selected' });
    // Ids are numbers (older rows) or UUID strings: compare as text.
    const id = String(req.params.id);
    let found = false;
    updateSubmissionLog(log => {
      const e = log.find(x => String(x.id) === id);
      if (!e || e.tenantId || !view.sees(e)) return false;
      e.tenantId = view.tid; found = true;
    });
    if (!found) return res.json({ success: false, error: 'Entry not found or already linked' });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

app.delete('/api/submission-log/:id', (req, res) => {
  try {
    const id = String(req.params.id);
    const view = scopedView(req, 'log-all');
    updateSubmissionLog(log => log.filter(e => !(String(e.id) === id && view.sees(e))));
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  Offline queue (Phase 1: queue-and-retry)
// ══════════════════════════════════════════════════════════════
// When URA is unreachable, the T109 submission is queued here (payload + public
// config only - NEVER the EFRIS password or Manager token). The extension flushes
// the queue when connectivity returns, supplying the secrets at that moment.
const OFFLINE_QUEUE_FILE = path.join(DATA_DIR, 'offline_queue.json');
function publicCfg(config) {
  const c = config || {};
  return { tin: c.tin, deviceNo: c.deviceNo, mode: c.mode || 'sandbox',
    businessName: c.businessName, tradeName: c.tradeName, businessAddress: c.businessAddress,
    brn: c.brn, phone: c.phone, email: c.email, vatRegistered: !!c.vatRegistered,
    // Non-secret fields buildT109 also reads (default commodity, unit, operator).
    defaultCommodityCode: c.defaultCommodityCode, defaultCommodityName: c.defaultCommodityName,
    defaultUnitOfMeasure: c.defaultUnitOfMeasure, issuedBy: c.issuedBy, operator: c.operator };
}
function loadQueue() { try { return JSON.parse(fs.readFileSync(OFFLINE_QUEUE_FILE, 'utf8')); } catch(e) { return []; } }
function saveQueue(q) { try { writeFileAtomic(OFFLINE_QUEUE_FILE, JSON.stringify(q, null, 2)); } catch(e) { console.log('offline queue write error: ' + e.message); } }
function offlineEnqueue(entry) {
  const q = loadQueue();
  const id = 'off_' + crypto.randomUUID();
  const createdAt = new Date().toISOString();
  q.push({ id, createdAt, saleAt: createdAt, status: 'pending', attempts: 0, lastError: '', ...actor(), ...entry });
  saveQueue(q);
  return id;
}

// Queue entries are per business, like the submission log.
// perm: what the caller needs in the entry's business ('queue' to see or link, 'log-all' to delete).
function queueView(req, perm) { const v = scopedView(req, perm || 'queue'); return e => v.sees({ tenantId: e.tenantId, tin: (e.cfgPublic || {}).tin, userId: e.userId }); }
app.get('/api/offline-queue', (req, res) => {
  const q = loadQueue().filter(queueView(req));
  res.json({ success: true, pending: q.filter(e => e.status === 'pending').length, failed: q.filter(e => e.status === 'failed').length,
    items: q.map(e => ({ id: e.id, createdAt: e.createdAt, saleAt: e.saleAt || e.createdAt, kind: e.kind, reference: e.reference, status: e.status, attempts: e.attempts, lastError: e.lastError, fdn: e.fdn || '', uncertain: !!e.uncertain,
      doneAt: e.doneAt || '', result: e.status === 'done' ? (e.result || { fdn: e.fdn }) : undefined, inManager: !!e.mgrWritten })),
    retry: (typeof _retry !== 'undefined') ? { nextAt: _retry.nextAt, lastAt: _retry.lastAt, lastOutcome: _retry.lastOutcome, online: _retry.online, now: Date.now() } : null });
});

// Attach the Manager document created for a queued sale, so the FDN is written
// onto it when the queue fiscalises it (the wizard creates the Manager receipt
// straight away: Manager is local and reachable while URA is not).
app.post('/api/offline-queue/:id/link', (req, res) => {
  const { documentKey, managerEndpoint } = req.body || {};
  if (!documentKey || !managerEndpoint) return res.status(400).json({ success: false, error: 'documentKey and managerEndpoint required' });
  const q = loadQueue(); const e = q.find(x => x.id === req.params.id);
  if (!e || !queueView(req)(e)) return res.json({ success: false, error: 'not found' });
  if (!e.documentKey) { e.documentKey = bareKey(documentKey); e.managerEndpoint = managerEndpoint; saveQueue(q); }
  res.json({ success: true, status: e.status, fdn: e.fdn || '' });
});

app.delete('/api/offline-queue/:id', (req, res) => {
  const sees = queueView(req, 'log-all');
  const q = loadQueue().filter(e => !(e.id === req.params.id && sees(e)));
  saveQueue(q);
  res.json({ success: true });
});

// Flush the queue: re-submit each pending item to EFRIS using the secrets supplied
// now (efrisPassword + Manager accessToken). Successful items get an FDN, are
// written back to the source Manager document, and removed from the queue.
// Re-submit pending queue entries. credsFor(entry) supplies the secrets for that
// entry ({ cfg, accessToken }) or null to skip it. Shared by the Flush button and
// the automatic retry below. Stops at the first network error (still offline).
let _flushing = false;
// Fields the flush owns. Only these are merged back into the queue file, so a
// /link (documentKey, managerEndpoint) made while a flush was running survives.
const FLUSH_FIELDS = ['status', 'fdn', 'result', 'attempts', 'lastError', 'doneAt', 'mgrWritten', 'mgrAttempts', 'uncertain', 'uncertainVia'];
// Fiscalised, linked to a Manager document, but the FDN is not on it yet.
function needsWriteBack(e) { return e.status === 'done' && !!e.documentKey && !!e.managerEndpoint && !e.mgrWritten && (e.mgrAttempts || 0) < 5; }
// Write the FDN onto the source Manager document. mgrWritten is set only when
// Manager accepted it; a failure is retried on later passes (max 5 tries).
// ep: where to write. A token from the vault only ever goes to the business's
// saved endpoint, never to the endpoint stored on the queue entry by a caller.
async function offlineWriteBack(entry, accessToken, vatRegistered, data, ep) {
  if (!ep) return;
  entry.mgrAttempts = (entry.mgrAttempts || 0) + 1;
  try {
    const w = await saveEfrisToManager(normEp(ep), accessToken, bareKey(entry.documentKey), data, vatRegistered);
    if (w && w.success) entry.mgrWritten = true;
    else console.log('offline write-back error: ' + ((w && w.error) || 'Manager did not accept the update'));
  } catch (e) { console.log('offline write-back error: ' + e.message); }
}
// A sale whose T109 timed out AFTER it was sent may already be fiscalised. Ask
// EFRIS (T106 invoice query, by reference) before sending it again, so it never
// gets a second FDN. Returns a submission-like result when found, null when EFRIS
// has no such document; throws when it cannot tell (network error: still offline).
async function findIssuedByReference(entry, cfg, ref) {
  const targets = efrisEndpoints(cfg);
  const t = targets.find(x => x.kind === (entry.uncertainVia || 'ura')) || targets[0];
  const qc = cfgForTarget(cfg, t);
  const session = await getSession(qc.tin, qc.deviceNo, qc.efrisPassword, t.url, keyOverrideFrom(qc));
  if (!session.aesKey) throw new Error('No AES key for T106');
  const t106data = {
    oriInvoiceNo: '', invoiceNo: '', deviceNo: qc.deviceNo || '',
    buyerTin: '', buyerLegalName: '', buyerNinBrn: '',
    combineKeywords: '', invoiceType: '', invoiceKind: '', isInvalid: '', isRefund: '',
    startDate: eatParts(Date.parse(entry.saleAt || entry.createdAt) || Date.now()).date, endDate: eatToday(),
    pageNo: '1', pageSize: '20',
    referenceNo: ref, branchName: '', queryType: '1',
    dataSource: '', sellerTinOrNin: qc.tin, currencyType: '', invoiceIndustryCode: '',
  };
  const t106 = await efrisSecure(t.url, 'T106', t106data, qc.tin, qc.deviceNo, session);
  const rc = t106.data && t106.data.returnStateInfo ? t106.data.returnStateInfo.returnCode : null;
  const rm = t106.data && t106.data.returnStateInfo ? t106.data.returnStateInfo.returnMessage : '';
  let records = null;
  if (t106.data && t106.data.data && t106.data.data.content) {
    try {
      const d = JSON.parse(efrisDecodeJson(t106.data.data.content, session.aesKey) || aesDecryptStr(t106.data.data.content, session.aesKey));
      records = d.records || d.invoiceList || d.list || (Array.isArray(d) ? d : []);
    } catch (e) { console.log('   T106 parse error:', e.message); }
  } else if (rc === '00') records = [];
  if (!records) throw new Error('Could not check EFRIS for reference ' + ref + ' (T106 ' + rc + ': ' + rm + '); not sending it again until EFRIS can be checked');
  const hit = records.find(r => String(r.referenceNo || '').trim() === ref && String(r.invoiceNo || '').trim());
  if (!hit) return null;
  const fdn = String(hit.invoiceNo).trim();
  const antifakeCode = hit.antifakeCode || hit.antiFakeCode || '';
  const efrisPortal = cfg.mode === 'production'
    ? 'https://efris.ura.go.ug/site_mobile/#/invoiceValidation'
    : 'https://efristest.ura.go.ug/site_new/#/invoiceValidation';
  const validationUrl = antifakeCode ? `${efrisPortal}?invoiceNo=${encodeURIComponent(fdn)}&antiFakeCode=${encodeURIComponent(antifakeCode)}` : null;
  const issuedDate = entry.saleAt || entry.createdAt || new Date().toISOString();
  const invoiceId = String(hit.id || hit.invoiceId || '');
  console.log(`   Offline queue: ${ref} was already fiscalised (FDN ${fdn}) - not resending`);
  try {
    // The timed-out submission never reached the log; record it now.
    appendSubmissionLog({
      id: crypto.randomUUID(), submittedAt: issuedDate, fdn, antifakeCode, validationUrl, tenantId: entry.tenantId || undefined,
      userId: entry.userId || undefined, userName: entry.userName || undefined,
      deviceNo: hit.deviceNo || qc.deviceNo, invoiceId, reference: ref, returnCode: '00', status: 'success', tin: cfg.tin,
      customerName: hit.buyerLegalName || hit.buyerBusinessName || '', totalAmount: parseFloat(hit.grossAmount) || 0,
      currency: (entry.invoice && entry.invoice.Currency) || 'UGX', invoiceKind: hit.invoiceKind || '', mode: cfg.mode || 'sandbox',
    });
  } catch (le) { console.log('Submission log write error:', le.message); }
  return { ok: true, fdn, qrCode: validationUrl || antifakeCode, antifakeCode, validationUrl, deviceNo: hit.deviceNo || qc.deviceNo, issuedDate, invoiceId, returnCode: '00', returnMessage: 'Found in EFRIS' };
}
// One queue entry: send it (or retry its Manager write-back). Returns true when
// URA is unreachable, so the caller stops and keeps the rest queued.
async function flushOne(entry, credsFor, results) {
  const creds = credsFor(entry); if (!creds) return false;
  const cfg = { ...entry.cfgPublic, ...creds.cfg };
  const wbEp = creds.fromVault ? (creds.managerEndpoint || '') : entry.managerEndpoint;
  // Fiscalised on an earlier pass, but the FDN did not reach Manager: retry that only.
  if (entry.status === 'done') {
    if (creds.accessToken) await offlineWriteBack(entry, creds.accessToken, cfg.vatRegistered, entry.result || { fdn: entry.fdn }, wbEp);
    return false;
  }
  if (!cfg.efrisPassword) return false;
  entry.attempts = (entry.attempts || 0) + 1;
  // Dated when the sale was made, not when it is finally sent.
  const saleAt = entry.saleAt || entry.createdAt;
  const invoice = saleAt ? { ...entry.invoice, _saleAt: saleAt } : entry.invoice;
  const ref = String(((entry.invoice || {}).IsRefund || (entry.invoice || {}).isRefund ? 'CN-' : '') + ((entry.invoice || {}).Reference || '')).trim();
  try {
    let r = null, netErr = null;
    if (entry.uncertain) {
      if (!ref) {
        entry.status = 'failed';
        entry.lastError = 'EFRIS did not answer in time and this sale has no reference to check it by. Check EFRIS for it before submitting it again.';
        results.push({ id: entry.id, tenantId: entry.tenantId || '', reference: entry.reference, ok: false, error: entry.lastError });
        return false;
      }
      r = await findIssuedByReference(entry, cfg, ref);
    }
    if (!r) for (const t of efrisEndpoints(cfg)) {
      try { r = await performInvoiceSubmission(invoice, cfgForTarget({ ...cfg, _tenantId: entry.tenantId || '', _userId: entry.userId || '', _userName: entry.userName || '' }, t), t.url); netErr = null; break; }
      catch (te) {
        // Sent but no answer: outcome unknown. Do not try the next target (that
        // could fiscalise it twice); check EFRIS by reference on the next pass.
        if (te.uncertain) { entry.uncertain = true; entry.uncertainVia = t.kind; netErr = te; break; }
        if (isNetworkError(te)) { netErr = te; continue; } throw te;
      }
    }
    if (!r && netErr) throw netErr;
    if (r.ok) {
      entry.status = 'done'; entry.fdn = r.fdn; entry.doneAt = new Date().toISOString(); entry.uncertain = false; entry.lastError = '';
      // Kept for a day so the extension can tell the cashier and print it.
      entry.result = { fdn: r.fdn, antifakeCode: r.antifakeCode, validationUrl: r.validationUrl, qrCode: r.qrCode, invoiceId: r.invoiceId, deviceNo: r.deviceNo, issuedDate: r.issuedDate };
      // Write-back to the source Manager document (retried later if it fails).
      if (entry.documentKey && entry.managerEndpoint && creds.accessToken) await offlineWriteBack(entry, creds.accessToken, cfg.vatRegistered, r, wbEp);
      results.push({ id: entry.id, tenantId: entry.tenantId || '', reference: entry.reference, ok: true, fdn: r.fdn });
    } else {
      // URA rejected it (a business error, not a connection problem): resending
      // the same document cannot succeed, so stop retrying. It stays listed
      // (status failed) until the cashier fixes and resubmits or deletes it.
      entry.status = 'failed'; entry.uncertain = false;
      entry.lastError = 'URA ' + r.returnCode + ': ' + r.returnMessage;
      results.push({ id: entry.id, tenantId: entry.tenantId || '', reference: entry.reference, ok: false, error: entry.lastError });
    }
  } catch (e) {
    entry.lastError = e.message;
    results.push({ id: entry.id, tenantId: entry.tenantId || '', reference: entry.reference, ok: false, error: e.message, network: isNetworkError(e) });
    if (isNetworkError(e)) return true; // still offline - stop, keep the rest queued
  }
  return false;
}
async function flushOfflineQueue(credsFor) {
  if (_flushing) return { busy: true, results: [] };
  _flushing = true;
  const results = [];
  try {
    const q = loadQueue();
    // Each entry runs under its own business, so the lines it prints (activity
    // log) are tagged with that business, not with whoever pressed Try now.
    const base = reqCtx.getStore();
    const user = (base && base.user) || null;
    for (const entry of q.filter(e => e.status === 'pending' || needsWriteBack(e))) {
      const stop = await reqCtx.run({ user, tenantId: entry.tenantId || '' }, () => flushOne(entry, credsFor, results));
      if (stop) break;
    }
    // Persist: reload the queue (it may have changed while we were waiting on
    // EFRIS) and merge only the fields the flush owns; completed entries stay for
    // a day (see above).
    const dayAgo = Date.now() - 86400000;
    const fresh = loadQueue();
    for (const e of fresh) {
      const u = q.find(x => x.id === e.id); if (!u) continue;
      for (const k of FLUSH_FIELDS) if (k in u) e[k] = u[k];
    }
    saveQueue(fresh.filter(e => e.status !== 'done' || Date.parse(e.doneAt || 0) > dayAgo));
  } finally { _flushing = false; }
  return { results };
}

// Flush button: secrets supplied now by the extension (efrisPassword + Manager token).
app.post('/api/offline-queue/flush', rateLimit(20), async (req, res) => {
  const { config, accessToken } = req.body || {};
  // Only this caller's business: never send another business's queued sales with
  // this caller's EFRIS credentials.
  const tid = reqTenant(req);
  const mine = e => !!config && String((e.cfgPublic || {}).tin || '') === String(config.tin || '') && String(e.tenantId || '') === tid;
  const pending = loadQueue().filter(e => (e.status === 'pending' || needsWriteBack(e)) && mine(e));
  if (!pending.length) return res.json({ success: true, processed: 0, results: [] });
  if (!config || !config.efrisPassword) return res.status(400).json({ success: false, error: 'EFRIS password required to flush the offline queue' });
  const extra = { efrisPassword: config.efrisPassword, enablerUrl: config.enablerUrl, enablerMode: config.enablerMode, efrisKeyPath: config.efrisKeyPath, efrisKeyPem: config.efrisKeyPem, efrisKeyPassphrase: config.efrisKeyPassphrase };
  // A token filled from the vault goes only to the business's saved endpoint.
  const out = await flushOfflineQueue(e => (mine(e) ? { cfg: extra, accessToken, fromVault: !!req.vaultFilled, managerEndpoint: req.vaultEndpoint || '' } : null));
  if (out.busy) return res.json({ success: true, processed: 0, results: [], busy: true, remaining: pending.length });
  res.json({ success: true, processed: out.results.length, results: out.results, remaining: loadQueue().filter(e => e.status === 'pending' && mine(e)).length });
});

// Automatic retry: every 3 minutes, re-submit queued documents using each
// business's credentials from the vault, so a document queued while URA was
// unreachable gets its FDN once the connection is back, without anyone pressing
// Flush. Entries with no saved credentials wait for the Flush button.
function offlineCredsFromVault(entry) {
  if (!entry.tenantId) return null;
  let t = null; try { t = vault.getTenant(entry.tenantId); } catch (_) { return null; }
  if (!t || !t.efrisPassword) return null;
  return { cfg: { efrisPassword: t.efrisPassword, efrisKeyPem: t.efrisPrivateKeyPem || '', efrisKeyPath: t.efrisPrivateKeyPath || '', efrisKeyPassphrase: t.efrisPassphrase || '',
                  enablerUrl: t.enablerUrl, enablerMode: t.enablerMode, enablerDeviceNo: t.enablerDeviceNo }, accessToken: t.managerToken || '',
           fromVault: true, managerEndpoint: t.managerEndpoint || '' };
}
// Schedule: a full retry every 3 minutes, plus a quick check every 30 seconds
// that URA answers at all, so a sale goes out within ~30s of the connection
// returning. The queue is a file in DATA_DIR, so it survives the relay being
// closed: the first retry runs about a minute after the relay starts (once the
// vault has unlocked).
const RETRY_EVERY = 3 * 60000;
const _retry = { nextAt: Date.now() + 60000, lastAt: 0, lastOutcome: '', online: null };
async function autoRetryQueue(why) {
  const pend = loadQueue().filter(e => (e.status === 'pending' || needsWriteBack(e)) && e.tenantId);
  if (!pend.length) { _retry.nextAt = Date.now() + RETRY_EVERY; return { results: [], processed: 0 }; }
  _retry.lastAt = Date.now();
  const out = await flushOfflineQueue(offlineCredsFromVault);
  if (out.busy) return out;
  _retry.nextAt = Date.now() + RETRY_EVERY;
  const ok = (out.results || []).filter(r => r.ok);
  const net = (out.results || []).some(r => r.network);
  // Summary lines go out per business (tagged with it); the connection line is
  // about the relay, not any one business.
  const base = reqCtx.getStore();
  const user = (base && base.user) || null;
  if (ok.length) {
    _retry.lastOutcome = 'sent'; _retry.online = true;
    const byTenant = new Map();
    for (const r of ok) { const t = r.tenantId || ''; if (!byTenant.has(t)) byTenant.set(t, []); byTenant.get(t).push(r); }
    for (const [t, list] of byTenant) reqCtx.run({ user, tenantId: t }, () => console.log('   Offline queue: ' + list.length + ' queued document(s) fiscalised automatically' + (why ? ' (' + why + ')' : '') + ': ' + list.map(r => r.reference + ' FDN ' + r.fdn).join(', ')));
  }
  else if (net) { _retry.lastOutcome = 'offline'; _retry.online = false; reqCtx.run({ user, tenantId: '' }, () => console.log('   Offline queue: URA still unreachable, will retry in 3 minutes')); }
  else if (!(out.results || []).length) _retry.lastOutcome = 'no-credentials';
  else _retry.lastOutcome = 'error';
  return out;
}
setInterval(async () => {
  try {
    const work = loadQueue().filter(e => (e.status === 'pending' || needsWriteBack(e)) && e.tenantId);
    if (!work.length) return;
    if (Date.now() >= _retry.nextAt) { await autoRetryQueue(''); return; }
    const pend = work.filter(e => e.status === 'pending');
    if (!pend.length) return;
    const mode = ((pend[0].cfgPublic || {}).mode === 'production') ? 'production' : 'sandbox';
    const up = await pingUrl(uraHost(mode), 3500);
    const was = _retry.online; _retry.online = up;
    if (up && was === false) { console.log('   Offline queue: URA is reachable again - sending ' + pend.length + ' queued document(s) now'); await autoRetryQueue('back online'); }
  } catch (e) { console.log('   Offline queue auto-retry error: ' + e.message); }
}, 30000).unref();

app.post('/api/offline-queue/retry-now', rateLimit(20), async (req, res) => {
  try {
    const out = await autoRetryQueue('Try now');
    if (out.busy) return res.json({ success: true, busy: true });
    const results = out.results || [];
    res.json({ success: true, sent: results.filter(r => r.ok).length, offline: results.some(r => r.network), processed: results.length,
      pending: loadQueue().filter(queueView(req)).filter(e => e.status === 'pending').length });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  Document Number Series
// ══════════════════════════════════════════════════════════════
const NUM_SERIES_FILE = path.join(DATA_DIR, 'number_series.json');

function loadSeries() {
  try { return JSON.parse(fs.readFileSync(NUM_SERIES_FILE, 'utf8')); }
  catch(e) { return []; }
}
function saveSeries(data) {
  fs.writeFileSync(NUM_SERIES_FILE, JSON.stringify(data, null, 2));
}

function buildNumber(s, counter) {
  const { year, month } = eatParts();   // Uganda time, whatever the server's zone
  const parts = [];
  for (const seg of (s.segments || [])) {
    if (seg === 'prefix'   && s.prefix)   parts.push(s.prefix);
    if (seg === 'division' && s.division) parts.push(s.division);
    if (seg === 'project'  && s.project)  parts.push(s.project);
    if (seg === 'year')    parts.push(year);
    if (seg === 'month')   parts.push(month);
    if (seg === 'counter') parts.push(String(counter).padStart(Math.min(Math.max(parseInt(s.digits, 10) || 4, 1), 12), '0'));
  }
  return parts.join(s.separator === 'none' ? '' : (s.separator || '-'));
}

function resolveNext(s) {
  const { year, month } = eatParts();
  const ym    = year + '-' + month;
  const startAt = parseInt(s.startAt) || 1;
  let counter = (s.lastCounter || 0) + 1;
  // When a reset period rolls over, restart at the series' starting number - NOT
  // hardcoded 1 (otherwise the configured start, e.g. 25, is ignored).
  if (s.resetOn === 'yearly'  && s.lastReset && s.lastReset !== year) counter = startAt;
  if (s.resetOn === 'monthly' && s.lastReset && s.lastReset !== ym)   counter = startAt;
  return counter;
}

// A series belongs to the business that created it (tenantId). Older series with
// no tenantId stay visible to owners and to admins of the requested business; an
// admin who edits one claims it for that business.
// perm: what the caller needs in the series' business ('sell' to use it, 'series' to change it).
function seriesVisible(req, s, perm) {
  const tid = reqTenant(req), user = req.auth;
  if (s.tenantId) {
    if (tid ? s.tenantId !== tid : !tenantIdsFor(user).includes(s.tenantId)) return false;
    return auth.can(auth.permissionsFor(user, s.tenantId), perm || 'sell');
  }
  if (user && (user.owner || user.service)) return true;
  return !!tid && auth.roleIn(user, tid) === 'admin';
}
function findSeries(req, series, perm) {
  const idx = series.findIndex(x => x.id === req.params.id);
  return idx >= 0 && seriesVisible(req, series[idx], perm) ? idx : -1;
}

// Next walk-in receipt number (PREFIX-YYMMDD-NNN) for the checked business, shared by
// every browser and till: one counter on the relay, never below the highest number
// already used today in the submission log or the offline queue.
const RECEIPT_COUNTER_FILE = path.join(DATA_DIR, 'receipt_counters.json');
app.post('/api/receipt-number/next', (req, res) => {
  const tid = reqTenant(req) || 'default';
  const prefix = String((req.body || {}).prefix || 'REC').replace(/[^A-Za-z0-9]/g, '').slice(0, 10) || 'REC';
  const ymd = String((req.body || {}).ymd || eatToday().slice(2).replace(/-/g, ''));
  if (!/^\d{6}$/.test(ymd)) return res.status(400).json({ success: false, error: 'ymd must be YYMMDD' });
  const key = tid + '|' + prefix + '|' + ymd;
  const rx = new RegExp('^' + prefix + '-' + ymd + '-(\\d+)$', 'i');
  let max = 0;
  const seen = ref => { const m = String(ref || '').match(rx); if (m) max = Math.max(max, parseInt(m[1], 10) || 0); };
  for (const e of readSubmissionLog()) if (!e.tenantId || e.tenantId === tid) seen(e.reference);
  try { for (const q of loadQueue()) seen(q && (q.reference || (q.invoice && q.invoice.Reference))); } catch (_) {}
  let counters = {};
  try { counters = JSON.parse(fs.readFileSync(RECEIPT_COUNTER_FILE, 'utf8')) || {}; } catch (_) {}
  const n = Math.max(max, parseInt(counters[key], 10) || 0) + 1;
  counters[key] = n;
  for (const k of Object.keys(counters)) if (!k.endsWith('|' + ymd) && k.split('|')[2] < ymd) delete counters[k];   // keep today only
  try { writeFileAtomic(RECEIPT_COUNTER_FILE, JSON.stringify(counters)); } catch (_) {}
  res.json({ success: true, number: prefix + '-' + ymd + '-' + String(n).padStart(3, '0') });
});

// Goods > My Items for the checked business, kept on the relay so every computer
// shows the same list (it used to live in one browser only). One file, keyed by
// business. updatedAt lets a browser tell whether its copy is the newer one.
const GOODS_CATALOG_FILE = path.join(DATA_DIR, 'goods_catalog.json');
const GOODS_CATALOG_MAX = 5000;
function readGoodsCatalogs() { try { return JSON.parse(fs.readFileSync(GOODS_CATALOG_FILE, 'utf8')) || {}; } catch (_) { return {}; } }
app.get('/api/goods-catalog', (req, res) => {
  const tid = reqTenant(req);
  if (!tid) return res.status(400).json({ success: false, error: 'Choose a business first' });
  const c = readGoodsCatalogs()[tid];
  res.json({ success: true, items: (c && Array.isArray(c.items)) ? c.items : [], updatedAt: (c && c.updatedAt) || '' });
});
app.put('/api/goods-catalog', (req, res) => {
  const tid = reqTenant(req);
  if (!tid) return res.status(400).json({ success: false, error: 'Choose a business first' });
  const b = req.body || {};
  if (!Array.isArray(b.items)) return res.status(400).json({ success: false, error: 'items must be a list' });
  if (b.items.length > GOODS_CATALOG_MAX) return res.status(400).json({ success: false, error: 'Too many items (most ' + GOODS_CATALOG_MAX + ')' });
  if (b.items.some(i => !i || typeof i !== 'object' || Array.isArray(i))) return res.status(400).json({ success: false, error: 'Each item must be an object' });
  const all = readGoodsCatalogs();
  // Saved on another computer since this browser loaded it: hand back the newer list.
  const cur = all[tid];
  if (b.baseUpdatedAt !== undefined && cur && cur.updatedAt && String(b.baseUpdatedAt) !== String(cur.updatedAt) && !b.force) {
    return res.status(409).json({ success: false, error: 'My Items was changed on another computer', items: cur.items || [], updatedAt: cur.updatedAt });
  }
  const updatedAt = new Date().toISOString();
  all[tid] = { items: b.items, updatedAt, by: (req.auth && (req.auth.displayName || req.auth.name)) || '' };
  try { writeFileAtomic(GOODS_CATALOG_FILE, JSON.stringify(all)); }
  catch (e) { return res.status(500).json({ success: false, error: 'Could not save My Items: ' + e.message }); }
  res.json({ success: true, updatedAt, count: b.items.length });
});

app.get('/api/number-series', (req, res) => {
  const series = loadSeries().filter(s => seriesVisible(req, s));
  res.json(series.map(s => ({
    ...s,
    preview: buildNumber(s, resolveNext(s))
  })));
});

app.post('/api/number-series', (req, res) => {
  const series = loadSeries();
  const { year, month } = eatParts();
  const ym   = year + '-' + month;
  // Initialise lastReset to the CURRENT period so the reset rule doesn't fire on the
  // very first number and wipe out the configured starting number.
  const lastReset = req.body.resetOn === 'monthly' ? ym : (req.body.resetOn === 'yearly' ? year : '');
  const startAt = parseInt(req.body.startAt) || 1;
  const s = { ...req.body, id: crypto.randomUUID(), startAt, lastCounter: startAt - 1, lastReset, tenantId: reqTenant(req) || undefined };
  series.push(s);
  saveSeries(series);
  res.json({ success: true, series: { ...s, preview: buildNumber(s, resolveNext(s)) } });
});

app.put('/api/number-series/:id', (req, res) => {
  const series = loadSeries();
  const idx = findSeries(req, series, 'series');
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  const old = series[idx];
  series[idx] = { ...old, ...req.body, id: req.params.id, lastCounter: old.lastCounter, lastReset: old.lastReset, tenantId: old.tenantId || reqTenant(req) || undefined };
  saveSeries(series);
  res.json({ success: true, series: { ...series[idx], preview: buildNumber(series[idx], resolveNext(series[idx])) } });
});

app.delete('/api/number-series/:id', (req, res) => {
  const series = loadSeries();
  const idx = findSeries(req, series, 'series');
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  series.splice(idx, 1);
  saveSeries(series);
  res.json({ success: true });
});

app.post('/api/number-series/:id/preview', (req, res) => {
  const series = loadSeries();
  const idx = findSeries(req, series);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  const s = series[idx];
  res.json({ success: true, number: buildNumber(s, resolveNext(s)) });
});

app.post('/api/number-series/:id/next', (req, res) => {
  const series = loadSeries();
  const idx = findSeries(req, series);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  const s = series[idx];
  const { year, month } = eatParts();   // Uganda time
  const ym   = year + '-' + month;
  const counter = resolveNext(s);
  const number = buildNumber(s, counter);
  series[idx].lastCounter = counter;
  series[idx].lastReset   = s.resetOn === 'monthly' ? ym : year;
  saveSeries(series);
  res.json({ success: true, number });
});

// ══════════════════════════════════════════════════════════════
//  Credential vault - per-tenant (per-business) secrets
// ══════════════════════════════════════════════════════════════
// Tenancy = a Manager business profile (its TIN + EFRIS device key). The caller's
// Manager token is their identity/authorization; before storing creds for a
// tenant we verify the token can actually reach that Manager business, so a user
// can only write creds for a business they have permission to.
async function verifyManagerAccess(managerEndpoint, accessToken) {
  if (!managerEndpoint || !accessToken) return false;
  try {
    const r = await managerCall(normEp(managerEndpoint), accessToken, 'GET', '/sales-invoices?pageSize=1', null);
    return r.status === 200 && !r._html;
  } catch (e) { return false; }
}

// ── Business setup (profile) ──
// Everything the extension saves for a business except its secrets. Secret-looking
// keys and private keys are dropped at any depth (the vault keeps the real ones);
// placeholders are dropped too and put back from the vault on the way out.
const PROFILE_MAX = 3 * 1024 * 1024;
const PROFILE_SECRET_KEY = /^(efrisPassword|efrisKeyPem|efrisKeyPassphrase|accessToken|apiAccessToken|managerToken|efrisPrivateKeyPem|efrisPassphrase|token|tk)$|password|passphrase|secret|privatekey/i;
const BAD_KEY = new Set(['__proto__', 'constructor', 'prototype']);
function stripProfile(v, depth) {
  if (depth > 8) return undefined;
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return v;
  if (typeof v === 'string') return (v === VAULT_PLACEHOLDER || /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(v)) ? undefined : v;
  if (Array.isArray(v)) return v.slice(0, 5000).map(x => { const c = stripProfile(x, depth + 1); return c === undefined ? null : c; });
  if (typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v)) {
      if (BAD_KEY.has(k) || PROFILE_SECRET_KEY.test(k)) continue;
      const c = stripProfile(v[k], depth + 1);
      if (c !== undefined) o[k] = c;
    }
    return o;
  }
  return undefined;
}
function cleanProfile(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) return null;
  const o = stripProfile(p, 0);
  delete o.tenantId;   // the record's own id is used
  if (typeof o.profileUpdatedAt !== 'string' || !o.profileUpdatedAt) o.profileUpdatedAt = new Date().toISOString();
  return o;
}
// The profile as the extension stores it: secrets as placeholders. A business
// saved before profiles existed gets one built from its vault record.
function profileForClient(id, rec) {
  const m = rec.meta || {};
  const p = rec.profile ? { ...rec.profile } : {
    tin: m.tin, deviceNo: m.deviceNo, legalName: m.businessName, tradeName: m.tradeName || m.businessName,
    managerEndpoint: m.managerEndpoint, sandbox: m.mode !== 'production', vatReg: !!rec.vatRegistered, profileUpdatedAt: '',
  };
  const has = rec.has || {};
  p.tenantId = id;
  p.efrisPassword = has.efrisPassword ? VAULT_PLACEHOLDER : '';
  p.efrisKeyPem = has.efrisPrivateKeyPem ? VAULT_PLACEHOLDER : '';
  p.efrisKeyPassphrase = has.efrisPassphrase ? VAULT_PLACEHOLDER : '';
  p.accessToken = has.managerToken ? VAULT_PLACEHOLDER : '';
  return p;
}

// Create/update a tenant's credentials (encrypted at rest). Allowed for an owner,
// or an admin of that business. A new business can be added by an owner or by
// anyone who administers another business; its creator becomes its admin.
// With a Manager token, it must also reach the given Manager endpoint.
app.post('/api/tenant', async (req, res) => {
  const b = req.body || {};
  const id = String(b.id || b.tin || '').trim();
  if (!id) return res.status(400).json({ success: false, error: 'tenant id (or TIN) required' });
  const user = req.auth;
  const privileged = !!(user.owner || user.service);
  let exists = false; try { exists = vault.listTenants().some(t => t.id === id); } catch (_) {}
  const roleHere = auth.roleIn(user, id);
  if (!privileged) {
    if (exists || roleHere) { if (roleHere !== 'admin') return res.status(403).json({ success: false, error: 'You do not have access to this business' }); }
    else if (!adminTenantIds(user).length) return res.status(403).json({ success: false, error: 'Your role cannot do this', permission: 'admin' });
  }
  // A new Manager address needs the token typed again (and verified against it),
  // or the saved token would follow the address to another server.
  if (exists && b.managerEndpoint && !b.managerToken) {
    let saved = ''; try { saved = (vault.getTenant(id) || {}).managerEndpoint || ''; } catch (_) {}
    if (saved && normEp(saved) !== normEp(b.managerEndpoint)) return res.status(400).json({ success: false, error: 'Enter the Manager access token again when you change the Manager address.' });
  }
  if (b.managerEndpoint && b.managerToken) {
    const ok = await verifyManagerAccess(b.managerEndpoint, b.managerToken);
    if (!ok) return res.status(403).json({ success: false, error: 'Manager token cannot access that endpoint - not authorised to store credentials for this business.' });
  }
  // The business setup (non-secret settings) the extension shows on every computer.
  // Newest wins: a copy older than the one on the relay is refused, and the
  // caller gets the relay's copy to load instead.
  let profile;
  if (b.profile !== undefined) {
    profile = cleanProfile(b.profile);
    if (!profile) return res.status(400).json({ success: false, error: 'The business setup is not valid.' });
    if (JSON.stringify(profile).length > PROFILE_MAX) return res.status(413).json({ success: false, error: 'The business setup is too large (logo or signature image too big). Use a smaller image.' });
    let cur = null; try { cur = vault.getProfile(id); } catch (_) {}
    const curAt = (cur && cur.profile && cur.profile.profileUpdatedAt) || '';
    if (curAt && String(profile.profileUpdatedAt) < curAt) {
      return res.status(409).json({ success: false, conflict: true, error: 'These settings were changed on another computer after this one loaded them.', profile: profileForClient(id, cur) });
    }
  }
  try {
    const meta = vault.putTenant(id, {
      profile,
      tin: b.tin, deviceNo: b.deviceNo, mode: b.mode, businessName: b.businessName,
      tradeName: b.tradeName, address: b.address, brn: b.brn, phone: b.phone, email: b.email,
      vatRegistered: b.vatRegistered === undefined ? undefined : !!b.vatRegistered,
      efrisPrivateKeyPem: b.efrisPrivateKeyPem, efrisPassphrase: b.efrisPassphrase, efrisPassword: b.efrisPassword,
      efrisPrivateKeyPath: b.efrisPrivateKeyPath,
      managerEndpoint: b.managerEndpoint, managerToken: b.managerToken,
      enablerUrl: b.enablerUrl, enablerMode: b.enablerMode, enablerDeviceNo: b.enablerDeviceNo,
    });
    if (!exists && !privileged && !roleHere) auth.grantRole(user.id, id, 'admin');
    if (!exists) console.log('   Business "' + (b.businessName || id) + '" added by ' + (user.name || 'service'));
    if (profile) console.log('   Business setup of "' + (meta.tradeName || meta.businessName || id) + '" saved by ' + (user.name || 'service'));
    res.json({ success: true, tenant: meta });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// One business's setup for the extension: any role in that business may read it,
// so a new browser, address or till gets the business without onboarding. Secrets
// never leave the vault: each one is '__vault__' when saved, '' when not.
app.get('/api/tenant/:id/profile', (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!canUseTenant(req.auth, id)) return res.status(403).json({ success: false, error: 'You do not have access to this business' });
  let rec = null;
  try { rec = vault.getProfile(id); } catch (e) { return res.status(500).json({ success: false, error: e.message }); }
  if (!rec) return res.status(404).json({ success: false, error: 'This business is not saved on EFRISConnect yet.' });
  const profile = profileForClient(id, rec);
  res.json({ success: true, profile, derived: !rec.profile, mgrBusiness: profile.mgrBusiness || '', updatedAt: profile.profileUpdatedAt || '', role: auth.roleIn(req.auth, id) });
});

// Only the businesses this user holds a role in (owners: all), with the role.
app.get('/api/tenant', (req, res) => {
  try {
    const mine = new Set(tenantIdsFor(req.auth));
    res.json({ success: true, tenants: vault.listTenants().filter(t => mine.has(t.id)).map(t => ({ ...t, role: auth.roleIn(req.auth, t.id) })) });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/tenant/:id', (req, res) => {
  const id = String(req.params.id || '');
  if (auth.roleIn(req.auth, id) !== 'admin') return res.status(403).json({ success: false, error: 'You do not have access to this business' });
  try {
    vault.delTenant(id); auth.removeTenantRoles(id);
    const cats = readGoodsCatalogs(); if (cats[id]) { delete cats[id]; writeFileAtomic(GOODS_CATALOG_FILE, JSON.stringify(cats)); }
    res.json({ success: true });
  }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  /extension ROUTE - serve EXTENSION_HTML
// ══════════════════════════════════════════════════════════════
// Pages get the allowed Manager origins only. No key: every API call needs a
// signed-in session (Authorization: Bearer), so a page is useless on its own.
function injectPageConfig(html) {
  const extra = JSON.stringify(EXTRA_ORIGINS).replace(/</g, '\\u003c');
  const lan = JSON.stringify(LAN_URLS[0] || '').replace(/</g, '\\u003c');
  return html.replace('</head>', `<script>window.__ALLOWED_ORIGINS=${extra};window.__LAN_URL=${lan};</script></head>`);
}

app.get('/extension', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(injectPageConfig(EXTENSION_HTML));
});

// Root - an informational landing page, separate from the extension itself.
// (index:false below stops express.static from auto-serving index.html here.)
app.get('/', (req, res) => {
  try {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(fs.readFileSync(path.join(__dirname, '..', 'frontend', 'landing.html'), 'utf8'));
  } catch (e) { res.redirect('/extension'); }
});

// ── Static files and SPA fallback ────────────────────────────
const FRONTEND = path.join(__dirname, '..', 'frontend');
app.use(express.static(FRONTEND, { index: false }));

// Offline PDF engine (html2pdf = jsPDF + html2canvas) for the receipt viewer's
// "Save PDF" button. Served from the local relay with a long immutable cache so
// it loads once; no internet/CDN needed. Must be before the SPA catch-all.
app.get('/html2pdf.bundle.min.js', (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(fs.readFileSync(path.join(FRONTEND, 'html2pdf.bundle.min.js')));
  } catch (e) { res.status(404).send('// html2pdf not available'); }
});

// Dedicated receipt viewer - must be before the SPA catch-all. Inject the offline
// QR encoder from the local relay so the printed receipt needs NO internet/CDN.
app.get('/receipt', (req, res) => {
  try {
    let html = fs.readFileSync(path.join(FRONTEND, 'receipt.html'), 'utf8');
    try {
      const lib = fs.readFileSync(path.join(FRONTEND, 'qrcode.lib.js'), 'utf8');
      html = html.replace('/*@QRLIB@*/', () => lib + '\n;');   // function repl - lib contains "$'"
    } catch (_) {}
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) { res.sendFile(path.join(FRONTEND, 'receipt.html')); }
});

// The branded Manager custom-theme HTML, served as plain text so it can be
// copied and pasted into Manager → Settings → Themes.
// The branded theme HTML with the offline QR encoder inlined (self-contained).
// Only the document settings the theme uses, type-checked and length-capped
// (they end up inside a script in Manager's theme).
function themePrefs(p) {
  p = (p && typeof p === 'object') ? p : {};
  const str = (v, n) => (typeof v === 'string' ? v.slice(0, n) : '');
  const out = { band: /^#[0-9a-f]{6}$/i.test(p.band || '') ? p.band : '#1f2937', footer: str(p.footer, 600), pay: {}, show: {}, paper: {}, seller: {},
    nameMode: ['legal', 'trade', 'both'].includes(p.nameMode) ? p.nameMode : 'legal' };
  // Seller details from the extension's EFRIS settings, for when Manager's
  // Business Details are empty (the legal name and TIN are what URA requires).
  const sel = p.seller || {};
  ['legal', 'trade', 'tin', 'brn', 'address', 'phone', 'email'].forEach(k => { const v = str(sel[k], 200).trim(); if (v) out.seller[k] = v; });
  const pay = p.pay || {};
  ['bank', 'accName', 'accNo', 'momo', 'terms'].forEach(k => { const v = str(pay[k], 160); if (v) out.pay[k] = v; });
  const show = p.show || {};
  ['servedBy', 'signatures'].forEach(k => { if (typeof show[k] === 'boolean') out.show[k] = show[k]; });
  const PAPERS = ['A4', 'A5', 'Letter', 'A6', '80mm', '58mm'], paper = p.paper || {};
  ['receipt', 'invoice', 'credit'].forEach(k => { if (PAPERS.includes(paper[k])) out.paper[k] = paper[k]; });
  return out;
}
function getBrandedThemeHtml(prefs) {
  let html = fs.readFileSync(path.join(FRONTEND, 'manager-theme.html'), 'utf8');
  const js = 'var EFC_PREFS=' + JSON.stringify(themePrefs(prefs)).replace(/</g, '\\u003c') + ';';
  html = html.replace('/*@PREFS@*/', () => js);
  try {
    const lib = fs.readFileSync(path.join(FRONTEND, 'qrcode.lib.js'), 'utf8');
    // Function replacement - a string replacement would interpret "$'" in the lib.
    html = html.replace('/*@QRLIB@*/', () => lib + '\n;');
  } catch (_) {}
  return html;
}

app.get('/branded-theme', (req, res) => {
  try {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    let prefs = null; try { prefs = req.query.prefs ? JSON.parse(String(req.query.prefs)) : null; } catch (_) {}
    res.send(getBrandedThemeHtml(prefs));
  } catch (e) { res.status(500).send('theme not found'); }
});

// Install/update the branded theme in Manager via the API - the same idea as
// "Check/Create EFRIS Custom Fields", so users don't copy-paste and updates land
// automatically. Manager's theme object shape isn't documented, so we try a few
// field-name variants; pass themeKey to update an existing theme in place.
app.post('/api/manager/install-theme', async (req, res) => {
  const { managerEndpoint, accessToken, themeKey, prefs } = req.body || {};
  if (!managerEndpoint || !accessToken) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  const ep = normEp(managerEndpoint);
  let html; try { html = getBrandedThemeHtml(prefs); } catch (e) { return res.status(500).json({ success: false, error: 'theme file missing' }); }
  const NAME = 'EFRISConnect';
  // Manager has used different field names for the theme body across builds. Send
  // ALL candidate content fields in one payload - Manager fills the one it knows
  // and ignores the rest, so we don't have to guess which build we're on.
  const body = { Name: NAME, Content: html, Template: html, Html: html, Theme: html, Body: html, Value: html };
  // No stored key (it was never captured): reuse the EFRISConnect theme that the
  // Form Defaults already point at, instead of creating yet another one.
  let key = bareKey(themeKey || '');
  if (!key) { try { key = await findInstalledThemeKey(ep, accessToken, NAME); if (key) console.log('   Theme: reusing the EFRISConnect theme set in Form Defaults (' + key + ')'); } catch (_) {} }
  let newKey = null, updated = false;
  const gated = st => st === 401 || st === 403;
  // Settings saves re-send the theme automatically. Skip the push when it is the
  // same theme this relay last pushed (the Install button always pushes).
  const themeHash = crypto.createHash('sha1').update(html).digest('hex');
  if (key && !(req.body && req.body.setDefault) && _themePushed[ep + '|' + key] === themeHash) return res.json({ success: true, key, updated: false, unchanged: true });
  try {
    // Update in place with PUT (Manager's update verb). A POST to the key's address
    // creates a NEW theme, which is how a duplicate "EFRISConnect" appeared.
    if (key) {
      const u = await managerCall(ep, accessToken, 'PUT', '/custom-theme-form/' + key, body);
      if (gated(u.status)) return res.json({ success: false, gated: true, error: 'Manager rejected the theme API (HTTP ' + u.status + '). This access token lacks theme permission - use the copy-paste method.' });
      if (u.status >= 200 && u.status < 300) { newKey = key; updated = true; console.log('   Theme updated in Manager (' + key + ')'); }
      else if (u.status !== 404) return res.json({ success: false, error: 'Manager did not accept the theme update (HTTP ' + u.status + '). Nothing was created. Use the copy-paste method.' });
      // 404: the stored theme was deleted in Manager, so create a fresh one below.
    }
    if (!updated) {
      const r = await managerCall(ep, accessToken, 'POST', '/custom-theme-form', body);
      if (gated(r.status)) return res.json({ success: false, gated: true, error: 'Manager rejected the theme API (HTTP ' + r.status + '). This access token lacks theme permission - use the copy-paste method.' });
      if (!(r.status >= 200 && r.status < 400)) return res.json({ success: false, error: 'Manager did not accept the theme (HTTP ' + r.status + '). Use the copy-paste method.' });
      newKey = (r.data && (r.data.key || r.data.Key || r.data.id)) || (typeof r.data === 'string' && /^[0-9a-f-]{36}$/i.test(r.data.trim()) ? r.data.trim() : null);
      // Manager returns the new record's address in the Location header.
      if (!newKey && r.headers) { const loc = r.headers.location || r.headers.Location || ''; const k = String(loc).split('?')[0].split('/').filter(Boolean).pop(); if (k && /^[0-9a-f-]{36}$/i.test(k)) newKey = k; }
      console.log('   Theme created in Manager' + (newKey ? ' (' + newKey + ')' : '') + ' - HTTP ' + r.status);
      if (!newKey) console.log('   Theme created, but Manager returned no key - the next install cannot update it in place. Location=' + ((r.headers && r.headers.location) || '-') + ' body=' + JSON.stringify(r.data || '').slice(0, 200));
    }
  } catch (e) {
    return res.json({ success: false, error: 'Could not reach Manager: ' + e.message + '. Use the copy-paste method.' });
  }
  // Optionally set it as the default theme on Sales Invoices / Receipts / Credit
  // Notes (Form Defaults), so the user doesn't have to tick it in three places.
  let defaults = null;
  if (newKey && req.body && req.body.setDefault) {
    try { defaults = await setThemeAsDefault(ep, accessToken, newKey); }
    catch (e) { defaults = { error: e.message }; }
  }
  if (newKey) _themePushed[ep + '|' + newKey] = themeHash;
  return res.json({ success: true, key: newKey, updated, defaults });
});
const _themePushed = {};

// The key of the theme named `name` that a document type's Form Defaults use
// (Manager has no theme list endpoint, so this is how an existing one is found).
async function findInstalledThemeKey(ep, token, name) {
  const forms = ['sales-invoice-form-defaults-form', 'receipt-form-defaults-form', 'credit-note-form-defaults-form'];
  for (const f of forms) {
    try {
      const g = await managerCall(ep, token, 'GET', '/' + f, null);
      const id = g && g.data && typeof g.data === 'object' && (g.data.CustomThemeId || g.data.ThemeKey || g.data.CustomThemeKey);
      if (!id || !/^[0-9a-f-]{36}$/i.test(String(id))) continue;
      const t = await managerCall(ep, token, 'GET', '/custom-theme-form/' + bareKey(id), null);
      if (t.status === 200 && t.data && String(t.data.Name || '').trim() === name) return bareKey(id);
    } catch (_) {}
  }
  return '';
}

// Set a custom theme as the DEFAULT on each document type's Form Defaults.
// Manager's *-form/{key} POST replaces the record, so we GET the current form
// first and inject ONLY the theme field - never wiping the user's other defaults.
// Endpoint/field names have varied across Manager builds, so they are resolved
// at runtime.
async function setThemeAsDefault(ep, token, themeKey) {
  const tk = bareKey(themeKey);
  const DOCS = [
    { label: 'Sales Invoices', lists: ['/sales-invoice-form-defaults', '/sales-invoices-form-defaults'], form: 'sales-invoice-form-defaults-form' },
    { label: 'Sales Receipts', lists: ['/receipt-form-defaults', '/sales-receipt-form-defaults', '/receipts-form-defaults'], form: 'receipt-form-defaults-form' },
    { label: 'Credit Notes', lists: ['/credit-note-form-defaults', '/credit-notes-form-defaults'], form: 'credit-note-form-defaults-form' },
  ];
  const THEME_FIELDS = ['Theme', 'CustomTheme', 'ThemeKey', 'CustomThemeKey'];
  const out = {};
  for (const d of DOCS) {
    let done = false, note = 'not found';
    // 1) find the singleton form-default record's key
    let key = null;
    for (const lp of d.lists) {
      try {
        const g = await managerCall(ep, token, 'GET', lp, null);
        if (g.status >= 200 && g.status < 300 && g.data) {
          if (Array.isArray(g.data) && g.data[0]) key = g.data[0].key || g.data[0].Key || null;
          else if (Array.isArray(g.data.customFields)) { /* form shape already */ }
          else key = g.data.key || g.data.Key || null;
          if (key || (g.data && typeof g.data === 'object')) { d._listHit = lp; break; }
        }
      } catch (_) {}
    }
    // 2) GET the editable form, inject the theme, POST it back
    try {
      const formPath = '/' + d.form + (key ? '/' + bareKey(key) : '');
      const gf = await managerCall(ep, token, 'GET', formPath, null);
      if (gf.status >= 200 && gf.status < 300 && gf.data && typeof gf.data === 'object' && !gf._html) {
        const form = { ...gf.data };
        // Manager stores the theme choice as CustomTheme (boolean "use a custom theme")
        // + CustomThemeId (the theme's key) - confirmed on the receipt form. Set those;
        // keep the legacy string fields too so older builds still take it.
        form.CustomTheme = true;
        form.CustomThemeId = tk;
        for (const f of THEME_FIELDS) if (f !== 'CustomTheme') form[f] = tk;
        const pf = await managerCall(ep, token, 'POST', formPath, form);
        if (pf.status >= 200 && pf.status < 400) { done = true; note = 'set'; }
        else note = 'POST HTTP ' + pf.status;
      } else { note = gf._html ? 'auth/redirect' : 'form HTTP ' + gf.status; }
    } catch (e) { note = e.message; }
    out[d.label] = done ? 'set' : note;
  }
  return out;
}

app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/') && req.path !== '/extension') {
    try {
      const html = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(injectPageConfig(html));
    } catch(e) {
      res.status(500).send('Frontend not found');
    }
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// Last-resort error handler: Express's default page includes a stack trace with
// server file paths. Return a short JSON error instead and log the detail.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON body' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
  logger.error('Unhandled route error', { path: req.path, message: err && err.message });
  res.status((err && err.status) || 500).json({ success: false, error: (err && err.expose) ? err.message : 'Internal error' });
});

// ══════════════════════════════════════════════════════════════
//  HTTPS via openssl child_process
// ══════════════════════════════════════════════════════════════
let httpsServer = null;

function tryStartHTTPS() {
  try {
    // 1. Preferred (offline): a locally-trusted cert placed in DATA_DIR by the
    //    Setup-Https script - a PFX, or a cert/key PEM pair. Because that script
    //    installs the cert into the Windows Trusted Root store, Manager's embedded
    //    browser accepts the HTTPS iframe with NO internet and NO openssl.
    const pfxFile  = path.join(DATA_DIR, 'https.pfx');
    const certFile2 = path.join(DATA_DIR, 'https_cert.pem');
    const keyFile2  = path.join(DATA_DIR, 'https_key.pem');
    let sslOptions = null, src = '';
    if (fs.existsSync(pfxFile)) {
      let pass = ''; try { pass = fs.readFileSync(path.join(DATA_DIR, 'https_pfx_pass.txt'), 'utf8').trim(); } catch(_) {}
      sslOptions = { pfx: fs.readFileSync(pfxFile), passphrase: pass }; src = 'trusted PFX (data/https.pfx)';
    } else if (fs.existsSync(certFile2) && fs.existsSync(keyFile2)) {
      sslOptions = { key: fs.readFileSync(keyFile2), cert: fs.readFileSync(certFile2) }; src = 'trusted PEM (data/https_cert.pem)';
    }
    if (sslOptions) {
      httpsServer = https.createServer(sslOptions, app);
      httpsServer.listen(HTTPS_PORT, BIND_HOST, () => { httpsUp = true; console.log('HTTPS running at https://localhost:' + HTTPS_PORT + '/extension  [' + src + ']'); console.log('This is the URL to use in Manager. http://localhost:' + PORT + ' now redirects here.'); });
      httpsServer.on('error', e => portError(e, HTTPS_PORT, 'HTTPS'));
      if (MANAGER_HTTPS_PORT) startManagerHttps(sslOptions);
      return;
    }
    // 2. Fallback (dev only): openssl-generated self-signed cert - UNTRUSTED, so
    //    Manager will reject it. Fine for a browser you click through; not for the
    //    embedded extension iframe. Prefer Setup-Https above.
    const { execFileSync } = require('child_process');
    const os = require('os');
    try {
      execFileSync('openssl', ['version'], { stdio: 'ignore' });
      // Generate into a private, single-use folder and remove it once the pair is
      // in memory, so no unencrypted key is left behind in the shared temp dir.
      // Named "selfsigned-localhost" so it is never mistaken for the EFRIS key.
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'efrisconnect-https-'));
      const keyFile  = path.join(tmpDir, 'selfsigned-localhost-key.pem');
      const certFile = path.join(tmpDir, 'selfsigned-localhost-cert.pem');
      let sslOptions2;
      try {
        execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyFile, '-out', certFile, '-days', '365', '-nodes', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
        sslOptions2 = { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch(_) {}
      }
      httpsServer = https.createServer(sslOptions2, app);
      httpsServer.listen(HTTPS_PORT, BIND_HOST, () => { httpsUp = true; console.log('HTTPS running (self-signed, untrusted) at https://localhost:' + HTTPS_PORT + '/extension'); });
      httpsServer.on('error', e => console.log('HTTPS startup error: ' + e.message));
    } catch(opensslErr) {
      console.log('No trusted cert (data/https.pfx) and openssl not installed - HTTPS off.');
      console.log('For offline Manager Desktop: run windows\\Setup-Https.bat as Administrator once, then restart.');
    }
  } catch(e) {
    console.log('Could not start HTTPS: ' + e.message);
  }
}

// A port already taken almost always means EFRISConnect is already running.
function portError(e, port, what) {
  if (e && e.code === 'EADDRINUSE') {
    console.log('[ERROR] Port ' + port + ' is already in use - EFRISConnect is probably already running (check the taskbar or the Windows service). Close the other copy, then start again.');
    setTimeout(() => process.exit(1), 300);
  } else console.log('[ERROR] ' + what + ' startup error: ' + (e && e.message));
}
// Shop network: Manager Server over HTTPS for the tills, with the relay's certificate.
// A failure here (port taken) leaves the relay itself running.
function startManagerHttps(tls) {
  try {
    const srv = require('./manager-proxy').startManagerProxy({ tls, port: MANAGER_HTTPS_PORT, bindHost: BIND_HOST,
      targetPort: +MANAGER_PORTS[0], log: m => console.log('   ' + m) });
    srv.on('error', e => console.log('[ERROR] Manager over HTTPS could not start on port ' + MANAGER_HTTPS_PORT + ': ' +
      (e.code === 'EADDRINUSE' ? 'the port is in use. Set MANAGER_HTTPS_PORT to a free port.' : e.message)));
    srv.listen(MANAGER_HTTPS_PORT, BIND_HOST, () => console.log('Manager over HTTPS for tills: https://' + require('os').hostname().toLowerCase() + ':' + MANAGER_HTTPS_PORT + '  (Manager Server on port ' + MANAGER_PORTS[0] + ')'));
  } catch (e) { console.log('[ERROR] Manager over HTTPS: ' + e.message); }
}
// Shop network: write the till kit (public certificate, trust/remove scripts,
// README with the addresses) into the data folder. Never throws.
function writeLanTillKit() {
  try {
    const os = require('os');
    const kit = tillKit.writeTillKit(DATA_DIR, { hostname: os.hostname(), urls: LAN_URLS,
      managerUrls: (MANAGER_HTTPS_PORT ? lanManagerOrigins(EXTRA_HOSTS, [String(MANAGER_HTTPS_PORT)]).filter(o => o.startsWith('https:'))
        : lanManagerOrigins(EXTRA_HOSTS, MANAGER_PORTS).filter(o => o.startsWith('http:'))).slice(0, 3) });
    if (kit.error) console.log('   Till kit: ' + kit.error);
    else console.log('   Till kit (copy this folder to each till): ' + kit.dir);
    return kit;
  } catch (e) { console.log('   Till kit could not be written: ' + e.message); return { error: e.message }; }
}
function relayUrls() {
  const local = (httpsUp ? 'https://localhost:' + HTTPS_PORT : 'http://localhost:' + PORT) + '/extension';
  // Shop network mode: the PC-name address first (it is the Manager button URL), then the rest.
  if (LAN_MODE && LAN_URLS.length) return { local, lan: LAN_URLS[0], lanAll: LAN_URLS, button: LAN_URLS[0] };
  let lan = '';
  if (!/^(127\.|localhost|::1)/.test(String(BIND_HOST))) {
    const os = require('os');
    for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) if (a.family === 'IPv4' && !a.internal && !lan) lan = (httpsUp ? 'https://' : 'http://') + a.address + ':' + (httpsUp ? HTTPS_PORT : PORT) + '/extension';
  }
  return { local, lan };
}

// A relay reachable from other computers must check the Host header and use
// HTTPS (its own certificate, or a TLS reverse proxy named in TRUST_PROXY):
// passwords and session tokens cross the network. Returns the problem, or ''.
function networkBindProblem(o) {
  if (LOOPBACK_HOST.test(String(o.bindHost || ''))) return '';
  const missing = [];
  if (!o.allowedHosts || !o.allowedHosts.length) missing.push('ALLOWED_HOSTS=<the name other computers use to reach this relay>');
  if (!o.https && !o.trustProxy) missing.push('HTTPS (run the HTTPS setup to create https.pfx in the data folder, or put the relay behind a TLS reverse proxy and set TRUST_PROXY)');
  return missing.length ? 'BIND_HOST=' + o.bindHost + ' makes EFRIS Connect reachable from other computers, but this is missing: ' + missing.join('; and ') + '. Set it and start again, or remove BIND_HOST to use this computer only.' : '';
}

// ── Start HTTP server (only when run directly, not during tests) ──────────
const bindProblem = require.main === module ? networkBindProblem({ bindHost: BIND_HOST, allowedHosts: EXTRA_HOSTS, trustProxy: !!process.env.TRUST_PROXY,
  https: ['https.pfx', 'https_cert.pem'].some(n => fs.existsSync(path.join(DATA_DIR, n))) }) : '';
if (bindProblem) { console.log('[ERROR] ' + bindProblem); setTimeout(() => process.exit(1), 300); }
else if (require.main === module) {
  // First run: no account yet. A one-time code lets the owner be created from
  // another computer; on this PC no code is needed.
  let setupCode = null;
  try { const sc = auth.ensureSetupCode(); if (sc) setupCode = sc.code; if (sc) console.log('   No account yet. Open EFRIS Connect in Manager on this PC to create the owner account' + (sc.file ? ' (from another computer, use the setup code shown below; it is also saved in ' + sc.file + ')' : '') + '.'); }
  catch (e) { console.log('   ⚠ Could not prepare the setup code: ' + e.message); }
  // Log retention: remove day log files older than LOG_RETENTION_DAYS (default 90), now and daily.
  const pruneLogs = () => {
    try {
      const keep = logTools.retentionDays();
      const n = logTools.prune(logger.LOG_DIR, keep);
      logger.info('Log retention: removed ' + n + ' log file(s) older than ' + keep + ' days');
    } catch (_) {}
  };
  pruneLogs();
  setInterval(pruneLogs, 24 * 3600000).unref();
  const httpServer = app.listen(PORT, BIND_HOST, () => {
    // Status block + hotkeys once HTTPS has had a moment to start.
    setTimeout(() => consoleUi.ready({
      urls: relayUrls(),
      inflight: () => _inflight,
      status: () => {
        let modes = []; try { modes = [...new Set(vault.listTenants().map(t => (t.mode || 'sandbox').toUpperCase()))]; } catch (_) {}
        const conn = (_connCache && _connCache.data) || {};
        let queue = 0; try { queue = loadQueue().filter(e => e.status === 'pending').length; } catch (_) {}
        return { version: APP_VERSION, mode: modes.join(' + '), vault: vault.isUnlocked(), ura: (_retry.online !== null ? _retry.online : (conn.ura === undefined ? null : conn.ura)),
          enabler: conn.enabler, queue, setupCode: (setupCode && !auth.hasUsers()) ? setupCode : '' };
      },
    }), 1500);
    console.log('=======================================================');
    console.log('  EFRISConnect ' + APP_VERSION);
    console.log('  URA EFRIS e-receipts and e-invoices for Manager.io');
    console.log('  Free and open source, by The Tukei Hope Initiative (EMC/CBO/025)');
    console.log('=======================================================');
    console.log('HTTP running on port ' + PORT + ' (will redirect to HTTPS once it is up)');
    tryStartHTTPS();
    if (LAN_MODE) writeLanTillKit();
    setTimeout(() => {
      if (!httpsUp) {
        console.log('-------------------------------------------------------');
        console.log('HTTPS is OFF. Open http://localhost:' + PORT + '/extension for now.');
        console.log('For the single-document button, Manager needs HTTPS: run');
        console.log('windows\\EFRISConnect.bat -> "First-time HTTPS setup", then restart.');
        console.log('-------------------------------------------------------');
      }
    }, 800);
  });
  httpServer.on('error', e => portError(e, PORT, 'HTTP'));
}

module.exports = app;
// Exposed for regression tests (decrypt paths). Not used at runtime.
module.exports._auth = auth;
module.exports._vault = vault;
module.exports._activity = activity;
module.exports._mailer = mailer;
module.exports._consoleUi = consoleUi;
module.exports._routePerms = ROUTE_PERMS.map(r => ({ method: r.method, path: r.path, perm: r.perm }));
module.exports._test = { lanManagerOrigins, lanRelayUrls, managerPorts, EXTRA_ORIGINS, LAN_URLS, FRAME_ANCESTORS, writeLanTillKit, learnVaultSecrets, networkBindProblem, isLocalRequest, routePerm, efrisDecodeJson, aesDecryptStr, aesEncryptB64, aesAlgo, buildT109, goodsStockOf, t106Kind, cnItem, eatToday, eatParts, uraUrl, uraHost, buildT108, lineDiscount, lookupCommodityTax, commodityTaxRule };
