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
const vault   = require('./vault');   // encrypted per-tenant credential store
const logger  = require('./logger');  // daily error/activity log for troubleshooting

// ── Redact secrets before anything gets logged ──────────────────
// Scans a request body for known-sensitive field names (wherever they are
// nested - config.efrisPassword, config.efrisKeyPassphrase, a bare
// accessToken, etc.) and strips those exact values out of a string. This
// way logging code never has to know which variable holds a given route's
// secret - it just redacts whatever the request actually contained.
const SECRET_FIELD_NAMES = new Set(['efrispassword','accesstoken','token','apiaccesstoken','efriskeypassphrase','efriskeypassword','password','efriskeypem']);
function collectSecrets(obj, acc, depth) {
  if (!obj || typeof obj !== 'object' || depth > 4) return acc;
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
const PORT = process.env.PORT || 3000;
const HTTPS_PORT = 5443;
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

app.set('trust proxy', true);
app.use(cors({ origin:'*', methods:['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders:['Content-Type','Authorization','X-API-KEY','X-Manager-Token','X-Manager-Endpoint'] }));
app.use(express.json({ limit: '5mb' }));   // cap request bodies to guard against oversized-payload DoS

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

// ── Internal API key - protects all /api/* routes from outside callers ──
// Set INTERNAL_API_KEY env var for a stable key; otherwise a random key is
// generated at startup (injected into the served HTML so the SPA can use it).
const API_KEY = process.env.INTERNAL_API_KEY || crypto.randomBytes(32).toString('hex');
app.use('/api', (req, res, next) => {
  if (req.path === '/health') return next(); // health check must stay public
  if (req.headers['x-api-key'] !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
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

// Load frontend HTML at startup - used as /extension and SPA
let EXTENSION_HTML = '';
try {
  EXTENSION_HTML = fs.readFileSync(path.join(__dirname, '..', 'frontend', 'index.html'), 'utf8');
  console.log('Loaded frontend/index.html as EXTENSION_HTML');
} catch(e) {
  console.warn('Could not load frontend/index.html:', e.message);
}

const DATA_DIR = process.env.DATA_DIR_OVERRIDE || path.join(__dirname, 'data');
let TREE = null;
let UNITS = null;

function getTree() {
  if (!TREE) {
    console.log('Loading goods_tree.json...');
    TREE = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'goods_tree.json'), 'utf8'));
    console.log('Loaded: ' + Object.keys(TREE).length + ' segments');
  }
  return TREE;
}

// Prefer the EFRIS-synced unit list (uom_synced.json) when present - it's the
// authoritative list pulled from the taxpayer's own EFRIS account and cached to
// disk so it also works offline. Falls back to the bundled static list.
function getUnits() {
  if (!UNITS) {
    for (const f of ['uom_synced.json', 'uom.json', 'units.json']) {
      try { const u = JSON.parse(fs.readFileSync(path.join(DATA_DIR, f), 'utf8')); if (Array.isArray(u) && u.length) { UNITS = u; break; } } catch(e) {}
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
    const req = lib.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e) { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', (e) => { logger.error('EFRIS network call failed', { url: baseUrl, message: e.message }); reject(e); });
    req.on('timeout', () => { req.destroy(); logger.error('EFRIS network call timed out', { url: baseUrl }); reject(new Error('EFRIS timed out after 30s')); });
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
    // Optional shared secret so an upstream WAF rule can distinguish this
    // backend's traffic from generic internet scanning and skip its bot check
    // only for requests carrying it. Unset by default - additive, never required.
    if (process.env.CLOUDFLARE_SKIP_SECRET) opts.headers['X-Backend-Secret'] = process.env.CLOUDFLARE_SKIP_SECRET;
    if (extraHeaders) Object.assign(opts.headers, extraHeaders);
    if (bodyStr) opts.headers['Content-Length'] = Buffer.byteLength(bodyStr);
    const req = lib.request(opts, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && _redirectsLeft > 0) {
        res.resume(); // discard body, we're not using this response
        const nextUrl = new URL(res.headers.location, parsed).toString();
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
          try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
          catch(e) { resolve({ status: res.statusCode, data }); }
        } else { resolve({ status: res.statusCode, data: null }); }
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
  if (ep.endsWith('/api4')) throw new Error('Manager API v4 endpoints (/api4) are not yet supported. Please use your /api2 endpoint URL instead.');
  else if (ep.endsWith('/api')) ep = ep + '2';
  else if (!ep.endsWith('/api2')) ep = ep + '/api2';
  return ep;
}

function bareKey(k) { return String(k || '').split('?')[0].replace(/\/+$/, '').split('/').pop(); }

function mgrCreds(req) {
  const ep = req.headers['x-manager-endpoint'] || req.query.ep || '';
  const tk = req.headers['x-manager-token'] || req.query.tk || '';
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
  if (!_taxCodeCache[cacheKey]) {
    try {
      const r = await managerCall(ep, tk, 'GET', '/tax-codes');
      _taxCodeCache[cacheKey] = (r.data && r.data.taxCodes) || [];
    } catch(e) { _taxCodeCache[cacheKey] = []; }
  }
  const codes = _taxCodeCache[cacheKey];
  // Match by VAT type: Standard=18%, Zero=0%, Exempt
  const query = vatType === 'Exempt' ? 'exempt'
    : vatType === 'Zero' ? ['zero', '0%', 'zero rated', 'zero-rated']
    : ['18%', 'standard', 'vat']; // Standard
  const q = Array.isArray(query) ? query : [query];
  const match = codes.find(c => {
    const nm = (c.name || c.Name || '').toLowerCase();
    return q.some(term => nm.includes(term));
  });
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
      console.log(`   Loaded Manager RECEIPT ${key} - fields: ${Object.keys(form).join(', ')}`);
    }
  }
  if (!form) return { _error: 'Manager returned HTTP ' + formR.status + ' (not found as invoice or receipt)', _status: formR.status };
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
        const tinKey = cf.byName['Buyer TIN'] || cf.byName['Customer TIN'] || cf.byName['TIN'];
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
    const price = parseFloat(l.SalesUnitPrice || l.UnitPrice || l.Amount || 0) || 0;
    const lineTotal = qty * price, taxAmount = lineTotal * (rate / 100);
    lines.push({ ItemName: itemName, ItemCode: code, Qty: qty, UnitPrice: price, LineTotal: lineTotal,
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
    Notes: form.Description || '', Lines: lines, CustomFields: cfVals, Key: key
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
      path.join(__dirname, 'data', 'private_key.pem'),
      '/app/keys/efris_private.pem',
    ];

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
      try { pem = fs.readFileSync(keyOverride.path, 'utf8'); } catch (e) { tried.push('config-key path not found: ' + keyOverride.path); }
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
function aesEncryptB64(plain, keyBytes) {
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
  const contentB64 = aesEncryptB64(json, aesKeyBytes);
  const signature = signSha1(contentB64, privatePem);
  const env = efrisEnv(code, '', tin, deviceNo);
  env.data.content = contentB64;
  env.data.signature = signature;
  env.data.dataDescription = { codeType: '1', encryptCode: '2', zipCode: '0' };
  return env;
}

function efrisEnv(code, content, tin, deviceNo) {
  const cs = typeof content === 'string' ? content : JSON.stringify(content);
  return {
    data: { content: Buffer.from(cs).toString('base64'), signature: null, dataDescription: { codeType:'0', encryptCode:'1', zipCode:'0' } },
    globalInfo: {
      appId:'AP04', version:'1.1.20191201', dataExchangeId: Date.now().toString(),
      interfaceCode: code, requestCode:'TP',
      requestTime: new Date().toISOString().replace('T',' ').slice(0,19),
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

async function getSession(tin, deviceNo, password, efrisBaseUrl, keyOverride) {
  const key = tin + '_' + deviceNo;
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
  const t104 = await efrisCall(efrisBaseUrl, efrisEnv('T104', '', tin, deviceNo));
  let symKeyEnc = null, aesKey = null, privatePem = null;
  try { const c = JSON.parse(Buffer.from(t104.data.data.content, 'base64').toString()); symKeyEnc = c.passowrdDes || c.passwordDes; } catch(e) {}
  let _aesErr = null;
  try { if (symKeyEnc) { const r = resolveAesKey(symKeyEnc, keyOverride); aesKey = r.key; privatePem = r.pem; } } catch(e) { _aesErr = e.message; console.log('   AES key error: ' + e.message); }
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
  const session = { symKeyEnc, aesKey, privatePem, ts: now };
  sessions[key] = session;
  return session;
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
async function getEfrisDictionary(tin, deviceNo, session, eu) {
  const key = tin + '_' + deviceNo;
  if (_dictCache[key]) return _dictCache[key];
  try {
    const t115 = await efrisCall(eu, efrisEnvEnc('T115', {}, tin, deviceNo, session.aesKey, session.privatePem));
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
          return dict;
        }
        console.log(`   (T115 content could not be decoded to JSON by any method)`);
      }
    }
  } catch(e) { console.log(`   (T115 dictionary fetch failed: ${e.message})`); }
  return null;
}

// Resolve an ISO currency (e.g. "UGX") to the EFRIS currency code expected by T130.
async function resolveEfrisCurrency(isoCode, tin, deviceNo, session, eu) {
  const iso = (isoCode || 'UGX').trim().toUpperCase();
  const dict = await getEfrisDictionary(tin, deviceNo, session, eu);
  if (!dict) return iso; // fallback to ISO if dictionary unavailable
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
      const r = await efrisCall(eu, efrisEnvEnc('T127', payload, tin, deviceNo, session.aesKey, session.privatePem));
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
  }
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

function buildT109(invoice, cfg) {
  const vat = !!cfg.vatRegistered;
  const isRefund = !!(invoice.IsRefund || invoice.isRefund);
  const r2 = n => (Math.round((parseFloat(n) || 0) * 100) / 100).toFixed(2);
  const lines = invoice.Lines || [];
  const goodsDetails = lines.map((l, i) => {
    const qty = parseFloat(l.Qty || 1) || 1;
    const unitPrice = parseFloat(l.UnitPrice || 0) || 0;
    const total = parseFloat(l.LineTotal || (unitPrice * qty)) || 0;
    const taxName = String(l.TaxName || l.TaxCode || invoice.TaxName || '').toLowerCase();
    const lineTax = parseFloat(l.TaxAmount || 0) || 0;
    let taxRate, tax, vatFlag, catCode;
    // Excise: a line is excisable if its item config carries excise data or the tax
    // name mentions excise. Per v24.0.1: exciseFlag '1' needs exciseRate, exciseRule
    // and exciseTax; exciseRule '2' (specific/quantity duty) also needs exciseUnit
    // and exciseCurrency ('1' = ad valorem). Values come from the item config so we
    // never guess a rate.
    const isExcise = /excise/.test(taxName) || l.ExciseFlag === '1' || !!(l.ExciseRate || l.ExciseTax);
    if (vat && /deemed/.test(taxName)) { taxRate = '0.18'; tax = r2(total - total / 1.18); vatFlag = '1'; catCode = '04'; }  // D - Deemed 18%
    else if (vat && /exempt/.test(taxName)) { taxRate = '-'; tax = '0'; vatFlag = '1'; catCode = '03'; }
    else if (vat && /zero/.test(taxName)) { taxRate = '0'; tax = '0'; vatFlag = '1'; catCode = '02'; }
    else if (vat && lineTax > 0) { taxRate = '0.18'; tax = r2(total - total / 1.18); vatFlag = '1'; catCode = '01'; }
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
      discountTotal: '', discountTaxRate: '', orderNumber: String(i),
      discountFlag: '2', deemedFlag: (catCode === '04' ? '1' : '2'), exciseFlag: (isExcise ? '1' : '2'),
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
    return g;
  });
  const gross = goodsDetails.reduce((s, g) => s + parseFloat(g.total), 0);
  const taxAmount = goodsDetails.reduce((s, g) => s + (parseFloat(g.tax) || 0), 0);
  const net = gross - taxAmount;
  const anyVat = goodsDetails.some(g => g.taxRate === '0.18');
  const catCode = goodsDetails[0] ? goodsDetails[0]._catCode : (anyVat ? '01' : '03');
  goodsDetails.forEach(g => delete g._catCode);
  const now = new Date();
  const d = invoice.IssueDate ? new Date(invoice.IssueDate) : now;
  const p = n => String(n).padStart(2, '0');
  const issuedDate = p(d.getDate()) + '/' + p(d.getMonth()+1) + '/' + d.getFullYear() + ' ' + p(now.getHours()) + ':' + p(now.getMinutes()) + ':' + p(now.getSeconds());

  // ── Buyer details - supports B2C, B2B, B2G, Foreign ──────────────────────
  // buyerType: '0'=Taxpayer(B2B/B2G with TIN), '1'=Citizen(B2C), '2'=Foreigner
  const custType = String(invoice.CustomerType || 'b2c').toLowerCase();
  const hasTin = !!(invoice.CustomerTIN && String(invoice.CustomerTIN).trim());
  let buyerType, buyerTin, buyerPassportNum, buyerCitizenship, buyerLegalName, buyerBusinessName, buyerAddress;
  if (custType === 'b2b') {
    buyerType = '0'; buyerTin = String(invoice.CustomerTIN || ''); buyerPassportNum = '';
    buyerCitizenship = ''; buyerLegalName = invoice.CustomerName || '';
    buyerBusinessName = invoice.CustomerName || ''; buyerAddress = invoice.CustomerAddress || '';
  } else if (custType === 'b2g') {
    buyerType = '0'; buyerTin = String(invoice.CustomerTIN || ''); buyerPassportNum = '';
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
    ? [{ taxCategoryCode: catCode, netAmount: r2(net), taxRate: (goodsDetails[0] ? goodsDetails[0].taxRate : (anyVat ? '0.18' : '0')), taxAmount: r2(taxAmount), grossAmount: r2(gross) }]
    : [];
  return {
    sellerDetails: { tin: cfg.tin, ninBrn: cfg.brn || '', legalName: cfg.businessName || cfg.tradeName || '', businessName: cfg.tradeName || cfg.businessName || '', address: cfg.businessAddress || 'Uganda', mobilePhone: cfg.phone || '', linePhone: '', emailAddress: cfg.email || '', placeOfBusiness: cfg.businessAddress || 'Uganda', referenceNo: (isRefund ? 'CN-' : '') + (invoice.Reference || '') },
    basicInformation: { invoiceNo: '', antifakeCode: '', deviceNo: cfg.deviceNo, issuedDate, operator: invoice.Operator || cfg.issuedBy || cfg.operator || cfg.businessName || cfg.tradeName || 'system', currency: invoice.Currency || 'UGX', oriInvoiceId: invoice.OriginalFDN || '', invoiceType: '1', invoiceKind: vat ? '1' : '2', dataSource: '103', invoiceIndustryCode: '101', isBatch: '0', isRefund: isRefund ? '1' : '0' },
    buyerDetails: { buyerTin, buyerNinBrn: '', buyerPassportNum, buyerLegalName, buyerBusinessName, buyerAddress, buyerEmail: invoice.CustomerEmail || '', buyerMobilePhone: invoice.CustomerPhone || '', buyerLinePhone: '', buyerPlaceOfBusi: invoice.CustomerDept || '', buyerType, buyerCitizenship, buyerSector: '', buyerReferenceNo: '' },
    goodsDetails,
    taxDetails,
    summary: { netAmount: r2(net), taxAmount: r2(taxAmount), grossAmount: r2(gross), itemCount: String(goodsDetails.length), modeCode: '1', remarks: (isRefund && invoice.CreditNoteReason ? invoice.CreditNoteReason + (invoice.Notes ? '. ' + invoice.Notes : '') : invoice.Notes || ''), qrCode: '' },
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
  const goodsDetails = base.goodsDetails.map(g => ({
    ...g,
    qty: negQty(g.qty),
    total: neg(g.total),
    tax: String(neg(g.tax)),
  }));
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
  const now = new Date();
  const p = n => String(n).padStart(2, '0');
  const applicationTime = `${now.getFullYear()}-${p(now.getMonth()+1)}-${p(now.getDate())} ${p(now.getHours())}:${p(now.getMinutes())}:${p(now.getSeconds())}`;
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
  res.json({
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
// Same /api/* auth as everything else (X-API-KEY), so this isn't public.
app.get('/api/admin/logs', (req, res) => {
  res.json({ days: logger.listDays() });
});
app.get('/api/admin/logs/:day', (req, res) => {
  const content = logger.readDay(req.params.day);
  if (content === null) return res.status(404).json({ error: 'No log for that day' });
  res.type('text/plain').send(content);
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
  logger.error('client: ' + trunc(redactSecrets(String(b.message || 'unknown error'), req), 500), {
    tab: trunc(b.tab, 40),
    breadcrumbs: Array.isArray(b.breadcrumbs) ? b.breadcrumbs.slice(-8).map(x => trunc(String(x), 60)) : undefined,
    stack: trunc(redactSecrets(String(b.stack || ''), req), 1500),
    url: trunc(b.url, 200),
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
    const eu = mode === 'production'
      ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
      : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
    const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
    const efrisUnits = await getEfrisMeasureUnits(tin, deviceNo, session, eu);
    if (!efrisUnits.length) return res.json({ success: false, error: 'EFRIS returned no measure units (T115 dictionary unavailable or empty). Kept the existing list.' });

    // Merge: start from static bundled units, then let EFRIS overwrite by code.
    let staticUnits = [];
    try { staticUnits = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'uom.json'), 'utf8')); } catch(_) {}
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
          if (taxGuid) { form.TaxCode = taxGuid; console.log(`   Tax code GUID → ${taxGuid} (${item.vat})`); }
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
        try { const tg = await mgrTaxCodeGuid(ep, accessToken, item.vat); if (tg) payload.TaxCode = tg; } catch(_) {}
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
      return res.json(ok
        ? { success: true, action, managerId: existingKey || null, comCodeWritten: !!(comCodeFieldKey && item.comCode), fieldsWritten: written }
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

app.get('/api/manager/accounts', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk required' });
  // Try several common Manager account-list endpoints. Manager API2 uses kebab-case
  // plural paths (cf. /inventory-items). Different editions expose different names.
  const paths = ['/profit-and-loss-statement-accounts', '/profit-and-loss-accounts', '/income-statement-accounts', '/balance-sheet-accounts', '/accounts', '/chart-of-accounts'];
  for (const path of paths) {
    try {
      const r = await managerCall(ep, tk, 'GET', path, null);
      console.log(`   accounts probe ${path} → HTTP ${r.status}`);
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
  inventoryItem:  '0dbdbf8a-d80c-48e6-b453-bb7862445b7c',
  nonInventoryItem:'7affe9ee-731f-4936-8acf-15cae7bcacee',
  customer:       'ec37c11e-2b67-49c6-8a58-6eccb7dd75ee',
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
  const BUYER = P.customer ? [P.salesInvoice, P.receipt, P.customer] : DOC;
  const ITEM = [P.inventoryItem, P.nonInventoryItem];
  const specs = [
    { create: 'FDN',              match: ['fdn', 'fiscal document number'],            placement: DOC },
    { create: 'Verification Code',match: ['verification code', 'antifake code'],       placement: DOC },
    { create: 'QR Code',          match: ['qr code'],                                  placement: DOC, type: 3 }, // Type 3 = Manager's native QR Code field (renders a scannable code)
    { create: 'Device Number',    match: ['device number'],                            placement: DOC },
    { create: 'Issued Time',      match: ['issued time'],                              placement: DOC },
    { create: 'Invoice ID',       match: ['invoice id'],                               placement: DOC },
    { create: 'Status',           match: ['status'],                                   placement: DOC },
    { create: 'Submission Date',  match: ['submission date'],                          placement: DOC },
    // Buyer fields - let the user tag a document before submission so the right
    // buyer type/TIN/payment mode flow into EFRIS (T109/T108).
    { create: 'Customer Type',    match: ['customer type', 'buyer type'],              placement: BUYER },
    { create: 'Buyer TIN',        match: ['buyer tin', 'customer tin'],                placement: BUYER },
    { create: 'Payment Method',   match: ['payment method', 'payment mode'],           placement: DOC },
    // Foreign-buyer fields (EFRIS requires these for non-Ugandan customers).
    { create: 'Passport / ID No', match: ['passport / id no', 'passport', 'passport no', 'id no'], placement: BUYER },
    { create: 'Nationality',      match: ['nationality', 'country'],                   placement: BUYER },
    { create: 'Commodity Code',   match: ['commodity code'],                           placement: ITEM },
    { create: 'Category Path',    match: ['category path', 'segment / class grouping'],placement: ITEM },
    { create: 'Price Currency',   match: ['price currency', 'sales currency', 'item currency'], placement: ITEM },
  ];
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
app.post('/api/manager/customers', async (req, res) => {
  const { managerEndpoint, accessToken } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  try {
    const r = await managerCall(ep, tk, 'GET', '/customers', null);
    const arr = (r.data && (r.data.customers || r.data.Customers)) || [];
    const customers = arr.map(c => ({ name: c.name || c.Name || '', code: c.code || c.Code || '', key: c.key || c.Key || '', type: '', tin: '' }));
    if (customers.length) {
      const list = await managerCall(ep, tk, 'GET', '/text-custom-fields', null);
      const nameByKey = {};
      for (const cf of ((list.data && list.data.textCustomFields) || [])) nameByKey[String(cf.key || cf.Key || '').toLowerCase()] = String(cf.name || '').trim().toLowerCase();
      const ENRICH_CAP = 60;
      await Promise.all(customers.slice(0, ENRICH_CAP).map(async c => {
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
      }));
      if (customers.length > ENRICH_CAP) console.log(`   customers list: enriched first ${ENRICH_CAP} of ${customers.length} with type/TIN`);
    }
    res.json({ success: true, customers });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Delete a Manager customer. DELETE alone isn't trusted (this session's rule:
// HTTP status codes lie) - read the record back and require it actually gone.
app.post('/api/manager/delete-customer', async (req, res) => {
  const { managerEndpoint, accessToken, key } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk || !key) return res.status(400).json({ success: false, error: 'managerEndpoint, accessToken and key required' });
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
  try {
    const placement = customer.placement || MGR_PLACEMENTS.customer || await discoverCustomerPlacement(ep, tk);
    // Reuse the SAME custom fields already created for documents - just ADD the
    // Customer placement to them (a Manager field can live on many forms). No
    // duplicate "EFRIS *" fields. Each concept maps to its existing field name.
    const specs = [
      { field: 'Customer Type',    aliases: ['customer type', 'buyer type'],                 val: customer.type },
      { field: 'Buyer TIN',        aliases: ['buyer tin', 'customer tin', 'tin'],            val: customer.tin },
      { field: 'Nationality',      aliases: ['nationality', 'country'],                      val: customer.nationality },
      { field: 'Passport / ID No', aliases: ['passport / id no', 'passport / id', 'passport', 'id no'], val: customer.passport },
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
            await managerCall(ep, tk, 'POST', '/text-custom-field-form', { Name: s.field, Placement: [MGR_PLACEMENTS.salesInvoice, MGR_PLACEMENTS.receipt, placement] });
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
app.post('/api/manager/ensure-efris-fields', async (req, res) => {
  const { managerEndpoint, accessToken, placements } = req.body || {};
  const ep = normEp(managerEndpoint || ''), tk = accessToken;
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
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
    for (const s of specs) {
      if (s.match.some(n => have.has(n))) { skipped.push(s.create); continue; }
      // Force the field Type explicitly (Manager: 0=single line, 1=paragraph,
      // 2=drop-down, 3=QR Code) so QR Code renders as a scannable code and the
      // rest stay single-line text - never inheriting a wrong Type from the template.
      const full = Object.assign({}, template, { Name: s.create, Placement: s.placement, Type: (s.type !== undefined ? s.type : 0) });
      try {
        let r = await managerCall(ep, tk, 'POST', '/text-custom-field-form', full);
        // If the richer payload is rejected, retry with the minimal shape so the
        // field is still created (richness is best-effort, never a blocker).
        if (!(r.status === 200 || r.status === 201) && Object.keys(template).length) {
          console.log(`   ⚠ rich create for "${s.create}" failed (HTTP ${r.status}) - retrying minimal`);
          r = await managerCall(ep, tk, 'POST', '/text-custom-field-form', { Name: s.create, Placement: s.placement, Type: (s.type !== undefined ? s.type : 0) });
        }
        if (r.status === 200 || r.status === 201) { created.push(s.create); console.log(`   ✓ created custom field: ${s.create}`); }
        else { failed.push({ field: s.create, status: r.status, error: r._cfChallenge ? 'Blocked by Cloudflare\'s browser-challenge page (not a Manager error) - add a WAF/Bot Fight Mode exception for this path' : ((r.data && (r.data.error || JSON.stringify(r.data))) || (r._htmlSnippet ? `HTTP ${r.status} - ${r._htmlSnippet}` : ('HTTP ' + r.status))) }); }
      } catch (e) { failed.push({ field: s.create, error: e.message }); }
    }
    res.json({ success: failed.length === 0, created, skipped, failed, templateUsed: tplField ? tplField.name : null,
      customerPlacement: P.customer || null,
      customerNote: P.customer ? undefined : 'Could not auto-detect Manager\'s Customer form placement, so the customer-object fields were skipped. The document-level buyer fields (Customer Type, Buyer TIN, Passport/ID, Nationality) were still created and are what EFRIS uses.' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
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
        code:  i.code || i.Code || i.ItemCode || '',
        name:  i.itemName || i.ItemName || i.name || i.Name || '',
        // The list returns the price as "SalePrice" (not Sales-); may be a {value,currency} object.
        price: num(sp),
        currency: cur(sp),
        type
      };
    };
    const inv = (invR.data && (invR.data.inventoryItems  || invR.data.InventoryItems  || [])).map(i => mapItem(i, 'inventory'));
    const ni  = (niR.data  && (niR.data.nonInventoryItems || niR.data.NonInventoryItems || [])).map(i => mapItem(i, 'service'));
    console.log(`[items-list] inventory=${inv.length} non-inventory=${ni.length} first=${JSON.stringify((inv[0]||ni[0])||{})}`);
    res.json({ success: true, items: [...inv, ...ni] });
  } catch(e) { res.status(500).json({ success: false, error: e.message }); }
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
    let receivedIn = receipt.receivedIn || '';
    if (!receivedIn) {
      try {
        const want = String(receipt.currency || 'UGX').toUpperCase();
        const bankR = await managerCall(ep, accessToken, 'GET', '/bank-and-cash-accounts', null);
        const arr = (bankR.data && (bankR.data.bankAndCashAccounts || bankR.data.BankAndCashAccounts)) || [];
        const accCur = a => String(a.currency || a.Currency || a.foreignCurrency || a.ForeignCurrency || '').toUpperCase();
        const nm = a => String(a.name || a.Name || '');
        const curOk = a => accCur(a) === want || (want === 'UGX' && !accCur(a) && !/eur|usd|gbp|kes|tzs|rwf|euro|dollar|pound/i.test(nm(a)));
        // Route to the bank/cash account that matches the PAYMENT MODE, so cash
        // doesn't land in the bank ledger. Match the account name to the method.
        const pm = String(receipt.paymentMethod || '').toLowerCase();
        let pmKey = null;
        if (/cash/.test(pm)) pmKey = /cash/i;
        else if (/mobile|momo|mtn|airtel/.test(pm)) pmKey = /mobile|momo|mtn|airtel/i;
        else if (/bank|transfer|eft|cheque|card|pos|credit|debit|visa|master/.test(pm)) pmKey = /bank|transfer|eft/i;
        // Match the receipt currency: an account in that currency; for UGX (base)
        // prefer one with no foreign currency set / no foreign code in its name.
        const pick =
          (pmKey ? arr.find(a => curOk(a) && pmKey.test(nm(a))) : null) ||   // payment mode + currency
          (pmKey ? arr.find(a => pmKey.test(nm(a))) : null) ||               // any account matching the mode
          arr.find(a => accCur(a) === want) ||
          (want === 'UGX' ? arr.find(a => !accCur(a) && !/eur|usd|gbp|kes|tzs|rwf|euro|dollar|pound/i.test(nm(a))) : null) ||
          (want === 'UGX' ? arr.find(a => !accCur(a)) : null) ||
          arr.find(a => !/eur|usd|gbp|kes|tzs|rwf|euro|dollar|pound/i.test(nm(a))) ||
          arr[0];
        if (pick) { receivedIn = pick.key || pick.Key || ''; console.log(`   Received-in account: "${nm(pick)}" (payment: ${receipt.paymentMethod || 'n/a'})`); }
      } catch(_) {}
    }
    const form = {};
    form.Date = receipt.date || new Date().toISOString().slice(0, 10);
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
    // Apply the branded theme: API-created receipts don't inherit Manager's "form
    // default" theme, so copy the CustomTheme from the most recent existing receipt
    // (the user installs the theme once and sets it on a receipt). Best-effort.
    try {
      const rl = await managerCall(ep, accessToken, 'GET', '/receipts?pageSize=1', null);
      const arr = (rl.data && (rl.data.receipts || rl.data.receiptsAndPayments)) || [];
      if (arr[0] && (arr[0].key || arr[0].Key)) {
        const rf = await managerCall(ep, accessToken, 'GET', '/receipt-form/' + (arr[0].key || arr[0].Key), null);
        const t = rf.data && (rf.data.CustomTheme || rf.data.Theme);
        if (t) { form.CustomTheme = t; console.log(`   Receipt theme copied from existing receipt: ${t}`); }
      }
    } catch (e) { console.log(`   Receipt theme copy skipped: ${e.message}`); }
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
      if (Object.keys(cfStr).length) form.CustomFields2 = { Strings: cfStr };
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
      return line;
    }));
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
    res.json({ success: true, key: newKey, reference: receipt.reference });
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
    // Not an inventory item - is it a non-inventory (service) item?
    try {
      const nr = await managerCall(ep, tk, 'GET', '/non-inventory-items', null);
      const narr = (nr.data && (nr.data.nonInventoryItems || nr.data.NonInventoryItems || [])) || [];
      if (match(narr)) return { key: null, reason: 'non-inventory' };
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

app.post('/api/manager/inventory-adjust', async (req, res) => {
  const b = req.body || {};
  const { managerEndpoint, accessToken } = b;
  if (!managerEndpoint || !accessToken) {
    return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken are required' });
  }
  const ep = normEp(managerEndpoint);
  const direction = (b.direction === 'out') ? 'out' : 'in';
  const date = b.date || new Date().toISOString().slice(0, 10);
  const description = b.description || (direction === 'in' ? 'Stock-in via EFRISConnect' : 'Stock adjustment via EFRISConnect');
  // Normalise to a list of {itemKey?, itemCode?, qty}
  let items = Array.isArray(b.items) ? b.items.slice()
            : (b.itemKey || b.itemCode) ? [{ itemKey: b.itemKey, itemCode: b.itemCode, qty: b.qty }] : [];
  items = items.map(i => ({ itemKey: i.itemKey || '', itemCode: i.itemCode || i.code || '', itemName: i.itemName || i.name || '', qty: parseFloat(i.qty != null ? i.qty : i.quantity) || 0, unitPrice: parseFloat(i.unitPrice != null ? i.unitPrice : i.unitCost) || 0 }))
               .filter(i => i.qty > 0 && (i.itemKey || i.itemCode || i.itemName));
  if (!items.length) return res.json({ success: false, error: 'No items with a positive quantity to mirror.' });

  const results = [];
  for (const it of items) {
    let key = it.itemKey;
    if (!key && (it.itemCode || it.itemName)) {
      const resolved = await resolveManagerItemKey(ep, accessToken, it.itemCode, it.itemName);
      key = resolved.key;
      if (!key) {
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
          Lines: [{ Item: key, Qty: it.qty, PurchaseUnitPrice: parseFloat(it.unitPrice) || 0 }]
        };
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

  // 2. Write-off template (needed before automated stock adjustments can work)
  try {
    const tpl = await findWriteOffLineTemplate(ep, tk);
    if (tpl) add('writeoff', 'Stock adjustment format', 'ok', `Write-off line format learned (fields: ${tpl.itemField}/${tpl.qtyField}).`);
    else add('writeoff', 'Stock adjustment format', 'warn', 'No manually created inventory write-off found to learn Manager\'s line format from.', 'Create ONE write-off manually in Manager (Inventory Write-offs → New Write-off, any item/qty). All automated adjustments copy its format.');
  } catch (e) { add('writeoff', 'Stock adjustment format', 'warn', e.message, 'Enable the Inventory Write-offs tab in Manager (Customize), then create one write-off manually.'); }

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
    else add('customfields', 'EFRIS custom fields', 'warn', `Missing: ${[!hasFdn && 'FDN field', !hasCom && 'commodity-code field'].filter(Boolean).join(', ')}.`, 'Run "Check / Create EFRIS Custom Fields" in Settings → Custom Fields.');
  } catch (e) { add('customfields', 'EFRIS custom fields', 'warn', e.message, 'Run "Check / Create EFRIS Custom Fields" in Settings → Custom Fields.'); }

  // 5. Chart of accounts reachable (needed by allocation picker + item sync)
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
  const ep = normEp(req.query.ep || '');
  const tk = req.query.tk || '';
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
  const eu = mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
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
  const eu = mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
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
    const t130 = await efrisCall(eu, efrisEnvEnc('T130', [t130Payload], tin, deviceNo, session.aesKey, session.privatePem));
    const outerRc = t130.data && t130.data.returnStateInfo ? t130.data.returnStateInfo.returnCode : null;
    const outerRm = t130.data && t130.data.returnStateInfo ? t130.data.returnStateInfo.returnMessage : '';
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
        const vr = await efrisCall(eu, efrisEnvEnc('T127', vp, tin, deviceNo, session.aesKey, session.privatePem));
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
    res.json({ success: ok, returnCode: itemRc, returnMessage: itemRm, alreadyExists,
      ghost, suggestedCode: ghost ? item.code + '-1' : undefined,
      unitProblem, sentUnit: uomCode, validUnits,
      error: ok ? undefined : (ghost ? itemRm : `EFRIS T130: ${itemRc} - ${itemRm}`) });
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
  const url = b.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    delete sessions[(b.tin||'') + '_' + (b.deviceNo||'')];
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
function efrisEndpoints(config) {
  const ura = config.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  const enabler = (config.enablerUrl || '').trim();
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
async function performInvoiceSubmission(invoice, config, eu) {
  const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
  if (!session.aesKey) throw new Error('No AES key available to encrypt T109');
  try {
    const goodsMap = await getRegisteredGoodsMap(config.tin, config.deviceNo, session, eu);
    annotateLinesWithRegisteredGoods(invoice, goodsMap);
  } catch (e) { console.log(`   goods-map annotate skipped: ${e.message}`); }
  const t109data = buildT109(invoice, config);
  t109data.goodsDetails.forEach(g => console.log(`   T109 line: item="${g.item}" itemCode="${g.itemCode}" uom="${g.unitOfMeasure}" taxRule="${g.taxRule}"`));
  let t109, rc, rm;
  for (let attempt = 1; attempt <= 3; attempt++) {
    t109 = await efrisCall(eu, efrisEnvEnc('T109', t109data, config.tin, config.deviceNo, session.aesKey, session.privatePem));
    rc = t109.data && t109.data.returnStateInfo ? t109.data.returnStateInfo.returnCode : null;
    rm = t109.data && t109.data.returnStateInfo ? t109.data.returnStateInfo.returnMessage : '';
    if (rc !== '15') break;
    console.log(`   T109 rc 15 (transient decrypt error) - retry ${attempt}/3`);
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
        id: Date.now(), submittedAt: issuedDate, fdn, antifakeCode, validationUrl,
        deviceNo: config.deviceNo, invoiceId, reference: invoice.Reference || invoice.reference || '',
        returnCode: rc, status: 'success', tin: config.tin,
        customerName: t109data.buyerDetails ? (t109data.buyerDetails.buyerLegalName || t109data.buyerDetails.buyerTin || '') : '',
        totalAmount: t109data.summary ? parseFloat(t109data.summary.grossAmount) || 0 : 0,
        currency: t109data.basicInformation ? t109data.basicInformation.currency || 'UGX' : 'UGX',
        invoiceKind: t109data.basicInformation ? t109data.basicInformation.invoiceKind || '' : '',
        mode: config.mode || 'sandbox',
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
        const dup = log.find(e => e.status === 'success' && String(e.reference || '').trim().toLowerCase() === ref.toLowerCase() && String(e.tin || config.tin) === String(config.tin));
        if (dup) return res.json({ success: false, duplicateRef: true, existingFdn: dup.fdn || '',
          error: `Reference "${ref}" was already fiscalised (FDN ${dup.fdn || '?'}). URA requires a unique reference per transaction. Use a new receipt number, or resubmit only if you are correcting a failed attempt.` });
      } catch(_) {}
    }
    // Try each endpoint (URA, then the local Offline Mode Enabler if configured).
    // A network failure moves to the next target; a URA business rejection is a
    // real result and stops here. If every target is unreachable → queue offline.
    const targets = efrisEndpoints(config);
    let result = null, lastNetErr = null, lastEndpointErr = null;
    for (const t of targets) {
      try {
        result = await performInvoiceSubmission(invoice, cfgForTarget(config, t), t.url);
        if (t.kind === 'enabler' && result) result.viaEnabler = true;
        lastNetErr = null; lastEndpointErr = null;
        break;
      } catch (subErr) {
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
      const offlineId = offlineEnqueue({ kind: 'invoice', invoice, cfgPublic: publicCfg(config), managerEndpoint: managerEndpoint || '', documentKey: documentKey || '', reference: invoice.Reference || '' });
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
  const eu = config.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    // T119: taxpayer query - look up a TIN to verify it exists and get details
    const t119 = await efrisCall(eu, efrisEnvEnc('T119', { tin: buyerTin, ninBrn: '', queryType: '1' }, config.tin, config.deviceNo, session.aesKey, session.privatePem));
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

// ── My details (T119 with own TIN) ────────────────────────────
app.post('/api/efris/my-details', async (req, res) => {
  const { config } = req.body || {};
  if (!config || !config.tin) return res.status(400).json({ success: false, error: 'config.tin required' });
  const eu = config.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    if (!session.aesKey) throw new Error('No AES key');
    const t119 = await efrisCall(eu, efrisEnvEnc('T119', { tin: config.tin, ninBrn: '', queryType: '1' }, config.tin, config.deviceNo, session.aesKey, session.privatePem));
    const rc = t119.data && t119.data.returnStateInfo ? t119.data.returnStateInfo.returnCode : null;
    const rm = t119.data && t119.data.returnStateInfo ? t119.data.returnStateInfo.returnMessage : '';
    let info = null;
    if (t119.data && t119.data.data && t119.data.data.content) {
      try { const s = aesDecryptStr(t119.data.data.content, session.aesKey); info = JSON.parse(s); } catch(e) {}
    }
    if (rc !== '00') return res.json({ success: false, error: 'URA ' + rc + ': ' + rm });
    const tp = (info && (info.taxpayer || info)) || {};
    const brn = (tp.ninBrn && !/non/i.test(tp.ninBrn)) ? tp.ninBrn : (tp.brn || '');
    const addr = String(tp.address || tp.placeOfBusiness || '').replace(/\s{2,}/g, ' ').trim();
    res.json({ success: true, legalName: tp.taxpayerLegalName || tp.legalName || tp.taxpayerName || '', businessName: tp.taxpayerName || tp.businessName || tp.legalName || '', address: addr, email: tp.contactEmail || '', phone: tp.contactMobile || tp.contactNumber || '', brn, tin: config.tin });
  } catch(e) {
    logger.error('my-details failed', { message: redactSecrets(e && e.message, req) });
    res.status(500).json({ success: false, error: e.message });
  }
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
    t108data.goodsDetails.forEach(g => console.log(`   CN line: item="${g.item}" itemCode="${g.itemCode}" uom="${g.unitOfMeasure}" qty=${g.qty} total=${g.total}`));
    // Per Interface Design v24.0.1, the Credit-Note Application interface is T110
    // (T108 is a query). Our payload is already a T110 application (reasonCode,
    // applicationTime, invoiceApplyCategoryCode). Send T110; if this EFRIS build
    // doesn't recognise it (older sandbox), fall back to T108 which worked before.
    const cnSubmit = async (code) => {
      const r = await efrisCall(eu, efrisEnvEnc(code, t108data, cnCfg.tin, cnCfg.deviceNo, session.aesKey, session.privatePem));
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
  const eu = config.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
    if (!session.aesKey) throw new Error('No AES key - private key not found or could not decrypt T104 session. Check that backend/data/private_key.pem exists and matches your EFRIS device.');
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
    const t106 = await efrisCall(eu, efrisEnvEnc('T106', t106data, config.tin, config.deviceNo, session.aesKey, session.privatePem));
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

// ── Stock-in (T131) ───────────────────────────────────────────
app.post('/api/efris/stock-in', rateLimit(30), async (req, res) => {
  const { supplierName, supplierTin, stockInDate, stockInType, branchId, remarks, productionBatchNo, productionDate, items, config } = req.body || {};
  if (!items || !items.length || !config || !config.tin) return res.status(400).json({ success: false, error: 'items and config required' });
  const eu = config.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
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
        stockInDate:       (stockInDate || new Date().toISOString().slice(0,10)).slice(0,10),
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
      console.log(`   T131 rc 15 (transient decrypt error) - retry ${attempt}/3`);
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
  const eu = config.mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
  try {
    const session = await getSession(config.tin, config.deviceNo, config.efrisPassword, eu, keyOverrideFrom(config));
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
        stockInDate:      (adjustDate || new Date().toISOString().slice(0,10)).slice(0,10),
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
async function saveEfrisToManager(ep, accessToken, key, efrisData, vatRegistered) {
  let formBase = '/sales-invoice-form';
  let getR = await managerCall(ep, accessToken, 'GET', '/sales-invoice-form/' + key, null);
  if (getR.status !== 200 || (getR.data && getR.data.error)) {
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
  setCFAny(['Status', 'EFRIS Status'], 'Submitted');
  setCFAny(['Submission Date', 'EFRIS Submission Date'], new Date().toISOString().slice(0,10));
  const docTypeLabel = vatRegistered ? 'Tax Invoice' : 'e-Receipt';
  if ('CustomTitle' in form || form.CustomTitle === undefined) form.CustomTitle = docTypeLabel;
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
  const { managerEndpoint, accessToken, originalKey, originalDocType, reason, referenceNo, efrisFdn, efrisInvoiceId, efrisAntifake, efrisQr, efrisSubDate } = req.body || {};
  if (!managerEndpoint || !accessToken || !originalKey) return res.status(400).json({ success: false, error: 'Missing required fields' });
  const ep = normEp(managerEndpoint);
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
  const today = new Date().toISOString().slice(0, 10);
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
  // Invoice/receipt lines store the price as SalesUnitPrice (UnitPrice is usually empty),
  // which is why the credit note showed 0.00. Read both and write both.
  if (Array.isArray(origForm.Lines)) cnForm.Lines = origForm.Lines.map(l => {
    const price = parseFloat(l.SalesUnitPrice != null ? l.SalesUnitPrice : (l.UnitPrice != null ? l.UnitPrice : l.Amount)) || 0;
    return { Item: l.Item, LineDescription: l.LineDescription, Qty: parseFloat(l.Qty) || 1, UnitPrice: price, SalesUnitPrice: price };
  });
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
      if (r.status !== 404) lastCnErr = `${path} HTTP ${r.status}: ${JSON.stringify(r.data || '').slice(0, 150)}`;
    } catch (e) { lastCnErr = path + ': ' + e.message; }
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
    if (fallbackForm.Lines) {
      fallbackForm.Lines = fallbackForm.Lines.map(l => {
        const price = parseFloat(l.SalesUnitPrice != null ? l.SalesUnitPrice : (l.UnitPrice != null ? l.UnitPrice : l.Amount)) || 0;
        return { ...l, Qty: -(parseFloat(l.Qty) || 1), UnitPrice: price, SalesUnitPrice: price };
      });
    }
    // Overwrite the cloned (original's) EFRIS custom fields with the credit note's.
    try { const cfMeta = await mgrTextCustomFields(ep, accessToken); applyCnEfris(fallbackForm, cfMeta); } catch (_) {}
    const fallR = await managerCall(ep, accessToken, 'POST', origFormBase, fallbackForm);
    let newKey = null;
    if (fallR.data && fallR.data.key) newKey = fallR.data.key;
    else if (Array.isArray(fallR.data) && fallR.data.length) newKey = fallR.data[fallR.data.length - 1].key;
    console.log(`   Fallback negative ${origFormBase} → key: ${newKey || 'unknown'}`);
    return res.json({ success: true, key: newKey, method: origFormBase + ' (negative fallback)' });
  } catch(e) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// Return the live T115 dictionary's structure for inspection - used to identify
// which section holds the goods measure-unit codes EFRIS validates against.
app.post('/api/efris/dictionary-dump', async (req, res) => {
  const { tin, deviceNo, efrisPassword, mode } = req.body || {};
  if (!tin || !deviceNo) return res.status(400).json({ success: false, error: 'tin and deviceNo required' });
  const eu = mode === 'production'
    ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation'
    : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
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
        const authWall = r.statusCode === 401 || r.statusCode === 403;
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
app.post('/api/manager/detect', async (req, res) => {
  const host = '127.0.0.1';
  // Ports people actually see for Manager (fixed installs / container host) - tried first.
  const common = [8080, 8081, 8082, 8090, 8443, 8888, 8889, 9090, 9091, 9000, 55667, 44300, 3100];
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
  const enablerUrl = (req.query.enablerUrl || '').trim();
  const enablerMode = (req.query.enablerMode || (enablerUrl ? 'fallback' : 'off'));
  const key = mode + '|' + enablerUrl + '|' + enablerMode;
  const now = Date.now();
  if (_connCache.data && _connCache.key === key && (now - _connCache.ts) < 15000) {
    return res.json({ ..._connCache.data, cached: true, pending: loadQueue().filter(e => e.status === 'pending').length });
  }
  const uraHost = mode === 'production' ? 'https://efrisws.ura.go.ug/' : 'https://efristest.ura.go.ug/';
  const [ura, enabler] = await Promise.all([
    pingUrl(uraHost, 3500),
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
  const key = String(req.query.key || '').trim();
  if (!target || target === 'UGX') return res.json({ success: true, rate: 1, source: 'UGX base' });
  const today = new Date().toISOString().slice(0, 10);
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
    } catch (e) { console.log('FX history (key) failed: ' + e.message); }
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
      const d = /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : new Date().toISOString().slice(0, 10);
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
  const d = date || new Date().toISOString().slice(0, 10);
  // Try the known Manager foreign-exchange-rate form path. Report the raw result
  // so the operator (or a later verification pass) can see exactly what happened.
  try {
    const r = await managerCall(ep, tk, 'POST', '/foreign-exchange-rate-form', { Date: d, Currency: cur, Rate: rt });
    if (r._html) return res.json({ success: false, error: 'Manager returned a login/HTML page - check the access token', verified: false });
    const ok = r.status >= 200 && r.status < 300;
    res.json({ success: ok, verified: ok, status: r.status, currency: cur, rate: rt, date: d,
      note: ok ? 'Pushed to Manager (confirm it appears under Settings → Exchange Rates).'
               : 'Manager did not accept the exchange-rate form - the path/fields need confirming for this build.', data: r.data });
  } catch (e) { res.json({ success: false, error: e.message, verified: false }); }
});

// ── Currency scan: what base + foreign currencies does this Manager business have? ──
app.get('/api/manager/currencies', async (req, res) => {
  const { ep, tk } = mgrCreds(req);
  if (!ep || !tk) return res.status(400).json({ success: false, error: 'ep and tk are required' });
  let base = null, foreign = [], baseDebug = {};
  // Base currency is a singleton form. Different builds expose it at slightly
  // different paths / shapes, so try a few and accept any that yields a code.
  for (const p of ['/base-currency-form', '/base-currency', '/base-currency-settings']) {
    try {
      const b = await managerCall(ep, tk, 'GET', p);
      baseDebug[p] = b.status;
      if (b.status === 200 && b.data && !b.data.error) {
        const d = b.data.baseCurrency || b.data.BaseCurrency || b.data;
        const code = d.Code || d.code || d.currency || d.Currency || '';
        if (code) { base = { code: String(code).toUpperCase(), name: d.Name || d.name || '' }; break; }
      }
    } catch(_) {}
  }
  try {
    const f = await managerCall(ep, tk, 'GET', '/foreign-currencies');
    const arr = (f.data && (f.data.foreignCurrencies || f.data.currencies || f.data.foreignCurrency)) || [];
    foreign = (Array.isArray(arr) ? arr : []).map(c => ({ key: c.key || c.Key || '', code: c.code || c.Code || '', name: c.name || c.Name || '' })).filter(c => c.code);
  } catch(_) {}
  res.json({ success: true, base: (base && base.code) ? base : null, foreign, baseDebug });
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
  const formPath = isBase ? '/base-currency-form' : '/foreign-currency-form';
  const body = isBase
    ? { Code: cc, Name: name }
    : { Code: cc, Name: name, Prefix: prefix || '', Suffix: suffix || '', DecimalPlaces: (decimalPlaces != null ? Number(decimalPlaces) : 2) };
  try {
    const r = await managerCall(ep, tk, 'POST', formPath, body);
    if (r._html) return res.json({ success: false, error: 'Manager returned a login/HTML page - check the access token' });
    const ok = r.status >= 200 && r.status < 300;
    res.json({ success: ok, status: r.status, code: cc,
      note: ok ? 'Created in Manager' : 'Manager did not accept the currency form (path/fields may differ for this build).', data: r.data });
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
    const eu = mode === 'production' ? 'https://efrisws.ura.go.ug/ws/taapp/getInformation' : 'https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation';
    // T127 = Goods/Services Inquiry (query goods registered under this TIN).
    // NOTE: T130 is goods *registration* (upload) and only echoes the request back -
    // it must NOT be used for search. T127 takes a single object (not a batch array).
    // `query` is a NAME substring (goodsName) - it does NOT match against goodsCode,
    // so a caller that already knows the exact code (e.g. Stock Management's
    // item-code lookup) must pass `goodsCode` instead, or EFRIS returns 0 records.
    const GOODS_SEARCH_IFACE = 'T127';
    const payload = { goodsCode: goodsCode || '', goodsName: query || '', commodityCategoryCode: '', pageNo: '1', pageSize: '99' };
    const sessionKey = tin + '_' + deviceNo;
    let items = [], outerRc, outerRm, pageInfo = null;
    // One retry with a forced-fresh session: a decrypt failure on a *reused*
    // cached session ("wrong final block length") looks like the server-side
    // session/key had gone stale in a way our 30-min in-memory cache didn't
    // detect - dropping the cache and re-doing the T101/T104/T103 handshake
    // resolves that class of failure without surfacing a confusing 0-results.
    for (let attempt = 1; attempt <= 2; attempt++) {
      const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
      const t131 = await efrisCall(eu, efrisEnvEnc(GOODS_SEARCH_IFACE, payload, tin, deviceNo, session.aesKey, session.privatePem));
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
      if (attempt === 1) { delete sessions[sessionKey]; console.log('   Dropping cached session, retrying T127 with a fresh one…'); }
      else logger.error('search-goods decrypt failed after session retry', { message: decryptErr.message });
    }
    // Pagination: on a full catalog load, pull the remaining pages so the picker +
    // offline cache hold EVERY registered good, not just the first page.
    if (isFullLoad && pageInfo && Number(pageInfo.pageCount) > 1) {
      try {
        const session = await getSession(tin, deviceNo, efrisPassword, eu, keyOverrideFrom(req.body));
        for (let p = 2; p <= Number(pageInfo.pageCount); p++) {
          const pr = await efrisCall(eu, efrisEnvEnc(GOODS_SEARCH_IFACE, { ...payload, pageNo: String(p) }, tin, deviceNo, session.aesKey, session.privatePem));
          if (pr.data?.data?.content) {
            const raw = efrisDecodeJson(pr.data.data.content, session.aesKey);
            if (raw) { const pd = JSON.parse(raw); items = items.concat(pd.records || pd.goodsList || pd.list || []); }
          }
        }
        console.log(`   T127 paginated: ${pageInfo.pageCount} pages, ${items.length} total`);
      } catch (e) { console.log(`   T127 pagination stopped: ${e.message}`); }
    }
    console.log(`   T127 search found ${items.length} items`);
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

let _logWriting = false;
const _logQueue = [];
function appendSubmissionLog(entry) {
  _logQueue.push(entry);
  if (!_logWriting) _flushLogQueue();
}
function _flushLogQueue() {
  if (!_logQueue.length) { _logWriting = false; return; }
  _logWriting = true;
  const entry = _logQueue.shift();
  let log = [];
  try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(e) {}
  log.unshift(entry);
  if (log.length > 1000) log = log.slice(0, 1000);
  fs.writeFile(SUBMISSION_LOG_FILE, JSON.stringify(log, null, 2), () => _flushLogQueue());
}

// Issued-document retrieval: the extension saves a render snapshot (the receipt.html
// query string) keyed by FDN when a document is issued, so History can re-open the
// ACTUAL rendered document later - not just its reference. Stored server-side so it
// survives browser cache clears and is shared across sessions on the same relay.
const RECEIPT_SNAP_FILE = path.join(DATA_DIR, 'receipt_snapshots.json');
function _readSnaps() { try { return JSON.parse(fs.readFileSync(RECEIPT_SNAP_FILE, 'utf8')); } catch(e) { return {}; } }
app.post('/api/receipt-snapshot', (req, res) => {
  const { key, query } = req.body || {};
  if (!key || !query) return res.status(400).json({ success: false, error: 'key and query required' });
  const map = _readSnaps();
  map[String(key)] = { query: String(query), savedAt: Date.now() };
  // Keep the most recent 1000 snapshots.
  const keys = Object.keys(map);
  if (keys.length > 1000) keys.sort((a, b) => (map[a].savedAt || 0) - (map[b].savedAt || 0)).slice(0, keys.length - 1000).forEach(k => delete map[k]);
  fs.writeFile(RECEIPT_SNAP_FILE, JSON.stringify(map), () => {});
  res.json({ success: true });
});
app.get('/api/receipt-snapshot', (req, res) => {
  const hit = _readSnaps()[String(req.query.key || '')];
  if (!hit) return res.json({ success: false, error: 'No saved document for this reference' });
  res.json({ success: true, query: hit.query });
});

app.get('/api/submission-log', (req, res) => {
  try {
    let log = [];
    try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(e) {}
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 1000);
    const q = (req.query.q || '').toLowerCase();
    const filtered = q ? log.filter(e =>
      (e.fdn || '').toLowerCase().includes(q) ||
      (e.invoiceId || '').toLowerCase().includes(q) ||
      (e.reference || '').toLowerCase().includes(q) ||
      (e.customerName || '').toLowerCase().includes(q)
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
    let log = []; try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(_) {}
    const ref = String(b.reference || '').trim();
    if (ref && log.some(e => e.managerOnly && String(e.reference || '').trim() === ref)) return res.json({ success: true, deduped: true });
    log.unshift({
      id: Date.now(), managerOnly: true, status: 'manager-only', fdn: '',
      reference: b.reference || '', customerName: b.customerName || '',
      totalAmount: b.totalAmount || 0, currency: b.currency || 'UGX',
      invoiceKind: '3', mode: b.mode || '', docKey: b.docKey || '',
      submittedAt: b.submittedAt || new Date().toISOString()
    });
    if (log.length > 5000) log = log.slice(0, 5000);
    fs.writeFile(SUBMISSION_LOG_FILE, JSON.stringify(log, null, 2), () => {});
    res.json({ success: true });
  } catch(e) { res.json({ success: false, error: e.message }); }
});

// Z daily report (URS §9.17) - end-of-day summary of a full day's fiscalised
// sales (00:00:00-23:59:59) built from the submission log: document count, and
// gross/tax/net totals by currency. `date` = YYYY-MM-DD (defaults to today).
app.get('/api/z-report', (req, res) => {
  try {
    const date = (req.query.date || new Date().toISOString().slice(0, 10)).slice(0, 10);
    let log = []; try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(_) {}
    const day = log.filter(e => String(e.submittedAt || '').slice(0, 10) === date && (e.status ? e.status === 'success' : true));
    const byCurrency = {};
    let count = 0, credits = 0;
    for (const e of day) {
      const cur = e.currency || 'UGX';
      const amt = parseFloat(e.totalAmount) || 0;
      const isCredit = amt < 0 || String(e.returnCode) === 'CN' || /credit/i.test(e.docType || '');
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
    const hit = log.find(e => String(e.fdn || '').trim() === fdn);
    if (!hit) return res.json({ success: false, error: 'FDN not found in local submission history. Enter the original invoice ID manually if you have it.' });
    res.json({ success: true, fdn: hit.fdn, invoiceId: hit.invoiceId || '', reference: hit.reference || '', customerName: hit.customerName || '', amount: hit.totalAmount || 0, currency: hit.currency || 'UGX' });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/submission-log/:id', (req, res) => {
  try {
    let log = [];
    try { log = JSON.parse(fs.readFileSync(SUBMISSION_LOG_FILE, 'utf8')); } catch(e) {}
    const id = parseInt(req.params.id);
    log = log.filter(e => e.id !== id);
    fs.writeFileSync(SUBMISSION_LOG_FILE, JSON.stringify(log, null, 2));
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
    brn: c.brn, phone: c.phone, email: c.email, vatRegistered: !!c.vatRegistered };
}
function loadQueue() { try { return JSON.parse(fs.readFileSync(OFFLINE_QUEUE_FILE, 'utf8')); } catch(e) { return []; } }
function saveQueue(q) { try { fs.writeFileSync(OFFLINE_QUEUE_FILE, JSON.stringify(q, null, 2)); } catch(e) { console.log('offline queue write error: ' + e.message); } }
function offlineEnqueue(entry) {
  const q = loadQueue();
  const id = 'off_' + Date.now() + '_' + Math.floor((process.hrtime()[1] % 100000));
  q.push({ id, createdAt: new Date().toISOString(), status: 'pending', attempts: 0, lastError: '', ...entry });
  saveQueue(q);
  return id;
}

app.get('/api/offline-queue', (req, res) => {
  const q = loadQueue();
  res.json({ success: true, pending: q.filter(e => e.status === 'pending').length,
    items: q.map(e => ({ id: e.id, createdAt: e.createdAt, kind: e.kind, reference: e.reference, status: e.status, attempts: e.attempts, lastError: e.lastError, fdn: e.fdn || '' })) });
});

app.delete('/api/offline-queue/:id', (req, res) => {
  const q = loadQueue().filter(e => e.id !== req.params.id);
  saveQueue(q);
  res.json({ success: true });
});

// Flush the queue: re-submit each pending item to EFRIS using the secrets supplied
// now (efrisPassword + Manager accessToken). Successful items get an FDN, are
// written back to the source Manager document, and removed from the queue.
app.post('/api/offline-queue/flush', rateLimit(20), async (req, res) => {
  const { config, accessToken } = req.body || {};
  const q = loadQueue();
  const pending = q.filter(e => e.status === 'pending');
  if (!pending.length) return res.json({ success: true, processed: 0, results: [] });
  if (!config || !config.efrisPassword) return res.status(400).json({ success: false, error: 'EFRIS password required to flush the offline queue' });
  const results = [];
  for (const entry of pending) {
    // Merge in the caller's current Enabler settings so flush can also route to it.
    const cfg = { ...entry.cfgPublic, efrisPassword: config.efrisPassword, enablerUrl: config.enablerUrl, enablerMode: config.enablerMode, efrisKeyPath: config.efrisKeyPath, efrisKeyPem: config.efrisKeyPem, efrisKeyPassphrase: config.efrisKeyPassphrase };
    const targets = efrisEndpoints(cfg);
    entry.attempts = (entry.attempts || 0) + 1;
    try {
      let r = null, netErr = null;
      for (const t of targets) {
        try { r = await performInvoiceSubmission(entry.invoice, cfgForTarget(cfg, t), t.url); netErr = null; break; }
        catch (te) { if (isNetworkError(te)) { netErr = te; continue; } throw te; }
      }
      if (!r && netErr) throw netErr;
      if (r.ok) {
        entry.status = 'done'; entry.fdn = r.fdn;
        // Best-effort write-back to the source Manager document.
        if (entry.documentKey && entry.managerEndpoint && accessToken) {
          try { await saveEfrisToManager(normEp(entry.managerEndpoint), accessToken, bareKey(entry.documentKey), r, cfg.vatRegistered); } catch(e) { console.log('offline write-back error: ' + e.message); }
        }
        results.push({ id: entry.id, reference: entry.reference, ok: true, fdn: r.fdn });
      } else {
        entry.lastError = 'URA ' + r.returnCode + ': ' + r.returnMessage;
        results.push({ id: entry.id, reference: entry.reference, ok: false, error: entry.lastError });
      }
    } catch (e) {
      entry.lastError = e.message;
      results.push({ id: entry.id, reference: entry.reference, ok: false, error: e.message, network: isNetworkError(e) });
      if (isNetworkError(e)) break; // still offline - stop, keep the rest queued
    }
  }
  // Persist: drop completed entries, keep the rest with updated attempts/errors.
  saveQueue(loadQueue().map(e => { const u = q.find(x => x.id === e.id); return u || e; }).filter(e => e.status !== 'done'));
  res.json({ success: true, processed: results.length, results, remaining: loadQueue().filter(e => e.status === 'pending').length });
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
  const now = new Date();
  const year  = String(now.getFullYear());
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const parts = [];
  for (const seg of (s.segments || [])) {
    if (seg === 'prefix'   && s.prefix)   parts.push(s.prefix);
    if (seg === 'division' && s.division) parts.push(s.division);
    if (seg === 'project'  && s.project)  parts.push(s.project);
    if (seg === 'year')    parts.push(year);
    if (seg === 'month')   parts.push(month);
    if (seg === 'counter') parts.push(String(counter).padStart(s.digits || 4, '0'));
  }
  return parts.join(s.separator === 'none' ? '' : (s.separator || '-'));
}

function resolveNext(s) {
  const now = new Date();
  const year  = String(now.getFullYear());
  const ym    = year + '-' + String(now.getMonth() + 1).padStart(2, '0');
  const startAt = parseInt(s.startAt) || 1;
  let counter = (s.lastCounter || 0) + 1;
  // When a reset period rolls over, restart at the series' starting number - NOT
  // hardcoded 1 (otherwise the configured start, e.g. 25, is ignored).
  if (s.resetOn === 'yearly'  && s.lastReset && s.lastReset !== year) counter = startAt;
  if (s.resetOn === 'monthly' && s.lastReset && s.lastReset !== ym)   counter = startAt;
  return counter;
}

app.get('/api/number-series', (req, res) => {
  const series = loadSeries();
  const now = new Date();
  const year = String(now.getFullYear());
  const ym   = year + '-' + String(now.getMonth() + 1).padStart(2, '0');
  res.json(series.map(s => ({
    ...s,
    preview: buildNumber(s, resolveNext(s))
  })));
});

app.post('/api/number-series', (req, res) => {
  const series = loadSeries();
  const now = new Date();
  const year = String(now.getFullYear());
  const ym   = year + '-' + String(now.getMonth() + 1).padStart(2, '0');
  // Initialise lastReset to the CURRENT period so the reset rule doesn't fire on the
  // very first number and wipe out the configured starting number.
  const lastReset = req.body.resetOn === 'monthly' ? ym : (req.body.resetOn === 'yearly' ? year : '');
  const startAt = parseInt(req.body.startAt) || 1;
  const s = { ...req.body, id: crypto.randomUUID(), startAt, lastCounter: startAt - 1, lastReset };
  series.push(s);
  saveSeries(series);
  res.json({ success: true, series: { ...s, preview: buildNumber(s, resolveNext(s)) } });
});

app.put('/api/number-series/:id', (req, res) => {
  const series = loadSeries();
  const idx = series.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  series[idx] = { ...series[idx], ...req.body, id: req.params.id, lastCounter: series[idx].lastCounter, lastReset: series[idx].lastReset };
  saveSeries(series);
  res.json({ success: true, series: { ...series[idx], preview: buildNumber(series[idx], resolveNext(series[idx])) } });
});

app.delete('/api/number-series/:id', (req, res) => {
  const series = loadSeries();
  const filtered = series.filter(s => s.id !== req.params.id);
  saveSeries(filtered);
  res.json({ success: true });
});

app.post('/api/number-series/:id/preview', (req, res) => {
  const series = loadSeries();
  const s = series.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ success: false, error: 'Not found' });
  res.json({ success: true, number: buildNumber(s, resolveNext(s)) });
});

app.post('/api/number-series/:id/next', (req, res) => {
  const series = loadSeries();
  const idx = series.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  const s = series[idx];
  const now = new Date();
  const year = String(now.getFullYear());
  const ym   = year + '-' + String(now.getMonth() + 1).padStart(2, '0');
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

// Create/update a tenant's credentials (encrypted at rest). Requires a working
// Manager token for the given endpoint (proves the caller owns that business).
app.post('/api/tenant', async (req, res) => {
  const b = req.body || {};
  const id = String(b.id || b.tin || '').trim();
  if (!id) return res.status(400).json({ success: false, error: 'tenant id (or TIN) required' });
  if (b.managerEndpoint && b.managerToken) {
    const ok = await verifyManagerAccess(b.managerEndpoint, b.managerToken);
    if (!ok) return res.status(403).json({ success: false, error: 'Manager token cannot access that endpoint - not authorised to store credentials for this business.' });
  }
  try {
    const meta = vault.putTenant(id, {
      tin: b.tin, deviceNo: b.deviceNo, mode: b.mode, businessName: b.businessName,
      tradeName: b.tradeName, address: b.address, brn: b.brn, phone: b.phone, email: b.email,
      vatRegistered: !!b.vatRegistered,
      efrisPrivateKeyPem: b.efrisPrivateKeyPem, efrisPassphrase: b.efrisPassphrase,
      efrisPrivateKeyPath: b.efrisPrivateKeyPath,
      managerEndpoint: b.managerEndpoint, managerToken: b.managerToken,
      enablerUrl: b.enablerUrl, enablerMode: b.enablerMode, enablerDeviceNo: b.enablerDeviceNo,
    });
    res.json({ success: true, tenant: meta });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/tenant', (req, res) => {
  try { res.json({ success: true, tenants: vault.listTenants() }); }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.delete('/api/tenant/:id', (req, res) => {
  try { vault.delTenant(req.params.id); res.json({ success: true }); }
  catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ══════════════════════════════════════════════════════════════
//  /extension ROUTE - serve EXTENSION_HTML
// ══════════════════════════════════════════════════════════════
// Inject API key into any HTML page we serve
function injectApiKey(html) {
  return html.replace('</head>', `<script>window.__API_KEY="${API_KEY}";</script></head>`);
}

app.get('/extension', (req, res) => {
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', 'frame-ancestors *');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(injectApiKey(EXTENSION_HTML));
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
function getBrandedThemeHtml() {
  let html = fs.readFileSync(path.join(FRONTEND, 'manager-theme.html'), 'utf8');
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
    res.send(getBrandedThemeHtml());
  } catch (e) { res.status(500).send('theme not found'); }
});

// Install/update the branded theme in Manager via the API - the same idea as
// "Check/Create EFRIS Custom Fields", so users don't copy-paste and updates land
// automatically. Manager's theme object shape isn't documented, so we try a few
// field-name variants; pass themeKey to update an existing theme in place.
app.post('/api/manager/install-theme', async (req, res) => {
  const { managerEndpoint, accessToken, themeKey } = req.body || {};
  if (!managerEndpoint || !accessToken) return res.status(400).json({ success: false, error: 'managerEndpoint and accessToken required' });
  const ep = normEp(managerEndpoint);
  let html; try { html = getBrandedThemeHtml(); } catch (e) { return res.status(500).json({ success: false, error: 'theme file missing' }); }
  const NAME = 'EFRISConnect';
  // Manager has used different field names for the theme body across builds. Send
  // ALL candidate content fields in one payload - Manager fills the one it knows
  // and ignores the rest, so we don't have to guess which build we're on.
  const body = { Name: NAME, Content: html, Template: html, Html: html, Theme: html, Body: html, Value: html };
  const key = bareKey(themeKey || '');
  const path = '/custom-theme-form' + (key ? '/' + key : '');
  let newKey = key || null;
  try {
    const r = await managerCall(ep, accessToken, 'POST', path, body);
    if (r.status === 401 || r.status === 403) {
      return res.json({ success: false, gated: true, error: 'Manager rejected the theme API (HTTP ' + r.status + '). This access token lacks theme permission - use the copy-paste method.' });
    }
    if (!(r.status >= 200 && r.status < 400)) {
      return res.json({ success: false, error: 'Manager did not accept the theme (HTTP ' + r.status + '). Use the copy-paste method.' });
    }
    newKey = newKey || (r.data && (r.data.key || r.data.Key)) || null;
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
  return res.json({ success: true, key: newKey, updated: !!key, defaults });
});

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
      res.send(injectApiKey(html));
    } catch(e) {
      res.status(500).send('Frontend not found');
    }
  }
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
      httpsServer.on('error', e => console.log('HTTPS startup error: ' + e.message));
      return;
    }
    // 2. Fallback (dev only): openssl-generated self-signed cert - UNTRUSTED, so
    //    Manager will reject it. Fine for a browser you click through; not for the
    //    embedded extension iframe. Prefer Setup-Https above.
    const { execSync } = require('child_process');
    const os = require('os');
    try {
      execSync('openssl version', { stdio: 'ignore' });
      const tmpDir = os.tmpdir();
      const keyFile  = path.join(tmpDir, 'efris_key.pem');
      const certFile = path.join(tmpDir, 'efris_cert.pem');
      execSync('openssl req -x509 -newkey rsa:2048 -keyout "' + keyFile + '" -out "' + certFile + '" -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"', { stdio: 'ignore' });
      const sslOptions2 = { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
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

// ── Start HTTP server (only when run directly, not during tests) ──────────
if (require.main === module) {
  app.listen(PORT, BIND_HOST, () => {
    console.log('=======================================================');
    console.log('Uganda EFRIS Connect + Goods Configurator');
    console.log('Tukei Hope Initiative | EMC/CBO/025');
    console.log('=======================================================');
    console.log('HTTP running on port ' + PORT + ' (will redirect to HTTPS once it is up)');
    tryStartHTTPS();
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
}

module.exports = app;
// Exposed for regression tests (decrypt paths). Not used at runtime.
module.exports._test = { efrisDecodeJson, aesDecryptStr, aesEncryptB64, aesAlgo };
