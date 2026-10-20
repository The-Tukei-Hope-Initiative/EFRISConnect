'use strict';
// Activity log: every line the relay console prints, kept so an admin can read it
// inside the extension (Settings > Logs). Each line becomes
//   { seq, time, level: 'info'|'warn'|'error', text, debug, tenantId?, user? }
// tenantId/user come from the request being handled when the line was printed
// (server.js passes a getter in; this module never requires server.js). The last
// RING_MAX entries stay in memory for the live view; every entry is also appended
// to <logDir>/<EAT day>-activity.log as one JSON line.
// Secrets are masked BEFORE anything is stored. Nothing here may throw into the
// code that is logging.
const fs = require('fs');
const path = require('path');

const RING_MAX = 2000;
const ring = [];
// Monotonic across restarts (start from the clock), so a page polling with
// after=<seq> never mistakes a new run's lines for ones it already has.
let seq = Date.now() * 1000;
let logDir = '';
let ctxGetter = null;
const known = new Set();   // exact secret values seen (vault secrets, the service key)

// Uganda time (EAT, UTC+3) day for a timestamp, whatever the server's time zone.
function eatDay(ms) { return new Date((ms == null ? Date.now() : ms) + 3 * 3600000).toISOString().slice(0, 10); }
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
function validDay(d) {
  if (typeof d !== 'string' || !DAY_RE.test(d)) return false;
  const t = Date.parse(d + 'T00:00:00Z');
  return !isNaN(t) && new Date(t).toISOString().slice(0, 10) === d;
}

// ── Masking ──
const ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]/g;
// A secret-looking field name: anything containing token, key, pem, pwd, pass*,
// secret, auth or cookie (managerToken, aesKey, privateKey, efrisKeyPem, pwd,
// passphrase, apiAccessToken, X-API-KEY, Authorization, ...).
const NAME = '[A-Za-z0-9_.-]*(?:token|key|pem|pwd|pass(?:word|wd|phrase|code)?|secret|auth[A-Za-z]*|cookie|credential)[A-Za-z0-9_.-]*';
// Names that must hold a secret: what a request body is learned from (a plain
// "key" there is a Manager document key, not a secret).
const LEARN_NAME = /token|pass(word|wd|phrase|code)?$|pwd|secret|pem$|private.?key|api.?key|aes.?key|access.?key|session.?key|authorization|cookie|credential/i;
const HEADER = '(?:proxy-)?authorization|x-api-key|x-manager-token|x-backend-secret|x-fx-key|cookie';
const SCHEME = '(?:Bearer|Basic|Token|Digest|ApiKey|Negotiate)';
const RULES = [
  // PEM blocks (keys, certificates), whole block
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, '[key removed]'],
  // Header values, whatever the scheme: Authorization: Token x, X-API-KEY: x,
  // "authorization":"Basic x". The scheme word stays, the value goes.
  [new RegExp('(\\b(?:' + HEADER + ')["\']?\\s*[:=]\\s*["\']?)(' + SCHEME + '\\s+)?([^\\s"\',;}&]+)', 'gi'),
    (m, p1, scheme, v) => (/^\*+$/.test(v) ? m : p1 + (scheme || '') + '***')],
  // Bearer <token> / Basic <creds> anywhere
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{6,}/gi, '$1 ***'],
  // Personal details (Data Protection and Privacy Act): email addresses and
  // Ugandan phone numbers never reach a log view, export or support bundle.
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[email]'],
  [/(?:\+?256[\s-]?|\b0)7\d{2}[\s-]?\d{3}[\s-]?\d{3}\b/g, '[phone]'],
  // JSON escaped inside a string: \"password\":\"x\"
  [new RegExp('(\\\\+"' + NAME + '\\\\+"\\s*:\\s*\\\\+")((?:(?!\\\\+").)*)', 'gi'), '$1***'],
  // JSON / object form, quoted name: "managerToken":"x", 'aesKey': 'x', "pwd": 123
  [new RegExp('((["\'])' + NAME + '\\2\\s*:\\s*)("(?:[^"\\\\]|\\\\.)*"|\'(?:[^\'\\\\]|\\\\.)*\'|[^\\s,;}\\]]+)', 'gi'),
    (m, p1, q, v) => (/^["']?\*+["']?$/.test(v) ? m : p1 + (/^["']/.test(v) ? v[0] + '***' + v[0] : '***'))],
  // query / form form: password=x, apiAccessToken=x, key=x, tk=x
  [new RegExp('(\\b' + NAME + '=)[^&\\s#\'",;]*', 'gi'), '$1***'],
  [/([?&](?:tk|k)=)[^&\s#'",;]*/gi, '$1***'],
  [/("tk"\s*:\s*)"(?:[^"\\]|\\.)*"/gi, '$1"***"'],
  // URL-encoded: password%3Dx, %22password%22%3A%22x%22
  [new RegExp('(\\b' + NAME + '%3D)(?:(?!%26)[^&\\s#\'",;])*', 'gi'), '$1***'],
  [new RegExp('(%22' + NAME + '%22(?:%20|\\+)*%3A(?:%20|\\+)*%22)(?:(?!%22)[^&\\s])*', 'gi'), '$1***'],
  // Plain "name: value" text. A bare "key"/"keys" is left alone so a Manager
  // record key ("Created receipt -> key: 019f...") stays readable.
  [new RegExp('(\\b(' + NAME + ')\\s*:\\s*)("(?:[^"\\\\]|\\\\.)*"|\'[^\']*\'|[^\\s,;}\\]]+)', 'gi'),
    (m, p1, name, v) => (/^keys?$/i.test(name) || /^(Bearer|Basic|Token|Digest|ApiKey|\*+|\[key|\[\d+)/i.test(v) ? m : p1 + (/^["']/.test(v) ? v[0] + '***' + v[0] : '***'))],
  // Long base64 runs (keys, encrypted payloads, tokens)
  [/[A-Za-z0-9+\/]{60,}={0,2}/g, m => '[' + m.length + ' chars removed]'],
];
// The forms a known secret can take in a log line: as is, JSON-escaped and URL-encoded.
function forms(v) {
  const out = [v];
  try { const j = JSON.stringify(v).slice(1, -1); if (j !== v) out.push(j); } catch (_) {}
  try { const u = encodeURIComponent(v); if (u !== v) { out.push(u); out.push(u.replace(/%20/g, '+')); } } catch (_) {}
  return out;
}
function mask(s) {
  let out = String(s == null ? '' : s).replace(ANSI, '');
  try {
    for (const v of known) for (const f of forms(v)) if (f && out.indexOf(f) >= 0) out = out.split(f).join('***');
    for (const [re, rep] of RULES) out = out.replace(re, rep);
  } catch (_) {}
  return out;
}
// Exact secret values to mask wherever they appear (never stored or exposed).
// The newest KNOWN_MAX are kept; vault secrets are noted again each time read.
const KNOWN_MAX = 2000;
function noteSecrets(values) {
  try {
    for (const v of [].concat(values || [])) {
      if (typeof v !== 'string') continue;
      const t = v.trim();
      if (t.length < 6 || t === '__vault__') continue;
      known.delete(t);
      known.add(t);
      if (known.size > KNOWN_MAX) known.delete(known.values().next().value);
    }
  } catch (_) {}
}
// Every string under a secret-looking field name in a request body (any depth),
// so it is masked before anything about the request is logged.
function secretsIn(obj, acc, depth) {
  acc = acc || [];
  if (!obj || typeof obj !== 'object' || (depth || 0) > 6) return acc;
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (typeof v === 'string' && LEARN_NAME.test(k)) acc.push(v);
    else if (v && typeof v === 'object') secretsIn(v, acc, (depth || 0) + 1);
  }
  return acc;
}
// Short plain words are skipped, so a request cannot make ordinary log text
// unreadable by sending it as a "password".
function noteBody(obj) { try { noteSecrets(secretsIn(obj).filter(v => !/^[A-Za-z ]{0,11}$/.test(v.trim()))); } catch (_) {} }

// ── Level: the console colours errors/warnings by wording too ──
function classify(line, level) {
  if (level === 'error' || /^\s*\[ERROR\]|could NOT|NOT recorded|✖|rejected/.test(line)) return 'error';
  if (level === 'warn' || /^\s*\[WARN\]|⚠|unreachable|timed out|transient/i.test(line)) return 'warn';
  return 'info';
}

function setDir(dir) { logDir = dir || ''; if (logDir) { try { fs.mkdirSync(logDir, { recursive: true }); } catch (_) {} } }
function setContextGetter(fn) { ctxGetter = typeof fn === 'function' ? fn : null; }
function fileFor(day) { return logDir ? path.join(logDir, day + '-activity.log') : ''; }

// One console call: the full text (masked as a whole, so a PEM spanning lines is
// caught), then one entry per non-empty line. isDebugLine(line) flags technical lines.
function capture(level, text, isDebugLine) {
  try {
    let ctx = null;
    try { ctx = ctxGetter ? ctxGetter() : null; } catch (_) { ctx = null; }
    const clean = mask(text);
    const now = Date.now();
    const time = new Date(now).toISOString();
    const lines = [];
    for (const line of clean.split('\n')) {
      if (!line.trim()) continue;
      const raw = line.length > 2000 ? line.slice(0, 2000) + ' ...' : line;
      const e = { seq: ++seq, time, level: classify(raw, level), text: raw, debug: !!(isDebugLine && safe(() => isDebugLine(raw))) };
      if (ctx && ctx.tenantId) e.tenantId = String(ctx.tenantId);
      if (ctx && ctx.user) e.user = String(ctx.user);
      ring.push(e);
      lines.push(JSON.stringify(e));
    }
    if (ring.length > RING_MAX) ring.splice(0, ring.length - RING_MAX);
    const f = fileFor(eatDay(now));
    if (f && lines.length) { try { fs.appendFileSync(f, lines.join('\n') + '\n'); } catch (_) {} }
  } catch (_) {}
}
function safe(fn) { try { return fn(); } catch (_) { return false; } }

// ── Reading ──
function readDayEntries(day) {
  if (!validDay(day)) return [];
  const f = fileFor(day);
  if (!f) return [];
  let raw = '';
  try { raw = fs.readFileSync(f, 'utf8'); } catch (_) { return []; }
  const out = [];
  for (const l of raw.split('\n')) { if (!l) continue; try { const e = JSON.parse(l); if (e && typeof e.text === 'string') out.push(e); } catch (_) {} }
  return out;
}
// Today: the day's file (whole day, across restarts) plus anything newer still in
// memory (a failed file write). after=<seq>: only the memory ring, for live polling.
function entries({ day, after } = {}) {
  const today = eatDay();
  const d = day || today;
  if (d === today && after != null) return ring.filter(e => e.seq > after);
  const fromFile = readDayEntries(d);
  if (d !== today) return fromFile;
  const top = fromFile.length ? fromFile[fromFile.length - 1].seq : -Infinity;
  return fromFile.concat(ring.filter(e => e.seq > top && eatDay(Date.parse(e.time)) === today));
}
function listDays() {
  const out = new Set([eatDay()]);
  try { for (const f of fs.readdirSync(logDir)) { const m = /^(\d{4}-\d{2}-\d{2})-activity\.log$/.exec(f); if (m) out.add(m[1]); } } catch (_) {}
  return [...out].sort().reverse();
}
function lastSeq() { return ring.length ? ring[ring.length - 1].seq : seq; }

module.exports = { capture, mask, noteSecrets, noteBody, secretsIn, classify, setDir, setContextGetter, entries, listDays, lastSeq, validDay, eatDay, RING_MAX, _ring: ring };
