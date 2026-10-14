'use strict';
// Structured daily error/activity log - one JSON-lines file per calendar day,
// so a support person (or the team) can open today's file and see exactly
// what went wrong without digging through raw container/process output.
const fs = require('fs');
const path = require('path');
const { mask } = require('./activity');   // same masking as the activity log

const LOG_DIR = process.env.LOG_DIR_OVERRIDE || path.join(require('./paths').DATA_DIR, 'logs');
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) {}

function dayFile(day) { return path.join(LOG_DIR, day + '.log'); }
function today() { return new Date().toISOString().slice(0, 10); }

// () => ({ tenantId }) for the request being handled (server.js passes it in), so
// each entry names its business and a support bundle can be limited to it.
let ctxGetter = null;
function setContextGetter(fn) { ctxGetter = typeof fn === 'function' ? fn : null; }

// Secrets never reach the file: every string is masked, and values under
// secret-looking keys are dropped entirely.
const SECRET_KEY_RE = /pass(word|phrase|wd|code)?|pwd|secret|token|api[_-]?key|aes[_-]?key|access[_-]?key|authorization|pem|private[_-]?key|cookie|credential/i;
function clean(v, depth) {
  if (typeof v === 'string') return mask(v);
  if (!v || typeof v !== 'object' || depth > 6) return v;
  if (Array.isArray(v)) return v.map(x => clean(x, depth + 1));
  const out = {};
  for (const k of Object.keys(v)) out[k] = SECRET_KEY_RE.test(k) ? '***' : clean(v[k], depth + 1);
  return out;
}

function write(level, message, meta) {
  message = clean(message, 0);
  meta = clean(meta, 0);
  const entry = { time: new Date().toISOString(), level, message };
  try { const c = ctxGetter ? ctxGetter() : null; if (c && c.tenantId) entry.tenantId = String(c.tenantId); } catch (_) {}
  if (meta && Object.keys(meta).length) entry.meta = meta;
  try { fs.appendFileSync(dayFile(today()), JSON.stringify(entry) + '\n'); }
  catch (e) { console.error('logger: failed to write log file:', e.message); }
  // Always echo to the console too, so container-host or process-manager log
  // capture still sees it even if disk access to LOG_DIR is unavailable.
  const fn = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  fn('[' + level.toUpperCase() + ']', message, meta ? JSON.stringify(meta) : '');
}

function error(message, meta) { write('error', message, meta); }
function warn(message, meta) { write('warn', message, meta); }
function info(message, meta) { write('info', message, meta); }

// List available log days, newest first (for a simple "pick a day" UI).
function listDays() {
  try { return fs.readdirSync(LOG_DIR).filter(f => /^\d{4}-\d{2}-\d{2}\.log$/.test(f)).map(f => f.slice(0, 10)).sort().reverse(); }
  catch (e) { return []; }
}

// Read one day's raw log content. `day` must be YYYY-MM-DD - reject anything
// else so this can't be used to read arbitrary files off disk.
function readDay(day) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return null;
  try { return fs.readFileSync(dayFile(day), 'utf8'); }
  catch (e) { return null; }
}

module.exports = { error, warn, info, listDays, readDay, today, setContextGetter, LOG_DIR };
