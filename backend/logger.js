'use strict';
// Structured daily error/activity log - one JSON-lines file per calendar day,
// so a support person (or the team) can open today's file and see exactly
// what went wrong without digging through raw container/process output.
const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR_OVERRIDE || path.join(__dirname, 'data', 'logs');
try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (e) {}

function dayFile(day) { return path.join(LOG_DIR, day + '.log'); }
function today() { return new Date().toISOString().slice(0, 10); }

function write(level, message, meta) {
  const entry = { time: new Date().toISOString(), level, message };
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

module.exports = { error, warn, info, listDays, readDay, today, LOG_DIR };
