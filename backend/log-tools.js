'use strict';
// Log housekeeping and packaging for Settings > Logs:
//   prune(dir, days)   delete day log files older than the retention period
//   retentionDays()    LOG_RETENTION_DAYS (default 90, at least 7)
//   zip(entries)       a small .zip writer (deflate, CRC32), no dependencies
//   dayRange(from, to) the EAT days from..to, validated
// Nothing here throws into the relay.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { eatDay, validDay } = require('./activity');

const DAY_MS = 86400000;
const DEFAULT_RETENTION = 90;
const MIN_RETENTION = 7;
// Only the relay's own day files: <day>.log, <day>-debug.log, <day>-activity.log.
const LOG_FILE_RE = /^(\d{4}-\d{2}-\d{2})(-debug|-activity)?\.log$/;

function retentionDays() {
  const raw = String(process.env.LOG_RETENTION_DAYS || '').trim();
  if (!/^\d{1,5}$/.test(raw)) return DEFAULT_RETENTION;
  return Math.max(MIN_RETENTION, parseInt(raw, 10));
}

// Removes the matching files whose day is more than `days` days before today
// (Uganda time). Returns how many were removed.
function prune(dir, days, now) {
  let removed = 0;
  try {
    if (!dir) return 0;
    const keep = Math.max(MIN_RETENTION, Number.isFinite(days) ? Math.floor(days) : DEFAULT_RETENTION);
    const cutoff = eatDay((now == null ? Date.now() : now) - keep * DAY_MS);
    let names = [];
    try { names = fs.readdirSync(dir); } catch (_) { return 0; }
    for (const name of names) {
      const m = LOG_FILE_RE.exec(name);
      if (!m || !validDay(m[1]) || m[1] >= cutoff) continue;
      const p = path.join(dir, name);
      try {
        const st = fs.lstatSync(p);
        if (!st.isFile()) continue;   // never follow links or touch folders
        fs.unlinkSync(p);
        removed++;
      } catch (_) {}
    }
  } catch (_) {}
  return removed;
}

// Days from..to inclusive. Returns { days } or { error }.
function dayRange(from, to, maxDays) {
  if (!validDay(from) || !validDay(to)) return { error: 'from and to must be dates like 2026-10-09' };
  if (to < from) return { error: 'to must be the same day as from or later' };
  const a = Date.parse(from + 'T00:00:00Z'), b = Date.parse(to + 'T00:00:00Z');
  const n = Math.round((b - a) / DAY_MS) + 1;
  if (n > maxDays) return { error: 'Choose at most ' + maxDays + ' days' };
  const days = [];
  for (let i = 0; i < n; i++) days.push(new Date(a + i * DAY_MS).toISOString().slice(0, 10));
  return { days };
}

// ── Zip (PKZIP 2.0, deflate, UTF-8 names): opens in Windows Explorer ──
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function dosTime(d) {
  const y = Math.max(1980, d.getFullYear());
  return { time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), date: ((y - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate() };
}
// files: [{ name, data: string|Buffer }]. Returns a Buffer.
function zip(files, when) {
  const t = dosTime(when || new Date());
  const locals = [], centrals = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(String(f.name), 'utf8');
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(String(f.data == null ? '' : f.data), 'utf8');
    const crc = crc32(data);
    let body = zlib.deflateRawSync(data);
    let method = 8;
    if (body.length >= data.length) { body = data; method = 0; }   // store when deflate does not help
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(t.time, 10); lh.writeUInt16LE(t.date, 12); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26); lh.writeUInt16LE(0, 28);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(t.time, 12); ch.writeUInt16LE(t.date, 14); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28);
    ch.writeUInt16LE(0, 30); ch.writeUInt16LE(0, 32); ch.writeUInt16LE(0, 34); ch.writeUInt16LE(0, 36); ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);
    locals.push(lh, name, body);
    centrals.push(ch, name);
    offset += lh.length + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(0, 4); end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16); end.writeUInt16LE(0, 20);
  return Buffer.concat(locals.concat([cd, end]));
}

module.exports = { prune, retentionDays, dayRange, zip, crc32, LOG_FILE_RE, DEFAULT_RETENTION, MIN_RETENTION };
