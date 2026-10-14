'use strict';
// Relay console: timestamped, coloured lines; technical detail hidden unless debug
// is on (press D, or EFC_DEBUG=1) and kept in logs/<day>-debug.log; a status block
// (S), the window title, and hotkeys (O open, L LAN address, C copy the Manager
// button URL, S status, D debug, Q quit after any sale in progress finishes).
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const activity = require('./activity');   // the same lines, kept for Settings > Logs (masked)

const TTY = !!(process.stdout && process.stdout.isTTY);
const C = TTY ? { red: '\x1b[31m', green: '\x1b[32m', amber: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', off: '\x1b[0m' }
              : { red: '', green: '', amber: '', dim: '', bold: '', off: '' };
let debug = process.env.EFC_DEBUG === '1';
let logDir = '';
let statusFn = null, inflightFn = () => 0, urls = {};

// Technical lines: useful when diagnosing, noise for a cashier.
const DEBUG_LINES = [/^\s*\[T103 login\] fields/, /T127 search raw/, /T127 record fields/, /T127 search found/, /^\s*🔍 T127 search rc/,
  /^\s*•\s/, /accounts probe/, /^\[items-list\]/, /^\s*Reusing cached session/, /^\s*T109 line:/, /^\s*Receipt line linked:/, /^\s*Line item resolved:/];
const isDebug = s => DEBUG_LINES.some(r => r.test(s));
function colourOf(s, level) {
  if (level === 'error' || /^\[ERROR\]|could NOT|NOT recorded|✖|rejected/.test(s)) return C.red;
  if (level === 'warn' || /^\[WARN\]|⚠|unreachable|timed out|transient/i.test(s)) return C.amber;
  if (/FDN:|fiscalised|✅|✔|Created |recorded |unlocked|running at|Theme updated/.test(s)) return C.green;
  return '';
}
function stamp() { const d = new Date(); return [d.getHours(), d.getMinutes(), d.getSeconds()].map(n => String(n).padStart(2, '0')).join(':'); }
function debugFile(line) {
  if (!logDir) return;
  try { fs.appendFileSync(path.join(logDir, new Date().toISOString().slice(0, 10) + '-debug.log'), stamp() + ' ' + line + '\n'); } catch (_) {}
}

// opts.context: () => ({ tenantId, user }) for the request being handled, so each
// activity entry names the business and person (server.js passes it in).
function install(dir, opts) {
  logDir = dir || '';
  activity.setDir(logDir);
  if (opts && opts.context) activity.setContextGetter(opts.context);
  for (const [name, level] of [['log', 'info'], ['warn', 'warn'], ['error', 'error']]) {
    const orig = console[name].bind(console);
    console[name] = (...args) => {
      const text = args.map(a => typeof a === 'string' ? a : (a instanceof Error ? a.message : (() => { try { return JSON.stringify(a); } catch (_) { return String(a); } })())).join(' ');
      activity.capture(level, text, isDebug);
      for (const line of text.split('\n')) {
        if (!line.trim()) { orig(''); continue; }
        if (isDebug(line)) { debugFile(line); if (!debug) continue; }
        const col = colourOf(line, level);
        orig(C.dim + stamp() + C.off + ' ' + col + line + (col ? C.off : ''));
      }
    };
  }
}

function printStatus() {
  if (!statusFn) return;
  let st = {}; try { st = statusFn() || {}; } catch (_) {}
  const dot = v => v === true ? C.green + '● ' : v === false ? C.red + '● ' : C.amber + '● ';
  const out = [
    '',
    C.bold + 'EFRISConnect ' + (st.version || '') + C.off + '   ' + (st.mode || ''),
    'Relay    ' + dot(true) + 'running' + C.off + '   ' + (urls.local || '') + (urls.lan ? '   LAN: ' + urls.lan : ''),
    ...(urls.button ? ['Shop net ' + dot(true) + 'LAN mode' + C.off + '   Manager button URL: ' + urls.button + C.dim + '   (L: all addresses)' + C.off] : []),
    'Vault    ' + dot(st.vault) + (st.vault ? 'unlocked' : st.vault === false ? 'locked' : 'unlocking') + C.off +
      '   URA ' + dot(st.ura) + (st.ura === true ? 'online' : st.ura === false ? 'unreachable' : 'not checked yet') + C.off +
      '   Enabler ' + (st.enabler === undefined || st.enabler === null ? C.dim + 'not used' + C.off : dot(st.enabler) + (st.enabler ? 'ready' : 'not answering') + C.off) +
      '   Queue ' + (st.queue || 0),
    ...(st.setupCode ? [C.amber + 'Setup    ' + C.bold + st.setupCode + C.off + C.amber + '   one-time code to create the owner account from another computer' + C.off,
      C.dim + '         (on this PC, open EFRIS Connect in Manager: no code needed)' + C.off] : []),
    C.dim + 'Keys: O open  L LAN address  C copy Manager URL  S status  D debug ' + (debug ? 'off' : 'on') + '  Q quit' + C.off,
    '',
  ];
  process.stdout.write(out.join('\n') + '\n');
}

function setTitle() {
  if (!statusFn) return;
  let st = {}; try { st = statusFn() || {}; } catch (_) {}
  try { process.title = 'EFRISConnect - running - ' + (st.queue || 0) + ' queued' + (st.ura === false ? ' - URA unreachable' : ''); } catch (_) {}
}

function openUrl(u) {
  const cmd = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', u]] : process.platform === 'darwin' ? ['open', [u]] : ['xdg-open', [u]];
  try { spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore', windowsHide: true }).unref(); } catch (_) {}
}
function copyText(t) {
  const cmd = process.platform === 'win32' ? ['clip', []] : process.platform === 'darwin' ? ['pbcopy', []] : ['xclip', ['-selection', 'clipboard']];
  try { const p = spawn(cmd[0], cmd[1], { stdio: ['pipe', 'ignore', 'ignore'], windowsHide: true }); p.on('error', () => {}); p.stdin.end(t); return true; } catch (_) { return false; }
}

let quitting = false;
function quit() {
  if (quitting) return; quitting = true;
  const t0 = Date.now();
  const wait = () => {
    const n = inflightFn();
    if (n > 0 && Date.now() - t0 < 30000) { if (!wait.said) { wait.said = true; console.log('   Waiting for ' + n + ' sale(s) in progress to finish before closing...'); } return setTimeout(wait, 300); }
    console.log('   EFRISConnect stopped.');
    process.exit(0);
  };
  wait();
}

// The L hotkey: the shop-network addresses (tills, Manager buttons), or why there are none.
function lanText(u) {
  u = u || urls;
  const all = (u.lanAll && u.lanAll.length) ? u.lanAll : (u.lan ? [u.lan] : []);
  if (!all.length) return '   LAN access is off (the relay listens on this PC only). Use the launcher option "Start for shop network (LAN)".';
  return ['   Shop network addresses (open on a till after trusting the certificate):']
    .concat(all.map(u => '     ' + u))
    .concat(u.button ? ['   Manager custom button URL: ' + u.button] : []).join('\n');
}

// Called once the servers are listening. status() returns {version, mode, vault, ura, enabler, queue, setupCode}.
function ready(opts) {
  statusFn = opts.status; inflightFn = opts.inflight || inflightFn; urls = opts.urls || {};
  printStatus(); setTitle();
  setInterval(setTitle, 15000).unref();
  if (!process.stdin.isTTY) return;
  try { process.stdin.setRawMode(true); } catch (_) { return; }
  const onKey = makeKeyHandler({
    quit,
    o: () => { openUrl(urls.local); console.log('   Opening ' + urls.local); },
    l: () => console.log(lanText()),
    c: () => { const u = urls.button || urls.local; console.log(copyText(u) ? '   Copied the Manager button URL: ' + u : '   Could not copy; the URL is ' + u); },
    s: () => printStatus(),
    d: () => { debug = !debug; console.log('   Technical detail ' + (debug ? 'shown' : 'hidden') + ' (always kept in logs/<day>-debug.log).'); },
    q: () => quit(),
  });
  process.stdin.on('data', onKey);
  process.stdin.resume();
}

// Hotkeys act on ONE key press only. A stdin chunk of several characters is
// pasted or typed-ahead text (or an arrow/function key's escape sequence) and is
// ignored, and the same key repeated within ~400 ms counts once, so pasting text
// into the window never opens the extension five times or flips debug back and
// forth. Ctrl+C (alone, or anywhere in a chunk) still quits.
// actions: { quit, o, l, c, s, d, q } -> functions. now: clock (tests).
const KEY_REPEAT_MS = 400;
function makeKeyHandler(actions, now) {
  now = now || Date.now;
  let lastKey = '', lastAt = -Infinity;
  return chunk => {
    const s = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk == null ? '' : chunk);
    if (s.includes('\u0003')) { if (actions.quit) actions.quit(); return 'quit'; }
    if (s.length !== 1) return null;
    const k = s.toLowerCase();
    const fn = Object.prototype.hasOwnProperty.call(actions, k) && k !== 'quit' ? actions[k] : null;
    if (!fn) return null;
    const t = now();
    if (k === lastKey && t - lastAt < KEY_REPEAT_MS) { lastAt = t; return null; }
    lastKey = k; lastAt = t;
    fn();
    return k;
  };
}

module.exports = { lanText, makeKeyHandler, install, ready, printStatus, quit, isDebugOn: () => debug, setContextGetter: activity.setContextGetter };
