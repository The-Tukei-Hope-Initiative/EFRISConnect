'use strict';
// Watchdog: ends the relay when it has stopped answering, so the runner
// (windows/run-relay.cmd) starts a fresh copy. Windows restarts the relay only when
// it exits, not when it hangs; a hung relay meant no fiscal receipts until someone
// chose Restart in the tray.
//
// The main thread ticks a shared clock every second. A worker thread (this same
// file, on its own thread, so it keeps running while the main one is stuck) checks
// the clock and, after STALL_MS without a tick, writes a line to the crash log and
// ends the process. Code that blocks on purpose (the vault waiting for Windows)
// calls expectBlock(ms) first so it is not taken for a hang.
const { Worker, isMainThread, workerData } = require('worker_threads');

const STALL_MS = 2 * 60 * 1000;

// The decision, used by the worker and the tests: stuck = no tick for longer than
// stallMs, and not inside an announced block. Times are BigInt milliseconds.
function isStalled(lastTick, blockUntil, at, stallMs) {
  return at - lastTick > stallMs && at > blockUntil;
}

if (!isMainThread && workerData && workerData.efcWatchdog) {
  const fs = require('fs');
  const c = new BigInt64Array(workerData.shared);
  const stall = BigInt(workerData.stallMs);
  setInterval(() => {
    const at = BigInt(Date.now()), last = Atomics.load(c, 0);
    if (!isStalled(last, Atomics.load(c, 1), at, stall)) return;
    const line = new Date().toISOString() + ' [WATCHDOG] The relay stopped answering for ' + Number((at - last) / 1000n) + ' s; ending it so it starts again.\n';
    try { if (workerData.crashLog) fs.appendFileSync(workerData.crashLog, line); } catch (_) {}
    process.kill(process.pid);   // the whole relay, not only this thread
  }, 10000);
}

const shared = new SharedArrayBuffer(16);
const clock = new BigInt64Array(shared);   // [0] last tick, [1] allowed to block until
let started = false;
const now = () => BigInt(Date.now());

function expectBlock(ms) {
  Atomics.store(clock, 1, now() + BigInt(Math.max(0, ms | 0)));
}

function start(opts) {
  if (started || !isMainThread) return;
  started = true;
  const o = opts || {};
  Atomics.store(clock, 0, now());
  const t = setInterval(() => Atomics.store(clock, 0, now()), 1000);
  if (t.unref) t.unref();
  try {
    const w = new Worker(__filename, { workerData: { efcWatchdog: true, shared, stallMs: o.stallMs || STALL_MS, crashLog: o.crashLog || '' } });
    w.unref();
    w.on('error', () => {});
  } catch (_) { /* no watchdog rather than no relay */ }
}

module.exports = { start, expectBlock, isStalled, STALL_MS };
