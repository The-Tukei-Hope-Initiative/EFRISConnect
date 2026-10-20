// ── URA Offline Mode Enabler: status, start, stop (Windows) ──────────────────
// The Enabler runs as two Windows services: TcsData (its MySQL database) and
// TcsTomcat (the Enabler itself, port 9880), which needs the database up first.
// Only these fixed service names are ever passed to sc.exe; nothing from a
// request reaches the command line. Starting or stopping a service needs
// administrator rights: the installed relay (startup task, account SYSTEM) has
// them; a relay started from the launcher as a normal user does not, and gets a
// clear message instead.
const path = require('path');
const { execFile } = require('child_process');

const SERVICES = ['TcsData', 'TcsTomcat'];   // start order; stop is the reverse
const SC = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'sc.exe');

function sc(args) {
  return new Promise(resolve => {
    execFile(SC, args, { windowsHide: true, timeout: 20000 }, (err, stdout, stderr) =>
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, out: String(stdout || '') + String(stderr || '') }));
  });
}

// "STATE : 4 RUNNING" -> 'running'; a missing service -> 'not-installed'.
function parseState(out) {
  if (/1060|does not exist/i.test(out)) return 'not-installed';
  const m = out.match(/STATE\s*:\s*\d+\s+([A-Z_]+)/);
  return m ? m[1].toLowerCase().replace(/_/g, '-') : 'unknown';
}

async function status() {
  if (process.platform !== 'win32') return { supported: false, installed: false, services: {} };
  const services = {};
  for (const s of SERVICES) services[s] = parseState((await sc(['query', s])).out);
  const installed = SERVICES.every(s => services[s] !== 'not-installed');
  return { supported: true, installed, running: installed && SERVICES.every(s => services[s] === 'running'), services };
}

async function waitFor(name, want, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (parseState((await sc(['query', name])).out) === want) return true;
    await new Promise(r => setTimeout(r, 1000));
  }
  return false;
}

// Turn sc.exe's answer into a sentence; 5 = access denied.
function failure(name, r) {
  if (r.code === 5 || /Access is denied|FAILED 5/i.test(r.out)) {
    return 'Windows refused to ' + name + ': EFRISConnect is not running with administrator rights. Use the tray icon (it asks for approval), or install EFRISConnect with Setup so it runs as a service.';
  }
  return (r.out.match(/FAILED[^\r\n]*/) || [r.out.trim().split(/\r?\n/).pop() || 'sc.exe error ' + r.code])[0];
}

async function control(action) {
  const st = await status();
  if (!st.supported) return { success: false, error: 'The Offline Enabler runs on Windows only.' };
  if (!st.installed) return { success: false, error: 'The Offline Enabler is not installed on this computer (services TcsData and TcsTomcat not found).' };
  const steps = [];
  const stop = async () => {
    for (const s of SERVICES.slice().reverse()) {
      if (st.services[s] === 'stopped') continue;
      const r = await sc(['stop', s]);
      if (r.code && !/1062|not been started/i.test(r.out)) return failure('stop ' + s, r);
      await waitFor(s, 'stopped', 60000); steps.push(s + ' stopped');
    }
    return '';
  };
  const start = async () => {
    for (const s of SERVICES) {
      const r = await sc(['start', s]);
      if (r.code && !/1056|already running/i.test(r.out)) return failure('start ' + s, r);
      if (!await waitFor(s, 'running', 90000)) return s + ' did not reach running within 90 seconds.';
      steps.push(s + ' running');
    }
    return '';
  };
  let err = '';
  if (action === 'stop') err = await stop();
  else if (action === 'start') err = await start();
  else if (action === 'restart') { err = await stop(); if (!err) err = await start(); }
  else return { success: false, error: 'Unknown action' };
  const after = await status();
  return err ? { success: false, error: err, steps, status: after } : { success: true, steps, status: after };
}

module.exports = { status, control, parseState, SERVICES };
