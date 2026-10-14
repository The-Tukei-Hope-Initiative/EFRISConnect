// ── Where EFRISConnect keeps its files ───────────────────────────────────────
// SHIPPED_DIR: reference data that ships with the code (commodity tree, units).
// DATA_DIR:    everything the relay writes - credential vault, master key, logs,
//              HTTPS certificate, submission log, offline queue.
//
// On Windows DATA_DIR is %ProgramData%\EFRISConnect\data: outside the code
// folder, so folder syncing (OneDrive, Google Drive), git and re-installs never
// touch it, and both the interactive relay and the Windows service (SYSTEM) use
// the same files. The folder is restricted to the installing user, SYSTEM and
// Administrators. Elsewhere (macOS, Linux, containers) DATA_DIR stays
// backend/data. DATA_DIR_OVERRIDE sets it explicitly anywhere.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const SHIPPED_DIR = path.join(__dirname, 'data');
// Windows tools by full path, so nothing earlier on PATH can stand in for them.
const SYS32 = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32');
const SHIPPED = new Set(['goods_tree.json', 'segments.json', 'segments', 'units.json', 'uom.json']);

function defaultDataDir() {
  if (process.platform === 'win32') return path.join(process.env.ProgramData || 'C:\\ProgramData', 'EFRISConnect', 'data');
  return SHIPPED_DIR;
}
const DATA_DIR = process.env.DATA_DIR_OVERRIDE || defaultDataDir();
// Only the default location migrates and gets restricted; an explicit
// DATA_DIR_OVERRIDE is left exactly as the operator set it up.
const SEPARATE = !process.env.DATA_DIR_OVERRIDE && path.resolve(DATA_DIR) !== path.resolve(SHIPPED_DIR);

// Limit the folder to this account, SYSTEM and Administrators (Windows only).
// SIDs keep it independent of the Windows display language. Done once per
// folder; a marker file records it.
function restrictDir(dir) {
  if (process.platform !== 'win32') return;
  const marker = path.join(dir, '.acl_v1');
  if (fs.existsSync(marker)) return;
  try {
    const csv = execFileSync(path.join(SYS32, 'whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
    const sid = (csv.match(/"(S-1-[0-9-]+)"/) || [])[1];
    const grants = ['*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'];
    if (sid && sid !== 'S-1-5-18') grants.unshift('*' + sid + ':(OI)(CI)F');
    execFileSync(path.join(SYS32, 'icacls.exe'), [dir, '/inheritance:r', '/grant:r', ...grants], { stdio: 'ignore', windowsHide: true });
    // Files created before this (e.g. by the HTTPS setup) still carry ProgramData's
    // "Users can read" entries: make every child inherit only from this folder.
    if (fs.readdirSync(dir).length) execFileSync(path.join(SYS32, 'icacls.exe'), [path.join(dir, '*'), '/reset', '/T', '/C', '/Q'], { stdio: 'ignore', windowsHide: true });
    fs.writeFileSync(marker, new Date().toISOString());
  } catch (e) {
    console.log('   ⚠ Could not restrict permissions on ' + dir + ': ' + e.message);
  }
}

// One-time move of runtime files from backend/data (inside the code folder) to
// DATA_DIR. Files already present in DATA_DIR are never overwritten; anything
// that could not be moved is listed so it can be removed by hand.
function migrateLegacy() {
  if (!SEPARATE) return;
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (_) {}
  restrictDir(DATA_DIR);
  let entries = [];
  try { entries = fs.readdirSync(SHIPPED_DIR); } catch (_) { return; }
  const moved = [], left = [];
  const walk = (src, dst) => {
    const st = fs.statSync(src);
    if (st.isDirectory()) {
      try { fs.mkdirSync(dst, { recursive: true }); } catch (_) {}
      for (const n of fs.readdirSync(src)) walk(path.join(src, n), path.join(dst, n));
      try { if (!fs.readdirSync(src).length) fs.rmdirSync(src); } catch (_) {}
      return;
    }
    if (fs.existsSync(dst)) {
      if (fs.statSync(dst).size === st.size) { fs.rmSync(src, { force: true }); moved.push(src); }
      else left.push(src);
      return;
    }
    fs.copyFileSync(src, dst);
    if (fs.statSync(dst).size === st.size) { fs.rmSync(src, { force: true }); moved.push(src); }
    else left.push(src);
  };
  for (const n of entries) {
    if (SHIPPED.has(n)) continue;
    try { walk(path.join(SHIPPED_DIR, n), path.join(DATA_DIR, n)); } catch (e) { left.push(path.join(SHIPPED_DIR, n) + ' (' + e.message + ')'); }
  }
  if (moved.length) console.log('   Moved ' + moved.length + ' data file(s) from ' + SHIPPED_DIR + ' to ' + DATA_DIR);
  if (left.length) console.log('   ⚠ Left in ' + SHIPPED_DIR + ' (a different copy already exists in ' + DATA_DIR + '; delete by hand once checked): ' + left.join(', '));
}

migrateLegacy();
if (SEPARATE) restrictDir(DATA_DIR);

module.exports = { SHIPPED_DIR, DATA_DIR, SYS32, restrictDir };
