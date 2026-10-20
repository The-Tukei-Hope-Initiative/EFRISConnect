// ── Credential vault ─────────────────────────────────────────────────────────
// Server-side, encrypted-at-rest store for per-tenant secrets (EFRIS private key
// + passphrase, Manager access token). Secrets are AES-256-GCM encrypted with a
// master key; non-secret metadata (TIN, device no, endpoint, flags) is stored in
// clear so the UI can list businesses without decrypting.
//
// The browser never holds the EFRIS key or the Manager token - it references a
// tenant by id; the relay decrypts into memory only when making a call.
//
// Master key resolution:
//   1. VAULT_MASTER_KEY env (base64 of 32 bytes) - REQUIRED in cloud/multi-tenant.
//   2. Windows: a random key protected with DPAPI (machine scope) in
//      .vault_master.dpapi - it only decrypts on this computer, so a copied data
//      folder (sync, backup, USB) is useless elsewhere. A plain .vault_master from
//      older versions is converted on first use and then deleted.
//   3. Other platforms: a random key in .vault_master (0600). Good enough for a
//      single taxpayer on their own machine; NOT for shared cloud.
const fs = require('fs');
const path = require('path');
const { writeDurable, readJsonDurable } = require('./safe-file');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const paths = require('./paths');

// Where the vault + local master key live: the relay's data folder (see
// paths.js). On a cloud/container host, set VAULT_DIR to a mounted persistent
// volume so credentials survive redeploys - and mount it OUTSIDE backend/data so
// the bundled read-only commodity catalog is not hidden by the mount.
const DATA_DIR = process.env.VAULT_DIR || paths.DATA_DIR;
const FILE = path.join(DATA_DIR, 'credentials_vault.json');
const MASTER_FILE = path.join(DATA_DIR, '.vault_master');
const MASTER_DPAPI = path.join(DATA_DIR, '.vault_master.dpapi');

// Windows DPAPI. Native module first (@primno/dpapi, milliseconds); PowerShell as
// the fallback when the module is missing (it can take minutes to start on a busy
// PC). Same scope (LocalMachine) and no entropy, so either can read the other's data.
let _native = null;
try { if (process.platform === 'win32') _native = require('@primno/dpapi').Dpapi; } catch (_) { _native = null; }
let dpapiVia = '';
function dpapi(op, b64) {
  if (_native) {
    try {
      const inp = Buffer.from(String(b64).trim(), 'base64');
      const out = op === 'Protect' ? _native.protectData(inp, null, 'LocalMachine') : _native.unprotectData(inp, null, 'LocalMachine');
      dpapiVia = 'native';
      return Buffer.from(out).toString('base64');
    } catch (e) { console.log('   Vault: native DPAPI failed (' + e.message + '), using PowerShell'); }
  }
  dpapiVia = 'PowerShell';
  return dpapiPS(op, b64);
}
// The key travels over stdin, never on the command line where other processes could see it.
function dpapiPS(op, b64) {
  const ps = 'Add-Type -AssemblyName System.Security; ' +
    '$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); ' +
    '$r=[Security.Cryptography.ProtectedData]::' + op + '($b,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine); ' +
    '[Convert]::ToBase64String($r)';
  const run = ms => execFileSync(path.join(paths.SYS32, 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command', ps],
    { input: b64, encoding: 'utf8', windowsHide: true, timeout: ms }).trim();
  // PowerShell can take over a minute to start on a busy or freshly booted PC; that
  // is a slow start, not a wrong key, so give it longer and try once more.
  try { return run(90000); }
  catch (e) { if (!/ETIMEDOUT|timed out/i.test(String(e && (e.code || e.message)))) throw e; console.log('   Vault: Windows was slow to unlock the key, trying again...'); return run(180000); }
}
function vaultHasSecrets() {
  try { const all = JSON.parse(fs.readFileSync(FILE, 'utf8')); return Object.values(all).some(r => r && SECRET.some(k => r[k])); } catch (_) { return false; }
}
function saveMasterKey(k) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (process.platform === 'win32') {
    const blob = dpapi('Protect', k.toString('base64'));
    fs.writeFileSync(MASTER_DPAPI, blob, { mode: 0o600 });
    // Prove it opens again before anything relies on it.
    if (Buffer.from(dpapi('Unprotect', blob), 'base64').compare(k) !== 0) throw new Error('DPAPI round-trip check failed');
  } else {
    fs.writeFileSync(MASTER_FILE, k, { mode: 0o600 });
  }
}

let _mk = null;
// True while warm() is unlocking the DPAPI key in the background. Requests must
// not start a second, blocking PowerShell meanwhile (execFileSync would freeze
// every route for up to minutes); they get a "try again shortly" error instead.
let _warming = false;
function lockedError() {
  const e = new Error('The credential vault is still unlocking (Windows is slow to start PowerShell). Try again in a few seconds.');
  e.code = 'VAULT_LOCKED'; e.status = 503; e.expose = true;
  return e;
}
function masterKey() {
  if (_mk) return _mk;
  if (_warming) throw lockedError();
  const b64 = process.env.VAULT_MASTER_KEY || '';
  if (b64) {
    const k = Buffer.from(b64, 'base64');
    if (k.length === 32) { _mk = k; return _mk; }
    // Fail loud rather than silently falling back to a local key: a wrong
    // VAULT_MASTER_KEY on a shared/cloud deployment would otherwise decrypt the
    // vault incorrectly (or per-replica), causing silent data loss.
    throw new Error('VAULT_MASTER_KEY is set but invalid - it must be base64 of exactly 32 bytes.');
  }
  // DPAPI-protected key (Windows).
  if (process.platform === 'win32' && fs.existsSync(MASTER_DPAPI)) {
    let k;
    try { k = Buffer.from(dpapi('Unprotect', fs.readFileSync(MASTER_DPAPI, 'utf8')), 'base64'); }
    catch (e) {
      if (/ETIMEDOUT|timed out/i.test(String(e && (e.code || e.message)))) throw new Error('Windows took too long to unlock the vault key (PowerShell did not answer). Nothing is wrong with your credentials: close EFRIS Connect and start it again. Detail: ' + e.message);
      throw new Error('The vault master key could not be unlocked on this computer (it was created on another machine or Windows was reinstalled). Re-enter your credentials in Settings after moving ' + MASTER_DPAPI + ' and credentials_vault.json aside. Detail: ' + e.message);
    }
    if (k.length !== 32) throw new Error('The vault master key in ' + MASTER_DPAPI + ' is damaged.');
    _mk = k; return _mk;
  }
  // Plain key file (older versions, or non-Windows).
  try {
    const k = fs.readFileSync(MASTER_FILE);
    if (k.length === 32) {
      _mk = k;
      if (process.platform === 'win32') {
        try { saveMasterKey(k); fs.rmSync(MASTER_FILE, { force: true }); console.log('   Vault master key is now protected with Windows DPAPI (this computer only).'); }
        catch (e) { console.log('   ⚠ Could not protect the vault master key with DPAPI, keeping the plain key file: ' + e.message); }
      }
      return _mk;
    }
  } catch (_) {}
  // No key anywhere. A vault that already holds secrets would be unreadable with a
  // new key, so stop instead of silently replacing it.
  if (vaultHasSecrets()) throw new Error('The vault holds encrypted credentials but its master key is missing (' + DATA_DIR + '). Restore the .vault_master file, or move credentials_vault.json aside and re-enter your credentials.');
  const k = crypto.randomBytes(32);
  try { saveMasterKey(k); }
  catch (e) {
    console.log('   ⚠ DPAPI unavailable (' + e.message + ') - storing the master key as a plain file.');
    fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(MASTER_FILE, k, { mode: 0o600 });
  }
  console.log('   Generated a new vault master key in ' + DATA_DIR + (process.platform === 'win32' ? ' (protected with Windows DPAPI)' : '') + '. Set VAULT_MASTER_KEY instead for cloud/multi-server use.');
  _mk = k;
  return _mk;
}

function enc(plain) {
  if (plain == null || plain === '') return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  const tag = c.getAuthTag();
  return 'v1:' + Buffer.concat([iv, tag, ct]).toString('base64');
}
function dec(blob) {
  if (!blob || typeof blob !== 'string' || !blob.startsWith('v1:')) return '';
  try {
    const raw = Buffer.from(blob.slice(3), 'base64');
    const iv = raw.subarray(0, 12), tag = raw.subarray(12, 28), ct = raw.subarray(28);
    const d = crypto.createDecipheriv('aes-256-gcm', masterKey(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch (e) {
    // Surface the reason (wrong master key or a corrupted/tampered value) instead
    // of silently returning empty, which is hard to diagnose later.
    console.log('   ⚠ Vault could not be read: ' + e.message);
    return '';
  }
}

// The vault files hold every business's EFRIS credentials: flushed to disk on
// write, with a .bak copy that is put back if a power cut damages the file.
function readVaultFile(file, forWrite, what) {
  let r;
  try { r = readJsonDurable(file, { backup: true, keepDamaged: true }); }
  catch (e) { if (forWrite) throw e; return {}; }
  if (r.state === 'ok' || r.state === 'restored') return r.value || {};
  if (r.state !== 'damaged') return {};
  if (!forWrite) return {};
  // Refuse a read-modify-write: saving one business would drop all the others.
  console.log('   ⚠ ' + what + ' ' + file + ' is damaged (' + (r.error ? r.error.message : 'unreadable') + ') - not overwriting it. Restore it from a backup or move it aside.');
  throw new Error('The ' + what.toLowerCase() + ' ' + path.basename(file) + ' is damaged and was not changed. Restore it from a backup or move it aside.');
}
function loadAll() { return readVaultFile(FILE, false, 'Vault file'); }
function loadAllForWrite() { return readVaultFile(FILE, true, 'Vault file'); }
function saveAll(o) {
  try { writeDurable(FILE, JSON.stringify(o, null, 2), { mode: 0o600, backup: true }); }
  catch (e) { console.log('vault write error: ' + e.message); throw e; }
}

// Fields that MUST be encrypted at rest. Everything else is non-secret metadata.
const SECRET = ['efrisPrivateKeyPem', 'efrisPassphrase', 'efrisPassword', 'managerToken'];

// Non-secret view for listing/UI - never includes decrypted secrets.
function meta(id, r) {
  r = r || loadAll()[id] || {};
  return {
    id, tin: r.tin || '', deviceNo: r.deviceNo || '', businessName: r.businessName || '', tradeName: r.tradeName || '',
    managerEndpoint: r.managerEndpoint || '', mode: r.mode || 'sandbox',
    hasEfrisKey: !!(r.efrisPrivateKeyPem || r.efrisPrivateKeyPath),
    hasEfrisPassword: !!r.efrisPassword, hasManagerToken: !!r.managerToken, hasEnabler: !!r.enablerUrl, updatedAt: r.updatedAt || '',
    profileUpdatedAt: (r.profile && typeof r.profile === 'object' && r.profile.profileUpdatedAt) || '',
  };
}

// The business setup the extension shows (non-secret settings, kept in `profile`)
// plus which secrets the vault holds, without decrypting anything. null when the
// business is not in the vault.
function getProfile(id) {
  const r = loadAll()[id];
  if (!r) return null;
  return {
    profile: (r.profile && typeof r.profile === 'object') ? r.profile : null,
    has: { efrisPassword: !!r.efrisPassword, efrisPrivateKeyPem: !!r.efrisPrivateKeyPem, efrisPassphrase: !!r.efrisPassphrase, managerToken: !!r.managerToken },
    meta: meta(id, r), vatRegistered: !!r.vatRegistered,
  };
}

// Create/merge a tenant record. Secret fields are encrypted; pass '' to clear a
// secret, or omit a field to leave it unchanged.
function putTenant(id, rec) {
  if (!id) throw new Error('tenant id required');
  const all = loadAllForWrite();
  const out = { ...(all[id] || {}) };
  for (const k of Object.keys(rec || {})) {
    if (rec[k] === undefined) continue;
    out[k] = SECRET.includes(k) ? (rec[k] ? enc(rec[k]) : '') : rec[k];
  }
  out.updatedAt = new Date().toISOString();
  all[id] = out;
  saveAll(all);
  return meta(id, out);
}

// Full decrypted creds for SERVER-SIDE use only (never send to the client).
// Optional listener told each business's decrypted secrets when it is read, so the
// activity log can mask those exact values (it never stores or shows them).
let _secretSink = null;
function setSecretSink(fn) { _secretSink = typeof fn === 'function' ? fn : null; }
function getTenant(id) {
  const t = _getTenant(id);
  if (t && _secretSink) { try { _secretSink(t); } catch (_) {} }
  return t;
}
function _getTenant(id) {
  const r = loadAll()[id];
  if (!r) return null;
  // dec() swallows errors, so check the lock here: otherwise a request during the
  // background unlock would get a tenant with every secret silently blank.
  if (!_mk && _warming && SECRET.some(k => r[k])) throw lockedError();
  return {
    id, tin: r.tin || '', deviceNo: r.deviceNo || '', mode: r.mode || 'sandbox',
    efrisPrivateKeyPem: dec(r.efrisPrivateKeyPem), efrisPassphrase: dec(r.efrisPassphrase), efrisPassword: dec(r.efrisPassword),
    efrisPrivateKeyPath: r.efrisPrivateKeyPath || '',
    managerEndpoint: r.managerEndpoint || '', managerToken: dec(r.managerToken),
    enablerUrl: r.enablerUrl || '', enablerMode: r.enablerMode || 'off', enablerDeviceNo: r.enablerDeviceNo || '',
    vatRegistered: !!r.vatRegistered, businessName: r.businessName || '', tradeName: r.tradeName || '',
    address: r.address || '', brn: r.brn || '', phone: r.phone || '', email: r.email || '',
  };
}

function listTenants() { const all = loadAll(); return Object.keys(all).map(id => meta(id, all[id])); }
function delTenant(id) { const all = loadAllForWrite(); delete all[id]; saveAll(all); }

// Unlock the DPAPI-protected master key in the background at startup. The first
// PowerShell after a reboot or a long idle can take minutes (antivirus scan, .NET
// load); doing it here, asynchronously, means no request waits on it. Until it
// finishes, requests that need the key get a "try again shortly" error; if it
// fails, masterKey() unlocks the key itself on the next request.
function warm() {
  if (_mk || process.env.VAULT_MASTER_KEY || process.platform !== 'win32' || !fs.existsSync(MASTER_DPAPI)) return;
  // Native DPAPI answers in milliseconds: unlock now, no background PowerShell needed.
  if (_native) {
    const t0 = Date.now();
    try {
      const k = Buffer.from(dpapi('Unprotect', fs.readFileSync(MASTER_DPAPI, 'utf8')), 'base64');
      if (k.length === 32 && dpapiVia === 'native') { _mk = k; console.log('   Vault: key unlocked (native, ' + (Date.now() - t0) + ' ms).'); return; }
      if (k.length === 32) { _mk = k; console.log('   Vault: key unlocked (PowerShell, ' + Math.round((Date.now() - t0) / 1000) + ' s).'); return; }
    } catch (_) { /* fall through to the background PowerShell unlock */ }
  }
  const { execFile } = require('child_process');
  const ps = 'Add-Type -AssemblyName System.Security; ' +
    '$b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); ' +
    '$r=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine); ' +
    '[Convert]::ToBase64String($r)';
  const t0 = Date.now();
  _warming = true;
  const child = execFile(path.join(paths.SYS32, 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command', ps],
    { encoding: 'utf8', windowsHide: true, timeout: 600000 }, (err, out) => {
      _warming = false;
      if (_mk) return;
      if (err) { console.log('   Vault: background unlock did not finish (' + (err.code || err.message) + '); it will be retried when needed.'); return; }
      const k = Buffer.from(String(out || '').trim(), 'base64');
      if (k.length === 32) { _mk = k; const s = Math.round((Date.now() - t0) / 1000); console.log('   Vault: key unlocked (PowerShell, ' + s + ' s).'); }
    });
  try { child.stdin.end(fs.readFileSync(MASTER_DPAPI, 'utf8')); } catch (_) { _warming = false; try { child.kill(); } catch (__) {} }
}

function isUnlocked() { return !!(_mk || process.env.VAULT_MASTER_KEY); }

// ── Relay-wide records ──
// Settings that belong to the relay, not to one business (the outgoing email
// server). Kept in their own file so they never show up as a business. Same
// encryption: the fields named in `secrets` are AES-GCM encrypted at rest.
const RELAY_FILE = path.join(DATA_DIR, 'relay_vault.json');
function loadRelayAll(forWrite) { return readVaultFile(RELAY_FILE, !!forWrite, 'Relay settings file'); }
// Decrypted record (server-side only), or null when none is saved.
function getRelay(name, secrets) {
  const r = loadRelayAll(false)[name];
  if (!r) return null;
  if (!_mk && _warming && (secrets || []).some(k => r[k])) throw lockedError();
  const out = { ...r };
  for (const k of secrets || []) out[k] = dec(r[k]);
  return out;
}
// Merge into a record. A secret field: a value encrypts it, '' clears it,
// undefined leaves it. rec === null removes the record.
function putRelay(name, rec, secrets) {
  const all = loadRelayAll(true);
  if (rec === null) { delete all[name]; }
  else {
    const out = { ...(all[name] || {}) };
    for (const k of Object.keys(rec)) {
      if (rec[k] === undefined) continue;
      out[k] = (secrets || []).includes(k) ? (rec[k] ? enc(rec[k]) : '') : rec[k];
    }
    out.updatedAt = new Date().toISOString();
    all[name] = out;
  }
  writeDurable(RELAY_FILE, JSON.stringify(all, null, 2), { mode: 0o600, backup: true });
}
// True when the record has a non-empty value in that (secret) field, without decrypting.
function relayHas(name, field) { const r = loadRelayAll(false)[name]; return !!(r && r[field]); }

module.exports = { putTenant, getTenant, getProfile, setSecretSink, meta, listTenants, delTenant, warm, isUnlocked, getRelay, putRelay, relayHas, RELAY_FILE, _enc: enc, _dec: dec };
