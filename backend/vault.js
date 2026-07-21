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
//   2. Self-hosted fallback: a per-install random key persisted at
//      backend/data/.vault_master (gitignored, 0600). Good enough for a single
//      taxpayer on their own machine; NOT for shared cloud.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Where the vault + local master key live. Defaults to backend/data for a
// self-hoster. On a cloud/container host, set VAULT_DIR to a mounted persistent
// volume so credentials survive redeploys - and mount it OUTSIDE backend/data so
// the bundled read-only commodity catalog is not hidden by the mount.
const DATA_DIR = process.env.VAULT_DIR || path.join(__dirname, 'data');
const FILE = path.join(DATA_DIR, 'credentials_vault.json');
const MASTER_FILE = path.join(DATA_DIR, '.vault_master');

let _mk = null;
function masterKey() {
  if (_mk) return _mk;
  const b64 = process.env.VAULT_MASTER_KEY || '';
  if (b64) {
    const k = Buffer.from(b64, 'base64');
    if (k.length === 32) { _mk = k; return _mk; }
    // Fail loud rather than silently falling back to a local key: a wrong
    // VAULT_MASTER_KEY on a shared/cloud deployment would otherwise decrypt the
    // vault incorrectly (or per-replica), causing silent data loss.
    throw new Error('VAULT_MASTER_KEY is set but invalid - it must be base64 of exactly 32 bytes.');
  }
  try { const k = fs.readFileSync(MASTER_FILE); if (k.length === 32) { _mk = k; return _mk; } } catch (_) {}
  _mk = crypto.randomBytes(32);
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(MASTER_FILE, _mk, { mode: 0o600 }); } catch (_) {}
  console.log('   ⚠ No VAULT_MASTER_KEY set - generated a local master key at backend/data/.vault_master (fine for a single self-hosted taxpayer; set VAULT_MASTER_KEY for cloud).');
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
    console.log('   ⚠ Vault decryption failed (wrong VAULT_MASTER_KEY or corrupted entry): ' + e.message);
    return '';
  }
}

function loadAll() { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (_) { return {}; } }
function saveAll(o) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(o, null, 2), { mode: 0o600 }); } catch (e) { console.log('vault write error: ' + e.message); } }

// Fields that MUST be encrypted at rest. Everything else is non-secret metadata.
const SECRET = ['efrisPrivateKeyPem', 'efrisPassphrase', 'managerToken'];

// Non-secret view for listing/UI - never includes decrypted secrets.
function meta(id, r) {
  r = r || loadAll()[id] || {};
  return {
    id, tin: r.tin || '', deviceNo: r.deviceNo || '', businessName: r.businessName || '',
    managerEndpoint: r.managerEndpoint || '', mode: r.mode || 'sandbox',
    hasEfrisKey: !!(r.efrisPrivateKeyPem || r.efrisPrivateKeyPath),
    hasManagerToken: !!r.managerToken, updatedAt: r.updatedAt || '',
  };
}

// Create/merge a tenant record. Secret fields are encrypted; pass '' to clear a
// secret, or omit a field to leave it unchanged.
function putTenant(id, rec) {
  if (!id) throw new Error('tenant id required');
  const all = loadAll();
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
function getTenant(id) {
  const r = loadAll()[id];
  if (!r) return null;
  return {
    id, tin: r.tin || '', deviceNo: r.deviceNo || '', mode: r.mode || 'sandbox',
    efrisPrivateKeyPem: dec(r.efrisPrivateKeyPem), efrisPassphrase: dec(r.efrisPassphrase),
    efrisPrivateKeyPath: r.efrisPrivateKeyPath || '',
    managerEndpoint: r.managerEndpoint || '', managerToken: dec(r.managerToken),
    enablerUrl: r.enablerUrl || '', enablerMode: r.enablerMode || 'off', enablerDeviceNo: r.enablerDeviceNo || '',
    vatRegistered: !!r.vatRegistered, businessName: r.businessName || '', tradeName: r.tradeName || '',
    address: r.address || '', brn: r.brn || '', phone: r.phone || '', email: r.email || '',
  };
}

function listTenants() { const all = loadAll(); return Object.keys(all).map(id => meta(id, all[id])); }
function delTenant(id) { const all = loadAll(); delete all[id]; saveAll(all); }

module.exports = { putTenant, getTenant, meta, listTenants, delTenant, _enc: enc, _dec: dec };
