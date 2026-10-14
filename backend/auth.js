'use strict';
// ── Users, sessions and roles ────────────────────────────────────────────────
// Everything that decides who is signed in and what they may do.
//
// users.json     the accounts: login name, display name, scrypt hash and salt,
//                roles per business { tenantId: 'admin'|'accountant'|'cashier' },
//                owner flag, lockout state, hashed recovery code, optional email
//                address, hashed emailed code. Also the hashed one-time setup
//                code while no account exists.
// sessions.json  SHA-256 of each session token (never the token itself), so a
//                relay restart keeps "remember this computer" sessions.
// owner-reset.json  a hashed one-time owner reset code written by reset-owner.js.
//                Kept apart from users.json so the CLI never races the relay.
// EFRIS Connect setup code.txt  the plaintext setup or reset code for the person
//                at the server (DATA_DIR is restricted to admins and the service).
//
// All files live in DATA_DIR, are written atomically, and a file that exists but
// does not parse is never overwritten (the accounts would be lost).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DATA_DIR } = require('./paths');
const { validEmail } = require('./mailer');

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const RESET_FILE = path.join(DATA_DIR, 'owner-reset.json');
const CODE_FILE = path.join(DATA_DIR, 'EFRIS Connect setup code.txt');

const SCRYPT = { N: 16384, r: 8, p: 1 };
const MIN_PASSWORD = 8;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60000;
const IDLE_MS = 8 * 3600000;
const ABS_REMEMBER_MS = 30 * 86400000;
const ABS_MS = 12 * 3600000;
const CODE_TTL_MS = 24 * 3600000;
const EMAIL_CODE_TTL_MS = 30 * 60000;   // an emailed code: 30 minutes, one use
const EMAIL_CODE_MAX_PER_HOUR = 3;
const EMAIL_CODE_MAX_TRIES = 5;          // wrong guesses before the emailed code is void
const ROLES = ['admin', 'accountant', 'cashier'];

// ── Permissions ──
// cashier:    sell, look things up, see the offline queue and its own log entries.
// accountant: cashier + credit/debit notes, reports, stock, number series, the
//             whole submission log, reconcile.
// admin:      everything ('*').
const CASHIER = ['view', 'sell', 'customers', 'goods-read', 'queue', 'log-own'];
const ROLE_PERMS = {
  cashier: CASHIER,
  accountant: CASHIER.concat(['credit', 'reports', 'stock', 'series', 'log-all', 'reconcile']),
  admin: ['*'],
};

// Test hook: tests move the clock to check expiry. Not used at runtime.
let clock = () => Date.now();
const now = () => clock();

// ── Files ──
function writeFileAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  try { fs.writeFileSync(tmp, data, { mode: 0o600 }); }
  catch (e) { try { fs.rmSync(tmp, { force: true }); } catch (_) {} throw e; }
  try { fs.renameSync(tmp, file); }
  catch (e) {
    // Windows: antivirus/indexer can hold the target open for a moment; write in place.
    try { fs.writeFileSync(file, data, { mode: 0o600 }); } finally { try { fs.rmSync(tmp, { force: true }); } catch (_) {} }
  }
}
// Read a JSON file for a read-modify-write. Missing or empty -> dflt; present but
// unparsable -> throw, so the caller never replaces it with a near-empty copy.
function readJsonStrict(file, dflt) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return dflt; throw e; }
  if (!raw.trim()) return dflt;
  try { return JSON.parse(raw); }
  catch (e) {
    const err = new Error('The file ' + path.basename(file) + ' in ' + DATA_DIR + ' is damaged and was not changed. Restore it from a backup or move it aside.');
    err.code = 'AUTH_FILE_DAMAGED'; err.status = 500; err.expose = true;
    console.log('   ⚠ ' + err.message + ' (' + e.message + ')');
    throw err;
  }
}

function loadDb() {
  const db = readJsonStrict(USERS_FILE, null) || {};
  if (!Array.isArray(db.users)) db.users = [];
  return db;
}
function saveDb(db) { writeFileAtomic(USERS_FILE, JSON.stringify(db, null, 2)); }

// Sessions are kept in memory and written on change; this process is their only writer.
let _sessions = null;
let _sessionsDirty = 0;
function sessions() {
  if (!_sessions) {
    try { _sessions = readJsonStrict(SESSIONS_FILE, {}) || {}; }
    catch (_) { _sessions = {}; }   // a damaged session file only signs everyone out
    purgeSessions(false);
  }
  return _sessions;
}
function saveSessions() { _sessionsDirty = now(); writeFileAtomic(SESSIONS_FILE, JSON.stringify(_sessions || {}, null, 2)); }

// ── Hashing ──
function scryptHex(secret, salt) { return crypto.scryptSync(String(secret), salt, 64, SCRYPT).toString('hex'); }
function hashSecret(secret) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: scryptHex(secret, salt) }; }
function checkSecret(secret, salt, hash) {
  if (!salt || !hash) return false;
  const a = Buffer.from(scryptHex(secret, salt), 'hex'), b = Buffer.from(String(hash), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
// Spend about the same time on an unknown name as on a wrong password.
const DUMMY = hashSecret('not-a-real-password');

// ── Codes ──
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';   // no I, O, 0, 1
function randomChars(n) { let s = ''; for (let i = 0; i < n; i++) s += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]; return s; }
function newRecoveryCode() { return [0, 1, 2, 3].map(() => randomChars(4)).join('-'); }
const normRecovery = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const WORDS = ('apple bamboo banana beach bell berry bird blue boat bread brick bridge brook brush cabin camel candle canoe ' +
  'carpet cedar chair chalk cherry cloud clover coast cocoa coffee comet coral cotton crane creek crown daisy dawn delta ' +
  'desert dolphin dove dragon drum eagle earth echo elbow ember fabric falcon feather fern field flame flute forest fossil ' +
  'fox garden garlic ginger glass globe goat gold grape grass gravel harbor hazel hill honey horse island ivory jacket ' +
  'jungle kettle kite ladder lake lamp lemon lily lime linen lion lotus mango maple marble meadow melon mint moon moss ' +
  'mountain music nectar needle nest nickel oak ocean olive onion orange orchid otter owl paddle palm panda paper parrot ' +
  'peach pearl pebble pepper piano pillow pine planet plum pond poppy potato prairie pumpkin quartz rabbit radio rain ' +
  'raven reed ribbon river robin rocket rose ruby saddle salmon sand sapphire shell silver sky slate snow spice spider ' +
  'spring spruce star stone storm stream sugar summit sun swan table thunder tiger timber tomato topaz tulip turtle ' +
  'valley velvet violet wagon walnut water whale wheat willow window winter wolf zebra').split(' ');
function newWordCode() {
  const w = () => WORDS[crypto.randomInt(WORDS.length)].toUpperCase();
  return w() + '-' + w() + '-' + String(crypto.randomInt(100)).padStart(2, '0');
}
const normWordCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]+/g, '-').replace(/^-|-$/g, '');

function writeCodeFile(code, what) {
  const text = what === 'reset'
    ? 'EFRIS Connect owner password reset code (one use, valid 24 hours). Enter it under "Forgot password" on the relay\'s own computer.\r\n\r\n' + code + '\r\n'
    : 'EFRIS Connect setup code (one use, valid 24 hours). Enter it in "Create the owner account" when you are not on the relay\'s own computer.\r\n\r\n' + code + '\r\n';
  writeFileAtomic(CODE_FILE, text);
  return CODE_FILE;
}

// ── Users ──
const normName = n => String(n || '').trim().toLowerCase();
function validatePassword(p) {
  if (typeof p !== 'string' || p.length < MIN_PASSWORD) return 'The password must be at least ' + MIN_PASSWORD + ' characters.';
  if (p.length > 200) return 'The password is too long.';
  return '';
}
// '' clears the address; anything else must look like an email address.
function cleanEmail(e) {
  if (e == null) return '';
  const v = String(e).trim();
  if (!v) return '';
  if (!validEmail(v)) throw userError('Enter a valid email address, for example name@example.com, or leave it empty.');
  return v;
}
function validName(n) { return typeof n === 'string' && /^[^\s].{0,63}$/.test(n.trim()) && n.trim().length >= 2; }
function cleanRoles(roles) {
  const out = {};
  for (const [t, r] of Object.entries(roles && typeof roles === 'object' ? roles : {})) {
    const tid = String(t || '').trim();
    if (tid && ROLES.includes(r)) out[tid] = r;
  }
  return out;
}
function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, displayName: u.displayName || u.name, email: u.email || '', owner: !!u.owner, disabled: !!u.disabled,
    roles: { ...(u.roles || {}) }, lastLogin: u.lastLogin || '', createdAt: u.createdAt || '', lockedUntil: (u.lockedUntil && u.lockedUntil > now()) ? u.lockedUntil : 0 };
}
function hasUsers() { try { return loadDb().users.length > 0; } catch (_) { return true; } }   // damaged file: never offer setup
function getUser(id) { return loadDb().users.find(u => u.id === id) || null; }
function findByName(name) { const n = normName(name); return loadDb().users.find(u => normName(u.name) === n) || null; }
function listUsers() { return loadDb().users.map(publicUser); }
function listOwners() { return loadDb().users.filter(u => u.owner).map(publicUser); }

function makeUser({ name, displayName, password, roles, owner, email }) {
  if (!validName(name)) throw userError('Enter a sign-in name (2 to 64 characters).');
  const bad = validatePassword(password); if (bad) throw userError(bad);
  const mail = cleanEmail(email);
  const { salt, hash } = hashSecret(password);
  return { id: crypto.randomUUID(), name: String(name).trim(), displayName: String(displayName || '').trim().slice(0, 80) || String(name).trim(), email: mail,
    salt, hash, roles: cleanRoles(roles), owner: !!owner, disabled: false, failedCount: 0, lockedUntil: 0, lastLogin: '',
    createdAt: new Date(now()).toISOString(), recoveryHash: null };
}
function userError(msg, status) { const e = new Error(msg); e.status = status || 400; e.expose = true; e.userError = true; return e; }

// ── Setup code (first owner) ──
// Generated at startup while there is no account. Only its hash is kept; the
// plaintext goes to the console and the protected setup-code file.
function ensureSetupCode() {
  const db = loadDb();
  if (db.users.length) return null;
  const code = newWordCode();
  const { salt, hash } = hashSecret(normWordCode(code));
  db.setup = { salt, hash, expiresAt: now() + CODE_TTL_MS };
  saveDb(db);
  let file = '';
  try { file = writeCodeFile(code, 'setup'); } catch (e) { console.log('   ⚠ Could not write the setup code file: ' + e.message); }
  return { code, file };
}
function checkSetupCode(code) {
  const db = loadDb(); const s = db.setup;
  if (!s || !code || s.expiresAt < now()) return false;
  return checkSecret(normWordCode(code), s.salt, s.hash);
}

// Create the first account (owner). Only while no account exists.
function createOwner({ name, displayName, password }) {
  const db = loadDb();
  if (db.users.length) throw userError('The owner account already exists. Sign in instead.', 409);
  const u = makeUser({ name, displayName, password, owner: true, roles: {} });
  const recoveryCode = newRecoveryCode();
  u.recoveryHash = hashSecret(normRecovery(recoveryCode));
  db.users.push(u);
  delete db.setup;   // single use
  saveDb(db);
  try { if (fs.existsSync(CODE_FILE)) fs.rmSync(CODE_FILE, { force: true }); } catch (_) {}
  return { user: publicUser(u), recoveryCode };
}

// ── Sessions ──
// opts.localAuto: a session the relay opened by itself in single-user mode. It is
// only accepted from the relay's own computer and ends when the mode is turned off.
function createSession(userId, remember, opts) {
  const token = crypto.randomBytes(32).toString('base64url');
  const t = now();
  sessions()[sha256(token)] = { userId, createdAt: t, lastSeen: t, remember: !!remember };
  if (opts && opts.localAuto) sessions()[sha256(token)].localAuto = true;
  saveSessions();
  return { token, expiresAt: sessionExpiry(sessions()[sha256(token)]) };
}
function sessionExpiry(s) { return Math.min(s.lastSeen + IDLE_MS, s.createdAt + (s.remember ? ABS_REMEMBER_MS : ABS_MS)); }
function purgeSessions(save) {
  const all = _sessions || {}; let n = 0;
  for (const [h, s] of Object.entries(all)) if (!s || sessionExpiry(s) <= now()) { delete all[h]; n++; }
  if (n && save !== false) saveSessions();
  return n;
}
// The user behind a bearer token, or null (unknown, expired, user gone or disabled).
function sessionFromToken(token) {
  if (!token || typeof token !== 'string' || token.length > 200) return null;
  const h = sha256(token);
  const s = sessions()[h];
  if (!s) return null;
  if (sessionExpiry(s) <= now()) { delete sessions()[h]; saveSessions(); return null; }
  const u = getUser(s.userId);
  if (!u || u.disabled) { delete sessions()[h]; saveSessions(); return null; }
  const t = now();
  s.lastSeen = t;
  // lastSeen only matters to the minute; do not rewrite the file on every request.
  if (t - _sessionsDirty > 60000) saveSessions();
  return { user: u, hash: h, session: s, expiresAt: sessionExpiry(s) };
}
function logout(token) {
  const h = sha256(token || '');
  if (sessions()[h]) { delete sessions()[h]; saveSessions(); return true; }
  return false;
}
// Single-user mode was turned off: its automatic sessions end.
function revokeLocalAutoSessions() {
  let n = 0;
  for (const [h, s] of Object.entries(sessions())) if (s && s.localAuto) { delete sessions()[h]; n++; }
  if (n) saveSessions();
  return n;
}
function revokeUserSessions(userId, exceptHash) {
  let n = 0;
  for (const [h, s] of Object.entries(sessions())) if (s.userId === userId && h !== exceptHash) { delete sessions()[h]; n++; }
  if (n) saveSessions();
  return n;
}

// ── Sign-in ──
const GENERIC = 'Wrong sign-in name or password.';
function login(name, password, remember) {
  const db = loadDb();
  const u = db.users.find(x => normName(x.name) === normName(name));
  if (!u) { checkSecret(String(password || ''), DUMMY.salt, DUMMY.hash); return { success: false, error: GENERIC }; }
  if (u.lockedUntil && u.lockedUntil > now()) {
    return { success: false, error: 'Too many wrong passwords. This account is locked for 15 minutes.', lockedUntil: u.lockedUntil };
  }
  if (!checkSecret(String(password || ''), u.salt, u.hash)) {
    u.failedCount = (u.failedCount || 0) + 1;
    let lockedUntil;
    if (u.failedCount >= MAX_FAILS) { u.lockedUntil = lockedUntil = now() + LOCK_MS; u.failedCount = 0; console.log('   ⚠ Sign-in: account "' + u.name + '" locked for 15 minutes after ' + MAX_FAILS + ' wrong passwords'); }
    saveDb(db);
    return lockedUntil ? { success: false, error: 'Too many wrong passwords. This account is locked for 15 minutes.', lockedUntil, justLocked: publicUser(u) } : { success: false, error: GENERIC };
  }
  if (u.disabled) return { success: false, error: 'This account is disabled. Ask your administrator.' };
  u.failedCount = 0; u.lockedUntil = 0; u.lastLogin = new Date(now()).toISOString();
  saveDb(db);
  const s = createSession(u.id, remember);
  return { success: true, token: s.token, expiresAt: s.expiresAt, user: publicUser(u) };
}

// ── Recovery ──
// code is the user's recovery code, or (allowReset: request from the relay's own
// PC) a reset code from reset-owner.js, which only works for an owner.
function readReset() { try { return JSON.parse(fs.readFileSync(RESET_FILE, 'utf8')); } catch (_) { return null; } }
function recover(name, code, newPassword, opts) {
  opts = opts || {};
  const bad = validatePassword(newPassword); if (bad) return { success: false, error: bad };
  const db = loadDb();
  const u = db.users.find(x => normName(x.name) === normName(name));
  const fail = { success: false, error: 'That name and code do not match.' };
  if (!u) { checkSecret('x', DUMMY.salt, DUMMY.hash); return fail; }
  if (u.disabled) return fail;
  let ok = false, usedReset = false, usedEmail = false;
  if (u.recoveryHash && /^[A-Z0-9]{16}$/.test(normRecovery(code))) ok = checkSecret(normRecovery(code), u.recoveryHash.salt, u.recoveryHash.hash);
  // An emailed code (8 characters) works from any computer, once, for 30 minutes.
  if (!ok && u.emailCode && /^[A-Z0-9]{8}$/.test(normRecovery(code))) {
    const ec = u.emailCode;
    if (ec.expiresAt > now() && checkSecret(normRecovery(code), ec.salt, ec.hash)) { ok = true; usedEmail = true; }
    else if (ec.expiresAt <= now()) { delete u.emailCode; saveDb(db); }
    else { ec.tries = (ec.tries || 0) + 1; if (ec.tries >= EMAIL_CODE_MAX_TRIES) delete u.emailCode; saveDb(db); }
  }
  if (!ok && opts.allowReset && u.owner) {
    const r = readReset();
    if (r && r.expiresAt > now() && (!r.userId || r.userId === u.id) && checkSecret(normWordCode(code), r.salt, r.hash)) { ok = true; usedReset = true; }
  }
  if (!ok) return fail;
  delete u.emailCode;   // any reset spends an emailed code
  const ph = hashSecret(newPassword);
  u.salt = ph.salt; u.hash = ph.hash; u.failedCount = 0; u.lockedUntil = 0; u.lastLogin = new Date(now()).toISOString();
  const recoveryCode = newRecoveryCode();
  u.recoveryHash = hashSecret(normRecovery(recoveryCode));   // the old code is spent
  saveDb(db);
  if (usedReset) { try { fs.rmSync(RESET_FILE, { force: true }); fs.rmSync(CODE_FILE, { force: true }); } catch (_) {} }
  revokeUserSessions(u.id);
  const s = createSession(u.id, false);
  const method = usedReset ? 'reset' : usedEmail ? 'email' : 'recovery';
  console.log('   Sign-in: password of "' + u.name + '" reset with ' + (usedReset ? 'an owner reset code' : usedEmail ? 'an emailed code' : 'its recovery code'));
  return { success: true, token: s.token, expiresAt: s.expiresAt, recoveryCode, user: publicUser(u), method };
}

// A one-time code to email to a user (Forgot password > Email me a code, or an
// admin's "Email a code to the user"). Only its hash is kept; a new code replaces
// the previous one. At most EMAIL_CODE_MAX_PER_HOUR per user per hour.
// lookup: { id } or { name }. Returns { code, user } or { error, limited } (no
// account, no email, disabled, too many). The caller must not tell a signed-out
// person which one it was.
function issueEmailCode(lookup) {
  const db = loadDb();
  const u = db.users.find(x => (lookup.id ? x.id === lookup.id : normName(x.name) === normName(lookup.name)));
  if (!u || u.disabled || !u.email) { hashSecret('x'); return { error: 'This user has no email address.' }; }
  const t = now();
  const sends = (Array.isArray(u.emailSends) ? u.emailSends : []).filter(x => t - x < 3600000);
  if (sends.length >= EMAIL_CODE_MAX_PER_HOUR) { u.emailSends = sends; saveDb(db); return { error: 'A code was already sent ' + EMAIL_CODE_MAX_PER_HOUR + ' times in the last hour. Wait a while and try again.', limited: true }; }
  const code = randomChars(8);
  const h = hashSecret(code);
  u.emailCode = { salt: h.salt, hash: h.hash, expiresAt: t + EMAIL_CODE_TTL_MS, tries: 0 };
  sends.push(t); u.emailSends = sends;
  saveDb(db);
  return { code, user: publicUser(u) };
}

// The signed-in user's own email address. Needs the current password, because
// the address can be used to reset the password.
function setOwnEmail(userId, current, email) {
  const db = loadDb(); const u = db.users.find(x => x.id === userId);
  if (!u) return { success: false, error: 'Account not found.' };
  if (!checkSecret(String(current || ''), u.salt, u.hash)) return { success: false, error: 'The current password is wrong.' };
  let mail;
  try { mail = cleanEmail(email); } catch (e) { return { success: false, error: e.message }; }
  const previous = u.email || '';
  u.email = mail;
  if (!mail) delete u.emailCode;
  saveDb(db);
  return { success: true, user: publicUser(u), previous, changed: previous !== mail };
}

// Written by reset-owner.js (run by a Windows administrator / root on the relay host).
function writeResetCode(ownerName) {
  const db = loadDb();
  const owners = db.users.filter(u => u.owner);
  if (!owners.length) throw new Error('There is no owner account yet. Start EFRIS Connect and create it in Manager.');
  let userId = null;
  if (ownerName) {
    const u = owners.find(x => normName(x.name) === normName(ownerName));
    if (!u) throw new Error('No owner account is called "' + ownerName + '". Owners: ' + owners.map(o => o.name).join(', '));
    userId = u.id;
  }
  const code = newWordCode();
  const { salt, hash } = hashSecret(normWordCode(code));
  writeFileAtomic(RESET_FILE, JSON.stringify({ salt, hash, userId, expiresAt: now() + CODE_TTL_MS, createdAt: new Date(now()).toISOString() }, null, 2));
  const file = writeCodeFile(code, 'reset');
  return { code, file, owners: owners.map(o => o.name) };
}

function changeOwnPassword(userId, current, next, keepHash) {
  const db = loadDb(); const u = db.users.find(x => x.id === userId);
  if (!u) return { success: false, error: 'Account not found.' };
  if (!checkSecret(String(current || ''), u.salt, u.hash)) return { success: false, error: 'The current password is wrong.' };
  const bad = validatePassword(next); if (bad) return { success: false, error: bad };
  const ph = hashSecret(next); u.salt = ph.salt; u.hash = ph.hash;
  saveDb(db);
  revokeUserSessions(u.id, keepHash);   // other devices sign in again
  return { success: true };
}

// ── Administration ──
function addUser({ name, displayName, password, roles, owner, email }) {
  const db = loadDb();
  if (db.users.some(u => normName(u.name) === normName(name))) throw userError('That sign-in name is already taken.', 409);
  const u = makeUser({ name, displayName, password, roles, owner, email });
  db.users.push(u); saveDb(db);
  return publicUser(u);
}
// Apply changes to one user. fields: displayName, email, roles (full replacement), disabled, password, owner.
// The relay must keep at least one enabled owner.
function updateUser(id, fields) {
  const db = loadDb(); const u = db.users.find(x => x.id === id);
  if (!u) throw userError('User not found.', 404);
  const before = JSON.stringify({ o: u.owner, d: u.disabled });
  if (fields.displayName !== undefined) u.displayName = String(fields.displayName || '').trim().slice(0, 80) || u.name;
  if (fields.email !== undefined) { u.email = cleanEmail(fields.email); if (!u.email) delete u.emailCode; }
  if (fields.roles !== undefined) u.roles = cleanRoles(fields.roles);
  if (fields.disabled !== undefined) u.disabled = !!fields.disabled;
  if (fields.owner !== undefined) u.owner = !!fields.owner;
  if (fields.password !== undefined && fields.password !== '') {
    const bad = validatePassword(fields.password); if (bad) throw userError(bad);
    const ph = hashSecret(fields.password); u.salt = ph.salt; u.hash = ph.hash; u.failedCount = 0; u.lockedUntil = 0;
  }
  if (!db.users.some(x => x.owner && !x.disabled)) throw userError('There must always be at least one active owner.', 409);
  saveDb(db);
  if (u.disabled || (fields.password !== undefined && fields.password !== '') || before !== JSON.stringify({ o: u.owner, d: u.disabled })) revokeUserSessions(u.id);
  return publicUser(u);
}
// A business was deleted: nobody keeps a role in it.
function removeTenantRoles(tenantId) {
  const db = loadDb(); let n = 0;
  for (const u of db.users) if (u.roles && u.roles[tenantId]) { delete u.roles[tenantId]; n++; }
  if (n) saveDb(db);
  return n;
}
function grantRole(userId, tenantId, role) {
  const db = loadDb(); const u = db.users.find(x => x.id === userId);
  if (!u || !ROLES.includes(role)) return false;
  u.roles = u.roles || {}; u.roles[tenantId] = role; saveDb(db);
  return true;
}

// ── Permissions ──
// The set of permissions a user has in one business. tenantId omitted: the union
// over every business the user holds a role in. Owners are admin everywhere.
function permissionsFor(user, tenantId) {
  if (!user) return new Set();
  if (user.owner || user.service) return new Set(['*']);
  const roles = user.roles || {};
  const list = tenantId ? [roles[tenantId]] : Object.values(roles);
  const out = new Set();
  for (const r of list) for (const p of (ROLE_PERMS[r] || [])) out.add(p);
  return out;
}
function can(perms, p) { return perms.has('*') || perms.has(p); }
function roleIn(user, tenantId) { if (!user) return null; if (user.owner || user.service) return 'admin'; return (user.roles || {})[tenantId] || null; }

module.exports = {
  ROLE_PERMS, ROLES, MIN_PASSWORD, CODE_FILE, USERS_FILE, SESSIONS_FILE, RESET_FILE,
  hasUsers, getUser, findByName, listUsers, publicUser, validatePassword,
  ensureSetupCode, checkSetupCode, createOwner,
  createSession, sessionFromToken, logout, revokeUserSessions, revokeLocalAutoSessions, purgeSessions,
  login, recover, writeResetCode, changeOwnPassword, issueEmailCode, setOwnEmail, listOwners, EMAIL_CODE_TTL_MS, EMAIL_CODE_MAX_PER_HOUR,
  addUser, updateUser, removeTenantRoles, grantRole,
  permissionsFor, can, roleIn,
  _test: { setNow: fn => { clock = fn || (() => Date.now()); }, newRecoveryCode, newWordCode, WORDS, resetCache: () => { _sessions = null; } },
};
