'use strict';
// Sign-in: first-owner setup, login, lockout, session expiry, remember, logout,
// recovery code and the owner reset code.
// "Another computer" is simulated with X-Forwarded-For (see helpers/relay.js).
const fs = require('fs');
const request = require('supertest');
const { loadRelay } = require('./helpers/relay');

const REMOTE = { 'X-Forwarded-For': '203.0.113.7' };
let relay, auth;
beforeAll(() => { relay = loadRelay(); auth = relay.app._auth; });
afterAll(() => { auth._test.setNow(null); relay.cleanup(); });

const post = (p, body, headers) => { const r = request(relay.app).post(p); for (const [k, v] of Object.entries(headers || {})) r.set(k, v); return r.send(body || {}); };

describe('first-run setup', () => {
  test('status says setup is needed and tells local from remote', async () => {
    const a = await request(relay.app).get('/api/auth/status');
    expect(a.body).toMatchObject({ success: true, setupNeeded: true, local: true, user: null, tenants: [] });
    const b = await request(relay.app).get('/api/auth/status').set(REMOTE);
    expect(b.body.local).toBe(false);
  });

  test('the setup code is written to the data folder and stored only hashed', () => {
    const sc = auth.ensureSetupCode();
    expect(sc.code).toMatch(/^[A-Z]+-[A-Z]+-\d{2}$/);
    expect(fs.readFileSync(sc.file, 'utf8')).toContain(sc.code);
    expect(fs.readFileSync(relay.file('users.json'), 'utf8')).not.toContain(sc.code);
    relay._code = sc.code;
  });

  test('from another computer, setup needs the code', async () => {
    const r = await post('/api/auth/setup', { name: 'boss', password: 'boss-pass-123' }, REMOTE);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ success: false, setupCodeRequired: true });
    const w = await post('/api/auth/setup', { setupCode: 'WRONG-CODE-00', name: 'boss', password: 'boss-pass-123' }, REMOTE);
    expect(w.status).toBe(403);
  });

  test('a short password is refused', async () => {
    const r = await post('/api/auth/setup', { name: 'boss', password: 'short' });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/at least 8/);
  });

  test('with the right code (any case, spaces) the owner is created from another computer', async () => {
    const code = relay._code.toLowerCase().replace(/-/g, ' ');
    const r = await post('/api/auth/setup', { setupCode: code, name: 'Boss', displayName: 'The Boss', password: 'boss-pass-123' }, REMOTE);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ success: true, user: { name: 'Boss', displayName: 'The Boss', owner: true } });
    expect(r.body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(r.body.recoveryCode).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/);
    relay._ownerToken = r.body.token;
    relay._recovery = r.body.recoveryCode;
    expect(fs.existsSync(auth.CODE_FILE)).toBe(false);
    const users = relay.readJson('users.json');
    expect(users.setup).toBeUndefined();
    expect(JSON.stringify(users)).not.toContain('boss-pass-123');
    expect(JSON.stringify(users)).not.toContain(r.body.recoveryCode);
  });

  test('a second setup is refused, even on this PC', async () => {
    const r = await post('/api/auth/setup', { name: 'other', password: 'other-pass-123' });
    expect(r.status).toBe(409);
  });

  test('status shows the signed-in owner', async () => {
    const r = await relay.as(relay._ownerToken).get('/api/auth/status');
    expect(r.body).toMatchObject({ setupNeeded: false, user: { name: 'Boss', owner: true } });
  });

  test('sessions are stored as hashes, never the token', () => {
    const raw = fs.readFileSync(relay.file('sessions.json'), 'utf8');
    expect(raw).not.toContain(relay._ownerToken);
    expect(Object.keys(JSON.parse(raw))[0]).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('setup on this PC needs no code', () => {
  test('loopback setup without a code works on a fresh relay', async () => {
    const r2 = loadRelay();
    try {
      const r = await request(r2.app).post('/api/auth/setup').send({ name: 'local', password: 'local-pass-123' });
      expect(r.body.success).toBe(true);
    } finally { r2.cleanup(); }
  });
});

describe('login, lockout, expiry, logout', () => {
  beforeAll(async () => {
    await request(relay.app).post('/api/auth/users').set('X-API-KEY', require('./helpers/relay').API_KEY)
      .send({ name: 'cash1', displayName: 'Cashier One', password: 'cash-pass-123', roles: { 'biz-a': 'cashier' } });
  });

  test('a signed-in user reaches a route; no token gets 401 with auth:true', async () => {
    const t = await relay.login('CASH1', 'cash-pass-123');   // names are case-insensitive
    expect((await relay.as(t).get('/api/submission-log')).status).toBe(200);
    const r = await request(relay.app).get('/api/submission-log');
    expect(r.status).toBe(401);
    expect(r.body.auth).toBe(true);
  });

  test('unknown name and wrong password get the same message', async () => {
    const a = await post('/api/auth/login', { name: 'nobody', password: 'whatever-123' }, { 'X-Forwarded-For': '198.18.0.1' });
    const b = await post('/api/auth/login', { name: 'cash1', password: 'wrong-pass-1' }, { 'X-Forwarded-For': '198.18.0.1' });
    expect(a.body).toEqual({ success: false, error: 'Wrong sign-in name or password.' });
    expect(b.body).toEqual({ success: false, error: 'Wrong sign-in name or password.' });
  });

  test('login is rate limited per address', async () => {
    let last;
    for (let i = 0; i < 11; i++) last = await post('/api/auth/login', { name: 'nobody', password: 'x' }, { 'X-Forwarded-For': '198.18.0.99' });
    expect(last.status).toBe(429);
  });

  test('5 wrong passwords lock the account for 15 minutes, even for the right password', async () => {
    await relay.addUser('locky', { 'biz-a': 'cashier' }, 'locky-pass-123');
    let r;
    for (let i = 0; i < 5; i++) r = await post('/api/auth/login', { name: 'locky', password: 'bad-pass-' + i }, { 'X-Forwarded-For': '198.18.1.' + i });
    expect(r.body.success).toBe(false);
    expect(r.body.lockedUntil).toBeGreaterThan(Date.now() + 14 * 60000);
    const ok = await post('/api/auth/login', { name: 'locky', password: 'locky-pass-123' }, { 'X-Forwarded-For': '198.18.1.9' });
    expect(ok.body).toMatchObject({ success: false });
    expect(ok.body.lockedUntil).toBeDefined();
    // After 15 minutes the right password works again.
    const t0 = Date.now();
    auth._test.setNow(() => t0 + 16 * 60000);
    try {
      const later = await post('/api/auth/login', { name: 'locky', password: 'locky-pass-123' }, { 'X-Forwarded-For': '198.18.1.10' });
      expect(later.body.success).toBe(true);
    } finally { auth._test.setNow(null); }
  });

  test('a session ends after 8 idle hours', async () => {
    const t = await relay.login('cash1', 'cash-pass-123');
    const t0 = Date.now();
    auth._test.setNow(() => t0 + 8 * 3600000 + 1000);
    try { expect((await relay.as(t).get('/api/submission-log')).status).toBe(401); }
    finally { auth._test.setNow(null); }
  });

  test('without "remember" a session ends after 12 hours even when active; with it, it lasts 30 days', async () => {
    const short = await relay.login('cash1', 'cash-pass-123');
    const long = await relay.login('cash1', 'cash-pass-123', { remember: true });
    const t0 = Date.now();
    try {
      // Stay active every 6 hours.
      for (let h = 6; h <= 12; h += 6) {
        auth._test.setNow(() => t0 + h * 3600000 + 1000);
        const s = (await relay.as(short).get('/api/submission-log')).status;
        expect(s).toBe(h < 12 ? 200 : 401);
        expect((await relay.as(long).get('/api/submission-log')).status).toBe(200);
      }
      let at = 12;
      for (; at <= 30 * 24 - 6; at += 6) { auth._test.setNow(() => t0 + at * 3600000); await relay.as(long).get('/api/submission-log'); }
      auth._test.setNow(() => t0 + (30 * 24 - 1) * 3600000);
      expect((await relay.as(long).get('/api/submission-log')).status).toBe(200);
      auth._test.setNow(() => t0 + (30 * 24 + 1) * 3600000);
      expect((await relay.as(long).get('/api/submission-log')).status).toBe(401);
    } finally { auth._test.setNow(null); }
  });

  test('sessions survive a relay restart', async () => {
    const t = await relay.login('cash1', 'cash-pass-123');
    auth._test.resetCache();   // as if the relay restarted: sessions reloaded from disk
    expect((await relay.as(t).get('/api/submission-log')).status).toBe(200);
  });

  test('logout ends the session', async () => {
    const t = await relay.login('cash1', 'cash-pass-123');
    expect((await relay.as(t).post('/api/auth/logout')).body.success).toBe(true);
    expect((await relay.as(t).get('/api/submission-log')).status).toBe(401);
  });

  test('a disabled user is signed out and cannot sign in', async () => {
    const t = await relay.addUser('gone', { 'biz-a': 'cashier' }, 'gone-pass-123');
    const id = (await relay.get('/api/auth/users')).body.users.find(u => u.name === 'gone').id;
    expect((await relay.post('/api/auth/users/' + id, { disabled: true })).body.success).toBe(true);
    expect((await relay.as(t).get('/api/submission-log')).status).toBe(401);
    const r = await post('/api/auth/login', { name: 'gone', password: 'gone-pass-123' }, { 'X-Forwarded-For': '198.18.2.1' });
    expect(r.body.success).toBe(false);
  });

  test('change password: needs the current one, signs out other sessions, keeps this one', async () => {
    const a = await relay.login('cash1', 'cash-pass-123');
    const b = await relay.login('cash1', 'cash-pass-123');
    expect((await relay.as(a).post('/api/auth/change-password', { currentPassword: 'nope-nope', newPassword: 'cash-pass-456' })).body.success).toBe(false);
    expect((await relay.as(a).post('/api/auth/change-password', { currentPassword: 'cash-pass-123', newPassword: 'cash-pass-456' })).body.success).toBe(true);
    expect((await relay.as(a).get('/api/submission-log')).status).toBe(200);
    expect((await relay.as(b).get('/api/submission-log')).status).toBe(401);
    await relay.login('cash1', 'cash-pass-456');
  });
});

describe('recovery', () => {
  test('the recovery code resets the password and is replaced by a new one', async () => {
    const r = await post('/api/auth/recover', { name: 'boss', code: relay._recovery.toLowerCase(), newPassword: 'boss-pass-456' }, REMOTE);
    expect(r.body).toMatchObject({ success: true, user: { name: 'Boss' } });
    expect(r.body.recoveryCode).not.toBe(relay._recovery);
    expect((await relay.as(relay._ownerToken).get('/api/auth/status')).body.user).toBeNull();   // old sessions ended
    expect((await relay.as(r.body.token).get('/api/auth/status')).body.user.name).toBe('Boss');
    // The old code is spent.
    const again = await post('/api/auth/recover', { name: 'boss', code: relay._recovery, newPassword: 'boss-pass-789' }, { 'X-Forwarded-For': '203.0.113.8' });
    expect(again.body.success).toBe(false);
    relay._recovery = r.body.recoveryCode;
  });

  test('a reset code from reset-owner.js works only on this PC, only for an owner, once', async () => {
    const { code, file } = auth.writeResetCode();
    expect(fs.readFileSync(file, 'utf8')).toContain(code);
    expect(fs.readFileSync(auth.RESET_FILE, 'utf8')).not.toContain(code);
    // From another computer: refused.
    expect((await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-pass-999' }, { 'X-Forwarded-For': '203.0.113.9' })).body.success).toBe(false);
    // Not an owner: refused.
    expect((await post('/api/auth/recover', { name: 'cash1', code, newPassword: 'cash-pass-999' })).body.success).toBe(false);
    // Owner on this PC: accepted.
    const ok = await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-pass-999' });
    expect(ok.body.success).toBe(true);
    expect(fs.existsSync(auth.RESET_FILE)).toBe(false);
    // Once only.
    expect((await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-pass-000' })).body.success).toBe(false);
  });

  test('an expired reset code is refused', async () => {
    const { code } = auth.writeResetCode('boss');
    const t0 = Date.now();
    auth._test.setNow(() => t0 + 25 * 3600000);
    try { expect((await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-pass-111' })).body.success).toBe(false); }
    finally { auth._test.setNow(null); }
  });
});

describe('damaged files', () => {
  test('an unparsable users.json is never overwritten', async () => {
    const r2 = loadRelay();
    try {
      fs.writeFileSync(r2.file('users.json'), '{ not json');
      const r = await request(r2.app).post('/api/auth/setup').send({ name: 'x1', password: 'xxxx-pass-1' });
      expect(r.body.success).not.toBe(true);
      expect(fs.readFileSync(r2.file('users.json'), 'utf8')).toBe('{ not json');
    } finally { r2.cleanup(); }
  });
});

describe('Control Centre: the one person signed in on this computer', () => {
  test('owner alone, signed in here: named; a second person anywhere, a cashier, or another computer: no', async () => {
    const r2 = loadRelay();
    try {
      const cs = h => { const q = request(r2.app).get('/api/auth/console-session'); for (const [k, v] of Object.entries(h || {})) q.set(k, v); return q; };
      expect((await cs()).body).toEqual({ success: true, user: null });   // nobody signed in
      const own = await request(r2.app).post('/api/auth/setup').send({ name: 'boss', displayName: 'The Boss', password: 'boss-pass-123' });
      expect((await cs()).body.user).toEqual({ name: 'boss', displayName: 'The Boss' });
      expect((await cs(REMOTE)).status).toBe(403);
      // A cashier signs in on a till: two people, so no automatic sign-in.
      await r2.addUser('till1', { 'biz-a': 'cashier' }, 'till1-pass-123');
      const c = await request(r2.app).post('/api/auth/login').set(REMOTE).send({ name: 'till1', password: 'till1-pass-123' });
      expect((await cs()).body.user).toBeNull();
      // The owner signs out: the cashier alone is not an admin, and signed in elsewhere.
      await request(r2.app).post('/api/auth/logout').set('Authorization', 'Bearer ' + own.body.token);
      expect((await cs()).body.user).toBeNull();
      await request(r2.app).post('/api/auth/logout').set('Authorization', 'Bearer ' + c.body.token);
      // The owner signed in only from another computer: not "on this computer".
      await request(r2.app).post('/api/auth/login').set(REMOTE).send({ name: 'boss', password: 'boss-pass-123' });
      expect((await cs()).body.user).toBeNull();
    } finally { r2.cleanup(); }
  });
});
