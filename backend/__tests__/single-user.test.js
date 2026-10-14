'use strict';
// Single-user mode: the relay's own computer opens without sign-in (an owner
// session, marked local-auto); every other computer still signs in. Only an owner
// may toggle it, and it is refused in LAN mode.
const request = require('supertest');
const { loadRelay } = require('./helpers/relay');

const REMOTE = { 'X-Forwarded-For': '198.51.100.77' };
const status = (app, headers) => { const r = request(app).get('/api/auth/status'); for (const [k, v] of Object.entries(headers || {})) r.set(k, v); return r; };

describe('single-user mode (loopback relay)', () => {
  let relay, owner, admin;
  beforeAll(async () => {
    relay = loadRelay();
    owner = await relay.setupOwner();
    await relay.addTenant('su-a');
    admin = await relay.addUser('biz-admin', { 'su-a': 'admin' });
  });
  afterAll(() => relay.cleanup());

  test('off by default: no automatic session on this computer', async () => {
    const r = await status(relay.app);
    expect(r.body.user).toBeNull();
    expect(r.body.autoToken).toBeUndefined();
    expect(r.body.singleUser).toBe(false);
  });

  test('only an owner can toggle it', async () => {
    expect((await relay.as(admin).post('/api/admin/single-user', { enabled: true })).status).toBe(403);
    expect((await relay.as(admin).get('/api/admin/single-user')).status).toBe(403);
    expect((await request(relay.app).post('/api/admin/single-user').send({ enabled: true })).status).toBe(401);
    const r = await relay.as(owner).post('/api/admin/single-user', { enabled: true });
    expect(r.body).toMatchObject({ success: true, enabled: true, allowed: true });
  });

  test('on: a local request gets an owner session, marked local-auto', async () => {
    const r = await status(relay.app);
    expect(r.body.user).toMatchObject({ name: 'owner', owner: true });
    expect(r.body.localAuto).toBe(true);
    expect(typeof r.body.autoToken).toBe('string');
    const sessions = relay.readJson('sessions.json', {});
    expect(Object.values(sessions).some(s => s.localAuto)).toBe(true);
    // The token works on this computer...
    const me = await relay.as(r.body.autoToken).get('/api/auth/status');
    expect(me.body.user.name).toBe('owner');
    expect(me.body.autoToken).toBeUndefined();   // no second session
    expect((await relay.as(r.body.autoToken).get('/api/tenant')).status).toBe(200);
    // ...but not from another computer.
    expect((await relay.as(r.body.autoToken, REMOTE).get('/api/tenant')).status).toBe(401);
  });

  test('on: a remote request still needs sign-in', async () => {
    const r = await status(relay.app, REMOTE);
    expect(r.body.user).toBeNull();
    expect(r.body.autoToken).toBeUndefined();
    expect((await request(relay.app).get('/api/tenant').set(REMOTE)).status).toBe(401);
  });

  test('turning it off ends the automatic sessions', async () => {
    const tok = (await status(relay.app)).body.autoToken;
    expect((await relay.as(owner).post('/api/admin/single-user', { enabled: false })).body.enabled).toBe(false);
    expect((await relay.as(tok).get('/api/tenant')).status).toBe(401);
    expect((await status(relay.app)).body.user).toBeNull();
    // The owner's own (signed-in) session is untouched.
    expect((await relay.as(owner).get('/api/tenant')).status).toBe(200);
  });
});

describe('single-user mode in LAN mode', () => {
  let relay, owner;
  beforeAll(async () => {
    relay = loadRelay({ env: { LAN_MODE: '1', ALLOWED_HOSTS: 'shop-pc' } });
    owner = await relay.setupOwner();
  });
  afterAll(() => relay.cleanup());

  test('cannot be turned on, and nobody is signed in automatically', async () => {
    const r = await relay.as(owner).post('/api/admin/single-user', { enabled: true });
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ allowed: false, enabled: false });
    expect(r.body.blockedReason).toMatch(/LAN/);
    expect((await status(relay.app)).body.user).toBeNull();
  });
});
