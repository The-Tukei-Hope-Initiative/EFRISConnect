'use strict';
// Offline Enabler service control: only admins reach it, only start/stop/restart
// are accepted, and sc.exe output is read correctly.
const { loadRelay } = require('./helpers/relay');
const { parseState } = require('../enabler-control');

describe('reading sc.exe output', () => {
  test('states', () => {
    expect(parseState('SERVICE_NAME: TcsData\r\n        STATE              : 4  RUNNING\r\n')).toBe('running');
    expect(parseState('        STATE              : 1  STOPPED')).toBe('stopped');
    expect(parseState('        STATE              : 2  START_PENDING')).toBe('start-pending');
    expect(parseState('[SC] EnumQueryServicesStatus:OpenService FAILED 1060:')).toBe('not-installed');
  });
});

describe('Offline Enabler routes', () => {
  const T = 'enab-a';
  let relay, tok;
  beforeAll(async () => {
    relay = loadRelay();
    await relay.setupOwner();
    expect((await relay.addTenant(T)).body.success).toBe(true);
    tok = { admin: await relay.addUser('enab-admin', { [T]: 'admin' }), cashier: await relay.addUser('enab-cash', { [T]: 'cashier' }) };
  });
  afterAll(() => relay.cleanup());

  test('a cashier is refused', async () => {
    const as = relay.as(tok.cashier, { 'X-Tenant-Id': T });
    expect((await as.get('/api/admin/enabler')).status).toBe(403);
    expect((await as.post('/api/admin/enabler/stop')).status).toBe(403);
  });
  test('no sign-in is refused', async () => {
    const r = await require('supertest')(relay.app).get('/api/admin/enabler');
    expect(r.status).toBe(401);
  });
  test('an unknown action is refused before anything runs', async () => {
    const r = await relay.as(tok.admin, { 'X-Tenant-Id': T }).post('/api/admin/enabler/format-disk');
    expect(r.status).toBe(400);
  });
  test('an admin reads the status', async () => {
    const r = await relay.as(tok.admin, { 'X-Tenant-Id': T }).get('/api/admin/enabler');
    expect(r.status).toBe(200);
    expect(r.body.success).toBe(true);
    expect(typeof r.body.supported).toBe('boolean');
  });
});
