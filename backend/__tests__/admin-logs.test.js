'use strict';
// GET /api/admin/logs and /api/admin/logs/:day return the relay's raw day files,
// which hold every business's entries: owners (and the service) only, masked.
const fs = require('fs');
const path = require('path');
const { loadRelay } = require('./helpers/relay');

const A = 'logs-a';
const DAY = '2026-10-01';
let relay, tok;
beforeAll(async () => {
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000001' })).body.success).toBe(true);
  tok = { owner: await relay.login('owner', 'owner-pass-123'), adminA: await relay.addUser('admin-a', { [A]: 'admin' }) };
  // A day file written before the logger masked its entries.
  const dir = path.join(relay.dataDir, 'logs');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, DAY + '.log'), [
    JSON.stringify({ time: DAY + 'T08:00:00Z', level: 'error', message: 'call failed password=old-pw-123', tenantId: 'other', meta: { managerToken: 'old-tok-456', url: 'http://m/api2?apiAccessToken=old-tok-789' } }),
    'not json Authorization: Bearer abcdefghijklmnop1234',
  ].join('\n') + '\n');
});
afterAll(() => relay.cleanup());

const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});

describe('/api/admin/logs', () => {
  test('a business admin is refused, with or without X-Tenant-Id', async () => {
    expect((await as('adminA', A).get('/api/admin/logs')).status).toBe(403);
    expect((await as('adminA').get('/api/admin/logs')).status).toBe(403);
    expect((await as('adminA', A).get('/api/admin/logs/' + DAY)).status).toBe(403);
  });

  test('the owner lists the days and reads a day, masked', async () => {
    const list = await as('owner').get('/api/admin/logs');
    expect(list.status).toBe(200);
    expect(list.body.days).toContain(DAY);
    const r = await as('owner').get('/api/admin/logs/' + DAY);
    expect(r.status).toBe(200);
    expect(r.text).toMatch(/call failed/);
    expect(r.text).not.toMatch(/old-pw-123|old-tok-456|old-tok-789|abcdefghijklmnop1234/);
    expect((await relay.get('/api/admin/logs/' + DAY)).status).toBe(200);   // service principal
  });
});
