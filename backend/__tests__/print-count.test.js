'use strict';
// Reprint marking (URS 9.10): the relay keeps each document's print count per business.
const { loadRelay } = require('./helpers/relay');

const A = 'biz-a', B = 'biz-b';
let relay, tok;
beforeAll(async () => {
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000001' })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: '1000000002' })).body.success).toBe(true);
  tok = {
    cashierA: await relay.addUser('pc-cash-a', { [A]: 'cashier' }),
    cashierA2: await relay.addUser('pc-cash-a2', { [A]: 'cashier' }),
    cashierB: await relay.addUser('pc-cash-b', { [B]: 'cashier' }),
    both: await relay.addUser('pc-both', { [A]: 'cashier', [B]: 'cashier' }),
  };
});
afterAll(() => relay.cleanup());
const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});

describe('print count', () => {
  test('starts at 0 and counts each print, shared by every user of the business', async () => {
    expect((await as('cashierA', A).get('/api/print-count?key=FDN-1')).body).toMatchObject({ success: true, count: 0, firstAt: null });
    const p1 = await as('cashierA', A).post('/api/print-count', { key: 'FDN-1', ref: 'REC-1' });
    expect(p1.body).toMatchObject({ success: true, count: 1, firstBy: 'pc-cash-a', lastBy: 'pc-cash-a' });
    // Another cashier (another computer) of the same business sees it and adds a copy.
    expect((await as('cashierA2', A).get('/api/print-count?key=FDN-1')).body.count).toBe(1);
    const p2 = await as('cashierA2', A).post('/api/print-count', { key: 'FDN-1' });
    expect(p2.body).toMatchObject({ count: 2, firstBy: 'pc-cash-a', lastBy: 'pc-cash-a2' });
    expect(p2.body.firstAt <= p2.body.lastAt).toBe(true);
    const stored = Object.values(relay.readJson('print_counts.json'));
    expect(stored).toEqual([expect.objectContaining({ tenantId: A, key: 'FDN-1', ref: 'REC-1', count: 2 })]);
  });

  test('is scoped to the business: another business does not see or change it', async () => {
    expect((await as('cashierB', B).get('/api/print-count?key=FDN-1')).body.count).toBe(0);
    expect((await as('cashierB', B).post('/api/print-count', { key: 'FDN-1' })).body.count).toBe(1);
    expect((await as('cashierA', A).get('/api/print-count?key=FDN-1')).body.count).toBe(2);
    // A user of one business may not name another.
    expect((await as('cashierB', A).get('/api/print-count?key=FDN-1')).status).toBe(403);
  });

  test('a single-business user needs no business header; a multi-business user must name one', async () => {
    expect((await as('cashierA').get('/api/print-count?key=FDN-1')).body.count).toBe(2);
    const r = await as('both').get('/api/print-count?key=FDN-1');
    expect(r.status).toBe(400);
    expect((await as('both', B).get('/api/print-count?key=FDN-1')).body.count).toBe(1);
  });

  test('a key is required and the routes need sign-in', async () => {
    expect((await as('cashierA', A).post('/api/print-count', {})).status).toBe(400);
    expect((await require('supertest')(relay.app).get('/api/print-count?key=FDN-1')).status).toBe(401);
  });
});
