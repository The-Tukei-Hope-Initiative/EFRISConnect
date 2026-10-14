'use strict';
// A user with different roles in two businesses gets, for each entry, only what
// their role in THAT entry's business allows, whether or not X-Tenant-Id is sent.
// (Without it the route check uses the union of roles; the data must not.)
const { loadRelay } = require('./helpers/relay');

const A = 'scope-a', B = 'scope-b';
let relay, tok, ids;
beforeAll(async () => {
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000011' })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: '1000000022' })).body.success).toBe(true);
  tok = {
    mixed: await relay.addUser('mixed', { [A]: 'cashier', [B]: 'accountant' }),
    cashierA: await relay.addUser('cash-a2', { [A]: 'cashier' }),
  };
  const users = (await relay.get('/api/auth/users')).body.users;
  ids = Object.fromEntries(users.map(u => [u.name, u.id]));
  const day = '2026-10-09T08:00:00Z';
  relay.writeJson('submission_log.json', [
    { id: 'a-mine', fdn: 'FA1', tenantId: A, tin: '1000000011', userId: ids.mixed, status: 'success', submittedAt: day, totalAmount: 10 },
    { id: 'a-other', fdn: 'FA2', tenantId: A, tin: '1000000011', userId: ids['cash-a2'], status: 'success', submittedAt: day, totalAmount: 20 },
    { id: 'a-cn', fdn: 'FA3', kind: 'credit-note', tenantId: A, tin: '1000000011', userId: ids.mixed, status: 'success', reference: 'CN-A', submittedAt: day, totalAmount: -5 },
    { id: 'a-legacy', fdn: 'FA4', tin: '1000000011', userId: ids['cash-a2'], status: 'success', submittedAt: day, totalAmount: 1 },
    { id: 'b-other', fdn: 'FB1', tenantId: B, tin: '1000000022', userId: ids['cash-a2'], status: 'success', submittedAt: day, totalAmount: 40 },
    { id: 'b-cn', fdn: 'FB2', kind: 'credit-note', tenantId: B, tin: '1000000022', status: 'success', reference: 'CN-B', submittedAt: day, totalAmount: -8 },
  ]);
});
afterAll(() => relay.cleanup());

const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});
const ids_ = r => r.body.items.map(e => e.id).sort();

describe('per-entry permissions without X-Tenant-Id', () => {
  test('submission log: own cashier entries in A, everything (with notes) in B', async () => {
    expect(ids_(await as('mixed').get('/api/submission-log'))).toEqual(['a-mine', 'b-cn', 'b-other']);
    expect(ids_(await as('mixed', A).get('/api/submission-log'))).toEqual(['a-mine']);
    expect(ids_(await as('mixed', B).get('/api/submission-log'))).toEqual(['b-cn', 'b-other']);
  });

  test('credit notes and other users\' entries of A stay hidden by FDN lookup', async () => {
    expect((await as('mixed').get('/api/submission-log/by-fdn/FA2')).body.success).toBe(false);
    expect((await as('mixed').get('/api/submission-log/by-fdn/FA3')).body.success).toBe(false);
    expect((await as('mixed').get('/api/submission-log/by-fdn/FA4')).body.success).toBe(false);
    expect((await as('mixed').get('/api/submission-log/by-fdn/FB2')).body.success).toBe(true);
  });

  test('Z report counts only the businesses where the user may see reports', async () => {
    const r = await as('mixed').get('/api/z-report?date=2026-10-09');
    expect(r.body.documents.map(d => d.fdn).sort()).toEqual(['FB1', 'FB2']);
  });

  test('deleting an entry needs log-all in that entry\'s business', async () => {
    await as('mixed').delete('/api/submission-log/a-other');
    await as('mixed').delete('/api/submission-log/b-other');
    const left = relay.readJson('submission_log.json').map(e => e.id);
    expect(left).toContain('a-other');
    expect(left).not.toContain('b-other');
  });

  test('number series: changing one needs the series permission in its business', async () => {
    const own = await relay.login('owner', 'owner-pass-123');
    const mkA = await relay.as(own, { 'X-Tenant-Id': A }).post('/api/number-series', { name: 'A', prefix: 'SA', segments: ['prefix', 'counter'] });
    const mkB = await relay.as(own, { 'X-Tenant-Id': B }).post('/api/number-series', { name: 'B', prefix: 'SB', segments: ['prefix', 'counter'] });
    expect((await as('mixed').put('/api/number-series/' + mkA.body.series.id, { prefix: 'HACK' })).status).toBe(404);
    expect((await as('mixed').put('/api/number-series/' + mkB.body.series.id, { prefix: 'SB2' })).body.success).toBe(true);
    expect(relay.readJson('number_series.json').find(s => s.id === mkA.body.series.id).prefix).toBe('SA');
    // Using A's series (sell) is still fine for its cashier.
    expect((await as('mixed').post('/api/number-series/' + mkA.body.series.id + '/next')).body.success).toBe(true);
  });

  test('receipt snapshots: a cashier reads only the ones they saved', async () => {
    expect((await as('cashierA', A).post('/api/receipt-snapshot', { key: 'SNAP-OTHER', query: 'x=1' })).body.success).toBe(true);
    expect((await as('mixed', A).post('/api/receipt-snapshot', { key: 'SNAP-MINE', query: 'x=2' })).body.success).toBe(true);
    expect((await as('mixed').get('/api/receipt-snapshot?key=SNAP-OTHER')).body.success).toBe(false);
    expect((await as('mixed', A).get('/api/receipt-snapshot?key=SNAP-OTHER')).body.success).toBe(false);
    expect((await as('mixed').get('/api/receipt-snapshot?key=SNAP-MINE')).body.success).toBe(true);
    expect((await as('cashierA', A).get('/api/receipt-snapshot?key=SNAP-OTHER')).body.success).toBe(true);
  });

  test('offline queue: deleting needs log-all in the entry\'s business', async () => {
    relay.writeJson('offline_queue.json', [
      { id: 'q-a', tenantId: A, status: 'pending', reference: 'QA', cfgPublic: { tin: '1000000011' } },
      { id: 'q-b', tenantId: B, status: 'pending', reference: 'QB', cfgPublic: { tin: '1000000022' } },
    ]);
    expect((await as('mixed').get('/api/offline-queue')).body.items.map(i => i.id).sort()).toEqual(['q-a', 'q-b']);
    await as('mixed').delete('/api/offline-queue/q-a');
    await as('mixed').delete('/api/offline-queue/q-b');
    expect(relay.readJson('offline_queue.json').map(e => e.id)).toEqual(['q-a']);
  });
});
