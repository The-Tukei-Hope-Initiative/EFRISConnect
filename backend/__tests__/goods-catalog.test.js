'use strict';
// Goods > My Items on the relay: one list per business, read by every role of that
// business, changed only by its admins, and never visible to another business.
const { loadRelay } = require('./helpers/relay');

const A = 'cat-a', B = 'cat-b';
let relay, tok;
beforeAll(async () => {
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A)).body.success).toBe(true);
  expect((await relay.addTenant(B)).body.success).toBe(true);
  tok = {
    adminA: await relay.addUser('cat-admin-a', { [A]: 'admin' }),
    acctA: await relay.addUser('cat-acct-a', { [A]: 'accountant' }),
    cashB: await relay.addUser('cat-cash-b', { [B]: 'cashier' }),
  };
});
afterAll(() => relay.cleanup());

const asA = t => relay.as(t, { 'X-Tenant-Id': A });
const water = { code: 'T10-WAT500', name: 'Mineral Water 500ml', efrisUom: 'BS', price: 1000 };

describe('goods catalog', () => {
  test('empty to begin with', async () => {
    const r = await asA(tok.acctA).get('/api/goods-catalog');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ success: true, items: [], updatedAt: '' });
  });

  test('admin saves; another role of the same business reads the same list', async () => {
    const w = await asA(tok.adminA).put('/api/goods-catalog', { items: [water], force: true });
    expect(w.body.success).toBe(true);
    const r = await asA(tok.acctA).get('/api/goods-catalog');
    expect(r.body.items).toEqual([water]);
    expect(r.body.updatedAt).toBe(w.body.updatedAt);
  });

  test('a non-admin cannot change it', async () => {
    const r = await asA(tok.acctA).put('/api/goods-catalog', { items: [] });
    expect(r.status).toBe(403);
    expect((await asA(tok.acctA).get('/api/goods-catalog')).body.items).toHaveLength(1);
  });

  test('another business sees neither the list nor the business', async () => {
    const own = await relay.as(tok.cashB, { 'X-Tenant-Id': B }).get('/api/goods-catalog');
    expect(own.body.items).toEqual([]);
    const other = await relay.as(tok.cashB, { 'X-Tenant-Id': A }).get('/api/goods-catalog');
    expect(other.status).toBe(403);
  });

  test('a save based on an older copy gets the newer list back (409)', async () => {
    const cur = (await asA(tok.adminA).get('/api/goods-catalog')).body.updatedAt;
    const r = await asA(tok.adminA).put('/api/goods-catalog', { items: [], baseUpdatedAt: '2000-01-01T00:00:00.000Z' });
    expect(r.status).toBe(409);
    expect(r.body.items).toEqual([water]);
    expect(r.body.updatedAt).toBe(cur);
    const ok = await asA(tok.adminA).put('/api/goods-catalog', { items: [water, { code: 'X', name: 'Other' }], baseUpdatedAt: cur });
    expect(ok.body.success).toBe(true);
  });

  test('bad input is refused', async () => {
    expect((await asA(tok.adminA).put('/api/goods-catalog', { items: 'nope' })).status).toBe(400);
    expect((await asA(tok.adminA).put('/api/goods-catalog', { items: [1, 2], force: true })).status).toBe(400);
  });
});
