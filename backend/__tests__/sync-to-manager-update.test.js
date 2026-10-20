'use strict';
// Re-syncing an existing service to Manager updates its price in place (PUT,
// DefaultSalesUnitPrice), without adding a second item.
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');

let relay, mgr;
beforeAll(async () => { mgr = await createFakeManager().start(); relay = loadRelay(); });
afterAll(async () => { await mgr.stop(); relay.cleanup(); });

test('a service price change reaches Manager', async () => {
  mgr.lists['non-inventory-items'] = [{ key: 'svc-1', code: 'SAF-001', name: 'Safari Day Trip' }];
  mgr.forms['non-inventory-item-form'] = { 'svc-1': { Code: 'SAF-001', Name: 'Safari Day Trip', UnitName: 'PS', HasDefaultSalesUnitPrice: true, DefaultSalesUnitPrice: 350000 } };
  const r = await relay.post('/api/goods/sync-to-manager', { managerEndpoint: mgr.url, accessToken: 'tk',
    item: { code: 'SAF-001', name: 'Safari Day Trip', price: 380000, cur: 'UGX', uom: 'Per Person', type: 'Service', comCode: '90121501' } });
  expect(r.body.success).toBe(true);
  expect(mgr.forms['non-inventory-item-form']['svc-1'].DefaultSalesUnitPrice).toBe(380000);
  expect(mgr.posts('non-inventory-item-form')).toHaveLength(0);
});
