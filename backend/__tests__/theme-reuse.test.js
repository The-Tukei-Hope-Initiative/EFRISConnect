'use strict';
// Installing the receipt theme again reuses the EFRISConnect theme already in
// Manager (found by name) instead of adding another copy.
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');

let relay, mgr;
beforeAll(async () => { mgr = await createFakeManager().start(); relay = loadRelay(); });
afterAll(async () => { await mgr.stop(); relay.cleanup(); });

test('an existing EFRISConnect theme is updated, not duplicated', async () => {
  mgr.lists['custom-themes'] = [{ key: 'other-1', name: 'Plain' }, { key: 'efc-1', name: 'EFRISConnect' }];
  mgr.forms['custom-theme-form'] = { 'other-1': { Name: 'Plain' }, 'efc-1': { Name: 'EFRISConnect' } };
  const r = await relay.post('/api/manager/install-theme', { managerEndpoint: mgr.url, accessToken: 'tk' });
  expect(r.body).toMatchObject({ success: true, key: 'efc-1' });
  expect(mgr.posts('custom-theme-form')).toHaveLength(0);
  expect(mgr.requests.some(q => q.method === 'PUT' && q.path === '/api2/custom-theme-form/efc-1')).toBe(true);
});
