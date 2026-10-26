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

test('Manager with no theme list: the relay remembers the key, so a new browser updates the same theme', async () => {
  // Manager Server's API has no theme list and no Form Defaults endpoint; a new
  // browser or app window has no saved theme key of its own.
  delete mgr.lists['custom-themes'];
  mgr.forms['custom-theme-form'] = {};
  mgr.reset();
  const first = await relay.post('/api/manager/install-theme', { managerEndpoint: mgr.url, accessToken: 'tk-2' });
  expect(first.body.success).toBe(true);
  const key = first.body.key;
  expect(mgr.posts('custom-theme-form')).toHaveLength(1);
  mgr.reset();
  const again = await relay.post('/api/manager/install-theme', { managerEndpoint: mgr.url, accessToken: 'tk-2', setDefault: true });
  expect(again.body).toMatchObject({ success: true, key, updated: true });
  expect(mgr.posts('custom-theme-form')).toHaveLength(0);
  // The readiness check finds it too, with no key from the browser.
  const audit = await relay.post('/api/manager/readiness-audit', { managerEndpoint: mgr.url, accessToken: 'tk-2' });
  expect(audit.body.checks.find(c => c.id === 'theme').status).toBe('ok');
});
