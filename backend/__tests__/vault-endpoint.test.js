'use strict';
// A Manager token kept in the vault only ever goes to the Manager endpoint saved
// with its business: an endpoint named by the caller (body, nested config,
// X-Manager-Endpoint, ?ep) is replaced, a business without a saved endpoint is
// refused, and a Manager redirect to another origin is not followed.
const http = require('http');
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');

const A = 'vault-a', C = 'vault-c';
let relay, mgr, evil, tok;
beforeAll(async () => {
  mgr = await createFakeManager().start();
  evil = await createFakeManager().start();
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000001' })).body.success).toBe(true);
  expect((await relay.addTenant(C, { tin: '1000000003' })).body.success).toBe(true);
  // Stored straight in the vault (POST /api/tenant would check the token against Manager).
  relay.app._vault.putTenant(A, { managerEndpoint: mgr.url, managerToken: 'token-of-A', efrisPassword: 'efris-pw-A' });
  relay.app._vault.putTenant(C, { managerToken: 'token-of-C' });   // no endpoint saved
  tok = {
    cashierA: await relay.addUser('cash-a', { [A]: 'cashier' }),
    cashierC: await relay.addUser('cash-c', { [C]: 'cashier' }),
  };
});
afterAll(async () => { await mgr.stop(); await evil.stop(); relay.cleanup(); });

const as = (who, tenant, extra) => relay.as(tok[who], Object.assign(tenant ? { 'X-Tenant-Id': tenant } : {}, extra || {}));
const keysSent = f => f.requests.map(r => r.headers['x-api-key']);

describe('vault token goes only to the business\'s own Manager', () => {
  beforeEach(() => { mgr.reset(); evil.reset(); });

  test('a caller-supplied managerEndpoint in the body is ignored', async () => {
    const r = await as('cashierA', A).post('/api/manager/customers', { managerEndpoint: evil.url, accessToken: '__vault__', refresh: true });
    expect(r.body.success).toBe(true);
    expect(evil.requests).toHaveLength(0);
    expect(new Set(keysSent(mgr))).toEqual(new Set(['token-of-A']));
  });

  test('X-Manager-Endpoint and ?ep are ignored when the token header comes from the vault', async () => {
    await as('cashierA', A, { 'X-Manager-Endpoint': evil.url, 'X-Manager-Token': '__vault__' }).get('/api/manager/invoice?key=k1');
    await as('cashierA', A, { 'X-Manager-Token': '__vault__' }).get('/api/manager/invoice?key=k2&ep=' + encodeURIComponent(evil.url));
    expect(evil.requests).toHaveLength(0);
    expect(mgr.requests.length).toBeGreaterThan(0);
    expect(new Set(keysSent(mgr))).toEqual(new Set(['token-of-A']));
  });

  test('a business with no saved Manager endpoint is refused (400), nothing is sent', async () => {
    const r = await as('cashierC', C).post('/api/manager/customers', { managerEndpoint: evil.url, accessToken: '__vault__' });
    expect(r.status).toBe(400);
    expect(evil.requests).toHaveLength(0);
    const h = await as('cashierC', C, { 'X-Manager-Endpoint': evil.url, 'X-Manager-Token': '__vault__' }).get('/api/manager/invoice?key=k1');
    expect(h.status).toBe(400);
    expect(evil.requests).toHaveLength(0);
  });

  test('a token typed by the caller (no vault) still goes where the caller says', async () => {
    const r = await as('cashierA', A).post('/api/manager/customers', { managerEndpoint: evil.url, accessToken: 'typed-token', refresh: true });
    expect(r.body.success).toBe(true);
    expect(new Set(keysSent(evil))).toEqual(new Set(['typed-token']));
    expect(mgr.requests).toHaveLength(0);
  });

  test('the automatic queue write-back uses the saved endpoint, not the one linked on the entry', async () => {
    relay.writeJson('offline_queue.json', [
      { id: 'off_1', tenantId: A, status: 'done', fdn: '3260000001', doneAt: new Date().toISOString(), result: { fdn: '3260000001' },
        documentKey: 'doc-1', managerEndpoint: evil.url, reference: 'Q1', cfgPublic: { tin: '1000000001' } },
    ]);
    const r = await as('cashierA', A).post('/api/offline-queue/retry-now', {});
    expect(r.body.success).toBe(true);
    expect(evil.requests).toHaveLength(0);
    expect(mgr.requests.length).toBeGreaterThan(0);
    expect(new Set(keysSent(mgr))).toEqual(new Set(['token-of-A']));
  });
});

describe('Manager redirects', () => {
  let redirector, hops;
  beforeAll(async () => {
    hops = [];
    redirector = http.createServer((req, res) => {
      hops.push({ path: req.url, key: req.headers['x-api-key'] });
      if (req.url.startsWith('/api2/customers')) { res.writeHead(302, { Location: evil.url + '/api2/customers' }); return res.end(); }
      if (req.url.startsWith('/api2/same')) { res.writeHead(302, { Location: '/api2/text-custom-fields' }); return res.end(); }
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ textCustomFields: [] }));
    });
    await new Promise(r => redirector.listen(0, '127.0.0.1', r));
  });
  afterAll(() => new Promise(r => redirector.close(r)));
  beforeEach(() => { evil.reset(); hops.length = 0; });

  test('a redirect to another origin is not followed and the key is not forwarded', async () => {
    const url = 'http://127.0.0.1:' + redirector.address().port;
    const r = await relay.post('/api/manager/customers', { managerEndpoint: url, accessToken: 'secret-key-1', refresh: true });
    expect(r.body.success).toBe(false);
    expect(r.body.error).toMatch(/not followed/);
    expect(evil.requests).toHaveLength(0);
  });

  test('a same-origin redirect is followed', async () => {
    const url = 'http://127.0.0.1:' + redirector.address().port;
    const r = await relay.post('/api/manager/debug-get', { managerEndpoint: url, accessToken: 'secret-key-2', path: '/same' });
    expect(hops.map(h => h.path)).toEqual(['/api2/same', '/api2/text-custom-fields']);
    expect(r.status).toBe(200);
  });
});
