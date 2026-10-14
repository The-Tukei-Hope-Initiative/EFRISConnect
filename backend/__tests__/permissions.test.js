'use strict';
// Roles, route permissions, deny-by-default and business isolation.
const request = require('supertest');
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');

const A = 'biz-a', B = 'biz-b';
let relay, mgr, tok;
beforeAll(async () => {
  mgr = await createFakeManager().start();
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000001', managerEndpoint: mgr.url, managerToken: '' })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: '1000000002' })).body.success).toBe(true);
  tok = {
    cashierA: await relay.addUser('cash-a', { [A]: 'cashier' }),
    accountantA: await relay.addUser('acct-a', { [A]: 'accountant' }),
    adminA: await relay.addUser('admin-a', { [A]: 'admin' }),
    cashierB: await relay.addUser('cash-b', { [B]: 'cashier' }),
    accountantB: await relay.addUser('acct-b', { [B]: 'accountant' }),
  };
});
afterAll(async () => { await mgr.stop(); relay.cleanup(); });

const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});
const denied = r => r.status === 403;
const allowed = r => r.status !== 401 && r.status !== 403;

describe('permission matrix', () => {
  test('cashier is refused credit-note status, reconcile, tenant save and goods registration', async () => {
    const c = as('cashierA', A);
    expect(denied(await c.post('/api/efris/credit-notes/status', {}))).toBe(true);
    expect(denied(await c.post('/api/reconcile/documents', {}))).toBe(true);
    expect(denied(await c.post('/api/reconcile/stock', {}))).toBe(true);
    expect(denied(await c.post('/api/efris/stock-in', {}))).toBe(true);
    expect(denied(await c.post('/api/tenant', { id: A, businessName: 'hijack' }))).toBe(true);
    expect(denied(await c.post('/api/efris/register-goods', {}))).toBe(true);
    expect(denied(await c.get('/api/admin/logs'))).toBe(true);
    const r = await c.post('/api/efris/credit-note', {});
    expect(r.body).toMatchObject({ success: false, error: 'Your role cannot do this', permission: 'credit' });
  });

  test('cashier can fiscalise (reaches the route) and look things up', async () => {
    const c = as('cashierA', A);
    const r = await c.post('/api/efris/submit-invoice', {});
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/Missing invoice/);
    expect(allowed(await c.get('/api/units'))).toBe(true);
    expect(allowed(await c.get('/api/offline-queue'))).toBe(true);
    expect(allowed(await c.get('/api/number-series'))).toBe(true);
  });

  test('accountant can reconcile and move stock, but not register goods or manage tenants', async () => {
    const a = as('accountantA', A);
    expect(allowed(await a.post('/api/reconcile/stock', {}))).toBe(true);
    expect(allowed(await a.post('/api/reconcile/documents', {}))).toBe(true);
    expect(allowed(await a.post('/api/efris/stock-in', {}))).toBe(true);
    expect(allowed(await a.post('/api/efris/credit-notes/status', {}))).toBe(true);
    expect(denied(await a.post('/api/efris/register-goods', {}))).toBe(true);
    expect(denied(await a.post('/api/manager/ensure-efris-fields', {}))).toBe(true);
    expect(denied(await a.post('/api/tenant', { id: A }))).toBe(true);
  });

  test('an admin of A is admin only in A', async () => {
    expect(allowed(await as('adminA', A).post('/api/efris/register-goods', {}))).toBe(true);
    expect(denied(await as('adminA', B).post('/api/efris/register-goods', {}))).toBe(true);
  });
});

describe('business isolation', () => {
  test('a business the user has no role in is refused', async () => {
    const r = await as('cashierA', B).get('/api/submission-log');
    expect(r.status).toBe(403);
    expect(r.body.error).toBe('You do not have access to this business');
    expect((await as('cashierA', 'no-such-biz').get('/api/units')).status).toBe(403);
  });

  test("'__vault__' is filled only from the checked business, never another's", async () => {
    relay.app._vault.putTenant(B, { managerToken: 'token-of-B' });
    mgr.reset();
    // Tenant B: refused before anything is filled or sent.
    const b = await as('cashierA', B).post('/api/manager/customers', { managerEndpoint: mgr.url, accessToken: '__vault__' });
    expect(b.status).toBe(403);
    expect(mgr.requests.length).toBe(0);
    // No business named: the placeholder is not filled at all.
    const none = await as('cashierA').post('/api/manager/customers', { managerEndpoint: mgr.url, accessToken: '__vault__' });
    expect(none.status).toBe(400);
    expect(mgr.requests.length).toBe(0);
  });

  test('the token in the vault reaches Manager only for its own business', async () => {
    // Stored straight in the vault (POST /api/tenant would check the token against Manager).
    const vaultMod = relay.app._vault;
    vaultMod.putTenant(A, { managerToken: 'token-of-A' });
    vaultMod.putTenant(B, { managerToken: 'token-of-B' });
    mgr.reset();
    const r = await as('cashierA', A).post('/api/manager/customers', { managerEndpoint: mgr.url, accessToken: '__vault__', refresh: true });
    expect(allowed(r)).toBe(true);
    const keys = mgr.requests.map(x => x.headers['x-api-key']);
    expect(keys.length).toBeGreaterThan(0);
    expect(new Set(keys)).toEqual(new Set(['token-of-A']));
  });

  test('GET /api/tenant lists only the businesses the user holds a role in', async () => {
    const r = await as('cashierA').get('/api/tenant');
    expect(r.body.tenants.map(t => t.id)).toEqual([A]);
    expect(r.body.tenants[0].role).toBe('cashier');
    const st = await as('cashierA').get('/api/auth/status');
    expect(st.body.tenants.map(t => t.id)).toEqual([A]);
    expect(st.body.permissions[A]).toEqual(expect.arrayContaining(['sell', 'log-own']));
    expect(st.body.permissions[A]).not.toContain('credit');
    const own = await relay.as(await relay.login('owner', 'owner-pass-123')).get('/api/auth/status');
    expect(own.body.tenants.map(t => t.id).sort()).toEqual([A, B]);
    expect(own.body.permissions[B]).toContain('*');
  });

  test('tenant save and delete need admin of that business; a new business makes its creator admin', async () => {
    expect(denied(await as('adminA').post('/api/tenant', { id: B, businessName: 'take over' }))).toBe(true);
    expect(denied(await as('adminA').delete('/api/tenant/' + B))).toBe(true);
    expect(denied(await as('cashierA').post('/api/tenant', { id: 'biz-new-1' }))).toBe(true);
    const c = await as('adminA').post('/api/tenant', { id: 'biz-new-2', businessName: 'New Shop' });
    expect(c.body.success).toBe(true);
    const st = await as('adminA').get('/api/auth/status');
    expect(st.body.tenants.find(t => t.id === 'biz-new-2')).toMatchObject({ role: 'admin', businessName: 'New Shop' });
    expect((await as('adminA').delete('/api/tenant/biz-new-2')).body.success).toBe(true);
    const after = await as('adminA').get('/api/auth/status');
    expect(after.body.tenants.find(t => t.id === 'biz-new-2')).toBeUndefined();
  });

  test('the submission log: a cashier sees only their own entries in their business', async () => {
    const users = (await relay.get('/api/auth/users')).body.users;
    const id = n => users.find(u => u.name === n).id;
    relay.writeJson('submission_log.json', [
      { id: 1, fdn: 'F1', tenantId: A, userId: id('cash-a'), status: 'success', submittedAt: '2026-10-09T08:00:00Z' },
      { id: 2, fdn: 'F2', tenantId: A, userId: id('acct-a'), status: 'success', submittedAt: '2026-10-09T08:00:00Z' },
      { id: 3, fdn: 'F3', tenantId: B, userId: id('cash-b'), status: 'success', submittedAt: '2026-10-09T08:00:00Z' },
    ]);
    const fdns = r => r.body.items.map(e => e.fdn).sort();
    expect(fdns(await as('cashierA', A).get('/api/submission-log'))).toEqual(['F1']);
    expect(fdns(await as('cashierA').get('/api/submission-log'))).toEqual(['F1']);
    expect(fdns(await as('accountantA', A).get('/api/submission-log'))).toEqual(['F1', 'F2']);
    expect(fdns(await as('accountantA').get('/api/submission-log'))).toEqual(['F1', 'F2']);
    expect(fdns(await relay.get('/api/submission-log'))).toEqual(['F1', 'F2', 'F3']);
    expect((await as('cashierA', A).get('/api/submission-log/by-fdn/F2')).body.success).toBe(false);
    expect((await as('accountantA', A).get('/api/submission-log/by-fdn/F2')).body.success).toBe(true);
    // Delete is accountant-only and cannot reach another business.
    expect(denied(await as('cashierA', A).delete('/api/submission-log/1'))).toBe(true);
    await as('accountantA', A).delete('/api/submission-log/3');
    expect(relay.readJson('submission_log.json').some(e => e.fdn === 'F3')).toBe(true);
  });

  test('Documents: credit notes are hidden from cashiers, searchable by reference/FDN for accountants', async () => {
    const users = (await relay.get('/api/auth/users')).body.users;
    const cash = users.find(u => u.name === 'cash-a').id;
    relay.writeJson('submission_log.json', [
      { id: 1, fdn: 'F1', tenantId: A, userId: cash, status: 'success', reference: 'R-1' },
      { id: 2, fdn: 'CNF1', kind: 'credit-note', tenantId: A, userId: cash, status: 'success', reference: 'CN-R-1', originalFdn: 'F1', approveStatus: '101' },
      { id: 3, fdn: '', kind: 'credit-note', tenantId: A, userName: 'URA check', adopted: true, status: 'success', reference: 'CN-R-2', originalFdn: 'F9', approveStatus: '102' },
    ]);
    const ids = r => r.body.items.map(e => e.id).sort();
    expect(ids(await as('cashierA', A).get('/api/submission-log'))).toEqual([1]);
    expect(ids(await as('cashierA', A).get('/api/submission-log?q=CN-R'))).toEqual([]);
    expect(ids(await as('accountantA', A).get('/api/submission-log'))).toEqual([1, 2, 3]);
    expect(ids(await as('accountantA', A).get('/api/submission-log?q=cn-r-2'))).toEqual([3]);
    expect(ids(await as('accountantA', A).get('/api/submission-log?q=CNF1'))).toEqual([2]);
    expect(ids(await as('accountantA', A).get('/api/submission-log?q=F9'))).toEqual([3]);   // original invoice FDN
  });

  test('new log entries record the signed-in user', async () => {
    relay.writeJson('submission_log.json', []);
    await as('cashierA', A).post('/api/manager-only-log', { reference: 'MO-1', totalAmount: 5 });
    const e = relay.readJson('submission_log.json')[0];
    expect(e).toMatchObject({ reference: 'MO-1', tenantId: A, userName: 'cash-a' });
    expect(e.userId).toBeTruthy();
  });

  test('number series belong to their business', async () => {
    const mk = await as('accountantA', A).post('/api/number-series', { name: 'A receipts', prefix: 'RA', segments: ['prefix', 'counter'] });
    expect(mk.body.success).toBe(true);
    const sid = mk.body.series.id;
    expect(relay.readJson('number_series.json').find(s => s.id === sid).tenantId).toBe(A);
    expect((await as('cashierA', A).get('/api/number-series')).body.map(s => s.id)).toContain(sid);
    expect((await as('accountantB', B).get('/api/number-series')).body.map(s => s.id)).not.toContain(sid);
    expect((await as('accountantB', B).post('/api/number-series/' + sid + '/next')).status).toBe(404);
    expect((await as('cashierA', A).post('/api/number-series/' + sid + '/next')).body.number).toBe('RA-0001');
    expect(denied(await as('cashierA', A).put('/api/number-series/' + sid, { prefix: 'X' }))).toBe(true);
  });

  test('receipt snapshots belong to their business', async () => {
    expect((await as('cashierA', A).post('/api/receipt-snapshot', { key: 'FDN-SNAP-1', query: 'tin=1000000001&x=1' })).body.success).toBe(true);
    expect((await as('cashierA', A).get('/api/receipt-snapshot?key=FDN-SNAP-1')).body.success).toBe(true);
    expect((await as('cashierB', B).get('/api/receipt-snapshot?key=FDN-SNAP-1')).body.success).toBe(false);
    expect((await as('cashierB', B).post('/api/receipt-snapshot', { key: 'FDN-SNAP-1', query: 'overwrite' })).status).toBe(403);
  });

  test('the offline queue shows only the business\'s own entries', async () => {
    relay.writeJson('offline_queue.json', [
      { id: 'off_a', tenantId: A, status: 'pending', reference: 'QA', cfgPublic: { tin: '1000000001' } },
      { id: 'off_b', tenantId: B, status: 'pending', reference: 'QB', cfgPublic: { tin: '1000000002' } },
    ]);
    const r = await as('cashierA', A).get('/api/offline-queue');
    expect(r.body.items.map(i => i.id)).toEqual(['off_a']);
    await as('accountantA', A).delete('/api/offline-queue/off_b');
    expect(relay.readJson('offline_queue.json').map(e => e.id).sort()).toEqual(['off_a', 'off_b']);
  });
});

describe('user administration', () => {
  test('an admin sees and manages only users of the businesses they administer', async () => {
    const list = (await as('adminA').get('/api/auth/users')).body.users;
    const names = list.map(u => u.name).sort();
    expect(names).toEqual(['acct-a', 'admin-a', 'cash-a']);
    expect(denied(await as('cashierA').get('/api/auth/users'))).toBe(true);
    // Cannot hand out a role in another business, or owner rights.
    expect(denied(await as('adminA').post('/api/auth/users', { name: 'sneaky', password: 'sneaky-pass-1', roles: { [B]: 'admin' } }))).toBe(true);
    expect(denied(await as('adminA').post('/api/auth/users', { name: 'sneaky2', password: 'sneaky-pass-1', roles: { [A]: 'cashier' }, owner: true }))).toBe(true);
    const add = await as('adminA').post('/api/auth/users', { name: 'cash-a2', password: 'cash-pass-a2', roles: { [A]: 'cashier' } });
    expect(add.body.success).toBe(true);
    // Promote within A; a role in B cannot be added.
    const id = add.body.user.id;
    expect((await as('adminA').post('/api/auth/users/' + id, { roles: { [A]: 'accountant' } })).body.user.roles).toEqual({ [A]: 'accountant' });
    expect(denied(await as('adminA').post('/api/auth/users/' + id, { roles: { [A]: 'cashier', [B]: 'admin' } }))).toBe(true);
    // Users of B are invisible to A's admin.
    const bId = (await relay.get('/api/auth/users')).body.users.find(u => u.name === 'cash-b').id;
    expect((await as('adminA').post('/api/auth/users/' + bId, { disabled: true })).status).toBe(404);
  });

  test('the last owner cannot be disabled or demoted', async () => {
    const ownerId = (await relay.get('/api/auth/users')).body.users.find(u => u.owner).id;
    const r = await relay.post('/api/auth/users/' + ownerId, { owner: false });
    expect(r.status).toBe(409);
  });
});

describe('deny by default', () => {
  const routes = () => {
    const out = [];
    for (const layer of relay.app._router.stack) {
      if (!layer.route || typeof layer.route.path !== 'string' || !layer.route.path.startsWith('/api/')) continue;
      for (const m of Object.keys(layer.route.methods)) out.push({ method: m.toUpperCase(), path: layer.route.path });
    }
    return out;
  };

  test('every line of the permission table names a real route', () => {
    const real = routes();
    const missing = relay.app._routePerms.filter(p => !real.some(r => r.method === p.method && r.path === '/api' + p.path));
    expect(missing).toEqual([]);
  });

  test('every route not granted to a role answers 403 for that role (unlisted routes: admin only)', async () => {
    const { routePerm } = relay.app._test;
    const perms = relay.app._auth.ROLE_PERMS;
    const failures = [];
    let adminOnly = 0;
    for (const r of routes()) {
      const sub = r.path.slice(4);
      const perm = routePerm(r.method, sub);
      if (perm === 'public' || perm === '') continue;
      if (perm === '*') adminOnly++;
      const url = r.path.replace(/:[A-Za-z]+/g, 'x1');
      for (const role of ['cashier', 'accountant']) {
        if (perms[role].includes(perm)) continue;
        const who = role === 'cashier' ? 'cashierA' : 'accountantA';
        const c = as(who, A);
        const res = await (r.method === 'GET' ? c.get(url) : r.method === 'DELETE' ? c.delete(url) : r.method === 'PUT' ? c.put(url, {}) : c.post(url, {}));
        if (res.status !== 403) failures.push(role + ' ' + r.method + ' ' + r.path + ' -> ' + res.status);
      }
    }
    expect(failures).toEqual([]);
    expect(adminOnly).toBeGreaterThan(20);
  });

  test('a route added later without a table entry is admin only', () => {
    expect(relay.app._test.routePerm('POST', '/some/new/route')).toBe('*');
  });

  test('every /api route needs sign-in except the public ones', async () => {
    const failures = [];
    for (const r of routes()) {
      const perm = relay.app._test.routePerm(r.method, r.path.slice(4));
      if (perm === 'public') continue;
      const url = r.path.replace(/:[A-Za-z]+/g, 'x1');
      const q = request(relay.app)[r.method.toLowerCase()](url);
      const res = await (r.method === 'GET' || r.method === 'DELETE' ? q : q.send({}));
      if (res.status !== 401) failures.push(r.method + ' ' + r.path + ' -> ' + res.status);
    }
    expect(failures).toEqual([]);
  });
});
