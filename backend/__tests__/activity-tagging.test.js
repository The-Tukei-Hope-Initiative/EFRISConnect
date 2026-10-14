'use strict';
// Work that spans businesses is logged under each business: "Try now" pressed in
// business A sends B's queued sale too, and B's lines must be tagged B, not A.
// The live activity view hides other businesses' TINs from a non-owner admin.
const path = require('path');
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { invoice } = require('./helpers/fixtures');

const A = 'tag-a', B = 'tag-b', TIN_A = '1000000101', TIN_B = '1000000202';
let relay, ura, act, tok;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  act = relay.app._activity;
  relay.app._consoleUi.install(path.join(relay.dataDir, 'logs'));
  await relay.setupOwner();
  for (const [id, tin] of [[A, TIN_A], [B, TIN_B]]) {
    const r = await relay.post('/api/tenant', { id, tin, deviceNo: tin + '_01', mode: 'sandbox', vatRegistered: true, efrisPassword: 'pw-' + id, efrisPrivateKeyPem: ura.privateKeyPem });
    expect(r.body.success).toBe(true);
  }
  tok = { owner: await relay.login('owner', 'owner-pass-123'), adminA: await relay.addUser('admin-a', { [A]: 'admin' }) };
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });

const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});
const queued = (id, tenant, tin, ref) => ({
  id, kind: 'invoice', tenantId: tenant, status: 'pending', attempts: 0, reference: ref, invoice: invoice(ref),
  cfgPublic: { tin, deviceNo: tin + '_01', mode: 'sandbox', vatRegistered: true, businessName: 'Biz ' + tenant },
  createdAt: new Date().toISOString(), saleAt: new Date().toISOString(),
});

describe('activity tagging across businesses', () => {
  test('retry-now pressed in A tags each queued sale\'s lines with its own business', async () => {
    relay.writeJson('offline_queue.json', [queued('off_a', A, TIN_A, 'QA-REF-1'), queued('off_b', B, TIN_B, 'QB-REF-1')]);
    const r = await as('adminA', A).post('/api/offline-queue/retry-now', {});
    expect(r.body.success).toBe(true);
    expect(relay.readJson('offline_queue.json').map(e => e.status)).toEqual(['done', 'done']);
    const lines = act.entries({});
    const bLines = lines.filter(e => /QB-REF-1/.test(e.text));
    const aLines = lines.filter(e => /QA-REF-1/.test(e.text));
    expect(bLines.length).toBeGreaterThan(0);
    expect(aLines.length).toBeGreaterThan(0);
    expect(new Set(bLines.map(e => e.tenantId))).toEqual(new Set([B]));
    expect(new Set(aLines.map(e => e.tenantId))).toEqual(new Set([A]));
    // The admin of A sees none of B's lines.
    const view = await as('adminA', A).get('/api/admin/activity?tenant=all&debug=1');
    expect(view.body.entries.map(e => e.text).join('\n')).not.toMatch(/QB-REF-1/);
  });

  test('the live activity view masks other businesses\' TINs for a non-owner admin', async () => {
    await as('adminA', A).post('/api/client-log', { message: 'customer moved from TIN ' + TIN_B + ' to ' + TIN_A });
    const mine = await as('adminA', A).get('/api/admin/activity?tenant=' + A);
    const t = mine.body.entries.map(e => e.text).join('\n');
    expect(t).toMatch(/customer moved/);
    expect(t).not.toContain(TIN_B);
    expect(t).toContain(TIN_A);
    const own = await as('owner').get('/api/admin/activity?tenant=' + A);
    expect(own.body.entries.map(e => e.text).join('\n')).toContain(TIN_B);
  });
});
