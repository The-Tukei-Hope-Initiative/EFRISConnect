'use strict';
// Offline queue: URA unreachable -> queued; URA back -> POST /api/offline-queue/retry-now
// sends it with the credentials saved in the vault. Plus the "uncertain" path:
// a queued sale that may already be at URA is looked up by reference (T106)
// instead of being sent a second time.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, DEVICE, efrisConfig, invoice } = require('./helpers/fixtures');

const TENANT = 'biz-test-1';
let relay, ura;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  // Credentials in the vault: the automatic retry reads them from there.
  const t = await relay.post('/api/tenant', { id: TENANT, tin: TIN, deviceNo: DEVICE, mode: 'sandbox', vatRegistered: true,
    efrisPassword: 'test-pw', efrisPrivateKeyPem: ura.privateKeyPem });
  expect(t.body).toMatchObject({ success: true, tenant: { id: TENANT, hasEfrisPassword: true, hasEfrisKey: true } });
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });

describe('offline queue', () => {
  let offlineId;

  test('URA unreachable: the sale is queued (pending, dated when it was made)', async () => {
    await ura.stop();
    const before = Date.now();
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('OFF-001'), config: efrisConfig(ura) }, { 'X-Tenant-Id': TENANT });
    expect(r.body).toMatchObject({ success: true, queued: true, offline: true, reference: 'OFF-001' });
    expect(r.body.uncertain).toBeUndefined();
    offlineId = r.body.offlineId;
    expect(offlineId).toMatch(/^off_/);

    const q = relay.readJson('offline_queue.json', []);
    expect(q).toHaveLength(1);
    expect(q[0]).toMatchObject({ id: offlineId, status: 'pending', kind: 'invoice', reference: 'OFF-001', tenantId: TENANT, attempts: 0 });
    expect(Date.parse(q[0].saleAt)).toBeGreaterThanOrEqual(before - 1000);
    expect(Date.parse(q[0].saleAt)).toBeLessThanOrEqual(Date.now());
    // Only the public config is kept: never the EFRIS password or the private key.
    expect(q[0].cfgPublic).toMatchObject({ tin: TIN, deviceNo: DEVICE, mode: 'sandbox', vatRegistered: true });
    expect(JSON.stringify(q[0])).not.toMatch(/test-pw|PRIVATE KEY/);
  });

  test('URA back: retry-now fiscalises the queued sale, dated at the original sale time', async () => {
    await ura.start(ura.port);
    ura.reset();
    ura.nextFdn = 'FDN-Q1';
    const saleAt = relay.readJson('offline_queue.json')[0].saleAt;
    const r = await relay.post('/api/offline-queue/retry-now');
    expect(r.body).toMatchObject({ success: true, sent: 1, offline: false, pending: 0 });

    const e = relay.readJson('offline_queue.json').find(x => x.id === offlineId);
    expect(e).toMatchObject({ status: 'done', fdn: 'FDN-Q1', attempts: 1, lastError: '' });
    expect(e.result).toMatchObject({ fdn: 'FDN-Q1', antifakeCode: 'AF1', invoiceId: 'ID1' });

    const t109 = ura.callsOf('T109');
    expect(t109).toHaveLength(1);
    const { eatParts } = relay.app._test;
    const p = eatParts(Date.parse(saleAt));
    expect(t109[0].body.basicInformation.issuedDate).toBe(p.date + ' ' + p.time);
    expect(relay.readJson('submission_log.json', []).find(x => x.reference === 'OFF-001')).toMatchObject({ fdn: 'FDN-Q1', tenantId: TENANT });
  });

  // Getting an entry marked "uncertain" through submit-invoice needs URA to accept
  // the request and then not answer: efrisCall's timeout is a fixed 30 s with no
  // env/config override, so that part is not exercised here.
  test.todo('submit-invoice marks a sale uncertain when URA accepts it but does not answer in time (needs the 30 s efrisCall timeout to be configurable)');

  test('an uncertain entry found at URA by reference (T106) is marked done without a second T109', async () => {
    const saleAt = new Date(Date.now() - 5 * 60000).toISOString();
    const q = relay.readJson('offline_queue.json', []);
    q.push({ id: 'off_uncertain_1', createdAt: saleAt, saleAt, status: 'pending', attempts: 0, lastError: '', kind: 'invoice',
      invoice: invoice('UNC-001'), cfgPublic: { tin: TIN, deviceNo: DEVICE, mode: 'sandbox', vatRegistered: true },
      tenantId: TENANT, managerEndpoint: '', documentKey: '', reference: 'UNC-001', uncertain: true, uncertainVia: 'ura' });
    relay.writeJson('offline_queue.json', q);
    ura.reset();
    ura.t106Records = [{ referenceNo: 'UNC-001', invoiceNo: 'FDN-U1', antifakeCode: 'AFU1', id: 'IDU1', grossAmount: '2360', invoiceKind: '1', buyerLegalName: 'Walk-in Customer' }];

    const r = await relay.post('/api/offline-queue/retry-now');
    expect(r.body).toMatchObject({ success: true, sent: 1, pending: 0 });
    expect(ura.callsOf('T106')).toHaveLength(1);
    expect(ura.callsOf('T106')[0].body).toMatchObject({ referenceNo: 'UNC-001', sellerTinOrNin: TIN });
    expect(ura.callsOf('T109')).toHaveLength(0);

    const e = relay.readJson('offline_queue.json').find(x => x.id === 'off_uncertain_1');
    expect(e).toMatchObject({ status: 'done', fdn: 'FDN-U1', uncertain: false });
    expect(relay.readJson('submission_log.json').find(x => x.reference === 'UNC-001')).toMatchObject({ fdn: 'FDN-U1', invoiceId: 'IDU1', status: 'success', totalAmount: 2360 });
  });

  test('an uncertain entry NOT found at URA is sent normally', async () => {
    const saleAt = new Date().toISOString();
    const q = relay.readJson('offline_queue.json', []);
    q.push({ id: 'off_uncertain_2', createdAt: saleAt, saleAt, status: 'pending', attempts: 0, lastError: '', kind: 'invoice',
      invoice: invoice('UNC-002'), cfgPublic: { tin: TIN, deviceNo: DEVICE, mode: 'sandbox', vatRegistered: true },
      tenantId: TENANT, reference: 'UNC-002', uncertain: true, uncertainVia: 'ura' });
    relay.writeJson('offline_queue.json', q);
    ura.reset();
    ura.t106Records = [];
    ura.nextFdn = 'FDN-U2';
    const r = await relay.post('/api/offline-queue/retry-now');
    expect(r.body).toMatchObject({ success: true, sent: 1 });
    expect(ura.codes().filter(c => c === 'T106' || c === 'T109')).toEqual(['T106', 'T109']);
    expect(relay.readJson('offline_queue.json').find(x => x.id === 'off_uncertain_2')).toMatchObject({ status: 'done', fdn: 'FDN-U2' });
  });
});
