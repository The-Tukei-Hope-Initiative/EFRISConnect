'use strict';
// A sale that has waited more than 24 hours for URA: the queue, the status pill
// and a new queued sale all say so, and the bell warns once a day per business.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, DEVICE, efrisConfig, invoice } = require('./helpers/fixtures');
const { match } = require('../notifications');

const TENANT = 'biz-overdue';
const HOUR = 3600000;
let relay, ura;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  const t = await relay.post('/api/tenant', { id: TENANT, tin: TIN, deviceNo: DEVICE, mode: 'sandbox', vatRegistered: true,
    efrisPassword: 'test-pw', efrisPrivateKeyPem: ura.privateKeyPem });
  expect(t.body.success).toBe(true);
  await ura.stop();
});
afterAll(() => relay.cleanup());

function entry(id, hoursAgo, status = 'pending') {
  const at = new Date(Date.now() - hoursAgo * HOUR).toISOString();
  return { id, createdAt: at, saleAt: at, status, attempts: 1, lastError: '', kind: 'invoice', reference: id, tenantId: TENANT,
    cfgPublic: { tin: TIN, deviceNo: DEVICE, mode: 'sandbox' }, invoice: invoice(id) };
}

test('under 24 hours: no warning', async () => {
  relay.writeJson('offline_queue.json', [entry('REC-NEW', 23)]);
  const r = await relay.get('/api/offline-queue').set('X-Tenant-Id', TENANT);
  expect(r.body).toMatchObject({ pending: 1, overdue: 0, warning: '' });
});

test('over 24 hours: the queue and the status pill count it, done sales are ignored', async () => {
  relay.writeJson('offline_queue.json', [entry('REC-OLD', 25), entry('REC-NEW', 1), entry('REC-SENT', 30, 'done')]);
  const q = await relay.get('/api/offline-queue').set('X-Tenant-Id', TENANT);
  expect(q.body).toMatchObject({ pending: 2, overdue: 1 });
  expect(q.body.warning).toMatch(/1 sale has waited more than 24 hours for URA.*Offline Enabler/);
  const c = await relay.get('/api/connectivity?mode=sandbox').set('X-Tenant-Id', TENANT);
  expect(c.body).toMatchObject({ pending: 2, overdue: 1 });
});

test('a new sale queued while another is overdue carries the warning', async () => {
  const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('REC-NEXT'), config: efrisConfig(ura) }, { 'X-Tenant-Id': TENANT });
  expect(r.body).toMatchObject({ success: true, queued: true, overdue: 1 });
  expect(r.body.warning).toMatch(/waited more than 24 hours/);
});

test('the bell: one warning per business per day', () => {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => { lines.push(a.join(' ')); };
  try {
    relay.app._test.warnOverdueQueue();
    relay.app._test.warnOverdueQueue();
  } finally { console.log = orig; }
  const warned = lines.filter(l => /waited more than 24 hours/.test(l));
  expect(warned).toHaveLength(1);
  const n = match({ text: warned[0] });
  expect(n).toMatchObject({ kind: 'queue-overdue', level: 'critical', perm: 'queue' });
  expect(n.body).toMatch(/1 sale has no FDN after 24 hours/);
});
