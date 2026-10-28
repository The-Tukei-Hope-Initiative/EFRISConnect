'use strict';
// Two businesses sharing a TIN: a credit note issued from one is updated there when
// the other checks URA (no second copy). A request to cancel an issued note is kept
// on that note. "Not found in Manager" is logged once per credit note.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { createFakeManager } = require('./helpers/fakeManager');
const { TIN, efrisConfig } = require('./helpers/fixtures');

const A = 'twin-a-2026', B = 'twin-b-2026';
let relay, ura, mgr, lines;
beforeAll(async () => {
  ura = await createFakeUra().start();
  mgr = await createFakeManager().start();
  relay = loadRelay({ uraUrl: ura.url });
  expect((await relay.addTenant(A, { tin: TIN })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: TIN })).body.success).toBe(true);
  relay.writeJson('submission_log.json', [
    { id: 'cn-a', kind: 'credit-note', status: 'success', tin: TIN, tenantId: A, mode: 'sandbox', reference: 'CN-TWIN-1',
      applicationId: 'APP-T1', approveStatus: '102', statusText: 'Pending approval', oriInvoiceNo: '326000000001' },
    { id: 'dn-b', kind: 'debit-note', status: 'success', tin: TIN, tenantId: B, mode: 'sandbox', reference: 'DN-1', fdn: '326000000777' },
  ]);
  ura.t111Records = [
    { id: 'APP-T1', referenceNo: 'CN-TWIN-1', oriInvoiceNo: '326000000001', invoiceNo: '326000000555', approveStatus: '101', invoiceApplyCategoryCode: '101' },
    { id: 'APP-X1', referenceNo: 'CX-1', oriInvoiceNo: '326000000777', invoiceNo: '', approveStatus: '103', applicationTime: '20/10/2026 10:00:00', invoiceApplyCategoryCode: '103' },
    { id: 'APP-N1', referenceNo: 'CN-NOMGR-1', oriInvoiceNo: '326000000002', invoiceNo: '326000000666', approveStatus: '101', invoiceApplyCategoryCode: '101' },
  ];
  ura.on.T108 = () => ({ content: {} });
  mgr.lists['credit-notes'] = [];
  lines = [];
  const orig = console.log;
  jest.spyOn(console, 'log').mockImplementation((...a) => { lines.push(a.join(' ')); });
  console.log.orig = orig;
});
afterAll(async () => { console.log.mockRestore(); await ura.stop(); await mgr.stop(); relay.cleanup(); });

const check = tid => relay.post('/api/efris/credit-notes/status',
  { config: efrisConfig(ura), managerEndpoint: mgr.url, accessToken: 'mgr-token' }, { 'X-Tenant-Id': tid });
const log = () => relay.readJson('submission_log.json');

test('the other business\'s credit note is updated in place, not copied', async () => {
  expect((await check(B)).body.success).toBe(true);
  const twins = log().filter(e => e.reference === 'CN-TWIN-1');
  expect(twins).toHaveLength(1);
  expect(twins[0]).toMatchObject({ tenantId: A, approveStatus: '101', statusText: 'Approved', fdn: '326000000555' });
});

test('a rejected cancellation request is kept on the note it is about', async () => {
  const dn = log().find(e => e.id === 'dn-b');
  expect(dn.cancelRequest).toMatchObject({ id: 'APP-X1', reference: 'CX-1', approveStatus: '103', statusText: 'Rejected' });
  expect(log().some(e => e.reference === 'CX-1')).toBe(false);
  expect(lines.filter(l => /Cancellation request CX-1 for DN-1 is now Rejected at URA/.test(l))).toHaveLength(1);
});

test('"no Manager credit note" is logged once across repeated checks', async () => {
  await check(B); await check(B);
  expect(lines.filter(l => /CN-NOMGR-1: no Manager credit note/.test(l))).toHaveLength(1);
  expect(lines.filter(l => /Cancellation request CX-1/.test(l))).toHaveLength(1);
  expect(log().find(e => e.reference === 'CN-NOMGR-1').mgrAttempts).toBe(3);
});
