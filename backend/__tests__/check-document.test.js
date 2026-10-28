'use strict';
// Status tab > Check a document: history, URA (T108 + T111) and Manager in one answer.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { createFakeManager } = require('./helpers/fakeManager');
const { TIN, efrisConfig } = require('./helpers/fixtures');

const T = 'chk-doc-2026', FDN = '326044300001';
let relay, ura, mgr;
beforeAll(async () => {
  ura = await createFakeUra().start();
  mgr = await createFakeManager().start();
  relay = loadRelay({ uraUrl: ura.url });
  expect((await relay.addTenant(T, { tin: TIN })).body.success).toBe(true);
  relay.writeJson('submission_log.json', [
    { id: 's1', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'REC-261027-001', fdn: FDN, totalAmount: 5000, currency: 'UGX', customerName: 'Walk-in Customer' },
    { id: 'c1', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'CN-1', oriInvoiceNo: FDN, approveStatus: '101', statusText: 'Approved', fdn: '326044300002', totalAmount: -1000 },
  ]);
  ura.on.T108 = call => (call.body.invoiceNo === FDN
    ? { content: { basicInformation: { invoiceNo: FDN, antifakeCode: 'AF12345', issuedDate: '27/10/2026 10:00:00', currency: 'UGX' }, summary: { grossAmount: '5000' }, buyerDetails: { buyerLegalName: 'Walk-in' } } }
    : { rc: '2124', msg: 'Invoice does not exist' });
  ura.t111Records = [
    { id: 'A1', referenceNo: 'CN-1', oriInvoiceNo: FDN, invoiceNo: '326044300002', approveStatus: '101', invoiceApplyCategoryCode: '101' },
    { id: 'A2', referenceNo: 'CN-2', oriInvoiceNo: FDN, invoiceNo: '', approveStatus: '103', grossAmount: '-500', invoiceApplyCategoryCode: '101' },
    { id: 'A3', referenceNo: 'CX-9', oriInvoiceNo: FDN, invoiceNo: '', approveStatus: '103', invoiceApplyCategoryCode: '103' },
  ];
  mgr.lists['text-custom-fields'] = [{ key: 'cf-fdn', name: 'FDN' }, { key: 'cf-ver', name: 'Verification Code' }];
  mgr.lists['receipts'] = [{ key: 'r-1', reference: 'REC-261027-001' }];
  mgr.forms['receipt-form'] = { 'r-1': { Reference: 'REC-261027-001', CustomFields2: { Strings: { 'cf-fdn': FDN, 'cf-ver': 'AF12345' } } } };
});
afterAll(async () => { await ura.stop(); await mgr.stop(); relay.cleanup(); });

const check = q => relay.post('/api/efris/check-document',
  { q, config: efrisConfig(ura), managerEndpoint: mgr.url, accessToken: 'mgr-token' }, { 'X-Tenant-Id': T });

test('by receipt number: URA has it, notes listed, FDN is in Manager', async () => {
  const r = (await check('REC-261027-001')).body;
  expect(r.success).toBe(true);
  expect(r.fdn).toBe(FDN);
  expect(r.history).toMatchObject({ reference: 'REC-261027-001', fdn: FDN });
  expect(r.ura).toMatchObject({ found: true, antifakeCode: 'AF12345', grossAmount: '5000' });
  expect(r.notes.map(n => n.reference).sort()).toEqual(['CN-1', 'CN-2', 'CX-9']);
  expect(r.notes.find(n => n.reference === 'CX-9')).toMatchObject({ kind: 'cancel-request', approveStatus: '103', statusText: 'Rejected' });
  expect(r.notes.find(n => n.reference === 'CN-2')).toMatchObject({ uraOnly: true, approveStatus: '103' });
  expect(r.manager).toMatchObject({ found: true, type: 'Receipt', fdn: FDN, matches: true });
});

test('an FDN URA does not have', async () => {
  const r = (await check('326099999999')).body;
  expect(r.success).toBe(true);
  expect(r.history).toBeUndefined();
  expect(r.ura).toMatchObject({ found: false });
  expect(r.ura.message).toContain('2124');
  expect(r.manager).toMatchObject({ noReference: true });
});
