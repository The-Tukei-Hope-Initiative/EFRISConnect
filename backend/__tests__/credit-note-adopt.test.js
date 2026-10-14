'use strict';
// A credit note URA has (T111) but the submission log does not (issued before
// credit notes were logged) is adopted into the log; once approved, its FDN,
// verification code and QR are written to the Manager credit note.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { createFakeManager } = require('./helpers/fakeManager');
const { TIN, DEVICE, efrisConfig } = require('./helpers/fixtures');

const TENANT = 'efris-test-2026-10';
const REF = 'CN-INV-B-2B-011', CN_FDN = '326044279999', ORIG_FDN = '326044272898';
let relay, ura, mgr;
beforeAll(async () => {
  ura = await createFakeUra().start();
  mgr = await createFakeManager().start();
  relay = loadRelay({ uraUrl: ura.url });
  expect((await relay.addTenant(TENANT, { tin: TIN })).body.success).toBe(true);
  relay.writeJson('submission_log.json', [
    { id: 'inv-1', status: 'success', tin: TIN, tenantId: TENANT, reference: 'INV-B-2B-011', fdn: ORIG_FDN },
  ]);
  ura.t111Records = [
    { id: 'APP-7', referenceNo: REF, oriInvoiceNo: ORIG_FDN, invoiceNo: CN_FDN, approveStatus: '101', grossAmount: '-59000', currency: 'UGX',
      applicationTime: '08/10/2026 14:05:00', invoiceApplyCategoryCode: '101', buyerLegalName: 'MAILA GROUP OF COMPANIES (U) LTD' },
    { id: 'APP-8', referenceNo: 'CN-PENDING-1', oriInvoiceNo: '326044270001', invoiceNo: '', approveStatus: '102', grossAmount: '-1180', currency: 'UGX',
      applicationTime: '09/10/2026 09:00:00', invoiceApplyCategoryCode: '101' },
    { id: 'APP-9', referenceNo: 'DN-CANCEL-1', oriInvoiceNo: '326044270002', invoiceNo: '', approveStatus: '101', invoiceApplyCategoryCode: '103' },
  ];
  ura.on.T108 = call => ({ content: { basicInformation: { invoiceNo: call.body.invoiceNo, antifakeCode: 'AFCN123' }, summary: { qrCode: 'QRDATA-CN' } } });
  mgr.lists['text-custom-fields'] = [
    { key: 'cf-fdn', name: 'FDN' }, { key: 'cf-ver', name: 'Verification Code' }, { key: 'cf-qr', name: 'QR Code' }, { key: 'cf-st', name: 'Status' },
  ];
  mgr.lists['credit-notes'] = [{ key: 'cn-key-1', reference: REF }, { key: 'cn-key-2', reference: 'CN-PENDING-1' }];
  mgr.forms['credit-note-form'] = {
    'cn-key-1': { Reference: REF, Description: 'Return', CustomFields2: { Strings: { 'cf-st': 'Awaiting URA approval' } } },
    'cn-key-2': { Reference: 'CN-PENDING-1', CustomFields2: { Strings: {} } },
  };
});
afterAll(async () => { await ura.stop(); await mgr.stop(); relay.cleanup(); });

const check = () => relay.post('/api/efris/credit-notes/status',
  { config: efrisConfig(ura), managerEndpoint: mgr.url, accessToken: 'mgr-token' }, { 'X-Tenant-Id': TENANT });
const cnEntries = () => relay.readJson('submission_log.json').filter(e => e.kind === 'credit-note');

describe('adopting credit notes found at URA', () => {
  test('an approved credit note with no log entry is adopted and written to Manager', async () => {
    const r = await check();
    expect(r.body.success).toBe(true);
    expect(r.body.managerUpdated).toBe(1);
    const log = cnEntries();
    expect(log).toHaveLength(2);   // the debit-note cancellation (category 103) is not adopted
    const e = log.find(x => x.reference === REF);
    expect(e).toMatchObject({
      kind: 'credit-note', docType: 'Credit note', adopted: true, status: 'success', userName: 'URA check',
      tenantId: TENANT, tin: TIN, mode: 'sandbox', applicationId: 'APP-7', approveStatus: '101', statusText: 'Approved',
      fdn: CN_FDN, originalFdn: ORIG_FDN, oriInvoiceNo: ORIG_FDN, grossAmount: '-59000', totalAmount: -59000, currency: 'UGX',
      customerName: 'MAILA GROUP OF COMPANIES (U) LTD', submittedAt: '2026-10-08T11:05:00.000Z',
      antifakeCode: 'AFCN123', qrCode: 'QRDATA-CN', mgrWritten: true,
    });
    expect(e.validationUrl).toContain('invoiceNo=' + CN_FDN);
    expect(e.validationUrl).toContain('antiFakeCode=AFCN123');
    expect(ura.callsOf('T108').map(c => c.body)).toEqual([{ invoiceNo: CN_FDN }]);

    const form = mgr.forms['credit-note-form']['cn-key-1'];
    expect(form.CustomFields2.Strings).toMatchObject({ 'cf-fdn': CN_FDN, 'cf-ver': 'AFCN123', 'cf-st': 'Approved' });
    expect(form.CustomFields2.Strings['cf-qr']).toBe(e.validationUrl);
    expect(form.Description).toContain('Credit Note FDN: ' + CN_FDN);
  });

  test('a pending credit note is adopted without a Manager write-back', () => {
    const e = cnEntries().find(x => x.reference === 'CN-PENDING-1');
    expect(e).toMatchObject({ adopted: true, approveStatus: '102', statusText: 'Pending approval', fdn: '', tenantId: TENANT, applicationId: 'APP-8' });
    expect(e.mgrWritten).toBeUndefined();
    expect(mgr.forms['credit-note-form']['cn-key-2'].CustomFields2.Strings).toEqual({});
  });

  test('a second check does not duplicate entries or write again', async () => {
    mgr.reset(); ura.reset();
    const r = await check();
    expect(r.body.success).toBe(true);
    expect(r.body.managerUpdated).toBe(0);
    expect(cnEntries()).toHaveLength(2);
    expect(mgr.requests.filter(q => q.method === 'POST')).toHaveLength(0);
    expect(ura.callsOf('T108')).toHaveLength(0);
  });

  test('once the pending one is approved, it gets its FDN and is written to Manager', async () => {
    ura.t111Records[1] = { ...ura.t111Records[1], approveStatus: '101', invoiceNo: '326044278888' };
    const r = await check();
    expect(r.body.managerUpdated).toBe(1);
    expect(cnEntries()).toHaveLength(2);
    expect(cnEntries().find(x => x.reference === 'CN-PENDING-1')).toMatchObject({ fdn: '326044278888', antifakeCode: 'AFCN123', mgrWritten: true });
    expect(mgr.forms['credit-note-form']['cn-key-2'].CustomFields2.Strings).toMatchObject({ 'cf-fdn': '326044278888', 'cf-ver': 'AFCN123', 'cf-st': 'Approved' });
  });

  test('without T108 details the FDN is still written', async () => {
    delete ura.on.T108;   // fake URA answers "unknown interface"
    ura.t111Records.push({ id: 'APP-10', referenceNo: 'CN-NOVER', oriInvoiceNo: '1', invoiceNo: '326044277777', approveStatus: '101', grossAmount: '-10', currency: 'UGX', invoiceApplyCategoryCode: '101' });
    mgr.lists['credit-notes'].push({ key: 'cn-key-3', reference: 'CN-NOVER' });
    mgr.forms['credit-note-form']['cn-key-3'] = { Reference: 'CN-NOVER', CustomFields2: { Strings: {} } };
    const r = await check();
    expect(r.body.managerUpdated).toBe(1);
    const s = mgr.forms['credit-note-form']['cn-key-3'].CustomFields2.Strings;
    expect(s).toMatchObject({ 'cf-fdn': '326044277777', 'cf-st': 'Approved' });
    expect(s['cf-ver']).toBeUndefined();
  });
});
