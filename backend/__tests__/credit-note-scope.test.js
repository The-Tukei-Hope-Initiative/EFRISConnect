'use strict';
// URA's credit-note verdicts are filed only under the business and mode (sandbox /
// production) that was checked, and a Manager credit note never receives a second
// credit note's FDN.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { createFakeManager } = require('./helpers/fakeManager');
const { TIN, efrisConfig } = require('./helpers/fixtures');

const T = 'scope-sandbox', P = 'scope-prod';
let relay, ura, mgr;
beforeAll(async () => {
  ura = await createFakeUra().start();
  mgr = await createFakeManager().start();
  relay = loadRelay({ uraUrl: ura.url });
  expect((await relay.addTenant(T, { tin: TIN, mode: 'sandbox' })).body.success).toBe(true);
  expect((await relay.addTenant(P, { tin: TIN, mode: 'production' })).body.success).toBe(true);
  ura.on.T108 = call => ({ content: { basicInformation: { invoiceNo: call.body.invoiceNo, antifakeCode: 'AF' }, summary: { qrCode: 'QR' } } });
  mgr.lists['text-custom-fields'] = [{ key: 'cf-fdn', name: 'FDN' }, { key: 'cf-st', name: 'Status' }];
});
afterAll(async () => { await ura.stop(); await mgr.stop(); relay.cleanup(); });

// The request claims production; the business's saved mode (sandbox) is used.
const check = (tenant, cfg) => relay.post('/api/efris/credit-notes/status',
  { config: efrisConfig(ura, cfg), managerEndpoint: mgr.url, accessToken: 'mgr-token' }, { 'X-Tenant-Id': tenant });
const byId = () => Object.fromEntries(relay.readJson('submission_log.json').map(e => [e.id, e]));
const now = new Date().toISOString();

describe('credit-note status scoping', () => {
  test('sandbox and production entries with the same TIN and reference stay separate', async () => {
    relay.writeJson('submission_log.json', [
      { id: 'sb', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'CN-SAME-1', submittedAt: now },
      { id: 'pr', kind: 'credit-note', status: 'success', tin: TIN, tenantId: P, mode: 'production', reference: 'CN-SAME-1', submittedAt: now },
      { id: 'pr2', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'production', reference: 'CN-SAME-1', submittedAt: now },
    ]);
    ura.t111Records = [{ id: 'APP-S', referenceNo: 'CN-SAME-1', oriInvoiceNo: '1', invoiceNo: '3260000000101', approveStatus: '101', invoiceApplyCategoryCode: '101' }];
    mgr.lists['credit-notes'] = [];
    mgr.forms['credit-note-form'] = {};
    const r = await check(T, { mode: 'production', tin: '9999999999' });
    expect(r.body.success).toBe(true);
    const e = byId();
    expect(e.sb).toMatchObject({ approveStatus: '101', fdn: '3260000000101', applicationId: 'APP-S' });
    expect(e.pr.approveStatus).toBeUndefined();
    expect(e.pr2.approveStatus).toBeUndefined();
    // Checked under the business's saved TIN, not the one in the request.
    expect(ura.callsOf('T111').pop().tin).toBe(TIN);
    expect(relay.readJson('submission_log.json').filter(x => x.adopted)).toHaveLength(0);
  });

  test('an adopted note is tagged with the checked business and its saved mode', async () => {
    ura.t111Records = [{ id: 'APP-NEW', referenceNo: 'CN-ADOPT-1', oriInvoiceNo: '2', invoiceNo: '', approveStatus: '102', invoiceApplyCategoryCode: '101' }];
    await check(T, { mode: 'production' });
    const a = relay.readJson('submission_log.json').find(x => x.reference === 'CN-ADOPT-1');
    expect(a).toMatchObject({ adopted: true, tenantId: T, mode: 'sandbox', tin: TIN });
  });

  test('two credit notes of one invoice never land on the same Manager credit note', async () => {
    relay.writeJson('submission_log.json', [
      { id: 'inv', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'INV-9', fdn: '3260000000900' },
      { id: 'n1', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'R-1', originalFdn: '3260000000900', oriInvoiceNo: '3260000000900', submittedAt: now },
      { id: 'n2', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'R-2', originalFdn: '3260000000900', oriInvoiceNo: '3260000000900', submittedAt: now },
    ]);
    ura.t111Records = [
      { id: 'APP-1', referenceNo: 'R-1', oriInvoiceNo: '3260000000900', invoiceNo: '3260000000901', approveStatus: '101', invoiceApplyCategoryCode: '101' },
      { id: 'APP-2', referenceNo: 'R-2', oriInvoiceNo: '3260000000900', invoiceNo: '3260000000902', approveStatus: '101', invoiceApplyCategoryCode: '101' },
    ];
    // Manager has one credit note, carrying the extension's default reference.
    mgr.lists['credit-notes'] = [{ key: 'only', description: '' }];
    mgr.forms['credit-note-form'] = { only: { Reference: 'CN-INV-9', CustomFields2: { Strings: {} } } };
    const r = await check(T);
    expect(r.body.managerUpdated).toBe(1);
    const e = byId();
    const written = ['n1', 'n2'].filter(id => e[id].mgrWritten);
    expect(written).toHaveLength(1);
    expect(e[written[0]].mgrKey).toBe('only');
    const fdn = mgr.forms['credit-note-form'].only.CustomFields2.Strings['cf-fdn'];
    expect(fdn).toBe(e[written[0]].fdn);
    // A later check does not overwrite it with the other note.
    const again = await check(T);
    expect(again.body.managerUpdated).toBe(0);
    expect(mgr.forms['credit-note-form'].only.CustomFields2.Strings['cf-fdn']).toBe(fdn);
  });

  test('a Manager document already recorded as another note\'s mgrKey is not written again, even on an exact reference', async () => {
    relay.writeJson('submission_log.json', [
      { id: 'old', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'R-OLD', fdn: '3260000000800', mgrWritten: true, mgrKey: 'taken', submittedAt: now },
      { id: 'new', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'R-NEW', submittedAt: now },
    ]);
    ura.t111Records = [{ id: 'APP-N', referenceNo: 'R-NEW', oriInvoiceNo: '5', invoiceNo: '3260000000801', approveStatus: '101', invoiceApplyCategoryCode: '101' }];
    mgr.lists['credit-notes'] = [{ key: 'taken', description: '' }];
    mgr.forms['credit-note-form'] = { taken: { Reference: 'R-NEW', CustomFields2: { Strings: { 'cf-fdn': '3260000000800' } } } };
    const r = await check(T);
    expect(r.body.managerUpdated).toBe(0);
    expect(mgr.forms['credit-note-form'].taken.CustomFields2.Strings['cf-fdn']).toBe('3260000000800');
  });
});
