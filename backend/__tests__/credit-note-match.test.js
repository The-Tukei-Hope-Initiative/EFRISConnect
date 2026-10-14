'use strict';
// Which Manager credit note gets an approved credit note's FDN: only an exact
// Reference match, or URA's long reference as a whole word in the description.
// Never a credit note whose reference merely contains ours.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { createFakeManager } = require('./helpers/fakeManager');
const { TIN, efrisConfig } = require('./helpers/fixtures');

const T = 'cn-match-biz';
let relay, ura, mgr;
beforeAll(async () => {
  ura = await createFakeUra().start();
  mgr = await createFakeManager().start();
  relay = loadRelay({ uraUrl: ura.url });
  expect((await relay.addTenant(T, { tin: TIN })).body.success).toBe(true);
  ura.on.T108 = call => ({ content: { basicInformation: { invoiceNo: call.body.invoiceNo, antifakeCode: 'AF1' }, summary: { qrCode: 'QR' } } });
  mgr.lists['text-custom-fields'] = [{ key: 'cf-fdn', name: 'FDN' }, { key: 'cf-st', name: 'Status' }];
});
afterAll(async () => { await ura.stop(); await mgr.stop(); relay.cleanup(); });

const check = () => relay.post('/api/efris/credit-notes/status',
  { config: efrisConfig(ura), managerEndpoint: mgr.url, accessToken: 'mgr-token' }, { 'X-Tenant-Id': T });
const strings = key => mgr.forms['credit-note-form'][key].CustomFields2.Strings;

describe('Manager credit note matching', () => {
  test('a reference that is only a substring of another note\'s reference or description is not matched', async () => {
    relay.writeJson('submission_log.json', [
      { id: 'c1', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: 'CN-INV-001', submittedAt: new Date().toISOString() },
    ]);
    ura.t111Records = [{ id: 'APP-1', referenceNo: 'CN-INV-001', oriInvoiceNo: '1', invoiceNo: '3260000000001', approveStatus: '101', invoiceApplyCategoryCode: '101' }];
    mgr.lists['credit-notes'] = [
      { key: 'other-1', description: 'Refund CN-INV-0012 and CN-INV-001X' },
      { key: 'other-2', description: 'Refund for CN-INV-001-B' },   // hyphen joins: not a whole word
    ];
    mgr.forms['credit-note-form'] = {
      'other-1': { Reference: 'CN-INV-0012', CustomFields2: { Strings: {} } },
      'other-2': { Reference: 'XCN-INV-001', CustomFields2: { Strings: {} } },
    };
    const r = await check();
    expect(r.body.success).toBe(true);
    expect(r.body.managerUpdated).toBe(0);
    expect(strings('other-1')).toEqual({});
    expect(strings('other-2')).toEqual({});
  });

  test('an exact Reference matches, ignoring case and surrounding spaces', async () => {
    mgr.lists['credit-notes'].push({ key: 'mine', description: '' });
    mgr.forms['credit-note-form'].mine = { Reference: '  cn-inv-001 ', CustomFields2: { Strings: {} } };
    const r = await check();
    expect(r.body.managerUpdated).toBe(1);
    expect(strings('mine')).toMatchObject({ 'cf-fdn': '3260000000001', 'cf-st': 'Approved' });
    expect(strings('other-1')).toEqual({});
  });

  test('a long URA reference as a whole word in the description matches; inside a longer word it does not', async () => {
    relay.writeJson('submission_log.json', [
      { id: 'c2', kind: 'credit-note', status: 'success', tin: TIN, tenantId: T, mode: 'sandbox', reference: '27PL020043618', submittedAt: new Date().toISOString() },
    ]);
    ura.t111Records = [{ id: 'APP-2', referenceNo: '27PL020043618', oriInvoiceNo: '2', invoiceNo: '3260000000002', approveStatus: '101', invoiceApplyCategoryCode: '101' }];
    mgr.lists['credit-notes'] = [
      { key: 'near', description: 'Return 27PL0200436189' },
      { key: 'word', description: 'Return | 27PL020043618 | goods damaged' },
    ];
    mgr.forms['credit-note-form'] = {
      near: { Reference: 'CR-1', CustomFields2: { Strings: {} } },
      word: { Reference: 'CR-2', CustomFields2: { Strings: {} } },
    };
    const r = await check();
    expect(r.body.managerUpdated).toBe(1);
    expect(strings('near')).toEqual({});
    expect(strings('word')).toMatchObject({ 'cf-fdn': '3260000000002' });
  });
});
