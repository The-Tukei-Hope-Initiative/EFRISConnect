'use strict';
// POST /api/efris/credit-notes/status: URA's T111 verdicts mapped and stored on
// the credit-note log entries.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, DEVICE, efrisConfig } = require('./helpers/fixtures');

let relay, ura;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  relay.writeJson('submission_log.json', [
    { id: 'cn-1', kind: 'credit-note', status: 'success', tin: TIN, deviceNo: DEVICE, reference: 'CN-001', submittedAt: '2026-10-08T10:00:00Z' },
    { id: 'cn-2', kind: 'credit-note', status: 'success', tin: TIN, deviceNo: DEVICE, reference: 'CN-002', submittedAt: '2026-10-08T11:00:00Z' },
    { id: 'cn-other', kind: 'credit-note', status: 'success', tin: '9999999999', reference: 'CN-001', submittedAt: '2026-10-08T10:00:00Z' },
    { id: 'inv-1', status: 'success', tin: TIN, reference: 'INV-001', fdn: '3240000000001' },
  ]);
  ura.t111Records = [
    { id: 'APP-101', referenceNo: 'CN-001', oriInvoiceNo: '3240000000001', invoiceNo: '3240000009999', approveStatus: '101', grossAmount: '-2360', currency: 'UGX', applicationTime: '08/10/2026 13:00:00', invoiceApplyCategoryCode: '101' },
    { id: 'APP-102', referenceNo: 'CN-002', oriInvoiceNo: '3240000000002', invoiceNo: '', approveStatus: '102', grossAmount: '-1180', currency: 'UGX', invoiceApplyCategoryCode: '101' },
  ];
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });

describe('credit-notes/status', () => {
  test('maps T111 records to items with a status text', async () => {
    const r = await relay.post('/api/efris/credit-notes/status', { config: efrisConfig(ura) });
    expect(r.body.success).toBe(true);
    expect(r.body.managerUpdated).toBe(0);
    expect(r.body.items).toEqual([
      { id: 'APP-101', referenceNo: 'CN-001', oriInvoiceNo: '3240000000001', invoiceNo: '3240000009999', approveStatus: '101', statusText: 'Approved',
        grossAmount: '-2360', currency: 'UGX', applicationTime: '08/10/2026 13:00:00', taskId: '', categoryCode: '101' },
      { id: 'APP-102', referenceNo: 'CN-002', oriInvoiceNo: '3240000000002', invoiceNo: '', approveStatus: '102', statusText: 'Pending approval',
        grossAmount: '-1180', currency: 'UGX', applicationTime: '', taskId: '', categoryCode: '101' },
    ]);
    const q = ura.callsOf('T111');
    expect(q).toHaveLength(1);
    expect(q[0].body).toMatchObject({ pageNo: '1', pageSize: '99', invoiceApplyCategoryCode: '101,103' });
  });

  test('stores approveStatus and, once approved, the FDN on the matching log entry only', () => {
    const log = relay.readJson('submission_log.json');
    const byId = Object.fromEntries(log.map(e => [e.id, e]));
    expect(byId['cn-1']).toMatchObject({ approveStatus: '101', statusText: 'Approved', fdn: '3240000009999', applicationId: 'APP-101' });
    expect(byId['cn-2']).toMatchObject({ approveStatus: '102', statusText: 'Pending approval', applicationId: 'APP-102' });
    expect(byId['cn-2'].fdn).toBeUndefined();
    expect(byId['cn-other'].approveStatus).toBeUndefined();   // another TIN, same reference
    expect(byId['inv-1'].approveStatus).toBeUndefined();      // not a credit note
  });

  test('a URA error on the first page is reported', async () => {
    ura.on.T111 = () => ({ rc: '1001', msg: 'Query failed' });
    try {
      const r = await relay.post('/api/efris/credit-notes/status', { config: efrisConfig(ura) });
      expect(r.body).toEqual({ success: false, error: 'URA 1001: Query failed' });
    } finally { delete ura.on.T111; }
  });
});
