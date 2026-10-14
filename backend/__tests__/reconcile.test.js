'use strict';
// POST /api/reconcile/documents: URA's T106 list against Manager's documents.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { createFakeManager } = require('./helpers/fakeManager');
const { efrisConfig } = require('./helpers/fixtures');

let relay, ura, mgr, res;
beforeAll(async () => {
  ura = await createFakeUra().start();
  mgr = await createFakeManager().start();
  relay = loadRelay({ uraUrl: ura.url });

  ura.t106Records = [
    { invoiceNo: '3240000001111', referenceNo: 'INV-1', grossAmount: '118000', invoiceType: '1', invoiceKind: '1', issuedDate: '05/10/2026' },
    { invoiceNo: '3240000002222', referenceNo: 'POS-77', grossAmount: '50000', invoiceType: '1', invoiceKind: '2', issuedDate: '05/10/2026' },
    { invoiceNo: '3240000003333', referenceNo: 'INV-3', grossAmount: '9000', invoiceType: '1', invoiceKind: '1', issuedDate: '06/10/2026' },
    { invoiceNo: '3240000004444', referenceNo: 'URA-ONLY', grossAmount: '700', invoiceType: '1', invoiceKind: '2', issuedDate: '07/10/2026' },
  ];
  mgr.lists['sales-invoices'] = [
    { key: 'si-1', reference: 'INV-1', invoiceAmount: { value: 118000, currency: 'UGX' }, issueDate: '2026-10-05' },
    { key: 'si-3', reference: 'INV-3', invoiceAmount: { value: 9500, currency: 'UGX' }, issueDate: '2026-10-06' },
    { key: 'si-old', reference: 'INV-OLD', invoiceAmount: { value: 1, currency: 'UGX' }, issueDate: '2026-09-01' },
  ];
  mgr.lists['receipts'] = [
    // Matched only through the FDN in its description (reference differs).
    { key: 'r-fdn', reference: 'R-9', description: 'Cash sale FDN 3240000002222', amount: { value: 50000 }, date: '2026-10-05' },
    // Payment against invoice INV-1: never at URA, listed under payments.
    { key: 'r-pay', reference: 'PAY-1', description: 'Payment for INV-1', amount: { value: 20000 }, date: '2026-10-06' },
    // A real sale that never reached URA.
    { key: 'r-sale', reference: 'R-10', description: 'Cash sale', amount: { value: 3000 }, date: '2026-10-07' },
  ];
  mgr.lists['credit-notes'] = [];
  mgr.forms['receipt-form'] = {
    'r-pay': { Lines: [{ Account: 'ar-key', AccountsReceivableSalesInvoice: 'si-1', Qty: 1, SalesUnitPrice: 20000 }] },
    'r-sale': { Lines: [{ Item: 'item-1', Qty: 1, SalesUnitPrice: 3000 }] },
  };

  res = await relay.post('/api/reconcile/documents', { config: efrisConfig(ura), startDate: '2026-10-01', endDate: '2026-10-09',
    managerEndpoint: mgr.url, accessToken: 'mgr-token' });
});
afterAll(async () => { await ura.stop(); await mgr.stop(); relay.cleanup(); });

describe('reconcile/documents', () => {
  test('answers with counts', () => {
    expect(res.body.success).toBe(true);
    expect(res.body.counts).toEqual({ ura: 4, manager: 4, matched: 3, payments: 1 });
  });

  test('payment-only receipts are listed under payments, not onlyManager', () => {
    expect(res.body.payments.map(p => p.reference)).toEqual(['PAY-1']);
    expect(res.body.onlyManager).toEqual([{ reference: 'R-10', type: 'receipt', amount: 3000, date: '2026-10-07', key: 'r-sale' }]);
  });

  test('a reference match and an FDN-in-description match both count; the rest is URA-only', () => {
    expect(res.body.onlyUra.map(u => u.reference)).toEqual(['URA-ONLY']);
    expect(res.body.onlyUra[0]).toMatchObject({ fdn: '3240000004444', kind: 'receipt', amount: 700 });
  });

  test('amount differences above 1 are flagged', () => {
    expect(res.body.amountMismatch).toEqual([{ reference: 'INV-3', fdn: '3240000003333', uraAmount: 9000, managerAmount: 9500 }]);
  });

  test('URA was queried with T106 for the date range', () => {
    const q = ura.callsOf('T106');
    expect(q).toHaveLength(1);
    expect(q[0].body).toMatchObject({ startDate: '2026-10-01', endDate: '2026-10-09', pageNo: '1', pageSize: '99' });
  });
});
