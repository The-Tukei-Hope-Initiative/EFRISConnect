'use strict';
// What we send to URA (Interface Design v24.0.1): the duplicate-reference guard
// and taking the FDN URA already has, deemed names, unknown tax codes, debit note
// reasons and cancelling a debit note, credit notes only through T110.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, DEVICE, efrisConfig, invoice } = require('./helpers/fixtures');

let relay, ura, T;
const cfg = { vatRegistered: true, tin: TIN, deviceNo: DEVICE, businessName: 'Test Traders Ltd' };
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  T = relay.app._test;
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });
beforeEach(() => { ura.reset(); ura.t109Error = null; ura.t106Records = []; ura.on = {}; });

describe('T109 payload', () => {
  test('a sale with a reference asks URA to refuse a second one (isCheckReferenceNo 1)', () => {
    expect(T.buildT109(invoice('REC-1'), cfg).sellerDetails).toMatchObject({ referenceNo: 'REC-1', isCheckReferenceNo: '1' });
    expect(T.buildT109(invoice(''), cfg).sellerDetails.isCheckReferenceNo).toBe('0');
  });

  test('a deemed line is named "<item> (deemed)", its discount line "<item> (deemed) (Discount)"', () => {
    const t = T.buildT109({ Reference: 'D-1', Lines: [{ ItemName: 'Cement', Qty: 1, UnitPrice: 1000, LineTotal: 900, Discount: 100, TaxName: 'Deemed VAT 18%' }] }, cfg);
    expect(t.goodsDetails.map(g => g.item)).toEqual(['Cement (deemed)', 'Cement (deemed) (Discount)']);
  });

  test('a tax code we cannot place stops the sale; "VAT 18%" is standard', () => {
    expect(() => T.buildT109({ Reference: 'U-1', Lines: [{ ItemName: 'Soap', Qty: 1, UnitPrice: 100, LineTotal: 100, TaxName: 'Luxury 5%' }] }, cfg))
      .toThrow(/Line 1 \(Soap\) has the tax code "Luxury 5%"/);
    const t = T.buildT109({ Reference: 'U-2', Lines: [{ ItemName: 'Soap', Qty: 1, UnitPrice: 118, LineTotal: 118, TaxName: 'VAT 18%' }] }, cfg);
    expect(t.goodsDetails[0]).toMatchObject({ taxRate: '0.18', taxRule: 'STANDARD' });
  });

  test('a debit note carries URA\'s reason code and text in extend', () => {
    const t = T.buildT109({ ...invoice('DN-1'), _debitOf: { oriInvoiceId: 'ID9', oriInvoiceNo: 'F9', reasonCode: '102', reason: 'Asked by buyer' } }, cfg);
    expect(t.extend).toEqual({ reason: 'Asked by buyer', reasonCode: '102' });
    expect(T.buildT109(invoice('S-1'), cfg).extend).toEqual({});
  });
});

describe('URA already has this reference (rc 2254)', () => {
  test('a live sale shows the FDN URA already has instead of an error', async () => {
    ura.t109Error = { rc: '2254', msg: "The seller's reference number already exists!" };
    ura.t106Records = [{ referenceNo: 'REC-DUP', invoiceNo: 'FDN-EXISTING', antifakeCode: 'AFX', id: 'IDX', grossAmount: '2360' }];
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('REC-DUP'), config: efrisConfig(ura) });
    expect(r.body).toMatchObject({ success: true, fdn: 'FDN-EXISTING', antifakeCode: 'AFX' });
    expect(ura.callsOf('T109')).toHaveLength(1);
  });

  test('when URA has no such document the rejection is shown', async () => {
    ura.t109Error = { rc: '2254', msg: "The seller's reference number already exists!" };
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('REC-DUP2'), config: efrisConfig(ura) });
    expect(r.body).toMatchObject({ success: false, returnCode: '2254' });
  });
});

describe('credit and debit notes', () => {
  test('cancelling a debit note is a T114 request with category 103', async () => {
    ura.on.T114 = () => ({ rc: '00' });
    const r = await relay.post('/api/efris/debit-notes/cancel', { config: efrisConfig(ura), oriInvoiceId: 'ID9', invoiceNo: 'DNFDN1', reasonCode: '101' });
    expect(r.body).toMatchObject({ success: true, pendingApproval: true });
    expect(ura.callsOf('T114')[0].body).toMatchObject({ oriInvoiceId: 'ID9', invoiceNo: 'DNFDN1', reasonCode: '101', invoiceApplyCategoryCode: '103' });
  });

  test('a credit note is never retried as T108 when T110 fails', async () => {
    ura.on.T110 = () => ({ rc: '99', msg: 'Interface not found' });
    ura.on.T108 = () => ({ rc: '00', content: { basicInformation: { invoiceNo: 'WRONG' } } });
    await relay.post('/api/efris/credit-note', { originalFDN: 'F1', originalInvoiceId: 'ID1', reasonCode: '102', invoice: invoice('CN-X'), config: efrisConfig(ura) });
    expect(ura.callsOf('T110')).toHaveLength(1);
    expect(ura.callsOf('T108')).toHaveLength(0);
  });
});
