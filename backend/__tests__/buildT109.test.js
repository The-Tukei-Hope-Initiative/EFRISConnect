'use strict';
// buildT109 (the EFRIS invoice/receipt payload) and the Uganda-time date helpers.
const { loadRelay } = require('./helpers/relay');

let relay, T;
beforeAll(() => { relay = loadRelay(); T = relay.app._test; });
afterAll(() => relay.cleanup());
afterEach(() => jest.restoreAllMocks());

const cfg = { vatRegistered: true, tin: '1000123456', deviceNo: 'DEV1', businessName: 'Test Traders Ltd' };
const mixed = () => ({
  Reference: 'INV-100', CustomerName: 'Jane Buyer',
  Lines: [
    { ItemName: 'Soda', ItemCode: 'SKU1', Qty: 2, UnitPrice: 59000, LineTotal: 118000, TaxName: 'Standard VAT 18%' },
    { ItemName: 'Maize flour', ItemCode: 'SKU2', Qty: 1, UnitPrice: 50000, LineTotal: 50000, TaxName: 'Exempt' },
  ],
});

describe('buildT109 tax groups', () => {
  test('a Standard line plus an Exempt line give one taxDetails row per category', () => {
    const t = T.buildT109(mixed(), cfg);
    expect(t.taxDetails).toEqual([
      { taxCategoryCode: '01', netAmount: '100000.00', taxRate: '0.18', taxAmount: '18000.00', grossAmount: '118000.00' },
      { taxCategoryCode: '03', netAmount: '50000.00', taxRate: '-', taxAmount: '0.00', grossAmount: '50000.00' },
    ]);
    for (const row of t.taxDetails) {
      expect(parseFloat(row.netAmount) + parseFloat(row.taxAmount)).toBeCloseTo(parseFloat(row.grossAmount), 2);
    }
    expect(t.summary).toMatchObject({ netAmount: '150000.00', taxAmount: '18000.00', grossAmount: '168000.00', itemCount: '2' });
    expect(t.goodsDetails.map(g => [g.taxRule, g.tax])).toEqual([['STANDARD', '18000.00'], ['EXEMPT', '0']]);
    expect(t.goodsDetails[0]).not.toHaveProperty('_catCode');
    expect(t.payWay).toEqual([{ paymentMode: '101', paymentAmount: '168000.00', orderNumber: '1' }]);
  });

  test('a non-VAT taxpayer issues an e-receipt (invoiceKind 2, OOS lines, no taxDetails)', () => {
    const t = T.buildT109(mixed(), { ...cfg, vatRegistered: false });
    expect(t.basicInformation.invoiceKind).toBe('2');
    expect(t.taxDetails).toEqual([]);
    expect(t.goodsDetails.every(g => g.taxRule === 'OOS' && g.tax === '0')).toBe(true);
  });
});

describe('buildT109 invoice type', () => {
  test('a normal sale is invoiceType 1 with no original invoice', () => {
    const t = T.buildT109(mixed(), cfg);
    expect(t.basicInformation).toMatchObject({ invoiceType: '1', oriInvoiceId: '', isRefund: '0', deviceNo: 'DEV1' });
    expect(t.sellerDetails.referenceNo).toBe('INV-100');
  });

  test('a debit note (_debitOf) is invoiceType 4 pointing at the original invoice id', () => {
    const t = T.buildT109({ ...mixed(), _debitOf: { oriInvoiceId: '987654321', oriInvoiceNo: '3240000001234' } }, cfg);
    expect(t.basicInformation).toMatchObject({ invoiceType: '4', oriInvoiceId: '987654321', isRefund: '0' });
  });
});

describe('buildT109 issuedDate (Uganda time, yyyy-MM-dd HH:mm:ss)', () => {
  test('22:30 UTC on 8 Oct is 01:30 on 9 Oct in Kampala', () => {
    jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-08T22:30:00Z'));
    const t = T.buildT109(mixed(), cfg);
    expect(t.basicInformation.issuedDate).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    expect(t.basicInformation.issuedDate).toBe('2026-10-09 01:30:00');
  });

  test('an offline sale (_saleAt) is dated when it was made, not when it is sent', () => {
    jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-10T08:00:00Z'));
    const t = T.buildT109({ ...mixed(), _saleAt: '2026-10-08T22:30:00.000Z' }, cfg);
    expect(t.basicInformation.issuedDate).toBe('2026-10-09 01:30:00');
  });

  test('an explicit IssueDate keeps its day and takes the time of the sale', () => {
    jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-08T22:30:00Z'));
    const t = T.buildT109({ ...mixed(), IssueDate: '2026-10-07' }, cfg);
    expect(t.basicInformation.issuedDate).toBe('2026-10-07 01:30:00');
  });
});

describe('eatToday / eatParts (UTC+3 day boundary)', () => {
  const at = iso => jest.spyOn(Date, 'now').mockReturnValue(Date.parse(iso));
  test('20:59:59.999 UTC is still the same day in Kampala', () => { at('2026-10-08T20:59:59.999Z'); expect(T.eatToday()).toBe('2026-10-08'); });
  test('21:00:00 UTC is already the next day in Kampala', () => { at('2026-10-08T21:00:00.000Z'); expect(T.eatToday()).toBe('2026-10-09'); });
  test('year end rolls over at 21:00 UTC on 31 Dec', () => { at('2026-12-31T21:00:00Z'); expect(T.eatToday()).toBe('2027-01-01'); });
  test('eatParts splits date, time, year and month', () => {
    expect(T.eatParts(Date.parse('2026-02-28T22:15:30Z'))).toEqual({ date: '2026-03-01', time: '01:15:30', year: '2026', month: '03' });
  });
});
