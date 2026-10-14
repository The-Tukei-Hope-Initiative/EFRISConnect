'use strict';
// URA discount rule on T109: a discounted item goes as the item at its full amount
// (discountFlag 1, discountTotal = -discount) followed by a discount line
// (discountFlag 0, total = -discount); undiscounted items keep discountFlag 2.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { efrisConfig } = require('./helpers/fixtures');

let relay, ura, T;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  T = relay.app._test;
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });

const cfg = { vatRegistered: true, tin: '1000123456', deviceNo: 'DEV1', businessName: 'Test Traders Ltd' };
// 2 x 59,000 VAT-inclusive soda with 11,800 off (pays 106,200), plus 50,000 exempt flour.
const discounted = ref => ({
  Reference: ref, CustomerName: 'Jane Buyer', Currency: 'UGX',
  Lines: [
    { ItemName: 'Soda', ItemCode: 'SKU1', Qty: 2, UnitPrice: 59000, LineTotal: 106200, _discount: 11800, TaxName: 'Standard VAT 18%' },
    { ItemName: 'Maize flour', ItemCode: 'SKU2', Qty: 1, UnitPrice: 50000, LineTotal: 50000, TaxName: 'Exempt' },
  ],
});

describe('buildT109 discount lines (VAT 18% inclusive)', () => {
  test('item line at full amount, then a discount line, then the undiscounted line', () => {
    const g = T.buildT109(discounted('D-1'), cfg).goodsDetails;
    expect(g).toHaveLength(3);
    expect(g[0]).toMatchObject({ item: 'Soda', itemCode: 'SKU1', qty: '2', unitPrice: '59000.00', total: '118000.00',
      taxRate: '0.18', tax: '18000.00', discountFlag: '1', discountTotal: '-11800.00', discountTaxRate: '0.18', orderNumber: '0' });
    expect(g[1]).toMatchObject({ item: 'Soda (Discount)', itemCode: 'SKU1', qty: '', unitPrice: '', total: '-11800.00',
      taxRate: '0.18', tax: '-1800.00', discountFlag: '0', discountTotal: '', orderNumber: '1' });
    expect(g[2]).toMatchObject({ item: 'Maize flour', total: '50000.00', discountFlag: '2', discountTotal: '', discountTaxRate: '', orderNumber: '2' });
    // The item line is qty x unitPrice exactly.
    expect(parseFloat(g[0].qty) * parseFloat(g[0].unitPrice)).toBeCloseTo(parseFloat(g[0].total), 2);
  });

  test('tax is on the discounted amount; totals and taxDetails reconcile', () => {
    const t = T.buildT109(discounted('D-1'), cfg);
    expect(t.taxDetails).toEqual([
      { taxCategoryCode: '01', netAmount: '90000.00', taxRate: '0.18', taxAmount: '16200.00', grossAmount: '106200.00' },
      { taxCategoryCode: '03', netAmount: '50000.00', taxRate: '-', taxAmount: '0.00', grossAmount: '50000.00' },
    ]);
    expect(t.summary).toMatchObject({ grossAmount: '156200.00', taxAmount: '16200.00', netAmount: '140000.00', itemCount: '2' });
    const sumTotals = t.goodsDetails.reduce((s, g) => s + parseFloat(g.total), 0);
    expect(sumTotals).toBeCloseTo(156200, 2);
    expect(t.payWay).toEqual([{ paymentMode: '101', paymentAmount: '156200.00', orderNumber: '1' }]);
  });

  test('the discount is read from LineTotal when it was entered on a VAT-exclusive price', () => {
    // 1 x 1,180 inclusive; 100 off the 1,000 net price = 118 off the gross.
    const t = T.buildT109({ Reference: 'D-2', Lines: [{ ItemName: 'Pen', Qty: 1, UnitPrice: 1180, LineTotal: 1062, _discount: 100, TaxName: 'Standard' }] }, cfg);
    expect(t.goodsDetails.map(g => [g.discountFlag, g.total, g.tax])).toEqual([['1', '1180.00', '180.00'], ['0', '-118.00', '-18.00']]);
    expect(t.summary).toMatchObject({ grossAmount: '1062.00', taxAmount: '162.00', netAmount: '900.00' });
  });

  test('a mix without any discount keeps discountFlag 2 on every line', () => {
    const inv = discounted('D-3'); delete inv.Lines[0]._discount; inv.Lines[0].LineTotal = 118000;
    const t = T.buildT109(inv, cfg);
    expect(t.goodsDetails.map(g => [g.discountFlag, g.orderNumber])).toEqual([['2', '0'], ['2', '1']]);
    expect(t.summary).toMatchObject({ grossAmount: '168000.00', taxAmount: '18000.00', itemCount: '2' });
  });

  test('a Manager discount (Discount field) is handled the same way', () => {
    const t = T.buildT109({ Reference: 'D-4', Lines: [{ ItemName: 'Soda', Qty: 2, UnitPrice: 59000, LineTotal: 106200, Discount: 11800, TaxName: 'Standard' }] }, cfg);
    expect(t.goodsDetails.map(g => g.discountFlag)).toEqual(['1', '0']);
  });

  test('a credit note reverses the pair: item negative, discount line positive', () => {
    const cn = T.buildT108(discounted('CN-1'), cfg, { oriInvoiceId: '1', oriInvoiceNo: 'F1' });
    expect(cn.goodsDetails[0]).toMatchObject({ qty: '-2', total: '-118000.00', tax: '-18000.00', discountFlag: '1', discountTotal: '11800.00' });
    expect(cn.goodsDetails[1]).toMatchObject({ qty: '', total: '11800.00', tax: '1800.00', discountFlag: '0' });
    expect(cn.summary).toMatchObject({ grossAmount: '-156200.00', taxAmount: '-16200.00' });
  });
});

describe('submit-invoice sends the discount lines to URA', () => {
  test('T109 body for a discounted VAT line', async () => {
    const r = await relay.post('/api/efris/submit-invoice', { invoice: discounted('DISC-001'), config: efrisConfig(ura) });
    expect(r.body).toMatchObject({ success: true, fdn: 'FDN123' });
    const t109 = ura.callsOf('T109')[0].body;
    expect(t109.goodsDetails.map(g => [g.item, g.discountFlag, g.qty, g.unitPrice, g.total, g.tax, g.discountTotal, g.orderNumber])).toEqual([
      ['Soda', '1', '2', '59000.00', '118000.00', '18000.00', '-11800.00', '0'],
      ['Soda (Discount)', '0', '', '', '-11800.00', '-1800.00', '', '1'],
      ['Maize flour', '2', '1', '50000.00', '50000.00', '0', '', '2'],
    ]);
    expect(t109.summary).toMatchObject({ grossAmount: '156200.00', taxAmount: '16200.00', netAmount: '140000.00', itemCount: '2' });
    // The history keeps only goods lines (for credit-note prefill).
    const log = relay.readJson('submission_log.json', []);
    expect(log[0].lines.map(l => [l.name, l.orderNumber])).toEqual([['Soda', 0], ['Maize flour', 2]]);
  });
});
