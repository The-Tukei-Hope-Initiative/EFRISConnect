'use strict';
// POST /api/manager/create-receipt against a fake Manager (API2).
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');

const UGX_CASH = { key: 'acc-cash', name: 'Cash on Hand', actualBalance: { value: 0, currency: 'UGX' } };
const UGX_MOMO = { key: 'acc-momo', name: 'MTN Mobile Money', actualBalance: { value: 0, currency: 'UGX' } };
const USD_CASH = { key: 'acc-usd', name: 'Cash on Hand USD', actualBalance: { value: 0, currency: 'USD' } };

let relay, mgr;
beforeAll(async () => {
  mgr = await createFakeManager().start();
  mgr.lists['customers'] = [{ key: 'cust-1', name: 'Jane Buyer' }];
  mgr.lists['chart-of-accounts'] = [{ key: 'sales-key', name: 'Sales' }, { key: 'ar-key', name: 'Accounts receivable' }];
  mgr.lists['tax-codes'] = [{ key: 'tc-exempt', name: 'Exempt' }, { key: 'tc-vat', name: 'VAT 18%' }];
  mgr.lists['inventory-items'] = [{ key: 'item-1', ItemCode: 'SKU1', name: 'Soda 500ml' }];
  mgr.lists['text-custom-fields'] = [{ key: 'cf-pay', name: 'Payment Method' }];
  mgr.forms['custom-theme-form'] = { 'theme-1': { Name: 'EFRISConnect Receipt' } };
  mgr.forms['customer-form'] = { 'cust-1': { Name: 'Jane Buyer', DueDateDays: 30 } };
  relay = loadRelay();
});
afterAll(async () => { await mgr.stop(); relay.cleanup(); });
beforeEach(() => { mgr.reset(); mgr.locationOnly.clear(); mgr.lists['bank-and-cash-accounts'] = [UGX_CASH, UGX_MOMO]; });

const createReceipt = receipt => relay.post('/api/manager/create-receipt', { managerEndpoint: mgr.url, accessToken: 'mgr-token', receipt });

describe('create-receipt', () => {
  test('(a) UGX cash sale: one receipt with the theme, the customer, the item and the tax code', async () => {
    const r = await createReceipt({ reference: 'R-001', date: '2026-10-09', customer: 'Jane Buyer', currency: 'UGX', paymentMethod: 'Cash',
      themeKey: 'theme-1', lines: [{ itemCode: 'SKU1', itemName: 'Soda 500ml', qty: 2, unitPrice: 5900, taxCat: 'Standard' }] });
    expect(r.status).toBe(200);
    const posted = mgr.posts('receipt-form');
    expect(posted).toHaveLength(1);
    expect(r.body).toEqual({ success: true, key: Object.keys(mgr.forms['receipt-form'])[0], reference: 'R-001', transfers: [] });
    const f = posted[0];
    expect(f).toMatchObject({ Date: '2026-10-09', Reference: 'R-001', ReceivedIn: 'acc-cash', PaidBy: 1, Customer: 'cust-1',
      CustomTheme: true, CustomThemeId: 'theme-1', QuantityColumn: true, UnitPriceColumn: true });
    expect(f.Lines).toEqual([{ Qty: 2, UnitPrice: 5900, SalesUnitPrice: 5900, Item: 'item-1', TaxCode: 'tc-vat' }]);
    expect(f.CustomFields2).toEqual({ Strings: { 'cf-pay': 'Cash' } });
    expect(mgr.posts('inter-account-transfer-form')).toHaveLength(0);
    expect(mgr.posts('customer-form')).toHaveLength(0);   // existing customer reused
  });

  test('(a2) a new customer is created with the buyer type, TIN and address; a known one gets its missing TIN', async () => {
    mgr.lists['text-custom-fields'] = [{ key: 'cf-pay', name: 'Payment Method' }, { key: 'cf-tin', name: 'Buyer TIN' }, { key: 'cf-type', name: 'Customer Type' }];
    let r = await createReceipt({ reference: 'R-B2B-1', customer: 'Aryami Consults Ltd', customerType: 'B2B', buyerTin: '1017307190',
      customerAddress: 'Plot 1 Kampala Road', currency: 'UGX', paymentMethod: 'Cash', lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 5900 }] });
    expect(r.body.success).toBe(true);
    const made = mgr.posts('customer-form')[0];
    expect(made).toMatchObject({ Name: 'Aryami Consults Ltd', BillingAddress: 'Plot 1 Kampala Road' });
    expect(made.CustomFields2.Strings).toMatchObject({ 'cf-tin': '1017307190', 'cf-type': 'B2B' });
    mgr.reset();
    r = await createReceipt({ reference: 'R-B2B-2', customer: 'Jane Buyer', customerType: 'B2B', buyerTin: '1000000001',
      currency: 'UGX', paymentMethod: 'Cash', lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 5900 }] });
    expect(r.body.success).toBe(true);
    const upd = mgr.posts('customer-form/cust-1')[0];
    expect(upd).toMatchObject({ DueDateDays: 30 });                  // kept
    expect(upd.CustomFields2.Strings).toMatchObject({ 'cf-tin': '1000000001' });
    expect(upd.BillingAddress).toBeUndefined();                       // not given, not wiped
    mgr.lists['text-custom-fields'] = [{ key: 'cf-pay', name: 'Payment Method' }];
  });

  test('(b) USD sale into a UGX-only account is recorded in UGX at the exchange rate', async () => {
    const r = await createReceipt({ reference: 'R-USD-1', currency: 'USD', exchangeRate: 4000, paymentMethod: 'Cash',
      lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 0.58 }] });
    expect(r.body.success).toBe(true);
    const f = mgr.posts('receipt-form')[0];
    expect(f.ReceivedIn).toBe('acc-cash');
    expect(f.Lines[0]).toMatchObject({ Qty: 1, SalesUnitPrice: 2320, UnitPrice: 2320 });
    expect(f.Description).toContain('(USD 0.58 at 4000 UGX/USD)');
  });

  test('(c) USD sale goes to the USD account, unconverted, when one exists', async () => {
    mgr.lists['bank-and-cash-accounts'] = [UGX_CASH, USD_CASH];
    const r = await createReceipt({ reference: 'R-USD-2', currency: 'USD', exchangeRate: 4000, paymentMethod: 'Cash',
      lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 0.58 }] });
    expect(r.body.success).toBe(true);
    const f = mgr.posts('receipt-form')[0];
    expect(f.ReceivedIn).toBe('acc-usd');
    expect(f.Lines[0]).toMatchObject({ SalesUnitPrice: 0.58 });
    expect(f.Description).toBeUndefined();
  });

  test('(d) split payment: Cash receipt plus an inter-account transfer of the Mobile Money part', async () => {
    const r = await createReceipt({ reference: 'R-SPLIT-1', date: '2026-10-09', currency: 'UGX', paymentMethod: 'Cash',
      payments: [{ method: 'Cash', amount: 30000 }, { method: 'Mobile Money', amount: 20000, txn: 'MP261009.1234.A' }],
      lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 50000 }] });
    expect(r.body).toMatchObject({ success: true, transfers: [{ method: 'Mobile Money', amount: 20000, ok: true }] });
    expect(mgr.posts('receipt-form')[0].ReceivedIn).toBe('acc-cash');
    const iat = mgr.posts('inter-account-transfer-form');
    expect(iat).toHaveLength(1);
    expect(iat[0]).toMatchObject({ Date: '2026-10-09', Reference: 'MP261009.1234.A', PaidFrom: 'acc-cash', ReceivedIn: 'acc-momo',
      Amount: 20000, CreditAmount: 20000, DebitAmount: 20000 });
    expect(iat[0].Description).toBe('Split payment R-SPLIT-1: Mobile Money part (Txn MP261009.1234.A)');
  });

  test('(e) credit sale: a sales invoice for the whole sale and a payment receipt against it', async () => {
    mgr.locationOnly.add('sales-invoice-form');   // key only in the Location header
    const r = await createReceipt({ reference: 'INV-CR-1', date: '2026-10-09', customer: 'Jane Buyer', currency: 'UGX', creditSale: true,
      themeKey: 'theme-1', payments: [{ method: 'Cash', amount: 10000 }, { method: 'Credit', amount: 40000 }],
      lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 50000, taxCat: 'Standard' }] });
    expect(r.status).toBe(200);
    const invKey = Object.keys(mgr.forms['sales-invoice-form'])[0];
    expect(r.body).toEqual({ success: true, key: invKey, kind: 'invoice', reference: 'INV-CR-1', payments: [{ method: 'Cash', amount: 10000, ok: true }] });

    const inv = mgr.posts('sales-invoice-form');
    expect(inv).toHaveLength(1);
    expect(inv[0]).toMatchObject({ IssueDate: '2026-10-09', DueDateDays: 30, Customer: 'cust-1', Reference: 'INV-CR-1', AmountsIncludeTax: true, CustomThemeId: 'theme-1' });
    expect(inv[0].Lines).toEqual([{ Qty: 1, UnitPrice: 50000, SalesUnitPrice: 50000, Item: 'item-1', TaxCode: 'tc-vat' }]);

    const pay = mgr.posts('receipt-form');
    expect(pay).toHaveLength(1);   // only the part paid now; the Credit part stays owed
    expect(pay[0]).toMatchObject({ PaidBy: 1, Customer: 'cust-1', ReceivedIn: 'acc-cash', QuantityColumn: true, UnitPriceColumn: true, CustomThemeId: 'theme-1' });
    expect(pay[0].Lines).toEqual([{ Account: 'ar-key', AccountsReceivableSalesInvoice: invKey, Qty: 1, SalesUnitPrice: 10000 }]);
  });

  test('a credit sale without a customer is refused', async () => {
    const r = await createReceipt({ reference: 'INV-CR-2', creditSale: true, lines: [{ qty: 1, unitPrice: 100 }] });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/needs a named customer/);
    expect(mgr.posts('sales-invoice-form')).toHaveLength(0);
  });

  test('the date defaults to today in Uganda time', async () => {
    const spy = jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-08T21:30:00Z'));
    try {
      await createReceipt({ reference: 'R-DATE-1', paymentMethod: 'Cash', lines: [{ qty: 1, unitPrice: 100 }] });
    } finally { spy.mockRestore(); }
    expect(mgr.posts('receipt-form')[0].Date).toBe('2026-10-09');
  });
});

describe('line discounts', () => {
  test('a discounted line reaches Manager as DiscountAmount with the discount column on', async () => {
    const r = await createReceipt({ date: '2026-10-20', reference: 'R-DISC', currency: 'UGX', customer: 'Walk-in Customer',
      lines: [{ itemCode: 'SKU1', itemName: 'Soda 500ml', qty: 2, unitPrice: 1500, discount: 500 }] });
    expect(r.body.success).toBe(true);
    const f = mgr.posts('receipt-form')[0];
    expect(f).toMatchObject({ Discount: true, DiscountType: 'ExactAmount' });
    expect(f.Lines[0]).toMatchObject({ Qty: 2, UnitPrice: 1500, DiscountAmount: 500 });
  });
  test('no discount: no discount column', async () => {
    await createReceipt({ date: '2026-10-20', reference: 'R-NODISC', currency: 'UGX', customer: 'Walk-in Customer', lines: [{ itemCode: 'SKU1', qty: 1, unitPrice: 1500 }] });
    expect(mgr.posts('receipt-form')[0].Discount).toBeUndefined();
  });
});
