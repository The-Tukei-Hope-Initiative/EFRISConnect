'use strict';
// Branches (T138), the end-of-day check (T117), export invoices (102/112) and
// the verification URL from URA's login (T103 qrCodeURL).
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
// URA's login answer (with its verification URL) for every session in this file.
const T103 = call => ({ rc: '00', content: { taxpayer: { tin: call.tin }, taxType: [], qrCodeURL: 'https://efristest.ura.go.ug/site_new/#/verifyNew', isAllowBackDate: '0', dictionaryVersion: '7' } });
beforeEach(() => { ura.reset(); ura.on = { T103 }; });

describe('branches', () => {
  test('URA branches are listed, and the chosen one goes on every sale', async () => {
    ura.on.T138 = () => ({ rc: '00', content: [{ branchId: '206637525568955296', branchName: 'Kampala' }, { branchId: '206637528324276772', branchName: 'Jinja' }] });
    const r = await relay.post('/api/efris/branches', { config: efrisConfig(ura) });
    expect(r.body.branches.map(b => b.branchName)).toEqual(['Kampala', 'Jinja']);
    expect(T.buildT109(invoice('B-1'), cfg).sellerDetails.branchId).toBeUndefined();
    const s = await relay.post('/api/efris/branch', { tin: TIN, branchId: '206637528324276772', branchName: 'Jinja' });
    expect(s.body.success).toBe(true);
    expect(T.buildT109(invoice('B-2'), cfg).sellerDetails.branchId).toBe('206637528324276772');
    await relay.post('/api/efris/branch', { tin: TIN, branchId: '' });
    expect(T.buildT109(invoice('B-3'), cfg).sellerDetails.branchId).toBeUndefined();
  });
  test('a branch id that is not a number is refused', async () => {
    const s = await relay.post('/api/efris/branch', { tin: TIN, branchId: '../x' });
    expect(s.body.success).toBe(false);
  });
});

test('end-of-day check sends the day\'s FDNs with their kinds and reports what URA lacks', async () => {
  const now = new Date().toISOString();
  relay.writeJson('submission_log.json', [
    { id: '1', status: 'success', fdn: 'F1', tin: TIN, submittedAt: now, reference: 'R-1' },
    { id: '2', status: 'success', fdn: 'C1', tin: TIN, submittedAt: now, kind: 'credit-note', reference: 'CN-1' },
    { id: '3', status: 'success', fdn: 'OLD', tin: TIN, submittedAt: '2020-01-01T09:00:00Z' },
  ]);
  ura.on.T117 = () => ({ rc: '00', content: [{ invoiceNo: 'C1', invoiceType: '2' }] });
  const r = await relay.post('/api/efris/check-day', { config: efrisConfig(ura) });
  expect(ura.callsOf('T117')[0].body).toEqual([{ invoiceNo: 'F1', invoiceType: '1' }, { invoiceNo: 'C1', invoiceType: '2' }]);
  expect(r.body).toMatchObject({ success: true, checked: 2, mismatches: [{ invoiceNo: 'C1', reference: 'CN-1' }] });
});

describe('export invoices', () => {
  const foreign = extra => ({ ...invoice('EX-1'), CustomerType: 'foreign', CustomerName: 'Hans', PassportNum: 'P1', Nationality: 'Germany', ...extra });
  test('export of goods: industry 102, delivery terms, zero-rated, weight and piece unit on lines', () => {
    const t = T.buildT109(foreign({ ExportType: 'goods', DeliveryTerms: 'fob', Lines: [{ ItemName: 'Coffee', Qty: 10, UnitPrice: 1000, LineTotal: 10000, TaxName: 'Standard', TotalWeight: '5', EFRISUnitOfMeasure: 'KGM' }] }), cfg);
    expect(t.basicInformation.invoiceIndustryCode).toBe('102');
    expect(t.buyerDetails.deliveryTermsCode).toBe('FOB');
    expect(t.goodsDetails[0]).toMatchObject({ taxRate: '0', tax: '0', totalWeight: '5', pieceQty: '10', exciseFlag: '2' });
    expect(t.taxDetails.map(x => x.taxCategoryCode)).toEqual(['02']);
  });
  test('export of goods without delivery terms or weight stops before URA', () => {
    expect(() => T.buildT109(foreign({ ExportType: 'goods' }), cfg)).toThrow(/delivery terms/);
    expect(() => T.buildT109(foreign({ ExportType: 'goods', DeliveryTerms: 'CIF' }), cfg)).toThrow(/weight of every line/);
  });
  test('export of services: industry 112 and zero-rated', () => {
    const t = T.buildT109(foreign({ ExportType: 'service' }), cfg);
    expect(t.basicInformation.invoiceIndustryCode).toBe('112');
    expect(t.goodsDetails[0].taxRate).toBe('0');
  });
  test('a normal sale stays industry 101', () => expect(T.buildT109(invoice('N-1'), cfg).basicInformation.invoiceIndustryCode).toBe('101'));
});

test('the verification link uses the qrCodeURL from URA\'s login once known', async () => {
  const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('QR-1'), config: efrisConfig(ura) });
  expect(r.body.success).toBe(true);
  expect(r.body.validationUrl).toMatch(/^https:\/\/efristest\.ura\.go\.ug\/site_new\/#\/verifyNew\?invoiceNo=/);
  const f = await relay.get('/api/efris/login-flags?tin=' + TIN);
  expect(f.body.flags).toMatchObject({ isAllowBackDate: '0', dictionaryVersion: '7' });
});
