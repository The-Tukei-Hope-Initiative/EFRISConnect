'use strict';
// Goods and units: service-or-goods from URA's own list, one-box commodity search
// with tour words, T130 add/modify and piece units, stock lines never "per person".
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, DEVICE, efrisConfig } = require('./helpers/fixtures');

let relay, ura, T;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
  T = relay.app._test;
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });
beforeEach(() => { ura.reset(); ura.on = {}; });

test('service or goods comes from the commodity list, not the segment number', () => {
  expect(T.commodityIsService('96010101')).toBe(true);    // Reimbursements: a service outside 70-94
  expect(T.commodityIsService('90121501')).toBe(true);    // Tour arrangement
  expect(T.commodityIsService('10101501')).toBe(false);   // Cats
  expect(T.commodityIsService('nope')).toBeNull();
});

test('commodity search: tour words find URA wording, results say service or goods', async () => {
  const r = await relay.get('/api/commodity/search?q=safari');
  expect(r.body.some(x => x.commodityCode === '90121501')).toBe(true);
  expect(r.body.find(x => x.commodityCode === '90121501').isService).toBe(true);
  const r2 = await relay.get('/api/commodity/search?q=car hire');
  expect(r2.body.some(x => /rental/i.test(x.commodityName))).toBe(true);
});

describe('T130', () => {
  const reg = (item, extra) => relay.post('/api/efris/register-goods', { ...efrisConfig(ura), item: { code: 'BEER', name: 'Beer', price: 5000, cur: 'UGX', uom: 'Bottle', efrisUom: 'PCE', comCode: '50202201', excise: 'No', ...item }, ...(extra || {}) });

  test('a new good is operationType 101; an update is 102', async () => {
    ura.on.T130 = () => ({ rc: '00', content: [] });
    await reg({});
    await reg({}, { update: true });
    const calls = ura.callsOf('T130').map(c => (Array.isArray(c.body) ? c.body[0] : c.body));
    expect(calls.map(b => b.operationType)).toEqual(['101', '102']);
    expect(calls[0]).toMatchObject({ havePieceUnit: '102', haveOtherUnit: '102', pieceMeasureUnit: '' });
  });

  test('sold by the piece: havePieceUnit 101 with the piece unit, scale and price', async () => {
    ura.on.T130 = () => ({ rc: '00', content: [] });
    await reg({ pieceUnit: 'pce', pieceScaled: '24', piecePrice: '250' });
    const b = ura.callsOf('T130').map(c => (Array.isArray(c.body) ? c.body[0] : c.body))[0];
    expect(b).toMatchObject({ havePieceUnit: '101', pieceMeasureUnit: 'PCE', pieceScaledValue: '24', packageScaledValue: '1', pieceUnitPrice: '250' });
  });

  test('a piece unit without how many pieces is refused before URA', async () => {
    const r = await reg({ pieceUnit: 'PCE' });
    expect(r.body).toMatchObject({ success: false });
    expect(r.body.error).toMatch(/how many pieces/);
    expect(ura.callsOf('T130')).toHaveLength(0);
  });

  test('an excisable good with no excise code is refused before URA', async () => {
    const r = await reg({ excise: 'Yes' });
    expect(r.body.error).toMatch(/excise duty code/);
    expect(ura.callsOf('T130')).toHaveLength(0);
  });
});

test('stock-in uses the registered unit and refuses a line with none', async () => {
  ura.on.T127 = () => ({ rc: '00', content: { records: [{ goodsCode: 'BEER', measureUnit: 'BO', commodityCategoryCode: '50202201' }], page: { pageNo: 1, pageCount: 1 } } });
  ura.on.T131 = () => ({ rc: '00', content: [] });
  const ok = await relay.post('/api/efris/stock-in', { supplierName: 'Brewery', items: [{ goodsCode: 'BEER', quantity: 10, unitPrice: 3000 }], config: efrisConfig(ura) });
  expect(ok.body.success).toBe(true);
  expect(ura.callsOf('T131')[0].body.goodsStockInItem[0].measureUnit).toBe('BO');
  const bad = await relay.post('/api/efris/stock-in', { supplierName: 'Brewery', items: [{ goodsCode: 'UNKNOWN', quantity: 1, unitPrice: 1 }], config: efrisConfig(ura) });
  expect(bad.body.error).toMatch(/No unit of measure is known for UNKNOWN/);
});
