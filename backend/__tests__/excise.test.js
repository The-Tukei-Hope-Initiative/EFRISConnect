'use strict';
// Excise duty (Interface Design v24.0.1): the line carries its excise duty code
// (categoryId), rate name, pack and stick; taxDetails gets a 05 row; summary tax
// adds the excise but summary gross leaves the excise row out (URA 1344/1346).
const { loadRelay } = require('./helpers/relay');

let relay, T;
beforeAll(() => { relay = loadRelay(); T = relay.app._test; });
afterAll(() => relay.cleanup());

const cfg = { vatRegistered: true, tin: '1000123456', deviceNo: 'DEV1', businessName: 'Bar Ltd' };
const beer = extra => ({ ItemName: 'Beer 500ml', ItemCode: 'BEER', Qty: 2, UnitPrice: 5900, LineTotal: 11800, TaxName: 'Standard', ExciseFlag: '1', ExciseDutyCode: 'LED090100', ExciseDutyName: 'Beer', ExciseRule: '1', ExciseRate: '0.3', ...extra });
const r2 = n => Math.round(n * 100) / 100;

test('a percentage excise line: code, rate name, tax worked out on the amount before VAT', () => {
  const t = T.buildT109({ Reference: 'X-1', Lines: [beer()] }, cfg);
  const g = t.goodsDetails[0];
  expect(g).toMatchObject({ exciseFlag: '1', categoryId: 'LED090100', categoryName: 'Beer', exciseRule: '1', exciseRate: '0.3', exciseRateName: '30%', pack: '1', stick: '1' });
  const beforeVat = 11800 / 1.18;   // 10,000
  expect(+g.exciseTax).toBeCloseTo(r2(beforeVat * 0.3 / 1.3), 2);
  const vatRow = t.taxDetails.find(x => x.taxCategoryCode === '01');
  const exRow = t.taxDetails.find(x => x.taxCategoryCode === '05');
  expect(exRow).toMatchObject({ taxRate: '0.3', taxRateName: '30%', grossAmount: '10000.00' });
  expect(+exRow.netAmount + +exRow.taxAmount).toBeCloseTo(+exRow.grossAmount, 2);
  expect(+t.summary.taxAmount).toBeCloseTo(+vatRow.taxAmount + +exRow.taxAmount, 2);
  expect(t.summary.grossAmount).toBe('11800.00');
  expect(+t.summary.netAmount).toBeCloseTo(11800 - +t.summary.taxAmount, 2);
});

test('an amount-per-unit excise line names currency, rate and unit', () => {
  const t = T.buildT109({ Reference: 'X-2', Lines: [beer({ ExciseRule: '2', ExciseRate: '650', ExciseUnit: '102', ExciseCurrency: 'UGX' })] }, cfg);
  expect(t.goodsDetails[0]).toMatchObject({ exciseRule: '2', exciseTax: '1300.00', exciseUnit: '102', exciseCurrency: 'UGX', exciseRateName: 'UGX650 per litre' });
  expect(t.taxDetails.find(x => x.taxCategoryCode === '05')).toMatchObject({ exciseUnit: '102', exciseCurrency: 'UGX', taxRateName: 'UGX650 per litre' });
});

test('an excisable line with no excise duty code stops before URA', () => {
  expect(() => T.buildT109({ Reference: 'X-3', Lines: [beer({ ExciseDutyCode: '' })] }, cfg)).toThrow(/has no URA excise duty code/);
});

test('a sale without excise has no 05 row', () => {
  const t = T.buildT109({ Reference: 'X-4', Lines: [{ ItemName: 'Soda', Qty: 1, UnitPrice: 1180, LineTotal: 1180, TaxName: 'Standard' }] }, cfg);
  expect(t.taxDetails.map(x => x.taxCategoryCode)).toEqual(['01']);
});

test('a registered excise good fills the line from T127 and the T125 list', () => {
  const list = [{ exciseDutyCode: 'LED050000', goodService: 'Spirits', exciseDutyDetailsList: [{ type: '102', rate: '2500', unit: '102', currency: '101' }] }];
  expect(T.exciseDutyDetail('LED050000', list)).toEqual({ rule: '2', rate: '2500', unit: '102', currency: 'UGX', name: 'Spirits' });
  const inv = { Lines: [{ ItemCode: 'gin', Qty: 1, UnitPrice: 30000 }] };
  T.annotateLinesWithRegisteredGoods(inv, { GIN: { haveExciseTax: '101', exciseDutyCode: 'LED050000', exciseDutyName: 'Spirits', pack: '1', stick: '1', taxRate: '0.18' } }, list);
  expect(inv.Lines[0]).toMatchObject({ ExciseFlag: '1', ExciseDutyCode: 'LED050000', ExciseRule: '2', ExciseRate: '2500', ExciseUnit: '102', ExciseCurrency: 'UGX' });
});
