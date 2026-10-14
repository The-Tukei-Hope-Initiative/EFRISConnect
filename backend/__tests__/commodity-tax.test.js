'use strict';
// POST /api/efris/commodity-tax: URA tax rule of a commodity code (T124, T146 fallback).
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { efrisConfig } = require('./helpers/fixtures');

const CATS = {
  '10151609': { commodityCategoryCode: '10151609', commodityCategoryName: 'Maize seeds', rate: '0', isLeafNode: '101', serviceMark: '102',
    isZeroRate: '102', isExempt: '101', exemptRateStartDate: '01/07/2020', exemptRateEndDate: '', excisable: '102' },
  '50221109': { commodityCategoryCode: '50221109', commodityCategoryName: 'Processed maize flour', rate: '0', isLeafNode: '101', serviceMark: '102',
    isZeroRate: '101', zeroRateStartDate: '01/07/2018', zeroRateEndDate: '', isExempt: '102', excisable: '102' },
  '50202306': { commodityCategoryCode: '50202306', commodityCategoryName: 'Soft drinks', rate: '0.18', isLeafNode: '101', serviceMark: '102',
    isZeroRate: '102', isExempt: '102', excisable: '101' },
  // Exemption that ended: back to the standard rate.
  '51132201': { commodityCategoryCode: '51132201', commodityCategoryName: 'Vitamins', rate: '0.18', isLeafNode: '101', serviceMark: '102',
    isZeroRate: '102', isExempt: '101', exemptRateStartDate: '01/07/2015', exemptRateEndDate: '30/06/2020', excisable: '102' },
};

let relay, ura;
beforeAll(async () => {
  ura = await createFakeUra().start();
  // T124 honours the code filter only for the first three codes; for the last it
  // returns an unrelated first page, so the relay must fall back to T146.
  ura.on.T124 = (call) => {
    const code = call.body && call.body.commodityCategoryCode;
    const recs = code && code !== '51132201' && CATS[code] ? [CATS[code]] : [CATS['50202306']];
    return { content: { page: { pageNo: 1, pageSize: 10, totalSize: recs.length, pageCount: 1 }, records: recs } };
  };
  ura.on.T146 = (call) => {
    const code = call.body && call.body.categoryCode;
    return CATS[code] ? { content: { commodityCategory: [CATS[code]] } } : { rc: '2179', msg: 'categoryCode not found', content: '' };
  };
  relay = loadRelay({ uraUrl: ura.url });
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });

describe('commodity-tax', () => {
  test('returns the VAT rule per code (exempt, zero, standard + excise, expired exemption)', async () => {
    const r = await relay.post('/api/efris/commodity-tax', { codes: ['10151609', '50221109', '50202306', '51132201'], config: efrisConfig(ura) });
    expect(r.body.success).toBe(true);
    const x = r.body.results;
    expect(x['10151609']).toMatchObject({ name: 'Maize seeds', rule: 'exempt', label: 'Exempt', isExempt: true, exemptRateStartDate: '01/07/2020', source: 'T124' });
    expect(x['50221109']).toMatchObject({ rule: 'zero', label: 'Zero-rated 0%', zeroRateStartDate: '01/07/2018' });
    expect(x['50202306']).toMatchObject({ rule: 'standard', rate: 18, excisable: true, label: 'Standard 18% + excise' });
    expect(x['51132201']).toMatchObject({ name: 'Vitamins', rule: 'standard', rate: 18, source: 'T146' });
    const t124 = ura.callsOf('T124');
    expect(t124[0].body).toMatchObject({ commodityCategoryCode: '10151609', pageNo: '1', pageSize: '10' });
    expect(ura.callsOf('T146').map(c => c.body.categoryCode)).toEqual(['51132201']);
  });

  test('answers from the 24 h cache without calling URA again', async () => {
    ura.reset();
    const r = await relay.post('/api/efris/commodity-tax', { codes: ['10151609'], config: efrisConfig(ura) });
    expect(r.body.results['10151609']).toMatchObject({ rule: 'exempt', cached: true });
    expect(ura.codes().filter(c => c === 'T124' || c === 'T146')).toEqual([]);
  });

  test('a code URA does not know comes back as not found, not an error for the request', async () => {
    const r = await relay.post('/api/efris/commodity-tax', { codes: ['99999999'], config: efrisConfig(ura) });
    expect(r.body.success).toBe(true);
    expect(r.body.results['99999999']).toMatchObject({ rule: 'unknown', label: 'Not found at URA' });
    expect(r.body.results['99999999'].error).toMatch(/T146 2179/);
  });

  test('needs codes and credentials', async () => {
    expect((await relay.post('/api/efris/commodity-tax', { config: efrisConfig(ura) })).status).toBe(400);
    expect((await relay.post('/api/efris/commodity-tax', { codes: ['1'] })).status).toBe(400);
  });

  test('a cashier (goods-read) may use it', () => {
    expect(relay.app._test.routePerm('POST', '/efris/commodity-tax')).toBe('goods-read');
  });

  test('rule mapping: deemed flag and rate as a percentage', () => {
    const rule = relay.app._test.commodityTaxRule;
    expect(rule({ commodityCategoryCode: '1', rate: '18', isDeemedVat: '101' }).rule).toBe('deemed');
    expect(rule({ commodityCategoryCode: '1', rate: '0.18', isZeroRate: '101', zeroRateStartDate: '01/01/2099' }).rule).toBe('standard');
  });
});
