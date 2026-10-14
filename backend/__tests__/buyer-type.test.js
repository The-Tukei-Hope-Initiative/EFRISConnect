'use strict';
// buyerType on T109: 0 B2B, 1 B2C, 2 Foreigner, 3 B2G.
const { loadRelay } = require('./helpers/relay');

let relay, T;
beforeAll(() => { relay = loadRelay(); T = relay.app._test; });
afterAll(() => relay.cleanup());

const cfg = { vatRegistered: true, tin: '1000123456', deviceNo: 'DEV1', businessName: 'Test Traders Ltd' };
const sale = extra => ({ Reference: 'BT-1', Lines: [{ ItemName: 'Soda', Qty: 1, UnitPrice: 1180, LineTotal: 1180, TaxName: 'Standard' }], ...extra });
const typeOf = (extra, c) => T.buildT109(sale(extra), c || cfg).buyerDetails;

describe('buyerType mapping', () => {
  test('B2B is 0 with the buyer TIN', () => expect(typeOf({ CustomerType: 'b2b', CustomerTIN: '1000000001', CustomerName: 'ABC Ltd' })).toMatchObject({ buyerType: '0', buyerTin: '1000000001' }));
  test('B2C without a TIN is 1', () => expect(typeOf({ CustomerType: 'b2c' })).toMatchObject({ buyerType: '1', buyerTin: '' }));
  test('B2C with a TIN is sent as a taxpayer (0)', () => expect(typeOf({ CustomerType: 'b2c', CustomerTIN: '1000000002' }).buyerType).toBe('0'));
  test('Foreigner is 2 with passport and nationality', () => expect(typeOf({ CustomerType: 'foreign', PassportNum: 'P123', Nationality: 'Kenya' })).toMatchObject({ buyerType: '2', buyerPassportNum: 'P123', buyerTin: '' }));
  test('B2G is 3 with the government TIN', () => expect(typeOf({ CustomerType: 'b2g', CustomerTIN: '1000000003', CustomerName: 'Ministry of Works' })).toMatchObject({ buyerType: '3', buyerTin: '1000000003', buyerLegalName: 'Ministry of Works' }));
  test('a business can switch B2G back to 0 with config b2gBuyerType', () => expect(typeOf({ CustomerType: 'b2g', CustomerTIN: '1000000003' }, { ...cfg, b2gBuyerType: '0' }).buyerType).toBe('0'));
  test('an invalid override is ignored', () => expect(typeOf({ CustomerType: 'b2g' }, { ...cfg, b2gBuyerType: '7' }).buyerType).toBe('3'));
});
