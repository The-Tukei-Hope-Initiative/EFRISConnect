'use strict';
// Shared test data.
const TIN = '1000123456';
const DEVICE = '1000123456_01';

function efrisConfig(fakeUra, extra) {
  return {
    tin: TIN, deviceNo: DEVICE, efrisPassword: 'test-pw', mode: 'sandbox', vatRegistered: true,
    businessName: 'Test Traders Ltd', businessAddress: 'Plot 1, Kampala',
    efrisKeyPem: fakeUra ? fakeUra.privateKeyPem : '',
    ...(extra || {}),
  };
}

// One standard-rated line: 2 x 1,180 = 2,360 (VAT 360 inclusive).
function invoice(reference, extra) {
  return {
    Reference: reference, CustomerName: 'Walk-in Customer', Currency: 'UGX',
    Lines: [{ ItemName: 'Soda 500ml', ItemCode: 'SKU1', Qty: 2, UnitPrice: 1180, LineTotal: 2360, TaxName: 'Standard VAT 18%' }],
    ...(extra || {}),
  };
}

module.exports = { TIN, DEVICE, efrisConfig, invoice };
