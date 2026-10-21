'use strict';
// Manager custom buttons: one per placement, pointing at this EFRISConnect; a
// button already there (same placement and address) is left alone.
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');

let relay, mgr;
beforeAll(async () => { mgr = await createFakeManager().start(); relay = loadRelay(); });
afterAll(async () => { await mgr.stop(); relay.cleanup(); });

const ensure = extensionUrl => relay.post('/api/manager/ensure-custom-buttons', { managerEndpoint: mgr.url, accessToken: 'tk', extensionUrl });

test('adds the missing buttons, keeps the existing one', async () => {
  mgr.lists['custom-buttons'] = [{ key: 'b1' }, { key: 'b2' }];
  mgr.forms['custom-button-form'] = {
    b1: { name: 'Fiscalise receipt', endpoint: 'https://localhost:5443/extension', placement: 'receipt-view' },
    b2: { name: 'Old', endpoint: 'https://localhost:5443/extension', placement: 'reciept-view' },   // a typo: does not count
  };
  const r = await ensure('https://localhost:5443/extension');
  expect(r.body).toMatchObject({ success: true, existed: ['receipt-view'], endpoint: 'https://localhost:5443/extension' });
  expect(r.body.created).toEqual(expect.arrayContaining(['receipt-form', 'sales-invoice-view', 'sales-invoice-form', 'credit-note-view', 'debit-note-view', 'customer-view', 'receipts', 'sales-invoices', 'inventory-items', 'inventory-item-view', 'non-inventory-items', 'non-inventory-item-view']));
  const posted = mgr.posts('custom-button-form');
  expect(posted).toHaveLength(17);
  expect(posted.every(b => b.Endpoint === 'https://localhost:5443/extension' && b.Name && b.Placement)).toBe(true);
});

test('an address that is not EFRISConnect\'s /extension is refused', async () => {
  const r = await ensure('https://evil.example/steal');
  expect(r.status).toBe(400);
});

test('a button at an older EFRISConnect address is moved to the new one, not duplicated', async () => {
  mgr.reset();
  mgr.lists['custom-buttons'] = [{ key: 'b1' }];
  mgr.forms['custom-button-form'] = { b1: { name: 'Fiscalise receipt', endpoint: 'https://localhost:5443/extension', placement: 'receipt-view' } };
  const r = await ensure('https://desktop-1:5443/extension');
  expect(r.body.updated).toEqual(['receipt-view']);
  // The Fiscalise button was moved; the only new one on that page is EFRISConnect.
  expect(mgr.posts('custom-button-form').filter(b => b.Placement === 'receipt-view').map(b => b.Name)).toEqual(['EFRISConnect']);
  const moved = mgr.posts('custom-button-form/b1')[0];
  expect(moved).toMatchObject({ Endpoint: 'https://desktop-1:5443/extension', name: 'Fiscalise receipt', placement: 'receipt-view' });
  expect(moved.endpoint).toBeUndefined();
});

test('a page with two buttons gets both: Fiscalise receipt and EFRISConnect on the receipt view', async () => {
  mgr.reset();
  mgr.lists['custom-buttons'] = [{ key: 'b1' }];
  mgr.forms['custom-button-form'] = { b1: { name: 'Fiscalise receipt', endpoint: 'https://localhost:5443/extension', placement: 'receipt-view' } };
  const r = await ensure('https://localhost:5443/extension');
  const onView = mgr.posts('custom-button-form').filter(b => b.Placement === 'receipt-view');
  expect(onView.map(b => b.Name)).toEqual(['EFRISConnect']);
  expect(r.body.existed).toContain('receipt-view');
});
