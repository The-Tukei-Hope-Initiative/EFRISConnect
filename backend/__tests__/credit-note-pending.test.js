'use strict';
// URA takes one credit note application per invoice at a time.
const { loadRelay } = require('./helpers/relay');

const TIN = '1000123456';
let relay, T;
beforeAll(() => { relay = loadRelay(); T = relay.app._test; });
afterAll(() => relay.cleanup());

const cn = extra => ({ id: 'c' + Math.random(), kind: 'credit-note', status: 'success', originalFdn: 'F100', tin: TIN, reference: 'CN-1',
  submittedAt: new Date().toISOString(), totalAmount: -1000, lines: [], ...extra });

test('a credit note still waiting for URA blocks the next one on that invoice', () => {
  relay.writeJson('submission_log.json', [cn({ fdn: '' })]);
  expect(T.cnPendingProblem('F100', TIN)).toMatch(/CN-1.*still waiting for URA approval/);
  expect(T.cnPendingProblem('F200', TIN)).toBeNull();                    // another invoice
});

test('approved, rejected or cancelled ones do not block', () => {
  for (const extra of [{ fdn: '3260001', approveStatus: '101' }, { approveStatus: '103' }, { approveStatus: '104' }, { cancelled: true }]) {
    relay.writeJson('submission_log.json', [cn(extra)]);
    expect(T.cnPendingProblem('F100', TIN)).toBeNull();
  }
});


test('a debit note is refused before URA when the invoice has a credit note (URA 306)', async () => {
  relay.writeJson('submission_log.json', [cn({ fdn: '' })]);
  const r = await relay.post('/api/efris/debit-note', { originalFDN: 'F100', originalInvoiceId: '99', reasonCode: '101', reason: 'Extra',
    invoice: { Reference: 'DN-1', Lines: [{ ItemName: 'Soda', Qty: 1, UnitPrice: 1500 }] }, config: { tin: TIN, deviceNo: 'D1', mode: 'sandbox' } });
  expect(r.body).toMatchObject({ success: false, limit: true });
  expect(r.body.error).toMatch(/has a credit note \(CN-1\)/);
});

test('a credit note is refused before URA when the invoice has a debit note (URA 317)', () => {
  const dn = { id: 'd1', kind: 'debit-note', status: 'success', originalFdn: 'F100', tin: TIN, reference: 'DN-1', fdn: '3260009' };
  relay.writeJson('submission_log.json', [dn]);
  expect(T.cnPendingProblem('F100', TIN)).toMatch(/has a debit note \(DN-1\)/);
  relay.writeJson('submission_log.json', [{ ...dn, cancelRequested: true }]);
  expect(T.cnPendingProblem('F100', TIN)).toMatch(/cancellation is still waiting/);
  relay.writeJson('submission_log.json', [{ ...dn, cancelled: true }]);
  expect(T.cnPendingProblem('F100', TIN)).toBeNull();
});

test('Z report leaves out a credit note still waiting for URA (no FDN yet)', async () => {
  const day = new Date().toISOString();
  relay.writeJson('submission_log.json', [
    { id: 's1', status: 'success', fdn: '3260001', tin: TIN, submittedAt: day, totalAmount: 769000, currency: 'UGX' },
    cn({ fdn: '', totalAmount: -380000, submittedAt: day }),
  ]);
  const date = new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10);
  const r = await relay.get('/api/z-report?date=' + date);
  expect(r.body).toMatchObject({ success: true, count: 1, credits: 0 });
  expect(r.body.totals[0].gross).toBe(769000);
});
