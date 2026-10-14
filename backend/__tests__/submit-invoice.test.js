'use strict';
// POST /api/efris/submit-invoice against a fake URA (T101 -> T104 -> T103 -> T127 -> T109).
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, efrisConfig, invoice } = require('./helpers/fixtures');

let relay, ura;
beforeAll(async () => {
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
});
afterAll(async () => { await ura.stop(); relay.cleanup(); });

describe('submit-invoice (online)', () => {
  test('fiscalises the sale and returns the FDN', async () => {
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('INV-001'), config: efrisConfig(ura) });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ success: true, fdn: 'FDN123', antifakeCode: 'AF1', invoiceId: 'ID1', returnCode: '00', viaEnabler: false });

    // Session handshake, then the encrypted, signed T109.
    expect(ura.codes().slice(0, 3)).toEqual(['T101', 'T104', 'T103']);
    const sent = ura.callsOf('T109');
    expect(sent).toHaveLength(1);
    expect(sent[0].encrypted).toBe(true);
    expect(typeof sent[0].signature).toBe('string');
    const t109 = sent[0].body;
    expect(t109.sellerDetails).toMatchObject({ tin: TIN, referenceNo: 'INV-001', legalName: 'Test Traders Ltd' });
    expect(t109.summary).toMatchObject({ grossAmount: '2360.00', taxAmount: '360.00', netAmount: '2000.00' });
    expect(t109.taxDetails).toEqual([{ taxCategoryCode: '01', netAmount: '2000.00', taxRate: '0.18', taxAmount: '360.00', grossAmount: '2360.00' }]);
  });

  test('writes a submission-log entry', () => {
    const log = relay.readJson('submission_log.json', []);
    expect(log).toHaveLength(1);
    expect(log[0]).toMatchObject({ fdn: 'FDN123', reference: 'INV-001', status: 'success', tin: TIN, returnCode: '00',
      totalAmount: 2360, currency: 'UGX', invoiceKind: '1', invoiceId: 'ID1', mode: 'sandbox' });
    expect(log[0].lines).toEqual([{ name: 'Soda 500ml', code: 'SKU1', qty: 2, unitPrice: 1180, orderNumber: 0 }]);
  });

  test('refuses a reference that was already fiscalised (no second T109)', async () => {
    ura.reset();
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('inv-001'), config: efrisConfig(ura) });
    expect(r.body).toMatchObject({ success: false, duplicateRef: true, existingFdn: 'FDN123' });
    expect(r.body.error).toMatch(/already fiscalised/);
    expect(ura.callsOf('T109')).toHaveLength(0);
  });

  test('a URA business rejection is reported and not logged', async () => {
    ura.t109Error = { rc: '2122', msg: 'Buyer TIN is invalid' };
    try {
      const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('INV-002'), config: efrisConfig(ura) });
      expect(r.body).toEqual({ success: false, error: 'URA 2122: Buyer TIN is invalid', returnCode: '2122' });
      expect(relay.readJson('submission_log.json', []).map(e => e.reference)).toEqual(['INV-001']);
      expect(relay.readJson('offline_queue.json', [])).toEqual([]);
    } finally { ura.t109Error = null; }
  });

  test('a document with no lines is refused before calling URA', async () => {
    ura.reset();
    const r = await relay.post('/api/efris/submit-invoice', { invoice: { Reference: 'EMPTY-1', Lines: [] }, config: efrisConfig(ura) });
    expect(r.body.success).toBe(false);
    expect(r.body.error).toMatch(/no line items/);
    expect(ura.calls).toHaveLength(0);
  });
});
