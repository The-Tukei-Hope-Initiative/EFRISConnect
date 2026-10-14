'use strict';
// Offline Mode Enabler, "always" mode: the session is plain (no T104 key
// exchange) and T109 goes to the Enabler as plain base64 JSON, never to URA.
const { loadRelay } = require('./helpers/relay');
const { createFakeUra } = require('./helpers/fakeUra');
const { TIN, efrisConfig, invoice } = require('./helpers/fixtures');

let relay, ura, enabler;
beforeAll(async () => {
  ura = await createFakeUra().start();
  enabler = await createFakeUra({ plain: true }).start();
  relay = loadRelay({ uraUrl: ura.url });
});
afterAll(async () => { await ura.stop(); await enabler.stop(); relay.cleanup(); });

describe('Enabler plain session', () => {
  test('T109 is sent to the Enabler as plain base64 JSON and succeeds', async () => {
    enabler.nextFdn = 'FDN-ENB-1';
    const config = efrisConfig(null, { enablerUrl: enabler.url, enablerMode: 'always', enablerDeviceNo: 'TCS-ENABLER-01' });
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('ENB-001'), config });
    expect(r.body).toMatchObject({ success: true, fdn: 'FDN-ENB-1', viaEnabler: true, deviceNo: 'TCS-ENABLER-01' });

    expect(ura.calls).toHaveLength(0);                 // URA never contacted
    expect(enabler.callsOf('T104')).toHaveLength(0);   // no key exchange with the Enabler
    const t109 = enabler.callsOf('T109');
    expect(t109).toHaveLength(1);
    expect(t109[0].encrypted).toBe(false);
    expect(t109[0].dataDescription).toMatchObject({ encryptCode: '1' });
    expect(t109[0].signature).toBeNull();
    // Plain base64 JSON: the fake decoded it without any key.
    expect(t109[0].body.sellerDetails).toMatchObject({ tin: TIN, referenceNo: 'ENB-001' });
    expect(t109[0].body.basicInformation.deviceNo).toBe('TCS-ENABLER-01');
    expect(t109[0].deviceNo).toBe('TCS-ENABLER-01');

    expect(relay.readJson('submission_log.json')[0]).toMatchObject({ fdn: 'FDN-ENB-1', reference: 'ENB-001', deviceNo: 'TCS-ENABLER-01' });
  });

  test('an internet address as Enabler URL is ignored (falls back to URA)', async () => {
    const config = efrisConfig(ura, { enablerUrl: 'https://enabler.example.com/getInformation', enablerMode: 'always' });
    ura.nextFdn = 'FDN-URA-2';
    const r = await relay.post('/api/efris/submit-invoice', { invoice: invoice('ENB-002'), config });
    expect(r.body).toMatchObject({ success: true, fdn: 'FDN-URA-2', viaEnabler: false });
    expect(ura.callsOf('T109')).toHaveLength(1);
  });
});
