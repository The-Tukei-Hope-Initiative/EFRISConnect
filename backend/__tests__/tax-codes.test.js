'use strict';
// Check / Create (POST /api/manager/ensure-efris-fields) also makes sure Manager
// has one tax code per EFRIS VAT category for a VAT-registered business.
const { loadRelay } = require('./helpers/relay');
const { createFakeManager } = require('./helpers/fakeManager');
const { createFakeUra } = require('./helpers/fakeUra');
const { efrisConfig } = require('./helpers/fixtures');

let relay, mgr, ura;
beforeAll(async () => {
  mgr = await createFakeManager().start();
  ura = await createFakeUra().start();
  relay = loadRelay({ uraUrl: ura.url });
});
afterAll(async () => { await mgr.stop(); await ura.stop(); relay.cleanup(); });
beforeEach(() => {
  mgr.reset();
  mgr.forms = {};
  // Manager's default VAT code, with the shape the new codes must copy.
  mgr.lists['tax-codes'] = [{ key: 'tc-std', name: 'VAT 18%' }];
  mgr.forms['tax-code-form'] = { 'tc-std': { Name: 'VAT 18%', Label: 'VAT', Rates: [18], TaxRateType: 'SingleRate', Account: 'acc-vat' } };
});

const ensure = (extra) => relay.post('/api/manager/ensure-efris-fields', Object.assign({ managerEndpoint: mgr.url, accessToken: 'tok' }, extra || {}));

describe('EFRIS tax codes in Manager', () => {
  test('VAT-registered: creates the missing codes in the existing shape, keeps the existing VAT 18%', async () => {
    const r = await ensure({ vatRegistered: true });
    expect(r.body.taxCodes.vatRegistered).toBe(true);
    expect(r.body.taxCodes.existing).toEqual([{ category: 'standard', name: 'VAT 18%' }]);
    expect(r.body.taxCodes.created.map(x => x.name)).toEqual(['Zero rated 0%', 'Exempt', 'Deemed VAT 18%']);
    const posted = mgr.posts('tax-code-form');
    expect(posted).toHaveLength(3);
    expect(posted[0]).toEqual({ Name: 'Zero rated 0%', Label: 'VAT', Rates: [0], TaxRateType: 'SingleRate', Account: 'acc-vat' });
    expect(posted[1]).toMatchObject({ Name: 'Exempt', Rates: [0] });
    expect(posted[2]).toMatchObject({ Name: 'Deemed VAT 18%', Rates: [18] });
    expect(posted.some(p => p.Name === 'VAT 18%')).toBe(false);
  });

  test('never duplicates: codes matched by name (any wording buildT109 understands)', async () => {
    mgr.lists['tax-codes'] = [{ key: 'tc-std', name: 'Standard VAT' }, { key: 'a', name: 'VAT 0%' }, { key: 'b', name: 'VAT Exempt' }, { key: 'c', name: 'Deemed VAT' }];
    const r = await ensure({ vatRegistered: true });
    expect(r.body.taxCodes.created).toEqual([]);
    expect(r.body.taxCodes.existing.map(x => x.category)).toEqual(['standard', 'zero', 'exempt', 'deemed']);
    expect(mgr.posts('tax-code-form')).toHaveLength(0);
  });

  test('no codes at all: creates all four, VAT 18% included', async () => {
    mgr.lists['tax-codes'] = [];
    const r = await ensure({ vatRegistered: true });
    expect(r.body.taxCodes.created.map(x => x.name)).toEqual(['VAT 18%', 'Zero rated 0%', 'Exempt', 'Deemed VAT 18%']);
    expect(mgr.posts('tax-code-form')[0]).toEqual({ Name: 'VAT 18%', Rates: [18] });
  });

  test('not VAT-registered: no tax codes', async () => {
    const r = await ensure({ vatRegistered: false });
    expect(r.body.taxCodes).toMatchObject({ vatRegistered: false, created: [] });
    expect(r.body.taxCodes.note).toMatch(/Not VAT-registered/);
    expect(mgr.posts('tax-code-form')).toHaveLength(0);
  });

  test('unknown flag: asks URA (T103 tax types list VAT)', async () => {
    const cfg = efrisConfig(ura); delete cfg.vatRegistered;
    const r = await ensure({ config: cfg });
    expect(r.body.taxCodes).toMatchObject({ vatRegistered: true, source: 'URA T103' });
    expect(r.body.taxCodes.created).toHaveLength(3);
  });

  test('unknown and no EFRIS credentials: nothing created, says why', async () => {
    const r = await ensure({});
    expect(r.body.taxCodes.vatRegistered).toBe(null);
    expect(r.body.taxCodes.note).toMatch(/unknown/);
    expect(mgr.posts('tax-code-form')).toHaveLength(0);
  });
});
