'use strict';
// Business setup (profile) on the relay: any role in a business reads it, only an
// admin writes it, other businesses are refused, and secrets never come back.
const { loadRelay } = require('./helpers/relay');

const A = 'prof-a', B = 'prof-b';
const PEM = '-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----';
let relay, tok;
beforeAll(async () => {
  relay = loadRelay();
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000011', efrisPassword: 'ura-secret-pass', efrisPrivateKeyPem: PEM, efrisPassphrase: 'pem-pass' })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: '1000000022' })).body.success).toBe(true);
  tok = {
    adminA: await relay.addUser('admin-a', { [A]: 'admin' }),
    cashierA: await relay.addUser('cash-a', { [A]: 'cashier' }),
    cashierB: await relay.addUser('cash-b', { [B]: 'cashier' }),
  };
});
afterAll(() => relay.cleanup());

const profile = (extra) => Object.assign({
  tenantId: A, legalName: 'Alpha Ltd', tradeName: 'Alpha', tin: '1000000011', deviceNo: 'D1', managerEndpoint: 'http://127.0.0.1:55667',
  sandbox: true, vatReg: true, efrisEnabled: true, mgrBusiness: 'Alpha Books', receiptPrefs: { width: 80 }, fxApiKey: 'fx-key',
  efrisPassword: 'leaked-pass', efrisKeyPem: PEM, efrisKeyPassphrase: 'leaked-phrase', accessToken: '__vault__',
  profileUpdatedAt: '2026-10-14T08:00:00.000Z',
}, extra || {});

describe('business profile', () => {
  test('a business without a saved profile gets one built from its vault record', async () => {
    const r = await relay.as(tok.cashierA).get('/api/tenant/' + A + '/profile');
    expect(r.status).toBe(200);
    expect(r.body.derived).toBe(true);
    expect(r.body.profile.tin).toBe('1000000011');
    expect(r.body.profile.efrisPassword).toBe('__vault__');
  });

  test('admin saves the profile; secrets are dropped before storing', async () => {
    const r = await relay.as(tok.adminA).post('/api/tenant', { id: A, profile: profile() });
    expect(r.body.success).toBe(true);
    const raw = JSON.stringify(relay.readJson('credentials_vault.json')[A].profile);
    expect(raw).not.toMatch(/leaked|BEGIN PRIVATE|__vault__/);
    expect(raw).toContain('Alpha Books');
  });

  test('round trip: the cashier of that business reads it, with placeholders only', async () => {
    const r = await relay.as(tok.cashierA).get('/api/tenant/' + A + '/profile');
    expect(r.status).toBe(200);
    expect(r.body.derived).toBe(false);
    expect(r.body.mgrBusiness).toBe('Alpha Books');
    const p = r.body.profile;
    expect(p).toMatchObject({ tenantId: A, legalName: 'Alpha Ltd', tradeName: 'Alpha', vatReg: true, receiptPrefs: { width: 80 }, fxApiKey: 'fx-key' });
    expect(p.efrisPassword).toBe('__vault__');
    expect(p.efrisKeyPem).toBe('__vault__');
    expect(p.efrisKeyPassphrase).toBe('__vault__');
    expect(p.accessToken).toBe('');   // no Manager token in the vault
    const text = JSON.stringify(r.body);
    expect(text).not.toMatch(/ura-secret-pass|pem-pass|leaked|BEGIN PRIVATE/);
  });

  test('another business is refused', async () => {
    expect((await relay.as(tok.cashierB).get('/api/tenant/' + A + '/profile')).status).toBe(403);
    expect((await relay.as(tok.adminA).get('/api/tenant/' + B + '/profile')).status).toBe(403);
    expect((await relay.as(tok.adminA).post('/api/tenant', { id: B, profile: profile({ tenantId: B }) })).status).toBe(403);
  });

  test('a cashier cannot write the profile', async () => {
    const r = await relay.as(tok.cashierA).post('/api/tenant', { id: A, profile: profile({ tradeName: 'Hacked', profileUpdatedAt: '2030-01-01T00:00:00.000Z' }) });
    expect(r.status).toBe(403);
    expect(relay.readJson('credentials_vault.json')[A].profile.tradeName).toBe('Alpha');
  });

  test('newest wins: an older copy is refused with the relay copy', async () => {
    const old = await relay.as(tok.adminA).post('/api/tenant', { id: A, profile: profile({ tradeName: 'Old', profileUpdatedAt: '2026-10-01T00:00:00.000Z' }) });
    expect(old.status).toBe(409);
    expect(old.body.profile.tradeName).toBe('Alpha');
    expect(old.body.profile.efrisPassword).toBe('__vault__');
    const nu = await relay.as(tok.adminA).post('/api/tenant', { id: A, profile: profile({ tradeName: 'Alpha 2', profileUpdatedAt: '2026-10-15T00:00:00.000Z' }) });
    expect(nu.body.success).toBe(true);
    expect((await relay.as(tok.cashierA).get('/api/tenant/' + A + '/profile')).body.profile.tradeName).toBe('Alpha 2');
  });

  test('a profile save keeps the saved secrets and VAT flag', async () => {
    const t = relay.readJson('credentials_vault.json')[A];
    expect(t.efrisPassword).toMatch(/^v1:/);
    const list = (await relay.as(tok.adminA).get('/api/tenant')).body.tenants;
    expect(list.find(x => x.id === A)).toMatchObject({ hasEfrisPassword: true, hasEfrisKey: true });
  });

  test('a profile is never listed with the businesses (only its timestamp)', async () => {
    const r = await relay.as(tok.adminA).get('/api/tenant');
    const a = r.body.tenants.find(x => x.id === A);
    expect(a.profile).toBeUndefined();
    expect(a.profileUpdatedAt).toBe('2026-10-15T00:00:00.000Z');
  });
});
