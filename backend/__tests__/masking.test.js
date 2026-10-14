'use strict';
// Activity-log masking: secret-looking names in every form (JSON, escaped JSON,
// k=v, k: v, URL-encoded), credential headers whatever the scheme, PEM blocks,
// long base64, and exact known secrets in their escaped and encoded forms.
// Secrets are learned from request bodies and from the vault before logging.
const path = require('path');
const { loadRelay } = require('./helpers/relay');

let relay, act;
beforeAll(async () => {
  relay = loadRelay();
  act = relay.app._activity;
  relay.app._consoleUi.install(path.join(relay.dataDir, 'logs'));
});
afterAll(() => relay.cleanup());

const m = s => act.mask(s);

describe('activity.mask', () => {
  test('names containing token / key / pem / pwd / pass* / secret, in JSON', () => {
    const out = m('{"managerToken":"mt-123456","aesKey":"aes-999","privateKey":"pk-1","efrisKeyPem":"pem-x","pwd":"p1","efrisPassphrase":"pp","clientSecret":"cs","tin":"100"}');
    for (const v of ['mt-123456', 'aes-999', 'pk-1', 'pem-x', '"p1"', '"pp"', '"cs"']) expect(out).not.toContain(v);
    expect(out).toContain('"tin":"100"');
  });

  test('k=v and k: v forms, single-quoted object literals', () => {
    const out = m("managerToken=abc123&ep=http://x aesKey: zzz999 pwd: hunter2 cfg { efrisPassword: 'xx-secret' }");
    expect(out).not.toMatch(/abc123|zzz999|hunter2|xx-secret/);
    expect(out).toContain('ep=http://x');
  });

  test('escaped JSON inside a string', () => {
    const out = m('payload "{\\"password\\":\\"inner-secret\\",\\"tin\\":\\"1\\"}"');
    expect(out).not.toContain('inner-secret');
    expect(out).toContain('\\"tin\\":\\"1\\"');
  });

  test('URL-encoded k=v and JSON', () => {
    const out = m('form password%3Dsecret99%26x%3D1 json %22managerToken%22%3A%22enc-secret%22');
    expect(out).not.toMatch(/secret99|enc-secret/);
    expect(out).toContain('%26x%3D1');
  });

  test('credential headers are masked whatever the scheme', () => {
    const out = m('Authorization: Token abc123def X-API-KEY: rawkey123 X-Manager-Token: t0ken99 Authorization: rawvalue77 Authorization: Basic dXNlcjpwYXNz "authorization":"Digest d1g3st"');
    expect(out).not.toMatch(/abc123def|rawkey123|t0ken99|rawvalue77|dXNlcjpwYXNz|d1g3st/);
    expect(out).toMatch(/Authorization: Token \*\*\*/);
  });

  test('PEM blocks and long base64 runs', () => {
    const out = m('k -----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34\n-----END RSA PRIVATE KEY----- b ' + 'QUJD'.repeat(20));
    expect(out).not.toMatch(/MIIBOgIBAAJBAKj34|QUJDQUJD/);
  });

  test('known secrets also in their JSON-escaped and URL-encoded forms', () => {
    act.noteSecrets('my vault "secret" & more');
    const out = m('a my vault \\"secret\\" & more b my%20vault%20%22secret%22%20%26%20more c my+vault+%22secret%22+%26+more');
    expect(out).not.toMatch(/vault/);
  });

  test('a Manager record key stays readable', () => {
    expect(m('Created Manager receipt → key: 019f1234-aaaa')).toBe('Created Manager receipt → key: 019f1234-aaaa');
    expect(m('record key: 019fabcd')).toBe('record key: 019fabcd');
    expect(m('top-level keys: a, b')).toBe('top-level keys: a, b');
  });
});

describe('secrets are learned before anything is logged', () => {
  test('from a request body', async () => {
    await relay.post('/api/manager/customers', { config: { efrisPassword: 'Body-Learned-77x' }, managerEndpoint: 'http://127.0.0.1:9', accessToken: 'tok-learned-88y' });
    console.log('oops raw Body-Learned-77x and tok-learned-88y');
    const all = act.entries({}).map(e => e.text).join('\n');
    expect(all).toMatch(/oops raw/);
    expect(all).not.toMatch(/Body-Learned-77x|tok-learned-88y/);
  });

  test('from every business in the vault, once unlocked', () => {
    relay.app._vault.putTenant('learn-biz', { tin: '1000000999', managerToken: 'vault-only-token-55z', efrisPassword: 'vault-pw-66q' });
    relay.app._test.learnVaultSecrets();
    expect(m('x vault-only-token-55z y vault-pw-66q')).toBe('x *** y ***');
  });

  test('the error log file is masked too', async () => {
    await relay.post('/api/client-log', { message: 'client said password=cl1ent-pw and {"managerToken":"cl1ent-tok"}' });
    const fs = require('fs');
    const day = new Date().toISOString().slice(0, 10);
    const raw = fs.readFileSync(path.join(relay.dataDir, 'logs', day + '.log'), 'utf8');
    expect(raw).toMatch(/client said/);
    expect(raw).not.toMatch(/cl1ent-pw|cl1ent-tok/);
  });
});
