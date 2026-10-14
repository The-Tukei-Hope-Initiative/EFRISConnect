'use strict';
// HTTP hardening, API-key protection, error handling and the URA URL test hook.
const request = require('supertest');
const { loadRelay } = require('./helpers/relay');

let relay;
beforeAll(() => { relay = loadRelay(); });
afterAll(() => relay.cleanup());

describe('HTTP headers', () => {
  test('/extension sends a Content-Security-Policy and no X-Powered-By', async () => {
    const r = await request(relay.app).get('/extension');
    expect(r.status).toBe(200);
    const csp = r.headers['content-security-policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toMatch(/frame-ancestors 'self' http:\/\/localhost:\*/);
    expect(csp).toContain("object-src 'none'");
    expect(r.headers['x-powered-by']).toBeUndefined();
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['referrer-policy']).toBe('no-referrer');
  });

  test('a foreign Host header is refused (DNS rebinding)', async () => {
    const r = await request(relay.app).get('/api/health').set('Host', 'evil.example.com');
    expect(r.status).toBe(421);
  });
});

describe('sign-in required and the service key', () => {
  test('/api routes without a session answer 401', async () => {
    const r = await request(relay.app).get('/api/submission-log');
    expect(r.status).toBe(401);
    expect(r.body).toEqual({ success: false, error: 'Sign in required', auth: true });
  });

  test('a made-up bearer token is refused', async () => {
    const r = await request(relay.app).get('/api/submission-log').set('Authorization', 'Bearer ' + 'x'.repeat(43));
    expect(r.status).toBe(401);
  });

  test('a wrong service key is refused, the right one accepted', async () => {
    expect((await request(relay.app).get('/api/submission-log').set('X-API-KEY', 'nope')).status).toBe(401);
    const ok = await relay.get('/api/submission-log');
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ success: true, total: 0 });
  });

  test('/api/health stays public but hides key details', async () => {
    const r = await request(relay.app).get('/api/health');
    expect(r.status).toBe(200);
    expect(Object.keys(r.body.key)).toEqual(['key_parse_ok']);
    const full = await relay.get('/api/health');
    expect(full.body.key).toHaveProperty('key_format');
  });

  test('/api/version stays public', async () => {
    expect((await request(relay.app).get('/api/version')).status).toBe(200);
  });

  test('no page carries the service key or any API key', async () => {
    const { API_KEY } = require('./helpers/relay');
    for (const p of ['/extension', '/', '/some/spa/route']) {
      const r = await request(relay.app).get(p);
      expect(r.text).not.toContain(API_KEY);
      expect(r.text).not.toMatch(/__API_KEYs*=/);
    }
  });
});

describe('network bind check', () => {
  test('loopback needs nothing; a network bind needs ALLOWED_HOSTS and HTTPS or TRUST_PROXY', () => {
    const check = relay.app._test.networkBindProblem;
    expect(check({ bindHost: '127.0.0.1' })).toBe('');
    expect(check({ bindHost: '0.0.0.0', allowedHosts: [], https: true })).toMatch(/ALLOWED_HOSTS/);
    expect(check({ bindHost: '0.0.0.0', allowedHosts: ['efris.lan'], https: false, trustProxy: false })).toMatch(/HTTPS/);
    expect(check({ bindHost: '0.0.0.0', allowedHosts: ['efris.lan'], https: true })).toBe('');
    expect(check({ bindHost: '0.0.0.0', allowedHosts: ['efris.example.org'], trustProxy: true })).toBe('');
  });
});

describe('errors', () => {
  test('a Manager endpoint ending in /api4 answers 400 with an explanation and the relay keeps running', async () => {
    const r = await relay.post('/api/manager/create-receipt', { managerEndpoint: 'http://127.0.0.1:9/api4', accessToken: 'x', receipt: { lines: [] } });
    expect(r.status).toBe(400);
    expect(r.body).toEqual({ success: false, error: 'Manager API v4 endpoints (/api4) are not yet supported. Please use your /api2 endpoint URL instead.' });
    const again = await relay.get('/api/version');
    expect(again.status).toBe(200);
  });

  test('invalid JSON answers 400 without a stack trace', async () => {
    const r = await request(relay.app).post('/api/efris/submit-invoice').set('X-API-KEY', require('./helpers/relay').API_KEY)
      .set('Content-Type', 'application/json').send('{"invoice":');
    expect(r.status).toBe(400);
    expect(r.body).toEqual({ error: 'Invalid JSON body' });
  });
});

describe('EFRIS_URL_OVERRIDE test hook', () => {
  test('replaces the URA URL for both modes when set', () => {
    const T = relay.app._test;
    process.env.EFRIS_URL_OVERRIDE = 'http://127.0.0.1:4555/efrisws/ws/taapp/getInformation';
    expect(T.uraUrl('sandbox')).toBe('http://127.0.0.1:4555/efrisws/ws/taapp/getInformation');
    expect(T.uraUrl('production')).toBe('http://127.0.0.1:4555/efrisws/ws/taapp/getInformation');
    expect(T.uraHost('production')).toBe('http://127.0.0.1:4555/');
  });

  test('has no effect when unset', () => {
    const T = relay.app._test;
    const saved = process.env.EFRIS_URL_OVERRIDE;
    delete process.env.EFRIS_URL_OVERRIDE;
    try {
      expect(T.uraUrl('production')).toBe('https://efrisws.ura.go.ug/ws/taapp/getInformation');
      expect(T.uraUrl('sandbox')).toBe('https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation');
      expect(T.uraUrl(undefined)).toBe('https://efristest.ura.go.ug/efrisws/ws/taapp/getInformation');
      expect(T.uraHost('production')).toBe('https://efrisws.ura.go.ug/');
      expect(T.uraHost('sandbox')).toBe('https://efristest.ura.go.ug/');
    } finally { process.env.EFRIS_URL_OVERRIDE = saved; }
  });
});
