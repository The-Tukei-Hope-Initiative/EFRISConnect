'use strict';
// Shop network (LAN) mode: the launcher sets BIND_HOST=0.0.0.0, ALLOWED_HOSTS
// (hostname, hostname.local, private IPs), LAN_MODE=1 and MANAGER_PORTS. Manager
// Server Edition reached at http://<name or IP>:<port> must be able to frame the
// extension and call the relay; nothing else may. The till kit holds no secrets.
const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const { loadRelay } = require('./helpers/relay');
const tillKit = require('../till-kit');

const HOSTS = 'shop-pc,shop-pc.local,192.168.1.20';

describe('networkBindProblem with the launcher settings', () => {
  let relay;
  beforeAll(() => { relay = loadRelay(); });
  afterAll(() => relay.cleanup());
  test('accepted with ALLOWED_HOSTS and the HTTPS certificate', () => {
    const p = relay.app._test.networkBindProblem;
    expect(p({ bindHost: '0.0.0.0', allowedHosts: HOSTS.split(','), https: true, trustProxy: false })).toBe('');
  });
  test('refused without the certificate (tills would send passwords in clear)', () => {
    const p = relay.app._test.networkBindProblem;
    expect(p({ bindHost: '0.0.0.0', allowedHosts: HOSTS.split(','), https: false, trustProxy: false })).toMatch(/HTTPS/);
    expect(p({ bindHost: '0.0.0.0', allowedHosts: [], https: true })).toMatch(/ALLOWED_HOSTS/);
  });
});

describe('LAN mode: Manager Server origins', () => {
  let relay;
  beforeAll(() => { relay = loadRelay({ env: { LAN_MODE: '1', ALLOWED_HOSTS: HOSTS, MANAGER_PORTS: '5000', MANAGER_ORIGINS: 'https://books.example.com' } }); });
  afterAll(() => relay.cleanup());

  test('frame-ancestors lists http and https on the Manager port for every name and IP', async () => {
    const r = await request(relay.app).get('/api/version');
    const csp = r.headers['content-security-policy'];
    for (const o of ['http://shop-pc:5000', 'https://shop-pc:5000', 'http://shop-pc.local:5000', 'http://192.168.1.20:5000', 'https://192.168.1.20:5000', 'https://books.example.com', 'http://localhost:*'])
      expect(csp).toContain(o);
    expect(csp).not.toContain('shop-pc:5443');
  });

  test('CORS allows the Manager Server origins only', async () => {
    const ok = await request(relay.app).get('/api/version').set('Origin', 'http://shop-pc:5000');
    expect(ok.headers['access-control-allow-origin']).toBe('http://shop-pc:5000');
    const ip = await request(relay.app).get('/api/version').set('Origin', 'http://192.168.1.20:5000');
    expect(ip.headers['access-control-allow-origin']).toBe('http://192.168.1.20:5000');
    const other = await request(relay.app).get('/api/version').set('Origin', 'http://shop-pc:8081');
    expect(other.headers['access-control-allow-origin']).toBeUndefined();
    const evil = await request(relay.app).get('/api/version').set('Origin', 'http://evil.example:5000');
    expect(evil.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('the extension page learns the origins and the LAN button URL (the PC name)', async () => {
    const r = await request(relay.app).get('/extension');
    expect(r.text).toContain('window.__LAN_URL="https://shop-pc:5443/extension"');
    expect(r.text).toContain('"http://shop-pc:5000"');
    expect(relay.app._test.LAN_URLS).toEqual(['https://shop-pc:5443/extension', 'https://shop-pc.local:5443/extension', 'https://192.168.1.20:5443/extension']);
  });

  test('requests that name the PC (Host header) are accepted', async () => {
    const r = await request(relay.app).get('/api/version').set('Host', 'shop-pc.local:5443');
    expect(r.status).toBe(200);
    const bad = await request(relay.app).get('/api/version').set('Host', 'evil.example');
    expect(bad.status).toBe(421);
  });
});

describe('not in LAN mode', () => {
  let relay;
  beforeAll(() => { relay = loadRelay({ env: { ALLOWED_HOSTS: HOSTS } }); });
  afterAll(() => relay.cleanup());
  test('no Manager Server origins and no LAN URL', async () => {
    const r = await request(relay.app).get('/api/version');
    expect(r.headers['content-security-policy']).not.toContain('shop-pc');
    expect(relay.app._test.LAN_URLS).toEqual([]);
    const page = await request(relay.app).get('/extension');
    expect(page.text).toContain('window.__LAN_URL=""');
  });
});

describe('helpers', () => {
  let relay;
  beforeAll(() => { relay = loadRelay(); });
  afterAll(() => relay.cleanup());
  test('managerPorts keeps valid ports only, default 5000', () => {
    const mp = relay.app._test.managerPorts;
    expect(mp('')).toEqual(['5000']);
    expect(mp('5000, 8080,abc,70000')).toEqual(['5000', '8080']);
  });
  test('loopback and 0.0.0.0 are never added as LAN origins', () => {
    expect(relay.app._test.lanManagerOrigins(['localhost', '127.0.0.1', '0.0.0.0', 'pc'], ['5000'])).toEqual(['http://pc:5000', 'https://pc:5000']);
  });
});

describe('till kit', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'efc-kit-')); });
  afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {} });

  test('writes the public certificate, trust/remove scripts and README, and no key or password', () => {
    // What the HTTPS setup leaves in the data folder: the PFX (with its key), its
    // password, and the public certificate.
    fs.writeFileSync(path.join(dir, 'https.pfx'), 'PFX-WITH-PRIVATE-KEY');
    fs.writeFileSync(path.join(dir, 'https_pfx_pass.txt'), 'secret-pfx-password');
    fs.writeFileSync(path.join(dir, 'https_cert.cer'), Buffer.from([0x30, 0x82, 0x01, 0x0a, 1, 2, 3]));
    const kit = tillKit.writeTillKit(dir, { hostname: 'SHOP-PC', urls: ['https://shop-pc:5443/extension', 'https://192.168.1.20:5443/extension'], managerUrls: ['http://shop-pc:5000'] });
    expect(kit.error).toBeUndefined();
    const files = fs.readdirSync(kit.dir).sort();
    expect(files).toEqual(['README.txt', 'Remove EFRISConnect trust.bat', 'Trust EFRISConnect server.bat', 'https_cert.cer']);
    const all = files.map(f => fs.readFileSync(path.join(kit.dir, f)).toString('latin1')).join('\n');
    expect(all).not.toMatch(/PRIVATE KEY|PFX-WITH|secret-pfx-password/);
    const trust = fs.readFileSync(path.join(kit.dir, 'Trust EFRISConnect server.bat'), 'utf8');
    expect(trust).toContain('certutil -addstore -f Root "%~dp0https_cert.cer"');
    expect(trust).toContain('-Verb RunAs');
    expect(trust).toContain('https://shop-pc:5443/extension');
    expect(trust).toMatch(/\r\n/);
    expect(fs.readFileSync(path.join(kit.dir, 'Remove EFRISConnect trust.bat'), 'utf8')).toContain('certutil -delstore Root');
    const readme = fs.readFileSync(path.join(kit.dir, 'README.txt'), 'utf8');
    expect(readme).toContain('https://192.168.1.20:5443/extension');
    expect(readme).toContain('http://shop-pc:5000');
  });

  test('refuses a certificate file that carries a private key, and needs a certificate', () => {
    fs.writeFileSync(path.join(dir, 'https_cert.pem'), '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n');
    const kit = tillKit.writeTillKit(dir, { urls: [] });
    expect(kit.error).toMatch(/HTTPS setup/);
    expect(fs.existsSync(path.join(dir, 'till-kit'))).toBe(false);
  });

  test('removes key material dropped into the kit folder', () => {
    fs.writeFileSync(path.join(dir, 'https_cert.cer'), Buffer.from([0x30, 1]));
    fs.mkdirSync(path.join(dir, 'till-kit'));
    fs.writeFileSync(path.join(dir, 'till-kit', 'https.pfx'), 'x');
    tillKit.writeTillKit(dir, { urls: [] });
    expect(fs.existsSync(path.join(dir, 'till-kit', 'https.pfx'))).toBe(false);
  });
});
