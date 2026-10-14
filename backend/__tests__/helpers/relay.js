'use strict';
// Loads server.js in isolation for one test file: a fresh temp data folder, a
// fixed vault key and service key (INTERNAL_API_KEY, sent as X-API-KEY: the
// "service" principal, a full admin), and URA pointed at a local fake (or at a
// dead loopback port when the file does not need URA).
//
// Signed-in users: relay.setupOwner() / relay.addUser() / relay.login() return a
// session token; relay.as(token) sends requests with Authorization: Bearer.
//
// "Another computer": supertest always connects over loopback. The relay treats a
// request carrying X-Forwarded-For as NOT local (a proxy on this machine forwarded
// it), so tests send X-Forwarded-For to act as a remote client. The same header
// also gives each simulated client its own rate-limit bucket (trust proxy is
// 'loopback').
const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

const API_KEY = 'test-internal-api-key-0123456789abcdef';
const VAULT_MASTER_KEY = Buffer.alloc(32, 7).toString('base64');
// Nothing listens on port 9 (discard) on loopback: any URA call fails fast.
const DEAD_URA = 'http://127.0.0.1:9/efrisws/ws/taapp/getInformation';

// Environment that would change how the relay loads (real keys, other data
// folders, network binds). Cleared so a developer's shell cannot leak in.
const CLEAR = ['VAULT_DIR', 'EFRIS_PRIVATE_KEY_B64', 'EFRIS_PRIVATE_KEY', 'BIND_HOST', 'ALLOWED_HOSTS', 'ALLOWED_ORIGINS',
  'TRUST_PROXY', 'MANAGER_INSECURE_TLS', 'CLOUDFLARE_SKIP_SECRET', 'ALLOWED_ENABLER_HOSTS', 'PORT', 'HTTPS_PORT', 'LAN_MODE', 'MANAGER_PORTS', 'MANAGER_ORIGINS'];

let _ip = 0;
const nextIp = () => '198.51.100.' + ((++_ip % 250) + 1);

function loadRelay(opts = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'efrisconnect-test-'));
  for (const k of CLEAR) delete process.env[k];
  process.env.DATA_DIR_OVERRIDE = dataDir;
  process.env.LOG_DIR_OVERRIDE = path.join(dataDir, 'logs');
  process.env.VAULT_MASTER_KEY = VAULT_MASTER_KEY;
  process.env.INTERNAL_API_KEY = API_KEY;
  process.env.EFRIS_URL_OVERRIDE = opts.uraUrl || DEAD_URA;
  // Extra environment for this load only (e.g. LAN mode); cleared again by the next load.
  for (const [k, v] of Object.entries(opts.env || {})) process.env[k] = v;
  let app;
  jest.isolateModules(() => { app = require('../../server'); });

  const api = {
    app, dataDir,
    get: (p) => request(app).get(p).set('X-API-KEY', API_KEY),
    post: (p, body, headers) => {
      const r = request(app).post(p).set('X-API-KEY', API_KEY);
      for (const [k, v] of Object.entries(headers || {})) r.set(k, v);
      return r.send(body || {});
    },
    file: (name) => path.join(dataDir, name),
    // Requests as a signed-in user. headers: extra headers for every request.
    as: (token, headers) => {
      const h = Object.assign({ Authorization: 'Bearer ' + token }, headers || {});
      const wrap = r => { for (const [k, v] of Object.entries(h)) r.set(k, v); return r; };
      return {
        get: (p) => wrap(request(app).get(p)),
        delete: (p) => wrap(request(app).delete(p)),
        post: (p, body) => wrap(request(app).post(p)).send(body || {}),
        put: (p, body) => wrap(request(app).put(p)).send(body || {}),
      };
    },
    // Create the owner from "this PC" (loopback, no setup code). Returns the token.
    setupOwner: async (name = 'owner', password = 'owner-pass-123') => {
      const r = await request(app).post('/api/auth/setup').send({ name, password });
      if (!r.body.success) throw new Error('setup failed: ' + JSON.stringify(r.body));
      return r.body.token;
    },
    login: async (name, password, extra) => {
      const r = await request(app).post('/api/auth/login').set('X-Forwarded-For', nextIp()).send(Object.assign({ name, password }, extra || {}));
      if (!r.body.success) throw new Error('login failed: ' + JSON.stringify(r.body));
      return r.body.token;
    },
    // Add a user through the service principal and sign them in. roles: { tenantId: role }.
    addUser: async (name, roles, password = 'user-pass-123') => {
      const r = await request(app).post('/api/auth/users').set('X-API-KEY', API_KEY).send({ name, password, roles });
      if (!r.body.success) throw new Error('addUser failed: ' + JSON.stringify(r.body));
      return api.login(name, password);
    },
    // A vault business, created through the service principal.
    addTenant: (id, extra) => request(app).post('/api/tenant').set('X-API-KEY', API_KEY).send(Object.assign({ id, tin: '100' + id.length + '000000', deviceNo: 'D1', mode: 'sandbox' }, extra || {})),
    readJson: (name, dflt) => { try { return JSON.parse(fs.readFileSync(path.join(dataDir, name), 'utf8')); } catch (_) { return dflt; } },
    writeJson: (name, v) => fs.writeFileSync(path.join(dataDir, name), JSON.stringify(v, null, 2)),
    cleanup: () => { try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch (_) {} },
  };
  return api;
}

module.exports = { loadRelay, API_KEY };
