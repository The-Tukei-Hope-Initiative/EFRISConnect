'use strict';
// Activity log (Settings > Logs): capture with business/user tags, masking,
// route scoping, day validation and live polling.
const fs = require('fs');
const path = require('path');
const { loadRelay } = require('./helpers/relay');

const A = 'biz-a', B = 'biz-b';
let relay, tok, act, logDir;
beforeAll(async () => {
  relay = loadRelay();
  logDir = path.join(relay.dataDir, 'logs');
  act = relay.app._activity;
  relay.app._consoleUi.install(logDir);   // what the real relay does at start
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: '1000000001' })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: '1000000002' })).body.success).toBe(true);
  tok = {
    owner: await relay.login('owner', 'owner-pass-123'),
    adminA: await relay.addUser('admin-a', { [A]: 'admin' }),
    adminB: await relay.addUser('admin-b', { [B]: 'admin' }),
    cashierA: await relay.addUser('cash-a', { [A]: 'cashier' }),
    accountantA: await relay.addUser('acct-a', { [A]: 'accountant' }),
  };
  // One line tagged with each business (printed inside a request), one system line.
  await relay.as(tok.adminA, { 'X-Tenant-Id': A }).post('/api/client-log', { message: 'marker-alpha from A' });
  await relay.as(tok.adminB, { 'X-Tenant-Id': B }).post('/api/client-log', { message: 'marker-bravo from B' });
  console.log('marker-system line');
});
afterAll(() => relay.cleanup());

const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});
const texts = r => (r.body.entries || []).map(e => e.text).join('\n');

describe('capture', () => {
  test('a line printed inside a request is tagged with the business and the user', () => {
    const e = act.entries({}).find(x => /marker-alpha/.test(x.text));
    expect(e).toBeTruthy();
    expect(e).toMatchObject({ tenantId: A, level: 'error', debug: false });
    expect(e.user).toMatch(/admin-a/i);
    expect(typeof e.seq).toBe('number');
    expect(new Date(e.time).toISOString()).toBe(e.time);
    const sys = act.entries({}).find(x => /marker-system/.test(x.text));
    expect(sys.tenantId).toBeUndefined();
    expect(sys.level).toBe('info');
  });

  test('entries are written to the EAT day activity file', () => {
    const f = path.join(logDir, act.eatDay() + '-activity.log');
    const raw = fs.readFileSync(f, 'utf8');
    expect(raw).toMatch(/marker-alpha/);
    JSON.parse(raw.trim().split('\n')[0]);
  });

  test('technical lines are flagged debug and colours are stripped', () => {
    console.log('\x1b[32m   T109 line: item 1\x1b[0m');
    const e = act.entries({}).filter(x => /T109 line: item 1/.test(x.text)).pop();
    expect(e.debug).toBe(true);
    expect(e.text).not.toMatch(/\x1b/);
  });
});

describe('masking', () => {
  const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nabc\n-----END PRIVATE KEY-----';
  const b64 = 'QUJD'.repeat(30);
  test('tokens, passwords, keys and long base64 never reach the store', () => {
    console.log('call with Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456');
    console.log('body {"efrisPassword":"Sup3rSecret!","tin":"100"} and password=hunter22 ok');
    console.log('url https://m.example/api2?apiAccessToken=tok123456789&key=kkkkkk99 and X-API-KEY: svc-key-xyz');
    console.log('loaded key ' + pem + ' done');
    console.log('payload ' + b64 + ' end');
    const all = act.entries({}).map(e => e.text).join('\n');
    expect(all).not.toMatch(/abcdefghijklmnopqrstuvwxyz123456/);
    expect(all).not.toMatch(/Sup3rSecret/);
    expect(all).not.toMatch(/hunter22/);
    expect(all).not.toMatch(/tok123456789/);
    expect(all).not.toMatch(/kkkkkk99/);
    expect(all).not.toMatch(/svc-key-xyz/);
    expect(all).not.toMatch(/MIIEvQIBADANBgkq/);
    expect(all).not.toContain(b64);
    expect(all).toMatch(/Bearer \*\*\*/);
    expect(all).toMatch(/"tin":"100"/);
    expect(all).toMatch(/payload \[120 chars removed\] end/);
    const file = fs.readFileSync(path.join(logDir, act.eatDay() + '-activity.log'), 'utf8');
    expect(file).not.toMatch(/Sup3rSecret|hunter22|MIIEvQIBADANBgkq/);
  });

  test('exact vault secret values are masked once the business has been read', () => {
    act.noteSecrets('zz-vault-secret-77');
    console.log('something printed zz-vault-secret-77 by mistake');
    expect(act.entries({}).map(e => e.text).join('\n')).not.toMatch(/zz-vault-secret-77/);
  });

  test('a logging failure never throws', () => {
    expect(() => act.capture('info', { toString() { throw new Error('x'); } })).not.toThrow();
  });
});

describe('GET /api/admin/activity', () => {
  test('owner sees every business and system lines', async () => {
    const r = await as('owner', A).get('/api/admin/activity');
    expect(r.status).toBe(200);
    expect(r.body.success).toBe(true);
    expect(texts(r)).toMatch(/marker-alpha/);
    expect(texts(r)).toMatch(/marker-bravo/);
    expect(texts(r)).toMatch(/marker-system/);
    expect(r.body.days[0]).toBe(act.eatDay());
    const sys = await as('owner', A).get('/api/admin/activity?tenant=system');
    expect(texts(sys)).toMatch(/marker-system/);
    expect(texts(sys)).not.toMatch(/marker-alpha|marker-bravo/);
    const onlyB = await as('owner', A).get('/api/admin/activity?tenant=' + B);
    expect(texts(onlyB)).toMatch(/marker-bravo/);
    expect(texts(onlyB)).not.toMatch(/marker-alpha|marker-system/);
  });

  test('an admin of A sees A lines only: not B, not system', async () => {
    const r = await as('adminA', A).get('/api/admin/activity');
    expect(r.status).toBe(200);
    expect(texts(r)).toMatch(/marker-alpha/);
    expect(texts(r)).not.toMatch(/marker-bravo/);
    expect(texts(r)).not.toMatch(/marker-system/);
    expect(r.body.entries.every(e => e.tenantId === A)).toBe(true);
    expect((await as('adminA', A).get('/api/admin/activity?tenant=system')).body.entries).toEqual([]);
    expect((await as('adminA', A).get('/api/admin/activity?tenant=' + B)).status).toBe(403);
    expect((await as('adminA', B).get('/api/admin/activity')).status).toBe(403);   // no role in B
  });

  test('cashier and accountant are refused', async () => {
    expect((await as('cashierA', A).get('/api/admin/activity')).status).toBe(403);
    expect((await as('accountantA', A).get('/api/admin/activity')).status).toBe(403);
    expect((await as('cashierA').get('/api/admin/activity')).status).toBe(403);
  });

  test('level, text and debug filters', async () => {
    const err = await as('owner', A).get('/api/admin/activity?level=error');
    expect(err.body.entries.length).toBeGreaterThan(0);
    expect(err.body.entries.every(e => e.level === 'error')).toBe(true);
    const q = await as('owner', A).get('/api/admin/activity?q=MARKER-BRAVO');
    expect(q.body.entries.length).toBe(1);
    expect(texts(await as('owner', A).get('/api/admin/activity'))).not.toMatch(/T109 line: item 1/);
    expect(texts(await as('owner', A).get('/api/admin/activity?debug=1'))).toMatch(/T109 line: item 1/);
    const lim = await as('owner', A).get('/api/admin/activity?limit=2');
    expect(lim.body.entries.length).toBe(2);
    expect(lim.body.truncated).toBe(true);
    expect((await as('owner', A).get('/api/admin/activity?level=bad')).status).toBe(400);
  });

  test('day must be a real YYYY-MM-DD date', async () => {
    for (const d of ['../../vault', '2026-13-01', '2026-02-30', '20261009', '2026-10-09/../x', '2026-10-09-activity']) {
      const r = await as('owner', A).get('/api/admin/activity?day=' + encodeURIComponent(d));
      expect(r.status).toBe(400);
    }
  });

  test('a past day is read from its file, with the same scoping', async () => {
    const day = '2026-01-02';
    const lines = [
      { seq: 1, time: '2026-01-02T08:00:00.000Z', level: 'info', text: 'old-a', debug: false, tenantId: A, user: 'x' },
      { seq: 2, time: '2026-01-02T08:00:01.000Z', level: 'warn', text: 'old-b', debug: false, tenantId: B },
      { seq: 3, time: '2026-01-02T08:00:02.000Z', level: 'info', text: 'old-sys', debug: false },
    ];
    fs.writeFileSync(path.join(logDir, day + '-activity.log'), lines.map(l => JSON.stringify(l)).join('\n') + '\nnot json\n');
    const o = await as('owner', A).get('/api/admin/activity?day=' + day);
    expect(o.body.entries.map(e => e.text)).toEqual(['old-a', 'old-b', 'old-sys']);
    expect(o.body.days).toContain(day);
    const a = await as('adminA', A).get('/api/admin/activity?day=' + day);
    expect(a.body.entries.map(e => e.text)).toEqual(['old-a']);
    const none = await as('owner', A).get('/api/admin/activity?day=2025-05-05');
    expect(none.status).toBe(200);
    expect(none.body.entries).toEqual([]);
  });

  test('after=<seq> returns only newer lines (live polling)', async () => {
    const first = await as('owner', A).get('/api/admin/activity');
    const last = first.body.lastSeq;
    expect(typeof last).toBe('number');
    const empty = await as('owner', A).get('/api/admin/activity?after=' + last);
    expect(empty.body.entries).toEqual([]);
    expect(empty.body.lastSeq).toBe(last);
    console.log('marker-new after poll');
    const next = await as('owner', A).get('/api/admin/activity?after=' + last);
    expect(next.body.entries.map(e => e.text)).toEqual(['marker-new after poll']);
    expect(next.body.lastSeq).toBeGreaterThan(last);
    expect((await as('owner', A).get('/api/admin/activity?after=abc')).status).toBe(400);
  });

  test('the old daily log routes still answer', async () => {
    const r = await as('owner', A).get('/api/admin/logs');
    expect(r.status).toBe(200);
    expect(Array.isArray(r.body.days)).toBe(true);
  });
});
