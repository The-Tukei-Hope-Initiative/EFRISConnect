'use strict';
// Notification centre: log lines become notifications, each business sees only
// its own, permissions filter them, and read / unread is kept per user.
const { loadRelay } = require('./helpers/relay');
const { match } = require('../notifications');

describe('log lines that become notifications', () => {
  test('credit note approved', () => {
    const n = match({ text: '   Credit note 27PL020043752 approved by URA: FDN 326044289251' });
    expect(n).toMatchObject({ kind: 'credit-approved', level: 'success', perm: 'credit' });
    expect(n.body).toContain('326044289251');
  });
  test('queued sales sent, and a rejected one', () => {
    expect(match({ text: '   Offline queue: 1 queued document(s) fiscalised automatically (back online): REC-1 FDN 3260' }))
      .toMatchObject({ kind: 'queue-sent', perm: 'queue' });
    expect(match({ text: '   Offline queue: REC-2 was rejected by URA (URA 1600: shortage)' }))
      .toMatchObject({ kind: 'queue-rejected', level: 'critical' });
  });
  test('an update this relay already runs is not shown', () => {
    const { create } = require('../notifications');
    const day = '2026-10-28';
    const line = { seq: 1, time: day + 'T00:00:00Z', text: '   Update available: EFRISConnect 1.0.23 (security update) - https://github.com/x/releases/tag/v1.0.23' };
    const activity = { eatDay: () => day, listDays: () => [day], entries: () => [line], lastSeq: () => 1 };
    const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'nt-'));
    const reader = { userId: 'u', tenantId: '', mayRead: () => true };
    expect(create({ activity, dataDir: dir, version: '1.0.22' }).list(reader).items).toHaveLength(1);
    expect(create({ activity, dataDir: dir, version: '1.0.23' }).list(reader).items).toHaveLength(0);
    expect(create({ activity, dataDir: dir, version: '1.0.24' }).list(reader).items).toHaveLength(0);
  });
  test('ordinary lines are ignored', () => {
    expect(match({ text: '   New session for TIN: 1000000001' })).toBeNull();
  });
});

describe('notification routes', () => {
  const A = 'note-a', B = 'note-b';
  let relay, tok;
  beforeAll(async () => {
    relay = loadRelay();
    await relay.setupOwner();
    expect((await relay.addTenant(A)).body.success).toBe(true);
    expect((await relay.addTenant(B)).body.success).toBe(true);
    tok = {
      acctA: await relay.addUser('note-acct-a', { [A]: 'accountant' }),
      cashA: await relay.addUser('note-cash-a', { [A]: 'cashier' }),
      cashB: await relay.addUser('note-cash-b', { [B]: 'cashier' }),
    };
    // Events as the relay logs them, tagged with their business.
    relay.app._consoleUi.install(require('path').join(relay.dataDir, 'logs'));
    const { reqCtx } = relay.app._test;
    const log = (tenantId, text) => reqCtx.run({ user: null, tenantId }, () => console.log(text));
    log(A, '   Credit note CN-A1 approved by URA: FDN 111');
    log(A, '   Offline queue: 1 queued document(s) fiscalised automatically: REC-A1 FDN 222');
    log(B, '   Offline queue: 1 queued document(s) fiscalised automatically: REC-B1 FDN 333');
  });
  afterAll(() => relay.cleanup());

  const get = (t, tid, p) => relay.as(t, { 'X-Tenant-Id': tid }).get(p);
  const post = (t, tid, p, b) => relay.as(t, { 'X-Tenant-Id': tid }).post(p, b);

  test('an accountant sees the credit note and the queued sale of their business', async () => {
    const r = await get(tok.acctA, A, '/api/notifications');
    expect(r.status).toBe(200);
    const bodies = r.body.items.map(i => i.body).join(' | ');
    expect(bodies).toContain('CN-A1');
    expect(bodies).toContain('REC-A1');
    expect(bodies).not.toContain('REC-B1');
  });
  test('a cashier does not see credit notes', async () => {
    const r = await get(tok.cashA, A, '/api/notifications');
    const bodies = r.body.items.map(i => i.body).join(' | ');
    expect(bodies).not.toContain('CN-A1');
    expect(bodies).toContain('REC-A1');
  });
  test('another business only sees its own', async () => {
    const r = await get(tok.cashB, B, '/api/notifications');
    const bodies = r.body.items.map(i => i.body).join(' | ');
    expect(bodies).toContain('REC-B1');
    expect(bodies).not.toContain('REC-A1');
    expect((await get(tok.cashB, A, '/api/notifications')).status).toBe(403);
  });
  test('read, unread and read-all, per user', async () => {
    const first = (await get(tok.acctA, A, '/api/notifications')).body;
    expect(first.unread).toBeGreaterThan(0);
    const id = first.items[0].id;
    let r = await post(tok.acctA, A, '/api/notifications/read', { ids: [id], read: true });
    expect(r.body.unread).toBe(first.unread - 1);
    r = await post(tok.acctA, A, '/api/notifications/read', { ids: [id], read: false });
    expect(r.body.unread).toBe(first.unread);
    r = await post(tok.acctA, A, '/api/notifications/read-all', {});
    expect(r.body.unread).toBe(0);
    // Another user of the same business is not affected.
    expect((await get(tok.cashA, A, '/api/notifications/count')).body.unread).toBeGreaterThan(0);
  });
  test('bad ids are refused', async () => {
    expect((await post(tok.acctA, A, '/api/notifications/read', { ids: ['../../x'] })).status).toBe(400);
  });
});
