'use strict';
// Settings > Logs > Export: log retention, date-range export and the support bundle.
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { loadRelay } = require('./helpers/relay');

const A = 'biz-a', B = 'biz-b';
const TIN_A = '1000000001', TIN_B = '1000000002';
const VAULT_SECRET = 'VaultPlanted-Secret-4242';
const PLANTED = ['PlantedPw-778899', 'plantedtoken9876543210', 'planted-mgr-tok-5555', VAULT_SECRET];
const DAYS = ['2026-03-01', '2026-03-02', '2026-03-03'];
let relay, tok, logDir, logTools;

// Activity lines for a past day, written straight to its file (raw, unmasked).
function writeActivity(day, lines) {
  fs.writeFileSync(path.join(logDir, day + '-activity.log'), lines.map((l, i) => JSON.stringify(Object.assign({ seq: i + 1, time: day + 'T0' + (i % 9) + ':00:00.000Z', level: 'info', debug: false }, l))).join('\n') + '\n');
}

beforeAll(async () => {
  relay = loadRelay();
  logDir = path.join(relay.dataDir, 'logs');
  logTools = require('../log-tools');
  await relay.setupOwner();
  expect((await relay.addTenant(A, { tin: TIN_A, businessName: 'Alpha Shop', efrisPassword: VAULT_SECRET, enablerUrl: 'http://localhost:9880/efrisws/ws/taapp/getInformation', enablerMode: 'fallback' })).body.success).toBe(true);
  expect((await relay.addTenant(B, { tin: TIN_B, businessName: 'Bravo Store', mode: 'production' })).body.success).toBe(true);
  tok = {
    owner: await relay.login('owner', 'owner-pass-123'),
    adminA: await relay.addUser('admin-a', { [A]: 'admin' }),
    cashierA: await relay.addUser('cash-a', { [A]: 'cashier' }),
    accountantA: await relay.addUser('acct-a', { [A]: 'accountant' }),
  };
  writeActivity(DAYS[0], [
    { text: 'd1-alpha sale', tenantId: A, user: 'admin-a' },
    { text: 'd1-bravo sale TIN ' + TIN_B, tenantId: B },
    { text: 'd1-system start' },
  ]);
  writeActivity(DAYS[1], [
    { text: 'd2-alpha error password=' + PLANTED[0], tenantId: A, level: 'error' },
    { text: 'd2-alpha call Authorization: Bearer ' + PLANTED[1], tenantId: A, level: 'warn' },
    { text: 'd2-alpha leaked ' + VAULT_SECRET + ' and other TIN ' + TIN_B, tenantId: A },
    { text: '   T109 line: d2-alpha technical', tenantId: A, debug: true },
    { text: 'd2-bravo error', tenantId: B, level: 'error' },
  ]);
  writeActivity(DAYS[2], [
    { text: 'd3-alpha "quoted", comma', tenantId: A },
    { text: 'd3-system ?apiAccessToken=' + PLANTED[2] },
  ]);
  // The structured error log (logger.js): one tagged A, one tagged B, one untagged.
  fs.writeFileSync(path.join(logDir, DAYS[1] + '.log'), [
    { time: DAYS[1] + 'T08:00:00.000Z', level: 'error', message: 'err-alpha token=' + PLANTED[1], tenantId: A, meta: { efrisPassword: PLANTED[0], note: 'x ' + VAULT_SECRET } },
    { time: DAYS[1] + 'T08:00:01.000Z', level: 'error', message: 'err-bravo', tenantId: B },
    { time: DAYS[1] + 'T08:00:02.000Z', level: 'error', message: 'err-system', meta: { managerToken: PLANTED[2] } },
  ].map(e => JSON.stringify(e)).join('\n') + '\n');
});
afterAll(() => relay.cleanup());

const as = (who, tenant) => relay.as(tok[who], tenant ? { 'X-Tenant-Id': tenant } : {});
const binary = r => r.buffer(true).parse((res, cb) => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => cb(null, Buffer.concat(c))); });
const exportUrl = (from, to, extra) => '/api/admin/activity/export?from=' + from + '&to=' + to + (extra || '');

// ── Minimal zip reader: end record -> central directory -> local headers ──
const CRC = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = b => { let c = 0xFFFFFFFF; for (const x of b) c = CRC[(c ^ x) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
function unzip(buf) {
  let eo = buf.length - 22;
  while (eo >= 0 && buf.readUInt32LE(eo) !== 0x06054b50) eo--;
  if (eo < 0) throw new Error('no end of central directory');
  const count = buf.readUInt16LE(eo + 10), cdSize = buf.readUInt32LE(eo + 12), cdOff = buf.readUInt32LE(eo + 16);
  expect(cdOff + cdSize).toBe(eo);
  const out = {};
  let p = cdOff;
  for (let i = 0; i < count; i++) {
    expect(buf.readUInt32LE(p)).toBe(0x02014b50);
    const method = buf.readUInt16LE(p + 10), crc = buf.readUInt32LE(p + 16), csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32), loff = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nlen).toString('utf8');
    expect(buf.readUInt32LE(loff)).toBe(0x04034b50);
    const start = loff + 30 + buf.readUInt16LE(loff + 26) + buf.readUInt16LE(loff + 28);
    const raw = buf.slice(start, start + csize);
    const data = method === 8 ? zlib.inflateRawSync(raw) : method === 0 ? raw : null;
    expect(data).not.toBeNull();
    expect(data.length).toBe(usize);
    expect(crc32(data)).toBe(crc);
    out[name] = data.toString('utf8');
    p += 46 + nlen + xlen + clen;
  }
  return out;
}

describe('log retention', () => {
  const NOW = Date.parse('2026-10-13T12:00:00Z');   // EAT day 2026-10-13; 90 days back: 2026-07-15
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'efc-retention-')); });
  afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {} });
  const touch = n => fs.writeFileSync(path.join(dir, n), 'x');

  test('deletes only day log files older than the retention period', () => {
    const old = ['2025-01-01.log', '2025-01-01-debug.log', '2025-01-01-activity.log', '2026-07-14.log', '2026-07-14-activity.log'];
    const keep = ['2026-07-15.log', '2026-07-15-debug.log', '2026-10-13-activity.log', '2026-10-13.log',
      'notes.txt', '2025-01-01.log.bak', '2025-01-01-other.log', 'x2025-01-01.log', '2025-01-01-activity.log.old', '2025-02-30.log', 'vault.json', '2025-1-1.log'];
    for (const n of old.concat(keep)) touch(n);
    fs.mkdirSync(path.join(dir, '2025-01-02.log'));   // a folder with a matching name is left alone
    expect(logTools.prune(dir, 90, NOW)).toBe(old.length);
    const left = fs.readdirSync(dir).sort();
    expect(left).toEqual(keep.concat(['2025-01-02.log']).sort());
  });

  test('never throws and keeps at least 7 days', () => {
    expect(logTools.prune(path.join(dir, 'missing'), 90, NOW)).toBe(0);
    expect(logTools.prune('', 90, NOW)).toBe(0);
    touch('2026-10-08.log'); touch('2026-10-05.log');
    expect(logTools.prune(dir, 1, NOW)).toBe(1);   // treated as 7: 2026-10-05 goes, 2026-10-08 stays
    expect(fs.readdirSync(dir)).toEqual(['2026-10-08.log']);
  });

  test('LOG_RETENTION_DAYS sets the period (default 90, minimum 7)', () => {
    const was = process.env.LOG_RETENTION_DAYS;
    try {
      delete process.env.LOG_RETENTION_DAYS; expect(logTools.retentionDays()).toBe(90);
      process.env.LOG_RETENTION_DAYS = '30'; expect(logTools.retentionDays()).toBe(30);
      process.env.LOG_RETENTION_DAYS = '3'; expect(logTools.retentionDays()).toBe(7);
      process.env.LOG_RETENTION_DAYS = 'abc'; expect(logTools.retentionDays()).toBe(90);
      process.env.LOG_RETENTION_DAYS = '-5'; expect(logTools.retentionDays()).toBe(90);
    } finally { if (was === undefined) delete process.env.LOG_RETENTION_DAYS; else process.env.LOG_RETENTION_DAYS = was; }
  });
});

describe('GET /api/admin/activity/export', () => {
  test('owner: every business and system lines across the range, as an attachment', async () => {
    const r = await as('owner', A).get(exportUrl(DAYS[0], DAYS[2]));
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toMatch(/text\/plain/);
    expect(r.headers['content-disposition']).toBe('attachment; filename="EFRISConnect-log-2026-03-01_to_2026-03-03.txt"');
    for (const m of ['d1-alpha', 'd1-bravo', 'd1-system', 'd2-alpha error', 'd2-bravo', 'd3-alpha', 'd3-system']) expect(r.text).toContain(m);
    expect(r.text).not.toContain('d2-alpha technical');   // technical lines only with debug=1
    expect(r.text.indexOf('d1-alpha')).toBeLessThan(r.text.indexOf('d3-alpha'));
    expect(r.text).toMatch(/\[Alpha Shop\] admin-a {2}d1-alpha sale/);
    for (const s of PLANTED) expect(r.text).not.toContain(s);
  });

  test('filters: level, business, text, debug; csv format', async () => {
    const err = await as('owner', A).get(exportUrl(DAYS[0], DAYS[2], '&level=error'));
    expect(err.text).toContain('d2-alpha error');
    expect(err.text).toContain('d2-bravo error');
    expect(err.text).not.toContain('d1-alpha');
    const onlyB = await as('owner', A).get(exportUrl(DAYS[0], DAYS[2], '&tenant=' + B));
    expect(onlyB.text).toContain('d1-bravo');
    expect(onlyB.text).not.toMatch(/alpha|system/);
    const sys = await as('owner', A).get(exportUrl(DAYS[0], DAYS[2], '&tenant=system'));
    expect(sys.text).toContain('d3-system');
    expect(sys.text).not.toMatch(/d\d-alpha|d\d-bravo/);
    const q = await as('owner', A).get(exportUrl(DAYS[0], DAYS[2], '&q=D3-ALPHA'));
    expect(q.text).toContain('d3-alpha');
    expect(q.text).not.toContain('d1-alpha');
    const dbg = await as('owner', A).get(exportUrl(DAYS[1], DAYS[1], '&debug=1'));
    expect(dbg.text).toContain('d2-alpha technical');
    const csv = await as('owner', A).get(exportUrl(DAYS[2], DAYS[2], '&format=csv'));
    expect(csv.status).toBe(200);
    expect(csv.headers['content-type']).toMatch(/text\/csv/);
    expect(csv.headers['content-disposition']).toMatch(/EFRISConnect-log-2026-03-03_to_2026-03-03\.csv/);
    expect(csv.text).toMatch(/^﻿?Date,Time,Level,Business,User,Technical,Text\r\n/);
    expect(csv.text).toContain('"d3-alpha ""quoted"", comma"');
  });

  test('admin of A gets A lines only (no B, no system, no other TINs); cashier and accountant refused', async () => {
    const r = await as('adminA', A).get(exportUrl(DAYS[0], DAYS[2], '&debug=1'));
    expect(r.status).toBe(200);
    expect(r.text).toContain('d1-alpha');
    expect(r.text).toContain('d2-alpha leaked');
    expect(r.text).not.toMatch(/bravo|system/);
    expect(r.text).not.toContain(TIN_B);
    for (const s of PLANTED) expect(r.text).not.toContain(s);
    expect((await as('adminA', A).get(exportUrl(DAYS[0], DAYS[2], '&tenant=' + B))).status).toBe(403);
    expect((await as('adminA', B).get(exportUrl(DAYS[0], DAYS[2]))).status).toBe(403);
    expect((await as('cashierA', A).get(exportUrl(DAYS[0], DAYS[2]))).status).toBe(403);
    expect((await as('accountantA', A).get(exportUrl(DAYS[0], DAYS[2]))).status).toBe(403);
  });

  test('bad ranges and options are rejected', async () => {
    const bad = [
      ['', ''], ['2026-03-01', ''], ['../../vault', '2026-03-02'], ['2026-02-30', '2026-03-01'], ['2026-13-01', '2026-13-02'],
      ['20260301', '20260302'], ['2026-03-03', '2026-03-01'], ['2026-01-01', '2026-04-03'], ['2026-03-01-activity', '2026-03-02'],
    ];
    for (const [f, t] of bad) expect((await as('owner', A).get(exportUrl(encodeURIComponent(f), encodeURIComponent(t)))).status).toBe(400);
    expect((await as('owner', A).get(exportUrl('2026-01-01', '2026-04-02'))).status).toBe(200);   // 92 days is the most
    expect((await as('owner', A).get(exportUrl(DAYS[0], DAYS[0], '&format=pdf'))).status).toBe(400);
    expect((await as('owner', A).get(exportUrl(DAYS[0], DAYS[0], '&level=bad'))).status).toBe(400);
  });
});

describe('GET /api/admin/support-bundle', () => {
  const bundle = async (who, tenant, extra) => {
    const r = await binary(as(who, tenant).get('/api/admin/support-bundle?from=' + DAYS[0] + '&to=' + DAYS[2] + (extra || '')));
    return r;
  };

  test('owner: a valid zip with activity, errors and system info, and no secrets', async () => {
    const r = await bundle('owner', A);
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toBe('application/zip');
    expect(r.headers['content-disposition']).toBe('attachment; filename="EFRISConnect-support-2026-03-01_to_2026-03-03.zip"');
    const files = unzip(r.body);
    expect(Object.keys(files).sort()).toEqual(['activity-2026-03-01.txt', 'activity-2026-03-02.txt', 'activity-2026-03-03.txt', 'errors-2026-03-02.jsonl', 'system-info.txt']);
    expect(files['activity-2026-03-02.txt']).toContain('d2-alpha technical');
    expect(files['activity-2026-03-01.txt']).toContain('d1-system');
    const errs = files['errors-2026-03-02.jsonl'].trim().split('\n').map(l => JSON.parse(l));
    expect(errs.map(e => e.message.split(' ')[0])).toEqual(['err-alpha', 'err-bravo', 'err-system']);
    expect(errs[0].meta.efrisPassword).toBe('***');
    const info = files['system-info.txt'];
    expect(info).toMatch(/EFRISConnect version: \S+/);
    expect(info).toContain('Node.js: ' + process.version);
    expect(info).toMatch(/Vault: (unlocked|locked)/);
    expect(info).toMatch(/URA: /);
    expect(info).toMatch(/Users: 4/);
    expect(info).toContain('Data folder: ' + relay.dataDir);
    expect(info).toMatch(/Alpha Shop \[biz-a\]: sandbox, Offline Enabler configured: yes, offline queue: 0 pending/);
    expect(info).toMatch(/Bravo Store \[biz-b\]: production, Offline Enabler configured: no/);
    for (const [name, text] of Object.entries(files)) {
      for (const s of PLANTED) expect({ name, leaked: text.includes(s) }).toEqual({ name, leaked: false });
      expect(text).not.toMatch(/owner-pass-123|user-pass-123|test-internal-api-key|BEGIN [A-Z ]*KEY/);
    }
  });

  test('admin of A: only A lines and A-tagged errors; nothing about B', async () => {
    const r = await bundle('adminA', A);
    expect(r.status).toBe(200);
    const files = unzip(r.body);
    expect(Object.keys(files).sort()).toEqual(['activity-2026-03-01.txt', 'activity-2026-03-02.txt', 'activity-2026-03-03.txt', 'errors-2026-03-02.jsonl', 'system-info.txt']);
    const all = Object.values(files).join('\n');
    expect(all).toContain('d1-alpha');
    expect(all).toContain('err-alpha');
    expect(all).not.toMatch(/bravo|Bravo|biz-b|d\d-system|err-system/);
    expect(all).not.toContain(TIN_B);
    expect(files['system-info.txt']).toMatch(/Users: 3/);
    expect(files['system-info.txt']).toMatch(/Businesses \(1\)/);
    for (const s of PLANTED) expect(all).not.toContain(s);
  });

  test('an admin with no tagged errors gets no errors file; refused for other roles and bad ranges', async () => {
    const r = await binary(as('adminA', A).get('/api/admin/support-bundle?from=' + DAYS[0] + '&to=' + DAYS[0]));
    expect(Object.keys(unzip(r.body)).sort()).toEqual(['activity-2026-03-01.txt', 'system-info.txt']);
    expect((await as('cashierA', A).get('/api/admin/support-bundle?from=' + DAYS[0] + '&to=' + DAYS[2])).status).toBe(403);
    expect((await as('accountantA', A).get('/api/admin/support-bundle?from=' + DAYS[0] + '&to=' + DAYS[2])).status).toBe(403);
    expect((await as('adminA', A).get('/api/admin/support-bundle?from=' + DAYS[0] + '&to=' + DAYS[2] + '&tenant=' + B)).status).toBe(403);
    expect((await as('owner', A).get('/api/admin/support-bundle?from=' + DAYS[2] + '&to=' + DAYS[0])).status).toBe(400);
    expect((await as('owner', A).get('/api/admin/support-bundle?from=2026-01-01&to=2026-12-31')).status).toBe(400);
    expect((await as('owner', A).get('/api/admin/support-bundle?from=..%2F..&to=2026-03-01')).status).toBe(400);
  });

  test('the zip writer round-trips empty, small and repetitive files', () => {
    const big = 'line of text\r\n'.repeat(5000);
    const z = logTools.zip([{ name: 'a.txt', data: '' }, { name: 'b.txt', data: 'x' }, { name: 'c.txt', data: big }, { name: 'ü.txt', data: Buffer.from([0, 1, 2]) }]);
    const files = unzip(z);
    expect(files['a.txt']).toBe('');
    expect(files['b.txt']).toBe('x');
    expect(files['c.txt']).toBe(big);
    expect(Buffer.from(files['ü.txt'], 'utf8')).toEqual(Buffer.from([0, 1, 2]));
    expect(z.length).toBeLessThan(big.length / 10);
  });
});

test('both routes are listed for admins in the permission table', () => {
  const perms = relay.app._routePerms;
  expect(perms).toEqual(expect.arrayContaining([
    { method: 'GET', path: '/admin/activity/export', perm: 'admin' },
    { method: 'GET', path: '/admin/support-bundle', perm: 'admin' },
  ]));
});

test('csv export: cells a spreadsheet would read as a formula start with an apostrophe', async () => {
  const day = '2026-03-04';
  writeActivity(day, [
    { text: '=HYPERLINK("http://evil.example","x")', tenantId: A, user: '@admin' },
    { text: '+1+2', tenantId: A },
    { text: '-3*cmd', tenantId: A },
    { text: '\tTAB lead', tenantId: A },
    { text: 'plain = text', tenantId: A },
  ]);
  const r = await as('owner', A).get('/api/admin/activity/export?from=' + day + '&to=' + day + '&format=csv&tenant=' + A);
  expect(r.status).toBe(200);
  expect(r.text).toContain('"\'=HYPERLINK(""http://evil.example"",""x"")"');
  expect(r.text).toContain('"\'@admin"');
  expect(r.text).toContain('"\'+1+2"');
  expect(r.text).toContain('"\'-3*cmd"');
  expect(r.text).toContain('"\'\tTAB lead"');
  expect(r.text).toContain('"plain = text"');
  expect(r.text).not.toMatch(/(^|,)"[=+@-]/m);
});
