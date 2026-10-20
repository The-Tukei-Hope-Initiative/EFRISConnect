'use strict';
// Power cuts: a file of zero bytes or NULs is restored from its .bak, and the
// damaged copy is kept. Seen in the field: users.json became all NULs.
const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');
const { writeDurable, readJsonDurable } = require('../safe-file');
const { loadRelay } = require('./helpers/relay');

const quiet = () => {};
let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'efc-safe-')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

describe('safe-file', () => {
  test('writeDurable keeps a backup when asked', () => {
    const f = path.join(dir, 'a.json');
    writeDurable(f, '{"n":1}', { backup: true });
    expect(fs.readFileSync(f + '.bak', 'utf8')).toBe('{"n":1}');
    writeDurable(path.join(dir, 'b.json'), '{}');
    expect(fs.existsSync(path.join(dir, 'b.json.bak'))).toBe(false);
  });

  test('a file of NULs is restored from the backup and the damaged copy kept', () => {
    const f = path.join(dir, 'a.json');
    writeDurable(f, '{"users":[1]}', { backup: true });
    fs.writeFileSync(f, Buffer.alloc(64));
    const r = readJsonDurable(f, { backup: true, log: quiet });
    expect(r).toMatchObject({ state: 'restored', value: { users: [1] } });
    expect(JSON.parse(fs.readFileSync(f, 'utf8'))).toEqual({ users: [1] });
    expect(fs.readdirSync(dir).some(n => n.startsWith('a.json.damaged-'))).toBe(true);
  });

  test('a missing file is never restored from the backup (it may have been moved aside on purpose)', () => {
    const f = path.join(dir, 'a.json');
    writeDurable(f, '{"n":1}', { backup: true });
    fs.rmSync(f);
    expect(readJsonDurable(f, { backup: true, log: quiet })).toMatchObject({ state: 'missing' });
    expect(fs.existsSync(f)).toBe(false);
  });

  test('damaged with no backup: moved aside, or left in place with keepDamaged', () => {
    const f = path.join(dir, 'a.json');
    fs.writeFileSync(f, '{ broken');
    expect(readJsonDurable(f, { keepDamaged: true, log: quiet })).toMatchObject({ state: 'damaged' });
    expect(fs.readFileSync(f, 'utf8')).toBe('{ broken');
    expect(readJsonDurable(f, { log: quiet })).toMatchObject({ state: 'damaged' });
    expect(fs.existsSync(f)).toBe(false);
  });

  test('an empty file with no backup reads as empty, not damaged', () => {
    const f = path.join(dir, 'a.json');
    fs.writeFileSync(f, '');
    expect(readJsonDurable(f, { backup: true, log: quiet })).toMatchObject({ state: 'empty' });
    expect(fs.existsSync(f)).toBe(true);
  });
});

describe('users.json after a power cut', () => {
  test('the owner account comes back from users.json.bak', async () => {
    const r = loadRelay();
    try {
      const s = await request(r.app).post('/api/auth/setup').send({ name: 'boss', password: 'boss-pass-111' });
      expect(s.body.success).toBe(true);
      expect(fs.existsSync(r.file('users.json.bak'))).toBe(true);
      fs.writeFileSync(r.file('users.json'), Buffer.alloc(128));
      const l = await request(r.app).post('/api/auth/login').send({ name: 'boss', password: 'boss-pass-111' });
      expect(l.body.success).toBe(true);
    } finally { r.cleanup(); }
  });
});

describe('offline queue after a power cut', () => {
  test('waiting sales come back from offline_queue.json.bak', async () => {
    const r = loadRelay();
    try {
      const q = [{ id: 'off_1', status: 'pending', saleAt: new Date().toISOString(), reference: 'REC-1', tenantId: '' }];
      writeDurable(r.file('offline_queue.json'), JSON.stringify(q), { backup: true });
      fs.writeFileSync(r.file('offline_queue.json'), Buffer.alloc(32));
      const res = await r.get('/api/offline-queue');
      expect(res.body.items.map(i => i.reference)).toEqual(['REC-1']);
    } finally { r.cleanup(); }
  });
});
