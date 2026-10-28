'use strict';
// Email: the SMTP settings (owner only, password never returned and masked),
// security alerts, "Email me a code" recovery and the admin's "Email a code to
// the user". Mail goes to a stub transport (mailer._test.setTransport); nothing
// leaves the machine.
const fs = require('fs');
const request = require('supertest');
const { loadRelay } = require('./helpers/relay');

const A = 'biz-a';
const SMTP_PW = 'smtp-Secret-Pass-9876';
let relay, auth, mailer, tok;
let sent = [], failNext = 0;
let ipN = 0;
const remote = () => ({ 'X-Forwarded-For': '203.0.113.' + ((++ipN % 200) + 20) });

beforeAll(async () => {
  relay = loadRelay();
  auth = relay.app._auth; mailer = relay.app._mailer;
  mailer._test.setTransport(() => ({
    sendMail: async m => {
      if (failNext > 0) { failNext--; const e = new Error('Invalid login: 535 5.7.8 Username and Password not accepted'); e.code = 'EAUTH'; throw e; }
      sent.push(m); return { messageId: 'x' };
    },
  }));
  tok = { owner: await relay.setupOwner('boss', 'boss-pass-123') };
  expect((await relay.addTenant(A, { tin: '1000000001', businessName: 'Shop A Ltd', tradeName: 'Shop A' })).body.success).toBe(true);
  tok.admin = await relay.addUser('admin-a', { [A]: 'admin' });
  tok.cashier = await relay.addUser('cash-a', { [A]: 'cashier' });
});
afterAll(() => { mailer._test.setTransport(null); auth._test.setNow(null); relay.cleanup(); });
const idle = () => mailer._test.idle();
const reset = async () => { await idle(); sent = []; };
const post = (p, body, headers) => { const r = request(relay.app).post(p); for (const [k, v] of Object.entries(headers || {})) r.set(k, v); return r.send(body || {}); };
const SETTINGS = { host: 'smtp.gmail.com', port: 587, security: 'starttls', username: 'shop@gmail.com', password: SMTP_PW, fromName: 'Shop A', fromAddress: 'shop@gmail.com' };
const userId = name => auth.listUsers().find(u => u.name === name).id;

describe('SMTP settings', () => {
  test('only an owner (or the service) may read or change them', async () => {
    for (const who of ['admin', 'cashier']) {
      const c = relay.as(tok[who], { 'X-Tenant-Id': A });
      expect((await c.get('/api/admin/email')).status).toBe(403);
      expect((await c.post('/api/admin/email', SETTINGS)).status).toBe(403);
      expect((await c.post('/api/admin/email/test', { to: 'x@example.com' })).status).toBe(403);
    }
    expect((await request(relay.app).get('/api/admin/email')).status).toBe(401);
    const r = await relay.as(tok.owner).get('/api/admin/email');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ success: true, configured: false, ownerHasEmail: false });
  });

  test('bad values are refused', async () => {
    const o = relay.as(tok.owner);
    expect((await o.post('/api/admin/email', { ...SETTINGS, host: 'smtp gmail' })).status).toBe(400);
    expect((await o.post('/api/admin/email', { ...SETTINGS, port: 70000 })).status).toBe(400);
    expect((await o.post('/api/admin/email', { ...SETTINGS, fromAddress: 'not-an-address' })).status).toBe(400);
  });

  test('the password is stored encrypted, never returned, and masked in the log', async () => {
    const r = await relay.as(tok.owner).post('/api/admin/email', SETTINGS);
    expect(r.status).toBe(200);
    expect(r.body.settings).toMatchObject({ host: 'smtp.gmail.com', port: 587, security: 'starttls', passwordSaved: true, fromAddress: 'shop@gmail.com' });
    expect(JSON.stringify(r.body)).not.toContain(SMTP_PW);
    const g = await relay.as(tok.owner).get('/api/admin/email');
    expect(JSON.stringify(g.body)).not.toContain(SMTP_PW);
    expect(g.body.settings.password).toBeUndefined();
    expect(fs.readFileSync(relay.app._vault.RELAY_FILE, 'utf8')).not.toContain(SMTP_PW);
    expect(relay.app._vault.listTenants().map(t => t.id)).toEqual([A]);   // not a business
    expect(relay.app._activity.mask('login failed for ' + SMTP_PW)).not.toContain(SMTP_PW);
    // Saving again without a password keeps the saved one.
    const k = await relay.as(tok.owner).post('/api/admin/email', { ...SETTINGS, password: '' });
    expect(k.body.settings.passwordSaved).toBe(true);
    expect(relay.app._vault.getRelay('smtp', ['password']).password).toBe(SMTP_PW);
  });

  test('test email: sent through the transport, or the server error comes back plainly', async () => {
    await reset();
    const ok = await relay.as(tok.owner).post('/api/admin/email/test', { to: 'boss@example.com' });
    expect(ok.body.success).toBe(true);
    expect(sent.map(m => m.to)).toEqual(['boss@example.com']);
    failNext = 1;
    const bad = await relay.as(tok.owner).post('/api/admin/email/test', { to: 'boss@example.com' });
    expect(bad.body.success).toBe(false);
    expect(bad.body.error).toMatch(/535 5\.7\.8 Username and Password not accepted/);
    expect(bad.body.error).not.toContain(SMTP_PW);
  });

  test('status tells the sign-in screen that email recovery is available', async () => {
    expect((await request(relay.app).get('/api/auth/status')).body.emailRecovery).toBe(true);
  });
});

describe('email addresses', () => {
  test('a user sets their own address with the current password; format is checked', async () => {
    const c = relay.as(tok.owner);
    expect((await c.post('/api/auth/me', { email: 'boss@example.com', currentPassword: 'wrong' })).body.success).toBe(false);
    expect((await c.post('/api/auth/me', { email: 'bad@', currentPassword: 'boss-pass-123' })).body.success).toBe(false);
    const r = await c.post('/api/auth/me', { email: 'boss@example.com', currentPassword: 'boss-pass-123' });
    expect(r.body).toMatchObject({ success: true, user: { email: 'boss@example.com' } });
    expect((await c.get('/api/auth/status')).body.user.email).toBe('boss@example.com');
    expect((await c.get('/api/admin/email')).body.ownerHasEmail).toBe(true);
  });

  test('an admin sets a staff address; Users shows it', async () => {
    const c = relay.as(tok.admin, { 'X-Tenant-Id': A });
    expect((await c.post('/api/auth/users/' + userId('cash-a'), { email: 'nope' })).status).toBe(400);
    const r = await c.post('/api/auth/users/' + userId('cash-a'), { email: 'cash@example.com' });
    expect(r.body).toMatchObject({ success: true, user: { email: 'cash@example.com' } });
    const list = await c.get('/api/auth/users');
    expect(list.body.users.find(u => u.name === 'cash-a').email).toBe('cash@example.com');
  });

  test('a user can be added with an address', async () => {
    await reset();
    const r = await relay.as(tok.owner).post('/api/auth/users', { name: 'cash-b', password: 'cash-pass-123', email: 'cashb@example.com', roles: { [A]: 'cashier' } });
    expect(r.body).toMatchObject({ success: true, user: { email: 'cashb@example.com' } });
    await idle();
    // New user added: the owner is told; the new user too (they have an address).
    const added = sent.filter(m => /New user added/.test(m.subject));
    expect(added.map(m => m.to).sort()).toEqual(['boss@example.com', 'cashb@example.com']);
    expect(added[0].text).toMatch(/"boss" added the user "cash-b"/);
    expect(added[0].text).toMatch(/Cashier at Shop A/);
    expect(added[0].text).toMatch(/\(Uganda time\)/);
    expect(added[0].text).toMatch(/If this was not you/);
    expect(added[0].text).not.toContain('cash-pass-123');
  });
});

describe('security alerts', () => {
  test('password changed: owner and user, no password in the mail', async () => {
    await reset();
    const t = await relay.login('cash-a', 'user-pass-123');
    const r = await relay.as(t, remote()).post('/api/auth/change-password', { currentPassword: 'user-pass-123', newPassword: 'cash-new-pass-1' });
    expect(r.body.success).toBe(true);
    await idle();
    const m = sent.filter(x => /Password changed/.test(x.subject));
    expect(m.map(x => x.to).sort()).toEqual(['boss@example.com', 'cash@example.com']);
    for (const x of m) { expect(x.text).not.toContain('cash-new-pass-1'); expect(x.html).not.toContain('cash-new-pass-1'); expect(x.text).toMatch(/From: another computer, network address/); }
  });

  test('admin password reset, role made admin, user disabled', async () => {
    await reset();
    const c = relay.as(tok.owner, { 'X-Tenant-Id': A });
    const id = userId('cash-b');
    expect((await c.post('/api/auth/users/' + id, { password: 'reset-by-boss-1' })).body.success).toBe(true);
    expect((await c.post('/api/auth/users/' + id, { roles: { [A]: 'admin' } })).body.success).toBe(true);
    expect((await c.post('/api/auth/users/' + id, { disabled: true })).body.success).toBe(true);
    await idle();
    const subj = sent.map(m => m.subject);
    expect(subj).toEqual(expect.arrayContaining(['EFRISConnect: Password reset by an admin', 'EFRISConnect: User made an admin', 'EFRISConnect: User disabled']));
    const role = sent.find(m => /made an admin/.test(m.subject));
    expect(role.text).toMatch(/an Admin of Shop A/);
    expect(role.text).toMatch(/Business: Shop A/);
    expect(JSON.stringify(sent)).not.toContain('reset-by-boss-1');
    await c.post('/api/auth/users/' + id, { disabled: false });
  });

  test('account locked after 5 wrong passwords: owner and user are told, the response carries no address', async () => {
    await reset();
    let last;
    const ip = remote();
    for (let i = 0; i < 5; i++) last = await post('/api/auth/login', { name: 'cash-a', password: 'wrong-' + i }, ip);
    expect(last.body.lockedUntil).toBeGreaterThan(Date.now());
    expect(JSON.stringify(last.body)).not.toContain('@');
    await idle();
    const m = sent.filter(x => /locked/.test(x.subject));
    expect(m.map(x => x.to).sort()).toEqual(['boss@example.com', 'cash@example.com']);
    expect(m[0].text).toMatch(/locked for 15 minutes after 5 wrong passwords/);
  });

  test('every recipient gets their own message', async () => {
    for (const m of sent) expect(typeof m.to).toBe('string');
  });

  test('a failed send does not break sign-in, password change or recovery', async () => {
    await reset();
    failNext = 100;
    const t = await relay.login('admin-a', 'user-pass-123');
    const r = await relay.as(t).post('/api/auth/change-password', { currentPassword: 'user-pass-123', newPassword: 'admin-new-pass-1' });
    expect(r.body.success).toBe(true);
    const o = await relay.as(tok.owner).post('/api/auth/me', { email: 'boss@example.com', currentPassword: 'boss-pass-123' });
    expect(o.body.success).toBe(true);
    const ec = await post('/api/auth/email-code', { name: 'boss' }, remote());
    expect(ec.body.success).toBe(true);
    await idle();
    failNext = 0;
    expect(sent).toEqual([]);
  });
});

describe('email recovery', () => {
  const codeFrom = m => (/Your code: ([A-Z2-9]{8})/.exec(m.text) || [])[1];

  test('the answer is the same for a known name, an unknown name and a user without email', async () => {
    await reset();
    const a = await post('/api/auth/email-code', { name: 'boss' }, remote());
    const b = await post('/api/auth/email-code', { name: 'nobody-here' }, remote());
    const c = await post('/api/auth/email-code', { name: 'admin-a' }, remote());
    expect(a.body).toEqual(b.body);
    expect(a.body).toEqual(c.body);
    await idle();
    expect(sent.map(m => m.to)).toEqual(['boss@example.com']);
    expect(codeFrom(sent[0])).toMatch(/^[A-HJ-NP-Z2-9]{8}$/);
    expect(fs.readFileSync(relay.file('users.json'), 'utf8')).not.toContain(codeFrom(sent[0]));
  });

  test('the emailed code works from another computer, once, and issues a new recovery code', async () => {
    await reset();
    await post('/api/auth/email-code', { name: 'cash-a' }, remote());
    await idle();
    const code = codeFrom(sent[0]);
    sent = [];
    const r = await post('/api/auth/recover', { name: 'cash-a', code: code.toLowerCase(), newPassword: 'cash-mail-pass-1' }, remote());
    expect(r.body.success).toBe(true);
    expect(r.body.recoveryCode).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/);
    expect(r.body.token).toBeTruthy();
    const again = await post('/api/auth/recover', { name: 'cash-a', code, newPassword: 'cash-mail-pass-2' }, remote());
    expect(again.body.success).toBe(false);
    await idle();
    const alertMail = sent.filter(m => /emailed code/.test(m.subject));
    expect(alertMail.length).toBe(2);
    for (const m of alertMail) { expect(m.text).not.toContain(r.body.recoveryCode); expect(m.text).not.toContain(code); expect(m.text).toMatch(/new recovery code was shown on screen/); }
  });

  test('an emailed code expires after 30 minutes', async () => {
    await reset();
    await post('/api/auth/email-code', { name: 'boss' }, remote());
    await idle();
    const code = codeFrom(sent[0]);
    const t0 = Date.now();
    auth._test.setNow(() => t0 + 31 * 60000);
    try {
      const r = await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-late-pass-1' }, remote());
      expect(r.body.success).toBe(false);
    } finally { auth._test.setNow(null); }
  });

  test('at most 3 codes per user per hour', async () => {
    await reset();
    const t0 = Date.now() + 2 * 3600000;   // a fresh hour for this user
    auth._test.setNow(() => t0);
    try {
      for (let i = 0; i < 5; i++) expect((await post('/api/auth/email-code', { name: 'cash-b' }, remote())).body.success).toBe(true);
      await idle();
      expect(sent.filter(m => m.to === 'cashb@example.com').length).toBe(3);
      auth._test.setNow(() => t0 + 3601000);
      await post('/api/auth/email-code', { name: 'cash-b' }, remote());
      await idle();
      expect(sent.filter(m => m.to === 'cashb@example.com').length).toBe(4);
    } finally { auth._test.setNow(null); }
  });

  test('wrong guesses void the emailed code', async () => {
    await reset();
    const t0 = Date.now() + 5 * 3600000;
    auth._test.setNow(() => t0);
    try {
      await post('/api/auth/email-code', { name: 'boss' }, remote());
      await idle();
      const code = codeFrom(sent[sent.length - 1]);
      for (let i = 0; i < 5; i++) await post('/api/auth/recover', { name: 'boss', code: 'ZZZZZZZ' + (i + 2), newPassword: 'boss-guess-pass' }, remote());
      expect((await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-guess-pass' }, remote())).body.success).toBe(false);
    } finally { auth._test.setNow(null); }
  });

  test('the launcher reset code still works only on this computer', async () => {
    const { code } = auth.writeResetCode();
    expect((await post('/api/auth/recover', { name: 'boss', code, newPassword: 'boss-pass-321' }, remote())).body.success).toBe(false);
  });
});

describe('admin: Email a code to the user', () => {
  test('sends a code to a staff member with an address; refused without one or out of scope', async () => {
    await reset();
    const c = relay.as(tok.owner, { 'X-Tenant-Id': A });
    const r = await c.post('/api/auth/users/' + userId('cash-a') + '/email-code', {});
    expect(r.body.success).toBe(true);
    await idle();
    expect(sent.map(m => m.to)).toEqual(['cash@example.com']);
    expect(sent[0].text).toMatch(/"boss" asked EFRISConnect to send you this code/);
    expect((await c.post('/api/auth/users/' + userId('admin-a') + '/email-code', {})).status).toBe(400);
    const cash = await relay.addUser('cash-c', { [A]: 'cashier' });
    expect((await relay.as(cash, { 'X-Tenant-Id': A }).post('/api/auth/users/' + userId('cash-a') + '/email-code', {})).status).toBe(403);
  });
});

describe('reset-owner.js', () => {
  test('emails the owners an alert without the code', async () => {
    await reset();
    jest.isolateModules(() => {
      // Same data folder and keys as the relay in this file.
      const ro = require('../reset-owner');
      const m = require('../mailer');
      m._test.setTransport(() => ({ sendMail: async x => { sent.push(x); return {}; } }));
      relay._ro = ro;
    });
    const { code } = auth.writeResetCode();
    const n = await relay._ro.notifyOwners();
    expect(n).toBe(1);
    const m = sent.find(x => /reset code generated/.test(x.subject));
    expect(m.to).toBe('boss@example.com');
    expect(m.text).not.toContain(code);
    expect(m.text).toMatch(/Reset owner password/);
  });
});

describe('Email off', () => {
  test('clearing the server turns email off; Email me a code still answers the same', async () => {
    const r = await relay.as(tok.owner).post('/api/admin/email', { host: '' });
    expect(r.body.configured).toBe(false);
    expect((await request(relay.app).get('/api/auth/status')).body.emailRecovery).toBe(false);
    await reset();
    const e = await post('/api/auth/email-code', { name: 'boss' }, remote());
    expect(e.body.success).toBe(true);
    await idle();
    expect(sent).toEqual([]);
  });
});
