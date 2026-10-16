'use strict';
// ── Email: password-reset codes and security alerts ─────────────────────────────────
// One outgoing mail server (SMTP) for the whole relay, set by an owner in
// Settings > Email. It is stored in the vault as a relay-wide record (not per
// business); the password is encrypted there and never sent back to a browser.
//
// Email is a helper, never a dependency: a send that fails (no internet, wrong
// password, server down) is logged and forgotten. queue() never throws and the
// action that asked for the email (sign-in, password reset) carries on.
//
// Every message goes to one recipient at a time, so nobody sees anyone else's
// address. The activity log names recipients by sign-in name, never by address.
const os = require('os');
const vault = require('./vault');
const activity = require('./activity');

const RECORD = 'smtp';
const SECRETS = ['password'];
const SECURITY = ['ssl', 'starttls', 'none'];
const TIMEOUT_MS = 15000;

// Test hook: a function (settings) -> transport with sendMail(message). Not used at runtime.
let _transportFactory = null;
const _pending = new Set();

// ── Validation ──
function validEmail(s) {
  if (typeof s !== 'string') return false;
  const v = s.trim();
  if (!v || v.length > 254 || /[\s<>()",;:\\\[\]]/.test(v)) return false;
  const at = v.lastIndexOf('@');
  if (at < 1 || at > 64) return false;
  return validHost(v.slice(at + 1)) && v.slice(at + 1).includes('.');
}
function validHost(h) {
  if (typeof h !== 'string' || !h || h.length > 253) return false;
  return h.split('.').every(l => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l));
}
const oneLine = s => String(s == null ? '' : s).replace(/[\r\n\t]+/g, ' ').trim();

// ── Settings ──
function raw() {
  try { return vault.getRelay(RECORD, SECRETS); } catch (_) { return null; }
}
// The settings with the password, for sending (server side only). The password is
// handed to the activity masker each time it is read.
function settingsWithSecret() {
  const r = raw();
  if (r && r.password) activity.noteSecrets(r.password);
  return r;
}
// What a browser may see: never the password, only whether one is saved.
function getSettings() {
  let r = null;
  try { r = vault.getRelay(RECORD, []); } catch (_) { r = null; }
  r = r || {};
  return {
    host: r.host || '', port: r.port || 587, security: SECURITY.includes(r.security) ? r.security : 'starttls',
    username: r.username || '', passwordSaved: vault.relayHas(RECORD, 'password'),
    fromName: r.fromName || '', fromAddress: r.fromAddress || '', updatedAt: r.updatedAt || '',
  };
}
function isConfigured() { const s = getSettings(); return !!(s.host && s.port && s.fromAddress); }

// Save from the Settings form. password: a value replaces the saved one, '' or
// missing keeps it; clearPassword: true removes it. host '' turns email off.
function saveSettings(b) {
  b = b || {};
  const host = oneLine(b.host).toLowerCase();
  if (!host) { vault.putRelay(RECORD, null); return { settings: getSettings() }; }
  if (!validHost(host)) return { error: 'Enter the mail server name, for example smtp.gmail.com.' };
  const port = Number(b.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: 'The port must be a number from 1 to 65535 (usually 587 or 465).' };
  const security = SECURITY.includes(b.security) ? b.security : 'starttls';
  const fromAddress = oneLine(b.fromAddress);
  if (!validEmail(fromAddress)) return { error: 'Enter a valid "From" email address.' };
  const username = oneLine(b.username).slice(0, 254);
  const fromName = oneLine(b.fromName).slice(0, 80);
  const rec = { host, port, security, username, fromName, fromAddress };
  if (b.clearPassword) rec.password = '';
  else if (typeof b.password === 'string' && b.password !== '') {
    if (b.password.length > 500) return { error: 'The password is too long.' };
    rec.password = b.password;
    activity.noteSecrets(b.password);
  }
  vault.putRelay(RECORD, rec, SECRETS);
  return { settings: getSettings() };
}

// ── Sending ──
function makeTransport(s) {
  if (_transportFactory) return _transportFactory(s);
  const nodemailer = require('nodemailer');   // loaded only when an email is sent
  return nodemailer.createTransport({
    host: s.host, port: Number(s.port) || 587,
    secure: s.security === 'ssl', requireTLS: s.security === 'starttls', ignoreTLS: s.security === 'none',
    auth: s.username ? { user: s.username, pass: s.password || '' } : undefined,
    connectionTimeout: TIMEOUT_MS, greetingTimeout: TIMEOUT_MS, socketTimeout: TIMEOUT_MS, dnsTimeout: TIMEOUT_MS,
    disableFileAccess: true, disableUrlAccess: true,
  });
}
// The server's own words, without the password or anyone's full address.
function plainError(e) {
  let m = oneLine((e && (e.response || e.message)) || 'unknown error');
  if (e && e.code === 'EAUTH') m = 'The mail server refused the user name or password. ' + m;
  else if (e && /ETIMEDOUT|ESOCKET|ECONNECTION|ECONNREFUSED|ENOTFOUND|EDNS/.test(String(e.code || ''))) m = 'Could not reach the mail server (' + e.code + '). Check the server name, port and security, and the internet connection. ' + m;
  return activity.mask(m).slice(0, 400);
}
const hideAddresses = s => String(s).replace(/[^\s<>"'@,;:]+@([A-Za-z0-9.-]+)/g, '***@$1');

// Send one message now. Resolves { success, error }; never rejects.
async function send(msg) {
  try {
    const s = settingsWithSecret();
    if (!s || !s.host || !s.fromAddress) return { success: false, error: 'Email is not set up. An owner can set it up in Settings > Email.' };
    if (!validEmail(msg.to)) return { success: false, error: 'That is not a valid email address.' };
    const from = s.fromName ? { name: oneLine(s.fromName), address: s.fromAddress } : s.fromAddress;
    const t = makeTransport(s);
    let timer;
    const guard = new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error('The mail server did not answer in time.'), { code: 'ETIMEDOUT' })), TIMEOUT_MS * 4); });
    try {
      await Promise.race([t.sendMail({ from, to: msg.to, subject: oneLine(msg.subject), text: msg.text, html: msg.html }), guard]);
    } finally { clearTimeout(timer); try { if (t.close) t.close(); } catch (_) {} }
    return { success: true };
  } catch (e) {
    return { success: false, error: plainError(e) };
  }
}

// Send in the background. label names the email in the log, who names the
// recipient (a sign-in name, never the address). Returns the promise (tests wait
// on it); it never rejects.
function queue(msg, label, who) {
  const p = new Promise(resolve => setImmediate(resolve)).then(() => send(msg)).then(r => {
    try {
      if (r.success) console.log('   Email: ' + label + ' sent to ' + who);
      else console.log('   ⚠ Email: ' + label + ' to ' + who + ' could not be sent: ' + hideAddresses(r.error));
    } catch (_) {}
    return r;
  }).catch(() => ({ success: false }));
  _pending.add(p);
  p.then(() => _pending.delete(p));
  return p;
}

// ── Messages ──
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// "13 Oct 2026, 14:05 (Uganda time)" whatever the server's time zone.
function eatTime(ms) {
  const d = new Date((ms == null ? Date.now() : ms) + 3 * 3600000);
  const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
  const p = n => String(n).padStart(2, '0');
  return d.getUTCDate() + ' ' + mon + ' ' + d.getUTCFullYear() + ', ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ' (Uganda time)';
}
// Plain text plus simple HTML from a list of paragraphs (a paragraph that is an
// array becomes a list).
function compose(paras) {
  const text = paras.map(p => Array.isArray(p) ? p.map(x => '- ' + x).join('\n') : p).join('\n\n') + '\n';
  const html = '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#222;max-width:560px;">'
    + paras.map(p => Array.isArray(p) ? '<ul>' + p.map(x => '<li>' + esc(x) + '</li>').join('') + '</ul>' : '<p>' + esc(p).replace(/\n/g, '<br>') + '</p>').join('')
    + '</div>';
  return { text, html };
}
const NOT_YOU = 'If this was not you:';
const NOT_YOU_STEPS = [
  'Sign in to EFRIS Connect and change your password (click your name at the top, then Change password).',
  'If you cannot sign in, the owner can run "Reset owner password" in the EFRIS Connect launcher on the computer that runs EFRIS Connect.',
  'Check Settings > Users for accounts or roles you do not recognise, and disable them.',
];
const FOOT = 'This is an automatic message from EFRIS Connect. Security alerts never contain passwords or codes, and nobody from EFRIS Connect will ask you to reply with one.';

// Security alert subjects and what happened, by event.
const EVENTS = {
  'reset-recovery': { subject: 'Password reset with a recovery code', what: c => 'The password for ' + c.who + ' was reset with a recovery code. A new recovery code was shown on screen.' },
  'reset-owner-code': { subject: 'Owner password reset with a reset code', what: c => 'The password for ' + c.who + ' was reset with an owner reset code from the EFRIS Connect launcher. A new recovery code was shown on screen.' },
  'reset-email-code': { subject: 'Password reset with an emailed code', what: c => 'The password for ' + c.who + ' was reset with a code sent by email. A new recovery code was shown on screen.' },
  'password-changed': { subject: 'Password changed', what: c => c.who + ' changed their password.' },
  'password-reset-admin': { subject: 'Password reset by an admin', what: c => c.actor + ' set a new password for ' + c.who + '.' },
  'locked': { subject: 'Account locked after wrong passwords', what: c => 'The account ' + c.who + ' was locked for 15 minutes after 5 wrong passwords in a row.' },
  'user-added': { subject: 'New user added', what: c => c.actor + ' added the user ' + c.who + (c.detail ? ' (' + c.detail + ')' : '') + '.' },
  'user-disabled': { subject: 'User disabled', what: c => c.actor + ' disabled the user ' + c.who + '. They cannot sign in until the account is enabled again.' },
  'role-admin': { subject: 'User made an admin', what: c => c.actor + ' made ' + c.who + ' an Admin' + (c.detail ? ' of ' + c.detail : '') + '. An admin can change settings and manage users.' },
  'owner-created': { subject: 'Owner account created', what: c => (c.actor ? c.actor + ' created the owner account ' + c.who + '.' : 'The owner account ' + c.who + ' was created.') },
  'email-changed': { subject: 'Email address changed', what: c => 'The email address for ' + c.who + ' was changed' + (c.actor ? ' by ' + c.actor : '') + '. Sign-in codes and alerts now go to the new address.' },
  'single-user-on': { subject: 'Single-user mode turned on', what: c => (c.actor ? c.actor + ' turned on' : 'Someone turned on') + ' single-user mode. EFRIS Connect now opens without sign-in, as ' + c.who + ', on the computer that runs it. Every other computer still has to sign in.' },
  'single-user-off': { subject: 'Single-user mode turned off', what: c => (c.actor ? c.actor + ' turned off' : 'EFRIS Connect turned off') + ' single-user mode' + (c.detail ? ' (' + c.detail + ')' : '') + '. Everyone has to sign in again, also on the computer that runs EFRIS Connect.' },
  'reset-code-generated': { subject: 'Owner reset code generated', what: c => 'Someone ran "Reset owner password" on the computer that runs EFRIS Connect' + (c.host ? ' (' + c.host + ')' : '') + '. A one-time reset code, valid 24 hours, was written to the data folder there. It works only on that computer.' },
};

function describeUser(u) { return u ? '"' + (u.name || '') + '"' + (u.displayName && u.displayName !== u.name ? ' (' + u.displayName + ')' : '') : 'an account'; }
function fromLine(ctx) {
  if (ctx.computer) return ctx.computer;
  if (ctx.local) return 'the computer that runs EFRIS Connect (this relay)';
  if (ctx.ip) return 'another computer, network address ' + ctx.ip;
  return 'unknown';
}

// Build and queue a security alert.
//   event:   a key of EVENTS
//   user:    the account it is about (raw or public user: name, displayName, email)
//   owners:  every owner account (each one with an email gets a copy)
//   actor:   who did it, when someone else did (display text)
//   detail:  business names or role text where relevant
//   ip, local, computer: where the request came from
// Returns the queued promises (tests wait on them).
function alert(event, ctx) {
  try {
    const ev = EVENTS[event];
    if (!ev || !isConfigured()) return [];
    ctx = ctx || {};
    const c = { who: describeUser(ctx.user), actor: ctx.actor ? String(ctx.actor) : '', detail: ctx.detail ? String(ctx.detail) : '', host: ctx.host || '' };
    const lines = ['What happened: ' + ev.what(c), 'When: ' + eatTime(ctx.time)];
    if (ctx.business) lines.push('Business: ' + ctx.business);
    lines.push('From: ' + fromLine(ctx));
    const body = compose(['EFRIS Connect security alert', lines.join('\n'), NOT_YOU, NOT_YOU_STEPS, FOOT]);
    const subject = 'EFRIS Connect: ' + ev.subject;
    const out = [];
    const seen = new Set();
    const to = (addr, who) => {
      const a = String(addr || '').trim();
      if (!validEmail(a) || seen.has(a.toLowerCase())) return;
      seen.add(a.toLowerCase());
      out.push(queue({ to: a, subject, text: body.text, html: body.html }, 'security alert "' + ev.subject + '"', who));
    };
    for (const o of ctx.owners || []) if (o && !o.disabled) to(o.email, 'owner ' + o.name);
    if (ctx.user && ctx.user.email) to(ctx.user.email, 'user ' + ctx.user.name);
    if (ctx.alsoTo) to(ctx.alsoTo, 'user ' + (ctx.user ? ctx.user.name : '') + ' (previous address)');
    return out;
  } catch (_) { return []; }
}

// The one-time code for "Email me a code" / an admin's "Email a code to the user".
function sendCode(user, code, ctx) {
  ctx = ctx || {};
  const asked = ctx.byAdmin ? ctx.byAdmin + ' asked EFRIS Connect to send you this code so you can set a new password.' : 'Someone (hopefully you) asked for a code to set a new password for EFRIS Connect.';
  const body = compose([
    'EFRIS Connect password code',
    asked,
    'Your code: ' + code,
    'It works once and is valid for 30 minutes. Open EFRIS Connect, click "Forgot password?", type your sign-in name (' + (user.name || '') + '), this code and a new password.',
    'When: ' + eatTime(ctx.time) + '\nFrom: ' + fromLine(ctx),
    'If you did not ask for this, ignore this email: your password stays as it is. If it happens again, tell the owner.',
  ]);
  return queue({ to: user.email, subject: 'EFRIS Connect: your password code', text: body.text, html: body.html }, 'password code', 'user ' + user.name);
}

function testMessage(to) {
  const body = compose(['EFRIS Connect test email', 'Email from EFRIS Connect works. Sign-in codes and security alerts will be sent from this address.', 'Sent: ' + eatTime() + ' from ' + os.hostname() + '.']);
  return { to, subject: 'EFRIS Connect: test email', text: body.text, html: body.html };
}

// Learn the saved password for the activity masker (called once the vault unlocks).
function learn() { try { settingsWithSecret(); return true; } catch (_) { return false; } }

module.exports = {
  validEmail, validHost, getSettings, saveSettings, isConfigured, send, queue, alert, sendCode, testMessage, learn, eatTime, EVENTS,
  _test: {
    setTransport: fn => { _transportFactory = typeof fn === 'function' ? fn : null; },
    idle: () => Promise.all([..._pending]),
  },
};
