'use strict';
// Reset a lost owner password (both the password and the recovery code lost).
//
//   node backend/reset-owner.js [owner-name]
//
// Run it on the relay's computer as an administrator (Windows: the launcher's
// "Reset owner password" option; Linux/macOS: unix/reset-owner.sh). It writes a
// one-time reset code, valid 24 hours, to "EFRIS Connect setup code.txt" in the
// data folder, which only administrators and the service can read. Then, on the
// relay's own computer, open EFRIS Connect, choose "Forgot password", and enter
// the owner name, that code and a new password. The relay does not need to be
// restarted. Only the hash of the code is kept (owner-reset.json).
//
// When email is set up (Settings > Email) and an owner has an email address, the
// owners are also sent an alert that a reset code was made on this computer. The
// code itself is never emailed.
const os = require('os');
const auth = require('./auth');
const mailer = require('./mailer');
const { DATA_DIR } = require('./paths');

function main() {
  const name = (process.argv[2] || '').trim();
  try {
    const r = auth.writeResetCode(name || null);
    console.log('');
    console.log('EFRIS Connect owner reset code written.');
    console.log('');
    console.log('  File:  ' + r.file);
    console.log('  Owner' + (r.owners.length > 1 ? 's' : '') + ': ' + r.owners.join(', ') + (name ? '   (code works for "' + name + '" only)' : ''));
    console.log('');
    console.log('Open that file to read the code (it is valid for 24 hours and works once).');
    console.log('Then, ON THIS COMPUTER, open EFRIS Connect, choose "Forgot password",');
    console.log('and enter the owner name, the code and a new password.');
    console.log('');
    return 0;
  } catch (e) {
    console.error('');
    console.error('Could not write a reset code: ' + e.message);
    console.error('Data folder: ' + DATA_DIR + ' (run this as an administrator).');
    console.error('');
    return 1;
  }
}

// Alert the owners by email (best effort: no email set up, no address, or no
// internet just means no alert). Resolves to the number of alerts sent.
async function notifyOwners(ownerName) {
  try {
    if (!mailer.isConfigured()) return 0;
    const owners = auth.listOwners();
    if (!owners.some(o => o.email && !o.disabled)) return 0;
    const target = ownerName ? owners.find(o => o.name.toLowerCase() === String(ownerName).trim().toLowerCase()) : null;
    const sends = mailer.alert('reset-code-generated', {
      owners, user: target || null, host: os.hostname(), computer: 'the computer that runs EFRIS Connect (' + os.hostname() + ')',
    });
    const results = await Promise.all(sends);
    const ok = results.filter(x => x && x.success).length;
    if (ok) console.log('An alert was emailed to the owner' + (ok > 1 ? 's' : '') + ' (it does not contain the code).');
    else if (results.length) console.log('The email alert to the owner could not be sent (check Settings > Email). The reset code still works.');
    return ok;
  } catch (_) { return 0; }
}

if (require.main === module) {
  process.exitCode = main();
  if (process.exitCode === 0) notifyOwners((process.argv[2] || '').trim()).then(() => {}, () => {});
}
module.exports = { main, notifyOwners };
