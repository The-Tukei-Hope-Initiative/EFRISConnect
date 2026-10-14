#!/usr/bin/env node
'use strict';
// Look up the URA tax rule (standard / zero-rated / exempt / deemed, excise) of
// commodity codes, with the credentials of the first vault business whose TIN is
// EFRIS_TIN (default 1015292010, the sandbox taxpayer). Uses the relay's own
// lookup (T124, T146 fallback) without starting the relay.
//
//   node backend/tools/commodity-tax.js 10151609 50221109 51132201
//
// Prints only code, name and rule. Never prints credentials.
const codes = process.argv.slice(2).filter(a => /^\d{1,10}$/.test(a));
if (!codes.length) { console.error('Usage: node backend/tools/commodity-tax.js <commodity code> [more codes...]'); process.exit(2); }
const TIN = process.env.EFRIS_TIN || '1015292010';

// The relay logs every step; keep this tool's output to the answer.
const out = console.log.bind(console);
const err = console.error.bind(console);
const quiet = !process.env.VERBOSE;
if (quiet) { console.log = () => {}; console.info = () => {}; console.warn = () => {}; console.error = () => {}; }

(async () => {
  let code = 0;
  try {
    const app = require('../server');
    const vault = app._vault;
    const meta = vault.listTenants().find(t => String(t.tin) === TIN);
    if (!meta) throw new Error('No business with TIN ' + TIN + ' in the vault (set EFRIS_TIN to choose another).');
    const t = vault.getTenant(meta.id);
    const cfg = { tin: t.tin, deviceNo: t.deviceNo, efrisPassword: t.efrisPassword, mode: t.mode,
      efrisKeyPem: t.efrisPrivateKeyPem, efrisKeyPath: t.efrisPrivateKeyPath, efrisKeyPassphrase: t.efrisPassphrase };
    const res = await app._test.lookupCommodityTax(codes, cfg);
    out('TIN ' + TIN + ' (' + (t.mode || 'sandbox') + ')');
    for (const c of codes) {
      const r = res[c] || { rule: 'unknown', label: 'no answer' };
      const dates = [r.exemptRateStartDate && 'exempt from ' + r.exemptRateStartDate, r.exemptRateEndDate && 'exempt until ' + r.exemptRateEndDate,
        r.zeroRateStartDate && 'zero from ' + r.zeroRateStartDate, r.zeroRateEndDate && 'zero until ' + r.zeroRateEndDate].filter(Boolean).join(', ');
      out(c + '  ' + (r.name || '(no name)') + '  ->  ' + (r.label || r.rule) + (dates ? '  [' + dates + ']' : '') + (r.source ? '  (' + r.source + ')' : '') + (r.error ? '  error: ' + r.error : ''));
    }
  } catch (e) {
    err('Failed: ' + (e && e.message));
    code = 1;
  }
  process.exit(code);
})();
