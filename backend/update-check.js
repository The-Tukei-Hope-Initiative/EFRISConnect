// ── Update check ─────────────────────────────────────────────────────────────
// Once a day the relay asks GitHub for the latest public EFRISConnect release (one
// read-only request to api.github.com; nothing about the business, users or sales is
// sent). A newer version is written to the log as one line, which the notification
// centre shows to admins. A release whose notes are marked "[security]" (or start
// with "Security update") is a security update: it is announced again every day
// until this relay runs that version. Admins can turn the check off.
const fs = require('fs');
const path = require('path');
const https = require('https');

const RELEASES = 'https://api.github.com/repos/The-Tukei-Hope-Initiative/EFRISConnect/releases/latest';
const DAY = 24 * 3600000;

// "1.0.10" > "1.0.9"; a leading "v" is ignored.
function newer(a, b) {
  const p = v => String(v || '').replace(/^v/i, '').split(/[.-]/).map(x => parseInt(x, 10) || 0);
  const x = p(a), y = p(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); }
  return false;
}
// A security update for this installation. Notes that name who needs it ("Security
// update for anyone on 1.0.17 or earlier") count only for those versions.
function isSecurity(notes, version) {
  const t = String(notes || '');
  if (!/\[security\]|^\s*security update/im.test(t)) return false;
  const m = /^\s*security update for anyone on v?(\d+(?:\.\d+)*) or earlier/im.exec(t);
  return !(m && version && newer(version, m[1]));
}

function create({ dataDir, version, log, get }) {
  const file = path.join(dataDir, 'update_check.json');
  const read = () => { try { return JSON.parse(fs.readFileSync(file, 'utf8')) || {}; } catch (_) { return {}; } };
  const save = s => { try { fs.writeFileSync(file, JSON.stringify(s)); } catch (_) {} };
  const fetchJson = get || (url => new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'EFRISConnect/' + version, Accept: 'application/vnd.github+json' }, timeout: 15000 }, r => {
      let d = ''; r.on('data', c => { d += c; if (d.length > 2e6) req.destroy(); });
      r.on('end', () => { if (r.statusCode !== 200) return reject(new Error('GitHub answered HTTP ' + r.statusCode)); try { resolve(JSON.parse(d)); } catch (e) { reject(e); } });
    });
    req.on('timeout', () => req.destroy(new Error('timed out'))); req.on('error', reject);
  }));

  function status() {
    const s = read();
    return { enabled: s.enabled !== false, current: version, latest: s.latest || '', security: !!s.security, url: s.url || '', checkedAt: s.checkedAt || '', available: !!(s.latest && newer(s.latest, version)) };
  }
  async function check(force) {
    const s = read();
    if (s.enabled === false && !force) return status();
    try {
      const rel = await fetchJson(RELEASES);
      const latest = String(rel.tag_name || '').replace(/^v/i, '');
      Object.assign(s, { latest, security: isSecurity(rel.body, version), url: rel.html_url || '', checkedAt: new Date().toISOString() });
      if (latest && newer(latest, version)) {
        const again = s.security && (!s.announcedAt || Date.now() - Date.parse(s.announcedAt) > DAY - 60000);
        if (s.announced !== latest || again) {
          log('   Update available: EFRISConnect ' + latest + (s.security ? ' (security update)' : '') + ' - ' + (s.url || 'https://github.com/The-Tukei-Hope-Initiative/EFRISConnect/releases'));
          s.announced = latest; s.announcedAt = new Date().toISOString();
        }
      }
      save(s);
    } catch (e) { s.lastError = e.message; s.checkedAt = new Date().toISOString(); save(s); }
    return status();
  }
  function setEnabled(on) { const s = read(); s.enabled = !!on; save(s); return status(); }
  function start() {
    const t1 = setTimeout(() => check().catch(() => {}), 2 * 60000); t1.unref && t1.unref();
    const t2 = setInterval(() => check().catch(() => {}), DAY); t2.unref && t2.unref();
  }
  return { status, check, setEnabled, start };
}

module.exports = { create, newer, isSecurity };
