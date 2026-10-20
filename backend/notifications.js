// ── Notification centre ──────────────────────────────────────────────────────
// Built from the relay's activity log, the record it already keeps of what
// happened (90 days). Every log line that matches a rule below becomes a
// notification, so events from before this feature existed show up too, and
// nothing has to be recorded twice. Read / unread is kept per user in
// notifications_read.json in the data folder.
const fs = require('fs');
const path = require('path');

// pattern -> notification. perm = what the reader needs in that business.
const RULES = [
  { re: /Credit note (\S+) approved by URA: FDN (\S+)/, kind: 'credit-approved', level: 'success', perm: 'credit',
    title: () => 'Credit note approved by URA', body: m => `Credit note ${m[1]} was approved. FDN ${m[2]}.` },
  { re: /Credit note (\S+) is now (.+) at URA/, kind: 'credit-status', level: 'warning', perm: 'credit',
    title: () => 'Credit note status changed', body: m => `Credit note ${m[1]} is now "${m[2]}" at URA.` },
  { re: /Credit note (\S+): FDN (\S+) (?:and verification code )?written to Manager/, kind: 'credit-written', level: 'info', perm: 'credit',
    title: () => 'Credit note updated in Manager', body: m => `FDN ${m[2]} of credit note ${m[1]} was written to the Manager credit note.` },
  { re: /Credit note (\S+): no Manager credit note with reference (.+); not written/, kind: 'credit-not-written', level: 'warning', perm: 'credit',
    title: () => 'Credit note not found in Manager', body: m => `URA approved ${m[1]}, but no Manager credit note has the reference ${m[2]}. Create it in Manager with that reference; EFRISConnect will then fill in the FDN.` },
  { re: /Offline queue: (\d+) queued document\(s\) fiscalised automatically(?: \(([^)]*)\))?: (.+)/, kind: 'queue-sent', level: 'success', perm: 'queue',
    title: () => 'Sales saved offline were sent to URA', body: m => `${m[1]} sale${m[1] === '1' ? '' : 's'} saved offline received an FDN: ${m[3]}.` },
  { re: /Offline queue: (\S+) was rejected by URA \((.+)\)/, kind: 'queue-rejected', level: 'critical', perm: 'queue',
    title: () => 'A sale saved offline was rejected by URA', body: m => `${m[1]}: ${m[2]}. Correct it and submit it again from the offline queue.` },
  { re: /Offline queue: URA is reachable again - sending (\d+) queued/, kind: 'online', level: 'info', perm: 'queue',
    title: () => 'URA is reachable again', body: m => `Sending ${m[1]} sale${m[1] === '1' ? '' : 's'} saved offline.` },
  { re: /Offline queue: (\d+) sales? ha(?:s|ve) waited more than 24 hours for URA/, kind: 'queue-overdue', level: 'critical', perm: 'queue',
    title: () => 'Sales waiting more than 24 hours for URA', body: m => `${m[1]} sale${m[1] === '1' ? ' has' : 's have'} no FDN after 24 hours. Start the Offline Enabler (Settings) so sales get an FDN, or call URA support if URA is down.` },
  { re: /Update available: EFRISConnect (\S+)( \(security update\))? - (https:\/\/\S+)/, kind: 'update', level: 'info', perm: 'admin',
    title: m => (m[2] ? 'Security update: EFRISConnect ' : 'EFRISConnect ') + m[1] + ' is available', body: m => (m[2] ? 'Install it soon: it fixes a security problem. ' : '') + 'Download it from the release page and run Setup; your data and settings are kept.' },
  { re: /Offline Enabler (start|stop|restart)(?:: done| failed: (.+))/, kind: 'enabler', level: 'info', perm: 'admin',
    title: m => 'Offline Enabler ' + (m[2] ? m[1] + ' failed' : m[1] === 'stop' ? 'stopped' : 'started'), body: m => m[2] || 'Done.' },
];
// The document a notification is about, to open it in Documents.
const REFS = { 'credit-approved': m => m[1], 'credit-status': m => m[1], 'credit-written': m => m[1], 'credit-not-written': m => m[1],
  'queue-sent': m => String(m[3]).split(' ')[0], 'queue-rejected': m => m[1] };
RULES.forEach(r => {
  if (REFS[r.kind]) r.ref = REFS[r.kind];
  if (r.kind === 'enabler') r.levelFor = m => (m[2] ? 'critical' : 'info');
  if (r.kind === 'update') { r.levelFor = m => (m[2] ? 'critical' : 'info'); r.link = m => m[3]; }
  if (r.kind === 'credit-status') r.levelFor = m => (/reject|fail|cancel/i.test(m[2]) ? 'critical' : 'info');
});

function match(entry) {
  const text = String(entry.text || '');
  for (const r of RULES) {
    const m = r.re.exec(text);
    if (m) return { kind: r.kind, level: r.levelFor ? r.levelFor(m) : r.level, perm: r.perm, title: r.title(m), body: r.body(m), ref: r.ref ? r.ref(m) : '', link: r.link ? r.link(m) : '' };
  }
  return null;
}

function create(opts) {
  const activity = opts.activity;
  const readFile = path.join(opts.dataDir, 'notifications_read.json');
  const write = opts.writeFileAtomic || ((f, d) => fs.writeFileSync(f, d));
  const pastCache = new Map();   // day -> notifications (past days never change)
  let today = { day: '', list: [], seq: -Infinity };

  function fromEntries(day, entries) {
    const out = [];
    for (const e of entries) {
      const n = match(e);
      if (n) out.push(Object.assign(n, { id: day + '#' + e.seq, time: e.time, tenantId: e.tenantId || '' }));
    }
    return out;
  }
  function forDay(day) {
    if (day === activity.eatDay()) {
      if (today.day !== day) today = { day, list: fromEntries(day, activity.entries({ day })), seq: activity.lastSeq() };
      else {
        const fresh = activity.entries({ day, after: today.seq });
        if (fresh.length) { today.list = today.list.concat(fromEntries(day, fresh)); today.seq = fresh[fresh.length - 1].seq; }
      }
      return today.list;
    }
    if (!pastCache.has(day)) pastCache.set(day, fromEntries(day, activity.entries({ day })));
    return pastCache.get(day);
  }
  // Every notification this reader may see in this business, newest first.
  function visible(tenantId, mayRead) {
    const out = [];
    for (const day of activity.listDays()) {
      for (const n of forDay(day)) if ((n.tenantId === tenantId || !n.tenantId) && mayRead(n.perm)) out.push(n);
    }
    return out.sort((a, b) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0));
  }

  function loadState() { try { return JSON.parse(fs.readFileSync(readFile, 'utf8')) || {}; } catch (_) { return {}; } }
  // A user's first look: the last day stays unread, older history shows as read.
  function userState(all, userId) {
    if (!all[userId]) all[userId] = { readBefore: new Date(Date.now() - 24 * 3600000).toISOString(), read: [], unread: [] };
    return all[userId];
  }
  function isRead(st, n) { return st.read.includes(n.id) || (n.time <= st.readBefore && !st.unread.includes(n.id)); }

  function list({ userId, tenantId, mayRead, limit = 30, before = '' }) {
    const all = loadState(), st = userState(all, userId);
    const items = visible(tenantId, mayRead);
    const unread = items.filter(n => !isRead(st, n)).length;
    let start = 0;
    if (before) { const i = items.findIndex(n => n.id === before); start = i < 0 ? items.length : i + 1; }
    const page = items.slice(start, start + Math.min(Math.max(1, limit), 100)).map(n => ({
      id: n.id, time: n.time, kind: n.kind, level: n.level, title: n.title, body: n.body, ref: n.ref || '', link: n.link || '', read: isRead(st, n) }));
    return { items: page, unread, total: items.length, more: start + page.length < items.length };
  }
  function count({ userId, tenantId, mayRead }) {
    const st = userState(loadState(), userId);
    return visible(tenantId, mayRead).filter(n => !isRead(st, n)).length;
  }
  function mark({ userId, ids, read }) {
    const all = loadState(), st = userState(all, userId);
    for (const id of ids) {
      st.read = st.read.filter(x => x !== id); st.unread = st.unread.filter(x => x !== id);
      (read ? st.read : st.unread).push(id);
    }
    st.read = st.read.slice(-2000); st.unread = st.unread.slice(-2000);
    write(readFile, JSON.stringify(all));
  }
  function markAll({ userId }) {
    const all = loadState(), st = userState(all, userId);
    st.readBefore = new Date().toISOString(); st.read = []; st.unread = [];
    write(readFile, JSON.stringify(all));
  }
  return { list, count, mark, markAll };
}

module.exports = { create, match, RULES };
