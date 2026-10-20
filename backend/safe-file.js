// ── Files that survive a power cut ───────────────────────────────────────────
// A laptop that loses power while Windows is still holding a write in its cache
// can leave a file full of zero bytes (seen in the field: users.json became
// all NULs and the owner account was lost). So:
//   writeDurable: write a temp file, flush it to the disk (fsync), then rename
//     it over the real one. With { backup: true } the same content is also kept
//     as <file>.bak, flushed the same way.
//   readJsonDurable: a file that is unreadable (bad JSON, zero bytes, all NULs)
//     is moved aside as <file>.damaged-<time> and, when <file>.bak is good, put
//     back from the backup. Nothing is ever overwritten without a copy. With
//     { keepDamaged: true } a damaged file with no good backup stays in place.
// A missing file is not damage: the user may have moved it aside on purpose
// (for example to reset the accounts), so it is never restored from .bak.
const fs = require('fs');
const path = require('path');

function writeSynced(file, data, mode) {
  const fd = fs.openSync(file, 'w', mode);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
}

function replaceSynced(file, data, mode) {
  const tmp = file + '.' + process.pid + '.' + Math.random().toString(16).slice(2, 10) + '.tmp';
  try { writeSynced(tmp, data, mode); }
  catch (e) { try { fs.rmSync(tmp, { force: true }); } catch (_) {} throw e; }
  try { fs.renameSync(tmp, file); }
  catch (e) {
    // Windows: antivirus/indexer can hold the target open for a moment; write in place.
    try { writeSynced(file, data, mode); } finally { try { fs.rmSync(tmp, { force: true }); } catch (_) {} }
  }
}

function writeDurable(file, data, opts = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const mode = opts.mode === undefined ? 0o600 : opts.mode;
  replaceSynced(file, data, mode);
  if (opts.backup) {
    try { replaceSynced(file + '.bak', data, mode); }
    catch (e) { (opts.log || console.log)('   ⚠ Could not update the backup of ' + path.basename(file) + ': ' + e.message); }
  }
}

function parseOrNull(raw) {
  if (!raw || !raw.replace(/\u0000/g, '').trim()) return { empty: true };
  try { return { value: JSON.parse(raw) }; } catch (e) { return { error: e }; }
}

function stamp() { return new Date().toISOString().replace(/[:.]/g, '-'); }

// Returns { value, state } where state is 'ok' | 'missing' | 'empty' | 'restored' | 'damaged'.
// 'empty' (zero bytes) counts as damage when a good backup exists.
function readJsonDurable(file, opts = {}) {
  const log = opts.log || console.log;
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch (e) { if (e.code === 'ENOENT') return { value: undefined, state: 'missing' }; throw e; }
  const p = parseOrNull(raw);
  if (p.value !== undefined) return { value: p.value, state: 'ok' };
  let bak;
  if (opts.backup) { try { bak = parseOrNull(fs.readFileSync(file + '.bak', 'utf8')); } catch (_) { bak = null; } }
  const goodBak = bak && bak.value !== undefined;
  if (p.empty && !raw.includes('\u0000') && !goodBak) return { value: undefined, state: 'empty' };
  const name = path.basename(file);
  // No good backup and the caller wants the damaged file left where it is (the
  // accounts file: a damaged one must never turn into "no accounts, set up again").
  if (!goodBak && opts.keepDamaged) return { value: undefined, state: 'damaged', error: p.error };
  const aside = file + '.damaged-' + stamp();
  try { fs.renameSync(file, aside); }
  catch (_) { try { fs.copyFileSync(file, aside); } catch (_) {} }
  if (goodBak) {
    try { replaceSynced(file, JSON.stringify(bak.value, null, 2), opts.mode === undefined ? 0o600 : opts.mode); } catch (_) {}
    log('   ⚠ ' + name + ' was damaged (probably a power cut) and was restored from its backup. The damaged copy is kept as ' + path.basename(aside) + '.');
    return { value: bak.value, state: 'restored' };
  }
  log('   ⚠ ' + name + ' was damaged (probably a power cut) and there is no good backup. It was moved aside as ' + path.basename(aside) + '.');
  return { value: undefined, state: 'damaged' };
}

module.exports = { writeDurable, readJsonDurable };
