// Two top-level `function x()` declarations with the same name silently replace
// each other (the later one wins everywhere), which once turned the credit-note
// applicationTime into an object. Keep every top-level function name unique.
const fs = require('fs');
const path = require('path');

for (const file of ['server.js', 'activity.js', 'auth.js', 'vault.js', 'logger.js', 'log-tools.js', 'console-ui.js']) {
  test(`${file} has no duplicate top-level function names`, () => {
    const p = path.join(__dirname, '..', file);
    if (!fs.existsSync(p)) return;
    const names = [...fs.readFileSync(p, 'utf8').matchAll(/^(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\(/gm)].map(m => m[1]);
    const dup = names.filter((n, i) => names.indexOf(n) !== i);
    expect(dup).toEqual([]);
  });
}
