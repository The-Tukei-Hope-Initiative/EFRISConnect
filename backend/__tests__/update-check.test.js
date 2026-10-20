'use strict';
// Update check: version comparison, security releases, and when a newer version is
// announced (once; a security update again each day). Uses a fake GitHub answer.
const fs = require('fs'), os = require('os'), path = require('path');
const { create, newer, isSecurity } = require('../update-check');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'efc-upd-'));
const release = (tag, body) => async () => ({ tag_name: tag, body, html_url: 'https://github.com/The-Tukei-Hope-Initiative/EFRISConnect/releases/tag/' + tag });

test('version comparison', () => {
  expect(newer('1.0.10', '1.0.9')).toBe(true);
  expect(newer('v1.0.8', '1.0.7')).toBe(true);
  expect(newer('1.0.7', '1.0.7')).toBe(false);
  expect(newer('1.0.6', '1.0.7')).toBe(false);
});
test('security releases are recognised from their notes', () => {
  expect(isSecurity('[security] fixes a session problem')).toBe(true);
  expect(isSecurity('Security update: please install')).toBe(true);
  expect(isSecurity('New: notification centre')).toBe(false);
});
test('a newer release is announced once', async () => {
  const lines = []; const u = create({ dataDir: tmp(), version: '1.0.7', log: t => lines.push(t), get: release('v1.0.8', 'New things') });
  const s = await u.check(true);
  expect(s).toMatchObject({ available: true, latest: '1.0.8', security: false });
  await u.check(true);
  expect(lines).toHaveLength(1);
  expect(lines[0]).toMatch(/Update available: EFRISConnect 1\.0\.8 - https:\/\/github\.com\//);
});
test('nothing is announced when this is the latest version', async () => {
  const lines = []; const u = create({ dataDir: tmp(), version: '1.0.8', log: t => lines.push(t), get: release('v1.0.8', '') });
  expect((await u.check(true)).available).toBe(false);
  expect(lines).toHaveLength(0);
});
test('turned off: no automatic check, but Check now still works', async () => {
  const lines = []; const u = create({ dataDir: tmp(), version: '1.0.7', log: t => lines.push(t), get: release('v1.0.8', '[security] fix') });
  u.setEnabled(false);
  await u.check(false);
  expect(lines).toHaveLength(0);
  await u.check(true);
  expect(lines[0]).toMatch(/\(security update\)/);
});
