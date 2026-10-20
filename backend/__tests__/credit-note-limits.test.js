'use strict';
// A credit note is checked before URA sees it: within 90 days of the original,
// never more than is left on it after earlier credit notes, never at a higher price.
const { loadRelay } = require('./helpers/relay');

const TIN = '1000123456';
const DAY = 86400000;
let relay, T;
beforeAll(() => { relay = loadRelay(); T = relay.app._test; });
afterAll(() => relay.cleanup());

const orig = (daysAgo, extra) => ({
  id: 'o1', status: 'success', fdn: 'F100', tin: TIN, submittedAt: new Date(Date.now() - daysAgo * DAY).toISOString(), totalAmount: 3000,
  lines: [{ name: 'Soda', orderNumber: 0, qty: 2, unitPrice: 1000 }, { name: 'Bread', orderNumber: 1, qty: 1, unitPrice: 1000 }], ...extra });
const cn = (lines, extra) => ({ id: 'c' + Math.random(), kind: 'credit-note', status: 'success', originalFdn: 'F100', tin: TIN,
  totalAmount: -lines.reduce((s, l) => s + l.qty * l.unitPrice, 0), lines, ...extra });
const line = (orderNumber, qty, unitPrice) => ({ orderNumber: String(orderNumber), qty: String(-qty), unitPrice: String(unitPrice), total: String(-qty * unitPrice), discountFlag: '2', item: 'x' });

test('within the limits: no problem', () => {
  relay.writeJson('submission_log.json', [orig(10)]);
  expect(T.cnLimitProblem('F100', TIN, [line(0, 1, 1000)])).toBeNull();
});

test('older than 90 days: refused with the date', () => {
  relay.writeJson('submission_log.json', [orig(91)]);
  expect(T.cnLimitProblem('F100', TIN, [line(0, 1, 1000)])).toMatch(/only within 90 days/);
});

test('more than is left after an earlier credit note: refused', () => {
  relay.writeJson('submission_log.json', [orig(5), cn([{ orderNumber: 0, qty: 2, unitPrice: 1000 }])]);
  expect(T.cnLimitProblem('F100', TIN, [line(0, 1, 1000)])).toMatch(/Soda.*only 0 of 2 is left/);
  // A rejected or withdrawn earlier credit note does not count.
  relay.writeJson('submission_log.json', [orig(5), cn([{ orderNumber: 0, qty: 2, unitPrice: 1000 }], { approveStatus: '103' })]);
  expect(T.cnLimitProblem('F100', TIN, [line(0, 1, 1000)])).toBeNull();
});

test('a higher price than the original: refused', () => {
  relay.writeJson('submission_log.json', [orig(5)]);
  expect(T.cnLimitProblem('F100', TIN, [line(1, 1, 1500)])).toMatch(/Bread.*higher than the original price 1000/);
});

test('total over what is left: refused even without line detail', () => {
  relay.writeJson('submission_log.json', [orig(5, { lines: undefined }), cn([{ orderNumber: 0, qty: 2, unitPrice: 1000 }])]);
  expect(T.cnLimitProblem('F100', TIN, [line(1, 1, 1500)])).toMatch(/more than is left to credit on F100: 1,000 of 3,000 is left/);
});

test('original not on this computer: left to URA', () => {
  relay.writeJson('submission_log.json', []);
  expect(T.cnLimitProblem('F100', TIN, [line(0, 50, 1000)])).toBeNull();
});
