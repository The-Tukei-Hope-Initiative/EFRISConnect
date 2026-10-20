'use strict';
// The watchdog ends a relay that has not ticked for 2 minutes, except while code
// has announced that it is waiting on purpose (the vault waiting for Windows).
const { isStalled, STALL_MS } = require('../watchdog');

const T = 1_000_000n, S = BigInt(STALL_MS);

test('a recent tick is not a stall', () => {
  expect(isStalled(T, 0n, T + 5000n, S)).toBe(false);
});
test('no tick for longer than 2 minutes is a stall', () => {
  expect(isStalled(T, 0n, T + S + 1n, S)).toBe(true);
});
test('an announced block is not a stall until it runs out', () => {
  expect(isStalled(T, T + S + 60000n, T + S + 1000n, S)).toBe(false);
  expect(isStalled(T, T + S + 60000n, T + S + 60001n, S)).toBe(true);
});
test('the watchdog is 2 minutes', () => { expect(STALL_MS).toBe(120000); });
