'use strict';
// Relay console hotkeys: one key press acts once; pasted text does nothing.
const { makeKeyHandler } = require('../console-ui');

function setup() {
  let t = 1000;
  const calls = [];
  const act = k => () => calls.push(k);
  const h = makeKeyHandler({ quit: act('quit'), o: act('o'), l: act('l'), c: act('c'), s: act('s'), d: act('d'), q: act('q') }, () => t);
  return { h, calls, tick: ms => { t += ms; } };
}

describe('console hotkeys', () => {
  test('a single key press runs its action (upper or lower case, Buffer or string)', () => {
    const { h, calls, tick } = setup();
    h(Buffer.from('o')); tick(500); h('D'); tick(500); h('s');
    expect(calls).toEqual(['o', 'd', 's']);
  });

  test('pasted text (a multi-character chunk) is ignored', () => {
    const { h, calls } = setup();
    expect(h('Hello, open debug status copy')).toBeNull();
    expect(h(Buffer.from('ODCS'))).toBeNull();
    expect(h('\x1b[A')).toBeNull();   // arrow key escape sequence
    expect(calls).toEqual([]);
  });

  test('the same key repeated within 400 ms counts once', () => {
    const { h, calls, tick } = setup();
    h('o'); tick(50); h('o'); tick(100); h('o'); tick(450); h('o');
    expect(calls).toEqual(['o', 'o']);
  });

  test('different keys in quick succession each act; unknown keys do nothing', () => {
    const { h, calls, tick } = setup();
    h('o'); tick(10); h('x'); tick(10); h('d');
    expect(calls).toEqual(['o', 'd']);
  });

  test('Ctrl+C quits, alone or inside a chunk', () => {
    const { h, calls } = setup();
    expect(h('\u0003')).toBe('quit');
    expect(h('abc\u0003')).toBe('quit');
    expect(calls).toEqual(['quit', 'quit']);
  });
});
