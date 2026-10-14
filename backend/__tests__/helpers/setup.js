'use strict';
// Runs before every test file (jest setupFilesAfterEnv).
//
// 1. Network guard: the suite must never reach URA, Manager or anything else on
//    the internet. Every outgoing TCP connection to a non-loopback host is
//    refused and recorded, and the test that caused it fails in afterEach.
// 2. Quiet console: the relay logs every step. Set TEST_VERBOSE=1 to see it.
const net = require('net');

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1']);

// Core modules are shared by all test files in a worker, so install once and keep
// the list of refused connections on the module itself.
if (!net.Socket.prototype.__efcGuard) {
  const realConnect = net.Socket.prototype.connect;
  net.__efcBlocked = [];
  net.Socket.prototype.connect = function guardedConnect(...args) {
    let o = args[0];
    if (Array.isArray(o)) o = o[0];   // net.createConnection passes normalized args
    let host;
    if (o && typeof o === 'object') {
      if (o.path) return realConnect.apply(this, args);   // IPC / named pipe
      host = o.host;
    } else if (typeof o === 'number' || /^\d+$/.test(String(o))) {
      host = args[1];
    } else {
      return realConnect.apply(this, args);               // IPC path string
    }
    host = host == null || host === '' ? 'localhost' : String(host);
    if (!LOOPBACK.has(host)) {
      net.__efcBlocked.push(host);
      const err = new Error('Test network guard: connection to ' + host + ' refused (tests must stay on 127.0.0.1)');
      err.code = 'ENETUNREACH';
      process.nextTick(() => this.destroy(err));
      return this;
    }
    return realConnect.apply(this, args);
  };
  net.Socket.prototype.__efcGuard = true;
}

afterEach(() => {
  const blocked = net.__efcBlocked.splice(0);
  if (blocked.length) throw new Error('Test tried to reach non-loopback host(s): ' + [...new Set(blocked)].join(', '));
});

if (!process.env.TEST_VERBOSE) {
  for (const m of ['log', 'info', 'warn', 'error']) jest.spyOn(console, m).mockImplementation(() => {});
}
