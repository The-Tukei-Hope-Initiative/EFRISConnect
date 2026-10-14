'use strict';
// A tiny stand-in for Manager.io's API2 on 127.0.0.1. The relay is given
// managerEndpoint = fake.url and appends /api2 itself (normEp).
//
//   GET  /api2/<list>            -> { <camelCaseList>: lists[<list>] }   e.g. bank-and-cash-accounts
//   GET  /api2/<x>-form/<key>    -> forms[<x>-form][<key>] or 404
//   POST /api2/<x>-form          -> stores the body under a new key; 201 with
//                                   Location: /api2/<x>-form/<key> and { key }
//                                   (only the Location header when locationOnly
//                                   includes <x>-form)
//   PUT  /api2/<x>-form/<key>    -> replaces the stored body
//   POST /api2/<x>-form/<key>    -> updates a stored form (404 when unknown)
// Every request is recorded in `requests` for assertions.
const http = require('http');

const camel = s => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

function createFakeManager() {
  let seq = 0;
  const fake = {
    lists: {},
    forms: {},
    locationOnly: new Set(),
    requests: [],
    port: 0, server: null,
    get url() { return 'http://127.0.0.1:' + this.port; },
    posts(form) { return this.requests.filter(r => r.method === 'POST' && r.path === '/api2/' + form).map(r => r.body); },
    reset() { this.requests = []; },
  };

  function send(res, status, obj, headers) {
    res.writeHead(status, { 'Content-Type': 'application/json', ...(headers || {}) });
    res.end(obj === undefined ? '' : JSON.stringify(obj));
  }

  function onRequest(req, res) {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', () => {
      const u = new URL(req.url, 'http://127.0.0.1');
      let body = null; try { body = raw ? JSON.parse(raw) : null; } catch (_) { body = raw; }
      fake.requests.push({ method: req.method, path: u.pathname, query: Object.fromEntries(u.searchParams), body, headers: req.headers });
      if (!u.pathname.startsWith('/api2/')) return send(res, 404, { error: 'not api2' });
      const seg = u.pathname.slice('/api2/'.length).split('/').filter(Boolean);
      const [name, key] = seg;
      if (name.endsWith('-form')) {
        const store = fake.forms[name] = fake.forms[name] || {};
        if (req.method === 'GET') return key && store[key] ? send(res, 200, store[key]) : send(res, 404, { error: 'not found' });
        if (req.method === 'POST' && !key) {
          const k = name.replace(/-form$/, '') + '-' + (++seq);
          store[k] = body;
          const loc = { Location: '/api2/' + name + '/' + k };
          return fake.locationOnly.has(name) ? send(res, 201, undefined, loc) : send(res, 201, { key: k }, loc);
        }
        if (req.method === 'PUT' && key) { store[key] = body; return send(res, 200, { key }); }
        if (req.method === 'POST' && key) { if (!store[key]) return send(res, 404, { error: 'not found' }); store[key] = body; return send(res, 200, { key }); }
        return send(res, 405, { error: 'method' });
      }
      if (req.method === 'GET' && seg.length === 1) {
        const skip = parseInt(u.searchParams.get('skip') || '0', 10) || 0;
        const all = fake.lists[name] || [];
        return send(res, 200, { [camel(name)]: skip ? [] : all, totalRecords: all.length });
      }
      return send(res, 404, { error: 'unknown route' });
    });
  }

  fake.start = () => new Promise((resolve, reject) => {
    fake.server = http.createServer(onRequest);
    fake.server.once('error', reject);
    fake.server.listen(0, '127.0.0.1', () => { fake.port = fake.server.address().port; resolve(fake); });
  });
  fake.stop = () => new Promise(resolve => {
    if (!fake.server) return resolve();
    const s = fake.server; fake.server = null;
    s.close(() => resolve());
    if (s.closeAllConnections) s.closeAllConnections();
  });
  return fake;
}

module.exports = { createFakeManager };
