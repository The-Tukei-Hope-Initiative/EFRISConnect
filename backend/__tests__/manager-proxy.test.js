/**
 * HTTPS front for Manager Server (manager-proxy.js): requests and bodies reach
 * Manager unchanged, redirects never drop to plain HTTP, and a stopped Manager
 * gives a clear page instead of a hung request.
 */
const http = require('http');
const { proxyHandler, rewriteLocation, forwardHeaders } = require('../manager-proxy');

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}
function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path, headers }, res => {
      let data = ''; res.on('data', c => { data += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

describe('Manager HTTPS front', () => {
  let manager, managerPort, proxy, proxyPort, seen;
  beforeAll(async () => {
    manager = http.createServer((req, res) => {
      let body = ''; req.on('data', c => { body += c; });
      req.on('end', () => {
        seen = { method: req.method, url: req.url, headers: req.headers, body };
        if (req.url === '/abs') { res.writeHead(302, { Location: 'http://' + req.headers.host + '/login' }); return res.end(); }
        if (req.url === '/rel') { res.writeHead(302, { Location: '/login' }); return res.end(); }
        res.writeHead(200, { 'Content-Type': 'text/plain', 'Set-Cookie': 'm=1; Path=/' });
        res.end('ok ' + req.method);
      });
    });
    managerPort = await listen(manager);
    proxy = http.createServer(proxyHandler({ targetPort: managerPort }));
    proxyPort = await listen(proxy);
  });
  afterAll(() => { proxy.close(); manager.close(); });

  test('passes method, path, body and cookies through; keeps the browser Host', async () => {
    const r = await request(proxyPort, { method: 'POST', path: '/receipt-form?x=1', headers: { Host: 'shop-pc:5001', 'Content-Type': 'application/x-www-form-urlencoded', Cookie: 'a=b' }, body: 'Qty=2' });
    expect(r.status).toBe(200);
    expect(r.body).toBe('ok POST');
    expect(r.headers['set-cookie']).toEqual(['m=1; Path=/']);
    expect(seen.url).toBe('/receipt-form?x=1');
    expect(seen.body).toBe('Qty=2');
    expect(seen.headers.host).toBe('shop-pc:5001');
    expect(seen.headers.cookie).toBe('a=b');
    expect(seen.headers['x-forwarded-proto']).toBe('https');
  });

  test('an absolute http:// redirect comes back as https on the same address', async () => {
    const r = await request(proxyPort, { path: '/abs', headers: { Host: 'shop-pc:5001' } });
    expect(r.status).toBe(302);
    expect(r.headers.location).toBe('https://shop-pc:5001/login');
  });

  test('a relative redirect is left alone', async () => {
    const r = await request(proxyPort, { path: '/rel', headers: { Host: 'shop-pc:5001' } });
    expect(r.headers.location).toBe('/login');
  });

  test('Manager not running: 502 with an explanation', async () => {
    const dead = http.createServer(proxyHandler({ targetPort: 1 }));
    const p = await listen(dead);
    const r = await request(p);
    dead.close();
    expect(r.status).toBe(502);
    expect(r.body).toMatch(/Manager Server is not running/);
  });
});

describe('rewriteLocation / forwardHeaders', () => {
  test('loopback Manager address becomes the browser address', () => {
    expect(rewriteLocation('http://127.0.0.1:5000/x?y=1', 'shop-pc:5001', 5000)).toBe('https://shop-pc:5001/x?y=1');
    expect(rewriteLocation('http://shop-pc:5000/x', 'shop-pc:5001', 5000)).toBe('https://shop-pc:5001/x');
  });
  test('other sites and https URLs are untouched', () => {
    expect(rewriteLocation('https://manager.io/help', 'shop-pc:5001', 5000)).toBe('https://manager.io/help');
    expect(rewriteLocation('http://example.com/', 'shop-pc:5001', 5000)).toBe('http://example.com/');
  });
  test('hop-by-hop headers are dropped', () => {
    const h = forwardHeaders({ headers: { connection: 'keep-alive', 'keep-alive': 'timeout=5', host: 'a:1', cookie: 'c' } }, '192.168.1.9');
    expect(h.connection).toBeUndefined();
    expect(h['keep-alive']).toBeUndefined();
    expect(h.cookie).toBe('c');
    expect(h['x-forwarded-for']).toBe('192.168.1.9');
  });
});

describe('plain http:// on the encrypted port', () => {
  const { plainHttpRedirect } = require('../manager-proxy');
  const loc = raw => plainHttpRedirect(Buffer.from(raw), 5001).split('\r\n').find(l => l.startsWith('Location:'));
  test('redirects to https on the address the browser used, keeping the path', () => {
    expect(loc('GET /receipts?x=1 HTTP/1.1\r\nHost: shop-pc:5001\r\n\r\n')).toBe('Location: https://shop-pc:5001/receipts?x=1');
  });
  test('odd paths and hosts fall back to safe values (no header injection)', () => {
    expect(loc('GET /a<script> HTTP/1.1\r\nHost: shop-pc:5001\r\n\r\n')).toBe('Location: https://shop-pc:5001/');
    expect(loc('GET / HTTP/1.1\r\nHost: a b\r\n\r\n')).toBe('Location: https://localhost:5001/');
    expect(plainHttpRedirect(Buffer.from('GET / HTTP/1.1\r\nHost: x\r\nSet-Cookie: y\r\n\r\n'), 5001)).not.toMatch(/Set-Cookie/);
  });
});
