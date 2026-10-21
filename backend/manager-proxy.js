// ── HTTPS front for Manager Server Edition (shop network) ────────────────────
// Manager Server only speaks plain HTTP, so on a shop network the tills' Manager
// passwords and business data would cross the Wi-Fi unencrypted. In LAN mode the
// relay also listens on MANAGER_HTTPS_PORT (default: Manager's port + 1) with the
// same certificate the tills already trust, and passes every request through to
// Manager Server on this PC (127.0.0.1:<Manager port>). Nothing on the tills
// changes except the address: https://<server>:5001 instead of http://<server>:5000.
const http = require('http');
const https = require('https');
const net = require('net');
const { Duplex } = require('stream');

// Hop-by-hop headers are for one connection only and are never forwarded.
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate']);

function forwardHeaders(req, remoteAddr) {
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k.toLowerCase())) h[k] = v;
  const prior = req.headers['x-forwarded-for'];
  h['x-forwarded-for'] = prior ? prior + ', ' + remoteAddr : remoteAddr;
  h['x-forwarded-proto'] = 'https';
  if (req.headers.host) h['x-forwarded-host'] = req.headers.host;
  return h;
}

// Manager builds some redirects as absolute http:// URLs. Point them back at the
// HTTPS address the browser used, so a redirect never drops to plain HTTP.
function rewriteLocation(loc, reqHost, targetPort) {
  if (!loc || !reqHost) return loc;
  try {
    const u = new URL(loc);
    const sameHost = u.host.toLowerCase() === String(reqHost).toLowerCase();
    const isTarget = /^(127\.0\.0\.1|localhost)$/i.test(u.hostname) && String(u.port || '80') === String(targetPort);
    const isPlainSameName = u.protocol === 'http:' && u.hostname.toLowerCase() === String(reqHost).toLowerCase().replace(/:\d+$/, '') && String(u.port || '80') === String(targetPort);
    if (u.protocol === 'http:' && (sameHost || isTarget || isPlainSameName)) return 'https://' + reqHost + u.pathname + u.search + u.hash;
  } catch (_) { /* relative Location: leave as is */ }
  return loc;
}

function unavailablePage(port) {
  return '<!doctype html><meta charset="utf-8"><title>Manager is not running</title>' +
    '<body style="font-family:system-ui,sans-serif;max-width:560px;margin:60px auto;line-height:1.5;color:#222">' +
    '<h2 style="color:#1b5e20">Manager Server is not running</h2>' +
    '<p>EFRISConnect could not reach Manager Server on the shop server (port ' + port + ').</p>' +
    '<p>On the shop server, open the EFRISConnect Control Centre (desktop shortcut or the icon next to the clock) and click Start next to Manager Server Edition. It is ready in about 30 seconds; then reload this page.</p></body>';
}

// Someone typed http:// for the encrypted port: answer with a redirect to https://
// on the same address instead of a blank "empty response" page. Built from the
// first bytes of the plain request; only safe host and path characters are kept.
function plainHttpRedirect(firstBytes, port) {
  const text = firstBytes.toString('latin1');
  const line = (text.split('\r\n')[0] || '').split(' ');
  const pathPart = /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@%\/?]*$/.test(line[1] || '') ? line[1] : '/';
  const hm = text.match(/\r\nhost:[ \t]*([^\r\n]+)/i);
  let host = hm ? hm[1].trim() : '';
  if (!/^[A-Za-z0-9.\-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/.test(host)) host = 'localhost:' + port;
  const loc = 'https://' + host + pathPart;
  const body = 'Use the encrypted address: ' + loc + '\n';
  return 'HTTP/1.1 301 Moved Permanently\r\nLocation: ' + loc + '\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ' +
    Buffer.byteLength(body) + '\r\nConnection: close\r\n\r\n' + body;
}

// Hand an already-read connection to the TLS server: Node's TLS layer reads from
// the socket handle directly and would miss the bytes taken to sniff it, so wrap
// it in a stream that replays them first.
function replayStream(sock, first) {
  const d = new Duplex({
    read() { sock.resume(); },
    write(chunk, enc, cb) { sock.write(chunk, enc, cb); },
    final(cb) { sock.end(); cb(); },
    destroy(err, cb) { sock.destroy(); cb(err); },
  });
  d.push(first);
  sock.on('data', c => { if (!d.push(c)) sock.pause(); });
  sock.on('end', () => d.push(null));
  sock.on('close', () => d.destroy());
  return d;
}

// opts: { tls, port, bindHost, targetPort, targetHost?, log? }. Returns a net.Server
// (listen / on('error') as usual): TLS connections go to the HTTPS proxy, plain
// HTTP ones get a redirect to https.
function startManagerProxy(opts) {
  const server = https.createServer(opts.tls, proxyHandler(opts));
  attachUpgrade(server, opts);
  // Manager backups and imports can take minutes: no overall request time limit.
  server.requestTimeout = 0;
  const front = net.createServer(sock => {
    sock.on('error', () => {});
    sock.once('data', buf => {
      sock.pause();
      if (buf[0] === 0x16) { server.emit('connection', replayStream(sock, buf)); return; }   // TLS handshake
      sock.end(plainHttpRedirect(buf, opts.port));
    });
  });
  front.httpsServer = server;
  return front;
}

// The request handler on its own (tests run it on plain HTTP).
function proxyHandler(opts) {
  const targetHost = opts.targetHost || '127.0.0.1';
  const log = opts.log || (() => {});
  return (req, res) => {
    const up = http.request({ host: targetHost, port: opts.targetPort, method: req.method, path: req.url,
      headers: forwardHeaders(req, req.socket.remoteAddress || '') }, (r) => {
      const headers = {};
      for (const [k, v] of Object.entries(r.headers)) if (!HOP.has(k.toLowerCase())) headers[k] = v;
      if (headers.location) headers.location = rewriteLocation(headers.location, req.headers.host, opts.targetPort);
      res.writeHead(r.statusCode || 502, r.statusMessage, headers);
      r.pipe(res);
    });
    up.on('error', (e) => {
      if (!res.headersSent) { res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(unavailablePage(opts.targetPort)); }
      else res.destroy();
      if (e.code !== 'ECONNREFUSED') log('Manager HTTPS: ' + req.method + ' ' + req.url.split('?')[0] + ' failed: ' + e.message);
    });
    req.pipe(up);
  };
}

// WebSocket and other upgrades: pass the raw connection through.
function attachUpgrade(server, opts) {
  const targetHost = opts.targetHost || '127.0.0.1';
  server.on('upgrade', (req, socket, head) => {
    const up = http.request({ host: targetHost, port: opts.targetPort, method: req.method, path: req.url,
      headers: Object.assign(forwardHeaders(req, socket.remoteAddress || ''), { connection: 'Upgrade', upgrade: req.headers.upgrade }) });
    up.on('upgrade', (r, upSocket, upHead) => {
      const lines = ['HTTP/1.1 ' + r.statusCode + ' ' + r.statusMessage];
      for (let i = 0; i < r.rawHeaders.length; i += 2) lines.push(r.rawHeaders[i] + ': ' + r.rawHeaders[i + 1]);
      socket.write(lines.join('\r\n') + '\r\n\r\n');
      if (upHead && upHead.length) socket.write(upHead);
      if (head && head.length) upSocket.write(head);
      upSocket.pipe(socket).pipe(upSocket);
      upSocket.on('error', () => socket.destroy()); socket.on('error', () => upSocket.destroy());
    });
    up.on('response', (r) => { socket.end('HTTP/1.1 ' + r.statusCode + ' ' + r.statusMessage + '\r\n\r\n'); });
    up.on('error', () => socket.destroy());
    up.end();
  });
}

module.exports = { startManagerProxy, proxyHandler, rewriteLocation, forwardHeaders, plainHttpRedirect };
