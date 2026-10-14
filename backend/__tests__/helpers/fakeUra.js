'use strict';
// A tiny stand-in for URA EFRIS (or, with plain: true, the URA Offline Mode
// Enabler) on 127.0.0.1. It speaks the EFRIS envelope the relay sends:
//   POST { data: { content, signature, dataDescription }, globalInfo: { interfaceCode, ... }, returnStateInfo }
// and answers the same envelope.
//
// URA style (default): T104 hands out an AES-256 key, RSA-PKCS#1 v1.5 encrypted
// with the PUBLIC key of a keypair made here; the relay gets the PRIVATE key
// through config.efrisKeyPem. Later requests (encryptCode '2') are AES-ECB
// encrypted with that key and so are the answers.
// Enabler style (plain): no key exchange (T104 answers rc 998); requests and
// answers are plain base64 JSON.
const http = require('http');
const crypto = require('crypto');

let _keys = null;   // one RSA keypair per test process is enough
function keypair() {
  if (!_keys) _keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  return _keys;
}

const b64 = s => Buffer.from(s, 'utf8').toString('base64');

function createFakeUra({ plain = false } = {}) {
  const { publicKey, privateKey } = keypair();
  const aesKey = crypto.randomBytes(32);
  const aesEnc = s => { const c = crypto.createCipheriv('aes-256-ecb', aesKey, null); return Buffer.concat([c.update(s, 'utf8'), c.final()]).toString('base64'); };
  const aesDec = s => { const d = crypto.createDecipheriv('aes-256-ecb', aesKey, null); return Buffer.concat([d.update(Buffer.from(s, 'base64')), d.final()]).toString('utf8'); };
  // Answer content: encrypted for URA style, plain base64 for the Enabler.
  const encode = obj => (plain ? b64(JSON.stringify(obj)) : aesEnc(JSON.stringify(obj)));

  const fake = {
    plain, aesKey, privateKeyPem: privateKey,
    calls: [],                 // every request: { code, encrypted, signature, body (decoded JSON or null) }
    nextFdn: 'FDN123',
    t109Error: null,           // { rc, msg } to make T109 a business rejection
    t106Records: [],
    t111Records: [],
    on: {},                    // per-interface override: code -> (call) => { rc, msg, content }
    port: 0, server: null,
    get url() {
      // URA style uses the decimal form of 127.0.0.1: the relay treats any
      // "http://127..." / "localhost" URL as the Offline Enabler (plain, no T104),
      // so the URA fake needs an address that does not look local but still
      // resolves to loopback (new URL() normalises 2130706433 to 127.0.0.1).
      return plain
        ? 'http://127.0.0.1:' + this.port + '/efristcs/ws/tcsapp/getInformation'
        : 'http://2130706433:' + this.port + '/efrisws/ws/taapp/getInformation';
    },
    codes() { return this.calls.map(c => c.code); },
    callsOf(code) { return this.calls.filter(c => c.code === code); },
    reset() { this.calls = []; },
  };

  function answer(rc, msg, content, extra) {
    return {
      data: { content: content == null ? '' : content, signature: '', dataDescription: { codeType: '1', encryptCode: plain ? '1' : '2', zipCode: '0' }, ...(extra || {}) },
      globalInfo: { interfaceCode: '', responseCode: 'TP' },
      returnStateInfo: { returnCode: rc, returnMessage: msg },
    };
  }

  function handle(code, call) {
    if (fake.on[code]) {
      const o = fake.on[code](call) || {};
      return answer(o.rc || '00', o.msg || 'SUCCESS', o.content === undefined ? '' : (typeof o.content === 'string' ? o.content : encode(o.content)));
    }
    switch (code) {
      case 'T101': return answer('00', 'SUCCESS', b64(JSON.stringify({ currentTime: '09/10/2026 10:00:00' })));
      case 'T104': {
        if (plain) return answer('998', 'Interface not supported');
        const passowrdDes = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(aesKey.toString('base64'), 'utf8')).toString('base64');
        return answer('00', 'SUCCESS', b64(JSON.stringify({ passowrdDes, sign: '' })));
      }
      case 'T103': return answer('00', 'SUCCESS', encode({ taxType: [{ taxTypeName: 'Value Added Tax', taxTypeCode: '101' }], taxpayer: { tin: call.tin, legalName: 'Test Traders Ltd' } }));
      case 'T109':
        if (fake.t109Error) return answer(fake.t109Error.rc, fake.t109Error.msg);
        return answer('00', 'SUCCESS', encode({ basicInformation: { invoiceNo: fake.nextFdn, antifakeCode: 'AF1', invoiceId: 'ID1' } }));
      case 'T127': return answer('00', 'SUCCESS', encode({ records: [], page: { pageNo: 1, pageCount: 1, totalSize: 0 } }));
      case 'T106': return answer('00', 'SUCCESS', encode({ records: fake.t106Records, page: { pageNo: 1, pageCount: 1, totalSize: fake.t106Records.length } }));
      case 'T111': return answer('00', 'SUCCESS', encode({ records: fake.t111Records, page: { pageNo: 1, pageCount: 1, totalSize: fake.t111Records.length } }));
      case 'T121': return answer('00', 'SUCCESS', encode({ currency: (call.body && call.body.currency) || 'USD', rate: '3700.50' }));
      case 'T110': return answer('00', 'SUCCESS', encode({ referenceNo: (call.body && call.body.sellersReferenceNo) || '', id: 'APP1' }));
      default: return answer('99', 'Unknown interface ' + code + ' (fake URA)');
    }
  }

  function onRequest(req, res) {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', () => {
      let env = {};
      try { env = JSON.parse(raw); } catch (_) {}
      const gi = env.globalInfo || {}, data = env.data || {};
      const encrypted = String((data.dataDescription || {}).encryptCode) === '2';
      let body = null;
      try {
        const s = data.content ? (encrypted ? aesDec(data.content) : Buffer.from(data.content, 'base64').toString('utf8')) : '';
        body = s ? JSON.parse(s) : null;
      } catch (_) { body = '<undecodable>'; }
      const call = { code: gi.interfaceCode, tin: gi.tin, deviceNo: gi.deviceNo, encrypted, signature: data.signature, dataDescription: data.dataDescription, body };
      fake.calls.push(call);
      const out = JSON.stringify(handle(gi.interfaceCode, call));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(out);
    });
  }

  fake.start = (port) => new Promise((resolve, reject) => {
    fake.server = http.createServer(onRequest);
    fake.server.once('error', reject);
    fake.server.listen(port || fake.port || 0, '127.0.0.1', () => { fake.port = fake.server.address().port; resolve(fake); });
  });
  // Stop listening AND drop the relay's kept-alive sockets, so the next call
  // really gets "connection refused" (URA unreachable).
  fake.stop = () => new Promise(resolve => {
    if (!fake.server) return resolve();
    const s = fake.server; fake.server = null;
    s.close(() => resolve());
    if (s.closeAllConnections) s.closeAllConnections();
  });
  return fake;
}

module.exports = { createFakeUra };
