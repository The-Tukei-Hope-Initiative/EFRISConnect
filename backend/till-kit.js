'use strict';
// Till kit for the shop network (LAN): a folder in the data folder holding what a
// till PC needs to trust this relay's HTTPS certificate, so a till never needs
// the EFRISConnect files. Copy the folder to a USB stick or share it.
//
//   till-kit/
//     https_cert.cer (or EFRISConnect.crt off Windows)  public certificate only
//     Trust EFRISConnect server.bat                     imports it into Trusted Root (self-elevates)
//     Remove EFRISConnect trust.bat                     removes it again
//     README.txt                                        the addresses to open
//
// Never copies the PFX, its password file or a private key: the certificate
// source is refused if it contains key material.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KIT_DIR = 'till-kit';
const FORBIDDEN = /PRIVATE KEY/;

// The public certificate the relay serves: https_cert.cer (DER or PEM, Windows
// setup) or https_cert.pem (openssl setup). Returns { file, buf, ext } or null.
function findPublicCert(dataDir) {
  for (const [name, ext] of [['https_cert.cer', '.cer'], ['https_cert.pem', '.crt']]) {
    const p = path.join(dataDir, name);
    try {
      const buf = fs.readFileSync(p);
      if (FORBIDDEN.test(buf.toString('latin1'))) continue;   // a key bundled in: never ship it
      return { file: p, buf, ext };
    } catch (_) {}
  }
  return null;
}

// SHA-1 thumbprint (what certutil -delstore takes), '' when unreadable.
function thumbprint(buf) {
  try {
    return new crypto.X509Certificate(buf).fingerprint.replace(/:/g, '');   // PEM or DER
  } catch (_) { return ''; }
}

const crlf = s => s.replace(/\r?\n/g, '\r\n');
// Batch-safe text: drop characters cmd.exe would interpret.
const batSafe = s => String(s || '').replace(/[^A-Za-z0-9._:\/\- ]/g, '');

function trustBat(certName, urls) {
  return crlf([
    '@echo off',
    'REM Trust the EFRISConnect server certificate on this till PC.',
    'REM Imports the PUBLIC certificate next to this file into Trusted Root (Local Machine).',
    'setlocal',
    'cd /d "%~dp0"',
    'net session >nul 2>&1',
    'if not "%errorlevel%"=="0" (',
    '  echo Asking for administrator rights...',
    '  powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"',
    '  exit /b 0',
    ')',
    'if not exist "%~dp0' + certName + '" ( echo Could not find ' + certName + ' next to this file. & pause & exit /b 1 )',
    'certutil -addstore -f Root "%~dp0' + certName + '"',
    'if errorlevel 1 (',
    '  echo.',
    '  echo   FAILED: the certificate was not trusted. See the message above.',
    '  pause',
    '  exit /b 1',
    ')',
    'echo.',
    'echo   Done: this PC now trusts the EFRISConnect server.',
    'echo   Open EFRISConnect in a browser (Edge or Chrome):',
    ...urls.map(u => 'echo     ' + batSafe(u)),
    'echo   or open Manager Server in the browser and use its EFRISConnect buttons.',
    'echo   Restart the browser first if it was open.',
    'pause',
    'exit /b 0',
    '',
  ].join('\n'));
}

function removeBat(thumb) {
  const target = thumb || 'EFRISConnect Local HTTPS';
  return crlf([
    '@echo off',
    'REM Remove the EFRISConnect server certificate from Trusted Root on this PC.',
    'setlocal',
    'net session >nul 2>&1',
    'if not "%errorlevel%"=="0" (',
    '  powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"',
    '  exit /b 0',
    ')',
    'certutil -delstore Root "' + batSafe(target) + '"',
    'if errorlevel 1 ( echo   Nothing removed - it may not be trusted on this PC. ) else ( echo   Removed: this PC no longer trusts the EFRISConnect server certificate. )',
    'pause',
    'exit /b 0',
    '',
  ].join('\n'));
}

function readme(o) {
  return crlf([
    'EFRISConnect till kit (shop network)',
    '====================================',
    '',
    'Server PC: ' + (o.hostname || '(unknown)'),
    'Made: ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC',
    '',
    'On each till PC (Windows), once:',
    '  1. Copy this whole folder to the till (USB stick or a shared folder).',
    '  2. Double-click "Trust EFRISConnect server.bat" and allow the administrator prompt.',
    '  3. Restart the browser.',
    '',
    'Then open EFRISConnect in Edge or Chrome:',
    ...o.urls.map(u => '  ' + u),
    '',
    'Sign in with your own EFRISConnect user (for example a cashier).',
    '',
    o.managerUrls && o.managerUrls.length ? 'Manager Server Edition on the server PC (open it in the browser):' : '',
    ...(o.managerUrls || []).map(u => '  ' + u),
    o.managerUrls && o.managerUrls.length ? '  Its EFRISConnect custom buttons must point at ' + (o.urls[0] || '') : '',
    '',
    'The till PC must be on the same private Wi-Fi/LAN as the server, and Windows must',
    'call that network "Private" (Settings > Network > the network > Private).',
    '',
    'To undo: run "Remove EFRISConnect trust.bat"',
    '(or as administrator: certutil -delstore Root ' + (o.thumb || '"EFRISConnect Local HTTPS"') + ').',
    '',
    'This folder holds only the PUBLIC certificate. It contains no password and no key.',
    'Other systems: import ' + o.certName + ' as a trusted root certificate',
    '(macOS: Keychain Access > System > Certificates; Android: Settings > Security > Install certificate).',
    '',
  ].filter((l, i, a) => !(l === '' && a[i - 1] === '')).join('\n'));
}

// Writes the kit. o: { hostname, urls: [relay URLs], managerUrls: [Manager Server URLs] }.
// Returns { dir, files } or { error } (no certificate yet).
function writeTillKit(dataDir, o) {
  o = o || {};
  const cert = findPublicCert(dataDir);
  if (!cert) return { error: 'No HTTPS certificate in ' + dataDir + ' yet: run the HTTPS setup first.' };
  const dir = path.join(dataDir, KIT_DIR);
  fs.mkdirSync(dir, { recursive: true });
  const certName = cert.ext === '.cer' ? 'https_cert.cer' : 'EFRISConnect.crt';
  const thumb = thumbprint(cert.buf);
  const urls = (o.urls || []).filter(Boolean);
  const files = {
    [certName]: cert.buf,
    'Trust EFRISConnect server.bat': trustBat(certName, urls),
    'Remove EFRISConnect trust.bat': removeBat(thumb),
    'README.txt': readme({ hostname: o.hostname, urls, managerUrls: o.managerUrls || [], certName, thumb }),
  };
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  // Anything else in the folder (an older kit, a file someone dropped in) stays,
  // but never key material.
  for (const f of fs.readdirSync(dir)) {
    if (/\.(pfx|p12|key)$/i.test(f) || /pass/i.test(f)) { try { fs.unlinkSync(path.join(dir, f)); } catch (_) {} }
  }
  return { dir, files: Object.keys(files) };
}

module.exports = { writeTillKit, findPublicCert, KIT_DIR };
