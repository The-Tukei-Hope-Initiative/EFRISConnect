/*
 * EFRIS Connect - install as a Windows service (most robust uptime).
 *
 * A Windows service starts at boot, before anyone logs in, and stays running
 * in the background - so the relay is always available to catch offline
 * documents and to serve till/POS browsers on a LAN.
 *
 * One-time setup (run in an ADMIN Command Prompt from the repo root):
 *     cd windows
 *     npm install node-windows
 *     node install-service.js
 *
 * To remove it later:  node uninstall-service.js
 */
const path = require('path');
let Service;
try {
  ({ Service } = require('node-windows'));
} catch (e) {
  console.error('\n  node-windows is not installed. Run:\n    npm install node-windows\n  then re-run:  node install-service.js\n');
  process.exit(1);
}

const svc = new Service({
  name: 'EFRISConnect',
  description: 'EFRIS Connect relay - Manager.io <-> URA EFRIS integration.',
  script: path.join(__dirname, '..', 'backend', 'server.js'),
  workingDirectory: path.join(__dirname, '..', 'backend'),
  // Restart on crash; keep logs under the service's daemon folder.
  wait: 2,
  grow: 0.5,
  maxRestarts: 10,
});

svc.on('install', () => {
  console.log('  EFRIS Connect service installed. Starting…');
  svc.start();
});
svc.on('alreadyinstalled', () => { console.log('  Service is already installed - making sure it is running…'); svc.start(); });
svc.on('start', () => console.log('  EFRIS Connect service is running - use https://localhost:5443/extension in Manager.'));
svc.on('error', (e) => console.error('  Service error:', e));

// One-step first setup: we're already elevated (service install needs admin), so
// also generate + trust the local HTTPS cert now. This is what lets Manager
// (Desktop / Docker-Desktop, all on localhost) load the extension over HTTPS,
// fully offline. Skipped gracefully if PowerShell/cert setup isn't available.
try {
  const { execSync } = require('child_process');
  const dataDir = path.join(__dirname, '..', 'backend', 'data');
  const ps = path.join(__dirname, 'setup-https.ps1');
  console.log('  Setting up local HTTPS certificate (trusted, offline)…');
  execSync('powershell -NoProfile -ExecutionPolicy Bypass -File "' + ps + '" -DataDir "' + dataDir + '"', { stdio: 'inherit' });
  console.log('  Local HTTPS ready → use https://localhost:5443/extension in Manager.');
} catch (e) {
  console.error('  HTTPS cert setup skipped:', e.message);
  console.error('  You can set it up later: run windows\\EFRISConnect.bat -> "First-time HTTPS setup".');
}

console.log('  Installing EFRIS Connect as a Windows service (requires admin)…');
svc.install();
