/*
 * EFRIS Connect - remove the Windows service.
 * Run in an ADMIN Command Prompt:  node uninstall-service.js
 */
const path = require('path');
let Service;
try {
  ({ Service } = require('node-windows'));
} catch (e) {
  console.error('\n  node-windows is not installed (nothing to remove), or run: npm install node-windows\n');
  process.exit(1);
}

const svc = new Service({
  name: 'EFRISConnect',
  script: path.join(__dirname, '..', 'backend', 'server.js'),
});

svc.on('uninstall', () => console.log('  EFRIS Connect service removed.'));
svc.on('error', (e) => console.error('  Service error:', e));

console.log('  Removing EFRIS Connect service…');
svc.uninstall();
