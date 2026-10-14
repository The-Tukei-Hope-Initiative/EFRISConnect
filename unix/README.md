# macOS / Linux helper scripts

Equivalents of the Windows helpers in `../windows/`. All are optional - you can
always just run `./start.sh` from the repo root.

- **../start.sh** - launch the relay (the everyday launcher).
- **setup-https.sh** - generate a local self-signed HTTPS certificate into
  `backend/data/` so Manager loads the button over HTTPS. For automatic browser
  trust, prefer `mkcert` (see `../docs/self-hosting.md`).
- **install-service.sh** - run EFRISConnect in the background as a service:
  systemd on Linux, a launchd LaunchAgent on macOS. Auto-starts on boot/login and
  restarts on failure.
- **uninstall-service.sh** - remove that service.
- **start-lan.sh** - start the relay for the shop network (LAN): binds to the
  network, allows this computer's name, `name.local` and private IPv4 addresses,
  and prints the till addresses. Makes no firewall changes (it prints a hint).
  See "Shop network (LAN)" in `../docs/self-hosting.md`.

Make them executable once if needed: `chmod +x unix/*.sh start.sh`.

Requirements: Node.js 20+ and (for setup-https.sh) openssl.
