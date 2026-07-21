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

Make them executable once if needed: `chmod +x unix/*.sh start.sh`.

Requirements: Node.js 18+ and (for setup-https.sh) openssl.
