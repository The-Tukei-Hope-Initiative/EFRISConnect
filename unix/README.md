# macOS / Linux helper scripts

Equivalents of the Windows helpers in `../windows/`. All are optional: you can
always run `./start.sh` from the repository root.

- **../start.sh**: start the relay (the everyday launcher). Runs `npm install`
  the first time.
- **setup-https.sh**: create a self-signed HTTPS certificate in `backend/data/`
  (`https_cert.pem`, `https_key.pem`) for `localhost`, this computer's name,
  `name.local` and its private IP addresses. Needs `openssl`. For automatic
  browser trust, `mkcert` is an alternative (see `../docs/self-hosting.md`).
- **install-service.sh**: run the relay in the background (systemd on Linux, a
  launchd LaunchAgent on macOS). Starts at boot or login and restarts on failure.
- **uninstall-service.sh**: remove that service.
- **start-lan.sh**: start the relay for the shop network (LAN). Sets `BIND_HOST`,
  `ALLOWED_HOSTS` (this computer's name, `name.local`, private IPv4 addresses),
  `LAN_MODE=1` and `MANAGER_PORTS` (default 5000), and prints the till addresses.
  It makes no firewall changes. See "Shop network (LAN)" in
  `../docs/self-hosting.md`.
- **reset-owner.sh**: create a one-time owner reset code when the owner has lost
  both the password and the recovery code (the same as Windows launcher option 7).

Make them executable once if needed: `chmod +x unix/*.sh start.sh`.

Requirements: Node.js 20 or newer, and `openssl` for `setup-https.sh`.
