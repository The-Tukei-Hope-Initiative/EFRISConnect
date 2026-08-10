# Running EFRIS Connect on Windows (Manager Desktop / Server)

The extension is a small local server (`backend/server.js`). Everything you need to
run it is in **one file: `EFRISConnect.bat`**. Double-click it and pick from the menu:

```
1) Start EFRIS Connect            (use this every day)
2) First-time HTTPS setup         (run once - admin)
3) Start automatically at logon
4) Install as Windows service     (server/always-on - admin)
5) Trust a server's certificate   (LAN till only - admin)
6) Uninstall auto-start / service
```

The admin steps (2, 4, 5) relaunch themselves elevated - you don't need to open an
admin prompt yourself. **Node.js LTS** (https://nodejs.org) must be installed first.

---

## One URL: `https://localhost:5443`

The relay serves a single canonical address, **`https://localhost:5443`**
(extension at **`https://localhost:5443/extension`**). HTTPS is required because
Manager only injects the current receipt/invoice context into a custom button over
HTTPS - so the "open this document and fiscalise it" flow only works on `https://`.

Port `3000` still exists as a fallback for first-run (before the certificate is set
up); once HTTPS is running, opening `http://localhost:3000` in a browser just
redirects you to `https://localhost:5443`. Use the HTTPS URL everywhere in Manager.

---

## First-time setup (once)

1. Double-click **`EFRISConnect.bat`** -> option **2) First-time HTTPS setup**.
   It generates ONE locally-trusted certificate covering `localhost`, `127.0.0.1`,
   this machine's hostname and its LAN IP(s), installs it into the machine's Trusted
   Root store, and writes `https.pfx` / `https_cert.cer` into `backend\data`.
   100% offline - no internet, no OpenSSL, valid 10 years.
2. Back in the menu -> option **1) Start EFRIS Connect**. Watch for
   `HTTPS running at https://localhost:5443`.
3. In Manager, set each EFRIS custom-button **Endpoint** to
   **`https://localhost:5443/extension`**.
4. Open a receipt/invoice and click the button - it loads that document ready to
   fiscalise.

For always-on machines, use option **3** (auto-start at logon) or **4** (Windows
service) instead of leaving the console window open.

---

## LAN / multi-till setup

Run the relay on **one** machine - the "fiscalisation host":

1. On the host: option **4) Install as Windows service** (starts at boot, restarts
   on crash, and also sets up + trusts the HTTPS cert in the same elevated step).
   If other machines must reach it, set `BIND_HOST=0.0.0.0` before starting.
2. On each till/POS PC: copy the host's `backend\data\https_cert.cer` next to
   `EFRISConnect.bat`, run option **5) Trust a server's certificate**, then point
   Manager at **`https://SERVER-NAME:5443/extension`**.
3. Install URA's **Offline Mode Enabler** on the **host only** (not every till) and
   set its URL in **Settings -> Offline Mode**, so all tills share one
   offline-capable fiscalisation point.

## Offline Mode Enabler (true offline FDN)

The relay always queues documents when URA is unreachable and auto-submits them on
reconnect. For a **valid FDN with no internet at all**, install URA's *EFRIS Offline
Mode Enabler* on this machine/LAN and enter its local `getInformation` URL in
**Settings -> Offline Mode**. Confirm the exact host/port from your Enabler
installation. The extension routes submissions to the Enabler (fallback or always)
using the same secure EFRIS protocol.

## Notes

- Requires **Node.js LTS** (https://nodejs.org).
- Canonical URL: **`https://localhost:5443/extension`** (port `3000` redirects here
  once HTTPS is up, and serves as the first-run fallback before the cert exists).
- The EFRIS private key path is set inside `EFRISConnect.bat` (option 1); edit it to
  match your setup. The cloud edition instead uses the `EFRIS_PRIVATE_KEY_B64` secret.
- The offline queue is stored in `backend/data/offline_queue.json` (never committed).
