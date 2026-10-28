# Self-hosting EFRISConnect

EFRISConnect runs on Windows, macOS and Linux. It is a Node.js relay plus a page
that opens inside Manager. Everything here is free and needs no account with
anyone except URA.

On Windows, the installer is the easiest route: see
[../installer/README.md](../installer/README.md). This guide covers the manual
install and the shop network in detail.

## Requirements

- Node.js 20 or newer (https://nodejs.org). The Windows installer bundles its own.
- Manager.io Desktop or Server Edition, and a Manager API access token for the
  business.
- EFRIS registration from URA:
  - EFRIS / e-invoicing registration.
  - A registered device (device number) with the thumbprint registration done.
  - The EFRIS private key (`.pem`) for that device, and its passphrase if set.

Test in the URA EFRIS sandbox with test data only. Live use requires the business
to pass URA's EFRIS approval (UAT) and uses its own production device and keys.
EFRISConnect does not register devices or grant approval.

## Install

```
git clone https://github.com/The-Tukei-Hope-Initiative/EFRISConnect.git
cd EFRISConnect/backend
npm install
```

## Run

- macOS / Linux: `./start.sh` from the repository root, or `node server.js` from
  `backend/`.
- Windows: `windows\EFRISConnect.bat` option 1, or `node server.js` from `backend\`.

The relay listens on `127.0.0.1` only. It serves `https://localhost:5443/extension`
once a certificate exists, and `http://localhost:3000` before that.

## Local HTTPS

Manager needs an `https://` address for the custom button.

### Windows

`windows\EFRISConnect.bat` option **2** (or the installer) creates a self-signed
certificate for `localhost`, `127.0.0.1`, the PC name, `PCNAME.local` and its IP
addresses, trusts it on this computer, and writes `https.pfx` and
`https_cert.cer` to `C:\ProgramData\EFRISConnect\data`.

### macOS / Linux

The relay looks in `backend/data/` for `https.pfx` (with `https_pfx_pass.txt`),
or a PEM pair named `https_cert.pem` and `https_key.pem`.

Option A, `unix/setup-https.sh`: creates the PEM pair for `localhost`, the computer
name, `name.local` and its private IP addresses. Then trust the certificate:
- macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain backend/data/https_cert.pem`
- Debian / Ubuntu: `sudo cp backend/data/https_cert.pem /usr/local/share/ca-certificates/efrisconnect.crt && sudo update-ca-certificates`.
  Chrome and Firefox may keep their own certificate stores: import it there too.

Option B, mkcert (trust is automatic):
```
mkcert -install
mkcert localhost 127.0.0.1
cp localhost+1.pem     backend/data/https_cert.pem
cp localhost+1-key.pem backend/data/https_key.pem
```

Restart the relay. The console shows `HTTPS running at https://localhost:5443/extension`.

## First run

1. Open EFRISConnect from the Manager button (or the address above) on the
   computer that runs the relay.
2. Create the owner account. From another computer, enter the one-time setup code
   from `EFRISConnect setup code.txt` in the data folder (valid 24 hours).
3. Save the recovery code.
4. Enter the business details, EFRIS credentials (TIN, device number, private key)
   and the Manager endpoint and access token. Auto-detect finds Manager Desktop's
   port.
5. Keep Sandbox mode on. Use a URA sandbox account, a separate Manager test
   business and test data.
6. Add users and their roles (Admin, Accountant, Cashier) in Settings > Users.

## Connect in Manager

**Settings > Custom Buttons > New Custom Button**:
- Name `EFRISConnect`, Source `Url`.
- URL: `https://localhost:5443/extension` (shop network:
  `https://SERVER-NAME:5443/extension`).
- One button per placement: the Receipts and Sales Invoices lists, the single
  receipt and sales invoice pages, and the inventory and non-inventory item pages.
  Credit notes are raised inside EFRISConnect, so they need no separate button.

## Environment variables

A single computer needs none of these.

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port (default 3000). |
| `HTTPS_PORT` | HTTPS port (default 5443). |
| `BIND_HOST` | Interface to listen on (default `127.0.0.1`). Any other value requires `ALLOWED_HOSTS` and HTTPS or `TRUST_PROXY`. |
| `ALLOWED_HOSTS` | Host names (besides localhost) the relay answers to, comma separated. |
| `ALLOWED_ORIGINS` / `MANAGER_ORIGINS` | Other browser origins that may frame the extension and call the relay, for example a Manager Server on its own domain. |
| `TRUST_PROXY` | Reverse proxy whose `X-Forwarded-For` is trusted (Express syntax). Default `loopback`. |
| `VAULT_MASTER_KEY` | Base64 of 32 random bytes. Vault key instead of the local key file. See [../SECURITY.md](../SECURITY.md). |
| `DATA_DIR_OVERRIDE` | Data folder location. |
| `LAN_MODE`, `MANAGER_PORTS`, `MANAGER_HTTPS_PORT` | Shop network settings, see below. |
| `LOG_RETENTION_DAYS` | Days of log files to keep (default 90, at least 7). |
| `INTERNAL_API_KEY` | Enables an `X-API-KEY` header for automation (tests, scripts). Unset means no key. |
| `EFRIS_PRIVATE_KEY` | Path to, or content of, a fallback EFRIS private key. The key in Settings is preferred. |
| `MANAGER_INSECURE_TLS=1` | Skip certificate checks for a Manager with a self-signed certificate. Leave unset otherwise. |

Set a variable in the same terminal before `node server.js`:
- PowerShell: `$env:LOG_RETENTION_DAYS = "180"; node server.js`
- Command Prompt: `set LOG_RETENTION_DAYS=180` then `node server.js`
- macOS / Linux: `LOG_RETENTION_DAYS=180 node server.js`

Or put them in a `.env` file (see `.env.example`), or in your service manager's
configuration.

## Shop network (LAN)

One PC in the shop (the **server PC**) runs EFRISConnect and Manager Server
Edition. The tills (laptops, other PCs) reach it over the shop's own Wi-Fi or
cable network.

### Requirements

- All PCs on the same **private** network (addresses 10.x, 172.16-31.x or
  192.168.x). Guest Wi-Fi that isolates devices does not work.
- On the server PC, Windows must call that network **Private** (Settings >
  Network & internet > the network > Network profile type: Private). The firewall
  rules EFRISConnect adds apply to Private networks only.
- The HTTPS certificate on the server PC. Tills only connect over HTTPS.

### How it fits together

| What | Where | Address for tills |
|---|---|---|
| Manager Server Edition | server PC, `127.0.0.1:5000` only | `https://SERVER-NAME:5001` (served by EFRISConnect) |
| EFRISConnect | server PC, port 5443 | `https://SERVER-NAME:5443/extension` |

Manager Server only speaks plain HTTP. In shop network mode EFRISConnect also
listens on Manager's port + 1 (default 5001) with the same certificate and passes
each request to Manager Server on the server PC. Manager passwords and business
data are therefore encrypted on the network. Plain `http://` on port 5001 is
redirected to `https://`.

### Server PC with the installer

Run Setup and choose **Shop server**. Select `ManagerServer.exe` if it is
installed on this PC (Setup then starts it when you sign in to Windows) and its
port. Setup adds the firewall rules, starts the relay at Windows startup and
prints the addresses. The till kit is in `C:\ProgramData\EFRISConnect\data\till-kit`.

### Server PC with the launcher

1. `windows\EFRISConnect.bat` option **2** (admin, once). The certificate covers
   `localhost`, the PC name, `PCNAME.local` and the current IP addresses. Run it
   again if the IP address changes and tills use the IP.
2. Option **9**: start Manager Server. It asks once for the path to
   `ManagerServer.exe` and the port (default 5000; option **10** changes it later),
   then starts `ManagerServer.exe --urls http://127.0.0.1:5000`. If a data folder
   is saved in `manager-server-data.txt` in the data folder, it adds
   `--path "<folder>"`. Close Manager Desktop first: by default Manager Server uses
   the same business data folder, and both must never have it open at once.
3. Option **8**: start the relay for the shop network. It checks the certificate,
   adds the firewall rules "EFRISConnect HTTPS (LAN)" (TCP 5443) and "EFRISConnect
   Manager HTTPS (LAN)" (TCP 5001) on the Private profile (one admin prompt the
   first time), then starts the relay with `BIND_HOST=0.0.0.0`,
   `ALLOWED_HOSTS=<pcname>,<pcname>.local,<private IPs>`, `LAN_MODE=1`,
   `MANAGER_PORTS=5000` and `MANAGER_HTTPS_PORT=5001`. It prints the till
   addresses and warns if the network is set to Public.

### Both ways, then

1. In EFRISConnect (Settings > System), the Manager endpoint stays on the server
   PC: `http://127.0.0.1:5000/api2`.
2. In Manager Server > Settings > Custom Buttons, set every EFRISConnect button URL
   to `https://SERVER-NAME:5443/extension`, not `localhost`: the buttons are shared
   by every browser that opens Manager. EFRISConnect's Home page shows this URL in
   shop network mode.
3. Copy the **till kit** folder (`C:\ProgramData\EFRISConnect\data\till-kit`) to a
   USB stick or a shared folder. It holds only the public certificate
   (`https_cert.cer`), `Trust EFRISConnect server.bat`,
   `Remove EFRISConnect trust.bat` and a `README.txt` with the addresses. No key and
   no password.

### Each till, once

1. Run the installer and choose **Till** (it asks for `https_cert.cer` and the
   server name, and adds a "Manager (shop)" desktop shortcut), or run
   `Trust EFRISConnect server.bat` from the till kit and approve the admin prompt.
   Restart the browser.
2. Open Manager at `https://SERVER-NAME:5001`. Its EFRISConnect buttons open
   `https://SERVER-NAME:5443/extension`.
3. Sign in to EFRISConnect with the till's own user (for example a Cashier).

Undo on a till: `Remove EFRISConnect trust.bat`, or as administrator
`certutil -delstore Root "EFRISConnect Local HTTPS"`. On the server, launcher
option **6** (or uninstalling) removes the firewall rules.

### Browser only, no Manager on the tills

Tills trust the certificate as above and open `https://SERVER-NAME:5443/extension`
directly. A cashier signs in and issues receipts in EFRISConnect, which records
them in Manager on the server PC.

### macOS / Linux server

Run `unix/setup-https.sh`, then `unix/start-lan.sh` (it sets the same variables;
`MANAGER_PORTS=8080 unix/start-lan.sh` for another Manager port). It makes no
firewall changes: allow inbound TCP 5443 and Manager's port + 1 from the shop
network yourself. The till kit is written to `backend/data/till-kit`.

### With the internet off

Works: signing in, Manager on the server PC and through it on the tills, and
issuing receipts. Sales are recorded in Manager and wait in the offline queue
(or go through the URA Offline Mode Enabler if installed). They are sent to URA
automatically when the internet returns.

Needs the internet: checking a buyer's TIN with URA, credit note approval status,
URA exchange rates and the URA tax rule of a commodity code.

### Settings used in shop network mode

- `LAN_MODE=1`: the Manager button URL becomes
  `https://<first ALLOWED_HOSTS name>:5443/extension`; the Manager Server addresses
  (each `ALLOWED_HOSTS` name and IP on each Manager port) may frame the extension;
  the Manager HTTPS front starts; the till kit is written at start. Single-user
  mode is not available.
- `MANAGER_PORTS`: Manager Server port(s), comma separated (default 5000).
- `MANAGER_HTTPS_PORT`: port of the Manager HTTPS front (default: first Manager
  port + 1). `0` turns it off.

## Offline Enabler (optional)

EFRISConnect already queues sales when URA is unreachable and sends them once the
connection returns. Most shops need nothing more.

URA also offers a separate **Offline Mode Enabler**: URA's own local application
that issues fiscal document numbers while offline. It is not part of EFRISConnect.

- Install it from URA (see URA's "EFRIS Offline Mode Enabler Installation Guide"),
  on the same computer or shop network as the relay. On a shop network, install it
  on the server only.
- It has its own device number, separate from your normal EFRIS device.
- Its local address is typically
  `http://localhost:9880/efristcs/ws/tcsapp/getInformation`. Only local or
  private network addresses are accepted.

In EFRISConnect, enable it in Settings > Offline Mode (or during first-run setup)
with its address and device number. It can run as a **fallback** (URA first) or
**always**.

## Running on a server or in a container

The relay is meant for one computer or a shop network. If you run it elsewhere,
for example with `backend/Dockerfile` (`docker build -f backend/Dockerfile .` from
the repository root), these are required once it binds a network address:

- `ALLOWED_HOSTS` with the exact names clients use.
- HTTPS: a certificate in the data folder, or a TLS reverse proxy in front with
  `TRUST_PROXY` naming it.
- `VAULT_MASTER_KEY`, kept outside the image and outside backups of the vault.
- A persistent data folder: set `DATA_DIR_OVERRIDE` to a mounted volume (for
  example `/data`) so the vault, users and logs survive a restart. Do not mount
  over `backend/data` in the image: it holds the shipped commodity and unit files.

Without `ALLOWED_HOSTS`, and HTTPS or `TRUST_PROXY`, the relay refuses to start on
a network address. Do not expose it directly on the public internet.

## Updating

- Installer: run the new Setup. Data, certificate and mode are kept.
- Manual: stop the relay, `git pull`, `npm install` in `backend`, start again.

The `VERSION` file and the matching Git tag identify each release. The app shows
its version in the footer and at `GET /api/version`.

## Security

See [../SECURITY.md](../SECURITY.md) for how credentials are transmitted, stored,
encrypted, logged, backed up and deleted.
