# Self-hosting EFRISConnect

EFRISConnect runs on Windows, macOS, and Linux. It is a Node.js relay plus a
browser UI. Everything below is free and needs no account or contact with
anyone.

## Requirements
- Node.js 20 or newer (https://nodejs.org)
- A Manager.io API access token for the business you are fiscalising
- A **URA-provisioned EFRIS device** - this is obtained from URA, not from
  EFRISConnect. You must already have:
  - EFRIS / e-invoicing registration with URA.
  - A registered device with completed device/thumbprint registration, giving
    you a Device Number (DSN).
  - Your generated EFRIS digital keys (private key PEM, and passphrase if set).
  This applies to both sandbox and production; going live (production) is a
  separate URA step with its own device and keys, and URA must approve/activate
  you for live e-invoicing. EFRISConnect uses the TIN, DSN, password, and keys
  URA issues; it does not register the device or grant go-live approval.

## Install
```
git clone https://github.com/The-Tukei-Hope-Initiative/EFRISConnect.git
cd EFRISConnect/backend
npm install
```

## Run
- macOS / Linux: `./start.sh` (from the repo root) or `node server.js` (from `backend/`)
- Windows: `windows\EFRISConnect.bat`, or `node server.js` from `backend\`

The relay listens on http://localhost:3000 and, once a certificate is present,
https://localhost:5443/extension.

## Local HTTPS

Manager custom buttons load over HTTPS, so a locally-trusted certificate makes
the in-Manager experience seamless.

### Windows
Run `windows\EFRISConnect.bat` and choose the HTTPS-setup option. It creates a
self-signed certificate covering `localhost`, this machine's hostname, and its
LAN IPs, trusts it on the machine, and writes the PFX the relay uses.

### macOS / Linux
The relay looks in `backend/data/` for either `https.pfx` (+ `https_pfx_pass.txt`)
or a PEM pair named exactly **`https_cert.pem`** and **`https_key.pem`**. So
generate a cert/key, then copy them into `backend/data/` under those two names.
(If no cert is found the relay serves plain HTTP, so HTTPS is optional for a quick
trial.)

Option A - mkcert (easiest; trust is automatic):
```
mkcert -install               # trusts mkcert's local CA in your OS/browser
mkcert localhost 127.0.0.1    # creates localhost+1.pem and localhost+1-key.pem
cp localhost+1.pem     backend/data/https_cert.pem
cp localhost+1-key.pem backend/data/https_key.pem
```
No separate trust step - `mkcert -install` already did it. Restart the relay.

Option B - openssl (self-signed; trust it manually):
```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout backend/data/https_key.pem -out backend/data/https_cert.pem \
  -days 3650 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```
Then trust `backend/data/https_cert.pem` so the browser accepts it:
- macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain backend/data/https_cert.pem`
- Linux (Debian/Ubuntu): `sudo cp backend/data/https_cert.pem /usr/local/share/ca-certificates/efrisconnect.crt && sudo update-ca-certificates` (Chrome/Firefox keep their own stores - you may also import it in the browser's certificate settings).

Restart the relay; the console shows `HTTPS running ... [trusted PEM (data/https_cert.pem)]`.

## Configure (first run, in the app)
1. Open the app in your browser (or via the Manager custom button).
2. Enter business details, EFRIS device credentials, and your Manager access token.
3. Keep Sandbox mode ON. While testing, use a URA **sandbox** account, a
   **separate Manager test business**, and **test data** only - never production
   credentials or your live company file. Rehearse a few documents end to end
   before switching to production (going live is a separate URA step).

## Environment variables (optional)
- `PORT` - override the HTTP port (default 3000).
- `VAULT_MASTER_KEY` - base64 of 32 random bytes; required for shared/cloud, not
  needed for a single self-hosted machine (see SECURITY.md). Generate one with:
  `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
  (or `openssl rand -base64 32`).
- `INTERNAL_API_KEY` - operator API key guarding sensitive relay endpoints. If
  unset, a random one is generated per process.
- `MANAGER_INSECURE_TLS=1` - skip Manager TLS certificate verification. Only for a
  self-signed Manager; leave unset otherwise (verification is on by default).

All of these are **optional** - a normal single-machine self-host needs none of
them. Set one only if the note above says you need it.

### How to set an environment variable
Set it in the same terminal/session that starts the relay, before `node server.js`:

- **Windows (PowerShell):** `$env:MANAGER_INSECURE_TLS = "1"; node server.js`
- **Windows (Command Prompt):** `set MANAGER_INSECURE_TLS=1` then `node server.js`
- **macOS / Linux:** `MANAGER_INSECURE_TLS=1 node server.js`

Or put them in a `.env` file next to `server.js` (see `.env.example`). To make one
permanent, use your OS's environment settings or your service manager's config.

## Connect in Manager.io
Settings -> Custom Buttons -> New Custom Button:
- Label `EFRISConnect`, Source `Url`
- Address: your instance, e.g. `https://localhost:5443/extension`
- Placements, by purpose:
  - Fiscalise receipts/invoices/credit notes: `/receipts`, `/sales-invoices`
    (list pages) and `/receipt-form`, `/sales-invoice-form` (a single open
    document, opened ready to fiscalise). Credit notes are raised inside the
    extension against an existing invoice/receipt - no separate placement.
  - Goods/services configuration: `/inventory-items`, `/non-inventory-items`
    (item lists) and `/inventory-item-form`, `/non-inventory-item-form`
    (a single item, to configure/register it).

## Shop network (LAN)
One PC in the shop (the **server PC**) runs EFRISConnect and Manager; the tills
(laptops, other PCs) reach it over the shop's own Wi-Fi or cable network.

### Requirements
- All PCs on the same **private** Wi-Fi/LAN (addresses 10.x, 172.16-31.x or
  192.168.x). Guest Wi-Fi that isolates devices does not work.
- On the server PC, Windows must call that network **Private** (Settings ->
  Network & internet -> the network -> Network profile type: Private). The
  firewall rules EFRISConnect adds apply to Private networks only.
- The HTTPS certificate on the server PC (launcher option 2, once). Tills only
  connect over HTTPS.

### Recommended: Manager Server Edition on the server PC
Manager Desktop can only be used on its own PC. For Manager on the tills, use
**Manager Server Edition** (`ManagerServer.exe`) on the server PC; tills open it in
a browser and use the EFRISConnect buttons inside it.

Manager Server uses the **same data folder as Manager Desktop** by default
(`--path`, normally `Documents\Manager.io`). Never run Desktop and Server on the
same data folder at the same time: close Manager Desktop first.

**Server PC, once:**
1. `windows\EFRISConnect.bat` -> **2) First-time HTTPS setup** (admin). The
   certificate covers `localhost`, the PC name, `PCNAME.local` and its current
   private IP addresses. Re-run it if the PC's IP address changes and tills use
   the IP.
2. `windows\EFRISConnect.bat` -> **9) Start Manager Server for the shop network**.
   It asks once for the path to `ManagerServer.exe` and the port (default 5000),
   adds a firewall rule "EFRISConnect Manager Server (LAN)" (TCP port, Private
   profile only, one admin prompt) and starts
   `ManagerServer.exe --urls http://*:5000`. The same by hand:
   `"C:\path\to\ManagerServer.exe" --urls http://*:5000`. Default user:
   `administrator`.
3. `windows\EFRISConnect.bat` -> **8) Start for shop network (LAN)**. It checks
   the certificate (else it tells you to run option 2 and stops), asks for
   Manager Server's port (default 5000, remembered), adds the firewall rule
   "EFRISConnect HTTPS (LAN)" (TCP 5443, Private profile only, one admin prompt the
   first time), then starts the relay with `BIND_HOST=0.0.0.0`,
   `ALLOWED_HOSTS=<pcname>,<pcname>.local,<private IPs>`, `LAN_MODE=1` and
   `MANAGER_PORTS=<port>`, and prints the till addresses. Press **L** in the relay
   window to see them again.
4. In EFRISConnect (Settings -> System), the Manager endpoint stays on the server
   PC: `http://127.0.0.1:5000/api2` (Auto-detect tries port 5000 first).
5. In Manager Server -> Settings -> Custom Buttons, set every EFRISConnect button
   URL to **`https://PCNAME:5443/extension`** (not `localhost`: the buttons are
   shared by every browser that opens Manager). EFRISConnect's Home page and the
   C key in the relay window show this exact URL in LAN mode.
6. Copy the **till kit** folder, `%ProgramData%\EFRISConnect\data\till-kit`, to a
   USB stick or a shared folder. It is written when option 8 starts and holds only
   the public certificate (`https_cert.cer`), `Trust EFRISConnect server.bat`,
   `Remove EFRISConnect trust.bat` and a `README.txt` with the addresses. No key,
   no password.

**Each till, once:**
1. Run `Trust EFRISConnect server.bat` from the till kit and approve the admin
   prompt (or, with the EFRISConnect files on the till, launcher option **5**
   and the path to `https_cert.cer`). Restart the browser.
2. Open Manager Server in the browser: `http://PCNAME:5000` (or
   `http://<server IP>:5000`). Its EFRISConnect buttons open
   `https://PCNAME:5443/extension`.
3. Sign in to EFRISConnect with the till's own user (for example a Cashier).

Undo on a till: `Remove EFRISConnect trust.bat`, or as administrator
`certutil -delstore Root "EFRISConnect Local HTTPS"`. On the server, option **6**
also removes both firewall rules.

### Fallback: browser only, no Manager on the tills
Skip Manager Server. Tills trust the certificate as above and open
`https://PCNAME:5443/extension` directly in Edge or Chrome, sign in as a cashier
and issue receipts in EFRISConnect; EFRISConnect records them in Manager (Desktop
or Server) on the server PC. Manager itself is used only on the server PC.

### macOS / Linux server
`unix/setup-https.sh` (covers the hostname, `.local` and private IPs), then
`unix/start-lan.sh` (sets the same variables; `MANAGER_PORTS=8080 unix/start-lan.sh`
for another Manager port). It makes no firewall changes: allow inbound TCP 5443
(and Manager's port) from the LAN yourself; the script prints a hint. The till kit
is written to `backend/data/till-kit`.

### With the internet off
Works: signing in, Manager on the server PC (and on tills through Manager
Server), issuing receipts (through the URA Offline Enabler if installed, else they
wait in the offline queue and go to URA automatically when the internet returns).

Needs the internet: checking a buyer's TIN with URA, credit-note approval status,
URA exchange rates and the URA tax rule of a commodity code.

### Settings used (set by the launcher)
- `LAN_MODE=1` - shop network mode: the Manager button URL becomes
  `https://<first ALLOWED_HOSTS name>:5443/extension`, and Manager Server origins
  (`http` and `https` on each `MANAGER_PORTS` port, for every `ALLOWED_HOSTS` name
  and IP) may frame the extension and call the relay. The till kit is written at
  start.
- `MANAGER_PORTS` - Manager Server port(s), comma separated (default 5000).
- `MANAGER_ORIGINS` - any other Manager origin, e.g. `https://books.example.com`
  (also outside LAN mode; same effect as `ALLOWED_ORIGINS`).

## Offline Enabler (optional - Desktop / LAN only)

EFRISConnect already queues documents when URA is unreachable and submits them
automatically once the connection returns - so **most self-hosters do not need
anything extra for offline resilience.**

URA also offers a separate **Offline Mode Enabler**: URA's own local application
that generates fiscal document numbers while genuinely offline. It is **not part
of EFRISConnect** - you obtain and install it from URA:

- Download and install it from URA (see URA's "EFRIS Offline Mode Enabler
  Installation Guide"). URA provides the Enabler for **Windows, macOS, and Linux** -
  install the build for your operating system. It runs on the same machine or LAN
  as EFRISConnect.
- It has its **own device number**, separate from your normal EFRIS DSN.
- It exposes a local API, typically
  `http://localhost:9880/efristcs/ws/tcsapp/getInformation`.

To use it, in EFRISConnect enable the Offline Enabler (onboarding step 3, or
Settings) and enter its URL and device number. You can run it as a **fallback**
(URA first, Enabler only when URA is down) or **always**. It applies to the
Desktop / Server-LAN setup only, not a cloud host.

## Releases and versions
The `VERSION` file records the current release, and each release is published as a
matching Git tag / GitHub Release. Check out a tag to run or inspect that exact
release.

## Security
See [SECURITY.md](../SECURITY.md) for exactly how credentials are transmitted,
stored, encrypted, logged, backed up, accessed, and deleted.
