# Self-hosting EFRISConnect

EFRISConnect runs on Windows, macOS, and Linux. It is a Node.js relay plus a
browser UI. Everything below is free and needs no account or contact with
anyone.

## Requirements
- Node.js 18 or newer (https://nodejs.org)
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
3. Keep Sandbox mode ON. Rehearse a few documents against URA's sandbox with test
   data before switching to production.

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

## Verifying the hosted instance
The `VERSION` file records the commit the hosted instance runs. Check out that
commit to confirm the published source matches the running service.

## Security
See [SECURITY.md](../SECURITY.md) for exactly how credentials are transmitted,
stored, encrypted, logged, backed up, accessed, and deleted.
