# Security and credential handling

This document describes how EFRISConnect handles sensitive data. It reflects the
code in this repository (`backend/vault.js`, `backend/auth.js`,
`backend/server.js`, `backend/paths.js`). If you find a difference, please report it.

## What is sensitive

- **Manager API access token**: access to your Manager.io business.
- **EFRIS password**, **EFRIS private key (PEM)** and its **passphrase**: used to
  sign and decrypt EFRIS traffic for your device.
- **User passwords**, **recovery codes**, **setup and reset codes**.
- **SMTP password** (Settings > Email).

## Where it runs

EFRISConnect is a relay you run yourself, on one computer or on a shop server.
There is no hosted service and nothing is sent to The Tukei Hope Initiative.

Apart from URA and your own Manager, the relay makes one other request: once a day it asks
GitHub (api.github.com) for the latest public EFRISConnect release, to show admins that
an update is available. Nothing about the business, users or sales is sent. The owner can
turn it off under Settings > System > Updates.

The browser page never receives the EFRIS private key, the EFRIS password or the
saved Manager token. It refers to a saved business by an id. The relay decrypts a
secret into memory only for the call to Manager or URA that needs it.

## Sign-in and roles

- Every API request needs a signed-in user, except health, version and the
  sign-in routes themselves.
- The first account is the **owner**, created on first run. On the relay's own
  computer no code is needed. From another computer a one-time **setup code** is
  needed (valid 24 hours, written to `EFRIS Connect setup code.txt` in the data
  folder, which only administrators and the relay can read).
- Roles are set per business: **Admin** (everything), **Accountant** (adds credit
  and debit notes, reports, stock, number series, the full log, reconcile) and
  **Cashier** (sell, customers, read goods, offline queue, own log entries). A
  route not listed in the permission table is admin only.
- Passwords are stored as scrypt hashes, at least 8 characters. Five wrong
  passwords lock the account for 15 minutes. Sign-in routes are rate limited.
- Each account gets a **recovery code** to reset a forgotten password. If the owner
  loses both, an administrator on the server can create a one-time reset code
  (launcher option 7, the tray menu, or `unix/reset-owner.sh`).
- With Settings > Email configured, users can get an emailed one-time code (valid
  30 minutes, one use) to set a new password, and owners get security alerts.
- Sessions: only a SHA-256 hash of each session token is stored. A session ends
  after 8 hours idle and at most 12 hours (30 days with "remember this computer").
- **Single-user mode** (owner only, for Manager Desktop on one PC) skips sign-in
  for requests from the relay's own computer. It is refused while the relay is
  reachable from other computers, and turned off at start if that changes.
- `INTERNAL_API_KEY`, when set, allows automation (tests, scripts) with an
  `X-API-KEY` header. If it is not set, there is no such key.

## Transmission

- Browser to relay: HTTPS on port 5443 once the certificate exists. Plain
  `http://localhost:3000` serves only until then, and later redirects browsers to
  HTTPS.
- Relay to Manager and relay to URA EFRIS: HTTPS to the endpoints you configure.
  EFRIS payloads are also encrypted and signed as URA's interface requires.
- The Manager token is accepted only in a request header, never in a URL.

## Storage (encryption at rest)

Secrets are stored in `credentials_vault.json` in the data folder, encrypted with
**AES-256-GCM** (random 12-byte IV per value, authentication tag, versioned
prefix). Non-secret details (TIN, device number, Manager endpoint, flags) are
stored in clear so businesses can be listed without decrypting anything. User
accounts are in `users.json` (hashes only) and sessions in `sessions.json`.

**Data folder.** On Windows: `C:\ProgramData\EFRISConnect\data`, outside the
program folder, so OneDrive or Google Drive syncing, git and reinstalls do not
touch it. It is restricted to the installing user, SYSTEM and Administrators.
Older installs that kept data in `backend\data` are moved there on first start.
On macOS and Linux the folder is `backend/data/`. `DATA_DIR_OVERRIDE` (and
`VAULT_DIR` for the vault alone) set it explicitly.

**Master key.** The vault key is found in this order:
1. `VAULT_MASTER_KEY` environment variable (base64 of 32 bytes). Use it for any
   relay you host for others or run in a container.
2. Windows: a random key protected with **DPAPI, machine scope**, in
   `.vault_master.dpapi`. It only unlocks on the computer that created it, so a
   copied data folder (backup, sync, USB) does not open elsewhere. Machine scope
   also lets the installed relay start as SYSTEM before anyone signs in. A plain
   `.vault_master` from older versions is converted on first use and deleted.
3. macOS and Linux: a random key in `.vault_master` with `0600` permissions.

If the vault holds secrets but no master key can be found, the relay does not
create a new one (that would make the stored secrets unreadable) and logs how to
recover.

What this does not protect against: an administrator of the machine, or a program
running with the relay's rights. The relay must decrypt secrets to use them, so
anything with that access can too.

`credentials_vault.json`, the key files and the data folder are git-ignored.

### Generating a VAULT_MASTER_KEY

It must be base64 of exactly 32 random bytes:
```
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
openssl rand -base64 32
```
Keep it out of backups of the vault itself. Store it in a password manager or
secrets store.

## Logging

- The relay console, the activity log (Settings > Logs) and the error log mask
  secrets before anything is written: passwords, passphrases, tokens, keys and
  known vault values. Values under secret-looking field names are dropped.
- Logs do contain operational data: customer names, TINs, amounts, document
  numbers. Treat them as sensitive.
- Day log files are kept 90 days by default (`LOG_RETENTION_DAYS`, at least 7).
- Admins can export logs and download a support bundle. Both are masked again on
  export. A non-owner admin sees only the businesses they administer.
- Email recipients appear in the activity log by sign-in name, not by address.

## Backup and moving to another computer

Manager's own backup does not include EFRISConnect's credentials. It does include
the fiscal details EFRISConnect writes into Manager (FDN, QR and verification code).

On Windows the vault is locked to the computer that created it, by design. To move
to another computer, set up EFRISConnect there and enter the credentials again from
their sources: TIN, device number and password (URA EFRIS portal), the private key
`.pem` file, and a new Manager access token. **Keep your own safe copy of the
`.pem` file.**

If you back up the data folder anyway, treat it as highly sensitive.

## Deletion

- Settings > Switch Business > delete removes that business's credentials from the
  vault, its user roles and its My Items list.
- To remove everything, stop the relay and delete the data folder. The Windows
  uninstaller asks whether to delete it (default: keep).
- Deletion is immediate and permanent.

## HTTPS certificate

The relay uses a self-signed certificate for this computer's names and addresses
(`localhost`, the PC name, `PCNAME.local`, its private IP addresses). It is not
related to any EFRIS or Manager credential.

- Windows: `windows/setup-https.ps1` (launcher option 2, or the installer) creates
  it, trusts it on this computer, and writes `https.pfx`, `https_cert.cer` and a
  random per-install PFX password file into the data folder.
- macOS and Linux: `unix/setup-https.sh` or your own cert/key pair (see
  [docs/self-hosting.md](docs/self-hosting.md)). Protect the key file with `0600`.
- The **till kit** given to tills holds only the public certificate and two
  scripts to trust or remove it. The kit writer refuses any file that contains a
  private key.

## Network exposure

By default the relay listens on `127.0.0.1` only.

When it listens on a network address (`BIND_HOST`), it refuses to start unless:
- `ALLOWED_HOSTS` lists the names other computers use (Host header allowlist, which
  also blocks DNS rebinding), and
- HTTPS is set up, or the relay sits behind a TLS reverse proxy named in
  `TRUST_PROXY`.

Shop network (LAN) mode, set by launcher option 8, `unix/start-lan.sh` or the
**Shop server** install:
- Tills reach the relay at `https://SERVER-NAME:5443`.
- Manager Server listens on `127.0.0.1` only. The relay serves it to the tills
  over HTTPS on Manager's port + 1 (default 5001) with the same certificate, so
  Manager passwords and business data are encrypted on the shop network. Plain
  `http://` on that port is redirected to `https://`.
- Windows firewall rules are added for the **Private** network profile only.

Do not publish the relay directly on the public internet.

## Other design notes

- **Manager TLS verification is on.** It is skipped only if you set
  `MANAGER_INSECURE_TLS=1` for a Manager with a self-signed certificate.
- **CORS and framing are limited** to loopback origins, `ALLOWED_ORIGINS` /
  `MANAGER_ORIGINS`, and in LAN mode the Manager Server addresses. A Content
  Security Policy restricts what the pages load.
- **Request bodies are capped** at 5 MB.
- **Rate limiting is per IP and in memory.** It suits a shop or a single computer.
- **On-disk caches** (for example the goods catalogue) are not encrypted. They hold
  product and price data, not credentials.
- **`deviceMAC`** sent to EFRIS is a fixed value the interface requires, not a secret.

## Checklist for a relay reachable from other computers

- [ ] HTTPS with the relay's certificate, or a TLS reverse proxy and `TRUST_PROXY`.
- [ ] `ALLOWED_HOSTS` set to the exact names used.
- [ ] `VAULT_MASTER_KEY` set when the relay is not on a single Windows computer.
- [ ] A persistent, access-restricted data folder.
- [ ] Firewall limited to the shop network or trusted addresses.
- [ ] Single-user mode off (the relay enforces this).
- [ ] `MANAGER_INSECURE_TLS` unset.

## Testing vs production

Keep **Sandbox mode** on while evaluating. Use URA's EFRIS sandbox with test data
only. Live use requires the business to pass URA's EFRIS approval (UAT).
Production submissions are live tax records.

## Reporting a vulnerability

Please report security issues privately to **outreach@tukeihopeinitiative.org**
rather than opening a public issue, so they can be fixed before disclosure.
