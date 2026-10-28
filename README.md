# EFRISConnect

**URA EFRIS e-receipts and e-invoices for Manager.io, built for Ugandan small businesses.**

EFRISConnect connects [Manager.io](https://www.manager.io/) accounting software to
URA EFRIS (the Uganda Revenue Authority's electronic fiscal receipting and invoicing
system). It is a small relay (Node.js) that runs on your own computer, plus a page
that opens inside Manager from a custom button.

It is free and open source (MIT). It is a project of
[The Tukei Hope Initiative](https://tukeihopeinitiative.org/) (EMC/CBO/025, Entebbe,
Uganda), through its Economic Empowerment programme, which helps micro and small
enterprises formalise and become tax compliant.

There is no hosted service. You install EFRISConnect on your own computer or shop
server, and your credentials stay there.

**Status:** tested on Windows so far, and for use in the URA EFRIS sandbox until
URA approves live use. See [Project status](#project-status).

---

## Who it is for

- Businesses in Uganda that keep their books in Manager.io (Desktop or Server
  Edition) and must issue EFRIS receipts and invoices.
- Shops with one computer, and shops with a server PC and several tills on the
  same network.
- Businesses not yet on EFRIS that want to prepare their items against URA's
  commodity codes and units first (turn EFRIS off in Settings).

## Features

**Sales documents (URA interface T109)**
- Issue a receipt, or submit an existing Manager sales invoice or receipt, to EFRIS.
  The fiscal document number (FDN), verification code and QR code are written back
  to the Manager record.
- Buyer types B2B, B2C, foreign and B2G. Buyer TIN check with URA.
- VAT standard rated, zero rated and exempt. Discount lines.
- Multi-currency, with the day's exchange rate.
- Bulk submission of several documents.
- Reprints are marked ORIGINAL the first time, then COPY 1, COPY 2 and so on.

**Credit and debit notes**
- Credit notes (T110) against an issued invoice or receipt, with URA approval
  status, withdraw and cancel.
- Debit notes.

**Documents**
- Find and reopen issued documents (view, print, download).
- Submission history, connection status, and reconciliation of Manager against URA.

**Goods and stock**
- My Items: your item list, stored on the relay per business and shared by every
  computer that uses it.
- Search URA's registered goods and the commodity code tree.
- Register goods with URA (T130, Admin only).
- Stock in and stock adjustments (T131), mirrored in Manager.
- Reconcile goods between Manager and EFRIS.

**Manager integration**
- Creates the tax codes and custom fields EFRISConnect needs in Manager.
- Receipt themes for Manager that print the EFRIS QR code and fiscal details.
- Customers: look up, create, and record EFRIS buyer details.

**Works when URA is unreachable**
- If URA cannot be reached, the sale is still recorded in Manager and waits in the
  offline queue. It is sent to URA automatically when the connection returns.
- Optional: URA's separate Offline Mode Enabler, for fiscal numbers with no internet
  at all (see [docs/self-hosting.md](docs/self-hosting.md#offline-enabler-optional)).

**Users and administration**
- Sign-in is required. Roles per business: Admin, Accountant and Cashier.
- Several businesses on one relay. Switch business, or delete one.
- Settings > Email: an SMTP server for security alerts and emailed one-time codes.
- Settings > Logs: activity log (kept 90 days), export, and a support bundle with
  secrets masked.
- Settings > Diagnostics and a readiness audit.

**Shop network**
- One server PC runs EFRISConnect and Manager Server Edition. Tills open Manager
  and EFRISConnect over HTTPS on the shop's own network. See
  [Shop network summary](#shop-network-summary).

## Requirements

- **URA EFRIS registration** for the business, obtained from URA, not from
  EFRISConnect:
  1. Registration for EFRIS / e-invoicing.
  2. A registered device on the EFRIS portal (device number) with the
     thumbprint registration done.
  3. The EFRIS private key (`.pem`) for that device, and its passphrase if it has one.
- **Manager.io** Desktop or Server Edition, and a Manager API access token for the
  business.
- **Windows 10 or 11** (64-bit) for the installer. macOS and Linux work with the
  manual install, but have not been tested yet (see [Project status](#project-status)).
- **Node.js 20 or newer** for the manual install. The Windows installer includes
  its own Node.js.

## Install

### Windows installer (recommended)

Download `EFRISConnect-Setup-<version>.exe` from this repository's
[Releases](https://github.com/The-Tukei-Hope-Initiative/EFRISConnect/releases) page
and run it. The first page asks how the computer is used:

| Choice | What it does |
|---|---|
| **This computer only** | Manager Desktop on one PC. Installs the relay (this computer only), creates and trusts the HTTPS certificate, starts the relay with Windows, and adds a tray icon. |
| **Shop server** | The same, plus it listens on the shop network, opens the firewall on Private networks only, and can start Manager Server when you sign in to Windows. |
| **Till** | Trusts the shop server's certificate and adds a "Manager (shop)" desktop shortcut. Nothing runs on the till. |

The installer is not code-signed yet, so Windows SmartScreen may warn on first run.
Details: [installer/README.md](installer/README.md).

### Manual install (Windows, macOS, Linux)

Install Node.js 20 or newer from https://nodejs.org, then:

```
git clone https://github.com/The-Tukei-Hope-Initiative/EFRISConnect.git
cd EFRISConnect/backend
npm install
```

- **Windows:** double-click `windows\EFRISConnect.bat`. Run option **2** (HTTPS
  setup) once, then option **1** to start. See [windows/README.md](windows/README.md).
- **macOS / Linux:** run `unix/setup-https.sh` once, then `./start.sh`. See
  [unix/README.md](unix/README.md) and [docs/self-hosting.md](docs/self-hosting.md).

The relay serves `https://localhost:5443/extension` once the certificate exists.
Before that it serves `http://localhost:3000`.

## Connect it in Manager

In Manager: **Settings > Custom Buttons > New Custom Button**.

- Name: `EFRISConnect`
- Source: `Url`
- URL: `https://localhost:5443/extension` (on a shop network:
  `https://SERVER-NAME:5443/extension`)
- Add one button for each placement you want: the Receipts and Sales Invoices
  lists, the single receipt and sales invoice pages, and the inventory and
  non-inventory item pages.

Manager only accepts an `https://` address here.

## First-run setup

Installing for the first time? Follow the
[installation checklist](docs/first-install-checklist.md): what you need from URA,
the install, Manager, tills, testing, and common errors with fixes.

1. Open EFRISConnect from the Manager button on the computer that runs the relay.
2. Create the owner account. From another computer you need the one-time setup
   code, which the relay writes to `EFRISConnect setup code.txt` in its data folder.
3. Save the recovery code shown after the account is created. It resets a
   forgotten password. Five wrong passwords lock an account for 15 minutes.
4. Enter the business details, the EFRIS credentials (TIN, device number, private
   key) and the Manager endpoint and access token.
5. Keep **Sandbox mode** on and test with sandbox credentials and test data.
6. Add users (Admin, Accountant, Cashier) under Settings > Users.

On a single PC with Manager Desktop, the owner can turn on **single-user mode**
(Settings > Users). EFRISConnect then opens without sign-in on that computer only.
It is not available in shop network mode.

If the owner loses both the password and the recovery code, use launcher option
**7**, the tray icon's "Reset owner password", or `unix/reset-owner.sh`.

## Shop network summary

One PC (the server) runs EFRISConnect and Manager Server Edition. Tills use a
browser.

1. Server: install with **Shop server**, or use the launcher (option 2 once,
   option 9 to start Manager Server, option 8 to start the relay for the network).
2. Manager Server listens on the server only (`127.0.0.1:5000`). EFRISConnect
   passes it on to the tills encrypted at `https://SERVER-NAME:5001`, with the same
   certificate.
3. Set every EFRISConnect button in Manager to `https://SERVER-NAME:5443/extension`.
4. Each till trusts the server certificate once, from the till kit
   (`C:\ProgramData\EFRISConnect\data\till-kit`) or with the installer's **Till** mode.
5. The firewall rules apply to Private networks only, so the shop network must be
   set to Private in Windows.

Sales still work with the internet off: they are recorded in Manager and sent to
URA when the connection returns. Full steps:
[docs/self-hosting.md](docs/self-hosting.md#shop-network-lan).

## Project status

- **Tested on Windows only so far:** Manager Desktop on one PC, and Manager Server
  Edition with tills on a shop network. macOS and Linux are supported through the
  manual install and the `unix/` scripts, but have not been tested yet. Reports
  from macOS and Linux users are welcome.
- **Not yet approved for live use:** for now, use EFRISConnect in the URA EFRIS
  sandbox only. Live (production) use needs URA's EFRIS approval for each
  business first.

## Testing and going live

- Develop and test only in the **URA EFRIS sandbox**, with a sandbox account,
  device and key, a separate Manager test business, and test data.
- Live (production) use requires the business to pass URA's EFRIS approval
  (UAT). Production uses its own device registration and keys issued by URA.
- Turn off Sandbox mode only after URA has approved you. Production submissions
  are live tax records.

EFRISConnect does not register devices or grant approval. Only URA does that.

## Updating

- **Installer:** run the new Setup. It stops the relay, replaces the program files,
  and keeps the data folder, the certificate (tills stay trusted) and the mode.
- **Manual install:** stop the relay, run `git pull`, run `npm install` in
  `backend`, and start it again. On Windows the data folder is outside the code
  folder, so an update does not touch it.

The running version is shown in the app footer and at `GET /api/version`. The
`VERSION` file and the matching Git tag (for example `v1.0.7`) identify each release.

## Security

- Credentials (EFRIS password, private key, Manager token) stay on the relay,
  encrypted with AES-256-GCM. The browser never receives them.
- On Windows the encryption key is protected with DPAPI (machine scope), so a
  copied data folder does not open on another computer.
- Sign-in with roles and lockout. A relay reachable from other computers must use
  HTTPS and a Host allowlist, or it refuses to start.

Full details, including backup and deletion: [SECURITY.md](SECURITY.md).

## Project structure

```
backend/    Relay (server.js), sign-in, vault, email, logs, Manager HTTPS front, tests
frontend/   The extension page (index.html), printable receipt, Manager receipt theme
windows/    Launcher (EFRISConnect.bat), HTTPS, shop network, tray and installer helpers
installer/  Inno Setup script and build script for the Windows installer
unix/       macOS / Linux scripts (HTTPS, shop network, service, owner reset)
docs/       Self-hosting and shop network guide
start.sh    macOS / Linux launcher
```

## Support and contributing

- Bugs and feature requests: open an issue in this repository.
- Pull requests are welcome. Run the tests first: `cd backend && npm test`.
- Security issues: report privately (see [SECURITY.md](SECURITY.md#reporting-a-vulnerability)).
- The Initiative offers optional paid training and setup. Nothing in this
  repository requires it.

EFRISConnect is given away free so that the smallest businesses can become tax
compliant. Donations, partnerships, or sponsoring the setup of a business that
cannot afford it keep it free: **outreach@tukeihopeinitiative.org**

## License

[MIT](LICENSE). Copyright (c) 2026 The Tukei Hope Initiative.
