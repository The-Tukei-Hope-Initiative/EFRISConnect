# EFRISConnect

**URA EFRIS compliance for Manager.io, built for Ugandan small businesses.**

Open source (MIT) and free to use. A project of
[The Tukei Hope Initiative](https://tukeihopeinitiative.org/)'s Economic
Empowerment programme, helping Ugandan micro and small enterprises formalise
and become tax compliant.

EFRISConnect is a small self-hostable web app (a Node.js relay + a browser UI)
that bridges [Manager.io](https://www.manager.io/) and URA EFRIS. It runs on
**Windows, macOS, and Linux** - anywhere Node.js runs.

---

## What it does

- Fiscalise receipts and invoices to URA EFRIS directly from your Manager.io
  documents; the FDN, verification code, and QR are written back onto the record.
- Configure goods and services against URA's commodity classification and units.
- Print branded fiscal receipts/invoices carrying the QR and fiscal document number.
- Multi-currency, offline queueing, credit notes.
- **Goods and Services Configurator mode:** if you turn EFRIS off, the extension
  becomes a pure goods/services configurator for Manager (classify items against
  URA commodity codes and units, branded receipts) without any fiscalisation - useful
  for businesses not yet on EFRIS, or for preparing your catalogue first.
- **Offline resilience:** if the connection to URA drops mid-sale, receipts are
  queued and submitted automatically once it returns. For true offline fiscal
  document numbers, EFRISConnect can also work with URA's separate Offline Mode
  Enabler (optional; see "Offline Enabler" in docs/self-hosting.md).

## What is open source, and what is paid

- **Open source (this repository):** the entire application - the relay
  (`backend/`), the UI (`frontend/`), and the data files. MIT licensed. You can
  read, run, modify, and redistribute all of it, for free, with no account and
  without contacting anyone.
- **Optional paid services:** The Initiative offers optional paid training and
  setup. This is never required - everything needed to install and run
  EFRISConnect yourself is in this repository and documented below.

EFRISConnect is a self-hosted application: you run it on your own machine or
server. It does not bypass URA - a business must still be registered and
provisioned by URA (device, thumbprint, digital keys) for both sandbox and
production.

---

## Testing and going live

EFRISConnect is under active testing. **If you are helping test (including URA
VAT testers), use a test setup only:**

- A **URA EFRIS sandbox** account, device, and digital keys - never production
  credentials.
- A **separate Manager.io test business**, not your live company file.
- **Test/dummy data only** - do not fiscalise real sales or real customer data.

Keep **Sandbox mode ON** in the app until you have verified everything end to
end. **Going live is a separate URA step:** it needs its own production device,
thumbprint registration, and digital keys, and URA must approve/activate you for
live e-invoicing. Only switch to production credentials once URA has activated
you and your testing is complete.

---

## Self-hosting (Windows, macOS, Linux)

You need **Node.js 20+** and a **URA-provisioned EFRIS device**. No cloud
account, no payment, and no contact with The Tukei Hope Initiative.

> **URA prerequisites (obtained from URA, not from EFRISConnect).**
> Before using EFRISConnect you must already be set up on URA EFRIS:
> 1. Be registered for EFRIS / e-invoicing with URA.
> 2. Have a **registered device** on the EFRIS portal, with the device
>    (thumbprint) registration completed, giving you a Device Number (DSN).
> 3. Have **generated your EFRIS digital keys** (the private key/PEM) for that
>    device.
>
> This applies to **both sandbox and production**. Sandbox uses a URA test
> account, device, and keys. **Going live (production) is a separate URA step**:
> it needs its own production device, thumbprint registration, and digital keys,
> and URA must approve/activate you for live e-invoicing. EFRISConnect uses
> whatever credentials and keys URA issues for the mode you are in; it does not
> register your device or grant go-live approval - only URA does that.

### 1. Install Node.js
Install Node.js 20 or newer from https://nodejs.org (LTS is fine). Verify:
```
node --version
```

### 2. Get the code
```
git clone https://github.com/The-Tukei-Hope-Initiative/EFRISConnect.git
cd EFRISConnect/backend
npm install
```

### 3. Run it
- **macOS / Linux:**
  ```
  ./start.sh
  ```
  (or `node server.js` from the `backend` folder)
- **Windows:** double-click `windows\EFRISConnect.bat`, or run `node server.js`
  in the `backend` folder from a terminal.

The app serves at **http://localhost:3000** (and, once the local HTTPS cert is
set up, **https://localhost:5443/extension**).

### 4. Local HTTPS (recommended)
Manager custom buttons load over HTTPS. Generate a locally-trusted certificate:
- **Windows:** `windows\EFRISConnect.bat` -> option for HTTPS setup.
- **macOS / Linux:** see `docs/self-hosting.md` for the `mkcert`/openssl steps
  (a one-line script generates a self-signed cert for `localhost`).

### 5. Connect it in Manager.io
In Manager: **Settings -> Custom Buttons -> New Custom Button**
- Label: `EFRISConnect`
- Source: `Url`
- Address: `https://localhost:5443/extension` (your own instance)
- Placements (add the ones you need):
  - **Fiscalise receipts / invoices / credit notes:** `/receipts`,
    `/sales-invoices` (button on the list pages) and `/receipt-form`,
    `/sales-invoice-form` (button on a single open document, which opens that
    exact record ready to fiscalise). Credit notes are raised from inside the
    extension against an existing invoice/receipt, so they use these same
    placements - no separate credit-note placement is needed.
  - **Goods / services configuration:** `/inventory-items`,
    `/non-inventory-items` (item list pages) and `/inventory-item-form`,
    `/non-inventory-item-form` (a single item, to configure/register it).

### 6. First-run setup (in the app)
Enter your business details, EFRIS device credentials (TIN, device number,
password, private key), and your Manager API access token. **Keep Sandbox mode
ON** and rehearse with test data until you are satisfied, before switching to
production. See [SECURITY.md](SECURITY.md) for exactly how these credentials are
stored.

Full step-by-step notes, including the macOS/Linux HTTPS steps, are in
[`docs/self-hosting.md`](docs/self-hosting.md).

---

## Which version you are running

Every release is tagged in this repository. The [`VERSION`](VERSION) file records
the release (e.g. `1.0.5`), and each release is published as a matching Git tag /
GitHub Release here (e.g. `v1.0.5`). The running app shows its version in the footer
and at `GET /api/version`, so you can check out that tag and confirm you are running
exactly the published code, nothing added.

## Security

Credentials never live in the browser; the relay encrypts them at rest with
AES-256-GCM. On a **desktop/single self-hosted** install the relay runs on your
own machine and the encryption key is stored locally, protected by file
permissions (so encryption mainly guards the file from casual copying, not from
someone with full access to that machine). On a **shared or cloud** server, set
`VAULT_MASTER_KEY` so the key is one you control. Full details - what is
transmitted, stored, encrypted, logged, backed up, and how to delete it - are in
**[SECURITY.md](SECURITY.md)**.

## Project structure

```
backend/    Node.js/Express relay (server.js), EFRIS crypto, data files, vault.js
frontend/   Browser UI (index.html), printable receipt (receipt.html), theme
windows/    Optional Windows launcher + local-HTTPS helper scripts
docs/        Self-hosting and setup notes
start.sh    macOS/Linux launcher
```

## License

[MIT](LICENSE) - free to use, modify, and share.
Copyright (c) 2026 The Tukei Hope Initiative.

## Support this work

EFRISConnect is built and given away free so that Uganda's smallest businesses
can become tax compliant without paying for software they cannot afford. If it
has helped you, please consider giving back - a donation of any size, a
partnership, or sponsoring the setup of a business that cannot afford it keeps
this tool free for the next person.

**Donate or partner with us: outreach@tukeihopeinitiative.org**
