# First installation checklist

Installing EFRISConnect for a business that keeps its books in Manager.io, from
the URA side to the first fiscalised receipt. Work through it in order and tick
each line. Allow about an hour once the URA items in part A are in hand; part A
itself can take days, because it depends on URA.

Always start in the **EFRIS sandbox** with a **separate Manager test business**.
Move to live only after URA has approved the business (part G).

---

## A. From URA (collect before the visit)

EFRISConnect does not register anyone with URA. The business (or its tax agent)
gets these from URA. URA's portal menus change from time to time; when in doubt,
follow URA's own EFRIS integration guide or ask the URA EFRIS help desk.

- [ ] **TIN** of the business (10 digits), and the legal name exactly as URA has it.
- [ ] **EFRIS portal account** (efris.ura.go.ug for live, efristest.ura.go.ug for the
      sandbox), and the EFRIS **password** used for system-to-system access.
- [ ] **System-to-system integration** approved for the business, with a **device
      number** for this installation (looks like `1000000000_01`). Each installation
      gets its own device number.
- [ ] **Key pair** for that device:
  - the **private key** stays with the business. EFRISConnect needs it as a `.pem`
    file (starts with `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE
    KEY-----`);
  - the **public certificate** is uploaded to URA when the device is registered.
  - Keep a copy of the private key somewhere safe (USB stick or password manager).
    URA cannot give it back.
- [ ] Sandbox first: a **sandbox** device number and key are separate from the
      live ones.

### Converting a key to .pem

If URA's tooling gave a `.pfx` / `.p12` keystore instead of a `.pem`, convert it
once with OpenSSL (it asks for the keystore password):

```
openssl pkcs12 -in efris.pfx -nocerts -nodes -out efris_private.pem
```

- `-nodes` writes the key unencrypted. If you keep it encrypted instead, tick
  "My private key is encrypted" in EFRISConnect and enter the passphrase.
- Never send the `.pem` or `.pfx` by email or chat.

### Offline Mode Enabler (optional)

Only for businesses that must issue fiscal numbers with **no internet at all**.
Without it, EFRISConnect still records every sale in Manager and sends it to URA
when the internet returns.

- [ ] Download the Offline Mode Enabler from URA's EFRIS portal and install it on
      the shop's server PC. It needs Java 8 and runs its own Tomcat and MySQL.
- [ ] The Enabler is registered with URA as **its own device**, with its own device
      number (often starting `TCS`).
- [ ] Later, in EFRISConnect: Settings > Offline Mode, Enabler URL
      `http://localhost:9880/efristcs/ws/tcsapp/getInformation`, its device number,
      mode **Fallback**, then **Test Enabler**.

## B. Before the visit

- [ ] Download `EFRISConnect-Setup-<version>.exe` and its `.sha256` from the
      [Releases page](https://github.com/The-Tukei-Hope-Initiative/EFRISConnect/releases).
- [ ] Decide the layout:
  - **One computer** with Manager Desktop: choose **This computer only**.
  - **Server plus tills** with Manager Server Edition: **Shop server** on the server
    PC, **Till** on each till.
- [ ] Shop network: give the server PC a **fixed IP** or a DHCP reservation on the
      router, and set the Wi-Fi/LAN to **Private** in Windows on every PC.
- [ ] Manager Server Edition (shop network only): download it from manager.io. It
      needs no licence. Plan a **local** data folder such as
      `C:\ProgramData\Manager.io`, not a OneDrive or Google Drive folder.

## C. Install on the PC that runs Manager (or the server)

- [ ] Run the Setup as a Windows user with admin rights, from the account that uses
      Manager every day.
- [ ] "Windows protected your PC": click **More info > Run anyway** (the installer is
      not code-signed yet).
- [ ] Choose the mode. Shop server: select `ManagerServer.exe` and the port (5000).
      Optionally select the private key `.pem` (it is copied into the protected data
      folder).
- [ ] At the end, note the **Manager button URL** Setup shows:
  - one computer: `https://localhost:5443/extension`
  - shop network: `https://SERVER-NAME:5443/extension`
- [ ] A coloured dot appears next to the clock: green is running, amber means sales
      are waiting for URA, red means not answering (right-click > Restart).

## D. In Manager

- [ ] Open the business (Desktop), or sign in to Manager Server at
      `https://localhost:5001` (server) or `https://SERVER-NAME:5001` (tills).
- [ ] **Access token:** Settings > Access Tokens (called API Keys in some versions) >
      New, copy the token. EFRISConnect asks for it once.
- [ ] **Custom buttons:** Settings > Custom Buttons > New Custom Button. Name
      `EFRISConnect`, Source **Url**, the URL from step C. Add one for each place you
      want it: Receipts list, Sales Invoices list, a single receipt, a single sales
      invoice, Inventory items, Non-inventory items.
- [ ] Shop network: the same URL on every button. Manager accepts `https://` only.

## E. First run of EFRISConnect

- [ ] Click an EFRISConnect button in Manager **on the server or main PC first**.
- [ ] **Create the owner account.** Save the **recovery code** (download or print it).
      From another computer the setup code is needed; it is in
      `C:\ProgramData\EFRISConnect\data\EFRIS Connect setup code.txt`.
- [ ] **Setup wizard:**
  - EFRIS: TIN, device number, EFRIS password, private key (paste the PEM content,
    or a file path), Sandbox **on**.
  - Manager: endpoint and access token.
    - Manager Desktop: **Auto-detect** (Desktop uses a random port).
    - Manager Server on the same PC: `http://127.0.0.1:5000/api2`.
  - **Test** each part until it shows green.
- [ ] Settings > **Custom Fields** > Check / Create, and the tax codes. EFRISConnect
      creates the fields and VAT codes it needs in Manager.
- [ ] Settings > **Branded Theme**: install the receipt theme so printouts carry the
      EFRIS QR code.
- [ ] Settings > **Business**: check legal name, address, phone, **your own email**.
- [ ] Settings > **Users**: add each person with the right role (Admin, Accountant,
      Cashier). On a single PC with Manager Desktop, **single-user mode** can skip
      sign-in on that PC.
- [ ] Optional: Settings > **Email** (SMTP) for security alerts and password-reset
      codes.

## F. Tills (shop network only)

- [ ] Copy `C:\ProgramData\EFRISConnect\data\till-kit` from the server to a USB stick.
- [ ] On each till: run the Setup and choose **Till**, with `https_cert.cer` from the
      kit (or run `Trust EFRISConnect server.bat` from the kit as administrator).
- [ ] Restart the browser, open `https://SERVER-NAME:5001`, sign in to Manager, then
      sign in to EFRISConnect from a button.

## G. Prove it works (sandbox)

- [ ] Goods: register or import the items (commodity code, unit, VAT rate), and do a
      **stock-in** for goods before selling them.
- [ ] Issue a test **receipt**: it should return an FDN and say "Recorded in Manager".
- [ ] Open it, **View / Print**: QR code, FDN, "Served by" the user. Scan the QR or
      verify the FDN on the URA portal.
- [ ] Turn the internet off, make a sale: "Saved offline, waiting for URA". Turn it on:
      it is sent on its own within a few minutes.
- [ ] Credit note on one test sale (URA approval can take a day or two in sandbox).
- [ ] When the business is ready, book **URA's EFRIS approval (UAT)**. After approval,
      enter the **live** device number and key, turn Sandbox off, and issue one real
      low-value receipt to confirm.

---

## Common problems and fixes

| What you see | Cause | Fix |
|---|---|---|
| "Windows protected your PC" | Installer not code-signed yet | More info > Run anyway |
| Manager says the button URL must be https | Custom button uses `http://` | Use `https://localhost:5443/extension` or `https://SERVER-NAME:5443/extension` |
| "Your connection is not private" / certificate error | HTTPS certificate not trusted on this PC | Server: rerun Setup. Till: Till mode or the till kit, then restart the browser |
| `ERR_SSL_PROTOCOL_ERROR` on Manager after an update | Browser remembered an old HTTPS rule | Open `chrome://net-internals/#hsts`, delete the domain `SERVER-NAME`, restart the browser |
| "This site doesn't support a secure connection" | Chrome's "Always use secure connections" with a plain `http://` address | Use the `https://...:5001` address for Manager |
| Blank page on `http://...:5001` | Old relay version | Use `https://...:5001`; current versions redirect |
| "Manager is not running" / `ECONNREFUSED 127.0.0.1:55667` | Manager Desktop closed, or an old setup still points at Desktop's random port | Start Manager, or delete the old setup in Settings > Switch Business |
| Manager answers 401 / access denied | Access token wrong or deleted | Create a new token in Manager, paste it in Settings |
| Page stuck on "Loading..." for everyone | Someone clicked inside the relay's console window (old launcher) and froze it | Press Esc in that window; use the installer or current launcher |
| "Port 5443 is already in use" | EFRISConnect already running (service, tray or another window) | Close the other copy; do not run the launcher and the installed version together |
| URA 1409 "applicationTime" | PC clock or time zone wrong | Set Windows time to automatic, time zone Kampala (EAT) |
| Session or decryption error with URA | Wrong private key for this device number, or an encrypted key without its passphrase | Use the key that belongs to this device; tick "encrypted" and enter the passphrase |
| "EFRIS network unreachable" / sale queued | Internet or URA down (URA sometimes returns an HTML "410 Server Unreachable" page) | Nothing: the sale is in Manager and is sent automatically. "Try now" retries at once |
| URA 1600 inventory shortage | No stock recorded at URA for that item | Goods > Stock Management > Stock in (Local Purchase, with the cost price) |
| URA 2081 supplier name | Stock-in without a supplier | Enter the supplier name |
| "Opening stock" refused for an item | Item already has stock at URA | Use Local Purchase |
| URA 1178 / 1304 on discounts | Old version | Update; discount lines are handled automatically |
| URA 3083 on a government (B2G) sale | Buyer TIN is not a government TIN in URA's register | Check the TIN with URA; the sandbox often has none |
| URA 1115 seller email | No email in Settings > Business | Fill in the business email |
| Amounts land in **Suspense** in Manager | Item without an account, or a document without a customer/supplier | Set the item's income/inventory accounts; current versions add a customer or supplier automatically |
| Credentials gone after copying the data folder to a new PC | Saved secrets are locked to the PC they were entered on (by design) | On the new PC, enter TIN, device number, password and key again |
| Lost owner password and recovery code | | Tray icon > Reset owner password (or launcher option 7), on the server PC |
