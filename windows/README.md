# Running EFRISConnect on Windows

There are two ways to run EFRISConnect on Windows:

- **The installer** (`EFRISConnect-Setup-<version>.exe`): recommended. It bundles
  Node.js, runs the relay as a startup task and adds a tray icon. See
  [../installer/README.md](../installer/README.md).
- **The launcher** in this folder, `EFRISConnect.bat`, for a manual install from
  the source code. It needs **Node.js 20 or newer** (https://nodejs.org) and
  `npm install` in `backend` first.

Do not use both on the same computer: they use the same ports. With the installer,
stop using launcher options 1 and 8.

## Launcher menu

Double-click `EFRISConnect.bat`:

```
 1)  Start EFRIS Connect            (use this every day)
 2)  First-time HTTPS setup         (run once - admin)
 3)  Start automatically at logon
 4)  Install as Windows service     (server/always-on - admin)
 5)  Trust a server's certificate   (LAN till only - admin)
 6)  Uninstall auto-start / service / LAN firewall rules
 7)  Reset owner password           (lost password - admin)
 8)  Start for shop network (LAN)   (server PC that tills reach)
 9)  Start Manager Server for the shop network
10)  Change the Manager Server port   (used by 8 and 9)
 0)  Exit
```

Steps that need administrator rights (2, 4, 5, 7, and the firewall changes of 6,
8 and 9) open an elevated window by themselves.

## The address: `https://localhost:5443/extension`

Manager needs an `https://` address for the custom button, and only passes the
open receipt or invoice to the button over HTTPS. Use
`https://localhost:5443/extension` in every EFRISConnect button.

Port `3000` serves the app before the certificate exists. Once HTTPS is running, a
browser that opens `http://localhost:3000` is redirected to port 5443.

## First-time setup (one computer)

1. Option **2) First-time HTTPS setup**. It creates one certificate for
   `localhost`, `127.0.0.1`, this PC's name, `PCNAME.local` and its IP addresses,
   trusts it on this computer, and writes `https.pfx` and `https_cert.cer` into
   the data folder. No internet needed. Valid 10 years.
2. Option **1) Start EFRIS Connect**. Wait for `HTTPS running at
   https://localhost:5443/extension`. Leave the window open.
3. In Manager, add the EFRISConnect custom buttons with that address.
4. Open EFRISConnect from a button and create the owner account.

To start it without the console window: option **3** (at logon) or option **4**
(Windows service).

## Shop network (LAN)

Full steps are in [../docs/self-hosting.md](../docs/self-hosting.md#shop-network-lan).
In short, on the server PC:

1. Option **2** once (HTTPS certificate).
2. Option **9**: starts Manager Server Edition bound to `127.0.0.1` on its port
   (default 5000). It asks once for the path to `ManagerServer.exe`. If a data
   folder is saved in `manager-server-data.txt` in the data folder, it is passed
   as `--path`. Close Manager Desktop first: both use the same business data.
3. Option **8**: starts the relay for the shop network. It needs the certificate,
   adds the firewall rules "EFRISConnect HTTPS (LAN)" (TCP 5443) and
   "EFRISConnect Manager HTTPS (LAN)" (Manager's port + 1, default 5001) for
   **Private** networks only, and prints the addresses. Tills then open:
   - Manager: `https://SERVER-NAME:5001` (plain `http://` on that port redirects
     to `https://`)
   - EFRISConnect buttons: `https://SERVER-NAME:5443/extension`
4. Option **10** changes the saved Manager Server port. Restart options 8 and 9
   after a change.

On each till, run `Trust EFRISConnect server.bat` from the till kit
(`C:\ProgramData\EFRISConnect\data\till-kit`), or option **5** with the
`https_cert.cer` from the kit. Restart the browser.

If the server PC's network is set to Public, option 8 warns you: set it to Private
in Windows Settings, or tills cannot connect.

## Offline Mode Enabler (optional)

The relay always queues sales when URA cannot be reached and sends them when the
connection returns. For fiscal numbers with no internet at all, install URA's
*EFRIS Offline Mode Enabler* on the server only and enter its address in
**Settings > Offline Mode**. See
[../docs/self-hosting.md](../docs/self-hosting.md#offline-enabler-optional).

## Notes

- The EFRIS private key is set per business in **Settings > EFRIS Credentials**
  (a file path or the pasted key). The `EFRIS_PRIVATE_KEY` environment variable
  also works.
- Runtime data (credential vault, users, offline queue, logs, HTTPS certificate,
  till kit) lives in `C:\ProgramData\EFRISConnect\data`, outside the program folder.
- Option **6** removes the auto-start shortcut, the Windows service and the shop
  network firewall rules.
