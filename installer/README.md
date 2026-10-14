# EFRISConnect Windows installer (draft)

One `EFRISConnect-Setup-<version>.exe` for three kinds of computer. The first page asks which one this is.

| Choice | What Setup does |
|---|---|
| **This computer only** | Installs the relay with its own Node.js, creates and trusts the HTTPS certificate, and adds the "EFRISConnect Relay" startup task (localhost only). Adds the tray icon. |
| **Shop server** | Same, plus: listens on the shop network, opens TCP 5443 (and the Manager Server port) on Private networks only, and optionally starts Manager Server at sign-in. Prints the Manager button URL and the till kit location. |
| **Till** | Trusts the server's `https_cert.cer` from the till kit and puts a "Manager (shop)" shortcut on the desktop. Nothing runs on the till. |

## Build

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1            # needs Inno Setup 6
powershell -ExecutionPolicy Bypass -File installer\build.ps1 -SkipCompile   # stage only
```

`build.ps1` does the following:
1. Stages the shipping files in `build\stage`, leaving out tests, runtime data and keys.
2. Runs `npm ci --omit=dev`.
3. Adds `node.exe`, checked against nodejs.org's SHA-256 list.
4. Compiles `EFRISConnect.iss`.

The output is `build\EFRISConnect-Setup-<version>.exe`. `build\` is git-ignored.

## Files

| File | Role |
|---|---|
| `installer/EFRISConnect.iss` | Wizard pages, file copy, shortcuts, uninstall questions |
| `windows/install-helper.ps1` | All system changes: `setup`, `till`, `stop`, `restart`, `reset-owner`, `uninstall` |
| `windows/run-relay.cmd` | What the startup task runs. It reads the mode, works out LAN addresses at every start, and restarts the relay after a crash |
| `windows/tray.ps1`, `tray.vbs` | Tray icon. Green: running. Amber: sales waiting for URA. Red: not answering. Menu: Open, Open Manager, Start Manager Server, Copy button URL, Restart, Logs, Till kit, Reset owner password |

## How it runs

- **Relay:** a scheduled task at Windows startup, account SYSTEM, no window. It starts before anyone signs in, and the vault's DPAPI machine scope allows this. Its logs stay in `C:\ProgramData\EFRISConnect\data\logs`. Crash output goes to `relay-crash.log`.
- **Manager Server:** keeps its businesses in the signed-in user's profile, so it is a logon task for that user, in a minimised window, the same as launcher option 9.
- **Upgrade:** run the new Setup. It stops the relay and tray, replaces the files, and keeps the data folder, the certificate (tills stay trusted) and the mode.
- **Uninstall:** removes the tasks and firewall rules. It asks before deleting the data folder and certificate (default: keep). On a till it asks before removing the trust.

## Open points before release

1. **Code signing.** Without a certificate, Windows SmartScreen warns on first run.
2. **The old launcher and the installed relay must not both run.** Both use port 5443, so with the installer, stop using launcher options 1 and 8. Launcher option 6 removes an old node-windows service.
3. **Over-the-shoulder admin.** If a standard user types an admin password, Setup sees the admin account. The data folder and the Manager Server logon task then belong to that admin. Run Setup from the account that uses Manager.
4. **DHCP address change.** The relay re-reads LAN addresses only when it starts. Use tray → Restart, or give the server a fixed IP / DHCP reservation.
5. **Tills downloading the certificate.** Not done yet: a till still needs the `.cer` from the kit (USB or share).
6. **Manager Server as a true service.** It currently runs at user logon. Manager Server 26.10 has `--path <directory>`, so it could run as a startup task with an explicit data folder. Its default folder is the user's Documents, which can be inside OneDrive: a business file synced by OneDrive while the server writes to it risks conflicts, so Setup should offer a local folder such as `C:\ProgramData\Manager.io`.
