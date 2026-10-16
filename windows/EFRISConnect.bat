@echo off
REM ============================================================
REM  EFRISConnect - URA EFRIS for Manager.io - all-in-one launcher
REM  (Manager Desktop and Server/LAN editions)
REM
REM  Just double-click this file. It shows a menu:
REM    1) Start EFRIS Connect        <- everyday use
REM    2) First-time HTTPS setup     <- run once (needs admin)
REM    3) Start automatically at logon
REM    4) Install as a Windows service (server/always-on, admin)
REM    5) Trust a server's certificate on this PC (LAN till, admin)
REM    6) Uninstall auto-start / service / shop-network firewall rules
REM    7) Reset owner password (lost password and recovery code, admin)
REM    8) Start for shop network (LAN)  <- server PC that tills reach
REM    9) Start Manager Server for the shop network (Manager Server Edition)
REM   10) Change the Manager Server port (used by 8 and 9)
REM
REM  The admin steps (2, 4, 5, 7, and the firewall rules of 6, 8, 9)
REM  relaunch this file elevated on their own - you don't need to open
REM  an admin prompt yourself.
REM ============================================================
setlocal EnableExtensions
cd /d "%~dp0"
REM Runtime data (vault, logs, HTTPS certificate) lives outside the code folder.
set "DATADIR=%ProgramData%\EFRISConnect\data"
set "OLDDATA=%~dp0..\backend\data"

REM --- Internal dispatch: elevated relaunches jump straight to a task ---
if /i "%~1"=="setup-https"      goto do_https
if /i "%~1"=="service-install"  goto do_service_install
if /i "%~1"=="trust-cert"       goto do_trust
if /i "%~1"=="reset-owner"      goto do_reset_owner
if /i "%~1"=="lan-firewall"     goto do_lan_firewall
if /i "%~1"=="manager-firewall" goto do_manager_firewall
if /i "%~1"=="manager-unfirewall" goto do_manager_unfirewall
if /i "%~1"=="lan-unfirewall"   goto do_lan_unfirewall
REM Start straight in shop network mode (used to restart the relay without the menu).
if /i "%~1"=="lan"              goto do_lan

:menu
cls
echo ============================================================
echo   EFRISConnect - URA EFRIS e-receipts and e-invoices for Manager.io
echo   Free and open source, by The Tukei Hope Initiative
echo ============================================================
echo.
echo   1)  Start EFRIS Connect            (use this every day)
echo   2)  First-time HTTPS setup         (run once - admin)
echo   3)  Start automatically at logon
echo   4)  Install as Windows service     (server/always-on - admin)
echo   5)  Trust a server's certificate   (LAN till only - admin)
echo   6)  Uninstall auto-start / service / LAN firewall rules
echo   7)  Reset owner password           (lost password - admin)
echo   8)  Start for shop network (LAN)   (server PC that tills reach)
echo   9)  Start Manager Server for the shop network
echo  10)  Change the Manager Server port   (used by 8 and 9)
echo   0)  Exit
echo.
set "CHOICE="
set /p "CHOICE=  Choose an option and press Enter: "
if "%CHOICE%"=="1" goto do_start
if "%CHOICE%"=="2" goto elevate_https
if "%CHOICE%"=="3" goto do_autostart
if "%CHOICE%"=="4" goto elevate_service
if "%CHOICE%"=="5" goto elevate_trust
if "%CHOICE%"=="6" goto do_uninstall
if "%CHOICE%"=="7" goto elevate_reset_owner
if "%CHOICE%"=="8" goto do_lan
if "%CHOICE%"=="9" goto do_manager_server
if "%CHOICE%"=="10" goto do_change_port
if "%CHOICE%"=="0" exit /b 0
goto menu

REM ------------------------------------------------------------
REM  1) Start the relay and open the extension in the browser
REM ------------------------------------------------------------
:do_start
title EFRIS Connect
REM EFRIS private key (Desktop/Server editions). Edit this path to match your setup.
REM EFRIS private key: usually set per business in Settings > EFRIS Credentials. A key
REM file path saved in the data folder (efris-key-path.txt) is used when present.
if not defined EFRIS_PRIVATE_KEY if exist "%DATADIR%\efris-key-path.txt" set /p EFRIS_PRIVATE_KEY=<"%DATADIR%\efris-key-path.txt"
REM Single-PC Desktop: bind loopback only so the relay is not exposed on the network.
REM For a Server/LAN box other machines must reach, set BIND_HOST=0.0.0.0 before running.
if not defined BIND_HOST set "BIND_HOST=127.0.0.1"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Node.js was not found. Install the LTS version from https://nodejs.org
  echo   and run this again.
  echo.
  pause
  goto menu
)

REM Pick the URL to open: HTTPS if the cert is set up, otherwise HTTP with a nudge.
set "OPENURL=http://localhost:3000/extension"
set "OPENPORT=3000"
set "HAVEPFX="
if exist "%DATADIR%\https.pfx" set "HAVEPFX=1"
if exist "%OLDDATA%\https.pfx" set "HAVEPFX=1"
if defined HAVEPFX set "OPENURL=https://localhost:5443/extension"
if defined HAVEPFX set "OPENPORT=5443"
if not defined HAVEPFX (
  echo.
  echo   NOTE: HTTPS is not set up yet, so the single-document button in Manager
  echo   will not work. Run option 2 once, then start again.
  echo.
)

echo.
echo   Starting EFRIS Connect ...  (leave this window open; close it to stop)
echo   When you see "HTTPS running" below, it is ready. Point Manager's
echo   EFRIS button Endpoint at:  %OPENURL%
echo.
cd /d "%~dp0..\backend"
REM A click in this window must not pause the relay (QuickEdit selection).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0no-quickedit.ps1"
REM The extension runs inside Manager's button window, so by default we do NOT
REM open a standalone browser (it would appear outside Manager, before the server
REM is even up). For standalone testing, run with OPEN_BROWSER=1 - it then WAITS
REM until the server's port actually answers, then opens the page. Never before.
if defined OPEN_BROWSER if not "%OPEN_BROWSER%"=="0" (
  start "" /min powershell -NoProfile -Command "for($i=0;$i -lt 120;$i++){ if(Test-NetConnection -ComputerName localhost -Port %OPENPORT% -InformationLevel Quiet -WarningAction SilentlyContinue){ Start-Process '%OPENURL%'; break } Start-Sleep -Milliseconds 400 }"
)
node server.js
echo.
echo   EFRIS Connect stopped.
pause
goto menu

REM ------------------------------------------------------------
REM  2) First-time HTTPS setup  (self-elevates, then runs setup-https.ps1)
REM ------------------------------------------------------------
:elevate_https
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'setup-https' -Verb RunAs"
echo   An elevated window will open to set up HTTPS. Follow it, then return here.
pause
goto menu

:do_https
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-https.ps1" -DataDir "%DATADIR%"
echo.
echo ============================================================
echo   Offline HTTPS is ready.
echo   1) Start EFRIS Connect (option 1) - watch for
echo        "HTTPS running at https://localhost:5443"
echo   2) In Manager, set each EFRIS custom-button Endpoint to:
echo        https://localhost:5443/extension
echo   3) Open a receipt/invoice - it should load that document.
echo ============================================================
pause
exit /b 0

REM ------------------------------------------------------------
REM  3) Auto-start at logon  (no admin - Startup-folder shortcut)
REM ------------------------------------------------------------
:do_autostart
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%STARTUP%\EFRISConnect.lnk');" ^
  "$s.TargetPath='%~f0'; $s.Arguments='start'; $s.WorkingDirectory='%~dp0';" ^
  "$s.WindowStyle=7; $s.Description='EFRIS Connect relay'; $s.Save()"
if errorlevel 1 ( echo   Could not create the auto-start shortcut. ) else ( echo   Auto-start installed - EFRIS Connect will launch at your next logon. )
echo.
pause
goto menu

REM ------------------------------------------------------------
REM  4) Windows service  (self-elevates; npm install + install-service.js)
REM ------------------------------------------------------------
:elevate_service
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'service-install' -Verb RunAs"
echo   An elevated window will install the service. Follow it, then return here.
pause
goto menu

:do_service_install
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
where node >nul 2>nul
if errorlevel 1 ( echo   Node.js not found - install it from https://nodejs.org first. & pause & exit /b 1 )
echo   Installing node-windows ...
call npm install node-windows
echo   Installing the EFRISConnect service (this also sets up + trusts HTTPS) ...
node "%~dp0install-service.js"
echo.
pause
exit /b 0

REM ------------------------------------------------------------
REM  5) Trust a server's cert on this PC (LAN till, admin)
REM ------------------------------------------------------------
:elevate_trust
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'trust-cert' -Verb RunAs"
echo   An elevated window will trust the certificate. Follow it, then return here.
pause
goto menu

:do_trust
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
REM Default: a copy next to this file, else this PC's own (the server's) till kit.
set "CER="
if exist "%~dp0https_cert.cer" set "CER=%~dp0https_cert.cer"
if not defined CER if exist "%DATADIR%\till-kit\https_cert.cer" set "CER=%DATADIR%\till-kit\https_cert.cer"
if not defined CER if exist "%DATADIR%\https_cert.cer" set "CER=%DATADIR%\https_cert.cer"
if not defined CER if exist "%OLDDATA%\https_cert.cer" set "CER=%OLDDATA%\https_cert.cer"
echo.
echo   Trust the EFRISConnect server's certificate on this PC.
echo   Use the https_cert.cer copied from the server - its till-kit folder in
echo   %%ProgramData%%\EFRISConnect\data\till-kit, on a USB stick or a share.
if defined CER echo   Press Enter to use: %CER%
set "CERIN="
set /p "CERIN=  Path to https_cert.cer: "
if defined CERIN set "CER=%CERIN:"=%"
if not defined CER ( echo   No certificate path given. & pause & exit /b 1 )
if not exist "%CER%" ( echo   Not found: %CER% & pause & exit /b 1 )
certutil -addstore -f Root "%CER%"
if errorlevel 1 ( echo   FAILED: the certificate was not trusted - see the message above. & pause & exit /b 1 )
echo.
echo   Certificate trusted. Restart the browser, then open the server's address, e.g.
echo     https://SERVER-NAME:5443/extension
echo   or open Manager Server in the browser and use its EFRISConnect buttons.
echo   To undo later: certutil -delstore Root "EFRISConnect Local HTTPS"  as administrator.
pause
exit /b 0

REM ------------------------------------------------------------
REM  6) Uninstall auto-start and/or the Windows service
REM ------------------------------------------------------------
:do_uninstall
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
if exist "%STARTUP%\EFRISConnect.lnk" ( del "%STARTUP%\EFRISConnect.lnk" & echo   Auto-start shortcut removed. ) else ( echo   No auto-start shortcut found. )
if exist "%~dp0uninstall-service.js" (
  echo   Removing the Windows service (if installed; needs admin) ...
  node "%~dp0uninstall-service.js"
)
REM Shop-network firewall rules (option 8 / 9): removed only when present.
set "HAVEFW="
netsh advfirewall firewall show rule name="EFRISConnect HTTPS (LAN)" >nul 2>&1 && set "HAVEFW=1"
netsh advfirewall firewall show rule name="EFRISConnect Manager Server (LAN)" >nul 2>&1 && set "HAVEFW=1"
netsh advfirewall firewall show rule name="EFRISConnect Manager HTTPS (LAN)" >nul 2>&1 && set "HAVEFW=1"
if defined HAVEFW (
  echo   Removing the shop-network firewall rules - an admin window opens ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'lan-unfirewall' -Verb RunAs -Wait"
) else (
  echo   No shop-network firewall rules found.
)
echo.
pause
goto menu

REM ------------------------------------------------------------
REM  7) Reset owner password  (self-elevates; writes a one-time
REM     reset code to the protected data folder)
REM ------------------------------------------------------------
:elevate_reset_owner
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'reset-owner' -Verb RunAs"
echo   An elevated window will create a reset code. Follow it, then return here.
pause
goto menu

:do_reset_owner
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
where node >nul 2>nul
if errorlevel 1 ( echo   Node.js not found - install it from https://nodejs.org first. & pause & exit /b 1 )
node "%~dp0..\backend\reset-owner.js"
echo   The code is in: %DATADIR%\EFRIS Connect setup code.txt
echo   Opening it now. Use it on THIS computer under "Forgot password".
if exist "%DATADIR%\EFRIS Connect setup code.txt" start "" notepad "%DATADIR%\EFRIS Connect setup code.txt"
pause
exit /b 0

REM ------------------------------------------------------------
REM  8) Start for shop network (LAN): tills on the same private
REM     Wi-Fi/LAN reach this PC at https://HOSTNAME:5443/extension
REM ------------------------------------------------------------
:do_lan
title EFRIS Connect - shop network
where node >nul 2>nul
if errorlevel 1 ( echo   Node.js was not found - install the LTS version from https://nodejs.org & pause & goto menu )
set "HAVEPFX="
if exist "%DATADIR%\https.pfx" set "HAVEPFX=1"
if exist "%OLDDATA%\https.pfx" set "HAVEPFX=1"
if not defined HAVEPFX (
  echo.
  echo   HTTPS is not set up on this PC yet. Tills only connect over HTTPS.
  echo   Run option 2 - First-time HTTPS setup - once, then choose 8 again.
  echo.
  pause
  goto menu
)
set "LANCMD=%TEMP%\efrisconnect-lan.cmd"
if exist "%LANCMD%" del "%LANCMD%" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lan.ps1" -Action config -Out "%LANCMD%"
if not exist "%LANCMD%" ( echo   Could not read this PC's network addresses. & pause & goto menu )
call "%LANCMD%"
del "%LANCMD%" >nul 2>&1
if not defined LANIPS (
  echo.
  echo   This PC has no private network address - 10.x, 172.16-31.x or 192.168.x.
  echo   Connect it to the shop Wi-Fi or LAN, then choose 8 again.
  echo.
  pause
  goto menu
)
REM Manager Server Edition port on this PC: tills open Manager at http://HOSTNAME:PORT,
REM and that page frames EFRISConnect, so the relay must allow it. Asked once, saved.
set "MGRPORT=5000"
if exist "%DATADIR%\lan-manager-port.txt" set /p MGRPORT=<"%DATADIR%\lan-manager-port.txt"
REM Asked only the first time; launcher option 10 changes it later.
if exist "%DATADIR%\lan-manager-port.txt" goto lan_port_known
set "NEWPORT="
set /p "NEWPORT=  Manager Server port on this PC [5000] - press Enter to keep: "
if defined NEWPORT set "MGRPORT=%NEWPORT%"
:lan_port_known
echo %MGRPORT%| findstr /r "^[0-9][0-9]*$" >nul || set "MGRPORT=5000"
> "%DATADIR%\lan-manager-port.txt" echo %MGRPORT%
echo   Manager Server port: %MGRPORT%   (option 10 changes it)
REM Tills open Manager over HTTPS on the next port (the relay passes it on to Manager Server).
set /a MGRHTTPS=%MGRPORT%+1
REM Firewall: inbound TCP 5443 and the Manager HTTPS port, Private networks only (one admin prompt).
set "NEEDFW="
netsh advfirewall firewall show rule name="EFRISConnect HTTPS (LAN)" >nul 2>&1 || set "NEEDFW=1"
netsh advfirewall firewall show rule name="EFRISConnect Manager HTTPS (LAN)" >nul 2>&1 || set "NEEDFW=1"
if defined NEEDFW (
  echo   Allowing tills through Windows Firewall - Private networks only. Approve the admin prompt.
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'lan-firewall %MGRHTTPS%' -Verb RunAs -Wait"
)
REM EFRIS private key: usually set per business in Settings > EFRIS Credentials. A key
REM file path saved in the data folder (efris-key-path.txt) is used when present.
if not defined EFRIS_PRIVATE_KEY if exist "%DATADIR%\efris-key-path.txt" set /p EFRIS_PRIVATE_KEY=<"%DATADIR%\efris-key-path.txt"
set "BIND_HOST=0.0.0.0"
set "LAN_MODE=1"
set "MANAGER_PORTS=%MGRPORT%"
set "MANAGER_HTTPS_PORT=%MGRHTTPS%"
echo.
echo ============================================================
echo   Shop network mode
echo   Tills open, after trusting the certificate once:
for %%u in (%LANHOST% %LANIPS%) do echo     https://%%u:5443/extension
echo   Manager custom button URL - every EFRISConnect button:
echo     https://%LANHOST%:5443/extension
echo   Manager for tills (encrypted): https://%LANHOST%:%MGRHTTPS%
echo   Till kit - copy to each till, run "Trust EFRISConnect server.bat":
echo     %DATADIR%\till-kit
if defined LANPUBLIC echo   WARNING: network "%LANPUBLIC%" is set to Public. Set it to Private in Windows Settings - Network - the network - or tills cannot connect.
echo ============================================================
echo.
cd /d "%~dp0..\backend"
REM A click in this window must not pause the relay (QuickEdit selection).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0no-quickedit.ps1"
node server.js
echo.
echo   EFRIS Connect stopped.
pause
goto menu

:do_lan_firewall
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
set "FWHTTPS=%~2"
if not defined FWHTTPS set "FWHTTPS=0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lan.ps1" -Action firewall -ManagerHttpsPort %FWHTTPS%
timeout /t 3 >nul
exit /b 0

:do_manager_firewall
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
set "FWPORT=%~2"
if not defined FWPORT set "FWPORT=5000"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lan.ps1" -Action manager-firewall -ManagerPort %FWPORT%
timeout /t 3 >nul
exit /b 0

:do_manager_unfirewall
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lan.ps1" -Action manager-unfirewall
timeout /t 3 >nul
exit /b 0

:do_lan_unfirewall
net session >nul 2>&1
if not "%errorlevel%"=="0" ( echo   Please run this step as Administrator. & pause & exit /b 1 )
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lan.ps1" -Action unfirewall
timeout /t 3 >nul
exit /b 0

REM ------------------------------------------------------------
REM  9) Start Manager Server Edition for the shop network:
REM     ManagerServer.exe --urls http://127.0.0.1:PORT (this PC only);
REM     tills reach it encrypted through option 8 at https://HOSTNAME:PORT+1.
REM     Path asked once and saved.
REM ------------------------------------------------------------
:do_manager_server
set "MSEXE="
if exist "%DATADIR%\manager-server-path.txt" set /p MSEXE=<"%DATADIR%\manager-server-path.txt"
if not defined MSEXE if exist "%ProgramFiles%\Manager Server\ManagerServer.exe" set "MSEXE=%ProgramFiles%\Manager Server\ManagerServer.exe"
if not defined MSEXE if exist "%LOCALAPPDATA%\Programs\Manager Server\ManagerServer.exe" set "MSEXE=%LOCALAPPDATA%\Programs\Manager Server\ManagerServer.exe"
if defined MSEXE echo   Manager Server: %MSEXE%
set "MSIN="
set /p "MSIN=  Full path to ManagerServer.exe - press Enter to keep the one above: "
if defined MSIN set "MSEXE=%MSIN:"=%"
if not defined MSEXE ( echo   No path given. & pause & goto menu )
if not exist "%MSEXE%" ( echo   Not found: %MSEXE% & pause & goto menu )
> "%DATADIR%\manager-server-path.txt" echo %MSEXE%
set "MGRPORT=5000"
if exist "%DATADIR%\lan-manager-port.txt" set /p MGRPORT=<"%DATADIR%\lan-manager-port.txt"
REM Asked only the first time; option 10 changes it later.
if exist "%DATADIR%\lan-manager-port.txt" goto ms_port_known
set "NEWPORT="
set /p "NEWPORT=  Port for Manager Server [%MGRPORT%] - press Enter to keep: "
if defined NEWPORT set "MGRPORT=%NEWPORT%"
:ms_port_known
echo %MGRPORT%| findstr /r "^[0-9][0-9]*$" >nul || set "MGRPORT=5000"
> "%DATADIR%\lan-manager-port.txt" echo %MGRPORT%
echo   Manager Server port: %MGRPORT%   (option 10 changes it)
echo.
echo   IMPORTANT: close Manager Desktop first. Manager Server uses the same data
echo   folder by default, and both must never have it open at the same time.
echo.
REM Manager Server listens on this PC only; tills reach it encrypted through
REM EFRISConnect (option 8) at https://PCNAME:PORT+1. The old plain-HTTP rule goes.
netsh advfirewall firewall show rule name="EFRISConnect Manager Server (LAN)" >nul 2>&1
if not errorlevel 1 (
  echo   Closing plain-HTTP Manager access from tills - they use the encrypted address. Approve the admin prompt.
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList 'manager-unfirewall' -Verb RunAs -Wait"
)
for %%D in ("%MSEXE%") do set "MSDIR=%%~dpD"
REM Business data folder: a local folder (not OneDrive) when one is saved.
set "MSDATA="
if exist "%DATADIR%\manager-server-data.txt" set /p MSDATA=<"%DATADIR%\manager-server-data.txt"
if defined MSDATA (
  echo   Manager data folder: %MSDATA%
  start "Manager Server" /D "%MSDIR%" "%MSEXE%" --urls http://127.0.0.1:%MGRPORT% --path "%MSDATA%"
) else (
  start "Manager Server" /D "%MSDIR%" "%MSEXE%" --urls http://127.0.0.1:%MGRPORT%
)
echo   Manager Server is starting in its own window - leave it open.
set /a MGRHTTPS=%MGRPORT%+1
echo   On this PC:  http://localhost:%MGRPORT%  or  https://localhost:%MGRHTTPS%
echo   On tills:    https://%COMPUTERNAME%:%MGRHTTPS%   (encrypted, needs option 8 running)
echo   EFRISConnect's Manager endpoint on this PC: http://127.0.0.1:%MGRPORT%/api2
echo   Then start EFRISConnect with option 8 and set the custom buttons to
echo     https://%COMPUTERNAME%:5443/extension
echo.
pause
goto menu

REM ------------------------------------------------------------
REM  10) Change the Manager Server port (saved for options 8 and 9)
REM ------------------------------------------------------------
:do_change_port
set "MGRPORT=5000"
if exist "%DATADIR%\lan-manager-port.txt" set /p MGRPORT=<"%DATADIR%\lan-manager-port.txt"
set "NEWPORT="
set /p "NEWPORT=  Manager Server port [%MGRPORT%] - type the new port, or Enter to keep: "
if defined NEWPORT set "MGRPORT=%NEWPORT%"
echo %MGRPORT%| findstr /r "^[0-9][0-9]*$" >nul || set "MGRPORT=5000"
> "%DATADIR%\lan-manager-port.txt" echo %MGRPORT%
echo   Saved: Manager Server port %MGRPORT%. Restart options 8 and 9 to use it.
pause
goto menu
