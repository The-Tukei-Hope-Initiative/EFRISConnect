@echo off
REM ============================================================
REM  EFRIS Connect / Goods Configurator - all-in-one launcher
REM  (Manager Desktop and Server/LAN editions)
REM
REM  Just double-click this file. It shows a menu:
REM    1) Start EFRIS Connect        <- everyday use
REM    2) First-time HTTPS setup     <- run once (needs admin)
REM    3) Start automatically at logon
REM    4) Install as a Windows service (server/always-on, admin)
REM    5) Trust a server's certificate on this PC (LAN till, admin)
REM    6) Uninstall auto-start / service
REM
REM  The admin steps (2, 4, 5) relaunch this file elevated on their
REM  own - you don't need to open an admin prompt yourself.
REM ============================================================
setlocal EnableExtensions
cd /d "%~dp0"

REM --- Internal dispatch: elevated relaunches jump straight to a task ---
if /i "%~1"=="setup-https"      goto do_https
if /i "%~1"=="service-install"  goto do_service_install
if /i "%~1"=="trust-cert"       goto do_trust

:menu
cls
echo ============================================================
echo   EFRIS Connect  /  Goods Configurator
echo   Tukei Hope Initiative
echo ============================================================
echo.
echo   1)  Start EFRIS Connect            (use this every day)
echo   2)  First-time HTTPS setup         (run once - admin)
echo   3)  Start automatically at logon
echo   4)  Install as Windows service     (server/always-on - admin)
echo   5)  Trust a server's certificate   (LAN till only - admin)
echo   6)  Uninstall auto-start / service
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
if "%CHOICE%"=="0" exit /b 0
goto menu

REM ------------------------------------------------------------
REM  1) Start the relay and open the extension in the browser
REM ------------------------------------------------------------
:do_start
title EFRIS Connect
REM EFRIS private key (Desktop/Server editions). Edit this path to match your setup.
if not defined EFRIS_PRIVATE_KEY set "EFRIS_PRIVATE_KEY=F:\EFRIS_Keys\efris_private_v2.pem"
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
if exist "%~dp0..\backend\data\https.pfx" set "OPENURL=https://localhost:5443/extension"
if not exist "%~dp0..\backend\data\https.pfx" (
  echo.
  echo   NOTE: HTTPS is not set up yet, so the single-document button in Manager
  echo   will not work. Run option 2 once, then start again.
  echo.
)

echo.
echo   Starting EFRIS Connect ...  (leave this window open; close it to stop)
echo   Opening %OPENURL%
echo.
cd /d "%~dp0..\backend"
start "" /min cmd /c "timeout /t 3 >nul & start "" %OPENURL%"
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
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-https.ps1" -DataDir "%~dp0..\backend\data"
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
set "CER=%~dp0https_cert.cer"
if not exist "%CER%" set "CER=%~dp0..\backend\data\https_cert.cer"
if not exist "%CER%" (
  echo   Could not find https_cert.cer.
  echo   Copy it from the server's backend\data folder next to this file, then re-run.
  pause
  exit /b 1
)
certutil -addstore -f Root "%CER%"
echo.
echo   Certificate trusted. Point Manager on this PC at the server URL, e.g.
echo     https://SERVER-NAME:5443/extension
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
echo.
pause
goto menu
