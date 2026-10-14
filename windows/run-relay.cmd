@echo off
REM ============================================================
REM  EFRISConnect relay runner for the installed version.
REM  Started by the "EFRISConnect Relay" scheduled task at Windows
REM  startup (account SYSTEM, no window). Reads the mode the
REM  installer saved, works out this PC's network addresses on every
REM  start (they can change), then keeps the relay running and
REM  restarts it after a crash.
REM ============================================================
setlocal EnableExtensions
set "APPDIR=%~dp0.."
set "DATADIR=%ProgramData%\EFRISConnect\data"
set "NODE=%APPDIR%\node\node.exe"
if not exist "%NODE%" set "NODE=node"
set "MODE=single"
if exist "%DATADIR%\install-mode.txt" set /p MODE=<"%DATADIR%\install-mode.txt"
if /i "%MODE%"=="server" call :lan
cd /d "%APPDIR%\backend"

:loop
REM The relay keeps its own daily logs in %DATADIR%\logs; only crashes land here.
"%NODE%" server.js >nul 2>>"%DATADIR%\relay-crash.log"
REM ping instead of timeout: timeout fails when the task has no console.
ping -n 6 127.0.0.1 >nul
goto loop

REM ------------------------------------------------------------
REM  Shop network mode: listen on the LAN, allow this PC's names
REM  and addresses, and allow Manager Server's port to frame us.
REM  At boot the network may not be up yet: wait up to a minute.
REM ------------------------------------------------------------
:lan
set "LANCMD=%TEMP%\efrisconnect-lan-task.cmd"
set /a TRIES=0
:lanretry
set "LANIPS="
if exist "%LANCMD%" del "%LANCMD%" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0lan.ps1" -Action config -Out "%LANCMD%"
if exist "%LANCMD%" call "%LANCMD%"
if defined LANIPS goto lanok
set /a TRIES+=1
if %TRIES% lss 12 ( ping -n 6 127.0.0.1 >nul & goto lanretry )
:lanok
if exist "%LANCMD%" del "%LANCMD%" >nul 2>&1
set "MGRPORT=5000"
if exist "%DATADIR%\lan-manager-port.txt" set /p MGRPORT=<"%DATADIR%\lan-manager-port.txt"
set "BIND_HOST=0.0.0.0"
set "LAN_MODE=1"
set "MANAGER_PORTS=%MGRPORT%"
set /a MANAGER_HTTPS_PORT=%MGRPORT%+1
exit /b 0
