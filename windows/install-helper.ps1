# EFRISConnect - installer helper. Run by EFRISConnect-Setup.exe (admin) and by the
# tray app (restart, reset owner). Every action is safe to repeat.
#
#   -Action setup   -Mode single|server [-ManagerExe <path>] [-ManagerPort 5000]
#                   [-KeyFile <path.pem>] [-User DOMAIN\name]
#       Data folder, HTTPS certificate (first time only), firewall rules (server),
#       the "EFRISConnect Relay" startup task and, with -ManagerExe, the
#       "EFRISConnect Manager Server" logon task. Starts the relay.
#   -Action till    -CertFile <https_cert.cer>
#       Trusts the shop server's certificate on this till.
#   -Action stop          Stops the relay and the tray icon (before an upgrade).
#   -Action restart       Restarts the relay (tray menu).
#   -Action reset-owner   One-time owner reset code, opened in Notepad (tray menu).
#   -Action uninstall [-RemoveCert] [-RemoveData]
#       Removes the tasks and firewall rules; optionally the certificate and data.
param(
  [ValidateSet('setup', 'till', 'stop', 'restart', 'reset-owner', 'uninstall')][string]$Action = 'setup',
  [ValidateSet('single', 'server')][string]$Mode = 'single',
  [string]$ManagerExe = '',
  [int]$ManagerPort = 5000,
  [string]$KeyFile = '',
  [string]$CertFile = '',
  [string]$User = '',
  [switch]$RemoveCert,
  [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
$AppDir = Split-Path -Parent $PSScriptRoot
$WinDir = $PSScriptRoot
$Root = Join-Path $env:ProgramData 'EFRISConnect'
$DataDir = Join-Path $Root 'data'
$Node = Join-Path $AppDir 'node\node.exe'
$RelayTask = 'EFRISConnect Relay'
$ManagerTask = 'EFRISConnect Manager Server'
$CertSubject = 'CN=EFRISConnect Local HTTPS'
$LogFile = Join-Path $Root 'install.log'

function Log([string]$m) {
  Write-Host "  $m"
  try { if (!(Test-Path $Root)) { New-Item -ItemType Directory -Path $Root | Out-Null }
        Add-Content -Path $LogFile -Value ("{0:yyyy-MM-dd HH:mm:ss}  {1}" -f (Get-Date), $m) -Encoding UTF8 } catch {}
}

function Write-Setting([string]$name, [string]$value) {
  # cmd.exe reads these with "set /p": one ASCII line, no trailing newline issues.
  [IO.File]::WriteAllText((Join-Path $DataDir $name), $value + "`r`n", [Text.Encoding]::ASCII)
}

# Stop relay processes started from this install only (never other Node programs).
function Stop-Relay {
  try { Stop-ScheduledTask -TaskName $RelayTask -ErrorAction SilentlyContinue } catch {}
  $mine = Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='cmd.exe'" -ErrorAction SilentlyContinue |
    Where-Object { ($_.ExecutablePath -and $_.ExecutablePath -ieq $Node) -or ($_.CommandLine -and $_.CommandLine -like "*$WinDir\run-relay.cmd*") }
  foreach ($p in $mine) { try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }
}

# The tray icon of every signed-in user (it reads files from this install).
function Stop-Tray {
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -like "*$WinDir\tray.ps1*" } |
    ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }
}

function Register-RelayTask {
  $act = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/d /c `"`"$WinDir\run-relay.cmd`"`"" -WorkingDirectory "$AppDir\backend"
  $trg = New-ScheduledTaskTrigger -AtStartup
  $pri = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
  $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
         -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $RelayTask -Action $act -Trigger $trg -Principal $pri -Settings $set `
    -Description 'EFRISConnect relay (Manager.io <-> URA EFRIS). Installed by EFRISConnect Setup.' -Force | Out-Null
  Log "Startup task '$RelayTask' registered (runs at Windows startup, before anyone signs in)."
}

# Manager Server keeps its businesses in the signed-in user's profile, so it runs at
# that user's logon (minimised window), exactly like launcher option 9.
function Register-ManagerTask([string]$exe, [int]$port, [string]$who) {
  $dir = Split-Path -Parent $exe
  $dataArg = ''
  $df = Join-Path $DataDir 'manager-server-data.txt'
  if (Test-Path $df) { $d = (Get-Content $df -TotalCount 1).Trim(); if ($d) { $dataArg = " --path `"$d`"" } }
  $act = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" `
         -Argument "/d /c start `"Manager Server`" /min /D `"$dir`" `"$exe`" --urls http://127.0.0.1:$port$dataArg" -WorkingDirectory $dir
  $trg = New-ScheduledTaskTrigger -AtLogOn -User $who
  $pri = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Limited
  $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $ManagerTask -Action $act -Trigger $trg -Principal $pri -Settings $set `
    -Description "Manager Server Edition for the shop network (port $port). Installed by EFRISConnect Setup." -Force | Out-Null
  Log "Logon task '$ManagerTask' registered for $who (http://127.0.0.1:$port, tills use https on port + 1)."
}

switch ($Action) {
  'setup' {
    Log "Setup started: mode $Mode, app folder $AppDir"
    if (!(Test-Path $Node)) { throw "Bundled Node.js not found at $Node" }
    if (!(Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    if (!$User) { $User = "$env:USERDOMAIN\$env:USERNAME" }
    # Same restriction backend/paths.js applies (this user, SYSTEM, Administrators), done
    # here first: the relay now runs as SYSTEM and would otherwise grant only itself,
    # locking the signed-in user (tray, logs folder) out.
    if (!(Test-Path (Join-Path $DataDir '.acl_v1'))) {
      $sid = (New-Object Security.Principal.NTAccount($User)).Translate([Security.Principal.SecurityIdentifier]).Value
      & icacls.exe $DataDir /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
      & icacls.exe (Join-Path $DataDir '*') /reset /T /C /Q 2>$null | Out-Null
      [IO.File]::WriteAllText((Join-Path $DataDir '.acl_v1'), (Get-Date).ToString('o'))
      Log "Data folder limited to $User, SYSTEM and Administrators."
    }
    Write-Setting 'install-mode.txt' $Mode

    # Old launcher-era service (node-windows) would hold the same ports.
    if (Get-Service -Name 'efrisconnect.exe', 'EFRISConnect' -ErrorAction SilentlyContinue) {
      Log 'WARNING: an older EFRISConnect Windows service exists. Remove it with the old launcher (option 6) so it does not hold port 5443.'
    }

    # HTTPS certificate: only when none exists, so tills that already trust it keep working.
    if (!(Test-Path (Join-Path $DataDir 'https.pfx'))) {
      Log 'Creating the HTTPS certificate for this PC ...'
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $WinDir 'setup-https.ps1') -DataDir $DataDir
      if ($LASTEXITCODE) { throw 'HTTPS certificate setup failed (see above).' }
    } else { Log 'HTTPS certificate already present - kept.' }
    # The relay task runs as SYSTEM: it must be able to read the PFX password.
    $pass = Join-Path $DataDir 'https_pfx_pass.txt'
    if (Test-Path $pass) { & icacls.exe $pass /grant '*S-1-5-18:R' | Out-Null }

    if ($KeyFile) {
      if (!(Test-Path $KeyFile)) { throw "EFRIS private key not found: $KeyFile" }
      Copy-Item -LiteralPath $KeyFile -Destination (Join-Path $DataDir 'private_key.pem') -Force
      Log 'EFRIS private key copied into the protected data folder (private_key.pem).'
    }

    if ($Mode -eq 'server') {
      Write-Setting 'lan-manager-port.txt' "$ManagerPort"
      & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $WinDir 'lan.ps1') -Action firewall -ManagerHttpsPort ($ManagerPort + 1)
      if ($ManagerExe) {
        if (!(Test-Path $ManagerExe)) { throw "ManagerServer.exe not found: $ManagerExe" }
        Write-Setting 'manager-server-path.txt' $ManagerExe
        # Manager Server listens on this PC only; tills use the relay's encrypted front.
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $WinDir 'lan.ps1') -Action manager-unfirewall
        Register-ManagerTask $ManagerExe $ManagerPort $User
      }
    }

    Stop-Relay
    Register-RelayTask
    Start-ScheduledTask -TaskName $RelayTask
    # Wait for the relay to answer (first start creates the till kit and setup code).
    $up = $false
    for ($i = 0; $i -lt 40 -and !$up; $i++) {
      Start-Sleep -Milliseconds 750
      try { $up = (Test-NetConnection -ComputerName localhost -Port 5443 -InformationLevel Quiet -WarningAction SilentlyContinue) } catch {}
    }
    if ($up) { Log 'EFRISConnect is running at https://localhost:5443/extension' }
    else { Log "EFRISConnect did not answer within 30 seconds. See $DataDir\relay-crash.log and $DataDir\logs." }
  }

  'till' {
    if (!$CertFile -or !(Test-Path $CertFile)) { throw "Server certificate not found: $CertFile" }
    $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2($CertFile)
    if ($c.HasPrivateKey) { throw 'That file contains a private key. Use https_cert.cer from the till kit, never the PFX.' }
    & certutil.exe -addstore -f Root $CertFile | Out-Null
    if ($LASTEXITCODE) { throw 'certutil could not trust the certificate.' }
    Log "Trusted the shop server certificate $($c.Subject) (thumbprint $($c.Thumbprint))."
  }

  'stop' {
    Stop-Relay
    Stop-Tray
    Log 'Relay and tray icon stopped.'
  }

  'restart' {
    Stop-Relay
    Start-ScheduledTask -TaskName $RelayTask
    Log 'Relay restarted.'
  }

  'reset-owner' {
    & $Node (Join-Path $AppDir 'backend\reset-owner.js')
    $f = Join-Path $DataDir 'EFRIS Connect setup code.txt'
    if (Test-Path $f) { Start-Process notepad.exe -ArgumentList "`"$f`"" }
  }

  'uninstall' {
    Stop-Relay
    Stop-Tray
    foreach ($t in @($RelayTask, $ManagerTask)) {
      if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $t -Confirm:$false; Log "Removed task '$t'."
      }
    }
    try { & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $WinDir 'lan.ps1') -Action unfirewall } catch {}
    if ($RemoveCert) {
      foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\My') {
        Get-ChildItem $store | Where-Object { $_.Subject -eq $CertSubject } | ForEach-Object {
          Remove-Item -LiteralPath $_.PSPath -Force; Log "Removed certificate $($_.Thumbprint) from $store."
        }
      }
    }
    if ($RemoveData -and (Test-Path $DataDir)) {
      Remove-Item -LiteralPath $DataDir -Recurse -Force
      Log 'Removed the data folder (vault, logs, receipts history).'
    }
  }
}
