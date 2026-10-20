# EFRISConnect - notification-area (tray) icon for the installed version.
# Started at sign-in by tray.vbs (no console window). Shows whether the relay is
# running and how many sales wait for URA, and offers the everyday actions.
# Green: running. Amber: running with sales queued for URA. Red: not answering.
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Windows names the sender of the tray's pop-ups after the process ("Windows PowerShell")
# unless the process carries the same app ID as the Start-menu shortcut (EFRISConnect).
try {
  Add-Type -Namespace EFC -Name Shell -MemberDefinition '[DllImport("shell32.dll")] public static extern int SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string id);'
  [void][EFC.Shell]::SetCurrentProcessExplicitAppUserModelID('TukeiHope.EFRISConnect')
} catch {}

# One tray icon per signed-in user.
$created = $false
$mutex = New-Object Threading.Mutex($true, 'Local\EFRISConnectTray', [ref]$created)
if (!$created) { exit }

$AppDir  = Split-Path -Parent $PSScriptRoot
$DataDir = Join-Path $env:ProgramData 'EFRISConnect\data'
$Helper  = Join-Path $PSScriptRoot 'install-helper.ps1'
function Read-Setting([string]$n, [string]$def) {
  $f = Join-Path $DataDir $n
  if (Test-Path $f) { $v = (Get-Content $f -TotalCount 1).Trim(); if ($v) { return $v } }
  return $def
}
$Mode    = Read-Setting 'install-mode.txt' 'single'
$MgrPort = Read-Setting 'lan-manager-port.txt' '5000'
$MgrExe  = Read-Setting 'manager-server-path.txt' ''
$MgrData = Read-Setting 'manager-server-data.txt' ''
$Host_   = $env:COMPUTERNAME.ToLower()
$ExtUrl  = 'https://localhost:5443/extension'
$BtnUrl  = if ($Mode -eq 'server') { "https://${Host_}:5443/extension" } else { $ExtUrl }

# The EFRISConnect icon with a status dot in its corner (green, amber, red); a plain
# dot when the icon file is missing.
$AppIcon = $null
try { $AppIcon = New-Object Drawing.Icon((Join-Path $AppDir 'efrisconnect.ico'), 32, 32) } catch {}
function New-DotIcon([Drawing.Color]$c) {
  $bmp = New-Object Drawing.Bitmap 32, 32
  $g = [Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'; $g.InterpolationMode = 'HighQualityBicubic'
  if ($AppIcon) {
    $g.DrawImage($AppIcon.ToBitmap(), 0, 0, 32, 32)
    $g.FillEllipse((New-Object Drawing.SolidBrush $c), 17, 17, 14, 14)
    $g.DrawEllipse((New-Object Drawing.Pen ([Drawing.Color]::White), 2), 17, 17, 14, 14)
  } else {
    $g.FillEllipse((New-Object Drawing.SolidBrush $c), 2, 2, 28, 28)
    $g.DrawEllipse((New-Object Drawing.Pen ([Drawing.Color]::White), 3), 2, 2, 28, 28)
  }
  $g.Dispose()
  [Drawing.Icon]::FromHandle($bmp.GetHicon())
}
$Icons = @{
  ok    = New-DotIcon ([Drawing.Color]::FromArgb(46, 125, 50))
  queue = New-DotIcon ([Drawing.Color]::FromArgb(245, 159, 0))
  down  = New-DotIcon ([Drawing.Color]::FromArgb(198, 40, 40))
}

$tray = New-Object Windows.Forms.NotifyIcon
$tray.Icon = $Icons.down
$tray.Text = 'EFRISConnect - checking ...'
$tray.Visible = $true
$menu = New-Object Windows.Forms.ContextMenuStrip
function Add-Item([string]$text, [scriptblock]$do) { $i = $menu.Items.Add($text); $i.add_Click($do); $i }
function Run-Elevated([string]$action) {
  Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Helper`" -Action $action"
}

$status = $menu.Items.Add('Checking ...'); $status.Enabled = $false
[void]$menu.Items.Add('-')
[void](Add-Item 'Open EFRISConnect' { Start-Process $ExtUrl })
# The Relay window: status, setup and live activity, with Start / Restart / Stop.
function Open-RelayWindow { Start-Process wscript.exe -ArgumentList "`"$(Join-Path $PSScriptRoot 'relay-window.vbs')`"" }
$rw = Add-Item 'Relay window (status and activity)' { Open-RelayWindow }
if ($Mode -eq 'server') {
  [void](Add-Item 'Open Manager' { Start-Process "https://localhost:$([int]$MgrPort + 1)" })
  if ($MgrExe) {
    [void](Add-Item 'Start Manager Server' {
      if (Get-Process -Name 'ManagerServer' -ErrorAction SilentlyContinue) { $tray.ShowBalloonTip(4000, 'EFRISConnect', 'Manager Server is already running.', 'Info'); return }
      $msArgs = "--urls http://127.0.0.1:$MgrPort"; if ($MgrData) { $msArgs += " --path `"$MgrData`"" }
      Start-Process -FilePath $MgrExe -ArgumentList $msArgs -WorkingDirectory (Split-Path -Parent $MgrExe) -WindowStyle Minimized
    })
  }
}
[void](Add-Item 'Copy Manager button URL' {
  [Windows.Forms.Clipboard]::SetText($BtnUrl)
  $tray.ShowBalloonTip(4000, 'EFRISConnect', "Copied: $BtnUrl", 'Info')
})
[void]$menu.Items.Add('-')
# The relay runs as a Windows scheduled task (EFRISConnect Relay, as SYSTEM, at start-up).
$relayMenu = New-Object Windows.Forms.ToolStripMenuItem 'EFRISConnect (the relay)'
[void]$relayMenu.DropDownItems.Add('Relay window ...').add_Click({ Open-RelayWindow })
[void]$relayMenu.DropDownItems.Add('-')
foreach ($pair in @(@('Start', 'start'), @('Restart', 'restart'), @('Stop', 'relay-stop'))) {
  $it = $relayMenu.DropDownItems.Add($pair[0]); $act = $pair[1]
  if ($act -eq 'relay-stop') {
    $it.add_Click({
      $a = [Windows.Forms.MessageBox]::Show('Stop EFRISConnect? Sales cannot be fiscalised until it is started again.', 'EFRISConnect', 'OKCancel', 'Warning')
      if ($a -eq 'OK') { Run-Elevated 'relay-stop' }
    })
  } else { $it.add_Click({ Run-Elevated $act }.GetNewClosure()) }
}
[void]$menu.Items.Add($relayMenu)
[void](Add-Item 'Open data folder' { Start-Process explorer.exe $DataDir })
[void](Add-Item 'Open logs folder' { Start-Process explorer.exe (Join-Path $DataDir 'logs') })
if ($Mode -eq 'server') { [void](Add-Item 'Open till kit folder' { Start-Process explorer.exe (Join-Path $DataDir 'till-kit') }) }
# URA Offline Enabler, when installed on this computer.
if (Get-Service -Name 'TcsTomcat' -ErrorAction SilentlyContinue) {
  $en = New-Object Windows.Forms.ToolStripMenuItem 'Offline Enabler'
  foreach ($pair in @(@('Start', 'enabler-start'), @('Restart', 'enabler-restart'), @('Stop', 'enabler-stop'))) {
    $it = $en.DropDownItems.Add($pair[0]); $act = $pair[1]
    $it.add_Click({ Run-Elevated $act }.GetNewClosure())
  }
  [void]$menu.Items.Add($en)
}
[void](Add-Item 'Reset owner password ...' {
  $a = [Windows.Forms.MessageBox]::Show('Create a one-time code to reset the owner password? Use it on this computer under "Forgot password".', 'EFRISConnect', 'OKCancel', 'Question')
  if ($a -eq 'OK') { Run-Elevated 'reset-owner' }
})
[void]$menu.Items.Add('-')
[void](Add-Item 'Hide this icon' { $tray.Visible = $false; [Windows.Forms.Application]::Exit() })
$tray.ContextMenuStrip = $menu
$tray.add_DoubleClick({ Start-Process $ExtUrl })

# Status: the relay's public health check, plus the offline queue file.
# A slow PC can take several seconds to answer while Windows starts or under load,
# so one missed check is not "stopped": it takes 3 in a row (about 30 seconds),
# and none count in the first 90 seconds after the tray starts.
$script:last = ''
$script:fails = 0
$script:warnedDown = $false
$script:started = Get-Date
function Update-Status {
  $up = $false
  try { $r = Invoke-WebRequest -Uri 'https://localhost:5443/api/health' -UseBasicParsing -TimeoutSec 8; $up = ($r.StatusCode -eq 200) } catch {}
  if ($up) { $script:fails = 0 } else { $script:fails++ }
  $starting = ((Get-Date) - $script:started).TotalSeconds -lt 90
  $down = (!$up) -and ($script:fails -ge 3) -and (!$starting)
  $q = 0; $old = 0
  # Only sales still waiting (sent ones stay in the file for a day). Windows PowerShell
  # passes a JSON array on as one object, so enumerate it with ForEach-Object.
  try {
    $pend = @((Get-Content (Join-Path $DataDir 'offline_queue.json') -Raw | ConvertFrom-Json) | ForEach-Object { $_ } | Where-Object { $_.status -eq 'pending' })
    $q = $pend.Count
    $cut = (Get-Date).ToUniversalTime().AddHours(-24)
    $old = @($pend | Where-Object { $t = $_.saleAt; if (!$t) { $t = $_.createdAt }; try { ([DateTime]::Parse($t)).ToUniversalTime() -lt $cut } catch { $false } }).Count
  } catch {}
  # The URA Offline Enabler, when installed here.
  $en = ''
  $svc = Get-Service -Name 'TcsTomcat' -ErrorAction SilentlyContinue
  if ($svc) { $en = if ($svc.Status -eq 'Running') { 'Enabler ready' } else { 'Enabler stopped' } }
  if ($down)     { $state = 'down';  $text = 'EFRISConnect - not running' }
  elseif (!$up)  { $state = if ($script:last) { $script:last } else { 'down' }; $text = 'EFRISConnect - starting or busy' }
  elseif ($q -gt 0) { $state = 'queue'; $text = "EFRISConnect - running - $q waiting for URA"; if ($old -gt 0) { $text += " ($old over 24 h)" } }
  else           { $state = 'ok';    $text = 'EFRISConnect - running' }
  if ($up -and $en) { $text += ' - ' + $en }
  $tray.Icon = $Icons[$state]
  $tray.Text = $text.Substring(0, [Math]::Min(63, $text.Length))
  $status.Text = $text
  if ($script:last -and $script:last -ne $state) {
    if ($state -eq 'down') { $script:warnedDown = $true; $tray.ShowBalloonTip(6000, 'EFRISConnect', 'EFRISConnect stopped answering. Right-click the icon and choose Restart.', 'Warning') }
    elseif ($script:last -eq 'down' -and $script:warnedDown) { $script:warnedDown = $false; $tray.ShowBalloonTip(4000, 'EFRISConnect', 'EFRISConnect is running again.', 'Info') }
    elseif ($state -eq 'ok' -and $script:last -eq 'queue') { $tray.ShowBalloonTip(4000, 'EFRISConnect', 'All queued sales have been sent to URA.', 'Info') }
  }
  # Once a day while sales wait more than 24 hours.
  if ($old -gt 0 -and $script:overdueDay -ne (Get-Date).Date) {
    $script:overdueDay = (Get-Date).Date
    $tray.ShowBalloonTip(8000, 'EFRISConnect', "$old sale(s) have waited more than 24 hours for URA. Start the Offline Enabler or call URA support.", 'Warning')
  }
  if (!$up -and !$down -and !$script:last) { return }   # still starting: decide on a later check
  $script:last = $state
}
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 10000
$timer.add_Tick({ Update-Status })
$timer.Start()
Update-Status
[Windows.Forms.Application]::Run()
$tray.Dispose()
$mutex.ReleaseMutex()
