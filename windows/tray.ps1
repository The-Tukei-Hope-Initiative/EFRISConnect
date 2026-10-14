# EFRISConnect - notification-area (tray) icon for the installed version.
# Started at sign-in by tray.vbs (no console window). Shows whether the relay is
# running and how many sales wait for URA, and offers the everyday actions.
# Green: running. Amber: running with sales queued for URA. Red: not answering.
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

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

function New-DotIcon([Drawing.Color]$c) {
  $bmp = New-Object Drawing.Bitmap 16, 16
  $g = [Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $g.FillEllipse((New-Object Drawing.SolidBrush $c), 1, 1, 14, 14)
  $g.DrawEllipse((New-Object Drawing.Pen ([Drawing.Color]::White), 1.5), 1, 1, 14, 14)
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
[void](Add-Item 'Restart EFRISConnect' { Run-Elevated 'restart' })
[void](Add-Item 'Open logs folder' { Start-Process explorer.exe (Join-Path $DataDir 'logs') })
if ($Mode -eq 'server') { [void](Add-Item 'Open till kit folder' { Start-Process explorer.exe (Join-Path $DataDir 'till-kit') }) }
[void](Add-Item 'Reset owner password ...' {
  $a = [Windows.Forms.MessageBox]::Show('Create a one-time code to reset the owner password? Use it on this computer under "Forgot password".', 'EFRISConnect', 'OKCancel', 'Question')
  if ($a -eq 'OK') { Run-Elevated 'reset-owner' }
})
[void]$menu.Items.Add('-')
[void](Add-Item 'Hide this icon' { $tray.Visible = $false; [Windows.Forms.Application]::Exit() })
$tray.ContextMenuStrip = $menu
$tray.add_DoubleClick({ Start-Process $ExtUrl })

# Status: the relay's public health check, plus the offline queue file.
$script:last = ''
function Update-Status {
  $up = $false
  try { $r = Invoke-WebRequest -Uri 'https://localhost:5443/api/health' -UseBasicParsing -TimeoutSec 3; $up = ($r.StatusCode -eq 200) } catch {}
  $q = 0
  # Windows PowerShell passes a JSON array on as one object, so .Count is its length.
  try { $q = [int]((Get-Content (Join-Path $DataDir 'offline_queue.json') -Raw) | ConvertFrom-Json).Count } catch {}
  if (!$up)      { $state = 'down';  $text = 'EFRISConnect - not running' }
  elseif ($q -gt 0) { $state = 'queue'; $text = "EFRISConnect - running - $q waiting for URA" }
  else           { $state = 'ok';    $text = 'EFRISConnect - running' }
  $tray.Icon = $Icons[$state]
  $tray.Text = $text.Substring(0, [Math]::Min(63, $text.Length))
  $status.Text = $text
  if ($script:last -and $script:last -ne $state) {
    if ($state -eq 'down') { $tray.ShowBalloonTip(6000, 'EFRISConnect', 'EFRISConnect stopped answering. Right-click the icon and choose Restart.', 'Warning') }
    elseif ($script:last -eq 'down') { $tray.ShowBalloonTip(4000, 'EFRISConnect', 'EFRISConnect is running again.', 'Info') }
    elseif ($state -eq 'ok' -and $script:last -eq 'queue') { $tray.ShowBalloonTip(4000, 'EFRISConnect', 'All queued sales have been sent to URA.', 'Info') }
  }
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
