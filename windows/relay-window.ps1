# EFRISConnect Relay window: what the relay is doing, in place of a console.
# Opened from the tray icon or the Start menu (relay-window.vbs, no console).
# Reads only what the signed-in user can read: the relay's public health check,
# the data folder (offline queue, submission log, activity log) and the scheduled
# task. Start, Restart and Stop go through install-helper.ps1 as Administrator,
# like the tray menu. Colours and shapes follow DESIGN-SYSTEM.md.
# -Snapshot <file.png>: draw the window once to a picture and close (for checking the design).
param([string]$Snapshot)
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# One window per signed-in user.
$created = $false
$mutex = New-Object Threading.Mutex($true, 'Local\EFRISConnectRelayWindow', [ref]$created)
if (!$created) { exit }

$AppDir  = Split-Path -Parent $PSScriptRoot
$DataDir = Join-Path $env:ProgramData 'EFRISConnect\data'
$LogDir  = Join-Path $DataDir 'logs'
$Helper  = Join-Path $PSScriptRoot 'install-helper.ps1'
$TaskName = 'EFRISConnect Relay'
function Read-Setting([string]$n, [string]$def) {
  $f = Join-Path $DataDir $n
  if (Test-Path $f) { $v = (Get-Content $f -TotalCount 1).Trim(); if ($v) { return $v } }
  return $def
}
$Mode = Read-Setting 'install-mode.txt' 'single'
$ModeText = @{ single = 'This computer only'; server = 'Shop server (tills connect to it)'; till = 'Till (uses the shop server)' }[$Mode]
if (!$ModeText) { $ModeText = $Mode }
$Version = ''
try { $Version = (Get-Content (Join-Path $AppDir 'package.json') -Raw | ConvertFrom-Json).version } catch {}
$Address = if ($Mode -eq 'server') { "https://$($env:COMPUTERNAME.ToLower()):5443" } else { 'https://localhost:5443' }

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EFRISConnect Relay" Width="820" Height="680" MinWidth="640" MinHeight="520"
        WindowStartupLocation="CenterScreen" Background="#F1F8E9" FontFamily="Segoe UI" FontSize="13" Foreground="#1A2E1A">
  <Window.Resources>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="White"/><Setter Property="BorderBrush" Value="#E3EAD9"/>
      <Setter Property="BorderThickness" Value="1"/><Setter Property="CornerRadius" Value="14"/><Setter Property="Padding" Value="15,12"/>
      <Setter Property="Effect"><Setter.Value><DropShadowEffect Color="#142E14" Opacity="0.12" BlurRadius="16" ShadowDepth="3" Direction="270"/></Setter.Value></Setter>
    </Style>
    <Style x:Key="CardTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="12"/><Setter Property="FontWeight" Value="Bold"/><Setter Property="Foreground" Value="#1B5E20"/>
    </Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="FontSize" Value="10.5"/><Setter Property="FontWeight" Value="Bold"/><Setter Property="Foreground" Value="#4A6741"/>
      <Setter Property="Margin" Value="0,3,12,3"/><Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Value" TargetType="TextBlock">
      <Setter Property="Margin" Value="0,3,0,3"/><Setter Property="TextWrapping" Value="Wrap"/><Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Padding" Value="14,7"/><Setter Property="Margin" Value="0,0,8,0"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="12"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Background" Value="White"/>
      <Setter Property="Foreground" Value="#4A6741"/><Setter Property="BorderBrush" Value="#E3EAD9"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="Button">
          <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="9" Padding="{TemplateBinding Padding}">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.88"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.5"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value></Setter>
    </Style>
    <Style x:Key="Chip" TargetType="RadioButton">
      <Setter Property="Margin" Value="5,0,0,0"/><Setter Property="Cursor" Value="Hand"/><Setter Property="FontSize" Value="11"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="RadioButton">
          <Border x:Name="b" Background="#F9F9F9" BorderBrush="#C8E6C9" BorderThickness="1" CornerRadius="5" Padding="9,2">
            <ContentPresenter x:Name="c" TextElement.Foreground="#1A2E1A"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="b" Property="Background" Value="#2E7D32"/><Setter TargetName="b" Property="BorderBrush" Value="#1B5E20"/>
              <Setter TargetName="c" Property="TextElement.Foreground" Value="White"/>
            </Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <DockPanel>
    <!-- Header: the app's dark green gradient with the gold line under it. -->
    <Border DockPanel.Dock="Top" BorderBrush="#F9A825" BorderThickness="0,0,0,3" Padding="16,12">
      <Border.Background><LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
        <GradientStop Color="#14431F" Offset="0"/><GradientStop Color="#1B5E20" Offset="0.42"/><GradientStop Color="#2E7D32" Offset="1"/>
      </LinearGradientBrush></Border.Background>
      <DockPanel>
        <Border x:Name="Pill" DockPanel.Dock="Right" CornerRadius="13" Padding="12,4,13,5" MinHeight="26" BorderThickness="1" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="Dot" Width="8" Height="8" Margin="0,0,6,0"/>
            <TextBlock x:Name="PillText" FontWeight="Bold" FontSize="12"/>
          </StackPanel>
        </Border>
        <StackPanel>
          <TextBlock Text="EFRISConnect Relay" Foreground="White" FontSize="15" FontWeight="Bold"/>
          <TextBlock Text="The background part that talks to URA and Manager" Foreground="White" Opacity="0.85" FontSize="11"/>
        </StackPanel>
      </DockPanel>
    </Border>
    <!-- Actions -->
    <DockPanel DockPanel.Dock="Bottom" Margin="16,0,16,14" LastChildFill="False">
      <Button x:Name="BtnStart" Content="Start" Style="{StaticResource Btn}" Background="#2E7D32" Foreground="White" BorderBrush="#2E7D32"/>
      <Button x:Name="BtnRestart" Content="Restart" Style="{StaticResource Btn}" Background="#2E7D32" Foreground="White" BorderBrush="#2E7D32"/>
      <Button x:Name="BtnStop" Content="Stop" Style="{StaticResource Btn}" Foreground="#C62828" BorderBrush="#C62828" BorderThickness="1.5"/>
      <Button x:Name="BtnOpen" DockPanel.Dock="Right" Content="Open EFRISConnect" Style="{StaticResource Btn}" Margin="0" Foreground="#2E7D32" BorderBrush="#2E7D32" BorderThickness="1.5"/>
      <Button x:Name="BtnData" DockPanel.Dock="Right" Content="Open data folder" Style="{StaticResource Btn}"/>
      <Button x:Name="BtnLogs" DockPanel.Dock="Right" Content="Open logs folder" Style="{StaticResource Btn}"/>
    </DockPanel>
    <Grid Margin="16,14,16,12">
      <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="10"/><ColumnDefinition/></Grid.ColumnDefinitions>
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="10"/><RowDefinition/></Grid.RowDefinitions>
      <Border Style="{StaticResource Card}">
        <StackPanel>
          <TextBlock Text="Status" Style="{StaticResource CardTitle}"/>
          <Border Height="1" Background="#E3EAD9" Margin="0,8,0,8"/>
          <Grid x:Name="StatusGrid"><Grid.ColumnDefinitions><ColumnDefinition Width="128"/><ColumnDefinition/></Grid.ColumnDefinitions></Grid>
        </StackPanel>
      </Border>
      <Border Grid.Column="2" Style="{StaticResource Card}">
        <StackPanel>
          <DockPanel>
            <TextBlock DockPanel.Dock="Right" x:Name="ChangeSetup" Text="Change in Setup" Foreground="#1565C0" FontSize="11.5" FontWeight="SemiBold" Cursor="Hand"
                       ToolTip="Ports and how this computer is used are chosen in Setup. Run the EFRISConnect Setup file again; your data is kept."/>
            <TextBlock Text="Setup" Style="{StaticResource CardTitle}"/>
          </DockPanel>
          <Border Height="1" Background="#E3EAD9" Margin="0,8,0,8"/>
          <Grid x:Name="SetupGrid"><Grid.ColumnDefinitions><ColumnDefinition Width="118"/><ColumnDefinition/></Grid.ColumnDefinitions></Grid>
        </StackPanel>
      </Border>
      <Border Grid.Row="2" Grid.ColumnSpan="3" Style="{StaticResource Card}">
        <DockPanel>
          <DockPanel DockPanel.Dock="Top">
            <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
              <RadioButton x:Name="FAll" Content="All" GroupName="f" IsChecked="True" Style="{StaticResource Chip}"/>
              <RadioButton x:Name="FUra" Content="URA" GroupName="f" Style="{StaticResource Chip}"/>
              <RadioButton x:Name="FMgr" Content="Manager" GroupName="f" Style="{StaticResource Chip}"/>
              <RadioButton x:Name="FProb" Content="Problems" GroupName="f" Style="{StaticResource Chip}"/>
            </StackPanel>
            <TextBlock Text="Activity" Style="{StaticResource CardTitle}" VerticalAlignment="Center"/>
          </DockPanel>
          <Border DockPanel.Dock="Top" Height="1" Background="#E3EAD9" Margin="0,8,0,8"/>
          <Border Background="#F7FAF5" BorderBrush="#E3EAD9" BorderThickness="1" CornerRadius="9">
            <ScrollViewer x:Name="LogScroll" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="0,5">
              <StackPanel x:Name="LogList"/>
            </ScrollViewer>
          </Border>
        </DockPanel>
      </Border>
    </Grid>
  </DockPanel>
</Window>
'@
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
foreach ($n in 'Pill','Dot','PillText','StatusGrid','SetupGrid','LogList','LogScroll','BtnStart','BtnRestart','BtnStop','BtnOpen','BtnData','BtnLogs','ChangeSetup','FAll','FUra','FMgr','FProb') { $ui[$n] = $win.FindName($n) }
try { $win.Icon = [Windows.Media.Imaging.BitmapFrame]::Create((New-Object Uri (Join-Path $AppDir 'efrisconnect.ico'))) } catch {}

function Brush([string]$hex) { [Windows.Media.BrushConverter]::new().ConvertFromString($hex) }
# A label / value table (labels in the small capitals of the design system).
function Set-Rows($grid, $rows) {
  $grid.Children.Clear(); $grid.RowDefinitions.Clear(); $i = 0
  foreach ($r in $rows) {
    $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition))
    $l = New-Object Windows.Controls.TextBlock; $l.Text = $r[0].ToUpper(); $l.Style = $win.Resources['Label']
    $v = New-Object Windows.Controls.TextBlock; $v.Text = $r[1]; $v.Style = $win.Resources['Value']
    if ($r.Count -gt 2 -and $r[2]) { $v.Foreground = Brush $r[2]; $v.FontWeight = 'SemiBold' }
    [Windows.Controls.Grid]::SetRow($l, $i); [Windows.Controls.Grid]::SetRow($v, $i); [Windows.Controls.Grid]::SetColumn($v, 1)
    [void]$grid.Children.Add($l); [void]$grid.Children.Add($v); $i++
  }
}
function When($t) {
  if (!$t) { return '' }
  try { $d = ([DateTime]::Parse($t)).ToLocalTime() } catch { return '' }
  $s = if ($d.Date -eq (Get-Date).Date) { 'Today ' + $d.ToString('HH:mm') } elseif ($d.Date -eq (Get-Date).Date.AddDays(-1)) { 'Yesterday ' + $d.ToString('HH:mm') } else { $d.ToString('d MMM HH:mm') }
  return $s
}
function Ago($t) {
  try { $span = (Get-Date) - ([DateTime]::Parse($t)).ToLocalTime() } catch { return '' }
  if ($span.TotalMinutes -lt 1) { return 'just now' }
  if ($span.TotalHours -lt 1) { return "$([int]$span.TotalMinutes) min ago" }
  if ($span.TotalDays -lt 1) { return "$([int][Math]::Floor($span.TotalHours)) h $($span.Minutes) min" }
  return "$([int][Math]::Floor($span.TotalDays)) days"
}
function Read-Json($name) { try { return @((Get-Content (Join-Path $DataDir $name) -Raw | ConvertFrom-Json) | ForEach-Object { $_ }) } catch { return @() } }

# -- Status and setup --
$script:state = ''
function Update-Status {
  $health = $null
  try { $health = Invoke-RestMethod -Uri 'https://localhost:5443/api/health' -TimeoutSec 4 } catch {}
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  $info = if ($task) { Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue } else { $null }
  $taskRunning = $task -and $task.State -eq 'Running'
  $state = if ($health) { 'running' } elseif ($taskRunning) { 'starting' } else { 'stopped' }
  $script:state = $state
  $look = @{ running = @('Running', '#E8F5E9', '#A5D6A7', '#1B5E20', '#43A047'); starting = @('Starting', '#FFF8E1', '#FFE082', '#8D5A00', '#F9A825'); stopped = @('Stopped', '#FFEBEE', '#EF9A9A', '#B71C1C', '#C62828') }[$state]
  $ui.PillText.Text = $look[0]; $ui.Pill.Background = Brush $look[1]; $ui.Pill.BorderBrush = Brush $look[2]
  $ui.PillText.Foreground = Brush $look[3]; $ui.Dot.Fill = Brush $look[4]
  $ui.BtnStart.Visibility = if ($state -eq 'stopped') { 'Visible' } else { 'Collapsed' }
  $ui.BtnRestart.Visibility = if ($state -ne 'stopped') { 'Visible' } else { 'Collapsed' }
  $ui.BtnStop.IsEnabled = ($state -ne 'stopped')

  $since = if ($health -and $health.startedAt) { (When $health.startedAt) + ' (' + (Ago $health.startedAt) + ')' } elseif ($state -eq 'starting') { 'Starting ...' } else { 'Not running' }
  $last = if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { When $info.LastRunTime.ToString('o') } elseif ($health -and $health.startedAt) { When $health.startedAt } else { '' }
  $sent = @(Read-Json 'submission_log.json' | Where-Object { $_.status -eq 'success' -and $_.submittedAt -and $_.importedFromUra -ne 'True' })
  $lastSent = ''; if ($sent.Count) { $t = ($sent | Sort-Object { $_.submittedAt } | Select-Object -Last 1).submittedAt; $lastSent = (When $t) + ' (' + (Ago $t) + ' ago)' -replace ' \(just now ago\)', ' (just now)' }
  $today = @($sent | Where-Object { try { ([DateTime]::Parse($_.submittedAt)).ToLocalTime().Date -eq (Get-Date).Date } catch { $false } }).Count
  $pend = @(Read-Json 'offline_queue.json' | Where-Object { $_.status -eq 'pending' })
  $rows = @(
    @('Running since', $since, $(if ($state -eq 'stopped') { '#B71C1C' } else { '' })),
    @('Last started', $(if ($last) { $last } else { '-' })),
    @('Last sent to URA', $(if ($lastSent) { $lastSent } else { 'Nothing yet' })),
    @('Sent today', "$today"),
    @('Waiting offline', $(if ($pend.Count) { "$($pend.Count) sale(s)" } else { 'None' }), $(if ($pend.Count) { '#8D5A00' } else { '#1B5E20' })),
    @('Version', $(if ($Version) { $Version } else { '-' }))
  )
  Set-Rows $ui.StatusGrid $rows

  $svc = Get-Service -Name 'TcsTomcat' -ErrorAction SilentlyContinue
  $setup = @(
    @('This computer', $ModeText),
    @('Address', $Address),
    @('Data folder', $DataDir),
    @('Logs folder', $LogDir),
    # Windows shows a task that runs as SYSTEM only to administrators, so "not visible"
    # is normal here; a relay that answers is proof enough that the task works.
    @('Runs as', $(if ($task -or $health) { 'Windows task, starts with the computer' } else { 'Windows task (status needs administrator rights)' }), $(if ($task -or $health) { '' } else { '#8D5A00' }))
  )
  if ($svc) { $setup += , @('Offline Enabler', $(if ($svc.Status -eq 'Running') { 'Running' } else { 'Stopped' })) }
  Set-Rows $ui.SetupGrid $setup
}

# -- Activity: the relay's activity log (plain lines), newest at the bottom --
$script:logSig = ''
# The log is written for support; this turns its technical lines into plain words.
# Returns '' for lines that are only noise here (automatic retries).
function Plain-Text([string]$t) {
  $t = $t -replace '[\p{So}\p{Cs}\uFE0F]', '' -replace '^\s*\[(ERROR|INFO|WARN)\]\s*', ''
  $t = $t.Trim() -replace '^[-*\s\u2022]+', ''
  if ($t -match 'transient error .* retry \d/\d' -or $t -match '^=+$') { return '' }
  if ($t -match '^(Manager\.io|EFRIS) network call failed\s*(\{.*\})\s*$') {
    $who = $Matches[1]; $m = $null; try { $m = $Matches[2] | ConvertFrom-Json } catch {}
    $msg = if ($m) { [string]$m.message } else { '' }
    $hostPart = ''; if ($m -and $m.url) { try { $u = [Uri]$m.url; $hostPart = $u.Host + ':' + $u.Port } catch {} }
    if ($who -eq 'EFRIS') {
      if ($msg -match 'ENOTFOUND|EAI_AGAIN') { return 'URA could not be reached (no internet connection?).' }
      if ($msg -match 'ETIMEDOUT|timed out') { return 'URA took too long to answer.' }
      return 'URA could not be reached: ' + $msg
    }
    if ($msg -match 'ECONNREFUSED') { return "Manager did not answer at $hostPart. Is Manager (or Manager Server) open?" }
    if ($msg -match 'ETIMEDOUT|timed out') { return "Manager at $hostPart took too long to answer." }
    return "Manager could not be reached at ${hostPart}: $msg"
  }
  if ($t -match 'vault placeholders but tenant') { return 'A saved password or access token for a business is missing on this computer. Enter it again in EFRISConnect Settings.' }
  if ($t -match '^Manager detected at (\S+)') { return 'Found Manager at ' + ($Matches[1] -replace '/api2$', '') + '.' }
  if ($t -match '^(\S.*?)\s*\{".*\}\s*$') { return $Matches[1] }   # drop a trailing technical detail block
  return $t
}
function Tag-Of($text, $level) {
  if ($level -eq 'error') { return @('Problem', '#FFEBEE', '#B71C1C', 'p') }
  if ($level -eq 'warn' -or $text -match '(?i)\b(failed|refused|rejected|could not|not reachable|unreachable|offline)\b') { return @('Check', '#FFF8E1', '#8D5A00', 'p') }
  if ($text -match '(?i)\b(URA|EFRIS|FDN)\b|fiscalis') { return @('URA', '#E8F5E9', '#1B5E20', 'u') }
  if ($text -match '(?i)\bManager\b') { return @('Manager', '#E8F5E9', '#1B5E20', 'm') }
  if ($text -match '(?i)sign(ed)?[- ]in|signed out|password') { return @('Sign-in', '#E3F2FD', '#0D47A1', 'o') }
  if ($text -match '(?i)\b(started|stopped|listening|restart)') { return @('Relay', '#E3F2FD', '#0D47A1', 'o') }
  return @('Info', '#E3F2FD', '#0D47A1', 'o')
}
function Update-Log([switch]$Force) {
  $f = Get-ChildItem $LogDir -Filter '*-activity.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
  $filter = if ($ui.FUra.IsChecked) { 'u' } elseif ($ui.FMgr.IsChecked) { 'm' } elseif ($ui.FProb.IsChecked) { 'p' } else { '' }
  $sig = if ($f) { "$($f.FullName)|$($f.Length)|$filter" } else { "none|$filter" }
  if (!$Force -and $sig -eq $script:logSig) { return }
  $script:logSig = $sig
  $atEnd = $ui.LogScroll.VerticalOffset -ge ($ui.LogScroll.ScrollableHeight - 4)
  $ui.LogList.Children.Clear()
  $lines = if ($f) { Get-Content $f.FullName -Tail 600 -Encoding UTF8 } else { @() }
  $shown = 0
  foreach ($ln in $lines) {
    try { $e = $ln | ConvertFrom-Json } catch { continue }
    if ($e.debug -eq $true) { continue }
    $text = Plain-Text ([string]$e.text)
    if (!$text) { continue }
    $tag = Tag-Of $text $e.level
    if ($filter -and $tag[3] -ne $filter) { continue }
    $row = New-Object Windows.Controls.DockPanel; $row.Margin = '10,2,10,2'
    $tm = New-Object Windows.Controls.TextBlock; $tm.FontFamily = 'Consolas'; $tm.FontSize = 11.5; $tm.Foreground = Brush '#6B7280'; $tm.Width = 62
    try { $tm.Text = ([DateTime]::Parse($e.time)).ToLocalTime().ToString('HH:mm:ss') } catch {}
    $chip = New-Object Windows.Controls.Border; $chip.CornerRadius = 5; $chip.Width = 62; $chip.Margin = '0,0,10,0'; $chip.Background = Brush $tag[1]; $chip.VerticalAlignment = 'Top'
    $ct = New-Object Windows.Controls.TextBlock; $ct.Text = $tag[0]; $ct.FontSize = 10; $ct.FontWeight = 'Bold'; $ct.Foreground = Brush $tag[2]; $ct.HorizontalAlignment = 'Center'; $ct.Padding = '0,1'
    $chip.Child = $ct
    $tx = New-Object Windows.Controls.TextBlock; $tx.Text = $text; $tx.TextWrapping = 'Wrap'; $tx.FontFamily = 'Consolas'; $tx.FontSize = 11.5
    if ($e.user) { $tx.ToolTip = "By $($e.user)" }
    [Windows.Controls.DockPanel]::SetDock($tm, 'Left'); [Windows.Controls.DockPanel]::SetDock($chip, 'Left')
    [void]$row.Children.Add($tm); [void]$row.Children.Add($chip); [void]$row.Children.Add($tx)
    [void]$ui.LogList.Children.Add($row); $shown++
  }
  if (!$shown) {
    $none = New-Object Windows.Controls.TextBlock; $none.Margin = '10,4'; $none.Foreground = Brush '#6B7280'
    $none.Text = if ($f) { 'Nothing to show for this filter yet.' } else { 'No activity recorded yet.' }
    [void]$ui.LogList.Children.Add($none)
  }
  if ($atEnd -or $Force) { $ui.LogScroll.ScrollToEnd() }
}

# -- Actions --
function Run-Elevated([string]$action) {
  try { Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Helper`" -Action $action" }
  catch { return }   # the Administrator prompt was declined
  $ui.PillText.Text = 'Working ...'
}
$ui.BtnStart.add_Click({ Run-Elevated 'start' })
$ui.BtnRestart.add_Click({ Run-Elevated 'restart' })
$ui.BtnStop.add_Click({
  $a = [Windows.MessageBox]::Show($win, 'While it is stopped, sales cannot be fiscalised. You can start it again from this window or the tray icon.', 'Stop the relay?', 'OKCancel', 'Warning')
  if ($a -eq 'OK') { Run-Elevated 'relay-stop' }
})
$ui.BtnOpen.add_Click({ Start-Process 'https://localhost:5443/extension' })
$ui.BtnData.add_Click({ Start-Process explorer.exe $DataDir })
$ui.BtnLogs.add_Click({ Start-Process explorer.exe $LogDir })
$ui.ChangeSetup.add_MouseLeftButtonUp({
  [void][Windows.MessageBox]::Show($win, "Ports and how this computer is used are chosen in Setup.`n`nTo change them, run the EFRISConnect Setup file again. Your data, users and settings are kept.", 'Change in Setup', 'OK', 'Information')
})
foreach ($c in 'FAll', 'FUra', 'FMgr', 'FProb') { $ui[$c].add_Checked({ Update-Log -Force }) }

$timer = New-Object Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(5)
$tick = 0
$timer.add_Tick({ Update-Log; $script:tick++; if ($script:tick % 2 -eq 0) { Update-Status } })
$win.add_ContentRendered({
  Update-Status; Update-Log -Force
  if ($Snapshot) {
    $win.UpdateLayout()
    $rtb = New-Object Windows.Media.Imaging.RenderTargetBitmap ([int]$win.ActualWidth), ([int]$win.ActualHeight), 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($win.Content)
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder; $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [IO.File]::Create($Snapshot); $enc.Save($fs); $fs.Close(); $win.Close(); return
  }
  $timer.Start()
})
[void]$win.ShowDialog()
$timer.Stop()
$mutex.ReleaseMutex()
