# EFRISConnect Control Centre: the relay, Manager, the Offline Enabler and start-up in
# one window, with on/off switches, plus what the relay is doing, in place of a console.
# Opened from the tray icon or the Start menu (relay-window.vbs, no console).
# Reads only what the signed-in user can read: the relay's public health check,
# the data folder (offline queue, submission log, activity log) and the scheduled
# task. Start, Restart and Stop go through install-helper.ps1 as Administrator,
# like the tray menu. Colours and shapes follow DESIGN-SYSTEM.md.
# -Snapshot <file.png>: draw the window once to a picture and close (for checking the design).
param([string]$Snapshot)
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
# Draw at the display's real resolution (otherwise Windows scales the window as a bitmap
# and the text looks blurred, like a screenshot).
try { Add-Type -Namespace EFC -Name Dpi -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();'; [void][EFC.Dpi]::SetProcessDPIAware() } catch {}

# Its own taskbar identity, so the taskbar button shows the EFRISConnect icon instead
# of PowerShell's (the tray icon does the same).
try {
  Add-Type -Namespace EFC -Name Shell -MemberDefinition '[DllImport("shell32.dll")] public static extern int SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string id);'
  [void][EFC.Shell]::SetCurrentProcessExplicitAppUserModelID('TukeiHope.EFRISConnect.ControlCentre')
} catch {}

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
        Title="EFRISConnect Control Centre" Width="860" Height="600" MinWidth="680" MinHeight="460" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display" TextOptions.TextRenderingMode="ClearType"
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
    <!-- Text people can select and copy, looking like plain text. -->
    <Style x:Key="Sel" TargetType="TextBox">
      <Setter Property="IsReadOnly" Value="True"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Background" Value="Transparent"/>
      <Setter Property="Padding" Value="0"/><Setter Property="TextWrapping" Value="Wrap"/><Setter Property="IsTabStop" Value="False"/>
      <Setter Property="Foreground" Value="#1A2E1A"/><Setter Property="SelectionBrush" Value="#A5D6A7"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="TextBox"><ScrollViewer x:Name="PART_ContentHost" Padding="0" Margin="0" Focusable="False" VerticalScrollBarVisibility="Disabled" HorizontalScrollBarVisibility="Disabled"/></ControlTemplate>
      </Setter.Value></Setter>
    </Style>
    <!-- On/off switch (the design system's toggle): green track when on. -->
    <Style x:Key="Switch" TargetType="CheckBox">
      <Setter Property="Cursor" Value="Hand"/><Setter Property="FontSize" Value="12.5"/><Setter Property="Foreground" Value="#1A2E1A"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="CheckBox">
          <StackPanel Orientation="Horizontal" Background="Transparent">
            <Border x:Name="track" Width="34" Height="18" CornerRadius="9" Background="#CFD8CC" VerticalAlignment="Center">
              <Ellipse x:Name="thumb" Width="14" Height="14" Fill="White" HorizontalAlignment="Left" Margin="2,0,0,0">
                <Ellipse.Effect><DropShadowEffect Color="#142E14" Opacity="0.25" BlurRadius="3" ShadowDepth="1" Direction="270"/></Ellipse.Effect>
              </Ellipse>
            </Border>
            <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
          </StackPanel>
          <ControlTemplate.Triggers>
            <Trigger Property="IsChecked" Value="True">
              <Setter TargetName="track" Property="Background" Value="#2E7D32"/>
              <Setter TargetName="thumb" Property="HorizontalAlignment" Value="Right"/><Setter TargetName="thumb" Property="Margin" Value="0,0,2,0"/>
            </Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="track" Property="Opacity" Value="0.5"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
      </Setter.Value></Setter>
    </Style>
    <!-- The tab switch at the bottom of the window (Status, Controls, Activity). -->
    <Style x:Key="TabBtn" TargetType="RadioButton">
      <Setter Property="Cursor" Value="Hand"/><Setter Property="FontSize" Value="12.5"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template"><Setter.Value>
        <ControlTemplate TargetType="RadioButton">
          <Border x:Name="b" Background="Transparent" CornerRadius="8" Padding="14,5">
            <ContentPresenter x:Name="c" TextElement.Foreground="#4A6741"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#F1F8E9"/></Trigger>
            <Trigger Property="IsChecked" Value="True"><Setter TargetName="b" Property="Background" Value="#2E7D32"/><Setter TargetName="c" Property="TextElement.Foreground" Value="White"/></Trigger>
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
        <Border x:Name="Pill" DockPanel.Dock="Right" CornerRadius="13" Padding="12,4,13,5" MinHeight="26" BorderThickness="1" VerticalAlignment="Center" Background="#F5F5F5" BorderBrush="#E0E0E0">
          <StackPanel Orientation="Horizontal">
            <Ellipse x:Name="Dot" Width="8" Height="8" Margin="0,0,6,0" Fill="#9E9E9E"/>
            <TextBlock x:Name="PillText" FontWeight="Bold" FontSize="12" Text="Checking..." Foreground="#4A6741"/>
          </StackPanel>
        </Border>
        <StackPanel>
          <TextBlock Text="EFRISConnect Control Centre" Foreground="White" FontSize="15" FontWeight="Bold"/>
          <TextBlock Text="Start, stop and switch on or off everything EFRISConnect runs on this computer" Foreground="White" Opacity="0.85" FontSize="11"/>
        </StackPanel>
      </DockPanel>
    </Border>
    <Border x:Name="Note" DockPanel.Dock="Top" Visibility="Collapsed" Background="#E3F2FD" BorderBrush="#90CAF9" BorderThickness="0,0,0,1" Padding="16,8">
      <DockPanel>
        <ProgressBar x:Name="NoteBar" DockPanel.Dock="Right" Width="120" Height="6" IsIndeterminate="True" Foreground="#2E7D32" Background="#E3EAD9" BorderThickness="0" VerticalAlignment="Center"/>
        <TextBox x:Name="NoteText" Style="{StaticResource Sel}" FontSize="12.5" Foreground="#0D47A1" Margin="0,0,12,0" VerticalAlignment="Center"/>
      </DockPanel>
    </Border>
    <!-- Actions on the left, the tab switch in the middle, EFRISConnect on the right.
         The relay buttons stay hidden until the first status check has run. -->
    <Grid DockPanel.Dock="Bottom" Margin="16,0,16,14">
      <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/><ColumnDefinition/></Grid.ColumnDefinitions>
      <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
        <Button x:Name="BtnStart" Content="Start" Visibility="Collapsed" Style="{StaticResource Btn}" Background="#2E7D32" Foreground="White" BorderBrush="#2E7D32"/>
        <Button x:Name="BtnRestart" Content="Restart" Visibility="Collapsed" Style="{StaticResource Btn}" Background="#2E7D32" Foreground="White" BorderBrush="#2E7D32"/>
        <Button x:Name="BtnStop" Content="Stop" Visibility="Collapsed" Style="{StaticResource Btn}" Foreground="#C62828" BorderBrush="#C62828" BorderThickness="1.5"/>
      </StackPanel>
      <Border x:Name="TabBar" Grid.Column="1" Visibility="Hidden" Background="White" BorderBrush="#E3EAD9" BorderThickness="1" CornerRadius="11" Padding="3" VerticalAlignment="Center">
        <StackPanel Orientation="Horizontal">
          <RadioButton x:Name="TabStatus" Content="Status" GroupName="tabs" IsChecked="True" Style="{StaticResource TabBtn}"/>
          <RadioButton x:Name="TabControls" Content="Controls" GroupName="tabs" Style="{StaticResource TabBtn}"/>
          <RadioButton x:Name="TabActivity" Content="Activity" GroupName="tabs" Style="{StaticResource TabBtn}"/>
        </StackPanel>
      </Border>
      <Button x:Name="BtnOpen" Grid.Column="2" HorizontalAlignment="Right" VerticalAlignment="Center" Content="Open EFRISConnect" Style="{StaticResource Btn}" Margin="0" Foreground="#2E7D32" BorderBrush="#2E7D32" BorderThickness="1.5"/>
    </Grid>
    <!-- Signed out: only the sign-in card. Signed in: Status, Controls and Activity. -->
    <Grid>
    <Grid x:Name="LockPane" Margin="12,14,12,10" Visibility="Collapsed">
          <Border x:Name="Lock" Style="{StaticResource Card}" HorizontalAlignment="Center" VerticalAlignment="Center" Width="420" Margin="0,0,0,10">
            <StackPanel>
              <TextBlock Text="Sign in to the Control Centre" Style="{StaticResource CardTitle}"/>
              <Border Height="1" Background="#E3EAD9" Margin="0,8,0,8"/>
              <TextBox x:Name="LockWhy" Style="{StaticResource Sel}" FontSize="12" Foreground="#4A6741"/>
              <TextBlock Text="SIGN-IN NAME" Style="{StaticResource Label}" Margin="0,10,0,3"/>
              <TextBox x:Name="LockName" Padding="8,6" FontSize="13" BorderBrush="#C8E6C9"/>
              <TextBlock Text="PASSWORD" Style="{StaticResource Label}" Margin="0,8,0,3"/>
              <Grid>
                <PasswordBox x:Name="LockPw" Padding="8,6" FontSize="13" BorderBrush="#C8E6C9"/>
                <TextBox x:Name="LockPwText" Padding="8,6" FontSize="13" BorderBrush="#C8E6C9" Visibility="Collapsed"/>
              </Grid>
              <CheckBox x:Name="LockShow" Content="Show password" FontSize="12" Foreground="#4A6741" Margin="0,7,0,0"/>
              <DockPanel Margin="0,10,0,0">
                <Button x:Name="LockGo" Content="Sign in" Style="{StaticResource Btn}" Background="#2E7D32" Foreground="White" BorderBrush="#2E7D32"/>
                <TextBox x:Name="LockMsg" Style="{StaticResource Sel}" FontSize="12" Foreground="#B71C1C" VerticalAlignment="Center" Margin="8,0,0,0"/>
              </DockPanel>
            </StackPanel>
          </Border>
    </Grid>
    <TabControl x:Name="Tabs" Margin="12,14,12,10" Background="Transparent" BorderThickness="0" Padding="0" Visibility="Hidden">
      <TabControl.Template>
        <ControlTemplate TargetType="TabControl">
          <DockPanel>
            <TabPanel DockPanel.Dock="Top" IsItemsHost="True" Visibility="Hidden" Height="0"/>
            <ContentPresenter ContentSource="SelectedContent"/>
          </DockPanel>
        </ControlTemplate>
      </TabControl.Template>
      <TabItem Header="Status">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="4,0">
          <Grid MaxWidth="820" HorizontalAlignment="Center" VerticalAlignment="Top">
            <Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="10"/><ColumnDefinition/></Grid.ColumnDefinitions>
      <Border Style="{StaticResource Card}" VerticalAlignment="Top">
        <StackPanel>
          <TextBlock Text="Status" Style="{StaticResource CardTitle}"/>
          <Border Height="1" Background="#E3EAD9" Margin="0,8,0,8"/>
          <Grid x:Name="StatusGrid"><Grid.ColumnDefinitions><ColumnDefinition Width="128"/><ColumnDefinition/></Grid.ColumnDefinitions></Grid>
        </StackPanel>
      </Border>
      <Border Grid.Column="2" Style="{StaticResource Card}" VerticalAlignment="Top">
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
          </Grid>
        </ScrollViewer>
      </TabItem>
      <TabItem Header="Controls">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="4,0">
          <StackPanel MaxWidth="820" HorizontalAlignment="Center">
          <Border x:Name="CtlCard" Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
                  <TextBlock x:Name="WhoText" FontSize="11.5" Foreground="#4A6741" Margin="0,0,10,0"/>
                  <TextBlock x:Name="SignOut" Text="Sign out" Foreground="#1565C0" FontSize="11.5" FontWeight="SemiBold" Cursor="Hand"/>
                </StackPanel>
                <TextBlock Text="Controls" Style="{StaticResource CardTitle}"/>
              </DockPanel>
              <Border Height="1" Background="#E3EAD9" Margin="0,8,0,4"/>
              <StackPanel x:Name="Controls"/>
            </StackPanel>
          </Border>
          </StackPanel>
        </ScrollViewer>
      </TabItem>
      <TabItem Header="Activity">
        <Grid Margin="4,0" MaxWidth="820">
      <Border Style="{StaticResource Card}">
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
      </TabItem>
    </TabControl>
    </Grid>
  </DockPanel>
</Window>
'@
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
foreach ($n in 'LockPane','TabBar','Lock','LockWhy','LockName','LockPw','LockPwText','LockShow','LockGo','LockMsg','CtlCard','WhoText','SignOut','Note','NoteBar','NoteText','Tabs','TabStatus','TabControls','TabActivity','Controls','Pill','Dot','PillText','StatusGrid','SetupGrid','LogList','LogScroll','BtnStart','BtnRestart','BtnStop','BtnOpen','ChangeSetup','FAll','FUra','FMgr','FProb') { $ui[$n] = $win.FindName($n) }
try { $win.Icon = [Windows.Media.Imaging.BitmapFrame]::Create((New-Object Uri (Join-Path $AppDir 'efrisconnect.ico'))) } catch {}

function Brush([string]$hex) { [Windows.Media.BrushConverter]::new().ConvertFromString($hex) }
# Text that can be selected and copied.
function Sel-Text([string]$text, [double]$size) {
  $t = New-Object Windows.Controls.TextBox; $t.Style = $win.Resources['Sel']; $t.Text = $text
  if ($size) { $t.FontSize = $size }
  return $t
}
# A confirmation or message in the EFRISConnect style (in place of the Windows message
# box). Returns $true for the main button.
function Ask([string]$title, [string]$msg, [string]$ok, [string]$kind) {
  [xml]$dx = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        WindowStyle="None" AllowsTransparency="True" Background="Transparent" SizeToContent="WidthAndHeight" ResizeMode="NoResize"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False" FontFamily="Segoe UI" UseLayoutRounding="True" TextOptions.TextFormattingMode="Display">
  <Border Margin="16" Background="White" CornerRadius="14" BorderBrush="#E3EAD9" BorderThickness="1" Width="400">
    <Border.Effect><DropShadowEffect Color="#142E14" Opacity="0.22" BlurRadius="22" ShadowDepth="4" Direction="270"/></Border.Effect>
    <StackPanel Margin="20,18,20,16">
      <DockPanel>
        <Border x:Name="Ico" Width="26" Height="26" CornerRadius="13" Margin="0,0,10,0" VerticalAlignment="Top">
          <TextBlock x:Name="IcoT" FontWeight="Bold" FontSize="14" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Border>
        <TextBlock x:Name="T" FontSize="15" FontWeight="Bold" Foreground="#1A2E1A" VerticalAlignment="Center" TextWrapping="Wrap"/>
      </DockPanel>
      <TextBox x:Name="M" IsReadOnly="True" BorderThickness="0" Background="Transparent" TextWrapping="Wrap" FontSize="13" Foreground="#4A6741" Margin="36,8,0,16" IsTabStop="False"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="No" Content="Cancel" Padding="16,7" Margin="0,0,8,0" Cursor="Hand" FontWeight="SemiBold" Background="White" Foreground="#4A6741" BorderBrush="#E3EAD9" IsCancel="True"/>
        <Button x:Name="Yes" Padding="16,7" Cursor="Hand" FontWeight="SemiBold" Foreground="White" IsDefault="True"/>
      </StackPanel>
    </StackPanel>
  </Border>
</Window>
'@
  $d = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $dx))
  $d.Owner = $win
  $look = @{ danger = @('#FFEBEE', '#C62828', '!'); info = @('#E3F2FD', '#1565C0', 'i'); ask = @('#E8F5E9', '#2E7D32', '?') }[$kind]
  if (!$look) { $look = @('#E8F5E9', '#2E7D32', '?') }
  $d.FindName('Ico').Background = Brush $look[0]; $d.FindName('IcoT').Text = $look[2]; $d.FindName('IcoT').Foreground = Brush $look[1]
  $d.FindName('T').Text = $title; $d.FindName('M').Text = $msg
  $yes = $d.FindName('Yes'); $yes.Content = $(if ($ok) { $ok } else { 'OK' }); $yes.Background = Brush $look[1]; $yes.BorderBrush = Brush $look[1]
  foreach ($b in $yes, $d.FindName('No')) { $b.Style = $win.Resources['Btn'] }
  $yes.Margin = '0'
  if ($kind -eq 'info') { $d.FindName('No').Visibility = 'Collapsed' }
  $yes.add_Click({ $d.DialogResult = $true })
  $d.add_MouseLeftButtonDown({ try { $d.DragMove() } catch {} })
  return [bool]$d.ShowDialog()
}
# A label / value table (labels in the small capitals of the design system).
function Set-Rows($grid, $rows) {
  $grid.Children.Clear(); $grid.RowDefinitions.Clear(); $i = 0
  foreach ($r in $rows) {
    $grid.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition))
    $l = New-Object Windows.Controls.TextBlock; $l.Text = $r[0].ToUpper(); $l.Style = $win.Resources['Label']
    if ($r.Count -gt 3 -and $r[3]) {
      # A folder: the path is a link that opens it in File Explorer.
      $v = New-Object Windows.Controls.TextBlock; $v.Text = $r[1]; $v.Style = $win.Resources['Value']
      $v.Foreground = Brush '#1565C0'; $v.Cursor = 'Hand'; $v.ToolTip = 'Open in File Explorer'; $v.Tag = $r[3]
      $v.add_MouseLeftButtonUp({ param($sender, $e) Start-Process explorer.exe $sender.Tag })
    } else {
      $v = Sel-Text $r[1] 13; $v.Margin = '0,3,0,3'; $v.VerticalAlignment = 'Center'
      if ($r.Count -gt 2 -and $r[2]) { $v.Foreground = Brush $r[2]; $v.FontWeight = 'SemiBold' }
    }
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
  $ui.BtnStop.Visibility = if ($state -ne 'stopped') { 'Visible' } else { 'Collapsed' }

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
    @('Data folder', $DataDir, '', $DataDir),
    @('Logs folder', $LogDir, '', $LogDir),
    # Windows shows a task that runs as SYSTEM only to administrators, so "not visible"
    # is normal here; a relay that answers is proof enough that the task works.
    @('Runs as', $(if ($task -or $health) { 'Windows task, starts with the computer' } else { 'Windows task (status needs administrator rights)' }), $(if ($task -or $health) { '' } else { '#8D5A00' }))
  )
  if ($svc) { $setup += , @('Offline Enabler', $(if ($svc.Status -eq 'Running') { 'Running' } else { 'Stopped' })) }
  Set-Rows $ui.SetupGrid $setup
  Update-Controls $health $task
  Apply-Lock $health
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
    $tx = Sel-Text $text 11.5; $tx.FontFamily = 'Consolas'
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
$MgrPort = Read-Setting 'lan-manager-port.txt' '5000'
$MgrExe  = Read-Setting 'manager-server-path.txt' ''
$MgrData = Read-Setting 'manager-server-data.txt' ''
$TrayLnk = Join-Path ([Environment]::GetFolderPath('CommonStartup')) 'EFRISConnect tray icon.lnk'
# Manager Desktop: the Microsoft Store app (opened by its app ID) or a classic install.
function Find-ManagerDesktop {
  try { $sa = Get-StartApps | Where-Object { $_.Name -eq 'Manager' -and $_.AppID -like 'Manager_*!*' } | Select-Object -First 1; if ($sa) { return 'shell:AppsFolder\' + $sa.AppID } } catch {}
  foreach ($c in @("$env:LOCALAPPDATA\Programs\Manager\ManagerDesktop.exe", "$env:LOCALAPPDATA\Programs\Manager\Manager.exe", "$env:ProgramFiles\Manager\ManagerDesktop.exe", "$env:ProgramFiles\Manager.io\ManagerDesktop.exe")) { if (Test-Path $c) { return $c } }
  return ''
}
# One row: name, state in colour, a short note, buttons and an on/off switch.
function Ctl-Row($name, $state, $ok, $note, $buttons, $switchText, $switchOn, $onAction, $offAction) {
  $row = New-Object Windows.Controls.DockPanel; $row.Margin = '0,6,0,6'
  $left = New-Object Windows.Controls.StackPanel; $left.Width = 260
  $t = Sel-Text $name 13; $t.FontWeight = 'SemiBold'
  $st = Sel-Text $state 12; $st.FontWeight = 'SemiBold'
  $st.Foreground = Brush $(if ($ok -eq $true) { '#1B5E20' } elseif ($ok -eq $false) { '#B71C1C' } else { '#8D5A00' })
  [void]$left.Children.Add($t); [void]$left.Children.Add($st)
  if ($note) { $n = Sel-Text $note 11; $n.Foreground = Brush '#6B7280'; [void]$left.Children.Add($n) }
  [Windows.Controls.DockPanel]::SetDock($left, 'Left'); [void]$row.Children.Add($left)
  $right = New-Object Windows.Controls.WrapPanel; $right.VerticalAlignment = 'Center'
  foreach ($b in $buttons) {
    $btn = New-Object Windows.Controls.Button; $btn.Content = $b[0]; $btn.Style = $win.Resources['Btn']; $btn.Margin = '0,2,8,2'; $btn.Padding = '12,5'
    if ($b.Count -gt 2 -and $b[2] -eq 'danger') { $btn.Foreground = Brush '#C62828'; $btn.BorderBrush = Brush '#C62828' }
    $btn.Tag = $b[1]; $btn.add_Click({ param($sender, $e) & $sender.Tag })
    [void]$right.Children.Add($btn)
  }
  if ($switchText) {
    $cb = New-Object Windows.Controls.CheckBox; $cb.Style = $win.Resources['Switch']; $cb.Content = $switchText; $cb.IsChecked = $switchOn; $cb.Margin = '4,6,0,2'; $cb.VerticalAlignment = 'Center'
    $cb.Tag = @($onAction, $offAction)
    $cb.add_Click({ param($sender, $e) if ($sender.IsChecked) { Run-Elevated $sender.Tag[0] } else { Run-Elevated $sender.Tag[1] } })
    [void]$right.Children.Add($cb)
  }
  [void]$row.Children.Add($right)
  $sep = New-Object Windows.Controls.Border; $sep.Height = 1; $sep.Background = Brush '#E3EAD9'
  [void]$ui.Controls.Children.Add($row); [void]$ui.Controls.Children.Add($sep)
}
function Update-Controls($health, $task) {
  $ui.Controls.Children.Clear()
  # The relay task is visible only to administrators: "start with Windows" shows as on
  # when the task is enabled or, when it cannot be read, while the relay runs.
  $relayAuto = if ($task) { $task.State -ne 'Disabled' } else { [bool]$health }
  Ctl-Row 'EFRISConnect (the relay)' $(if ($health) { 'Running' } else { 'Stopped' }) ([bool]$health) 'Talks to URA and Manager. Sales cannot be fiscalised while it is stopped.' @(
      @('Start', { Run-Elevated 'start' }), @('Restart', { Run-Elevated 'restart' }),
      @('Stop', { if (Ask 'Stop EFRISConnect?' 'While it is stopped, sales cannot be fiscalised. You can start it again here or from the tray icon.' 'Stop' 'danger') { Run-Elevated 'relay-stop' } }, 'danger')
    ) 'Start with Windows' $relayAuto 'relay-autostart-on' 'relay-autostart-off'
  # Manager: Server Edition on a shop server, Desktop otherwise.
  if ($Mode -eq 'server' -and $MgrExe) {
    $mgrUp = [bool](Get-Process -Name 'ManagerServer' -ErrorAction SilentlyContinue)
    $mt = Get-ScheduledTask -TaskName 'EFRISConnect Manager Server' -ErrorAction SilentlyContinue
    $mgrAuto = if ($mt) { $mt.State -ne 'Disabled' } else { $true }
    Ctl-Row 'Manager Server Edition' $(if ($mgrUp) { "Running on port $MgrPort" } else { 'Stopped' }) $mgrUp ("Tills open it at https://$($env:COMPUTERNAME.ToLower()):$([int]$MgrPort + 1)") @(
        @('Start', { if (Port-Open ([int]$MgrPort)) { Show-Note "Manager Server is already running on port $MgrPort." 'ok'; return }; Run-Elevated 'manager-start' }),
        @('Open Manager', { Start-Process "http://localhost:$MgrPort" }),
        @('Stop', { if (Ask 'Stop Manager Server?' 'Tills and this computer cannot open Manager while it is stopped.' 'Stop' 'danger') { Run-Elevated 'manager-stop' } }, 'danger')
      ) 'Start with Windows (in the background)' $mgrAuto 'manager-autostart-on' 'manager-autostart-off'
  } else {
    $md = Find-ManagerDesktop
    $mgrUp = [bool](Get-Process -Name 'ManagerDesktop', 'Manager' -ErrorAction SilentlyContinue)
    $btns = @(); if ($md) { $btns += , @('Open Manager Desktop', { $t = Find-ManagerDesktop; if ($t -like 'shell:*') { Start-Process explorer.exe $t } else { Start-Process $t }; Show-Note 'Opening Manager Desktop. It is ready in a few seconds.' 'ok' }) }
    Ctl-Row 'Manager Desktop' $(if ($mgrUp) { 'Open' } else { 'Closed' }) $(if ($mgrUp) { $true } else { $null }) 'To use Manager Server Edition and serve tills, run Setup again and choose Shop server (your data is kept).' $btns '' $false '' ''
  }
  # URA Offline Enabler, when installed.
  $svc = Get-Service -Name 'TcsTomcat' -ErrorAction SilentlyContinue
  if ($svc) {
    $enUp = $svc.Status -eq 'Running'
    Ctl-Row 'URA Offline Enabler' $(if ($enUp) { 'Running' } else { 'Stopped' }) $enUp 'Issues receipts with no internet at all and uploads them to URA later.' @(
        @('Start', { Run-Elevated 'enabler-start' }), @('Restart', { Run-Elevated 'enabler-restart' }), @('Stop', { Run-Elevated 'enabler-stop' }, 'danger')
      ) 'Start with Windows' ($svc.StartType -ne 'Manual' -and $svc.StartType -ne 'Disabled') 'enabler-autostart-on' 'enabler-autostart-off'
  }
  Ctl-Row 'Icon next to the clock' 'Status and quick actions' $true '' @() 'Show it when I sign in' (Test-Path $TrayLnk) 'tray-autostart-on' 'tray-autostart-off'
  if ($Mode -eq 'server') {
    Ctl-Row 'Shop network' "Tills use $Address" $true 'Copy the till kit to a USB stick and run Setup on each till (choose Till).' @(
        @('Open till kit folder', { Start-Process explorer.exe (Join-Path $DataDir 'till-kit') }),
        @('Copy Manager button URL', { [Windows.Clipboard]::SetText("$Address/extension"); Show-Note "Copied $Address/extension. Paste it as the address of each EFRISConnect custom button in Manager." 'ok' }),
        @('Repair firewall rules', { Run-Elevated 'firewall-repair' })
      ) '' $false '' ''
  }
  Ctl-Row 'Maintenance' "Version $Version" $true '' @(
      @('EFRISConnect Settings', { Open-App 'https://localhost:5443/extension' }),
      @('Reset owner password', { if (Ask 'Reset owner password?' 'This makes a one-time code. Use it on this computer under "Forgot password" on the EFRISConnect sign-in page.' 'Make the code' 'ask') { Run-Elevated 'reset-owner' } })
    ) '' $false '' ''
}
# EFRISConnect in its own app window (app mode: no address bar or tabs): Chrome, else
# Edge, else the default browser.
function Open-App([string]$url) {
  $b = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
         "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($b) { Start-Process $b -ArgumentList "--app=$url" } else { Start-Process $url }
}
$script:job = $null
function Show-Note([string]$text, [string]$kind) {
  $look = @{ busy = @('#E3F2FD', '#90CAF9', '#0D47A1'); ok = @('#E8F5E9', '#A5D6A7', '#1B5E20'); fail = @('#FFEBEE', '#EF9A9A', '#B71C1C') }[$kind]
  $ui.Note.Background = Brush $look[0]; $ui.Note.BorderBrush = Brush $look[1]; $ui.NoteText.Foreground = Brush $look[2]
  $ui.NoteText.Text = $text; $ui.NoteBar.Visibility = if ($kind -eq 'busy') { 'Visible' } else { 'Collapsed' }
  $ui.Note.Visibility = 'Visible'
}
# Watch an action: $check returns $true when it is done; the message changes when it is,
# or when it takes longer than expected.
function Watch-Job($busy, $check, $done, $secs, $proc) {
  Show-Note $busy 'busy'
  $script:job = @{ check = $check; done = $done; until = (Get-Date).AddSeconds($secs); proc = $proc; started = Get-Date }
}
function Tick-Job {
  $j = $script:job; if (!$j) { return }
  $ok = $false; try { $ok = [bool](& $j.check) } catch {}
  if ($ok) { $script:job = $null; Show-Note $j.done 'ok'; Update-Status; $t = New-Object Windows.Threading.DispatcherTimer; $t.Interval = [TimeSpan]::FromSeconds(8); $t.add_Tick({ param($sender, $e) $sender.Stop(); if (!$script:job) { $ui.Note.Visibility = 'Collapsed' } }); $t.Start(); return }
  if ($j.proc -and $j.proc.HasExited -and $j.proc.ExitCode -ne 0 -and ((Get-Date) - $j.started).TotalSeconds -gt 3) { $script:job = $null; Show-Note 'That did not work. See the Activity tab or the logs folder for the reason.' 'fail'; return }
  if ((Get-Date) -gt $j.until) { $script:job = $null; Show-Note 'This is taking longer than usual. It may still finish; check again in a minute, or see the Activity tab.' 'fail' }
}
function Relay-Up { try { $null = Invoke-RestMethod -Uri 'https://localhost:5443/api/health' -TimeoutSec 3; $true } catch { $false } }
function Port-Open([int]$port) { $c = New-Object Net.Sockets.TcpClient; try { $c.ConnectAsync('127.0.0.1', $port).Wait(800) -and $c.Connected } catch { $false } finally { $c.Close() } }
# What each action does, how long it usually takes, and how to tell it is done.
$Expect = @{
  'start'          = @('Starting EFRISConnect. Approve the Windows prompt; it is ready in about 30 seconds.', { Relay-Up }, 'EFRISConnect is running.', 120)
  'restart'        = @('Restarting EFRISConnect. Approve the Windows prompt; it is back in about 30 seconds.', { Relay-Up }, 'EFRISConnect is running again.', 120)
  'relay-stop'     = @('Stopping EFRISConnect. Approve the Windows prompt.', { -not (Relay-Up) }, 'EFRISConnect is stopped. Sales are not fiscalised until you start it again.', 60)
  'enabler-start'  = @('Starting the URA Offline Enabler. Approve the Windows prompt; it usually takes 1 to 2 minutes.', { (Get-Service TcsTomcat).Status -eq 'Running' }, 'The Offline Enabler is running.', 180)
  'enabler-restart'= @('Restarting the URA Offline Enabler. It usually takes 1 to 2 minutes.', { (Get-Service TcsTomcat).Status -eq 'Running' }, 'The Offline Enabler is running again.', 180)
  'enabler-stop'   = @('Stopping the URA Offline Enabler.', { (Get-Service TcsTomcat).Status -eq 'Stopped' }, 'The Offline Enabler is stopped.', 90)
  'firewall-repair'= @('Setting the shop network firewall rules again.', $null, 'Firewall rules are set. Tills can reach this computer.', 60)
  'manager-start'  = @('Starting Manager Server in the background. Approve the Windows prompt; it is usually ready in 20 to 40 seconds.', { Port-Open ([int]$MgrPort) }, 'Manager Server is running. Tills and EFRISConnect can use it now.', 120)
  'manager-stop'   = @('Stopping Manager Server. Approve the Windows prompt.', { -not (Port-Open ([int]$MgrPort)) }, 'Manager Server is stopped. Tills cannot open Manager until you start it again.', 60)
  'reset-owner'    = @('Making a one-time owner reset code. It opens in Notepad.', $null, 'The reset code is in Notepad. Use it under "Forgot password" on this computer.', 60)
}
function Run-Elevated([string]$action) {
  $p = $null
  try { $p = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Helper`" -Action $action" }
  catch { Show-Note 'Nothing was changed: the Windows approval was declined.' 'fail'; return }
  $e = $Expect[$action]
  if ($e -and $e[1]) { Watch-Job $e[0] $e[1] $e[2] $e[3] $p; return }
  $msg = if ($e) { $e[0] } else { 'Saving the change. Approve the Windows prompt.' }
  $done = if ($e) { $e[2] } elseif ($action -like '*-autostart-*') { 'Saved. It applies from the next time Windows starts or you sign in.' } else { 'Done.' }
  Watch-Job $msg ({ $script:job.proc.HasExited -and $script:job.proc.ExitCode -eq 0 }.GetNewClosure()) $done 90 $p
}
$ui.BtnStart.add_Click({ Run-Elevated 'start' })
$ui.BtnRestart.add_Click({ Run-Elevated 'restart' })
$ui.BtnStop.add_Click({
  if (Ask 'Stop EFRISConnect?' 'While it is stopped, sales cannot be fiscalised. You can start it again here or from the tray icon.' 'Stop' 'danger') { Run-Elevated 'relay-stop' }
})
$ui.BtnOpen.add_Click({ Open-App 'https://localhost:5443/extension' })
$ui.TabStatus.add_Checked({ $ui.Tabs.SelectedIndex = 0 })
$ui.TabControls.add_Checked({ $ui.Tabs.SelectedIndex = 1 })
$ui.TabActivity.add_Checked({ $ui.Tabs.SelectedIndex = 2 })
$ui.ChangeSetup.add_MouseLeftButtonUp({
  [void](Ask 'Change in Setup' "Ports and how this computer is used are chosen in Setup. To change them, run the EFRISConnect Setup file again. Your data, users and settings are kept." 'OK' 'info')
})
foreach ($c in 'FAll', 'FUra', 'FMgr', 'FProb') { $ui[$c].add_Checked({ Update-Log -Force }) }

$script:unlockedUntil = [DateTime]::MinValue
$script:unlockedBy = ''
function Is-Unlocked { (Get-Date) -lt $script:unlockedUntil }
function Check-Admin([string]$name, [string]$pw) {
  try {
    $r = Invoke-RestMethod -Method Post -Uri 'https://localhost:5443/api/auth/login' -ContentType 'application/json' -TimeoutSec 8 -Body (@{ name = $name; password = $pw; remember = $false } | ConvertTo-Json)
  } catch { return @{ ok = $false; error = 'EFRISConnect did not answer. Start it first (it needs to run to check your password).' } }
  if (!$r.success -or !$r.token) { return @{ ok = $false; error = $(if ($r.lockedUntil) { 'Too many wrong passwords. Try again in a few minutes.' } elseif ($r.error) { [string]$r.error } else { 'Wrong name or password.' }) } }
  $h = @{ Authorization = 'Bearer ' + $r.token }
  $ok = [bool]$r.user.owner
  if (!$ok) { try { $st = Invoke-RestMethod -Uri 'https://localhost:5443/api/auth/status' -Headers $h -TimeoutSec 8; $ok = @($st.tenants | Where-Object { $_.role -eq 'admin' }).Count -gt 0 } catch {} }
  try { $null = Invoke-RestMethod -Method Post -Uri 'https://localhost:5443/api/auth/logout' -Headers $h -TimeoutSec 5 } catch {}
  if (!$ok) { return @{ ok = $false; error = 'Only an owner or admin of EFRISConnect can change settings here.' } }
  return @{ ok = $true; who = [string]$(if ($r.user.displayName) { $r.user.displayName } else { $r.user.name }) }
}
# An owner or admin already signed in to EFRISConnect on this computer, when nobody else
# is signed in anywhere, opens the controls without typing the password again. Not
# after "Sign out" here, until this window is closed.
$script:noAuto = $false
$script:wasOpen = $false
function Try-AutoUnlock {
  $r = $null
  try { $r = Invoke-RestMethod -Uri 'https://localhost:5443/api/auth/console-session' -TimeoutSec 4 } catch { return }
  if (!$r -or !$r.user) { return }
  $script:unlockedUntil = (Get-Date).AddMinutes(15); $script:unlockedBy = [string]$r.user.displayName
  Show-Note ("Signed in as " + $script:unlockedBy + " (already signed in to EFRISConnect on this computer). Controls stay unlocked for 15 minutes after your last click.") 'ok'
}
function Apply-Lock($health) {
  if (!(Is-Unlocked) -and $health -and !$script:noAuto) { Try-AutoUnlock }
  $open = Is-Unlocked
  if ($script:wasOpen -and !$open) { Show-Note 'Controls locked again after 15 minutes without a click. Sign in to change settings.' 'ok' }
  $script:wasOpen = $open
  # Signed out, the whole window is the sign-in card (Status and Activity too).
  $ui.LockPane.Visibility = if ($open) { 'Collapsed' } else { 'Visible' }
  $ui.Tabs.Visibility = if ($open) { 'Visible' } else { 'Hidden' }
  $ui.TabBar.Visibility = if ($open) { 'Visible' } else { 'Hidden' }
  $ui.WhoText.Text = if ($open) { 'Signed in as ' + $script:unlockedBy } else { '' }
  # Signed out, the relay's Restart and Stop are hidden. Start stays while the relay is
  # stopped, as it cannot check a password then (Windows still asks for an administrator).
  if (!$open) { $ui.BtnRestart.Visibility = 'Collapsed'; $ui.BtnStop.Visibility = 'Collapsed' }
  $ui.LockWhy.Text = if ($health) { 'Only an owner or admin of EFRISConnect can open the Control Centre. Use the same name and password as in EFRISConnect.' } else { 'EFRISConnect is not running, so a password cannot be checked. Use Start at the bottom (Windows asks for an administrator), then sign in here.' }
}
function Do-Unlock {
  $ui.LockMsg.Text = 'Checking...'
  $pw = if ($ui.LockShow.IsChecked) { $ui.LockPwText.Text } else { $ui.LockPw.Password }
  $res = Check-Admin $ui.LockName.Text $pw
  $ui.LockPw.Password = ''; $ui.LockPwText.Text = ''
  if (!$res.ok) { $ui.LockMsg.Text = $res.error; return }
  $script:unlockedUntil = (Get-Date).AddMinutes(15); $script:unlockedBy = $res.who
  $ui.LockMsg.Text = ''
  Show-Note ("Signed in as " + $res.who + ". Controls stay unlocked for 15 minutes after your last click.") 'ok'
  Update-Status
}
$ui.LockGo.add_Click({ Do-Unlock })
$ui.LockPw.add_KeyDown({ param($sender, $e) if ($e.Key -eq 'Return') { Do-Unlock } })
$ui.LockPwText.add_KeyDown({ param($sender, $e) if ($e.Key -eq 'Return') { Do-Unlock } })
$ui.LockShow.add_Checked({ $ui.LockPwText.Text = $ui.LockPw.Password; $ui.LockPw.Visibility = 'Collapsed'; $ui.LockPwText.Visibility = 'Visible' })
$ui.LockShow.add_Unchecked({ $ui.LockPw.Password = $ui.LockPwText.Text; $ui.LockPwText.Text = ''; $ui.LockPwText.Visibility = 'Collapsed'; $ui.LockPw.Visibility = 'Visible' })
$ui.SignOut.add_MouseLeftButtonUp({
  $script:unlockedUntil = [DateTime]::MinValue; $script:unlockedBy = ''; $script:noAuto = $true; $script:wasOpen = $false
  Show-Note 'Signed out of the Control Centre. Sign in again to change settings.' 'ok'
  Update-Status
})
# Every click while unlocked keeps it open another 15 minutes.
$win.add_PreviewMouseDown({ if (Is-Unlocked) { $script:unlockedUntil = (Get-Date).AddMinutes(15) } })
$jobTimer = New-Object Windows.Threading.DispatcherTimer
$jobTimer.Interval = [TimeSpan]::FromSeconds(1)
$jobTimer.add_Tick({ Tick-Job })
$jobTimer.Start()
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
