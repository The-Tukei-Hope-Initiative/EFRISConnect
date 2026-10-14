# EFRISConnect - shop network (LAN) helper for windows\EFRISConnect.bat.
#
#   -Action config  -Out <file.cmd>   Write "set" lines for this PC's names and private
#                                     IPv4 addresses (ALLOWED_HOSTS, LANHOST, LANIPS) and
#                                     whether a connected network is marked Public.
#   -Action firewall                  Allow inbound TCP 5443 (EFRISConnect HTTPS) on the
#                                     Private profile only. Admin. Idempotent.
#   -Action firewall -ManagerHttpsPort 5001
#                                     Also allow Manager over HTTPS (the relay's front for
#                                     Manager Server, manager-proxy.js). Admin.
#   -Action manager-firewall -ManagerPort 5000
#                                     Same for Manager Server Edition's port. Admin.
#   -Action manager-unfirewall        Remove only the plain-HTTP Manager Server rule (tills
#                                     now use the encrypted address). Admin.
#   -Action unfirewall                Remove all three rules. Admin.
param(
  [ValidateSet('config', 'firewall', 'manager-firewall', 'manager-unfirewall', 'unfirewall')][string]$Action = 'config',
  [string]$Out,
  [int]$Port = 5443,
  [int]$ManagerPort = 5000,
  [int]$ManagerHttpsPort = 0
)
$ErrorActionPreference = 'Stop'
$RelayRule = 'EFRISConnect HTTPS (LAN)'
$ManagerRule = 'EFRISConnect Manager Server (LAN)'
$ManagerHttpsRule = 'EFRISConnect Manager HTTPS (LAN)'
$PrivateIp = '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
# Virtual adapters (Hyper-V, WSL, Docker, VirtualBox, VMware) are not the shop network.
$Virtual = 'vEthernet|WSL|Hyper-V|VirtualBox|VMware|Docker|Loopback'

function Set-Rule([string]$Name, [int]$LocalPort) {
  $r = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
  if ($r) {
    $r | Set-NetFirewallRule -Direction Inbound -Action Allow -Profile Private -Enabled True
    $r | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol TCP -LocalPort $LocalPort
    Write-Host "  Firewall rule '$Name' already present (TCP $LocalPort, Private networks only)."
  } else {
    New-NetFirewallRule -DisplayName $Name -Direction Inbound -Protocol TCP -LocalPort $LocalPort -Action Allow -Profile Private | Out-Null
    Write-Host "  Added firewall rule '$Name' (TCP $LocalPort, Private networks only)."
  }
}

switch ($Action) {
  'config' {
    $hostName = $env:COMPUTERNAME.ToLower()
    $ips = @()
    try {
      $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -match $PrivateIp -and $_.AddressState -eq 'Preferred' -and $_.InterfaceAlias -notmatch $Virtual } |
        ForEach-Object { $_.IPAddress } | Select-Object -Unique)
    } catch {}
    $hosts = @($hostName, "$hostName.local") + $ips
    $public = ''
    try {
      $public = (@(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.NetworkCategory -eq 'Public' } |
        ForEach-Object { $_.Name -replace '[^A-Za-z0-9 ._-]', '' })) -join ', '
    } catch {}
    $lines = @(
      "set `"LANHOST=$hostName`"",
      "set `"LANIPS=$($ips -join ' ')`"",
      "set `"ALLOWED_HOSTS=$($hosts -join ',')`"",
      "set `"LANPUBLIC=$public`""
    )
    # cmd.exe reads the file in the console code page: keep it ASCII.
    $lines | Out-File -FilePath $Out -Encoding ascii
  }
  'firewall' {
    Set-Rule $RelayRule $Port
    if ($ManagerHttpsPort -gt 0) { Set-Rule $ManagerHttpsRule $ManagerHttpsPort }
  }
  'manager-firewall' { Set-Rule $ManagerRule $ManagerPort }
  'manager-unfirewall' {
    $r = Get-NetFirewallRule -DisplayName $ManagerRule -ErrorAction SilentlyContinue
    if ($r) { $r | Remove-NetFirewallRule; Write-Host "  Removed firewall rule '$ManagerRule': tills now use the encrypted address." }
  }
  'unfirewall' {
    foreach ($n in @($RelayRule, $ManagerRule, $ManagerHttpsRule)) {
      $r = Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue
      if ($r) { $r | Remove-NetFirewallRule; Write-Host "  Removed firewall rule '$n'." } else { Write-Host "  No firewall rule '$n'." }
    }
  }
}
