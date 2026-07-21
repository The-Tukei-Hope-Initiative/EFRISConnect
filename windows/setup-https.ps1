# EFRISConnect - offline local HTTPS setup (Desktop, Docker-Desktop, and LAN/server).
# Generates ONE self-signed certificate that covers localhost, 127.0.0.1, this
# machine's hostname, and its LAN IPv4 address(es); installs it into the machine's
# Trusted Root store; and exports it as a PFX (for the relay) and a .cer (to trust
# on any till/client PCs on the LAN). 100% offline - no internet, no openssl, no
# renewals. Run once, as Administrator, on the machine that runs the relay.
param(
  [string]$DataDir,
  [string[]]$ExtraNames = @()   # optional extra hostnames/IPs, e.g. -ExtraNames "efris.local","192.168.1.50"
)
$ErrorActionPreference = "Stop"

# Build the Subject Alternative Name list: DNS names + IP addresses.
$dns = @('localhost', $env:COMPUTERNAME) + ($ExtraNames | Where-Object { $_ -notmatch '^\d+\.\d+\.\d+\.\d+$' })
$ips = @('127.0.0.1')
try {
  $ips += (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' }).IPAddress
} catch {}
$ips += ($ExtraNames | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
$dns = $dns | Where-Object { $_ } | Select-Object -Unique
$ips = $ips | Where-Object { $_ } | Select-Object -Unique
$san = (($dns | ForEach-Object { "DNS=$_" }) + ($ips | ForEach-Object { "IPAddress=$_" })) -join '&'

Write-Host "Generating a locally-trusted certificate for https://localhost:5443 ..."
Write-Host "  Covers: $($dns -join ', '), $($ips -join ', ')"
$cert = New-SelfSignedCertificate `
  -Subject "CN=EFRISConnect Local HTTPS" `
  -CertStoreLocation "Cert:\LocalMachine\My" `
  -FriendlyName "EFRISConnect Local HTTPS" `
  -NotAfter (Get-Date).AddYears(10) `
  -KeyExportPolicy Exportable `
  -TextExtension @("2.5.29.17={text}$san")

# Trust it on THIS machine (Trusted Root, LocalMachine).
$root = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$root.Open("ReadWrite"); $root.Add($cert); $root.Close()
Write-Host "Installed into Trusted Root (this machine)."

if (!(Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir | Out-Null }
# Use a RANDOM per-install password for the PFX (never a shared constant), and lock
# the password file to the current user. This protects only the LOCAL self-signed
# localhost/LAN certificate's private key; it is unrelated to any EFRIS or Manager
# credential. The private key's real protection is the file system permissions.
$pfxPass = [System.Guid]::NewGuid().ToString("N")
$pwd = ConvertTo-SecureString $pfxPass -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath (Join-Path $DataDir "https.pfx") -Password $pwd | Out-Null
$passFile = Join-Path $DataDir "https_pfx_pass.txt"
$pfxPass | Out-File -FilePath $passFile -Encoding ascii -NoNewline
try { icacls $passFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null } catch {}
# Public cert (no private key) - copy this to LAN till PCs to trust the server there.
Export-Certificate -Cert $cert -FilePath (Join-Path $DataDir "https_cert.cer") | Out-Null

Write-Host ""
Write-Host "Done. Relay will serve HTTPS on localhost AND this machine's LAN address."
Write-Host "For LAN tills: copy backend\data\https_cert.cer to each PC, then run"
Write-Host "windows\EFRISConnect.bat -> option 5 (Trust a server's certificate) there."
