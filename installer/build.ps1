# EFRISConnect - build the Windows installer.
#
#   powershell -ExecutionPolicy Bypass -File installer\build.ps1 [-NodeVersion 24.16.0] [-SkipCompile]
#
# 1. Stages the shipping files in build\stage (no tests, no runtime data, no keys).
# 2. Installs the production dependencies there (npm ci --omit=dev).
# 3. Bundles node.exe for Windows x64, checked against nodejs.org's SHA-256 list.
# 4. Compiles installer\EFRISConnect.iss with Inno Setup 6 into build\EFRISConnect-Setup-<version>.exe.
# Needs: Node.js + npm on this PC (for step 2), Inno Setup 6 (https://jrsoftware.org/isinfo.php).
param(
  [string]$NodeVersion = '24.16.0',
  [switch]$SkipCompile
)
$ErrorActionPreference = 'Stop'
$Repo    = Split-Path -Parent $PSScriptRoot
$Build   = Join-Path $Repo 'build'
$Stage   = Join-Path $Build 'stage'
$Cache   = Join-Path $Build 'cache'
$Version = (Get-Content (Join-Path $Repo 'VERSION') -TotalCount 1).Trim()
Write-Host "EFRISConnect $Version - building the installer with Node.js $NodeVersion"

# --- 1. Stage ---------------------------------------------------------------
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage, $Cache -Force | Out-Null
foreach ($f in 'LICENSE', 'README.md', 'VERSION', 'package.json') { Copy-Item (Join-Path $Repo $f) $Stage }
# robocopy exit codes below 8 mean success.
function Copy-Tree([string]$from, [string]$to, [string[]]$xd = @(), [string[]]$xf = @()) {
  $rc = @($from, $to, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP')
  if ($xd) { $rc += "/XD"; $rc += $xd }
  if ($xf) { $rc += "/XF"; $rc += $xf }
  & robocopy.exe @rc | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "Copy failed: $from" }
}
Copy-Tree (Join-Path $Repo 'frontend') (Join-Path $Stage 'frontend') @('Old*')
Copy-Tree (Join-Path $Repo 'windows')  (Join-Path $Stage 'windows')
Copy-Tree (Join-Path $Repo 'backend')  (Join-Path $Stage 'backend') `
  @('__tests__', 'node_modules', 'keys', 'Old*', 'data') @('Dockerfile', '*.pem', '*.key', '*.pfx', '*.log')
# Only the reference data that ships with the code; everything else in backend\data is runtime.
$shipped = 'goods_tree.json', 'segments.json', 'units.json', 'uom.json'
New-Item -ItemType Directory -Path (Join-Path $Stage 'backend\data') | Out-Null
foreach ($f in $shipped) {
  $p = Join-Path $Repo "backend\data\$f"; if (Test-Path $p) { Copy-Item $p (Join-Path $Stage 'backend\data') }
}
$seg = Join-Path $Repo 'backend\data\segments'
if (Test-Path $seg) { Copy-Tree $seg (Join-Path $Stage 'backend\data\segments') }

# --- 2. Production dependencies --------------------------------------------
Push-Location (Join-Path $Stage 'backend')
try {
  & npm.cmd ci --omit=dev --no-audit --no-fund
  if ($LASTEXITCODE) { throw 'npm ci failed' }
} finally { Pop-Location }

# --- 3. Node.js runtime ----------------------------------------------------
$zipName = "node-v$NodeVersion-win-x64.zip"
$zip  = Join-Path $Cache $zipName
$base = "https://nodejs.org/dist/v$NodeVersion"
if (!(Test-Path $zip)) {
  Write-Host "Downloading $zipName ..."
  Invoke-WebRequest "$base/$zipName" -OutFile $zip -UseBasicParsing
}
$sums = (Invoke-WebRequest "$base/SHASUMS256.txt" -UseBasicParsing).Content -split "`n"
$want = (($sums | Where-Object { $_ -match "\s$([regex]::Escape($zipName))$" }) -split '\s+')[0]
$have = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if (!$want -or $have -ne $want.ToLower()) { Remove-Item $zip -Force; throw "SHA-256 mismatch for $zipName - download removed, run again." }
Write-Host "Node.js checksum OK ($have)"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [IO.Compression.ZipFile]::OpenRead($zip)
try {
  $nodeDir = Join-Path $Stage 'node'; New-Item -ItemType Directory -Path $nodeDir | Out-Null
  foreach ($e in $z.Entries) {
    if ($e.FullName -match '/(node\.exe|LICENSE)$') {
      [IO.Compression.ZipFileExtensions]::ExtractToFile($e, (Join-Path $nodeDir $e.Name), $true)
    }
  }
} finally { $z.Dispose() }

# Quick check that the staged relay loads with the bundled runtime.
& (Join-Path $Stage 'node\node.exe') --check (Join-Path $Stage 'backend\server.js')
if ($LASTEXITCODE) { throw 'Staged server.js failed node --check' }

# --- 4. Compile ------------------------------------------------------------
if ($SkipCompile) { Write-Host "Staged in $Stage (compile skipped)."; exit 0 }
$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (!$iscc) { throw 'Inno Setup 6 (ISCC.exe) not found. Install it from https://jrsoftware.org/isinfo.php or use -SkipCompile.' }
& $iscc "/DAppVersion=$Version" "/DStageDir=$Stage" (Join-Path $PSScriptRoot 'EFRISConnect.iss')
if ($LASTEXITCODE) { throw 'Inno Setup compile failed' }
Write-Host "Built: $Build\EFRISConnect-Setup-$Version.exe"
