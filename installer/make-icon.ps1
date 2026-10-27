# EFRISConnect - build the application icon (installer\efrisconnect.ico) from the
# brand kit's app mark (EFRISConnect_Brand_Kit_v1.2\04_PNG\efrisconnect-app.png,
# 2400 px): the same interlocked EC at every size, 16 px included, scaled down in
# halving steps so small sizes stay sharp.
# 16 to 128 px are stored as 32-bit bitmaps, 256 px as PNG: the layout every reader
# accepts (.NET's Icon class, used by the tray icon, fails on small PNG frames).
#   powershell -ExecutionPolicy Bypass -File installer\make-icon.ps1 [-Kit <brand kit folder>]
param(
  [string]$Kit = (Join-Path (Split-Path -Parent $PSScriptRoot) 'EFRISConnect_Brand_Kit_v1.2'),
  [string]$Out = (Join-Path $PSScriptRoot 'efrisconnect.ico'),
  [string]$PreviewDir = ''
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$sizes = 16, 24, 32, 48, 64, 128, 256
$src = Join-Path $Kit '04_PNG\efrisconnect-app.png'
if (!(Test-Path $src)) { throw "Missing $src" }
$master = New-Object Drawing.Bitmap $src
function Scale-To([int]$s) {
  $cur = $master
  while ($cur.Width / 2 -ge $s) {
    $n = New-Object Drawing.Bitmap ([int]($cur.Width / 2)), ([int]($cur.Height / 2))
    $g = [Drawing.Graphics]::FromImage($n); $g.InterpolationMode = 'HighQualityBicubic'; $g.PixelOffsetMode = 'HighQuality'; $g.CompositingQuality = 'HighQuality'
    $g.DrawImage($cur, 0, 0, $n.Width, $n.Height); $g.Dispose(); $cur = $n
  }
  $o = New-Object Drawing.Bitmap $s, $s
  $g = [Drawing.Graphics]::FromImage($o); $g.InterpolationMode = 'HighQualityBicubic'; $g.PixelOffsetMode = 'HighQuality'; $g.CompositingQuality = 'HighQuality'
  $g.DrawImage($cur, 0, 0, $s, $s); $g.Dispose()
  return $o
}
$frames = foreach ($s in $sizes) {
  $img = Scale-To $s
  if ($s -eq 256) { $pm = New-Object IO.MemoryStream; $img.Save($pm, [Drawing.Imaging.ImageFormat]::Png); , $pm.ToArray(); continue }
  # A bitmap frame: BITMAPINFOHEADER (height doubled for the mask), BGRA rows bottom
  # up, then an all-zero AND mask (the alpha channel carries the transparency).
  $bmp = $img
  $ms = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter $ms
  $bw.Write([int32]40); $bw.Write([int32]$s); $bw.Write([int32]($s * 2)); $bw.Write([int16]1); $bw.Write([int16]32)
  $bw.Write([int32]0); $bw.Write([int32]($s * $s * 4)); $bw.Write([int32]0); $bw.Write([int32]0); $bw.Write([int32]0); $bw.Write([int32]0)
  for ($y = $s - 1; $y -ge 0; $y--) { for ($x = 0; $x -lt $s; $x++) { $c = $bmp.GetPixel($x, $y); $bw.Write([byte]$c.B); $bw.Write([byte]$c.G); $bw.Write([byte]$c.R); $bw.Write([byte]$c.A) } }
  $maskRow = [int]([Math]::Ceiling($s / 32.0) * 4)
  $bw.Write((New-Object byte[] ($maskRow * $s)))
  $bw.Flush(); $bmp.Dispose()
  , $ms.ToArray()
}
$ms = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter $ms
$bw.Write([int16]0); $bw.Write([int16]1); $bw.Write([int16]$sizes.Count)
$off = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
  $s = $sizes[$i]; $d = $frames[$i]
  $bw.Write([byte]($s % 256)); $bw.Write([byte]($s % 256)); $bw.Write([byte]0); $bw.Write([byte]0)
  $bw.Write([int16]1); $bw.Write([int16]32); $bw.Write([int32]$d.Length); $bw.Write([int32]$off); $off += $d.Length
}
foreach ($d in $frames) { $bw.Write($d) }
$bw.Flush(); [IO.File]::WriteAllBytes($Out, $ms.ToArray())
if ($PreviewDir) { foreach ($s in 16, 24, 32, 48) { (Scale-To $s).Save((Join-Path $PreviewDir "icon-$s.png"), [Drawing.Imaging.ImageFormat]::Png) } }
# Check: .NET can read every size.
foreach ($s in $sizes) { $ic = New-Object Drawing.Icon($Out, $s, $s); $null = $ic.ToBitmap(); $ic.Dispose() }
Write-Host "Wrote $Out ($($sizes -join ', ') px)"
