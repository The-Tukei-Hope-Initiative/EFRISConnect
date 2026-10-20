# EFRISConnect - draw the application icon (installer\efrisconnect.ico).
# A rounded green square (the extension's header green) with a white "E" and a
# gold bar (the gold of the Uganda flag and the footer). Sizes 16-256 px, stored
# as PNG images inside one .ico, which every supported Windows version reads.
#   powershell -ExecutionPolicy Bypass -File installer\make-icon.ps1
param([string]$Out = (Join-Path $PSScriptRoot 'efrisconnect.ico'))
Add-Type -AssemblyName System.Drawing

# A bar with rounded corners of radius r (r = 0: a plain rectangle).
function Fill-Bar($g, $brush, [float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
  if ($r -le 0) { $g.FillRectangle($brush, $x, $y, $w, $h); return }
  $p = New-Object Drawing.Drawing2D.GraphicsPath; $d = 2 * $r
  $p.AddArc($x, $y, $d, $d, 180, 90); $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
  $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90); $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90); $p.CloseFigure()
  $g.FillPath($brush, $p)
}
function Draw-Png([int]$size) {
  $bmp = New-Object Drawing.Bitmap $size, $size
  $g = [Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'AntiAliasGridFit'; $g.InterpolationMode = 'HighQualityBicubic'
  $g.Clear([Drawing.Color]::Transparent)
  $r = [Math]::Max(2, [int]($size * 0.22)); $d = $r * 2; $w = $size - 1
  $path = New-Object Drawing.Drawing2D.GraphicsPath
  $path.AddArc(0, 0, $d, $d, 180, 90); $path.AddArc($w - $d, 0, $d, $d, 270, 90)
  $path.AddArc($w - $d, $w - $d, $d, $d, 0, 90); $path.AddArc(0, $w - $d, $d, $d, 90, 90); $path.CloseFigure()
  $g.FillPath((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(27, 94, 32))), $path)
  # The "E": three bars and a stem, so it stays crisp at 16 px.
  $white = New-Object Drawing.SolidBrush ([Drawing.Color]::White)
  $u = $size / 16.0
  $x0 = 4 * $u; $th = [Math]::Max(1.5, 2.2 * $u)
  # Soft rounded ends on every bar (from 32 px up; at 16-24 px a curve would only blur).
  $rr = if ($size -ge 32) { $th * 0.45 } else { 0 }
  Fill-Bar $g $white $x0 (3 * $u) $th (10 * $u) $rr            # stem
  Fill-Bar $g $white $x0 (3 * $u) (7.5 * $u) $th $rr           # top
  Fill-Bar $g $white $x0 (6.9 * $u) (6 * $u) $th $rr           # middle
  Fill-Bar $g $white $x0 (13 * $u - $th) (7.5 * $u) $th $rr    # bottom
  # Gold accent at the right of the middle bar.
  $gold = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(249, 168, 37))
  Fill-Bar $g $gold (11.5 * $u) (6.9 * $u) (1.6 * $u) $th ($rr * 0.7)
  $g.Dispose()
  $ms = New-Object IO.MemoryStream
  if ($size -ge 256) { $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); return ,$ms.ToArray() }
  # Smaller sizes as classic 32-bit bitmaps: every reader (the tray, .NET) takes those.
  $bw = New-Object IO.BinaryWriter $ms
  $bw.Write([UInt32]40); $bw.Write([Int32]$size); $bw.Write([Int32]($size * 2)); $bw.Write([UInt16]1); $bw.Write([UInt16]32)
  $bw.Write([UInt32]0); $bw.Write([UInt32]0); $bw.Write([Int32]0); $bw.Write([Int32]0); $bw.Write([UInt32]0); $bw.Write([UInt32]0)
  for ($y = $size - 1; $y -ge 0; $y--) {
    for ($x = 0; $x -lt $size; $x++) { $c = $bmp.GetPixel($x, $y); $bw.Write([byte]$c.B); $bw.Write([byte]$c.G); $bw.Write([byte]$c.R); $bw.Write([byte]$c.A) }
  }
  $maskRow = [int]([Math]::Ceiling($size / 32.0) * 4)
  for ($y = 0; $y -lt $size; $y++) { $bw.Write((New-Object byte[] $maskRow)) }
  $bw.Flush(); $bmp.Dispose()
  return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = foreach ($s in $sizes) { ,(Draw-Png $s) }
$fs = [IO.File]::Create($Out); $bw = New-Object IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
  $s = $sizes[$i]; $len = $images[$i].Length
  $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s }))); $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))
  $bw.Write([byte]0); $bw.Write([byte]0); $bw.Write([UInt16]1); $bw.Write([UInt16]32)
  $bw.Write([UInt32]$len); $bw.Write([UInt32]$offset); $offset += $len
}
foreach ($img in $images) { $bw.Write($img) }
$bw.Close()
Write-Host "Wrote $Out"
