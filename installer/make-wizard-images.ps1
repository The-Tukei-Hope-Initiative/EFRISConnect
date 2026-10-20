# EFRISConnect - draw the Setup wizard pictures (installer\wizard-*.bmp).
# Left panel: a deep green column (the extension's header green, slightly darker
# at the foot), the EFRISConnect logo on a white tile, the name, one line on what
# it does, three short points with gold ticks, and at the foot a thin black,
# yellow and red rule (Uganda's colours, without drawing the flag itself) over
# the credit as in the extension's footer: a project of The Tukei Hope
# Initiative, CBO, Entebbe, registration no. (the welcome page links the website). Small picture: the app icon.
# Sizes are those of Inno Setup's MODERN wizard (WizardStyle=modern): the large
# picture is 240 x 459 and the small one 58 x 58 at 100%; each is drawn at 100,
# 125, 150, 175 and 200% so Setup uses an exact fit instead of stretching.
#   powershell -ExecutionPolicy Bypass -File installer\make-wizard-images.ps1
#   (add -Preview to also write PNG copies to the TEMP folder)
param([switch]$Preview)
Add-Type -AssemblyName System.Drawing
$dir = $PSScriptRoot
$green = [Drawing.Color]::FromArgb(27, 94, 32)
$greenDark = [Drawing.Color]::FromArgb(16, 64, 22)
$light = [Drawing.Color]::FromArgb(200, 230, 201)
$gold = [Drawing.Color]::FromArgb(249, 168, 37)

function Save-Bmp($bmp, $name) {
  # Inno Setup reads 24-bit bitmaps; copy onto an opaque canvas first.
  $out = New-Object Drawing.Bitmap $bmp.Width, $bmp.Height, ([Drawing.Imaging.PixelFormat]::Format24bppRgb)
  $g = [Drawing.Graphics]::FromImage($out); $g.DrawImage($bmp, 0, 0, $bmp.Width, $bmp.Height); $g.Dispose()
  $out.Save((Join-Path $dir $name), [Drawing.Imaging.ImageFormat]::Bmp)
  if ($Preview) { $out.Save((Join-Path $env:TEMP ($name -replace '\.bmp$', '.png')), [Drawing.Imaging.ImageFormat]::Png) }
  $out.Dispose()
}

function Rounded([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
  $p = New-Object Drawing.Drawing2D.GraphicsPath; $d = 2 * $r
  $p.AddArc($x, $y, $d, $d, 180, 90); $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
  $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90); $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90); $p.CloseFigure()
  return $p
}

# The logo: the app icon's "E" (stem, three bars) and gold accent, in green on a
# white rounded tile (the icon itself is white on green).
function Draw-Logo($g, [float]$x, [float]$y, [float]$s) {
  $g.FillPath((New-Object Drawing.SolidBrush ([Drawing.Color]::White)), (Rounded $x $y $s $s ($s * 0.22)))
  $u = $s / 16.0; $th = 2.2 * $u; $rr = $th * 0.45   # soft rounded ends on every bar
  $gb = New-Object Drawing.SolidBrush $green
  $x0 = $x + 4 * $u
  $g.FillPath($gb, (Rounded $x0 ($y + 3 * $u) $th (10 * $u) $rr))
  $g.FillPath($gb, (Rounded $x0 ($y + 3 * $u) (7.5 * $u) $th $rr))
  $g.FillPath($gb, (Rounded $x0 ($y + 6.9 * $u) (6 * $u) $th $rr))
  $g.FillPath($gb, (Rounded $x0 ($y + 13 * $u - $th) (7.5 * $u) $th $rr))
  $g.FillPath((New-Object Drawing.SolidBrush $gold), (Rounded ($x + 11.5 * $u) ($y + 6.9 * $u) (1.6 * $u) $th ($rr * 0.7)))
}

# A gold tick, drawn as two strokes.
function Draw-Tick($g, [float]$x, [float]$y, [float]$s) {
  $pen = New-Object Drawing.Pen $gold, ([float]($s * 0.18)); $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
  $pts = [Drawing.PointF[]]@((New-Object Drawing.PointF ($x), ($y + $s * 0.55)), (New-Object Drawing.PointF ($x + $s * 0.38), ($y + $s * 0.9)), (New-Object Drawing.PointF ($x + $s), ($y + $s * 0.15)))
  $g.DrawLines($pen, $pts); $pen.Dispose()
}

foreach ($pct in 100, 125, 150, 175, 200) {
  $k = $pct / 100
  # Large: 240 x 459 at 100%.
  $w = [int][Math]::Round(240 * $k); $h = [int][Math]::Round(459 * $k)
  $bmp = New-Object Drawing.Bitmap $w, $h
  $g = [Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.TextRenderingHint = 'ClearTypeGridFit'
  # Background: header green, easing to a darker green towards the foot.
  $bg = New-Object Drawing.Drawing2D.LinearGradientBrush (New-Object Drawing.Rectangle 0, 0, $w, $h), $green, $greenDark, 90
  $g.FillRectangle($bg, 0, 0, $w, $h)
  $pad = 26 * $k
  $white = New-Object Drawing.SolidBrush ([Drawing.Color]::White)
  $lightB = New-Object Drawing.SolidBrush $light

  Draw-Logo $g $pad (28 * $k) (50 * $k)
  $fName = New-Object Drawing.Font('Segoe UI Semibold', [float](24 * $k), [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
  $fTag = New-Object Drawing.Font('Segoe UI', [float](13.5 * $k), [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
  $fPt = New-Object Drawing.Font('Segoe UI', [float](13 * $k), [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
  $fFoot = New-Object Drawing.Font('Segoe UI', [float](11.5 * $k), [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
  $g.DrawString('EFRISConnect', $fName, $white, $pad - 2 * $k, 88 * $k)
  $box = New-Object Drawing.RectangleF ([float]$pad), ([float](122 * $k)), ([float]($w - 2 * $pad)), ([float](44 * $k))
  $g.DrawString("URA EFRIS e-receipts and`ne-invoices for Manager.io", $fTag, $lightB, $box)
  $g.FillRectangle((New-Object Drawing.SolidBrush $gold), $pad, [float](172 * $k), [float](32 * $k), [float](3 * $k))

  # Three points.
  $pts = @('Receipts, invoices and credit notes', 'Keeps selling when the internet is down', 'Your data stays on your computer')
  $y = 192 * $k
  foreach ($t in $pts) {
    Draw-Tick $g $pad ($y + 3 * $k) (12 * $k)
    $tb = New-Object Drawing.RectangleF ([float]($pad + 22 * $k)), ([float]$y), ([float]($w - 2 * $pad - 22 * $k)), ([float](40 * $k))
    $g.DrawString($t, $fPt, $white, $tb)
    $y += 41 * $k
  }

  # Foot: a thin rule in Uganda's colours, then the credit.
  $ry = $h - 122 * $k; $seg = ($w - 2 * $pad) / 3
  $cols = @([Drawing.Color]::Black, [Drawing.Color]::FromArgb(252, 220, 4), [Drawing.Color]::FromArgb(217, 0, 0))
  for ($i = 0; $i -lt 3; $i++) { $g.FillRectangle((New-Object Drawing.SolidBrush $cols[$i]), [float]($pad + $i * $seg), [float]$ry, [float]$seg, [float](3 * $k)) }
  # The credit, as in the extension's footer (the organisation's name in gold).
  $goldB = New-Object Drawing.SolidBrush $gold
  $fFootB = New-Object Drawing.Font('Segoe UI Semibold', [float](11.5 * $k), [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
  # Centred under the rule, like the extension's footer.
  $fy = $ry + 10 * $k; $lh = 17 * $k; $cx = 8 * $k; $cw = $w - 2 * $cx
  $mid = New-Object Drawing.StringFormat; $mid.Alignment = 'Center'; $mid.FormatFlags = 'NoWrap'
  function Centre($text, $font, $brush) { $g.DrawString($text, $font, $brush, (New-Object Drawing.RectangleF ([float]$cx), ([float]$script:fy), ([float]$cw), ([float]$lh)), $mid); $script:fy += $lh }
  Centre 'EFRISConnect - Free & Open Source' $fFootB $white
  # "A project of" in light green, the name in gold, centred as one line.
  $a = 'A project of'; $b = 'The Tukei Hope Initiative'; $gap = 4 * $k
  $wa = $g.MeasureString($a, $fFoot, 1000, [Drawing.StringFormat]::GenericTypographic).Width
  $wb = $g.MeasureString($b, $fFootB, 1000, [Drawing.StringFormat]::GenericTypographic).Width
  $x1 = $cx + ($cw - $wa - $gap - $wb) / 2
  $g.DrawString($a, $fFoot, $lightB, [float]$x1, [float]$fy, [Drawing.StringFormat]::GenericTypographic)
  $g.DrawString($b, $fFootB, $goldB, [float]($x1 + $wa + $gap), [float]$fy, [Drawing.StringFormat]::GenericTypographic); $fy += $lh
  Centre 'Community Based Organisation,' $fFoot $lightB
  Centre 'Entebbe, Uganda' $fFoot $lightB
  Centre 'Registration No. EMC/CBO/025' $fFoot $lightB
  Centre 'Your Hope, Our Mission' $fFoot $lightB
  $g.Dispose()
  Save-Bmp $bmp ('wizard-large-' + $pct + '.bmp'); $bmp.Dispose()

  # Small: 58 x 58 at 100%, the app icon on white (from its 256 px PNG frame).
  $s = [int][Math]::Round(58 * $k)
  $bmp = New-Object Drawing.Bitmap $s, $s
  $g = [Drawing.Graphics]::FromImage($bmp); $g.Clear([Drawing.Color]::White); $g.InterpolationMode = 'HighQualityBicubic'; $g.PixelOffsetMode = 'HighQuality'
  $ico = New-Object Drawing.Icon((Join-Path $dir 'efrisconnect.ico'), 256, 256)
  $m = [int](4 * $k); $g.DrawImage($ico.ToBitmap(), $m, $m, $s - 2 * $m, $s - 2 * $m); $g.Dispose()
  Save-Bmp $bmp ('wizard-small-' + $pct + '.bmp'); $bmp.Dispose()
}
# The logo alone (green background, white tile), for the side panel Setup draws as
# text: 120 px, shown at 44 px and scaled down sharply at every display scale.
$bmp = New-Object Drawing.Bitmap 120, 120
$g = [Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'
$g.Clear($green); Draw-Logo $g 0 0 120; $g.Dispose()
Save-Bmp $bmp 'logo-tile.bmp'; $bmp.Dispose()
Write-Host 'Wrote installer\wizard-large-*.bmp, wizard-small-*.bmp and logo-tile.bmp'
