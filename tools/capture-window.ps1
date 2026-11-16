# Captures the Kestrel window (not the whole desktop) for design evidence.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools/capture-window.ps1 -Path artifacts/x.png [-Width 1180 -Height 760 -X 0 -Y 0]
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [int]$Width = 0,
  [int]$Height = 0,
  [int]$X = 0,
  [int]$Y = 0
)
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h, ref POINT p);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hgt, bool repaint);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
}
"@
$proc = Get-Process kestrel -ErrorAction Stop | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $proc) { throw "no kestrel window" }
$h = $proc.MainWindowHandle
[void][Win]::ShowWindow($h, 9)
[void][Win]::SetForegroundWindow($h)
if ($Width -gt 0 -and $Height -gt 0) {
  [void][Win]::MoveWindow($h, $X, $Y, $Width, $Height, $true)
  Start-Sleep -Milliseconds 500
}
Start-Sleep -Milliseconds 350
$rect = New-Object Win+RECT
[void][Win]::GetClientRect($h, [ref]$rect)
$origin = New-Object Win+POINT
[void][Win]::ClientToScreen($h, [ref]$origin)
$w = $rect.R - $rect.L
$hgt = $rect.B - $rect.T
$bmp = New-Object System.Drawing.Bitmap $w, $hgt
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen($origin.X, $origin.Y, 0, 0, (New-Object System.Drawing.Size $w, $hgt))
$dir = Split-Path -Parent $Path
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
$gfx.Dispose(); $bmp.Dispose()
Write-Output "saved $Path ($w x $hgt)"
