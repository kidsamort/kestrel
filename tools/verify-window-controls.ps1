# Verifies the custom titlebar's window buttons against the real window.
# No screenshots: the checks are window-state assertions.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $root 'src-tauri\target\debug\kestrel.exe'
if (-not (Test-Path $exe)) { Write-Output "missing $exe"; exit 1 }

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L; public int T; public int R; public int B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, int extra);
}
"@

function Click-At([IntPtr]$handle, [int]$x, [int]$y) {
    [void][W]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 250
    $r = New-Object W+RECT
    [void][W]::GetWindowRect($handle, [ref]$r)
    [void][W]::SetCursorPos($r.L + $x, $r.T + $y)
    Start-Sleep -Milliseconds 150
    [void][W]::mouse_event(0x0002, 0, 0, 0, 0)
    [void][W]::mouse_event(0x0004, 0, 0, 0, 0)
}

function Rect-Of([IntPtr]$handle) {
    $r = New-Object W+RECT
    [void][W]::GetWindowRect($handle, [ref]$r)
    return $r
}

$proc = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 9
$proc.Refresh()
$h = $proc.MainWindowHandle
if ($h -eq [IntPtr]::Zero) { Write-Output "FAIL: no main window"; exit 1 }

$r0 = Rect-Of $h
$w = $r0.R - $r0.L
$barY = 19
$minX = $w - 110
$maxX = $w - 66
$closeX = $w - 22
Write-Output "window ${w}x$($r0.B - $r0.T) at ($($r0.L),$($r0.T))"

Click-At $h $minX $barY
Start-Sleep -Seconds 1
$minimized = [W]::IsIconic($h)
Write-Output ("minimize button: " + $(if ($minimized) { "PASS" } else { "FAIL" }))
[void][W]::ShowWindow($h, 9) # SW_RESTORE
Start-Sleep -Seconds 1

$before = Rect-Of $h
Click-At $h $maxX $barY
Start-Sleep -Seconds 1
$after = Rect-Of $h
$grew = (($after.R - $after.L) -gt ($before.R - $before.L)) -and (($after.B - $after.T) -gt ($before.B - $before.T))
Write-Output ("maximize button: " + $(if ($grew) { "PASS" } else { "FAIL" }) + " ($($before.R - $before.L) -> $($after.R - $after.L) wide)")

Click-At $h $maxX $barY
Start-Sleep -Seconds 1
$restored = Rect-Of $h
$back = (($restored.R - $restored.L) -eq ($before.R - $before.L))
Write-Output ("restore via same button: " + $(if ($back) { "PASS" } else { "FAIL" }))

Click-At $h $closeX $barY
Start-Sleep -Seconds 3
$proc.Refresh()
Write-Output ("close button: " + $(if ($proc.HasExited) { "PASS" } else { "FAIL" }))
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
