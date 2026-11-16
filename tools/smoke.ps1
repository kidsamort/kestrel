# Builds the desktop binary and launches it for a smoke test, then captures the window.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools/smoke.ps1
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$cargo = "$env:USERPROFILE\.cargo\bin"
$mingw = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
$env:PATH = "$cargo;$mingw;C:\Windows\System32;C:\Windows"
$env:RUSTUP_TOOLCHAIN = "stable-x86_64-pc-windows-gnu"

Write-Output "== building =="
cargo build --manifest-path src-tauri/Cargo.toml --bin kestrel 2>&1 | Select-Object -Last 5
if ($LASTEXITCODE -ne 0) { Write-Output "build failed"; exit 1 }

$exe = Join-Path $root 'src-tauri\target\debug\kestrel.exe'
if (-not (Test-Path $exe)) { Write-Output "missing $exe"; exit 1 }

Write-Output "== launching $exe =="
$proc = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 7
if ($proc.HasExited) { Write-Output "process exited early: $($proc.ExitCode)"; exit 1 }
Write-Output "running pid=$($proc.Id)"

$shot = Join-Path $root 'artifacts\window.png'
& (Join-Path $PSScriptRoot 'screenshot.ps1') -Path $shot

Stop-Process -Id $proc.Id -ErrorAction SilentlyContinue
Write-Output "ok"
