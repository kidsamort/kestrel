# Sets a clean Windows PATH for the Rust/GNU toolchain and runs the given command.
# The harness shell mangles PATH, so every Rust invocation goes through here.
$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false
$cargo = "$env:USERPROFILE\.cargo\bin"
$mingw = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin"
$env:PATH = "$cargo;$mingw;C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem"
$env:RUSTUP_TOOLCHAIN = if ($env:RUSTUP_TOOLCHAIN) { $env:RUSTUP_TOOLCHAIN } else { 'stable-x86_64-pc-windows-gnu' }

if ($args.Count -eq 0) {
    rustc -V
    gcc --version | Select-Object -First 1
    exit 0
}

$exe = $args[0]
$rest = @()
if ($args.Count -gt 1) { $rest = $args[1..($args.Count - 1)] }
& $exe @rest 2>&1 | ForEach-Object { $_ }
exit $LASTEXITCODE
