# Runs the shell crate's Rust tests with the one adjustment they need.
#
# `tauri` pulls `muda`, which imports `TaskDialogIndirect` from comctl32 v6.
# tauri-build embeds the Common-Controls v6 manifest with
# `cargo:rustc-link-arg-bins`, so only **bin** targets get it. The lib's test
# binary keeps mingw's default manifest, the loader binds comctl32 v5, and the
# process dies with STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139) before `main`.
#
# Cargo cannot express "link this only for the lib test target":
# `cargo:rustc-link-arg-tests` is rejected because the package declares no
# `[[test]]` target, and `cargo:rustc-link-arg` would give the bin a second copy
# of the resource archive (`ld: .rsrc merge failure: duplicate leaf`). So the
# archive goes in through RUSTFLAGS for the test run only — no bin is linked
# here, which is why it is safe.
#
# Usage:
#   powershell -File tools/test-shell.ps1                  # every unit test
#   powershell -File tools/test-shell.ps1 -Filter autofill::
#
# This runs the `kestrel` package only. The core suites are a separate package
# and a separate command (they need no manifest workaround):
#   powershell -File tools/rust-env.ps1 cargo test -p kestrel-core
param([string]$Filter = '', [switch]$Refresh)

$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
Push-Location (Join-Path $root 'src-tauri')
try {
    # A stable copy on purpose: the archive lives under a build-script hash
    # directory that changes whenever the build script re-runs, and a changing
    # RUSTFLAGS makes cargo keep a fresh ~270 MB test binary under
    # `target/debug/build/kestrel/<hash>/out/` for every value. One fixed path
    # means one cached test binary.
    $stable = Join-Path (Get-Location) 'target/kestrel-test-resource.a'

    # The bin build is what produces the archive, and it uses no RUSTFLAGS, so
    # running it every time would fingerprint the crate twice. Build it only
    # when the stable copy is missing or explicitly refreshed.
    if ($Refresh -or -not (Test-Path $stable)) {
        & (Join-Path $PSScriptRoot 'rust-env.ps1') cargo build -p kestrel --offline --bins | Out-Null
        $resource = Get-ChildItem 'target/debug/build/kestrel/*/out/libresource.a' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if (-not $resource) {
            Write-Error 'no libresource.a under src-tauri/target/debug/build/kestrel'
            exit 1
        }
        Copy-Item -Force $resource.FullName $stable
    }

    $env:RUSTFLAGS = "-C link-arg=$stable"
    # `[string[]]` on purpose: a one-element `@('--lib')` unrolls to a bare
    # string, and `+=` then concatenates instead of appending.
    [string[]]$cargoArgs = @('--lib')
    # The filter is cargo's positional TESTNAME, so no `--` separator: the
    # wrapper passes arguments through PowerShell, where a bare `--` does not
    # survive intact.
    if ($Filter) { $cargoArgs += $Filter }
    & (Join-Path $PSScriptRoot 'rust-env.ps1') cargo test -p kestrel --offline @cargoArgs
    exit $LASTEXITCODE
}
finally {
    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
    Pop-Location
}
