# Register Kestrel as a sparse package: the app keeps running from its own
# folder, but Windows gives it a package identity. Passkey plugin authenticators
# require that identity — without it `WebAuthNPluginAddAuthenticator` answers
# 0x80073D54 (APPMODEL_ERROR_NO_PACKAGE).
#
#   powershell -ExecutionPolicy Bypass -File deploy\msix\register-sparse.ps1
#
# Needs Developer Mode (or sideloading enabled). The package references the
# release build through -ExternalLocation, so build first:
#
#   npm run app:build            (or: cargo build -p kestrel --release)
#
# Launch the packaged app afterwards, so it runs with identity:
#
#   Start-Process "shell:AppsFolder\Kestrel.Passkeys_g7f8a26w9rava!Kestrel"

param(
  [string]$ExternalLocation = (Join-Path $PSScriptRoot '..\..\src-tauri\target\release')
)

$manifest = Join-Path $PSScriptRoot 'AppxManifest.xml'
if (-not (Test-Path $manifest)) { throw "manifest not found: $manifest" }
if (-not (Test-Path (Join-Path $ExternalLocation 'kestrel.exe'))) {
  throw "kestrel.exe not found in $ExternalLocation — build the release app first"
}

Get-AppxPackage Kestrel.Passkeys | Remove-AppxPackage -ErrorAction SilentlyContinue
Add-AppxPackage -Register $manifest -ExternalLocation (Resolve-Path $ExternalLocation) -ErrorAction Stop

$pkg = Get-AppxPackage Kestrel.Passkeys
Write-Output ("registered {0}" -f $pkg.PackageFullName)
Write-Output ("launch: Start-Process 'shell:AppsFolder\{0}!Kestrel'" -f $pkg.PackageFamilyName)
