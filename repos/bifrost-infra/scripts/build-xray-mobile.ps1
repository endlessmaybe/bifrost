# Compatibility entry point.  Xray is no longer built as a second gomobile
# runtime: the supported Android artifact is the single unified libbox AAR.
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$GoRoot = '',
  [string]$AndroidNdk = '',
  [string]$Version = '26.3.27',
  [string]$XraySource = ''
)

$script = Join-Path $PSScriptRoot 'build-unified-libbox.ps1'
& $script -RepoRoot $RepoRoot -GoRoot $GoRoot -AndroidNdk $AndroidNdk -XrayVersion $Version -XraySource $XraySource
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
