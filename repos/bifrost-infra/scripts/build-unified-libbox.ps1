param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$GoRoot = '',
  [string]$AndroidSdk = '',
  [string]$AndroidNdk = '',
  [string]$SingBoxSource = '',
  [string]$XraySource = '',
  [string]$SingTunSource = '',
  [string]$GomobilePath = '',
  [string]$XrayVersion = '26.3.27',
  [switch]$ReusePinnedRuntime
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$clients = Join-Path $RepoRoot 'repos\bifrost-clients'
$bridge = Join-Path $PSScriptRoot 'libbox-xray-bridge.go'
$source = if ($SingBoxSource) { [IO.Path]::GetFullPath($SingBoxSource) } else { Join-Path $RepoRoot 'build-work\sing-box-src' }
$xray = if ($XraySource) { [IO.Path]::GetFullPath($XraySource) } else { Join-Path $RepoRoot "build-work\xray-src-$XrayVersion" }
$out = Join-Path $clients 'android-app\libs\libbox.aar'
$goBin = if ($GoRoot) { Join-Path $GoRoot 'bin\go.exe' } else { 'go' }
$gomobile = if ($GomobilePath) { [IO.Path]::GetFullPath($GomobilePath) } elseif ($GoRoot) { Join-Path $GoRoot 'bin\gomobile.exe' } else { 'gomobile' }
$singTun = if ($SingTunSource) { [IO.Path]::GetFullPath($SingTunSource) } else { Join-Path $RepoRoot 'build-work\sing-tun-src' }
$goDir = if ($GoRoot) { Join-Path $GoRoot 'bin' } else { Split-Path (Get-Command go.exe -ErrorAction Stop).Source }

function Require-File([string]$path, [string]$hint) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path. $hint" }
}

if ($ReusePinnedRuntime) {
  $lockPath = Join-Path $clients 'core-adapters\android-runtime.lock.json'
  Require-File $lockPath 'A source-controlled runtime lock is required for cached native builds.'
  $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
  if ($lock.format -ne 'BIFROST-ANDROID-RUNTIME-1' -or $lock.artifacts.Count -ne 6) { throw 'Invalid Android runtime lock.' }
  foreach ($artifact in $lock.artifacts) {
    $candidate = [IO.Path]::GetFullPath((Join-Path $RepoRoot $artifact.path))
    if (-not $candidate.StartsWith(([IO.Path]::GetFullPath($RepoRoot).TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'Android runtime input escaped the workspace.' }
    Require-File $candidate 'Restore the exact pinned native runtime/source input before packaging.'
    if (((Get-Item -LiteralPath $candidate).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Android runtime input cannot be a reparse point.' }
    if ((Get-Item -LiteralPath $candidate).Length -ne $artifact.bytes -or (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant() -ne $artifact.sha256) { throw "Android runtime input digest mismatch: $($artifact.path)" }
  }
  Write-Output 'Verified pinned unified libbox runtime and corresponding sing-box/Xray/bridge source inputs.'
  return
}

Require-File $bridge 'The tracked unified bridge source is required.'
Require-File (Join-Path $source 'go.mod') 'Use the pinned sing-box source checkout.'
Require-File (Join-Path $xray 'go.mod') 'Use the pinned Xray source checkout.'
Require-File (Join-Path $singTun 'go.mod') 'Extract the release-bound patched sing-tun source archive.'
Require-File (Join-Path $singTun 'stack_gvisor_filter.go') 'The Android TUN detach fix is required.'
$dnsOverlay = Join-Path $PSScriptRoot 'sing-box-tproxy_bifrost.go'
Require-File $dnsOverlay 'The scoped IPv6 DNS reply overlay is required.'
if ((Get-FileHash -LiteralPath (Join-Path $source 'protocol\redirect\tproxy.go')).Hash -ne (Get-FileHash -LiteralPath $dnsOverlay).Hash) { throw 'The sing-box scoped DNS overlay does not match the release-bound source.' }
$detachOverlay = Join-Path $PSScriptRoot 'sing-tun-gvisor-filter_bifrost.go'
Require-File $detachOverlay 'The source-controlled TUN detach overlay is required.'
if ((Get-FileHash -LiteralPath (Join-Path $singTun 'stack_gvisor_filter.go')).Hash -ne (Get-FileHash -LiteralPath $detachOverlay).Hash) { throw 'The sing-tun detach overlay does not match the release-bound source.' }
Require-File $goBin 'The pinned Go toolchain is required.'
Require-File $gomobile 'The pinned gomobile tool is required.'

if ($AndroidSdk) { $env:ANDROID_HOME = [IO.Path]::GetFullPath($AndroidSdk); $env:ANDROID_SDK_ROOT = $env:ANDROID_HOME }
if ($AndroidNdk) { $env:ANDROID_NDK_HOME = [IO.Path]::GetFullPath($AndroidNdk) }
if (-not $env:ANDROID_HOME -and $env:ANDROID_SDK_ROOT) { $env:ANDROID_HOME = $env:ANDROID_SDK_ROOT }
if (-not $env:ANDROID_NDK_HOME) { throw 'ANDROID_NDK_HOME (pinned NDK 28+) is required.' }
$env:PATH = "$goDir;$($env:PATH)"
$env:GOTOOLCHAIN = 'local'

$libbox = Join-Path $source 'experimental\libbox'
$overlay = Join-Path $libbox 'xray_bridge_bifrost.go'
$goMod = Join-Path $source 'go.mod'
$goSum = Join-Path $source 'go.sum'
$backupDir = Join-Path ([IO.Path]::GetTempPath()) ("bifrost-libbox-build-" + [guid]::NewGuid().ToString('N'))
$previousGoFlags = $env:GOFLAGS
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
Copy-Item -LiteralPath $goMod -Destination (Join-Path $backupDir 'go.mod') -Force
if (Test-Path -LiteralPath $goSum -PathType Leaf) { Copy-Item -LiteralPath $goSum -Destination (Join-Path $backupDir 'go.sum') -Force }

try {
  # Resolve the two declared local source replacements in the temporary build
  # module. go.mod/go.sum are restored below; the source archives are immutable.
  $env:GOFLAGS = (($previousGoFlags -replace '(?<!\S)-mod=\S+', '').Trim() + ' -mod=mod').Trim()
  Copy-Item -LiteralPath $bridge -Destination $overlay -Force
  Push-Location $source
  try {
    # gomobile's sing-box generator refuses to overwrite the per-ABI files it
    # leaves under build/.  They are generated build output (never source or
    # release input), so remove only this exact pinned checkout directory before
    # every bind.  This makes repeated release builds deterministic after an
    # interrupted/previous bind instead of failing with "file exists".
    $generatedBuild = Join-Path $source 'build'
    if (Test-Path -LiteralPath $generatedBuild -PathType Container) {
      $resolvedBuild = [IO.Path]::GetFullPath($generatedBuild)
      $resolvedSource = [IO.Path]::GetFullPath($source).TrimEnd('\')
      if ($resolvedBuild -ne "$resolvedSource\build") { throw "Refusing to clean unexpected gomobile output: $resolvedBuild" }
      [IO.Directory]::Delete($resolvedBuild, $true)
    }
    & $goBin mod edit "-require=github.com/xtls/xray-core@v0.0.0"
    & $goBin mod edit "-replace=github.com/xtls/xray-core=$xray"
    & $goBin mod edit "-replace=github.com/sagernet/sing-tun=$singTun"
    if ($LASTEXITCODE -ne 0) { throw "go mod edit failed with exit code $LASTEXITCODE" }
    # Download only the module needed by the libbox pidfd/terminal path.  A
    # full tidy is intentionally avoided: it rewrites the pinned source's
    # reproducible dependency graph on machines with a restricted proxy.
    & $goBin mod download golang.org/x/term
    if ($LASTEXITCODE -ne 0) { throw "go module download failed with exit code $LASTEXITCODE" }
    & $gomobile init
    if ($LASTEXITCODE -ne 0) { throw "gomobile init failed with exit code $LASTEXITCODE" }
    $tags = 'with_gvisor,with_quic,with_wireguard,with_utls,with_naive_outbound,with_clash_api,badlinkname,tfogo_checklinkname0,with_tailscale,ts_omit_logtail,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,with_low_memory'
    & $gomobile bind -target android -androidapi 28 -javapkg io.nekohasekai -libname box '-ldflags=-checklinkname=0' "-tags=$tags" -o $out .\experimental\libbox
    if ($LASTEXITCODE -ne 0) { throw "unified libbox gomobile bind failed with exit code $LASTEXITCODE" }
  } finally {
    Pop-Location
  }
} finally {
  $env:GOFLAGS = $previousGoFlags
  if (Test-Path -LiteralPath (Join-Path $backupDir 'go.mod') -PathType Leaf) { Copy-Item -LiteralPath (Join-Path $backupDir 'go.mod') -Destination $goMod -Force }
  if (Test-Path -LiteralPath (Join-Path $backupDir 'go.sum') -PathType Leaf) { Copy-Item -LiteralPath (Join-Path $backupDir 'go.sum') -Destination $goSum -Force }
  if (Test-Path -LiteralPath $overlay -PathType Leaf) { Remove-Item -LiteralPath $overlay -Force }
  Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
}

Require-File $out 'The unified libbox AAR was not produced.'
$size = (Get-Item -LiteralPath $out).Length
if ($size -lt 150MB) { throw "Unified AAR is unexpectedly small ($size bytes); Xray must be embedded in the same runtime." }
Write-Output "Unified libbox+Xray AAR: $out ($size bytes)"
