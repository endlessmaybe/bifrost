param(
  [switch]$WindowsOnly,
  [switch]$DeferControlSync,
  [switch]$LocalOnly,
  [string]$ReleaseAuthorityRoot = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$clients = Join-Path $root 'repos\bifrost-clients'
$releases = Join-Path $root 'releases'
$toolchains = Join-Path $root 'build-work\toolchains'
$androidSdk = Join-Path $toolchains 'android-sdk'
$dotnetPortable = Join-Path $toolchains 'dotnet\dotnet.exe'
$gradleWrapper = Join-Path $clients 'android-app\gradlew.bat'
$androidProject = Join-Path $clients 'android-app'
$windowsApp = Join-Path $clients 'windows-app\BifrostApp.csproj'
$windowsService = Join-Path $clients 'windows-service\BifrostClientService.csproj'
$windowsInstaller = Join-Path $PSScriptRoot '..\installer\BifrostSetup.csproj'
$node = (Get-Command node.exe -ErrorAction Stop).Source

function Require-File([string]$path, [string]$hint) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path. $hint" }
}

function Resolve-ReleaseAuthorityEnvironment([string]$AuthorityRoot) {
  if ([string]::IsNullOrWhiteSpace($AuthorityRoot)) {
    $AuthorityRoot = [string]$env:BIFROST_RELEASE_AUTHORITY_ROOT
  }
  if ([string]::IsNullOrWhiteSpace($AuthorityRoot)) { return }

  $authority = [IO.Path]::GetFullPath($AuthorityRoot).TrimEnd('\')
  if (-not (Test-Path -LiteralPath $authority -PathType Container)) {
    throw "Release authority root does not exist: $authority"
  }
  $rootDescriptor = Join-Path $authority 'release-root.json'
  $releasePrivate = Join-Path $authority 'release-signing-private.pem'
  $releasePublic = Join-Path $authority 'release-signing-public.pem'
  Require-File $rootDescriptor 'Provision the production release authority before packaging.'
  Require-File $releasePrivate 'Provision the production release authority before packaging.'
  Require-File $releasePublic 'Provision the production release authority before packaging.'

  # provision-release-authority.ps1 defines this immutable directory layout.
  # Accepting the authority root removes three error-prone operator path
  # arguments without weakening release-sign.mjs: the normal verify-key gate
  # still validates root ancestry, the delegated Ed25519 pair and signatures.
  if ([string]::IsNullOrWhiteSpace([string]$env:BIFROST_RELEASE_TRUST_ROOT_FILE)) {
    $env:BIFROST_RELEASE_TRUST_ROOT_FILE = $rootDescriptor
  }
  if ([string]::IsNullOrWhiteSpace([string]$env:BIFROST_RELEASE_SIGNING_PRIVATE_KEY_FILE)) {
    $env:BIFROST_RELEASE_SIGNING_PRIVATE_KEY_FILE = $releasePrivate
  }
  if ([string]::IsNullOrWhiteSpace([string]$env:BIFROST_RELEASE_SIGNING_PUBLIC_KEY_FILE)) {
    $env:BIFROST_RELEASE_SIGNING_PUBLIC_KEY_FILE = $releasePublic
  }
}

Resolve-ReleaseAuthorityEnvironment $ReleaseAuthorityRoot

function Invoke-Native([string]$label, [string]$file, [string[]]$arguments, [string]$workingDirectory) {
  Write-Output "== $label =="
  Push-Location $workingDirectory
  try {
    # Invoke nested PowerShell scripts through a fresh powershell.exe process.
    # Passing a string-array directly to a script command can bind a later
    # named argument (notably -AndroidSdk) as the preceding optional value on
    # Windows PowerShell 5.1.  -File preserves the exact named-parameter
    # contract while native executables continue to run in-process.
    if ([IO.Path]::GetExtension($file) -ieq '.ps1') {
      & (Join-Path $PSHOME $(if ($PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) -NoProfile -ExecutionPolicy Bypass -File $file @arguments
    } else {
      & $file @arguments
    }
    if ($LASTEXITCODE -ne 0) { throw "$label failed with exit code $LASTEXITCODE" }
  } finally { Pop-Location }
}

function Ensure-AndroidSigningMaterial {
  $provided = @(
    $env:BIFROST_ANDROID_KEYSTORE,
    $env:BIFROST_ANDROID_KEYSTORE_PASSWORD,
    $env:BIFROST_ANDROID_KEY_ALIAS,
    $env:BIFROST_ANDROID_KEY_PASSWORD
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  $provided = @($provided)
  if ($provided.Count -gt 0 -and $provided.Count -ne 4) {
    throw 'BIFROST_ANDROID_KEYSTORE, _KEYSTORE_PASSWORD, _KEY_ALIAS and _KEY_PASSWORD must be supplied together.'
  }
  if ($provided.Count -eq 4) {
    $resolved = [IO.Path]::GetFullPath($env:BIFROST_ANDROID_KEYSTORE)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Android signing keystore not found: $resolved" }
    $env:BIFROST_ANDROID_KEYSTORE = $resolved
    return 'operator'
  }
  throw 'Production client build is fail-closed: set BIFROST_ANDROID_KEYSTORE, BIFROST_ANDROID_KEYSTORE_PASSWORD, BIFROST_ANDROID_KEY_ALIAS and BIFROST_ANDROID_KEY_PASSWORD together. For an explicitly unsigned local APK use android-app\gradlew.bat assembleRelease directly; this release script never creates or uses a local signing key.'
}

function Ensure-ProductionControlOrigin {
  $raw = [string]$env:BIFROST_CONTROL_BASE_URL
  if ([string]::IsNullOrWhiteSpace($raw)) {
    throw 'Production client build is fail-closed: BIFROST_CONTROL_BASE_URL must be the canonical public HTTPS client-edge origin.'
  }
  $uri = $null
  if (-not [Uri]::TryCreate($raw.Trim(), [UriKind]::Absolute, [ref]$uri) -or
      $uri.Scheme -ne [Uri]::UriSchemeHttps -or $uri.Port -ne 443 -or
      -not [string]::IsNullOrEmpty($uri.UserInfo) -or
      $uri.AbsolutePath -ne '/' -or -not [string]::IsNullOrEmpty($uri.Query) -or -not [string]::IsNullOrEmpty($uri.Fragment) -or
      [Uri]::CheckHostName($uri.Host) -ne [UriHostNameType]::Dns -or
      $uri.Host -eq 'localhost' -or $uri.Host.EndsWith('.localhost', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BIFROST_CONTROL_BASE_URL must be a canonical public https://DNS-name origin on port 443 with no path, query, fragment, credentials, localhost, or IP literal.'
  }
  $canonical = $uri.GetLeftPart([UriPartial]::Authority).TrimEnd('/')
  # The apex host is the immutable release-blob/CDN surface. Authenticated
  # enrollment, device sessions and release-manifest discovery are served by
  # the dedicated client edge.  Pin production promotion builds to that exact
  # authority so a valid-looking but unrouted HTTPS origin cannot strand an
  # already-installed client again.
  if (-not [string]::Equals($canonical, 'https://edge.bifrostlog.com', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Production client build is fail-closed: BIFROST_CONTROL_BASE_URL must be https://edge.bifrostlog.com.'
  }
  return 'https://edge.bifrostlog.com'
}

function Ensure-ReleaseTrustRoot {
  $raw = [string]$env:BIFROST_RELEASE_TRUST_ROOT_FILE
  if ([string]::IsNullOrWhiteSpace($raw)) {
    throw 'Production client build is fail-closed: BIFROST_RELEASE_TRUST_ROOT_FILE must point to the offline production release trust-root ceremony artifact.'
  }
  $resolved = [IO.Path]::GetFullPath($raw)
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "Production release trust-root ceremony artifact not found: $resolved"
  }
  return $resolved
}

function Release-KeyArguments {
  $arguments = @()
  if (-not [string]::IsNullOrWhiteSpace([string]$env:BIFROST_RELEASE_SIGNING_PRIVATE_KEY_FILE)) {
    $private = [IO.Path]::GetFullPath($env:BIFROST_RELEASE_SIGNING_PRIVATE_KEY_FILE)
    if (-not (Test-Path -LiteralPath $private -PathType Leaf)) { throw "Release signing private key not found: $private" }
    $arguments += @('--private-key-file', $private)
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$env:BIFROST_RELEASE_SIGNING_PUBLIC_KEY_FILE)) {
    $public = [IO.Path]::GetFullPath($env:BIFROST_RELEASE_SIGNING_PUBLIC_KEY_FILE)
    if (-not (Test-Path -LiteralPath $public -PathType Leaf)) { throw "Release signing public key not found: $public" }
    $arguments += @('--public-key-file', $public)
  }
  return $arguments
}

function Assert-StableReleaseVersionIsNew([string]$Version) {
  $channel = if ([string]::IsNullOrWhiteSpace([string]$env:BIFROST_RELEASE_CHANNEL)) { 'stable' } else { [string]$env:BIFROST_RELEASE_CHANNEL }
  if (-not [string]::Equals($channel, 'stable', [StringComparison]::OrdinalIgnoreCase)) { return }

  $pointerPath = Join-Path $releases 'current.json'
  if (-not (Test-Path -LiteralPath $pointerPath -PathType Leaf)) { return }
  $pointer = Get-Content -LiteralPath $pointerPath -Raw -Encoding UTF8 | ConvertFrom-Json
  $generationName = [string]$pointer.generation
  if ([string]$pointer.format -ne 'BIFROST-RELEASE-CURRENT-1' -or $generationName -notmatch '^seq-[1-9][0-9]{0,15}-[A-Za-z0-9._-]{1,128}$') {
    throw 'Existing signed release pointer is invalid.'
  }

  $generationParent = [IO.Path]::GetFullPath((Join-Path $releases 'generations')).TrimEnd('\') + '\'
  $generation = [IO.Path]::GetFullPath((Join-Path $generationParent $generationName))
  if (-not $generation.StartsWith($generationParent, [StringComparison]::OrdinalIgnoreCase) -or
      -not (Test-Path -LiteralPath $generation -PathType Container)) {
    throw 'Existing signed release generation is invalid.'
  }
  $manifestPath = Join-Path $generation 'RELEASE-MANIFEST.json'
  Require-File $manifestPath 'Existing signed release manifest is missing.'
  $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
  if (-not [string]::Equals([string]$manifest.channel, 'stable', [StringComparison]::OrdinalIgnoreCase)) { return }

  $metadataArtifacts = @($manifest.build.artifacts | Where-Object {
    [string]$_.platform -eq 'windows' -and [string]$_.arch -eq 'x64' -and [string]$_.kind -eq 'metadata'
  })
  if ($metadataArtifacts.Count -ne 1) { throw 'Existing signed stable release metadata is invalid.' }
  $relativeMetadata = ([string]$metadataArtifacts[0].path).Replace('/', '\')
  $metadataPath = [IO.Path]::GetFullPath((Join-Path $generation $relativeMetadata))
  $generationPrefix = $generation.TrimEnd('\') + '\'
  if (-not $metadataPath.StartsWith($generationPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Existing signed stable release metadata path is invalid.'
  }
  Require-File $metadataPath 'Existing signed stable release install metadata is missing.'
  $publishedVersion = [string](Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json).version
  if ($publishedVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Existing signed stable release version is invalid.' }
  if ([string]::Equals($publishedVersion, $Version, [StringComparison]::Ordinal)) {
    throw "BF-RELEASE-VERSION-REUSED: stable version $Version is already published. Bump BifrostApp.csproj before creating another release; if only packaging was interrupted, run resume-windows-release-packaging.ps1 for the existing signed generation."
  }
}

New-Item -ItemType Directory -Force -Path $releases | Out-Null

if (-not $WindowsOnly) {
  if (-not (Test-Path -LiteralPath $androidSdk -PathType Container)) {
    throw "Android SDK not found at $androidSdk. Install the pinned SDK with the local toolchain setup documented in README."
  }
  Require-File $gradleWrapper 'The Android Gradle wrapper must be present.'
  $env:ANDROID_SDK_ROOT = $androidSdk
  $env:ANDROID_HOME = $androidSdk
}
$androidSigningScope = if ($WindowsOnly) { 'not-applicable-windows-only' } else { Ensure-AndroidSigningMaterial }
$androidSigningKeyAlias = if ($WindowsOnly) { 'not-applicable' } else { [string]$env:BIFROST_ANDROID_KEY_ALIAS }
$productionControlOrigin = Ensure-ProductionControlOrigin
$releaseMirrorHost = [string]$env:BIFROST_RELEASE_MIRROR_SSH_HOST
if (-not $LocalOnly -and ([string]::IsNullOrWhiteSpace($releaseMirrorHost) -or $releaseMirrorHost -notmatch '^[A-Za-z0-9._-]{1,253}$')) {
  throw 'Production client build is fail-closed: BIFROST_RELEASE_MIRROR_SSH_HOST must name the configured release-mirror SSH host.'
}
$releaseTrustRoot = Ensure-ReleaseTrustRoot
$releaseKeyArgs = @(Release-KeyArguments)
$env:BIFROST_CONTROL_BASE_URL = $productionControlOrigin
# The native clients embed this signer.  Validate the existing private/public
# pair and its derived key against that same trust anchor before any release
# artifact is built; never silently generate or replace a signing key here.
Invoke-Native 'Release signer preflight' $node (@((Join-Path $PSScriptRoot 'release-sign.mjs'), 'verify-key', '--root', $root, '--root-public-key-file', $releaseTrustRoot) + $releaseKeyArgs) $root

# Build into a fresh immutable payload generation.  A running/AV-scanned prior
# release must never force the release job to overwrite a locked executable.
# The signed artifact path may be versioned while install_path remains stable.
if ([string]::IsNullOrWhiteSpace($env:BIFROST_RELEASE_SEQUENCE)) { $env:BIFROST_RELEASE_SEQUENCE = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() }
if ($env:BIFROST_RELEASE_SEQUENCE -notmatch '^[1-9][0-9]{0,15}$') { throw 'BIFROST_RELEASE_SEQUENCE must be a positive decimal safe release sequence.' }
$parsedReleaseSequence = 0L
if (-not [long]::TryParse($env:BIFROST_RELEASE_SEQUENCE, [ref]$parsedReleaseSequence) -or $parsedReleaseSequence -gt 9007199254740991L) { throw 'BIFROST_RELEASE_SEQUENCE is outside the safe integer range.' }
$generationRoot = Join-Path $releases 'generations'
if (Test-Path -LiteralPath $generationRoot -PathType Container) {
  $reused = @(Get-ChildItem -LiteralPath $generationRoot -Directory -Filter "seq-$parsedReleaseSequence-*" -ErrorAction SilentlyContinue)
  if ($reused.Count -gt 0) {
    throw "BIFROST_RELEASE_SEQUENCE $parsedReleaseSequence has already been published. Release sequences are anti-equivocation identities and must never be reused."
  }
}
$payloadGeneration = "payload-$($env:BIFROST_RELEASE_SEQUENCE)-$PID"
$windowsAppRelease = Join-Path $releases "windows-app\$payloadGeneration"
$windowsServiceRelease = Join-Path $releases "windows-service\$payloadGeneration"
$windowsInstallerRelease = Join-Path $releases "windows-installer\$payloadGeneration"

# Freeze the exact corresponding source before the first compiler/native build
# runs.  The final SOURCE-BUNDLE must come from these bytes, not from whatever
# happens to be in a mutable checkout after a long build finishes.
$sourceSnapshotBase = if (-not [string]::IsNullOrWhiteSpace([string]$env:BIFROST_SOURCE_SNAPSHOT_DIR)) {
  [IO.Path]::GetFullPath([string]$env:BIFROST_SOURCE_SNAPSHOT_DIR)
} else {
  Join-Path $root 'build-work\source-snapshots'
}
$sourceSnapshotDirectory = Join-Path $sourceSnapshotBase $payloadGeneration
$sourceSnapshotManifest = Join-Path $sourceSnapshotDirectory 'source-snapshot.json'
New-Item -ItemType Directory -Force -Path $sourceSnapshotBase | Out-Null
Invoke-Native 'Freeze corresponding source snapshot' $node @(
  (Join-Path $PSScriptRoot 'source-bundle.mjs'), 'snapshot',
  '--root', $root,
  '--output', $sourceSnapshotDirectory
) $root
Require-File $sourceSnapshotManifest 'The pre-build source snapshot was not created.'

$androidArtifacts = @()
$androidAbis = @('arm64-v8a', 'armeabi-v7a', 'x86_64')
if (-not $WindowsOnly) {
  # Build the pinned sing-box/libbox and Xray transport into one gomobile
  # runtime. Keeping a single AAR avoids duplicate go.Seq/libgojni loaders.
  Invoke-Native 'Unified Android libbox + Xray runtime' (Join-Path $PSScriptRoot 'build-unified-libbox.ps1') @(
    '-RepoRoot', $root,
    '-ReusePinnedRuntime',
    '-GoRoot', (Join-Path $toolchains 'go'),
    '-AndroidSdk', $androidSdk,
    '-AndroidNdk', (Join-Path $androidSdk 'ndk\28.0.13004108')
  ) $root
  Invoke-Native 'Android signed release APK' $gradleWrapper @('--no-daemon', 'assembleRelease', "-PreleaseTrustRootFile=$releaseTrustRoot") $androidProject
  $androidRelease = Join-Path $releases 'android'
  New-Item -ItemType Directory -Force -Path $androidRelease | Out-Null
  foreach ($abi in $androidAbis) {
    $releaseDir = Join-Path $androidProject 'build\outputs\apk\release'
    $candidates = @(Get-ChildItem -LiteralPath $releaseDir -Filter "*-$abi-release.apk" -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -ne 1) { throw "Expected exactly one $abi release APK, found $($candidates.Count)." }
    $androidArtifact = Join-Path $androidRelease ("BifrostAndroid-$abi-release.apk")
    Copy-Item -LiteralPath $candidates[0].FullName -Destination $androidArtifact -Force
    $androidArtifacts += [ordered]@{ Id = "android-$abi-apk"; Path = $androidArtifact; Platform = 'android'; Arch = $abi; Kind = 'apk' }
  }
  foreach ($legacy in @('BifrostAndroid-debug.apk', 'BifrostAndroid-release.apk')) {
    $legacyPath = Join-Path $androidRelease $legacy
    if (Test-Path -LiteralPath $legacyPath -PathType Leaf) { Remove-Item -LiteralPath $legacyPath -Force }
  }
}

$dotnet = if (Test-Path -LiteralPath $dotnetPortable -PathType Leaf) { $dotnetPortable } else { (Get-Command dotnet.exe -ErrorAction Stop).Source }
$versionProject = [xml](Get-Content -LiteralPath $windowsApp -Raw)
$declaredClientVersion = [string]($versionProject.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version
$localVersionOverride = [string]$env:BIFROST_LOCAL_BUILD_VERSION_OVERRIDE
if (-not [string]::IsNullOrWhiteSpace($localVersionOverride) -and -not $LocalOnly) {
  throw 'BIFROST_LOCAL_BUILD_VERSION_OVERRIDE is accepted only with -LocalOnly.'
}
$clientVersion = if ($LocalOnly -and -not [string]::IsNullOrWhiteSpace($localVersionOverride)) {
  $localVersionOverride.Trim()
} else {
  $declaredClientVersion
}
if ($clientVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Windows client version must use numeric major.minor.patch form in BifrostApp.csproj.' }
Assert-StableReleaseVersionIsNew $clientVersion
$clientVersionProperties = @(
  "-p:Version=$clientVersion",
  "-p:AssemblyVersion=$clientVersion.0",
  "-p:FileVersion=$clientVersion.0",
  "-p:InformationalVersion=$clientVersion"
)
$releaseTrustArgs = @("-p:BifrostReleaseTrustRootFile=$releaseTrustRoot", '-p:BifrostReleaseTrustRootTestOnly=false')
$windowsAppAuthorityArgs = @('-p:BifrostLocalEvaluation=false', "-p:BifrostTrustedControlOrigin=$productionControlOrigin", '-p:BifrostRequireTrustedControlOrigin=true')
# The portable SDK's compiler server can retain a memory-mapped intermediate
# DLL after a cancelled publish.  Disable server reuse for release artifacts so
# a retry cannot inherit that stale lock or leave one for the next promotion.
$releaseCompilationArgs = @('-p:UseSharedCompilation=false')
Invoke-Native 'Windows WPF self-contained x64' $dotnet (@('publish', $windowsApp, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true', '-p:PublishTrimmed=false', '-p:EnableCompressionInSingleFile=false', '-o', $windowsAppRelease) + $releaseCompilationArgs + $clientVersionProperties + $windowsAppAuthorityArgs + $releaseTrustArgs) $root
Invoke-Native 'Windows service self-contained x64' $dotnet (@('publish', $windowsService, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:PublishTrimmed=false', '-p:EnableCompressionInSingleFile=false', '-p:BifrostLocalEvaluation=false', '-o', $windowsServiceRelease) + $releaseCompilationArgs + $clientVersionProperties + $releaseTrustArgs) $root
Invoke-Native 'Windows self-contained installer' $dotnet (@('publish', $windowsInstaller, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true', '-p:PublishTrimmed=false', '-p:EnableCompressionInSingleFile=true', '-o', $windowsInstallerRelease) + $releaseCompilationArgs + $clientVersionProperties + $releaseTrustArgs) $root

# BifrostSetup.exe is the manifest-bound *inner* installer/update helper.  It
# is intentionally kept only inside the immutable windows-installer/payload-*
# tree: by itself it does not carry RELEASE-ENVELOPE.json or the signed
# payload, so exposing a root-level copy makes a perfectly valid helper look
# like a standalone user installer and fails with BF-SETUP-ENVELOPE when a
# user double-clicks it.  The only human-facing Windows installer is the
# self-contained Bifrost-Offline-Setup-*-Windows-x64.exe built below.

# Desktop clients are self-contained: the selected core is never discovered
# through an environment variable on a production install.  The pinned
# TEST-ONLY/toolchain downloads are copied into both versioned component trees
# and accompanied by a per-component digest manifest consumed by the service
# before it starts any process.
$coreRoot = Join-Path $toolchains 'cores'
$desktopCoreSources = @{
  'mihomo.exe' = Join-Path $coreRoot 'mihomo\1.19.30\windows-amd64-compatible\mihomo.exe'
}
$desktopRuleSources = @(
  @{ Id = 'geosite'; Name = 'GeoSite.dat'; Source = (Join-Path $coreRoot 'mihomo-rules\2026-09-22\geosite.dat'); Version = 'meta-rules-dat-release-393387661'; Sha256 = '9ac232ceb7e350f31e05c0d1a973a4b12eab96726f7fc1b59cb052bc5c6519ca' },
  @{ Id = 'geoip'; Name = 'geoip.metadb'; Source = (Join-Path $coreRoot 'mihomo-rules\2026-09-22\geoip.metadb'); Version = 'meta-rules-dat-release-393387661'; Sha256 = '6eef2fedc2dae7091c112be13895968135ec01e702df2f5b4b1161b07d714720' }
)
$componentReleaseDirs = @{ 'windows-app' = $windowsAppRelease; 'windows-service' = $windowsServiceRelease }
foreach ($component in @('windows-app', 'windows-service')) {
  $componentCoreRoot = Join-Path $componentReleaseDirs[$component] 'cores'
  New-Item -ItemType Directory -Force -Path $componentCoreRoot | Out-Null
  $coreEntries = @()
  foreach ($coreName in $desktopCoreSources.Keys) {
    Require-File $desktopCoreSources[$coreName] 'Run setup-core-binaries.ps1 -Platform desktop first.'
    $destination = Join-Path $componentCoreRoot $coreName
    Copy-Item -LiteralPath $desktopCoreSources[$coreName] -Destination $destination -Force
    $coreEntries += [ordered]@{ path = $coreName; version = '1.19.30'; sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant(); bytes = (Get-Item -LiteralPath $destination).Length }
  }
  foreach ($rule in $desktopRuleSources) {
    Require-File $rule.Source "Pinned Mihomo geodata is missing: $($rule.Name)"
    $actualRuleHash = (Get-FileHash -LiteralPath $rule.Source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualRuleHash -ne $rule.Sha256) { throw "Pinned Mihomo geodata digest mismatch: $($rule.Name)" }
    $destination = Join-Path $componentCoreRoot $rule.Name
    Copy-Item -LiteralPath $rule.Source -Destination $destination -Force
    $coreEntries += [ordered]@{ path = $rule.Name; version = $rule.Version; sha256 = $rule.Sha256; bytes = (Get-Item -LiteralPath $destination).Length }
  }
  [ordered]@{ format = 'BIFROST-CORE-MANIFEST-2'; platform = 'windows-x64'; generated_at = (Get-Date).ToUniversalTime().ToString('o'); artifacts = $coreEntries } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $componentCoreRoot 'CORE-MANIFEST.json') -Encoding UTF8
}

& {
  $evidenceScript = Join-Path $PSScriptRoot 'prepare-windows-release-evidence.mjs'
  Invoke-Native 'Windows release evidence' $node @($evidenceScript, '--root', $root) $root
  if (-not $WindowsOnly) {
    Invoke-Native 'Android release evidence' $node @((Join-Path $PSScriptRoot 'prepare-android-release-evidence.mjs'), '--root', $root) $root
  }
  $env:BIFROST_CORE_PROVENANCE = Join-Path $root 'build-inputs\core-provenance.json'
  $env:BIFROST_BUILD_INPUT_MANIFEST = Join-Path $root 'build-inputs\build-input-manifest.json'
  $env:BIFROST_DEPENDENCY_LICENSE_MANIFEST = Join-Path $root 'build-inputs\dependency-license-manifest.json'
}

$artifacts = @()
$artifactDefinitions = @()
$artifactDefinitions += $androidArtifacts
$artifactDefinitions += @{ Path = (Join-Path $windowsAppRelease 'Bifrost.exe'); Platform = 'windows'; Arch = 'x64'; Kind = 'exe'; InstallPath = 'Bifrost.exe' }
$artifactDefinitions += @{ Path = (Join-Path $windowsServiceRelease 'BifrostClientService.exe'); Platform = 'windows'; Arch = 'x64'; Kind = 'service-exe'; InstallPath = 'BifrostClientService.exe' }
$artifactDefinitions += @{ Path = (Join-Path $windowsInstallerRelease 'BifrostSetup.exe'); Platform = 'windows'; Arch = 'x64'; Kind = 'installer'; InstallPath = 'BifrostSetup.exe' }
foreach ($coreName in $desktopCoreSources.Keys) {
  $artifactDefinitions += @{ Path = (Join-Path $windowsServiceRelease "cores\$coreName"); Platform = 'windows'; Arch = 'x64'; Kind = 'core'; InstallPath = "cores/$coreName" }
}
foreach ($rule in $desktopRuleSources) {
  $artifactDefinitions += @{ Id = $rule.Id; Path = (Join-Path $windowsServiceRelease "cores\$($rule.Name)"); Platform = 'windows'; Arch = 'x64'; Kind = 'core'; InstallPath = "cores/$($rule.Name)" }
}
$artifactDefinitions += @{ Path = (Join-Path $windowsServiceRelease 'cores\CORE-MANIFEST.json'); Platform = 'windows'; Arch = 'x64'; Kind = 'core-manifest'; InstallPath = 'cores/CORE-MANIFEST.json' }
$releaseContract = Get-Content -LiteralPath (Join-Path $clients 'config-contracts\release-contract-v1.json') -Raw | ConvertFrom-Json
$rootDescriptor = Get-Content -LiteralPath $releaseTrustRoot -Raw | ConvertFrom-Json
$installMetadataPath = Join-Path $windowsInstallerRelease 'install-metadata.json'
$installMetadata = [ordered]@{
  format = 'BIFROST-INSTALL-METADATA-1'
  product = 'Bifrost'
  version = $clientVersion
  platform = 'windows'
  arch = 'x64'
  release_contract = [string]$releaseContract.contract_version
  control_origin = $productionControlOrigin
  trust_root_key_id = [string]$rootDescriptor.key_id
  trust_root_fingerprint = [string]$rootDescriptor.fingerprint
} | ConvertTo-Json -Depth 4
# Windows PowerShell 5.1's `-Encoding UTF8` writes a BOM. The release signer
# deliberately requires a canonical UTF-8 round trip, so write this signed
# metadata artifact explicitly as UTF-8 without BOM and with one LF terminator.
[IO.File]::WriteAllText($installMetadataPath, ($installMetadata + "`n"), [Text.UTF8Encoding]::new($false))
$artifactDefinitions += @{ Id = 'install-metadata'; Path = $installMetadataPath; Platform = 'windows'; Arch = 'x64'; Kind = 'metadata'; InstallPath = 'install-metadata.json' }
foreach ($definition in $artifactDefinitions) {
  $artifactPath = $definition.Path
  Require-File $artifactPath 'The build output is incomplete.'
  $item = Get-Item -LiteralPath $artifactPath
  $relative = $item.FullName.Substring($releases.TrimEnd('\').Length + 1).Replace('\', '/')
  $declaredInstallPath = $definition['InstallPath']
  $installPath = if ($null -ne $declaredInstallPath -and -not [string]::IsNullOrWhiteSpace([string]$declaredInstallPath)) { [string]$declaredInstallPath } else { [IO.Path]::GetFileName($item.FullName) }
  $artifactId = if ($definition.Contains('Id') -and -not [string]::IsNullOrWhiteSpace([string]$definition['Id'])) { [string]$definition['Id'] } else { switch ([string]$definition.Kind) { 'exe' { 'app'; break } 'service-exe' { 'service'; break } 'installer' { 'installer'; break } 'core-manifest' { 'core-manifest'; break } 'core' { [IO.Path]::GetFileNameWithoutExtension($item.Name); break } default { [IO.Path]::GetFileNameWithoutExtension($item.Name) } } }
  $artifacts += [ordered]@{ id = $artifactId; path = $relative; install_path = $installPath; platform = $definition.Platform; arch = $definition.Arch; kind = $definition.Kind; bytes = $item.Length; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{
  format = 'BIFROST-BUILD-MANIFEST-2'
  generated_at = (Get-Date).ToUniversalTime().ToString('o')
  configuration = 'Release/self-contained where supported'
  android_signing_scope = $androidSigningScope
  android_signing_key_alias = $androidSigningKeyAlias
  artifact_root = 'releases'
  artifacts = $artifacts
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $releases 'BUILD-MANIFEST.json') -Encoding UTF8
Write-Output "Build completed. Manifest: $(Join-Path $releases 'BUILD-MANIFEST.json')"
# Use the explicit sequence selected before compilation for both the build
# payload directory and the later signed release envelope.
$buildManifestPath = Join-Path $releases 'BUILD-MANIFEST.json'
$sourceManifestPath = Join-Path $releases 'source-bundle-manifest.json'
$sourceArchivePath = Join-Path $releases 'SOURCE-BUNDLE.tar'
$dependencyLicenseManifestPath = if ($env:BIFROST_DEPENDENCY_LICENSE_MANIFEST) { [IO.Path]::GetFullPath($env:BIFROST_DEPENDENCY_LICENSE_MANIFEST) } else { Join-Path $root 'build-inputs\dependency-license-manifest.json' }
$sourceArgs = @((Join-Path $PSScriptRoot 'source-bundle.mjs'), 'build', '--root', $root, '--manifest', $sourceManifestPath, '--archive', $sourceArchivePath)
$sourceArgs += @('--source-snapshot', $sourceSnapshotManifest)
if ($env:BIFROST_CORE_PROVENANCE) { $sourceArgs += @('--core-provenance', [IO.Path]::GetFullPath($env:BIFROST_CORE_PROVENANCE)) }
if ($env:BIFROST_BUILD_INPUT_MANIFEST) { $sourceArgs += @('--build-input-manifest', [IO.Path]::GetFullPath($env:BIFROST_BUILD_INPUT_MANIFEST)) }
$sourceArgs += @('--dependency-license-manifest', $dependencyLicenseManifestPath)
Invoke-Native 'Corresponding GPL source bundle' $node $sourceArgs $root
$sbomArgs = @((Join-Path $PSScriptRoot 'generate-sbom.mjs'), 'generate', '--root', $root, '--releases', $releases, '--draft-manifest', $buildManifestPath, '--source-manifest', $sourceManifestPath)
if ($env:BIFROST_CORE_PROVENANCE) { $sbomArgs += @('--core-provenance', [IO.Path]::GetFullPath($env:BIFROST_CORE_PROVENANCE)) }
if ($env:BIFROST_BUILD_INPUT_MANIFEST) { $sbomArgs += @('--build-input-manifest', [IO.Path]::GetFullPath($env:BIFROST_BUILD_INPUT_MANIFEST)) }
$sbomArgs += @('--dependency-license-manifest', $dependencyLicenseManifestPath)
Invoke-Native 'SBOM and license inventory' $node $sbomArgs $root
 $signArgs = @((Join-Path $PSScriptRoot 'release-sign.mjs'), 'create', '--root', $root, '--root-public-key-file', $releaseTrustRoot, '--draft-manifest', $buildManifestPath) + $releaseKeyArgs
if ($env:BIFROST_CORE_PROVENANCE) { $signArgs += @('--core-provenance', [IO.Path]::GetFullPath($env:BIFROST_CORE_PROVENANCE)) }
if ($env:BIFROST_BUILD_INPUT_MANIFEST) { $signArgs += @('--build-input-manifest', [IO.Path]::GetFullPath($env:BIFROST_BUILD_INPUT_MANIFEST)) }
$signArgs += @('--dependency-license-manifest', $dependencyLicenseManifestPath)
Invoke-Native 'Release manifest signing' $node $signArgs $root
Invoke-Native 'Release signature verification' $node (@((Join-Path $PSScriptRoot 'release-sign.mjs'), 'verify', '--root', $root, '--root-public-key-file', $releaseTrustRoot) + $releaseKeyArgs) $root

# `releases` is the machine-consumed immutable publication tree. `dist` has one
# human-facing deliverable: the self-contained offline installer built below.
# Keeping staging payloads or legacy fixed filenames beside current.json would
# make ReleaseVerifier correctly reject the update tree as ambiguous.
$currentPointerPath = Join-Path $releases 'current.json'
Require-File $currentPointerPath 'Release signing completed without current.json.'
$currentPointer = Get-Content -LiteralPath $currentPointerPath -Raw | ConvertFrom-Json
if ($currentPointer.format -ne 'BIFROST-RELEASE-CURRENT-1' -or [string]::IsNullOrWhiteSpace([string]$currentPointer.generation)) {
  throw 'Signed release pointer is invalid.'
}
$currentGeneration = Join-Path $generationRoot ([string]$currentPointer.generation)
$currentManifestPath = Join-Path $currentGeneration 'RELEASE-MANIFEST.json'
Require-File $currentManifestPath 'Signed generation is missing RELEASE-MANIFEST.json.'
$currentManifest = Get-Content -LiteralPath $currentManifestPath -Raw | ConvertFrom-Json
if (-not $LocalOnly) { Invoke-Native 'Release mirror publication' (Join-Path $PSHOME $(if ($PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) @(
  '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
  (Join-Path $PSScriptRoot 'publish-release-mirror.ps1'), '-Root', $root, '-SshHost', $releaseMirrorHost,
  '-ReleaseTrustRootFile', $releaseTrustRoot
) $root }

# The signed online release is already complete once its immutable generation
# has verified and the artifact mirror has accepted it.  Do not make client
# update discovery depend on the later human-facing offline wrapper build: an
# interrupted wrapper publish must never leave Control serving an older
# current.json while a newer client is already in circulation.  Collapse the
# source workspace back to the immutable release surface now, verify that exact
# surface, then atomically advance the protected Control supervisor snapshot.
foreach ($entry in @(Get-ChildItem -LiteralPath $releases -Force)) {
  if ($entry.Name -in @('current.json', 'generations')) { continue }
  Remove-Item -LiteralPath $entry.FullName -Recurse -Force
}
Invoke-Native 'Online release post-clean verification' $node (@((Join-Path $PSScriptRoot 'release-sign.mjs'), 'verify', '--root', $root, '--root-public-key-file', $releaseTrustRoot) + $releaseKeyArgs) $root
Invoke-Native 'Online live release surface verification' $node @((Join-Path $PSScriptRoot 'verify-release-surface.mjs'), '--root', $root) $root
if (-not $LocalOnly -and -not $DeferControlSync) { Invoke-Native 'Online Control runtime release synchronization' (Join-Path $PSHOME $(if ($PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) @(
  '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
  (Join-Path $PSScriptRoot 'sync-control-release.ps1'), '-Root', $root
) $root }

$distRoot = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $distRoot | Out-Null

# Build one explicit redistributable package from the exact signed generation.
# The single-file wrapper locates the one manifest-bound installer inside its
# versioned artifact directory. Do not duplicate the 100+ MB self-contained
# installer at the package root: ZIP compresses duplicate entries separately
# and the redundant alias materially bloats every offline setup. All payload
# paths remain exactly as declared by the signed manifest so the shipping
# installer can perform its own independent verification before touching
# Program Files or SCM.
$redistributableNext = Join-Path $distRoot "offline-payload.next-$PID"
$redistributableZipNext = Join-Path $distRoot "offline-payload.next-$PID.zip"
$offlineSetupWork = Join-Path $distRoot "offline-setup.next-$PID"
try {
Remove-Item -LiteralPath $redistributableNext -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $redistributableZipNext -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $redistributableNext | Out-Null
foreach ($artifact in @($currentManifest.build.artifacts)) {
  if ([string]$artifact.platform -ne 'windows' -or [string]$artifact.arch -notin @('x64', 'any')) { continue }
  if ([string]$artifact.kind -notin @('exe', 'service-exe', 'installer', 'core', 'core-manifest', 'metadata', 'source', 'notice')) { continue }
  $source = Join-Path $currentGeneration ([string]$artifact.path).Replace('/', '\')
  Require-File $source "Signed redistributable artifact is missing: $($artifact.path)"
  $destination = Join-Path $redistributableNext ([string]$artifact.path).Replace('/', '\')
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
  Copy-Item -LiteralPath $source -Destination $destination -Force
}
foreach ($sidecar in @('RELEASE-MANIFEST.json', 'RELEASE-MANIFEST.sig', 'RELEASE-ENVELOPE.json', 'SBOM.json', 'source-bundle-manifest.json')) {
  $source = Join-Path $currentGeneration $sidecar
  Require-File $source "Signed redistributable is missing $sidecar."
  Copy-Item -LiteralPath $source -Destination (Join-Path $redistributableNext $sidecar) -Force
}
$dependencyEvidence = Join-Path $currentGeneration 'build-inputs\dependency-license-manifest.json'
Require-File $dependencyEvidence 'Signed redistributable is missing dependency license evidence.'
$dependencyDestination = Join-Path $redistributableNext 'build-inputs\dependency-license-manifest.json'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dependencyDestination) | Out-Null
Copy-Item -LiteralPath $dependencyEvidence -Destination $dependencyDestination -Force

$signedInstallerArtifact = @($currentManifest.build.artifacts | Where-Object {
  [string]$_.platform -eq 'windows' -and [string]$_.arch -eq 'x64' -and [string]$_.kind -eq 'installer'
})
if ($signedInstallerArtifact.Count -ne 1) { throw 'Signed redistributable must contain exactly one Windows x64 installer.' }
$signedInstallerInPackage = Join-Path $redistributableNext ([string]$signedInstallerArtifact[0].path).Replace('/', '\')
Require-File $signedInstallerInPackage 'Redistributable package is missing the signed installer payload.'
# BifrostSetup is a WinExe. Windows PowerShell does not reliably wait for a
# GUI-subsystem native executable invoked with `&`, which previously allowed
# packaging to continue before self-verification had actually exited. Use an
# explicit waited process and check its real exit code before publishing the
# directory/ZIP.
Write-Output '== Redistributable installer self-verification =='
$quotedRedistributableRoot = '"' + $redistributableNext + '"'
$redistributableVerify = Start-Process -FilePath $signedInstallerInPackage -ArgumentList @('--verify', '--package-root', $quotedRedistributableRoot) -Wait -PassThru -NoNewWindow
if ($redistributableVerify.ExitCode -ne 0) { throw "Redistributable installer self-verification failed with exit code $($redistributableVerify.ExitCode)" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($redistributableNext, $redistributableZipNext, [IO.Compression.CompressionLevel]::Optimal, $false)

# Produce a single-file offline setup wrapper after the signed generation and
# exact temporary payload ZIP exists. The wrapper only selects a custom local
# install directory and extracts/launches the signed inner installer; the inner
# installer still performs the authoritative envelope, artifact and rollback
# verification before any privileged system mutation.
$offlineSetupProject = Join-Path $PSScriptRoot '..\redistributable-launcher\BifrostOfflineSetup.csproj'
$offlineSetupName = "Bifrost-Offline-Setup-$clientVersion-r$parsedReleaseSequence-Windows-x64.exe"
$offlineSetupPath = Join-Path $distRoot $offlineSetupName
$permanentWindowsBaselineName = 'Bifrost-Offline-Setup-2.1.44-r1788324491-Windows-x64.exe'
Remove-Item -LiteralPath $offlineSetupWork -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $offlineSetupWork | Out-Null
Invoke-Native 'Single-file offline setup wrapper' $dotnet (@(
  'publish', $offlineSetupProject,
  '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
  '-p:PublishSingleFile=true', '-p:PublishTrimmed=false', '-p:EnableCompressionInSingleFile=true', '-p:UseSharedCompilation=false',
  "-p:BifrostPayloadZip=$redistributableZipNext",
  "-p:BifrostReleaseSequence=$parsedReleaseSequence"
) + $clientVersionProperties + @(
  '-o', $offlineSetupWork
)) $root
$offlineSetupBuilt = Join-Path $offlineSetupWork 'BifrostOfflineSetup.exe'
Require-File $offlineSetupBuilt 'Offline setup wrapper build did not produce BifrostOfflineSetup.exe.'
Write-Output '== Offline setup embedded-payload verification =='
$offlineIdentityPath = Join-Path $offlineSetupWork 'verified-identity.json'
$quotedOfflineIdentityPath = '"' + $offlineIdentityPath + '"'
$offlineVerify = Start-Process -FilePath $offlineSetupBuilt -ArgumentList @('--verify', '--identity-file', $quotedOfflineIdentityPath) -Wait -PassThru -NoNewWindow
if ($offlineVerify.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $offlineIdentityPath -PathType Leaf)) { throw "Offline setup wrapper verification failed with exit code $($offlineVerify.ExitCode)" }
$offlineIdentity = Get-Content -LiteralPath $offlineIdentityPath -Raw | ConvertFrom-Json
$signedManifestDigest = (Get-FileHash -LiteralPath $currentManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$signedSignatureDigest = (Get-FileHash -LiteralPath (Join-Path $currentGeneration 'RELEASE-MANIFEST.sig') -Algorithm SHA256).Hash.ToLowerInvariant()
if ([string]$offlineIdentity.format -ne 'BIFROST-OFFLINE-IDENTITY-1' -or
    [long]$offlineIdentity.release_sequence -ne $parsedReleaseSequence -or
    [string]$offlineIdentity.version -ne $clientVersion -or
    [string]$offlineIdentity.manifest_sha256 -ne $signedManifestDigest -or
    [string]$offlineIdentity.signature_sha256 -ne $signedSignatureDigest) {
  throw 'Offline setup wrapper embedded identity does not match the signed current generation.'
}
Remove-Item -LiteralPath $offlineIdentityPath -Force
if ($LocalOnly) {
  Copy-Item -LiteralPath $offlineSetupBuilt -Destination $offlineSetupPath -Force
  Write-Output "Local-only offline installer (not published): $offlineSetupPath"
} else {
  Invoke-Native 'Authenticated offline installer publication' (Join-Path $PSHOME $(if ($PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
    (Join-Path $PSScriptRoot 'publish-offline-installer.ps1'),
    '-Root', $root, '-BuiltInstallerPath', $offlineSetupBuilt, '-FinalInstallerPath', $offlineSetupPath,
    '-ReleaseTrustRootFile', $releaseTrustRoot, '-SshHost', $releaseMirrorHost
  ) $root
}
Remove-Item -LiteralPath $offlineSetupWork -Recurse -Force -ErrorAction SilentlyContinue

# A successful release exposes one current manual deliverable and permanently
# retains the final Windows 2.1.44 recovery/online-upgrade baseline. Remove all
# other historical installers and convenience copies only after the new
# wrapper has verified and moved into place, so a failed build never destroys
# either the current deliverable or the permanent baseline.
foreach ($entry in @(Get-ChildItem -LiteralPath $distRoot -Force)) {
  if ([string]::Equals([IO.Path]::GetFullPath($entry.FullName), [IO.Path]::GetFullPath($offlineSetupPath), [StringComparison]::OrdinalIgnoreCase)) { continue }
  # Windows 2.1.44 is the permanent online-upgrade/recovery baseline.  The
  # canonical cleanup below validates its pinned identity and retains it; this
  # pre-clean must therefore never delete it first.
  if ([string]::Equals($entry.Name, $permanentWindowsBaselineName, [StringComparison]::OrdinalIgnoreCase)) { continue }
  # Android is an independent signed update/delivery channel. A Windows
  # promotion must not remove its manually deliverable APK directory while
  # pruning obsolete Windows wrappers.
  if ($entry.PSIsContainer -and $entry.Name -match '^Android-[0-9]+\.[0-9]+\.[0-9]+$') { continue }
  # The attestation directory is hidden release evidence, not a second manual
  # deliverable.  Keep it so clean-release-artifacts.ps1 and later operators
  # can re-verify the published wrapper without re-signing historical bytes.
  if ($entry.Name -eq '.offline-attestations' -and $entry.PSIsContainer) { continue }
  Remove-Item -LiteralPath $entry.FullName -Recurse -Force
}
Write-Output "Single-file offline installer: $offlineSetupPath"
} finally {
  # Never turn an interrupted or failed release into a new source of clutter.
  Remove-Item -LiteralPath $offlineSetupWork -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $redistributableZipNext -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $redistributableNext -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($entry in @(Get-ChildItem -LiteralPath $releases -Force)) {
  if ($entry.Name -in @('current.json', 'generations')) { continue }
  Remove-Item -LiteralPath $entry.FullName -Recurse -Force
}
Invoke-Native 'Release post-clean verification' $node (@((Join-Path $PSScriptRoot 'release-sign.mjs'), 'verify', '--root', $root, '--root-public-key-file', $releaseTrustRoot) + $releaseKeyArgs) $root
# release-sign verifies the authenticated manifest/envelope/artifact bindings,
# while the live Control release surface additionally requires the whole
# immutable generations tree to contain no undeclared files. Run that exact
# verifier here so an offline-package sidecar (or any future publication
# residue) can never turn a green build into BF-RELEASE-404 for clients.
Invoke-Native 'Live release surface verification' $node @((Join-Path $PSScriptRoot 'verify-release-surface.mjs'), '--root', $root) $root
# The public client edge runs from the protected Control supervisor snapshot,
# not directly from this source workspace. Publishing blobs to the static CDN
# without advancing that runtime current.json leaves the new digest unknown to
# /v1/releases/blobs and produces BF-RELEASE-404. Synchronize the already
# verified generation atomically after packaging succeeds.
if (-not $LocalOnly -and -not $DeferControlSync) { Invoke-Native 'Control runtime release synchronization' (Join-Path $PSHOME $(if ($PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) @(
  '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
  (Join-Path $PSScriptRoot 'sync-control-release.ps1'), '-Root', $root
) $root }

# A successful production release must leave one current signed generation,
# one current offline installer, and the permanent 2.1.44 recovery baseline.
# Remove reproducible bin/obj/test outputs too, so repeated releases cannot
# turn the development drive into an archive.
if (-not $LocalOnly) {
  Invoke-Native 'Release artifact cleanup' (Join-Path $PSHOME $(if ($PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })) @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
    (Join-Path $PSScriptRoot 'clean-release-artifacts.ps1'), '-Root', $root,
    '-ReleaseTrustRootFile', $releaseTrustRoot, '-IncludeBuildOutputs'
  ) $root
} else {
  Write-Output 'Local-only build complete; remote publication, Control sync, and publication cleanup were skipped.'
}
$global:LASTEXITCODE = 0
