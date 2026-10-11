param(
  [ValidateSet('all', 'desktop', 'linux', 'android')]
  [string]$Platform = 'all',
  [string]$Destination,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
if ([string]::IsNullOrWhiteSpace($Destination)) { $Destination = Join-Path $root 'build-work\toolchains\cores' }
$Destination = [IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Force -Path $Destination | Out-Null

function Download-Verified([string]$url, [string]$path, [string]$sha256) {
  if ($Force -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing
  }
  $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $sha256.ToLowerInvariant()) { throw "SHA-256 mismatch for ${path}: $actual" }
}

function Extract-Core([hashtable]$asset, [string]$archive, [string]$target) {
  $stage = Join-Path $Destination ('.extract-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  try {
    if ($asset.archive -eq 'zip') {
      Expand-Archive -LiteralPath $archive -DestinationPath $stage -Force
    } elseif ($asset.archive -eq 'tar.gz') {
      & tar.exe -xzf $archive -C $stage
      if ($LASTEXITCODE -ne 0) { throw "tar extraction failed for $archive (exit $LASTEXITCODE)" }
    } else { throw "Unsupported archive type: $($asset.archive)" }
    $binary = Get-ChildItem -LiteralPath $stage -Recurse -File |
      Where-Object { $_.Name -eq $asset.binary -or $_.Name -eq ($asset.binary + '.exe') } |
      Select-Object -First 1
    if (-not $binary) { throw "Archive does not contain $($asset.binary): $archive" }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $binary.FullName -Destination $target -Force
    if ($asset.platform -ne 'desktop') {
      # Android/Linux packages are unpacked on Windows and receive their
      # executable bit when copied to the target device by the installer.
      $sidecar = $target + '.sha256'
      Set-Content -LiteralPath $sidecar -Value ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()) -Encoding ASCII
    }
  } finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
  }
}

$assets = @(
  @{ id = 'mihomo-windows-amd64-compatible'; platform = 'desktop'; version = '1.19.30'; core = 'mihomo'; archive = 'zip'; binary = 'mihomo-windows-amd64-compatible'; file = 'mihomo-windows-amd64-compatible-v1.19.30.zip'; url = 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-windows-amd64-compatible-v1.19.30.zip'; sha256 = '289fde5e29d37a5b3326480590d8b3551c5bf7f8737290355c19bce74d57a563'; target = 'mihomo\1.19.30\windows-amd64-compatible\mihomo.exe' },
  @{ id = 'xray-linux-amd64'; platform = 'linux'; version = '26.3.27'; core = 'xray'; archive = 'zip'; binary = 'xray'; file = 'Xray-linux-64.zip'; url = 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip'; sha256 = '23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'; target = 'xray\26.3.27\linux-amd64\xray' },
  @{ id = 'xray-linux-arm64'; platform = 'linux'; version = '26.3.27'; core = 'xray'; archive = 'zip'; binary = 'xray'; file = 'Xray-linux-arm64-v8a.zip'; url = 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip'; sha256 = '4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c'; target = 'xray\26.3.27\linux-arm64\xray' },
  @{ id = 'sing-box-linux-amd64'; platform = 'linux'; version = '1.13.16'; core = 'sing-box'; archive = 'tar.gz'; binary = 'sing-box'; file = 'sing-box-1.13.16-linux-amd64.tar.gz'; url = 'https://github.com/SagerNet/sing-box/releases/download/v1.13.16/sing-box-1.13.16-linux-amd64.tar.gz'; sha256 = 'e37c312859dfa84cba148f41072ff6369f08361ae91d622dc1fd3aab49611a8d'; target = 'sing-box\1.13.16\linux-amd64\sing-box' },
  @{ id = 'sing-box-linux-arm64'; platform = 'linux'; version = '1.13.16'; core = 'sing-box'; archive = 'tar.gz'; binary = 'sing-box'; file = 'sing-box-1.13.16-linux-arm64.tar.gz'; url = 'https://github.com/SagerNet/sing-box/releases/download/v1.13.16/sing-box-1.13.16-linux-arm64.tar.gz'; sha256 = 'd587fb00bdc3c044227f35d15d154f271bc75108475091eda2542e4b82bb2949'; target = 'sing-box\1.13.16\linux-arm64\sing-box' },
  @{ id = 'xray-android-arm64'; platform = 'android'; version = '26.3.27'; core = 'xray'; archive = 'zip'; binary = 'xray'; file = 'Xray-android-arm64-v8a.zip'; url = 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-android-arm64-v8a.zip'; sha256 = '57149ffd48b629c07bf76938e73ab2729fde5910091497eab3e93d1c190f4c1b'; target = 'xray\26.3.27\android-arm64-v8a\xray' },
  @{ id = 'xray-android-amd64'; platform = 'android'; version = '26.3.27'; core = 'xray'; archive = 'zip'; binary = 'xray'; file = 'Xray-android-amd64.zip'; url = 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-android-amd64.zip'; sha256 = 'bfa1dd4cb3cd94f92af6c718ac6933cc84bd3ddd8343aa1e413162152930bee5'; target = 'xray\26.3.27\android-amd64\xray' },
  @{ id = 'sing-box-android-arm64'; platform = 'android'; version = '1.13.16'; core = 'sing-box'; archive = 'tar.gz'; binary = 'sing-box'; file = 'sing-box-1.13.16-android-arm64.tar.gz'; url = 'https://github.com/SagerNet/sing-box/releases/download/v1.13.16/sing-box-1.13.16-android-arm64.tar.gz'; sha256 = '0a5a2b11f7dd32c3584f3d2d0962c2a1f6e08fc0bcef13efdff0f6e7770f5194'; target = 'sing-box\1.13.16\android-arm64\sing-box' },
  @{ id = 'sing-box-android-amd64'; platform = 'android'; version = '1.13.16'; core = 'sing-box'; archive = 'tar.gz'; binary = 'sing-box'; file = 'sing-box-1.13.16-android-amd64.tar.gz'; url = 'https://github.com/SagerNet/sing-box/releases/download/v1.13.16/sing-box-1.13.16-android-amd64.tar.gz'; sha256 = '50d26033aa62ca19f1b42968d326371cdc5e1f0d2e7d4c4573358634cf8d856c'; target = 'sing-box\1.13.16\android-amd64\sing-box' }
)

$selected = $assets | Where-Object { $Platform -eq 'all' -or $_.platform -eq $Platform }
$records = [System.Collections.Generic.List[object]]::new()
foreach ($asset in $selected) {
  $archive = Join-Path $Destination ('downloads\' + $asset.file)
  Download-Verified $asset.url $archive $asset.sha256
  $target = Join-Path $Destination $asset.target
  $targetHash = if (-not $Force -and (Test-Path -LiteralPath $target -PathType Leaf)) { (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
  if ($Force -or -not (Test-Path -LiteralPath $target -PathType Leaf) -or -not $targetHash) { Extract-Core $asset $archive $target }
  $records.Add([ordered]@{
      id = $asset.id; core = $asset.core; version = $asset.version; platform = $asset.platform
      source = $asset.url; archive_sha256 = $asset.sha256; installed_path = [IO.Path]::GetFullPath($target)
      installed_sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}
$manifest = [ordered]@{
  format = 'BIFROST-CORE-MANIFEST-1'
  generated_at = (Get-Date).ToUniversalTime().ToString('o')
  destination = $Destination
  entries = @($records)
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Destination 'CORE-MANIFEST.json') -Encoding UTF8
Write-Output "Core binaries ready under $Destination"
Write-Output (Join-Path $Destination 'CORE-MANIFEST.json')
$global:LASTEXITCODE = 0
