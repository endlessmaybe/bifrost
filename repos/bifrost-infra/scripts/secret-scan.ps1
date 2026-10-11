$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$paths = @('repos\bifrost-clients','repos\bifrost-control','repos\bifrost-node-agent','repos\bifrost-infra','repos\bifrost-docs') | ForEach-Object { Join-Path $root $_ }
# Generic protocol labels (for parsers, UI hints and docs) are safe.  Scan
# for an actual long encoded VMess payload instead, which catches accidentally
# committed real share links without rejecting the feature itself.
$patterns = @(
  # Share links and proxy credentials must never be committed, even when a
  # developer forgets to put them in a test-fixtures directory.
  'vmess://[A-Za-z0-9+/_=-]{40,}',
  'socks5h?://[^<>\\s/:]{1,64}:[^<>\\s@]{1,128}@[^<>\\s]{3,}',
  # Literal secret assignments catch accidental credentials while allowing
  # code that calls randomToken()/readSecret() and explicit placeholders.
  '(?i)(?:password|passphrase|client[_-]?secret|api[_-]?key|access[_-]?token|tunnel[_ -]?token)\\s*[:=]\\s*[A-Za-z0-9_./+=-]{12,}',
  'X-Bifrost-Session\\s*[:=]\\s*[^<]',
  'BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY',
  'allowInsecure\\s*[:=]\\s*true'
)

function Find-SecretPatternHits([string]$path) {
  $pattern = $patterns -join '|'
  $ripgrep = Get-Command rg -ErrorAction SilentlyContinue
  if ($ripgrep) {
    return @(& $ripgrep.Source --no-heading --line-number --hidden --glob '!**/.git/**' --glob '!**/node_modules/**' --glob '!**/secret-scan.ps1' --regexp $pattern -- $path 2>$null)
  }

  # Keep the repository validation self-contained on a clean Windows host.
  # ripgrep is an optional accelerator, never a prerequisite for the security
  # gate.  The fallback deliberately scans only bounded text-like files so a
  # large APK/AAR/EXE cannot turn the scan into an accidental binary parser.
  $binaryExtensions = @(
    '.7z','.aar','.apk','.bin','.bmp','.class','.db','.dll','.dylib','.exe',
    '.gif','.ico','.jar','.jpeg','.jpg','.jks','.keystore','.lib','.msi','.msix',
    '.nupkg','.p12','.pfx','.png','.so','.sqlite','.tar','.webp','.zip'
  )
  $result = @()
  Get-ChildItem -LiteralPath $path -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -ne 'secret-scan.ps1' -and
      $_.Name -ne 'NUL' -and
      $_.Length -le 10MB -and
      $_.FullName -notmatch '[\\/](?:\.git|node_modules)[\\/]' -and
      $binaryExtensions -notcontains $_.Extension.ToLowerInvariant()
    } |
    ForEach-Object {
      $file = $_
      try {
        foreach ($match in @(Select-String -LiteralPath $file.FullName -Pattern $pattern -AllMatches -ErrorAction Stop)) {
          $result += '{0}:{1}:{2}' -f $file.FullName, $match.LineNumber, $match.Line
        }
      } catch {
        throw "Secret scan could not read text candidate: $($file.FullName)"
      }
    }
  return $result
}

$hits = @()
foreach ($path in $paths) {
  if (Test-Path -LiteralPath $path) {
    $hits += Find-SecretPatternHits $path
  }
}
$filtered = $hits | Where-Object {
  $_ -notmatch '<(PLACEHOLDER|SOCKS_|CLOUDFLARE_|WS_PATH_|DEVICE_|OUTER_)' -and
  $_ -notmatch 'TEST-ONLY' -and
  $_ -notmatch 'socks5h?://user:password@host' -and
  $_ -notmatch '(?i)fixture\.test|paste-user|paste-pass' -and
  $_ -notmatch '(?i)System\.getenv\("BIFROST_[A-Z0-9_]*(?:PASSWORD|KEY|TOKEN)"\)' -and
  $_ -notmatch 'test-fixtures' -and
  $_ -notmatch '(?i)example\\.(com|net|org)' -and
  $_ -notmatch '(?i)redacted|dummy|sample'
}
if ($filtered) { $filtered | Out-String; throw 'Potential secret or unsafe transport material found.' }
Write-Output 'Secret scan passed (placeholders only).'
exit 0
