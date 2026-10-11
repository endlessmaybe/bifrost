param(
  [Parameter(Mandatory = $true)] [string] $InstallRoot,
  [switch] $WhatIf,
  [switch] $Install,
  [switch] $Uninstall,
  [switch] $Rollback,
  [switch] $ApplyPending,
  [switch] $Purge,
  [string] $ServiceName = 'BifrostClientService',
  # Explicitly test-only seams. Production invocations cannot override the
  # trusted setup path or turn a long poll into an unbounded wait.
  [switch] $TestSeam,
  [string] $TestSetupPath,
  [string] $TestUpdateRoot,
  [string] $TestFakeServiceMode,
  [string] $TestAfterSetupHookPath,
  [int] $TestPollIntervalMilliseconds = 250,
  [int] $TestPollTimeoutMilliseconds = 120000
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (@(@($Install, $Uninstall, $Rollback, $ApplyPending) | Where-Object { $_ }).Count -gt 1) {
  throw 'Choose only one operation.'
}
if (-not $WhatIf -and -not ($Install -or $Uninstall -or $Rollback -or $ApplyPending)) {
  throw 'Default is dry-run. Specify -WhatIf or an explicit operation.'
}
if ((-not $TestSeam) -and (
    -not [string]::IsNullOrWhiteSpace($TestSetupPath) -or
    -not [string]::IsNullOrWhiteSpace($TestUpdateRoot) -or
    -not [string]::IsNullOrWhiteSpace($TestFakeServiceMode) -or
    -not [string]::IsNullOrWhiteSpace($TestAfterSetupHookPath) -or
    $TestPollIntervalMilliseconds -ne 250 -or
    $TestPollTimeoutMilliseconds -ne 120000)) {
  throw 'Test-only setup overrides require -TestSeam.'
}
if ($TestSeam -and [string]::IsNullOrWhiteSpace($TestSetupPath)) {
  throw 'Test seam requires an explicit setup path.'
}
if ($TestSeam -and ($TestPollIntervalMilliseconds -lt 1 -or $TestPollTimeoutMilliseconds -lt 1)) {
  throw 'Test poll bounds are invalid.'
}
if ($TestSeam -and -not [string]::IsNullOrWhiteSpace($TestAfterSetupHookPath) -and
    -not (Test-Path -LiteralPath $TestAfterSetupHookPath -PathType Leaf)) {
  throw 'Test operation hook is missing.'
}

$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$releases = [IO.Path]::GetFullPath((Join-Path $root 'releases')).TrimEnd('\')
$resolvedInstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$resolvedWorkspace = [IO.Path]::GetFullPath($root).TrimEnd('\')
if ($resolvedInstallRoot.Equals($resolvedWorkspace, [StringComparison]::OrdinalIgnoreCase) -or
    $resolvedInstallRoot -in @('E:\', 'C:\', 'D:\')) {
  throw 'InstallRoot must be a dedicated client directory.'
}

function Resolve-CurrentSignedPackageRoot {
  $currentPath = Join-Path $releases 'current.json'
  if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
    throw 'Current signed release pointer is missing.'
  }
  try {
    $current = Get-Content -LiteralPath $currentPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $generation = [string]$current.generation
  } catch {
    throw 'Current signed release pointer is invalid.'
  }
  if ($generation -notmatch '^seq-[1-9][0-9]{0,15}-[A-Za-z0-9]{1,128}$') {
    throw 'Current signed release pointer has an invalid generation.'
  }
  $packageRoot = Join-Path (Join-Path $releases 'generations') $generation
  if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
    throw 'Current signed release generation is missing.'
  }
  return $packageRoot
}

function Resolve-TrustedSetupPath([string] $packageRoot) {
  $setups = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File -Filter 'BifrostSetup.exe' -ErrorAction Stop)
  if ($setups.Count -ne 1) {
    throw 'Current signed release must contain exactly one BifrostSetup.exe.'
  }
  return $setups[0].FullName
}

function Invoke-TrustedSetup([string[]] $Arguments) {
  $setupPath = if ($TestSeam) { $TestSetupPath } else {
    $currentSignedPackageRoot = Resolve-CurrentSignedPackageRoot
    Resolve-TrustedSetupPath $currentSignedPackageRoot
  }
  if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw 'Trusted BifrostSetup is missing from the signed release.'
  }
  $resolvedSetup = [IO.Path]::GetFullPath($setupPath)
  $setupArgs = @($Arguments)
  if ($WhatIf -and $setupArgs -notcontains '--what-if') { $setupArgs += '--what-if' }
  # PowerShell launches GUI-subsystem executables asynchronously when they are
  # invoked as a bare command.  A pipeline makes it wait for the trusted setup
  # and therefore exposes the real native exit code instead of reporting a
  # successful install while the setup is still running or has already failed.
  & $resolvedSetup @setupArgs 2>&1 | Out-Null
  if (-not (Test-Path -LiteralPath 'Variable:global:LASTEXITCODE')) {
    throw 'Trusted setup did not return an exit code.'
  }
  $setupExitCode = [int]$global:LASTEXITCODE
  if ($setupExitCode -ne 0) { throw 'Trusted setup rejected the signed release.' }
}

if ($ApplyPending) {
  $installedSetup = if ($TestSeam) { $TestSetupPath } else { Join-Path $resolvedInstallRoot 'BifrostSetup.exe' }
  if (-not (Test-Path -LiteralPath $installedSetup -PathType Leaf)) {
    throw 'Trusted updater is missing from the protected install root.'
  }
  # Installed promotion consumes only the signed pending marker and the
  # installer-owned machine update root. It must not depend on a mutable
  # workspace/release directory after installation.
  $args = @('--apply-pending', '--install-root', $resolvedInstallRoot)
  if ($WhatIf) { $args += '--what-if' }
  if ($TestSeam) {
    if ([string]::IsNullOrWhiteSpace($TestUpdateRoot)) { throw 'Test seam requires an update root.' }
    $args += '--test-root'
    $args += '--update-root'
    $args += [IO.Path]::GetFullPath($TestUpdateRoot)
    if (-not [string]::IsNullOrWhiteSpace($TestFakeServiceMode)) {
      $args += '--fake-service'
      $args += $TestFakeServiceMode
    }
  }
  $operationPath = Join-Path $resolvedInstallRoot '.bifrost-state\update-operation.json'
  $setupOutput = @(& ([IO.Path]::GetFullPath($installedSetup)) @args 2>&1)
  if ($LASTEXITCODE -ne 0) { throw 'Trusted updater rejected the pending marker.' }
  if (-not $WhatIf) {
    # The trusted setup returns the operation nonce and expected release
    # sequence. Only that pair may terminate this invocation; stale failed or
    # succeeded records and a different sequence are ignored.
    $expectedNonce = $null
    $expectedSequence = $null
    foreach ($line in $setupOutput) {
      try {
        $candidate = ConvertFrom-Json -InputObject ([string]$line)
        if ($candidate.state -in @('scheduled', 'succeeded') -and
            -not [string]::IsNullOrWhiteSpace([string]$candidate.operation_nonce) -and
            [long]$candidate.sequence -gt 0) {
          $expectedNonce = [string]$candidate.operation_nonce
          $expectedSequence = [long]$candidate.sequence
          break
        }
      } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($expectedNonce) -or $null -eq $expectedSequence) {
      throw 'BF-SETUP-OPERATION-CORRUPT'
    }
    if ($TestSeam -and -not [string]::IsNullOrWhiteSpace($TestAfterSetupHookPath)) {
      & ([IO.Path]::GetFullPath($TestAfterSetupHookPath)) $operationPath $expectedNonce ([string]$expectedSequence)
      if ($LASTEXITCODE -ne 0) { throw 'BF-SETUP-TEST-HOOK' }
    }
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TestPollTimeoutMilliseconds)
    $completed = $false
    while ([DateTime]::UtcNow -lt $deadline) {
      if (Test-Path -LiteralPath $operationPath -PathType Leaf) {
        try {
          $operation = Get-Content -LiteralPath $operationPath -Raw -Encoding UTF8 | ConvertFrom-Json
          $state = [string]$operation.state
          $sequence = [long]$operation.sequence
          $nonce = [string]$operation.operation_nonce
          if ($state -notin @('scheduled', 'succeeded', 'failed') -or $sequence -le 0 -or [string]::IsNullOrWhiteSpace($nonce)) {
            throw 'BF-SETUP-OPERATION-CORRUPT'
          }
          if ($sequence -ne $expectedSequence -or $nonce -ne $expectedNonce) {
            # A stale record from an earlier invocation is not this update.
            Start-Sleep -Milliseconds $TestPollIntervalMilliseconds
            continue
          }
          if ($state -eq 'succeeded') { $completed = $true; break }
          if ($state -eq 'failed') { throw 'BF-SETUP-UPDATE-FAILED' }
        } catch {
          if ($_.Exception.Message -like 'BF-SETUP-*') { throw }
          throw 'BF-SETUP-OPERATION-CORRUPT'
        }
      }
      Start-Sleep -Milliseconds $TestPollIntervalMilliseconds
    }
    if (-not $completed) { throw 'BF-SETUP-UPDATE-TIMEOUT' }
  }
  exit 0
}

if ($Uninstall -or $Rollback) {
  $action = if ($Uninstall) { '--uninstall' } else { '--rollback' }
  $args = @($action, '--install-root', $resolvedInstallRoot)
  if ($WhatIf) { $args += '--what-if' }
  if ($TestSeam) {
    if ([string]::IsNullOrWhiteSpace($TestSetupPath)) { throw 'Test seam requires an explicit setup path.' }
    $args += '--test-root'
    if (-not [string]::IsNullOrWhiteSpace($TestUpdateRoot)) {
      $args += '--update-root'
      $args += [IO.Path]::GetFullPath($TestUpdateRoot)
    }
    $args += '--fake-service'
    $args += $(if ([string]::IsNullOrWhiteSpace($TestFakeServiceMode)) { 'success' } else { $TestFakeServiceMode })
  }
  if ($Purge) { $args += '--purge' }
  Invoke-TrustedSetup $args
  exit 0
}

# Both ordinary installation and dry-run use the compiled, signed setup. The
# script never parses a manifest, invokes Node, copies payloads, or establishes
# a trust root after elevation. The setup owns the flat install topology and
# ProgramData\Bifrost\updates is the only pending-update root.
$currentSignedPackageRoot = Resolve-CurrentSignedPackageRoot
$args = @('--install', '--package-root', $currentSignedPackageRoot, '--install-root', $resolvedInstallRoot)
if ($WhatIf) { $args += '--what-if' }
Invoke-TrustedSetup $args
exit 0
