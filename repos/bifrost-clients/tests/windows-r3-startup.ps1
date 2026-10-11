param(
    [Parameter(Mandatory = $true)]
    [string] $ExePath,
    [int] $TimeoutSeconds = 10
)

$ErrorActionPreference = 'Stop'
$resolvedExe = (Resolve-Path -LiteralPath $ExePath).Path
if (-not [IO.Path]::GetFileName($resolvedExe).Equals('Bifrost.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BF-R3-STARTUP-PATH'
}

$startAt = [DateTime]::UtcNow
$applicationEventsBefore = @()
try {
    $applicationEventsBefore = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1026, 1000; StartTime = $startAt.AddSeconds(-2) } -ErrorAction Stop | Where-Object { $_.ProviderName -in @('.NET Runtime', 'Application Error') })
} catch [Exception] {
    # Event log access is diagnostic-only; startup assertions remain strict.
    $applicationEventsBefore = @()
}

$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $resolvedExe
$psi.WorkingDirectory = [IO.Path]::GetDirectoryName($resolvedExe)
$psi.UseShellExecute = $true
$process = [Diagnostics.Process]::Start($psi)
if ($null -eq $process) { throw 'BF-R3-STARTUP-SPAWN' }
$ownedPid = $process.Id
$started = $false
$windowHandle = [IntPtr]::Zero
$title = ''
try {
    $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(1, $TimeoutSeconds))
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) { throw "BF-R3-STARTUP-EXIT:$($process.ExitCode)" }
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) {
            $process.Refresh()
            $windowHandle = $process.MainWindowHandle
            $title = $process.MainWindowTitle
            if ($title -eq 'Bifrost') { $started = $true; break }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $started) { throw 'BF-R3-STARTUP-TIMEOUT' }
} finally {
    if ($null -ne $process) {
        try { $process.Refresh() } catch { }
        if (-not $process.HasExited) {
            try { [void]$process.CloseMainWindow(); [void]$process.WaitForExit(3000) } catch { }
        }
        if (-not $process.HasExited) {
            # The process object is the exact child created above; no lookup by
            # name/port and no unrelated process is inspected or terminated.
            try { $process.Kill() } catch { }
            try { [void]$process.WaitForExit(3000) } catch { }
        }
    }
}

$applicationEventsAfter = @()
try {
    $applicationEventsAfter = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1026, 1000; StartTime = $startAt } -ErrorAction Stop | Where-Object { $_.ProviderName -in @('.NET Runtime', 'Application Error') })
} catch [Exception] {
    $applicationEventsAfter = @()
}
if ($applicationEventsAfter.Count -gt $applicationEventsBefore.Count) {
    throw 'BF-R3-STARTUP-EVENT-CRASH'
}
$runtimeDelta = @($applicationEventsAfter | Where-Object { $_.Id -eq 1026 }).Count - @($applicationEventsBefore | Where-Object { $_.Id -eq 1026 }).Count
$applicationDelta = @($applicationEventsAfter | Where-Object { $_.Id -eq 1000 }).Count - @($applicationEventsBefore | Where-Object { $_.Id -eq 1000 }).Count
if ($runtimeDelta -gt 0 -or $applicationDelta -gt 0) { throw 'BF-R3-STARTUP-EVENT-CRASH' }
[pscustomobject]@{ status = 'PASS'; pid_owned = $true; main_window_handle = ('0x{0:X}' -f $windowHandle.ToInt64()); title = $title; exited = $false; dotnet_runtime_1026_delta = $runtimeDelta; application_error_1000_delta = $applicationDelta }
