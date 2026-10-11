namespace Bifrost.ClientService;

// A slow but nonzero stream must not postpone its own recovery forever.
// Permit one bounded comparison after sustained low traffic; ordinary large
// transfers still take precedence. All times are monotonic milliseconds.
internal sealed class NodeQualityRecoveryGate
{
    internal const double IdleBytesPerSecond = 16 * 1024;
    // Ordinary interactive traffic (chat, status polling, small page assets)
    // should not starve the background optimizer forever. The live machine
    // peaks around 50 KiB/s during this workload, so leave generous headroom
    // while still yielding well before a real stream/download becomes busy.
    internal const double InteractiveCeilingBytesPerSecond = 128 * 1024;
    // Video is bursty: a connection averaging only a few Mbps can briefly
    // exceed 512 KiB/s while fetching the next segment. Treating every such
    // burst as "healthy/high traffic" erased the 30-second recovery window
    // and starved the optimizer indefinitely. Recovery remains bounded to one
    // slot every two minutes and still yields above 32 Mbps.
    internal const double RecoveryCeilingBytesPerSecond = 4 * 1024 * 1024;
    internal const long SustainedLowTrafficMs = 30_000;
    internal const long RecoveryCooldownMs = 120_000;
    private long? _lowSince;
    private long? _lastLowTraffic;
    private long _nextRecovery;

    internal bool TryAdmit(long now, double bytesPerSecond, out bool recovery)
    {
        recovery = false;
        if (!double.IsFinite(bytesPerSecond) || bytesPerSecond < 0 || bytesPerSecond >= RecoveryCeilingBytesPerSecond)
        { _lowSince = null; _lastLowTraffic = null; return false; }
        // A short gap between image/video bursts is still the same slow
        // session. Otherwise every gap resets recovery and each ordinary
        // comparison yields again when the next burst arrives.
        if (_lastLowTraffic is not null && (now < _lastLowTraffic ||
            bytesPerSecond <= IdleBytesPerSecond && now - _lastLowTraffic >= SustainedLowTrafficMs))
        { _lowSince = null; _lastLowTraffic = null; }
        if (bytesPerSecond <= IdleBytesPerSecond)
        {
            if (_lowSince is not null && now - _lowSince >= SustainedLowTrafficMs && now >= _nextRecovery)
            { _nextRecovery = now + RecoveryCooldownMs; recovery = true; }
            return true;
        }
        _lastLowTraffic = now;
        if (_lowSince is null || now < _lowSince) _lowSince = now;
        if (now - _lowSince < SustainedLowTrafficMs || now < _nextRecovery) return false;
        _nextRecovery = now + RecoveryCooldownMs;
        recovery = true;
        return true;
    }

    internal static bool CanContinue(double bytesPerSecond, bool recovery) =>
        double.IsFinite(bytesPerSecond) && bytesPerSecond >= 0 &&
        bytesPerSecond < (recovery ? RecoveryCeilingBytesPerSecond : InteractiveCeilingBytesPerSecond);
}
