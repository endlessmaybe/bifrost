namespace Bifrost.ClientService;

// Bounds diagnostic downloads only; it never limits application traffic.
internal sealed class NodeQualityProbeBudget
{
    internal const long WindowMs = 5 * 60_000;
    // Diagnostic traffic remains bounded and always yields to foreground
    // packets, but the old 8 MiB cap allowed only a handful of comparisons per
    // five minutes.  A large signed provider could therefore take hours to
    // reach its fastest member.  This budget is sized for a complete 600-node
    // throughput sweep plus confirmations.
    internal const long MaximumBytes = 768L * 1024 * 1024;
    private long _started = -1;
    private long _spent;
    internal bool TrySpend(long now, long bytes)
    {
        if (bytes <= 0 || bytes > MaximumBytes) return false;
        if (_started < 0 || now < _started || now - _started >= WindowMs)
        { _started = now; _spent = 0; }
        if (_spent + bytes > MaximumBytes) return false;
        _spent += bytes;
        return true;
    }
    internal bool CanStart(long now) => _started < 0 || now < _started || now - _started >= WindowMs ||
        MaximumBytes - _spent >= 1024 * 1024;
}
