using System.Diagnostics;
using System.Net.NetworkInformation;

namespace Bifrost.ClientService;

internal sealed class NodeQualityForegroundInterruptedException : IOException
{
    internal NodeQualityForegroundInterruptedException() : base("BF-QUALITY-FOREGROUND-YIELD") { }
}

internal sealed record NodeQualityTrafficCounters(string Identity, long Received, long Sent);

internal static class NodeQualityForegroundGuard
{
    internal static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(250);

    // User packets traverse bifrost1. The private loopback mixed listener used
    // by quality probes bypasses this TUN, so its own downloads cannot trigger
    // the guard. Admission and mid-probe checks both watch this tunnel so
    // other VPNs and applications on the physical NIC cannot starve a sweep.
    internal static Func<NodeQualityTrafficCounters?> TunnelReader()
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(item =>
            item.Name.Equals(MihomoWindowsContract.TunInterfaceName, StringComparison.OrdinalIgnoreCase)
            && item.OperationalStatus == OperationalStatus.Up);
        return () =>
        {
            if (adapter is null) return null;
            try
            {
                var counters = adapter.GetIPStatistics();
                return new(adapter.Id, counters.BytesReceived, counters.BytesSent);
            }
            catch { return null; }
        };
    }

    internal static bool MustYield(NodeQualityTrafficCounters previous, NodeQualityTrafficCounters? current,
        double seconds, bool recovery)
    {
        if (current is null || current.Identity != previous.Identity || previous.Received < 0 || previous.Sent < 0
            || current.Received < previous.Received || current.Sent < previous.Sent || !double.IsFinite(seconds) || seconds <= 0)
            return true;
        var receivedRate = (double)(current.Received - previous.Received) / seconds;
        var sentRate = (double)(current.Sent - previous.Sent) / seconds;
        var rate = receivedRate + sentRate;
        return !NodeQualityRecoveryGate.CanContinue(rate, recovery);
    }

    internal static async Task<T> RunAsync<T>(Func<NodeQualityTrafficCounters?> read,
        Func<CancellationToken, Task<T>> measure, bool recovery, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var previous = read();
        if (previous is null || previous.Received < 0 || previous.Sent < 0)
            throw new NodeQualityForegroundInterruptedException();
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        var interrupted = 0;
        async Task WatchAsync()
        {
            var at = Stopwatch.GetTimestamp();
            while (true)
            {
                await Task.Delay(PollInterval, lifetime.Token).ConfigureAwait(false);
                NodeQualityTrafficCounters? current;
                try { current = read(); }
                catch { current = null; }
                var now = Stopwatch.GetTimestamp();
                if (MustYield(previous, current, Stopwatch.GetElapsedTime(at, now).TotalSeconds, recovery))
                {
                    Interlocked.Exchange(ref interrupted, 1);
                    lifetime.Cancel();
                    return;
                }
                previous = current!;
                at = now;
            }
        }
        var watcher = WatchAsync();
        T result;
        try { result = await measure(lifetime.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && Volatile.Read(ref interrupted) != 0)
        { throw new NodeQualityForegroundInterruptedException(); }
        finally
        {
            lifetime.Cancel();
            try { await watcher.ConfigureAwait(false); }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        }
        token.ThrowIfCancellationRequested();
        // A completed read racing with a foreground burst is not evidence for
        // ranking a node. Discard it, preserving the sweep's completed members.
        if (Volatile.Read(ref interrupted) != 0) throw new NodeQualityForegroundInterruptedException();
        return result;
    }
}
