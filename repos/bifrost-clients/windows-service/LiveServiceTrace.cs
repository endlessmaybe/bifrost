using System.Diagnostics;

namespace Bifrost.ClientService;

internal static class LiveServiceTrace
{
    private static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bifrost");
    private static readonly string Marker = Path.Combine(Root, "live-service-trace.enable");
    private static readonly Lazy<BoundedTraceWriter> Writer = new(() =>
        new BoundedTraceWriter(new RotatingTraceFile(Path.Combine(Root, "live-service-trace.log")).WriteBatchAsync));
    private static long _nextMarkerCheck;
    private static int _enabled;

    internal static void Write(string message)
    {
        if (!OperatingSystem.IsWindows()) return;
        var now = Stopwatch.GetTimestamp();
        var nextCheck = Volatile.Read(ref _nextMarkerCheck);
        if (now >= nextCheck && Interlocked.CompareExchange(ref _nextMarkerCheck, now + Stopwatch.Frequency, nextCheck) == nextCheck)
            Volatile.Write(ref _enabled, File.Exists(Marker) ? 1 : 0);
        if (Volatile.Read(ref _enabled) == 0) return;
        Writer.Value.TryWrite($"{DateTimeOffset.Now:O}|pid={Environment.ProcessId}|tid={Environment.CurrentManagedThreadId}|{message}");
    }

    internal static async Task CompleteAsync()
    {
        if (!Writer.IsValueCreated) return;
        try { await Writer.Value.CompleteAsync().WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
        catch { /* Diagnostics cannot prevent service shutdown or update. */ }
    }
}
