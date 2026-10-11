namespace Bifrost.ClientService;

/// Owns one in-memory user connection intent for the lifetime of the service.
/// No credentials or unsigned replacement configuration are manufactured here.
internal sealed class RuntimeConnectionRecovery
{
    internal sealed class Intent(Func<CancellationToken, ServiceStatus> reconnect)
    {
        internal readonly CancellationTokenSource Cancellation = new();
        internal readonly Func<CancellationToken, ServiceStatus> Reconnect = reconnect;
        internal bool Armed;
        internal int Failures;
        internal long? FailedAt;
        internal long? HealthySince;
        internal TimeSpan Delay;
    }

    private readonly object _gate = new();
    private readonly TimeProvider _time;
    private Intent? _intent;
    private long _cancellationRevision;
    private int _running;
    private int _reconnecting;
    internal bool IsReconnecting => Volatile.Read(ref _reconnecting) != 0;
    internal static readonly TimeSpan StableConnectionWindow = TimeSpan.FromSeconds(30);
    internal RuntimeConnectionRecovery(TimeProvider? time = null) => _time = time ?? TimeProvider.System;

    internal long CancellationRevision { get { lock (_gate) return _cancellationRevision; } }

    internal Intent Begin(Func<CancellationToken, ServiceStatus> reconnect) => BeginCore(null, reconnect)!;

    internal Intent? TryBegin(long cancellationRevision, Func<CancellationToken, ServiceStatus> reconnect) =>
        BeginCore(cancellationRevision, reconnect);

    private Intent? BeginCore(long? cancellationRevision, Func<CancellationToken, ServiceStatus> reconnect)
    {
        Intent next;
        Intent? previous;
        lock (_gate)
        {
            if (cancellationRevision is { } revision && revision != _cancellationRevision) return null;
            next = new Intent(reconnect);
            previous = _intent;
            _intent = next;
        }
        previous?.Cancellation.Cancel();
        return next;
    }

    internal void CompleteInitial(Intent intent, ServiceStatus result)
    {
        lock (_gate)
        {
            if (!ReferenceEquals(_intent, intent)) return;
            // A failed first connect is not permission to connect later.
            intent.Armed = result.Ok && result.Connected;
            intent.HealthySince = intent.Armed ? _time.GetTimestamp() : null;
        }
    }

    internal void Cancel()
    {
        Intent? previous;
        lock (_gate) { _cancellationRevision++; previous = _intent; _intent = null; }
        previous?.Cancellation.Cancel();
    }

    internal bool IsCurrent(Intent intent)
    {
        lock (_gate) return ReferenceEquals(_intent, intent) && !intent.Cancellation.IsCancellationRequested;
    }

    internal static bool IsTransient(string? code) => code is
        "BF-RUNTIME-HEALTH" or "BF-CORE-NOT-READY" or "BF-CORE-EXITED" or
        "BF-CORE-START" or "BF-SOURCE-ALL-CANDIDATES-DEAD" or
        "BF-MIHOMO-PROVIDER-NOT-READY" ||
        (code?.StartsWith("BF-TRANSPORT-PROBE", StringComparison.Ordinal) == true);

    internal static TimeSpan RetryDelay(int failures) => TimeSpan.FromSeconds(failures switch
    { <= 1 => 2, 2 => 5, 3 => 10, 4 => 20, _ => 30 });

    internal void Tick(Func<ServiceStatus> readStatus, CancellationToken stopping)
    {
        if (Interlocked.Exchange(ref _running, 1) != 0) return;
        try
        {
            Intent? intent;
            lock (_gate) intent = _intent is { Armed: true } current ? current : null;
            if (intent is null || stopping.IsCancellationRequested) return;
            var status = readStatus();
            lock (_gate)
            {
                if (!ReferenceEquals(_intent, intent)) return;
                if (status.Ok && status.Connected)
                {
                    intent.HealthySince ??= _time.GetTimestamp();
                    // A brief successful handshake is not a recovered link.
                    // Preserve backoff across flapping sessions until the
                    // connection has remained healthy for a continuous window.
                    if (_time.GetElapsedTime(intent.HealthySince.Value) >= StableConnectionWindow)
                    { intent.Failures = 0; intent.FailedAt = null; }
                    return;
                }
                intent.HealthySince = null;
                if (!IsTransient(status.Code)) { intent.Armed = false; return; }
                if (intent.FailedAt is { } at && _time.GetElapsedTime(at) < intent.Delay) return;
            }
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stopping, intent.Cancellation.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(75));
            ServiceStatus result;
            try { Volatile.Write(ref _reconnecting, 1); result = intent.Reconnect(deadline.Token); }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested || intent.Cancellation.IsCancellationRequested) { return; }
            catch (OperationCanceledException) { result = ServiceStatus.Blocked("BF-CORE-START"); }
            // Unexpected failures are not evidence permitting another start.
            catch { lock (_gate) { if (ReferenceEquals(_intent, intent)) intent.Armed = false; } return; }
            finally { Volatile.Write(ref _reconnecting, 0); }
            lock (_gate)
            {
                if (!ReferenceEquals(_intent, intent)) return;
                if (result.Ok && result.Connected || IsTransient(result.Code))
                {
                    intent.Failures = Math.Min(intent.Failures + 1, 5);
                    intent.Delay = RetryDelay(intent.Failures);
                    intent.FailedAt = _time.GetTimestamp();
                    intent.HealthySince = result.Ok && result.Connected ? _time.GetTimestamp() : null;
                }
                else intent.Armed = false;
            }
        }
        finally { Volatile.Write(ref _running, 0); }
    }
}
