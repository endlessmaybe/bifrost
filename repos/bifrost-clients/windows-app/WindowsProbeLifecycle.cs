using System.Windows;
using System.Windows.Threading;
using System.Diagnostics;

namespace Bifrost;

public sealed record ProbeLifecycleOutcome(
    bool Success,
    long ConfigGeneration,
    string Source,
    string? SelectedCandidateLabel = null,
    IReadOnlyList<CandidateProbeStatus>? Candidates = null,
    bool IsPartial = false,
    int Completed = 0,
    int Total = 0,
    string? ErrorCode = null);

public interface IProbeLifecycleScheduler : IDisposable
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

internal sealed class TaskProbeLifecycleScheduler : IProbeLifecycleScheduler
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => Task.Delay(delay, cancellationToken);
    public void Dispose() { }
}

public interface IUiStateDispatcher
{
    bool CheckAccess { get; }
    void Post(Action action);
}

internal sealed class WpfUiStateDispatcher : IUiStateDispatcher
{
    private readonly Dispatcher? _dispatcher = Application.Current?.Dispatcher;
    public bool CheckAccess => _dispatcher is null || _dispatcher.CheckAccess();
    public void Post(Action action)
    {
        if (_dispatcher is null || _dispatcher.CheckAccess()) action();
        else _dispatcher.BeginInvoke(action, DispatcherPriority.DataBind);
    }
}

/// <summary>
/// Owns the lifetime of Windows candidate probing.  It has no sockets or
/// timers of its own: production delay is injected through Task.Delay and
/// deterministic fixtures provide a manual scheduler.
/// </summary>
public sealed class WindowsProbeLifecycle : IDisposable
{
    public static readonly TimeSpan NetworkQuietPeriod = TimeSpan.FromMilliseconds(1500);
    public static readonly TimeSpan RefreshCadence = TimeSpan.FromHours(2);

    private readonly IUiShellCoordinator _coordinator;
    private readonly IProbeLifecycleScheduler _scheduler;
    private readonly Action<ProbeLifecycleOutcome> _publish;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    // A new source/key supersedes the visible round, but the old task can
    // still be unwinding cancellation. Keep every task/source until it has
    // completed (or the single bounded Dispose join has elapsed).
    private readonly HashSet<Task> _ownedTasks = new();
    private readonly HashSet<CancellationTokenSource> _ownedSources = new();
    private CancellationTokenSource? _roundCancellation;
    private CancellationTokenSource? _debounceCancellation;
    private Task? _roundTask;
    private Task? _debounceTask;
    private Task? _cadenceTask;
    private string _source = "";
    private long _configGeneration;
    private long _triggerGeneration;
    private bool _started;
    private bool _disposed;
    private long _networkQuietGeneration;

    public WindowsProbeLifecycle(
        IUiShellCoordinator coordinator,
        Action<ProbeLifecycleOutcome> publish,
        IProbeLifecycleScheduler? scheduler = null)
    {
        _coordinator = coordinator;
        _publish = publish;
        _scheduler = scheduler ?? new TaskProbeLifecycleScheduler();
        _ownedSources.Add(_lifetime);
    }

    public void Start(string source, long configGeneration)
    {
        lock (_gate)
        {
            if (_disposed) return;
            if (_started)
            {
                ConfigurationRefreshedLocked(source, configGeneration);
                return;
            }
            _started = true;
            _source = source;
            _configGeneration = configGeneration;
            _cadenceTask = CadenceLoopAsync();
            TrackTaskLocked(_cadenceTask, source: null);
            StartRoundLocked();
        }
    }

    public void ConfigurationRefreshed(string source, long configGeneration)
    {
        lock (_gate)
        {
            if (_disposed || !_started) return;
            ConfigurationRefreshedLocked(source, configGeneration);
        }
    }

    private void ConfigurationRefreshedLocked(string source, long configGeneration)
    {
        if (string.Equals(_source, source, StringComparison.Ordinal) && _configGeneration == configGeneration) return;
        _source = source;
        _configGeneration = configGeneration;
        _triggerGeneration++;
        CancelDebounceLocked();
        CancelRoundLocked();
        StartRoundLocked();
    }

    public void SourceChanged(string source, long configGeneration)
    {
        lock (_gate)
        {
            if (_disposed || !_started || (string.Equals(_source, source, StringComparison.Ordinal) && _configGeneration == configGeneration)) return;
            _source = source;
            _configGeneration = configGeneration;
            _triggerGeneration++;
            CancelDebounceLocked();
            CancelRoundLocked();
            StartRoundLocked();
        }
    }

    public void TriggerManual()
    {
        lock (_gate)
        {
            if (_disposed || !_started) return;
            CancelDebounceLocked();
            StartRoundLocked();
        }
    }

    public void CancelManual()
    {
        lock (_gate)
        {
            if (_disposed || !_started) return;
            CancelDebounceLocked();
            CancelRoundLocked();
        }
    }

    public void NetworkInvalidated(long configGeneration)
    {
        lock (_gate)
        {
            if (_disposed || !_started) return;
            _configGeneration = configGeneration;
            _triggerGeneration++;
            CancelRoundLocked();
            CancelDebounceLocked();
            var quietGeneration = ++_networkQuietGeneration;
            var debounceCancellation = CreateOwnedLinkedSourceLocked();
            _debounceCancellation = debounceCancellation;
            _debounceTask = DebounceAsync(quietGeneration, debounceCancellation);
            TrackTaskLocked(_debounceTask, debounceCancellation);
        }
    }

    private bool HasValidSourceLocked()
    {
        if (!_coordinator.IsEnrolled || _configGeneration <= 0 || string.IsNullOrWhiteSpace(_source) || string.Equals(_source, "auto", StringComparison.OrdinalIgnoreCase)) return false;
        try { return _coordinator.GetUiConfigOptions().Sources.Any(option => string.Equals(option.Code, _source, StringComparison.OrdinalIgnoreCase)); }
        catch { return false; }
    }

    private void StartRoundLocked()
    {
        if (!HasValidSourceLocked()) return;
        var key = new ProbeKey(_source, _configGeneration, _triggerGeneration);
        if (_roundTask is { IsCompleted: false } && _activeKey == key) return;
        CancelRoundLocked();
        var cancellation = CreateOwnedLinkedSourceLocked();
        _roundCancellation = cancellation;
        _activeKey = key;
        _roundTask = RunRoundAsync(key, cancellation);
        TrackTaskLocked(_roundTask, cancellation);
    }

    private ProbeKey? _activeKey;
    private async Task RunRoundAsync(ProbeKey key, CancellationTokenSource cancellation)
    {
        bool success = false;
        bool publish = false;
        string? errorCode = null;
        CandidateProbeSnapshot? snapshot = null;
        try
        {
            snapshot = await _coordinator.ProbeCandidateStatusesAsync(key.Source, progress => PublishPartial(key, cancellation, progress), cancellation.Token).ConfigureAwait(false);
            success = snapshot.Candidates.Any(candidate => candidate.Success);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return; }
        catch (ServiceException error)
        {
            success = false;
            errorCode = error.Code;
        }
        catch
        {
            success = false;
            errorCode = "BF-PROBE-FAILED";
        }
        finally
        {
            lock (_gate)
            {
                if (!_disposed && !cancellation.IsCancellationRequested && _activeKey == key)
                {
                    _activeKey = null;
                    _roundCancellation = null;
                    publish = true;
                }
            }
        }
        // Serialize publication with Dispose.  Once Dispose wins the gate no
        // late result can touch the ViewModel/dispatcher.
        if (publish)
        {
            lock (_gate)
            {
                if (!_disposed) _publish(new ProbeLifecycleOutcome(
                    success,
                    key.ConfigGeneration,
                    key.Source,
                    snapshot?.SelectedCandidateLabel,
                    snapshot?.Candidates ?? Array.Empty<CandidateProbeStatus>(),
                    ErrorCode: errorCode));
            }
        }
    }

    private void PublishPartial(ProbeKey key, CancellationTokenSource cancellation, CandidateProbeProgress progress)
    {
        lock (_gate)
        {
            if (_disposed || cancellation.IsCancellationRequested || _activeKey != key ||
                !string.Equals(progress.Source, key.Source, StringComparison.Ordinal)) return;
            _publish(new ProbeLifecycleOutcome(
                Success: progress.Status.Success,
                ConfigGeneration: key.ConfigGeneration,
                Source: key.Source,
                SelectedCandidateLabel: null,
                Candidates: new[] { progress.Status },
                IsPartial: true,
                Completed: progress.Completed,
                Total: progress.Total));
        }
    }

    private async Task DebounceAsync(long quietGeneration, CancellationTokenSource cancellation)
    {
        try { await _scheduler.DelayAsync(NetworkQuietPeriod, cancellation.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }
        lock (_gate)
        {
            if (_disposed || quietGeneration != _networkQuietGeneration || !ReferenceEquals(_debounceCancellation, cancellation)) return;
            _debounceCancellation = null;
            StartRoundLocked();
        }
    }

    private async Task CadenceLoopAsync()
    {
        try
        {
            while (true)
            {
                await _scheduler.DelayAsync(RefreshCadence, _lifetime.Token).ConfigureAwait(false);
                lock (_gate)
                {
                    if (_disposed) return;
                    if (_debounceCancellation is null) StartRoundLocked();
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private void CancelRoundLocked()
    {
        try { _roundCancellation?.Cancel(); } catch (ObjectDisposedException) { }
        _roundCancellation = null;
        _activeKey = null;
    }

    private void CancelDebounceLocked()
    {
        try { _debounceCancellation?.Cancel(); } catch (ObjectDisposedException) { }
        _debounceCancellation = null;
        _networkQuietGeneration++;
    }

    private CancellationTokenSource CreateOwnedLinkedSourceLocked()
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _ownedSources.Add(source);
        return source;
    }

    private void TrackTaskLocked(Task task, CancellationTokenSource? source)
    {
        _ownedTasks.Add(task);
        _ = task.ContinueWith(
            completed => OnTaskCompleted(completed, source),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void OnTaskCompleted(Task task, CancellationTokenSource? source)
    {
        lock (_gate)
        {
            _ownedTasks.Remove(task);
            if (source is not null && !ReferenceEquals(source, _lifetime) && _ownedSources.Remove(source))
            {
                // The task is complete, so no cancellation callback can race
                // this disposal. Dispose is idempotently owned by this set.
                source.Dispose();
            }
        }
    }

    public void Dispose()
    {
        Task[] tasks;
        CancellationTokenSource[] sources;
        var started = Stopwatch.GetTimestamp();
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            // Detach the visible handles atomically before cancellation. Any
            // callback that races this point observes _disposed and cannot
            // start or publish new work.
            _roundCancellation = null;
            _debounceCancellation = null;
            _activeKey = null;
            _networkQuietGeneration++;
            tasks = _ownedTasks.ToArray();
            sources = _ownedSources.Where(source => !ReferenceEquals(source, _lifetime)).ToArray();
        }

        // Cancel outside the gate so a scheduler's cancellation callback may
        // complete a task/continuation without deadlocking Dispose.
        foreach (var source in sources)
        {
            try { source.Cancel(); } catch (ObjectDisposedException) { }
        }
        try { _lifetime.Cancel(); } catch (ObjectDisposedException) { }

        var remaining = TimeSpan.FromMilliseconds(Math.Max(0, 500 - Stopwatch.GetElapsedTime(started).TotalMilliseconds));
        if (tasks.Length != 0 && remaining > TimeSpan.Zero)
        {
            try { Task.WhenAll(tasks).Wait(remaining); } catch { /* cancellation/fault is fail-closed */ }
        }

        lock (_gate)
        {
            // This also disposes stubborn-work sources after the one total
            // join budget; their late continuations can only remove an absent
            // set entry and are barred from publication by _disposed.
            foreach (var source in _ownedSources.ToArray())
            {
                _ownedSources.Remove(source);
                try { source.Dispose(); } catch (ObjectDisposedException) { }
            }
        }
        _scheduler.Dispose();
    }

    private sealed record ProbeKey(string Source, long ConfigGeneration, long TriggerGeneration);
}
