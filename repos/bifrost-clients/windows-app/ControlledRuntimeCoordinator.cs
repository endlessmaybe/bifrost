using System;

namespace Bifrost;

/// <summary>
/// Production connection ordering seam used by the Windows service and the
/// isolated lifecycle fixture.  The injected adapters are the only place that
/// can touch a core or network boundary; this coordinator never falls back to
/// direct traffic when a proxy-classified start fails.
/// </summary>
public interface IControlledCoreAdapter
{
    bool Start(IControlledPackage package);
    bool IsHealthy { get; }
    bool Stop();
}

/// <summary>Small package contract shared by the WPF and service entrypoints.</summary>
public interface IControlledPackage
{
    string ConnectionType { get; }
    string Core { get; }
}

public interface IControlledNetworkBoundary
{
    bool EnterFailClosed();
    bool Activate();
    bool IsBound { get; }
    bool Release();
}

public sealed record ControlledRuntimeResult(bool Connected, bool FailClosed, string Route, string Core);

public enum ControlledRuntimePhase
{
    Idle,
    FencedStarting,
    Connected,
    BlockedFailure,
    Disconnecting,
}

public sealed record ControlledRuntimeState(ControlledRuntimePhase Phase, bool BoundaryHeld, string? FailureCode = null)
{
    public bool IsBlocked => Phase == ControlledRuntimePhase.BlockedFailure;
}

public sealed class ControlledRuntimeCoordinator
{
    private readonly IControlledCoreAdapter _core;
    private readonly IControlledNetworkBoundary _boundary;
    private readonly object _sync = new();
    private ControlledRuntimePhase _phase = ControlledRuntimePhase.Idle;
    private bool _boundaryHeld;
    private string? _failureCode;

    public ControlledRuntimeCoordinator(IControlledCoreAdapter core, IControlledNetworkBoundary boundary)
    {
        _core = core ?? throw new ArgumentNullException(nameof(core));
        _boundary = boundary ?? throw new ArgumentNullException(nameof(boundary));
    }

    public ControlledRuntimeState State
    {
        get { lock (_sync) return new ControlledRuntimeState(_phase, _boundaryHeld, _failureCode); }
    }

    public ControlledRuntimeResult Connect(IControlledPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);
        lock (_sync)
        {
            if (_phase != ControlledRuntimePhase.Idle)
                throw new InvalidOperationException("BF-CONNECTION-RESET-REQUIRED");
            _failureCode = null;
            _phase = ControlledRuntimePhase.FencedStarting;
            // A failed prepare/activation is conservatively considered held.
            // Only a successful explicit Disconnect may release it.
            _boundaryHeld = true;
            try
            {
                if (!_boundary.EnterFailClosed() || !_core.Start(package) || !_core.IsHealthy ||
                    !_boundary.Activate() || !_boundary.IsBound)
                    throw new InvalidOperationException("BF-PROXY-REQUIRED");
                _phase = ControlledRuntimePhase.Connected;
                return new ControlledRuntimeResult(true, false, package.ConnectionType, package.Core);
            }
            catch (Exception error)
            {
                RollbackFailedConnectLocked(StableFailureCode(error));
                throw;
            }
        }
    }

    /// <summary>Marks a live runtime failure while retaining the boundary fence.</summary>
    public void MarkFailure(string code = "BF-PROXY-REQUIRED")
    {
        lock (_sync)
        {
            if (_phase == ControlledRuntimePhase.Idle) return;
            EnterBlockedFailureLocked(code);
        }
    }

    /// <summary>
    /// Teardown is the only path allowed to release the boundary.  A failed
    /// stop or release leaves the coordinator blocked and retryable.
    /// </summary>
    public bool Disconnect()
    {
        lock (_sync)
        {
            if (_phase == ControlledRuntimePhase.Idle) return true;
            _phase = ControlledRuntimePhase.Disconnecting;
            var stopped = false;
            try { stopped = _core.Stop(); } catch { stopped = false; }
            if (!stopped)
            {
                _failureCode = "BF-CONNECTION-TEARDOWN";
                _phase = ControlledRuntimePhase.BlockedFailure;
                return false;
            }
            if (_boundaryHeld)
            {
                var released = false;
                try { released = _boundary.Release(); } catch { released = false; }
                if (!released)
                {
                    _failureCode = "BF-CONNECTION-TEARDOWN";
                    _phase = ControlledRuntimePhase.BlockedFailure;
                    return false;
                }
                _boundaryHeld = false;
            }
            _phase = ControlledRuntimePhase.Idle;
            _failureCode = null;
            return true;
        }
    }

    private void EnterBlockedFailureLocked(string? code = null)
    {
        _phase = ControlledRuntimePhase.BlockedFailure;
        _boundaryHeld = true;
        _failureCode = StableFailureCode(code) ?? _failureCode ?? "BF-PROXY-REQUIRED";
        // Fence before stopping the core.  The adapter is intentionally
        // idempotent for prepared/active generations and never releases here.
        try { _boundary.EnterFailClosed(); } catch { }
        try { _core.Stop(); } catch { }
    }

    /// <summary>
    /// A connection that never reached Connected is still a transaction in
    /// progress, not an established protected session. Roll it back eagerly so
    /// a transient candidate/TLS/core-start failure does not strand the client
    /// behind a persistent fail-closed fence. Only a teardown failure is
    /// allowed to remain blocked; live Connected failures still use
    /// MarkFailure and retain the fence until an explicit disconnect.
    /// </summary>
    private void RollbackFailedConnectLocked(string? code)
    {
        _phase = ControlledRuntimePhase.Disconnecting;
        var stopped = false;
        try { stopped = _core.Stop(); } catch { stopped = false; }
        var released = !_boundaryHeld;
        if (_boundaryHeld)
        {
            try { released = _boundary.Release(); } catch { released = false; }
        }
        if (stopped && released)
        {
            _boundaryHeld = false;
            _failureCode = null;
            _phase = ControlledRuntimePhase.Idle;
            return;
        }
        _boundaryHeld = true;
        _failureCode = "BF-CONNECTION-TEARDOWN";
        _phase = ControlledRuntimePhase.BlockedFailure;
        try { _boundary.EnterFailClosed(); } catch { }
    }

    private static string? StableFailureCode(Exception error) => StableFailureCode(error.Message);

    private static string? StableFailureCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code) || !code.StartsWith("BF-", StringComparison.Ordinal) || code.Length > 96) return null;
        return code.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-') ? code : null;
    }
}
