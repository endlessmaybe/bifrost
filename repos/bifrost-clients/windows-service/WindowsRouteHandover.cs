using System.Net;

namespace Bifrost.ClientService;

internal sealed class WindowsRouteHandover : IDisposable
{
    private readonly int _interfaceIndex;
    private readonly bool _includeIpv6;
    private readonly Func<string, string, int, bool>? _routeRunner;
    private readonly Func<bool, bool> _routeReadback;
    private OwnedTunRouteCommit? _routes;
    private HandoverSnapshot? _snapshot;
    private bool _disposed;

    internal WindowsRouteHandover(
        int interfaceIndex,
        bool includeIpv6,
        Func<string, string, int, bool>? routeRunner = null,
        Func<bool, bool>? routeReadback = null)
    {
        if (interfaceIndex <= 0) throw new InvalidDataException("BF-HANDOVER-ROUTE-COMMIT");
        _interfaceIndex = interfaceIndex;
        _includeIpv6 = includeIpv6;
        _routeRunner = routeRunner;
        _routeReadback = routeReadback ?? (_ => true);
    }

    internal HandoverSnapshot PrepareAndCommit(
        MihomoRuntimeIdentity runtime,
        MihomoGroupState group,
        IReadOnlySet<string> allowedCandidates,
        IPAddress canaryAddress,
        Func<IPAddress, CancellationToken, bool> canaryProbe,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(group);
        ArgumentNullException.ThrowIfNull(allowedCandidates);
        ArgumentNullException.ThrowIfNull(canaryAddress);
        ArgumentNullException.ThrowIfNull(canaryProbe);
        ThrowIfDisposed();
        if (_snapshot is not null) throw new InvalidDataException("BF-HANDOVER-ALREADY-COMMITTED");
        if (runtime.ProcessId <= 0 || runtime.ConfigDigest.Length != 64)
            throw new InvalidDataException("BF-MIHOMO-RUNTIME");
        if (group.Now is "DIRECT" or "COMPATIBLE" or "REJECT" || string.IsNullOrWhiteSpace(group.Now))
            throw new InvalidDataException("BF-MIHOMO-DIRECT-FALLBACK");
        if (!allowedCandidates.Contains(group.Now)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        var selected = group.Candidates.SingleOrDefault(candidate => string.Equals(candidate.Name, group.Now, StringComparison.OrdinalIgnoreCase));
        if (selected is not { Alive: true }) throw new InvalidDataException("BF-SOURCE-ALL-CANDIDATES-DEAD");
        if (canaryAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            throw new InvalidDataException("BF-HANDOVER-CANARY");

        var routes = new OwnedTunRouteCommit(_interfaceIndex, _includeIpv6, _routeRunner);
        _routes = routes;
        var canaryInstalled = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            routes.InstallCanary(canaryAddress);
            canaryInstalled = true;
            if (!canaryProbe(canaryAddress, cancellationToken)) throw new InvalidDataException("BF-HANDOVER-CANARY");
            cancellationToken.ThrowIfCancellationRequested();
            try { routes.CommitFullTunnel(); }
            catch { throw new InvalidDataException("BF-HANDOVER-ROUTE-COMMIT"); }
            try { routes.RemoveCanary(); canaryInstalled = false; }
            catch { throw new InvalidDataException("BF-HANDOVER-ROUTE-COMMIT"); }
            if (!routes.HasFullTunnel || !_routeReadback(true)) throw new InvalidDataException("BF-HANDOVER-ROUTE-COMMIT");
            _snapshot = new HandoverSnapshot(_interfaceIndex, IPAddress.Parse(canaryAddress.ToString()), true, _includeIpv6);
            return _snapshot;
        }
        catch
        {
            var rollback = routes.RemoveAll();
            _snapshot = null;
            if (!rollback || !_routeReadback(false)) throw new InvalidDataException("BF-HANDOVER-ROLLBACK");
            throw;
        }
        finally
        {
            if (canaryInstalled && _snapshot is null) _ = routes.RemoveAll();
        }
    }

    internal void RollbackAndVerify()
    {
        ThrowIfDisposed();
        if (_routes is null) { _snapshot = null; return; }
        if (!_routes.RemoveAll() || !_routeReadback(false)) throw new InvalidDataException("BF-HANDOVER-ROLLBACK");
        _snapshot = null;
    }

    public void Dispose()
    {
        if (_disposed) return;
        try { if (_routes is not null) _ = _routes.RemoveAll(); } catch { }
        _routes?.Dispose();
        _snapshot = null;
        _disposed = true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(WindowsRouteHandover));
    }
}
