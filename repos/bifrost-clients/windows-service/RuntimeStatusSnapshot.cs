namespace Bifrost.ClientService;

/// Read-only IPC view of the latest completed health observation. Network
/// probes and recovery remain on the service monitor, never on the reader.
internal sealed class RuntimeStatusSnapshot(TimeProvider? time = null)
{
    private sealed record Observation(ServiceStatus Status, long Timestamp);
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private Observation? _latest;
    internal void Publish(ServiceStatus status) =>
        Volatile.Write(ref _latest, new Observation(status, _time.GetTimestamp()));

    internal ServiceStatus Read(bool reconnecting)
    {
        if (reconnecting) return ServiceStatus.Reconnecting();
        var observed = Volatile.Read(ref _latest);
        if (observed is null) return ServiceStatus.Disconnected();
        // Never report stale protection if the monitor has stopped making
        // progress. A normal observation includes a bounded network probe.
        if (observed.Status.Connected && _time.GetElapsedTime(observed.Timestamp) > TimeSpan.FromSeconds(15))
            return new(false, false, "error", "BF-IPC-TIMEOUT", null, null, null, null, null, null);
        return observed.Status;
    }
}
