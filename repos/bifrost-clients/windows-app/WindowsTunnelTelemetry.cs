using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace Bifrost;

/// <summary>
/// Reads counters from the one TUN interface owned by Bifrost.  The UI never
/// fabricates throughput: if the adapter is absent or Windows cannot expose
/// its counters, the snapshot is explicitly unavailable.
/// </summary>
internal sealed class WindowsTunnelTelemetry : IDisposable
{
    private const string InterfaceName = "bifrost1";
    private readonly TunnelTrafficTracker _tracker = new();
    private readonly object _sync = new();
    private NetworkInterface? _adapter;
    private long _lastAdapterScan;
    private int _networkGeneration;
    private int _adapterGeneration = -1;
    private bool _disposed;
    private readonly NetworkAddressChangedEventHandler _networkChanged;

    internal WindowsTunnelTelemetry()
    {
        _networkChanged = (_, _) => Interlocked.Increment(ref _networkGeneration);
        NetworkChange.NetworkAddressChanged += _networkChanged;
    }

    internal UiTunnelTelemetry Capture(bool connected)
    {
        lock (_sync) return CaptureCore(connected);
    }

    private UiTunnelTelemetry CaptureCore(bool connected)
    {
        if (_disposed || !connected) { _adapter = null; return _tracker.Reset(); }

        try
        {
            var generation = Volatile.Read(ref _networkGeneration);
            if (_adapter is null || generation != _adapterGeneration || Stopwatch.GetElapsedTime(_lastAdapterScan) >= TimeSpan.FromSeconds(30))
            {
                _adapter = NetworkInterface.GetAllNetworkInterfaces().SingleOrDefault(item =>
                    string.Equals(item.Name, InterfaceName, StringComparison.OrdinalIgnoreCase) &&
                    item.OperationalStatus == OperationalStatus.Up);
                _lastAdapterScan = Stopwatch.GetTimestamp();
                _adapterGeneration = generation;
            }
            var adapter = _adapter;
            if (adapter is null) return _tracker.Unavailable();

            var statistics = adapter.GetIPv4Statistics();
            // Meta/Wintun exposes counters from the virtual adapter's point
            // of view: packets injected by the core towards Windows are
            // BytesSent, while packets captured from Windows for the core are
            // BytesReceived.  The activity page is user-facing, so translate
            // those counters to Internet direction instead of applying the
            // conventional physical-NIC labels.
            var received = statistics.BytesSent;     // user download
            var sent = statistics.BytesReceived;     // user upload
            return _tracker.Capture(new TunnelTrafficSample(adapter.Id, received, sent,
                Stopwatch.GetElapsedTime(0, Stopwatch.GetTimestamp())));
        }
        catch
        {
            _adapter = null;
            return _tracker.Unavailable();
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            _adapter = null;
            NetworkChange.NetworkAddressChanged -= _networkChanged;
        }
    }
}

internal sealed record UiTunnelTelemetry(
    bool Available,
    string DownloadRate,
    string UploadRate,
    string SessionTraffic,
    string Duration,
    ImmutableArray<double> DownloadSamples,
    ImmutableArray<double> UploadSamples)
{
    internal static UiTunnelTelemetry Empty { get; } =
        new(false, "—", "—", "—", "—", ImmutableArray<double>.Empty, ImmutableArray<double>.Empty);

    internal static UiTunnelTelemetry Waiting { get; } =
        new(false, "等待网卡", "等待网卡", "—", "00:00", ImmutableArray<double>.Empty, ImmutableArray<double>.Empty);
}
