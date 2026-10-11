using System.Collections.Immutable;

namespace Bifrost;

internal readonly record struct TunnelTrafficSample(string AdapterId, long DownloadBytes, long UploadBytes, TimeSpan Timestamp);

/// <summary>Pure session accounting. Timestamps are monotonic; a recreated
/// adapter or counter reset starts a new measurement interval without losing
/// traffic already observed in the current connection.</summary>
internal sealed class TunnelTrafficTracker
{
    private const int MaximumSamples = 60;
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB"];
    private readonly Queue<double> _download = new();
    private readonly Queue<double> _upload = new();
    private TunnelTrafficSample? _previous;
    private TimeSpan? _connectedAt;
    private double _sessionBytes;
    private UiTunnelTelemetry _snapshot = UiTunnelTelemetry.Empty;

    internal UiTunnelTelemetry Capture(TunnelTrafficSample sample)
    {
        if (sample.DownloadBytes < 0 || sample.UploadBytes < 0 || string.IsNullOrWhiteSpace(sample.AdapterId))
            return Unavailable();
        if (_previous is { } last && sample.Timestamp <= last.Timestamp) return _snapshot;
        _connectedAt ??= sample.Timestamp;
        double downloadRate = 0, uploadRate = 0;
        if (_previous is { } previous && previous.AdapterId == sample.AdapterId &&
            sample.DownloadBytes >= previous.DownloadBytes && sample.UploadBytes >= previous.UploadBytes)
        {
            var seconds = (sample.Timestamp - previous.Timestamp).TotalSeconds;
            var received = sample.DownloadBytes - previous.DownloadBytes;
            var sent = sample.UploadBytes - previous.UploadBytes;
            downloadRate = received / seconds;
            uploadRate = sent / seconds;
            _sessionBytes += (double)received + sent;
        }
        else
        {
            // A missing/recreated adapter is a discontinuity, not a burst of
            // traffic from a different counter epoch.
            _download.Clear();
            _upload.Clear();
        }
        _previous = sample;
        Append(_download, downloadRate);
        Append(_upload, uploadRate);
        return _snapshot = new UiTunnelTelemetry(true, $"{FormatBytes(downloadRate)}/s", $"{FormatBytes(uploadRate)}/s",
            FormatBytes(_sessionBytes), FormatDuration(sample.Timestamp - _connectedAt.Value),
            _download.ToImmutableArray(), _upload.ToImmutableArray());
    }

    internal UiTunnelTelemetry Unavailable()
    {
        _previous = null;
        _download.Clear();
        _upload.Clear();
        return _snapshot = UiTunnelTelemetry.Waiting;
    }

    internal UiTunnelTelemetry Reset()
    {
        Unavailable();
        _connectedAt = null;
        _sessionBytes = 0;
        return _snapshot = UiTunnelTelemetry.Empty;
    }

    private static void Append(Queue<double> samples, double value)
    {
        samples.Enqueue(value);
        while (samples.Count > MaximumSamples) samples.Dequeue();
    }

    private static string FormatBytes(double bytes)
    {
        var value = Math.Max(0d, bytes);
        var unit = 0;
        while (value >= 1024d && unit < Units.Length - 1) { value /= 1024d; unit++; }
        return unit == 0 ? $"{value:0} {Units[unit]}" : $"{value:0.##} {Units[unit]}";
    }

    private static string FormatDuration(TimeSpan duration) => duration.TotalHours >= 1d
        ? $"{(long)duration.TotalHours:00}:{duration.Minutes:00}:{duration.Seconds:00}"
        : $"{duration.Minutes:00}:{duration.Seconds:00}";
}
