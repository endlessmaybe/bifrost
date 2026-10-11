using Bifrost;

internal static class TunnelTrafficFixture
{
    internal static int Run()
    {
        try
        {
            var tracker = new TunnelTrafficTracker();
            UiTunnelTelemetry Capture(string id, long down, long up, double seconds) =>
                tracker.Capture(new(id, down, up, TimeSpan.FromSeconds(seconds)));
            void Assert(bool value, string message) { if (!value) throw new Exception(message); }
            Capture("adapter-a", 1000, 500, 0);
            var sample = Capture("adapter-a", 3048, 1524, 2);
            Assert(sample.DownloadRate == "1 KB/s" && sample.UploadRate == "512 B/s", "Direction or monotonic rate calculation failed.");
            Assert(sample.SessionTraffic == "3 KB", "Session bytes failed.");
            var duplicate = Capture("adapter-a", 99999, 99999, 2);
            Assert(ReferenceEquals(sample, duplicate), "Duplicate timestamps must not corrupt the measurement baseline.");
            sample = Capture("adapter-a", 10, 10, 3);
            Assert(sample.DownloadRate == "0 B/s" && sample.SessionTraffic == "3 KB", "Counter reset lost observed traffic or fabricated a rate.");
            sample = Capture("adapter-b", 900000, 800000, 4);
            Assert(sample.DownloadRate == "0 B/s" && sample.SessionTraffic == "3 KB", "Replacement adapter counters leaked into the session.");
            tracker.Unavailable();
            sample = Capture("adapter-b", 990000, 880000, 6);
            Assert(sample.DownloadRate == "0 B/s" && sample.DownloadSamples.Length == 1, "Missing interface must break the sampling interval.");
            for (var i = 1; i <= 100; i++) sample = Capture("adapter-b", 990000 + i, 880000 + i, 6 + i);
            Assert(sample.DownloadSamples.Length == 60 && sample.UploadSamples.Length == 60, "History exceeded its bound.");
            sample = Capture("adapter-b", 991000, 881000, 90000);
            Assert(sample.Duration == "25:00:00", "Connection duration wrapped at 24 hours.");
            Assert(!tracker.Reset().Available, "Disconnected session remained available.");
            sample = Capture("adapter-b", 1000000, 1000000, 90001);
            Assert(sample.SessionTraffic == "0 B" && sample.Duration == "00:00", "New session retained previous traffic or duration.");
            Console.WriteLine("PASS tunnel telemetry rates, counter reset, adapter replacement, missing samples, bounded history and 24-hour duration");
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
