using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Bifrost.ClientService;

internal static class ForegroundGuardFixture
{
    private static void Assert(bool value, string message)
    { if (!value) throw new Exception(message); }

    internal static async Task Run()
    {
        var baseline = new NodeQualityTrafficCounters("tun-1", 1000, 1000);
        Assert(!NodeQualityForegroundGuard.MustYield(baseline, baseline, .25, false), "idle counters cancelled own probe");
        var lowTraffic = baseline with { Received = 1000 + 25 * 1024 };
        Assert(!NodeQualityForegroundGuard.MustYield(baseline, lowTraffic, .25, false), "light interactive traffic starved background optimization");
        Assert(!NodeQualityForegroundGuard.MustYield(baseline, lowTraffic, .25, true), "bounded slow-stream recovery disabled");
        Assert(NodeQualityForegroundGuard.MustYield(baseline, baseline with { Received = 1000 + 64 * 1024 }, .25, false), "sustained foreground download not detected");
        Assert(NodeQualityForegroundGuard.MustYield(baseline, baseline with { Sent = 1000 + 2 * 1024 * 1024 }, .25, true), "foreground upload above the recovery ceiling not detected");
        foreach (var invalid in new NodeQualityTrafficCounters?[] { null, baseline with { Identity = "tun-2" }, baseline with { Received = 1 } })
            Assert(NodeQualityForegroundGuard.MustYield(baseline, invalid, .25, true), "topology or counter epoch failure admitted");
        foreach (var seconds in new[] { 0.0, -1, double.NaN, double.PositiveInfinity })
            Assert(NodeQualityForegroundGuard.MustYield(baseline, baseline, seconds, false), "invalid sampling duration admitted");

        var reads = 0;
        var measured = await NodeQualityForegroundGuard.RunAsync(() => { reads++; return baseline; },
            async ct => { await Task.Delay(650, ct); return 42; }, false, CancellationToken.None);
        Assert(measured == 42 && reads >= 3, "quiet probe did not finish while being monitored");
        var finishedReads = reads;
        await Task.Delay(350);
        Assert(reads == finishedReads, "watcher survived successful probe");

        var started = false;
        try
        {
            await NodeQualityForegroundGuard.RunAsync<int>(() => null,
                _ => { started = true; return Task.FromResult(1); }, false, CancellationToken.None);
            throw new Exception("Missing TUN did not yield");
        }
        catch (NodeQualityForegroundInterruptedException) { }
        Assert(!started, "probe started without accounting");

        // Exercise cancellation of the real HttpClient CONNECT/header wait,
        // not just a synthetic delay. No external server or credentials used.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var foreground = false;
            var drained = false;
            var accepted = listener.AcceptTcpClientAsync();
            var probe = NodeQualityForegroundGuard.RunAsync(
                () => foreground ? baseline with { Received = 10 * 1024 * 1024 } : baseline,
                async ct =>
                {
                    try { return await MihomoQualityOptimizer.MeasureAsync(((IPEndPoint)listener.LocalEndpoint).Port, "TEST-ONLY", ct); }
                    finally { drained = true; }
                }, false, CancellationToken.None);
            using var peer = await accepted.WaitAsync(TimeSpan.FromSeconds(3));
            var timer = Stopwatch.StartNew();
            foreground = true;
            try { await probe.WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("Foreground burst produced a node score"); }
            catch (NodeQualityForegroundInterruptedException) { }
            Assert(drained, "yield returned before active HTTP request finished");
            Console.WriteLine($"NODE-QUALITY mid-probe real HTTP wait cancelled by user traffic in {timer.Elapsed.TotalMilliseconds:F1} ms PASS");
        }
        finally { listener.Stop(); }

        // Also cover a response that has delivered headers and a first body
        // byte but then stalls, so cancellation does not rely on another read
        // finishing or on reaching the six-second measurement deadline.
        var bodyListener = new TcpListener(IPAddress.Loopback, 0);
        bodyListener.Start();
        try
        {
            var foreground = false;
            var bodyStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var accepted = bodyListener.AcceptTcpClientAsync();
            using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false });
            var probe = NodeQualityForegroundGuard.RunAsync(() => foreground ? lowTraffic with { Sent = 10 * 1024 * 1024 } : baseline,
                async ct =>
                {
                    using var response = await http.GetAsync($"http://127.0.0.1:{((IPEndPoint)bodyListener.LocalEndpoint).Port}/",
                        HttpCompletionOption.ResponseHeadersRead, ct);
                    using var stream = await response.Content.ReadAsStreamAsync(ct);
                    var buffer = new byte[1];
                    await stream.ReadExactlyAsync(buffer, ct);
                    bodyStarted.TrySetResult();
                    await stream.ReadExactlyAsync(buffer, ct);
                    return 1;
                }, false, CancellationToken.None);
            using var peer = await accepted.WaitAsync(TimeSpan.FromSeconds(3));
            await peer.GetStream().WriteAsync(System.Text.Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx"));
            await bodyStarted.Task.WaitAsync(TimeSpan.FromSeconds(3));
            var timer = Stopwatch.StartNew();
            foreground = true;
            try { await probe.WaitAsync(TimeSpan.FromSeconds(3)); throw new Exception("Body stall ignored foreground traffic"); }
            catch (NodeQualityForegroundInterruptedException) { }
            Console.WriteLine($"NODE-QUALITY stalled HTTP body cancelled by user traffic in {timer.Elapsed.TotalMilliseconds:F1} ms PASS");
        }
        finally { bodyListener.Stop(); }

        using (var stop = new CancellationTokenSource())
        {
            var draining = false;
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var probe = NodeQualityForegroundGuard.RunAsync<int>(() => baseline, async ct =>
            {
                entered.TrySetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return 0; }
                finally { draining = true; }
            }, false, stop.Token);
            await entered.Task;
            stop.Cancel();
            try { await probe; throw new Exception("Disconnect swallowed"); }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            Assert(draining, "disconnect left probe active");
        }

        foreach (var mode in new[] { "missing", "reset", "replaced", "read-error" })
        {
            var captured = 0;
            NodeQualityTrafficCounters? Read()
            {
                if (++captured == 1) return baseline;
                return mode switch
                {
                    "missing" => null,
                    "reset" => baseline with { Sent = 0 },
                    "replaced" => baseline with { Identity = "replacement" },
                    _ => throw new IOException("TEST-ONLY counter failure")
                };
            }
            try
            {
                await NodeQualityForegroundGuard.RunAsync<int>(Read,
                    async ct => { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return 0; }, true, CancellationToken.None)
                    .WaitAsync(TimeSpan.FromSeconds(3));
                throw new Exception("Bad counter evidence was retained: " + mode);
            }
            catch (NodeQualityForegroundInterruptedException) { }
        }

        // A yielded round retains already completed candidates, never promotes
        // the unfinished pair, and enters the existing bounded retry cadence.
        using (var stop = new CancellationTokenSource())
        {
            var rounds = 0;
            var waits = 0;
            var trace = new List<string>();
            try
            {
                await MihomoQualityOptimizer.RunRoundsAsync((visited, _) =>
                {
                    if (++rounds == 1) { visited.Add("completed-node"); throw new NodeQualityForegroundInterruptedException(); }
                    Assert(visited.SetEquals(["completed-node"]), "foreground interruption lost sweep progress");
                    return Task.FromResult(true);
                }, (delay, ct) =>
                {
                    Assert(delay == (++waits == 1 ? TimeSpan.FromSeconds(15) : MihomoQualityOptimizer.StableSweepInterval), "yield used wrong retry cadence");
                    if (waits == 2) { stop.Cancel(); ct.ThrowIfCancellationRequested(); }
                    return Task.CompletedTask;
                }, stop.Token, trace.Add);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            Assert(trace.Contains("quality-foreground-yield"), "foreground cancellation logged as node failure");
        }
        Console.WriteLine("NODE-QUALITY foreground guard idle completion, recovery, upload/download, counter reset, missing adapter, cleanup, disconnect and progress PASS");
    }
}
