using System.Net;
using System.Net.Sockets;
using System.Text;
using Bifrost.ClientService;

static partial class Fixture
{
    private const string Secret = "0123456789abcdef0123456789abcdef";

    private static async Task<int> Main(string[] args)
    {
        if (args is ["--benchmark"]) { await BenchmarkReadback(); return 0; }
        await VerifiedQualityPair();
        await MonitoredReadback();
        await FixedGroupReadback();
        await ValidGroupRoundTrip();
        await ExpandedSourceKeepsEveryMeasurement();
        await StartupMeasurementWaitsForProviderInitialization();
        await LoadedProviderWithoutHistoryIsStillPending();
        await SlowHealthRequestKeepsCompletedCandidates();
        await BoundedBatchesStreamAndCancel();
        await ConnectsBeforeTheLastCandidateAndReadsTheImprovedWinner();
        await RepeatedMeasurementWaitsForFreshProviderHistory();
        await WaitsForMeasuredOptimumInsteadOfFirstHealthyCandidate();
        await WaitsThroughInitialRejectUntilSignedCandidateIsHealthy();
        await RejectDirectFallback();
        await RejectUnknownGroupField();
        await RejectWrongSecretResponsePath();
        Console.WriteLine("MIHOMO-CONTROLLER-FIXTURE PASS");
        return 0;
    }

    private static async Task StartupMeasurementWaitsForProviderInitialization()
    {
        var responses = new Dictionary<string, Response>
        {
            ["GET /providers/proxies/BIFROST-SOURCE-A/healthcheck"] = new Response(204, "", "text/plain"),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(Array.Empty<string>())),
        };
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var measurement = client.MeasureGroupUntilUsableAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A",
            new[] { "A-01", "A-02" }, TimeSpan.FromSeconds(2), CancellationToken.None);
        await Task.Delay(150);
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200,
            Provider(new[] { Proxy("A-01", false, 0), Proxy("A-02", true, 207) })));
        var measured = await measurement;
        Assert(measured.Count(candidate => candidate.Alive) == 1 && measured.Single(candidate => candidate.Name == "A-02").DelayMs == 207,
            "startup consumes partial provider health instead of classifying every node dead when one group member times out");
    }

    private static async Task ExpandedSourceKeepsEveryMeasurement()
    {
        foreach (var count in new[] { 169, 300, 600 })
        {
            var labels = Enumerable.Range(1, count).Select(index => $"A-{index}").ToArray();
            await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
            {
                ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200,
                    Provider(labels.Select((label, index) => Proxy(label, index % 3 != 0, index % 3 != 0 ? 100 + index : 0)).ToArray())),
            });
            using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
            var result = await client.ReadCandidatesAsync("BIFROST-SOURCE-A", labels, CancellationToken.None);
            Assert(result.Count == count && result.Count(item => item.Alive) == count - (count + 2) / 3,
                "expanded source preserves individual successes and failures");
            var wrong = labels.ToArray(); wrong[^1] = "FOREIGN-1";
            await ExpectCode(() => client.ReadCandidatesAsync("BIFROST-SOURCE-A", wrong, CancellationToken.None), "BF-CANDIDATE-SOURCE-MISMATCH");
        }
        var oversized = Enumerable.Range(1, 601).Select(index => $"A-{index}").ToArray();
        await using var oversizedServer = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(oversized.Select(label => Proxy(label, true, 200)).ToArray())),
        });
        using var bounded = new MihomoControllerClient(oversizedServer.BaseUri, Secret, TimeSpan.FromSeconds(2));
        await ExpectCode(() => bounded.ReadCandidatesAsync("BIFROST-SOURCE-A", oversized.Take(600).ToArray(), CancellationToken.None), "BF-MIHOMO-CONTROLLER-JSON");
    }

    private static async Task ConnectsBeforeTheLastCandidateAndReadsTheImprovedWinner()
    {
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["DELETE /proxies/BIFROST-SMART-A"] = new Response(204, "", "text/plain"),
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("A-01", new[] { "A-01", "A-02" })),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(new[] { Proxy("A-01", true, 280), Proxy("A-02", false, 0) })),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var first = await client.WaitForFirstUsableAutomaticGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A",
            new HashSet<string> { "A-01", "A-02" }, TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert(first.Now == "A-01" && !first.Candidates.Single(item => item.Name == "A-02").Alive,
            "first usable connection does not await the remaining candidate");
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200, Provider(new[] { Proxy("A-01", true, 280), Proxy("A-02", true, 120) })));
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-02", new[] { "A-01", "A-02" })));
        var improved = await client.ReadGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A", CancellationToken.None);
        Assert(improved.Now == "A-02", "native improved selection is consumed through the same controller session");
    }

    private static async Task BoundedBatchesStreamAndCancel()
    {
        var labels = Enumerable.Range(1, 25).Select(index => $"A-{index:00}").ToArray();
        var responses = new Dictionary<string, Response>
        {
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(labels.Select(label => Proxy(label, false, 0)).ToArray())),
        };
        foreach (var label in labels)
            responses[$"GET /providers/proxies/BIFROST-SOURCE-A/{label}/healthcheck?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000&expected=204"] =
                new Response(label == "A-25" ? 504 : 200, label == "A-25" ? "{}" : "{\"delay\":203}", "application/json", label == "A-01" ? 30 : 150);
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var progress = new List<string>();
        var measured = await client.MeasureCandidatesInBatchesAsync("BIFROST-SOURCE-A", labels, item =>
        {
            progress.Add(item.Name);
            if (progress.Count == 1) Assert(server.CompletedDelays < labels.Length, "first result streams before the remaining batches");
            return Task.CompletedTask;
        }, CancellationToken.None);
        Assert(measured.Count == 25 && measured.Count(item => item.Alive) == 24 && progress.Distinct().Count() == 25,
            "all batches retain successful and timed-out results exactly once");
        Assert(server.MaxActiveDelays <= 12 && server.StartedDelays == 25, "at most twelve candidate requests run concurrently");
        using var cancel = new CancellationTokenSource();
        var startedBefore = server.StartedDelays;
        try
        {
            await client.MeasureCandidatesInBatchesAsync("BIFROST-SOURCE-A", labels, item => { cancel.Cancel(); return Task.CompletedTask; }, cancel.Token);
            throw new InvalidOperationException("fixture assertion failed: cancellation ignored");
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
        Assert(server.StartedDelays - startedBefore <= 12, "cancellation never starts the next batch");
    }

    private static async Task SlowHealthRequestKeepsCompletedCandidates()
    {
        var responses = new Dictionary<string, Response>
        {
            ["GET /providers/proxies/BIFROST-SOURCE-A/healthcheck"] = new Response(204, "", "text/plain", 1500),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(new[] { Proxy("A-01", false, 0), Proxy("A-02", false, 0) })),
        };
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var measurement = client.MeasureGroupUntilUsableAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A", new[] { "A-01", "A-02" }, TimeSpan.FromSeconds(1), CancellationToken.None);
        await Task.Delay(150);
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200, Provider(new[] { Proxy("A-01", true, 203, "2026-08-25T00:00:01Z"), Proxy("A-02", false, 0) })));
        var result = await measurement;
        Assert(result.Single(item => item.Name == "A-01").DelayMs == 203 && !result.Single(item => item.Name == "A-02").Alive,
            "a slow health request cannot erase completed candidates at the deadline");
    }

    private static async Task LoadedProviderWithoutHistoryIsStillPending()
    {
        var responses = new Dictionary<string, Response>
        {
            ["GET /providers/proxies/BIFROST-SOURCE-A/healthcheck"] = new Response(204, "", "text/plain"),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(Array.Empty<string>())),
        };
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var measurement = client.MeasureGroupUntilUsableAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A", new[] { "A-01" }, TimeSpan.FromSeconds(2), CancellationToken.None);
        await Task.Delay(120);
        var unmeasured = System.Text.Json.Nodes.JsonNode.Parse(Proxy("A-01", false, 0))!;
        unmeasured["history"] = new System.Text.Json.Nodes.JsonArray();
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200, Provider(new[] { unmeasured.ToJsonString() })));
        await Task.Delay(150);
        Assert(!measurement.IsCompleted, "provider membership alone is not a completed health round");
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200, Provider(new[] { Proxy("A-01", true, 203) })));
        Assert((await measurement).Single().DelayMs == 203, "first actual history entry finishes initialization");
    }

    private static async Task RepeatedMeasurementWaitsForFreshProviderHistory()
    {
        var responses = new Dictionary<string, Response>
        {
            ["GET /providers/proxies/BIFROST-SOURCE-A/healthcheck"] = new Response(204, "", "text/plain"),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(new[]
            {
                Proxy("A-01", true, 211, "2026-08-25T00:00:00Z"),
                Proxy("A-02", true, 237, "2026-08-25T00:00:00Z"),
            })),
        };
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var measurement = client.MeasureGroupUntilUsableAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A",
            new[] { "A-01", "A-02" }, TimeSpan.FromSeconds(2), CancellationToken.None);
        await Task.Delay(150);
        Assert(!measurement.IsCompleted, "a manual retest must not reuse the previous positive provider history");
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200, Provider(new[]
        {
            Proxy("A-01", true, 211, "2026-08-25T00:00:01Z"),
            Proxy("A-02", true, 237, "2026-08-25T00:00:01Z"),
        })));
        var measured = await measurement;
        Assert(measured.Single(candidate => candidate.Name == "A-01").DelayMs == 211 &&
               measured.Single(candidate => candidate.Name == "A-02").DelayMs == 237,
            "a manual retest accepts a fresh history entry even when the measured delays are identical");
    }

    private static async Task WaitsForMeasuredOptimumInsteadOfFirstHealthyCandidate()
    {
        var responses = new Dictionary<string, Response>
        {
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("A-01", new[] { "A-01", "A-02", "A-03" })),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200,
                Provider(new[] { Proxy("A-01", true, 281), Proxy("A-02", true, 202), Proxy("A-03", true, 219) })),
        };
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var measured = new[]
        {
            new MihomoProxyHealth("A-01", true, 281),
            new MihomoProxyHealth("A-02", true, 202),
            new MihomoProxyHealth("A-03", true, 219),
        };
        var wait = client.WaitForOptimizedGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "A-01", "A-02", "A-03" }, measured,
            toleranceMilliseconds: 50, TimeSpan.FromSeconds(1), CancellationToken.None);
        await Task.Delay(100);
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-03", new[] { "A-01", "A-02", "A-03" })));
        var group = await wait;
        Assert(group.Now == "A-03", "URLTest accepts a measured candidate inside the configured tolerance window");
    }

    private static async Task WaitsThroughInitialRejectUntilSignedCandidateIsHealthy()
    {
        var responses = new Dictionary<string, Response>
        {
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("REJECT", new[] { "A-01", "A-02" })),
        };
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var wait = client.WaitForHealthyGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "A-01", "A-02" }, TimeSpan.FromSeconds(1), CancellationToken.None);
        await Task.Delay(100);
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-02", new[] { "A-01", "A-02" })));
        server.SetResponse("GET /providers/proxies/BIFROST-SOURCE-A", Json(200,
            Provider(new[] { Proxy("A-01", false, 0), Proxy("A-02", true, 205) })));
        var group = await wait;
        Assert(group.Now == "A-02" && group.Candidates.Single(item => item.Name == "A-02").Alive,
            "initial reject is a wait state, not a terminal direct fallback");
    }

    private static async Task ValidGroupRoundTrip()
    {
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /version"] = Json(200, "{\"meta\":true,\"version\":\"v1.19.30\"}"),
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("A-02", new[] { "A-01", "A-02" })),
            ["GET /providers/proxies/BIFROST-SOURCE-A"] = Json(200, Provider(new[] { Proxy("A-01", false, 0), Proxy("A-02", true, 203) })),
            ["GET /providers/proxies/BIFROST-SOURCE-A/healthcheck"] = new Response(204, "", "text/plain"),
            ["PUT /providers/proxies/BIFROST-SOURCE-A"] = new Response(204, "", "text/plain"),
            ["PUT /proxies/BIFROST-FIXED-A"] = new Response(204, "", "text/plain"),
            ["GET /group/BIFROST-SMART-A/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=5000&expected=204"] =
                Json(200, "{\"A-01\":0,\"A-02\":203}"),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        await client.WaitReadyAsync(CancellationToken.None);
        await client.TriggerProviderHealthAsync("BIFROST-SOURCE-A", CancellationToken.None);
        await client.RefreshProviderAsync("BIFROST-SOURCE-A", CancellationToken.None);
        await client.SelectAsync("BIFROST-FIXED-A", "A-02", CancellationToken.None);
        var measured = await client.MeasureGroupAsync("BIFROST-SMART-A", new[] { "A-01", "A-02" }, CancellationToken.None);
        Assert(measured.Single(item => item.Name == "A-02") is { Alive: true, DelayMs: 203 }, "group delay uses official URLTest endpoint");
        var state = await client.ReadGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A", CancellationToken.None);
        Assert(state.Now == "A-02" && state.Candidates.Count == 2, "group readback");
        Assert(state.Candidates.Single(candidate => candidate.Name == "A-02") is { Alive: true, DelayMs: 203 }, "candidate health");
        Assert(server.AuthorizationFailures == 0, "bearer secret sent on every request");
    }

    private static async Task RejectDirectFallback()
    {
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("DIRECT", new[] { "A-01" })),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        await ExpectCode(() => client.ReadGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A", CancellationToken.None), "BF-MIHOMO-DIRECT-FALLBACK");
    }

    private static async Task RejectUnknownGroupField()
    {
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("A-01", new[] { "A-01" })[..^1] + ",\"unexpected\":true}"),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        await ExpectCode(() => client.ReadGroupAsync("BIFROST-SMART-A", "BIFROST-SOURCE-A", CancellationToken.None), "BF-MIHOMO-CONTROLLER-JSON");
    }

    private static async Task RejectWrongSecretResponsePath()
    {
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /version"] = Json(200, "{\"meta\":true,\"version\":\"v1.19.30\"}"),
        });
        using var client = new MihomoControllerClient(server.BaseUri, "fedcba9876543210fedcba9876543210", TimeSpan.FromSeconds(2));
        await ExpectCode(() => client.WaitReadyAsync(CancellationToken.None), "BF-MIHOMO-CONTROLLER-AUTH");
    }

    private static string Group(string now, IReadOnlyList<string> all) =>
        $"{{\"alive\":true,\"all\":[{string.Join(',', all.Select(value => $"\"{value}\""))}],\"dialer-proxy\":\"\",\"emptyFallback\":\"REJECT\",\"expectedStatus\":\"204\",\"extra\":{{}},\"fixed\":\"\",\"hidden\":false,\"history\":[],\"icon\":\"\",\"interface\":\"\",\"mptcp\":false,\"name\":\"BIFROST-SMART-A\",\"now\":\"{now}\",\"provider-name\":\"\",\"routing-mark\":0,\"smux\":false,\"testUrl\":\"https://www.gstatic.com/generate_204\",\"tfo\":false,\"type\":\"URLTest\",\"udp\":true,\"uot\":false,\"xudp\":false}}";

    private static string Proxy(string name, bool alive, int delay, string time = "2026-08-25T00:00:00Z") =>
        $"{{\"alive\":{alive.ToString().ToLowerInvariant()},\"dialer-proxy\":\"\",\"extra\":{{}},\"history\":[{{\"time\":\"{time}\",\"delay\":{delay}}}],\"id\":\"00000000-0000-0000-0000-000000000001\",\"interface\":\"TEST-ONLY\",\"mptcp\":false,\"name\":\"{name}\",\"provider-name\":\"BIFROST-SOURCE-A\",\"routing-mark\":0,\"smux\":false,\"tfo\":false,\"type\":\"Vmess\",\"udp\":true,\"uot\":true,\"xudp\":false}}";

    private static string Provider(IReadOnlyList<string> proxies) =>
        $"{{\"name\":\"BIFROST-SOURCE-A\",\"type\":\"Proxy\",\"vehicleType\":\"File\",\"proxies\":[{string.Join(',', proxies)}],\"testUrl\":\"https://www.gstatic.com/generate_204\",\"expectedStatus\":\"204\",\"updatedAt\":\"2026-08-25T00:00:00Z\"}}";

    private static Response Json(int status, string body) => new(status, body, "application/json");

    private static async Task ExpectCode(Func<Task> action, string code)
    {
        try { await action(); }
        catch (Exception error) when (error.Message == code) { return; }
        throw new InvalidOperationException("expected " + code);
    }

    private static void Assert(bool value, string label)
    {
        if (!value) throw new InvalidOperationException("fixture assertion failed: " + label);
    }
}

internal sealed record Response(int Status, string Body, string ContentType, int DelayMilliseconds = 0);

internal sealed class FixtureServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly string _secret;
    private readonly Dictionary<string, Response> _responses;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _owner;
    internal int AuthorizationFailures;
    internal int StartedDelays, CompletedDelays, MaxActiveDelays;
    private readonly Dictionary<string, int> _requestCounts = new(StringComparer.Ordinal);
    internal int RequestCount(string key) { lock (_responses) return _requestCounts.GetValueOrDefault(key); }
    private int _activeDelays;
    internal Uri BaseUri { get; }

    internal FixtureServer(string secret, IReadOnlyDictionary<string, Response> responses)
    {
        _secret = secret; _responses = new Dictionary<string, Response>(responses, StringComparer.Ordinal);
        _listener = new TcpListener(IPAddress.Loopback, 0); _listener.Start();
        BaseUri = new Uri($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/");
        _owner = AcceptLoop();
    }

    internal void SetResponse(string key, Response response)
    {
        lock (_responses) _responses[key] = response;
    }

    private async Task AcceptLoop()
    {
        while (!_lifetime.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_lifetime.Token); }
            catch (OperationCanceledException) { return; }
            _ = Handle(client);
        }
    }

    private async Task Handle(TcpClient client)
    {
        using (client)
        {
            var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            var request = await reader.ReadLineAsync() ?? "";
            var authorized = false;
            while (await reader.ReadLineAsync() is { Length: > 0 } header)
                if (header == "Authorization: Bearer " + _secret) authorized = true;
            if (!authorized) Interlocked.Increment(ref AuthorizationFailures);
            var key = request.Split(' ').Take(2).Aggregate((left, right) => left + " " + right);
            Response response;
            lock (_responses)
            {
                _requestCounts[key] = _requestCounts.GetValueOrDefault(key) + 1;
                response = !authorized ? new Response(401, "", "text/plain") :
                    _responses.TryGetValue(key, out var configured) ? configured : new Response(404, "", "text/plain");
            }
            var body = Encoding.UTF8.GetBytes(response.Body);
            var isDelay = key.Contains("/healthcheck?", StringComparison.Ordinal);
            if (isDelay)
            {
                Interlocked.Increment(ref StartedDelays);
                var active = Interlocked.Increment(ref _activeDelays);
                lock (_responses) MaxActiveDelays = Math.Max(MaxActiveDelays, active);
            }
            if (response.DelayMilliseconds > 0) await Task.Delay(response.DelayMilliseconds);
            if (isDelay) { Interlocked.Decrement(ref _activeDelays); Interlocked.Increment(ref CompletedDelays); }
            var head = Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} {(response.Status == 204 ? "No Content" : response.Status == 200 ? "OK" : response.Status == 401 ? "Unauthorized" : "Not Found")}\r\nContent-Type: {response.ContentType}\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
            try { await stream.WriteAsync(head); if (body.Length > 0) await stream.WriteAsync(body); }
            catch (IOException) when (response.DelayMilliseconds > 0) { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel(); _listener.Stop();
        try { await _owner; } catch { }
        _lifetime.Dispose();
    }
}
