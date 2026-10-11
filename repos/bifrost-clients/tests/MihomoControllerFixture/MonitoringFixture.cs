using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

static partial class Fixture
{
    private static async Task MonitoredReadback()
    {
        var allowed = new HashSet<string>(["A-01", "A-02"], StringComparer.OrdinalIgnoreCase);
        const string providerPath = "GET /providers/proxies/BIFROST-SOURCE-A";
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group("A-01", allowed.ToArray())),
            ["GET /proxies/BIFROST-CHATGPT-A"] = Json(200, Group("A-01", allowed.ToArray()).Replace("BIFROST-SMART-A", "BIFROST-CHATGPT-A")),
            [providerPath] = Json(200, Provider([Proxy("A-01", true, 100), Proxy("A-02", true, 200)])),
            [providerPath + "/A-01"] = Json(200, Proxy("A-01", true, 100)),
            [providerPath + "/A-02"] = Json(200, Proxy("A-02", true, 200)),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        Task<MihomoGroupState> Read(string group = "BIFROST-SMART-A", bool force = false, string? pin = null) =>
            client.ReadMonitoredGroupAsync(group, "BIFROST-SOURCE-A", allowed, CancellationToken.None, force, pin);
        var original = await Read();
        await Read("BIFROST-CHATGPT-A");
        for (var i = 0; i < 10; i++) await Read();
        Assert(server.RequestCount(providerPath) == 1, "two groups and unchanged ticks share the provider snapshot");
        Assert(server.RequestCount(providerPath + "/A-01") == 11, "selected health stays fresh every tick");
        server.SetResponse(providerPath + "/A-01", Json(200, Proxy("A-01", false, 0)));
        var failed = await Read();
        Assert(!failed.Candidates.Single(x => x.Name == "A-01").Alive && original.Candidates[0].Alive,
            "active failure is immediate and cannot mutate an earlier snapshot");
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-02", allowed.ToArray())));
        server.SetResponse(providerPath, Json(200, Provider([Proxy("A-01", false, 0), Proxy("A-02", true, 120)])));
        var switched = await Read();
        Assert(switched.Now == "A-02" && server.RequestCount(providerPath) == 2, "native switch immediately refreshes full membership");
        server.SetResponse(providerPath + "/A-01", Json(200, Proxy("A-01", true, 90)));
        var pinned = await Read(pin: "A-01");
        Assert(pinned.Candidates.Single(x => x.Name == "A-01").DelayMs == 90, "a non-selected affinity pin also receives fresh health");
        await Read(force: true);
        Assert(server.RequestCount(providerPath) == 3, "explicit refresh bypasses catalogue reuse");
        await Task.Delay(MihomoControllerClient.ProviderReadbackInterval + TimeSpan.FromMilliseconds(30));
        await Read();
        Assert(server.RequestCount(providerPath) == 4, "catalogue is refreshed when its bounded lifetime expires");
        await client.ReadCandidatesAsync("BIFROST-SOURCE-A", allowed.ToArray(), CancellationToken.None);
        Assert(server.RequestCount(providerPath) == 5, "measurement reads never consume the monitoring cache");

        server.SetResponse(providerPath + "/A-02", Json(200, Proxy("FOREIGN", true, 100)));
        await ExpectCode(() => Read(), "BF-CANDIDATE-SOURCE-MISMATCH");
        await Read();
        Assert(server.RequestCount(providerPath) == 6, "invalid member response evicts cached evidence");
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("DIRECT", allowed.ToArray())));
        await ExpectCode(() => Read(), "BF-MIHOMO-DIRECT-FALLBACK");
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-01", ["A-01", "FOREIGN"])));
        await ExpectCode(() => Read(), "BF-CANDIDATE-SOURCE-MISMATCH");
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-01", allowed.ToArray())[..^1] + ",\"now\":\"A-01\"}"));
        await ExpectCode(() => Read(), "BF-MIHOMO-CONTROLLER-JSON");
        server.SetResponse("GET /proxies/BIFROST-SMART-A", Json(200, Group("A-01", allowed.ToArray())));
        foreach (var invalid in new[] {
            Proxy("A-01", true, 100).Replace("\"delay\":100", "\"delay\":100,\"delay\":200"),
            Proxy("A-01", true, 100).Replace("\"delay\":100", "\"unexpected\":100"),
            Proxy("A-01", true, 100).Replace("2026-08-25T00:00:00Z", "") })
        {
            server.SetResponse(providerPath, Json(200, Provider([invalid, Proxy("A-02", true, 200)])));
            await ExpectCode(() => Read(force: true), "BF-MIHOMO-CONTROLLER-JSON");
        }
        Console.WriteLine("MIHOMO-MONITOR shared catalogue, fresh active/pin, native switch, strict validation PASS");
    }

    private static async Task BenchmarkReadback()
    {
        var labels = Enumerable.Range(1, 600).Select(i => $"A-{i:000}").ToArray();
        var proxies = labels.Select(name => {
            var proxy = JsonNode.Parse(Proxy(name, true, 100))!;
            proxy["history"] = new JsonArray(Enumerable.Range(0, 16).Select(i => (JsonNode)new JsonObject {
                ["time"] = $"2026-09-10T00:00:{i:00}Z", ["delay"] = 100 + i }).ToArray());
            return proxy.ToJsonString();
        }).ToArray();
        const string providerPath = "GET /providers/proxies/BIFROST-SOURCE-A";
        var provider = Provider(proxies);
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            ["GET /proxies/BIFROST-SMART-A"] = Json(200, Group(labels[0], labels)),
            ["GET /proxies/BIFROST-CHATGPT-A"] = Json(200, Group(labels[0], labels).Replace("BIFROST-SMART-A", "BIFROST-CHATGPT-A")),
            [providerPath] = Json(200, provider), [providerPath + "/" + labels[0]] = Json(200, proxies[0]),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(5));
        var allowed = labels.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var monitored = typeof(MihomoControllerClient).GetMethod("ReadMonitoredGroupAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        async Task Tick() {
            foreach (var group in new[] { "BIFROST-SMART-A", "BIFROST-CHATGPT-A" })
                if (monitored is null) await client.ReadGroupAsync(group, "BIFROST-SOURCE-A", CancellationToken.None);
                else await (Task<MihomoGroupState>)monitored.Invoke(client, [group, "BIFROST-SOURCE-A", allowed, CancellationToken.None, false, null, null])!;
        }
        for (var i = 0; i < 3; i++) await Tick();
        var allocated = GC.GetTotalAllocatedBytes(true);
        var cpu = Process.GetCurrentProcess().TotalProcessorTime;
        var timer = Stopwatch.StartNew();
        for (var i = 0; i < 60; i++) await Tick();
        Console.WriteLine(JsonSerializer.Serialize(new { monitored = monitored is not null, ticks = 60, nodes = 600, history = 16,
            elapsed_ms = timer.Elapsed.TotalMilliseconds, cpu_ms = (Process.GetCurrentProcess().TotalProcessorTime - cpu).TotalMilliseconds,
            allocated_bytes = GC.GetTotalAllocatedBytes(true) - allocated, provider_bytes = System.Text.Encoding.UTF8.GetByteCount(provider),
            provider_requests = server.RequestCount(providerPath) }));
    }
}
