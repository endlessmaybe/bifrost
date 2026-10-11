using Bifrost.ClientService;

static partial class Fixture
{
    private static async Task FixedGroupReadback()
    {
        var allowed = new HashSet<string>(["A-01", "A-02"], StringComparer.OrdinalIgnoreCase);
        const string groupPath = "GET /proxies/BIFROST-FIXED-A";
        const string providerPath = "GET /providers/proxies/BIFROST-SOURCE-A";
        string Fixed(string selected, string[] members) => Group(selected, members)
            .Replace("BIFROST-SMART-A", "BIFROST-FIXED-A").Replace("URLTest", "Selector")
            .Replace("\"expectedStatus\":\"204\",", "").Replace("\"fixed\":\"\",", "");
        var healthPath = providerPath + "/A-02/healthcheck?url=" + Uri.EscapeDataString(MihomoWindowsContract.StartupProbeUrl)
            + "&timeout=5000&expected=" + MihomoWindowsContract.StartupProbeExpectedStatus;
        await using var server = new FixtureServer(Secret, new Dictionary<string, Response>
        {
            [groupPath] = Json(200, Fixed("A-02", ["A-02"])),
            [providerPath] = Json(200, Provider([Proxy("A-01", true, 50), Proxy("A-02", true, 1500)])),
            [providerPath + "/A-02"] = Json(200, Proxy("A-02", true, 1500)),
            [healthPath] = Json(200, "{\"delay\":1500}"),
        });
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(2));
        var ready = await client.WaitForHealthyGroupAsync("BIFROST-FIXED-A", "BIFROST-SOURCE-A", allowed,
            TimeSpan.FromSeconds(1), CancellationToken.None, fixedCandidate: "A-02");
        Assert(ready.Now == "A-02" && ready.Candidates.Count == 2, "Global startup confused the one-member selector with the full provider");
        Task<MihomoGroupState> Read() => client.ReadMonitoredGroupAsync("BIFROST-FIXED-A", "BIFROST-SOURCE-A",
            allowed, CancellationToken.None, fixedCandidate: "A-02");
        for (var tick = 0; tick < 10; tick++)
        {
            var status = await Read();
            Assert(status.Now == "A-02" && status.Candidates.Count == 2, "Healthy global status was blocked");
        }
        var measured = await client.MeasureVerifiedCandidateAsync("BIFROST-SOURCE-A", "A-02", allowed, CancellationToken.None);
        Assert(measured.Alive && measured.DelayMs == 1500 && server.RequestCount(healthPath) == 1,
            "Reconnect hint did not test only its verified provider member");
        foreach (var wrong in new[] { Fixed("A-01", ["A-01"]), Fixed("A-02", ["A-01", "A-02"]), Fixed("FOREIGN", ["FOREIGN"]) })
        {
            server.SetResponse(groupPath, Json(200, wrong));
            await ExpectCode(Read, "BF-CANDIDATE-SOURCE-MISMATCH");
        }
        server.SetResponse(groupPath, Json(200, Fixed("A-02", ["A-02"])));
        server.SetResponse(providerPath, Json(200, Provider([Proxy("FOREIGN", true, 50), Proxy("A-02", true, 1500)])));
        await ExpectCode(Read, "BF-CANDIDATE-SOURCE-MISMATCH");
        await ExpectCode(() => client.MeasureVerifiedCandidateAsync("BIFROST-SOURCE-A", "A-02", allowed, CancellationToken.None), "BF-CANDIDATE-SOURCE-MISMATCH");
        Console.WriteLine("MIHOMO-GLOBAL startup and repeated monitoring keep fixed healthy node; exact fixed choice and full provider remain enforced PASS");
    }
}
