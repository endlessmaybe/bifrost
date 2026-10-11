using Bifrost.ClientService;

static partial class Fixture
{
    private static async Task VerifiedQualityPair()
    {
        const string provider = "BIFROST-SOURCE-A";
        const string catalogue = "GET /providers/proxies/" + provider;
        var probeQuery = "?url=" + Uri.EscapeDataString(MihomoWindowsContract.StartupProbeUrl)
            + "&timeout=5000&expected=" + MihomoWindowsContract.StartupProbeExpectedStatus;
        var labels = Enumerable.Range(1, 600).Select(i => $"A-{i:000}").ToArray();
        var allowed = labels.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var responses = new Dictionary<string, Response>
        {
            [catalogue] = Json(200, Provider(labels.Select(name => Proxy(name, true, 100)).ToArray())),
            [catalogue + "/A-001/healthcheck" + probeQuery] = new Response(200, "{\"delay\":100}", "application/json", 20),
            [catalogue + "/A-600/healthcheck" + probeQuery] = new Response(200, "{\"delay\":120}", "application/json", 20),
        };
        foreach (var label in labels.Take(32))
            responses[catalogue + $"/{label}/healthcheck" + probeQuery] =
                new Response(200, "{\"delay\":100}", "application/json", 1);
        await using var server = new FixtureServer(Secret, responses);
        using var client = new MihomoControllerClient(server.BaseUri, Secret, TimeSpan.FromSeconds(3));
        var pair = new[] { "A-001", "A-600" };
        var result = await client.MeasureVerifiedCandidatesAsync(provider, pair, allowed, CancellationToken.None);
        Assert(result.Select(item => item.Name).SequenceEqual(pair) && result.All(item => item.Alive), "both members measured");
        Assert(server.RequestCount(catalogue) == 1 && server.StartedDelays == 2 && server.MaxActiveDelays == 1,
            "one full catalogue for two fresh sequential probes");
        await client.MeasureVerifiedCandidatesAsync(provider, pair, allowed, CancellationToken.None);
        Assert(server.RequestCount(catalogue) == 2 && server.StartedDelays == 4, "next pair revalidates fresh membership");
        var startupCohort = labels.Take(32).ToArray();
        var startup = await client.MeasureVerifiedCandidatesAsync(provider, startupCohort, allowed, CancellationToken.None);
        Assert(startup.Select(item => item.Name).SequenceEqual(startupCohort) && startup.All(item => item.Alive),
            "complete 32-member startup cohort is measured instead of rejected by the pair-oriented legacy bound");
        Assert(server.RequestCount(catalogue) == 3 && server.StartedDelays == 36 && server.MaxActiveDelays == 1,
            "startup cohort performs one membership validation and fresh sequential probes");
        foreach (var invalid in new[] { new[] { "FOREIGN" }, new[] { "A-001", "A-001" }, Array.Empty<string>() })
            await ExpectCode(() => client.MeasureVerifiedCandidatesAsync(provider, invalid, allowed, CancellationToken.None), "BF-CANDIDATE-SOURCE-MISMATCH");
        Assert(server.RequestCount(catalogue) == 3 && server.StartedDelays == 36, "invalid request starts no work");
        await ExpectCode(() => client.MeasureVerifiedCandidatesAsync(provider, labels.Take(33).ToArray(), allowed, CancellationToken.None), "BF-CANDIDATE-SOURCE-MISMATCH");
        Assert(server.RequestCount(catalogue) == 3 && server.StartedDelays == 36, "oversized startup cohort starts no work");
        server.SetResponse(catalogue, Json(200, Provider([Proxy("FOREIGN", true, 100)])));
        await ExpectCode(() => client.MeasureVerifiedCandidatesAsync(provider, pair, allowed, CancellationToken.None), "BF-CANDIDATE-SOURCE-MISMATCH");
        Assert(server.StartedDelays == 36, "changed provider cannot authorize a probe");
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        try { await client.MeasureVerifiedCandidatesAsync(provider, pair, allowed, cancel.Token); throw new Exception("Cancellation ignored"); }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
        server.SetResponse(catalogue, Json(200, Provider(labels.Select(name => Proxy(name, true, 100)).ToArray())));
        var shortlist = labels.Take(8).ToArray();
        foreach (var label in shortlist)
            server.SetResponse(catalogue + $"/{label}/healthcheck" + probeQuery,
                new Response(200, "{\"delay\":100}", "application/json", 30));
        var beforeCatalogue = server.RequestCount(catalogue);
        var beforeProbes = server.StartedDelays;
        var fresh = await client.MeasureStartupCandidatesAsync(provider, shortlist, allowed, CancellationToken.None);
        Assert(fresh.Select(item => item.Name).SequenceEqual(shortlist) && fresh.All(item => item.Alive) &&
            server.RequestCount(catalogue) == beforeCatalogue + 1 &&
            server.StartedDelays == beforeProbes + 8 && server.MaxActiveDelays >= 2,
            "startup shortlist validates exact membership once and probes concurrently");
        await ExpectCode(() => client.MeasureStartupCandidatesAsync(provider, labels.Take(9).ToArray(),
            allowed, CancellationToken.None), "BF-CANDIDATE-SOURCE-MISMATCH");
        Console.WriteLine("MIHOMO-QUALITY-PAIR 600-node catalogue supports 32-member startup cohort; fresh sequential probes, membership and cancellation PASS");
    }
}
