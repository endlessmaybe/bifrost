using System.Diagnostics;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

internal static class LiveQualityFixture
{
    internal static async Task Run(string signedPath, string underlayPath, string binary, string scratch,
        string sourceCode = "A", string? candidateCsv = null)
    {
        Directory.CreateDirectory(scratch);
        var signed = JsonNode.Parse(File.ReadAllText(signedPath))!.AsObject();
        var underlay = JsonNode.Parse(File.ReadAllText(underlayPath))!["interface-name"]!.GetValue<string>();
        var secret = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
        var policy = ApplicationPolicySnapshot.Create("smart", "none", [], [], new string('d',32));
        sourceCode = sourceCode.Trim().ToUpperInvariant();
        if (sourceCode is not ("A" or "B")) throw new ArgumentOutOfRangeException(nameof(sourceCode));
        var package = MihomoConfigCompiler.Compile(new(signed,sourceCode,"direct-vmess","smart",null,"default",policy,underlay,24792,secret,"bifrost1",$"providers/{sourceCode}.json",null));
        var runtime = MihomoQualityOptimizer.Prepare(package);
        if(runtime.Port <= 0) throw new Exception("Quality transport missing");
        if(runtime.StartupLanes.Count != MihomoQualityOptimizer.StartupLaneCount ||
            runtime.StartupLanes.Select(lane => lane.Port).Distinct().Count() != runtime.StartupLanes.Count ||
            runtime.StartupLanes.Select(lane => lane.Group).Distinct().Count() != runtime.StartupLanes.Count)
            throw new Exception("Startup probe lanes share a listener or selection group");
        var main = JsonNode.Parse(runtime.Package.MainConfig)!.AsObject();
        main["tun"]!["enable"] = false; main["dns"]!["enable"] = false;
        Directory.CreateDirectory(Path.Combine(scratch,"providers"));
        File.WriteAllBytes(Path.Combine(scratch,$"providers/{sourceCode}.json"),package.Provider);
        File.WriteAllText(Path.Combine(scratch,"config.private.json"),main.ToJsonString());
        foreach(var name in new[]{"GeoSite.dat","geoip.metadb"}) File.Copy(Path.Combine(Path.GetDirectoryName(binary)!,name),Path.Combine(scratch,name),true);
        var start = new ProcessStartInfo(binary) { WorkingDirectory=scratch,UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true };
        foreach(var arg in new[]{"-d",scratch,"-f",Path.Combine(scratch,"config.private.json")})start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr=process.StandardError.ReadToEndAsync();
        // Keep the live harness slightly wider than the shipping startup
        // qualification budget. A complete 29-node source is intentionally
        // screened before finalist capacity confirmation, so the old 100 s
        // fixture deadline could cancel valid production work and produce a
        // false negative.
        using var deadline = new CancellationTokenSource(
            MihomoQualityOptimizer.StartupQualificationTimeout + TimeSpan.FromSeconds(30));
        using var controller = new MihomoControllerClient(new Uri("http://127.0.0.1:24792/"),secret,TimeSpan.FromSeconds(8));
        try {
            await controller.WaitReadyAsync(deadline.Token);
            var group = await controller.WaitForFirstUsableAutomaticGroupAsync(package.ActiveGroup,package.ProviderName,package.AllowedCandidates,TimeSpan.FromSeconds(30),deadline.Token);
            await controller.SelectAsync(package.ActiveGroup,group.Now,deadline.Token);
            await Task.Delay(8000,deadline.Token);
            group=await controller.ReadGroupAsync(package.ActiveGroup,package.ProviderName,deadline.Token);
            var requested = (candidateCsv ?? string.Empty).Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
            var candidates = candidateCsv == "-" ? [] : requested.Length > 0
                ? requested.Select(name => group.Candidates.Single(x => x.Name == name && x.Alive && x.DelayMs > 0)).ToArray()
                : group.Candidates.Where(x=>x.Alive&&x.DelayMs>0).OrderBy(x=>x.DelayMs).Take(3).ToArray();
            var results = new JsonArray();
            foreach(var candidate in candidates) {
                await controller.SelectAsync(MihomoQualityOptimizer.ProbeGroup,candidate.Name,deadline.Token);
                var screen=await MihomoQualityOptimizer.MeasureAsync(runtime.Port,runtime.Password,deadline.Token,
                    MihomoQualityOptimizer.StartupScreenBytes,results.Count,adaptive:false,excludeWarmup:false);
                var final=await MihomoQualityOptimizer.MeasureAsync(runtime.Port,runtime.Password,deadline.Token,
                    MihomoQualityOptimizer.StartupFinalBytes,100+results.Count,adaptive:false,excludeWarmup:false);
                var readback=await controller.ReadGroupAsync(package.ActiveGroup,package.ProviderName,deadline.Token);
                if(readback.Now!=group.Now)throw new Exception("Measurement changed active selection");
                results.Add(new JsonObject{["candidate"]=candidate.Name,
                    ["screenOk"]=screen.Ok,["screenBps"]=screen.BytesPerSecond,["screenLatencyMs"]=screen.LatencyMs,
                    ["finalOk"]=final.Ok,["finalBps"]=final.BytesPerSecond,["finalLatencyMs"]=final.LatencyMs,
                    ["activeUnchanged"]=true});
            }
            var startupTrace = new System.Collections.Concurrent.ConcurrentQueue<string>();
            var qualified = await MihomoQualityOptimizer.QualifyStartupAsync(runtime,controller,group,
                value => startupTrace.Enqueue(value),deadline.Token);
            await controller.SelectAsync(MihomoQualityOptimizer.ProbeGroup, qualified.Now, deadline.Token);
            var privatePath = await MihomoQualityOptimizer.MeasureParallelAsync(runtime.Port, runtime.Password,
                deadline.Token, MihomoQualityOptimizer.ComparisonBytes, 2);
            var userPath = await MihomoQualityOptimizer.MeasureParallelAsync(24793, runtime.Password,
                deadline.Token, MihomoQualityOptimizer.ComparisonBytes, 2);
            File.WriteAllText(Path.Combine(scratch,"result.json"),new JsonObject{
                ["status"]="passed",["hostOnly"]=true,["tunDisabled"]=true,["initialCandidate"]=group.Now,
                ["qualifiedCandidate"]=qualified.Now,["results"]=results,
                ["privatePathOk"]=privatePath.Ok,["privatePathBps"]=privatePath.BytesPerSecond,
                ["userPathOk"]=userPath.Ok,["userPathBps"]=userPath.BytesPerSecond,
                ["startupTrace"]=new JsonArray(startupTrace.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray())}.ToJsonString());
            if(candidates.Length > 0 && !results.OfType<JsonObject>().Any(x=>x["finalOk"]!.GetValue<bool>())) throw new Exception("No sustained end-to-end payload measurement succeeded");
            Console.WriteLine($"LIVE NODE QUALITY PASS: sustained payload through selected candidate, active group unchanged; startup {group.Now}->{qualified.Now}");
        } finally {
            if(!process.HasExited)process.Kill(true);
            await process.WaitForExitAsync();
            File.WriteAllText(Path.Combine(scratch,"core.private.log"),(await stdout)+(await stderr));
        }
    }
}
