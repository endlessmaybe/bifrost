using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

static class Fixture
{
    private static async Task<int> Main()
    {
        var sourceBinary = Environment.GetEnvironmentVariable("BIFROST_MIHOMO_EXE")
            ?? throw new InvalidOperationException("BIFROST_MIHOMO_EXE required");
        var scratch = Path.Combine(Path.GetTempPath(), "bifrost-mihomo-health-" + Guid.NewGuid().ToString("N"));
        var complete = false;
        try
        {
            var installedGeneration = Environment.GetEnvironmentVariable("BIFROST_GENERATION_ROOT");
            var generation = string.IsNullOrWhiteSpace(installedGeneration)
                ? Path.Combine(scratch, "generation")
                : Path.GetFullPath(installedGeneration);
            string binary;
            if (string.IsNullOrWhiteSpace(installedGeneration))
            {
                Directory.CreateDirectory(Path.Combine(generation, "cores"));
                binary = Path.Combine(generation, "cores", "mihomo.exe");
                CopyRuntimeArtifacts(sourceBinary, Path.GetDirectoryName(binary)!);
            }
            else
            {
                binary = Path.GetFullPath(sourceBinary);
                Assert(binary.StartsWith(generation.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase), "installed core belongs to supplied generation root");
            }
            var realConfigFile = Environment.GetEnvironmentVariable("BIFROST_SIGNED_CONFIG_FILE");
            var realConfig = !string.IsNullOrWhiteSpace(realConfigFile);
            var config = realConfig
                ? JsonNode.Parse(File.ReadAllText(Path.GetFullPath(realConfigFile!))) as JsonObject
                    ?? throw new InvalidDataException("real signed config must be a JSON object")
                : SignedConfig();
            var source = (config["sources"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(item =>
                string.Equals(item["code"]?.GetValue<string>(), "A", StringComparison.OrdinalIgnoreCase) &&
                item["configured"]?.GetValue<bool>() == true)
                ?? throw new InvalidDataException("fixture source A missing");
            var candidateLabels = (source["candidates"] as JsonArray)?.OfType<JsonObject>()
                .Select(item => item["label"]?.GetValue<string>())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Select(item => item!)
                .ToArray() ?? Array.Empty<string>();
            Assert(candidateLabels.Length is >= 1 and <= 300 && candidateLabels.Distinct(StringComparer.OrdinalIgnoreCase).Count() == candidateLabels.Length,
                "signed source exposes a bounded unique candidate set");
            var policy = ApplicationPolicySnapshot.Create("global", "none", Array.Empty<string>(), Array.Empty<string>(), new string('d', 32));
            var controllerPort = AllocatePortPair();
            var package = MihomoConfigCompiler.Compile(new MihomoCompileInput(config, "A", "direct-vmess", "global", candidateLabels[0],
                "default", policy, ResolveUnderlay(), controllerPort, new string('q', 48), "bifrost1", "providers/source-a.json", null));
            using (var compiled = JsonDocument.Parse(package.MainConfig))
                Assert(compiled.RootElement.GetProperty("proxy-groups")[0].GetProperty("type").GetString() == "select",
                    "fixture exercises the manual selector package that previously exited before controller startup");
            var before = ExactProcessCount(binary);
            var tunBefore = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Count(item => item.Name == "bifrost1");
            var configuredRuntimeParent = Environment.GetEnvironmentVariable("BIFROST_PROBE_RUNTIME_PARENT");
            var runtimeRoot = string.IsNullOrWhiteSpace(configuredRuntimeParent)
                ? Path.Combine(scratch, "runtime")
                : Path.Combine(Path.GetFullPath(configuredRuntimeParent), ".mihomo-probe-fixture-" + Guid.NewGuid().ToString("N"));
            var result = await MihomoHealthProbeSession.MeasureAsync(package, binary, Hash(binary), generation,
                runtimeRoot, package.AllowedCandidates.Order(StringComparer.Ordinal).ToArray(), CancellationToken.None);
            Assert(result.Count == candidateLabels.Length, "measurement returns one terminal result per signed candidate");
            if (!realConfig) Assert(result.All(item => !item.Alive), "unreachable candidates return bounded failures");
            Assert(ExactProcessCount(binary) == before, "health session leaves no Mihomo process");
            Assert(System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Count(item => item.Name == "bifrost1") == tunBefore,
                "health session never creates the Bifrost TUN");
            Console.WriteLine(realConfig
                ? $"MIHOMO-HEALTH-PROBE-FIXTURE PASS real candidates={result.Count} alive={result.Count(item => item.Alive)}"
                : "MIHOMO-HEALTH-PROBE-FIXTURE PASS");
            if (!string.IsNullOrWhiteSpace(configuredRuntimeParent))
            {
                try { Directory.Delete(runtimeRoot, true); } catch { }
            }
            complete = true;
            return 0;
        }
        finally
        {
            if (complete) { try { Directory.Delete(scratch, true); } catch { } }
            else Console.Error.WriteLine("MIHOMO-HEALTH-SCRATCH " + scratch);
        }
    }

    private static int ExactProcessCount(string binary)
    {
        var count = 0;
        foreach (var process in Process.GetProcessesByName("mihomo"))
        {
            try { if (string.Equals(Path.GetFullPath(process.MainModule?.FileName ?? ""), Path.GetFullPath(binary), StringComparison.OrdinalIgnoreCase)) count++; }
            catch { }
            finally { process.Dispose(); }
        }
        return count;
    }

    private static void CopyRuntimeArtifacts(string sourceBinary, string destination)
    {
        var source = Path.GetDirectoryName(Path.GetFullPath(sourceBinary)) ?? throw new InvalidOperationException("binary directory missing");
        foreach (var name in new[] { "mihomo.exe", "CORE-MANIFEST.json", "GeoSite.dat", "geoip.metadb" })
        {
            var path = Path.Combine(source, name);
            if (!File.Exists(path)) throw new InvalidOperationException("required Mihomo runtime artifact missing: " + path);
            File.Copy(path, Path.Combine(destination, name));
        }
    }

    private static int AllocatePortPair()
    {
        for (var port = 24000; port < 60000; port += 2)
        {
            System.Net.Sockets.TcpListener? first = null; System.Net.Sockets.TcpListener? second = null;
            try
            {
                first = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Any, port); first.Start(1);
                second = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Any, port + 1); second.Start(1);
                return port;
            }
            catch { }
            finally { try { first?.Stop(); } catch { } try { second?.Stop(); } catch { } }
        }
        throw new InvalidOperationException("no test port pair");
    }

    private static string ResolveUnderlay()
    {
        var templateFile = Environment.GetEnvironmentVariable("BIFROST_MIHOMO_TEMPLATE_FILE");
        if (string.IsNullOrWhiteSpace(templateFile)) return "TEST-ONLY-ETHERNET";
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.GetFullPath(templateFile)));
        var value = document.RootElement.GetProperty("interface-name").GetString();
        return !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException("template underlay missing");
    }

    private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
    private static JsonObject SignedConfig() => new()
    {
        ["sources"] = new JsonArray(new JsonObject
        {
            ["code"] = "A", ["configured"] = true, ["server_name"] = "a.test-only.invalid", ["ws_path"] = "/a",
            ["transport"] = new JsonObject { ["network"] = "ws", ["tls"] = true, ["security"] = "auto", ["alter_id"] = 0, ["host"] = "a.test-only.invalid", ["sni"] = "a.test-only.invalid" },
            ["candidates"] = new JsonArray(Enumerable.Range(1, 3).Select(index => (JsonNode)new JsonObject { ["label"] = $"A-0{index}", ["dial_address"] = "127.0.0.1", ["port"] = 9 + index }).ToArray()),
            ["profiles"] = new JsonObject { ["direct"] = new JsonObject { ["profile_id"] = "A-direct", ["uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }, ["countries"] = new JsonObject() },
        }),
        ["routing"] = new JsonObject { ["dns_policy"] = new JsonObject { ["remote"] = "https://1.1.1.1/dns-query", ["direct"] = "https://223.5.5.5/dns-query", ["plaintext_fallback"] = false, ["failure"] = "block" } },
    };
    private static void Assert(bool value, string label) { if (!value) throw new InvalidOperationException("fixture assertion failed: " + label); }
}
