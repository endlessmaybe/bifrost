using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

static class Fixture
{
    private static int Main(string[] args)
    {
        if (args.Contains("--teardown-child")) { Thread.Sleep(TimeSpan.FromSeconds(60)); return 0; }
        if (args.Contains("--connect-admission")) { RuntimeConnectAdmissionFixture.Run(); return 0; }
        if (args.Contains("--teardown-only")) { RuntimeTeardownFixture.Run(); return 0; }
        var root = Path.Combine(Path.GetTempPath(), "bifrost-mihomo-package-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            var policy = ApplicationPolicySnapshot.Create("smart", "none", Array.Empty<string>(), Array.Empty<string>(), new string('a', 32));
            var compiled = MihomoConfigCompiler.Compile(new MihomoCompileInput(
                SignedConfig(), "A", "direct-vmess", "smart", null, "default", policy,
                "TEST-ONLY-ETHERNET", 19099, new string('s', 48), "bifrost1",
                "providers/source-a.json", null));

            var staged = ClientPackageStager.Stage(root, new ClientPackageInput(
                "smart", "mihomo", "A", "default", "none", compiled.MainConfig, compiled.Provider, policy), durable: false);
            Assert(staged.Core == "mihomo", "stager fixes the one Windows core");
            var directory = Path.Combine(root, staged.ConfigId);
            Assert(Directory.EnumerateFileSystemEntries(directory).Select(Path.GetFileName).Order(StringComparer.Ordinal)
                .SequenceEqual(new[] { "mihomo.json", "package.json", "provider.json" }, StringComparer.Ordinal),
                "staged package has exactly three files");

            var resolved = ClientPackageStager.Resolve(root, staged.ConfigId, "smart", "mihomo", "A", "default", policy);
            Assert(Path.GetFileName(resolved.MainConfigPath) == "mihomo.json" &&
                Path.GetFileName(resolved.ProviderConfigPath) == "provider.json", "resolved exact file names");
            Assert(resolved.MainSha256 == staged.MainSha256 && resolved.ProviderSha256 == staged.ProviderSha256,
                "resolved digests match the immutable stage result");

            ExpectCode(() => ClientPackageStager.Resolve(root, staged.ConfigId, "smart", "auto", "A", "default", policy), "BF-CONFIG-CORE");
            ExpectCode(() => ClientPackageStager.Stage(root, new ClientPackageInput(
                "smart", "unsupported", "A", "default", "none", compiled.MainConfig, compiled.Provider, policy), durable: false),
                "BF-CONFIG-PACKAGE");

            var providerPath = resolved.ProviderConfigPath;
            var originalProvider = File.ReadAllBytes(providerPath);
            try
            {
                var tampered = originalProvider.ToArray();
                tampered[^2] ^= 1;
                File.WriteAllBytes(providerPath, tampered);
                ExpectCode(() => ClientPackageStager.Resolve(root, staged.ConfigId, "smart", "mihomo", "A", "default", policy),
                    "BF-CONFIG-PACKAGE");
            }
            finally { File.WriteAllBytes(providerPath, originalProvider); }

            var duplicateMetadata = Encoding.UTF8.GetBytes("{\"config_id\":\"a\",\"config_id\":\"b\"}");
            ExpectCode(() => { using var _ = ClientPackageStager.ParseMetadata(duplicateMetadata); }, "BF-CONFIG-PACKAGE");

            var command = JsonSerializer.Serialize(new
            {
                action = "connect",
                mode = "smart",
                connection_type = "direct-vmess",
                core = "unsupported",
                source = "A",
                country = "default",
                config_id = staged.ConfigId,
                app_policy = "none",
                app_policy_snapshot = policy.CanonicalJson,
                app_policy_digest = policy.Digest,
                app_policy_generation = policy.Generation,
            });
            ExpectCode(() => IpcProtocol.ParseCommand(command), "BF-CONFIG-PACKAGE");

            Console.WriteLine("WINDOWS-MIHOMO-SERVICE-CONTRACT PASS");
            return 0;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static JsonObject SignedConfig() => new()
    {
        ["schema_version"] = "1.0",
        ["sources"] = new JsonArray(Source("A", "203.0.113.", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")),
        ["countries"] = new JsonArray(),
        ["routing"] = new JsonObject
        {
            ["dns_policy"] = new JsonObject
            {
                ["version"] = "dns-policy-v1",
                ["remote"] = "https://1.1.1.1/dns-query",
                ["direct"] = "https://223.5.5.5/dns-query",
                ["smart_gate_remote"] = true,
                ["plaintext_fallback"] = false,
                ["ipv4"] = "proxy",
                ["ipv6"] = "block",
                ["failure"] = "block",
            }
        },
    };

    private static JsonObject Source(string code, string prefix, string uuid) => new()
    {
        ["code"] = code,
        ["configured"] = true,
        ["server_name"] = "a.test-only.invalid",
        ["ws_path"] = "/a",
        ["transport"] = new JsonObject
        {
            ["network"] = "ws", ["tls"] = true, ["security"] = "auto", ["alter_id"] = 0,
            ["host"] = "a.test-only.invalid", ["sni"] = "a.test-only.invalid",
        },
        ["candidates"] = new JsonArray(Enumerable.Range(1, 3).Select(index => (JsonNode)new JsonObject
        {
            ["label"] = $"{code}-0{index}", ["dial_address"] = prefix + (10 + index), ["port"] = 443,
        }).ToArray()),
        ["profiles"] = new JsonObject
        {
            ["direct"] = new JsonObject { ["profile_id"] = "A-direct", ["uuid"] = uuid },
            ["countries"] = new JsonObject(),
        },
    };

    private static void ExpectCode(Action action, string code)
    {
        try { action(); }
        catch (Exception failure) when (failure.Message == code) { return; }
        throw new InvalidOperationException("expected " + code);
    }

    private static void Assert(bool condition, string label)
    {
        if (!condition) throw new InvalidOperationException("fixture assertion failed: " + label);
    }
}
