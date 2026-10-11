using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Bifrost.ClientService;

internal static class RoutingMatrixFixture
{
    internal static void Run(params MihomoCompiledPackage[] packages)
    {
        var root = AppContext.BaseDirectory;
        var cases = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "routing-services-v1.json")))!["cases"]!.AsArray();
        var data = Directory.EnumerateFiles(Path.Combine(root, "routing-geodata"), "geosite-*.json")
            .ToDictionary(path => Path.GetFileNameWithoutExtension(path)[8..], path => JsonNode.Parse(File.ReadAllText(path))!["rules"]!.AsArray());
        static IEnumerable<string> Strings(JsonObject rule, string key) => (rule[key] as JsonArray)?.Select(v => v!.GetValue<string>()) ?? [];
        bool Geo(string category, string host) => data[category].OfType<JsonObject>().Any(rule =>
            Strings(rule,"domain").Contains(host) || Strings(rule,"domain_suffix").Any(s => host == s.TrimStart('.') || host.EndsWith("." + s.TrimStart('.'))) ||
            Strings(rule,"domain_keyword").Any(host.Contains) || Strings(rule,"domain_regex").Any(s => Regex.IsMatch(host,s)));
        foreach (var package in packages)
        {
            var main = JsonNode.Parse(package.MainConfig)!;
            var rules = main["rules"]!.AsArray().Select(v => v!.GetValue<string>().Split(',')).ToArray();
            var smart = rules.Any(r => r[0] == "GEOSITE");
            var process = rules.FirstOrDefault(r => r[0] == "PROCESS-NAME" && r[1].Equals("browser.exe", StringComparison.OrdinalIgnoreCase));
            foreach (var value in cases)
            {
                var host = value!["host"]!.GetValue<string>();
                var hit = rules.First(r => r[0] == "MATCH" || r[0] == "DOMAIN" && r[1] == host ||
                    r[0] == "DOMAIN-SUFFIX" && (host == r[1] || host.EndsWith("." + r[1])) || r[0] == "GEOSITE" && Geo(r[1],host));
                var actual = hit[0] == "MATCH" ? hit[1] : hit[2];
                var expected = smart ? value["smart"]!.GetValue<string>() : process is null ? "proxy" : rules.Last()[1] == "BIFROST-DIRECT" ? "direct" : "proxy";
                var normalized = actual == "BIFROST-DIRECT" ? "direct" : actual == "REJECT" ? "reject" : "proxy";
                if (normalized != expected) throw new Exception($"Routing matrix: {package.ActiveGroup} {host} expected {expected}, actual {string.Join(',',hit)}");
                if (process is not null && process[2] == rules.Last()[1]) throw new Exception("Per-app inclusion/exclusion lost its distinct fallback");
                var dns = main["dns"]!;
                var policy = dns["nameserver-policy"]!.AsObject();
                var found = policy.FirstOrDefault(kv => kv.Key == host || kv.Key.StartsWith("+.") && (host == kv.Key[2..] || host.EndsWith(kv.Key[1..])));
                if (found.Key is null) found = policy.FirstOrDefault(kv => kv.Key.StartsWith("geosite:") && Geo(kv.Key[8..],host));
                var resolver = (found.Value ?? dns["nameserver"])![0]!.GetValue<string>();
                // DNS can be explicitly bound to BIFROST-DIRECT with the same
                // Mihomo `#outbound` syntax used for proxied resolvers. A '#'
                // therefore means "pinned transport", not necessarily proxy.
                var resolverUsesProxy = resolver.Contains('#') &&
                    !resolver.EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal);
                if (smart && expected != "reject" && resolverUsesProxy != (expected == "proxy"))
                    throw new Exception($"DNS matrix: {package.ActiveGroup} {host} differs from {actual}");
            }
        }
        Console.WriteLine($"ROUTING-MATRIX PASS {cases.Count} service/dependency hosts across {packages.Length} Windows policies");
    }
}
