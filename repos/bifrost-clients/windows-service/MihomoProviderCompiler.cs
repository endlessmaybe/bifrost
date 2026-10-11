using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

internal sealed record MihomoProviderResult(JsonObject Document, string ProviderName, IReadOnlySet<string> Candidates, IReadOnlyList<JsonObject> FrontProxies);

internal static class MihomoProviderCompiler
{
    internal static MihomoProviderResult Compile(MihomoCompileInput input)
    {
        var sourceCode = SafeToken(input.Source, "BF-SOURCE-SELECTION-REQUIRED").ToUpperInvariant();
        if (input.SignedConfig["sources"] is not JsonArray sources)
            throw new InvalidDataException("BF-CONFIG-SOURCES");
        if (input.ConnectionType == "smartgate") return CompileSmartGate(input, sources);

        var source = FindSource(sources, sourceCode);
        if (source["configured"]?.GetValue<bool>() != true)
            throw new InvalidDataException("BF-SOURCE-NOT-READY");
        if (source["candidates"] is not JsonArray candidates || candidates.Count == 0 || candidates.Count > 300)
            throw new InvalidDataException("BF-CANDIDATE-MISSING");

        var profile = ResolveProfile(source, input.ConnectionType, input.Country);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var proxies = new JsonArray();
        var orderedCandidates = candidates.OfType<JsonObject>();
        // Preserve signed catalogue order for identity and reproducibility.
        // Its position is not a throughput ranking; live body probes decide.
        if (input.RouteMode == "global" && !string.IsNullOrWhiteSpace(input.FixedCandidate))
            orderedCandidates = orderedCandidates.OrderBy(candidate =>
                string.Equals(candidate["label"]?.GetValue<string>(), input.FixedCandidate, StringComparison.OrdinalIgnoreCase) ? 0 : 1);
        foreach (var candidate in orderedCandidates)
        {
            var label = SafeToken(candidate["label"]?.GetValue<string>(), "BF-CANDIDATE-LABEL-MISSING");
            var declaredSource = candidate["source_code"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(declaredSource) && !string.Equals(declaredSource, sourceCode, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
            if (!seen.Add(label)) throw new InvalidDataException("BF-CANDIDATE-LABEL-DUPLICATE");
            proxies.Add(BuildProxy(source, candidate, profile, input, label, null));
        }
        var providerName = "BIFROST-SOURCE-" + sourceCode;
        return new MihomoProviderResult(new JsonObject { ["proxies"] = proxies }, providerName,
            new HashSet<string>(seen, StringComparer.OrdinalIgnoreCase), Array.Empty<JsonObject>());
    }

    private static MihomoProviderResult CompileSmartGate(MihomoCompileInput input, JsonArray sources)
    {
        var countryCode = SafeToken(input.Country, "BF-SMARTGATE-COUNTRY").ToUpperInvariant();
        var country = (input.SignedConfig["countries"] as JsonArray)?.OfType<JsonObject>().SingleOrDefault(item =>
            string.Equals(item["code"]?.GetValue<string>(), countryCode, StringComparison.OrdinalIgnoreCase) &&
            item["status"]?.GetValue<string>() == "enabled")
            ?? throw new InvalidDataException("BF-CONFIG-COUNTRY");
        var socks = country["socks"] as JsonObject ?? throw new InvalidDataException("BF-SMARTGATE-SOCKS");
        var socksHost = SafeHost(socks["host"]?.GetValue<string>());
        var socksPort = socks["port"]?.GetValue<int>() ?? 0;
        if (socksPort is < 1 or > 65535) throw new InvalidDataException("BF-SMARTGATE-SOCKS");
        var socksUser = SafeCredential(socks["user"]?.GetValue<string>(), 128);
        var socksPassword = SafeCredential(socks["password"]?.GetValue<string>(), 256);
        if (socks["scheme"]?.GetValue<string>() is not ("socks5" or "socks5h"))
            throw new InvalidDataException("BF-SMARTGATE-SOCKS");

        var mappedSources = (country["front_source_options"] as JsonArray)?.OfType<JsonValue>()
            .Select(value => SafeToken(value.GetValue<string>(), "BF-SMARTGATE-FRONT-NOT-MAPPED").ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? Array.Empty<string>();
        if (mappedSources.Length == 0 || mappedSources.Length > 2)
            throw new InvalidDataException("BF-SMARTGATE-FRONT-NOT-MAPPED");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var providerProxies = new JsonArray();
        var frontProxies = new List<JsonObject>();
        foreach (var mappedSourceCode in mappedSources)
        {
            var source = FindSource(sources, mappedSourceCode);
            var directProfile = (source["profiles"] as JsonObject)?["direct"] as JsonObject
                ?? throw new InvalidDataException("BF-SMARTGATE-FRONT-PROFILE");
            var candidates = source["candidates"] as JsonArray ?? throw new InvalidDataException("BF-CANDIDATE-MISSING");
            foreach (var candidate in candidates.OfType<JsonObject>())
            {
                var label = SafeToken(candidate["label"]?.GetValue<string>(), "BF-CANDIDATE-LABEL-MISSING");
                if (!seen.Add(label)) throw new InvalidDataException("BF-CANDIDATE-LABEL-DUPLICATE");
                if (seen.Count > 600) throw new InvalidDataException("BF-CANDIDATE-MISSING");
                var frontName = "BIFROST-SMARTGATE-FRONT-" + label;
                frontProxies.Add(BuildProxy(source, candidate, directProfile, input, frontName, null));
                providerProxies.Add(new JsonObject
                {
                    ["name"] = label,
                    ["type"] = "socks5",
                    ["server"] = socksHost,
                    ["port"] = socksPort,
                    ["username"] = socksUser,
                    ["password"] = socksPassword,
                    ["udp"] = country["udp"]?.GetValue<bool>() == true,
                    ["dialer-proxy"] = frontName,
                });
            }
        }
        if (seen.Count == 0) throw new InvalidDataException("BF-CANDIDATE-MISSING");
        return new MihomoProviderResult(
            new JsonObject { ["proxies"] = providerProxies },
            "BIFROST-SMARTGATE-" + countryCode,
            new HashSet<string>(seen, StringComparer.OrdinalIgnoreCase),
            frontProxies);
    }

    private static JsonObject FindSource(JsonArray sources, string code) =>
        sources.OfType<JsonObject>().SingleOrDefault(item =>
            string.Equals(item["code"]?.GetValue<string>(), code, StringComparison.OrdinalIgnoreCase) &&
            item["configured"]?.GetValue<bool>() == true)
        ?? throw new InvalidDataException("BF-SOURCE-NOT-READY");

    private static JsonObject BuildProxy(
        JsonObject source,
        JsonObject candidate,
        JsonObject profile,
        MihomoCompileInput input,
        string name,
        string? dialerProxy)
    {
        var uuid = SafeUuid(profile["uuid"]?.GetValue<string>());
        var transport = source["transport"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-TRANSPORT");
        var serverName = SafeHost(source["server_name"]?.GetValue<string>());
        var host = SafeHost(transport["host"]?.GetValue<string>() ?? serverName);
        var sni = SafeHost(transport["sni"]?.GetValue<string>() ?? serverName);
        if (transport["network"]?.GetValue<string>() != "ws" || transport["tls"]?.GetValue<bool>() != true)
            throw new InvalidDataException("BF-CONFIG-TRANSPORT");
        var alterId = transport["alter_id"]?.GetValue<int>() ?? 0;
        if (alterId is < 0 or > 65535) throw new InvalidDataException("BF-CONFIG-CRYPTO");
        var server = SafeHost(candidate["dial_address"]?.GetValue<string>() ?? candidate["address"]?.GetValue<string>());
        var port = candidate["port"]?.GetValue<int>() ?? 443;
        if (port is < 1 or > 65535) throw new InvalidDataException("BF-CANDIDATE-PORT");
        var proxy = new JsonObject
        {
            ["name"] = name,
            ["type"] = "vmess",
            ["server"] = server,
            ["port"] = port,
            ["uuid"] = uuid,
            ["alterId"] = alterId,
            ["cipher"] = SafeCipher(transport["security"]?.GetValue<string>() ?? "auto"),
            ["udp"] = true,
            ["ip-version"] = "ipv4-prefer",
            ["tls"] = true,
            ["servername"] = sni,
            ["client-fingerprint"] = "chrome",
            ["skip-cert-verify"] = false,
            ["network"] = "ws",
            ["ws-opts"] = new JsonObject
            {
                ["path"] = SafePath(source["ws_path"]?.GetValue<string>()),
                ["headers"] = new JsonObject { ["Host"] = host },
            },
        };
        if (!string.IsNullOrWhiteSpace(dialerProxy)) proxy["dialer-proxy"] = dialerProxy;
        else proxy["interface-name"] = SafeInterface(input.UnderlayInterface);
        return proxy;
    }

    private static JsonObject ResolveProfile(JsonObject source, string connectionType, string country)
    {
        var profiles = source["profiles"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-PROFILE");
        if (connectionType == "direct-vmess")
        {
            if (country != "default") throw new InvalidDataException("BF-CONNECTION-TYPE");
            return profiles["direct"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-PROFILE");
        }
        if (connectionType != "smartgate" || country is "default" or "auto" || string.IsNullOrWhiteSpace(country))
            throw new InvalidDataException("BF-CONNECTION-TYPE");
        return profiles["countries"]?[country] as JsonObject ?? throw new InvalidDataException("BF-SMARTGATE-PROFILE");
    }

    internal static string SafeToken(string? value, string code)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value) || value.Length > 96 || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')))
            throw new InvalidDataException(code);
        return value;
    }

    private static string SafeHost(string? value)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value) || value.Length > 253 || value.Any(char.IsControl) ||
            value.Contains('/') || value.Contains('\\') || value.Contains('@'))
            throw new InvalidDataException("BF-CONFIG-HOST");
        return value;
    }

    private static string SafeCredential(string? value, int maxLength)
    {
        value ??= string.Empty;
        if (value.Length == 0 || value.Length > maxLength || value.Any(char.IsControl))
            throw new InvalidDataException("BF-SMARTGATE-SOCKS");
        return value;
    }

    private static string SafeUuid(string? value) =>
        Guid.TryParseExact(value, "D", out var parsed) && parsed != Guid.Empty
            ? parsed.ToString("D") : throw new InvalidDataException("BF-CONFIG-CRYPTO");

    private static string SafePath(string? value)
    {
        value = string.IsNullOrWhiteSpace(value) ? "/" : value.Trim();
        if (!value.StartsWith('/')) value = "/" + value;
        if (value.Length > 2048 || value.Any(char.IsControl)) throw new InvalidDataException("BF-CONFIG-TRANSPORT");
        return value;
    }

    private static string SafeCipher(string value) => value is "auto" or "aes-128-gcm" or "chacha20-poly1305"
        ? value : throw new InvalidDataException("BF-CONFIG-CRYPTO");

    private static string SafeInterface(string? value)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value) || value.Length > 256 || value.Any(char.IsControl))
            throw new InvalidDataException("BF-TUN-CONFIG");
        return value;
    }
}
