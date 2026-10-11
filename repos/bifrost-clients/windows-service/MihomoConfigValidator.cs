using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

internal static class MihomoConfigValidator
{
    internal static void Validate(MihomoCompiledPackage package, MihomoCompileInput input)
    {
        if (package.MainConfig.Length is < 64 or > 1024 * 1024 || package.Provider.Length is < 32 or > 1024 * 1024 ||
            package.AllowedCandidates.Count is < 1 or > 600 || !IsDigest(package.Digest))
            throw new InvalidDataException("BF-MIHOMO-CONFIG");
        var main = JsonNode.Parse(package.MainConfig) as JsonObject ?? throw new InvalidDataException("BF-MIHOMO-CONFIG");
        var provider = JsonNode.Parse(package.Provider) as JsonObject ?? throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        if (main["external-controller"]?.GetValue<string>() != $"127.0.0.1:{input.ControllerPort}" ||
            main["secret"]?.GetValue<string>() != input.ControllerSecret || main["allow-lan"]?.GetValue<bool>() != false ||
            main["interface-name"]?.GetValue<string>() != input.UnderlayInterface)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        var providerConfig = main["proxy-providers"]?[package.ProviderName] as JsonObject
            ?? throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        var healthCheck = providerConfig["health-check"] as JsonObject
            ?? throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        if (healthCheck["enable"]?.GetValue<bool>() != true ||
            healthCheck["url"]?.GetValue<string>() != MihomoWindowsContract.StartupProbeUrl ||
            healthCheck["expected-status"]?.GetValue<int>() != MihomoWindowsContract.StartupProbeExpectedStatus ||
            healthCheck["interval"]?.GetValue<int>() != 300 ||
            healthCheck["timeout"]?.GetValue<int>() != 5000 ||
            healthCheck["lazy"]?.GetValue<bool>() != false)
            throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        var tun = main["tun"] as JsonObject ?? throw new InvalidDataException("BF-TUN-CONFIG");
        if (tun["device"]?.GetValue<string>() != "bifrost1" || tun["enable"]?.GetValue<bool>() != true ||
            tun["auto-route"]?.GetValue<bool>() != false || tun["strict-route"]?.GetValue<bool>() != false)
            throw new InvalidDataException("BF-TUN-CONFIG");
        var groups = main["proxy-groups"] as JsonArray ?? throw new InvalidDataException("BF-MIHOMO-GROUP");
        var hasChatGptGroup = input.RouteMode == "smart" && input.ConnectionType != "smartgate";
        if (groups.Count != (hasChatGptGroup ? 2 : 1) || groups[0] is not JsonObject group || group["name"]?.GetValue<string>() != package.ActiveGroup)
            throw new InvalidDataException("BF-MIHOMO-GROUP");
        if (input.RouteMode != "global")
        {
            var expectedType = "url-test";
            if (group["type"]?.GetValue<string>() != expectedType || group["empty-fallback"]?.GetValue<string>() != "REJECT" ||
                group["url"]?.GetValue<string>() != MihomoWindowsContract.StartupProbeUrl ||
                group["expected-status"]?.GetValue<int>() != MihomoWindowsContract.StartupProbeExpectedStatus || group["interval"]?.GetValue<int>() != 60 ||
                group["timeout"]?.GetValue<int>() != 5000 ||
                group["tolerance"]?.GetValue<int>() != MihomoPolicyCompiler.AutoSelectToleranceMs ||
                group["max-failed-times"]?.GetValue<int>() != 2 || group["default-selected"] is not null)
                throw new InvalidDataException("BF-MIHOMO-GROUP");
        }
        else ValidateFixedGroup(group, package.ProviderName, new[] { input.FixedCandidate ?? string.Empty });
        var chatGptGroupName = package.ActiveGroup;
        if (hasChatGptGroup)
        {
            if (groups[1] is not JsonObject chatGptGroup) throw new InvalidDataException("BF-MIHOMO-GROUP");
            chatGptGroupName = "BIFROST-OPENAI-" + input.Source.ToUpperInvariant();
            if (chatGptGroup["name"]?.GetValue<string>() != chatGptGroupName ||
                chatGptGroup["type"]?.GetValue<string>() != "fallback" ||
                chatGptGroup["use"] is not JsonArray { Count: 1 } chatGptUse || chatGptUse[0]?.GetValue<string>() != package.ProviderName ||
                chatGptGroup["url"]?.GetValue<string>() != MihomoWindowsContract.StartupProbeUrl ||
                chatGptGroup["expected-status"]?.GetValue<int>() != MihomoWindowsContract.StartupProbeExpectedStatus ||
                chatGptGroup["interval"]?.GetValue<int>() != 300 || chatGptGroup["timeout"]?.GetValue<int>() != 5000 ||
                chatGptGroup["tolerance"] is not null || chatGptGroup["lazy"]?.GetValue<bool>() != false ||
                chatGptGroup["max-failed-times"]?.GetValue<int>() != 2 || chatGptGroup["empty-fallback"]?.GetValue<string>() != "REJECT" ||
                chatGptGroup["default-selected"] is not null)
                throw new InvalidDataException("BF-MIHOMO-GROUP");
        }
        ValidatePerformanceAndDns(main, input.RouteMode, package.ActiveGroup, chatGptGroupName);
        var proxies = provider["proxies"] as JsonArray ?? throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        var names = proxies.OfType<JsonObject>().Select(proxy => proxy["name"]?.GetValue<string>())
            .Where(name => name is not null).Cast<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!names.SetEquals(package.AllowedCandidates)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        ValidateRuntimePolicy(main, input.RouteMode, input.ConnectionType == "smartgate", package.ActiveGroup, chatGptGroupName, input.ApplicationPolicy);
        var serialized = main.ToJsonString();
        if (serialized.Contains("COMPATIBLE", StringComparison.OrdinalIgnoreCase) ||
            input.RouteMode != "per-app" && serialized.Contains("MATCH,BIFROST-DIRECT", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-MIHOMO-DIRECT-FALLBACK");
    }

    internal static void ValidateStaged(
        ReadOnlySpan<byte> mainBytes,
        ReadOnlySpan<byte> providerBytes,
        string source,
        string mode,
        ApplicationPolicySnapshot policy)
    {
        if (mainBytes.Length is < 64 or > 1024 * 1024 || providerBytes.Length is < 32 or > 1024 * 1024 ||
            policy.RouteMode != mode) throw new InvalidDataException("BF-MIHOMO-CONFIG");
        JsonObject main;
        JsonObject provider;
        try
        {
            main = JsonNode.Parse(mainBytes) as JsonObject ?? throw new InvalidDataException("BF-MIHOMO-CONFIG");
            provider = JsonNode.Parse(providerBytes) as JsonObject ?? throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        }
        catch (JsonException) { throw new InvalidDataException("BF-MIHOMO-CONFIG"); }
        var groups = main["proxy-groups"] as JsonArray ?? throw new InvalidDataException("BF-MIHOMO-GROUP");
        if (groups.Count is < 1 or > 2 || groups[0] is not JsonObject group) throw new InvalidDataException("BF-MIHOMO-GROUP");
        var name = group["name"]?.GetValue<string>() ?? string.Empty;
        var smartGate = name.StartsWith("BIFROST-SMARTGATE-", StringComparison.Ordinal);
        var hasChatGptGroup = mode == "smart" && !smartGate;
        if (groups.Count != (hasChatGptGroup ? 2 : 1)) throw new InvalidDataException("BF-MIHOMO-GROUP");
        var expectedSuffix = "-" + source.ToUpperInvariant();
        if (mode != "global" && !name.EndsWith(expectedSuffix, StringComparison.Ordinal) && !name.StartsWith("BIFROST-SMARTGATE-", StringComparison.Ordinal))
            throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        if (mode == "global" && (!name.StartsWith("BIFROST-FIXED-", StringComparison.Ordinal) || !name.EndsWith(expectedSuffix, StringComparison.Ordinal)))
            throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        var proxies = provider["proxies"] as JsonArray ?? throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        var candidateNames = proxies.OfType<JsonObject>().Select(proxy => proxy["name"]?.GetValue<string>() ?? string.Empty).ToArray();
        if (candidateNames.Length is < 1 or > 600 || candidateNames.Any(string.IsNullOrWhiteSpace) ||
            candidateNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() != candidateNames.Length)
            throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        if (mode == "global")
        {
            ValidateFixedGroup(group, "BIFROST-SOURCE-" + source.ToUpperInvariant(), candidateNames);
        }
        else
        {
            var expectedType = "url-test";
            if (group["type"]?.GetValue<string>() != expectedType || group["empty-fallback"]?.GetValue<string>() != "REJECT" ||
                group["tolerance"]?.GetValue<int>() != MihomoPolicyCompiler.AutoSelectToleranceMs ||
                group["default-selected"] is not null)
                throw new InvalidDataException("BF-MIHOMO-GROUP");
        }
        var chatGptGroupName = name;
        if (hasChatGptGroup)
        {
            if (groups[1] is not JsonObject chatGptGroup) throw new InvalidDataException("BF-MIHOMO-GROUP");
            chatGptGroupName = "BIFROST-OPENAI-" + source.ToUpperInvariant();
            if (chatGptGroup["name"]?.GetValue<string>() != chatGptGroupName ||
                chatGptGroup["type"]?.GetValue<string>() != "fallback" ||
                chatGptGroup["tolerance"] is not null ||
                chatGptGroup["empty-fallback"]?.GetValue<string>() != "REJECT" || chatGptGroup["default-selected"] is not null)
                throw new InvalidDataException("BF-MIHOMO-GROUP");
        }
        ValidatePerformanceAndDns(main, mode, name, chatGptGroupName);
        ValidateRuntimePolicy(main, mode, smartGate, name, chatGptGroupName, policy);
        var serialized = main.ToJsonString();
        if (serialized.Contains("COMPATIBLE", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("BF-MIHOMO-DIRECT-FALLBACK");
    }

    private static void ValidateFixedGroup(JsonObject group, string providerName, IEnumerable<string> candidates)
    {
        if (group.Count != 5 || group["type"]?.GetValue<string>() != "select" ||
            group["use"] is not JsonArray { Count: 1 } use || use[0]?.GetValue<string>() != providerName ||
            group["empty-fallback"]?.GetValue<string>() != "REJECT" ||
            group["filter"] is not JsonValue filter || !filter.TryGetValue<string>(out var expression))
            throw new InvalidDataException("BF-MIHOMO-GROUP");
        // Compare the canonical escaped expression, never execute a staged
        // regex or allow a filter to widen the user's fixed-candidate choice.
        if (candidates.Count(candidate => !string.IsNullOrEmpty(candidate) &&
            expression == MihomoPolicyCompiler.FixedCandidateFilter(candidate)) != 1)
            throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
    }

    private static bool IsDigest(string value) => value.Length == 64 && value.All(character =>
        character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static void ValidatePerformanceAndDns(JsonObject main, string mode, string active, string chatGptActive)
    {
        // Older signed UI generations omit the pinned core's default address.
        // Keep that update transition compatible, but reject a changed peer.
        if (main["tun"]?["inet4-address"] is { } addresses &&
            (addresses is not JsonArray { Count: 1 } addressList ||
             addressList[0]?.GetValue<string>() != MihomoWindowsContract.TunIpv4Cidr))
            throw new InvalidDataException("BF-TUN-DNS");
        if (main["unified-delay"]?.GetValue<bool>() != true || main["tcp-concurrent"]?.GetValue<bool>() != true ||
            main["keep-alive-interval"]?.GetValue<int>() != 15 || main["keep-alive-idle"]?.GetValue<int>() != 30 ||
            main["disable-keep-alive"]?.GetValue<bool>() != false ||
            main["find-process-mode"]?.GetValue<string>() != (mode == "per-app" ? "always" : "strict") ||
            main["geodata-mode"]?.GetValue<bool>() != false || main["geodata-loader"]?.GetValue<string>() != "standard" ||
            main["geosite-matcher"]?.GetValue<string>() != "succinct")
            throw new InvalidDataException("BF-MIHOMO-PERFORMANCE");
        var sniffer = main["sniffer"] as JsonObject ?? throw new InvalidDataException("BF-MIHOMO-SNIFFER");
        if (sniffer["enable"]?.GetValue<bool>() != true || sniffer["force-dns-mapping"]?.GetValue<bool>() != true ||
            sniffer["parse-pure-ip"]?.GetValue<bool>() != true || sniffer["override-destination"]?.GetValue<bool>() != true)
            throw new InvalidDataException("BF-MIHOMO-SNIFFER");
        var dns = main["dns"] as JsonObject ?? throw new InvalidDataException("BF-CONFIG-DNS");
        var ipv6 = main["ipv6"]?.GetValue<bool>() == true;
        if (dns["ipv6"]?.GetValue<bool>() != ipv6 ||
            (ipv6 && (main["tun"]?["inet6-address"] is not JsonArray { Count: 1 } v6 ||
                v6[0]?.GetValue<string>() != MihomoWindowsContract.TunIpv6Cidr ||
                dns["fake-ip-range6"]?.GetValue<string>() != MihomoWindowsContract.FakeIpv6Cidr)) ||
            (!ipv6 && (main["tun"]?["inet6-address"] is not null || dns["fake-ip-range6"] is not null)))
            throw new InvalidDataException("BF-CONFIG-IPV6");
        var requiredNameserverKeys = new HashSet<string>(StringComparer.Ordinal)
        {
            "www.gstatic.com",
            "cp.cloudflare.com",
        };
        if (mode == "smart")
        {
            var directDnsHost = DnsPolicyHost(dns["direct-nameserver"]?[0]?.GetValue<string>());
            var remoteDnsHost = DnsPolicyHost(dns["nameserver"]?[0]?.GetValue<string>());
            if (directDnsHost is not null) requiredNameserverKeys.Add(directDnsHost);
            if (remoteDnsHost is not null && !string.Equals(remoteDnsHost, directDnsHost, StringComparison.OrdinalIgnoreCase))
                requiredNameserverKeys.Add(remoteDnsHost);
            foreach (var domain in MihomoPolicyCompiler.LocalDirectExactDomains) requiredNameserverKeys.Add(domain);
            foreach (var domain in MihomoPolicyCompiler.LocalDirectDomainSuffixes.Concat(MihomoPolicyCompiler.LocalDnsOnlySuffixes))
                requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in MihomoPolicyCompiler.TencentDirectDomainSuffixes) requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes) requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in MihomoPolicyCompiler.SystemDirectExactDomains) requiredNameserverKeys.Add(domain);
            foreach (var domain in MihomoPolicyCompiler.SystemDirectDomainSuffixes) requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in MihomoPolicyCompiler.GoogleProxyDomainSuffixes) requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in MihomoPolicyCompiler.GoogleProxyExactDomains) requiredNameserverKeys.Add(domain);
            foreach (var domain in BifrostServiceRouting.YoutubeSuffixes) requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in BifrostServiceRouting.YoutubeDomains) requiredNameserverKeys.Add(domain);
            requiredNameserverKeys.UnionWith(new[] { "geosite:openai", "geosite:category-ads-all", "geosite:private",
                $"geosite:{MihomoPolicyCompiler.DomesticTldGeosite}", "geosite:cn", "geosite:geolocation-!cn" });
            foreach (var geosite in MihomoPolicyCompiler.DomesticDirectGeosites)
                requiredNameserverKeys.Add($"geosite:{geosite}");
            foreach (var domain in MihomoPolicyCompiler.ChatGptProxyDomainSuffixes) requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in MihomoPolicyCompiler.ChatGptProxyExactDomains) requiredNameserverKeys.Add(domain);
            foreach (var domain in MihomoPolicyCompiler.SteamDownloadDirectDomainSuffixes)
                requiredNameserverKeys.Add($"+.{domain}");
            foreach (var domain in BifrostServiceRouting.Domains) requiredNameserverKeys.Add(domain);
            foreach (var domain in MihomoPolicyCompiler.MicrosoftProxyExactDomains) requiredNameserverKeys.Add(domain);
            foreach (var geosite in MihomoPolicyCompiler.ForeignProxyGeosites)
                requiredNameserverKeys.Add($"geosite:{geosite}");
        }

        if (dns["enhanced-mode"]?.GetValue<string>() != "fake-ip" || dns["cache-algorithm"]?.GetValue<string>() != "arc" ||
            dns["prefer-h3"]?.GetValue<bool>() != false || dns["use-hosts"]?.GetValue<bool>() != true ||
            dns["use-system-hosts"]?.GetValue<bool>() != true ||
            dns["respect-rules"]?.GetValue<bool>() != true || dns["fake-ip-filter-mode"]?.GetValue<string>() != "rule" ||
            dns["direct-nameserver-follow-policy"]?.GetValue<bool>() != (mode == "smart") ||
            dns["default-nameserver"] is not JsonArray { Count: 1 } || dns["nameserver"] is not JsonArray { Count: 1 } ||
            dns["proxy-server-nameserver"] is not JsonArray { Count: 1 } || dns["direct-nameserver"] is not JsonArray { Count: 1 } ||
            dns["nameserver-policy"] is not JsonObject nameserverPolicy ||
            nameserverPolicy.Count != requiredNameserverKeys.Count ||
            requiredNameserverKeys.Any(key => !nameserverPolicy.ContainsKey(key)))
            throw new InvalidDataException("BF-CONFIG-DNS");
        var filters = (dns["fake-ip-filter"] as JsonArray)?.Select(item => item?.GetValue<string>() ?? string.Empty).ToArray();
        var baseFilters = new List<string> { "GEOSITE,private,real-ip" };
        baseFilters.AddRange(MihomoPolicyCompiler.LocalDirectExactDomains.Select(domain => $"DOMAIN,{domain},real-ip"));
        baseFilters.AddRange(MihomoPolicyCompiler.LocalDirectDomainSuffixes.Concat(MihomoPolicyCompiler.LocalDnsOnlySuffixes)
            .Select(domain => $"DOMAIN-SUFFIX,{domain},real-ip"));
        if (mode == "smart")
        {
            baseFilters.AddRange(MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes
                .Select(domain => $"DOMAIN-SUFFIX,{domain},real-ip"));
            baseFilters.AddRange(MihomoPolicyCompiler.SystemDirectExactDomains.Select(domain => $"DOMAIN,{domain},real-ip"));
            baseFilters.AddRange(MihomoPolicyCompiler.SystemDirectDomainSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},real-ip"));
        }
        baseFilters.Add("MATCH,fake-ip");
        var expectedFilters = baseFilters.ToArray();
        if (filters is null || !filters.SequenceEqual(expectedFilters, StringComparer.Ordinal))
            throw new InvalidDataException("BF-CONFIG-DNS");
        var direct = (main["proxies"] as JsonArray)?.OfType<JsonObject>()
            .Where(proxy => proxy["name"]?.GetValue<string>() == "BIFROST-DIRECT").ToArray();
        if (direct is not { Length: 1 } || direct[0].Count != 5 ||
            direct[0]["type"]?.GetValue<string>() != "direct" ||
            direct[0]["ip-version"]?.GetValue<string>() != "ipv4-prefer" ||
            direct[0]["udp"]?.GetValue<bool>() != true ||
            direct[0]["interface-name"]?.GetValue<string>() != main["interface-name"]?.GetValue<string>())
            throw new InvalidDataException("BF-CONFIG-IPV6");
        var generalDns = dns["nameserver"]?[0]?.GetValue<string>() ?? string.Empty;
        if (!generalDns.EndsWith("#" + active, StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-DNS");
        foreach (var key in new[] { "proxy-server-nameserver", "direct-nameserver" })
            if (!(dns[key]?[0]?.GetValue<string>() ?? string.Empty).EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal))
                throw new InvalidDataException("BF-CONFIG-DNS");
        if (mode != "smart") return;
        var validatedDirectDnsHost = DnsPolicyHost(dns["direct-nameserver"]?[0]?.GetValue<string>());
        var validatedRemoteDnsHost = DnsPolicyHost(dns["nameserver"]?[0]?.GetValue<string>());
        if (validatedDirectDnsHost is not null) RequireDnsGroup(nameserverPolicy, validatedDirectDnsHost, "BIFROST-DIRECT");
        if (validatedRemoteDnsHost is not null && !string.Equals(validatedRemoteDnsHost, validatedDirectDnsHost, StringComparison.OrdinalIgnoreCase))
            RequireDnsGroup(nameserverPolicy, validatedRemoteDnsHost, active);
        foreach (var domain in MihomoPolicyCompiler.LocalDirectExactDomains) RequireDnsGroup(nameserverPolicy, domain, "BIFROST-DIRECT");
        foreach (var domain in MihomoPolicyCompiler.LocalDirectDomainSuffixes.Concat(MihomoPolicyCompiler.LocalDnsOnlySuffixes))
            RequireDnsGroup(nameserverPolicy, $"+.{domain}", "BIFROST-DIRECT");
        foreach (var domain in MihomoPolicyCompiler.TencentDirectDomainSuffixes)
            RequireDnsGroup(nameserverPolicy, $"+.{domain}", "BIFROST-DIRECT");
        foreach (var domain in MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes)
            RequireDnsGroup(nameserverPolicy, $"+.{domain}", "BIFROST-DIRECT");
        foreach (var domain in MihomoPolicyCompiler.SystemDirectExactDomains)
            RequireDnsGroup(nameserverPolicy, domain, "BIFROST-DIRECT");
        foreach (var domain in MihomoPolicyCompiler.SystemDirectDomainSuffixes)
            RequireDnsGroup(nameserverPolicy, $"+.{domain}", "BIFROST-DIRECT");
        RequireDnsGroup(nameserverPolicy, "geosite:private", "BIFROST-DIRECT");
        RequireDnsGroup(nameserverPolicy, $"geosite:{MihomoPolicyCompiler.DomesticTldGeosite}", "BIFROST-DIRECT");
        RequireDnsGroup(nameserverPolicy, "geosite:cn", "BIFROST-DIRECT");
        foreach (var domain in MihomoPolicyCompiler.GoogleProxyDomainSuffixes) RequireDnsGroup(nameserverPolicy, $"+.{domain}", active);
        foreach (var domain in MihomoPolicyCompiler.GoogleProxyExactDomains) RequireDnsGroup(nameserverPolicy, domain, active);
        foreach (var domain in BifrostServiceRouting.YoutubeSuffixes) RequireDnsGroup(nameserverPolicy, $"+.{domain}", active);
        foreach (var domain in BifrostServiceRouting.YoutubeDomains) RequireDnsGroup(nameserverPolicy, domain, active);
        foreach (var domain in MihomoPolicyCompiler.ChatGptProxyDomainSuffixes)
            RequireDnsGroup(nameserverPolicy, $"+.{domain}", chatGptActive);
        foreach (var domain in MihomoPolicyCompiler.ChatGptProxyExactDomains)
            RequireDnsGroup(nameserverPolicy, domain, chatGptActive);
        RequireDnsGroup(nameserverPolicy, "geosite:openai", chatGptActive);
        foreach (var domain in MihomoPolicyCompiler.SteamDownloadDirectDomainSuffixes)
            RequireDnsGroup(nameserverPolicy, $"+.{domain}", "BIFROST-DIRECT");
        if (nameserverPolicy["geosite:category-ads-all"] is not JsonArray { Count: 1 } adDns ||
            adDns[0]?.GetValue<string>() != "rcode://success")
            throw new InvalidDataException("BF-CONFIG-DNS");
        foreach (var geosite in MihomoPolicyCompiler.DomesticDirectGeosites)
            RequireDnsGroup(nameserverPolicy, $"geosite:{geosite}", "BIFROST-DIRECT");
        RequireDnsGroup(nameserverPolicy, "geosite:geolocation-!cn", active);
        foreach (var domain in BifrostServiceRouting.Domains) RequireDnsGroup(nameserverPolicy, domain, active);
        foreach (var domain in MihomoPolicyCompiler.MicrosoftProxyExactDomains) RequireDnsGroup(nameserverPolicy, domain, active);
        foreach (var geosite in MihomoPolicyCompiler.ForeignProxyGeosites)
            RequireDnsGroup(nameserverPolicy, $"geosite:{geosite}", active);
    }

    private static void RequireDnsGroup(JsonObject policy, string key, string group)
    {
        if (policy[key] is not JsonArray { Count: 1 } values || values[0]?.GetValue<string>() is not string value ||
            !value.EndsWith("#" + group, StringComparison.Ordinal)) throw new InvalidDataException("BF-CONFIG-DNS");
    }

    private static string? DnsPolicyHost(string? resolver)
    {
        if (string.IsNullOrWhiteSpace(resolver)) return null;
        var separator = resolver.LastIndexOf('#');
        var url = separator > 0 ? resolver[..separator] : resolver;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host) ||
            System.Net.IPAddress.TryParse(uri.Host, out _)) return null;
        return uri.Host.TrimEnd('.').ToLowerInvariant();
    }

    private static void ValidateRuntimePolicy(JsonObject main, string mode, bool smartGate, string active, string chatGptActive, ApplicationPolicySnapshot policy)
    {
        var rules = (main["rules"] as JsonArray)?.Select(item => item?.GetValue<string>() ?? string.Empty).ToArray()
            ?? throw new InvalidDataException("BF-MIHOMO-RULES");
        string[] expected;
        if (mode == "global") expected = new[] { $"MATCH,{active}" };
        else if (mode == "smart")
        {
            var smart = new List<string>
            {
                "PROCESS-NAME,QQ.exe,BIFROST-DIRECT",
                "PROCESS-NAME,QQNT.exe,BIFROST-DIRECT",
                "PROCESS-NAME,TIM.exe,BIFROST-DIRECT",
            };
            smart.AddRange(MihomoPolicyCompiler.LocalDirectExactDomains.Select(domain => $"DOMAIN,{domain},BIFROST-DIRECT"));
            smart.AddRange(MihomoPolicyCompiler.LocalDirectDomainSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT"));
            smart.AddRange(MihomoPolicyCompiler.TencentDirectDomainSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT"));
            smart.AddRange(MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT"));
            smart.AddRange(MihomoPolicyCompiler.SystemDirectExactDomains.Select(domain => $"DOMAIN,{domain},BIFROST-DIRECT"));
            smart.AddRange(MihomoPolicyCompiler.SystemDirectDomainSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT"));
            var dns = main["dns"]?.AsObject() ?? throw new InvalidDataException("BF-CONFIG-DNS");
            var directDnsHost = DnsPolicyHost(dns["direct-nameserver"]?[0]?.GetValue<string>());
            var remoteDnsHost = DnsPolicyHost(dns["nameserver"]?[0]?.GetValue<string>());
            if (directDnsHost is not null) smart.Add($"DOMAIN,{directDnsHost},BIFROST-DIRECT");
            if (remoteDnsHost is not null && !string.Equals(remoteDnsHost, directDnsHost, StringComparison.OrdinalIgnoreCase))
                smart.Add($"DOMAIN,{remoteDnsHost},{active}");
            smart.Add("DST-PORT,853,REJECT");
            smart.AddRange(MihomoPolicyCompiler.DnsBypassBlockGeosites.Select(geosite => $"GEOSITE,{geosite},REJECT"));
            smart.AddRange(MihomoPolicyCompiler.GoogleProxyDomainSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},{active}"));
            smart.AddRange(MihomoPolicyCompiler.GoogleProxyExactDomains.Select(domain => $"DOMAIN,{domain},{active}"));
            smart.AddRange(BifrostServiceRouting.YoutubeSuffixes.Select(domain => $"DOMAIN-SUFFIX,{domain},{active}"));
            smart.AddRange(BifrostServiceRouting.YoutubeDomains.Select(domain => $"DOMAIN,{domain},{active}"));
            smart.AddRange(MihomoPolicyCompiler.ChatGptProxyDomainSuffixes.Select(domain =>
                $"DOMAIN-SUFFIX,{domain},{chatGptActive}"));
            smart.AddRange(MihomoPolicyCompiler.ChatGptProxyExactDomains.Select(domain =>
                $"DOMAIN,{domain},{chatGptActive}"));
            smart.Add($"GEOSITE,openai,{chatGptActive}");
            smart.AddRange(MihomoPolicyCompiler.SteamDownloadDirectDomainSuffixes.Select(domain =>
                $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT"));
            smart.AddRange(new[]
            {
                "GEOSITE,category-ads-all,REJECT",
                "GEOSITE,private,BIFROST-DIRECT",
                "GEOIP,private,BIFROST-DIRECT,no-resolve",
                "IP-CIDR,127.0.0.0/8,BIFROST-DIRECT,no-resolve",
                "IP-CIDR,10.0.0.0/8,BIFROST-DIRECT,no-resolve",
                "IP-CIDR,172.16.0.0/12,BIFROST-DIRECT,no-resolve",
                "IP-CIDR,192.168.0.0/16,BIFROST-DIRECT,no-resolve",
                "IP-CIDR,169.254.0.0/16,BIFROST-DIRECT,no-resolve",
                "IP-CIDR,100.64.0.0/10,BIFROST-DIRECT,no-resolve",
                "IP-CIDR6,::1/128,BIFROST-DIRECT,no-resolve",
                "IP-CIDR6,fc00::/7,BIFROST-DIRECT,no-resolve",
                "IP-CIDR6,fe80::/10,BIFROST-DIRECT,no-resolve",
            });
            smart.AddRange(BifrostServiceRouting.Domains.Select(domain => $"DOMAIN,{domain},{active}"));
            smart.AddRange(MihomoPolicyCompiler.MicrosoftProxyExactDomains.Select(domain => $"DOMAIN,{domain},{active}"));
            smart.AddRange(MihomoPolicyCompiler.DomesticDirectGeosites.Select(geosite => $"GEOSITE,{geosite},BIFROST-DIRECT"));
            smart.AddRange(MihomoPolicyCompiler.ForeignProxyGeosites.Select(geosite => $"GEOSITE,{geosite},{active}"));
            smart.AddRange(new[]
            {
                $"GEOSITE,{MihomoPolicyCompiler.DomesticTldGeosite},BIFROST-DIRECT",
                "GEOSITE,cn,BIFROST-DIRECT",
                $"GEOSITE,geolocation-!cn,{active}",
                "GEOIP,CN,BIFROST-DIRECT,no-resolve",
                $"MATCH,{active}",
            });
            expected = smart.ToArray();
        }
        else if (mode == "per-app" && policy.PolicyMode == "allow")
            expected = policy.IncludeIdentities.Select(identity => $"PROCESS-NAME,{identity},{active}").Append("MATCH,BIFROST-DIRECT").ToArray();
        else if (mode == "per-app" && policy.PolicyMode == "exclude")
            expected = policy.ExcludeIdentities.Select(identity => $"PROCESS-NAME,{identity},BIFROST-DIRECT").Append($"MATCH,{active}").ToArray();
        else throw new InvalidDataException("BF-MIHOMO-RULES");
        if (mode != "per-app")
            expected = MihomoWindowsContract.DataPlaneProbeHosts.Select(host => $"DOMAIN,{host},{active}").Concat(expected).ToArray();
        if (!rules.SequenceEqual(expected, StringComparer.Ordinal)) throw new InvalidDataException("BF-MIHOMO-RULES");
    }
}
