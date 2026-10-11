using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

internal static class MihomoConfigCompiler
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    // Configuration version 123 was signed while the local Control process
    // still carried the development DNS placeholders.  Those reserved names
    // can never resolve on the public Internet.  Keep one narrow compatibility
    // bridge so already-issued packages recover without weakening normal
    // signed DNS authority: only the two exact historical placeholders are
    // migrated, while every other endpoint is still validated and honored as
    // signed.
    internal const string LegacyRemoteDnsPlaceholder = "https://resolver.example.invalid/dns-query";
    internal const string LegacyDirectDnsPlaceholder = "https://direct.example.invalid/dns-query";
    internal const string ShippingRemoteDns = "https://cloudflare-dns.com/dns-query";
    internal const string ShippingDirectDns = "https://dns.alidns.com/dns-query";

    internal static MihomoCompiledPackage Compile(MihomoCompileInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        ValidateInput(input);
        var provider = MihomoProviderCompiler.Compile(input);
        var dnsPolicy = input.SignedConfig["routing"]?["dns_policy"] as JsonObject
            ?? throw new InvalidDataException("BF-CONFIG-DNS");
        var remoteDns = SafeDns(dnsPolicy["remote"]?.GetValue<string>());
        var directDns = SafeDns(dnsPolicy["direct"]?.GetValue<string>());
        var remoteDnsHost = DnsRuleHost(remoteDns);
        var directDnsHost = DnsRuleHost(directDns);
        var policy = MihomoPolicyCompiler.Compile(input, provider, remoteDnsHost, directDnsHost);
        var enableIpv6 = input.EnableIpv6 && dnsPolicy["ipv6"]?.GetValue<string>() == "proxy";
        if (dnsPolicy["plaintext_fallback"]?.GetValue<bool>() != false || dnsPolicy["failure"]?.GetValue<string>() != "block")
            throw new InvalidDataException("BF-DNS-PLAINTEXT");

        var remoteProxyDns = remoteDns + "#" + policy.ActiveGroup;
        var chatGptProxyDns = remoteDns + "#" + policy.ChatGptGroupName;
        // DIRECT data is explicitly pinned to the physical underlay. DNS for
        // DIRECT traffic and proxy-node bootstrap must use the same boundary;
        // otherwise respect-rules can make a direct DoH connection recurse
        // back through the TUN or an already selected proxy group.
        var directBoundDns = directDns + "#BIFROST-DIRECT";
        // Order specific service policies before broad geosite policies.  This
        // is intentionally symmetric with the route rules: a ChatGPT hostname
        // must resolve through the same selected proxy group that will carry
        // its HTTPS connection, even if GeoIP/geosite data is stale or a CDN
        // address would otherwise look domestic.
        var nameserverPolicy = new JsonObject
        {
            ["www.gstatic.com"] = new JsonArray(directBoundDns),
            ["cp.cloudflare.com"] = new JsonArray(directBoundDns),
        };
        // Domain-based splitting belongs only to smart mode. In global mode
        // it selected domestic CDN answers for traffic using a foreign exit;
        // in per-app mode it overrode the user's process-based routing choice.
        // Keep only the two bounded health bootstrap exceptions in other modes.
        if (input.RouteMode == "smart")
        {
            if (directDnsHost is not null) nameserverPolicy[directDnsHost] = new JsonArray(directBoundDns);
            if (remoteDnsHost is not null && !string.Equals(remoteDnsHost, directDnsHost, StringComparison.OrdinalIgnoreCase))
                nameserverPolicy[remoteDnsHost] = new JsonArray(remoteProxyDns);
            foreach (var domain in MihomoPolicyCompiler.LocalDirectExactDomains)
                nameserverPolicy[domain] = new JsonArray(directBoundDns);
            foreach (var domain in MihomoPolicyCompiler.LocalDirectDomainSuffixes.Concat(MihomoPolicyCompiler.LocalDnsOnlySuffixes))
                nameserverPolicy[$"+.{domain}"] = new JsonArray(directBoundDns);
            foreach (var domain in MihomoPolicyCompiler.TencentDirectDomainSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(directBoundDns);
            foreach (var domain in MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(directBoundDns);
            foreach (var domain in MihomoPolicyCompiler.SystemDirectExactDomains)
                nameserverPolicy[domain] = new JsonArray(directBoundDns);
            foreach (var domain in MihomoPolicyCompiler.SystemDirectDomainSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(directBoundDns);
            foreach (var domain in MihomoPolicyCompiler.GoogleProxyDomainSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(remoteProxyDns);
            foreach (var domain in MihomoPolicyCompiler.GoogleProxyExactDomains)
                nameserverPolicy[domain] = new JsonArray(remoteProxyDns);
            foreach (var domain in BifrostServiceRouting.YoutubeSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(remoteProxyDns);
            foreach (var domain in BifrostServiceRouting.YoutubeDomains)
                nameserverPolicy[domain] = new JsonArray(remoteProxyDns);
            foreach (var domain in MihomoPolicyCompiler.ChatGptProxyDomainSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(chatGptProxyDns);
            foreach (var domain in MihomoPolicyCompiler.ChatGptProxyExactDomains)
                nameserverPolicy[domain] = new JsonArray(chatGptProxyDns);
            nameserverPolicy["geosite:openai"] = new JsonArray(chatGptProxyDns);
            foreach (var domain in MihomoPolicyCompiler.SteamDownloadDirectDomainSuffixes)
                nameserverPolicy[$"+.{domain}"] = new JsonArray(directBoundDns);
            // Advertising is already terminally rejected by the route policy;
            // answer it locally instead of leaking a useless query upstream.
            nameserverPolicy["geosite:category-ads-all"] = new JsonArray("rcode://success");
            nameserverPolicy["geosite:private"] = new JsonArray(directBoundDns);
            foreach (var domain in BifrostServiceRouting.Domains)
                nameserverPolicy[domain] = new JsonArray(remoteProxyDns);
            foreach (var domain in MihomoPolicyCompiler.MicrosoftProxyExactDomains)
                nameserverPolicy[domain] = new JsonArray(remoteProxyDns);
            foreach (var geosite in MihomoPolicyCompiler.DomesticDirectGeosites)
                nameserverPolicy[$"geosite:{geosite}"] = new JsonArray(directBoundDns);
            foreach (var geosite in MihomoPolicyCompiler.ForeignProxyGeosites)
                nameserverPolicy[$"geosite:{geosite}"] = new JsonArray(remoteProxyDns);
            nameserverPolicy[$"geosite:{MihomoPolicyCompiler.DomesticTldGeosite}"] = new JsonArray(directBoundDns);
            nameserverPolicy["geosite:cn"] = new JsonArray(directBoundDns);
            nameserverPolicy["geosite:geolocation-!cn"] = new JsonArray(remoteProxyDns);
        }
        var fakeIpFilter = new JsonArray("GEOSITE,private,real-ip");
        foreach (var domain in MihomoPolicyCompiler.LocalDirectExactDomains)
            fakeIpFilter.Add($"DOMAIN,{domain},real-ip");
        foreach (var domain in MihomoPolicyCompiler.LocalDirectDomainSuffixes.Concat(MihomoPolicyCompiler.LocalDnsOnlySuffixes))
            fakeIpFilter.Add($"DOMAIN-SUFFIX,{domain},real-ip");
        if (input.RouteMode == "smart")
        {
            foreach (var domain in MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes)
                fakeIpFilter.Add($"DOMAIN-SUFFIX,{domain},real-ip");
            foreach (var domain in MihomoPolicyCompiler.SystemDirectExactDomains)
                fakeIpFilter.Add($"DOMAIN,{domain},real-ip");
            foreach (var domain in MihomoPolicyCompiler.SystemDirectDomainSuffixes)
                fakeIpFilter.Add($"DOMAIN-SUFFIX,{domain},real-ip");
        }
        fakeIpFilter.Add("MATCH,fake-ip");

        var providerEntry = new JsonObject
        {
            ["type"] = "file",
            ["path"] = input.ProviderFileName.Replace('\\', '/'),
            ["health-check"] = new JsonObject
            {
                ["enable"] = true,
                // Startup health must not resolve a hostname through the
                // SmartGate group that this very probe is trying to select.
                // Its exact DNS policy above bootstraps through direct DoH,
                // independently of the group being tested.
                ["url"] = MihomoWindowsContract.StartupProbeUrl,
                ["interval"] = 300,
                ["timeout"] = 5000,
                ["lazy"] = false,
                ["expected-status"] = MihomoWindowsContract.StartupProbeExpectedStatus,
            },
        };
        var main = new JsonObject
        {
            ["allow-lan"] = false,
            ["bind-address"] = "127.0.0.1",
            // Apply the verified physical underlay to every outbound, not only
            // the VMess provider entries.  In smart mode, DIRECT traffic is
            // emitted by Mihomo itself; without this global binding Windows
            // can feed that traffic straight into a pre-existing v2rayN /
            // sing-box TUN and turn "domestic direct" into a second proxy hop.
            ["interface-name"] = input.UnderlayInterface,
            ["mixed-port"] = input.ControllerPort + 1,
            ["mode"] = "rule",
            ["log-level"] = "warning",
            ["ipv6"] = enableIpv6,
            ["unified-delay"] = true,
            ["tcp-concurrent"] = true,
            ["find-process-mode"] = input.RouteMode == "per-app" ? "always" : "strict",
            ["keep-alive-interval"] = 15,
            ["keep-alive-idle"] = 30,
            ["disable-keep-alive"] = false,
            ["geodata-mode"] = false,
            // This desktop build deliberately favors lookup throughput over
            // the lowest possible memory footprint. The standard loader keeps
            // the routing datasets hot instead of repeatedly optimizing for
            // memory on a long-lived Windows service.
            ["geodata-loader"] = "standard",
            ["geosite-matcher"] = "succinct",
            ["profile"] = new JsonObject
            {
                ["store-selected"] = false,
                ["store-fake-ip"] = true,
            },
            ["sniffer"] = new JsonObject
            {
                ["enable"] = true,
                ["force-dns-mapping"] = true,
                ["parse-pure-ip"] = true,
                ["override-destination"] = true,
                ["sniff"] = new JsonObject
                {
                    ["HTTP"] = new JsonObject { ["ports"] = new JsonArray(80, "8080-8880"), ["override-destination"] = true },
                    ["TLS"] = new JsonObject { ["ports"] = new JsonArray(443, 8443) },
                    ["QUIC"] = new JsonObject { ["ports"] = new JsonArray(443, 8443) },
                },
                ["skip-domain"] = new JsonArray("Mijia Cloud", "+.lan", "+.local", "+.push.apple.com"),
            },
            ["external-controller"] = $"127.0.0.1:{input.ControllerPort}",
            ["secret"] = input.ControllerSecret,
            ["tun"] = new JsonObject
            {
                ["enable"] = true,
                ["stack"] = "mixed",
                ["device"] = input.TunName,
                ["inet4-address"] = new JsonArray(MihomoWindowsContract.TunIpv4Cidr),
                ["auto-route"] = false,
                ["strict-route"] = false,
                ["auto-detect-interface"] = false,
                ["dns-hijack"] = new JsonArray("any:53", "tcp://any:53"),
                ["mtu"] = 1500,
            },
            ["dns"] = new JsonObject
            {
                ["enable"] = true,
                ["listen"] = "127.0.0.1:0",
                ["ipv6"] = enableIpv6,
                ["prefer-h3"] = false,
                ["use-hosts"] = true,
                ["use-system-hosts"] = true,
                ["enhanced-mode"] = "fake-ip",
                ["fake-ip-range"] = "198.18.0.1/16",
                ["cache-algorithm"] = "arc",
                ["fake-ip-filter-mode"] = "rule",
                ["fake-ip-filter"] = fakeIpFilter,
                ["respect-rules"] = true,
                ["default-nameserver"] = new JsonArray(DefaultDns(directDns)),
                ["nameserver"] = new JsonArray(remoteProxyDns),
                ["proxy-server-nameserver"] = new JsonArray(directBoundDns),
                ["direct-nameserver"] = new JsonArray(directBoundDns),
                // A process explicitly excluded from the VPN must resolve its
                // real destination with the direct resolver, not a foreign
                // service policy inherited from smart mode.
                ["direct-nameserver-follow-policy"] = input.RouteMode == "smart",
                ["nameserver-policy"] = nameserverPolicy,
            },
            ["proxy-providers"] = new JsonObject { [provider.ProviderName] = providerEntry },
            ["proxy-groups"] = policy.ChatGptGroup is null
                ? new JsonArray(policy.Group)
                : new JsonArray(policy.Group, policy.ChatGptGroup),
            ["rules"] = policy.Rules,
        };
        if (enableIpv6)
        {
            main["tun"]!["inet6-address"] = new JsonArray(MihomoWindowsContract.TunIpv6Cidr);
            main["dns"]!["fake-ip-range6"] = MihomoWindowsContract.FakeIpv6Cidr;
        }
        var runtimeProxies = new JsonArray(new JsonObject
        {
            ["name"] = "BIFROST-DIRECT", ["type"] = "direct",
            ["ip-version"] = "ipv4-prefer", ["udp"] = true,
            ["interface-name"] = input.UnderlayInterface,
        });
        foreach (var frontProxy in provider.FrontProxies) runtimeProxies.Add(frontProxy.DeepClone());
        if (runtimeProxies.Count > 0) main["proxies"] = runtimeProxies;
        var providerBytes = JsonSerializer.SerializeToUtf8Bytes(provider.Document, JsonOptions);
        var mainBytes = JsonSerializer.SerializeToUtf8Bytes(main, JsonOptions);
        var digest = Convert.ToHexString(SHA256.HashData(mainBytes.Concat(providerBytes).ToArray())).ToLowerInvariant();
        var preferredCandidates = (provider.Document["proxies"] as JsonArray)?.OfType<JsonObject>()
            .Select(proxy => proxy["name"]?.GetValue<string>()).Where(name => !string.IsNullOrWhiteSpace(name))
            .Cast<string>().ToArray() ?? Array.Empty<string>();
        var package = new MihomoCompiledPackage(mainBytes, providerBytes, provider.ProviderName, policy.ActiveGroup,
            provider.Candidates, digest, policy.ChatGptGroup is null ? null : policy.ChatGptGroupName, preferredCandidates);
        MihomoConfigValidator.Validate(package, input);
        return package;
    }

    private static void ValidateInput(MihomoCompileInput input)
    {
        if (input.ControllerPort is < 1024 or >= 65534 || input.ControllerPort + 1 > 65535)
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        if (input.ControllerSecret.Length is < 32 or > 256 || input.ControllerSecret.Any(char.IsControl))
            throw new InvalidDataException("BF-MIHOMO-CONTROLLER");
        if (input.TunName != "bifrost1") throw new InvalidDataException("BF-TUN-CONFIG");
        var provider = input.ProviderFileName.Replace('\\', '/');
        if (!provider.StartsWith("providers/", StringComparison.Ordinal) || provider.Contains("..", StringComparison.Ordinal) ||
            !provider.EndsWith(".json", StringComparison.Ordinal)) throw new InvalidDataException("BF-MIHOMO-PROVIDER");
        if (input.ApplicationPolicy.RouteMode != input.RouteMode)
            throw new InvalidDataException("BF-APP-POLICY-SNAPSHOT");
    }

    private static string SafeDns(string? value)
    {
        if (string.Equals(value, LegacyRemoteDnsPlaceholder, StringComparison.OrdinalIgnoreCase))
            value = ShippingRemoteDns;
        else if (string.Equals(value, LegacyDirectDnsPlaceholder, StringComparison.OrdinalIgnoreCase))
            value = ShippingDirectDns;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 ||
            !string.IsNullOrEmpty(uri.Fragment) || string.IsNullOrWhiteSpace(uri.Host)) throw new InvalidDataException("BF-DNS-PLAINTEXT");
        return uri.AbsoluteUri;
    }

    private static string? DnsRuleHost(string value)
    {
        var host = new Uri(value, UriKind.Absolute).Host.TrimEnd('.').ToLowerInvariant();
        return System.Net.IPAddress.TryParse(host, out _) ? null : host;
    }

    private static string DefaultDns(string directDns)
    {
        var uri = new Uri(directDns, UriKind.Absolute);
        return System.Net.IPAddress.TryParse(uri.Host, out _) ? directDns : "https://223.5.5.5/dns-query";
    }
}
