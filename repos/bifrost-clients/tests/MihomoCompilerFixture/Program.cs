using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Bifrost.ClientService;

static class Fixture
{
    private static int Main(string[] args)
    {
        if (args.Length > 0) return CompileSignedConfig(args);

        var signed = SignedConfig();
        var policy = ApplicationPolicySnapshot.Create("smart", "none", Array.Empty<string>(), Array.Empty<string>(), new string('a', 32));
        var large = SignedConfig();
        foreach (var sourceNode in large["sources"]!.AsArray())
        {
            var source = sourceNode!.AsObject();
            var code = source["code"]!.GetValue<string>();
            source["candidates"] = new JsonArray(Enumerable.Range(1, 300).Select(index => (JsonNode)new JsonObject
            {
                ["label"] = $"{code}-{index:D2}", ["dial_address"] = $"candidate-{code}-{index}.test", ["port"] = 443
            }).ToArray());
        }
        var largeCompiled = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            large, "A", "direct-vmess", "smart", null, "default", policy,
            "TEST-ONLY-ETHERNET", 19099, new string('s', 48), "bifrost1", "providers/source-A.json", null));
        Assert(largeCompiled.AllowedCandidates.Count == 300 && largeCompiled.AllowedCandidates.Contains("A-300"), "300 candidates remain selectable");
        var smart = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "smart", null, "default", policy,
            "TEST-ONLY-ETHERNET", 19099, new string('s', 48), "bifrost1", "providers/source-A.json", null));

        var legacyDnsSigned = signed.DeepClone().AsObject();
        legacyDnsSigned["routing"]!["dns_policy"]!["remote"] = MihomoConfigCompiler.LegacyRemoteDnsPlaceholder;
        legacyDnsSigned["routing"]!["dns_policy"]!["direct"] = MihomoConfigCompiler.LegacyDirectDnsPlaceholder;
        var legacyDnsCompiled = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            legacyDnsSigned, "A", "direct-vmess", "smart", null, "default", policy,
            "TEST-ONLY-ETHERNET", 19109, new string('l', 48), "bifrost1", "providers/source-A.json", null));
        var legacyDnsMain = JsonNode.Parse(legacyDnsCompiled.MainConfig)!.AsObject();
        Assert(legacyDnsMain["dns"]!["nameserver"]![0]!.GetValue<string>() ==
               MihomoConfigCompiler.ShippingRemoteDns + "#BIFROST-SMART-A" &&
               legacyDnsMain["dns"]!["direct-nameserver"]![0]!.GetValue<string>() ==
               MihomoConfigCompiler.ShippingDirectDns + "#BIFROST-DIRECT" &&
               !legacyDnsMain.ToJsonString().Contains("example.invalid", StringComparison.OrdinalIgnoreCase),
            "legacy signed DNS placeholders migrate only to the audited shipping DoH endpoints");

        Assert(smart.ActiveGroup == "BIFROST-SMART-A", "smart A active group");
        Assert(smart.AllowedCandidates.SetEquals(new[] { "A-01", "A-02", "A-03" }), "smart A candidate authority");
        var provider = JsonNode.Parse(smart.Provider)!.AsObject();
        Assert(provider["proxies"]!.AsArray().Select(item => item!["name"]!.GetValue<string>()).SequenceEqual(new[] { "A-01", "A-02", "A-03" }), "provider carries A only");
        Assert(!provider.ToJsonString().Contains("B-01", StringComparison.Ordinal), "provider never crosses to B");

        var main = JsonNode.Parse(smart.MainConfig)!.AsObject();
        var preferredDirect = main["proxies"]!.AsArray().OfType<JsonObject>().Single(p => p["name"]?.GetValue<string>() == "BIFROST-DIRECT");
        Assert(preferredDirect["ip-version"]?.GetValue<string>() == "ipv4-prefer", "direct prefers IPv4 with IPv6 fallback");
        Assert(main["dns"]!["fake-ip-filter"]!.AsArray().Select(rule => rule!.GetValue<string>()).SequenceEqual(
            new[] {
                "GEOSITE,private,real-ip", "DOMAIN,localhost,real-ip", "DOMAIN-SUFFIX,lan,real-ip",
                "DOMAIN-SUFFIX,local,real-ip", "DOMAIN-SUFFIX,home.arpa,real-ip", "DOMAIN-SUFFIX,arpa,real-ip",
                "DOMAIN-SUFFIX,edu.cn,real-ip", "DOMAIN-SUFFIX,gov.cn,real-ip", "DOMAIN-SUFFIX,ac.cn,real-ip",
                "DOMAIN,captive.apple.com,real-ip", "DOMAIN,dns.msftncsi.com,real-ip",
                "DOMAIN,time.apple.com,real-ip", "DOMAIN,time.windows.com,real-ip",
                "DOMAIN,www.msftconnecttest.com,real-ip", "DOMAIN,www.msftncsi.com,real-ip",
                "DOMAIN-SUFFIX,pool.ntp.org,real-ip", "MATCH,fake-ip"
            }),
            "smart routing limits real-IP DNS to private and OS compatibility names");
        var badDirect = main.DeepClone().AsObject();
        badDirect["proxies"]!.AsArray().OfType<JsonObject>().Single(p => p["name"]?.GetValue<string>() == "BIFROST-DIRECT")["ip-version"] = "ipv6";
        ExpectCode(() => MihomoConfigValidator.ValidateStaged(JsonSerializer.SerializeToUtf8Bytes(badDirect), smart.Provider, "A", "smart", policy), "BF-CONFIG-IPV6");
        Assert(main["ipv6"]!.GetValue<bool>() && main["dns"]!["ipv6"]!.GetValue<bool>() &&
            main["tun"]!["inet6-address"]![0]!.GetValue<string>() == MihomoWindowsContract.TunIpv6Cidr &&
            main["dns"]!["fake-ip-range6"]!.GetValue<string>() == MihomoWindowsContract.FakeIpv6Cidr,
            "IPv6 routing and virtual DNS are enabled as one validated contract");
        var ipv4 = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "smart", null, "default", policy,
            "TEST-ONLY-ETHERNET", 19099, new string('s', 48), "bifrost1", "providers/source-A.json", null,
            EnableIpv6: false));
        var ipv4Main = JsonNode.Parse(ipv4.MainConfig)!.AsObject();
        Assert(!ipv4Main["ipv6"]!.GetValue<bool>() && !ipv4Main["dns"]!["ipv6"]!.GetValue<bool>() &&
            ipv4Main["tun"]!["inet6-address"] is null && ipv4Main["dns"]!["fake-ip-range6"] is null,
            "IPv4-only compatibility keeps the original tunnel and DNS configuration");
        var mismatchedFamily = JsonNode.Parse(smart.MainConfig)!.AsObject();
        mismatchedFamily["tun"]!.AsObject().Remove("inet6-address");
        ExpectCode(() => MihomoConfigValidator.ValidateStaged(
            JsonSerializer.SerializeToUtf8Bytes(mismatchedFamily), smart.Provider, "A", "smart", policy), "BF-CONFIG-IPV6");
        Assert(main["interface-name"]!.GetValue<string>() == "TEST-ONLY-ETHERNET", "all outbounds bind physical underlay");
        var providerHealth = main["proxy-providers"]![smart.ProviderName]!["health-check"]!.AsObject();
        var groups = main["proxy-groups"]!.AsArray();
        Assert(groups.Count == 2, "smart mode emits general and ChatGPT-sticky health groups");
        var group = groups[0]!.AsObject();
        var chatGptGroup = groups[1]!.AsObject();
        Assert(group["type"]!.GetValue<string>() == "url-test", "smart uses url-test");
        Assert(group["url"]!.GetValue<string>() == "https://www.gstatic.com/generate_204" &&
               providerHealth["url"]!.GetValue<string>() == group["url"]!.GetValue<string>(),
            "provider and URLTest share the production startup probe");
        Assert(group["expected-status"]!.GetValue<int>() == 204 &&
               providerHealth["expected-status"]!.GetValue<int>() == group["expected-status"]!.GetValue<int>(),
            "provider and URLTest compare the same probe result domain");
        Assert(group["tolerance"]!.GetValue<int>() == MihomoPolicyCompiler.AutoSelectToleranceMs,
            "native URLTest owns automatic selection with a bounded anti-flap tolerance");
        Assert(chatGptGroup["name"]!.GetValue<string>() == "BIFROST-OPENAI-A" &&
               chatGptGroup["type"]!.GetValue<string>() == "fallback" &&
               chatGptGroup["tolerance"] is null &&
               chatGptGroup["use"]!.AsArray().Single()!.GetValue<string>() == smart.ProviderName,
            "ChatGPT uses an independent failure-only sticky group");
        Assert(group["interval"]!.GetValue<int>() == 60, "native one minute health interval");
        Assert(group["timeout"]!.GetValue<int>() == 5000, "five second timeout");
        Assert(group["max-failed-times"]!.GetValue<int>() == 2, "two failures");
        Assert(group["empty-fallback"]!.GetValue<string>() == "REJECT", "all-dead rejects");
        Assert(group["default-selected"] is null, "smart selection has no first-candidate startup bias");
        Assert(main["tun"]!["auto-route"]!.GetValue<bool>() == false, "route-neutral startup");
        Assert(main["tun"]!["inet4-address"]!.AsArray().Single()!.GetValue<string>() == MihomoWindowsContract.TunIpv4Cidr,
            "the TUN address and Windows DNS peer share an explicit pinned subnet");
        Assert(main["tun"]!["strict-route"]!.GetValue<bool>() == false, "service owns cutover");
        Assert(!main.ToJsonString().Contains("COMPATIBLE", StringComparison.Ordinal), "no compatible direct fallback");
        var smartRules = main["rules"]!.AsArray().Select(item => item!.GetValue<string>()).ToArray();
        Assert(smartRules.Take(2).SequenceEqual(new[] { "DOMAIN,www.gstatic.com,BIFROST-SMART-A", "DOMAIN,cp.cloudflare.com,BIFROST-SMART-A" }),
            "Both health endpoints prove the selected proxy before any direct rules");
        Assert(smartRules.Skip(5).Take(4).SequenceEqual(new[]
        {
            "DOMAIN,localhost,BIFROST-DIRECT", "DOMAIN-SUFFIX,lan,BIFROST-DIRECT",
            "DOMAIN-SUFFIX,local,BIFROST-DIRECT", "DOMAIN-SUFFIX,home.arpa,BIFROST-DIRECT"
        }), "local and special-use names bypass public proxy routing");
        Assert(smartRules.Skip(9).Take(6).SequenceEqual(new[]
        {
            "DOMAIN-SUFFIX,qq.com,BIFROST-DIRECT", "DOMAIN-SUFFIX,qpic.cn,BIFROST-DIRECT", "DOMAIN-SUFFIX,gtimg.cn,BIFROST-DIRECT",
            "DOMAIN-SUFFIX,qlogo.cn,BIFROST-DIRECT", "DOMAIN-SUFFIX,tencent.com,BIFROST-DIRECT", "DOMAIN-SUFFIX,myqcloud.com,BIFROST-DIRECT"
        }), "Tencent direct rules precede broad rejection rules");
        Assert(MihomoPolicyCompiler.SystemDirectExactDomains.All(domain =>
            Array.IndexOf(smartRules, $"DOMAIN,{domain},BIFROST-DIRECT") >= 0) &&
            MihomoPolicyCompiler.SystemDirectDomainSuffixes.All(domain =>
                Array.IndexOf(smartRules, $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT") >= 0),
            "OS connectivity and time bootstrap names remain direct");
        var dnsPortBlock = Array.IndexOf(smartRules, "DST-PORT,853,REJECT");
        var dohBlock = Array.IndexOf(smartRules, "GEOSITE,category-doh,REJECT");
        var httpDnsDirect = Array.IndexOf(smartRules, "GEOSITE,category-httpdns-cn,BIFROST-DIRECT");
        Assert(dnsPortBlock >= 0 && dohBlock > dnsPortBlock && httpDnsDirect >= 0,
            "smart routing rejects generic encrypted-DNS bypass while keeping mainland HTTPDNS compatible");
        Assert(MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes.All(domain =>
            Array.IndexOf(smartRules, $"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT") is var index && index >= 0 && index < dohBlock),
            "mainland academic/public namespaces bypass broad category rejection deterministically");
        var openAiRule = Array.IndexOf(smartRules, "DOMAIN-SUFFIX,chatgpt.com,BIFROST-OPENAI-A");
        var rejectRule = Array.IndexOf(smartRules, "GEOSITE,category-ads-all,REJECT");
        var openAiGeositeRule = Array.IndexOf(smartRules, "GEOSITE,openai,BIFROST-OPENAI-A");
        var foreignRule = Array.IndexOf(smartRules, "GEOSITE,geolocation-!cn,BIFROST-SMART-A");
        var tldCnRule = Array.IndexOf(smartRules, $"GEOSITE,{MihomoPolicyCompiler.DomesticTldGeosite},BIFROST-DIRECT");
        var cnDomainRule = Array.IndexOf(smartRules, "GEOSITE,cn,BIFROST-DIRECT");
        var cnIpRule = Array.IndexOf(smartRules, "GEOIP,CN,BIFROST-DIRECT,no-resolve");
        Assert(openAiRule >= 0 && openAiRule < rejectRule, "OpenAI application domains are pinned to proxy before rejection/CN fallback");
        Assert(openAiGeositeRule >= 0 && openAiGeositeRule < rejectRule, "maintained OpenAI geosite is pinned before broad rejection/CN fallback");
        Assert(MihomoPolicyCompiler.ChatGptProxyDomainSuffixes.All(domain =>
            Array.IndexOf(smartRules, $"DOMAIN-SUFFIX,{domain},BIFROST-OPENAI-A") is var index && index >= 0 && index < rejectRule),
            "all official ChatGPT wildcard domains are pinned to one sticky proxy group");
        Assert(MihomoPolicyCompiler.ChatGptProxyExactDomains.All(domain =>
            Array.IndexOf(smartRules, $"DOMAIN,{domain},BIFROST-OPENAI-A") is var index && index >= 0 && index < rejectRule),
            "all official ChatGPT exact dependency hosts are pinned to one sticky proxy group");
        Assert(Array.IndexOf(smartRules, "DOMAIN-SUFFIX,oaiusercontent.com,BIFROST-OPENAI-A") is var uploadRoute &&
               uploadRoute >= 0 && uploadRoute < rejectRule,
            "OpenAI's documented files.oaiusercontent.com upload path is pinned to the sticky OpenAI group");
        Assert(Array.IndexOf(smartRules, "DOMAIN-SUFFIX,chatgpt.com,BIFROST-OPENAI-A") is var websocketRoute &&
               websocketRoute >= 0 && websocketRoute < rejectRule,
            "OpenAI's documented ws.chatgpt.com WebSocket path is pinned to the sticky OpenAI group");
        var rejectedUpload = JsonNode.Parse(smart.MainConfig)!.AsObject();
        rejectedUpload["rules"]!.AsArray().Insert(0,
            "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,oaiusercontent.com)),REJECT");
        ExpectCode(() => MihomoConfigValidator.ValidateStaged(
            JsonSerializer.SerializeToUtf8Bytes(rejectedUpload), smart.Provider, "A", "smart", policy), "BF-MIHOMO-RULES");
        Assert(foreignRule >= 0 && foreignRule < cnIpRule, "foreign domain classification precedes GeoIP CN fallback");
        Assert(MihomoPolicyCompiler.ForeignProxyGeosites.All(geosite =>
               Array.IndexOf(smartRules, $"GEOSITE,{geosite},BIFROST-SMART-A") is var index && index >= 0 && index < cnDomainRule),
            "maintained foreign service GeoSites override broad CN classification");
        Assert(tldCnRule >= 0 && tldCnRule < cnDomainRule && cnDomainRule < foreignRule,
            "China-managed TLD fallback stays direct before broad CN/non-CN geographic classification");
        Assert(smartRules.Length < 256 &&
               Array.IndexOf(smartRules, "DOMAIN-SUFFIX,facebook.com,BIFROST-SMART-A") < 0 &&
               Array.IndexOf(smartRules, "DOMAIN-SUFFIX,github.com,BIFROST-SMART-A") < 0,
            "smart routing keeps the hot rule chain compact instead of expanding the full service suffix catalogue");
        Assert(Array.IndexOf(smartRules, "DOMAIN-SUFFIX,gvt2-cn.com,BIFROST-SMART-A") < Array.IndexOf(smartRules, "GEOSITE,cn,BIFROST-DIRECT"),
            "Google regional downloads cannot be split by overlapping CN categories");
        var dnsPolicy = main["dns"]!["nameserver-policy"]!.AsObject();
        Assert(dnsPolicy.ContainsKey("geosite:geolocation-!cn") && dnsPolicy.ContainsKey("+.chatgpt.com") &&
               dnsPolicy.ContainsKey("+.openai.com") && dnsPolicy.ContainsKey("+.oaiusercontent.com") &&
               dnsPolicy.ContainsKey("+.oaistatsig.com") && dnsPolicy.ContainsKey("geosite:openai"),
            "foreign/OpenAI DNS follows the selected proxy group");
        Assert(MihomoPolicyCompiler.ChatGptProxyDomainSuffixes.All(domain => dnsPolicy.ContainsKey($"+.{domain}")) &&
               MihomoPolicyCompiler.ChatGptProxyExactDomains.All(dnsPolicy.ContainsKey),
            "DNS mirrors the complete ChatGPT service route boundary");
        Assert(MihomoPolicyCompiler.DomesticDirectGeosites.All(geosite =>
               dnsPolicy.ContainsKey($"geosite:{geosite}")),
            "DNS includes maintained domestic service subsets");
        Assert(MihomoPolicyCompiler.ForeignProxyGeosites.All(geosite =>
               dnsPolicy.ContainsKey($"geosite:{geosite}")),
            "DNS includes maintained foreign service categories");
        Assert(MihomoPolicyCompiler.DomesticDirectGeosites.SequenceEqual(
               new[] { "apple-cn", "onedrive", "microsoft@cn", "steam@cn", "category-games@cn",
                   "category-ai-cn", "category-automobile-cn", "category-bank-cn", "category-blog-cn",
                   "category-cdn-cn", "category-collaborate-cn", "category-companies@cn", "category-dev@cn",
                   "category-documents-cn", "category-education-cn", "category-electronic-cn", "category-ecommerce@cn",
                   "category-httpdns-cn" }),
            "domestic direct policy includes the complete pinned MetaCubeX service subsets");
        Assert(dnsPolicy["geosite:category-ads-all"]!.AsArray().Single()!.GetValue<string>() == "rcode://success",
            "advertising DNS is terminated locally instead of leaking upstream");
        Assert(dnsPolicy["+.chatgpt.com"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-OPENAI-A", StringComparison.Ordinal) &&
               dnsPolicy["geosite:openai"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-OPENAI-A", StringComparison.Ordinal) &&
               dnsPolicy["geosite:geolocation-!cn"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-SMART-A", StringComparison.Ordinal),
            "ChatGPT DNS stays on the sticky OpenAI group while generic foreign DNS remains latency-responsive");
        Assert(dnsPolicy["+.oaiusercontent.com"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-OPENAI-A", StringComparison.Ordinal) &&
               dnsPolicy["+.chatgpt.com"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-OPENAI-A", StringComparison.Ordinal),
            "upload and WebSocket DNS resolution follows the same sticky OpenAI egress as the HTTPS session");
        Assert(MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes.All(domain =>
               dnsPolicy[$"+.{domain}"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal)),
            "mainland academic/public DNS stays on the physical direct resolver");
        Assert(MihomoPolicyCompiler.DomesticPriorityDirectDomainSuffixes.All(domain =>
               main["dns"]!["fake-ip-filter"]!.AsArray().Any(rule =>
                   rule!.GetValue<string>() == $"DOMAIN-SUFFIX,{domain},real-ip")),
            "mainland academic/public namespaces use real IP answers for maximum direct-site compatibility");
        Assert(dnsPolicy["+.local"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal) &&
               dnsPolicy["+.qq.com"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal) &&
               dnsPolicy["www.msftconnecttest.com"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal) &&
               dnsPolicy["+.pool.ntp.org"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal) &&
               main["dns"]!["direct-nameserver"]![0]!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal) &&
               main["dns"]!["proxy-server-nameserver"]![0]!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal),
            "local/domestic and node bootstrap DNS is pinned to the physical direct boundary");
        Assert(main["dns"]!["fake-ip-filter"]!.AsArray().All(rule =>
                rule!.GetValue<string>() != "GEOSITE,cn,real-ip"),
            "public CN DNS stays on fake-IP fast path and is re-resolved only after DIRECT routing");
        Assert(MihomoPolicyCompiler.DomesticDirectGeosites.All(geosite =>
               main["dns"]!["fake-ip-filter"]!.AsArray().All(rule =>
                   rule!.GetValue<string>() != $"GEOSITE,{geosite},real-ip")),
            "domestic service subsets retain fake-IP domain classification until DIRECT re-resolution");
        Assert(MihomoPolicyCompiler.DomesticDirectGeosites.All(geosite =>
               dnsPolicy[$"geosite:{geosite}"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal)),
            "domestic Apple/Microsoft/OneDrive/Steam/game DNS stays on encrypted direct DNS");
        Assert(dnsPolicy[$"geosite:{MihomoPolicyCompiler.DomesticTldGeosite}"]!.AsArray().Single()!.GetValue<string>()
                .EndsWith("#BIFROST-DIRECT", StringComparison.Ordinal),
            "China-managed TLD DNS uses encrypted direct DNS");
        Assert(MihomoPolicyCompiler.ForeignProxyGeosites.All(geosite =>
               dnsPolicy[$"geosite:{geosite}"]!.AsArray().Single()!.GetValue<string>().EndsWith("#BIFROST-SMART-A", StringComparison.Ordinal)),
            "foreign service GeoSite DNS stays on encrypted proxy DNS");
        Assert(MihomoPolicyCompiler.DomesticDirectGeosites.All(geosite =>
               Array.IndexOf(smartRules, $"GEOSITE,{geosite},BIFROST-DIRECT") is var index &&
               index >= 0 && index < foreignRule),
            "maintained domestic service routes precede foreign fallback");
        var dnsKeys = dnsPolicy.Select(item => item.Key).ToArray();
        Assert(Array.IndexOf(dnsKeys, "www.gstatic.com") < Array.IndexOf(dnsKeys, "geosite:geolocation-!cn") &&
               Array.IndexOf(dnsKeys, "+.oaiusercontent.com") < Array.IndexOf(dnsKeys, "geosite:cn"),
            "specific DNS policies precede broad geographic policies");

        var coexist = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "smart", null, "default", policy,
            "TEST-ONLY-ETHERNET", 19103, new string('w', 48), "bifrost1", "providers/source-A.json",
            new MihomoBootstrapProxy("socks5", 10808)));
        Assert(JsonNode.Parse(coexist.MainConfig)!["proxies"]!.AsArray().All(item => item?["type"]?.GetValue<string>() == "direct"), "Mihomo never depends on a third-party user-session bootstrap");
        Assert(JsonNode.Parse(coexist.Provider)!["proxies"]!.AsArray().All(item =>
            item!["interface-name"]!.GetValue<string>() == "TEST-ONLY-ETHERNET" && item!["dialer-proxy"] is null),
            "every candidate binds the physical underlay directly");

        var fixedPolicy = ApplicationPolicySnapshot.Create("global", "none", Array.Empty<string>(), Array.Empty<string>(), new string('b', 32));
        var fixedRoute = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "global", "A-02", "default", fixedPolicy,
            "TEST-ONLY-ETHERNET", 19100, new string('t', 48), "bifrost1", "providers/source-A.json", null));
        var fixedGroup = JsonNode.Parse(fixedRoute.MainConfig)!["proxy-groups"]!.AsArray().Single()!.AsObject();
        Assert(fixedRoute.ActiveGroup == "BIFROST-FIXED-A" && fixedGroup["type"]!.GetValue<string>() == "select", "fixed select group");
        Assert(fixedGroup["use"]!.AsArray().Single()!.GetValue<string>() == fixedRoute.ProviderName &&
            fixedGroup["filter"]!.GetValue<string>() == "^A-02$" &&
            fixedGroup["empty-fallback"]!.GetValue<string>() == "REJECT", "fixed exact provider candidate, fail closed");
        MihomoConfigValidator.ValidateStaged(fixedRoute.MainConfig, fixedRoute.Provider, "A", "global", fixedPolicy);
        foreach (var expression in new[] { "A-02", "^A-0.*$", "^B-01$", "^A-02$|^A-03$" })
        {
            var widened = JsonNode.Parse(fixedRoute.MainConfig)!.AsObject();
            widened["proxy-groups"]![0]!["filter"] = expression;
            ExpectCode(() => MihomoConfigValidator.ValidateStaged(
                JsonSerializer.SerializeToUtf8Bytes(widened), fixedRoute.Provider, "A", "global", fixedPolicy),
                "BF-CANDIDATE-SOURCE-MISMATCH");
        }

        var perAppAllowPolicy = ApplicationPolicySnapshot.Create("per-app", "allow", new[] { "browser.exe" }, Array.Empty<string>(), new string('d', 32));
        var perAppExcludePolicy = ApplicationPolicySnapshot.Create("per-app", "exclude", Array.Empty<string>(), new[] { "browser.exe" }, new string('e', 32));
        var perAppAllow = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "per-app", null, "default", perAppAllowPolicy,
            "TEST-ONLY-ETHERNET", 19104, new string('y', 48), "bifrost1", "providers/source-A.json", null));
        var perAppExclude = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "per-app", null, "default", perAppExcludePolicy,
            "TEST-ONLY-ETHERNET", 19105, new string('z', 48), "bifrost1", "providers/source-A.json", null));
        MihomoConfigValidator.ValidateStaged(perAppAllow.MainConfig, perAppAllow.Provider, "A", "per-app", perAppAllowPolicy);
        MihomoConfigValidator.ValidateStaged(perAppExclude.MainConfig, perAppExclude.Provider, "A", "per-app", perAppExcludePolicy);

        foreach (var package in new[] { fixedRoute, perAppAllow, perAppExclude })
        {
            var compiled = JsonNode.Parse(package.MainConfig)!.AsObject();
            var dns = compiled["dns"]!.AsObject();
            Assert(dns["nameserver-policy"]!.AsObject().Select(pair => pair.Key).Order().SequenceEqual(
                new[] { "cp.cloudflare.com", "www.gstatic.com" }), "only health bootstrap exceptions survive non-smart modes");
            Assert(dns["nameserver"]!.AsArray().Single()!.GetValue<string>().EndsWith("#" + package.ActiveGroup),
                "non-smart DNS uses the same selected source as proxy traffic");
            Assert(!dns["direct-nameserver-follow-policy"]!.GetValue<bool>(), "per-process direct DNS cannot inherit proxy domain policies");
            Assert(dns["fake-ip-filter"]!.AsArray().All(rule => !rule!.GetValue<string>().Contains("GEOSITE,cn,")),
                "CN real-IP exceptions do not bleed into global or per-app mode");
        }

        var smartGate = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "smartgate", "smart", null, "us", policy,
            "TEST-ONLY-ETHERNET", 19102, new string('v', 48), "bifrost1", "providers/source-A.json", null,
            "B", "B-01"));
        var smartGateMain = JsonNode.Parse(smartGate.MainConfig)!.AsObject();
        var smartGateFronts = smartGateMain["proxies"]!.AsArray().Select(item => item!.AsObject()).Where(item => item["type"]?.GetValue<string>() != "direct").ToArray();
        var smartGateExits = JsonNode.Parse(smartGate.Provider)!["proxies"]!.AsArray().Select(item => item!.AsObject()).ToArray();
        Assert(smartGate.ActiveGroup == "BIFROST-SMARTGATE-US", "SmartGate group is country-scoped");
        var countryRules = smartGateMain["rules"]!.AsArray().Select(item => item!.GetValue<string>()).ToArray();
        Assert(countryRules.SequenceEqual(smartRules.Select(rule => rule
            .Replace("BIFROST-OPENAI-A", smartGate.ActiveGroup, StringComparison.Ordinal)
            .Replace("BIFROST-SMART-A", smartGate.ActiveGroup, StringComparison.Ordinal))),
            "SmartGate shares smart domestic bypass, service precedence and selected-country fallback");
        var countryDns = smartGateMain["dns"]!["nameserver-policy"]!.AsObject();
        Assert(countryDns["geosite:cn"]!.ToJsonString() == dnsPolicy["geosite:cn"]!.ToJsonString() &&
               countryDns["geosite:private"]!.ToJsonString() == dnsPolicy["geosite:private"]!.ToJsonString(),
            "SmartGate domestic DNS follows the same direct policy as smart routing");
        Assert(countryDns["+.chatgpt.com"]!.AsArray().Single()!.GetValue<string>().EndsWith("#" + smartGate.ActiveGroup, StringComparison.Ordinal) &&
               countryDns["geosite:geolocation-!cn"]!.AsArray().Single()!.GetValue<string>().EndsWith("#" + smartGate.ActiveGroup, StringComparison.Ordinal),
            "SmartGate foreign and OpenAI DNS stay on the customer-selected country");
        MihomoConfigValidator.ValidateStaged(smartGate.MainConfig, smartGate.Provider, "A", "smart", policy);
        var countryWithoutSplit = JsonNode.Parse(smartGate.MainConfig)!.AsObject();
        countryWithoutSplit["rules"] = new JsonArray($"MATCH,{smartGate.ActiveGroup}");
        ExpectCode(() => MihomoConfigValidator.ValidateStaged(JsonSerializer.SerializeToUtf8Bytes(countryWithoutSplit),
            smartGate.Provider, "A", "smart", policy), "BF-MIHOMO-RULES");
        var countryBypass = JsonNode.Parse(smartGate.MainConfig)!.AsObject();
        countryBypass["rules"]!.AsArray()[countryRules.Length - 1] = "MATCH,BIFROST-DIRECT";
        ExpectCode(() => MihomoConfigValidator.ValidateStaged(JsonSerializer.SerializeToUtf8Bytes(countryBypass),
            smartGate.Provider, "A", "smart", policy), "BF-MIHOMO-RULES");
        Assert(smartGateMain["proxy-groups"]![0]!["type"]!.GetValue<string>() == "url-test" &&
               smartGateMain["proxy-groups"]![0]!["tolerance"]!.GetValue<int>() == MihomoPolicyCompiler.AutoSelectToleranceMs,
            "SmartGate automatically selects the fastest healthy verified front");
        Assert(smartGateFronts.Length == 3 && smartGateFronts.All(front =>
               front["name"]!.GetValue<string>().StartsWith("BIFROST-SMARTGATE-FRONT-B-") &&
               front["uuid"]!.GetValue<string>() == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), "fronts use every mapped B direct candidate");
        Assert(smartGateExits.All(exit => exit["type"]!.GetValue<string>() == "socks5" &&
            exit["server"]!.GetValue<string>() == "socks.us.test-only.invalid" &&
            exit["username"]!.GetValue<string>() == "us-user" && exit["password"]!.GetValue<string>() == "us-password" &&
            exit["dialer-proxy"]!.GetValue<string>() == "BIFROST-SMARTGATE-FRONT-" + exit["name"]!.GetValue<string>()),
            "each SOCKS5 exit dials through its matching VMess front");

        ExpectCode(() => MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, "A", "direct-vmess", "global", "B-01", "default", fixedPolicy,
            "TEST-ONLY-ETHERNET", 19101, new string('u', 48), "bifrost1", "providers/source-A.json", null)),
            "BF-CANDIDATE-SOURCE-MISMATCH");

        RoutingMatrixFixture.Run(smart, fixedRoute, perAppAllow, perAppExclude, smartGate);
        if (Environment.GetEnvironmentVariable("BIFROST_MIHOMO_EXE") is { Length: > 0 } mihomo)
        {
            ValidateWithMihomo(mihomo, smart);
            Ipv4PreferenceFixture.Run(mihomo, smart);
            MihomoDatagramRegression.Run(mihomo, smart);
            ValidateWithMihomo(mihomo, fixedRoute);
            MihomoDatagramRegression.Run(mihomo, fixedRoute, "A-02");
            ValidateWithMihomo(mihomo, perAppAllow);
            ValidateWithMihomo(mihomo, perAppExclude);
            ValidateWithMihomo(mihomo, smartGate);
        }

        Console.WriteLine("MIHOMO-COMPILER-FIXTURE PASS");
        return 0;
    }

    private static int CompileSignedConfig(string[] args)
    {
        if (args.Length != 3 || args[0] != "--signed-config")
            throw new ArgumentException("usage: --signed-config <config.json> <country>");
        var signed = JsonNode.Parse(File.ReadAllText(args[1]))?.AsObject()
            ?? throw new InvalidDataException("signed config is not an object");
        var countryCode = args[2].Trim().ToLowerInvariant();
        var country = (signed["countries"] as JsonArray)?.OfType<JsonObject>().Single(item =>
            string.Equals(item["code"]?.GetValue<string>(), countryCode, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException("country is missing");
        var sourceCode = (country["front_source_options"] as JsonArray)?[0]?.GetValue<string>()
            ?? throw new InvalidDataException("front source is missing");
        var policy = ApplicationPolicySnapshot.Create(
            "smart", "none", Array.Empty<string>(), Array.Empty<string>(), new string('c', 32));
        var compiled = MihomoConfigCompiler.Compile(new MihomoCompileInput(
            signed, sourceCode, "smartgate", "smart", null, countryCode, policy,
            "TEST-ONLY-ETHERNET", 19112, new string('x', 48), "bifrost1",
            "providers/generated-smartgate.json", null));

        var socks = country["socks"]?.AsObject() ?? throw new InvalidDataException("SOCKS5 is missing");
        var expectedUser = socks["user"]?.GetValue<string>();
        var expectedPassword = socks["password"]?.GetValue<string>();
        var exits = JsonNode.Parse(compiled.Provider)?["proxies"]?.AsArray()
            ?? throw new InvalidDataException("compiled exits are missing");
        Assert(exits.Count > 0 && exits.All(item =>
            item?["username"]?.GetValue<string>() == expectedUser &&
            item?["password"]?.GetValue<string>() == expectedPassword),
            "generated config preserves exact SOCKS5 credentials");
        var fronts = JsonNode.Parse(compiled.MainConfig)?["proxies"]?.AsArray()
            ?? throw new InvalidDataException("compiled fronts are missing");
        Assert(fronts.Count > 1 && fronts.Where(item => item?["type"]?.GetValue<string>() != "direct").All(item =>
            item?["ws-opts"]?["path"]?.GetValue<string>() == "/"),
            "generated config normalizes the historical root WebSocket path");

        Console.WriteLine("GENERATED-SMARTGATE-COMPILER PASS");
        return 0;
    }

    private static void ValidateWithMihomo(string executable, MihomoCompiledPackage package)
    {
        var root = Path.Combine(Path.GetTempPath(), "bifrost-mihomo-compiler-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "providers"));
            File.WriteAllBytes(Path.Combine(root, "config.json"), package.MainConfig);
            File.WriteAllBytes(Path.Combine(root, "providers", "source-A.json"), package.Provider);
            if (Environment.GetEnvironmentVariable("BIFROST_MIHOMO_GEODATA_DIR") is { Length: > 0 } geodata)
            {
                File.Copy(Path.Combine(geodata, "geosite.dat"), Path.Combine(root, "GeoSite.dat"), true);
                File.Copy(Path.Combine(geodata, "geoip.metadb"), Path.Combine(root, "geoip.metadb"), true);
            }
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("-t"); start.ArgumentList.Add("-d"); start.ArgumentList.Add(root);
            start.ArgumentList.Add("-f"); start.ArgumentList.Add(Path.Combine(root, "config.json"));
            using var process = Process.Start(start) ?? throw new InvalidOperationException("fixture did not start Mihomo");
            var stdout = process.StandardOutput.ReadToEnd(); var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert(process.ExitCode == 0, "Mihomo rejected config: " + stdout + " " + stderr);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }

    private static JsonObject SignedConfig() => new()
    {
        ["schema_version"] = "1.0",
        ["sources"] = new JsonArray(Source("A", "203.0.113.", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab"), Source("B", "198.51.100.", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc")),
        ["countries"] = new JsonArray(new JsonObject
        {
            ["code"] = "us", ["status"] = "enabled", ["udp"] = true,
            ["front_source_code"] = "B", ["front_source_options"] = new JsonArray("B"),
            ["socks"] = new JsonObject
            {
                ["scheme"] = "socks5", ["host"] = "socks.us.test-only.invalid", ["port"] = 1080,
                ["user"] = "us-user", ["password"] = "us-password"
            }
        }),
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
                ["ipv6"] = "proxy",
                ["failure"] = "block",
            }
        },
    };

    private static JsonObject Source(string code, string prefix, string uuid, string countryUuid) => new()
    {
        ["code"] = code,
        ["configured"] = true,
        ["server_name"] = code.ToLowerInvariant() + ".test-only.invalid",
        ["ws_path"] = "/" + code.ToLowerInvariant(),
        ["transport"] = new JsonObject
        {
            ["network"] = "ws", ["tls"] = true, ["security"] = "auto", ["alter_id"] = 0,
            ["host"] = code.ToLowerInvariant() + ".test-only.invalid", ["sni"] = code.ToLowerInvariant() + ".test-only.invalid",
        },
        ["candidates"] = new JsonArray(Enumerable.Range(1, 3).Select(index => (JsonNode)new JsonObject
        {
            ["label"] = $"{code}-0{index}", ["dial_address"] = prefix + (10 + index), ["port"] = 443,
        }).ToArray()),
        ["profiles"] = new JsonObject
        {
            ["direct"] = new JsonObject { ["profile_id"] = code + "-direct", ["uuid"] = uuid },
            ["countries"] = new JsonObject { ["us"] = new JsonObject { ["profile_id"] = code + "-us", ["uuid"] = countryUuid } },
        },
    };

    private static void ExpectCode(Action action, string code)
    {
        try { action(); }
        catch (Exception error) when (error.Message == code) { return; }
        throw new InvalidOperationException("expected " + code);
    }

    private static void Assert(bool value, string label)
    {
        if (!value) throw new InvalidOperationException("fixture assertion failed: " + label);
    }
}
