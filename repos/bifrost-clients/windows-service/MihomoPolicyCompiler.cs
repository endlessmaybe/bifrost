using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Bifrost.ClientService;

internal sealed record MihomoPolicyResult(
    JsonObject Group,
    JsonObject? ChatGptGroup,
    JsonArray Rules,
    string ActiveGroup,
    string ChatGptGroupName);

internal static class MihomoPolicyCompiler
{
    // Native Mihomo URLTest is the authoritative automatic selector.  A small
    // hysteresis band prevents normal RTT jitter from flapping long-lived
    // sessions while still moving away from a meaningfully slower path.
    internal const int AutoSelectToleranceMs = 50;
    // Regional download domains can occur in both CN and non-CN geosite sets.
    // Resolve and route the Google download service consistently on both clients.
    internal static readonly string[] GoogleProxyDomainSuffixes =
        ["gvt1.com", "gvt2.com", "gvt3.com", "gvt2-cn.com", "ggpht.com", "googleusercontent.com", "gstatic.com"];
    internal static readonly string[] GoogleProxyExactDomains =
        ["play.google.com", "play.googleapis.com", "android.googleapis.com", "android.apis.google.com", "android.clients.google.com", "dl.google.com", "dl-ssl.google.com"];
    // Local/special-use names must never depend on public fake-IP mappings.
    // Keep these explicit even though the pinned private geosite normally
    // overlaps them: local discovery and home-router names should remain
    // deterministic if an upstream geosite dataset changes.
    internal static readonly string[] LocalDirectDomainSuffixes = ["lan", "local", "home.arpa"];
    internal static readonly string[] LocalDnsOnlySuffixes = ["arpa"];
    internal static readonly string[] LocalDirectExactDomains = ["localhost"];
    internal static readonly string[] SystemDirectExactDomains =
    [
        "captive.apple.com",
        "dns.msftncsi.com",
        "time.apple.com",
        "time.windows.com",
        "www.msftconnecttest.com",
        "www.msftncsi.com",
    ];
    internal static readonly string[] SystemDirectDomainSuffixes = ["pool.ntp.org"];
    internal static readonly string[] MicrosoftProxyExactDomains =
        ["download.windowsupdate.com", "storeedgefd.dsx.mp.microsoft.com"];
    internal static readonly string[] TencentDirectDomainSuffixes =
        ["qq.com", "qpic.cn", "gtimg.cn", "qlogo.cn", "tencent.com", "myqcloud.com"];
    // High-confidence mainland public/academic namespaces. Keep these as
    // explicit suffix rules ahead of broad category rejection so sites such
    // as USTC speed test do not depend on geosite overlap/order to stay on the
    // physical direct path.
    internal static readonly string[] DomesticPriorityDirectDomainSuffixes = ["edu.cn", "gov.cn", "ac.cn"];
    // Regional/direct subsets maintained by the pinned MetaCubeX geodata.
    // Keep these ahead of broader foreign categories: many category lists are
    // intentionally cross-region and expose @cn projections specifically so a
    // Chinese CDN/service edge can stay local without making the whole parent
    // service DIRECT.  The final tld-cn/cn layers below remain the long-tail
    // safety net rather than a substitute for these higher-confidence sets.
    internal static readonly string[] DomesticDirectGeosites =
    [
        "apple-cn", "onedrive", "microsoft@cn", "steam@cn", "category-games@cn",
        "category-ai-cn", "category-automobile-cn", "category-bank-cn", "category-blog-cn",
        "category-cdn-cn", "category-collaborate-cn", "category-companies@cn", "category-dev@cn",
        "category-documents-cn", "category-education-cn", "category-electronic-cn", "category-ecommerce@cn",
        // Chinese HTTPDNS is an application compatibility dependency, not an
        // alternate tunnel. Let it stay on the domestic direct path; blanket
        // rejection breaks otherwise ordinary CN sites/apps that bootstrap
        // through HTTPDNS and still leaves GEOIP/domain routing in authority
        // for the returned destination.
        "category-httpdns-cn",
    ];
    // Maintained foreign/service categories from the pinned MetaCubeX geodata.
    // These are evaluated before domestic/geographic fallbacks so an upstream
    // overlap (for example a GitHub hostname appearing in another vendor set)
    // cannot accidentally turn a foreign service into DIRECT traffic.  Using
    // compact GeoSite matchers also avoids expanding the large service-domain
    // catalogue into thousands of hot-path Mihomo rules.
    internal static readonly string[] ForeignProxyGeosites =
    [
        "google", "github", "category-ai-!cn", "category-scholar-!cn",
        "category-anticensorship", "category-browser-!cn", "category-cdn-!cn",
        "category-companies@!cn", "category-games-!cn", "category-social-media-!cn",
        "youtube", "twitter", "telegram", "discord", "reddit", "netflix",
        "disney", "spotify", "tiktok", "instagram", "facebook", "biliintl", "pixiv",
    ];
    // tld-cn includes the conventional .cn namespace plus CNNIC-managed IDN
    // and brand TLDs.  It is deliberately evaluated after explicit foreign
    // categories, so a known foreign service keeps its proxy policy even if
    // it also owns a Chinese-facing hostname.
    internal const string DomesticTldGeosite = "tld-cn";
    internal static readonly string[] SteamDownloadDirectDomainSuffixes = ["steamcontent.com"];
    internal static readonly string[] DnsBypassBlockGeosites = ["category-doh"];
    // Keep ChatGPT as one service boundary instead of relying on GEOIP for
    // individual CDN addresses.  The suffix/exact host lists mirror OpenAI's
    // published ChatGPT network allow-list (first-party wildcards plus the
    // explicitly named third-party hosts that participate in auth, challenge,
    // assets, telemetry and support flows).  Keeping them here also lets DNS
    // and route compilation share one authoritative set.
    internal static readonly string[] ChatGptProxyDomainSuffixes =
    [
        "chatgpt.com",
        "openai.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "openaiusercontent.com",
        "oaistatsig.com",
        "ct.sendgrid.net",
        "intercom.io",
        "intercomcdn.com",
    ];

    internal static readonly string[] ChatGptProxyExactDomains =
    [
        "cdn.openaimerge.com",
        "cdn.workos.com",
        "challenges.cloudflare.com",
        "forwarder.workos.com",
        "humb.apple.com",
        "images.workoscdn.com",
        "js.stripe.com",
        "o207216.ingest.sentry.io",
        "o33249.ingest.sentry.io",
        "rum.browser-intake-datadoghq.com",
        "setup.workos.com",
        "workos.imgix.net",
    ];

    internal static MihomoPolicyResult Compile(
        MihomoCompileInput input,
        MihomoProviderResult provider,
        string? remoteDnsHost = null,
        string? directDnsHost = null)
    {
        var source = input.Source.ToUpperInvariant();
        JsonObject group;
        JsonObject? chatGptGroup = null;
        string active;
        string chatGptActive;
        if (input.ConnectionType == "smartgate")
        {
            active = "BIFROST-SMARTGATE-" + MihomoProviderCompiler.SafeToken(input.Country, "BF-SMARTGATE-COUNTRY").ToUpperInvariant();
            // The selected country remains fixed; only its verified front
            // paths participate in automatic selection.  Let Mihomo URLTest
            // continuously choose the lowest-latency healthy front instead of
            // pinning the first provider entry until hard failure.
            group = UrlTest(active, provider.ProviderName);
            chatGptActive = active;
        }
        else if (input.RouteMode == "global")
        {
            var fixedCandidate = MihomoProviderCompiler.SafeToken(input.FixedCandidate, "BF-CANDIDATE-NOT-READY");
            if (!provider.Candidates.Contains(fixedCandidate)) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
            active = "BIFROST-FIXED-" + source;
            group = new JsonObject
            {
                ["name"] = active,
                ["type"] = "select",
                // File-provider leaves are unavailable in the parser's static
                // proxy map. Select through the provider with an exact filter.
                ["use"] = new JsonArray(provider.ProviderName),
                ["filter"] = FixedCandidateFilter(fixedCandidate),
                ["empty-fallback"] = "REJECT",
            };
            chatGptActive = active;
        }
        else if (input.RouteMode is "smart" or "per-app")
        {
            if (!string.IsNullOrWhiteSpace(input.FixedCandidate)) throw new InvalidDataException("BF-CANDIDATE-MODE");
            active = "BIFROST-SMART-" + source;
            group = UrlTest(active, provider.ProviderName);
            // Native URLTest owns startup selection and hard-failure recovery.
            // The background quality worker can pin a separately confirmed
            // sustained-throughput winner for new flows. ChatGPT gets an
            // independent ordered fallback group: once a healthy candidate
            // is carrying the authenticated service boundary, Mihomo keeps it
            // until that candidate is actually unavailable. This intentionally
            // avoids URLTest latency churn moving page/auth traffic and a later
            // files.oaiusercontent.com upload onto different public egress IPs.
            // Provider health still gives the group autonomous failover when
            // the incumbent really fails.
            if (input.RouteMode == "smart")
            {
                chatGptActive = "BIFROST-OPENAI-" + source;
                chatGptGroup = Fallback(chatGptActive, provider.ProviderName);
            }
            else chatGptActive = active;
        }
        else throw new InvalidDataException("BF-CONFIG-MODE");

        var rules = new JsonArray();
        // Health traffic must prove the selected tunnel, even if a packaged
        // geosite/IP classification or per-app bypass would route it directly.
        if (input.RouteMode != "per-app")
            foreach (var host in MihomoWindowsContract.DataPlaneProbeHosts)
                rules.Add($"DOMAIN,{host},{active}");
        // Country egress changes the proxy destination, not the routing
        // policy. SmartGate shares domestic bypass and service precedence.
        if (input.RouteMode == "per-app")
        {
            if (input.ApplicationPolicy.PolicyMode == "allow")
            {
                foreach (var identity in input.ApplicationPolicy.IncludeIdentities) rules.Add($"PROCESS-NAME,{identity},{active}");
                rules.Add("MATCH,BIFROST-DIRECT");
            }
            else if (input.ApplicationPolicy.PolicyMode == "exclude")
            {
                foreach (var identity in input.ApplicationPolicy.ExcludeIdentities) rules.Add($"PROCESS-NAME,{identity},BIFROST-DIRECT");
                rules.Add($"MATCH,{active}");
            }
            else throw new InvalidDataException("BF-APP-POLICY");
        }
        else if (input.RouteMode == "smart")
        {
            AddSmartRoutingRules(rules, active, chatGptActive, remoteDnsHost, directDnsHost);
        }
        else
        {
            if (input.ApplicationPolicy.PolicyMode != "none" || input.ApplicationPolicy.Identities.Count != 0)
                throw new InvalidDataException("BF-APP-POLICY");
            rules.Add($"MATCH,{active}");
        }
        return new MihomoPolicyResult(group, chatGptGroup, rules, active, chatGptActive);
    }

    private static void AddSmartRoutingRules(
        JsonArray rules,
        string active,
        string chatGptActive,
        string? remoteDnsHost,
        string? directDnsHost)
    {
        // Order is authoritative: rejection and local-network safety precede
        // domestic routing; the selected source group is the only fallback.
        // Tencent desktop clients use a mixture of domains, literal CN IPs and
        // long-lived UDP flows.  Keep their process/domain routes ahead of the
        // broad advertising category so login, presence and media endpoints
        // cannot be rejected by an overlapping geosite classification.
        rules.Add("PROCESS-NAME,QQ.exe,BIFROST-DIRECT");
        rules.Add("PROCESS-NAME,QQNT.exe,BIFROST-DIRECT");
        rules.Add("PROCESS-NAME,TIM.exe,BIFROST-DIRECT");
        foreach (var domain in LocalDirectExactDomains) rules.Add($"DOMAIN,{domain},BIFROST-DIRECT");
        foreach (var domain in LocalDirectDomainSuffixes) rules.Add($"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT");
        foreach (var domain in TencentDirectDomainSuffixes) rules.Add($"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT");
        foreach (var domain in DomesticPriorityDirectDomainSuffixes) rules.Add($"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT");
        foreach (var domain in SystemDirectExactDomains) rules.Add($"DOMAIN,{domain},BIFROST-DIRECT");
        foreach (var domain in SystemDirectDomainSuffixes) rules.Add($"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT");
        if (!string.IsNullOrWhiteSpace(directDnsHost)) rules.Add($"DOMAIN,{directDnsHost},BIFROST-DIRECT");
        if (!string.IsNullOrWhiteSpace(remoteDnsHost) && !string.Equals(remoteDnsHost, directDnsHost, StringComparison.OrdinalIgnoreCase))
            rules.Add($"DOMAIN,{remoteDnsHost},{active}");
        // Port 853 covers conventional DoT and DoQ. Known DoH and HTTPDNS
        // hosts are rejected on every port, after the two signed resolver
        // exceptions above and before broad CN/non-CN classification.
        rules.Add("DST-PORT,853,REJECT");
        foreach (var geosite in DnsBypassBlockGeosites) rules.Add($"GEOSITE,{geosite},REJECT");
        foreach (var domain in GoogleProxyDomainSuffixes) rules.Add($"DOMAIN-SUFFIX,{domain},{active}");
        foreach (var domain in GoogleProxyExactDomains) rules.Add($"DOMAIN,{domain},{active}");
        // Player/authentication requests must not be split by broad ads/CN
        // rules. The bounded compatibility list is shared with Android.
        foreach (var domain in BifrostServiceRouting.YoutubeSuffixes) rules.Add($"DOMAIN-SUFFIX,{domain},{active}");
        foreach (var domain in BifrostServiceRouting.YoutubeDomains) rules.Add($"DOMAIN,{domain},{active}");

        // Keep one ChatGPT session on one egress policy.  OpenAI's web UI and
        // uploads span first-party hosts plus a small set of explicit service
        // dependencies; letting any of them fall through to GEOIP,CN can split
        // one browser session across DIRECT/proxy paths. Route QUIC through
        // the same sticky group as HTTPS. In the pinned core UDP REJECT is a
        // silent sink; it does not notify Chromium to immediately use TCP and
        // can stall the first upload while later retries use a cached fallback.
        foreach (var domain in ChatGptProxyDomainSuffixes)
            rules.Add($"DOMAIN-SUFFIX,{domain},{chatGptActive}");
        foreach (var domain in ChatGptProxyExactDomains)
            rules.Add($"DOMAIN,{domain},{chatGptActive}");
        // MetaCubeX's OpenAI geosite acts as a maintained catch-all behind the
        // explicit official list, while the explicit list remains authoritative
        // if the packaged geodata lags a newly introduced ChatGPT hostname.
        rules.Add($"GEOSITE,openai,{chatGptActive}");
        foreach (var domain in SteamDownloadDirectDomainSuffixes)
            rules.Add($"DOMAIN-SUFFIX,{domain},BIFROST-DIRECT");
        rules.Add("GEOSITE,category-ads-all,REJECT");
        rules.Add("GEOSITE,private,BIFROST-DIRECT");
        // Cover literal-address traffic that has no hostname to classify.
        // CGNAT, IPv6 ULA and link-local are common on mobile/hotspot/LAN
        // underlays and must not take an unnecessary proxy round trip.
        rules.Add("GEOIP,private,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR,127.0.0.0/8,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR,10.0.0.0/8,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR,172.16.0.0/12,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR,192.168.0.0/16,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR,169.254.0.0/16,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR,100.64.0.0/10,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR6,::1/128,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR6,fc00::/7,BIFROST-DIRECT,no-resolve");
        rules.Add("IP-CIDR6,fe80::/10,BIFROST-DIRECT,no-resolve");
        // Keep the handful of cross-source exact dependencies explicit.  The
        // former massive suffix expansion is intentionally replaced by the
        // compact maintained GeoSite categories below; this keeps domestic
        // DIRECT connection admission close to native-cost rule matching.
        foreach (var domain in BifrostServiceRouting.Domains) rules.Add($"DOMAIN,{domain},{active}");
        foreach (var domain in MicrosoftProxyExactDomains) rules.Add($"DOMAIN,{domain},{active}");
        foreach (var geosite in DomesticDirectGeosites) rules.Add($"GEOSITE,{geosite},BIFROST-DIRECT");
        foreach (var geosite in ForeignProxyGeosites) rules.Add($"GEOSITE,{geosite},{active}");
        rules.Add($"GEOSITE,{DomesticTldGeosite},BIFROST-DIRECT");
        rules.Add("GEOSITE,cn,BIFROST-DIRECT");
        // Domain classification is more authoritative than GeoIP for CDN and
        // anycast destinations.  This mirrors mature V2Ray/Clash rule ordering:
        // known CN domains go direct, known non-CN domains stay on the proxy,
        // and GEOIP is only a literal-IP/fallback decision.
        rules.Add($"GEOSITE,geolocation-!cn,{active}");
        rules.Add("GEOIP,CN,BIFROST-DIRECT,no-resolve");
        rules.Add($"MATCH,{active}");
    }

    internal static string FixedCandidateFilter(string candidate) => "^" + Regex.Escape(candidate) + "$";

    internal static string? FixedCandidate(MihomoCompiledPackage package)
    {
        if (!package.ActiveGroup.StartsWith("BIFROST-FIXED-", StringComparison.Ordinal)) return null;
        var main = JsonNode.Parse(package.MainConfig)!;
        var filter = main["proxy-groups"]?.AsArray().OfType<JsonObject>()
            .Single(group => group["name"]?.GetValue<string>() == package.ActiveGroup)["filter"]?.GetValue<string>();
        var matches = package.AllowedCandidates.Where(candidate => FixedCandidateFilter(candidate) == filter).ToArray();
        if (matches.Length != 1) throw new InvalidDataException("BF-CANDIDATE-SOURCE-MISMATCH");
        return matches[0];
    }

    private static JsonObject UrlTest(string name, string provider, int tolerance = AutoSelectToleranceMs) => new()
    {
        ["name"] = name,
        ["type"] = "url-test",
        ["use"] = new JsonArray(provider),
        ["url"] = MihomoWindowsContract.StartupProbeUrl,
        ["expected-status"] = MihomoWindowsContract.StartupProbeExpectedStatus,
        ["interval"] = 60,
        ["timeout"] = 5000,
        // URLTest owns the primary route just as it does in Clash/Mihomo.
        // Bifrost's body-transfer optimizer may refine a choice only inside
        // this same latency band; it must never drag traffic onto a clearly
        // higher-latency path.
        ["tolerance"] = tolerance,
        ["lazy"] = false,
        ["max-failed-times"] = 2,
        ["empty-fallback"] = "REJECT",
    };

    private static JsonObject Fallback(string name, string provider) => new()
    {
        ["name"] = name,
        ["type"] = "fallback",
        ["use"] = new JsonArray(provider),
        ["url"] = MihomoWindowsContract.StartupProbeUrl,
        ["expected-status"] = MihomoWindowsContract.StartupProbeExpectedStatus,
        ["interval"] = 300,
        ["timeout"] = 5000,
        ["lazy"] = false,
        ["max-failed-times"] = 2,
        ["empty-fallback"] = "REJECT",
    };
}
