package com.bifrost.client

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/** Both Android transports route in libbox before reaching VMess/Xray.
 * Rules are derived from the same pinned Windows data and shipped in the APK. */
internal object BifrostRoutingRules {
    val domesticDirectSets = listOf(
        "geosite-apple-cn",
        "geosite-onedrive",
        "geosite-microsoft@cn",
        "geosite-steam@cn",
        "geosite-category-games@cn",
        "geosite-category-ai-cn",
        "geosite-category-automobile-cn",
        "geosite-category-bank-cn",
        "geosite-category-blog-cn",
        "geosite-category-cdn-cn",
        "geosite-category-collaborate-cn",
        "geosite-category-companies@cn",
        "geosite-category-dev@cn",
        "geosite-category-documents-cn",
        "geosite-category-education-cn",
        "geosite-category-electronic-cn",
        "geosite-category-ecommerce@cn",
        "geosite-category-httpdns-cn",
    )
    val foreignProxySets = listOf(
        "geosite-google",
        "geosite-github",
        "geosite-category-ai-!cn",
        "geosite-category-scholar-!cn",
        "geosite-category-anticensorship",
        "geosite-category-browser-!cn",
        "geosite-category-cdn-!cn",
        "geosite-category-companies@!cn",
        "geosite-category-games-!cn",
        "geosite-category-social-media-!cn",
        "geosite-youtube",
        "geosite-twitter",
        "geosite-telegram",
        "geosite-discord",
        "geosite-reddit",
        "geosite-netflix",
        "geosite-disney",
        "geosite-spotify",
        "geosite-tiktok",
        "geosite-instagram",
        "geosite-facebook",
        "geosite-biliintl",
        "geosite-pixiv",
    )
    const val domesticTldSet = "geosite-tld-cn"
    val dnsBypassBlockSets = listOf("geosite-category-doh")
    val categories = listOf(
        "geosite-cn",
        "geosite-geolocation-!cn",
        "geosite-private",
        "geosite-category-ads-all",
        "geosite-openai",
        domesticTldSet,
    ) + dnsBypassBlockSets + foreignProxySets + domesticDirectSets + "geoip-cn"
    val localDirectSuffixes = listOf("lan", "local", "home.arpa")
    val localDnsOnlySuffixes = listOf("arpa")
    val localDirectDomains = listOf("localhost")
    val domesticPriorityDirectSuffixes = listOf("edu.cn", "gov.cn", "ac.cn")
    val steamDownloadDirectSuffixes = listOf("steamcontent.com")
    val healthBootstrapDnsDomains = listOf("www.gstatic.com", "cp.cloudflare.com")
    val systemDirectDomains = listOf(
        "captive.apple.com", "dns.msftncsi.com", "time.apple.com", "time.windows.com",
        "www.msftconnecttest.com", "www.msftncsi.com",
    )
    val systemDirectSuffixes = listOf("pool.ntp.org")
    // These two Windows delivery hosts are members of Microsoft's broader CN
    // attribute set, but Bifrost's cross-client service matrix intentionally
    // keeps them on the foreign path.  Keep the exceptions exact so the
    // genuinely regional dl.delivery.mp.microsoft.com CDN can stay direct.
    val microsoftProxyDomains = listOf("download.windowsupdate.com", "storeedgefd.dsx.mp.microsoft.com")
    val tencent = listOf("qq.com", "qpic.cn", "gtimg.cn", "qlogo.cn", "tencent.com", "myqcloud.com")
    // Keep domestic share/deep-link and media hosts explicit instead of
    // depending only on the periodically refreshed geosite-cn snapshot. These
    // names are frequently opened inside another application's WebView (QQ,
    // browsers, launchers) where package identity must never decide whether a
    // foreign destination is direct or proxied.
    val domesticMedia = listOf(
        "b23.tv", "bilibili.com", "hdslb.com", "bilivideo.com", "biliapi.com", "biliapi.net",
    )
    val playPackages = listOf("com.android.vending", "com.google.android.gms", "com.android.providers.downloads")
    val playSuffixes = listOf("gvt1.com", "gvt2.com", "gvt3.com", "gvt2-cn.com", "ggpht.com", "googleusercontent.com", "gstatic.com")
    val playDomains = listOf("play.google.com", "play.googleapis.com", "android.googleapis.com", "android.apis.google.com", "android.clients.google.com", "dl.google.com", "dl-ssl.google.com")
    val openAiSuffixes = listOf("chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "openaiusercontent.com", "oaistatsig.com", "ct.sendgrid.net", "intercom.io", "intercomcdn.com")
    val openAiDomains = listOf("cdn.openaimerge.com", "cdn.workos.com", "challenges.cloudflare.com", "forwarder.workos.com", "humb.apple.com", "images.workoscdn.com", "js.stripe.com", "o207216.ingest.sentry.io", "o33249.ingest.sentry.io", "rum.browser-intake-datadoghq.com", "setup.workos.com", "workos.imgix.net")

    fun prepare(context: Context): String {
        val directory = File(context.noBackupFilesDir, "bifrost-routing")
        check(directory.isDirectory || directory.mkdirs()) { "BF-CONFIG-STORAGE" }
        check(!Files.isSymbolicLink(directory.toPath())) { "BF-CONFIG-STORAGE" }
        val manifest = context.assets.open("routing/manifest.json").bufferedReader().use { JSONObject(it.readText()) }
        val files = manifest.getJSONArray("files")
        check(files.length() == categories.size) { "BF-CONFIG-DIGEST" }
        for (category in categories) {
            val name = "$category.json"
            val row = (0 until files.length()).map { files.getJSONObject(it) }.single { it.getString("name") == name }
            val expected = row.getString("sha256")
            val target = File(directory, name)
            check(!Files.isSymbolicLink(target.toPath())) { "BF-CONFIG-STORAGE" }
            fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            if (target.isFile && target.length() == row.getLong("bytes") && digest(target.readBytes()) == expected) continue
            val bytes = context.assets.open("routing/$name").use { it.readBytes() }
            check(bytes.size.toLong() == row.getLong("bytes") && digest(bytes) == expected) { "BF-CONFIG-DIGEST" }
            val temporary = File.createTempFile("rules-", ".tmp", directory)
            try {
                temporary.outputStream().use { it.write(bytes); it.fd.sync() }
                Files.move(temporary.toPath(), target.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
            } finally { temporary.delete() }
        }
        return directory.absolutePath
    }

    fun apply(
        route: JSONObject,
        dns: JSONObject,
        proxy: String,
        directory: String,
        remoteDnsHost: String?,
        directDnsHost: String?,
    ) {
        val rules = route.getJSONArray("rules")
        fun domains(suffixes: List<String>, exact: List<String> = emptyList()) = JSONObject().apply {
            if (suffixes.isNotEmpty()) put("domain_suffix", JSONArray(suffixes))
            if (exact.isNotEmpty()) put("domain", JSONArray(exact))
        }
        fun set(tag: String) = JSONObject().put("rule_set", JSONArray().put(tag))
        // Match the Windows precedence: service exceptions, ads, private,
        // CN domains, non-CN domains, literal CN IPs, selected-source fallback.
        rules.put(domains(localDirectSuffixes, localDirectDomains).put("outbound", "direct"))
        rules.put(domains(tencent).put("outbound", "direct"))
        rules.put(domains(domesticMedia).put("outbound", "direct"))
        rules.put(domains(domesticPriorityDirectSuffixes).put("outbound", "direct"))
        rules.put(domains(systemDirectSuffixes, systemDirectDomains).put("outbound", "direct"))
        // Bifrost's own signed DoH endpoints are bounded exceptions.  All
        // other known DoH/HTTPDNS endpoints and the standard DoT/DoQ port are
        // rejected below so applications cannot silently bypass split DNS.
        if (directDnsHost != null) rules.put(domains(emptyList(), listOf(directDnsHost)).put("outbound", "direct"))
        if (remoteDnsHost != null && remoteDnsHost != directDnsHost)
            rules.put(domains(emptyList(), listOf(remoteDnsHost)).put("outbound", proxy))
        rules.put(JSONObject().put("port", 853).put("action", "reject"))
        dnsBypassBlockSets.forEach { rules.put(set(it).put("action", "reject")) }
        rules.put(domains(emptyList(), healthBootstrapDnsDomains).put("outbound", proxy))
        // Play's downloader may connect to a regional IP without a usable
        // sniffed hostname. Keep its authenticated download and API traffic
        // on the selected proxy before ads/CN-IP fallback can split the path.
        rules.put(JSONObject().put("package_name", JSONArray(playPackages)).put("outbound", proxy))
        rules.put(domains(playSuffixes, playDomains).put("outbound", proxy))
        // Cached CDN addresses and resumed QUIC packets may carry no hostname.
        // Keep the actual YouTube applications on the same egress in smart
        // mode, as for Play, rather than letting a regional IP bypass it.
        rules.put(JSONObject().put("package_name", JSONArray(BifrostServiceRouting.youtubePackages)).put("outbound", proxy))
        rules.put(domains(BifrostServiceRouting.youtubeSuffixes, BifrostServiceRouting.youtubeDomains).put("outbound", proxy))
        rules.put(domains(openAiSuffixes, openAiDomains).put("outbound", proxy))
        rules.put(set("geosite-openai").put("outbound", proxy))
        rules.put(domains(steamDownloadDirectSuffixes).put("outbound", "direct"))
        rules.put(set("geosite-category-ads-all").put("action", "reject"))
        rules.put(set("geosite-private").put("outbound", "direct"))
        // Keep the small cross-source exact dependency list explicit.  Large
        // service suffix catalogues are represented by compact pinned rule
        // sets below instead of being parsed and matched on every connection.
        rules.put(domains(emptyList(), BifrostServiceRouting.domains).put("outbound", proxy))
        rules.put(domains(emptyList(), microsoftProxyDomains).put("outbound", proxy))
        domesticDirectSets.forEach { rules.put(set(it).put("outbound", "direct")) }
        foreignProxySets.forEach { rules.put(set(it).put("outbound", proxy)) }
        rules.put(set(domesticTldSet).put("outbound", "direct"))
        rules.put(set("geosite-cn").put("outbound", "direct"))
        rules.put(set("geosite-geolocation-!cn").put("outbound", proxy))
        rules.put(set("geoip-cn").put("outbound", "direct"))
        route.put("rule_set", JSONArray().also { entries -> categories.forEach { name ->
            entries.put(JSONObject().put("type", "local").put("tag", name).put("format", "source").put("path", File(directory, "$name.json").path))
        } })
        val dnsRules = JSONArray()
        val existingDnsRules = dns.optJSONArray("rules") ?: JSONArray()
        for (index in 0 until existingDnsRules.length()) dnsRules.put(existingDnsRules.get(index))
        dnsRules
            .put(domains(localDirectSuffixes + localDnsOnlySuffixes, localDirectDomains).put("server", "direct-dns"))
            .put(domains(tencent).put("server", "direct-dns"))
            .put(domains(domesticMedia).put("server", "direct-dns"))
            .put(domains(domesticPriorityDirectSuffixes).put("server", "direct-dns"))
            .put(domains(systemDirectSuffixes, systemDirectDomains).put("server", "direct-dns"))
            .also { list ->
                if (directDnsHost != null) list.put(domains(emptyList(), listOf(directDnsHost)).put("server", "direct-dns"))
                if (remoteDnsHost != null && remoteDnsHost != directDnsHost)
                    list.put(domains(emptyList(), listOf(remoteDnsHost)).put("server", "remote-dns"))
                dnsBypassBlockSets.forEach { list.put(set(it).put("action", "reject")) }
            }
            .put(domains(openAiSuffixes, openAiDomains).put("server", "remote-dns"))
            .put(set("geosite-openai").put("server", "remote-dns"))
            .put(domains(playSuffixes, playDomains).put("server", "remote-dns"))
            .put(domains(BifrostServiceRouting.youtubeSuffixes, BifrostServiceRouting.youtubeDomains).put("server", "remote-dns"))
            .put(domains(steamDownloadDirectSuffixes).put("server", "direct-dns"))
            .put(set("geosite-category-ads-all").put("action", "reject"))
            .put(set("geosite-private").put("server", "direct-dns"))
            .put(domains(emptyList(), BifrostServiceRouting.domains).put("server", "remote-dns"))
            .put(domains(emptyList(), microsoftProxyDomains).put("server", "remote-dns"))
            .also { list -> domesticDirectSets.forEach { list.put(set(it).put("server", "direct-dns")) } }
            .also { list -> foreignProxySets.forEach { list.put(set(it).put("server", "remote-dns")) } }
            .put(set(domesticTldSet).put("server", "direct-dns"))
            .put(set("geosite-cn").put("server", "direct-dns"))
            .put(set("geosite-geolocation-!cn").put("server", "remote-dns"))
        for (index in 0 until dnsRules.length()) {
            val rule = dnsRules.getJSONObject(index)
            if (rule.has("server")) rule.put("action", "route")
        }
        // Keep direct/remote cache partitions isolated, but give the pinned
        // sing-box core a larger bounded LRU so repeated domestic lookups stay
        // hot instead of paying unnecessary resolver/TUN latency.
        dns.put("independent_cache", true).put("cache_capacity", 4096).put("rules", dnsRules)
    }

    fun preserveYoutubeUdp(rules: JSONArray) {
        // Route options are non-terminal: global/per-app routing remains in
        // charge of the outbound. Keep QUIC alive between buffered segments;
        // the default protocol-specific timeout in this core is only 30s.
        rules.put(JSONObject().put("type", "logical").put("mode", "and")
            .put("rules", JSONArray()
                .put(JSONObject().put("network", "udp").put("port", 443))
                .put(JSONObject().put("type", "logical").put("mode", "or").put("rules", JSONArray()
                    .put(JSONObject().put("domain_suffix", JSONArray(BifrostServiceRouting.youtubeSuffixes))
                        .put("domain", JSONArray(BifrostServiceRouting.youtubeDomains)))
                    .put(JSONObject().put("package_name", JSONArray(BifrostServiceRouting.youtubePackages))))))
            .put("action", "route-options").put("udp_timeout", BifrostServiceRouting.youtubeUdpIdleTimeout))
    }
}
