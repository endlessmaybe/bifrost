package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject

/** Scoped IPv6 DNS sockets stay bound to wlan0 and bypass a default TUN route.
 * The Root boundary redirects those DNS packets to this loopback-only ingress.
 * It uses the same encrypted DNS policy and fake-IP map as the TUN itself.
 */
internal object BifrostRootDnsRouting {
    const val PORT = 15353
    private const val UPSTREAM_ROUTING_MARK = "0x1020000"
    fun configure(config: JSONObject, infrastructurePackages: List<String> = emptyList()) {
        // The root daemon runs as uid 0, which is intentionally captured by
        // the BFR12 uid-range rules.  sing-box DNS transports are independent
        // dialers; unlike ordinary proxy/direct outbound sockets they are not
        // guaranteed to pass through PlatformInterface.autoDetectInterfaceControl.
        // Mark only the direct HTTPS DNS transports at Root-config time so
        // their bootstrap/query sockets bypass our own TUN instead of feeding
        // back into table 404xx.  Keep this out of the shared VPN config:
        // unprivileged VpnService mode must continue to rely on protect(fd).
        config.optJSONObject("dns")?.optJSONArray("servers")?.let { servers ->
            for (index in 0 until servers.length()) {
                val server = servers.optJSONObject(index) ?: continue
                if (server.optString("tag") in setOf("direct-dns", "direct-bootstrap-dns"))
                    server.put("routing_mark", UPSTREAM_ROUTING_MARK)
            }
        }
        val inbounds = config.getJSONArray("inbounds")
        check((0 until inbounds.length()).none { inbounds.getJSONObject(it).optString("tag") == "root-dns" })
        inbounds.put(JSONObject().put("type", "tproxy").put("tag", "root-dns")
            .put("listen", "::1").put("listen_port", PORT).put("routing_mark", UPSTREAM_ROUTING_MARK))
        val route = config.getJSONObject("route")
        val existing = route.getJSONArray("rules")
        val rules = JSONArray().put(JSONObject().put("inbound", JSONArray().put("root-dns"))
            .put("action", "hijack-dns"))
        // BFR12 marks IPv4 resolver sockets in OUTPUT and transparently
        // delivers them through the app-owned policy-routing table. The
        // ingress must therefore be a TProxy peer as well; mixing BFR12's
        // kernel TPROXY rules with a `direct` inbound (or falling back to the
        // older BFR11 DNAT path) leaves Android's netd queries unanswered on
        // current sing-box/libbox builds.
        inbounds.put(JSONObject().put("type", "tproxy").put("tag", "root-app-dns")
            .put("listen", "127.0.0.1").put("listen_port", 15355)
            .put("routing_mark", UPSTREAM_ROUTING_MARK))
        rules.put(JSONObject().put("inbound", JSONArray().put("root-app-dns")).put("action", "hijack-dns"))
        if (infrastructurePackages.isNotEmpty()) {
            for ((tag, address) in listOf("root-vpn-dns4" to "127.0.0.1", "root-vpn-dns6" to "::1")) {
                val ipv6 = address == "::1"
                inbounds.put(JSONObject().put("type", "tproxy").put("tag", tag)
                    .put("listen", address).put("listen_port", if (ipv6) 15356 else 15354)
                    .put("routing_mark", UPSTREAM_ROUTING_MARK))
                rules.put(JSONObject().put("inbound", JSONArray().put(tag)).put("action", "hijack-dns"))
            }
        }
        for (index in 0 until existing.length()) rules.put(existing.get(index))
        route.put("rules", rules)

        // Scoped Wi-Fi DNS enters here instead of tun-in. Extend only the
        // application's fake-IP rules: otherwise these queries fall through
        // to real IPv4 answers and lose the hostname recovery used by VPN.
        // Bootstrap, private names, rejection rules and single-stack policy
        // must retain their existing resolver and matching conditions.
        val dnsRules = config.optJSONObject("dns")?.optJSONArray("rules") ?: return
        for (index in 0 until dnsRules.length()) {
            val rule = dnsRules.getJSONObject(index)
            if (rule.optString("server") != "dual-stack-dns") continue
            val ingress = rule.optJSONArray("inbound") ?: continue
            val tags = (0 until ingress.length()).map(ingress::getString)
            // BFR11 separates application and infrastructure DNS by kernel UID
            // before redirecting it. No per-query process scan is required;
            // Tailscale bootstrap retains real answers in its own ingress.
            if ("tun-in" in tags) {
                if ("root-dns" !in tags) ingress.put("root-dns")
                if ("root-app-dns" !in tags) ingress.put("root-app-dns")
            }
        }
    }
}
