package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject

/**
 * Hand applications virtual A/AAAA addresses and restore the hostname in the
 * core. An IPv6 socket then does not force an IPv6-only upstream connection:
 * the direct dialer can race both families, preferring the working IPv4 path,
 * while VMess/SOCKS carries the hostname to the selected egress.
 */
internal object BifrostDualStackDns {
    const val FAKE_V4 = "198.18.0.0/15"
    const val FAKE_V6 = "fc00::/18"
    fun configure(dns: JSONObject, route: JSONObject, outbounds: JSONArray) {
        dns.getJSONArray("servers").put(JSONObject().put("type", "fakeip").put("tag", "dual-stack-dns")
            .put("inet4_range", FAKE_V4).put("inet6_range", FAKE_V6))
        val prior = dns.optJSONArray("rules") ?: JSONArray()
        val rules = JSONArray()
        fun mapped(original: JSONObject): JSONObject = JSONObject(original.toString())
            .put("inbound", JSONArray().put("tun-in")).put("query_type", JSONArray().put("A").put("AAAA"))
            .put("action", "route").put("server", "dual-stack-dns").put("strategy", "prefer_ipv4")
        for (i in 0 until prior.length()) {
            val rule = prior.getJSONObject(i)
            val server = rule.optString("server")
            val privateNames = rule.optJSONArray("rule_set")?.toString()?.contains("\"geosite-private\"") == true
            val localNames = rule.optJSONArray("domain")?.let { domains ->
                (0 until domains.length()).any { domains.optString(it) in BifrostRoutingRules.localDirectDomains }
            } == true || rule.optJSONArray("domain_suffix")?.let { suffixes ->
                (0 until suffixes.length()).any {
                    suffixes.optString(it).trimStart('.') in (BifrostRoutingRules.localDirectSuffixes + BifrostRoutingRules.localDnsOnlySuffixes)
                }
            } == true
            val systemRealIp = rule.optJSONArray("domain")?.let { domains ->
                (0 until domains.length()).any { domains.optString(it) in BifrostRoutingRules.systemDirectDomains }
            } == true || rule.optJSONArray("domain_suffix")?.let { suffixes ->
                (0 until suffixes.length()).any {
                    suffixes.optString(it).trimStart('.') in
                        (BifrostRoutingRules.systemDirectSuffixes + BifrostRoutingRules.domesticPriorityDirectSuffixes)
                }
            } == true
            // Direct domains need real CDN addresses. A virtual fc00::/18
            // answer can be caught by the early private-IP route before the
            // fake-IP reverse map runs, resetting image TLS connections.
            // Keep virtual dual-stack answers only for proxied domains.
            if (server == "remote-dns" && !privateNames && !localNames && !systemRealIp) rules.put(mapped(rule))
            rules.put(rule)
        }
        rules.put(mapped(JSONObject()))
        dns.put("rules", rules)
        // Internal/bootstrap DNS never reaches the fake server (only tun-in
        // queries match above). Keep the proven IPv4 bootstrap behaviour.
        route.put("default_domain_resolver", JSONObject().put("server", "remote-dns").put("strategy", "prefer_ipv4"))
        for (i in 0 until outbounds.length()) {
            val outbound = outbounds.getJSONObject(i)
            if (outbound.optString("type") == "direct") outbound
                .put("domain_resolver", JSONObject().put("server", "direct-dns").put("strategy", "prefer_ipv4"))
                .put("fallback_delay", "300ms")
        }
    }
}
