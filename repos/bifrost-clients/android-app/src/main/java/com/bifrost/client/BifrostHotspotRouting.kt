package com.bifrost.client

import org.json.JSONArray
import org.json.JSONObject

/** Two authenticated kernel ingresses keep tether DNS separate from app DNS. */
internal object BifrostHotspotRouting {
    const val SMART_PORT = 15357
    const val DIRECT_PORT = 15358
    private val smartTags = listOf("root-hotspot4", "root-hotspot6")
    private val directTags = listOf("root-hotspot-direct4", "root-hotspot-direct6")

    fun configure(config: JSONObject) {
        val inbounds = config.getJSONArray("inbounds")
        for ((tags, port) in listOf(smartTags to SMART_PORT, directTags to DIRECT_PORT)) {
            tags.forEachIndexed { index, tag ->
                check((0 until inbounds.length()).none { inbounds.getJSONObject(it).optString("tag") == tag })
                inbounds.put(JSONObject().put("type", "tproxy").put("tag", tag)
                    .put("listen", if (index == 0) "127.0.0.1" else "::1")
                    .put("listen_port", port).put("routing_mark", "0x1020000"))
            }
        }
        val dns = config.getJSONObject("dns")
        val dnsRules = dns.getJSONArray("rules")
        // A direct hotspot must receive real addresses even in global mode.
        val nextDns = JSONArray().put(JSONObject().put("inbound", JSONArray(directTags))
            .put("action", "route").put("server", "direct-dns").put("strategy", "prefer_ipv4"))
        for (index in 0 until dnsRules.length()) {
            val rule = dnsRules.getJSONObject(index)
            if (rule.optString("server") == "dual-stack-dns") {
                val ingress = rule.optJSONArray("inbound")
                if (ingress != null && (0 until ingress.length()).any { ingress.optString(it) == "tun-in" }) {
                    smartTags.forEach { tag -> if ((0 until ingress.length()).none { ingress.optString(it) == tag }) ingress.put(tag) }
                }
            }
            nextDns.put(rule)
        }
        dns.put("rules", nextDns)
        val route = config.getJSONObject("route")
        val prior = route.getJSONArray("rules")
        val rules = JSONArray()
            .put(JSONObject().put("inbound", JSONArray(directTags)).put("action", "hijack-dns"))
        for (index in 0 until prior.length()) rules.put(prior.get(index))
        route.put("rules", rules)
    }
}
