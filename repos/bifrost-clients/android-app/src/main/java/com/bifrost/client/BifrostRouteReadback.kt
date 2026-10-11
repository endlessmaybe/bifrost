package com.bifrost.client

/** Labels come from the same compiler loop as the running outbound graph.
 * Follow native selector readback, including proxy -> proxy-auto -> leaf.
 * Never substitute the connection's unmeasured seed for a missing readback. */
internal object BifrostRouteReadback {
    fun resolve(labels: Map<String, String>, selections: Map<String, String>, root: String = "proxy"): String? {
        val visited = mutableSetOf<String>()
        var tag = root
        while (visited.add(tag)) {
            val next = selections[tag]
            if (next != null) tag = next else return labels[tag]
        }
        return null
    }
}
