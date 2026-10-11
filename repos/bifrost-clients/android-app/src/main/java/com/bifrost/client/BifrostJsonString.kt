package com.bifrost.client

/** JSON.stringify-compatible string bytes for signed protocol data.
 * Android JSONObject.quote escapes '/' whereas Control's JSON.stringify does
 * not. Never use platform JSON writers to reconstruct a signature payload.
 */
internal object BifrostJsonString {
    fun quote(value: String): String = buildString(value.length + 2) {
        append('"')
        var index = 0
        while (index < value.length) {
            val c = value[index]
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> when {
                    c.code < 0x20 -> appendEscape(c)
                    c.isHighSurrogate() -> {
                        if (index + 1 < value.length && value[index + 1].isLowSurrogate()) {
                            append(c).append(value[++index])
                        } else appendEscape(c)
                    }
                    c.isLowSurrogate() -> appendEscape(c)
                    else -> append(c)
                }
            }
            index++
        }
        append('"')
    }

    private fun StringBuilder.appendEscape(c: Char) {
        append("\\u").append(c.code.toString(16).padStart(4, '0'))
    }
}
