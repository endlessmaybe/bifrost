package com.bifrost.client

/** Native socket marking avoids hidden Android APIs and preserves netId. */
internal object BifrostRootSocket {
    init { System.loadLibrary("bifrost_socket") }
    external fun owner(protocol: Int, source: String, sourcePort: Int, target: String, targetPort: Int): Int
    external fun protect(fd: Int): Boolean
}
