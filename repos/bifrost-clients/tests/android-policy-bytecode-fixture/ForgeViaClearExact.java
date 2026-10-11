package com.bifrost.client;

/** Direct registry owner erasure is not a Java-callable release capability. */
final class ForgeViaClearExact {
    static void bypass(BifrostServiceTransactionToken token) {
        BifrostServiceOwnershipRegistry.INSTANCE.clearExactInternal(token);
    }
}
