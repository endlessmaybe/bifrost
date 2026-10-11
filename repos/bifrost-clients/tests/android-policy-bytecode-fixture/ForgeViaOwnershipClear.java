package com.bifrost.client;

/** Local ownership erasure is not a Java-callable release capability. */
final class ForgeViaOwnershipClear {
    static void bypass(BifrostServiceTransactionOwnership ownership) {
        ownership.clear();
    }
}
