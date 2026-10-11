package com.bifrost.client;

/** Same-package adversary: the gate exposes only complete-token correlation. */
public final class ForgeViaTransactionId {
    public static boolean probe(BifrostConnectionTransactionGate gate, String id) {
        return gate.isActive(id);
    }
}
