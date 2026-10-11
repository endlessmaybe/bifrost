package com.bifrost.client;

/** Activity cannot retire committed/blocked state without an exact receipt. */
final class ForgeViaReleaseBypass {
    static void bypass(BifrostConnectionTransactionGate gate, BifrostConnectionTransactionToken token) {
        gate.releaseCommittedExact(token);
        gate.releaseBlockedExact(token);
    }
}
