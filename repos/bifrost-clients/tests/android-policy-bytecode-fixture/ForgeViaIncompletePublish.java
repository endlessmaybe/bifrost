package com.bifrost.client;

/** The registry requires the complete immutable description at every call. */
final class ForgeViaIncompletePublish {
    static void bypass(BifrostApplicationPolicySnapshot snapshot, BifrostServiceTransactionToken token) {
        BifrostServiceOwnershipRegistry.publish(BifrostServiceOwnershipPhase.PENDING, token, snapshot);
    }
}
