package com.bifrost.client;

/** Receipt issuance is owned by the production coordinator, not Java callers. */
final class ForgeViaNoteReleased {
    static void bypass(BifrostServiceTransactionToken token) {
        BifrostServiceOwnershipRegistry.INSTANCE.noteReleasedExact(token);
    }
}
