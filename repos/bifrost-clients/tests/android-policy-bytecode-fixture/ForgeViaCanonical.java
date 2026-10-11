package com.bifrost.client;

/** This source must fail because no canonical/digest/generation parser exists. */
final class ForgeViaCanonical {
    static BifrostApplicationPolicySnapshot forge(String canonical) {
        return BifrostApplicationPolicySnapshot.fromCanonicalJson(canonical);
    }
}
