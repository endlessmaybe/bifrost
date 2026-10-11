package com.bifrost.client;

/** This source must fail because generation is never caller-selectable. */
final class ForgeViaGeneration {
    static BifrostApplicationPolicySnapshot forge() {
        return BifrostApplicationPolicySnapshot.fromSelection(
                "per-app", "allow", java.util.Collections.emptyList(), java.util.Collections.emptyList(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }
}
