package com.bifrost.client;

/** Same-package adversary: a snapshot cannot be implemented or constructed. */
final class Adversarial {
    static final class Forge extends BifrostApplicationPolicySnapshot { }

    static void bypass() {
        new BifrostApplicationPolicySnapshot(
                "per-app", "allow", java.util.Collections.emptyList(), java.util.Collections.emptyList(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "{}"
        );
    }
}
