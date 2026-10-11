package com.bifrost.client;

/** Release bytecode must not expose a registry reset authority. */
final class ForgeViaReset {
    static void bypass() {
        BifrostServiceOwnershipRegistry.INSTANCE.resetState();
    }
}
