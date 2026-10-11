package com.bifrost.client;

/** This source must fail because no public Prepared/submit capability exists. */
final class ForgeViaPrepared {
    static void bypass() {
        BifrostApplicationPolicyConnectionCoordinator.Prepared prepared;
        BifrostApplicationPolicyConnectionCoordinator.submit(null);
    }
}
