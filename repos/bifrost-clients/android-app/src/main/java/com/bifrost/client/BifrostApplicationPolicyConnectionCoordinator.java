package com.bifrost.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Validates one complete immutable snapshot and package-image binding set.
 * There is intentionally no public capability object and no generic
 * persist-then-start callback API.  Production callers retain the snapshot
 * they already own and receive only a defensive binding list after this
 * validator has rechecked both the value and the installed APK images.
 */
public final class BifrostApplicationPolicyConnectionCoordinator {
    private final BifrostApplicationPolicyPackageValidator validator;

    public BifrostApplicationPolicyConnectionCoordinator(
            BifrostApplicationPolicyPackageValidator validator) {
        this.validator = validator;
    }

    public List<BifrostApplicationPackageBinding> validate(
            BifrostApplicationPolicySnapshot snapshot) {
        return validate(snapshot, null);
    }

    public List<BifrostApplicationPackageBinding> validate(
            BifrostApplicationPolicySnapshot snapshot,
            List<BifrostApplicationPackageBinding> expectedBindings) {
        BifrostApplicationPolicySnapshot verified = BifrostApplicationPolicySnapshot.verify(snapshot);
        return Collections.unmodifiableList(new ArrayList<>(validator.validate(verified, expectedBindings)));
    }
}
