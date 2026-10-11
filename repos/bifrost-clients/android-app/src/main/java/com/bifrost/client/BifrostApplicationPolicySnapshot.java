package com.bifrost.client;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Final immutable policy capability.  It is deliberately a class, never an
 * interface: same-package Java/Kotlin code cannot implement or substitute a
 * snapshot.  Public construction accepts only raw selection values; the
 * private issue path performs all validation, canonical JSON generation,
 * digest derivation and generation issuance.
 */
public final class BifrostApplicationPolicySnapshot {
    private static final int VERSION = 1;
    private static final String PLATFORM = "android";
    private static final int MAX_IDENTITIES = 64;
    private static final int MAX_IDENTITY_BYTES = 255;
    private static final int MAX_TOTAL_IDENTITY_BYTES = 8 * 1024;
    private static final String GENERATION_PATTERN = "[0-9a-f]{32}";
    private static final String PACKAGE_PATTERN = "[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+";

    private final String routeMode;
    private final String policyMode;
    private final List<String> includePackages;
    private final List<String> excludePackages;
    private final String generation;
    private final String digest;
    private final String canonicalJson;

    private BifrostApplicationPolicySnapshot(
            String routeMode,
            String policyMode,
            List<String> includePackages,
            List<String> excludePackages,
            String generation,
            String digest,
            String canonicalJson) {
        this.routeMode = routeMode;
        this.policyMode = policyMode;
        this.includePackages = immutable(includePackages);
        this.excludePackages = immutable(excludePackages);
        this.generation = generation;
        this.digest = digest;
        this.canonicalJson = canonicalJson;
    }

    /** Sole raw-selection factory; generation is always issued internally. */
    public static BifrostApplicationPolicySnapshot fromSelection(
            String routeMode,
            String policyMode,
            Iterable<String> include,
            Iterable<String> exclude) {
        String generation = UUID.randomUUID().toString().replace("-", "");
        return issue(routeMode, policyMode, include, exclude, generation);
    }

    /** Recompute and compare every immutable field before each process hop. */
    public static BifrostApplicationPolicySnapshot verify(BifrostApplicationPolicySnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        BifrostApplicationPolicySnapshot rebuilt = issue(
                snapshot.routeMode,
                snapshot.policyMode,
                snapshot.includePackages,
                snapshot.excludePackages,
                snapshot.generation);
        if (!MessageDigest.isEqual(
                snapshot.digest.getBytes(StandardCharsets.US_ASCII),
                rebuilt.digest.getBytes(StandardCharsets.US_ASCII))
                || !snapshot.canonicalJson.equals(rebuilt.canonicalJson)
                || !snapshot.equals(rebuilt)) invalid("BF-APP-POLICY-SNAPSHOT");
        return snapshot;
    }

    /** Shared bounded identity normalization for UI parsing. */
    static List<String> normalizeIdentities(Iterable<String> values) {
        return validateIdentities(values, false);
    }

    public String getRouteMode() {
        return routeMode;
    }

    public String getPolicyMode() {
        return policyMode;
    }

    public List<String> getIncludePackages() {
        return includePackages;
    }

    public List<String> getExcludePackages() {
        return excludePackages;
    }

    public String getGeneration() {
        return generation;
    }

    public String getDigest() {
        return digest;
    }

    public String getCanonicalJson() {
        return canonicalJson;
    }

    public List<String> getIdentities() {
        return "allow".equals(policyMode) ? includePackages
                : "exclude".equals(policyMode) ? excludePackages
                : Collections.emptyList();
    }

    private static BifrostApplicationPolicySnapshot issue(
            String routeMode,
            String policyMode,
            Iterable<String> include,
            Iterable<String> exclude,
            String generation) {
        if (!"smart".equals(routeMode) && !"global".equals(routeMode) && !"per-app".equals(routeMode)) {
            invalid("BF-APP-POLICY");
        }
        if (!"none".equals(policyMode) && !"allow".equals(policyMode) && !"exclude".equals(policyMode)) {
            invalid("BF-APP-POLICY");
        }
        if (generation == null || !generation.matches(GENERATION_PATTERN)) invalid("BF-APP-GENERATION");
        List<String> cleanInclude = validateIdentities(include, false);
        List<String> cleanExclude = validateIdentities(exclude, false);
        if (!cleanInclude.isEmpty() && !cleanExclude.isEmpty()) invalid("BF-APP-POLICY-CONFLICT");
        if ("per-app".equals(routeMode)) {
            if ("allow".equals(policyMode) && (cleanInclude.isEmpty() || !cleanExclude.isEmpty())) {
                invalid("BF-APP-ALLOW-EMPTY");
            }
            if ("exclude".equals(policyMode) && (cleanExclude.isEmpty() || !cleanInclude.isEmpty())) {
                invalid("BF-APP-EXCLUDE-EMPTY");
            }
            if ("none".equals(policyMode)) invalid("BF-APP-POLICY");
        } else if (!"none".equals(policyMode) || !cleanInclude.isEmpty() || !cleanExclude.isEmpty()) {
            invalid("BF-APP-POLICY");
        }
        List<String> identities = "allow".equals(policyMode) ? cleanInclude
                : "exclude".equals(policyMode) ? cleanExclude
                : Collections.emptyList();
        String digest = computeDigest(routeMode, policyMode, generation, identities);
        try {
            JSONArray jsonIdentities = new JSONArray();
            for (String identity : identities) jsonIdentities.put(identity);
            String canonical = new JSONObject()
                    .put("version", VERSION)
                    .put("platform", PLATFORM)
                    .put("route_mode", routeMode)
                    .put("policy_mode", policyMode)
                    .put("generation", generation)
                    .put("identities", jsonIdentities)
                    .put("digest", digest)
                    .toString();
            return new BifrostApplicationPolicySnapshot(
                    routeMode, policyMode, cleanInclude, cleanExclude, generation, digest, canonical);
        } catch (Exception error) {
            throw new IllegalStateException("BF-APP-JSON", error);
        }
    }

    private static List<String> validateIdentities(Iterable<String> values, boolean rejectDuplicates) {
        if (values == null) invalid("BF-APP-ID");
        ArrayList<String> result = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();
        int totalBytes = 0;
        for (String value : values) {
            if (value == null || !value.equals(value.trim()) || value.isEmpty()
                    || value.codePoints().anyMatch(Character::isISOControl)
                    || !value.matches(PACKAGE_PATTERN)) invalid("BF-APP-ID");
            int bytes = value.getBytes(StandardCharsets.UTF_8).length;
            if (bytes > MAX_IDENTITY_BYTES) invalid("BF-APP-ID");
            totalBytes += bytes;
            if (totalBytes > MAX_TOTAL_IDENTITY_BYTES) invalid("BF-APP-LIMIT");
            if (!seen.add(value)) {
                if (rejectDuplicates) invalid("BF-APP-ID");
                continue;
            }
            result.add(value);
            if (result.size() > MAX_IDENTITIES) invalid("BF-APP-LIMIT");
        }
        return result;
    }

    private static String computeDigest(String routeMode, String policyMode, String generation, List<String> identities) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("BIFROST-APPLICATION-POLICY\u0000".getBytes(StandardCharsets.US_ASCII));
            updateLengthPrefixed(digest, Integer.toString(VERSION));
            updateLengthPrefixed(digest, PLATFORM);
            updateLengthPrefixed(digest, routeMode);
            updateLengthPrefixed(digest, policyMode);
            updateLengthPrefixed(digest, generation);
            digest.update(ByteBuffer.allocate(4).putInt(identities.size()).array());
            for (String identity : identities) updateLengthPrefixed(digest, identity);
            byte[] bytes = digest.digest();
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte value : bytes) {
                result.append(Character.forDigit((value >>> 4) & 0x0f, 16));
                result.append(Character.forDigit(value & 0x0f, 16));
            }
            return result.toString();
        } catch (Exception error) {
            throw new IllegalStateException("BF-APP-DIGEST", error);
        }
    }

    private static void updateLengthPrefixed(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        try {
            digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
            digest.update(bytes);
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private static List<String> immutable(List<String> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

    private static void invalid(String code) {
        throw new IllegalArgumentException(code);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof BifrostApplicationPolicySnapshot)) return false;
        BifrostApplicationPolicySnapshot that = (BifrostApplicationPolicySnapshot) other;
        return routeMode.equals(that.routeMode)
                && policyMode.equals(that.policyMode)
                && includePackages.equals(that.includePackages)
                && excludePackages.equals(that.excludePackages)
                && generation.equals(that.generation)
                && digest.equals(that.digest)
                && canonicalJson.equals(that.canonicalJson);
    }

    @Override
    public int hashCode() {
        return Objects.hash(routeMode, policyMode, includePackages, excludePackages, generation, digest, canonicalJson);
    }
}
