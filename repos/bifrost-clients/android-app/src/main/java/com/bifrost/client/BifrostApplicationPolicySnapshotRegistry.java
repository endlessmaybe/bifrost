package com.bifrost.client;

import java.util.HashMap;
import java.util.Map;

/**
 * Process-private handoff for an already issued immutable snapshot.  Android
 * keeps the Activity and its non-exported VPN service in one application
 * process; the Intent carries only correlation/integrity fields.  A process
 * death clears this registry, so stale persisted metadata can never recreate
 * a live policy capability.
 */
final class BifrostApplicationPolicySnapshotRegistry {
    private static final String ID_PATTERN = "[0-9a-f]{32}";
    private static final Map<String, BifrostApplicationPolicySnapshot> ENTRIES = new HashMap<>();
    private static Object configurationChange;

    private BifrostApplicationPolicySnapshotRegistry() { }

    static synchronized boolean register(
            String transactionId,
            BifrostApplicationPolicySnapshot snapshot) {
        if (transactionId == null || !transactionId.matches(ID_PATTERN) || snapshot == null) return false;
        BifrostApplicationPolicySnapshot.verify(snapshot);
        if (configurationChange != null || ENTRIES.containsKey(transactionId)) return false;
        ENTRIES.put(transactionId, snapshot);
        return true;
    }

    static synchronized BifrostApplicationPolicySnapshot lookup(String transactionId) {
        if (transactionId == null || !transactionId.matches(ID_PATTERN)) return null;
        return ENTRIES.get(transactionId);
    }

    static synchronized void remove(String transactionId) {
        if (transactionId != null) ENTRIES.remove(transactionId);
    }

    /** Package-private test/diagnostic surface; no caller can issue a value. */
    static synchronized int count() {
        return ENTRIES.size();
    }

    /** Exclude connection admission while a user authorizes a tunnel-mode change. */
    static synchronized Object beginConfigurationChange() {
        if (configurationChange != null || !ENTRIES.isEmpty()) return null;
        configurationChange = new Object();
        return configurationChange;
    }

    static synchronized boolean configurationChanging() { return configurationChange != null; }

    static synchronized void endConfigurationChange(Object owner) {
        if (owner != null && configurationChange == owner) configurationChange = null;
    }

    static synchronized void clear() {
        ENTRIES.clear();
        configurationChange = null;
    }
}
