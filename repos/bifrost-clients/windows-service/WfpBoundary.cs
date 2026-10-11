namespace Bifrost.ClientService;

/// <summary>
/// Windows Filtering Platform integration is deliberately disabled in this
/// release.  A broad ALE connect rule cannot prove that an application owns
/// the Bifrost tunnel, so it would also cut off v2rayN and unrelated programs.
/// We retain a deterministic plan for diagnostics and future proofing, but no
/// code path opens the WFP engine or installs a host-wide rule.
/// </summary>
public static class WfpBoundary
{
    public const string SublayerId = "Bifrost-WFP-DISABLED";

    public sealed record RulePlan(
        string Mode,
        bool TunReady,
        bool ExplicitApply,
        bool WillApply,
        string Scope,
        string Reason);

    public static RulePlan BuildPlan(string mode, string lockedCoreBinary, bool tunReady, bool? explicitApply = null)
    {
        // There is deliberately no environment switch in the product.  A
        // caller may pass an explicit value in a test, but production always
        // remains a dry-run until a narrowly owned per-process boundary is
        // proven.  This prevents a machine-wide kill switch from being
        // enabled by an untrusted environment variable.
        var requested = explicitApply ?? false;
        var validMode = mode is "smart" or "global" or "per-app";
        var validCore = !string.IsNullOrWhiteSpace(lockedCoreBinary);
        var reason = !validMode ? "unsupported route mode" :
            !validCore ? "locked core path is missing" :
            !tunReady ? "owned TUN readiness evidence is missing" :
            requested ? "WFP apply is disabled: no safe per-process boundary is available" :
            "dry-run only; WFP apply is disabled";
        return new RulePlan(mode, tunReady, requested, false, "none (WFP apply disabled)", reason);
    }

    /// <summary>
    /// Kept as an explicit failure instead of silently claiming that a
    /// kill-switch is active. This protects existing host networking.
    /// </summary>
    public static void InstallOwnRulesOnly(string lockedCoreBinary) =>
        throw new InvalidOperationException("BF-WFP-DISABLED: WFP rules are disabled until a narrowly scoped per-process boundary is proven");

    public static void InstallOwnRulesOnly() => InstallOwnRulesOnly(string.Empty);

    /// <summary>
    /// No-op by design: this release never installs rules. The parameter is
    /// retained for lifecycle callers and is intentionally ignored.
    /// </summary>
    public static void RemoveOwnRulesOnly(bool allowSystemChange = false) { }
}
