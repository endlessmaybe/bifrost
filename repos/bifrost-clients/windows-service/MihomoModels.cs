using System.Text.Json.Nodes;

namespace Bifrost.ClientService;

internal sealed record MihomoBootstrapProxy(string Type, int Port);

internal sealed record MihomoCompileInput(
    JsonObject SignedConfig,
    string Source,
    string ConnectionType,
    string RouteMode,
    string? FixedCandidate,
    string Country,
    ApplicationPolicySnapshot ApplicationPolicy,
    string UnderlayInterface,
    int ControllerPort,
    string ControllerSecret,
    string TunName,
    string ProviderFileName,
    MihomoBootstrapProxy? BootstrapProxy,
    string? FrontSource = null,
    string? FrontCandidate = null,
    bool EnableIpv6 = true);

internal sealed record MihomoCompiledPackage(
    byte[] MainConfig,
    byte[] Provider,
    string ProviderName,
    string ActiveGroup,
    IReadOnlySet<string> AllowedCandidates,
    string Digest,
    string? ChatGptGroupName = null,
    IReadOnlyList<string>? PreferredCandidates = null);

internal sealed record MihomoProxyHealth(string Name, bool Alive, int? DelayMs);

internal sealed record MihomoGroupState(string Name, string Now, IReadOnlyList<MihomoProxyHealth> Candidates);

internal sealed record MihomoRuleReadback(string Type, string Payload, string Proxy);

internal sealed record MihomoRuntimeIdentity(int ProcessId, string ImagePath, string ConfigDigest);

internal sealed record HandoverSnapshot(
    int TunInterfaceIndex,
    System.Net.IPAddress CanaryAddress,
    bool Ipv4Committed,
    bool Ipv6Committed);
