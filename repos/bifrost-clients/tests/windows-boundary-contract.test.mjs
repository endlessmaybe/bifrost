import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const read = async (relative) => readFile(new URL(relative, root), 'utf8');

test('Windows UI uses stable protocol tags, never display labels', async () => {
  const xaml = await read('windows-app/MainWindow.xaml');
  const code = await read('windows-app/MainWindow.xaml.cs');
  for (const value of ['smart', 'global', 'smartgate', 'auto', 'mihomo']) assert.match(xaml, new RegExp(`Tag="${value}"`));
  assert.match(xaml, /x:Name="AppPolicyEnabledBox"[\s\S]*IsChecked="\{Binding AppPolicyEnabled, Mode=TwoWay\}"/);
  assert.match(await read('windows-app/UiShellViewModel.cs'), /FromPresentation\(_state\.Mode, enabled\)[\s\S]*RouteMode = typed\.RouteModeCode/);
  assert.doesNotMatch(xaml, /Tag="sing-box"|Tag="xray"/);
  assert.doesNotMatch(xaml, /ListBoxItem Tag="direct"/);
  assert.match(code, /\.Tag\?\.ToString\(\)/);
  assert.doesNotMatch(code, /SelectedItem\).*Content/);
});

test('WFP remains an explicit dry-run and requires owned TUN evidence', async () => {
  const wfp = await read('windows-service/WfpBoundary.cs');
  const service = await read('windows-service/Program.cs');
  assert.doesNotMatch(wfp, /BIFROST_WFP_APPLY|Environment\s*\./);
  assert.match(wfp, /tunReady/);
  assert.match(wfp, /WFP apply is disabled/);
  assert.match(wfp, /return new RulePlan\(mode, tunReady, requested, false,/);
  assert.doesNotMatch(wfp, /FwpMatchNotEqual|FwpActionBlock|FwpmFilterAdd0|FwpmEngineOpen0/);
  assert.doesNotMatch(wfp, /non-loopback.*kill switch/i);
  assert.doesNotMatch(service, /--ready-file|BIFROST_CORE_READY_FILE|--tun-fd/);
  assert.match(service, /ResolveMihomoHealthEndpoint/);
  assert.match(service, /WfpBoundary\.BuildPlan\(mode, effectiveCore, true\)/);
  assert.match(service, /UseProxy = false/);
});

test('disconnect and core crash cannot alter unrelated process networking', async () => {
  const wfp = await read('windows-service/WfpBoundary.cs');
  const service = await read('windows-service/Program.cs');
  assert.match(wfp, /RemoveOwnRulesOnly\([^)]*\) \{ \}/);
  assert.doesNotMatch(service, /_wfpApplied\s*=\s*true/);
  assert.doesNotMatch(service, /Fwpm|FwpAction|ALE_AUTH_CONNECT/);
});

test('desktop UI accepts the service-verified data plane without a second blocking probe', async () => {
  const ui = await read('windows-app/UiShellViewModel.cs');
  assert.match(ui, /authenticated LocalSystem service returns "connected" only after/);
  assert.match(ui, /That service result is the connection authority/);
  assert.doesNotMatch(ui, /VerifyDesktopApplicationDataPlaneAsync/);
  assert.doesNotMatch(ui, /BF-TRANSPORT-PROBE-HTTP/);
  assert.doesNotMatch(ui, /_service\.DisconnectAsync\(cleanup\.Token\)/);
});

test('Meta TUN counters are translated to user-facing Internet direction', async () => {
  const telemetry = await read('windows-app/WindowsTunnelTelemetry.cs');
  assert.match(telemetry, /var received = statistics\.BytesSent;\s*\/\/ user download/);
  assert.match(telemetry, /var sent = statistics\.BytesReceived;\s*\/\/ user upload/);
  assert.match(telemetry, /new TunnelTrafficSample\(adapter\.Id, received, sent/);
  const tracker = await read('windows-app/TunnelTrafficTracker.cs');
  assert.match(tracker, /_sessionBytes \+= \(double\)received \+ sent/);
});

test('shipping service connect path uses the shared fail-closed runtime coordinator', async () => {
  const service = await read('windows-service/Program.cs');
  assert.match(service, /private ControlledRuntimeCoordinator\? _controlledRuntime/);
  assert.match(service, /new ControlledRuntimeCoordinator\(/);
  assert.match(service, /controlled\.Connect\(controlledPackage\)/);
  assert.match(service, /ServiceBoundaryAdapter/);
  assert.match(service, /ServiceCoreAdapter/);
  assert.doesNotMatch(service, /StartCoreProcess\(binary, config\)/);
});

test('shipping service repeats exact packaged-core orphan recovery immediately before Mihomo start', async () => {
  const service = await read('windows-service/Program.cs');
  assert.match(service, /RecoverOrphanedPackagedCoresLocked\("startup"\)/);
  assert.match(service, /ConfirmStartupOrphanRecoveryAsync\(cancellationToken\)/);
  assert.match(service, /startup-confirm-/);
  assert.match(service, /StartMihomoProcessesLocked[\s\S]*RecoverOrphanedPackagedCoresLocked\("pre-connect"\)[\s\S]*LoadMihomoPackage/);
  assert.match(service, /CleanupOrphanedPackagedCores\(out var stoppedAny\)/);
  assert.match(service, /BF-CORE-BLOCKED-STOP-UNCONFIRMED/);
  assert.match(service, /OwnedTunRouteCommit\.RemoveKnownFullTunnelRoutesBestEffort/);
});

test('packaged-core cleanup owns legacy sing-box and inaccessible Mihomo only by exact generation file locks', async () => {
  const service = await read('windows-service/Program.cs');
  assert.match(service, /new\[\] \{ "mihomo\.exe", "sing-box\.exe" \}/);
  assert.match(service, /new\[\] \{ "mihomo", "sing-box" \}/);
  assert.match(service, /RmRegisterResources/);
  assert.match(service, /GetLockingProcessIds\(ownedImages\)/);
  assert.match(service, /lockingProcessIds\.Contains\(process\.Id\)/);
  assert.match(service, /parts\[2\] is not \("mihomo\.exe" or "sing-box\.exe"\)/);
  assert.match(service, /full\.StartsWith\(rootPrefix, StringComparison\.OrdinalIgnoreCase\)/);
  assert.match(service, /if \(!exactLockOwner && \(fullImage is null \|\| !IsOwnedGenerationCore\(fullImage\)\)\)[\s\S]*continue;/);
});

test('shipping Mihomo cutover retries a slow or degraded winner before fail-closed rollback', async () => {
  const service = await read('windows-service/Program.cs');
  assert.match(service, /CutoverDataPlaneProbeTimeout = TimeSpan\.FromSeconds\(12\)/);
  assert.match(service, /CutoverDataPlaneProbeAttempts = 2/);
  assert.match(service, /runtime-mihomo-cutover-probe attempt=/);
  assert.match(service, /MeasureGroupUntilUsableAsync[\s\S]*runtime-mihomo-cutover-remeasured/);
  assert.match(service, /WaitForHealthyGroupAsync[\s\S]*runtime-mihomo-cutover-reselected/);
  assert.match(service, /if \(aliveCount == 0\) throw new ServiceFailure\("BF-SOURCE-ALL-CANDIDATES-DEAD"\)/);
  assert.match(service, /runtime-connect-failed code=/);
});

test('steady-state data-plane failure uses fast confirmation without tolerating lost owned routes', async () => {
  const service = await read('windows-service/Program.cs');
  assert.match(service, /DataPlaneFailureRetryInterval = TimeSpan\.FromSeconds\(1\)/);
  assert.match(service, /DataPlaneFailureThreshold = 3/);
  assert.match(service, /DataPlaneFastFailureThreshold = 2/);
  assert.match(service, /selectedCandidateHealthy = readback\.Candidates\.Any/);
  assert.match(service, /_selectedCandidateTransientUnhealthy = true/);
  assert.match(service, /_selectedCandidateTransientUnhealthy = false/);
  assert.match(service, /runtime-mihomo-readback-transient-unhealthy/);
  assert.match(service, /probeInterval = _consecutiveDataPlaneProbeFailures > 0[\s\S]*DataPlaneFailureRetryInterval[\s\S]*DataPlaneProbeInterval/);
  assert.match(service, /fastFailure = _selectedCandidateTransientUnhealthy \|\| IsFastDataPlaneFailure\(result\.Code\)/);
  assert.match(service, /failureThreshold = fastFailure \? DataPlaneFastFailureThreshold : DataPlaneFailureThreshold/);
  assert.match(service, /IsFastDataPlaneFailure\(string code\) => DataPlaneHealthPolicy\.IsFastFailure\(code\)/);
  assert.match(service, /routeOwnershipLost = string\.Equals\(result\.Code, "BF-TUN-ROUTE", StringComparison\.Ordinal\)/);
  assert.match(service, /DataPlaneHealthPolicy\.ShouldDisconnect\(_consecutiveDataPlaneProbeFailures/);
  assert.match(service, /ServiceStatus\.Blocked\("BF-RUNTIME-HEALTH", diagnostic\)/);
  assert.doesNotMatch(service, /if \(force \|\| _coexistRoutes is not null \|\| _consecutiveDataPlaneProbeFailures/);
});

test('Windows automatic startup requalifies a recent verified winner and bounds cold-start qualification', async () => {
  const service = await read('windows-service/Program.cs');
  const quality = await read('windows-service/MihomoQualityOptimizer.cs');
  assert.match(service, /recalledGroup is not null[\s\S]*QualifyStartupAsync[\s\S]*compactReconnect: true/);
  assert.match(service, /qualityRuntime\.Port > 0[\s\S]*new MihomoQualityOptimizer/);
  assert.match(quality, /quality-startup-screen-complete measured=\{startupSamples\.Count\} eligible=\{cohort\.Length\}/);
  assert.match(quality, /Task\.WhenAll\(lanes\.Select\(ScreenLaneAsync\)\)/);
  assert.match(quality, /ScoreStartupCapacity\(streams\.Where\(stream => stream\.IsCompletedSuccessfully\)/);
  assert.match(quality, /quality-startup-throughput-selected/);
  assert.doesNotMatch(quality, /speed\.cloudflare\.com\/__down/);
});
