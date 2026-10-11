import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const app = path.join(root, 'windows-app');

test('Windows native client consumes the control plane and stages only signed selection authority', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const contract = fs.readFileSync(path.join(app, 'ClientServiceContract.cs'), 'utf8');
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const provider = fs.readFileSync(path.join(root, 'windows-service', 'MihomoProviderCompiler.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  const updater = fs.readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8');
  for (const endpoint of [
    '/v1/enrollment/redeem',
    '/v1/recovery/request',
    '/v1/pairing/create',
    '/v1/pairing/redeem',
    '/v1/device/challenge',
    '/v1/device/session',
    '/v1/config/manifest',
    '/v1/config/packages/',
    '/v1/device/logout',
  ]) assert.match(client, new RegExp(endpoint.replace(/[/.]/g, '\\$&')));
  for (const marker of ['ProtectedData', 'UseProxy = true', 'DefaultProxyCredentials = null', 'X25519', 'HKDF', 'AesGcm', 'PrepareSignedPackage', 'anti_rollback', 'content_digest', 'signed_config_json', 'selected_candidate', 'MihomoConfigCompiler.Compile', 'protocol']) {
    assert.match(`${client}\n${contract}\n${compiler}\n${provider}\n${importer}`, new RegExp(marker.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')), `missing ${marker}`);
  }
  assert.doesNotMatch(client, /ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator/);
  assert.match(updater, /UseProxy = true/);
  assert.match(updater, /DefaultProxyCredentials = null/);
  assert.doesNotMatch(updater, /ServerCertificateCustomValidationCallback|DangerousAcceptAnyServerCertificateValidator/);
  assert.match(`${client}\n${contract}`, /SignedClientPackageRequest/);
  assert.doesNotMatch(contract, /SingBoxConfigUtf8|XrayConfigUtf8|sing_box_base64|xray_base64/);
  assert.doesNotMatch(client, /ConfigPath|RuntimeDirectory|LastKnownGoodConfig|country-socks|countrySocks/);
  assert.doesNotMatch(client, /Environment\.GetEnvironmentVariable\("BIFROST_(DEVICE|SESSION|CONFIG)/);
  for (const marker of ['RecoverAsync', 'CreatePairingAsync', 'RedeemPairingAsync', 'recovery pending', 'PairingCode']) assert.match(client, new RegExp(marker.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')));
  assert.match(client, /RetrieveRecoveryDeliveryAsync/);
  const enrollment = client.slice(client.indexOf('public async Task<ControlResult> EnrollAsync'), client.indexOf('public async Task<ControlResult> RecoverAsync'));
  assert.match(enrollment, /EnrollmentInviteFingerprint/);
  assert.match(enrollment, /EnrollmentIdempotency/);
  assert.match(enrollment, /var hasPendingEnrollment = !string\.IsNullOrWhiteSpace\(_state\.EnrollmentIdempotency\)/);
  assert.match(enrollment, /resume-old-before-new-code/);
  assert.match(enrollment, /var resumed = await ResumeEnrollmentAsync\(cancellationToken\)\.ConfigureAwait\(false\);/);
  assert.match(enrollment, /return new ControlResult\(true, "enrollment resumed", _state\.PublicId, null, resumed\.ConfigVersion\)/);
  assert.match(enrollment, /catch \(InvalidOperationException error\) when \(error\.Message == "BF-DEVICE-404"\)/);
  assert.match(enrollment, /EnrollWithFreshCandidateAsync/);
  assert.doesNotMatch(enrollment, /throw new InvalidOperationException\("BF-ENROLL-INVITE"\)/);
  const currentIdentityEnrollment = client.slice(client.indexOf('private async Task<ControlResult> EnrollCurrentIdentityAsync'), client.indexOf('private async Task<ControlResult> EnrollWithFreshCandidateAsync'));
  assert.match(currentIdentityEnrollment, /var enrollmentIdempotency = _state\.EnrollmentIdempotency \?\? CreateIdempotencyKey\(\);/);
  assert.match(currentIdentityEnrollment, /SaveState\(_stateFile, pending, allowLifecycleOrigin: _lifecycleOnly\)/);
  assert.match(currentIdentityEnrollment, /catch \(InvalidOperationException error\) when \(error\.Message == "BF-DEVICE-404"\)/);
  assert.match(currentIdentityEnrollment, /catch \(InvalidOperationException error\) when \(error\.Message == "BF-ENROLL-003"\)/);
  assert.match(currentIdentityEnrollment, /catch \(Exception error\) when \(IsRejectedEnrollment\(error\)\)/);
  const freshCandidateEnrollment = client.slice(client.indexOf('private async Task<ControlResult> EnrollWithFreshCandidateAsync'), client.indexOf('private ControlState CreateEnrollmentCandidate'));
  assert.match(freshCandidateEnrollment, /EnrollmentCandidateStateFile\(primaryFile\)/);
  assert.match(freshCandidateEnrollment, /LoadState\(candidateFile, allowLifecycleOrigin: _lifecycleOnly\)/);
  assert.match(freshCandidateEnrollment, /SaveState\(primaryFile, completed, allowLifecycleOrigin: _lifecycleOnly\)/);
  assert.match(freshCandidateEnrollment, /DeleteEnrollmentCandidateState\(candidateFile\)/);
  assert.match(freshCandidateEnrollment, /catch \(InvalidOperationException error\) when \(error\.Message is "BF-DEVICE-404" or "BF-AUTH-003"\)/);
  const resume = client.slice(client.indexOf('private async Task<ControlResult> ResumeEnrollmentAsync'), client.indexOf('private async Task<ControlResult> RefreshOnlineAsync'));
  assert.match(resume, /pending\.ControlUrl = origin;/);
  assert.match(resume, /await EnsureEnrollmentIdentitySessionAsync\(cancellationToken\)\.ConfigureAwait\(false\);/);
  assert.match(resume, /await RefreshOnlineAsync\(cancellationToken\)\.ConfigureAwait\(false\);/);
  assert.match(resume, /resumed\.ConfigVersion <= 0 \|\| !IsEnrolled/);
  assert.doesNotMatch(resume, /ClearEnrollmentAttempt\(\)/);
  const refresh = client.slice(client.indexOf('public async Task<ControlResult> RefreshAsync'), client.indexOf('private async Task<ControlResult> ResumeEnrollmentAsync'));
  assert.match(refresh, /if \(!IsEnrolled\)[\s\S]*return await ResumeEnrollmentAsync\(cancellationToken\)\.ConfigureAwait\(false\);/);
  assert.match(refresh, /catch \(InvalidOperationException error\) when \(error\.Message == "BF-AUTH-003"\)/);
  assert.doesNotMatch(refresh, /if \(!IsEnrolled\) return new ControlResult/);
  const session = client.slice(client.indexOf('private async Task EstablishSessionAsync'), client.indexOf('private async Task<JsonObject> SendJsonAsync'));
  assert.match(session, /session\["public_id"\]/);
  assert.match(session, /candidate\.PublicId = publicId\.Trim\(\)/);
  assert.match(session, /"BF-AUTH-IDENTITY"/);
  assert.match(session, /requestSessionIdentity: true/);
  assert.match(client, /X-Bifrost-Session-Identity", "public-id-v1"/);
  assert.match(client, /var observedToken = string\.IsNullOrWhiteSpace\(_state\.PublicId\) \? _state\.SessionToken : null;/);
  const responseReader = client.slice(client.indexOf('private static async Task<JsonObject> ReadJsonAsync'), client.indexOf('private static Exception StatusBodyFailure'));
  assert.match(responseReader, /parsed\["error"\]\?\["code"\]\?\.GetValue<string>\(\)/);
  assert.match(responseReader, /ErrorRegistry\.IsRegistered\(code\)/);
  assert.match(responseReader, /throw new InvalidOperationException\(code\)/);
  const enrollmentUi = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  assert.match(enrollmentUi, /FileVersionInfo\.GetVersionInfo\(executable\)\.FileVersion/);
  assert.match(enrollmentUi, /ShouldClearEnrollmentInvite = UiErrorMapper\.ExtractCode\(error\) is "BF-ENROLL-001" or "BF-ENROLL-002"/);
  const windowCode = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');
  assert.match(windowCode, /ClearAccountSensitiveInputs\(clearInvite: ViewModel\.ShouldClearEnrollmentInvite\)/);
  assert.match(windowCode, /private void ClearAccountSensitiveInputs\(bool clearInvite = true\)/);
  assert.match(client, /EnsureKeys\(new ControlState\(\), persist: false\)/);
  assert.match(client, /device id already\s+\/\/ enrolled/);
  const recoveryDelivery = client.slice(client.indexOf('public async Task<ControlResult> RetrieveRecoveryDeliveryAsync'), client.indexOf('public async Task<ControlResult> CreatePairingAsync'));
  assert.doesNotMatch(recoveryDelivery, /if \(!IsEnrolled\)/);
  assert.match(recoveryDelivery, /await RefreshOnlineAsync\(cancellationToken\)\.ConfigureAwait\(false\)/);
  assert.match(recoveryDelivery, /"recovery complete"/);
  assert.match(client, /SendAuthorizedAsync\(HttpMethod\.Get, endpoint, null, cancellationToken, deliveryIdempotency\)/);
  assert.match(client, /response\["config_version"\]/);
  assert.match(client, /response\["recovery_delivery"\] as JsonObject/);
  assert.match(client, /ProtocolContract\.ValidateResponse\(path, parsed, method, status\)/);
  const sensitiveDialog = fs.readFileSync(path.join(app, 'SensitiveCodeDialog.cs'), 'utf8');
  assert.match(sensitiveDialog, /已隐藏（点击“显示一次”查看完整代码）/);
  assert.doesNotMatch(sensitiveDialog, /••••••••••••••••/);
});

test('Windows live refresh diagnostic accepts an enrolled state before its first configuration arrives', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const diagnostic = client.slice(
    client.indexOf('internal static BifrostControlClient CreateLiveDiagnosticClientForTest()'),
    client.indexOf('#endif', client.indexOf('internal static BifrostControlClient CreateLiveDiagnosticClientForTest()'))
  );
  assert.match(diagnostic, /var hasConfig = !string\.IsNullOrWhiteSpace\(state\.ConfigJson\);/);
  assert.match(diagnostic, /var config = hasConfig \? JsonNode\.Parse\(state\.ConfigJson!\) as JsonObject : null;/);
  assert.match(diagnostic, /hasConfig && \(state\.ConfigVersion <= 0 \|\| config\?\["sources"\] is not JsonArray\)/);
  assert.doesNotMatch(diagnostic, /JsonNode\.Parse\(state\.ConfigJson \?\? string\.Empty\)/);
});

test('Windows recovery activates the companion platform and retains restart-safe legacy recovery delivery', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const viewModel = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const codeBehind = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');

  for (const control of ['RecoveryPublicIdBox', 'RecoveryCodeBox', 'RecoverButton']) {
    assert.match(xaml, new RegExp(`x:Name="${control}"`));
  }
  assert.match(xaml, /x:Name="RecoveryPublicIdBox" Visibility="Collapsed"/);
  assert.doesNotMatch(xaml, /x:Name="RecoveryCodeBox" Visibility="Collapsed"/);
  assert.doesNotMatch(xaml, /x:Name="RecoverButton" Visibility="Collapsed"/);
  const recoveryHandler = codeBehind.slice(codeBehind.indexOf('private async void Recover_Click'), codeBehind.indexOf('private async void RotateRecoveryCode_Click'));
  assert.match(recoveryHandler, /EnrollCommand\.ExecuteAsync\(new UiShellViewModel\.EnrollRequest\(code\)\)/);
  assert.doesNotMatch(recoveryHandler, /RecoverCommand|RecoveryPublicIdBox/);
  assert.match(viewModel, /HasPendingRecovery/);
  assert.match(viewModel, /EnsureRecoveryDeliveryLoopStarted\(\)/);
  assert.match(viewModel, /RetrieveRecoveryDeliveryAsync\(_lifetime\.Token\)/);
  assert.match(viewModel, /等待管理员批准；批准后软件会自动继续/);
  assert.match(client, /RecoveryPending/);
  assert.match(client, /RecoveryDeliveryIdempotency/);
  assert.match(client, /deliveryIdempotency = _state\.RecoveryDeliveryIdempotency/);
  assert.match(client, /completed\.RecoveryPending = false/);
  assert.match(client, /completed\.RecoveryCode = recoveryCode/);
  assert.match(client, /RecoveryCode = recoveryCode \?\? previous\.RecoveryCode/);
  assert.match(client, /ProtectedData\.Protect\(plaintext, null, DataProtectionScope\.CurrentUser\)/);
  assert.match(viewModel, /public string RecoveryCode => _coordinator\.RecoveryCode \?\? ""/);
  assert.match(xaml, /x:Name="SavedRecoveryCodeBox"[\s\S]*Text="\{Binding RecoveryCode, Mode=OneWay\}"/);
  assert.match(xaml, /x:Name="RotateRecoveryCodeButton"[\s\S]*Click="RotateRecoveryCode_Click"/);
  assert.match(client, /RotateRecoveryCodeAsync[\s\S]*\/v1\/recovery\/rotate[\s\S]*completed\.RecoveryCode = recoveryCode/);
  assert.match(viewModel, /public async Task<ControlResult\?> RotateRecoveryCodeAsync\(\)/);
  assert.match(codeBehind, /RotateRecoveryCode_Click[\s\S]*ViewModel\.RotateRecoveryCodeAsync\(\)/);
  assert.match(xaml, /AutomationProperties\.Name="当前账号完整恢复码"/);
  assert.match(codeBehind, /完整恢复码已经加密保存在设置中，换设备时可以随时回来查看/);
  assert.match(client, /completed\.RecoveryDeliveryIdempotency = null/);
});

test('Windows keeps the old UI alive until update success, then relaunches the stable current entry point', () => {
  const viewModel = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const window = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  assert.match(viewModel, /public event Action<long>\? ProgramUpdateScheduled/);
  assert.match(viewModel, /if \(automatic\)[\s\S]*发现新版本，请及时更新[\s\S]*立即更新/);
  assert.match(viewModel, /update_scheduled[\s\S]*ProgramUpdateScheduled\?\.Invoke\(result\.Sequence\)/);
  assert.match(window, /ViewModel\.ProgramUpdateScheduled \+= ViewModel_ProgramUpdateScheduled/);
  const restart = window.slice(window.indexOf('ViewModel_ProgramUpdateScheduled(long expectedSequence)'), window.indexOf('private static class HeadlessNative'));
  assert.match(restart, /update-operation\.json/);
  assert.match(restart, /actualSequence != expectedSequence/);
  assert.match(restart, /"succeeded"[\s\S]*Process\.Start[\s\S]*CloseForExit\(\)/);
  assert.match(restart, /"failed"[\s\S]*更新安装失败[\s\S]*return/);
  assert.match(restart, /AddMinutes\(5\)/);
  const schedule = service.slice(service.indexOf('private static ServiceStatus SchedulePendingUpdate()'), service.indexOf('private static NamedPipeServerStream CreatePipe'));
  assert.match(schedule, /using var installer = Process\.Start\(start\) \?\? throw new ServiceFailure\("BF-UPDATE-INSTALLER"\)/);
  assert.doesNotMatch(schedule, /Task\.Run|Task\.Delay|try \{ Process\.Start\(start\)\?\.Dispose\(\); \} catch \{ \}/);
});

test('Windows LocalSystem compiler owns the production graph while UI uses signed display-name fields', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const provider = fs.readFileSync(path.join(root, 'windows-service', 'MihomoProviderCompiler.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'ClientPackageProtocol.cs'), 'utf8');
  const project = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  assert.match(importer, /MihomoConfigCompiler\.Compile/);
  assert.doesNotMatch(importer, /BuildSingBox|BuildXray|BIFROST_LEGACY_WINDOWS_CORES/);
  assert.doesNotMatch(project, /WindowsConfigCompiler\.cs/);
  assert.doesNotMatch(client, /BuildXrayPackageAsync|XrayConfigUtf8|SingBoxConfigUtf8/);
  assert.match(client, /display_name/);
  assert.match(client, /name_zh/);
  assert.match(client, /SelectProfile\(front, "default"\)/);
  assert.match(provider, /front_source_options/);
  assert.match(provider, /\["type"\] = "socks5"/);
  assert.match(provider, /BIFROST-SMARTGATE-FRONT-/);
  assert.match(provider, /dialer-proxy/);
  assert.match(compiler, /MihomoPolicyCompiler\.Compile/);
  assert.match(validator, /MihomoConfigValidator\.ValidateStaged/);
  assert.match(validator, /main_sha256/);
  assert.match(validator, /provider_sha256/);
});

test('Windows native control-plane identity uses the shared Ed25519 implementation', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const crypto = fs.readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8');
  assert.match(client, /Ed25519\.Sign/);
  assert.match(client, /Ed25519\.Verify/);
  assert.match(client, /SigningSeed/);
  assert.doesNotMatch(client, /CreateEd25519|ECDsa\.Create\(ECCurve\.CreateFromFriendlyName\("ed25519"\)\)/);
  assert.match(crypto, /public static byte\[\] Sign\(/);
  assert.match(crypto, /RFC 8032 Ed25519 signing/);
});

test('Windows candidate probing follows signed source.ws_path and transport host/SNI', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const engine = fs.readFileSync(path.join(app, 'CandidateProbeEngine.cs'), 'utf8');
  for (const marker of [
    'source["ws_path"]',
    'transport["host"]',
    'transport["sni"]',
    'transport["tls"]',
    'transport["network"]',
    'RandomNumberGenerator.GetBytes(16)',
    'SHA1.HashData',
    'BF-PROBE-WS-STATUS',
    'BF-PROBE-WS-UPGRADE',
    'BF-PROBE-WS-CONNECTION',
    'BF-PROBE-WS-ACCEPT',
  ]) assert.ok(client.includes(marker) || engine.includes(marker), `missing ${marker}`);
  assert.match(client, /MaxProbeCandidates = 600/);
  assert.match(client, /MaxProbeConcurrency = Math\.Clamp\(Environment\.ProcessorCount, 4, 16\)/);
  assert.match(client, /WindowsNetworkBucket/);
  assert.match(client, /CancelNetworkProbeRound/);
  assert.match(engine, /DefaultRoundBudgetBytes = 12 \* 1024/);
  assert.match(engine, /ProbeBudget/);
  assert.match(engine, /ResolveProbeUnderlay\(\)/);
  assert.match(engine, /IP_UNICAST_IF|IpUnicastIf = 31/);
  assert.match(engine, /setsockopt\(socket\.Handle, IpProtoIp, IpUnicastIf/);
  assert.match(engine, /IPAddress\.HostToNetworkOrder\(underlay\.Ipv4Index\)/);
  assert.match(engine, /TryGetPhysicalUnderlay|physical\.Length != 1/);
  assert.match(client, /ProtectedData/);
  assert.match(client, /LegacyProbeCachePath/);
  assert.doesNotMatch(`${client}\n${engine}`, /\.Wait\(|\.Result\b|GetAwaiter\(\)\.GetResult/);
});

test('Windows candidate selection measures the complete signed source on the physical runtime path', () => {
  const control = fs.readFileSync(path.join(root, 'windows-app', 'ControlPlaneClient.cs'), 'utf8');
  assert.match(control, /BuildCohort\([\s\S]*MaxProbeCandidates/);
  assert.match(control, /new SemaphoreSlim\(MaxProbeConcurrency, MaxProbeConcurrency\)/);
  assert.match(control, /Task\.WhenAll\(probes\.Select\(async candidate =>[\s\S]*candidateBudget = new ProbeBudget\(CandidateProbeEngine\.DefaultRoundBudgetBytes\)/);
  assert.doesNotMatch(control, /var discoveredBootstrap = CandidateProbeEngine\.DefaultPathUsesTunnel\(\)/);
  assert.doesNotMatch(control, /AttachBootstrapProxy\(preferredCandidate/);
});

test('Windows coexist mode pins every ordinary Mihomo candidate to the physical underlay', () => {
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoProviderCompiler.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'ClientPackageProtocol.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  assert.match(importer, /TryGetPhysicalUnderlay/);
  assert.match(importer, /physicalUnderlay/);
  assert.doesNotMatch(importer, /TryGetCompetingDefaultTunnel|BF-TUN-ALREADY-OPEN/);
  assert.match(compiler, /proxy\["interface-name"\] = SafeInterface\(input\.UnderlayInterface\)/);
  assert.doesNotMatch(compiler, /BootstrapProxyType|process_path|sing-box|xray/i);
  assert.match(validator, /MihomoConfigValidator\.ValidateStaged/);
});

test('Windows probe cancellation ignores virtual-adapter churn and retries one real underlay transition only', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  assert.match(client, /_physicalIpv4GatewaySignature = TryGetPhysicalIpv4GatewaySignature\(\)/);
  assert.match(client, /_networkAddressChangedHandler = \(_, _\) => OnNetworkTopologyChanged\(\)/);
  assert.match(client, /_networkAvailabilityChangedHandler = \(_, _\) => OnNetworkTopologyChanged\(\)/);
  assert.doesNotMatch(client, /_networkAddressChangedHandler = \(_, _\) => InvalidateNetworkProbeRound\(\)/);
  assert.doesNotMatch(client, /_networkAvailabilityChangedHandler = \(_, _\) => InvalidateNetworkProbeRound\(\)/);
  assert.match(client, /TryGetPhysicalIpv4GatewaySignature\(\)/);
  assert.match(client, /GatewayAddresses/);
  assert.match(client, /item\.Id \+ "=" \+ string\.Join\(',', gateways\)/);
  for (const virtualMarker of ['wintun', 'v2ray', 'tailscale', 'zerotier', 'radmin vpn', 'wireguard', 'openvpn']) {
    assert.ok(client.includes(virtualMarker), `missing virtual-adapter guard ${virtualMarker}`);
  }
  assert.match(client, /Interlocked\.Increment\(ref _physicalNetworkGeneration\)/);
  assert.match(client, /for \(var attempt = 0; attempt < 2; attempt\+\+\)/);
  assert.match(client, /physicalGeneration != Volatile\.Read\(ref _physicalNetworkGeneration\)/);
  assert.match(client, /!cancellationToken\.IsCancellationRequested/);
  assert.match(client, /internal void CancelNetworkProbeRound\(\) => InvalidateNetworkProbeRound\(\)/);
});

test('Windows release updater is wired to the authenticated native session', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const updater = fs.readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8');
  assert.match(client, /public string\? ControlUrl/);
  assert.match(client, /public string\? SessionToken/);
  assert.match(client, /Task EnsureSessionForUpdateAsync\(CancellationToken cancellationToken\)\s*=>\s*EnsureSessionAsync\(null, cancellationToken\)/);
  assert.match(client, /SessionRenewalSkew = TimeSpan\.FromMinutes\(5\)/);
  assert.match(client, /SessionExpiresAtUnixMilliseconds <= renewBefore/);
  assert.match(client, /session\["expires_at"\][\s\S]*DateTimeOffset\.TryParse/);
  assert.match(client, /every authenticated operation[\s\S]*await EnsureSessionAsync\(null, requestToken\)/);
  assert.match(client, /Keep the previous token durably until the replacement has been[\s\S]*await EstablishSessionAsync/);
  assert.match(client, /Task<string> RefreshSessionForUpdateAsync\(string observedToken, CancellationToken cancellationToken\)/);
  assert.match(client, /await EnsureSessionAsync\(observedToken, cancellationToken\)\.ConfigureAwait\(false\);/);
  const updateCoordinator = ui.slice(ui.indexOf('private async Task<ReleaseCheckResult?> CheckUpdateCoreAsync'), ui.indexOf('private void OnNetworkProbeInvalidated'));
  assert.match(updateCoordinator, /if \(!IsEnrolled\)[\s\S]*_control\.RefreshAsync\(cancellationToken\)[\s\S]*!activation\.Ok \|\| !IsEnrolled/);
  assert.match(updateCoordinator, /if \(string\.IsNullOrWhiteSpace\(ControlUrl\)\) return null;/);
  assert.doesNotMatch(updateCoordinator, /string\.IsNullOrWhiteSpace\(SessionToken\).*return null/);
  assert.match(updateCoordinator, /await _control\.EnsureSessionForUpdateAsync\(cancellationToken\)\.ConfigureAwait\(false\);/);
  assert.match(updateCoordinator, /var sessionToken = SessionToken \?\? throw new InvalidOperationException\("BF-AUTH-SESSION"\);/);
  assert.match(updateCoordinator, /CheckAndStageWithSessionAsync\(ControlUrl!, sessionToken, cancellationToken,/);
  assert.match(updateCoordinator, /\(token, method, uri, body\) => _control\.CreateSenderProofForSession\(token, method, uri, body\)/);
  assert.match(updateCoordinator, /\(rejectedToken, token\) => _control\.RefreshSessionForUpdateAsync\(rejectedToken, token\), progress, stageArtifacts\)/);
  assert.match(updater, /CheckAndStageWithSessionAsync/);
  assert.match(updater, /CheckAndStageCoreAsync/);
  assert.match(updater, /Func<string, CancellationToken, Task<string>> renewSession/);
  assert.match(updater, /Func<string, HttpMethod, Uri, byte\[\]\?, IReadOnlyDictionary<string, string>> proofFactory/);
  assert.match(updater, /proofFactory\?\.Invoke\(sessionToken, HttpMethod\.Get, request\.RequestUri!, null\)/);
  assert.match(updater, /X-Bifrost-Client-Version[\s\S]*CurrentClientVersion/);
  assert.match(updater, /response\.StatusCode == HttpStatusCode\.Unauthorized && attempt == 0 && renewSession is not null/);
  assert.match(updater, /activeSessionToken = await renewSession\(activeSessionToken, manifestDeadline\.Token\)\.ConfigureAwait\(false\);/);
  assert.match(updater, /DownloadAndVerifyArtifactWithFallbackAsync\(download\.Uri, download\.FallbackUri, activeSessionToken!/);
  assert.match(updater, /proofFactory\(activeSessionToken!, method, uri, body\)/);
  assert.doesNotMatch(updater, /DownloadAndVerifyArtifactWithFallbackAsync\(download\.Uri, download\.FallbackUri, tokenText!/);
  assert.match(updater, /ReleaseBlobBaseUri = RequireCanonicalOrigin\(new Uri\("https:\/\/bifrostlog\.com"\)\)/);
  assert.match(updater, /var fallbackUri = new Uri\(baseUri, blobPath\)/);
  assert.match(updater, /DownloadAndVerifyArtifactAsync\(preferredUri[\s\S]*DownloadAndVerifyArtifactAsync\(fallbackUri/);
  assert.match(updater, /for \(var attempt = 0; attempt < 2; attempt\+\+\)/);
  assert.match(updater, /ArtifactChunkBytes = 4 \* 1024 \* 1024/);
  assert.match(updater, /MaxParallelArtifactDownloads = Math\.Clamp\(Environment\.ProcessorCount, 4, 12\)/);
  assert.match(updater, /MaxParallelChunksPerArtifact = 2/);
  assert.match(updater, /ArtifactChunkAttempts = 5/);
  assert.match(updater, /total == 0 && artifactUri\.AbsolutePath\.StartsWith\("\/v1\/releases\/blobs\/"[\s\S]*DownloadFullArtifactAsync/);
  assert.match(updater, /ArtifactResponseHeaderTimeout = TimeSpan\.FromMinutes\(2\)/);
  assert.match(updater, /ArtifactReadIdleTimeout = TimeSpan\.FromMinutes\(2\)/);
  assert.doesNotMatch(updater, /Artifact(?:Chunk|Full)Timeout/);
  assert.match(updater, /ManifestCheckTimeout = TimeSpan\.FromSeconds\(30\)/);
  assert.match(updater, /CancellationTokenSource\.CreateLinkedTokenSource\(cancellationToken\)/);
  assert.match(updater, /new RangeHeaderValue\(start, end\)/);
  assert.match(updater, /DefaultRequestVersion = HttpVersion\.Version20/);
  assert.match(updater, /DefaultVersionPolicy = HttpVersionPolicy\.RequestVersionOrLower/);
  assert.doesNotMatch(updater, /request\.Headers\.ConnectionClose/);
  assert.match(updater, /idleDeadline\.CancelAfter\(ArtifactReadIdleTimeout\)/);
  assert.match(updater, /input\.ReadAsync\(buffer, idleDeadline\.Token\)/);
  assert.match(updater, /EnsureSuccessfulArtifactResponse\(response\)/);
  assert.match(updater, /HttpStatusCode\.RequestTimeout[\s\S]*HttpStatusCode\.TooManyRequests[\s\S]*HttpStatusCode\.InternalServerError[\s\S]*HttpStatusCode\.BadGateway[\s\S]*HttpStatusCode\.ServiceUnavailable[\s\S]*HttpStatusCode\.GatewayTimeout/);
  assert.match(updater, /throw new HttpRequestException\("BF-RELEASE-HTTP-TRANSIENT", null, response\.StatusCode\)/);
  assert.match(updater, /var alreadyReported = reportedByPreferred/);
  assert.match(updater, /BF-RELEASE-CHUNK-RETRY/);
  assert.match(updater, /hash\.AppendData\(chunkBytes\)[\s\S]*output\.WriteAsync\(chunkBytes/);
  assert.match(updater, /Queue<\(long Start, Task<byte\[\]> Download\)>/);
  assert.match(updater, /pending\.Count < MaxParallelChunksPerArtifact/);
  assert.match(updater, /pendingChunk\.Start != committedBytes/);
  assert.match(updater, /pipelineCancellation\.Cancel\(\)/);
  const downloadMethod = updater.slice(updater.indexOf('private async Task DownloadAndVerifyArtifactAsync('), updater.indexOf('private async Task<byte[]> DownloadArtifactChunkAsync('));
  assert.match(downloadMethod, /FileMode\.OpenOrCreate[\s\S]*FileAccess\.ReadWrite[\s\S]*FileShare\.None/);
  assert.match(downloadMethod, /if \(total > 0\) onBytesCopied\?\.Invoke\(total\)/);
  assert.match(downloadMethod, /await output\.FlushAsync\(cancellationToken\)\.ConfigureAwait\(false\);[\s\S]*if \(total != metadata\.Bytes/);
  assert.match(downloadMethod, /if \(total != metadata\.Bytes[\s\S]*output\.CopyToAsync[\s\S]*File\.Move\(destinationTemporary, destination, true\);/);
  assert.match(updater, /SemaphoreSlim\(MaxParallelArtifactDownloads/);
  assert.match(updater, /Task\.WhenAll\(tasks\)/);
  assert.match(updater, /Bifrost\.ReleaseOperation\.v2[\s\S]*DataProtectionScope\.LocalMachine/);
  assert.match(updater, /UnprotectInstallationState[\s\S]*DataProtectionScope\.LocalMachine[\s\S]*DataProtectionScope\.CurrentUser/);
});

test('Windows preserves enrolled identity across the historical production Control origin migration', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  assert.match(client, /HistoricalProductionControlOrigin = "https:\/\/bifrostlog\.com"/);
  assert.match(client, /CurrentProductionControlOrigin = "https:\/\/edge\.bifrostlog\.com"/);
  assert.match(client, /TryMigrateHistoricalProductionState\(_stateFile, _state, _trustedOrigin, out var migrated\)/);
  assert.match(client, /legacy\.ConfigVersion <= 0[\s\S]*string\.IsNullOrWhiteSpace\(legacy\.ConfigJson\)[\s\S]*!IsSha256Digest\(legacy\.ConfigDigest\)/);
  assert.match(client, /candidate\.ControlUrl = target\.Value;[\s\S]*ValidateState\(candidate\);[\s\S]*SaveState\(file, candidate\)/);
  assert.match(client, /HistoricalProductionOriginMigrationForTest/);
});

test('Windows custom install roots remain authoritative for service and updater', () => {
  const updater = fs.readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const wire = fs.readFileSync(path.join(root, 'windows-service', 'BifrostIpcWire.cs'), 'utf8');
  assert.match(wire, /ResolveInstallRootFromGenerationDirectory/);
  assert.match(wire, /\.bifrost-generations/);
  assert.match(updater, /ResolveInstallRootFromGenerationDirectory\(AppContext\.BaseDirectory\)/);
  assert.match(service, /ResolveInstallRootFromGenerationDirectory\(AppContext\.BaseDirectory\)/);
  assert.doesNotMatch(updater, /SpecialFolder\.ProgramFiles/);
  assert.doesNotMatch(service, /SpecialFolder\.ProgramFiles/);
});

test('Windows enrollment authority is an immutable build origin and never an editable URL', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const origin = fs.readFileSync(path.join(app, 'TrustedControlOrigin.cs'), 'utf8');
  const project = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  assert.match(project, /BifrostTrustedControlOrigin/);
  assert.match(project, /BifrostRequireTrustedControlOrigin/);
  assert.match(origin, /https:\/\/\{host\}/);
  for (const marker of ['Uri.UriSchemeHttps', 'UriHostNameType.Dns', 'IPAddress.TryParse', 'BF-CONTROL-UNCONFIGURED']) assert.match(`${origin}\n${client}`, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(client, /RequireTrustedOrigin\(\)/);
  assert.match(client, /_state\.ControlUrl, _trustedOrigin\.Value/);
  assert.doesNotMatch(`${client}\n${xaml}`, /127\.0\.0\.1:8787|ControlUrlBox|Environment\.GetEnvironmentVariable/);
  assert.match(xaml, /ControlOriginStatus/);
  assert.doesNotMatch(client, /EnrollAsync\(string baseUrl|RecoverAsync\(string baseUrl|RedeemPairingAsync\(string baseUrl/);
});

test('Windows LocalEvaluation is an explicit fixed loopback variant and production remains HTTPS-only', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const origin = fs.readFileSync(path.join(app, 'TrustedControlOrigin.cs'), 'utf8');
  const project = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  const vm = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  assert.match(project, /BifrostLocalEvaluation/);
  assert.match(project, /BifrostLocalEvaluationFixture/);
  assert.match(project, /http:\/\/127\.0\.0\.1:17880/);
  assert.match(project, /LocalEvaluation requires the immutable/);
  assert.match(project, /LocalEvaluation requires an explicit release trust root/);
  assert.match(origin, /LocalEvaluationOrigin = "http:\/\/127\.0\.0\.1:17880"/);
  assert.match(origin, /BifrostBuildConstants\.LocalEvaluation/);
  assert.match(origin, /LocalEvaluationFixture/);
  assert.match(origin, /uri\.Port != 17880/);
  assert.match(client, /IsLocalEvaluation/);
  assert.match(vm, /本机控制面 \{DisplayOrigin\(_control\.CompiledOriginDisplay\)\}、尚未激活/);
  assert.match(vm, /CanConnect/);
  assert.match(vm, /GetStatusAsync\(_lifetime\.Token\)[\s\S]*ApplyStatus\(status\)/);
  assert.match(vm, /recoverableBlocked[\s\S]*status\.Ok \|\| recoverableBlocked/);
  assert.match(vm, /Presentation\.State == UiConnectionState\.Blocked[\s\S]*DisconnectAsync/);
  assert.match(project, /BifrostLocalEvaluation Condition=.*false/);
  assert.match(project, /BifrostLocalEvaluationFixture Condition=.*false/);
  assert.match(client, /TryMigrateLegacyLocalEvaluationState\(_stateFile, _trustedOrigin, out var migrated\)/);
  assert.match(client, /LoadState\(file, allowLifecycleOrigin: true, discardLegacyConfigTrust: true\)/);
  assert.match(client, /string\.Equals\(legacy\.ControlUrl, TrustedControlOrigin\.LocalEvaluationOrigin, StringComparison\.Ordinal\)/);
  assert.match(client, /candidate\.ControlUrl = target\.Value/);
  assert.match(client, /var hasLkg = _state\.ConfigVersion > 0/);
  assert.match(client, /catch \(Exception error\) when \(hasLkg && BifrostWindowsAvailabilityClassifier\.CanUseOffline/);
});

test('Windows candidate probe lifecycle is generation-safe, debounced and dispatcher-owned', () => {
  const lifecycle = fs.readFileSync(path.join(app, 'WindowsProbeLifecycle.cs'), 'utf8');
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  for (const marker of ['NetworkQuietPeriod', 'RefreshCadence', 'SourceChanged', 'NetworkInvalidated', 'TriggerManual', 'IProbeLifecycleScheduler', 'CancellationTokenSource', 'ConfigureAwait(false)']) assert.match(lifecycle, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(lifecycle, /_activeKey == key/);
  assert.match(lifecycle, /cancellation\.IsCancellationRequested/);
  assert.match(ui, /_probeLifecycle\.NetworkInvalidated/);
  assert.doesNotMatch(ui, /private void OnNetworkProbeInvalidated\(\)\s*\{[^}]*RefreshAsync/);
  assert.match(ui, /_dispatcher\.Post/);
  assert.match(lifecycle, /SelectedCandidateLabel/);
  assert.match(lifecycle, /string\? ErrorCode = null/);
  assert.match(lifecycle, /catch \(ServiceException error\)[\s\S]*errorCode = error\.Code/);
  assert.match(ui, /_autoCandidateLabel = outcome\.Success \? outcome\.SelectedCandidateLabel/);
  assert.match(ui, /节点探测完成：\{EffectiveCandidateLabel\}/);
  assert.match(ui, /BF-IPC-IDENTITY/);
  assert.match(fs.readFileSync(path.join(app, 'UiErrorMapper.cs'), 'utf8'), /客户端与本机服务版本不一致/);
  assert.match(ui, /线路测速失败：\{outcome\.ErrorCode \?\? "BF-PROBE-FAILED"\}/);
  assert.match(ui, /else if \(!_candidateProbesBySource\.ContainsKey\(outcome\.Source\)\)/);
  assert.match(ui, /new Dictionary<string, CandidateProbeStatus>\(StringComparer\.OrdinalIgnoreCase\)/);
});

test('Windows automatic connect uses URLTest for startup and confirmed body throughput for steady-state routing', () => {
  const shell = fs.readFileSync(path.join(root, 'windows-app', 'UiShellViewModel.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const controller = fs.readFileSync(path.join(root, 'windows-service', 'MihomoControllerClient.cs'), 'utf8');
  const policy = fs.readFileSync(path.join(root, 'windows-service', 'MihomoPolicyCompiler.cs'), 'utf8');
  const status = fs.readFileSync(path.join(root, 'windows-service', 'ServiceStatusProtocol.cs'), 'utf8');
  assert.match(shell, /connectPhase = "prepare-mihomo-provider"/);
  assert.match(shell, /candidateOrder = new\[\] \{ placeholder \}/);
  assert.doesNotMatch(shell, /connectPhase = "measure-candidates"/);
  assert.doesNotMatch(shell, /await _coordinator\.ProbeCandidateStatusesAsync\(_state\.Source, null, _lifetime\.Token\)/);
  assert.match(shell, /staged\.Core != ProtocolCodes\.CoreMihomo/);
  assert.match(service,
    /RefreshProviderAsync\(package\.ProviderName[\s\S]*WaitForFirstUsableAutomaticGroupAsync\(package\.ActiveGroup, package\.ProviderName/);
  assert.match(service, /runtime-mihomo-provider-refreshed/);
  assert.match(service, /runtime-mihomo-first-usable-ready/);
  assert.match(service, /StartupGroupSelectionTimeout = TimeSpan\.FromSeconds\(5\)/);
  assert.match(service, /StartupTunReadyTimeout = TimeSpan\.FromSeconds\(22\)/);
  assert.match(service, /WaitForOwnedTunInterfaceAsync\(supervisor, identity, StartupTunReadyTimeout/);
  assert.match(service, /canaryReady = Task\.Run\(\(\) => ResolveHostProbeAddress/);
  assert.doesNotMatch(service, /WaitForOptimizedGroupAsync\(package\.ActiveGroup, package\.ProviderName/);
  assert.match(controller, /TriggerProviderHealthAsync\(provider, linked\.Token\)/);
  assert.match(controller, /group\/\{Escape\(group\)\}\/delay/);
  assert.match(controller, /bestDelay \+ toleranceMilliseconds/);
  assert.match(policy, /\["type"\] = "url-test"/);
  assert.match(policy, /AutoSelectToleranceMs = 50/);
  assert.match(policy, /UrlTest\(string name, string provider, int tolerance = AutoSelectToleranceMs\)/);
  assert.match(service, /MihomoQualityOptimizer\.Prepare\(LoadMihomoPackage\(resolved\)\)/);
  assert.match(service, /new MihomoQualityOptimizer\(qualityRuntime, controllerUri, controllerSecret/);
  assert.match(service, /runtime-mihomo-quality-observer-active/);
  assert.match(service, /_mihomoQualityOptimizer\?\.Dispose\(\)/);
  const optimizer = fs.readFileSync(path.join(root, 'windows-service', 'MihomoQualityOptimizer.cs'), 'utf8');
  assert.match(optimizer, /ThroughputEligible/);
  assert.match(optimizer, /SelectAsync\(package\.ActiveGroup, winner/);
  assert.match(optimizer, /quality-throughput-selected/);
  assert.match(optimizer, /WaitForFirstUsableAutomaticGroupAsync\(package\.ActiveGroup/);
  assert.match(optimizer, /StartupScreenOrder\(initialGroup\.Now, preferred, localFallback/);
  assert.match(optimizer, /ComparisonBytes = 1 \* 1024 \* 1024/);
  assert.match(optimizer, /StartupScreenBytes = ComparisonBytes/);
  assert.match(optimizer, /EndOfSweepFinalistCount = 4/);
  assert.match(optimizer, /CloseConnectionsUsingProxyAsync[\s\S]*IsRecoverableMediaHost/);
  assert.match(controller, /HttpMethod\.Delete, \$"connections\/\{Uri\.EscapeDataString\(id\)\}"/);
  assert.doesNotMatch(service, /PreferredCandidates\.FirstOrDefault/);
  assert.match(service, /TryRecoverAutomaticMihomoPathLocked/);
  assert.match(service, /runtime-mihomo-inplace-recovery-succeeded/);
  assert.match(policy, /BIFROST-OPENAI-[\s\S]*Fallback\(chatGptActive, provider\.ProviderName\)/);
  assert.match(policy, /private static JsonObject Fallback[\s\S]*\["type"\] = "fallback"/);
  assert.match(policy, /\["tolerance"\] = tolerance/);
  assert.doesNotMatch(policy, /default-selected/);
  assert.match(status, /active_candidate/);
  assert.match(shell, /ApplyRuntimeSnapshot\(status, presentation/);
  const runtimeRefresh = fs.readFileSync(path.join(root, 'windows-app', 'UiShellViewModel.Runtime.cs'), 'utf8');
  assert.match(runtimeRefresh, /ApplyMihomoReadback\(status\)/);
  assert.match(shell, /_autoCandidateLabel = mihomo\.ActiveCandidate/);
  assert.match(shell, /_lastAutomaticCandidateAttempts\.Add\(mihomo\.ActiveCandidate\)/);
  assert.match(service, /CutoverDataPlaneProbeAttempts = 2/);
  assert.match(service, /new DataPlaneProbeTarget\("www\.gstatic\.com", 443, "\/generate_204"/);
  assert.match(service, /runtime-mihomo-cutover-probe attempt=/);
  assert.doesNotMatch(shell, /VerifyDesktopApplicationDataPlaneAsync|BF-TRANSPORT-PROBE-HTTP/);
});

test('Windows activation state requires durable server enrollment evidence and exposes the invite-code action', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const shell = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const enrollmentPredicate = client.match(/public bool IsEnrolled =>[\s\S]*?public string\? ControlUrl/)?.[0] ?? '';
  assert.match(enrollmentPredicate, /_state\.PublicId[\s\S]*_state\.ConfigVersion > 0[\s\S]*_state\.ConfigJson[\s\S]*IsSha256Digest\(_state\.ConfigDigest\)/);
  assert.doesNotMatch(enrollmentPredicate, /SessionToken/);
  assert.match(shell, /Page = enrolled \? _state\.Page : "settings"/);
  assert.match(shell, /public bool RequiresActivation => !IsEnrolled/);
  assert.match(shell, /public bool IsEnrollmentPending => _coordinator\.HasPendingEnrollment/);
  assert.match(shell, /DeviceRegistrationStatus => IsEnrolled[\s\S]*IsRecoveryPending/);
  assert.match(shell, /DeviceRegistrationStatus => IsEnrolled\s*\? "已激活"/);
  assert.match(shell, /IsEnrollmentPending[\s\S]*"正在完成激活"/);
  assert.doesNotMatch(xaml, /Text="已登记"/);
  assert.match(xaml, /Text="\{Binding DeviceRegistrationStatus\}"/);
  assert.match(xaml, /x:Name="InviteBox"[\s\S]*AutomationProperties\.Name="邀请码或账号恢复码"/);
  assert.match(xaml, /x:Name="EnrollButton"[\s\S]*Content="激活设备"/);
  assert.match(xaml, /<RowDefinition Height="Auto" \/><\/Grid\.RowDefinitions>/);
  assert.match(xaml, /Visibility="\{Binding RequiresActivation, Converter=\{StaticResource BoolToVisibility\}\}"/);
});

test('Windows recovery card remains auto-sized and responsive at narrow widths', () => {
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const window = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');

  assert.match(xaml, /<RowDefinition Height="Auto" \/><\/Grid\.RowDefinitions>/);
  assert.match(xaml, /x:Name="RecoveryPublicIdBox"[\s\S]*MinHeight="38"/);
  assert.match(xaml, /x:Name="RecoveryCodeBox"[\s\S]*MinHeight="38"/);
  assert.match(xaml, /x:Name="RecoverButton"[\s\S]*MinHeight="40"/);
  assert.match(xaml, /x:Name="ActivationRecoveryLayout"[\s\S]*<Grid\.ColumnDefinitions><ColumnDefinition Width="1\*" \/><ColumnDefinition Width="14" \/><ColumnDefinition Width="1\*" \/><\/Grid\.ColumnDefinitions>/);
  assert.match(xaml, /x:Name="EnrollButton"[\s\S]*<\/StackPanel>[\s\S]*<Border Grid\.Column="2"[\s\S]*x:Name="RecoveryPublicIdBox"/);
  assert.doesNotMatch(xaml, /x:Name="EnrollButton"[\s\S]*<Border Margin="0,18,0,0" Padding="10,8"/);
  for (const row of ['SettingsTopRow', 'SettingsBottomRow', 'SettingsNarrowThirdRow', 'SettingsNarrowFourthRow']) {
    assert.match(xaml, new RegExp(`x:Name="${row}"`));
  }
  for (const card of ['SettingsGeneralCard', 'SettingsAppearanceCard', 'SettingsAccountCard', 'SettingsUpdateCard']) {
    assert.match(xaml, new RegExp(`x:Name="${card}"`));
    assert.match(window, new RegExp(card));
  }
  assert.doesNotMatch(window, /SettingsLayout\.Children\.OfType<(?:Border|StackPanel)>\(\)\.ToArray\(\)/);
  assert.match(window, /if \(CenterWorkspace is null\) return;/);
  assert.doesNotMatch(window, /if \(CenterWorkspace is not null\) return;/);
  assert.match(window, /var settingsCards = new FrameworkElement\[\]\s*\{\s*SettingsGeneralCard, SettingsAppearanceCard, SettingsAccountCard, SettingsUpdateCard\s*\};/);
  assert.match(window, /SettingsNarrowThirdRow\.Height = GridLength\.Auto[\s\S]*SettingsNarrowFourthRow\.Height = GridLength\.Auto/);
  assert.match(window, /Grid\.SetRow\(settingsCards\[index\], index \* 2\)/);
  assert.match(window, /Grid\.SetColumn\(settingsCards\[2\], 0\); Grid\.SetRow\(settingsCards\[2\], 2\);[\s\S]*Grid\.SetColumn\(settingsCards\[3\], 2\); Grid\.SetRow\(settingsCards\[3\], 2\);/);
});

test('Windows service reaps exact Bifrost cores left in installer rename directories', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  assert.match(service, /Bifrost\.uninstalling-/);
  assert.match(service, /Guid\.TryParseExact\(suffix, "N"/);
  assert.match(service, /FileAttributes\.ReparsePoint/);
  assert.match(service, /GetLockingProcessIds\(ownedImages\)/);
  assert.match(service, /historicalOwnedImages/);
  assert.match(service, /preRenameRootAbsent/);
  assert.match(service, /Path\.Combine\(generation, "cores", coreName\)/);
  assert.match(service, /TryResolveLegacyInstallTombstoneCore\(image, out var tombstoneImage\)/);
  assert.match(service, /legacyInstallRoot\.Name, "Bifrost"/);
  assert.match(service, /Directory\.Exists\(legacyInstallRoot\.FullName\)[\s\S]*return false/);
  assert.match(service, /Directory\.EnumerateDirectories\(volumeRoot\.FullName, "Bifrost\.uninstalling-\*"/);
  assert.match(service, /ownedImages\.Add\(tombstoneImage\)/);
});

test('Windows removes only a stale registry-bound bifrost1 Wintun instance before core startup', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  assert.match(service, /RemoveStaleOwnedWintunDeviceBestEffort\(phase\)/);
  assert.match(service, /OwnedTunNetworkBoundary\.HasExactTun\(\)\) return/);
  assert.match(service, /Control\\Network\\\{4D36E972-E325-11CE-BFC1-08002BE10318\}/);
  assert.match(service, /GetValue\("Name"\)[\s\S]*MihomoWindowsContract\.TunInterfaceName/);
  assert.match(service, /GetValue\("PnpInstanceID"\)[\s\S]*SWD\\Wintun\\\{/);
  assert.match(service, /Guid\.TryParse\(instanceId\[wintunPrefix\.Length\.\.\^1\], out _\)/);
  assert.match(service, /owned\.Count != 1/);
  assert.match(service, /pnputil\.exe[\s\S]*\/remove-device[\s\S]*owned\[0\]/);
  assert.match(service, /stale-wintun-cleanup exit=/);
});

test('Windows direct A/B and SmartGate country scopes are mutually exclusive across UI, IPC and LocalSystem compile', () => {
  const shell = fs.readFileSync(path.join(root, 'windows-app', 'UiShellViewModel.cs'), 'utf8');
  const client = fs.readFileSync(path.join(root, 'windows-app', 'ClientServiceContract.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(root, 'windows-app', 'MainWindow.xaml'), 'utf8');
  const window = fs.readFileSync(path.join(root, 'windows-app', 'MainWindow.xaml.cs'), 'utf8');
  assert.match(shell, /RequestCountry\(state\)[\s\S]*ConnectionType\.SmartGate[\s\S]*: "default"/);
  assert.match(shell, /Country = "default",[\s\S]*FrontSource = "auto"/);
  assert.match(client, /country scope does not match the connection type/);
  assert.match(service, /connectionType == "direct-vmess" && country != "default"/);
  assert.match(importer, /if \(connectionType == "direct-vmess"\)[\s\S]*_ = Profile\(source, "default"\)/);
  assert.match(importer, /else if \(connectionType == "smartgate"\)[\s\S]*_ = Profile\(source, "default"\)/);
  assert.match(importer, /countryObject\["socks"\] as JsonObject/);
  assert.match(xaml, /x:Name="CountrySelectionCard"/);
  assert.match(window, /CountrySelectionCard\.Visibility = smartGate \? Visibility\.Visible : Visibility\.Collapsed/);
});

test('Windows application rules select installed executables and normalize real process identities', () => {
  const shell = fs.readFileSync(path.join(root, 'windows-app', 'UiShellViewModel.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(root, 'windows-app', 'MainWindow.xaml'), 'utf8');
  const window = fs.readFileSync(path.join(root, 'windows-app', 'MainWindow.xaml.cs'), 'utf8');
  assert.match(xaml, /选择已安装程序加入应用规则/);
  assert.match(window, /OpenFileDialog[\s\S]*Windows 程序 \(\*\.exe\)/);
  assert.match(window, /Multiselect = true/);
  assert.match(window, /ViewModel\.AddApplicationIdentities/);
  assert.match(shell, /ApplicationPolicySnapshot\.NormalizeIdentities\(existing\.Concat\(incoming\)\)/);
  assert.match(shell, /RouteMode = typed\.RouteModeCode/);
});

test('Windows UI forwards stable protocol tags and opaque staged config id to service', () => {
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const serviceContract = fs.readFileSync(path.join(app, 'ClientServiceContract.cs'), 'utf8');
  const presentation = fs.readFileSync(path.join(app, 'UiPresentationModel.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const codes = fs.readFileSync(path.join(app, 'ProtocolCodes.cs'), 'utf8');
  for (const marker of ['EnrollAsync', 'RefreshAsync', 'PrepareSignedPackage', 'StageConfigAsync', 'staged.ConfigId', 'staged.Core', 'ConnectAsync', 'LogoutAsync', 'NavigateAsync']) assert.match(ui, new RegExp(marker));
  for (const marker of ['ConnectCommand', 'RefreshCommand', 'LogoutCommand', 'NavigateCommand']) assert.match(xaml, new RegExp(`Command="\\{Binding ${marker}\\}"`));
  assert.doesNotMatch(ui, /configPath|ConfigPath|LocalAppData/);
  for (const marker of ['smart', 'global', 'per-app', 'auto', 'mihomo']) assert.match(codes, new RegExp(`"${marker}"`));
  assert.doesNotMatch(codes, /CoreSingBox|CoreXray/);
  assert.doesNotMatch(ui, /"鏅鸿兘鍒嗘祦"\s*[,)]/);
  assert.doesNotMatch(ui, /"鑷姩"\s*[,)]/);
  assert.match(presentation, /(?:ClientService\.)?ServiceSelectionCodes\.IsSource\(status\.Source\)/);
  assert.doesNotMatch(presentation, /PipeClientProtocol\.IsOpaqueId\(status\.Source\)/);
  assert.match(serviceContract, /GetStatusAsync[\s\S]*allowNonOkStatus:\s*true/);
  assert.match(serviceContract, /if \(!status\.Ok && !allowNonOkStatus\)/);
});

test('Windows internal live latency validation measures candidates without entering connect', () => {
  const appStartup = fs.readFileSync(path.join(app, 'App.xaml.cs'), 'utf8');
  const shell = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const project = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  assert.match(project, /BifrostInternalLiveValidation/);
  assert.match(project, /BIFROST_INTERNAL_LIVE_VALIDATION/);
  assert.match(appStartup, /--live-validate-latency/);
  assert.match(shell, /RunLiveLatencyValidationAsync\(string source\)[\s\S]*_coordinator\.ProbeCandidateStatusesAsync\(source, null, _lifetime\.Token\)/);
  const latencyStart = appStartup.indexOf('if (validateLatency)');
  const latencyEnd = latencyStart < 0 ? -1 : appStartup.indexOf('window.ViewModel.Mode =', latencyStart);
  assert.ok(latencyStart >= 0 && latencyEnd > latencyStart, 'latency-only live-validation branch must precede connect validation');
  const latencyBranch = appStartup.slice(latencyStart, latencyEnd);
  assert.match(latencyBranch, /RunLiveLatencyValidationAsync\("A"\)/);
  assert.match(latencyBranch, /requested_mode = "latency-only"/);
  assert.match(latencyBranch, /connected = latencyStatus\.Connected/);
  assert.match(latencyBranch, /return;/);
  assert.doesNotMatch(latencyBranch, /ConnectAsync\(/);
});

test('shipping Windows loose payload redirects to the registered installed client instead of exposing a disabled updater', () => {
  const appStartup = fs.readFileSync(path.join(app, 'App.xaml.cs'), 'utf8');
  assert.match(appStartup, /#if !BIFROST_INTERNAL_LIVE_VALIDATION[\s\S]*ResolveInstallRootFromGenerationDirectory\(AppContext\.BaseDirectory\)/);
  assert.match(appStartup, /RegistryHive\.LocalMachine[\s\S]*RegistryView\.Registry64/);
  assert.match(appStartup, /GetValue\("InstallLocation"\)/);
  assert.match(appStartup, /schema\.GetString\(\) != "bifrost-current-v2"/);
  assert.match(appStartup, /current_root/);
  assert.match(appStartup, /current_payload_root/);
  assert.match(appStartup, /FileName = launcher[\s\S]*UseShellExecute = true/);
  assert.match(appStartup, /Shutdown\(0\);[\s\S]*return;/);
});

test('Windows app embeds the icon and renders the Nordic dial from production vectors', () => {
  const appProject = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  const mainWindow = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const dial = fs.readFileSync(path.join(app, 'ObsidianMechanicalDial.cs'), 'utf8');
  const icon = path.join(app, 'Assets', 'bifrost.ico');
  assert.match(appProject, /ApplicationIcon>Assets\\bifrost\.ico<\/ApplicationIcon>/);
  assert.match(appProject, /<Resource Include="Assets\\bifrost\.ico"\s*\/>/);
  assert.doesNotMatch(appProject, /<Content Include="Assets\\bifrost\.ico"\s*\/>/);
  assert.match(appProject, /<PublishReadyToRun Condition="'\$\(Configuration\)' == 'Release'">true<\/PublishReadyToRun>/);
  assert.match(appProject, /<PublishReadyToRunComposite Condition="'\$\(Configuration\)' == 'Release'">true<\/PublishReadyToRunComposite>/);
  assert.match(appProject, /<TieredPGO Condition="'\$\(Configuration\)' == 'Release'">true<\/TieredPGO>/);
  assert.match(appProject, /<ConcurrentGarbageCollection Condition="'\$\(Configuration\)' == 'Release'">true<\/ConcurrentGarbageCollection>/);
  assert.match(appProject, /<IncludeNativeLibrariesForSelfExtract>true<\/IncludeNativeLibrariesForSelfExtract>/);
  assert.match(appProject, /<IncludeAllContentForSelfExtract>false<\/IncludeAllContentForSelfExtract>/);
  assert.doesNotMatch(appProject, /obsidian-mechanical-dial/);
  assert.match(dial, /DrawMedallion/);
  assert.match(dial, /DrawValknut/);
  assert.doesNotMatch(dial, /DrawImage\(asset/);
  assert.match(mainWindow, /Icon="pack:\/\/application:,,,\/Bifrost;component\/Assets\/bifrost\.ico"/);
  assert.doesNotMatch(mainWindow, /Icon="Assets\//);
  assert.ok(fs.statSync(icon).size > 1024, 'multi-size ICO must be shipped');
  const installerProject = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'installer', 'BifrostSetup.csproj'), 'utf8');
  assert.match(installerProject, /ApplicationIcon>Assets\\bifrost\.ico<\/ApplicationIcon>/);
});

test('Windows Mihomo transport is the sole core and owns controller, TUN, provider and handover', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const provider = fs.readFileSync(path.join(root, 'windows-service', 'MihomoProviderCompiler.cs'), 'utf8');
  assert.match(service, /ResolveLockedBinary\("mihomo"\)/);
  assert.match(service, /MihomoRuntimeSupervisor/);
  assert.match(service, /MeasureGroupUntilUsableAsync/);
  assert.match(service, /WaitForHealthyGroupAsync/);
  assert.match(importer, /MihomoConfigCompiler\.Compile/);
  assert.match(compiler, /\["external-controller"\]/);
  assert.match(compiler, /\["tun"\]/);
  assert.match(provider, /\["interface-name"\]/);
  assert.doesNotMatch(`${service}\n${importer}`, /BuildSingBox|BuildXray|ResolveLockedBinary\("sing-box"\)|ResolveLockedBinary\("xray"\)/);
});

test('Windows startup safely coexists with an existing full-tunnel and proves real data-plane readiness', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const boundary = fs.readFileSync(path.join(root, 'windows-service', 'NetworkBoundary.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const provider = fs.readFileSync(path.join(root, 'windows-service', 'MihomoProviderCompiler.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'ClientPackageProtocol.cs'), 'utf8');
  const mihomoHandover = fs.readFileSync(path.join(root, 'windows-service', 'WindowsRouteHandover.cs'), 'utf8');
  assert.match(importer, /TryGetPhysicalUnderlay/);
  assert.doesNotMatch(importer, /TryGetCompetingDefaultTunnel|BF-TUN-ALREADY-OPEN/);
  assert.match(provider, /proxy\["interface-name"\] = SafeInterface\(input\.UnderlayInterface\)/);
  assert.match(compiler, /\["auto-route"\] = false/);
  assert.match(compiler, /\["strict-route"\] = false/);
  assert.match(validator, /MihomoConfigValidator\.ValidateStaged/);
  assert.match(service, /WaitForHealthyGroupAsync[\s\S]*new WindowsRouteHandover/);
  assert.match(service, /new WindowsRouteHandover\(interfaceIndex, includeIpv6\)/);
  assert.match(service, /handover\.PrepareAndCommit\(identity, group, package\.AllowedCandidates/);
  assert.match(mihomoHandover, /InstallCanary[\s\S]*CommitFullTunnel[\s\S]*RollbackAndVerify/);
  assert.doesNotMatch(`${service}\n${importer}\n${compiler}\n${provider}\n${validator}`,
    /WindowsConfigCompiler|BuildSingBox|BuildXray|BIFROST_LEGACY_WINDOWS_CORES/);
});

test('Windows service accepts bounded concurrent authenticated IPC clients without parallel tunnel mutation authority', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  assert.match(service, /MaxConcurrentIpcClients = Math\.Clamp\(Environment\.ProcessorCount \* 2, 8, 32\)/);
  assert.match(service, /new SemaphoreSlim\(MaxConcurrentIpcClients, MaxConcurrentIpcClients\)/);
  assert.match(service, /CreatePipe\(firstPipeInstance\)/);
  assert.match(service, /firstPipeInstance = false/);
  assert.match(service, /HandleConnectedClientAsync\(connectedPipe, runtime, ipcSlots, cancellationToken\)/);
  assert.match(service, /NamedPipeServerStreamAcl\.Create\(PipeName, PipeDirection\.InOut, MaxConcurrentIpcClients/);
  assert.match(service, /firstInstance \? PipeOptions\.FirstPipeInstance : PipeOptions\.None/);
  assert.match(service, /new SecurityIdentifier\(WellKnownSidType\.LocalSystemSid, null\)/);
  assert.match(service, /security\.SetOwner\(localSystem\)/);
  assert.match(service, /PipeAccessRule\(localSystem, System\.IO\.Pipes\.PipeAccessRights\.FullControl/);
  assert.match(service, /PipeAccessRule\(user, System\.IO\.Pipes\.PipeAccessRights\.ReadWrite/);
  assert.match(service, /PipeClientIdentity \{ Rejected, BoundInteractive, LocalSystem \}/);
  assert.match(service, /ClassifyPipeClientIdentity\(serverPipe, binding\.Sid\)/);
  assert.match(service, /clientIdentity == PipeClientIdentity\.LocalSystem/);
  assert.match(service, /localSystemClient && command\.Action != "release_health"/);
  assert.match(service, /throw new ServiceFailure\("BF-IPC-IDENTITY"\)/);
  assert.match(service, /new SecurityIdentifier\(WellKnownSidType\.LocalSystemSid, null\)\.Value/);
  assert.match(service, /if \(!IpcProtocol\.VerifyAuth[\s\S]*if \(!IpcProtocol\.VerifyRequest[\s\S]*localSystemClient && command\.Action != "release_health"/);
  assert.match(service, /serialization authority for tunnel state mutations/);
  assert.match(service, /public ServiceStatus Connect\([\s\S]*lock \(_sync\)/);
  assert.match(service, /public ServiceStatus Disconnect\(\)[\s\S]*lock \(_sync\)/);
});

test('Windows signed core policy has one concrete default and connect consumes the staged core', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const store = fs.readFileSync(path.join(root, '..', 'bifrost-control', 'src', 'store.mjs'), 'utf8');
  const postgresStore = fs.readFileSync(path.join(root, '..', 'bifrost-control', 'src', 'postgres-store.mjs'), 'utf8');
  const platformCorePolicy = /core_policy:\s*device.platform === 'android' \? \{ allowed: \['sing-box', 'xray'\], default: 'sing-box' \} : \{ allowed: \['mihomo'\], default: 'mihomo' \}/;
  assert.match(store, platformCorePolicy);
  assert.match(postgresStore, platformCorePolicy);
  assert.doesNotMatch(service, /core\.Equals\("auto"[\s\S]*\? "sing-box"/);
});

test('Windows connect IPC budget covers core startup without weakening other service requests', () => {
  const client = fs.readFileSync(path.join(app, 'ClientServiceContract.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const serviceProject = fs.readFileSync(path.join(root, 'windows-service', 'BifrostClientService.csproj'), 'utf8');
  assert.match(client, /ConnectOperationTimeout\s*=\s*TimeSpan\.FromSeconds\(335\)/);
  assert.match(client, /ConnectAsync[\s\S]*PipeClientProtocol\.ConnectOperationTimeout/);
  assert.match(service, /authenticationDeadline\.CancelAfter\(IpcProtocol\.OperationTimeout\)/);
  assert.match(service, /"connect" => IpcProtocol\.ConnectOperationTimeout,[\s\S]*"latency_batch" => IpcProtocol\.LatencyBatchOperationTimeout,[\s\S]*_ => IpcProtocol\.OperationTimeout/);
  assert.doesNotMatch(service, /"latency_test"/);
  assert.match(service, /ConnectOperationTimeout\s*=\s*TimeSpan\.FromSeconds\(330\)/);
  assert.match(service, /DataPlaneProbeTimeout\s*=\s*TimeSpan\.FromSeconds\(15\)/);
  assert.match(service, /SteadyStateDataPlaneProbeTimeout\s*=\s*DataPlaneHealthPolicy\.EndpointTimeout/);
  const healthPolicy = fs.readFileSync(path.join(root, 'windows-service', 'DataPlaneHealthPolicy.cs'), 'utf8');
  assert.match(healthPolicy, /EndpointTimeout\s*=\s*TimeSpan\.FromSeconds\(6\)/);
  assert.match(service, /DataPlaneProbeInterval\s*=\s*TimeSpan\.FromSeconds\(15\)/);
  assert.match(service, /"connect" => TraceConnect\(runtime, command, commandDeadline\.Token\)/);
  assert.match(service, /private static ServiceStatus TraceConnect[\s\S]*runtime\.ConnectWithRecovery\(command, cancellationToken\)/);
  assert.match(service, /private readonly object _connectCancellationSync = new\(\)/);
  assert.match(service, /private CancellationTokenSource\? _connectCancellation/);
  assert.match(service, /private void CancelConnectionStart\(\)/);
  assert.match(service, /public ServiceStatus Disconnect\(\)[\s\S]*CancelConnectionStart\(\);[\s\S]*lock \(_sync\)/);
  assert.match(service, /public ServiceStatus Connect\([\s\S]*CancellationToken cancellationToken = default[\s\S]*CreateLinkedTokenSource\(cancellationToken\)/);
  assert.match(service, /StartCoreProcessesLocked\([\s\S]*CancellationToken cancellationToken = default\)/);
  assert.match(service, /StartMihomoProcessesLocked\([\s\S]*CancellationToken cancellationToken\)/);
  assert.match(service, /WaitReadyAsync\(cancellationToken\)/);
  assert.match(service, /WaitForHealthyGroupAsync\([\s\S]*cancellationToken\)/);
  assert.match(service, /ProbeDataPlane\(DataPlaneProbeTarget target, CancellationToken cancellationToken = default, TimeSpan\? timeout = null\)/);
  assert.match(serviceProject, /<PublishReadyToRun Condition="'\$\(Configuration\)' == 'Release'">true<\/PublishReadyToRun>/);
  assert.match(serviceProject, /<PublishReadyToRunComposite Condition="'\$\(Configuration\)' == 'Release'">true<\/PublishReadyToRunComposite>/);
  assert.match(serviceProject, /<TieredPGO Condition="'\$\(Configuration\)' == 'Release'">true<\/TieredPGO>/);
  assert.match(serviceProject, /<ServerGarbageCollection Condition="'\$\(Configuration\)' == 'Release'">true<\/ServerGarbageCollection>/);
  assert.doesNotMatch(service, /requestDeadline\.CancelAfter\(IpcProtocol\.OperationTimeout\)/);
  assert.match(service, /MihomoRuntimeSupervisor/);
  assert.doesNotMatch(service, /BuildSingBox|BuildXray|StartCoreProcess\(/);
});

test('Windows Mihomo encrypted DNS is policy-bound, fake-IP based and has no plaintext fallback', () => {
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'ClientPackageProtocol.cs'), 'utf8');
  const importer = fs.readFileSync(path.join(root, 'windows-service', 'SignedClientPackageImporter.cs'), 'utf8');
  const project = fs.readFileSync(path.join(root, 'windows-service', 'BifrostClientService.csproj'), 'utf8');
  assert.match(compiler, /plaintext_fallback/);
  assert.match(compiler, /failure/);
  assert.match(compiler, /\["enhanced-mode"\] = "fake-ip"/);
  assert.match(compiler, /\["respect-rules"\] = true/);
  assert.match(compiler, /var remoteProxyDns = remoteDns \+ "#" \+ policy\.ActiveGroup/);
  assert.match(compiler, /var chatGptProxyDns = remoteDns \+ "#" \+ policy\.ChatGptGroupName/);
  assert.match(compiler, /\["nameserver"\] = new JsonArray\(remoteProxyDns\)/);
  assert.match(compiler, /nameserverPolicy\["geosite:openai"\] = new JsonArray\(chatGptProxyDns\)/);
  assert.match(compiler, /ChatGptProxyDomainSuffixes/);
  assert.match(compiler, /ChatGptProxyExactDomains/);
  assert.match(compiler, /var directBoundDns = directDns \+ "#BIFROST-DIRECT"/);
  assert.match(compiler, /\["proxy-server-nameserver"\] = new JsonArray\(directBoundDns\)/);
  assert.match(compiler, /\["direct-nameserver"\] = new JsonArray\(directBoundDns\)/);
  assert.match(compiler, /ForeignProxyGeosites[\s\S]*geosite:\{geosite\}[\s\S]*remoteProxyDns/);
  assert.match(compiler, /https:\/\/223\.5\.5\.5\/dns-query/);
  assert.match(validator, /MihomoConfigValidator\.ValidateStaged/);
  assert.doesNotMatch(`${compiler}\n${validator}`, /udp:\/\/|tcp:\/\/(?!any:53)/);
  assert.match(importer, /#if BIFROST_RELEASE_TRUST_ROOT_TEST_ONLY[\s\S]*allowLiteralIpDns = true/);
  assert.match(project, /BIFROST_RELEASE_TRUST_ROOT_TEST_ONLY/);
  assert.match(project, /Configuration.*Release.*BifrostReleaseTrustRootTestOnly.*true/);
});

test('Windows smart and SmartGate use source-scoped URLTest while country/source authority stays independent', () => {
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoPolicyCompiler.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigValidator.cs'), 'utf8');
  const shell = fs.readFileSync(path.join(root, 'windows-app', 'UiShellViewModel.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(root, 'windows-app', 'MainWindow.xaml'), 'utf8');
  for (const rule of [
    'PROCESS-NAME,QQ.exe,BIFROST-DIRECT',
    'GEOSITE,category-ads-all,REJECT',
    'GEOSITE,private,BIFROST-DIRECT',
    'GEOSITE,cn,BIFROST-DIRECT',
    'GEOIP,CN,BIFROST-DIRECT,no-resolve',
    'MATCH,{active}',
  ]) assert.match(compiler, new RegExp(rule.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(compiler, /TencentDirectDomainSuffixes\s*=\s*[\s\S]*"qq\.com"/);
  assert.match(compiler, /foreach \(var domain in TencentDirectDomainSuffixes\) rules\.Add\(\$"DOMAIN-SUFFIX,\{domain\},BIFROST-DIRECT"\)/);
  assert.match(compiler, /ForeignProxyGeosites[\s\S]*"google"[\s\S]*"github"[\s\S]*"category-ai-!cn"/);
  assert.match(compiler, /foreach \(var geosite in ForeignProxyGeosites\) rules\.Add\(\$"GEOSITE,\{geosite\},\{active\}"\)/);
  const mainCompiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  assert.match(mainCompiler, /\["interface-name"\] = input\.UnderlayInterface/);
  // Country egress shares smart routing and URLTest without crossing the
  // customer-selected country/source authority.
  assert.match(compiler, /input\.ConnectionType == "smartgate"[\s\S]*group = UrlTest\(active, provider\.ProviderName\)/);
  assert.match(compiler, /else if \(input\.RouteMode == "smart"\)[\s\S]*AddSmartRoutingRules\(rules, active, chatGptActive, remoteDnsHost, directDnsHost\)/);
  assert.match(validator, /if \(mode == "global"\) expected = new\[\] \{ \$"MATCH,\{active\}" \};/);
  assert.match(validator, /else if \(mode == "smart"\)[\s\S]*expected = smart\.ToArray\(\)/);
  assert.match(validator, /category-ads-all[\s\S]*GEOSITE,cn,BIFROST-DIRECT[\s\S]*GEOIP,CN,BIFROST-DIRECT,no-resolve/);
  assert.match(shell, /固定源站 \{Source\}，只在该源站内部自动选择和故障切换候选线路/);
  assert.match(xaml, /不会自动跨到另一个源站/);
});

test('Windows pins the complete OpenAI service boundary to one failure-only egress affinity', () => {
  const policy = fs.readFileSync(path.join(root, 'windows-service', 'MihomoPolicyCompiler.cs'), 'utf8');
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigValidator.cs'), 'utf8');
  const models = fs.readFileSync(path.join(root, 'windows-service', 'MihomoModels.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  assert.match(policy, /chatGptActive = "BIFROST-OPENAI-" \+ source;[\s\S]*Fallback\(chatGptActive, provider\.ProviderName\)/);
  assert.match(policy, /DOMAIN-SUFFIX,\{domain\},\{chatGptActive\}[\s\S]*GEOSITE,openai,\{chatGptActive\}/);
  assert.match(compiler, /chatGptProxyDns = remoteDns \+ "#" \+ policy\.ChatGptGroupName/);
  assert.match(models, /string\? ChatGptGroupName = null/);
  assert.match(validator, /groups\.Count != \(hasChatGptGroup \? 2 : 1\)/);
  assert.match(validator, /chatGptGroup\["type"\].*!= "fallback"/);
  assert.match(service, /groups\.GetArrayLength\(\) is < 1 or > 2/);
  assert.match(service, /var chatGptGroupName = groups\.GetArrayLength\(\) == 2/);
  assert.match(service, /SelectAsync\(package\.ChatGptGroupName, group\.Now, cancellationToken\)/);
  assert.match(service, /runtime-mihomo-openai-pinned/);
  assert.match(service, /RefreshChatGptAffinityLocked\(readback, deadline\.Token\)/);
  assert.match(service, /runtime-mihomo-openai-affinity-restored/);
  assert.match(service, /runtime-mihomo-openai-failover/);
  assert.match(service, /_mihomoChatGptGroupName = null;[\s\S]*_mihomoChatGptCandidate = null;/);
});

test('Windows SmartGate startup health does not depend on the not-yet-selected proxy DNS group', () => {
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigCompiler.cs'), 'utf8');
  const policy = fs.readFileSync(path.join(root, 'windows-service', 'MihomoPolicyCompiler.cs'), 'utf8');
  const validator = fs.readFileSync(path.join(root, 'windows-service', 'MihomoConfigValidator.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const windowsContract = fs.readFileSync(path.join(root, 'windows-service', 'MihomoWindowsContract.cs'), 'utf8');
  assert.match(windowsContract, /StartupProbeUrl = "https:\/\/www\.gstatic\.com\/generate_204"/);
  assert.match(windowsContract, /StartupProbeExpectedStatus = 204/);
  assert.match(compiler, /health-check[\s\S]*MihomoWindowsContract\.StartupProbeUrl[\s\S]*MihomoWindowsContract\.StartupProbeExpectedStatus/);
  assert.match(compiler, /\["www\.gstatic\.com"\] = new JsonArray\(directBoundDns\)/);
  assert.equal((policy.match(/MihomoWindowsContract\.StartupProbeUrl/g) ?? []).length, 2);
  assert.equal((policy.match(/MihomoWindowsContract\.StartupProbeExpectedStatus/g) ?? []).length, 2);
  assert.match(validator, /healthCheck\["url"\][\s\S]*MihomoWindowsContract\.StartupProbeUrl/);
  assert.match(fs.readFileSync(path.join(root, 'windows-service', 'MihomoControllerClient.cs'), 'utf8'),
    /MihomoWindowsContract\.StartupProbeUrl[\s\S]*MihomoWindowsContract\.StartupProbeExpectedStatus/);
  assert.match(fs.readFileSync(path.join(root, 'windows-service', 'MihomoControllerClient.cs'), 'utf8'),
    /const string testUrl = MihomoWindowsContract\.StartupProbeUrl[\s\S]*expected=\{MihomoWindowsContract\.StartupProbeExpectedStatus\}/);
  assert.match(service, /StartupProviderMeasurementTimeout = TimeSpan\.FromSeconds\(30\)/);
  assert.match(service, /WaitForFirstUsableAutomaticGroupAsync\(package\.ActiveGroup, package\.ProviderName,[\s\S]{0,180}StartupGroupSelectionTimeout/);
  assert.doesNotMatch(service, /WaitForOptimizedGroupAsync/);
  assert.match(service, /group = MergeMeasuredCandidateHealth\(group, measured\)/);
  assert.match(service, /measurement\.Alive && measurement\.DelayMs is > 0/);
  assert.match(fs.readFileSync(path.join(root, 'windows-service', 'MihomoControllerClient.cs'), 'utf8'),
    /candidate\.Alive && candidate\.DelayMs is > 0/);
});

test('Windows per-app allow/exclude policies are mutually exclusive and fail closed', () => {
  const client = fs.readFileSync(path.join(app, 'ControlPlaneClient.cs'), 'utf8');
  const compiler = fs.readFileSync(path.join(root, 'windows-service', 'MihomoPolicyCompiler.cs'), 'utf8');
  const snapshot = fs.readFileSync(path.join(root, 'windows-service', 'ApplicationPolicySnapshot.cs'), 'utf8');
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  for (const marker of ['appPolicyMode', 'BF-APP-POLICY-CONFLICT', 'BF-APP-ALLOW-EMPTY', 'BF-APP-EXCLUDE-EMPTY', 'IncludeIdentities', 'ExcludeIdentities', 'PROCESS-NAME']) {
    assert.match(`${client}\n${compiler}\n${snapshot}`, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `missing ${marker}`);
  }
  // Assert the actual selectable policy labels, not removed hidden text.
  assert.match(xaml, /<ComboBoxItem Tag="allow">仅名单内应用走代理<\/ComboBoxItem>/);
  assert.match(xaml, /<ComboBoxItem Tag="exclude">名单内应用直连，其余走代理<\/ComboBoxItem>/);
  assert.match(client, /policy == "allow"/);
  assert.match(client, /policy == "exclude"/);
  // The routing-page switch is an independent capability. Closed mode never
  // parses, validates, or transmits text; switching allow/exclude also clears
  // the now-inactive list so the UI cannot preserve a conflicting policy.
  assert.match(ui, /var include = _state\.AppPolicyEnabled \? SplitApplications\(_state\.IncludeApps\) : Array\.Empty<string>\(\)/);
  assert.match(ui, /var exclude = _state\.AppPolicyEnabled \? SplitApplications\(_state\.ExcludeApps\) : Array\.Empty<string>\(\)/);
  assert.match(ui, /applicationPolicyEnabled = value == ProtocolCodes\.ModeSmart && _state\.AppPolicyEnabled/);
  assert.match(ui, /enabled = value && _state\.Mode == ProtocolCodes\.ModeSmart/);
  assert.match(ui, /ConnectionRouteSelection\.FromPresentation\(value, applicationPolicyEnabled\)/);
  assert.match(ui, /ConnectionRouteSelection\.FromPresentation\(_state\.Mode, enabled\)/);
  assert.match(ui, /ConnectionTypeCode/);
  assert.match(ui, /RouteModeCode/);
  assert.match(ui, /_state\.AppPolicyEnabled \? _state\.AppPolicy : "none"/);
  assert.match(ui, /AppPolicy = normalized, ExcludeApps = ""/);
  assert.match(ui, /AppPolicy = normalized, IncludeApps = ""/);
  assert.match(xaml, /ModeAppPolicyEnabledBox[\s\S]*IsChecked="\{Binding AppPolicyEnabled, Mode=TwoWay\}"/);
  assert.match(xaml, /ModeIncludeAppsBox[\s\S]*IsEnabled="\{Binding CanEditConnectionSettings\}"/);
  assert.equal((xaml.match(/UpdateSourceTrigger=PropertyChanged, Delay=300/g) || []).length, 4,
    'application-list text persistence must be debounced across both mirrored editors');
  const bridge = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');
  assert.match(bridge, /ModeIncludeAppsPanel\.IsEnabled = state\.AppPolicyEnabled && ViewModel\.CanEditConnectionSettings/);
  assert.match(bridge, /ModeExcludeAppsPanel\.IsEnabled = state\.AppPolicyEnabled && ViewModel\.CanEditConnectionSettings/);
});

test('Windows FUNCTION1 UI automation verifies the fixed dark-only theme without cycling retired themes', () => {
  const harness = fs.readFileSync(path.join(root, 'tests', 'windows-function1-ui.ps1'), 'utf8');
  assert.match(harness, /\[int\]\$TimeoutSeconds = 20/);
  assert.match(harness, /function Wait-WindowHelp/);
  assert.match(harness, /Wait-WindowHelp "当前页面：\$expectedPage；\*" 5/);
  assert.match(harness, /themes \+= '深色'/);
  assert.doesNotMatch(harness, /Invoke-Element \$initialTheme/);
});

test('Windows manual-route delay streams bounded batches from one isolated Mihomo process', () => {
  const client = fs.readFileSync(path.join(app, 'ClientServiceContract.cs'), 'utf8');
  const coordinator = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const controller = fs.readFileSync(path.join(root, 'windows-service', 'MihomoControllerClient.cs'), 'utf8');
  const session = fs.readFileSync(path.join(root, 'windows-service', 'MihomoHealthProbeSession.cs'), 'utf8');
  assert.match(client, /action = "latency_batch"/);
  assert.match(client, /ParseLatencyBatchFrame/);
  assert.match(client, /response\.RootElement\.TryGetProperty\("connected", out _\)/);
  assert.match(client, /ParseStatus\(response\.RootElement\)/);
  assert.match(client, /service rejected the latency batch before streaming began/);
  assert.match(service, /"latency_batch" => ParseLatencyBatch/);
  assert.match(service, /MeasureLatencyBatchAsync/);
  assert.match(service, /SignedClientPackageImporter\.Import\(ServicePaths\.ConfigRoot/);
  assert.match(service, /One signed source produces one provider containing all/);
  assert.match(service, /MihomoHealthProbeSession\.MeasureAsync/);
  assert.match(controller, /candidates\.Chunk\(12\)/);
  assert.doesNotMatch(service, /liveController\.TriggerProviderHealthAsync\(package\.ProviderName[\s\S]{0,500}liveController\.ReadCandidatesAsync/);
  assert.match(service, /private void CancelLatencyBatch\(\)/);
  assert.match(service, /public ServiceStatus Disconnect\(\)[\s\S]*CancelLatencyBatch\(\)/);
  assert.match(service, /public ServiceStatus Connect\([\s\S]*CancelLatencyBatch\(\)/);
  assert.match(service, /LatencyBatchFrame\.Progress/);
  assert.match(service, /catch \(Exception error\)[\s\S]*LatencyBatchFrame\.Blocked\(code, completed, Math\.Max\(1, total\)\)/);
  assert.match(service, /const string code = "BF-CANDIDATE-PROBE-FAILED"/);
  assert.match(coordinator, /ProbeCandidateStatusesAsync\(string source/);
  assert.match(session, /new MihomoRuntimeSupervisor/);
  assert.match(session, /MeasureCandidatesInBatchesAsync\(package\.ProviderName, candidates/);
  assert.match(session, /health\["enable"\] = false/);
  assert.match(controller, /group\/\{Escape\(group\)\}\/delay/);
  assert.doesNotMatch(service, /SignedClientPackageImporter\.ImportBatch/);
});

test('Windows update and latency actions expose progressive user feedback without blocking first paint', () => {
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  const client = fs.readFileSync(path.join(app, 'ClientServiceContract.cs'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const bridge = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');
  const release = fs.readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8');
  const uiStateFixture = fs.readFileSync(path.join(root, 'tests', 'ui-state-fixture', 'Program.cs'), 'utf8');
  const appProject = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  const serviceProject = fs.readFileSync(path.join(root, 'windows-service', 'BifrostClientService.csproj'), 'utf8');
  const productVersion = appProject.match(/<Version>([^<]+)<\/Version>/)?.[1];
  assert.ok(productVersion, 'Windows product version must be declared in BifrostApp.csproj');
  const escapedProductVersion = productVersion.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  assert.match(appProject, new RegExp(`<AssemblyVersion>${escapedProductVersion}\\.0<\\/AssemblyVersion>`));
  assert.match(appProject, new RegExp(`<FileVersion>${escapedProductVersion}\\.0<\\/FileVersion>`));
  assert.match(appProject, new RegExp(`<InformationalVersion>${escapedProductVersion}<\\/InformationalVersion>`));
  assert.match(serviceProject, new RegExp(`<Version>${escapedProductVersion}<\\/Version>`));
  assert.match(serviceProject, new RegExp(`<AssemblyVersion>${escapedProductVersion}\\.0<\\/AssemblyVersion>`));
  assert.match(serviceProject, new RegExp(`<FileVersion>${escapedProductVersion}\\.0<\\/FileVersion>`));
  assert.match(serviceProject, new RegExp(`<InformationalVersion>${escapedProductVersion}<\\/InformationalVersion>`));
  assert.match(xaml, /CheckUpdateButton[\s\S]*Content="\{Binding UpdateActionLabel\}"/);
  assert.match(xaml, /Text="\{Binding UpdateStatusTitle\}"[\s\S]*AutomationProperties\.LiveSetting="Polite"/);
  assert.match(xaml, /Value="\{Binding UpdateProgress, Mode=OneWay\}"/);
  assert.match(xaml, /IsIndeterminate="\{Binding UpdateProgressIndeterminate, Mode=OneWay\}"/);
  // The current update card uses its dedicated status binding; UpdateText
  // remains activation-only and no longer has a named WPF element.
  assert.match(xaml, /Text="\{Binding UpdateStatusMessage\}"/);
  assert.doesNotMatch(xaml, /<TextBlock[^>]*Text="\{Binding UpdateStatusMessage\}"[^>]*Visibility="Collapsed"/);
  assert.match(xaml, /Value="\{Binding CandidateProbeProgressPercent, Mode=OneWay\}"/);
  assert.match(xaml, /Content="\{Binding CandidateProbeActionLabel\}"/);
  assert.match(xaml, /RefreshCandidateProbesCommand[\s\S]*IsEnabled="\{Binding CanRefreshCandidateProbes\}"/);
  assert.match(xaml, /AutomationProperties\.Name="\{Binding CandidateProbeAutomationName\}"/);
  assert.match(ui, /CanRefreshCandidateProbes => IsCandidateProbeRunning \|\| CanEditConnectionSettings/);
  assert.match(ui, /CandidateProbeActionLabel => IsCandidateProbeRunning[\s\S]*停止测速/);
  assert.match(ui, /_probeLifecycle\.CancelManual\(\)/);
  assert.match(client, /kind = "cancel"[\s\S]*cancel\|\{parsed\.Nonce\}\|\{operationId\}\|3/);
  assert.match(service, /MonitorLatencyBatchCancelAsync/);
  assert.match(service, /VerifyCancel/);
  assert.match(ui, /SetUpdateFeedback\(0, "checking", "正在检查更新"/);
  assert.match(ui, /UpdateProgressIndeterminate => IsUpdateChecking && _updateStatusKind == "checking"/);
  assert.match(ui, /if \(!IsUpdateChecking\) return;/);
  assert.match(ui, /检查更新超时[\s\S]*60 秒内没有响应/);
  assert.match(ui, /BF-RELEASE-ORIGIN[\s\S]*当前为本地评估版，未接入正式 HTTPS 签名更新源/);
  assert.match(ui, /UpdateAvailabilityText => _coordinator\.IsLocalEvaluation \? "评估版关闭" : "已启用"/);
  assert.match(xaml, /Text="\{Binding UpdateAvailabilityText\}"/);
  assert.doesNotMatch(ui, /CanFallbackLegacyLatencyBatch/);
  assert.doesNotMatch(ui, /_control\.ProbeCandidateStatusesAsync\(source, cancellationToken\)/);
  assert.match(ui, /completedRound = !pending && probes is not null/);
  assert.match(ui, /"up-to-date"[\s\S]*已是最新版本/);
  assert.match(ui, /outcome\.IsPartial[\s\S]*线路测速中/);
  assert.match(ui, /配置已同步，正在准备线路/);
  assert.match(ui, /正在准备安全配置/);
  assert.match(ui, /正在连接 \{_state\.Source\} · \{candidateLabel\}/);
  assert.match(ui, /连接完成 · \{connectTimer\.Elapsed\.TotalSeconds:0\.0\} 秒/);
  assert.match(ui, /UiConnectionState\.Protected or UiConnectionState\.Preparing or UiConnectionState\.Reconnecting => TimeSpan\.FromSeconds\(1\)/);
  assert.match(ui, /_ => TimeSpan\.FromSeconds\(4\)/);
  const startup = ui.slice(ui.indexOf('public Task StartAsync()'), ui.indexOf('private void EnsureRecoveryDeliveryLoopStarted'));
  assert.match(startup, /if \(!_coordinator\.IsEnrolled\)[\s\S]*_startupTask \?\?= WarmStartAsync\(\)[\s\S]*return Task\.CompletedTask/);
  assert.doesNotMatch(startup, /if \(!_coordinator\.IsEnrolled\) return Task\.CompletedTask/);
  const warmStart = ui.slice(ui.indexOf('private async Task WarmStartAsync()'), ui.indexOf('internal void SetPresentation'));
  assert.match(warmStart, /while \(!_lifetime\.IsCancellationRequested\)[\s\S]*if \(!result\.Ok \|\| !_coordinator\.IsEnrolled\)[\s\S]*return;[\s\S]*IsEnrolled = true[\s\S]*persist: true[\s\S]*EnsureConfigRefreshLoopStarted\(\)[\s\S]*EnsureProgramUpdateLoopStarted\(\)/);
  assert.match(ui, /ActivationResumeRetryDelays[\s\S]*FromSeconds\(2\)[\s\S]*FromMinutes\(1\)/);
  assert.match(warmStart, /_startupRetryScheduler\.DelayAsync\(delay, _lifetime\.Token\)/);
  assert.match(uiStateFixture, /refreshFailuresBeforeSuccess: 1[\s\S]*ReleaseNext\(\)[\s\S]*RefreshCalls == 2/);
  assert.match(uiStateFixture, /rejectedCoordinator[\s\S]*PendingCount == 0[\s\S]*explicit not-registered result/);
  assert.match(ui, /NavigateAsync\(string page\)[\s\S]*"nodes"[\s\S]*EnsureProbeLifecycleStarted/);
  assert.match(bridge, /ContentRendered \+=/);
  assert.match(bridge, /DispatcherPriority\.ContextIdle/);
  assert.match(release, /ReleaseUpdateProgress/);
  assert.match(release, new RegExp(`CurrentClientVersion = "${escapedProductVersion}"`));
  assert.match(xaml, /Text="\{Binding ProductVersion\}"/);
  assert.doesNotMatch(xaml, new RegExp(`Text="${escapedProductVersion}"`));
  assert.match(release, /ManifestCheckTimeout = TimeSpan\.FromSeconds\(30\)/);
  assert.match(release, /manifestDeadline\.CancelAfter\(ManifestCheckTimeout\)/);
  assert.match(release, /new ReleaseUpdateProgress\(0, "checking", "正在检查可用版本"\)/);
  assert.match(release, /正在下载更新 · \{Volatile\.Read\(ref completedArtifacts\)\}\/\{selected\.Length\} 个组件完成/);
  assert.match(release, /artifact\.Kind == "installer" && string\.Equals\(relative, "BifrostSetup\.exe", StringComparison\.Ordinal\)/);
  assert.match(release, /onBytesCopied\?\.Invoke\(chunkBytes\.Length\)/);
});

test('Windows release build keeps one signed installer in the immutable payload tree without a redundant ZIP-root copy', () => {
  const script = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'scripts', 'build-clients.ps1'), 'utf8');
  assert.match(script, /Path = \(Join-Path \$windowsInstallerRelease 'BifrostSetup\.exe'\); Platform = 'windows'; Arch = 'x64'; Kind = 'installer'/);
  assert.doesNotMatch(script, /\$rootInstallerArtifact/,
    'the manifest-bound inner helper must never be exposed as a root-level human-facing installer');
  assert.doesNotMatch(script, /Join-Path \$releases 'BifrostSetup\.exe'/,
    'release root must not contain a standalone inner helper that lacks the signed package envelope');
  assert.doesNotMatch(script, /Copy-Item -LiteralPath \$signedInstallerInPackage -Destination \$redistributableSetup -Force/);
  assert.match(script, /Do not duplicate the 100\+ MB self-contained[\s\S]*redundant alias materially bloats every offline setup/);
  assert.match(script, /Start-Process -FilePath \$signedInstallerInPackage[\s\S]*-Wait -PassThru -NoNewWindow/);
  assert.match(script, /redistributableVerify\.ExitCode -ne 0/);
  assert.doesNotMatch(script, /artifactDefinitions \+= @\{ Path = \$rootInstallerArtifact; Platform = 'windows'; Arch = 'x64'; Kind = 'installer'/);
});

test('Windows manual route list lets the user select any signed candidate without forcing an immediate connect', () => {
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  assert.match(xaml, /Content="选择"[\s\S]*SelectCandidateCommand[\s\S]*CommandParameter="\{Binding Code\}"/);
  assert.match(xaml, /点击“选择”固定线路/);
  assert.doesNotMatch(xaml, /UseCandidateCommand/);
  assert.doesNotMatch(xaml, /使用并连接/);
  assert.match(ui, /private Task SelectCandidateAsync\(string\? code\)[\s\S]*CandidateMode = "manual"[\s\S]*CandidateLabel = code/);
});

test('Windows client automatically refreshes newly published signed config while it stays open', () => {
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  assert.match(ui, /EnsureConfigRefreshLoopStarted\(\)/);
  assert.match(ui, /PollControlConfigAsync\(\)/);
  assert.match(ui, /IsLocalEvaluation \? TimeSpan\.FromSeconds\(5\) : TimeSpan\.FromSeconds\(30\)/);
  assert.match(ui, /var before = _coordinator\.LastConfigVersion;[\s\S]*RefreshAsync\(_lifetime\.Token\)[\s\S]*after <= before/);
  assert.match(ui, /ApplyOptions\(options\)[\s\S]*配置已自动同步：v\{after\}/);
  assert.match(ui, /if \(!_state\.IsProtected\) _probeLifecycle\.TriggerManual\(\)/);
});

test('SmartGate requires an explicit customer-selected node instead of automatic egress selection', () => {
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  const ui = fs.readFileSync(path.join(app, 'UiShellViewModel.cs'), 'utf8');
  assert.match(xaml, /x:Name="SmartGateNodeBox"[\s\S]*ItemsSource="\{Binding CountryOptions\}"[\s\S]*SelectedValue="\{Binding Country, Mode=TwoWay\}"/);
  assert.match(xaml, /Text="用户手动"/);
  assert.match(xaml, /IsEnabled="\{Binding CanUseSmartGateAction\}"/);
  assert.match(ui, /HasSelectedSmartGateNode[\s\S]*CountryOptions\.Count > 0[\s\S]*ContainsOption\(CountryOptions, Country\)/);
  assert.match(ui, /SmartGateManualFailoverStatus[\s\S]*不跨用户所选节点切换/);
  assert.match(ui, /SmartGate is customer-directed/);
});


test('Windows minimize stays in the taskbar while optional close-to-tray preserves an explicit exit path', () => {
  const project = fs.readFileSync(path.join(app, 'BifrostApp.csproj'), 'utf8');
  const main = fs.readFileSync(path.join(app, 'MainWindow.xaml.cs'), 'utf8');
  const xaml = fs.readFileSync(path.join(app, 'MainWindow.xaml'), 'utf8');
  assert.match(project, /<UseWindowsForms>true<\/UseWindowsForms>/);
  assert.match(main, /System\.Windows\.Forms\.NotifyIcon/);
  assert.doesNotMatch(main, /StateChanged \+= [\s\S]*WindowState == WindowState\.Minimized[\s\S]*MinimizeToTray\(\)/);
  assert.match(main, /Closing \+= Window_Closing/);
  assert.match(main, /if \(_forceWindowExit \|\| !_closeToTrayEnabled \|\| _trayIcon is null\) return;[\s\S]*e\.Cancel = true;[\s\S]*MinimizeToTray\(\)/);
  assert.match(main, /ShowInTaskbar = false;[\s\S]*Hide\(\)/);
  assert.match(main, /ShowInTaskbar = true;[\s\S]*Show\(\);[\s\S]*WindowState = WindowState\.Normal;[\s\S]*Activate\(\)/);
  const tray = fs.readFileSync(path.join(app, "MainWindow.Tray.cs"), "utf8");
  assert.match(tray, /BifrostTrayMenu\.Action\("打开 Bifrost"[\s\S]*RestoreFromTray/);
  assert.match(tray, /BifrostTrayMenu\.Action\("退出 Bifrost"[\s\S]*CloseForExit/);
  assert.match(tray, /ViewModel\.ConnectCommand/);
  assert.match(tray, /ViewModel\.UseCandidateCommand/);
  assert.match(main, /CloseForExit\(\)[\s\S]*_forceWindowExit = true;[\s\S]*Close\(\)/);
  assert.match(main, /DoubleClick \+= [\s\S]*RestoreFromTray/);
  assert.match(main, /Closed \+= [\s\S]*DisposeTrayIcon/);
  assert.match(main, /CloseWindow_Click[\s\S]*=> Close\(\)/);
  assert.match(main, /PersistUiPreference\("CloseToTray"/);
  assert.match(xaml, /关闭时最小化到托盘/);
});

test('Mihomo latency batch uses fresh per-candidate requests and startup preserves partial history', () => {
  const service = fs.readFileSync(path.join(root, 'windows-service', 'Program.cs'), 'utf8');
  const controller = fs.readFileSync(path.join(root, 'windows-service', 'MihomoControllerClient.cs'), 'utf8');
  assert.match(service, /MihomoHealthProbeSession.MeasureAsync/);
  assert.match(controller, /MeasureCandidateAsync\(provider, candidate, round.Token\)/);
  const measureStart = controller.indexOf('internal async Task<IReadOnlyList<MihomoProxyHealth>> MeasureGroupUntilUsableAsync');
  const measureEnd = controller.indexOf('internal async Task<IReadOnlyList<MihomoRuleReadback>>', measureStart);
  assert.ok(measureStart >= 0 && measureEnd > measureStart);
  const measure = controller.slice(measureStart, measureEnd);
  assert.match(measure, /ReadCandidateSamplesAsync[\s\S]*baseline/);
  assert.match(measure, /TriggerProviderHealthAsync/);
  assert.match(measure, /HistoryVersion/);
  assert.match(measure, /freshRound/);
  assert.doesNotMatch(measure, /last\.All\(candidate => candidate\.Alive && candidate\.DelayMs is > 0\)\) return last/);
});
