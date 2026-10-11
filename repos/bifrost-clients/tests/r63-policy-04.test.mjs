import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const android = path.join(root, 'android-app', 'src', 'main', 'java', 'com', 'bifrost', 'client');
const windowsApp = path.join(root, 'windows-app');
const windowsService = path.join(root, 'windows-service');

const read = (...parts) => fs.readFileSync(path.join(...parts), 'utf8');
const androidSource = name => read(android, name);
const windowsSource = name => read(windowsService, name);

test('R63-POLICY-04 production sources reject truncation and fail-open policy parsing', () => {
  const sources = [
    androidSource('ApplicationPolicy.kt'),
    androidSource('MainActivity.kt'),
    androidSource('BifrostVpnService.kt'),
    androidSource('BifrostConfigCompiler.kt'),
    androidSource('BifrostXrayConfigCompiler.kt'),
    androidSource('BifrostCoreAdapter.kt'),
    androidSource('BifrostLibboxPlatform.kt'),
    windowsSource('ApplicationPolicySnapshot.cs'),
    windowsSource('MihomoConfigCompiler.cs'),
    windowsSource('MihomoPolicyCompiler.cs'),
    windowsSource('MihomoProviderCompiler.cs'),
    windowsSource('ClientPackageProtocol.cs'),
    read(windowsApp, 'ControlPlaneClient.cs'),
    read(windowsApp, 'ClientServiceContract.cs'),
    read(windowsApp, 'MainWindow.xaml.cs'),
    windowsSource('Program.cs'),
  ].join('\n');
  assert.doesNotMatch(sources, /(?:\.|)take\s*\(\s*64\s*\)/i);
  assert.doesNotMatch(sources, /\.Take\s*\(\s*64\s*\)/);
  assert.match(androidSource('BifrostApplicationPolicySnapshot.java'), /MAX_IDENTITIES\s*=\s*64/);
  assert.match(androidSource('BifrostApplicationPolicySnapshot.java'), /MAX_TOTAL_IDENTITY_BYTES/);
  assert.match(androidSource('MainActivity.kt'), /BF-APP-PERSISTED-INVALID/);
  assert.match(androidSource('BifrostCoreAdapter.kt'), /BF-APP-POLICY-MISSING/);
  assert.match(androidSource('BifrostLibboxPlatform.kt'), /applicationPolicyReadback/);
});

test('Android Activity, Intent, service, compiler and platform use one verified snapshot', () => {
  const activity = androidSource('MainActivity.kt');
  const vpn = androidSource('BifrostVpnService.kt');
  const compiler = androidSource('BifrostConfigCompiler.kt');
  const xrayCompiler = androidSource('BifrostXrayConfigCompiler.kt');
  const adapter = androidSource('BifrostCoreAdapter.kt');
  const platform = androidSource('BifrostLibboxPlatform.kt');
  assert.match(activity, /applicationPolicySnapshot/);
  assert.match(activity, /BifrostApplicationPolicySnapshotRegistry\.register/);
  assert.doesNotMatch(activity, /putExtra\([^\n]*EXTRA_APPLICATION_POLICY[,)]/);
  assert.match(vpn, /SnapshotRegistry\.lookup/);
  assert.match(vpn, /BifrostApplicationPolicy(?:\.verify|::verify)/);
  assert.match(vpn, /applicationPolicy/);
  assert.match(compiler, /resolveApplicationPolicy/);
  assert.match(xrayCompiler, /resolveApplicationPolicy/);
  assert.match(adapter, /prepareXray\([^)]*applicationPolicy/);
  assert.match(adapter, /applicationPolicyReadback\(\)/);
  assert.match(adapter, /ApplicationPolicySnapshot/);
  assert.match(platform, /configureApplicationPolicy\(\s*snapshot/);
  assert.match(platform, /applicationPolicyReadback/);
  assert.match(platform, /snapshot\.includePackages|snapshot\.excludePackages/);
  assert.match(compiler, /applicationPolicy:\s*BifrostApplicationPolicySnapshot[,)]/);
  assert.match(xrayCompiler, /applicationPolicy:\s*BifrostApplicationPolicySnapshot[,)]/);
  assert.doesNotMatch(compiler, /if\s*\(supplied\s*==\s*null\)/);
  assert.doesNotMatch(xrayCompiler, /if\s*\(supplied\s*==\s*null\)/);
  assert.doesNotMatch(`${activity}\n${vpn}\n${adapter}`, /fromJson\([^)]*\)\s*\?\s*emptyList/);
  assert.doesNotMatch(vpn, /if\s*\(core\.isReady\(\)\)\s*return\s+START_STICKY/);
});

test('Android connection is a generation-bound service acknowledgement transaction', () => {
  const activity = androidSource('MainActivity.kt');
  const uiText = androidSource('ui/model/BifrostUiText.kt');
  const vpn = androidSource('BifrostVpnService.kt');
  const coordinator = androidSource('ApplicationPackagePolicy.kt');
  const coordinatorJava = androidSource('BifrostApplicationPolicyConnectionCoordinator.java');
  const serviceCoordinator = androidSource('BifrostServiceCommandCoordinator.kt');
  const runtime = androidSource('BifrostRuntimeCoordinator.kt');
  const ownershipRegistry = androidSource('BifrostServiceTransactionOwnership.kt');
  const commitStart = activity.indexOf('private fun commitAndStart');
  const serviceStart = activity.indexOf('private fun startVpnService');
  assert.ok(commitStart >= 0 && serviceStart > commitStart);
  assert.doesNotMatch(activity.slice(commitStart, serviceStart), /uiPut\s*\(/);
  assert.doesNotMatch(activity.slice(commitStart, serviceStart), /selected(?:Mode|Core|Source|Country|AppPolicy)\s*=/);
  for (const marker of [
    'EXTRA_TRANSACTION_ID',
    'EXTRA_APPLICATION_POLICY_DIGEST',
    'EXTRA_APPLICATION_POLICY_GENERATION',
    'EXTRA_ACK_RECEIVER',
    'handleVpnAck',
  ]) assert.match(activity, new RegExp(marker));
  for (const marker of [
    'EXTRA_TRANSACTION_ID',
    'EXTRA_ACK_CODE',
    'EXTRA_ACK_DIGEST',
    'EXTRA_ACK_GENERATION',
    'EXTRA_ACK_BINDINGS',
    'EXTRA_ACK_BLOCKED',
    'sendAck',
    'RESULT_READY',
    'applicationPolicyReadback',
  ]) assert.match(vpn, new RegExp(marker));
  assert.match(vpn, /BifrostServiceCommandCoordinator/);
  assert.match(vpn, /transactionOwnership\.adoptExisting/);
  assert.match(vpn, /RESULT_DISCONNECTED/);
  assert.match(vpn, /ACTION_STATUS/);
  assert.match(vpn, /EXTRA_ACK_IDLE/);
  assert.match(vpn, /EXTRA_ACK_RELEASE_EPOCH/);
  assert.match(vpn, /cleanupOwnService/);
  assert.match(vpn, /status\?\.exactLive/);
  assert.match(vpn, /status\?\.globalOwner\s*==\s*null/);
  assert.match(vpn, /result\.released/);
  assert.match(vpn, /transactionOwnership\.ready/);
  assert.match(serviceCoordinator, /failAfterFence/);
  assert.match(androidSource('BifrostServiceTransactionOwnership.kt'), /BifrostServiceLifecycleDecision/);
  assert.match(androidSource('BifrostServiceTransactionOwnership.kt'), /STOP_REMOVE/);
  assert.ok(vpn.indexOf('transactionOwnership.begin(transaction)') < vpn.indexOf('runtime.starting()'));
  assert.match(vpn, /EXTRA_APPLICATION_POLICY_GENERATION/);
  assert.match(vpn, /EXTRA_APPLICATION_POLICY_DIGEST/);
  assert.doesNotMatch(activity, /\bcheck\s*\(/);
  assert.doesNotMatch(coordinator, /Prepared|submit\s*\(/);
  assert.match(coordinatorJava, /public final class BifrostApplicationPolicyConnectionCoordinator/);
  assert.doesNotMatch(coordinatorJava, /Prepared|submit\s*\(/);
  assert.match(coordinatorJava, /validator\.validate/);
  assert.match(activity, /BifrostConnectionTransactionGate/);
  assert.match(activity, /handleConnectionUpdateResult[\s\S]*isActive\(pending\.token\(\)\)/);
  assert.match(activity, /private fun requestVpn[\s\S]*isActive\(pending\.token\(\)\)/);
  assert.match(activity, /sendScopedDisconnect/);
  assert.match(activity, /beginDisconnectExact/);
  assert.match(activity, /releaseDisconnectExact/);
  assert.match(activity, /completeDiscoveredRelease/);
  assert.match(activity, /reconcileDisconnect/);
  assert.doesNotMatch(activity, /releaseCommittedExact\(committedToken\)/);
  assert.doesNotMatch(activity, /releaseBlockedExact\(blocked\.token\(\)\)/);
  assert.match(activity, /consumeReleaseReceipt/);
  assert.match(activity, /releaseEpoch/);
  assert.match(uiText, /disconnectUnknown/);
  assert.doesNotMatch(activity, /actual\s*==\s*null\s*\|\|\s*actual\s*==\s*expected/);
  assert.match(activity, /BifrostServiceConnectionMetadata\.complete/);
  assert.match(activity, /EXTRA_CANDIDATE/);
  assert.match(activity, /pending\.candidate/);
  assert.match(vpn, /BF-CANDIDATE-MISSING/);
  assert.match(androidSource('BifrostServiceTransactionOwnership.kt'), /BF-CONNECTION-DESCRIPTION/);
  assert.match(activity, /readBatch\(this, uiKeys\)/);
  assert.match(activity, /restoreUiState/);
  assert.match(activity, /BF-CONNECTION-TIMEOUT/);
  assert.match(activity, /BifrostUiText\.vpnConnected/);
  assert.doesNotMatch(activity, /Bifrost VPN connected|awaiting policy/);
  assert.doesNotMatch(activity, /stopService\s*\(/);
  assert.match(vpn, /stopForeground\(STOP_FOREGROUND_REMOVE\)/);
  assert.match(androidSource('BifrostServiceCommandCoordinator.kt'), /BifrostServiceOwnershipRegistry\.noteReleasedExact/);
  assert.doesNotMatch(vpn, /Source-compatible helper/);
  assert.doesNotMatch(androidSource('BifrostConnectionTransactionGate.kt'), /releaseCommittedExact|releaseBlockedExact/);
  assert.match(androidSource('BifrostServiceTransactionOwnership.kt'), /fun reset\(\) = Unit/);
  assert.match(androidSource('BifrostServiceTransactionOwnership.kt'), /private fun resetState/);
  assert.match(serviceCoordinator, /BifrostServiceFailureCoordinator/);
  assert.match(serviceCoordinator, /completeDisconnectWithRelease/);
  assert.match(serviceCoordinator, /DISCONNECTING/);
  assert.match(serviceCoordinator, /globalOwner/);
  assert.match(serviceCoordinator, /cleanupOwnService/);
  assert.doesNotMatch(serviceCoordinator, /runtimeFenceEstablished\(token\)/);
  assert.match(runtime, /BifrostRuntimeCoreFailureOutcome/);
  assert.match(runtime, /BF-WATCHDOG-STOP/);
  assert.match(runtime, /BF-LOCKDOWN-EVIDENCE/);
  assert.match(runtime, /teardownConfirmed/);
  assert.match(activity, /releaseDiscoveryToken/);
  assert.match(activity, /restoreSavedDisconnectHandoff/);
  assert.doesNotMatch(activity, /requestedDisconnect\(\)\s*\n\s*\?\s*:/);
  assert.doesNotMatch(activity, /releaseDiscoveryToken\(\)\s*\)?\s*\?\s*:/);
  assert.match(activity, /UNPROTECTED_FAILED/);
  assert.match(ownershipRegistry, /unprotected\s*=\s*token/);
  assert.match(ownershipRegistry, /releaseDiscoveryToken\(token:/);
  assert.match(ownershipRegistry, /consumedReleaseEpochs/);
  assert.match(ownershipRegistry, /disconnectRequests/);
});

test('Android bytecode and same-package adversary prove snapshot and capability closure', () => {
  const snapshotKt = androidSource('ApplicationPolicy.kt');
  const snapshotJava = androidSource('BifrostApplicationPolicySnapshot.java');
  const coordinatorJava = androidSource('BifrostApplicationPolicyConnectionCoordinator.java');
  assert.doesNotMatch(snapshotKt, /DefaultConstructorMarker|sealed\s+interface/);
  assert.match(snapshotJava, /public final class BifrostApplicationPolicySnapshot/);
  assert.match(snapshotJava, /private BifrostApplicationPolicySnapshot\(/);
  assert.match(snapshotJava, /fromSelection\s*\(\s*String routeMode[\s\S]*Iterable<String> exclude/);
  assert.doesNotMatch(snapshotJava, /fromSelection\s*\([^)]*String generation/);
  assert.doesNotMatch(snapshotJava, /fromCanonicalJson/);
  assert.doesNotMatch(coordinatorJava, /Prepared|submit\s*\(/);
  const kotlinClasses = path.join(root, 'android-app', 'build', 'tmp', 'kotlin-classes', 'debug');
  const javaClasses = path.join(root, 'android-app', 'build', 'intermediates', 'javac', 'debug', 'compileDebugJavaWithJavac', 'classes');
  const snapshotClass = path.join(javaClasses, 'com', 'bifrost', 'client', 'BifrostApplicationPolicySnapshot.class');
  const coordinatorClass = path.join(javaClasses, 'com', 'bifrost', 'client', 'BifrostApplicationPolicyConnectionCoordinator.class');
  assert.ok(fs.existsSync(snapshotClass), `required snapshot build output missing: ${snapshotClass}`);
  assert.ok(fs.existsSync(coordinatorClass), `required coordinator build output missing: ${coordinatorClass}`);
  const candidates = [
    process.env.JAVA_HOME?.trim() ? path.join(process.env.JAVA_HOME.trim(), 'bin', process.platform === 'win32' ? 'javap.exe' : 'javap') : '',
    'C:\\Program Files\\Java\\jdk-17\\bin\\javap.exe',
    'C:\\Program Files\\Android\\jdk\\jdk-8.0.302.8-hotspot\\jdk8u302-b08\\bin\\javap.exe',
    'javap',
  ].filter(Boolean);
  const javap = candidates.find(candidate => candidate === 'javap' || fs.existsSync(candidate));
  assert.ok(javap, 'javap is required for bytecode API audit');
  const inspect = className => {
    const result = spawnSync(javap, ['-private', '-classpath', `${kotlinClasses};${javaClasses}`, className], {
      cwd: root,
      encoding: 'utf8',
      timeout: 30000,
    });
    assert.equal(result.status, 0, `${result.stdout ?? ''}${result.stderr ?? ''}`);
    return `${result.stdout ?? ''}${result.stderr ?? ''}`;
  };
  const snapshot = inspect('com.bifrost.client.BifrostApplicationPolicySnapshot');
  assert.match(snapshot, /public final class com\.bifrost\.client\.BifrostApplicationPolicySnapshot/);
  assert.match(snapshot, /private .*BifrostApplicationPolicySnapshot\(/);
  assert.doesNotMatch(snapshot, /public .*BifrostApplicationPolicySnapshot\(/);
  assert.doesNotMatch(snapshot, /DefaultConstructorMarker|Companion|issue\$/);
  const coordinator = inspect('com.bifrost.client.BifrostApplicationPolicyConnectionCoordinator');
  assert.doesNotMatch(coordinator, /Prepared|submit\s*\(/);

  for (const className of [
    'com.bifrost.client.BifrostConnectionTransactionGate',
    'com.bifrost.client.BifrostServiceTransactionOwnership',
  ]) inspect(className);
  const gate = inspect('com.bifrost.client.BifrostConnectionTransactionGate');
  assert.doesNotMatch(gate, /isActive\(java\.lang\.String\)/);
  assert.match(gate, /beginDisconnectExact/);
  assert.match(gate, /releaseDisconnectExact/);

  const fixtureDir = path.join(root, 'tests', 'android-policy-bytecode-fixture');
  const fixtures = [
    'Adversarial.java', 'ForgeViaCanonical.java', 'ForgeViaGeneration.java',
    'ForgeViaPrepared.java', 'ForgeViaTransactionId.java',
    'ForgeViaIncompletePublish.java', 'ForgeViaReleaseBypass.java', 'ForgeViaReset.java', 'ForgeViaClearExact.java', 'ForgeViaNoteReleased.java', 'ForgeViaOwnershipClear.java',
  ];
  for (const name of fixtures) assert.ok(fs.existsSync(path.join(fixtureDir, name)), `compile-negative fixture missing: ${name}`);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-policy-negative-'));
  try {
    for (const name of fixtures) {
      const result = spawnSync('javac', [
        '-proc:none', '-XDrawDiagnostics', '-d', temp,
        '-classpath', `${kotlinClasses};${javaClasses}`, path.join(fixtureDir, name),
      ], { cwd: root, encoding: 'utf8', timeout: 30000 });
      const diagnostics = `${result.stdout ?? ''}${result.stderr ?? ''}`;
      assert.notEqual(result.status, 0, `${name} unexpectedly compiled`);
       assert.match(diagnostics, /final|private|fromCanonicalJson|fromSelection|Prepared|submit|isActive|publish|releaseCommitted|releaseBlocked|reset|clearExact|clear|noteReleased/);
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('Windows UI, compiled package, staging metadata, IPC and service bind policy digest/generation', () => {
  const snapshot = windowsSource('ApplicationPolicySnapshot.cs');
  const compiler = windowsSource('MihomoConfigCompiler.cs');
  const policyCompiler = windowsSource('MihomoPolicyCompiler.cs');
  const pkg = windowsSource('ClientPackageProtocol.cs');
  const service = windowsSource('Program.cs');
  const signedImporter = windowsSource('SignedClientPackageImporter.cs');
  const client = read(windowsApp, 'ControlPlaneClient.cs');
  const contract = read(windowsApp, 'ClientServiceContract.cs');
  const ui = read(windowsApp, 'MainWindow.xaml.cs');
  const uiViewModel = read(windowsApp, 'UiShellViewModel.cs');
  assert.match(snapshot, /MaxIdentities\s*=\s*64/);
  assert.match(snapshot, /MaxIdentityBytes\s*=\s*255/);
  assert.match(snapshot, /MaxTotalIdentityBytes/);
  assert.match(snapshot, /FixedTimeEquals/);
  assert.match(compiler, /MihomoPolicyCompiler\.Compile/);
  assert.match(policyCompiler, /input\.ApplicationPolicy/);
  assert.match(policyCompiler, /PROCESS-NAME/);
  for (const marker of ['app_policy_snapshot', 'app_policy_digest', 'app_policy_generation']) {
    assert.match(pkg, new RegExp(marker));
    assert.match(service, new RegExp(marker));
  }
  assert.match(pkg, /ApplicationPolicyDigest/);
  assert.match(pkg, /ApplicationPolicyGeneration/);
  assert.match(client, /ApplicationPolicySnapshot/);
  assert.match(client, /snapshot\.Digest/);
  assert.match(client, /snapshot\.Generation/);
  assert.match(uiViewModel, /ApplicationPolicySnapshot\.Create/);
  assert.match(uiViewModel, /PrepareSignedPackageAsync[\s\S]*snapshot/);
  assert.match(service, /resolved\.ApplicationPolicyDigest/);
  assert.match(service, /resolved\.ApplicationPolicyGeneration/);
  assert.match(service, /NetworkBoundaryIntent\([^)]*PolicyDigest/);
  assert.match(contract, /action = "stage_config"/);
  assert.match(contract, /signed_config_json/);
  assert.match(contract, /signed_envelope_json/);
  assert.match(contract, /config_content_digest/);
  assert.doesNotMatch(contract, /sing_box_base64|xray_base64/);
  assert.match(service, /IsTrustedStageClient/);
  assert.match(service, /GetNamedPipeClientProcessId/);
  assert.match(service, /HaveSameSha256\(actual, expected\)/);
  assert.match(service, /CryptographicOperations\.FixedTimeEquals\(actualHash, expectedHash\)/);
  assert.match(service, /FileAttributes\.ReparsePoint \| FileAttributes\.Directory/);
  assert.match(service, /SignedClientPackageImporter\.Import/);
  assert.match(signedImporter, /ConfigKeyTrust\.Verify/);
  assert.match(signedImporter, /ClientPackageStager\.Stage/);
  assert.match(signedImporter, /MihomoConfigCompiler\.Compile/);
  assert.doesNotMatch(signedImporter, /BuildSingBox|BuildXray|BIFROST_LEGACY_WINDOWS_CORES/);
  assert.match(pkg, /main_sha256/);
  assert.match(pkg, /provider_sha256/);
  assert.doesNotMatch(pkg, /sing_box_sha256|xray_sha256/);
  assert.match(signedImporter, /BF-CONFIG-ANTI-ROLLBACK/);
  assert.doesNotMatch(contract, /sing_box_config_b64|xray_config_b64|sing_box_base64|xray_base64/);
});

test('R63-POLICY-04 fixture executes the production contract with the locked SDK', () => {
  const lockedSdk = process.env.BIFROST_DOTNET?.trim()
    ? path.resolve(process.env.BIFROST_DOTNET.trim())
    : path.resolve(root, '..', '..', 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  assert.ok(fs.existsSync(lockedSdk), `locked dotnet SDK missing: ${lockedSdk}`);
  const project = path.join(root, 'tests', 'windows-service-contract-fixture', 'windows-service-contract-fixture.csproj');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-service-root-'));
  try {
    // This seed is TEST-ONLY and is mirrored by the compiled fixture.  The
    // production service receives only the public descriptor through the
    // normal build-time root provisioning target.
    const seed = Buffer.alloc(32, 0x42);
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    const publicKey = createPublicKey(privateKey);
    const publicDer = publicKey.export({ type: 'spki', format: 'der' });
    const rootFile = path.join(temp, 'release-root.json');
    fs.writeFileSync(rootFile, JSON.stringify({
      key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519',
      public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }),
      fingerprint: createHash('sha256').update(publicDer).digest('hex'),
    }) + '\n', 'utf8');
    const result = spawnSync(
      lockedSdk,
      ['run', '--project', project, '-c', 'Debug', '--no-restore',
        `-p:BifrostReleaseTrustRootFile=${rootFile}`, '-p:BifrostReleaseTrustRootTestOnly=true'],
      { cwd: root, encoding: 'utf8', timeout: 180000, maxBuffer: 8 * 1024 * 1024 },
    );
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    assert.equal(result.error, undefined, result.error?.message ?? output);
    assert.equal(result.status, 0, output);
    assert.match(output, /WINDOWS-MIHOMO-SERVICE-CONTRACT PASS/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
