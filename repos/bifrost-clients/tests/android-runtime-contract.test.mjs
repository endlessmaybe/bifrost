import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import os from 'node:os';

const root = path.resolve(import.meta.dirname, '..');
const app = path.join(root, 'android-app');

test('Android control startup does not load native networking before a VPN worker needs it', () => {
  const main = path.join(app, 'src/main/java/com/bifrost/client');
  const application = fs.readFileSync(path.join(main, 'BifrostApplication.kt'), 'utf8');
  const startup = application.slice(application.indexOf('override fun onCreate()'), application.indexOf('@Synchronized'));
  assert.doesNotMatch(startup, /Libbox\.|SetupOptions|ensureLibboxInitialized/);
  assert.match(application, /if \(libboxInitialized\) return/);
  assert.ok(application.indexOf('libboxInitialized = true') > application.indexOf('Libbox.setup('));
  const adapter = fs.readFileSync(path.join(main, 'BifrostCoreAdapter.kt'), 'utf8');
  for (const [begin, end, native] of [
    ['fun prepareXray(', 'fun prepareXray(config:', 'Libbox.setXraySocketProtector'],
    ['fun start(', 'fun applicationPolicyReadback(', 'Libbox.newCommandServer'],
  ]) {
    const entry = adapter.slice(adapter.indexOf(begin), adapter.indexOf(end));
    assert.ok(entry.indexOf('ensureLibboxInitialized()') >= 0);
    assert.ok(entry.indexOf('ensureLibboxInitialized()') < entry.indexOf(native));
  }
});

test('Android can select a measured winner before startup health completes', () => {
  const adapter = fs.readFileSync(path.join(app, 'src/main/java/com/bifrost/client/BifrostCoreAdapter.kt'), 'utf8');
  const start = adapter.slice(adapter.indexOf('server.startOrReloadService(runtimeConfig'));
  const observer = start.indexOf('startTrafficObserver(runtimeConfig)');
  const health = start.indexOf('health.check(');
  assert.ok(observer >= 0 && observer < health, 'partial results must reach selection before the first-candidate health gate');
  const observerSetup = adapter.slice(adapter.indexOf('private fun startTrafficObserver('), adapter.indexOf('@Synchronized fun isReady()'));
  assert.match(observerSetup, /trafficObserver\.start\(config,/);
  const refresh = adapter.slice(adapter.indexOf('internal fun refreshOutboundHealth()'), adapter.indexOf('/** libbox invokes'));
  assert.match(refresh, /trafficObserver\.refreshOutboundHealth\(\)/);
  assert.doesNotMatch(refresh, /\.urlTest\("(?:proxy|front-vmess)"\)/, 'outer selectors must not launch duplicate all-node sweeps');
});

test('Android node refresh and updater preserve the working system route with physical recovery', () => {
  const main = path.join(app, 'src/main/java/com/bifrost/client');
  const network = fs.readFileSync(path.join(main, 'BifrostUnderlyingNetwork.kt'), 'utf8');
  assert.match(network, /NET_CAPABILITY_NOT_VPN/);
  assert.match(network, /network\?\.openConnection\(url, Proxy\.NO_PROXY\)/);
  assert.match(network, /system = \{ url\.openConnection\(Proxy\.NO_PROXY\)/);
  assert.match(network, /BifrostControlNetworkPolicy\.open/);
  for (const file of ['BifrostControlClient.kt', 'BifrostUpdateManager.kt']) {
    const code = fs.readFileSync(path.join(main, file), 'utf8');
    assert.match(code, /BifrostUnderlyingNetwork\.openControlConnection\(context, URL\(endpoint\)(?:, networkAttempt)?\)/);
    assert.doesNotMatch(code, /URL\(endpoint\)\.openConnection/);
  }
});

function zipEntries(file) {
  const javaHome = process.env.JAVA_HOME || 'C:\\Program Files\\Java\\jdk-17';
  const jar = path.join(javaHome, 'bin', 'jar.exe');
  return execFileSync(jar, ['tf', file], { encoding: 'utf8' }).split(/\r?\n/).filter(Boolean);
}

function nestedClassEntries(aar) {
  const javaHome = process.env.JAVA_HOME || 'C:\\Program Files\\Java\\jdk-17';
  const jar = path.join(javaHome, 'bin', 'jar.exe');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-aar-'));
  try {
    execFileSync(jar, ['xf', aar, 'classes.jar'], { cwd: dir });
    return execFileSync(jar, ['tf', path.join(dir, 'classes.jar')], { encoding: 'utf8' }).split(/\r?\n/).filter(Boolean);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('Android release runtime ships one unified libbox+Xray AAR for every ABI', () => {
  const aar = path.join(app, 'libs', 'libbox.aar');
  assert.ok(fs.statSync(aar).size > 150 * 1024 * 1024, 'unified libbox AAR must include the pinned Xray transport');
  const entries = zipEntries(aar);
  for (const abi of ['armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64']) {
    assert.ok(entries.includes(`jni/${abi}/libbox.so`), `missing libbox ${abi}`);
  }
  assert.ok(entries.includes('classes.jar'));
  const classes = nestedClassEntries(aar);
  assert.ok(classes.includes('io/nekohasekai/libbox/XrayEngine.class'));
  assert.ok(classes.includes('io/nekohasekai/libbox/XraySocketProtector.class'));
  assert.ok(!fs.existsSync(path.join(app, 'libs', 'xraymobile.aar')), 'a second gomobile runtime would conflict on go.Seq/libgojni');
  // The generated classes are checked from the AAR when the JDK jar tool is
  // available; source contracts below remain the deterministic fallback.
  assert.ok(entries.includes('classes.jar'));
});

test('Android mode scopes and application rules use real installed-package selections', () => {
  const policy = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'ApplicationPackagePolicy.kt'), 'utf8');
  const activity = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'MainActivity.kt'), 'utf8');
  const screen = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'ui', 'screens', 'BifrostAHomeScreen.kt'), 'utf8');
  const model = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'ui', 'model', 'BifrostUiModel.kt'), 'utf8');
  assert.match(policy, /fun selectable\(\): List<BifrostApplicationPackageOption>/);
  assert.match(policy, /getInstalledApplications/);
  assert.match(screen, /applicationOptions\.filter[\s\S]*applicationSearch/);
  assert.doesNotMatch(screen, /applicationOptions\.take\(/);
  assert.match(screen, /Checkbox\([\s\S]*option\.packageName in selected/);
  assert.match(model, /country = if \(event\.value == "smartgate"\) state\.country else "auto"/);
  assert.match(model, /is BifrostUiEvent\.Country -> state\.copy\(country = if \(state\.mode == "smartgate"\)/);
  assert.match(activity, /val smartGate = connectionSelection\.connectionType == BifrostConnectionType\.SMARTGATE/);
  assert.match(activity, /canonicalCountry = if \(smartGate\)[\s\S]*else "auto"/);
});

test('Android uses the unified libbox Xray bridge and cannot regress to app-home exec', () => {
  const source = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostCoreAdapter.kt'), 'utf8');
  assert.doesNotMatch(source, /--tun-fd|--ready-file|Os\.dup2/);
  assert.doesNotMatch(source, /ProcessBuilder|filesDir.*xray|xrayProcess|setExecutable/);
  assert.match(source, /core == "auto" \|\| core == "sing-box" \|\| core == "xray"/);
  assert.match(source, /Libbox\.newCommandServer/);
  assert.match(source, /startOrReloadService/);
  assert.match(source, /setXraySocketProtector/);
  const xray = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostXrayTransport.kt'), 'utf8');
  assert.match(xray, /Libbox\.newXrayEngine/);
  assert.doesNotMatch(xray, /com\.bifrost\.xraymobile|filesDir|ProcessBuilder/);
  const platform = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostLibboxPlatform.kt'), 'utf8');
  assert.match(platform, /VpnService/);
  assert.match(platform, /XraySocketProtector/);
  assert.match(platform, /vpn\.protect/);
  // Keep the VPN owner's sockets outside its own UID routing/filter rules.
  // Android forbids mixing allowed and disallowed application lists.
  const allowPolicy = platform.slice(platform.indexOf('"allow" ->'), platform.indexOf('"exclude" ->'));
  const excludePolicy = platform.slice(platform.indexOf('"exclude" ->'), platform.indexOf('"none" ->'));
  assert.match(allowPolicy, /addPackages\(builder, bindings, allow = true\)/);
  assert.doesNotMatch(allowPolicy, /addDisallowedApplication/);
  assert.match(excludePolicy, /addDisallowedApplication\(vpn\.packageName\)/);
  assert.match(excludePolicy, /addPackages\(builder, bindings, allow = false\)/);
  assert.match(platform, /"none" -> builder\.addDisallowedApplication\(vpn\.packageName\)/);
  const activity = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'MainActivity.kt'), 'utf8');
  assert.match(activity, /(?:selectedCore|core).*xray|["']xray["']/i);
  const store = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostConfigStore.kt'), 'utf8');
  assert.match(store, /xray/);
  const bridge = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'scripts', 'libbox-xray-bridge.go'), 'utf8');
  assert.match(bridge, /RegisterDialerController/);
  assert.match(bridge, /Protect\(int64\(fd\)\)/);
  assert.doesNotMatch(bridge, /syscall\.Close\(int\(fd\)\)/, 'RawConn owns the descriptor; the controller must not double-close it');
  assert.match(bridge, /net\.Dialer\{Control: controller\}/);
  assert.match(bridge, /DialContext/);
  assert.match(bridge, /listener\.Accept/);
  assert.match(bridge, /func XrayProtectProbe\(\) bool/);
  assert.match(bridge, /protected/);
  assert.match(xray, /LOOPBACK_PORT\s*=\s*10808/);
  assert.doesNotMatch(xray, /ServerSocket|\.replace\(/, 'Xray port must come from the typed fixed-port contract');
  assert.match(source, /Libbox\.xrayProtectProbe\(\)/);
  const smoke = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'scripts', 'android-unified-runtime-smoke.ps1'), 'utf8');
  assert.match(smoke, /assembleAndroidTest/);
  assert.match(smoke, /am instrument/);
  assert.match(smoke, /No Android emulator\/device/);
  const instrumentation = fs.readFileSync(path.join(app, 'src', 'androidTest', 'java', 'com', 'bifrost', 'client', 'UnifiedRuntimeInstrumentedTest.kt'), 'utf8');
  assert.match(instrumentation, /xrayBindingCarriesTestOnlyLoopbackTraffic/);
  assert.match(instrumentation, /ServerSocket/);
  assert.match(instrumentation, /SOCKS5|0x05/);
  assert.match(instrumentation, /ping/);
  assert.match(instrumentation, /transport\.stop\(\)/);
});

test('Android candidate selection is source-scoped, budgeted, TLS-aware, and scheduled', () => {
  const selector = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostCandidateSelector.kt'), 'utf8');
  assert.match(selector, /REFRESH_INTERVAL_MS/);
  assert.match(selector, /MAX_PROBES\s*=\s*3/);
  assert.match(selector, /MAX_COHORTS_PER_ROUND\s*=\s*3/);
  assert.match(selector, /MAX_PROBE_BYTES/);
  assert.match(selector, /MAX_APPLICATION_PROBE_BYTES/);
  assert.match(selector, /MAX_TLS_HANDSHAKES_PER_ROUND/);
  assert.match(selector, /roundCohorts\([\s\S]*take\(MAX_COHORTS_PER_ROUND\)/);
  assert.match(selector, /sourceCode/);
  assert.match(selector, /networkSignature/);
  assert.match(selector, /jitter|loss|recentFailure|cooldown/i);
  assert.match(selector, /ProbeDescriptor/);
  assert.match(selector, /source\.optString\("ws_path"\)/);
  assert.match(selector, /transport\.optString\("host"\)/);
  assert.match(selector, /transport\.optString\("sni"\)/);
  assert.match(selector, /SSLSocket|startHandshake|TLS/i);
  assert.match(selector, /endpointIdentificationAlgorithm\s*=\s*"HTTPS"/);
  assert.doesNotMatch(selector, /port\s*==\s*443/);
  assert.match(selector, /ByteArray\(16\)|nextBytes/);
  assert.match(selector, /MessageDigest\.getInstance\("SHA-1"\)/);
  assert.match(selector, /Sec-WebSocket-Accept/);
  assert.match(selector, /webSocketProbe|Upgrade: websocket|Sec-WebSocket-Key/i);
  assert.match(selector, /Executors|ExecutorService|concurrent|parallel/i);
  assert.match(selector, /selected source|other source|source group|source/i);
  assert.match(selector, /probe_buckets_v3/);
  assert.doesNotMatch(selector, /probe_buckets_v2/);
  const coordinator = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostCandidateProbeCoordinator.kt'), 'utf8');
  assert.match(coordinator, /BifrostProbeLifecycleCoordinator/);
  assert.match(coordinator, /AndroidNetworkBucket\.observe/);
  assert.match(coordinator, /REFRESH_INTERVAL_MS/);
  assert.match(coordinator, /configVersion|configDigest|candidateFingerprint|transportFingerprint|generation/);
  assert.match(coordinator, /acquireLease/);
  assert.match(coordinator, /BifrostConfigStore\.load/);
  const vpn = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostVpnService.kt'), 'utf8');
  assert.doesNotMatch(vpn, /BifrostCandidateSelector\.select/);
  assert.match(vpn, /candidateProbeCoordinator\.acquireLease/);
  assert.match(vpn, /EXTRA_CANDIDATE/);
  assert.doesNotMatch(vpn, /scheduleWithFixedDelay\(\{\s*probe|selectorExecutor|probeRounds/s);
  const activity = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'MainActivity.kt'), 'utf8');
  assert.match(activity, /onStart\(\)/);
  assert.match(activity, /candidateProbeCoordinator\.acquireLease/);
  assert.doesNotMatch(activity, /BifrostProbeRoundController|probeExecutor|foregroundProbe/);
  assert.match(activity, /onStop\(\)/);
  assert.match(activity, /selectedSource.*A|selectedSource.*B/s);
});

test('Android update path is native, signed, and wired before connect', () => {
  const manager = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostUpdateManager.kt'), 'utf8');
  assert.match(manager, /manifest_text/);
  assert.match(manager, /com\.google\.crypto\.tink\.subtle\.Ed25519Verify/);
  assert.doesNotMatch(manager, /KeyFactory\.getInstance\("Ed25519"\)|Signature\.getInstance\("Ed25519"\)/);
  assert.match(manager, /release_sequence/);
  assert.match(manager, /MessageDigest\.getInstance\("SHA-256"\)/);
  assert.match(manager, /PackageInstaller/);
  assert.match(manager, /pending_sequence/);
  assert.match(manager, /STATUS_SUCCESS/);
  assert.match(manager, /STATUS_PENDING_USER_ACTION/);
  assert.match(manager, /EXTRA_INTENT/);
  assert.match(manager, /FLAG_ACTIVITY_NEW_TASK/);
  assert.match(manager, /platform/);
  assert.match(manager, /arch/);
  assert.match(manager, /kind/);
  assert.match(manager, /selectAndroidArtifacts/);
  assert.match(manager, /arch !in supported/);
  assert.match(manager, /BF-RELEASE-DUPLICATE-ABI/);
  assert.doesNotMatch(manager, /arch != "universal"/);
  assert.match(manager, /FileInputStream/);
  assert.match(manager, /MessageDigest/);
  assert.match(manager, /MAX_ARTIFACT_BYTES/);
  assert.match(manager, /requireSecureUrl/);
  assert.match(manager, /DUPLICATE-PATH/);
  assert.doesNotMatch(manager, /getSharedPreferences\("bifrost-control"/);
  assert.match(manager, /finalizePackageInstall/);
  assert.match(manager, /safeRelative/);
  assert.match(manager, /Build\.VERSION\.SDK_INT >= Build\.VERSION_CODES\.R/);
  assert.match(manager, /shouldAbandonLegacySession/);
  assert.match(manager, /pending_session_started_at/);
  assert.doesNotMatch(manager, /ProcessBuilder|Runtime\.getRuntime\(\)\.exec/);
  const cleanupTest = fs.readFileSync(path.join(app, 'src', 'test', 'java', 'com', 'bifrost', 'client', 'BifrostUpdateCleanupTest.kt'), 'utf8');
  assert.match(cleanupTest, /api28/);
  assert.match(cleanupTest, /api29/);
  const activity = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'MainActivity.kt'), 'utf8');
  assert.match(activity, /BifrostUpdateManager/);
  assert.match(activity, /updates\.checkAndStage\(stageArtifacts = (?:false|install)\)/);
  const manifest = fs.readFileSync(path.join(app, 'src', 'main', 'AndroidManifest.xml'), 'utf8');
  assert.match(manifest, /android\.permission\.ACCESS_NETWORK_STATE/);
  assert.match(manifest, /UpdateInstallReceiver/);
  assert.match(manifest, /REQUEST_INSTALL_PACKAGES/);
  assert.match(manifest, /android:icon="@mipmap\/ic_launcher"/);
  const launcher = path.join(app, 'src', 'main', 'res', 'mipmap-anydpi', 'ic_launcher.xml');
  assert.match(fs.readFileSync(launcher, 'utf8'), /adaptive-icon/);
  assert.match(fs.readFileSync(launcher, 'utf8'), /monochrome/);
  assert.equal(fs.existsSync(path.join(app, 'src', 'main', 'res', 'mipmap-anydpi-v26', 'ic_launcher.xml')), false);
  assert.ok(fs.existsSync(path.join(app, 'src', 'main', 'res', 'drawable', 'ic_bifrost_notification.xml')));
  const secure = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostSecureStore.kt'), 'utf8');
  assert.match(secure, /EncryptedSharedPreferences/);
  assert.match(secure, /MasterKey/);
  assert.match(secure, /legacy/);
  const gradle = fs.readFileSync(path.join(app, 'build.gradle.kts'), 'utf8');
  assert.match(gradle, /com\.google\.crypto\.tink:tink-android:1\.8\.0/);
  assert.match(gradle, /isUniversalApk = false/);
  for (const abi of ['armeabi-v7a', 'arm64-v8a', 'x86_64']) assert.match(gradle, new RegExp(abi));
  const buildScript = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'scripts', 'build-clients.ps1'), 'utf8');
  assert.match(buildScript, /androidAbis/);
  assert.doesNotMatch(buildScript, /outputs\\apk\\release.*Select-Object -First 1/);
  assert.match(buildScript, /BifrostAndroid-\$abi-release\.apk/);
  assert.match(buildScript, /Production client build is fail-closed/);
  assert.match(buildScript, /Ensure-ProductionControlOrigin/);
  assert.match(buildScript, /BIFROST_CONTROL_BASE_URL must be the canonical public HTTPS client-edge origin/);
  assert.match(buildScript, /Ensure-ReleaseTrustRoot/);
  assert.match(buildScript, /BIFROST_RELEASE_TRUST_ROOT_FILE/);
  assert.match(buildScript, /-PreleaseTrustRootFile=\$releaseTrustRoot/);
  assert.match(buildScript, /BifrostTrustedControlOrigin=\$productionControlOrigin/);
  assert.match(buildScript, /BifrostRequireTrustedControlOrigin=true/);
  assert.match(buildScript, /verify-key[^\n]*--root-public-key-file[^\n]*\$releaseTrustRoot/);
  assert.match(buildScript, /'create'[^\n]*'--root-public-key-file'[^\n]*\$releaseTrustRoot/);
  assert.match(buildScript, /'verify'[^\n]*'--root-public-key-file'[^\n]*\$releaseTrustRoot/);
  assert.match(buildScript, /PSIsContainer[^\n]*Android-\[0-9\]/, 'Windows release pre-clean must preserve independent Android delivery directories');
  const resumeWindows = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'scripts', 'resume-windows-release-packaging.ps1'), 'utf8');
  const cleanRelease = fs.readFileSync(path.join(root, '..', 'bifrost-infra', 'scripts', 'clean-release-artifacts.ps1'), 'utf8');
  assert.match(resumeWindows, /PSIsContainer[^\n]*Android-\[0-9\]/, 'Windows packaging resume must preserve independent Android delivery directories');
  assert.match(cleanRelease, /PSIsContainer[^\n]*Android-\[0-9\]/, 'Windows canonical cleanup must preserve independent Android delivery directories');
  for (const variable of ['BIFROST_ANDROID_KEYSTORE', 'BIFROST_ANDROID_KEYSTORE_PASSWORD', 'BIFROST_ANDROID_KEY_ALIAS', 'BIFROST_ANDROID_KEY_PASSWORD']) {
    assert.match(buildScript, new RegExp(variable));
  }
  assert.doesNotMatch(buildScript, /androidLocalKeystore|androidLocalPassword|keytool .*genkey/i);
});

test('Android control-plane vertical slice uses secure enrollment, sessions, and last-good config', () => {
  const control = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostControlClient.kt'), 'utf8');
  for (const endpoint of ['/v1/enrollment/redeem', '/v1/recovery/rotate', '/v1/recovery/delivery', '/v1/pairing/create', '/v1/pairing/redeem', '/v1/device/challenge', '/v1/device/session', '/v1/config/manifest', '/v1/config/packages/', '/v1/device/logout']) {
    assert.match(control, new RegExp(endpoint.replace(/[/.]/g, '\\$&')));
  }
  assert.match(control, /requestDigest/);
  assert.match(control, /"method", "GET"/);
  assert.match(control, /"path", "\/v1\/config\/manifest"/);
  assert.match(control, /DeviceKeys\.sign/);
  assert.match(control, /X25519/);
  assert.match(control, /HKDF|hkdf/i);
  assert.match(control, /AES\/GCM|AES-GCM/);
  assert.match(control, /BifrostConfigStore\.save/);
  assert.match(control, /anti_rollback/);
  assert.match(control, /config_signing_public_key/);
  assert.match(control, /createPairing/);
  assert.match(control, /redeemPairing/);
  const crossPlatformRecovery = control.slice(control.indexOf('fun recover('), control.indexOf('fun savedRecoveryCode('));
  assert.match(crossPlatformRecovery, /enroll\(baseUrl, recoveryCode\)/, 'recovery codes must use immediate cross-platform activation');
  assert.doesNotMatch(crossPlatformRecovery, /recovery\/request|pending|publicId/, 'activating the other platform does not require an account ID or approval');
  assert.match(control, /"account_recovery_code" to recovery\.takeIf/);
  assert.match(control, /recoveryEnvelope = result\.optJSONObject\("recovery_delivery"\)/, 'cross-platform activation must accept an enrollment response without a replacement recovery delivery');
  assert.match(control, /recoveryEnvelope == null\) "" else decryptRecoveryDelivery/, 'a reused account activation code must not force recovery-code rotation');
  const settingsScreen = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'ui', 'screens', 'BifrostSettingsScreen.kt'), 'utf8');
  assert.match(settingsScreen, /normalizedValue\.startsWith\("PAIR-", ignoreCase = true\)/, 'Android must distinguish temporary pairing codes from account recovery codes');
  assert.match(settingsScreen, /!normalizedValue\.startsWith\("PAIR-", ignoreCase = true\)/, 'the pairing tab must reject non-pairing credentials before submission');
  assert.match(settingsScreen, /mismatchMessage\.isBlank\(\)/, 'credential-type mismatch must disable activation instead of sending the wrong endpoint');
  // Recovery delivery must stay on the generated wrapper contract all the way
  // into the real client parser: parseResponse runs the generated validator,
  // then the client reads config_version and the nested sealed envelope.
  assert.match(control, /parseResponse\(response, "BF-RECOVERY-DELIVERY"\)/);
  assert.match(control, /strictLongField\(result, "config_version", "BF-RECOVERY-DELIVERY"\)/);
  assert.match(control, /result\.optJSONObject\("recovery_delivery"\)/);
  const keys = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'DeviceKeys.kt'), 'utf8');
  assert.match(keys, /Ed25519Sign/);
  assert.match(keys, /X25519/);
  assert.match(keys, /BifrostSecureStore/);
  assert.match(keys, /deriveEncryptionSharedSecret/);
  assert.doesNotMatch(keys, /fun\s+encryptionPrivateKey\s*\(/, 'production device identity must not export long-lived X25519 private bytes');
  assert.doesNotMatch(control, /DeviceKeys\.encryptionPrivateKey\s*\(/, 'control client must use the device-key agreement boundary');
  const compiler = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostConfigCompiler.kt'), 'utf8');
  assert.match(compiler, /source/);
  assert.match(compiler, /country/);
  assert.match(compiler, /routing/);
  assert.match(compiler, /httpsDnsServer\(remoteDns, "remote-dns", finalTag, null\)/);
  assert.match(compiler, /httpsDnsServer\(directDns, "direct-dns", "direct", "remote-dns"\)/);
  assert.match(compiler, /if \(domainResolver != null\)/);
  const vpn = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostVpnService.kt'), 'utf8');
  const runtimeCoordinator = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostRuntimeCoordinator.kt'), 'utf8');
  assert.match(vpn, /BifrostConfigCompiler/);
  const transaction = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostConnectionTransaction.kt'), 'utf8');
  assert.match(vpn, /BifrostConnectionTransaction\(runtime, ProductionBifrostCorePort\(core\)\)/);
  assert.match(transaction, /runtime\.starting\(\)/);
  assert.match(transaction, /runtime\.coreReady\(\)/);
  assert.match(transaction, /applicationPolicy\.digest/);
  assert.match(transaction, /BF-APP-POLICY-READBACK/);
  assert.match(vpn, /EXTRA_SOURCE/);
  assert.match(vpn, /BifrostLeakBoundary/);
  assert.match(vpn, /runtime\.coreFailure\(\)/);
  assert.match(runtimeCoordinator, /coreFailed/);
  assert.match(vpn, /onCoreServiceStop/);
  assert.match(vpn, /coreFailureHandling/);
  assert.match(vpn, /AndroidBlackholeController/);
  assert.match(vpn, /onRevoke/);
  assert.match(runtimeCoordinator, /boundary\.destroyed/);
  assert.match(vpn, /scheduleHealthMonitor/);
  const activity = fs.readFileSync(path.join(app, 'src', 'main', 'java', 'com', 'bifrost', 'client', 'MainActivity.kt'), 'utf8');
  assert.match(activity, /enroll/);
  assert.match(activity, /recoveryCode\.isNotBlank\(\)[\s\S]*crossPlatformActivationSuccess/, 'Android UI must distinguish first-account enrollment from same-code cross-platform binding');
  assert.match(activity, /refresh/);
  assert.match(activity, /sourceOptions|availableSources/);
  assert.match(activity, /countryOptions|availableCountries/);
  assert.match(activity, /EXTRA_SOURCE/);
  assert.match(activity, /EXTRA_COUNTRY/);
});
