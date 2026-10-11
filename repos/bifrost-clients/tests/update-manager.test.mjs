import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { parseReleaseEnvelope, readSequence, stageRelease, verifyArtifact, writeReleaseState, releaseStateChecksum, writeSequence } from '../release/update-manager.mjs';
import { verifyFixtureRelease } from './release-fixture-adapter.mjs';

const root = path.resolve(import.meta.dirname, '..');
process.env.BIFROST_TEST_LEGACY_FIXTURE = '1';
const installableWindowsKinds = new Set(['exe', 'service-exe', 'installer', 'core', 'core-manifest', 'metadata']);
const installableWindowsArtifacts = (manifest) => manifest.build.artifacts.filter((artifact) =>
  artifact.platform === 'windows' && artifact.arch === 'x64' && installableWindowsKinds.has(artifact.kind));

// Installer behavior tests use real current Windows artifact bytes, but a
// dedicated TEST-ONLY manifest/key.  Never couple lifecycle tests to the
// operator-signed releases manifest: local client iteration may replace a
// build artifact before the next production signing ceremony, and that must
// not turn rollback/SCM tests into unrelated artifact-size failures.
let installerReleaseFixture = null;
function testReleaseRoot() {
  if (installerReleaseFixture) return installerReleaseFixture;
  const umbrella = path.resolve(root, '..', '..');
  const source = path.join(umbrella, 'releases');
  let activeSource = source;
  const currentPath = path.join(source, 'current.json');
  if (existsSync(currentPath)) {
    const pointer = JSON.parse(readFileSync(currentPath, 'utf8'));
    if (pointer?.format !== 'BIFROST-RELEASE-CURRENT-1' ||
        typeof pointer.generation !== 'string' ||
        !/^[A-Za-z0-9._-]{1,128}$/.test(pointer.generation))
      throw new Error('invalid active release pointer');
    activeSource = path.join(source, 'generations', pointer.generation);
  }
  const fixtureRoot = mkdtempSync(path.join(umbrella, 'build-work', 'installer-test-release-'));
  const manifest = JSON.parse(readFileSync(path.join(activeSource, 'RELEASE-MANIFEST.json'), 'utf8'));
  for (const artifact of manifest.build.artifacts) {
    if (artifact.platform !== 'windows' || artifact.arch !== 'x64') continue;
    const sourceFile = path.join(activeSource, artifact.path);
    const destination = path.join(fixtureRoot, artifact.path);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(sourceFile, destination);
    const bytes = readFileSync(destination);
    artifact.bytes = bytes.length;
    artifact.sha256 = createHash('sha256').update(bytes).digest('hex');
  }
  // The installed operator generation may predate the Mihomo geodata
  // expansion.  Lifecycle tests construct the current exact eight-artifact
  // Windows contract using the pinned official rule assets instead of
  // perpetuating an old release shape.
  const geodataRoot = path.join(umbrella, 'build-work', 'toolchains', 'cores', 'mihomo-rules', '2026-09-22');
  for (const [id, file, installPath] of [['geosite', 'geosite.dat', 'cores/GeoSite.dat'], ['geoip', 'geoip.metadb', 'cores/geoip.metadb']]) {
    if (manifest.build.artifacts.some((artifact) => artifact.id === id)) continue;
    const sourceFile = path.join(geodataRoot, file);
    const artifactPath = `windows-service/test-fixture/${file}`;
    const destination = path.join(fixtureRoot, artifactPath);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(sourceFile, destination);
    const bytes = readFileSync(destination);
    manifest.build.artifacts.push({ id, path: artifactPath, install_path: installPath, platform: 'windows', arch: 'x64', kind: 'core', bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), source_bundle: 'bifrost-release-source', notice: 'bifrost-release-notice', dependencies: [] });
  }
  const pair = generateKeyPairSync('ed25519');
  const manifestText = JSON.stringify(manifest);
  const signature = sign(null, Buffer.from(manifestText, 'utf8'), pair.privateKey).toString('base64url');
  const publicKeyPath = path.join(fixtureRoot, 'release-signing-public.pem');
  writeFileSync(path.join(fixtureRoot, 'RELEASE-MANIFEST.json'), manifestText, 'utf8');
  writeFileSync(path.join(fixtureRoot, 'RELEASE-MANIFEST.sig'), `${signature}\n`, 'utf8');
  writeFileSync(publicKeyPath, pair.publicKey.export({ type: 'spki', format: 'pem' }), 'utf8');
  process.env.BIFROST_TEST_RELEASE_PUBLIC_KEY_FILE = publicKeyPath;
  installerReleaseFixture = fixtureRoot;
  return fixtureRoot;
}
after(() => {
  if (installerReleaseFixture) rmSync(installerReleaseFixture, { recursive: true, force: true });
});

// Behavior gates build an explicitly test-only installer harness.  The
// shipping Release build is intentionally compiled without BIFROST_TEST_HARNESS
// and therefore contains no compact/raw-key verifier.
let setupHarnessReady = false;
function compiledSetupDll() {
  const configured = process.env.BIFROST_SETUP_DLL;
  if (configured) return path.resolve(configured);
  const output = path.resolve(root, '..', 'bifrost-infra', 'installer', 'bin', 'Debug', 'net10.0-windows', 'win-x64', 'BifrostSetup.dll');
  if (!setupHarnessReady) {
    const umbrella = path.resolve(root, '..', '..');
    const dotnet = path.join(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
    const project = path.join(umbrella, 'repos', 'bifrost-infra', 'installer', 'BifrostSetup.csproj');
    const build = spawnSync(dotnet, ['build', project, '-c', 'Debug', '--no-restore', '-t:Rebuild', '-p:RuntimeIdentifier=win-x64', '-p:BifrostTestHarness=true'], { encoding: 'utf8', timeout: 180000 });
    if (build.status !== 0) throw new Error(`test-only setup harness build failed: ${build.stderr || build.stdout}`);
    setupHarnessReady = true;
  }
  return output;
}

function compiledSetupApphost() {
  compiledSetupDll();
  return path.resolve(root, '..', 'bifrost-infra', 'installer', 'bin', 'Debug', 'net10.0-windows', 'win-x64', 'BifrostSetup.exe');
}

function sleepSync(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function dotnetTimestamp() {
  return new Date().toISOString().replace(/\.(\d{3})Z$/, (_, milliseconds) => `.${milliseconds}0000Z`);
}

function powershellExecutable() {
  const candidates = [
    process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe') : null,
    'powershell.exe'
  ].filter(Boolean);
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'], { encoding: 'utf8' });
    if (probe.status === 0) return candidate;
  }
  throw new Error('Windows PowerShell is required for the script behavior gate');
}

function fixture(sequence = 7) {
  const bytes = Buffer.from('Bifrost release fixture');
  const manifest = { format: 'BIFROST-RELEASE-MANIFEST-2', release_sequence: sequence, signing_algorithm: 'Ed25519', build: { artifact_root: 'releases', artifacts: [{ path: 'windows/Bifrost.exe', install_path: 'windows/Bifrost.exe', platform: 'windows', arch: 'x64', kind: 'exe', bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }] } };
  const pair = generateKeyPairSync('ed25519');
  const text = JSON.stringify(manifest);
  return { bytes, manifest, manifestText: text, signatureText: sign(null, Buffer.from(text), pair.privateKey).toString('base64url'), publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }), testOnly: true };
}

test('release envelope verifies signature, sequence, relative paths, and artifact digest', async () => {
  const item = fixture();
  const envelope = verifyFixtureRelease(item);
  assert.equal(envelope.sequence, 7);
  assert.deepEqual(verifyArtifact(item.bytes, item.manifest.build.artifacts[0]), item.bytes);
  assert.throws(() => verifyFixtureRelease({ ...item, previousSequence: 7 }), /rollback/i);
  assert.throws(() => verifyArtifact(Buffer.from('tampered'), item.manifest.build.artifacts[0]), /size|digest/);
  const traversal = { ...item, manifestText: item.manifestText.replace('windows/Bifrost.exe', '../escape') };
  assert.throws(() => verifyFixtureRelease(traversal), /signature invalid|escapes|BF-RELEASE-PATH/);
});

test('release envelope permits a direct upgrade across arbitrarily skipped versions', () => {
  const item = fixture(1_000_007);
  const envelope = verifyFixtureRelease({ ...item, previousSequence: 7 });
  assert.equal(envelope.sequence, 1_000_007);
  assert.equal(envelope.idempotent, false);
});

test('release envelope is exact and rejects duplicate, unknown, missing, and non-canonical fields', () => {
  const item = fixture();
  const envelopeText = JSON.stringify({ manifest_text: item.manifestText, signature: item.signatureText });
  assert.throws(() => parseReleaseEnvelope(envelopeText), /FIELDS|ENVELOPE|TRUST-ROOT/);
  assert.throws(() => parseReleaseEnvelope('{"manifest_text":"x","manifest_text":"y","signature":"x"}'), /duplicate/);
  assert.throws(() => parseReleaseEnvelope('{"manifest_text":"x","signature":"x","extra":1}'), /schema|FIELDS/);
  assert.throws(() => parseReleaseEnvelope('{"manifest_text":"x"}'), /schema|FIELDS/);
  assert.throws(() => parseReleaseEnvelope(`${envelopeText} trailing`), /trailing|FIELDS|JSON/);
  const tamperedSignature = `${item.signatureText[0] === 'A' ? 'B' : 'A'}${item.signatureText.slice(1)}`;
  assert.throws(() => verifyFixtureRelease({ ...item, signatureText: tamperedSignature }), /signature invalid|BF-RELEASE-SIGNATURE/);
  const collision = { ...item, manifestText: item.manifestText.replace('windows/Bifrost.exe', 'windows/bifrost.exe'), signatureText: tamperedSignature };
  assert.throws(() => verifyFixtureRelease(collision), /signature invalid|BF-RELEASE-/);
});

test('corrupt or truncated release sequence fails closed', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'bifrost-sequence-'));
  const state = path.join(dir, 'state.json');
  try {
    assert.equal(readSequence(state), 0);
    writeSequence(state, 3);
    assert.equal(readSequence(state), 3);
    writeFileSync(state, '{"last_sequence":');
    assert.throws(() => readSequence(state), /BF-RELEASE-STATE-CORRUPT/);
    writeFileSync(state, '{"last_sequence":1,"extra":2}');
    assert.throws(() => readSequence(state), /BF-RELEASE-STATE-CORRUPT/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('release staging is atomic and keeps a recoverable backup', async () => {
  const item = fixture();
  const envelope = verifyFixtureRelease(item);
  const root = mkdtempSync(path.join(os.tmpdir(), 'bifrost-release-'));
  const installRoot = path.join(root, 'current');
  const old = path.join(installRoot, 'windows');
  const { mkdirSync, writeFileSync } = await import('node:fs');
  mkdirSync(old, { recursive: true }); writeFileSync(path.join(old, 'Bifrost.exe'), 'old');
  try {
    const statePath = path.join(root, 'state.json');
    const previousState = { last_sequence: 0, last_manifest_digest: '0'.repeat(64), envelope_digest: '0'.repeat(64), authority_digest: envelope.plan.authority_digest, authority_generation: envelope.plan.authority_generation, root_key_id: envelope.plan.root_key_id, root_fingerprint: envelope.plan.root_fingerprint, delegation_generation: envelope.plan.delegation_generation, key_id: envelope.plan.signing_key_id, signing_key_fingerprint: envelope.plan.signing_key_fingerprint, channel: envelope.plan.channel, floor: 1, state_generation: 1, slot: 'b', state_checksum: '', updated_at: new Date().toISOString() };
    previousState.state_checksum = releaseStateChecksum(previousState);
    writeReleaseState(statePath, previousState);
    const result = await stageRelease({ plan: envelope.plan, envelopeBytes: envelope.envelope_bytes, installRoot, statePath, fetchArtifact: async () => item.bytes });
    assert.equal(readFileSync(path.join(installRoot, 'windows', 'Bifrost.exe')).toString(), item.bytes.toString());
    assert.equal(readFileSync(path.join(result.backup, 'windows', 'Bifrost.exe')).toString(), 'old');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('compiled trusted Windows setup rejects tainted pending state without writing', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  assert.ok(existsSync(setup), 'trusted setup must be built before the behavior gate');
  assert.ok(existsSync(dotnet), 'locked dotnet toolchain must be available');
  const sourceReleases = testReleaseRoot();
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-behavior-'));
  const installRoot = path.join(temp, 'install');
  const packageRoot = path.join(temp, 'package');
  const updateRoot = path.join(temp, 'updates');
  const outside = path.join(temp, 'outside-stage');
  try {
    mkdirSync(installRoot, { recursive: true });
    mkdirSync(packageRoot, { recursive: true });
    mkdirSync(updateRoot, { recursive: true });
    writeFileSync(path.join(packageRoot, 'RELEASE-MANIFEST.json'), manifestText);
    writeFileSync(path.join(packageRoot, 'RELEASE-MANIFEST.sig'), signature);
    writeFileSync(path.join(updateRoot, 'update-pending.json'), JSON.stringify({ manifest_text: manifestText, signature, stage_directory: outside }));
    const tainted = spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--what-if'], { encoding: 'utf8', cwd: path.dirname(setup) });
    assert.notEqual(tainted.status, 0, 'outside stage must be rejected by the compiled setup');
    assert.equal(existsSync(path.join(installRoot, '.bifrost-state', 'update-state.json')), false);
    writeFileSync(path.join(updateRoot, 'update-pending.json'), JSON.stringify({ manifest_text: manifestText, signature: `${signature.slice(0, -1)}A`, stage_directory: path.join(updateRoot, 'stage') }));
    const wrongPin = spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--what-if'], { encoding: 'utf8', cwd: path.dirname(setup) });
    assert.notEqual(wrongPin.status, 0, 'tampered signature must be rejected by the compiled setup');
    assert.equal(existsSync(path.join(installRoot, '.bifrost-state', 'update-state.json')), false);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('compiled trusted setup enforces sequence, exact stage, rollback and success in a temp root', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  assert.ok(existsSync(setup), 'trusted setup must be built before the behavior gate');
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const manifest = JSON.parse(manifestText);
  const windows = installableWindowsArtifacts(manifest);
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-promotion-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const stage = path.join(updateRoot, 'stage');
  try {
    mkdirSync(stage, { recursive: true });
    for (const artifact of windows) {
      const source = path.join(sourceReleases, artifact.path);
      const destination = path.join(stage, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(destination), { recursive: true });
      cpSync(source, destination);
    }
    const markerPath = path.join(updateRoot, 'update-pending.json');
    const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
    const writeMarker = () => writeFileSync(markerPath, JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage }));
    const invoke = (...extra) => spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', ...extra], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });
    const invokeInstall = (...extra) => spawnSync(dotnet, [setup, '--install', '--package-root', sourceReleases, '--install-root', installRoot, '--update-root', updateRoot, '--test-root', ...extra], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });

    // The same durable authority is used by initial install and pending
    // promotion; an equal/older signed release cannot overwrite it.
    mkdirSync(path.dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify({ last_sequence: manifest.release_sequence, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
    assert.notEqual(invokeInstall('--what-if').status, 0, 'initial install must reject an old signed sequence');
    assert.notEqual(invoke('--what-if').status, 0, 'pending promotion must reject an old signed sequence');
    rmSync(statePath, { force: true });
    // A pending apply is never an initial install: deleting durable state
    // while an installed payload exists must fail closed rather than reset
    // the rollback floor to zero.
    mkdirSync(installRoot, { recursive: true });
    writeFileSync(path.join(installRoot, 'BifrostSetup.exe'), 'existing-installed-payload');
    assert.notEqual(invoke('--what-if').status, 0, 'pending apply must reject missing state with installed payload');
    writeFileSync(statePath, JSON.stringify({ last_sequence: manifest.release_sequence - 1, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));

    writeMarker();
    writeFileSync(path.join(stage, 'unexpected.bin'), 'extra');
    assert.notEqual(invoke('--what-if').status, 0, 'extra stage entries must be rejected');
    rmSync(path.join(stage, 'unexpected.bin'), { force: true });

    const firstArtifact = windows[0];
    const firstStagePath = path.join(stage, firstArtifact.install_path ?? firstArtifact.path);
    const originalFirst = readFileSync(firstStagePath);
    writeFileSync(firstStagePath, Buffer.from('tampered-stage-artifact'));
    assert.notEqual(invoke('--what-if').status, 0, 'replaced stage artifacts must be rejected');
    writeFileSync(firstStagePath, originalFirst);

    // Seed both old payloads and a running fake service. A post-promotion
    // start/health failure must restore every file, the service marker, and
    // leave the signed pending marker available for retry.
    for (const artifact of windows) {
      const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(installed), { recursive: true });
      writeFileSync(installed, Buffer.from(`old-${artifact.kind}`));
    }
    mkdirSync(updateRoot, { recursive: true });
    writeFileSync(path.join(updateRoot, 'service-lifecycle.marker'), 'running');
    // Earlier negative checks intentionally exercise cleanup.  Start the
    // behavior assertion from a clean event journal so the ordered rollback
    // trace cannot be masked by those expected failures.
    rmSync(path.join(updateRoot, 'service-lifecycle.events'), { force: true });
    writeMarker();
    const failed = invoke('--fake-service', 'health-fails');
    if (process.env.BIFROST_TEST_SETUP_TRACE === '1') process.stderr.write(`[setup-trace] ${failed.stderr || failed.stdout}\n`);
    assert.notEqual(failed.status, 0, `failure injection unexpectedly succeeded: ${failed.stderr || failed.stdout}`);
    assert.equal(existsSync(markerPath), true, 'failed promotion must retain pending marker');
    assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).last_sequence, manifest.release_sequence - 1, 'failed promotion must preserve durable state');
    assert.equal(readFileSync(path.join(updateRoot, 'service-lifecycle.marker'), 'utf8'), 'running', 'service must be restored');
    const healthFailureEvents = readFileSync(path.join(updateRoot, 'service-lifecycle.events'), 'utf8').trim().split(/\r?\n/);
    assert.deepEqual(
      healthFailureEvents.slice(0, 8),
      ['stop-old', 'promote', 'reconfigure', 'health', 'stop-new', 'restore-files', 'restore-state', 'start-old'],
      `rollback must reconfigure the registered service, restore files/state, then start old; setup=${failed.stderr || failed.stdout || '<no diagnostic>'}`
    );
    assert.deepEqual(healthFailureEvents.slice(-2), ['cleanup-backup', 'cleanup-protected'], 'rollback cleanup must run after service/file/state restoration');
    for (const artifact of windows) {
      const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
      assert.equal(readFileSync(installed, 'utf8'), `old-${artifact.kind}`, `rollback lost ${artifact.install_path}`);
    }

    const result = invoke('--fake-service', 'success');
    assert.equal(result.status, 0, `compiled promotion failed: ${result.stderr || result.stdout}`);
    assert.equal(existsSync(path.join(updateRoot, 'update-pending.json')), false);
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    assert.equal(state.last_sequence, manifest.release_sequence);
    assert.equal(readFileSync(path.join(updateRoot, 'service-lifecycle.marker'), 'utf8'), 'running');
    for (const artifact of windows) {
      const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
      assert.equal(existsSync(installed), true, `missing installed artifact ${artifact.install_path}`);
      assert.equal(readFileSync(installed).length, artifact.bytes);
      assert.equal(createHash('sha256').update(readFileSync(installed)).digest('hex'), artifact.sha256);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('compiled setup keeps the user-writable inbox separate from the protected install root', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-root-boundary-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(installRoot, 'updates');
  try {
    mkdirSync(installRoot, { recursive: true });
    const result = spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--what-if'], { encoding: 'utf8', cwd: path.dirname(setup) });
    assert.notEqual(result.status, 0, 'nested update/install roots must be rejected before any write');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('self-update helper derives the production inbox and only accepts an explicit test override in test mode', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const production = spawnSync(dotnet, [setup, '--test-helper-args'], { encoding: 'utf8', cwd: path.dirname(setup) });
  assert.equal(production.status, 0, production.stderr || production.stdout);
  const productionArgs = JSON.parse(production.stdout.trim());
  assert.equal(productionArgs.includes('--update-root'), false, 'production helper must derive the machine inbox');
  const testMode = spawnSync(dotnet, [setup, '--test-helper-args', '--test-root'], { encoding: 'utf8', cwd: path.dirname(setup) });
  assert.equal(testMode.status, 0, testMode.stderr || testMode.stdout);
  const testArgs = JSON.parse(testMode.stdout.trim());
  assert.equal(testArgs.includes('--update-root'), true, 'test helper seam may override the inbox');
  assert.equal(testArgs.includes('--test-root'), true);
});

test('compiled setup exposes standard-user ACL intent for inbox and protected state', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const run = (profile) => spawnSync(dotnet, [setup, '--test-acl-policy', '--profile', profile], { encoding: 'utf8', cwd: path.dirname(setup) });
  const inbox = JSON.parse(run('inbox').stdout.trim());
  const state = JSON.parse(run('state').stdout.trim());
  const users = rules => rules.find(rule => rule.principal === 'Users');
  assert.equal(users(inbox.rules).rights, 'Modify');
  assert.equal(users(state.rules).rights, 'ReadAndExecute');
  assert.equal(users(inbox.rules).access, 'Allow');
  assert.equal(users(state.rules).access, 'Allow');
  assert.equal(users(inbox.rules).inheritance, 'ContainerInherit,ObjectInherit');
  assert.equal(users(state.rules).inheritance, 'ContainerInherit,ObjectInherit');
  assert.equal(users(inbox.rules).propagation, 'None');
  assert.equal(users(state.rules).propagation, 'None');
  assert.doesNotMatch(users(state.rules).rights, /Write|Modify|Delete|ChangePermissions|TakeOwnership/);
  assert.equal(state.rules.find(rule => rule.principal === 'SYSTEM').rights, 'FullControl');
  assert.equal(state.rules.find(rule => rule.principal === 'Administrators').rights, 'FullControl');
  assert.equal(state.rules.find(rule => rule.principal === 'SYSTEM').access, 'Allow');
  assert.equal(state.rules.find(rule => rule.principal === 'Administrators').access, 'Allow');
});

test('compiled setup uses the production numeric SCM transition executor', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const run = states => spawnSync(dotnet, [setup, '--test-scm-transition', '--states', states], { encoding: 'utf8', cwd: path.dirname(setup) });
  const startPending = run('2,4,3,1');
  assert.equal(startPending.status, 0, startPending.stderr || startPending.stdout);
  assert.deepEqual(JSON.parse(startPending.stdout.trim()), { present: true, was_running: true, events: ['wait-running', 'stop', 'wait-stopped'] });
  const stopPending = run('3,1');
  assert.equal(stopPending.status, 0, stopPending.stderr || stopPending.stdout);
  assert.deepEqual(JSON.parse(stopPending.stdout.trim()), { present: true, was_running: false, events: ['wait-stopped'] });
  const running = run('4,3,1');
  assert.equal(running.status, 0, running.stderr || running.stdout);
  assert.deepEqual(JSON.parse(running.stdout.trim()), { present: true, was_running: true, events: ['stop', 'wait-stopped'] });
  const localized = spawnSync(dotnet, [setup, '--test-scm-parse', '--raw', 'TYPE        : 10  WIN32_OWN_PROCESS\r\n状态      : 4  本地化运行\r\n'], { encoding: 'utf8', cwd: path.dirname(setup) });
  assert.equal(localized.status, 0, localized.stderr || localized.stdout);
  assert.deepEqual(JSON.parse(localized.stdout.trim()), { state: 'Running' }, 'SCM parser must use numeric state, not localized labels');
  const localizedRaw = 'TYPE        : 10  WIN32_OWN_PROCESS\\r\\n状态      : 4  本地化运行\\r\\n';
  const validLocalizedRaw = ['TYPE        : 10  WIN32_OWN_PROCESS', String.fromCharCode(0x72B6, 0x6001) + '      : 4  ' + String.fromCharCode(0x672C, 0x5730, 0x5316, 0x8FD0, 0x884C), ''].join(String.fromCharCode(13, 10));
  const localizedUtf8 = spawnSync(dotnet, [setup, '--test-scm-parse', '--raw', validLocalizedRaw], { encoding: 'utf8', cwd: path.dirname(setup) });
  assert.equal(localizedUtf8.status, 0, localizedUtf8.stderr || localizedUtf8.stdout);
  assert.deepEqual(JSON.parse(localizedUtf8.stdout.trim()), { state: 'Running' }, 'numeric state must survive a real localized label');
  const absent = run('1060');
  assert.equal(absent.status, 0, absent.stderr || absent.stdout);
  assert.deepEqual(JSON.parse(absent.stdout.trim()), { present: false, was_running: false, events: [] });
  assert.notEqual(run('exit:5').status, 0, 'access-denied query must fail closed');
  assert.notEqual(run('2').status, 0, 'a non-progressing state must hit the bounded timeout');
  assert.notEqual(run('5').status, 0, 'unknown numeric state must fail closed');
});

test('compiled parent wait fails closed before promotion and has a deterministic timeout seam', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const completed = spawnSync(dotnet, [setup, '--test-parent-wait', '--outcome', 'exit'], { encoding: 'utf8', cwd: path.dirname(setup) });
  assert.equal(completed.status, 0, completed.stderr || completed.stdout);
  assert.deepEqual(JSON.parse(completed.stdout.trim()), { completed: true });
  const timedOut = spawnSync(dotnet, [setup, '--test-parent-wait', '--outcome', 'timeout'], { encoding: 'utf8', cwd: path.dirname(setup) });
  assert.notEqual(timedOut.status, 0, 'parent timeout must fail closed');

  const sourceReleases = testReleaseRoot();
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const manifest = JSON.parse(manifestText);
  const windows = installableWindowsArtifacts(manifest);
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-parent-timeout-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const stage = path.join(updateRoot, 'stage');
  const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
  const markerPath = path.join(updateRoot, 'update-pending.json');
  try {
    mkdirSync(stage, { recursive: true });
    mkdirSync(installRoot, { recursive: true });
    for (const artifact of windows) {
      const staged = path.join(stage, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(staged), { recursive: true });
      cpSync(path.join(sourceReleases, artifact.path), staged);
      const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(installed), { recursive: true });
      writeFileSync(installed, Buffer.from(`old-${artifact.kind}`));
    }
    mkdirSync(path.dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify({ last_sequence: manifest.release_sequence - 1, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
    writeFileSync(markerPath, JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage }));
    const result = spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--helper', '--fake-parent-wait', 'timeout', '--operation-nonce', 'parent-timeout', '--expected-sequence', String(manifest.release_sequence), '--fake-service', 'success'], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });
    assert.notEqual(result.status, 0, 'a helper parent timeout must stop before promotion');
    assert.equal(existsSync(markerPath), true, 'pending must remain retryable');
    assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).last_sequence, manifest.release_sequence - 1);
    const lifecycleEventsPath = path.join(updateRoot, 'service-lifecycle.events');
    if (existsSync(lifecycleEventsPath)) {
      const lifecycleEvents = readFileSync(lifecycleEventsPath, 'utf8').trim().split(/\r?\n/).filter(Boolean);
      assert.deepEqual(lifecycleEvents.filter(event => !event.startsWith('cleanup-')), [], 'service lifecycle must not start before parent exit');
    }
    for (const artifact of windows) {
      assert.equal(readFileSync(path.join(installRoot, artifact.install_path ?? artifact.path), 'utf8'), `old-${artifact.kind}`);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('compiled setup bounds stale helper bundles while preserving current and recent bundles', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-helper-cleanup-'));
  try {
    const current = path.join(temp, 'current');
    const recent = path.join(temp, 'recent');
    const stale = path.join(temp, 'stale');
    mkdirSync(current, { recursive: true }); mkdirSync(recent, { recursive: true }); mkdirSync(stale, { recursive: true });
    writeFileSync(path.join(current, 'BifrostSetup.exe'), 'current');
    writeFileSync(path.join(recent, 'BifrostSetup.exe'), 'recent');
    writeFileSync(path.join(stale, 'BifrostSetup.exe'), 'stale');
    const old = new Date('2020-01-01T00:00:00Z');
    utimesSync(stale, old, old);
    const result = spawnSync(dotnet, [setup, '--test-helper-cleanup', '--helper-root', temp, '--current-root', path.join(current, 'BifrostSetup.exe')], { encoding: 'utf8', cwd: path.dirname(setup) });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(existsSync(current), true);
    assert.equal(existsSync(recent), true);
    assert.equal(existsSync(stale), false);

    // Quantity bound: retain the current bundle and only the newest bounded
    // set; older siblings are pruned even when they are not yet seven days old.
    const bundles = [];
    for (let index = 0; index < 8; index++) {
      const bundle = path.join(temp, `bundle-${index}`);
      mkdirSync(bundle, { recursive: true });
      writeFileSync(path.join(bundle, 'BifrostSetup.exe'), `bundle-${index}`);
      const stamp = new Date(Date.now() - (index + 1) * 1000);
      utimesSync(bundle, stamp, stamp);
      bundles.push(bundle);
    }
    const outside = mkdtempSync(path.join(os.tmpdir(), 'bifrost-helper-outside-'));
    writeFileSync(path.join(outside, 'sentinel.txt'), 'must-survive');
    const reparse = path.join(temp, 'reparse-bundle');
    let reparseCreated = false;
    try { symlinkSync(outside, reparse, 'junction'); reparseCreated = true; } catch { /* junctions may be unavailable */ }
    const bounded = spawnSync(dotnet, [setup, '--test-helper-cleanup', '--helper-root', temp, '--current-root', path.join(current, 'BifrostSetup.exe')], { encoding: 'utf8', cwd: path.dirname(setup) });
    assert.equal(bounded.status, 0, bounded.stderr || bounded.stdout);
    assert.equal(existsSync(path.join(current, 'BifrostSetup.exe')), true, 'the actual current helper executable must remain');
    const remainingBundles = readdirSync(temp, { withFileTypes: true }).filter(entry => entry.isDirectory() && entry.name.startsWith('bundle-'));
    assert.ok(remainingBundles.length <= 4, `helper bundle count exceeded bound: ${remainingBundles.length}`);
    if (reparseCreated) {
      assert.equal(lstatSync(reparse).isSymbolicLink(), true, 'reparse entry must not be followed or deleted');
      assert.equal(existsSync(path.join(outside, 'sentinel.txt')), true, 'external target must not be deleted');
    }
    rmSync(outside, { recursive: true, force: true });
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('installed apphost completes self-update through a helper without replacing its running executable', () => {
  const umbrella = path.resolve(root, '..', '..');
  const apphost = compiledSetupApphost();
  const dotnetRoot = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet');
  const sourceReleases = testReleaseRoot();
  assert.ok(existsSync(apphost), 'compiled apphost setup executable must be built before this gate');
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const manifest = JSON.parse(manifestText);
  const windows = installableWindowsArtifacts(manifest);
  const installerArtifact = windows.find((artifact) => artifact.kind === 'installer');
  assert.ok(installerArtifact, 'signed manifest must contain installer artifact');
  const installedSetupSource = path.join(sourceReleases, installerArtifact.path);
  assert.ok(existsSync(installedSetupSource), 'signed production setup executable must be built before this gate');
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-self-update-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const stage = path.join(updateRoot, 'stage');
  try {
    mkdirSync(stage, { recursive: true });
    for (const artifact of windows) {
      const source = path.join(sourceReleases, artifact.path);
      const destination = path.join(stage, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(destination), { recursive: true });
      cpSync(source, destination);
    }
    mkdirSync(installRoot, { recursive: true });
    // Run the compiled production apphost with its locked runtime payload so
    // this gate exercises the real self-update branch, not a DLL invocation.
    // The signed release executable remains the artifact promoted by the
    // helper and is verified below.
    cpSync(path.dirname(apphost), installRoot, { recursive: true });
    const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
    mkdirSync(path.dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify({ last_sequence: manifest.release_sequence - 1, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
    writeFileSync(path.join(updateRoot, 'update-pending.json'), JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage }));
    const result = spawnSync(path.join(installRoot, 'BifrostSetup.exe'), ['--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--fake-service', 'success'], { encoding: 'utf8', cwd: installRoot, timeout: 180000, env: { ...process.env, DOTNET_ROOT: dotnetRoot, DOTNET_ROOT_X64: dotnetRoot, DOTNET_MULTILEVEL_LOOKUP: '0' } });
    assert.equal(result.status, 0, `installed apphost did not schedule helper: ${result.stderr || result.stdout}`);
    // The real helper waits for the parent apphost to exit before replacing its
    // executable.  The parent can return to this test before that bounded wait
    // completes, so observe the production hand-off for the full deadline.
    for (let attempt = 0; attempt < 300 && (!existsSync(statePath) || existsSync(path.join(updateRoot, 'update-pending.json'))); attempt++) sleepSync(250);
    assert.equal(existsSync(statePath), true, 'helper must advance durable state after parent exits');
    assert.equal(existsSync(path.join(updateRoot, 'update-pending.json')), false, 'helper must clear pending only after promotion');
    assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).last_sequence, manifest.release_sequence);
    const installedSetup = path.join(installRoot, 'BifrostSetup.exe');
    assert.equal(createHash('sha256').update(readFileSync(installedSetup)).digest('hex'), installerArtifact.sha256, 'installer artifact must be replaced by helper');
    assert.equal(existsSync(path.join(installRoot, '.bifrost-updater')), true, 'helper bootstrap remains outside the replaced payload');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('compiled initial install rolls back payload and fake service when start fails', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  const manifest = JSON.parse(readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8'));
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-install-failure-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
  try {
    const result = spawnSync(dotnet, [setup, '--install', '--package-root', sourceReleases, '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--fake-service', 'start-fails'], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });
    assert.notEqual(result.status, 0, 'fake start failure must fail installation');
    assert.equal(existsSync(statePath), false, 'failed install must not advance state');
    assert.equal(existsSync(path.join(updateRoot, 'service-lifecycle.marker')), false, 'failed service creation/start must leave no service');
    for (const artifact of manifest.build.artifacts.filter((artifact) => artifact.platform === 'windows' && artifact.arch === 'x64')) {
      assert.equal(existsSync(path.join(installRoot, artifact.install_path ?? artifact.path)), false, `failed install left ${artifact.install_path}`);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('compiled initial install health failure deletes transaction service and never starts an old service', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  const manifest = JSON.parse(readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8'));
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-health-failure-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
  try {
    const result = spawnSync(dotnet, [setup, '--install', '--package-root', sourceReleases, '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--fake-service', 'health-fails'], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });
    assert.notEqual(result.status, 0, 'fake health failure must fail installation');
    assert.equal(existsSync(statePath), false);
    assert.equal(existsSync(path.join(updateRoot, 'service-lifecycle.marker')), false);
    const events = readFileSync(path.join(updateRoot, 'service-lifecycle.events'), 'utf8').trim().split(/\r?\n/);
    assert.deepEqual(events, ['create', 'health', 'stop-new', 'restore-files', 'restore-state'], 'initial rollback must not start a deleted transaction service');
    for (const artifact of manifest.build.artifacts.filter((artifact) => artifact.platform === 'windows' && artifact.arch === 'x64')) {
      assert.equal(existsSync(path.join(installRoot, artifact.install_path ?? artifact.path)), false);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('PowerShell ApplyPending accepts only the current setup nonce and sequence', () => {
  const infraRoot = path.resolve(root, '..', 'bifrost-infra');
  const script = path.join(infraRoot, 'scripts', 'install-client-release.ps1');
  const powershell = powershellExecutable();
  const sequence = 91;
  const makeCase = (name, previous, current, writesCurrent, operationHook = false) => {
    const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-powershell-' + name + '-'));
    const installRoot = path.join(temp, 'install');
    const updateRoot = path.join(temp, 'updates');
    const setupPath = path.join(temp, 'fake-setup.ps1');
    mkdirSync(path.join(installRoot, '.bifrost-state'), { recursive: true });
    mkdirSync(updateRoot, { recursive: true });
    if (previous) writeFileSync(path.join(installRoot, '.bifrost-state', 'update-operation.json'), JSON.stringify(previous));
    writeFileSync(path.join(updateRoot, 'update-pending.json'), JSON.stringify({ manifest_text: 'test', signature: 'test', stage_directory: path.join(updateRoot, 'stage') }));
    const fake = [
      'param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Ignored)',
      "$state = Join-Path $env:FAKE_INSTALL '.bifrost-state'",
      'New-Item -ItemType Directory -Force -Path $state | Out-Null',
      "if ($env:FAKE_WRITE_OPERATION -eq '1') { [IO.File]::WriteAllText((Join-Path $state 'update-operation.json'), $env:FAKE_OPERATION_JSON) }",
      'Write-Output $env:FAKE_OUTPUT_JSON',
      'exit 0'
    ].join(String.fromCharCode(13, 10));
    writeFileSync(setupPath, fake, 'utf8');
    let operationHookPath = null;
    if (operationHook) {
      operationHookPath = path.join(temp, 'replace-operation.ps1');
      writeFileSync(operationHookPath, [
      'param([string]$OperationPath, [string]$Nonce, [string]$Sequence)',
      '$replacement = @{ state = "failed"; sequence = [long]$Sequence; operation_nonce = $Nonce } | ConvertTo-Json -Compress',
      '$temporary = "$OperationPath.replacement"',
      '[IO.File]::WriteAllText($temporary, $replacement, [Text.UTF8Encoding]::new($false))',
      'try { [IO.File]::Replace($temporary, $OperationPath, $null) } catch { [IO.File]::Delete($OperationPath); [IO.File]::Move($temporary, $OperationPath) }',
      '[IO.File]::ReadAllText($OperationPath) | Out-Null'
    ].join(String.fromCharCode(13, 10)), 'utf8');
    }
    return { temp, installRoot, updateRoot, setupPath, previous, current, writesCurrent, operationHook: operationHookPath };
  };
  const invoke = (item) => {
    const env = {
      ...process.env,
      FAKE_INSTALL: item.installRoot,
      FAKE_UPDATE: item.updateRoot,
      FAKE_OUTPUT_JSON: JSON.stringify({ state: 'scheduled', sequence, operation_nonce: 'current-nonce' }),
      FAKE_OPERATION_JSON: JSON.stringify(item.current),
      FAKE_WRITE_OPERATION: item.writesCurrent ? '1' : '0'
    };
    return spawnSync(powershell, [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script,
      '-InstallRoot', item.installRoot, '-ApplyPending', '-TestSeam',
      '-TestSetupPath', item.setupPath, '-TestUpdateRoot', item.updateRoot,
      '-TestPollIntervalMilliseconds', '1', '-TestPollTimeoutMilliseconds', '120'
    ].concat(item.operationHook ? ['-TestAfterSetupHookPath', item.operationHook] : []), { encoding: 'utf8', cwd: infraRoot, env, timeout: 30000 });
  };
  const cases = [
    makeCase('fast', { state: 'failed', sequence, operation_nonce: 'old-nonce' }, { state: 'succeeded', sequence, operation_nonce: 'current-nonce' }, true),
    makeCase('old-failed', { state: 'failed', sequence, operation_nonce: 'old-nonce' }, { state: 'succeeded', sequence, operation_nonce: 'current-nonce' }, false),
    makeCase('old-succeeded', { state: 'succeeded', sequence, operation_nonce: 'old-nonce' }, { state: 'succeeded', sequence, operation_nonce: 'current-nonce' }, false),
    makeCase('wrong-sequence', { state: 'succeeded', sequence: sequence - 1, operation_nonce: 'current-nonce' }, { state: 'succeeded', sequence: sequence - 1, operation_nonce: 'current-nonce' }, false),
    makeCase('operation-replaced', { state: 'failed', sequence, operation_nonce: 'old-nonce' }, { state: 'succeeded', sequence, operation_nonce: 'current-nonce' }, true, true)
  ];
  try {
    const [fast, oldFailed, oldSucceeded, wrongSequence, operationReplaced] = cases;
    const fastResult = invoke(fast);
    assert.equal(fastResult.status, 0, (fastResult.stderr || '') + (fastResult.stdout || ''));
    assert.equal(JSON.parse(readFileSync(path.join(fast.installRoot, '.bifrost-state', 'update-operation.json'), 'utf8')).state, 'succeeded');
    for (const stale of [oldFailed, oldSucceeded, wrongSequence]) {
      const result = invoke(stale);
      assert.notEqual(result.status, 0, stale.temp + ' stale/mismatched operation must not be accepted');
      const operation = JSON.parse(readFileSync(path.join(stale.installRoot, '.bifrost-state', 'update-operation.json'), 'utf8'));
      assert.equal(operation.operation_nonce, stale.previous.operation_nonce);
      assert.equal(existsSync(path.join(stale.updateRoot, 'update-pending.json')), true);
    }
    const replacedResult = invoke(operationReplaced);
    assert.notEqual(replacedResult.status, 0, 'an atomic operation replacement must change the polling result');
    const replacedOperation = JSON.parse(readFileSync(path.join(operationReplaced.installRoot, '.bifrost-state', 'update-operation.json'), 'utf8'));
    assert.deepEqual({ state: replacedOperation.state, sequence: replacedOperation.sequence, operation_nonce: replacedOperation.operation_nonce }, { state: 'failed', sequence, operation_nonce: 'current-nonce' });
    assert.equal(existsSync(path.join(operationReplaced.updateRoot, 'update-pending.json')), true);
  } finally {
    for (const item of cases) rmSync(item.temp, { recursive: true, force: true });
  }
});

test('PowerShell ApplyPending drives the compiled BifrostSetup apphost in a safe temp root', () => {
  const umbrella = path.resolve(root, '..', '..');
  const infraRoot = path.resolve(root, '..', 'bifrost-infra');
  const script = path.join(infraRoot, 'scripts', 'install-client-release.ps1');
  const compiledDll = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  const powershell = powershellExecutable();
  assert.equal(existsSync(compiledDll), true, 'Setup production assembly must be built before this integration test');
  assert.equal(existsSync(dotnet), true, 'pinned test runtime must exist');
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const manifest = JSON.parse(manifestText);
  const windows = installableWindowsArtifacts(manifest);
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-powershell-apphost-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const stage = path.join(updateRoot, 'stage');
  const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
  const markerPath = path.join(updateRoot, 'update-pending.json');
  const setup = path.join(temp, 'setup-wrapper.ps1');
  try {
    writeFileSync(setup, [
      'param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Forwarded)',
      `& '${dotnet.replace(/'/g, "''")}' '${compiledDll.replace(/'/g, "''")}' @Forwarded`,
      'exit $LASTEXITCODE'
    ].join(String.fromCharCode(13, 10)), 'utf8');
    mkdirSync(stage, { recursive: true });
    for (const artifact of windows) {
      const relative = artifact.install_path ?? artifact.path;
      const source = path.join(sourceReleases, artifact.path);
      const staged = path.join(stage, relative);
      const installed = path.join(installRoot, relative);
      mkdirSync(path.dirname(staged), { recursive: true });
      mkdirSync(path.dirname(installed), { recursive: true });
      cpSync(source, staged);
      writeFileSync(installed, Buffer.from(`old-${artifact.kind}`));
    }
    mkdirSync(path.dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify({ last_sequence: manifest.release_sequence - 1, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
    writeFileSync(markerPath, JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage }));
    const result = spawnSync(powershell, [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script,
      '-InstallRoot', installRoot, '-ApplyPending', '-TestSeam', '-TestSetupPath', setup,
      '-TestUpdateRoot', updateRoot, '-TestFakeServiceMode', 'success',
      '-TestPollIntervalMilliseconds', '1', '-TestPollTimeoutMilliseconds', '10000'
    ], { encoding: 'utf8', cwd: infraRoot, timeout: 180000 });
    assert.equal(result.status, 0, (result.stderr || '') + (result.stdout || ''));
    const operation = JSON.parse(readFileSync(path.join(installRoot, '.bifrost-state', 'update-operation.json'), 'utf8'));
    assert.equal(operation.state, 'succeeded');
    assert.equal(operation.sequence, manifest.release_sequence);
    assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).last_sequence, manifest.release_sequence);
    assert.equal(existsSync(markerPath), false, 'successful compiled apply removes pending');
    for (const artifact of windows) {
      const relative = artifact.install_path ?? artifact.path;
      assert.deepEqual(readFileSync(path.join(installRoot, relative)), readFileSync(path.join(sourceReleases, artifact.path)), `compiled helper promoted ${relative}`);
    }
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('compiled pending rollback isolates locked-file, restore-state, service-restore and cleanup faults', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const manifest = JSON.parse(manifestText);
  const windows = installableWindowsArtifacts(manifest);

  const runFault = (fault, serviceMode = 'success') => {
    const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-fault-'));
    const installRoot = path.join(temp, 'install');
    const updateRoot = path.join(temp, 'updates');
    const stage = path.join(updateRoot, 'stage');
    const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
    const markerPath = path.join(updateRoot, 'update-pending.json');
    try {
      mkdirSync(stage, { recursive: true });
      mkdirSync(installRoot, { recursive: true });
      for (const artifact of windows) {
        const source = path.join(sourceReleases, artifact.path);
        const staged = path.join(stage, artifact.install_path ?? artifact.path);
        mkdirSync(path.dirname(staged), { recursive: true });
        cpSync(source, staged);
        const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
        mkdirSync(path.dirname(installed), { recursive: true });
        writeFileSync(installed, Buffer.from(`old-${artifact.kind}`));
      }
      mkdirSync(path.dirname(statePath), { recursive: true });
      writeFileSync(statePath, JSON.stringify({ last_sequence: manifest.release_sequence - 1, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
      writeFileSync(markerPath, JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage }));
      writeFileSync(path.join(updateRoot, 'service-lifecycle.marker'), 'running');
      const result = spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--fake-service', serviceMode, '--fake-failure', fault], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });
      assert.notEqual(result.status, 0, `${fault} must fail closed: ${result.stderr || result.stdout}`);
      assert.equal(existsSync(markerPath), true, `${fault} must retain pending marker`);
      assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).last_sequence, manifest.release_sequence - 1, `${fault} must preserve rollback floor`);
      const operation = JSON.parse(readFileSync(path.join(installRoot, '.bifrost-state', 'update-operation.json'), 'utf8'));
      assert.equal(operation.state, 'failed', `${fault} must publish a failed operation`);
      const events = readFileSync(path.join(updateRoot, 'service-lifecycle.events'), 'utf8').trim().split(/\r?\n/);
      assert.ok(events.includes('restore-files'), `${fault} must attempt file restore`);
      assert.ok(events.includes('restore-state'), `${fault} must attempt state restore`);
      assert.ok(events.includes('start-old'), `${fault} must attempt old service restore`);
      assert.ok(events.includes('cleanup-backup'), `${fault} must attempt backup cleanup (events: ${events.join(',')})`);
      assert.ok(events.includes('cleanup-protected'), `${fault} must attempt protected cleanup`);
      assert.ok(events.indexOf('cleanup-backup') < events.indexOf('cleanup-protected'), `${fault} cleanup steps must both execute in order`);
      if (!fault.split(',').includes('restore-files')) {
        for (const artifact of windows) {
          const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
          assert.equal(readFileSync(installed, 'utf8'), `old-${artifact.kind}`, `${fault} must restore ${artifact.install_path}`);
        }
      }
      const protectedRoot = path.join(installRoot, '.bifrost-protected');
      assert.equal(existsSync(protectedRoot) && readdirSync(protectedRoot).length > 0, false, `${fault} must attempt protected cleanup`);
    } finally { rmSync(temp, { recursive: true, force: true }); }
  };

  runFault('locked-file');
  runFault('restore-files', 'health-fails');
  runFault('restore-state', 'health-fails');
  runFault('restore-state', 'health-fails,service-restore-fails');
  runFault('restore-files,cleanup-backup', 'health-fails');
});

test('compiled helper correlation is nonce and sequence bound without polling races', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const manifest = JSON.parse(manifestText);
  const windows = installableWindowsArtifacts(manifest);
  const sequence = manifest.release_sequence;
  const nonce = 'correlation-test-nonce';
  const createCase = (operation, marker = { manifest_text: manifestText, signature, stage_directory: null }) => {
    const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-helper-correlation-'));
    const installRoot = path.join(temp, 'install');
    const updateRoot = path.join(temp, 'updates');
    const stage = path.join(updateRoot, 'stage');
    const statePath = path.join(installRoot, '.bifrost-state', 'update-state.json');
    mkdirSync(stage, { recursive: true });
    mkdirSync(installRoot, { recursive: true });
    for (const artifact of windows) {
      const staged = path.join(stage, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(staged), { recursive: true });
      cpSync(path.join(sourceReleases, artifact.path), staged);
    }
    for (const artifact of windows) {
      const installed = path.join(installRoot, artifact.install_path ?? artifact.path);
      mkdirSync(path.dirname(installed), { recursive: true });
      writeFileSync(installed, Buffer.from(`old-${artifact.kind}`));
    }
    mkdirSync(path.dirname(statePath), { recursive: true });
    writeFileSync(statePath, JSON.stringify({ last_sequence: sequence - 1, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
    writeFileSync(path.join(updateRoot, 'update-pending.json'), JSON.stringify({ ...marker, stage_directory: marker.stage_directory ?? stage }));
    writeFileSync(path.join(installRoot, '.bifrost-state', 'update-operation.json'), JSON.stringify({ ...operation, updated_at: '2026-01-01T00:00:00.0000000+00:00' }));
    return { temp, installRoot, updateRoot, statePath, markerPath: path.join(updateRoot, 'update-pending.json'), operationPath: path.join(installRoot, '.bifrost-state', 'update-operation.json') };
  };
  const invoke = ({ installRoot, updateRoot }, expectedSequence = sequence, opNonce = nonce) => spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--helper', '--wait-for-pid', '2147483647', '--operation-nonce', opNonce, '--expected-sequence', String(expectedSequence), '--fake-service', 'success'], { encoding: 'utf8', cwd: path.dirname(setup), timeout: 180000 });

  const fast = createCase({ state: 'scheduled', sequence, operation_nonce: nonce });
  try {
    const result = invoke(fast);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const completed = JSON.parse(readFileSync(fast.operationPath, 'utf8'));
    assert.deepEqual({ state: completed.state, sequence: completed.sequence, operation_nonce: completed.operation_nonce }, { state: 'succeeded', sequence, operation_nonce: nonce }, 'a helper that completed before the first poll must be observable as this operation');
  } finally { rmSync(fast.temp, { recursive: true, force: true }); }

  for (const staleState of ['failed', 'succeeded']) {
    const stale = createCase({ state: staleState, sequence, operation_nonce: nonce });
    try {
      const result = invoke(stale);
      assert.notEqual(result.status, 0, `stale ${staleState} must not be accepted`);
      const failed = JSON.parse(readFileSync(stale.operationPath, 'utf8'));
      assert.deepEqual({ state: failed.state, sequence: failed.sequence, operation_nonce: failed.operation_nonce }, { state: 'failed', sequence, operation_nonce: nonce });
      assert.equal(existsSync(stale.markerPath), true, 'stale operation rejection keeps pending for retry');
    } finally { rmSync(stale.temp, { recursive: true, force: true }); }
  }

  const wrongSequence = createCase({ state: 'scheduled', sequence: sequence - 1, operation_nonce: nonce });
  try {
    const result = invoke(wrongSequence, sequence);
    assert.notEqual(result.status, 0, 'wrong sequence correlation must fail');
    const failed = JSON.parse(readFileSync(wrongSequence.operationPath, 'utf8'));
    assert.deepEqual({ state: failed.state, sequence: failed.sequence, operation_nonce: failed.operation_nonce }, { state: 'failed', sequence, operation_nonce: nonce });
  } finally { rmSync(wrongSequence.temp, { recursive: true, force: true }); }

  // The parent has already established the scheduled operation; a marker
  // replacement after that point is treated as an untrusted helper input but
  // must still terminate the same nonce+sequence operation deterministically.
  const replaced = createCase({ state: 'scheduled', sequence, operation_nonce: nonce }, { manifest_text: manifestText, signature, stage_directory: path.join(os.tmpdir(), 'outside-stage') });
  try {
    const result = invoke(replaced);
    assert.notEqual(result.status, 0, 'replacement marker must fail closed');
    const failed = JSON.parse(readFileSync(replaced.operationPath, 'utf8'));
    assert.deepEqual({ state: failed.state, sequence: failed.sequence, operation_nonce: failed.operation_nonce }, { state: 'failed', sequence, operation_nonce: nonce });
    assert.equal(existsSync(replaced.markerPath), true);
  } finally { rmSync(replaced.temp, { recursive: true, force: true }); }
});

test('compiled trusted setup rejects pending marker shape and corrupt durable state', () => {
  const umbrella = path.resolve(root, '..', '..');
  const setup = compiledSetupDll();
  const dotnet = path.resolve(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const sourceReleases = testReleaseRoot();
  const manifestText = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.json'), 'utf8');
  const signature = readFileSync(path.join(sourceReleases, 'RELEASE-MANIFEST.sig'), 'utf8').trim();
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-setup-marker-'));
  const installRoot = path.join(temp, 'install');
  const updateRoot = path.join(temp, 'updates');
  const stage = path.join(updateRoot, 'stage');
  const invoke = (marker) => {
    writeFileSync(path.join(updateRoot, 'update-pending.json'), marker);
    return spawnSync(dotnet, [setup, '--apply-pending', '--install-root', installRoot, '--update-root', updateRoot, '--test-root', '--what-if'], { encoding: 'utf8', cwd: path.dirname(setup) });
  };
  try {
    mkdirSync(stage, { recursive: true });
    assert.notEqual(invoke(JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage, extra: 1 })).status, 0);
    assert.notEqual(invoke(JSON.stringify({ manifest_text: manifestText, stage_directory: stage })).status, 0);
    assert.notEqual(invoke(`{"manifest_text":${JSON.stringify(manifestText)},"manifest_text":"x","signature":${JSON.stringify(signature)},"stage_directory":${JSON.stringify(stage)}}`).status, 0);
    mkdirSync(path.join(installRoot, '.bifrost-state'), { recursive: true });
    writeFileSync(path.join(installRoot, '.bifrost-state', 'update-state.json'), '{"last_sequence":');
    assert.notEqual(invoke(JSON.stringify({ manifest_text: manifestText, signature, stage_directory: stage })).status, 0);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('release Ed25519 fixed vector is shared by native verifiers and rejects tampering/old sequence', () => {
  const vector = JSON.parse(readFileSync(path.join(root, 'tests', 'fixtures', 'fixed-ed25519-vector.json'), 'utf8'));
  const payload = Buffer.from(vector.message_utf8, 'utf8');
  const signature = Buffer.from(vector.signature_base64url, 'base64url');
  const publicKey = createPublicKey(vector.public_key_pem);
  assert.equal(signature.length, 64);
  assert.equal(verify(null, payload, publicKey, signature), true);
  assert.equal(verify(null, Buffer.concat([payload, Buffer.from('!')]), publicKey, signature), false);
  assert.equal(verify(null, payload, publicKey, Buffer.from(signature.subarray(0, 63))), false);
  const wrong = generateKeyPairSync('ed25519').publicKey;
  assert.equal(verify(null, payload, wrong, signature), false);

  const android = readFileSync(path.join(root, 'android-app', 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostUpdateManager.kt'), 'utf8');
  const windows = readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8');
  assert.doesNotMatch(android, /HOvPHzgTfkusEObQQacilPrv7a6HdQlDVqLYZNxpyLE=/);
  assert.doesNotMatch(windows, /HOvPHzgTfkusEObQQacilPrv7a6HdQlDVqLYZNxpyLE=/);
  assert.match(android, /TRUST_ROOT_PROVISIONED/);
  assert.match(windows, /TRUST-ROOT/);

  const item = fixture();
  assert.throws(() => verifyFixtureRelease({ ...item, previousSequence: 7 }), /rollback|FIELDS/i);
  assert.throws(() => verifyFixtureRelease({ ...item, previousSequence: 8 }), /rollback|FIELDS/i);
});

test('release ceremony is explicit and test vectors are not production pins', () => {
  const infraRoot = path.resolve(root, '..', 'bifrost-infra');
  const umbrellaRoot = path.resolve(root, '..', '..');
  const nativeSources = [
    readFileSync(path.join(root, 'android-app', 'build.gradle.kts'), 'utf8'),
    readFileSync(path.join(root, 'android-app', 'src', 'main', 'java', 'com', 'bifrost', 'client', 'BifrostUpdateManager.kt'), 'utf8'),
    readFileSync(path.join(root, 'release', 'ReleaseUpdateManager.cs'), 'utf8'),
    readFileSync(path.join(root, 'release', 'update-manager.mjs'), 'utf8'),
    readFileSync(path.join(infraRoot, 'scripts', 'release-sign.mjs'), 'utf8')
  ];
  for (const source of nativeSources) {
    assert.doesNotMatch(source, /MCowBQYDK2VwAyEAHOvPHzgTfkusEObQQacilPrv7a6HdQlDVqLYZNxpyLE=/);
  }
  assert.equal(JSON.parse(readFileSync(path.join(root, 'config-contracts', 'release-contract-v1.json'), 'utf8')).trust_root.status, 'PENDING-EXTERNAL-CEREMONY');
});
