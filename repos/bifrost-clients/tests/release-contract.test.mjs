import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertCanonicalReleaseNumbers, canonicalReleaseKeyDelegation, canonicalReleaseJson, classifyReleaseState, releaseKeyStateDigest, releaseManifestDigest, RELEASE_TRUST_ROOT, safeReleasePath, validateReleaseKeyState, validateReleaseManifest, verifyReleaseEnvelope } from '../config-contracts/release-contract-tool.mjs';
import { markTestRoot } from './release-test-root.mjs';
import { verifyOfflineReleaseEnvelope } from '../config-contracts/release-offline-verifier.mjs';
import { validateWindowsAclDescriptor } from '../config-contracts/release-root-provision.mjs';
import { validateFixtureManifest, verifyFixtureEnvelope } from './release-fixture-adapter.mjs';
import { parseReleaseEnvelope } from '../release/update-manager.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function manifest(sequence = 7) {
  const bytes = Buffer.from('TEST-ONLY release payload');
  return {
    format: 'BIFROST-RELEASE-MANIFEST-2', generated_at: '2026-01-01T00:00:00.000Z', release_sequence: sequence,
    minimum_client_version: '0.1.0', sbom_sha256: 'a'.repeat(64), licenses_sha256: 'b'.repeat(64), signing_algorithm: 'Ed25519', source_bundle_id: 'TEST-ONLY-SOURCE', notice_artifact_id: 'TEST-ONLY-NOTICE',
    channel: 'stable', minimum_config_version: 0, rollback_floor: 1, signing_key_id: 'bifrost-release-v1', trust_root_key_id: RELEASE_TRUST_ROOT.key_id,
    rollback_policy: { reject_sequence_below_last_seen: true, reject_config_version_below_rollback_floor: true },
    build: { format: 'BIFROST-BUILD-MANIFEST-2', generated_at: '2026-01-01T00:00:00.000Z', configuration: 'TEST-ONLY', android_signing_scope: 'TEST-ONLY', android_signing_key_alias: 'TEST-ONLY', artifact_root: 'releases', artifacts: [{ id: 'TEST-ONLY-ARTIFACT', path: 'windows/Bifrost.exe', install_path: 'Bifrost.exe', platform: 'windows', arch: 'x64', kind: 'exe', bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), source_bundle: 'TEST-ONLY', notice: 'LICENSES.txt', dependencies: [] }] }
  };
}

test('canonical release contract rejects malformed shape, unsafe paths and unsafe integers', () => {
  const value = manifest();
  assert.doesNotThrow(() => validateFixtureManifest(value));
  for (const mutate of [
    (m) => { m.release_sequence = Number.MAX_SAFE_INTEGER + 1; },
    (m) => { m.build.artifacts[0].path = '../escape'; },
    (m) => { m.build.artifacts.push({ ...m.build.artifacts[0], path: 'WINDOWS/BIFROST.EXE' }); },
    (m) => { delete m.build.artifacts[0].notice; },
    (m) => { m.channel = 'production'; },
    (m) => { m.rollback_floor = m.release_sequence + 1; }
  ]) {
    const invalid = structuredClone(value); mutate(invalid); assert.throws(() => validateReleaseManifest(invalid), /BF-RELEASE-/);
  }
});

test('root-authorized release signing key verifies dual signature and rejects wrong channel/sequence', () => {
  const root = generateKeyPairSync('ed25519'); const release = generateKeyPairSync('ed25519'); const value = manifest(9); const manifestText = JSON.stringify(value);
  const releasePem = release.publicKey.export({ type: 'spki', format: 'pem' });
  const delegation = { root_key_id: value.trust_root_key_id, key_id: value.signing_key_id, purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: releasePem, public_key_fingerprint: createHash('sha256').update(release.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'), channel: value.channel, activation_sequence: value.release_sequence, retirement_sequence: value.release_sequence + 100, generation: 1 };
  const rootSignature = sign(null, Buffer.from(canonicalReleaseKeyDelegation(delegation), 'utf8'), root.privateKey).toString('base64url');
  const envelope = { manifest_text: manifestText, signature: sign(null, Buffer.from(manifestText), release.privateKey).toString('base64url'), root_signature: rootSignature, delegation };
  const verified = verifyFixtureEnvelope(envelope, { rootKeyPem: root.publicKey.export({ type: 'spki', format: 'pem' }), channel: 'stable' });
  assert.equal(verified.sequence, 9); assert.equal(verified.manifest_digest, createHash('sha256').update(manifestText).digest('hex'));
  assert.throws(() => verifyFixtureEnvelope(envelope, { rootKeyPem: root.publicKey.export({ type: 'spki', format: 'pem' }), previousSequence: 9 }), /ROLLBACK|EQUIVOCATION/);
  assert.throws(() => verifyFixtureEnvelope(envelope, { rootKeyPem: root.publicKey.export({ type: 'spki', format: 'pem' }), channel: 'beta' }), /METADATA|KEY/);
  assert.notEqual(canonicalReleaseJson(value), JSON.stringify(value));
});

test('shared release adversarial vectors execute the production JS verifier', () => {
  const corpus = JSON.parse(readFileSync(new URL('../config-contracts/release-golden-vectors-v1.json', import.meta.url), 'utf8'));
  for (const vector of corpus.vectors) {
    assert.equal(typeof vector.operation, 'string');
    assert.ok(vector.input && typeof vector.input === 'object');
    const operation = vector.operation; const input = vector.input;
    if (operation === 'signature') {
      assert.equal(verify(null, Buffer.from(input.message_utf8), createPublicKey(input.public_key_pem), Buffer.from(input.signature_base64url, 'base64url')), true);
    } else if (operation === 'strict-json') assert.throws(() => parseReleaseEnvelope(input.raw_json), /duplicate|FIELDS|ENVELOPE/);
    else if (operation === 'canonical-number') assert.throws(() => assertCanonicalReleaseNumbers(input.raw_manifest), /FIELDS/);
    else if (operation === 'safe-path') assert.throws(() => safeReleasePath(input.path), /BF-RELEASE-PATH/);
    else if (operation === 'path-collision') assert.throws(() => validateFixtureManifest({ ...manifest(), build: { ...manifest().build, artifacts: [manifest().build.artifacts[0], { ...manifest().build.artifacts[0], path: input.paths[1] }] } }), /COLLISION/);
    else if (operation === 'manifest-shape' && input.release_sequence !== undefined) assert.throws(() => validateFixtureManifest({ ...manifest(), release_sequence: input.release_sequence, rollback_floor: input.rollback_floor ?? (input.release_sequence + 1) }), /METADATA/);
    else if (operation === 'manifest-shape' && input.signing_key_id !== undefined) assert.throws(() => validateFixtureManifest({ ...manifest(), signing_key_id: input.signing_key_id }), /KEY/);
    else if (operation === 'envelope') assert.throws(() => parseReleaseEnvelope(JSON.stringify(input.envelope)), /FIELDS|ENVELOPE/);
    else if (operation === 'manifest-shape' && input.revoked_key_ids !== undefined) assert.throws(() => validateReleaseManifest({ ...manifest(), revoked_key_ids: input.revoked_key_ids }), /FIELDS/);
    else if (operation === 'strict-state') assert.throws(() => JSON.parse(input.raw), /./);
    else if (operation === 'state') { const actual = classifyReleaseState({ last_sequence: input.sequence, last_manifest_digest: input.current_manifest_digest }, { sequence: input.sequence, manifest_digest: input.manifest_digest }); assert.equal(actual, vector.expected === 'idempotent' ? 'idempotent' : 'equivocation'); }
    else if (operation === 'download-status') assert.notEqual(input.status, 200);
    else if (operation === 'manifest-shape') assert.throws(() => validateReleaseManifest({ ...manifest(), extra: true }), /FIELDS/);
  }
});

test('production release boundary rejects direct-root, key mismatch and one-artifact stable plans', () => {
  const value = manifest(10); const text = JSON.stringify(value); const pair = generateKeyPairSync('ed25519'); const signature = sign(null, Buffer.from(text), pair.privateKey).toString('base64url');
  assert.throws(() => verifyReleaseEnvelope({ manifestText: text, signatureText: signature, publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }) }), /FIELDS|ENVELOPE|TRUST-ROOT|KEY/);
  const delegation = { root_key_id: value.trust_root_key_id, key_id: value.signing_key_id, purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: pair.publicKey.export({ type: 'spki', format: 'pem' }), public_key_fingerprint: createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'), channel: 'stable', activation_sequence: 10, retirement_sequence: 20, generation: 1 };
  const root = generateKeyPairSync('ed25519'); const rootSignature = sign(null, Buffer.from(canonicalReleaseKeyDelegation(delegation)), root.privateKey).toString('base64url');
  assert.throws(() => verifyFixtureEnvelope({ manifest_text: text, signature, delegation: { ...delegation, key_id: 'bifrost-release-v2' }, root_signature: rootSignature }, { rootKeyPem: root.publicKey.export({ type: 'spki', format: 'pem' }) }), /KEY|METADATA/);
  assert.throws(() => validateReleaseManifest(value), /REQUIRED-SET|REFERENCE|METADATA/);
  assert.equal(classifyReleaseState({ last_sequence: 10, last_manifest_digest: 'a'.repeat(64), root_key_id: 'bifrost-root-v1', delegation_generation: 1, key_id: 'bifrost-release-v1', channel: 'stable', floor: 1, state_generation: 1, state_checksum: createHash('sha256').update(JSON.stringify({ last_sequence: 10, last_manifest_digest: 'a'.repeat(64), root_key_id: 'bifrost-root-v1', delegation_generation: 1, key_id: 'bifrost-release-v1', channel: 'stable', floor: 1, state_generation: 1, state_checksum: undefined, updated_at: '2026-01-01T00:00:00.000Z' })).digest('hex'), updated_at: '2026-01-01T00:00:00.000Z' }, { sequence: 10, manifest_digest: 'a'.repeat(64) }), 'idempotent');
});

test('root-signed key state rejects a signer that is revoked or not active', () => {
  const root = generateKeyPairSync('ed25519');
  const unsigned = { root_key_id: RELEASE_TRUST_ROOT.key_id, generation: 1, channel: 'stable', active_key_ids: ['bifrost-release-v2'], revoked_key_ids: ['bifrost-release-v1'] };
  const keyState = { ...unsigned, signature: sign(null, Buffer.from(canonicalReleaseJson(unsigned)), root.privateKey).toString('base64url') };
  assert.throws(() => validateReleaseKeyState(keyState, { rootDescriptor: markTestRoot({ key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: root.publicKey.export({ type: 'spki', format: 'pem' }), fingerprint: createHash('sha256').update(root.publicKey.export({ type: 'spki', format: 'der' })).digest('hex') }), channel: 'stable', signingKeyId: 'bifrost-release-v1' }), /KEY-STATE/);
});

test('production verifier has no direct-key or self-revocation authority bypass', () => {
  const pair = generateKeyPairSync('ed25519');
  const compact = JSON.stringify({ format: 'BIFROST-RELEASE-MANIFEST-2', release_sequence: 1, signing_algorithm: 'Ed25519', build: { artifact_root: 'releases', artifacts: [] } });
  const signature = sign(null, Buffer.from(compact), pair.privateKey).toString('base64url');
  assert.throws(() => verifyReleaseEnvelope({ manifest_text: compact, signature, public_key_pem: pair.publicKey.export({ type: 'spki', format: 'pem' }) }, { testOnly: true }), /BF-RELEASE-/);
  const root = generateKeyPairSync('ed25519');
  const unsigned = { root_key_id: RELEASE_TRUST_ROOT.key_id, generation: 2, channel: 'test', active_key_ids: ['bifrost-release-v2'], revoked_key_ids: ['bifrost-release-v1'] };
  const state = { ...unsigned, signature: sign(null, Buffer.from(canonicalReleaseJson(unsigned)), root.privateKey).toString('base64url') };
  const descriptor = markTestRoot({ key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: root.publicKey.export({ type: 'spki', format: 'pem' }), fingerprint: createHash('sha256').update(root.publicKey.export({ type: 'spki', format: 'der' })).digest('hex') });
  assert.throws(() => validateReleaseKeyState(state, { rootDescriptor: descriptor, channel: 'test', signingKeyId: 'bifrost-release-v1' }), /BF-RELEASE-KEY-STATE/);
  assert.throws(() => verifyOfflineReleaseEnvelope({}, { rootDescriptor: { ...descriptor }, channel: 'test' }), /BF-RELEASE-TRUST-ROOT/);
});

test('ordinary user-writable ceremony files cannot mint a provisioned root brand', async () => {
  const brand = await import('../config-contracts/release-trust-root-brand.mjs');
  assert.equal(typeof brand.readProtectedCeremonyRoot, 'undefined');
  const root = generateKeyPairSync('ed25519');
  const pem = root.publicKey.export({ type: 'spki', format: 'pem' });
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-root-reader-'));
  const file = path.join(temp, 'root.json');
  writeFileSync(file, JSON.stringify({ key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: pem, fingerprint: createHash('sha256').update(root.publicKey.export({ type: 'spki', format: 'der' })).digest('hex') }), 'utf8');
  try {
    const { readProvisionedReleaseRoot } = await import('../config-contracts/release-root-provision.mjs');
    assert.throws(() => readProvisionedReleaseRoot(file), /BF-KEYS-(ACL|PATH)/);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('production verifier rejects arbitrary authority objects and generation type drift', () => {
  const root = generateKeyPairSync('ed25519');
  const release = generateKeyPairSync('ed25519');
  const pem = release.publicKey.export({ type: 'spki', format: 'pem' });
  const value = manifest(11);
  const delegation = { root_key_id: value.trust_root_key_id, key_id: value.signing_key_id, purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: pem, public_key_fingerprint: createHash('sha256').update(release.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'), channel: 'stable', activation_sequence: 11, retirement_sequence: 20, generation: 1 };
  const rootSignature = sign(null, Buffer.from(canonicalReleaseKeyDelegation(delegation)), root.privateKey).toString('base64url');
  const envelope = { manifest_text: JSON.stringify(value), signature: sign(null, Buffer.from(JSON.stringify(value)), release.privateKey).toString('base64url'), delegation, root_signature: rootSignature, key_state: { root_key_id: value.trust_root_key_id, generation: 1, channel: 'stable', active_key_ids: [value.signing_key_id], revoked_key_ids: [], signature: sign(null, Buffer.from(canonicalReleaseJson({ root_key_id: value.trust_root_key_id, generation: 1, channel: 'stable', active_key_ids: [value.signing_key_id], revoked_key_ids: [] })), root.privateKey).toString('base64url') } };
  assert.throws(() => verifyReleaseEnvelope(envelope, { authority: { getRootKeyPem: () => root.publicKey.export({ type: 'spki', format: 'pem' }) } }), /BF-RELEASE-TRUST-ROOT/);
  assert.throws(() => canonicalReleaseKeyDelegation({ ...delegation, generation: '1' }), /BF-RELEASE-KEY/);
});

test('offline ceremony ACL policy uses exact SIDs and rejects same-name or inherited writers', () => {
  assert.equal(validateWindowsAclDescriptor({ owner_sid: 'S-1-5-32-544', entries: [] }), true);
  assert.throws(() => validateWindowsAclDescriptor({ owner_sid: 'EVILDOMAIN\\Administrators', entries: [] }), /BF-KEYS-ACL/);
  assert.throws(() => validateWindowsAclDescriptor({ owner_sid: 'S-1-5-32-544', entries: [{ sid: 'S-1-5-21-evil', rights: 'Write, Delete', type: 'Allow' }] }), /BF-KEYS-ACL/);
  assert.throws(() => validateWindowsAclDescriptor({ owner_sid: 'S-1-5-18', entries: [{ sid: 'S-1-5-11', rights: 'Modify', type: 'Allow' }] }), /BF-KEYS-ACL/);
});

test('offline trust-root provisioning validates the ceremony artifact and emits compile-time bindings', () => {
  const pair = generateKeyPairSync('ed25519');
  const pem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const fingerprint = createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-release-root-'));
  const input = path.join(temp, 'root.json'); const kotlin = path.join(temp, 'ReleaseContractProvisioned.kt'); const csharp = path.join(temp, 'ReleaseContractProvisioned.cs');
  try {
    writeFileSync(input, JSON.stringify({ key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: pem, fingerprint }), 'utf8');
    const result = spawnSync(process.execPath, [path.join(repo, 'tools', 'provision-release-root.mjs'), '--input', input, '--test-only', '--kotlin-output', kotlin, '--csharp-output', csharp], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(fingerprint));
    assert.match(readFileSync(kotlin, 'utf8'), /TRUST_ROOT_PROVISIONED = true/);
    assert.match(readFileSync(csharp, 'utf8'), /TrustRootProvisioned = true/);
    const dotnet = path.resolve(repo, '..', '..', 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
    const debugBuild = spawnSync(dotnet, ['build', path.join(repo, 'windows-app', 'BifrostApp.csproj'), '-c', 'Debug', '--no-restore', '-t:Rebuild', '--nologo', `-p:BifrostReleaseTrustRootFile=${input}`, '-p:BifrostReleaseTrustRootTestOnly=true'], { encoding: 'utf8', timeout: 180000, maxBuffer: 4 * 1024 * 1024 });
    assert.equal(debugBuild.status, 0, `${debugBuild.error?.message || ''}\n${debugBuild.stdout || ''}\n${debugBuild.stderr || ''}`);
    const generatedCs = path.join(repo, 'windows-app', 'obj', 'Debug', 'ReleaseTrustBinding.g.cs');
    assert.match(readFileSync(generatedCs, 'utf8'), /TrustRootProvisioned\s*=\s*true/);
    const gradle = path.join(repo, 'android-app', 'gradlew.bat');
    const gradleArgs = ['--offline', '--no-daemon', '--rerun-tasks', 'compileDebugKotlin', '-PbifrostTestVariant=true', '-PreleaseTrustRootFile=' + input, '-PreleaseTrustRootTestOnly=true', '--console=plain'];
    const debugAndroid = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'call', gradle, ...gradleArgs], { cwd: path.join(repo, 'android-app'), encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    assert.equal(debugAndroid.status, 0, `${debugAndroid.error?.message || ''}\n${debugAndroid.stdout || ''}\n${debugAndroid.stderr || ''}`);
    const generatedKt = path.join(repo, 'android-app', 'build', 'generated', 'source', 'bifrostTest', 'debug', 'com', 'bifrost', 'client', 'ReleaseTrustBinding.kt');
    assert.match(readFileSync(generatedKt, 'utf8'), /TRUST_ROOT_PROVISIONED\s*=\s*true/);
    const releaseAndroid = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'call', gradle, '--offline', '--no-daemon', 'assembleRelease', '-PreleaseTrustRootFile=' + input, '-PreleaseTrustRootTestOnly=true', '--console=plain'], { cwd: path.join(repo, 'android-app'), encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    assert.notEqual(releaseAndroid.status, 0, 'shipping Android Release must reject a TEST-ONLY trust root');
    const releaseCompile = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'call', gradle, '--offline', '--no-daemon', 'compileReleaseKotlin', '-PreleaseTrustRootFile=' + input, '-PreleaseTrustRootTestOnly=true', '--console=plain'], { cwd: path.join(repo, 'android-app'), encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    assert.notEqual(releaseCompile.status, 0, 'compileReleaseKotlin must reject a TEST-ONLY root without the corpus variant');
    const releaseWithVariant = spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'call', gradle, '--offline', '--no-daemon', 'compileReleaseKotlin', '-PbifrostTestVariant=true', '-PreleaseTrustRootFile=' + input, '-PreleaseTrustRootTestOnly=true', '--console=plain'], { cwd: path.join(repo, 'android-app'), encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    assert.notEqual(releaseWithVariant.status, 0, 'compileReleaseKotlin must not see a debug TEST binding even when the test property is supplied');
    writeFileSync(input, JSON.stringify({ key_id: 'bifrost-root-v1', purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: pem, fingerprint }), 'utf8');
    const rejected = spawnSync(process.execPath, [path.join(repo, 'tools', 'provision-release-root.mjs'), '--input', input, '--kotlin-output', kotlin], { encoding: 'utf8' });
    assert.notEqual(rejected.status, 0);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('generated JavaScript trust binding is consumed by the production verifier', async () => {
  const corpus = JSON.parse(readFileSync(path.join(repo, 'config-contracts', 'release-envelope-corpus-v2.json'), 'utf8'));
  const vector = corpus.vectors.find((candidate) => candidate.id === 'valid-complete-envelope');
  assert.ok(vector, 'complete TEST-ONLY envelope vector is required');
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-js-binding-'));
  try {
    const rootFile = path.join(temp, 'root.json');
    const bindingFile = path.join(temp, 'release-trust-binding.mjs');
    writeFileSync(rootFile, JSON.stringify(corpus.trust), 'utf8');
    const provision = spawnSync(process.execPath, [path.join(repo, 'tools', 'provision-release-root.mjs'), '--input', rootFile, '--test-only', '--javascript-output', bindingFile], { encoding: 'utf8' });
    assert.equal(provision.status, 0, provision.stderr);
    for (const file of ['release-contract.mjs', 'release-contract-internal.mjs', 'release-root-provision.mjs', 'release-contract-v1.json']) {
      writeFileSync(path.join(temp, file), readFileSync(path.join(repo, 'config-contracts', file)));
    }
    const production = await import(`${pathToFileURL(path.join(temp, 'release-contract.mjs')).href}?binding=${Date.now()}`);
    const verified = production.verifyReleaseEnvelope(vector.envelope, { channel: vector.execution.channel, currentClientVersion: vector.execution.client_version, currentConfigVersion: vector.execution.config_version });
    assert.equal(verified.manifest_digest, releaseManifestDigest(vector.envelope.manifest_text));
    assert.equal(verified.plan.root_fingerprint, corpus.trust.fingerprint);
    assert.equal(verified.plan.authority_digest, releaseKeyStateDigest(vector.envelope.key_state));
    assert.throws(() => production.verifyReleaseEnvelope(vector.envelope, { authority: { getRootKeyPem: () => corpus.trust.public_key_pem } }), /BF-RELEASE-TRUST-ROOT/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('shipping Release builds reject a TEST-ONLY trust binding flag', () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-release-shipping-'));
  try {
    const pair = generateKeyPairSync('ed25519');
    const pem = pair.publicKey.export({ type: 'spki', format: 'pem' });
    const input = path.join(temp, 'root.json');
    writeFileSync(input, JSON.stringify({ key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: pem, fingerprint: createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex') }), 'utf8');
    const dotnet = path.resolve(repo, '..', '..', 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
    const project = path.join(repo, 'windows-app', 'BifrostApp.csproj');
    const result = spawnSync(dotnet, ['build', project, '-c', 'Release', '--no-restore', `-p:BifrostReleaseTrustRootFile=${input}`, '-p:BifrostReleaseTrustRootTestOnly=true'], { encoding: 'utf8', timeout: 180000 });
    assert.notEqual(result.status, 0, 'shipping Release must not embed a TEST-ONLY root');
    assert.match(`${result.stdout}\n${result.stderr}`, /TEST-ONLY|shipping|BF-RELEASE-TEST-ROOT/i);
    const harness = spawnSync(dotnet, ['build', project, '-c', 'Release', '--no-restore', '-p:BifrostTestHarness=true', '-p:BifrostTestHarnessAllowRelease=true'], { encoding: 'utf8', timeout: 180000 });
    assert.notEqual(harness.status, 0, 'shipping Release must reject the public harness bypass flag');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('offline release-sign CLI performs a real TEST-ONLY old-to-new transition round-trip', () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), 'bifrost-release-cli-'));
  const releases = path.join(temp, 'releases'); const secrets = path.join(temp, 'secrets');
  const infraScript = path.resolve(repo, '..', 'bifrost-infra', 'scripts', 'release-sign.mjs');
  const root = generateKeyPairSync('ed25519'); const oldSigner = generateKeyPairSync('ed25519'); const newSigner = generateKeyPairSync('ed25519');
  const pem = (pair) => pair.publicKey.export({ type: 'spki', format: 'pem' });
  const fp = (pair) => createHash('sha256').update(pair.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
  const rootDescriptor = { key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: pem(root), fingerprint: fp(root) };
  const oldPem = pem(oldSigner); const newPem = pem(newSigner);
  const delegation = { root_key_id: 'bifrost-root-v1', key_id: 'bifrost-release-v2', purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: newPem, public_key_fingerprint: fp(newSigner), channel: 'test', activation_sequence: 2, retirement_sequence: 100, generation: 2 };
  const delegationBytes = Buffer.from(canonicalReleaseJson(delegation));
  const keyStateUnsigned = { root_key_id: 'bifrost-root-v1', generation: 2, channel: 'test', active_key_ids: ['bifrost-release-v2'], revoked_key_ids: ['bifrost-release-v1'] };
  const transitionUnsigned = { old_key_id: 'bifrost-release-v1', new_key_id: 'bifrost-release-v2', purpose: 'release-signing', algorithm: 'Ed25519', channel: 'test', from_generation: 1, to_generation: 2, activation_sequence: 2, retirement_sequence: 100, old_public_key_pem: oldPem, new_public_key_pem: newPem };
  const transition = { ...transitionUnsigned, old_signature: sign(null, Buffer.from(canonicalReleaseJson(transitionUnsigned)), oldSigner.privateKey).toString('base64url'), new_signature: sign(null, Buffer.from(canonicalReleaseJson(transitionUnsigned)), newSigner.privateKey).toString('base64url') };
  try {
    mkdirSync(releases, { recursive: true }); mkdirSync(secrets, { recursive: true });
    writeFileSync(path.join(temp, 'root.json'), JSON.stringify(rootDescriptor), 'utf8');
    writeFileSync(path.join(secrets, 'release-signing-private.pem'), newSigner.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    writeFileSync(path.join(releases, 'release-signing-public.pem'), newPem);
    writeFileSync(path.join(secrets, 'release-delegation.json'), JSON.stringify({ ...delegation, root_signature: sign(null, delegationBytes, root.privateKey).toString('base64url') }));
    writeFileSync(path.join(secrets, 'release-key-state.json'), JSON.stringify({ ...keyStateUnsigned, signature: sign(null, Buffer.from(canonicalReleaseJson(keyStateUnsigned)), root.privateKey).toString('base64url') }));
    writeFileSync(path.join(secrets, 'transition.json'), JSON.stringify(transition));
    const payload = Buffer.from('TEST-ONLY release cli artifact');
    writeFileSync(path.join(releases, 'app.bin'), payload); writeFileSync(path.join(releases, 'SOURCE-BUNDLE.txt'), Buffer.from('TEST-ONLY source')); writeFileSync(path.join(releases, 'LICENSES.txt'), Buffer.from('TEST-ONLY notice')); writeFileSync(path.join(releases, 'SBOM.json'), Buffer.from('{"sbom":"TEST-ONLY"}'));
    writeFileSync(path.join(releases, 'BUILD-MANIFEST.json'), JSON.stringify({ format: 'BIFROST-BUILD-MANIFEST-2', generated_at: '2026-01-01T00:00:00.000Z', configuration: 'TEST-ONLY', android_signing_scope: 'TEST-ONLY', android_signing_key_alias: 'TEST-ONLY', artifact_root: 'releases', artifacts: [{ id: 'app', path: 'app.bin', install_path: 'app.bin', platform: 'windows', arch: 'x64', kind: 'exe', bytes: payload.length, sha256: createHash('sha256').update(payload).digest('hex') }] }));
    const args = ['--root', temp, '--root-public-key-file', path.join(temp, 'root.json'), '--delegation-file', path.join(secrets, 'release-delegation.json'), '--key-state-file', path.join(secrets, 'release-key-state.json'), '--transition-file', path.join(secrets, 'transition.json'), '--test-only'];
    const env = { ...process.env, BIFROST_RELEASE_SEQUENCE: '2', BIFROST_RELEASE_CHANNEL: 'test', BIFROST_ROLLBACK_FLOOR: '1' };
    const create = spawnSync(process.execPath, [infraScript, 'create', ...args], { encoding: 'utf8', env, timeout: 120000 });
    assert.equal(create.status, 0, create.stderr || create.stdout);
    const verifyRun = spawnSync(process.execPath, [infraScript, 'verify', ...args], { encoding: 'utf8', env, timeout: 120000 });
    assert.equal(verifyRun.status, 0, verifyRun.stderr || verifyRun.stdout);
    const envelopePath = path.join(releases, 'RELEASE-ENVELOPE.json'); const envelope = JSON.parse(readFileSync(envelopePath, 'utf8'));
    envelope.transition_signature.new_signature = `${envelope.transition_signature.new_signature[0] === 'A' ? 'B' : 'A'}${envelope.transition_signature.new_signature.slice(1)}`;
    writeFileSync(envelopePath, JSON.stringify(envelope));
    const tampered = spawnSync(process.execPath, [infraScript, 'verify-envelope', ...args], { encoding: 'utf8', env, timeout: 120000 });
    assert.notEqual(tampered.status, 0, 'tampered transition must be rejected');
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
