// One-shot TEST-ONLY corpus generator.  It emits public material and signed
// envelopes only; private keys are held in memory and never written.  Each
// semantic vector is signed at the layer it exercises, while tamper vectors
// intentionally alter already-signed bytes.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { canonicalReleaseJson } from '../config-contracts/release-contract.mjs';

const source = JSON.parse(readFileSync(new URL('../config-contracts/release-envelope-corpus-v2.json', import.meta.url), 'utf8'));
// Deterministic TEST-ONLY Ed25519 fixtures.  The PKCS#8 seed bytes are test
// material, never a production root or release credential.  Determinism is
// required so `--check` can detect drift instead of rewriting the corpus with
// a fresh random trust root on every invocation.
const deterministicPair = (seedHex) => {
  const seed = Buffer.from(seedHex, 'hex');
  if (seed.length !== 32) throw new Error('TEST-ONLY seed length');
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
};
const rootPair = deterministicPair('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const releasePair = deterministicPair('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100');
const pem = (key) => key.export({ type: 'spki', format: 'pem' });
const fingerprint = (key) => createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
const rootPem = pem(rootPair.publicKey); const releasePem = pem(releasePair.publicKey);
const rootFp = fingerprint(rootPair.publicKey); const releaseFp = fingerprint(releasePair.publicKey);
const b64 = (bytes) => Buffer.from(bytes).toString('base64url');
const signText = (text, key) => b64(sign(null, Buffer.from(text, 'utf8'), key));

const baseManifest = JSON.parse(source.base_envelope.manifest_text);
// Every generated manifest carries the dependency-license binding so stable
// vectors exercise the same exact field set as the production release lane.
// The bytes are TEST-ONLY fixture material; production releases replace this
// with the digest of the signed generation's bound manifest.
Object.assign(baseManifest, {
  source_manifest_sha256: 'a'.repeat(64),
  build_plan_sha256: 'b'.repeat(64),
  source_policy_sha256: 'd'.repeat(64),
  core_provenance_sha256: 'e'.repeat(64),
  build_inputs_sha256: 'f'.repeat(64),
  toolchain_sha256: '1'.repeat(64),
  dependency_license_manifest_sha256: 'c'.repeat(64)
});
baseManifest.channel = 'test'; baseManifest.signing_key_id = 'bifrost-release-v1'; baseManifest.trust_root_key_id = 'bifrost-root-v1';
const delegationBase = { root_key_id: 'bifrost-root-v1', key_id: 'bifrost-release-v1', purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: releasePem, public_key_fingerprint: releaseFp, channel: 'test', activation_sequence: 1, retirement_sequence: 100, generation: 1 };
const keyStateBase = { root_key_id: 'bifrost-root-v1', generation: 1, channel: 'test', active_key_ids: ['bifrost-release-v1'], revoked_key_ids: [] };

function makeEnvelope({ manifest = baseManifest, delegation = delegationBase, keyState = keyStateBase, transitionSignature = null, rootSigner = rootPair.privateKey, releaseSigner = releasePair.privateKey, tamperSignature = false, tamperMessage = false, unknownManifest = false, unknownKeyState = false, unknownDelegation = false, nonCanonicalNumber = false, duplicateManifest = false } = {}) {
  const manifestValue = structuredClone(manifest);
  if (unknownManifest) manifestValue.extra = true;
  let manifestText = canonicalReleaseJson(manifestValue);
  if (nonCanonicalNumber) manifestText = manifestText.replace('"release_sequence":1', '"release_sequence":1.0');
  if (duplicateManifest) {
    const marker = '"release_sequence":'; const start = manifestText.indexOf(marker); const end = manifestText.indexOf(',', start);
    manifestText = `${manifestText.slice(0, end)},${manifestText.slice(start, end)}${manifestText.slice(end)}`;
  }
  const delegationValue = structuredClone(delegation); if (unknownDelegation) delegationValue.extra = true;
  const delegationBytes = Buffer.from(canonicalReleaseJson(delegationValue));
  const rootSignature = sign(null, delegationBytes, rootSigner).toString('base64url');
  const keyStateValue = structuredClone(keyState); if (unknownKeyState) keyStateValue.extra = true;
  const keyStateBytes = Buffer.from(canonicalReleaseJson(keyStateValue));
  keyStateValue.signature = sign(null, keyStateBytes, rootSigner).toString('base64url');
  let signature = signText(manifestText, releaseSigner);
  if (tamperSignature) signature = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
  if (tamperMessage) manifestText = manifestText.replace('"generated_at":"2026-01-01T00:00:00.000Z"', '"generated_at":"2026-01-01T00:00:01.000Z"');
  return { manifest_text: manifestText, signature, delegation: delegationValue, root_signature: rootSignature, key_state: keyStateValue, ...(transitionSignature ? { transition_signature: transitionSignature } : {}) };
}

const base = makeEnvelope();
const baseDigest = createHash('sha256').update(base.manifest_text).digest('hex');
const baseAuthorityDigest = createHash('sha256').update(canonicalReleaseJson(keyStateBase)).digest('hex');
const previous = { sequence: 1, manifest_digest: baseDigest, authority_generation: 1, authority_digest: baseAuthorityDigest, signing_key_id: 'bifrost-release-v1', signing_key_fingerprint: releaseFp };
const execution = (extra = {}) => ({ client_version: '0.1.0', config_version: 0, channel: 'test', previous_state: null, ...extra });
const vectors = [];
const add = (id, envelope, expected, error_family = null, exec = execution()) => vectors.push({ id, envelope, execution: exec, expected, error_family });
add('valid-complete-envelope', base, 'accept');
add('string-generation', makeEnvelope({ delegation: { ...delegationBase, generation: '1' } }), 'reject', 'BF-RELEASE-KEY');
add('unknown-delegation-field', makeEnvelope({ unknownDelegation: true }), 'reject', 'BF-RELEASE-FIELDS');
add('manifest-unknown-field', makeEnvelope({ unknownManifest: true }), 'reject', 'BF-RELEASE-FIELDS');
add('key-state-unknown-field', makeEnvelope({ unknownKeyState: true }), 'reject', 'BF-RELEASE-FIELDS');
add('tampered-release-signature', makeEnvelope({ tamperSignature: true }), 'reject', 'BF-RELEASE-SIGNATURE');
add('tampered-release-message', makeEnvelope({ tamperMessage: true }), 'reject', 'BF-RELEASE-SIGNATURE');
add('revoked-signer', makeEnvelope({ keyState: { ...keyStateBase, active_key_ids: [], revoked_key_ids: ['bifrost-release-v1'] } }), 'reject', 'BF-RELEASE-KEY-STATE');
add('not-active-signer', makeEnvelope({ keyState: { ...keyStateBase, active_key_ids: ['bifrost-release-v2'] } }), 'reject', 'BF-RELEASE-KEY-STATE');
add('manifest-delegation-mismatch', makeEnvelope({ manifest: { ...baseManifest, signing_key_id: 'bifrost-release-v2' } }), 'reject', 'BF-RELEASE-KEY');
add('minimum-config-too-new', makeEnvelope({ manifest: { ...baseManifest, minimum_config_version: 1 } }), 'reject', 'BF-RELEASE-MIN-CONFIG-VERSION');
add('minimum-client-too-new', makeEnvelope({ manifest: { ...baseManifest, minimum_client_version: '9.0.0' } }), 'reject', 'BF-RELEASE-MIN-VERSION');
add('rollback-floor-invalid', makeEnvelope({ manifest: { ...baseManifest, rollback_floor: 999 } }), 'reject', 'BF-RELEASE-METADATA');
add('noncanonical-manifest-number', makeEnvelope({ nonCanonicalNumber: true }), 'reject', 'BF-RELEASE-FIELDS');
add('duplicate-manifest-key', makeEnvelope({ duplicateManifest: true }), 'reject', 'BF-RELEASE-DUPLICATE-KEY');
add('authority-rollback', base, 'reject', 'BF-RELEASE-AUTHORITY-ROLLBACK', execution({ previous_state: { ...previous, authority_generation: 2 } }));
add('authority-same-generation-equivocation', base, 'reject', 'BF-RELEASE-AUTHORITY-EQUIVOCATION', execution({ previous_state: { ...previous, authority_digest: '0'.repeat(64) } }));
add('same-sequence-idempotent', base, 'idempotent', null, execution({ previous_state: previous }));
const nextManifest = { ...baseManifest, minimum_config_version: 0, generated_at: '2026-01-02T00:00:00.000Z' };
const next = makeEnvelope({ manifest: nextManifest });
add('same-sequence-different-digest', next, 'reject', 'BF-RELEASE-EQUIVOCATION', execution({ previous_state: previous }));
add('wrong-channel-runtime', base, 'reject', 'BF-RELEASE-METADATA', execution({ channel: 'stable' }));
add('direct-root-no-delegation', { manifest_text: base.manifest_text, signature: base.signature, root_signature: base.root_signature, key_state: base.key_state }, 'reject', 'BF-RELEASE-FIELDS');

// Stable-channel exact payload-set vectors.  These are complete, correctly
// signed envelopes; only the signed manifest payload-set differs.
const artifact = (id, platform, arch, kind) => ({ id, path: `${platform}/${id}.bin`, install_path: `${platform}/${id}.bin`, platform, arch, kind, bytes: 1, sha256: '00'.repeat(32), source_bundle: 'source', notice: 'notice', dependencies: [] });
const stableArtifacts = [
  artifact('app', 'windows', 'x64', 'exe'), artifact('service', 'windows', 'x64', 'service-exe'), artifact('installer', 'windows', 'x64', 'installer'), artifact('mihomo', 'windows', 'x64', 'core'), artifact('geosite', 'windows', 'x64', 'core'), artifact('geoip', 'windows', 'x64', 'core'), artifact('core-manifest', 'windows', 'x64', 'core-manifest'), artifact('install-metadata', 'windows', 'x64', 'metadata'),
  artifact('android-arm64-v8a-apk', 'android', 'arm64-v8a', 'apk'), artifact('android-armeabi-v7a-apk', 'android', 'armeabi-v7a', 'apk'), artifact('android-x86_64-apk', 'android', 'x86_64', 'apk'), artifact('source', 'windows', 'any', 'source'), artifact('notice', 'windows', 'any', 'notice')
];
const stableManifest = { ...baseManifest, channel: 'stable', release_sequence: 4, signing_key_id: 'bifrost-release-v1', trust_root_key_id: 'bifrost-root-v1', build: { ...baseManifest.build, artifacts: stableArtifacts } };
const stableDelegation = { ...delegationBase, channel: 'stable' };
const stableKeyState = { ...keyStateBase, channel: 'stable' };
add('stable-exact-set-valid', makeEnvelope({ manifest: stableManifest, delegation: stableDelegation, keyState: stableKeyState }), 'accept', null, execution({ channel: 'stable' }));
add('stable-windows-only-valid', makeEnvelope({ manifest: { ...stableManifest, build: { ...stableManifest.build, artifacts: stableArtifacts.filter((item) => item.platform !== 'android') } }, delegation: stableDelegation, keyState: stableKeyState }), 'accept', null, execution({ channel: 'stable' }));
add('stable-android-only-valid', makeEnvelope({ manifest: { ...stableManifest, build: { ...stableManifest.build, artifacts: stableArtifacts.filter((item) => item.platform === 'android' || item.kind === 'source' || item.kind === 'notice') } }, delegation: stableDelegation, keyState: stableKeyState }), 'accept', null, execution({ channel: 'stable' }));
add('stable-exact-set-extra', makeEnvelope({ manifest: { ...stableManifest, build: { ...stableManifest.build, artifacts: [...stableArtifacts, artifact('unexpected', 'windows', 'x64', 'exe')] } }, delegation: stableDelegation, keyState: stableKeyState }), 'reject', 'BF-RELEASE-WINDOWS-SET', execution({ channel: 'stable' }));
add('stable-exact-set-missing', makeEnvelope({ manifest: { ...stableManifest, build: { ...stableManifest.build, artifacts: stableArtifacts.filter((item) => item.id !== 'mihomo') } }, delegation: stableDelegation, keyState: stableKeyState }), 'reject', 'BF-RELEASE-WINDOWS-SET', execution({ channel: 'stable' }));

// A real old->new release-key transition: both keys sign the same canonical
// transition bytes and the new authority generation is persisted in the
// envelope.  Missing and tampered transitions are separate negative vectors.
const release2Pair = deterministicPair('11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff');
const release2Pem = pem(release2Pair.publicKey); const release2Fp = fingerprint(release2Pair.publicKey);
const delegation2 = { ...delegationBase, key_id: 'bifrost-release-v2', public_key_pem: release2Pem, public_key_fingerprint: release2Fp, generation: 2 };
const keyState2Unsigned = { root_key_id: 'bifrost-root-v1', generation: 2, channel: 'test', active_key_ids: ['bifrost-release-v2'], revoked_key_ids: ['bifrost-release-v1'] };
const transitionUnsigned = { old_key_id: 'bifrost-release-v1', new_key_id: 'bifrost-release-v2', purpose: 'release-signing', algorithm: 'Ed25519', channel: 'test', from_generation: 1, to_generation: 2, activation_sequence: 2, retirement_sequence: 100, old_public_key_pem: releasePem, new_public_key_pem: release2Pem };
const transition = { ...transitionUnsigned, old_signature: sign(null, Buffer.from(canonicalReleaseJson(transitionUnsigned)), releasePair.privateKey).toString('base64url'), new_signature: sign(null, Buffer.from(canonicalReleaseJson(transitionUnsigned)), release2Pair.privateKey).toString('base64url') };
const transitionManifest = { ...baseManifest, release_sequence: 2, generated_at: '2026-01-03T00:00:00.000Z', signing_key_id: 'bifrost-release-v2' };
const transitionEnvelope = makeEnvelope({ manifest: transitionManifest, delegation: delegation2, keyState: keyState2Unsigned, transitionSignature: transition, releaseSigner: release2Pair.privateKey });
const transitionPrevious = { ...previous };
add('transition-valid-old-new', transitionEnvelope, 'accept', null, execution({ previous_state: transitionPrevious }));
add('transition-required-missing', makeEnvelope({ manifest: transitionManifest, delegation: delegation2, keyState: keyState2Unsigned, releaseSigner: release2Pair.privateKey }), 'reject', 'BF-RELEASE-TRANSITION', execution({ previous_state: transitionPrevious }));
add('transition-tampered-old-signature', { ...transitionEnvelope, transition_signature: { ...transition, old_signature: `${transition.old_signature[0] === 'A' ? 'B' : 'A'}${transition.old_signature.slice(1)}` } }, 'reject', 'BF-RELEASE-TRANSITION', execution({ previous_state: transitionPrevious }));

// Additional complete, independently signed semantic vectors.  These are
// intentionally assembled from the same production manifest/delegation
// helpers as the valid baseline; only signature/tamper vectors mutate signed
// bytes after signing.
add('numeric-generation-valid', base, 'accept');
add('decimal-generation-reject', { ...base, delegation: { ...delegationBase, generation: 1.5 } }, 'reject', 'BF-RELEASE-KEY');
const authority2 = { ...keyStateBase, generation: 2 };
const authority2Manifest = { ...baseManifest, release_sequence: 2, generated_at: '2026-01-04T00:00:00.000Z' };
add('authority-higher-generation', makeEnvelope({ manifest: authority2Manifest, keyState: authority2 }), 'accept', null, execution({ previous_state: previous }));
const baseBuild = structuredClone(baseManifest.build);
const withBuild = (mutate) => { const build = structuredClone(baseBuild); mutate(build.artifacts, build); return makeEnvelope({ manifest: { ...baseManifest, build } }); };
add('reference-missing', withBuild((artifacts) => { artifacts[0].source_bundle = 'missing-source'; }), 'reject', 'BF-RELEASE-METADATA');
add('reference-wrong-kind', withBuild((artifacts) => { artifacts[0].notice = artifacts[0].source_bundle; }), 'reject', 'BF-RELEASE-METADATA');
add('dependency-cycle', withBuild((artifacts) => { artifacts[0].dependencies = ['source']; artifacts[1].dependencies = ['android-arm64-v8a-apk']; }), 'reject', 'BF-RELEASE-METADATA');
add('dependency-platform-mismatch', withBuild((artifacts) => {
  artifacts.push({ id: 'foreign-core', path: 'windows/foreign-core.bin', install_path: 'windows/foreign-core.bin', platform: 'windows', arch: 'x64', kind: 'core', bytes: 1, sha256: '00'.repeat(32), source_bundle: 'source', notice: 'notice', dependencies: [] });
  artifacts[0].dependencies = ['foreign-core'];
}), 'reject', 'BF-RELEASE-METADATA');
add('transition-wrong-old-id', { ...transitionEnvelope, transition_signature: { ...transition, old_key_id: 'bifrost-release-v9' } }, 'reject', 'BF-RELEASE-TRANSITION', execution({ previous_state: transitionPrevious }));
add('transition-wrong-new-id', { ...transitionEnvelope, transition_signature: { ...transition, new_key_id: 'bifrost-release-v9' } }, 'reject', 'BF-RELEASE-TRANSITION', execution({ previous_state: transitionPrevious }));
add('transition-bad-new-signature', { ...transitionEnvelope, transition_signature: { ...transition, new_signature: `${transition.new_signature[0] === 'A' ? 'B' : 'A'}${transition.new_signature.slice(1)}` } }, 'reject', 'BF-RELEASE-TRANSITION', execution({ previous_state: transitionPrevious }));
add('transition-outside-window', { ...transitionEnvelope, transition_signature: { ...transition, retirement_sequence: 2 } }, 'reject', 'BF-RELEASE-TRANSITION', execution({ previous_state: transitionPrevious }));
const spuriousTransition = { ...transition, new_key_id: 'bifrost-release-v2' };
add('transition-spurious-same-signer', { ...base, transition_signature: spuriousTransition }, 'reject', 'BF-RELEASE-TRANSITION');
add('missing-key-state', { manifest_text: base.manifest_text, signature: base.signature, delegation: base.delegation, root_signature: base.root_signature }, 'reject', 'BF-RELEASE-FIELDS');
add('corrupt-previous-state', base, 'reject', 'BF-RELEASE-STATE-CORRUPT', execution({ previous_state: { sequence: -1, manifest_digest: 'not-a-digest', authority_generation: 0, authority_digest: 'not-a-digest' }, state_status: 'corrupt' }));

const output = { ...source, schema_version: 'bifrost.release.corpus.v3', trust: { key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: rootPem, fingerprint: rootFp }, base_envelope: base, vectors };
const outputText = `${JSON.stringify(output, null, 2)}\n`;
const outputUrl = new URL('../config-contracts/release-envelope-corpus-v2.json', import.meta.url);
const resourceUrl = new URL('../android-app/src/test/resources/com/bifrost/client/release-envelope-corpus-v2.json', import.meta.url);
if (process.argv.includes('--check')) {
  const current = readFileSync(outputUrl, 'utf8');
  const resource = readFileSync(resourceUrl, 'utf8');
  if (current !== outputText || resource !== outputText) throw new Error('release corpus is stale; run the TEST-ONLY generator');
  process.stdout.write(`release corpus check vectors=${vectors.length} root=${rootFp}\n`);
} else {
  writeFileSync(outputUrl, outputText, 'utf8');
  writeFileSync(resourceUrl, outputText, 'utf8');
  process.stdout.write(`generated release corpus vectors=${vectors.length} root=${rootFp}\n`);
}
