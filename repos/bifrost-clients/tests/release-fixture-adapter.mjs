// TEST-ONLY adapter.  It accepts the historical compact fixture shape and
// feeds the same strict manifest/signature/plan primitives used by the
// production verifier.  This file is never imported by the updater runtime.
import { validateReleaseManifest, releaseManifestDigest, buildVerifiedReleasePlan, canonicalReleaseKeyDelegation, canonicalReleaseEnvelopeBytes } from '../config-contracts/release-contract-tool.mjs';
import { markTestRoot } from './release-test-root.mjs';
import { createHash, createPublicKey, verify } from 'node:crypto';

function completeFixtureManifest(input) {
  const manifest = structuredClone(input);
  const payloads = Array.isArray(manifest.build?.artifacts) ? manifest.build.artifacts : [];
  const sourceBytes = Buffer.from('TEST-ONLY source bundle');
  const noticeBytes = Buffer.from('TEST-ONLY notice');
  const source = { id: 'TEST-ONLY-SOURCE', path: 'sources/TEST-ONLY-SOURCE.txt', install_path: 'sources/TEST-ONLY-SOURCE.txt', platform: 'windows', arch: 'x64', kind: 'source', bytes: sourceBytes.length, sha256: (awaitHash(sourceBytes)), source_bundle: 'TEST-ONLY-SOURCE', notice: 'TEST-ONLY-NOTICE', dependencies: [] };
  const notice = { id: 'TEST-ONLY-NOTICE', path: 'notices/TEST-ONLY-NOTICE.txt', install_path: 'notices/TEST-ONLY-NOTICE.txt', platform: 'windows', arch: 'x64', kind: 'notice', bytes: noticeBytes.length, sha256: (awaitHash(noticeBytes)), source_bundle: 'TEST-ONLY-SOURCE', notice: 'TEST-ONLY-NOTICE', dependencies: [] };
  const normalized = payloads.map((artifact, index) => ({
    id: `TEST-ONLY-ARTIFACT-${index}`,
    path: artifact.path,
    install_path: artifact.install_path,
    platform: artifact.platform,
    arch: artifact.arch,
    kind: artifact.kind,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
    source_bundle: 'TEST-ONLY-SOURCE',
    notice: 'TEST-ONLY-NOTICE',
    dependencies: []
  }));
  manifest.format ??= 'BIFROST-RELEASE-MANIFEST-2';
  manifest.generated_at ??= '2026-01-01T00:00:00.000Z';
  manifest.minimum_client_version ??= '0.1.0';
  manifest.minimum_config_version ??= 0;
  // Compact fixtures are intentionally not production stable releases.  Keep
  // the caller's original object untouched (the envelope helper still checks
  // its requested channel), but validate the completed copy on the TEST lane
  // so the production stable exact-set gate is never relaxed.
  manifest.channel = 'test';
  manifest.rollback_floor ??= 1;
  manifest.sbom_sha256 ??= 'a'.repeat(64);
  manifest.licenses_sha256 ??= 'b'.repeat(64);
  manifest.source_bundle_id = 'TEST-ONLY-SOURCE';
  manifest.notice_artifact_id = 'TEST-ONLY-NOTICE';
  manifest.signing_algorithm ??= 'Ed25519';
  manifest.signing_key_id ??= 'bifrost-release-v1';
  manifest.trust_root_key_id ??= 'bifrost-root-v1';
  manifest.rollback_policy ??= { reject_sequence_below_last_seen: true, reject_config_version_below_rollback_floor: true };
  manifest.build = {
    format: manifest.build.format ?? 'BIFROST-BUILD-MANIFEST-2',
    generated_at: manifest.build.generated_at ?? manifest.generated_at,
    configuration: manifest.build.configuration ?? 'TEST-ONLY',
    android_signing_scope: manifest.build.android_signing_scope ?? 'TEST-ONLY',
    android_signing_key_alias: manifest.build.android_signing_key_alias ?? 'TEST-ONLY',
    artifact_root: manifest.build.artifact_root ?? 'releases',
    artifacts: [source, notice, ...normalized]
  };
  return manifest;
}

function awaitHash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function validateFixtureManifest(manifest) {
  validateReleaseManifest(completeFixtureManifest(manifest));
  return true;
}

function verifyFixtureSignature(text, signatureText, pem) {
  const signature = Buffer.from(signatureText, 'base64url');
  if (signature.length !== 64 || !verify(null, Buffer.from(text, 'utf8'), createPublicKey(pem), signature)) throw new Error('BF-RELEASE-SIGNATURE');
}

export function verifyFixtureEnvelope(input, { rootKeyPem, previousSequence = 0, channel } = {}) {
  const manifestText = input.manifest_text ?? input.manifestText;
  const manifest = JSON.parse(manifestText);
  validateReleaseManifest(completeFixtureManifest(manifest));
  if (!input.delegation || !rootKeyPem) throw new Error('BF-RELEASE-TRUST-ROOT');
  const delegationBytes = Buffer.from(canonicalReleaseKeyDelegation(input.delegation), 'utf8');
  const rootSignature = Buffer.from(input.root_signature ?? input.rootSignature ?? '', 'base64url');
  if (rootSignature.length !== 64 || !verify(null, delegationBytes, createPublicKey(rootKeyPem), rootSignature)) throw new Error('BF-RELEASE-KEY');
  if (input.delegation.key_id !== manifest.signing_key_id || (channel && manifest.channel !== channel)) throw new Error('BF-RELEASE-KEY');
  if (manifest.release_sequence < previousSequence) throw new Error('BF-RELEASE-ROLLBACK');
  if (manifest.release_sequence === previousSequence) throw new Error('BF-RELEASE-EQUIVOCATION');
  verifyFixtureSignature(manifestText, input.signature ?? input.signatureText, input.delegation.public_key_pem);
  const digest = releaseManifestDigest(manifestText);
  const rootDescriptor = markTestRoot({ key_id: manifest.trust_root_key_id ?? 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: rootKeyPem, fingerprint: createHash('sha256').update(createPublicKey(rootKeyPem).export({ type: 'spki', format: 'der' })).digest('hex') });
  const plan = buildVerifiedReleasePlan({ manifest, manifestText, delegation: input.delegation, signature: input.signature ?? input.signatureText, rootSignature: input.root_signature ?? input.rootSignature, rootDescriptor });
  const testPlan = plan;
  const envelopeBytes = canonicalReleaseEnvelopeBytes({ manifest_text: manifestText, signature: input.signature ?? input.signatureText, delegation: input.delegation, root_signature: input.root_signature ?? input.rootSignature });
  return Object.freeze({ manifest, manifest_text: manifestText, signature: input.signature ?? input.signatureText, sequence: manifest.release_sequence, manifest_digest: digest, signing_key_id: manifest.signing_key_id, idempotent: manifest.release_sequence === previousSequence, plan: testPlan, envelope_bytes: envelopeBytes });
}

export function verifyFixtureRelease(input, { previousSequence = 0, minimumSequence = 0, channel } = {}) {
  previousSequence = Number(input.previousSequence ?? previousSequence) || 0;
  const manifest = JSON.parse(input.manifestText);
  validateReleaseManifest(completeFixtureManifest(manifest));
  if (channel && manifest.channel && channel !== manifest.channel) throw new Error('BF-RELEASE-METADATA');
  const digest = releaseManifestDigest(input.manifestText);
  if (manifest.release_sequence < Math.max(previousSequence, minimumSequence) || (manifest.release_sequence === previousSequence && (!input.previousManifestDigest || input.previousManifestDigest !== digest))) throw new Error('BF-RELEASE-ROLLBACK');
  verifyFixtureSignature(input.manifestText, input.signatureText, input.publicKeyPem);
  const rootDescriptor = markTestRoot({ key_id: manifest.trust_root_key_id ?? 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: input.publicKeyPem, fingerprint: createHash('sha256').update(createPublicKey(input.publicKeyPem).export({ type: 'spki', format: 'der' })).digest('hex') });
  const delegation = { root_key_id: rootDescriptor.key_id, key_id: manifest.signing_key_id || 'TEST-ONLY-release', purpose: 'release-signing', algorithm: 'Ed25519', public_key_pem: input.publicKeyPem, public_key_fingerprint: rootDescriptor.fingerprint, channel: manifest.channel || 'test', activation_sequence: manifest.release_sequence, retirement_sequence: manifest.release_sequence + 100, generation: 1 };
  const keyState = { root_key_id: rootDescriptor.key_id, generation: 1, channel: delegation.channel, active_key_ids: [delegation.key_id], revoked_key_ids: [] };
  const plan = buildVerifiedReleasePlan({ manifest, manifestText: input.manifestText, delegation, signature: input.signatureText, rootSignature: '', keyState, rootDescriptor });
  return Object.freeze({ manifest, manifest_text: input.manifestText, signature: input.signatureText, sequence: manifest.release_sequence, manifest_digest: digest, signing_key_id: manifest.signing_key_id || null, test_only: true, idempotent: manifest.release_sequence === previousSequence, plan, envelope_bytes: canonicalReleaseEnvelopeBytes({ manifest_text: input.manifestText, signature: input.signatureText, delegation, root_signature: '', key_state: keyState }) });
}
