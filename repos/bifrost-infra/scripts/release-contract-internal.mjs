import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isProvisionedReleaseRoot } from './release-root-provision.mjs';
import { COMPILED_RELEASE_TRUST_ROOT } from './release-trust-binding.mjs';

const sourcePath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'release-contract-v1.json');
export const RELEASE_CONTRACT = Object.freeze(JSON.parse(readFileSync(sourcePath, 'utf8')));
// The ceremony has not happened in this tree.  Deliberately do not expose a
// test key here: production consumers must fail closed until a protected
// build-time provisioning artifact is supplied.
export const RELEASE_TRUST_ROOT = Object.freeze(RELEASE_CONTRACT.trust_root);
const VERIFIED_PLAN_BRAND = Symbol('BifrostVerifiedReleasePlan');

const SAFE_INT = (value) => Number.isSafeInteger(value);
const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const GENERATION = /^[A-Za-z0-9._-]{1,96}$/;
const REFERENCE = /^[A-Za-z0-9._-]{1,128}$/;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function error(code) { throw new Error(code); }

export function strictUtf8(value) {
  const bytes = Buffer.isBuffer(value) ? Buffer.from(value) : (typeof value === 'string' ? Buffer.from(value, 'utf8') : error('BF-RELEASE-UTF8'));
  if (Buffer.from(bytes.toString('utf8'), 'utf8').compare(bytes) !== 0) error('BF-RELEASE-UTF8');
  return bytes;
}

export function assertNoDuplicateKeys(text) {
  const source = Buffer.isBuffer(text) ? strictUtf8(text).toString('utf8') : String(text);
  const stack = []; let i = 0;
  const skip = () => { while (i < source.length && /\s/.test(source[i])) i += 1; };
  const string = () => { if (source[i] !== '"') error('BF-RELEASE-JSON'); i += 1; let out = ''; while (i < source.length) { const c = source[i++]; if (c === '"') return out; if (c === '\\') { if (i >= source.length) error('BF-RELEASE-JSON'); const e = source[i++]; if (e === 'u') { const h = source.slice(i, i + 4); if (!/^[0-9a-f]{4}$/i.test(h)) error('BF-RELEASE-JSON'); i += 4; out += `\\u${h}`; } else out += `\\${e}`; } else { if (c.charCodeAt(0) < 0x20) error('BF-RELEASE-JSON'); out += c; } } error('BF-RELEASE-JSON'); };
  const value = () => { skip(); const c = source[i]; if (c === '"') { string(); return; } if (c === '{') { i += 1; const keys = new Set(); skip(); if (source[i] === '}') { i += 1; return; } while (i < source.length) { skip(); const key = string(); if (keys.has(key)) error('BF-RELEASE-DUPLICATE-KEY'); keys.add(key); skip(); if (source[i++] !== ':') error('BF-RELEASE-JSON'); value(); skip(); if (source[i] === '}') { i += 1; return; } if (source[i++] !== ',') error('BF-RELEASE-JSON'); } error('BF-RELEASE-JSON'); } if (c === '[') { i += 1; skip(); if (source[i] === ']') { i += 1; return; } while (i < source.length) { value(); skip(); if (source[i] === ']') { i += 1; return; } if (source[i++] !== ',') error('BF-RELEASE-JSON'); } error('BF-RELEASE-JSON'); } const token = source.slice(i).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/)?.[0]; if (!token) error('BF-RELEASE-JSON'); i += token.length; };
  value(); skip(); if (i !== source.length) error('BF-RELEASE-JSON'); return true;
}

export function canonicalReleaseJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') { if (!SAFE_INT(value)) error('BF-RELEASE-FIELDS'); return String(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalReleaseJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalReleaseJson(value[key])}`).join(',')}}`;
  error('BF-RELEASE-FIELDS');
}

export const RELEASE_CONTRACT_FINGERPRINT = createHash('sha256').update(canonicalReleaseJson(RELEASE_CONTRACT)).digest('hex');

export function assertCanonicalReleaseNumbers(text) {
  const source = String(text); let i = 0;
  while (i < source.length) { if (source[i] === '"') { i += 1; while (i < source.length) { const c = source[i++]; if (c === '\\') i += source[i] === 'u' ? 4 : 1; else if (c === '"') break; } continue; } if (source[i] === '-' || /[0-9]/.test(source[i])) { const start = i++; while (i < source.length && /[0-9.eE+-]/.test(source[i])) i += 1; const token = source.slice(start, i); if (!/^(?:0|-?[1-9][0-9]*)$/.test(token) || !SAFE_INT(Number(token))) error('BF-RELEASE-FIELDS'); continue; } i += 1; }
  return true;
}

export function releaseManifestDigest(manifestText) { return createHash('sha256').update(strictUtf8(manifestText)).digest('hex'); }
function publicKeyFingerprint(pem) { return createHash('sha256').update(createPublicKey(String(pem)).export({ type: 'spki', format: 'der' })).digest('hex'); }
function exact(value, allowed, required) { if (!value || typeof value !== 'object' || Array.isArray(value)) error('BF-RELEASE-FIELDS'); const keys = Object.keys(value); if (keys.some((key) => !allowed.includes(key)) || required.some((key) => !keys.includes(key))) error('BF-RELEASE-FIELDS'); }

function assertProvisionedReleaseRoot(value) {
  if (!isProvisionedReleaseRoot(value)) error('BF-RELEASE-TRUST-ROOT');
  if (value.key_id !== RELEASE_TRUST_ROOT.key_id || value.purpose !== RELEASE_TRUST_ROOT.purpose || value.algorithm !== RELEASE_TRUST_ROOT.algorithm || typeof value.public_key_pem !== 'string' || !HEX64.test(String(value.fingerprint || ''))) error('BF-RELEASE-TRUST-ROOT');
  let key;
  try { key = createPublicKey(value.public_key_pem); } catch { error('BF-RELEASE-TRUST-ROOT'); }
  if (key.asymmetricKeyType !== 'ed25519' || publicKeyFingerprint(value.public_key_pem) !== value.fingerprint) error('BF-RELEASE-TRUST-ROOT');
  return value;
}

// Shipping JS (when this tool-only updater is deliberately provisioned for a
// release) consumes a generated compile-time binding.  It must not use the
// WeakSet/tool brand, because that brand is intentionally private to the
// offline ceremony loader.  The generated binding is still validated as a
// complete Ed25519 descriptor and cannot be supplied through verifier
// options.
function assertCompiledReleaseRoot(value) {
  if (!value || typeof value !== 'object' || value.provenance !== 'compiled-trust-binding') error('BF-RELEASE-TRUST-ROOT');
  if (value.key_id !== RELEASE_TRUST_ROOT.key_id || value.purpose !== RELEASE_TRUST_ROOT.purpose || value.algorithm !== RELEASE_TRUST_ROOT.algorithm || typeof value.public_key_pem !== 'string' || !HEX64.test(String(value.fingerprint || ''))) error('BF-RELEASE-TRUST-ROOT');
  let key;
  try { key = createPublicKey(value.public_key_pem); } catch { error('BF-RELEASE-TRUST-ROOT'); }
  if (key.asymmetricKeyType !== 'ed25519' || publicKeyFingerprint(value.public_key_pem) !== value.fingerprint) error('BF-RELEASE-TRUST-ROOT');
  return value;
}

export function canonicalReleaseKeyDelegation(delegation) {
  const required = RELEASE_CONTRACT.envelope.delegation_required;
  exact(delegation, required, required);
  if (!KEY_ID.test(String(delegation.root_key_id)) || !KEY_ID.test(String(delegation.key_id)) || delegation.root_key_id !== RELEASE_TRUST_ROOT.key_id || delegation.purpose !== RELEASE_CONTRACT.trust_root.delegation_purpose || delegation.algorithm !== 'Ed25519' || !RELEASE_CONTRACT.manifest.channels.includes(delegation.channel) || !SAFE_INT(delegation.activation_sequence) || delegation.activation_sequence < 1 || !SAFE_INT(delegation.retirement_sequence) || delegation.retirement_sequence <= delegation.activation_sequence || !SAFE_INT(delegation.generation) || delegation.generation < 1) error('BF-RELEASE-KEY');
  let key; try { key = createPublicKey(String(delegation.public_key_pem)); } catch { error('BF-RELEASE-KEY'); }
  if (key.asymmetricKeyType !== 'ed25519' || !HEX64.test(String(delegation.public_key_fingerprint)) || delegation.public_key_fingerprint !== publicKeyFingerprint(delegation.public_key_pem)) error('BF-RELEASE-KEY');
  return canonicalReleaseJson(delegation);
}

function authorizeReleaseSigningKey({ delegation, rootSignature, rootDescriptor, releaseSequence, channel }) {
  const rootKeyPem = rootDescriptor?.public_key_pem;
  if (!rootKeyPem) error('BF-RELEASE-TRUST-ROOT');
  const bytes = Buffer.from(canonicalReleaseKeyDelegation(delegation), 'utf8');
  if (delegation.channel !== channel || !SAFE_INT(releaseSequence) || releaseSequence < delegation.activation_sequence || releaseSequence >= delegation.retirement_sequence) error('BF-RELEASE-KEY');
  const signature = Buffer.from(String(rootSignature || ''), 'base64url');
  if (signature.length !== 64) error('BF-RELEASE-KEY');
  let root; try { root = createPublicKey(rootKeyPem); } catch { error('BF-RELEASE-TRUST-ROOT'); }
  if (!verify(null, bytes, root, signature)) error('BF-RELEASE-KEY');
  return createPublicKey(delegation.public_key_pem);
}

/** Root-authoritative key state.  A release signer cannot revoke itself by
 * adding a field to its own manifest; only this separately root-signed object
 * changes the accepted key set. */
export function validateReleaseKeyState(keyState, { rootDescriptor, rootMode = 'provisioned', previousGeneration = 0, previousDigest, channel, signingKeyId, expectedRootKeyId = RELEASE_TRUST_ROOT.key_id } = {}) {
  if (!keyState || typeof keyState !== 'object' || Array.isArray(keyState)) error('BF-RELEASE-KEY-STATE');
  exact(keyState, ['root_key_id', 'generation', 'channel', 'active_key_ids', 'revoked_key_ids', 'signature'], ['root_key_id', 'generation', 'channel', 'active_key_ids', 'revoked_key_ids', 'signature']);
  const canonicalIds = (value) => Array.isArray(value) && value.every((id) => typeof id === 'string' && KEY_ID.test(id)) && value.every((id, index) => index === 0 || value[index - 1] < id);
  if (keyState.root_key_id !== expectedRootKeyId || !SAFE_INT(keyState.generation) || keyState.generation < 1 || keyState.generation < previousGeneration || (keyState.generation === previousGeneration && previousDigest && previousDigest !== releaseKeyStateDigest(keyState)) || !RELEASE_CONTRACT.manifest.channels.includes(keyState.channel) || (channel && channel !== keyState.channel) || !canonicalIds(keyState.active_key_ids) || keyState.active_key_ids.length < 1 || !canonicalIds(keyState.revoked_key_ids) || new Set([...keyState.active_key_ids, ...keyState.revoked_key_ids]).size !== keyState.active_key_ids.length + keyState.revoked_key_ids.length || typeof keyState.signature !== 'string') error('BF-RELEASE-KEY-STATE');
  if (signingKeyId && (!keyState.active_key_ids.includes(signingKeyId) || keyState.revoked_key_ids.includes(signingKeyId))) error('BF-RELEASE-KEY-STATE');
  const root = rootMode === 'compiled' ? assertCompiledReleaseRoot(rootDescriptor) : assertProvisionedReleaseRoot(rootDescriptor);
  if (root.key_id !== expectedRootKeyId) error('BF-RELEASE-TRUST-ROOT');
  const signed = { root_key_id: keyState.root_key_id, generation: keyState.generation, channel: keyState.channel, active_key_ids: keyState.active_key_ids, revoked_key_ids: keyState.revoked_key_ids };
  const signature = Buffer.from(keyState.signature, 'base64url');
  let rootKey; try { rootKey = createPublicKey(root.public_key_pem); } catch { error('BF-RELEASE-KEY-STATE'); }
  if (signature.length !== 64 || !verify(null, Buffer.from(canonicalReleaseJson(signed)), rootKey, signature)) error('BF-RELEASE-KEY-STATE');
  return deepFreeze({ ...keyState });
}

export function releaseKeyStateDigest(keyState) {
  if (!keyState || typeof keyState !== 'object') error('BF-RELEASE-KEY-STATE');
  const signed = { root_key_id: keyState.root_key_id, generation: keyState.generation, channel: keyState.channel, active_key_ids: keyState.active_key_ids, revoked_key_ids: keyState.revoked_key_ids };
  return createHash('sha256').update(canonicalReleaseJson(signed)).digest('hex');
}

export function validateReleaseTransition(transition, { channel, keyStateGeneration, signingKeyId, signingKeyFingerprint, previousSigningKeyId, previousSigningKeyFingerprint, releaseSequence } = {}) {
  const allowed = ['old_key_id', 'new_key_id', 'purpose', 'algorithm', 'channel', 'from_generation', 'to_generation', 'activation_sequence', 'retirement_sequence', 'old_public_key_pem', 'new_public_key_pem', 'old_signature', 'new_signature'];
  exact(transition, allowed, allowed);
  if (!KEY_ID.test(String(transition.old_key_id)) || !KEY_ID.test(String(transition.new_key_id)) || transition.old_key_id === transition.new_key_id || (signingKeyId && transition.new_key_id !== signingKeyId) || (previousSigningKeyId && transition.old_key_id !== previousSigningKeyId) || transition.purpose !== 'release-signing' || transition.algorithm !== 'Ed25519' || !RELEASE_CONTRACT.manifest.channels.includes(transition.channel) || (channel && transition.channel !== channel) || !SAFE_INT(transition.from_generation) || !SAFE_INT(transition.to_generation) || transition.from_generation < 1 || transition.to_generation !== transition.from_generation + 1 || (keyStateGeneration !== undefined && transition.to_generation !== keyStateGeneration) || !SAFE_INT(transition.activation_sequence) || !SAFE_INT(transition.retirement_sequence) || transition.activation_sequence < 1 || transition.retirement_sequence <= transition.activation_sequence || (releaseSequence !== undefined && (releaseSequence < transition.activation_sequence || releaseSequence >= transition.retirement_sequence))) error('BF-RELEASE-TRANSITION');
  let oldKey; let newKey;
  try { oldKey = createPublicKey(String(transition.old_public_key_pem)); newKey = createPublicKey(String(transition.new_public_key_pem)); } catch { error('BF-RELEASE-TRANSITION'); }
  if (oldKey.asymmetricKeyType !== 'ed25519' || newKey.asymmetricKeyType !== 'ed25519' || (previousSigningKeyFingerprint && publicKeyFingerprint(transition.old_public_key_pem) !== previousSigningKeyFingerprint) || (signingKeyFingerprint && publicKeyFingerprint(transition.new_public_key_pem) !== signingKeyFingerprint) || !/^[A-Za-z0-9_-]{86}$/.test(String(transition.old_signature)) || !/^[A-Za-z0-9_-]{86}$/.test(String(transition.new_signature))) error('BF-RELEASE-TRANSITION');
  const unsigned = { old_key_id: transition.old_key_id, new_key_id: transition.new_key_id, purpose: transition.purpose, algorithm: transition.algorithm, channel: transition.channel, from_generation: transition.from_generation, to_generation: transition.to_generation, activation_sequence: transition.activation_sequence, retirement_sequence: transition.retirement_sequence, old_public_key_pem: transition.old_public_key_pem, new_public_key_pem: transition.new_public_key_pem };
  const bytes = Buffer.from(canonicalReleaseJson(unsigned), 'utf8');
  const oldSignature = Buffer.from(String(transition.old_signature), 'base64url'); const newSignature = Buffer.from(String(transition.new_signature), 'base64url');
  if (oldSignature.length !== 64 || newSignature.length !== 64 || !verify(null, bytes, oldKey, oldSignature) || !verify(null, bytes, newKey, newSignature)) error('BF-RELEASE-TRANSITION');
  return deepFreeze({ ...transition });
}

export function parseReleaseEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) error('BF-RELEASE-ENVELOPE');
  const required = RELEASE_CONTRACT.envelope.required; exact(envelope, [...RELEASE_CONTRACT.envelope.fields, 'key_state', 'transition_signature'], required);
  if (typeof envelope.manifest_text !== 'string' || typeof envelope.signature !== 'string' || typeof envelope.root_signature !== 'string' || !envelope.delegation || strictUtf8(envelope.manifest_text).length > RELEASE_CONTRACT.envelope.max_bytes) error('BF-RELEASE-ENVELOPE');
  canonicalReleaseKeyDelegation(envelope.delegation);
  return Object.freeze({ manifest_text: envelope.manifest_text, signature: envelope.signature, delegation: Object.freeze({ ...envelope.delegation }), root_signature: envelope.root_signature, ...(envelope.key_state ? { key_state: Object.freeze({ ...envelope.key_state }) } : {}), ...(envelope.transition_signature ? { transition_signature: envelope.transition_signature } : {}) });
}

export function safeReleasePath(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 240 || value.includes('\0') || value.includes(':') || value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value)) error('BF-RELEASE-PATH');
  const raw = value.replaceAll('\\', '/'); const parts = raw.split('/');
  if (raw.normalize('NFC') !== raw || parts.some((part) => !part || part === '.' || part === '..' || part.endsWith(' ') || part.endsWith('.') || /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i.test(part) || [...part].some((ch) => ch.charCodeAt(0) < 0x20))) error('BF-RELEASE-PATH');
  return raw;
}

function requiredStableReferences(manifest, artifact) { if (!REFERENCE.test(String(artifact.source_bundle || '')) || !REFERENCE.test(String(artifact.notice || '')) || !Array.isArray(artifact.dependencies) || artifact.dependencies.length > 32 || artifact.dependencies.some((id) => !REFERENCE.test(String(id)))) error('BF-RELEASE-METADATA'); }

export function validateReleaseManifest(manifest, { requireStableReferences = false, allowTestOnlyShape = false } = {}) {
  const required = RELEASE_CONTRACT.manifest.required;
  const optional = ['source_manifest_sha256', 'build_plan_sha256', 'source_policy_sha256', 'core_provenance_sha256', 'build_inputs_sha256', 'toolchain_sha256', 'dependency_license_manifest_sha256'];
  exact(manifest, [...required, ...optional], required);
  if (manifest.format !== RELEASE_CONTRACT.format || manifest.signing_algorithm !== 'Ed25519') error('BF-RELEASE-FORMAT');
  if (typeof manifest.generated_at !== 'string' || !Number.isFinite(Date.parse(manifest.generated_at))) error('BF-RELEASE-METADATA');
  if (!SAFE_INT(manifest.release_sequence) || manifest.release_sequence < 1) error('BF-RELEASE-SEQUENCE');
  if (typeof manifest.minimum_client_version !== 'string' || !SEMVER.test(manifest.minimum_client_version)) error('BF-RELEASE-MIN-VERSION');
  if (!SAFE_INT(manifest.minimum_config_version) || manifest.minimum_config_version < 0 || !RELEASE_CONTRACT.manifest.channels.includes(manifest.channel) || !SAFE_INT(manifest.rollback_floor) || manifest.rollback_floor < 1 || manifest.rollback_floor > manifest.release_sequence || !KEY_ID.test(String(manifest.signing_key_id)) || !KEY_ID.test(String(manifest.trust_root_key_id)) || manifest.trust_root_key_id !== RELEASE_TRUST_ROOT.key_id || !HEX64.test(String(manifest.sbom_sha256)) || !HEX64.test(String(manifest.licenses_sha256))) error('BF-RELEASE-METADATA');
  for (const field of optional) if (manifest[field] !== undefined && !HEX64.test(String(manifest[field]))) error('BF-RELEASE-METADATA');
  if (!allowTestOnlyShape && manifest.channel === 'stable') { const digestFields = new Set(['source_manifest_sha256', 'build_plan_sha256', 'source_policy_sha256', 'core_provenance_sha256', 'build_inputs_sha256', 'toolchain_sha256', 'dependency_license_manifest_sha256']); const missingStable = (RELEASE_CONTRACT.manifest.stable_required || []).filter((field) => !Object.prototype.hasOwnProperty.call(manifest, field) || (digestFields.has(field) && !HEX64.test(String(manifest[field] || '')))); if (missingStable.length) error('BF-RELEASE-METADATA'); }
  if (!/^bifrost-release-v[0-9]+$/.test(String(manifest.signing_key_id))) error('BF-RELEASE-KEY');
  if (!REFERENCE.test(String(manifest.source_bundle_id)) || !REFERENCE.test(String(manifest.notice_artifact_id))) error('BF-RELEASE-METADATA');
  const policy = manifest.rollback_policy; exact(policy, ['reject_sequence_below_last_seen', 'reject_config_version_below_rollback_floor'], ['reject_sequence_below_last_seen', 'reject_config_version_below_rollback_floor']); if (policy.reject_sequence_below_last_seen !== true || policy.reject_config_version_below_rollback_floor !== true) error('BF-RELEASE-METADATA');
  const build = manifest.build; exact(build, RELEASE_CONTRACT.build.required, RELEASE_CONTRACT.build.required); if (build.artifact_root !== 'releases' || !Array.isArray(build.artifacts) || build.artifacts.length < 1 || build.artifacts.length > RELEASE_CONTRACT.build.max_artifacts) error('BF-RELEASE-BUILD');
  const ids = new Set(); const paths = new Set(); const installs = new Set(); let total = 0;
  for (const artifact of build.artifacts) {
    const artifactAllowed = RELEASE_CONTRACT.artifact.required; exact(artifact, artifactAllowed, artifactAllowed);
    if (!REFERENCE.test(String(artifact.id)) || ids.has(artifact.id)) error('BF-RELEASE-ARTIFACT');
    ids.add(String(artifact.id));
    const p = safeReleasePath(artifact.path); const install = safeReleasePath(artifact.install_path); const pk = p.normalize('NFC').toLocaleLowerCase('en-US'); const ik = install.normalize('NFC').toLocaleLowerCase('en-US'); if (paths.has(pk) || installs.has(ik)) error('BF-RELEASE-PATH-COLLISION'); paths.add(pk); installs.add(ik);
    if (!RELEASE_CONTRACT.artifact.platforms.includes(artifact.platform) || !/^[A-Za-z0-9._-]+$/.test(String(artifact.arch)) || !RELEASE_CONTRACT.artifact.kinds.includes(artifact.kind) || !SAFE_INT(artifact.bytes) || artifact.bytes < 1 || artifact.bytes > RELEASE_CONTRACT.build.max_artifact_bytes || !HEX64.test(String(artifact.sha256)) || artifact.sha256 !== artifact.sha256.toLowerCase()) error('BF-RELEASE-ARTIFACT');
    if (requireStableReferences || manifest.channel === 'stable') requiredStableReferences(manifest, artifact);
    total += artifact.bytes; if (!SAFE_INT(total) || total > RELEASE_CONTRACT.build.max_total_bytes) error('BF-RELEASE-TOTAL-SIZE');
  }
  {
    if (!ids.has(manifest.source_bundle_id) || !ids.has(manifest.notice_artifact_id)) error('BF-RELEASE-METADATA');
    const dependencyGraph = new Map();
    for (const artifact of build.artifacts) {
      if (!ids.has(String(artifact.source_bundle)) || !ids.has(String(artifact.notice)) || !Array.isArray(artifact.dependencies) || artifact.dependencies.length > 32 || artifact.dependencies.some((id) => !ids.has(String(id)) || String(id) === String(artifact.id))) error('BF-RELEASE-METADATA');
      const source = build.artifacts.find((candidate) => String(candidate.id) === String(artifact.source_bundle));
      const notice = build.artifacts.find((candidate) => String(candidate.id) === String(artifact.notice));
      if (!source || source.kind !== 'source' || !notice || notice.kind !== 'notice') error('BF-RELEASE-METADATA');
      for (const dependencyId of artifact.dependencies) {
        const dependency = build.artifacts.find((candidate) => String(candidate.id) === String(dependencyId));
        if (!dependency || (dependency.kind !== 'source' && dependency.kind !== 'notice' && (dependency.platform !== artifact.platform || dependency.arch !== artifact.arch))) error('BF-RELEASE-METADATA');
      }
      dependencyGraph.set(String(artifact.id), artifact.dependencies.map(String));
    }
    const visiting = new Set(); const visited = new Set();
    const visit = (id) => { if (visiting.has(id)) error('BF-RELEASE-METADATA'); if (visited.has(id)) return; visiting.add(id); for (const dep of dependencyGraph.get(id) || []) visit(dep); visiting.delete(id); visited.add(id); };
    for (const id of dependencyGraph.keys()) visit(id);
    const windows = build.artifacts.filter((a) => a.platform === 'windows' && a.arch === 'x64');
    const windowsPayload = windows.filter((a) => !['source', 'notice'].includes(a.kind));
    if (manifest.channel === 'stable') {
      const requiredIds = new Set(RELEASE_CONTRACT.required_sets['windows-x64']);
      const expectedKinds = new Map([
        ['app', 'exe'], ['service', 'service-exe'], ['installer', 'installer'],
        ['mihomo', 'core'], ['geosite', 'core'], ['geoip', 'core'],
        ['core-manifest', 'core-manifest'], ['install-metadata', 'metadata']
      ]);
      const idsForWindows = new Set(windowsPayload.map((a) => String(a.id)));
      const matchesProfile = windowsPayload.length === requiredIds.size && idsForWindows.size === requiredIds.size &&
        [...requiredIds].every((id) => idsForWindows.has(id)) &&
        windowsPayload.every((a) => expectedKinds.get(String(a.id)) === a.kind);
      if (windowsPayload.length > 0 && !matchesProfile) error('BF-RELEASE-WINDOWS-SET');
    }
    const android = build.artifacts.filter((a) => a.platform === 'android' && a.kind === 'apk');
    if (manifest.channel === 'stable') {
      const requiredAndroid = new Set(RELEASE_CONTRACT.required_sets.android);
      const androidPayload = build.artifacts.filter((a) => a.platform === 'android' && !['source', 'notice'].includes(a.kind));
      const androidIds = new Set(androidPayload.map((a) => String(a.id)));
      if (androidPayload.length > 0 && (androidPayload.length !== requiredAndroid.size || androidIds.size !== requiredAndroid.size || [...requiredAndroid].some((id) => !androidIds.has(id)) || [...requiredAndroid].some((id) => {
        const artifact = build.artifacts.find((candidate) => candidate.id === id);
        return !artifact || artifact.platform !== 'android' || artifact.kind !== 'apk' || id !== `android-${artifact.arch}-apk`;
      }))) error('BF-RELEASE-ANDROID-SET');
      if (windowsPayload.length === 0 && androidPayload.length === 0) error('BF-RELEASE-REQUIRED-SET');
    }
  }
  return manifest;
}

function verifyReleaseSignature(manifestText, signatureText, publicKeyPem) { if (!publicKeyPem) error('BF-RELEASE-TRUST-ROOT'); const payload = strictUtf8(manifestText); assertNoDuplicateKeys(payload); assertCanonicalReleaseNumbers(payload); if (!/^[A-Za-z0-9_-]{86}$/.test(String(signatureText || ''))) error('BF-RELEASE-SIGNATURE'); const signature = Buffer.from(String(signatureText), 'base64url'); if (signature.length !== 64 || !verify(null, payload, createPublicKey(publicKeyPem), signature)) error('BF-RELEASE-SIGNATURE'); return signature; }

function verifyReleaseEnvelopeWithRoot(envelope, { rootDescriptor, rootMode = 'provisioned', previousSequence = 0, previousManifestDigest = undefined, previousAuthorityGeneration = 0, previousAuthorityDigest, previousSigningKeyId, previousSigningKeyFingerprint, minimumSequence = 0, channel, currentClientVersion, currentConfigVersion, allowTestOnlyShape = false } = {}) {
  const root = rootMode === 'compiled' ? assertCompiledReleaseRoot(rootDescriptor) : assertProvisionedReleaseRoot(rootDescriptor);
  const parsed = parseReleaseEnvelope(envelope); const manifest = JSON.parse(parsed.manifest_text); validateReleaseManifest(manifest, { allowTestOnlyShape }); if (channel && manifest.channel !== channel) error('BF-RELEASE-METADATA');
  if (currentClientVersion && SEMVER.test(String(manifest.minimum_client_version)) && compareSemver(currentClientVersion, manifest.minimum_client_version) < 0) error('BF-RELEASE-MIN-VERSION');
  if (currentConfigVersion !== undefined && (!SAFE_INT(currentConfigVersion) || manifest.minimum_config_version > currentConfigVersion)) error('BF-RELEASE-MIN-CONFIG-VERSION');
  const manifestDigest = releaseManifestDigest(parsed.manifest_text); if (manifest.release_sequence < Math.max(previousSequence, minimumSequence) || (manifest.release_sequence === previousSequence && previousManifestDigest !== manifestDigest)) error(manifest.release_sequence === previousSequence ? 'BF-RELEASE-EQUIVOCATION' : 'BF-RELEASE-ROLLBACK');
  if (manifest.signing_key_id !== parsed.delegation.key_id || manifest.trust_root_key_id !== parsed.delegation.root_key_id || parsed.delegation.channel !== manifest.channel || parsed.delegation.root_key_id !== root.key_id) error('BF-RELEASE-KEY');
  authorizeReleaseSigningKey({ delegation: parsed.delegation, rootSignature: parsed.root_signature, rootDescriptor: root, releaseSequence: manifest.release_sequence, channel: manifest.channel });
  if (!parsed.key_state) error('BF-RELEASE-KEY-STATE');
  // Classify authority monotonicity before validating the new state's member
  // set.  This keeps a validly signed older authority state distinguishable
  // from malformed key-state input and makes the state machine deterministic
  // across all consumers.
  if (previousAuthorityGeneration > 0 && parsed.key_state && SAFE_INT(parsed.key_state.generation)) {
    if (parsed.key_state.generation < previousAuthorityGeneration) error('BF-RELEASE-AUTHORITY-ROLLBACK');
    if (parsed.key_state.generation === previousAuthorityGeneration && previousAuthorityDigest && previousAuthorityDigest !== releaseKeyStateDigest(parsed.key_state)) error('BF-RELEASE-AUTHORITY-EQUIVOCATION');
  }
  const keyState = validateReleaseKeyState(parsed.key_state, { rootDescriptor: root, rootMode, previousGeneration: previousAuthorityGeneration, previousDigest: previousAuthorityDigest, channel: manifest.channel, signingKeyId: parsed.delegation.key_id, expectedRootKeyId: root.key_id });
  const signerFingerprint = publicKeyFingerprint(parsed.delegation.public_key_pem);
  if (previousSigningKeyFingerprint && previousAuthorityGeneration > 0 && signerFingerprint !== previousSigningKeyFingerprint && !parsed.transition_signature) error('BF-RELEASE-TRANSITION');
  const transition = parsed.transition_signature ? validateReleaseTransition(parsed.transition_signature, { channel: manifest.channel, keyStateGeneration: keyState.generation, signingKeyId: parsed.delegation.key_id, signingKeyFingerprint: signerFingerprint, previousSigningKeyId, previousSigningKeyFingerprint, releaseSequence: manifest.release_sequence }) : null;
  if (parsed.transition_signature && previousSigningKeyFingerprint && signerFingerprint === previousSigningKeyFingerprint) error('BF-RELEASE-TRANSITION');
  verifyReleaseSignature(parsed.manifest_text, parsed.signature, parsed.delegation.public_key_pem);
  const plan = buildVerifiedReleasePlan({ manifest, manifestText: parsed.manifest_text, delegation: parsed.delegation, signature: parsed.signature, rootSignature: parsed.root_signature, keyState, transitionSignature: transition, rootDescriptor: root, rootMode });
  return Object.freeze({ manifest, manifest_text: parsed.manifest_text, signature: parsed.signature, delegation: parsed.delegation, root_signature: parsed.root_signature, key_state: keyState, transition_signature: transition, sequence: manifest.release_sequence, manifest_digest: manifestDigest, idempotent: manifest.release_sequence === previousSequence, plan });
}

export function verifyReleaseEnvelope(envelope, options = {}) {
  if (Object.prototype.hasOwnProperty.call(options, 'authority') || Object.prototype.hasOwnProperty.call(options, 'publicKeyPem') || Object.prototype.hasOwnProperty.call(options, 'testOnly')) error('BF-RELEASE-TRUST-ROOT');
  const root = COMPILED_RELEASE_TRUST_ROOT.public_key_pem ? COMPILED_RELEASE_TRUST_ROOT : null;
  if (!root) error('BF-RELEASE-TRUST-ROOT');
  return verifyReleaseEnvelopeWithRoot(envelope, { ...options, rootDescriptor: root, rootMode: 'compiled' });
}

// Offline signer/tooling only.  This deliberately is not part of the shipping
// verifier API: production callers must use verifyReleaseEnvelope(), which
// resolves the compile-time trust binding and never accepts a caller supplied
// key/descriptor/callback.  Tooling imports this symbol through the explicit
// release-offline-verifier module, not through the client update manager.
export function verifyReleaseEnvelopeOfflineInternal(envelope, { rootDescriptor, ...options } = {}) {
  return verifyReleaseEnvelopeWithRoot(envelope, { ...options, rootDescriptor });
}

function compareSemver(left, right) {
  const parse = (value) => String(value).split('-', 1)[0].split('.').map((part) => Number(part));
  const a = parse(left); const b = parse(right); for (let i = 0; i < 3; i += 1) { if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) - (b[i] ?? 0); } return 0;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export function canonicalReleaseEnvelopeBytes({ manifest_text, signature, delegation, root_signature, key_state = null, transition_signature = null }) {
  const envelope = { manifest_text, signature, delegation, root_signature };
  if (key_state !== null) envelope.key_state = key_state;
  if (transition_signature !== null) envelope.transition_signature = transition_signature;
  return Buffer.from(canonicalReleaseJson(envelope), 'utf8');
}

export function fullReleaseEnvelopeDigest(envelope) {
  return createHash('sha256').update(canonicalReleaseEnvelopeBytes(envelope)).digest('hex');
}

export function classifyReleaseState(current, plan) {
  if (!current) return 'first-install';
  // The strict persisted reader calls validateReleaseState.  Keep this pure
  // classifier tolerant of the historical vector's compact shape so old
  // vectors can be compared without becoming a production persistence path.
  if (current.state_checksum !== undefined && current.envelope_digest !== undefined && current.root_fingerprint !== undefined && current.signing_key_fingerprint !== undefined && current.slot !== undefined) validateReleaseState(current);
  const sequence = Number(current.last_sequence ?? current.sequence);
  const digest = current.last_manifest_digest ?? current.manifest_digest;
  const floor = Number(current.floor ?? 0);
  if (!Number.isSafeInteger(sequence) || !HEX64.test(String(digest))) error('BF-RELEASE-STATE-CORRUPT');
  if (plan.sequence < sequence || plan.sequence < floor) return 'rollback';
  if (plan.sequence === sequence) return plan.manifest_digest === digest ? 'idempotent' : 'equivocation';
  return 'advance';
}

export function buildVerifiedReleasePlan({ manifest, manifestText, delegation, signature = '', rootSignature = '', keyState = null, transitionSignature = null, rootDescriptor = null, rootMode = 'provisioned' }) {
  const root = rootMode === 'compiled' ? assertCompiledReleaseRoot(rootDescriptor) : assertProvisionedReleaseRoot(rootDescriptor);
  const manifestDigest = releaseManifestDigest(manifestText);
  const allowlist = manifest.build.artifacts.map((artifact) => ({ ...artifact }));
  const allowlistDigest = createHash('sha256').update(canonicalReleaseJson(allowlist)).digest('hex');
  const envelopeDigest = fullReleaseEnvelopeDigest({ manifest_text: manifestText, signature, delegation, root_signature: rootSignature, key_state: keyState, transition_signature: transitionSignature });
  return deepFreeze({
    [VERIFIED_PLAN_BRAND]: true,
    type: 'BifrostVerifiedReleasePlan',
    envelope_digest: envelopeDigest,
    manifest_digest: manifestDigest,
    allowlist_digest: allowlistDigest,
    sequence: manifest.release_sequence,
    channel: manifest.channel ?? 'test',
    floor: manifest.rollback_floor ?? 1,
    minimum_client_version: manifest.minimum_client_version ?? '0.0.0',
    minimum_config_version: manifest.minimum_config_version ?? 0,
    root_key_id: root.key_id,
    root_fingerprint: root.fingerprint,
    authority_digest: keyState ? releaseKeyStateDigest(keyState) : null,
    authority_generation: keyState?.generation ?? null,
    delegation_generation: delegation?.generation ?? null,
    signing_key_id: delegation?.key_id ?? manifest.signing_key_id ?? null,
    signing_key_fingerprint: delegation?.public_key_pem ? publicKeyFingerprint(delegation.public_key_pem) : null,
    transition_signature: transitionSignature ? deepFreeze({ ...transitionSignature }) : null,
    artifacts: allowlist
  });
}

export function isVerifiedReleasePlan(value) { return Boolean(value && value[VERIFIED_PLAN_BRAND] === true && Object.isFrozen(value)); }

export function validateReleaseState(state, { allowMissing = false } = {}) {
  if (state === undefined || state === null) { if (allowMissing) return null; error('BF-RELEASE-STATE-CORRUPT'); }
  const required = RELEASE_CONTRACT.state.required;
  exact(state, required, required);
  if (!SAFE_INT(state.last_sequence) || state.last_sequence < 0 || !HEX64.test(String(state.last_manifest_digest)) || !HEX64.test(String(state.envelope_digest)) || !HEX64.test(String(state.authority_digest)) || !SAFE_INT(state.authority_generation) || state.authority_generation < 1 || !KEY_ID.test(String(state.root_key_id)) || !HEX64.test(String(state.root_fingerprint)) || !SAFE_INT(state.delegation_generation) || state.delegation_generation < 1 || !KEY_ID.test(String(state.key_id)) || !HEX64.test(String(state.signing_key_fingerprint)) || !RELEASE_CONTRACT.manifest.channels.includes(state.channel) || !SAFE_INT(state.floor) || state.floor < 1 || !SAFE_INT(state.state_generation) || state.state_generation < 1 || !HEX64.test(String(state.state_checksum)) || typeof state.slot !== 'string' || !/^[ab]$/.test(state.slot) || typeof state.updated_at !== 'string' || !Number.isFinite(Date.parse(state.updated_at))) error('BF-RELEASE-STATE-CORRUPT');
  const check = releaseStateChecksum(state);
  if (check !== state.state_checksum) error('BF-RELEASE-STATE-CORRUPT');
  return state;
}

export function releaseStateChecksum(state) {
  const { state_checksum: _ignoredChecksum, ...value } = state;
  return createHash('sha256').update(canonicalReleaseJson(value)).digest('hex');
}
