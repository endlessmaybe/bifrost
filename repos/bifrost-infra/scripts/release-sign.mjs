import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, chmodSync, statSync, lstatSync, rmSync, renameSync, openSync, readSync, closeSync, mkdtempSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { RELEASE_TRUST_ROOT, safeReleasePath, validateReleaseManifest, canonicalReleaseKeyDelegation } from './release-contract-tool.mjs';
import { verifyOfflineReleaseEnvelope as verifyCanonicalReleaseEnvelope } from './release-offline-verifier.mjs';
import { readProvisionedReleaseRoot } from './release-root-provision.mjs';
import { verifyArchive as verifySourceArchive } from './source-bundle.mjs';
import { verifySbom as verifySignedSbom } from './license-sbom.mjs';
import { generateSbom } from './license-sbom.mjs';
import { binaryPlanDigest, canonicalBinaryPlan } from './release-plan.mjs';

const argument = (name, fallback) => { const index = process.argv.indexOf(name); return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback; };
const root = path.resolve(argument('--root', path.resolve(import.meta.dirname, '..', '..', '..')));
// Publishing Android must use its independent channel when present. Build and
// signing commands retain the historical releases/ workspace; this selection
// is limited to the read-only mirror-plan command.
const mirrorAndroidChannel = process.argv[2] === 'publish-plan' && argument('--platform', 'windows') === 'android'
  && existsSync(path.join(root, 'releases-android', 'current.json'));
const releases = path.join(root, mirrorAndroidChannel ? 'releases-android' : 'releases'); const secrets = path.join(root, 'secrets');
const configuredPrivatePath = argument('--private-key-file', process.env.BIFROST_RELEASE_SIGNING_PRIVATE_KEY_FILE);
const configuredPublicPath = argument('--public-key-file', process.env.BIFROST_RELEASE_SIGNING_PUBLIC_KEY_FILE);
const privatePath = configuredPrivatePath ? path.resolve(configuredPrivatePath) : path.join(secrets, 'release-signing-private.pem');
const publicPath = configuredPublicPath ? path.resolve(configuredPublicPath) : path.join(releases, 'release-signing-public.pem');
const manifestPath = path.join(releases, 'RELEASE-MANIFEST.json'); const sigPath = path.join(releases, 'RELEASE-MANIFEST.sig');
const envelopePath = path.join(releases, 'RELEASE-ENVELOPE.json');
const generationRoot = path.join(releases, 'generations');
const currentPointerPath = path.join(releases, 'current.json');
const testRootFlag = () => process.argv.includes('--test-only');
// A TEST-ONLY root may be used by an isolated fixture, but this explicit
// semantic lane deliberately runs the same production source/SBOM/contract
// validators.  It never changes the shipping updater graph.
const semanticTestLane = () => process.argv.includes('--test-only-production-semantics');
const semanticTestOnly = () => testRootFlag() && !semanticTestLane();

function resolveReleaseFiles() {
  if (existsSync(currentPointerPath)) {
    let pointer;
    try { pointer = JSON.parse(strictUtf8(readFileSync(currentPointerPath))); } catch { throw new Error('BF-RELEASE-STATE'); }
    if (!pointer || pointer.format !== 'BIFROST-RELEASE-CURRENT-1' || typeof pointer.generation !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(pointer.generation) || !Array.isArray(pointer.files) || pointer.files.length !== 5) throw new Error('BF-RELEASE-STATE');
    const generation = path.join(generationRoot, pointer.generation); const paths = { generation };
    for (const name of ['manifest', 'signature', 'envelope', 'sbom', 'licenses']) {
      const row = pointer.files.find((item) => item?.kind === name);
      if (!row || typeof row.path !== 'string' || path.isAbsolute(row.path) || row.path.includes('..') || !row.path.startsWith(`generations/${pointer.generation}/`)) throw new Error('BF-RELEASE-STATE');
      const file = path.resolve(releases, row.path); if (!file.startsWith(`${generation}${path.sep}`) || !existsSync(file) || !lstatSync(file).isFile()) throw new Error('BF-RELEASE-STATE');
      const identity = fileDigest(file); if (identity.bytes !== row.bytes || identity.sha256 !== row.sha256) throw new Error('BF-RELEASE-STATE');
      paths[name] = file;
    }
    return paths;
  }
  return { generation: releases, manifest: manifestPath, signature: sigPath, envelope: envelopePath, sbom: path.join(releases, 'SBOM.json'), licenses: path.join(releases, 'LICENSES.txt') };
}
function fileDigest(file, maxBytes = 1024 * 1024 * 1024) {
  const descriptor = openSync(file, 'r'); const digest = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024); let total = 0;
  try { while (true) { const count = readSync(descriptor, buffer, 0, buffer.length, null); if (count === 0) break; total += count; if (total > maxBytes) throw new Error('BF-RELEASE-ARTIFACT-SIZE'); digest.update(buffer.subarray(0, count)); } }
  finally { closeSync(descriptor); }
  return { bytes: total, sha256: digest.digest('hex') };
}
// No production ceremony artifact is present in this tree.  Signing and
// verification therefore remain explicitly pending instead of trusting a
// test vector or a mutable package file.
const PRODUCTION_ROOT_READY = RELEASE_TRUST_ROOT.status !== 'PENDING-EXTERNAL-CEREMONY' && typeof RELEASE_TRUST_ROOT.public_key_pem === 'string';
function requireProvisionedRoot() {
  if (PRODUCTION_ROOT_READY) return readProvisionedReleaseRoot(RELEASE_TRUST_ROOT.path);
  const rootFile = argument('--root-public-key-file');
  try { return readProvisionedReleaseRoot(rootFile, { testOnly: testRootFlag() }); } catch { throw new Error('BF-RELEASE-TRUST-ROOT'); }
}
function strictUtf8(bytes) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const text = decoder.decode(bytes);
  if (!Buffer.from(text, 'utf8').equals(Buffer.from(bytes))) throw new Error('release manifest is not canonical UTF-8');
  return text;
}
function assertNoDuplicateKeys(text) {
  let index = 0;
  const skip = () => { while (/\s/.test(text[index] || '')) index += 1; };
  const stringEnd = () => { if (text[index] !== '"') throw new Error('release JSON string expected'); index += 1; while (index < text.length) { const ch = text[index++]; if (ch === '\\') { if (index >= text.length) throw new Error('release JSON escape truncated'); index += text[index] === 'u' ? 5 : 1; } else if (ch === '"') return; else if (ch < ' ') throw new Error('release JSON control character'); } throw new Error('release JSON string truncated'); };
  const value = () => { skip(); if (text[index] === '"') { stringEnd(); return; } if (text[index] === '{') { object(); return; } if (text[index] === '[') { index += 1; skip(); if (text[index] === ']') { index += 1; return; } while (true) { value(); skip(); if (text[index] === ']') { index += 1; return; } if (text[index++] !== ',') throw new Error('release JSON array delimiter'); } } const start = index; while (index < text.length && !',]}'.includes(text[index]) && ![' ', '\t', '\r', '\n'].includes(text[index])) index += 1; if (index === start) throw new Error('release JSON value expected'); };
  const object = () => { index += 1; skip(); const seen = new Set(); if (text[index] === '}') { index += 1; return; } while (true) { const start = index; stringEnd(); const key = JSON.parse(text.slice(start, index)); if (seen.has(key)) throw new Error('release JSON duplicate property'); seen.add(key); skip(); if (text[index++] !== ':') throw new Error('release JSON object delimiter'); value(); skip(); if (text[index] === '}') { index += 1; return; } if (text[index++] !== ',') throw new Error('release JSON object delimiter'); skip(); } };
  value(); skip(); if (index !== text.length) throw new Error('release JSON trailing data');
}
const artifactPath = (relative, releaseRoot = releases) => {
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative) || /^[A-Za-z]:[\\/]/.test(relative)) throw new Error(`artifact path must be relative: ${relative}`);
  const resolved = path.resolve(releaseRoot, relative);
  const rootWithSep = `${releaseRoot}${path.sep}`;
  if (resolved !== releaseRoot && !resolved.startsWith(rootWithSep)) throw new Error(`artifact path escapes release root: ${relative}`);
  return resolved;
};
function assertNoSymlinkUnderRelease(resolved, releaseRoot = releases) {
  const relative = path.relative(releaseRoot, resolved);
  let current = releaseRoot;
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (lstatSync(current).isSymbolicLink()) throw new Error(`release artifact reparse path: ${relative}`);
  }
}
function validateBuild(build, releaseRoot = releases) {
  if (build?.format !== 'BIFROST-BUILD-MANIFEST-2') throw new Error('unsupported build manifest format');
  if (build.artifact_root !== 'releases' || !Array.isArray(build.artifacts) || build.artifacts.length === 0) throw new Error('build manifest artifact root/list is invalid');
  if (build.artifacts.length > 64) throw new Error('too many release artifacts');
  const paths = new Set(); const installPaths = new Set(); let total = 0;
  for (const artifact of build.artifacts) {
    if (!['android', 'windows', 'linux'].includes(artifact.platform) || !/^[A-Za-z0-9._-]+$/.test(String(artifact.arch || '')) || !['apk', 'exe', 'service-exe', 'installer', 'core', 'core-manifest', 'node-agent', 'metadata', 'notice', 'source'].includes(artifact.kind)) throw new Error(`release artifact platform/arch/kind metadata is invalid: ${artifact.path}`);
    const linuxMetadata = artifact.platform === 'linux';
    const expectedBaseKeys = linuxMetadata ? ['arch', 'bytes', 'install_path', 'kind', 'mode', 'owner', 'owner_gid', 'owner_uid', 'path', 'platform', 'sha256'] : ['arch', 'bytes', 'install_path', 'kind', 'path', 'platform', 'sha256'];
    const keys = Object.keys(artifact).sort();
    const hasReferences = artifact.source_bundle !== undefined || artifact.notice !== undefined || artifact.dependencies !== undefined;
    const expectedKeys = [...expectedBaseKeys, 'id', ...(hasReferences ? ['dependencies', 'notice', 'source_bundle'] : [])].sort();
    if (keys.join('|') !== expectedKeys.join('|') || (hasReferences && (!/^[A-Za-z0-9._-]{1,128}$/.test(String(artifact.source_bundle || '')) || !/^[A-Za-z0-9._-]{1,128}$/.test(String(artifact.notice || '')) || !Array.isArray(artifact.dependencies) || artifact.dependencies.some((value) => !/^[A-Za-z0-9._-]{1,128}$/.test(String(value))))) || (linuxMetadata && (!/^[0-7]{3,4}$/.test(String(artifact.mode)) || !/^[A-Za-z0-9._-]{1,64}$/.test(String(artifact.owner)) || !Number.isSafeInteger(artifact.owner_uid) || !Number.isSafeInteger(artifact.owner_gid) || artifact.owner_uid < 0 || artifact.owner_gid < 0))) throw new Error(`release artifact metadata shape is invalid: ${artifact.path}`);
    let normalizedPath;
    try { normalizedPath = safeReleasePath(artifact.path); } catch { throw new Error(`unsafe release artifact path: ${artifact.path}`); }
    const pathKey = normalizedPath.toLowerCase();
    if (paths.has(pathKey)) throw new Error(`duplicate release artifact path: ${artifact.path}`);
    paths.add(pathKey); artifact.path = normalizedPath;
    const resolved = artifactPath(artifact.path, releaseRoot); assertNoSymlinkUnderRelease(resolved, releaseRoot);
    if (!existsSync(resolved) || !statSync(resolved).isFile() || lstatSync(resolved).isSymbolicLink() || statSync(resolved).nlink > 1) throw new Error(`release artifact missing: ${artifact.path}`);
    const stat = statSync(resolved);
    const bytes = stat.size;
    if (bytes < 1 || bytes > 512 * 1024 * 1024) throw new Error(`release artifact size invalid: ${artifact.path}`);
    total += bytes; if (total > 1024 * 1024 * 1024) throw new Error('release artifact total size invalid');
    if (Number(artifact.bytes) !== bytes) throw new Error(`release artifact byte count mismatch: ${artifact.path}`);
    if (linuxMetadata && process.platform !== 'win32' && (stat.mode & 0o7777) !== parseInt(artifact.mode, 8)) throw new Error(`release artifact mode mismatch: ${artifact.path}`);
    const digest = fileDigest(resolved);
    if (digest.bytes !== bytes || String(artifact.sha256 || '').toLowerCase() !== digest.sha256) throw new Error(`release artifact digest mismatch: ${artifact.path}`);
    const target = String(artifact.install_path || '');
    let normalizedTarget;
    try { normalizedTarget = safeReleasePath(target); } catch { throw new Error(`release install_path is unsafe: ${target}`); }
    artifact.install_path = normalizedTarget;
    const installKey = normalizedTarget.toLowerCase();
    if (installPaths.has(installKey)) throw new Error(`duplicate release install_path: ${normalizedTarget}`);
    installPaths.add(installKey);
  }
  return build;
}
function ensureKey() {
  mkdirSync(secrets, { recursive: true }); mkdirSync(releases, { recursive: true });
  const generate = process.argv.includes('--generate-key');
  if (generate) throw new Error('release signing keys are ceremony-provisioned; automatic generation is disabled (TEST-ONLY keys must use an explicit isolated harness)');
  if (configuredPrivatePath && !path.isAbsolute(configuredPrivatePath)) throw new Error('BF-RELEASE-KEY-PATH');
  if (configuredPublicPath && !path.isAbsolute(configuredPublicPath)) throw new Error('BF-RELEASE-KEY-PATH');
  if (!existsSync(privatePath) || !existsSync(publicPath)) throw new Error('release signing key pair is incomplete; provision the ceremony-managed key pair explicitly');
  const privateKey = createPrivateKey(readFileSync(privatePath)); const derived = createPublicKey(privateKey);
  const configured = createPublicKey(readFileSync(publicPath));
  if (privateKey.asymmetricKeyType !== 'ed25519' || configured.asymmetricKeyType !== 'ed25519' || derived.asymmetricKeyType !== 'ed25519') throw new Error('release signing key algorithm must be Ed25519');
  const expected = derived.export({ type: 'spki', format: 'der' }); const actual = configured.export({ type: 'spki', format: 'der' });
  if (!Buffer.from(expected).equals(Buffer.from(actual))) throw new Error('release signing public key does not match private key');
  return { privateKey, publicKey: configured, publicPem: readFileSync(publicPath, 'utf8') };
}
function readDelegation() {
  const delegationPath = argument('--delegation-file', path.join(secrets, 'release-delegation.json'));
  if (!path.isAbsolute(delegationPath) || !existsSync(delegationPath)) throw new Error('BF-RELEASE-KEY');
  const value = JSON.parse(readFileSync(delegationPath, 'utf8'));
  const required = ['root_key_id', 'key_id', 'purpose', 'algorithm', 'public_key_pem', 'public_key_fingerprint', 'channel', 'activation_sequence', 'retirement_sequence', 'generation', 'root_signature'];
  if (Object.keys(value).length !== required.length || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) throw new Error('BF-RELEASE-METADATA');
  const { root_signature: rootSignature, ...delegation } = value;
  if (typeof rootSignature !== 'string' || !rootSignature) throw new Error('BF-RELEASE-METADATA');
  canonicalReleaseKeyDelegation(delegation);
  const rootDescriptor = requireProvisionedRoot();
  return { delegation, rootSignature, rootDescriptor };
}
function readKeyState() {
  const file = argument('--key-state-file', path.join(secrets, 'release-key-state.json'));
  if (!path.isAbsolute(file) || !existsSync(file)) throw new Error('BF-RELEASE-KEY-STATE');
  const value = JSON.parse(readFileSync(file, 'utf8'));
  const required = ['root_key_id', 'generation', 'channel', 'active_key_ids', 'revoked_key_ids', 'signature'];
  if (!value || Object.keys(value).some((key) => !required.includes(key)) || required.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) || !Number.isSafeInteger(value.generation) || value.generation < 1 || !Array.isArray(value.active_key_ids) || !Array.isArray(value.revoked_key_ids) || new Set([...value.active_key_ids, ...value.revoked_key_ids]).size !== value.active_key_ids.length + value.revoked_key_ids.length) throw new Error('BF-RELEASE-KEY-STATE');
  return value;
}
function readTransition() {
  const file = argument('--transition-file');
  if (!file) return null;
  if (!path.isAbsolute(file) || !existsSync(file)) throw new Error('BF-RELEASE-TRANSITION');
  const value = JSON.parse(readFileSync(file, 'utf8'));
  if (!value || typeof value !== 'object') throw new Error('BF-RELEASE-TRANSITION');
  return value;
}

function releaseSequenceValue() {
  const value = Number(process.env.BIFROST_RELEASE_SEQUENCE || Date.now());
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('BF-RELEASE-SEQUENCE');
  return value;
}

function assertReleaseSequenceUnused(sequence) {
  if (!existsSync(generationRoot)) return;
  const prefix = `seq-${sequence}-`;
  for (const entry of readdirSync(generationRoot, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name.startsWith(prefix)) {
      // A release sequence is an anti-equivocation identity, not merely a
      // sortable build number.  Reusing it for another generation would make
      // already-installed clients correctly reject the later manifest.
      throw new Error('BF-RELEASE-SEQUENCE-REUSED');
    }
  }
}

function createRelease() {
  const rootDescriptor = requireProvisionedRoot();
  const testOnly = semanticTestOnly();
  const buildPath = path.resolve(argument('--draft-manifest', path.join(releases, 'BUILD-MANIFEST.json')));
  const generationTestMode = testOnly && process.env.BIFROST_RELEASE_GENERATION_TEST === '1';
  const releaseSequence = releaseSequenceValue();
  const generationId = (!testOnly || generationTestMode) ? `seq-${releaseSequence}-${process.pid}` : null;
  if (generationId) assertReleaseSequenceUnused(releaseSequence);
  const generation = generationId ? path.join(generationRoot, generationId) : releases;
  const targetManifestPath = generationId ? path.join(generation, 'RELEASE-MANIFEST.json') : manifestPath;
  const targetSigPath = generationId ? path.join(generation, 'RELEASE-MANIFEST.sig') : sigPath;
  const targetEnvelopePath = generationId ? path.join(generation, 'RELEASE-ENVELOPE.json') : envelopePath;
  const sbomPath = path.join(generation, 'SBOM.json');
  const licensePath = path.join(generation, 'LICENSES.txt');
  const dependencyInput = argument('--dependency-license-manifest');
  if (!path.isAbsolute(buildPath) || !existsSync(buildPath)) throw new Error('BF-RELEASE-BUILD-MANIFEST');
  const build = validateBuild(JSON.parse(readFileSync(buildPath, 'utf8').replace(/^\uFEFF/, ''))); const keys = ensureKey(); const authorization = readDelegation(); const keyState = readKeyState(); const transition = readTransition();
  if (generationId) {
    mkdirSync(generationRoot, { recursive: true }); mkdirSync(generation, { recursive: false });
    for (const artifact of build.artifacts || []) {
      const source = path.resolve(releases, artifact.path); const target = path.resolve(generation, artifact.path);
      if (!source.startsWith(`${releases}${path.sep}`) || target === generation || !existsSync(source)) throw new Error('BF-RELEASE-ARTIFACT');
      mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(source, target);
    }
  }
  let dependencyPathForSbom = dependencyInput ? path.resolve(dependencyInput) : null;
  if (!testOnly && (!dependencyPathForSbom || !path.isAbsolute(dependencyPathForSbom) || !existsSync(dependencyPathForSbom))) throw new Error('BF-RELEASE-SBOM-LICENSE-MANIFEST');
  if (generationId && dependencyPathForSbom) {
    const stagedDependency = path.join(generation, 'build-inputs', 'dependency-license-manifest.json');
    mkdirSync(path.dirname(stagedDependency), { recursive: true }); copyFileSync(dependencyPathForSbom, stagedDependency); dependencyPathForSbom = stagedDependency;
  }
  const transactionFiles = [targetManifestPath, targetSigPath, targetEnvelopePath, sbomPath, licensePath];
  const previous = new Map(transactionFiles.map((file) => [file, existsSync(file) ? readFileSync(file) : null]));
  const restorePrevious = () => { for (const [file, bytes] of previous) { try { if (bytes === null) rmSync(file, { force: true }); else writeFileSync(file, bytes); } catch {} } if (generationId) { try { rmSync(generation, { recursive: true, force: true }); } catch {} } };
  try {
   let sourceArchive = existsSync(path.join(releases, 'SOURCE-BUNDLE.tar')) ? path.join(releases, 'SOURCE-BUNDLE.tar') : (testOnly ? path.join(releases, 'SOURCE-BUNDLE.txt') : null);
   let sourceManifestFile = path.join(releases, 'source-bundle-manifest.json');
  if (!sourceArchive || (!existsSync(sourceManifestFile) && !testOnly)) throw new Error('BF-RELEASE-SOURCE-BUNDLE');
  // Before a signature is created, verify the archive structure and exact
  // source manifest.  The subsequent signed envelope binds the resulting
  // archive bytes; no release can sign an unchecked sidecar.
   if (sourceManifestFile && existsSync(sourceManifestFile) && sourceArchive.endsWith('.tar')) verifySourceArchive(sourceArchive, sourceManifestFile, undefined, { allowTestOnly: true });
   else if (!testOnly) throw new Error('BF-RELEASE-SOURCE-BUNDLE');
   if (generationId) {
     const stagedSource = path.join(generation, path.basename(sourceArchive));
     const stagedManifest = path.join(generation, 'source-bundle-manifest.json');
     copyFileSync(sourceArchive, stagedSource); if (existsSync(sourceManifestFile)) copyFileSync(sourceManifestFile, stagedManifest);
     sourceArchive = stagedSource; sourceManifestFile = stagedManifest;
   }
  if (authorization.rootDescriptor.key_id !== rootDescriptor.key_id || authorization.rootDescriptor.fingerprint !== rootDescriptor.fingerprint || authorization.rootDescriptor.public_key_pem !== rootDescriptor.public_key_pem) throw new Error('BF-RELEASE-TRUST-ROOT');
  const windowsUpdateBaselineVersion = '2.1.44';
  const minimumClientVersion = process.env.BIFROST_MIN_CLIENT_VERSION || '0.1.0';
  const releaseChannel = process.env.BIFROST_RELEASE_CHANNEL || 'stable';
  const semverParts = (value) => String(value).split('.').map((part) => Number(part));
  const minimumParts = semverParts(minimumClientVersion);
  const baselineParts = semverParts(windowsUpdateBaselineVersion);
  const compareParts = (left, right) => {
    for (let index = 0; index < 3; index++) {
      if (left[index] !== right[index]) return left[index] - right[index];
    }
    return 0;
  };
  if (releaseChannel === 'stable' &&
      (minimumParts.length !== 3 || minimumParts.some((part) => !Number.isSafeInteger(part) || part < 0) ||
       compareParts(minimumParts, baselineParts) > 0)) throw new Error('BF-WINDOWS-UPDATE-BASELINE');
  const release = {
    format: 'BIFROST-RELEASE-MANIFEST-2',
    generated_at: new Date().toISOString(),
    release_sequence: releaseSequence,
    minimum_client_version: minimumClientVersion,
    build,
    sbom_sha256: '0'.repeat(64),
    licenses_sha256: '0'.repeat(64),
    signing_algorithm: 'Ed25519',
    channel: releaseChannel,
    minimum_config_version: Number(process.env.BIFROST_MIN_CONFIG_VERSION || 0),
    rollback_floor: Number(process.env.BIFROST_ROLLBACK_FLOOR || releaseSequence),
    signing_key_id: authorization.delegation.key_id,
    trust_root_key_id: authorization.delegation.root_key_id,
    rollback_policy: { reject_sequence_below_last_seen: true, reject_config_version_below_rollback_floor: true }
  };
  release.source_bundle_id = 'bifrost-release-source'; release.notice_artifact_id = 'bifrost-release-notice';
  release.build.artifacts = release.build.artifacts.map((artifact) => {
    if (typeof artifact.id !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(artifact.id)) throw new Error('BF-RELEASE-ARTIFACT-ID');
    return { ...artifact, source_bundle: artifact.source_bundle || 'bifrost-release-source', notice: artifact.notice || 'bifrost-release-notice', dependencies: Array.isArray(artifact.dependencies) ? artifact.dependencies : [] };
  });
  release.build.artifacts.sort((left, right) => String(left.id).localeCompare(String(right.id)));
   const sourceArchiveName = sourceArchive ? path.relative(generationId ? generation : releases, sourceArchive).replaceAll('\\', '/') : null;
   if (!sourceArchiveName) throw new Error('BF-RELEASE-SOURCE-BUNDLE');
   const sourceIdentity = fileDigest(sourceArchive);
   const noticeIdentity = existsSync(licensePath) ? fileDigest(licensePath) : { bytes: 0, sha256: '0'.repeat(64) };
   release.build.artifacts.push({ id: release.source_bundle_id, path: sourceArchiveName, install_path: sourceArchiveName, platform: 'windows', arch: 'x64', kind: 'source', bytes: sourceIdentity.bytes, sha256: sourceIdentity.sha256, source_bundle: release.source_bundle_id, notice: release.notice_artifact_id, dependencies: [] });
   release.build.artifacts.push({ id: release.notice_artifact_id, path: path.relative(generationId ? generation : releases, licensePath).replaceAll('\\', '/'), install_path: 'LICENSES.txt', platform: 'windows', arch: 'x64', kind: 'notice', bytes: noticeIdentity.bytes, sha256: noticeIdentity.sha256, source_bundle: release.source_bundle_id, notice: release.notice_artifact_id, dependencies: [] });
  if (existsSync(sourceManifestFile)) {
    const sourceManifestBytes = readFileSync(sourceManifestFile); const sourceManifest = JSON.parse(strictUtf8(sourceManifestBytes));
    if (!sourceManifest.build_plan_sha256 || !sourceManifest.binary_artifacts_sha256) throw new Error('BF-RELEASE-SOURCE-MANIFEST');
    release.source_manifest_sha256 = createHash('sha256').update(sourceManifestBytes).digest('hex');
    release.build_plan_sha256 = sourceManifest.build_plan_sha256;
    release.source_policy_sha256 = sourceManifest.policy_sha256;
    if (sourceManifest.core_provenance && sourceManifest.core_provenance.input_sha256) release.core_provenance_sha256 = sourceManifest.core_provenance.input_sha256;
    if (sourceManifest.build_inputs && sourceManifest.build_inputs.input_sha256) release.build_inputs_sha256 = sourceManifest.build_inputs.input_sha256;
    if (sourceManifest.toolchain_sha256) release.toolchain_sha256 = sourceManifest.toolchain_sha256;
    if (sourceManifest.dependency_license_manifest?.input_sha256) release.dependency_license_manifest_sha256 = sourceManifest.dependency_license_manifest.input_sha256;
     const planDigest = binaryPlanDigest(release.build.artifacts.filter((artifact) => !['source', 'notice'].includes(artifact.kind)));
    if (planDigest !== sourceManifest.build_plan_sha256 || planDigest !== sourceManifest.binary_artifacts_sha256) throw new Error('BF-RELEASE-SOURCE-MANIFEST');
  }
  // Build the SBOM only after the final source/notice artifact set exists.
  // The draft manifest is an input plan, not a signed authority; it lets the
  // generator resolve the exact artifact graph without a circular hash.
  // Generate the license inventory before its artifact hash is placed in the
  // signed plan.  The second production generation then verifies the exact
  // final artifact set and resolved graph.
   generateSbom({ root, releases, output: sbomPath, testOnly: true, writeInventoryOnly: true, licenseInventoryPath: licensePath, releaseManifestValue: release, sourceManifestPath: sourceManifestFile, sourceManifestEvidencePath: generationId ? 'source-bundle-manifest.json' : null, coreProvenancePath: argument('--core-provenance'), buildInputManifestPath: argument('--build-input-manifest'), dependencyLicenseManifestPath: dependencyPathForSbom });
   const noticeFile = licensePath; const noticeStat = statSync(noticeFile); const noticeBytes = readFileSync(noticeFile);
  const noticeArtifact = release.build.artifacts.find((artifact) => artifact.id === release.notice_artifact_id); if (!noticeArtifact) throw new Error('BF-RELEASE-NOTICE');
  noticeArtifact.bytes = noticeStat.size; noticeArtifact.sha256 = createHash('sha256').update(noticeBytes).digest('hex');
   generateSbom({ root, releases: generationId ? generation : releases, output: sbomPath, testOnly, licenseInventoryPath: licensePath, releaseManifestValue: release, sourceManifestPath: sourceManifestFile, sourceManifestEvidencePath: generationId ? 'source-bundle-manifest.json' : null, coreProvenancePath: argument('--core-provenance'), buildInputManifestPath: argument('--build-input-manifest'), dependencyLicenseManifestPath: dependencyPathForSbom, dependencyLicenseManifestEvidencePath: generationId ? 'build-inputs/dependency-license-manifest.json' : null });
  const sbom = readFileSync(sbomPath); release.sbom_sha256 = createHash('sha256').update(sbom).digest('hex'); release.licenses_sha256 = fileDigest(noticeFile).sha256;
  validateReleaseManifest(release, { requireStableReferences: release.channel === 'stable', allowTestOnlyShape: testOnly });
  const payload = Buffer.from(`${JSON.stringify(release, null, 2)}\n`, 'utf8'); const signatureText = sign(null, payload, keys.privateKey).toString('base64url');
  if (keyState.root_key_id !== authorization.delegation.root_key_id || keyState.channel !== release.channel || !keyState.active_key_ids.includes(authorization.delegation.key_id) || keyState.revoked_key_ids.includes(authorization.delegation.key_id)) throw new Error('BF-RELEASE-KEY-STATE');
  const envelope = { manifest_text: strictUtf8(payload), signature: signatureText, delegation: authorization.delegation, root_signature: authorization.rootSignature, key_state: keyState, ...(transition ? { transition_signature: transition } : {}) };
  verifyCanonicalReleaseEnvelope(envelope, { rootDescriptor, channel: release.channel, allowTestOnlyShape: testOnly });
  const envelopeBytes = Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
  // Read back through the same production verifiers before reporting success.
  // A malformed source/SBOM sidecar must never leave a release that appears
  // signed but cannot be consumed by the updater.
  if (!testOnly && sourceArchive.endsWith('.tar')) {
    try {
      const cleanParent = mkdtempSync(path.join(os.tmpdir(), 'bifrost-release-verify-')); const cleanRoot = path.join(cleanParent, 'unpacked');
      try {
        verifySourceArchive(sourceArchive, sourceManifestFile, cleanRoot, { allowTestOnly: false, sourceEnvelope: envelope, rootDescriptor, unpack: true });
        verifySignedSbom({ sbomPath, releases: generationId ? generation : releases, root, allowTestOnly: false, manifestValue: release, licenseInventoryPath: licensePath, dependencyLicenseManifestPath: path.join(cleanRoot, 'build-inputs', 'dependency-license-manifest.json'), boundGraphRoot: cleanRoot });
      } finally { rmSync(cleanParent, { recursive: true, force: true }); }
    } catch (error) {
      throw error;
    }
  }
  // Production publication is one generation plus one current-pointer
  // rename.  A crash before the pointer commit leaves the previous complete
  // generation authoritative; it can never expose a new manifest with an
  // older signature/SBOM sidecar.
  if (generationId) {
    const generationFiles = [[targetManifestPath, payload], [targetSigPath, Buffer.from(`${signatureText}\n`, 'utf8')], [targetEnvelopePath, envelopeBytes]];
    for (const [file, bytes] of generationFiles) writeFileSync(file, bytes, { flag: 'wx', mode: 0o644 });
    if (process.env.BIFROST_RELEASE_CRASH_POINT === 'before-pointer' && generationTestMode) process.exit(91);
    const pointer = { format: 'BIFROST-RELEASE-CURRENT-1', generation: generationId, files: [
      { kind: 'manifest', path: path.relative(releases, targetManifestPath).replaceAll('\\', '/'), ...fileDigest(targetManifestPath) },
      { kind: 'signature', path: path.relative(releases, targetSigPath).replaceAll('\\', '/'), ...fileDigest(targetSigPath) },
      { kind: 'envelope', path: path.relative(releases, targetEnvelopePath).replaceAll('\\', '/'), ...fileDigest(targetEnvelopePath) },
      { kind: 'sbom', path: path.relative(releases, sbomPath).replaceAll('\\', '/'), ...fileDigest(sbomPath) },
      { kind: 'licenses', path: path.relative(releases, licensePath).replaceAll('\\', '/'), ...fileDigest(licensePath) }
    ] };
    const pointerTemp = `${currentPointerPath}.next-${process.pid}`; writeFileSync(pointerTemp, `${JSON.stringify(pointer)}\n`, { flag: 'wx', mode: 0o644 }); renameSync(pointerTemp, currentPointerPath);
    return { generation: generationId, manifest: targetManifestPath, signature: targetSigPath, envelope: targetEnvelopePath, public_key: publicPath, current: currentPointerPath };
  }
  const next = [[manifestPath, `${manifestPath}.next-${process.pid}` , payload], [sigPath, `${sigPath}.next-${process.pid}`, Buffer.from(`${signatureText}\n`, 'utf8')], [envelopePath, `${envelopePath}.next-${process.pid}`, envelopeBytes]];
  try { for (const [, file, bytes] of next) writeFileSync(file, bytes, { flag: 'wx', mode: 0o644 }); for (const [target, file] of next.map(([target, file]) => [target, file])) renameSync(file, target); }
  catch (error) { for (const [, file] of next) rmSync(file, { force: true }); restorePrevious(); throw error; }
  return { manifest: manifestPath, signature: sigPath, envelope: envelopePath, public_key: publicPath };
  } catch (error) { restorePrevious(); throw error; }
}
function verifyRelease() {
  const testOnly = semanticTestOnly();
  const rootDescriptor = requireProvisionedRoot();
  const files = resolveReleaseFiles();
  // A committed generation is self-contained: the signed delegation inside
  // RELEASE-ENVELOPE carries the release public key and the protected root
  // descriptor authenticates it.  The legacy sidecar is required only for
  // the pre-generation layout; never make clean-room verification depend on
  // a file outside the selected generation.
  if (!existsSync(currentPointerPath) && !existsSync(publicPath)) throw new Error('release signature files are incomplete');
  const payload = readFileSync(files.manifest); const manifestText = strictUtf8(payload); assertNoDuplicateKeys(manifestText);
  const signatureBytes = readFileSync(files.signature); const signatureText = strictUtf8(signatureBytes).trim();
  const envelopeBytes = readFileSync(files.envelope); const envelope = JSON.parse(strictUtf8(envelopeBytes));
  if (envelope.manifest_text !== manifestText || envelope.signature !== signatureText) throw new Error('BF-RELEASE-METADATA');
  const verified = verifyCanonicalReleaseEnvelope(envelope, { rootDescriptor, channel: envelope.delegation?.channel, allowTestOnlyShape: testOnly });
  const manifest = verified.manifest; const releaseRoot = path.dirname(files.manifest); validateManifestShape(manifest); validateBuild(manifest.build, releaseRoot); validateReleaseManifest(manifest, { requireStableReferences: manifest.channel === 'stable', allowTestOnlyShape: testOnly });
  if (!existsSync(files.sbom) || fileDigest(files.sbom).sha256 !== manifest.sbom_sha256) throw new Error('release SBOM digest verification failed');
  const cleanParent = !testOnly ? mkdtempSync(path.join(os.tmpdir(), 'bifrost-release-verify-')) : null; const cleanRoot = cleanParent ? path.join(cleanParent, 'unpacked') : null;
  if (!existsSync(files.licenses) || fileDigest(files.licenses).sha256 !== manifest.licenses_sha256) throw new Error('release license inventory digest verification failed');
  const sourceArtifact = manifest.build.artifacts.find((artifact) => artifact.id === manifest.source_bundle_id && artifact.kind === 'source');
  const sourceManifestFile = path.join(path.dirname(files.manifest), 'source-bundle-manifest.json');
  if (!sourceArtifact || !existsSync(sourceManifestFile)) {
    if (!testOnly) throw new Error('BF-RELEASE-SOURCE-BUNDLE');
  } else {
    const sourceArchive = path.resolve(releaseRoot, sourceArtifact.path);
    if (cleanRoot) {
      try {
        verifySourceArchive(sourceArchive, sourceManifestFile, cleanRoot, { allowTestOnly: testOnly, sourceEnvelope: envelope, rootDescriptor, unpack: true });
        verifySignedSbom({ sbomPath: files.sbom, releases: releaseRoot, root, boundGraphRoot: cleanRoot, allowTestOnly: testOnly, manifestValue: manifest, licenseInventoryPath: files.licenses, dependencyLicenseManifestPath: path.join(cleanRoot, 'build-inputs', 'dependency-license-manifest.json') });
      } finally { rmSync(cleanParent, { recursive: true, force: true }); }
    } else verifySignedSbom({ sbomPath: files.sbom, releases: releaseRoot, root, boundGraphRoot: root, allowTestOnly: testOnly, manifestValue: manifest, licenseInventoryPath: files.licenses, dependencyLicenseManifestPath: argument('--dependency-license-manifest') });
  }
  const identities = {
    manifest: { bytes: payload.length, sha256: createHash('sha256').update(payload).digest('hex') },
    signature: { bytes: signatureBytes.length, sha256: createHash('sha256').update(signatureBytes).digest('hex') },
    envelope: { bytes: envelopeBytes.length, sha256: createHash('sha256').update(envelopeBytes).digest('hex') }
  };
  for (const kind of ['manifest', 'signature', 'envelope']) {
    const actual = fileDigest(files[kind]);
    if (actual.bytes !== identities[kind].bytes || actual.sha256 !== identities[kind].sha256) throw new Error('BF-RELEASE-STATE-CHANGED');
  }
  const result = { verified: true, manifest: files.manifest, envelope: files.envelope, public_key: publicPath, plan: verified.plan };
  Object.defineProperties(result, {
    snapshotFiles: { value: Object.freeze({ ...files }) },
    snapshotManifest: { value: manifest },
    snapshotVerified: { value: verified },
    snapshotIdentities: { value: Object.freeze(identities) }
  });
  return result;
}
function verifyEnvelopeFiles() {
  const testOnly = semanticTestOnly();
  const rootDescriptor = requireProvisionedRoot();
  const active = resolveReleaseFiles();
  const manifestTextPath = argument('--manifest-text-file'); const signaturePath = argument('--signature-file'); const sourceEnvelope = argument('--envelope-file', active.envelope);
  if (!existsSync(sourceEnvelope)) throw new Error('BF-RELEASE-ENVELOPE');
  const envelope = JSON.parse(readFileSync(sourceEnvelope, 'utf8'));
  const verified = verifyCanonicalReleaseEnvelope(envelope, { rootDescriptor, channel: envelope.delegation?.channel, allowTestOnlyShape: testOnly });
  if (manifestTextPath && strictUtf8(readFileSync(manifestTextPath)) !== verified.manifest_text) throw new Error('BF-RELEASE-METADATA');
  if (signaturePath && strictUtf8(readFileSync(signaturePath)).trim() !== verified.signature) throw new Error('BF-RELEASE-METADATA');
  return { manifest_text: verified.manifest_text, signature: verified.signature, manifest: verified.manifest, plan: verified.plan };
}
function validateManifestShape(manifest) {
  const testOnly = semanticTestOnly();
  const allowed = new Set(['format', 'generated_at', 'release_sequence', 'minimum_client_version', 'build', 'sbom_sha256', 'licenses_sha256', 'source_bundle_id', 'notice_artifact_id', 'signing_algorithm', 'rollback_policy', 'channel', 'minimum_config_version', 'rollback_floor', 'signing_key_id', 'trust_root_key_id', 'source_manifest_sha256', 'build_plan_sha256', 'source_policy_sha256', 'core_provenance_sha256', 'build_inputs_sha256', 'toolchain_sha256', 'dependency_license_manifest_sha256']);
  const keys = Object.keys(manifest || {});
  if (!manifest || keys.some((key) => !allowed.has(key)) || !['format', 'release_sequence', 'build', 'signing_algorithm'].every((key) => keys.includes(key)) || manifest.format !== 'BIFROST-RELEASE-MANIFEST-2' || manifest.signing_algorithm !== 'Ed25519') throw new Error('unsupported release manifest format');
  if (!Number.isSafeInteger(manifest.release_sequence) || manifest.release_sequence < 1 || !manifest.build || !/^[0-9a-f]{64}$/.test(String(manifest.sbom_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(manifest.licenses_sha256 || ''))) throw new Error('release manifest schema invalid');
  if (!testOnly && manifest.channel === 'stable' && ['source_manifest_sha256', 'build_plan_sha256', 'source_policy_sha256', 'core_provenance_sha256', 'build_inputs_sha256', 'toolchain_sha256', 'dependency_license_manifest_sha256'].some((key) => !/^[0-9a-f]{64}$/.test(String(manifest[key] || '')))) throw new Error('release manifest source binding is incomplete');
  if (!testOnly && manifest.build?.artifacts && binaryPlanDigest(manifest.build.artifacts.filter((artifact) => !['source', 'notice'].includes(artifact.kind))) !== manifest.build_plan_sha256) throw new Error('release manifest binary plan mismatch');
  return manifest;
}

const OFFLINE_ATTESTATION_DIRECTORY = '.offline-attestations';
const OFFLINE_ATTESTATION_FORMAT = 'BIFROST-OFFLINE-INSTALLER-ATTESTATION-1';

function exactKeys(value, expected, code = 'BF-OFFLINE-ATTESTATION') {
  const keys = Object.keys(value || {}).sort();
  if (!value || typeof value !== 'object' || Array.isArray(value) || keys.join('|') !== [...expected].sort().join('|')) throw new Error(code);
}

function releaseVersion(manifest, generation) {
  const metadata = (manifest.build?.artifacts || []).filter((artifact) => artifact.id === 'install-metadata');
  if (metadata.length !== 1) throw new Error('BF-OFFLINE-ATTESTATION-METADATA');
  const metadataPath = artifactPath(metadata[0].path, generation);
  assertNoSymlinkUnderRelease(metadataPath, generation);
  const metadataBytes = readFileSync(metadataPath);
  const metadataIdentity = { bytes: metadataBytes.length, sha256: createHash('sha256').update(metadataBytes).digest('hex') };
  if (metadataIdentity.bytes !== Number(metadata[0].bytes) || metadataIdentity.sha256 !== String(metadata[0].sha256 || '').toLowerCase()) throw new Error('BF-OFFLINE-ATTESTATION-METADATA');
  const value = JSON.parse(strictUtf8(metadataBytes).replace(/^\uFEFF/, ''));
  if (typeof value.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(value.version)) throw new Error('BF-OFFLINE-ATTESTATION-METADATA');
  return value.version;
}

function offlineInstallerPath(file, manifest, generation) {
  if (!file || !path.isAbsolute(file)) throw new Error('BF-OFFLINE-INSTALLER-PATH');
  const resolved = path.resolve(file); const dist = path.join(root, 'dist'); const relative = path.relative(dist, resolved);
  const parts = relative.split(path.sep);
  const directDeliverable = parts.length === 1;
  const pendingDeliverable = parts.length === 2 && /^\.offline-setup\.pending-[0-9]+-[0-9a-f]{32}$/.test(parts[0]);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative) || (!directDeliverable && !pendingDeliverable)) throw new Error('BF-OFFLINE-INSTALLER-PATH');
  const expectedVersion = releaseVersion(manifest, generation);
  const match = /^Bifrost-Offline-Setup-([0-9]+\.[0-9]+\.[0-9]+)-r([1-9][0-9]{0,15})-Windows-x64\.exe$/.exec(path.basename(resolved));
  if (!match || match[1] !== expectedVersion || Number(match[2]) !== manifest.release_sequence || !existsSync(resolved)) throw new Error('BF-OFFLINE-INSTALLER-PATH');
  assertNoSymlinkUnderRelease(resolved, dist);
  const descriptor = lstatSync(resolved);
  if (!descriptor.isFile() || descriptor.isSymbolicLink() || descriptor.nlink !== 1) throw new Error('BF-OFFLINE-INSTALLER-PATH');
  return { path: resolved, filename: path.basename(resolved), version: expectedVersion };
}

function offlineAttestationPath(manifest, generation, { createDirectory = false } = {}) {
  const version = releaseVersion(manifest, generation);
  const dist = path.join(root, 'dist');
  const directory = path.join(dist, OFFLINE_ATTESTATION_DIRECTORY);
  if (createDirectory) mkdirSync(directory, { recursive: true });
  if (!existsSync(dist) || !lstatSync(dist).isDirectory() || lstatSync(dist).isSymbolicLink()) throw new Error('BF-OFFLINE-ATTESTATION-PATH');
  if (existsSync(directory) && (!lstatSync(directory).isDirectory() || lstatSync(directory).isSymbolicLink())) throw new Error('BF-OFFLINE-ATTESTATION-PATH');
  const filename = `Bifrost-Offline-Setup-${version}-r${manifest.release_sequence}-Windows-x64.exe.attestation.json`;
  const target = path.resolve(directory, filename);
  if (path.dirname(target) !== path.resolve(directory)) throw new Error('BF-OFFLINE-ATTESTATION-PATH');
  return target;
}

function authenticatedCurrentRelease() {
  const snapshot = verifyRelease();
  const testPointerSwap = process.env.BIFROST_RELEASE_TEST_SWAP_CURRENT_AFTER_VERIFY;
  if (testRootFlag() && testPointerSwap) copyFileSync(path.resolve(testPointerSwap), currentPointerPath);
  const current = {
    files: snapshot.snapshotFiles,
    verified: snapshot.snapshotVerified,
    manifest: snapshot.snapshotManifest,
    identities: snapshot.snapshotIdentities
  };
  for (const kind of ['manifest', 'signature', 'envelope']) {
    const actual = fileDigest(current.files[kind]);
    const expected = current.identities[kind];
    if (actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) throw new Error('BF-RELEASE-STATE-CHANGED');
  }
  return current;
}

function createMirrorPublishPlan() {
  const current = authenticatedCurrentRelease();
  const platform = argument('--platform', 'windows');
  if (!['windows', 'android'].includes(platform)) throw new Error('BF-RELEASE-MIRROR-ARTIFACTS');
  const allowedKinds = new Set(['exe', 'service-exe', 'installer', 'core', 'core-manifest', 'metadata']);
  const artifacts = current.manifest.build.artifacts.filter((artifact) => platform === 'windows'
    ? artifact.platform === 'windows' && artifact.arch === 'x64' && allowedKinds.has(artifact.kind)
    : artifact.platform === 'android' && artifact.kind === 'apk' || artifact.id === current.manifest.source_bundle_id || artifact.id === current.manifest.notice_artifact_id);
  if (artifacts.length !== (platform === 'windows' ? 8 : 5)) throw new Error('BF-RELEASE-MIRROR-ARTIFACTS');
  const generation = current.files.generation;
  const prepared = artifacts.map((artifact) => {
    const source = artifactPath(artifact.path, generation); assertNoSymlinkUnderRelease(source, generation);
    const actual = fileDigest(source);
    if (actual.bytes !== Number(artifact.bytes) || actual.sha256 !== String(artifact.sha256 || '').toLowerCase()) throw new Error('BF-RELEASE-STATE-CHANGED');
    return { source, path: artifact.path, bytes: actual.bytes, sha256: actual.sha256, leaf: `${path.basename(artifact.path)}.bin` };
  });
  return {
    format: 'BIFROST-RELEASE-MIRROR-PLAN-1',
    generation: path.basename(generation),
    release_sequence: current.manifest.release_sequence,
    manifest: { path: current.files.manifest, ...current.identities.manifest },
    artifacts: prepared
  };
}

function createOfflineInstallerAttestation() {
  const current = authenticatedCurrentRelease(); const installer = offlineInstallerPath(argument('--offline-installer'), current.manifest, current.files.generation);
  const keys = ensureKey();
  const configuredPublic = keys.publicKey.export({ type: 'spki', format: 'der' });
  const authorizedPublic = createPublicKey(current.verified.delegation.public_key_pem).export({ type: 'spki', format: 'der' });
  if (!Buffer.from(configuredPublic).equals(Buffer.from(authorizedPublic))) throw new Error('BF-OFFLINE-ATTESTATION-KEY');
  const identity = fileDigest(installer.path);
  const attestation = {
    format: OFFLINE_ATTESTATION_FORMAT,
    release_sequence: current.manifest.release_sequence,
    version: installer.version,
    filename: installer.filename,
    bytes: identity.bytes,
    sha256: identity.sha256,
    release_manifest_sha256: current.identities.manifest.sha256,
    release_signature_sha256: current.identities.signature.sha256,
    signing_key_id: current.verified.delegation.key_id
  };
  const attestationText = `${JSON.stringify(attestation, null, 2)}\n`;
  const signature = sign(null, Buffer.from(attestationText, 'utf8'), keys.privateKey).toString('base64url');
  const envelope = { format: OFFLINE_ATTESTATION_FORMAT, attestation_text: attestationText, signature };
  // This attestation is metadata for the human-facing offline wrapper, not a
  // member of the signed automatic-update generation. Keeping it under the
  // immutable generation makes ReleaseVerifier correctly reject the entire
  // release tree as containing an undeclared file, which in turn makes the
  // public edge return BF-RELEASE-404 for otherwise valid update blobs.
  const target = offlineAttestationPath(current.manifest, current.files.generation, { createDirectory: true });
  const temporary = `${target}.next-${process.pid}`;
  if (existsSync(target)) throw new Error('BF-OFFLINE-ATTESTATION-EXISTS');
  try { writeFileSync(temporary, `${JSON.stringify(envelope, null, 2)}\n`, { flag: 'wx', mode: 0o644 }); renameSync(temporary, target); }
  catch (error) { rmSync(temporary, { force: true }); throw error; }
  return { created: true, attestation: target, installer: installer.path, ...identity };
}

function verifyOfflineInstallerAttestation() {
  const current = authenticatedCurrentRelease();
  const target = offlineAttestationPath(current.manifest, current.files.generation);
  if (!existsSync(target) || !lstatSync(target).isFile() || lstatSync(target).isSymbolicLink() || statSync(target).size > 64 * 1024) throw new Error('BF-OFFLINE-ATTESTATION');
  const envelopeText = strictUtf8(readFileSync(target)); assertNoDuplicateKeys(envelopeText);
  const envelope = JSON.parse(envelopeText); exactKeys(envelope, ['format', 'attestation_text', 'signature']);
  if (envelope.format !== OFFLINE_ATTESTATION_FORMAT || typeof envelope.attestation_text !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(String(envelope.signature || ''))) throw new Error('BF-OFFLINE-ATTESTATION');
  assertNoDuplicateKeys(envelope.attestation_text); const attestation = JSON.parse(envelope.attestation_text);
  exactKeys(attestation, ['format', 'release_sequence', 'version', 'filename', 'bytes', 'sha256', 'release_manifest_sha256', 'release_signature_sha256', 'signing_key_id']);
  if (attestation.format !== OFFLINE_ATTESTATION_FORMAT || !Number.isSafeInteger(attestation.release_sequence) || !Number.isSafeInteger(attestation.bytes) || attestation.bytes < 1 ||
      !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(String(attestation.version || '')) || !/^Bifrost-Offline-Setup-[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,15}-Windows-x64\.exe$/.test(String(attestation.filename || '')) ||
      !/^[0-9a-f]{64}$/.test(String(attestation.sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(attestation.release_manifest_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(attestation.release_signature_sha256 || '')) || typeof attestation.signing_key_id !== 'string') throw new Error('BF-OFFLINE-ATTESTATION');
  const signature = Buffer.from(envelope.signature, 'base64url');
  if (signature.length !== 64 || !verify(null, Buffer.from(envelope.attestation_text, 'utf8'), createPublicKey(current.verified.delegation.public_key_pem), signature)) throw new Error('BF-OFFLINE-ATTESTATION-SIGNATURE');
  const expectedVersion = releaseVersion(current.manifest, current.files.generation);
  if (attestation.release_sequence !== current.manifest.release_sequence || attestation.version !== expectedVersion || attestation.signing_key_id !== current.verified.delegation.key_id ||
      attestation.release_manifest_sha256 !== current.identities.manifest.sha256 || attestation.release_signature_sha256 !== current.identities.signature.sha256) throw new Error('BF-OFFLINE-ATTESTATION-BINDING');
  const requestedInstaller = argument('--offline-installer');
  let installer = null;
  if (requestedInstaller) {
    installer = offlineInstallerPath(requestedInstaller, current.manifest, current.files.generation);
    const actual = fileDigest(installer.path);
    if (installer.filename !== attestation.filename || actual.bytes !== attestation.bytes || actual.sha256 !== attestation.sha256) throw new Error('BF-OFFLINE-INSTALLER-DIGEST');
  }
  return { verified: true, attestation: target, installer: installer?.path || null, ...attestation };
}

function verifyRetainedOfflineInstallerAttestation() {
  // Historical manual installers live outside the immutable current release
  // generation.  They therefore cannot be checked with verify-offline, whose
  // binding intentionally requires the attestation to describe current.json.
  // This retained-proof verifier authenticates the detached envelope with the
  // root-authorized historical delegation rather than the *current* release
  // delegation. That distinction matters after a future release-key rotation:
  // an old proof must remain verifiable as historical evidence without making
  // an old key active again. The caller separately pins the baseline wrapper
  // bytes and compares the signed manifest/signature digests with the wrapper's
  // embedded verified identity, so a later key revocation cannot authorize
  // different recovery bytes.
  const authorization = readDelegation();
  const installerArgument = argument('--offline-installer');
  const attestationArgument = argument('--attestation-file');
  if (!installerArgument || !path.isAbsolute(installerArgument) || !attestationArgument || !path.isAbsolute(attestationArgument))
    throw new Error('BF-OFFLINE-ATTESTATION-PATH');
  const dist = path.resolve(root, 'dist');
  const installer = path.resolve(installerArgument);
  const attestationFile = path.resolve(attestationArgument);
  const attestationDirectory = path.resolve(dist, OFFLINE_ATTESTATION_DIRECTORY);
  const installerRelative = path.relative(dist, installer);
  const attestationRelative = path.relative(attestationDirectory, attestationFile);
  if (!installerRelative || installerRelative.startsWith('..') || path.isAbsolute(installerRelative) || installerRelative.includes(path.sep) ||
      !attestationRelative || attestationRelative.startsWith('..') || path.isAbsolute(attestationRelative) || attestationRelative.includes(path.sep) ||
      path.basename(attestationFile) !== `${path.basename(installer)}.attestation.json`)
    throw new Error('BF-OFFLINE-ATTESTATION-PATH');
  assertNoSymlinkUnderRelease(installer, dist);
  assertNoSymlinkUnderRelease(attestationFile, attestationDirectory);
  const installerDescriptor = lstatSync(installer);
  const attestationDescriptor = lstatSync(attestationFile);
  if (!installerDescriptor.isFile() || installerDescriptor.isSymbolicLink() || installerDescriptor.nlink !== 1 ||
      !attestationDescriptor.isFile() || attestationDescriptor.isSymbolicLink() || attestationDescriptor.nlink !== 1 || attestationDescriptor.size > 64 * 1024)
    throw new Error('BF-OFFLINE-ATTESTATION');

  const envelopeText = strictUtf8(readFileSync(attestationFile)); assertNoDuplicateKeys(envelopeText);
  const envelope = JSON.parse(envelopeText); exactKeys(envelope, ['format', 'attestation_text', 'signature']);
  if (envelope.format !== OFFLINE_ATTESTATION_FORMAT || typeof envelope.attestation_text !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(String(envelope.signature || '')))
    throw new Error('BF-OFFLINE-ATTESTATION');
  assertNoDuplicateKeys(envelope.attestation_text); const attestation = JSON.parse(envelope.attestation_text);
  exactKeys(attestation, ['format', 'release_sequence', 'version', 'filename', 'bytes', 'sha256', 'release_manifest_sha256', 'release_signature_sha256', 'signing_key_id']);
  if (attestation.format !== OFFLINE_ATTESTATION_FORMAT || !Number.isSafeInteger(attestation.release_sequence) || attestation.release_sequence < 1 ||
      !Number.isSafeInteger(attestation.bytes) || attestation.bytes < 1 || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(String(attestation.version || '')) ||
      !/^Bifrost-Offline-Setup-[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,15}-Windows-x64\.exe$/.test(String(attestation.filename || '')) ||
      !/^[0-9a-f]{64}$/.test(String(attestation.sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(attestation.release_manifest_sha256 || '')) ||
      !/^[0-9a-f]{64}$/.test(String(attestation.release_signature_sha256 || '')) || typeof attestation.signing_key_id !== 'string')
    throw new Error('BF-OFFLINE-ATTESTATION');
  const signature = Buffer.from(envelope.signature, 'base64url');
  const delegation = authorization.delegation;
  const rootSignature = Buffer.from(String(authorization.rootSignature || ''), 'base64url');
  let rootKey;
  try { rootKey = createPublicKey(authorization.rootDescriptor.public_key_pem); } catch { throw new Error('BF-RELEASE-TRUST-ROOT'); }
  if (rootSignature.length !== 64 ||
      !verify(null, Buffer.from(canonicalReleaseKeyDelegation(delegation), 'utf8'), rootKey, rootSignature) ||
      attestation.signing_key_id !== delegation.key_id ||
      attestation.release_sequence < delegation.activation_sequence || attestation.release_sequence >= delegation.retirement_sequence ||
      delegation.channel !== 'stable' || signature.length !== 64 ||
      !verify(null, Buffer.from(envelope.attestation_text, 'utf8'), createPublicKey(delegation.public_key_pem), signature))
    throw new Error('BF-OFFLINE-ATTESTATION-SIGNATURE');
  const match = /^Bifrost-Offline-Setup-([0-9]+\.[0-9]+\.[0-9]+)-r([1-9][0-9]{0,15})-Windows-x64\.exe$/.exec(path.basename(installer));
  if (!match || match[1] !== attestation.version || Number(match[2]) !== attestation.release_sequence || attestation.filename !== path.basename(installer))
    throw new Error('BF-OFFLINE-ATTESTATION-BINDING');
  const actual = fileDigest(installer);
  if (actual.bytes !== attestation.bytes || actual.sha256 !== attestation.sha256) throw new Error('BF-OFFLINE-INSTALLER-DIGEST');
  return { verified: true, retained: true, attestation: attestationFile, installer, ...attestation };
}

const mode = process.argv[2] || 'create';
try {
  const result = mode === 'verify' ? verifyRelease() : mode === 'publish-plan' ? createMirrorPublishPlan() : mode === 'verify-envelope' ? verifyEnvelopeFiles() : mode === 'verify-key' ? (requireProvisionedRoot(), ensureKey(), { verified: true }) : mode === 'sign-offline' ? createOfflineInstallerAttestation() : mode === 'verify-offline' ? verifyOfflineInstallerAttestation() : mode === 'verify-offline-retained' ? verifyRetainedOfflineInstallerAttestation() : createRelease();
  process.stdout.write(JSON.stringify(result) + '\n');
} catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
