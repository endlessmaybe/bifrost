import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  copyFileSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  openSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  statSync,
  chmodSync,
  utimesSync,
  writeFileSync
  ,writeSync
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyOfflineReleaseEnvelope } from './release-offline-verifier.mjs';
import { readProvisionedReleaseRoot } from './release-root-provision.mjs';
import { canonicalBinaryPlan, binaryPlanDigest, normalizeBinaryArtifact } from './release-plan.mjs';

const FORMAT = 'BIFROST-SOURCE-BUNDLE-1';
const MAX_ENTRIES = 20000;
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_MATERIALIZED_BYTES = 256 * 1024 * 1024;
const MAX_COMPRESSION_RATIO = 100;
const SAFE_REFERENCE = /^[A-Za-z0-9._-]{1,160}$/;
const PRIVATE_PREFIXES = ['repos/bifrost-control/', 'repos/bifrost-node-agent/', 'runtime/', 'secrets/'];
const INFRA_ALLOWLIST = [
  'scripts/build-clients.ps1', 'scripts/build-unified-libbox.ps1', 'scripts/build-xray-mobile.ps1',
  'scripts/generate-sbom.mjs', 'scripts/license-sbom.mjs', 'scripts/prepare-windows-release-evidence.mjs', 'scripts/release-sign.mjs', 'scripts/release-contract-tool.mjs',
  'scripts/release-contract-internal.mjs', 'scripts/release-contract-v1.json', 'scripts/release-offline-verifier.mjs',
  'scripts/release-root-provision.mjs', 'scripts/release-trust-binding.mjs', 'scripts/install-client-release.ps1',
  'scripts/secret-scan.ps1', 'scripts/setup-core-binaries.ps1', 'scripts/source-bundle.mjs', 'scripts/release-plan.mjs', 'config/source-bundle-policy-v1.json', 'config/source-bundle-manifest-v1.schema.json', 'config/core-provenance-v1.schema.json', 'config/build-input-manifest-v1.schema.json', 'config/dependency-license-manifest-v1.schema.json', 'config/cyclonedx-1.5-bifrost.schema.json', 'config/spdx.schema.json', 'config/jsf-0.82.schema.json', 'config/cyclonedx-schema-provenance.json',
  'installer/BifrostSetup.csproj', 'installer/Program.cs', 'installer/SetupWizard.cs',
  'redistributable-launcher/BifrostOfflineSetup.csproj', 'redistributable-launcher/Program.cs',
  'scripts/prepare-android-release-evidence.mjs', 'scripts/libbox-xray-bridge.go', 'installer/Assets/bifrost.ico'
];

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
function streamFileDigest(file, maxBytes = MAX_ARCHIVE_BYTES) {
  const descriptor = openSync(file, 'r'); const digest = createHash('sha256'); const buffer = Buffer.alloc(1024 * 1024); let total = 0;
  try { while (true) { const count = readSync(descriptor, buffer, 0, buffer.length, null); if (count === 0) break; total += count; if (total > maxBytes) fail('BF-SOURCE-ARCHIVE'); digest.update(buffer.subarray(0, count)); } }
  finally { closeSync(descriptor); }
  return { bytes: total, sha256: digest.digest('hex') };
}
const bytewise = (left, right) => Buffer.from(String(left), 'utf8').compare(Buffer.from(String(right), 'utf8'));
const fileDigest = (file) => sha256(readFileSync(file));
const strictUtf8 = (bytes) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail('BF-SOURCE-UTF8'); } };
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));

function canonical(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item) ?? 'null').join(',')}]`;
  return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function fail(code, message = code) { const error = new Error(message); error.code = code; throw error; }

function safeRelative(input) {
  if (typeof input !== 'string' || !input || input.includes('\\') || input.includes('\0') || /^[A-Za-z]:/.test(input) || input.startsWith('/') || input.startsWith('//')) fail('BF-SOURCE-PATH');
  if ([...input].some((character) => character.charCodeAt(0) > 0x7e)) fail('BF-SOURCE-PATH');
  const pieces = input.split('/');
  if (pieces.some((piece) => !piece || piece === '.' || piece === '..' || piece.endsWith('.') || piece.endsWith(' ') || piece.includes(':') || /^(CON|PRN|AUX|NUL|CLOCK\$|COM[0-9]|LPT[0-9])(?:\..*)?$/i.test(piece))) fail('BF-SOURCE-PATH');
  const normalized = pieces.join('/');
  if (normalized.normalize('NFC') !== normalized || normalized.toLowerCase() !== normalized.toLocaleLowerCase('en-US')) {
    // NFC is required; case is checked separately by the collision set.
    if (normalized.normalize('NFC') !== normalized) fail('BF-SOURCE-PATH');
  }
  return normalized;
}

function assertNoLinkChain(file, root) {
  const absoluteRoot = realpathSync(root);
  const absolute = path.resolve(file);
  const relative = path.relative(absoluteRoot, absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) fail('BF-SOURCE-ROOT');
  let current = absoluteRoot;
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || (stat.isDirectory() && (stat.mode & 0o170000) !== 0o040000)) fail('BF-SOURCE-LINK');
    // Directory link counts are structural (normally at least two on Unix)
    // and are not evidence of a hard-linked payload.  Only regular files are
    // rejected when their identity is shared.
    if (!stat.isDirectory() && stat.nlink > 1) fail('BF-SOURCE-HARDLINK');
  }
}

function collectFiles(root, prefix, excluded = new Set()) {
  const rows = [];
  const walk = (directory, relativeDirectory) => {
    for (const name of readdirSync(directory, { withFileTypes: true })) {
      const generatedPayload = /\.(aar|apk|exe|dll|pdb|so|dylib|class|zip|7z|msi|db|sqlite|bin)$/i.test(name.name);
      const wrapperJar = name.name.toLowerCase() === 'gradle-wrapper.jar';
      if (excluded.has(name.name) || name.name === '.git' || name.name === 'node_modules' || name.name === '.gradle' || name.name === '.kotlin' || name.name === 'local.properties' || name.name === 'bin' || name.name === 'obj' || name.name === 'build' || name.name === 'artifacts' || name.name === 'releases' || name.name === 'runtime' || name.name === 'secrets' || (generatedPayload && !wrapperJar)) continue;
      const absolute = path.join(directory, name.name);
      assertNoLinkChain(absolute, root);
      const relative = safeRelative(path.posix.join(relativeDirectory, name.name));
      if (name.isDirectory()) walk(absolute, relative);
      else if (name.isFile()) {
        const stat = statSync(absolute);
        if (stat.size > MAX_ENTRY_BYTES) fail('BF-SOURCE-ENTRY-SIZE');
        rows.push({ path: path.posix.join(prefix, relative), absolute, bytes: stat.size, sha256: fileDigest(absolute), mode: (stat.mode & 0o777).toString(8).padStart(3, '0') });
      } else fail('BF-SOURCE-LINK');
    }
  };
  walk(root, '');
  return rows;
}

function hasGitWorkTree(root) {
  try {
    const result = spawnSync('git', ['-C', root, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8' });
    return result.status === 0 && String(result.stdout || '').trim() === 'true';
  } catch { return false; }
}

// A real checkout is bounded by Git's tracked + untracked/non-ignored view.
// This keeps dirty source files in the signed bundle while excluding only
// repository-declared build/runtime junk. Every returned path still goes
// through the same portable-path and link checks as fixture trees.
function clientSourcePathIncluded(input) {
  const normalizedToken = String(input || '').replaceAll('\\', '/');
  const parts = normalizedToken.split('/');
  const leaf = parts.at(-1) || '';
  const generatedPayload = /\.(aar|apk|exe|dll|pdb|so|dylib|class|zip|7z|msi|db|sqlite|bin)$/i.test(leaf);
  const wrapperJar = leaf.toLowerCase() === 'gradle-wrapper.jar';
  return !(parts.some((part) => ['node_modules', '.gradle', '.kotlin', 'bin', 'obj', 'build', 'artifacts', 'releases', 'runtime', 'secrets'].includes(part)) || leaf === 'local.properties' || (generatedPayload && !wrapperJar));
}

function collectGitWorkingTreeFiles(root, prefix) {
  let raw;
  try {
    raw = execFileSync('git', ['-C', root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], { encoding: 'buffer' });
  } catch { fail('BF-SOURCE-GIT'); }
  const rows = [];
  const seen = new Set();
  for (const token of raw.toString('utf8').split('\0').filter(Boolean)) {
    const normalizedToken = token.replaceAll('\\', '/');
    if (!clientSourcePathIncluded(normalizedToken)) continue;
    const relative = safeRelative(normalizedToken);
    const folded = relative.toLowerCase();
    if (seen.has(folded)) fail('BF-SOURCE-COLLISION');
    seen.add(folded);
    const absolute = path.join(root, ...relative.split('/'));
    // A tracked deletion belongs in gitEvidence but not in the current source
    // tree that is being archived.
    if (!existsSync(absolute)) continue;
    assertNoLinkChain(absolute, root);
    const stat = lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1) fail('BF-SOURCE-LINK');
    if (stat.size > MAX_ENTRY_BYTES) fail('BF-SOURCE-ENTRY-SIZE');
    rows.push({ path: path.posix.join(prefix, relative), absolute, bytes: stat.size, sha256: fileDigest(absolute), mode: (stat.mode & 0o777).toString(8).padStart(3, '0') });
  }
  return rows;
}

function gitEvidence(directory, testOnly, includePath = () => true) {
  if (testOnly) return { available: false, test_only: true, status: 'TEST-ONLY-NOT-A-GIT-CHECKOUT' };
  try {
    // Porcelain -z is the only status form which is unambiguous for quoted,
    // renamed and deleted paths.  Keep the actual change list in the signed
    // source manifest; a status string alone cannot prove dirty inputs were
    // included in the archive.
    const raw = execFileSync('git', ['-C', directory, 'status', '--porcelain=v1', '-z', '--untracked-files=all'], { encoding: 'buffer' });
    const head = execFileSync('git', ['-C', directory, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const tokens = raw.toString('utf8').split('\0').filter(Boolean);
    const changes = [];
    for (let index = 0; index < tokens.length; index += 1) {
      const token = tokens[index];
      const status = token.slice(0, 2);
      let relative = token.slice(3);
      const renamed = status.includes('R') || status.includes('C');
      let oldPath;
      if (renamed && index + 1 < tokens.length) { const newPath = relative; oldPath = tokens[++index]; relative = newPath; }
      const normalizedRelative = relative.replaceAll('\\', '/');
      const normalizedOldPath = oldPath ? oldPath.replaceAll('\\', '/') : null;
      if (!includePath(normalizedRelative) && !(normalizedOldPath && includePath(normalizedOldPath))) continue;
      changes.push({ status, path: normalizedRelative, ...(normalizedOldPath ? { old_path: normalizedOldPath } : {}) });
    }
    const statusText = changes.map((change) => `${change.status} ${change.path}${change.old_path ? ` <- ${change.old_path}` : ''}`).join('\n');
    return { available: true, head, status: statusText, status_sha256: sha256(Buffer.from(statusText, 'utf8')), changes, included_untracked: true };
  } catch { fail('BF-SOURCE-GIT'); }
}

function sourceRoots(root, testOnly) {
  const clients = path.join(root, 'repos', 'bifrost-clients');
  const infra = path.join(root, 'repos', 'bifrost-infra');
  if (existsSync(clients)) {
    if (!existsSync(infra)) fail('BF-SOURCE-INPUT');
    const policyFile = path.join(infra, 'config', 'source-bundle-policy-v1.json');
    if (!testOnly) {
      if (!existsSync(policyFile)) fail('BF-SOURCE-POLICY');
      const policy = readJson(policyFile);
      if (policy.format !== 'BIFROST-SOURCE-BUNDLE-POLICY-1' || JSON.stringify(policy.public_infra_allowlist) !== JSON.stringify(INFRA_ALLOWLIST)) fail('BF-SOURCE-POLICY');
    }
    const clientsGit = hasGitWorkTree(clients);
    const infraGit = hasGitWorkTree(infra);
    const rows = clientsGit ? collectGitWorkingTreeFiles(clients, 'clients') : collectFiles(clients, 'clients');
    for (const relative of INFRA_ALLOWLIST) {
      const absolute = path.join(infra, relative);
      if (!existsSync(absolute) || !lstatSync(absolute).isFile()) fail('BF-SOURCE-INPUT');
      assertNoLinkChain(absolute, infra);
      const stat = statSync(absolute);
      if (stat.size > MAX_ENTRY_BYTES) fail('BF-SOURCE-ENTRY-SIZE');
      rows.push({ path: safeRelative(path.posix.join('infra', relative.replaceAll('\\', '/'))), absolute, bytes: stat.size, sha256: fileDigest(absolute), mode: (stat.mode & 0o777).toString(8).padStart(3, '0') });
    }
    const noGit = (testOnly) => ({ available: false, test_only: Boolean(testOnly), status: testOnly ? 'TEST-ONLY-NOT-A-GIT-CHECKOUT' : 'SOURCE-TREE-NOT-A-GIT-CHECKOUT' });
    const infraScope = new Set(INFRA_ALLOWLIST.map((value) => value.replaceAll('\\', '/')));
    return { rows, git: { clients: clientsGit ? gitEvidence(clients, testOnly, clientSourcePathIncluded) : noGit(testOnly), infra: infraGit ? gitEvidence(infra, testOnly, (value) => infraScope.has(value)) : noGit(testOnly) } };
  }
  const source = path.join(root, 'source');
  const buildInputs = path.join(root, 'build-inputs');
  if (!testOnly || !existsSync(source)) fail('BF-SOURCE-INPUT');
  const rows = collectFiles(source, 'source');
  if (existsSync(buildInputs)) rows.push(...collectFiles(buildInputs, 'build-inputs'));
  return { rows, git: { available: false, test_only: true } };
}

function createSourceSnapshot(root, outputDirectory, { testOnly = false } = {}) {
  const absoluteOutput = path.resolve(outputDirectory);
  if (existsSync(absoluteOutput)) fail('BF-SOURCE-SNAPSHOT-OUTPUT');
  const { rows, git } = sourceRoots(path.resolve(root), testOnly);
  if (rows.length < 1 || rows.length > MAX_ENTRIES) fail('BF-SOURCE-COUNT');
  const filesRoot = path.join(absoluteOutput, 'files');
  mkdirSync(filesRoot, { recursive: true, mode: 0o700 });
  const seen = new Set();
  const entries = [];
  for (const row of rows) {
    const relative = safeRelative(row.path);
    const key = relative.normalize('NFC').toLowerCase();
    if (seen.has(key)) fail('BF-SOURCE-COLLISION');
    seen.add(key);
    if (PRIVATE_PREFIXES.some((prefix) => relative.startsWith(prefix))) fail('BF-SOURCE-PRIVATE');
    const bytes = readFileSync(row.absolute);
    if (bytes.length !== row.bytes || sha256(bytes) !== row.sha256) fail('BF-SOURCE-INPUT-CHANGED');
    const target = path.join(filesRoot, ...relative.split('/'));
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, bytes, { mode: Number.parseInt(row.mode, 8) });
    entries.push({ path: relative, bytes: row.bytes, sha256: row.sha256, mode: row.mode });
  }
  const snapshot = {
    format: 'BIFROST-SOURCE-SNAPSHOT-1',
    test_only: Boolean(testOnly),
    entries: entries.sort((a, b) => bytewise(a.path, b.path)),
    git
  };
  const manifestPath = path.join(absoluteOutput, 'source-snapshot.json');
  writeFileSync(manifestPath, `${canonical(snapshot)}\n`, { encoding: 'utf8', mode: 0o600 });
  return { manifestPath, entries: snapshot.entries.length };
}

function loadSourceSnapshot(snapshotManifestPath) {
  const manifestPath = path.resolve(snapshotManifestPath);
  if (!existsSync(manifestPath) || !lstatSync(manifestPath).isFile() || lstatSync(manifestPath).isSymbolicLink()) fail('BF-SOURCE-SNAPSHOT');
  const text = strictUtf8(readFileSync(manifestPath));
  let snapshot; try { snapshot = JSON.parse(text); } catch { fail('BF-SOURCE-SNAPSHOT'); }
  if (`${canonical(snapshot)}\n` !== text || snapshot?.format !== 'BIFROST-SOURCE-SNAPSHOT-1' ||
      !Array.isArray(snapshot.entries) || snapshot.entries.length < 1 || snapshot.entries.length > MAX_ENTRIES) fail('BF-SOURCE-SNAPSHOT');
  const filesRoot = path.join(path.dirname(manifestPath), 'files');
  const rows = []; const seen = new Set();
  for (const entry of snapshot.entries) {
    if (!entry || typeof entry !== 'object' || Object.keys(entry).some((key) => !['path', 'bytes', 'sha256', 'mode'].includes(key)) ||
        !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !/^[0-9a-f]{64}$/.test(String(entry.sha256)) ||
        !/^[0-7]{3}$/.test(String(entry.mode))) fail('BF-SOURCE-SNAPSHOT');
    const relative = safeRelative(entry.path); const key = relative.normalize('NFC').toLowerCase();
    if (seen.has(key) || PRIVATE_PREFIXES.some((prefix) => relative.startsWith(prefix))) fail('BF-SOURCE-SNAPSHOT');
    seen.add(key);
    const absolute = path.join(filesRoot, ...relative.split('/'));
    if (!existsSync(absolute) || !lstatSync(absolute).isFile() || lstatSync(absolute).isSymbolicLink() || lstatSync(absolute).nlink > 1) fail('BF-SOURCE-SNAPSHOT');
    const stat = statSync(absolute);
    if (stat.size !== entry.bytes || fileDigest(absolute) !== entry.sha256) fail('BF-SOURCE-SNAPSHOT');
    rows.push({ path: relative, absolute, bytes: entry.bytes, sha256: entry.sha256, mode: entry.mode });
  }
  return { rows, git: snapshot.git || { available: false }, manifestPath };
}

function readReleaseBinding(root, releaseManifestPath, testOnly) {
  // During a build the signed release does not exist yet.  Always bind the
  // explicit BUILD-MANIFEST draft unless the caller deliberately supplies a
  // signed manifest path (verification never infers authority from a stale
  // neighboring file).
  const candidate = releaseManifestPath ? path.resolve(releaseManifestPath) : null;
  const buildPath = path.join(root, 'releases', 'BUILD-MANIFEST.json');
  if (candidate && !existsSync(candidate)) fail('BF-SOURCE-RELEASE');
  // Never select a mutable sidecar by mtime.  A production source bundle is
  // bound to the signed RELEASE-MANIFEST only; BUILD-MANIFEST is a draft input
  // and may be used on the explicit test lane.
  if (!candidate) {
    // The signed RELEASE-MANIFEST is created after BUILD-MANIFEST and the
    // source archive.  A release build may therefore bind the planned binary
    // set from BUILD-MANIFEST, but only when an explicit safe release sequence
    // is supplied; an empty directory is never treated as sequence zero.
    const sequence = Number(process.env.BIFROST_RELEASE_SEQUENCE || 0);
    // A build manifest is an explicit draft input, never selected by mtime or
    // treated as release authority.  It is sufficient to assemble the draft
    // source archive; production verification still requires a signed
    // RELEASE-ENVELOPE binding the resulting archive.
    if (!testOnly && existsSync(buildPath) && Number.isSafeInteger(sequence) && sequence > 0) {
      const build = readJson(buildPath); const artifacts = Array.isArray(build?.artifacts) ? build.artifacts : [];
      if (artifacts.length < 1 || artifacts.some((artifact) => typeof artifact.id !== 'string')) fail('BF-SOURCE-RELEASE');
      // BUILD-MANIFEST and RELEASE-MANIFEST are two inputs to the same
      // binary plan.  Never reduce the draft rows to a four-field shape: the
      // install target, platform, architecture and kind are part of the
      // signed plan digest and must survive the source-build lane too.
      return { sequence, artifacts: artifacts.map((artifact) => artifact?.kind === 'source' || artifact?.kind === 'notice' ? artifact : normalizeBinaryArtifact(artifact)).sort((a, b) => bytewise(String(a.id), String(b.id))), manifest_sha256: fileDigest(buildPath), status: 'BOUND-DRAFT-BUILD-MANIFEST' };
    }
    if (!testOnly) fail('BF-SOURCE-RELEASE');
    return { sequence: 0, artifacts: [], status: 'TEST-ONLY-NO-RELEASE' };
  }
  const value = JSON.parse(readFileSync(candidate, 'utf8'));
  const sequence = value.release_sequence ?? value.manifest?.release_sequence;
  if (!Number.isSafeInteger(sequence) || sequence < 0) fail('BF-SOURCE-RELEASE');
  const artifacts = Array.isArray(value.build?.artifacts) ? value.build.artifacts : Array.isArray(value.artifacts) ? value.artifacts : [];
  // Preserve the complete binary plan.  Reducing rows to id/path/hash/bytes
  // here used to make source manifests disagree with the signed release
  // (install_path/platform/arch/kind were silently lost).
  return { sequence, artifacts: artifacts.map((artifact) => artifact?.kind === 'source' || artifact?.kind === 'notice' ? artifact : normalizeBinaryArtifact(artifact)).sort((a, b) => String(a.id).localeCompare(String(b.id))), manifest_sha256: fileDigest(candidate), status: 'BOUND' };
}

function readBoundInput(file, label, { testOnly = false, required = false } = {}) {
  if (!file) { if (required && !testOnly) fail(`BF-SOURCE-${label.toUpperCase()}`); return null; }
  const absolute = path.resolve(file);
  if (!path.isAbsolute(file) || !existsSync(absolute) || !lstatSync(absolute).isFile() || lstatSync(absolute).nlink > 1) fail(`BF-SOURCE-${label.toUpperCase()}`);
  const bytes = readFileSync(absolute); if (!bytes.length || bytes.includes(0)) fail(`BF-SOURCE-${label.toUpperCase()}`);
  let value; let text; try { text = strictUtf8(bytes); value = JSON.parse(text); } catch { fail(`BF-SOURCE-${label.toUpperCase()}`); }
  if (`${canonical(value)}\n` !== text) fail(`BF-SOURCE-${label.toUpperCase()}`);
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`BF-SOURCE-${label.toUpperCase()}`);
  return { path: absolute, sha256: sha256(bytes), value };
}

function validateCoreProvenance(value) {
  const common = ['format', 'patches_digest', 'source_archive', 'overlay'];
  const componentNames = ['mihomo'];
  if (!value || value.format !== 'BIFROST-CORE-PROVENANCE-1' || !Object.prototype.hasOwnProperty.call(value, 'mihomo') ||
      Object.keys(value).some((key) => ![...common, ...componentNames, 'input_sha256'].includes(key)) ||
      common.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) ||
      !/^[0-9a-f]{64}$/.test(String(value.patches_digest))) fail('BF-SOURCE-CORE-PROVENANCE');
  for (const list of [value.source_archive, value.overlay]) if (!Array.isArray(list) || list.length < 1) fail('BF-SOURCE-CORE-PROVENANCE');
  for (const item of [...value.source_archive, ...value.overlay]) if (!item || typeof item.path !== 'string' || !Number.isSafeInteger(item.bytes) || item.bytes < 1 || !/^[0-9a-f]{64}$/.test(String(item.sha256))) fail('BF-SOURCE-CORE-PROVENANCE');
  for (const name of componentNames) {
    const item = value[name];
    if (!item || typeof item !== 'object' || Object.keys(item).some((key) => !['version', 'source_digest', 'patch_digest', 'source_path', 'patch_path'].includes(key)) || ['version', 'source_digest', 'patch_digest', 'source_path', 'patch_path'].some((key) => !Object.prototype.hasOwnProperty.call(item, key)) || typeof item.version !== 'string' || !item.version || typeof item.source_path !== 'string' || typeof item.patch_path !== 'string' || !/^[0-9a-f]{64}$/.test(String(item.source_digest)) || !/^[0-9a-f]{64}$/.test(String(item.patch_digest))) fail('BF-SOURCE-CORE-PROVENANCE');
  }
  return value;
}

function validateBuildInputManifest(value) {
  if (!value || value.format !== 'BIFROST-BUILD-INPUTS-1' || Object.keys(value).some((key) => !['format', 'inputs', 'toolchain', 'input_sha256'].includes(key)) || !Array.isArray(value.inputs) || value.inputs.length < 1 || value.inputs.length > MAX_ENTRIES) fail('BF-SOURCE-BUILD-INPUTS');
  const seen = new Set();
  for (const input of value.inputs) {
    if (!input || Object.keys(input).some((key) => !['path', 'sha256', 'bytes', 'mode', 'kind'].includes(key)) || ['path', 'sha256', 'bytes', 'mode', 'kind'].some((key) => !Object.prototype.hasOwnProperty.call(input, key)) || typeof input.path !== 'string' || !/^[0-9a-f]{64}$/.test(String(input.sha256)) || !Number.isSafeInteger(input.bytes) || input.bytes < 1 || input.bytes > MAX_ENTRY_BYTES || !/^[0-7]{3,4}$/.test(String(input.mode)) || !['source', 'lock', 'verification', 'wrapper', 'patch', 'overlay', 'script', 'metadata', 'toolchain', 'core', 'license'].includes(String(input.kind))) fail('BF-SOURCE-BUILD-INPUTS');
    const relative = safeRelative(input.path); const key = relative.normalize('NFC').toLowerCase(); if (seen.has(key)) fail('BF-SOURCE-BUILD-INPUTS'); seen.add(key);
  }
  return value;
}

function validateToolchain(value, { production = false } = {}) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.required) || value.required.length < 1) { if (production) fail('BF-SOURCE-TOOLCHAIN'); return null; }
  for (const item of value.required) {
    if (!item || typeof item.name !== 'string' || !item.name || typeof item.version !== 'string' || !item.version || typeof item.download_url !== 'string' || !/^https:\/\//.test(item.download_url) || !/^[0-9a-f]{64}$/.test(String(item.sha256))) fail('BF-SOURCE-TOOLCHAIN');
  }
  return { required: value.required.map((item) => ({ name: item.name, version: item.version, download_url: item.download_url, sha256: item.sha256 })).sort((a, b) => bytewise(a.name, b.name)) };
}

function buildManifest(root, output, { testOnly = false, releaseManifestPath, coreProvenancePath, buildInputManifestPath, dependencyLicenseManifestPath, sourceSnapshotPath } = {}) {
  const frozenSource = sourceSnapshotPath ? loadSourceSnapshot(sourceSnapshotPath) : sourceRoots(path.resolve(root), testOnly);
  const { rows, git } = frozenSource;
  if (rows.length < 1 || rows.length > MAX_ENTRIES) fail('BF-SOURCE-COUNT');
  const collisions = new Set();
  for (const row of rows) {
    const key = row.path.normalize('NFC').toLowerCase();
    if (collisions.has(key)) fail('BF-SOURCE-COLLISION');
    collisions.add(key);
    if (PRIVATE_PREFIXES.some((prefix) => row.path.startsWith(prefix))) fail('BF-SOURCE-PRIVATE');
  }
  const total = rows.reduce((sum, row) => sum + row.bytes, 0);
  if (total > MAX_TOTAL_BYTES) fail('BF-SOURCE-TOTAL-SIZE');
  const release = readReleaseBinding(path.resolve(root), releaseManifestPath, testOnly);
  const policyPath = path.join(path.resolve(root), 'repos', 'bifrost-infra', 'config', 'source-bundle-policy-v1.json');
  const frozenPolicy = rows.find((row) => row.path === 'infra/config/source-bundle-policy-v1.json');
  const policyDigest = sourceSnapshotPath ? frozenPolicy?.sha256 ?? null : (existsSync(policyPath) ? fileDigest(policyPath) : null);
  const binaryArtifacts = release.artifacts.filter((artifact) => artifact?.kind !== 'source' && artifact?.kind !== 'notice').map(normalizeBinaryArtifact);
  const coreInput = readBoundInput(coreProvenancePath, 'core-provenance', { testOnly, required: !testOnly });
  const buildInput = readBoundInput(buildInputManifestPath, 'build-inputs', { testOnly, required: !testOnly });
  const dependencyLicenseInput = readBoundInput(dependencyLicenseManifestPath, 'dependency-license-manifest', { testOnly, required: !testOnly });
  if (dependencyLicenseInput && (dependencyLicenseInput.value.format !== 'BIFROST-DEPENDENCY-LICENSES-1' || !Array.isArray(dependencyLicenseInput.value.components) || dependencyLicenseInput.value.components.length < 1)) fail('BF-SOURCE-DEPENDENCY-LICENSES');
  if (coreInput) validateCoreProvenance(coreInput.value);
  if (buildInput) validateBuildInputManifest(buildInput.value);
  const toolchain = buildInput?.value?.toolchain ? validateToolchain(buildInput.value.toolchain, { production: !testOnly }) : validateToolchain(null, { production: !testOnly });
  // Ceremony-supplied attestations are copied into the source bundle under a
  // stable path, so the archive remains independently verifiable even when
  // the input file originated outside the checkout.
  for (const [input, name] of [[coreInput, 'build-inputs/core-provenance.json'], [buildInput, 'build-inputs/build-input-manifest.json'], [dependencyLicenseInput, 'build-inputs/dependency-license-manifest.json']]) {
    if (input) { const stat = statSync(input.path); rows.push({ path: name, absolute: input.path, bytes: stat.size, sha256: input.sha256, mode: (stat.mode & 0o777).toString(8).padStart(3, '0') }); }
  }
  // Every declared build input is an actual source of the build, not merely a
  // claim in a sidecar JSON file.  Resolve it against the workspace root,
  // open it through the same no-link boundary as ordinary source files, and
  // include the exact bytes in the bundle.  This makes the source plan
  // independently reproducible and prevents a later workspace substitution.
  if (buildInput) {
    for (const input of buildInput.value.inputs) {
      const relative = safeRelative(String(input.path).replaceAll('\\', '/'));
      const absolute = path.resolve(root, relative);
      if (!absolute.startsWith(`${path.resolve(root)}${path.sep}`) || !existsSync(absolute) || !lstatSync(absolute).isFile()) fail('BF-SOURCE-BUILD-INPUTS');
      assertNoLinkChain(absolute, root);
      const stat = statSync(absolute); if (stat.size !== input.bytes || fileDigest(absolute) !== input.sha256) fail('BF-SOURCE-BUILD-INPUTS');
      rows.push({ path: safeRelative(`build-inputs/declared/${relative}`), absolute, bytes: stat.size, sha256: input.sha256, mode: (stat.mode & 0o777).toString(8).padStart(3, '0') });
    }
  }
  if (coreInput) {
    const declared = [];
    for (const item of [coreInput.value.source_archive, coreInput.value.overlay]) {
      if (Array.isArray(item)) declared.push(...item);
      else if (item && typeof item === 'object') declared.push(item);
    }
    for (const input of declared) {
      if (!input || typeof input.path !== 'string' || !Number.isSafeInteger(input.bytes) || input.bytes < 1 || !/^[0-9a-f]{64}$/.test(String(input.sha256))) fail('BF-SOURCE-CORE-PROVENANCE');
      const relative = safeRelative(input.path.replaceAll('\\', '/')); const absolute = path.resolve(root, relative);
      if (!absolute.startsWith(`${path.resolve(root)}${path.sep}`) || !existsSync(absolute) || !lstatSync(absolute).isFile()) fail('BF-SOURCE-CORE-PROVENANCE');
      assertNoLinkChain(absolute, root); const stat = statSync(absolute); if (stat.size !== input.bytes || fileDigest(absolute) !== input.sha256) fail('BF-SOURCE-CORE-PROVENANCE');
      rows.push({ path: safeRelative(`build-inputs/core/${relative}`), absolute, bytes: stat.size, sha256: input.sha256, mode: (stat.mode & 0o777).toString(8).padStart(3, '0') });
    }
  }
  rows.sort((a, b) => bytewise(a.path, b.path));
  const manifest = {
    format: FORMAT,
    test_only: Boolean(testOnly),
    // This file is a draft until a release envelope signs it.  The status is
    // descriptive only and is never accepted as cryptographic authority.
    signature_status: testOnly ? 'TEST-ONLY-UNSIGNED' : 'DRAFT-NOT-RELEASABLE',
    release_sequence: release.sequence,
    // The final signed release manifest does not exist yet.  Binding its hash
    // here would create a circular dependency and would either bind a stale
    // previous manifest or make the release impossible to verify.  The final
    // envelope instead carries source_manifest_sha256 and build_plan_sha256.
    build_plan_sha256: binaryPlanDigest(binaryArtifacts),
    binary_artifacts: binaryArtifacts,
    binary_artifacts_sha256: binaryPlanDigest(binaryArtifacts),
    policy_sha256: policyDigest,
    source_policy_sha256: policyDigest,
    source_bundle_id: 'bifrost-release-source',
    scope: { included: ['bifrost-clients', 'public-contracts', 'release-build-inputs'], excluded: ['bifrost-control', 'bifrost-node-agent', 'private-admin', 'runtime', 'secrets'] },
    git: Object.fromEntries(Object.entries(git).map(([name, value]) => [name, value && value.available ? { ...value, deletions: (value.changes || []).flatMap((change) => { const status = String(change.status || ''); return status.includes('D') ? [change.path] : (status.includes('R') || status.includes('C')) && change.old_path ? [change.old_path] : []; }), renames: (value.changes || []).filter((change) => String(change.status || '').includes('R') || String(change.status || '').includes('C')).map((change) => ({ old_path: change.old_path, path: change.path })) } : value])),
    entries: rows.map(({ path: entryPath, bytes, sha256: digest, mode }) => ({ path: entryPath, bytes, sha256: digest, mode })),
    toolchain: toolchain || { source: 'TEST-ONLY', locked: true, external_ceremony: 'TEST-ONLY', required: [
      { name: 'JDK', version: '17', download_url: 'PENDING-EXTERNAL', sha256: 'PENDING-EXTERNAL' },
      { name: 'Gradle/Android SDK/NDK', version: 'pinned-by-verification-metadata', download_url: 'PENDING-EXTERNAL', sha256: 'PENDING-EXTERNAL' },
      { name: '.NET SDK/NuGet', version: 'pinned-by-assets', download_url: 'PENDING-EXTERNAL', sha256: 'PENDING-EXTERNAL' },
      { name: 'Go/gomobile', version: 'pinned-by-go-module', download_url: 'PENDING-EXTERNAL', sha256: 'PENDING-EXTERNAL' }
    ] },
    toolchain_sha256: sha256(Buffer.from(canonical(toolchain || { source: 'TEST-ONLY' }), 'utf8')),
    core_provenance: coreInput ? { ...coreInput.value, input_sha256: coreInput.sha256 } : { status: 'PENDING-EXTERNAL', input_sha256: null },
    build_inputs: buildInput ? { ...buildInput.value, input_sha256: buildInput.sha256 } : { status: 'PENDING-EXTERNAL', input_sha256: null },
    dependency_license_manifest: dependencyLicenseInput ? { ...dependencyLicenseInput.value, input_sha256: dependencyLicenseInput.sha256 } : { status: 'PENDING-EXTERNAL', input_sha256: null },
    core_provenance_sha256: coreInput?.sha256 || null,
    build_inputs_sha256: buildInput?.sha256 || null,
    limits: { max_entries: MAX_ENTRIES, max_entry_bytes: MAX_ENTRY_BYTES, max_total_bytes: MAX_TOTAL_BYTES, max_compression_ratio: MAX_COMPRESSION_RATIO },
    archive_policy: { format: 'ustar', entry_order: 'lexicographic-bytewise', timestamp: 0, mode_source: 'manifest' }
  };
  const text = `${canonical(manifest)}\n`;
  const manifestPath = output || path.join(path.resolve(root), 'source-bundle-manifest.json');
  mkdirSync(path.dirname(manifestPath), { recursive: true });
  writeFileSync(manifestPath, text, { encoding: 'utf8', mode: 0o644 });
  return { manifest, manifestPath, manifestSha256: sha256(Buffer.from(text, 'utf8')), rows };
}

function archiveRelative(entry) { return safeRelative(entry.replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/$/, '')); }

function octalField(bytes, start, length, code = 'BF-SOURCE-ARCHIVE') {
  const field = bytes.subarray(start, start + length); const nul = field.indexOf(0); if (nul >= 0 && field.subarray(nul + 1).some((value) => value !== 0 && value !== 0x20)) fail(code);
  const text = field.toString('ascii').replace(/\0.*$/, '').trim();
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text)) fail(code);
  const value = Number.parseInt(text, 8); if (!Number.isSafeInteger(value)) fail(code); return value;
}

function asciiField(bytes, start, length) {
  const field = bytes.subarray(start, start + length); const end = field.indexOf(0);
  if (end >= 0 && field.subarray(end + 1).some((value) => value !== 0)) fail('BF-SOURCE-ARCHIVE-METADATA');
  const value = field.subarray(0, end < 0 ? length : end); if (value.some((byte) => byte < 0x20 || byte > 0x7e)) fail('BF-SOURCE-ARCHIVE-METADATA');
  return value.toString('ascii');
}

function parseUstarArchive(archive) {
  const archiveStat = lstatSync(archive);
  if (!archiveStat.isFile() || archiveStat.isSymbolicLink() || archiveStat.nlink > 1) fail('BF-SOURCE-ARCHIVE');
  const handle = openSync(archive, 'r');
  try {
    const archiveBytes = fstatSync(handle).size;
    if (!Number.isSafeInteger(archiveBytes) || archiveBytes > MAX_ARCHIVE_BYTES || archiveBytes < 1024 || archiveBytes % 512 !== 0) fail('BF-SOURCE-ARCHIVE');
    const readBlock = (offset, length) => {
      const out = Buffer.alloc(length); let done = 0;
      while (done < length) { const count = readSync(handle, out, done, length - done, offset + done); if (count < 1) fail('BF-SOURCE-ARCHIVE-TRUNCATED'); done += count; }
      return out;
    };
    const zero = (buffer) => buffer.every((value) => value === 0);
    const files = []; const directories = new Set(); const allNames = []; const seen = new Set();
    let offset = 0; let ended = false; let total = 0; let materialized = 0;
    while (offset + 512 <= archiveBytes) {
      const header = readBlock(offset, 512);
      if (zero(header)) {
        const second = readBlock(offset + 512, 512);
        if (!zero(second) || offset + 1024 !== archiveBytes) fail('BF-SOURCE-ARCHIVE');
        ended = true; break;
      }
      const storedChecksum = octalField(header, 148, 8);
      let checksum = 0; for (let index = 0; index < 512; index += 1) checksum += (index >= 148 && index < 156) ? 0x20 : header[index];
      if (storedChecksum !== checksum) fail('BF-SOURCE-ARCHIVE-CHECKSUM');
      if (header.subarray(500).some((value) => value !== 0)) fail('BF-SOURCE-ARCHIVE-METADATA');
      const magic = header.subarray(257, 263).toString('ascii'); if (magic !== 'ustar\0') fail('BF-SOURCE-ARCHIVE-MAGIC');
      if (header[263] !== 0x30 || header[264] !== 0x30) fail('BF-SOURCE-ARCHIVE-METADATA');
      const name = asciiField(header, 0, 100); const prefix = asciiField(header, 345, 155); const linkname = asciiField(header, 157, 100); const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
      if (asciiField(header, 265, 32) || asciiField(header, 297, 32) || octalField(header, 329, 8) !== 0 || octalField(header, 337, 8) !== 0) fail('BF-SOURCE-ARCHIVE-METADATA');
      const fullName = prefix ? `${prefix}/${name}` : name;
      if (!fullName || fullName.includes('\\') || fullName.includes('\0')) fail('BF-SOURCE-PATH');
      const isDirectory = type === '5';
      if (type === '0' && fullName.endsWith('/')) fail('BF-SOURCE-ARCHIVE-TYPE');
      const normalized = fullName.replace(/^\.\//, '').replace(/\/$/, '');
      if (normalized === '.' && isDirectory) { offset += 512; continue; }
      if (!normalized || normalized === '.') fail('BF-SOURCE-ARCHIVE');
      const safeName = archiveRelative(normalized); const key = safeName.normalize('NFC').toLowerCase();
      if (seen.has(key)) fail('BF-SOURCE-ARCHIVE-DUPLICATE'); seen.add(key); allNames.push(safeName);
      const mode = octalField(header, 100, 8); const uid = octalField(header, 108, 8); const gid = octalField(header, 116, 8); const size = octalField(header, 124, 12); const mtime = octalField(header, 136, 12);
      if (mode > 0o7777 || uid > 0 || gid > 0 || mtime !== 0 || size > MAX_ENTRY_BYTES) fail('BF-SOURCE-ARCHIVE-METADATA');
      if (type !== '0' && !isDirectory) fail('BF-SOURCE-ARCHIVE-TYPE');
      if (linkname) fail('BF-SOURCE-ARCHIVE-LINK');
      if (isDirectory) { directories.add(key); if (size !== 0) fail('BF-SOURCE-ARCHIVE-METADATA'); }
      else {
        total += size; if (total > MAX_TOTAL_BYTES) fail('BF-SOURCE-TOTAL-SIZE');
        const chunks = []; let done = 0; const chunkSize = Math.min(1024 * 1024, Math.max(1, size));
        while (done < size) { const part = Buffer.alloc(Math.min(chunkSize, size - done)); const count = readSync(handle, part, 0, part.length, offset + 512 + done); if (count < 1) fail('BF-SOURCE-ARCHIVE-TRUNCATED'); chunks.push(part.subarray(0, count)); done += count; }
        materialized += size; if (materialized > MAX_MATERIALIZED_BYTES) fail('BF-SOURCE-MATERIALIZED-BUDGET');
        const data = Buffer.concat(chunks, size);
        const padding = Math.ceil(size / 512) * 512 - size;
        if (padding) { const pad = readBlock(offset + 512 + size, padding); if (!zero(pad)) fail('BF-SOURCE-ARCHIVE-PADDING'); }
        files.push({ name: safeName, key, bytes: data, mode });
      }
      offset += 512 + Math.ceil(size / 512) * 512;
      if (files.length + directories.size > MAX_ENTRIES + 4096 || offset > archiveBytes) fail('BF-SOURCE-COUNT');
    }
    if (!ended) fail('BF-SOURCE-ARCHIVE-TRUNCATED');
    const sorted = [...allNames].sort(bytewise); if (allNames.some((name, index) => name !== sorted[index])) fail('BF-SOURCE-ARCHIVE-ORDER');
    const names = files.map((entry) => entry.name); const sortedFiles = [...names].sort(bytewise); if (names.some((name, index) => name !== sortedFiles[index])) fail('BF-SOURCE-ARCHIVE-ORDER');
    return { files, directories, archiveBytes };
  } finally { closeSync(handle); }
}

// Production archive verification is deliberately single-pass.  The legacy
// parseUstarArchive helper remains available to small contract fixtures, but
// release verification must not retain every source file in memory.
function streamUstarArchive(archive, { onEntryStart = () => {}, onEntryChunk = () => {}, onEntryEnd = () => {} } = {}) {
  const archiveStat = lstatSync(archive);
  if (!archiveStat.isFile() || archiveStat.isSymbolicLink() || archiveStat.nlink > 1) fail('BF-SOURCE-ARCHIVE');
  const handle = openSync(archive, 'r');
  try {
    const archiveBytes = fstatSync(handle).size;
    if (!Number.isSafeInteger(archiveBytes) || archiveBytes > MAX_ARCHIVE_BYTES || archiveBytes < 1024 || archiveBytes % 512 !== 0) fail('BF-SOURCE-ARCHIVE');
    const readExact = (offset, length) => {
      const out = Buffer.alloc(length); let done = 0;
      while (done < length) { const count = readSync(handle, out, done, length - done, offset + done); if (count < 1) fail('BF-SOURCE-ARCHIVE-TRUNCATED'); done += count; }
      return out;
    };
    const zero = (buffer) => buffer.every((value) => value === 0);
    const names = []; const seen = new Set(); const directories = new Set(); let offset = 0; let total = 0; let ended = false;
    while (offset + 512 <= archiveBytes) {
      const header = readExact(offset, 512);
      if (zero(header)) {
        const second = readExact(offset + 512, 512);
        if (!zero(second) || offset + 1024 !== archiveBytes) fail('BF-SOURCE-ARCHIVE');
        ended = true; break;
      }
      const storedChecksum = octalField(header, 148, 8);
      let checksum = 0; for (let index = 0; index < 512; index += 1) checksum += (index >= 148 && index < 156) ? 0x20 : header[index];
      if (storedChecksum !== checksum) fail('BF-SOURCE-ARCHIVE-CHECKSUM');
      if (header.subarray(500).some((value) => value !== 0)) fail('BF-SOURCE-ARCHIVE-METADATA');
      if (header.subarray(265, 297).some((value) => value !== 0) || header.subarray(297, 329).some((value) => value !== 0)) fail('BF-SOURCE-ARCHIVE-METADATA');
      const magic = header.subarray(257, 263).toString('ascii'); if (magic !== 'ustar\0' || header[263] !== 0x30 || header[264] !== 0x30) fail('BF-SOURCE-ARCHIVE-MAGIC');
      const name = asciiField(header, 0, 100); const prefix = asciiField(header, 345, 155); const linkname = asciiField(header, 157, 100); const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
      const fullName = prefix ? `${prefix}/${name}` : name;
      if (!fullName || fullName.includes('\\') || fullName.includes('\0')) fail('BF-SOURCE-PATH');
      const isDirectory = type === '5'; if (type === '0' && fullName.endsWith('/')) fail('BF-SOURCE-ARCHIVE-TYPE');
      const normalized = fullName.replace(/^\.\//, '').replace(/\/$/, '');
      if (normalized === '.' && isDirectory) { offset += 512; continue; }
      if (!normalized || normalized === '.') fail('BF-SOURCE-ARCHIVE');
      const safeName = archiveRelative(normalized); const key = safeName.normalize('NFC').toLowerCase();
      if (seen.has(key)) fail('BF-SOURCE-ARCHIVE-DUPLICATE'); seen.add(key); names.push(safeName);
      const mode = octalField(header, 100, 8); const uid = octalField(header, 108, 8); const gid = octalField(header, 116, 8); const size = octalField(header, 124, 12); const mtime = octalField(header, 136, 12);
      if (mode > 0o7777 || uid > 0 || gid > 0 || mtime !== 0 || size > MAX_ENTRY_BYTES) fail('BF-SOURCE-ARCHIVE-METADATA');
      if (type !== '0' && !isDirectory) fail('BF-SOURCE-ARCHIVE-TYPE'); if (linkname) fail('BF-SOURCE-ARCHIVE-LINK');
      const meta = { name: safeName, key, mode, size, type, offset: offset + 512 };
      if (isDirectory) { if (size !== 0) fail('BF-SOURCE-ARCHIVE-METADATA'); directories.add(key); onEntryStart(meta); onEntryEnd(meta, { sha256: sha256(Buffer.alloc(0)), bytes: 0 }); }
      else {
        total += size; if (total > MAX_TOTAL_BYTES) fail('BF-SOURCE-TOTAL-SIZE');
        const consume = onEntryStart(meta) || {};
        const digest = createHash('sha256'); let done = 0; const chunk = Buffer.alloc(Math.min(1024 * 1024, Math.max(1, Math.min(size || 1, MAX_ENTRY_BYTES))));
        while (done < size) {
          const length = Math.min(chunk.length, size - done); const count = readSync(handle, chunk, 0, length, offset + 512 + done); if (count !== length) fail('BF-SOURCE-ARCHIVE-TRUNCATED');
          const piece = chunk.subarray(0, count); digest.update(piece); onEntryChunk(meta, piece); done += count;
        }
        const padding = Math.ceil(size / 512) * 512 - size; if (padding) { const pad = readExact(offset + 512 + size, padding); if (!zero(pad)) fail('BF-SOURCE-ARCHIVE-PADDING'); }
        onEntryEnd(meta, { sha256: digest.digest('hex'), bytes: size });
      }
      offset += 512 + Math.ceil(size / 512) * 512; if (names.length + directories.size > MAX_ENTRIES + 4096 || offset > archiveBytes) fail('BF-SOURCE-COUNT');
    }
    if (!ended) fail('BF-SOURCE-ARCHIVE-TRUNCATED');
    const sorted = [...names].sort(bytewise); if (names.some((name, index) => name !== sorted[index])) fail('BF-SOURCE-ARCHIVE-ORDER');
    return { archiveBytes, names, directories, totalBytes: total };
  } finally { closeSync(handle); }
}

function validateSourceEnvelopeBinding(manifest, archive, manifestBytes, sourceEnvelope, { allowTestOnly = false, rootDescriptor } = {}) {
  if (typeof sourceEnvelope === 'string') { if (!path.isAbsolute(sourceEnvelope) || !existsSync(sourceEnvelope)) fail('BF-SOURCE-SIGNATURE'); sourceEnvelope = readJson(sourceEnvelope); }
  if (!sourceEnvelope || typeof sourceEnvelope !== 'object') fail('BF-SOURCE-SIGNATURE');
  let verified;
  try {
    // Tool-only offline verification is explicitly required for a source
    // bundle ceremony.  Production callers must pass a complete signed
    // RELEASE-ENVELOPE and a protected root descriptor; a status string or a
    // public key embedded beside the archive is never sufficient.
    verified = verifyOfflineReleaseEnvelope(sourceEnvelope, { rootDescriptor, channel: sourceEnvelope.delegation?.channel });
  } catch (error) { fail(error?.code || 'BF-SOURCE-SIGNATURE'); }
  const releaseManifest = verified.manifest; const digestInfo = streamFileDigest(archive); const digest = digestInfo.sha256;
  const sourceId = manifest.source_bundle_id || manifest.release_source_artifact_id;
  const artifacts = releaseManifest.build?.artifacts || [];
  const source = artifacts.find((artifact) => artifact.id === sourceId || artifact.path === path.basename(archive));
  if (!source || source.kind !== 'source' || source.bytes !== digestInfo.bytes || String(source.sha256).toLowerCase() !== digest) fail('BF-SOURCE-BINDING');
  const manifestDigest = sha256(manifestBytes);
  if (manifest.release_sequence !== releaseManifest.release_sequence || !Number.isSafeInteger(manifest.release_sequence) || manifest.release_sequence < 1) fail('BF-SOURCE-BINDING');
  const releasePlanArtifacts = artifacts.filter((artifact) => artifact.kind !== 'source' && artifact.kind !== 'notice');
  const releaseBuildDigest = binaryPlanDigest(releasePlanArtifacts);
  if (manifest.build_plan_sha256 !== releaseBuildDigest || manifest.binary_artifacts_sha256 !== releaseBuildDigest || binaryPlanDigest(manifest.binary_artifacts || []) !== releaseBuildDigest) fail('BF-SOURCE-BINDING');
  const requiredBindings = ['source_manifest_sha256', 'build_plan_sha256', 'source_policy_sha256', 'core_provenance_sha256', 'build_inputs_sha256', 'toolchain_sha256', 'dependency_license_manifest_sha256'];
  if (!allowTestOnly && requiredBindings.some((key) => typeof verified.manifest[key] !== 'string' || !/^[0-9a-f]{64}$/.test(verified.manifest[key]))) fail('BF-SOURCE-BINDING');
  if (!allowTestOnly || verified.manifest.source_manifest_sha256 !== undefined) {
    if (verified.manifest.source_manifest_sha256 !== manifestDigest || verified.manifest.build_plan_sha256 !== manifest.build_plan_sha256) fail('BF-SOURCE-BINDING');
    if (verified.manifest.source_policy_sha256 !== manifest.policy_sha256 || verified.manifest.core_provenance_sha256 !== manifest.core_provenance?.input_sha256 || verified.manifest.build_inputs_sha256 !== manifest.build_inputs?.input_sha256 || verified.manifest.toolchain_sha256 !== manifest.toolchain_sha256 || verified.manifest.dependency_license_manifest_sha256 !== manifest.dependency_license_manifest?.input_sha256) fail('BF-SOURCE-BINDING');
  }
  if (!allowTestOnly && (manifest.test_only || verified.manifest.channel === 'test')) fail('BF-SOURCE-SIGNATURE');
  return { verified, source, source_manifest_sha256: manifestDigest, archive_sha256: digest };
}

function verifyManifestShape(manifest, { allowTestOnly = false, hasSourceEnvelope = false } = {}) {
  if (!manifest || manifest.format !== FORMAT || typeof manifest.test_only !== 'boolean' || (!allowTestOnly && manifest.test_only)) fail('BF-SOURCE-MANIFEST');
  const allowed = new Set(['format', 'test_only', 'signature_status', 'release_sequence', 'build_plan_sha256', 'binary_artifacts', 'binary_artifacts_sha256', 'policy_sha256', 'source_policy_sha256', 'core_provenance_sha256', 'build_inputs_sha256', 'toolchain_sha256', 'scope', 'git', 'entries', 'toolchain', 'core_provenance', 'build_inputs', 'dependency_license_manifest', 'limits', 'archive_policy', 'source_bundle_id']);
  if (Object.keys(manifest).some((key) => !allowed.has(key))) fail('BF-SOURCE-MANIFEST');
  if (!allowTestOnly && (!hasSourceEnvelope || !['SIGNED-EXTERNAL-CEREMONY', 'DRAFT-NOT-RELEASABLE'].includes(manifest.signature_status))) fail('BF-SOURCE-SIGNATURE');
  if (!manifest.archive_policy || manifest.archive_policy.format !== 'ustar' || manifest.archive_policy.entry_order !== 'lexicographic-bytewise' || manifest.archive_policy.timestamp !== 0 || manifest.archive_policy.mode_source !== 'manifest') fail('BF-SOURCE-MANIFEST');
  if (!Array.isArray(manifest.entries) || manifest.entries.length < 1 || manifest.entries.length > MAX_ENTRIES) fail('BF-SOURCE-COUNT');
  const seen = new Set(); let total = 0;
  for (const entry of manifest.entries) {
    if (!entry || Object.keys(entry).sort().join('|') !== 'bytes|mode|path|sha256' || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || entry.bytes > MAX_ENTRY_BYTES || !/^[0-9a-f]{64}$/.test(entry.sha256) || !/^[0-7]{3}$/.test(entry.mode)) fail('BF-SOURCE-MANIFEST');
    const normalized = archiveRelative(entry.path); const key = normalized.normalize('NFC').toLowerCase();
    if (seen.has(key) || PRIVATE_PREFIXES.some((prefix) => normalized.startsWith(prefix))) fail('BF-SOURCE-COLLISION');
    seen.add(key); total += entry.bytes;
  }
  if (total > MAX_TOTAL_BYTES) fail('BF-SOURCE-TOTAL-SIZE');
  if (!allowTestOnly && (!Number.isSafeInteger(manifest.release_sequence) || manifest.release_sequence < 1 || !/^[0-9a-f]{64}$/.test(String(manifest.build_plan_sha256 || '')) || !Array.isArray(manifest.binary_artifacts) || manifest.binary_artifacts.length < 1 || !/^[0-9a-f]{64}$/.test(String(manifest.binary_artifacts_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(manifest.policy_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(manifest.source_policy_sha256 || manifest.policy_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(manifest.core_provenance_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(manifest.build_inputs_sha256 || '')) || !/^[0-9a-f]{64}$/.test(String(manifest.toolchain_sha256 || '')) || !manifest.core_provenance || !manifest.build_inputs || !manifest.dependency_license_manifest || manifest.dependency_license_manifest.format !== 'BIFROST-DEPENDENCY-LICENSES-1' || !/^[0-9a-f]{64}$/.test(String(manifest.dependency_license_manifest.input_sha256 || '')))) fail('BF-SOURCE-MANIFEST');
  if (!allowTestOnly) { validateCoreProvenance(manifest.core_provenance); validateBuildInputManifest(manifest.build_inputs); }
  if (!allowTestOnly && JSON.stringify(manifest).includes('PENDING-EXTERNAL')) fail('BF-SOURCE-INPUT');
  if (!allowTestOnly) validateToolchain(manifest.toolchain, { production: true });
  if (!allowTestOnly && (binaryPlanDigest(manifest.binary_artifacts) !== manifest.binary_artifacts_sha256 || manifest.build_plan_sha256 !== manifest.binary_artifacts_sha256)) fail('BF-SOURCE-MANIFEST');
  if (!allowTestOnly && Array.isArray(manifest.binary_artifacts)) {
    const artifactIds = new Set(); const artifactPaths = new Set();
    for (const artifact of manifest.binary_artifacts) {
      if (!artifact || typeof artifact.id !== 'string' || !SAFE_REFERENCE.test(artifact.id) || artifactIds.has(artifact.id) || typeof artifact.path !== 'string' || !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 || !/^[0-9a-f]{64}$/.test(String(artifact.sha256))) fail('BF-SOURCE-MANIFEST');
      const normalized = archiveRelative(artifact.path); const key = normalized.normalize('NFC').toLowerCase(); if (artifactPaths.has(key)) fail('BF-SOURCE-COLLISION'); artifactIds.add(artifact.id); artifactPaths.add(key);
    }
  }
  if (!manifest.scope?.excluded?.includes('bifrost-control') || !manifest.scope.excluded.includes('bifrost-node-agent')) fail('BF-SOURCE-PRIVATE');
  if (!allowTestOnly && manifest.git && typeof manifest.git === 'object') {
    const files = new Set(manifest.entries.map((entry) => String(entry.path)));
    for (const repo of Object.values(manifest.git)) {
      if (!repo?.available || !Array.isArray(repo.changes)) continue;
      const deletions = new Set(Array.isArray(repo.deletions) ? repo.deletions : []);
      for (const change of repo.changes) {
        const pathName = String(change.path || '').replaceAll('\\', '/');
        const status = String(change.status || '');
        try { safeRelative(pathName); if (change.old_path) safeRelative(String(change.old_path).replaceAll('\\', '/')); } catch { fail('BF-SOURCE-GIT-COVERAGE'); }
        const present = [...files].some((entry) => entry === pathName || entry.endsWith(`/${pathName}`));
        const deleted = status.includes('D') && [...deletions].some((entry) => entry === pathName || entry.endsWith(`/${pathName}`));
        const renamed = (status.includes('R') || status.includes('C')) && String(change.old_path || '').length > 0 && present && [...deletions].some((entry) => entry === change.old_path || entry.endsWith(`/${change.old_path}`));
        if (!present && !deleted && !renamed) fail('BF-SOURCE-GIT-COVERAGE');
        if ((status.includes('R') || status.includes('C')) && !change.old_path) fail('BF-SOURCE-GIT-COVERAGE');
      }
    }
  }
  return manifest;
}

function assertOutputPathSafe(outputDirectory) {
  if (!outputDirectory) return;
  const resolved = path.resolve(outputDirectory); const cwd = path.resolve(process.cwd()); const home = path.resolve(os.homedir());
  const tempRoot = path.resolve(os.tmpdir());
  if (resolved === path.parse(resolved).root || resolved === cwd || resolved.startsWith(`${cwd}${path.sep}`) || (resolved === home || resolved.startsWith(`${home}${path.sep}`)) && !resolved.startsWith(`${tempRoot}${path.sep}`)) fail('BF-SOURCE-OUTPUT');
  let ancestor = resolved;
  while (ancestor && ancestor !== path.dirname(ancestor)) {
    if (existsSync(ancestor)) { const parentStat = lstatSync(ancestor); if (parentStat.isSymbolicLink() || (!parentStat.isDirectory() && parentStat.nlink > 1)) fail('BF-SOURCE-OUTPUT'); }
    ancestor = path.dirname(ancestor);
  }
  if (existsSync(resolved)) {
    // Extraction always owns a newly created staging directory.  Reusing an
    // arbitrary pre-existing empty directory would make a later caller able
    // to confuse ownership/cleanup, so it is rejected unless a future caller
    // explicitly introduces an authenticated owned-output adapter.
    fail('BF-SOURCE-OUTPUT');
  }
}

function verifyArchiveStreaming(archive, manifestFile, outputDirectory, { allowTestOnly = false, unpack = false, sourceEnvelope, rootDescriptor } = {}) {
  if (!existsSync(archive) || statSync(archive).size > MAX_ARCHIVE_BYTES) fail('BF-SOURCE-ARCHIVE');
  const manifestBytes = readFileSync(manifestFile);
  if (manifestBytes[0] === 0xef && manifestBytes[1] === 0xbb && manifestBytes[2] === 0xbf) fail('BF-SOURCE-UTF8');
  const manifestText = strictUtf8(manifestBytes);
  const manifest = JSON.parse(manifestText);
  if (`${canonical(manifest)}\n` !== manifestText) fail('BF-SOURCE-MANIFEST');
  verifyManifestShape(manifest, { allowTestOnly, hasSourceEnvelope: Boolean(sourceEnvelope) });
  if (!allowTestOnly) validateSourceEnvelopeBinding(manifest, archive, manifestBytes, sourceEnvelope, { allowTestOnly, rootDescriptor });
  assertOutputPathSafe(outputDirectory);
  const expected = new Set(['source-bundle-manifest.json', ...manifest.entries.map((entry) => archiveRelative(entry.path))]);
  const expectedRows = new Map([['source-bundle-manifest.json', { bytes: manifestBytes.length, sha256: sha256(manifestBytes), mode: 0o644 }], ...manifest.entries.map((entry) => [archiveRelative(entry.path), { bytes: entry.bytes, sha256: entry.sha256, mode: Number.parseInt(entry.mode, 8) }])]);
  const declaredBytes = manifest.entries.reduce((sum, entry) => sum + entry.bytes, 0);
  if (declaredBytes > 0 && statSync(archive).size > 0 && declaredBytes / statSync(archive).size > MAX_COMPRESSION_RATIO) fail('BF-SOURCE-COMPRESSION');
  let outputCreated = false; let outputRoot;
  if (outputDirectory) { assertOutputPathSafe(outputDirectory); mkdirSync(outputDirectory, { recursive: true }); outputCreated = true; outputRoot = path.resolve(outputDirectory); }
  const seen = new Set(); const seenDirectories = new Set(); const manifestChunks = []; const openOutputs = new Map();
  try {
    const streamed = streamUstarArchive(archive, {
      onEntryStart: (meta) => {
        if (seen.has(meta.key) || seenDirectories.has(meta.key)) fail('BF-SOURCE-ARCHIVE-DUPLICATE');
        if (meta.type === '5') {
          const hasChild = [...expected].some((name) => name.toLowerCase().startsWith(`${meta.key}/`));
          if (!hasChild) fail('BF-SOURCE-ARCHIVE');
          seenDirectories.add(meta.key); return {};
        }
        const row = expectedRows.get(meta.name); if (!row) fail('BF-SOURCE-ARCHIVE');
        const modeMatches = meta.mode === row.mode || (process.platform === 'win32' && (meta.mode & 0o666) === (row.mode & 0o666) && (meta.mode & ~0o666) <= 0o111);
        if (!modeMatches || meta.size !== row.bytes) fail('BF-SOURCE-ARCHIVE');
        seen.add(meta.name);
        if (outputRoot) {
          const target = path.join(outputRoot, ...meta.name.split('/')); mkdirSync(path.dirname(target), { recursive: true }); assertNoLinkChain(path.dirname(target), outputRoot);
          const fd = openSync(target, 'wx', row.mode); openOutputs.set(meta.key, fd);
        }
        return {};
      },
      onEntryChunk: (meta, chunk) => {
        if (meta.name === 'source-bundle-manifest.json') manifestChunks.push(Buffer.from(chunk));
        const fd = openOutputs.get(meta.key); if (fd !== undefined) writeSync(fd, chunk);
      },
      onEntryEnd: (meta, digest) => {
        const row = expectedRows.get(meta.name);
        if (meta.type !== '5' && (!row || digest.bytes !== row.bytes || digest.sha256 !== row.sha256)) fail(meta.name === 'source-bundle-manifest.json' ? 'BF-SOURCE-MANIFEST' : 'BF-SOURCE-ARCHIVE');
        const fd = openOutputs.get(meta.key); if (fd !== undefined) { fsyncSync(fd); closeSync(fd); openOutputs.delete(meta.key); chmodSync(path.join(outputRoot, ...meta.name.split('/')), row.mode); utimesSync(path.join(outputRoot, ...meta.name.split('/')), 0, 0); }
      }
    });
    for (const fd of openOutputs.values()) closeSync(fd);
    openOutputs.clear();
    if (seen.size !== expected.size || [...expected].some((name) => !seen.has(name))) fail('BF-SOURCE-ARCHIVE');
    if (!Buffer.concat(manifestChunks).equals(manifestBytes)) fail('BF-SOURCE-MANIFEST');
    return { manifest, entries: manifest.entries.length, total_bytes: declaredBytes, archive_bytes: streamed.archiveBytes };
  } catch (error) {
    for (const fd of openOutputs.values()) { try { closeSync(fd); } catch {} }
    if (outputCreated) rmSync(outputRoot, { recursive: true, force: true });
    throw error;
  }
}

function verifyArchive(archive, manifestFile, outputDirectory, options = {}) {
  return verifyArchiveStreaming(archive, manifestFile, outputDirectory, options);
}

function packSourceBundle(manifestInfo, archive) {
  if (existsSync(archive)) { const existing = lstatSync(archive); if (!existing.isFile() || existing.isSymbolicLink() || existing.nlink > 1) fail('BF-SOURCE-ARCHIVE'); }
  const staging = mkdtempSync(path.join(os.tmpdir(), 'bifrost-source-pack-'));
  try {
    const manifestTarget = path.join(staging, 'source-bundle-manifest.json');
    copyFileSync(manifestInfo.manifestPath, manifestTarget);
    chmodSync(manifestTarget, 0o644); utimesSync(manifestTarget, 0, 0);
    for (const row of manifestInfo.rows) {
      // Re-read and verify the exact input immediately before copying. A
      // dirty/untracked file changed after manifest creation is a release
      // failure; silently taking a later workspace version would break the
      // binary/source correspondence.
      const bytes = readFileSync(row.absolute);
      if (bytes.length !== row.bytes || sha256(bytes) !== row.sha256) fail('BF-SOURCE-INPUT-CHANGED');
      const target = path.join(staging, ...row.path.split('/')); mkdirSync(path.dirname(target), { recursive: true }); writeFileSync(target, bytes, { mode: Number.parseInt(row.mode, 8) }); chmodSync(target, Number.parseInt(row.mode, 8)); utimesSync(target, 0, 0);
    }
    const normalizeDirectories = (directory) => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const child = path.join(directory, entry.name);
        if (entry.isDirectory()) normalizeDirectories(child);
      }
      utimesSync(directory, 0, 0);
    };
    normalizeDirectories(staging);
    mkdirSync(path.dirname(archive), { recursive: true });
    const names = ['source-bundle-manifest.json', ...manifestInfo.rows.map((row) => row.path)].sort(bytewise);
    const byName = new Map([['source-bundle-manifest.json', { absolute: manifestTarget, bytes: statSync(manifestTarget).size, mode: 0o644 }], ...manifestInfo.rows.map((row) => [row.path, row])]);
    const field = (buffer, start, length, value) => { const bytes = Buffer.from(String(value), 'ascii'); if (bytes.length > length) fail('BF-SOURCE-ARCHIVE-NAME'); bytes.copy(buffer, start); };
    const octal = (value, length) => { const text = Number(value).toString(8); if (text.length + 1 > length) fail('BF-SOURCE-ARCHIVE-METADATA'); return `${'0'.repeat(length - text.length - 1)}${text}\0`; };
    const headerFor = (name, size, mode) => {
      const header = Buffer.alloc(512); let prefix = ''; let leaf = name;
      if (Buffer.byteLength(leaf, 'utf8') > 100) { const split = name.lastIndexOf('/'); if (split < 1) fail('BF-SOURCE-ARCHIVE-NAME'); prefix = name.slice(0, split); leaf = name.slice(split + 1); }
      if (Buffer.byteLength(leaf, 'utf8') > 100 || Buffer.byteLength(prefix, 'utf8') > 155) fail('BF-SOURCE-ARCHIVE-NAME');
      field(header, 0, 100, leaf); field(header, 100, 8, octal(mode, 8)); field(header, 108, 8, octal(0, 8)); field(header, 116, 8, octal(0, 8)); field(header, 124, 12, octal(size, 12)); field(header, 136, 12, octal(0, 12)); header.fill(0x20, 148, 156); header[156] = 0x30; field(header, 257, 6, 'ustar\0'); field(header, 263, 2, '00'); field(header, 345, 155, prefix);
      let sum = 0; for (const byte of header) sum += byte; const check = `${'0'.repeat(6 - sum.toString(8).length)}${sum.toString(8)}\0 `; field(header, 148, 8, check); return header;
    };
    const output = openSync(archive, 'w');
    try {
      for (const name of names) {
        const row = byName.get(name); const bytes = readFileSync(row.absolute); if (bytes.length !== row.bytes || sha256(bytes) !== (row.sha256 || sha256(bytes))) fail('BF-SOURCE-INPUT-CHANGED');
        const mode = typeof row.mode === 'number' ? row.mode : Number.parseInt(String(row.mode), 8);
        writeSync(output, headerFor(name, bytes.length, mode));
        // writeFileSync with a numeric fd is intentionally used only for the
        // already-open archive handle; no path is re-opened between hashing
        // and writing.
        const chunk = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, bytes.length))); let offset = 0;
        while (offset < bytes.length) { const length = Math.min(chunk.length, bytes.length - offset); bytes.copy(chunk, 0, offset, offset + length); writeSync(output, chunk, 0, length); offset += length; }
        const padding = (512 - (bytes.length % 512)) % 512; if (padding) writeSync(output, Buffer.alloc(padding));
      }
      writeSync(output, Buffer.alloc(1024)); fsyncSync(output);
    } finally { closeSync(output); }
    return archive;
  } finally { rmSync(staging, { recursive: true, force: true }); }
}

export { buildManifest, packSourceBundle, verifyArchive, verifyManifestShape, safeRelative, canonical, parseUstarArchive, canonicalBinaryPlan, binaryPlanDigest, createSourceSnapshot, loadSourceSnapshot };

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const command = process.argv[2];
  const arg = (name, fallback) => { const index = process.argv.indexOf(name); return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback; };
  try {
    if (command === 'snapshot') {
      const root = arg('--root', path.resolve(import.meta.dirname, '..', '..', '..'));
      const result = createSourceSnapshot(root, arg('--output'), { testOnly: process.argv.includes('--test-only') });
      console.log(JSON.stringify(result));
    } else if (command === 'build') {
      const root = arg('--root', path.resolve(import.meta.dirname, '..', '..', '..')); const manifest = buildManifest(root, arg('--manifest'), { testOnly: process.argv.includes('--test-only'), releaseManifestPath: arg('--release-manifest'), coreProvenancePath: arg('--core-provenance'), buildInputManifestPath: arg('--build-input-manifest'), dependencyLicenseManifestPath: arg('--dependency-license-manifest'), sourceSnapshotPath: arg('--source-snapshot') });
      const archive = packSourceBundle(manifest, arg('--archive', path.join(path.dirname(manifest.manifestPath), 'BIFROST-SOURCE-BUNDLE.tar'))); console.log(JSON.stringify({ manifest: manifest.manifestPath, archive, manifest_sha256: manifest.manifestSha256, entries: manifest.rows.length }));
    } else if (command === 'verify') {
      let envelope;
      const envelopePath = arg('--source-envelope');
      if (envelopePath) envelope = readJson(envelopePath);
      const rootFile = arg('--root-public-key-file'); const rootDescriptor = rootFile ? readProvisionedReleaseRoot(rootFile, { testOnly: process.argv.includes('--test-only') }) : undefined;
      const result = verifyArchive(arg('--archive'), arg('--manifest'), arg('--output'), { allowTestOnly: process.argv.includes('--test-only'), unpack: true, sourceEnvelope: envelope, rootDescriptor }); console.log(JSON.stringify({ ok: true, entries: result.entries, total_bytes: result.total_bytes, archive_bytes: result.archive_bytes }));
    } else throw new Error('usage: source-bundle.mjs snapshot|build|verify');
  } catch (error) { console.error(error.code || 'BF-SOURCE-BUNDLE'); process.exitCode = 1; }
}
