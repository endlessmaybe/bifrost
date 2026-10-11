import { createHash } from 'node:crypto';

// The binary plan is the one shared representation used by source-bundle,
// SBOM generation and release signing.  It deliberately excludes supporting
// source/notice artifacts: those are appended only after this immutable build
// plan has been produced.  Do not silently preserve arbitrary object fields;
// every consumer must compare this exact byte representation.
const PLAN_KEYS = ['id', 'path', 'install_path', 'platform', 'arch', 'kind', 'bytes', 'sha256'];
const ID = /^[A-Za-z0-9._-]{1,128}$/;
const HEX = /^[0-9a-f]{64}$/;
const PATH = /^[^\\\0]+$/;

const bytewise = (a, b) => Buffer.from(String(a), 'utf8').compare(Buffer.from(String(b), 'utf8'));

function canonical(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item) ?? 'null').join(',')}]`;
  return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort(bytewise).map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function fail(code, message = code) { const error = new Error(message); error.code = code; throw error; }

function normalizeBinaryArtifact(artifact) {
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) fail('BF-RELEASE-BUILD-PLAN');
  const keys = Object.keys(artifact);
  for (const key of PLAN_KEYS) if (!Object.prototype.hasOwnProperty.call(artifact, key)) fail('BF-RELEASE-BUILD-PLAN');
  if (!ID.test(String(artifact.id)) || !PATH.test(String(artifact.path)) || !PATH.test(String(artifact.install_path))) fail('BF-RELEASE-BUILD-PLAN');
  if (!['android', 'windows', 'linux'].includes(artifact.platform) || typeof artifact.arch !== 'string' || !artifact.arch || typeof artifact.kind !== 'string' || !artifact.kind) fail('BF-RELEASE-BUILD-PLAN');
  if (!Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 || artifact.bytes > 1024 * 1024 * 1024 || !HEX.test(String(artifact.sha256))) fail('BF-RELEASE-BUILD-PLAN');
  return {
    id: String(artifact.id),
    path: String(artifact.path).replaceAll('\\', '/'),
    install_path: String(artifact.install_path).replaceAll('\\', '/'),
    platform: String(artifact.platform),
    arch: String(artifact.arch),
    kind: String(artifact.kind),
    bytes: artifact.bytes,
    sha256: String(artifact.sha256).toLowerCase()
  };
}

function canonicalBinaryPlan(artifacts) {
  if (!Array.isArray(artifacts)) fail('BF-RELEASE-BUILD-PLAN');
  const rows = artifacts.filter((artifact) => artifact?.kind !== 'source' && artifact?.kind !== 'notice').map(normalizeBinaryArtifact);
  if (rows.length !== artifacts.filter((artifact) => artifact?.kind !== 'source' && artifact?.kind !== 'notice').length) fail('BF-RELEASE-BUILD-PLAN');
  const ids = new Set(); const paths = new Set(); const installs = new Set();
  for (const row of rows) {
    const id = row.id.toLowerCase(); const p = row.path.normalize('NFC').toLowerCase(); const i = row.install_path.normalize('NFC').toLowerCase();
    if (ids.has(id) || paths.has(p) || installs.has(i)) fail('BF-RELEASE-BUILD-PLAN');
    ids.add(id); paths.add(p); installs.add(i);
  }
  rows.sort((a, b) => bytewise(a.id, b.id) || bytewise(a.path, b.path));
  return canonical(rows);
}

function binaryPlanDigest(artifacts) { return createHash('sha256').update(Buffer.from(canonicalBinaryPlan(artifacts), 'utf8')).digest('hex'); }

export { PLAN_KEYS, canonical, canonicalBinaryPlan, binaryPlanDigest, normalizeBinaryArtifact };
