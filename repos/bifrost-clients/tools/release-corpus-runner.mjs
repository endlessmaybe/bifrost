// Machine-readable Node runner for the complete release corpus.  The runner
// deliberately has no per-vector switch: every vector is resolved to its
// complete envelope (or the corpus baseline for legacy vectors) and passed to
// the same offline tool verifier.
import { readFileSync } from 'node:fs';
import { verifyOfflineReleaseEnvelope } from '../config-contracts/release-offline-verifier.mjs';
import { markTestRoot } from '../tests/release-test-root.mjs';

export function runReleaseCorpus(file = new URL('../config-contracts/release-envelope-corpus-v2.json', import.meta.url)) {
  const corpus = JSON.parse(readFileSync(file, 'utf8'));
  const rootDescriptor = markTestRoot(corpus.trust);
  const output = [];
  for (const vector of corpus.vectors) {
    const execution = vector.execution || {};
    const previous = execution.previous_state || {};
    const source = vector.envelope && typeof vector.envelope === 'object' ? vector.envelope : corpus.base_envelope;
    let disposition = 'accept'; let errorFamily = null; let plan = null;
    try {
      if (execution.state_status === 'corrupt' || execution.state_status === 'missing') throw new Error('BF-RELEASE-STATE-CORRUPT');
      const result = verifyOfflineReleaseEnvelope(applyOperations(source, vector.operations || []), {
        rootDescriptor,
        previousSequence: previous.sequence ?? 0,
        previousManifestDigest: previous.manifest_digest,
        previousAuthorityGeneration: previous.authority_generation ?? 0,
        previousAuthorityDigest: previous.authority_digest,
        previousSigningKeyId: previous.signing_key_id,
        previousSigningKeyFingerprint: previous.signing_key_fingerprint,
        channel: execution.channel,
        currentClientVersion: execution.client_version,
        currentConfigVersion: execution.config_version
      });
      plan = result.plan;
      disposition = result.idempotent ? 'idempotent' : 'accept';
    } catch (error) {
      disposition = 'reject';
      errorFamily = String(error?.message || 'BF-RELEASE-UNKNOWN').split(':')[0];
    }
    output.push({
      id: vector.id,
      disposition,
      error_family: errorFamily,
      manifest_digest: plan?.manifest_digest ?? null,
      envelope_digest: plan?.envelope_digest ?? null,
      allowlist_digest: plan?.allowlist_digest ?? null,
      authority_digest: plan?.authority_digest ?? null,
      root_fingerprint: plan?.root_fingerprint ?? null
    });
  }
  return output;
}

function applyOperations(source, operations) {
  const value = structuredClone(source);
  for (const operation of operations) {
    if (typeof operation.manifest_field === 'string') {
      const manifest = JSON.parse(value.manifest_text);
      manifest[operation.manifest_field] = structuredClone(operation.set);
      value.manifest_text = JSON.stringify(manifest);
      continue;
    }
    if (typeof operation.manifest_number === 'string') {
      const token = `"${operation.manifest_number}":1`;
      if (!value.manifest_text.includes(token)) throw new Error('BF-RELEASE-CORPUS-MUTATION');
      value.manifest_text = value.manifest_text.replace(token, `"${operation.manifest_number}":${operation.encoding}`);
      continue;
    }
    if (typeof operation.manifest_duplicate === 'string') {
      const marker = `"${operation.manifest_duplicate}":`;
      const start = value.manifest_text.indexOf(marker);
      const comma = value.manifest_text.indexOf(',', start);
      if (start < 0 || comma < 0) throw new Error('BF-RELEASE-CORPUS-MUTATION');
      const field = value.manifest_text.slice(start, comma);
      value.manifest_text = `${value.manifest_text.slice(0, comma)},${field}${value.manifest_text.slice(comma)}`;
      continue;
    }
    if (!Array.isArray(operation.path) || operation.path.length === 0) throw new Error('BF-RELEASE-CORPUS-MUTATION');
    let target = value;
    for (const key of operation.path.slice(0, -1)) target = target[key];
    const leaf = operation.path.at(-1);
    if (operation.flip_first === true) {
      const current = String(target[leaf] || '');
      target[leaf] = `${current[0] === 'A' ? 'B' : 'A'}${current.slice(1)}`;
    } else target[leaf] = structuredClone(operation.set);
  }
  return value;
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}`) {
  for (const row of runReleaseCorpus()) process.stdout.write(`${JSON.stringify(row)}\n`);
}
