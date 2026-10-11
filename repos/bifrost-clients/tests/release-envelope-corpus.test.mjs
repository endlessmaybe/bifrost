import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyOfflineReleaseEnvelope } from '../config-contracts/release-offline-verifier.mjs';
import { markTestRoot } from './release-test-root.mjs';

const corpusUrl = new URL('../config-contracts/release-envelope-corpus-v2.json', import.meta.url);

function setPath(value, path, next) {
  let target = value;
  for (const key of path.slice(0, -1)) target = target[key];
  target[path.at(-1)] = structuredClone(next);
}

function mutateEnvelope(base, operations = []) {
  const value = structuredClone(base);
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
      if (start < 0) throw new Error('BF-RELEASE-CORPUS-MUTATION');
      const comma = value.manifest_text.indexOf(',', start);
      if (comma < 0) throw new Error('BF-RELEASE-CORPUS-MUTATION');
      const field = value.manifest_text.slice(start, comma);
      value.manifest_text = `${value.manifest_text.slice(0, comma)},${field}${value.manifest_text.slice(comma)}`;
      continue;
    }
    if (!Array.isArray(operation.path) || operation.path.length === 0) throw new Error('BF-RELEASE-CORPUS-MUTATION');
    if (operation.flip_first === true) {
      let target = value;
      for (const key of operation.path.slice(0, -1)) target = target[key];
      const current = String(target[operation.path.at(-1)] || '');
      target[operation.path.at(-1)] = `${current[0] === 'A' ? 'B' : 'A'}${current.slice(1)}`;
    } else setPath(value, operation.path, operation.set);
  }
  return value;
}

test('complete release-envelope corpus uses one full machine-readable input and production verifier', () => {
  const corpus = JSON.parse(readFileSync(corpusUrl, 'utf8'));
  const rootDescriptor = markTestRoot(corpus.trust);
  const outputs = [];
  for (const vector of corpus.vectors) {
    let disposition = 'accept'; let errorFamily = null; let plan = null;
    try {
      const execution = vector.execution || {};
      if (execution.state_status === 'corrupt' || execution.state_status === 'missing') throw new Error('BF-RELEASE-STATE-CORRUPT');
      const sourceEnvelope = vector.envelope && typeof vector.envelope === 'object' ? vector.envelope : corpus.base_envelope;
      const result = verifyOfflineReleaseEnvelope(mutateEnvelope(sourceEnvelope, vector.operations), { rootDescriptor, previousSequence: execution.previous_state?.sequence ?? 0, previousManifestDigest: execution.previous_state?.manifest_digest, previousAuthorityGeneration: execution.previous_state?.authority_generation ?? 0, previousAuthorityDigest: execution.previous_state?.authority_digest, previousSigningKeyId: execution.previous_state?.signing_key_id, previousSigningKeyFingerprint: execution.previous_state?.signing_key_fingerprint, channel: execution.channel, currentClientVersion: execution.client_version, currentConfigVersion: execution.config_version });
      plan = result.plan;
      disposition = result.idempotent ? 'idempotent' : 'accept';
    } catch (error) { disposition = 'reject'; errorFamily = String(error?.message || 'BF-RELEASE-UNKNOWN').split(':')[0]; }
    outputs.push({ id: vector.id, disposition, error_family: errorFamily, manifest_digest: plan?.manifest_digest ?? null, envelope_digest: plan?.envelope_digest ?? null, allowlist_digest: plan?.allowlist_digest ?? null, root_fingerprint: plan?.root_fingerprint ?? null });
    assert.equal(disposition, vector.expected, vector.id);
    assert.equal(errorFamily, vector.error_family ?? null, vector.id + ':error-family');
    if (vector.expected_digests) {
      assert.equal(outputs.at(-1).manifest_digest, vector.expected_digests.manifest, vector.id + ':manifest-digest');
      assert.equal(outputs.at(-1).envelope_digest, vector.expected_digests.envelope, vector.id + ':envelope-digest');
      assert.equal(outputs.at(-1).allowlist_digest, vector.expected_digests.allowlist, vector.id + ':allowlist-digest');
    }
  }
  assert.equal(outputs.length, corpus.vectors.length);
  assert.equal(outputs[0].manifest_digest?.length, 64);
  assert.equal(outputs[0].envelope_digest?.length, 64);
  assert.equal(outputs[0].allowlist_digest?.length, 64);
  assert.equal(outputs[0].root_fingerprint, rootDescriptor.fingerprint);
});
