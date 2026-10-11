import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { PROTOCOL_CONTRACT, PROTOCOL_CONTRACT_FINGERPRINT, canonicalProtocolJson, validateContractEnvelope } from '../config-contracts/protocol-contract.mjs';
import { ERROR_REGISTRY, ERROR_REGISTRY_FINGERPRINT, errorDescriptor } from '../config-contracts/error-registry.mjs';
import vectors from '../config-contracts/protocol-golden-vectors-v1.json' with { type: 'json' };
import { parseReleaseEnvelope } from '../release/update-manager.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('single protocol source has strict OpenAPI, budgets, and independent version axes', () => {
  execFileSync(process.execPath, [path.join(repo, 'tools', 'generate-protocol-contract.mjs'), '--check'], { cwd: repo, stdio: 'pipe' });
  assert.equal(PROTOCOL_CONTRACT.openapi, '3.1.0');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].contract_id, 'bifrost.protocol');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].contract_version, '1.0.0');
  assert.notEqual(PROTOCOL_CONTRACT['x-bifrost'].api_schema_version, PROTOCOL_CONTRACT['x-bifrost'].config_schema_version);
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].compatibility.current.config_schema_version, '1.0');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].compatibility.previous.status, 'NOT-APPLICABLE');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].compatibility.unsupported_policy, 'fail-closed-before-activation');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].schema_ids.desired_state, 'bifrost.node.desired-state.v2');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].schema_ids.node_ack, 'bifrost.node.ack.v1');
  assert.equal(PROTOCOL_CONTRACT['x-bifrost'].error_registry.fingerprint, ERROR_REGISTRY_FINGERPRINT);
  assert.match(PROTOCOL_CONTRACT.paths['/v1/enrollment/redeem'].post.requestBody.$ref, /Enrollment$/);
  assert.match(PROTOCOL_CONTRACT.paths['/v1/pairing/create'].post.requestBody.$ref, /PairingCreate$/);
  assert.match(PROTOCOL_CONTRACT.paths['/v1/pairing/redeem'].post.requestBody.$ref, /PairingRedeem$/);
  assert.match(PROTOCOL_CONTRACT.paths['/v1/recovery/request'].post.requestBody.$ref, /Recovery$/);
  assert.ok(PROTOCOL_CONTRACT['x-bifrost'].budgets.request_bytes <= 1024 * 1024);
  assert.ok(Object.keys(PROTOCOL_CONTRACT.paths).length >= 10);
  for (const [name, schema] of Object.entries(PROTOCOL_CONTRACT.components.schemas)) {
    if (schema.type === 'object' || schema.properties || schema.required) {
      assert.equal(schema.additionalProperties, false, `${name} must reject unknown fields`);
    }
  }
});

test('workflow status accepts nullable ref siblings and rejects malformed/null non-nullable refs', () => {
  const action = () => ({ allowed: false, reason: '外部发布信任适配器尚未配置', required_phase: 'blocked', trust_adapter_state: 'adapter_unavailable', preview_required: true });
  const actions = { discover: action(), verify_candidate: action(), start_canary: action(), confirm_canary: action(), promote: action(), rollback: action(), canary_targets: [], rollback_points: [] };
  const empty = {
    schema_version: 'BIFROST-RELEASE-WORKFLOW-STATUS-1', state: 'absent', active: null, candidates: [],
    canary: { state: 'not_started', targets: [], confirmed: 0, total: 0, progress_percent: 0 },
    receipt: { state: 'pending_external', sequence: null, summary: '尚无可认证发布回执' }, recovery: null, operations: [],
    eligibility: { ...actions, candidate_eligibility: [] }, candidate_eligibility: [], summary: '当前没有可验证发布物'
  };
  assert.doesNotThrow(() => validateContractEnvelope('AdminReleaseWorkflowStatusResponse', empty));
  const missingActive = { ...empty }; delete missingActive.active;
  assert.throws(() => validateContractEnvelope('AdminReleaseWorkflowStatusResponse', missingActive));
  assert.throws(() => validateContractEnvelope('AdminReleaseWorkflowStatusResponse', { ...empty, active: {} }));
  assert.throws(() => validateContractEnvelope('AdminReleaseWorkflowStatusResponse', { ...empty, canary: null }));
});

test('canonical cross-language vectors are stable and valid', () => {
  for (const vector of vectors.vectors) {
    const digest = createHash('sha256').update(Buffer.from(vector.canonical_json, 'utf8')).digest('hex');
    assert.equal(digest, vector.sha256, vector.id);
    if (vector.canonical_json.length > 0) {
      assert.equal(canonicalProtocolJson(JSON.parse(vector.canonical_json)), vector.canonical_json, vector.id);
      if (vector.schema && vector.schema !== 'SignedBytes') assert.doesNotThrow(() => validateContractEnvelope(vector.schema, JSON.parse(vector.canonical_json)), vector.id);
    }
    if (vector.signature_base64url) {
      const raw = Buffer.from(vector.public_key_raw_base64url, 'base64url');
      const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
      const signature = Buffer.from(vector.signature_base64url, 'base64url');
      assert.equal(verify(null, Buffer.from(vector.canonical_json, 'utf8'), key, signature), true, vector.id);
      assert.equal(verify(null, Buffer.from(vector.canonical_json + 'tampered', 'utf8'), key, signature), false, vector.id);
    }
  }
  assert.equal(vectors.contract_id, PROTOCOL_CONTRACT['x-bifrost'].contract_id);
  assert.equal(vectors.contract_version, PROTOCOL_CONTRACT['x-bifrost'].contract_version);
  assert.match(PROTOCOL_CONTRACT_FINGERPRINT, /^[0-9a-f]{64}$/);
  assert.ok(vectors.vectors.some((vector) => vector.signature_base64url && vector.test_only));
  assert.ok(vectors.negative_vectors.length >= 8);
  for (const vector of vectors.negative_vectors) {
    if (vector.json && vector.schema && vector.schema !== 'SignedBytes') {
      const value = vector.id === 'oversize-string'
        ? { code: 'BF-TEST-CONTRACT', message_key: 'error.generic', request_id: 'req_TESTONLY01', message: 'X'.repeat(5000) }
        : JSON.parse(vector.json);
      if (vector.operation === 'canonical-bytes') {
        assert.notEqual(canonicalProtocolJson(value), vector.json, vector.id);
      } else {
        assert.throws(() => validateContractEnvelope(vector.schema, value), undefined, vector.id);
      }
    }
  }
});

test('strict envelope rejects duplicate, unknown, invalid UTF-8 and noncanonical input', () => {
  assert.throws(() => parseReleaseEnvelope('{"manifest_text":"x","manifest_text":"y","signature":"x"}'), /duplicate/i);
  assert.throws(() => parseReleaseEnvelope('{"manifest_text":"x","signature":"x","extra":true}'), /schema|FIELDS/i);
  assert.throws(() => parseReleaseEnvelope(Buffer.from([0x7b, 0x22, 0x6d, 0xc3, 0x7d])), /UTF-8|utf-8/i);
  assert.throws(() => validateContractEnvelope('Error', { code: 'BF-TEST-CONTRACT', message_key: 'error.generic' }), /shape/i);
  assert.throws(() => validateContractEnvelope('Error', { code: 'BF-TEST-CONTRACT', message_key: 'error.generic', request_id: 'req_TESTONLY01', extra: true }), /shape/i);
  for (const vector of vectors.negative_vectors.filter((item) => item.raw_utf8_base64)) {
    assert.throws(() => parseReleaseEnvelope(Buffer.from(vector.raw_utf8_base64, 'base64')), undefined, vector.id);
  }
});

test('contract and vector files contain only TEST-ONLY/reserved fixtures', () => {
  const files = ['config-contracts/protocol-contract-v1.json', 'config-contracts/protocol-golden-vectors-v1.json', 'config-contracts/error-registry-v1.json'];
  for (const file of files) {
    const text = readFileSync(path.join(repo, file), 'utf8');
    assert.doesNotMatch(text, /-----BEGIN (?:PRIVATE|RSA PRIVATE) KEY-----/);
    assert.doesNotMatch(text, /socks5:\/\/[^\s<]+:[^\s<]+@/i);
    assert.doesNotMatch(text, /(?:password|token|secret)\s*[:=]\s*['"][^<\n]{16,}/i);
  }
});

test('single error registry maps stable codes without existence leakage', () => {
  assert.equal(ERROR_REGISTRY.contract_id, 'bifrost.errors');
  assert.match(ERROR_REGISTRY_FINGERPRINT, /^[0-9a-f]{64}$/);
  assert.ok(ERROR_REGISTRY.codes.includes('BF-CONTRACT-SCHEMA'));
  assert.equal(ERROR_REGISTRY.entries.length, ERROR_REGISTRY.codes.length);
  assert.equal(new Set(ERROR_REGISTRY.entries.map((entry) => entry.code)).size, ERROR_REGISTRY.entries.length);
  const auth = errorDescriptor('BF-AUTH-003');
  assert.equal(auth.http_status, 401); assert.equal(auth.existence_leak, false);
  const unknown = errorDescriptor('BF-UNKNOWN-TEST-ONLY');
  assert.equal(unknown.existence_leak, false); assert.equal(typeof unknown.message_zh, 'string');
  assert.equal(errorDescriptor('BF-HTTP-TIMEOUT').retryable, true);
  for (const code of ['BF-KEYS-MISSING', 'BF-ADMIN-SECRET', 'BF-ADMIN-SESSION-LIMIT', 'BF-AUDIT-KEYS', 'BF-NODE-ACK-REQUIRED']) { assert.equal(errorDescriptor(code).http_status, 503, code); assert.equal(errorDescriptor(code).retryable, true, code); }
  assert.equal(errorDescriptor('BF-IDEMPOTENCY-IN-FLIGHT').http_status, 409);
  assert.equal(errorDescriptor('BF-IDEMPOTENCY-IN-FLIGHT').retryable, false);
  assert.equal(ERROR_REGISTRY.entries.some((entry) => entry.code === 'BF-CONTROL-'), false);
  assert.equal(errorDescriptor('BF-CONTROL-').http_status, 400);
  const emitted = new Set();
  const scan = (directory) => { for (const entry of readdirSync(directory, { withFileTypes: true })) { const file = path.join(directory, entry.name); if (entry.isDirectory()) scan(file); else if (/\.m?js$/.test(entry.name)) for (const match of readFileSync(file, 'utf8').matchAll(/BF-[A-Z0-9]+(?:-[A-Z0-9]+)+/g)) emitted.add(match[0]); } };
  scan(path.resolve(repo, '..', 'bifrost-control', 'src')); scan(path.resolve(repo, '..', 'bifrost-node-agent', 'src'));
  const familyMatches = (code, pattern) => { if (!pattern.includes('*')) return code === pattern; const [prefix, suffix = ''] = pattern.split('*'); return code.startsWith(prefix) && code.endsWith(suffix) && code.length > prefix.length + suffix.length; };
  for (const code of emitted) assert.ok(ERROR_REGISTRY.entries.some((entry) => entry.code === code) || ERROR_REGISTRY.families.some((family) => family.patterns.some((pattern) => familyMatches(code, pattern))), `emitted code missing from registry: ${code}`);
});

test('schema validator rejects null/missing/unknown, depth/count overflow and preserves Unicode edge bytes', () => {
  assert.throws(() => validateContractEnvelope('EnrollmentRequest', { invite_code: null }), /shape|type/i);
  assert.throws(() => validateContractEnvelope('EnrollmentRequest', { invite_code: 'TEST-ONLY-invite' }), /shape/i);
  assert.throws(() => validateContractEnvelope('EnrollmentRequest', { invite_code: 'TEST-ONLY-invite', platform: 'android', device_id: 'TEST-ONLY-device', signing_public_key: 'A'.repeat(32), encryption_public_key: 'B'.repeat(32), key_level: 'software', extra: true }), /shape/i);
  assert.throws(() => validateContractEnvelope('Error', { code: 'BF-TEST', message_key: 'error.test', request_id: 'req_TESTONLY01', operation_id: 'x'.repeat(5000) }), /string/i);
  const nfc = 'é'; const nfd = 'e\u0301';
  assert.notEqual(canonicalProtocolJson({ value: nfc }), canonicalProtocolJson({ value: nfd }));
  assert.doesNotThrow(() => validateContractEnvelope('Error', { code: 'BF-TEST', message_key: 'error.test', request_id: 'req_TESTONLY01' }));
});

test('shared schema vectors exercise nested minProperties, nullable, and real DesiredState timestamp', () => {
  for (const vector of vectors.schema_vectors || []) {
    const value = JSON.parse(vector.json);
    if (vector.expected === 'accept') assert.doesNotThrow(() => validateContractEnvelope(vector.schema, value), vector.id);
    else assert.throws(() => validateContractEnvelope(vector.schema, value), undefined, vector.id);
  }
  assert.throws(() => validateContractEnvelope('Page', {}), /PROPERTIES/);
  assert.doesNotThrow(() => validateContractEnvelope('Page', { next_cursor: null }));
});

test('shared signature negatives reach Ed25519 verification with structurally valid bytes', () => {
  const base = vectors.vectors.find((vector) => vector.id === 'node-ack-signed-test-only');
  const raw = Buffer.from(base.public_key_raw_base64url, 'base64url');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
  const message = Buffer.from(base.canonical_json, 'utf8');
  const signature = Buffer.from(base.signature_base64url, 'base64url');
  assert.equal(verify(null, message, key, signature), true);
  assert.equal(verify(null, Buffer.concat([message.subarray(0, message.length - 1), Buffer.from('0')]), key, signature), false);
  const altered = Buffer.from(signature); altered[0] ^= 1; assert.equal(verify(null, message, key, altered), false);
  const wrong = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'spki' });
  assert.equal(verify(null, message, wrong, signature), false);
  assert.equal(verify(null, message, key, signature.subarray(0, 63)), false);
  for (const vector of vectors.signature_vectors || []) {
    assert.equal(vector.schema, 'NodeAckSignedBytes', vector.id);
    assert.equal(vector.input_encoding, 'canonical-utf8', vector.id);
    assert.equal(vector.expected_crypto_stage, 'signature-verification', vector.id);
    let candidateMessage = message; let candidateSignature = signature; let candidateKey = key;
    if (vector.mutation === 'message-byte') { candidateMessage = Buffer.from(message); candidateMessage[candidateMessage.length - 1] ^= 1; }
    if (vector.mutation === 'signature-byte') { candidateSignature = Buffer.from(signature); candidateSignature[0] ^= 1; }
    if (vector.mutation === 'wrong-key') candidateKey = wrong;
    if (vector.mutation === 'truncate-signature') candidateSignature = signature.subarray(0, 63);
    assert.equal(verify(null, candidateMessage, candidateKey, candidateSignature), false, vector.id);
  }
});
