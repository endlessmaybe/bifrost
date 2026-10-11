import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  configKeyStateDigest,
  selectConfigSigningKey,
  signConfigKeyState,
  verifyConfigKeyState,
} from '../config-contracts/config-key-state.mjs';

const pem = (key) => key.export({ type: 'spki', format: 'pem' }).toString();
const fingerprint = (key) => createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
const root = generateKeyPairSync('ed25519');
const v1 = generateKeyPairSync('ed25519');
const v2 = generateKeyPairSync('ed25519');
const rootPem = pem(root.publicKey);
const rootFingerprint = fingerprint(root.publicKey);

function entry(keyId, pair, activationFloor, retirementFloor = null) {
  return { key_id: keyId, public_key_pem: pem(pair.publicKey), fingerprint: fingerprint(pair.publicKey), activation_floor: activationFloor, retirement_floor: retirementFloor };
}

function state({ generation = 1, active = 'config-signing-v1', keys = [entry('config-signing-v1', v1, 1)], previous = null } = {}) {
  return signConfigKeyState({
    version: 1,
    purpose: 'config-signing-key-state',
    root_key_id: 'bifrost-root-v1',
    root_fingerprint: rootFingerprint,
    generation,
    active_key_id: active,
    trusted_keys: keys,
    previous_state_digest: previous,
  }, root.privateKey);
}

const verify = (value, options = {}) => verifyConfigKeyState(value, { rootKeyPem: rootPem, rootFingerprint, ...options });

test('config key state accepts v1, overlap, v2 active, and retirement transition', () => {
  const first = state();
  const verified1 = verify(first, { currentConfigVersion: 1 });
  assert.equal(selectConfigSigningKey(verified1, 'config-signing-v1', 1).key_id, 'config-signing-v1');

  const overlap = state({
    generation: 2,
    active: 'config-signing-v1',
    keys: [entry('config-signing-v1', v1, 1), entry('config-signing-v2', v2, 20)],
    previous: configKeyStateDigest(first),
  });
  const verified2 = verify(overlap, { previousGeneration: 1, previousDigest: configKeyStateDigest(first), currentConfigVersion: 19 });
  assert.throws(() => selectConfigSigningKey(verified2, 'config-signing-v2', 19), /BF-CONFIG-KEY-NOT-ACTIVE/);
  assert.equal(selectConfigSigningKey(verified2, 'config-signing-v2', 20).key_id, 'config-signing-v2');

  const activeV2 = state({
    generation: 3,
    active: 'config-signing-v2',
    keys: [entry('config-signing-v1', v1, 1, 40), entry('config-signing-v2', v2, 20)],
    previous: configKeyStateDigest(overlap),
  });
  const verified3 = verify(activeV2, { previousGeneration: 2, previousDigest: configKeyStateDigest(overlap), currentConfigVersion: 20 });
  assert.equal(selectConfigSigningKey(verified3, 'config-signing-v1', 39).key_id, 'config-signing-v1');
  assert.throws(() => selectConfigSigningKey(verified3, 'config-signing-v1', 40), /BF-CONFIG-KEY-RETIRED/);
  assert.equal(selectConfigSigningKey(verified3, 'config-signing-v2', 40).key_id, 'config-signing-v2');
});

test('config key state rejects stale, equivocated, skipped, and mis-chained generations', () => {
  const first = state();
  const firstDigest = configKeyStateDigest(first);
  assert.throws(() => verify(first, { previousGeneration: 2, previousDigest: 'a'.repeat(64) }), /BF-CONFIG-KEY-ROLLBACK/);
  assert.throws(() => verify(first, { previousGeneration: 1, previousDigest: 'a'.repeat(64) }), /BF-CONFIG-KEY-EQUIVOCATION/);

  const skipped = state({ generation: 3, previous: firstDigest });
  assert.throws(() => verify(skipped, { previousGeneration: 1, previousDigest: firstDigest }), /BF-CONFIG-KEY-ROLLBACK/);

  const wrongChain = state({ generation: 2, previous: 'b'.repeat(64) });
  assert.throws(() => verify(wrongChain, { previousGeneration: 1, previousDigest: firstDigest }), /BF-CONFIG-KEY-ROLLBACK/);
});

test('config key state rejects unknown, premature, and retired signing keys', () => {
  const value = state({
    active: 'config-signing-v2',
    keys: [entry('config-signing-v1', v1, 1, 30), entry('config-signing-v2', v2, 20)],
  });
  const verified = verify(value, { currentConfigVersion: 20 });
  assert.throws(() => selectConfigSigningKey(verified, 'config-signing-v3', 20), /BF-CONFIG-KEY-UNKNOWN/);
  assert.throws(() => selectConfigSigningKey(verified, 'config-signing-v2', 19), /BF-CONFIG-KEY-NOT-ACTIVE/);
  assert.throws(() => selectConfigSigningKey(verified, 'config-signing-v1', 30), /BF-CONFIG-KEY-RETIRED/);
});

test('config key state rejects malformed trust lists and wrong root/signature', () => {
  const first = state();
  const wrongRoot = generateKeyPairSync('ed25519');
  assert.throws(() => verifyConfigKeyState(first, { rootKeyPem: pem(wrongRoot.publicKey), rootFingerprint: fingerprint(wrongRoot.publicKey) }), /BF-CONFIG-TRUST-ROOT/);

  const tampered = { ...first, active_key_id: 'config-signing-v2' };
  assert.throws(() => verify(tampered), /BF-CONFIG-KEY-SIGNATURE/);

  const duplicate = state({ keys: [entry('config-signing-v1', v1, 1), entry('config-signing-v1', v1, 2)] });
  assert.throws(() => verify(duplicate), /BF-CONFIG-KEY-STATE/);

  const unsorted = state({ keys: [entry('config-signing-v2', v2, 20), entry('config-signing-v1', v1, 1)], active: 'config-signing-v2' });
  assert.throws(() => verify(unsorted), /BF-CONFIG-KEY-STATE/);
});

test('v2 package key is rejected before overlap and accepted after overlap', () => {
  const before = verify(state());
  assert.throws(() => selectConfigSigningKey(before, 'config-signing-v2', 20), /BF-CONFIG-KEY-UNKNOWN/);
  const overlap = verify(state({ keys: [entry('config-signing-v1', v1, 1), entry('config-signing-v2', v2, 20)] }));
  assert.equal(selectConfigSigningKey(overlap, 'config-signing-v2', 20).key_id, 'config-signing-v2');
});
