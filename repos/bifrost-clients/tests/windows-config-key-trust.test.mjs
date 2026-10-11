import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const workspace = path.resolve(root, '..', '..');
const dotnet = path.join(workspace, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
const client = fs.readFileSync(path.join(root, 'windows-app', 'ControlPlaneClient.cs'), 'utf8');
const trust = fs.readFileSync(path.join(root, 'windows-app', 'ConfigKeyTrust.cs'), 'utf8');

test('Windows config signing trust is root-anchored and generation chained', () => {
  for (const marker of [
    'ReleaseContract.TrustRootProvisioned',
    'ReleaseContract.TrustRootKeyId',
    'config-signing-key-state',
    'previous_state_digest',
    'BF-CONFIG-KEY-EQUIVOCATION',
    'BF-CONFIG-KEY-ROLLBACK',
    'BF-CONFIG-KEY-NOT-ACTIVE',
    'BF-CONFIG-KEY-RETIRED',
    'Ed25519.Verify',
    'ActivationFloor',
    'RetirementFloor',
  ]) assert.match(trust, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `missing ${marker}`);
  assert.match(trust, /generation == previousGeneration/);
  assert.match(trust, /generation == previousGeneration \+ 1/);
  assert.match(trust, /strictly newer state/);
  assert.match(trust, /PublicKeyFingerprint/);
  assert.match(trust, /RawPublicKey/);
});

test('Windows production config/recovery verification selects the state-declared leaf', () => {
  assert.match(client, /VerifyConfigKeyState\(manifest, version\)/);
  assert.match(client, /VerifyConfigKeyState\(response, version\)/);
  assert.match(client, /trustState\.Select\(signingKeyId, version\)/);
  assert.match(client, /trustState\.Select\(signingKeyId, configVersion\)/);
  assert.match(client, /"signing_key_id"/);
  assert.match(client, /ApplyConfigKeyState\(candidate, trustState\)/);
  assert.match(client, /ConfigKeyStateGeneration/);
  assert.match(client, /ConfigKeyStateDigest/);
  assert.doesNotMatch(client, /const string keyId = "config-signing-v1"/);
  assert.doesNotMatch(client, /envelope\["key_id"\]\?\.GetValue<string>\(\) != "config-signing-v1"/);
});

test('Windows v1 fallback is explicitly development-only once a root exists', () => {
  const fallbackChecks = [...client.matchAll(/ReleaseContract\.TrustRootProvisioned \|\| !string\.Equals\(signingKeyId, "config-signing-v1", StringComparison\.Ordinal\)/g)];
  assert.equal(fallbackChecks.length, 2, 'config package and recovery fallback must both be guarded by an unprovisioned root');
  assert.match(trust, /if \(state is null\)[\s\S]*ReleaseContract\.TrustRootProvisioned[\s\S]*BF-CONFIG-KEY-STATE/);
});

test('Windows DPAPI state binds config trust generation, digest and canonical state', () => {
  assert.match(client, /ValidateStateString\(state\.ConfigKeyStateJson, 64 \* 1024, true\)/);
  assert.match(client, /verifiedKeyState\.Generation != state\.ConfigKeyStateGeneration/);
  assert.match(client, /verifiedKeyState\.Digest, state\.ConfigKeyStateDigest/);
  assert.match(client, /verifiedKeyState\.CanonicalState, state\.ConfigKeyStateJson/);
  assert.match(client, /CryptographicOperations\.ZeroMemory\(keyStateBytes\)/);
});

test('compiled Windows ConfigKeyTrust executes rotation, offline generation catch-up, and fail-closed negatives', () => {
  const project = path.join(root, 'tests', 'ui-state-fixture', 'BifrostUiStateFixture.csproj');
  const build = spawnSync(dotnet, ['build', project, '-c', 'Debug', '--no-restore', '-t:Rebuild', '--nologo'], {
    cwd: root, encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(build.status, 0, build.stderr || build.stdout);
  const run = spawnSync(dotnet, ['run', '--project', project, '-c', 'Debug', '--no-restore', '--no-build', '--', '--config-key-trust'], {
    cwd: root, encoding: 'utf8', timeout: 120000, windowsHide: true, maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  assert.match(run.stdout, /CONFIG-KEY-TRUST PASS/);
});
