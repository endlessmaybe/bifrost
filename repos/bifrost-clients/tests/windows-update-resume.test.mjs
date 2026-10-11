import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { canonicalReleaseJson } from '../config-contracts/release-contract.mjs';

const root = path.resolve(import.meta.dirname, '..');

function deterministicPair(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  const key = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  const privateKey = createPrivateKey({ key, format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function fingerprint(publicKey) {
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
}

function createFormalSessionFixture(directory) {
  const corpus = JSON.parse(readFileSync(path.join(root, 'config-contracts', 'release-envelope-corpus-v2.json'), 'utf8'));
  const template = corpus.vectors.find((item) => item.id === 'stable-windows-only-valid');
  assert.ok(template, 'stable signed Windows fixture template must exist');
  const manifest = JSON.parse(template.envelope.manifest_text);
  const installableKinds = new Set(['exe', 'service-exe', 'installer', 'core', 'core-manifest', 'metadata']);
  const pathById = new Map([
    ['app', ['windows-app/app.bin', 'Bifrost.exe']],
    ['service', ['windows-service/service.bin', 'BifrostClientService.exe']],
    ['installer', ['windows-installer/installer.bin', 'BifrostSetup.exe']],
    ['mihomo', ['windows-service/mihomo.bin', 'cores/mihomo.exe']],
    ['geosite', ['windows-service/geosite.bin', 'cores/GeoSite.dat']],
    ['geoip', ['windows-service/geoip.bin', 'cores/geoip.metadb']],
    ['core-manifest', ['windows-service/core-manifest.bin', 'cores/CORE-MANIFEST.json']],
    ['install-metadata', ['windows-installer/install-metadata.bin', 'install-metadata.json']]
  ]);
  const artifacts = [];
  for (const artifact of manifest.build.artifacts) {
    if (!installableKinds.has(artifact.kind)) continue;
    const payload = Buffer.from(`signed-${artifact.id}-payload`, 'utf8');
    const [artifactPath, installPath] = pathById.get(artifact.id);
    artifact.path = artifactPath;
    artifact.install_path = installPath;
    artifact.bytes = payload.length;
    artifact.sha256 = createHash('sha256').update(payload).digest('hex');
    artifacts.push({ id: artifact.id, payload_base64: payload.toString('base64') });
  }
  assert.equal(artifacts.length, 8, 'fixture must contain the exact Windows update set');

  const rootPair = deterministicPair('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const releasePair = deterministicPair('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100');
  const rootPem = rootPair.publicKey.export({ type: 'spki', format: 'pem' });
  const rootFingerprint = fingerprint(rootPair.publicKey);
  const releaseFingerprint = fingerprint(releasePair.publicKey);
  const delegation = structuredClone(template.envelope.delegation);
  const keyState = structuredClone(template.envelope.key_state);
  delete keyState.signature;
  const rootSignature = sign(null, Buffer.from(canonicalReleaseJson(delegation)), rootPair.privateKey).toString('base64url');
  const keyStateSignature = sign(null, Buffer.from(canonicalReleaseJson(keyState)), rootPair.privateKey).toString('base64url');
  const manifestText = canonicalReleaseJson(manifest);
  const envelope = {
    manifest_text: manifestText,
    signature: sign(null, Buffer.from(manifestText), releasePair.privateKey).toString('base64url'),
    delegation,
    root_signature: rootSignature,
    key_state: { ...keyState, signature: keyStateSignature }
  };
  const previousState = {
    last_sequence: manifest.release_sequence - 1,
    last_manifest_digest: 'a'.repeat(64),
    envelope_digest: 'b'.repeat(64),
    authority_digest: createHash('sha256').update(canonicalReleaseJson(keyState)).digest('hex'),
    authority_generation: keyState.generation,
    root_key_id: 'bifrost-root-v1',
    root_fingerprint: rootFingerprint,
    delegation_generation: delegation.generation,
    key_id: delegation.key_id,
    signing_key_fingerprint: releaseFingerprint,
    channel: manifest.channel,
    floor: 1,
    state_generation: 1,
    slot: 'a',
    state_checksum: '',
    updated_at: '2026-01-01T00:00:00.000Z'
  };
  const rootFile = path.join(directory, 'release-test-root.json');
  const fixtureFile = path.join(directory, 'release-session-fixture.json');
  writeFileSync(rootFile, JSON.stringify({ key_id: 'bifrost-root-v1', purpose: 'release-trust-root', algorithm: 'Ed25519', public_key_pem: rootPem, fingerprint: rootFingerprint }));
  writeFileSync(fixtureFile, JSON.stringify({ envelope, previous_state: previousState, artifacts }));
  return { rootFile, fixtureFile };
}

test('Windows updater resumes downloads and carries a renewed session through protected artifacts', () => {
  const umbrella = path.resolve(root, '..', '..');
  const dotnet = path.join(umbrella, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
  const project = path.join(root, 'tests', 'ui-state-fixture', 'BifrostUiStateFixture.csproj');
  assert.ok(existsSync(dotnet), 'locked .NET SDK must exist');
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'bifrost-update-session-fixture-'));
  try {
    const signed = createFormalSessionFixture(temporary);
    const build = spawnSync(dotnet, ['build', project, '-c', 'Debug', '--no-restore', '-t:Rebuild',
      `/p:BifrostReleaseTrustRootFile=${signed.rootFile}`, '/p:BifrostReleaseTrustRootTestOnly=true'], {
      cwd: path.dirname(project), encoding: 'utf8', timeout: 180000
    });
    assert.equal(build.status, 0, build.stderr || build.stdout);
    const fixture = path.join(root, 'tests', 'ui-state-fixture', 'bin', 'Debug', 'net10.0-windows', 'Bifrost.UiStateFixture.dll');
    assert.ok(existsSync(fixture), 'compiled update fixture must exist');
    for (const scenario of ['--authentication-recovery', '--smartgate-recovery']) {
      const regression = spawnSync(dotnet, [fixture, scenario], {
        cwd: path.dirname(fixture), encoding: 'utf8', timeout: 30000
      });
      assert.equal(regression.status, 0, regression.stderr || regression.stdout);
      assert.match(regression.stdout, /RECOVERY PASS/);
    }
    const run = spawnSync(dotnet, [fixture, '--release-resume-download'], {
      cwd: path.dirname(fixture), encoding: 'utf8', timeout: 30000
    });
    assert.equal(run.status, 0, run.stderr || run.stdout);
    assert.match(run.stdout, /UPDATE-RESUME PASS partial=8388608 total=9121725 resumed_requests=1 cdn_full=1 resumed_blob_ranges=2 max_parallel=2 mirror_fallback=1 trusted_redirect=1 transient_retries=2 corrupt_mirror_fallback=1/);

    const renewal = spawnSync(dotnet, [fixture, '--release-session-renewal'], {
      cwd: path.dirname(fixture), encoding: 'utf8', timeout: 30000,
      env: { ...process.env, BIFROST_RELEASE_SESSION_FIXTURE: signed.fixtureFile }
    });
    assert.equal(renewal.status, 0, renewal.stderr || renewal.stdout);
    assert.match(renewal.stdout, /UPDATE-DISCOVERY PASS verified_manifest=1 artifact_requests=0 authority_unchanged=1/);
    assert.match(renewal.stdout, /UPDATE-SESSION-RENEWAL PASS formal_entry=1 manifest_requests=2 renewal_calls=1 protected_requests=8/);

    const automaticLoop = spawnSync(dotnet, [fixture, '--program-update-loop'], {
      cwd: path.dirname(fixture), encoding: 'utf8', timeout: 30000
    });
    assert.equal(automaticLoop.status, 0, automaticLoop.stderr || automaticLoop.stdout);
    assert.match(automaticLoop.stdout, /PROGRAM-UPDATE-LOOP PASS checks=2 ui_notifications=8 staged_reminder=true explicit_apply=true loop_alive=true/);
    const restart = spawnSync(dotnet, [fixture, '--update-restart-intent'], {
      cwd: path.dirname(fixture), encoding: 'utf8', timeout: 30000
    });
    assert.equal(restart.status, 0, restart.stderr || restart.stdout);
    assert.match(restart.stdout, /UPDATE-RESTART-INTENT PASS/);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
