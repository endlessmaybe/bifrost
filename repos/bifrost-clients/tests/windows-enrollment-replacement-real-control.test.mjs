import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { ControlStore } from '../../bifrost-control/src/store.mjs';
import { loadSigningKeys } from '../../bifrost-control/src/crypto.mjs';
import { loadConfigKeyState } from '../../bifrost-control/src/config-key-state-loader.mjs';

const clientsRoot = path.resolve(import.meta.dirname, '..');
const workspace = path.resolve(clientsRoot, '..', '..');
const controlRoot = path.resolve(clientsRoot, '..', 'bifrost-control');
const dotnet = process.env.BIFROST_DOTNET?.trim()
  || path.join(workspace, 'build-work', 'toolchains', 'dotnet', 'dotnet.exe');
const fixtureProject = path.join(clientsRoot, 'tests', 'ui-state-fixture', 'BifrostUiStateFixture.csproj');
const bootstrapTrust = path.join(controlRoot, 'scripts', 'local-evaluation-trust-bootstrap.mjs');

async function freePort() {
  const listener = net.createServer();
  await new Promise((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

async function startControl(rootDir, rootFile, port) {
  const base = `http://127.0.0.1:${port}`;
  let stderr = '';
  const child = spawn(process.execPath, [path.join(controlRoot, 'src', 'server.mjs')], {
    cwd: controlRoot,
    env: {
      ...process.env,
      BIFROST_ROOT: rootDir,
      BIFROST_CONTROL_PORT: String(port),
      BIFROST_LOCAL_RELEASE_TRUST_ROOT_FILE: rootFile,
    },
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-6000); });
  for (let attempt = 0; attempt < 160; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`isolated Control exited early: ${stderr}`);
    try {
      const ready = await fetch(`${base}/readyz`);
      if (ready.ok) return { child, base, stderr: () => stderr };
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  child.kill();
  throw new Error(`isolated Control did not become ready: ${stderr}`);
}

async function stopControl(instance) {
  if (!instance?.child || instance.child.exitCode !== null || instance.child.signalCode !== null) return;
  const exited = new Promise(resolve => instance.child.once('exit', resolve));
  instance.child.kill('SIGTERM');
  await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 4000))]);
  if (instance.child.exitCode === null && instance.child.signalCode === null) instance.child.kill('SIGKILL');
}

function runFixture(rootFile, origin, args) {
  const result = spawnSync(dotnet, [
    'run', '--project', fixtureProject, '-c', 'Debug', '--no-restore',
    '-p:BifrostLocalEvaluation=true',
    '-p:BifrostLocalEvaluationFixture=true',
    '-p:BifrostTestHarness=true',
    `-p:BifrostTrustedControlOrigin=${origin}`,
    `-p:BifrostReleaseTrustRootFile=${rootFile}`,
    '-p:BifrostReleaseTrustRootTestOnly=true',
    '--', ...args,
  ], {
    cwd: clientsRoot,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(result.status, 0, `fixture failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  return result.stdout;
}

function capture(output, name) {
  const match = new RegExp(`${name}=([^\\s]+)`).exec(output);
  assert.ok(match, `fixture output is missing ${name}: ${output}`);
  return match[1];
}

for (const retirement of ['deleted', 'disabled']) {
test(`real Control ${retirement} identity allows activation with a valid new code`, async (t) => {
  assert.ok(fs.existsSync(dotnet), `locked .NET SDK must exist: ${dotnet}`);
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bifrost-real-enrollment-replacement-'));
  const secretsDir = path.join(rootDir, 'secrets');
  const stateFile = path.join(rootDir, 'windows-state', 'control-state.bin');
  fs.mkdirSync(secretsDir, { recursive: true });
  t.after(() => fs.rmSync(rootDir, { recursive: true, force: true }));

  // Create the same legacy signing pair a development Control would create,
  // then use the production local-evaluation ceremony tool to establish the
  // root-signed config-key state consumed by both Control and the C# fixture.
  loadSigningKeys(secretsDir);
  const trust = spawnSync(process.execPath, [bootstrapTrust, '--secrets-dir', secretsDir], {
    cwd: controlRoot, encoding: 'utf8', windowsHide: true, timeout: 30_000,
  });
  assert.equal(trust.status, 0, `local trust bootstrap failed: ${trust.stderr}`);
  const rootFile = path.join(secretsDir, 'local-evaluation-release-root.json');
  const rootDescriptor = JSON.parse(fs.readFileSync(rootFile, 'utf8'));
  const signingKeys = loadSigningKeys(secretsDir, { allowGenerate: false, allowLegacyPair: true });
  const configKeyState = loadConfigKeyState(path.join(secretsDir, 'config-key-state.json'), {
    signingKeys, rootDescriptor, required: true,
  });

  const bootstrap = new ControlStore({ rootDir, signingKeys, configKeyState, seedDefaults: true });
  const oldInvite = bootstrap.createInvite({ batch: 'TEST-ONLY-real-replacement', note: 'old account' });
  const replacementInvite = bootstrap.createInvite({ batch: 'TEST-ONLY-real-replacement', note: 'replacement account' });
  const unusedInvite = bootstrap.createInvite({ batch: 'TEST-ONLY-real-replacement', note: 'must remain unused' });
  bootstrap.db.close();

  const port = await freePort();
  let control = await startControl(rootDir, rootFile, port);
  t.after(async () => { await stopControl(control); });

  const seedOutput = runFixture(rootFile, control.base, ['--enrollment-real-seed', stateFile, control.base, oldInvite]);
  assert.match(seedOutput, /ENROLLMENT-REAL-SEED PASS/);
  const oldPublicId = capture(seedOutput, 'public_id');
  const oldDeviceId = capture(seedOutput, 'device_id');

  await stopControl(control);
  control = null;

  // Perform the exact backend operation from the admin deletion path. It
  // revokes then removes every device/session/package row before deleting the
  // account, while the Windows DPAPI state deliberately remains untouched.
  const deletionStore = new ControlStore({ rootDir, signingKeys, configKeyState, seedDefaults: false });
  const deletion = retirement === 'deleted'
    ? deletionStore.deleteAccountImmediately(oldPublicId, { reason: 'TEST-ONLY real replacement integration' })
    : deletionStore.setAccountStatus(oldPublicId, 'disabled', { reason: 'TEST-ONLY real replacement integration' });
  assert.equal(deletion.status, retirement);
  assert.equal(deletion.affected_devices, 1);
  assert.equal(deletionStore.one('SELECT COUNT(*) AS n FROM accounts WHERE public_id = ?', oldPublicId).n, retirement === 'deleted' ? 0 : 1);
  assert.equal(deletionStore.one("SELECT COUNT(*) AS n FROM devices WHERE random_device_id = ? AND status = 'active'", oldDeviceId).n, 0);
  assert.ok(deletionStore.findInvite(replacementInvite), 'replacement invite is unused before the second activation');
  assert.ok(deletionStore.findInvite(unusedInvite), 'third invite is unused before retained-identity resume');
  deletionStore.db.close();

  control = await startControl(rootDir, rootFile, port);
  const replacementOutput = runFixture(rootFile, control.base, [
    '--enrollment-real-replace', stateFile, control.base, replacementInvite, unusedInvite,
  ]);
  assert.match(replacementOutput, /ENROLLMENT-REAL-REPLACE PASS/);
  const newPublicId = capture(replacementOutput, 'public_id');
  const newDeviceId = capture(replacementOutput, 'device_id');
  assert.notEqual(newPublicId, oldPublicId);
  assert.notEqual(newDeviceId, oldDeviceId);

  await stopControl(control);
  control = null;

  const verified = new ControlStore({ rootDir, signingKeys, configKeyState, seedDefaults: false });
  const usedReplacement = verified.findInvite(replacementInvite, { allowUsed: true });
  const stillUnused = verified.findInvite(unusedInvite);
  assert.ok(usedReplacement?.used_at, 'replacement invite is consumed exactly by the fresh candidate activation');
  assert.ok(stillUnused && stillUnused.used_at === null, 'different invite remains unused when retained identity resumes');
  assert.equal(verified.one("SELECT COUNT(*) AS n FROM accounts WHERE status = 'active'").n, 1, 'only the replacement account is active');
  assert.equal(verified.one("SELECT COUNT(*) AS n FROM devices WHERE status = 'active'").n, 1, 'only the committed replacement device is active');
  assert.equal(verified.one('SELECT COUNT(*) AS n FROM devices WHERE random_device_id = ?', newDeviceId).n, 1);
  if (retirement === 'deleted') assert.equal(verified.one("SELECT COUNT(*) AS n FROM audit_events WHERE action = 'account.deletion.immediate' AND target = ?", oldPublicId).n, 1);
  else assert.equal(verified.one('SELECT status FROM accounts WHERE public_id = ?', oldPublicId).status, 'disabled', 'replacement never reactivates the disabled account');
  verified.db.close();
});
}
